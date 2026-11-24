//! Delivery of a tree run's portable record.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::StatusCode;
use ring::digest::{SHA256, digest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::watch;
use url::Url;
use useful_execution::{CancellationReason, CaptureCancellation, PortableRecordCapture};

use super::TreeRun;
use crate::runner_http::ServingTarget;
use crate::service::backoff::Backoff;
use crate::service::run_inputs::validate_capability_url;

#[derive(Clone)]
pub(in crate::service) struct Scope {
    assignment: String,
    attempt: String,
    stopped: CaptureCancellation,
}

impl Scope {
    pub(super) fn new(assignment: &str, attempt: &str) -> Self {
        Self {
            assignment: assignment.into(),
            attempt: attempt.into(),
            stopped: CaptureCancellation::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::service) struct RecordFile {
    sha256: String,
    size_bytes: u64,
}
impl RecordFile {
    fn new(sha256: String, size_bytes: u64) -> Self {
        Self { sha256, size_bytes }
    }
}

pub(in crate::service) struct Capability {
    url: Url,
    headers: BTreeMap<String, String>,
}

pub(in crate::service) enum UploadBody {
    File(PathBuf),
    Manifest(Arc<Vec<u8>>),
}

#[derive(Debug)]
pub(in crate::service) enum Store {
    Complete(Complete),
    Incomplete(Vec<RecordFile>),
}
#[derive(Debug)]
pub(in crate::service) enum Complete {
    Stored,
    Superseded,
}
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(in crate::service) enum Failure {
    Retry(&'static str),
    Stop(&'static str),
}

const INVALID: Failure = Failure::Retry("response_invalid");
const SERVICE: Failure = Failure::Retry("service_unavailable");
const UPLOAD: Failure = Failure::Retry("upload_failed");

pub(in crate::service) trait RecordBroker: Send + Sync {
    fn links(
        &self,
        scope: &Scope,
        files: &[RecordFile],
    ) -> Result<Vec<Option<Capability>>, Failure>;
    fn put(
        &self,
        scope: &Scope,
        capability: &Capability,
        size: u64,
        body: &UploadBody,
    ) -> Result<(), Failure>;
    fn store(&self, scope: &Scope, sequence: u64, manifest: &RecordFile) -> Result<Store, Failure>;
}

pub(in crate::service) struct HttpRecordBroker {
    target: ServingTarget,
    boot_id: String,
}

fn operation<T>(
    scope: &Scope,
    seconds: u64,
    failure: Failure,
    f: impl AsyncFnOnce(reqwest::Client) -> Result<T, Failure>,
) -> Result<T, Failure> {
    useful_support::install_provider();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| failure)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(seconds))
        .build()
        .map_err(|_| failure)?;
    runtime.block_on(async {
        tokio::select! {
            biased;
            () = scope.stopped.cancelled() => Err(failure),
            result = f(client) => result,
        }
    })
}

impl HttpRecordBroker {
    pub(in crate::service) fn new(target: ServingTarget, boot_id: &str) -> Self {
        Self {
            target,
            boot_id: boot_id.into(),
        }
    }

    fn post(
        &self,
        path: &str,
        scope: &Scope,
        mut body: Value,
        seconds: u64,
        limit: usize,
    ) -> Result<Value, Failure> {
        body["schemaVersion"] = 1.into();
        body["bootId"] = self.boot_id.as_str().into();
        body["assignmentId"] = scope.assignment.as_str().into();
        body["attemptId"] = scope.attempt.as_str().into();
        operation(scope, seconds, SERVICE, async |client| {
            let target = self.target.current();
            let mut response = client
                .post(target.url(path))
                .bearer_auth(target.credential().bearer_value())
                .json(&body)
                .send()
                .await
                .map_err(|_| SERVICE)?;
            match response.status() {
                StatusCode::OK => {}
                StatusCode::CONFLICT => return Err(Failure::Stop("assignment_fenced")),
                StatusCode::BAD_REQUEST => return Err(Failure::Stop("request_invalid")),
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED => {
                    return Err(Failure::Stop("routes_unavailable"));
                }
                _ => return Err(SERVICE),
            }
            if response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|val| val.to_str().ok())
                != Some("application/json")
            {
                return Err(INVALID);
            }
            let mut bytes = vec![];
            while let Some(chunk) = response.chunk().await.map_err(|_| SERVICE)? {
                if bytes.len() + chunk.len() > limit {
                    return Err(INVALID);
                }
                bytes.extend_from_slice(&chunk);
            }
            let mut value = useful_support::strict_json_from_slice(&bytes).map_err(|_| INVALID)?;
            if value
                .as_object_mut()
                .and_then(|o| o.remove("schemaVersion"))
                .and_then(|v| v.as_u64())
                != Some(1)
            {
                return Err(INVALID);
            }
            Ok(value)
        })
    }
}

#[derive(Deserialize)]
#[serde(
    tag = "outcome",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum UploadAnswer {
    Issued {
        #[serde(rename = "capabilityExpiresAt")]
        _expires: String,
        files: Vec<Link>,
    },
    Refused {
        reason: String,
    },
}

#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields, rename_all_fields = "camelCase")]
enum Link {
    Held {
        sha256: String,
        size_bytes: u64,
        held: bool,
    },
    Issued {
        sha256: String,
        size_bytes: u64,
        held: bool,
        url: String,
        headers: BTreeMap<String, String>,
    },
}

#[derive(Deserialize)]
#[serde(
    tag = "outcome",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum StoreAnswer {
    Stored {
        sequence: u64,
        #[serde(rename = "storedAt")]
        _stored_at: String,
    },
    Superseded {
        kept_sequence: u64,
    },
    Incomplete {
        missing: Vec<RecordFile>,
        missing_count: u64,
    },
    Refused {
        reason: String,
    },
}

impl RecordBroker for HttpRecordBroker {
    fn links(
        &self,
        scope: &Scope,
        files: &[RecordFile],
    ) -> Result<Vec<Option<Capability>>, Failure> {
        let value = self.post(
            "/v1/runner/run-records/upload-capabilities",
            scope,
            json!({"files":files}),
            30,
            2 * 1024 * 1024,
        )?;
        match serde_json::from_value(value).map_err(|_| INVALID)? {
            UploadAnswer::Issued { files: links, .. } if links.len() == files.len() => files
                .iter()
                .zip(links)
                .map(|(file, link)| match link {
                    Link::Held {
                        sha256,
                        size_bytes,
                        held: true,
                    } if file.sha256 == sha256 && file.size_bytes == size_bytes => Ok(None),
                    Link::Issued {
                        sha256,
                        size_bytes,
                        held: false,
                        url,
                        headers,
                    } if file.sha256 == sha256 && file.size_bytes == size_bytes => {
                        Ok(Some(Capability {
                            url: validate_capability_url(&url).map_err(|_| INVALID)?,
                            headers,
                        }))
                    }
                    _ => Err(INVALID),
                })
                .collect(),
            UploadAnswer::Refused { reason } if reason == "record_limit_exceeded" => {
                Err(Failure::Stop("record_limit_exceeded"))
            }
            _ => Err(INVALID),
        }
    }

    fn put(
        &self,
        scope: &Scope,
        capability: &Capability,
        size: u64,
        body: &UploadBody,
    ) -> Result<(), Failure> {
        let bytes = match body {
            UploadBody::File(path) => {
                let file = fs::File::open(path).map_err(|_| UPLOAD)?;
                if file.metadata().map_err(|_| UPLOAD)?.len() != size {
                    return Err(UPLOAD);
                }
                use std::io::Read as _;
                let mut bytes = Vec::new();
                file.take(size.saturating_add(1))
                    .read_to_end(&mut bytes)
                    .map_err(|_| UPLOAD)?;
                bytes
            }
            UploadBody::Manifest(bytes) => bytes.as_ref().clone(),
        };
        if bytes.len() as u64 != size {
            return Err(UPLOAD);
        }
        operation(scope, 300, UPLOAD, async move |client| {
            let mut request = client.put(capability.url.clone());
            for (name, value) in &capability.headers {
                if !name.eq_ignore_ascii_case("content-length") {
                    request = request.header(name, value);
                }
            }
            let response = request
                .header(reqwest::header::CONTENT_LENGTH, size)
                .body(bytes)
                .send()
                .await
                .map_err(|_| UPLOAD)?;
            if response.status().is_success()
                || response.status() == StatusCode::PRECONDITION_FAILED
            {
                Ok(())
            } else {
                Err(UPLOAD)
            }
        })
    }

    fn store(&self, scope: &Scope, sequence: u64, manifest: &RecordFile) -> Result<Store, Failure> {
        let value = self.post(
            "/v1/runner/run-records/commit",
            scope,
            json!({"sequence":sequence,"manifest":manifest}),
            90,
            64 * 1024,
        )?;
        match serde_json::from_value(value).map_err(|_| INVALID)? {
            StoreAnswer::Stored {
                sequence: stored, ..
            } if sequence == stored => Ok(Store::Complete(Complete::Stored)),
            StoreAnswer::Superseded { kept_sequence } if kept_sequence > sequence => {
                Ok(Store::Complete(Complete::Superseded))
            }
            StoreAnswer::Incomplete {
                missing,
                missing_count,
            } if !missing.is_empty()
                && missing.len() <= 256
                && missing.len() as u64 <= missing_count =>
            {
                Ok(Store::Incomplete(missing))
            }
            StoreAnswer::Refused { reason } => Err(match reason.as_str() {
                "manifest_invalid" => Failure::Stop("manifest_invalid"),
                "sequence_reused" => Failure::Stop("sequence_reused"),
                "record_limit_exceeded" => Failure::Stop("record_limit_exceeded"),
                _ => INVALID,
            }),
            _ => Err(INVALID),
        }
    }
}
#[derive(Clone, Default)]
pub(in crate::service) struct Summary {
    pub(in crate::service) end: Option<&'static str>,
    pub(in crate::service) failure: Option<&'static str>,
    pub(in crate::service) sequence: Option<u64>,
}

#[derive(Clone)]
pub(super) struct Delivery {
    broker: Arc<dyn RecordBroker>,
    scope: Scope,
    files: PathBuf,
    bound: Duration,
    summary: Arc<Mutex<Summary>>,
}
impl Delivery {
    pub(super) fn new(
        broker: Arc<dyn RecordBroker>,
        scope: Scope,
        files: PathBuf,
        bound: Duration,
    ) -> Self {
        Self {
            broker,
            scope,
            files,
            bound,
            summary: Arc::default(),
        }
    }

    pub(super) fn summary(&self) -> Summary {
        self.summary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn update(&self, f: impl FnOnce(&mut Summary)) {
        f(&mut self
            .summary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner));
    }
}

struct Snapshot {
    manifest: RecordFile,
    bytes: Arc<Vec<u8>>,
    files: Vec<RecordFile>,
    entries: Value,
    sequence: Option<u64>,
}

fn capture(capture: &mut PortableRecordCapture, path: &Path) -> Result<Snapshot, &'static str> {
    let record = capture.capture(path).map_err(|e| e.code())?;
    let mut manifest: Value =
        serde_json::from_slice(&record.manifest).map_err(|_| "record_invalid")?;
    let entries = manifest
        .as_object_mut()
        .and_then(|o| o.remove("entries"))
        .ok_or("record_invalid")?;
    let key = digest(&SHA256, &record.manifest)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(Snapshot {
        manifest: RecordFile::new(key, record.manifest.len() as u64),
        files: record
            .files
            .into_iter()
            .map(|(key, size)| RecordFile::new(key, size))
            .collect(),
        bytes: Arc::new(record.manifest),
        entries,
        sequence: None,
    })
}

struct Worker<'a> {
    run: &'a TreeRun,
    delivery: &'a Delivery,
    known: BTreeSet<String>,
    last_sequence: u64,
}

impl Worker<'_> {
    fn current(&self) -> Result<(), Failure> {
        if self.run.cancellation.source().cancellation_reason()
            == Some(CancellationReason::ExecutionLeaseExpired)
        {
            Err(Failure::Stop("lease_lost"))
        } else {
            Ok(())
        }
    }

    async fn request<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&dyn RecordBroker, &Scope) -> Result<T, Failure> + Send + 'static,
    ) -> Result<T, Failure> {
        self.current()?;
        let delivery = self.delivery.clone();
        let source = self.run.cancellation.source().clone();
        tokio::task::spawn_blocking(move || {
            if source.cancellation_reason() == Some(CancellationReason::ExecutionLeaseExpired) {
                return Err(Failure::Stop("lease_lost"));
            }
            operation(delivery.broker.as_ref(), &delivery.scope)
        })
        .await
        .map_err(|_| SERVICE)?
    }

    async fn upload(&mut self, snapshot: &Snapshot, files: Vec<RecordFile>) -> Result<(), Failure> {
        for batch in files.chunks(256) {
            let requested = batch.to_vec();
            let links = self.request(move |b, s| b.links(s, &requested)).await?;
            for (file, link) in batch.iter().zip(links) {
                if let Some(link) = link {
                    let body = if file == &snapshot.manifest {
                        UploadBody::Manifest(snapshot.bytes.clone())
                    } else {
                        UploadBody::File(self.delivery.files.join(&file.sha256))
                    };
                    let size = file.size_bytes;
                    self.request(move |b, s| b.put(s, &link, size, &body))
                        .await?;
                }
                self.known.insert(file.sha256.clone());
            }
        }
        Ok(())
    }

    async fn attempt(&mut self, snapshot: &mut Snapshot) -> Result<Complete, Failure> {
        let files: BTreeMap<_, _> = snapshot
            .files
            .iter()
            .chain([&snapshot.manifest])
            .map(|f| (f.sha256.clone(), f.clone()))
            .collect();
        let pending = files
            .values()
            .filter(|f| !self.known.contains(&f.sha256))
            .cloned()
            .collect();
        self.upload(snapshot, pending).await?;
        let sequence = *snapshot.sequence.get_or_insert_with(|| {
            self.last_sequence += 1;
            self.last_sequence
        });
        let mut repaired = BTreeSet::new();
        loop {
            let manifest = snapshot.manifest.clone();
            let answer = self
                .request(move |b, s| b.store(s, sequence, &manifest))
                .await?;
            let missing = match answer {
                Store::Complete(result) => return Ok(result),
                Store::Incomplete(missing) => missing,
            };
            for file in &missing {
                if files.get(&file.sha256) != Some(file) {
                    return Err(INVALID);
                }
                self.known.remove(&file.sha256);
                if !repaired.insert(file.sha256.clone()) {
                    return Err(UPLOAD);
                }
            }
            self.upload(snapshot, missing).await?;
        }
    }
}

async fn prune(directory: PathBuf, files: Vec<RecordFile>) {
    let _ = tokio::task::spawn_blocking(move || {
        let keep: BTreeSet<_> = files.into_iter().map(|f| f.sha256).collect();
        for entry in fs::read_dir(directory)?.flatten() {
            if !entry.file_name().to_str().is_some_and(|s| keep.contains(s)) {
                fs::remove_file(entry.path())?;
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await;
}

#[derive(Clone)]
pub(super) enum Signal {
    Progress(Option<PathBuf>),
    Final(Option<PathBuf>),
}

/// Dropping the drive also drops its authority to finish an HTTP call on a blocking worker.
struct CancelRequests<'a>(&'a CaptureCancellation);

impl Drop for CancelRequests<'_> {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(super) async fn deliver(
    run: &TreeRun,
    signal: watch::Receiver<Signal>,
    ended: tokio::sync::oneshot::Receiver<()>,
) {
    let Some(delivery) = &run.delivery else {
        return;
    };
    let _cancel_requests = CancelRequests(&delivery.scope.stopped);
    let lease_lost = async {
        if run.cancellation.source().wait_for_cancellation().await
            != CancellationReason::ExecutionLeaseExpired
        {
            std::future::pending::<()>().await;
        }
    };
    let deadline = async {
        let _ = ended.await;
        run.sleeper.sleep(delivery.bound).await;
    };
    tokio::select! {
        biased;
        () = lease_lost => delivery.update(|s| s.end = Some("lease_lost")),
        () = deadline => delivery.update(|s| s.end = Some("unstored")),
        () = deliver_records(run, delivery, signal) => {}
    }
}

async fn deliver_records(run: &TreeRun, delivery: &Delivery, mut signal: watch::Receiver<Signal>) {
    let files = delivery.files.clone();
    let Ok(Ok(mut cache)) = tokio::task::spawn_blocking(move || {
        fs::DirBuilder::new().mode(0o700).create(&files)?;
        Ok::<_, std::io::Error>(PortableRecordCapture::new(&files))
    })
    .await
    else {
        delivery.update(|s| s.end = Some("files_unavailable"));
        return;
    };
    let mut worker = Worker {
        run,
        delivery,
        known: BTreeSet::new(),
        last_sequence: 0,
    };
    let mut backoff = Backoff::new();
    let mut stored_entries = None;
    let mut snapshot: Option<Snapshot> = None;
    let mut read = false;
    let mut final_read = false;
    loop {
        if snapshot.is_none() && !read {
            if final_read || signal.changed().await.is_err() {
                return;
            }
            read = true;
        }
        if read {
            let message = signal.borrow_and_update().clone();
            let directory = match message {
                Signal::Progress(directory) => directory,
                Signal::Final(directory) => {
                    final_read = true;
                    match directory {
                        Some(path) => Some(path),
                        None => super::resume_loop::locate(&run.runs).await,
                    }
                }
            };
            read = false;
            let Some(path) = directory else {
                if final_read {
                    delivery.update(|s| s.end = Some("unstored"));
                    return;
                }
                continue;
            };
            let Ok((returned, result)) = tokio::task::spawn_blocking(move || {
                let result = capture(&mut cache, &path);
                (cache, result)
            })
            .await
            else {
                delivery.update(|s| {
                    s.failure = Some("run_directory_invalid");
                    s.end = Some("unstored");
                });
                return;
            };
            cache = returned;
            match result {
                Ok(captured) if stored_entries.as_ref() == Some(&captured.entries) => {
                    snapshot = None;
                    delivery.update(|s| s.end = Some("stored"));
                    continue;
                }
                Ok(captured) => {
                    // A commit with a lost acknowledgement must be retried under the same
                    // sequence and manifest, even when the final capture observed it again.
                    if snapshot
                        .as_ref()
                        .is_none_or(|prior| prior.entries != captured.entries)
                    {
                        snapshot = Some(captured);
                    }
                    delivery.update(|s| s.end = Some("unstored"));
                }
                Err("run_changing") => {
                    run.sleeper.sleep(run.intervals.record).await;
                    read = true;
                    continue;
                }
                Err(code) => {
                    delivery.update(|s| {
                        s.failure = Some(code);
                        s.end = Some("unstored");
                    });
                    snapshot = None;
                    continue;
                }
            }
        }
        let Some(mut current) = snapshot.take() else {
            continue;
        };
        match worker.attempt(&mut current).await {
            Ok(Complete::Stored) => {
                backoff.reset();
                delivery.update(|s| {
                    s.end = Some("stored");
                    s.sequence = current.sequence;
                });
                stored_entries = Some(current.entries);
                prune(delivery.files.clone(), current.files).await;
            }
            Ok(Complete::Superseded) => {}
            Err(Failure::Stop(reason)) => {
                delivery.update(|s| s.end = Some(reason));
                return;
            }
            Err(Failure::Retry(reason)) => {
                delivery.update(|s| s.failure = Some(reason));
                run.sleeper.sleep(backoff.next_delay()).await;
                read = signal.has_changed().unwrap_or(false);
                snapshot = Some(current);
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::test_support::tree_fixture::{RecordFault, RecordGateway};

    impl HttpRecordBroker {
        /// A broker serving `endpoint` with the test runner credential.
        pub(in crate::service) fn for_test(endpoint: &Url, boot_id: &str) -> Self {
            let target =
                crate::runner_http::Target::new(endpoint, &crate::credential::test_credential())
                    .unwrap();
            Self::new(ServingTarget::new(target), boot_id)
        }
    }

    // A rotated runner credential must reach both record routes of a broker built before
    // the rotation, or the run's next checkpoint is refused until the runner restarts.
    #[test]
    fn record_broker_requests_follow_the_serving_target() {
        use crate::runner_http::test_server::assert_promoted_bearer;

        let scope = Scope::new("assignment", "attempt");
        let file = RecordFile::new("a".repeat(64), 3);
        assert_promoted_bearer(
            |target| HttpRecordBroker::new(target, "boot"),
            |broker| {
                let _ = broker.links(&scope, std::slice::from_ref(&file));
            },
        );
        assert_promoted_bearer(
            |target| HttpRecordBroker::new(target, "boot"),
            |broker| {
                let _ = broker.store(&scope, 1, &file);
            },
        );
    }

    fn fixture(name: &str, kind: &str) -> Value {
        let file = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/run-records/v1")
            .join(format!("{name}-{kind}.json"));
        serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap()
    }

    // Exercise the wire client with the same exchanges as Cloud.
    #[test]
    fn record_delivery_wire_fixtures_and_refusals() {
        for name in [
            "upload-issued",
            "upload-refused",
            "commit-stored",
            "commit-superseded",
            "commit-incomplete",
            "commit-manifest-invalid",
            "commit-sequence-reused",
            "commit-limit-exceeded",
        ] {
            let request = fixture(name, "request");
            let answer = fixture(name, "response");
            let gateway = RecordGateway::new(RecordFault::Answer(answer.clone()));
            let broker =
                HttpRecordBroker::for_test(&gateway.endpoint, request["bootId"].as_str().unwrap());
            let scope = Scope::new(
                request["assignmentId"].as_str().unwrap(),
                request["attemptId"].as_str().unwrap(),
            );
            let result = if name.starts_with("upload") {
                let files =
                    serde_json::from_value::<Vec<RecordFile>>(request["files"].clone()).unwrap();
                broker.links(&scope, &files).map(|links| {
                    assert_eq!(links.len(), 2);
                    assert!(links[0].is_none());
                    assert_eq!(
                        links[1].as_ref().unwrap().url.as_str(),
                        answer["files"][1]["url"].as_str().unwrap()
                    );
                    "issued"
                })
            } else {
                let file = serde_json::from_value(request["manifest"].clone()).unwrap();
                broker
                    .store(&scope, request["sequence"].as_u64().unwrap(), &file)
                    .map(|result| match result {
                        Store::Complete(Complete::Stored) => "stored",
                        Store::Complete(Complete::Superseded) => "superseded",
                        Store::Incomplete(files) => {
                            assert_eq!(serde_json::to_value(files).unwrap(), answer["missing"]);
                            "incomplete"
                        }
                    })
            };
            if answer["outcome"] == "refused" {
                assert!(matches!(result, Err(Failure::Stop(reason)) if reason == answer["reason"]));
            } else {
                assert_eq!(result.unwrap(), answer["outcome"]);
            }
            let state = gateway.state.lock().unwrap();
            let req = &state.requests[0];
            let route = if name.starts_with("upload") {
                "/v1/runner/run-records/upload-capabilities"
            } else {
                "/v1/runner/run-records/commit"
            };
            assert_eq!(req.target, route);
            assert_eq!(serde_json::from_slice::<Value>(&req.body).unwrap(), request);
            assert_eq!(
                req.headers
                    .iter()
                    .filter(|(k, _)| k == "authorization")
                    .count(),
                1
            );
        }
    }

    #[test]
    fn record_delivery_distinguishes_retryable_route_and_put_failures() {
        let (closed, silent) = std::sync::mpsc::channel();
        drop(closed);
        for (fault, expected) in [
            (
                RecordFault::NeverAnswer(Arc::new(Mutex::new(silent))),
                Failure::Retry("service_unavailable"),
            ),
            (RecordFault::Status(409), Failure::Stop("assignment_fenced")),
            (RecordFault::Status(400), Failure::Stop("request_invalid")),
            (
                RecordFault::Status(404),
                Failure::Stop("routes_unavailable"),
            ),
            (
                RecordFault::Status(405),
                Failure::Stop("routes_unavailable"),
            ),
            (
                RecordFault::Status(503),
                Failure::Retry("service_unavailable"),
            ),
            (
                RecordFault::Status(502),
                Failure::Retry("service_unavailable"),
            ),
            (RecordFault::Close(1), Failure::Retry("service_unavailable")),
            (
                RecordFault::Answer(
                    json!({"schemaVersion":1,"outcome":"stored","sequence":1,"storedAt":"now","unexpected":0}),
                ),
                Failure::Retry("response_invalid"),
            ),
        ] {
            let gateway = RecordGateway::new(fault);
            let broker = HttpRecordBroker::for_test(&gateway.endpoint, "boot");
            let file = RecordFile::new("a".repeat(64), 3);
            assert_eq!(
                broker.store(&Scope::new("a", "b"), 1, &file).unwrap_err(),
                expected
            );
        }
        for status in [200, 412, 403] {
            let gateway = RecordGateway::new(RecordFault::Status(status));
            let broker = HttpRecordBroker::for_test(&gateway.endpoint, "boot");
            let temp = tempfile::tempdir().unwrap();
            let bytes = b"\x00\xffrecord";
            let path = temp.path().join("file");
            std::fs::write(&path, bytes).unwrap();
            let capability = Capability {
                url: validate_capability_url(&format!(
                    "http://{}/objects/file",
                    gateway.endpoint.socket_addrs(|| None).unwrap()[0]
                ))
                .unwrap(),
                headers: BTreeMap::from([
                    ("Content-Length".into(), "8".into()),
                    ("If-None-Match".into(), "*".into()),
                    ("Content-Type".into(), "application/octet-stream".into()),
                ]),
            };
            let result = broker.put(
                &Scope::new("a", "b"),
                &capability,
                bytes.len() as u64,
                &UploadBody::File(path),
            );
            assert_eq!(
                result,
                if status == 403 {
                    Err(Failure::Retry("upload_failed"))
                } else {
                    Ok(())
                }
            );
            let state = gateway.state.lock().unwrap();
            assert_eq!(state.requests[0].body, bytes);
            for (name, value) in &capability.headers {
                assert_eq!(
                    state.requests[0]
                        .headers
                        .iter()
                        .filter(|(k, v)| k.eq_ignore_ascii_case(name) && v == value)
                        .count(),
                    1
                );
            }
        }
    }
}
