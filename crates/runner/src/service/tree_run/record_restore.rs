//! Restore a handover assignment's kept run under its local definition.

use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use tempfile::TempDir;
use time::OffsetDateTime;
use url::Url;
use useful_execution::{
    CancellationPolicy, CancellationSource, WorkflowRunRecord, assemble_portable_record,
    open_portable_record, portable_record_files,
};
use useful_runner_protocol::WorkflowTreeV1RunnerProjection;

use super::command::{self, UsefulCommand};
use super::record_delivery::{CancelRequests, Delivery, Failure, RecordBroker, RecordFile, Scope};
use super::{TreeLayout, write_resolution};
use crate::service::backoff::Backoff;
use crate::service::run_inputs::validate_capability_url;

const INVALID: Failure = Failure::Retry("response_invalid");
const ALTERED: Failure = Failure::Stop("record_altered");
const FILES: Failure = Failure::Stop("files_unavailable");

#[derive(Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct KeptRecord {
    run_id: String,
    engine_run_id: String,
    attempt_number: u64,
    sequence: u64,
    stored_at: String,
    manifest: RecordFile,
    file_count: u64,
    total_size_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(in crate::service) struct DownloadLink {
    pub(super) sha256: String,
    pub(super) size_bytes: u64,
    #[serde(deserialize_with = "capability_url")]
    pub(super) url: Url,
}

fn capability_url<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Url, D::Error> {
    let raw = String::deserialize(deserializer)?;
    validate_capability_url(&raw).map_err(|_| serde::de::Error::custom("invalid download URL"))
}

#[derive(Deserialize)]
#[serde(
    tag = "outcome",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum DownloadAnswer {
    Issued {
        record: KeptRecord,
        capability_expires_at: String,
        files: Vec<DownloadLink>,
    },
    Refused {
        reason: String,
    },
}

pub(in crate::service) struct DownloadBatch {
    pub(super) record: KeptRecord,
    pub(super) links: Vec<DownloadLink>,
    expires: OffsetDateTime,
}

impl DownloadBatch {
    pub(super) fn decode(value: Value, requested: &[&str]) -> Result<Self, Failure> {
        match serde_json::from_value(value).map_err(|_| INVALID)? {
            DownloadAnswer::Issued {
                record,
                capability_expires_at,
                files,
            } => {
                let manifest = [record.manifest.sha256.as_str()];
                let expected = if requested.is_empty() {
                    &manifest[..]
                } else {
                    requested
                };
                if !files
                    .iter()
                    .map(|file| file.sha256.as_str())
                    .eq(expected.iter().copied())
                {
                    return Err(INVALID);
                }
                let expires =
                    crate::enrollment::parse_rfc3339(&capability_expires_at).ok_or(INVALID)?;
                Ok(Self {
                    record,
                    links: files,
                    expires,
                })
            }
            DownloadAnswer::Refused { reason } => Err(match reason.as_str() {
                "record_absent" => Failure::Stop("record_absent"),
                "record_gone" => Failure::Stop("record_gone"),
                "file_unavailable" => Failure::Stop("file_unavailable"),
                _ => INVALID,
            }),
        }
    }
}

/// Holds all downloaded bytes outside the useful home until the engine restores them.
struct Staged {
    temporary: TempDir,
    run: WorkflowRunRecord,
}

fn download(broker: &dyn RecordBroker, scope: &Scope, private: &Path) -> Result<Staged, Failure> {
    let issued = broker.download_links(scope, &[])?;
    let manifest_link = &issued.links[0];
    if manifest_link.size_bytes != issued.record.manifest.size_bytes
        || manifest_link.size_bytes > useful_execution::MAXIMUM_DURABLE_RECORD_BYTES
    {
        return Err(ALTERED);
    }
    if useful_support::utc_now() >= issued.expires {
        return Err(Failure::Retry("service_unavailable"));
    }
    let mut manifest = Vec::new();
    broker.get(scope, manifest_link, &mut manifest)?;
    let listed = portable_record_files(&manifest).map_err(|_| ALTERED)?;
    if listed.run != issued.record.engine_run_id {
        return Err(ALTERED);
    }
    let temporary = tempfile::Builder::new()
        .prefix("handover-")
        .tempdir_in(private)
        .map_err(|_| FILES)?;
    let files = temporary.path().join("files");
    DirBuilder::new()
        .mode(0o700)
        .create(&files)
        .map_err(|_| FILES)?;
    for batch in listed.files.chunks(100) {
        let mut remaining = batch;
        while !remaining.is_empty() {
            let keys: Vec<_> = remaining.iter().map(|(key, _)| key.as_str()).collect();
            let links = broker.download_links(scope, &keys)?;
            if links.record != issued.record {
                return Err(ALTERED);
            }
            let mut fetched = 0;
            for (link, (digest, size)) in links.links.iter().zip(remaining) {
                if useful_support::utc_now() >= links.expires {
                    break;
                }
                if link.size_bytes != *size {
                    return Err(ALTERED);
                }
                let mut file = crate::enrollment::create_new_private_file(&files.join(digest))
                    .map_err(|_| FILES)?;
                broker.get(scope, link, &mut file)?;
                fetched += 1;
            }
            if fetched == 0 {
                return Err(Failure::Retry("service_unavailable"));
            }
            remaining = &remaining[fetched..];
        }
    }
    let record = temporary.path().join("record");
    assemble_portable_record(&manifest, &files, &record).map_err(|e| Failure::Stop(e.code()))?;
    let opened = open_portable_record(&record).map_err(|e| Failure::Stop(e.code()))?;
    Ok(Staged {
        temporary,
        run: opened.run().clone(),
    })
}

/// Called after the assignment starts, when its lease authorizes record downloads.
pub(super) async fn restore(
    delivery: Option<&Delivery>,
    useful: &UsefulCommand,
    private: &Path,
    tree: &WorkflowTreeV1RunnerProjection,
    cancellation: &CancellationPolicy,
) -> Result<PathBuf, &'static str> {
    let delivery = delivery.ok_or("service_unavailable")?;
    let scope = delivery.download_scope();
    let _cancel_requests = CancelRequests(&scope.stopped);
    // A large, healthy transfer may renew several batches of links. Bound retries
    // from the first transient failure, allowing the initial transfer to make progress.
    let first_retry = tokio::sync::Notify::new();
    let retry_deadline = async {
        first_retry.notified().await;
        useful.sleeper.sleep(Duration::from_secs(300)).await;
    };
    let fetch = async {
        let mut backoff = Backoff::new();
        loop {
            let broker = Arc::clone(&delivery.broker);
            let scope = scope.clone();
            let private = private.to_owned();
            match tokio::task::spawn_blocking(move || download(broker.as_ref(), &scope, &private))
                .await
                .map_err(|_| "files_unavailable")?
            {
                Ok(staged) => return Ok(staged),
                Err(Failure::Stop(reason)) => return Err(reason),
                Err(Failure::Retry(_)) => {
                    first_retry.notify_one();
                    useful.sleeper.sleep(backoff.next_delay()).await;
                }
            }
        }
    };
    let source = cancellation.source();
    let staged = tokio::select! {
        biased;
        _ = source.wait_for_cancellation() => return Err("assignment_fenced"),
        () = retry_deadline => return Err("service_unavailable"),
        result = fetch => result?,
    };
    let restored = restore_staged(&staged, useful, private, tree, source).await;
    // The staged record can hold many files: remove it off the executor.
    let _ = tokio::task::spawn_blocking(move || drop(staged)).await;
    restored
}

/// Publishes the tree under the staged record's definition and restores the record there.
async fn restore_staged(
    staged: &Staged,
    useful: &UsefulCommand,
    private: &Path,
    tree: &WorkflowTreeV1RunnerProjection,
    source: &CancellationSource,
) -> Result<PathBuf, &'static str> {
    let definition = staged
        .run
        .definition
        .as_deref()
        .ok_or("record_definition_mismatch")?;
    if tree.digest != staged.run.tree {
        return Err("record_definition_mismatch");
    }
    let layout = TreeLayout::under(private);
    let published = command::publish_as(
        useful,
        &layout.tree,
        &layout.bindings,
        Some(definition),
        useful.bound,
        async {
            source.wait_for_cancellation().await;
        },
    )
    .await
    .map_err(|failure| match failure {
        command::PublishFailure::Refused(_) => "workflow_tree_publication_refused",
        command::PublishFailure::Launch => "tree_run_launch_failed",
        command::PublishFailure::Abandoned => "workflow_tree_publication_abandoned",
    })?;
    if published.digest != staged.run.tree
        || Some(published.revision) != staged.run.revision
        || published.definition != definition
    {
        return Err("record_definition_mismatch");
    }
    let target = useful.home.join("workflows").join(definition);
    let written = tokio::task::spawn_blocking({
        let (target, resolution) = (target.clone(), tree.resolution.clone());
        move || write_resolution(&target, published.revision, &resolution)
    })
    .await;
    if !matches!(written, Ok(Ok(()))) {
        return Err("files_unavailable");
    }
    let restored =
        command::restore_record(useful, &staged.temporary.path().join("record"), source).await?;
    if restored != target.join("runs").join(&staged.run.id) {
        return Err("record_restore_refused");
    }
    Ok(restored)
}
