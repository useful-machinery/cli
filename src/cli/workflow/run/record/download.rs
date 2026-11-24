//! Download the immutable files named by one read of a kept record.

use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use clap::Args;
use serde::Serialize;
use useful_api::{
    HttpCancellation, RunApi, RunFailure, RunRecordRead, UnreachableCategory, capability_batches,
    transfer_capability_batch,
};
use useful_execution::{
    PortableRecordError, assemble_portable_record, normalize_terminal_path, portable_record_files,
};

use super::super::{
    cloud_api,
    input::{DownloadCommitControl, destination_parent},
    target::{CloudOptions, CloudRunArg, InCloud},
};
use crate::cli::{self, context::OrgArgs};
use crate::exit_code::ExitCode;

#[derive(Debug, Args)]
pub(super) struct DownloadCommand {
    #[command(flatten)]
    run: CloudRunArg,
    #[arg(
        long,
        value_name = "DIRECTORY",
        help = "New directory for the portable run record"
    )]
    output: PathBuf,
    #[command(flatten)]
    org: OrgArgs,
    #[command(flatten)]
    options: CloudOptions,
}

impl DownloadCommand {
    pub(super) fn execute(self) -> cli::CommandResult {
        let cloud = match self.run.find(
            &self.org,
            &self.options.authentication,
            &self.options.http,
            "useful workflow run record download",
            self.options.json,
        ) {
            Ok(cloud) => cloud,
            Err(result) => return result,
        };
        if self.options.json {
            self.output
                .to_str()
                .context("record download destination must be valid UTF-8 for JSON output")?;
        }
        let download = Arc::new(Download {
            cloud,
            destination: self.output,
            options: self.options,
        });
        let report_signal = Arc::clone(&download);
        let commit = Arc::new(DownloadCommitControl::new());
        let interrupt = Arc::clone(&commit);
        cli::execute_cancellable_mutation_with_signals(
            "record download",
            move |cancel, control| {
                let result = download.transfer(cancel, &commit);
                cli::complete_operation(control, || download.finish(result))
            },
            move || interrupt.interrupt(),
            move |signal, unknown| {
                report_signal.refuse(
                    if unknown {
                        "commitment_unknown"
                    } else {
                        "interrupted"
                    },
                    signal,
                )
            },
        )
    }
}

struct Download {
    cloud: InCloud,
    destination: PathBuf,
    options: CloudOptions,
}

enum Failure {
    Local(&'static str),
    Cloud(RunFailure),
    Session(anyhow::Error),
}

impl From<RunFailure> for Failure {
    fn from(error: RunFailure) -> Self {
        match error {
            RunFailure::InputDownloadRejected => Self::Local("integrity_mismatch"),
            failure => Self::Cloud(failure),
        }
    }
}

impl From<PortableRecordError> for Failure {
    fn from(error: PortableRecordError) -> Self {
        Self::Local(match error {
            PortableRecordError::DestinationExists => "destination_exists",
            PortableRecordError::RecordUnavailable { .. } => "staging_unavailable",
            _ => "integrity_mismatch",
        })
    }
}

fn kept<T>(read: RunRecordRead<T>) -> Result<T, Failure> {
    match read {
        RunRecordRead::Kept(value) => Ok(value),
        RunRecordRead::Absent => Err(Failure::Local("record_absent")),
        RunRecordRead::Gone => Err(Failure::Local("record_gone")),
    }
}

impl Download {
    fn api<T>(
        &self,
        cancel: &HttpCancellation,
        operation: impl FnMut(&RunApi<'_>) -> Result<T, RunFailure>,
    ) -> Result<T, Failure> {
        if cancel.is_cancelled() {
            return Err(RunFailure::Interrupted.into());
        }
        cloud_api::with_api(
            &self.cloud.deployment,
            self.options.http.transport_policy(),
            &self.options.authentication,
            operation,
        )
        .map_err(Failure::Session)?
        .map_err(Failure::from)
    }

    /// Fetch a batch before requesting the next. Each time links expire during the
    /// transfer, request fresh links for just the remaining files.
    fn fetch(
        &self,
        files: &[(String, u64)],
        cancel: &HttpCancellation,
        mut save: impl FnMut(&str, zeroize::Zeroizing<Vec<u8>>) -> Result<(), Failure>,
    ) -> Result<(), Failure> {
        let unavailable = || Failure::Cloud(RunFailure::Unreachable(UnreachableCategory::Server));
        for batch in capability_batches(files) {
            transfer_capability_batch(
                batch,
                |remaining| {
                    kept(self.api(cancel, |api| {
                        api.issue_record_download_capabilities(
                            &self.cloud.organization,
                            &self.cloud.run_id,
                            remaining,
                        )
                    })?)
                },
                |(sha, _), capability| {
                    let bytes =
                        self.api(cancel, |api| api.download_record_file(capability, cancel))?;
                    save(sha, bytes)
                },
                useful_support::utc_now,
                unavailable,
            )?;
        }
        Ok(())
    }

    fn transfer(
        &self,
        cancel: &HttpCancellation,
        commit: &DownloadCommitControl,
    ) -> Result<Downloaded, Failure> {
        match fs::symlink_metadata(&self.destination) {
            Ok(_) => return Err(Failure::Local("destination_exists")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(Failure::Local("invalid_destination")),
        }
        let (parent, _) =
            destination_parent(&self.destination).ok_or(Failure::Local("invalid_destination"))?;
        let staging_error = |_| Failure::Local("staging_unavailable");
        let staging = tempfile::Builder::new()
            .prefix(".useful-record-download-")
            .tempdir_in(parent)
            .map_err(staging_error)?;
        let files = staging.path().join("files");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&files)
            .map_err(staging_error)?;

        let facts = kept(self.api(cancel, |api| {
            api.get_run_record(&self.cloud.organization, &self.cloud.run_id)
        })?)?;
        let manifest_file = (
            facts.manifest.sha256.clone(),
            u64::try_from(facts.manifest.size_bytes)
                .map_err(|_| Failure::Local("integrity_mismatch"))?,
        );
        let mut manifest = zeroize::Zeroizing::new(Vec::new());
        self.fetch(&[manifest_file], cancel, |_, bytes| {
            manifest = bytes;
            Ok(())
        })?;
        let listed = portable_record_files(&manifest)?;
        if listed.run != facts.engine_run_id {
            return Err(Failure::Local("integrity_mismatch"));
        }
        self.fetch(&listed.files, cancel, |sha, bytes| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(files.join(sha))
                .and_then(|mut file| file.write_all(&bytes))
                .map_err(staging_error)
        })?;
        if cancel.is_cancelled() || !commit.begin_commit() {
            return Err(RunFailure::Interrupted.into());
        }
        let created = assemble_portable_record(&manifest, &files, &self.destination)?;
        Ok(Downloaded {
            engine_run_id: created.run,
            attempt_number: facts.attempt_number,
            sequence: facts.sequence,
            file_count: created.file_count,
            total_size_bytes: created.total_bytes,
        })
    }

    fn finish(&self, result: Result<Downloaded, Failure>) -> cli::CommandResult {
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(Failure::Local(outcome)) => return self.refuse(outcome, ExitCode::GeneralFailure),
            Err(Failure::Cloud(error)) => {
                return Ok(cloud_api::write_failure(
                    self.cloud.deployment.fingerprint().api_url(),
                    &self.cloud.organization,
                    Some(&self.cloud.run_id),
                    &error,
                    self.options.authentication.kind(),
                    self.options.json,
                )?);
            }
            Err(Failure::Session(error)) => return Err(error.into()),
        };
        if self.options.json {
            self.write_document("downloaded", Some(&receipt))?;
        } else {
            writeln!(
                io::stdout().lock(),
                "Downloaded record of {} ({}, attempt {}, sequence {}) to {} ({} files, {} bytes).",
                self.cloud.run_id,
                receipt.engine_run_id,
                receipt.attempt_number,
                receipt.sequence,
                normalize_terminal_path(&self.destination),
                receipt.file_count,
                receipt.total_size_bytes
            )
            .context("write record download output")?;
        }
        Ok(ExitCode::Success)
    }

    fn refuse(&self, outcome: &'static str, exit: ExitCode) -> cli::CommandResult {
        if self.options.json {
            self.write_document(outcome, None)?;
        } else {
            writeln!(
                io::stderr().lock(),
                "Record download for {} at {}: {outcome}.",
                self.cloud.run_id,
                normalize_terminal_path(&self.destination)
            )
            .context("write record download failure")?;
        }
        Ok(exit)
    }

    fn write_document(
        &self,
        outcome: &'static str,
        receipt: Option<&Downloaded>,
    ) -> anyhow::Result<()> {
        cloud_api::write_json(&Document {
            schema_version: 1,
            deployment: self.cloud.deployment.fingerprint().api_url(),
            outcome,
            organization_ref: &self.cloud.organization,
            run_id: &self.cloud.run_id,
            destination: &self.destination,
            receipt,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Document<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    organization_ref: &'a str,
    run_id: &'a str,
    destination: &'a std::path::Path,
    #[serde(flatten)]
    receipt: Option<&'a Downloaded>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Downloaded {
    engine_run_id: String,
    attempt_number: i32,
    sequence: i64,
    file_count: u64,
    total_size_bytes: u64,
}
