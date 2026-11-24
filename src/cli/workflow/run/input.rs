//! `useful workflow run input`: the inputs a Cloud run retains, which `RUN` names in Cloud
//! alone in the organization in effect; nothing under the `useful` home is read.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use anyhow::Context as _;
use clap::{Args, Subcommand};
use serde::Serialize;

use super::cloud_api as runs;
use super::target::{CloudOptions, CloudRunArg, InCloud};
use crate::cli::context::OrgArgs;
use crate::cli::{self as cli, PrincipalAuthenticationKind};
use crate::exit_code::ExitCode;
use useful_api::{
    RetainedRunInputs, RunFailure, UnreachableCategory, capability_batches, retained_manifest,
    transfer_capability_batch,
};

pub(super) const ABOUT: &str = "Manage the inputs a Cloud run retains";
const PATH: &[&str] = &["workflow", "run", "input"];
const SHOW: &str = "useful workflow run input show";
const DOWNLOAD: &str = "useful workflow run input download";
const DELETE: &str = "useful workflow run input delete";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<InputsCommand>,
}

#[derive(Debug, Subcommand)]
enum InputsCommand {
    #[command(
        about = "Delete a run's retained inputs",
        after_help = "Deletion:\n  Retained input content becomes logically unavailable; cleanup is scheduled."
    )]
    Delete(DeleteCommand),
    #[command(
        about = "Download a run's inputs, verified",
        after_help = "Download:\n  Verified members are committed together; no partial result is left at the destination."
    )]
    Download(DownloadCommand),
    #[command(about = "List the inputs a run retains")]
    Show(ShowCommand),
}

#[derive(Debug, Args)]
struct ShowCommand {
    #[command(flatten)]
    run: CloudRunArg,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: CloudOptions,
}

#[derive(Debug, Args)]
struct DownloadCommand {
    #[command(flatten)]
    run: CloudRunArg,

    #[arg(
        long,
        value_name = "DIRECTORY",
        help = "Directory to create for the complete input download (must not already exist)"
    )]
    output: PathBuf,

    #[arg(
        long = "member",
        value_name = "MEMBER",
        action = clap::ArgAction::Append,
        help = "Download one exact logical member (repeat to select more)"
    )]
    members: Vec<String>,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: CloudOptions,
}

#[derive(Debug, Args)]
struct DeleteCommand {
    #[command(flatten)]
    run: CloudRunArg,

    #[command(flatten)]
    confirmation: cli::ConfirmationArgs,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: CloudOptions,
}

impl Command {
    pub(super) fn execute(self) -> cli::CommandResult {
        match self.command {
            None => cli::print_help(PATH),
            Some(InputsCommand::Show(command)) => command.execute(),
            Some(InputsCommand::Download(command)) => command.execute(),
            Some(InputsCommand::Delete(command)) => command.execute(),
        }
    }
}

/// The Cloud run `run` names for the leaf `command`, or the leaf's result when none is found.
fn find(
    run: &CloudRunArg,
    org: &OrgArgs,
    options: &CloudOptions,
    command: &'static str,
) -> Result<InCloud, cli::CommandResult> {
    run.find(
        org,
        &options.authentication,
        &options.http,
        command,
        options.json,
    )
}

impl ShowCommand {
    fn execute(self) -> cli::CommandResult {
        let cloud = match find(&self.run, &self.org, &self.options, SHOW) {
            Ok(cloud) => cloud,
            Err(result) => return result,
        };
        cli::execute_read_only_with_signals("retained input show", move |control| {
            let result = runs::with_api(
                &cloud.deployment,
                self.options.http.transport_policy(),
                &self.options.authentication,
                |api| api.get_retained_inputs(&cloud.organization, &cloud.run_id),
            )?;
            cli::complete_read_only_output(control, || {
                write_inventory(
                    cloud.deployment.fingerprint().api_url(),
                    &cloud.organization,
                    &cloud.run_id,
                    result,
                    self.options.authentication.kind(),
                    self.options.json,
                )
                .map_err(Into::into)
            })
        })
    }
}

const DOWNLOAD_STAGING: u8 = 0;
const DOWNLOAD_CANCELLED: u8 = 1;
const DOWNLOAD_COMMITTING: u8 = 2;

pub(super) struct DownloadCommitControl {
    state: AtomicU8,
}

impl DownloadCommitControl {
    pub(super) const fn new() -> Self {
        Self {
            state: AtomicU8::new(DOWNLOAD_STAGING),
        }
    }

    pub(super) fn begin_commit(&self) -> bool {
        self.state
            .compare_exchange(
                DOWNLOAD_STAGING,
                DOWNLOAD_COMMITTING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    pub(super) fn interrupt(&self) -> bool {
        match self.state.compare_exchange(
            DOWNLOAD_STAGING,
            DOWNLOAD_CANCELLED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) | Err(DOWNLOAD_CANCELLED) => false,
            Err(DOWNLOAD_COMMITTING) => true,
            Err(_) => true,
        }
    }
}

impl DownloadCommand {
    fn execute(self) -> cli::CommandResult {
        let cloud = match find(&self.run, &self.org, &self.options, DOWNLOAD) {
            Ok(cloud) => cloud,
            Err(result) => return result,
        };
        let json_destination = if self.options.json {
            self.output.to_str().map(str::to_owned).context(
                "retained input download destination must be valid UTF-8 for JSON output",
            )?
        } else {
            String::new()
        };
        let signal_json_destination = json_destination.clone();
        let commit_control = Arc::new(DownloadCommitControl::new());
        let operation_commit_control = Arc::clone(&commit_control);
        let signal_commit_control = Arc::clone(&commit_control);
        let signal_deployment = cloud.deployment.clone();
        let signal_organization = cloud.organization.clone();
        let signal_run_id = cloud.run_id.clone();
        let signal_destination = self.output.clone();
        let signal_json = self.options.json;
        cli::execute_cancellable_mutation_with_signals(
            "retained input download",
            move |cancellation, control| {
                let result =
                    download_selected(&cloud, &self, cancellation, &operation_commit_control)?;
                if cancellation.is_cancelled() {
                    return Ok(ExitCode::GeneralFailure);
                }
                cli::complete_operation(control, || {
                    write_download(
                        cloud.deployment.fingerprint().api_url(),
                        &cloud.organization,
                        &cloud.run_id,
                        ReportedDestination {
                            path: &self.output,
                            json: &json_destination,
                        },
                        result,
                        self.options.authentication.kind(),
                        self.options.json,
                    )
                    .map_err(Into::into)
                })
            },
            move || signal_commit_control.interrupt(),
            move |signal, commitment_unknown| {
                write_download_interrupted(
                    signal_deployment.fingerprint().api_url(),
                    &signal_organization,
                    &signal_run_id,
                    ReportedDestination {
                        path: &signal_destination,
                        json: &signal_json_destination,
                    },
                    signal_json,
                    commitment_unknown,
                    signal,
                )
                .map_err(Into::into)
            },
        )
    }
}

#[derive(Debug)]
enum DownloadFailure {
    Api {
        failure: RunFailure,
        input_set_id: Option<String>,
    },
    DestinationInvalid,
    DestinationExists,
    StagingUnavailable,
    CommitUnavailable,
    CommitUnconfirmed,
}

enum DownloadTransferFailure {
    Fatal(anyhow::Error),
    Download(DownloadFailure),
}

fn download_selected(
    cloud: &InCloud,
    command: &DownloadCommand,
    cancellation: &useful_api::HttpCancellation,
    commit_control: &DownloadCommitControl,
) -> anyhow::Result<Result<DownloadedInputs, DownloadFailure>> {
    let Some((parent, destination_name)) = destination_parent(&command.output) else {
        return Ok(Err(DownloadFailure::DestinationInvalid));
    };
    if std::fs::symlink_metadata(&command.output).is_ok() {
        return Ok(Err(DownloadFailure::DestinationExists));
    }
    let deployment = &cloud.deployment;
    let inventory = match runs::with_api(
        deployment,
        command.options.http.transport_policy(),
        &command.options.authentication,
        |api| api.get_retained_inputs(&cloud.organization, &cloud.run_id),
    )? {
        Ok(inventory) => inventory,
        Err(failure) => return Ok(Err(download_api_failure(failure, None))),
    };
    let manifest = match retained_manifest(&inventory) {
        Ok(manifest) => manifest,
        Err(failure) => {
            return Ok(Err(download_api_failure(
                failure,
                Some(&inventory.input_set_id),
            )));
        }
    };
    let all_members = manifest.objects();
    let members = match select_members(all_members, &command.members) {
        Ok(members) => members,
        Err(failure) => {
            return Ok(Err(download_api_failure(
                failure,
                Some(&inventory.input_set_id),
            )));
        }
    };
    let total_size_bytes = members.iter().map(|member| member.size_bytes).sum();
    let staging = match tempfile::Builder::new()
        .prefix(".useful-input-download-")
        .tempdir_in(&parent)
    {
        Ok(staging) => staging,
        Err(_) => return Ok(Err(DownloadFailure::StagingUnavailable)),
    };
    if std::fs::create_dir(staging.path().join("inputs")).is_err() {
        return Ok(Err(DownloadFailure::StagingUnavailable));
    }

    for batch in capability_batches(&members) {
        let transferred = transfer_capability_batch(
            batch,
            |remaining| {
                if cancellation.is_cancelled() {
                    return Err(DownloadTransferFailure::Download(download_api_failure(
                        RunFailure::Interrupted,
                        Some(&inventory.input_set_id),
                    )));
                }
                match runs::with_api(
                    deployment,
                    command.options.http.transport_policy(),
                    &command.options.authentication,
                    |api| {
                        api.issue_input_download_capabilities(
                            &cloud.organization,
                            &cloud.run_id,
                            &inventory,
                            remaining,
                        )
                    },
                ) {
                    Ok(Ok(capabilities)) => Ok(capabilities),
                    Ok(Err(failure)) => Err(DownloadTransferFailure::Download(
                        download_api_failure(failure, Some(&inventory.input_set_id)),
                    )),
                    Err(error) => Err(DownloadTransferFailure::Fatal(error)),
                }
            },
            |_, capability| {
                if cancellation.is_cancelled() {
                    return Err(DownloadTransferFailure::Download(download_api_failure(
                        RunFailure::Interrupted,
                        Some(&inventory.input_set_id),
                    )));
                }
                let path = staging.path().join(&capability.metadata.member_id);
                if let Some(parent) = path.parent()
                    && std::fs::create_dir_all(parent).is_err()
                {
                    return Err(DownloadTransferFailure::Download(
                        DownloadFailure::StagingUnavailable,
                    ));
                }
                let bytes = match runs::with_api(
                    deployment,
                    command.options.http.transport_policy(),
                    &command.options.authentication,
                    |api| api.download_input_member(capability, cancellation),
                ) {
                    Ok(Ok(bytes)) => bytes,
                    Ok(Err(failure)) => {
                        return Err(DownloadTransferFailure::Download(download_api_failure(
                            failure,
                            Some(&inventory.input_set_id),
                        )));
                    }
                    Err(error) => return Err(DownloadTransferFailure::Fatal(error)),
                };
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .map_err(|_| {
                        DownloadTransferFailure::Download(DownloadFailure::StagingUnavailable)
                    })?;
                file.write_all(&bytes)
                    .and_then(|()| file.flush())
                    .and_then(|()| file.sync_all())
                    .map_err(|_| {
                        DownloadTransferFailure::Download(DownloadFailure::StagingUnavailable)
                    })
            },
            useful_support::utc_now,
            || {
                DownloadTransferFailure::Download(download_api_failure(
                    RunFailure::Unreachable(UnreachableCategory::Server),
                    Some(&inventory.input_set_id),
                ))
            },
        );
        match transferred {
            Ok(()) => {}
            Err(DownloadTransferFailure::Fatal(error)) => return Err(error),
            Err(DownloadTransferFailure::Download(failure)) => return Ok(Err(failure)),
        }
    }
    if cancellation.is_cancelled() {
        return Ok(Err(DownloadFailure::Api {
            failure: RunFailure::Interrupted,
            input_set_id: Some(inventory.input_set_id.clone()),
        }));
    }
    if sync_tree(staging.path()).is_err() {
        return Ok(Err(DownloadFailure::StagingUnavailable));
    }
    if cancellation.is_cancelled() || !commit_control.begin_commit() {
        return Ok(Err(DownloadFailure::Api {
            failure: RunFailure::Interrupted,
            input_set_id: Some(inventory.input_set_id.clone()),
        }));
    }
    match cli::atomic_directory::commit_noreplace(staging, &parent, destination_name) {
        Ok(()) => {}
        Err(cli::atomic_directory::CommitError::DestinationExists) => {
            return Ok(Err(DownloadFailure::DestinationExists));
        }
        Err(cli::atomic_directory::CommitError::Unavailable) => {
            return Ok(Err(DownloadFailure::CommitUnavailable));
        }
        Err(cli::atomic_directory::CommitError::DurabilityUnconfirmed) => {
            return Ok(Err(DownloadFailure::CommitUnconfirmed));
        }
    }
    Ok(Ok(DownloadedInputs {
        input_set_id: inventory.input_set_id,
        member_count: members.len(),
        total_size_bytes,
    }))
}

fn download_api_failure(failure: RunFailure, input_set_id: Option<&str>) -> DownloadFailure {
    DownloadFailure::Api {
        failure,
        input_set_id: input_set_id.map(str::to_owned),
    }
}

pub(super) fn destination_parent(destination: &Path) -> Option<(PathBuf, &std::ffi::OsStr)> {
    let name = destination.file_name().filter(|name| !name.is_empty())?;
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::metadata(parent)
        .ok()?
        .is_dir()
        .then(|| (parent.to_owned(), name))
}

fn select_members(
    all_members: Vec<useful_api::RunInputObjectMetadata>,
    requested: &[String],
) -> Result<Vec<useful_api::RunInputObjectMetadata>, RunFailure> {
    if requested.is_empty() {
        return Ok(all_members);
    }
    let selected = requested.iter().map(String::as_str).collect::<HashSet<_>>();
    if selected.len() != requested.len()
        || !selected.iter().all(|member_id| {
            all_members
                .iter()
                .any(|member| member.member_id == *member_id)
        })
    {
        return Err(RunFailure::InvalidInput);
    }
    Ok(all_members
        .into_iter()
        .filter(|member| selected.contains(member.member_id.as_str()))
        .collect())
}

fn sync_tree(root: &Path) -> io::Result<()> {
    fn sync_directory(path: &Path) -> io::Result<()> {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                sync_directory(&entry.path())?;
            }
        }
        File::open(path)?.sync_all()
    }

    sync_directory(root)
}

impl DeleteCommand {
    fn execute(self) -> cli::CommandResult {
        let cloud = match find(&self.run, &self.org, &self.options, DELETE) {
            Ok(cloud) => cloud,
            Err(result) => return result,
        };
        let key = useful_support::generate_idempotency_key()
            .context("generate retained input deletion identity")?;
        let signal_deployment = cloud.deployment.clone();
        let signal_organization = cloud.organization.clone();
        let signal_run_id = cloud.run_id.clone();
        let signal_json = self.options.json;
        cli::execute_mutation_with_signals(
            "retained input deletion",
            (),
            move |control| {
                let result = runs::with_api(
                    &cloud.deployment,
                    self.options.http.transport_policy(),
                    &self.options.authentication,
                    |api| {
                        api.delete_retained_inputs(&cloud.organization, &cloud.run_id, &key, || {
                            control.begin_dispatch()
                        })
                    },
                )?;
                runs::finish_operation(control, || {
                    write_delete(
                        cloud.deployment.fingerprint().api_url(),
                        &cloud.organization,
                        &cloud.run_id,
                        result,
                        self.options.authentication.kind(),
                        self.options.json,
                    )
                })
            },
            move |signal, snapshot| {
                cli::report_dispatched_signal(signal, snapshot, |()| {
                    runs::write_resource_mutation_unknown(
                        "retained input deletion",
                        signal_deployment.fingerprint().api_url(),
                        &signal_organization,
                        "run",
                        Some(&signal_run_id),
                        signal_json,
                        signal,
                    )
                    .map_err(Into::into)
                })
            },
        )
    }
}

fn write_inventory(
    deployment: &str,
    organization: &str,
    run_id: &str,
    result: Result<RetainedRunInputs, RunFailure>,
    authentication: PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    write_run_outcome(
        deployment,
        organization,
        run_id,
        result,
        authentication,
        json,
        |inventory| {
            if json {
                runs::write_json(&InventoryResult {
                    schema_version: 1,
                    deployment,
                    outcome: "found",
                    inventory: &inventory,
                })?;
            } else {
                let mut stdout = io::stdout().lock();
                writeln!(stdout, "✓ Retained run inputs found.\n")?;
                writeln!(stdout, "run: {run_id}")?;
                writeln!(stdout, "input set: {}", inventory.input_set_id)?;
                writeln!(stdout, "availability: available")?;
                writeln!(stdout, "inputs: {}", inventory.input_count)?;
                writeln!(stdout, "attachment members: {}", inventory.attachment_count)?;
                writeln!(stdout, "bytes: {}", inventory.aggregate_size_bytes)?;
                writeln!(
                    stdout,
                    "content expires: {}",
                    inventory
                        .content_expires_at
                        .as_deref()
                        .unwrap_or("not scheduled")
                )?;
                writeln!(stdout, "organization: {organization}")?;
                writeln!(stdout, "deployment: {deployment}")?;
            }
            Ok(())
        },
    )
}

fn write_download(
    deployment: &str,
    organization: &str,
    run_id: &str,
    destination: ReportedDestination<'_>,
    result: Result<DownloadedInputs, DownloadFailure>,
    authentication: PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    match result {
        Ok(downloaded) => {
            if json {
                runs::write_json(&DownloadResult {
                    schema_version: 1,
                    deployment,
                    outcome: "downloaded",
                    organization_ref: organization,
                    run_id,
                    input_set_id: &downloaded.input_set_id,
                    destination: destination.json,
                    member_count: downloaded.member_count,
                    total_size_bytes: downloaded.total_size_bytes,
                })?;
            } else {
                writeln!(
                    io::stdout().lock(),
                    "✓ Retained inputs downloaded.\n\nrun: {run_id}\ninput set: {}\nmembers: {}\nbytes: {}\ndestination: {}\norganization: {organization}\ndeployment: {deployment}",
                    downloaded.input_set_id,
                    downloaded.member_count,
                    downloaded.total_size_bytes,
                    destination.path.display()
                )?;
            }
            Ok(ExitCode::Success)
        }
        Err(DownloadFailure::Api {
            failure,
            input_set_id,
        }) => runs::write_failure_with_input_set(
            deployment,
            organization,
            Some(run_id),
            input_set_id.as_deref(),
            &failure,
            authentication,
            json,
        ),
        Err(failure) => {
            let outcome = match &failure {
                DownloadFailure::DestinationInvalid => "invalid_destination",
                DownloadFailure::DestinationExists => "destination_exists",
                DownloadFailure::StagingUnavailable => "staging_unavailable",
                DownloadFailure::CommitUnavailable => "commit_unavailable",
                DownloadFailure::CommitUnconfirmed => "commitment_unknown",
                DownloadFailure::Api { .. } => "api_failure",
            };
            if json {
                runs::write_json(&DownloadFailureResult {
                    schema_version: 1,
                    deployment,
                    outcome,
                    organization_ref: organization,
                    run_id,
                    destination: destination.json,
                })?;
            } else if matches!(failure, DownloadFailure::CommitUnconfirmed) {
                writeln!(
                    io::stderr().lock(),
                    "error: retained input download commit is unconfirmed\n\ndestination: {}\n\nInspect the destination before retrying.",
                    destination.path.display()
                )?;
            } else {
                writeln!(
                    io::stderr().lock(),
                    "error: retained input download failed: {outcome}\n\ndestination: {}\n\nNo downloaded result was committed. Check the new destination path and try again.",
                    destination.path.display()
                )?;
            }
            Ok(ExitCode::GeneralFailure)
        }
    }
}

struct ReportedDestination<'a> {
    path: &'a Path,
    json: &'a str,
}

fn write_download_interrupted(
    deployment: &str,
    organization: &str,
    run_id: &str,
    destination: ReportedDestination<'_>,
    json: bool,
    commitment_unknown: bool,
    exit_code: ExitCode,
) -> anyhow::Result<ExitCode> {
    let outcome = if commitment_unknown {
        "commitment_unknown"
    } else {
        "interrupted"
    };
    if json {
        runs::write_json(&DownloadFailureResult {
            schema_version: 1,
            deployment,
            outcome,
            organization_ref: organization,
            run_id,
            destination: destination.json,
        })?;
    } else if commitment_unknown {
        writeln!(
            io::stderr().lock(),
            "error: retained input download commit status is unknown\n\ndestination: {}\n\nInspect the destination before retrying.",
            destination.path.display()
        )?;
    } else {
        writeln!(
            io::stderr().lock(),
            "error: retained input download was interrupted\n\ndestination: {}\n\nNo downloaded result was committed. Run the command again to start with fresh capabilities.",
            destination.path.display()
        )?;
    }
    Ok(exit_code)
}

// Retained-input deletion emits a mutation receipt while inventory emits the full retained-input
// projection; each closure stays next to its machine contract.
fn write_delete(
    deployment: &str,
    organization: &str,
    run_id: &str,
    result: Result<(), RunFailure>,
    authentication: PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    write_run_outcome(
        deployment,
        organization,
        run_id,
        result,
        authentication,
        json,
        |()| {
            if json {
                runs::write_json(&DeleteResult {
                    schema_version: 1,
                    deployment,
                    outcome: "deleted",
                    organization_ref: organization,
                    run_id,
                })?;
            } else {
                writeln!(
                    io::stdout().lock(),
                    "✓ Retained input content made logically unavailable; cleanup scheduled.\n\nrun: {run_id}\norganization: {organization}\ndeployment: {deployment}"
                )?;
            }
            Ok(())
        },
    )
}

fn write_run_outcome<T>(
    deployment: &str,
    organization: &str,
    run_id: &str,
    result: Result<T, RunFailure>,
    authentication: PrincipalAuthenticationKind,
    json: bool,
    write_success: impl FnOnce(T) -> anyhow::Result<()>,
) -> anyhow::Result<ExitCode> {
    runs::write_api_outcome(result, write_success, |failure| {
        runs::write_failure(
            deployment,
            organization,
            Some(run_id),
            failure,
            authentication,
            json,
        )
    })
}

struct DownloadedInputs {
    input_set_id: String,
    member_count: usize,
    total_size_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InventoryResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    inventory: &'a RetainedRunInputs,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DownloadResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    organization_ref: &'a str,
    run_id: &'a str,
    input_set_id: &'a str,
    destination: &'a str,
    member_count: usize,
    total_size_bytes: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DownloadFailureResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    organization_ref: &'a str,
    run_id: &'a str,
    destination: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    organization_ref: &'a str,
    run_id: &'a str,
}
