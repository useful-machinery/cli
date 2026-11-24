//! Capture a local run or restore it under the current home.

mod download;

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Args, Subcommand};
use serde::Serialize;
use useful_execution::{
    DefinitionError, LocalRunDirectoryError, OpenedPortableRecord, PortableRecordError, RunState,
    SubjectClaim, WorkflowHome, create_portable_record, locate_run, normalize_terminal_path,
    open_portable_record, read_definition, restore_portable_record,
};

use super::control::{JsonOutput, Refusal, home_miss, run_locked, write_refusal};
use super::target::RunArg;
use crate::cli::{CommandResult, print_help, write_pretty_json};
use crate::exit_code::ExitCode;

pub(super) const ABOUT: &str = "Move a workflow run's record between hosts";
const CREATE: &str = "useful workflow run record create";
const RESTORE: &str = "useful workflow run record restore";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<RecordCommand>,
}

#[derive(Debug, Subcommand)]
enum RecordCommand {
    #[command(about = "Create a portable record of a local run")]
    Create {
        #[command(flatten)]
        run: RunArg,
        #[arg(
            long,
            value_name = "DIRECTORY",
            help = "New directory for the portable run record"
        )]
        output: PathBuf,
        #[command(flatten)]
        format: JsonOutput,
    },
    #[command(about = "Download a Cloud run's kept record")]
    Download(download::DownloadCommand),
    #[command(about = "Restore a portable run record under the useful home")]
    Restore {
        #[arg(
            value_name = "DIRECTORY",
            help = "Directory holding the portable run record"
        )]
        directory: PathBuf,
        #[command(flatten)]
        format: JsonOutput,
    },
}

impl Command {
    pub(super) fn execute(self) -> CommandResult {
        match self.command {
            None => print_help(&["workflow", "run", "record"]),
            Some(RecordCommand::Create {
                run,
                output,
                format,
            }) => create(run, &output, format.json),
            Some(RecordCommand::Download(command)) => command.execute(),
            Some(RecordCommand::Restore { directory, format }) => restore(&directory, format.json),
        }
    }
}

/// The refusal of `error`: its code and a sentence saying what was found, naming the path
/// when the error has one.
fn portable_refusal(error: PortableRecordError) -> Refusal {
    let message = match &error {
        PortableRecordError::RunLocked => return run_locked(),
        PortableRecordError::OwnershipUnproven { reason, .. } => format!(
            "The processes the run's attempts recorded could not be proven stopped ({}); {}.",
            reason.as_str(),
            reason.remedy()
        ),
        PortableRecordError::RunChanging => "The run changed during capture. Try again.".to_owned(),
        PortableRecordError::ChildRun => {
            "A child run has no record of its own; name its root run.".to_owned()
        }
        PortableRecordError::RunRecordMissing => {
            "The run has no run record, so it has no ID to restore under.".to_owned()
        }
        PortableRecordError::RunDirectoryInvalid(cause) => {
            format!("The run directory is not valid: {cause}.")
        }
        PortableRecordError::DestinationExists => {
            "The destination already exists; name a directory that does not.".to_owned()
        }
        PortableRecordError::RecordIncomplete(path) => {
            format!("The record is missing {}.", normalize_terminal_path(path))
        }
        PortableRecordError::RecordAltered(path) => format!(
            "The record's {} does not match record.json.",
            normalize_terminal_path(path)
        ),
        PortableRecordError::RecordInvalid(path) => format!(
            "The record's {} is not valid.",
            normalize_terminal_path(path)
        ),
        PortableRecordError::RecordUnavailable { path, source } => {
            format!("{}: {source}.", normalize_terminal_path(path))
        }
    };
    Refusal::new(error.code(), message)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordDocument<'a> {
    schema_version: u8,
    command: &'static str,
    outcome: &'static str,
    exit_status: u8,
    run: &'a str,
    run_directory: &'a Path,
    record: &'a Path,
    #[serde(flatten)]
    counts: Option<Counts>,
}

#[derive(Serialize)]
struct Counts {
    files: u64,
    bytes: u64,
}

fn create(run: RunArg, output: &Path, json: bool) -> CommandResult {
    let directory = match run.home_only() {
        Ok(directory) => directory,
        Err(error) => {
            let error = home_miss(
                error,
                "Download a Cloud run's record with useful workflow run record download.",
            );
            return write_refusal(CREATE, None, &Refusal::new(error.code, error.message), json);
        }
    };
    let created = match create_portable_record(&directory, output) {
        Ok(created) => created,
        Err(error) => {
            return write_refusal(CREATE, Some(&directory), &portable_refusal(error), json);
        }
    };
    if json {
        write_pretty_json(&RecordDocument {
            schema_version: 1,
            command: CREATE,
            outcome: "created",
            exit_status: 0,
            run: &created.run,
            run_directory: &directory,
            record: &created.record_directory,
            counts: Some(Counts {
                files: created.file_count,
                bytes: created.total_bytes,
            }),
        })
    } else {
        writeln!(
            io::stdout().lock(),
            "Created record of {} at {} ({} files, {} bytes).",
            created.run,
            normalize_terminal_path(&created.record_directory),
            created.file_count,
            created.total_bytes
        )
    }
    .context("write workflow run record create output")?;
    Ok(ExitCode::Success)
}

fn restore(directory: &Path, json: bool) -> CommandResult {
    let record = match open_portable_record(directory) {
        Ok(record) => record,
        Err(error) => return write_refusal(RESTORE, None, &portable_refusal(error), json),
    };
    let destination = match install(&record) {
        Ok(destination) => destination,
        Err(refusal) => return write_refusal(RESTORE, None, &refusal, json),
    };
    let id = &record.run().id;
    if json {
        write_pretty_json(&RecordDocument {
            schema_version: 1,
            command: RESTORE,
            outcome: "restored",
            exit_status: 0,
            run: id,
            run_directory: &destination,
            record: directory,
            counts: None,
        })
    } else {
        writeln!(
            io::stdout().lock(),
            "Restored {} at {}.",
            id,
            normalize_terminal_path(&destination)
        )
    }
    .context("write workflow run record restore output")?;
    Ok(ExitCode::Success)
}

fn home_refusal(error: DefinitionError) -> Refusal {
    Refusal::new(error.code(), error.to_string())
}

fn install(record: &OpenedPortableRecord) -> Result<PathBuf, Refusal> {
    let run = record.run();
    let home = WorkflowHome::from_environment().map_err(home_refusal)?;
    let exists = |path: &Path| {
        Refusal::new(
            "run_exists",
            format!(
                "Run {} already exists at {}.",
                run.id,
                normalize_terminal_path(path)
            ),
        )
    };
    match locate_run(&home, &run.id) {
        Ok(path) => return Err(exists(&path)),
        Err(LocalRunDirectoryError::RunNotFound) => (),
        Err(error) => return Err(Refusal::new("run_directory_unavailable", error.to_string())),
    }

    let definition = run
        .definition
        .as_deref()
        .filter(|id| read_definition(&home, id).is_ok());
    let parent = match definition {
        Some(id) => home.create_runs_directory(id),
        None => home.create_home_runs_directory(),
    }
    .map_err(home_refusal)?;
    let destination = parent.join(&run.id);
    let claim = match (definition, run.subject.as_deref(), run.state) {
        (Some(id), Some(subject), RunState::Running | RunState::Waiting) => Some(
            SubjectClaim::take(&home, id, subject, None).map_err(|error| {
                if error.run() == Some(&run.id) {
                    exists(&destination)
                } else {
                    Refusal::new(
                        error.code().unwrap_or("subject_index_unavailable"),
                        error.to_string(),
                    )
                }
            })?,
        ),
        _ => None,
    };
    restore_portable_record(record, &destination).map_err(|error| {
        if matches!(error, PortableRecordError::DestinationExists)
            && let Ok(path) = locate_run(&home, &run.id)
        {
            return exists(&path);
        }
        portable_refusal(error)
    })?;
    if let Some(claim) = claim {
        claim
            .name(&run.id)
            .map_err(|error| Refusal::new("subject_index_unavailable", error.to_string()))?;
    }
    Ok(destination)
}
