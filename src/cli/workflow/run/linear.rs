//! `useful workflow run linear list` (REQ-TRIGGER-145): the Linear state updates a Cloud run
//! made, which `RUN` names in Cloud alone in the organization in effect (REQ-LOCALRUN-180);
//! nothing under the `useful` home is read.

use std::io::{self, Write};

use clap::{Args, Subcommand};
use serde::Serialize;

use super::cloud_api as runs;
use super::target::{CloudOptions, CloudRunArg};
use crate::cli::context::OrgArgs;
use crate::cli::{self as cli, PaginationArgs, PrincipalAuthenticationKind};
use crate::exit_code::ExitCode;
use useful_api::{RunFailure, RunLinearLifecycleUpdate};

pub(super) const ABOUT: &str = "Read a Cloud run's Linear state updates";
const PATH: &[&str] = &["workflow", "run", "linear"];
const LIST: &str = "useful workflow run linear list";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<LinearLifecycleCommand>,
}

#[derive(Debug, Subcommand)]
enum LinearLifecycleCommand {
    #[command(about = "List the Linear state updates a run made, newest first")]
    List(ListCommand),
}

#[derive(Debug, Args)]
struct ListCommand {
    #[command(flatten)]
    run: CloudRunArg,
    #[command(flatten)]
    page: PaginationArgs<100>,
    #[command(flatten)]
    org: OrgArgs,
    #[command(flatten)]
    options: CloudOptions,
}

impl Command {
    pub(super) fn execute(self) -> cli::CommandResult {
        match self.command {
            None => cli::print_help(PATH),
            Some(LinearLifecycleCommand::List(command)) => command.execute(),
        }
    }
}

/// The run a lifecycle command names, as every envelope and diagnostic repeats it.
struct Target<'a> {
    deployment: &'a str,
    organization: &'a str,
    run_id: &'a str,
}

impl ListCommand {
    fn execute(self) -> cli::CommandResult {
        let cloud = match self.run.find(
            &self.org,
            &self.options.authentication,
            &self.options.http,
            LIST,
            self.options.json,
        ) {
            Ok(cloud) => cloud,
            Err(result) => return result,
        };
        cli::execute_read_only_with_signals("Cloud run Linear lifecycle list", move |control| {
            let result = runs::with_api(
                &cloud.deployment,
                self.options.http.transport_policy(),
                &self.options.authentication,
                |api| {
                    api.list_linear_lifecycle_updates(
                        &cloud.organization,
                        &cloud.run_id,
                        self.page.limit.map(u32::from),
                        self.page.cursor.as_deref(),
                    )
                },
            )?;
            cli::complete_read_only_output(control, || {
                let target = Target {
                    deployment: cloud.deployment.fingerprint().api_url(),
                    organization: &cloud.organization,
                    run_id: &cloud.run_id,
                };
                write_read(
                    &target,
                    "list",
                    result.as_ref(),
                    (self.options.authentication.kind(), self.options.json),
                    |page| ListPayload { updates: page },
                    |page| write_list(&page.items, page.next_cursor.as_deref()),
                )
                .map_err(Into::into)
            })
        })
    }
}

/// The JSON envelope every lifecycle command writes, with its operation's
/// members between the outcome and the error.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LinearLifecycleResult<'a, P> {
    schema_version: u8,
    operation: &'static str,
    deployment: &'a str,
    organization_ref: &'a str,
    run_id: &'a str,
    outcome: &'static str,
    #[serde(flatten)]
    payload: P,
    error: Option<LinearLifecycleError>,
}

#[derive(Serialize)]
struct ListPayload<'a, P> {
    updates: Option<&'a P>,
}

#[derive(Serialize)]
struct LinearLifecycleError {
    code: &'static str,
}

type Outcome = (&'static str, Option<LinearLifecycleError>, ExitCode);

fn write_envelope(
    target: &Target<'_>,
    operation: &'static str,
    outcome: &'static str,
    payload: impl Serialize,
    error: Option<LinearLifecycleError>,
) -> anyhow::Result<()> {
    runs::write_json(&LinearLifecycleResult {
        schema_version: 1,
        operation,
        deployment: target.deployment,
        organization_ref: target.organization,
        run_id: target.run_id,
        outcome,
        payload,
        error,
    })
}

/// Writes a read's envelope, or its value as `human` prints it, or its failure.
fn write_read<'v, V, P: Serialize>(
    target: &Target<'_>,
    operation: &'static str,
    result: Result<&'v V, &RunFailure>,
    (authentication, json): (PrincipalAuthenticationKind, bool),
    payload: impl FnOnce(Option<&'v V>) -> P,
    human: impl FnOnce(&V) -> anyhow::Result<()>,
) -> anyhow::Result<ExitCode> {
    let (outcome, error, exit) = match result {
        Ok(_) => ("found", None, ExitCode::Success),
        Err(failure) => failure_outcome(failure, authentication),
    };
    if json {
        write_envelope(target, operation, outcome, payload(result.ok()), error)?;
    } else if let Ok(value) = result {
        human(value)?;
    } else if let Some(error) = error {
        write_failure(target, operation, error.code, &[])?;
    }
    Ok(exit)
}

fn failure_outcome(failure: &RunFailure, authentication: PrincipalAuthenticationKind) -> Outcome {
    let (code, exit) = runs::failure_code(failure, authentication);
    let outcome = match failure {
        RunFailure::NotFound => "not_found",
        RunFailure::Conflict => "conflict",
        _ => "error",
    };
    (outcome, Some(LinearLifecycleError { code }), exit)
}

fn write_failure(
    target: &Target<'_>,
    operation: &str,
    code: &str,
    details: &[(&str, &str)],
) -> anyhow::Result<()> {
    let mut stderr = io::stderr().lock();
    writeln!(
        stderr,
        "error: Cloud run Linear lifecycle {operation}: {code}\n\nrun: {}\norganization: {}",
        target.run_id, target.organization
    )?;
    for (label, value) in details {
        writeln!(stderr, "{label}: {value}")?;
    }
    Ok(())
}

/// Writes each update as `useful workflow run show` writes the latest one, newest first with a blank
/// line between updates, then the cursor of a page that is not the last.
fn write_list(
    updates: &[RunLinearLifecycleUpdate],
    next_cursor: Option<&str>,
) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    for (index, update) in updates.iter().enumerate() {
        if index > 0 {
            writeln!(stdout)?;
        }
        runs::write_linear_lifecycle_update(&mut stdout, update, "")?;
    }
    if let Some(cursor) = next_cursor {
        if !updates.is_empty() {
            writeln!(stdout)?;
        }
        writeln!(stdout, "next cursor: {cursor}")?;
    }
    Ok(())
}
