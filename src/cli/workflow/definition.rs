//! `useful workflow definition`: the definitions under the `useful` home and those of the
//! project in effect, each named by its ID or its name. The Cloud leaves share one client
//! of the public API and its resend rule.

mod change;
mod cloud_report;
mod enabled;
mod evaluation;
mod list;
mod publish;
pub(in crate::cli::workflow) mod report;
mod show;
pub(in crate::cli) mod target;

pub(in crate::cli) use publish::parse_binding;

use anyhow::{Context, anyhow};
use clap::{Args, Subcommand};

use crate::exit_code::ExitCode;
use target::Options;
use useful_api::{HttpClient, WorkflowDefinitionApi, WorkflowDefinitionFailure};
use useful_execution::DefinitionError;
use useful_human_auth::Deployment;

pub(super) const ABOUT: &str = "Work with workflow definitions under the useful home and in Cloud";
const COMMAND_PATH: &[&str] = &["workflow", "definition"];

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<DefinitionCommand>,
}

#[derive(Debug, Subcommand)]
enum DefinitionCommand {
    #[command(about = change::ARCHIVE_ABOUT)]
    Archive(change::Target),
    #[command(about = change::DELETE_ABOUT)]
    Delete(change::Delete),
    #[command(about = enabled::DISABLE_ABOUT)]
    Disable(enabled::Command),
    #[command(about = enabled::ENABLE_ABOUT)]
    Enable(enabled::Command),
    #[command(about = evaluation::ABOUT)]
    Evaluation(evaluation::Command),
    #[command(about = list::ABOUT)]
    List(list::Command),
    #[command(about = publish::ABOUT)]
    Publish(publish::Command),
    #[command(about = show::ABOUT)]
    Show(show::Command),
    #[command(about = change::UNARCHIVE_ABOUT)]
    Unarchive(change::Target),
    #[command(about = change::UPDATE_ABOUT)]
    Update(change::Update),
}

impl Command {
    pub(super) fn execute(self) -> super::super::CommandResult {
        match self.command {
            None => super::super::print_help(COMMAND_PATH),
            Some(DefinitionCommand::Archive(command)) => command.execute(change::Change::Archive),
            Some(DefinitionCommand::Delete(command)) => command.execute(),
            Some(DefinitionCommand::Disable(command)) => command.execute(false),
            Some(DefinitionCommand::Enable(command)) => command.execute(true),
            Some(DefinitionCommand::Evaluation(command)) => command.execute(),
            Some(DefinitionCommand::List(command)) => command.execute(),
            Some(DefinitionCommand::Publish(command)) => command.execute(),
            Some(DefinitionCommand::Show(command)) => command.execute(),
            Some(DefinitionCommand::Unarchive(command)) => {
                command.execute(change::Change::Unarchive)
            }
            Some(DefinitionCommand::Update(command)) => command.execute(),
        }
    }
}

/// Writes the outcome of a definition command over the home: `write` with the result and
/// whether `--json` was given, exit 0, or the refusal headed by `refused`, exit 1.
fn finish<T>(
    command: &'static str,
    refused: &str,
    result: Result<T, DefinitionError>,
    json: bool,
    write: impl FnOnce(&T, bool) -> anyhow::Result<()>,
) -> super::super::CommandResult {
    let (written, exit_code) = match result {
        Ok(value) => (write(&value, json), ExitCode::Success),
        Err(error) => (
            report::write_refused(command, refused, &error, json),
            ExitCode::GeneralFailure,
        ),
    };
    written.with_context(|| format!("write {command} result"))?;
    Ok(exit_code)
}

/// `yes` or `no` for a human report field.
fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// Sends a keyed request, and sends it once more, at once, when Cloud does not answer or
/// answers with a transient problem: the caller keeps the key, so a request Cloud applied
/// before its answer was lost is answered again, not applied twice.
fn resend_once<T>(
    mut send: impl FnMut() -> Result<T, WorkflowDefinitionFailure>,
) -> Result<T, WorkflowDefinitionFailure> {
    match send() {
        Err(WorkflowDefinitionFailure::Unreachable { .. }) => send(),
        sent => sent,
    }
}

/// Runs `operation` against the deployment under the leaf's session, again with a refreshed
/// session when the first is rejected.
fn with_api<T>(
    deployment: &Deployment,
    options: &Options,
    mut operation: impl FnMut(&WorkflowDefinitionApi<'_>) -> Result<T, WorkflowDefinitionFailure>,
) -> anyhow::Result<Result<T, WorkflowDefinitionFailure>> {
    let client = HttpClient::new(options.http.transport_policy())
        .map_err(|error| anyhow!(error))
        .context("prepare workflow definition networking")?;
    super::super::execute_selected_api_operation(
        super::super::principal_api_context(
            &client,
            deployment,
            &options.authentication,
            "acquire human session",
        ),
        |token| {
            let api =
                WorkflowDefinitionApi::new(deployment.fingerprint().api_url(), token, &client)
                    .map_err(|error| anyhow!(error))
                    .context("prepare workflow definition API")?;
            Ok(operation(&api))
        },
        WorkflowDefinitionFailure::credential_rejected,
        || WorkflowDefinitionFailure::Unauthenticated,
        |category| WorkflowDefinitionFailure::Unreachable { category },
    )
}
