use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, anyhow};
use clap::Args;
use serde::Serialize;

use crate::exit_code::{ExitCode, OutcomeClass};
use useful_runner::{
    AgentLoginProvider, AgentLoginReadiness, ControlError, CredentialMode, CredentialSource,
    Operation, ProviderReadiness, RequestFailure, Response,
};
use useful_support::{CredentialStatus, NextAction};

use super::super::{CommandFailure, CommandResult, JsonArgs, RunnerJson};

pub(super) const ABOUT: &str = "Ask Runner Serve to set up grants now";

#[derive(Debug, Args)]
pub(super) struct Command {
    /// Read the control socket path from the closed runner operator
    /// configuration; the runner home under the useful home is the default, read
    /// without creating anything.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(flatten)]
    output: JsonArgs<RunnerJson>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncOutput<'a, Check: Serialize> {
    schema_version: u8,
    outcome: &'static str,
    agent_logins: ReadinessView<'a>,
    /// Each login whose check in the setup gave no answer, with why, as the
    /// control socket names them; absent when there is none.
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    unanswered_checks: &'a [Check],
    /// The credential mode the runner's setup went by; absent while it goes by none.
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_mode: Option<CredentialMode>,
}

/// The readiness the control socket returned, each provider with its
/// availability and next action; the control socket carries only the facts.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadinessView<'a> {
    updated_at: &'a str,
    providers: Vec<ProviderView<'a>>,
}

#[derive(Serialize)]
struct ProviderView<'a> {
    #[serde(flatten)]
    readiness: &'a ProviderReadiness,
    #[serde(flatten)]
    status: CredentialStatus,
}

impl<'a> ReadinessView<'a> {
    fn of(readiness: &'a AgentLoginReadiness) -> Self {
        Self {
            updated_at: &readiness.updated_at,
            providers: readiness
                .providers
                .iter()
                .map(|entry| ProviderView {
                    readiness: entry,
                    status: entry.credential_status(),
                })
                .collect(),
        }
    }
}

impl Command {
    // The live runner runs the setup, checks included; this command contacts no
    // Cloud deployment itself.
    pub(super) fn execute(self) -> CommandResult {
        let socket_path = super::configured_control_socket_path(self.config.as_deref())?;
        let synced = match useful_runner::request(&socket_path, Operation::SyncAgentLogins) {
            Ok(Response::AgentLoginsSynced(synced)) => synced,
            Ok(Response::Error(error)) => return Err(control_failure(error)),
            Ok(Response::Status(_) | Response::Reloaded { .. }) => {
                return Err(CommandFailure::for_outcome(
                    anyhow!("Runner Serve control protocol is invalid"),
                    OutcomeClass::Protocol,
                ));
            }
            Err(error) => {
                let outcome = match error {
                    RequestFailure::NotReachable => OutcomeClass::Unreachable,
                    RequestFailure::Protocol(_) => OutcomeClass::Protocol,
                };
                return Err(CommandFailure::for_outcome(
                    anyhow::Error::new(error),
                    outcome,
                ));
            }
        };
        let readiness = &synced.readiness;
        let mut stdout = io::stdout().lock();
        if self.output.json {
            serde_json::to_writer_pretty(
                &mut stdout,
                &SyncOutput {
                    schema_version: 1,
                    outcome: "synced",
                    agent_logins: ReadinessView::of(readiness),
                    unanswered_checks: &synced.unanswered_checks,
                    credential_mode: synced.credential_mode,
                },
            )
            .context("write agent-login readiness")?;
            writeln!(stdout).context("write agent-login readiness")?;
        } else {
            write_readiness(&mut stdout, readiness, synced.credential_mode)
                .and_then(|()| {
                    write_unanswered_checks(
                        &mut stdout,
                        synced
                            .unanswered_checks
                            .iter()
                            .map(|check| (check.provider, check.cause)),
                    )
                })
                .and_then(|()| write_credential_mode(&mut stdout, synced.credential_mode))
                .context("write agent-login readiness")?;
        }
        Ok(
            if readiness
                .providers
                .iter()
                .any(ProviderReadiness::fails_readiness)
            {
                ExitCode::GeneralFailure
            } else {
                ExitCode::Success
            },
        )
    }
}

fn control_failure(error: ControlError) -> CommandFailure {
    match error {
        ControlError::RunnerBusy => CommandFailure::with_exit_code(
            anyhow!(
                "Runner Serve did not finish agent-login setup because a run it holds is working (runner_busy); retry once every run it holds is waiting or has ended"
            ),
            ExitCode::Unavailable,
        ),
        ControlError::NotYetConnected => CommandFailure::with_exit_code(
            anyhow!(
                "agent-login setup not started: Runner Serve has not connected to Cloud since it started\n\ncode: not_yet_connected\n\nRetry once `useful runner show` reports the connection as connected:\n  useful runner sync"
            ),
            ExitCode::Unavailable,
        ),
        // Only a serving process older than this release refuses the
        // well-formed request this command sends.
        ControlError::InvalidRequest => CommandFailure::new(anyhow!(
            "Runner Serve does not offer agent-login setup (invalid_request); restart the running `useful runner serve` on this release"
        )),
        error => CommandFailure::new(anyhow!(
            "Runner Serve could not set up agent logins ({})",
            super::show::enum_json(error).unwrap_or_else(|_| "unknown".to_owned())
        )),
    }
}

/// Writes one line per provider: its readiness state, for an OAuth
/// provider's entry of an ended assignment the run and the check time it is
/// as of, the run left out where the entry names none, for a login the
/// runner installed or a token it was issued the generation, its
/// availability with the next action and the step it names, for a login with
/// one, its last use and when, the time left out where the serving process
/// states none, and, where the entry records one, where the provider's
/// credential comes from in [`source_words`].
pub(super) fn write_readiness(
    output: &mut impl Write,
    readiness: &AgentLoginReadiness,
    mode: Option<CredentialMode>,
) -> io::Result<()> {
    for entry in &readiness.providers {
        let label = format!("{} login:", super::show::enum_json(entry.provider)?);
        let state = super::show::enum_json(entry.state)?;
        let as_of = as_of(entry);
        let generation = entry
            .generation
            .map(|generation| format!(" (generation {generation})"))
            .unwrap_or_default();
        let status = entry.credential_status();
        let step = if entry.provider.is_brokered() {
            grant_step(status, entry.provider)
        } else if mode == Some(CredentialMode::Host)
            && matches!(status.next_action, NextAction::ResolveServiceLogin)
        {
            Some(HOST_MODE_STEP.to_owned())
        } else {
            let login = Login {
                provider: &super::show::enum_json(entry.provider)?,
                id: entry.agent_login_id.as_deref(),
            };
            runner_step(status, Some(login))
        };
        let last_use = match entry.last_use {
            Some(last_use) => {
                let last_use = super::show::enum_json(last_use)?;
                match entry.last_use_at.as_deref() {
                    Some(at) => format!(" · last use: {last_use} at {at}"),
                    None => format!(" · last use: {last_use}"),
                }
            }
            None => String::new(),
        };
        let source = match entry.source {
            Some(source) => format!(" · source: {}", source_words(source)),
            None => String::new(),
        };
        writeln!(
            output,
            "{label:<19}{state}{as_of}{generation}, {}{last_use}{source}",
            status.text(step.as_deref())
        )?;
    }
    Ok(())
}

/// The step beside a coding agent's `foreign_login` on a runner that goes by
/// `host`: the runner stands back for the service's own logins by its mode,
/// which only an owner changes.
const HOST_MODE_STEP: &str = "the runner's credential mode is host, so it uses the service's own logins; an owner changes the mode with `useful runner credentials`";

/// Writes, when the setup went by a credential mode, one line naming it;
/// for `host` it also says that Cloud was asked for nothing.
fn write_credential_mode(output: &mut impl Write, mode: Option<CredentialMode>) -> io::Result<()> {
    match mode {
        None => Ok(()),
        Some(CredentialMode::Host) => writeln!(
            output,
            "{:<19}host · Cloud was asked for no agent login, list or token",
            "credential mode:"
        ),
        Some(mode @ CredentialMode::Cloud) => {
            writeln!(output, "{:<19}{}", "credential mode:", mode.as_str())
        }
    }
}

/// The words a readiness line prints for a recorded source: `org_connection`
/// as the installation it names, every other source by its wire name, which
/// `--json` and the doctor check carry for all of them.
fn source_words(source: CredentialSource) -> &'static str {
    match source {
        CredentialSource::OrgConnection => "the organization's GitHub App installation",
        CredentialSource::Host | CredentialSource::Grant => source.as_str(),
    }
}

/// What an OAuth provider's entry of an ended assignment is as of: its run,
/// where the entry names one, and the time of its check. An entry without an
/// end is current and is as of nothing.
fn as_of(entry: &ProviderReadiness) -> String {
    if !entry.provider.is_brokered() || entry.ended_at.is_none() {
        return String::new();
    }
    match (entry.run_id.as_deref(), entry.checked_at.as_deref()) {
        (Some(run_id), Some(at)) => format!(" as of run {run_id} at {at}"),
        (Some(run_id), None) => format!(" as of run {run_id}"),
        (None, Some(at)) => format!(" as of {at}"),
        (None, None) => " as of an ended run".to_owned(),
    }
}

/// Writes, after the readiness lines, one line per login whose check gave no
/// answer, naming its provider and the cause. A check with no answer says
/// nothing of the login, so it changes no exit status.
fn write_unanswered_checks<Provider: Serialize, Cause: Serialize>(
    output: &mut impl Write,
    checks: impl IntoIterator<Item = (Provider, Cause)>,
) -> io::Result<()> {
    for (provider, cause) in checks {
        let label = format!("{} check:", super::show::enum_json(provider)?);
        writeln!(
            output,
            "{label:<19}no answer ({})",
            super::show::enum_json(cause)?
        )?;
    }
    Ok(())
}

/// The step an OAuth provider's next action names. Its entry is one
/// assignment's outcome, which no runner command changes: the next
/// assignment the runner admits asks for a token again, and only the
/// grant's owner can consent again. For `github`, Cloud also refuses an
/// organization's GitHub App installation that no owner of the organization
/// has verified, so its reconnection names that owner's command beside the
/// grant's.
fn grant_step(status: CredentialStatus, provider: AgentLoginProvider) -> Option<String> {
    let installation = if provider == AgentLoginProvider::Github {
        ", or an owner of the organization verifies its GitHub App installation with `useful org integration connect github`"
    } else {
        ""
    };
    let provider = provider.grant_provider().unwrap_or(provider.as_str());
    match status.next_action {
        NextAction::SyncRunner => {
            Some("the next assignment the runner admits asks for a token again".to_owned())
        }
        NextAction::CheckTarget => Some(
            "the deployment issues no tokens for this provider; the next assignment the runner admits asks again"
                .to_owned(),
        ),
        NextAction::Reconnect => Some(format!(
            "the owner of the grant consents again with `useful account integration reconnect {provider}`{installation}; only they can"
        )),
        _ => runner_step(status, None),
    }
}

/// The login a runner's next action is about: its provider, and the agent
/// login the runner holds for it when the runner names one.
pub(super) struct Login<'a> {
    pub(super) provider: &'a str,
    pub(super) id: Option<&'a str>,
}

/// The command or step a runner's next action names, each command a `useful account integration`
/// one or `useful runner sync`. Reconnecting a login is the agent login's owner's to do, not the
/// runner operator's, so that names the agent login.
pub(super) fn runner_step(status: CredentialStatus, login: Option<Login<'_>>) -> Option<String> {
    let id = login.as_ref().and_then(|login| login.id);
    let agent_login = id.map_or_else(
        || "the agent login".to_owned(),
        |id| format!("agent login {id}"),
    );
    match status.next_action {
        // The owner names the grant by the agent login's ID, which is the grant's, when the
        // runner reports it, and otherwise by its provider.
        NextAction::Reconnect => Some(format!(
            "the owner of {agent_login} signs in again with `useful account integration reconnect {}`; only they can",
            id.or(login.as_ref().map(|login| login.provider))
                .unwrap_or("INTEGRATION")
        )),
        NextAction::SyncRunner => {
            Some("set grants up again with `useful runner sync`".to_owned())
        }
        NextAction::CheckTarget => Some(
            "the deployment does not serve this provider for the runner's operating system"
                .to_owned(),
        ),
        NextAction::ResolveServiceLogin => Some(
            "the service's own login is in use; remove it from the service's environment or home to use the agent login"
                .to_owned(),
        ),
        NextAction::None
        | NextAction::ResolveRunnerConflict
        | NextAction::WaitForRunner
        | NextAction::AuthorizeRunner
        | NextAction::Connect => None,
    }
}
