use std::io::{self, Write};

use anyhow::Context;
use clap::{Args, Subcommand};

use super::{CloudOptions, OrgArgs, PaginationArgs, cloud};
use crate::exit_code::ExitCode;
use useful_human_auth::Deployment;
use useful_support::generate_idempotency_key;

pub(super) const ABOUT: &str = "Manage runner credential lifecycle";
const COMMAND_PATH: &[&str] = &["runner", "credential"];
const RUNNER_HELP: &str = "Runner ID or exact name";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<CredentialCommand>,
}

#[derive(Debug, Subcommand)]
enum CredentialCommand {
    #[command(
        about = "List runner credential metadata",
        after_help = "Privacy:\n  The list contains credential metadata, not secrets."
    )]
    List(ListCommand),
    #[command(
        about = "Revoke a runner credential",
        after_help = "Revocation:\n  The credential is revoked at once, or with --after 1h retires after Cloud's one-hour grace."
    )]
    Revoke(RevokeCommand),
}

// Credential commands keep their own Clap metadata so help and resource contracts remain
// explicit instead of coupling lifecycle commands to activation or registration
// administration.
#[derive(Debug, Args)]
struct ListCommand {
    #[arg(value_name = "RUNNER", help = RUNNER_HELP)]
    runner: String,
    #[command(flatten)]
    pagination: PaginationArgs,
    #[command(flatten)]
    org: OrgArgs,
    #[command(flatten)]
    options: CloudOptions,
}

#[derive(Debug, Args)]
struct RevokeCommand {
    #[arg(value_name = "CREDENTIAL", help = "Runner credential ID")]
    credential: String,
    // The same help as the `account integration` leaves' `--runner`, one help class.
    #[arg(long, value_name = "RUNNER", help = RUNNER_HELP)]
    runner: String,
    #[arg(
        long,
        value_name = "DURATION",
        value_parser = parse_grace,
        help = "Retire the credential after Cloud's one-hour grace instead of at once; only 1h or 60m"
    )]
    after: Option<RetirementGrace>,
    #[command(flatten)]
    confirmation: super::super::ConfirmationArgs,
    #[command(flatten)]
    org: OrgArgs,
    #[command(flatten)]
    options: CloudOptions,
}

/// The grace of a scheduled retirement, which Cloud fixes at one hour.
#[derive(Clone, Copy, Debug)]
struct RetirementGrace;

/// Reads `--after` as a whole number of minutes, hours or days that comes to exactly one
/// hour; any other duration is refused before anything is read or sent.
fn parse_grace(value: &str) -> Result<RetirementGrace, String> {
    let seconds =
        super::super::split_unit_suffix(value, &[("d", 86_400_u32), ("h", 3_600), ("m", 60)])
            .filter(|(quantity, _)| {
                !quantity.is_empty() && quantity.bytes().all(|byte| byte.is_ascii_digit())
            })
            .and_then(|(quantity, unit)| quantity.parse::<u32>().ok()?.checked_mul(unit));
    if seconds == Some(3_600) {
        Ok(RetirementGrace)
    } else {
        Err("Cloud retires a credential one hour after the request; use --after 1h, or omit --after to revoke it at once".to_owned())
    }
}

// This namespace deliberately mirrors sibling runner namespaces while retaining
// its credential-specific command path and deployment-loading boundary.
impl Command {
    pub(super) fn execute(self) -> super::super::CommandResult {
        let Some(command) = self.command else {
            return super::super::print_help(COMMAND_PATH);
        };
        super::execute_in_cloud(command, |command, deployment| match command {
            CredentialCommand::List(command) => command.execute(deployment),
            CredentialCommand::Revoke(command) => command.execute(deployment),
        })
    }
}

impl ListCommand {
    fn execute(self, deployment: &Deployment) -> super::super::CommandResult {
        let Self {
            runner,
            pagination,
            org,
            options,
        } = self;
        super::execute_in(
            org,
            options,
            deployment,
            |options, organization| -> anyhow::Result<ExitCode> {
                // Credential and pool listings resolve different resource hierarchies and retain
                // separate output schemas despite sharing pagination fields.
                let result = cloud::with_api(
                    deployment,
                    options.http.transport_policy(),
                    &options.authentication,
                    |api| {
                        let runner = api.get_registration(organization, &runner)?;
                        api.list_credentials(
                            organization,
                            &runner.id,
                            pagination.limit,
                            pagination.cursor.as_deref(),
                        )
                    },
                )?;
                let page = match result {
                    Ok(page) => page,
                    Err(failure) => return options.write_failure(deployment, &failure),
                };
                if options.json {
                    serde_json::to_writer_pretty(
                        &mut io::stdout().lock(),
                        &CredentialListOutput {
                            schema_version: 1,
                            deployment: deployment.fingerprint().api_url(),
                            outcome: "listed",
                            items: &page.items,
                            next_cursor: page.next_cursor.as_deref(),
                        },
                    )?;
                    writeln!(io::stdout().lock())?;
                    return Ok(ExitCode::Success);
                }
                let mut output = io::stdout().lock();
                writeln!(output, "✓ Runner credentials listed.\n")?;
                for credential in page.items {
                    writeln!(
                        output,
                        "  Credential: {}  Stored: {}  Effective: {}  Created: {}",
                        credential.id,
                        stored_state_label(credential.stored_state),
                        effective_state_label(credential.effective_state),
                        credential.created_at,
                    )?;
                    if let Some(last_authenticated_at) = credential.last_authenticated_at {
                        writeln!(output, "    Last authenticated: {last_authenticated_at}")?;
                    }
                    if let Some(retire_at) = credential.retire_at {
                        writeln!(output, "    Retires:            {retire_at}")?;
                    }
                    if let Some(revoked_at) = credential.revoked_at {
                        writeln!(output, "    Revoked:            {revoked_at}")?;
                    }
                }
                if let Some(cursor) = page.next_cursor {
                    writeln!(output, "\n  Next cursor: {cursor}")?;
                }
                Ok(ExitCode::Success)
            },
        )
    }
}

impl RevokeCommand {
    fn execute(self, deployment: &Deployment) -> super::super::CommandResult {
        let Self {
            credential,
            runner,
            after,
            confirmation: _,
            org,
            options,
        } = self;
        // With `--after`, the revocation is the retirement Cloud schedules one hour out;
        // without it, the revocation is immediate.
        let retire = after.is_some();
        super::execute_in(org, options, deployment, |options, organization| {
            let key = generate_idempotency_key().context(if retire {
                "generate credential retirement identity"
            } else {
                "generate credential revocation identity"
            })?;
            let result = cloud::with_api(
                deployment,
                options.http.transport_policy(),
                &options.authentication,
                |api| {
                    let runner = api.get_registration(organization, &runner)?;
                    if retire {
                        api.retire_credential(organization, &runner.id, &credential, &key)
                    } else {
                        api.revoke_credential(organization, &runner.id, &credential, &key)
                    }
                },
            )?;
            write_credential_transition(deployment, &options, retire, result)
        })
    }
}

fn write_credential_transition(
    deployment: &Deployment,
    options: &CloudOptions,
    retire: bool,
    result: Result<useful_api::RunnerCredential, useful_api::RunnerFailure>,
) -> anyhow::Result<ExitCode> {
    let credential = match result {
        Ok(credential) => credential,
        Err(failure) => return options.write_failure(deployment, &failure),
    };
    if options.json {
        serde_json::to_writer_pretty(
            &mut io::stdout().lock(),
            &CredentialMutationOutput {
                schema_version: 1,
                deployment: deployment.fingerprint().api_url(),
                outcome: if retire { "retiring" } else { "revoked" },
                credential: &credential,
            },
        )?;
        writeln!(io::stdout().lock())?;
        return Ok(ExitCode::Success);
    }
    let heading = if retire {
        "✓ Runner credential retirement scheduled."
    } else {
        "✓ Runner credential revoked."
    };
    let mut output = io::stdout().lock();
    writeln!(output, "{heading}\n")?;
    writeln!(output, "  Credential: {}", credential.id)?;
    writeln!(
        output,
        "  Effective state: {}",
        effective_state_label(credential.effective_state),
    )?;
    if let Some(retire_at) = credential.retire_at {
        writeln!(output, "  Retires: {retire_at}")?;
    }
    Ok(ExitCode::Success)
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialListOutput<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    items: &'a [useful_api::RunnerCredential],
    next_cursor: Option<&'a str>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialMutationOutput<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    credential: &'a useful_api::RunnerCredential,
}

fn stored_state_label(state: useful_api::RunnerCredentialStoredState) -> &'static str {
    use useful_api::RunnerCredentialStoredState;
    match state {
        RunnerCredentialStoredState::Active => "active",
        RunnerCredentialStoredState::Retiring => "retiring",
        RunnerCredentialStoredState::Revoked => "revoked",
    }
}

fn effective_state_label(state: useful_api::RunnerCredentialEffectiveState) -> &'static str {
    use useful_api::RunnerCredentialEffectiveState;
    match state {
        RunnerCredentialEffectiveState::Active => "active",
        RunnerCredentialEffectiveState::Retiring => "retiring",
        RunnerCredentialEffectiveState::Revoked => "revoked",
    }
}
