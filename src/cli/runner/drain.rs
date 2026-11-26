use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::anyhow;
use clap::{ArgGroup, Args};
use useful_runner::{ControlError, Operation, RequestFailure, Response};

use crate::exit_code::{ExitCode, OutcomeClass};

use super::super::context::OrgArgs;
use super::super::{CommandFailure, CommandResult};
use super::{CloudOptions, ModeCommand, RunnerTarget, execute_in_cloud};

pub(super) const ABOUT: &str = "Drain a runner registration, or this host's live runner";
pub(super) const AFTER_HELP: &str = "This host:\n  With no RUNNER, the command asks this host's live runner to drain its own registration.\n  It needs no sign-in and exits 0 once Cloud has the registration draining.";
const DRAINING: &str = "✓ Runner draining.";

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("cloud_read")
        .args(["org", "api_key_file", "allow_insecure_http", "json"])
        .multiple(true)
        .requires("runner")
))]
pub(super) struct Command {
    #[arg(
        value_name = "RUNNER",
        help = "Runner ID or exact name; omitted, this host's live runner"
    )]
    runner: Option<String>,

    /// Read the control socket path from the closed runner operator configuration;
    /// the runner home under the useful home is the default, read without creating anything.
    #[arg(long, value_name = "PATH", conflicts_with = "runner")]
    config: Option<PathBuf>,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: CloudOptions,
}

impl Command {
    pub(super) fn execute(self) -> CommandResult {
        if let Some(runner) = self.runner {
            let command = ModeCommand {
                target: RunnerTarget {
                    runner,
                    org: self.org,
                },
                options: self.options,
            };
            return execute_in_cloud(command, |command, deployment| {
                command.execute(
                    deployment,
                    useful_api::RunnerRegistrationMode::Draining,
                    "draining",
                    DRAINING,
                )
            });
        }

        let socket_path = super::configured_control_socket_path(self.config.as_deref())?;
        match useful_runner::request(&socket_path, Operation::DrainRegistration) {
            Ok(Response::Drained) => {
                writeln!(io::stdout().lock(), "{DRAINING}").map_err(anyhow::Error::new)?;
                Ok(ExitCode::Success)
            }
            Ok(Response::Error(error)) => Err(control_failure(error)),
            Ok(_) => Err(CommandFailure::for_outcome(
                anyhow!("Runner Serve control protocol is invalid"),
                OutcomeClass::Protocol,
            )),
            Err(error) => {
                let outcome = match error {
                    RequestFailure::NotReachable => OutcomeClass::Unreachable,
                    RequestFailure::Protocol(_) => OutcomeClass::Protocol,
                };
                Err(CommandFailure::for_outcome(
                    anyhow::Error::new(error),
                    outcome,
                ))
            }
        }
    }
}

fn control_failure(error: ControlError) -> CommandFailure {
    let cause = match error {
        ControlError::DrainCredentialRefused => {
            "Cloud refused the runner credential (drain_credential_refused)"
        }
        ControlError::DrainNotServed => {
            "Cloud does not serve runner-initiated drains (drain_not_served)"
        }
        ControlError::DrainFailed => "Cloud did not confirm the registration drain (drain_failed)",
        ControlError::InvalidRequest => {
            "the serving runner is too old to drain its own registration (invalid_request). Restart `useful runner serve` on this release"
        }
        ControlError::CloudUnreachable => {
            return CommandFailure::with_exit_code(
                anyhow!(
                    "the runner could not reach Cloud to confirm the registration drain (cloud_unreachable)"
                ),
                ExitCode::Unavailable,
            );
        }
        error => {
            return CommandFailure::new(anyhow!(
                "Runner Serve could not drain its registration ({})",
                super::show::enum_json(error).unwrap_or_else(|_| "unknown".to_owned())
            ));
        }
    };
    CommandFailure::new(anyhow!(cause))
}
