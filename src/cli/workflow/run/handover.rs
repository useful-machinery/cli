use anyhow::anyhow;
use clap::Args;
use useful_api::RunContinuationRequestRunner;

use super::cloud_api::{RunWaitArgs, parse_continuation_step};
use super::target::{Found, RunArg};
use crate::cli::context::OrgArgs;
use crate::cli::{CommandFailure, CommandResult, HttpOptions, PrincipalAuthenticationArgs};
use crate::exit_code::ExitCode;

pub(super) const ABOUT: &str = "Continue an ended Cloud run on a replacement runner";
pub(super) const AFTER_HELP: &str = "RUN is a run ID or subject. Cloud starts a new attempt from its kept record. Use --from STEP to choose where to continue, or omit it to continue from where the record stands. With --wait the command follows the new attempt until the run settles.";
const COMMAND: &str = "useful workflow run handover";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(flatten)]
    run: RunArg,

    #[arg(long = "from", value_name = "STEP", value_parser = parse_continuation_step,
        help = "Ordinary step to rerun from (repeatable)")]
    from_steps: Vec<String>,

    #[arg(long, value_name = "VERSION", value_parser = clap::value_parser!(i64).range(1..),
        help = "Require this positive run version at admission")]
    expected_version: Option<i64>,

    #[command(flatten)]
    wait: RunWaitArgs,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    presentation: super::PresentationOptions,

    #[command(flatten)]
    authentication: PrincipalAuthenticationArgs,

    #[command(flatten)]
    http: HttpOptions,
}

pub(super) fn local_option_on_cloud() -> CommandFailure {
    CommandFailure::with_exit_code(
        anyhow!(
            "--handover applies to a run under the useful home, and RUN names a Cloud run\n\nRequest a handover with useful workflow run handover RUN."
        ),
        ExitCode::UsageError,
    )
}

impl Command {
    pub(super) fn execute(self) -> CommandResult {
        let json = self.presentation.output.json;
        match super::control::find(
            COMMAND,
            &self.run,
            &self.org,
            &self.authentication,
            &self.http,
            json,
        ) {
            Ok(Found::Cloud(run)) => {
                super::cloud::CloudRun::found(*run, self.authentication, self.http, json, false)
                    .continue_from(
                        COMMAND,
                        self.from_steps,
                        self.expected_version,
                        self.wait,
                        Some(RunContinuationRequestRunner::Replacement),
                    )
            }
            Ok(Found::Home(_)) => Err(CommandFailure::with_exit_code(
                anyhow!(
                    "RUN names a run under the useful home\n\nContinue it with useful workflow run retry RUN --execution-root ROOT --handover."
                ),
                ExitCode::UsageError,
            )),
            Err(result) => result,
        }
    }
}
