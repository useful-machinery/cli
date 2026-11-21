//! `useful workflow run upgrade RUN [--from STEP]` (REQ-LOCALRUN-194, REQ-LOCALRUN-197): a
//! successor of a waiting run under the `useful` home on its definition's current revision,
//! keeping the run's wait or, with `--from`, running `STEP` and its dependents again.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::Args;

use super::successor::SuccessorRequest;
use crate::exit_code::ExitCode;

pub(super) const ABOUT: &str = "Move a waiting run to its definition's current revision";
pub(super) const AFTER_HELP: &str = "RUN is a run directory, a run ID or a subject, looked up under the useful home alone: a Cloud run has no upgrade.

Starts a successor of a waiting definition run under the useful home on the definition's current revision. The successor takes the run's subject, and the run exits superseded. A run that is running, abandoned or ended is refused, and the refusal names the commands that apply.

Without --from the successor keeps the run's pending wait, so no step runs again: it takes the run's attempts and position and waits where the run waited. Answer, approve or otherwise resolve the successor's wait to continue it. The command refuses, and changes nothing, when the run is already on the current revision, when a recorded control already resolves its wait, or when the current revision no longer has a step, outcome or element the run's state names.

With --from STEP the successor inherits the results of the steps completed before STEP and runs STEP and its dependents again under the current revision. A fan-out STEP runs again from its first element; without --from a run waiting inside one stays at its element. The run's inputs carry over to the inputs the current revision declares; --input-text sets a Text input on top of them, except the one the workflow names as its subject.";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(flatten)]
    run: super::target::RunArg,
    #[arg(
        long = "from",
        value_name = "STEP",
        help = "Ordinary step the successor runs again from"
    )]
    from: Option<String>,
    #[arg(
        long,
        value_names = ["NAME", "TEXT"],
        num_args = 2,
        action = clap::ArgAction::Append,
        requires = "from",
        help = "Set one named Text input of the current revision"
    )]
    input_text: Vec<OsString>,
    #[arg(
        long,
        value_name = "PATH",
        requires = "from",
        help = "Existing execution root; defaults to the run's last attempt's root"
    )]
    execution_root: Option<PathBuf>,
    #[command(flatten)]
    presentation: super::PresentationOptions,
}

impl Command {
    pub(super) fn execute(self) -> super::super::super::CommandResult {
        super::create::execute_with_runtime(
            "start local workflow upgrade runtime",
            self.execute_async(),
        )
    }

    async fn execute_async(self) -> super::super::super::CommandResult {
        let request = match self.from {
            Some(from) => SuccessorRequest::Restart {
                from,
                input_text: super::successor::text_inputs(&self.input_text).map_err(|error| {
                    super::super::super::CommandFailure::with_exit_code(error, ExitCode::UsageError)
                })?,
                execution_root: self.execution_root,
            },
            None => SuccessorRequest::Upgrade,
        };
        // REQ-LOCALRUN-180: Cloud carries no upgrade, so the home is the one place looked in.
        let run_directory = self
            .run
            .home_only()
            .map_err(|error| super::control::home_miss(error, "A Cloud run has no upgrade."))
            .map_err(anyhow::Error::new)?;
        let config = super::create::presentation_config(&self.presentation);
        super::successor::start(run_directory, request, config).await
    }
}
