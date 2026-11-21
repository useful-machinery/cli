use clap::Args;

use crate::cli::deletion::{CancellationOptions, DeletionTarget};

pub(super) const ABOUT: &str = "Cancel account deletion";
pub(super) const AFTER_HELP: &str = "Proof:\n  This command starts a fresh browser sign-in for the same linked identity.\n  The proof is sent only as the cancellation bearer and is not stored as a local session.";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(flatten)]
    options: CancellationOptions,
}

impl Command {
    pub(super) fn execute(self) -> super::super::CommandResult {
        super::super::execute_deployment_command(
            Some(self),
            &[super::NAME, "restore"],
            "configure Useful Machinery account deletion",
            |command, deployment| command.options.execute(deployment, DeletionTarget::Account),
        )
    }
}
