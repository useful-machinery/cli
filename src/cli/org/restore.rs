use clap::Args;

use crate::cli::OrganizationArg;
use crate::cli::deletion::{CancellationOptions, DeletionTarget};

pub(super) const ABOUT: &str = "Cancel organization deletion";
pub(super) const AFTER_HELP: &str = "Authorization:\n  Cancellation requires a current active human owner using the same linked identity that requested deletion.\n\nProof:\n  This command starts a fresh browser sign-in. The proof is not stored as a local session.";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[arg(value_name = super::ORG, help = OrganizationArg::HELP)]
    organization_ref: OrganizationArg,

    #[command(flatten)]
    options: CancellationOptions,
}

impl Command {
    pub(super) fn execute(self) -> super::super::CommandResult {
        super::super::execute_deployment_command(
            Some(self),
            &[super::NAME, "restore"],
            "configure Useful Machinery organization deletion",
            |command, deployment| {
                command.options.execute(
                    deployment,
                    DeletionTarget::Organization(command.organization_ref.into_string()),
                )
            },
        )
    }
}
