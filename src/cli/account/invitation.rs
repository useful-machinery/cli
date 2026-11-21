use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::cli::invitation::{self, Access, InvitationOptions};
use crate::cli::{ConfirmationArgs, PaginationArgs};

pub(super) const ABOUT: &str = "Manage your invitations";
const NAME: &str = "invitation";
const ERROR_CONTEXT: &str = "configure Useful Machinery invitation access";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<InvitationCommand>,
}

#[derive(Debug, Subcommand)]
enum InvitationCommand {
    #[command(about = "Accept an invitation")]
    Accept(AccessCommand),
    #[command(about = "Decline an invitation")]
    Decline(DeclineCommand),
    #[command(about = "List your invitation inbox")]
    List(InboxCommand),
    #[command(about = "Show an invitation before you answer it")]
    Show(AccessCommand),
}

#[derive(Debug, Args)]
struct InboxCommand {
    #[command(flatten)]
    pagination: PaginationArgs,

    #[command(flatten)]
    options: InvitationOptions,
}

#[derive(Debug, Args)]
struct InvitationAccess {
    #[arg(
        value_name = "INVITATION",
        value_parser = invitation::parse_invitation_id,
        help = "Invitation ID"
    )]
    invitation_id: String,

    #[arg(
        long,
        value_name = "PATH|-",
        help = "Read an email invitation capability from a protected file or explicit stdin"
    )]
    capability_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct AccessCommand {
    #[command(flatten)]
    access: InvitationAccess,

    #[command(flatten)]
    options: InvitationOptions,
}

#[derive(Debug, Args)]
struct DeclineCommand {
    #[command(flatten)]
    access: InvitationAccess,

    #[command(flatten)]
    confirmation: ConfirmationArgs,

    #[command(flatten)]
    options: InvitationOptions,
}

impl Command {
    pub(super) fn execute(self) -> super::super::CommandResult {
        super::super::execute_deployment_command(
            self.command,
            &[super::NAME, NAME],
            ERROR_CONTEXT,
            |command, deployment| match command {
                InvitationCommand::List(command) => {
                    invitation::list_inbox(command.options, deployment, &command.pagination)
                }
                InvitationCommand::Show(command) => command.access().show(deployment),
                InvitationCommand::Accept(command) => command.access().accept(deployment),
                InvitationCommand::Decline(command) => AccessCommand {
                    access: command.access,
                    options: command.options,
                }
                .access()
                .decline(deployment),
            },
        )
    }
}

impl AccessCommand {
    fn access(self) -> Access {
        Access {
            invitation_id: self.access.invitation_id,
            capability_file: self.access.capability_file,
            options: self.options,
        }
    }
}
