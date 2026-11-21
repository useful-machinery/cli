use clap::{ArgGroup, Args, Subcommand, builder::NonEmptyStringValueParser};

use crate::cli::context::OrgArgs;
use crate::cli::invitation::{self, InvitationOptions};
use crate::cli::{CommandResult, PaginationArgs};
use useful_api::InvitationTarget;
use useful_human_auth::Deployment;

pub(super) const ABOUT: &str = "Manage organization invitations";
const ERROR_CONTEXT: &str = "configure Useful Machinery invitation access";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<InvitationCommand>,
}

#[derive(Debug, Subcommand)]
enum InvitationCommand {
    #[command(about = "Issue an organization invitation")]
    Issue(IssueCommand),
    #[command(about = "List organization invitation history")]
    List(ListCommand),
    #[command(about = "Revoke an organization invitation")]
    Revoke(RevokeCommand),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .multiple(false)
        .args(["account", "email"])
))]
struct IssueCommand {
    #[command(flatten)]
    org: OrgArgs,

    #[arg(
        long,
        value_name = "ACCOUNT",
        value_parser = invitation::parse_principal_id,
        help = "Invite an exact active principal ID"
    )]
    account: Option<String>,

    #[arg(
        long,
        value_name = "EMAIL",
        value_parser = NonEmptyStringValueParser::new(),
        help = "Invite one email address"
    )]
    email: Option<String>,

    #[command(flatten)]
    options: InvitationOptions,
}

// This page belongs to owner-visible invitation history; keeping its arguments local prevents
// runner-list semantics from becoming a shared abstraction merely because both are paginated.
#[derive(Debug, Args)]
struct ListCommand {
    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    pagination: PaginationArgs,

    #[command(flatten)]
    options: InvitationOptions,
}

#[derive(Debug, Args)]
struct RevokeCommand {
    #[command(flatten)]
    org: OrgArgs,

    #[arg(
        value_name = "INVITATION",
        value_parser = invitation::parse_invitation_id,
        help = "Invitation ID"
    )]
    invitation_id: String,

    #[command(flatten)]
    confirmation: super::super::ConfirmationArgs,

    #[command(flatten)]
    options: InvitationOptions,
}

impl Command {
    pub(super) fn execute(self) -> super::super::CommandResult {
        super::super::execute_deployment_command(
            self.command,
            &[super::NAME, "invitation"],
            ERROR_CONTEXT,
            |command, deployment| match command {
                InvitationCommand::Issue(command) => command.execute(deployment),
                InvitationCommand::List(command) => invitation::list_for_organization(
                    command.options,
                    deployment,
                    command.org,
                    &command.pagination,
                ),
                InvitationCommand::Revoke(command) => invitation::revoke(
                    command.options,
                    deployment,
                    command.org,
                    &command.invitation_id,
                ),
            },
        )
    }
}

impl IssueCommand {
    fn execute(self, deployment: &Deployment) -> CommandResult {
        let target = match (self.account.as_deref(), self.email.as_deref()) {
            (Some(principal_id), None) => InvitationTarget::Principal(principal_id),
            (None, Some(email)) => InvitationTarget::Email(email),
            (None, None) | (Some(_), Some(_)) => {
                return Err(anyhow::anyhow!(
                    "invitation target is unavailable after command parsing"
                )
                .into());
            }
        };
        invitation::issue(self.options, deployment, self.org, target)
    }
}
