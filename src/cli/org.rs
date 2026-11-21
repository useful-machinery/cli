mod audit;
pub(super) mod connection;
mod create;
mod delete;
mod invitation;
mod leave;
mod list;
pub(super) mod member;
mod output;
mod restore;
mod show;
mod update;

use anyhow::Context;
use clap::{Args, Subcommand};

use super::context::{self, OrgArgs};
use crate::exit_code::ExitCode;
use useful_api::{
    CreateOrganizationOutcome, GetOrganizationOutcome, HttpClient,
    ListCurrentPrincipalMembershipsOutcome, ListOrganizationAuditRecordsOutcome,
    ListOrganizationMembershipHistoryOutcome, ListOrganizationMembershipsOutcome,
    MembershipTerminationOutcome, OrganizationError, UpdateOrganizationMembershipOutcome,
    UpdateOrganizationOutcome,
};
use useful_human_auth::Deployment;

pub(super) const ABOUT: &str = "Manage Useful Machinery organizations";
const NAME: &str = "org";
/// The value name of this family's organization positional.
const ORG: &str = "ORG";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<OrganizationCommand>,
}

#[derive(Debug, Subcommand)]
enum OrganizationCommand {
    #[command(about = audit::ABOUT)]
    Audit(audit::Command),
    #[command(about = create::ABOUT)]
    Create(create::Command),
    #[command(about = delete::ABOUT, after_help = delete::AFTER_HELP)]
    Delete(delete::Command),
    #[command(about = connection::ABOUT)]
    Integration(connection::Command),
    #[command(about = invitation::ABOUT)]
    Invitation(invitation::Command),
    #[command(about = leave::ABOUT)]
    Leave(leave::Command),
    #[command(about = list::ABOUT)]
    List(list::Command),
    #[command(about = member::ABOUT)]
    Member(member::Command),
    #[command(about = restore::ABOUT, after_help = restore::AFTER_HELP)]
    Restore(restore::Command),
    #[command(about = show::ABOUT)]
    Show(show::Command),
    #[command(about = update::ABOUT)]
    Update(update::Command),
}

type LeafOptions = super::CommonArgs<super::OrganizationJson, super::PrincipalAuthenticationArgs>;

impl LeafOptions {
    fn execute<O>(
        self,
        deployment: &Deployment,
        operation: impl FnMut(&HttpClient, &str, &str) -> Result<O, OrganizationError>,
        write: impl FnOnce(
            &str,
            &O,
            super::PrincipalAuthenticationKind,
            bool,
        ) -> anyhow::Result<ExitCode>,
    ) -> anyhow::Result<ExitCode>
    where
        O: super::HumanCredentialOutcome<Error = OrganizationError>,
    {
        let outcome = self.read(deployment, operation)?;
        write(
            deployment.fingerprint().api_url(),
            &outcome,
            self.authentication.kind(),
            self.json,
        )
        .context("write organization result")
    }

    /// The outcome of `operation` under the leaf's credential, for a leaf that writes it with
    /// more than the outcome.
    fn read<O>(
        &self,
        deployment: &Deployment,
        operation: impl FnMut(&HttpClient, &str, &str) -> Result<O, OrganizationError>,
    ) -> anyhow::Result<O>
    where
        O: super::HumanCredentialOutcome<Error = OrganizationError>,
    {
        super::execute_with_principal_credential(
            deployment,
            self.http.transport_policy(),
            &self.authentication,
            "prepare organization networking",
            "contact organization API at",
            operation,
        )
    }

    /// Runs `run` in the organization in effect (REQ-ORG-87); a failed read of it is written by
    /// this family's common-failure writer.
    fn execute_in(
        self,
        org: OrgArgs,
        deployment: &Deployment,
        run: impl FnOnce(Self, &str) -> anyhow::Result<ExitCode>,
    ) -> super::CommandResult {
        context::execute_in(org, self, deployment, output::write_context_failure, run)
    }

    // Organization mutations add request identity before delegating to the same domain-specific
    // renderer; keeping that boundary explicit is clearer than callback-shaping the read path.
    fn execute_mutation<O>(
        self,
        deployment: &Deployment,
        mut operation: impl FnMut(&HttpClient, &str, &str, &str) -> Result<O, OrganizationError>,
        write: impl FnOnce(
            &str,
            &O,
            super::PrincipalAuthenticationKind,
            bool,
        ) -> anyhow::Result<ExitCode>,
    ) -> anyhow::Result<ExitCode>
    where
        O: super::HumanCredentialOutcome<Error = OrganizationError>,
    {
        let idempotency_key = useful_support::generate_idempotency_key()
            .context("generate organization mutation request identity")?;
        self.execute(
            deployment,
            |client, api_url, access_token| {
                operation(client, api_url, access_token, &idempotency_key)
            },
            write,
        )
    }
}

impl Command {
    pub(super) fn execute(self) -> super::CommandResult {
        match self.command {
            None => super::print_help(&[NAME]),
            Some(OrganizationCommand::Audit(command)) => command.execute(),
            Some(OrganizationCommand::Integration(command)) => command.execute(),
            Some(OrganizationCommand::Create(command)) => {
                execute_leaf(command, create::Command::execute)
            }
            Some(OrganizationCommand::Delete(command)) => command.execute(),
            Some(OrganizationCommand::Invitation(command)) => command.execute(),
            Some(OrganizationCommand::Leave(command)) => {
                execute_leaf(command, leave::Command::execute)
            }
            Some(OrganizationCommand::List(command)) => {
                execute_leaf(command, list::Command::execute)
            }
            Some(OrganizationCommand::Restore(command)) => command.execute(),
            Some(OrganizationCommand::Show(command)) => {
                execute_leaf(command, show::Command::execute)
            }
            Some(OrganizationCommand::Update(command)) => {
                execute_leaf(command, update::Command::execute)
            }
            Some(OrganizationCommand::Member(command)) => command.execute(),
        }
    }
}

fn execute_leaf<T, E: Into<super::CommandFailure>>(
    command: T,
    execute: impl FnOnce(T, &Deployment) -> Result<ExitCode, E>,
) -> super::CommandResult {
    super::execute_deployment_command(
        Some(command),
        &[NAME],
        "configure Useful Machinery organization access",
        |command, deployment| execute(command, deployment).map_err(Into::into),
    )
}

super::impl_organization_human_credential_outcome!(
    CreateOrganizationOutcome,
    GetOrganizationOutcome,
    UpdateOrganizationOutcome,
    ListCurrentPrincipalMembershipsOutcome,
    ListOrganizationAuditRecordsOutcome,
    ListOrganizationMembershipHistoryOutcome,
    ListOrganizationMembershipsOutcome,
    MembershipTerminationOutcome,
    UpdateOrganizationMembershipOutcome,
);
