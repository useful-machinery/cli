use anyhow::{Context, anyhow};
use clap::Args;

use crate::cli::OrganizationArg;
use crate::cli::deletion::{
    DeletionTarget, LocalCredentialDisposition, RequestOptions, request_deletion_with_credential,
    write_request_outcome,
};
use crate::exit_code::ExitCode;
use useful_api::{HttpClient, RequestDeletionOutcome, request_organization_deletion};
use useful_human_auth::Deployment;

pub(super) const ABOUT: &str = "Request organization deletion";
pub(super) const AFTER_HELP: &str = "Authorization:\n  Only a current active human owner can request organization deletion.\n\nAccount access:\n  A confirmed organization request leaves the local human credential unchanged.";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[arg(value_name = super::ORG, help = OrganizationArg::HELP)]
    organization_ref: OrganizationArg,

    #[command(flatten)]
    request: RequestOptions<super::super::NoAuthenticationArgs>,
}

impl Command {
    pub(super) fn execute(self) -> super::super::CommandResult {
        super::super::execute_deployment_leaf(
            self,
            &[super::NAME, "delete"],
            "configure Useful Machinery organization deletion",
            Self::request,
        )
    }

    fn request(self, deployment: &Deployment) -> anyhow::Result<ExitCode> {
        let organization_ref = self.organization_ref.into_string();
        let idempotency_key = useful_support::generate_idempotency_key()
            .context("generate organization deletion request identity")?;
        let client = HttpClient::new(self.request.http.transport_policy())
            .map_err(|error| anyhow!(error))
            .context("prepare organization deletion networking")?;
        let (outcome, _binding) = request_deletion_with_credential(
            &client,
            deployment,
            &super::super::PrincipalAuthenticationArgs::default(),
            format!(
                "request organization deletion through {}",
                deployment.fingerprint().api_url()
            ),
            |client, api_url, access_token| {
                request_organization_deletion(
                    client,
                    api_url,
                    access_token,
                    &organization_ref,
                    &idempotency_key,
                )
            },
        )?;
        write_request_outcome(
            &DeletionTarget::Organization(organization_ref),
            deployment.fingerprint().api_url(),
            &outcome,
            matches!(outcome, RequestDeletionOutcome::Scheduled(_))
                .then_some(LocalCredentialDisposition::Unchanged),
            super::super::PrincipalAuthenticationKind::HumanSession,
            self.request.json,
        )
    }
}
