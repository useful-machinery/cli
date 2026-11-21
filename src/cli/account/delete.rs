use std::io::{self, Write};

use anyhow::{Context, anyhow};
use clap::Args;

use crate::cli::deletion::{
    DeletionTarget, LocalCredentialDisposition, RequestOptions, request_deletion_with_credential,
    write_request_outcome,
};
use crate::exit_code::ExitCode;
use useful_api::{HttpClient, RequestDeletionOutcome, request_current_principal_deletion};
use useful_human_auth::{Deployment, LocalCredentialState};

pub(super) const ABOUT: &str = "Request account deletion";
pub(super) const AFTER_HELP: &str = "Behavior:\n  A human request schedules deletion and removes this deployment's local credential.\n  A service request authenticated with --api-key-file deletes the service immediately.\n  Human cancellation requires a fresh browser proof from the same linked identity before the deadline.";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(flatten)]
    request: RequestOptions<super::super::PrincipalAuthenticationArgs>,
}

impl Command {
    pub(super) fn execute(self) -> super::super::CommandResult {
        super::super::execute_deployment_leaf(
            self,
            &[super::NAME, "delete"],
            "configure Useful Machinery account deletion",
            Self::request,
        )
    }

    fn request(self, deployment: &Deployment) -> anyhow::Result<ExitCode> {
        let idempotency_key = useful_support::generate_idempotency_key()
            .context("generate account deletion request identity")?;
        let client = HttpClient::new(self.request.http.transport_policy())
            .map_err(|error| anyhow!(error))
            .context("prepare account deletion networking")?;
        let (outcome, binding) = request_deletion_with_credential(
            &client,
            deployment,
            &self.request.authentication,
            format!(
                "request account deletion through {}",
                deployment.fingerprint().api_url()
            ),
            |client, api_url, access_token| {
                request_current_principal_deletion(client, api_url, access_token, &idempotency_key)
            },
        )?;
        let (credential, cleanup_error) = if matches!(outcome, RequestDeletionOutcome::Scheduled(_))
        {
            match binding {
                Some(binding) => {
                    match useful_human_auth::remove_bound_credential(deployment, &binding) {
                        Ok(LocalCredentialState::Removed) => {
                            (Some(LocalCredentialDisposition::Removed), None)
                        }
                        Ok(LocalCredentialState::Retained) => {
                            (Some(LocalCredentialDisposition::Changed), None)
                        }
                        Err(error) => (
                            Some(LocalCredentialDisposition::RemovalUnconfirmed),
                            Some(anyhow!(error).context(
                                "remove the local credential after scheduling account deletion",
                            )),
                        ),
                    }
                }
                None => (
                    Some(LocalCredentialDisposition::RemovalUnconfirmed),
                    Some(anyhow!(
                        "the requesting human session binding is unavailable"
                    )),
                ),
            }
        } else {
            (None, None)
        };
        let exit_code = write_request_outcome(
            &DeletionTarget::Account,
            deployment.fingerprint().api_url(),
            &outcome,
            credential,
            self.request.authentication.kind(),
            self.request.json,
        )?;
        if let Some(error) = cleanup_error {
            let mut stderr = io::stderr().lock();
            writeln!(stderr, "error: {error:#}")?;
            writeln!(
                stderr,
                "\nRemove the deployment's local credential before continuing:\n  useful account logout"
            )?;
            return Ok(ExitCode::GeneralFailure);
        }
        Ok(exit_code)
    }
}
