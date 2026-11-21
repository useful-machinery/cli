use clap::Args;

use super::super::super::integration_token::{self, Tokens};
use crate::exit_code::ExitCode;
use useful_api::{IntegrationTokenOwner, MemberGrantKind};
use useful_human_auth::Deployment;

use super::{Options, accounts, every_grant, output, projection, unrevoked};

pub(super) const ABOUT: &str = "List your grants and tokens with where each may run";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(flatten)]
    options: Options,
}

impl Command {
    /// Reads every grant of the member and then the providers the deployment serves, to name
    /// the other OAuth providers they hold nothing of (REQ-GRANT-64, REQ-GRANT-96), and, where
    /// that read names a token service, the member's tokens (REQ-INTEGRATION-19): against a
    /// deployment that serves none no token list is read. A deployment that predates the served
    /// read names none, and a read that fails otherwise fails the command as a failed grant
    /// read does. Nothing of an organization's is read.
    pub(super) fn run(self, deployment: &Deployment) -> anyhow::Result<ExitCode> {
        let json = self.options.json;
        let read = super::with_api(deployment, &self.options, |api| {
            let mut grants: Vec<_> = every_grant(api)?.into_iter().filter(unrevoked).collect();
            // Cloud lists OAuth grants first; the order is kept whatever it sends.
            grants.sort_by_key(|grant| grant.kind != MemberGrantKind::GrantKindOAuth);
            // One read names both the providers and the token services served.
            let served = api.served_integrations()?;
            let tokens = match &served {
                Some(served) if !served.token_services.is_empty() => {
                    integration_token::every(api, IntegrationTokenOwner::Member)?
                }
                _ => Vec::new(),
            };
            let providers = served.map(|served| served.providers).unwrap_or_default();
            let organizations = accounts::organization_slugs(api, &grants);
            Ok((grants, providers, Tokens::member(tokens), organizations))
        })?;
        let api_url = deployment.fingerprint().api_url();
        let (grants, served, tokens, organizations) = match read {
            Ok(read) => read,
            Err(failure) => return output::failure(api_url, &failure, json),
        };
        let accounts = accounts::named(
            deployment,
            self.options.http.transport_policy(),
            &grants,
            organizations,
        )?;
        output::write_list(
            api_url,
            &grants,
            &tokens,
            &projection::providers(&served),
            &accounts,
            json,
        )
    }
}
