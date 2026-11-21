use std::collections::BTreeMap;

use anyhow::anyhow;
use clap::Args;

use super::super::super::integration_token::ListedToken;
use crate::cli::{CommandFailure, CommandResult};
use crate::exit_code::ExitCode;
use useful_api::{GrantApi, GrantFailure, GrantUseList, MemberGrantFailure, MemberGrantKind};
use useful_human_auth::Deployment;

use super::{Found, GRANT_HELP, GrantArg, Options, Resolved, accounts, lookup, output};

pub(super) const ABOUT: &str = "Show one of your grants with its runners and uses, or a token";

// The tokens issued from an OAuth grant that its detail shows unless `--uses` names another
// number (REQ-GRANT-64).
const USES_SHOWN: u16 = 20;

#[derive(Debug, Args)]
pub(super) struct Command {
    #[arg(value_name = "INTEGRATION", value_parser = super::parse_grant, help = GRANT_HELP)]
    grant: GrantArg,

    #[arg(
        long = "uses",
        value_name = "N",
        value_parser = clap::value_parser!(u16).range(1..=200),
        help = "Show the newest N tokens issued from an OAuth grant (1-200) [default: 20]"
    )]
    uses: Option<u16>,

    #[command(flatten)]
    options: Options,
}

impl Command {
    /// Reads the one grant `INTEGRATION` names (REQ-GRANT-65), and for an OAuth grant the newest
    /// tokens issued from it (REQ-GRANT-8), with no read of the providers the deployment
    /// serves; or, where a provider name names no grant, the member's token of the token
    /// service it names, read once the served read names a token service (REQ-INTEGRATION-19).
    /// `--uses` is refused for a token, exit 2, once it is found.
    pub(super) fn run(self, deployment: &Deployment) -> CommandResult {
        let json = self.options.json;
        let read = super::with_api(deployment, &self.options, |api| {
            let found = lookup(api, &self.grant)?;
            let organizations = match &found {
                Found::Grant(Resolved::Grant(grant)) => {
                    accounts::organization_slugs(api, std::slice::from_ref(grant))
                }
                Found::Grant(Resolved::Ambiguous { .. }) | Found::Token(_) => BTreeMap::new(),
            };
            Ok((found, organizations))
        })?;
        let api_url = deployment.fingerprint().api_url();
        let (grant, organizations) = match read {
            Ok((Found::Grant(Resolved::Grant(grant)), organizations)) => (grant, organizations),
            Ok((Found::Grant(Resolved::Ambiguous { provider, ids }), _)) => {
                return Ok(output::write_ambiguous(
                    api_url,
                    &provider,
                    &ids,
                    |id| format!("useful account integration show {id}"),
                    json,
                    false,
                )?);
            }
            Ok((Found::Token(token), _)) => {
                if self.uses.is_some() {
                    return Err(CommandFailure::with_exit_code(
                        anyhow!(
                            "--uses does not apply to a token\n\nA token records no use. Show it \
                             without --uses:\n  useful account integration show {}",
                            token.provider
                        ),
                        ExitCode::UsageError,
                    ));
                }
                return Ok(ListedToken::member(*token).write_shown(api_url, json)?);
            }
            Err(failure) => return Ok(output::failure(api_url, &failure, json)?),
        };
        // A native grant issues no token, so Cloud records no use of it (REQ-GRANT-62).
        let uses = if grant.kind == MemberGrantKind::GrantKindOAuth {
            let limit = self.uses.unwrap_or(USES_SHOWN);
            match read_uses(deployment, &self.options, &grant.id, limit)? {
                Ok(page) => Some(page),
                Err(failure) => return Ok(output::failure(api_url, &failure, json)?),
            }
        } else {
            None
        };
        let accounts = accounts::named(
            deployment,
            self.options.http.transport_policy(),
            std::slice::from_ref(&grant),
            organizations,
        )?;
        Ok(output::write_grant(
            api_url,
            &grant,
            &accounts,
            uses.as_ref().map(|page| page.items.as_slice()),
            json,
        )?)
    }
}

/// The newest `limit` tokens issued from the OAuth grant `grant_id`, newest first: one page,
/// since the uses grow with every assignment (REQ-GRANT-8). A failed read is reported as a
/// failed read of the grant.
fn read_uses(
    deployment: &Deployment,
    options: &Options,
    grant_id: &str,
    limit: u16,
) -> anyhow::Result<Result<GrantUseList, MemberGrantFailure>> {
    let page = super::super::super::with_human_session_api(
        deployment,
        options.http.transport_policy(),
        |api: &GrantApi| api.uses(grant_id, Some(i32::from(limit)), None),
    )?;
    Ok(page.map_err(|failure| match failure {
        GrantFailure::Unauthenticated => MemberGrantFailure::Unauthenticated,
        GrantFailure::Forbidden => MemberGrantFailure::Forbidden,
        GrantFailure::InvalidInput => MemberGrantFailure::InvalidInput,
        GrantFailure::NotFound => MemberGrantFailure::GrantNotFound,
        GrantFailure::IdempotencyConflict => MemberGrantFailure::IdempotencyConflict,
        GrantFailure::ProviderUnavailable => MemberGrantFailure::ProviderUnavailable,
        GrantFailure::RateLimited { retry_after } => {
            MemberGrantFailure::RateLimited { retry_after }
        }
        GrantFailure::Unreachable { category } => MemberGrantFailure::Unreachable { category },
        GrantFailure::InvalidResponse {
            credential_rejected,
        } => MemberGrantFailure::InvalidResponse {
            credential_rejected,
        },
        // The uses route starts no consent, so this answer is not one it defines.
        GrantFailure::ConsentInProgress => MemberGrantFailure::InvalidResponse {
            credential_rejected: false,
        },
    }))
}
