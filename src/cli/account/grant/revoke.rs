use anyhow::Context;
use clap::Args;

use super::super::super::integration_token;
use crate::exit_code::ExitCode;
use useful_api::{IntegrationTokenOwner, MemberGrantKind};
use useful_human_auth::Deployment;

use super::confirmation::{Confirmation, Kind, NATIVE_REVOKE, Stated, Statement, TOKEN_REVOKE};
use super::{GRANT_HELP, GrantArg, Options, Subject, act_on, output, replayed};

pub(super) const ABOUT: &str = "Revoke one of your grants or tokens everywhere";

#[derive(Debug, Args)]
pub(in crate::cli) struct Command {
    #[arg(value_name = "INTEGRATION", value_parser = super::parse_grant, help = GRANT_HELP)]
    grant: GrantArg,

    #[command(flatten)]
    confirmation: Confirmation<Self>,

    #[command(flatten)]
    options: Options,
}

/// What revoking does (REQ-GRANT-68): an OAuth grant is erased and revoked at the provider,
/// a native grant's runners' runs are asked to stop (REQ-GRANT-48), and a token is erased from
/// Cloud alone (REQ-INTEGRATION-20).
impl Stated for Command {
    const COMMAND: &'static str = "useful account integration disconnect";
    const STATEMENT: Statement = Statement(&[
        (
            Kind::Grant(MemberGrantKind::GrantKindOAuth),
            &[
                "the grant is erased, and revoked at the provider where the provider offers it; \
                 no run can be issued a token from it again",
            ],
        ),
        (Kind::Grant(MemberGrantKind::GrantKindNative), NATIVE_REVOKE),
        (Kind::Token, TOKEN_REVOKE),
    ]);
    const ACTION: &'static str = "to revoke the grant or token";
}

impl Command {
    /// Revokes what `INTEGRATION` names: a grant, or the member's token of a token service
    /// (REQ-INTEGRATION-20).
    pub(super) fn run(self, deployment: &Deployment) -> anyhow::Result<ExitCode> {
        let key = useful_support::generate_idempotency_key()
            .context("generate grant revocation request key")?;
        act_on::<Self, _>(
            deployment,
            &self.options,
            &self.grant,
            |subject| format!("Revoking {}:", subject.named()),
            |api, subject| match subject {
                Subject::Grant(grant) => {
                    replayed(|| api.revoke(&grant.id, &key))?;
                    // A revoked native grant is still read back (REQ-GRANT-13). The read only
                    // reports each runner's removal and stop; its failure leaves the revocation
                    // done. An OAuth grant's runners kept no copy.
                    Ok((grant.kind == MemberGrantKind::GrantKindNative)
                        .then(|| api.get(&grant.id).ok()))
                }
                // A token's runners are issued it no more; nothing is read after.
                Subject::Token(token) => {
                    replayed(|| {
                        api.revoke_integration_token(IntegrationTokenOwner::Member, &token.id, &key)
                    })?;
                    Ok(None)
                }
            },
            |api_url, subject, after, json| match subject {
                Subject::Grant(grant) => {
                    output::write_revoke(api_url, grant, after.as_ref().map(Option::as_ref), json)
                }
                Subject::Token(token) => {
                    integration_token::write_revoked(api_url, token, None, json)
                }
            },
            |id| format!("useful account integration disconnect {id} --yes"),
        )
    }
}
