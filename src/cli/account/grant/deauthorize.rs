use anyhow::Context;
use clap::Args;

use crate::exit_code::ExitCode;
use useful_api::{
    IntegrationTokenOwner, MemberGrant, MemberGrantApi, MemberGrantFailure, MemberGrantKind,
};
use useful_human_auth::Deployment;

use super::authorization::{ended_authorization_views, write_deauthorized};
use super::confirmation::{
    Confirmation, Kind, NATIVE_DEAUTHORIZE, Stated, Statement, TOKEN_DEAUTHORIZE,
};
use super::{
    GRANT_HELP, GrantArg, Options, RUNNER_HELP, RunnerArgs, Subject, replayed, runner_choice,
    state_then_act, subject_and_runner,
};

pub(super) const ABOUT: &str = "End a runner or personal pool authorization for an integration";

/// End a personal pool authorization of a grant or a runner authorization of a grant or token.
#[derive(Debug, Args)]
pub(in crate::cli) struct Command {
    #[arg(value_name = "INTEGRATION", value_parser = super::parse_grant, help = GRANT_HELP)]
    grant: GrantArg,

    #[arg(long, value_name = "RUNNER", help = RUNNER_HELP)]
    runner: Option<String>,

    #[arg(
        long,
        conflicts_with = "runner",
        help = "Select your personal runner pool"
    )]
    personal_pool: bool,

    #[command(flatten)]
    org: crate::cli::context::OrgArgs,

    #[command(flatten)]
    confirmation: Confirmation<Self>,

    #[command(flatten)]
    options: Options,
}

/// What ending the authorization does: for a native grant, the stop Cloud requests of the
/// runner's run; for an OAuth grant, no further token, and no stop; for a token, no
/// further delivery of it.
impl Stated for Command {
    const COMMAND: &'static str = "useful account integration deauthorize";
    const STATEMENT: Statement = Statement(&[
        (
            Kind::Grant(MemberGrantKind::GrantKindOAuth),
            &[
                "no run on the runner can be issued a token from the grant again; a token \
                 already issued expires on its own lifetime",
            ],
        ),
        (
            Kind::Grant(MemberGrantKind::GrantKindNative),
            NATIVE_DEAUTHORIZE,
        ),
        (Kind::Token, TOKEN_DEAUTHORIZE),
    ]);
    const ACTION: &'static str = "to end the runner's authorization";
    const ASKS: bool = true;
}

impl Command {
    pub(super) fn run(self, deployment: &Deployment) -> crate::cli::CommandResult {
        super::check_pool_org(&self.org, self.personal_pool)?;
        if self.personal_pool {
            return self.run_pool(deployment);
        }
        self.run_runner(deployment).map_err(Into::into)
    }

    fn run_pool(&self, deployment: &Deployment) -> crate::cli::CommandResult {
        let options = &self.options;
        let action = super::confirmation::PoolAction::Deauthorize;
        let selection = match super::PoolSelection::read::<Self>(
            action,
            deployment,
            options,
            &self.grant,
            &self.org,
            self.confirmation.yes,
        )? {
            Ok(selection) => selection,
            Err(exit) => return Ok(exit),
        };
        let api_url = deployment.fingerprint().api_url();
        let Some(authorization) = selection.authorization() else {
            return super::output::pool_report(api_url, &MemberGrantFailure::AuthorizationNotFound)
                .write(api_url, options.json)
                .map_err(Into::into);
        };
        let pool = authorization
            .runner_pool_id
            .as_deref()
            .context("pool authorization omitted runnerPoolId")?;
        let before = &selection.grant;
        if let Err(exit) = selection.confirm::<Self>(
            action,
            format_args!(
                "Ending your personal pool {pool}'s authorization for grant {}:",
                before.id
            ),
        )? {
            return Ok(exit);
        }
        let key = useful_support::generate_idempotency_key()
            .context("generate grant deauthorization request key")?;
        let after = match super::with_api(deployment, options, |api| {
            end_grant_authorization(api, before, &authorization.id, &key)
        })? {
            Ok(after) => after,
            Err(failure) => {
                return super::output::pool_report(api_url, &failure)
                    .write(api_url, options.json)
                    .map_err(Into::into);
            }
        };
        let ended = after.as_ref().map(|after| {
            let previously_ended = before.ended_authorizations.as_deref().unwrap_or_default();
            let covered = authorization.runners.as_deref().unwrap_or_default();
            ended_authorization_views(after.ended_authorizations.as_deref().unwrap_or_default())
                .into_iter()
                .filter(|ended| {
                    covered
                        .iter()
                        .any(|runner| runner.runner_id == ended.authorization.runner_id)
                        && !previously_ended
                            .iter()
                            .any(|old| old.id == ended.authorization.id)
                })
                .collect()
        });
        write_deauthorized(
            api_url,
            super::Holder::Grant(&before.id),
            &authorization.id,
            super::authorization::EndedTarget::pool(pool, ended),
            options.json,
        )
        .map_err(Into::into)
    }

    fn run_runner(self, deployment: &Deployment) -> anyhow::Result<ExitCode> {
        let options = &self.options;
        let runner = RunnerArgs {
            named: self.runner.as_deref(),
            yes: self.confirmation.yes,
        };
        let target = match subject_and_runner::<Self>(
            deployment,
            options,
            &self.grant,
            &runner,
            |subject| {
                runner_choice::to_deauthorize(runner_choice::authorized(
                    deployment,
                    options.http.transport_policy(),
                    subject,
                ))
            },
            |subject| {
                runner_choice::authorized(deployment, options.http.transport_policy(), subject)
            },
            |subject| format!("whose authorization for {} to end", subject.named()),
        )? {
            Ok(target) => target,
            Err(exit) => return Ok(exit),
        };
        let runner_id = target.runner.id.as_str();
        let key = useful_support::generate_idempotency_key()
            .context("generate grant deauthorization request key")?;
        state_then_act::<Self, _>(
            deployment,
            options,
            &target.subject,
            &format!(
                "Ending runner {}'s authorization for {}:",
                target.runner.named,
                target.subject.named()
            ),
            target.asks,
            |api, subject| {
                deauthorize(api, IntegrationTokenOwner::Member, subject, runner_id, &key)
            },
            |api_url, subject, ended, json| write(api_url, subject, runner_id, ended, json),
        )
    }
}

/// The ended authorization's ID and, for a native grant, the grant read after it ended, or
/// `None` when that read failed or there was none to read.
pub(in crate::cli) type Ended = (String, Option<MemberGrant>);

/// Ends `runner_id`'s authorization of `subject` under `key`, the refusal that the runner holds
/// none in force when the subject lists none for it; for a native grant, then reads the grant
/// once more for the ended authorization's removal state and stop.
pub(in crate::cli) fn deauthorize(
    api: &MemberGrantApi,
    owner: IntegrationTokenOwner<'_>,
    subject: &Subject,
    runner_id: &str,
    key: &str,
) -> Result<Ended, MemberGrantFailure> {
    // A grant lists only its authorizations in force, and so does a token.
    let authorization_id = subject
        .in_force()
        .iter()
        .find(|authorization| authorization.runner_id == runner_id)
        .map(|authorization| authorization.id.to_owned());
    match subject {
        Subject::Grant(grant) => {
            let authorization_id =
                authorization_id.ok_or(MemberGrantFailure::AuthorizationNotFound)?;
            let after = end_grant_authorization(api, grant, &authorization_id, key)?;
            Ok((authorization_id, after))
        }
        Subject::Token(token) => {
            let authorization_id = authorization_id
                .ok_or(MemberGrantFailure::IntegrationTokenAuthorizationNotFound)?;
            replayed(|| {
                api.deauthorize_integration_token(owner, &token.id, &authorization_id, key)
            })?;
            // A token's runner reports nothing back, so nothing is read after.
            Ok((authorization_id, None))
        }
    }
}

fn end_grant_authorization(
    api: &MemberGrantApi,
    grant: &MemberGrant,
    id: &str,
    key: &str,
) -> Result<Option<MemberGrant>, MemberGrantFailure> {
    replayed(|| api.deauthorize(&grant.id, id, key))?;
    // A failure to read the removal and stop leaves the authorization ended.
    Ok((grant.kind == MemberGrantKind::GrantKindNative)
        .then(|| api.get(&grant.id).ok())
        .flatten())
}

/// Reports `runner_id`'s ended authorization of `subject`.
pub(in crate::cli) fn write(
    api_url: &str,
    subject: &Subject,
    runner_id: &str,
    (authorization_id, after): Ended,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let ended = after
        .as_ref()
        .and_then(|after| after.ended_authorizations.as_deref())
        .map(ended_authorization_views)
        .into_iter()
        .flatten()
        .find(|ended| ended.authorization.id == authorization_id);
    write_deauthorized(
        api_url,
        subject.holder(),
        &authorization_id,
        super::authorization::EndedTarget::runner(runner_id, ended),
        json,
    )
}
