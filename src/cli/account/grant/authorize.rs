use anyhow::Context;
use clap::Args;

use super::super::super::{ApiFailureReport, integration_token, with_human_session_api};
use crate::exit_code::ExitCode;
use useful_api::{
    HttpTransportPolicy, IntegrationTokenAuthorization, IntegrationTokenOwner, MemberGrantApi,
    MemberGrantAuthorization, MemberGrantFailure, MemberGrantKind,
};
use useful_human_auth::Deployment;

use super::authorization::{AuthorizationView, MadeView, write_authorized};
use super::confirmation::{self, Confirmation, Kind, NATIVE_AUTHORIZE, Stated, Statement};
use super::runner_choice::{self, Acting};
use super::{
    GRANT_HELP, GrantArg, Options, RUNNER_HELP, RunnerArgs, Subject, every_grant, output, replayed,
    state_then_act, subject_and_runner, unrevoked,
};

pub(super) const ABOUT: &str =
    "Authorize your personal pool for a grant, or a runner for one or all grants and tokens";

/// The remedy for a Codex grant authorized for another runner, which `useful account integration
/// authorize` reports: a Codex grant serves one runner, and another sign-in cannot make a second
/// grant for another runner, since a held grant is refused or replaced in place.
pub(in crate::cli) const MOVE_CODEX_GRANT: &str = "A Codex grant serves one runner at a time. To move it to this runner, end its authorization for the other, which `useful account integration show INTEGRATION` names, then authorize this one:\n  useful account integration deauthorize INTEGRATION --runner RUNNER --yes";

/// Select one grant and a runner or personal pool. With `--all`, authorize only a runner.
#[derive(Debug, Args)]
#[group(id = "target", args = ["grant", "all"], required = true, multiple = false)]
pub(in crate::cli) struct Command {
    #[arg(value_name = "INTEGRATION", value_parser = super::parse_grant, help = GRANT_HELP)]
    grant: Option<GrantArg>,

    #[arg(
        long,
        help = "Authorize the runner for every grant and token of yours that can serve it, in place of INTEGRATION"
    )]
    all: bool,

    #[arg(long, value_name = "RUNNER", help = RUNNER_HELP)]
    runner: Option<String>,

    #[arg(long, conflicts_with_all = ["runner", "all"], help = "Select your personal runner pool")]
    personal_pool: bool,

    #[command(flatten)]
    org: crate::cli::context::OrgArgs,

    #[command(flatten)]
    confirmation: Confirmation<Self>,

    #[command(flatten)]
    options: Options,
}

/// Who can use the grant or token once the runner is authorized for it: an OAuth grant's tokens
/// are issued only to the runs its owner started, and every step of such a run can read the
/// token, while a native grant's login is the runner's to every run and step. The member's token
/// is issued to the runs whose actor is the member and whose workflow declares the service as
/// the member's.
impl Stated for Command {
    const COMMAND: &'static str = "useful account integration authorize";
    const STATEMENT: Statement = Statement(&[
        (
            Kind::Grant(MemberGrantKind::GrantKindOAuth),
            &[
                "every run on the runner that you start can be issued tokens from the grant",
                "every step of such a run can read the token the runner is issued for it",
            ],
        ),
        (
            Kind::Grant(MemberGrantKind::GrantKindNative),
            NATIVE_AUTHORIZE,
        ),
        (
            Kind::Token,
            &[
                "every run on the runner whose actor is you and whose workflow declares the \
                 service as yours can be issued the token",
                "every step of such a run can read your token",
            ],
        ),
    ]);
    const ACTION: &'static str = "to authorize the runner";
    const ASKS: bool = true;
}

/// An authorization `authorize` made: of a grant, or of a token.
pub(in crate::cli) enum Made {
    Grant(MemberGrantAuthorization),
    Token(IntegrationTokenAuthorization),
}

impl Made {
    pub(super) fn view(&self) -> anyhow::Result<MadeView<'_>> {
        match self {
            Self::Grant(authorization) => MadeView::grant(authorization),
            Self::Token(authorization) => {
                Ok(MadeView::Runner(AuthorizationView::of_token(authorization)))
            }
        }
    }
}

/// What `--all` did with one grant or token.
pub(in crate::cli) enum Outcome {
    Authorized(Made),
    /// The runner was authorized for the grant already, and is left as it is.
    AlreadyAuthorized,
    /// A Codex grant authorized for another runner, which it serves in place of this one.
    AuthorizedElsewhere,
    /// A native grant of an organization other than the runner's, which cannot serve it.
    OtherOrganization,
    Refused(MemberGrantFailure),
}

impl Outcome {
    /// Whether Cloud found the runner where the grant can serve it, so that another native
    /// grant's `grant-runner-not-found` means another organization.
    const fn found_runner(&self) -> bool {
        matches!(
            self,
            Self::Authorized(_)
                | Self::AlreadyAuthorized
                | Self::AuthorizedElsewhere
                | Self::Refused(MemberGrantFailure::RunnerHoldsLogin)
        )
    }
}

/// A refusal of one grant or token that leaves `--all` to try the others; any other failure
/// ends it.
const fn refuses_one_subject(failure: &MemberGrantFailure) -> bool {
    matches!(
        failure,
        MemberGrantFailure::ProviderUnavailable
            | MemberGrantFailure::GrantNotFound
            | MemberGrantFailure::RunnerNotFound
            | MemberGrantFailure::RunnerHoldsLogin
            | MemberGrantFailure::IntegrationTokenNotFound
            | MemberGrantFailure::IntegrationTokenRunnerNotFound
    )
}

impl Command {
    pub(super) fn run(self, deployment: &Deployment) -> crate::cli::CommandResult {
        super::check_pool_org(&self.org, self.personal_pool)?;
        if self.personal_pool {
            return self.run_pool(deployment);
        }
        self.run_runner(deployment).map_err(Into::into)
    }

    fn run_runner(self, deployment: &Deployment) -> anyhow::Result<ExitCode> {
        let options = &self.options;
        let policy = options.http.transport_policy();
        let runner = RunnerArgs {
            named: self.runner.as_deref(),
            yes: self.confirmation.yes,
        };
        let grant = match (&self.grant, self.all) {
            (Some(grant), false) => grant,
            _ => return self.run_all(deployment, &runner),
        };
        let target = match subject_and_runner::<Self>(
            deployment,
            options,
            grant,
            &runner,
            |subject| runner_choice::to_authorize(deployment, policy, subject),
            |subject| runner_choice::authorizable(deployment, policy, subject),
            |subject| format!("to authorize for {}", subject.named()),
        )? {
            Ok(target) => target,
            Err(exit) => return Ok(exit),
        };
        let key = useful_support::generate_idempotency_key()
            .context("generate grant authorization request key")?;
        let runner_id = target.runner.id.as_str();
        state_then_act::<Self, _>(
            deployment,
            options,
            &target.subject,
            &format!(
                "Authorizing runner {} for {}:",
                target.runner.named,
                target.subject.named()
            ),
            target.asks,
            |api, subject| authorize(api, IntegrationTokenOwner::Member, subject, runner_id, &key),
            |api_url, subject, made, json| write(api_url, subject, &made, json),
        )
    }

    fn run_pool(&self, deployment: &Deployment) -> crate::cli::CommandResult {
        let action = confirmation::PoolAction::Authorize;
        let name = self
            .grant
            .as_ref()
            .context("personal pool authorization requires a grant")?;
        let options = &self.options;
        let selection = match super::PoolSelection::read::<Self>(
            action,
            deployment,
            options,
            name,
            &self.org,
            self.confirmation.yes,
        )? {
            Ok(selection) => selection,
            Err(exit) => return Ok(exit),
        };
        let grant = &selection.grant;
        let pool = match runner_choice::personal_pool(deployment, options, &selection.organization)?
        {
            Ok(pool) => pool,
            Err(exit) => return Ok(exit),
        };
        if let Err(exit) = selection.confirm::<Self>(
            action,
            format_args!(
                "Authorizing your personal pool {pool} for grant {}:",
                grant.id
            ),
        )? {
            return Ok(exit);
        }
        let key = useful_support::generate_idempotency_key()
            .context("generate grant authorization request key")?;
        let api_url = deployment.fingerprint().api_url();
        let answer = super::with_api(deployment, options, |api| {
            replayed(|| {
                api.authorize(
                    &grant.id,
                    useful_api::GrantAuthorizationTarget::PersonalPool(&pool),
                    &key,
                )
            })
        })?;
        Ok(match answer {
            Ok(authorization) => write_authorized(
                api_url,
                super::Holder::Grant(&grant.id),
                Made::Grant(authorization).view()?,
                options.json,
            )?,
            Err(failure) => output::pool_report(api_url, &failure).write(api_url, options.json)?,
        })
    }

    /// The runner `authorize --all` acts on, named by `--runner` among the runners of every
    /// organization the member is an active member of, and whether to ask before acting; given
    /// no `--runner` it names those runners and exits.
    fn all_runner(
        &self,
        deployment: &Deployment,
        runner: &RunnerArgs<'_>,
    ) -> anyhow::Result<Result<(Acting, bool), ExitCode>> {
        let options = &self.options;
        let example =
            |runner_id: &str| format!("{} --all --runner {runner_id} --yes", Self::COMMAND);
        let Some(named) = runner.named else {
            let offer = runner_choice::to_authorize_all(runner_choice::in_active_organizations(
                deployment,
                options.http.transport_policy(),
            ))?;
            return runner_choice::refuse(
                deployment,
                options.json,
                offer,
                None,
                super::GROUP,
                &format!("to authorize for {EVERY}"),
                example,
            )
            .map(Err);
        };
        let asks = match confirmation::asks::<Self>(runner.yes, options.json)? {
            Ok(asks) => asks,
            Err(exit) => return Ok(Err(exit)),
        };
        Ok(runner_choice::resolve(
            deployment,
            options.json,
            output::Family::Document,
            named,
            None,
            || runner_choice::in_active_organizations(deployment, options.http.transport_policy()),
            example,
        )?
        .map(|acting| (acting, asks)))
    }

    /// Authorizes the runner `--runner` names for every unrevoked grant and every token of the
    /// member that can serve it: each tried in turn, since only Cloud knows which organization
    /// the runner is in. Without `--yes` it asks after the statement where it can ask. The
    /// tokens are read only once the served read names a token service.
    fn run_all(
        &self,
        deployment: &Deployment,
        runner: &RunnerArgs<'_>,
    ) -> anyhow::Result<ExitCode> {
        let (runner, asks) = match self.all_runner(deployment, runner)? {
            Ok(acting) => acting,
            Err(exit) => return Ok(exit),
        };
        let json = self.options.json;
        let api_url = deployment.fingerprint().api_url();
        let runner_id = runner.id.as_str();
        confirmation::state(
            format_args!("Authorizing runner {} for {EVERY}:", runner.named),
            &Self::STATEMENT.every_line(),
        )?;
        if let Err(exit) = confirmation::go_on(asks)? {
            return Ok(exit);
        }
        let read = super::with_api(deployment, &self.options, |api| {
            let mut subjects: Vec<_> = every_grant(api)?
                .into_iter()
                .filter(unrevoked)
                .map(|grant| Subject::Grant(Box::new(grant)))
                .collect();
            if !integration_token::served(api)?.is_empty() {
                subjects.extend(
                    integration_token::every(api, IntegrationTokenOwner::Member)?
                        .into_iter()
                        .map(|token| Subject::Token(Box::new(token))),
                );
            }
            Ok(subjects)
        })?;
        let subjects = match read {
            Ok(subjects) if subjects.is_empty() => {
                return output::failure(api_url, &MemberGrantFailure::GrantNotFound, json);
            }
            Ok(subjects) => subjects,
            Err(failure) => return output::failure(api_url, &failure, json),
        };
        authorize_every(
            deployment,
            self.options.http.transport_policy(),
            json,
            IntegrationTokenOwner::Member,
            &subjects,
            runner_id,
            |failure| output::report(api_url, failure),
        )
    }
}

/// Authorizes `runner_id` for each of `subjects`, the grants and tokens of `owner`, in turn,
/// each under a request key of its own made before anything is sent and kept for the replay of a
/// lost answer and of a refreshed session, since only Cloud knows which organization the runner
/// is in. A refusal of one subject is its outcome; any other failure ends the command at that
/// subject, keeping the outcomes before it to report, and is reported with `report`'s remedy, as
/// is a runner nothing found.
pub(in crate::cli) fn authorize_every(
    deployment: &Deployment,
    policy: HttpTransportPolicy,
    json: bool,
    owner: IntegrationTokenOwner<'_>,
    subjects: &[Subject],
    runner_id: &str,
    report: impl Fn(&MemberGrantFailure) -> ApiFailureReport,
) -> anyhow::Result<ExitCode> {
    let api_url = deployment.fingerprint().api_url();
    let keys = subjects
        .iter()
        .map(|_| useful_support::generate_idempotency_key())
        .collect::<Result<Vec<_>, _>>()
        .context("generate a request key for each request")?;
    let mut outcomes = Vec::with_capacity(keys.len());
    let ended = with_human_session_api(deployment, policy, |api: &MemberGrantApi| {
        // A refreshed session replays every subject with its key, so the outcomes restart.
        outcomes.clear();
        for (subject, key) in subjects.iter().zip(&keys) {
            outcomes.push(authorize_one(api, owner, subject, runner_id, key)?);
        }
        Ok(())
    })?
    .err();
    let found_runner = outcomes.iter().any(Outcome::found_runner);
    match &ended {
        Some(failure) if outcomes.is_empty() => {
            return report(failure).write(api_url, json);
        }
        // Nothing found the runner: it is in none of the organizations the subjects serve.
        None if !found_runner => {
            let failure = if subjects
                .iter()
                .all(|subject| matches!(subject, Subject::Token(_)))
            {
                MemberGrantFailure::IntegrationTokenRunnerNotFound
            } else {
                MemberGrantFailure::RunnerNotFound
            };
            return report(&failure).write(api_url, json);
        }
        _ => {}
    }
    if found_runner {
        for (subject, outcome) in subjects.iter().zip(&mut outcomes) {
            if let Subject::Grant(grant) = subject
                && grant.kind == MemberGrantKind::GrantKindNative
                && matches!(
                    outcome,
                    Outcome::Refused(MemberGrantFailure::RunnerNotFound)
                )
            {
                *outcome = Outcome::OtherOrganization;
            }
        }
    }
    output::write_authorize_all(
        api_url,
        runner_id,
        subjects,
        &outcomes,
        ended.as_ref().map(&report),
        json,
    )
}

/// What `authorize --all` authorizes the runner for, as its statement and its list of runners
/// name it.
const EVERY: &str = "every grant and token of yours that can serve it";

/// Authorizes `runner_id` for `subject` under `key`, once more when the answer was lost: a
/// token through the routes of its owner, `owner`.
pub(in crate::cli) fn authorize(
    api: &MemberGrantApi,
    owner: IntegrationTokenOwner<'_>,
    subject: &Subject,
    runner_id: &str,
    key: &str,
) -> Result<Made, MemberGrantFailure> {
    match subject {
        Subject::Grant(grant) => replayed(|| {
            api.authorize(
                &grant.id,
                useful_api::GrantAuthorizationTarget::Runner(runner_id),
                key,
            )
        })
        .map(Made::Grant),
        Subject::Token(token) => {
            replayed(|| api.authorize_integration_token(owner, &token.id, runner_id, key))
                .map(Made::Token)
        }
    }
}

/// Reports the authorization of a runner for `subject`.
pub(in crate::cli) fn write(
    api_url: &str,
    subject: &Subject,
    made: &Made,
    json: bool,
) -> anyhow::Result<ExitCode> {
    write_authorized(api_url, subject.holder(), made.view()?, json)
}

/// Authorizes `runner_id` for `subject` unless it already is, reporting a refusal of this one
/// grant or token as its outcome.
fn authorize_one(
    api: &MemberGrantApi,
    owner: IntegrationTokenOwner<'_>,
    subject: &Subject,
    runner_id: &str,
    key: &str,
) -> Result<Outcome, MemberGrantFailure> {
    if subject
        .in_force()
        .iter()
        .any(|authorization| authorization.runner_id == runner_id)
    {
        return Ok(Outcome::AlreadyAuthorized);
    }
    match (authorize(api, owner, subject, runner_id, key), subject) {
        (Ok(made), _) => Ok(Outcome::Authorized(made)),
        // The grant does not list the runner, so for a native grant the authorization Cloud
        // holds is another runner's; an OAuth grant's is this runner's, made since the list.
        (Err(MemberGrantFailure::AlreadyAuthorized), Subject::Grant(grant)) => {
            Ok(match grant.kind {
                MemberGrantKind::GrantKindNative => Outcome::AuthorizedElsewhere,
                MemberGrantKind::GrantKindOAuth => Outcome::AlreadyAuthorized,
            })
        }
        // A token is authorized for any number of runners: this one, since the list.
        (Err(MemberGrantFailure::IntegrationTokenAlreadyAuthorized), _) => {
            Ok(Outcome::AlreadyAuthorized)
        }
        (Err(failure), _) if refuses_one_subject(&failure) => Ok(Outcome::Refused(failure)),
        (Err(failure), _) => Err(failure),
    }
}
