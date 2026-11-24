//! `useful org integration authorize`: authorizes a runner of the organization to be issued the
//! organization's token of a token service, or every token of it, or, with `--project`, to use
//! one of the organization's connections for the runs of that project `--runs` names, offering
//! the guided setup of a GitHub installation that is not ready. `deauthorize` ends either,
//! through the same dispatch.

use anyhow::{Context as _, anyhow};
use clap::{Args, ValueEnum};
use useful_api::{ConnectionAuthorizationRuns, MemberGrantApi};
use useful_human_auth::Deployment;

use super::authorization::{self, CONNECTION_DEAUTHORIZE, Reaching, RouteFailure, Scope, Unready};
use super::list::Options;
use super::target::{Integration, Target, VALUE_NAME};
use super::token::{GROUP, ORG_TOKEN_AUTHORIZE, OrgTokens, member_session};
use crate::cli::account::grant::authorization::Holder;
use crate::cli::account::grant::confirmation::{
    self, Confirmation, Kind, Stated, Statement, TOKEN_DEAUTHORIZE,
};
use crate::cli::account::grant::output::Family;
use crate::cli::account::grant::{InForce, RUNNER_HELP, runner_choice};
use crate::cli::context::{self, ContextFailure, OrgArgs, ProjectRef, ProjectSubject};
use crate::cli::{
    ApiFailureReport, CommandFailure, CommandResult, PrincipalAuthenticationKind,
    with_human_session_api,
};
use crate::exit_code::{ExitCode, OutcomeClass};
use useful_api::{ConnectionAuthorizationRefusal, MemberGrantFailure};

pub(super) const ABOUT: &str =
    "Authorize a runner to use the organization's token, or one of its connections in a project";
pub(super) const PROJECT_HELP: &str =
    "Project ID or exact name whose runs may use the connection; required for a connection";

#[derive(Debug, Args)]
#[group(id = "target", args = ["integration", "all"], required = true, multiple = false)]
pub(super) struct Command {
    #[arg(value_name = VALUE_NAME, value_parser = Integration::parse, help = Integration::HELP)]
    integration: Option<Integration>,

    #[arg(
        long,
        conflicts_with = "project",
        help = "Authorize the runner for every token of the organization, in place of INTEGRATION"
    )]
    all: bool,

    #[arg(long, value_name = "RUNNER", help = RUNNER_HELP)]
    runner: Option<String>,

    #[arg(long, value_name = ProjectRef::VALUE_NAME, help = PROJECT_HELP)]
    project: Option<ProjectRef>,

    #[arg(
        long,
        value_enum,
        value_name = "RUNS",
        requires = "project",
        help = "With --project, the runs of the project on the runner the authorization covers: app, its app runs, or all, every run, each acting as the organization's connection; omit for app"
    )]
    runs: Option<Runs>,

    #[command(flatten)]
    confirmation: Confirmation<Self>,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: Options,
}

/// The value of `--runs`.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Runs {
    App,
    All,
}

impl From<Runs> for ConnectionAuthorizationRuns {
    fn from(runs: Runs) -> Self {
        match runs {
            Runs::App => Self::App,
            Runs::All => Self::All,
        }
    }
}

/// Who can use the organization's token once the runner is authorized for it. What
/// authorizing a runner for a connection in a project reaches is stated once the command
/// has read it.
impl Stated for Command {
    const COMMAND: &'static str = "useful org integration authorize";
    const STATEMENT: Statement = Statement(&[(Kind::OrgToken, ORG_TOKEN_AUTHORIZE)]);
    const ACTION: &'static str = "to authorize the runner";
    const ASKS: bool = true;
}

impl Command {
    pub(super) fn execute(self, deployment: &Deployment) -> CommandResult {
        let target = match (self.integration, self.all) {
            (Some(integration), false) => Some(integration),
            _ => None,
        };
        run::<Self>(
            Leaf::Authorize,
            Arguments {
                target,
                runner: self.runner,
                project: self.project,
                runs: self
                    .runs
                    .map_or(ConnectionAuthorizationRuns::App, Into::into),
                yes: self.confirmation.yes,
                org: self.org,
                options: self.options,
            },
            deployment,
        )
    }
}

/// `useful org integration deauthorize`: ends a runner's authorization for the organization's
/// token of a token service, or, with `--project`, for one of its connections in that
/// project.
pub(super) mod deauthorize {
    use super::{
        Arguments, CONNECTION_DEAUTHORIZE, CommandResult, Confirmation,
        ConnectionAuthorizationRuns, Deployment, Integration, Kind, Leaf, Options, OrgArgs,
        PROJECT_HELP_ENDING, ProjectRef, RUNNER_HELP, Stated, Statement, TOKEN_DEAUTHORIZE,
        VALUE_NAME, run,
    };
    use clap::Args;

    pub(in crate::cli::org::connection) const ABOUT: &str = "End a runner's authorization for the organization's token, or for one of its connections in a project";

    #[derive(Debug, Args)]
    pub(in crate::cli::org::connection) struct Command {
        #[arg(value_name = VALUE_NAME, value_parser = Integration::parse, help = Integration::HELP)]
        integration: Integration,

        #[arg(long, value_name = "RUNNER", help = RUNNER_HELP)]
        runner: Option<String>,

        #[arg(long, value_name = ProjectRef::VALUE_NAME, help = PROJECT_HELP_ENDING)]
        project: Option<ProjectRef>,

        #[command(flatten)]
        confirmation: Confirmation<Self>,

        #[command(flatten)]
        org: OrgArgs,

        #[command(flatten)]
        options: Options,
    }

    /// What ending the authorization does: the token is issued to the runner no more,
    /// and the connection's permission ends.
    impl Stated for Command {
        const COMMAND: &'static str = "useful org integration deauthorize";
        const STATEMENT: Statement = Statement(&[
            (Kind::OrgToken, TOKEN_DEAUTHORIZE),
            (Kind::Connection, CONNECTION_DEAUTHORIZE),
        ]);
        const ACTION: &'static str = "to end the runner's authorization";
        const ASKS: bool = true;
    }

    impl Command {
        pub(in crate::cli::org::connection) fn execute(
            self,
            deployment: &Deployment,
        ) -> CommandResult {
            run::<Self>(
                Leaf::Deauthorize,
                Arguments {
                    target: Some(self.integration),
                    runner: self.runner,
                    project: self.project,
                    // Ending names no runs: the one authorization in force is ended.
                    runs: ConnectionAuthorizationRuns::App,
                    yes: self.confirmation.yes,
                    org: self.org,
                    options: self.options,
                },
                deployment,
            )
        }
    }
}

const PROJECT_HELP_ENDING: &str =
    "Project ID or exact name of the authorization to end; required for a connection";

/// Which of the two leaves runs.
#[derive(Clone, Copy)]
enum Leaf {
    Authorize,
    Deauthorize,
}

impl Leaf {
    const fn name(self) -> &'static str {
        match self {
            Self::Authorize => "authorize",
            Self::Deauthorize => "deauthorize",
        }
    }
}

/// What the command line of either leaf gave: the integration, or none for `authorize --all`.
struct Arguments {
    target: Option<Integration>,
    runner: Option<String>,
    project: Option<ProjectRef>,
    runs: ConnectionAuthorizationRuns,
    yes: bool,
    org: OrgArgs,
    options: Options,
}

/// Refuses with exit 2 before any request what the command line cannot act on: `--project` for a
/// token, and no `--project` for a connection, naming the form that authorizes a runner for it
/// in one project, and a service API key, which reaches none of this; asks before acting where
/// `--runner` is given without `--yes` and the command can ask, and refuses a missing `--yes`
/// elsewhere, `authorize` of a connection once it has read and stated what the authorization
/// reaches; then acts in the organization in effect.
fn run<C: Stated>(leaf: Leaf, arguments: Arguments, deployment: &Deployment) -> CommandResult {
    let Arguments {
        target,
        runner,
        project,
        runs,
        yes,
        org,
        options,
    } = arguments;
    let usage = |message: String| {
        Err(CommandFailure::with_exit_code(
            anyhow!(message),
            ExitCode::UsageError,
        ))
    };
    let name = leaf.name();
    let acting = match (target, project) {
        (Some(Integration::Token(service)), Some(_)) => {
            return usage(format!(
                "--project does not apply to a token\n\nA runner is authorized for the \
                 organization's {service} token in every project:\n  {GROUP} {name} {service} \
                 --runner RUNNER --yes"
            ));
        }
        (Some(Integration::Token(service)), None) => Acting::Token(service),
        (Some(Integration::Connection(target)), Some(project)) => {
            Acting::Connection(target, project)
        }
        (Some(Integration::Connection(target)), None) => {
            let named = target_name(&target);
            return usage(format!(
                "a connection is authorized for a runner in one project, which --project names\n\n\
                 Name the project:\n  {GROUP} {name} {named} --runner RUNNER --project PROJECT \
                 --yes"
            ));
        }
        // `--all` conflicts with `--project`.
        (None, _) => Acting::EveryToken,
    };
    member_session(
        &options.authentication,
        "the organization's tokens or connection authorizations",
    )?;
    // Authorizing for a connection states what it reaches once it has read it, so a missing
    // `--yes` is asked for or refused after that statement.
    let deferred = matches!((leaf, &acting), (Leaf::Authorize, Acting::Connection(..)));
    let asks = match runner {
        Some(_) if deferred => !yes,
        Some(_) => match confirmation::asks::<C>(yes, options.json)? {
            Ok(asks) => asks,
            Err(exit) => return Ok(exit),
        },
        None => false,
    };
    let runner = runner.as_deref();
    let service = match acting {
        Acting::Connection(target, project) => {
            return connection(
                (leaf, C::COMMAND, C::ACTION),
                (target, project, runs),
                (runner, asks),
                org,
                options,
                deployment,
            );
        }
        Acting::Token(service) => Some(service),
        Acting::EveryToken => None,
    };
    super::target::execute_in(org, options, deployment, |options, organization| {
        let tokens = OrgTokens {
            deployment,
            policy: options.http.transport_policy(),
            json: options.json,
            organization,
        };
        match (leaf, service) {
            (Leaf::Authorize, Some(service)) => tokens.authorize(&service, runner, asks),
            (Leaf::Deauthorize, Some(service)) => tokens.deauthorize(&service, runner, asks),
            (_, None) => tokens.authorize_all(runner, asks),
        }
    })
}

/// Runs `leaf` on the connection `target` names in the project `project` names, both in the
/// organization in effect, for the runs `runs` names.
fn connection(
    (leaf, command, action): (Leaf, &'static str, &'static str),
    (target, project, runs): (Target, ProjectRef, ConnectionAuthorizationRuns),
    (runner, asks): (Option<&str>, bool),
    org: OrgArgs,
    options: Options,
    deployment: &Deployment,
) -> CommandResult {
    context::execute_in_project_keeping_exit(
        org,
        ProjectSubject::Named(project),
        options,
        deployment,
        write_context_failure,
        |options, organization, project_id| {
            let scope = Scope {
                command,
                organization,
                project_id,
                target: &target,
                runs,
            };
            match leaf {
                Leaf::Authorize => {
                    authorize_connection(deployment, &options, &scope, (runner, asks), action)
                }
                Leaf::Deauthorize => {
                    end_connection_authorization(deployment, &options, &scope, runner, asks)
                        .map_err(Into::into)
                }
            }
        },
    )
}

/// What a leaf acts on once its command line is checked.
enum Acting {
    /// A runner's authorization for a connection in the project `--project` names.
    Connection(Target, ProjectRef),
    /// The organization's token of a token service.
    Token(String),
    /// Every token of the organization: `authorize --all`.
    EveryToken,
}

/// The connection as the command line named it, for a remedy.
fn target_name(target: &Target) -> &str {
    match target {
        Target::Id(_, id) => id,
        Target::Provider(provider) => provider.as_str(),
    }
}

/// A failed read of the organization or of the project `--project` names: a refusal as every
/// leaf of the family writes one, and a name no project of the organization has as
/// `project_not_found`.
fn write_context_failure(
    deployment: &str,
    failure: &ContextFailure,
    authentication: PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    match failure {
        ContextFailure::Refused(failure) => {
            super::super::output::write_context_failure(deployment, failure, authentication, json)
        }
        ContextFailure::UnknownProject => ApiFailureReport::new(
            "project_not_found",
            "error: the organization in effect has no project of that name",
            "List the organization's projects:\n  useful project list",
            OutcomeClass::GeneralFailure,
        )
        .write(deployment, json),
    }
}

/// Authorizes the runner for the connection `scope` names, in its project, for the runs it
/// names: reads what it acts on, for `github` the project and the installation that holds its
/// repository, and refuses with nothing sent where it cannot be authorized, unless that
/// installation is not ready and the member, on a terminal and without `--json`, accepts to set
/// it up first and the setup completes it; then authorizes as [`authorize_reached`] does.
fn authorize_connection(
    deployment: &Deployment,
    options: &Options,
    scope: &Scope<'_>,
    runner: (Option<&str>, bool),
    action: &str,
) -> CommandResult {
    let api_url = deployment.fingerprint().api_url();
    let json = options.json;
    let reached = match scope.reached(deployment, options, runner.0)? {
        Reaching::Reached(reached) => reached,
        Reaching::Ended(exit) => return Ok(exit),
        Reaching::Unready(unready) => {
            // Offered whatever `--yes` says: it confirms the authorization, and the setup needs
            // the member at GitHub anyway.
            if json || !confirmation::can_ask() || !offer_setup(scope, &unready)? {
                return Ok(scope.unready(&unready).write(api_url, json)?);
            }
            match scope.set_up(deployment, options, unready)? {
                Ok(reached) => reached,
                Err(exit) => return Ok(exit),
            }
        }
    };
    Ok(authorize_reached(
        deployment, options, scope, &reached, runner, action,
    )?)
}

/// Says that the installation `unready` names is not ready and what setting it up does, then
/// asks whether to set it up now: whether the answer is yes.
fn offer_setup(scope: &Scope<'_>, unready: &Unready) -> anyhow::Result<bool> {
    let offer = scope.setup_offer(unready);
    confirmation::state(format_args!("{}", offer.finding), &offer.lines)?;
    Ok(confirmation::ask(format_args!("{}", offer.question))?)
}

/// Authorizes the runner for `reached`, the connection [`authorize_connection`] read: the runner
/// `--runner` names, an ID or a name among the organization's runners; given none, names those
/// that hold no authorization in force for the project and the provider and exits 2. It states
/// what the authorization reaches, asks where `asks` on a terminal and without `--json` and
/// refuses with exit 2 elsewhere, and sends the authorization under one key, once more under it
/// when the answer was lost.
fn authorize_reached(
    deployment: &Deployment,
    options: &Options,
    scope: &Scope<'_>,
    reached: &authorization::Reached,
    (runner, asks): (Option<&str>, bool),
    action: &str,
) -> anyhow::Result<ExitCode> {
    let api_url = deployment.fingerprint().api_url();
    let json = options.json;
    let policy = options.http.transport_policy();
    let connection = &reached.connection;
    let holder = Some(Holder::Connection(connection.id()));
    let example = |runner_id: &str| scope.command_line(runner_id, Some(connection.id()));
    let in_organization = || runner_choice::in_organization(deployment, policy, scope.organization);
    let Some(named) = runner else {
        let read = with_human_session_api(deployment, policy, |api: &MemberGrantApi| {
            scope.in_force(api, None)
        })?;
        let in_force: Vec<_> = match RouteFailure::answered(read) {
            Ok(in_force) => in_force
                .into_iter()
                .map(|authorization| authorization.runner_id)
                .collect(),
            Err(failure) => return scope.report(api_url, &failure).write(api_url, json),
        };
        let offer = runner_choice::unauthorized(in_organization(), |runner_id| {
            in_force.iter().any(|authorized| authorized == runner_id)
        })?;
        return runner_choice::refuse(
            deployment,
            json,
            offer,
            holder,
            GROUP,
            &format!(
                "to authorize for the {} connection {}",
                connection.provider().as_str(),
                connection.id()
            ),
            example,
        );
    };
    let runner = match runner_choice::resolve(
        deployment,
        json,
        Family::Document,
        named,
        holder,
        in_organization,
        example,
    )? {
        Ok(runner) => runner,
        Err(exit) => return Ok(exit),
    };
    confirmation::state(
        format_args!("{}", scope.heading(&runner.named, connection)),
        &scope.statement(reached),
    )?;
    if let Err(exit) =
        confirmation::go_on_or_refuse(asks, json, action, &scope.command_line(&runner.id, None))?
    {
        return Ok(exit);
    }
    let key = useful_support::generate_idempotency_key()
        .context("generate connection authorization request key")?;
    let made = with_human_session_api(deployment, policy, |api: &MemberGrantApi| {
        scope.authorize(api, connection.id(), &runner.id, &key)
    })?;
    match RouteFailure::answered(made) {
        Ok(made) => authorization::write_authorized(api_url, &made, json),
        Err(failure) => scope
            .refused_authorization(api_url, &failure)
            .write(api_url, json),
    }
}

/// Ends the runner's authorization for the connection `scope` names, in its project: finds it
/// among the organization's authorizations in force for the project and the provider, of the
/// connection `INTEGRATION` names by ID where it names one, and of the runner `--runner` names,
/// an ID or a name among the runners that hold one; given none, names those runners and exits 2.
/// None is reported `authorization_not_found`, with nothing more sent. It states that the
/// permission ends, asks where `asks`, and ends it under one key, once more under it when the
/// answer was lost.
fn end_connection_authorization(
    deployment: &Deployment,
    options: &Options,
    scope: &Scope<'_>,
    runner: Option<&str>,
    asks: bool,
) -> anyhow::Result<ExitCode> {
    let api_url = deployment.fingerprint().api_url();
    let json = options.json;
    let policy = options.http.transport_policy();
    let report = |failure: &RouteFailure| scope.report(api_url, failure);
    let not_found = || {
        report(&RouteFailure::Failed(
            MemberGrantFailure::ConnectionAuthorizationRefused(
                ConnectionAuthorizationRefusal::AuthorizationNotFound,
            ),
        ))
        .write(api_url, json)
    };
    // A runner named by its ID keeps its authorization alone; a name is looked up among the
    // runners of every one in force.
    let runner_id = runner.filter(|runner| useful_support::valid_typed_id(runner, "rnr_"));
    let read = with_human_session_api(deployment, policy, |api: &MemberGrantApi| {
        scope.to_end(api, runner_id)
    })?;
    let in_force = match RouteFailure::answered(read) {
        Ok(in_force) if in_force.is_empty() => return not_found(),
        Ok(in_force) => in_force,
        Err(failure) => return report(&failure).write(api_url, json),
    };
    // The connection every authorization in force names, which the runner list names.
    let connection = in_force
        .first()
        .map(|first| first.connection_id.as_str())
        .filter(|first| {
            in_force
                .iter()
                .all(|authorization| authorization.connection_id == *first)
        });
    let holder = connection.map(Holder::Connection);
    let example = |runner_id: &str| scope.command_line(runner_id, None);
    let holding = || {
        let in_force: Vec<_> = in_force
            .iter()
            .map(|authorization| InForce {
                id: &authorization.id,
                runner_id: &authorization.runner_id,
                organization_id: &authorization.organization_id,
            })
            .collect();
        runner_choice::holding(deployment, policy, &in_force)
    };
    let Some(named) = runner else {
        let offer = runner_choice::to_deauthorize(holding())?;
        return runner_choice::refuse(
            deployment,
            json,
            offer,
            holder,
            GROUP,
            "whose authorization for the connection to end",
            example,
        );
    };
    let runner = match runner_choice::resolve(
        deployment,
        json,
        Family::Document,
        named,
        holder,
        holding,
        example,
    )? {
        Ok(runner) => runner,
        Err(exit) => return Ok(exit),
    };
    // Cloud holds at most one in force for the project, the runner and the provider.
    let Some(authorization) = in_force
        .iter()
        .find(|authorization| authorization.runner_id == runner.id)
    else {
        return not_found();
    };
    confirmation::state(
        format_args!("{}", scope.ending_heading(&runner.named, authorization)),
        CONNECTION_DEAUTHORIZE,
    )?;
    if let Err(exit) = confirmation::go_on(asks)? {
        return Ok(exit);
    }
    let key = useful_support::generate_idempotency_key()
        .context("generate connection deauthorization request key")?;
    let ended = with_human_session_api(deployment, policy, |api: &MemberGrantApi| {
        scope.end(api, &authorization.id, &key)
    })?;
    match RouteFailure::answered(ended) {
        Ok(()) => authorization::write_deauthorized(api_url, authorization, json),
        Err(failure) => report(&failure).write(api_url, json),
    }
}
