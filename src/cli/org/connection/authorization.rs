//! A runner's authorization for one of the organization's connections in one project: the
//! connection `authorize INTEGRATION --project` chooses, for `github` the installation that
//! holds the project's repository, read with the project and offered the guided setup where it
//! needs it; the organization's authorizations in force for the project, read to name a runner
//! or to find the one to end; the statement of what an authorization reaches; the authorization
//! made, for the runs `--runs` names, or ended, each through the member grant client's
//! connection authorization routes under the member's session; and what `list` and `show` print
//! of the authorizations in force under each connection. A generic `not-found` from one of
//! those routes is resolved by one read of the organization, since a deployment that routes
//! none of them answers it as it answers an organization the member cannot read; `list` and
//! `show` pass it over with no such read.

use std::io::{self, Write};

use anyhow::Context as _;
use serde::{Serialize, Serializer};
use useful_api::{
    ConnectionAuthorization, ConnectionAuthorizationFilter, ConnectionAuthorizationRefusal,
    ConnectionAuthorizationRequest, ConnectionAuthorizationRuns, ConnectionAuthorizationScope,
    ConnectionAuthorizationState, GitHubInstallation, GitHubInstallationState,
    GitHubRepositorySelection, HttpTransportPolicy, MemberGrantApi, MemberGrantFailure,
    ProjectFailure, ProjectRepository, UnreachableCategory,
};
use useful_execution::visible_text;
use useful_human_auth::Deployment;

use super::github::{self, Guidance};
use super::list::{self, Options, Provider, Record};
use super::target::Target;
use crate::cli::account::grant::{output as grant_output, replayed};
use crate::cli::paging::every_page;
use crate::cli::{
    ApiFailureReport, CommandFailure, CommonArgs, PrincipalAuthenticationArgs,
    PrincipalAuthenticationKind, project, with_human_session_api,
};
use crate::exit_code::{ExitCode, OutcomeClass};

// The largest page the connection authorization list serves.
const PAGE: i32 = 200;

/// What ending a runner's authorization for a connection in one project does: the runner is
/// issued the installation no more for the project's runs, a token issued already lives out
/// its hour, and no run is touched.
pub(super) const CONNECTION_DEAUTHORIZE: &[&str] = &[
    "the runner is issued the connection no more for the project's runs",
    "a token already issued stays valid until it expires, within the hour",
    "no run is asked to stop",
];

/// The state word of a connection a runner can be authorized for.
const ACTIVE: &str = "active";

/// The connection authorizations in force of the organization `organization` names, of the
/// connection `connection` alone where one is given, oldest first, read to the last page under
/// the member's session. `None` where Cloud refused the read, as it refuses a member who is not
/// an owner, answered the generic `not-found`, as a deployment that does not route it does, or
/// answered that it cannot serve it: `list` and `show` pass those over. Any other failure is the
/// inner error.
pub(super) fn in_force(
    deployment: &Deployment,
    policy: HttpTransportPolicy,
    organization: &str,
    connection: Option<&str>,
) -> anyhow::Result<Result<Option<Vec<ConnectionAuthorization>>, MemberGrantFailure>> {
    let filter = ConnectionAuthorizationFilter {
        connection_id: connection,
        ..ConnectionAuthorizationFilter::default()
    };
    let read = with_human_session_api(deployment, policy, |api: &MemberGrantApi| {
        every_page(invalid(), |cursor| {
            api.connection_authorizations(organization, filter, Some(PAGE), cursor)
                .map(|page| (page.items, page.next_cursor))
        })
    })?;
    Ok(match read {
        Ok(authorizations) => Ok(Some(authorizations)),
        Err(
            MemberGrantFailure::Forbidden
            | MemberGrantFailure::OrganizationNotFound
            | MemberGrantFailure::Unreachable {
                category: UnreachableCategory::Server,
            },
        ) => Ok(None),
        Err(failure) => Err(failure),
    })
}

/// The authorizations in force of the connection `connection_id` that `show` prints under it:
/// none under a service API key, which the member's routes do not admit, nor where the read
/// was passed over. A read that fails otherwise is reported, and its exit status is the inner
/// error.
pub(super) fn of_connection(
    deployment: &Deployment,
    options: &Options,
    organization: &str,
    connection_id: &str,
) -> anyhow::Result<Result<Option<InForce>, ExitCode>> {
    if options.authentication.kind() == PrincipalAuthenticationKind::ServiceApiKey {
        return Ok(Ok(None));
    }
    let policy = options.http.transport_policy();
    Ok(
        match in_force(deployment, policy, organization, Some(connection_id))? {
            Ok(read) => Ok(read.map(|authorizations| InForce::of(&authorizations, connection_id))),
            Err(failure) => {
                let api_url = deployment.fingerprint().api_url();
                Err(grant_output::report(api_url, &failure).write(api_url, options.json)?)
            }
        },
    )
}

/// The authorizations in force of one connection, as `list` and `show` print them under it.
pub(super) struct InForce(Vec<ConnectionAuthorization>);

impl InForce {
    /// Those of `authorizations` that name the connection `connection_id`.
    pub(super) fn of(authorizations: &[ConnectionAuthorization], connection_id: &str) -> Self {
        Self(
            authorizations
                .iter()
                .filter(|authorization| authorization.connection_id == connection_id)
                .cloned()
                .collect(),
        )
    }

    /// Writes each authorization's lines of a human report, each line after `indent`.
    pub(super) fn write_human(&self, output: &mut impl Write, indent: &str) -> io::Result<()> {
        for authorization in &self.0 {
            AuthorizationView::new(authorization).write_human(output, indent)?;
        }
        Ok(())
    }
}

impl Serialize for InForce {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(AuthorizationView::new))
    }
}

/// A runner's authorization for a connection in one project, as a command prints it: what
/// names it, its runs, its repository, null where Cloud answered none, who made it and when,
/// and its scope. Never a credential: an authorization holds none, and only these named
/// fields are printed.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizationView<'a> {
    #[serde(flatten)]
    named: NamedView<'a>,
    runs: &'static str,
    repository: Option<&'a str>,
    authorized_by: &'a str,
    created_at: &'a str,
    scope: ScopeView<'a>,
}

/// What names a runner's authorization for a connection: its ID and provider, its project,
/// runner and connection, which the report of one ended prints alone.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NamedView<'a> {
    id: &'a str,
    provider: &'a str,
    project_id: &'a str,
    project_name: &'a str,
    runner_id: &'a str,
    runner_name: &'a str,
    connection_id: &'a str,
    connection_account: &'a str,
}

/// What the provider grants the authorization's connection: its state, and for a `current`
/// GitHub scope the App it acts as and the installation's repository selection and permissions.
#[derive(Serialize)]
struct ScopeView<'a> {
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    github: Option<GitHubScopeView<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GitHubScopeView<'a> {
    app_slug: &'a str,
    repository_selection: &'static str,
    permissions: Vec<PermissionView<'a>>,
}

/// A permission the installation grants, its name and access as GitHub reports them.
#[derive(Serialize)]
struct PermissionView<'a> {
    name: &'a str,
    access: &'a str,
}

impl<'a> ScopeView<'a> {
    fn new(scope: &'a ConnectionAuthorizationScope) -> Self {
        let current = scope.state == ConnectionAuthorizationState::Current;
        Self {
            state: match scope.state {
                ConnectionAuthorizationState::Current => "current",
                ConnectionAuthorizationState::Unavailable => "unavailable",
            },
            github: scope
                .github
                .as_deref()
                .filter(|_| current)
                .map(|github| GitHubScopeView {
                    app_slug: &github.app_slug,
                    repository_selection: match github.repository_selection {
                        GitHubRepositorySelection::GitHubInstallationScopeRepositorySelectionAll => {
                            "all"
                        }
                        GitHubRepositorySelection::GitHubInstallationScopeRepositorySelectionSelected => {
                            "selected"
                        }
                    },
                    permissions: github
                        .permissions
                        .iter()
                        .map(|permission| PermissionView {
                            name: &permission.name,
                            access: &permission.access,
                        })
                        .collect(),
                }),
        }
    }

    /// Writes the scope's lines of a human report: the App the authorization acts as, the
    /// repository selection and one line for each permission, which are GitHub's text and
    /// printed visibly; that the provider could not be read; or, for a `current` scope this
    /// release knows no member of, `current` alone.
    fn write_human(&self, output: &mut impl Write, indent: &str) -> io::Result<()> {
        match (&self.github, self.state) {
            (Some(github), _) => {
                writeln!(output, "{indent}acts as: {}", visible_text(github.app_slug))?;
                writeln!(
                    output,
                    "{indent}scope: {} repositories",
                    github.repository_selection
                )?;
                for permission in &github.permissions {
                    writeln!(
                        output,
                        "{indent}permission: {} · {}",
                        visible_text(permission.name),
                        visible_text(permission.access)
                    )?;
                }
                Ok(())
            }
            (None, "unavailable") => writeln!(
                output,
                "{indent}scope: unavailable, the provider could not be read"
            ),
            (None, state) => writeln!(output, "{indent}scope: {state}"),
        }
    }
}

impl<'a> AuthorizationView<'a> {
    fn new(authorization: &'a ConnectionAuthorization) -> Self {
        Self {
            named: NamedView::new(authorization),
            runs: ConnectionAuthorizationRuns::of(authorization.runs).name(),
            repository: authorization.repository.as_deref(),
            authorized_by: &authorization.authorized_by,
            created_at: &authorization.created_at,
            scope: ScopeView::new(&authorization.scope),
        }
    }

    /// Writes the view's lines of a human report: what names the authorization, its runs and
    /// its repository, another party's text, or why it has none, then who made it and when, and
    /// its scope.
    fn write_human(&self, output: &mut impl Write, indent: &str) -> io::Result<()> {
        self.named.write_human(output, indent)?;
        writeln!(output, "{indent}runs: {}", self.runs)?;
        match self.repository {
            Some(repository) => {
                writeln!(output, "{indent}repository: {}", visible_text(repository))?;
            }
            None => writeln!(
                output,
                "{indent}repository: none, the project has no active repository of this connection"
            )?,
        }
        writeln!(output, "{indent}authorized by: {}", self.authorized_by)?;
        writeln!(output, "{indent}authorized at: {}", self.created_at)?;
        self.scope.write_human(output, indent)
    }
}

impl<'a> NamedView<'a> {
    fn new(authorization: &'a ConnectionAuthorization) -> Self {
        Self {
            id: &authorization.id,
            provider: &authorization.provider,
            project_id: &authorization.project_id,
            project_name: &authorization.project_name,
            runner_id: &authorization.runner_id,
            runner_name: &authorization.runner_name,
            connection_id: &authorization.connection_id,
            connection_account: &authorization.connection_account,
        }
    }

    /// Writes the view's lines of a human report. What Cloud names, a project, a runner and an
    /// account, is another party's text and is printed visibly, each with its ID.
    fn write_human(&self, output: &mut impl Write, indent: &str) -> io::Result<()> {
        writeln!(output, "{indent}authorization: {}", self.id)?;
        writeln!(output, "{indent}provider: {}", self.provider)?;
        writeln!(
            output,
            "{indent}project: {} ({})",
            visible_text(self.project_name),
            self.project_id
        )?;
        writeln!(
            output,
            "{indent}runner: {} ({})",
            visible_text(self.runner_name),
            self.runner_id
        )?;
        writeln!(
            output,
            "{indent}connection: {} ({})",
            visible_text(self.connection_account),
            self.connection_id
        )
    }
}

/// A failure of an operation on a connection authorization route, as the command reports it.
pub(super) enum RouteFailure {
    /// The failure the member grant client answered.
    Failed(MemberGrantFailure),
    /// The deployment routes no connection authorization: a route answered the generic
    /// `not-found` while the organization answers its read.
    NotServed,
}

impl RouteFailure {
    /// What `read`, an operation on a connection authorization route run under the member's
    /// session, answered: its value, or the failure of the route or of the session.
    pub(super) fn answered<T>(
        read: Result<Result<T, Self>, MemberGrantFailure>,
    ) -> Result<T, Self> {
        read.map_err(Self::Failed).and_then(|answered| answered)
    }
}

/// The organization's connection authorizations at one provider in one project, which
/// `authorize` and `deauthorize` given `--project` act on: the organization by the reference in
/// effect, the project by its ID, the connection `INTEGRATION` names, by its provider or its ID,
/// the leaf's command path and the runs `authorize` makes one for.
pub(super) struct Scope<'a> {
    pub(super) command: &'static str,
    pub(super) organization: &'a str,
    pub(super) project_id: &'a str,
    pub(super) target: &'a Target,
    /// The runs `--runs` names, `app` where it names none.
    pub(super) runs: ConnectionAuthorizationRuns,
}

/// What `authorize` acts on, read before it names a runner: the connection, and for `github` the
/// full name of the project's repository, the one repository a token of the installation reaches
/// for the project's runs.
pub(super) struct Reached {
    pub(super) connection: Record,
    pub(super) repository: Option<String>,
}

/// What `authorize` came to of what it read before it names a runner.
pub(super) enum Reaching {
    /// What it acts on.
    Reached(Reached),
    /// For `github`, the installation that holds the project's repository, which is not ready:
    /// reported, or on a terminal offered to set up.
    Unready(Box<Unready>),
    /// It ends here with this status, having reported why.
    Ended(ExitCode),
}

/// The installation that holds the project's repository, which is not `active` or whose
/// authority was never verified, with that repository's full name.
pub(super) struct Unready {
    installation: GitHubInstallation,
    repository: String,
    not_ready: NotReady,
}

/// How a connection a runner is to be authorized for is not ready.
#[derive(Clone, Copy)]
enum NotReady {
    /// It is not `active`.
    Inactive,
    /// Its authority was never verified.
    Unverified,
}

/// Why `authorize github` sends no authorization for the project: what it read of the project
/// and the organization's installations, judged in this order.
enum Unreached {
    /// The project has no repository, or one that is not GitHub's or not `active`, or
    /// `INTEGRATION` names another installation than the one that holds it; the reason, as the
    /// refusal states it.
    RepositoryNotConnected(&'static str),
    /// The installation the project's repository names is not among those listed, by its ID.
    ConnectionNotFound(String),
    /// That installation is not `active`, or its authority was never verified.
    Unready(Box<Unready>),
}

impl Unready {
    /// `installation`, holding the repository `repository`, where it is not ready: not
    /// `active`, or its authority never verified.
    fn of(installation: GitHubInstallation, repository: String) -> Result<Reached, Box<Self>> {
        let not_ready = if installation.state != GitHubInstallationState::Active {
            NotReady::Inactive
        } else if installation.authority_verified_at.is_none() {
            NotReady::Unverified
        } else {
            return Ok(Reached {
                connection: Record::Github(installation),
                repository: Some(repository),
            });
        };
        Err(Box::new(Self {
            installation,
            repository,
            not_ready,
        }))
    }
}

impl Unreached {
    /// What the organization's GitHub `records`, read from its list of installations, reach of
    /// the project whose repository is `repository`, with `named` the installation `INTEGRATION`
    /// names by ID.
    fn judged(
        repository: Option<ProjectRepository>,
        records: Vec<Record>,
        named: Option<&str>,
    ) -> Result<Reached, Self> {
        let Some(repository) = repository else {
            return Err(Self::RepositoryNotConnected("has no repository"));
        };
        let github =
            useful_support::wire_name(repository.provider_kind).as_deref() == Some("github");
        let binding = match repository.installation_binding_id {
            Some(binding) if github => binding,
            _ => {
                return Err(Self::RepositoryNotConnected(
                    "has a repository that is not GitHub's",
                ));
            }
        };
        if useful_support::wire_name(repository.availability).as_deref() != Some(ACTIVE) {
            return Err(Self::RepositoryNotConnected(
                "has a repository that is not active",
            ));
        }
        if named.is_some_and(|named| named != binding) {
            return Err(Self::RepositoryNotConnected(
                "has a repository that another installation than the one named holds",
            ));
        }
        let Some(installation) = records.into_iter().find_map(|record| match record {
            Record::Github(installation) if installation.id == binding => Some(installation),
            _ => None,
        }) else {
            return Err(Self::ConnectionNotFound(binding));
        };
        Unready::of(installation, repository.full_name).map_err(Self::Unready)
    }
}

/// What `authorize github` says on a terminal of an installation that is not ready, before it
/// offers to set it up: the finding, as a statement's heading, what setting it up does, as its
/// lines, and the question.
pub(super) struct SetupOffer {
    pub(super) finding: String,
    pub(super) lines: [&'static str; 3],
    pub(super) question: String,
}

impl Scope<'_> {
    const fn provider(&self) -> Provider {
        self.target.provider()
    }

    /// The connection `INTEGRATION` named by its ID, where it named one.
    fn connection_id(&self) -> Option<&str> {
        match self.target {
            Target::Id(_, id) => Some(id),
            Target::Provider(_) => None,
        }
    }

    /// The leaf's command line for `runner` and the connection `connection`, by its ID, or
    /// where none is given as `INTEGRATION` named it, with `--runs` where it names `all`.
    pub(super) fn command_line(&self, runner: &str, connection: Option<&str>) -> String {
        let named = connection
            .or_else(|| self.connection_id())
            .unwrap_or(self.provider().as_str());
        let runs = match self.runs {
            ConnectionAuthorizationRuns::App => "",
            ConnectionAuthorizationRuns::All => " --runs all",
        };
        format!(
            "{} {named} --runner {runner} --project {} --org {}{runs} --yes",
            self.command, self.project_id, self.organization
        )
    }

    /// What `authorize` acts on, read under `options` before any runner is named. For
    /// `github`: the project, whose read not finding it is `project_not_found`, then the
    /// organization's installations, judged by [`Unreached::judged`], an installation that is
    /// not ready left to the leaf to report or offer to set up. For `gitlab` and `linear`: the
    /// connection [`Scope::connection`] takes. Otherwise the command ends here, having
    /// reported why, with nothing sent.
    pub(super) fn reached(
        &self,
        deployment: &Deployment,
        options: &Options,
        runner: Option<&str>,
    ) -> anyhow::Result<Reaching> {
        if self.provider() != Provider::Github {
            return Ok(match self.connection(deployment, options, runner)? {
                Ok(connection) => Reaching::Reached(Reached {
                    connection,
                    repository: None,
                }),
                Err(exit) => Reaching::Ended(exit),
            });
        }
        let api_url = deployment.fingerprint().api_url();
        let json = options.json;
        let repository = match self.project_repository(deployment, options)? {
            Ok(repository) => repository,
            Err(failure) => {
                return self
                    .report(api_url, &RouteFailure::Failed(failure))
                    .write(api_url, json)
                    .map(Reaching::Ended);
            }
        };
        let records = match list::read(self.provider(), deployment, options, self.organization)? {
            Ok(records) => records,
            Err(refusal) => {
                return refusal
                    .write(deployment, self.organization, options)
                    .map(Reaching::Ended);
            }
        };
        match Unreached::judged(repository, records, self.connection_id()) {
            Ok(reached) => Ok(Reaching::Reached(reached)),
            Err(Unreached::Unready(unready)) => Ok(Reaching::Unready(unready)),
            Err(unreached) => self
                .unreached(&unreached)
                .write(api_url, json)
                .map(Reaching::Ended),
        }
    }

    /// The repository of the project, or none, read under `options`; a failed read as the
    /// nearest failure of a connection authorization route, a project not found as Cloud's
    /// own refusal of one.
    fn project_repository(
        &self,
        deployment: &Deployment,
        options: &Options,
    ) -> anyhow::Result<Result<Option<ProjectRepository>, MemberGrantFailure>> {
        let read = project::with_api(
            deployment,
            options.http.transport_policy(),
            &options.authentication,
            |api| api.get(self.organization, self.project_id),
        )?;
        Ok(read
            .map(|project| project.repository.map(|repository| *repository))
            .map_err(project_failure))
    }

    /// The refusal of `unreached`: `repository_not_connected` with the command that shows
    /// the project, `connection_not_found` with the list of the organization's
    /// integrations, and an installation that is not ready as [`Scope::unready`] reports
    /// it.
    fn unreached(&self, unreached: &Unreached) -> ApiFailureReport {
        match unreached {
            Unreached::RepositoryNotConnected(reason) => ApiFailureReport::new(
                "repository_not_connected",
                format!(
                    "error: the project {} {reason}, so no GitHub installation of the \
                     organization {} can be authorized for its runs",
                    self.project_id, self.organization
                ),
                format!(
                    "Show the project's repository:\n  useful project show {} --org {}",
                    self.project_id, self.organization
                ),
                OutcomeClass::GeneralFailure,
            ),
            Unreached::ConnectionNotFound(id) => {
                no_connection(self.organization, self.provider(), Some(id))
            }
            Unreached::Unready(unready) => self.unready(unready),
        }
    }

    /// The refusal of authorizing for the installation `unready` names, where no setup ran:
    /// `connection_inactive` or `connection_unverified`, exit 1, naming the guided setup of
    /// that installation by its GitHub ID.
    pub(super) fn unready(&self, unready: &Unready) -> ApiFailureReport {
        connection_not_ready(
            self.organization,
            self.provider(),
            unready.not_ready,
            Some(&unready.installation),
        )
    }

    /// What `authorize` says on a terminal of the installation `unready` names, and the question
    /// with which it offers to set it up. The installation's account and the repository are
    /// another party's text.
    pub(super) fn setup_offer(&self, unready: &Unready) -> SetupOffer {
        let organization = self.organization;
        let installation = &unready.installation;
        let account = visible_text(&installation.provider_account_login);
        let repository = visible_text(&unready.repository);
        let standing = match unready.not_ready {
            NotReady::Inactive => format!("is not active in the organization {organization}"),
            NotReady::Unverified => {
                format!("was never verified for the organization {organization}")
            }
        };
        SetupOffer {
            finding: format!(
                "The GitHub installation {} on {account}, which holds the project's repository \
                 {repository}, {standing}. Connecting it now:",
                installation.id
            ),
            lines: [
                "begins a GitHub setup session for the organization that names the installation",
                "waits while you prove at GitHub that you administer it",
                "authorizes the runner once the setup completes, after stating what it reaches",
            ],
            question: format!(
                "Connect the installation on {account} that holds {repository} to the \
                 organization {organization} now?"
            ),
        }
    }

    /// Runs the guided setup of the installation `unready` names for the organization, under the
    /// member's session with the transport `options` selects, as `useful org integration connect
    /// github --installation ID` runs it, printing its reports. Where it completes and answers
    /// that installation `active` and verified, what `authorize` then acts on; where it answers
    /// another or one not ready, the refusal [`Scope::unready`] words; otherwise the setup's
    /// status, its report naming the next step.
    pub(super) fn set_up(
        &self,
        deployment: &Deployment,
        options: &Options,
        unready: Box<Unready>,
    ) -> Result<Result<Reached, ExitCode>, CommandFailure> {
        let guided = github::guide(
            deployment,
            CommonArgs::new(
                false,
                PrincipalAuthenticationArgs::default(),
                crate::cli::HttpOptions {
                    allow_insecure_http: options.http.allow_insecure_http,
                },
            ),
            Guidance {
                organization: self.organization,
                installation: Some(&unready.installation.provider_installation_id),
                binding: None,
                listed: None,
                no_wait: false,
                timeout: None,
            },
        )?;
        let Some(completed) = guided.completed else {
            return Ok(Err(guided.status));
        };
        let unready = if completed.id == unready.installation.id {
            match Unready::of(completed, unready.repository) {
                Ok(reached) => return Ok(Ok(reached)),
                Err(unready) => unready,
            }
        } else {
            unready
        };
        let api_url = deployment.fingerprint().api_url();
        Ok(Err(self.unready(&unready).write(api_url, false)?))
    }

    /// What authorizing the runner reaches, which `authorize` states before it acts: the runs
    /// the authorization covers; for `github`, besides, the account that owns the installation
    /// and the project's repository, each another party's text, that the runs act as Cloud's
    /// GitHub App, and that the runner is issued a token for a run only.
    pub(super) fn statement(&self, reached: &Reached) -> Vec<String> {
        let github = self.provider() == Provider::Github;
        let runs = match (self.runs, github) {
            (ConnectionAuthorizationRuns::App, _) => {
                "the authorization covers every app run of the project on the runner, whoever or \
                 whatever caused it; members' runs are unaffected"
            }
            (ConnectionAuthorizationRuns::All, true) => {
                "the authorization covers every run of the project on the runner: each member's \
                 run acts at GitHub as the App, and no member's GitHub sign-in is used there"
            }
            (ConnectionAuthorizationRuns::All, false) => {
                "the authorization covers every run of the project on the runner, whoever caused \
                 it"
            }
        };
        let mut lines = vec![runs.to_owned()];
        if github {
            if let Some(account) = reached.connection.account() {
                lines.push(format!(
                    "the GitHub account {} owns the installation",
                    visible_text(account)
                ));
            }
            if let Some(repository) = reached.repository.as_deref() {
                lines.push(format!(
                    "a token reaches one repository, the project's: {}",
                    visible_text(repository)
                ));
            }
            lines.extend(
                [
                    "the runs act as Cloud's GitHub App: GitHub attributes the commits, pushes \
                     and pull requests made with the token to the App, not to a member",
                    "the runner is issued a token for a run only, each expiring within the hour",
                ]
                .map(str::to_owned),
            );
        }
        lines
    }

    /// The connection a runner is authorized for, read from the provider's list of the
    /// organization's connections under the leaf's credential: the one `INTEGRATION` names by
    /// ID, whatever its state, else the one whose state is `active`. Otherwise the command ends
    /// here, having reported it: several `active`, exit 2 (`connection_required`), naming each by
    /// ID and account with the command line that names one; none, or none by the ID named,
    /// exit 1 (`connection_not_found`); or the read's refusal, as the provider's commands report
    /// it.
    pub(super) fn connection(
        &self,
        deployment: &Deployment,
        options: &Options,
        runner: Option<&str>,
    ) -> anyhow::Result<Result<Record, ExitCode>> {
        let api_url = deployment.fingerprint().api_url();
        let json = options.json;
        let records = match list::read(self.provider(), deployment, options, self.organization)? {
            Ok(records) => records,
            Err(refusal) => {
                return refusal
                    .write(deployment, self.organization, options)
                    .map(Err);
            }
        };
        let not_found = || {
            no_connection(self.organization, self.provider(), self.connection_id())
                .write(api_url, json)
                .map(Err)
        };
        if let Some(named) = self.connection_id() {
            return match records.into_iter().find(|record| record.id() == named) {
                Some(record) => Ok(Ok(record)),
                None => not_found(),
            };
        }
        let mut active: Vec<_> = records
            .into_iter()
            .filter(|record| record.state() == ACTIVE)
            .collect();
        match active.len() {
            0 => not_found(),
            1 => Ok(Ok(active.remove(0))),
            _ => {
                let example =
                    self.command_line(runner.unwrap_or("RUNNER"), active.first().map(Record::id));
                write_connection_required(api_url, self.provider(), &active, &example, json)
                    .map(Err)
            }
        }
    }

    /// The organization's authorizations in force for the project and the provider, of
    /// `runner_id` alone where one is given, read to the last page: those that hold the
    /// project and the provider for a runner, whichever connection they name.
    pub(super) fn in_force(
        &self,
        api: &MemberGrantApi,
        runner_id: Option<&str>,
    ) -> Result<Result<Vec<ConnectionAuthorization>, RouteFailure>, MemberGrantFailure> {
        self.listed(api, runner_id, None)
    }

    /// The authorizations [`Scope::in_force`] reads, of `runner_id` alone where one is given
    /// and of the connection `INTEGRATION` names by ID alone where it names one: those
    /// `deauthorize` can end.
    pub(super) fn to_end(
        &self,
        api: &MemberGrantApi,
        runner_id: Option<&str>,
    ) -> Result<Result<Vec<ConnectionAuthorization>, RouteFailure>, MemberGrantFailure> {
        self.listed(api, runner_id, self.connection_id())
    }

    fn listed(
        &self,
        api: &MemberGrantApi,
        runner_id: Option<&str>,
        connection_id: Option<&str>,
    ) -> Result<Result<Vec<ConnectionAuthorization>, RouteFailure>, MemberGrantFailure> {
        let filter = ConnectionAuthorizationFilter {
            project_id: Some(self.project_id),
            runner_id,
            provider: Some(self.provider().wire()),
            connection_id,
        };
        let read = every_page(invalid(), |cursor| {
            api.connection_authorizations(self.organization, filter, Some(PAGE), cursor)
                .map(|page| (page.items, page.next_cursor))
        });
        self.resolved(api, read)
    }

    /// Authorizes `runner_id` for `connection_id` in the project for the runs `--runs` named
    /// under `key`, once more under the same key when the answer was lost. The runs are sent
    /// on every request, and never dropped.
    pub(super) fn authorize(
        &self,
        api: &MemberGrantApi,
        connection_id: &str,
        runner_id: &str,
        key: &str,
    ) -> Result<Result<ConnectionAuthorization, RouteFailure>, MemberGrantFailure> {
        let request = ConnectionAuthorizationRequest {
            project_id: self.project_id,
            runner_id,
            provider: self.provider().wire(),
            connection_id,
            runs: self.runs,
        };
        let made = replayed(|| api.authorize_connection(self.organization, &request, key));
        self.resolved(api, made)
    }

    /// Ends the authorization `authorization_id` under `key`, once more under the same key when
    /// the answer was lost.
    pub(super) fn end(
        &self,
        api: &MemberGrantApi,
        authorization_id: &str,
        key: &str,
    ) -> Result<Result<(), RouteFailure>, MemberGrantFailure> {
        let ended =
            replayed(|| api.end_connection_authorization(self.organization, authorization_id, key));
        self.resolved(api, ended)
    }

    /// `answer`, an answer of a connection authorization route, with a generic `not-found`
    /// resolved by one read of the organization: one that answers means the deployment does not
    /// serve the route, and one that does not is not found. Any other failure, and a failure of
    /// that read, is the outer error, so that a rejected session is refreshed.
    fn resolved<T>(
        &self,
        api: &MemberGrantApi,
        answer: Result<T, MemberGrantFailure>,
    ) -> Result<Result<T, RouteFailure>, MemberGrantFailure> {
        match answer {
            Ok(value) => Ok(Ok(value)),
            Err(MemberGrantFailure::OrganizationNotFound) => {
                Ok(Err(if api.organization_answers(self.organization)? {
                    RouteFailure::NotServed
                } else {
                    RouteFailure::Failed(MemberGrantFailure::OrganizationNotFound)
                }))
            }
            Err(failure) => Err(failure),
        }
    }

    /// `failure` as the command reports it, worded with the organization and the provider.
    pub(super) fn report(&self, deployment: &str, failure: &RouteFailure) -> ApiFailureReport {
        report(deployment, failure, self.organization, self.provider())
    }

    /// `failure` of making an authorization as the command reports it: a request Cloud refuses
    /// as malformed is one that does not serve its runs, `runs_not_served`; any other as
    /// [`Scope::report`] words it.
    pub(super) fn refused_authorization(
        &self,
        deployment: &str,
        failure: &RouteFailure,
    ) -> ApiFailureReport {
        match failure {
            RouteFailure::Failed(MemberGrantFailure::InvalidInput) => ApiFailureReport::new(
                "runs_not_served",
                format!(
                    "error: this deployment refused the authorization of {} runs as malformed; \
                     it does not serve an authorization's runs",
                    self.runs.name()
                ),
                "Ask the deployment's operator when it will. Nothing was authorized.".to_owned(),
                OutcomeClass::GeneralFailure,
            ),
            failure => self.report(deployment, failure),
        }
    }

    /// The heading of the statement of authorizing the runner `runner` for `connection`.
    pub(super) fn heading(&self, runner: &str, connection: &Record) -> String {
        format!(
            "Authorizing runner {runner} for {}:",
            self.connection_named(connection.id(), connection.account())
        )
    }

    /// The heading of the statement of ending the runner `runner`'s `authorization`.
    pub(super) fn ending_heading(
        &self,
        runner: &str,
        authorization: &ConnectionAuthorization,
    ) -> String {
        format!(
            "Ending runner {runner}'s authorization for {}:",
            self.connection_named(
                &authorization.connection_id,
                Some(&authorization.connection_account)
            )
        )
    }

    /// The connection `connection_id` on the account `account`, which is another party's text,
    /// with the organization and the project, as a statement's heading names it.
    fn connection_named(&self, connection_id: &str, account: Option<&str>) -> String {
        let account = account.map_or_else(String::new, |account| {
            format!(" ({})", visible_text(account))
        });
        format!(
            "the {} connection {connection_id}{account} of {} in project {}",
            self.provider().as_str(),
            self.organization,
            self.project_id
        )
    }
}

/// The document of an authorization made or ended, whose view is `V`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizationResult<'a, V> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    authorization: V,
}

/// Reports the authorization `authorize` made.
pub(super) fn write_authorized(
    deployment: &str,
    authorization: &ConnectionAuthorization,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let view = AuthorizationView::new(authorization);
    write_outcome(
        deployment,
        ("authorized", "✓ Runner authorized."),
        &view,
        |output| view.write_human(output, ""),
        json,
    )
}

/// Reports the authorization `deauthorize` ended: what names it, without who made it, when or
/// its scope.
pub(super) fn write_deauthorized(
    deployment: &str,
    authorization: &ConnectionAuthorization,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let view = NamedView::new(authorization);
    write_outcome(
        deployment,
        ("deauthorized", "✓ Runner authorization ended."),
        &view,
        |output| view.write_human(output, ""),
        json,
    )
}

/// Reports an authorization made or ended under `outcome`, the document's outcome and the
/// report's first line: under `--json` one document carrying `view`, else the report, whose
/// lines of the authorization `write_human` writes, then the deployment.
fn write_outcome(
    deployment: &str,
    (outcome, done): (&'static str, &str),
    view: &impl Serialize,
    write_human: impl FnOnce(&mut io::StdoutLock<'static>) -> io::Result<()>,
    json: bool,
) -> anyhow::Result<ExitCode> {
    if json {
        crate::cli::write_pretty_json(&AuthorizationResult {
            schema_version: 1,
            deployment,
            outcome,
            authorization: view,
        })
        .context("write JSON connection authorization result")?;
        return Ok(ExitCode::Success);
    }
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{done}")?;
    write_human(&mut stdout)?;
    writeln!(stdout, "deployment: {deployment}")?;
    stdout.flush()?;
    Ok(ExitCode::Success)
}

/// A connection a leaf names among those it can act on: its ID and account.
#[derive(Serialize)]
struct NamedConnectionView<'a> {
    id: &'a str,
    account: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionRequiredResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    connections: Vec<NamedConnectionView<'a>>,
}

/// Refuses a leaf given a provider where the organization holds several `active` connections at
/// it: exit 2, naming each by its ID and account, then the command line `example` that names
/// one; under `--json`, one document with outcome `connection_required`.
fn write_connection_required(
    deployment: &str,
    provider: Provider,
    connections: &[Record],
    example: &str,
    json: bool,
) -> anyhow::Result<ExitCode> {
    if json {
        crate::cli::write_pretty_json(&ConnectionRequiredResult {
            schema_version: 1,
            deployment,
            outcome: "connection_required",
            connections: connections
                .iter()
                .map(|connection| NamedConnectionView {
                    id: connection.id(),
                    account: connection.account(),
                })
                .collect(),
        })
        .context("write JSON connection authorization result")?;
    } else {
        let mut stderr = io::stderr().lock();
        writeln!(
            stderr,
            "error: name the {} connection to authorize, one of:",
            provider.as_str()
        )?;
        for connection in connections {
            match connection.account() {
                Some(account) => {
                    writeln!(stderr, "  {} · {}", connection.id(), visible_text(account))?;
                }
                None => writeln!(stderr, "  {}", connection.id())?,
            }
        }
        writeln!(stderr, "\nName one by its ID, for example:\n  {example}")?;
    }
    Ok(ExitCode::UsageError)
}

/// The command that connects the organization `org` at `provider`.
fn connecting(org: &str, provider: Provider) -> String {
    let required = match provider {
        Provider::Gitlab => " --token-file PATH --kind KIND",
        Provider::Github | Provider::Linear => "",
    };
    format!(
        "useful org integration connect {}{required} --org {org}",
        provider.as_str()
    )
}

/// The refusal of a leaf that finds no connection of the organization `org` at `provider` to
/// authorize a runner for: none `active`, with the command that connects one, or none by the ID
/// `INTEGRATION` named, with the list of the organization's integrations.
fn no_connection(org: &str, provider: Provider, connection_id: Option<&str>) -> ApiFailureReport {
    let name = provider.as_str();
    let (summary, remedy) = match connection_id {
        None => (
            format!("error: the organization {org} holds no active {name} connection"),
            format!(
                "Connect the organization at {name}:\n  {}",
                connecting(org, provider)
            ),
        ),
        Some(id) => (
            format!("error: the organization {org} holds no {name} connection {id}"),
            format!(
                "List the organization's integrations:\n  useful org integration list --org {org}"
            ),
        ),
    };
    ApiFailureReport::new(
        "connection_not_found",
        summary,
        remedy,
        OutcomeClass::GeneralFailure,
    )
}

/// The refusal of authorizing a runner for a connection of the organization `org` at `provider`
/// that is not ready, `connection_inactive` or `connection_unverified`, the command's own where
/// it read `installation` and Cloud's otherwise: exit 1, with the command that connects the
/// organization, which makes or verifies one, naming the installation by its GitHub ID where
/// the command read it.
fn connection_not_ready(
    org: &str,
    provider: Provider,
    not_ready: NotReady,
    installation: Option<&GitHubInstallation>,
) -> ApiFailureReport {
    let name = provider.as_str();
    let connecting = match installation {
        Some(installation) => format!(
            "useful org integration connect github --installation {} --org {org}",
            installation.provider_installation_id
        ),
        None => connecting(org, provider),
    };
    let connection = installation.map_or_else(
        || format!("that {name} connection"),
        |installation| format!("the {name} connection {}", installation.id),
    );
    let (outcome, summary, remedy) = match not_ready {
        NotReady::Inactive => (
            "connection_inactive",
            format!("error: {connection} of the organization {org} is not active"),
            format!("Connect the organization at {name}:"),
        ),
        NotReady::Unverified => (
            "connection_unverified",
            format!(
                "error: the authority of {connection} of the organization {org} was never \
                 verified"
            ),
            format!("Connect the organization at {name} again, which verifies its authority:"),
        ),
    };
    ApiFailureReport::new(
        outcome,
        summary,
        format!(
            "{remedy}\n  {connecting}\nor list its integrations:\n  useful org integration list \
             --org {org}"
        ),
        OutcomeClass::GeneralFailure,
    )
}

/// A failed read of the project as the nearest failure of a connection authorization route: a
/// project the read does not find is Cloud's refusal of one not found.
fn project_failure(failure: ProjectFailure) -> MemberGrantFailure {
    match failure {
        ProjectFailure::NotFound => MemberGrantFailure::ConnectionAuthorizationRefused(
            ConnectionAuthorizationRefusal::ProjectNotFound,
        ),
        ProjectFailure::Forbidden => MemberGrantFailure::Forbidden,
        ProjectFailure::Unauthenticated => MemberGrantFailure::Unauthenticated,
        ProjectFailure::RateLimited { retry_after } => MemberGrantFailure::RateLimited {
            retry_after: Some(retry_after),
        },
        ProjectFailure::Unreachable(category) => MemberGrantFailure::Unreachable { category },
        ProjectFailure::Protocol {
            credential_rejected,
        } => MemberGrantFailure::InvalidResponse {
            credential_rejected,
        },
        // A project read defines none of these answers.
        ProjectFailure::InvalidInput
        | ProjectFailure::RepositoryNotBound
        | ProjectFailure::NameUnavailable
        | ProjectFailure::QuantityLimitReached
        | ProjectFailure::ProviderUnavailable { .. }
        | ProjectFailure::IdempotencyConflict
        | ProjectFailure::SourceConflict
        | ProjectFailure::RepositoryUnavailable
        | ProjectFailure::ProjectArchived
        | ProjectFailure::Conflict => invalid(),
    }
}

/// The refusal of a project `--project` names by a name no project of the organization `org`
/// has.
pub(super) fn project_not_found(org: &str) -> ApiFailureReport {
    ApiFailureReport::new(
        "project_not_found",
        format!("error: project not found in the organization {org}"),
        format!("List the organization's projects:\n  useful project list --org {org}"),
        OutcomeClass::GeneralFailure,
    )
}

/// A failure of a leaf acting on a connection authorization of the organization `org` at
/// `provider`: an owner's refusal, each refusal only those routes answer worded with the
/// organization and the provider, and a deployment that does not serve them; any other as a
/// grant's.
fn report(
    deployment: &str,
    failure: &RouteFailure,
    org: &str,
    provider: Provider,
) -> ApiFailureReport {
    use ConnectionAuthorizationRefusal as R;
    let name = provider.as_str();
    let list = format!("useful org integration list --org {org}");
    let refused = |outcome, summary: String, remedy: String| {
        ApiFailureReport::new(outcome, summary, remedy, OutcomeClass::GeneralFailure)
    };
    let refusal = match failure {
        RouteFailure::NotServed => {
            return refused(
                "connection_authorizations_not_served",
                "error: this deployment does not serve connection authorizations".to_owned(),
                "Ask the deployment's operator when it will; until then no command authorizes a \
                 runner for an organization's connection there."
                    .to_owned(),
            );
        }
        RouteFailure::Failed(MemberGrantFailure::Forbidden) => {
            return ApiFailureReport::new(
                "forbidden",
                format!(
                    "! Only an owner of the organization {org} can authorize a runner for its \
                     connections or end that authorization."
                ),
                format!(
                    "Ask an owner of {org}. List the organization's members:\n  useful org \
                     member list --org {org}"
                ),
                OutcomeClass::Forbidden,
            );
        }
        RouteFailure::Failed(MemberGrantFailure::ConnectionAuthorizationRefused(refusal)) => {
            *refusal
        }
        RouteFailure::Failed(failure) => return grant_output::report(deployment, failure),
    };
    let connect = format!(
        "Connect the organization at {name}:\n  {}\nor list its integrations:\n  {list}",
        connecting(org, provider)
    );
    match refusal {
        R::ProjectNotFound => project_not_found(org),
        R::RunnerNotFound => refused(
            "runner_not_found",
            format!("error: runner not found in the organization {org}"),
            format!("List the organization's runners:\n  useful runner list --org {org}"),
        ),
        R::ConnectionNotFound => refused(
            "connection_not_found",
            format!("error: {name} connection not found in the organization {org}"),
            connect,
        ),
        R::ConnectionInactive => connection_not_ready(org, provider, NotReady::Inactive, None),
        R::ConnectionUnverified => connection_not_ready(org, provider, NotReady::Unverified, None),
        R::ProviderIneligible => refused(
            "provider_ineligible",
            format!(
                "error: this deployment cannot authorize a runner for an organization's {name} \
                 connection"
            ),
            format!("List the organization's integrations:\n  {list}"),
        ),
        R::AlreadyAuthorized => refused(
            "already_authorized",
            format!(
                "error: the runner is already authorized for a {name} connection of the \
                 organization {org} in that project"
            ),
            format!(
                "List the organization's integrations:\n  {list}\nAn authorization of other \
                 runs is made only after the one in force is ended. End the runner's \
                 authorization in that project:\n  useful org integration deauthorize {name} \
                 --runner RUNNER --project PROJECT --org {org} --yes"
            ),
        ),
        R::AuthorizationNotFound => refused(
            "authorization_not_found",
            format!("error: connection authorization not found in the organization {org}"),
            format!("List the organization's integrations:\n  {list}"),
        ),
    }
}

const fn invalid() -> MemberGrantFailure {
    MemberGrantFailure::InvalidResponse {
        credential_rejected: false,
    }
}
