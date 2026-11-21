//! A runner's authorization for one of the organization's connections in one project
//! (REQ-INTEGRATION-26 to REQ-INTEGRATION-34): the connection `authorize INTEGRATION --project`
//! chooses, the organization's authorizations in force for the project, read to name a runner
//! or to find the one to end, the authorization made or ended, each through the member grant
//! client's connection authorization routes under the member's session, and what `list` and
//! `show` print of the authorizations in force under each connection. A generic `not-found` from
//! one of those routes is resolved by one read of the organization, since a deployment that
//! routes none of them answers it as it answers an organization the member cannot read; `list`
//! and `show` pass it over with no such read.

use std::io::{self, Write};

use anyhow::Context as _;
use serde::{Serialize, Serializer};
use useful_api::{
    ConnectionAuthorization, ConnectionAuthorizationFilter, ConnectionAuthorizationRefusal,
    ConnectionAuthorizationRequest, ConnectionAuthorizationScope, ConnectionAuthorizationState,
    GitHubRepositorySelection, HttpTransportPolicy, MemberGrantApi, MemberGrantFailure,
    UnreachableCategory,
};
use useful_execution::visible_text;
use useful_human_auth::Deployment;

use super::list::{self, Options, Provider, Record};
use super::target::Target;
use crate::cli::account::grant::{output as grant_output, replayed};
use crate::cli::paging::every_page;
use crate::cli::{ApiFailureReport, PrincipalAuthenticationKind, with_human_session_api};
use crate::exit_code::{ExitCode, OutcomeClass};

// The largest page the connection authorization list serves.
const PAGE: i32 = 200;

/// What authorizing a runner for a connection in one project permits (REQ-INTEGRATION-33): a
/// permission, which the authorization records and Cloud acts on for no run today
/// (REQ-INTEGRATION-24).
pub(super) const CONNECTION_AUTHORIZE: &[&str] = &[
    "the permission covers every app run of the project on the runner, whoever or whatever \
     caused the run",
    "the permission reaches whatever the provider grants the connection; no authorization \
     narrows that",
    "Cloud delivers an organization's connection to no run today: the authorization records a \
     permission and delivers nothing",
];

/// What ending a runner's authorization for a connection in one project does
/// (REQ-INTEGRATION-29): the permission ends, and no run is touched.
pub(super) const CONNECTION_DEAUTHORIZE: &[&str] = &[
    "the runner's permission to use the connection for the project's app runs ends",
    "no run is asked to stop and none loses anything: Cloud delivers an organization's \
     connection to no run today",
];

/// The state word of a connection a runner can be authorized for.
const ACTIVE: &str = "active";

/// The connection authorizations in force of the organization `organization` names, of the
/// connection `connection` alone where one is given, oldest first, read to the last page under
/// the member's session (REQ-INTEGRATION-34). `None` where Cloud refused the read, as it refuses
/// a member who is not an owner, answered the generic `not-found`, as a deployment that does not
/// route it does, or answered that it cannot serve it: `list` and `show` pass those over. Any
/// other failure is the inner error.
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

/// The authorizations in force of the connection `connection_id` that `show` prints under it
/// (REQ-INTEGRATION-34): none under a service API key, which the member's routes do not admit,
/// nor where the read was passed over. A read that fails otherwise is reported, and its exit
/// status is the inner error.
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

/// A runner's authorization for a connection in one project, as a command prints it
/// (REQ-INTEGRATION-32, REQ-INTEGRATION-33): what names it, who made it and when, and its
/// scope. Never a credential: an authorization holds none, and only these named fields are
/// printed.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizationView<'a> {
    #[serde(flatten)]
    named: NamedView<'a>,
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

/// What the provider grants the authorization's connection (REQ-INTEGRATION-32): its state, and
/// for a `current` GitHub scope the installation's repository selection and permissions.
#[derive(Serialize)]
struct ScopeView<'a> {
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    github: Option<GitHubScopeView<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GitHubScopeView<'a> {
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

    /// Writes the scope's lines of a human report: the repository selection and one line for
    /// each permission, which are GitHub's text and printed visibly; that the provider could not
    /// be read; or, for a `current` scope this release knows no member of, `current` alone.
    fn write_human(&self, output: &mut impl Write, indent: &str) -> io::Result<()> {
        match (&self.github, self.state) {
            (Some(github), _) => {
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
            authorized_by: &authorization.authorized_by,
            created_at: &authorization.created_at,
            scope: ScopeView::new(&authorization.scope),
        }
    }

    /// Writes the view's lines of a human report: what names the authorization, then who made
    /// it and when, and its scope.
    fn write_human(&self, output: &mut impl Write, indent: &str) -> io::Result<()> {
        self.named.write_human(output, indent)?;
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
/// and the leaf's command path.
pub(super) struct Scope<'a> {
    pub(super) command: &'static str,
    pub(super) organization: &'a str,
    pub(super) project_id: &'a str,
    pub(super) target: &'a Target,
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
    /// where none is given as `INTEGRATION` named it.
    pub(super) fn command_line(&self, runner: &str, connection: Option<&str>) -> String {
        let named = connection
            .or_else(|| self.connection_id())
            .unwrap_or(self.provider().as_str());
        format!(
            "{} {named} --runner {runner} --project {} --org {} --yes",
            self.command, self.project_id, self.organization
        )
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
    /// `runner_id` alone where one is given, read to the last page (REQ-INTEGRATION-28): those
    /// that hold the project and the provider for a runner, whichever connection they name.
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

    /// Authorizes `runner_id` for `connection_id` in the project under `key`, once more under
    /// the same key when the answer was lost (REQ-INTEGRATION-27).
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
        };
        let made = replayed(|| api.authorize_connection(self.organization, &request, key));
        self.resolved(api, made)
    }

    /// Ends the authorization `authorization_id` under `key`, once more under the same key when
    /// the answer was lost (REQ-INTEGRATION-29).
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

/// Reports the authorization `authorize` made (REQ-INTEGRATION-33).
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

/// Reports the authorization `deauthorize` ended (REQ-INTEGRATION-33): what names it, without
/// who made it, when or its scope.
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
/// it (REQ-INTEGRATION-33): exit 2, naming each by its ID and account, then the command line
/// `example` that names one; under `--json`, one document with outcome `connection_required`.
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
/// authorize a runner for (REQ-INTEGRATION-33): none `active`, with the command that connects
/// one, or none by the ID `INTEGRATION` named, with the list of the organization's integrations.
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

/// The refusal of a project `--project` names by a name no project of the organization `org`
/// has (REQ-INTEGRATION-33).
pub(super) fn project_not_found(org: &str) -> ApiFailureReport {
    ApiFailureReport::new(
        "project_not_found",
        format!("error: project not found in the organization {org}"),
        format!("List the organization's projects:\n  useful project list --org {org}"),
        OutcomeClass::GeneralFailure,
    )
}

/// A failure of a leaf acting on a connection authorization of the organization `org` at
/// `provider` (REQ-INTEGRATION-33): an owner's refusal, each refusal only those routes answer
/// worded with the organization and the provider, and a deployment that does not serve them;
/// any other as a grant's.
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
        R::ConnectionInactive => refused(
            "connection_inactive",
            format!("error: that {name} connection of the organization {org} is not active"),
            connect,
        ),
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
                "List the organization's integrations:\n  {list}\nor end the runner's \
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
