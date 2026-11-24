//! The organization and the project in effect: the organization and the project a command acts
//! in when it is not given them as its own subject. For the organization the first source that
//! names one wins: `--org ORG`, then `USEFUL_ORG`, then the checkout, then the caller's only
//! active membership. For the project: `--project PROJECT`, then `USEFUL_PROJECT`, then the
//! checkout, within the organization in effect. The options and the variables are read without
//! a request; `git` is run, and the memberships and projects asked, only when a source left
//! unnamed needs them. Every command that reads the organization or the project in effect
//! resolves it here, before its own operation and under its own credential.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::ffi::OsStr;
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use clap::Args;
use serde::Serialize;
use useful_api::{
    CommonOrganizationFailure, CurrentPrincipalMembership, HttpClient, HttpTransportPolicy,
    ListCurrentPrincipalMembershipsOutcome, MembershipState, OrganizationState, Project,
    ProjectApi, ProjectFailure, UnreachableCategory, list_current_principal_memberships,
};
use useful_execution::{CommandRequest, CommandRunner, SystemCommandRunner};
use useful_human_auth::Deployment;

use super::{
    CommandFailure, CommandResult, CommonArgs, JsonOutputKind, OrganizationArg,
    PrincipalAuthenticationArgs, PrincipalAuthenticationKind,
};
use crate::exit_code::ExitCode;

/// The variable that names the organization in effect when `--org` does not.
const VARIABLE: &str = "USEFUL_ORG";
const HELP: &str = "Organization ID or exact slug to act in (default: USEFUL_ORG, then the project of this checkout, then your only organization)";
/// The variable that names the project in effect when `--project` does not.
const PROJECT_VARIABLE: &str = "USEFUL_PROJECT";
const PROJECT_HELP: &str = "Project ID or exact name to act in (default: USEFUL_PROJECT, then the project of this checkout)";
// The largest page the membership list serves.
const MEMBERSHIP_PAGE: u16 = 200;
// The bounds of the checkout's one `git` probe, as the runner's own Git probes are bounded.
const GIT_TIMEOUT: Duration = Duration::from_secs(5);
const GIT_STDOUT_BYTES: usize = 64 * 1024;

/// `--org ORG`, which a leaf that reads the organization in effect flattens beside its
/// `CommonArgs`; it is never a root option, so a leaf that does not read it refuses it.
#[derive(Clone, Debug, Args)]
pub(super) struct OrgArgs {
    #[arg(long, value_name = "ORG", help = HELP)]
    org: Option<OrganizationArg>,
}

impl OrgArgs {
    /// Whether `--org` was given; `USEFUL_ORG` is not an option.
    pub(super) const fn given(&self) -> bool {
        self.org.is_some()
    }

    /// The organization in effect `--org` or else `USEFUL_ORG` names, without a request; none
    /// when neither does. A variable that is not an organization ID or slug refuses the command
    /// with exit 2, naming it.
    pub(super) fn named_in_process(&self) -> Result<Option<InEffect>, CommandFailure> {
        self.named(std::env::var_os(VARIABLE).as_deref())
    }

    /// The organization `--org` or else `variable`, the value of `USEFUL_ORG`, names, as
    /// given; neither costs a request. An empty variable is unset, and one that is not an
    /// organization ID or slug refuses the command with exit 2, naming the variable.
    fn named(&self, variable: Option<&OsStr>) -> Result<Option<InEffect>, CommandFailure> {
        if let Some(org) = &self.org {
            return Ok(Some(InEffect::new(org.clone().into_string(), Source::Flag)));
        }
        let Some(value) = variable.filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        value
            .to_str()
            .and_then(|value| value.parse::<OrganizationArg>().ok())
            .map(|organization| {
                Some(InEffect::new(
                    organization.into_string(),
                    Source::Environment,
                ))
            })
            .ok_or_else(|| {
                CommandFailure::with_exit_code(
                    anyhow!(
                        "{VARIABLE} is not an organization ID or exact slug\n\n\
                         Set it to one, or unset it and name the organization with --org."
                    ),
                    ExitCode::UsageError,
                )
            })
    }
}

/// `--project PROJECT`, which a leaf that reads the project in effect flattens beside
/// [`OrgArgs`]; like `--org` it is never a root option.
#[derive(Clone, Debug, Args)]
pub(super) struct ProjectArgs {
    #[arg(long, value_name = "PROJECT", help = PROJECT_HELP)]
    project: Option<ProjectRef>,
}

impl ProjectArgs {
    /// Whether `--project` was given; `USEFUL_PROJECT` is not an option.
    pub(super) const fn given(&self) -> bool {
        self.project.is_some()
    }

    /// The project `--project` or else `variable`, the value of `USEFUL_PROJECT`, names, with
    /// its source; none when neither does. An empty variable is unset, and one that is neither
    /// a project ID nor a project name names none.
    fn named(self, variable: Option<&OsStr>) -> Result<Option<(ProjectRef, Source)>, NoProject> {
        if let Some(project) = self.project {
            return Ok(Some((project, Source::Flag)));
        }
        let Some(value) = variable.filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        value
            .to_str()
            .and_then(|value| value.parse().ok())
            .map(|project| Some((project, Source::Environment)))
            .ok_or(NoProject::MalformedVariable)
    }
}

/// A project as `--project`, `USEFUL_PROJECT` or a command's `PROJECT` names it: its ID, taken
/// as given, or the exact name of a project of the organization in effect, which a name never
/// mistakes for an ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ProjectRef {
    Id(String),
    Name(String),
}

impl ProjectRef {
    /// The placeholder and the help of a command's own `PROJECT`.
    pub(super) const VALUE_NAME: &'static str = "PROJECT";
    pub(super) const HELP: &'static str = "Project ID or exact name";
}

impl FromStr for ProjectRef {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if useful_support::valid_typed_id(value, "prj_") {
            Ok(Self::Id(value.to_owned()))
        } else if useful_support::valid_url_safe_name(value) {
            Ok(Self::Name(value.to_owned()))
        } else {
            Err("must be a project ID or exact project name".to_owned())
        }
    }
}

/// The organization in effect: `organization`, the reference a command sends, which is the
/// value `--org` or `USEFUL_ORG` gave or else the organization's ID, and the source that
/// named it. Serialized, it is the `organizationInEffect` member of a document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct InEffect {
    pub(super) organization: String,
    pub(super) source: Source,
}

impl InEffect {
    const fn new(organization: String, source: Source) -> Self {
        Self {
            organization,
            source,
        }
    }
}

/// The project in effect: the project's ID and the source that named it. Serialized, it is
/// the `projectInEffect` member of a document.
#[derive(Debug, Eq, PartialEq, Serialize)]
pub(super) struct ProjectInEffect {
    pub(super) project: String,
    pub(super) source: Source,
}

/// The source that named the organization or the project in effect. Its JSON word is its
/// serialized form and its human word is [`Source::label`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Source {
    Flag,
    Environment,
    Checkout,
    OnlyMembership,
}

impl Source {
    /// The source as human output names it.
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Flag => "flag",
            Self::Environment => "environment",
            Self::Checkout => "checkout",
            Self::OnlyMembership => "only membership",
        }
    }
}

/// Why no project is in effect. Each displays as a diagnostic with its remedy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum NoProject {
    /// No source names a project.
    Unnamed,
    /// `USEFUL_PROJECT` is neither a project ID nor a project name.
    MalformedVariable,
    /// A name no project of the organization in effect has.
    UnknownName { name: String, organization: String },
    /// A name, with no organization in effect to look it up in.
    NoOrganization { name: String },
    /// The checkout's remotes name several projects, by ID.
    SeveralInCheckout(Vec<String>),
    /// The checkout's one project belongs to `owner`, not to the organization `named`.
    OtherOrganization {
        project: String,
        owner: String,
        named: String,
    },
}

impl fmt::Display for NoProject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unnamed => write!(
                formatter,
                "no project is in effect\n\n\
                 Name one with --project PROJECT, or set {PROJECT_VARIABLE}."
            ),
            Self::MalformedVariable => write!(
                formatter,
                "{PROJECT_VARIABLE} is not a project ID or exact project name\n\n\
                 Set it to one, or unset it and name the project with --project."
            ),
            Self::UnknownName { name, organization } => write!(
                formatter,
                "organization {organization} has no project named {name}\n\n\
                 Name one of its projects by ID or exact name."
            ),
            Self::NoOrganization { name } => write!(
                formatter,
                "project {name} is named without an organization in effect\n\n\
                 Name the organization with --org ORG, or the project by its ID."
            ),
            Self::SeveralInCheckout(projects) => write!(
                formatter,
                "this checkout names several projects: {}\n\n\
                 Name the one to act in with --project PROJECT.",
                projects.join(", ")
            ),
            Self::OtherOrganization {
                project,
                owner,
                named,
            } => write!(
                formatter,
                "this checkout's project {project} belongs to organization {owner}, not {named}\n\n\
                 Name a project of {named} with --project PROJECT, or name {owner} with --org."
            ),
        }
    }
}

/// The organization and the project in effect for a command that reports both. With no
/// organization in effect, `organization` holds the caller's active organizations, which name
/// none: none of them, or several.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct Context {
    pub(super) organization: Result<InEffect, Vec<Organization>>,
    pub(super) project: Result<ProjectInEffect, NoProject>,
}

/// Why the context could not be resolved: `USEFUL_ORG` names no organization, Cloud refused a
/// read of the memberships or projects, or a read failed otherwise.
pub(super) enum Unresolved {
    Variable(CommandFailure),
    Refused(CommonOrganizationFailure),
    Failed(anyhow::Error),
}

/// An organization of the caller's, by ID, with its slug when a read named it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Organization {
    pub(super) id: String,
    pub(super) slug: Option<String>,
}

impl Organization {
    /// Whether `reference`, an organization ID or slug, names this organization.
    fn is(&self, reference: &str) -> bool {
        self.id == reference || self.slug.as_deref() == Some(reference)
    }
}

/// The organizations of `memberships` the caller is an active member of, whose own state is
/// active too: those the checkout and the only membership choose among.
pub(super) fn active_organizations(
    memberships: &[CurrentPrincipalMembership],
) -> Vec<Organization> {
    memberships
        .iter()
        .filter(|membership| {
            membership.state == MembershipState::Active
                && membership.organization_state == OrganizationState::Active
        })
        .map(|membership| Organization {
            id: membership.organization_id.clone(),
            slug: membership.organization_slug.clone(),
        })
        .collect()
}

/// The caller's only active organization, or else all of them, none or several, which name no
/// organization.
pub(super) fn only_membership(
    organizations: Vec<Organization>,
) -> Result<Organization, Vec<Organization>> {
    <[Organization; 1]>::try_from(organizations).map(|[organization]| organization)
}

/// Runs `run` with `options` in the organization in effect. When no source names one the leaf
/// ends with exit 2, and when a read fails, with the failure `write_failure` writes as the
/// leaf's own failure is written.
pub(super) fn execute_in<F: JsonOutputKind>(
    org: OrgArgs,
    options: CommonArgs<F, PrincipalAuthenticationArgs>,
    deployment: &Deployment,
    write_failure: impl FnOnce(
        &str,
        &CommonOrganizationFailure,
        PrincipalAuthenticationKind,
        bool,
    ) -> anyhow::Result<ExitCode>,
    run: impl FnOnce(CommonArgs<F, PrincipalAuthenticationArgs>, &str) -> anyhow::Result<ExitCode>,
) -> CommandResult {
    execute_in_keeping_exit(org, options, deployment, write_failure, run)
}

/// [`execute_in`] for a `run` whose failure is a [`CommandFailure`] or becomes one: the failure
/// keeps its exit code.
pub(super) fn execute_in_keeping_exit<F: JsonOutputKind, E: Into<CommandFailure>>(
    org: OrgArgs,
    options: CommonArgs<F, PrincipalAuthenticationArgs>,
    deployment: &Deployment,
    write_failure: impl FnOnce(
        &str,
        &CommonOrganizationFailure,
        PrincipalAuthenticationKind,
        bool,
    ) -> anyhow::Result<ExitCode>,
    run: impl FnOnce(CommonArgs<F, PrincipalAuthenticationArgs>, &str) -> Result<ExitCode, E>,
) -> CommandResult {
    match organization(org, &options, deployment, write_failure) {
        Ok(organization) => run(options, &organization).map_err(Into::into),
        Err(result) => result,
    }
}

/// The project a `useful project` leaf acts on: the project in effect its `ProjectArgs` read,
/// or the `PROJECT` its command names as its own subject.
pub(super) enum ProjectSubject {
    InEffect(ProjectArgs),
    Named(ProjectRef),
}

/// Why a `useful project` leaf does not run, written by the family's own failure writer: Cloud
/// refused a read of the memberships or projects, or no project of the organization has the
/// name the command's `PROJECT` gives.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum ContextFailure {
    Refused(CommonOrganizationFailure),
    UnknownProject,
}

/// Runs `run` with `options`, the organization reference to send (the value `--org` or
/// `USEFUL_ORG` gave, else the organization's ID) and the project's ID. A `PROJECT` subject
/// is resolved as `--project` is, a name among the organization's projects, archived ones
/// included; `--org` or `USEFUL_ORG` with a project ID costs no request and runs no `git`.
/// With no organization or no project in effect the leaf ends with exit 2 before a request of
/// its own; a refused read and a subject name no project has are written by `write_failure`,
/// as the leaf's own failures are.
pub(super) fn execute_in_project<F: JsonOutputKind>(
    org: OrgArgs,
    project: ProjectSubject,
    options: CommonArgs<F, PrincipalAuthenticationArgs>,
    deployment: &Deployment,
    write_failure: impl FnOnce(
        &str,
        &ContextFailure,
        PrincipalAuthenticationKind,
        bool,
    ) -> anyhow::Result<ExitCode>,
    run: impl FnOnce(CommonArgs<F, PrincipalAuthenticationArgs>, &str, &str) -> anyhow::Result<ExitCode>,
) -> CommandResult {
    execute_in_project_keeping_exit(org, project, options, deployment, write_failure, run)
}

/// [`execute_in_project`] for a `run` whose failure is a [`CommandFailure`] or becomes one: the
/// failure keeps its exit code.
pub(super) fn execute_in_project_keeping_exit<F: JsonOutputKind, E: Into<CommandFailure>>(
    org: OrgArgs,
    project: ProjectSubject,
    options: CommonArgs<F, PrincipalAuthenticationArgs>,
    deployment: &Deployment,
    write_failure: impl FnOnce(
        &str,
        &ContextFailure,
        PrincipalAuthenticationKind,
        bool,
    ) -> anyhow::Result<ExitCode>,
    run: impl FnOnce(CommonArgs<F, PrincipalAuthenticationArgs>, &str, &str) -> Result<ExitCode, E>,
) -> CommandResult {
    let subject = matches!(project, ProjectSubject::Named(_));
    let named = match project {
        ProjectSubject::InEffect(project) => {
            project.named(std::env::var_os(PROJECT_VARIABLE).as_deref())
        }
        ProjectSubject::Named(reference) => Ok(Some((reference, Source::Flag))),
    };
    let failure = match resolved(org, named, &options, deployment) {
        Ok(context) => match runnable(context, subject) {
            Ok((organization, project)) => {
                return run(options, &organization, &project).map_err(Into::into);
            }
            Err(Unrunnable::NoOrganization(organizations)) => {
                return Err(unresolved(&organizations));
            }
            Err(Unrunnable::NoProject(none)) => {
                return Err(CommandFailure::with_exit_code(
                    anyhow!("{none}"),
                    ExitCode::UsageError,
                ));
            }
            Err(Unrunnable::UnknownProject) => ContextFailure::UnknownProject,
        },
        Err(Unresolved::Variable(failure)) => return Err(failure),
        Err(Unresolved::Refused(failure)) => ContextFailure::Refused(failure),
        Err(Unresolved::Failed(error)) => return Err(error.into()),
    };
    write_failure(
        deployment.fingerprint().api_url(),
        &failure,
        options.authentication.kind(),
        options.json,
    )
    .context("write project result")
    .map_err(Into::into)
}

/// Why a resolved context runs no project leaf: no organization is in effect, among the
/// caller's active organizations; no project is; or the command's own `PROJECT` names, by name,
/// no project of the organization.
#[derive(Debug, Eq, PartialEq)]
enum Unrunnable {
    NoOrganization(Vec<Organization>),
    NoProject(NoProject),
    UnknownProject,
}

/// The organization reference and the project ID a project leaf runs with, from `context`;
/// `subject` holds when the project is the command's own `PROJECT`, whose unknown name is the
/// family's `not_found` rather than a usage error.
fn runnable(context: Context, subject: bool) -> Result<(String, String), Unrunnable> {
    let organization = context.organization.map_err(Unrunnable::NoOrganization)?;
    match context.project {
        Ok(project) => Ok((organization.organization, project.project)),
        Err(NoProject::UnknownName { .. }) if subject => Err(Unrunnable::UnknownProject),
        Err(none) => Err(Unrunnable::NoProject(none)),
    }
}

/// The organization in effect for a leaf run with `options`, as the reference the leaf sends:
/// the value `--org` or `USEFUL_ORG` gave, or else the ID of the organization the checkout or
/// the caller's only active membership names. Otherwise the result the leaf ends with.
fn organization<F: JsonOutputKind>(
    org: OrgArgs,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    deployment: &Deployment,
    write_failure: impl FnOnce(
        &str,
        &CommonOrganizationFailure,
        PrincipalAuthenticationKind,
        bool,
    ) -> anyhow::Result<ExitCode>,
) -> Result<String, CommandResult> {
    match organization_in_effect(
        &org,
        options.http.transport_policy(),
        &options.authentication,
        deployment,
    ) {
        Ok(Ok(organization)) => Ok(organization),
        Ok(Err(failure)) => Err(write_failure(
            deployment.fingerprint().api_url(),
            &failure,
            options.authentication.kind(),
            options.json,
        )
        .context("write organization result")
        .map_err(Into::into)),
        Err(failure) => Err(Err(failure)),
    }
}

/// The organization in effect as the reference a command sends, the value `--org` or
/// `USEFUL_ORG` gave or else the ID of the organization the checkout or the caller's only
/// active membership names, for a command that holds `authentication` and `transport_policy`
/// rather than `CommonArgs`, as `useful runner serve` does for a registration on a host with no
/// state. A refused read of the memberships or projects is the inner error, for the command to
/// write as its own failures are written; no organization in effect is the exit 2 of
/// [`unresolved`].
pub(super) fn organization_in_effect(
    org: &OrgArgs,
    transport_policy: HttpTransportPolicy,
    authentication: &PrincipalAuthenticationArgs,
    deployment: &Deployment,
) -> Result<Result<String, CommonOrganizationFailure>, CommandFailure> {
    if let Some(named) = org.named_in_process()? {
        return Ok(Ok(named.organization));
    }
    match unnamed_organization_as(transport_policy, authentication, deployment, None)? {
        Ok(Ok((organization, _))) => Ok(Ok(organization.id)),
        Ok(Err(organizations)) => Err(unresolved(&organizations)),
        Err(failure) => Ok(Err(failure)),
    }
}

/// The organization in effect the checkout or else the caller's only active membership names,
/// when neither `--org` nor `USEFUL_ORG` does, or else every active organization of the
/// caller's. `known` holds those organizations when the command has already read every
/// membership, which is then not read again; the projects of the checkout are read either way.
pub(super) fn unnamed_in_effect<F: JsonOutputKind>(
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    deployment: &Deployment,
    known: Option<Vec<Organization>>,
) -> anyhow::Result<Result<Result<InEffect, Vec<Organization>>, CommonOrganizationFailure>> {
    Ok(
        unnamed_organization(options, deployment, known)?.map(|unnamed| {
            unnamed.map(|(organization, source)| InEffect::new(organization.id, source))
        }),
    )
}

/// What the unnamed sources name: the organization the checkout or else the caller's only
/// active membership names, with its slug where the read names it and the source that named
/// it, or else every active organization of the caller's.
pub(super) type Chosen = Result<(Organization, Source), Vec<Organization>>;

/// [`unnamed_in_effect`], naming the organization with its slug where the read names it, as a
/// command that prints the organization it acted in names it.
pub(super) fn unnamed_organization<F: JsonOutputKind>(
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    deployment: &Deployment,
    known: Option<Vec<Organization>>,
) -> anyhow::Result<Result<Chosen, CommonOrganizationFailure>> {
    unnamed_organization_as(
        options.http.transport_policy(),
        &options.authentication,
        deployment,
        known,
    )
}

/// [`unnamed_organization`] under `authentication` with `transport_policy`.
pub(super) fn unnamed_organization_as(
    transport_policy: HttpTransportPolicy,
    authentication: &PrincipalAuthenticationArgs,
    deployment: &Deployment,
    known: Option<Vec<Organization>>,
) -> anyhow::Result<Result<Chosen, CommonOrganizationFailure>> {
    let remotes = checkout_remotes(&SystemCommandRunner);
    read_as(transport_policy, authentication, deployment, |reader| {
        unnamed(
            &remotes,
            || match &known {
                Some(known) => Ok(known.clone()),
                None => reader.memberships(),
            },
            |organization| reader.projects(organization, false),
        )
        .map(|unnamed| unnamed.organization)
    })
}

/// The organization and the project in effect for a leaf run with `options` that flattens
/// `org` and `project`. Both named, the project by ID, cost no request and run no `git`;
/// otherwise the reads the unnamed sources need are made under the leaf's credential.
pub(super) fn in_effect<F: JsonOutputKind>(
    org: OrgArgs,
    project: ProjectArgs,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    deployment: &Deployment,
) -> Result<Context, Unresolved> {
    resolved(
        org,
        project.named(std::env::var_os(PROJECT_VARIABLE).as_deref()),
        options,
        deployment,
    )
}

/// [`in_effect`] with the project `--project` or `USEFUL_PROJECT`, or else a command's own
/// `PROJECT`, already named.
fn resolved<F: JsonOutputKind>(
    org: OrgArgs,
    project: Result<Option<(ProjectRef, Source)>, NoProject>,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    deployment: &Deployment,
) -> Result<Context, Unresolved> {
    let organization = org.named_in_process().map_err(Unresolved::Variable)?;
    let checkout_asked = organization.is_none() || matches!(project, Ok(None));
    let remotes = if checkout_asked {
        checkout_remotes(&SystemCommandRunner)
    } else {
        Vec::new()
    };
    let reads = organization.is_none()
        || match &project {
            Ok(None) => !remotes.is_empty(),
            Ok(Some((reference, _))) => matches!(reference, ProjectRef::Name(_)),
            Err(_) => false,
        };
    // With nothing to read the credential is not used, so no session is refreshed either.
    if !reads {
        return resolve::<Infallible>(
            organization,
            project,
            &remotes,
            || Ok(Vec::new()),
            |_, _| Ok(None),
        )
        .map_err(|never| match never {});
    }
    match read(options, deployment, |reader| {
        resolve(
            organization.clone(),
            project.clone(),
            &remotes,
            || reader.memberships(),
            |organization, include_archived| reader.projects(organization, include_archived),
        )
    }) {
        Ok(Ok(context)) => Ok(context),
        Ok(Err(failure)) => Err(Unresolved::Refused(failure)),
        Err(error) => Err(Unresolved::Failed(error)),
    }
}

/// The context from the named sources, the checkout's `remotes`, and the readers of the
/// caller's active organizations and of an organization's projects, unarchived ones alone or
/// with the archived. A reader is asked only when a source left unnamed needs it.
fn resolve<E>(
    organization: Option<InEffect>,
    project: Result<Option<(ProjectRef, Source)>, NoProject>,
    remotes: &[Remote],
    memberships: impl FnOnce() -> Result<Vec<Organization>, E>,
    mut projects: impl FnMut(&str, bool) -> Result<Option<Vec<Project>>, E>,
) -> Result<Context, E> {
    let (organization, checkout) = match organization {
        Some(named) => {
            let checkout = if matches!(project, Ok(None)) && !remotes.is_empty() {
                checkout(remotes, &memberships()?, &mut |id| projects(id, false))?
            } else {
                Checkout::Nothing
            };
            (Ok(named), checkout)
        }
        None => {
            let unnamed = unnamed(remotes, memberships, |id| projects(id, false))?;
            let organization = unnamed
                .organization
                .map(|(organization, source)| InEffect::new(organization.id, source));
            (organization, unnamed.checkout)
        }
    };
    let project = match project {
        Err(none) => Err(none),
        Ok(Some((ProjectRef::Id(project), source))) => Ok(ProjectInEffect { project, source }),
        Ok(Some((ProjectRef::Name(name), source))) => match &organization {
            Err(_) => Err(NoProject::NoOrganization { name }),
            Ok(in_effect) => projects(&in_effect.organization, true)?
                .unwrap_or_default()
                .into_iter()
                .find(|project| project.name == name)
                .map(|project| ProjectInEffect {
                    project: project.id,
                    source,
                })
                .ok_or_else(|| NoProject::UnknownName {
                    name,
                    organization: in_effect.organization.clone(),
                }),
        },
        Ok(None) => match checkout {
            Checkout::Nothing => Err(NoProject::Unnamed),
            Checkout::Several(projects) => Err(NoProject::SeveralInCheckout(projects)),
            Checkout::One { project, owner } => match &organization {
                Ok(in_effect) if !owner.is(&in_effect.organization) => {
                    Err(NoProject::OtherOrganization {
                        project,
                        owner: owner.slug.unwrap_or(owner.id),
                        named: in_effect.organization.clone(),
                    })
                }
                _ => Ok(ProjectInEffect {
                    project,
                    source: Source::Checkout,
                }),
            },
        },
    };
    Ok(Context {
        organization,
        project,
    })
}

/// Runs `read` under the leaf's credential, refreshing a rejected session once.
fn read<F: JsonOutputKind, T>(
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    deployment: &Deployment,
    read: impl FnMut(&Reader<'_>) -> Result<T, ReadFailure>,
) -> anyhow::Result<Result<T, CommonOrganizationFailure>> {
    read_as(
        options.http.transport_policy(),
        &options.authentication,
        deployment,
        read,
    )
}

/// [`read`] under `authentication` with `policy`.
fn read_as<T>(
    policy: HttpTransportPolicy,
    authentication: &PrincipalAuthenticationArgs,
    deployment: &Deployment,
    mut read: impl FnMut(&Reader<'_>) -> Result<T, ReadFailure>,
) -> anyhow::Result<Result<T, CommonOrganizationFailure>> {
    let client = HttpClient::new(policy)
        .map_err(|error| anyhow!(error))
        .context("prepare organization networking")?;
    let api_url = deployment.fingerprint().api_url();
    super::execute_selected_api_operation(
        super::principal_api_context(
            &client,
            deployment,
            authentication,
            "acquire human session for the organization in effect",
        ),
        |token| {
            let reader = Reader {
                client: &client,
                api_url,
                token,
                projects: ProjectApi::new(api_url, token, policy)
                    .map_err(|error| anyhow!(error))
                    .context("prepare project networking")?,
            };
            match read(&reader) {
                Ok(read) => Ok(Ok(read)),
                Err(ReadFailure::Refused(failure)) => Ok(Err(failure)),
                Err(ReadFailure::Invalid(error)) => Err(error),
            }
        },
        |failure| matches!(failure, CommonOrganizationFailure::Unauthenticated),
        || CommonOrganizationFailure::Unauthenticated,
        CommonOrganizationFailure::Unreachable,
    )
}

/// Why a read of the memberships or projects named nothing: Cloud refused it with one of the
/// outcomes every organization command reports, or answered outside the contract.
enum ReadFailure {
    Refused(CommonOrganizationFailure),
    Invalid(anyhow::Error),
}

/// The memberships and projects, read under one credential.
struct Reader<'a> {
    client: &'a HttpClient,
    api_url: &'a str,
    token: &'a str,
    projects: ProjectApi,
}

impl Reader<'_> {
    /// The caller's active organizations (`active_organizations`), read to the last page of
    /// `GET /v1/me/memberships`.
    fn memberships(&self) -> Result<Vec<Organization>, ReadFailure> {
        let repeated = ReadFailure::Invalid(anyhow!(
            "list organization memberships: a page repeated an earlier cursor"
        ));
        super::paging::every_page(repeated, |cursor| match list_current_principal_memberships(
            self.client,
            self.api_url,
            self.token,
            Some(MEMBERSHIP_PAGE),
            cursor,
        ) {
            Ok(ListCurrentPrincipalMembershipsOutcome::Listed(page)) => {
                Ok((active_organizations(&page.items), page.next_cursor))
            }
            Ok(ListCurrentPrincipalMembershipsOutcome::Common(failure)) => {
                Err(ReadFailure::Refused(failure))
            }
            Err(error) => Err(ReadFailure::Invalid(
                anyhow!(error).context("list organization memberships"),
            )),
        })
    }

    /// Every project of `organization`, the archived ones too when `include_archived` holds,
    /// read to the last page, or none when Cloud refuses the list as forbidden or not found:
    /// such an organization is passed over.
    fn projects(
        &self,
        organization: &str,
        include_archived: bool,
    ) -> Result<Option<Vec<Project>>, ReadFailure> {
        let read = super::paging::every_page(
            ProjectFailure::Protocol {
                credential_rejected: false,
            },
            |cursor| {
                self.projects
                    .list(organization, None, cursor, include_archived)
                    .map(|page| (page.items, page.next_cursor))
            },
        );
        match read {
            Ok(projects) => Ok(Some(projects)),
            Err(ProjectFailure::Forbidden | ProjectFailure::NotFound) => Ok(None),
            Err(ProjectFailure::Unauthenticated) => Err(ReadFailure::Refused(
                CommonOrganizationFailure::Unauthenticated,
            )),
            Err(ProjectFailure::InvalidInput) => Err(ReadFailure::Refused(
                CommonOrganizationFailure::InvalidInput,
            )),
            Err(ProjectFailure::Unreachable(category)) => Err(ReadFailure::Refused(
                CommonOrganizationFailure::Unreachable(category),
            )),
            Err(ProjectFailure::RateLimited { .. }) => Err(ReadFailure::Refused(
                CommonOrganizationFailure::Unreachable(UnreachableCategory::RateLimited),
            )),
            Err(failure) => Err(ReadFailure::Invalid(anyhow!(
                "list the projects of organization {organization}: {failure:?}"
            ))),
        }
    }
}

/// What the unnamed sources name, [`Chosen`], and what the checkout names.
struct Unnamed {
    organization: Chosen,
    checkout: Checkout,
}

/// The organization the checkout or else the caller's only active membership names, by ID,
/// or else every active organization of the caller's, when neither names one. `memberships`
/// reads the caller's active organizations, once for both sources; `projects` reads an
/// organization's unarchived projects, and is asked only when the checkout has a remote.
fn unnamed<E>(
    remotes: &[Remote],
    memberships: impl FnOnce() -> Result<Vec<Organization>, E>,
    mut projects: impl FnMut(&str) -> Result<Option<Vec<Project>>, E>,
) -> Result<Unnamed, E> {
    let organizations = memberships()?;
    let checkout = checkout(remotes, &organizations, &mut projects)?;
    let organization = match &checkout {
        Checkout::One { owner, .. } => Ok((owner.clone(), Source::Checkout)),
        Checkout::Nothing | Checkout::Several(_) => only_membership(organizations)
            .map(|organization| (organization, Source::OnlyMembership)),
    };
    Ok(Unnamed {
        organization,
        checkout,
    })
}

/// What the checkout names among the unarchived projects of the caller's active
/// organizations: nothing, the one project a remote names with its organization, or several
/// projects by ID.
enum Checkout {
    Nothing,
    One {
        project: String,
        owner: Organization,
    },
    Several(Vec<String>),
}

/// The projects, among the unarchived projects of `organizations`, whose repository a remote
/// of the checkout names.
fn checkout<E>(
    remotes: &[Remote],
    organizations: &[Organization],
    projects: &mut impl FnMut(&str) -> Result<Option<Vec<Project>>, E>,
) -> Result<Checkout, E> {
    if remotes.is_empty() {
        return Ok(Checkout::Nothing);
    }
    let mut named = BTreeMap::new();
    for organization in organizations {
        let Some(listed) = projects(&organization.id)? else {
            continue;
        };
        for project in listed {
            if remotes.iter().any(|remote| remote.names(&project)) {
                named.insert(project.id, organization.clone());
            }
        }
    }
    if named.len() > 1 {
        return Ok(Checkout::Several(named.into_keys().collect()));
    }
    Ok(named
        .pop_first()
        .map_or(Checkout::Nothing, |(project, owner)| Checkout::One {
            project,
            owner,
        }))
}

/// The refusal when no source names an organization: exit 2, naming `--org` and the caller's
/// active organizations.
pub(super) fn unresolved(organizations: &[Organization]) -> CommandFailure {
    CommandFailure::with_exit_code(
        anyhow!(unresolved_message(organizations, None)),
        ExitCode::UsageError,
    )
}

/// What [`unresolved`] says: that the command acts in one organization, the caller's active
/// organizations, and how to name one, with `--org` or `USEFUL_ORG`, or as the command line
/// `example` does.
pub(super) fn unresolved_message(organizations: &[Organization], example: Option<&str>) -> String {
    let none = "this command acts in one organization, and you are an active member of none";
    if organizations.is_empty() {
        return match example {
            None => {
                format!("{none}\n\nCreate or join an organization, then name it with --org ORG.")
            }
            Some(example) => {
                format!("{none}\n\nCreate or join an organization, then name it:\n  {example}")
            }
        };
    }
    let names = organizations
        .iter()
        .map(|organization| organization.slug.as_deref().unwrap_or(&organization.id))
        .collect::<Vec<_>>()
        .join(", ");
    let several = format!(
        "this command acts in one organization, and you are an active member of several: {names}"
    );
    match example {
        None => format!("{several}\n\nName the one it acts in with --org ORG, or set {VARIABLE}."),
        Some(example) => format!("{several}\n\nName the one it acts in:\n  {example}"),
    }
}

/// A remote of the working directory's repository, as the host and path its fetch address
/// names.
#[derive(Debug, Eq, PartialEq)]
struct Remote {
    host: String,
    path: String,
}

impl Remote {
    /// Whether this remote names the project's repository: the host is the provider's
    /// (`github.com`, or the host of the project's GitLab instance, else `gitlab.com`) and the
    /// path is the repository's `owner/name` path, both without regard to ASCII case.
    fn names(&self, project: &Project) -> bool {
        let Some(repository) = project.repository.as_deref() else {
            return false;
        };
        let host = match useful_support::wire_name(repository.provider_kind).as_deref() {
            Some("github") => Some("github.com"),
            Some("gitlab") => repository
                .instance_url
                .as_deref()
                .map_or(Some("gitlab.com"), |url| {
                    useful_support::remote_address(url).map(|address| address.host)
                }),
            _ => None,
        };
        host.is_some_and(|host| host.eq_ignore_ascii_case(&self.host))
            && self.path.eq_ignore_ascii_case(&repository.full_name)
    }
}

/// The remotes of the repository holding the working directory, from the fetch addresses
/// `git remote -v` prints. A missing `git`, a directory outside a repository, and a failed,
/// timed-out or truncated probe are no checkout and have none.
fn checkout_remotes(runner: &dyn CommandRunner) -> Vec<Remote> {
    let Ok(output) = runner.run(CommandRequest {
        program: Path::new("git"),
        args: &["remote", "-v"],
        timeout: GIT_TIMEOUT,
        maximum_stdout_bytes: GIT_STDOUT_BYTES,
        clear_environment: false,
        environment: &[],
        current_directory: None,
    }) else {
        return Vec::new();
    };
    if !output.success || output.truncated {
        return Vec::new();
    }
    std::str::from_utf8(&output.stdout).map_or_else(|_| Vec::new(), remotes)
}

/// The distinct remotes a `git remote -v` listing names by fetch address. A fetch line is
/// `NAME<tab>ADDRESS (fetch)`, followed in a partial clone by the remote's filter in brackets.
/// An address that is not a host and a path names none; each is dropped once read, since its
/// user information can hold a credential.
fn remotes(listing: &str) -> Vec<Remote> {
    let mut remotes = Vec::new();
    for line in listing.lines() {
        let Some((address, _)) = line
            .split_once('\t')
            .and_then(|(_, rest)| rest.rsplit_once(" (fetch)"))
            .filter(|(_, filter)| filter.is_empty() || filter.starts_with(" ["))
        else {
            continue;
        };
        let Some(address) = useful_support::remote_address(address.trim()) else {
            continue;
        };
        let remote = Remote {
            host: address.host.to_owned(),
            path: address.path.to_owned(),
        };
        if !remote.path.is_empty() && !remotes.contains(&remote) {
            remotes.push(remote);
        }
    }
    remotes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(host: &str, path: &str) -> Remote {
        Remote {
            host: host.to_owned(),
            path: path.to_owned(),
        }
    }

    fn project(id: &str, organization: &str, repository: serde_json::Value) -> Project {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "organizationId": organization,
            "name": "widgets",
            "runnerPool": null,
            "repository": repository,
            "executionReadiness": {"ready": false, "blockers": ["runner_pool_unassigned"]},
            "createdAt": "2026-09-05T12:00:00Z",
            "updatedAt": "2026-09-05T12:01:00Z"
        }))
        .unwrap()
    }

    fn repository(provider: &str, instance: Option<&str>, full_name: &str) -> serde_json::Value {
        let mut repository = serde_json::json!({
            "connectionId": "rpc_01k0z6r1w8f4jy2m7q9v3x5abc",
            "providerKind": provider,
            "providerRepositoryId": "123456789",
            "fullName": full_name,
            "defaultBranch": "main",
            "availability": "active"
        });
        if let Some(instance) = instance {
            repository["instanceUrl"] = serde_json::json!(instance);
        }
        repository
    }

    fn organization(id: &str, slug: &str) -> Organization {
        Organization {
            id: id.to_owned(),
            slug: Some(slug.to_owned()),
        }
    }

    const ACME: &str = "org_01k0z6r1w8f4jy2m7q9v3x5abc";
    const DUNDER: &str = "org_01k0z6r1w8f4jy2m7q9v3x5abd";

    fn resolve_unnamed(
        remotes: &[Remote],
        listed: &[(&str, Option<Vec<Project>>)],
    ) -> Result<InEffect, Vec<String>> {
        let organizations = vec![organization(ACME, "acme"), organization(DUNDER, "dunder")];
        unnamed::<()>(
            remotes,
            || Ok(organizations),
            |id| {
                Ok(listed
                    .iter()
                    .find(|(listed, _)| *listed == id)
                    .and_then(|(_, projects)| projects.clone()))
            },
        )
        .unwrap()
        .organization
        .map(|(organization, source)| InEffect::new(organization.id, source))
        .map_err(|organizations| {
            organizations
                .into_iter()
                .map(|organization| organization.id)
                .collect()
        })
    }

    fn named(name: &str, project: Project) -> Project {
        Project {
            name: name.to_owned(),
            ..project
        }
    }

    #[test]
    fn a_remote_is_its_fetch_address_as_a_host_and_a_path_without_its_user_information() {
        let listing = "origin\thttps://user:synthetic-secret@GitHub.com/Acme/Widgets.git (fetch)\n\
                       origin\thttps://user:synthetic-secret@GitHub.com/Acme/Widgets.git (push)\n\
                       fork\tgit@github.com:ada/widgets.git (fetch)\n\
                       fork\tgit@github.com:ada/widgets.git (push)\n\
                       mirror\tssh://git@gitlab.example.test:2222/group/sub/widgets/ (fetch)\n\
                       copy\thttps://github.com/ada/widgets (fetch)\n\
                       partial\thttps://github.com/acme/gadgets.git (fetch) [blob:none]\n\
                       partial\thttps://github.com/acme/gadgets.git (push)\n\
                       local\t/srv/git/widgets.git (fetch)\n\
                       relative\t../widgets (fetch)\n\
                       bare\thttps://github.com/ (fetch)\n\
                       push-only\tgit@github.com:other/repo.git (push)\n";

        let remotes = remotes(listing);

        assert_eq!(
            remotes,
            [
                remote("GitHub.com", "Acme/Widgets"),
                remote("github.com", "ada/widgets"),
                remote("gitlab.example.test", "group/sub/widgets"),
                // A partial clone's fetch line ends with its filter.
                remote("github.com", "acme/gadgets"),
            ]
        );
        assert!(
            remotes
                .iter()
                .all(|remote| !remote.host.contains("synthetic-secret"))
        );
    }

    #[test]
    fn a_remote_names_a_project_by_the_provider_host_and_the_repository_path() {
        let github = project(
            "prj_01k0z6r1w8f4jy2m7q9v3x5abc",
            ACME,
            repository("github", None, "acme/widgets"),
        );
        let gitlab_com = project(
            "prj_01k0z6r1w8f4jy2m7q9v3x5abd",
            ACME,
            repository("gitlab", None, "group/sub/widgets"),
        );
        let gitlab_instance = project(
            "prj_01k0z6r1w8f4jy2m7q9v3x5abe",
            ACME,
            repository(
                "gitlab",
                Some("https://GitLab.Example.Test:8443"),
                "group/sub/widgets",
            ),
        );

        assert!(remote("GITHUB.COM", "Acme/Widgets").names(&github));
        assert!(!remote("gitlab.com", "acme/widgets").names(&github));
        assert!(!remote("github.com", "acme/widgets-two").names(&github));
        assert!(remote("gitlab.com", "Group/Sub/Widgets").names(&gitlab_com));
        assert!(!remote("gitlab.example.test", "group/sub/widgets").names(&gitlab_com));
        assert!(remote("gitlab.example.test", "group/sub/widgets").names(&gitlab_instance));
        assert!(!remote("gitlab.com", "group/sub/widgets").names(&gitlab_instance));
        let detached = project(
            "prj_01k0z6r1w8f4jy2m7q9v3x5abf",
            ACME,
            serde_json::Value::Null,
        );
        assert!(!remote("github.com", "acme/widgets").names(&detached));
    }

    #[test]
    fn the_checkout_names_an_organization_only_through_exactly_one_project() {
        let widgets = project(
            "prj_01k0z6r1w8f4jy2m7q9v3x5abc",
            DUNDER,
            repository("github", None, "acme/widgets"),
        );
        let other = project(
            "prj_01k0z6r1w8f4jy2m7q9v3x5abd",
            ACME,
            repository("github", None, "acme/widgets"),
        );
        let fork = remote("github.com", "ada/widgets");
        let upstream = remote("github.com", "acme/widgets");

        // The fork's upstream names the project, whichever remote it is.
        assert_eq!(
            resolve_unnamed(
                &[fork, remote("github.com", "acme/widgets")],
                &[
                    (ACME, Some(Vec::new())),
                    (DUNDER, Some(vec![widgets.clone()]))
                ],
            ),
            Ok(InEffect::new(DUNDER.to_owned(), Source::Checkout))
        );
        // Two projects named by the checkout name none; the memberships decide.
        assert_eq!(
            resolve_unnamed(
                std::slice::from_ref(&upstream),
                &[
                    (ACME, Some(vec![other])),
                    (DUNDER, Some(vec![widgets.clone()]))
                ],
            ),
            Err(vec![ACME.to_owned(), DUNDER.to_owned()])
        );
        // An organization whose projects Cloud refuses is passed over.
        assert_eq!(
            resolve_unnamed(
                std::slice::from_ref(&upstream),
                &[(ACME, None), (DUNDER, Some(vec![widgets]))],
            ),
            Ok(InEffect::new(DUNDER.to_owned(), Source::Checkout))
        );
    }

    #[test]
    fn no_remote_asks_for_no_project_and_one_membership_names_its_organization() {
        let read = unnamed::<()>(
            &[],
            || Ok(vec![organization(ACME, "acme")]),
            |_| panic!("no project is read without a remote"),
        );

        assert_eq!(
            read.map(|unnamed| unnamed.organization.ok()),
            Ok(Some((organization(ACME, "acme"), Source::OnlyMembership)))
        );
    }

    #[test]
    fn an_empty_variable_is_unset_and_a_malformed_one_is_refused_naming_it() {
        let unnamed = || OrgArgs { org: None };

        assert_eq!(unnamed().named(None).ok(), Some(None));
        assert_eq!(unnamed().named(Some(OsStr::new(""))).ok(), Some(None));
        assert_eq!(
            unnamed().named(Some(OsStr::new("acme"))).ok(),
            Some(Some(InEffect::new("acme".to_owned(), Source::Environment)))
        );
        let flagged = OrgArgs {
            org: Some("other".parse().unwrap()),
        };
        assert_eq!(
            flagged.named(Some(OsStr::new("acme"))).ok(),
            Some(Some(InEffect::new("other".to_owned(), Source::Flag)))
        );
        for malformed in ["Acme", "acme research", "org_short"] {
            let refusal = unnamed()
                .named(Some(OsStr::new(malformed)))
                .expect_err("a malformed variable is refused");
            assert_eq!(refusal.exit_code(), ExitCode::UsageError);
            assert!(refusal.error().to_string().starts_with(VARIABLE));
        }
    }

    #[test]
    fn an_empty_project_variable_is_unset_and_a_malformed_one_names_none_naming_it() {
        let unnamed = || ProjectArgs { project: None };
        let id = "prj_01k0z6r1w8f4jy2m7q9v3x5abc";

        assert_eq!(unnamed().named(None), Ok(None));
        assert_eq!(unnamed().named(Some(OsStr::new(""))), Ok(None));
        assert_eq!(
            unnamed().named(Some(OsStr::new("paper"))),
            Ok(Some((
                ProjectRef::Name("paper".to_owned()),
                Source::Environment
            )))
        );
        assert_eq!(
            unnamed().named(Some(OsStr::new(id))),
            Ok(Some((ProjectRef::Id(id.to_owned()), Source::Environment)))
        );
        let flagged = ProjectArgs {
            project: Some("pencil".parse().unwrap()),
        };
        assert_eq!(
            flagged.named(Some(OsStr::new("paper"))),
            Ok(Some((ProjectRef::Name("pencil".to_owned()), Source::Flag)))
        );
        for malformed in ["Paper", "paper project", "prj_short", "-paper"] {
            let none = unnamed()
                .named(Some(OsStr::new(malformed)))
                .expect_err("a malformed variable names no project");
            assert_eq!(none, NoProject::MalformedVariable);
            assert!(none.to_string().starts_with(PROJECT_VARIABLE));
        }
    }

    #[test]
    fn both_named_the_project_by_id_read_nothing() {
        let id = "prj_01k0z6r1w8f4jy2m7q9v3x5abc";
        let context = resolve::<()>(
            Some(InEffect::new("acme".to_owned(), Source::Flag)),
            Ok(Some((ProjectRef::Id(id.to_owned()), Source::Environment))),
            &[remote("github.com", "acme/widgets")],
            || panic!("no membership is read"),
            |_, _| panic!("no project is read"),
        );

        assert_eq!(
            context,
            Ok(Context {
                organization: Ok(InEffect::new("acme".to_owned(), Source::Flag)),
                project: Ok(ProjectInEffect {
                    project: id.to_owned(),
                    source: Source::Environment,
                }),
            })
        );
    }

    #[test]
    fn a_project_name_is_matched_exactly_among_every_project_of_the_organization_in_effect() {
        let widgets = project(
            "prj_01k0z6r1w8f4jy2m7q9v3x5abc",
            ACME,
            repository("github", None, "acme/widgets"),
        );
        let listed = vec![
            named("widgets-two", widgets.clone()),
            named(
                "widgets",
                Project {
                    id: "prj_01k0z6r1w8f4jy2m7q9v3x5abd".to_owned(),
                    ..widgets
                },
            ),
        ];
        let find = |name: &str| {
            let mut asked = Vec::new();
            let context = resolve::<()>(
                Some(InEffect::new("acme".to_owned(), Source::Flag)),
                Ok(Some((ProjectRef::Name(name.to_owned()), Source::Flag))),
                &[],
                || panic!("no membership is read"),
                |organization, include_archived| {
                    asked.push((organization.to_owned(), include_archived));
                    Ok(Some(listed.clone()))
                },
            )
            .unwrap();
            assert_eq!(asked, [("acme".to_owned(), true)]);
            context.project
        };

        assert_eq!(
            find("widgets"),
            Ok(ProjectInEffect {
                project: "prj_01k0z6r1w8f4jy2m7q9v3x5abd".to_owned(),
                source: Source::Flag,
            })
        );
        assert_eq!(
            find("widget"),
            Err(NoProject::UnknownName {
                name: "widget".to_owned(),
                organization: "acme".to_owned(),
            })
        );
    }

    #[test]
    fn a_project_leaf_runs_with_both_in_effect_and_a_subject_it_cannot_find_is_not_found() {
        let id = "prj_01k0z6r1w8f4jy2m7q9v3x5abc";
        let acme = || Ok(InEffect::new("acme".to_owned(), Source::Flag));
        let ghost = || NoProject::UnknownName {
            name: "ghost".to_owned(),
            organization: "acme".to_owned(),
        };
        let context = |organization, project| Context {
            organization,
            project,
        };
        let found = Ok(ProjectInEffect {
            project: id.to_owned(),
            source: Source::Checkout,
        });

        assert_eq!(
            runnable(context(acme(), found), false),
            Ok(("acme".to_owned(), id.to_owned()))
        );
        assert_eq!(
            runnable(context(acme(), Err(ghost())), true),
            Err(Unrunnable::UnknownProject)
        );
        assert_eq!(
            runnable(context(acme(), Err(ghost())), false),
            Err(Unrunnable::NoProject(ghost()))
        );
        let several = vec![organization(ACME, "acme"), organization(DUNDER, "dunder")];
        assert_eq!(
            runnable(
                context(
                    Err(several.clone()),
                    Err(NoProject::NoOrganization {
                        name: "ghost".to_owned()
                    })
                ),
                true
            ),
            Err(Unrunnable::NoOrganization(several))
        );
    }

    #[test]
    fn a_checkout_that_matches_two_projects_names_none() {
        let upstream = remote("github.com", "acme/widgets");
        let widgets = project(
            "prj_01k0z6r1w8f4jy2m7q9v3x5abc",
            ACME,
            repository("github", None, "acme/widgets"),
        );
        let other = project(
            "prj_01k0z6r1w8f4jy2m7q9v3x5abd",
            DUNDER,
            repository("github", None, "acme/widgets"),
        );

        let context = resolve::<()>(
            None,
            Ok(None),
            std::slice::from_ref(&upstream),
            || {
                Ok(vec![
                    organization(ACME, "acme"),
                    organization(DUNDER, "dunder"),
                ])
            },
            |id, include_archived| {
                assert!(!include_archived);
                Ok(Some(vec![if id == ACME {
                    widgets.clone()
                } else {
                    other.clone()
                }]))
            },
        )
        .unwrap();

        assert_eq!(
            context.organization,
            Err(vec![
                organization(ACME, "acme"),
                organization(DUNDER, "dunder")
            ])
        );
        assert_eq!(
            context.project,
            Err(NoProject::SeveralInCheckout(vec![
                "prj_01k0z6r1w8f4jy2m7q9v3x5abc".to_owned(),
                "prj_01k0z6r1w8f4jy2m7q9v3x5abd".to_owned(),
            ]))
        );
    }
}
