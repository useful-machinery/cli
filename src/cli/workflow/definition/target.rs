//! A definition named by its ID or its name wherever it lives (REQ-CLOUDDEF-42, INV-CLI-20):
//! under the `useful` home, read without a request, and in the project in effect
//! (REQ-PROJECT-100), read through the public API (REQ-CLOUDDEF-1). A local and a Cloud
//! definition's ID have one form, so an ID is found by looking, under the home first and in
//! the project only when the home holds none; a name never has an ID's form. `find` looks in
//! both places and `home_only` under the home alone; a leaf that changes a definition reads the
//! home for an ID alone (`held`) and otherwise acts in the project in effect (`in_project`, or
//! `within_project` for a leaf that chooses its definition itself); `useful workflow run create`
//! reads the home alone under `--on local` and the project alone under a Cloud place
//! (`acting_in_project`).

use std::convert::Infallible;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context as _, anyhow};
use clap::{Args, ValueEnum};
use serde::Serialize;

use super::cloud_report as report;
use crate::cli::context::{
    self, Context, ContextFailure, OrgArgs, ProjectArgs, ProjectSubject, Unresolved,
};
use crate::cli::{
    CommandFailure, CommandResult, CommonArgs, PrincipalAuthenticationArgs, WorkflowJson, paging,
};
use crate::exit_code::ExitCode;
use useful_api::{
    CommonOrganizationFailure, UnreachableCategory, WorkflowDefinition, WorkflowDefinitionFailure,
    WorkflowRefusal,
};
use useful_execution::{
    DefinitionError, StoredDefinition, WorkflowHome, check_definition_id, list_definitions,
    read_definition,
};
use useful_human_auth::Deployment;

/// The options of a definition leaf that may ask Cloud.
pub(in crate::cli) type Options = CommonArgs<WorkflowJson, PrincipalAuthenticationArgs>;

/// The value name of `--on`, which every command that picks a place spells the same way.
pub(in crate::cli) const PLACE: &str = "PLACE";
pub(in crate::cli) const DEFINITION: &str = "DEFINITION";
pub(in crate::cli) const DEFINITION_HELP: &str = "Workflow definition ID or name";
const DEPLOYMENT_CONTEXT: &str = "configure Useful Machinery workflow definitions";

/// Where a definition lives, as `--on` names it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(in crate::cli) enum On {
    /// The useful home
    Local,
    /// The project in effect
    Project,
}

/// `--org` and `--project`: the organization and the project in effect a leaf asks Cloud in,
/// with whether either was given on the command line, which a leaf that stays under the home
/// refuses rather than ignores.
#[derive(Debug, Args)]
pub(in crate::cli) struct InEffect {
    #[command(flatten)]
    org: OrgArgs,
    #[command(flatten)]
    project: ProjectArgs,
}

impl InEffect {
    /// The organization and project `org` and `project` name, for a leaf that reads each
    /// option itself.
    pub(in crate::cli) const fn new(org: OrgArgs, project: ProjectArgs) -> Self {
        Self { org, project }
    }

    /// Whether `--org` or `--project` was given; `USEFUL_ORG` and `USEFUL_PROJECT` are not
    /// options.
    pub(in crate::cli) const fn given(&self) -> bool {
        self.org.given() || self.project.given()
    }
}

/// A definition as a command names it: an ID, `def_` and 26 characters, or else a name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::cli) enum Named {
    Id(String),
    Name(String),
}

impl Named {
    pub(in crate::cli) fn as_str(&self) -> &str {
        match self {
            Self::Id(value) | Self::Name(value) => value,
        }
    }
}

impl FromStr for Named {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(if check_definition_id(value).is_ok() {
            Self::Id(value.to_owned())
        } else {
            Self::Name(value.to_owned())
        })
    }
}

impl fmt::Display for Named {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The project in effect a command asks Cloud in: the organization reference it sends and the
/// project's ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::cli) struct Project {
    pub(in crate::cli) organization: String,
    pub(in crate::cli) project: String,
}

/// Why Cloud was not asked.
pub(in crate::cli) enum NotAsked {
    /// The command reads the home alone.
    LocalOnly,
    /// Nobody is signed in.
    SignedOut,
    /// No organization or no project is in effect: the usage error a command that needs one
    /// ends with.
    NoProject(CommandFailure),
    /// Cloud could not be reached.
    Unreachable(UnreachableCategory),
}

impl NotAsked {
    /// The `reason` a document names.
    pub(in crate::cli) const fn reason(&self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::SignedOut => "signed_out",
            Self::NoProject(_) => "no_project",
            Self::Unreachable(_) => "unreachable",
        }
    }

    /// The failure a leaf that must ask Cloud ends with when it was not asked, written as any
    /// Cloud leaf writes one; no project in effect is the usage error itself.
    pub(in crate::cli) fn failure(self) -> Result<WorkflowDefinitionFailure, CommandFailure> {
        match self {
            Self::NoProject(failure) => Err(failure),
            Self::Unreachable(category) => Ok(WorkflowDefinitionFailure::Unreachable { category }),
            Self::SignedOut | Self::LocalOnly => Ok(WorkflowDefinitionFailure::Unauthenticated),
        }
    }

    /// Why Cloud was not asked, as a diagnostic and its remedy.
    pub(in crate::cli) fn why(&self) -> String {
        match self {
            Self::LocalOnly => "only the useful home was read".to_owned(),
            Self::SignedOut => {
                "you're not signed in\n\nSign in with useful account login.".to_owned()
            }
            Self::NoProject(failure) => format!("{:#}", failure.error()),
            Self::Unreachable(category) => format!(
                "Useful Machinery could not be reached ({})\n\nCheck your connection and try again.",
                category.as_str()
            ),
        }
    }
}

/// Whether Cloud was asked, and where, or why not: the `cloud` member of a document.
pub(in crate::cli) enum Asked {
    Asked(Project),
    NotAsked(NotAsked),
}

impl Serialize for Asked {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Document<'a> {
            asked: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            organization_ref: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            project_id: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            reason: Option<&'static str>,
        }
        let document = match self {
            Self::Asked(project) => Document {
                asked: true,
                organization_ref: Some(&project.organization),
                project_id: Some(&project.project),
                reason: None,
            },
            Self::NotAsked(not_asked) => Document {
                asked: false,
                organization_ref: None,
                project_id: None,
                reason: Some(not_asked.reason()),
            },
        };
        document.serialize(serializer)
    }
}

/// The project in effect as Cloud can be asked in it, read under the leaf's credential, or
/// why it cannot be. A variable that names nothing, a read Cloud refused otherwise and a read
/// that failed end the command.
pub(in crate::cli) fn reach(
    in_effect: InEffect,
    options: &Options,
    deployment: &Deployment,
) -> Result<Result<Project, NotAsked>, CommandFailure> {
    let no_project = |message: String| {
        Ok(Err(NotAsked::NoProject(CommandFailure::with_exit_code(
            anyhow!(message),
            ExitCode::UsageError,
        ))))
    };
    match context::in_effect(in_effect.org, in_effect.project, options, deployment) {
        Ok(Context {
            organization: Ok(organization),
            project: Ok(project),
        }) => Ok(Ok(Project {
            organization: organization.organization,
            project: project.project,
        })),
        Ok(Context {
            organization: Err(organizations),
            ..
        }) => Ok(Err(NotAsked::NoProject(context::unresolved(
            &organizations,
        )))),
        Ok(Context {
            project: Err(none), ..
        }) => no_project(none.to_string()),
        Err(Unresolved::Variable(failure)) => Err(failure),
        Err(Unresolved::Refused(CommonOrganizationFailure::Unauthenticated)) => {
            Ok(Err(NotAsked::SignedOut))
        }
        Err(Unresolved::Refused(CommonOrganizationFailure::Unreachable(category))) => {
            Ok(Err(NotAsked::Unreachable(category)))
        }
        Err(Unresolved::Refused(CommonOrganizationFailure::Forbidden)) => {
            Err(refused_context("forbidden"))
        }
        Err(Unresolved::Refused(CommonOrganizationFailure::InvalidInput)) => {
            Err(refused_context("rejected as invalid"))
        }
        Err(Unresolved::Failed(error)) => Err(error.into()),
    }
}

/// A read of the organization or the project in effect that Cloud refused, `reason` saying how.
fn refused_context(reason: &str) -> CommandFailure {
    CommandFailure::new(anyhow!(
        "read the organization and project in effect: {reason}\n\n\
         Check your access to the organization and the project, then try again."
    ))
}

/// A read of the project's definitions that Cloud answered, or failed as a Cloud leaf fails;
/// the session missing is Cloud not asked.
pub(in crate::cli) enum Answer<T> {
    Read(T),
    NotAsked(NotAsked),
    Failed(WorkflowDefinitionFailure),
}

/// Every definition of `project`, read to the last page, archived ones included.
pub(in crate::cli) fn every_definition(
    deployment: &Deployment,
    options: &Options,
    project: &Project,
) -> anyhow::Result<Answer<Vec<WorkflowDefinition>>> {
    let read = super::with_api(deployment, options, |api| {
        match paging::every_page(Paged::RepeatedCursor, |cursor| {
            api.definitions(&project.organization, &project.project, None, cursor)
                .map_err(Paged::Failed)
        }) {
            Err(Paged::Failed(failure)) => Err(failure),
            paged => Ok(paged),
        }
    })?;
    Ok(match read {
        Ok(Ok(definitions)) => Answer::Read(definitions),
        Ok(Err(Paged::RepeatedCursor)) => {
            return Err(anyhow!(
                "list the workflow definitions of project {}: a page repeated an earlier cursor",
                project.project
            ));
        }
        Ok(Err(Paged::Failed(failure))) | Err(failure) => Answer::of(failure),
    })
}

impl<T> Answer<T> {
    /// A failed read: a missing session is nobody signed in, and Cloud not answering is Cloud
    /// not reached.
    fn of(failure: WorkflowDefinitionFailure) -> Self {
        match failure {
            WorkflowDefinitionFailure::Unauthenticated => Self::NotAsked(NotAsked::SignedOut),
            WorkflowDefinitionFailure::Unreachable { category } => {
                Self::NotAsked(NotAsked::Unreachable(category))
            }
            failure => Self::Failed(failure),
        }
    }
}

/// Why paging the definitions stopped.
enum Paged {
    Failed(WorkflowDefinitionFailure),
    RepeatedCursor,
}

/// A definition the lookup found.
pub(in crate::cli) enum Found {
    /// Under the home, which the command reads further without a request.
    Home {
        home: WorkflowHome,
        definition: StoredDefinition,
    },
    /// In the project in effect, read under the deployment the command reads further with.
    Project {
        deployment: Deployment,
        project: Project,
        definition: WorkflowDefinition,
    },
}

/// The leaf a lookup is for: its name below `useful workflow definition`, its command, the
/// line that heads its human refusal, and whether `--json` was given.
#[derive(Clone, Copy)]
pub(in crate::cli) struct Leaf {
    pub(in crate::cli) name: &'static str,
    pub(in crate::cli) command: &'static str,
    pub(in crate::cli) refused: &'static str,
    pub(in crate::cli) json: bool,
}

/// Where a lookup that found nothing looked: the home, when it looked there, and whether it
/// asked Cloud, and in which project, or why not.
pub(in crate::cli) struct Looked {
    pub(in crate::cli) home: Option<PathBuf>,
    pub(in crate::cli) cloud: Asked,
}

/// Finds `named` under the home and then, when the home holds none, in the project in effect
/// (REQ-CLOUDDEF-42): under the home an ID is read and a name is matched among the records,
/// both without a request; in the project an ID is read and a name is matched among every
/// definition, archived ones included. The deployment is loaded only when the home holds none.
/// Several of one place with the name, none anywhere and any failure end the command, written
/// as `leaf` writes them: the error is its result.
pub(in crate::cli) fn find(
    named: &Named,
    in_effect: InEffect,
    options: &Options,
    leaf: Leaf,
) -> Result<Found, CommandResult> {
    let home = match WorkflowHome::from_environment() {
        Ok(home) => home,
        Err(error) => return Err(refused(leaf, &error)),
    };
    let home = match in_home(&home, named) {
        Ok(Some(definition)) => return Ok(Found::Home { home, definition }),
        Ok(None) => home.root().to_path_buf(),
        Err(Missed::Several(ids)) => return Err(Err(several(named, "the useful home", &ids))),
        Err(Missed::Refused(error)) => return Err(refused(leaf, &error)),
    };
    let missing = |cloud: Asked| {
        Err(not_found(
            leaf,
            named,
            &Looked {
                home: Some(home.clone()),
                cloud,
            },
        ))
    };
    let deployment = Deployment::load()
        .map_err(|error| anyhow!(error))
        .context(DEPLOYMENT_CONTEXT)
        .map_err(|error| Err(error.into()))?;
    let project = match reach(in_effect, options, &deployment) {
        Ok(Ok(project)) => project,
        Ok(Err(NotAsked::Unreachable(category))) => {
            return Err(failed(
                leaf,
                None,
                &WorkflowDefinitionFailure::Unreachable { category },
            ));
        }
        Ok(Err(not_asked)) => return missing(Asked::NotAsked(not_asked)),
        Err(failure) => return Err(Err(failure)),
    };
    let read = match named {
        Named::Id(id) => by_id(&deployment, options, &project, id),
        Named::Name(name) => by_name(&deployment, options, &project, name),
    }
    .map_err(|error| Err(error.into()))?;
    match read {
        Answer::Read(Ok(Some(definition))) => Ok(Found::Project {
            deployment,
            project,
            definition,
        }),
        Answer::Read(Ok(None)) => missing(Asked::Asked(project)),
        Answer::Read(Err(ids)) => Err(Err(several(
            named,
            &format!("project {}", project.project),
            &ids,
        ))),
        Answer::NotAsked(NotAsked::Unreachable(category)) => Err(failed(
            leaf,
            Some(&project),
            &WorkflowDefinitionFailure::Unreachable { category },
        )),
        Answer::NotAsked(not_asked) => missing(Asked::NotAsked(not_asked)),
        Answer::Failed(failure) => Err(failed(leaf, Some(&project), &failure)),
    }
}

/// The record under the home `named` names when it is an ID the home holds, read without a
/// request; none for a name or for an ID the home does not hold. A leaf that changes a
/// definition looks under the home for an ID alone (REQ-CLOUDDEF-42): a name, there, always
/// names a Cloud definition. A refusal of the home ends the command, written as `leaf` writes
/// one: the error is its result.
pub(in crate::cli) fn held(
    named: &Named,
    leaf: Leaf,
) -> Result<Option<(WorkflowHome, StoredDefinition)>, CommandResult> {
    let Named::Id(id) = named else {
        return Ok(None);
    };
    let home = WorkflowHome::from_environment().map_err(|error| refused(leaf, &error))?;
    match read_definition(&home, id) {
        Ok(definition) => Ok(Some((home, definition))),
        Err(DefinitionError::NotFound { .. }) => Ok(None),
        Err(error) => Err(refused(leaf, &error)),
    }
}

/// The record under the home `named` names, by ID or by name, read without a request, for a
/// leaf told to look under the home alone (REQ-CLOUDDEF-42): a name several records hold exits
/// 2 listing their IDs, and none is `definition_not_found` saying Cloud was not asked. A refusal
/// of the home ends the command, written as `leaf` writes one: the error is its result.
pub(in crate::cli) fn home_only(
    named: &Named,
    leaf: Leaf,
) -> Result<StoredDefinition, CommandResult> {
    let home = WorkflowHome::from_environment().map_err(|error| refused(leaf, &error))?;
    match in_home(&home, named) {
        Ok(Some(definition)) => Ok(definition),
        Ok(None) => Err(not_found(
            leaf,
            named,
            &Looked {
                home: Some(home.root().to_path_buf()),
                cloud: Asked::NotAsked(NotAsked::LocalOnly),
            },
        )),
        Err(Missed::Several(ids)) => Err(Err(several(named, "the useful home", &ids))),
        Err(Missed::Refused(error)) => Err(refused(leaf, &error)),
    }
}

/// Ends a leaf that acts on a Cloud definition alone when `named` is an ID the home holds:
/// `definition_local`, exit 1, before the deployment is loaded and anything is sent
/// (REQ-CLOUDDEF-42).
pub(in crate::cli) fn cloud_only(named: &Named, leaf: Leaf) -> Result<(), CommandResult> {
    match held(named, leaf)? {
        Some((_, definition)) => Err(local(leaf, &definition)),
        None => Ok(()),
    }
}

/// `definition_local`: the definition is under the home and the leaf acts on a Cloud one.
fn local(leaf: Leaf, definition: &StoredDefinition) -> CommandResult {
    super::report::write_local(
        leaf.command,
        leaf.refused,
        &definition.record.id,
        &definition.path,
        leaf.json,
    )
    .with_context(|| format!("write {} result", leaf.command))?;
    Ok(ExitCode::GeneralFailure)
}

/// Runs `run` with the deployment, the options, the project in effect (REQ-PROJECT-100) and the
/// ID of the Cloud definition `named` names there (REQ-CLOUDDEF-42). An ID is sent as given,
/// costing no request, so Cloud answers for a definition it does not hold; a name is matched
/// among every definition of the project, archived ones included, and several with it exit 2
/// listing their IDs. With no organization or no project in effect the leaf ends with exit 2
/// before a request of its own (INV-CLI-20), and every other failure, a read of the project
/// Cloud refused included, is written as any Cloud leaf writes one.
pub(in crate::cli) fn in_project(
    named: Named,
    in_effect: InEffect,
    options: Options,
    leaf: Leaf,
    run: impl FnOnce(&Deployment, &Options, &Project, &str) -> CommandResult,
) -> CommandResult {
    acting_in_project(
        named,
        in_effect,
        options,
        leaf,
        |deployment, options, project, id| run(deployment, &options, project, id),
    )
}

/// As [`in_project`], handing `run` the options themselves, for a leaf that goes on to act
/// under them as a command of another family: `useful workflow run create --on personal|project`
/// (REQ-RUN-94), whose credential, read once, serves the lookup and the creation.
pub(in crate::cli) fn acting_in_project(
    named: Named,
    in_effect: InEffect,
    options: Options,
    leaf: Leaf,
    run: impl FnOnce(&Deployment, Options, &Project, &str) -> CommandResult,
) -> CommandResult {
    owning_project(
        in_effect,
        options,
        leaf,
        |deployment, options, project| match project_id(named, deployment, &options, project, leaf)?
        {
            Ok(id) => run(deployment, options, project, &id),
            Err(result) => result,
        },
    )
}

/// Runs `run` with the deployment, the options and the project in effect (REQ-PROJECT-100), as
/// [`in_project`] does for a leaf that chooses its definition itself.
pub(in crate::cli) fn within_project(
    in_effect: InEffect,
    options: Options,
    leaf: Leaf,
    run: impl FnOnce(&Deployment, &Options, &Project) -> CommandResult,
) -> CommandResult {
    owning_project(in_effect, options, leaf, |deployment, options, project| {
        run(deployment, &options, project)
    })
}

/// [`within_project`], handing `run` the options themselves.
fn owning_project(
    in_effect: InEffect,
    options: Options,
    leaf: Leaf,
    run: impl FnOnce(&Deployment, Options, &Project) -> CommandResult,
) -> CommandResult {
    let deployment = Deployment::load()
        .map_err(|error| anyhow!(error))
        .context(DEPLOYMENT_CONTEXT)?;
    let mut ended = None;
    let exit_code = context::execute_in_project(
        in_effect.org,
        ProjectSubject::InEffect(in_effect.project),
        options,
        &deployment,
        |_, failure, _, json| context_failed(leaf, failure, json),
        |options, organization, project| {
            let project = Project {
                organization: organization.to_owned(),
                project: project.to_owned(),
            };
            run(&deployment, options, &project).or_else(|failure| {
                let exit_code = failure.exit_code();
                ended = Some(failure);
                Ok(exit_code)
            })
        },
    )?;
    ended.map_or(Ok(exit_code), Err)
}

/// The ID of the definition `named` names in `project`, or the result that ends the leaf: a
/// name none has is `definition_not_found` naming the project, and several with it exit 2.
fn project_id(
    named: Named,
    deployment: &Deployment,
    options: &Options,
    project: &Project,
    leaf: Leaf,
) -> anyhow::Result<Result<String, CommandResult>> {
    let name = match named {
        Named::Id(id) => return Ok(Ok(id)),
        Named::Name(name) => name,
    };
    Ok(Err(match by_name(deployment, options, project, &name)? {
        Answer::Read(Ok(Some(definition))) => return Ok(Ok(definition.id)),
        Answer::Read(Ok(None)) => not_found(
            leaf,
            &Named::Name(name),
            &Looked {
                home: None,
                cloud: Asked::Asked(project.clone()),
            },
        ),
        Answer::Read(Err(ids)) => Err(several(
            &Named::Name(name),
            &format!("project {}", project.project),
            &ids,
        )),
        Answer::NotAsked(not_asked) => match not_asked.failure() {
            Ok(failure) => failed(leaf, Some(project), &failure),
            Err(failure) => Err(failure),
        },
        Answer::Failed(failure) => failed(leaf, Some(project), &failure),
    }))
}

/// A read of the organization or the project in effect that Cloud refused, written as the
/// leaf's own refusal of that kind (REQ-CLOUDDEF-15).
fn context_failed(leaf: Leaf, failure: &ContextFailure, json: bool) -> anyhow::Result<ExitCode> {
    let failure = match failure {
        ContextFailure::Refused(failure) => organization_failure(failure),
        ContextFailure::UnknownProject => refusal(404, "not-found"),
    };
    report::write_failure(&report::Scope::of(Leaf { json, ..leaf }, None), &failure)
}

/// A refused organization read, such as of the project in effect or of the member directory, as
/// the failure a definition leaf reports: the status and problem type the read was answered
/// with, or the session or Cloud missing.
pub(in crate::cli) fn organization_failure(
    failure: &CommonOrganizationFailure,
) -> WorkflowDefinitionFailure {
    match failure {
        CommonOrganizationFailure::Unauthenticated => WorkflowDefinitionFailure::Unauthenticated,
        CommonOrganizationFailure::Unreachable(category) => {
            WorkflowDefinitionFailure::Unreachable {
                category: *category,
            }
        }
        CommonOrganizationFailure::Forbidden => refusal(403, "forbidden"),
        CommonOrganizationFailure::InvalidInput => refusal(400, "bad-request"),
    }
}

/// A refusal of `status` with problem type `problem`, which carries no workflow safe facts.
pub(in crate::cli) fn refusal(status: u16, problem: &str) -> WorkflowDefinitionFailure {
    WorkflowDefinitionFailure::Refused(Box::new(WorkflowRefusal {
        status,
        problem: problem.to_owned(),
        workflow: None,
    }))
}

/// Why the home's records name no one definition.
enum Missed {
    Several(Vec<String>),
    Refused(DefinitionError),
}

/// The record under `home` that `named` names, none when it holds none.
fn in_home(home: &WorkflowHome, named: &Named) -> Result<Option<StoredDefinition>, Missed> {
    match named {
        Named::Id(id) => match read_definition(home, id) {
            Ok(definition) => Ok(Some(definition)),
            Err(DefinitionError::NotFound { .. }) => Ok(None),
            Err(error) => Err(Missed::Refused(error)),
        },
        Named::Name(name) => {
            let mut matching = list_definitions(home)
                .map_err(Missed::Refused)?
                .into_iter()
                .filter(|definition| definition.record.name == *name)
                .collect::<Vec<_>>();
            match matching.len() {
                0 => Ok(None),
                1 => Ok(matching.pop()),
                _ => Err(Missed::Several(
                    matching
                        .into_iter()
                        .map(|definition| definition.record.id)
                        .collect(),
                )),
            }
        }
    }
}

/// Definition `id` of `project`, none when Cloud answers that it holds none.
fn by_id(
    deployment: &Deployment,
    options: &Options,
    project: &Project,
    id: &str,
) -> anyhow::Result<Answer<Result<Option<WorkflowDefinition>, Vec<String>>>> {
    let read = super::with_api(deployment, options, |api| {
        match api.definition(&project.organization, &project.project, id) {
            Ok(definition) => Ok(Some(definition)),
            Err(WorkflowDefinitionFailure::Refused(refusal)) if refusal.status == 404 => Ok(None),
            Err(failure) => Err(failure),
        }
    })?;
    Ok(match read {
        Ok(definition) => Answer::Read(Ok(definition)),
        Err(failure) => Answer::of(failure),
    })
}

/// The one definition of `project` named `name`, none when none is, or the IDs of every one
/// that is when several are.
fn by_name(
    deployment: &Deployment,
    options: &Options,
    project: &Project,
    name: &str,
) -> anyhow::Result<Answer<Result<Option<WorkflowDefinition>, Vec<String>>>> {
    Ok(match every_definition(deployment, options, project)? {
        Answer::Read(definitions) => {
            let mut matching = definitions
                .into_iter()
                .filter(|definition| definition.name.as_deref() == Some(name))
                .collect::<Vec<_>>();
            Answer::Read(match matching.len() {
                0 | 1 => Ok(matching.pop()),
                _ => Err(matching
                    .into_iter()
                    .map(|definition| definition.id)
                    .collect()),
            })
        }
        Answer::NotAsked(not_asked) => Answer::NotAsked(not_asked),
        Answer::Failed(failure) => Answer::Failed(failure),
    })
}

/// Several definitions of one place have the name: exit 2, listing their IDs.
pub(super) fn several(named: &Named, place: &str, ids: &[String]) -> CommandFailure {
    let ids = ids
        .iter()
        .map(|id| super::report::display(id))
        .collect::<Vec<_>>()
        .join(", ");
    CommandFailure::with_exit_code(
        anyhow!(
            "{place} holds several workflow definitions named {}: {ids}\n\n\
             Name the one to use by its ID.",
            super::report::display(named.as_str())
        ),
        ExitCode::UsageError,
    )
}

/// A refusal of the home, written as `leaf` writes one, exit 1.
fn refused(leaf: Leaf, error: &DefinitionError) -> CommandResult {
    super::report::write_refused(leaf.command, leaf.refused, error, leaf.json)
        .with_context(|| format!("write {} result", leaf.command))?;
    Ok(ExitCode::GeneralFailure)
}

/// `definition_not_found`, saying where the lookup looked, exit 1.
pub(super) fn not_found(leaf: Leaf, named: &Named, looked: &Looked) -> CommandResult {
    super::report::write_not_found(
        leaf.command,
        leaf.refused,
        named.as_str(),
        looked,
        leaf.json,
    )
    .with_context(|| format!("write {} result", leaf.command))?;
    Ok(ExitCode::GeneralFailure)
}

/// A Cloud failure, written as any Cloud leaf writes one.
pub(in crate::cli) fn failed(
    leaf: Leaf,
    project: Option<&Project>,
    failure: &WorkflowDefinitionFailure,
) -> CommandResult {
    report::finish::<()>(&report::Scope::of(leaf, project), Err(failure), |_: &()| {
        Ok(())
    })
}
