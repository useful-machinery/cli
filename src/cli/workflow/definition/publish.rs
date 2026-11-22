//! `useful workflow definition publish DIR`: a revision of the tree under the `useful` home
//! (REQ-WFDEF-18 to REQ-WFDEF-22) or, with `--on project`, of a Cloud definition of the project in
//! effect alone (REQ-CLOUDDEF-14, REQ-CLOUDDEF-20), which writes nothing under the home. With no
//! `--on` a `--to` ID the home does not hold is looked for in the project and published to there.
//! Either sets the bindings the invocation names and keeps the rest (REQ-WFDEF-21,
//! REQ-CLOUDDEF-41).

use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, anyhow};
use clap::Args;
use serde::Serialize;

use super::report::{display, write_invalid, write_json};
use super::target::{self, Answer, Found, InEffect, Leaf, Named, On, Options, Project};
use super::{resend_once, with_api};
use crate::cli::{CommandFailure, CommandResult};
use crate::exit_code::ExitCode;
use useful_api::{
    WorkflowBindingValues, WorkflowDefinition, WorkflowDefinitionApi, WorkflowDefinitionFailure,
    WorkflowProblemDetail, WorkflowPublication, WorkflowTreeFile,
};
use useful_execution::{
    BindingOption, BindingValue, BindingsFile, DefinitionError, Named as NamedBinding,
    NamedBindings, PublishTarget, Published, ValidatedTree, WorkflowHome, publish,
    validate_workflow_tree,
};
use useful_human_auth::Deployment;

pub(super) const ABOUT: &str =
    "Publish a workflow tree as a definition revision under the useful home or in the project";
const COMMAND_NAME: &str = "useful workflow definition publish";
const REFUSED: &str = "Publish refused.";
const ON_HELP: &str = "Publish under the useful home or to the project in effect (default: local)";
const TO_HELP: &str = "Publish to this definition ID or name, whatever its name";
const NEW_HELP: &str = "Create another definition even when one has the tree's name";
/// The problem slug of a reuse that matched several identical Cloud definitions.
const DEFINITION_REUSE_AMBIGUOUS: &str = "definition-reuse-ambiguous";
/// The `state` of a Cloud definition a publication may reach by its name.
const ACTIVE: &str = "active";
/// The problem slug of a Cloud definition the project does not hold, a deleted one included.
const NOT_FOUND: &str = "not-found";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[arg(
        value_name = "DIR",
        help = "Tree directory holding workflow.yaml, resolved from the initial working directory"
    )]
    directory: PathBuf,

    #[arg(
        long,
        value_name = "FILE",
        help = "JSON object naming the binding values to set, null for a binding's default, an integration's nested under its id, resolved from the initial working directory"
    )]
    bindings: Option<PathBuf>,

    #[arg(
        long,
        value_name = "KEY=VALUE",
        value_parser = parse_binding,
        help = "Set binding KEY, `<integration>.<name>` for an integration's, to VALUE; a members value is comma-separated ids (repeatable)"
    )]
    binding: Vec<(String, String)>,

    #[arg(
        long,
        value_name = "KEY",
        help = "Set binding KEY to its declared default (repeatable)"
    )]
    binding_default: Vec<String>,

    #[arg(long, value_enum, value_name = target::PLACE, help = ON_HELP)]
    on: Option<On>,

    #[arg(long, value_name = target::DEFINITION, conflicts_with = "new", help = TO_HELP)]
    to: Option<Named>,

    #[arg(long, help = NEW_HELP)]
    new: bool,

    #[command(flatten)]
    in_effect: InEffect,

    #[command(flatten)]
    options: Options,
}

/// REQ-WFDEF-41: `KEY=VALUE`, split at the first `=`.
fn parse_binding(value: &str) -> Result<(String, String), String> {
    let (key, value) = value
        .split_once('=')
        .ok_or_else(|| "expected KEY=VALUE".to_owned())?;
    Ok((key.to_owned(), value.to_owned()))
}

/// REQ-WFDEF-41: the bindings `--binding` and then `--binding-default` name, in the order
/// given, each `KEY` named at most once across both.
fn binding_options(
    values: Vec<(String, String)>,
    defaults: Vec<String>,
) -> anyhow::Result<Vec<BindingOption>> {
    let options = values
        .into_iter()
        .map(|(key, value)| BindingOption {
            key,
            value: Some(value),
        })
        .chain(
            defaults
                .into_iter()
                .map(|key| BindingOption { key, value: None }),
        )
        .collect::<Vec<_>>();
    let mut keys = HashSet::new();
    if let Some(repeated) = options
        .iter()
        .find(|option| !keys.insert(option.key.as_str()))
    {
        return Err(anyhow!(
            "--binding and --binding-default name `{}` more than once",
            repeated.key
        ));
    }
    Ok(options)
}

/// What a publication to Cloud is addressed to, as the options name it.
enum Aim {
    /// `--to DEFINITION` (REQ-CLOUDDEF-20).
    To(Named),
    /// `--new`: a create that asks for no identical definition.
    New,
    /// The project's one active definition of the root's name, or else a create that asks for
    /// the project's identical definition (REQ-CLOUDDEF-89, REQ-CLOUDDEF-22).
    Named(String),
}

/// Where a publication to Cloud goes, chosen before anything is uploaded.
enum Addressed {
    /// The next revision of this existing definition.
    Existing(String),
    /// A create, asking for the project's identical definition or not.
    Create { reuse_identical: bool },
}

impl Addressed {
    /// The existing definition the publication is addressed to; none for a create.
    fn existing(&self) -> Option<&str> {
        match self {
            Self::Existing(id) => Some(id),
            Self::Create { .. } => None,
        }
    }
}

/// The refusal of `--org` or `--project` given to a publication that stays under the home,
/// which would otherwise publish there where the caller named a project to publish in.
fn project_under_the_home() -> CommandFailure {
    CommandFailure::with_exit_code(
        anyhow!(
            "--org and --project choose the project a publication to Cloud reaches; \
             this publication is under the useful home alone\n\n\
             Drop them, or publish with --on project."
        ),
        ExitCode::UsageError,
    )
}

/// The Cloud definition a publication reached and its current revision: the one it published,
/// or for a reused definition the one it already had; and whether Cloud already held the tree
/// sealed.
struct CloudPublished {
    definition: String,
    created: bool,
    reused: bool,
    revision: i32,
    tree_digest: String,
    tree_reused: bool,
}

/// The tree validated and named, with the bindings the invocation names judged against its
/// root (REQ-WFDEF-20, REQ-WFDEF-41): what every publication starts from.
struct Ready {
    tree: ValidatedTree,
    name: String,
    named: NamedBindings,
}

impl Command {
    pub(super) fn execute(self) -> CommandResult {
        let json = self.options.json;
        let options = binding_options(self.binding, self.binding_default)
            .map_err(|error| CommandFailure::with_exit_code(error, ExitCode::UsageError))?;
        let leaf = Leaf {
            name: "publish",
            command: COMMAND_NAME,
            refused: REFUSED,
            json,
        };
        // A publication under the home asks Cloud nothing, so it takes no project to ask in.
        // Only `--on project`, or with no `--on` a `--to` ID, which may be a Cloud
        // definition's, can reach Cloud.
        let named_project = self.in_effect.given();
        let may_reach_cloud = matches!(
            (self.on, &self.to),
            (Some(On::Project), _) | (None, Some(Named::Id(_)))
        );
        if named_project && !may_reach_cloud {
            return Err(project_under_the_home());
        }
        let tree = match validate_workflow_tree(&self.directory) {
            Ok(tree) => tree,
            Err(diagnostics) => {
                write_invalid(COMMAND_NAME, &self.directory, &diagnostics, json)
                    .context("write workflow definition publish result")?;
                return Ok(ExitCode::GeneralFailure);
            }
        };
        let ready = tree
            .name
            .clone()
            .ok_or(DefinitionError::NameMissing)
            .and_then(|name| {
                let file = self
                    .bindings
                    .as_deref()
                    .map(BindingsFile::read)
                    .transpose()?;
                let named = NamedBindings::judge(&tree, file.as_ref(), &options)?;
                Ok(Ready { tree, name, named })
            });
        let ready = match ready {
            Ok(ready) => ready,
            Err(error) => return refuse(error, json),
        };
        match (self.on, self.to) {
            (Some(On::Project), to) => {
                let aim = match (to, self.new) {
                    (Some(named), _) => Aim::To(named),
                    (None, true) => Aim::New,
                    (None, false) => Aim::Named(ready.name.clone()),
                };
                to_project(&ready, aim, self.in_effect, self.options, leaf)
            }
            // An ID the home does not hold names a Cloud definition of the project in effect.
            (None, Some(named @ Named::Id(_))) => {
                match target::find(&named, self.in_effect, &self.options, leaf) {
                    Ok(Found::Home { .. }) if named_project => Err(project_under_the_home()),
                    Ok(Found::Home { home, definition }) => {
                        in_home(&home, &ready, PublishTarget::To(definition.record.id), json)
                    }
                    Ok(Found::Project {
                        deployment,
                        project,
                        definition,
                    }) => publish_to(
                        &deployment,
                        &self.options,
                        &project,
                        &ready,
                        Addressed::Existing(definition.id),
                    ),
                    Err(ended) => ended,
                }
            }
            (_, Some(named)) => match target::home_only(&named, leaf) {
                Ok(definition) => match WorkflowHome::from_environment() {
                    Ok(home) => {
                        in_home(&home, &ready, PublishTarget::To(definition.record.id), json)
                    }
                    Err(error) => refuse(error, json),
                },
                Err(ended) => ended,
            },
            (_, None) => match WorkflowHome::from_environment() {
                Ok(home) => {
                    let target = if self.new {
                        PublishTarget::New
                    } else {
                        PublishTarget::Resolve
                    };
                    in_home(&home, &ready, target, json)
                }
                Err(error) => refuse(error, json),
            },
        }
    }
}

/// A refusal before anything is written or sent, exit 1 (REQ-WFDEF-27).
fn refuse(error: DefinitionError, json: bool) -> CommandResult {
    super::finish::<()>(COMMAND_NAME, REFUSED, Err(error), json, |_, _| Ok(()))
}

/// Publishes under the home (REQ-WFDEF-19 to REQ-WFDEF-22): the form the runner runs, which
/// prints the document it always has and makes no request.
fn in_home(home: &WorkflowHome, ready: &Ready, target: PublishTarget, json: bool) -> CommandResult {
    let published = publish(
        home,
        &ready.tree,
        target,
        &ready.named,
        &super::super::login_name(),
    );
    super::finish(COMMAND_NAME, REFUSED, published, json, |published, json| {
        if json {
            write_json(&published_report(published), "workflow definition publish")
        } else {
            write_human_published(published)
        }
    })
}

/// Publishes to Cloud alone, in the project in effect (REQ-CLOUDDEF-14): the target is chosen
/// before anything is uploaded.
fn to_project(
    ready: &Ready,
    aim: Aim,
    in_effect: InEffect,
    options: Options,
    leaf: Leaf,
) -> CommandResult {
    target::within_project(
        in_effect,
        options,
        leaf,
        |deployment, options, project| match address(&aim, deployment, options, project, leaf)? {
            Ok(addressed) => publish_to(deployment, options, project, ready, addressed),
            Err(ended) => ended,
        },
    )
}

/// Where `aim` sends the publication in `project`, or the result that ends the command before
/// anything is uploaded: a `--to` name is matched among every definition of the project, archived
/// ones included, and the root's name among the active ones (REQ-CLOUDDEF-42, REQ-CLOUDDEF-14).
fn address(
    aim: &Aim,
    deployment: &Deployment,
    options: &Options,
    project: &Project,
    leaf: Leaf,
) -> anyhow::Result<Result<Addressed, CommandResult>> {
    let (name, any_state) = match aim {
        Aim::To(Named::Id(id)) => return Ok(Ok(Addressed::Existing(id.clone()))),
        Aim::New => {
            return Ok(Ok(Addressed::Create {
                reuse_identical: false,
            }));
        }
        Aim::To(Named::Name(name)) => (name, true),
        Aim::Named(name) => (name, false),
    };
    let definitions = match target::every_definition(deployment, options, project)? {
        Answer::Read(definitions) => definitions,
        Answer::NotAsked(not_asked) => {
            return Ok(Err(match not_asked.failure() {
                Ok(failure) => write_cloud(project, None, &Err(failure), leaf.json),
                Err(failure) => Err(failure),
            }));
        }
        Answer::Failed(failure) => {
            return Ok(Err(write_cloud(project, None, &Err(failure), leaf.json)));
        }
    };
    let ids = definitions
        .into_iter()
        .filter(|definition| {
            definition.name.as_deref() == Some(name.as_str())
                && (any_state || is_active(definition))
        })
        .map(|definition| definition.id)
        .collect::<Vec<_>>();
    let named = Named::Name(name.clone());
    Ok(match (ids.as_slice(), aim) {
        ([id], _) => Ok(Addressed::Existing(id.clone())),
        ([], Aim::To(_)) => Err(target::not_found(
            leaf,
            &named,
            &target::Looked {
                home: None,
                cloud: target::Asked::Asked(project.clone()),
            },
        )),
        ([], _) => Ok(Addressed::Create {
            reuse_identical: true,
        }),
        (_, Aim::To(_)) => Err(Err(target::several(
            &named,
            &format!("project {}", project.project),
            &ids,
        ))),
        (_, _) => Err(Err(several_named(name, project, &ids))),
    })
}

/// Whether a publication may reach `definition` by its name: Cloud refuses one to an archived
/// definition, so an archived one is passed over.
fn is_active(definition: &WorkflowDefinition) -> bool {
    super::cloud_report::wire(definition.state) == ACTIVE
}

/// Several active definitions of the project have the root's name: exit 2, listing their IDs and
/// the two ways to choose (REQ-CLOUDDEF-14).
fn several_named(name: &str, project: &Project, ids: &[String]) -> CommandFailure {
    let listed = ids
        .iter()
        .map(|id| display(id))
        .collect::<Vec<_>>()
        .join(", ");
    CommandFailure::with_exit_code(
        anyhow!(
            "project {} holds several active workflow definitions named {}: {listed}\n\n\
             Publish to the one you choose, or create another:\n  \
             useful workflow definition publish <DIR> --on project --to <DEFINITION>\n  \
             useful workflow definition publish <DIR> --on project --new",
            display(&project.project),
            display(name)
        ),
        ExitCode::UsageError,
    )
}

/// Uploads and seals the tree, then publishes the next revision of the existing definition
/// `addressed` names over the current revision it reads first (REQ-CLOUDDEF-14,
/// REQ-CLOUDDEF-20), or creates one (REQ-CLOUDDEF-22); and reports it. A refused read or
/// publication of an existing definition never falls through to a create. It sends the
/// bindings the invocation names and nothing else, `null` for one named for its default, so
/// Cloud keeps every other binding of the current revision or, for a create, gives it its
/// default (REQ-CLOUDDEF-41): the flat ones in `bindings`, a `members` value as an array, and
/// each integration's under its id in `integrationBindings`, each member absent when it would
/// be empty. It sends the tree's executable files too; one fresh key covers the seal and the
/// publication for the whole invocation.
fn publish_to(
    deployment: &Deployment,
    options: &Options,
    project: &Project,
    ready: &Ready,
    addressed: Addressed,
) -> CommandResult {
    let json = options.json;
    let key = useful_support::generate_idempotency_key()
        .context("generate Cloud workflow definition request identity")?;
    let tree = &ready.tree;
    let files = tree
        .files
        .iter()
        .map(|(path, file)| WorkflowTreeFile {
            path,
            bytes: &file.bytes,
            executable: file.executable,
        })
        .collect::<Vec<_>>();
    let bindings = ready
        .named
        .bindings()
        .iter()
        .map(|(binding, named)| {
            let value = match named {
                NamedBinding::Value(value) => serde_json::to_value(value)?,
                NamedBinding::Default => serde_json::Value::Null,
            };
            Ok((binding.clone(), value))
        })
        .collect::<Result<WorkflowBindingValues, serde_json::Error>>()
        .context("encode the named bindings")?;
    let integration_bindings = ready
        .named
        .integration_bindings()
        .iter()
        .map(|(provider, group)| {
            let values = group
                .iter()
                .map(|(name, named)| {
                    let value = match named {
                        NamedBinding::Value(BindingValue::Text(text)) => Some(text.clone()),
                        NamedBinding::Value(BindingValue::List(_)) => {
                            return Err(anyhow!(
                                "integration binding `{}.{name}` holds a list",
                                provider.as_str()
                            ));
                        }
                        NamedBinding::Default => None,
                    };
                    Ok((name.clone(), value))
                })
                .collect::<anyhow::Result<HashMap<_, _>>>()?;
            Ok((provider.as_str().to_owned(), values))
        })
        .collect::<anyhow::Result<HashMap<_, _>>>()
        .context("encode the named integration bindings")?;
    // Every executable file, `[]` when none is, so clearing the last bit is published too.
    let executable_paths = tree
        .files
        .iter()
        .filter(|(_, file)| file.executable)
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    let digest = format!("{}:{}", tree.digest.algorithm.as_str(), tree.digest.value);
    let steps = CloudSteps {
        project,
        digest: &digest,
        files: &files,
        bindings: (!bindings.is_empty()).then_some(&bindings),
        integration_bindings: (!integration_bindings.is_empty()).then_some(&integration_bindings),
        executable_paths: &executable_paths,
        addressed: &addressed,
        key: &key,
    };
    let reached = with_api(deployment, options, |api| steps.run(api))?;
    write_cloud(project, addressed.existing(), &reached, json)
}

/// One invocation's Cloud steps, rerun whole with the same key when a refreshed session
/// retries them.
struct CloudSteps<'a> {
    project: &'a Project,
    /// The tree digest, `sha256:<hex>`.
    digest: &'a str,
    files: &'a [WorkflowTreeFile<'a>],
    /// The flat bindings named, `Value::Null` for a default; `None` when none is named.
    bindings: Option<&'a WorkflowBindingValues>,
    /// Each integration's bindings named, by name under its id, `None` for a default; `None`
    /// when none is named.
    integration_bindings: Option<&'a HashMap<String, HashMap<String, Option<String>>>>,
    /// The tree's executable files, in bytewise order.
    executable_paths: &'a [String],
    addressed: &'a Addressed,
    key: &'a str,
}

impl CloudSteps<'_> {
    fn run(
        &self,
        api: &WorkflowDefinitionApi<'_>,
    ) -> Result<CloudPublished, WorkflowDefinitionFailure> {
        let (organization, project) = (
            self.project.organization.as_str(),
            self.project.project.as_str(),
        );
        let (_, tree_reused) = api.upload_tree(organization, self.digest, self.files, self.key)?;
        let publication = WorkflowPublication {
            tree_digest: self.digest,
            bindings: self.bindings,
            integration_bindings: self.integration_bindings,
            executable_paths: Some(self.executable_paths),
        };
        // The create or publication is sent again once, under the same key, when Cloud
        // does not answer it or answers with a transient problem (REQ-CLOUDDEF-82,
        // REQ-CLOUDDEF-174).
        let (publication, created, reused) = match self.addressed {
            Addressed::Existing(id) => {
                let current = api.definition(organization, project, id)?.current_revision;
                let published = resend_once(|| {
                    api.publish_revision(organization, project, id, self.key, current, publication)
                })?;
                (published, false, false)
            }
            Addressed::Create { reuse_identical } => {
                let (published, reused) = resend_once(|| {
                    api.create_definition(
                        organization,
                        project,
                        self.key,
                        publication,
                        *reuse_identical,
                    )
                })?;
                (published, !reused, reused)
            }
        };
        Ok(CloudPublished {
            definition: publication.definition.id,
            created,
            reused,
            revision: publication.revision.number,
            tree_digest: publication.revision.tree_digest,
            tree_reused,
        })
    }
}

/// The JSON `failure` of a Cloud failure and its exit status: 1 for a refusal.
pub(super) const fn cloud_failure(failure: &WorkflowDefinitionFailure) -> (&'static str, ExitCode) {
    match failure {
        WorkflowDefinitionFailure::Refused(_) => ("refused", ExitCode::GeneralFailure),
        WorkflowDefinitionFailure::UploadRejected { .. } => {
            ("upload_rejected", ExitCode::GeneralFailure)
        }
        WorkflowDefinitionFailure::Unauthenticated => {
            ("authentication_required", ExitCode::AuthenticationRequired)
        }
        WorkflowDefinitionFailure::Unreachable { .. }
        | WorkflowDefinitionFailure::RateLimited { .. } => ("unavailable", ExitCode::Unavailable),
        WorkflowDefinitionFailure::InvalidResponse { .. } => {
            ("invalid_response", ExitCode::GeneralFailure)
        }
    }
}

/// Where an invalid response was detected (REQ-CLOUDDEF-28, REQ-CLOUDDEF-76, REQ-CLOUDDEF-78):
/// the JSON `diagnostic` of the failure, or none for every other failure. It holds the slugs
/// and the status alone, never the error the failure retains.
pub(super) fn invalid_response_diagnostic(
    failure: &WorkflowDefinitionFailure,
) -> Option<InvalidResponseDiagnostic> {
    match failure {
        WorkflowDefinitionFailure::InvalidResponse(invalid) => Some(InvalidResponseDiagnostic {
            stage: invalid.stage().slug(),
            check: invalid.check().slug(),
            http_status: invalid.status(),
        }),
        _ => None,
    }
}

/// The stage and check an invalid response failed, with the status a check of the status
/// judged.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct InvalidResponseDiagnostic {
    stage: &'static str,
    check: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_status: Option<u16>,
}

impl InvalidResponseDiagnostic {
    /// Writes the stage, the check and the status as labelled lines under an error.
    pub(super) fn write(&self, out: &mut impl Write) -> io::Result<()> {
        writeln!(out, "stage: {}", self.stage)?;
        writeln!(out, "check: {}", self.check)?;
        if let Some(status) = self.http_status {
            writeln!(out, "http status: {status}")?;
        }
        Ok(())
    }
}

/// Writes what a publication to Cloud reached in `project`, or its failure, and returns its exit
/// status: `target` is the existing definition it was addressed to, none for a create.
fn write_cloud(
    project: &Project,
    target: Option<&str>,
    reached: &Result<CloudPublished, WorkflowDefinitionFailure>,
    json: bool,
) -> CommandResult {
    write_cloud_published(project, target, reached, json)
        .context("write workflow definition publish result")?;
    Ok(match reached {
        Ok(_) => ExitCode::Success,
        Err(failure) => cloud_failure(failure).1,
    })
}

fn write_cloud_published(
    project: &Project,
    target: Option<&str>,
    reached: &Result<CloudPublished, WorkflowDefinitionFailure>,
    json: bool,
) -> anyhow::Result<()> {
    let refusal = match reached {
        Err(WorkflowDefinitionFailure::Refused(refusal)) => Some(refusal),
        _ => None,
    };
    if json {
        let reached_ok = reached.as_ref().ok();
        let cloud = JsonCloud {
            organization_ref: &project.organization,
            project_id: &project.project,
            target,
            definition: reached_ok.map(|reached| reached.definition.as_str()),
            created: reached_ok.map(|reached| reached.created),
            reused: reached_ok.map(|reached| reached.reused),
            revision: reached_ok.map(|reached| reached.revision),
            tree_digest: reached_ok.map(|reached| reached.tree_digest.as_str()),
            tree_reused: reached_ok.map(|reached| reached.tree_reused),
            failure: reached
                .as_ref()
                .err()
                .map(|failure| cloud_failure(failure).0),
            status: refusal.map(|refusal| refusal.status),
            problem: refusal.map(|refusal| refusal.problem.as_str()),
            workflow: refusal.and_then(|refusal| refusal.workflow.as_ref()),
            diagnostic: reached.as_ref().err().and_then(invalid_response_diagnostic),
        };
        return write_json(
            &JsonCloudPublished {
                schema_version: 1,
                command: COMMAND_NAME,
                outcome: if cloud.failure.is_some() {
                    "cloud_failed"
                } else {
                    "published"
                },
                cloud,
            },
            "workflow definition publish",
        );
    }
    match reached {
        Ok(reached) => {
            let mut stdout = io::stdout().lock();
            writeln!(
                stdout,
                "✓ Published revision {} of Cloud definition {} in project {}.",
                reached.revision,
                display(&reached.definition),
                display(&project.project)
            )?;
            writeln!(stdout, "cloud definition: {}", display(&reached.definition))?;
            writeln!(stdout, "cloud created: {}", super::yes_no(reached.created))?;
            writeln!(
                stdout,
                "cloud definition reused: {}",
                super::yes_no(reached.reused)
            )?;
            writeln!(stdout, "cloud revision: {}", reached.revision)?;
            writeln!(stdout, "cloud tree: {}", display(&reached.tree_digest))?;
            writeln!(
                stdout,
                "cloud tree reused: {}",
                super::yes_no(reached.tree_reused)
            )?;
        }
        Err(failure) => {
            let mut stderr = io::stderr().lock();
            let publication = target.map_or_else(
                || "Cloud publication".to_owned(),
                |id| format!("Cloud publication to {}", display(id)),
            );
            match refusal {
                Some(refusal) => {
                    writeln!(
                        stderr,
                        "error: {publication} refused: {} (HTTP {})",
                        refusal.problem, refusal.status
                    )?;
                    if let Some(current) = refusal
                        .workflow
                        .as_ref()
                        .and_then(|detail| detail.current_revision)
                    {
                        writeln!(stderr, "cloud current revision: {current}")?;
                    }
                    if let Some(integration) = refusal
                        .workflow
                        .as_ref()
                        .and_then(|detail| detail.integration.as_deref())
                    {
                        writeln!(stderr, "integration: {}", display(integration))?;
                    }
                    if let Some(key) = refusal
                        .workflow
                        .as_ref()
                        .and_then(|detail| detail.binding_key.as_deref())
                    {
                        writeln!(stderr, "binding: {}", display(key))?;
                    }
                    // The loop the publication would close, in start order (REQ-CLOUDDEF-35).
                    if let Some(ids) = refusal
                        .workflow
                        .as_ref()
                        .and_then(|detail| detail.r#loop.as_deref())
                    {
                        let ids = ids.iter().map(|id| display(id)).collect::<Vec<_>>();
                        writeln!(stderr, "loop: {}", ids.join(" -> "))?;
                    }
                    if let Some(ids) = refusal
                        .workflow
                        .as_ref()
                        .and_then(|detail| detail.definition_ids.as_deref())
                    {
                        let ids = ids.iter().map(|id| display(id)).collect::<Vec<_>>();
                        writeln!(stderr, "cloud definitions: {}", ids.join(", "))?;
                    }
                }
                None => {
                    writeln!(
                        stderr,
                        "error: {publication} failed: {}",
                        cloud_failure(failure).0
                    )?;
                    if let Some(diagnostic) = invalid_response_diagnostic(failure) {
                        diagnostic.write(&mut stderr)?;
                    }
                }
            }
            let ambiguous =
                refusal.is_some_and(|refusal| refusal.problem == DEFINITION_REUSE_AMBIGUOUS);
            // The definition `--to` names is not found in the project, as after a delete: the
            // next attempt at the same target would be refused again, so the owner creates
            // another or names one (REQ-CLOUDDEF-14).
            let target_not_found = refusal.is_some_and(|refusal| refusal.problem == NOT_FOUND);
            match target {
                Some(_) if target_not_found => writeln!(
                    stderr,
                    "\nCloud does not hold that definition in the project. Publish again to create another Cloud definition, or to one that you choose:\n  useful workflow definition publish <DIR> --on project --new\n  useful workflow definition publish <DIR> --on project --to <DEFINITION>"
                )?,
                // Nothing was recorded, so the next attempt names the target again.
                Some(id) => writeln!(
                    stderr,
                    "\nResolve the error and publish again to the definition:\n  useful workflow definition publish <DIR> --on project --to {}",
                    display(id)
                )?,
                // Several identical definitions answered the reuse: the owner chooses one.
                None if ambiguous => writeln!(
                    stderr,
                    "\nSeveral Cloud definitions of the project are identical to this publication. Publish again to the one listed that you choose, or create another:\n  useful workflow definition publish <DIR> --on project --to <DEFINITION>\n  useful workflow definition publish <DIR> --on project --new"
                )?,
                None => writeln!(stderr, "\nResolve the error and publish again.")?,
            }
        }
    }
    Ok(())
}

fn write_human_published(published: &Published) -> anyhow::Result<()> {
    let record = &published.record;
    let revision = &published.revision;
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    writeln!(
        stdout,
        "✓ Published {} revision {}.",
        display(&record.name),
        revision.n
    )?;
    writeln!(stdout, "definition: {}", display(&record.id))?;
    writeln!(stdout, "name: {}", display(&record.name))?;
    writeln!(stdout, "created: {}", super::yes_no(published.created))?;
    writeln!(stdout, "revision: {}", revision.n)?;
    writeln!(stdout, "tree: {}", display(&revision.tree))?;
    writeln!(stdout, "bindings: {}", display(&revision.bindings))?;
    writeln!(stdout, "published at: {}", display(&revision.published_at))?;
    writeln!(stdout, "by: {}", display(&revision.by))?;
    Ok(())
}

fn published_report(published: &Published) -> JsonPublished<'_> {
    let record = &published.record;
    let revision = &published.revision;
    JsonPublished {
        schema_version: 1,
        command: COMMAND_NAME,
        outcome: "published",
        definition: JsonDefinition {
            id: &record.id,
            name: &record.name,
            enabled: record.enabled,
            current: record.current,
            created: published.created,
            path: published.path.to_string_lossy().into_owned(),
        },
        revision: JsonRevision {
            n: revision.n,
            tree: &revision.tree,
            bindings: &revision.bindings,
            published_at: &revision.published_at,
            by: &revision.by,
        },
    }
}

/// A publication under the home: the record and the revision it wrote (REQ-WFDEF-19).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonPublished<'a> {
    schema_version: u8,
    command: &'static str,
    outcome: &'static str,
    definition: JsonDefinition<'a>,
    revision: JsonRevision<'a>,
}

/// A publication to Cloud, which writes no record (REQ-CLOUDDEF-14).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonCloudPublished<'a> {
    schema_version: u8,
    command: &'static str,
    outcome: &'static str,
    cloud: JsonCloud<'a>,
}

/// The Cloud publication: the existing definition it was addressed to, the definition and
/// revision it reached with whether it was created, reused or published to and whether the tree
/// was reused (REQ-CLOUDDEF-22), or its failure with a refusal's status, problem slug and
/// `workflow` safe facts or an invalid response's diagnostic (REQ-CLOUDDEF-28).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonCloud<'a> {
    organization_ref: &'a str,
    project_id: &'a str,
    /// The existing definition `--to` or the root's name chose; absent when a create is sent,
    /// whether it creates a definition or reuses one.
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    definition: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<bool>,
    /// Whether the create answered the project's identical definition; present exactly when
    /// `created` is.
    #[serde(skip_serializing_if = "Option::is_none")]
    reused: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tree_digest: Option<&'a str>,
    /// Whether Cloud already held the tree sealed, so nothing was uploaded or sealed; present
    /// exactly when `created` is.
    #[serde(skip_serializing_if = "Option::is_none")]
    tree_reused: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    problem: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workflow: Option<&'a WorkflowProblemDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic: Option<InvalidResponseDiagnostic>,
}

#[derive(Serialize)]
struct JsonDefinition<'a> {
    id: &'a str,
    name: &'a str,
    enabled: bool,
    current: u64,
    created: bool,
    path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonRevision<'a> {
    n: u64,
    tree: &'a str,
    bindings: &'a str,
    published_at: &'a str,
    by: &'a str,
}
