//! `useful workflow definition archive`, `unarchive`, `delete` and `update DEFINITION --run-as
//! SERVICE`, and `enable` and `disable` of a Cloud definition: each a keyed change to, or the
//! delete of, a definition of the project in effect through the public API, with the CLI's session
//! handling and each refusal's problem type. The definition is named by its ID or its name, and an
//! ID the home holds is refused with `definition_local`, except by `enable` and `disable`, which
//! act on such a definition themselves.

use std::io::{self, Write};

use anyhow::Context as _;
use clap::Args;
use serde::Serialize;

use super::cloud_report::{self as report, Scope};
use super::report::display;
use super::target::{self, InEffect, Leaf, Named, Options, Project};
use super::{resend_once, with_api};
use crate::cli::org::member::{self, Resolution, Unresolved};
use crate::cli::{CommandResult, ConfirmationArgs};
use crate::exit_code::ExitCode;
use useful_api::{WorkflowDefinition, WorkflowDefinitionApi, WorkflowDefinitionFailure};
use useful_human_auth::Deployment;

pub(super) const ARCHIVE_ABOUT: &str =
    "Archive a Cloud workflow definition and turn off its automatic starts";
pub(super) const DELETE_ABOUT: &str = "Delete an archived Cloud workflow definition";
pub(super) const UNARCHIVE_ABOUT: &str = "Restore an archived Cloud workflow definition";
pub(super) const UPDATE_ABOUT: &str =
    "Set the service principal a Cloud workflow definition's automatic starts run as";
const RUN_AS_HELP: &str =
    "Service principal the automatic starts run as, by ID or by its display name";

/// A Cloud definition a leaf changes, in the project in effect.
#[derive(Debug, Args)]
pub(super) struct Target {
    #[arg(value_name = target::DEFINITION, help = target::DEFINITION_HELP)]
    definition: Named,
    #[command(flatten)]
    in_effect: InEffect,
    #[command(flatten)]
    options: Options,
}

/// The archived Cloud definition `delete` deletes, with its confirmation.
#[derive(Debug, Args)]
pub(super) struct Delete {
    #[command(flatten)]
    target: Target,
    #[command(flatten)]
    confirmation: ConfirmationArgs,
}

#[derive(Debug, Args)]
pub(super) struct Update {
    #[arg(value_name = target::DEFINITION, help = target::DEFINITION_HELP)]
    definition: Named,
    #[arg(long, value_name = "SERVICE", help = RUN_AS_HELP)]
    run_as: String,
    #[command(flatten)]
    in_effect: InEffect,
    #[command(flatten)]
    options: Options,
}

/// A keyed change one leaf makes to a definition's settings.
#[derive(Clone, Copy)]
pub(super) enum Change<'a> {
    Enable,
    Disable,
    Archive,
    Unarchive,
    Principal(&'a str),
}

impl Change<'_> {
    /// The leaf that makes the change, with whether `--json` was given.
    pub(super) const fn leaf(self, json: bool) -> Leaf {
        let (name, command, refused) = match self {
            Self::Enable => (
                "enable",
                "useful workflow definition enable",
                "Enable refused.",
            ),
            Self::Disable => (
                "disable",
                "useful workflow definition disable",
                "Disable refused.",
            ),
            Self::Archive => (
                "archive",
                "useful workflow definition archive",
                "Archive refused.",
            ),
            Self::Unarchive => (
                "unarchive",
                "useful workflow definition unarchive",
                "Unarchive refused.",
            ),
            Self::Principal(_) => (
                "update",
                "useful workflow definition update",
                "Update refused.",
            ),
        };
        Leaf {
            name,
            command,
            refused,
            json,
        }
    }

    pub(super) const fn outcome(self) -> &'static str {
        match self {
            Self::Enable => "enabled",
            Self::Disable => "disabled",
            Self::Archive => "archived",
            Self::Unarchive => "unarchived",
            Self::Principal(_) => "principal_set",
        }
    }

    fn send(
        self,
        api: &WorkflowDefinitionApi<'_>,
        project: &Project,
        id: &str,
        key: &str,
    ) -> Result<WorkflowDefinition, WorkflowDefinitionFailure> {
        let (organization, project) = (project.organization.as_str(), project.project.as_str());
        match self {
            Self::Enable => api.enable(organization, project, id, key),
            Self::Disable => api.disable(organization, project, id, key),
            Self::Archive => api.archive(organization, project, id, key),
            Self::Unarchive => api.unarchive(organization, project, id, key),
            Self::Principal(principal) => {
                api.set_execution_principal(organization, project, id, key, principal)
            }
        }
    }
}

impl Target {
    /// Archives or unarchives the Cloud definition the leaf names.
    pub(super) fn execute(self, change: Change<'_>) -> CommandResult {
        if let Err(ended) = target::cloud_only(&self.definition, change.leaf(self.options.json)) {
            return ended;
        }
        send(self.definition, self.in_effect, self.options, change)
    }
}

impl Delete {
    /// Deletes the archived Cloud definition the leaf names under one fresh key, sent again
    /// once when the response is lost or is a transient problem.
    pub(super) fn execute(self) -> CommandResult {
        let Target {
            definition,
            in_effect,
            options,
        } = self.target;
        let leaf = Leaf {
            name: "delete",
            command: "useful workflow definition delete",
            refused: "Delete refused.",
            json: options.json,
        };
        if let Err(ended) = target::cloud_only(&definition, leaf) {
            return ended;
        }
        target::in_project(
            definition,
            in_effect,
            options,
            leaf,
            |deployment, options, project, id| {
                let deleted = keyed(deployment, options, |api, key| {
                    api.delete(&project.organization, &project.project, id, key)
                })?;
                report::finish_delete(&Scope::of(leaf, Some(project)), id, deleted.as_ref())
            },
        )
    }
}

impl Update {
    /// Sets the principal the definition's automatic starts run as: `--run-as` resolved in the
    /// organization's member directory unless it is a principal ID.
    pub(super) fn execute(self) -> CommandResult {
        let leaf = Change::Principal(&self.run_as).leaf(self.options.json);
        if let Err(ended) = target::cloud_only(&self.definition, leaf) {
            return ended;
        }
        let run_as = self.run_as.as_str();
        target::in_project(
            self.definition,
            self.in_effect,
            self.options,
            leaf,
            |deployment, options, project, id| match service(
                run_as, deployment, options, project, leaf,
            )? {
                Ok(principal) => apply(
                    deployment,
                    options,
                    project,
                    id,
                    Change::Principal(&principal),
                ),
                Err(ended) => ended,
            },
        )
    }
}

/// Makes `change` to the Cloud definition `named` names in the project in effect.
pub(super) fn send(
    named: Named,
    in_effect: InEffect,
    options: Options,
    change: Change<'_>,
) -> CommandResult {
    let leaf = change.leaf(options.json);
    target::in_project(
        named,
        in_effect,
        options,
        leaf,
        |deployment, options, project, id| apply(deployment, options, project, id, change),
    )
}

/// Applies `change` to definition `id` under one fresh key, sent again once when the response is
/// lost or is a transient problem.
fn apply(
    deployment: &Deployment,
    options: &Options,
    project: &Project,
    id: &str,
    change: Change<'_>,
) -> CommandResult {
    let changed = keyed(deployment, options, |api, key| {
        change.send(api, project, id, key)
    })?;
    let scope = Scope::of(change.leaf(options.json), Some(project));
    report::finish(&scope, changed.as_ref(), |definition| {
        report::changed(&scope, change.outcome(), definition)
    })
}

/// Sends `send` under one fresh `Idempotency-Key`, and once more under that key when Cloud
/// does not answer or answers with a transient problem.
fn keyed<T>(
    deployment: &Deployment,
    options: &Options,
    send: impl Fn(&WorkflowDefinitionApi<'_>, &str) -> Result<T, WorkflowDefinitionFailure>,
) -> anyhow::Result<Result<T, WorkflowDefinitionFailure>> {
    let key = useful_support::generate_idempotency_key()
        .context("generate Cloud workflow definition request identity")?;
    with_api(deployment, options, |api| resend_once(|| send(api, &key)))
}

/// The principal ID `run_as` names: a `prn_` ID as given, and otherwise the one service
/// principal of the organization with that display name, read from its member directory; or
/// the result that ends the leaf before any change is sent.
fn service(
    run_as: &str,
    deployment: &Deployment,
    options: &Options,
    project: &Project,
    leaf: Leaf,
) -> anyhow::Result<Result<String, CommandResult>> {
    if useful_support::valid_typed_id(run_as, "prn_") {
        return Ok(Ok(run_as.to_owned()));
    }
    let scope = Scope::of(leaf, Some(project));
    Ok(
        match member::service_principal(
            deployment,
            options.http.transport_policy(),
            &options.authentication,
            &project.organization,
            run_as,
        )? {
            Resolution::Member(principal) => Ok(principal),
            Resolution::Unresolved(Unresolved::NotFound) => Err(no_service(&scope, run_as)),
            Resolution::Unresolved(Unresolved::Common(failure)) => Err(report::write_failure(
                &scope,
                &target::organization_failure(&failure),
            )
            .map_err(Into::into)),
            Resolution::Ambiguous(refusal) => Err(Err(refusal)),
        },
    )
}

/// No service principal of the organization has the display name `name`: `not_found`, exit 1.
fn no_service(scope: &Scope<'_>, name: &str) -> CommandResult {
    let written = if scope.json {
        scope.write("not_found", NoService { service: name })
    } else {
        writeln!(
            io::stderr().lock(),
            "error: no service principal of organization {} has the display name {}\n\n\
             Name the service principal by its ID, or check its name with useful org member list.",
            display(scope.organization.unwrap_or_default()),
            display(name)
        )
        .map_err(Into::into)
    };
    written.context("write useful workflow definition update result")?;
    Ok(ExitCode::GeneralFailure)
}

#[derive(Serialize)]
struct NoService<'a> {
    service: &'a str,
}
