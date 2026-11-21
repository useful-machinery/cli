//! `useful workflow definition show DEFINITION` (REQ-WFDEF-26, REQ-CLOUDDEF-15): a definition
//! under the home, read without a request, or else one of the project in effect
//! (REQ-CLOUDDEF-42).

use std::io::{self, Write};

use clap::Args;
use serde::Serialize;

use super::cloud_report;
use super::report::{display, display_members, write_json};
use super::target::{self, Found, InEffect, Leaf, Named, Options, Project};
use crate::cli::CommandResult;
use useful_api::WorkflowDefinition;
use useful_execution::{
    BindingValue, BindingsSnapshot, DefinitionError, ListedRun, RevisionRecord, RunState,
    StoredDefinition, WorkflowHome, list_runs, read_current_bindings,
};
use useful_human_auth::Deployment;

pub(super) const ABOUT: &str = "Show a workflow definition and its revisions";
const COMMAND_NAME: &str = "useful workflow definition show";
const REFUSED: &str = "Show refused.";
const TREE_ROOT_FILE: &str = "workflow.yaml";
/// The most revisions a Cloud definition's `show` reads, the API's page bound.
const SHOWN_REVISIONS: i32 = 100;

#[derive(Debug, Args)]
pub(super) struct Command {
    #[arg(value_name = target::DEFINITION, help = target::DEFINITION_HELP)]
    definition: Named,

    #[command(flatten)]
    in_effect: InEffect,

    #[command(flatten)]
    options: Options,
}

/// The record, whether each revision's tree copy is under the home, newest first, the
/// current revision's snapshot, and the definition's live runs in id order.
struct Shown {
    definition: StoredDefinition,
    retained: Vec<bool>,
    bindings: BindingsSnapshot,
    runs: Vec<ListedRun>,
}

impl Command {
    /// Finds the definition under the home and then in the project, and shows it.
    pub(super) fn execute(self) -> CommandResult {
        let json = self.options.json;
        let leaf = Leaf {
            name: "show",
            command: COMMAND_NAME,
            refused: REFUSED,
            json,
        };
        let found = target::find(&self.definition, self.in_effect, &self.options, leaf);
        match found {
            Ok(Found::Home { home, definition }) => super::finish(
                COMMAND_NAME,
                REFUSED,
                shown(&home, definition),
                json,
                |shown, json| {
                    if json {
                        write_json(&show_report(shown), "workflow definition")
                    } else {
                        write_human(shown)
                    }
                },
            ),
            Ok(Found::Project {
                deployment,
                project,
                definition,
            }) => show_cloud(&deployment, &self.options, &project, definition),
            Err(ended) => ended,
        }
    }
}

/// A Cloud definition with its current revision and the newest page of its revisions.
fn show_cloud(
    deployment: &Deployment,
    options: &Options,
    project: &Project,
    definition: WorkflowDefinition,
) -> CommandResult {
    let (organization, project_id, id) = (
        project.organization.as_str(),
        project.project.as_str(),
        definition.id.as_str(),
    );
    let read = super::with_api(deployment, options, |api| {
        let current = api.revision(organization, project_id, id, definition.current_revision)?;
        let (revisions, more) =
            api.revisions(organization, project_id, id, Some(SHOWN_REVISIONS), None)?;
        Ok((current, revisions, more.is_some()))
    })?;
    let scope = cloud_report::Scope {
        leaf: "show",
        organization: Some(organization),
        project: Some(project_id),
        json: options.json,
    };
    let shown = read.map(|(current, revisions, more)| cloud_report::Shown {
        definition,
        current,
        revisions,
        more,
    });
    cloud_report::finish(&scope, shown.as_ref(), |shown| {
        cloud_report::shown(&scope, shown)
    })
}

fn shown(home: &WorkflowHome, definition: StoredDefinition) -> Result<Shown, DefinitionError> {
    let id = definition.record.id.as_str();
    let bindings = read_current_bindings(&definition)?;
    let retained = definition
        .record
        .revisions
        .iter()
        .map(|revision| {
            home.tree_directory(&revision.tree)
                .is_some_and(|tree| tree.join(TREE_ROOT_FILE).is_file())
        })
        .collect();
    let runs = list_runs(home)
        .map_err(|error| DefinitionError::StoreUnavailable {
            path: home.runs_directory(id),
            operation: "list runs",
            source: io::Error::other(error),
        })?
        .runs
        .into_iter()
        .filter(|run| {
            run.record.definition.as_deref() == Some(id)
                && matches!(run.record.state, RunState::Running | RunState::Waiting)
        })
        .collect();
    Ok(Shown {
        definition,
        retained,
        bindings,
        runs,
    })
}

fn write_human(shown: &Shown) -> anyhow::Result<()> {
    let record = &shown.definition.record;
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "definition: {}", display(&record.id))?;
    writeln!(stdout, "name: {}", display(&record.name))?;
    writeln!(stdout, "enabled: {}", super::yes_no(record.enabled))?;
    writeln!(stdout, "current: {}", record.current)?;
    writeln!(
        stdout,
        "cloud id: {}",
        record
            .cloud_id
            .as_deref()
            .map_or_else(|| "none".to_owned(), display)
    )?;
    writeln!(stdout, "── revisions ──")?;
    for (revision, retained) in record.revisions.iter().zip(&shown.retained) {
        writeln!(
            stdout,
            "{}{} · tree {} · bindings {} · published at {} · by {} · tree copy {}",
            revision.n,
            if revision.n == record.current {
                " (current)"
            } else {
                ""
            },
            display(&revision.tree),
            display(&revision.bindings),
            display(&revision.published_at),
            display(&revision.by),
            if *retained { "present" } else { "missing" }
        )?;
    }
    writeln!(stdout, "── bindings ──")?;
    for (key, bound) in shown.bindings.bindings() {
        let value = match &bound.value {
            BindingValue::Text(value) => display(value),
            BindingValue::List(members) => display_members(members),
        };
        writeln!(
            stdout,
            "{}: {value} ({})",
            display(key),
            bound.kind.as_str()
        )?;
    }
    for (provider, group) in shown.bindings.integration_bindings() {
        for (name, bound) in group {
            writeln!(
                stdout,
                "{}.{}: {} ({})",
                display(provider.as_str()),
                display(name),
                display(&bound.value),
                display(&bound.kind)
            )?;
        }
    }
    writeln!(stdout, "── live runs ──")?;
    if shown.runs.is_empty() {
        writeln!(stdout, "No live runs.")?;
    }
    for run in shown.runs.iter().map(|run| live_run(run, record.current)) {
        writeln!(
            stdout,
            "{} · revision {} · {} · {}{}",
            display(run.id),
            run.revision,
            run.subject.map_or_else(|| "-".to_owned(), display),
            run.state,
            if run.drifted { " · drifted" } else { "" }
        )?;
    }
    Ok(())
}

/// `run` as `show` reports it, drifted when behind `current` (REQ-LOCALRUN-190).
fn live_run(run: &ListedRun, current: u64) -> JsonRun<'_> {
    let record = &run.record;
    JsonRun {
        id: &record.id,
        revision: record.revision.unwrap_or_default(),
        subject: record.subject.as_deref(),
        state: super::super::state_name(record.state),
        drifted: run.drifted(current),
    }
}

fn show_report(shown: &Shown) -> JsonShown<'_> {
    let definition = &shown.definition;
    let record = &definition.record;
    JsonShown {
        schema_version: 1,
        command: COMMAND_NAME,
        on: "local",
        definition: JsonDefinition {
            id: &record.id,
            name: &record.name,
            enabled: record.enabled,
            current: record.current,
            cloud_id: record.cloud_id.as_deref(),
            path: definition.path.to_string_lossy().into_owned(),
        },
        revisions: record
            .revisions
            .iter()
            .zip(&shown.retained)
            .map(|(revision, retained)| JsonRevision {
                revision,
                tree_retained: *retained,
            })
            .collect(),
        bindings: &shown.bindings,
        runs: shown
            .runs
            .iter()
            .map(|run| live_run(run, record.current))
            .collect(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonShown<'a> {
    schema_version: u8,
    command: &'static str,
    on: &'static str,
    definition: JsonDefinition<'a>,
    revisions: Vec<JsonRevision<'a>>,
    bindings: &'a BindingsSnapshot,
    runs: Vec<JsonRun<'a>>,
}

/// A live run of the definition: `id`, `revision`, `subject`, `state` and `drifted`.
#[derive(Serialize)]
struct JsonRun<'a> {
    id: &'a str,
    revision: u64,
    subject: Option<&'a str>,
    state: &'static str,
    drifted: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonDefinition<'a> {
    id: &'a str,
    name: &'a str,
    enabled: bool,
    current: u64,
    cloud_id: Option<&'a str>,
    path: String,
}

/// A revision as the record holds it (`n`, `tree`, `bindings`, `publishedAt`, `by`) and
/// whether its tree copy is present.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonRevision<'a> {
    #[serde(flatten)]
    revision: &'a RevisionRecord,
    tree_retained: bool,
}
