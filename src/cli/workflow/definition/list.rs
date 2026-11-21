//! `useful workflow definition list [--on local|project]` (REQ-WFDEF-25): the definitions under
//! the home and then those of the project in effect, read to the last page, each saying where
//! it lives.

use std::io::{self, Write};

use anyhow::Context as _;
use clap::Args;
use serde::Serialize;

use super::cloud_report;
use super::report::{display, write_json, write_refused};
use super::target::{self, Answer, Asked, InEffect, Leaf, NotAsked, On, Options};
use crate::cli::CommandResult;
use crate::exit_code::ExitCode;
use useful_api::WorkflowDefinition;
use useful_execution::{StoredDefinition, WorkflowHome, list_definitions};
use useful_human_auth::Deployment;

pub(super) const ABOUT: &str = "List workflow definitions under the useful home and in the project";
const COMMAND_NAME: &str = "useful workflow definition list";
const COMMAND_PATH: &[&str] = &["workflow", "definition", "list"];
const REFUSED: &str = "List refused.";
const DEPLOYMENT_CONTEXT: &str = "configure Useful Machinery workflow definitions";
const ON_HELP: &str = "List only the definitions of one place (default: both)";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[arg(long, value_enum, value_name = target::PLACE, help = ON_HELP)]
    on: Option<On>,

    #[command(flatten)]
    in_effect: InEffect,

    #[command(flatten)]
    options: Options,
}

impl Command {
    /// Reads the home, unless `--on project`, and then, unless `--on local`, the project.
    pub(super) fn execute(self) -> CommandResult {
        let json = self.options.json;
        let local = if self.on == Some(On::Project) {
            Vec::new()
        } else {
            match WorkflowHome::from_environment().and_then(|home| list_definitions(&home)) {
                Ok(definitions) => definitions,
                Err(error) => {
                    write_refused(COMMAND_NAME, REFUSED, &error, json)
                        .with_context(|| format!("write {COMMAND_NAME} result"))?;
                    return Ok(ExitCode::GeneralFailure);
                }
            }
        };
        if self.on == Some(On::Local) {
            return write(&local, &[], &Asked::NotAsked(NotAsked::LocalOnly), json);
        }
        crate::cli::execute_deployment_command(
            Some((self, local)),
            COMMAND_PATH,
            DEPLOYMENT_CONTEXT,
            |(command, local), deployment| command.with_project(deployment, &local),
        )
    }

    /// Reads every page of the project's definitions and writes them after `local`. With no
    /// `--on`, a project Cloud cannot be asked in leaves the home's alone, said on standard
    /// error; with `--on project` it ends the command as a Cloud leaf ends.
    fn with_project(self, deployment: &Deployment, local: &[StoredDefinition]) -> CommandResult {
        let json = self.options.json;
        let leaf = Leaf {
            name: "list",
            command: COMMAND_NAME,
            refused: REFUSED,
            json,
        };
        let (project, not_asked) = match target::reach(self.in_effect, &self.options, deployment)? {
            Ok(project) => match target::every_definition(deployment, &self.options, &project)? {
                Answer::Read(definitions) => {
                    return write(local, &definitions, &Asked::Asked(project), json);
                }
                Answer::NotAsked(not_asked) => (Some(project), not_asked),
                Answer::Failed(failure) => return target::failed(leaf, Some(&project), &failure),
            },
            Err(not_asked) => (None, not_asked),
        };
        if self.on == Some(On::Project) {
            return target::failed(leaf, project.as_ref(), &not_asked.failure()?);
        }
        writeln!(
            io::stderr().lock(),
            "! Cloud was not asked: {}",
            not_asked.why()
        )
        .context("write workflow definition list note")?;
        write(local, &[], &Asked::NotAsked(not_asked), json)
    }
}

/// Writes the home's definitions and then the project's, exit 0.
fn write(
    local: &[StoredDefinition],
    cloud: &[WorkflowDefinition],
    asked: &Asked,
    json: bool,
) -> CommandResult {
    if json {
        write_json(
            &list_report(local, cloud, asked),
            "workflow definition list",
        )
    } else {
        write_human(local, cloud)
    }
    .with_context(|| format!("write {COMMAND_NAME} result"))?;
    Ok(ExitCode::Success)
}

fn published_at(definition: &StoredDefinition) -> Option<&str> {
    definition
        .record
        .current_revision()
        .map(|revision| revision.published_at.as_str())
}

/// One line per definition, after where it lives; `No workflow definitions.` for none.
fn write_human(local: &[StoredDefinition], cloud: &[WorkflowDefinition]) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    if local.is_empty() && cloud.is_empty() {
        writeln!(stdout, "No workflow definitions.")?;
        return Ok(());
    }
    for definition in local {
        let record = &definition.record;
        let count = record.revisions.len();
        write!(
            stdout,
            "local · {} · {} · {} · current {} · {} revision{}",
            display(&record.id),
            display(&record.name),
            if record.enabled {
                "enabled"
            } else {
                "disabled"
            },
            record.current,
            count,
            if count == 1 { "" } else { "s" }
        )?;
        if let Some(published_at) = published_at(definition) {
            write!(stdout, " · published at {}", display(published_at))?;
        }
        writeln!(stdout)?;
    }
    for definition in cloud {
        cloud_report::write_listed(&mut stdout, "project", definition)?;
    }
    Ok(())
}

fn list_report<'a>(
    local: &'a [StoredDefinition],
    cloud: &'a [WorkflowDefinition],
    asked: &'a Asked,
) -> JsonList<'a> {
    let local = local.iter().map(|definition| {
        Row::Local(Placed {
            on: "local",
            row: JsonListed {
                id: &definition.record.id,
                name: &definition.record.name,
                enabled: definition.record.enabled,
                current: definition.record.current,
                revisions: definition.record.revisions.len(),
                published_at: published_at(definition),
                path: definition.path.to_string_lossy().into_owned(),
            },
        })
    });
    let cloud = cloud.iter().map(|definition| {
        Row::Project(Placed {
            on: "project",
            row: definition,
        })
    });
    JsonList {
        schema_version: 1,
        command: COMMAND_NAME,
        definitions: local.chain(cloud).collect(),
        cloud: asked,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonList<'a> {
    schema_version: u8,
    command: &'static str,
    definitions: Vec<Row<'a>>,
    cloud: &'a Asked,
}

/// A listed definition: one under the home as the home's record says, or one of the project
/// as Cloud returned it.
#[derive(Serialize)]
#[serde(untagged)]
enum Row<'a> {
    Local(Placed<JsonListed<'a>>),
    Project(Placed<&'a WorkflowDefinition>),
}

/// A row and where it lives, `on`.
#[derive(Serialize)]
struct Placed<B: Serialize> {
    on: &'static str,
    #[serde(flatten)]
    row: B,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonListed<'a> {
    id: &'a str,
    name: &'a str,
    enabled: bool,
    current: u64,
    revisions: usize,
    published_at: Option<&'a str>,
    path: String,
}
