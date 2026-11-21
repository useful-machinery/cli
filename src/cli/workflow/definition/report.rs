//! Reports shared by the `useful workflow definition` leaves and the tree form of `useful
//! workflow validate`: an invalid tree exactly as `useful workflow validate DIR` prints it
//! (REQ-WFDEF-15) and a refused definition command (REQ-WFDEF-27).

use std::io::{self, Write};
use std::path::Path;

use anyhow::Context;
use serde::Serialize;

use useful_execution::{
    DefinitionError, RejectionLocation, TreeDiagnostic, TreeLocation, normalize_terminal_scalar,
};

pub(in crate::cli::workflow) fn display(value: &str) -> String {
    normalize_terminal_scalar(value.as_bytes())
}

/// A `members` value as `["a", "b"]`, each member normalized as [`display`] does.
pub(in crate::cli::workflow) fn display_members(members: &[String]) -> String {
    let members = members
        .iter()
        .map(|member| format!("\"{}\"", display(member)))
        .collect::<Vec<_>>();
    format!("[{}]", members.join(", "))
}

pub(in crate::cli::workflow) fn display_path(path: &Path) -> String {
    normalize_terminal_scalar(path.as_os_str().as_encoded_bytes())
}

pub(in crate::cli::workflow) fn write_json(
    report: &impl Serialize,
    what: &'static str,
) -> anyhow::Result<()> {
    super::super::super::write_pretty_json(report).with_context(|| format!("write {what}"))
}

#[derive(Serialize)]
pub(in crate::cli::workflow) struct JsonTree {
    pub(super) path: String,
}

impl JsonTree {
    pub(in crate::cli::workflow) fn new(directory: &Path) -> Self {
        Self {
            path: directory.to_string_lossy().into_owned(),
        }
    }
}

/// `outcome` `invalid`: every failure found in the tree, as `useful workflow validate DIR --json`
/// writes it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvalidReport<'a> {
    schema_version: u8,
    command: &'static str,
    tree: JsonTree,
    outcome: &'static str,
    diagnostics: Vec<JsonDiagnostic<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonDiagnostic<'a> {
    code: &'static str,
    location: &'a TreeLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    workflow_location: Option<RejectionLocation<'a>>,
}

fn invalid_report<'a>(
    command: &'static str,
    directory: &Path,
    diagnostics: &'a [TreeDiagnostic],
) -> InvalidReport<'a> {
    InvalidReport {
        schema_version: 1,
        command,
        tree: JsonTree::new(directory),
        outcome: "invalid",
        diagnostics: diagnostics
            .iter()
            .map(|diagnostic| JsonDiagnostic {
                code: diagnostic.code,
                location: &diagnostic.location,
                workflow_location: diagnostic.workflow_location(),
            })
            .collect(),
    }
}

fn write_human_invalid(directory: &Path, diagnostics: &[TreeDiagnostic]) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "✗ Workflow tree is invalid.")?;
    writeln!(stdout, "tree: {}", display_path(directory))?;
    for diagnostic in diagnostics {
        write!(
            stdout,
            "code: {}  location: {}",
            diagnostic.code, diagnostic.location
        )?;
        if let Some(location) = diagnostic.workflow_location() {
            write!(stdout, "; {location}")?;
        }
        writeln!(stdout)?;
    }
    writeln!(stdout, "No workflow steps were executed.")?;
    for remedy in diagnostics.iter().filter_map(TreeDiagnostic::remedy) {
        writeln!(stdout)?;
        writeln!(stdout, "{remedy}")?;
    }
    Ok(())
}

/// Writes the invalid-tree report of `command` in the form `json` selects.
pub(in crate::cli::workflow) fn write_invalid(
    command: &'static str,
    directory: &Path,
    diagnostics: &[TreeDiagnostic],
    json: bool,
) -> anyhow::Result<()> {
    if json {
        write_json(
            &invalid_report(command, directory, diagnostics),
            "workflow tree validation result",
        )
    } else {
        write_human_invalid(directory, diagnostics)
    }
}

/// `outcome` `refused`: the one stable code and what it concerns, never file contents.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RefusedReport<'a> {
    schema_version: u8,
    command: &'static str,
    outcome: &'static str,
    diagnostics: [RefusalDiagnostic<'a>; 1],
}

#[derive(Serialize)]
struct RefusalDiagnostic<'a> {
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    definition: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    definitions: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    integration: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
}

impl<'a> RefusalDiagnostic<'a> {
    fn new(error: &'a DefinitionError) -> Self {
        Self {
            code: error.code(),
            definition: error.id(),
            definitions: Some(error.ids()).filter(|ids| !ids.is_empty()),
            integration: error.integration(),
            binding: error.key(),
            path: error.path().map(|path| path.to_string_lossy().into_owned()),
        }
    }
}

fn refused_report<'a>(command: &'static str, error: &'a DefinitionError) -> RefusedReport<'a> {
    RefusedReport {
        schema_version: 1,
        command,
        outcome: "refused",
        diagnostics: [RefusalDiagnostic::new(error)],
    }
}

/// `✗ <summary>` then `code: <code>` and what it concerns on one line.
fn write_human_refused(summary: &str, error: &DefinitionError) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "✗ {summary}")?;
    write!(stdout, "code: {}", error.code())?;
    if let Some(id) = error.id() {
        write!(stdout, "  definition: {}", display(id))?;
    }
    if !error.ids().is_empty() {
        let ids = error.ids().iter().map(|id| display(id)).collect::<Vec<_>>();
        write!(stdout, "  definitions: {}", ids.join(", "))?;
    }
    if let Some(integration) = error.integration() {
        write!(stdout, "  integration: {}", display(integration))?;
    }
    if let Some(key) = error.key() {
        write!(stdout, "  binding: {}", display(key))?;
    }
    if let Some(path) = error.path() {
        write!(stdout, "  path: {}", display_path(path))?;
    }
    writeln!(stdout)?;
    Ok(())
}

/// Writes the refusal of `command` in the form `json` selects; `summary` heads the human
/// form, such as `Publish refused.`.
pub(super) fn write_refused(
    command: &'static str,
    summary: &str,
    error: &DefinitionError,
    json: bool,
) -> anyhow::Result<()> {
    if json {
        write_json(
            &refused_report(command, error),
            "workflow definition refusal",
        )
    } else {
        write_human_refused(summary, error)
    }
}

/// `outcome` `refused` with `definition_not_found`: what was named, the home the lookup looked
/// under, and whether it asked Cloud, in which project, or why not (REQ-CLOUDDEF-42).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NotFoundReport<'a> {
    schema_version: u8,
    command: &'static str,
    outcome: &'static str,
    diagnostics: [NotFoundDiagnostic<'a>; 1],
}

#[derive(Serialize)]
struct NotFoundDiagnostic<'a> {
    code: &'static str,
    definition: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    home: Option<String>,
    cloud: &'a super::target::Asked,
}

/// Writes that `command` found no definition `named` where `looked` says, in the form `json`
/// selects; `summary` heads the human form.
pub(super) fn write_not_found(
    command: &'static str,
    summary: &str,
    named: &str,
    looked: &super::target::Looked,
    json: bool,
) -> anyhow::Result<()> {
    if json {
        return write_json(
            &NotFoundReport {
                schema_version: 1,
                command,
                outcome: "refused",
                diagnostics: [NotFoundDiagnostic {
                    code: NOT_FOUND,
                    definition: named,
                    home: looked
                        .home
                        .as_ref()
                        .map(|home| home.to_string_lossy().into_owned()),
                    cloud: &looked.cloud,
                }],
            },
            "workflow definition refusal",
        );
    }
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "✗ {summary}")?;
    writeln!(stdout, "code: {NOT_FOUND}  definition: {}", display(named))?;
    if let Some(home) = &looked.home {
        writeln!(stdout, "home: {}", display_path(home))?;
    }
    match &looked.cloud {
        super::target::Asked::Asked(project) => writeln!(
            stdout,
            "project: {}  organization: {}",
            display(&project.project),
            display(&project.organization)
        )?,
        super::target::Asked::NotAsked(not_asked) => {
            writeln!(stdout, "Cloud was not asked: {}", not_asked.why())?;
        }
    }
    Ok(())
}

const NOT_FOUND: &str = "definition_not_found";

/// Writes that `command`, which acts on a Cloud definition alone, refused definition `id` under
/// the home at `path` with `definition_local` (REQ-CLOUDDEF-42), in the form `json` selects, as
/// [`write_refused`] writes a refusal; `summary` heads the human form.
pub(super) fn write_local(
    command: &'static str,
    summary: &str,
    id: &str,
    path: &Path,
    json: bool,
) -> anyhow::Result<()> {
    if json {
        return write_json(
            &RefusedReport {
                schema_version: 1,
                command,
                outcome: "refused",
                diagnostics: [RefusalDiagnostic {
                    code: LOCAL,
                    definition: Some(id),
                    definitions: None,
                    integration: None,
                    binding: None,
                    path: Some(path.to_string_lossy().into_owned()),
                }],
            },
            "workflow definition refusal",
        );
    }
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "✗ {summary}")?;
    writeln!(
        stdout,
        "code: {LOCAL}  definition: {}  path: {}",
        display(id),
        display_path(path)
    )?;
    writeln!(stdout)?;
    writeln!(
        stdout,
        "The definition is under the useful home, and {command} acts on a Cloud definition."
    )?;
    Ok(())
}

const LOCAL: &str = "definition_local";
