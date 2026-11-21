//! `useful workflow definition enable` and `disable` (REQ-WFDEF-24): one command whose
//! target value the leaf supplies. A definition the home holds, named by its ID, has its
//! record's `enabled` set without a request; any other ID, or a name, names a Cloud definition of
//! the project in effect, whose automatic starts are turned on or off (REQ-CLOUDDEF-15).

use std::io::{self, Write};

use clap::Args;
use serde::Serialize;

use super::change::{self, Change};
use super::report::{display, write_json};
use super::target::{self, InEffect, Named, Options};
use crate::cli::CommandResult;
use useful_execution::{EnabledChange, set_enabled};

pub(super) const ENABLE_ABOUT: &str =
    "Turn on a Cloud workflow definition's automatic starts, or enable one under the useful home";
pub(super) const DISABLE_ABOUT: &str =
    "Turn off a Cloud workflow definition's automatic starts, or disable one under the useful home";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[arg(value_name = target::DEFINITION, help = target::DEFINITION_HELP)]
    definition: Named,

    #[command(flatten)]
    in_effect: InEffect,

    #[command(flatten)]
    options: Options,
}

/// What one of the two leaves sets and how it names itself.
struct Leaf {
    enabled: bool,
    change: Change<'static>,
    done: &'static str,
}

const ENABLE: Leaf = Leaf {
    enabled: true,
    change: Change::Enable,
    done: "Enabled",
};

const DISABLE: Leaf = Leaf {
    enabled: false,
    change: Change::Disable,
    done: "Disabled",
};

impl Command {
    pub(super) fn execute(self, enabled: bool) -> CommandResult {
        let leaf = if enabled { &ENABLE } else { &DISABLE };
        let json = self.options.json;
        let named = leaf.change.leaf(json);
        match target::held(&self.definition, named) {
            Ok(Some((home, definition))) => super::finish(
                named.command,
                named.refused,
                set_enabled(&home, &definition.record.id, leaf.enabled),
                json,
                |change, json| {
                    if json {
                        write_json(&enabled_report(leaf, change), "workflow definition state")
                    } else {
                        write_human(leaf, change)
                    }
                },
            ),
            Ok(None) => change::send(self.definition, self.in_effect, self.options, leaf.change),
            Err(ended) => ended,
        }
    }
}

fn write_human(leaf: &Leaf, change: &EnabledChange) -> anyhow::Result<()> {
    let record = &change.definition.record;
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    if change.changed {
        writeln!(
            stdout,
            "✓ {} definition {}.",
            leaf.done,
            display(&record.name)
        )?;
    } else {
        writeln!(
            stdout,
            "✓ Definition {} is already {}.",
            display(&record.name),
            leaf.change.outcome()
        )?;
    }
    writeln!(stdout, "definition: {}", display(&record.id))?;
    writeln!(stdout, "name: {}", display(&record.name))?;
    writeln!(stdout, "enabled: {}", super::yes_no(record.enabled))?;
    Ok(())
}

fn enabled_report<'a>(leaf: &Leaf, change: &'a EnabledChange) -> JsonEnabled<'a> {
    let record = &change.definition.record;
    JsonEnabled {
        schema_version: 1,
        command: leaf.change.leaf(true).command,
        outcome: leaf.change.outcome(),
        definition: JsonDefinition {
            id: &record.id,
            name: &record.name,
            enabled: record.enabled,
            current: record.current,
            changed: change.changed,
            path: change.definition.path.to_string_lossy().into_owned(),
        },
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonEnabled<'a> {
    schema_version: u8,
    command: &'static str,
    outcome: &'static str,
    definition: JsonDefinition<'a>,
}

#[derive(Serialize)]
struct JsonDefinition<'a> {
    id: &'a str,
    name: &'a str,
    enabled: bool,
    current: u64,
    changed: bool,
    path: String,
}
