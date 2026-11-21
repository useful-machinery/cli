//! The design export's scenarios, each under its title with its steps in the export's order
//! as the export writes them, parsed against the real tree, so a step that stops parsing fails
//! here. The commands that still take a flag the export does not write, because what would
//! make it unnecessary waits on Cloud, are one table.
use std::collections::BTreeSet;

use clap::CommandFactory;
use clap::error::ErrorKind;

use super::{Cli, parse};

#[path = "../../tests/support/scenarios.rs"]
mod fixtures;
use fixtures::{WAITS_ON_CLOUD, scenarios};

/// The command path a step's arguments name, without the program name.
fn command_path(root: &clap::Command, words: &[String]) -> String {
    let mut node = root;
    let mut path = Vec::new();
    for word in words.iter().skip(1) {
        match node.find_subcommand(word) {
            Some(child) => {
                node = child;
                path.push(word.as_str());
            }
            None => break,
        }
    }
    path.join(" ")
}

// INV-CLI-21, INV-CLI-20, REQ-MEMBER-48, REQ-MEMBER-50
#[test]
fn every_scenario_step_parses_against_the_command_tree() {
    let scenarios = scenarios().expect("scenario fixture");
    assert_eq!(scenarios.len(), 13);
    let steps = || scenarios.iter().flat_map(|scenario| scenario.steps.iter());
    assert_eq!(steps().count(), 68);
    assert_eq!(steps().collect::<BTreeSet<_>>().len(), 62);

    let root = Cli::command();
    for scenario in &scenarios {
        for step in &scenario.steps {
            let mut words = vec![String::from("useful")];
            words.extend_from_slice(step);
            let path = command_path(&root, &words);
            if let Some(row) = WAITS_ON_CLOUD
                .iter()
                .find(|row| row.required && row.command == path)
            {
                let error = parse(&words).expect_err("documented deferred lookup flag");
                assert_eq!(
                    error.kind(),
                    ErrorKind::MissingRequiredArgument,
                    "{}: {step:?}",
                    scenario.title
                );
                words.extend([format!("--{}", row.flag), row.value.to_owned()]);
            }
            if let Err(error) = parse(&words) {
                panic!("{}: {words:?} does not parse: {error}", scenario.title);
            }
        }
    }

    for row in WAITS_ON_CLOUD {
        let command = row.command.split_whitespace().fold(&root, |node, token| {
            node.find_subcommand(token)
                .unwrap_or_else(|| panic!("{} is a command", row.command))
        });
        let option = command
            .get_arguments()
            .find(|argument| argument.get_long() == Some(row.flag))
            .unwrap_or_else(|| panic!("{} has --{}", row.command, row.flag));
        assert_eq!(
            option.is_required_set(),
            row.required,
            "{} --{}, waiting on {}",
            row.command,
            row.flag,
            row.cloud_change
        );
    }
}
