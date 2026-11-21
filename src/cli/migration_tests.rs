//! The migration guide read against the real tree: no earlier path it names still parses,
//! every replacement it names is a visible command, and no command takes a retired option.
use std::collections::{BTreeMap, BTreeSet};

use clap::CommandFactory;

use super::tests::customer_command_paths;
use super::{Cli, parse};

#[path = "../../tests/support/migration.rs"]
mod migration;
use migration::{RETIRED_OPTIONS, guide_rows};

/// The node of the tree at `path`, the root for the empty path.
fn node<'a>(root: &'a clap::Command, path: &str) -> &'a clap::Command {
    path.split_whitespace().fold(root, |node, token| {
        node.find_subcommand(token)
            .unwrap_or_else(|| panic!("{path:?} is a path of the tree"))
    })
}

/// Whether `path` is a command of the tree, not a group, and, when `visible`, one with no
/// hidden step on its way.
fn is_command(root: &clap::Command, path: &str, visible: bool) -> bool {
    let mut node = root;
    for token in path.split_whitespace() {
        match node.find_subcommand(token) {
            Some(child) if !(visible && child.is_hide_set()) => node = child,
            _ => return false,
        }
    }
    !node.has_subcommands()
}

// INV-CLI-21
#[test]
fn the_migration_guide_names_only_gone_paths_and_visible_replacements() {
    let earlier = guide_rows("Earlier commands and their replacements");
    let hidden = guide_rows("Hidden earlier spellings");
    assert_eq!((earlier.len(), hidden.len()), (190, 19));

    let paths: BTreeSet<String> = customer_command_paths().into_iter().collect();
    let root = Cli::command();
    let mut seen = BTreeSet::new();
    for row in earlier.iter().chain(&hidden) {
        assert!(
            seen.insert(row.earlier.as_str()),
            "{:?} is one row of the guide",
            row.earlier
        );
        let replacements = row.replacements.as_deref().unwrap_or_default();
        // A command that keeps its path may be hidden now, as the runner's `workflow run
        // event` is; the guide sends a person to no other hidden command.
        for replacement in replacements {
            assert!(
                is_command(&root, replacement, *replacement != row.earlier),
                "replacement {replacement:?} of {:?} is a visible command",
                row.earlier
            );
        }
        if replacements.contains(&row.earlier) {
            assert!(
                paths.contains(&row.earlier),
                "{:?} keeps its path",
                row.earlier
            );
            continue;
        }
        assert!(
            !paths.contains(&row.earlier),
            "{:?} is gone from the tree",
            row.earlier
        );
        let arguments = std::iter::once("useful").chain(row.earlier.split_whitespace());
        let error = parse(arguments).err().unwrap_or_else(|| {
            panic!("{:?} no longer parses", row.earlier);
        });
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::InvalidSubcommand,
            "{:?} is an unknown subcommand",
            row.earlier
        );
    }
}

// INV-CLI-21
#[test]
fn no_command_takes_a_retired_option_spelling() {
    let expected: BTreeMap<&str, BTreeSet<&str>> = RETIRED_OPTIONS
        .iter()
        .map(|(spelling, paths)| (*spelling, paths.iter().copied().collect()))
        .collect();
    let root = Cli::command();
    let mut actual: BTreeMap<&str, BTreeSet<&str>> = expected
        .keys()
        .map(|spelling| (*spelling, BTreeSet::new()))
        .collect();
    let paths = customer_command_paths();
    for path in std::iter::once("").chain(paths.iter().map(String::as_str)) {
        for argument in node(&root, path).get_arguments() {
            let spellings = argument
                .get_long()
                .into_iter()
                .chain(argument.get_all_aliases().unwrap_or_default());
            for spelling in spellings {
                if let Some(holders) = actual.get_mut(spelling) {
                    holders.insert(path);
                }
            }
        }
    }
    assert_eq!(actual, expected);
}
