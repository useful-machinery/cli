use super::run;
use std::collections::BTreeSet;

#[path = "../support/migration.rs"]
mod migration;

#[test]
fn installed_command_tree_has_the_declared_paths_visibility_and_options() {
    const HIDDEN: [&str; 2] = ["workflow run deliver", "workflow run event"];
    let mut pending = vec![String::new()];
    let mut visible = BTreeSet::new();
    while let Some(path) = pending.pop() {
        let mut args: Vec<_> = path.split_whitespace().collect();
        args.push("--help");
        let output = run(&args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        let help = std::str::from_utf8(&output.stdout).unwrap();
        let options: BTreeSet<_> = help
            .lines()
            .flat_map(|line| {
                line.split_whitespace()
                    .take(2)
                    .filter_map(|word| word.trim_end_matches(',').strip_prefix("--"))
            })
            .collect();
        for &(option, retained) in migration::RETIRED_OPTIONS {
            assert!(
                !options.contains(option) || retained.contains(&path.as_str()),
                "{path} --{option}"
            );
        }
        if let Some((_, commands)) = help.split_once("\nCommands:\n") {
            for row in commands.lines().take_while(|row| row.starts_with("  ")) {
                let child = row.split_whitespace().next().unwrap();
                if child == "help" {
                    continue;
                }
                let full = format!("{path} {child}").trim_start().to_owned();
                assert!(visible.insert(full.clone()), "duplicate command {full}");
                pending.push(full);
            }
        }
    }
    let expected = include_str!("../fixtures/command-tree.txt")
        .lines()
        .filter(|path| !HIDDEN.contains(path))
        .map(str::to_owned)
        .collect();
    assert_eq!(visible, expected);
    for path in HIDDEN {
        let mut args: Vec<_> = path.split_whitespace().collect();
        args.push("--help");
        assert!(run(&args).status.success(), "{path}");
    }
}

#[test]
fn installed_cli_refuses_retired_command_spellings() {
    for heading in [
        "Earlier commands and their replacements",
        "Hidden earlier spellings",
    ] {
        let rows = migration::guide_rows(heading);
        assert!(!rows.is_empty());
        for row in rows {
            if row
                .replacements
                .as_ref()
                .is_some_and(|paths| paths.contains(&row.earlier))
            {
                continue;
            }
            let mut args: Vec<_> = row.earlier.split_whitespace().collect();
            args.push("--help");
            assert_eq!(run(&args).status.code(), Some(2), "{}", row.earlier);
        }
    }
}

#[path = "../support/scenarios.rs"]
mod fixtures;

#[test]
fn documented_scenario_arguments_reach_their_installed_leaf() {
    let inventory: BTreeSet<_> = include_str!("../fixtures/command-tree.txt")
        .lines()
        .collect();
    let directory = super::private_credential_directory();
    let checkout = directory.path().join("checkout");
    let starter = checkout.join(".useful/starter");
    std::fs::create_dir_all(&starter).unwrap();
    std::fs::write(starter.join("workflow.yaml"), "schemaVersion: 1\nsteps:\n  verify:\n    kind: cmd\n    command:\n      argv: [sh, -c, 'exit 0']\n").unwrap();
    let useful_home = directory.path().join("useful");
    let home = directory.path().to_str().unwrap();
    let credentials = directory.path().join("absent-credentials");
    // PATH holds the starter step's shell and nothing else: `/bin` holds Git on some hosts
    // and not on others, and a command that asks Git about this checkout exits differently
    // when Git answers.
    let tools = directory.path().join("tools");
    std::fs::create_dir(&tools).unwrap();
    std::os::unix::fs::symlink("/bin/sh", tools.join("sh")).unwrap();
    // Every command gets the same signed-out checkout. An insecure issuer is
    // refused locally, including by account signup, which initiates its own login.
    let refused = useful_test_support::RefusedPort::hold();
    let origin = format!("http://{}", refused.address());
    let environment = [
        ("HOME", home),
        ("PATH", tools.to_str().unwrap()),
        ("USEFUL_HOME", useful_home.to_str().unwrap()),
        ("USEFUL_CREDENTIALS_FILE", credentials.to_str().unwrap()),
        ("USEFUL_API_URL", origin.as_str()),
        ("USEFUL_AUTH_ISSUER", origin.as_str()),
        ("USEFUL_AUTH_CLIENT_ID", "fixture"),
        ("USEFUL_AUTH_AUDIENCE", "fixture"),
    ];
    let invoke = |args: &[&str]| super::run_with_env_in(args, &environment, &checkout);
    for scenario in fixtures::scenarios().unwrap() {
        for step in &scenario.steps {
            let mut args: Vec<&str> = step.iter().map(String::as_str).collect();
            let path = (1..=args.len())
                .map(|n| args[..n].join(" "))
                .take_while(|path| inventory.contains(path.as_str()))
                .last()
                .unwrap();
            let flag;
            if let Some(row) = fixtures::WAITS_ON_CLOUD
                .iter()
                .find(|row| row.command == path && row.required)
            {
                flag = format!("--{}", row.flag);
                let refused = invoke(&args);
                assert_eq!(
                    refused.status.code(),
                    Some(2),
                    "{}: {step:?}",
                    scenario.title
                );
                assert!(
                    String::from_utf8_lossy(&refused.stderr).contains(&flag),
                    "{}",
                    row.cloud_change
                );
                args.extend([&flag, row.value]);
            }
            if path == "account integration authorize" {
                // The documented interactive form requires confirmation on a pipe.
                let refused = invoke(&args);
                assert_eq!(refused.status.code(), Some(2));
                assert!(String::from_utf8_lossy(&refused.stderr).contains("--yes"));
                args.push("--yes");
            }
            let output = invoke(&args);
            let expected = match path.as_str() {
                "workflow run list" => 0,
                "runner show" | "runner sync" => 4,
                "workflow run create" if args.contains(&"--path") => 0,
                "workflow validate" => 0,
                "account signup"
                | "runner serve"
                | "workflow doctor"
                | "workflow definition publish"
                | "workflow run show"
                | "workflow run view"
                | "workflow run answer"
                | "workflow run approve"
                | "workflow run hand-back"
                | "workflow run pause"
                | "workflow run unpause"
                | "workflow run retry"
                | "workflow run upgrade"
                | "workflow run artifact list"
                | "workflow run artifact download"
                | "workflow run artifact validate"
                | "workflow run publication create"
                | "project webhook create"
                | "account integration connect" => 1,
                _ if args.contains(&"--api-key-file") => 1,
                _ => 3, // The command reached authentication with no saved sign-in.
            };
            assert_eq!(
                output.status.code(),
                Some(expected),
                "{}: {args:?}: {output:?}",
                scenario.title
            );
        }
    }
}
