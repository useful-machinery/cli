//! Structural CLI grammar conformance. Paths, not rendered help, identify violations.
use std::collections::{BTreeMap, BTreeSet};

use clap::{Arg, ArgAction, Command, CommandFactory};

use super::Cli;

const LEAVES: &str = "accept add answer approve authorize archive cancel connect create credentials deauthorize decline delete deliver disable disconnect doctor download drain enable end event hand-back handover interrupt issue leave link list login logout pause propose prune publish reconnect reference release remove replay restore resume retry revoke rotate schema seal serve show signup sync test unarchive unpause update upgrade upload validate version view watch";
const GROUPS: &str = "account artifact audit credential definition delegation delivery event identity input input-set integration invitation join-key key linear member org pool project publication record repository run runner secret service team evaluation webhook workflow";
const COMMON: [&str; 3] = ["json", "api-key-file", "allow-insecure-http"];
// These leaves have no limit/cursor contract; see cli/docs/output-style.md.
const UNPAGINATED_LISTS: [&str; 4] = [
    "org integration list",
    "account integration list",
    "runner join-key list",
    "workflow definition list",
];
// These destructive leaves' own confirmation refuses a missing --yes with the statement the
// leaf makes before it acts, which clap's refusal of a required argument cannot carry;
// destructive_leaves_require_confirmation_but_runner_modes_do_not pins that refusal.
const SELF_CONFIRMING: [&str; 1] = ["account integration disconnect"];
// These destructive leaves take no --yes at all: `project webhook secret revoke` ends only the
// overlap of a secret a rotation already replaced, so the subscription keeps a working secret
// and the tree writes the leaf without a confirmation.
const UNCONFIRMED: [&str; 1] = ["project webhook secret revoke"];

// These identities are backed by shared Args or identifier argument types in cli/src/cli.rs
// and cli/src/cli/entity.rs. A long spelling alone is never a help identity.
fn semantic_class(path: &str, long: &str) -> Option<String> {
    let shared = match long {
        // An upgrade's Text input overrides one carried over from the run, so it is not
        // the required value `--input-text` supplies elsewhere.
        "input-text" if path == "workflow run upgrade" => "input-text:override",
        // The connection a project's repository is bound through, GitHub's or GitLab's alone,
        // found when omitted (`org/connection/reach.rs`).
        "connection" if matches!(path, "project create" | "project update") => {
            "connection:repository"
        }
        // The runner key `runner join-key issue` writes is no API key: its destination is the
        // same `PATH|-`, and its help names the key it holds.
        "key-file" if path == "runner join-key issue" => "key-file:runner-key",
        // A runner a single-runner key is issued for may be a name no runner has yet, which
        // the issue registers.
        "runner" if path == "runner join-key issue" => "runner:registering",
        "api-key-file"
        | "key-file"
        | "allow-insecure-http"
        // The connection a `useful org integration` leaf acts on (`org/connection/target.rs`).
        | "connection"
        | "cursor"
        | "org"
        | "project-id"
        | "repository-id"
        | "timeout"
        | "yes"
        | "input-text-file"
        | "input-json"
        | "input-json-file"
        | "input-file"
        | "input-attachment"
        | "input-attachments-empty"
        | "agent-profiles"
        // A runner by ID or exact name, at each grant leaf that takes one and at `workflow
        // doctor`.
        | "runner" => long,
        // Only these paths flatten PaginationArgs. Other options named --limit
        // do not acquire pagination semantics just by sharing the spelling.
        "limit" => match path {
            "org audit list" | "org integration team list" | "org integration team show" => {
                "limit:100"
            }
            "org integration repository list"
            | "account delegation list"
            | "account identity list"
            | "account invitation list"
            | "account service key list"
            | "org list"
            | "org invitation list"
            | "org member list"
            | "org member event list"
            | "project list"
            | "runner pool list"
            | "runner credential list"
            | "runner list"
            | "workflow run artifact list"
            | "workflow run publication list" => "limit:200",
            _ => return None,
        },
        // The project in effect (`context::ProjectArgs`), at `account show`, `workflow doctor`,
        // `workflow input-set create`, `workflow run create`, `workflow run list`, the
        // `workflow definition` leaves and every `useful project` leaf that reads it.
        "project"
            if matches!(
                path,
                "account show"
                    | "workflow doctor"
                    | "workflow input-set create"
                    | "workflow run create"
                    | "workflow run list"
            )
                || path.starts_with("workflow definition ")
                || path.starts_with("project ") =>
        {
            "project:in-effect"
        }
        "project" => return None,
        // `run upgrade` replaces one input of the successor's current revision, not a
        // required input of a new run.
        "input-text" => match path {
            "workflow run upgrade" => "input-text:upgrade",
            _ => "input-text",
        },
        "json" => {
            // JsonArgs<F> is parameterized by output family; deletion cancellation
            // uses StreamingJson rather than DeletionJson.
            let family = if matches!(
                path,
                "account login"
                    | "account integration connect"
                    | "account integration reconnect"
                    | "account identity link"
                    | "account restore"
                    | "org integration connect"
                    | "org integration reconnect"
                    | "org restore"
            ) {
                "streaming-events"
            } else if path.starts_with("org integration ") {
                "org-connection"
            } else if matches!(path, "account logout" | "account show") {
                "sign-in"
            } else if path.starts_with("account identity ") {
                "identity"
            } else if path.starts_with("account integration ") {
                "grant"
            } else if path.starts_with("org invitation ") || path.starts_with("account invitation ")
            {
                "invitation"
            } else if path.starts_with("account service ") {
                "service-principal"
            } else if path.starts_with("account delegation ") {
                "delegation"
            } else if matches!(path, "account delete" | "org delete") {
                "deletion"
            } else {
                path.split(' ').next().unwrap_or("")
            };
            return Some(format!("json:{family}"));
        }
        _ => return None,
    };
    Some(shared.to_owned())
}

fn value_shape(arg: &Arg) -> String {
    if matches!(
        arg.get_action(),
        ArgAction::SetTrue
            | ArgAction::SetFalse
            | ArgAction::Count
            | ArgAction::Help
            | ArgAction::Version
    ) {
        return "flag".to_owned();
    }
    // clap uses the ID verbatim when no value name is supplied. The value
    // count is part of the shape even when the printed names are unchanged.
    let names = arg.get_value_names().map_or_else(
        || vec![arg.get_id().to_string()],
        |names| names.iter().map(ToString::to_string).collect(),
    );
    let count = arg.get_num_args().unwrap_or(1.into());
    format!(
        "value:{}:{}..={}",
        names.join(","),
        count.min_values(),
        count.max_values()
    )
}

fn violations(root: &Command) -> BTreeSet<String> {
    let mut failures = BTreeSet::new();
    let mut shapes: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut helps: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut descriptions: BTreeMap<String, String> = BTreeMap::new();

    fn visit(
        node: &Command,
        path: &str,
        failures: &mut BTreeSet<String>,
        shapes: &mut BTreeMap<String, (String, String)>,
        helps: &mut BTreeMap<String, (String, String)>,
        descriptions: &mut BTreeMap<String, String>,
    ) {
        let children: Vec<_> = node
            .get_subcommands()
            .filter(|c| c.get_name() != "help")
            .collect();
        if !path.is_empty() {
            let token = node.get_name();
            if children.is_empty() {
                if !LEAVES.split_whitespace().any(|verb| verb == token) {
                    failures.insert(format!("leaf-token|{path}"));
                }
                let destructive = matches!(
                    token,
                    "delete" | "decline" | "disconnect" | "end" | "leave" | "remove" | "revoke"
                );
                let has = |long| node.get_arguments().any(|arg| arg.get_long() == Some(long));
                if UNCONFIRMED.contains(&path) {
                    if has("yes") {
                        failures.insert(format!("confirmation|{path}"));
                    }
                } else if destructive
                    && !node.get_arguments().any(|arg| {
                        arg.get_long() == Some("yes")
                            && matches!(arg.get_action(), ArgAction::SetTrue)
                            && (arg.is_required_set() || SELF_CONFIRMING.contains(&path))
                    })
                {
                    failures.insert(format!("confirmation|{path}"));
                }
                if (token == "list" && !UNPAGINATED_LISTS.contains(&path) && !has("cursor"))
                    || (UNPAGINATED_LISTS.contains(&path) && has("cursor"))
                    || (has("cursor")
                        && (!has("limit")
                            || !node.get_after_help().is_some_and(|note| {
                                note.to_string()
                                    .matches(super::PAGINATION_AFTER_HELP)
                                    .count()
                                    == 1
                            })))
                {
                    failures.insert(format!("pagination|{path}"));
                }
                if let Some(description) = node.get_about() {
                    let description = description.to_string();
                    if let Some(other) = descriptions.insert(description.clone(), path.to_owned()) {
                        failures.insert(format!("description|{other}|{path}"));
                    }
                }
            } else if !GROUPS.split_whitespace().any(|noun| noun == token) {
                failures.insert(format!("group-token|{path}"));
            }
        }

        // clap sorts options by display order and then short or long spelling.
        // get_arguments() itself retains insertion order, which need not match help.
        let mut common: Vec<_> = node
            .get_arguments()
            .filter(|arg| arg.get_long().is_some_and(|long| COMMON.contains(&long)))
            .collect();
        common.sort_by_key(|arg| {
            let spelling = if let Some(short) = arg.get_short() {
                format!(
                    "{}{}",
                    short.to_ascii_lowercase(),
                    if short.is_ascii_lowercase() { '0' } else { '1' }
                )
            } else {
                arg.get_long().unwrap_or_default().to_owned()
            };
            (arg.get_display_order(), spelling)
        });
        if common.windows(2).any(|pair| {
            let first = COMMON
                .iter()
                .position(|name| Some(*name) == pair[0].get_long());
            let second = COMMON
                .iter()
                .position(|name| Some(*name) == pair[1].get_long());
            first >= second
        }) {
            failures.insert(format!("common-order|{path}"));
        }
        for arg in node.get_arguments() {
            let Some(long) = arg.get_long() else { continue };
            let shape = value_shape(arg);
            if let Some((other, expected)) = shapes.get(long) {
                if expected != &shape {
                    failures.insert(format!("placeholder|--{long}|{other}|{path}"));
                }
            } else {
                shapes.insert(long.to_owned(), (path.to_owned(), shape));
            }
            if let Some(class) = semantic_class(path, long) {
                let help = arg.get_help().map(ToString::to_string).unwrap_or_default();
                if let Some((other, expected)) = helps.get(&class) {
                    if expected != &help {
                        failures.insert(format!("option-help|{class}|{other}|{path}"));
                    }
                } else {
                    helps.insert(class, (path.to_owned(), help));
                }
            }
        }
        for child in children {
            let child_path = if path.is_empty() {
                child.get_name().to_owned()
            } else {
                format!("{path} {}", child.get_name())
            };
            visit(child, &child_path, failures, shapes, helps, descriptions);
        }
    }
    visit(
        root,
        "",
        &mut failures,
        &mut shapes,
        &mut helps,
        &mut descriptions,
    );
    failures
}

#[test]
fn cli_grammar_conforms() {
    let mut root = Cli::command();
    root.build();
    let observed = violations(&root);
    assert!(
        observed.is_empty(),
        "CLI grammar violations:\n{}",
        observed.into_iter().collect::<Vec<_>>().join("\n")
    );
}

// The lexicons hold the words the tree uses and no other, so a word the tree gave up
// cannot name a new path without changing them.
#[test]
fn lexicons_hold_exactly_the_words_of_the_tree() {
    fn collect<'a>(
        node: &'a Command,
        leaves: &mut BTreeSet<&'a str>,
        groups: &mut BTreeSet<&'a str>,
    ) {
        for child in node.get_subcommands().filter(|c| c.get_name() != "help") {
            if child.has_subcommands() {
                groups.insert(child.get_name());
                collect(child, leaves, groups);
            } else {
                leaves.insert(child.get_name());
            }
        }
    }
    let root = Cli::command();
    let (mut leaves, mut groups) = (BTreeSet::new(), BTreeSet::new());
    collect(&root, &mut leaves, &mut groups);
    assert_eq!(leaves, LEAVES.split_whitespace().collect::<BTreeSet<_>>());
    assert_eq!(groups, GROUPS.split_whitespace().collect::<BTreeSet<_>>());
}

// The guide's Verb lexicon runs from its marker to the next bullet. Parenthesised
// glosses are dropped before tokens are collected, since a gloss may name a word
// that is no verb.
fn guide_verb_lexicon(guide: &str) -> BTreeSet<&str> {
    let lexicon = guide
        .split_once("**Verb lexicon:**")
        .map_or("", |(_, rest)| {
            rest.split_once("\n- **").map_or(rest, |(bullet, _)| bullet)
        });
    let mut spans = lexicon.split('(');
    let unglossed = spans
        .next()
        .into_iter()
        .chain(spans.map(|span| span.split_once(')').map_or("", |(_, after)| after)));
    unglossed
        .flat_map(|span| span.split('`').skip(1).step_by(2))
        .collect()
}

#[test]
fn guide_verb_lexicon_is_the_admitted_leaf_set() {
    let guide = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/output-style.md"));
    let documented = guide_verb_lexicon(guide);
    let admitted = LEAVES.split_whitespace().collect::<BTreeSet<_>>();
    let undocumented = admitted
        .difference(&documented)
        .copied()
        .collect::<Vec<_>>();
    let unadmitted = documented
        .difference(&admitted)
        .copied()
        .collect::<Vec<_>>();
    assert!(
        undocumented.is_empty() && unadmitted.is_empty(),
        "verbs admitted by LEAVES but absent from the guide's Verb lexicon: {}\n\
         verbs in the guide's Verb lexicon but absent from LEAVES: {}",
        undocumented.join(" "),
        unadmitted.join(" ")
    );
}

#[test]
fn entity_identifier_flags_match_the_command_tree_and_parser() {
    let cases: &[(&[&str], &str, &str, &[&str])] = &[
        (
            &["project", "create"],
            "pool",
            "pool-id",
            &[
                "widget",
                "--repository",
                "123",
                "--integration",
                "ghi_01k0z6r1w8f4jy2m7q9v3x5abc",
                "--pool",
                "builders",
            ],
        ),
        (
            &["runner", "update"],
            "pool",
            "pool-id",
            &["builder-one", "--pool", "builders"],
        ),
        (
            &["runner", "serve"],
            "pool",
            "pool-id",
            &["--pool", "builders"],
        ),
        (
            &["runner", "serve"],
            "org",
            "organization",
            &["--personal", "--org", "acme"],
        ),
        (
            &["org", "invitation", "issue"],
            "account",
            "principal-id",
            &["--account", "prn_01k0z6r1w8f4jy2m7q9v3x5abc"],
        ),
        (
            &["workflow", "definition", "update"],
            "project",
            "project-id",
            &[
                "engineering",
                "--run-as",
                "ci",
                "--project",
                "prj_01k0z6r1w8f4jy2m7q9v3x5abc",
            ],
        ),
    ];

    for &(path, replacement, removed, arguments) in cases {
        let mut command = Cli::command();
        for segment in path {
            command = command.find_subcommand(segment).unwrap().clone();
        }
        assert!(
            command
                .get_arguments()
                .any(|arg| arg.get_long() == Some(replacement)),
            "{path:?}"
        );
        assert!(
            !command
                .get_arguments()
                .any(|arg| arg.get_long() == Some(removed)),
            "{path:?}"
        );

        let input = std::iter::once("useful")
            .chain(path.iter().copied())
            .chain(arguments.iter().copied());
        assert!(super::parse(input).is_ok(), "{path:?}");
        let replacement_flag = format!("--{replacement}");
        let old_flag = format!("--{removed}");
        let old_arguments = arguments.iter().map(|arg| {
            if *arg == replacement_flag {
                old_flag.as_str()
            } else {
                *arg
            }
        });
        let input = std::iter::once("useful")
            .chain(path.iter().copied())
            .chain(old_arguments);
        assert!(
            super::parse(input).is_err(),
            "old flag accepted at {path:?}"
        );
    }
}

#[test]
fn runner_drain_separates_local_and_cloud_targets() {
    for args in [&[][..], &["--config", "runner.json"]] {
        let input = ["useful", "runner", "drain"]
            .into_iter()
            .chain(args.iter().copied());
        assert!(super::parse(input).is_ok(), "{args:?}");
    }
    for args in [
        &["runner", "--config", "runner.json"][..],
        &["--org", "acme"],
    ] {
        let input = ["useful", "runner", "drain"]
            .into_iter()
            .chain(args.iter().copied());
        assert!(super::parse(input).is_err(), "{args:?}");
    }
}

#[test]
fn destructive_leaves_require_confirmation_but_runner_modes_do_not() {
    let gated: &[&[&str]] = &[
        &[
            "account",
            "service",
            "key",
            "revoke",
            "crd_01k0z6r1w8f4jy2m7q9v3x5abc",
            "--api-key-file",
            "key",
        ],
        &[
            "runner",
            "credential",
            "revoke",
            "credential",
            "--runner",
            "runner",
        ],
        &["account", "integration", "disconnect", "codex"],
        &["account", "identity", "remove", "identity"],
        &[
            "org",
            "integration",
            "disconnect",
            "ghi_01k0z6r1w8f4jy2m7q9v3x5abc",
        ],
        &[
            "org",
            "integration",
            "repository",
            "remove",
            "7",
            "--integration",
            "glc_01k0z6r1w8f4jy2m7q9v3x5abc",
        ],
        &["project", "pool", "remove", "builders"],
    ];
    for &args in gated {
        let input = std::iter::once("useful").chain(args.iter().copied());
        assert_eq!(
            super::parse(input).unwrap_err().kind(),
            clap::error::ErrorKind::MissingRequiredArgument,
            "{args:?}"
        );
        let input = std::iter::once("useful")
            .chain(args.iter().copied())
            .chain(std::iter::once("--yes"));
        assert!(super::parse(input).is_ok(), "{args:?}");
    }
    for mode in ["disable", "drain"] {
        assert!(
            super::parse(["useful", "runner", mode, "runner"]).is_ok(),
            "{mode}"
        );
    }
    // `authorize` and `deauthorize` check a missing `--yes` as they run, asking on a terminal
    // in its place.
    for leaf in ["authorize", "deauthorize"] {
        let input = [
            "useful",
            "account",
            "integration",
            leaf,
            "agl_01k0z6r1w8f4jy2m7q9v3x5abc",
            "--runner",
            "rnr_01k0z6r1w8f4jy2m7q9v3x5abc",
        ];
        assert!(super::parse(input).is_ok(), "{leaf}");
    }
}

// `authorize` takes `INTEGRATION` or `--all`, never both, and either leaf names its runner with
// `--runner`, by ID or by name, or names none, to be told the runners it can name.
#[test]
fn authorize_and_deauthorize_take_runner_as_an_option_and_refuse_a_malformed_target() {
    const GRANT: &str = "agl_01k0z6r1w8f4jy2m7q9v3x5abc";
    const RUNNER: &str = "rnr_01k0z6r1w8f4jy2m7q9v3x5abc";
    for args in [
        &["authorize", GRANT][..],
        &["authorize", "codex"],
        &["authorize", "--all"],
        &["deauthorize", GRANT],
        &["authorize", GRANT, "--runner", RUNNER, "--yes"],
        &["authorize", "--all", "--runner", RUNNER],
        &["authorize", "--all", "--runner", "build-1"],
        &["deauthorize", GRANT, "--runner", "build-1"],
    ] {
        let input = ["useful", "account", "integration"]
            .into_iter()
            .chain(args.iter().copied());
        assert!(super::parse(input).is_ok(), "{args:?}");
    }
    for (args, kind) in [
        // The runner is no positional.
        (
            &["authorize", GRANT, RUNNER, "--yes"][..],
            clap::error::ErrorKind::UnknownArgument,
        ),
        (
            &["authorize", GRANT, "--all", "--runner", RUNNER],
            clap::error::ErrorKind::ArgumentConflict,
        ),
        (
            &["authorize", "--runner", RUNNER, "--yes"],
            clap::error::ErrorKind::MissingRequiredArgument,
        ),
        (
            &["deauthorize", "--runner", RUNNER, "--yes"],
            clap::error::ErrorKind::MissingRequiredArgument,
        ),
    ] {
        let input = ["useful", "account", "integration"]
            .into_iter()
            .chain(args.iter().copied());
        assert_eq!(super::parse(input).unwrap_err().kind(), kind, "{args:?}");
    }
}

#[test]
fn connections_live_only_under_org_integration() {
    let mut root = Cli::command();
    root.build();
    for family in ["connection", "github", "gitlab", "linear"] {
        assert!(root.find_subcommand(family).is_none(), "{family}");
    }
    let leaves = root
        .find_subcommand("org")
        .and_then(|org| org.find_subcommand("integration"))
        .unwrap()
        .get_subcommands()
        .map(|command| command.get_name().to_owned())
        .filter(|name| name != "help")
        .collect::<BTreeSet<_>>();
    assert_eq!(
        leaves,
        BTreeSet::from(
            [
                "authorize",
                "connect",
                "deauthorize",
                "disconnect",
                "list",
                "reconnect",
                "repository",
                "show",
                "team"
            ]
            .map(str::to_owned)
        )
    );
    for path in [
        &["connection"][..],
        &["github"][..],
        &["github", "setup", "begin", "example"][..],
        &["gitlab", "list", "example"][..],
        &["linear"][..],
        &["connection", "github", "setup", "begin", "acme"][..],
        &["connection", "gitlab", "credential", "show", "acme"][..],
    ] {
        let input = std::iter::once("useful").chain(path.iter().copied());
        assert_eq!(
            super::parse(input).unwrap_err().kind(),
            clap::error::ErrorKind::InvalidSubcommand,
            "{path:?}"
        );
    }
}

#[test]
fn project_update_takes_a_change_and_confirms_only_a_cleared_repository() {
    for arguments in [
        &["--clear-repository"][..],
        &[][..],
        &["--yes", "--name", "gadget"][..],
        &["--clear-repository", "--yes", "--repository", "a/b"][..],
        &["--integration", "github", "--name", "gadget"][..],
    ] {
        let input = ["useful", "project", "update", "widget"]
            .into_iter()
            .chain(arguments.iter().copied());
        assert!(super::parse(input).is_err(), "{arguments:?}");
    }
    assert!(
        super::parse([
            "useful",
            "project",
            "update",
            "widget",
            "--clear-repository",
            "--yes",
            "--name",
            "gadget",
        ])
        .is_ok()
    );
}

#[test]
fn project_triggers_and_schedules_are_unknown_commands() {
    let mut root = Cli::command();
    root.build();
    let project = root.find_subcommand("project").unwrap();
    for group in ["trigger", "schedule"] {
        assert!(project.find_subcommand(group).is_none(), "{group}");
    }
    for path in [
        &["project", "trigger"][..],
        &["project", "trigger", "list", "example", "project"][..],
        &["project", "schedule"][..],
        &["project", "schedule", "list", "example", "project"][..],
    ] {
        let input = std::iter::once("useful").chain(path.iter().copied());
        assert_eq!(
            super::parse(input).unwrap_err().kind(),
            clap::error::ErrorKind::InvalidSubcommand,
            "{path:?}"
        );
    }
}

#[test]
fn run_linear_offers_only_its_reads() {
    let mut root = Cli::command();
    root.build();
    let linear = root
        .find_subcommand("workflow")
        .and_then(|workflow| workflow.find_subcommand("run"))
        .and_then(|run| run.find_subcommand("linear"))
        .unwrap();
    let leaves: Vec<_> = linear
        .get_subcommands()
        .map(Command::get_name)
        .filter(|name| *name != "help")
        .collect();
    assert_eq!(leaves, ["list"]);
}

#[test]
fn renamed_leaves_have_only_the_approved_verb_paths() {
    let mut root = Cli::command();
    root.build();
    for (family, replacement, old) in [
        (&["org", "integration"][..], "disconnect", "remove"),
        (&["org", "integration"][..], "disconnect", "delete"),
        (&["runner", "join-key"][..], "issue", "create"),
    ] {
        let command = family.iter().fold(&root, |parent, token| {
            parent.find_subcommand(token).unwrap()
        });
        assert!(command.find_subcommand(replacement).is_some(), "{family:?}");
        assert!(command.find_subcommand(old).is_none(), "{family:?}");
    }
    for family in [
        &["runner", "join-key"][..],
        &["org", "invitation"][..],
        &["account", "service", "key"][..],
    ] {
        let command = family.iter().fold(&root, |parent, token| {
            parent.find_subcommand(token).unwrap()
        });
        assert!(command.find_subcommand("issue").is_some(), "{family:?}");
        assert!(command.find_subcommand("revoke").is_some(), "{family:?}");
        assert!(command.find_subcommand("create").is_none(), "{family:?}");
    }
    let project = root.find_subcommand("project").unwrap();
    for leaf in ["update", "pool"] {
        assert!(project.find_subcommand(leaf).is_some(), "{leaf}");
    }
    for gone in ["rename", "repository", "runner-pool"] {
        assert!(project.find_subcommand(gone).is_none(), "{gone}");
    }
    for path in [
        &["org", "integration", "remove"][..],
        &["org", "integration", "delete"][..],
        &["runner", "join-key", "create"][..],
        &["runner", "activation", "issue"][..],
        &["runner", "create"][..],
    ] {
        let input = std::iter::once("useful").chain(path.iter().copied());
        assert_eq!(
            super::parse(input).unwrap_err().kind(),
            clap::error::ErrorKind::InvalidSubcommand,
            "{path:?}"
        );
    }
    assert!(
        super::parse([
            "useful",
            "runner",
            "join-key",
            "issue",
            "--runner",
            "example",
            "--key-file",
            "-",
        ])
        .is_ok()
    );
}

#[test]
fn structural_rules_reject_discriminating_changes() {
    let fixture = || {
        Command::new("fixture").subcommand(
            Command::new("entity")
                .subcommand(
                    Command::new("list")
                        .about("A")
                        .arg(Arg::new("cursor").long("cursor").help("same")),
                )
                .subcommand(Command::new("show").about("B")),
        )
    };
    let found = violations(&fixture());
    assert!(found.contains("pagination|entity list"));
    let unpaged = Command::new("fixture")
        .subcommand(Command::new("entity").subcommand(Command::new("list").about("A")));
    assert!(violations(&unpaged).contains("pagination|entity list"));
    let complete = Command::new("fixture").subcommand(
        Command::new("entity").subcommand(
            Command::new("list")
                .about("A")
                .after_help(super::PAGINATION_AFTER_HELP)
                .arg(Arg::new("cursor").long("cursor"))
                .arg(Arg::new("limit").long("limit")),
        ),
    );
    assert!(
        !violations(&complete)
            .iter()
            .any(|id| id.starts_with("pagination|"))
    );
    let repeated_note = Command::new("fixture").subcommand(
        Command::new("entity").subcommand(
            Command::new("list")
                .about("A")
                .after_help(format!(
                    "{}\n{}",
                    super::PAGINATION_AFTER_HELP,
                    super::PAGINATION_AFTER_HELP
                ))
                .arg(Arg::new("cursor").long("cursor"))
                .arg(Arg::new("limit").long("limit")),
        ),
    );
    assert!(violations(&repeated_note).contains("pagination|entity list"));
    let found = violations(
        &Command::new("fixture")
            .subcommand(Command::new("people").subcommand(Command::new("detach").about("A"))),
    );
    assert!(found.contains("group-token|people"));
    assert!(found.contains("leaf-token|people detach"));
    let found = violations(
        &Command::new("fixture").subcommand(
            Command::new("entity")
                .subcommand(Command::new("remove").about("A"))
                .subcommand(Command::new("show").about("A")),
        ),
    );
    assert!(found.contains("confirmation|entity remove"));
    assert!(found.contains("description|entity remove|entity show"));
    let confirmation = |yes: Arg| {
        Command::new("fixture").subcommand(
            Command::new("entity").subcommand(Command::new("remove").about("A").arg(yes)),
        )
    };
    assert!(
        violations(&confirmation(
            Arg::new("yes").long("yes").action(ArgAction::SetTrue)
        ))
        .contains("confirmation|entity remove")
    );
    assert!(
        !violations(&confirmation(
            Arg::new("yes")
                .long("yes")
                .required(true)
                .action(ArgAction::SetTrue)
        ))
        .contains("confirmation|entity remove")
    );
    // The one unconfirmed path takes no `--yes`, and its exemption is that path's alone.
    let unconfirmed = |path: [&'static str; 4], yes: Option<Arg>| {
        let leaf = Command::new(path[3]).about("A");
        Command::new("fixture").subcommand(Command::new(path[0]).subcommand(
            Command::new(path[1]).subcommand(
                Command::new(path[2]).subcommand(yes.into_iter().fold(leaf, Command::arg)),
            ),
        ))
    };
    let exempt = ["project", "webhook", "secret", "revoke"];
    assert!(
        !violations(&unconfirmed(exempt, None))
            .contains("confirmation|project webhook secret revoke")
    );
    assert!(
        violations(&unconfirmed(
            exempt,
            Some(Arg::new("yes").long("yes").action(ArgAction::SetTrue))
        ))
        .contains("confirmation|project webhook secret revoke")
    );
    assert!(
        violations(&unconfirmed(
            ["project", "webhook", "delivery", "revoke"],
            None
        ))
        .contains("confirmation|project webhook delivery revoke")
    );
    // The insertion order is correct; only display metadata reverses help order.
    let ordered = |http_order, json_order| {
        Command::new("fixture").subcommand(
            Command::new("entity").subcommand(
                Command::new("list")
                    .about("A")
                    .arg(
                        Arg::new("json")
                            .long("json")
                            .action(ArgAction::SetTrue)
                            .display_order(json_order),
                    )
                    .arg(
                        Arg::new("http")
                            .long("allow-insecure-http")
                            .action(ArgAction::SetTrue)
                            .display_order(http_order),
                    ),
            ),
        )
    };
    assert!(!violations(&ordered(2, 1)).contains("common-order|entity list"));
    assert!(violations(&ordered(0, 1)).contains("common-order|entity list"));
}

#[test]
fn option_identity_and_effective_placeholders_are_distinct() {
    let command = |second: Arg| {
        Command::new("fixture").subcommand(
            Command::new("account")
                .subcommand(
                    Command::new("show")
                        .about("A")
                        .arg(Arg::new("name").long("name").help("source")),
                )
                .subcommand(Command::new("list").about("B").arg(second)),
        )
    };
    // Same spelling with different semantic roles is not a help class.
    assert!(
        !violations(&command(Arg::new("name").long("name").help("destination")))
            .iter()
            .any(|id| id.starts_with("option-help"))
    );
    // Implicit placeholder <name> versus a valueless flag is not equivalent.
    assert!(
        violations(&command(
            Arg::new("name").long("name").action(ArgAction::SetTrue)
        ))
        .iter()
        .any(|id| id.starts_with("placeholder|--name"))
    );
    let shared = |second_help| {
        Command::new("fixture").subcommand(
            Command::new("account")
                .subcommand(
                    Command::new("signup").about("A").arg(
                        Arg::new("json")
                            .long("json")
                            .action(ArgAction::SetTrue)
                            .help("first"),
                    ),
                )
                .subcommand(
                    Command::new("list").about("B").arg(
                        Arg::new("json")
                            .long("json")
                            .action(ArgAction::SetTrue)
                            .help(second_help),
                    ),
                ),
        )
    };
    assert!(
        violations(&shared("different"))
            .iter()
            .any(|id| id.starts_with("option-help|json:account"))
    );
    assert!(
        !violations(&shared("first"))
            .iter()
            .any(|id| id.starts_with("option-help"))
    );
    let placeholder = || {
        Command::new("fixture").subcommand(
            Command::new("account")
                .subcommand(
                    Command::new("show")
                        .about("A")
                        .arg(Arg::new("organization").long("organization").help("shared")),
                )
                .subcommand(
                    Command::new("list").about("B").arg(
                        Arg::new("organization")
                            .long("organization")
                            .value_name("OTHER")
                            .help("shared"),
                    ),
                ),
        )
    };
    assert!(
        violations(&placeholder())
            .iter()
            .any(|id| id.starts_with("placeholder|--organization"))
    );
    let implicit = Arg::new("name").long("name");
    assert_eq!(
        value_shape(&implicit),
        value_shape(&Arg::new("name").long("name").value_name("name"))
    );
    assert_ne!(
        value_shape(&implicit),
        value_shape(&Arg::new("name").long("name").value_name("NAME"))
    );
    assert!(
        !violations(&command(Arg::new("name").long("name").value_name("name")))
            .iter()
            .any(|id| id.starts_with("placeholder|--name"))
    );
    assert!(
        violations(&command(Arg::new("name").long("name").value_name("NAME")))
            .iter()
            .any(|id| id.starts_with("placeholder|--name"))
    );
    let cardinality = |count| command(Arg::new("name").long("name").num_args(count));
    assert!(
        violations(&cardinality(2))
            .iter()
            .any(|id| id.starts_with("placeholder|--name"))
    );
    assert!(
        !violations(&cardinality(1))
            .iter()
            .any(|id| id.starts_with("placeholder|--name"))
    );
    assert_ne!(
        value_shape(&Arg::new("name").long("name").num_args(1..=2)),
        value_shape(&Arg::new("name").long("name").num_args(1..=3))
    );
    // A long option `semantic_class` names is one class on every command, as
    // `--project-id` is in this fixture; drift within that class must fail
    // even when another long option happens to match.
    let project = |second_help| {
        Command::new("fixture").subcommand(
            Command::new("run")
                .subcommand(
                    Command::new("create")
                        .about("A")
                        .arg(Arg::new("project_id").long("project-id").help("shared")),
                )
                .subcommand(
                    Command::new("input-set").subcommand(
                        Command::new("create")
                            .about("B")
                            .arg(Arg::new("project_id").long("project-id").help(second_help)),
                    ),
                ),
        )
    };
    assert!(
        !violations(&project("shared"))
            .iter()
            .any(|id| id.starts_with("option-help|project-id"))
    );
    assert!(
        violations(&project("drift"))
            .iter()
            .any(|id| id.starts_with("option-help|project-id|run create|run input-set create"))
    );
}

#[test]
fn parameterized_option_classes_are_isolated_but_ratchet_within_each_class() {
    let json = |path: &'static str, help: &'static str| {
        let mut parts = path.split_whitespace();
        let group = parts.next().unwrap();
        let leaf = parts.next().unwrap();
        Command::new(group).subcommand(
            Command::new(leaf).about(path.to_owned()).arg(
                Arg::new("json")
                    .long("json")
                    .action(ArgAction::SetTrue)
                    .help(help),
            ),
        )
    };
    let different_families = Command::new("fixture")
        .subcommand(json("account signup", "account"))
        .subcommand(json("runner sync", "runner"));
    assert!(
        !violations(&different_families)
            .iter()
            .any(|id| id.starts_with("option-help"))
    );
    assert_ne!(
        semantic_class("account login", "json"),
        semantic_class("account show", "json")
    );
    assert_eq!(
        semantic_class("account login", "json"),
        semantic_class("account identity link", "json")
    );
    assert_ne!(
        semantic_class("org audit list", "limit"),
        semantic_class("org list", "limit")
    );
    let limit = |help| Arg::new("limit").long("limit").help(help);
    let bounds = Command::new("fixture").subcommand(
        Command::new("org")
            .subcommand(
                Command::new("audit")
                    .subcommand(Command::new("list").about("Audit").arg(limit("100"))),
            )
            .subcommand(
                Command::new("list")
                    .about("Organizations")
                    .arg(limit("200")),
            )
            .subcommand(
                Command::new("member")
                    .subcommand(Command::new("list").about("Members").arg(limit("changed"))),
            ),
    );
    let found = violations(&bounds);
    assert!(
        !found
            .iter()
            .any(|id| id.starts_with("option-help|limit:100"))
    );
    assert!(
        found
            .iter()
            .any(|id| id.starts_with("option-help|limit:200"))
    );
    let streaming = Command::new("fixture").subcommand(
        Command::new("account")
            .subcommand(
                Command::new("login").about("Login").arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("events"),
                ),
            )
            .subcommand(
                Command::new("identity").subcommand(
                    Command::new("link").about("Link").arg(
                        Arg::new("json")
                            .long("json")
                            .action(ArgAction::SetTrue)
                            .help("drift"),
                    ),
                ),
            ),
    );
    assert!(
        violations(&streaming)
            .iter()
            .any(|id| id.starts_with("option-help|json:streaming-events"))
    );
}

#[test]
fn handover_takes_cloud_continuation_options() {
    let command = ["useful", "workflow", "run", "handover", "run_1"];
    let options = [
        "--from",
        "build",
        "--from",
        "test",
        "--expected-version",
        "7",
        "--wait",
        "--timeout",
        "5m",
        "--org",
        "acme",
        "--json",
    ];
    assert!(super::parse(command.into_iter().chain(options)).is_ok());
    let error = super::parse(command.into_iter().chain(["--execution-root", "root"])).unwrap_err();
    assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
}

// `resume` keeps `--workflow` and `--execution-root` and takes no `--from`; `retry` takes
// `--from` or `--all`, and `--workflow` with neither `--all`.
#[test]
fn resume_and_retry_take_their_options() {
    let resume = ["useful", "workflow", "run", "resume", "run_1"];
    let retry = ["useful", "workflow", "run", "retry", "run_1"];
    for command in [resume, retry] {
        let options = ["--handover", "--execution-root", "root"];
        assert!(super::parse(command.into_iter().chain(options)).is_ok());
        let error = super::parse(command.into_iter().chain(["--handover"])).unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }
    for accepted in [
        &[][..],
        &["--workflow", "repair.yaml", "--execution-root", "root"][..],
        &["--org", "acme", "--json", "--allow-insecure-http"][..],
    ] {
        let input = resume.iter().chain(accepted).copied();
        assert!(super::parse(input).is_ok(), "{accepted:?}");
    }
    for accepted in [
        &[][..],
        &[
            "--from",
            "build",
            "--from",
            "review",
            "--workflow",
            "repair.yaml",
            "--execution-root",
            "root",
        ][..],
        &["--all", "--execution-root", "root"][..],
        &[
            "--all",
            "--org",
            "acme",
            "--expected-version",
            "7",
            "--timeout",
            "5m",
        ][..],
        &[
            "--from",
            "build",
            "--org",
            "acme",
            "--wait",
            "--timeout",
            "5m",
        ][..],
        &["--agent-profiles", "profiles.json"][..],
    ] {
        let input = retry.iter().chain(accepted).copied();
        assert!(super::parse(input).is_ok(), "{accepted:?}");
    }
    for conflicting in [
        &["--all", "--from", "build"][..],
        &["--all", "--workflow", "repair.yaml"][..],
        &["--all", "--execution-root", "root", "--handover"][..],
    ] {
        let input = retry.iter().chain(conflicting).copied();
        let error = super::parse(input).unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::ArgumentConflict,
            "{conflicting:?}"
        );
        assert_eq!(error.exit_code(), 2, "{conflicting:?}");
    }
}

// A definition's evaluations are listed and shown by the definition's ID or name in the
// project in effect, `--state` and `--run` filtering the list.
#[test]
fn definition_evaluations_name_the_definition_in_the_project_in_effect() {
    let evaluation = "wev_01k0z6r1w8f4jy2m7q9v3x5abc";
    let base = ["useful", "workflow", "definition", "evaluation"];
    for accepted in [
        &["list", "engineering"][..],
        &[
            "list",
            "engineering",
            "--state",
            "failed",
            "--run",
            "run_1",
            "--limit",
            "5",
            "--cursor",
            "c",
            "--json",
        ][..],
        &["show", evaluation, "--definition", "engineering"][..],
    ] {
        let input = base.iter().chain(accepted).copied();
        assert!(super::parse(input).is_ok(), "{accepted:?}");
    }
    for refused in [&["list"][..], &["show", evaluation][..]] {
        let input = base.iter().chain(refused).copied();
        assert!(super::parse(input).is_err(), "{refused:?}");
    }
}
