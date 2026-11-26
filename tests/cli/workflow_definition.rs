use std::collections::BTreeSet;
use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use tempfile::TempDir;

use super::{CREDENTIALS_FILE_VARIABLE, run_with_env};

const ROOT_WORKFLOW: &str =
    include_str!("../../crates/execution/tests/fixtures/workflow/v1/valid/root-workflow.yaml");
const DESIGN_WORKFLOW: &str = r#"schemaVersion: 1
inputs:
  ticket:
    kind: text
steps:
  design:
    kind: cmd
    command:
      argv: ["design.py"]
"#;
const CONTENT_SENTINEL: &str = "unique-tree-content-sentinel";
const START_WHERE: &str = "event.team == $linearTeam and event.state == $ownedState";

pub(super) struct Tree {
    _temporary: TempDir,
    root: PathBuf,
}

impl Tree {
    pub(super) fn engineering() -> Self {
        Self::with(ROOT_WORKFLOW, DESIGN_WORKFLOW)
    }

    fn with(root_workflow: &str, design_workflow: &str) -> Self {
        let temporary = tempfile::tempdir().expect("temporary tree should be created");
        let root = temporary.path().join("engineering");
        let tree = Self {
            _temporary: temporary,
            root,
        };
        tree.write("workflow.yaml", root_workflow);
        tree.write("design.yaml", design_workflow);
        tree.write(
            "scripts/design.py",
            &format!("print('{CONTENT_SENTINEL}')\n"),
        );
        tree.write(
            "policy/engineering.json",
            &format!("{{\"note\": \"{CONTENT_SENTINEL}\"}}\n"),
        );
        tree.write("tests/test_x.py", "def test_x():\n    pass\n");
        tree
    }

    pub(super) fn write(&self, relative: &str, contents: &str) {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().expect("tree file should have a parent"))
            .expect("tree directory should be created");
        fs::write(path, contents).expect("tree file should be written");
    }

    pub(super) fn path(&self) -> &str {
        self.root
            .to_str()
            .expect("temporary tree path should be UTF-8")
    }
}

fn validate(directory: &str, json: bool) -> std::process::Output {
    let mut args = vec!["workflow", "validate", directory];
    if json {
        args.push("--json");
    }
    run_offline(&args, &[])
}

/// Runs `useful` with no stored session and a network sentinel that fails the test when the
/// command opens a connection; `environment` adds pairs such as `USEFUL_HOME`.
fn run_offline(args: &[&str], environment: &[(&str, &str)]) -> std::process::Output {
    let listener = TcpListener::bind("127.0.0.1:0").expect("network sentinel should bind");
    listener
        .set_nonblocking(true)
        .expect("network sentinel should be nonblocking");
    let api_url = format!("http://{}/api", listener.local_addr().unwrap());
    let credentials = super::private_credential_directory();
    let credentials = credentials.path().join("credentials.json");
    let credentials = credentials
        .to_str()
        .expect("temporary credential path should be UTF-8");
    let mut pairs = vec![
        (CREDENTIALS_FILE_VARIABLE, credentials),
        ("USEFUL_API_URL", api_url.as_str()),
        (
            "USEFUL_AUTH_ISSUER",
            "http://auth.workflow-definition.invalid/",
        ),
        (
            "USEFUL_AUTH_AUDIENCE",
            "https://api.workflow-definition.invalid",
        ),
        ("USEFUL_AUTH_CLIENT_ID", "workflow-definition-client"),
    ];
    pairs.extend_from_slice(environment);
    let output = run_with_env(args, &pairs);
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "workflow definition commands must not open a network connection"
    );
    output
}

fn report(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("tree validation output should be JSON")
}

fn assert_no_content(output: &std::process::Output) {
    for stream in [&output.stdout, &output.stderr] {
        assert!(
            !String::from_utf8_lossy(stream).contains(CONTENT_SENTINEL),
            "tree validation must not print file contents"
        );
    }
}

fn rejection_codes(directory: &str) -> Vec<(String, Value)> {
    let output = validate(directory, true);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_no_content(&output);
    let report = report(&output);
    assert_eq!(report["outcome"], "invalid");
    assert_eq!(report["command"], "useful workflow validate");
    report["diagnostics"]
        .as_array()
        .expect("diagnostics should be a list")
        .iter()
        .map(|diagnostic| {
            (
                diagnostic["code"]
                    .as_str()
                    .expect("diagnostic code should be text")
                    .to_owned(),
                diagnostic["location"].clone(),
            )
        })
        .collect()
}

fn single_rejection(root_workflow: &str, design_workflow: &str) -> (String, Value) {
    let tree = Tree::with(root_workflow, design_workflow);
    let mut codes = rejection_codes(tree.path());
    assert_eq!(codes.len(), 1, "{codes:?}");
    codes.remove(0)
}

// SC-WFDEF-1
#[test]
fn engineering_tree_validates_with_digest_files_triggers_and_bindings() {
    let tree = Tree::engineering();
    let output = validate(tree.path(), true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_no_content(&output);
    let report = report(&output);

    assert_eq!(report["schemaVersion"], 1);
    assert_eq!(report["command"], "useful workflow validate");
    assert_eq!(report["outcome"], "valid");
    assert!(report["tree"]["path"].is_string());
    assert_eq!(report["name"], "engineering");
    assert_eq!(report["version"], "1.0.0");
    assert_eq!(report["digest"]["algorithm"], "sha256");
    let digest = report["digest"]["value"]
        .as_str()
        .expect("digest value should be text");
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(
        report["workflowFiles"],
        json!(["workflow.yaml", "design.yaml"])
    );
    assert_eq!(report["programs"], json!(["scripts"]));
    assert_eq!(report["requiresTools"], json!(["git", "gh", "python3"]));
    assert_eq!(
        report["triggers"],
        json!({
            "start": {
                "kind": "start",
                "source": "$connection",
                "event": "issue.state_entered",
                "where": START_WHERE,
                "subject": "event.issue.identifier",
                "inputs": {"ticket": "event.issue.identifier", "baseBranch": "main"},
            },
            "release": {
                "kind": "control",
                "source": "$connection",
                "event": "issue.state_left",
                "where": START_WHERE,
                "action": {"when": "event.to == $canceled", "then": "cancel", "else": "withdraw"},
            },
        })
    );
    assert_eq!(
        report["bindings"]["connection"],
        json!({"kind": "connection", "required": true})
    );
    assert_eq!(
        report["bindings"]["ownedState"],
        json!({"kind": "linear.state", "default": "Engineering", "required": false})
    );
    assert_eq!(
        report["bindings"]
            .as_object()
            .expect("bindings should be an object")
            .len(),
        7
    );

    // Moving excluded test files leaves the digest unchanged.
    fs::rename(
        tree.root.join("tests/test_x.py"),
        tree.root.join("tests/test_y.py"),
    )
    .expect("excluded file should move");
    assert_eq!(
        report_digest(&validate(tree.path(), true)),
        digest,
        "excluded files must not change the digest"
    );

    let human = validate(tree.path(), false);
    assert_eq!(human.status.code(), Some(0), "{human:?}");
    assert_no_content(&human);
    let stdout = String::from_utf8(human.stdout).expect("human output should be UTF-8");
    for expected in [
        "✓ Workflow tree is valid.",
        &format!("sha256:{digest}"),
        "workflow.yaml, design.yaml",
        "engineering",
        "1.0.0",
        "start",
        "release",
        "action: when event.to == $canceled then cancel else withdraw",
        "issue.state_entered",
        "(required)",
        "(default \"Engineering\")",
    ] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in {stdout}"
        );
    }
}

#[test]
fn validate_reports_a_named_control_action() {
    let root = ROOT_WORKFLOW.replace(
        r#"{when: "event.to == $canceled", then: cancel, else: withdraw}"#,
        "release",
    );
    let tree = Tree::with(&root, DESIGN_WORKFLOW);
    let output = validate(tree.path(), true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        report(&output)["triggers"]["release"]["action"],
        json!({"name": "release"})
    );
}

// A tree is its own source root, so a boundary or an agent-profile replacement given with a
// directory is refused before anything is read.
#[test]
fn validate_refuses_a_source_root_or_agent_profiles_with_a_directory() {
    let tree = Tree::engineering();
    tree.write("profiles.yaml", "schemaVersion: 1\nagentProfiles: {}\n");
    let profiles = tree.root.join("profiles.yaml");
    let profiles = profiles.to_str().expect("profiles path should be UTF-8");
    for option in [
        ["--source-root", tree.path()],
        ["--agent-profiles", profiles],
    ] {
        let mut arguments = vec!["workflow", "validate", tree.path()];
        arguments.extend(option);
        arguments.push("--json");
        let output = run_offline(&arguments, &[]);

        assert_eq!(output.status.code(), Some(2), "{option:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{option:?}: {output:?}");
    }
}

// `files` lists, in bytewise order, the paths the digest covers and none the root's
// `exclude` matches (`tests/`, `**/__pycache__/`).
#[test]
fn validate_json_reports_the_files_the_digest_covers() {
    let tree = Tree::engineering();
    tree.write("scripts/__pycache__/design.cpython-312.pyc", "cached\n");
    let output = validate(tree.path(), true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        report(&output)["files"],
        json!([
            "design.yaml",
            "policy/engineering.json",
            "scripts/design.py",
            "workflow.yaml",
        ])
    );
}

fn declaring_integrations(declaration: &str) -> String {
    let root = ROOT_WORKFLOW.replacen(
        "requires:\n  tools:",
        &format!("requires:\n{declaration}  tools:"),
        1,
    );
    assert_ne!(root, ROOT_WORKFLOW);
    root
}

fn valid_report(directory: &str) -> Value {
    let output = validate(directory, true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    report(&output)
}

fn integrations_lines(directory: &str) -> Vec<String> {
    let output = validate(directory, false);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    String::from_utf8(output.stdout)
        .expect("human output should be UTF-8")
        .lines()
        .filter(|line| line.starts_with("integrations:"))
        .map(str::to_owned)
        .collect()
}

// A root that declares integrations reports each with the `as` that applies to it, and
// otherwise validates and publishes as it does without them, the digest apart; a root that
// declares none reports no `requiresIntegrations` and no line.
#[test]
fn a_root_declaring_integrations_reports_them_and_publishes_as_without_them() {
    let declared_root = declaring_integrations(
        "  as: member\n  integrations: {linear: {as: org}, github: {}, claude_code: {}}\n",
    );
    let without_identity = |mut report: Value| {
        let object = report.as_object_mut().unwrap();
        object.remove("digest");
        object.remove("tree");
        object.remove("requiresIntegrations");
        report
    };
    let plain = Tree::engineering();
    let declared = Tree::with(&declared_root, DESIGN_WORKFLOW);
    let declared_report = valid_report(declared.path());
    let plain_report = valid_report(plain.path());
    assert_eq!(
        declared_report["requiresIntegrations"],
        json!({
            "claude_code": {"as": "member"},
            "github": {"as": "member"},
            "linear": {"as": "org"},
        })
    );
    assert!(
        !plain_report
            .as_object()
            .unwrap()
            .contains_key("requiresIntegrations"),
        "{plain_report}"
    );
    assert_eq!(
        without_identity(declared_report),
        without_identity(plain_report)
    );

    let lines = integrations_lines(declared.path());
    assert_eq!(lines.len(), 1, "{lines:?}");
    for expected in ["claude_code as member", "github as member", "linear as org"] {
        assert!(
            lines[0].contains(expected),
            "missing {expected:?} in {lines:?}"
        );
    }
    assert_eq!(integrations_lines(plain.path()), Vec::<String>::new());

    for tree in [&plain, &declared] {
        let home = Home::new();
        let published = home.publish(tree, &["--bindings", &tree.engineering_bindings()]);
        assert_eq!(published["revision"]["n"], 1);
        assert_eq!(published["definition"]["current"], 1);
    }
}

// A root's `requires.check` is checked for its shape and reported as nothing: the report is
// the same root's without it, the digest apart. A stage file that declares one carries a
// root-only block.
#[test]
fn a_root_declaring_a_host_check_reports_as_without_it() {
    let declared_root = declaring_integrations("  check: {argv: [host-check, --quick]}\n");
    let without_identity = |mut report: Value| {
        let object = report.as_object_mut().unwrap();
        object.remove("digest");
        object.remove("tree");
        report
    };
    let plain = Tree::engineering();
    let declared = Tree::with(&declared_root, DESIGN_WORKFLOW);
    let declared_report = valid_report(declared.path());
    let plain_report = valid_report(plain.path());
    assert_ne!(declared_report["digest"], plain_report["digest"]);
    assert_eq!(
        without_identity(declared_report),
        without_identity(plain_report)
    );

    let design = format!("{DESIGN_WORKFLOW}requires:\n  check: {{argv: [host-check]}}\n");
    let (code, location) = single_rejection(ROOT_WORKFLOW, &design);
    assert_eq!(code, "root_only_block_outside_root");
    assert_eq!(location["path"], "design.yaml");
    assert_eq!(location["key"], "requires");
}

// Without `requires.as` an entry's own `as` is reported and an entry without one has none;
// a stage file's override is not reported.
#[test]
fn validate_reports_the_roots_own_as_for_each_integration() {
    let tree = Tree::with(
        &declaring_integrations("  integrations: {github: {}, linear: {as: org}}\n"),
        DESIGN_WORKFLOW,
    );
    assert_eq!(
        valid_report(tree.path())["requiresIntegrations"],
        json!({"github": {}, "linear": {"as": "org"}})
    );

    let overridden = Tree::with(
        &declaring_integrations("  integrations: {linear: {as: org}}\n"),
        &format!("{DESIGN_WORKFLOW}requires:\n  integrations:\n    linear: {{as: member}}\n"),
    );
    assert_eq!(
        valid_report(overridden.path())["requiresIntegrations"],
        json!({"linear": {"as": "org"}})
    );
}

// A root that declares the token services `mergify` and `buildkite` reports each with the `as` that
// applies to it, and otherwise validates and publishes as the plain tree does, the digest apart.
#[test]
fn a_root_declaring_token_services_reports_them_and_publishes() {
    let declared = Tree::with(
        &declaring_integrations(
            "  as: member\n  integrations: {mergify: {as: org}, buildkite: {}}\n",
        ),
        DESIGN_WORKFLOW,
    );
    let mut declared_report = valid_report(declared.path());
    let mut plain_report = valid_report(Tree::engineering().path());
    assert_eq!(
        declared_report["requiresIntegrations"],
        json!({"buildkite": {"as": "member"}, "mergify": {"as": "org"}})
    );
    for report in [&mut declared_report, &mut plain_report] {
        let object = report.as_object_mut().unwrap();
        object.remove("digest");
        object.remove("tree");
        object.remove("requiresIntegrations");
    }
    assert_eq!(declared_report, plain_report);

    let home = Home::new();
    let published = home.publish(&declared, &["--bindings", &declared.engineering_bindings()]);
    assert_eq!(published["revision"]["n"], 1);
    assert_eq!(published["definition"]["current"], 1);
}

// A stage file may override a token service the root declares, and overriding
// one the root does not declare is `integration_undeclared`.
#[test]
fn a_stage_file_overrides_a_token_service_only_when_the_root_declares_it() {
    let overriding =
        format!("{DESIGN_WORKFLOW}requires:\n  integrations:\n    mergify: {{as: org}}\n");
    let tree = Tree::with(
        &declaring_integrations("  integrations: {mergify: {}}\n"),
        &overriding,
    );
    let output = validate(tree.path(), true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");

    let (code, location) = single_rejection(
        &declaring_integrations("  integrations: {buildkite: {}}\n"),
        &overriding,
    );
    assert_eq!(code, "integration_undeclared");
    assert_eq!(location["path"], "design.yaml");
    assert_eq!(location["integration"], "mergify");
}

fn report_digest(output: &std::process::Output) -> String {
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    report(output)["digest"]["value"]
        .as_str()
        .expect("digest value should be text")
        .to_owned()
}

#[test]
fn a_root_with_a_workflow_step_validates_with_its_stage_file() {
    let steps = ROOT_WORKFLOW
        .find("steps:\n")
        .expect("the root fixture declares steps");
    let root = format!(
        "{}steps:\n  design:\n    kind: workflow\n    workflow: design.yaml\n    inputs:\n      ticket: {{ref: inputs.ticket}}\n    on:\n      succeeded: exit.landed\n      failed: exit.failed\noutcomes: [landed, failed]\n",
        &ROOT_WORKFLOW[..steps]
    );
    let tree = Tree::with(&root, DESIGN_WORKFLOW);
    let output = validate(tree.path(), true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = report(&output);
    assert_eq!(report["outcome"], "valid");
    assert_eq!(
        report["workflowFiles"],
        json!(["workflow.yaml", "design.yaml"])
    );
}

#[test]
fn root_only_block_in_a_stage_file_is_rejected() {
    let design = format!("{DESIGN_WORKFLOW}bindings:\n  team: {{kind: linear.team}}\n");
    let (code, location) = single_rejection(ROOT_WORKFLOW, &design);
    assert_eq!(code, "root_only_block_outside_root");
    assert_eq!(location["kind"], "workflow");
    assert_eq!(location["path"], "design.yaml");
    assert_eq!(location["key"], "bindings");
}

// A stage file may override integrations the root declares and no others; `Tree::with`'s root names
// `design.yaml` in no `workflow` step, so the check covers a file no step reaches.
#[test]
fn a_stage_file_overrides_only_integrations_the_root_declares() {
    let declaring = declaring_integrations("  integrations: {linear: {}, github: {}}\n");
    let overriding = |block: &str| format!("{DESIGN_WORKFLOW}requires:\n{block}");
    let assert_undeclared = |location: &Value, integration: &str| {
        assert_eq!(location["kind"], "workflow");
        assert_eq!(location["path"], "design.yaml");
        assert_eq!(location["key"], "requires");
        assert_eq!(location["integration"], integration);
    };

    let tree = Tree::with(
        &declaring,
        &overriding("  integrations:\n    linear: {as: org}\n"),
    );
    let output = validate(tree.path(), true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        report(&output)["workflowFiles"],
        json!(["workflow.yaml", "design.yaml"])
    );

    let codex = overriding("  integrations:\n    codex: {}\n");
    let (code, location) = single_rejection(&declaring, &codex);
    assert_eq!(code, "integration_undeclared");
    assert_undeclared(&location, "codex");
    let tree = Tree::with(&declaring, &codex);
    let human = validate(tree.path(), false);
    assert_eq!(human.status.code(), Some(1), "{human:?}");
    let stdout = String::from_utf8(human.stdout).expect("human output should be UTF-8");
    for expected in ["integration_undeclared", "design.yaml", "codex"] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in {stdout}"
        );
    }

    let (code, location) = single_rejection(
        ROOT_WORKFLOW,
        &overriding("  integrations:\n    linear: {}\n"),
    );
    assert_eq!(code, "integration_undeclared");
    assert_undeclared(&location, "linear");

    let tree = Tree::with(
        &declaring,
        &overriding("  integrations:\n    gitlab.com: {}\n    codex: {}\n"),
    );
    let codes = rejection_codes(tree.path());
    assert_eq!(codes.len(), 2, "{codes:?}");
    for ((code, location), integration) in codes.iter().zip(["codex", "gitlab.com"]) {
        assert_eq!(code, "integration_undeclared");
        assert_undeclared(location, integration);
    }

    let tree = Tree::with(&declaring, &overriding("  as: org\n"));
    let output = validate(tree.path(), true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");

    for block in [
        "  tools: [git]\n",
        "  tools: [git]\n  integrations:\n    linear: {}\n",
    ] {
        let (code, location) = single_rejection(&declaring, &overriding(block));
        assert_eq!(code, "root_only_block_outside_root");
        assert_eq!(location["path"], "design.yaml");
        assert_eq!(location["key"], "requires");
    }
}

#[test]
fn mirror_in_a_stage_file_is_rejected() {
    let design = format!("{DESIGN_WORKFLOW}mirror:\n  linear:\n    issue: inputs.ticket\n");
    let (code, location) = single_rejection(ROOT_WORKFLOW, &design);
    assert_eq!(code, "root_only_block_outside_root");
    assert_eq!(location["kind"], "workflow");
    assert_eq!(location["path"], "design.yaml");
    assert_eq!(location["key"], "mirror");
}

#[test]
fn a_structural_failure_names_the_field_and_the_rule_in_validate_and_publish() {
    assert!(ROOT_WORKFLOW.contains("\nname: engineering\n"));
    let tree = Tree::with(
        &ROOT_WORKFLOW.replacen("\nname: engineering\n", "\nname: grant-e2e\n", 1),
        DESIGN_WORKFLOW,
    );
    let expected = json!({
        "kind": "workflow",
        "field": "name",
        "rule": "pattern",
        "expected": "^[a-z][A-Za-z0-9]*$",
    });
    let assert_structural = |report: &Value| {
        let diagnostics = report["diagnostics"]
            .as_array()
            .expect("diagnostics should be a list");
        assert_eq!(diagnostics.len(), 1, "{report}");
        assert_eq!(diagnostics[0]["code"], "invalid_workflow_structure");
        assert_eq!(diagnostics[0]["location"]["path"], "workflow.yaml");
        assert_eq!(diagnostics[0]["workflowLocation"], expected);
        assert!(!report.to_string().contains("grant-e2e"), "{report}");
    };

    let output = validate(tree.path(), true);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_structural(&report(&output));

    let home = Home::new();
    let bindings = tree.engineering_bindings();
    let output = home.run(&["publish", tree.path(), "--bindings", &bindings, "--json"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report = report(&output);
    assert_eq!(report["command"], PUBLISH_COMMAND);
    assert_structural(&report);
    assert!(!home.root.join("workflows").exists());

    let human = validate(tree.path(), false);
    assert_eq!(human.status.code(), Some(1), "{human:?}");
    let stdout = String::from_utf8(human.stdout).expect("human output should be UTF-8");
    let line = stdout
        .lines()
        .find(|line| line.contains("invalid_workflow_structure"))
        .unwrap_or_else(|| panic!("{stdout}"));
    let (_, workflow_location) = line.split_once("; ").unwrap_or_else(|| panic!("{line}"));
    assert!(workflow_location.contains("name"), "{line}");
    assert!(workflow_location.contains("^[a-z][A-Za-z0-9]*$"), "{line}");
    assert!(!stdout.contains("grant-e2e"), "{stdout}");
}

#[test]
fn the_root_mirror_block_validates() {
    assert!(ROOT_WORKFLOW.contains("\nmirror:") && ROOT_WORKFLOW.contains("issue: inputs.ticket"));
    let tree = Tree::engineering();
    let output = validate(tree.path(), true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(report(&output)["outcome"], "valid");
}

/// The one rejection of the engineering root with `from` replaced by `to` once.
fn mirror_rejection(from: &str, to: &str) -> (String, Value) {
    assert!(ROOT_WORKFLOW.contains(from), "{from:?}");
    single_rejection(&ROOT_WORKFLOW.replacen(from, to, 1), DESIGN_WORKFLOW)
}

fn assert_mirror_location(location: &Value, key: &str) {
    assert_eq!(location["kind"], "mirror", "{location}");
    assert_eq!(location["key"], key, "{location}");
}

fn assert_outcome_location(location: &Value, key: &str, outcome: &str) {
    assert_mirror_location(location, key);
    assert_eq!(location["outcome"], outcome, "{location}");
}

#[test]
fn mirror_states_must_be_declared_linear_state_bindings() {
    let (code, location) = mirror_rejection("{state: $done}", "{state: Done}");
    assert_eq!(code, "invalid_workflow_structure");
    assert_eq!(location["kind"], "workflow");
    assert_eq!(location["path"], "workflow.yaml");

    let (code, location) = mirror_rejection("{state: $done}", "{state: $nope}");
    assert_eq!(code, "binding_undeclared");
    assert_outcome_location(&location, "onOutcome.state", "landed");
    assert_eq!(location["binding"], "nope");

    let (code, location) = mirror_rejection("{state: $done}", "{state: $linearTeam}");
    assert_eq!(code, "binding_kind_mismatch");
    assert_outcome_location(&location, "onOutcome.state", "landed");
    assert_eq!(location["binding"], "linearTeam");
}

/// The engineering root with its bindings declared under the integrations they belong to.
pub(super) const NESTED_ROOT: &str = include_str!(
    "../../crates/execution/tests/fixtures/workflow/v1/valid/root-integration-bindings.yaml"
);

/// The one rejection of the nested root with `from` replaced by `to` once.
fn nested_rejection(from: &str, to: &str) -> (String, Value) {
    assert!(NESTED_ROOT.contains(from), "{from:?}");
    single_rejection(&NESTED_ROOT.replacen(from, to, 1), DESIGN_WORKFLOW)
}

// Each integration's bindings are reported with it, `{kind, default?, required}` as a flat
// binding is, and a trigger's source as written.
#[test]
fn validate_reports_each_integrations_bindings_and_its_source() {
    let tree = Tree::nested();
    let report = valid_report(tree.path());
    let state = |default: &str| json!({"kind": "state", "default": default, "required": false});
    assert_eq!(
        report["requiresIntegrations"],
        json!({
            "github": {"bindings": {"repository": {"kind": "repository", "required": true}}},
            "linear": {"bindings": {
                "backlog": state("Backlog"),
                "canceled": state("Canceled"),
                "done": state("Done"),
                "ownedState": state("Engineering"),
                "team": {"kind": "team", "required": true},
            }},
        })
    );
    assert_eq!(report["bindings"], json!({}));
    assert_eq!(report["triggers"]["start"]["source"], "linear");
    assert_eq!(report["triggers"]["release"]["source"], "linear");

    let human = validate(tree.path(), false);
    assert_eq!(human.status.code(), Some(0), "{human:?}");
    let stdout = String::from_utf8(human.stdout).expect("human output should be UTF-8");
    let lines = stdout.lines().collect::<Vec<_>>();
    for expected in [
        ["linear.team", "team", "(required)"],
        ["linear.ownedState", "state", "(default \"Engineering\")"],
        ["github.repository", "repository", "(required)"],
    ] {
        assert!(
            lines
                .iter()
                .any(|line| expected.iter().all(|part| line.contains(part))),
            "missing {expected:?} in {stdout}"
        );
    }
    for trigger in ["start", "release"] {
        assert!(
            lines
                .iter()
                .any(|line| line.contains(&format!("{trigger}:")) && line.contains("on linear ")),
            "missing {trigger} on linear in {stdout}"
        );
    }
}

// A mirror state or guard names an integration binding as `$<id>.<name>`, of kind `state` under
// `linear`; a failure names the integration and the binding, and a flat key declared under an
// integration too is declared twice.
#[test]
fn mirror_states_and_guards_take_linear_state_integration_bindings() {
    let tree = Tree::nested();
    let output = validate(tree.path(), true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");

    let assert_reference = |location: &Value, integration: &str, binding: &str| {
        assert_eq!(location["integration"], integration, "{location}");
        assert_eq!(location["binding"], binding, "{location}");
    };
    let (code, location) = nested_rejection("{state: $linear.done}", "{state: $linear.team}");
    assert_eq!(code, "binding_kind_mismatch");
    assert_outcome_location(&location, "onOutcome.state", "landed");
    assert_reference(&location, "linear", "team");

    let (code, location) = nested_rejection("{state: $linear.done}", "{state: $github.repository}");
    assert_eq!(code, "binding_kind_mismatch");
    assert_reference(&location, "github", "repository");

    let (code, location) = nested_rejection("{state: $linear.done}", "{state: $linear.nope}");
    assert_eq!(code, "binding_undeclared");
    assert_reference(&location, "linear", "nope");

    let (code, location) = nested_rejection(
        "unless: issue.state != $linear.ownedState}",
        "unless: issue.state != $linear.team}",
    );
    assert_eq!(code, "binding_kind_mismatch");
    assert_outcome_location(&location, "onOutcome.unless", "withdrawn");
    assert_reference(&location, "linear", "team");

    let (code, location) = nested_rejection(
        "\ntriggers:",
        "\nbindings:\n  team: {kind: linear.team}\ntriggers:",
    );
    assert_eq!(code, "binding_declared_twice");
    assert_eq!(
        location,
        json!({"kind": "binding", "binding": "team", "integration": "linear"})
    );
}

#[test]
fn mirror_guards_follow_the_guard_grammar() {
    const GUARD: &str = "unless: issue.state != $ownedState}";
    let (code, location) = mirror_rejection(GUARD, "unless: 'issue.state != \"Engineering\"'}");
    assert_eq!(code, "literal_where_binding_expected");
    assert_outcome_location(&location, "onOutcome.unless", "withdrawn");

    let (code, location) = mirror_rejection(GUARD, "unless: issue.state = $ownedState}");
    assert_eq!(code, "mirror_guard_invalid");
    assert_outcome_location(&location, "onOutcome.unless", "withdrawn");

    let (code, location) = mirror_rejection(GUARD, "unless: issue.state == $linearTeam}");
    assert_eq!(code, "binding_kind_mismatch");
    assert_outcome_location(&location, "onOutcome.unless", "withdrawn");
    assert_eq!(location["binding"], "linearTeam");
}

#[test]
fn mirror_outcomes_must_be_outcomes_the_root_exits_with_other_than_superseded() {
    for outcome in ["superseded", "shipped"] {
        let (code, location) = mirror_rejection(
            "      landed:    {state: $done}\n",
            &format!("      landed:    {{state: $done}}\n      {outcome}: {{state: $backlog}}\n"),
        );
        assert_eq!(code, "mirror_outcome_undeclared");
        assert_outcome_location(&location, "onOutcome", outcome);
    }
}

#[test]
fn mirror_templates_name_only_their_hooks_variables() {
    const START: &str = "Engineering started by {{operator}}. Run: {{run.url}}";
    for template in ["{{stage}}", "{{nope}}", "{{ operator }}"] {
        let (code, location) = mirror_rejection(START, template);
        assert_eq!(code, "mirror_variable_unknown", "{template}");
        assert_mirror_location(&location, "onStart.comment");
    }
    let (code, location) = mirror_rejection("{{wait.kind}}", "{{summary}}");
    assert_eq!(code, "mirror_variable_unknown");
    assert_mirror_location(&location, "onWait.comment");
}

// `operator`, `run.id`, `run.url` and `run.reference` are every hook's.
#[test]
fn mirror_templates_name_the_operator_and_the_run_in_every_hook() {
    const EVERY_HOOK: &str = "{{operator}} {{run.id}} {{run.url}} {{run.reference}}";
    let mut root = ROOT_WORKFLOW.to_owned();
    for template in [
        "Engineering started by {{operator}}. Run: {{run.url}}",
        "{{stage}}: {{summary}}",
        "Waiting for {{wait.kind}}: {{wait.summary}}",
    ] {
        assert!(root.contains(template), "{template:?}");
        root = root.replacen(template, EVERY_HOOK, 1);
    }
    let tree = Tree::with(&root, DESIGN_WORKFLOW);
    let output = validate(tree.path(), true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(report(&output)["outcome"], "valid");
}

#[test]
fn the_mirror_issue_names_a_declared_text_input() {
    let (code, location) = mirror_rejection("issue: inputs.ticket", "issue: inputs.policy");
    assert_eq!(code, "mirror_issue_input_not_text");
    assert_mirror_location(&location, "issue");
    assert_eq!(location["input"], "policy");

    let (code, location) = mirror_rejection("issue: inputs.ticket", "issue: inputs.nothing");
    assert_eq!(code, "mirror_issue_input_undeclared");
    assert_mirror_location(&location, "issue");
    assert_eq!(location["input"], "nothing");
}

#[test]
fn subject_in_a_stage_file_is_rejected() {
    let design = format!("{DESIGN_WORKFLOW}subject: ticket\n");
    let (code, location) = single_rejection(ROOT_WORKFLOW, &design);
    assert_eq!(code, "root_only_block_outside_root");
    assert_eq!(location["kind"], "workflow");
    assert_eq!(location["path"], "design.yaml");
    assert_eq!(location["key"], "subject");
}

#[test]
fn a_command_program_named_by_path_is_rejected_with_its_file_and_step() {
    let design = DESIGN_WORKFLOW.replacen("design.py", "./scripts/design.py", 1);
    let (code, location) = single_rejection(ROOT_WORKFLOW, &design);
    assert_eq!(code, "command_program_is_path");
    assert_eq!(location["kind"], "workflow");
    assert_eq!(location["path"], "design.yaml");
    assert_eq!(location["step"], "design");
    assert_eq!(location["key"], "command.argv");
}

#[test]
fn trigger_rules_must_name_declared_bindings_of_the_right_kind() {
    let literal = ROOT_WORKFLOW.replacen(
        &format!("\"{START_WHERE}\""),
        "'event.team == $linearTeam and event.state == \"Engineering\"'",
        1,
    );
    let (code, location) = single_rejection(&literal, DESIGN_WORKFLOW);
    assert_eq!(code, "literal_where_binding_expected");
    assert_eq!(location["kind"], "trigger");
    assert_eq!(location["trigger"], "start");

    let mismatched = ROOT_WORKFLOW.replacen("source: $connection", "source: $linearTeam", 1);
    let (code, location) = single_rejection(&mismatched, DESIGN_WORKFLOW);
    assert_eq!(code, "binding_kind_mismatch");
    assert_eq!(location["trigger"], "start");
    assert_eq!(location["binding"], "linearTeam");

    let undeclared = ROOT_WORKFLOW.replacen("$ownedState\"", "$nobody\"", 1);
    let (code, location) = single_rejection(&undeclared, DESIGN_WORKFLOW);
    assert_eq!(code, "binding_undeclared");
    assert_eq!(location["trigger"], "start");
    assert_eq!(location["binding"], "nobody");
}

// A definition trigger's input reads only what a finished run's event holds, and the
// event's attempt is not among it.
#[test]
fn a_definition_trigger_input_must_read_what_a_runs_event_holds() {
    let from = "ticket: event.exports.repairRequest";
    let root = definition_trigger_root("{definition: $verify, outcome: [broken, failed]}");
    assert!(root.contains(from), "{from}");
    let attempt = root.replacen(from, "ticket: event.attempt", 1);
    let (code, location) = single_rejection(&attempt, DESIGN_WORKFLOW);
    assert_eq!(code, "definition_trigger_invalid");
    assert_eq!(location["trigger"], "repairMain");
    assert_eq!(location["key"], "inputs");
    assert_eq!(location["input"], "ticket");
}

// A trigger rule outside the grammar that evaluates it is refused, the start `where`
// against Cloud's and the control `when` against the wait's.
#[test]
fn trigger_rules_outside_their_grammar_are_refused() {
    let unequal = ROOT_WORKFLOW.replacen(
        &format!("\"{START_WHERE}\""),
        "\"event.team != $linearTeam and event.state == $ownedState\"",
        1,
    );
    let (code, location) = single_rejection(&unequal, DESIGN_WORKFLOW);
    assert_eq!(code, "trigger_rule_invalid");
    assert_eq!(location["kind"], "trigger");
    assert_eq!(location["trigger"], "start");
    assert_eq!(location["key"], "on.where");

    let disjunction = ROOT_WORKFLOW.replacen(
        "\"event.to == $canceled\"",
        "\"event.to == $canceled or event.to == $done\"",
        1,
    );
    let (code, location) = single_rejection(&disjunction, DESIGN_WORKFLOW);
    assert_eq!(code, "trigger_rule_invalid");
    assert_eq!(location["trigger"], "release");
    assert_eq!(location["key"], "control.action.when");
}

#[test]
fn start_trigger_inputs_must_match_the_root_inputs() {
    let missing = ROOT_WORKFLOW.replacen("      ticket:     event.issue.identifier\n", "", 1);
    let (code, location) = single_rejection(&missing, DESIGN_WORKFLOW);
    assert_eq!(code, "trigger_input_missing");
    assert_eq!(location["trigger"], "start");
    assert_eq!(location["input"], "ticket");

    let undeclared = ROOT_WORKFLOW.replacen(
        "      baseBranch: \"main\"\n",
        "      baseBranch: \"main\"\n      extra: event.issue.title\n",
        1,
    );
    let (code, location) = single_rejection(&undeclared, DESIGN_WORKFLOW);
    assert_eq!(code, "trigger_input_undeclared");
    assert_eq!(location["input"], "extra");
}

#[test]
fn programs_must_name_tree_directories() {
    let root = ROOT_WORKFLOW.replacen("programs: [scripts]", "programs: [bin]", 1);
    let (code, location) = single_rejection(&root, DESIGN_WORKFLOW);
    assert_eq!(code, "program_directory_missing");
    assert_eq!(location["kind"], "program");
    assert_eq!(location["program"], "bin");
}

#[test]
fn tree_entries_must_be_regular_and_the_root_must_exist() {
    let tree = Tree::engineering();
    symlink(
        tree.root.join("policy/engineering.json"),
        tree.root.join("scripts/policy.json"),
    )
    .expect("symbolic link should be created");
    let codes = rejection_codes(tree.path());
    assert_eq!(codes.len(), 1, "{codes:?}");
    assert_eq!(codes[0].0, "tree_entry_not_regular");
    assert_eq!(codes[0].1["kind"], "tree");
    assert_eq!(codes[0].1["path"], "scripts/policy.json");

    let empty = tempfile::tempdir().expect("temporary directory should be created");
    let codes = rejection_codes(
        empty
            .path()
            .to_str()
            .expect("temporary directory should be UTF-8"),
    );
    assert_eq!(codes.len(), 1, "{codes:?}");
    assert_eq!(codes[0].0, "tree_root_missing");
}

// Linux only: other platforms' file systems refuse to create a name that is not UTF-8.
#[cfg(target_os = "linux")]
#[test]
fn a_non_utf8_path_and_a_tree_over_64_mib_are_refused() {
    use std::os::unix::ffi::OsStrExt;

    let tree = Tree::engineering();
    fs::write(
        tree.root
            .join("scripts")
            .join(std::ffi::OsStr::from_bytes(b"\xffnotes.txt")),
        "notes\n",
    )
    .expect("non-UTF-8 file should be written");
    let codes = rejection_codes(tree.path());
    assert_eq!(codes.len(), 1, "{codes:?}");
    assert_eq!(codes[0].0, "invalid_canonical_path");

    let tree = Tree::engineering();
    fs::File::create(tree.root.join("policy/large.bin"))
        .and_then(|file| file.set_len(64 * 1024 * 1024 + 1))
        .expect("sparse large file should be created");
    let codes = rejection_codes(tree.path());
    assert_eq!(codes.len(), 1, "{codes:?}");
    assert_eq!(codes[0].0, "tree_too_large");
    assert_eq!(codes[0].1["kind"], "tree");
}

// SC-WFDEF-1: a root-only block in a stage file the root runs through a `workflow` step fails
// the root at that step, and the root's failure is listed alone, without the start trigger's own
// failure.
#[test]
fn a_root_only_block_in_a_reached_stage_file_fails_the_root_alone() {
    let steps = ROOT_WORKFLOW
        .find("steps:\n")
        .expect("the root fixture declares steps");
    let root = format!(
        "{}steps:\n  design:\n    kind: workflow\n    workflow: design.yaml\n    inputs:\n      ticket: {{ref: inputs.ticket}}\n    on:\n      succeeded: exit.landed\n      failed: exit.failed\noutcomes: [landed, failed]\n",
        &ROOT_WORKFLOW[..steps]
    )
    .replacen(
        &format!("\"{START_WHERE}\""),
        "'event.team == $linearTeam and event.state == \"Engineering\"'",
        1,
    );
    let design = format!("{DESIGN_WORKFLOW}bindings:\n  team: {{kind: linear.team}}\n");
    let tree = Tree::with(&root, &design);
    let codes = rejection_codes(tree.path());
    assert_eq!(codes.len(), 1, "{codes:?}");
    assert_eq!(codes[0].0, "child_workflow_root_blocks");
    assert_eq!(codes[0].1["kind"], "workflow");
    assert_eq!(codes[0].1["path"], "workflow.yaml");
}

// `Tree::with`'s root names `design.yaml` in no `workflow` step, so the stage file's
// own failure is listed beside the root's.
#[test]
fn every_failure_in_a_tree_is_listed() {
    let root = ROOT_WORKFLOW.replacen(
        &format!("\"{START_WHERE}\""),
        "'event.team == $linearTeam and event.state == \"Engineering\"'",
        1,
    );
    let design = format!("{DESIGN_WORKFLOW}bindings:\n  team: {{kind: linear.team}}\n");
    let tree = Tree::with(&root, &design);
    let codes = rejection_codes(tree.path());
    let codes = codes
        .iter()
        .map(|(code, location)| (code.as_str(), location))
        .collect::<Vec<_>>();
    assert_eq!(codes.len(), 2, "{codes:?}");
    assert!(codes.iter().any(|(code, location)| {
        *code == "root_only_block_outside_root" && location["path"] == "design.yaml"
    }));
    assert!(codes.iter().any(|(code, location)| {
        *code == "literal_where_binding_expected" && location["trigger"] == "start"
    }));

    let human = validate(tree.path(), false);
    assert_eq!(human.status.code(), Some(1), "{human:?}");
    assert_no_content(&human);
    let stdout = String::from_utf8(human.stdout).expect("human output should be UTF-8");
    assert!(
        stdout.starts_with("✗ Workflow tree is invalid."),
        "{stdout}"
    );
    assert!(stdout.contains("root_only_block_outside_root"), "{stdout}");
    assert!(
        stdout.contains("literal_where_binding_expected"),
        "{stdout}"
    );
}

const PUBLISH_COMMAND: &str = "useful workflow definition publish";

/// An empty `useful` home in a temporary directory, passed to a command as `USEFUL_HOME`.
pub(super) struct Home {
    _temporary: TempDir,
    root: PathBuf,
}

impl Home {
    pub(super) fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary home should be created");
        let root = temporary.path().join("home");
        Self {
            _temporary: temporary,
            root,
        }
    }

    pub(super) fn path(&self) -> &str {
        self.root
            .to_str()
            .expect("temporary home path should be UTF-8")
    }

    /// Runs `useful workflow definition ARGS` offline against this home.
    fn run(&self, args: &[&str]) -> std::process::Output {
        let mut full = vec!["workflow", "definition"];
        full.extend_from_slice(args);
        run_offline(&full, &[("USEFUL_HOME", self.path())])
    }

    /// `useful workflow definition publish DIR ARGS --json`, asserting it publishes; the report.
    pub(super) fn publish(&self, tree: &Tree, args: &[&str]) -> Value {
        let mut full = vec!["publish", tree.path()];
        full.extend_from_slice(args);
        let report = self.json(&full);
        assert_eq!(report["outcome"], "published", "{report}");
        report
    }

    /// `useful workflow definition publish DIR ARGS --json`, asserting it is refused with `code`;
    /// the one diagnostic.
    fn refused(&self, tree: &Tree, args: &[&str], code: &str) -> Value {
        let mut full = vec!["publish", tree.path()];
        full.extend_from_slice(args);
        self.refused_command(&full, PUBLISH_COMMAND, code)
    }

    pub(super) fn definition_directory(&self, id: &str) -> PathBuf {
        self.root.join("workflows").join(id)
    }

    fn workflow_entries(&self) -> Vec<String> {
        match fs::read_dir(self.root.join("workflows")) {
            Ok(entries) => entries
                .map(|entry| {
                    entry
                        .expect("home entry should be readable")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => panic!("home workflows should be readable: {error}"),
        }
    }

    /// No command here creates a run under the home or a definition.
    pub(super) fn assert_no_runs(&self) {
        assert!(!self.root.join("runs").exists());
        for id in self.workflow_entries() {
            assert!(!self.definition_directory(&id).join("runs").exists());
        }
    }
}

impl Tree {
    /// Writes `value` as a bindings file beside the tree, outside its digest.
    fn bindings_file(&self, file: &str, value: &Value) -> String {
        let path = self
            .root
            .parent()
            .expect("tree should have a parent")
            .join(file);
        fs::write(
            &path,
            serde_json::to_vec(value).expect("bindings should encode"),
        )
        .expect("bindings file should be written");
        path.to_str()
            .expect("temporary bindings path should be UTF-8")
            .to_owned()
    }

    pub(super) fn engineering_bindings(&self) -> String {
        self.bindings_file(
            "auto.json",
            &json!({
                "connection": "local",
                "linearTeam": "AUTO",
                "repository": "useful-machinery/platform",
            }),
        )
    }

    /// The engineering tree whose root declares its bindings under its integrations.
    pub(super) fn nested() -> Self {
        Self::with(NESTED_ROOT, DESIGN_WORKFLOW)
    }

    /// Writes `nested_bindings()` beside the tree: the bindings file of `nested`.
    pub(super) fn nested_bindings(&self) -> String {
        self.bindings_file("nested.json", &nested_bindings())
    }
}

/// The values of the nested root's bindings without a default, under their integrations.
pub(super) fn nested_bindings() -> Value {
    json!({
        "linear": {"team": "AUTO"},
        "github": {"repository": "useful-machinery/platform"},
    })
}

fn is_definition_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("def_") else {
        return false;
    };
    rest.len() == 26
        && rest.starts_with(|first: char| ('0'..='7').contains(&first))
        && rest.bytes().all(|byte| {
            byte.is_ascii_digit()
                || (byte.is_ascii_lowercase() && !matches!(byte, b'i' | b'l' | b'o' | b'u'))
        })
}

fn text<'a>(value: &'a Value, what: &str) -> &'a str {
    value
        .as_str()
        .unwrap_or_else(|| panic!("{what} should be text: {value}"))
}

pub(super) fn schema(file: &str) -> jsonschema::Validator {
    let path = crate::fixture_root().join("schemas").join(file);
    let schema: Value = serde_json::from_slice(&fs::read(path).expect("schema should be readable"))
        .expect("schema should be JSON");
    jsonschema::draft202012::new(&schema).expect("schema should compile")
}

pub(super) fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("record should be readable"))
        .expect("record should be JSON")
}

#[test]
fn publish_records_a_revision_with_its_tree_copy_and_carries_bindings_forward() {
    let home = Home::new();
    let tree = Tree::engineering();
    let digest = format!("sha256:{}", report_digest(&validate(tree.path(), true)));
    let bindings = tree.engineering_bindings();

    let first = home.publish(&tree, &["--bindings", &bindings]);
    assert_eq!(first["schemaVersion"], 1);
    assert_eq!(first["command"], PUBLISH_COMMAND);
    let id = text(&first["definition"]["id"], "definition id").to_owned();
    assert!(is_definition_id(&id), "{id}");
    assert_eq!(first["definition"]["name"], "engineering");
    assert_eq!(first["definition"]["enabled"], true);
    assert_eq!(first["definition"]["current"], 1);
    assert_eq!(first["definition"]["created"], true);
    assert_eq!(
        Path::new(text(&first["definition"]["path"], "definition path")),
        home.definition_directory(&id)
    );
    assert_eq!(first["revision"]["n"], 1);
    assert_eq!(first["revision"]["tree"], digest.as_str());
    let bindings_digest = text(&first["revision"]["bindings"], "bindings digest").to_owned();
    assert!(
        bindings_digest
            .strip_prefix("sha256:")
            .is_some_and(|hex| hex.len() == 64),
        "{bindings_digest}"
    );
    time::OffsetDateTime::parse(
        text(&first["revision"]["publishedAt"], "publish time"),
        &time::format_description::well_known::Rfc3339,
    )
    .expect("publish time should be RFC 3339");
    assert!(first["revision"]["by"].is_string());

    let definition = home.definition_directory(&id);
    let record = read_json(&definition.join("definition.json"));
    assert!(
        schema("workflow-definition-v1.schema.json").is_valid(&record),
        "{record}"
    );
    let snapshot = read_json(&definition.join("revisions/1/bindings.json"));
    assert!(
        schema("workflow-definition-bindings-v1.schema.json").is_valid(&snapshot),
        "{snapshot}"
    );
    let copy = home
        .root
        .join("trees/sha256")
        .join(digest.trim_start_matches("sha256:"));
    assert!(copy.join("scripts/design.py").is_file());
    assert!(!copy.join("tests").exists());

    let second = home.publish(&tree, &[]);
    assert_eq!(second["definition"]["id"], id.as_str());
    assert_eq!(second["definition"]["created"], false);
    assert_eq!(second["definition"]["current"], 2);
    assert_eq!(second["revision"]["n"], 2);
    assert_eq!(second["revision"]["tree"], digest.as_str());
    assert_eq!(second["revision"]["bindings"], bindings_digest.as_str());

    let human = home.run(&["publish", tree.path()]);
    assert_eq!(human.status.code(), Some(0), "{human:?}");
    assert_no_content(&human);
    let stdout = String::from_utf8(human.stdout).expect("human output should be UTF-8");
    for expected in [
        id.as_str(),
        "engineering",
        "3",
        digest.as_str(),
        bindings_digest.as_str(),
    ] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in {stdout}"
        );
    }
    assert_eq!(home.workflow_entries(), vec![id]);
    home.assert_no_runs();
}

#[test]
fn publish_resolves_the_definition_by_name_or_refuses() {
    let home = Home::new();
    let unnamed = Tree::with(
        &ROOT_WORKFLOW.replacen("name: engineering\n", "", 1),
        DESIGN_WORKFLOW,
    );
    let bindings = unnamed.engineering_bindings();
    home.refused(
        &unnamed,
        &["--bindings", &bindings],
        "definition_name_missing",
    );
    assert!(home.workflow_entries().is_empty());

    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let first = home.publish(&tree, &["--bindings", &bindings]);
    let first_id = text(&first["definition"]["id"], "definition id").to_owned();
    let canary = home.publish(&tree, &["--new", "--bindings", &bindings]);
    assert_eq!(canary["definition"]["created"], true);
    assert_eq!(canary["revision"]["n"], 1);
    let canary_id = text(&canary["definition"]["id"], "definition id").to_owned();
    assert_ne!(first_id, canary_id);

    let ambiguous = home.refused(&tree, &[], "definition_name_ambiguous");
    let mut both = vec![first_id.clone(), canary_id.clone()];
    both.sort();
    assert_eq!(ambiguous["definitions"], json!(both));

    let human = home.run(&["publish", tree.path()]);
    assert_eq!(human.status.code(), Some(1), "{human:?}");
    let stdout = String::from_utf8(human.stdout).expect("human output should be UTF-8");
    for expected in ["definition_name_ambiguous", &first_id, &canary_id] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in {stdout}"
        );
    }

    let unknown = "def_01jzzzzzzzzzzzzzzzzzzzzzzz";
    let not_found = home.refused(&tree, &["--to", unknown], "definition_not_found");
    assert_eq!(not_found["definition"], unknown);

    let targeted = home.publish(&tree, &["--to", &first_id]);
    assert_eq!(targeted["definition"]["id"], first_id.as_str());
    assert_eq!(targeted["revision"]["n"], 2);

    let usage = home.run(&["publish", tree.path(), "--to", &first_id, "--new", "--json"]);
    assert_eq!(usage.status.code(), Some(2), "{usage:?}");
    assert!(usage.stdout.is_empty(), "{usage:?}");
    home.assert_no_runs();
}

#[test]
fn publish_of_an_invalid_tree_reports_it_and_writes_nothing() {
    let home = Home::new();
    let design = format!("{DESIGN_WORKFLOW}bindings:\n  team: {{kind: linear.team}}\n");
    let tree = Tree::with(ROOT_WORKFLOW, &design);
    let bindings = tree.engineering_bindings();
    let output = home.run(&["publish", tree.path(), "--bindings", &bindings, "--json"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_no_content(&output);
    let report = report(&output);
    assert_eq!(report["command"], PUBLISH_COMMAND);
    assert_eq!(report["outcome"], "invalid");
    assert!(report["tree"]["path"].is_string());
    assert!(
        report["diagnostics"]
            .as_array()
            .expect("diagnostics should be a list")
            .iter()
            .any(|diagnostic| diagnostic["code"] == "root_only_block_outside_root"),
        "{report}"
    );
    assert!(!home.root.join("workflows").exists());
    home.assert_no_runs();
}

#[test]
fn publish_refuses_missing_or_unusable_bindings() {
    let home = Home::new();
    let tree = Tree::engineering();
    home.refused(&tree, &[], "bindings_required");

    let partial = tree.bindings_file(
        "partial.json",
        &json!({"connection": "local", "linearTeam": "AUTO"}),
    );
    let missing = home.refused(&tree, &["--bindings", &partial], "binding_missing");
    assert_eq!(missing["binding"], "repository");
    assert!(missing.get("integration").is_none(), "{missing}");

    let absent = tree
        .root
        .parent()
        .expect("tree should have a parent")
        .join("absent.json");
    let absent = absent.to_str().expect("temporary path should be UTF-8");
    let unreadable = home.refused(&tree, &["--bindings", absent], "bindings_file_invalid");
    assert_eq!(unreadable["path"], absent);

    assert!(home.workflow_entries().is_empty());
    home.assert_no_runs();
}

#[test]
fn a_later_publish_with_a_partial_bindings_file_changes_only_what_it_names() {
    let home = Home::new();
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let first = home.publish(&tree, &["--bindings", &bindings]);
    let id = text(&first["definition"]["id"], "definition id").to_owned();
    let original = home.json(&["show", &id])["bindings"].clone();

    let partial = tree.bindings_file(
        "partial.json",
        &json!({"linearTeam": "ENG", "done": "Shipped"}),
    );
    home.publish(&tree, &["--bindings", &partial]);
    let mut expected = original.clone();
    expected["linearTeam"]["value"] = json!("ENG");
    expected["done"]["value"] = json!("Shipped");
    assert_eq!(home.json(&["show", &id])["bindings"], expected);

    let reset = tree.bindings_file("reset.json", &json!({"done": null}));
    home.publish(&tree, &["--bindings", &reset]);
    let shown = home.json(&["show", &id]);
    assert_eq!(shown["bindings"]["done"], original["done"]);
    assert_eq!(shown["bindings"]["done"]["value"], "Done");
    assert_eq!(shown["bindings"]["linearTeam"]["value"], "ENG");

    let without_default = tree.bindings_file("repository.json", &json!({"repository": null}));
    let missing = home.refused(&tree, &["--bindings", &without_default], "binding_missing");
    assert_eq!(missing["binding"], "repository");
    assert_eq!(
        home.json(&["show", &id])["definition"]["current"],
        shown["definition"]["current"]
    );
    home.assert_no_runs();
}

// Integration bindings nested under their id are published, shown as `<id>.<name>`, and a refusal
// about one names the integration.
#[test]
fn integration_bindings_are_published_shown_and_refused_by_integration() {
    let home = Home::new();
    let tree = Tree::nested();

    let without_team = tree.bindings_file(
        "without-team.json",
        &json!({"github": {"repository": "useful-machinery/platform"}}),
    );
    let missing = home.refused(&tree, &["--bindings", &without_team], "binding_missing");
    assert_eq!(missing["integration"], "linear", "{missing}");
    assert_eq!(missing["binding"], "team", "{missing}");
    let human = home.human(&["publish", tree.path(), "--bindings", &without_team], 1);
    let code_line = human
        .lines()
        .find(|line| line.starts_with("code: binding_missing"))
        .unwrap_or_else(|| panic!("missing the code line in {human}"));
    assert_contains_all(code_line, &["linear", "team"]);

    let bare = tree.bindings_file(
        "bare.json",
        &json!({"linear": "AUTO", "github": {"repository": "useful-machinery/platform"}}),
    );
    let invalid = home.refused(&tree, &["--bindings", &bare], "bindings_file_invalid");
    assert_eq!(invalid["path"], bare.as_str(), "{invalid}");
    assert_eq!(invalid["integration"], "linear", "{invalid}");
    assert!(invalid.get("binding").is_none(), "{invalid}");
    assert!(home.workflow_entries().is_empty());

    let nested = tree.nested_bindings();
    let published = home.publish(&tree, &["--bindings", &nested]);
    let id = text(&published["definition"]["id"], "definition id").to_owned();
    let snapshot = read_json(
        &home
            .definition_directory(&id)
            .join("revisions/1/bindings.json"),
    );
    assert!(
        schema("workflow-definition-bindings-v2.schema.json").is_valid(&snapshot),
        "{snapshot}"
    );
    assert_eq!(home.json(&["show", &id])["bindings"], snapshot);
    assert_contains_all(
        &home.human(&["show", &id], 0),
        &[
            "linear.team: AUTO (team)",
            "linear.ownedState: Engineering (state)",
            "github.repository: useful-machinery/platform (repository)",
        ],
    );
    home.assert_no_runs();
}

const MEMBER_ROOT: &str = r#"schemaVersion: 1
name: owners
bindings:
  includedOwners: {kind: members, default: []}
  reviewers: {kind: members, default: ["prn_a", "prn_b"]}
  nightlyOwner: {kind: member}
steps:
  prepare:
    kind: cmd
    command:
      argv: ["true"]
"#;

// `member` and `members` bindings are reported with their defaults as declared and shown
// with their values as bound, a list kept a list.
#[test]
fn member_bindings_are_reported_and_shown_as_typed_values() {
    let tree = Tree::with(MEMBER_ROOT, DESIGN_WORKFLOW);
    let output = validate(tree.path(), true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        report(&output)["bindings"],
        json!({
            "includedOwners": {"kind": "members", "default": [], "required": false},
            "reviewers": {"kind": "members", "default": ["prn_a", "prn_b"], "required": false},
            "nightlyOwner": {"kind": "member", "required": true},
        })
    );
    let human = validate(tree.path(), false);
    assert_eq!(human.status.code(), Some(0), "{human:?}");
    assert_contains_all(
        &String::from_utf8(human.stdout).expect("human output should be UTF-8"),
        &[
            "includedOwners: members (default [])",
            "reviewers: members (default [\"prn_a\", \"prn_b\"])",
            "nightlyOwner: member (required)",
        ],
    );

    let home = Home::new();
    let string_for_members = tree.bindings_file(
        "string.json",
        &json!({"nightlyOwner": "prn_x", "includedOwners": "prn_a"}),
    );
    let refused = home.refused(
        &tree,
        &["--bindings", &string_for_members],
        "binding_value_invalid",
    );
    assert_eq!(refused["binding"], "includedOwners");

    let owners = tree.bindings_file(
        "owners.json",
        &json!({"nightlyOwner": "prn_x", "includedOwners": ["prn_a"]}),
    );
    let published = home.publish(&tree, &["--bindings", &owners]);
    let id = text(&published["definition"]["id"], "definition id").to_owned();
    let shown = home.json(&["show", &id]);
    assert_eq!(
        shown["bindings"],
        json!({
            "includedOwners": {"kind": "members", "value": ["prn_a"]},
            "reviewers": {"kind": "members", "value": ["prn_a", "prn_b"]},
            "nightlyOwner": {"kind": "member", "value": "prn_x"},
        })
    );
    assert_contains_all(
        &home.human(&["show", &id], 0),
        &[
            "includedOwners: [\"prn_a\"] (members)",
            "nightlyOwner: prn_x (member)",
        ],
    );
}

const BINDING_VALUE_SENTINEL: &str = "unique-binding-value-sentinel";

// `--binding KEY=VALUE` and `--binding-default KEY` each name one binding, flat or
// `<integration>.<name>`, in place of the file's member for it; every other binding keeps the
// current revision's value. A refusal names the binding and never the value, and a malformed
// or repeated `KEY` is a usage error that writes nothing.
#[test]
fn binding_options_name_one_binding_each_beside_the_file() {
    let nested = Tree::nested();
    let by_file = Home::new();
    let file = nested.nested_bindings();
    let from_file = by_file.publish(&nested, &["--bindings", &file]);
    let file_id = text(&from_file["definition"]["id"], "definition id").to_owned();
    let expected = by_file.json(&["show", &file_id])["bindings"].clone();

    let home = Home::new();
    let published = home.publish(
        &nested,
        &[
            "--binding",
            "linear.team=AUTO",
            "--binding",
            "github.repository=useful-machinery/platform",
        ],
    );
    let id = text(&published["definition"]["id"], "definition id").to_owned();
    assert_eq!(home.json(&["show", &id])["bindings"], expected);

    home.publish(&nested, &["--binding", "linear.ownedState=Doing"]);
    let mut doing = expected.clone();
    doing["linear"]["ownedState"]["value"] = json!("Doing");
    assert_eq!(home.json(&["show", &id])["bindings"], doing);
    home.publish(&nested, &["--binding-default", "linear.ownedState"]);
    let shown = home.json(&["show", &id]);
    assert_eq!(shown["bindings"], expected);

    // A refusal leaves `current` as it was and prints no value, in either form.
    let refuse = |home: &Home, tree: &Tree, args: &[&str], code: &str| {
        let diagnostic = home.refused(tree, args, code);
        assert!(
            !diagnostic.to_string().contains(BINDING_VALUE_SENTINEL),
            "{diagnostic}"
        );
        let mut human = vec!["publish", tree.path()];
        human.extend_from_slice(args);
        let output = home.run(&human);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        for stream in [&output.stdout, &output.stderr] {
            assert!(!String::from_utf8_lossy(stream).contains(BINDING_VALUE_SENTINEL));
        }
        diagnostic
    };
    let undeclared_value = format!("nope={BINDING_VALUE_SENTINEL}");
    let undeclared = refuse(
        &home,
        &nested,
        &["--binding", &undeclared_value],
        "binding_undeclared",
    );
    assert_eq!(undeclared["binding"], "nope", "{undeclared}");
    assert!(undeclared.get("integration").is_none(), "{undeclared}");
    let under_linear = format!("linear.nope={BINDING_VALUE_SENTINEL}");
    let undeclared = refuse(
        &home,
        &nested,
        &["--binding", &under_linear],
        "binding_undeclared",
    );
    assert_eq!(undeclared["integration"], "linear", "{undeclared}");
    assert_eq!(undeclared["binding"], "nope", "{undeclared}");
    let undeclared = refuse(
        &home,
        &nested,
        &["--binding-default", "nope"],
        "binding_undeclared",
    );
    assert_eq!(undeclared["binding"], "nope", "{undeclared}");
    assert_eq!(
        home.json(&["show", &id])["definition"]["current"],
        shown["definition"]["current"]
    );

    let owners_tree = Tree::with(MEMBER_ROOT, DESIGN_WORKFLOW);
    let owners = Home::new();
    let owners_file = owners_tree.bindings_file(
        "owners.json",
        &json!({"nightlyOwner": "prn_x", "includedOwners": ["prn_a"]}),
    );
    let published = owners.publish(
        &owners_tree,
        &[
            "--bindings",
            &owners_file,
            "--binding",
            "nightlyOwner=prn_y",
            "--binding",
            "includedOwners=prn_a,prn_b",
        ],
    );
    let owners_id = text(&published["definition"]["id"], "definition id").to_owned();
    let owners_bindings = |home: &Home| home.json(&["show", &owners_id])["bindings"].clone();
    let shown = owners_bindings(&owners);
    assert_eq!(shown["nightlyOwner"]["value"], "prn_y");
    assert_eq!(shown["includedOwners"]["value"], json!(["prn_a", "prn_b"]));
    owners.publish(&owners_tree, &["--binding-default", "includedOwners"]);
    assert_eq!(
        owners_bindings(&owners)["includedOwners"]["value"],
        json!([])
    );
    owners.publish(&owners_tree, &["--binding", "includedOwners=prn_c"]);
    owners.publish(&owners_tree, &["--binding", "includedOwners="]);
    let shown = owners_bindings(&owners);
    assert_eq!(shown["includedOwners"]["value"], json!([]));
    assert_eq!(shown["nightlyOwner"]["value"], "prn_y");

    let current = owners.json(&["show", &owners_id])["definition"]["current"].clone();
    for (option, binding) in [
        ("nightlyOwner=", "nightlyOwner"),
        ("includedOwners=prn_a,,prn_b", "includedOwners"),
    ] {
        let invalid = refuse(
            &owners,
            &owners_tree,
            &["--binding", option],
            "binding_value_invalid",
        );
        assert_eq!(invalid["binding"], binding, "{invalid}");
    }
    assert_eq!(
        owners.json(&["show", &owners_id])["definition"]["current"],
        current
    );

    let engineering = Tree::engineering();
    let fresh = Home::new();
    let repeated = format!("connection={BINDING_VALUE_SENTINEL}");
    for args in [
        vec!["--binding", "connection"],
        vec!["--binding", &repeated, "--binding", "connection=b"],
        vec!["--binding", &repeated, "--binding-default", "connection"],
        vec!["--binding-default", "done", "--binding-default", "done"],
    ] {
        let mut full = vec!["publish", engineering.path()];
        full.extend_from_slice(&args);
        full.push("--json");
        let output = fresh.run(&full);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains(BINDING_VALUE_SENTINEL),
            "{args:?}: {output:?}"
        );
    }
    assert!(fresh.workflow_entries().is_empty());
    fresh.assert_no_runs();
}

/// The engineering root with a start policy on `start` and a `nightly` schedule trigger that
/// queues the latest start while its subject is busy.
fn start_policy_root() -> String {
    let replacements = [
        (
            "  repository:      {kind: github.repository}\n",
            "  repository:      {kind: github.repository}\n  includedOwners:  {kind: members, default: []}\n  nightlyOwner:    {kind: member, default: \"prn_n\"}\n",
        ),
        (
            "and event.state == $ownedState\"}\n    subject:",
            "and event.state == $ownedState and event.issue.blocked == false\"}\n    stopBefore: {labels: event.issue.labels, prefix: \"hold:\"}\n    owner: {from: [event.issue.assignee, event.issue.creator], only: $includedOwners}\n    subject:",
        ),
        (
            "  release:",
            "  nightly:\n    on: {schedule: \"0 6 * * *\", timezone: \"UTC\"}\n    subject: \"nightly-sweep\"\n    owner: $nightlyOwner\n    busyBehavior: queueLatest\n    inputs:\n      ticket: \"nightly\"\n  release:",
        ),
    ];
    replacements
        .into_iter()
        .fold(ROOT_WORKFLOW.to_owned(), |root, (from, to)| {
            assert!(root.contains(from), "{from}");
            root.replacen(from, to, 1)
        })
}

// The report prints each start trigger's `where`, `subject`, `inputs`, `stopBefore`, `owner`
// and a declared `busyBehavior` and names a schedule trigger by its kind and timetable;
// publishing the tree starts no run.
#[test]
fn start_policies_and_schedule_triggers_are_reported_and_start_nothing() {
    let tree = Tree::with(&start_policy_root(), DESIGN_WORKFLOW);
    let output = validate(tree.path(), true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        report(&output)["triggers"],
        json!({
            "start": {
                "kind": "start",
                "source": "$connection",
                "event": "issue.state_entered",
                "where": format!("{START_WHERE} and event.issue.blocked == false"),
                "subject": "event.issue.identifier",
                "inputs": {"ticket": "event.issue.identifier", "baseBranch": "main"},
                "stopBefore": {"labels": "event.issue.labels", "prefix": "hold:"},
                "owner": {
                    "from": ["event.issue.assignee", "event.issue.creator"],
                    "only": "$includedOwners",
                },
            },
            "nightly": {
                "kind": "schedule",
                "schedule": "0 6 * * *",
                "timezone": "UTC",
                "subject": "nightly-sweep",
                "inputs": {"ticket": "nightly"},
                "owner": {"from": "$nightlyOwner"},
                "busyBehavior": "queueLatest",
            },
            "release": {
                "kind": "control",
                "source": "$connection",
                "event": "issue.state_left",
                "where": START_WHERE,
                "action": {"when": "event.to == $canceled", "then": "cancel", "else": "withdraw"},
            },
        })
    );
    let human = validate(tree.path(), false);
    assert_eq!(human.status.code(), Some(0), "{human:?}");
    assert_contains_all(
        &String::from_utf8(human.stdout).expect("human output should be UTF-8"),
        &[
            "nightly: schedule",
            "0 6 * * *",
            "hold:",
            "$includedOwners",
            "event.issue.blocked == false",
            "nightly-sweep",
            "event.issue.identifier",
            "queueLatest",
        ],
    );

    let home = Home::new();
    home.publish(&tree, &["--bindings", &tree.engineering_bindings()]);
    home.assert_no_runs();
}

/// The engineering root with a `verify` definition binding and a `repairMain` start trigger
/// on `on`, written as given.
fn definition_trigger_root(on: &str) -> String {
    let replacements = [
        (
            "  repository:      {kind: github.repository}\n".to_owned(),
            "  repository:      {kind: github.repository}\n  verify:          {kind: definition}\n"
                .to_owned(),
        ),
        (
            "  release:".to_owned(),
            format!(
                "  repairMain:\n    on: {on}\n    subject: main\n    busyBehavior: skip\n    inputs:\n      ticket: event.exports.repairRequest\n      baseBranch: \"main\"\n  release:"
            ),
        ),
    ];
    replacements
        .into_iter()
        .fold(ROOT_WORKFLOW.to_owned(), |root, (from, to)| {
            assert!(root.contains(&from), "{from}");
            root.replacen(&from, &to, 1)
        })
}

// A start trigger on another definition's run is reported as a start trigger with its
// `definition` reference and `outcomes` as written, a `definition` binding as any binding,
// and the other triggers gain no member; an engine outcome or a `where` beside
// `definition` is structurally invalid.
#[test]
fn definition_triggers_and_bindings_are_reported_as_written() {
    let unmodified = report(&validate(Tree::engineering().path(), true));
    let tree = Tree::with(
        &definition_trigger_root("{definition: $verify, outcome: [broken, failed]}"),
        DESIGN_WORKFLOW,
    );
    let output = validate(tree.path(), true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report_value = report(&output);
    let repair_main = |outcomes: Value| {
        json!({
            "kind": "start",
            "definition": "$verify",
            "outcomes": outcomes,
            "subject": "main",
            "inputs": {"ticket": "event.exports.repairRequest", "baseBranch": "main"},
            "busyBehavior": "skip",
        })
    };
    assert_eq!(
        report_value["triggers"]["repairMain"],
        repair_main(json!(["broken", "failed"]))
    );
    assert_eq!(
        report_value["bindings"]["verify"],
        json!({"kind": "definition", "required": true})
    );
    for name in ["start", "release"] {
        assert_eq!(
            report_value["triggers"][name], unmodified["triggers"][name],
            "{name}"
        );
    }

    let human = validate(tree.path(), false);
    assert_eq!(human.status.code(), Some(0), "{human:?}");
    assert_contains_all(
        &String::from_utf8(human.stdout).expect("human output should be UTF-8"),
        &["repairMain", "$verify", "broken", "failed"],
    );

    let tree = Tree::with(
        &definition_trigger_root("{definition: $verify, outcome: broken}"),
        DESIGN_WORKFLOW,
    );
    let output = validate(tree.path(), true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        report(&output)["triggers"]["repairMain"],
        repair_main(json!(["broken"]))
    );

    for root in [
        definition_trigger_root("{definition: $verify, outcome: canceled}"),
        definition_trigger_root(
            "{definition: $verify, outcome: broken, where: \"event.outcome == broken\"}",
        ),
    ] {
        let (code, _) = single_rejection(&root, DESIGN_WORKFLOW);
        assert_eq!(code, "invalid_workflow_structure", "{root}");
    }
}

// A tree with a definition trigger publishes locally with the bindings a runner gives it,
// which omit the `definition` binding, and the snapshot has no entry for it.
#[test]
fn a_definition_binding_given_no_value_publishes_locally_without_an_entry() {
    let tree = Tree::with(
        &definition_trigger_root("{definition: $verify, outcome: [broken, failed]}"),
        DESIGN_WORKFLOW,
    );
    let home = Home::new();
    let published = home.publish(&tree, &["--bindings", &tree.engineering_bindings()]);
    let id = text(&published["definition"]["id"], "definition id").to_owned();
    let shown = home.json(&["show", &id]);
    let bindings = shown["bindings"]
        .as_object()
        .expect("show should report the bindings as an object");
    assert!(bindings.contains_key("connection"), "{shown}");
    assert!(!bindings.contains_key("verify"), "{shown}");
    home.assert_no_runs();
}

/// The engineering root with a `github` connection and a `pushed` start trigger on `event`.
fn push_trigger_root(event: &str) -> String {
    let replacements = [
        (
            "  repository:      {kind: github.repository}\n".to_owned(),
            "  repository:      {kind: github.repository}\n  github:          {kind: connection}\n"
                .to_owned(),
        ),
        (
            "  release:".to_owned(),
            format!(
                "  pushed:\n    on:      {{source: $github, event: {event}, where: \"event.projectBranch == true\"}}\n    subject: event.branch\n    inputs:\n      ticket: event.commit\n      branch: event.branch\n  release:"
            ),
        ),
    ];
    replacements
        .into_iter()
        .fold(ROOT_WORKFLOW.to_owned(), |root, (from, to)| {
            assert!(root.contains(&from), "{from}");
            root.replacen(&from, &to, 1)
        })
}

// A start trigger on the one-segment event `push` validates and is reported as written beside
// a two-segment one; an event name of any other shape is structurally invalid.
#[test]
fn one_segment_trigger_event_is_reported_as_written() {
    let tree = Tree::with(&push_trigger_root("push"), DESIGN_WORKFLOW);
    let output = validate(tree.path(), true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let triggers = &report(&output)["triggers"];
    assert_eq!(
        triggers["pushed"],
        json!({
            "kind": "start",
            "source": "$github",
            "event": "push",
            "where": "event.projectBranch == true",
            "subject": "event.branch",
            "inputs": {"ticket": "event.commit", "branch": "event.branch"},
        })
    );
    assert_eq!(triggers["start"]["event"], "issue.state_entered");

    for event in ["push.", "Push"] {
        let (code, _) = single_rejection(&push_trigger_root(event), DESIGN_WORKFLOW);
        assert_eq!(code, "invalid_workflow_structure", "{event}");
    }
}

impl Home {
    /// `useful workflow definition ARGS --json`, asserting it exits 0; the report.
    pub(super) fn json(&self, args: &[&str]) -> Value {
        let mut full = args.to_vec();
        full.push("--json");
        let output = self.run(&full);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_no_content(&output);
        report(&output)
    }

    /// `useful workflow definition ARGS --json`, asserting it is refused with `code`; the one
    /// diagnostic.
    fn refused_command(&self, args: &[&str], command: &str, code: &str) -> Value {
        let mut full = args.to_vec();
        full.push("--json");
        let output = self.run(&full);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert_no_content(&output);
        let report = report(&output);
        assert_eq!(report["schemaVersion"], 1);
        assert_eq!(report["command"], command);
        assert_eq!(report["outcome"], "refused", "{report}");
        let diagnostics = report["diagnostics"]
            .as_array()
            .expect("diagnostics should be a list");
        assert_eq!(diagnostics.len(), 1, "{report}");
        assert_eq!(diagnostics[0]["code"], code, "{report}");
        diagnostics[0].clone()
    }

    /// `useful workflow definition ARGS` in the human form, asserting its exit status; stdout.
    fn human(&self, args: &[&str], status: i32) -> String {
        let output = self.run(args);
        assert_eq!(output.status.code(), Some(status), "{output:?}");
        assert_no_content(&output);
        String::from_utf8(output.stdout).expect("human output should be UTF-8")
    }

    /// The engineering definition and a `--new` canary of the same name; their ids.
    fn seed(&self, tree: &Tree) -> (String, String) {
        let bindings = tree.engineering_bindings();
        let first = self.publish(tree, &["--bindings", &bindings]);
        let canary = self.publish(tree, &["--new", "--bindings", &bindings]);
        (
            text(&first["definition"]["id"], "definition id").to_owned(),
            text(&canary["definition"]["id"], "definition id").to_owned(),
        )
    }
}

fn assert_contains_all(stdout: &str, expected: &[&str]) {
    for expected in expected {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in {stdout}"
        );
    }
}

const UNKNOWN_ID: &str = "def_01jzzzzzzzzzzzzzzzzzzzzzzz";

#[test]
fn enable_and_disable_set_only_the_enabled_flag() {
    let home = Home::new();
    let tree = Tree::engineering();
    let (id, _) = home.seed(&tree);
    let record_path = home.definition_directory(&id).join("definition.json");
    let before = read_json(&record_path);
    assert_eq!(before["enabled"], true);

    let disabled = home.json(&["disable", &id]);
    assert_eq!(disabled["schemaVersion"], 1);
    assert_eq!(disabled["command"], "useful workflow definition disable");
    assert_eq!(disabled["outcome"], "disabled");
    assert_eq!(disabled["definition"]["id"], id.as_str());
    assert_eq!(disabled["definition"]["name"], "engineering");
    assert_eq!(disabled["definition"]["enabled"], false);
    assert_eq!(disabled["definition"]["current"], 1);
    assert_eq!(disabled["definition"]["changed"], true);
    assert_eq!(
        Path::new(text(&disabled["definition"]["path"], "definition path")),
        home.definition_directory(&id)
    );
    let mut expected = before.clone();
    expected["enabled"] = json!(false);
    let after = read_json(&record_path);
    assert_eq!(after, expected);
    assert!(
        schema("workflow-definition-v1.schema.json").is_valid(&after),
        "{after}"
    );

    let again = home.json(&["disable", &id]);
    assert_eq!(again["outcome"], "disabled");
    assert_eq!(again["definition"]["enabled"], false);
    assert_eq!(again["definition"]["changed"], false);
    assert_eq!(read_json(&record_path), expected);

    let stdout = home.human(&["enable", &id], 0);
    assert_contains_all(&stdout, &[&id, "engineering", "enabled"]);
    assert_eq!(read_json(&record_path), before);
    let enabled = home.json(&["enable", &id]);
    assert_eq!(enabled["command"], "useful workflow definition enable");
    assert_eq!(enabled["outcome"], "enabled");
    assert_eq!(enabled["definition"]["enabled"], true);
    assert_eq!(enabled["definition"]["changed"], false);

    // Any other ID, and a name, names a Cloud definition of the project in effect: with nobody
    // signed in the leaf ends as a Cloud leaf does, and the record is left as it was.
    for named in [UNKNOWN_ID, "engineering"] {
        let output = home.run(&["disable", named, "--json"]);
        assert_eq!(output.status.code(), Some(3), "{output:?}");
        let failed = report(&output);
        assert_eq!(failed["command"], "useful workflow definition disable");
        assert_eq!(failed["outcome"], "authentication_required", "{failed}");
    }
    assert_eq!(read_json(&record_path), before);
    home.assert_no_runs();
}

// With nobody signed in the home's definitions are listed, each `on` `local`, and the command
// exits 0 having asked Cloud nothing (`run_offline` fails on any connection).
#[test]
fn list_prints_every_definition_sorted_by_name_then_id() {
    let home = Home::new();
    let empty = home.json(&["list"]);
    assert_eq!(empty["schemaVersion"], 1);
    assert_eq!(empty["command"], "useful workflow definition list");
    assert_eq!(empty["definitions"], json!([]));
    assert_eq!(
        empty["cloud"],
        json!({"asked": false, "reason": "signed_out"})
    );
    assert_eq!(
        home.human(&["list"], 0).trim_end(),
        "No workflow definitions."
    );
    assert!(!home.root.exists(), "list must not create the home");

    let tree = Tree::engineering();
    let (first, canary) = home.seed(&tree);
    let second = home.publish(&tree, &["--to", &first]);
    let alpha = Tree::with(
        &ROOT_WORKFLOW.replacen("name: engineering\n", "name: alpha\n", 1),
        DESIGN_WORKFLOW,
    );
    let alpha_bindings = alpha.engineering_bindings();
    let alpha = home.publish(&alpha, &["--bindings", &alpha_bindings]);
    let alpha_id = text(&alpha["definition"]["id"], "definition id").to_owned();
    home.json(&["disable", &canary]);

    let listed = home.json(&["list"]);
    assert_eq!(
        listed["cloud"],
        json!({"asked": false, "reason": "signed_out"})
    );
    let definitions = listed["definitions"]
        .as_array()
        .expect("definitions should be a list");
    assert!(
        definitions
            .iter()
            .all(|definition| definition["on"] == "local"),
        "{listed}"
    );
    let mut engineering = [first.clone(), canary.clone()];
    engineering.sort();
    let order = definitions
        .iter()
        .map(|definition| text(&definition["id"], "definition id"))
        .collect::<Vec<_>>();
    assert_eq!(
        order,
        vec![alpha_id.as_str(), &engineering[0], &engineering[1]]
    );
    for definition in definitions {
        let id = text(&definition["id"], "definition id");
        assert_eq!(
            Path::new(text(&definition["path"], "definition path")),
            home.definition_directory(id)
        );
        let record = read_json(&home.definition_directory(id).join("definition.json"));
        assert_eq!(
            definition["publishedAt"],
            record["revisions"][0]["publishedAt"]
        );
    }
    let by_id = |id: &str| {
        definitions
            .iter()
            .find(|definition| definition["id"] == id)
            .expect("definition should be listed")
            .clone()
    };
    let listed_first = by_id(&first);
    assert_eq!(listed_first["name"], "engineering");
    assert_eq!(listed_first["enabled"], true);
    assert_eq!(listed_first["current"], 2);
    assert_eq!(listed_first["revisions"], 2);
    assert_eq!(
        listed_first["publishedAt"],
        second["revision"]["publishedAt"]
    );
    let listed_canary = by_id(&canary);
    assert_eq!(listed_canary["enabled"], false);
    assert_eq!(listed_canary["current"], 1);
    assert_eq!(listed_canary["revisions"], 1);
    assert_eq!(by_id(&alpha_id)["name"], "alpha");

    let stdout = home.human(&["list"], 0);
    assert_eq!(stdout.lines().count(), 3, "{stdout}");
    assert_contains_all(
        &stdout,
        &[&first, &canary, &alpha_id, "engineering", "alpha"],
    );
    home.assert_no_runs();
}

// SC-WFDEF-2
#[test]
fn show_prints_the_record_its_revisions_and_the_current_bindings() {
    let home = Home::new();
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let first = home.publish(&tree, &["--bindings", &bindings]);
    let id = text(&first["definition"]["id"], "definition id").to_owned();
    tree.write(
        "policy/engineering.json",
        &format!("{{\"note\": \"{CONTENT_SENTINEL} edited\"}}\n"),
    );
    let second = home.publish(&tree, &[]);
    assert_eq!(second["revision"]["n"], 2);
    assert_ne!(second["revision"]["tree"], first["revision"]["tree"]);

    let canary = home.publish(&tree, &["--new", "--bindings", &bindings]);
    let canary_id = text(&canary["definition"]["id"], "definition id").to_owned();
    home.refused(&tree, &[], "definition_name_ambiguous");
    let third = home.publish(&tree, &["--to", &id]);
    assert_eq!(third["revision"]["n"], 3);
    home.json(&["disable", &canary_id]);
    let listed = home.json(&["list"]);
    let enabled = listed["definitions"]
        .as_array()
        .expect("definitions should be a list")
        .iter()
        .map(|definition| (definition["id"].clone(), definition["enabled"].clone()))
        .collect::<Vec<_>>();
    assert_eq!(enabled.len(), 2);
    assert!(enabled.contains(&(json!(id), json!(true))));
    assert!(enabled.contains(&(json!(canary_id), json!(false))));

    // The first revision's tree copy is gone from the home; the others stay.
    let first_hex = text(&first["revision"]["tree"], "tree digest")
        .trim_start_matches("sha256:")
        .to_owned();
    let trees = home.root.join("trees/sha256");
    fs::rename(
        trees.join(&first_hex),
        trees.join(format!("gone-{first_hex}")),
    )
    .expect("tree copy should move aside");

    let shown = home.json(&["show", &id]);
    assert_eq!(shown["schemaVersion"], 1);
    assert_eq!(shown["command"], "useful workflow definition show");
    assert_eq!(shown["on"], "local");
    assert_eq!(
        shown["definition"],
        json!({
            "id": id,
            "name": "engineering",
            "enabled": true,
            "current": 3,
            "cloudId": null,
            "path": home.definition_directory(&id).to_str().expect("home path should be UTF-8"),
        })
    );
    let revisions = shown["revisions"]
        .as_array()
        .expect("revisions should be a list");
    assert_eq!(
        revisions
            .iter()
            .map(|revision| revision["n"].clone())
            .collect::<Vec<_>>(),
        vec![json!(3), json!(2), json!(1)]
    );
    for (revision, published) in revisions.iter().zip([&third, &second, &first]) {
        for field in ["n", "tree", "bindings", "publishedAt", "by"] {
            assert_eq!(revision[field], published["revision"][field], "{field}");
        }
    }
    assert_eq!(revisions[0]["treeRetained"], true);
    assert_eq!(revisions[1]["treeRetained"], true);
    assert_eq!(revisions[2]["treeRetained"], false);
    assert_eq!(
        shown["bindings"],
        json!({
            "connection": {"kind": "connection", "value": "local"},
            "linearTeam": {"kind": "linear.team", "value": "AUTO"},
            "ownedState": {"kind": "linear.state", "value": "Engineering"},
            "backlog": {"kind": "linear.state", "value": "Backlog"},
            "canceled": {"kind": "linear.state", "value": "Canceled"},
            "done": {"kind": "linear.state", "value": "Done"},
            "repository": {"kind": "github.repository", "value": "useful-machinery/platform"},
        })
    );

    let stdout = home.human(&["show", &id], 0);
    assert_contains_all(
        &stdout,
        &[
            &id,
            "engineering",
            text(&third["revision"]["tree"], "tree digest"),
            text(&first["revision"]["tree"], "tree digest"),
            text(&third["revision"]["bindings"], "bindings digest"),
            "linearTeam",
            "linear.team",
            "AUTO",
            "useful-machinery/platform",
        ],
    );
    home.assert_no_runs();
}

// `show` lists the definition's live runs, a run behind the current revision drifted, and
// `No live runs.` for a definition without one.
#[test]
fn show_lists_the_live_runs_and_their_drift() {
    let published = super::workflow_run_control::PublishedWaitTree::with_subject();
    let home = &published.home;
    let id = published.definition.as_str();
    let (_, waiting) = published.waiting_for(id, "AUTO-1");
    let (_, exited) = published.waiting_for(id, "AUTO-2");
    let withdrawn = super::workflow_run_control::run_control(Some(home), "cancel", &exited, &[]);
    assert_eq!(withdrawn.status.code(), Some(0), "{withdrawn:?}");
    let live = json!([{
        "id": waiting,
        "revision": 1,
        "subject": "AUTO-1",
        "state": "waiting",
        "drifted": false,
    }]);
    assert_eq!(home.json(&["show", id])["runs"], live);

    published.republish(&[]);
    let shown = home.json(&["show", id]);
    assert_eq!(shown["definition"]["current"], 2);
    let mut drifted = live;
    drifted[0]["drifted"] = json!(true);
    assert_eq!(shown["runs"], drifted, "{shown}");
    let stdout = home.human(&["show", id], 0);
    assert!(
        stdout
            .lines()
            .any(|line| line == format!("{waiting} · revision 1 · AUTO-1 · waiting · drifted")),
        "{stdout}"
    );
    assert!(!stdout.contains(&exited), "{stdout}");

    let canary = published.republish(&["--new"]);
    let canary = text(&canary["definition"]["id"], "definition id").to_owned();
    assert_eq!(home.json(&["show", &canary])["runs"], json!([]));
    let stdout = home.human(&["show", &canary], 0);
    assert!(
        stdout.lines().any(|line| line == "No live runs."),
        "{stdout}"
    );
}

#[test]
fn list_and_show_refuse_a_record_not_of_the_published_shape() {
    let home = Home::new();
    let tree = Tree::engineering();
    let (id, _) = home.seed(&tree);
    let record_path = home.definition_directory(&id).join("definition.json");
    fs::write(&record_path, "{}").expect("record should be replaced");
    let record = record_path.to_str().expect("home path should be UTF-8");

    let listed = home.refused_command(
        &["list"],
        "useful workflow definition list",
        "definition_record_invalid",
    );
    assert_eq!(listed["path"], record);
    let shown = home.refused_command(
        &["show", &id],
        "useful workflow definition show",
        "definition_record_invalid",
    );
    assert_eq!(shown["path"], record);

    let stdout = home.human(&["list"], 1);
    assert_contains_all(&stdout, &["definition_record_invalid", record]);
    let stdout = home.human(&["show", &id], 1);
    assert_contains_all(&stdout, &["definition_record_invalid", record]);
}

const CLOUD_TOKEN: &str = "unique-workflow-definition-cloud-token-sentinel";
const CLOUD_ORGANIZATION: &str = "acme-research";
const CLOUD_PROJECT: &str = "prj_01k0z6r1w8f4jy2m7q9v3x5abc";
const CLOUD_PUBLISHER: &str = "prn_01k0z6r1w8f4jy2m7q9v3x5abc";
const CLOUD_TIME: &str = "2026-11-10T12:00:00Z";
/// A minted Cloud definition id is this and one more character.
const CLOUD_ID_STEM: &str = "def_01k0z6r1w8f4jy2m7q9v3x5ab";
const PROBLEMS: &str = "https://api.usefulmachinery.com/problems/";

/// One request the fake Gateway received, its path below the listener.
pub(super) struct GatewayRequest {
    pub(super) method: String,
    pub(super) path: String,
    headers: Vec<(String, String)>,
    pub(super) body: Vec<u8>,
}

impl GatewayRequest {
    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub(super) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("request body should be JSON")
    }

    /// `METHOD path`, the path without its query.
    pub(super) fn route(&self) -> String {
        format!(
            "{} {}",
            self.method,
            self.path.split('?').next().unwrap_or_default()
        )
    }
}

/// What the fake Gateway holds between invocations: the bindings the published root declares,
/// the file contents the organization retains, the sealed tree digests, each definition,
/// whether the next publication to an id
/// loses a race to another publisher or is forbidden, whether the reply to the next create,
/// publication or delete is lost after it is applied, the problems the next keyed definition
/// requests are answered with before they are applied, the fault the next request on the
/// route it names is answered with, each create or publication reply, with its status, by
/// its `Idempotency-Key`, and the `Idempotency-Key` of each applied delete.
#[derive(Default)]
struct GatewayState {
    declarations: Declarations,
    runs: std::collections::BTreeMap<String, Value>,
    retained: std::collections::BTreeSet<String>,
    sealed: std::collections::BTreeSet<String>,
    definitions: std::collections::BTreeMap<String, FakeDefinition>,
    lose_next_publication: bool,
    forbid_next_publication: bool,
    drop_next_publication_reply: bool,
    keyed_problems: std::collections::VecDeque<(&'static str, u16, &'static str, Value)>,
    fault: Option<Fault>,
    publications: std::collections::BTreeMap<String, (&'static str, Value)>,
    members: Vec<Value>,
    deletions: std::collections::BTreeSet<String>,
}

impl GatewayState {
    /// Whether the next request on `fault`'s route is to be answered with it, consuming it.
    fn fault(&mut self, fault: Fault) -> bool {
        self.fault.take_if(|next| *next == fault).is_some()
    }

    /// The reply to a create or publication keyed `key`: the one recorded under the key with
    /// its status, or `publish`'s, recorded and, when the next reply is to be lost, not sent
    /// (no bytes).
    fn publication(
        &mut self,
        key: &str,
        keyed: impl Fn(&str, Value) -> Vec<u8>,
        publish: impl FnOnce(&mut Self) -> Result<(&'static str, Value), Vec<u8>>,
    ) -> Vec<u8> {
        if let Some((status, replayed)) = self.publications.get(key) {
            return keyed(status, replayed.clone());
        }
        let (status, published) = match publish(self) {
            Ok(published) => published,
            Err(refusal) => return refusal,
        };
        self.publications
            .insert(key.to_owned(), (status, published.clone()));
        if std::mem::take(&mut self.drop_next_publication_reply) {
            return Vec::new();
        }
        keyed(status, published)
    }
}

/// A faulty answer to the next request on the route a fault names.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Fault {
    /// The tree upload's capability URLs carry a user and `CAPABILITY_PASSWORD`.
    UploadCapabilityCredentials,
    /// The seal is applied and answered without its `Idempotency-Key`.
    SealWithoutKey,
    /// The create is answered 404 with an HTML page, applying nothing.
    CreateHtmlNotFound,
    /// A definition read is answered with the definition under `CLOUD_TARGET`'s id.
    ReadOtherDefinition,
    /// A setting change or a delete is applied and answered without its `Idempotency-Key`.
    ChangeWithoutKey,
    /// The definition list is answered with no definition, as it is read before another
    /// owner's first publication of the same tree lands.
    ListNoDefinition,
}

/// A binding the fake's root declares: its kind and its default, none when it has none.
type DeclaredBinding = (&'static str, Option<&'static str>);

/// The `linear.state` bindings both roots declare, each with its default.
const DECLARED_STATES: [(&str, &str); 4] = [
    ("ownedState", "Engineering"),
    ("backlog", "Backlog"),
    ("canceled", "Canceled"),
    ("done", "Done"),
];

/// The bindings the root every request publishes declares: the flat block's by key and each
/// integration's by name under its id.
#[derive(Default)]
struct Declarations {
    flat: std::collections::BTreeMap<&'static str, DeclaredBinding>,
    integrations: std::collections::BTreeMap<
        &'static str,
        std::collections::BTreeMap<&'static str, DeclaredBinding>,
    >,
}

impl Declarations {
    /// `ROOT_WORKFLOW`'s.
    fn engineering() -> Self {
        let mut flat = std::collections::BTreeMap::from([
            ("connection", ("connection", None)),
            ("linearTeam", ("linear.team", None)),
            ("repository", ("github.repository", None)),
        ]);
        flat.extend(DECLARED_STATES.map(|(key, default)| (key, ("linear.state", Some(default)))));
        Self {
            flat,
            integrations: std::collections::BTreeMap::new(),
        }
    }

    /// `NESTED_ROOT`'s.
    fn nested() -> Self {
        let mut linear = std::collections::BTreeMap::from([("team", ("team", None))]);
        linear.extend(DECLARED_STATES.map(|(name, default)| (name, ("state", Some(default)))));
        Self {
            flat: std::collections::BTreeMap::new(),
            integrations: std::collections::BTreeMap::from([
                ("linear", linear),
                (
                    "github",
                    std::collections::BTreeMap::from([("repository", ("repository", None))]),
                ),
            ]),
        }
    }

    /// What a create (`current` none) or a publication over a current revision that published
    /// `current` records from request `body`, as Cloud merges it: each declared binding takes
    /// its named value, its default when it is named `null` or, by a create, not named, and
    /// otherwise its current value, as `{kind, value}`. A named binding the root does not
    /// declare is 422 `binding-unresolved`, and one left without a value 422
    /// `binding-missing`.
    fn merge(&self, body: &Value, current: Option<&Value>) -> Result<Value, Vec<u8>> {
        let none = serde_json::Map::new();
        let named = body["bindings"].as_object().unwrap_or(&none);
        let named_groups = body["integrationBindings"].as_object().unwrap_or(&none);
        if let Some(key) = named
            .keys()
            .find(|key| !self.flat.contains_key(key.as_str()))
        {
            return Err(binding_refusal("binding-unresolved", None, key));
        }
        for (integration, group) in named_groups {
            let declared = self.integrations.get(integration.as_str());
            let group = group
                .as_object()
                .expect("an integration's bindings should be an object");
            if let Some(name) = group
                .keys()
                .find(|name| !declared.is_some_and(|declared| declared.contains_key(name.as_str())))
            {
                return Err(binding_refusal(
                    "binding-unresolved",
                    Some(integration),
                    name,
                ));
            }
        }
        let mut bindings = serde_json::Map::new();
        for (key, (kind, default)) in &self.flat {
            let value = bound_value(
                named.get(*key),
                *default,
                current.map(|current| &current["bindings"][*key]["value"]),
            )
            .ok_or_else(|| binding_refusal("binding-missing", None, key))?;
            bindings.insert((*key).to_owned(), json!({"kind": kind, "value": value}));
        }
        let mut groups = serde_json::Map::new();
        for (integration, declared) in &self.integrations {
            let mut group = serde_json::Map::new();
            for (name, (kind, default)) in declared {
                let value = bound_value(
                    named_groups
                        .get(*integration)
                        .and_then(|group| group.get(*name)),
                    *default,
                    current.map(
                        |current| &current["integrationBindings"][*integration][*name]["value"],
                    ),
                )
                .ok_or_else(|| binding_refusal("binding-missing", Some(integration), name))?;
                group.insert((*name).to_owned(), json!({"kind": kind, "value": value}));
            }
            groups.insert((*integration).to_owned(), Value::Object(group));
        }
        Ok(json!({
            "treeDigest": body["treeDigest"],
            "bindings": bindings,
            "integrationBindings": groups,
            "executablePaths": body["executablePaths"],
        }))
    }
}

/// The value a declared binding takes from what the request names for it: the named value,
/// its default when named `null` or, by a create (`current` none), not named, and otherwise
/// the current value; none when that leaves it without one.
fn bound_value(
    named: Option<&Value>,
    default: Option<&str>,
    current: Option<&Value>,
) -> Option<Value> {
    match (named, current) {
        (Some(Value::Null), _) | (None, None) => default.map(Value::from),
        (Some(value), _) => Some(value.clone()),
        (None, Some(current)) => Some(current.clone()).filter(|value| !value.is_null()),
    }
}

/// The 422 refusal `slug` of binding `key`, under `integration` for an integration's.
fn binding_refusal(slug: &str, integration: Option<&str>, key: &str) -> Vec<u8> {
    let mut workflow = json!({"bindingKey": key});
    if let Some(integration) = integration {
        workflow["integration"] = json!(integration);
    }
    super::problem_http_response(
        "422 Unprocessable Entity",
        json!({
            "type": format!("{PROBLEMS}{slug}"),
            "title": "Binding refused",
            "status": 422,
            "workflow": workflow,
        }),
    )
}

/// The password a faulty upload capability URL carries.
const CAPABILITY_PASSWORD: &str = "unique-capability-password-sentinel";

/// One Cloud definition the fake Gateway holds: its name (`engineering` when none is set), its
/// current revision, what that revision published (its `treeDigest`, its merged `bindings` and
/// `integrationBindings` and its `executablePaths`), its settings and whether its revisions
/// hold integration bindings.
#[derive(Clone, Default)]
struct FakeDefinition {
    name: Option<String>,
    current: i64,
    published: Value,
    archived: bool,
    automatic_starts: bool,
    principal: Option<String>,
    integrations: bool,
}

/// A loopback fake of the Gateway's tree and definition operations and of signed storage,
/// serving one `useful` invocation at a time with a stored human session for `CLOUD_TOKEN`. A
/// tree upload reports missing the files under `scripts/` and `policy/` the organization
/// does not yet retain.
pub(super) struct FakeGateway {
    listener: TcpListener,
    api_url: String,
    _credentials: TempDir,
    credentials: String,
    state: std::sync::Arc<std::sync::Mutex<GatewayState>>,
}

impl FakeGateway {
    /// A Gateway whose published root declares `ROOT_WORKFLOW`'s bindings.
    pub(super) fn new() -> Self {
        Self::declaring(Declarations::engineering())
    }

    /// A Gateway whose published root declares `NESTED_ROOT`'s bindings.
    pub(super) fn nested() -> Self {
        Self::declaring(Declarations::nested())
    }

    fn declaring(declarations: Declarations) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("fake Gateway should bind");
        let api_url = format!("http://{}/api", listener.local_addr().unwrap());
        let directory = super::private_credential_directory();
        let credentials = directory.path().join("credentials.json");
        super::write_credential_fixture(
            &credentials,
            &api_url,
            CLOUD_TOKEN,
            "2999-01-01T00:00:00Z",
        );
        Self {
            listener,
            api_url,
            credentials: credentials.to_str().unwrap().to_owned(),
            _credentials: directory,
            state: std::sync::Arc::new(std::sync::Mutex::new(GatewayState {
                declarations,
                ..GatewayState::default()
            })),
        }
    }

    /// Answers the next publication to an existing id with 409 `definition-revision-conflict`
    /// after another publisher's revision.
    pub(super) fn lose_next_publication(&self) {
        self.state.lock().unwrap().lose_next_publication = true;
    }

    /// Answers the next publication to an existing id with 403 `forbidden`, as Cloud answers
    /// a caller who is not an owner, and changes nothing.
    pub(super) fn forbid_next_publication(&self) {
        self.state.lock().unwrap().forbid_next_publication = true;
    }

    /// Applies the next create, publication or delete but sends no reply to it.
    pub(super) fn drop_next_publication_reply(&self) {
        self.state.lock().unwrap().drop_next_publication_reply = true;
    }

    /// Answers the next keyed request under the definitions with problem `slug` under
    /// `status` (its status line `line`), applying and recording nothing; queued answers are
    /// given to successive keyed requests.
    pub(super) fn answer_next_keyed_with(
        &self,
        line: &'static str,
        status: u16,
        slug: &'static str,
    ) {
        self.refuse_next_keyed_with(line, status, slug, Value::Null);
    }

    /// As [`Self::answer_next_keyed_with`], the problem carrying `workflow` as its safe facts
    /// unless it is null.
    pub(super) fn refuse_next_keyed_with(
        &self,
        line: &'static str,
        status: u16,
        slug: &'static str,
        workflow: Value,
    ) {
        self.state
            .lock()
            .unwrap()
            .keyed_problems
            .push_back((line, status, slug, workflow));
    }

    /// Answers the next request on the route `fault` names with it.
    pub(super) fn answer_next_with(&self, fault: Fault) {
        self.state.lock().unwrap().fault = Some(fault);
    }

    /// Holds definition `id` at revision `current`, active, disabled and with no principal,
    /// its current revision publishing `engineering_published`.
    pub(super) fn define(&self, id: &str, current: i64) {
        self.state.lock().unwrap().definitions.insert(
            id.to_owned(),
            FakeDefinition {
                current,
                published: engineering_published(current),
                ..FakeDefinition::default()
            },
        );
    }

    /// Lists a member of the organization whose principal `principal` is of `kind`, `human` or
    /// `service`, and named `name`, in its member directory.
    pub(super) fn add_member(&self, principal: &str, kind: &str, name: &str) {
        let mut state = self.state.lock().unwrap();
        let membership = format!("mem_01k0z6r1w8f4jy2m7q9v3x5a{:02}", state.members.len());
        state.members.push(json!({
            "id": membership,
            "principalId": principal,
            "principalType": kind,
            "principalState": "active",
            "displayName": name,
            "role": "member",
            "state": "active",
        }));
    }

    /// Holds definition `id` named `name` at revision `current`, active, disabled and with no
    /// principal.
    pub(super) fn define_named(&self, id: &str, current: i64, name: &str) {
        self.state.lock().unwrap().definitions.insert(
            id.to_owned(),
            FakeDefinition {
                name: Some(name.to_owned()),
                current,
                published: engineering_published(current),
                ..FakeDefinition::default()
            },
        );
    }

    /// As [`Self::define`], each revision also holding `gateway_integrations`.
    pub(super) fn define_with_integrations(&self, id: &str, current: i64) {
        self.state.lock().unwrap().definitions.insert(
            id.to_owned(),
            FakeDefinition {
                current,
                published: engineering_published(current),
                integrations: true,
                ..FakeDefinition::default()
            },
        );
    }

    /// Runs `useful ARGS` against this Gateway and `home`; the output and the requests served.
    pub(super) fn run(
        &self,
        home: &Home,
        args: &[&str],
    ) -> (std::process::Output, Vec<GatewayRequest>) {
        let listener = self.listener.try_clone().unwrap();
        let address = listener.local_addr().unwrap();
        let state = std::sync::Arc::clone(&self.state);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopping = std::sync::Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            loop {
                let (mut stream, _) = listener.accept().unwrap();
                if stopping.load(std::sync::atomic::Ordering::SeqCst) {
                    return requests;
                }
                let request = read_gateway_request(&stream);
                let response = respond(&mut state.lock().unwrap(), &request, &address.to_string());
                std::io::Write::write_all(&mut stream, &response).unwrap();
                requests.push(request);
            }
        });
        let mut environment =
            super::deployment_environment(&self.api_url, &self.credentials).to_vec();
        environment.push(("USEFUL_HOME", home.path()));
        let output = run_with_env(args, &environment);
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(address);
        (output, server.join().unwrap())
    }
}

fn read_gateway_request(stream: &std::net::TcpStream) -> GatewayRequest {
    use std::io::{BufRead as _, Read as _};
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').expect("header should have a colon");
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .map_or(0, |(_, value)| value.parse().unwrap());
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    GatewayRequest {
        method,
        path,
        headers,
        body,
    }
}

/// The 404 `not-found` problem the fake answers for anything it does not hold.
fn gateway_not_found() -> Vec<u8> {
    super::problem_http_response(
        "404 Not Found",
        json!({"type": format!("{PROBLEMS}not-found"), "title": "Not Found", "status": 404}),
    )
}

fn respond(state: &mut GatewayState, request: &GatewayRequest, address: &str) -> Vec<u8> {
    let organization = format!("/api/v1/organizations/{CLOUD_ORGANIZATION}");
    let definitions = format!("{organization}/projects/{CLOUD_PROJECT}/workflow-definitions");
    let route = request.route();
    let key = request
        .header("idempotency-key")
        .unwrap_or_default()
        .to_owned();
    let runs = format!("{organization}/runs");
    if route == format!("POST {runs}") {
        let input = request.json();
        let definition = input["definition"]["definitionId"].as_str().unwrap();
        assert!(
            state.definitions.contains_key(definition),
            "unpublished {definition}"
        );
        assert_eq!(input["projectId"], CLOUD_PROJECT);
        let id = format!("run_01k0z6r1w8f4jy2m7q9v3x5a{:02}", state.runs.len());
        let owner = if input.get("owner").is_some() {
            Value::Null
        } else {
            json!(CLOUD_PUBLISHER)
        };
        state.runs.insert(
            id.clone(),
            super::workflow_run_list::cloud_list_item(&id, owner, "running"),
        );
        return super::run_command::acceptance_response_for(
            "202 Accepted",
            &id,
            false,
            &[
                ("Idempotency-Key", &key),
                (
                    "Location",
                    &format!("/v1/organizations/{CLOUD_ORGANIZATION}/runs/{id}"),
                ),
            ],
        );
    }
    if route == format!("GET {runs}") {
        return super::workflow_run_list::page_response(
            &json!({"items":state.runs.values().collect::<Vec<_>>(),"nextCursor":null }),
        );
    }
    if let Some(id) = route.strip_prefix(&format!("GET {runs}/"))
        && state.runs.contains_key(id)
    {
        let mut body = super::run_command::run_body_with_state("running");
        body["id"] = id.into();
        return super::run_command::run_response(body);
    }
    let keyed = |status: &str, body: Value| {
        super::http_response_with_headers(
            status,
            Some("application/json"),
            &[("Idempotency-Key", &key), ("Location", "/v1/fixture")],
            &serde_json::to_vec(&body).unwrap(),
        )
    };
    if route == format!("GET {organization}/memberships") {
        return super::json_http_response("200 OK", json!({"items": state.members}));
    }
    if route == format!("POST {organization}/workflow-trees") {
        let manifest = request.json();
        let digest = text(&manifest["digest"], "manifest digest").to_owned();
        let sealed = state.sealed.contains(&digest);
        let authority = if state.fault(Fault::UploadCapabilityCredentials) {
            format!("owner:{CAPABILITY_PASSWORD}@{address}")
        } else {
            address.to_owned()
        };
        let capabilities = if sealed {
            Vec::new()
        } else {
            manifest["files"]
                .as_array()
                .expect("manifest files should be a list")
                .iter()
                .filter(|file| {
                    let path = text(&file["path"], "manifest path");
                    (path.starts_with("scripts/") || path.starts_with("policy/"))
                        && !state.retained.contains(text(&file["sha256"], "file sha256"))
                })
                .map(|file| {
                    let sha256 = text(&file["sha256"], "file sha256");
                    let raw = (0..sha256.len())
                        .step_by(2)
                        .map(|at| u8::from_str_radix(&sha256[at..at + 2], 16).unwrap())
                        .collect::<Vec<_>>();
                    json!({
                        "sha256": sha256,
                        "url": format!("http://{authority}/storage/{sha256}?X-Amz-Signature=fixture"),
                        "requiredHeaders": {
                            "contentLength": file["sizeBytes"].to_string(),
                            "contentType": "application/octet-stream",
                            "ifNoneMatch": "*",
                            "xAmzChecksumSha256": base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD, raw),
                        },
                    })
                })
                .collect()
        };
        let expires = if capabilities.is_empty() {
            Value::Null
        } else {
            json!("2999-01-01T00:00:00Z")
        };
        return super::json_http_response(
            "200 OK",
            json!({
                "tree": gateway_tree(&digest, sealed),
                "capabilityExpiresAt": expires,
                "capabilities": capabilities,
            }),
        );
    }
    if let Some(sha256) = route.strip_prefix("PUT /storage/") {
        let observed = ring::digest::digest(&ring::digest::SHA256, &request.body);
        let hex = observed
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            hex, sha256,
            "an uploaded object should have its manifest digest"
        );
        state.retained.insert(hex);
        return super::http_response("200 OK", None, b"");
    }
    if let Some(digest) = route
        .strip_prefix(&format!("POST {organization}/workflow-trees/"))
        .and_then(|rest| rest.strip_suffix("/seal"))
    {
        let digest = digest.replace("%3A", ":").replace("%3a", ":");
        state.sealed.insert(digest.clone());
        if state.fault(Fault::SealWithoutKey) {
            return super::json_http_response("200 OK", gateway_tree(&digest, true));
        }
        return keyed("200 OK", gateway_tree(&digest, true));
    }
    if request.header("idempotency-key").is_some()
        && request.path.starts_with(definitions.as_str())
        && let Some((line, status, slug, workflow)) = state.keyed_problems.pop_front()
    {
        let mut problem =
            json!({"type": format!("{PROBLEMS}{slug}"), "title": "Unavailable", "status": status});
        if !workflow.is_null() {
            problem["workflow"] = workflow;
        }
        return super::problem_http_response(line, problem);
    }
    if route == format!("POST {definitions}") {
        if state.fault(Fault::CreateHtmlNotFound) {
            return super::http_response(
                "404 Not Found",
                Some("text/html"),
                b"<html><body>Not Found</body></html>",
            );
        }
        let body = request.json();
        return state.publication(&key, keyed, |state| {
            let published = state.declarations.merge(&body, None)?;
            // `reuseIdentical` answers the active definition whose current revision published the
            // same tree, snapshot and executable files, and refuses when several did.
            if body["reuseIdentical"] == true {
                let identical = state
                    .definitions
                    .iter()
                    .filter(|(_, definition)| {
                        !definition.archived && definition.published == published
                    })
                    .map(|(id, _)| id.clone())
                    .collect::<Vec<_>>();
                match identical.as_slice() {
                    [] => {}
                    [id] => {
                        return Ok(("200 OK", gateway_publication(id, &state.definitions[id])));
                    }
                    ids => {
                        return Err(super::problem_http_response(
                            "409 Conflict",
                            json!({
                                "type": format!("{PROBLEMS}definition-reuse-ambiguous"),
                                "title": "Definition reuse ambiguous",
                                "status": 409,
                                "workflow": {"definitionIds": ids},
                            }),
                        ));
                    }
                }
            }
            // Counting the deleted ones too, so that, as in Cloud, an id is never minted again.
            let id = format!(
                "{CLOUD_ID_STEM}{}",
                ['c', 'd', 'e', 'f', 'g', 'h'][state.definitions.len() + state.deletions.len()]
            );
            state.definitions.insert(
                id.clone(),
                FakeDefinition {
                    current: 1,
                    published,
                    ..FakeDefinition::default()
                },
            );
            Ok((
                "201 Created",
                gateway_publication(&id, &state.definitions[&id]),
            ))
        });
    }
    if let Some(id) = route.strip_prefix(&format!("DELETE {definitions}/")) {
        return respond_delete(state, id, &key);
    }
    if let Some(response) = respond_settings(state, request, &definitions, keyed) {
        return response;
    }
    if let Some((id, evaluation)) = route
        .strip_prefix(&format!("GET {definitions}/"))
        .and_then(|rest| rest.split_once("/evaluations"))
    {
        // As Cloud does, an evaluation is listed and read only under a vocabulary that
        // holds its event: the push evaluation from 2, the `issue.unblocked_in_state` ones
        // from 3 and the `run.ended` one from 4; a request naming none is vocabulary 1.
        let vocabulary = evaluation_vocabulary(request);
        let mut answer = match evaluation.strip_prefix('/') {
            Some(CLOUD_PUSH_EVALUATION) if vocabulary < 2 => return gateway_not_found(),
            Some(CLOUD_WAITING_EVALUATION | CLOUD_UNBLOCKED_EVALUATION) if vocabulary < 3 => {
                return gateway_not_found();
            }
            Some(CLOUD_RUN_ENDED_EVALUATION) if vocabulary < 4 => return gateway_not_found(),
            Some(CLOUD_PUSH_EVALUATION) => gateway_push_evaluation(id),
            Some(CLOUD_WAITING_EVALUATION) => gateway_waiting_evaluation(id),
            Some(CLOUD_UNBLOCKED_EVALUATION) => gateway_unblocked_evaluation(id),
            Some(CLOUD_RUN_ENDED_EVALUATION) => gateway_run_ended_evaluation(id),
            Some(CLOUD_NOT_READY_EVALUATION) => gateway_not_ready_evaluation(id),
            Some(CLOUD_DIAGNOSED_EVALUATION) => gateway_diagnosed_evaluation(id),
            Some(CLOUD_STAGE_DIAGNOSED_EVALUATION) => gateway_stage_diagnosed_evaluation(id),
            Some(evaluation) => gateway_evaluation(id, evaluation),
            None => {
                let mut items = Vec::new();
                if vocabulary >= 4 {
                    items.push(gateway_run_ended_evaluation(id));
                }
                if vocabulary >= 3 {
                    items.extend([
                        gateway_unblocked_evaluation(id),
                        gateway_waiting_evaluation(id),
                    ]);
                }
                if vocabulary >= 2 {
                    items.push(gateway_push_evaluation(id));
                }
                items.extend([
                    gateway_diagnosed_evaluation(id),
                    gateway_stage_diagnosed_evaluation(id),
                    gateway_evaluation(id, CLOUD_EVALUATION),
                    gateway_blocked_evaluation(id),
                    gateway_not_ready_evaluation(id),
                ]);
                json!({"items": items, "nextCursor": "older-evaluations"})
            }
        };
        // As Cloud does, an evaluation's diagnostic is answered only to a request that asks
        // for representation 4 or later; a request naming none is 1.
        if query_number(request, "representation").unwrap_or(1) < 4 {
            match answer.get_mut("items").and_then(Value::as_array_mut) {
                Some(items) => items.iter_mut().for_each(withhold_diagnostic),
                None => withhold_diagnostic(&mut answer),
            }
        }
        return super::json_http_response("200 OK", answer);
    }
    if let Some(id) = route.strip_prefix(&format!("GET {definitions}/")) {
        let answered = if state.fault(Fault::ReadOtherDefinition) {
            CLOUD_TARGET
        } else {
            id
        };
        return match state.definitions.get(id) {
            Some(definition) => {
                super::json_http_response("200 OK", gateway_definition(answered, definition))
            }
            None => gateway_not_found(),
        };
    }
    if let Some(id) = route
        .strip_prefix(&format!("POST {definitions}/"))
        .and_then(|rest| rest.strip_suffix("/revisions"))
    {
        let body = request.json();
        return state.publication(&key, keyed, |state| {
            let lose = std::mem::take(&mut state.lose_next_publication);
            let forbid = std::mem::take(&mut state.forbid_next_publication);
            let Some(definition) = state.definitions.get_mut(id) else {
                return Err(gateway_not_found());
            };
            if forbid {
                return Err(super::problem_http_response(
                    "403 Forbidden",
                    json!({"type": format!("{PROBLEMS}forbidden"), "title": "Forbidden", "status": 403}),
                ));
            }
            if lose {
                definition.current += 1;
            }
            if body["expectedCurrentRevision"] != json!(definition.current) {
                return Err(super::problem_http_response(
                    "409 Conflict",
                    json!({
                        "type": format!("{PROBLEMS}definition-revision-conflict"),
                        "title": "Definition revision conflict",
                        "status": 409,
                        "workflow": {"currentRevision": definition.current},
                    }),
                ));
            }
            definition.published = state
                .declarations
                .merge(&body, Some(&definition.published))?;
            definition.current += 1;
            Ok(("201 Created", gateway_publication(id, definition)))
        });
    }
    gateway_not_found()
}

fn gateway_tree(digest: &str, sealed: bool) -> Value {
    json!({
        "digest": digest,
        "state": if sealed { "sealed" } else { "uploading" },
        "sizeBytes": 512,
        "fileCount": 4,
        "name": if sealed { json!("engineering") } else { Value::Null },
        "createdAt": CLOUD_TIME,
        "sealedAt": if sealed { json!(CLOUD_TIME) } else { Value::Null },
    })
}

fn gateway_definition(id: &str, definition: &FakeDefinition) -> Value {
    json!({
        "id": id,
        "projectId": CLOUD_PROJECT,
        "name": definition.name.as_deref().unwrap_or("engineering"),
        "state": if definition.archived { "archived" } else { "active" },
        "automaticStarts": definition.automatic_starts,
        "executionPrincipalId": definition.principal,
        "currentRevision": definition.current,
        "createdAt": CLOUD_TIME,
        "updatedAt": CLOUD_TIME,
    })
}

const CLOUD_EVALUATION: &str = "wev_01k0z6r1w8f4jy2m7q9v3x5abc";
const CLOUD_BLOCKED_EVALUATION: &str = "wev_01k0z6r1w8f4jy2m7q9v3x5abd";
const CLOUD_BLOCKING_RUN: &str = "run_01k0z6r1w8f4jy2m7q9v3x5abd";
const CLOUD_NOT_READY_EVALUATION: &str = "wev_01k0z6r1w8f4jy2m7q9v3x5abe";

/// A `failed` evaluation of definition `id` whose project was not ready, with the readiness
/// blockers Cloud observed when it refused the start.
fn gateway_not_ready_evaluation(id: &str) -> Value {
    let mut evaluation = gateway_evaluation(id, CLOUD_NOT_READY_EVALUATION);
    evaluation["reason"] = json!("project_not_ready");
    evaluation["observations"] = json!({
        "observedAt": CLOUD_TIME,
        "admissionFailure": {"phase": "create_run", "cause": "source_unavailable"},
        "project": {"blockers": ["runner_pool_unassigned", "repository_detached"]},
    });
    evaluation
}

/// A `skipped_active` evaluation of definition `id` that names the run holding its subject.
fn gateway_blocked_evaluation(id: &str) -> Value {
    let mut evaluation = gateway_evaluation(id, CLOUD_BLOCKED_EVALUATION);
    evaluation["state"] = json!("skipped_active");
    evaluation["reason"] = json!("subject_busy");
    evaluation["blockingRunId"] = json!(CLOUD_BLOCKING_RUN);
    evaluation
}

/// A failed start evaluation `evaluation` of definition `id` with its stored reason.
fn gateway_evaluation(id: &str, evaluation: &str) -> Value {
    json!({
        "id": evaluation,
        "definitionId": id,
        "revision": 2,
        "triggerName": "start-on-todo",
        "connectionId": "lnc_01k0z6r1w8f4jy2m7q9v3x5abc",
        "executionPrincipalId": CLOUD_PRINCIPAL,
        "eventName": "issue.state_entered",
        "event": {
            "issue": {"id": "issue-7", "identifier": "AUTO-7"},
            "issueUpdatedAt": CLOUD_TIME,
            "team": CLOUD_TEAM_ID,
            "state": "state-todo",
            "actor": null,
            "at": CLOUD_TIME,
        },
        "state": "failed",
        "reason": "owner_unresolved",
        "observations": null,
        "runId": null,
        "blockingRunId": null,
        "cycleNumber": 1,
        "attemptNumber": 2,
        "cycleStartedAt": CLOUD_TIME,
        "cycleDeadline": "2026-11-11T12:00:00Z",
        "nextAttemptAt": null,
        "acceptedAt": CLOUD_TIME,
        "expiresAt": "2026-12-10T12:00:00Z",
        "settledAt": CLOUD_TIME,
    })
}

const CLOUD_PUSH_EVALUATION: &str = "wev_01k0z6r1w8f4jy2m7q9v3x5abf";
const CLOUD_PUSH_COMMIT: &str = "9fceb02d0ae598e95dc970b74767f19372d61af8";

/// The start evaluation of a push to `main` of definition `id`, newer than
/// [`CLOUD_EVALUATION`], which Cloud shows from evaluation vocabulary 2.
fn gateway_push_evaluation(id: &str) -> Value {
    let mut evaluation = gateway_evaluation(id, CLOUD_PUSH_EVALUATION);
    evaluation["triggerName"] = json!("pushed");
    evaluation["connectionId"] = json!("ghi_01k0z6r1w8f4jy2m7q9v3x5ab0");
    evaluation["eventName"] = json!("push");
    evaluation["event"] = json!({
        "repository": {"id": "11", "fullName": "acme/widgets"},
        "ref": "refs/heads/main",
        "branch": "main",
        "commit": CLOUD_PUSH_COMMIT,
        "before": null,
        "created": true,
        "forced": false,
        "projectBranch": true,
        "at": CLOUD_TIME,
    });
    evaluation
}

const CLOUD_RUN_ENDED_EVALUATION: &str = "wev_01k0z6r1w8f4jy2m7q9v3x5abj";
const CLOUD_ENDED_RUN: &str = "run_01k0z6r1w8f4jy2m7q9v3x5abe";

/// The start evaluation of the end of a `verify` run of definition `id`, newer than the push
/// evaluation, which Cloud shows only under evaluation vocabulary 4 and above.
fn gateway_run_ended_evaluation(id: &str) -> Value {
    let mut evaluation = gateway_evaluation(id, CLOUD_RUN_ENDED_EVALUATION);
    evaluation["triggerName"] = json!("repairMain");
    evaluation["connectionId"] = Value::Null;
    evaluation["eventName"] = json!("run.ended");
    evaluation["reason"] = json!("export_too_large");
    evaluation["observations"] = json!({"observedAt": CLOUD_TIME, "input": "request"});
    evaluation["event"] = json!({
        "definitionId": CLOUD_BOUND_DEFINITION,
        "runId": CLOUD_ENDED_RUN,
        "attempt": 2,
        "outcome": "broken",
        "subject": "main",
        "commit": "3b18e512dba79e4c8300dd08aeb37f8e728b8dad",
        "exports": {
            "request": {"state": "too_large", "size": 70000},
            "notes": {"state": "available", "size": 12},
        },
        "at": CLOUD_TIME,
    });
    evaluation
}

const CLOUD_WAITING_EVALUATION: &str = "wev_01k0z6r1w8f4jy2m7q9v3x5abg";
const CLOUD_UNBLOCKED_EVALUATION: &str = "wev_01k0z6r1w8f4jy2m7q9v3x5abh";
const CLOUD_UNBLOCKED_RUN: &str = "run_01k0z6r1w8f4jy2m7q9v3x5abh";
const CLOUD_WAIT_SINCE: &str = "2026-11-10T09:30:00Z";
const CLOUD_NEXT_READ: &str = "2026-11-10T12:05:00Z";

/// An `issue.unblocked_in_state` evaluation `evaluation` of definition `id`, which Cloud
/// shows from evaluation vocabulary 3, observed with `blocker_wait`.
fn gateway_blocker_wait_evaluation(id: &str, evaluation: &str, blocker_wait: Value) -> Value {
    let mut evaluation = gateway_evaluation(id, evaluation);
    evaluation["eventName"] = json!("issue.unblocked_in_state");
    evaluation["event"]["from"] = json!("state-backlog");
    evaluation["observations"] = json!({
        "observedAt": CLOUD_TIME,
        "rule": {"matched": true},
        "blockerWait": blocker_wait,
    });
    evaluation
}

/// An unsettled evaluation of definition `id` waiting since [`CLOUD_WAIT_SINCE`] for two
/// open blockers, one of which Cloud returned without an identifier.
fn gateway_waiting_evaluation(id: &str) -> Value {
    let mut evaluation = gateway_blocker_wait_evaluation(
        id,
        CLOUD_WAITING_EVALUATION,
        json!({
            "since": CLOUD_WAIT_SINCE,
            "blockers": [
                {"id": "issue-a", "identifier": "AUTO-2"},
                {"id": "issue-c", "identifier": null},
            ],
        }),
    );
    evaluation["state"] = json!("retry_waiting");
    evaluation["event"]["actor"] = json!({"id": "linear-user-7", "type": "user"});
    evaluation["reason"] = json!("issue_blocked");
    evaluation["nextAttemptAt"] = json!(CLOUD_NEXT_READ);
    evaluation["settledAt"] = Value::Null;
    evaluation
}

/// An evaluation of definition `id` that waited for its issue's blockers and created a run
/// once none was open.
fn gateway_unblocked_evaluation(id: &str) -> Value {
    let mut evaluation = gateway_blocker_wait_evaluation(
        id,
        CLOUD_UNBLOCKED_EVALUATION,
        json!({"since": CLOUD_WAIT_SINCE, "blockers": []}),
    );
    evaluation["state"] = json!("run_created");
    evaluation["reason"] = Value::Null;
    evaluation["runId"] = json!(CLOUD_UNBLOCKED_RUN);
    evaluation
}

const CLOUD_DIAGNOSED_EVALUATION: &str = "wev_01k0z6r1w8f4jy2m7q9v3x5abk";
const CLOUD_STAGE_DIAGNOSED_EVALUATION: &str = "wev_01k0z6r1w8f4jy2m7q9v3x5abm";

/// A start evaluation `evaluation` of definition `id` that failed `issue_unavailable` with
/// `diagnostic`, which Cloud answers from representation 4.
fn gateway_issue_unavailable_evaluation(id: &str, evaluation: &str, diagnostic: Value) -> Value {
    let mut evaluation = gateway_evaluation(id, evaluation);
    evaluation["reason"] = json!("issue_unavailable");
    evaluation["observations"] = json!({"observedAt": CLOUD_TIME, "diagnostic": diagnostic});
    evaluation
}

/// An evaluation of definition `id` whose issue read Linear refused with HTTP 401.
fn gateway_diagnosed_evaluation(id: &str) -> Value {
    gateway_issue_unavailable_evaluation(
        id,
        CLOUD_DIAGNOSED_EVALUATION,
        json!({"stage": "issue_read", "errorType": "token_refused", "httpStatus": 401}),
    )
}

/// An evaluation of definition `id` whose issue read Cloud could not classify further.
fn gateway_stage_diagnosed_evaluation(id: &str) -> Value {
    gateway_issue_unavailable_evaluation(
        id,
        CLOUD_STAGE_DIAGNOSED_EVALUATION,
        json!({"stage": "issue_read"}),
    )
}

/// Drops `observations.diagnostic` from `evaluation`, as Cloud answers it below
/// representation 4.
fn withhold_diagnostic(evaluation: &mut Value) {
    if let Some(observations) = evaluation
        .get_mut("observations")
        .and_then(Value::as_object_mut)
    {
        observations.remove("diagnostic");
    }
}

/// What revision `current` of a definition `define` holds publishes: the engineering root
/// with `connection` `local`, `linearTeam` `AUTO`, `repository` `useful-machinery/platform`
/// and the defaults.
fn engineering_published(current: i64) -> Value {
    let body = json!({
        "treeDigest": gateway_tree_digest(current),
        "bindings": {
            "connection": "local",
            "linearTeam": "AUTO",
            "repository": "useful-machinery/platform",
        },
        "executablePaths": [],
    });
    Declarations::engineering()
        .merge(&body, None)
        .unwrap_or_else(|_| panic!("the engineering snapshot should merge"))
}

/// Definition `id` and its current revision, as a create or publication answers them: the
/// snapshot that revision published, its integrations' only when it holds any.
fn gateway_publication(id: &str, definition: &FakeDefinition) -> Value {
    let published = &definition.published;
    let mut revision = json!({
        "definitionId": id,
        "number": definition.current,
        "treeDigest": published["treeDigest"],
        "bindings": published["bindings"],
        "resolution": {},
        "publishedAt": CLOUD_TIME,
        "publishedBy": CLOUD_PUBLISHER,
    });
    if published["integrationBindings"]
        .as_object()
        .is_some_and(|groups| !groups.is_empty())
    {
        revision["integrationBindings"] = published["integrationBindings"].clone();
    }
    json!({"definition": gateway_definition(id, definition), "revision": revision})
}

/// `useful workflow definition publish DIR [--bindings FILE] --on project --org ORG --project
/// PRJ --allow-insecure-http EXTRA`.
fn cloud_publish_args<'a>(
    tree: &'a Tree,
    bindings: Option<&'a str>,
    extra: &[&'a str],
) -> Vec<&'a str> {
    let mut args = vec!["workflow", "definition", "publish", tree.path()];
    if let Some(bindings) = bindings {
        args.extend_from_slice(&["--bindings", bindings]);
    }
    args.extend_from_slice(&[
        "--on",
        "project",
        "--org",
        CLOUD_ORGANIZATION,
        "--project",
        CLOUD_PROJECT,
        "--allow-insecure-http",
    ]);
    args.extend_from_slice(extra);
    args
}

fn routes(requests: &[GatewayRequest]) -> Vec<String> {
    requests.iter().map(GatewayRequest::route).collect()
}

/// A publication to Cloud writes nothing under the home, not even the home
/// itself.
fn assert_home_untouched(home: &Home) {
    assert!(
        !home.root.exists(),
        "a publication to Cloud must write nothing under the home"
    );
}

/// The project's definitions route, read before a publication chooses its target.
fn project_definitions() -> String {
    format!(
        "/api/v1/organizations/{CLOUD_ORGANIZATION}/projects/{CLOUD_PROJECT}/workflow-definitions"
    )
}

/// The body of the one request of `requests` on `route`.
fn sent_to(requests: &[GatewayRequest], route: &str) -> Value {
    let sent = requests
        .iter()
        .filter(|request| request.route() == route)
        .collect::<Vec<_>>();
    assert_eq!(sent.len(), 1, "{route}: {:?}", routes(requests));
    sent[0].json()
}

/// What the current revision of the fake Gateway's definition `id` published.
fn held_publication(gateway: &FakeGateway, id: &str) -> Value {
    gateway.state.lock().unwrap().definitions[id]
        .published
        .clone()
}

// A create and a publication send only the bindings the invocation names, `null` for a
// default, so a home that holds none of them publishes to an existing definition, and Cloud
// keeps every binding not named.
#[test]
fn publish_on_project_sends_only_the_bindings_it_names() {
    let (first_home, second_home) = (Home::new(), Home::new());
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let gateway = FakeGateway::new();
    let definitions = project_definitions();

    // The create sends the file's members and nothing for the bindings it does not name.
    let (output, requests) = gateway.run(
        &first_home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let cloud_id = cloud_definition(&report(&output));
    let create = sent_to(&requests, &format!("POST {definitions}"));
    assert_eq!(
        create["bindings"],
        json!({
            "connection": "local",
            "linearTeam": "AUTO",
            "repository": "useful-machinery/platform",
        }),
        "{create}"
    );
    assert!(create.get("integrationBindings").is_none(), "{create}");

    // A publication sends the one binding named.
    let publications = format!("POST {definitions}/{cloud_id}/revisions");
    let (output, requests) = gateway.run(
        &first_home,
        &cloud_publish_args(&tree, None, &["--binding", "done=Shipped", "--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let published = sent_to(&requests, &publications);
    assert_eq!(
        published["bindings"],
        json!({"done": "Shipped"}),
        "{published}"
    );
    assert_eq!(
        held_publication(&gateway, &cloud_id)["bindings"]["done"],
        json!({"kind": "linear.state", "value": "Shipped"})
    );

    // A home that holds none of the bindings publishes naming none, and Cloud keeps them all.
    let (output, requests) = gateway.run(
        &second_home,
        &cloud_publish_args(&tree, None, &["--to", &cloud_id, "--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let targeted = report(&output);
    assert_eq!(targeted["outcome"], "published", "{targeted}");
    let published = sent_to(&requests, &publications);
    for member in ["bindings", "integrationBindings"] {
        assert!(published.get(member).is_none(), "{member}: {published}");
    }
    let kept = held_publication(&gateway, &cloud_id)["bindings"].clone();
    assert_eq!(kept["done"]["value"], "Shipped", "{kept}");
    assert_eq!(kept["linearTeam"]["value"], "AUTO", "{kept}");

    // `--binding-default` sends `null`, which Cloud records as the default.
    let (output, requests) = gateway.run(
        &second_home,
        &cloud_publish_args(&tree, None, &["--binding-default", "done", "--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        sent_to(&requests, &publications)["bindings"],
        json!({"done": null})
    );
    assert_eq!(
        held_publication(&gateway, &cloud_id)["bindings"]["done"],
        json!({"kind": "linear.state", "value": "Done"})
    );
    for home in [&first_home, &second_home] {
        assert_home_untouched(home);
    }

    // An integration's binding is named under its id, and the rest of the snapshot stays.
    let home = Home::new();
    let tree = Tree::nested();
    let bindings = tree.nested_bindings();
    let gateway = FakeGateway::nested();
    let (output, _) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let id = cloud_definition(&report(&output));
    let publications = format!("POST {definitions}/{id}/revisions");
    for (named, sent, recorded) in [
        (
            ["--binding", "linear.ownedState=Doing"],
            json!("Doing"),
            "Doing",
        ),
        (
            ["--binding-default", "linear.ownedState"],
            Value::Null,
            "Engineering",
        ),
    ] {
        let mut args = named.to_vec();
        args.push("--json");
        let (output, requests) = gateway.run(&home, &cloud_publish_args(&tree, None, &args));
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let published = sent_to(&requests, &publications);
        assert_eq!(
            published["integrationBindings"],
            json!({"linear": {"ownedState": sent}}),
            "{published}"
        );
        assert!(published.get("bindings").is_none(), "{published}");
        let held = held_publication(&gateway, &id)["integrationBindings"].clone();
        assert_eq!(
            held["linear"]["ownedState"],
            json!({"kind": "state", "value": recorded}),
            "{held}"
        );
        assert_eq!(
            held["github"]["repository"],
            json!({"kind": "repository", "value": "useful-machinery/platform"}),
            "{held}"
        );
    }
    assert_home_untouched(&home);
}

// Whether the bindings a create names are complete is Cloud's to judge. One that names none,
// of a root whose bindings lack defaults, is sent and refused `binding-missing` naming the
// binding, and creates nothing.
#[test]
fn publish_on_project_leaves_a_create_that_names_no_binding_to_cloud() {
    let home = Home::new();
    let tree = Tree::engineering();
    let gateway = FakeGateway::new();
    for extra in [&["--json"][..], &["--new", "--json"]] {
        let (output, _) = gateway.run(&home, &cloud_publish_args(&tree, None, extra));
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let refused = report(&output);
        assert_eq!(refused["outcome"], "cloud_failed", "{refused}");
        assert_eq!(refused["cloud"]["failure"], "refused", "{refused}");
        assert_eq!(refused["cloud"]["status"], 422, "{refused}");
        assert_eq!(refused["cloud"]["problem"], "binding-missing", "{refused}");
        assert_eq!(
            refused["cloud"]["workflow"]["bindingKey"], "connection",
            "{refused}"
        );
    }
    assert!(gateway_definitions(&gateway).is_empty());
    assert_home_untouched(&home);
}

// `--on project` publishes to Cloud alone. With no definition of the tree's name it creates
// one, asking for the project's identical one; with one it publishes the next revision to it,
// sending no bindings without `--bindings`; with several it stops before any upload; `--new`
// reads no list.
#[test]
fn publish_on_project_creates_then_publishes_to_the_definition_of_the_tree_s_name() {
    use std::os::unix::fs::PermissionsExt as _;
    let home = Home::new();
    let tree = Tree::engineering();
    fs::set_permissions(
        Path::new(tree.path()).join("scripts/design.py"),
        fs::Permissions::from_mode(0o755),
    )
    .expect("script should become executable");
    let digest = format!("sha256:{}", report_digest(&validate(tree.path(), true)));
    let bindings = tree.engineering_bindings();
    let gateway = FakeGateway::new();
    let organization = format!("/api/v1/organizations/{CLOUD_ORGANIZATION}");
    let definitions = project_definitions();
    let list = format!("GET {definitions}");

    let (output, requests) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_no_content(&output);
    super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
    let first = report(&output);
    assert_eq!(first["schemaVersion"], 1);
    assert_eq!(first["command"], PUBLISH_COMMAND);
    assert_eq!(first["outcome"], "published", "{first}");
    for member in ["definition", "revision"] {
        assert!(first.get(member).is_none(), "{member}: {first}");
    }
    let cloud_id = cloud_definition(&first);
    assert!(
        cloud_id.starts_with(CLOUD_ID_STEM) && is_definition_id(&cloud_id),
        "{first}"
    );
    assert_eq!(first["cloud"]["organizationRef"], CLOUD_ORGANIZATION);
    assert_eq!(first["cloud"]["projectId"], CLOUD_PROJECT);
    assert_eq!(first["cloud"]["created"], true);
    assert_eq!(first["cloud"]["reused"], false);
    assert_eq!(first["cloud"]["revision"], 1);
    assert_eq!(first["cloud"]["treeDigest"], digest.as_str());
    assert!(first["cloud"].get("target").is_none(), "{first}");
    assert_home_untouched(&home);

    let seal = format!(
        "POST {organization}/workflow-trees/{}/seal",
        digest.replace(':', "%3A")
    );
    let stored = |path: &str| {
        let bytes = fs::read(Path::new(tree.path()).join(path)).unwrap();
        let sha256 = ring::digest::digest(&ring::digest::SHA256, &bytes)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        (bytes, sha256)
    };
    let (script, script_sha) = stored("scripts/design.py");
    let (policy, policy_sha) = stored("policy/engineering.json");
    assert_eq!(
        routes(&requests),
        vec![
            list.clone(),
            format!("POST {organization}/workflow-trees"),
            format!("PUT /storage/{policy_sha}"),
            format!("PUT /storage/{script_sha}"),
            seal,
            format!("POST {definitions}"),
        ]
    );
    let manifest = requests[1].json();
    assert_eq!(manifest["digest"], digest.as_str());
    let files = manifest["files"].as_array().expect("manifest files");
    assert_eq!(
        files
            .iter()
            .map(|file| (text(&file["path"], "path"), file["executable"].as_bool()))
            .collect::<Vec<_>>(),
        vec![
            ("design.yaml", Some(false)),
            ("policy/engineering.json", Some(false)),
            ("scripts/design.py", Some(true)),
            ("workflow.yaml", Some(false)),
        ]
    );
    assert_eq!(files[2]["sha256"], script_sha.as_str());
    assert_eq!(files[2]["sizeBytes"], script.len());
    assert_eq!(requests[2].body, policy);
    assert_eq!(requests[3].body, script);
    assert_eq!(requests[2].header("if-none-match"), Some("*"));
    let key = requests[4]
        .header("idempotency-key")
        .expect("seal key")
        .to_owned();
    assert_eq!(requests[5].header("idempotency-key"), Some(key.as_str()));
    for request in [&requests[0], &requests[1], &requests[4], &requests[5]] {
        assert_eq!(
            request.header("authorization"),
            Some(format!("Bearer {CLOUD_TOKEN}").as_str())
        );
    }
    let created = requests[5].json();
    assert_eq!(created["treeDigest"], digest.as_str());
    // The bindings the file names and no other.
    assert_eq!(
        created["bindings"]
            .as_object()
            .expect("bindings")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["connection", "linearTeam", "repository"])
    );
    assert_eq!(created["bindings"]["linearTeam"], "AUTO");
    // A binding the invocation does not name is not sent, so Cloud gives it its default.
    assert!(created["bindings"].get("ownedState").is_none(), "{created}");
    assert_eq!(created["executablePaths"], json!(["scripts/design.py"]));
    assert_eq!(created["reuseIdentical"], true);
    // A root that declares no integration binding sends no integration values.
    assert!(created.get("integrationBindings").is_none(), "{created}");

    // One active definition of the name: it is read and receives the next revision.
    let (output, requests) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let second = report(&output);
    assert_eq!(second["cloud"]["definition"], cloud_id.as_str());
    assert_eq!(second["cloud"]["target"], cloud_id.as_str());
    assert_eq!(second["cloud"]["created"], false);
    assert_eq!(second["cloud"]["reused"], false);
    assert_eq!(second["cloud"]["revision"], 2);
    assert_eq!(
        routes(&requests),
        vec![
            list.clone(),
            format!("POST {organization}/workflow-trees"),
            format!("GET {definitions}/{cloud_id}"),
            format!("POST {definitions}/{cloud_id}/revisions"),
        ]
    );
    let published = requests[3].json();
    assert_eq!(published["expectedCurrentRevision"], 1);
    assert_eq!(published["treeDigest"], digest.as_str());
    assert_eq!(published["bindings"]["linearTeam"], "AUTO");
    assert!(
        published.get("integrationBindings").is_none(),
        "{published}"
    );
    assert_ne!(requests[3].header("idempotency-key"), Some(key.as_str()));

    // A publication that names no binding sends none, so Cloud keeps its own.
    let (output, requests) = gateway.run(&home, &cloud_publish_args(&tree, None, &["--json"]));
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(report(&output)["cloud"]["revision"], 3);
    let published = requests.last().expect("publication request");
    assert_eq!(
        published.route(),
        format!("POST {definitions}/{cloud_id}/revisions")
    );
    assert!(
        published.json().get("bindings").is_none(),
        "{:?}",
        published.json()
    );

    // A refusal names the problem type.
    gateway.lose_next_publication();
    let (output, requests) = gateway.run(&home, &cloud_publish_args(&tree, Some(&bindings), &[]));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(requests.len(), 4, "{:?}", routes(&requests));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("definition-revision-conflict"), "{stderr}");

    // `--new` creates another without reading the list or asking for the identical one.
    let (output, requests) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--new", "--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let fourth = report(&output);
    let other = cloud_definition(&fourth);
    assert_ne!(other, cloud_id);
    assert_eq!(fourth["cloud"]["created"], true);
    assert_eq!(fourth["cloud"]["revision"], 1);
    assert_eq!(
        routes(&requests),
        vec![
            format!("POST {organization}/workflow-trees"),
            format!("POST {definitions}"),
        ]
    );
    assert!(requests[1].json().get("reuseIdentical").is_none());

    // Two active definitions of the name: exit 2 naming both, `--to` and `--new`, before any
    // upload.
    let (output, requests) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(routes(&requests), vec![list]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for named in [cloud_id.as_str(), other.as_str(), "--to", "--new"] {
        assert!(stderr.contains(named), "{named}: {stderr}");
    }

    // An archived definition of the name is passed over: with the other one archived, the
    // publication reaches the one that is still active.
    let (output, _) = gateway.run(
        &home,
        &[
            "workflow",
            "definition",
            "archive",
            other.as_str(),
            "--org",
            CLOUD_ORGANIZATION,
            "--project",
            CLOUD_PROJECT,
            "--allow-insecure-http",
            "--json",
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let (output, _) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(report(&output)["cloud"]["target"], cloud_id.as_str());
    assert_home_untouched(&home);
}

// The create and the publication of a root that declares bindings under its integrations
// send each integration's bindings the file names, by name under its id, and no flat
// block.
#[test]
fn publish_cloud_sends_each_integrations_binding_values() {
    let home = Home::new();
    let tree = Tree::nested();
    let bindings = tree.nested_bindings();
    let gateway = FakeGateway::nested();
    let definitions = format!(
        "/api/v1/organizations/{CLOUD_ORGANIZATION}/projects/{CLOUD_PROJECT}/workflow-definitions"
    );
    let expected = nested_bindings();

    let (output, requests) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let first = report(&output);
    let cloud_id = cloud_definition(&first);
    let created = requests
        .iter()
        .find(|request| request.route() == format!("POST {definitions}"))
        .expect("the create")
        .json();
    assert_eq!(created["integrationBindings"], expected, "{created}");
    assert!(created.get("bindings").is_none(), "{created}");

    let (output, requests) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let published = requests
        .iter()
        .find(|request| request.route() == format!("POST {definitions}/{cloud_id}/revisions"))
        .expect("the publication")
        .json();
    assert_eq!(published["integrationBindings"], expected, "{published}");
    assert!(published.get("bindings").is_none(), "{published}");
}

// A refusal about an integration binding names the integration and the binding, and one
// about the integration itself names it alone, in the human report and in `--json`'s
// `workflow` facts.
#[test]
fn publish_cloud_reports_the_integration_a_refusal_names() {
    let home = Home::new();
    let tree = Tree::nested();
    let bindings = tree.nested_bindings();
    let gateway = FakeGateway::new();
    let both = json!({"integration": "linear", "bindingKey": "team"});
    let alone = json!({"integration": "linear"});

    gateway.refuse_next_keyed_with(
        "422 Unprocessable Entity",
        422,
        "binding-unresolved",
        both.clone(),
    );
    let (output, _) = gateway.run(&home, &cloud_publish_args(&tree, Some(&bindings), &[]));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_contains_all(&stderr, &["binding-unresolved", "linear", "team"]);

    gateway.refuse_next_keyed_with(
        "422 Unprocessable Entity",
        422,
        "binding-unresolved",
        both.clone(),
    );
    let (output, _) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let refused = report(&output);
    assert_eq!(refused["outcome"], "cloud_failed", "{refused}");
    assert_eq!(
        refused["cloud"]["problem"], "binding-unresolved",
        "{refused}"
    );
    assert_eq!(refused["cloud"]["workflow"], both, "{refused}");

    gateway.refuse_next_keyed_with(
        "422 Unprocessable Entity",
        422,
        "binding-unresolved",
        alone.clone(),
    );
    let (output, _) = gateway.run(&home, &cloud_publish_args(&tree, Some(&bindings), &[]));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_contains_all(&stderr, &["binding-unresolved", "linear"]);
    assert!(!stderr.contains("team"), "{stderr}");

    gateway.refuse_next_keyed_with(
        "422 Unprocessable Entity",
        422,
        "binding-unresolved",
        alone.clone(),
    );
    let (output, _) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(report(&output)["cloud"]["workflow"], alone);
}

#[test]
fn publish_on_project_resends_a_lost_publication_once_and_publishes_executable_bits() {
    use std::os::unix::fs::PermissionsExt as _;
    let home = Home::new();
    let tree = Tree::engineering();
    let script = Path::new(tree.path()).join("scripts/design.py");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755))
        .expect("script should become executable");
    let bindings = tree.engineering_bindings();
    let gateway = FakeGateway::new();
    let definitions = project_definitions();

    // The create's reply is lost: it is sent once more under the same key and creates one
    // definition.
    gateway.drop_next_publication_reply();
    let (output, requests) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let first = report(&output);
    assert_eq!(first["outcome"], "published", "{first}");
    let cloud_id = cloud_definition(&first);
    assert_eq!(first["cloud"]["created"], true);
    let digest = text(&first["cloud"]["treeDigest"], "tree digest").to_owned();
    let creates = requests
        .iter()
        .filter(|request| request.route() == format!("POST {definitions}"))
        .collect::<Vec<_>>();
    assert_eq!(creates.len(), 2, "{:?}", routes(&requests));
    let key = creates[0].header("idempotency-key").expect("create key");
    assert_eq!(creates[1].header("idempotency-key"), Some(key));
    assert_eq!(creates[0].body, creates[1].body);
    assert_eq!(
        creates[0].json()["executablePaths"],
        json!(["scripts/design.py"])
    );
    assert_eq!(gateway_definitions(&gateway), vec![(cloud_id.clone(), 1)]);
    assert_home_untouched(&home);

    // Clearing the last executable bit leaves the digest and publishes a new revision that
    // runs no file executable.
    fs::set_permissions(&script, fs::Permissions::from_mode(0o644))
        .expect("script should stop being executable");
    let (output, requests) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let second = report(&output);
    assert_eq!(second["cloud"]["treeDigest"], digest.as_str());
    assert_eq!(second["cloud"]["definition"], cloud_id.as_str());
    assert_eq!(second["cloud"]["revision"], 2);
    let published = requests
        .iter()
        .find(|request| request.route() == format!("POST {definitions}/{cloud_id}/revisions"))
        .expect("publication request")
        .json();
    assert_eq!(published["treeDigest"], digest.as_str());
    assert_eq!(published["executablePaths"], json!([]));
}

// A create or publication answered with a transient problem is sent once more under its key; a
// second such answer is reported as Cloud being unavailable, and a 503 naming its own cause is
// refused, neither with a diagnostic.
#[test]
fn publish_on_project_resends_a_create_or_publication_answered_with_a_transient_problem_once() {
    let home = Home::new();
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let gateway = FakeGateway::new();
    let definitions = project_definitions();
    let keyed_to = |requests: &[GatewayRequest], route: &str| {
        requests
            .iter()
            .filter(|request| request.route() == route)
            .map(|request| {
                (
                    request.header("idempotency-key").expect("key").to_owned(),
                    request.body.clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    let publish = || {
        gateway.run(
            &home,
            &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
        )
    };

    gateway.answer_next_keyed_with("503 Service Unavailable", 503, "service-unavailable");
    let (output, requests) = publish();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let first = report(&output);
    assert_eq!(first["outcome"], "published", "{first}");
    let cloud_id = cloud_definition(&first);
    let creates = keyed_to(&requests, &format!("POST {definitions}"));
    assert_eq!(creates.len(), 2, "{:?}", routes(&requests));
    assert_eq!(creates[0], creates[1]);
    assert_eq!(gateway_definitions(&gateway), vec![(cloud_id.clone(), 1)]);

    let publications = format!("POST {definitions}/{cloud_id}/revisions");
    gateway.answer_next_keyed_with("500 Internal Server Error", 500, "internal-server-error");
    gateway.answer_next_keyed_with("500 Internal Server Error", 500, "internal-server-error");
    let (output, requests) = publish();
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    let failed = report(&output);
    assert_eq!(failed["outcome"], "cloud_failed", "{failed}");
    assert_eq!(failed["cloud"]["failure"], "unavailable", "{failed}");
    assert_eq!(failed["cloud"]["target"], cloud_id.as_str(), "{failed}");
    for member in ["status", "problem", "workflow", "diagnostic"] {
        assert!(failed["cloud"].get(member).is_none(), "{failed}");
    }
    for member in ["definition", "revision"] {
        assert!(failed.get(member).is_none(), "{member}: {failed}");
    }
    let sent = keyed_to(&requests, &publications);
    assert_eq!(sent.len(), 2, "{:?}", routes(&requests));
    assert_eq!(sent[0].0, sent[1].0);
    assert_eq!(gateway_definitions(&gateway), vec![(cloud_id.clone(), 1)]);

    gateway.answer_next_keyed_with(
        "503 Service Unavailable",
        503,
        "binding-resolution-unavailable",
    );
    let (output, requests) = publish();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let refused = report(&output);
    assert_eq!(refused["cloud"]["failure"], "refused", "{refused}");
    assert_eq!(refused["cloud"]["status"], 503);
    assert!(refused["cloud"].get("diagnostic").is_none(), "{refused}");
    assert_eq!(
        refused["cloud"]["problem"],
        "binding-resolution-unavailable"
    );
    assert_eq!(keyed_to(&requests, &publications).len(), 1);
    assert_eq!(gateway_definitions(&gateway), vec![(cloud_id, 1)]);
    assert_home_untouched(&home);
}

// An answer failing a check at the tree upload, the seal or the create is an invalid response
// reported with the stage and check that failed (and the status of a status check), and nothing
// of the signed URL, the session or the body.
#[test]
fn publish_on_project_reports_the_stage_and_check_of_an_invalid_response() {
    let home = Home::new();
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let gateway = FakeGateway::new();
    let create = format!("POST {}", project_definitions());
    let withheld = [CAPABILITY_PASSWORD, "X-Amz-Signature", CLOUD_TOKEN];

    gateway.answer_next_with(Fault::UploadCapabilityCredentials);
    let (output, _) = gateway.run(&home, &cloud_publish_args(&tree, Some(&bindings), &[]));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    super::assert_no_secret_output(&output, &withheld);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_contains_all(&stderr, &["file_upload", "capability_url_policy"]);

    for (fault, diagnostic) in [
        (
            Fault::UploadCapabilityCredentials,
            json!({"stage": "file_upload", "check": "capability_url_policy"}),
        ),
        (
            Fault::SealWithoutKey,
            json!({"stage": "tree_seal", "check": "idempotency_key"}),
        ),
        (
            Fault::CreateHtmlNotFound,
            json!({"stage": "definition_create", "check": "problem_decode", "httpStatus": 404}),
        ),
    ] {
        gateway.answer_next_with(fault);
        let (output, requests) = gateway.run(
            &home,
            &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
        );
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        super::assert_no_secret_output(&output, &withheld);
        let failed = report(&output);
        assert_eq!(failed["outcome"], "cloud_failed", "{failed}");
        assert_eq!(failed["cloud"]["failure"], "invalid_response", "{failed}");
        assert_eq!(failed["cloud"]["diagnostic"], diagnostic, "{failed}");
        for member in ["status", "problem", "workflow"] {
            assert!(failed["cloud"].get(member).is_none(), "{failed}");
        }
        let sent = routes(&requests);
        let seal = |route: &String| route.starts_with("POST ") && route.ends_with("/seal");
        match fault {
            Fault::UploadCapabilityCredentials => {
                assert!(
                    !sent
                        .iter()
                        .any(|route| route.starts_with("PUT /storage/") || seal(route)),
                    "{sent:?}"
                );
            }
            Fault::SealWithoutKey => assert!(sent.iter().any(seal), "{sent:?}"),
            _ => {}
        }
        assert_eq!(
            sent.iter().filter(|route| **route == create).count(),
            usize::from(fault == Fault::CreateHtmlNotFound),
            "{sent:?}"
        );
    }
    assert!(gateway_definitions(&gateway).is_empty());
    assert_home_untouched(&home);
}

// What a publication cannot send is refused before it is sent: `--to` with `--new`, `--org` or
// `--project` with a publication that stays under the home and the retired Cloud options are
// usage errors, and a root with no `name` and a named binding the root does not declare are
// refused. Whether the bindings named are complete is Cloud's to judge, so a create that names
// none is sent.
#[test]
fn publish_on_project_refuses_what_it_cannot_publish_before_sending_it() {
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let gateway = FakeGateway::new();
    let base = ["workflow", "definition", "publish", tree.path()];
    for extra in [
        &["--to", "engineering", "--new"][..],
        &["--on", "local", "--org", CLOUD_ORGANIZATION],
        &["--on", "local", "--project", CLOUD_PROJECT],
        // With no `--on` the publication stays under the home too, whatever name `--to` gives.
        &["--org", CLOUD_ORGANIZATION],
        &["--project", CLOUD_PROJECT],
        &["--to", "engineering", "--project", CLOUD_PROJECT],
        &["--cloud", CLOUD_ORGANIZATION, "--project", CLOUD_PROJECT],
        &["--cloud-new"],
        &["--cloud-to", CLOUD_TARGET],
    ] {
        let home = Home::new();
        let args = [&base[..], &["--bindings", &bindings], extra].concat();
        let (output, requests) = gateway.run(&home, &args);
        assert_eq!(output.status.code(), Some(2), "{extra:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{extra:?}: {output:?}");
        assert!(requests.is_empty(), "{extra:?}: {:?}", routes(&requests));
        assert!(home.workflow_entries().is_empty(), "{extra:?}");
    }

    let refused = |args: &[&str], code: &str| {
        let home = Home::new();
        let (output, requests) = gateway.run(&home, args);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let refused = report(&output);
        assert_eq!(refused["outcome"], "refused", "{refused}");
        assert_eq!(refused["diagnostics"][0]["code"], code, "{refused}");
        assert_home_untouched(&home);
        routes(&requests)
    };
    let unnamed = Tree::with(
        &ROOT_WORKFLOW.replacen("name: engineering\n", "", 1),
        DESIGN_WORKFLOW,
    );
    let unnamed_bindings = unnamed.engineering_bindings();
    let sent = refused(
        &cloud_publish_args(&unnamed, Some(&unnamed_bindings), &["--json"]),
        "definition_name_missing",
    );
    assert!(sent.is_empty(), "{sent:?}");
    for named in [
        &["--binding", "nope=value"][..],
        &["--binding-default", "nope"],
    ] {
        let extra = [named, &["--json"]].concat();
        let sent = refused(
            &cloud_publish_args(&tree, Some(&bindings), &extra),
            "binding_undeclared",
        );
        assert!(sent.is_empty(), "{sent:?}");
    }
    assert!(gateway_definitions(&gateway).is_empty());
}

/// A Cloud definition id of the definition id shape that no fake Gateway mints.
const CLOUD_TARGET: &str = "def_01k0z6r1w8f4jy2m7q9v3x5abz";

/// The fake's definitions, each with its current revision.
fn gateway_definitions(gateway: &FakeGateway) -> Vec<(String, i64)> {
    gateway
        .state
        .lock()
        .unwrap()
        .definitions
        .iter()
        .map(|(id, definition)| (id.clone(), definition.current))
        .collect()
}

/// No request created a Cloud definition, in the addressed project or any other.
fn assert_no_definition_created(requests: &[GatewayRequest]) {
    let routes = routes(requests);
    assert!(
        !routes
            .iter()
            .any(|route| route.starts_with("POST ") && route.ends_with("/workflow-definitions")),
        "{routes:?}"
    );
}

// `--to` names the Cloud definition of the project in effect a revision goes to, by name or by
// ID with `--on project`, or by an ID the home does not hold with no `--on`; the publication
// never creates one, from a home that has never published.
#[test]
fn publish_to_publishes_to_the_named_cloud_definition_and_never_creates_one() {
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let gateway = FakeGateway::new();
    let organization = format!("/api/v1/organizations/{CLOUD_ORGANIZATION}");
    let definitions = project_definitions();
    let alpha = format!("{CLOUD_ID_STEM}c");
    gateway.define_named(&alpha, 2, "alpha");
    let to_alpha = [
        format!("GET {definitions}/{alpha}"),
        format!("POST {definitions}/{alpha}/revisions"),
    ];
    // Publishes from a fresh home with `args`, asserting it reached `alpha` at `revision` and
    // created nothing; the routes it sent.
    let reached = |args: &[&str], revision: i64| {
        let home = Home::new();
        let (output, requests) = gateway.run(&home, args);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_no_content(&output);
        super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
        let targeted = report(&output);
        assert_eq!(targeted["outcome"], "published", "{targeted}");
        assert_eq!(targeted["cloud"]["created"], false);
        assert_eq!(targeted["cloud"]["reused"], false);
        assert_eq!(targeted["cloud"]["definition"], alpha.as_str());
        assert_eq!(targeted["cloud"]["target"], alpha.as_str());
        assert_eq!(targeted["cloud"]["revision"], revision);
        assert_no_definition_created(&requests);
        assert_home_untouched(&home);
        let sent = routes(&requests);
        assert!(sent.ends_with(&to_alpha), "{sent:?}");
        sent
    };

    // By name, whatever the tree's own name: the list names the definition.
    let sent = reached(
        &cloud_publish_args(&tree, Some(&bindings), &["--to", "alpha", "--json"]),
        3,
    );
    assert_eq!(
        sent[..2],
        [
            format!("GET {definitions}"),
            format!("POST {organization}/workflow-trees")
        ]
    );

    // By ID: no list is read.
    let sent = reached(
        &cloud_publish_args(&tree, Some(&bindings), &["--to", &alpha, "--json"]),
        4,
    );
    assert_eq!(sent[0], format!("POST {organization}/workflow-trees"));

    // By an ID the home does not hold, with no `--on`: found in the project in effect.
    let sent = reached(
        &[
            "workflow",
            "definition",
            "publish",
            tree.path(),
            "--bindings",
            &bindings,
            "--to",
            &alpha,
            "--org",
            CLOUD_ORGANIZATION,
            "--project",
            CLOUD_PROJECT,
            "--allow-insecure-http",
            "--json",
        ],
        5,
    );
    assert_eq!(sent[0], to_alpha[0]);

    // A changed root name still reaches the named definition.
    let renamed = Tree::with(
        &ROOT_WORKFLOW.replacen("name: engineering\n", "name: beta\n", 1),
        DESIGN_WORKFLOW,
    );
    let renamed_bindings = renamed.engineering_bindings();
    reached(
        &cloud_publish_args(
            &renamed,
            Some(&renamed_bindings),
            &["--to", &alpha, "--json"],
        ),
        6,
    );
    assert_eq!(gateway_definitions(&gateway), vec![(alpha, 6)]);
}

// A target Cloud refuses, of another project included, is reported naming it and creates
// nothing; a name the project does not hold is `definition_not_found` before anything is
// uploaded.
#[test]
fn publish_to_refusals_create_nothing() {
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let gateway = FakeGateway::new();
    let cloud_id = format!("{CLOUD_ID_STEM}c");
    gateway.define(&cloud_id, 2);
    // Publishes from a fresh home with `args`, asserting a Cloud refusal of `target` with
    // `status` and `problem` and no create in any project.
    let refused = |args: &[&str], target: &str, status: u16, problem: &str| {
        let home = Home::new();
        let (output, requests) = gateway.run(&home, args);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let failed = report(&output);
        assert_eq!(failed["outcome"], "cloud_failed", "{failed}");
        assert_eq!(failed["cloud"]["failure"], "refused");
        assert_eq!(failed["cloud"]["status"], status);
        assert_eq!(failed["cloud"]["problem"], problem);
        assert_eq!(failed["cloud"]["target"], target);
        assert!(failed["cloud"].get("definition").is_none(), "{failed}");
        assert_no_definition_created(&requests);
        assert_home_untouched(&home);
        failed
    };

    refused(
        &cloud_publish_args(&tree, Some(&bindings), &["--to", CLOUD_TARGET, "--json"]),
        CLOUD_TARGET,
        404,
        "not-found",
    );
    assert_eq!(gateway_definitions(&gateway), vec![(cloud_id.clone(), 2)]);

    let other_project = [
        "workflow",
        "definition",
        "publish",
        tree.path(),
        "--bindings",
        &bindings,
        "--on",
        "project",
        "--org",
        CLOUD_ORGANIZATION,
        "--project",
        "prj_01k0z6r1w8f4jy2m7q9v3x5xyz",
        "--to",
        &cloud_id,
        "--allow-insecure-http",
        "--json",
    ];
    refused(&other_project, &cloud_id, 404, "not-found");
    assert_eq!(gateway_definitions(&gateway), vec![(cloud_id.clone(), 2)]);

    gateway.forbid_next_publication();
    refused(
        &cloud_publish_args(&tree, Some(&bindings), &["--to", &cloud_id, "--json"]),
        &cloud_id,
        403,
        "forbidden",
    );
    assert_eq!(gateway_definitions(&gateway), vec![(cloud_id.clone(), 2)]);

    // Another publisher's revision 3 lands first: the conflict carries it.
    gateway.lose_next_publication();
    let conflict = refused(
        &cloud_publish_args(&tree, Some(&bindings), &["--to", &cloud_id, "--json"]),
        &cloud_id,
        409,
        "definition-revision-conflict",
    );
    assert_eq!(conflict["cloud"]["workflow"]["currentRevision"], 3);
    assert_eq!(gateway_definitions(&gateway), vec![(cloud_id.clone(), 3)]);

    // A name no definition of the project has is not found, and nothing is uploaded.
    let home = Home::new();
    let (output, requests) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--to", "nosuch", "--json"]),
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let missing = report(&output);
    assert_eq!(missing["outcome"], "refused", "{missing}");
    assert_eq!(missing["diagnostics"][0]["code"], "definition_not_found");
    assert_eq!(
        routes(&requests),
        vec![format!("GET {}", project_definitions())]
    );
    assert_home_untouched(&home);
    assert_eq!(gateway_definitions(&gateway), vec![(cloud_id, 3)]);
}

// A publication to a Cloud definition that is no longer found, as after a delete, is refused
// without a create and says to publish again with `--new` or with `--to` naming another; a
// publication that names none then creates another definition.
#[test]
fn publish_to_a_deleted_definition_is_refused_and_says_how_to_publish_again() {
    let home = Home::new();
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let gateway = FakeGateway::new();

    let (output, _) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let created = report(&output);
    let deleted = cloud_definition(&created);
    for leaf in [vec!["archive"], vec!["delete", "--yes"]] {
        let mut args = vec![
            "workflow",
            "definition",
            leaf[0],
            &deleted,
            "--org",
            CLOUD_ORGANIZATION,
            "--project",
            CLOUD_PROJECT,
            "--allow-insecure-http",
        ];
        args.extend_from_slice(&leaf[1..]);
        let (output, _) = gateway.run(&home, &args);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
    }

    let (output, requests) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--to", &deleted, "--json"]),
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let failed = report(&output);
    assert_eq!(failed["outcome"], "cloud_failed", "{failed}");
    assert_eq!(failed["cloud"]["failure"], "refused");
    assert_eq!(failed["cloud"]["status"], 404);
    assert_eq!(failed["cloud"]["problem"], "not-found");
    assert_eq!(failed["cloud"]["target"], deleted.as_str());
    assert_no_definition_created(&requests);

    // The indented command lines of the human report's remedy.
    let (output, requests) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--to", &deleted]),
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_no_definition_created(&requests);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let commands = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("  useful workflow definition publish "))
        .collect::<Vec<_>>();
    assert!(
        commands.iter().any(|line| line.ends_with("--new")),
        "{output:?}"
    );
    assert!(
        commands.iter().any(|line| line.contains("--to")),
        "{output:?}"
    );
    assert!(
        !commands.iter().any(|line| line.contains(deleted.as_str())),
        "{output:?}"
    );

    let (output, _) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let republished = report(&output);
    assert_eq!(republished["cloud"]["created"], true, "{republished}");
    assert_ne!(cloud_definition(&republished), deleted);
    assert_home_untouched(&home);
}

#[test]
fn a_published_definition_runs_in_both_cloud_places_and_the_runs_are_discoverable() {
    let gateway = FakeGateway::new();
    let home = Home::new();
    let tree = Tree::engineering();
    let published =
        publish_from_a_fresh_home(&gateway, &tree, &tree.engineering_bindings(), &["--json"]);
    let definition = cloud_definition(&published);
    let invoke = |args: &[&str]| {
        let mut all = vec!["workflow", "run"];
        all.extend_from_slice(args);
        all.extend([
            "--org",
            CLOUD_ORGANIZATION,
            "--allow-insecure-http",
            "--json",
        ]);
        let (output, _) = gateway.run(&home, &all);
        assert!(output.status.success(), "{args:?}: {output:?}");
        report(&output)
    };
    let personal = invoke(&[
        "create",
        &definition,
        "--on",
        "personal",
        "--project",
        CLOUD_PROJECT,
    ]);
    let project = invoke(&[
        "create",
        &definition,
        "--on",
        "project",
        "--project",
        CLOUD_PROJECT,
    ]);
    let page = invoke(&["list", "--all"]);
    let rows = page["runs"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for (receipt, place) in [(&personal, "personal"), (&project, "project")] {
        let row = rows
            .iter()
            .find(|row| row["id"] == receipt["runId"])
            .unwrap();
        assert_eq!(row["on"], place);
        let shown = invoke(&["show", row["id"].as_str().unwrap()]);
        assert_eq!(shown["run"]["id"], receipt["runId"]);
    }
}

/// The Cloud definition id `report` reached.
fn cloud_definition(report: &Value) -> String {
    text(&report["cloud"]["definition"], "cloud definition id").to_owned()
}

/// Publishes `tree` with `bindings` and `extra` from a fresh home, asserting it succeeds; the
/// report.
fn publish_from_a_fresh_home(
    gateway: &FakeGateway,
    tree: &Tree,
    bindings: &str,
    extra: &[&str],
) -> Value {
    let (output, _) = gateway.run(
        &Home::new(),
        &cloud_publish_args(tree, Some(bindings), extra),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    report(&output)
}

// A first publication whose list shows no definition of the tree's name, because another owner's
// first publication of the same tree, bindings and bits lands in between, reaches that owner's
// definition; the next one finds it by its name.
#[test]
fn publish_on_project_reuses_the_identical_definition_a_concurrent_publication_created() {
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let gateway = FakeGateway::new();
    let organization = format!("/api/v1/organizations/{CLOUD_ORGANIZATION}");
    let definitions = project_definitions();

    let created = publish_from_a_fresh_home(&gateway, &tree, &bindings, &["--json"]);
    let cloud_id = cloud_definition(&created);
    assert_eq!(created["cloud"]["created"], true, "{created}");
    assert_eq!(created["cloud"]["reused"], false);
    assert_eq!(created["cloud"]["treeReused"], false);

    gateway.answer_next_with(Fault::ListNoDefinition);
    let home = Home::new();
    let (output, requests) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_no_content(&output);
    super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
    let reused = report(&output);
    assert_eq!(reused["outcome"], "published", "{reused}");
    assert_eq!(reused["cloud"]["created"], false);
    assert_eq!(reused["cloud"]["reused"], true);
    assert_eq!(reused["cloud"]["definition"], cloud_id.as_str());
    assert_eq!(reused["cloud"]["revision"], 1);
    assert_eq!(reused["cloud"]["treeReused"], true);
    assert!(reused["cloud"].get("target").is_none(), "{reused}");
    assert_eq!(
        routes(&requests),
        vec![
            format!("GET {definitions}"),
            format!("POST {organization}/workflow-trees"),
            format!("POST {definitions}"),
        ]
    );
    assert_eq!(requests[2].json()["reuseIdentical"], true);
    assert_eq!(gateway_definitions(&gateway), vec![(cloud_id.clone(), 1)]);
    assert_home_untouched(&home);

    // The next publication finds that definition by its name.
    let (output, requests) = gateway.run(&home, &cloud_publish_args(&tree, Some(&bindings), &[]));
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        routes(&requests),
        vec![
            format!("GET {definitions}"),
            format!("POST {organization}/workflow-trees"),
            format!("GET {definitions}/{cloud_id}"),
            format!("POST {definitions}/{cloud_id}/revisions"),
        ]
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout
            .lines()
            .next()
            .is_some_and(|line| line.contains(&cloud_id) && line.contains("revision 2")),
        "{stdout}"
    );
    assert_contains_all(
        &stdout,
        &[
            format!("cloud definition: {cloud_id}\n").as_str(),
            "cloud created: no\n",
            "cloud definition reused: no\n",
            "cloud revision: 2\n",
            "cloud tree reused: yes\n",
        ],
    );
    assert_eq!(gateway_definitions(&gateway), vec![(cloud_id, 2)]);
}

// A create that shares only the tree reuses the tree, never a definition.
#[test]
fn publish_on_project_with_other_binding_values_reuses_the_tree_and_creates_a_definition() {
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let other_bindings = tree.bindings_file(
        "eng.json",
        &json!({
            "connection": "local",
            "linearTeam": "ENG",
            "repository": "useful-machinery/platform",
        }),
    );
    let gateway = FakeGateway::new();
    let cloud_id = cloud_definition(&publish_from_a_fresh_home(
        &gateway,
        &tree,
        &bindings,
        &["--json"],
    ));

    gateway.answer_next_with(Fault::ListNoDefinition);
    let other = publish_from_a_fresh_home(&gateway, &tree, &other_bindings, &["--json"]);
    assert_eq!(other["cloud"]["created"], true, "{other}");
    assert_eq!(other["cloud"]["reused"], false);
    assert_eq!(other["cloud"]["treeReused"], true);
    let other_id = cloud_definition(&other);
    assert_ne!(other_id, cloud_id);
    assert_eq!(
        gateway_definitions(&gateway),
        vec![(cloud_id, 1), (other_id, 1)]
    );
}

// `--new` reads no list and never asks for reuse, so it creates another definition
// although the project holds an identical one of the name.
#[test]
fn publish_on_project_new_creates_another_definition_although_an_identical_one_exists() {
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let gateway = FakeGateway::new();
    let organization = format!("/api/v1/organizations/{CLOUD_ORGANIZATION}");
    let definitions = project_definitions();
    let cloud_id = cloud_definition(&publish_from_a_fresh_home(
        &gateway,
        &tree,
        &bindings,
        &["--json"],
    ));

    let home = Home::new();
    let (output, requests) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--new", "--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let created = report(&output);
    assert_eq!(created["cloud"]["created"], true, "{created}");
    assert_eq!(created["cloud"]["reused"], false);
    assert_eq!(created["cloud"]["treeReused"], true);
    let other = cloud_definition(&created);
    assert_ne!(other, cloud_id);
    assert_eq!(
        routes(&requests),
        vec![
            format!("POST {organization}/workflow-trees"),
            format!("POST {definitions}"),
        ]
    );
    assert!(
        requests[1].json().get("reuseIdentical").is_none(),
        "{}",
        requests[1].json()
    );
    assert_home_untouched(&home);
    assert_eq!(
        gateway_definitions(&gateway),
        vec![(cloud_id, 1), (other, 1)]
    );
}

// With several identical definitions held, a create that asks for reuse is refused and names
// them all and both ways out.
#[test]
fn publish_on_project_refuses_an_ambiguous_reuse() {
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let gateway = FakeGateway::new();
    let held = [&["--json"][..], &["--new", "--json"]]
        .into_iter()
        .map(|extra| {
            let created = publish_from_a_fresh_home(&gateway, &tree, &bindings, extra);
            (cloud_definition(&created), 1)
        })
        .collect::<Vec<_>>();
    assert_eq!(gateway_definitions(&gateway), held);
    let ids = held.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>();

    gateway.answer_next_with(Fault::ListNoDefinition);
    let home = Home::new();
    let (output, _) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let refused = report(&output);
    assert_eq!(refused["outcome"], "cloud_failed", "{refused}");
    assert_eq!(refused["cloud"]["failure"], "refused");
    assert_eq!(refused["cloud"]["status"], 409);
    assert_eq!(refused["cloud"]["problem"], "definition-reuse-ambiguous");
    assert_eq!(refused["cloud"]["workflow"]["definitionIds"], json!(ids));
    for member in ["target", "definition", "created", "reused", "treeReused"] {
        assert!(
            refused["cloud"].get(member).is_none(),
            "{member}: {refused}"
        );
    }
    assert_home_untouched(&home);
    assert_eq!(gateway_definitions(&gateway), held);

    // The human report names every matching definition and both ways out.
    gateway.answer_next_with(Fault::ListNoDefinition);
    let (output, _) = gateway.run(&home, &cloud_publish_args(&tree, Some(&bindings), &[]));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    for named in ids.iter().chain(&["--on project --to", "--new"]) {
        assert!(stderr.contains(named), "{named}: {stderr}");
    }
    assert_eq!(gateway_definitions(&gateway), held);
}

// Each `binding-unresolved` refusal Cloud answers a publication with names the binding, and one
// that would close a loop of definitions reports the loop in start order; every refusal records
// nothing locally and leaves Cloud unchanged.
#[test]
fn publish_cloud_prints_the_loop_a_publication_would_close() {
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let cloud_id = format!("{CLOUD_ID_STEM}c");
    let second = format!("{CLOUD_ID_STEM}d");
    let third = format!("{CLOUD_ID_STEM}e");
    let (c, d, e) = (cloud_id.as_str(), second.as_str(), third.as_str());
    let rows: [(&str, Option<Vec<&str>>); 4] = [
        // A binding Cloud does not resolve, as a definition of another project is: no loop.
        ("unresolved", None),
        ("bound to itself", Some(vec![c, c])),
        ("loop of two", Some(vec![c, d, c])),
        ("loop of three", Some(vec![c, d, e, c])),
    ];

    for (row, loop_ids) in rows {
        let gateway = FakeGateway::new();
        gateway.define(&cloud_id, 2);
        let workflow = match &loop_ids {
            Some(ids) => json!({"bindingKey": "verify", "loop": ids}),
            None => json!({"bindingKey": "verify"}),
        };
        let refuse_next = || {
            gateway.refuse_next_keyed_with(
                "422 Unprocessable Entity",
                422,
                "binding-unresolved",
                workflow.clone(),
            );
        };

        refuse_next();
        let home = Home::new();
        let (output, _) = gateway.run(
            &home,
            &cloud_publish_args(&tree, Some(&bindings), &["--to", &cloud_id, "--json"]),
        );
        assert_eq!(output.status.code(), Some(1), "{row}: {output:?}");
        let refused = report(&output);
        assert_eq!(refused["outcome"], "cloud_failed", "{row}: {refused}");
        assert_eq!(refused["cloud"]["failure"], "refused", "{row}");
        assert_eq!(refused["cloud"]["status"], 422, "{row}");
        assert_eq!(refused["cloud"]["problem"], "binding-unresolved", "{row}");
        assert_eq!(
            refused["cloud"]["workflow"]["bindingKey"], "verify",
            "{row}"
        );
        match &loop_ids {
            Some(ids) => assert_eq!(refused["cloud"]["workflow"]["loop"], json!(ids), "{row}"),
            None => assert!(
                refused["cloud"]["workflow"].get("loop").is_none(),
                "{row}: {refused}"
            ),
        }
        assert_home_untouched(&home);
        assert_eq!(
            gateway_definitions(&gateway),
            vec![(cloud_id.clone(), 2)],
            "{row}"
        );

        refuse_next();
        let (output, _) = gateway.run(
            &Home::new(),
            &cloud_publish_args(&tree, Some(&bindings), &["--to", &cloud_id]),
        );
        assert_eq!(output.status.code(), Some(1), "{row}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let lines = stderr.lines().collect::<Vec<_>>();
        let binding = lines
            .iter()
            .position(|line| line.starts_with("binding:") && line.contains("verify"))
            .unwrap_or_else(|| panic!("{row}: no binding line: {stderr}"));
        match &loop_ids {
            Some(ids) => {
                let named = lines
                    .get(binding + 1)
                    .and_then(|line| line.strip_prefix("loop:"))
                    .unwrap_or_else(|| panic!("{row}: no loop line after the binding: {stderr}"));
                // The line names the ids in start order.
                let mut rest = named;
                for id in ids {
                    let at = rest
                        .find(id)
                        .unwrap_or_else(|| panic!("{row}: {id} not in order: {stderr}"));
                    rest = &rest[at + id.len()..];
                }
            }
            None => assert!(
                !lines.iter().any(|line| line.starts_with("loop:")),
                "{row}: {stderr}"
            ),
        }
        assert_eq!(
            gateway_definitions(&gateway),
            vec![(cloud_id.clone(), 2)],
            "{row}"
        );
    }
}

// A reuse whose reply is lost is sent once more under the same key and reported as the
// reuse Cloud recorded.
#[test]
fn publish_on_project_resends_a_reuse_whose_reply_is_lost_and_reports_the_reuse() {
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let gateway = FakeGateway::new();
    let definitions = project_definitions();
    let cloud_id = cloud_definition(&publish_from_a_fresh_home(
        &gateway,
        &tree,
        &bindings,
        &["--json"],
    ));

    gateway.answer_next_with(Fault::ListNoDefinition);
    gateway.drop_next_publication_reply();
    let home = Home::new();
    let (output, requests) = gateway.run(
        &home,
        &cloud_publish_args(&tree, Some(&bindings), &["--json"]),
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let reused = report(&output);
    assert_eq!(reused["cloud"]["created"], false, "{reused}");
    assert_eq!(reused["cloud"]["reused"], true);
    assert_eq!(reused["cloud"]["definition"], cloud_id.as_str());
    assert_eq!(reused["cloud"]["revision"], 1);
    let creates = requests
        .iter()
        .filter(|request| request.route() == format!("POST {definitions}"))
        .collect::<Vec<_>>();
    assert_eq!(creates.len(), 2, "{:?}", routes(&requests));
    let key = creates[0].header("idempotency-key").expect("create key");
    assert_eq!(creates[1].header("idempotency-key"), Some(key));
    assert_eq!(creates[0].body, creates[1].body);
    assert_eq!(creates[0].json()["reuseIdentical"], true);
    assert_home_untouched(&home);
    assert_eq!(gateway_definitions(&gateway), vec![(cloud_id, 1)]);
}

// With no `--on` a publish stays under the home. The form the runner runs writes the record
// and the revision, prints today's document and sends nothing, and `--to NAME` publishes to
// the home's one record of that name, never looked for in the project.
#[test]
fn publish_with_no_on_publishes_under_the_home_and_sends_nothing() {
    let home = Home::new();
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let gateway = FakeGateway::new();
    gateway.define_named(&format!("{CLOUD_ID_STEM}c"), 1, "engineering");
    gateway.define_named(&format!("{CLOUD_ID_STEM}d"), 1, "alpha");
    let keys = |value: &Value| {
        value
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
    };
    let names = |names: &[&str]| {
        names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<BTreeSet<_>>()
    };

    let (output, requests) = gateway.run(
        &home,
        &[
            "workflow",
            "definition",
            "publish",
            tree.path(),
            "--bindings",
            &bindings,
            "--json",
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(requests.is_empty(), "{:?}", routes(&requests));
    let published = report(&output);
    assert_eq!(
        keys(&published),
        names(&[
            "command",
            "definition",
            "outcome",
            "revision",
            "schemaVersion"
        ])
    );
    assert_eq!(
        keys(&published["definition"]),
        names(&["created", "current", "enabled", "id", "name", "path"])
    );
    assert_eq!(
        keys(&published["revision"]),
        names(&["bindings", "by", "n", "publishedAt", "tree"])
    );
    let id = text(&published["definition"]["id"], "definition id").to_owned();
    let definition = home.definition_directory(&id);
    assert!(definition.join("definition.json").is_file());
    assert!(definition.join("revisions/1/bindings.json").is_file());

    let local = |extra: &[&str]| {
        let args = [
            &[
                "workflow",
                "definition",
                "publish",
                tree.path(),
                "--allow-insecure-http",
                "--json",
            ][..],
            extra,
        ]
        .concat();
        gateway.run(&home, &args)
    };
    let (output, requests) = local(&["--to", "engineering"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(requests.is_empty(), "{:?}", routes(&requests));
    let targeted = report(&output);
    assert_eq!(targeted["definition"]["id"], id.as_str());
    assert_eq!(targeted["revision"]["n"], 2);

    // An id the home holds keeps the publication under the home, so the project `--project`
    // names is refused rather than ignored, and no revision is written.
    let (output, requests) = local(&["--to", &id, "--project", CLOUD_PROJECT]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(requests.is_empty(), "{:?}", routes(&requests));
    assert!(!home.definition_directory(&id).join("revisions/3").exists());

    let (output, requests) = local(&["--to", "alpha"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(requests.is_empty(), "{:?}", routes(&requests));
    assert_eq!(
        report(&output)["diagnostics"][0]["code"],
        "definition_not_found"
    );
    assert_eq!(home.workflow_entries(), vec![id]);
}

// No command writes `cloudId`. A new record holds null, and a record an earlier release wrote
// with one is published to and shown with the value unchanged.
#[test]
fn a_record_keeps_the_cloud_id_an_earlier_release_wrote() {
    let home = Home::new();
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let first = home.publish(&tree, &["--bindings", &bindings]);
    let id = text(&first["definition"]["id"], "definition id").to_owned();
    let path = home.definition_directory(&id).join("definition.json");
    let mut record = read_json(&path);
    assert_eq!(record["cloudId"], Value::Null, "{record}");

    record["cloudId"] = json!(CLOUD_TARGET);
    fs::write(
        &path,
        serde_json::to_vec(&record).expect("record should encode"),
    )
    .expect("record should be written");
    let second = home.publish(&tree, &[]);
    assert_eq!(second["definition"]["id"], id.as_str());
    assert_eq!(second["revision"]["n"], 2);
    let record = read_json(&path);
    assert_eq!(record["cloudId"], CLOUD_TARGET, "{record}");
    assert!(
        schema("workflow-definition-v1.schema.json").is_valid(&record),
        "{record}"
    );
    assert_eq!(
        home.json(&["show", &id])["definition"]["cloudId"],
        CLOUD_TARGET
    );
}

const CLOUD_PRINCIPAL: &str = "prn_01k0z6r1w8f4jy2m7q9v3x5xyz";
const CLOUD_TEAM_ID: &str = "8f2c4c9e-team-automation";

/// The tree digest the fake records for revision `number`.
fn gateway_tree_digest(number: i64) -> String {
    format!("sha256:{number:0>64}")
}

/// Revision `number` of `id`, with one Linear team binding and its resolution and, when the
/// definition's revisions hold them, `gateway_integrations`.
fn gateway_revision(id: &str, number: i64, integrations: bool) -> Value {
    let mut revision = json!({
        "definitionId": id,
        "number": number,
        "treeDigest": gateway_tree_digest(number),
        "bindings": {"linearTeam": {"kind": "linear.team", "value": "AUTO"}},
        "resolution": {"linearTeam": {
            "kind": "linear.team", "value": "AUTO", "id": CLOUD_TEAM_ID, "name": "Automation",
        }},
        "publishedAt": CLOUD_TIME,
        "publishedBy": CLOUD_PUBLISHER,
    });
    if integrations {
        let (bindings, resolution) = gateway_integrations();
        revision["integrationBindings"] = bindings;
        revision["integrationResolution"] = resolution;
    }
    revision
}

/// The Linear connection a revision's `linear` integration resolved through.
const CLOUD_LINEAR_ACCOUNT: &str = "lcn_01k0z6r1w8f4jy2m7q9v3x5abc";
/// The installation a revision's `github` integration resolved through.
const CLOUD_GITHUB_ACCOUNT: &str = "ghi_01k0z6r1w8f4jy2m7q9v3x5abc";
/// The team a revision's `linear.team` resolved to.
const CLOUD_INTEGRATION_TEAM_ID: &str = "3a71d0b2-team-engineering";

/// A revision's `integrationBindings` and `integrationResolution`: `linear` with `team` and
/// `ownedState`, `github` with `repository`, each with its account.
fn gateway_integrations() -> (Value, Value) {
    (
        json!({
            "linear": {
                "team": {"kind": "team", "value": "ENG"},
                "ownedState": {"kind": "state", "value": "Engineering"},
            },
            "github": {"repository": {"kind": "repository", "value": "useful-machinery/platform"}},
        }),
        json!({
            "linear": {
                "account": {"id": CLOUD_LINEAR_ACCOUNT, "name": "Useful"},
                "bindings": {
                    "team": {
                        "kind": "team", "value": "ENG",
                        "id": CLOUD_INTEGRATION_TEAM_ID, "name": "Engineering",
                    },
                    "ownedState": {
                        "kind": "state", "value": "Engineering",
                        "id": "5c09e7f4-state-engineering", "name": "Engineering",
                    },
                },
            },
            "github": {
                "account": {"id": CLOUD_GITHUB_ACCOUNT},
                "bindings": {
                    "repository": {"kind": "repository", "value": "useful-machinery/platform"},
                },
            },
        }),
    )
}

/// Whether `request`'s query names vocabulary 2, as a revision read may.
fn asks_for_vocabulary_2(request: &GatewayRequest) -> bool {
    request
        .path
        .split_once('?')
        .is_some_and(|(_, query)| query.split('&').any(|pair| pair == "vocabulary=2"))
}

/// The evaluation vocabulary `request`'s query names, 1 when it names none.
fn evaluation_vocabulary(request: &GatewayRequest) -> u32 {
    query_number(request, "vocabulary").unwrap_or(1)
}

/// The number `request`'s query names for `key`, `None` when it names none.
fn query_number(request: &GatewayRequest, key: &str) -> Option<u32> {
    let (_, query) = request.path.split_once('?')?;
    query.split('&').find_map(|pair| {
        let (name, number) = pair.split_once('=')?;
        (name == key).then(|| number.parse().expect("a number"))
    })
}

const CLOUD_BOUND_DEFINITION: &str = "def_01k0z6r1w8f4jy2m7q9v3x5abe";
const CLOUD_BOUND_DEFINITION_NAME: &str = "verify-change";

/// The `verify` binding of kind `definition` and its resolution, which Cloud shows only under
/// binding vocabulary 2.
fn gateway_definition_binding() -> (Value, Value) {
    (
        json!({"kind": "definition", "value": CLOUD_BOUND_DEFINITION}),
        json!({
            "kind": "definition", "value": CLOUD_BOUND_DEFINITION,
            "id": CLOUD_BOUND_DEFINITION, "name": CLOUD_BOUND_DEFINITION_NAME,
        }),
    )
}

/// The answer to a delete of definition `id` under `key`, as Cloud answers it: 204 with the key
/// again for a key already applied, `not-found` for an id the fake does not hold and 409
/// `definition-not-archived` for an active one; an archived one is removed and the key recorded.
fn respond_delete(state: &mut GatewayState, id: &str, key: &str) -> Vec<u8> {
    let deleted = |headers: &[(&str, &str)]| {
        super::http_response_with_headers("204 No Content", None, headers, b"")
    };
    if state.deletions.contains(key) {
        return deleted(&[("Idempotency-Key", key)]);
    }
    let Some(definition) = state.definitions.get(id) else {
        return gateway_not_found();
    };
    if !definition.archived {
        return super::problem_http_response(
            "409 Conflict",
            json!({
                "type": format!("{PROBLEMS}definition-not-archived"),
                "title": "Definition not archived",
                "status": 409,
            }),
        );
    }
    state.definitions.remove(id);
    state.deletions.insert(key.to_owned());
    if std::mem::take(&mut state.drop_next_publication_reply) {
        return Vec::new();
    }
    if state.fault(Fault::ChangeWithoutKey) {
        return deleted(&[]);
    }
    deleted(&[("Idempotency-Key", key)])
}

/// The most definitions one page of the fake Gateway's list holds.
const DEFINITION_PAGE: usize = 2;

/// The definition list in pages of `DEFINITION_PAGE` in id order, the revision reads and the
/// setting changes; an enable without an execution principal is refused 409
/// `definition-not-startable`. As Cloud does, a revision read or listing that asks for binding
/// vocabulary 2 is answered with the `verify` binding.
fn respond_settings(
    state: &mut GatewayState,
    request: &GatewayRequest,
    definitions: &str,
    keyed: impl Fn(&str, Value) -> Vec<u8>,
) -> Option<Vec<u8>> {
    let route = request.route();
    if route == format!("GET {definitions}") {
        if state.fault(Fault::ListNoDefinition) {
            return Some(super::json_http_response(
                "200 OK",
                json!({"items": [], "nextCursor": null}),
            ));
        }
        let start = request
            .path
            .split_once('?')
            .and_then(|(_, query)| {
                query
                    .split('&')
                    .find_map(|pair| pair.strip_prefix("cursor="))
            })
            .map_or(0, |cursor| {
                cursor.parse().expect("cursor should be an index")
            });
        let end = (start + DEFINITION_PAGE).min(state.definitions.len());
        let items = state
            .definitions
            .iter()
            .skip(start)
            .take(end - start)
            .map(|(id, definition)| gateway_definition(id, definition))
            .collect::<Vec<_>>();
        let next = (end < state.definitions.len()).then(|| end.to_string());
        return Some(super::json_http_response(
            "200 OK",
            json!({"items": items, "nextCursor": next}),
        ));
    }
    let (method, rest) = route.split_once(' ')?;
    let (id, action) = rest
        .strip_prefix(definitions)?
        .strip_prefix('/')?
        .split_once('/')?;
    let definition = state.definitions.get_mut(id)?;
    let latest = asks_for_vocabulary_2(request);
    let integrations = definition.integrations;
    let revision = |number| {
        let mut revision = gateway_revision(id, number, integrations);
        if latest {
            let (binding, resolved) = gateway_definition_binding();
            revision["bindings"]["verify"] = binding;
            revision["resolution"]["verify"] = resolved;
        }
        revision
    };
    match (method, action) {
        ("GET", "revisions") => {
            let items = (1..=definition.current)
                .rev()
                .map(revision)
                .collect::<Vec<_>>();
            return Some(super::json_http_response("200 OK", json!({"items": items})));
        }
        ("GET", action) => {
            let number = action.strip_prefix("revisions/")?.parse().ok()?;
            return Some(super::json_http_response("200 OK", revision(number)));
        }
        ("POST", "enable") if definition.principal.is_none() => {
            return Some(super::problem_http_response(
                "409 Conflict",
                json!({
                    "type": format!("{PROBLEMS}definition-not-startable"),
                    "title": "Definition not startable",
                    "status": 409,
                    "workflow": {"startCheck": "execution-principal"},
                }),
            ));
        }
        ("POST", "enable") => definition.automatic_starts = true,
        ("POST", "disable") => definition.automatic_starts = false,
        ("POST", "archive") => {
            definition.archived = true;
            definition.automatic_starts = false;
        }
        ("POST", "unarchive") => definition.archived = false,
        ("PUT", "execution-principal") => {
            definition.principal =
                Some(text(&request.json()["principalId"], "principal id").to_owned());
        }
        _ => return None,
    }
    let changed = gateway_definition(id, definition);
    if state.fault(Fault::ChangeWithoutKey) {
        return Some(super::json_http_response("200 OK", changed));
    }
    Some(keyed("200 OK", changed))
}

fn workflow_definitions_route() -> String {
    format!(
        "GET /api/v1/organizations/{CLOUD_ORGANIZATION}/projects/{CLOUD_PROJECT}/workflow-definitions"
    )
}

/// Each listed definition's `on` and `id`.
fn placed(listed: &Value) -> Vec<(String, String)> {
    listed["definitions"]
        .as_array()
        .expect("definitions should be a list")
        .iter()
        .map(|definition| {
            (
                text(&definition["on"], "on").to_owned(),
                text(&definition["id"], "definition id").to_owned(),
            )
        })
        .collect()
}

// `list` prints the home's definitions and then every page of the project's in effect, each
// saying where it lives; `--on local` asks Cloud nothing, and `--on project` fails as a
// Cloud command fails.
#[test]
fn list_reads_the_home_and_then_every_page_of_the_project_in_effect() {
    let home = Home::new();
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let local = home.publish(&tree, &["--bindings", &bindings]);
    let local = text(&local["definition"]["id"], "definition id").to_owned();
    let gateway = FakeGateway::new();
    let cloud = ["c", "d", "e"].map(|last| format!("{CLOUD_ID_STEM}{last}"));
    for id in &cloud {
        gateway.define_named(id, 1, "alpha");
    }
    let list = |args: &[&str]| {
        let mut all = vec!["workflow", "definition", "list"];
        all.extend_from_slice(args);
        all.extend_from_slice(&["--project", CLOUD_PROJECT, "--allow-insecure-http"]);
        let (output, requests) = gateway.run(&home, &all);
        super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
        (output, requests)
    };

    let (output, requests) = list(&["--org", CLOUD_ORGANIZATION, "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let listed = report(&output);
    assert_eq!(listed["command"], "useful workflow definition list");
    assert_eq!(
        listed["cloud"],
        json!({
            "asked": true,
            "organizationRef": CLOUD_ORGANIZATION,
            "projectId": CLOUD_PROJECT,
        })
    );
    let mut expected = vec![("local".to_owned(), local.clone())];
    expected.extend(cloud.iter().map(|id| ("project".to_owned(), id.clone())));
    assert_eq!(placed(&listed), expected);
    assert_eq!(listed["definitions"][0]["enabled"], true);
    assert_eq!(listed["definitions"][1]["automaticStarts"], false);
    assert_eq!(
        routes(&requests),
        vec![workflow_definitions_route(), workflow_definitions_route()]
    );
    assert!(
        requests[1].path.contains("cursor=2"),
        "{}",
        requests[1].path
    );

    let (output, _) = list(&["--org", CLOUD_ORGANIZATION]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines = stdout.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 4, "{stdout}");
    assert!(
        lines[0].contains(&local) && lines[0].contains("local"),
        "{stdout}"
    );
    for (line, id) in lines[1..].iter().zip(&cloud) {
        assert!(line.contains(id) && line.contains("project"), "{stdout}");
    }

    // A session and a project in effect, and still nothing is asked.
    let (output, requests) = list(&["--on", "local", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(requests.is_empty(), "{:?}", routes(&requests));
    let listed = report(&output);
    assert_eq!(
        listed["cloud"],
        json!({"asked": false, "reason": "local_only"})
    );
    assert_eq!(placed(&listed), vec![("local".to_owned(), local)]);

    // With nobody signed in, `--on project` ends as a Cloud command does, asking nothing.
    let output = home.run(&["list", "--on", "project", "--json"]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
}

// `show` finds a definition by its ID or its name under the home first, without a request, and
// then in the project in effect, among every page of its definitions.
#[test]
fn show_finds_a_definition_by_id_or_name_under_the_home_and_then_in_the_project() {
    let home = Home::new();
    let tree = Tree::engineering();
    let bindings = tree.engineering_bindings();
    let local = home.publish(&tree, &["--bindings", &bindings]);
    let local = text(&local["definition"]["id"], "definition id").to_owned();
    let gateway = FakeGateway::new();
    let [alpha, twin, other_twin, engineering] =
        ["c", "d", "e", "f"].map(|last| format!("{CLOUD_ID_STEM}{last}"));
    gateway.define_named(&alpha, 2, "alpha");
    gateway.define_named(&twin, 1, "twin");
    gateway.define_named(&other_twin, 1, "twin");
    gateway.define_named(&engineering, 1, "engineering");
    let definitions = workflow_definitions_route();
    let show = |args: &[&str]| {
        let mut all = vec!["workflow", "definition", "show"];
        all.extend_from_slice(args);
        all.extend_from_slice(&[
            "--org",
            CLOUD_ORGANIZATION,
            "--project",
            CLOUD_PROJECT,
            "--allow-insecure-http",
        ]);
        let (output, requests) = gateway.run(&home, &all);
        super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
        (output, requests)
    };

    // The home's definition wins over the project's of the same name.
    for named in ["engineering", local.as_str()] {
        let (output, requests) = show(&[named, "--json"]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(requests.is_empty(), "{:?}", routes(&requests));
        let shown = report(&output);
        assert_eq!(shown["on"], "local", "{shown}");
        assert_eq!(shown["definition"]["id"], local.as_str());
    }

    let (output, requests) = show(&["alpha", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let shown = report(&output);
    assert_eq!(shown["on"], "project", "{shown}");
    assert_eq!(shown["definition"]["id"], alpha.as_str());
    assert_eq!(shown["revision"]["number"], 2);
    assert_eq!(
        routes(&requests),
        vec![
            definitions.clone(),
            definitions.clone(),
            format!("{definitions}/{alpha}/revisions/2"),
            format!("{definitions}/{alpha}/revisions"),
        ]
    );

    let (output, requests) = show(&["twin", "--json"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_contains_all(&stderr, &[&twin, &other_twin]);
    assert_eq!(
        routes(&requests),
        vec![definitions.clone(), definitions.clone()]
    );

    let (output, requests) = show(&[&alpha, "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(report(&output)["on"], "project");
    assert_eq!(
        routes(&requests),
        vec![
            format!("{definitions}/{alpha}"),
            format!("{definitions}/{alpha}/revisions/2"),
            format!("{definitions}/{alpha}/revisions"),
        ]
    );

    // An ID neither place holds: the refusal names the home and the project.
    let absent = format!("{CLOUD_ID_STEM}y");
    let (output, requests) = show(&[&absent, "--json"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(routes(&requests), vec![format!("{definitions}/{absent}")]);
    let refused = report(&output);
    assert_eq!(refused["command"], "useful workflow definition show");
    assert_eq!(refused["outcome"], "refused", "{refused}");
    let diagnostic = &refused["diagnostics"][0];
    assert_eq!(diagnostic["code"], "definition_not_found");
    assert_eq!(diagnostic["definition"], absent.as_str());
    assert_eq!(diagnostic["home"], home.path());
    assert_eq!(
        diagnostic["cloud"],
        json!({
            "asked": true,
            "organizationRef": CLOUD_ORGANIZATION,
            "projectId": CLOUD_PROJECT,
        })
    );
    let (output, _) = show(&[&absent]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_contains_all(
        &String::from_utf8_lossy(&output.stdout),
        &["definition_not_found", &absent, home.path(), CLOUD_PROJECT],
    );

    // With nobody signed in only the home is looked in, and the refusal says why.
    let refused = home.refused_command(
        &["show", "alpha"],
        "useful workflow definition show",
        "definition_not_found",
    );
    assert_eq!(refused["home"], home.path());
    assert_eq!(
        refused["cloud"],
        json!({"asked": false, "reason": "signed_out"})
    );
}

#[test]
fn definition_leaves_list_show_and_change_cloud_definitions() {
    let home = Home::new();
    let gateway = FakeGateway::new();
    let first = format!("{CLOUD_ID_STEM}c");
    let second = format!("{CLOUD_ID_STEM}d");
    gateway.define(&second, 1);
    gateway.define(&first, 2);
    let definitions = format!(
        "/api/v1/organizations/{CLOUD_ORGANIZATION}/projects/{CLOUD_PROJECT}/workflow-definitions"
    );

    // Every leaf acts in the project in effect.
    let definition = |args: &[&str]| {
        let mut all = vec!["workflow", "definition"];
        all.extend_from_slice(args);
        all.extend_from_slice(&[
            "--org",
            CLOUD_ORGANIZATION,
            "--project",
            CLOUD_PROJECT,
            "--allow-insecure-http",
        ]);
        let (output, requests) = gateway.run(&home, &all);
        super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
        for request in &requests {
            assert_eq!(
                request.header("authorization"),
                Some(format!("Bearer {CLOUD_TOKEN}").as_str())
            );
        }
        (output, requests)
    };
    let target = |leaf: &'static str, json: bool| {
        let mut args = vec![leaf, first.as_str()];
        if json {
            args.push("--json");
        }
        definition(&args)
    };
    let (output, requests) = definition(&["list", "--on", "project", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let listed = report(&output);
    assert_eq!(
        listed["cloud"],
        json!({
            "asked": true,
            "organizationRef": CLOUD_ORGANIZATION,
            "projectId": CLOUD_PROJECT,
        })
    );
    let items = listed["definitions"].as_array().expect("definitions");
    assert_eq!(
        items
            .iter()
            .map(|item| (
                text(&item["on"], "on"),
                text(&item["id"], "id"),
                item["currentRevision"].as_i64()
            ))
            .collect::<Vec<_>>(),
        vec![
            ("project", first.as_str(), Some(2)),
            ("project", second.as_str(), Some(1))
        ]
    );
    assert_eq!(routes(&requests), vec![format!("GET {definitions}")]);

    let (output, requests) = definition(&["show", &first]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains_all(
        &stdout,
        &[
            &first,
            &gateway_tree_digest(2),
            &gateway_tree_digest(1),
            "linearTeam",
            CLOUD_TEAM_ID,
            "Automation",
            CLOUD_PUBLISHER,
        ],
    );
    assert_eq!(
        routes(&requests),
        vec![
            format!("GET {definitions}/{first}"),
            format!("GET {definitions}/{first}/revisions/2"),
            format!("GET {definitions}/{first}/revisions"),
        ]
    );
    let (output, _) = definition(&["show", &first, "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let shown = report(&output);
    assert_eq!(shown["command"], "useful workflow definition show");
    assert_eq!(shown["outcome"], "shown", "{shown}");
    assert_eq!(shown["on"], "project", "{shown}");
    assert_eq!(shown["organizationRef"], CLOUD_ORGANIZATION);
    assert_eq!(shown["projectId"], CLOUD_PROJECT);
    assert_eq!(shown["definition"]["id"], first.as_str());
    assert_eq!(shown["revision"]["number"], 2);
    assert_eq!(shown["revision"]["treeDigest"], gateway_tree_digest(2));
    assert_eq!(
        shown["revision"]["resolution"]["linearTeam"]["id"],
        CLOUD_TEAM_ID
    );
    assert_eq!(
        shown["revisions"]
            .as_array()
            .expect("revisions")
            .iter()
            .map(|revision| revision["number"].as_i64())
            .collect::<Vec<_>>(),
        vec![Some(2), Some(1)]
    );

    // Enabling without an execution principal is refused with the problem type.
    let (output, requests) = target("enable", false);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_contains_all(
        &stderr,
        &["definition-not-startable", "execution-principal"],
    );
    assert_eq!(
        routes(&requests),
        vec![format!("POST {definitions}/{first}/enable")]
    );
    assert!(requests[0].header("idempotency-key").is_some());
    let (output, _) = target("enable", true);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let refused = report(&output);
    assert_eq!(refused["outcome"], "refused", "{refused}");
    assert_eq!(refused["status"], 409);
    assert_eq!(refused["problem"], "definition-not-startable");
    assert_eq!(refused["workflow"]["startCheck"], "execution-principal");

    let (output, requests) = definition(&["update", &first, "--run-as", CLOUD_PRINCIPAL, "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let set = report(&output);
    assert_eq!(set["command"], "useful workflow definition update");
    assert_eq!(set["outcome"], "principal_set", "{set}");
    assert_eq!(set["definition"]["executionPrincipalId"], CLOUD_PRINCIPAL);
    assert_eq!(
        routes(&requests),
        vec![format!("PUT {definitions}/{first}/execution-principal")]
    );
    assert_eq!(requests[0].json(), json!({"principalId": CLOUD_PRINCIPAL}));
    assert!(requests[0].header("idempotency-key").is_some());

    let (output, requests) = target("enable", true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let enabled = report(&output);
    assert_eq!(enabled["outcome"], "enabled", "{enabled}");
    assert_eq!(enabled["definition"]["automaticStarts"], true);
    assert_eq!(
        routes(&requests),
        vec![format!("POST {definitions}/{first}/enable")]
    );

    for (leaf, state, automatic_starts) in [
        ("disable", "active", false),
        ("archive", "archived", false),
        ("unarchive", "active", false),
    ] {
        let (output, requests) = target(leaf, true);
        assert_eq!(output.status.code(), Some(0), "{leaf}: {output:?}");
        let changed = report(&output);
        assert_eq!(changed["outcome"], format!("{leaf}d"), "{changed}");
        assert_eq!(changed["definition"]["state"], state);
        assert_eq!(changed["definition"]["automaticStarts"], automatic_starts);
        assert_eq!(
            routes(&requests),
            vec![format!("POST {definitions}/{first}/{leaf}")]
        );
    }
    assert!(home.workflow_entries().is_empty());
}

// `delete` sends nothing without `--yes`, is refused for a definition that is still active
// with the archive to run first, deletes an archived one under one key that it sends again
// when the reply is lost, and then finds it no more; it finds an archived definition by its
// name, and touches nothing under the `useful` home.
#[test]
fn delete_deletes_an_archived_cloud_definition_under_one_key() {
    let home = Home::new();
    let gateway = FakeGateway::new();
    let first = format!("{CLOUD_ID_STEM}c");
    let second = format!("{CLOUD_ID_STEM}d");
    gateway.define(&first, 2);
    let definitions = format!(
        "/api/v1/organizations/{CLOUD_ORGANIZATION}/projects/{CLOUD_PROJECT}/workflow-definitions"
    );
    let deleted_route = format!("DELETE {definitions}/{first}");
    let definition = |args: &[&str]| {
        let mut all = vec!["workflow", "definition"];
        all.extend_from_slice(args);
        all.extend_from_slice(&[
            "--org",
            CLOUD_ORGANIZATION,
            "--project",
            CLOUD_PROJECT,
            "--allow-insecure-http",
        ]);
        let (output, requests) = gateway.run(&home, &all);
        super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
        (output, requests)
    };
    let listed = || {
        let (output, _) = definition(&["list", "--on", "project", "--json"]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        report(&output)["definitions"]
            .as_array()
            .expect("definitions")
            .iter()
            .map(|item| text(&item["id"], "id").to_owned())
            .collect::<Vec<_>>()
    };

    let (output, requests) = definition(&["delete", &first, "--json"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(requests.is_empty());
    assert!(
        gateway
            .state
            .lock()
            .unwrap()
            .definitions
            .contains_key(&first)
    );

    let (output, requests) = definition(&["delete", &first, "--yes", "--json"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let refused = report(&output);
    assert_eq!(refused["command"], "useful workflow definition delete");
    assert_eq!(refused["outcome"], "refused", "{refused}");
    assert_eq!(refused["status"], 409);
    assert_eq!(refused["problem"], "definition-not-archived");
    assert_eq!(routes(&requests), vec![deleted_route.clone()]);
    assert!(
        requests[0]
            .header("idempotency-key")
            .is_some_and(|key| !key.is_empty())
    );
    let (output, _) = definition(&["delete", &first, "--yes"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("definition-not-archived"), "{stderr}");
    assert!(
        stderr
            .lines()
            .any(|line| line.starts_with("  useful workflow definition archive")),
        "{stderr}"
    );

    let (output, _) = definition(&["archive", &first, "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    gateway.drop_next_publication_reply();
    let (output, requests) = definition(&["delete", &first, "--yes", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let deleted = report(&output);
    assert_eq!(deleted["outcome"], "deleted", "{deleted}");
    assert_eq!(deleted["definitionId"], first.as_str());
    assert_eq!(deleted["organizationRef"], CLOUD_ORGANIZATION);
    assert_eq!(deleted["projectId"], CLOUD_PROJECT);
    assert!(deleted.get("definition").is_none(), "{deleted}");
    assert_eq!(
        routes(&requests),
        vec![deleted_route.clone(), deleted_route.clone()]
    );
    let key = requests[0].header("idempotency-key");
    assert!(key.is_some_and(|key| !key.is_empty()));
    assert_eq!(requests[1].header("idempotency-key"), key);
    assert!(!listed().contains(&first));

    let (output, _) = definition(&["delete", &first, "--yes", "--json"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let missing = report(&output);
    assert_eq!(missing["status"], 404, "{missing}");
    assert_eq!(missing["problem"], "not-found");

    // An archived definition is found by its name.
    gateway.define_named(&second, 1, "retired");
    let (output, _) = definition(&["archive", "retired"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let (output, requests) = definition(&["delete", "retired", "--yes"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        routes(&requests).last(),
        Some(&format!("DELETE {definitions}/{second}"))
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(&second),
        "{output:?}"
    );
    assert!(home.workflow_entries().is_empty());
}

// `show` of a revision holding integration bindings prints, after the flat resolution, each
// integration's account with its id and each of its bindings as `<id>.<name>` with its value,
// kind and resolved id; `--json` carries both members as Cloud returned them.
#[test]
fn cloud_show_prints_each_integrations_account_and_bindings() {
    let home = Home::new();
    let gateway = FakeGateway::new();
    let id = format!("{CLOUD_ID_STEM}c");
    gateway.define_with_integrations(&id, 1);
    let show = |json: bool| {
        let mut args = vec![
            "workflow",
            "definition",
            "show",
            id.as_str(),
            "--org",
            CLOUD_ORGANIZATION,
            "--project",
            CLOUD_PROJECT,
            "--allow-insecure-http",
        ];
        if json {
            args.push("--json");
        }
        let (output, _) = gateway.run(&home, &args);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        output
    };

    let stdout = String::from_utf8(show(false).stdout).expect("UTF-8 report");
    let lines = stdout.lines().collect::<Vec<_>>();
    let at = |what: &dyn Fn(&str) -> bool| {
        lines
            .iter()
            .position(|line| what(line))
            .unwrap_or_else(|| panic!("no such line in {stdout}"))
    };
    let flat = at(&|line| line.starts_with("linearTeam") && line.contains(CLOUD_TEAM_ID));
    let linear_account = at(&|line| line.contains(CLOUD_LINEAR_ACCOUNT));
    let github_account = at(&|line| line.contains(CLOUD_GITHUB_ACCOUNT));
    let team = at(&|line| line.starts_with("linear.team"));
    let state = at(&|line| line.starts_with("linear.ownedState"));
    let repository = at(&|line| line.starts_with("github.repository"));
    assert_contains_all(lines[linear_account], &["linear", "Useful"]);
    assert_contains_all(lines[github_account], &["github"]);
    assert_contains_all(
        lines[team],
        &["ENG", "(team)", CLOUD_INTEGRATION_TEAM_ID, "Engineering"],
    );
    assert_contains_all(
        lines[repository],
        &["useful-machinery/platform", "(repository)"],
    );
    assert!(
        flat < github_account
            && github_account < repository
            && repository < linear_account
            && linear_account < state
            && state < team,
        "{stdout}"
    );

    let shown = report(&show(true));
    let (bindings, resolution) = gateway_integrations();
    assert_eq!(
        shown["revision"]["integrationBindings"], bindings,
        "{shown}"
    );
    assert_eq!(
        shown["revision"]["integrationResolution"], resolution,
        "{shown}"
    );
}

/// The problems Cloud answers when it is temporarily unable to serve a request, each with its
/// status line and status.
const TRANSIENT_PROBLEMS: [(&str, u16, &str); 3] = [
    ("503 Service Unavailable", 503, "service-unavailable"),
    ("503 Service Unavailable", 503, "retryable-conflict"),
    ("500 Internal Server Error", 500, "internal-server-error"),
];

// A change answered with a transient problem is sent once more under its key and a second such
// answer is Cloud being unavailable; a 503 naming its own cause is refused.
#[test]
fn a_definition_change_answered_with_a_transient_problem_is_resent_once() {
    let home = Home::new();
    let gateway = FakeGateway::new();
    let id = format!("{CLOUD_ID_STEM}c");
    gateway.define(&id, 2);
    let disable = format!(
        "POST /api/v1/organizations/{CLOUD_ORGANIZATION}/projects/{CLOUD_PROJECT}/workflow-definitions/{id}/disable"
    );
    let args = [
        "workflow",
        "definition",
        "disable",
        id.as_str(),
        "--org",
        CLOUD_ORGANIZATION,
        "--project",
        CLOUD_PROJECT,
        "--json",
        "--allow-insecure-http",
    ];
    let enable = || {
        gateway
            .state
            .lock()
            .unwrap()
            .definitions
            .get_mut(&id)
            .expect("seeded definition")
            .automatic_starts = true;
    };
    let one_key = |requests: &[GatewayRequest]| {
        assert_eq!(routes(requests), vec![disable.clone(), disable.clone()]);
        let key = requests[0].header("idempotency-key").expect("change key");
        assert!(!key.is_empty());
        assert_eq!(requests[1].header("idempotency-key"), Some(key));
    };

    for (line, status, slug) in TRANSIENT_PROBLEMS {
        enable();
        gateway.answer_next_keyed_with(line, status, slug);
        let (output, requests) = gateway.run(&home, &args);
        assert_eq!(output.status.code(), Some(0), "{slug}: {output:?}");
        let changed = report(&output);
        assert_eq!(changed["outcome"], "disabled", "{changed}");
        assert_eq!(changed["definition"]["automaticStarts"], false);
        one_key(&requests);

        enable();
        gateway.answer_next_keyed_with(line, status, slug);
        gateway.answer_next_keyed_with(line, status, slug);
        let (output, requests) = gateway.run(&home, &args);
        assert_eq!(output.status.code(), Some(4), "{slug}: {output:?}");
        let unavailable = report(&output);
        assert_eq!(unavailable["outcome"], "unavailable", "{unavailable}");
        for member in ["status", "problem", "workflow", "diagnostic"] {
            assert!(unavailable.get(member).is_none(), "{unavailable}");
        }
        one_key(&requests);
        let state = gateway.state.lock().unwrap();
        assert!(state.definitions[&id].automatic_starts);
        assert_eq!(state.definitions[&id].current, 2);
    }

    gateway.answer_next_keyed_with(
        "503 Service Unavailable",
        503,
        "binding-resolution-unavailable",
    );
    let (output, requests) = gateway.run(&home, &args);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let refused = report(&output);
    assert_eq!(refused["outcome"], "refused", "{refused}");
    assert_eq!(refused["status"], 503);
    assert_eq!(refused["problem"], "binding-resolution-unavailable");
    assert_eq!(routes(&requests), vec![disable.clone()]);
    assert!(gateway.state.lock().unwrap().definitions[&id].automatic_starts);
    assert!(home.workflow_entries().is_empty());
}

// A definition leaf whose answer from Cloud fails a check reports `invalid_response` with the
// stage and the check that failed.
#[test]
fn definition_leaves_report_the_stage_and_check_of_an_invalid_response() {
    let home = Home::new();
    let gateway = FakeGateway::new();
    let id = format!("{CLOUD_ID_STEM}c");
    gateway.define(&id, 2);
    gateway
        .state
        .lock()
        .unwrap()
        .definitions
        .get_mut(&id)
        .expect("seeded definition")
        .principal = Some(CLOUD_PRINCIPAL.to_owned());
    let archived = format!("{CLOUD_ID_STEM}d");
    gateway.define(&archived, 1);
    gateway
        .state
        .lock()
        .unwrap()
        .definitions
        .get_mut(&archived)
        .expect("seeded definition")
        .archived = true;
    let deleting = vec![
        "workflow",
        "definition",
        "delete",
        archived.as_str(),
        "--yes",
        "--org",
        CLOUD_ORGANIZATION,
        "--project",
        CLOUD_PROJECT,
        "--allow-insecure-http",
        "--json",
    ];
    let leaf = |leaf: &'static str, json: bool| {
        let mut args = vec![
            "workflow",
            "definition",
            leaf,
            id.as_str(),
            "--org",
            CLOUD_ORGANIZATION,
            "--project",
            CLOUD_PROJECT,
            "--allow-insecure-http",
        ];
        if json {
            args.push("--json");
        }
        args
    };
    let show = |json: bool| {
        let mut args = vec![
            "workflow",
            "definition",
            "show",
            id.as_str(),
            "--org",
            CLOUD_ORGANIZATION,
            "--project",
            CLOUD_PROJECT,
            "--allow-insecure-http",
        ];
        if json {
            args.push("--json");
        }
        args
    };

    for (fault, args, diagnostic) in [
        (
            Fault::ReadOtherDefinition,
            show(true),
            json!({"stage": "definition_read", "check": "identity"}),
        ),
        (
            Fault::ChangeWithoutKey,
            leaf("enable", true),
            json!({"stage": "definition_change", "check": "idempotency_key"}),
        ),
        (
            Fault::ChangeWithoutKey,
            deleting,
            json!({"stage": "definition_change", "check": "idempotency_key"}),
        ),
    ] {
        gateway.answer_next_with(fault);
        let (output, _) = gateway.run(&home, &args);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
        let failed = report(&output);
        assert_eq!(failed["outcome"], "invalid_response", "{failed}");
        assert_eq!(failed["diagnostic"], diagnostic, "{failed}");
        for member in ["status", "problem", "workflow"] {
            assert!(failed.get(member).is_none(), "{failed}");
        }
    }

    gateway.answer_next_with(Fault::ReadOtherDefinition);
    let (output, _) = gateway.run(&home, &show(false));
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_contains_all(
        &stderr,
        &["invalid_response", "definition_read", "identity"],
    );
}

// `evaluation list` sends its filters and page as typed and `evaluation show` reads one
// evaluation, both asking for representation 4; both report each evaluation's state, stored
// reason and blocking run, `-` when it has none, and the readiness blockers of an evaluation
// whose project was not ready.
#[test]
fn definition_evaluations_are_listed_with_their_filters_and_shown_with_their_reason() {
    let home = Home::new();
    let gateway = FakeGateway::new();
    let definition = format!("{CLOUD_ID_STEM}c");
    gateway.define(&definition, 2);
    let evaluations = format!(
        "/api/v1/organizations/{CLOUD_ORGANIZATION}/projects/{CLOUD_PROJECT}/workflow-definitions/{definition}/evaluations"
    );
    let run_id = "run_01k0z6r1w8f4jy2m7q9v3x5abc";
    let evaluation = |args: &[&str]| {
        let mut all = vec!["workflow", "definition", "evaluation"];
        all.extend_from_slice(args);
        all.extend_from_slice(&[
            "--org",
            CLOUD_ORGANIZATION,
            "--project",
            CLOUD_PROJECT,
            "--allow-insecure-http",
        ]);
        let (output, requests) = gateway.run(&home, &all);
        super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
        (output, requests)
    };
    let list = |extra: &[&str]| {
        let mut args = vec!["list", definition.as_str()];
        args.extend_from_slice(extra);
        evaluation(&args)
    };

    let (output, requests) = list(&[
        "--state", "failed", "--run", run_id, "--limit", "5", "--cursor", "page-2", "--json",
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(requests.len(), 1);
    let (path, query) = requests[0].path.split_once('?').expect("a query");
    assert_eq!(path, evaluations);
    let mut pairs = query.split('&').collect::<Vec<_>>();
    pairs.sort_unstable();
    assert_eq!(
        pairs,
        [
            "cursor=page-2",
            "limit=5",
            "representation=4",
            &format!("runId={run_id}"),
            "state=failed",
            "vocabulary=4"
        ]
    );
    let listed = report(&output);
    assert_eq!(
        listed["command"],
        "useful workflow definition evaluation list"
    );
    assert_eq!(listed["outcome"], "listed", "{listed}");
    assert_eq!(listed["organizationRef"], CLOUD_ORGANIZATION);
    assert_eq!(listed["projectId"], CLOUD_PROJECT);
    assert_eq!(listed["definitionId"], definition.as_str());
    assert_eq!(listed["nextCursor"], "older-evaluations");
    let items = listed["evaluations"].as_array().expect("evaluations");
    let named = [
        gateway_evaluation(&definition, CLOUD_EVALUATION),
        gateway_blocked_evaluation(&definition),
        gateway_not_ready_evaluation(&definition),
    ];
    assert!(
        items.ends_with(&named),
        "the oldest evaluations, in order: {listed}"
    );
    assert_eq!(
        items
            .last()
            .map(|item| &item["observations"]["project"]["blockers"]),
        Some(&json!(["runner_pool_unassigned", "repository_detached"]))
    );

    let (output, requests) = list(&[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        requests[0].path,
        format!("{evaluations}?representation=4&vocabulary=4")
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains_all(
        &stdout,
        &[
            CLOUD_EVALUATION,
            "failed",
            "owner_unresolved",
            "start-on-todo",
            "older-evaluations",
        ],
    );
    let line = |id: &str| {
        stdout
            .lines()
            .find(|line| line.contains(id))
            .unwrap_or_else(|| panic!("a line for {id}: {stdout}"))
    };
    let blocking_run = |id: &str| {
        line(id)
            .rsplit(" · ")
            .next()
            .and_then(|field| field.strip_prefix("blocking run "))
            .map(str::to_owned)
    };
    assert_eq!(blocking_run(CLOUD_EVALUATION).as_deref(), Some("-"));
    assert_eq!(
        blocking_run(CLOUD_BLOCKED_EVALUATION).as_deref(),
        Some(CLOUD_BLOCKING_RUN)
    );
    let not_ready = line(CLOUD_NOT_READY_EVALUATION);
    assert_contains_all(not_ready, &["project_not_ready"]);
    assert_eq!(
        not_ready.rsplit(" · ").next(),
        Some("project blockers runner_pool_unassigned, repository_detached"),
        "{not_ready}"
    );

    let show = |id: &str, json: bool| {
        let mut args = vec!["show", id, "--definition", definition.as_str()];
        if json {
            args.push("--json");
        }
        evaluation(&args)
    };
    let (output, requests) = show(CLOUD_EVALUATION, true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        requests
            .iter()
            .map(|request| &request.path)
            .collect::<Vec<_>>(),
        [&format!(
            "{evaluations}/{CLOUD_EVALUATION}?representation=4&vocabulary=4"
        )]
    );
    let shown = report(&output);
    assert_eq!(shown["outcome"], "shown", "{shown}");
    assert_eq!(
        shown["evaluation"],
        gateway_evaluation(&definition, CLOUD_EVALUATION)
    );
    let project_blockers = |stdout: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix("project blockers: "))
            .map(str::to_owned)
    };
    let (output, _) = show(CLOUD_EVALUATION, false);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains_all(
        &stdout,
        &[
            CLOUD_EVALUATION,
            "failed",
            "owner_unresolved",
            "AUTO-7",
            CLOUD_PRINCIPAL,
        ],
    );
    assert_eq!(project_blockers(&stdout).as_deref(), Some("-"), "{stdout}");

    let (output, _) = show(CLOUD_NOT_READY_EVALUATION, true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let shown = report(&output);
    assert_eq!(
        shown["evaluation"]["observations"]["project"]["blockers"],
        json!(["runner_pool_unassigned", "repository_detached"]),
        "{shown}"
    );
    let (output, _) = show(CLOUD_NOT_READY_EVALUATION, false);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains_all(&stdout, &["project_not_ready"]);
    assert_eq!(
        project_blockers(&stdout).as_deref(),
        Some("runner_pool_unassigned, repository_detached"),
        "{stdout}"
    );
    assert!(home.workflow_entries().is_empty());
}

// `evaluation list` and `evaluation show` ask for an evaluation vocabulary that holds the push
// event, so a push evaluation is listed and read, printed as Cloud sent it under `--json` and
// with its branch and commit in human output.
#[test]
fn definition_evaluations_list_and_show_a_push_with_its_branch_and_commit() {
    let home = Home::new();
    let gateway = FakeGateway::new();
    let definition = format!("{CLOUD_ID_STEM}c");
    gateway.define(&definition, 2);
    let evaluations = format!(
        "/api/v1/organizations/{CLOUD_ORGANIZATION}/projects/{CLOUD_PROJECT}/workflow-definitions/{definition}/evaluations"
    );
    let pushed = gateway_push_evaluation(&definition);
    let evaluation = |args: &[&str]| {
        let mut all = vec!["workflow", "definition", "evaluation"];
        all.extend_from_slice(args);
        all.extend_from_slice(&[
            "--org",
            CLOUD_ORGANIZATION,
            "--project",
            CLOUD_PROJECT,
            "--allow-insecure-http",
        ]);
        let (output, requests) = gateway.run(&home, &all);
        super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
        (output, requests)
    };

    let list = ["list", definition.as_str()];
    let show = [
        "show",
        CLOUD_PUSH_EVALUATION,
        "--definition",
        definition.as_str(),
    ];
    let (output, requests) = evaluation(&[&list[..], &["--json"]].concat());
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(requests.len(), 1);
    let (path, query) = requests[0].path.split_once('?').expect("a query");
    assert_eq!(path, evaluations);
    assert!(
        query.split('&').any(|pair| pair == "vocabulary=4"),
        "{query}"
    );
    let listed = report(&output);
    assert_eq!(listed["outcome"], "listed", "{listed}");
    let items = listed["evaluations"].as_array().expect("evaluations");
    assert!(items.contains(&pushed), "{listed}");

    let (output, requests) = evaluation(&[&show[..], &["--json"]].concat());
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].path,
        format!("{evaluations}/{CLOUD_PUSH_EVALUATION}?representation=4&vocabulary=4")
    );
    let shown = report(&output);
    assert_eq!(shown["outcome"], "shown", "{shown}");
    assert_eq!(shown["evaluation"], pushed);

    for args in [&list[..], &show[..]] {
        let (output, _) = evaluation(args);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_contains_all(
            &String::from_utf8_lossy(&output.stdout),
            &[CLOUD_PUSH_EVALUATION, "push", "main", CLOUD_PUSH_COMMIT],
        );
    }
    assert!(home.workflow_entries().is_empty());
}

// `enable` and `disable` set the record's `enabled` of a definition the home holds by its ID and
// send nothing; a name is looked up in the project alone, so the project's definition of the
// name is enabled and the home's record of the same name is left as it was.
#[test]
fn enable_acts_on_the_home_s_record_by_its_id_and_on_the_project_s_definition_by_name() {
    let home = Home::new();
    let tree = Tree::engineering();
    let (local, _) = home.seed(&tree);
    let record_path = home.definition_directory(&local).join("definition.json");
    let gateway = FakeGateway::new();
    let cloud = format!("{CLOUD_ID_STEM}c");
    gateway.define_named(&cloud, 1, "engineering");
    gateway
        .state
        .lock()
        .unwrap()
        .definitions
        .get_mut(&cloud)
        .expect("seeded definition")
        .principal = Some(CLOUD_PRINCIPAL.to_owned());
    let definition = |args: &[&str]| {
        let mut all = vec!["workflow", "definition"];
        all.extend_from_slice(args);
        all.extend_from_slice(&[
            "--org",
            CLOUD_ORGANIZATION,
            "--project",
            CLOUD_PROJECT,
            "--allow-insecure-http",
            "--json",
        ]);
        let (output, requests) = gateway.run(&home, &all);
        super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
        (output, requests)
    };

    let (output, requests) = definition(&["disable", &local]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(requests.is_empty(), "{:?}", routes(&requests));
    let disabled = report(&output);
    assert_eq!(disabled["outcome"], "disabled", "{disabled}");
    assert_eq!(disabled["definition"]["id"], local.as_str());
    assert_eq!(disabled["definition"]["changed"], true);
    let record = read_json(&record_path);
    assert_eq!(record["enabled"], false);

    let (output, requests) = definition(&["enable", "engineering"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let enabled = report(&output);
    assert_eq!(enabled["outcome"], "enabled", "{enabled}");
    assert_eq!(enabled["definition"]["id"], cloud.as_str());
    assert_eq!(enabled["definition"]["automaticStarts"], true);
    let definitions = workflow_definitions_route();
    let route = definitions.replacen("GET", "POST", 1);
    assert_eq!(
        routes(&requests),
        vec![definitions.clone(), format!("{route}/{cloud}/enable")]
    );
    assert_eq!(read_json(&record_path), record);
}

// A leaf that acts on a Cloud definition alone refuses an ID the home holds with
// `definition_local`, before anything is sent.
#[test]
fn a_cloud_leaf_refuses_a_definition_under_the_home() {
    let home = Home::new();
    let tree = Tree::engineering();
    let (local, _) = home.seed(&tree);
    let record_path = home.definition_directory(&local).join("definition.json");
    let record = read_json(&record_path);
    let gateway = FakeGateway::new();
    for (leaf, json) in [
        (&["archive"][..], true),
        (&["archive"], false),
        (&["delete", "--yes"], true),
    ] {
        let mut args = vec!["workflow", "definition", leaf[0], local.as_str()];
        args.extend_from_slice(&leaf[1..]);
        args.extend_from_slice(&[
            "--org",
            CLOUD_ORGANIZATION,
            "--project",
            CLOUD_PROJECT,
            "--allow-insecure-http",
        ]);
        if json {
            args.push("--json");
        }
        let (output, requests) = gateway.run(&home, &args);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(requests.is_empty(), "{:?}", routes(&requests));
        if json {
            let refused = report(&output);
            assert_eq!(
                refused["command"],
                format!("useful workflow definition {}", leaf[0])
            );
            assert_eq!(refused["outcome"], "refused", "{refused}");
            assert_eq!(refused["diagnostics"][0]["code"], "definition_local");
            assert_eq!(refused["diagnostics"][0]["definition"], local.as_str());
        } else {
            assert_contains_all(
                &String::from_utf8_lossy(&output.stdout),
                &["definition_local", &local],
            );
        }
    }
    assert_eq!(read_json(&record_path), record);
}

// `update DEFINITION --run-as SERVICE` sends the principal ID of the one service
// principal of the organization with that display name, read from the member directory,
// or a principal ID as given; a name several have or none has sends no change.
#[test]
fn update_run_as_names_a_service_principal_by_its_display_name_or_its_id() {
    let home = Home::new();
    let gateway = FakeGateway::new();
    let engineering = format!("{CLOUD_ID_STEM}c");
    gateway.define_named(&engineering, 1, "engineering");
    gateway.define_named(&format!("{CLOUD_ID_STEM}d"), 1, "alpha");
    gateway.define_named(&format!("{CLOUD_ID_STEM}e"), 1, "beta");
    let ci = "prn_01k0z6r1w8f4jy2m7q9v3x5c10";
    let [deploy, other_deploy] =
        ["1", "2"].map(|last| format!("prn_01k0z6r1w8f4jy2m7q9v3x5de{last}"));
    gateway.add_member(CLOUD_PUBLISHER, "human", "ci");
    gateway.add_member(ci, "service", "ci");
    gateway.add_member(&deploy, "service", "deploy");
    gateway.add_member(&other_deploy, "service", "deploy");
    let definitions = workflow_definitions_route();
    let members = format!("GET /api/v1/organizations/{CLOUD_ORGANIZATION}/memberships");
    let principal = format!(
        "{}/{engineering}/execution-principal",
        definitions.replacen("GET", "PUT", 1)
    );
    let update = |run_as: &str| {
        let (output, requests) = gateway.run(
            &home,
            &[
                "workflow",
                "definition",
                "update",
                "engineering",
                "--run-as",
                run_as,
                "--org",
                CLOUD_ORGANIZATION,
                "--project",
                CLOUD_PROJECT,
                "--json",
                "--allow-insecure-http",
            ],
        );
        super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
        (output, requests)
    };

    let (output, requests) = update("ci");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let set = report(&output);
    assert_eq!(set["outcome"], "principal_set", "{set}");
    assert_eq!(set["definition"]["executionPrincipalId"], ci);
    assert_eq!(
        routes(&requests),
        vec![
            definitions.clone(),
            definitions.clone(),
            members.clone(),
            principal.clone()
        ]
    );
    assert_eq!(requests[3].json(), json!({"principalId": ci}));

    let (output, requests) = update(&deploy);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        report(&output)["definition"]["executionPrincipalId"],
        deploy.as_str()
    );
    assert_eq!(
        routes(&requests),
        vec![definitions.clone(), definitions.clone(), principal.clone()]
    );

    let (output, requests) = update("deploy");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_contains_all(
        &String::from_utf8_lossy(&output.stderr),
        &[&deploy, &other_deploy],
    );
    assert_eq!(
        routes(&requests),
        vec![definitions.clone(), definitions.clone(), members.clone()]
    );

    let (output, requests) = update("release");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(report(&output)["outcome"], "not_found");
    assert_eq!(
        routes(&requests),
        vec![definitions.clone(), definitions, members]
    );
    let state = gateway.state.lock().unwrap();
    assert_eq!(
        state.definitions[&engineering].principal.as_deref(),
        Some(deploy.as_str())
    );
}

// `evaluation list` and `evaluation show` find the definition by its name in the project in
// effect and send the filters and the page as given.
#[test]
fn definition_evaluations_find_the_definition_by_its_name() {
    evaluations_find_the_definition(false);
}

// `enable` takes the definition ID `update --run-as` printed, and `evaluation show` the
// evaluation ID `evaluation list` printed for the definition they configured.
#[test]
fn a_definition_given_an_identity_and_enabled_reports_the_evaluation_its_list_names() {
    evaluations_find_the_definition(true);
}

/// `evaluation list` and `evaluation show` of the definition named `engineering`, alone or
/// `configured_first`: after `update --run-as` and `enable`, with each ID taken from the
/// output of the command before.
fn evaluations_find_the_definition(configured_first: bool) {
    let home = Home::new();
    let gateway = FakeGateway::new();
    let engineering = format!("{CLOUD_ID_STEM}c");
    gateway.define_named(&engineering, 2, "engineering");
    let definitions = workflow_definitions_route();
    let evaluations = format!(
        "/api/v1/organizations/{CLOUD_ORGANIZATION}/projects/{CLOUD_PROJECT}/workflow-definitions/{engineering}/evaluations"
    );
    let run_id = "run_01k0z6r1w8f4jy2m7q9v3x5abc";
    let definition = |args: &[&str]| {
        let mut all = vec!["workflow", "definition"];
        all.extend_from_slice(args);
        all.extend_from_slice(&[
            "--org",
            CLOUD_ORGANIZATION,
            "--project",
            CLOUD_PROJECT,
            "--json",
            "--allow-insecure-http",
        ]);
        let (output, requests) = gateway.run(&home, &all);
        super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
        (output, requests)
    };

    if configured_first {
        gateway.add_member(CLOUD_PRINCIPAL, "service", "ci");
        let (updated, _) = definition(&["update", "engineering", "--run-as", "ci"]);
        assert!(updated.status.success(), "{updated:?}");
        let updated = report(&updated);
        assert_eq!(
            updated["definition"]["executionPrincipalId"],
            CLOUD_PRINCIPAL
        );
        let (enabled, _) = definition(&["enable", updated["definition"]["id"].as_str().unwrap()]);
        assert!(enabled.status.success(), "{enabled:?}");
        assert_eq!(report(&enabled)["definition"]["automaticStarts"], true);
    }
    let (output, requests) = definition(&[
        "evaluation",
        "list",
        "engineering",
        "--state",
        "not_matched",
        "--run",
        run_id,
        "--limit",
        "2",
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(routes(&requests[..1]), vec![definitions.clone()]);
    assert_eq!(requests.len(), 2, "{:?}", routes(&requests));
    let (path, query) = requests[1].path.split_once('?').expect("a query");
    assert_eq!(path, evaluations);
    let mut pairs = query.split('&').collect::<Vec<_>>();
    pairs.sort_unstable();
    assert_eq!(
        pairs,
        [
            "limit=2",
            "representation=4",
            &format!("runId={run_id}"),
            "state=not_matched",
            "vocabulary=4"
        ]
    );
    assert_eq!(report(&output)["definitionId"], engineering.as_str());

    let page = report(&output);
    let selected = if configured_first {
        page["evaluations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|evaluation| evaluation["id"] == CLOUD_EVALUATION)
            .unwrap()["id"]
            .as_str()
            .unwrap()
    } else {
        CLOUD_EVALUATION
    };
    let (output, requests) = definition(&[
        "evaluation",
        "show",
        selected,
        "--definition",
        "engineering",
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(requests.len(), 2, "{:?}", routes(&requests));
    assert_eq!(routes(&requests[..1]), vec![definitions]);
    assert_eq!(
        requests[1].path,
        format!("{evaluations}/{CLOUD_EVALUATION}?representation=4&vocabulary=4")
    );
    let shown = report(&output);
    assert_eq!(shown["outcome"], "shown", "{shown}");
    assert_eq!(shown["definitionId"], engineering.as_str());
    assert_eq!(
        shown["evaluation"],
        gateway_evaluation(&engineering, CLOUD_EVALUATION)
    );
    assert!(home.workflow_entries().is_empty());
}

/// `useful workflow definition evaluation list DEFINITION EXTRA...` or `show EXTRA...
/// --definition DEFINITION`, whose first `EXTRA` is the evaluation, in the test project.
fn evaluation_command<'a>(leaf: &'a str, definition: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut all = vec!["workflow", "definition", "evaluation", leaf];
    if leaf == "show" {
        all.extend_from_slice(extra);
        all.extend_from_slice(&["--definition", definition]);
    } else {
        all.push(definition);
        all.extend_from_slice(extra);
    }
    all.extend_from_slice(&[
        "--org",
        CLOUD_ORGANIZATION,
        "--project",
        CLOUD_PROJECT,
        "--allow-insecure-http",
    ]);
    all
}

// `evaluation list` and `evaluation show` ask for evaluation vocabulary 4, so a `run.ended`
// evaluation is listed and read, printed as Cloud sent it under `--json` and with the ended
// run, its attempt and its outcome in human output.
#[test]
fn definition_evaluations_ask_for_vocabulary_4_and_show_a_run_end_with_its_run_attempt_and_outcome()
{
    let home = Home::new();
    let gateway = FakeGateway::new();
    let definition = format!("{CLOUD_ID_STEM}c");
    gateway.define(&definition, 2);
    let evaluations = format!(
        "/api/v1/organizations/{CLOUD_ORGANIZATION}/projects/{CLOUD_PROJECT}/workflow-definitions/{definition}/evaluations"
    );
    let ended = gateway_run_ended_evaluation(&definition);
    let evaluation = |leaf: &str, extra: &[&str]| {
        let all = evaluation_command(leaf, &definition, extra);
        let (output, requests) = gateway.run(&home, &all);
        super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
        (output, requests)
    };

    let (output, requests) = evaluation("list", &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(requests.len(), 1);
    let (path, query) = requests[0].path.split_once('?').expect("a query");
    assert_eq!(path, evaluations);
    assert!(
        query.split('&').any(|pair| pair == "vocabulary=4"),
        "{query}"
    );
    let listed = report(&output);
    assert_eq!(listed["outcome"], "listed", "{listed}");
    let items = listed["evaluations"].as_array().expect("evaluations");
    assert!(items.contains(&ended), "{listed}");

    let (output, requests) = evaluation("show", &[CLOUD_RUN_ENDED_EVALUATION, "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].path,
        format!("{evaluations}/{CLOUD_RUN_ENDED_EVALUATION}?representation=4&vocabulary=4")
    );
    let shown = report(&output);
    assert_eq!(shown["outcome"], "shown", "{shown}");
    assert_eq!(shown["evaluation"], ended);

    let subject = format!("run.ended {CLOUD_ENDED_RUN} attempt 2 broken");
    for args in [vec!["list"], vec!["show", CLOUD_RUN_ENDED_EVALUATION]] {
        let (output, _) = evaluation(args[0], &args[1..]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_contains_all(
            &String::from_utf8_lossy(&output.stdout),
            &[CLOUD_RUN_ENDED_EVALUATION, &subject],
        );
    }
    assert!(home.workflow_entries().is_empty());
}

// `show` asks for binding vocabulary 2 on the revision read and the revision listing, so a
// `definition` binding is printed as Cloud sent it under `--json` and with the bound definition's
// id and name in human output.
#[test]
fn definition_show_asks_for_binding_vocabulary_2_and_prints_a_definition_binding() {
    let home = Home::new();
    let gateway = FakeGateway::new();
    let definition = format!("{CLOUD_ID_STEM}c");
    gateway.define(&definition, 2);
    let revisions = format!(
        "/api/v1/organizations/{CLOUD_ORGANIZATION}/projects/{CLOUD_PROJECT}/workflow-definitions/{definition}/revisions"
    );
    let show = |json: bool| {
        let mut all = vec![
            "workflow",
            "definition",
            "show",
            definition.as_str(),
            "--org",
            CLOUD_ORGANIZATION,
            "--project",
            CLOUD_PROJECT,
            "--allow-insecure-http",
        ];
        if json {
            all.push("--json");
        }
        let (output, requests) = gateway.run(&home, &all);
        super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
        (output, requests)
    };
    let (binding, resolved) = gateway_definition_binding();

    let (output, requests) = show(true);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let shown = report(&output);
    assert_eq!(shown["outcome"], "shown", "{shown}");
    assert_eq!(shown["revision"]["bindings"]["verify"], binding, "{shown}");
    assert_eq!(
        shown["revision"]["resolution"]["verify"], resolved,
        "{shown}"
    );
    let items = shown["revisions"].as_array().expect("revisions");
    assert_eq!(items.len(), 2, "{shown}");
    for item in items {
        assert_eq!(item["bindings"]["verify"], binding, "{item}");
        assert_eq!(item["resolution"]["verify"], resolved, "{item}");
    }
    let revision_reads = requests
        .iter()
        .filter(|request| request.route().starts_with(&format!("GET {revisions}")))
        .collect::<Vec<_>>();
    assert_eq!(
        revision_reads
            .iter()
            .map(|request| request.route())
            .collect::<Vec<_>>(),
        vec![format!("GET {revisions}/2"), format!("GET {revisions}")]
    );
    for request in revision_reads {
        assert!(asks_for_vocabulary_2(request), "{}", request.path);
    }

    let (output, _) = show(false);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|line| line.starts_with("verify"))
        .unwrap_or_else(|| panic!("no verify line: {stdout}"));
    assert_contains_all(
        line,
        &[
            CLOUD_BOUND_DEFINITION,
            "definition",
            CLOUD_BOUND_DEFINITION_NAME,
        ],
    );
    assert!(home.workflow_entries().is_empty());
}

// `evaluation list` and `evaluation show` ask for representation 4 and an evaluation vocabulary
// that holds `issue.unblocked_in_state`, so such an evaluation is listed and read, printed as Cloud
// sent it under `--json` and in human output with its issue and its blocker wait: when the wait
// began and the blockers still open, each by its identifier or else its Linear id.
#[test]
fn definition_evaluations_ask_for_representation_4_and_show_an_evaluation_with_its_blocker_wait() {
    let home = Home::new();
    let gateway = FakeGateway::new();
    let definition = format!("{CLOUD_ID_STEM}c");
    gateway.define(&definition, 2);
    let evaluations = format!(
        "/api/v1/organizations/{CLOUD_ORGANIZATION}/projects/{CLOUD_PROJECT}/workflow-definitions/{definition}/evaluations"
    );
    let waiting = gateway_waiting_evaluation(&definition);
    let unblocked = gateway_unblocked_evaluation(&definition);
    let evaluation = |leaf: &str, extra: &[&str]| {
        let all = evaluation_command(leaf, &definition, extra);
        let (output, requests) = gateway.run(&home, &all);
        super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
        (output, requests)
    };

    let (output, requests) = evaluation("list", &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(requests.len(), 1);
    let (path, query) = requests[0].path.split_once('?').expect("a query");
    assert_eq!(path, evaluations);
    let mut pairs = query.split('&').collect::<Vec<_>>();
    pairs.sort_unstable();
    assert_eq!(pairs, ["representation=4", "vocabulary=4"]);
    let listed = report(&output);
    assert_eq!(listed["outcome"], "listed", "{listed}");
    let items = listed["evaluations"].as_array().expect("evaluations");
    assert!(items.contains(&waiting), "{listed}");
    assert!(items.contains(&unblocked), "{listed}");
    let listed_wait = |id: &str| {
        items
            .iter()
            .find(|item| item["id"] == id)
            .map(|item| item["observations"]["blockerWait"].clone())
    };
    assert_eq!(
        listed_wait(CLOUD_WAITING_EVALUATION).map(|wait| wait["blockers"][1].clone()),
        Some(json!({"id": "issue-c", "identifier": null}))
    );
    assert_eq!(
        listed_wait(CLOUD_UNBLOCKED_EVALUATION).map(|wait| wait["blockers"].clone()),
        Some(json!([]))
    );

    let (output, requests) = evaluation("show", &[CLOUD_WAITING_EVALUATION, "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].path,
        format!("{evaluations}/{CLOUD_WAITING_EVALUATION}?representation=4&vocabulary=4")
    );
    let shown = report(&output);
    assert_eq!(shown["outcome"], "shown", "{shown}");
    assert_eq!(shown["evaluation"], waiting);

    // The wait names when it began, then the open blockers, or `-` when none is open.
    let assert_wait = |wait: &str, blockers: &str| {
        let since = wait.find(CLOUD_WAIT_SINCE);
        assert!(since.is_some(), "{wait}");
        assert!(wait.ends_with(blockers), "{wait}");
        assert!(since < Some(wait.len() - blockers.len()), "{wait}");
    };

    let (output, _) = evaluation("list", &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = |id: &str| {
        stdout
            .lines()
            .find(|line| line.contains(id))
            .unwrap_or_else(|| panic!("a line for {id}: {stdout}"))
    };
    let fields = |id: &str| line(id).split(" · ").collect::<Vec<_>>();
    let event = fields(CLOUD_EVALUATION)
        .iter()
        .position(|field| *field == "issue.state_entered AUTO-7")
        .unwrap_or_else(|| panic!("an event field: {stdout}"));
    assert_eq!(
        fields(CLOUD_WAITING_EVALUATION)[event],
        "issue.unblocked_in_state AUTO-7"
    );
    assert_contains_all(
        line(CLOUD_WAITING_EVALUATION),
        &["retry_waiting", "issue_blocked"],
    );
    let listed_wait = |id: &str| {
        line(id)
            .split_once(" · blocker wait ")
            .map(|(_, wait)| wait.to_owned())
            .unwrap_or_else(|| panic!("a blocker wait for {id}: {stdout}"))
    };
    assert_wait(&listed_wait(CLOUD_WAITING_EVALUATION), "AUTO-2, issue-c");
    assert_wait(&listed_wait(CLOUD_UNBLOCKED_EVALUATION), " -");
    assert_eq!(
        line(CLOUD_EVALUATION).rsplit(" · ").next(),
        Some("blocking run -"),
        "{stdout}"
    );

    let show = |id: &str| {
        let (output, _) = evaluation("show", &[id]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let field = |stdout: &str, label: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(label))
            .map(str::to_owned)
            .unwrap_or_else(|| panic!("a {label:?} line: {stdout}"))
    };
    let stdout = show(CLOUD_WAITING_EVALUATION);
    assert_eq!(field(&stdout, "event: "), "issue.unblocked_in_state AUTO-7");
    let mut lines = stdout.lines();
    lines.find(|line| line.starts_with("event: ")).unwrap();
    assert_eq!(
        lines
            .next()
            .and_then(|line| line.strip_prefix("event actor: ")),
        Some("user linear-user-7")
    );
    assert_wait(&field(&stdout, "blocker wait: "), "AUTO-2, issue-c");
    assert_eq!(field(&stdout, "next attempt: "), CLOUD_NEXT_READ);
    assert_wait(
        &field(&show(CLOUD_UNBLOCKED_EVALUATION), "blocker wait: "),
        " -",
    );
    let stdout = show(CLOUD_EVALUATION);
    assert_eq!(field(&stdout, "blocker wait: "), "-");
    assert_eq!(field(&stdout, "event actor: "), "-");
    assert!(home.workflow_entries().is_empty());
}

// `evaluation list` and `evaluation show` ask for representation 4, so the diagnostic of an
// evaluation that could not read its issue is printed as Cloud sent it under `--json` and in human
// output as its labelled facts, absent members left out, at the end of the listed line and on a
// `diagnostic:` line after `blocker wait:`, which reads `-` for an evaluation with none.
#[test]
fn definition_evaluations_ask_for_representation_4_and_show_an_evaluation_with_its_diagnostic() {
    let home = Home::new();
    let gateway = FakeGateway::new();
    let definition = format!("{CLOUD_ID_STEM}c");
    gateway.define(&definition, 2);
    let evaluations = format!(
        "/api/v1/organizations/{CLOUD_ORGANIZATION}/projects/{CLOUD_PROJECT}/workflow-definitions/{definition}/evaluations"
    );
    let diagnosed = gateway_diagnosed_evaluation(&definition);
    let evaluation = |leaf: &str, extra: &[&str]| {
        let all = evaluation_command(leaf, &definition, extra);
        let (output, requests) = gateway.run(&home, &all);
        super::assert_no_secret_output(&output, &[CLOUD_TOKEN]);
        (output, requests)
    };
    let pairs = |requests: &[GatewayRequest], path: &str| {
        assert_eq!(requests.len(), 1);
        let (requested, query) = requests[0].path.split_once('?').expect("a query");
        assert_eq!(requested, path);
        let mut pairs = query.split('&').map(str::to_owned).collect::<Vec<_>>();
        pairs.sort_unstable();
        pairs
    };

    let (output, requests) = evaluation("list", &["--state", "failed", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        pairs(&requests, &evaluations),
        ["representation=4", "state=failed", "vocabulary=4"]
    );
    let listed = report(&output);
    assert_eq!(listed["outcome"], "listed", "{listed}");
    let items = listed["evaluations"].as_array().expect("evaluations");
    assert!(items.contains(&diagnosed), "{listed}");

    let (output, requests) = evaluation("show", &[CLOUD_DIAGNOSED_EVALUATION, "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        pairs(
            &requests,
            &format!("{evaluations}/{CLOUD_DIAGNOSED_EVALUATION}")
        ),
        ["representation=4", "vocabulary=4"]
    );
    let shown = report(&output);
    assert_eq!(shown["outcome"], "shown", "{shown}");
    assert_eq!(shown["evaluation"], diagnosed);
    assert_eq!(
        shown["evaluation"]["observations"]["diagnostic"],
        json!({"stage": "issue_read", "errorType": "token_refused", "httpStatus": 401})
    );

    let full = "stage issue_read, error type token_refused, http status 401";
    let (output, _) = evaluation("list", &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = |id: &str| {
        stdout
            .lines()
            .find(|line| line.contains(id))
            .unwrap_or_else(|| panic!("a line for {id}: {stdout}"))
    };
    let diagnosed_line = line(CLOUD_DIAGNOSED_EVALUATION);
    assert_contains_all(diagnosed_line, &["failed", "issue_unavailable"]);
    assert!(
        diagnosed_line.ends_with(&format!(" · blocking run - · diagnostic {full}")),
        "{stdout}"
    );
    assert!(
        line(CLOUD_STAGE_DIAGNOSED_EVALUATION).ends_with(" · diagnostic stage issue_read"),
        "{stdout}"
    );
    for id in [CLOUD_EVALUATION, CLOUD_WAITING_EVALUATION] {
        assert!(!line(id).contains(" · diagnostic "), "{stdout}");
    }

    // The diagnostic line follows the blocker wait line.
    let diagnostic = |id: &str| {
        let (output, _) = evaluation("show", &[id]);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let lines = stdout.lines().collect::<Vec<_>>();
        let wait = lines
            .iter()
            .position(|line| line.starts_with("blocker wait: "))
            .unwrap_or_else(|| panic!("a blocker wait line: {stdout}"));
        lines
            .get(wait + 1)
            .and_then(|line| line.strip_prefix("diagnostic: "))
            .map(str::to_owned)
            .unwrap_or_else(|| panic!("a diagnostic line after the blocker wait: {stdout}"))
    };
    assert_eq!(diagnostic(CLOUD_DIAGNOSED_EVALUATION), full);
    assert_eq!(
        diagnostic(CLOUD_STAGE_DIAGNOSED_EVALUATION),
        "stage issue_read"
    );
    assert_eq!(diagnostic(CLOUD_EVALUATION), "-");
    assert!(home.workflow_entries().is_empty());
}
