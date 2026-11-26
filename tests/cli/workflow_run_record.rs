use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

use super::workflow_continue::{
    attempt_count, chained, completed, decide, decide_each, loop_tree, ordinals_of,
    partition_event, read_json, wait_tree,
};
use super::workflow_run::{TreeBundle, isolated_command, run_record, workflow_run_schema};
use super::workflow_run_control::{
    LiveRun, OPERATOR, PublishedWaitTree, attempt_result, refused, states, step_states,
};
use super::workflow_status::signed_out;

fn run_command(home: &Path, args: &[&str]) -> Command {
    let mut command = isolated_command(&[]);
    command.args(["workflow", "run"]).args(args).arg("--json");
    command.env("USEFUL_HOME", home).env("USER", OPERATOR);
    command
}

fn run(home: &Path, args: &[&str]) -> Output {
    signed_out(run_command(home, args))
}

fn success(output: Output) -> Value {
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

fn create(home: &Path, id: &str, record: &Path) -> Output {
    run(
        home,
        &["record", "create", id, "--output", record.to_str().unwrap()],
    )
}

fn restore(home: &Path, record: &Path) -> Output {
    run(home, &["record", "restore", record.to_str().unwrap()])
}

fn path_command(bundle: &TreeBundle, home: &Path) -> Command {
    let mut command = isolated_command(&[]);
    command
        .args(["workflow", "run", "create", "--path"])
        .arg(bundle.source_root())
        .arg("--execution-root")
        .arg(bundle.execution_root())
        .arg("--json")
        .env("USEFUL_HOME", home)
        .env("USER", OPERATOR);
    command
}

fn path_run(bundle: &TreeBundle, home: &Path) -> Value {
    completed(&signed_out(path_command(bundle, home)))
}

fn id(terminal: &Value) -> &str {
    Path::new(terminal["runDirectory"].as_str().unwrap())
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
}

#[test]
fn a_restored_run_shows_as_it_did() {
    let bundle = wait_tree();
    let root = bundle
        .execution_root()
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap();
    let home = root.join("home-a");
    let other = root.join("home-b");
    let record = root.join("record");
    decide(&bundle, "design", "blocked");
    let terminal = path_run(&bundle, &home);
    assert_eq!(terminal["wait"]["kind"], "answer");
    let id = id(&terminal);
    let created = success(create(&home, id, &record));
    assert_eq!(created["outcome"], "created");
    assert_eq!(created["run"], id);
    assert_eq!(created["record"], record.to_str().unwrap());
    for count in ["files", "bytes"] {
        assert!(created[count].as_u64().unwrap() > 0);
    }
    let restored = success(restore(&other, &record));
    assert_eq!(restored["outcome"], "restored");
    assert_eq!(restored["run"], id);
    assert_eq!(
        restored["runDirectory"],
        other.join("runs").join(id).to_str().unwrap()
    );

    let show = |home: &Path| {
        success(run(home, &["show", id]))
            .to_string()
            .replace(home.to_str().unwrap(), "HOME")
    };
    assert_eq!(show(&home), show(&other));
    let listed = success(run(&other, &["list"]));
    assert_eq!(listed["runs"][0]["id"], id);
    assert_eq!(listed["runs"][0]["state"], "waiting");
    success(run(&other, &["view", id]));
    refused(&restore(&other, &record), "record restore", "run_exists");
    refused(
        &create(&home, id, &record),
        "record create",
        "destination_exists",
    );
}

#[test]
fn publishing_with_the_records_definition_id_restores_the_run_under_that_definition() {
    let published = PublishedWaitTree::new();
    let root = published.bundle.execution_root().parent().unwrap();
    let record = root.join("record");
    let other = root.join("home-b");
    let (_, run, _) = published.run("blocked");
    success(create(Path::new(published.home.path()), &run, &record));

    let publish = || {
        let mut command = isolated_command(&[]);
        command
            .args(["workflow", "definition", "publish"])
            .arg(published.bundle.source_root())
            .args(["--id", &published.definition, "--on", "local", "--json"])
            .env("USEFUL_HOME", &other);
        signed_out(command)
    };
    let report = success(publish());
    assert_eq!(report["definition"]["id"], published.definition);
    assert_eq!(report["revision"]["n"], 1);
    let definition = other.join("workflows").join(&published.definition);
    let restored = success(restore(&other, &record));
    let directory = definition.join("runs").join(&run);
    assert_eq!(restored["runDirectory"], directory.to_str().unwrap());
    assert!(directory.is_dir());
    assert!(!other.join("runs").join(&run).exists());

    let before = fs::read(definition.join("definition.json")).unwrap();
    let refused = publish();
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    let report: Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(report["diagnostics"][0]["code"], "definition_exists");
    assert_eq!(
        fs::read(definition.join("definition.json")).unwrap(),
        before
    );
    assert!(!definition.join("revisions/2").exists());
}

#[test]
fn a_restored_live_run_takes_its_subject() {
    let published = PublishedWaitTree::with_subject();
    let root = published.bundle.execution_root().parent().unwrap();
    let source = Path::new(published.home.path());
    let other = root.join("home-b");
    let busy = root.join("home-c");
    for destination in [&other, &busy] {
        assert!(
            Command::new("cp")
                .arg("-R")
                .arg(source)
                .arg(destination)
                .status()
                .unwrap()
                .success()
        );
    }
    let subject = "AUTO-1";
    let (_, id) = published.waiting_for(&published.definition, subject);
    let record = root.join("record");
    success(create(source, &id, &record));
    let restored = success(restore(&other, &record));
    let definition = PathBuf::from("workflows").join(&published.definition);
    let run_path = definition.join("runs").join(&id);
    assert_eq!(
        restored["runDirectory"],
        other.join(&run_path).to_str().unwrap()
    );
    assert_eq!(
        fs::read_to_string(other.join(&definition).join("subjects").join(subject))
            .unwrap()
            .trim(),
        id
    );
    assert_eq!(success(run(&other, &["show", subject]))["record"]["id"], id);
    let mut command =
        published.create_command(&published.definition, &["--input-text", "ticket", subject]);
    let holder = completed(&command.env("USEFUL_HOME", &busy).output().unwrap());
    let holder = Path::new(holder["runDirectory"].as_str().unwrap())
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    let refusal = refused(&restore(&busy, &record), "record restore", "subject_busy");
    assert!(
        refusal["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains(holder)
    );
    assert!(!busy.join(run_path).exists());
    let empty = root.join("empty");
    let restored = success(restore(&empty, &record));
    assert_eq!(
        restored["runDirectory"],
        empty.join("runs").join(id).to_str().unwrap()
    );
    assert!(!empty.join("workflows").exists());
}

// SC-RECORD-1
#[test]
fn a_damaged_record_is_refused() {
    let bundle = TreeBundle::new(
        r#"schemaVersion: 1
steps:
  write:
    kind: cmd
    command: {argv: [sh, -c, "echo hello > greeting.txt"]}
    outputs:
      greeting: {kind: text, from: path, path: greeting.txt}
exports:
  greeting: {ref: outputs.write.greeting}
"#,
    );
    let root = bundle.execution_root().parent().unwrap();
    let home = root.join("home-a");
    let other = root.join("home-b");
    let record = root.join("record");
    let terminal = path_run(&bundle, &home);
    let id = id(&terminal);
    success(create(&home, id, &record));
    let relative = "attempts/000001/result/exports/0001";
    let carrier = record.join("run").join(relative);
    let mut bytes = fs::read(&carrier).unwrap();
    bytes[0] ^= 1;
    fs::write(carrier, bytes).unwrap();
    let refusal = refused(
        &restore(&other, &record),
        "record restore",
        "record_altered",
    );
    assert!(
        refusal["diagnostics"][0]["message"]
            .as_str()
            .unwrap()
            .contains(relative)
    );
    assert!(!other.join("runs").join(id).exists());
}

/// Carry the record between isolated homes. Once it is restored, discard everything on
/// host A, including the original workflow source, before running another command.
fn move_run(bundle: &TreeBundle, home: &Path, id: &str) -> (PathBuf, PathBuf) {
    let root = bundle.execution_root().parent().unwrap();
    let record = root.join("record");
    let other = root.join("home-b");
    let new = root.join("execution-b");
    fs::create_dir(&other).unwrap();
    fs::create_dir(&new).unwrap();
    success(create(home, id, &record));
    success(restore(&other, &record));
    discard_source_host(bundle, home);
    (other, new)
}

fn discard_source_host(bundle: &TreeBundle, home: &Path) {
    // A captured workflow tree in the old run has read-only directories.
    assert!(
        Command::new("chmod")
            .args(["-R", "u+w"])
            .arg(home)
            .status()
            .unwrap()
            .success()
    );
    for path in [home, bundle.execution_root(), bundle.source_root()] {
        fs::remove_dir_all(path).unwrap();
    }
}

fn binary_output_tree() -> TreeBundle {
    let bundle = TreeBundle::new(
        r#"schemaVersion: 1
programs: [bin]
steps:
  first:
    kind: cmd
    command: {argv: [produce]}
    outputs:
      bytes: {kind: file, from: path, path: first.bin, mediaType: application/octet-stream}
  second:
    kind: cmd
    inputs:
      bytes: {ref: outputs.first.bytes}
    command: {argv: [consume]}
"#,
    );
    bundle.write_program(
        "bin/produce",
        r#"#!/bin/sh
set -eu
echo first >> calls
printf '\000\377\200' > first.bin
"#,
    );
    bundle.write_program(
        "bin/consume",
        r#"#!/bin/sh
set -eu
echo second >> calls
cp "$USEFUL_STEP_INPUTS/values/bytes" copy.bin
if test -e hold; then
    touch held
    while test ! -e release; do sleep 0.1; done
fi
test -e ready
"#,
    );
    bundle
}

fn check_binary_copy(root: &Path) {
    assert_eq!(fs::read(root.join("copy.bin")).unwrap(), [0, 255, 128]);
    assert_eq!(fs::read_to_string(root.join("calls")).unwrap(), "second\n");
}

fn restored_retry(bundle: &TreeBundle, from: &str) -> (Command, PathBuf, PathBuf) {
    let root = bundle.execution_root().parent().unwrap();
    let home = root.join("home-a");
    let counter = root.join("check-base-calls");
    let mut initial = path_command(bundle, &home);
    initial.env("PHASE", "initial").env("COUNTER", &counter);
    let failed = signed_out(initial);
    assert_eq!(failed.status.code(), Some(1), "{failed:?}");
    let terminal: Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(terminal["result"]["primaryIssue"]["node"]["id"], from);
    let id = id(&terminal);
    let (other, new) = move_run(bundle, &home, id);
    let mut retry = run_command(
        &other,
        &[
            "retry",
            id,
            "--from",
            from,
            "--execution-root",
            new.to_str().unwrap(),
        ],
    );
    retry.env("PHASE", "continuation").env("COUNTER", &counter);
    (retry, other.join("runs").join(id), new)
}

fn retry_after_move(bundle: &TreeBundle, from: &str) -> (Output, PathBuf) {
    let (retry, run, _) = restored_retry(bundle, from);
    let workspace = run.join("workspaces/candidate");
    assert!(!workspace.exists());
    (signed_out(retry), workspace)
}

// SC-HANDOVER-1
#[test]
fn handover_rebuilds_the_checkout_in_an_empty_root() {
    let bundle = TreeBundle::new(
        r#"schemaVersion: 1
environmentPassthrough: [PHASE]
steps:
  checkout:
    kind: cmd
    workspace: new
    command: {argv: [sh, -ec, 'printf base > file.txt']}
  edit:
    kind: cmd
    dependsOn: [checkout]
    command: {argv: [sh, -ec, 'printf edited >> file.txt']}
  test:
    kind: cmd
    dependsOn: [edit]
    command: {argv: [sh, -ec, 'test "$(cat file.txt)" = baseedited && test "$PHASE" = continuation']}
"#,
    );
    let (mut retry, _, new) = restored_retry(&bundle, "test");
    retry.arg("--handover");
    let output = signed_out(retry);
    let terminal = completed(&output);
    assert_eq!(terminal["attemptNumber"], 2);
    assert_eq!(terminal["outcome"], "succeeded");
    assert_eq!(
        partition_event(&output)["continuation"]["rebuiltWorkspaces"],
        serde_json::json!(["checkout"])
    );
    assert_eq!(
        step_states(&terminal["result"]),
        states(&[
            ("checkout", "succeeded"),
            ("edit", "succeeded"),
            ("test", "succeeded")
        ])
    );
    assert_eq!(fs::read_dir(new).unwrap().count(), 0);
}

fn handover_refusal(output: Output) -> Value {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(workflow_run_schema().is_valid(&result), "{result}");
    assert_eq!(result["outcome"], "rejected");
    assert_eq!(result["phase"], "continuation");
    result
}

// SC-HANDOVER-7
#[test]
fn handover_refuses_the_selected_execution_root_step_before_an_attempt() {
    let bundle = TreeBundle::new(
        r#"schemaVersion: 1
environmentPassthrough: [PHASE]
steps:
  prepare:
    kind: cmd
    command: {argv: [sh, -c, 'true']}
  test:
    kind: cmd
    dependsOn: [prepare]
    command: {argv: [sh, -ec, 'test "$PHASE" = continuation && touch ran']}
"#,
    );
    let (mut retry, run, new) = restored_retry(&bundle, "test");
    retry.arg("--handover");
    let before = super::workflow_run_list::snapshot(&run);
    let result = handover_refusal(signed_out(retry));
    assert_eq!(result["diagnostics"].as_array().unwrap().len(), 1);
    let diagnostic = &result["diagnostics"][0];
    assert_eq!(diagnostic["code"], "handover_execution_root_required");
    assert_eq!(
        diagnostic["location"],
        serde_json::json!({"kind": "execution_root_step", "id": "test"})
    );
    assert_eq!(attempt_count(&run), 1);
    assert_eq!(super::workflow_run_list::snapshot(&run), before);

    let home = new.with_file_name("home-b");
    let mut retry = run_command(
        &home,
        &[
            "retry",
            run.file_name().unwrap().to_str().unwrap(),
            "--from",
            "test",
            "--execution-root",
            new.to_str().unwrap(),
        ],
    );
    retry.env("PHASE", "continuation");
    assert_eq!(completed(&signed_out(retry))["attemptNumber"], 2);
    assert!(new.join("ran").is_file());
}

// SC-CONTINUE-16
#[test]
fn retry_rebuilds_the_restored_runs_workspace() {
    let bundle = TreeBundle::new(
        r#"schemaVersion: 1
environmentPassthrough: [PHASE, COUNTER]
steps:
  candidate:
    kind: cmd
    workspace: new
    command: {argv: [sh, -c, 'printf base > file.txt']}
  checkBase:
    kind: cmd
    workspace: read
    dependsOn: [candidate]
    command:
      argv:
        - sh
        - -ec
        - |
          test "$(cat file.txt)" = base
          echo "$PHASE" >> "$COUNTER"
          printf 'base-%s' "$PHASE" > base-result
    outputs:
      result: {kind: text, from: path, path: base-result}
  edit:
    kind: cmd
    dependsOn: [checkBase]
    command: {argv: [sh, -c, 'printf -- "-edited" >> file.txt']}
  checkEdit:
    kind: cmd
    workspace: read
    dependsOn: [edit]
    command:
      argv:
        - sh
        - -ec
        - |
          test "$(cat file.txt)" = base-edited
          printf 'edit-%s' "$PHASE" > edit-result
    outputs:
      result: {kind: text, from: path, path: edit-result}
  publish:
    kind: cmd
    dependsOn: [checkEdit]
    inputs:
      base: {ref: outputs.checkBase.result}
      edit: {ref: outputs.checkEdit.result}
    command:
      argv:
        - sh
        - -ec
        - |
          test "$(cat file.txt)" = base-edited
          test "$(cat "$USEFUL_STEP_INPUTS/values/base")" = base-initial
          test "$(cat "$USEFUL_STEP_INPUTS/values/edit")" = edit-continuation
          test "$PHASE" = continuation
"#,
    );
    let (output, workspace) = retry_after_move(&bundle, "publish");
    let terminal = completed(&output);
    assert_eq!(terminal["attemptNumber"], 2);
    assert_eq!(terminal["outcome"], "succeeded");
    let partition = &partition_event(&output)["continuation"];
    assert_eq!(
        partition["rebuiltWorkspaces"],
        serde_json::json!(["candidate"])
    );
    assert_eq!(
        partition["reexecutedSteps"],
        serde_json::json!(["candidate", "edit", "checkEdit", "publish"])
    );
    assert_eq!(
        partition["revalidatedSteps"],
        serde_json::json!(["checkBase"])
    );
    let steps = terminal["result"]["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 5);
    for step in steps {
        let expected = if step["id"] == "checkBase" {
            "inherited"
        } else {
            "succeeded"
        };
        assert_eq!(step["state"], expected, "{step}");
    }
    assert_eq!(
        fs::read_to_string(workspace.join("file.txt")).unwrap(),
        "base-edited"
    );
    let counter = bundle.execution_root().with_file_name("check-base-calls");
    assert_eq!(fs::read_to_string(counter).unwrap(), "initial\n");
}

// SC-CONTINUE-21
#[test]
fn retry_of_a_none_step_leaves_the_restored_workspace_absent() {
    let bundle = TreeBundle::new(
        r#"schemaVersion: 1
environmentPassthrough: [PHASE]
steps:
  candidate:
    kind: cmd
    workspace: new
    command: {argv: [sh, -c, 'printf base > file.txt']}
  notify:
    kind: cmd
    workspace: none
    dependsOn: [candidate]
    command: {argv: [sh, -c, 'test "$PHASE" = continuation']}
"#,
    );
    let (output, workspace) = retry_after_move(&bundle, "notify");
    let terminal = completed(&output);
    assert_eq!(terminal["attemptNumber"], 2);
    let steps = &terminal["result"]["steps"];
    assert_eq!(steps[0]["state"], "inherited");
    assert_eq!(steps[1]["state"], "succeeded");
    let partition = &partition_event(&output)["continuation"];
    assert_eq!(partition["reexecutedSteps"], serde_json::json!(["notify"]));
    assert!(partition.get("rebuiltWorkspaces").is_none());
    assert!(!workspace.exists());
}

enum BuildWorkspace {
    Checkout,
    AmendedCheckout,
    ExecutionRoot,
}

fn repair_tree(workspace: BuildWorkspace) -> TreeBundle {
    let bundle = TreeBundle::new(
        r#"schemaVersion: 1
environmentPassthrough: [PHASE, COUNTER]
outcomes: [landed, failed]
steps:
  design:
    kind: workflow
    workflow: design.yaml
    on: {planned: build, failed: exit.failed}
  build:
    kind: workflow
    workflow: build.yaml
    inputs:
      commit: {ref: outputs.design.commit}
    on: {built: exit.landed, failed: {wait: repair, then: build}}
exports:
  package: {ref: outputs.build.package}
"#,
    );
    bundle.write_source(
        "design.yaml",
        r#"schemaVersion: 1
environmentPassthrough: [PHASE, COUNTER]
outcomes: [planned, failed]
outcome: {from: outputs.plan.verdict, onFailure: failed}
steps:
  plan:
    kind: cmd
    workspace: none
    command:
      argv:
        - sh
        - -ec
        - |
          echo design >> "$COUNTER"
          printf abc123 > commit
          printf planned > verdict
    outputs:
      commit: {kind: text, from: path, path: commit}
      verdict: {kind: text, from: path, path: verdict}
exports:
  commit: {ref: outputs.plan.commit}
"#,
    );
    let build = r#"schemaVersion: 1
environmentPassthrough: [PHASE, COUNTER]
inputs:
  commit: {kind: text}
outcomes: [built, failed]
outcome: {from: outputs.package.verdict, onFailure: failed}
steps:
  prepare:
    kind: cmd
    workspace: new
    inputs:
      commit: {ref: inputs.commit}
    command:
      argv:
        - sh
        - -ec
        - |
          echo prepare >> "$COUNTER"
          cp "$USEFUL_STEP_INPUTS/values/commit" checkout.txt
  check:
    kind: cmd
    workspace: read
    dependsOn: [prepare]
    command:
      argv:
        - sh
        - -ec
        - |
          echo check >> "$COUNTER"
          test "$(cat checkout.txt)" = abc123
          printf "checked-%s" "$PHASE" > check-result
    outputs:
      result: {kind: text, from: path, path: check-result}
  package:
    kind: cmd
    dependsOn: [check]
    inputs:
      check: {ref: outputs.check.result}
    command:
      argv:
        - sh
        - -ec
        - |
          echo package >> "$COUNTER"
          test "$PHASE" = continuation
          printf "%s+%s" "$(cat checkout.txt)" "$(cat "$USEFUL_STEP_INPUTS/values/check")" > package.txt
          printf built > verdict
    outputs:
      package: {kind: text, from: path, path: package.txt}
      verdict: {kind: text, from: path, path: verdict}
exports:
  package: {ref: outputs.package.package}
"#;
    let build = match workspace {
        BuildWorkspace::Checkout => build.to_owned(),
        BuildWorkspace::AmendedCheckout => build
            .replace(
                "  check:\n",
                r#"  amend:
    kind: cmd
    dependsOn: [prepare]
    command: {argv: [sh, -ec, 'echo amend >> "$COUNTER"; touch amended.txt']}
  check:
"#,
            )
            .replace(
                "workspace: read\n    dependsOn: [prepare]",
                "workspace: read\n    dependsOn: [amend]",
            ),
        BuildWorkspace::ExecutionRoot => build
            .lines()
            .filter(|line| !line.starts_with("    workspace:"))
            .collect::<Vec<_>>()
            .join("\n"),
    };
    bundle.write_source("build.yaml", &build);
    bundle
}

fn restored_stage_retry(bundle: &TreeBundle) -> (Command, PathBuf, PathBuf, PathBuf) {
    let root = bundle.execution_root().parent().unwrap();
    let home = root.join("home-a");
    let counter = root.join("calls");
    let mut initial = path_command(bundle, &home);
    initial.env("PHASE", "initial").env("COUNTER", &counter);
    let waiting = completed(&signed_out(initial));
    assert_eq!(waiting["wait"]["kind"], "repair");
    assert_eq!(waiting["wait"]["payload"]["child"], "children/build/000001");
    let id = id(&waiting);
    let (other, new) = move_run(bundle, &home, id);
    let mut retry = run_command(
        &other,
        &["retry", id, "--execution-root", new.to_str().unwrap()],
    );
    retry.env("PHASE", "continuation").env("COUNTER", &counter);
    (retry, other.join("runs").join(id), new, counter)
}

fn retry_restored_stage(bundle: &TreeBundle) -> (PathBuf, PathBuf, String) {
    let (retry, restored, new, counter) = restored_stage_retry(bundle);
    chained(&signed_out(retry));
    assert_eq!(run_record(&restored)["outcome"], "landed");
    (restored, new, fs::read_to_string(counter).unwrap())
}

// SC-HANDOVER-1, SC-HANDOVER-7
#[test]
fn handover_judges_a_waiting_stage_by_its_child_workspaces() {
    let bundle = repair_tree(BuildWorkspace::ExecutionRoot);
    let (mut retry, run, _, _) = restored_stage_retry(&bundle);
    retry.arg("--handover");
    let result = handover_refusal(signed_out(retry));
    assert!(result["diagnostics"].as_array().unwrap().iter().any(|diagnostic|
        diagnostic["code"] == "handover_execution_root_required"
            && diagnostic["location"] == serde_json::json!({"kind": "execution_root_step", "id": "build", "child": "prepare"})
    ), "{result}");
    let build = run.join("children/build");
    assert_eq!(ordinals_of(&build), ["000001"]);
    assert_eq!(attempt_count(&build.join("000001")), 1);

    let bundle = repair_tree(BuildWorkspace::Checkout);
    let (mut retry, run, _, _) = restored_stage_retry(&bundle);
    retry.arg("--handover");
    chained(&signed_out(retry));
    assert_eq!(run_record(&run)["outcome"], "landed");
    let build = run.join("children/build");
    assert_eq!(ordinals_of(&build), ["000001"]);
    assert_eq!(attempt_count(&build.join("000001")), 2);
}

// SC-CONTINUE-18
#[test]
fn a_restored_stage_rebuilds_its_workspace_in_the_same_child() {
    let bundle = repair_tree(BuildWorkspace::Checkout);
    let (run, new, calls) = retry_restored_stage(&bundle);
    let build = run.join("children/build");
    assert_eq!(ordinals_of(&build), ["000001"], "{calls}");
    assert_eq!(calls, "design\nprepare\ncheck\npackage\nprepare\npackage\n");
    let child = build.join("000001");
    assert_eq!(attempt_count(&child), 2);
    let result = attempt_result(&child, 2);
    let continuation = &result["continuation"];
    assert_eq!(continuation["reason"], "retry");
    assert_eq!(
        continuation["rebuiltWorkspaces"],
        serde_json::json!(["prepare"])
    );
    assert_eq!(
        continuation["reexecutedSteps"],
        serde_json::json!(["prepare", "package"])
    );
    assert_eq!(
        continuation["revalidatedSteps"],
        serde_json::json!(["check"])
    );
    assert_eq!(
        step_states(&result),
        states(&[
            ("prepare", "succeeded"),
            ("check", "inherited"),
            ("package", "succeeded")
        ])
    );
    assert_eq!(
        fs::read_to_string(run.join("attempts/000002/result/exports/0001")).unwrap(),
        "abc123+checked-initial"
    );
    assert_eq!(fs::read_dir(new).unwrap().count(), 0);
}

// SC-CONTINUE-22
#[test]
fn a_restored_stage_rechecks_a_replayed_write() {
    let bundle = repair_tree(BuildWorkspace::AmendedCheckout);
    let (run, _, calls) = retry_restored_stage(&bundle);
    let build = run.join("children/build");
    assert_eq!(ordinals_of(&build), ["000001"]);
    assert_eq!(attempt_count(&build.join("000001")), 2);
    assert_eq!(
        calls,
        "design\nprepare\namend\ncheck\npackage\nprepare\namend\ncheck\npackage\n"
    );
}

// SC-CONTINUE-23
#[test]
fn a_restored_stage_using_the_execution_root_starts_a_new_child() {
    let bundle = repair_tree(BuildWorkspace::ExecutionRoot);
    let (run, _, _) = retry_restored_stage(&bundle);
    let build = run.join("children/build");
    assert_eq!(ordinals_of(&build), ["000001", "000002"]);
    assert_eq!(attempt_count(&build.join("000001")), 1);
}

// SC-RECORD-2
#[test]
fn retry_restores_binary_outputs_from_the_prior_attempt() {
    let bundle = binary_output_tree();
    let home = bundle.execution_root().parent().unwrap().join("home-a");
    let failed = signed_out(path_command(&bundle, &home));
    assert_eq!(failed.status.code(), Some(1), "{failed:?}");
    let terminal: Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(terminal["outcome"], "failed", "{terminal}");
    let id = id(&terminal);
    let (other, new) = move_run(&bundle, &home, id);
    let unavailable = run(&other, &["retry", id, "--from", "second"]);
    assert_eq!(unavailable.status.code(), Some(1));
    let refusal: Value = serde_json::from_slice(&unavailable.stdout).unwrap();
    assert_eq!(
        refusal["diagnostics"][0]["code"], "execution_root_unavailable",
        "{refusal}"
    );
    fs::write(new.join("ready"), "").unwrap();
    let retried = completed(&run(
        &other,
        &[
            "retry",
            id,
            "--from",
            "second",
            "--execution-root",
            new.to_str().unwrap(),
        ],
    ));
    assert_eq!(retried["attemptNumber"], 2);
    let status = success(run(&other, &["show", id]));
    let first = &status["state"]["attempts"][1]["progress"]["steps"][0];
    assert_eq!(first["state"], "inherited");
    assert_eq!(first["outputs"][0]["producer"]["attemptNumber"], 1);
    check_binary_copy(&new);
}

fn hold_second_step(bundle: &TreeBundle, home: &Path) -> LiveRun {
    let root = bundle.execution_root();
    fs::write(root.join("hold"), "").unwrap();
    let live = LiveRun {
        process: path_command(bundle, home)
            .env("USEFUL_CREDENTIALS_FILE", home.join("empty-credentials"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
        release: root.join("release"),
    };
    super::poll_until(
        "second to be held",
        || root.join("held").exists(),
        |ready| *ready,
    );
    live
}

// SC-RECORD-6
#[test]
fn resume_settles_the_restored_abandoned_attempt() {
    use rustix::process::Signal;
    let bundle = binary_output_tree();
    let home = bundle.execution_root().parent().unwrap().join("home-a");
    let mut live = hold_second_step(&bundle, &home);
    assert!(!live.signal(Signal::KILL).status.success());
    drop(live);
    let list = success(run(&home, &["list"]));
    let id = list["runs"][0]["id"].as_str().unwrap();
    let (other, new) = move_run(&bundle, &home, id);
    check_resumed_second_step(&other, &new, id);
}

fn check_resumed_second_step(other: &Path, new: &Path, id: &str) {
    let status = success(run(other, &["show", id]));
    assert_eq!(status["recovery"]["status"], "abandoned");
    let unavailable = run(other, &["resume", id]);
    assert_eq!(unavailable.status.code(), Some(1));
    let refusal: Value = serde_json::from_slice(&unavailable.stdout).unwrap();
    assert_eq!(
        refusal["diagnostics"][0]["code"], "execution_root_unavailable",
        "{refusal}"
    );
    let after_refusal = success(run(other, &["show", id]));
    assert_eq!(after_refusal["recovery"]["status"], "abandoned");
    assert_eq!(
        after_refusal["state"]["attempts"][0],
        status["state"]["attempts"][0]
    );
    fs::write(new.join("ready"), "").unwrap();
    let resumed = completed(&run(
        other,
        &["resume", id, "--execution-root", new.to_str().unwrap()],
    ));
    assert_eq!(resumed["attemptNumber"], 2);
    let status = success(run(other, &["show", id]));
    assert_eq!(status["state"]["attempts"][0]["state"], "interrupted");
    check_binary_copy(new);
}

// SC-RECORD-3
#[test]
fn retry_preserves_the_number_of_hand_backs() {
    let bundle = loop_tree();
    bundle.write_source(
        "workflow.yaml",
        r#"schemaVersion: 1
programs: [bin]
outcomes: [landed, failed]
steps:
  review:
    kind: workflow
    workflow: review.yaml
    on:
      proceed: exit.landed
      hand_back: {then: fix, limit: 2, else: {wait: repair, then: review}}
      failed: exit.failed
  fix:
    kind: workflow
    workflow: fix.yaml
    inputs:
      findings: {ref: outputs.review.findings}
    on:
      built: review
      failed: {wait: repair, then: fix}
"#,
    );
    let home = bundle.execution_root().parent().unwrap().join("home-a");
    decide_each(&bundle, "review", &["hand_back", "hand_back"]);
    decide_each(&bundle, "fix", &["built", "failed"]);
    let documents = chained(&signed_out(path_command(&bundle, &home)));
    let terminal = documents.last().unwrap();
    let id = id(terminal);
    assert_eq!(terminal["wait"]["step"], serde_json::json!(["fix"]));
    let edges = serde_json::json!({"review.hand_back": 2});
    assert_eq!(success(run(&home, &["show", id]))["record"]["edges"], edges);
    let (other, new) = move_run(&bundle, &home, id);
    // A sentinel at the tail of each queue proves each child ran exactly once.
    fs::write(new.join("verdicts-fix"), "built\nfailed\n").unwrap();
    fs::write(new.join("verdicts-review"), "hand_back\nproceed\n").unwrap();
    fs::write(new.join("findings.txt"), "again").unwrap();
    let documents = chained(&run(
        &other,
        &["retry", id, "--execution-root", new.to_str().unwrap()],
    ));
    let wait = &documents.last().unwrap()["wait"];
    assert_eq!(wait["kind"], "repair");
    assert_eq!(wait["step"], serde_json::json!(["review"]));
    assert_eq!(
        success(run(&other, &["show", id]))["record"]["edges"],
        edges
    );
    assert_eq!(
        fs::read_to_string(new.join("verdicts-fix")).unwrap(),
        "failed\n"
    );
    assert_eq!(
        fs::read_to_string(new.join("verdicts-review")).unwrap(),
        "proceed\n"
    );
}

// SC-RECORD-4
#[test]
fn answer_resolves_the_restored_design_wait() {
    let bundle = wait_tree();
    let home = bundle.execution_root().parent().unwrap().join("home-a");
    decide(&bundle, "design", "blocked");
    let terminal = path_run(&bundle, &home);
    let id = id(&terminal);
    let wait = &terminal["wait"];
    assert_eq!(wait["kind"], "answer");
    assert_eq!(wait["payload"]["questions"], "1. keep the cache?");
    let (other, new) = move_run(&bundle, &home, id);
    assert_eq!(&success(run(&other, &["show", id]))["wait"], wait);
    success(run(
        &other,
        &["answer", id, "--text", "keep it", "--record-only"],
    ));
    fs::write(new.join("questions.txt"), "").unwrap();
    fs::write(new.join("verdict-design"), "planned").unwrap();
    fs::write(new.join("verdict-review"), "approve").unwrap();
    let resumed = completed(&run(
        &other,
        &["resume", id, "--execution-root", new.to_str().unwrap()],
    ));
    assert_eq!(resumed["attemptNumber"], 2);
    assert_eq!(
        resumed["result"]["continuation"]["fromSteps"],
        serde_json::json!(["design"])
    );
    assert_eq!(resumed["wait"]["kind"], "approval");
    assert_eq!(
        read_json(&new.join("seen-answers")),
        serde_json::json!({"1": "keep it"})
    );
}

// SC-RECORD-5
#[test]
fn retry_continues_the_fan_out_and_reads_the_finished_childs_export() {
    let bundle = TreeBundle::new(
        r#"schemaVersion: 1
inputs:
  parts: {kind: json}
outcomes: [landed, failed]
steps:
  plan:
    kind: workflow
    workflow: plan.yaml
    on: {planned: design, failed: exit.failed}
  design:
    kind: workflow
    workflow: design.yaml
    forEach: inputs.parts
    inputs:
      part: {ref: item.name}
    on: {built: merge, failed: {wait: repair, then: design}}
  merge:
    kind: workflow
    workflow: merge.yaml
    inputs:
      note: {ref: outputs.plan.note}
    on: {landed: exit.landed, failed: exit.failed}
"#,
    );
    bundle.write_source("plan.yaml", r#"schemaVersion: 1
outcomes: [planned, failed]
outcome: {from: outputs.plan.verdict, onFailure: failed}
steps:
  plan:
    kind: cmd
    command: {argv: [sh, -c, 'echo plan >> calls && cp note-input note && printf planned > verdict']}
    outputs:
      note: {kind: text, from: path, path: note}
      verdict: {kind: text, from: path, path: verdict}
exports:
  note: {ref: outputs.plan.note}
"#);
    bundle.write_source("design.yaml", r#"schemaVersion: 1
inputs:
  part: {kind: text}
outcomes: [built, failed]
outcome: {from: outputs.design.verdict, onFailure: failed}
steps:
  design:
    kind: cmd
    inputs:
      part: {ref: inputs.part}
    command:
      argv: [sh, -c, 'part=$(cat "$USEFUL_STEP_INPUTS/values/part") && echo "$part" >> calls && cat "verdict-$part" > verdict']
    outputs:
      verdict: {kind: text, from: path, path: verdict}
"#);
    bundle.write_source("merge.yaml", r#"schemaVersion: 1
inputs:
  note: {kind: text}
outcomes: [landed, failed]
outcome: {from: outputs.merge.verdict, onFailure: failed}
steps:
  merge:
    kind: cmd
    inputs:
      note: {ref: inputs.note}
    command:
      argv: [sh, -c, 'echo merge >> calls && cp "$USEFUL_STEP_INPUTS/values/note" received && printf landed > verdict']
    outputs:
      verdict: {kind: text, from: path, path: verdict}
"#);
    let root = bundle.execution_root();
    let home = root.parent().unwrap().join("home-a");
    let note = "written on A";
    fs::write(root.join("note-input"), note).unwrap();
    fs::write(root.join("verdict-a"), "built").unwrap();
    fs::write(root.join("verdict-b"), "failed").unwrap();
    let mut command = path_command(&bundle, &home);
    command.args([
        "--input-json",
        "parts",
        r#"[{"name":"a"},{"name":"b"},{"name":"c"}]"#,
    ]);
    let terminal = completed(&signed_out(command));
    let id = id(&terminal);
    assert_eq!(terminal["wait"]["kind"], "repair");
    assert_eq!(
        terminal["wait"]["step"],
        serde_json::json!(["design", {"item": 2}])
    );
    assert_eq!(
        fs::read_to_string(root.join("calls")).unwrap(),
        "plan\na\nb\n"
    );
    let (other, new) = move_run(&bundle, &home, id);
    fs::write(new.join("verdict-b"), "built").unwrap();
    fs::write(new.join("verdict-c"), "built").unwrap();
    completed(&run(
        &other,
        &["retry", id, "--execution-root", new.to_str().unwrap()],
    ));
    let status = success(run(&other, &["show", id]));
    assert_eq!(status["record"]["outcome"], "landed");
    assert_eq!(
        fs::read_to_string(new.join("calls")).unwrap(),
        "b\nc\nmerge\n"
    );
    assert_eq!(fs::read_to_string(new.join("received")).unwrap(), note);
}

#[derive(Clone, Copy, PartialEq)]
enum RecordResponse {
    Kept,
    Altered,
    Expiring,
    Absent,
    Gone,
}

#[expect(
    clippy::disallowed_methods,
    reason = "the mock download server issues and expires links against the CLI process's wall clock"
)]
fn server_now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

/// Answer each request by route, with the same record layout the CLI wrote to disk.
fn cloud_download(record: &Path, destination: &Path, response: RecordResponse) -> (Output, usize) {
    use super::run_command::{ORGANIZATION, RUN_ID, TOKEN, hex_digest};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::io::Write as _;
    use std::net::{TcpListener, TcpStream};

    let manifest = fs::read(record.join("record.json")).unwrap();
    let manifest_sha = hex_digest(&manifest);
    let index: Value = serde_json::from_slice(&manifest).unwrap();
    let mut files = BTreeMap::new();
    let mut count = 0;
    let mut total = 0;
    for entry in index["entries"].as_array().unwrap() {
        if let Some(sha) = entry["sha256"].as_str() {
            let bytes = fs::read(record.join("run").join(entry["path"].as_str().unwrap())).unwrap();
            count += 1;
            total += bytes.len();
            files.insert(sha.to_owned(), bytes);
        }
    }
    let facts = json!({
        "runId": RUN_ID, "engineRunId": index["run"], "attemptNumber": 2, "sequence": 7,
        "storedAt": "2026-09-15T12:00:00Z", "expiresAt": null,
        "fileCount": count, "totalSizeBytes": total,
        "manifest": {"sha256": manifest_sha, "sizeBytes": manifest.len()}
    });
    files.insert(manifest_sha.clone(), manifest);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let api_url = format!("http://{address}/api");
    let credentials = super::private_credential_directory();
    let path = credentials.path().join("credentials.json");
    super::write_credential_fixture(&path, &api_url, TOKEN, "2999-01-01T00:00:00Z");
    let endpoint = format!("/api/v1/organizations/{ORGANIZATION}/runs/{RUN_ID}/record");
    let server = std::thread::spawn(move || {
        let mut requests = 0;
        // Under `Expiring`, the first two requests for the listed files answer links that
        // expire while their first file is in transit.
        let mut asked = Vec::new();
        let mut held = None;
        let private = |value: &Value| {
            super::http_response_with_headers(
                "200 OK",
                Some("application/json"),
                &[("Cache-Control", "private, no-store")],
                &serde_json::to_vec(value).unwrap(),
            )
        };
        loop {
            let (mut stream, _) = listener.accept().unwrap();
            let mut first = [0_u8];
            if stream.peek(&mut first).unwrap() == 0 {
                break;
            }
            let raw = useful_test_support::read_request(&mut stream);
            let (header, body) = useful_test_support::split_request(&raw).unwrap();
            let header = std::str::from_utf8(header).unwrap();
            let mut line = header.split_ascii_whitespace();
            let method = line.next().unwrap();
            let route = line.next().unwrap();
            requests += 1;
            let bytes = if method == "GET" && route == endpoint {
                match response {
                    RecordResponse::Absent | RecordResponse::Gone => {
                        let (status, code, slug) = if response == RecordResponse::Absent {
                            ("404 Not Found", 404, "run-record-absent")
                        } else {
                            ("410 Gone", 410, "run-record-gone")
                        };
                        super::problem_http_response(
                            status,
                            json!({"status": code, "title": slug,
                            "type": format!("https://api.usefulmachinery.com/problems/{slug}")}),
                        )
                    }
                    _ => private(&facts),
                }
            } else if method == "POST" && route == format!("{endpoint}/download-capabilities") {
                let request: Value = serde_json::from_slice(body).unwrap();
                let requested = request["files"].as_array().unwrap();
                assert!((1..=100).contains(&requested.len()));
                if requests == 2 {
                    assert_eq!(requested, &[json!(manifest_sha)]);
                }
                let links: Vec<_> = requested
                    .iter()
                    .map(|sha| {
                        let sha = sha.as_str().unwrap();
                        json!({"sha256": sha, "sizeBytes": files[sha].len(),
                        "url": format!("http://{address}/objects/{sha}?signed=yes")})
                    })
                    .collect();
                let mut expiry = "2999-01-01T00:00:00Z".to_owned();
                if response == RecordResponse::Expiring && requests > 2 {
                    asked.push(requested.len());
                    if asked.len() <= 2 {
                        let soon = (server_now() + time::Duration::seconds(2))
                            .replace_nanosecond(0)
                            .unwrap();
                        expiry = soon
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap();
                        held = Some(soon);
                    }
                }
                private(&json!({"capabilityExpiresAt": expiry, "files": links}))
            } else {
                assert_eq!(method, "GET");
                assert!(useful_test_support::request_header(header, "authorization").is_none());
                let sha = route
                    .strip_prefix("/objects/")
                    .unwrap()
                    .strip_suffix("?signed=yes")
                    .unwrap();
                if let Some(expiry) = held.take() {
                    while server_now() <= expiry {
                        super::sleep(std::time::Duration::from_millis(20));
                    }
                }
                let mut bytes = files[sha].clone();
                if response == RecordResponse::Altered && sha != manifest_sha && !bytes.is_empty() {
                    bytes[0] ^= 1;
                }
                super::http_response("200 OK", Some("application/octet-stream"), &bytes)
            };
            stream.write_all(&bytes).unwrap();
        }
        if response == RecordResponse::Expiring {
            let listed = files.len() - 1;
            assert!((3..=100).contains(&listed), "{listed} files");
            assert_eq!(asked, [listed, listed - 1, listed - 2]);
        }
        requests
    });
    let output = super::run_with_env(
        &[
            "workflow",
            "run",
            "record",
            "download",
            RUN_ID,
            "--org",
            ORGANIZATION,
            "--output",
            destination.to_str().unwrap(),
            "--json",
            "--allow-insecure-http",
        ],
        &super::deployment_environment(&api_url, path.to_str().unwrap()),
    );
    drop(TcpStream::connect(address).unwrap());
    (output, server.join().unwrap())
}

#[test]
fn download_writes_a_record_that_restores_as_the_source_showed() {
    let bundle = wait_tree();
    let root = bundle
        .execution_root()
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap();
    let home = root.join("home-a");
    let other = root.join("home-b");
    decide(&bundle, "design", "blocked");
    let terminal = path_run(&bundle, &home);
    let id = id(&terminal);
    let record = root.join("record");
    let created = success(create(&home, id, &record));
    let destination = root.join("download");
    let (output, _) = cloud_download(&record, &destination, RecordResponse::Kept);
    let result = success(output);
    assert_eq!(result["outcome"], "downloaded");
    assert_eq!(result["runId"], super::run_command::RUN_ID);
    assert_eq!(result["engineRunId"], id);
    assert_eq!(result["destination"], destination.to_str().unwrap());
    assert_eq!(result["attemptNumber"], 2);
    assert_eq!(result["sequence"], 7);
    assert_eq!(result["fileCount"], created["files"]);
    assert_eq!(result["totalSizeBytes"], created["bytes"]);
    success(restore(&other, &destination));
    let show = |path: &Path| {
        success(run(path, &["show", id]))
            .to_string()
            .replace(path.to_str().unwrap(), "HOME")
    };
    assert_eq!(show(&home), show(&other));
}

#[test]
fn download_asks_again_for_the_files_left_each_time_links_expire() {
    let bundle = wait_tree();
    let root = bundle.execution_root().parent().unwrap();
    let home = root.join("home");
    decide(&bundle, "design", "blocked");
    let terminal = path_run(&bundle, &home);
    let record = root.join("record");
    let created = success(create(&home, id(&terminal), &record));
    let destination = root.join("download");
    let (output, _) = cloud_download(&record, &destination, RecordResponse::Expiring);
    let result = success(output);
    assert_eq!(result["outcome"], "downloaded");
    assert_eq!(result["fileCount"], created["files"]);
}

#[test]
fn download_refusals_leave_nothing_behind() {
    let bundle = wait_tree();
    let root = bundle.execution_root().parent().unwrap();
    let home = root.join("home");
    decide(&bundle, "design", "blocked");
    let terminal = path_run(&bundle, &home);
    let record = root.join("record");
    success(create(&home, id(&terminal), &record));
    let parent = tempfile::tempdir().unwrap();
    let existing = parent.path().join("existing");
    fs::write(&existing, b"preserve").unwrap();
    for (response, relative, outcome, local) in [
        (
            RecordResponse::Altered,
            "download",
            "integrity_mismatch",
            false,
        ),
        (RecordResponse::Absent, "download", "record_absent", false),
        (RecordResponse::Gone, "download", "record_gone", false),
        (RecordResponse::Kept, "existing", "destination_exists", true),
        (
            RecordResponse::Kept,
            "missing/download",
            "invalid_destination",
            true,
        ),
    ] {
        let destination = parent.path().join(relative);
        let (output, requests) = cloud_download(&record, &destination, response);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["outcome"], outcome, "{result}");
        assert_eq!(result["destination"], destination.to_str().unwrap());
        assert_eq!(requests == 0, local);
        let entries: Vec<_> = fs::read_dir(parent.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(entries, std::slice::from_ref(&existing));
        assert_eq!(fs::read(&existing).unwrap(), b"preserve");
    }
}
