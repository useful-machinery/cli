use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use serde_json::{Value, json};

use super::poll_until;
use super::run_command::{ORGANIZATION, PROJECT_ID, RUN_ID, prepared_run};
use super::workflow_continue::{chained, completed, decide, decide_each, loop_tree, read_json};
use super::workflow_definition::Home;
use super::workflow_run::{isolated_command, run_record};
use super::workflow_run_control::{LiveRun, OPERATOR, PublishedWaitTree, run_control};
use super::workflow_status::signed_out;
use super::{
    deployment_environment, http_response_with_headers, private_credential_directory, run_with_env,
};

/// `useful workflow run list ARGS` as `OPERATOR` against `home`.
fn list(home: &Home, args: &[&str]) -> Output {
    list_at(Path::new(home.path()), args)
}

/// `useful workflow run list ARGS` as `OPERATOR` against the home at `home`, as that path spells
/// it, with nobody signed in.
fn list_at(home: &Path, args: &[&str]) -> Output {
    let mut command = isolated_command(
        &["workflow", "run", "list"]
            .into_iter()
            .chain(args.iter().copied())
            .map(str::to_owned)
            .collect::<Vec<_>>(),
    );
    command.env("USEFUL_HOME", home).env("USER", OPERATOR);
    signed_out(command)
}

/// The `useful workflow run list ARGS --json` document, checked: with nobody signed in each row
/// is a local run and Cloud was not asked.
fn document(home: &Home, args: &[&str]) -> Value {
    let output = list(home, &[args, &["--json"]].concat());
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["schemaVersion"], 1, "{document}");
    assert_eq!(document["command"], "useful workflow run list");
    assert_eq!(document["cloud"]["asked"], false, "{document}");
    for run in document["runs"].as_array().unwrap() {
        assert_eq!(run["on"], "local", "{run}");
    }
    document
}

/// The runs `useful workflow run list ARGS --json` lists.
fn listed(home: &Home, args: &[&str]) -> Vec<Value> {
    document(home, args)["runs"].as_array().unwrap().clone()
}

/// The ids `useful workflow run list ARGS --json` lists and the exited runs it says it left
/// out.
fn selected(home: &Home, args: &[&str]) -> (Vec<String>, u64) {
    let document = document(home, args);
    let ids = ids(document["runs"].as_array().unwrap())
        .into_iter()
        .map(str::to_owned)
        .collect();
    (ids, document["exitedHidden"].as_u64().unwrap())
}

/// `useful workflow run list ARGS`'s plain output, which exits 0.
fn plain(home: &Home, args: &[&str]) -> String {
    let output = list(home, args);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

fn ids(runs: &[Value]) -> Vec<&str> {
    runs.iter().map(|run| run["id"].as_str().unwrap()).collect()
}

/// The questions `design` asks, so one answer leaves the wait open.
fn two_questions() -> Value {
    json!([
        {"id": "q1", "text": "keep the cache?"},
        {"id": "q2", "text": "name?"},
    ])
}

// `list` lists the live runs under the home in id order with their record and wait and counts the
// exited runs it left out, `--all` lists every run, the filters select in memory, and an unreadable
// entry is named on stderr.
#[test]
fn list_shows_the_live_runs_or_with_all_every_run() {
    let published = PublishedWaitTree::with_json_questions(&two_questions());
    let home = Some(&published.home);
    decide(&published.bundle, "review", "approve");
    decide(&published.bundle, "merge", "landed");
    let (waiting, waiting_id, terminal) = published.run("blocked");
    let wait = terminal["wait"].clone();
    assert_eq!(wait["kind"], "answer", "{terminal}");

    let (landed, landed_id, terminal) = published.run("planned");
    assert_eq!(terminal["wait"]["kind"], "approval", "{terminal}");
    completed(&run_control(home, "approve", &landed_id, &[]));
    assert_eq!(run_record(&landed)["outcome"], "landed");

    let (withdrawn, withdrawn_id, _) = published.run("blocked");
    let output = run_control(home, "cancel", &withdrawn_id, &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");

    // A run whose `design` holds its step reads `running` while its process lives.
    let execution = published.bundle.execution_root();
    fs::write(execution.join("hold-design"), "").unwrap();
    let mut live = LiveRun {
        process: published
            .create_command(&published.definition, &[])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        release: execution.join("release-design"),
    };
    poll_until(
        "the running run's held step",
        || execution.join("held-design").exists(),
        |held| *held,
    );
    let runs_directory = PathBuf::from(published.home.path())
        .join("workflows")
        .join(&published.definition)
        .join("runs");
    let running_id = fs::read_dir(&runs_directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .find(|id| ![&waiting_id, &landed_id, &withdrawn_id].contains(&id))
        .unwrap();
    let running = fs::canonicalize(runs_directory.join(&running_id)).unwrap();
    assert_eq!(run_record(&running)["state"], "running");

    let mut live_ids = vec![waiting_id.clone(), running_id.clone()];
    live_ids.sort_unstable();
    let mut every = vec![
        waiting_id.clone(),
        landed_id.clone(),
        withdrawn_id.clone(),
        running_id.clone(),
    ];
    every.sort_unstable();
    let home = &published.home;
    assert_eq!(selected(home, &[]), (live_ids.clone(), 2));
    assert_eq!(selected(home, &["--all"]), (every.clone(), 0));

    let runs = listed(home, &["--all"]);
    for (run, directory) in [
        (&waiting_id, &waiting),
        (&landed_id, &landed),
        (&withdrawn_id, &withdrawn),
        (&running_id, &running),
    ] {
        let listed = runs.iter().find(|listed| listed["id"] == **run).unwrap();
        let record = run_record(directory);
        assert_eq!(listed["directory"], directory.to_str().unwrap());
        for (field, member) in [
            ("definition", "definition"),
            ("revision", "revision"),
            ("workflow", "workflow"),
            ("owner", "owner"),
            ("state", "state"),
            ("outcome", "outcome"),
            ("attempts", "attempts"),
            ("startedAt", "startedAt"),
        ] {
            assert_eq!(listed[field], record[member], "{field}: {listed}");
        }
        assert_eq!(listed["definition"], published.definition.as_str());
        assert_eq!(listed["owner"], OPERATOR);
    }
    // A home spelled through a symbolic link lists each run by the same resolved directory,
    // whatever `TMPDIR` the suite runs under.
    let alias = tempfile::tempdir().unwrap();
    let aliased = alias.path().join("home");
    symlink(home.path(), &aliased).unwrap();
    let output = list_at(&aliased, &["--all", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let through_alias: Value = serde_json::from_slice(&output.stdout).unwrap();
    let directories = |runs: &[Value]| {
        runs.iter()
            .map(|run| (run["id"].clone(), run["directory"].clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        directories(through_alias["runs"].as_array().unwrap()),
        directories(&runs),
        "{through_alias}"
    );
    let entry = |id: &str| runs.iter().find(|run| run["id"] == id).unwrap();
    let waiting_entry = entry(&waiting_id);
    assert_eq!(waiting_entry["state"], "waiting");
    assert_eq!(waiting_entry["position"], "design");
    assert_eq!(
        waiting_entry["wait"],
        json!({"kind": "answer", "since": wait["since"], "step": ["design"]})
    );
    assert_eq!(entry(&running_id)["state"], "running");
    assert_eq!(entry(&running_id)["wait"], Value::Null);
    for other in [&landed_id, &withdrawn_id] {
        let entry = entry(other);
        assert_eq!(entry["state"], "exited", "{entry}");
        assert_eq!(entry["position"], Value::Null, "{entry}");
        assert_eq!(entry["wait"], Value::Null, "{entry}");
    }
    assert_eq!(entry(&landed_id)["outcome"], "landed");

    assert_eq!(
        selected(home, &["--waiting"]),
        (vec![waiting_id.clone()], 0)
    );
    for filter in [
        ["--owner", "me"],
        ["--owner", OPERATOR],
        ["--definition", published.definition.as_str()],
    ] {
        assert_eq!(selected(home, &filter), (live_ids.clone(), 2), "{filter:?}");
        assert_eq!(
            selected(home, &[&filter[..], &["--all"]].concat()),
            (every.clone(), 0),
            "{filter:?}"
        );
    }
    assert_eq!(selected(home, &["--owner", "nobody"]), (vec![], 0));
    assert_eq!(
        selected(home, &["--definition", "def_7zzzzzzzzzzzzzzzzzzzzzzzzz"]),
        (vec![], 0)
    );
    for flag in ["--waiting", "--drift"] {
        let output = list(home, &["--all", flag]);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
    }

    let output = plain(home, &[]);
    let lines = output.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 4, "{output}");
    for (line, id) in lines.iter().zip(&live_ids) {
        assert!(line.starts_with(&format!("local · {id}")), "{output}");
    }
    assert_eq!(
        lines[2..],
        ["", "2 exited runs hidden. Pass --all to list every run."],
        "{output}"
    );
    let output = plain(home, &["--all"]);
    let lines = output.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 4, "{output}");
    for (line, id) in lines.iter().zip(&every) {
        assert!(line.starts_with(&format!("local · {id}")), "{output}");
    }

    // An entry under `runs/` without a run record is named on stderr and omitted.
    let stray = runs_directory.join("run_00000000000000000000000000");
    fs::create_dir(&stray).unwrap();
    let output = list(home, &["--all", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        ids(document["runs"].as_array().unwrap()),
        every,
        "{document}"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains(&format!("! {}: run_record_missing", stray.display())),
        "{stderr}"
    );
    fs::remove_dir(&stray).unwrap();

    // With the live runs ended, the listing has no run and says how many it left out.
    let output = run_control(Some(home), "cancel", &running_id, &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    poll_until(
        "the canceled run's process exit",
        || live.process.try_wait().unwrap(),
        Option::is_some,
    );
    let output = run_control(Some(home), "cancel", &waiting_id, &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(selected(home, &[]), (vec![], 4));
    assert_eq!(
        plain(home, &[]),
        "No live workflow runs.\n\n4 exited runs hidden. Pass --all to list every run.\n"
    );

    let empty = Home::new();
    assert_eq!(plain(&empty, &[]), "No live workflow runs.\n");
    assert_eq!(plain(&empty, &["--all"]), "No workflow runs.\n");
    assert_eq!(selected(&empty, &[]), (vec![], 0));
    assert_eq!(selected(&empty, &["--all"]), (vec![], 0));
}

// Each run lists its subject, the one exited run is counted as hidden, and `--drift` keeps
// the live runs behind their definition's current revision, each with that revision.
#[test]
fn list_shows_the_subject_and_the_drifted_runs() {
    let published = PublishedWaitTree::with_subject();
    let home = &published.home;
    let (_, behind) = published.waiting_for(&published.definition, "AUTO-1");
    let (_, exited) = published.waiting_for(&published.definition, "AUTO-2");
    let output = run_control(Some(home), "cancel", &exited, &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");

    let runs = listed(home, &[]);
    let entry = runs.iter().find(|run| run["id"] == *behind).unwrap();
    assert_eq!(entry["subject"], "AUTO-1", "{entry}");
    assert!(entry.get("current").is_none(), "{entry}");
    let plain = list(home, &[]);
    assert_eq!(plain.status.code(), Some(0), "{plain:?}");
    let plain = String::from_utf8(plain.stdout).unwrap();
    let line = plain
        .lines()
        .find(|line| line.starts_with(&format!("local · {behind}")))
        .unwrap_or_else(|| panic!("{plain}"));
    assert!(
        line.starts_with(&format!(
            "local · {behind} · {}@1 · AUTO-1 · waiting",
            published.definition
        )),
        "{plain}"
    );
    assert_eq!(
        plain.lines().last(),
        Some("1 exited run hidden. Pass --all to list every run."),
        "{plain}"
    );
    assert!(listed(home, &["--drift"]).is_empty());

    let second = published.republish(&[]);
    assert_eq!(second["revision"]["n"], 2, "{second}");
    let (_, current) = published.waiting_for(&published.definition, "AUTO-3");
    assert_eq!(ids(&listed(home, &[])).len(), 2);
    assert_eq!(ids(&listed(home, &["--all"])).len(), 3);

    let drifted = listed(home, &["--drift"]);
    assert_eq!(ids(&drifted), [behind.as_str()], "{drifted:?}");
    assert_eq!(drifted[0]["revision"], 1);
    assert_eq!(drifted[0]["current"], 2);
    assert_eq!(drifted[0]["subject"], "AUTO-1");
    assert!(!ids(&drifted).contains(&current.as_str()));
    let plain = list(home, &["--drift"]);
    assert_eq!(plain.status.code(), Some(0), "{plain:?}");
    let plain = String::from_utf8(plain.stdout).unwrap();
    let lines = plain.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 1, "{plain}");
    assert!(
        lines[0].starts_with(&format!("local · {behind}")),
        "{plain}"
    );
    assert!(lines[0].ends_with(" · current 2"), "{plain}");

    // A definition whose record cannot be read is named on stderr and its runs omitted.
    let record = PathBuf::from(home.path())
        .join("workflows")
        .join(&published.definition)
        .join("definition.json");
    fs::write(&record, "{}").unwrap();
    let output = list(home, &["--drift", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["runs"], json!([]), "{document}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains(&format!(
            "! {}: definition_record_invalid",
            record.parent().unwrap().display()
        )),
        "{stderr}"
    );
}

/// Every path under `directory` with its size and modification time.
pub(super) fn snapshot(directory: &Path) -> Vec<(PathBuf, u64, std::time::SystemTime)> {
    let mut entries = Vec::new();
    let mut pending = vec![directory.to_owned()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap();
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            if metadata.is_dir() {
                pending.push(entry.path());
            }
            entries.push((entry.path(), metadata.len(), metadata.modified().unwrap()));
        }
    }
    entries.sort();
    entries
}

fn shown(home: &PublishedWaitTree, run: impl AsRef<std::ffi::OsStr>) -> Value {
    let output = run_control(Some(&home.home), "show", run, &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["schemaVersion"], 1, "{document}");
    assert_eq!(document["command"], "useful workflow run show");
    assert_eq!(document["outcome"], "shown");
    assert_eq!(document["exitStatus"], 0);
    document
}

// `show` prints one run's record, position, wait, attempts, children and controls without taking
// its lock or changing its directory.
#[test]
fn show_prints_a_run_with_its_children_and_controls() {
    let published = PublishedWaitTree::with_json_questions(&two_questions());
    let (run, id, terminal) = published.run("blocked");
    let wait = terminal["wait"].clone();

    let before = snapshot(&run);
    let document = shown(&published, &id);
    assert_eq!(document["controls"], json!([]));
    assert!(!run.join("controls").exists());
    assert_eq!(snapshot(&run), before);

    let home = Some(&published.home);
    let stop = run_control(
        home,
        "pause",
        &id,
        &["--before", "review", "--reason", "hold"],
    );
    assert_eq!(stop.status.code(), Some(0), "{stop:?}");
    let answer = run_control(home, "answer", &id, &["--question", "q1", "--text", "yes"]);
    assert_eq!(answer.status.code(), Some(0), "{answer:?}");

    let before = snapshot(&run);
    let document = shown(&published, &id);
    assert_eq!(snapshot(&run), before);
    assert_eq!(document["runDirectory"], run.to_str().unwrap());
    assert_eq!(document["record"], run_record(&run));
    // The record's position names the step whose child last started.
    assert_eq!(document["record"]["position"], json!(["design"]));
    assert_eq!(document["position"], "design");
    assert_eq!(document["wait"], wait);
    assert_eq!(
        document["wait"]["rule"],
        read_json(&run.join("wait.json"))["rule"]
    );
    assert_eq!(document["wait"]["payload"]["questions"], two_questions());
    let attempts = document["attempts"].as_array().unwrap();
    assert_eq!(attempts.len(), 1, "{document}");
    assert_eq!(attempts[0]["number"], 1);
    assert_eq!(attempts[0]["trigger"], "initial");
    assert_eq!(attempts[0]["state"], "waiting");
    assert_eq!(attempts[0]["reason"], Value::Null);
    let child = run.join("children/design/000001");
    assert_eq!(
        document["children"],
        json!([{
            "step": "design",
            "item": null,
            "ordinal": 1,
            "id": run_record(&child)["id"],
            "state": "exited",
            "outcome": "blocked",
            "directory": child.to_str().unwrap(),
            "progress": null,
        }])
    );
    let controls = document["controls"].as_array().unwrap();
    assert_eq!(controls.len(), 2, "{document}");
    for (ordinal, (shown, file)) in controls
        .iter()
        .zip(["0001-stop.json", "0002-answer.json"])
        .enumerate()
    {
        let control = read_json(&run.join("controls").join(file));
        assert_eq!(shown["ordinal"], ordinal + 1);
        for field in ["event", "by", "at", "payload"] {
            assert_eq!(shown[field], control[field], "{field}: {shown}");
        }
        assert_eq!(
            shown["wait"],
            control.get("wait").cloned().unwrap_or(Value::Null)
        );
    }
    assert_eq!(controls[0]["event"], "control.stop");
    assert_eq!(controls[1]["event"], "control.answer");
    assert_eq!(controls[1]["payload"]["complete"], false);

    // The run's directory names the same run.
    assert_eq!(shown(&published, &run), document);

    let unknown = super::workflow_status::signed_out(super::workflow_run_control::control_command(
        home,
        "show",
        "run_7zzzzzzzzzzzzzzzzzzzzzzzzz",
        &[],
    ));
    let error = super::workflow_status::show_error(&unknown, "run_not_found");
    assert!(error.get("runDirectory").is_none(), "{error}");
}

/// `useful workflow run show RUN` without `--json`, which exits 0.
pub(super) fn shown_plain(run: &Path) -> String {
    let output = isolated_command(&[
        "workflow".to_owned(),
        "run".to_owned(),
        "show".to_owned(),
        run.to_string_lossy().into_owned(),
    ])
    .output()
    .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

// `show` prints the run's `edges` counts and, for an attempt a backward or limited edge
// started, the edge it took beside its `reason`.
#[test]
fn show_prints_the_edges_a_run_took() {
    let bundle = loop_tree();
    decide(&bundle, "design", "planned");
    decide_each(&bundle, "review", &["hand_back", "proceed"]);
    decide(&bundle, "fix", "built");
    decide(&bundle, "merge", "landed");
    let destination = bundle.result("shown-edges");
    chained(
        &isolated_command(&bundle.args(&destination))
            .output()
            .unwrap(),
    );
    let run = fs::canonicalize(&destination).unwrap();

    let output = run_control(None, "show", &run, &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["record"], run_record(&run));
    assert_eq!(document["record"]["edges"], json!({"review.hand_back": 1}));
    let attempts = document["attempts"].as_array().unwrap();
    assert_eq!(attempts.len(), 3, "{document}");
    assert_eq!(attempts[0]["reason"], Value::Null);
    assert_eq!(attempts[0]["edge"], Value::Null);
    assert_eq!(attempts[1]["reason"], "edge");
    assert_eq!(
        attempts[1]["edge"],
        json!({"step": "review", "outcome": "hand_back", "target": "fix", "counted": true})
    );
    assert_eq!(attempts[2]["reason"], "edge");
    assert_eq!(
        attempts[2]["edge"],
        json!({"step": "fix", "outcome": "built", "target": "review", "counted": false})
    );

    let plain = shown_plain(&run);
    let lines = plain.lines().collect::<Vec<_>>();
    assert!(lines.contains(&"edges: review.hand_back=1"), "{plain}");
    let attempt = lines
        .iter()
        .find(|line| line.starts_with("  2  "))
        .unwrap_or_else(|| panic!("{plain}"));
    assert!(attempt.contains("review.hand_back -> fix"), "{plain}");

    // A run that took no edge prints none.
    let published = PublishedWaitTree::new();
    let (waiting, _, _) = published.run("blocked");
    assert!(shown_plain(&waiting).lines().any(|line| line == "edges: -"));
}

/// `useful workflow run list ARGS --allow-insecure-http` as `OPERATOR` against `home` and a
/// deployment that answers `responses`, signed in or not, with the requests it was sent.
fn cloud_list(
    home: &Home,
    args: &[&str],
    signed_in: bool,
    environment: &[(&str, &str)],
    responses: Vec<Vec<u8>>,
) -> (Output, Vec<String>) {
    let (server, _directory, credential_path) = prepared_run(responses);
    let missing = private_credential_directory();
    let missing = missing.path().join("credentials.json");
    let credential_path = if signed_in {
        credential_path
    } else {
        missing.to_str().unwrap().to_owned()
    };
    let environment = deployment_environment(&server.api_url, &credential_path)
        .into_iter()
        .chain([("USEFUL_HOME", home.path()), ("USER", OPERATOR)])
        .chain(environment.iter().copied())
        .collect::<Vec<_>>();
    let arguments = [
        &["workflow", "run", "list"][..],
        args,
        &["--allow-insecure-http"],
    ]
    .concat();
    let output = run_with_env(&arguments, &environment);
    (output, server.finish())
}

/// The page of Cloud runs a deployment answers: one waiting run with an owner and one running
/// run with none, and `nextCursor` `next-page`.
pub(super) fn cloud_list_item(id: &str, owner: Value, state: &str) -> Value {
    json!({
        "id": id, "displayName": "Release checks", "projectId": PROJECT_ID,
        "workflowPath": "workflows/build.yaml", "state": "running",
        "createdAt": "2025-01-03T00:00:00Z", "updatedAt": "2025-01-03T01:00:00Z",
        "integrationContext": {}, "placement": null, "owner": owner,
        "workflowState": state, "workflowWait": null,
    })
}

fn cloud_page() -> Value {
    json!({
        "items": [
            cloud_list_item(RUN_ID, json!("prn_01k0z6r1w8f4jy2m7q9v3x5abc"), "waiting"),
            cloud_list_item("run_01k0z6r1w8f4jy2m7q9v3x5abd", Value::Null, "running"),
        ],
        "nextCursor": "next-page",
    })
}

pub(super) fn page_response(page: &Value) -> Vec<u8> {
    http_response_with_headers(
        "200 OK",
        Some("application/json"),
        &[("Cache-Control", "private, no-store")],
        &serde_json::to_vec(page).unwrap(),
    )
}

fn parsed(output: &Output) -> Value {
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

/// `item` as the listing prints a Cloud row: the item as Cloud returned it with `on`.
fn placed(item: &Value, on: &str) -> Value {
    let mut row = item.clone();
    row["on"] = json!(on);
    row
}

// `list` prints the runs under the home and then one page of the Cloud runs of the organization
// in effect, each saying where it executes, asks for the live ones unless `--all`, keeps the
// waiting ones under `--waiting`, sends the project in effect, prints no local row after the
// first page, and asks no Cloud under a filter only a local record holds.
#[test]
fn list_prints_the_home_and_then_one_page_of_cloud_runs() {
    let published = PublishedWaitTree::new();
    let (_, local_id, _) = published.run("blocked");
    let home = &published.home;
    let page = cloud_page();
    let items = page["items"].as_array().unwrap();

    let (output, requests) = cloud_list(
        home,
        &["--org", ORGANIZATION, "--json"],
        true,
        &[],
        vec![page_response(&page)],
    );
    let document = parsed(&output);
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert!(
        requests[0].contains(&format!("/v1/organizations/{ORGANIZATION}/runs?"))
            && requests[0].contains("stateGroup=active")
            && !requests[0].contains("projectId="),
        "{requests:?}"
    );
    let runs = document["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 3, "{document}");
    assert_eq!(runs[0]["on"], "local", "{document}");
    assert_eq!(runs[0]["id"], local_id.as_str(), "{document}");
    assert_eq!(runs[1], placed(&items[0], "personal"), "{document}");
    assert_eq!(runs[2], placed(&items[1], "project"), "{document}");
    assert_eq!(
        document["cloud"],
        json!({"asked": true, "organizationRef": ORGANIZATION, "nextCursor": "next-page"}),
        "{document}"
    );
    assert!(output.stderr.is_empty(), "{output:?}");

    // The report leads each row with its place and ends with the next cursor.
    let (output, _) = cloud_list(
        home,
        &["--org", ORGANIZATION],
        true,
        &[],
        vec![page_response(&page)],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let report = String::from_utf8(output.stdout).unwrap();
    let leads = report
        .lines()
        .filter(|line| !line.starts_with(' '))
        .map(|line| line.split(' ').next().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(leads, ["local", "personal", "project", "next"], "{report}");
    assert_eq!(report.lines().last(), Some("next cursor: next-page"));

    let (output, requests) = cloud_list(
        home,
        &["--org", ORGANIZATION, "--all", "--json"],
        true,
        &[],
        vec![page_response(&page)],
    );
    assert_eq!(parsed(&output)["runs"].as_array().unwrap().len(), 3);
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert!(!requests[0].contains("stateGroup"), "{requests:?}");

    let (output, requests) = cloud_list(
        home,
        &["--org", ORGANIZATION, "--waiting", "--json"],
        true,
        &[],
        vec![page_response(&page)],
    );
    let document = parsed(&output);
    assert!(requests[0].contains("stateGroup=active"), "{requests:?}");
    let runs = document["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 2, "{document}");
    assert_eq!(runs[0]["id"], local_id.as_str(), "{document}");
    assert_eq!(runs[1], placed(&items[0], "personal"), "{document}");

    let (output, requests) = cloud_list(
        home,
        &["--org", ORGANIZATION, "--cursor", "prior-page", "--json"],
        true,
        &[],
        vec![page_response(&page)],
    );
    let document = parsed(&output);
    assert!(requests[0].contains("cursor=prior-page"), "{requests:?}");
    assert!(
        document["runs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|run| run["on"] != "local"),
        "{document}"
    );

    let (output, requests) = cloud_list(
        home,
        &["--org", ORGANIZATION, "--project", PROJECT_ID, "--json"],
        true,
        &[],
        vec![page_response(&page)],
    );
    let document = parsed(&output);
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert!(
        requests[0].contains(&format!("projectId={PROJECT_ID}")),
        "{requests:?}"
    );
    assert_eq!(document["cloud"]["projectId"], PROJECT_ID, "{document}");

    let (output, requests) = cloud_list(
        home,
        &["--owner", "me", "--org", ORGANIZATION, "--json"],
        true,
        &[],
        vec![],
    );
    let document = parsed(&output);
    assert!(requests.is_empty(), "{requests:?}");
    assert_eq!(
        document["cloud"],
        json!({"asked": false, "reason": "local_only"}),
        "{document}"
    );
    assert_eq!(
        ids(document["runs"].as_array().unwrap()),
        [local_id.as_str()]
    );
}

// With nobody signed in `list` prints the home's runs, says on standard error that Cloud was
// not asked and exits 0, `--on local` asks no Cloud and says nothing of it, a Cloud place fails
// as a Cloud read does, and options of another place are usage errors.
#[test]
fn list_without_cloud_prints_the_home_and_says_why() {
    let published = PublishedWaitTree::new();
    let (_, local_id, _) = published.run("blocked");
    let home = &published.home;

    let (output, requests) = cloud_list(home, &["--json"], false, &[], vec![]);
    let document = parsed(&output);
    assert!(requests.is_empty(), "{requests:?}");
    assert_eq!(
        ids(document["runs"].as_array().unwrap()),
        [local_id.as_str()]
    );
    assert_eq!(document["runs"][0]["on"], "local", "{document}");
    assert_eq!(document["runs"][0]["state"], "waiting", "{document}");
    assert_eq!(
        document["cloud"],
        json!({"asked": false, "reason": "signed_out"}),
        "{document}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("useful account login"),
        "{output:?}"
    );

    let (output, requests) = cloud_list(
        home,
        &["--on", "local", "--json"],
        true,
        &[("USEFUL_ORG", ORGANIZATION)],
        vec![],
    );
    let document = parsed(&output);
    assert!(requests.is_empty(), "{requests:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(
        document["cloud"],
        json!({"asked": false, "reason": "local_only"}),
        "{document}"
    );

    let (output, requests) = cloud_list(home, &["--on", "project", "--json"], false, &[], vec![]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(requests.is_empty(), "{requests:?}");

    for args in [
        &["--on", "personal", "--drift"][..],
        &["--on", "local", "--cursor", "prior-page"],
        &["--on", "local", "--org", ORGANIZATION],
        &["--state-group", "active", "--all"],
    ] {
        let (output, requests) = cloud_list(home, args, true, &[], vec![]);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
        assert!(requests.is_empty(), "{args:?}: {requests:?}");
    }
}
