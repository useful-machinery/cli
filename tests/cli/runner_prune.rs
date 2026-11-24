use super::*;

use std::io::BufReader;
use std::path::PathBuf;

use super::runner_agent_login::ScriptedControlSocket;
use super::runner_status::{ServeStatusFixture, write_status_config};

/// The `prune` request for the kept-run bounds, the one `--yes` alone sends.
const PRUNE_BOUNDS_REQUEST: &[u8] =
    b"{\"schemaVersion\":1,\"operation\":\"prune\",\"all\":false}\n";
const BUSY_RESPONSE: &[u8] =
    b"{\"schemaVersion\":1,\"outcome\":\"error\",\"error\":\"runner_busy\"}\n";
const INVALID_REQUEST_RESPONSE: &[u8] =
    b"{\"schemaVersion\":1,\"outcome\":\"error\",\"error\":\"invalid_request\"}\n";

/// The bytes of the valid control-socket fixture `name`.
fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        crate::fixture_root()
            .join("tests/fixtures/runner-control/v1/valid")
            .join(name),
    )
    .unwrap()
}

/// The member `member` of the fixture `name`'s answer.
fn fixture_member(name: &str, member: &str) -> serde_json::Value {
    let answer: serde_json::Value = serde_json::from_slice(&fixture(name)).unwrap();
    answer[member].clone()
}

/// Runs `useful runner prune --config PATH` and `extra` against a fake control socket that
/// answers `response` to one request, and returns the command's output with the request
/// the socket received.
fn prune_against(response: Vec<u8>, extra: &[&str]) -> (Output, Vec<u8>) {
    let directory = private_credential_directory();
    let runtime = tempfile::tempdir_in("/tmp").unwrap();
    let socket_path = runtime.path().join("runner.sock");
    let socket = ScriptedControlSocket::answering(&socket_path, response);
    let config = write_status_config(&directory, &socket_path);
    let mut args = vec!["runner", "prune", "--config", &config];
    args.extend_from_slice(extra);
    let output = run_with_env(
        &args,
        &[(
            "USEFUL_API_URL",
            "https://cloud-prune-must-not-be-read.example",
        )],
    );
    (output, socket.request())
}

fn json_document(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)))
}

#[test]
fn prune_asks_kept_without_yes_and_prune_with_it_for_the_scope_all_gives() {
    let kept = fixture("kept-idle-response.json");
    let pruned = fixture("pruned-incomplete-response.json");
    for (extra, response, expected) in [
        (&[][..], &kept, fixture("kept-request.json")),
        (&["--all"][..], &kept, fixture("kept-all-request.json")),
        (&["--yes"][..], &pruned, PRUNE_BOUNDS_REQUEST.to_vec()),
        (
            &["--all", "--yes"][..],
            &pruned,
            fixture("prune-request.json"),
        ),
    ] {
        let (_, request) = prune_against(response.clone(), extra);
        assert_eq!(
            request,
            expected,
            "{extra:?}: {}",
            String::from_utf8_lossy(&request)
        );
    }
}

#[test]
fn prune_without_yes_prints_the_kept_report_and_exits_0() {
    let (output, _) = prune_against(fixture("kept-response.json"), &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let kept = fixture_member("kept-response.json", "kept");
    for workspace in kept["workspaces"].as_array().unwrap() {
        if let Some(run_id) = workspace["runId"].as_str() {
            assert!(stdout.contains(run_id), "{run_id}\n{stdout}");
        }
        for directory in workspace["directories"].as_array().unwrap() {
            let directory = directory.as_str().unwrap();
            assert!(stdout.contains(directory), "{directory}\n{stdout}");
        }
    }
    for cache in kept["buildCaches"].as_array().unwrap() {
        let path = cache["path"].as_str().unwrap();
        assert!(stdout.contains(path), "{path}\n{stdout}");
    }

    let (output, _) = prune_against(fixture("kept-response.json"), &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let document = json_document(&output);
    assert_eq!(document["schemaVersion"], 1);
    assert_eq!(document["outcome"], "kept");
    assert_eq!(document["kept"], kept);
}

/// `pruned-response.json` with its failed directory removed instead, so that nothing
/// failed and the pass finished.
fn clean_pruned_response() -> serde_json::Value {
    let mut answer: serde_json::Value =
        serde_json::from_slice(&fixture("pruned-response.json")).unwrap();
    answer["pruned"]["directories"][1]["result"] = "removed".into();
    answer["pruned"]["failedDirectories"] = 0.into();
    answer
}

fn answer_bytes(answer: &serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(answer).unwrap();
    bytes.push(b'\n');
    bytes
}

#[test]
fn prune_with_yes_prints_the_result_and_exits_by_what_failed_and_whether_it_finished() {
    let clean = clean_pruned_response();
    let mut failed_cache = clean.clone();
    failed_cache["pruned"]["buildCaches"][0]["failedFiles"] = 2.into();
    let failed_directory: serde_json::Value =
        serde_json::from_slice(&fixture("pruned-response.json")).unwrap();
    let incomplete: serde_json::Value =
        serde_json::from_slice(&fixture("pruned-incomplete-response.json")).unwrap();
    for (answer, code) in [
        (&failed_directory, 1),
        (&failed_cache, 1),
        (&incomplete, 4),
        (&clean, 0),
    ] {
        let (output, _) = prune_against(answer_bytes(answer), &["--yes"]);
        assert_eq!(output.status.code(), Some(code), "{output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        for directory in answer["pruned"]["directories"].as_array().unwrap() {
            let path = directory["path"].as_str().unwrap();
            assert!(stdout.contains(path), "{path}\n{stdout}");
            if let Some(run_id) = directory["runId"].as_str() {
                assert!(stdout.contains(run_id), "{run_id}\n{stdout}");
            }
        }
        for cache in answer["pruned"]["buildCaches"].as_array().unwrap() {
            let path = cache["path"].as_str().unwrap();
            assert!(stdout.contains(path), "{path}\n{stdout}");
        }

        let (output, _) = prune_against(answer_bytes(answer), &["--yes", "--json"]);
        assert_eq!(output.status.code(), Some(code), "{output:?}");
        let document = json_document(&output);
        assert_eq!(document["schemaVersion"], 1);
        assert_eq!(document["outcome"], "pruned");
        assert_eq!(document["pruned"], answer["pruned"]);
    }
}

#[test]
fn prune_refused_runner_busy_exits_4_having_printed_no_result() {
    for extra in [&["--yes"][..], &["--yes", "--json"][..]] {
        let (output, request) = prune_against(BUSY_RESPONSE.to_vec(), extra);
        assert_eq!(request, PRUNE_BOUNDS_REQUEST);
        assert_eq!(output.status.code(), Some(4), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("runner_busy"), "{stderr}");
    }
}

#[test]
fn prune_against_an_earlier_runner_exits_1_naming_useful_runner_serve() {
    for extra in [&[][..], &["--yes"][..], &["--json"][..]] {
        let (output, _) = prune_against(INVALID_REQUEST_RESPONSE.to_vec(), extra);
        assert_eq!(output.status.code(), Some(1), "{extra:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("useful runner serve"), "{stderr}");
    }
}

#[test]
fn prune_with_no_live_runner_exits_4() {
    let directory = private_credential_directory();
    let runtime = tempfile::tempdir_in("/tmp").unwrap();
    let config = write_status_config(&directory, &runtime.path().join("runner.sock"));
    for extra in [&[][..], &["--all", "--yes"][..]] {
        let mut args = vec!["runner", "prune", "--config", &config];
        args.extend_from_slice(extra);
        let output = run(&args);
        assert_eq!(output.status.code(), Some(4), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(!output.stderr.is_empty(), "{output:?}");
    }
}

/// The names of the entries of `directory`, sorted.
fn entries(directory: &Path) -> Vec<String> {
    let mut names = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

// SC-RUNNERENROLL-13: a live runner reports its build cache measured with nothing due, and
// an operator's `--all --yes` empties it but for its `CACHEDIR.TAG`, after which another
// removes nothing.
#[test]
fn prune_reports_and_empties_a_live_runners_build_cache() {
    // Cloud accepts the connection and never answers it; the control socket serves
    // without it.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("ws://{}/v1/runner/connect", listener.local_addr().unwrap());
    let cache_root = tempfile::tempdir().unwrap();
    let cache: PathBuf = cache_root.path().join("cargo-target");
    fs::create_dir(&cache).unwrap();
    fs::write(
        cache.join("CACHEDIR.TAG"),
        "Signature: 8a477f597d28d172789f06886806bc55\n",
    )
    .unwrap();
    const FILES: [&str; 3] = ["a.rlib", "b.rlib", "c.rmeta"];
    for name in FILES {
        fs::write(cache.join(name), vec![b'x'; 4096]).unwrap();
    }
    let fixture = ServeStatusFixture::with_build_cache(&endpoint, &cache, 1_073_741_824);
    let home = tempfile::tempdir().unwrap();
    let empty_path = tempfile::tempdir().unwrap();
    let mut serve = Command::new(crate::executable())
        .args(["runner", "serve", "--config", &fixture.config])
        .env("OTEL_SDK_DISABLED", "true")
        .env("PATH", empty_path.path())
        .env("HOME", home.path())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let serve_stderr = serve.stderr.take().unwrap();
    let stderr_reader = thread::spawn(move || {
        let mut output = String::new();
        let _ = BufReader::new(serve_stderr).read_to_string(&mut output);
        output
    });

    let report = poll_until(
        "the kept report of the live runner",
        || run(&["runner", "prune", "--config", &fixture.config, "--json"]),
        |output| output.status.code() != Some(4),
    );
    let pruned = run(&[
        "runner",
        "prune",
        "--config",
        &fixture.config,
        "--all",
        "--yes",
        "--json",
    ]);
    let after_prune = entries(&cache);
    let again = run(&[
        "runner",
        "prune",
        "--config",
        &fixture.config,
        "--all",
        "--yes",
        "--json",
    ]);
    serve.kill().unwrap();
    serve.wait().unwrap();
    let serve_stderr = stderr_reader.join().unwrap();
    drop(listener);

    assert_eq!(report.status.code(), Some(0), "{report:?}\n{serve_stderr}");
    let report = json_document(&report);
    assert_eq!(report["outcome"], "kept");
    let caches = report["kept"]["buildCaches"].as_array().unwrap();
    assert_eq!(caches.len(), 1, "{report}");
    assert_eq!(caches[0]["path"], cache.to_str().unwrap());
    assert_eq!(caches[0]["state"], "measured");
    assert_eq!(caches[0]["dueBytes"], 0);

    assert_eq!(pruned.status.code(), Some(0), "{pruned:?}\n{serve_stderr}");
    let pruned = json_document(&pruned);
    assert_eq!(pruned["outcome"], "pruned");
    assert_eq!(pruned["pruned"]["complete"], true);
    let caches = pruned["pruned"]["buildCaches"].as_array().unwrap();
    assert_eq!(caches.len(), 1, "{pruned}");
    assert_eq!(caches[0]["removedFiles"], FILES.len());
    assert_eq!(after_prune, ["CACHEDIR.TAG"]);

    assert_eq!(again.status.code(), Some(0), "{again:?}\n{serve_stderr}");
    let again = json_document(&again);
    assert_eq!(again["outcome"], "pruned");
    assert_eq!(again["pruned"]["removedBytes"], 0);
    assert!(
        again["pruned"]["buildCaches"]
            .as_array()
            .unwrap()
            .iter()
            .all(|cache| cache["removedFiles"] == 0),
        "{again}"
    );
    assert_eq!(entries(&cache), ["CACHEDIR.TAG"]);
}
