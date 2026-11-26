use super::*;

use std::io::{BufRead as _, BufReader};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

use base64::Engine as _;
use futures_util::{SinkExt as _, StreamExt as _};
use tokio_tungstenite::tungstenite::Message;

use super::runner_status::{
    ServeStatusFixture, accept_runner_connection_answering, accept_runner_socket,
    cloud_observation_ack, cloud_welcome, write_status_config,
};

pub(super) const SYNC_REQUEST: &[u8] =
    b"{\"schemaVersion\":1,\"operation\":\"sync_agent_logins\"}\n";

/// The control socket's answer to a sync whose `codex` entry is `state`.
pub(super) fn synced_response(codex: &str) -> Vec<u8> {
    synced_with(serde_json::json!([
        serde_json::from_str::<serde_json::Value>(codex).unwrap(),
        {"provider": "github", "state": "not_delivered"},
        {"provider": "gitlab", "state": "not_delivered"},
        {"provider": "linear", "state": "not_delivered"}
    ]))
}

/// The control socket's answer to a sync whose providers are `providers`.
fn synced_with(providers: serde_json::Value) -> Vec<u8> {
    let mut response = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1,
        "outcome": "synced",
        "agentLogins": {"updatedAt": "2026-11-12T01:00:00Z", "providers": providers}
    }))
    .unwrap();
    response.push(b'\n');
    response
}

pub(super) const READY_CODEX: &str = r#"{"provider":"codex","state":"ready","agentLoginId":"agl_01k0z6r1w8f4jy2m7q9v3x5abc","generation":3,"checkedAt":"2026-11-12T01:00:00Z","installedAt":"2026-11-12T00:55:00Z"}"#;

/// The sync command.
pub(super) const SYNC: [&str; 2] = ["runner", "sync"];

const BUSY_RESPONSE: &[u8] =
    b"{\"schemaVersion\":1,\"outcome\":\"error\",\"error\":\"runner_busy\"}\n";

/// The answer of a runner that goes by `host`: its `codex`
/// entry is `foreign_login` with no agent login.
const SYNCED_IN_HOST: &[u8] = include_bytes!(
    "../fixtures/runner-control/v1/valid/agent-logins-synced-credential-mode-response.json"
);
/// The `codex` entry of [`SYNCED_IN_HOST`].
const FOREIGN_CODEX: &str =
    r#"{"provider":"codex","state":"foreign_login","checkedAt":"2026-11-12T01:00:00Z"}"#;
/// The answer of a runner Cloud has not welcomed since it started.
const NOT_YET_CONNECTED: &[u8] =
    include_bytes!("../fixtures/runner-control/v1/valid/not-yet-connected-response.json");
/// The answer of a runner that goes by no credential mode.
const SYNCED_IN_NO_MODE: &[u8] =
    include_bytes!("../fixtures/runner-control/v1/valid/agent-logins-synced-response.json");

/// The value of each `credential mode:` line `stdout` prints: its first word.
pub(super) fn printed_credential_modes(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("credential mode:"))
        .map(|value| value.split_whitespace().next().unwrap_or_default())
        .collect()
}

/// The step `stdout` prints on the provider's line after its next action.
pub(super) fn printed_step<'a>(stdout: &'a str, provider: &str, next_action: &str) -> &'a str {
    let line = stdout
        .lines()
        .find(|line| line.starts_with(&format!("{provider} login:")))
        .unwrap_or_else(|| panic!("{stdout}"));
    line.split_once(&format!("next action {next_action}: "))
        .unwrap_or_else(|| panic!("{line}"))
        .1
}

/// Runs `command --config PATH` and `extra` against a fake control socket
/// that answers `response` to one request, and returns the command's output
/// with the request the socket received.
fn sync_against(command: [&str; 2], response: Vec<u8>, extra: &[&str]) -> (Output, Vec<u8>) {
    let directory = private_credential_directory();
    let runtime = tempfile::tempdir_in("/tmp").unwrap();
    let socket_path = runtime.path().join("runner.sock");
    let socket = ScriptedControlSocket::answering(&socket_path, response);
    let config = write_status_config(&directory, &socket_path);
    let mut args = command.to_vec();
    args.extend_from_slice(&["--config", &config]);
    args.extend_from_slice(extra);
    let output = run_with_env(
        &args,
        &[(
            "USEFUL_API_URL",
            "https://cloud-sync-must-not-be-read.example",
        )],
    );
    (output, socket.request())
}

/// A fake control socket that answers one request with a scripted response.
pub(super) struct ScriptedControlSocket {
    path: PathBuf,
    server: thread::JoinHandle<Vec<u8>>,
}

impl ScriptedControlSocket {
    /// Binds `path` and answers `response` to the first request line.
    pub(super) fn answering(path: &Path, response: Vec<u8>) -> Self {
        let listener = UnixListener::bind(path).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut request = Vec::new();
            reader.read_until(b'\n', &mut request).unwrap();
            // A command that never connected leaves only the closed stream
            // below, which cannot take the answer.
            let _ = reader.get_mut().write_all(&response);
            request
        });
        Self {
            path: path.to_owned(),
            server,
        }
    }

    /// The request the socket received, empty when the command never
    /// connected.
    pub(super) fn request(self) -> Vec<u8> {
        // Release the server if the command exited without connecting, so the
        // test fails on the empty request instead of waiting forever.
        drop(UnixStream::connect(&self.path));
        self.server.join().unwrap()
    }
}

/// Runs `command --config PATH` with no runner listening on the socket the
/// configuration names.
fn sync_with_no_live_runner(command: [&str; 2], config: &str) -> Output {
    let mut args = command.to_vec();
    args.extend_from_slice(&["--config", config]);
    run(&args)
}

#[test]
fn sync_asks_the_live_runner_and_prints_each_provider_readiness() {
    let (output, request) = sync_against(SYNC, synced_response(READY_CODEX), &[]);

    assert_eq!(request, SYNC_REQUEST);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_provider_lines(
        &stdout,
        &[
            ("codex", "ready", "unverified"),
            ("github", "not_delivered", "not_delivered"),
            ("gitlab", "not_delivered", "not_delivered"),
            ("linear", "not_delivered", "not_delivered"),
        ],
    );
    assert!(output.stderr.is_empty());
}

// The earlier spellings of the sync are unknown commands, refused before any request,
// with no notice naming the command that replaced them.
#[test]
fn the_earlier_sync_spellings_are_unknown_and_print_no_notice() {
    let directory = private_credential_directory();
    let runtime = tempfile::tempdir_in("/tmp").unwrap();
    let socket_path = runtime.path().join("runner.sock");
    let config = write_status_config(&directory, &socket_path);
    for earlier in [
        &["runner", "agent-login", "sync"][..],
        &["runner", "grant", "sync"][..],
    ] {
        let socket = ScriptedControlSocket::answering(&socket_path, synced_response(READY_CODEX));
        let mut args = earlier.to_vec();
        args.extend_from_slice(&["--config", &config]);
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{earlier:?}");
        assert!(output.stdout.is_empty(), "{earlier:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            !stderr.contains("useful runner sync"),
            "{earlier:?}: {stderr}"
        );
        assert!(socket.request().is_empty(), "{earlier:?}");
        fs::remove_file(&socket_path).unwrap();
    }
}

/// Asserts that `stdout` has exactly one line per provider, in order, each
/// naming the provider's state and availability.
pub(super) fn assert_provider_lines(stdout: &str, providers: &[(&str, &str, &str)]) {
    let lines = stdout
        .lines()
        .filter(|line| line.contains(" login:"))
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), providers.len(), "{stdout}");
    for (line, (provider, state, availability)) in lines.iter().zip(providers) {
        let words = line
            .split([' ', ',', ':'])
            .filter(|word| !word.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(words.first(), Some(provider), "{line}");
        assert!(words.contains(state), "{line}");
        assert!(words.contains(availability), "{line}");
    }
}

/// The provider's line in `stdout`.
fn provider_line<'a>(stdout: &'a str, provider: &str) -> &'a str {
    stdout
        .lines()
        .find(|line| line.starts_with(&format!("{provider} login:")))
        .unwrap_or_else(|| panic!("{stdout}"))
}

/// The source `stdout` prints on the provider's line: the rest of the line
/// after `source: `, or none where the line names no source.
pub(super) fn printed_source<'a>(stdout: &'a str, provider: &str) -> Option<&'a str> {
    provider_line(stdout, provider)
        .split_once("source: ")
        .map(|(_, source)| source)
}

const CONNECTION_AUTHORIZATION_ID: &str = "cna_01k0z6r1w8f4jy2m7q9v3x5abc";

#[test]
fn sync_prints_org_connection_as_the_organizations_github_app_installation() {
    let codex = READY_CODEX.replace(r#""installedAt""#, r#""source":"grant","installedAt""#);
    let response = synced_with(serde_json::json!([
        serde_json::from_str::<serde_json::Value>(&codex).unwrap(),
        {
            "provider": "github",
            "state": "ready",
            "connectionAuthorizationId": CONNECTION_AUTHORIZATION_ID,
            "generation": 1,
            "expiresAt": "2026-11-12T02:00:00Z",
            "checkedAt": "2026-11-12T01:00:00Z",
            "runId": "run_01k0z6r1w8f4jy2m7q9v3x5abp",
            "source": "org_connection",
        },
        {
            "provider": "gitlab",
            "state": "not_delivered",
            "checkedAt": "2026-11-12T01:00:00Z",
            "runId": "run_01k0z6r1w8f4jy2m7q9v3x5abp",
            "source": "host",
        },
        {"provider": "linear", "state": "not_delivered"},
    ]));

    let (output, _) = sync_against(SYNC, response.clone(), &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    for (provider, source) in [
        ("codex", Some("grant")),
        ("github", Some("the organization's GitHub App installation")),
        ("gitlab", Some("host")),
        ("linear", None),
    ] {
        assert_eq!(printed_source(&stdout, provider), source, "{stdout}");
    }
    assert!(!stdout.contains("org_connection"), "{stdout}");

    let (output, _) = sync_against(SYNC, response, &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let github = &document["agentLogins"]["providers"][1];
    assert_eq!(github["provider"], "github", "{document}");
    assert_eq!(github["source"], "org_connection", "{document}");
    assert_eq!(
        github["connectionAuthorizationId"], CONNECTION_AUTHORIZATION_ID,
        "{document}"
    );
}

#[test]
fn sync_names_the_installations_remedy_beside_the_grants_for_github_alone() {
    let reconnect = |provider: &str| {
        serde_json::json!({
            "provider": provider,
            "state": "reconnect_required",
            "checkedAt": "2026-11-12T01:00:00Z",
        })
    };
    let response = synced_with(serde_json::json!([
        reconnect("github"),
        reconnect("gitlab"),
        {"provider": "linear", "state": "not_delivered"},
    ]));

    let (output, _) = sync_against(SYNC, response, &[]);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let github = provider_line(&stdout, "github");
    for command in [
        "`useful account integration reconnect github`",
        "`useful org integration connect github`",
    ] {
        assert!(github.contains(command), "{github}");
    }
    let gitlab = provider_line(&stdout, "gitlab");
    assert!(
        gitlab.contains("`useful account integration reconnect gitlab.com`"),
        "{gitlab}"
    );
    assert!(!gitlab.contains("org integration"), "{gitlab}");
}

#[test]
fn sync_prints_each_recorded_source_and_its_json_carries_it() {
    let codex = READY_CODEX.replace(r#""installedAt""#, r#""source":"grant","installedAt""#);
    let mut response: serde_json::Value = serde_json::from_slice(&synced_response(&codex)).unwrap();
    response["agentLogins"]["providers"][1] = serde_json::json!({
        "provider": "github",
        "state": "not_delivered",
        "checkedAt": "2026-11-12T01:00:00Z",
        "runId": "run_01k0z6r1w8f4jy2m7q9v3x5abp",
        "source": "host",
    });
    let mut response = serde_json::to_vec(&response).unwrap();
    response.push(b'\n');

    let (output, _) = sync_against(SYNC, response.clone(), &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    for (provider, source) in [
        ("codex", Some("grant")),
        ("github", Some("host")),
        ("gitlab", None),
        ("linear", None),
    ] {
        assert_eq!(printed_source(&stdout, provider), source, "{stdout}");
    }

    let (output, _) = sync_against(SYNC, response, &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let sources = document["agentLogins"]["providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| (entry["provider"].clone(), entry.get("source").cloned()))
        .collect::<Vec<_>>();
    assert_eq!(
        sources,
        [
            ("codex".into(), Some("grant".into())),
            ("github".into(), Some("host".into())),
            ("gitlab".into(), None),
            ("linear".into(), None),
        ],
        "{document}"
    );
}

#[test]
fn sync_json_prints_the_readiness_as_a_document() {
    let (output, request) = sync_against(SYNC, synced_response(READY_CODEX), &["--json"]);

    assert_eq!(request, SYNC_REQUEST);
    assert_eq!(output.status.code(), Some(0));
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["schemaVersion"], 1);
    assert_eq!(document["outcome"], "synced");
    // The control socket's readiness, each provider with its availability and
    // next action.
    let mut expected = serde_json::from_slice::<serde_json::Value>(&synced_response(READY_CODEX))
        .unwrap()["agentLogins"]
        .clone();
    for (entry, (availability, next_action)) in expected["providers"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .zip([
            ("unverified", "none"),
            ("not_delivered", "none"),
            ("not_delivered", "none"),
            ("not_delivered", "none"),
        ])
    {
        entry["availability"] = availability.into();
        entry["nextAction"] = next_action.into();
    }
    assert_eq!(document["agentLogins"], expected);
}

#[test]
fn sync_reports_each_providers_availability_and_fails_a_login_refused_at_its_last_use() {
    let used = |last_use: &str| {
        READY_CODEX.replace(
            r#""installedAt""#,
            &format!(r#""selected":true,"lastUse":"{last_use}","installedAt""#),
        )
    };
    for (codex, code, availability, next_action) in [
        (used("refused"), 1, "reconnect_required", "reconnect"),
        (used("accepted"), 0, "available", "none"),
        (READY_CODEX.to_owned(), 0, "unverified", "none"),
        // An earlier serving process may still say the provider was selected,
        // which changes nothing.
        (
            r#"{"provider":"codex","state":"not_authorized","agentLoginId":"agl_01k0z6r1w8f4jy2m7q9v3x5abc","checkedAt":"2026-11-12T01:00:00Z","selected":true}"#.to_owned(),
            0,
            "not_connected",
            "none",
        ),
    ] {
        let (output, _) = sync_against(SYNC, synced_response(&codex), &["--json"]);
        assert_eq!(output.status.code(), Some(code), "{codex}");
        let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let providers = document["agentLogins"]["providers"].as_array().unwrap();
        assert_eq!(providers[0]["availability"], availability, "{codex}");
        assert_eq!(providers[0]["nextAction"], next_action, "{codex}");
        assert!(
            providers[1..]
                .iter()
                .all(|entry| entry["availability"] == "not_delivered"
                    && entry["nextAction"] == "none"),
            "{document}"
        );

        let (output, _) = sync_against(SYNC, synced_response(&codex), &[]);
        assert_eq!(output.status.code(), Some(code), "{codex}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let codex_line = stdout.lines().next().unwrap();
        assert!(codex_line.contains(availability), "{stdout}");
        // A next action is printed only when there is one to take.
        assert_eq!(
            codex_line.contains(next_action),
            next_action != "none",
            "{stdout}"
        );
    }
}

#[test]
fn sync_prints_a_logins_last_use_with_its_time_where_the_runner_states_one() {
    const LAST_USE_AT: &str = "2026-11-12T00:58:00Z";
    let timed = READY_CODEX.replace(
        r#""installedAt""#,
        &format!(
            r#""selected":true,"lastUse":"accepted","lastUseAt":"{LAST_USE_AT}","installedAt""#
        ),
    );
    let (output, _) = sync_against(SYNC, synced_response(&timed), &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let codex = &document["agentLogins"]["providers"][0];
    assert_eq!(codex["lastUse"], "accepted", "{document}");
    assert_eq!(codex["lastUseAt"], LAST_USE_AT, "{document}");

    let (output, _) = sync_against(SYNC, synced_response(&timed), &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let line = stdout.lines().next().unwrap();
    assert!(line.starts_with("codex login:"), "{stdout}");
    assert!(line.contains("accepted"), "{line}");
    assert!(line.contains(LAST_USE_AT), "{line}");

    // A serving process that predates the time states the last use alone:
    // it is printed without a time.
    let untimed = READY_CODEX.replace(
        r#""installedAt""#,
        r#""selected":true,"lastUse":"accepted","installedAt""#,
    );
    let (output, _) = sync_against(SYNC, synced_response(&untimed), &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let line = stdout.lines().next().unwrap();
    assert!(line.starts_with("codex login:"), "{stdout}");
    assert!(line.contains("accepted"), "{line}");
    assert!(!line.contains("2026-"), "{line}");
}

#[test]
fn sync_names_each_login_whose_check_gave_no_answer_without_changing_its_exit_status() {
    let unanswered = |codex: &str| {
        let mut response: serde_json::Value =
            serde_json::from_slice(&synced_response(codex)).unwrap();
        response["unansweredChecks"] =
            serde_json::json!([{"provider": "codex", "cause": "program_unavailable"}]);
        let mut response = serde_json::to_vec(&response).unwrap();
        response.push(b'\n');
        response
    };
    let refused = READY_CODEX.replace(
        r#""installedAt""#,
        r#""selected":true,"lastUse":"refused","installedAt""#,
    );
    // The exit status is what the readiness alone gives.
    for (codex, code) in [(READY_CODEX.to_owned(), 0), (refused, 1)] {
        let (output, request) = sync_against(SYNC, unanswered(&codex), &[]);
        assert_eq!(request, SYNC_REQUEST);
        assert_eq!(output.status.code(), Some(code), "{output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        // One line per provider's readiness, and after them the check.
        assert_provider_lines(
            &stdout,
            &[
                (
                    "codex",
                    "ready",
                    if code == 0 {
                        "unverified"
                    } else {
                        "reconnect_required"
                    },
                ),
                ("github", "not_delivered", "not_delivered"),
                ("gitlab", "not_delivered", "not_delivered"),
                ("linear", "not_delivered", "not_delivered"),
            ],
        );
        let lines = stdout.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 5, "{stdout}");
        let check = lines[4];
        assert!(check.starts_with("codex "), "{stdout}");
        assert!(check.contains("program_unavailable"), "{stdout}");

        let (output, _) = sync_against(SYNC, unanswered(&codex), &["--json"]);
        assert_eq!(output.status.code(), Some(code), "{output:?}");
        let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            document["unansweredChecks"],
            serde_json::json!([{"provider": "codex", "cause": "program_unavailable"}])
        );
        assert_eq!(document["agentLogins"]["providers"][0]["provider"], "codex");
    }

    // A sync whose checks all answered carries no list.
    let (output, _) = sync_against(SYNC, synced_response(READY_CODEX), &["--json"]);
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(document.get("unansweredChecks").is_none(), "{document}");
}

#[test]
fn sync_exits_1_only_when_an_authorized_provider_is_not_ready() {
    for (codex, code) in [
        (
            r#"{"provider":"codex","state":"not_authorized","checkedAt":"2026-11-12T01:00:00Z"}"#,
            0,
        ),
        (
            r#"{"provider":"codex","state":"revoked","agentLoginId":"agl_01k0z6r1w8f4jy2m7q9v3x5abc","checkedAt":"2026-11-12T01:00:00Z"}"#,
            0,
        ),
        // The host's own login is in use: nothing fails.
        (
            r#"{"provider":"codex","state":"foreign_login","agentLoginId":"agl_01k0z6r1w8f4jy2m7q9v3x5abc","checkedAt":"2026-11-12T01:00:00Z"}"#,
            0,
        ),
        (
            r#"{"provider":"codex","state":"cloud_unavailable","checkedAt":"2026-11-12T01:00:00Z"}"#,
            1,
        ),
    ] {
        for extra in [&[][..], &["--json"][..]] {
            let (output, _) = sync_against(SYNC, synced_response(codex), extra);
            assert_eq!(output.status.code(), Some(code), "{codex} {extra:?}");
            assert!(!output.stdout.is_empty());
        }
    }
}

#[test]
fn sync_exits_4_when_no_runner_is_live_or_a_run_it_holds_is_working() {
    let directory = private_credential_directory();
    let runtime = tempfile::tempdir_in("/tmp").unwrap();
    let config = write_status_config(&directory, &runtime.path().join("runner.sock"));
    let absent = sync_with_no_live_runner(SYNC, &config);
    assert_eq!(absent.status.code(), Some(4));
    assert!(absent.stdout.is_empty());
    assert!(!absent.stderr.is_empty());

    let (busy, request) = sync_against(SYNC, BUSY_RESPONSE.to_vec(), &["--json"]);
    assert_eq!(request, SYNC_REQUEST);
    assert_eq!(busy.status.code(), Some(4));
    assert!(busy.stdout.is_empty());
    assert!(String::from_utf8_lossy(&busy.stderr).contains("runner_busy"));
}

// before Cloud has first welcomed the runner it makes no
// setup for the command, which exits 4 and prints nothing on standard output.
#[test]
fn sync_exits_4_before_cloud_has_first_welcomed_the_runner() {
    for extra in [&[][..], &["--json"][..]] {
        let (output, request) = sync_against(SYNC, NOT_YET_CONNECTED.to_vec(), extra);
        assert_eq!(request, SYNC_REQUEST);
        assert_eq!(output.status.code(), Some(4), "{extra:?}");
        assert!(output.stdout.is_empty(), "{extra:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("not_yet_connected"),
            "{extra:?}"
        );
    }
}

// on a runner that goes by `host` the sync prints the mode
// after the readiness and exits 0, and beside `foreign_login` it names the command an
// owner changes the mode with rather than the step the line names with no mode; the
// projection in `--json` does not change.
#[test]
fn sync_on_a_runner_that_goes_by_host_prints_the_mode_and_exits_0() {
    let (output, request) = sync_against(SYNC, SYNCED_IN_HOST.to_vec(), &[]);
    assert_eq!(request, SYNC_REQUEST);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(printed_credential_modes(&stdout), ["host"], "{stdout}");
    let lines = stdout.lines().collect::<Vec<_>>();
    let readiness_end = lines
        .iter()
        .rposition(|line| line.contains(" login:"))
        .unwrap();
    let mode_line = lines
        .iter()
        .position(|line| line.starts_with("credential mode:"))
        .unwrap();
    assert!(mode_line > readiness_end, "{stdout}");
    assert_provider_lines(
        &stdout,
        &[
            ("codex", "foreign_login", "not_delivered"),
            ("github", "not_delivered", "not_delivered"),
            ("gitlab", "not_delivered", "not_delivered"),
            ("linear", "not_delivered", "not_delivered"),
        ],
    );
    let step = printed_step(&stdout, "codex", "resolve_service_login");
    assert!(step.contains("`useful runner credentials`"), "{stdout}");

    let (no_mode, _) = sync_against(SYNC, synced_response(FOREIGN_CODEX), &[]);
    assert_eq!(no_mode.status.code(), Some(0), "{no_mode:?}");
    let no_mode = String::from_utf8(no_mode.stdout).unwrap();
    let step_with_no_mode = printed_step(&no_mode, "codex", "resolve_service_login");
    assert_ne!(step, step_with_no_mode, "{stdout}");
    assert!(
        !step_with_no_mode.contains("`useful runner credentials`"),
        "{no_mode}"
    );

    let (output, _) = sync_against(SYNC, SYNCED_IN_HOST.to_vec(), &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["credentialMode"], "host", "{document}");
    let codex = &document["agentLogins"]["providers"][0];
    assert_eq!(codex["provider"], "codex", "{document}");
    assert_eq!(codex["state"], "foreign_login", "{document}");
    assert_eq!(codex["nextAction"], "resolve_service_login", "{document}");
}

// a runner that goes by no credential mode answers no mode, and the
// command prints no `credential mode:` line and no `credentialMode` member.
#[test]
fn sync_on_a_runner_that_goes_by_no_mode_prints_no_mode() {
    let (output, _) = sync_against(SYNC, SYNCED_IN_NO_MODE.to_vec(), &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(printed_credential_modes(&stdout).is_empty(), "{stdout}");

    let (output, _) = sync_against(SYNC, SYNCED_IN_NO_MODE.to_vec(), &["--json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(document.get("credentialMode").is_none(), "{document}");
}

#[test]
fn sync_against_an_older_runner_says_it_must_be_restarted_on_this_release() {
    let (output, _) = sync_against(
        SYNC,
        b"{\"schemaVersion\":1,\"outcome\":\"error\",\"error\":\"invalid_request\"}\n".to_vec(),
        &[],
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("restart"), "{stderr}");
    assert!(stderr.contains("useful runner serve"), "{stderr}");
}

const AGENT_LOGIN_ID: &str = "agl_01k0z6r1w8f4jy2m7q9v3x5abc";
/// The Codex login Cloud delivers; its token is the sentinel no output may
/// carry.
const CODEX_MATERIAL: &str =
    r#"{"auth_mode":"chatgpt","tokens":{"access_token":"agent-login-sentinel-5d1f7b"}}"#;
const SENTINEL: &str = "agent-login-sentinel-5d1f7b";
const CLAUDE_CODE_LOGIN_ID: &str = "agl_01k0z6r1w8f4jy2m7q9v3x5abd";
/// The Claude Code token Cloud delivers, which no output may carry either.
const CLAUDE_CODE_TOKEN: &str = "sk-ant-oat01-claude-code-sentinel-8e2a4c";

fn private_json_answer(body: &serde_json::Value) -> Vec<u8> {
    http_response_with_headers(
        "200 OK",
        Some("application/json"),
        &[("Cache-Control", "private, no-store")],
        body.to_string().as_bytes(),
    )
}

/// Cloud's agent-login routes for a runner authorized for one Codex login
/// and one Claude Code login, each at generation 1.
fn cloud_with_agent_logins(request: &[u8]) -> Vec<u8> {
    let authorized = |provider: &str, agent_login_id: &str| {
        serde_json::json!({
            "provider": provider,
            "state": "authorized",
            "agentLoginId": agent_login_id,
            "generation": 1,
            "recordSchemaVersion": 1
        })
    };
    let delivered = |provider: &str, agent_login_id: &str, material: &str| {
        private_json_answer(&serde_json::json!({
            "schemaVersion": 1,
            "provider": provider,
            "agentLoginId": agent_login_id,
            "generation": 1,
            "recordSchemaVersion": 1,
            "material": base64::engine::general_purpose::STANDARD.encode(material)
        }))
    };
    let for_claude_code = String::from_utf8_lossy(request).contains(r#""provider":"claude_code""#);
    if request.starts_with(b"POST /v1/runner/agent-logins/status ") {
        private_json_answer(&serde_json::json!({
            "schemaVersion": 1,
            "logins": [
                authorized("codex", AGENT_LOGIN_ID),
                authorized("claude_code", CLAUDE_CODE_LOGIN_ID)
            ]
        }))
    } else if request.starts_with(b"POST /v1/runner/agent-logins/delivery ") && for_claude_code {
        delivered("claude_code", CLAUDE_CODE_LOGIN_ID, CLAUDE_CODE_TOKEN)
    } else if request.starts_with(b"POST /v1/runner/agent-logins/delivery ") {
        delivered("codex", AGENT_LOGIN_ID, CODEX_MATERIAL)
    } else {
        cloud_without_agent_logins(request)
    }
}

/// A Cloud without the agent-login routes, which answers every request 404.
fn cloud_without_agent_logins(_request: &[u8]) -> Vec<u8> {
    http_response("404 Not Found", None, b"")
}

/// Serves the runner's connection with a welcome that names
/// `credential_mode`, none where it is `None`, and its agent-login requests
/// from `agent_logins`, for as long as the test runs.
fn serve_gateway_with_agent_logins(
    listener: TcpListener,
    agent_logins: fn(&[u8]) -> Vec<u8>,
    credential_mode: Option<&'static str>,
) {
    thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                loop {
                    let stream = accept_runner_connection_answering(&listener, &agent_logins).await;
                    tokio::spawn(async move {
                        let mut socket = accept_runner_socket(stream).await;
                        let Some(Ok(Message::Text(hello))) = socket.next().await else {
                            return;
                        };
                        let hello: serde_json::Value = serde_json::from_str(&hello).unwrap();
                        let _ = socket.send(welcome_naming(credential_mode)).await;
                        let _ = socket
                            .send(cloud_observation_ack(
                                hello["messageId"].as_str().unwrap(),
                                hello["sequence"].as_u64().unwrap(),
                            ))
                            .await;
                        while let Some(Ok(_)) = socket.next().await {}
                    });
                }
            });
    });
}

/// Cloud's `welcome`, naming `credential_mode` where it is one.
fn welcome_naming(credential_mode: Option<&str>) -> Message {
    let welcome = cloud_welcome();
    let Some(mode) = credential_mode else {
        return welcome;
    };
    let mut frame: serde_json::Value = serde_json::from_str(welcome.to_text().unwrap()).unwrap();
    frame["payload"]["credentialMode"] = mode.into();
    Message::Text(frame.to_string().into())
}

/// A live `useful runner serve` against a Cloud whose agent-login routes answer
/// with `agent_logins`, asked once setup has run: `sync --json`, then
/// `status` and the `credentials.agent-logins` doctor check.
struct ServedRunner {
    fixture: ServeStatusFixture,
    home: tempfile::TempDir,
    sync: Output,
    status: Output,
    doctor: Output,
    serve_stderr: String,
}

impl ServedRunner {
    fn against(agent_logins: fn(&[u8]) -> Vec<u8>) -> Self {
        Self::welcomed(agent_logins, None)
    }

    /// `against`, with Cloud's welcome naming `credential_mode`.
    fn welcomed(agent_logins: fn(&[u8]) -> Vec<u8>, credential_mode: Option<&'static str>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("ws://{}/v1/runner/connect", listener.local_addr().unwrap());
        let fixture = ServeStatusFixture::new(&endpoint);
        let home = tempfile::tempdir().unwrap();
        // No coding agent's program is on the service's `PATH`, so a check
        // of a login gives no answer and never reaches a provider.
        let empty_path = tempfile::tempdir().unwrap();
        serve_gateway_with_agent_logins(listener, agent_logins, credential_mode);
        let mut serve = Command::new(crate::executable())
            .args(["runner", "serve", "--config", &fixture.config])
            .env("OTEL_SDK_DISABLED", "true")
            .env("PATH", empty_path.path())
            .env("HOME", home.path())
            .env_remove("CODEX_HOME")
            .env_remove("CLAUDE_CODE_OAUTH_TOKEN")
            .env_remove("CLAUDE_CONFIG_DIR")
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

        let sync = poll_until(
            "sync against the live runner",
            || run(&["runner", "sync", "--json", "--config", &fixture.config]),
            |output| output.status.code() != Some(4),
        );
        let status = run(&["runner", "show", "--config", &fixture.config]);
        let doctor = run(&[
            "runner",
            "doctor",
            "--check",
            "credentials.agent-logins",
            "--json",
            "--config",
            &fixture.config,
        ]);
        serve.kill().unwrap();
        serve.wait().unwrap();
        let serve_stderr = stderr_reader.join().unwrap();
        Self {
            fixture,
            home,
            sync,
            status,
            doctor,
            serve_stderr,
        }
    }
}

#[test]
fn a_runner_with_nothing_authorized_passes_against_a_cloud_without_the_routes() {
    let ServedRunner {
        sync,
        doctor,
        serve_stderr,
        ..
    } = ServedRunner::against(cloud_without_agent_logins);

    assert_eq!(
        sync.status.code(),
        Some(0),
        "{}\n{serve_stderr}",
        String::from_utf8_lossy(&sync.stderr)
    );
    let synced: serde_json::Value = serde_json::from_slice(&sync.stdout).unwrap();
    let providers = synced["agentLogins"]["providers"].as_array().unwrap();
    assert!(
        providers
            .iter()
            .all(|provider| provider["state"] != "cloud_unavailable"),
        "{synced}"
    );
    assert!(
        doctor.status.success(),
        "{}",
        String::from_utf8_lossy(&doctor.stdout)
    );
}

#[test]
fn installed_agent_logins_reach_their_files_and_no_output() {
    let ServedRunner {
        fixture,
        home,
        sync,
        status,
        doctor,
        serve_stderr,
    } = ServedRunner::against(cloud_with_agent_logins);

    assert_eq!(
        sync.status.code(),
        Some(0),
        "{}\n{serve_stderr}",
        String::from_utf8_lossy(&sync.stderr)
    );
    let synced: serde_json::Value = serde_json::from_slice(&sync.stdout).unwrap();
    assert_eq!(synced["agentLogins"]["providers"][0]["state"], "ready");
    assert_eq!(synced["agentLogins"]["providers"][0]["generation"], 1);
    assert_eq!(
        synced["agentLogins"]["providers"][1]["provider"],
        "claude_code"
    );
    assert_eq!(synced["agentLogins"]["providers"][1]["state"], "ready");
    assert_eq!(synced["agentLogins"]["providers"][1]["generation"], 1);
    // The sync checked both logins; without their programs neither check
    // answered, which changes neither readiness nor the exit status.
    assert_eq!(
        synced["unansweredChecks"],
        serde_json::json!([
            {"provider": "codex", "cause": "program_unavailable"},
            {"provider": "claude_code", "cause": "program_unavailable"}
        ]),
        "{synced}"
    );
    // Both logins are in the runner's own directory beside its state, and
    // nothing is written under the service's home.
    let mode =
        |path: &std::path::Path| fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777;
    let directory = fixture.state_directory().join(".runner-agent-login");
    assert_eq!(mode(&directory), 0o700);
    let token = directory.join("claude-code.token");
    assert_eq!(fs::read_to_string(&token).unwrap(), CLAUDE_CODE_TOKEN);
    assert_eq!(mode(&token), 0o600);
    let codex_home = directory.join("codex");
    assert_eq!(mode(&codex_home), 0o700);
    assert_eq!(
        fs::read_to_string(codex_home.join("auth.json")).unwrap(),
        CODEX_MATERIAL
    );
    assert_eq!(mode(&codex_home.join("auth.json")), 0o600);
    assert_eq!(
        fs::read_to_string(codex_home.join("config.toml")).unwrap(),
        "cli_auth_credentials_store = \"file\"\n"
    );
    assert_eq!(fs::read_dir(home.path()).unwrap().count(), 0);
    assert!(status.status.success());
    let status_text = String::from_utf8_lossy(&status.stdout);
    assert!(status_text.contains("codex login:       ready"));
    assert!(status_text.contains("claude_code login: ready (generation 1)"));
    assert!(
        doctor.status.success(),
        "{}",
        String::from_utf8_lossy(&doctor.stdout)
    );
    assert!(serve_stderr.contains("runner.agent_login_setup"));

    let encoded = base64::engine::general_purpose::STANDARD.encode(CODEX_MATERIAL);
    let encoded_token = base64::engine::general_purpose::STANDARD.encode(CLAUDE_CODE_TOKEN);
    let readiness =
        fs::read_to_string(fixture.state_directory().join(".runner-agent-logins.json")).unwrap();
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    for (name, output) in [
        ("runner standard error", serve_stderr),
        ("readiness document", readiness),
        ("runner show", text(&status.stdout)),
        ("runner show error", text(&status.stderr)),
        ("runner sync", text(&sync.stdout)),
        ("runner sync error", text(&sync.stderr)),
        ("runner doctor", text(&doctor.stdout)),
        ("runner doctor error", text(&doctor.stderr)),
    ] {
        assert!(!output.contains(SENTINEL), "{name} carries the agent login");
        assert!(!output.contains(&encoded), "{name} carries the agent login");
        assert!(
            !output.contains(CLAUDE_CODE_TOKEN),
            "{name} carries the Claude Code token"
        );
        assert!(
            !output.contains(&encoded_token),
            "{name} carries the Claude Code token"
        );
    }
}

/// Each request to a route that asks Cloud for a credential or about one:
/// agent-login status and delivery, the provider and token-service lists
/// and a grant token.
static CREDENTIAL_REQUESTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// [`cloud_with_agent_logins`], counting each request to a credential route
/// in [`CREDENTIAL_REQUESTS`].
fn cloud_counting_credential_requests(request: &[u8]) -> Vec<u8> {
    let request_line = request
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    let request_line = String::from_utf8_lossy(request_line);
    if [
        "/v1/runner/agent-logins/status",
        "/v1/runner/agent-logins/delivery",
        "/v1/runner/grants/providers",
        "/v1/runner/credentials/providers",
        "/v1/runner/integrations/providers",
        "/v1/runner/grants/token",
    ]
    .iter()
    .any(|route| request_line.contains(&format!(" {route} ")))
    {
        CREDENTIAL_REQUESTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    cloud_with_agent_logins(request)
}

// SC-RUNNERGRANT-15: a runner Cloud welcomes in `host` asks Cloud
// for no login although Cloud would authorize and deliver one; its sync says so and
// exits 0, its status prints the mode, and no login reaches its directory.
#[test]
fn a_runner_that_uses_only_its_host_asks_cloud_for_no_login() {
    let ServedRunner {
        fixture,
        sync,
        status,
        serve_stderr,
        ..
    } = ServedRunner::welcomed(cloud_counting_credential_requests, Some("host"));

    assert_eq!(
        sync.status.code(),
        Some(0),
        "{}\n{serve_stderr}",
        String::from_utf8_lossy(&sync.stderr)
    );
    let synced: serde_json::Value = serde_json::from_slice(&sync.stdout).unwrap();
    assert_eq!(synced["credentialMode"], "host", "{synced}");
    assert_eq!(synced["agentLogins"]["providers"][0]["provider"], "codex");
    assert_eq!(
        synced["agentLogins"]["providers"][0]["state"], "foreign_login",
        "{synced}"
    );
    assert!(status.status.success(), "{status:?}");
    assert_eq!(
        printed_credential_modes(&String::from_utf8_lossy(&status.stdout)),
        ["host"]
    );
    assert!(
        !fixture
            .state_directory()
            .join(".runner-agent-login/codex/auth.json")
            .exists()
    );
    assert_eq!(
        CREDENTIAL_REQUESTS.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "{serve_stderr}"
    );
}

/// The GitHub token Cloud issues for the assignment, which no output may
/// carry.
const GRANT_TOKEN: &str = "gho_grant-token-sentinel-3c9e1a";
const GRANT_ASSIGNMENT: &str = "asn_01k0z6r1w8f4jy2m7q9v3x5abn";
/// The run of that assignment.
const GRANT_RUN: &str = "run_01k0z6r1w8f4jy2m7q9v3x5abp";

/// The pinned assignment offer and its prepare, whose preparation expires
/// long after the test.
fn offer_and_prepare() -> (Message, Message) {
    let fixture = |name: &str| {
        let path = format!(
            "{}/tests/fixtures/runner-protocol/v1/valid/{name}",
            crate::fixture_root().display()
        );
        serde_json::from_str::<serde_json::Value>(&fs::read_to_string(path).unwrap()).unwrap()
    };
    let offer = fixture("cloud-assignment-offer.json");
    let mut prepare = fixture("cloud-assignment-prepare.json");
    prepare["payload"]["preparationExpiresAt"] = "2099-01-01T00:00:00Z".into();
    assert_eq!(offer["payload"]["assignmentId"], GRANT_ASSIGNMENT);
    assert_eq!(offer["payload"]["runId"], GRANT_RUN);
    assert_eq!(prepare["payload"]["assignmentId"], GRANT_ASSIGNMENT);
    (
        Message::Text(offer.to_string().into()),
        Message::Text(prepare.to_string().into()),
    )
}

/// Cloud's grant-token route, which issues the run's GitHub token and has
/// no grant of the other providers for it. Any other route is answered 404.
fn cloud_issuing_a_github_token(request: &[u8]) -> Vec<u8> {
    if !request.starts_with(b"POST /v1/runner/grants/token ") {
        return cloud_without_agent_logins(request);
    }
    let text = String::from_utf8_lossy(request);
    assert!(
        text.contains(&format!(r#""assignmentId":"{GRANT_ASSIGNMENT}""#)),
        "{text}"
    );
    assert!(text.contains(r#""bootId":"rbt_"#), "{text}");
    if text.contains(r#""provider":"github""#) {
        private_json_answer(&serde_json::json!({
            "schemaVersion": 1,
            "provider": "github",
            "grantId": "pgr_01k0z6r1w8f4jy2m7q9v3x5abc",
            "generation": 2,
            "accessToken": GRANT_TOKEN,
            "expiresAt": "2099-01-01T00:00:00.5Z",
            "refreshAfterSeconds": 600
        }))
    } else {
        http_response_with_headers(
            "409 Conflict",
            Some("application/json"),
            &[("Cache-Control", "private, no-store")],
            br#"{"schemaVersion":1,"reason":"unauthorized"}"#,
        )
    }
}

/// The token file named `name` of `GRANT_ASSIGNMENT` in the runner's
/// state directory.
fn grant_token_file(name: &str) -> String {
    format!(".runner-agent-login/assignments/{GRANT_ASSIGNMENT}/{name}")
}

/// The GitHub token file of `GRANT_ASSIGNMENT`.
const GITHUB_TOKEN_FILE: &str = "github.token";

/// The token Cloud issues for `example`, a provider of its configuration,
/// which no output may carry either.
const EXAMPLE_GRANT_TOKEN: &str = "example_grant-token-sentinel-7b4d2f";

/// The token file of `example`, a provider of Cloud's configuration, of
/// `GRANT_ASSIGNMENT`.
const EXAMPLE_TOKEN_FILE: &str = "grant-tokens/example.token";

/// Cloud's grant routes for an assignment whose providers are `github` and
/// `example`, a provider of its configuration, each with the names its row
/// gives it: it lists both and issues the token of each.
fn cloud_listing_github_and_example(request: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(request);
    if request.starts_with(b"POST /v1/runner/grants/providers ") {
        assert!(
            text.contains(&format!(r#""assignmentId":"{GRANT_ASSIGNMENT}""#)),
            "{text}"
        );
        private_json_answer(&serde_json::json!({
            "schemaVersion": 1,
            "providers": [
                {
                    "provider": "github",
                    "environment": {"token": "GH_TOKEN", "tokenFile": "GH_TOKEN_FILE"}
                },
                {
                    "provider": "example",
                    "environment": {
                        "token": "EXAMPLE_ACCESS_TOKEN",
                        "tokenFile": "EXAMPLE_ACCESS_TOKEN_FILE"
                    }
                }
            ]
        }))
    } else if request.starts_with(b"POST /v1/runner/grants/token ")
        && text.contains(r#""provider":"example""#)
    {
        private_json_answer(&serde_json::json!({
            "schemaVersion": 1,
            "provider": "example",
            "grantId": "pgr_01k0z6r1w8f4jy2m7q9v3x5abd",
            "generation": 1,
            "accessToken": EXAMPLE_GRANT_TOKEN,
            "expiresAt": "2099-01-01T00:00:00.5Z",
            "refreshAfterSeconds": 600
        }))
    } else {
        cloud_issuing_a_github_token(request)
    }
}

/// Serves the runner's connection: a welcome, an acknowledgement of each
/// frame, the pinned offer and, once the runner is preparing, its prepare;
/// sends the payload of the rejection that follows to `rejected`.
async fn serve_one_assignment(
    stream: tokio::net::TcpStream,
    rejected: mpsc::SyncSender<serde_json::Value>,
) {
    let mut socket = accept_runner_socket(stream).await;
    let (offer, prepare) = offer_and_prepare();
    let mut prepare = Some(prepare);
    let mut offered = false;
    while let Some(Ok(Message::Text(frame))) = socket.next().await {
        let frame: serde_json::Value = serde_json::from_str(&frame).unwrap();
        if frame["type"] == "hello" {
            socket.send(cloud_welcome()).await.unwrap();
        }
        if let (Some(message_id), Some(sequence)) =
            (frame["messageId"].as_str(), frame["sequence"].as_u64())
        {
            socket
                .send(cloud_observation_ack(message_id, sequence))
                .await
                .unwrap();
        }
        if !offered {
            offered = true;
            socket.send(offer.clone()).await.unwrap();
        }
        if frame["type"] == "assignment_preparing"
            && let Some(prepare) = prepare.take()
        {
            socket.send(prepare).await.unwrap();
        }
        if frame["type"] == "assignment_rejected" {
            let _ = rejected.try_send(frame["payload"].clone());
        }
    }
}

/// A live `useful runner serve` that admits the pinned assignment against a
/// Cloud whose routes answer as `routes` does, once that assignment has
/// ended: the source route has no credential, so the admission is rejected.
struct EndedGrantAssignment {
    fixture: ServeStatusFixture,
    _home: tempfile::TempDir,
    serve: std::process::Child,
    stderr_reader: thread::JoinHandle<String>,
    token_file: PathBuf,
    /// What the token file held, and its mode, when the admission went on
    /// to ask for its source credential, the step after the grant tokens.
    held_at_source: Option<Option<(String, u32)>>,
    rejection: Option<serde_json::Value>,
}

impl EndedGrantAssignment {
    /// The runner served by `routes`, watching the token file at `watched`
    /// in its state directory.
    fn served(routes: fn(&[u8]) -> Vec<u8>, watched: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("ws://{}/v1/runner/connect", listener.local_addr().unwrap());
        let fixture = ServeStatusFixture::new(&endpoint);
        let home = tempfile::tempdir().unwrap();
        let token_file = fixture.state_directory().join(watched);
        let (held_sender, held) = mpsc::sync_channel(1);
        let (rejected_sender, rejected) = mpsc::sync_channel(1);
        let watched = token_file.clone();
        let cloud = routes;
        let routes = move |request: &[u8]| {
            if request.starts_with(b"POST /v1/runner/source-credentials ") {
                let _ = held_sender.try_send(
                    fs::read_to_string(&watched).ok().zip(
                        fs::symlink_metadata(&watched)
                            .ok()
                            .map(|metadata| metadata.permissions().mode() & 0o777),
                    ),
                );
            }
            cloud(request)
        };
        thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    let stream = accept_runner_connection_answering(&listener, &routes).await;
                    tokio::spawn(serve_one_assignment(stream, rejected_sender));
                    // The runner's HTTP requests go on arriving on this listener.
                    loop {
                        drop(accept_runner_connection_answering(&listener, &routes).await);
                    }
                });
        });
        let mut serve = Command::new(crate::executable())
            .args(["runner", "serve", "--config", &fixture.config])
            .env("OTEL_SDK_DISABLED", "true")
            .env("HOME", home.path())
            .env_remove("EXAMPLE_ACCESS_TOKEN")
            .env_remove("EXAMPLE_ACCESS_TOKEN_FILE")
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

        let held_at_source = poll_until(
            "the admission's request for its source credential",
            || held.try_recv().ok(),
            Option::is_some,
        );
        let rejection = poll_until(
            "the admission's rejection",
            || rejected.try_recv().ok(),
            Option::is_some,
        );
        Self {
            fixture,
            _home: home,
            serve,
            stderr_reader,
            token_file,
            held_at_source,
            rejection,
        }
    }

    /// Stops the runner and answers what it wrote to standard error.
    fn stop(mut self) -> String {
        self.serve.kill().unwrap();
        self.serve.wait().unwrap();
        self.stderr_reader.join().unwrap()
    }
}

#[test]
fn an_admitted_assignment_keeps_its_grant_token_in_its_file_and_prints_it_nowhere() {
    let served = EndedGrantAssignment::served(
        cloud_issuing_a_github_token,
        &grant_token_file(GITHUB_TOKEN_FILE),
    );
    let token_file = served.token_file.clone();
    let removed = poll_until(
        "the token file's removal once the assignment ended",
        || token_file.exists(),
        |exists| !exists,
    );
    let status = run(&["runner", "show", "--config", &served.fixture.config]);
    let readiness = fs::read(
        served
            .fixture
            .state_directory()
            .join(".runner-agent-logins.json"),
    )
    .unwrap();
    let (held_at_source, rejection) = (served.held_at_source.clone(), served.rejection.clone());
    let serve_stderr = served.stop();

    assert_eq!(
        held_at_source,
        Some(Some((GRANT_TOKEN.to_owned(), 0o600))),
        "{serve_stderr}"
    );
    assert!(rejection.is_some(), "{serve_stderr}");
    assert!(!removed);
    let readiness: serde_json::Value = serde_json::from_slice(&readiness).unwrap();
    let entry = |provider: &str| {
        readiness["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["provider"] == provider)
            .cloned()
            .unwrap()
    };
    assert_eq!(entry("github")["state"], "ready", "{readiness}");
    assert_eq!(entry("github")["generation"], 2, "{readiness}");
    assert!(entry("github").get("selected").is_none(), "{readiness}");
    for provider in ["gitlab", "linear"] {
        assert_eq!(entry(provider)["state"], "not_authorized", "{readiness}");
    }
    assert!(status.status.success());
    assert!(
        serve_stderr.contains("runner.grant_token"),
        "{serve_stderr}"
    );
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    for (name, output) in [
        ("runner standard error", serve_stderr),
        ("readiness document", readiness.to_string()),
        ("runner show", text(&status.stdout)),
        ("runner show error", text(&status.stderr)),
    ] {
        assert!(
            !output.contains(GRANT_TOKEN),
            "{name} carries the grant token"
        );
        assert!(
            !output.contains("github.token"),
            "{name} names the token file"
        );
    }
}

#[test]
fn a_configured_providers_token_is_kept_in_its_own_file_and_printed_nowhere() {
    let served = EndedGrantAssignment::served(
        cloud_listing_github_and_example,
        &grant_token_file(EXAMPLE_TOKEN_FILE),
    );
    let token_file = served.token_file.clone();
    let removed = poll_until(
        "the token file's removal once the assignment ended",
        || token_file.exists(),
        |exists| !exists,
    );
    let status = run(&["runner", "show", "--config", &served.fixture.config]);
    let readiness = fs::read(
        served
            .fixture
            .state_directory()
            .join(".runner-agent-logins.json"),
    )
    .unwrap();
    let held_at_source = served.held_at_source.clone();
    let serve_stderr = served.stop();

    assert_eq!(
        held_at_source,
        Some(Some((EXAMPLE_GRANT_TOKEN.to_owned(), 0o600))),
        "{serve_stderr}"
    );
    assert!(!removed);
    assert!(status.status.success());
    let readiness: serde_json::Value = serde_json::from_slice(&readiness).unwrap();
    assert!(
        readiness["providers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["provider"] != "example"),
        "{readiness}"
    );
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    for (name, output) in [
        ("runner standard error", serve_stderr),
        ("readiness document", readiness.to_string()),
        ("runner show", text(&status.stdout)),
        ("runner show error", text(&status.stderr)),
    ] {
        for secret in [EXAMPLE_GRANT_TOKEN, GRANT_TOKEN] {
            assert!(!output.contains(secret), "{name} carries a grant token");
        }
        assert!(
            !output.contains("example.token"),
            "{name} names the token file"
        );
    }
}

#[test]
fn sync_shows_an_ended_assignments_grant_token_as_of_its_run_and_not_as_current() {
    let served = EndedGrantAssignment::served(
        cloud_issuing_a_github_token,
        &grant_token_file(GITHUB_TOKEN_FILE),
    );
    let config = served.fixture.config.clone();
    // The runner answers a sync only once it is idle.
    let sync = poll_until(
        "sync once the runner is idle",
        || run(&["runner", "sync", "--config", &config]),
        |output| output.status.code() != Some(4),
    );
    let json = run(&["runner", "sync", "--json", "--config", &config]);
    let serve_stderr = served.stop();

    // An OAuth entry never fails the sync, ended or not.
    assert_eq!(
        sync.status.code(),
        Some(0),
        "{}\n{serve_stderr}",
        String::from_utf8_lossy(&sync.stderr)
    );
    let stdout = String::from_utf8(sync.stdout).unwrap();
    let github = stdout
        .lines()
        .find(|line| line.starts_with("github login:"))
        .unwrap_or_else(|| panic!("{stdout}"));
    let words = github
        .split([' ', ',', ':'])
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    assert!(words.contains(&"ready"), "{github}");
    assert!(github.contains("as of run"), "{github}");
    assert!(words.contains(&GRANT_RUN), "{github}");
    assert!(words.contains(&"unverified"), "{github}");
    assert!(!github.contains("availability available"), "{github}");

    assert_eq!(json.status.code(), Some(0));
    let document: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let entry = document["agentLogins"]["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["provider"] == "github")
        .cloned()
        .unwrap();
    assert_eq!(entry["state"], "ready", "{document}");
    assert_eq!(entry["runId"], GRANT_RUN, "{document}");
    assert!(entry["endedAt"].is_string(), "{document}");
    assert_eq!(entry["availability"], "unverified", "{document}");
    assert_eq!(entry["nextAction"], "none", "{document}");
}
