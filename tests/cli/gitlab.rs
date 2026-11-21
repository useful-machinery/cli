use super::*;

const ORG: &str = "acme-research";
const CONNECTION: &str = "glc_01k0z6r1w8f4jy2m7q9v3x5abc";
const CANDIDATE: &str = "glca_01k0z6r1w8f4jy2m7q9v3x5abc";
const SECRET: &str = "private-gitlab-token-sentinel";
const SESSION: &str = "human-session-fixture";

fn connection() -> serde_json::Value {
    serde_json::json!({"id":CONNECTION,"organizationId":"org_01k0z6r1w8f4jy2m7q9v3x5abc",
        "instanceUrl":"https://gitlab.com", "state":"credential_required", "credentialReason":"not-configured",
        "version":3,"providerUser":null,"credential":null,"selectedRepositoryIds":[],
        "support":{"state":"unverified","observedVersion":null},
        "createdAt":"2026-09-05T12:00:00Z","updatedAt":"2026-09-05T12:01:00Z"})
}
fn initial_connection() -> serde_json::Value {
    let mut value = connection();
    value["version"] = 1.into();
    value
}
/// An active connection at `https://gitlab.com` whose bot user is `automation-bot`.
pub(super) fn active_connection() -> serde_json::Value {
    let mut value = connection();
    value["state"] = "active".into();
    value["credentialReason"] = serde_json::Value::Null;
    value["version"] = 4.into();
    value["providerUser"] = serde_json::json!({"id":"42","username":"automation-bot"});
    value["credential"] = serde_json::json!({"providerTokenId":"77","kind":"personal_access_token",
        "accountUse":"dedicated_user","permissionProfile":"api","expiresAt":"2027-09-05T00:00:00Z",
        "validatedAt":"2026-09-05T12:02:00Z","expiryNotice":"none"});
    value
}
fn disconnected_connection() -> serde_json::Value {
    let mut value = connection();
    value["state"] = "disconnected".into();
    value["credentialReason"] = serde_json::Value::Null;
    value["version"] = 4.into();
    value
}
fn group_pending() -> serde_json::Value {
    let mut value = candidate("pending");
    value["kind"] = "group_access_token".into();
    value["accountUse"] = serde_json::Value::Null;
    value
}
fn candidate(state: &str) -> serde_json::Value {
    serde_json::json!({"id":CANDIDATE,"connectionId":CONNECTION,"organizationId":"org_01k0z6r1w8f4jy2m7q9v3x5abc",
        "instanceUrl":"https://gitlab.com","initiatorId":"prn_01k0z6r1w8f4jy2m7q9v3x5abc",
        "connectionVersion":3,"authorityGeneration":1,"generation":1,"kind":"personal_access_token",
        "accountUse":"dedicated_user","state":state,"failureCode":null,"providerUserId":if state == "verified" {Some("42")} else {None},
        "providerUsername":if state == "verified" {Some("automation-bot")} else {None},
        "previousProviderUserId":null,"previousProviderUsername":null,
        "providerTokenId":if state == "verified" {Some("77")} else {None},
        "permissionProfile":if state == "verified" {Some("api")} else {None},
        "tokenExpiresAt":if state == "verified" {Some("2027-09-05T00:00:00Z")} else {None},
        "validatedAt":if state == "verified" {Some("2026-09-05T12:02:00Z")} else {None},"createdAt":"2026-09-05T12:00:00Z",
        "expiresAt":"2026-09-05T12:10:00Z","terminalAt":null})
}
fn prepared(responses: Vec<Vec<u8>>) -> (ScriptedServer, tempfile::TempDir, String) {
    let server = ScriptedServer::respond(responses);
    let dir = private_credential_directory();
    let path = dir.path().join("credentials.json");
    write_credential_fixture(&path, &server.api_url, SESSION, "2999-01-01T00:00:00Z");
    (server, dir, path.to_str().unwrap().to_owned())
}
/// A token file holding `SECRET` in `dir`: a regular file of the caller's with mode 0600.
fn token_file(dir: &tempfile::TempDir) -> String {
    let path = dir.path().join("token");
    fs::write(&path, SECRET).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    path.to_str().unwrap().to_owned()
}
/// The options that confirm the verified identity `42` without a terminal (REQ-CONNECTION-58).
const CONFIRM: [&str; 3] = [
    "--expected-provider-user-id",
    "42",
    "--dedicated-automation",
];
/// `useful org integration connect gitlab` of the group access token in `token`, confirmed as
/// `42`, with `args`.
fn create_gitlab(server: &ScriptedServer, credential: &str, token: &str, args: &[&str]) -> Output {
    let create = [
        "connect",
        "gitlab",
        "--token-file",
        token,
        "--kind",
        "group-access-token",
    ];
    run_org(server, credential, &[&create[..], &CONFIRM, args].concat())
}
/// `useful org integration reconnect` of `INTEGRATION` at version 3 with the group access token in
/// `token`, confirmed as `42`, with `args`.
fn reconnect_gitlab(
    server: &ScriptedServer,
    credential: &str,
    token: &str,
    args: &[&str],
) -> Output {
    let reconnect = [
        "reconnect",
        CONNECTION,
        "--expected-version",
        "3",
        "--token-file",
        token,
        "--kind",
        "group-access-token",
    ];
    run_org(
        server,
        credential,
        &[&reconnect[..], &CONFIRM, args].concat(),
    )
}
/// `useful org integration list` of GitLab's connections alone, for the organization `ORG`.
fn list_gitlab(server: &ScriptedServer, credential: &str, args: &[&str]) -> Output {
    let list = [
        "org",
        "integration",
        "list",
        "--provider",
        "gitlab",
        "--org",
        ORG,
    ];
    run_json(server, credential, &[&list[..], args].concat())
}
/// `useful org integration show` of the GitLab connection `INTEGRATION` in the organization `ORG`.
fn show_gitlab(server: &ScriptedServer, credential: &str, args: &[&str]) -> Output {
    let show = ["org", "integration", "show", CONNECTION, "--org", ORG];
    run_json(server, credential, &[&show[..], args].concat())
}
/// `useful org integration repository list` of the GitLab connection `INTEGRATION` in `ORG`.
const LIST_REPOSITORIES: [&str; 7] = [
    "org",
    "integration",
    "repository",
    "list",
    CONNECTION,
    "--org",
    ORG,
];
fn list_repositories(server: &ScriptedServer, credential: &str, args: &[&str]) -> Output {
    run_json(server, credential, &[&LIST_REPOSITORIES[..], args].concat())
}
/// `useful org integration` with `args`, in the organization `ORG`.
fn run_org(server: &ScriptedServer, credential: &str, args: &[&str]) -> Output {
    run_json(
        server,
        credential,
        &[&["org", "integration"][..], args, &["--org", ORG]].concat(),
    )
}
fn run_json(server: &ScriptedServer, credential: &str, args: &[&str]) -> Output {
    let mut command = args.to_vec();
    command.extend_from_slice(&["--json", "--allow-insecure-http"]);
    run_with_env(
        &command,
        &deployment_environment(&server.api_url, credential),
    )
}
/// Every JSON document `output` wrote; none carries the token.
fn documents(output: &Output) -> Vec<serde_json::Value> {
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
    let documents: Vec<serde_json::Value> = output
        .stdout
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    for document in &documents {
        assert_eq!(document["schemaVersion"], 1, "{document}");
    }
    documents
}
fn document(output: &Output) -> serde_json::Value {
    let mut documents = documents(output);
    assert_eq!(documents.len(), 1, "{output:?}");
    documents.remove(0)
}
fn single(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    document(output)
}
fn failure(output: &Output, exit: i32) -> serde_json::Value {
    assert_eq!(output.status.code(), Some(exit), "{output:?}");
    let doc = document(output);
    assert_eq!(doc["organizationRef"], ORG);
    assert!(output.stderr.is_empty(), "{output:?}");
    doc
}
/// The documents of a `create gitlab` or `reconnect` that ended with `exit`, one per step and the
/// last its ending.
fn steps(output: &Output, exit: i32) -> Vec<serde_json::Value> {
    assert_eq!(output.status.code(), Some(exit), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let documents = documents(output);
    for document in &documents {
        assert_eq!(document["organizationRef"], ORG, "{document}");
    }
    documents
}
fn outcomes(documents: &[serde_json::Value]) -> Vec<&str> {
    documents
        .iter()
        .map(|document| document["outcome"].as_str().unwrap())
        .collect()
}
/// A candidate GitLab verified as the user `user`.
fn verified_as(user: &str) -> serde_json::Value {
    let mut value = candidate("verified");
    value["providerUserId"] = user.into();
    value
}
/// Cloud's acknowledgement of a candidate's cancellation.
fn cancelled() -> Vec<u8> {
    http_response("204 No Content", None, b"")
}
/// The path, under the organization's GitLab connections, of the candidate `CANDIDATE`.
fn candidate_path() -> String {
    format!("/{CONNECTION}/credential-candidates/{CANDIDATE}")
}
fn not_found() -> Vec<u8> {
    problem_http_response(
        "404 Not Found",
        serde_json::json!({"type":"https://api.usefulmachinery.com/problems/not-found","title":"Not found","status":404}),
    )
}
fn request(
    request: &str,
    method: &str,
    suffix: &str,
    body: Option<serde_json::Value>,
    key: Option<&str>,
) {
    assert!(
        request.starts_with(&format!(
            "{method} /api/v1/organizations/{ORG}/connections/gitlab{suffix} "
        )),
        "{request}"
    );
    if let Some(key) = key {
        assert_eq!(header_value(request, "idempotency-key"), key);
    }
    if let Some(body) = body {
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(request.split_once("\r\n\r\n").unwrap().1)
                .unwrap(),
            body
        );
    }
}

// REQ-CONNECTION-56, REQ-CONNECTION-74, REQ-CONNECTION-75, REQ-CONNECTION-104,
// REQ-CONNECTION-105
#[test]
fn connection_and_candidate_verbs_use_exact_resources_and_explicit_bodies() {
    let (server, dir, credential) = prepared(vec![
        json_http_response("201 Created", initial_connection()),
        json_http_response("201 Created", group_pending()),
        json_http_response("200 OK", group_pending()),
        json_http_response("200 OK", candidate("verified")),
        json_http_response("200 OK", active_connection()),
        json_http_response(
            "200 OK",
            serde_json::json!({"items":[active_connection()],"nextCursor":null}),
        ),
        super::connection::no_authorizations(),
        super::connection::no_authorizations(),
        json_http_response("200 OK", active_connection()),
        json_http_response("200 OK", disconnected_connection()),
    ]);
    let token = token_file(&dir);
    let delegator = "prn_01k0z6r1w8f4jy2m7q9v3x5abc";
    let output = create_gitlab(
        &server,
        &credential,
        &token,
        &[
            "--delegator-principal-id",
            delegator,
            "--idempotency-key",
            "test-key",
        ],
    );
    let created = steps(&output, 0);
    assert_eq!(outcomes(&created), ["created", "submitted", "activated"]);
    for document in &created {
        assert_eq!(document["idempotencyKey"], "test-key", "{document}");
    }
    assert_eq!(created[0]["result"]["id"], CONNECTION);
    assert_eq!(created[1]["result"]["id"], CANDIDATE);
    assert_eq!(created[2]["result"]["state"], "active");
    assert_eq!(
        single(&list_gitlab(&server, &credential, &[]))["outcome"],
        "listed"
    );
    assert_eq!(
        single(&show_gitlab(&server, &credential, &[]))["outcome"],
        "shown"
    );
    let removed = single(&run_org(
        &server,
        &credential,
        &[
            "disconnect",
            CONNECTION,
            "--expected-version",
            "4",
            "--yes",
            "--idempotency-key",
            "test-key",
        ],
    ));
    assert_eq!(removed["outcome"], "disconnected");
    let requests = server.finish();
    let suffix = format!("/{CONNECTION}");
    request(
        &requests[0],
        "POST",
        "",
        Some(
            serde_json::json!({"instanceUrl":"https://gitlab.com","delegatorPrincipalId":delegator}),
        ),
        Some("test-key.create"),
    );
    request(
        &requests[1],
        "POST",
        &format!("{suffix}/credential-candidates"),
        Some(
            serde_json::json!({"expectedVersion":1,"kind":"group_access_token","token":SECRET,"delegatorPrincipalId":delegator}),
        ),
        Some("test-key.submit"),
    );
    request(&requests[2], "GET", &candidate_path(), None, None);
    request(&requests[3], "GET", &candidate_path(), None, None);
    request(
        &requests[4],
        "POST",
        &format!("{}/activate", candidate_path()),
        Some(serde_json::json!({"expectedProviderUserId":"42","dedicatedAutomation":true})),
        Some("test-key.activate"),
    );
    request(&requests[5], "GET", "?limit=100", None, None);
    request(&requests[8], "GET", &suffix, None, None);
    request(
        &requests[9],
        "POST",
        &format!("{suffix}/disconnect"),
        Some(serde_json::json!({"expectedVersion":4})),
        Some("test-key"),
    );
}

// REQ-CONNECTION-56
#[test]
fn a_candidate_that_fails_verification_ends_the_command_without_cancelling_it() {
    let instance = "https://gitlab.example.com";
    let mut connection = initial_connection();
    connection["instanceUrl"] = instance.into();
    let mut failed = group_pending();
    failed["instanceUrl"] = instance.into();
    failed["state"] = "failed".into();
    failed["failureCode"] = "identity-rejected".into();
    let (server, dir, credential) = prepared(vec![
        json_http_response("201 Created", connection),
        json_http_response("201 Created", group_pending()),
        json_http_response("200 OK", failed),
    ]);
    let token = token_file(&dir);
    let output = create_gitlab(&server, &credential, &token, &["--instance-url", instance]);
    let documents = steps(&output, 7);
    assert_eq!(
        outcomes(&documents),
        ["created", "submitted", "candidate_unavailable"]
    );
    let ending = &documents[2];
    assert_eq!(ending["failureCode"], "identity-rejected");
    assert_eq!(ending["connectionId"], CONNECTION);
    assert_eq!(ending["candidateId"], CANDIDATE);
    assert!(ending.get("cancellation").is_none(), "{ending}");
    let requests = server.finish();
    assert_eq!(requests.len(), 3);
    request(
        &requests[0],
        "POST",
        "",
        Some(serde_json::json!({"instanceUrl":instance})),
        None,
    );
    request(&requests[2], "GET", &candidate_path(), None, None);
}

// REQ-CONNECTION-56, REQ-CONNECTION-58, REQ-CONNECTION-74
#[test]
fn an_identity_other_than_the_confirmed_one_cancels_the_candidate() {
    for (answer, cancellation) in [
        (cancelled(), "acknowledged"),
        (
            http_response("500 Internal Server Error", None, b""),
            "failed",
        ),
    ] {
        let (server, dir, credential) = prepared(vec![
            json_http_response("201 Created", initial_connection()),
            json_http_response("201 Created", group_pending()),
            json_http_response("200 OK", verified_as("43")),
            answer,
        ]);
        let token = token_file(&dir);
        let output = create_gitlab(
            &server,
            &credential,
            &token,
            &["--idempotency-key", "mismatch-key"],
        );
        let documents = steps(&output, 8);
        assert_eq!(
            outcomes(&documents),
            ["created", "submitted", "identity_mismatch"]
        );
        let ending = &documents[2];
        assert_eq!(ending["connectionId"], CONNECTION);
        assert_eq!(ending["candidateId"], CANDIDATE);
        assert_eq!(ending["cancellation"], cancellation);
        assert_eq!(ending["idempotencyKey"], "mismatch-key");
        let requests = server.finish();
        assert_eq!(requests.len(), 4);
        request(
            &requests[3],
            "DELETE",
            &candidate_path(),
            None,
            Some("mismatch-key.cancel"),
        );
    }
}

// REQ-CONNECTION-56, REQ-CONNECTION-77
#[test]
fn a_wait_that_times_out_cancels_the_candidate() {
    let (server, dir, credential) = prepared(vec![
        json_http_response("201 Created", group_pending()),
        json_http_response("200 OK", group_pending()),
        cancelled(),
    ]);
    let token = token_file(&dir);
    let output = reconnect_gitlab(&server, &credential, &token, &["--timeout", "1ms"]);
    let documents = steps(&output, 1);
    assert_eq!(outcomes(&documents), ["submitted", "timed_out"]);
    assert_eq!(documents[1]["connectionId"], CONNECTION);
    assert_eq!(documents[1]["cancellation"], "acknowledged");
    let requests = server.finish();
    request(&requests[2], "DELETE", &candidate_path(), None, None);
}

// REQ-CONNECTION-56
#[test]
fn a_signal_while_the_candidate_is_pending_cancels_it() {
    for (signal, code) in [
        (rustix::process::Signal::INT, 130),
        (rustix::process::Signal::TERM, 143),
    ] {
        let (mut server, dir, credential) = prepared(vec![
            json_http_response("201 Created", group_pending()),
            cancelled(),
        ]);
        let token = token_file(&dir);
        let mut command = Command::new(crate::executable());
        command
            .args(["org", "integration", "reconnect", CONNECTION])
            .args(["--expected-version", "3", "--kind", "group-access-token"])
            .args(["--token-file", &token, "--idempotency-key", "signal-key"])
            .args(CONFIRM)
            .args(["--org", ORG, "--json", "--allow-insecure-http"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for variable in DEPLOYMENT_VARIABLES {
            command.env_remove(variable);
        }
        command.env_remove(CREDENTIALS_FILE_VARIABLE);
        command.envs(deployment_environment(&server.api_url, &credential));
        // The candidate is read only after the production cadence, so the signal finds it
        // pending.
        command.env("USEFUL_TEST_POLL_INTERVAL_MILLISECONDS", "5000");
        let child = command.spawn().unwrap();
        let submission = server.wait_for_request();
        assert_eq!(
            header_value(&submission, "idempotency-key"),
            "signal-key.submit"
        );
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap(),
            signal,
        )
        .unwrap();
        let output = child.wait_with_output().unwrap();
        let documents = steps(&output, code);
        assert_eq!(outcomes(&documents), ["submitted", "interrupted"]);
        let ending = &documents[1];
        assert_eq!(ending["connectionId"], CONNECTION);
        assert_eq!(ending["candidateId"], CANDIDATE);
        assert_eq!(ending["cancellation"], "acknowledged");
        assert_eq!(ending["idempotencyKey"], "signal-key");
        let requests = server.finish();
        assert_eq!(requests.len(), 1);
        request(
            &requests[0],
            "DELETE",
            &candidate_path(),
            None,
            Some("signal-key.cancel"),
        );
    }
}

// REQ-CONNECTION-58
#[test]
fn a_confirmation_that_cannot_be_asked_is_refused_before_any_request() {
    let (server, dir, credential) = prepared(vec![]);
    let token = token_file(&dir);
    let kind = [
        "--token-file",
        token.as_str(),
        "--kind",
        "group-access-token",
    ];
    for args in [
        [&["connect", "gitlab"][..], &kind].concat(),
        [&["reconnect", CONNECTION][..], &kind].concat(),
    ] {
        let output = run_org(&server, &credential, &args);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
    }
    // Without --json and in a new session, which has no terminal to ask on.
    let mut command = Command::new("python3");
    command
        .args([
            "-c",
            "import os, sys; os.setsid(); os.execv(sys.argv[1], sys.argv[1:])",
            crate::executable().to_str().unwrap(),
            "org",
            "integration",
            "connect",
            "gitlab",
        ])
        .args(kind)
        .args(["--org", ORG, "--allow-insecure-http"])
        .stdin(Stdio::null());
    for variable in DEPLOYMENT_VARIABLES {
        command.env_remove(variable);
    }
    command.envs(deployment_environment(&server.api_url, &credential));
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(server.finish().is_empty());
}

// REQ-CONNECTION-108, REQ-CONNECTION-57
#[test]
fn reconnect_stages_a_token_on_the_existing_connection() {
    let mut pending = candidate("pending");
    pending["accountUse"] = "service_account".into();
    let (server, dir, credential) = prepared(vec![
        json_http_response("200 OK", connection()),
        json_http_response("201 Created", pending),
        json_http_response("200 OK", candidate("verified")),
        json_http_response("200 OK", active_connection()),
    ]);
    let token = token_file(&dir);
    let reconnect = [
        "reconnect",
        CONNECTION,
        "--token-file",
        token.as_str(),
        "--kind",
        "service-account",
    ];
    let output = run_org(&server, &credential, &[&reconnect[..], &CONFIRM].concat());
    let documents = steps(&output, 0);
    assert_eq!(outcomes(&documents), ["submitted", "activated"]);
    assert_eq!(documents[1]["result"]["id"], CONNECTION);
    for args in [
        vec!["reconnect", CONNECTION],
        vec!["reconnect", CONNECTION, "--kind", "service-account"],
        vec!["reconnect", CONNECTION, "--token-file", token.as_str()],
    ] {
        let output = run_org(&server, &credential, &[&args[..], &CONFIRM].concat());
        assert_eq!(output.status.code(), Some(2), "{output:?}");
    }
    let requests = server.finish();
    assert_eq!(requests.len(), 4);
    request(&requests[0], "GET", &format!("/{CONNECTION}"), None, None);
    request(
        &requests[1],
        "POST",
        &format!("/{CONNECTION}/credential-candidates"),
        Some(
            serde_json::json!({"expectedVersion":3,"kind":"personal_access_token","accountUse":"service_account","token":SECRET}),
        ),
        None,
    );
    request(&requests[2], "GET", &candidate_path(), None, None);
    request(
        &requests[3],
        "POST",
        &format!("{}/activate", candidate_path()),
        Some(serde_json::json!({"expectedProviderUserId":"42","dedicatedAutomation":true})),
        None,
    );
}

// REQ-CONNECTION-106
#[test]
fn options_of_another_provider_are_refused_before_any_request() {
    let (server, dir, credential) = prepared(vec![]);
    let token = token_file(&dir);
    let gitlab = [
        "connect",
        "gitlab",
        "--token-file",
        token.as_str(),
        "--kind",
        "group-access-token",
    ];
    for args in [
        [&gitlab[..], &CONFIRM, &["--no-wait"]].concat(),
        [&gitlab[..], &CONFIRM, &["--state-updates"]].concat(),
        [&gitlab[..], &CONFIRM, &["--installation", "7"]].concat(),
        vec!["connect", "github", "--token-file", token.as_str()],
        vec!["connect", "github", "--timeout", "1m"],
        vec!["connect", "linear", "--kind", "group-access-token"],
        vec!["connect", "linear", "--instance-url", "https://gitlab.com"],
        vec![
            "reconnect",
            "ghi_01k0z6r1w8f4jy2m7q9v3x5abc",
            "--idempotency-key",
            "k",
        ],
        vec![
            "reconnect",
            "lcn_01k0z6r1w8f4jy2m7q9v3x5abc",
            "--expected-version",
            "3",
        ],
        [
            &["reconnect", CONNECTION, "--no-wait"][..],
            &gitlab[2..],
            &CONFIRM,
        ]
        .concat(),
    ] {
        let output = run_org(&server, &credential, &args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
    }
    assert!(server.finish().is_empty());
}

// REQ-CONNECTION-56, REQ-CONNECTION-72, REQ-CONNECTION-73
#[test]
fn repository_discovery_and_selection_use_exact_generated_actions() {
    let mut selected = active_connection();
    selected["version"] = 5.into();
    selected["selectedRepositoryIds"] = serde_json::json!(["123456789", "42"]);
    let mut removed = selected.clone();
    removed["version"] = 6.into();
    removed["selectedRepositoryIds"] = serde_json::json!([]);
    let page = serde_json::json!({"items":[{"providerRepositoryId":"123456789",
        "fullName":"group/subgroup/widget", "defaultBranch":"main", "selected":true,
        "availability":"unavailable"}], "nextCursor":"another-page"});
    let (server, _dir, credential) = prepared(vec![
        json_http_response("200 OK", page.clone()),
        json_http_response("200 OK", page.clone()),
        json_http_response("200 OK", page),
        json_http_response("200 OK", selected),
        json_http_response("200 OK", removed),
    ]);
    let doc = single(&list_repositories(
        &server,
        &credential,
        &["--selected", "--limit", "2"],
    ));
    assert_eq!(doc["outcome"], "repositories_listed");
    assert_eq!(doc["organizationRef"], ORG);
    assert!(doc["idempotencyKey"].is_null(), "{doc}");
    assert_eq!(doc["result"]["nextCursor"], "another-page");
    assert_eq!(doc["result"]["items"][0]["availability"], "unavailable");
    let human = run_with_env(
        &[
            &LIST_REPOSITORIES[..],
            &[
                "--search",
                "widget",
                "--cursor",
                "another-page",
                "--allow-insecure-http",
            ],
        ]
        .concat(),
        &deployment_environment(&server.api_url, &credential),
    );
    assert!(human.status.success(), "{human:?}");
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(text.starts_with("GitLab repositories: repositories listed\n"));
    assert!(text.contains("123456789  group/subgroup/widget  main  selected  unavailable"));
    assert!(text.contains("next cursor: another-page"));
    let exact = single(&list_repositories(
        &server,
        &credential,
        &["--repository-id", "123456789"],
    ));
    assert_eq!(
        exact["result"]["items"][0]["providerRepositoryId"],
        "123456789"
    );
    for (verb, version, outcome) in [("add", "4", "linked"), ("remove", "5", "removed")] {
        let args = [
            vec![
                "repository",
                verb,
                "123456789",
                "42",
                "--integration",
                CONNECTION,
                "--expected-version",
                version,
                "--idempotency-key",
                "selection-key",
                "--delegator-principal-id",
                "prn_01k0z6r1w8f4jy2m7q9v3x5abc",
            ],
            if verb == "remove" {
                vec!["--yes"]
            } else {
                vec![]
            },
        ]
        .concat();
        let doc = single(&run_org(&server, &credential, &args));
        assert_eq!(doc["outcome"], outcome);
        assert_eq!(doc["idempotencyKey"], "selection-key");
    }
    let requests = server.finish();
    request(
        &requests[0],
        "GET",
        &format!("/{CONNECTION}/repositories?limit=2&selected=true"),
        None,
        None,
    );
    request(
        &requests[1],
        "GET",
        &format!("/{CONNECTION}/repositories?cursor=another-page&search=widget"),
        None,
        None,
    );
    request(
        &requests[2],
        "GET",
        &format!("/{CONNECTION}/repositories?providerRepositoryId=123456789"),
        None,
        None,
    );
    for (index, version, field) in [
        (3, 4, "addProviderRepositoryIds"),
        (4, 5, "removeProviderRepositoryIds"),
    ] {
        request(
            &requests[index],
            "PATCH",
            &format!("/{CONNECTION}/repository-selection"),
            Some(serde_json::json!({
                "expectedVersion":version, (field):["123456789", "42"],
                "delegatorPrincipalId":"prn_01k0z6r1w8f4jy2m7q9v3x5abc"
            })),
            Some("selection-key"),
        );
    }
}

// REQ-CONNECTION-70
#[test]
fn repository_selection_preconditions_conflicts_and_lost_response_replay() {
    let (server, _dir, credential) = prepared(vec![]);
    let add = ["repository", "add"];
    let remove = ["repository", "remove"];
    let target = ["--integration", CONNECTION];
    for args in [
        [&add[..], &["0"], &target, &["--expected-version", "4"]].concat(),
        [&add[..], &["0"], &target].concat(),
        [
            &remove[..],
            &["42"],
            &target,
            &["--expected-version", "0", "--yes"],
        ]
        .concat(),
        [&add[..], &target, &["--expected-version", "4"]].concat(),
        [
            &add[..],
            &["42", "0"],
            &target,
            &["--expected-version", "4"],
        ]
        .concat(),
        [
            &remove[..],
            &["42", "+43"],
            &target,
            &["--expected-version", "4", "--yes"],
        ]
        .concat(),
        [
            &add[..],
            &["42", "9223372036854775808"],
            &target,
            &["--expected-version", "4"],
        ]
        .concat(),
    ] {
        let output = run_org(&server, &credential, &args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty());
    }
    for args in [
        &["--selected", "--search", "foo"][..],
        &["--repository-id", "01"],
    ] {
        let output = list_repositories(&server, &credential, args);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty());
    }
    assert!(server.finish().is_empty());

    let conflict = problem_http_response(
        "409 Conflict",
        serde_json::json!({
            "type":"https://api.usefulmachinery.com/problems/repository-unavailable",
            "title":"Conflict", "status":409, "detail":SECRET
        }),
    );
    let (server, _dir, credential) = prepared(vec![conflict]);
    let output = run_org(
        &server,
        &credential,
        &[&add[..], &["42"], &target, &["--expected-version", "4"]].concat(),
    );
    let doc = failure(&output, 6);
    assert_eq!(doc["outcome"], "conflict");
    assert!(
        doc["idempotencyKey"]
            .as_str()
            .is_some_and(|key| !key.is_empty())
    );
    assert_eq!(server.finish().len(), 1);

    for verb in ["add", "remove"] {
        let (server, _dir, credential) = prepared(vec![
            Vec::new(),
            json_http_response("200 OK", active_connection()),
        ]);
        let args = [
            vec![
                "repository",
                verb,
                "42",
                "43",
                "--integration",
                CONNECTION,
                "--expected-version",
                "3",
                "--idempotency-key",
                "replay-selection",
            ],
            if verb == "remove" {
                vec!["--yes"]
            } else {
                vec![]
            },
        ]
        .concat();
        let doc = single(&run_org(&server, &credential, &args));
        assert_eq!(doc["idempotencyKey"], "replay-selection");
        let calls = server.finish();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], calls[1]);
        request(
            &calls[0],
            "PATCH",
            &format!("/{CONNECTION}/repository-selection"),
            Some(serde_json::json!({
                "expectedVersion":3,
                (if verb == "add" { "addProviderRepositoryIds" } else { "removeProviderRepositoryIds" }):["42", "43"]
            })),
            Some("replay-selection"),
        );
    }
}

// REQ-CONNECTION-74, REQ-CONNECTION-107
#[test]
fn an_omitted_expected_version_is_read_from_the_connection_and_a_given_one_is_sent_unread() {
    // `gitlab` names the connection still in use, though a disconnected one stays listed.
    let mut removed = disconnected_connection();
    removed["id"] = "glc_01k0z6r1w8f4jy2m7q9v3x5xyz".into();
    removed["version"] = 9.into();
    let list = serde_json::json!({"items":[removed, active_connection()],"nextCursor":null});
    let (server, _dir, credential) = prepared(vec![
        json_http_response("200 OK", connection()),
        json_http_response("200 OK", disconnected_connection()),
        json_http_response("200 OK", disconnected_connection()),
        json_http_response("200 OK", active_connection()),
        json_http_response("200 OK", active_connection()),
        json_http_response("200 OK", list),
        json_http_response("200 OK", disconnected_connection()),
    ]);
    let key = ["--idempotency-key", "version-key"];
    for (args, outcome) in [
        (vec!["disconnect", CONNECTION, "--yes"], "disconnected"),
        (
            vec!["disconnect", CONNECTION, "--yes", "--expected-version", "3"],
            "disconnected",
        ),
        (
            vec!["repository", "add", "7", "8", "--integration", CONNECTION],
            "linked",
        ),
        (vec!["disconnect", "gitlab", "--yes"], "disconnected"),
    ] {
        let doc = single(&run_org(&server, &credential, &[&args[..], &key].concat()));
        assert_eq!(doc["outcome"], outcome, "{args:?}");
        assert_eq!(doc["idempotencyKey"], "version-key", "{args:?}");
    }
    let requests = server.finish();
    assert_eq!(requests.len(), 7);
    let suffix = format!("/{CONNECTION}");
    let disconnect = format!("{suffix}/disconnect");
    request(&requests[0], "GET", &suffix, None, None);
    assert!(useful_test_support::request_header(&requests[0], "idempotency-key").is_none());
    for (index, version) in [(1, 3), (2, 3), (6, 4)] {
        request(
            &requests[index],
            "POST",
            &disconnect,
            Some(serde_json::json!({"expectedVersion":version})),
            Some("version-key"),
        );
    }
    request(&requests[3], "GET", &suffix, None, None);
    request(
        &requests[4],
        "PATCH",
        &format!("{suffix}/repository-selection"),
        Some(serde_json::json!({"expectedVersion":4,"addProviderRepositoryIds":["7", "8"]})),
        Some("version-key"),
    );
    request(&requests[5], "GET", "?limit=100", None, None);
}

// REQ-CONNECTION-105
#[test]
fn active_connection_rendering_uses_only_nonsecret_metadata() {
    let mut active = active_connection();
    // A malformed upstream extension cannot turn an unknown field into CLI output.
    active["token"] = SECRET.into();
    let (server, _dir, credential) = prepared(vec![
        super::connection::no_authorizations(),
        json_http_response("200 OK", active),
    ]);
    let output = run_with_env(
        &[
            "org",
            "integration",
            "show",
            CONNECTION,
            "--org",
            ORG,
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential),
    );
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    for value in [
        "automation-bot",
        "42",
        "dedicated_user",
        "2027-09-05T00:00:00Z",
    ] {
        assert!(text.contains(value));
    }
    assert!(!text.contains(SECRET));
    assert_eq!(server.finish().len(), 2);
}

#[test]
fn human_candidate_review_shows_verified_identity_and_expiry_without_secret() {
    let (server, dir, credential) = prepared(vec![
        json_http_response("201 Created", candidate("pending")),
        json_http_response("200 OK", candidate("verified")),
        json_http_response("200 OK", active_connection()),
    ]);
    let token = token_file(&dir);
    let reconnect = [
        "org",
        "integration",
        "reconnect",
        CONNECTION,
        "--expected-version",
        "3",
        "--token-file",
        token.as_str(),
        "--kind",
        "dedicated-user",
        "--org",
        ORG,
        "--allow-insecure-http",
    ];
    let output = run_with_env(
        &[&reconnect[..], &CONFIRM].concat(),
        &deployment_environment(&server.api_url, &credential),
    );
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stdout);
    for value in [
        "automation-bot",
        "42",
        "dedicated_user",
        "api",
        "token expires (UTC instant): 2027-09-05T00:00:00Z",
    ] {
        assert!(text.contains(value), "{text}");
    }
    assert!(!text.contains(SECRET));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
    assert_eq!(server.finish().len(), 3);
}

#[expect(
    clippy::disallowed_methods,
    reason = "PTY prompt channel synchronizes by data; timeout only bounds a failed child"
)]
fn await_terminal_prompt(
    rx: &mpsc::Receiver<Vec<u8>>,
    child: &mut std::process::Child,
    transcript: &mut String,
    prompt: &str,
) {
    while !transcript.contains(prompt) {
        // The timeout only bounds a failed child/PTY, not prompt readiness.
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(bytes) => transcript.push_str(&String::from_utf8_lossy(&bytes)),
            Err(error) => {
                let _ = child.kill();
                let status = child.wait();
                let mut stderr = String::new();
                let _ = child.stderr.take().unwrap().read_to_string(&mut stderr);
                panic!(
                    "terminal prompt unavailable: {error}; status {status:?}; stderr {stderr}; {transcript}"
                );
            }
        }
    }
}

// REQ-CONNECTION-58
#[test]
fn terminal_review_requires_exact_identity_and_dedication_before_activation() {
    for (id, attestation, exit, last) in [
        ("41", None, 8, cancelled()),
        ("42", Some("not dedicated\n"), 2, cancelled()),
        (
            "42",
            Some("dedicated automation\n"),
            0,
            json_http_response("200 OK", active_connection()),
        ),
    ] {
        let (server, dir, credential) = prepared(vec![
            json_http_response("201 Created", group_pending()),
            json_http_response("200 OK", candidate("verified")),
            last,
        ]);
        let token = token_file(&dir);
        let pty = open_test_pty(None).unwrap();
        let peer = rustix::pty::ptsname(&pty.master, Vec::new()).unwrap();
        let mut writer = fs::File::from(rustix::io::dup(&pty.master).unwrap());
        // The CLI test environment includes Python. Its child makes a new session
        // and opens the slave as controlling tty before execing the actual CLI.
        let mut command = Command::new("python3");
        command.args(["-c", "import os,sys; os.setsid(); fd=os.open(sys.argv[1], os.O_RDWR); os.dup2(fd, 0); os.write(1, b'R'); os.execv(sys.argv[2], sys.argv[2:])"])
            .arg(peer.to_str().unwrap())
            .arg(crate::executable())
            .args(["org", "integration", "reconnect", CONNECTION, "--expected-version", "3",
                "--token-file", &token, "--kind", "group-access-token", "--org", ORG,
                "--allow-insecure-http"])
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        for variable in DEPLOYMENT_VARIABLES {
            command.env_remove(variable);
        }
        command.env_remove(CREDENTIALS_FILE_VARIABLE);
        for (name, value) in deployment_environment(&server.api_url, &credential) {
            command.env(name, value);
        }
        let mut child = command.spawn().unwrap();
        let mut ready = [0];
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut ready)
            .unwrap();
        assert_eq!(ready, *b"R");
        let (tx, rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut master = fs::File::from(pty.master);
            let mut buf = [0u8; 512];
            while let Ok(n) = master.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        drop(pty.slave);
        let mut transcript = String::new();
        await_terminal_prompt(
            &rx,
            &mut child,
            &mut transcript,
            "Enter the verified provider user ID: ",
        );
        assert!(transcript.contains("automation-bot (42)"));
        assert!(transcript.contains("token expires (UTC instant): 2027-09-05T00:00:00Z"));
        writer.write_all(format!("{id}\n").as_bytes()).unwrap();
        if let Some(attestation) = attestation {
            await_terminal_prompt(
                &rx,
                &mut child,
                &mut transcript,
                "Type 'dedicated automation'",
            );
            writer.write_all(attestation.as_bytes()).unwrap();
        }
        let output = child.wait_with_output().unwrap();
        drop(writer);
        reader.join().unwrap();
        assert_eq!(output.status.code(), Some(exit), "{output:?}");
        assert!(!transcript.contains(SECRET));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
        let requests = server.finish();
        assert_eq!(requests.len(), 3);
        let method = if exit == 0 { "POST" } else { "DELETE" };
        assert!(requests[2].starts_with(method), "{}", requests[2]);
    }
}

#[test]
fn mismatched_resource_response_cannot_authorize_identity_review() {
    let mut wrong = candidate("verified");
    wrong["connectionId"] = "glc_01k0z6r1w8f4jy2m7q9v3x5abd".into();
    let (server, dir, credential) = prepared(vec![
        json_http_response("201 Created", group_pending()),
        json_http_response("200 OK", wrong),
        cancelled(),
    ]);
    let token = token_file(&dir);
    let documents = steps(&reconnect_gitlab(&server, &credential, &token, &[]), 1);
    assert_eq!(outcomes(&documents), ["submitted", "invalid_response"]);
    assert_eq!(documents[1]["cancellation"], "acknowledged");
    let requests = server.finish();
    request(&requests[2], "DELETE", &candidate_path(), None, None);
}

// REQ-CONNECTION-58
#[test]
fn help_links_public_setup_and_requires_explicit_activation_flags() {
    for args in [
        vec!["org", "integration", "connect", "--help"],
        vec!["org", "integration", "reconnect", "--help"],
        vec!["org", "integration", "repository", "list", "--help"],
        vec!["org", "integration", "repository", "add", "--help"],
        vec!["project", "create", "--help"],
        vec!["project", "update", "--help"],
    ] {
        let output = run(&args);
        assert!(output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("https://docs.usefulmachinery.com/agent/gitlab-setup.md"),
            "{args:?}"
        );
    }
    let output = run(&[
        "org",
        "integration",
        "connect",
        "gitlab",
        "--token-file",
        "token",
        "--kind",
        "group-access-token",
        "--expected-provider-user-id",
        "42",
    ]);
    assert_eq!(output.status.code(), Some(2));
    // The refusal is the missing attestation, not the token file that does not exist.
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--dedicated-automation"),
        "{output:?}"
    );
}

// REQ-CONNECTION-77, REQ-CONNECTION-104
#[test]
fn authentication_and_candidate_conflicts_have_distinct_exits() {
    let problem = |status, code, kind| {
        problem_http_response(
            status,
            serde_json::json!({
        "type":format!("https://api.usefulmachinery.com/problems/{kind}"),"title":"Rejected", "status":code,"detail":SECRET}),
        )
    };
    let (server, dir, credential) = prepared(vec![
        problem("401 Unauthorized", 401, "unauthorized"),
        problem("409 Conflict", 409, "candidate-conflict"),
        problem("503 Service Unavailable", 503, "service-unavailable"),
        problem("503 Service Unavailable", 503, "provider-unavailable"),
        problem("500 Internal Server Error", 500, "internal"),
    ]);
    let token = token_file(&dir);
    let service_path = dir.path().join("service.key");
    fs::write(
        &service_path,
        "crd_01k0z6r1w8f4jy2m7q9v3x5abc.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
    )
    .unwrap();
    fs::set_permissions(&service_path, Permissions::from_mode(0o600)).unwrap();
    for (args, exit, outcome) in [
        (vec!["show"], 3, "unauthenticated"),
        (vec!["reconnect"], 6, "conflict"),
        (vec!["list"], 4, "service_unavailable"),
        (vec!["repository"], 4, "provider_unavailable"),
        (vec!["show"], 4, "unreachable"),
    ] {
        let mutation = args.contains(&"reconnect");
        let args = [args, vec!["--api-key-file", service_path.to_str().unwrap()]].concat();
        let output = if args[0] == "list" {
            list_gitlab(&server, &credential, &args[1..])
        } else if args[0] == "show" {
            show_gitlab(&server, &credential, &args[1..])
        } else if args[0] == "repository" {
            list_repositories(&server, &credential, &args[1..])
        } else {
            reconnect_gitlab(&server, &credential, &token, &args[1..])
        };
        let doc = failure(&output, exit);
        assert_eq!(doc["outcome"], outcome);
        assert!(doc["deployment"].as_str().is_some_and(|d| !d.is_empty()));
        if mutation {
            assert!(
                doc["idempotencyKey"]
                    .as_str()
                    .is_some_and(|key| !key.is_empty())
            );
        } else {
            assert!(doc["idempotencyKey"].is_null(), "{doc}");
        }
        if outcome == "unreachable" {
            assert_eq!(doc["category"], "server");
        } else {
            assert!(doc.get("category").is_none(), "{doc}");
        }
    }
    assert_eq!(server.finish().len(), 5);
}

// REQ-CONNECTION-74
#[test]
fn a_server_error_answer_to_a_mutation_is_not_repeated() {
    // Only one answer is scripted: a repeat would find no listener and report `connection`.
    let (server, dir, credential) =
        prepared(vec![http_response("500 Internal Server Error", None, b"")]);
    let token = token_file(&dir);
    let doc = failure(
        &reconnect_gitlab(
            &server,
            &credential,
            &token,
            &["--idempotency-key", "server-error-key"],
        ),
        4,
    );
    assert_eq!(doc["outcome"], "unreachable");
    assert_eq!(doc["category"], "server");
    assert_eq!(doc["idempotencyKey"], "server-error-key");
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    request(
        &requests[0],
        "POST",
        &format!("/{CONNECTION}/credential-candidates"),
        None,
        Some("server-error-key.submit"),
    );
}

// REQ-CONNECTION-57
#[test]
fn credential_kinds_select_only_the_approved_token_declaration() {
    for (flag, kind, account) in [
        ("group-access-token", "group_access_token", None),
        (
            "service-account",
            "personal_access_token",
            Some("service_account"),
        ),
        (
            "dedicated-user",
            "personal_access_token",
            Some("dedicated_user"),
        ),
    ] {
        let mut response = candidate("pending");
        response["kind"] = kind.into();
        response["accountUse"] = account.into();
        let mut failed = response.clone();
        failed["state"] = "failed".into();
        let (server, dir, credential) = prepared(vec![
            json_http_response("201 Created", response),
            json_http_response("200 OK", failed),
        ]);
        let token = token_file(&dir);
        let reconnect = [
            "reconnect",
            CONNECTION,
            "--expected-version",
            "3",
            "--kind",
            flag,
            "--token-file",
            token.as_str(),
        ];
        let output = run_org(&server, &credential, &[&reconnect[..], &CONFIRM].concat());
        assert_eq!(outcomes(&steps(&output, 7))[0], "submitted");
        let requests = server.finish();
        let body: serde_json::Value =
            serde_json::from_str(requests[0].split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(body["kind"], kind);
        assert_eq!(body["accountUse"].as_str(), account);
        assert_eq!(body["expectedVersion"], 3);
        assert_eq!(body["token"], SECRET);
        if account.is_none() {
            assert!(body.get("accountUse").is_none());
        }
    }
}

// REQ-CONNECTION-57, REQ-CONNECTION-74
#[test]
fn unsafe_token_sources_and_versions_fail_before_network_use() {
    use std::os::unix::fs::symlink;
    let (server, dir, credential) = prepared(vec![]);
    let token = dir.path().join("token");
    fs::write(&token, SECRET).unwrap();
    let alias = dir.path().join("alias");
    symlink(&token, &alias).unwrap();
    for (path, mode) in [(&token, 0o400), (&token, 0o644), (&alias, 0o600)] {
        fs::set_permissions(&token, Permissions::from_mode(mode)).unwrap();
        let output = create_gitlab(&server, &credential, path.to_str().unwrap(), &[]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains(SECRET));
    }
    fs::set_permissions(&token, Permissions::from_mode(0o600)).unwrap();
    let path = token.to_str().unwrap();
    // A key of 241 characters leaves no room for the suffix of a step.
    let long_key = "k".repeat(241);
    let output = create_gitlab(
        &server,
        &credential,
        path,
        &["--idempotency-key", &long_key],
    );
    assert_eq!(output.status.code(), Some(2));
    for version in ["0", "-1", "9007199254740992"] {
        let output = run_org(
            &server,
            &credential,
            &[
                &[
                    "reconnect",
                    CONNECTION,
                    "--expected-version",
                    version,
                    "--kind",
                    "group-access-token",
                    "--token-file",
                    path,
                ][..],
                &CONFIRM,
            ]
            .concat(),
        );
        assert_eq!(output.status.code(), Some(2));
        let output = run_org(
            &server,
            &credential,
            &[
                "disconnect",
                CONNECTION,
                "--expected-version",
                version,
                "--yes",
            ],
        );
        assert_eq!(output.status.code(), Some(2));
    }
    fs::write(&token, vec![b'x'; 16386]).unwrap();
    let output = create_gitlab(&server, &credential, path, &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(server.finish().is_empty());
}

// REQ-CONNECTION-58, REQ-CONNECTION-74
#[test]
fn a_lost_mutation_response_replays_the_same_key_and_body() {
    // A closed socket with no HTTP response is an ambiguous transport result.
    let (server, dir, credential) = prepared(vec![
        Vec::new(),
        json_http_response("201 Created", initial_connection()),
        Vec::new(),
        json_http_response("201 Created", group_pending()),
        json_http_response("200 OK", candidate("verified")),
        Vec::new(),
        json_http_response("200 OK", active_connection()),
        Vec::new(),
        json_http_response("200 OK", disconnected_connection()),
    ]);
    let token = token_file(&dir);
    let key = ["--idempotency-key", "replay-key"];
    let created = steps(&create_gitlab(&server, &credential, &token, &key), 0);
    assert_eq!(outcomes(&created), ["created", "submitted", "activated"]);
    single(&run_org(
        &server,
        &credential,
        &[
            &["disconnect", CONNECTION, "--expected-version", "4", "--yes"][..],
            &key,
        ]
        .concat(),
    ));
    let requests = server.finish();
    for (pair, step) in [
        (&requests[0..2], "replay-key.create"),
        (&requests[2..4], "replay-key.submit"),
        (&requests[5..7], "replay-key.activate"),
        (&requests[7..9], "replay-key"),
    ] {
        assert_eq!(header_value(&pair[0], "idempotency-key"), step);
        assert_eq!(header_value(&pair[1], "idempotency-key"), step);
        assert_eq!(
            pair[0].split_once("\r\n\r\n").unwrap().1,
            pair[1].split_once("\r\n\r\n").unwrap().1
        );
        assert_eq!(
            pair[0].split_once(" HTTP/").unwrap().0,
            pair[1].split_once(" HTTP/").unwrap().0
        );
    }
}

// REQ-CONNECTION-74
#[test]
fn generated_key_survives_two_lost_responses_and_recovers_on_later_invocation() {
    let (server, dir, credential) = prepared(vec![
        Vec::new(),
        Vec::new(),
        json_http_response("201 Created", initial_connection()),
        json_http_response("201 Created", group_pending()),
        json_http_response("200 OK", candidate("verified")),
        json_http_response("200 OK", active_connection()),
    ]);
    let token = token_file(&dir);
    let lost = failure(&create_gitlab(&server, &credential, &token, &[]), 4);
    assert_eq!(lost["outcome"], "unreachable");
    assert_eq!(lost["category"], "connection");
    let key = lost["idempotencyKey"].as_str().unwrap();
    assert!(!key.is_empty());
    let created = steps(
        &create_gitlab(&server, &credential, &token, &["--idempotency-key", key]),
        0,
    );
    for document in &created {
        assert_eq!(document["idempotencyKey"], key);
    }
    let requests = server.finish();
    assert_eq!(requests.len(), 6);
    for request_text in &requests[..3] {
        request(
            request_text,
            "POST",
            "",
            Some(serde_json::json!({"instanceUrl":"https://gitlab.com"})),
            Some(&format!("{key}.create")),
        );
    }
}

// REQ-CONNECTION-74
#[test]
fn explicit_activation_replay_recovers_after_terminal_or_missing_candidate() {
    for terminal in [
        json_http_response("200 OK", candidate("activated")),
        not_found(),
    ] {
        let (server, dir, credential) = prepared(vec![
            json_http_response("201 Created", initial_connection()),
            json_http_response("201 Created", group_pending()),
            json_http_response("200 OK", candidate("verified")),
            Vec::new(),
            Vec::new(),
            cancelled(),
            json_http_response("201 Created", initial_connection()),
            json_http_response("201 Created", group_pending()),
            terminal,
            json_http_response("200 OK", active_connection()),
        ]);
        let token = token_file(&dir);
        let key = ["--idempotency-key", "activation-replay-key"];
        let first = steps(&create_gitlab(&server, &credential, &token, &key), 4);
        assert_eq!(outcomes(&first), ["created", "submitted", "unreachable"]);
        assert_eq!(first[2]["idempotencyKey"], "activation-replay-key");
        let replay = steps(&create_gitlab(&server, &credential, &token, &key), 0);
        assert_eq!(replay[2]["result"]["state"], "active");
        let calls = server.finish();
        assert_eq!(calls.len(), 10);
        for i in [3, 4, 9] {
            request(
                &calls[i],
                "POST",
                &format!("{}/activate", candidate_path()),
                Some(serde_json::json!({"expectedProviderUserId":"42","dedicatedAutomation":true})),
                Some("activation-replay-key.activate"),
            );
        }
    }
}

#[test]
fn vanished_candidate_is_unavailable_for_activation() {
    let pending = || json_http_response("201 Created", group_pending());
    for script in [
        vec![pending(), not_found()],
        vec![
            pending(),
            json_http_response("200 OK", candidate("activated")),
        ],
        vec![
            pending(),
            json_http_response("200 OK", candidate("verified")),
            not_found(),
        ],
    ] {
        let expected_calls = script.len();
        let (server, dir, credential) = prepared(script);
        let token = token_file(&dir);
        let documents = steps(&reconnect_gitlab(&server, &credential, &token, &[]), 7);
        assert_eq!(outcomes(&documents), ["submitted", "candidate_unavailable"]);
        assert_eq!(server.finish().len(), expected_calls);
    }
}

// REQ-CONNECTION-77
#[test]
fn candidate_submission_and_activation_conflicts_do_not_retry() {
    let conflict = |kind: &str| {
        problem_http_response(
            "409 Conflict",
            serde_json::json!({
            "type":format!("https://api.usefulmachinery.com/problems/{kind}"),
            "title":"Conflict","status":409,"detail":"candidate changed"}),
        )
    };
    let (server, dir, credential) = prepared(vec![
        conflict("candidate-conflict"),
        json_http_response("201 Created", group_pending()),
        json_http_response("200 OK", candidate("verified")),
        conflict("candidate-conflict"),
        cancelled(),
        conflict("connection-version-conflict"),
    ]);
    let token = token_file(&dir);
    let output = reconnect_gitlab(&server, &credential, &token, &[]);
    assert_eq!(failure(&output, 6)["outcome"], "conflict");
    let documents = steps(&reconnect_gitlab(&server, &credential, &token, &[]), 6);
    assert_eq!(outcomes(&documents), ["submitted", "conflict"]);
    assert_eq!(documents[1]["cancellation"], "acknowledged");
    let output = run_org(
        &server,
        &credential,
        &["disconnect", CONNECTION, "--expected-version", "3", "--yes"],
    );
    assert_eq!(failure(&output, 6)["outcome"], "conflict");
    assert_eq!(server.finish().len(), 6);
}

// REQ-CONNECTION-57
#[test]
fn token_stdin_is_exclusive_and_never_printed() {
    let mut failed = group_pending();
    failed["state"] = "failed".into();
    let (server, _dir, credential) = prepared(vec![
        json_http_response("201 Created", group_pending()),
        json_http_response("200 OK", failed),
    ]);
    let args = [
        &[
            "org",
            "integration",
            "reconnect",
            CONNECTION,
            "--expected-version",
            "3",
            "--kind",
            "group-access-token",
            "--token-file",
            "-",
            "--org",
            ORG,
            "--json",
            "--allow-insecure-http",
        ][..],
        &CONFIRM,
    ]
    .concat();
    let output = run_with_stdin(
        &args,
        &deployment_environment(&server.api_url, &credential),
        SECRET.as_bytes(),
    );
    assert_eq!(steps(&output, 7)[0]["result"]["state"], "pending");
    let request = server.finish();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request[0].split_once("\r\n\r\n").unwrap().1)
            .unwrap()["token"],
        SECRET
    );
    let (server, _dir, credential) = prepared(vec![]);
    let args = [args.as_slice(), &["--api-key-file", "-"]].concat();
    let output = run_with_stdin(
        &args,
        &deployment_environment(&server.api_url, &credential),
        SECRET.as_bytes(),
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(server.finish().is_empty());
}
