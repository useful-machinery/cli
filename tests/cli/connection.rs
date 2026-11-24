use super::*;

const TOKEN: &str = "private-linear-token-sentinel";
const SECRET: &str = "private-linear-verifier-sentinel";
const ORG: &str = "acme-research";
const SESSION: &str = "las_01k0z6r1w8f4jy2m7q9v3x5abc";
const CONNECTION: &str = "lcn_01k0z6r1w8f4jy2m7q9v3x5abc";
const ORG_ID: &str = "org_01k0z6r1w8f4jy2m7q9v3x5abc";

fn prepared(responses: Vec<Vec<u8>>) -> (ScriptedServer, tempfile::TempDir, String) {
    let server = ScriptedServer::respond(responses);
    let directory = private_credential_directory();
    let path = directory.path().join("credentials.json");
    write_credential_fixture(&path, &server.api_url, TOKEN, "2999-01-01T00:00:00Z");
    (server, directory, path.to_str().unwrap().to_owned())
}
/// The organization's connection authorizations in force: none.
pub(super) fn no_authorizations() -> Vec<u8> {
    json_http_response("200 OK", serde_json::json!({"items": []}))
}
/// The answer of a deployment that predates the served-providers read, which serves no token
/// service.
pub(super) fn serving_nothing() -> Vec<u8> {
    problem_http_response(
        "404 Not Found",
        serde_json::json!({"type":"https://api.usefulmachinery.com/problems/not-found",
            "title":"Not found","status":404}),
    )
}
pub(super) fn session(status: &str) -> serde_json::Value {
    let mut value = serde_json::json!({"id": SESSION, "organizationId": ORG_ID, "operation":"connect", "status":status,
        "createdAt":"2026-09-05T12:00:00Z", "expiresAt":"2026-09-05T12:15:00Z", "verifier":SECRET});
    if status == "pending" {
        value.as_object_mut().unwrap().insert(
            "authorizationUrl".into(),
            "https://linear.example/oauth/authorize?state=public-fixture-state".into(),
        );
    }
    value
}
/// An active connection of the workspace `Research`, with a member the contract does not name.
pub(super) fn connection() -> serde_json::Value {
    serde_json::json!({"id":CONNECTION,"organizationId":ORG_ID,"status":"active", "workspaceId":"workspace-1",
        "workspaceName":"Research", "requiredScopes":["read"], "grantedScopes":["read"], "stateUpdatesConsented":false,
        "lifecycleGeneration":1,"createdAt":"2026-09-05T12:00:00Z","updatedAt":"2026-09-05T12:01:00Z", "token":SECRET})
}
/// A session completed with the connection it made.
pub(super) fn completed_session() -> serde_json::Value {
    let mut value = session("completed");
    value
        .as_object_mut()
        .unwrap()
        .insert("resultConnection".into(), connection());
    value
}
fn env_run(server: &ScriptedServer, credential: &str, args: &[&str]) -> Output {
    run_with_env(args, &deployment_environment(&server.api_url, credential))
}
fn lines(output: &Output) -> Vec<serde_json::Value> {
    output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

#[test]
fn create_linear_with_state_updates_connects_and_waits_for_the_session() {
    let mut pending = session("pending");
    pending.as_object_mut().unwrap().insert(
        "requestedScopes".into(),
        serde_json::json!(["read", "write"]),
    );
    let mut done = session("completed");
    done.as_object_mut()
        .unwrap()
        .insert("resultConnection".into(), connection());
    let (server, _dir, credential) = prepared(vec![
        json_http_response("201 Created", pending),
        json_http_response("200 OK", done),
    ]);
    let output = env_run(
        &server,
        &credential,
        &[
            "org",
            "integration",
            "connect",
            "linear",
            "--org",
            ORG,
            "--state-updates",
            "--json",
            "--allow-insecure-http",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events = lines(&output);
    assert_eq!(
        events
            .iter()
            .map(|line| line["outcome"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["pending", "completed"]
    );
    assert!(
        events[0]["session"]["authorizationUrl"]
            .as_str()
            .unwrap()
            .starts_with("https://linear.example/")
    );
    assert_eq!(
        events[0]["session"]["requestedScopes"],
        serde_json::json!(["read", "write"])
    );
    assert_no_secret_output(&output, &[TOKEN, SECRET]);
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with(&format!(
        "POST /api/v1/organizations/{ORG}/connections/linear/authorization-sessions "
    )));
    let body: serde_json::Value =
        serde_json::from_str(requests[0].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body["operation"], "connect");
    assert_eq!(body["enableStateUpdates"], true);
    assert!(requests[1].contains(&format!("/authorization-sessions/{SESSION} ")));
}

#[test]
fn team_list_and_show_page_discovery_and_print_full_set_suggestions() {
    let (server, _dir, credential) = prepared(vec![
        json_http_response(
            "200 OK",
            serde_json::json!({"items":[{"id":"team","name":"Example"}],"nextCursor":"teams-page"}),
        ),
        json_http_response(
            "200 OK",
            serde_json::json!({"items":[{"id":"first","name":"Working","type":"started"}],
            "nextCursor":"states-page","presetSuggestions":{"started":{"status":"suggested","stateId":"first"},
            "succeeded":{"status":"suggested","stateId":"outside-page"},"failed":{"status":"ambiguous"}}}),
        ),
    ]);
    let teams = env_run(
        &server,
        &credential,
        &[
            "org",
            "integration",
            "team",
            "list",
            CONNECTION,
            "--limit",
            "2",
            "--cursor",
            "C",
            "--org",
            ORG,
            "--json",
            "--allow-insecure-http",
        ],
    );
    assert!(
        teams.status.success(),
        "{}",
        String::from_utf8_lossy(&teams.stderr)
    );
    assert_eq!(
        lines(&teams),
        [
            serde_json::json!({"schemaVersion":1,"deployment":server.api_url,"organizationRef":ORG,
            "connectionId":CONNECTION,"outcome":"listed","items":[{"id":"team","name":"Example"}],
            "nextCursor":"teams-page"})
        ]
    );
    let states = env_run(
        &server,
        &credential,
        &[
            "org",
            "integration",
            "team",
            "show",
            "team",
            "--integration",
            CONNECTION,
            "--limit",
            "2",
            "--org",
            ORG,
            "--json",
            "--allow-insecure-http",
        ],
    );
    assert!(
        states.status.success(),
        "{}",
        String::from_utf8_lossy(&states.stderr)
    );
    let document = &lines(&states)[0];
    assert_eq!(document["outcome"], "listed");
    assert_eq!(document["organizationRef"], ORG);
    assert_eq!(document["connectionId"], CONNECTION);
    assert_eq!(document["teamId"], "team");
    assert_eq!(document["items"][0]["id"], "first");
    assert_eq!(document["nextCursor"], "states-page");
    assert_eq!(
        document["presetSuggestions"]["succeeded"]["stateId"],
        "outside-page"
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with(&format!(
        "GET /api/v1/organizations/{ORG}/connections/linear/{CONNECTION}/teams?limit=2&cursor=C HTTP/1.1\r\n"
    )));
    assert!(requests[1].starts_with(&format!(
        "GET /api/v1/organizations/{ORG}/connections/linear/{CONNECTION}/teams/team/states?limit=2 HTTP/1.1\r\n"
    )));
}

#[test]
fn discovery_rejects_open_or_inconsistent_suggestion_records() {
    for payload in [
        serde_json::json!({"items":[],"presetSuggestions":{"started":{"status":"ambiguous","stateId":"unexpected"},
            "succeeded":{"status":"not_found"},"failed":{"status":"not_found"}}}),
        serde_json::json!({"items":[],"presetSuggestions":{"started":{"status":"suggested","stateId":"state","extra":"unknown"},
            "succeeded":{"status":"not_found"},"failed":{"status":"not_found"}}}),
    ] {
        let (server, _dir, credential) = prepared(vec![json_http_response("200 OK", payload)]);
        let output = env_run(
            &server,
            &credential,
            &[
                "org",
                "integration",
                "team",
                "show",
                "team",
                "--integration",
                CONNECTION,
                "--org",
                ORG,
                "--json",
                "--allow-insecure-http",
            ],
        );
        assert!(!output.status.success());
        assert!(
            lines(&output)
                .iter()
                .all(|event| event["outcome"] != "listed")
        );
        server.finish();
    }
}

#[test]
fn consent_handoff_and_later_authorization_inspection_are_nonsecret() {
    let (server, _dir, credential) = prepared(vec![
        json_http_response("201 Created", session("pending")),
        json_http_response("200 OK", completed_session()),
    ]);
    let started = env_run(
        &server,
        &credential,
        &[
            "org",
            "integration",
            "connect",
            "linear",
            "--org",
            ORG,
            "--no-wait",
            "--json",
            "--allow-insecure-http",
        ],
    );
    assert!(started.status.success());
    let events = lines(&started);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["outcome"], "pending");
    assert_eq!(events[0]["session"]["id"], SESSION);
    assert!(
        events[0]["session"]["authorizationUrl"]
            .as_str()
            .unwrap()
            .starts_with("https://linear.example/")
    );
    let inspected = env_run(
        &server,
        &credential,
        &[
            "org",
            "integration",
            "show",
            SESSION,
            "--org",
            ORG,
            "--json",
            "--allow-insecure-http",
        ],
    );
    assert!(inspected.status.success());
    assert_eq!(
        lines(&inspected)[0]["session"]["resultConnection"]["id"],
        CONNECTION
    );
    assert_eq!(lines(&inspected)[0]["outcome"], "completed");
    for output in [&started, &inspected] {
        assert_no_secret_output(output, &[TOKEN, SECRET]);
    }
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with(&format!(
        "POST /api/v1/organizations/{ORG}/connections/linear/authorization-sessions "
    )));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(requests[0].split_once("\r\n\r\n").unwrap().1)
            .unwrap()["operation"],
        "connect"
    );
    assert!(requests[1].contains(&format!("/authorization-sessions/{SESSION} ")));
}

#[test]
fn polling_completion_uses_the_same_session_and_shows_connection_metadata() {
    let (server, _dir, credential) = prepared(vec![
        json_http_response("201 Created", session("pending")),
        json_http_response("200 OK", completed_session()),
    ]);
    let output = env_run(
        &server,
        &credential,
        &[
            "org",
            "integration",
            "connect",
            "linear",
            "--org",
            ORG,
            "--json",
            "--allow-insecure-http",
        ],
    );
    assert!(output.status.success());
    assert_eq!(
        lines(&output)
            .iter()
            .map(|line| line["outcome"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["pending", "completed"]
    );
    assert_eq!(
        lines(&output)[1]["session"]["resultConnection"]["id"],
        CONNECTION
    );
    assert_eq!(
        lines(&output)[1]["session"]["resultConnection"]["workspaceId"],
        "workspace-1"
    );
    assert_no_secret_output(&output, &[TOKEN, SECRET]);
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains(&format!("/authorization-sessions/{SESSION} ")));
}

fn reauthorizing(connection: &str) -> serde_json::Value {
    let mut reauthorized = session("pending");
    reauthorized["operation"] = "reauthorize".into();
    reauthorized["connectionId"] = connection.into();
    reauthorized
}
fn reconnect(server: &ScriptedServer, credential: &str, connection: &str) -> Output {
    env_run(
        server,
        credential,
        &[
            "org",
            "integration",
            "reconnect",
            connection,
            "--org",
            ORG,
            "--no-wait",
            "--json",
            "--allow-insecure-http",
        ],
    )
}
fn request_body(request: &str) -> serde_json::Value {
    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
}

#[test]
fn reauthorization_targets_only_the_requested_connection() {
    let (server, _dir, credential) = prepared(vec![json_http_response(
        "201 Created",
        reauthorizing(CONNECTION),
    )]);
    let output = reconnect(&server, &credential, CONNECTION);
    assert!(output.status.success());
    assert_eq!(lines(&output)[0]["outcome"], "pending");
    assert_eq!(lines(&output)[0]["session"]["connectionId"], CONNECTION);
    assert_eq!(lines(&output)[0]["session"]["operation"], "reauthorize");
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with(&format!(
        "POST /api/v1/organizations/{ORG}/connections/linear/authorization-sessions "
    )));
    assert_eq!(request_body(&requests[0])["operation"], "reauthorize");
    assert_eq!(request_body(&requests[0])["connectionId"], CONNECTION);
    assert_no_secret_output(&output, &[TOKEN, SECRET]);
}

#[test]
fn reconnect_of_the_provider_reauthorizes_the_connection_its_list_names() {
    let (server, _dir, credential) = prepared(vec![
        linear_list(&[
            linear_connection(SECOND_CONNECTION, "deleted"),
            linear_connection(CONNECTION, "recovery_required"),
        ]),
        json_http_response("201 Created", reauthorizing(CONNECTION)),
    ]);
    let output = reconnect(&server, &credential, "linear");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(lines(&output)[0]["session"]["connectionId"], CONNECTION);
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(linear_list_request(&requests[0]), "{}", requests[0]);
    assert_eq!(request_body(&requests[1])["operation"], "reauthorize");
    assert_eq!(request_body(&requests[1])["connectionId"], CONNECTION);
}

#[test]
fn reconnect_of_a_linear_connection_refuses_gitlab_token_options_without_contacting_the_deployment()
{
    let (server, _dir, credential) = prepared(Vec::new());
    let output = env_run(
        &server,
        &credential,
        &[
            "org",
            "integration",
            "reconnect",
            CONNECTION,
            "--token-file",
            "t",
            "--kind",
            "group-access-token",
            "--org",
            ORG,
            "--json",
            "--allow-insecure-http",
        ],
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(server.finish().is_empty());
}

#[test]
fn reauthorization_conflict_and_role_loss_have_distinct_outcomes() {
    let problem = |status: &str, code: u16, kind: &str| {
        problem_http_response(
            status,
            serde_json::json!({
                "type": format!("https://api.usefulmachinery.com/problems/{kind}"), "title": SECRET, "status":code,"detail":SECRET
            }),
        )
    };
    let (server, _dir, credential) = prepared(vec![
        problem("409 Conflict", 409, "source-connection-conflict"),
        problem("403 Forbidden", 403, "forbidden"),
    ]);
    let conflict = env_run(
        &server,
        &credential,
        &[
            "org",
            "integration",
            "reconnect",
            CONNECTION,
            "--org",
            ORG,
            "--no-wait",
            "--json",
            "--allow-insecure-http",
        ],
    );
    assert_eq!(conflict.status.code(), Some(1));
    assert_eq!(lines(&conflict)[0]["outcome"], "conflict");
    let lost_role = env_run(
        &server,
        &credential,
        &[
            "org",
            "integration",
            "show",
            SESSION,
            "--org",
            ORG,
            "--json",
            "--allow-insecure-http",
        ],
    );
    assert_eq!(lost_role.status.code(), Some(1));
    assert_eq!(lines(&lost_role)[0]["outcome"], "forbidden");
    assert_no_secret_output(&conflict, &[TOKEN, SECRET]);
    assert_no_secret_output(&lost_role, &[TOKEN, SECRET]);
    let requests = server.finish();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(requests[0].split_once("\r\n\r\n").unwrap().1)
            .unwrap()["connectionId"],
        CONNECTION
    );
}

#[test]
fn lost_start_response_reuses_one_key_and_does_not_create_second_session() {
    let (server, _dir, credential) = prepared(vec![
        Vec::new(),
        json_http_response("201 Created", session("pending")),
    ]);
    let output = env_run(
        &server,
        &credential,
        &[
            "org",
            "integration",
            "connect",
            "linear",
            "--org",
            ORG,
            "--no-wait",
            "--json",
            "--allow-insecure-http",
        ],
    );
    assert!(output.status.success());
    assert_eq!(lines(&output)[0]["session"]["id"], SESSION);
    assert_no_secret_output(&output, &[TOKEN, SECRET]);
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        header_value(&requests[0], "idempotency-key"),
        header_value(&requests[1], "idempotency-key")
    );
}

#[test]
fn unresolved_start_retries_only_within_this_invocation() {
    let (server, _dir, credential) = prepared(vec![Vec::new(), Vec::new()]);
    let output = env_run(
        &server,
        &credential,
        &[
            "org",
            "integration",
            "connect",
            "linear",
            "--org",
            ORG,
            "--no-wait",
            "--json",
            "--allow-insecure-http",
        ],
    );
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(lines(&output)[0]["outcome"], "unreachable");
    assert!(lines(&output)[0]["sessionId"].is_null());
    assert!(lines(&output)[0]["idempotencyKey"].is_null());
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        header_value(&requests[0], "idempotency-key"),
        header_value(&requests[1], "idempotency-key")
    );
    assert_no_secret_output(&output, &[TOKEN, SECRET]);
}

#[test]
fn ambiguous_poll_response_keeps_known_session_without_restarting_consent() {
    let (server, _dir, credential) = prepared(vec![
        json_http_response("201 Created", session("pending")),
        Vec::new(),
    ]);
    let output = env_run(
        &server,
        &credential,
        &[
            "org",
            "integration",
            "connect",
            "linear",
            "--org",
            ORG,
            "--json",
            "--allow-insecure-http",
        ],
    );
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(
        lines(&output)
            .iter()
            .map(|line| line["outcome"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["pending", "unreachable"]
    );
    assert_eq!(lines(&output)[1]["sessionId"], SESSION);
    assert_no_secret_output(&output, &[TOKEN, SECRET]);
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains(&format!("/authorization-sessions/{SESSION} ")));
}

#[test]
fn polling_stops_on_owner_role_loss_without_restarting_consent() {
    let (server, _dir, credential) = prepared(vec![
        json_http_response("201 Created", session("pending")),
        problem_http_response(
            "403 Forbidden",
            serde_json::json!({"type":"https://api.usefulmachinery.com/problems/forbidden","title":SECRET,"status":403}),
        ),
    ]);
    let output = env_run(
        &server,
        &credential,
        &[
            "org",
            "integration",
            "connect",
            "linear",
            "--org",
            ORG,
            "--json",
            "--allow-insecure-http",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        lines(&output)
            .iter()
            .map(|line| line["outcome"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["pending", "forbidden"]
    );
    assert_eq!(lines(&output)[1]["sessionId"], SESSION);
    assert_no_secret_output(&output, &[TOKEN, SECRET]);
    assert_eq!(server.finish().len(), 2);
}

#[test]
fn rejected_service_credential_does_not_expose_a_token() {
    let (server, directory, credential) = prepared(vec![problem_http_response(
        "401 Unauthorized",
        serde_json::json!({
        "type":"https://api.usefulmachinery.com/problems/unauthorized","title":SECRET,"status":401}),
    )]);
    let service_path = directory.path().join("service.key");
    fs::write(
        &service_path,
        "crd_01k0z6r1w8f4jy2m7q9v3x5abc.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
    )
    .unwrap();
    fs::set_permissions(&service_path, Permissions::from_mode(0o600)).unwrap();
    let output = env_run(
        &server,
        &credential,
        &[
            "org",
            "integration",
            "show",
            SESSION,
            "--org",
            ORG,
            "--api-key-file",
            service_path.to_str().unwrap(),
            "--json",
            "--allow-insecure-http",
        ],
    );
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(lines(&output)[0]["outcome"], "unauthenticated");
    assert_no_secret_output(
        &output,
        &[
            TOKEN,
            SECRET,
            "crd_01k0z6r1w8f4jy2m7q9v3x5abc.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ],
    );
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn remove_of_a_linear_connection_requires_confirmation() {
    for release in [&[][..], &["--release-workspace"]] {
        let remove = ["org", "integration", "disconnect", CONNECTION, "--org", ORG];
        let output = run(&[&remove[..], release].concat());
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("--yes"));
    }
}

#[test]
fn polling_respects_rate_limit_and_reports_recovery_required() {
    let mut recovered = session("recovery_required");
    recovered
        .as_object_mut()
        .unwrap()
        .insert("reasonCode".into(), "exchange_ambiguous".into());
    let (server, _dir, credential) = prepared(vec![
        json_http_response("201 Created", session("pending")),
        http_response_with_headers(
            "429 Too Many Requests",
            Some("application/problem+json"),
            &[("Retry-After", "1")],
            &serde_json::to_vec(
                &serde_json::json!({"type":"about:blank","title":SECRET,"status":429}),
            )
            .unwrap(),
        ),
        json_http_response("200 OK", recovered),
    ]);
    let output = env_run(
        &server,
        &credential,
        &[
            "org",
            "integration",
            "connect",
            "linear",
            "--org",
            ORG,
            "--json",
            "--allow-insecure-http",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        lines(&output)
            .iter()
            .map(|line| line["outcome"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["pending", "recovery_required"]
    );
    assert_eq!(
        lines(&output)[1]["session"]["reasonCode"],
        "exchange_ambiguous"
    );
    assert_no_secret_output(&output, &[TOKEN, SECRET]);
    assert_eq!(server.finish().len(), 3);
}

#[test]
fn ambiguous_disconnect_reuses_exact_key_and_target() {
    let mut disconnected = connection();
    disconnected
        .as_object_mut()
        .unwrap()
        .insert("status".into(), "disconnected".into());
    let (server, _dir, credential) =
        prepared(vec![Vec::new(), json_http_response("200 OK", disconnected)]);
    let output = env_run(
        &server,
        &credential,
        &[
            "org",
            "integration",
            "disconnect",
            CONNECTION,
            "--org",
            ORG,
            "--yes",
            "--json",
            "--allow-insecure-http",
        ],
    );
    assert!(output.status.success());
    assert_eq!(lines(&output)[0]["outcome"], "disconnected");
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        header_value(&requests[0], "idempotency-key"),
        header_value(&requests[1], "idempotency-key")
    );
    for request in &requests {
        assert!(request.contains(&format!("/connections/linear/{CONNECTION}/disconnect ")));
    }
    assert_no_secret_output(&output, &[TOKEN, SECRET]);
}

#[test]
fn list_show_disconnect_and_delete_use_nonsecret_projections() {
    let (server, _dir, credential) = prepared(vec![
        json_http_response("200 OK", serde_json::json!({"items":[connection()]})),
        no_authorizations(),
        no_authorizations(),
        json_http_response("200 OK", connection()),
        json_http_response("200 OK", {
            let mut c = connection();
            c.as_object_mut()
                .unwrap()
                .insert("status".into(), "disconnected".into());
            c
        }),
        http_response("204 No Content", None, b""),
    ]);
    let commands: [(&[&str], &str); 4] = [
        (
            &[
                "org",
                "integration",
                "list",
                "--provider",
                "linear",
                "--org",
                ORG,
            ],
            "listed",
        ),
        (
            &["org", "integration", "show", CONNECTION, "--org", ORG],
            "shown",
        ),
        (
            &[
                "org",
                "integration",
                "disconnect",
                CONNECTION,
                "--org",
                ORG,
                "--yes",
            ],
            "disconnected",
        ),
        (
            &[
                "org",
                "integration",
                "disconnect",
                CONNECTION,
                "--org",
                ORG,
                "--yes",
                "--release-workspace",
            ],
            "deleted",
        ),
    ];
    for (args, outcome) in commands {
        let mut command = args.to_vec();
        command.extend(["--json", "--allow-insecure-http"]);
        let output = env_run(&server, &credential, &command);
        assert!(
            output.status.success(),
            "{outcome}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(lines(&output)[0]["outcome"], outcome);
        assert_no_secret_output(&output, &[TOKEN, SECRET]);
    }
    assert_eq!(server.finish().len(), 6);
}

#[cfg(target_os = "linux")]
#[test]
fn interrupted_removal_reports_unknown_commitment_without_retrying() {
    let mut server = ScriptedServer::respond_with_paused_first_response(vec![json_http_response(
        "200 OK",
        connection(),
    )]);
    let directory = private_credential_directory();
    let path = directory.path().join("credentials.json");
    write_credential_fixture(&path, &server.api_url, TOKEN, "2999-01-01T00:00:00Z");
    let mut command = Command::new(crate::executable());
    command
        .args([
            "org",
            "integration",
            "disconnect",
            CONNECTION,
            "--org",
            ORG,
            "--yes",
            "--json",
            "--allow-insecure-http",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for variable in DEPLOYMENT_VARIABLES {
        command.env_remove(variable);
    }
    command.env_remove(CREDENTIALS_FILE_VARIABLE);
    for (name, value) in deployment_environment(&server.api_url, path.to_str().unwrap()) {
        command.env(name, value);
    }
    let child = command.spawn().unwrap();
    let request = server.wait_for_request();
    assert!(request.contains(&format!("/connections/linear/{CONNECTION}/disconnect ")));
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap(),
        rustix::process::Signal::INT,
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    server.release_paused_response();
    assert_eq!(output.status.code(), Some(130));
    assert_eq!(lines(&output)[0]["outcome"], "commitment_unknown");
    assert_eq!(lines(&output)[0]["connectionId"], CONNECTION);
    assert_eq!(
        lines(&output)[0]["idempotencyKey"],
        header_value(&request, "idempotency-key")
    );
    assert_no_secret_output(&output, &[TOKEN, SECRET]);
    assert!(server.finish().is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn interruption_after_start_preserves_session_for_later_inspection() {
    for (signal, code) in [
        (rustix::process::Signal::INT, 130),
        (rustix::process::Signal::TERM, 143),
    ] {
        let mut server = ScriptedServer::respond_with_paused_last_response(vec![
            json_http_response("201 Created", session("pending")),
            json_http_response("200 OK", session("completed")),
        ]);
        let directory = private_credential_directory();
        let path = directory.path().join("credentials.json");
        write_credential_fixture(&path, &server.api_url, TOKEN, "2999-01-01T00:00:00Z");
        let mut command = Command::new(crate::executable());
        command
            .args([
                "org",
                "integration",
                "connect",
                "linear",
                "--org",
                ORG,
                "--json",
                "--allow-insecure-http",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for variable in DEPLOYMENT_VARIABLES {
            command.env_remove(variable);
        }
        command.env_remove(CREDENTIALS_FILE_VARIABLE);
        for (name, value) in deployment_environment(&server.api_url, path.to_str().unwrap()) {
            command.env(name, value);
        }
        let child = command.spawn().unwrap();
        let start = server.wait_for_request();
        let poll = server.wait_for_request();
        assert!(start.starts_with("POST "));
        assert!(poll.contains(&format!("/authorization-sessions/{SESSION} ")));
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap(),
            signal,
        )
        .unwrap();
        let output = child.wait_with_output().unwrap();
        server.release_paused_response();
        assert_eq!(output.status.code(), Some(code));
        assert_eq!(
            lines(&output)
                .iter()
                .map(|line| line["outcome"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["pending", "observation_stopped"]
        );
        assert_eq!(lines(&output)[1]["sessionId"], SESSION);
        assert_no_secret_output(&output, &[TOKEN, SECRET]);
        assert!(server.finish().is_empty());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn interruption_before_start_response_preserves_request_identity() {
    for (signal, code) in [
        (rustix::process::Signal::INT, 130),
        (rustix::process::Signal::TERM, 143),
    ] {
        let mut server =
            ScriptedServer::respond_with_paused_first_response(vec![json_http_response(
                "201 Created",
                session("pending"),
            )]);
        let directory = private_credential_directory();
        let path = directory.path().join("credentials.json");
        write_credential_fixture(&path, &server.api_url, TOKEN, "2999-01-01T00:00:00Z");
        let mut command = Command::new(crate::executable());
        command
            .args([
                "org",
                "integration",
                "connect",
                "linear",
                "--org",
                ORG,
                "--json",
                "--allow-insecure-http",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for variable in DEPLOYMENT_VARIABLES {
            command.env_remove(variable);
        }
        command.env_remove(CREDENTIALS_FILE_VARIABLE);
        for (name, value) in deployment_environment(&server.api_url, path.to_str().unwrap()) {
            command.env(name, value);
        }
        let child = command.spawn().unwrap();
        let request = server.wait_for_request();
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap(),
            signal,
        )
        .unwrap();
        let output = child.wait_with_output().unwrap();
        server.release_paused_response();
        assert_eq!(output.status.code(), Some(code));
        assert_eq!(lines(&output)[0]["outcome"], "observation_stopped");
        assert!(lines(&output)[0]["sessionId"].is_null());
        assert!(lines(&output)[0].get("idempotencyKey").is_none());
        assert!(!header_value(&request, "idempotency-key").is_empty());
        assert_no_secret_output(&output, &[TOKEN, SECRET]);
        assert!(server.finish().is_empty());
    }
}

const INSTALLATION: &str = "ghi_01k0z6r1w8f4jy2m7q9v3x5abc";
const GITLAB_CONNECTION: &str = "glc_01k0z6r1w8f4jy2m7q9v3x5abc";
const SECOND_CONNECTION: &str = "lcn_01k0z6r1w8f4jy2m7q9v3x5abd";

pub(super) fn installation() -> serde_json::Value {
    serde_json::json!({"id":INSTALLATION,"providerInstallationId":"713","providerAccountId":"829",
        "providerAccountLogin":"acme","providerAccountType":"Organization","state":"active",
        "createdAt":"2026-09-05T12:00:00Z","updatedAt":"2026-09-05T12:01:00Z",
        "authorityVerifiedAt":"2026-09-05T12:01:00Z"})
}
pub(super) fn gitlab_connection() -> serde_json::Value {
    serde_json::json!({"id":GITLAB_CONNECTION,"organizationId":ORG_ID,
        "instanceUrl":"https://gitlab.com","state":"credential_required","credentialReason":"not-configured",
        "version":3,"providerUser":null,"credential":null,"selectedRepositoryIds":[],
        "support":{"state":"unverified","observedVersion":null},
        "createdAt":"2026-09-05T12:00:00Z","updatedAt":"2026-09-05T12:01:00Z"})
}
fn refused(status: &str, code: u16, kind: &str) -> Vec<u8> {
    problem_http_response(
        status,
        serde_json::json!({"type":format!("https://api.usefulmachinery.com/problems/{kind}"),
            "title":"Refused","status":code,"detail":SECRET}),
    )
}
fn list_connections(server: &ScriptedServer, credential: &str, args: &[&str]) -> Output {
    let mut command = vec!["org", "integration", "list", "--org", ORG];
    command.extend_from_slice(args);
    command.extend_from_slice(&["--json", "--allow-insecure-http"]);
    env_run(server, credential, &command)
}

#[test]
fn org_connection_list_reads_every_page_of_each_provider_into_one_list() {
    let mut second = connection();
    second["id"] = SECOND_CONNECTION.into();
    second["status"] = "disconnected".into();
    second["workspaceName"] = "Platform".into();
    let (server, _dir, credential) = prepared(vec![
        json_http_response("200 OK", serde_json::json!({"items":[installation()]})),
        json_http_response(
            "200 OK",
            serde_json::json!({"items":[gitlab_connection()],"nextCursor":null}),
        ),
        json_http_response(
            "200 OK",
            serde_json::json!({"items":[connection()],"nextCursor":"linear-page-2"}),
        ),
        json_http_response("200 OK", serde_json::json!({"items":[second]})),
        no_authorizations(),
        serving_nothing(),
    ]);

    let output = list_connections(&server, &credential, &[]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let documents = lines(&output);
    assert_eq!(documents.len(), 1, "{documents:?}");
    let document = &documents[0];
    assert_eq!(document["schemaVersion"], 1);
    assert_eq!(document["deployment"], server.api_url);
    assert_eq!(document["organizationRef"], ORG);
    assert_eq!(document["outcome"], "listed");
    assert_eq!(document["unlisted"], serde_json::json!([]));
    let items = document["items"].as_array().unwrap();
    let summaries: Vec<_> = items
        .iter()
        .map(|item| {
            (
                item["provider"].as_str().unwrap(),
                item["id"].as_str().unwrap(),
                item["state"].as_str().unwrap(),
                item["name"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        summaries,
        [
            ("github", INSTALLATION, "active", "acme"),
            (
                "gitlab",
                GITLAB_CONNECTION,
                "credential_required",
                "https://gitlab.com"
            ),
            ("linear", CONNECTION, "active", "Research"),
            ("linear", SECOND_CONNECTION, "disconnected", "Platform"),
        ]
    );
    assert_eq!(items[0]["connection"]["providerInstallationId"], "713");
    assert_eq!(items[1]["connection"]["version"], 3);
    assert_eq!(items[2]["connection"]["workspaceId"], "workspace-1");
    assert_no_secret_output(&output, &[TOKEN, SECRET]);

    let requests = server.finish();
    assert_eq!(requests.len(), 6);
    assert!(requests[0].starts_with(&format!(
        "GET /api/v1/organizations/{ORG}/github/installations HTTP/1.1\r\n"
    )));
    assert!(requests[1].starts_with(&format!(
        "GET /api/v1/organizations/{ORG}/connections/gitlab?limit=100 HTTP/1.1\r\n"
    )));
    assert!(requests[2].starts_with(&format!(
        "GET /api/v1/organizations/{ORG}/connections/linear?limit=100 HTTP/1.1\r\n"
    )));
    let last = requests[3].lines().next().unwrap();
    assert!(
        last.starts_with(&format!(
            "GET /api/v1/organizations/{ORG}/connections/linear?"
        )) && last.contains("limit=100")
            && last.contains("cursor=linear-page-2"),
        "{last}"
    );
}

#[test]
fn org_connection_list_of_one_provider_reads_that_provider_alone() {
    let (server, _dir, credential) = prepared(vec![
        json_http_response(
            "200 OK",
            serde_json::json!({"items":[gitlab_connection()],"nextCursor":null}),
        ),
        no_authorizations(),
    ]);

    let output = list_connections(&server, &credential, &["--provider", "gitlab"]);

    assert!(output.status.success(), "{output:?}");
    let document = &lines(&output)[0];
    assert_eq!(document["items"][0]["provider"], "gitlab");
    assert_eq!(document["items"].as_array().unwrap().len(), 1);
    assert_eq!(document["unlisted"], serde_json::json!([]));
    // `--provider` keeps one provider's connections, and no token.
    assert_eq!(document["tokens"], serde_json::json!([]));
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with(&format!(
        "GET /api/v1/organizations/{ORG}/connections/gitlab?limit=100 HTTP/1.1\r\n"
    )));
}

#[test]
fn org_connection_list_takes_no_limit() {
    let (server, _dir, credential) = prepared(Vec::new());

    let output = list_connections(&server, &credential, &["--limit", "5"]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(server.finish().is_empty());
}

#[test]
fn org_connection_list_names_the_providers_it_could_not_list() {
    let (server, _dir, credential) = prepared(vec![
        refused("403 Forbidden", 403, "forbidden"),
        json_http_response(
            "200 OK",
            serde_json::json!({"items":[gitlab_connection()],"nextCursor":null}),
        ),
        refused("503 Service Unavailable", 503, "service-unavailable"),
        no_authorizations(),
        serving_nothing(),
    ]);

    let output = list_connections(&server, &credential, &[]);

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let document = &lines(&output)[0];
    assert_eq!(document["outcome"], "listed");
    let items = document["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["provider"], "gitlab");
    assert_eq!(
        document["unlisted"],
        serde_json::json!([
            {"provider":"github","reason":"forbidden"},
            {"provider":"linear","reason":"service_unavailable"},
        ])
    );
    assert_no_secret_output(&output, &[TOKEN, SECRET]);
    assert_eq!(server.finish().len(), 5);
}

#[test]
fn org_connection_list_with_every_provider_refused_ends_with_the_first_failure() {
    let (server, _dir, credential) = prepared(vec![
        refused("403 Forbidden", 403, "forbidden"),
        refused("403 Forbidden", 403, "forbidden"),
        refused("503 Service Unavailable", 503, "service-unavailable"),
    ]);

    let output = list_connections(&server, &credential, &[]);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["outcome"], "forbidden");
    assert_eq!(document["organizationRef"], ORG);
    assert!(document.get("items").is_none(), "{document}");
    assert_no_secret_output(&output, &[TOKEN, SECRET]);
    assert_eq!(server.finish().len(), 3);
}

fn show_connection(server: &ScriptedServer, credential: &str, connection: &str) -> Output {
    env_run(
        server,
        credential,
        &[
            "org",
            "integration",
            "show",
            connection,
            "--org",
            ORG,
            "--json",
            "--allow-insecure-http",
        ],
    )
}
fn linear_connection(id: &str, status: &str) -> serde_json::Value {
    let mut value = connection();
    value["id"] = id.into();
    value["status"] = status.into();
    value
}
fn linear_list(items: &[serde_json::Value]) -> Vec<u8> {
    json_http_response("200 OK", serde_json::json!({ "items": items }))
}
fn linear_list_request(request: &str) -> bool {
    request.starts_with(&format!(
        "GET /api/v1/organizations/{ORG}/connections/linear?limit=100 HTTP/1.1\r\n"
    ))
}

#[test]
fn org_connection_show_of_a_provider_shows_its_connection_in_use() {
    let (server, _dir, credential) = prepared(vec![
        linear_list(&[
            linear_connection(SECOND_CONNECTION, "deleted"),
            connection(),
        ]),
        no_authorizations(),
        json_http_response("200 OK", connection()),
    ]);

    let output = show_connection(&server, &credential, "linear");

    assert!(output.status.success(), "{output:?}");
    let document = &lines(&output)[0];
    assert_eq!(document["outcome"], "shown");
    assert_eq!(document["organizationRef"], ORG);
    assert_eq!(document["connectionId"], CONNECTION);
    assert_eq!(document["connection"]["status"], "active");
    assert_no_secret_output(&output, &[TOKEN, SECRET]);
    let requests = server.finish();
    assert_eq!(requests.len(), 3);
    assert!(linear_list_request(&requests[0]), "{}", requests[0]);
    assert!(requests[2].starts_with(&format!(
        "GET /api/v1/organizations/{ORG}/connections/linear/{CONNECTION} HTTP/1.1\r\n"
    )));
}

#[test]
fn org_connection_show_of_a_provider_with_one_removed_connection_shows_it() {
    let (server, _dir, credential) = prepared(vec![
        linear_list(&[linear_connection(SECOND_CONNECTION, "disconnected")]),
        no_authorizations(),
        json_http_response(
            "200 OK",
            linear_connection(SECOND_CONNECTION, "disconnected"),
        ),
    ]);

    let output = show_connection(&server, &credential, "linear");

    assert!(output.status.success(), "{output:?}");
    assert_eq!(lines(&output)[0]["connectionId"], SECOND_CONNECTION);
    let requests = server.finish();
    assert_eq!(requests.len(), 3);
    assert!(requests[2].contains(&format!("/connections/linear/{SECOND_CONNECTION} ")));
}

#[test]
fn org_connection_show_of_a_provider_naming_several_connections_names_them_and_sends_nothing_more()
{
    let (server, _dir, credential) = prepared(vec![linear_list(&[
        connection(),
        linear_connection(SECOND_CONNECTION, "active"),
    ])]);

    let output = show_connection(&server, &credential, "linear");

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    for id in [CONNECTION, SECOND_CONNECTION] {
        assert!(stderr.contains(id), "{stderr}");
    }
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert!(linear_list_request(&requests[0]), "{}", requests[0]);
}

#[test]
fn org_connection_show_of_a_provider_with_no_connection_names_create() {
    let (server, _dir, credential) = prepared(vec![linear_list(&[])]);

    let output = show_connection(&server, &credential, "linear");

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("useful org integration connect"),
        "{output:?}"
    );
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn org_connection_show_of_an_id_sends_that_connection_request_alone() {
    let (server, _dir, credential) = prepared(vec![
        no_authorizations(),
        json_http_response("200 OK", connection()),
    ]);

    let output = show_connection(&server, &credential, CONNECTION);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(lines(&output)[0]["connectionId"], CONNECTION);
    // The connection's authorizations in force are read first.
    assert_eq!(lines(&output)[0]["authorizations"], serde_json::json!([]));
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with(&format!(
        "GET /api/v1/organizations/{ORG}/connection-authorizations?limit=200&connectionId={CONNECTION} HTTP/1.1\r\n"
    )));
    assert!(requests[1].starts_with(&format!(
        "GET /api/v1/organizations/{ORG}/connections/linear/{CONNECTION} HTTP/1.1\r\n"
    )));
}

#[test]
fn org_connection_show_refuses_a_malformed_connection_without_contacting_the_deployment() {
    let (server, _dir, credential) = prepared(Vec::new());

    for connection in ["Bogus", "lcn_short"] {
        let output = show_connection(&server, &credential, connection);

        assert_eq!(output.status.code(), Some(2), "{connection}: {output:?}");
        assert!(output.stdout.is_empty(), "{connection}: {output:?}");
    }
    assert!(server.finish().is_empty());

    // A lowercase word may name a token service, so what the deployment serves is read first;
    // one it serves as none, a typo of a provider among them, is refused naming the providers,
    // and no token is read.
    let (server, _dir, credential) = prepared(vec![serving_nothing()]);
    let output = show_connection(&server, &credential, "gihub");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    for provider in ["github", "gitlab", "linear"] {
        assert!(stderr.contains(provider), "{provider}: {stderr}");
    }
    let requests = server.finish();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert!(
        requests[0].starts_with("GET /api/v1/me/grant-providers HTTP/1.1\r\n"),
        "{}",
        requests[0]
    );
}

#[test]
fn org_connection_reads_refuse_another_providers_connection_or_option_without_contacting_the_deployment()
 {
    let (server, _dir, credential) = prepared(Vec::new());
    let mut cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["repository", "list", "linear"], "GitLab"),
        (vec!["repository", "list", CONNECTION], "GitLab"),
        (vec!["team", "list", INSTALLATION], "Linear"),
        (
            vec!["team", "show", "team", "--integration", GITLAB_CONNECTION],
            "Linear",
        ),
    ];
    for option in [
        &["--limit", "5"][..],
        &["--cursor", "C"],
        &["--search", "widget"],
        &["--repository-id", "42"],
        &["--selected"],
    ] {
        for connection in [INSTALLATION, "github"] {
            cases.push((
                [&["repository", "list", connection][..], option].concat(),
                "GitLab",
            ));
        }
    }

    for (args, needed) in cases {
        let mut command = vec!["org", "integration"];
        command.extend(&args);
        command.extend(["--org", ORG, "--json", "--allow-insecure-http"]);
        let output = env_run(&server, &credential, &command);

        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(needed),
            "{args:?}: {output:?}"
        );
    }
    assert!(server.finish().is_empty());
}

#[test]
fn org_connection_remove_disconnects_a_linear_connection_or_with_release_workspace_deletes_it() {
    let mut disconnected = connection();
    disconnected["status"] = "disconnected".into();
    let (server, _dir, credential) = prepared(vec![
        json_http_response("200 OK", disconnected),
        http_response("204 No Content", None, b""),
    ]);

    for (release, outcome) in [
        (&[][..], "disconnected"),
        (&["--release-workspace"][..], "deleted"),
    ] {
        let remove = [
            "org",
            "integration",
            "disconnect",
            CONNECTION,
            "--org",
            ORG,
            "--yes",
        ];
        let command = [&remove[..], release, &["--json", "--allow-insecure-http"]].concat();
        let output = env_run(&server, &credential, &command);

        assert!(output.status.success(), "{outcome}: {output:?}");
        assert_eq!(lines(&output)[0]["outcome"], outcome);
    }
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    let path = format!("/api/v1/organizations/{ORG}/connections/linear/{CONNECTION}");
    assert!(
        requests[0].starts_with(&format!("POST {path}/disconnect HTTP/1.1\r\n")),
        "{}",
        requests[0]
    );
    assert!(
        requests[1].starts_with(&format!("DELETE {path} HTTP/1.1\r\n")),
        "{}",
        requests[1]
    );
}

#[test]
fn org_connection_mutations_refuse_another_providers_connection_or_option_without_contacting_the_deployment()
 {
    let (server, _dir, credential) = prepared(Vec::new());
    let cases: [(&[&str], &str); 9] = [
        (
            &["disconnect", INSTALLATION, "--yes", "--release-workspace"],
            "Linear",
        ),
        (
            &[
                "disconnect",
                GITLAB_CONNECTION,
                "--yes",
                "--release-workspace",
            ],
            "Linear",
        ),
        (
            &["repository", "add", "7", "--integration", INSTALLATION],
            "GitLab",
        ),
        (
            &[
                "repository",
                "remove",
                "7",
                "--integration",
                "github",
                "--yes",
            ],
            "GitLab",
        ),
        (
            &["repository", "add", "7", "--integration", CONNECTION],
            "GitLab",
        ),
        (
            &["disconnect", CONNECTION, "--yes", "--expected-version", "3"],
            "GitLab",
        ),
        (
            &[
                "disconnect",
                INSTALLATION,
                "--yes",
                "--idempotency-key",
                "key",
            ],
            "GitLab",
        ),
        (
            &[
                "disconnect",
                "linear",
                "--yes",
                "--delegator-principal-id",
                "prn_01k0z6r1w8f4jy2m7q9v3x5abc",
            ],
            "GitLab",
        ),
        (
            &[
                "repository",
                "add",
                "7",
                "--integration",
                "github",
                "--expected-version",
                "3",
            ],
            "GitLab",
        ),
    ];

    for (args, needed) in cases {
        let mut command = vec!["org", "integration"];
        command.extend(args);
        command.extend(["--org", ORG, "--json", "--allow-insecure-http"]);
        let output = env_run(&server, &credential, &command);

        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(needed),
            "{args:?}: {output:?}"
        );
    }
    assert!(server.finish().is_empty());
}
