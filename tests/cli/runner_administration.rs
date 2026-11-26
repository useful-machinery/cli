use super::organization::{
    LIST_CURRENT_MEMBERSHIPS, OTHER_IN_EFFECT_ID, active_memberships, request_lines, run_in_effect,
};
use super::*;

pub(super) const TOKEN: &str = "unique-runner-command-token-sentinel";
const SERVICE_API_KEY: &str =
    "crd_01k0z6r1w8f4jy2m7q9v3x5abc.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
pub(super) const ORGANIZATION: &str = "acme-research";
pub(super) const ORGANIZATION_ID: &str = "org_01k0z6r1w8f4jy2m7q9v3x5abc";
pub(super) const POOL_ID: &str = "rpl_01k0z6r1w8f4jy2m7q9v3x5abc";
pub(super) const RUNNER_ID: &str = "rnr_01k0z6r1w8f4jy2m7q9v3x5abc";
pub(super) const ACTIVATION_ID: &str = "rna_01k0z6r1w8f4jy2m7q9v3x5abc";
pub(super) const ACTIVATION_SECRET: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
// rrc_ values are public IDs, not credential secrets.
const CREDENTIAL_ID: &str = "rrc_01k0z6r1w8f4jy2m7q9v3x5abc";
pub(super) const MEMBER_ID: &str = "prn_01k0z6r1w8f4jy2m7q9v3x5abc";

pub(super) fn prepared_runner(
    responses: Vec<Vec<u8>>,
) -> (ScriptedServer, tempfile::TempDir, String) {
    let server = ScriptedServer::respond(responses);
    let credential_directory = private_credential_directory();
    let credential_path = credential_directory.path().join("credentials.json");
    write_credential_fixture(
        &credential_path,
        &server.api_url,
        TOKEN,
        "2999-01-01T00:00:00Z",
    );
    let credential_path = credential_path.to_str().unwrap().to_owned();
    (server, credential_directory, credential_path)
}

pub(super) fn request_body(request: &str) -> &str {
    request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("request should contain a body separator")
}

fn pool_body() -> serde_json::Value {
    serde_json::json!({
        "id": POOL_ID,
        "organizationId": ORGANIZATION_ID,
        "name": "builders",
        "createdAt": "2026-08-09T12:00:00Z",
        "updatedAt": "2026-08-09T12:00:00Z"
    })
}

pub(super) fn activation_issuance_body() -> serde_json::Value {
    serde_json::json!({
        "activation": {
            "id": ACTIVATION_ID,
            "runnerId": RUNNER_ID,
            "state": "issued",
            "issuedAt": "2026-08-09T12:00:00Z",
            "expiresAt": "2026-08-09T13:00:00Z"
        },
        "artifact": {
            "schemaVersion": 1,
            "activationUrl": format!("https://api.usefulmachinery.com/v1/runner-enrollments/{ACTIVATION_ID}/activate"),
            "activationToken": format!("{ACTIVATION_ID}.{ACTIVATION_SECRET}"),
            "runnerId": RUNNER_ID,
            "expiresAt": "2026-08-09T13:00:00Z"
        }
    })
}

fn credential_body(state: &str) -> serde_json::Value {
    let mut credential = serde_json::json!({
        "id": CREDENTIAL_ID,
        "storedState": state,
        "effectiveState": state,
        "createdAt": "2026-08-09T12:02:00Z",
        "lastAuthenticatedAt": "2026-08-09T12:04:00Z"
    });
    match state {
        "retiring" => {
            credential["retireAt"] = serde_json::json!("2026-08-09T13:05:00Z");
        }
        "revoked" => {
            credential["revokedAt"] = serde_json::json!("2026-08-09T12:05:00Z");
        }
        _ => {}
    }
    credential
}

pub(super) fn pool_list_body() -> serde_json::Value {
    serde_json::json!({"items": [pool_body()]})
}

fn registration_list_body() -> serde_json::Value {
    serde_json::json!({"items": [registration_body()]})
}

fn deletion_success_response() -> Vec<u8> {
    http_response_with_headers(
        "204 No Content",
        None,
        &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
        &[],
    )
}

fn registration_body() -> serde_json::Value {
    serde_json::json!({
        "id": RUNNER_ID,
        "organizationId": ORGANIZATION_ID,
        "runnerPool": {"id": POOL_ID, "name": "builders"},
        "name": "builder-one",
        "administration": {
            "mode": "draining",
            "createdAt": "2026-08-09T12:00:00Z",
            "updatedAt": "2026-08-09T12:01:00Z"
        },
        "enrollment": {
            "state": "credentialed",
            "firstEnrolledAt": "2026-08-09T12:02:00Z",
            "validCredentialCount": 1
        },
        "connectivity": {
            "state": "online",
            "connectedAt": "2026-08-09T12:03:00Z",
            "lastSeenAt": "2026-08-09T12:04:00Z"
        },
        "activity": {"state": "assigned", "currentAssignmentCount": 1},
        "advertisedMetadata": {
            "runnerVersion": "1.2.3",
            "protocolVersion": 1
        }
    })
}

fn rate_limit_response() -> Vec<u8> {
    problem_http_response(
        "429 Too Many Requests",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/rate-limit-exceeded",
            "title": "Rate limit exceeded",
            "status": 429
        }),
    )
}

#[test]
fn runner_deletion_requires_literal_confirmation_before_local_or_network_access() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let api_url = format!("http://{}/api", listener.local_addr().unwrap());
    let missing_credentials = tempfile::tempdir().unwrap().path().join("missing.json");
    let credential_path = missing_credentials.to_str().unwrap();
    let environment = deployment_environment(&api_url, credential_path);

    for args in [
        vec![
            "runner",
            "delete",
            RUNNER_ID,
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        vec![
            "runner",
            "pool",
            "delete",
            POOL_ID,
            "--org",
            ORGANIZATION,
            "--yes=false",
            "--allow-insecure-http",
        ],
    ] {
        let output = run_with_env(&args, &environment);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stderr.contains('?'));
        assert!(!stderr.to_ascii_lowercase().contains("prompt"));
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn runner_show_without_a_credential_reports_sign_in_on_stderr() {
    let output = run(&["runner", "show", RUNNER_ID, "--org", ORGANIZATION]);

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("useful account login")
    );
}

#[test]
fn runner_protocol_failure_uses_the_shared_general_failure_status() {
    let (server, _directory, credential_path) = prepared_runner(vec![json_http_response(
        "200 OK",
        serde_json::json!({"invalidRunnerResponse": true}),
    )]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "runner",
            "show",
            RUNNER_ID,
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["outcome"],
        "invalid_response"
    );
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn pool_create_sends_the_name_and_reports_the_created_pool() {
    let response = http_response_with_headers(
        "201 Created",
        Some("application/json"),
        &[
            ("Idempotency-Key", ECHO_IDEMPOTENCY_KEY),
            (
                "Location",
                "/v1/organizations/org_01k0z6r1w8f4jy2m7q9v3x5abc/runner-pools/rpl_01k0z6r1w8f4jy2m7q9v3x5abc",
            ),
        ],
        &serde_json::to_vec(&pool_body()).unwrap(),
    );
    let (server, _directory, credential_path) = prepared_runner(vec![response]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "runner",
            "pool",
            "create",
            "builders",
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert!(output.status.success());
    let report = String::from_utf8(output.stdout).unwrap();
    for fact in [
        POOL_ID,
        "builders",
        ORGANIZATION_ID,
        server.api_url.as_str(),
    ] {
        assert!(report.contains(fact), "{fact}: {report}");
    }
    assert!(output.stderr.is_empty());

    let request = server.finish().pop().unwrap();
    assert!(request.starts_with(&format!(
        "POST /api/v1/organizations/{ORGANIZATION}/runner-pools HTTP/1.1\r\n"
    )));
    assert_eq!(
        header_value(&request, "authorization"),
        format!("Bearer {TOKEN}")
    );
    assert_eq!(header_value(&request, "content-type"), "application/json");
    let key = header_value(&request, "idempotency-key");
    assert_eq!(key.len(), 64);
    assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request_body(&request)).unwrap(),
        serde_json::json!({"name": "builders"})
    );
}

#[test]
fn deletion_by_name_resolves_once_and_emits_exact_success_json() {
    for (args, resolution, expected_path, expected_output) in [
        (
            vec![
                "runner",
                "delete",
                "builder-one",
                "--org",
                ORGANIZATION,
                "--yes",
                "--json",
                "--allow-insecure-http",
            ],
            json_http_response("200 OK", registration_list_body()),
            format!(
                "DELETE /api/v1/organizations/{ORGANIZATION}/runner-registrations/{RUNNER_ID} HTTP/1.1\r\n"
            ),
            ("runnerId", RUNNER_ID),
        ),
        (
            vec![
                "runner",
                "pool",
                "delete",
                "builders",
                "--org",
                ORGANIZATION,
                "--yes",
                "--json",
                "--allow-insecure-http",
            ],
            json_http_response("200 OK", pool_list_body()),
            format!(
                "DELETE /api/v1/organizations/{ORGANIZATION}/runner-pools/{POOL_ID} HTTP/1.1\r\n"
            ),
            ("runnerPoolId", POOL_ID),
        ),
    ] {
        let (server, _directory, credential_path) =
            prepared_runner(vec![resolution, deletion_success_response()]);
        let environment = deployment_environment(&server.api_url, &credential_path);
        let output = run_with_env(&args, &environment);

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!(
                concat!(
                    "{{\n",
                    "  \"schemaVersion\": 1,\n",
                    "  \"deployment\": \"{}\",\n",
                    "  \"outcome\": \"deleted\",\n",
                    "  \"{}\": \"{}\",\n",
                    "  \"deleted\": true\n",
                    "}}\n"
                ),
                server.api_url, expected_output.0, expected_output.1
            )
        );
        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("GET "));
        assert!(requests[1].starts_with(&expected_path));
        assert_eq!(request_body(&requests[1]), "");
        let key = header_value(&requests[1], "idempotency-key");
        assert_eq!(key.len(), 64);
        assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}

#[test]
fn runner_deletion_reads_a_service_key_from_stdin_once() {
    let server = ScriptedServer::respond(vec![
        json_http_response("200 OK", registration_list_body()),
        deletion_success_response(),
    ]);
    let directory = private_credential_directory();
    let missing_human_store = directory.path().join("missing-human.json");
    let environment =
        deployment_environment(&server.api_url, missing_human_store.to_str().unwrap());

    let output = run_with_stdin(
        &[
            "runner",
            "delete",
            "builder-one",
            "--org",
            ORGANIZATION,
            "--yes",
            "--api-key-file",
            "-",
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
        format!("{SERVICE_API_KEY}\n").as_bytes(),
    );

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["outcome"],
        "deleted"
    );
    assert!(output.stderr.is_empty());
    assert!(!missing_human_store.exists());
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert_eq!(
            header_value(&request, "authorization"),
            format!("Bearer {SERVICE_API_KEY}")
        );
    }
}

#[test]
fn deletion_refresh_reuses_the_resolved_id_and_invocation_key() {
    let rejected = problem_http_response(
        "401 Unauthorized",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/unauthorized",
            "title": "Unauthorized",
            "status": 401
        }),
    );
    let server = ScriptedServer::respond(vec![
        json_http_response("200 OK", registration_list_body()),
        rejected,
        json_http_response(
            "200 OK",
            serde_json::json!({
                "access_token": "unique-refreshed-delete-access-token",
                "refresh_token": "unique-refreshed-delete-refresh-token",
                "token_type": "Bearer",
                "expires_in": 3600
            }),
        ),
        deletion_success_response(),
    ]);
    let credential_directory = private_credential_directory();
    let credential_path = credential_directory.path().join("credentials.json");
    write_credential_fixture_for_deployment(
        &credential_path,
        &server.api_url,
        &server.issuer,
        TOKEN,
        "2999-01-01T00:00:00Z",
    );
    let environment = deployment_environment_with_issuer(
        &server.api_url,
        &server.issuer,
        credential_path.to_str().unwrap(),
    );

    let output = run_with_env(
        &[
            "runner",
            "delete",
            "builder-one",
            "--org",
            ORGANIZATION,
            "--yes",
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.starts_with("GET "))
            .count(),
        1
    );
    let deletes = [&requests[1], &requests[3]];
    for request in deletes {
        assert!(request.starts_with(&format!(
            "DELETE /api/v1/organizations/{ORGANIZATION}/runner-registrations/{RUNNER_ID} HTTP/1.1\r\n"
        )));
    }
    assert_eq!(
        header_value(deletes[0], "idempotency-key"),
        header_value(deletes[1], "idempotency-key")
    );
    assert_eq!(
        crate::header_value(deletes[1], "authorization"),
        "Bearer unique-refreshed-delete-access-token"
    );
}

#[test]
fn deletion_blockers_remain_ordered_and_bound_to_the_resolved_id() {
    let blocked = problem_http_response(
        "409 Conflict",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/runner-registration-delete-unavailable",
            "title": "Runner registration deletion unavailable",
            "status": 409,
            "blockers": ["capacity_reserved", "nonterminal_assignment"]
        }),
    );
    let (server, _directory, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", registration_body()),
        blocked,
    ]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "runner",
            "delete",
            RUNNER_ID,
            "--org",
            ORGANIZATION,
            "--yes",
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["outcome"], "delete_unavailable");
    assert_eq!(result["runnerId"], RUNNER_ID);
    assert_eq!(
        result["blockers"],
        serde_json::json!(["capacity_reserved", "nonterminal_assignment"])
    );
    assert!(result.get("deleted").is_none());
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
}

#[test]
fn post_dispatch_transport_server_and_protocol_failures_report_unknown_commitment() {
    let failures = [
        Vec::new(),
        http_response("204 No Content", None, &[]),
        problem_http_response(
            "500 Internal Server Error",
            serde_json::json!({
                "type": "https://api.usefulmachinery.com/problems/internal-server-error",
                "title": "Internal server error",
                "status": 500
            }),
        ),
    ];
    for failure in failures {
        let (server, _directory, credential_path) = prepared_runner(vec![
            json_http_response("200 OK", registration_body()),
            failure,
        ]);
        let environment = deployment_environment(&server.api_url, &credential_path);
        let output = run_with_env(
            &[
                "runner",
                "delete",
                RUNNER_ID,
                "--org",
                ORGANIZATION,
                "--yes",
                "--json",
                "--allow-insecure-http",
            ],
            &environment,
        );

        assert_eq!(output.status.code(), Some(4));
        assert!(output.stderr.is_empty());
        let diagnostic: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            diagnostic,
            serde_json::json!({
                "schemaVersion": 1,
                "deployment": server.api_url,
                "outcome": "unknown",
                "runnerId": RUNNER_ID,
                "commitment": "unknown"
            })
        );
        assert!(diagnostic.get("deleted").is_none());
        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("GET "));
        assert!(requests[1].starts_with("DELETE "));
    }
}

#[test]
fn later_owner_directed_deletion_uses_a_new_key_after_unknown_commitment() {
    let (first, _directory, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", registration_body()),
        Vec::new(),
    ]);
    let environment = deployment_environment(&first.api_url, &credential_path);
    let first_output = run_with_env(
        &[
            "runner",
            "delete",
            RUNNER_ID,
            "--org",
            ORGANIZATION,
            "--yes",
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );
    assert_eq!(first_output.status.code(), Some(4));
    let first_requests = first.finish();
    let first_key = header_value(&first_requests[1], "idempotency-key").to_owned();

    let (later, _directory, later_credential_path) = prepared_runner(vec![
        json_http_response("200 OK", registration_body()),
        deletion_success_response(),
    ]);
    let later_environment = deployment_environment(&later.api_url, &later_credential_path);
    let later_output = run_with_env(
        &[
            "runner",
            "delete",
            RUNNER_ID,
            "--org",
            ORGANIZATION,
            "--yes",
            "--json",
            "--allow-insecure-http",
        ],
        &later_environment,
    );
    assert!(later_output.status.success());
    let later_requests = later.finish();
    let later_key = header_value(&later_requests[1], "idempotency-key");
    assert_ne!(first_key, later_key);
}

#[cfg(target_os = "linux")]
#[test]
fn post_dispatch_interrupt_and_termination_report_unknown_without_retry() {
    for (signal, expected_exit) in [
        (rustix::process::Signal::INT, 130),
        (rustix::process::Signal::TERM, 143),
    ] {
        let mut server = ScriptedServer::respond_with_paused_last_response(vec![
            json_http_response("200 OK", registration_body()),
            deletion_success_response(),
        ]);
        let credential_directory = private_credential_directory();
        let credential_path = credential_directory.path().join("credentials.json");
        write_credential_fixture(
            &credential_path,
            &server.api_url,
            TOKEN,
            "2999-01-01T00:00:00Z",
        );
        let environment =
            deployment_environment(&server.api_url, credential_path.to_str().unwrap());
        let mut command = Command::new(crate::executable());
        command
            .args([
                "runner",
                "delete",
                RUNNER_ID,
                "--org",
                ORGANIZATION,
                "--yes",
                "--json",
                "--allow-insecure-http",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in &environment {
            command.env(name, value);
        }
        let child = command.spawn().unwrap();

        let resolution = server.next_request();
        let deletion = server.next_request();
        assert!(resolution.starts_with("GET "));
        assert!(deletion.starts_with("DELETE "));
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap(),
            signal,
        )
        .unwrap();
        let output = child.wait_with_output().unwrap();
        server.release_paused_response();
        assert_eq!(output.status.code(), Some(expected_exit));
        assert!(output.stderr.is_empty());
        let diagnostic: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(diagnostic["runnerId"], RUNNER_ID);
        assert_eq!(diagnostic["commitment"], "unknown");
        assert!(diagnostic.get("deleted").is_none());
        assert!(server.finish().is_empty());
    }
}

/// The name lookup of a runner the organization does not hold: its one page of registrations.
fn no_registrations() -> Vec<u8> {
    json_http_response("200 OK", serde_json::json!({"items": []}))
}

fn registration_lookup() -> String {
    format!("GET /api/v1/organizations/{ORGANIZATION}/runner-registrations?limit=200 HTTP/1.1")
}

fn registration_creation() -> String {
    format!("POST /api/v1/organizations/{ORGANIZATION}/runner-registrations HTTP/1.1")
}

fn activation_creation(runner_id: &str) -> String {
    format!(
        "POST /api/v1/organizations/{ORGANIZATION}/runner-registrations/{runner_id}/activations HTTP/1.1"
    )
}

fn unauthorized_response() -> Vec<u8> {
    problem_http_response(
        "401 Unauthorized",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/unauthorized",
            "title": "Unauthorized",
            "status": 401
        }),
    )
}

fn forbidden_response() -> Vec<u8> {
    problem_http_response(
        "403 Forbidden",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/forbidden",
            "title": "Forbidden",
            "status": 403
        }),
    )
}

fn refreshed_token_response() -> Vec<u8> {
    json_http_response(
        "200 OK",
        serde_json::json!({
            "access_token": "unique-refreshed-single-runner-key-access-token",
            "refresh_token": "unique-refreshed-single-runner-key-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600
        }),
    )
}

/// A runner with a session whose token the deployment's issuer can refresh.
fn refreshable_runner(
    responses: Vec<Vec<u8>>,
) -> (ScriptedServer, tempfile::TempDir, Vec<(String, String)>) {
    let server = ScriptedServer::respond(responses);
    let credential_directory = private_credential_directory();
    let credential_path = credential_directory.path().join("credentials.json");
    write_credential_fixture_for_deployment(
        &credential_path,
        &server.api_url,
        &server.issuer,
        TOKEN,
        "2999-01-01T00:00:00Z",
    );
    let environment = deployment_environment_with_issuer(
        &server.api_url,
        &server.issuer,
        credential_path.to_str().unwrap(),
    )
    .iter()
    .map(|(name, value)| ((*name).to_owned(), value.to_string()))
    .collect();
    (server, credential_directory, environment)
}

fn borrowed(environment: &[(String, String)]) -> Vec<(&str, &str)> {
    environment
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

// A credential refreshed between the registration and the key issues the key for the runner
// it registered, under the same request identity.
#[test]
fn single_runner_key_refreshes_a_token_rejected_after_the_registration() {
    let (server, _credentials, environment) = refreshable_runner(vec![
        no_registrations(),
        json_http_response("200 OK", pool_body()),
        registration_created_response(),
        unauthorized_response(),
        refreshed_token_response(),
        activation_issued_response(),
    ]);
    let key_directory = private_credential_directory();
    let key_path = key_directory.path().join("builder-one.key");

    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "issue",
            "--runner",
            "builder-one",
            "--pool",
            POOL_ID,
            "--key-file",
            key_path.to_str().unwrap(),
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &borrowed(&environment),
    );

    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["runner"]["id"], RUNNER_ID);
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [
            registration_lookup().as_str(),
            &format!("GET /api/v1/organizations/{ORGANIZATION}/runner-pools/{POOL_ID} HTTP/1.1"),
            &registration_creation(),
            &activation_creation(RUNNER_ID),
            "POST /auth/oauth/token HTTP/1.1",
            &activation_creation(RUNNER_ID),
        ]
    );
    assert_eq!(
        crate::header_value(&requests[5], "authorization"),
        "Bearer unique-refreshed-single-runner-key-access-token"
    );
    assert_eq!(
        header_value(&requests[3], "idempotency-key"),
        header_value(&requests[5], "idempotency-key")
    );
    assert!(key_path.exists());
}

#[test]
fn single_runner_key_keeps_the_registered_runner_when_the_refreshed_issue_fails() {
    let (server, _credentials, environment) = refreshable_runner(vec![
        no_registrations(),
        json_http_response("200 OK", pool_body()),
        registration_created_response(),
        unauthorized_response(),
        refreshed_token_response(),
        rate_limit_response(),
    ]);
    let key_directory = private_credential_directory();
    let key_path = key_directory.path().join("builder-one.key");

    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "issue",
            "--runner",
            "builder-one",
            "--pool",
            POOL_ID,
            "--key-file",
            key_path.to_str().unwrap(),
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &borrowed(&environment),
    );

    assert_eq!(output.status.code(), Some(4), "{output:?}");
    assert!(output.stderr.is_empty());
    let failure: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(failure["outcome"], "rate_limited");
    assert_eq!(failure["runnerId"], RUNNER_ID);
    assert!(!key_path.exists());
    assert_eq!(server.finish().len(), 6);
}

// With `-`, as with no file, standard output carries the key alone, as one line, and
// standard error the status.
#[test]
fn single_runner_key_without_a_file_writes_only_the_key_to_stdout() {
    for (destination, registers) in [
        (Some("-"), true),
        (None, true),
        (Some("-"), false),
        (None, false),
    ] {
        let mut responses = if registers {
            vec![no_registrations(), registration_created_response()]
        } else {
            vec![json_http_response("200 OK", registration_list_body())]
        };
        responses.push(activation_issued_response());
        let (server, _credentials, credential_path) = prepared_runner(responses);
        let working_directory = tempfile::tempdir().unwrap();
        let mut args = vec!["runner", "join-key", "issue", "--runner", "builder-one"];
        if let Some(destination) = destination {
            args.extend(["--key-file", destination]);
        }
        args.extend(["--org", ORGANIZATION, "--allow-insecure-http"]);

        let output = run_with_env_in(
            &args,
            &deployment_environment(&server.api_url, &credential_path),
            working_directory.path(),
        );

        assert!(output.status.success(), "{args:?}: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(stdout.lines().count(), 1, "{stdout}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&stdout).unwrap(),
            activation_issuance_body()["artifact"]
        );
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(RUNNER_ID), "{stderr}");
        assert!(!stderr.contains(ACTIVATION_SECRET), "{stderr}");
        assert_eq!(fs::read_dir(working_directory.path()).unwrap().count(), 0);
        let requests = server.finish();
        let mut expected = vec![registration_lookup()];
        if registers {
            expected.push(registration_creation());
        }
        expected.push(activation_creation(RUNNER_ID));
        assert_eq!(request_lines(&requests), expected);
    }
}

// A name no runner has registers the runner by that name in the pool, then issues its key
// into a file only its owner can read; the result names the runner and never carries the
// token.
#[test]
fn single_runner_key_for_a_new_name_registers_the_runner_in_the_pool() {
    let (server, _credentials, credential_path) = prepared_runner(vec![
        no_registrations(),
        json_http_response("200 OK", pool_list_body()),
        registration_created_response(),
        activation_issued_response(),
    ]);
    let directory = tempfile::tempdir().unwrap();
    let key_path = directory.path().join("builder-one.key");
    let key_path = key_path.to_str().unwrap();

    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "issue",
            "--runner",
            "builder-one",
            "--pool",
            "builders",
            "--key-file",
            key_path,
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains(ACTIVATION_SECRET), "{stdout}");
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["outcome"], "created");
    assert_eq!(report["deployment"], server.api_url);
    assert_eq!(report["runner"]["id"], RUNNER_ID);
    assert_eq!(report["runner"]["name"], "builder-one");
    assert_eq!(
        report["activation"],
        activation_issuance_body()["activation"]
    );
    assert_eq!(report["activationFile"], key_path);
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [
            registration_lookup(),
            format!("GET /api/v1/organizations/{ORGANIZATION}/runner-pools?limit=200 HTTP/1.1"),
            registration_creation(),
            activation_creation(RUNNER_ID),
        ]
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request_body(&requests[2])).unwrap(),
        serde_json::json!({"runnerPoolId": POOL_ID, "name": "builder-one"})
    );
    assert_eq!(
        fs::metadata(key_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let written = fs::read_to_string(key_path).unwrap();
    assert_eq!(written.lines().count(), 1, "{written}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&written).unwrap(),
        activation_issuance_body()["artifact"]
    );
}

/// The organization's directory as an owner reads it: Pam holds `pam@dundermifflin.com`
/// verified, and a colleague holds it unverified.
fn pam_directory() -> Vec<u8> {
    let row = |membership: &str, principal: &str, verified: bool| {
        serde_json::json!({
            "id": membership,
            "principalId": principal,
            "principalType": "human",
            "principalState": "active",
            "displayName": "Pam Beesly",
            "linkedEmails": [{"email": "pam@dundermifflin.com", "verified": verified}],
            "role": "member",
            "state": "active"
        })
    };
    json_http_response(
        "200 OK",
        serde_json::json!({
            "items": [
                row("mem_01k0z6r1w8f4jy2m7q9v3x5abd", OTHER_MEMBER_ID, false),
                row(PAM_MEMBERSHIP, MEMBER_ID, true),
            ]
        }),
    )
}

const PAM_MEMBERSHIP: &str = "mem_01k0z6r1w8f4jy2m7q9v3x5abc";

// `--member` sends the member's principal ID and no pool: a principal ID as it is, a
// membership ID or a verified address as the directory resolves it.
#[test]
fn single_runner_key_by_member_sends_the_members_principal_and_no_pool() {
    for (member, directory) in [
        (MEMBER_ID, false),
        (PAM_MEMBERSHIP, true),
        ("pam@dundermifflin.com", true),
    ] {
        let mut responses = Vec::new();
        if directory {
            responses.push(pam_directory());
        }
        responses.extend([
            no_registrations(),
            registration_created_response(),
            activation_issued_response(),
        ]);
        let (server, _credentials, credential_path) = prepared_runner(responses);
        let key_directory = tempfile::tempdir().unwrap();
        let key_path = key_directory.path().join("builder-one.key");

        let output = run_with_env(
            &[
                "runner",
                "join-key",
                "issue",
                "--runner",
                "builder-one",
                "--member",
                member,
                "--key-file",
                key_path.to_str().unwrap(),
                "--org",
                ORGANIZATION,
                "--allow-insecure-http",
            ],
            &deployment_environment(&server.api_url, &credential_path),
        );

        assert!(output.status.success(), "{member}: {output:?}");
        let requests = server.finish();
        let mut expected = Vec::new();
        if directory {
            expected.push(format!(
                "GET /api/v1/organizations/{ORGANIZATION}/memberships?limit=200 HTTP/1.1"
            ));
        }
        expected.extend([
            registration_lookup(),
            registration_creation(),
            activation_creation(RUNNER_ID),
        ]);
        assert_eq!(request_lines(&requests), expected, "{member}");
        let creation = &requests[expected.len() - 2];
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(request_body(creation)).unwrap(),
            serde_json::json!({"memberId": MEMBER_ID, "name": "builder-one"}),
            "{member}"
        );
    }
}

// A `--member` the directory does not hold registers nothing, in no pool, the caller's
// own included.
#[test]
fn single_runner_key_for_a_member_the_directory_does_not_hold_registers_nothing() {
    let (server, _credentials, credential_path) = prepared_runner(vec![pam_directory()]);
    let key_directory = tempfile::tempdir().unwrap();
    let key_path = key_directory.path().join("builder-one.key");

    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "issue",
            "--runner",
            "builder-one",
            "--member",
            "nobody@dundermifflin.com",
            "--key-file",
            key_path.to_str().unwrap(),
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["outcome"], "not_found");
    assert_eq!(
        request_lines(&server.finish()),
        [format!(
            "GET /api/v1/organizations/{ORGANIZATION}/memberships?limit=200 HTTP/1.1"
        )]
    );
}

#[test]
fn single_runner_key_with_neither_pool_nor_member_sends_neither() {
    let (server, _credentials, credential_path) = prepared_runner(vec![
        no_registrations(),
        registration_created_response(),
        activation_issued_response(),
    ]);
    let directory = tempfile::tempdir().unwrap();
    let key_path = directory.path().join("builder-one.key");

    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "issue",
            "--runner",
            "builder-one",
            "--key-file",
            key_path.to_str().unwrap(),
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(RUNNER_ID), "{stdout}");
    assert!(!stdout.contains(ACTIVATION_SECRET), "{stdout}");
    let requests = server.finish();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request_body(&requests[1])).unwrap(),
        serde_json::json!({"name": "builder-one"})
    );
    let artifact: serde_json::Value =
        serde_json::from_slice(&fs::read(&key_path).unwrap()).unwrap();
    assert_eq!(artifact["runnerId"], RUNNER_ID);
}

#[test]
fn single_runner_key_without_a_personal_pool_exits_with_pool_personal_unavailable() {
    for json in [true, false] {
        let refused = problem_http_response(
            "409 Conflict",
            serde_json::json!({
                "type": "https://api.usefulmachinery.com/problems/runner-pool-personal-unavailable",
                "title": "Personal runner pool unavailable",
                "status": 409
            }),
        );
        let (server, _credentials, credential_path) =
            prepared_runner(vec![no_registrations(), refused]);
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("builder-one.key");
        let mut args = vec![
            "runner",
            "join-key",
            "issue",
            "--runner",
            "builder-one",
            "--key-file",
            key_path.to_str().unwrap(),
            "--org",
            ORGANIZATION,
        ];
        if json {
            args.push("--json");
        }
        args.push("--allow-insecure-http");

        let output = run_with_env(
            &args,
            &deployment_environment(&server.api_url, &credential_path),
        );

        assert_eq!(output.status.code(), Some(1), "{output:?}");
        if json {
            assert!(output.stderr.is_empty(), "{output:?}");
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["outcome"], "pool_personal_unavailable");
            assert!(result.get("runnerId").is_none(), "{result}");
        } else {
            assert!(output.stdout.is_empty());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("--pool") && stderr.contains("--member"),
                "{stderr}"
            );
            assert!(!stderr.contains("--pool-id"), "{stderr}");
        }
        assert!(!key_path.exists());
        assert_eq!(server.finish().len(), 2);
    }
}

// `--member` beside `--pool`, or without `--runner`, a member that is no principal ID,
// membership ID or address, and `--expires-in` or `--remove-after` beside `--runner` are
// usage errors before anything is read.
#[test]
fn single_runner_key_refuses_a_malformed_target_before_network_access() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let api_url = format!("http://{}/api", listener.local_addr().unwrap());
    let missing_credentials = tempfile::tempdir().unwrap().path().join("missing.json");
    let environment = deployment_environment(&api_url, missing_credentials.to_str().unwrap());

    for target in [
        vec![
            "--runner",
            "builder-one",
            "--member",
            MEMBER_ID,
            "--pool",
            POOL_ID,
        ],
        vec!["--runner", "builder-one", "--member", "prn_malformed"],
        vec!["--runner", "builder-one", "--member", POOL_ID],
        vec!["--member", MEMBER_ID, "--expires-in", "1d"],
        vec!["--runner", "builder-one", "--expires-in", "1d"],
        vec!["--runner", "builder-one", "--remove-after", "1d"],
    ] {
        let mut args = vec!["runner", "join-key", "issue"];
        args.extend(target);
        args.extend(["--org", ORGANIZATION, "--allow-insecure-http"]);
        let output = run_with_env(&args, &environment);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty());
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

// A runner the organization holds gets a key of its own and no second registration;
// `--pool` or `--member` naming the pool it is in is accepted.
#[test]
fn single_runner_key_for_a_runner_that_exists_issues_its_key_alone() {
    for (target, reads) in [
        (vec![], vec![]),
        (
            vec!["--pool", "builders"],
            vec![format!(
                "GET /api/v1/organizations/{ORGANIZATION}/runner-pools?limit=200 HTTP/1.1"
            )],
        ),
        (
            vec!["--member", MEMBER_ID],
            vec![format!(
                "GET /api/v1/organizations/{ORGANIZATION}/runner-pools/{POOL_ID} HTTP/1.1"
            )],
        ),
    ] {
        let mut responses = vec![json_http_response("200 OK", registration_list_body())];
        if target.first() == Some(&"--pool") {
            responses.push(json_http_response("200 OK", pool_list_body()));
        } else if !target.is_empty() {
            responses.push(json_http_response("200 OK", personal_pool_body()));
        }
        responses.push(activation_issued_response());
        let (server, _credentials, credential_path) = prepared_runner(responses);
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("builder-one.key");
        let mut args = vec!["runner", "join-key", "issue", "--runner", "builder-one"];
        args.extend(target.iter().copied());
        args.extend([
            "--key-file",
            key_path.to_str().unwrap(),
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ]);

        let output = run_with_env(
            &args,
            &deployment_environment(&server.api_url, &credential_path),
        );

        assert!(output.status.success(), "{args:?}: {output:?}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["outcome"], "created");
        assert_eq!(report["runner"]["id"], RUNNER_ID);
        assert_eq!(
            report["activation"],
            activation_issuance_body()["activation"]
        );
        assert_eq!(report["activationFile"], key_path.to_str().unwrap());
        let requests = server.finish();
        let mut expected = vec![registration_lookup()];
        expected.extend(reads);
        expected.push(activation_creation(RUNNER_ID));
        assert_eq!(request_lines(&requests), expected, "{args:?}");
    }
}

// `--pool` or `--member` for a runner in another pool exits 2 naming the runner's pool and
// `useful runner update`, and issues nothing.
#[test]
fn single_runner_key_for_a_runner_in_another_pool_exits_2_and_issues_nothing() {
    for (target, pool_read) in [
        (
            ["--pool", "ci"],
            json_http_response("200 OK", serde_json::json!({"items": [shared_pool_body()]})),
        ),
        (
            ["--member", OTHER_MEMBER_ID],
            json_http_response("200 OK", personal_pool_body()),
        ),
    ] {
        let (server, _credentials, credential_path) = prepared_runner(vec![
            json_http_response("200 OK", registration_list_body()),
            pool_read,
        ]);
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("builder-one.key");
        let mut args = vec!["runner", "join-key", "issue", "--runner", "builder-one"];
        args.extend(target);
        args.extend([
            "--key-file",
            key_path.to_str().unwrap(),
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ]);

        let output = run_with_env(
            &args,
            &deployment_environment(&server.api_url, &credential_path),
        );

        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("builders"), "{stderr}");
        assert!(stderr.contains("useful runner update"), "{stderr}");
        assert!(!key_path.exists());
        let requests = server.finish();
        assert_eq!(requests.len(), 2, "{args:?}");
        assert!(requests.iter().all(|request| request.starts_with("GET ")));
    }
}

// A registration that succeeds and a key that fails reports the runner and names the command
// that issues its key without registering another; a runner that existed is reported as the
// failure alone.
#[test]
fn single_runner_key_reports_a_failed_issue_with_the_registered_runner() {
    for json in [true, false] {
        let (server, _directory, credential_path) = prepared_runner(vec![
            no_registrations(),
            registration_created_response(),
            rate_limit_response(),
        ]);
        let key_directory = private_credential_directory();
        let key_path = key_directory.path().join("builder-one.key");
        let mut args = vec![
            "runner",
            "join-key",
            "issue",
            "--runner",
            "builder-one",
            "--key-file",
            key_path.to_str().unwrap(),
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ];
        if json {
            args.push("--json");
        }

        let output = run_with_env(
            &args,
            &deployment_environment(&server.api_url, &credential_path),
        );

        assert_eq!(output.status.code(), Some(4), "{output:?}");
        if json {
            assert!(output.stderr.is_empty());
            let failure: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(failure["outcome"], "rate_limited");
            assert_eq!(failure["runnerId"], RUNNER_ID);
            assert_eq!(failure["deployment"], server.api_url);
        } else {
            assert!(output.stdout.is_empty());
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(
                stderr.contains(&format!(
                    "useful runner join-key issue --runner {RUNNER_ID} --key-file <PATH> --org {ORGANIZATION}"
                )),
                "{stderr}"
            );
        }
        assert!(!key_path.exists());
        assert_eq!(server.finish().len(), 3);
    }

    let (server, _directory, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", registration_list_body()),
        rate_limit_response(),
    ]);
    let key_directory = private_credential_directory();
    let key_path = key_directory.path().join("builder-one.key");
    let existing = run_with_env(
        &[
            "runner",
            "join-key",
            "issue",
            "--runner",
            "builder-one",
            "--key-file",
            key_path.to_str().unwrap(),
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );
    assert_eq!(existing.status.code(), Some(4), "{existing:?}");
    let failure: serde_json::Value = serde_json::from_slice(&existing.stdout).unwrap();
    assert_eq!(failure["outcome"], "rate_limited");
    assert!(failure.get("runnerId").is_none(), "{failure}");
    assert!(!key_path.exists());
    assert_eq!(server.finish().len(), 2);
}

// A runner ID the organization does not hold is `not_found`, and nothing is registered under
// it.
#[test]
fn single_runner_key_for_an_unknown_runner_id_registers_nothing() {
    let missing = problem_http_response(
        "404 Not Found",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/not-found",
            "title": "Not found",
            "status": 404
        }),
    );
    let (server, _directory, credential_path) = prepared_runner(vec![missing]);

    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "issue",
            "--runner",
            RUNNER_ID,
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    assert_eq!(
        request_lines(&server.finish()),
        [format!(
            "GET /api/v1/organizations/{ORGANIZATION}/runner-registrations/{RUNNER_ID} HTTP/1.1"
        )]
    );
}

/// The API's answer to the read of the signed-in principal, `MEMBER_ID`.
pub(super) fn current_principal_response() -> Vec<u8> {
    json_http_response(
        "200 OK",
        serde_json::json!({
            "principal": {"id": MEMBER_ID, "type": "human", "state": "active"}
        }),
    )
}

pub(super) fn registration_created_response() -> Vec<u8> {
    http_response_with_headers(
        "201 Created",
        Some("application/json"),
        &[
            ("Idempotency-Key", ECHO_IDEMPOTENCY_KEY),
            (
                "Location",
                &format!("/v1/organizations/{ORGANIZATION}/runner-registrations/{RUNNER_ID}"),
            ),
        ],
        &serde_json::to_vec(&registration_body()).unwrap(),
    )
}

fn activation_issued_response() -> Vec<u8> {
    activation_issued_response_with(&activation_issuance_body())
}

pub(super) fn activation_issued_response_with(issuance: &serde_json::Value) -> Vec<u8> {
    http_response_with_headers(
        "201 Created",
        Some("application/json"),
        &[
            ("Idempotency-Key", ECHO_IDEMPOTENCY_KEY),
            (
                "Location",
                &format!(
                    "/v1/organizations/{ORGANIZATION}/runner-registrations/{RUNNER_ID}/activations/{ACTIVATION_ID}"
                ),
            ),
        ],
        &serde_json::to_vec(issuance).unwrap(),
    )
}

#[test]
fn runner_disable_refused_by_cloud_exits_with_forbidden() {
    let refused = problem_http_response(
        "403 Forbidden",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/forbidden",
            "title": "Forbidden",
            "status": 403
        }),
    );
    let (server, _directory, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", registration_body()),
        refused,
    ]);

    let output = run_with_env(
        &[
            "runner",
            "disable",
            RUNNER_ID,
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["outcome"], "forbidden");
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].starts_with(&format!(
        "PUT /api/v1/organizations/{ORGANIZATION}/runner-registrations/{RUNNER_ID}/mode HTTP/1.1\r\n"
    )));
}

#[test]
fn credential_list_returns_only_lifecycle_metadata() {
    let credentials = serde_json::json!({
        "items": [credential_body("active")],
        "nextCursor": "next-credentials"
    });
    let (server, _directory, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", registration_body()),
        json_http_response("200 OK", credentials),
    ]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "runner",
            "credential",
            "list",
            RUNNER_ID,
            "--limit",
            "1",
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["outcome"], "listed");
    assert_eq!(result["deployment"], server.api_url);
    assert_eq!(result["items"][0], credential_body("active"));
    let encoded = String::from_utf8(output.stdout).unwrap();
    assert!(!encoded.contains("verifier"));
    assert!(!encoded.contains("secret"));

    let requests = server.finish();
    assert!(requests[1].starts_with(&format!(
        "GET /api/v1/organizations/{ORGANIZATION}/runner-registrations/{RUNNER_ID}/credentials?limit=1 HTTP/1.1\r\n"
    )));
}

#[test]
fn credential_mutations_send_empty_bodies_and_idempotency_keys() {
    for (after, subresource, state) in [
        (Some("1h"), "retirement", "retiring"),
        (Some("60m"), "retirement", "retiring"),
        (None, "revocation", "revoked"),
    ] {
        let response = http_response_with_headers(
            "200 OK",
            Some("application/json"),
            &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
            &serde_json::to_vec(&credential_body(state)).unwrap(),
        );
        let (server, _directory, credential_path) = prepared_runner(vec![
            json_http_response("200 OK", registration_body()),
            response,
        ]);
        let environment = deployment_environment(&server.api_url, &credential_path);

        let mut args = vec![
            "runner",
            "credential",
            "revoke",
            CREDENTIAL_ID,
            "--runner",
            RUNNER_ID,
            "--yes",
        ];
        if let Some(after) = after {
            args.extend(["--after", after]);
        }
        args.extend(["--org", ORGANIZATION, "--json", "--allow-insecure-http"]);

        let output = run_with_env(&args, &environment);

        assert!(output.status.success(), "{args:?}: {output:?}");
        assert!(output.stderr.is_empty());
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["deployment"], server.api_url);
        assert_eq!(result["outcome"], state);
        assert_eq!(result["credential"], credential_body(state));

        let requests = server.finish();
        assert!(requests[1].starts_with(&format!(
            "POST /api/v1/organizations/{ORGANIZATION}/runner-registrations/{RUNNER_ID}/credentials/{CREDENTIAL_ID}/{subresource} HTTP/1.1\r\n"
        )));
        assert_eq!(request_body(&requests[1]), "{}");
        let key = header_value(&requests[1], "idempotency-key");
        assert_eq!(key.len(), 64);
        assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}

#[test]
fn credential_revoke_refuses_another_grace_or_no_runner_before_network_access() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let api_url = format!("http://{}/api", listener.local_addr().unwrap());
    let missing_credentials = tempfile::tempdir().unwrap().path().join("missing.json");
    let environment = deployment_environment(&api_url, missing_credentials.to_str().unwrap());

    for (args, grace) in [
        (
            vec![
                "runner",
                "credential",
                "revoke",
                CREDENTIAL_ID,
                "--runner",
                RUNNER_ID,
                "--yes",
                "--after",
                "2h",
                "--org",
                ORGANIZATION,
                "--allow-insecure-http",
            ],
            true,
        ),
        (
            vec![
                "runner",
                "credential",
                "revoke",
                CREDENTIAL_ID,
                "--yes",
                "--org",
                ORGANIZATION,
                "--allow-insecure-http",
            ],
            false,
        ),
    ] {
        let output = run_with_env(&args, &environment);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        if grace {
            assert!(stderr.contains("--after 1h"), "{stderr}");
        } else {
            assert!(stderr.contains("--runner"), "{stderr}");
        }
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn refused_credential_transition_reports_its_outcome_and_advises_listing_credentials() {
    for json in [true, false] {
        let refused = problem_http_response(
            "409 Conflict",
            serde_json::json!({
                "type": "https://api.usefulmachinery.com/problems/runner-credential-transition-unavailable",
                "title": "Runner credential transition unavailable",
                "status": 409
            }),
        );
        let (server, _directory, credential_path) = prepared_runner(vec![
            json_http_response("200 OK", registration_body()),
            refused,
        ]);
        let environment = deployment_environment(&server.api_url, &credential_path);
        let mut args = vec![
            "runner",
            "credential",
            "revoke",
            CREDENTIAL_ID,
            "--runner",
            RUNNER_ID,
            "--yes",
            "--after",
            "1h",
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ];
        if json {
            args.push("--json");
        }

        let output = run_with_env(&args, &environment);

        assert_eq!(output.status.code(), Some(1));
        if json {
            assert!(output.stderr.is_empty());
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["outcome"], "credential_transition_unavailable");
        } else {
            assert!(output.stdout.is_empty());
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .to_ascii_lowercase()
                    .contains("list credentials")
            );
        }
        assert_eq!(server.finish().len(), 2);
    }
}

/// A development operator configuration in `directory` whose state, socket and work root
/// lie under it, answering the configuration's and the state's paths.
fn enrollment_host(directory: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    for child in ["run", "work"] {
        let path = directory.join(child);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
    }
    let state_path = directory.join("state/runner-state.json");
    let config_path = directory.join("runner.json");
    fs::write(
        &config_path,
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "deploymentMode": "development",
            "runnerStatePath": state_path,
            "controlSocketPath": directory.join("run/runner.sock"),
            "workRoot": directory.join("work")
        }))
        .unwrap(),
    )
    .unwrap();
    (config_path, state_path)
}

/// The single-runner key of `RUNNER_ID` for Cloud at `api_url`.
fn single_runner_key(api_url: &str) -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": 1,
        "activationUrl": format!(
            "{}/v1/runner-enrollments/{ACTIVATION_ID}/activate",
            api_url.trim_end_matches("/api")
        ),
        "activationToken": format!("{ACTIVATION_ID}.{ACTIVATION_SECRET}"),
        "runnerId": RUNNER_ID,
        "expiresAt": "2999-01-01T00:00:00Z"
    })
}

#[test]
fn enrollment_accepts_a_key_from_explicit_stdin_without_a_sign_in() {
    let witness = super::runner_enrollment::ConnectionWitness::new();
    let enrollment = serde_json::json!({
        "schemaVersion": 1,
        "runnerId": RUNNER_ID,
        "runnerName": "builder-one",
        "organization": {
            "id": ORGANIZATION_ID,
            "displayName": "Acme Research"
        },
        "runnerPool": {
            "id": POOL_ID,
            "name": "builders"
        },
        "credentialId": "rrc_01k0z6r1w8f4jy2m7q9v3x5abc",
        "connectionUrl": witness.url
    });
    let server = ScriptedServer::respond(vec![json_http_response("201 Created", enrollment)]);
    let directory = tempfile::tempdir().unwrap();
    let (config_path, state_path) = enrollment_host(directory.path());
    let artifact = single_runner_key(&server.api_url).to_string();

    let mut command = super::runner_enrollment::serve_command(&[
        "--join-key-file",
        "-",
        "--config",
        config_path.to_str().unwrap(),
    ]);
    command.env_remove(CREDENTIALS_FILE_VARIABLE);
    for variable in DEPLOYMENT_VARIABLES {
        command.env_remove(variable);
    }
    let serve = super::runner_enrollment::ServeProcess::start(
        command,
        super::runner_enrollment::StandardInput::Piped(&artifact),
    );
    let (_, stderr) = super::runner_enrollment::first_connection(serve, &witness);

    let state: serde_json::Value = serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    assert_eq!(state["runnerId"], RUNNER_ID);
    let secret = state["currentCredential"]["secret"].as_str().unwrap();
    assert!(stderr.contains(RUNNER_ID), "{stderr}");
    assert!(!stderr.contains(secret), "{stderr}");
    assert!(!stderr.contains(ACTIVATION_SECRET), "{stderr}");

    let request = server.finish().pop().unwrap();
    assert!(request.starts_with(&format!(
        "POST /v1/runner-enrollments/{ACTIVATION_ID}/activate HTTP/1.1\r\n"
    )));
    assert_eq!(
        header_value(&request, "authorization"),
        format!("Bearer {ACTIVATION_ID}.{ACTIVATION_SECRET}")
    );
    assert!(!request_body(&request).contains(secret));
}

#[test]
fn enrollment_gone_reports_that_the_commit_did_not_complete() {
    let server = ScriptedServer::respond(vec![http_response("410 Gone", None, &[])]);
    let directory = private_credential_directory();
    let (config_path, state_path) = enrollment_host(directory.path());
    let activation_path = directory.path().join("activation.json");
    fs::write(
        &activation_path,
        single_runner_key(&server.api_url).to_string(),
    )
    .unwrap();
    fs::set_permissions(&activation_path, Permissions::from_mode(0o600)).unwrap();

    let output = super::runner_enrollment::serve_command(&[
        "--join-key-file",
        activation_path.to_str().unwrap(),
        "--config",
        config_path.to_str().unwrap(),
    ])
    .output()
    .unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(ACTIVATION_ID),
        "{output:?}"
    );
    assert!(!state_path.exists());
    let receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(state_path.with_file_name(".runner-enrollment.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["activationId"], ACTIVATION_ID);
    assert_eq!(receipt["disposition"], "gone");
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn runner_mode_commands_send_closed_targets_with_idempotency() {
    for (command, mode) in [
        ("enable", "enabled"),
        ("drain", "draining"),
        ("disable", "disabled"),
    ] {
        let response = http_response_with_headers(
            "200 OK",
            Some("application/json"),
            &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
            &serde_json::to_vec(&registration_body()).unwrap(),
        );
        let (server, _directory, credential_path) = prepared_runner(vec![
            json_http_response("200 OK", registration_body()),
            response,
        ]);
        let environment = deployment_environment(&server.api_url, &credential_path);

        let output = run_with_env(
            &[
                "runner",
                command,
                RUNNER_ID,
                "--org",
                ORGANIZATION,
                "--json",
                "--allow-insecure-http",
            ],
            &environment,
        );

        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["outcome"], mode);
        let requests = server.finish();
        assert!(requests[1].starts_with(&format!(
            "PUT /api/v1/organizations/{ORGANIZATION}/runner-registrations/{RUNNER_ID}/mode HTTP/1.1\r\n"
        )));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(request_body(&requests[1])).unwrap(),
            serde_json::json!({"mode": mode})
        );
        assert_eq!(
            header_value(&requests[1], "content-type"),
            "application/json"
        );
        assert_eq!(header_value(&requests[1], "idempotency-key").len(), 64);
    }
}

fn credential_mode_response(mode: &str) -> Vec<u8> {
    let mut runner = registration_body();
    runner["administration"]["credentialMode"] = serde_json::json!(mode);
    registration_change_response(&runner)
}

const GPU_POOL_ID: &str = "rpl_01k0z6r1w8f4jy2m7q9v3x5abe";

/// The registration of `registration_body` as Cloud returns it once moved to the `gpu` pool,
/// and renamed to `name`.
fn moved_registration_body(name: &str) -> serde_json::Value {
    let mut runner = registration_body();
    runner["runnerPool"] = serde_json::json!({"id": GPU_POOL_ID, "name": "gpu"});
    runner["name"] = serde_json::json!(name);
    runner
}

fn gpu_pool_list_body() -> serde_json::Value {
    let mut pool = pool_body();
    pool["id"] = serde_json::json!(GPU_POOL_ID);
    pool["name"] = serde_json::json!("gpu");
    serde_json::json!({"items": [pool]})
}

/// A change Cloud answers with the registration, echoing the request's key.
fn registration_change_response(runner: &serde_json::Value) -> Vec<u8> {
    http_response_with_headers(
        "200 OK",
        Some("application/json"),
        &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
        &serde_json::to_vec(runner).unwrap(),
    )
}

// SC-RUNNERPOOL-8
#[test]
fn runner_credentials_sets_a_closed_credential_mode_with_idempotency() {
    for (runner, lookup, mode) in [
        (RUNNER_ID, registration_body(), "cloud"),
        ("builder-one", registration_list_body(), "host"),
    ] {
        let (server, _directory, credential_path) = prepared_runner(vec![
            json_http_response("200 OK", lookup.clone()),
            credential_mode_response(mode),
        ]);
        let environment = deployment_environment(&server.api_url, &credential_path);

        let output = run_with_env(
            &[
                "runner",
                "credentials",
                "--org",
                ORGANIZATION,
                runner,
                mode,
                "--json",
                "--allow-insecure-http",
            ],
            &environment,
        );

        assert!(output.status.success(), "{runner}: {output:?}");
        assert!(output.stderr.is_empty());
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["schemaVersion"], 1);
        assert_eq!(result["outcome"], "credential_mode_set");
        assert_eq!(result["runner"]["administration"]["credentialMode"], mode);
        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].starts_with(&format!(
            "PUT /api/v1/organizations/{ORGANIZATION}/runner-registrations/{RUNNER_ID}/credential-mode HTTP/1.1\r\n"
        )));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(request_body(&requests[1])).unwrap(),
            serde_json::json!({"credentialMode": mode})
        );
        assert_eq!(
            header_value(&requests[1], "content-type"),
            "application/json"
        );
        assert_eq!(header_value(&requests[1], "idempotency-key").len(), 64);

        let (server, _directory, credential_path) = prepared_runner(vec![
            json_http_response("200 OK", lookup),
            credential_mode_response(mode),
        ]);
        let output = run_with_env(
            &[
                "runner",
                "credentials",
                "--org",
                ORGANIZATION,
                runner,
                mode,
                "--allow-insecure-http",
            ],
            &deployment_environment(&server.api_url, &credential_path),
        );
        assert!(output.status.success(), "{runner}: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(credential_mode_line(&stdout, "credentials").0, mode);
        assert_eq!(server.finish().len(), 2);
    }
}

#[test]
fn runner_credentials_refused_by_cloud_exits_with_forbidden() {
    let refused = problem_http_response(
        "403 Forbidden",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/forbidden",
            "title": "Forbidden",
            "status": 403
        }),
    );
    let (server, _directory, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", registration_body()),
        refused,
    ]);

    let output = run_with_env(
        &[
            "runner",
            "credentials",
            "--org",
            ORGANIZATION,
            RUNNER_ID,
            "cloud",
            "--json",
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["outcome"], "forbidden");
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].starts_with(&format!(
        "PUT /api/v1/organizations/{ORGANIZATION}/runner-registrations/{RUNNER_ID}/credential-mode HTTP/1.1\r\n"
    )));
}

#[test]
fn runner_credentials_refuses_an_open_or_missing_mode_before_network_access() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let api_url = format!("http://{}/api", listener.local_addr().unwrap());
    let missing_credentials = tempfile::tempdir().unwrap().path().join("missing.json");
    let environment = deployment_environment(&api_url, missing_credentials.to_str().unwrap());

    for mode in [Some("both"), Some("none"), Some("Cloud"), None] {
        let mut args = vec!["runner", "credentials", "--org", ORGANIZATION, RUNNER_ID];
        args.extend(mode);
        args.push("--allow-insecure-http");
        let output = run_with_env(&args, &environment);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty());
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn runner_credentials_without_a_credential_exits_with_sign_in_required() {
    let output = run(&[
        "runner",
        "credentials",
        "--org",
        ORGANIZATION,
        RUNNER_ID,
        "cloud",
    ]);

    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(output.stdout.is_empty());
}

/// The responses `runner update builder-one --pool gpu --name builder-two` reads, ending with
/// `rename`, the answer to its rename.
fn update_responses(rename: Vec<u8>) -> Vec<Vec<u8>> {
    vec![
        json_http_response("200 OK", registration_list_body()),
        json_http_response("200 OK", registration_body()),
        json_http_response("200 OK", gpu_pool_list_body()),
        registration_change_response(&moved_registration_body("builder-one")),
        json_http_response("200 OK", moved_registration_body("builder-one")),
        rename,
    ]
}

const UPDATE_ARGUMENTS: [&str; 10] = [
    "runner",
    "update",
    "builder-one",
    "--pool",
    "gpu",
    "--name",
    "builder-two",
    "--org",
    ORGANIZATION,
    "--json",
];

/// The changes among `requests`: every request but a read.
fn changes(requests: &[String]) -> Vec<&String> {
    requests
        .iter()
        .filter(|request| !request.starts_with("GET "))
        .collect()
}

#[test]
fn runner_update_resolves_the_destination_pool_and_sends_only_its_id() {
    for pool in [POOL_ID, "builders"] {
        let (server, _directory, credential_path) = prepared_runner(vec![
            json_http_response("200 OK", registration_body()),
            json_http_response("200 OK", registration_body()),
            json_http_response(
                "200 OK",
                if pool == POOL_ID {
                    pool_body()
                } else {
                    pool_list_body()
                },
            ),
            registration_change_response(&registration_body()),
        ]);
        let environment = deployment_environment(&server.api_url, &credential_path);

        let output = run_with_env(
            &[
                "runner",
                "update",
                RUNNER_ID,
                "--pool",
                pool,
                "--org",
                ORGANIZATION,
                "--json",
                "--allow-insecure-http",
            ],
            &environment,
        );

        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty());
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["outcome"], "updated");
        assert_eq!(result["applied"], serde_json::json!(["pool"]));
        let requests = server.finish();
        if pool != POOL_ID {
            assert!(requests[2].starts_with(&format!(
                "GET /api/v1/organizations/{ORGANIZATION}/runner-pools?limit=200 HTTP/1.1\r\n"
            )));
        }
        let changes = changes(&requests);
        assert_eq!(changes.len(), 1, "{requests:?}");
        assert!(changes[0].starts_with(&format!(
            "PUT /api/v1/organizations/{ORGANIZATION}/runner-registrations/{RUNNER_ID}/pool HTTP/1.1\r\n"
        )));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(request_body(changes[0])).unwrap(),
            serde_json::json!({"runnerPoolId": POOL_ID})
        );
    }
}

// The runner's name is resolved once, the move is sent before the rename, and each change
// has its own key.
#[test]
fn runner_update_moves_then_renames_each_under_its_own_key() {
    let (server, _directory, credential_path) = prepared_runner(update_responses(
        registration_change_response(&moved_registration_body("builder-two")),
    ));
    let environment = deployment_environment(&server.api_url, &credential_path);
    let mut args = UPDATE_ARGUMENTS.to_vec();
    args.push("--allow-insecure-http");

    let output = run_with_env(&args, &environment);

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["outcome"], "updated");
    assert_eq!(result["applied"], serde_json::json!(["pool", "name"]));
    assert_eq!(result["runner"]["runnerPool"]["id"], GPU_POOL_ID);
    assert_eq!(result["runner"]["name"], "builder-two");
    let requests = server.finish();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("/runner-registrations?"))
            .count(),
        1,
        "the runner's name is looked up once: {requests:?}"
    );
    let changes = changes(&requests);
    assert_eq!(changes.len(), 2, "{requests:?}");
    assert!(changes[0].starts_with(&format!(
        "PUT /api/v1/organizations/{ORGANIZATION}/runner-registrations/{RUNNER_ID}/pool HTTP/1.1\r\n"
    )));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request_body(changes[0])).unwrap(),
        serde_json::json!({"runnerPoolId": GPU_POOL_ID})
    );
    assert!(changes[1].starts_with(&format!(
        "PATCH /api/v1/organizations/{ORGANIZATION}/runner-registrations/{RUNNER_ID} HTTP/1.1\r\n"
    )));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request_body(changes[1])).unwrap(),
        serde_json::json!({"name": "builder-two"})
    );
    let keys = changes
        .iter()
        .map(|request| header_value(request, "idempotency-key"))
        .collect::<Vec<_>>();
    assert!(keys.iter().all(|key| key.len() == 64), "{keys:?}");
    assert_ne!(keys[0], keys[1]);
}

// A rename that fails after the move leaves the move in place, and the command exits with
// the rename's failure, naming what was applied and the runner as moved.
#[test]
fn runner_update_whose_rename_fails_reports_the_move_it_kept() {
    for json in [true, false] {
        let (server, _directory, credential_path) =
            prepared_runner(update_responses(problem_http_response(
                "409 Conflict",
                serde_json::json!({
                    "type": "https://api.usefulmachinery.com/problems/runner-name-unavailable",
                    "title": "Runner name unavailable",
                    "status": 409
                }),
            )));
        let environment = deployment_environment(&server.api_url, &credential_path);
        let mut args = UPDATE_ARGUMENTS.to_vec();
        if !json {
            args.pop();
        }
        args.push("--allow-insecure-http");

        let output = run_with_env(&args, &environment);

        assert_eq!(output.status.code(), Some(1), "{output:?}");
        if json {
            assert!(output.stderr.is_empty());
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["outcome"], "name_unavailable");
            assert_eq!(result["applied"], serde_json::json!(["pool"]));
            assert_eq!(result["runner"]["runnerPool"]["id"], GPU_POOL_ID);
            assert_eq!(result["runner"]["name"], "builder-one");
        } else {
            assert!(output.stdout.is_empty());
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(stderr.starts_with("error: "), "{stderr}");
            assert!(stderr.contains(RUNNER_ID), "{stderr}");
        }
        assert_eq!(changes(&server.finish()).len(), 2);
    }
}

// The move is sent first, so a move Cloud refuses sends no rename and a runner named by
// its name is still found by it.
#[test]
fn runner_update_whose_move_is_refused_sends_no_rename() {
    let (server, _directory, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", registration_list_body()),
        json_http_response("200 OK", registration_body()),
        json_http_response("200 OK", gpu_pool_list_body()),
        problem_http_response(
            "409 Conflict",
            serde_json::json!({
                "type": "https://api.usefulmachinery.com/problems/runner-pool-move-unavailable",
                "title": "Runner pool move unavailable",
                "status": 409
            }),
        ),
    ]);
    let environment = deployment_environment(&server.api_url, &credential_path);
    let mut args = UPDATE_ARGUMENTS.to_vec();
    args.push("--allow-insecure-http");

    let output = run_with_env(&args, &environment);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["outcome"], "pool_move_unavailable");
    assert!(result.get("applied").is_none(), "{result}");
    let requests = server.finish();
    let changes = changes(&requests);
    assert_eq!(changes.len(), 1, "{requests:?}");
    assert!(changes[0].starts_with("PUT "), "{requests:?}");
}

#[test]
fn runner_update_without_a_change_exits_2_and_sends_nothing() {
    let (server, _directory, credential_path) = prepared_runner(vec![]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "runner",
            "update",
            "builder-one",
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(server.finish().is_empty());
}

// A runner command acts in the organization in effect: the one `--org` names, with no request
// before its own, or else the caller's only active membership, by ID; with several memberships
// and no `--org` it exits 2 naming `--org` after the membership read.
#[test]
fn runner_show_acts_in_the_organization_in_effect() {
    let (output, requests) = run_in_effect(
        &["runner", "show", "builder-one", "--json"],
        vec![json_http_response("200 OK", registration_list_body())],
        &["--org", ORGANIZATION],
        &[],
    );
    assert!(output.status.success(), "{output:?}");
    assert!(!requests.is_empty());
    for line in request_lines(&requests) {
        assert!(
            line.contains(&format!(" /api/v1/organizations/{ORGANIZATION}/")),
            "{line}"
        );
    }

    let (output, requests) = run_in_effect(
        &["runner", "show", "builder-one", "--json"],
        vec![
            active_memberships(&[(ORGANIZATION_ID, ORGANIZATION)]),
            json_http_response("200 OK", registration_list_body()),
        ],
        &[],
        &[],
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        request_lines(&requests),
        [
            LIST_CURRENT_MEMBERSHIPS.trim_end(),
            &format!(
                "GET /api/v1/organizations/{ORGANIZATION_ID}/runner-registrations?limit=200 HTTP/1.1"
            ),
        ]
    );

    let (output, requests) = run_in_effect(
        &["runner", "show", "builder-one", "--json"],
        vec![active_memberships(&[
            (ORGANIZATION_ID, ORGANIZATION),
            (OTHER_IN_EFFECT_ID, "acme-labs"),
        ])],
        &[],
        &[],
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--org"));
    assert_eq!(
        request_lines(&requests),
        [LIST_CURRENT_MEMBERSHIPS.trim_end()]
    );
}

/// A registration of `registration_body` with its own ID and name, in the pool `pool_id`.
fn registration_in(id: &str, name: &str, pool_id: &str) -> serde_json::Value {
    let mut runner = registration_body();
    runner["id"] = serde_json::json!(id);
    runner["name"] = serde_json::json!(name);
    runner["runnerPool"]["id"] = serde_json::json!(pool_id);
    runner
}

#[test]
fn runner_list_with_a_pool_reads_every_page_and_prints_only_the_pools_runners() {
    const FIRST: &str = "rnr_01k0z6r1w8f4jy2m7q9v3x5ab1";
    const OTHER: &str = "rnr_01k0z6r1w8f4jy2m7q9v3x5ab2";
    const LAST: &str = "rnr_01k0z6r1w8f4jy2m7q9v3x5ab3";
    let (server, _directory, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", pool_list_body()),
        json_http_response(
            "200 OK",
            serde_json::json!({
                "items": [
                    registration_in(FIRST, "builder-one", POOL_ID),
                    registration_in(OTHER, "gpu-one", GPU_POOL_ID),
                ],
                "nextCursor": "page-2"
            }),
        ),
        json_http_response(
            "200 OK",
            serde_json::json!({"items": [registration_in(LAST, "builder-two", POOL_ID)]}),
        ),
    ]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "runner",
            "list",
            "--pool",
            "builders",
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty());
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["outcome"], "listed");
    assert_eq!(
        result["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|runner| runner["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [FIRST, LAST]
    );
    assert!(result.get("nextCursor").is_none(), "{result}");
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [
            format!("GET /api/v1/organizations/{ORGANIZATION}/runner-pools?limit=200 HTTP/1.1"),
            format!(
                "GET /api/v1/organizations/{ORGANIZATION}/runner-registrations?limit=200 HTTP/1.1"
            ),
            format!(
                "GET /api/v1/organizations/{ORGANIZATION}/runner-registrations?limit=200&cursor=page-2 HTTP/1.1"
            ),
        ]
    );
}

#[test]
fn pool_update_sends_the_rename_and_reports_the_renamed_pool() {
    let mut renamed = pool_body();
    renamed["name"] = serde_json::json!("renamed");
    let (server, _directory, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", pool_list_body()),
        http_response_with_headers(
            "200 OK",
            Some("application/json"),
            &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
            &serde_json::to_vec(&renamed).unwrap(),
        ),
    ]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "runner",
            "pool",
            "update",
            "builders",
            "--name",
            "renamed",
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert!(output.status.success(), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["outcome"], "renamed");
    assert_eq!(result["pool"]["name"], "renamed");
    let request = server.finish().pop().unwrap();
    assert!(request.starts_with(&format!(
        "PATCH /api/v1/organizations/{ORGANIZATION}/runner-pools/{POOL_ID} HTTP/1.1\r\n"
    )));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request_body(&request)).unwrap(),
        serde_json::json!({"name": "renamed"})
    );
}

fn personal_pool_body() -> serde_json::Value {
    let mut pool = pool_body();
    pool["member"] = serde_json::json!({"id": MEMBER_ID, "displayName": "Ada Lovelace"});
    pool
}

#[test]
fn pool_member_commands_are_unknown_and_send_nothing() {
    for leaf in [
        vec!["set", ORGANIZATION, POOL_ID, MEMBER_ID],
        vec!["remove", ORGANIZATION, POOL_ID, "--yes"],
    ] {
        let (server, _directory, credential_path) = prepared_runner(vec![]);
        let environment = deployment_environment(&server.api_url, &credential_path);
        let mut args = vec!["runner", "pool", "member"];
        args.extend(leaf);
        args.push("--allow-insecure-http");

        let output = run_with_env(&args, &environment);

        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
        assert!(server.finish().is_empty());
    }
}

/// The shared 403 `forbidden` problem whose `reason` names the personal-pool refusal.
fn personal_pool_refusal_response() -> Vec<u8> {
    problem_http_response(
        "403 Forbidden",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/forbidden",
            "title": "Forbidden",
            "status": 403,
            "detail": "A member's personal runner pool cannot be renamed, or deleted while its member belongs to the organization.",
            "reason": "runner-pool-personal"
        }),
    )
}

#[test]
fn personal_pool_rename_refusal_exits_with_pool_personal() {
    for json in [true, false] {
        let (server, _directory, credential_path) = prepared_runner(vec![
            json_http_response("200 OK", personal_pool_body()),
            personal_pool_refusal_response(),
        ]);
        let environment = deployment_environment(&server.api_url, &credential_path);
        let mut args = vec![
            "runner",
            "pool",
            "update",
            POOL_ID,
            "--name",
            "renamed",
            "--org",
            ORGANIZATION,
        ];
        if json {
            args.push("--json");
        }
        args.push("--allow-insecure-http");

        let output = run_with_env(&args, &environment);

        assert_eq!(output.status.code(), Some(1));
        if json {
            assert!(output.stderr.is_empty());
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["outcome"], "pool_personal");
        } else {
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).starts_with("error: "));
        }
        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        assert!(requests[1].starts_with(&format!(
            "PATCH /api/v1/organizations/{ORGANIZATION}/runner-pools/{POOL_ID} HTTP/1.1\r\n"
        )));
    }
}

#[test]
fn personal_pool_deletion_refusal_exits_with_pool_personal() {
    for json in [true, false] {
        let (server, _directory, credential_path) = prepared_runner(vec![
            json_http_response("200 OK", personal_pool_body()),
            personal_pool_refusal_response(),
        ]);
        let environment = deployment_environment(&server.api_url, &credential_path);
        let mut args = vec![
            "runner",
            "pool",
            "delete",
            POOL_ID,
            "--org",
            ORGANIZATION,
            "--yes",
        ];
        if json {
            args.push("--json");
        }
        args.push("--allow-insecure-http");

        let output = run_with_env(&args, &environment);

        assert_eq!(output.status.code(), Some(1));
        if json {
            assert!(output.stderr.is_empty());
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["outcome"], "pool_personal");
            assert_eq!(result["runnerPoolId"], POOL_ID);
            assert!(result.get("commitment").is_none(), "{result}");
        } else {
            assert!(output.stdout.is_empty());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.starts_with("error: "), "{stderr}");
            assert!(stderr.contains(POOL_ID), "{stderr}");
        }
        let requests = server.finish();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("GET "));
        assert!(requests[1].starts_with(&format!(
            "DELETE /api/v1/organizations/{ORGANIZATION}/runner-pools/{POOL_ID} HTTP/1.1\r\n"
        )));
    }
}

#[test]
fn pool_show_prints_the_personal_pool_member() {
    let (server, _directory, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", personal_pool_body()),
        pool_status_unavailable_response(),
    ]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "runner",
            "pool",
            "show",
            POOL_ID,
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            concat!(
                "✓ Runner pool found.\n\n",
                "  Pool:         {}\n",
                "  Name:         builders\n",
                "  Organization: {}\n",
                "  Member:       {} (Ada Lovelace)\n",
                "  Deployment:   {}\n"
            ),
            POOL_ID, ORGANIZATION_ID, MEMBER_ID, server.api_url
        )
    );
    assert_eq!(server.finish().len(), 2);
}

fn pool_status_body() -> serde_json::Value {
    serde_json::json!({
        "runnerPoolId": POOL_ID,
        "queuedRuns": 5,
        "runners": {"total": 7, "online": 4, "offline": 3, "busy": 2, "idle": 1}
    })
}

fn pool_status_unavailable_response() -> Vec<u8> {
    problem_http_response(
        "404 Not Found",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/not-found",
            "title": "Not found",
            "status": 404
        }),
    )
}

fn pool_show(server: &ScriptedServer, credential_path: &str, json: bool) -> std::process::Output {
    let environment = deployment_environment(&server.api_url, credential_path);
    let mut args = vec!["runner", "pool", "show", "builders", "--org", ORGANIZATION];
    if json {
        args.push("--json");
    }
    args.push("--allow-insecure-http");
    run_with_env(&args, &environment)
}

fn assert_pool_then_status_requests(requests: &[String]) {
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(requests[0].starts_with(&format!(
        "GET /api/v1/organizations/{ORGANIZATION}/runner-pools?"
    )));
    assert!(requests[1].starts_with(&format!(
        "GET /api/v1/organizations/{ORGANIZATION}/runner-pools/{POOL_ID}/status HTTP/1.1\r\n"
    )));
}

#[test]
fn pool_show_reads_the_pool_then_its_status_and_reports_its_load() {
    for json in [false, true] {
        let (server, _directory, credential_path) = prepared_runner(vec![
            json_http_response("200 OK", pool_list_body()),
            json_http_response("200 OK", pool_status_body()),
        ]);

        let output = pool_show(&server, &credential_path, json);

        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty());
        if json {
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["outcome"], "found");
            assert_eq!(result["pool"]["id"], POOL_ID);
            assert_eq!(result["status"], pool_status_body());
        } else {
            let stdout = String::from_utf8(output.stdout).unwrap();
            let lines = stdout.lines().collect::<Vec<_>>();
            let position = |label: &str| {
                lines
                    .iter()
                    .position(|line| line.trim_start().starts_with(label))
                    .unwrap_or_else(|| panic!("{label} should be printed: {stdout}"))
            };
            let identity = position("Organization:");
            let waiting = position("Waiting runs:");
            let runners = position("Runners:");
            assert!(identity < waiting && waiting < runners, "{stdout}");
            assert!(lines[waiting].trim_end().ends_with(" 5"), "{stdout}");
            for count in ["4 online", "2 busy", "1 idle", "3 offline"] {
                assert!(lines[runners].contains(count), "{count}: {stdout}");
            }
        }
        assert_pool_then_status_requests(&server.finish());
    }
}

#[test]
fn pool_show_prints_the_runs_its_runners_hold_after_the_runner_counts() {
    let mut held_status = pool_status_body();
    held_status["heldRuns"] = serde_json::json!({"working": 2, "waiting": 3});
    for (status, json) in [
        (held_status.clone(), false),
        (held_status, true),
        (pool_status_body(), false),
    ] {
        let (server, _directory, credential_path) = prepared_runner(vec![
            json_http_response("200 OK", pool_list_body()),
            json_http_response("200 OK", status.clone()),
        ]);

        let output = pool_show(&server, &credential_path, json);

        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty());
        if json {
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["status"], status);
        } else {
            let stdout = String::from_utf8(output.stdout).unwrap();
            let lines = stdout.lines().collect::<Vec<_>>();
            let runners = lines
                .iter()
                .position(|line| line.trim_start().starts_with("Runners:"))
                .unwrap_or_else(|| panic!("runner counts should be printed: {stdout}"));
            let held = lines
                .iter()
                .position(|line| line.trim_start().starts_with("Held runs:"));
            if status.get("heldRuns").is_none() {
                assert_eq!(held, None, "a status without heldRuns: {stdout}");
                assert_pool_then_status_requests(&server.finish());
                continue;
            }
            let held = held.unwrap_or_else(|| panic!("held runs should be printed: {stdout}"));
            assert!(runners < held, "{stdout}");
            for count in ["2 working", "3 in a wait"] {
                assert!(lines[held].contains(count), "{count}: {stdout}");
            }
            assert!(!lines[held].contains("Waiting runs"), "{stdout}");
        }
        assert_pool_then_status_requests(&server.finish());
    }
}

#[test]
fn pool_show_against_a_cloud_without_pool_status_prints_the_pool_alone() {
    for json in [false, true] {
        let (server, _directory, credential_path) = prepared_runner(vec![
            json_http_response("200 OK", pool_list_body()),
            pool_status_unavailable_response(),
        ]);

        let output = pool_show(&server, &credential_path, json);

        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty());
        if json {
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["outcome"], "found");
            assert_eq!(result["pool"]["id"], POOL_ID);
            assert!(result.get("status").is_none(), "{result}");
        } else {
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(stdout.contains(POOL_ID), "{stdout}");
            assert!(!stdout.contains("Waiting runs"), "{stdout}");
            assert!(!stdout.contains("Runners:"), "{stdout}");
        }
        assert_pool_then_status_requests(&server.finish());
    }
}

#[test]
fn runner_commands_report_reserved_run_and_idle_capacity() {
    for assigned in [true, false] {
        let mut runner = registration_body();
        if assigned {
            runner["activity"]["currentAssignment"] = serde_json::json!({
                "runId": "run_01k0z6r1w8f4jy2m7q9v3x5abc",
                "runDisplayName": "Production release",
                "projectId": "prj_01k0z6r1w8f4jy2m7q9v3x5abc",
                "assignedAt": "2026-08-09T12:05:00Z"
            });
        } else {
            runner["activity"] = serde_json::json!({
                "state": "idle", "currentAssignmentCount": 0
            });
        }
        let responses = vec![
            json_http_response("200 OK", runner.clone()),
            json_http_response("200 OK", runner.clone()),
            json_http_response("200 OK", serde_json::json!({"items": [runner.clone()]})),
            json_http_response("200 OK", serde_json::json!({"items": [runner.clone()]})),
        ];
        let (server, _directory, credential_path) = prepared_runner(responses);
        let environment = deployment_environment(&server.api_url, &credential_path);
        for (command, arguments) in [("show", vec![RUNNER_ID]), ("list", vec![])] {
            for json in [false, true] {
                let mut args = vec!["runner", command];
                args.extend(arguments.iter().copied());
                args.extend(["--org", ORGANIZATION]);
                if json {
                    args.push("--json");
                }
                args.push("--allow-insecure-http");
                let output = run_with_env(&args, &environment);
                assert!(
                    output.status.success(),
                    "{command} failed: {:?}",
                    output.stderr
                );
                assert!(output.stderr.is_empty());
                if json {
                    let document: serde_json::Value =
                        serde_json::from_slice(&output.stdout).unwrap();
                    let activity = if command == "show" {
                        &document["runner"]["activity"]
                    } else {
                        &document["items"][0]["activity"]
                    };
                    assert_eq!(
                        activity["currentAssignmentCount"],
                        if assigned { 1 } else { 0 }
                    );
                    if assigned {
                        assert_eq!(
                            activity["currentAssignment"],
                            runner["activity"]["currentAssignment"]
                        );
                    } else {
                        assert!(activity.get("currentAssignment").is_none());
                    }
                } else {
                    let text = String::from_utf8(output.stdout).unwrap();
                    assert!(text.contains(if assigned { "assigned" } else { "idle" }));
                    for field in [
                        "run_01k0z6r1w8f4jy2m7q9v3x5abc",
                        "Production release",
                        "prj_01k0z6r1w8f4jy2m7q9v3x5abc",
                        "2026-08-09T12:05:00Z",
                    ] {
                        assert_eq!(text.contains(field), assigned, "{command} {field}: {text}");
                    }
                }
            }
        }
        assert_eq!(server.finish().len(), 4);
    }
}

// The value after a `Credential mode:` label and the line printed after it.
fn credential_mode_line<'a>(text: &'a str, command: &str) -> (&'a str, Option<&'a str>) {
    let lines = text.lines().collect::<Vec<_>>();
    let index = lines
        .iter()
        .position(|line| line.contains("Credential mode:"))
        .unwrap_or_else(|| panic!("{command} should print the credential mode: {text}"));
    let (_, value) = lines[index].split_once("Credential mode:").unwrap();
    (value.trim(), lines.get(index + 1).copied())
}

#[test]
fn runner_show_and_list_print_the_credential_mode() {
    let unset = registration_body();
    let mut applied = registration_body();
    applied["administration"]["credentialMode"] = serde_json::json!("cloud");
    applied["advertisedMetadata"]["credentialMode"] = serde_json::json!(true);
    let mut unapplied = registration_body();
    unapplied["administration"]["credentialMode"] = serde_json::json!("cloud");
    let mut unconnected = registration_body();
    unconnected["administration"]["credentialMode"] = serde_json::json!("host");
    unconnected
        .as_object_mut()
        .unwrap()
        .remove("advertisedMetadata");

    let mut unapplied_note = None;
    for (case, runner, mode) in [
        ("unset", &unset, "host first"),
        ("applied", &applied, "cloud"),
        ("unapplied", &unapplied, "cloud"),
        ("unconnected", &unconnected, "host"),
    ] {
        let mut responses = vec![
            json_http_response("200 OK", runner.clone()),
            json_http_response("200 OK", serde_json::json!({"items": [runner.clone()]})),
        ];
        if case == "applied" {
            responses.push(json_http_response("200 OK", runner.clone()));
        }
        let request_count = responses.len();
        let (server, _directory, credential_path) = prepared_runner(responses);
        let environment = deployment_environment(&server.api_url, &credential_path);
        let run = |args: &[&str]| {
            let output = run_with_env(args, &environment);
            assert!(output.status.success(), "{case} {args:?}: {output:?}");
            assert!(output.stderr.is_empty(), "{case} {args:?}: {output:?}");
            String::from_utf8(output.stdout).unwrap()
        };

        let show = run(&[
            "runner",
            "show",
            "--org",
            ORGANIZATION,
            RUNNER_ID,
            "--allow-insecure-http",
        ]);
        let (value, next) = credential_mode_line(&show, "show");
        assert_eq!(value, mode, "{case}: {show}");
        let next = next.unwrap_or_default();
        let created = next.trim_start().starts_with("Created:");
        match case {
            // No mode is set, so there is nothing for the runner to apply and no note.
            "unset" => assert!(created, "{case}: {show}"),
            "applied" => {
                assert!(!show.contains("host first"), "{case}: {show}");
                assert!(created, "{case}: {show}");
            }
            "unapplied" => {
                assert!(next.contains("host first"), "{case}: {show}");
                unapplied_note = Some(next.to_owned());
            }
            "unconnected" => {
                assert!(!created, "{case}: {show}");
                assert_ne!(Some(next), unapplied_note.as_deref(), "{case}: {show}");
                assert!(!next.contains("host first"), "{case}: {show}");
            }
            _ => {}
        }

        let list = run(&[
            "runner",
            "list",
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ]);
        let line = format!("Mode: draining  Credential mode: {mode}  Enrollment:");
        assert!(list.contains(&line), "{case}: {list}");

        if case == "applied" {
            let document: serde_json::Value = serde_json::from_str(&run(&[
                "runner",
                "show",
                "--org",
                ORGANIZATION,
                RUNNER_ID,
                "--json",
                "--allow-insecure-http",
            ]))
            .unwrap();
            assert_eq!(
                document["runner"]["administration"]["credentialMode"],
                "cloud"
            );
            assert_eq!(
                document["runner"]["advertisedMetadata"]["credentialMode"],
                true
            );
        }
        assert_eq!(server.finish().len(), request_count);
    }
}

fn held_run(run: &str, assigned_at: &str, state: &str) -> serde_json::Value {
    serde_json::json!({
        "runId": run,
        "projectId": "prj_01k0z6r1w8f4jy2m7q9v3x5abc",
        "assignedAt": assigned_at,
        "state": state
    })
}

// The text of each held run's block, from the line naming its run to the next held run's
// line or the end of the run's lines, in the order the runs are printed.
fn held_run_blocks(text: &str, runs: &[&str]) -> Vec<String> {
    let lines = text.lines().collect::<Vec<_>>();
    let starts = runs
        .iter()
        .map(|run| {
            lines
                .iter()
                .position(|line| line.contains(run))
                .unwrap_or_else(|| panic!("{run} should be printed: {text}"))
        })
        .collect::<Vec<_>>();
    assert!(
        starts.windows(2).all(|pair| pair[0] < pair[1]),
        "held runs should print in order: {text}"
    );
    starts
        .iter()
        .enumerate()
        .map(|(index, &start)| {
            let end = starts.get(index + 1).copied().unwrap_or_else(|| {
                lines[start..]
                    .iter()
                    .position(|line| line.trim().is_empty() || line.contains("Runner: "))
                    .map_or(lines.len(), |offset| start + offset)
            });
            lines[start..end].join("\n")
        })
        .collect()
}

#[test]
fn runner_commands_print_every_run_a_runner_holds_with_its_state() {
    const WORKING: &str = "run_01k0z6r1w8f4jy2m7q9v3x5aaa";
    const FIRST_WAITING: &str = "run_01k0z6r1w8f4jy2m7q9v3x5bbb";
    const SECOND_WAITING: &str = "run_01k0z6r1w8f4jy2m7q9v3x5ccc";
    let mut holding = registration_body();
    let mut working = held_run(WORKING, "2026-08-09T12:05:00Z", "working");
    working["runDisplayName"] = serde_json::json!("Production release");
    holding["activity"] = serde_json::json!({
        "state": "assigned",
        "currentAssignmentCount": 3,
        "currentAssignment": {
            "runId": WORKING,
            "runDisplayName": "Production release",
            "projectId": "prj_01k0z6r1w8f4jy2m7q9v3x5abc",
            "assignedAt": "2026-08-09T12:05:00Z"
        },
        "assignments": [
            working,
            held_run(FIRST_WAITING, "2026-08-09T12:06:00Z", "waiting"),
            held_run(SECOND_WAITING, "2026-08-09T12:07:00Z", "waiting"),
        ]
    });
    let mut waiting = registration_body();
    waiting["activity"] = serde_json::json!({
        "state": "assigned",
        "currentAssignmentCount": 2,
        "assignments": [
            held_run(FIRST_WAITING, "2026-08-09T12:06:00Z", "waiting"),
            held_run(SECOND_WAITING, "2026-08-09T12:07:00Z", "waiting"),
        ]
    });

    for (runner, held) in [
        (
            holding,
            vec![
                (WORKING, "working"),
                (FIRST_WAITING, "waiting"),
                (SECOND_WAITING, "waiting"),
            ],
        ),
        (
            waiting,
            vec![(FIRST_WAITING, "waiting"), (SECOND_WAITING, "waiting")],
        ),
    ] {
        let responses = vec![
            json_http_response("200 OK", runner.clone()),
            json_http_response("200 OK", runner.clone()),
            json_http_response("200 OK", serde_json::json!({"items": [runner.clone()]})),
            json_http_response("200 OK", serde_json::json!({"items": [runner.clone()]})),
        ];
        let (server, _directory, credential_path) = prepared_runner(responses);
        let environment = deployment_environment(&server.api_url, &credential_path);
        let runs = held.iter().map(|(run, _)| *run).collect::<Vec<_>>();
        for (command, arguments) in [("show", vec![RUNNER_ID]), ("list", vec![])] {
            for json in [false, true] {
                let mut args = vec!["runner", command];
                args.extend(arguments.iter().copied());
                args.extend(["--org", ORGANIZATION]);
                if json {
                    args.push("--json");
                }
                args.push("--allow-insecure-http");
                let output = run_with_env(&args, &environment);
                assert!(output.status.success(), "{command}: {output:?}");
                assert!(output.stderr.is_empty());
                if json {
                    let document: serde_json::Value =
                        serde_json::from_slice(&output.stdout).unwrap();
                    let activity = if command == "show" {
                        &document["runner"]["activity"]
                    } else {
                        &document["items"][0]["activity"]
                    };
                    assert_eq!(activity, &runner["activity"], "{command}");
                    continue;
                }
                let text = String::from_utf8(output.stdout).unwrap();
                if command == "show" {
                    let count = held.len().to_string();
                    assert!(
                        text.lines().any(|line| {
                            line.to_ascii_lowercase().contains("held")
                                && line.split_whitespace().any(|word| word == count)
                        }),
                        "show should print the number of runs held: {text}"
                    );
                } else {
                    let runner_line = text
                        .lines()
                        .position(|line| line.contains(RUNNER_ID))
                        .unwrap_or_else(|| panic!("runner line: {text}"));
                    let first_run = text
                        .lines()
                        .position(|line| line.contains(runs[0]))
                        .unwrap_or_else(|| panic!("held run: {text}"));
                    assert!(runner_line < first_run, "{text}");
                }
                for (block, (run, state)) in held_run_blocks(&text, &runs).iter().zip(&held) {
                    let other = if *state == "working" {
                        "waiting"
                    } else {
                        "working"
                    };
                    assert!(block.contains(state), "{command} {run}: {block}");
                    assert!(!block.contains(other), "{command} {run}: {block}");
                }
            }
        }
        assert_eq!(server.finish().len(), 4);
    }
}

#[test]
fn runner_show_reports_independent_cloud_and_informational_projections() {
    let (server, _directory, credential_path) =
        prepared_runner(vec![json_http_response("200 OK", registration_body())]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "runner",
            "show",
            RUNNER_ID,
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "draining",
        "credentialed",
        "online",
        "assigned",
        "1.2.3",
        &server.api_url,
    ] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in {stdout:?}"
        );
    }
    assert!(output.stderr.is_empty());

    let request = server.finish().pop().unwrap();
    assert!(request.starts_with(&format!(
        "GET /api/v1/organizations/{ORGANIZATION}/runner-registrations/{RUNNER_ID} HTTP/1.1\r\n"
    )));
    assert_eq!(
        header_value(&request, "authorization"),
        format!("Bearer {TOKEN}")
    );
}

const JOIN_KEY_ID: &str = "rjk_01k0z6r1w8f4jy2m7q9v3x5abc";
const JOIN_KEY_SECRET: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const SHARED_POOL_ID: &str = "rpl_01k0z6r1w8f4jy2m7q9v3x5abd";
const OTHER_MEMBER_ID: &str = "prn_01k0z6r1w8f4jy2m7q9v3x5abd";

fn join_key_body(pool_id: &str, state: &str) -> serde_json::Value {
    let mut key = serde_json::json!({
        "id": JOIN_KEY_ID,
        "runnerPoolId": pool_id,
        "issuedByPrincipalId": MEMBER_ID,
        "state": state,
        "issuedAt": "2026-11-09T12:00:00Z",
        "expiresAt": "2026-11-16T12:00:00Z",
        "offlineRemovalSeconds": 3600
    });
    if state == "revoked" {
        key["revokedAt"] = serde_json::json!("2026-11-10T12:00:00Z");
    }
    key
}

fn join_key_issued_response(pool_id: &str) -> Vec<u8> {
    let body = serde_json::json!({
        "joinKey": join_key_body(pool_id, "issued"),
        "artifact": join_key_artifact()
    });
    http_response_with_headers(
        "201 Created",
        Some("application/json"),
        &[
            ("Idempotency-Key", ECHO_IDEMPOTENCY_KEY),
            (
                "Location",
                &format!("/v1/organizations/{ORGANIZATION}/runner-join-keys/{JOIN_KEY_ID}"),
            ),
        ],
        &serde_json::to_vec(&body).unwrap(),
    )
}

fn join_key_artifact() -> serde_json::Value {
    serde_json::json!({
        "schemaVersion": 1,
        "joinUrl": format!("https://api.usefulmachinery.com/v1/runner-join-keys/{JOIN_KEY_ID}/join"),
        "joinKeyId": JOIN_KEY_ID,
        "joinToken": format!("{JOIN_KEY_ID}.{JOIN_KEY_SECRET}"),
        "expiresAt": "2026-11-16T12:00:00Z"
    })
}

fn shared_pool_body() -> serde_json::Value {
    let mut pool = pool_body();
    pool["id"] = serde_json::json!(SHARED_POOL_ID);
    pool["name"] = serde_json::json!("ci");
    pool
}

fn assert_join_key_issuance_request(request: &str, pool_id: &str, expires: u64, removal: u64) {
    assert!(
        request.starts_with(&format!(
            "POST /api/v1/organizations/{ORGANIZATION}/runner-pools/{pool_id}/join-keys HTTP/1.1\r\n"
        )),
        "{request}"
    );
    assert_eq!(header_value(request, "idempotency-key").len(), 64);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request_body(request)).unwrap(),
        serde_json::json!({"expiresInSeconds": expires, "offlineRemovalSeconds": removal})
    );
}

#[test]
fn join_key_issue_resolves_the_pool_sends_seconds_and_writes_a_private_artifact() {
    let (server, _credentials, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", serde_json::json!({"items": [shared_pool_body()]})),
        join_key_issued_response(SHARED_POOL_ID),
    ]);
    let directory = tempfile::tempdir().unwrap();
    let artifact_path = directory.path().join("join-key.json");
    let artifact_path = artifact_path.to_str().unwrap();

    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "issue",
            "--org",
            ORGANIZATION,
            "--pool",
            "ci",
            "--expires-in",
            "7d",
            "--remove-after",
            "1h",
            "--key-file",
            artifact_path,
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(JOIN_KEY_ID), "{stdout}");
    assert!(!stdout.contains(JOIN_KEY_SECRET));
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains(JOIN_KEY_SECRET)
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with(&format!(
        "GET /api/v1/organizations/{ORGANIZATION}/runner-pools?limit=200 HTTP/1.1\r\n"
    )));
    assert_join_key_issuance_request(&requests[1], SHARED_POOL_ID, 604_800, 3_600);

    let metadata = fs::metadata(artifact_path).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let written = fs::read_to_string(artifact_path).unwrap();
    assert_eq!(written.lines().count(), 1, "{written}");
    assert!(written.ends_with('\n'));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&written).unwrap(),
        join_key_artifact()
    );

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let api_url = format!("http://{}/api", listener.local_addr().unwrap());
    let repeated = run_with_env(
        &[
            "runner",
            "join-key",
            "issue",
            "--org",
            ORGANIZATION,
            "--pool",
            "ci",
            "--expires-in",
            "7d",
            "--remove-after",
            "1h",
            "--key-file",
            artifact_path,
            "--allow-insecure-http",
        ],
        &deployment_environment(&api_url, &credential_path),
    );
    assert!(!repeated.status.success());
    assert_eq!(fs::read_to_string(artifact_path).unwrap(), written);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn join_key_issue_without_a_pool_uses_the_callers_personal_pool_and_writes_only_the_artifact() {
    let mut other_personal = personal_pool_body();
    other_personal["id"] = serde_json::json!("rpl_01k0z6r1w8f4jy2m7q9v3x5abe");
    other_personal["member"]["id"] = serde_json::json!(OTHER_MEMBER_ID);
    let (server, _credentials, credential_path) = prepared_runner(vec![
        current_principal_response(),
        json_http_response(
            "200 OK",
            serde_json::json!({
                "items": [shared_pool_body(), other_personal, personal_pool_body()]
            }),
        ),
        join_key_issued_response(POOL_ID),
    ]);

    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "issue",
            "--org",
            ORGANIZATION,
            "--expires-in",
            "30m",
            "--remove-after",
            "5m",
            "--key-file",
            "-",
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&stdout).unwrap(),
        join_key_artifact()
    );
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains(JOIN_KEY_SECRET)
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("GET /api/v1/me HTTP/1.1\r\n"));
    assert!(requests[1].starts_with(&format!(
        "GET /api/v1/organizations/{ORGANIZATION}/runner-pools?limit=200 HTTP/1.1\r\n"
    )));
    assert_join_key_issuance_request(&requests[2], POOL_ID, 1_800, 300);
}

#[test]
fn join_key_issue_without_a_file_writes_only_the_artifact_to_stdout() {
    let (server, _credentials, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", shared_pool_body()),
        join_key_issued_response(SHARED_POOL_ID),
    ]);
    let working_directory = tempfile::tempdir().unwrap();
    let args = [
        "runner",
        "join-key",
        "issue",
        "--org",
        ORGANIZATION,
        "--pool",
        SHARED_POOL_ID,
        "--expires-in",
        "1h",
        "--remove-after",
        "7d",
        "--allow-insecure-http",
    ];

    let output = run_with_env_in(
        &args,
        &deployment_environment(&server.api_url, &credential_path),
        working_directory.path(),
    );

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(stdout.ends_with('\n'));
    let artifact: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(artifact, join_key_artifact());
    assert_eq!(
        artifact["joinToken"],
        format!("{JOIN_KEY_ID}.{JOIN_KEY_SECRET}")
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(JOIN_KEY_ID), "{stderr}");
    assert!(!stderr.contains(JOIN_KEY_SECRET), "{stderr}");
    assert_eq!(
        fs::read_dir(working_directory.path()).unwrap().count(),
        0,
        "no file is created when none is named"
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert_join_key_issuance_request(&requests[1], SHARED_POOL_ID, 3_600, 604_800);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let api_url = format!("http://{}/api", listener.local_addr().unwrap());
    let mut json_args = args.to_vec();
    json_args.push("--json");
    let refused = run_with_env_in(
        &json_args,
        &deployment_environment(&api_url, &credential_path),
        working_directory.path(),
    );
    assert!(!refused.status.success(), "{refused:?}");
    assert!(refused.stdout.is_empty(), "{refused:?}");
    assert_eq!(fs::read_dir(working_directory.path()).unwrap().count(), 0);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn join_key_issue_without_a_personal_pool_sends_no_issuance() {
    let (server, _credentials, credential_path) = prepared_runner(vec![
        json_http_response(
            "200 OK",
            serde_json::json!({
                "principal": {"id": MEMBER_ID, "type": "service", "state": "active"}
            }),
        ),
        json_http_response("200 OK", serde_json::json!({"items": [shared_pool_body()]})),
    ]);
    let directory = tempfile::tempdir().unwrap();
    let artifact_path = directory.path().join("join-key.json");

    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "issue",
            "--org",
            ORGANIZATION,
            "--expires-in",
            "1d",
            "--remove-after",
            "1h",
            "--key-file",
            artifact_path.to_str().unwrap(),
            "--json",
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["outcome"], "pool_personal_unavailable");
    assert!(!artifact_path.exists());
    assert_eq!(server.finish().len(), 2);
}

#[test]
fn join_key_issue_json_reports_the_key_without_its_token() {
    let (server, _credentials, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", shared_pool_body()),
        join_key_issued_response(SHARED_POOL_ID),
    ]);
    let directory = tempfile::tempdir().unwrap();
    let artifact_path = directory.path().join("join-key.json");
    let artifact_path = artifact_path.to_str().unwrap();

    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "issue",
            "--org",
            ORGANIZATION,
            "--pool",
            SHARED_POOL_ID,
            "--expires-in",
            "365d",
            "--remove-after",
            "30d",
            "--key-file",
            artifact_path,
            "--json",
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains(JOIN_KEY_SECRET), "{stdout}");
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["outcome"], "issued");
    assert_eq!(report["deployment"], server.api_url);
    assert_eq!(report["joinKey"], join_key_body(SHARED_POOL_ID, "issued"));
    assert_eq!(report["joinKeyFile"], artifact_path);
    let requests = server.finish();
    assert_join_key_issuance_request(&requests[1], SHARED_POOL_ID, 31_536_000, 2_592_000);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let api_url = format!("http://{}/api", listener.local_addr().unwrap());
    for (expires, removal, destination, json) in [
        ("7d", "1h", "-", true),
        ("366d", "1h", "-", false),
        ("59s", "1h", "-", false),
        ("7d", "4m", "-", false),
        ("7d", "31d", "-", false),
        ("7w", "1h", "-", false),
        ("-1d", "1h", "-", false),
    ] {
        let mut args = vec![
            "runner",
            "join-key",
            "issue",
            "--org",
            ORGANIZATION,
            "--pool",
            SHARED_POOL_ID,
            "--expires-in",
            expires,
            "--remove-after",
            removal,
            "--key-file",
            destination,
        ];
        if json {
            args.push("--json");
        }
        args.push("--allow-insecure-http");
        let refused = run_with_env(&args, &deployment_environment(&api_url, &credential_path));
        assert!(!refused.status.success(), "{args:?}");
        assert!(refused.stdout.is_empty(), "{args:?}");
    }
    // With no `--key-file` the key of either kind goes to standard output, which `--json`
    // never shares with it.
    for kind in [
        &["--pool", SHARED_POOL_ID, "--expires-in", "7d"][..],
        &["--runner", "builder-one"][..],
    ] {
        let mut args = vec!["runner", "join-key", "issue", "--org", ORGANIZATION];
        args.extend(kind);
        args.extend(["--json", "--allow-insecure-http"]);
        let refused = run_with_env(&args, &deployment_environment(&api_url, &credential_path));
        assert!(!refused.status.success(), "{args:?}");
        assert!(refused.stdout.is_empty(), "{args:?}");
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

// With no `--remove-after` the request carries 30 days, the longest the API admits, and the
// result prints it.
#[test]
fn join_key_issue_without_a_removal_time_sends_thirty_days() {
    let (server, _credentials, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", serde_json::json!({"items": [shared_pool_body()]})),
        join_key_issued_response(SHARED_POOL_ID),
    ]);
    let directory = tempfile::tempdir().unwrap();
    let key_path = directory.path().join("ci.key");

    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "issue",
            "--pool",
            "ci",
            "--expires-in",
            "7d",
            "--key-file",
            key_path.to_str().unwrap(),
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );

    assert!(output.status.success(), "{output:?}");
    let requests = server.finish();
    assert_join_key_issuance_request(&requests[1], SHARED_POOL_ID, 604_800, 2_592_000);
    assert!(key_path.exists());
}

const UNREADABLE_RUNNER_ID: &str = "rnr_01k0z6r1w8f4jy2m7q9v3x5abd";
const SECOND_ACTIVATION_ID: &str = "rna_01k0z6r1w8f4jy2m7q9v3x5abd";

/// A single-runner key of `runner_id` in `state`, as the API lists it.
fn activation_in(id: &str, runner_id: &str, state: &str) -> serde_json::Value {
    let mut activation = activation_issuance_body()["activation"].clone();
    activation["id"] = serde_json::json!(id);
    activation["runnerId"] = serde_json::json!(runner_id);
    activation["state"] = serde_json::json!(state);
    activation
}

/// Two runners: `builder-one` in the builders pool, whose keys the caller may read, and a second
/// in the ci pool.
fn two_registrations() -> Vec<u8> {
    json_http_response(
        "200 OK",
        serde_json::json!({
            "items": [
                registration_body(),
                registration_in(UNREADABLE_RUNNER_ID, "builder-two", SHARED_POOL_ID),
            ]
        }),
    )
}

fn activation_list(runner_id: &str, cursor: Option<&str>) -> String {
    let cursor = cursor.map_or_else(String::new, |cursor| format!("&cursor={cursor}"));
    format!(
        "GET /api/v1/organizations/{ORGANIZATION}/runner-registrations/{runner_id}/activations?limit=200{cursor} HTTP/1.1"
    )
}

// The list reads every page of the join keys, of the registrations and of each runner's
// single-runner keys, passes over a runner whose keys the caller may not read, and prints the
// pool keys and then the single-runner keys, with no cursor.
#[test]
fn join_key_list_prints_the_pool_keys_and_every_runners_single_runner_keys() {
    let issued = activation_in(ACTIVATION_ID, RUNNER_ID, "issued");
    let consumed = activation_in(SECOND_ACTIVATION_ID, RUNNER_ID, "consumed");
    let responses = || {
        vec![
            json_http_response(
                "200 OK",
                serde_json::json!({
                    "items": [join_key_body(POOL_ID, "issued")],
                    "nextCursor": "next-join-keys"
                }),
            ),
            json_http_response(
                "200 OK",
                serde_json::json!({"items": [join_key_body(SHARED_POOL_ID, "revoked")]}),
            ),
            two_registrations(),
            json_http_response(
                "200 OK",
                serde_json::json!({"items": [issued.clone()], "nextCursor": "next-keys"}),
            ),
            json_http_response("200 OK", serde_json::json!({"items": [consumed.clone()]})),
            forbidden_response(),
        ]
    };
    let expected_requests = [
        format!("GET /api/v1/organizations/{ORGANIZATION}/runner-join-keys?limit=200 HTTP/1.1"),
        format!(
            "GET /api/v1/organizations/{ORGANIZATION}/runner-join-keys?limit=200&cursor=next-join-keys HTTP/1.1"
        ),
        registration_lookup(),
        activation_list(RUNNER_ID, None),
        activation_list(RUNNER_ID, Some("next-keys")),
        activation_list(UNREADABLE_RUNNER_ID, None),
    ];

    let (server, _credentials, credential_path) = prepared_runner(responses());
    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "list",
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["outcome"], "listed");
    assert_eq!(report["deployment"], server.api_url);
    assert_eq!(
        report["items"],
        serde_json::json!([
            join_key_body(POOL_ID, "issued"),
            join_key_body(SHARED_POOL_ID, "revoked")
        ])
    );
    assert_eq!(
        report["singleRunnerKeys"],
        serde_json::json!([issued, consumed])
    );
    assert!(report.get("nextCursor").is_none(), "{report}");
    assert_eq!(request_lines(&server.finish()), expected_requests);

    let (server, _credentials, credential_path) = prepared_runner(responses());
    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "list",
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let pool_keys: Vec<_> = stdout
        .lines()
        .filter(|line| line.contains(JOIN_KEY_ID))
        .collect();
    assert_eq!(pool_keys.len(), 2, "{stdout}");
    for (row, pool, state) in [
        (pool_keys[0], POOL_ID, "issued"),
        (pool_keys[1], SHARED_POOL_ID, "revoked"),
    ] {
        for field in [pool, MEMBER_ID, state, "2026-11-16T12:00:00Z", "1h"] {
            assert!(row.contains(field), "missing {field:?} in {row:?}");
        }
    }
    for (id, state) in [
        (ACTIVATION_ID, "issued"),
        (SECOND_ACTIVATION_ID, "consumed"),
    ] {
        let row = stdout
            .lines()
            .find(|line| line.contains(id))
            .unwrap_or_else(|| panic!("no row for {id} in {stdout}"));
        for field in [RUNNER_ID, state, "2026-08-09T13:00:00Z"] {
            assert!(row.contains(field), "missing {field:?} in {row:?}");
        }
    }
    let last_pool_key = stdout.find(pool_keys[1]).unwrap();
    assert!(
        stdout.find(ACTIVATION_ID).unwrap() > last_pool_key,
        "{stdout}"
    );
    assert!(!stdout.contains(UNREADABLE_RUNNER_ID), "{stdout}");
    assert!(!stdout.contains("cursor"), "{stdout}");
    assert_eq!(request_lines(&server.finish()), expected_requests);
}

// `--pool` keeps the pool's keys and runners; `--runner` reads that runner's
// single-runner keys alone, with no join-key read.
#[test]
fn join_key_list_by_pool_or_runner_reads_only_their_keys() {
    let issued = activation_in(ACTIVATION_ID, RUNNER_ID, "issued");
    let (server, _credentials, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", serde_json::json!({"items": [shared_pool_body()]})),
        json_http_response(
            "200 OK",
            serde_json::json!({"items": [join_key_body(SHARED_POOL_ID, "issued")]}),
        ),
        two_registrations(),
        json_http_response("200 OK", serde_json::json!({"items": []})),
    ]);
    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "list",
            "--pool",
            "ci",
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["items"],
        serde_json::json!([join_key_body(SHARED_POOL_ID, "issued")])
    );
    assert_eq!(report["singleRunnerKeys"], serde_json::json!([]));
    let requests = server.finish();
    let lines = request_lines(&requests);
    assert_eq!(lines.len(), 4, "{lines:?}");
    assert!(
        lines[1].contains(&format!("runnerPoolId={SHARED_POOL_ID}")),
        "{lines:?}"
    );
    assert_eq!(lines[2], registration_lookup());
    assert_eq!(lines[3], activation_list(UNREADABLE_RUNNER_ID, None));

    let (server, _credentials, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", registration_list_body()),
        json_http_response("200 OK", serde_json::json!({"items": [issued.clone()]})),
    ]);
    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "list",
            "--runner",
            "builder-one",
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["items"], serde_json::json!([]));
    assert_eq!(report["singleRunnerKeys"], serde_json::json!([issued]));
    assert_eq!(
        request_lines(&server.finish()),
        [registration_lookup(), activation_list(RUNNER_ID, None)]
    );
}

fn revoked_response(body: &serde_json::Value) -> Vec<u8> {
    http_response_with_headers(
        "200 OK",
        Some("application/json"),
        &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
        &serde_json::to_vec(body).unwrap(),
    )
}

fn activation_revocation(runner_id: &str, activation_id: &str) -> String {
    format!(
        "POST /api/v1/organizations/{ORGANIZATION}/runner-registrations/{runner_id}/activations/{activation_id}/revocation HTTP/1.1"
    )
}

// A single-runner key's ID finds the runner that holds it, reading runners' keys and
// passing over one the caller may not read, and revokes it there; with `--runner` it
// goes straight to that runner.
#[test]
fn join_key_revoke_finds_the_runner_that_holds_a_single_runner_key() {
    const HELD_ID: &str = "rna_01k0z6r1w8f4jy2m7q9v3x5abe";
    let revoked = activation_in(HELD_ID, RUNNER_ID, "revoked");
    let (server, _credentials, credential_path) = prepared_runner(vec![
        json_http_response(
            "200 OK",
            serde_json::json!({
                "items": [
                    registration_in(UNREADABLE_RUNNER_ID, "builder-two", SHARED_POOL_ID),
                    registration_body(),
                ]
            }),
        ),
        forbidden_response(),
        json_http_response(
            "200 OK",
            serde_json::json!({
                "items": [
                    activation_in(ACTIVATION_ID, RUNNER_ID, "consumed"),
                    activation_in(HELD_ID, RUNNER_ID, "issued"),
                ]
            }),
        ),
        revoked_response(&revoked),
    ]);
    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "revoke",
            HELD_ID,
            "--yes",
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["outcome"], "revoked");
    assert_eq!(report["deployment"], server.api_url);
    assert_eq!(report["activation"], revoked);
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [
            registration_lookup(),
            activation_list(UNREADABLE_RUNNER_ID, None),
            activation_list(RUNNER_ID, None),
            activation_revocation(RUNNER_ID, HELD_ID),
        ]
    );
    assert_eq!(header_value(&requests[3], "idempotency-key").len(), 64);

    let (server, _credentials, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", registration_list_body()),
        revoked_response(&revoked),
    ]);
    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "revoke",
            HELD_ID,
            "--runner",
            "builder-one",
            "--yes",
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8(output.stdout).unwrap().contains(HELD_ID));
    assert_eq!(
        request_lines(&server.finish()),
        [
            registration_lookup(),
            activation_revocation(RUNNER_ID, HELD_ID)
        ]
    );
}

// A single-runner key no runner holds is `not_found` with nothing revoked, and `--runner`
// beside a pool key's ID is a usage error before anything is sent.
#[test]
fn join_key_revoke_of_an_unheld_key_or_a_pool_key_with_a_runner_revokes_nothing() {
    for json in [true, false] {
        let (server, _credentials, credential_path) = prepared_runner(vec![
            two_registrations(),
            json_http_response("200 OK", serde_json::json!({"items": []})),
            json_http_response("200 OK", serde_json::json!({"items": []})),
        ]);
        let mut args = vec![
            "runner",
            "join-key",
            "revoke",
            ACTIVATION_ID,
            "--yes",
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ];
        if json {
            args.push("--json");
        }
        let output = run_with_env(
            &args,
            &deployment_environment(&server.api_url, &credential_path),
        );
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        if json {
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(result["outcome"], "not_found");
        } else {
            assert!(output.stdout.is_empty());
        }
        let requests = server.finish();
        assert_eq!(requests.len(), 3);
        assert!(requests.iter().all(|request| request.starts_with("GET ")));
    }

    let (server, _credentials, credential_path) = prepared_runner(vec![]);
    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "revoke",
            JOIN_KEY_ID,
            "--runner",
            "builder-one",
            "--yes",
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(server.finish().is_empty());
}

#[test]
fn join_key_revoke_requires_confirmation_and_sends_the_revocation() {
    let (server, _credentials, credential_path) = prepared_runner(vec![]);
    let environment = deployment_environment(&server.api_url, &credential_path);
    let unconfirmed = run_with_env(
        &[
            "runner",
            "join-key",
            "revoke",
            "--org",
            ORGANIZATION,
            JOIN_KEY_ID,
            "--allow-insecure-http",
        ],
        &environment,
    );
    assert_eq!(unconfirmed.status.code(), Some(2));
    assert!(unconfirmed.stdout.is_empty());
    assert!(server.finish().is_empty());

    let revoked = join_key_body(POOL_ID, "revoked");
    let (server, _credentials, credential_path) =
        prepared_runner(vec![http_response_with_headers(
            "200 OK",
            Some("application/json"),
            &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
            &serde_json::to_vec(&revoked).unwrap(),
        )]);
    let output = run_with_env(
        &[
            "runner",
            "join-key",
            "revoke",
            "--org",
            ORGANIZATION,
            JOIN_KEY_ID,
            "--yes",
            "--json",
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, &credential_path),
    );
    assert!(output.status.success(), "{output:?}");
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["outcome"], "revoked");
    assert_eq!(report["joinKey"], revoked);
    let request = server.finish().pop().unwrap();
    assert!(request.starts_with(&format!(
        "POST /api/v1/organizations/{ORGANIZATION}/runner-join-keys/{JOIN_KEY_ID}/revocation HTTP/1.1\r\n"
    )));
    assert_eq!(header_value(&request, "idempotency-key").len(), 64);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request_body(&request)).unwrap(),
        serde_json::json!({})
    );
}

#[test]
fn runner_show_prints_the_join_key_of_a_joined_runner() {
    let mut joined = registration_body();
    joined["joinKey"] = serde_json::json!({"id": JOIN_KEY_ID});
    let (server, _credentials, credential_path) = prepared_runner(vec![
        json_http_response("200 OK", joined),
        json_http_response("200 OK", registration_body()),
    ]);
    let environment = deployment_environment(&server.api_url, &credential_path);
    let args = [
        "runner",
        "show",
        RUNNER_ID,
        "--org",
        ORGANIZATION,
        "--allow-insecure-http",
    ];

    let shown = run_with_env(&args, &environment);
    let by_hand = run_with_env(&args, &environment);

    assert!(shown.status.success(), "{shown:?}");
    assert!(
        String::from_utf8(shown.stdout)
            .unwrap()
            .lines()
            .any(|line| line.contains("Join key") && line.contains(JOIN_KEY_ID))
    );
    assert!(by_hand.status.success(), "{by_hand:?}");
    assert!(
        !String::from_utf8(by_hand.stdout)
            .unwrap()
            .contains("Join key")
    );
    assert_eq!(server.finish().len(), 2);
}

#[test]
fn pool_list_reads_one_page_and_returns_its_continuation() {
    let cursor = "more/+";
    let mut page = pool_list_body();
    page["nextCursor"] = cursor.into();
    let (server, _dir, credential) = prepared_runner(vec![
        json_http_response("200 OK", page),
        json_http_response("200 OK", serde_json::json!({"items": [pool_body()]})),
        json_http_response("200 OK", serde_json::json!({"items": []})),
        forbidden_response(),
    ]);
    let env = deployment_environment(&server.api_url, &credential);
    let list = |options: &[&str]| {
        let mut args = vec![
            "runner",
            "pool",
            "list",
            "--org",
            ORGANIZATION,
            "--limit",
            "1",
            "--allow-insecure-http",
        ];
        args.extend_from_slice(options);
        run_with_env(&args, &env)
    };
    let output = list(&["--json"]);
    assert!(output.status.success(), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["outcome"], "listed");
    assert_eq!(result["items"][0]["id"], POOL_ID);
    assert_eq!(result["items"][0]["name"], "builders");
    assert_eq!(result["nextCursor"], cursor);
    let output = list(&["--cursor", result["nextCursor"].as_str().unwrap()]);
    assert!(output.status.success(), "{output:?}");
    let human = String::from_utf8(output.stdout).unwrap();
    assert!(human.contains(POOL_ID) && human.contains("builders"));
    let output = list(&["--json"]);
    assert!(output.status.success());
    let empty: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(empty["items"], serde_json::json!([]));
    assert!(empty.get("nextCursor").is_none());
    let refused = list(&["--json"]);
    assert!(!refused.status.success());
    let result: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(result["outcome"], "forbidden");
    let base = format!("GET /api/v1/organizations/{ORGANIZATION}/runner-pools?limit=1");
    assert_eq!(
        request_lines(&server.finish()),
        [
            format!("{base} HTTP/1.1"),
            format!("{base}&cursor=more%2F%2B HTTP/1.1"),
            format!("{base} HTTP/1.1"),
            format!("{base} HTTP/1.1")
        ]
    );
}
