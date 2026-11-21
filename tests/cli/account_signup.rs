use super::*;

fn signup_environment<'a>(
    server: &'a ScriptedServer,
    credential_path: &'a str,
) -> [(&'static str, &'a str); 5] {
    [
        (CREDENTIALS_FILE_VARIABLE, credential_path),
        ("USEFUL_API_URL", &server.api_url),
        ("USEFUL_AUTH_ISSUER", &server.issuer),
        ("USEFUL_AUTH_AUDIENCE", "https://api.fixture.example"),
        ("USEFUL_AUTH_CLIENT_ID", "fixture-public-client"),
    ]
}

fn prepared_signup(
    responses: Vec<Vec<u8>>,
    access_token: &str,
) -> (
    ScriptedServer,
    tempfile::TempDir,
    std::path::PathBuf,
    String,
) {
    let server = ScriptedServer::respond(responses);
    let credential_directory = private_credential_directory();
    let credential_path = credential_directory.path().join("credentials.json");
    write_credential_fixture_for_deployment(
        &credential_path,
        &server.api_url,
        &server.issuer,
        access_token,
        "2999-01-01T00:00:00Z",
    );
    let credential_path_string = credential_path.to_str().unwrap().to_owned();
    (
        server,
        credential_directory,
        credential_path,
        credential_path_string,
    )
}

fn created_response() -> Vec<u8> {
    json_http_response(
        "201 Created",
        serde_json::json!({
            "id": "prn_fixture",
            "type": "human",
            "state": "active",
            "displayName": "Ada Lovelace"
        }),
    )
}

// REQ-ACCOUNT-16, REQ-ACCOUNT-17
#[test]
fn human_signup_creates_and_reports_the_account() {
    let (server, _directory, _path, credential_path) = prepared_signup(
        vec![created_response()],
        "unique-human-signup-synthetic-token",
    );
    let environment = signup_environment(&server, &credential_path);

    let output = run_with_env(
        &["account", "signup", "--allow-insecure-http"],
        &environment,
    );

    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        concat!(
            "✓ Useful Machinery account created.\n",
            "\n",
            "  Account:    Ada Lovelace\n",
            "  Principal:  prn_fixture\n",
            "  Deployment: "
        )
        .as_bytes()
        .iter()
        .copied()
        .chain(server.api_url.bytes())
        .chain(std::iter::once(b'\n'))
        .collect::<Vec<_>>()
    );
    assert!(output.stderr.is_empty());
    let request = server.finish().pop().unwrap();
    assert!(request.starts_with("POST /api/v1/signup HTTP/1.1\r\n"));
    assert_eq!(
        crate::header_value(&request, "authorization"),
        "Bearer unique-human-signup-synthetic-token"
    );
    let idempotency_key = header_value(&request, "idempotency-key");
    assert_eq!(idempotency_key.len(), 64);
    assert!(idempotency_key.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("unique-human-signup-synthetic-token")
    );
}

// REQ-ACCOUNT-18
#[test]
fn structured_signup_reports_the_authenticated_principal() {
    let (server, _directory, _path, credential_path) = prepared_signup(
        vec![created_response()],
        "unique-json-signup-synthetic-token",
    );
    let environment = signup_environment(&server, &credential_path);

    let output = run_with_env(
        &["account", "signup", "--json", "--allow-insecure-http"],
        &environment,
    );

    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "outcome": "authenticated",
            "principal": {
                "id": "prn_fixture",
                "type": "human",
                "state": "active",
                "displayName": "Ada Lovelace"
            }
        })
    );
    assert!(output.stdout.ends_with(b"\n"));
    assert!(output.stderr.is_empty());
    server.finish();
}

// REQ-ACCOUNT-18, REQ-ACCOUNT-19
#[test]
fn signup_reports_policy_denial_without_claiming_a_principal() {
    let response = problem_http_response(
        "403 Forbidden",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/signup-not-permitted",
            "title": "Signup not permitted",
            "status": 403,
            "detail": "The platform signup policy does not permit signup."
        }),
    );
    let (server, _directory, _path, credential_path) =
        prepared_signup(vec![response], "unique-policy-signup-synthetic-token");
    let environment = signup_environment(&server, &credential_path);

    let output = run_with_env(
        &["account", "signup", "--json", "--allow-insecure-http"],
        &environment,
    );

    assert_eq!(output.status.code(), Some(1));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result,
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "outcome": "signup_not_permitted"
        })
    );
    assert!(result.get("principal").is_none());
    assert!(output.stderr.is_empty());
    server.finish();
}

// REQ-ACCOUNT-70
#[test]
fn signup_reports_a_refused_account_as_forbidden_and_names_deletion_cancel() {
    let (server, _directory, _path, credential_path) = prepared_signup(
        vec![forbidden_problem_response()],
        "unique-refused-signup-synthetic-token",
    );
    let environment = signup_environment(&server, &credential_path);

    let output = run_with_env(
        &["account", "signup", "--json", "--allow-insecure-http"],
        &environment,
    );

    assert_eq!(output.status.code(), Some(1));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result,
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "outcome": "forbidden"
        })
    );
    assert!(result.get("principal").is_none());
    assert!(output.stderr.is_empty());
    server.finish();

    let (server, _directory, _path, credential_path) = prepared_signup(
        vec![forbidden_problem_response()],
        "unique-refused-human-signup-synthetic-token",
    );
    let environment = signup_environment(&server, &credential_path);

    let output = run_with_env(
        &["account", "signup", "--allow-insecure-http"],
        &environment,
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).contains("useful account restore"));
    server.finish();
}

// REQ-ACCOUNT-20
#[test]
fn already_provisioned_signup_directs_the_human_to_status() {
    let response = problem_http_response(
        "409 Conflict",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/principal-already-provisioned",
            "title": "Principal already provisioned",
            "status": 409
        }),
    );
    let (server, _directory, _path, credential_path) =
        prepared_signup(vec![response], "unique-existing-signup-synthetic-token");
    let environment = signup_environment(&server, &credential_path);

    let output = run_with_env(
        &["account", "signup", "--allow-insecure-http"],
        &environment,
    );

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        output.stdout,
        b"! This identity already has a Useful Machinery account.\n\nRun:\n  useful account show\n"
    );
    assert!(output.stderr.is_empty());
    server.finish();
}

fn signed_out_signup(responses: Vec<Vec<u8>>) -> (ScriptedServer, tempfile::TempDir, String) {
    let server = ScriptedServer::respond(responses);
    let credential_directory = private_credential_directory();
    let credential_path = credential_directory
        .path()
        .join("credentials.json")
        .to_str()
        .unwrap()
        .to_owned();
    (server, credential_directory, credential_path)
}

// REQ-ACCOUNT-16
#[test]
fn signed_out_signup_signs_in_first_and_then_creates_the_account() {
    let (server, _directory, credential_path) = signed_out_signup(vec![
        auth_login::device_authorization_response("private-signup-device-code", "SIGNUP-CODE"),
        auth_login::issued_token_response(
            "unique-signed-in-signup-token",
            "unique-signed-in-signup-refresh-token",
        ),
        auth_login::principal_not_provisioned_response(),
        created_response(),
    ]);
    let environment = signup_environment(&server, &credential_path);

    let output = run_with_env(
        &["account", "signup", "--allow-insecure-http"],
        &environment,
    );

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let activation = stdout
        .find("https://auth.fixture.example/activate")
        .unwrap();
    let code = stdout.find("SIGNUP-CODE").unwrap();
    let created = stdout.find("prn_fixture").unwrap();
    assert!(activation < created && code < created);
    for secret in [
        "private-signup-device-code",
        "unique-signed-in-signup-token",
        "unique-signed-in-signup-refresh-token",
    ] {
        assert!(!stdout.contains(secret));
    }
    assert!(output.stderr.is_empty());

    let requests = server.finish();
    assert_eq!(requests.len(), 4);
    assert!(requests[0].starts_with("POST /auth/oauth/device/code HTTP/1.1\r\n"));
    assert!(requests[1].starts_with("POST /auth/oauth/token HTTP/1.1\r\n"));
    assert!(requests[2].starts_with("GET /api/v1/me HTTP/1.1\r\n"));
    assert_eq!(
        crate::header_value(&requests[2], "authorization"),
        "Bearer unique-signed-in-signup-token"
    );
    assert!(requests[3].starts_with("POST /api/v1/signup HTTP/1.1\r\n"));
    assert_eq!(
        crate::header_value(&requests[3], "authorization"),
        "Bearer unique-signed-in-signup-token"
    );

    let stored: serde_json::Value =
        serde_json::from_slice(&fs::read(&credential_path).unwrap()).unwrap();
    assert_eq!(
        stored["credentials"][0]["accessToken"],
        "unique-signed-in-signup-token"
    );
}

// REQ-ACCOUNT-16
#[test]
fn structured_signed_out_signup_reports_unauthenticated_without_signing_in() {
    let (server, _directory, credential_path) = signed_out_signup(Vec::new());
    let environment = signup_environment(&server, &credential_path);

    let output = run_with_env(
        &["account", "signup", "--json", "--allow-insecure-http"],
        &environment,
    );

    assert_eq!(output.status.code(), Some(3));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "outcome": "unauthenticated"
        })
    );
    assert!(output.stderr.is_empty());
    assert!(server.finish().is_empty());
}

// REQ-ACCOUNT-16
#[test]
fn denied_sign_in_ends_signup_without_asking() {
    let (server, _directory, credential_path) = signed_out_signup(vec![
        auth_login::device_authorization_response("private-denied-device-code", "DENY-CODE"),
        auth_login::denied_token_response(),
    ]);
    let environment = signup_environment(&server, &credential_path);

    let output = run_with_env(
        &["account", "signup", "--allow-insecure-http"],
        &environment,
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("POST /auth/oauth/device/code HTTP/1.1\r\n"));
    assert!(requests[1].starts_with("POST /auth/oauth/token HTTP/1.1\r\n"));
}

fn rate_limit_response(problem_type: &str, retry_after: Option<&str>) -> Vec<u8> {
    let headers: Vec<(&str, &str)> = retry_after
        .map(|value| vec![("Retry-After", value)])
        .unwrap_or_default();
    http_response_with_headers(
        "429 Too Many Requests",
        Some("application/problem+json"),
        &headers,
        &serde_json::to_vec(&serde_json::json!({
            "type": problem_type,
            "title": "signup-rate-title-sentinel",
            "status": 429,
            "detail": "signup-rate-detail-sentinel"
        }))
        .unwrap(),
    )
}

const RATE_LIMIT_EXCEEDED: &str = "https://api.usefulmachinery.com/problems/rate-limit-exceeded";

// REQ-ACCOUNT-79
#[test]
fn rate_limited_signup_reports_the_wait_without_retrying() {
    let (server, _directory, _path, credential_path) = prepared_signup(
        vec![rate_limit_response(RATE_LIMIT_EXCEEDED, Some("42"))],
        "unique-rate-limited-json-signup-synthetic-token",
    );
    let environment = signup_environment(&server, &credential_path);

    let output = run_with_env(
        &["account", "signup", "--json", "--allow-insecure-http"],
        &environment,
    );

    assert_eq!(output.status.code(), Some(4));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "outcome": "rate_limited",
            "retryAfter": 42
        })
    );
    assert!(output.stderr.is_empty());
    assert_eq!(server.finish().len(), 1);

    let (server, _directory, _path, credential_path) = prepared_signup(
        vec![rate_limit_response(RATE_LIMIT_EXCEEDED, Some("42"))],
        "unique-rate-limited-human-signup-synthetic-token",
    );
    let environment = signup_environment(&server, &credential_path);

    let output = run_with_env(
        &["account", "signup", "--allow-insecure-http"],
        &environment,
    );

    assert_eq!(output.status.code(), Some(4));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("42"));
    assert!(!stdout.contains("signup-rate-title-sentinel"));
    assert!(!stdout.contains("signup-rate-detail-sentinel"));
    assert_eq!(server.finish().len(), 1);
}

// REQ-ACCOUNT-79
#[test]
fn signup_rate_limit_without_a_usable_wait_or_problem_is_a_protocol_failure() {
    for (problem_type, retry_after) in [
        (RATE_LIMIT_EXCEEDED, None),
        (RATE_LIMIT_EXCEEDED, Some("0")),
        (RATE_LIMIT_EXCEEDED, Some("soon")),
        (RATE_LIMIT_EXCEEDED, Some("+42")),
        (
            "https://api.usefulmachinery.com/problems/quantity-limit-reached",
            Some("42"),
        ),
    ] {
        let (server, _directory, _path, credential_path) = prepared_signup(
            vec![rate_limit_response(problem_type, retry_after)],
            "unique-malformed-rate-signup-synthetic-token",
        );
        let environment = signup_environment(&server, &credential_path);

        let output = run_with_env(
            &["account", "signup", "--json", "--allow-insecure-http"],
            &environment,
        );

        assert_eq!(
            output.status.code(),
            Some(1),
            "{problem_type} {retry_after:?}"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("rate_limited"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("signup-rate-title-sentinel"));
        assert!(!stderr.contains("signup-rate-detail-sentinel"));
        assert_eq!(server.finish().len(), 1);
    }
}
