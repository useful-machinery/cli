use super::*;

const TOKEN: &str = "unique-organization-command-token-sentinel";

pub(super) fn prepared_organization(
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
    write_credential_fixture(
        &credential_path,
        &server.api_url,
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

pub(super) fn prepared_organization_refresh(
    mut responses: Vec<Vec<u8>>,
    access_token: &str,
) -> (
    ScriptedServer,
    tempfile::TempDir,
    std::path::PathBuf,
    String,
) {
    if responses.len() == 1
        && responses[0]
            .windows("401 Unauthorized".len())
            .any(|window| window == b"401 Unauthorized")
    {
        responses.push(json_http_response(
            "400 Bad Request",
            serde_json::json!({"error": "invalid_grant"}),
        ));
    }
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

fn organization_body() -> serde_json::Value {
    serde_json::json!({
        "id": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
        "state": "active",
        "displayName": "Acme Research",
        "slug": "acme-research",
        "createdAt": "2026-07-22T20:32:00Z",
        "updatedAt": "2026-07-22T20:32:00Z",
        "future": { "accepted": true }
    })
}

fn organization_success(status: &str) -> Vec<u8> {
    if status == "201 Created" {
        http_response_with_headers(
            status,
            Some("application/json"),
            &[
                ("Idempotency-Key", ECHO_IDEMPOTENCY_KEY),
                (
                    "Location",
                    "/v1/organizations/org_01k0z6r1w8f4jy2m7q9v3x5abc",
                ),
            ],
            &serde_json::to_vec(&organization_body()).unwrap(),
        )
    } else {
        json_http_response(status, organization_body())
    }
}

fn update_success() -> Vec<u8> {
    http_response_with_headers(
        "200 OK",
        Some("application/json"),
        &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
        &serde_json::to_vec(&organization_body()).unwrap(),
    )
}

fn membership_success(items: serde_json::Value, next_cursor: Option<&str>) -> Vec<u8> {
    let mut page = serde_json::json!({ "items": items });
    if let Some(next_cursor) = next_cursor {
        page["nextCursor"] = serde_json::Value::String(next_cursor.to_owned());
    }
    json_http_response("200 OK", page)
}

fn membership_history_items() -> serde_json::Value {
    serde_json::json!([
        {
            "id": "mem_01k0z6r1w8f4jy2m7q9v3x5abc",
            "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
            "principalId": "prn_01k0z6r1w8f4jy2m7q9v3x5abc",
            "principalType": "human",
            "displayName": "Ada Lovelace",
            "nameState": "live",
            "linkedEmails": [{"email": "first@example.test", "verified": false}, {"email": "second@example.test"}],
            "role": "owner",
            "state": "active",
            "createdAt": "2026-07-29T12:00:00Z",
            "updatedAt": "2026-07-29T12:00:00Z",
            "future": { "accepted": true }
        },
        {
            "id": "mem_01k0z6r1w8f4jy2m7q9v3x5abd",
            "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
            "principalId": "prn_01k0z6r1w8f4jy2m7q9v3x5abd",
            "principalType": "service",
            "displayName": "At departure",
            "nameState": "snapshot",
            "role": "member",
            "state": "ended",
            "createdAt": "2026-07-29T12:01:00Z",
            "updatedAt": "2026-07-29T12:02:00Z",
            "terminalAt": "2026-07-29T12:02:00Z"
        },
        {
            "id": "mem_01k0z6r1w8f4jy2m7q9v3x5abe",
            "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
            "principalId": "prn_01k0z6r1w8f4jy2m7q9v3x5abe",
            "principalType": "human",
            "displayName": "Ada Lovelace",
            "nameState": "live",
            "linkedEmails": [],
            "role": "member",
            "state": "suspended",
            "createdAt": "2026-07-29T12:03:00Z",
            "updatedAt": "2026-07-29T12:03:00Z"
        },
        {
            "id": "mem_01k0z6r1w8f4jy2m7q9v3x5abf",
            "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
            "principalId": "prn_01k0z6r1w8f4jy2m7q9v3x5abf",
            "principalType": "human",
            "nameState": "missing",
            "linkedEmails": [],
            "role": "member",
            "state": "active",
            "createdAt": "2026-07-29T12:04:00Z",
            "updatedAt": "2026-07-29T12:04:00Z"
        },
        {
            "id": "mem_01k0z6r1w8f4jy2m7q9v3x5abg",
            "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
            "principalId": "prn_01k0z6r1w8f4jy2m7q9v3x5abg",
            "principalType": "human",
            "nameState": "unavailable",
            "role": "member",
            "state": "ended",
            "createdAt": "2026-07-29T12:05:00Z",
            "updatedAt": "2026-07-29T12:06:00Z",
            "terminalAt": "2026-07-29T12:06:00Z"
        },
        {
            "id": "mem_01k0z6r1w8f4jy2m7q9v3x5abh",
            "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
            "principalType": "human",
            "nameState": "unavailable",
            "role": "member",
            "state": "ended",
            "createdAt": "2026-07-29T12:07:00Z",
            "updatedAt": "2026-07-29T12:08:00Z",
            "terminalAt": "2026-07-29T12:08:00Z"
        },
        {
            "id": "mem_01k0z6r1w8f4jy2m7q9v3x5abj",
            "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
            "principalId": "prn_01k0z6r1w8f4jy2m7q9v3x5abj",
            "principalType": "human",
            "displayName": "At departure",
            "nameState": "snapshot",
            "linkedEmails": [{"email": "then@example.test", "verified": false}, {"email": "unknown@example.test"}],
            "role": "member",
            "state": "ended",
            "createdAt": "2026-07-29T12:09:00Z",
            "updatedAt": "2026-07-29T12:10:00Z",
            "terminalAt": "2026-07-29T12:10:00Z"
        }
    ])
}

fn membership_update_success() -> Vec<u8> {
    let body = serde_json::json!({
        "id": "mem_01k0z6r1w8f4jy2m7q9v3x5abc",
        "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
        "principalId": "prn_01k0z6r1w8f4jy2m7q9v3x5abc",
        "principalType": "human",
        "displayName": "Ada Lovelace",
        "nameState": "live",
        "role": "member",
        "state": "active",
        "createdAt": "2026-07-29T12:00:00Z",
        "updatedAt": "2026-09-05T12:00:00Z"
    });
    http_response_with_headers(
        "200 OK",
        Some("application/json"),
        &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
        &serde_json::to_vec(&body).unwrap(),
    )
}

pub(super) fn membership_termination_success() -> Vec<u8> {
    http_response_with_headers(
        "204 No Content",
        None,
        &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
        &[],
    )
}

fn current_membership_items() -> serde_json::Value {
    serde_json::json!([
        {
            "id": "mem_01k0z6r1w8f4jy2m7q9v3x5abc",
            "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
            "organizationState": "active",
            "organizationDisplayName": "Acme Research",
            "organizationSlug": "acme-research",
            "role": "owner",
            "state": "active",
            "createdAt": "2026-07-22T20:32:00Z",
            "updatedAt": "2026-07-23T10:00:00Z",
            "future": { "accepted": true }
        },
        {
            "id": "mem_01k0z6r1w8f4jy2m7q9v3x5abd",
            "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abd",
            "organizationState": "suspended",
            "role": "member",
            "state": "ended",
            "createdAt": "2026-08-01T12:00:00Z",
            "updatedAt": "2026-09-01T12:00:00Z",
            "terminalAt": "2026-09-01T12:00:00Z"
        }
    ])
}

pub(super) fn organization_problem(status_text: &str, status: u16, problem_type: &str) -> Vec<u8> {
    problem_http_response(
        status_text,
        serde_json::json!({
            "type": problem_type,
            "title": "organization-problem-title-sentinel",
            "status": status,
            "detail": "organization-problem-detail-sentinel"
        }),
    )
}

fn response_with_detail(detail: &str) -> Vec<u8> {
    problem_http_response(
        "404 Not Found",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/not-found",
            "title": "Private target",
            "status": 404,
            "detail": detail
        }),
    )
}

fn request_body(request: &str) -> &str {
    request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("request should contain a body separator")
}

#[test]
fn organization_has_no_alias_and_create_requires_a_display_name() {
    for args in [
        &["organization", "show", "acme"][..],
        &["org", "create", "--json"][..],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn human_create_has_exact_output_and_request_contract() {
    let (server, _directory, _path, credential_path) =
        prepared_organization(vec![organization_success("201 Created")], TOKEN);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "org",
            "create",
            "--name",
            "\u{2003}Acme Research\u{2003}",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            concat!(
                "✓ Organization created.\n\n",
                "  Organization: org_01k0z6r1w8f4jy2m7q9v3x5abc\n",
                "  Name:         Acme Research\n",
                "  Slug:         acme-research\n",
                "  State:        active\n",
                "  Deployment:   {}\n"
            ),
            server.api_url
        )
    );
    assert!(output.stderr.is_empty());

    let request = server.finish().pop().unwrap();
    assert!(request.starts_with("POST /api/v1/organizations HTTP/1.1\r\n"));
    assert_eq!(
        header_value(&request, "authorization"),
        format!("Bearer {TOKEN}")
    );
    assert_eq!(header_value(&request, "content-type"), "application/json");
    assert_eq!(
        header_value(&request, "accept"),
        "application/json, application/problem+json"
    );
    let key = header_value(&request, "idempotency-key");
    assert_eq!(key.len(), 64);
    assert!(
        key.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request_body(&request)).unwrap(),
        serde_json::json!({"displayName": "\u{2003}Acme Research\u{2003}"})
    );
}

#[test]
fn service_create_sends_explicit_delegator_without_using_human_credentials() {
    const SERVICE_KEY: &str =
        "crd_01k0z6r1w8f4jy2m7q9v3x5abc.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const DELEGATOR: &str = "prn_01k0z6r1w8f4jy2m7q9v3x5abc";
    let server = ScriptedServer::respond(vec![organization_success("201 Created")]);
    let directory = private_credential_directory();
    let key_path = directory.path().join("service.key");
    fs::write(&key_path, format!("{SERVICE_KEY}\n")).unwrap();
    fs::set_permissions(&key_path, Permissions::from_mode(0o600)).unwrap();
    let human_credentials = directory.path().join("unused-human.json");
    let environment = deployment_environment(&server.api_url, human_credentials.to_str().unwrap());

    let output = run_with_env(
        &[
            "org",
            "create",
            "--name",
            "Acme Research",
            "--delegator-principal-id",
            DELEGATOR,
            "--api-key-file",
            key_path.to_str().unwrap(),
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SERVICE_KEY));
    assert!(output.stderr.is_empty());
    let request = server.finish().pop().unwrap();
    assert_eq!(
        header_value(&request, "authorization"),
        format!("Bearer {SERVICE_KEY}")
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request_body(&request)).unwrap(),
        serde_json::json!({
            "displayName": "Acme Research",
            "delegatorPrincipalId": DELEGATOR
        })
    );
}

#[test]
fn service_create_name_gate_points_to_the_nominated_human_without_private_fields() {
    const SERVICE_KEY: &str =
        "crd_01k0z6r1w8f4jy2m7q9v3x5abc.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const DELEGATOR: &str = "prn_01k0z6r1w8f4jy2m7q9v3x5abc";
    let response = organization_problem(
        "409 Conflict",
        409,
        "https://api.usefulmachinery.com/problems/human-display-name-required",
    );
    let server = ScriptedServer::respond(vec![response]);
    let directory = private_credential_directory();
    let key_path = directory.path().join("service.key");
    fs::write(&key_path, format!("{SERVICE_KEY}\n")).unwrap();
    fs::set_permissions(&key_path, Permissions::from_mode(0o600)).unwrap();
    let human_credentials = directory.path().join("unused-human.json");
    let environment = deployment_environment(&server.api_url, human_credentials.to_str().unwrap());
    let output = run_with_env(
        &[
            "org",
            "create",
            "--name",
            "Acme",
            "--delegator-principal-id",
            DELEGATOR,
            "--api-key-file",
            key_path.to_str().unwrap(),
            "--allow-insecure-http",
        ],
        &environment,
    );
    assert_eq!(output.status.code(), Some(1));
    let message = String::from_utf8_lossy(&output.stdout);
    assert!(message.contains("nominated human"));
    assert!(!message.contains(DELEGATOR));
    assert!(!message.contains("private-problem-detail"));
    server.finish();
}

#[test]
fn service_create_requires_explicit_human_delegator() {
    const SERVICE_KEY: &str =
        "crd_01k0z6r1w8f4jy2m7q9v3x5abc.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let server = ScriptedServer::respond(Vec::new());
    let directory = private_credential_directory();
    let key_path = directory.path().join("service.key");
    fs::write(&key_path, format!("{SERVICE_KEY}\n")).unwrap();
    fs::set_permissions(&key_path, Permissions::from_mode(0o600)).unwrap();
    let human_credentials = directory.path().join("unused-human.json");
    let environment = deployment_environment(&server.api_url, human_credentials.to_str().unwrap());

    let output = run_with_env(
        &[
            "org",
            "create",
            "--name",
            "Acme Research",
            "--api-key-file",
            key_path.to_str().unwrap(),
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--delegator-principal-id is required when --api-key-file is used")
    );
    assert!(server.finish().is_empty());
}

#[test]
fn json_create_reports_schema_one_and_supplied_slug() {
    let (server, _directory, _path, credential_path) =
        prepared_organization(vec![organization_success("201 Created")], TOKEN);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "org",
            "create",
            "--name",
            "Acme Research",
            "--slug",
            "acme-research",
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "outcome": "created",
            "organization": {
                "id": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
                "state": "active",
                "displayName": "Acme Research",
                "slug": "acme-research",
                "createdAt": "2026-07-22T20:32:00Z",
                "updatedAt": "2026-07-22T20:32:00Z"
            }
        })
    );
    assert!(output.stdout.ends_with(b"\n"));
    assert!(output.stderr.is_empty());
    let request = server.finish().pop().unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request_body(&request)).unwrap(),
        serde_json::json!({
            "displayName": "Acme Research",
            "slug": "acme-research"
        })
    );
}

#[test]
fn create_retries_one_ambiguous_failure_with_the_same_complete_request() {
    let (server, _directory, _path, credential_path) =
        prepared_organization(vec![Vec::new(), organization_success("201 Created")], TOKEN);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "org",
            "create",
            "--name",
            "Acme Research",
            "--slug",
            "acme-research",
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert!(output.status.success());
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1]);
    assert_eq!(
        header_value(&requests[0], "idempotency-key"),
        header_value(&requests[1], "idempotency-key")
    );
}

#[test]
fn create_expected_outcomes_have_exact_json_and_exit_statuses() {
    let cases = [
        (
            organization_problem(
                "400 Bad Request",
                400,
                "https://api.usefulmachinery.com/problems/bad-request",
            ),
            "invalid_input",
            1,
            None,
        ),
        (
            organization_problem(
                "401 Unauthorized",
                401,
                "https://api.usefulmachinery.com/problems/unauthorized",
            ),
            "unauthenticated",
            3,
            None,
        ),
        (
            organization_problem(
                "403 Forbidden",
                403,
                "https://api.usefulmachinery.com/problems/forbidden",
            ),
            "forbidden",
            1,
            None,
        ),
        (
            organization_problem(
                "403 Forbidden",
                403,
                "https://api.usefulmachinery.com/problems/organization-creation-not-permitted",
            ),
            "creation_not_permitted",
            1,
            None,
        ),
        (
            organization_problem(
                "409 Conflict",
                409,
                "https://api.usefulmachinery.com/problems/human-display-name-required",
            ),
            "human_display_name_required",
            1,
            None,
        ),
        (
            organization_problem(
                "409 Conflict",
                409,
                "https://api.usefulmachinery.com/problems/slug-unavailable",
            ),
            "slug_unavailable",
            1,
            None,
        ),
        (
            organization_problem(
                "409 Conflict",
                409,
                "https://api.usefulmachinery.com/problems/quantity-limit-reached",
            ),
            "quantity_limit_reached",
            1,
            None,
        ),
        (
            organization_problem(
                "409 Conflict",
                409,
                "https://api.usefulmachinery.com/problems/membership-limit-reached",
            ),
            "membership_limit_reached",
            1,
            None,
        ),
        (
            organization_problem(
                "409 Conflict",
                409,
                "https://api.usefulmachinery.com/problems/idempotency-conflict",
            ),
            "idempotency_conflict",
            1,
            None,
        ),
        (
            http_response_with_headers(
                "429 Too Many Requests",
                Some("application/problem+json"),
                &[("Retry-After", "42")],
                &serde_json::to_vec(&serde_json::json!({
                    "type": "https://api.usefulmachinery.com/problems/rate-limit-exceeded",
                    "title": "organization-problem-title-sentinel",
                    "status": 429,
                    "detail": "organization-problem-detail-sentinel"
                }))
                .unwrap(),
            ),
            "rate_limited",
            4,
            Some(42),
        ),
        (
            http_response("503 Service Unavailable", None, &[]),
            "unreachable",
            4,
            None,
        ),
    ];

    for (response, expected_outcome, expected_status, retry_after) in cases {
        let (server, _directory, _path, credential_path) =
            prepared_organization_refresh(vec![response], TOKEN);
        let environment =
            deployment_environment_with_issuer(&server.api_url, &server.issuer, &credential_path);
        let output = run_with_env(
            &[
                "org",
                "create",
                "--name",
                "Acme Research",
                "--json",
                "--allow-insecure-http",
            ],
            &environment,
        );

        assert_eq!(output.status.code(), Some(expected_status));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["deployment"], server.api_url);
        assert_eq!(value["outcome"], expected_outcome);
        if let Some(retry_after) = retry_after {
            assert_eq!(value["retryAfter"], retry_after);
        } else {
            assert!(value.get("retryAfter").is_none());
        }
        if expected_outcome == "unreachable" {
            assert_eq!(value["category"], "server");
        } else {
            assert!(value.get("category").is_none());
        }
        assert!(value.get("title").is_none());
        assert!(value.get("detail").is_none());
        assert!(output.stderr.is_empty());
        let requests = server.finish();
        let expected_requests = if expected_outcome == "unauthenticated" {
            2
        } else {
            1
        };
        assert_eq!(requests.len(), expected_requests);
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.starts_with("POST /auth/oauth/token HTTP/1.1\r\n"))
                .count(),
            usize::from(expected_outcome == "unauthenticated")
        );
    }
}

#[test]
fn two_ambiguous_create_failures_report_an_unconfirmed_result() {
    let (server, _directory, _path, credential_path) =
        prepared_organization(vec![Vec::new(), Vec::new()], TOKEN);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "org",
            "create",
            "--name",
            "Acme Research",
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert_eq!(output.status.code(), Some(4));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["outcome"],
        "unreachable"
    );
    assert!(output.stderr.is_empty());
    assert_eq!(server.finish().len(), 2);
}

#[test]
fn malformed_rate_limit_metadata_is_a_protocol_failure() {
    for retry_after in [None, Some("invalid"), Some("+42"), Some("0")] {
        let headers: Vec<(&str, &str)> = retry_after
            .map(|value| vec![("Retry-After", value)])
            .unwrap_or_default();
        let body = serde_json::to_vec(&serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/rate-limit-exceeded",
            "title": "rate-title-sentinel",
            "status": 429,
            "detail": "rate-detail-sentinel"
        }))
        .unwrap();
        let response = http_response_with_headers(
            "429 Too Many Requests",
            Some("application/problem+json"),
            &headers,
            &body,
        );
        let (server, _directory, _path, credential_path) =
            prepared_organization(vec![response], TOKEN);
        let environment = deployment_environment(&server.api_url, &credential_path);

        let output = run_with_env(
            &[
                "org",
                "create",
                "--name",
                "Acme",
                "--json",
                "--allow-insecure-http",
            ],
            &environment,
        );

        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("rate-title-sentinel"));
        assert!(!stderr.contains("rate-detail-sentinel"));
        server.finish();
    }
}

#[test]
fn unauthorized_removes_only_the_rejected_credential_and_forbidden_retains_it() {
    for (response, expected_status, expect_credential) in [
        (
            organization_problem(
                "401 Unauthorized",
                401,
                "https://api.usefulmachinery.com/problems/unauthorized",
            ),
            3,
            false,
        ),
        (
            http_response(
                "401 Unauthorized",
                Some("application/problem+json"),
                b"not-json",
            ),
            3,
            false,
        ),
        (
            organization_problem(
                "403 Forbidden",
                403,
                "https://api.usefulmachinery.com/problems/forbidden",
            ),
            1,
            true,
        ),
    ] {
        let (server, _directory, credential_path, credential_path_string) =
            prepared_organization_refresh(vec![response], TOKEN);
        let environment = deployment_environment_with_issuer(
            &server.api_url,
            &server.issuer,
            &credential_path_string,
        );

        let output = run_with_env(
            &["org", "show", "acme", "--json", "--allow-insecure-http"],
            &environment,
        );

        assert_eq!(output.status.code(), Some(expected_status));
        let stored: serde_json::Value =
            serde_json::from_slice(&fs::read(&credential_path).unwrap()).unwrap();
        assert_eq!(
            !stored["credentials"].as_array().unwrap().is_empty(),
            expect_credential
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!combined.contains(TOKEN));
        server.finish();
    }
}

#[test]
fn show_success_preserves_schema_and_the_valid_reference_target() {
    let (server, _directory, _path, credential_path) =
        prepared_organization(vec![organization_success("200 OK")], TOKEN);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "org",
            "show",
            "acme-research",
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["deployment"], server.api_url);
    assert_eq!(value["outcome"], "found");
    assert_eq!(
        value["organization"],
        serde_json::json!({
            "id": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
            "state": "active",
            "displayName": "Acme Research",
            "slug": "acme-research",
            "createdAt": "2026-07-22T20:32:00Z",
            "updatedAt": "2026-07-22T20:32:00Z"
        })
    );
    assert!(value["organization"].get("future").is_none());
    assert!(output.stdout.ends_with(b"\n"));
    assert!(output.stderr.is_empty());
    let request = server.finish().pop().unwrap();
    assert!(request.starts_with("GET /api/v1/organizations/acme-research HTTP/1.1\r\n"));
    assert_eq!(
        header_value(&request, "authorization"),
        format!("Bearer {TOKEN}")
    );
    assert!(useful_test_support::request_header(&request, "idempotency-key").is_none());
}

#[test]
fn a_rejected_request_does_not_remove_a_concurrently_replaced_credential() {
    let response = organization_problem(
        "401 Unauthorized",
        401,
        "https://api.usefulmachinery.com/problems/unauthorized",
    );
    let mut server = ScriptedServer::respond_with_paused_first_response(vec![
        response,
        organization_success("200 OK"),
    ]);
    let api_url = server.api_url.clone();
    let directory = private_credential_directory();
    let credential_path = directory.path().join("credentials.json");
    write_credential_fixture(
        &credential_path,
        &api_url,
        "original-organization-token",
        "2999-01-01T00:00:00Z",
    );
    let credential_path_string = credential_path.to_str().unwrap().to_owned();
    let environment = deployment_environment(&api_url, &credential_path_string);

    let output = thread::scope(|scope| {
        let command = scope.spawn(|| {
            run_with_env(
                &["org", "show", "acme", "--json", "--allow-insecure-http"],
                &environment,
            )
        });
        let request = server.next_request();
        assert_eq!(
            header_value(&request, "authorization"),
            "Bearer original-organization-token"
        );
        fs::remove_file(&credential_path).unwrap();
        write_credential_fixture(
            &credential_path,
            &api_url,
            "replacement-organization-token",
            "2999-01-01T00:00:00Z",
        );
        server.release_paused_response();
        command.join().unwrap()
    });

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stored: serde_json::Value =
        serde_json::from_slice(&fs::read(&credential_path).unwrap()).unwrap();
    assert_eq!(
        stored["credentials"][0]["accessToken"],
        "replacement-organization-token"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains("original-organization-token"));
    assert!(!combined.contains("replacement-organization-token"));
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        header_value(&requests[0], "authorization"),
        "Bearer replacement-organization-token"
    );
}

#[test]
fn organization_commands_have_closed_transport_and_protocol_failures() {
    let cases = [
        (
            &[
                "org",
                "show",
                "acme-research",
                "--json",
                "--allow-insecure-http",
            ][..],
            vec![Vec::new()],
            4,
            Some("connection"),
            1,
        ),
        (
            &[
                "org",
                "update",
                "acme",
                "--slug",
                "acme-labs",
                "--json",
                "--allow-insecure-http",
            ][..],
            vec![Vec::new(), Vec::new()],
            4,
            Some("connection"),
            2,
        ),
        (
            &[
                "org",
                "update",
                "acme",
                "--slug",
                "acme-labs",
                "--json",
                "--allow-insecure-http",
            ][..],
            vec![json_http_response(
                "200 OK",
                serde_json::json!({"protocol-response-sentinel": true}),
            )],
            1,
            None,
            1,
        ),
        (
            &[
                "org",
                "member",
                "list",
                "--org",
                "acme",
                "--json",
                "--allow-insecure-http",
            ][..],
            vec![Vec::new()],
            4,
            Some("connection"),
            1,
        ),
        (
            &[
                "org",
                "member",
                "list",
                "--org",
                "acme",
                "--json",
                "--allow-insecure-http",
            ][..],
            vec![json_http_response(
                "200 OK",
                serde_json::json!({
                    "items": [],
                    "nextCursor": "",
                    "protocol-response-sentinel": true
                }),
            )],
            1,
            None,
            1,
        ),
    ];

    for (args, responses, expected_status, expected_category, expected_requests) in cases {
        let (server, _directory, _path, credential_path) = prepared_organization(responses, TOKEN);
        let environment = deployment_environment(&server.api_url, &credential_path);

        let output = run_with_env(args, &environment);

        assert_eq!(output.status.code(), Some(expected_status));
        if let Some(expected_category) = expected_category {
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(value["outcome"], "unreachable");
            assert_eq!(value["category"], expected_category);
            assert!(output.stderr.is_empty());
        } else {
            assert!(output.stdout.is_empty());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!stderr.is_empty());
            assert!(!stderr.contains("protocol-response-sentinel"));
            assert!(!stderr.contains(TOKEN));
        }
        assert_eq!(server.finish().len(), expected_requests);
    }
}

#[test]
fn organization_commands_reject_invalid_cli_input_before_deployment_loading() {
    for args in [
        &["org", "show", "."][..],
        &["org", "show", ".."][..],
        &["org", "show", "acme/research"][..],
        &["org", "show", "acme\\research"][..],
        &["org", "leave", "acme/research", "--yes"][..],
        &["org", "member", "event", "list", "--org", "acme/research"][..],
        &[
            "org",
            "member",
            "update",
            "--org",
            "acme/research",
            "mem_01k0z6r1w8f4jy2m7q9v3x5abc",
            "--role",
            "member",
        ][..],
        &[
            "org",
            "member",
            "remove",
            "--org",
            "acme/research",
            "mem_01k0z6r1w8f4jy2m7q9v3x5abc",
            "--yes",
        ][..],
        &["org", "update", "acme"][..],
        &["org", "list", "--limit", "0"][..],
        &["org", "list", "--limit", "201"][..],
        &["org", "list", "--cursor", ""][..],
        &["org", "member", "list", "--org", "acme", "--limit", "0"][..],
        &["org", "member", "list", "--org", "acme", "--limit", "201"][..],
        &["org", "member", "list", "--org", "acme", "--cursor", ""][..],
        &[
            "org", "member", "event", "list", "--org", "acme", "--limit", "201",
        ][..],
        &[
            "org",
            "member",
            "update",
            "--org",
            "acme",
            "mem_01k0z6r1w8f4jy2m7q9v3x5abc",
            "--role",
            "administrator",
        ][..],
    ] {
        let output = run_with_env(
            args,
            &[("USEFUL_API_URL", "partial-override-must-not-load")],
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn update_accepts_each_patch_shape_and_preserves_the_request_contract() {
    let cases = [
        (
            &["--name", "\u{2003}Acme Labs\u{2003}"][..],
            serde_json::json!({"displayName": "\u{2003}Acme Labs\u{2003}"}),
        ),
        (
            &["--slug", "Server_Invalid"][..],
            serde_json::json!({"slug": "Server_Invalid"}),
        ),
        (
            &["--name", "Acme Labs", "--slug", "acme-labs"][..],
            serde_json::json!({"displayName": "Acme Labs", "slug": "acme-labs"}),
        ),
    ];

    for (profile_args, expected_body) in cases {
        let (server, _directory, _path, credential_path) =
            prepared_organization(vec![update_success()], TOKEN);
        let environment = deployment_environment(&server.api_url, &credential_path);
        let mut args = vec![
            "org",
            "update",
            "acme-research",
            "--json",
            "--allow-insecure-http",
        ];
        args.extend_from_slice(profile_args);

        let output = run_with_env(&args, &environment);

        assert!(output.status.success());
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["schemaVersion"], 1);
        assert_eq!(result["deployment"], server.api_url);
        assert_eq!(result["outcome"], "updated");
        let mut expected_organization = organization_body();
        expected_organization
            .as_object_mut()
            .unwrap()
            .remove("future");
        assert_eq!(result["organization"], expected_organization);
        assert!(output.stdout.ends_with(b"\n"));
        assert!(output.stderr.is_empty());

        let request = server.finish().pop().unwrap();
        assert!(request.starts_with("PATCH /api/v1/organizations/acme-research HTTP/1.1\r\n"));
        assert_eq!(
            header_value(&request, "authorization"),
            format!("Bearer {TOKEN}")
        );
        assert_eq!(
            header_value(&request, "content-type"),
            "application/merge-patch+json"
        );
        let key = header_value(&request, "idempotency-key");
        assert_eq!(key.len(), 64);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(request_body(&request)).unwrap(),
            expected_body
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!combined.contains(TOKEN));
        assert!(!combined.contains(key));
    }
}

#[test]
fn human_update_has_exact_success_output() {
    let (server, _directory, _path, credential_path) =
        prepared_organization(vec![update_success()], TOKEN);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "org",
            "update",
            "acme-research",
            "--name",
            "Acme Research",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!(
            concat!(
                "✓ Organization updated.\n\n",
                "  Organization: org_01k0z6r1w8f4jy2m7q9v3x5abc\n",
                "  Name:         Acme Research\n",
                "  Slug:         acme-research\n",
                "  State:        active\n",
                "  Deployment:   {}\n"
            ),
            server.api_url
        )
    );
    assert!(output.stderr.is_empty());
    server.finish();
}

#[test]
fn update_expected_outcomes_have_exact_json_and_exit_statuses() {
    let cases = [
        (
            organization_problem(
                "409 Conflict",
                409,
                "https://api.usefulmachinery.com/problems/slug-unavailable",
            ),
            "slug_unavailable",
            1,
        ),
        (
            organization_problem(
                "409 Conflict",
                409,
                "https://api.usefulmachinery.com/problems/idempotency-conflict",
            ),
            "idempotency_conflict",
            1,
        ),
    ];

    for (response, expected_outcome, expected_status) in cases {
        let (server, _directory, _path, credential_path) =
            prepared_organization_refresh(vec![response], TOKEN);
        let environment =
            deployment_environment_with_issuer(&server.api_url, &server.issuer, &credential_path);
        let output = run_with_env(
            &[
                "org",
                "update",
                "acme-research",
                "--slug",
                "acme-labs",
                "--json",
                "--allow-insecure-http",
            ],
            &environment,
        );

        assert_eq!(output.status.code(), Some(expected_status));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["deployment"], server.api_url);
        assert_eq!(value["outcome"], expected_outcome);
        assert!(value.get("category").is_none());
        assert!(value.get("title").is_none());
        assert!(value.get("detail").is_none());
        assert!(output.stderr.is_empty());
        assert_eq!(server.finish().len(), 1);
    }
}

#[test]
fn organization_list_emits_one_visibility_preserving_page() {
    let cursor = "next page /+=";
    let response_items = current_membership_items();
    let (server, _directory, _path, credential_path) = prepared_organization(
        vec![
            membership_success(response_items.clone(), Some(cursor)),
            membership_success(response_items.clone(), None),
        ],
        TOKEN,
    );
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "org",
            "list",
            "--limit",
            "2",
            "--cursor",
            "opaque /+=?&",
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert!(output.status.success());
    let mut expected_items = response_items;
    expected_items[0].as_object_mut().unwrap().remove("future");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "outcome": "listed",
            "items": expected_items,
            "nextCursor": cursor,
            "organizationInEffect": {
                "organization": IN_EFFECT_ID,
                "source": "only_membership"
            }
        })
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["items"][0]["organizationSlug"], "acme-research");
    assert!(value["items"][1].get("organizationDisplayName").is_none());
    assert!(value["items"][1].get("organizationSlug").is_none());
    assert!(output.stdout.ends_with(b"\n"));
    assert!(output.stderr.is_empty());

    // The page shown is the one asked for; a page that may not hold every membership leaves
    // the organization in effect to its own read.
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [
            "GET /api/v1/me/memberships?limit=2&cursor=opaque+%2F%2B%3D%3F%26 HTTP/1.1",
            LIST_CURRENT_MEMBERSHIPS.trim_end(),
        ],
        "nextCursor must not trigger pagination"
    );
    assert_eq!(
        header_value(&requests[0], "authorization"),
        format!("Bearer {TOKEN}")
    );
    assert!(useful_test_support::request_header(&requests[0], "idempotency-key").is_none());
}

#[test]
fn human_organization_list_exposes_identity_and_history_without_synthesizing_profile_data() {
    let (server, _directory, _path, credential_path) = prepared_organization(
        vec![membership_success(current_membership_items(), None)],
        TOKEN,
    );
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(&["org", "list", "--allow-insecure-http"], &environment);

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "organization: org_01k0z6r1w8f4jy2m7q9v3x5abc",
        "organization slug: acme-research",
        "organization: org_01k0z6r1w8f4jy2m7q9v3x5abd · organization state: suspended",
        "membership: mem_01k0z6r1w8f4jy2m7q9v3x5abd · role: member · membership state: ended",
        "terminal: 2026-09-01T12:00:00Z",
    ] {
        assert!(stdout.contains(expected));
    }
    assert!(!stdout.contains("unavailable"));
    assert!(output.stderr.is_empty());
    server.finish();
}

#[test]
fn human_organization_list_api_failure_uses_the_diagnostic_stream() {
    let response = organization_problem(
        "400 Bad Request",
        400,
        "https://api.usefulmachinery.com/problems/bad-request",
    );
    let (server, _directory, _path, credential_path) = prepared_organization(vec![response], TOKEN);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(&["org", "list", "--allow-insecure-http"], &environment);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("error: "));
    assert!(stderr.contains("\n\n"));
    assert!(!stderr.contains(TOKEN));
    server.finish();
}

#[test]
fn organization_list_rejects_responses_that_violate_profile_visibility() {
    let malformed_pages = [
        serde_json::json!({
            "items": [{
                "id": "mem_01k0z6r1w8f4jy2m7q9v3x5abc",
                "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
                "organizationState": "active",
                "role": "owner",
                "state": "active",
                "createdAt": "2026-07-22T20:32:00Z",
                "updatedAt": "2026-07-22T20:32:00Z"
            }]
        }),
        serde_json::json!({
            "items": [{
                "id": "mem_01k0z6r1w8f4jy2m7q9v3x5abc",
                "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
                "organizationState": "suspended",
                "organizationDisplayName": "private-profile-sentinel",
                "organizationSlug": "private-slug-sentinel",
                "role": "owner",
                "state": "active",
                "createdAt": "2026-07-22T20:32:00Z",
                "updatedAt": "2026-07-22T20:32:00Z"
            }]
        }),
        serde_json::json!({
            "items": [{
                "id": "mem_01k0z6r1w8f4jy2m7q9v3x5abc",
                "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
                "organizationState": "active",
                "organizationDisplayName": "private-profile-sentinel",
                "organizationSlug": "private-slug-sentinel",
                "role": "owner",
                "state": "ended",
                "createdAt": "2026-07-22T20:32:00Z",
                "updatedAt": "2026-07-22T20:32:00Z",
                "terminalAt": "2026-07-22T20:32:00Z"
            }]
        }),
        serde_json::json!({"items": [], "nextCursor": null}),
    ];

    for page in malformed_pages {
        let (server, _directory, _path, credential_path) =
            prepared_organization(vec![json_http_response("200 OK", page)], TOKEN);
        let environment = deployment_environment(&server.api_url, &credential_path);

        let output = run_with_env(
            &["org", "list", "--json", "--allow-insecure-http"],
            &environment,
        );

        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("private-profile-sentinel"));
        assert!(!stderr.contains(TOKEN));
        server.finish();
    }
}

#[test]
fn members_list_preserves_omitted_and_opaque_query_values() {
    let cases = [
        (&[][..], "/api/v1/organizations/acme-research/memberships"),
        (
            &["--limit", "1"][..],
            "/api/v1/organizations/acme-research/memberships?limit=1",
        ),
        (
            &["--limit", "200"][..],
            "/api/v1/organizations/acme-research/memberships?limit=200",
        ),
        (
            &["--cursor", "opaque /+=?&"][..],
            "/api/v1/organizations/acme-research/memberships?cursor=opaque+%2F%2B%3D%3F%26",
        ),
        (
            &["--limit", "42", "--cursor", "opaque /+=?&"][..],
            "/api/v1/organizations/acme-research/memberships?limit=42&cursor=opaque+%2F%2B%3D%3F%26",
        ),
    ];

    for (query_args, expected_target) in cases {
        let (server, _directory, _path, credential_path) =
            prepared_organization(vec![membership_success(serde_json::json!([]), None)], TOKEN);
        let environment = deployment_environment(&server.api_url, &credential_path);
        let mut args = vec![
            "org",
            "member",
            "list",
            "--org",
            "acme-research",
            "--json",
            "--allow-insecure-http",
        ];
        args.extend_from_slice(query_args);

        let output = run_with_env(&args, &environment);

        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let request = server.finish().pop().unwrap();
        assert!(request.starts_with(&format!("GET {expected_target} HTTP/1.1\r\n")));
        assert_eq!(
            header_value(&request, "authorization"),
            format!("Bearer {TOKEN}")
        );
        assert!(useful_test_support::request_header(&request, "idempotency-key").is_none());
    }
}

#[test]
fn json_members_list_emits_one_continued_page_exactly() {
    let items = serde_json::json!([
        {
            "id": "mem_owner",
            "principalId": "prn_human",
            "principalType": "human",
            "principalState": "active",
            "displayName": "Ada Lovelace",
            "linkedEmails": [{"email": "ada@first.test", "verified": true}, {"email": "ada@second.test"}],
            "role": "owner",
            "state": "active",
            "future": "member-response-sentinel"
        },
        {
            "id": "mem_service",
            "principalId": "prn_service",
            "principalType": "service",
            "principalState": "suspended",
            "role": "member",
            "state": "suspended"
        }
    ]);
    let cursor = "opaque continuation /+=?&";
    let (server, _directory, _path, credential_path) =
        prepared_organization(vec![membership_success(items, Some(cursor))], TOKEN);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "org",
            "member",
            "list",
            "--org",
            "acme",
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({
            "schemaVersion": 2,
            "deployment": server.api_url,
            "outcome": "listed",
            "items": [
                {
                    "id": "mem_owner",
                    "principalId": "prn_human",
                    "principalType": "human",
                    "principalState": "active",
                    "displayName": "Ada Lovelace",
                    "linkedEmails": [{"email": "ada@first.test", "verified": true}, {"email": "ada@second.test"}],
                    "role": "owner",
                    "state": "active"
                },
                {
                    "id": "mem_service",
                    "principalId": "prn_service",
                    "principalType": "service",
                    "principalState": "suspended",
                    "role": "member",
                    "state": "suspended"
                }
            ],
            "nextCursor": cursor
        })
    );
    assert!(output.stdout.ends_with(b"\n"));
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("member-response-sentinel"));
    assert_eq!(
        server.finish().len(),
        1,
        "nextCursor must not trigger pagination"
    );
}

#[test]
fn human_and_empty_members_pages_have_exact_output() {
    let items = serde_json::json!([
        {
            "id": "mem_owner",
            "principalId": "prn_human",
            "principalType": "human",
            "principalState": "active",
            "displayName": "Ada Lovelace",
            "role": "owner",
            "state": "active"
        },
        {
            "id": "mem_service",
            "principalId": "prn_service",
            "principalType": "service",
            "principalState": "suspended",
            "role": "member",
            "state": "active"
        }
    ]);
    let (server, _directory, _path, credential_path) =
        prepared_organization(vec![membership_success(items, Some("next-page"))], TOKEN);
    let environment = deployment_environment(&server.api_url, &credential_path);
    let human = run_with_env(
        &[
            "org",
            "member",
            "list",
            "--org",
            "acme",
            "--allow-insecure-http",
        ],
        &environment,
    );
    assert!(human.status.success());
    assert_eq!(
        String::from_utf8(human.stdout).unwrap(),
        format!(
            concat!(
                "✓ Organization members listed.\n\n",
                "  Membership: mem_owner  Principal: prn_human  Type: human  Role: owner  Name: Ada Lovelace  State: active\n",
                "  Membership: mem_service  Principal: prn_service  Type: service  Role: member  State: active\n",
                "    Principal state: suspended\n\n",
                "  Next cursor: next-page\n",
                "  Deployment: {}\n"
            ),
            server.api_url
        )
    );
    assert!(human.stderr.is_empty());
    server.finish();

    let (server, _directory, _path, credential_path) =
        prepared_organization(vec![membership_success(serde_json::json!([]), None)], TOKEN);
    let environment = deployment_environment(&server.api_url, &credential_path);
    let empty_human = run_with_env(
        &[
            "org",
            "member",
            "list",
            "--org",
            "acme",
            "--allow-insecure-http",
        ],
        &environment,
    );
    assert!(empty_human.status.success());
    assert_eq!(
        String::from_utf8(empty_human.stdout).unwrap(),
        format!(
            "✓ Organization members listed.\n\n  Deployment: {}\n",
            server.api_url
        )
    );
    assert!(empty_human.stderr.is_empty());
    server.finish();

    let (server, _directory, _path, credential_path) =
        prepared_organization(vec![membership_success(serde_json::json!([]), None)], TOKEN);
    let environment = deployment_environment(&server.api_url, &credential_path);
    let empty = run_with_env(
        &[
            "org",
            "member",
            "list",
            "--org",
            "acme",
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );
    assert!(empty.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&empty.stdout).unwrap(),
        serde_json::json!({
            "schemaVersion": 2,
            "deployment": server.api_url,
            "outcome": "listed",
            "items": []
        })
    );
    assert!(empty.stderr.is_empty());
    server.finish();
}

#[test]
fn members_list_rejects_explicit_null_optional_fields() {
    let malformed_pages = [
        serde_json::json!({"items": [], "nextCursor": null}),
        serde_json::json!({
            "items": [{
                "id": "mem_01k0z6r1w8f4jy2m7q9v3x5abc",
                "principalId": "prn_01k0z6r1w8f4jy2m7q9v3x5abc",
                "principalType": "human",
                "displayName": null,
                "role": "member"
            }]
        }),
    ];
    let mut statuses = Vec::new();
    let mut standard_outputs = Vec::new();

    for page in malformed_pages {
        let response = json_http_response("200 OK", page);
        let (server, _directory, _path, credential_path) =
            prepared_organization(vec![response], TOKEN);
        let environment = deployment_environment(&server.api_url, &credential_path);

        let output = run_with_env(
            &[
                "org",
                "member",
                "list",
                "--org",
                "acme",
                "--json",
                "--allow-insecure-http",
            ],
            &environment,
        );
        statuses.push(output.status.code());
        standard_outputs.push(output.stdout);
        server.finish();
    }

    assert_eq!(statuses, [Some(1), Some(1)]);
    assert!(standard_outputs.iter().all(Vec::is_empty));
}

#[test]
fn membership_management_workflow_has_stable_json_and_request_contracts() {
    let history_items = membership_history_items();
    let (server, _directory, _path, credential_path) = prepared_organization(
        vec![
            membership_success(history_items.clone(), Some("next history page")),
            membership_update_success(),
            membership_termination_success(),
            membership_termination_success(),
        ],
        TOKEN,
    );
    let environment = deployment_environment(&server.api_url, &credential_path);

    let history = run_with_env(
        &[
            "org",
            "member",
            "event",
            "list",
            "--org",
            "acme-research",
            "--limit",
            "6",
            "--cursor",
            "opaque /+=?&",
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );
    assert!(history.status.success());
    let mut expected_history = history_items;
    expected_history[0]
        .as_object_mut()
        .unwrap()
        .remove("future");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&history.stdout).unwrap(),
        serde_json::json!({
            "schemaVersion": 2,
            "deployment": server.api_url,
            "outcome": "listed",
            "items": expected_history,
            "nextCursor": "next history page"
        })
    );
    assert!(history.stderr.is_empty());

    let update = run_with_env(
        &[
            "org",
            "member",
            "update",
            "--org",
            "acme-research",
            "mem_01k0z6r1w8f4jy2m7q9v3x5abc",
            "--role",
            "member",
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );
    assert!(update.status.success());
    let update_json: serde_json::Value = serde_json::from_slice(&update.stdout).unwrap();
    assert_eq!(update_json["schemaVersion"], 1);
    assert_eq!(update_json["deployment"], server.api_url);
    assert_eq!(update_json["outcome"], "updated");
    assert_eq!(update_json["membership"]["role"], "member");
    assert_eq!(update_json["membership"]["state"], "active");
    assert!(update.stderr.is_empty());

    let remove = run_with_env(
        &[
            "org",
            "member",
            "remove",
            "--org",
            "acme-research",
            "mem_01k0z6r1w8f4jy2m7q9v3x5abd",
            "--yes",
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );
    assert!(remove.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&remove.stdout).unwrap(),
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "outcome": "removed",
            "organization": "acme-research",
            "membershipId": "mem_01k0z6r1w8f4jy2m7q9v3x5abd"
        })
    );
    assert!(remove.stderr.is_empty());

    let leave = run_with_env(
        &[
            "org",
            "leave",
            "acme-research",
            "--yes",
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );
    assert!(leave.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&leave.stdout).unwrap(),
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "outcome": "left",
            "organization": "acme-research"
        })
    );
    assert!(leave.stderr.is_empty());

    let requests = server.finish();
    assert_eq!(requests.len(), 4);
    assert!(requests[0].starts_with(
        "GET /api/v1/organizations/acme-research/memberships/history?limit=6&cursor=opaque+%2F%2B%3D%3F%26 HTTP/1.1\r\n"
    ));
    assert!(requests[1].starts_with(
        "PATCH /api/v1/organizations/acme-research/memberships/mem_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1\r\n"
    ));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request_body(&requests[1])).unwrap(),
        serde_json::json!({"role": "member"})
    );
    assert!(requests[2].starts_with(
        "DELETE /api/v1/organizations/acme-research/memberships/mem_01k0z6r1w8f4jy2m7q9v3x5abd HTTP/1.1\r\n"
    ));
    assert!(
        requests[3]
            .starts_with("DELETE /api/v1/organizations/acme-research/memberships/me HTTP/1.1\r\n")
    );
    for request in &requests[1..] {
        let key = header_value(request, "idempotency-key");
        assert_eq!(key.len(), 64);
        assert!(!key.is_empty());
    }
}

#[test]
fn membership_management_preserves_closed_authorization_and_conflict_outcomes() {
    let cases = [
        (
            vec![
                "org",
                "member",
                "event",
                "list",
                "--org",
                "acme",
                "--json",
                "--allow-insecure-http",
            ],
            organization_problem(
                "403 Forbidden",
                403,
                "https://api.usefulmachinery.com/problems/forbidden",
            ),
            "forbidden",
        ),
        (
            vec![
                "org",
                "member",
                "update",
                "--org",
                "acme",
                "mem_01k0z6r1w8f4jy2m7q9v3x5abc",
                "--role",
                "member",
                "--json",
                "--allow-insecure-http",
            ],
            organization_problem(
                "409 Conflict",
                409,
                "https://api.usefulmachinery.com/problems/human-owner-required",
            ),
            "human_owner_required",
        ),
        (
            vec![
                "org",
                "member",
                "remove",
                "--org",
                "acme",
                "mem_01k0z6r1w8f4jy2m7q9v3x5abc",
                "--yes",
                "--json",
                "--allow-insecure-http",
            ],
            organization_problem(
                "409 Conflict",
                409,
                "https://api.usefulmachinery.com/problems/membership-transition-unavailable",
            ),
            "transition_unavailable",
        ),
        (
            vec![
                "org",
                "leave",
                "private-target",
                "--yes",
                "--json",
                "--allow-insecure-http",
            ],
            response_with_detail("The target is inactive."),
            "not_found",
        ),
    ];

    for (args, response, expected_outcome) in cases {
        let (server, _directory, _path, credential_path) =
            prepared_organization(vec![response], TOKEN);
        let environment = deployment_environment(&server.api_url, &credential_path);

        let output = run_with_env(&args, &environment);

        assert_eq!(output.status.code(), Some(1));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["deployment"], server.api_url);
        assert_eq!(value["outcome"], expected_outcome);
        assert!(value.get("title").is_none());
        assert!(value.get("detail").is_none());
        assert!(output.stderr.is_empty());
        assert_eq!(server.finish().len(), 1);
    }
}

#[test]
fn membership_management_human_reports_use_the_expected_streams() {
    let (server, _directory, _path, credential_path) = prepared_organization(
        vec![membership_success(membership_history_items(), None)],
        TOKEN,
    );
    let environment = deployment_environment(&server.api_url, &credential_path);

    let history = run_with_env(
        &[
            "org",
            "member",
            "event",
            "list",
            "--org",
            "acme",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert!(
        history.status.success(),
        "{}",
        String::from_utf8_lossy(&history.stderr)
    );
    let report = String::from_utf8(history.stdout).unwrap();
    assert!(report.contains("membership: mem_01k0z6r1w8f4jy2m7q9v3x5abd"));
    assert!(report.contains("principal: prn_01k0z6r1w8f4jy2m7q9v3x5abd · type: service"));
    assert!(report.contains("role: member · state: ended"));
    assert!(report.contains("terminal: 2026-07-29T12:02:00Z"));
    assert!(report.contains("name: At departure"));
    assert!(report.contains("name: missing"));
    assert!(report.contains("name: unavailable"));
    assert!(report.contains("principal: unavailable · type: human"));
    assert!(report.contains("first@example.test (unverified)"));
    assert!(report.contains("second@example.test (verification unknown)"));
    assert!(report.contains("then@example.test (unverified)"));
    assert!(report.contains("unknown@example.test (verification unknown)"));
    assert!(history.stderr.is_empty());
    server.finish();

    let response = organization_problem(
        "409 Conflict",
        409,
        "https://api.usefulmachinery.com/problems/human-owner-required",
    );
    let (server, _directory, _path, credential_path) = prepared_organization(vec![response], TOKEN);
    let environment = deployment_environment(&server.api_url, &credential_path);
    let rejected = run_with_env(
        &[
            "org",
            "member",
            "update",
            "--org",
            "acme",
            "mem_01k0z6r1w8f4jy2m7q9v3x5abc",
            "--role",
            "member",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert_eq!(rejected.status.code(), Some(1));
    assert!(rejected.stdout.is_empty());
    let diagnostic = String::from_utf8(rejected.stderr).unwrap();
    assert!(diagnostic.starts_with("error: "));
    assert!(diagnostic.contains("\n\n"));
    assert!(!diagnostic.contains("organization-problem-detail-sentinel"));
    server.finish();
}

#[test]
fn organization_member_remove_rejects_self_route_alias() {
    let output = run_with_env(
        &[
            "org",
            "member",
            "remove",
            "--org",
            "acme",
            "me",
            "--yes",
            "--json",
            "--allow-insecure-http",
        ],
        &[("USEFUL_API_URL", "partial-override-must-not-load")],
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn terminal_membership_commands_require_explicit_confirmation() {
    for args in [
        &[
            "org",
            "member",
            "remove",
            "--org",
            "acme",
            "mem_01k0z6r1w8f4jy2m7q9v3x5abc",
        ][..],
        &["org", "leave", "acme"][..],
    ] {
        let output = run_with_env(
            args,
            &[("USEFUL_API_URL", "partial-override-must-not-load")],
        );

        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn organization_commands_report_missing_credentials_without_network_requests() {
    for args in [
        &[
            "org",
            "update",
            "acme",
            "--slug",
            "acme-labs",
            "--json",
            "--allow-insecure-http",
        ][..],
        &["org", "list", "--json", "--allow-insecure-http"][..],
        &[
            "org",
            "member",
            "list",
            "--org",
            "acme",
            "--json",
            "--allow-insecure-http",
        ][..],
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let api_url = format!("http://{}/api", listener.local_addr().unwrap());
        let directory = private_credential_directory();
        let credential_path = directory.path().join("credentials.json");
        let environment = deployment_environment(&api_url, credential_path.to_str().unwrap());

        let output = run_with_env(args, &environment);

        assert_eq!(output.status.code(), Some(3));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            serde_json::json!({
                "schemaVersion": 1,
                "deployment": api_url,
                "outcome": "unauthenticated"
            })
        );
        assert!(output.stderr.is_empty());
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
}

#[test]
fn organization_commands_keep_private_not_found_outputs_identical() {
    for base_args in [
        &[
            "org",
            "update",
            "private-target",
            "--slug",
            "still-private",
            "--allow-insecure-http",
        ][..],
        &[
            "org",
            "member",
            "list",
            "--org",
            "private-target",
            "--allow-insecure-http",
        ][..],
        &["org", "show", "private-target", "--allow-insecure-http"][..],
    ] {
        for json in [false, true] {
            let responses = [
                "The target is inaccessible.",
                "The target is inactive.",
                "The target is absent.",
            ]
            .map(response_with_detail)
            .into_iter()
            .collect();
            let (server, _directory, _path, credential_path) =
                prepared_organization(responses, TOKEN);
            let environment = deployment_environment(&server.api_url, &credential_path);
            let mut outputs = Vec::new();

            for _ in 0..3 {
                let mut args = base_args.to_vec();
                if json {
                    args.push("--json");
                }
                let output = run_with_env(&args, &environment);
                assert_eq!(output.status.code(), Some(1));
                assert!(output.stderr.is_empty());
                if !json {
                    assert!(!output.stdout.is_empty());
                }
                outputs.push(output.stdout);
            }
            assert_eq!(outputs[0], outputs[1]);
            assert_eq!(outputs[1], outputs[2]);
            assert_eq!(server.finish().len(), 3);
        }
    }
}

pub(super) const IN_EFFECT_ID: &str = "org_01k0z6r1w8f4jy2m7q9v3x5abc";
pub(super) const OTHER_IN_EFFECT_ID: &str = "org_01k0z6r1w8f4jy2m7q9v3x5abd";
pub(super) const LIST_CURRENT_MEMBERSHIPS: &str =
    "GET /api/v1/me/memberships?limit=200 HTTP/1.1\r\n";

pub(super) fn active_memberships(organizations: &[(&str, &str)]) -> Vec<u8> {
    let items = organizations
        .iter()
        .enumerate()
        .map(|(index, (organization_id, slug))| {
            serde_json::json!({
                "id": format!("mem_01k0z6r1w8f4jy2m7q9v3x5ab{}", ["c", "d", "e"][index]),
                "organizationId": organization_id,
                "organizationState": "active",
                "organizationDisplayName": slug,
                "organizationSlug": slug,
                "role": "owner",
                "state": "active",
                "createdAt": "2026-07-22T20:32:00Z",
                "updatedAt": "2026-07-23T10:00:00Z"
            })
        })
        .collect();
    membership_success(serde_json::Value::Array(items), None)
}

pub(super) fn projects_of(organization_id: &str, project_id: &str, full_name: &str) -> Vec<u8> {
    json_http_response(
        "200 OK",
        serde_json::json!({
            "items": [{
                "id": project_id,
                "organizationId": organization_id,
                "name": "widgets",
                "runnerPool": {"id": "rpl_01k0z6r1w8f4jy2m7q9v3x5abc", "name": "builders"},
                "repository": {
                    "connectionId": "rpc_01k0z6r1w8f4jy2m7q9v3x5abc",
                    "providerKind": "github",
                    "installationBindingId": "ghi_01k0z6r1w8f4jy2m7q9v3x5abc",
                    "providerRepositoryId": "123456789",
                    "fullName": full_name,
                    "defaultBranch": "main",
                    "availability": "active"
                },
                "executionReadiness": {"ready": true, "blockers": []},
                "createdAt": "2026-09-05T12:00:00Z",
                "updatedAt": "2026-09-05T12:01:00Z"
            }]
        }),
    )
}

/// A `git` whose working directory is a checkout of `Acme/Widgets` on GitHub, passed as `PATH`.
pub(super) fn acme_widgets_checkout() -> tempfile::TempDir {
    fake_git(
        "if [ \"$1 $2\" = 'remote -v' ]; then\n\
         printf 'origin\\tgit@github.com:Acme/Widgets.git (fetch)\\norigin\\tgit@github.com:Acme/Widgets.git (push)\\n'\n\
         else exit 1; fi",
    )
}

pub(super) fn request_lines(requests: &[String]) -> Vec<&str> {
    requests
        .iter()
        .map(|request| request.split_once("\r\n").unwrap().0)
        .collect()
}

fn in_effect_members_list(
    responses: Vec<Vec<u8>>,
    arguments: &[&str],
    environment: &[(&str, &str)],
) -> (Output, Vec<String>) {
    run_in_effect(
        &["org", "member", "list", "--json"],
        responses,
        arguments,
        environment,
    )
}

pub(super) fn run_in_effect(
    command: &[&str],
    responses: Vec<Vec<u8>>,
    arguments: &[&str],
    environment: &[(&str, &str)],
) -> (Output, Vec<String>) {
    let (server, _directory, _path, credential_path) = prepared_organization(responses, TOKEN);
    let mut variables = deployment_environment(&server.api_url, &credential_path).to_vec();
    variables.extend_from_slice(environment);
    let mut args = command.to_vec();
    args.push("--allow-insecure-http");
    args.extend_from_slice(arguments);
    let output = run_with_env(&args, &variables);
    (output, server.finish())
}

#[test]
fn the_variable_names_the_organization_in_effect_without_another_request() {
    let (output, requests) = in_effect_members_list(
        vec![membership_success(serde_json::json!([]), None)],
        &[],
        &[("USEFUL_ORG", "acme")],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        request_lines(&requests),
        ["GET /api/v1/organizations/acme/memberships HTTP/1.1"]
    );
}

#[test]
fn the_option_wins_over_the_variable() {
    let (output, requests) = in_effect_members_list(
        vec![membership_success(serde_json::json!([]), None)],
        &["--org", "other"],
        &[("USEFUL_ORG", "acme")],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        request_lines(&requests),
        ["GET /api/v1/organizations/other/memberships HTTP/1.1"]
    );
}

#[test]
fn the_only_active_membership_names_the_organization_in_effect_by_its_id() {
    let (output, requests) = in_effect_members_list(
        vec![
            active_memberships(&[(IN_EFFECT_ID, "acme")]),
            membership_success(serde_json::json!([]), None),
        ],
        &[],
        &[],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        request_lines(&requests),
        [
            LIST_CURRENT_MEMBERSHIPS.trim_end(),
            &format!("GET /api/v1/organizations/{IN_EFFECT_ID}/memberships HTTP/1.1"),
        ]
    );
}

#[test]
fn several_memberships_and_no_checkout_name_no_organization_and_change_nothing() {
    let (output, requests) = in_effect_members_list(
        vec![active_memberships(&[
            (IN_EFFECT_ID, "acme"),
            (OTHER_IN_EFFECT_ID, "dunder"),
        ])],
        &[],
        &[],
    );

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    for named in ["--org", "acme", "dunder"] {
        assert!(stderr.contains(named), "{stderr}");
    }
    assert_eq!(
        request_lines(&requests),
        [LIST_CURRENT_MEMBERSHIPS.trim_end()]
    );
}

#[test]
fn the_checkout_names_the_organization_of_the_one_project_its_remote_names() {
    let git = acme_widgets_checkout();
    let path = git.path().to_str().unwrap();
    let (output, requests) = in_effect_members_list(
        vec![
            active_memberships(&[(OTHER_IN_EFFECT_ID, "dunder"), (IN_EFFECT_ID, "acme")]),
            projects_of(
                OTHER_IN_EFFECT_ID,
                "prj_01k0z6r1w8f4jy2m7q9v3x5abd",
                "dunder/paper",
            ),
            projects_of(
                IN_EFFECT_ID,
                "prj_01k0z6r1w8f4jy2m7q9v3x5abc",
                "acme/widgets",
            ),
            membership_success(serde_json::json!([]), None),
        ],
        &[],
        &[("PATH", path)],
    );

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        request_lines(&requests),
        [
            LIST_CURRENT_MEMBERSHIPS.trim_end(),
            &format!("GET /api/v1/organizations/{OTHER_IN_EFFECT_ID}/projects HTTP/1.1"),
            &format!("GET /api/v1/organizations/{IN_EFFECT_ID}/projects HTTP/1.1"),
            &format!("GET /api/v1/organizations/{IN_EFFECT_ID}/memberships HTTP/1.1"),
        ]
    );
}

#[test]
fn commands_that_change_an_organization_take_it_only_as_their_argument() {
    for args in [
        &["org", "leave", "--yes", "--allow-insecure-http"][..],
        &["org", "update", "--name", "X", "--allow-insecure-http"][..],
    ] {
        let server = ScriptedServer::respond(Vec::new());
        let directory = private_credential_directory();
        let credential_path = directory.path().join("credentials.json");
        let mut environment =
            deployment_environment(&server.api_url, credential_path.to_str().unwrap()).to_vec();
        environment.push(("USEFUL_ORG", "acme"));

        let output = run_with_env(args, &environment);

        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
        assert!(server.finish().is_empty(), "{args:?}");
    }
}

#[test]
fn show_without_an_argument_shows_the_organization_in_effect() {
    let (server, _directory, _path, credential_path) =
        prepared_organization(vec![organization_success("200 OK")], TOKEN);
    let mut environment = deployment_environment(&server.api_url, &credential_path).to_vec();
    environment.push(("USEFUL_ORG", "acme-research"));

    let output = run_with_env(
        &["org", "show", "--json", "--allow-insecure-http"],
        &environment,
    );

    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["outcome"], "found");
    assert_eq!(
        request_lines(&server.finish()),
        ["GET /api/v1/organizations/acme-research HTTP/1.1"]
    );

    let server = ScriptedServer::respond(Vec::new());
    let environment = deployment_environment(&server.api_url, &credential_path);
    let output = run_with_env(
        &[
            "org",
            "show",
            "acme-research",
            "--org",
            "other",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(server.finish().is_empty());
}

const LIST_MEMBERSHIP_PAGE: &str = "GET /api/v1/me/memberships HTTP/1.1";
// The prefix of the field that marks the membership of the organization in effect, and of the
// line after a page that does not hold it.
const ROW_MARKER: &str = "in effect:";
const PAGE_MARKER: &str = "organization in effect:";

fn org_list(
    responses: Vec<Vec<u8>>,
    arguments: &[&str],
    environment: &[(&str, &str)],
) -> (Output, Vec<String>) {
    run_in_effect(&["org", "list"], responses, arguments, environment)
}

fn listed_document(output: &Output) -> serde_json::Value {
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["outcome"], "listed");
    value
}

/// The lines of the human page's row for `membership`.
fn listed_row<'a>(stdout: &'a str, membership: &str) -> Vec<&'a str> {
    stdout
        .split("\n\n")
        .find(|row| {
            row.lines()
                .any(|line| line.starts_with(&format!("membership: {membership} ")))
        })
        .unwrap_or_else(|| panic!("no row for {membership} in {stdout}"))
        .lines()
        .collect()
}

#[test]
fn org_list_names_the_organization_the_variable_gave_without_another_request() {
    let (output, requests) = org_list(
        vec![active_memberships(&[
            (IN_EFFECT_ID, "acme-research"),
            (OTHER_IN_EFFECT_ID, "dunder"),
        ])],
        &["--json"],
        &[("USEFUL_ORG", "acme-research")],
    );

    let value = listed_document(&output);
    assert_eq!(
        value["organizationInEffect"],
        serde_json::json!({"organization": "acme-research", "source": "environment"})
    );
    assert_eq!(value["items"].as_array().unwrap().len(), 2);
    assert_eq!(request_lines(&requests), [LIST_MEMBERSHIP_PAGE]);
}

#[test]
fn org_list_marks_the_membership_of_the_organization_the_option_names() {
    let page = || {
        active_memberships(&[
            (IN_EFFECT_ID, "acme-research"),
            (OTHER_IN_EFFECT_ID, "dunder"),
        ])
    };
    let (output, requests) = org_list(
        vec![page()],
        &["--org", IN_EFFECT_ID, "--json"],
        &[("USEFUL_ORG", "dunder")],
    );

    assert_eq!(
        listed_document(&output)["organizationInEffect"],
        serde_json::json!({"organization": IN_EFFECT_ID, "source": "flag"})
    );
    assert_eq!(request_lines(&requests), [LIST_MEMBERSHIP_PAGE]);

    let (output, requests) = org_list(vec![page()], &["--org", IN_EFFECT_ID], &[]);

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let marked = listed_row(&stdout, "mem_01k0z6r1w8f4jy2m7q9v3x5abc");
    assert!(
        marked
            .iter()
            .any(|line| line.starts_with(ROW_MARKER) && line.contains("flag")),
        "{stdout}"
    );
    let other = listed_row(&stdout, "mem_01k0z6r1w8f4jy2m7q9v3x5abd");
    assert!(!other.iter().any(|line| line.starts_with(ROW_MARKER)));
    assert!(!stdout.lines().any(|line| line.starts_with(PAGE_MARKER)));
    assert_eq!(request_lines(&requests), [LIST_MEMBERSHIP_PAGE]);
}

#[test]
fn org_list_names_the_only_active_membership_from_the_page_it_shows() {
    let (output, requests) = org_list(
        vec![active_memberships(&[(IN_EFFECT_ID, "acme-research")])],
        &["--json"],
        &[],
    );

    assert_eq!(
        listed_document(&output)["organizationInEffect"],
        serde_json::json!({"organization": IN_EFFECT_ID, "source": "only_membership"})
    );
    assert_eq!(request_lines(&requests), [LIST_MEMBERSHIP_PAGE]);
}

#[test]
fn org_list_with_no_organization_in_effect_prints_its_page_and_does_not_fail() {
    let page = || {
        active_memberships(&[
            (IN_EFFECT_ID, "acme-research"),
            (OTHER_IN_EFFECT_ID, "dunder"),
        ])
    };
    let (output, requests) = org_list(vec![page()], &["--json"], &[]);

    let value = listed_document(&output);
    assert!(value.get("organizationInEffect").is_none(), "{value}");
    assert_eq!(value["items"].as_array().unwrap().len(), 2);
    assert_eq!(request_lines(&requests), [LIST_MEMBERSHIP_PAGE]);

    let (output, _) = org_list(vec![page()], &[], &[]);

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    for membership in [
        "mem_01k0z6r1w8f4jy2m7q9v3x5abc",
        "mem_01k0z6r1w8f4jy2m7q9v3x5abd",
    ] {
        let row = listed_row(&stdout, membership);
        assert!(!row.iter().any(|line| line.starts_with(ROW_MARKER)));
    }
    assert!(
        stdout.lines().any(|line| line.starts_with(PAGE_MARKER)),
        "{stdout}"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn org_list_reports_an_unusable_variable_and_still_prints_its_page() {
    let (output, requests) = org_list(
        vec![active_memberships(&[
            (IN_EFFECT_ID, "acme-research"),
            (OTHER_IN_EFFECT_ID, "dunder"),
        ])],
        &["--json"],
        &[("USEFUL_ORG", "not an organization")],
    );

    let value = listed_document(&output);
    assert!(value.get("organizationInEffect").is_none(), "{value}");
    assert_eq!(value["items"].as_array().unwrap().len(), 2);
    assert_eq!(request_lines(&requests), [LIST_MEMBERSHIP_PAGE]);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("USEFUL_ORG"), "{stderr}");
}

const PAM_MEMBERSHIP: &str = "mem_01k0z6r1w8f4jy2m7q9v3x5abc";
const COLLEAGUE_MEMBERSHIP: &str = "mem_01k0z6r1w8f4jy2m7q9v3x5abd";
const SERVICE_MEMBERSHIP: &str = "mem_01k0z6r1w8f4jy2m7q9v3x5abe";
const ACME_DIRECTORY: &str = "GET /api/v1/organizations/acme/memberships?limit=200 HTTP/1.1";

/// A human's row of the organization's directory; `linked_emails` is absent, as for a reader
/// who is not an owner, when `None`.
pub(super) fn human_row(
    membership: &str,
    linked_emails: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut row = serde_json::json!({
        "id": membership,
        "principalId": membership.replacen("mem_", "prn_", 1),
        "principalType": "human",
        "principalState": "active",
        "displayName": "Pam Beesly",
        "role": "member",
        "state": "active"
    });
    if let Some(linked_emails) = linked_emails {
        row["linkedEmails"] = linked_emails;
    }
    row
}

fn service_row() -> serde_json::Value {
    serde_json::json!({
        "id": SERVICE_MEMBERSHIP,
        "principalId": "prn_01k0z6r1w8f4jy2m7q9v3x5abe",
        "principalType": "service",
        "principalState": "active",
        "role": "member",
        "state": "active"
    })
}

/// The directory as an owner reads it: Pam holds `pam@example.test` verified, and a colleague
/// holds it unverified beside a verified address of her own.
fn owner_directory() -> Vec<u8> {
    membership_success(
        serde_json::json!([
            human_row(
                COLLEAGUE_MEMBERSHIP,
                Some(serde_json::json!([
                    {"email": "pam@example.test", "verified": false},
                    {"email": "angela@example.test", "verified": true}
                ]))
            ),
            service_row(),
            human_row(
                PAM_MEMBERSHIP,
                Some(serde_json::json!([{"email": "pam@example.test", "verified": true}]))
            ),
        ]),
        None,
    )
}

fn json_outcome(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| panic!("{error}: {output:?}"))
}

#[test]
fn member_update_sends_the_role_change_to_the_one_member_holding_the_address_verified() {
    let first_page = membership_success(
        serde_json::json!([
            human_row(
                COLLEAGUE_MEMBERSHIP,
                Some(serde_json::json!([{"email": "pam@example.test", "verified": false}]))
            ),
            service_row(),
        ]),
        Some("second page"),
    );
    let second_page = membership_success(
        serde_json::json!([human_row(
            PAM_MEMBERSHIP,
            Some(serde_json::json!([{"email": "pam@example.test", "verified": true}]))
        )]),
        None,
    );
    let (output, requests) = run_in_effect(
        &["org", "member", "update", "Pam@Example.test"],
        vec![first_page, second_page, membership_update_success()],
        &["--org", "acme", "--role", "owner", "--json"],
        &[],
    );

    assert!(output.status.success(), "{output:?}");
    let value = json_outcome(&output);
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["outcome"], "updated");
    assert_eq!(value["membership"]["id"], PAM_MEMBERSHIP);
    assert_eq!(
        request_lines(&requests),
        [
            ACME_DIRECTORY,
            "GET /api/v1/organizations/acme/memberships?limit=200&cursor=second+page HTTP/1.1",
            &format!("PATCH /api/v1/organizations/acme/memberships/{PAM_MEMBERSHIP} HTTP/1.1"),
        ]
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request_body(&requests[2])).unwrap(),
        serde_json::json!({"role": "owner"})
    );
    assert_eq!(header_value(&requests[2], "idempotency-key").len(), 64);
}

#[test]
fn member_remove_ends_the_membership_of_the_member_holding_the_address_verified() {
    let (output, requests) = run_in_effect(
        &["org", "member", "remove", "pam@example.test"],
        vec![owner_directory(), membership_termination_success()],
        &["--org", "acme", "--yes", "--json"],
        &[],
    );

    assert!(output.status.success(), "{output:?}");
    let value = json_outcome(&output);
    assert_eq!(
        value,
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": value["deployment"],
            "outcome": "removed",
            "organization": "acme",
            "membershipId": PAM_MEMBERSHIP
        })
    );
    assert_eq!(
        request_lines(&requests),
        [
            ACME_DIRECTORY,
            &format!("DELETE /api/v1/organizations/acme/memberships/{PAM_MEMBERSHIP} HTTP/1.1"),
        ]
    );
}

/// Runs `org member update ADDRESS` and `org member remove ADDRESS` against `directory` and
/// returns each output with the requests its server received.
fn change_by_address(address: &str, directory: impl Fn() -> Vec<u8>) -> Vec<(Output, Vec<String>)> {
    [
        (
            &["org", "member", "update", address][..],
            &["--org", "acme", "--role", "owner", "--json"][..],
        ),
        (
            &["org", "member", "remove", address][..],
            &["--org", "acme", "--yes", "--json"][..],
        ),
    ]
    .into_iter()
    .map(|(command, arguments)| run_in_effect(command, vec![directory()], arguments, &[]))
    .collect()
}

#[test]
fn an_address_no_member_holds_verified_is_not_found_and_changes_nothing() {
    for address in ["pam@example.test", "nobody@example.test"] {
        let directory = || {
            membership_success(
                serde_json::json!([
                    human_row(
                        COLLEAGUE_MEMBERSHIP,
                        Some(serde_json::json!([{"email": "pam@example.test", "verified": false}]))
                    ),
                    human_row(
                        PAM_MEMBERSHIP,
                        Some(serde_json::json!([{"email": "pam@example.test"}]))
                    ),
                ]),
                None,
            )
        };
        for (output, requests) in change_by_address(address, directory) {
            assert_eq!(output.status.code(), Some(1), "{address}: {output:?}");
            assert_eq!(json_outcome(&output)["outcome"], "not_found");
            assert_eq!(request_lines(&requests), [ACME_DIRECTORY]);
        }
    }
}

#[test]
fn a_directory_that_shows_no_addresses_is_forbidden_and_changes_nothing() {
    let directory = || {
        membership_success(
            serde_json::json!([human_row(PAM_MEMBERSHIP, None), service_row()]),
            None,
        )
    };
    for (output, requests) in change_by_address("pam@example.test", directory) {
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert_eq!(json_outcome(&output)["outcome"], "forbidden");
        assert_eq!(request_lines(&requests), [ACME_DIRECTORY]);
    }
}

#[test]
fn an_address_two_members_hold_verified_is_refused_naming_both() {
    let directory = || {
        membership_success(
            serde_json::json!([
                human_row(
                    COLLEAGUE_MEMBERSHIP,
                    Some(serde_json::json!([{"email": "PAM@example.test", "verified": true}]))
                ),
                human_row(
                    PAM_MEMBERSHIP,
                    Some(serde_json::json!([{"email": "pam@example.test", "verified": true}]))
                ),
            ]),
            None,
        )
    };
    for (output, requests) in change_by_address("pam@example.test", directory) {
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        for membership in [COLLEAGUE_MEMBERSHIP, PAM_MEMBERSHIP] {
            assert!(stderr.contains(membership), "{stderr}");
        }
        assert_eq!(request_lines(&requests), [ACME_DIRECTORY]);
    }
}
