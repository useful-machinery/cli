use super::*;

const TOKEN: &str = "unique-github-command-token-sentinel";
const ORGANIZATION: &str = "acme-research";
const SETUP_SESSION: &str = "ghs_01k0z6r1w8f4jy2m7q9v3x5abc";
const INSTALLATION: &str = "ghi_01k0z6r1w8f4jy2m7q9v3x5abc";

fn prepared_github(responses: Vec<Vec<u8>>) -> (ScriptedServer, tempfile::TempDir, String) {
    let server = ScriptedServer::respond(responses);
    let credential_directory = private_credential_directory();
    let credential_path = credential_directory.path().join("credentials.json");
    write_credential_fixture(
        &credential_path,
        &server.api_url,
        TOKEN,
        "2999-01-01T00:00:00Z",
    );
    let credential_path = credential_path.to_string_lossy().into_owned();
    (server, credential_directory, credential_path)
}

/// The GitHub App installation page a setup session hands the browser to.
fn setup_url() -> String {
    format!("https://github.example/apps/scherzo/installations/new?state={SETUP_SESSION}")
}

/// A setup session as `setup begin` is answered it, with a member the contract does not name.
pub(super) fn setup_session() -> serde_json::Value {
    serde_json::json!({
        "id": SETUP_SESSION,
        "state": "pending",
        "expiresAt": "2026-09-05T12:10:00Z",
        "setupUrl": setup_url(),
        "future": "setup-response-sentinel"
    })
}

pub(super) fn installation_body(state: &str) -> serde_json::Value {
    serde_json::json!({
        "id": INSTALLATION,
        "providerInstallationId": "713",
        "providerAccountId": "829",
        "providerAccountLogin": "acme",
        "providerAccountType": "Organization",
        "state": state,
        "createdAt": "2026-09-05T12:00:00Z",
        "updatedAt": "2026-09-05T12:01:00Z",
        "future": { "omitted": true }
    })
}

fn github_problem(status_text: &str, status: u16, problem_type: &str) -> Vec<u8> {
    problem_http_response(
        status_text,
        serde_json::json!({
            "type": problem_type,
            "title": "private-github-title-sentinel",
            "status": status,
            "detail": "private-github-proof-sentinel"
        }),
    )
}

fn request_body(request: &str) -> &str {
    request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("request should contain a body separator")
}

// REQ-CONNECTION-88
#[test]
fn removed_top_level_github_family_is_a_usage_error_without_contacting_the_deployment() {
    let (server, _directory, credential_path) = prepared_github(Vec::new());
    let environment = deployment_environment(&server.api_url, &credential_path);

    for args in [
        &["github"][..],
        &["github", "installation", "list", ORGANIZATION][..],
        &[
            "github",
            "setup",
            "begin",
            ORGANIZATION,
            "--allow-insecure-http",
        ][..],
        &[
            "connection",
            "github",
            "setup",
            "begin",
            ORGANIZATION,
            "--allow-insecure-http",
        ][..],
        &["connection", "github", "installation", "list", ORGANIZATION][..],
    ] {
        let output = run_with_env(args, &environment);

        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(!output.stderr.is_empty(), "{args:?}");
    }
    assert!(server.finish().is_empty());
}

/// A response beginning the setup session `id`, whose page is `setup_url`.
pub(super) fn setup_session_response(id: &str, setup_url: &str) -> Vec<u8> {
    let mut session = setup_session();
    session["id"] = id.into();
    session["setupUrl"] = setup_url.into();
    json_http_response("201 Created", session)
}

/// `useful org integration ARGS... --org ORGANIZATION --allow-insecure-http`.
fn org_connection<'a>(args: &[&'a str]) -> Vec<&'a str> {
    ["org", "integration"]
        .into_iter()
        .chain(args.iter().copied())
        .chain(["--org", ORGANIZATION, "--allow-insecure-http"])
        .collect()
}

// REQ-CONNECTION-16, REQ-CONNECTION-17, REQ-INTEGRATION-21, REQ-INTEGRATION-59
#[test]
fn create_github_prints_the_page_and_then_completes_for_the_installation_alone() {
    let setup_url = setup_url();
    let second_session = "ghs_01k0z6r1w8f4jy2m7q9v3x5abd";
    let mut installation = installation_body("active");
    installation["providerInstallationId"] = serde_json::Value::String("714".to_owned());
    let (server, _directory, credential_path) = prepared_github(vec![
        setup_session_response(SETUP_SESSION, &setup_url),
        setup_session_response(second_session, &setup_url),
        json_http_response("200 OK", installation),
    ]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let begin = run_with_env(&org_connection(&["connect", "github"]), &environment);

    assert!(begin.status.success(), "{begin:?}");
    let human = String::from_utf8(begin.stdout).unwrap();
    assert!(human.starts_with("✓ GitHub setup started.\n"));
    assert!(human.contains(&format!("  {setup_url}\n")));
    assert!(human.contains(&format!(
        "\n  useful org integration connect github --installation <INSTALLATION_ID> --org {ORGANIZATION}\n"
    )));
    // The second invocation needs nothing from the first, so no session is printed to type.
    assert!(!human.replace(&setup_url, "").contains(SETUP_SESSION));
    assert!(!human.contains("setup-response-sentinel"));
    assert!(begin.stderr.is_empty());

    let complete = run_with_env(
        &org_connection(&["connect", "github", "--installation", "714", "--json"]),
        &environment,
    );

    assert!(complete.status.success(), "{complete:?}");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&complete.stdout).unwrap(),
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "organizationRef": ORGANIZATION,
            "outcome": "completed",
            "installation": {
                "id": INSTALLATION,
                "providerInstallationId": "714",
                "providerAccountId": "829",
                "providerAccountLogin": "acme",
                "providerAccountType": "Organization",
                "state": "active",
                "createdAt": "2026-09-05T12:00:00Z",
                "updatedAt": "2026-09-05T12:01:00Z"
            }
        })
    );
    assert!(complete.stdout.ends_with(b"\n"));
    assert!(complete.stderr.is_empty());

    let requests = server.finish();
    assert_eq!(requests.len(), 3);
    for request in &requests[..2] {
        assert!(request.starts_with(&format!(
            "POST /api/v1/organizations/{ORGANIZATION}/github/setup-sessions HTTP/1.1\r\n"
        )));
        assert!(request_body(request).is_empty());
    }
    assert!(requests[2].starts_with(&format!(
        "POST /api/v1/organizations/{ORGANIZATION}/github/setup-sessions/{second_session}/completion HTTP/1.1\r\n"
    )));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request_body(&requests[2])).unwrap(),
        serde_json::json!({"providerInstallationId": "714"})
    );
    for request in requests {
        assert_eq!(
            header_value(&request, "authorization"),
            format!("Bearer {TOKEN}")
        );
        assert!(useful_test_support::request_header(&request, "idempotency-key").is_none());
    }
}

// REQ-CONNECTION-17
#[test]
fn create_github_with_a_failed_begin_sends_no_completion() {
    let (server, _directory, credential_path) = prepared_github(vec![github_problem(
        "403 Forbidden",
        403,
        "https://api.usefulmachinery.com/problems/forbidden",
    )]);

    let output = run_with_env(
        &org_connection(&["connect", "github", "--installation", "714", "--json"]),
        &deployment_environment(&server.api_url, &credential_path),
    );

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["outcome"], "forbidden");
    assert_eq!(server.finish().len(), 1);
}

/// The organization's list of bindings holding `installation` alone.
pub(super) fn installation_list(installation: serde_json::Value) -> Vec<u8> {
    json_http_response("200 OK", serde_json::json!({"items": [installation]}))
}

// REQ-CONNECTION-108, REQ-CONNECTION-6
#[test]
fn reconnect_of_a_disconnected_binding_completes_a_session_for_its_own_installation() {
    let setup_url =
        format!("https://github.example/apps/scherzo/installations/new?state={SETUP_SESSION}");
    let (server, _directory, credential_path) = prepared_github(vec![
        installation_list(installation_body("disconnected")),
        setup_session_response(SETUP_SESSION, &setup_url),
        json_http_response("200 OK", installation_body("active")),
    ]);

    let output = run_with_env(
        &org_connection(&["reconnect", INSTALLATION, "--json"]),
        &deployment_environment(&server.api_url, &credential_path),
    );

    assert!(output.status.success(), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["outcome"], "completed");
    assert_eq!(document["installation"]["id"], INSTALLATION);
    assert_eq!(document["installation"]["state"], "active");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&setup_url));
    let requests = server.finish();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with(&format!(
        "GET /api/v1/organizations/{ORGANIZATION}/github/installations HTTP/1.1\r\n"
    )));
    assert!(requests[1].starts_with(&format!(
        "POST /api/v1/organizations/{ORGANIZATION}/github/setup-sessions HTTP/1.1\r\n"
    )));
    assert!(requests[2].starts_with(&format!(
        "POST /api/v1/organizations/{ORGANIZATION}/github/setup-sessions/{SETUP_SESSION}/completion HTTP/1.1\r\n"
    )));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request_body(&requests[2])).unwrap(),
        serde_json::json!({"providerInstallationId": "713"})
    );
}

// REQ-CONNECTION-108
#[test]
fn reconnect_of_a_completion_that_names_another_binding_is_a_protocol_failure() {
    let setup_url =
        format!("https://github.example/apps/scherzo/installations/new?state={SETUP_SESSION}");
    let mut other = installation_body("active");
    other["id"] = serde_json::Value::String("ghi_01k0z6r1w8f4jy2m7q9v3x5abd".to_owned());
    let (server, _directory, credential_path) = prepared_github(vec![
        installation_list(installation_body("disconnected")),
        setup_session_response(SETUP_SESSION, &setup_url),
        json_http_response("200 OK", other),
    ]);

    let output = run_with_env(
        &org_connection(&["reconnect", INSTALLATION, "--json"]),
        &deployment_environment(&server.api_url, &credential_path),
    );

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["outcome"], "invalid_response");
    assert_eq!(server.finish().len(), 3);
}

// REQ-CONNECTION-108, REQ-CONNECTION-10
#[test]
fn reconnect_of_a_revoked_binding_is_refused_before_any_session() {
    let (server, _directory, credential_path) = prepared_github(vec![
        installation_list(installation_body("revoked")),
        installation_list(installation_body("revoked")),
    ]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let json = run_with_env(
        &org_connection(&["reconnect", INSTALLATION, "--json"]),
        &environment,
    );

    assert_eq!(json.status.code(), Some(1), "{json:?}");
    let document: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(document["schemaVersion"], 1);
    assert_eq!(document["organizationRef"], ORGANIZATION);
    assert_eq!(document["outcome"], "source_connection_conflict");
    assert!(json.stderr.is_empty());

    let human = run_with_env(&org_connection(&["reconnect", "github"]), &environment);

    assert_eq!(human.status.code(), Some(1), "{human:?}");
    assert!(human.stdout.is_empty());
    let diagnostic = String::from_utf8(human.stderr).unwrap();
    assert!(diagnostic.starts_with("error: "));
    assert!(diagnostic.contains("\n  useful org integration connect github\n"));

    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    for request in requests {
        assert!(request.starts_with(&format!(
            "GET /api/v1/organizations/{ORGANIZATION}/github/installations HTTP/1.1\r\n"
        )));
    }
}

// REQ-CONNECTION-106
#[test]
fn options_of_another_provider_are_refused_before_any_request() {
    let (server, _directory, credential_path) = prepared_github(Vec::new());
    let environment = deployment_environment(&server.api_url, &credential_path);

    for args in [
        &["connect", "github", "--state-updates"][..],
        &["connect", "github", "--no-wait"][..],
        &["connect", "github", "--timeout", "5m"][..],
        &[
            "connect",
            "github",
            "--token-file",
            "t",
            "--kind",
            "service-account",
        ][..],
        &["connect", "linear", "--installation", "7"][..],
        &["connect", "github", "--installation", "seven"][..],
        &["reconnect", INSTALLATION, "--state-updates"][..],
        &["reconnect", INSTALLATION, "--installation", "7"][..],
    ] {
        let output = run_with_env(&org_connection(args), &environment);

        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(!output.stderr.is_empty(), "{args:?}");
    }
    assert!(server.finish().is_empty());
}

/// `useful org integration repository list INTEGRATION --json` in the organization `ORGANIZATION`.
fn list_repositories(connection: &str) -> [&str; 9] {
    [
        "org",
        "integration",
        "repository",
        "list",
        connection,
        "--org",
        ORGANIZATION,
        "--json",
        "--allow-insecure-http",
    ]
}

// REQ-CONNECTION-16, REQ-CONNECTION-73, REQ-CONNECTION-104
#[test]
fn installation_and_repository_lists_expose_current_provider_state() {
    let mut disconnected = installation_body("disconnected");
    disconnected["id"] = serde_json::Value::String("ghi_01k0z6r1w8f4jy2m7q9v3x5abd".to_owned());
    disconnected["providerInstallationId"] = serde_json::Value::String("714".to_owned());
    disconnected["providerAccountType"] = serde_json::Value::String("User".to_owned());
    let (server, _directory, credential_path) = prepared_github(vec![
        json_http_response(
            "200 OK",
            serde_json::json!({
                "items": [installation_body("active"), disconnected],
                "future": "installation-list-sentinel"
            }),
        ),
        super::connection::no_authorizations(),
        json_http_response(
            "200 OK",
            serde_json::json!({
                "installation": installation_body("active"),
                "items": [
                    {
                        "providerRepositoryId": "991",
                        "fullName": "acme/widgets",
                        "defaultBranch": "main",
                        "future": "repository-response-sentinel"
                    },
                    {
                        "providerRepositoryId": "992",
                        "fullName": "acme/services",
                        "defaultBranch": "release"
                    }
                ],
                "future": "repository-list-sentinel"
            }),
        ),
    ]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let installations = run_with_env(
        &[
            "org",
            "integration",
            "list",
            "--provider",
            "github",
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );
    assert!(installations.status.success());
    let installations_json: serde_json::Value =
        serde_json::from_slice(&installations.stdout).unwrap();
    assert_eq!(installations_json["outcome"], "listed");
    assert_eq!(installations_json["organizationRef"], ORGANIZATION);
    assert_eq!(installations_json["items"][0]["provider"], "github");
    assert_eq!(installations_json["items"][0]["state"], "active");
    assert_eq!(installations_json["items"][1]["state"], "disconnected");
    assert_eq!(
        installations_json["items"][1]["connection"]["providerAccountType"],
        "User"
    );
    assert!(!String::from_utf8_lossy(&installations.stdout).contains("sentinel"));
    assert!(installations.stderr.is_empty());

    let repositories = run_with_env(&list_repositories(INSTALLATION), &environment);
    assert!(repositories.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&repositories.stdout).unwrap(),
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "organizationRef": ORGANIZATION,
            "outcome": "listed",
            "installation": {
                "id": INSTALLATION,
                "providerInstallationId": "713",
                "providerAccountId": "829",
                "providerAccountLogin": "acme",
        "providerAccountType": "Organization",
                "state": "active",
                "createdAt": "2026-09-05T12:00:00Z",
                "updatedAt": "2026-09-05T12:01:00Z"
            },
            "items": [
                {
                    "providerRepositoryId": "991",
                    "fullName": "acme/widgets",
                    "defaultBranch": "main"
                },
                {
                    "providerRepositoryId": "992",
                    "fullName": "acme/services",
                    "defaultBranch": "release"
                }
            ]
        })
    );
    assert!(repositories.stderr.is_empty());

    let requests = server.finish();
    assert!(
        requests[0].starts_with(
            "GET /api/v1/organizations/acme-research/github/installations HTTP/1.1\r\n"
        )
    );
    // The installations' authorizations in force are read after them (REQ-INTEGRATION-34).
    assert!(requests[1].starts_with(
        "GET /api/v1/organizations/acme-research/connection-authorizations?limit=200 HTTP/1.1\r\n"
    ));
    assert!(requests[2].starts_with(&format!(
        "GET /api/v1/organizations/acme-research/github/installations/{INSTALLATION}/repositories HTTP/1.1\r\n"
    )));
}

#[test]
fn github_successes_reject_mismatched_response_subjects() {
    let mut mismatched_provider = installation_body("active");
    mismatched_provider["providerInstallationId"] = serde_json::Value::String("714".to_owned());

    let mismatched_binding_id = "ghi_01k0z6r1w8f4jy2m7q9v3x5abd";
    let mut mismatched_binding = installation_body("disconnected");
    mismatched_binding["id"] = serde_json::Value::String(mismatched_binding_id.to_owned());

    let mut mismatched_repository_binding = installation_body("active");
    mismatched_repository_binding["id"] =
        serde_json::Value::String(mismatched_binding_id.to_owned());

    let (server, _directory, credential_path) = prepared_github(vec![
        setup_session_response(SETUP_SESSION, "https://github.example/apps/scherzo"),
        json_http_response("200 OK", mismatched_provider),
        json_http_response("200 OK", mismatched_binding),
        json_http_response(
            "200 OK",
            serde_json::json!({
                "installation": mismatched_repository_binding,
                "items": []
            }),
        ),
    ]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let commands = [
        org_connection(&["connect", "github", "--installation", "713", "--json"]),
        vec![
            "org",
            "integration",
            "disconnect",
            INSTALLATION,
            "--org",
            ORGANIZATION,
            "--yes",
            "--json",
            "--allow-insecure-http",
        ],
        list_repositories(INSTALLATION).to_vec(),
    ];

    let observed = commands
        .iter()
        .map(|args| {
            let output = run_with_env(args, &environment);
            let body: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            (
                output.status.code(),
                body["outcome"].as_str().unwrap().to_owned(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(server.finish().len(), 4);
    assert_eq!(
        observed,
        vec![
            (Some(1), "invalid_response".to_owned()),
            (Some(1), "invalid_response".to_owned()),
            (Some(1), "invalid_response".to_owned()),
        ],
        "success responses must remain bound to the provider or binding ID in the request"
    );
}

// REQ-CONNECTION-19
#[test]
fn replayable_connection_mutations_retry_one_ambiguous_transport_failure() {
    let setup = || setup_session_response(SETUP_SESSION, "https://github.example/apps/scherzo");
    let cases = [
        (
            org_connection(&["connect", "github", "--installation", "713", "--json"]),
            vec![setup()],
            "active",
            "completed",
            format!(
                "POST /api/v1/organizations/{ORGANIZATION}/github/setup-sessions/{SETUP_SESSION}/completion HTTP/1.1\r\n"
            ),
        ),
        (
            org_connection(&["reconnect", INSTALLATION, "--json"]),
            vec![
                installation_list(installation_body("disconnected")),
                setup(),
            ],
            "active",
            "completed",
            format!(
                "POST /api/v1/organizations/{ORGANIZATION}/github/setup-sessions/{SETUP_SESSION}/completion HTTP/1.1\r\n"
            ),
        ),
        (
            org_connection(&["disconnect", INSTALLATION, "--yes", "--json"]),
            Vec::new(),
            "disconnected",
            "disconnected",
            format!(
                "DELETE /api/v1/organizations/{ORGANIZATION}/github/installations/{INSTALLATION} HTTP/1.1\r\n"
            ),
        ),
    ];

    for (args, leading, state, expected_outcome, expected_request) in cases {
        let before = leading.len();
        let responses = leading
            .into_iter()
            .chain([
                Vec::new(),
                json_http_response("200 OK", installation_body(state)),
            ])
            .collect();
        let (server, _directory, credential_path) = prepared_github(responses);
        let environment = deployment_environment(&server.api_url, &credential_path);

        let output = run_with_env(&args, &environment);

        assert!(output.status.success(), "{args:?}: {output:?}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["outcome"], expected_outcome);
        assert_eq!(value["installation"]["state"], state);
        assert!(output.stderr.is_empty());
        let requests = server.finish();
        assert_eq!(requests.len(), before + 2, "{args:?}");
        assert_eq!(requests[before], requests[before + 1]);
        assert!(requests[before].starts_with(&expected_request));
    }
}

// REQ-CONNECTION-19
#[test]
fn meaningful_api_failures_have_closed_json_and_exit_statuses() {
    let cases = [(
        github_problem(
            "409 Conflict",
            409,
            "https://api.usefulmachinery.com/problems/source-connection-conflict",
        ),
        list_repositories(INSTALLATION)[..7].to_vec(),
        "source_connection_conflict",
        1,
    )];

    for (response, mut args, expected_outcome, expected_status) in cases {
        let (server, _directory, credential_path) = prepared_github(vec![response]);
        let environment = deployment_environment(&server.api_url, &credential_path);
        args.extend(["--json", "--allow-insecure-http"]);

        let output = run_with_env(&args, &environment);

        assert_eq!(output.status.code(), Some(expected_status));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(value["deployment"], server.api_url);
        assert_eq!(value["organizationRef"], ORGANIZATION);
        assert_eq!(value["outcome"], expected_outcome);
        assert!(value.get("category").is_none());
        assert!(value.get("title").is_none());
        assert!(value.get("detail").is_none());
        assert!(output.stderr.is_empty());
        let combined = String::from_utf8_lossy(&output.stdout);
        assert!(!combined.contains("private-github"));
        assert!(!combined.contains(TOKEN));
        assert_eq!(server.finish().len(), 1);
    }
}

// REQ-CONNECTION-20
#[test]
fn setup_conflict_is_actionable_on_standard_error_without_problem_prose() {
    let response = github_problem(
        "409 Conflict",
        409,
        "https://api.usefulmachinery.com/problems/source-connection-conflict",
    );
    let (server, _directory, credential_path) = prepared_github(vec![
        setup_session_response(SETUP_SESSION, "https://github.example/apps/scherzo"),
        response,
    ]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &org_connection(&["connect", "github", "--installation", "713"]),
        &environment,
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(diagnostic.starts_with("error: "));
    let (_, remedy) = diagnostic.split_once("\n\n").unwrap();
    assert!(remedy.contains("\n  useful org integration list\n"));
    assert!(remedy.contains("\n  useful org integration connect github\n"));
    assert!(!diagnostic.contains("private-github"));
    assert!(!diagnostic.contains(TOKEN));
    assert_eq!(server.finish().len(), 2);
}

#[test]
fn oversized_github_success_response_is_rejected() {
    let repositories = (1..=1_024)
        .map(|provider_id| {
            serde_json::json!({
                "providerRepositoryId": provider_id.to_string(),
                "fullName": format!("acme/repo-{provider_id}"),
                "defaultBranch": "b".repeat(1_024)
            })
        })
        .collect::<Vec<_>>();
    let response_body = serde_json::to_vec(&serde_json::json!({
        "installation": installation_body("active"),
        "items": repositories
    }))
    .unwrap();
    assert!(response_body.len() > 1_024 * 1_024);
    let response = http_response("200 OK", Some("application/json"), &response_body);
    let (server, _directory, credential_path) = prepared_github(vec![response]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(&list_repositories(INSTALLATION), &environment);

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["outcome"],
        "invalid_response"
    );
    assert!(output.stderr.is_empty());
    server.finish();
}

// REQ-CONNECTION-18
#[test]
fn remote_insecure_setup_url_is_rejected_before_browser_handoff() {
    let unsafe_url = "http://github.example/private-setup-url-sentinel";
    let response = json_http_response(
        "201 Created",
        serde_json::json!({
            "id": SETUP_SESSION,
            "state": "pending",
            "expiresAt": "2026-09-05T12:10:00Z",
            "setupUrl": unsafe_url
        }),
    );
    let (server, _directory, credential_path) = prepared_github(vec![response]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &org_connection(&["connect", "github", "--json"]),
        &environment,
    );

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["outcome"],
        "invalid_response"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(unsafe_url));
    assert!(output.stderr.is_empty());
    server.finish();
}

#[test]
fn malformed_success_is_a_redacted_protocol_failure() {
    let mut invalid = installation_body("active");
    invalid["providerInstallationId"] =
        serde_json::Value::String("private-invalid-provider-id-sentinel".to_owned());
    let (server, _directory, credential_path) =
        prepared_github(vec![json_http_response("200 OK", invalid)]);
    let environment = deployment_environment(&server.api_url, &credential_path);

    let output = run_with_env(
        &[
            "org",
            "integration",
            "disconnect",
            INSTALLATION,
            "--org",
            ORGANIZATION,
            "--yes",
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["outcome"],
        "invalid_response"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains("private-invalid-provider-id-sentinel"));
    assert!(!combined.contains(TOKEN));
    server.finish();
}

fn show_installation(server: &ScriptedServer, credential_path: &str) -> Output {
    run_with_env(
        &[
            "org",
            "integration",
            "show",
            INSTALLATION,
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &deployment_environment(&server.api_url, credential_path),
    )
}

// REQ-CONNECTION-105
#[test]
fn show_of_an_active_binding_reads_it_from_the_list_and_then_its_repositories() {
    let mut other = installation_body("revoked");
    other["id"] = serde_json::Value::String("ghi_01k0z6r1w8f4jy2m7q9v3x5abd".to_owned());
    let (server, _directory, credential_path) = prepared_github(vec![
        super::connection::no_authorizations(),
        json_http_response(
            "200 OK",
            serde_json::json!({"items": [other, installation_body("active")]}),
        ),
        json_http_response(
            "200 OK",
            serde_json::json!({
                "installation": installation_body("active"),
                "items": [{
                    "providerRepositoryId": "991",
                    "fullName": "acme/widgets",
                    "defaultBranch": "main"
                }]
            }),
        ),
    ]);

    let output = show_installation(&server, &credential_path);

    assert!(output.status.success(), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["schemaVersion"], 1);
    assert_eq!(document["deployment"], server.api_url);
    assert_eq!(document["organizationRef"], ORGANIZATION);
    assert_eq!(document["outcome"], "shown");
    assert_eq!(document["installation"]["id"], INSTALLATION);
    assert_eq!(document["installation"]["state"], "active");
    assert_eq!(document["items"][0]["fullName"], "acme/widgets");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("omitted"));
    assert_eq!(document["authorizations"], serde_json::json!([]));
    let requests = server.finish();
    assert_eq!(requests.len(), 3);
    assert!(
        requests[1].starts_with(
            "GET /api/v1/organizations/acme-research/github/installations HTTP/1.1\r\n"
        )
    );
    assert!(requests[2].starts_with(&format!(
        "GET /api/v1/organizations/acme-research/github/installations/{INSTALLATION}/repositories HTTP/1.1\r\n"
    )));
}

// REQ-CONNECTION-105
#[test]
fn show_of_a_disconnected_binding_reads_no_repositories() {
    let (server, _directory, credential_path) = prepared_github(vec![
        super::connection::no_authorizations(),
        json_http_response(
            "200 OK",
            serde_json::json!({"items": [installation_body("disconnected")]}),
        ),
    ]);

    let output = show_installation(&server, &credential_path);

    assert!(output.status.success(), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["outcome"], "shown");
    assert_eq!(document["installation"]["state"], "disconnected");
    assert!(document.get("items").is_none(), "{document}");
    assert_eq!(server.finish().len(), 2);
}

// REQ-CONNECTION-105
#[test]
fn show_of_a_binding_the_list_does_not_hold_is_not_found() {
    let (server, _directory, credential_path) = prepared_github(vec![
        super::connection::no_authorizations(),
        json_http_response("200 OK", serde_json::json!({"items": []})),
    ]);

    let output = show_installation(&server, &credential_path);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["outcome"], "not_found");
    assert_eq!(server.finish().len(), 2);
}

// REQ-CONNECTION-73, REQ-CONNECTION-107
#[test]
fn repository_list_of_github_lists_the_repositories_of_the_binding_in_use() {
    let mut revoked = installation_body("revoked");
    revoked["id"] = serde_json::Value::String("ghi_01k0z6r1w8f4jy2m7q9v3x5abd".to_owned());
    let (server, _directory, credential_path) = prepared_github(vec![
        json_http_response(
            "200 OK",
            serde_json::json!({"items": [revoked, installation_body("active")]}),
        ),
        json_http_response(
            "200 OK",
            serde_json::json!({"installation": installation_body("active"), "items": []}),
        ),
    ]);

    let output = run_with_env(
        &list_repositories("github"),
        &deployment_environment(&server.api_url, &credential_path),
    );

    assert!(output.status.success(), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["outcome"], "listed");
    assert_eq!(document["installation"]["id"], INSTALLATION);
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].starts_with(&format!(
        "GET /api/v1/organizations/acme-research/github/installations/{INSTALLATION}/repositories HTTP/1.1\r\n"
    )));
}
