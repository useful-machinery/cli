use super::organization::{
    IN_EFFECT_ID, LIST_CURRENT_MEMBERSHIPS, OTHER_IN_EFFECT_ID, acme_widgets_checkout,
    active_memberships, projects_of, request_lines, run_in_effect,
};
use super::*;

const PROJECT_ID: &str = "prj_01k0z6r1w8f4jy2m7q9v3x5abc";
const PAPER_ID: &str = "prj_01k0z6r1w8f4jy2m7q9v3x5abe";
const ME: &str = "GET /api/v1/me HTTP/1.1";
const SERVICE_KEY: &str =
    "crd_01k0z6r1w8f4jy2m7q9v3x5abc.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn me(principal_type: &str) -> Vec<u8> {
    json_http_response(
        "200 OK",
        serde_json::json!({
            "principal": {
                "id": "prn_01k0z6r1w8f4jy2m7q9v3x5abc",
                "type": principal_type,
                "state": "active"
            }
        }),
    )
}

/// The projects of `organization_id`, archived ones included: `widgets` and the archived
/// `paper`.
fn widgets_and_archived_paper(organization_id: &str) -> Vec<u8> {
    let project = |id: &str, name: &str, full_name: &str| {
        serde_json::json!({
            "id": id,
            "organizationId": organization_id,
            "name": name,
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
        })
    };
    let mut paper = project(PAPER_ID, "paper", "acme/paper");
    paper["archivedAt"] = serde_json::json!("2026-09-06T12:00:00Z");
    json_http_response(
        "200 OK",
        serde_json::json!({
            "items": [project(PROJECT_ID, "widgets", "acme/widgets"), paper]
        }),
    )
}

fn show(
    responses: Vec<Vec<u8>>,
    arguments: &[&str],
    environment: &[(&str, &str)],
) -> (Output, Vec<String>) {
    run_in_effect(
        &["account", "show", "--json"],
        responses,
        arguments,
        environment,
    )
}

fn authenticated(output: &Output) -> serde_json::Value {
    assert!(output.status.success(), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["state"], "authenticated");
    document
}

fn in_effect(name: &str, value: &str, source: &str) -> serde_json::Value {
    serde_json::json!({ name: value, "source": source })
}

fn projects_request(organization: &str, query: &str) -> String {
    format!("GET /api/v1/organizations/{organization}/projects{query} HTTP/1.1")
}

// REQ-ORG-88, REQ-PROJECT-100, REQ-AUTH-31
#[test]
fn the_variables_name_both_without_another_request() {
    let (output, requests) = show(
        vec![me("human")],
        &[],
        &[("USEFUL_ORG", "acme"), ("USEFUL_PROJECT", PROJECT_ID)],
    );

    let document = authenticated(&output);
    assert_eq!(
        document["organizationInEffect"],
        in_effect("organization", "acme", "environment")
    );
    assert_eq!(
        document["projectInEffect"],
        in_effect("project", PROJECT_ID, "environment")
    );
    assert!(output.stderr.is_empty());
    assert_eq!(request_lines(&requests), [ME]);
}

// REQ-ORG-88, REQ-PROJECT-100
#[test]
fn a_project_name_is_found_among_every_project_of_the_organization_in_effect() {
    let (output, requests) = show(
        vec![me("human"), widgets_and_archived_paper(IN_EFFECT_ID)],
        &["--org", "acme", "--project", "paper"],
        &[],
    );

    let document = authenticated(&output);
    assert_eq!(
        document["organizationInEffect"],
        in_effect("organization", "acme", "flag")
    );
    assert_eq!(
        document["projectInEffect"],
        in_effect("project", PAPER_ID, "flag")
    );
    assert_eq!(
        request_lines(&requests),
        [ME, &projects_request("acme", "?includeArchived=true")]
    );

    let (output, requests) = show(
        vec![me("human"), widgets_and_archived_paper(IN_EFFECT_ID)],
        &["--org", "acme", "--project", "pencil"],
        &[],
    );

    let document = authenticated(&output);
    assert_eq!(
        document["organizationInEffect"],
        in_effect("organization", "acme", "flag")
    );
    assert!(document.get("projectInEffect").is_none(), "{document}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("pencil"));
    assert_eq!(requests.len(), 2);
}

// REQ-ORG-88, REQ-PROJECT-100
#[test]
fn the_checkout_names_the_project_and_its_organization() {
    let git = acme_widgets_checkout();
    let (output, requests) = show(
        vec![
            me("human"),
            active_memberships(&[(OTHER_IN_EFFECT_ID, "dunder"), (IN_EFFECT_ID, "acme")]),
            projects_of(
                OTHER_IN_EFFECT_ID,
                "prj_01k0z6r1w8f4jy2m7q9v3x5abd",
                "dunder/paper",
            ),
            projects_of(IN_EFFECT_ID, PROJECT_ID, "acme/widgets"),
        ],
        &[],
        &[("PATH", git.path().to_str().unwrap())],
    );

    let document = authenticated(&output);
    assert_eq!(
        document["organizationInEffect"],
        in_effect("organization", IN_EFFECT_ID, "checkout")
    );
    assert_eq!(
        document["projectInEffect"],
        in_effect("project", PROJECT_ID, "checkout")
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        request_lines(&requests),
        [
            ME,
            LIST_CURRENT_MEMBERSHIPS.trim_end(),
            &projects_request(OTHER_IN_EFFECT_ID, ""),
            &projects_request(IN_EFFECT_ID, ""),
        ]
    );
}

// REQ-ORG-88, REQ-PROJECT-100
#[test]
fn the_checkout_supplies_the_project_only_in_the_organization_named() {
    let git = acme_widgets_checkout();
    let path = git.path().to_str().unwrap();
    let responses = || {
        vec![
            me("human"),
            active_memberships(&[(OTHER_IN_EFFECT_ID, "dunder"), (IN_EFFECT_ID, "acme")]),
            projects_of(
                OTHER_IN_EFFECT_ID,
                "prj_01k0z6r1w8f4jy2m7q9v3x5abd",
                "dunder/paper",
            ),
            projects_of(IN_EFFECT_ID, PROJECT_ID, "acme/widgets"),
        ]
    };

    let (output, requests) = show(responses(), &["--org", "dunder"], &[("PATH", path)]);

    let document = authenticated(&output);
    assert_eq!(
        document["organizationInEffect"],
        in_effect("organization", "dunder", "flag")
    );
    assert!(document.get("projectInEffect").is_none(), "{document}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    for named in ["dunder", "acme"] {
        assert!(stderr.contains(named), "{stderr}");
    }
    assert_eq!(requests.len(), 4);

    // The organization named by its slug is the checkout project's.
    let (output, _) = show(responses(), &[], &[("PATH", path), ("USEFUL_ORG", "acme")]);

    let document = authenticated(&output);
    assert_eq!(
        document["organizationInEffect"],
        in_effect("organization", "acme", "environment")
    );
    assert_eq!(
        document["projectInEffect"],
        in_effect("project", PROJECT_ID, "checkout")
    );
    assert!(output.stderr.is_empty());
}

// REQ-ORG-88, REQ-PROJECT-100, REQ-AUTH-31
#[test]
fn nothing_named_leaves_none_in_effect_and_the_status_stands() {
    let memberships =
        || active_memberships(&[(IN_EFFECT_ID, "acme"), (OTHER_IN_EFFECT_ID, "dunder")]);
    let (output, requests) = show(vec![me("human"), memberships()], &[], &[]);

    let document = authenticated(&output);
    assert!(document.get("organizationInEffect").is_none(), "{document}");
    assert!(document.get("projectInEffect").is_none(), "{document}");
    assert!(output.stderr.is_empty());
    assert_eq!(
        request_lines(&requests),
        [ME, LIST_CURRENT_MEMBERSHIPS.trim_end()]
    );

    let (output, _) = run_in_effect(
        &["account", "show"],
        vec![me("human"), memberships()],
        &[],
        &[],
    );

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    for none in ["organization in effect: none", "project in effect: none"] {
        assert!(stdout.lines().any(|line| line == none), "{stdout}");
    }
}

// REQ-ORG-88, REQ-AUTH-31
#[test]
fn a_signed_out_caller_gets_the_status_alone() {
    let server = ScriptedServer::respond(vec![problem_http_response(
        "401 Unauthorized",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/unauthorized",
            "title": "Unauthorized",
            "status": 401
        }),
    )]);
    let directory = private_credential_directory();
    let credential_path = directory.path().join("credentials.json");
    let mut environment =
        deployment_environment(&server.api_url, credential_path.to_str().unwrap()).to_vec();
    environment.push(("USEFUL_ORG", "acme"));

    let output = run_with_env(
        &["account", "show", "--json", "--allow-insecure-http"],
        &environment,
    );

    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["state"], "unauthenticated");
    assert!(document.get("organizationInEffect").is_none(), "{document}");
    assert!(document.get("projectInEffect").is_none(), "{document}");
    assert_eq!(request_lines(&server.finish()), [ME]);
}

// REQ-ORG-88, REQ-AUTH-31
#[test]
fn a_failed_membership_read_is_said_on_standard_error_and_the_status_stands() {
    let (output, requests) = show(
        vec![
            me("human"),
            problem_http_response(
                "503 Service Unavailable",
                serde_json::json!({
                    "type": "about:blank",
                    "title": "Service Unavailable",
                    "status": 503
                }),
            ),
        ],
        &[],
        &[],
    );

    let document = authenticated(&output);
    assert!(document.get("organizationInEffect").is_none(), "{document}");
    assert!(document.get("projectInEffect").is_none(), "{document}");
    assert!(!output.stderr.is_empty());
    assert_eq!(
        request_lines(&requests),
        [ME, LIST_CURRENT_MEMBERSHIPS.trim_end()]
    );
}

// REQ-ORG-88, REQ-AUTH-31
#[test]
fn the_service_api_key_reads_the_memberships() {
    let server = ScriptedServer::respond(vec![
        me("service"),
        active_memberships(&[(IN_EFFECT_ID, "acme")]),
    ]);
    let directory = private_credential_directory();
    let key_path = directory.path().join("service.key");
    fs::write(&key_path, format!("{SERVICE_KEY}\n")).unwrap();
    fs::set_permissions(&key_path, Permissions::from_mode(0o600)).unwrap();
    let human_credentials = directory.path().join("unused-human.json");
    let environment = deployment_environment(&server.api_url, human_credentials.to_str().unwrap());

    let output = run_with_env(
        &[
            "account",
            "show",
            "--json",
            "--api-key-file",
            key_path.to_str().unwrap(),
            "--allow-insecure-http",
        ],
        &environment,
    );

    let document = authenticated(&output);
    assert_eq!(
        document["organizationInEffect"],
        in_effect("organization", IN_EFFECT_ID, "only_membership")
    );
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [ME, LIST_CURRENT_MEMBERSHIPS.trim_end()]
    );
    for request in &requests {
        assert_eq!(
            header_value(request, "authorization"),
            format!("Bearer {SERVICE_KEY}")
        );
    }
}
