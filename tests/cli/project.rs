use super::connection::{gitlab_connection, installation};
use super::organization::{
    LIST_CURRENT_MEMBERSHIPS, acme_widgets_checkout, active_memberships, projects_of,
    request_lines, run_in_effect,
};
use super::*;

#[path = "project/webhook.rs"]
mod webhook;

const TOKEN: &str = "unique-project-command-token-sentinel";
const SERVICE_API_KEY: &str =
    "crd_01k0z6r1w8f4jy2m7q9v3x5abc.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const ORGANIZATION: &str = "acme-research";
const ORGANIZATION_ID: &str = "org_01k0z6r1w8f4jy2m7q9v3x5abc";
const MEMBERSHIP_ID: &str = "mem_01k0z6r1w8f4jy2m7q9v3x5abc";
const PROJECT_ID: &str = "prj_01k0z6r1w8f4jy2m7q9v3x5abc";
const INSTALLATION_ID: &str = "ghi_01k0z6r1w8f4jy2m7q9v3x5abc";
const GITLAB_CONNECTION_ID: &str = "glc_01k0z6r1w8f4jy2m7q9v3x5abc";
const CONNECTION_ID: &str = "rpc_01k0z6r1w8f4jy2m7q9v3x5abc";
const POOL_ID: &str = "rpl_01k0z6r1w8f4jy2m7q9v3x5abc";
const SHARED_POOL_ID: &str = "rpl_01k0z6r1w8f4jy2m7q9v3x5abd";
const REPOSITORY_ID: &str = "123456789";
const RUN_ID: &str = "run_01k0z6r1w8f4jy2m7q9v3x5abc";
const DEFINITION_ID: &str = "def_01k0z6r1w8f4jy2m7q9v3x5abc";

fn prepared_project(responses: Vec<Vec<u8>>) -> (ScriptedServer, tempfile::TempDir, String) {
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

fn repository_body(full_name: &str, default_branch: &str) -> serde_json::Value {
    serde_json::json!({
        "connectionId": CONNECTION_ID,
        "providerKind": "github",
        "installationBindingId": INSTALLATION_ID,
        "providerRepositoryId": REPOSITORY_ID,
        "fullName": full_name,
        "defaultBranch": default_branch,
        "availability": "active"
    })
}

fn pool_body() -> serde_json::Value {
    serde_json::json!({
        "id": POOL_ID,
        "organizationId": ORGANIZATION_ID,
        "name": "builders",
        "createdAt": "2026-09-05T12:00:00Z",
        "updatedAt": "2026-09-05T12:01:00Z"
    })
}

fn shared_pool_body() -> serde_json::Value {
    let mut pool = pool_body();
    pool["id"] = serde_json::json!(SHARED_POOL_ID);
    pool["name"] = serde_json::json!("shared");
    pool
}

fn project_body(
    name: &str,
    pool: bool,
    repository: Option<serde_json::Value>,
) -> serde_json::Value {
    let blockers = match (pool, repository.is_some()) {
        (false, true) => serde_json::json!(["runner_pool_unassigned"]),
        (true, false) => serde_json::json!(["repository_detached"]),
        (false, false) => {
            serde_json::json!(["runner_pool_unassigned", "repository_detached"])
        }
        (true, true) => serde_json::json!([]),
    };
    serde_json::json!({
        "id": PROJECT_ID,
        "organizationId": ORGANIZATION_ID,
        "name": name,
        "runnerPool": pool.then(|| serde_json::json!({"id": POOL_ID, "name": "builders"})),
        "repository": repository,
        "executionReadiness": {
            "ready": blockers.as_array().unwrap().is_empty(),
            "blockers": blockers
        },
        "createdAt": "2026-09-05T12:00:00Z",
        "updatedAt": "2026-09-05T12:01:00Z"
    })
}

fn project_response(status: &str, project: serde_json::Value, create: bool) -> Vec<u8> {
    let mut headers = vec![("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)];
    if create {
        headers.push((
            "Location",
            "/v1/organizations/acme-research/projects/prj_01k0z6r1w8f4jy2m7q9v3x5abc",
        ));
    }
    http_response_with_headers(
        status,
        Some("application/json"),
        &headers,
        &serde_json::to_vec(&project).unwrap(),
    )
}

fn request_body(request: &str) -> serde_json::Value {
    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
}

fn run_project(args: &[&str], server: &ScriptedServer, credential_path: &str) -> Output {
    let environment = deployment_environment(&server.api_url, credential_path);
    run_with_env(args, &environment)
}

fn assert_json_success(output: &Output, outcome: &str) -> serde_json::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["outcome"], outcome);
    value
}

// REQ-AUTH-48, REQ-AUTH-49
// REQ-PROJECT-75
#[test]
fn project_list_uses_only_the_explicit_service_api_key() {
    let directory = private_credential_directory();
    let service_key_path = directory.path().join("service.key");
    fs::write(&service_key_path, format!("{SERVICE_API_KEY}\n")).unwrap();
    fs::set_permissions(&service_key_path, Permissions::from_mode(0o600)).unwrap();
    let service_key_path = service_key_path.to_str().unwrap();

    let server = ScriptedServer::respond(vec![json_http_response(
        "200 OK",
        serde_json::json!({"items": []}),
    )]);
    let missing_human_store = directory.path().join("missing-human.json");
    let environment =
        deployment_environment(&server.api_url, missing_human_store.to_str().unwrap());
    let output = run_with_env(
        &[
            "project",
            "list",
            "--org",
            ORGANIZATION,
            "--api-key-file",
            service_key_path,
            "--json",
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert_json_success(&output, "listed");
    assert!(!missing_human_store.exists());
    let request = server.finish().pop().unwrap();
    assert_eq!(
        header_value(&request, "authorization"),
        format!("Bearer {SERVICE_API_KEY}")
    );

    let server = ScriptedServer::respond(vec![problem_http_response(
        "401 Unauthorized",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/unauthorized",
            "title": "Unauthorized",
            "status": 401
        }),
    )]);
    let invalid_human_store = directory.path().join("invalid-human.json");
    fs::write(&invalid_human_store, b"human-store-must-not-be-read\n").unwrap();
    fs::set_permissions(&invalid_human_store, Permissions::from_mode(0o600)).unwrap();
    let before = fs::read(&invalid_human_store).unwrap();
    let environment =
        deployment_environment(&server.api_url, invalid_human_store.to_str().unwrap());
    let output = run_with_env(
        &[
            "project",
            "list",
            "--org",
            ORGANIZATION,
            "--api-key-file",
            service_key_path,
            "--allow-insecure-http",
        ],
        &environment,
    );

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        concat!(
            "error: service API key rejected\n\n",
            "Use a different active service API key.\n"
        )
    );
    assert_eq!(fs::read(&invalid_human_store).unwrap(), before);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SERVICE_API_KEY));
    let request = server.finish().pop().unwrap();
    assert_eq!(
        header_value(&request, "authorization"),
        format!("Bearer {SERVICE_API_KEY}")
    );
}

// REQ-PROJECT-75, REQ-PROJECT-76,
// REQ-PROJECT-77, REQ-PROJECT-79, REQ-PROJECT-81, REQ-PROJECT-90, REQ-WORKSPACE-7
#[test]
fn discovery_and_project_management_feed_an_inputless_cloud_run() {
    let membership_page = serde_json::json!({
        "items": [{
            "id": MEMBERSHIP_ID,
            "organizationId": ORGANIZATION_ID,
            "organizationState": "active",
            "organizationDisplayName": "Acme Research",
            "organizationSlug": ORGANIZATION,
            "role": "owner",
            "state": "active",
            "createdAt": "2026-09-05T11:00:00Z",
            "updatedAt": "2026-09-05T11:00:00Z"
        }]
    });
    let installation = serde_json::json!({
        "id": INSTALLATION_ID,
        "providerInstallationId": "87654321",
        "providerAccountId": "11223344",
        "providerAccountLogin": "acme",
        "providerAccountType": "Organization",
        "state": "active",
        "createdAt": "2026-09-05T11:00:00Z",
        "updatedAt": "2026-09-05T11:00:00Z"
    });
    let discovered_repository = serde_json::json!({
        "providerRepositoryId": REPOSITORY_ID,
        "fullName": "acme/widget",
        "defaultBranch": "main"
    });
    let initial = project_body(
        "widget",
        false,
        Some(repository_body("acme/widget", "release")),
    );
    let renamed = project_body(
        "widget-service",
        false,
        Some(repository_body("acme/widget", "release")),
    );
    let ready = project_body(
        "widget-service",
        true,
        Some(repository_body("acme/widget", "release")),
    );
    let rebound = project_body(
        "widget-service",
        true,
        Some(repository_body("acme/widget-next", "main")),
    );
    let branch_updated = project_body(
        "widget-service",
        true,
        Some(repository_body("acme/widget-next", "stable")),
    );
    let detached = project_body("widget-service", true, None);
    let unconfigured = project_body("widget-service", false, None);
    let acceptance = http_response_with_headers(
        "202 Accepted",
        Some("application/json"),
        &[
            ("Idempotency-Key", ECHO_IDEMPOTENCY_KEY),
            (
                "Location",
                "/v1/organizations/acme-research/runs/run_01k0z6r1w8f4jy2m7q9v3x5abc",
            ),
        ],
        &serde_json::to_vec(&serde_json::json!({"runId": RUN_ID, "replayed": false})).unwrap(),
    );
    let (server, _directory, credential_path) = prepared_project(vec![
        json_http_response("200 OK", membership_page),
        json_http_response(
            "200 OK",
            serde_json::json!({"items": [installation.clone()]}),
        ),
        // The installation's authorizations in force, which the list reads after it
        // (REQ-INTEGRATION-34).
        super::connection::no_authorizations(),
        json_http_response(
            "200 OK",
            serde_json::json!({
                "installation": installation,
                "items": [discovered_repository]
            }),
        ),
        project_response("201 Created", initial.clone(), true),
        json_http_response(
            "200 OK",
            serde_json::json!({"items": [initial.clone()], "nextCursor": "next-project-page"}),
        ),
        json_http_response("200 OK", initial.clone()),
        project_response("200 OK", renamed.clone(), false),
        json_http_response("200 OK", pool_body()),
        json_http_response("200 OK", renamed.clone()),
        project_response("200 OK", ready.clone(), false),
        json_http_response("200 OK", ready.clone()),
        project_response("200 OK", rebound, false),
        project_response("200 OK", branch_updated, false),
        project_response("200 OK", detached.clone(), false),
        json_http_response("200 OK", pool_body()),
        json_http_response("200 OK", detached),
        project_response("200 OK", unconfigured, false),
        acceptance,
    ]);

    let organizations = run_project(
        &["org", "list", "--json", "--allow-insecure-http"],
        &server,
        &credential_path,
    );
    let organizations = assert_json_success(&organizations, "listed");
    assert_eq!(organizations["items"][0]["organizationSlug"], ORGANIZATION);

    let installations = run_project(
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
        &server,
        &credential_path,
    );
    let installations = assert_json_success(&installations, "listed");
    assert_eq!(installations["items"][0]["id"], INSTALLATION_ID);

    let repositories = run_project(
        &[
            "org",
            "integration",
            "repository",
            "list",
            INSTALLATION_ID,
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    let repositories = assert_json_success(&repositories, "listed");
    assert_eq!(
        repositories["items"][0]["providerRepositoryId"],
        REPOSITORY_ID
    );
    assert_eq!(repositories["items"][0]["defaultBranch"], "main");

    let created = run_project(
        &[
            "project",
            "create",
            "widget",
            "--repository",
            REPOSITORY_ID,
            "--integration",
            INSTALLATION_ID,
            "--org",
            ORGANIZATION,
            "--default-branch",
            "release",
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    let created = assert_json_success(&created, "created");
    assert_eq!(created["project"]["id"], PROJECT_ID);
    assert_eq!(created["project"]["executionReadiness"]["ready"], false);
    assert_eq!(
        created["project"]["executionReadiness"]["blockers"],
        serde_json::json!(["runner_pool_unassigned"])
    );

    let listed = run_project(
        &[
            "project",
            "list",
            "--org",
            ORGANIZATION,
            "--limit",
            "1",
            "--cursor",
            "opaque /+=?&",
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    let listed = assert_json_success(&listed, "listed");
    assert_eq!(listed["items"][0]["id"], PROJECT_ID);
    assert_eq!(listed["nextCursor"], "next-project-page");

    let shown = run_project(
        &[
            "project",
            "show",
            PROJECT_ID,
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    assert_eq!(
        assert_json_success(&shown, "found")["project"]["name"],
        "widget"
    );

    let renamed_output = run_project(
        &[
            "project",
            "update",
            PROJECT_ID,
            "--name",
            "widget-service",
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    let renamed_output = assert_json_success(&renamed_output, "updated");
    assert_eq!(renamed_output["applied"], serde_json::json!(["renamed"]));
    assert_eq!(renamed_output["project"]["name"], "widget-service");

    let pool_added = run_pool(&["add", POOL_ID], &server, &credential_path);
    let pool_added = assert_json_success(&pool_added, "runner_pool_added");
    assert_eq!(pool_added["project"]["runnerPool"]["id"], POOL_ID);
    assert_eq!(pool_added["project"]["executionReadiness"]["ready"], true);

    let repository = run_project(
        &[
            "project",
            "show",
            "--org",
            ORGANIZATION,
            "--project",
            PROJECT_ID,
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    assert_eq!(
        assert_json_success(&repository, "found")["project"]["repository"]["connectionId"],
        CONNECTION_ID
    );

    let repository_set = run_project(
        &[
            "project",
            "update",
            PROJECT_ID,
            "--repository",
            REPOSITORY_ID,
            "--integration",
            INSTALLATION_ID,
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    assert_eq!(
        assert_json_success(&repository_set, "updated")["applied"],
        serde_json::json!(["repository_set"])
    );

    let repository_updated = run_project(
        &[
            "project",
            "update",
            PROJECT_ID,
            "--default-branch",
            "stable",
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    let repository_updated = assert_json_success(&repository_updated, "updated");
    assert_eq!(
        repository_updated["applied"],
        serde_json::json!(["repository_updated"])
    );
    assert_eq!(
        repository_updated["project"]["repository"]["defaultBranch"],
        "stable"
    );

    let repository_detached = run_project(
        &[
            "project",
            "update",
            PROJECT_ID,
            "--clear-repository",
            "--yes",
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    let repository_detached = assert_json_success(&repository_detached, "updated");
    assert_eq!(
        repository_detached["applied"],
        serde_json::json!(["repository_detached"])
    );
    assert_eq!(
        repository_detached["project"]["repository"],
        serde_json::Value::Null
    );

    let pool_removed = run_pool(&["remove", POOL_ID, "--yes"], &server, &credential_path);
    let pool_removed = assert_json_success(&pool_removed, "runner_pool_removed");
    assert_eq!(
        pool_removed["project"]["executionReadiness"]["blockers"],
        serde_json::json!(["runner_pool_unassigned", "repository_detached"])
    );

    let run_created = run_project(
        &[
            "workflow",
            "run",
            "create",
            DEFINITION_ID,
            "--on",
            "personal",
            "--org",
            ORGANIZATION,
            "--project",
            PROJECT_ID,
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    assert_eq!(
        assert_json_success(&run_created, "accepted")["runId"],
        RUN_ID
    );

    let mut requests = server.finish();
    // The list reads the installation's authorizations after it (REQ-INTEGRATION-34).
    let authorizations = requests.remove(2);
    assert!(
        authorizations.starts_with(&format!(
            "GET /api/v1/organizations/{ORGANIZATION}/connection-authorizations?limit=200 "
        )),
        "{authorizations}"
    );
    assert_eq!(requests.len(), 18);
    assert!(requests[0].starts_with("GET /api/v1/me/memberships HTTP/1.1\r\n"));
    assert!(requests[1].starts_with(&format!(
        "GET /api/v1/organizations/{ORGANIZATION}/github/installations HTTP/1.1\r\n"
    )));
    assert!(requests[2].starts_with(&format!(
        "GET /api/v1/organizations/{ORGANIZATION}/github/installations/{INSTALLATION_ID}/repositories HTTP/1.1\r\n"
    )));
    assert!(requests[3].starts_with(&format!(
        "POST /api/v1/organizations/{ORGANIZATION}/projects HTTP/1.1\r\n"
    )));
    assert_eq!(
        request_body(&requests[3]),
        serde_json::json!({
            "name": "widget",
            "repository": {
                "providerKind": "github",
                "installationBindingId": INSTALLATION_ID,
                "providerRepositoryId": REPOSITORY_ID,
                "defaultBranch": "release"
            }
        })
    );
    assert!(requests[4].starts_with(&format!(
        "GET /api/v1/organizations/{ORGANIZATION}/projects?limit=1&cursor=opaque+%2F%2B%3D%3F%26 HTTP/1.1\r\n"
    )));
    for read in [&requests[5], &requests[8], &requests[10], &requests[15]] {
        assert!(read.starts_with(&format!(
            "GET /api/v1/organizations/{ORGANIZATION}/projects/{PROJECT_ID} HTTP/1.1\r\n"
        )));
    }
    assert!(requests[6].starts_with("PATCH "));
    assert_eq!(
        header_value(&requests[6], "content-type"),
        "application/merge-patch+json"
    );
    assert_eq!(
        request_body(&requests[6]),
        serde_json::json!({"name": "widget-service"})
    );
    for read in [&requests[7], &requests[14]] {
        assert!(read.starts_with(&format!(
            "GET /api/v1/organizations/{ORGANIZATION}/runner-pools/{POOL_ID} HTTP/1.1\r\n"
        )));
    }
    assert_eq!(request_lines(&requests[9..10]), [PUT_POOLS]);
    assert_eq!(
        request_body(&requests[9]),
        serde_json::json!({"runnerPoolIds": [POOL_ID]})
    );
    assert_eq!(
        request_body(&requests[11]),
        serde_json::json!({
            "providerKind": "github",
            "installationBindingId": INSTALLATION_ID,
            "providerRepositoryId": REPOSITORY_ID
        })
    );
    assert_eq!(
        header_value(&requests[12], "content-type"),
        "application/merge-patch+json"
    );
    assert_eq!(
        request_body(&requests[12]),
        serde_json::json!({"defaultBranch": "stable"})
    );
    assert!(requests[13].starts_with("DELETE "));
    assert!(requests[16].starts_with(&format!(
        "DELETE /api/v1/organizations/{ORGANIZATION}/projects/{PROJECT_ID}/runner-pool HTTP/1.1\r\n"
    )));
    assert_eq!(
        request_body(&requests[17]),
        serde_json::json!({
            "projectId": PROJECT_ID,
            "definition": {"definitionId": DEFINITION_ID}
        })
    );
    for request in &requests {
        assert_eq!(
            header_value(request, "authorization"),
            format!("Bearer {TOKEN}")
        );
    }
    for request in [
        &requests[3],
        &requests[6],
        &requests[9],
        &requests[11],
        &requests[12],
        &requests[13],
        &requests[16],
        &requests[17],
    ] {
        let key = header_value(request, "idempotency-key");
        assert_eq!(key.len(), 64);
        assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}

/// A project whose pool set is `pools`, each `(id, name)`, in their order.
fn project_with_pools(pools: &[(&str, &str)]) -> serde_json::Value {
    let mut project = project_body(
        "widget",
        !pools.is_empty(),
        Some(repository_body("acme/widget", "main")),
    );
    let pools: Vec<_> = pools
        .iter()
        .map(|(id, name)| serde_json::json!({"id": id, "name": name}))
        .collect();
    project["runnerPool"] = pools.first().cloned().into();
    project["runnerPools"] = pools.into();
    project
}

/// Runs `useful project pool ARGS...` in the named organization and project.
fn run_pool(args: &[&str], server: &ScriptedServer, credential_path: &str) -> Output {
    let mut arguments = vec!["project", "pool"];
    arguments.extend(args);
    arguments.extend([
        "--org",
        ORGANIZATION,
        "--project",
        PROJECT_ID,
        "--json",
        "--allow-insecure-http",
    ]);
    run_project(&arguments, server, credential_path)
}

const LIST_POOLS: &str = "GET /api/v1/organizations/acme-research/runner-pools?limit=200 HTTP/1.1";
const PUT_POOLS: &str = "PUT /api/v1/organizations/acme-research/projects/prj_01k0z6r1w8f4jy2m7q9v3x5abc/runner-pools HTTP/1.1";

// REQ-PROJECT-77, REQ-PROJECT-79, REQ-PROJECT-90
#[test]
fn project_pool_add_reads_the_project_and_writes_the_set_with_the_pool_appended() {
    let both = project_with_pools(&[(POOL_ID, "builders"), (SHARED_POOL_ID, "shared")]);
    let (server, _directory, credential_path) = prepared_project(vec![
        json_http_response(
            "200 OK",
            serde_json::json!({"items": [pool_body(), shared_pool_body()]}),
        ),
        json_http_response("200 OK", project_with_pools(&[(POOL_ID, "builders")])),
        project_response("200 OK", both.clone(), false),
    ]);

    let output = run_pool(&["add", "shared"], &server, &credential_path);

    let result = assert_json_success(&output, "runner_pool_added");
    assert_eq!(result["project"]["runnerPools"], both["runnerPools"]);
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [LIST_POOLS, READ_PROJECT, PUT_POOLS]
    );
    assert_eq!(
        request_body(&requests[2]),
        serde_json::json!({"runnerPoolIds": [POOL_ID, SHARED_POOL_ID]})
    );
}

// REQ-PROJECT-90
#[test]
fn project_pool_add_of_a_pool_the_set_holds_writes_nothing() {
    let project = project_with_pools(&[(POOL_ID, "builders")]);
    let (server, _directory, credential_path) = prepared_project(vec![
        json_http_response(
            "200 OK",
            serde_json::json!({"items": [pool_body(), shared_pool_body()]}),
        ),
        json_http_response("200 OK", project.clone()),
    ]);

    let output = run_pool(&["add", "builders"], &server, &credential_path);

    let result = assert_json_success(&output, "runner_pool_added");
    assert_eq!(result["project"]["runnerPools"], project["runnerPools"]);
    assert_eq!(request_lines(&server.finish()), [LIST_POOLS, READ_PROJECT]);
}

// REQ-PROJECT-77, REQ-PROJECT-79, REQ-PROJECT-90
#[test]
fn project_pool_remove_writes_the_set_without_the_pool() {
    let remaining = project_with_pools(&[(POOL_ID, "builders")]);
    let (server, _directory, credential_path) = prepared_project(vec![
        json_http_response(
            "200 OK",
            serde_json::json!({"items": [pool_body(), shared_pool_body()]}),
        ),
        json_http_response(
            "200 OK",
            project_with_pools(&[(POOL_ID, "builders"), (SHARED_POOL_ID, "shared")]),
        ),
        project_response("200 OK", remaining.clone(), false),
    ]);

    let output = run_pool(&["remove", "shared", "--yes"], &server, &credential_path);

    let result = assert_json_success(&output, "runner_pool_removed");
    assert_eq!(result["project"]["runnerPools"], remaining["runnerPools"]);
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [LIST_POOLS, READ_PROJECT, PUT_POOLS]
    );
    assert_eq!(
        request_body(&requests[2]),
        serde_json::json!({"runnerPoolIds": [POOL_ID]})
    );
}

// REQ-PROJECT-90
#[test]
fn project_pool_remove_of_the_last_pool_deletes_the_assignment() {
    let (server, _directory, credential_path) = prepared_project(vec![
        json_http_response(
            "200 OK",
            serde_json::json!({"items": [pool_body(), shared_pool_body()]}),
        ),
        json_http_response("200 OK", project_with_pools(&[(POOL_ID, "builders")])),
        project_response("200 OK", project_with_pools(&[]), false),
    ]);

    let output = run_pool(&["remove", "builders", "--yes"], &server, &credential_path);

    let result = assert_json_success(&output, "runner_pool_removed");
    assert_eq!(result["project"]["runnerPools"], serde_json::json!([]));
    assert_eq!(
        request_lines(&server.finish()),
        [
            LIST_POOLS,
            READ_PROJECT,
            "DELETE /api/v1/organizations/acme-research/projects/prj_01k0z6r1w8f4jy2m7q9v3x5abc/runner-pool HTTP/1.1",
        ]
    );
}

// REQ-PROJECT-90
#[test]
fn project_pool_remove_of_a_pool_the_set_does_not_hold_writes_nothing() {
    let project = project_with_pools(&[(POOL_ID, "builders")]);
    let (server, _directory, credential_path) = prepared_project(vec![
        json_http_response(
            "200 OK",
            serde_json::json!({"items": [pool_body(), shared_pool_body()]}),
        ),
        json_http_response("200 OK", project.clone()),
    ]);

    let output = run_pool(&["remove", "shared", "--yes"], &server, &credential_path);

    let result = assert_json_success(&output, "runner_pool_removed");
    assert_eq!(result["project"]["runnerPools"], project["runnerPools"]);
    assert_eq!(request_lines(&server.finish()), [LIST_POOLS, READ_PROJECT]);
}

// REQ-PROJECT-77, REQ-PROJECT-90
#[test]
fn project_pool_add_of_a_name_no_pool_has_is_not_found_before_the_project_read() {
    let (server, _directory, credential_path) = prepared_project(vec![json_http_response(
        "200 OK",
        serde_json::json!({"items": [pool_body(), shared_pool_body()]}),
    )]);

    let output = run_pool(&["add", "ghost"], &server, &credential_path);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["outcome"], "not_found");
    assert_eq!(request_lines(&server.finish()), [LIST_POOLS]);
}

// REQ-PROJECT-76, REQ-PROJECT-77
#[test]
fn project_creation_resolves_an_exact_pool_name() {
    let project = project_body("widget", true, Some(repository_body("acme/widget", "main")));
    let (server, _directory, credential_path) = prepared_project(vec![
        json_http_response("200 OK", serde_json::json!({"items": [pool_body()]})),
        project_response("201 Created", project, true),
    ]);

    let output = run_project(
        &[
            "project",
            "create",
            "widget",
            "--repository",
            REPOSITORY_ID,
            "--integration",
            INSTALLATION_ID,
            "--org",
            ORGANIZATION,
            "--pool",
            "builders",
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );

    assert_json_success(&output, "created");
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with(&format!(
        "GET /api/v1/organizations/{ORGANIZATION}/runner-pools?limit=200 HTTP/1.1\r\n"
    )));
    assert!(requests[1].starts_with(&format!(
        "POST /api/v1/organizations/{ORGANIZATION}/projects HTTP/1.1\r\n"
    )));
    assert_eq!(
        request_body(&requests[1]),
        serde_json::json!({
            "name": "widget",
            "repository": {
                "providerKind": "github",
                "installationBindingId": INSTALLATION_ID,
                "providerRepositoryId": REPOSITORY_ID
            },
            "runnerPoolId": POOL_ID
        })
    );
}

/// Runs `useful project create ARGS...` in the named organization.
fn run_create(args: &[&str], server: &ScriptedServer, credential_path: &str) -> Output {
    let mut arguments = vec!["project", "create"];
    arguments.extend(args);
    arguments.extend(["--org", ORGANIZATION, "--json", "--allow-insecure-http"]);
    run_project(&arguments, server, credential_path)
}

const LIST_BINDINGS: &str = "GET /api/v1/organizations/acme-research/github/installations HTTP/1.1";
const LIST_BINDING_REPOSITORIES: &str = "GET /api/v1/organizations/acme-research/github/installations/ghi_01k0z6r1w8f4jy2m7q9v3x5abc/repositories HTTP/1.1";
const LIST_GITLAB_CONNECTIONS: &str =
    "GET /api/v1/organizations/acme-research/connections/gitlab?limit=100 HTTP/1.1";
const CREATE_PROJECT: &str = "POST /api/v1/organizations/acme-research/projects HTTP/1.1";

/// The organization's GitHub bindings: the one active binding.
fn github_bindings() -> Vec<u8> {
    json_http_response("200 OK", serde_json::json!({"items": [installation()]}))
}

/// The repositories the one binding's installation grants: `full_name` as `REPOSITORY_ID`.
fn granted(full_name: &str) -> Vec<u8> {
    json_http_response(
        "200 OK",
        serde_json::json!({
            "installation": installation(),
            "items": [{
                "providerRepositoryId": REPOSITORY_ID,
                "fullName": full_name,
                "defaultBranch": "main"
            }]
        }),
    )
}

fn gitlab_connections(connections: &[serde_json::Value]) -> Vec<u8> {
    json_http_response(
        "200 OK",
        serde_json::json!({"items": connections, "nextCursor": null}),
    )
}

/// The repositories selected for the GitLab connection: `full_name` as `REPOSITORY_ID`.
fn selected(full_name: &str) -> Vec<u8> {
    json_http_response(
        "200 OK",
        serde_json::json!({
            "items": [{
                "providerRepositoryId": REPOSITORY_ID,
                "fullName": full_name,
                "defaultBranch": "main",
                "selected": true,
                "availability": "active"
            }],
            "nextCursor": null
        }),
    )
}

/// Whether `line` reads the selected repositories of the GitLab connection.
fn reads_selected(line: &str) -> bool {
    line.starts_with(&format!(
        "GET /api/v1/organizations/acme-research/connections/gitlab/{GITLAB_CONNECTION_ID}/repositories?"
    )) && line.contains("selected=true")
}

fn created_project(provider: &str) -> Vec<u8> {
    let mut repository = repository_body("acme/widget", "main");
    if provider == "gitlab" {
        repository = serde_json::json!({
            "connectionId": CONNECTION_ID,
            "providerKind": "gitlab",
            "gitlabConnectionId": GITLAB_CONNECTION_ID,
            "instanceUrl": "https://gitlab.com",
            "providerRepositoryId": REPOSITORY_ID,
            "fullName": "group/widget",
            "defaultBranch": "main",
            "availability": "active"
        });
    }
    project_response(
        "201 Created",
        project_body("widget", false, Some(repository)),
        true,
    )
}

fn github_selection() -> serde_json::Value {
    serde_json::json!({
        "providerKind": "github",
        "installationBindingId": INSTALLATION_ID,
        "providerRepositoryId": REPOSITORY_ID
    })
}

fn gitlab_selection() -> serde_json::Value {
    serde_json::json!({
        "providerKind": "gitlab",
        "gitlabConnectionId": GITLAB_CONNECTION_ID,
        "providerRepositoryId": REPOSITORY_ID
    })
}

// REQ-PROJECT-101
#[test]
fn project_create_finds_the_one_connection_that_reaches_the_repository() {
    let (server, _directory, credential_path) = prepared_project(vec![
        github_bindings(),
        granted("acme/widget"),
        gitlab_connections(&[]),
        created_project("github"),
    ]);

    let output = run_create(
        &["widget", "--repository", "Acme/Widget"],
        &server,
        &credential_path,
    );

    assert_json_success(&output, "created");
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [
            LIST_BINDINGS,
            LIST_BINDING_REPOSITORIES,
            LIST_GITLAB_CONNECTIONS,
            CREATE_PROJECT
        ]
    );
    assert_eq!(
        request_body(&requests[3]),
        serde_json::json!({"name": "widget", "repository": github_selection()})
    );
}

// REQ-PROJECT-101
#[test]
fn project_create_with_several_connections_reaching_the_repository_names_them_and_creates_nothing()
{
    let mut gitlab = gitlab_connection();
    gitlab["state"] = "active".into();
    let (server, _directory, credential_path) = prepared_project(vec![
        github_bindings(),
        granted("acme/widget"),
        gitlab_connections(&[gitlab]),
        selected("acme/widget"),
    ]);

    let output = run_create(
        &["widget", "--repository", "acme/widget"],
        &server,
        &credential_path,
    );

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(INSTALLATION_ID), "{stderr}");
    assert!(stderr.contains(GITLAB_CONNECTION_ID), "{stderr}");
    assert!(stderr.contains("--integration"), "{stderr}");
    let requests = server.finish();
    assert_eq!(requests.len(), 4);
    assert!(!request_lines(&requests).contains(&CREATE_PROJECT));
}

// REQ-PROJECT-101
#[test]
fn project_create_with_no_connection_reaching_the_repository_creates_nothing() {
    let (server, _directory, credential_path) = prepared_project(vec![
        github_bindings(),
        granted("acme/other"),
        gitlab_connections(&[]),
    ]);

    let output = run_create(
        &["widget", "--repository", "acme/widget"],
        &server,
        &credential_path,
    );

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("useful org integration repository list INTEGRATION"),
        "{stderr}"
    );
    assert_eq!(
        request_lines(&server.finish()),
        [
            LIST_BINDINGS,
            LIST_BINDING_REPOSITORIES,
            LIST_GITLAB_CONNECTIONS
        ]
    );
}

// REQ-PROJECT-101
#[test]
fn project_create_with_a_connection_reads_that_connection_alone() {
    let (server, _directory, credential_path) =
        prepared_project(vec![selected("group/widget"), created_project("gitlab")]);

    let output = run_create(
        &[
            "widget",
            "--repository",
            "group/widget",
            "--integration",
            GITLAB_CONNECTION_ID,
        ],
        &server,
        &credential_path,
    );

    assert_json_success(&output, "created");
    let requests = server.finish();
    let lines = request_lines(&requests);
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(reads_selected(lines[0]), "{lines:?}");
    assert_eq!(lines[1], CREATE_PROJECT);
    assert_eq!(
        request_body(&requests[1]),
        serde_json::json!({"name": "widget", "repository": gitlab_selection()})
    );
}

// REQ-PROJECT-101
#[test]
fn project_create_with_a_connection_id_and_a_repository_id_reads_nothing_first() {
    let (server, _directory, credential_path) = prepared_project(vec![created_project("github")]);

    let output = run_create(
        &[
            "widget",
            "--repository",
            REPOSITORY_ID,
            "--integration",
            INSTALLATION_ID,
        ],
        &server,
        &credential_path,
    );

    assert_json_success(&output, "created");
    let requests = server.finish();
    assert_eq!(request_lines(&requests), [CREATE_PROJECT]);
    assert_eq!(
        request_body(&requests[0]),
        serde_json::json!({"name": "widget", "repository": github_selection()})
    );
}

// REQ-PROJECT-101
#[test]
fn project_create_refuses_a_linear_connection_and_a_bare_repository_name_before_any_request() {
    for args in [
        &[
            "widget",
            "--repository",
            "acme/widget",
            "--integration",
            "lcn_01k0z6r1w8f4jy2m7q9v3x5abc",
        ][..],
        &["widget", "--repository", "widget"][..],
    ] {
        let (server, _directory, credential_path) = prepared_project(Vec::new());

        let output = run_create(args, &server, &credential_path);

        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
        assert!(server.finish().is_empty(), "{args:?}");
    }
}

// REQ-PROJECT-101
#[test]
fn project_create_passes_over_a_provider_whose_connections_it_may_not_read() {
    let mut gitlab = gitlab_connection();
    gitlab["state"] = "active".into();
    let (server, _directory, credential_path) = prepared_project(vec![
        problem_http_response(
            "403 Forbidden",
            serde_json::json!({
                "type": "https://api.usefulmachinery.com/problems/forbidden",
                "title": "Forbidden",
                "status": 403
            }),
        ),
        gitlab_connections(&[gitlab]),
        selected("group/widget"),
        created_project("gitlab"),
    ]);

    let output = run_create(
        &["widget", "--repository", "group/widget"],
        &server,
        &credential_path,
    );

    assert_json_success(&output, "created");
    let requests = server.finish();
    let lines = request_lines(&requests);
    assert_eq!(lines.len(), 4, "{lines:?}");
    assert_eq!(lines[..2], [LIST_BINDINGS, LIST_GITLAB_CONNECTIONS]);
    assert!(reads_selected(lines[2]), "{lines:?}");
    assert_eq!(lines[3], CREATE_PROJECT);
    assert_eq!(
        request_body(&requests[3]),
        serde_json::json!({"name": "widget", "repository": gitlab_selection()})
    );
}

/// `create widget --repository REPOSITORY_ID --integration INSTALLATION_ID` with the pools
/// `builders` and `shared`, the pool `PUT` answered with `assigned`.
fn create_with_two_pools(assigned: Vec<u8>) -> (Output, Vec<String>) {
    let pools = || {
        json_http_response(
            "200 OK",
            serde_json::json!({"items": [pool_body(), shared_pool_body()]}),
        )
    };
    let (server, _directory, credential_path) = prepared_project(vec![
        pools(),
        pools(),
        project_response(
            "201 Created",
            project_with_pools(&[(POOL_ID, "builders")]),
            true,
        ),
        assigned,
    ]);
    let output = run_create(
        &[
            "widget",
            "--repository",
            REPOSITORY_ID,
            "--integration",
            INSTALLATION_ID,
            "--pool",
            "builders",
            "--pool",
            "shared",
        ],
        &server,
        &credential_path,
    );
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [LIST_POOLS, LIST_POOLS, CREATE_PROJECT, PUT_POOLS]
    );
    assert_eq!(request_body(&requests[2])["runnerPoolId"], POOL_ID);
    assert_eq!(
        request_body(&requests[3]),
        serde_json::json!({"runnerPoolIds": [POOL_ID, SHARED_POOL_ID]})
    );
    assert_ne!(
        header_value(&requests[2], "idempotency-key"),
        header_value(&requests[3], "idempotency-key")
    );
    (output, requests)
}

// REQ-PROJECT-76
#[test]
fn project_create_with_several_pools_creates_and_then_assigns_them_all() {
    let both = project_with_pools(&[(POOL_ID, "builders"), (SHARED_POOL_ID, "shared")]);

    let (output, _) = create_with_two_pools(project_response("200 OK", both.clone(), false));

    let result = assert_json_success(&output, "created");
    assert_eq!(result["project"]["runnerPools"], both["runnerPools"]);
}

// REQ-PROJECT-76
#[test]
fn project_create_whose_pool_assignment_fails_reports_the_created_project() {
    let (output, _) = create_with_two_pools(problem_http_response(
        "409 Conflict",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/runner-pool-member-assigned",
            "title": "Conflict",
            "status": 409
        }),
    ));

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["outcome"], "conflict");
    assert_eq!(document["applied"], serde_json::json!(["created"]));
    assert_eq!(document["project"]["id"], PROJECT_ID);
    assert_eq!(
        document["project"]["runnerPools"],
        serde_json::json!([{"id": POOL_ID, "name": "builders"}])
    );
}

/// Runs `useful project update ARGS...` in the named organization.
fn run_update(args: &[&str], server: &ScriptedServer, credential_path: &str) -> Output {
    let mut arguments = vec!["project", "update"];
    arguments.extend(args);
    arguments.extend(["--org", ORGANIZATION, "--json", "--allow-insecure-http"]);
    run_project(&arguments, server, credential_path)
}

const PATCH_PROJECT: &str =
    "PATCH /api/v1/organizations/acme-research/projects/prj_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1";
const PUT_REPOSITORY: &str = "PUT /api/v1/organizations/acme-research/projects/prj_01k0z6r1w8f4jy2m7q9v3x5abc/repository HTTP/1.1";
const PATCH_REPOSITORY: &str = "PATCH /api/v1/organizations/acme-research/projects/prj_01k0z6r1w8f4jy2m7q9v3x5abc/repository HTTP/1.1";
const DELETE_REPOSITORY: &str = "DELETE /api/v1/organizations/acme-research/projects/prj_01k0z6r1w8f4jy2m7q9v3x5abc/repository HTTP/1.1";

// REQ-PROJECT-102
#[test]
fn project_update_sends_one_request_for_each_change_it_is_given() {
    let renamed = project_body("gadget", true, Some(repository_body("acme/widget", "main")));
    let branched = project_body(
        "widget",
        true,
        Some(repository_body("acme/widget", "release")),
    );
    let detached = project_body("widget", true, None);
    for (args, project, line, applied) in [
        (&["--name", "gadget"][..], renamed, PATCH_PROJECT, "renamed"),
        (
            &["--default-branch", "release"][..],
            branched,
            PATCH_REPOSITORY,
            "repository_updated",
        ),
        (
            &["--clear-repository", "--yes"][..],
            detached,
            DELETE_REPOSITORY,
            "repository_detached",
        ),
    ] {
        let (server, _directory, credential_path) =
            prepared_project(vec![project_response("200 OK", project.clone(), false)]);
        let mut arguments = vec![PROJECT_ID];
        arguments.extend(args);

        let output = run_update(&arguments, &server, &credential_path);

        let result = assert_json_success(&output, "updated");
        assert_eq!(result["applied"], serde_json::json!([applied]), "{args:?}");
        for field in ["name", "repository"] {
            assert_eq!(result["project"][field], project[field], "{args:?}");
        }
        let requests = server.finish();
        assert_eq!(request_lines(&requests), [line], "{args:?}");
        if line.starts_with("PATCH ") {
            assert_eq!(
                header_value(&requests[0], "content-type"),
                "application/merge-patch+json"
            );
        }
        match applied {
            "renamed" => assert_eq!(
                request_body(&requests[0]),
                serde_json::json!({"name": "gadget"})
            ),
            "repository_updated" => assert_eq!(
                request_body(&requests[0]),
                serde_json::json!({"defaultBranch": "release"})
            ),
            _ => assert_eq!(requests[0].split_once("\r\n\r\n").unwrap().1, ""),
        }
    }
}

/// `update widget --repository REPOSITORY_ID --integration INSTALLATION_ID --default-branch
/// release --name gadget`, its rename answered with `renamed`: the name is resolved, then the
/// repository is set with the branch, then the name is changed.
fn update_repository_and_name(renamed: Vec<u8>) -> (Output, Vec<String>) {
    let (server, _directory, credential_path) = prepared_project(vec![
        project_list_of(&[active_project_body()]),
        project_response("200 OK", rebound_project(), false),
        renamed,
    ]);
    let output = run_update(
        &[
            "widget",
            "--repository",
            REPOSITORY_ID,
            "--integration",
            INSTALLATION_ID,
            "--default-branch",
            "release",
            "--name",
            "gadget",
        ],
        &server,
        &credential_path,
    );
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [LIST_WITH_ARCHIVED, PUT_REPOSITORY, PATCH_PROJECT]
    );
    let mut selection = github_selection();
    selection["defaultBranch"] = serde_json::json!("release");
    assert_eq!(request_body(&requests[1]), selection);
    assert_eq!(
        request_body(&requests[2]),
        serde_json::json!({"name": "gadget"})
    );
    assert_ne!(
        header_value(&requests[1], "idempotency-key"),
        header_value(&requests[2], "idempotency-key")
    );
    (output, requests)
}

/// The project as the repository request of `update_repository_and_name` returns it.
fn rebound_project() -> serde_json::Value {
    project_body(
        "widget",
        true,
        Some(repository_body("acme/widget", "release")),
    )
}

// REQ-PROJECT-102
#[test]
fn project_update_sets_the_repository_before_it_renames() {
    let renamed = project_body(
        "gadget",
        true,
        Some(repository_body("acme/widget", "release")),
    );

    let (output, _) =
        update_repository_and_name(project_response("200 OK", renamed.clone(), false));

    let result = assert_json_success(&output, "updated");
    assert_eq!(
        result["applied"],
        serde_json::json!(["repository_set", "renamed"])
    );
    assert_eq!(result["project"]["name"], "gadget");
    assert_eq!(result["project"]["repository"], renamed["repository"]);
}

// REQ-PROJECT-102
#[test]
fn project_update_whose_rename_fails_reports_the_repository_it_set() {
    let (output, _) = update_repository_and_name(problem_http_response(
        "409 Conflict",
        serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/project-name-unavailable",
            "title": "Conflict",
            "status": 409
        }),
    ));

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["outcome"], "name_unavailable");
    assert_eq!(document["applied"], serde_json::json!(["repository_set"]));
    assert_eq!(document["project"]["name"], "widget");
    assert_eq!(
        document["project"]["repository"],
        rebound_project()["repository"]
    );
}

// REQ-PROJECT-101
#[test]
fn project_update_finds_the_connection_that_reaches_the_repository() {
    update_finds_the_connection(false);
}

// REQ-PROJECT-101, REQ-CONNECTION-108: `project update` takes the project ID `project show`
// printed and reaches the repository through the binding `org integration list` printed and
// `org integration reconnect` restored.
#[test]
fn a_shown_project_is_updated_through_the_binding_reconnected_before_it() {
    update_finds_the_connection(true);
}

/// `project update --repository` finding the binding that reaches the repository, alone or
/// `after_reconnect`: after `project show`, `org integration list` and `org integration
/// reconnect`, each given an ID the command before it printed.
fn update_finds_the_connection(after_reconnect: bool) {
    use super::github::{installation_body, installation_list, setup_session_response};
    let session = "ghs_01k0z6r1w8f4jy2m7q9v3x5abc";
    let setup_url =
        format!("https://github.example/apps/scherzo/installations/new?state={session}");
    let mut responses = Vec::new();
    if after_reconnect {
        responses.extend([
            json_http_response("200 OK", project_body("paper", true, None)),
            installation_list(installation_body("disconnected")),
            super::connection::no_authorizations(),
            installation_list(installation_body("disconnected")),
            setup_session_response(session, &setup_url),
            json_http_response("200 OK", installation_body("active")),
        ]);
    }
    let before_update = responses.len();
    responses.extend([
        github_bindings(),
        granted("acme/widget"),
        gitlab_connections(&[]),
        project_response("200 OK", active_project_body(), false),
    ]);
    let (server, _directory, credential_path) = prepared_project(responses);

    let project = if after_reconnect {
        let invoke = |args: &[&str]| {
            let mut args = args.to_vec();
            args.extend(["--org", ORGANIZATION, "--json", "--allow-insecure-http"]);
            let output = run_project(&args, &server, &credential_path);
            assert!(output.status.success(), "{args:?}: {output:?}");
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
        };
        let project = invoke(&["project", "show", PROJECT_ID]);
        let connections = invoke(&["org", "integration", "list", "--provider", "github"]);
        let binding = connections["items"][0]["id"].as_str().unwrap();
        let restored = invoke(&["org", "integration", "reconnect", binding]);
        assert_eq!(restored["installation"]["state"], "active");
        assert_eq!(restored["installation"]["id"], binding);
        project["project"]["id"].as_str().unwrap().to_owned()
    } else {
        PROJECT_ID.to_owned()
    };

    let output = run_update(
        &[&project, "--repository", "acme/widget"],
        &server,
        &credential_path,
    );

    assert_eq!(
        assert_json_success(&output, "updated")["applied"],
        serde_json::json!(["repository_set"])
    );
    let requests = server.finish();
    if after_reconnect {
        let organization = "/api/v1/organizations/acme-research";
        let show = format!("GET {organization}/projects/{PROJECT_ID} HTTP/1.1");
        let authorizations =
            format!("GET {organization}/connection-authorizations?limit=200 HTTP/1.1");
        let sessions = format!("POST {organization}/github/setup-sessions");
        assert_eq!(
            request_lines(&requests[..before_update]),
            [
                show.as_str(),
                LIST_BINDINGS,
                &authorizations,
                LIST_BINDINGS,
                &format!("{sessions} HTTP/1.1"),
                &format!("{sessions}/{session}/completion HTTP/1.1"),
            ]
        );
    }
    assert_eq!(
        request_lines(&requests[before_update..]),
        [
            LIST_BINDINGS,
            LIST_BINDING_REPOSITORIES,
            LIST_GITLAB_CONNECTIONS,
            PUT_REPOSITORY
        ]
    );
    assert_eq!(
        request_body(&requests[before_update + 3]),
        github_selection()
    );
}

// REQ-PROJECT-81
#[test]
fn project_create_retries_one_ambiguous_response() {
    let project = project_body(
        "widget",
        false,
        Some(repository_body("acme/widget", "main")),
    );
    let (server, _directory, credential_path) = prepared_project(vec![
        Vec::new(),
        project_response("201 Created", project, true),
    ]);

    let output = run_project(
        &[
            "project",
            "create",
            "widget",
            "--repository",
            REPOSITORY_ID,
            "--integration",
            INSTALLATION_ID,
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );

    assert_json_success(&output, "created");
    assert_eq!(server.finish().len(), 2);
}

// REQ-PROJECT-82
#[test]
fn project_create_rejects_success_without_required_identity_headers() {
    let project = project_body(
        "widget",
        false,
        Some(repository_body("acme/widget", "main")),
    );
    let responses = [
        json_http_response("201 Created", project.clone()),
        http_response_with_headers(
            "201 Created",
            Some("application/json"),
            &[
                ("Idempotency-Key", ECHO_IDEMPOTENCY_KEY),
                (
                    "Location",
                    "/v1/organizations/acme-research/projects/prj_wrong",
                ),
            ],
            &serde_json::to_vec(&project).unwrap(),
        ),
    ];

    for response in responses {
        let (server, _directory, credential_path) = prepared_project(vec![response]);
        let output = run_project(
            &[
                "project",
                "create",
                "widget",
                "--repository",
                REPOSITORY_ID,
                "--integration",
                INSTALLATION_ID,
                "--org",
                ORGANIZATION,
                "--json",
                "--allow-insecure-http",
            ],
            &server,
            &credential_path,
        );

        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["outcome"],
            "invalid_response"
        );
        server.finish();
    }
}

// REQ-PROJECT-78
#[test]
fn gitlab_project_create_bind_and_read_preserve_provider_identity() {
    let long_path = format!("group/subgroup/{}", "a".repeat(260));
    let repository = serde_json::json!({
        "connectionId": CONNECTION_ID,
        "providerKind": "gitlab",
        "gitlabConnectionId": GITLAB_CONNECTION_ID,
        "instanceUrl": "https://gitlab.com",
        "admissionDiagnostic": "gitlab_admission_closed",
        "providerRepositoryId": REPOSITORY_ID,
        "fullName": long_path,
        "defaultBranch": "main",
        "availability": "unavailable"
    });
    let mut project = project_body("widget", false, Some(repository.clone()));
    project["executionReadiness"] = serde_json::json!({
        "ready": false,
        "blockers": ["runner_pool_unassigned", "repository_unavailable"]
    });
    let (server, _directory, credential_path) = prepared_project(vec![
        json_http_response(
            "200 OK",
            serde_json::json!({
                "id": GITLAB_CONNECTION_ID, "organizationId": ORGANIZATION_ID,
                "instanceUrl": "https://gitlab.com", "state": "active", "credentialReason": null,
                "version": 5, "providerUser": {"id":"42","username":"automation-bot"},
                "credential": {"providerTokenId":"77","kind":"personal_access_token",
                    "accountUse":"dedicated_user","permissionProfile":"api",
                    "expiresAt":"2027-09-05T00:00:00Z","validatedAt":"2026-09-05T12:00:00Z",
                    "expiryNotice":"none"},
                "selectedRepositoryIds": [REPOSITORY_ID],
                "support": {"state":"supported","observedVersion":"18.0"},
                "createdAt":"2026-09-05T12:00:00Z", "updatedAt":"2026-09-05T12:01:00Z"
            }),
        ),
        project_response("201 Created", project.clone(), true),
        project_response("200 OK", project.clone(), false),
        json_http_response("200 OK", project),
    ]);
    // A project can bind only after an owner explicitly selects the provider ID.
    let selection = run_project(
        &[
            "org",
            "integration",
            "repository",
            "add",
            REPOSITORY_ID,
            "--integration",
            GITLAB_CONNECTION_ID,
            "--org",
            ORGANIZATION,
            "--expected-version",
            "4",
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    assert_json_success(&selection, "linked");
    let create = run_project(
        &[
            "project",
            "create",
            "widget",
            "--repository",
            REPOSITORY_ID,
            "--integration",
            GITLAB_CONNECTION_ID,
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    let created = assert_json_success(&create, "created");
    assert_eq!(created["project"]["repository"], repository);
    assert_eq!(created["project"]["executionReadiness"]["ready"], false);

    let bind = run_project(
        &[
            "project",
            "update",
            PROJECT_ID,
            "--repository",
            REPOSITORY_ID,
            "--integration",
            GITLAB_CONNECTION_ID,
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    let bind = assert_json_success(&bind, "updated");
    assert_eq!(bind["applied"], serde_json::json!(["repository_set"]));
    assert_eq!(bind["project"]["repository"], repository);
    let show = run_project(
        &[
            "project",
            "show",
            PROJECT_ID,
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    assert!(
        show.status.success(),
        "{}",
        String::from_utf8_lossy(&show.stderr)
    );
    let text = String::from_utf8(show.stdout).unwrap();
    assert!(text.contains(&format!("repository: {long_path}")));
    assert!(text.contains(&format!("GitLab connection: {GITLAB_CONNECTION_ID}")));
    assert!(text.contains(&format!("provider repository: {REPOSITORY_ID}")));
    assert!(text.contains("repository_unavailable"));
    assert!(text.contains("admission: GitLab run admission is closed"));

    let requests = server.finish();
    assert_eq!(requests.len(), 4);
    assert!(requests[0].starts_with(&format!(
        "PATCH /api/v1/organizations/{ORGANIZATION}/connections/gitlab/{GITLAB_CONNECTION_ID}/repository-selection "
    )));
    assert_eq!(
        request_body(&requests[0])["addProviderRepositoryIds"],
        serde_json::json!([REPOSITORY_ID])
    );
    for request in &requests[1..3] {
        let body = request_body(request);
        let selection = if body.get("repository").is_some() {
            &body["repository"]
        } else {
            &body
        };
        assert_eq!(selection["providerKind"], "gitlab");
        assert_eq!(selection["gitlabConnectionId"], GITLAB_CONNECTION_ID);
        assert!(selection.get("installationBindingId").is_none());
    }
}

// REQ-PROJECT-78: the closed-admission line follows the diagnostic, not the provider, so
// a GitLab project that reads ready while the deployment's admission is open prints none.
#[test]
fn ready_gitlab_project_prints_no_closed_admission_line() {
    let project = project_body(
        "widget",
        true,
        Some(serde_json::json!({
            "connectionId": CONNECTION_ID,
            "providerKind": "gitlab",
            "gitlabConnectionId": GITLAB_CONNECTION_ID,
            "instanceUrl": "https://gitlab.com",
            "providerRepositoryId": REPOSITORY_ID,
            "fullName": "group/sub/project",
            "defaultBranch": "main",
            "availability": "active"
        })),
    );
    let (server, _directory, credential_path) =
        prepared_project(vec![json_http_response("200 OK", project)]);
    let show = run_project(
        &[
            "project",
            "show",
            PROJECT_ID,
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    assert!(
        show.status.success(),
        "{}",
        String::from_utf8_lossy(&show.stderr)
    );
    let text = String::from_utf8(show.stdout).unwrap();
    assert!(
        text.lines().any(|line| line == "readiness: ready"),
        "{text}"
    );
    assert!(
        text.lines()
            .any(|line| line == format!("GitLab connection: {GITLAB_CONNECTION_ID}")),
        "{text}"
    );
    assert!(
        text.lines().all(|line| !line.starts_with("admission:")),
        "{text}"
    );
    server.finish();
}

// REQ-PROJECT-78: a bound repository is shown in full, its installation and provider ID
// included, since no other command prints the binding.
#[test]
fn project_human_output_exposes_readiness_and_blockers() {
    let project = project_body(
        "widget",
        false,
        Some(repository_body("acme/widget", "main")),
    );
    let (server, _directory, credential_path) =
        prepared_project(vec![json_http_response("200 OK", project)]);

    let output = run_project(
        &[
            "project",
            "show",
            PROJECT_ID,
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for field in [
        format!("project: {PROJECT_ID}"),
        "name: widget".to_owned(),
        "runner pool: none".to_owned(),
        "repository: acme/widget".to_owned(),
        format!("installation: {INSTALLATION_ID}"),
        format!("provider repository: {REPOSITORY_ID}"),
        "default branch: main".to_owned(),
        "readiness: blocked".to_owned(),
        "blockers: runner_pool_unassigned".to_owned(),
    ] {
        assert!(
            stdout.lines().any(|line| line == field),
            "missing {field:?}"
        );
    }
    server.finish();
}

fn show_project_human(project: serde_json::Value) -> Vec<String> {
    let (server, _directory, credential_path) =
        prepared_project(vec![json_http_response("200 OK", project)]);
    let output = run_project(
        &[
            "project",
            "show",
            PROJECT_ID,
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    server.finish();
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("runner pool"))
        .map(str::to_owned)
        .collect()
}

// REQ-PROJECT-78, REQ-PROJECT-90
#[test]
fn project_human_output_lists_every_pool_of_the_set() {
    let repository = Some(repository_body("acme/widget", "main"));
    let mut several = project_body("widget", true, repository.clone());
    several["runnerPools"] = serde_json::json!([
        {"id": POOL_ID, "name": "builders"},
        {"id": SHARED_POOL_ID, "name": "shared"}
    ]);
    assert_eq!(
        show_project_human(several),
        [
            format!("runner pool: builders ({POOL_ID})"),
            format!("runner pool: shared ({SHARED_POOL_ID})"),
        ]
    );

    let mut empty = project_body("widget", false, repository.clone());
    empty["runnerPools"] = serde_json::json!([]);
    assert_eq!(show_project_human(empty), ["runner pool: none"]);

    // A Cloud that predates the set omits `runnerPools`; its single pool is the set.
    assert_eq!(
        show_project_human(project_body("widget", true, repository)),
        [format!("runner pool: builders ({POOL_ID})")]
    );
}

const ARCHIVED_AT: &str = "2026-09-06T08:30:00Z";

fn archived_project_body() -> serde_json::Value {
    let mut project = project_body("widget", true, Some(repository_body("acme/widget", "main")));
    project["archivedAt"] = serde_json::json!(ARCHIVED_AT);
    project["updatedAt"] = serde_json::json!(ARCHIVED_AT);
    project
}

fn active_project_body() -> serde_json::Value {
    project_body("widget", true, Some(repository_body("acme/widget", "main")))
}

fn assert_bodyless_post(request: &str, verb: &str) {
    assert!(
        request.starts_with(&format!(
            "POST /api/v1/organizations/{ORGANIZATION}/projects/{PROJECT_ID}/{verb} HTTP/1.1\r\n"
        )),
        "{request}"
    );
    assert_eq!(request.split_once("\r\n\r\n").unwrap().1, "");
    let key = header_value(request, "idempotency-key");
    assert_eq!(key.len(), 64);
    assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
}

// REQ-PROJECT-75, REQ-PROJECT-79
#[test]
fn project_archive_and_unarchive_post_once_without_a_body() {
    for (verb, outcome, project) in [
        ("archive", "archived", archived_project_body()),
        ("unarchive", "unarchived", active_project_body()),
    ] {
        let (server, _directory, credential_path) =
            prepared_project(vec![project_response("200 OK", project, false)]);

        let output = run_project(
            &[
                "project",
                verb,
                PROJECT_ID,
                "--org",
                ORGANIZATION,
                "--json",
                "--allow-insecure-http",
            ],
            &server,
            &credential_path,
        );

        let value = assert_json_success(&output, outcome);
        assert_eq!(value["project"]["id"], PROJECT_ID);
        if verb == "archive" {
            assert_eq!(value["project"]["archivedAt"], ARCHIVED_AT);
        } else {
            assert!(value["project"].get("archivedAt").is_none());
        }
        let requests = server.finish();
        assert_eq!(requests.len(), 1);
        assert_bodyless_post(&requests[0], verb);
    }
}

// REQ-PROJECT-78
#[test]
fn project_human_output_shows_the_archive_time_only_when_archived() {
    for (verb, project, archived_line) in [
        (
            "archive",
            archived_project_body(),
            Some(format!("archived: {ARCHIVED_AT}")),
        ),
        ("unarchive", active_project_body(), None),
    ] {
        let (server, _directory, credential_path) =
            prepared_project(vec![project_response("200 OK", project, false)]);

        let output = run_project(
            &[
                "project",
                verb,
                PROJECT_ID,
                "--org",
                ORGANIZATION,
                "--allow-insecure-http",
            ],
            &server,
            &credential_path,
        );

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        let archived: Vec<_> = stdout
            .lines()
            .filter(|line| line.starts_with("archived"))
            .collect();
        assert_eq!(archived, archived_line.as_slice());
        server.finish();
    }
}

// REQ-PROJECT-76, REQ-PROJECT-78
#[test]
fn project_list_includes_archived_projects_only_when_asked_and_marks_them() {
    let mut active = active_project_body();
    active["id"] = serde_json::json!("prj_01k0z6r1w8f4jy2m7q9v3x5abd");
    let page = serde_json::json!({"items": [archived_project_body(), active]});
    let (server, _directory, credential_path) = prepared_project(vec![
        json_http_response("200 OK", page),
        json_http_response("200 OK", serde_json::json!({"items": []})),
    ]);

    let included = run_project(
        &[
            "project",
            "list",
            "--org",
            ORGANIZATION,
            "--include-archived",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );
    let default = run_project(
        &[
            "project",
            "list",
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );

    for output in [&included, &default] {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
    }
    let stdout = String::from_utf8(included.stdout).unwrap();
    let entries: Vec<_> = stdout
        .lines()
        .filter(|line| line.starts_with("project: "))
        .collect();
    assert_eq!(
        entries,
        [
            format!("project: {PROJECT_ID} · name: widget · readiness: ready · archived"),
            "project: prj_01k0z6r1w8f4jy2m7q9v3x5abd · name: widget · readiness: ready".to_owned(),
        ]
    );
    let requests = server.finish();
    assert!(requests[0].starts_with(&format!(
        "GET /api/v1/organizations/{ORGANIZATION}/projects?includeArchived=true HTTP/1.1\r\n"
    )));
    assert!(requests[1].starts_with(&format!(
        "GET /api/v1/organizations/{ORGANIZATION}/projects HTTP/1.1\r\n"
    )));
}

fn project_list_of(projects: &[serde_json::Value]) -> Vec<u8> {
    json_http_response("200 OK", serde_json::json!({"items": projects}))
}

const LIST_WITH_ARCHIVED: &str =
    "GET /api/v1/organizations/acme-research/projects?includeArchived=true HTTP/1.1";
const READ_PROJECT: &str =
    "GET /api/v1/organizations/acme-research/projects/prj_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1";

// REQ-PROJECT-75: with the organization named and the project by ID, `show` sends its one
// read and resolves nothing.
#[test]
fn project_show_by_id_in_a_named_organization_sends_only_its_read() {
    let (output, requests) = run_in_effect(
        &["project", "show", "--json"],
        vec![json_http_response("200 OK", active_project_body())],
        &["--org", ORGANIZATION, "--project", PROJECT_ID],
        &[],
    );

    assert_eq!(
        assert_json_success(&output, "found")["project"]["id"],
        PROJECT_ID
    );
    assert_eq!(request_lines(&requests), [READ_PROJECT]);
}

// REQ-PROJECT-75: a `PROJECT` name is looked up among the organization's projects, archived
// ones included, and the command then acts on the ID the list gave it.
#[test]
fn a_project_named_by_name_is_looked_up_and_then_read_or_changed_by_id() {
    let (output, requests) = run_in_effect(
        &["project", "show", "widget", "--json"],
        vec![
            project_list_of(&[active_project_body()]),
            json_http_response("200 OK", active_project_body()),
        ],
        &["--org", ORGANIZATION],
        &[],
    );
    assert_eq!(
        assert_json_success(&output, "found")["project"]["id"],
        PROJECT_ID
    );
    assert_eq!(request_lines(&requests), [LIST_WITH_ARCHIVED, READ_PROJECT]);

    let (output, requests) = run_in_effect(
        &["project", "unarchive", "widget", "--json"],
        vec![
            project_list_of(&[archived_project_body()]),
            project_response("200 OK", active_project_body(), false),
        ],
        &["--org", ORGANIZATION],
        &[],
    );
    assert_json_success(&output, "unarchived");
    assert_eq!(requests.len(), 2);
    assert_eq!(request_lines(&requests)[0], LIST_WITH_ARCHIVED);
    assert_bodyless_post(&requests[1], "unarchive");
}

// REQ-PROJECT-75: a name no project of the organization has is the family's `not_found`,
// with nothing sent after the list.
#[test]
fn a_project_name_no_project_has_is_not_found_after_the_list_alone() {
    let (output, requests) = run_in_effect(
        &["project", "show", "ghost", "--json"],
        vec![project_list_of(&[active_project_body()])],
        &["--org", ORGANIZATION],
        &[],
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["outcome"], "not_found");
    assert_eq!(request_lines(&requests), [LIST_WITH_ARCHIVED]);
}

// REQ-PROJECT-75: `list` acts in the organization in effect, here the caller's only
// membership, which it names by ID.
#[test]
fn project_list_acts_in_the_only_membership_by_its_id() {
    let (output, requests) = run_in_effect(
        &["project", "list", "--json"],
        vec![
            active_memberships(&[(ORGANIZATION_ID, ORGANIZATION)]),
            project_list_of(&[active_project_body()]),
        ],
        &[],
        &[],
    );

    assert_eq!(
        assert_json_success(&output, "listed")["items"][0]["id"],
        PROJECT_ID
    );
    assert_eq!(
        request_lines(&requests),
        [
            LIST_CURRENT_MEMBERSHIPS.trim_end(),
            &format!("GET /api/v1/organizations/{ORGANIZATION_ID}/projects HTTP/1.1"),
        ]
    );
}

// REQ-PROJECT-100: `show` with no `PROJECT` shows the project in effect, and with none in
// effect exits 2 naming `--project` before any request.
#[test]
fn project_show_without_a_project_shows_the_project_in_effect() {
    let (output, requests) = run_in_effect(
        &["project", "show", "--json"],
        Vec::new(),
        &["--org", ORGANIZATION],
        &[],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--project"),
        "{output:?}"
    );
    assert!(requests.is_empty());

    let git = acme_widgets_checkout();
    let (output, requests) = run_in_effect(
        &["project", "show", "--json"],
        vec![
            active_memberships(&[(ORGANIZATION_ID, ORGANIZATION)]),
            projects_of(ORGANIZATION_ID, PROJECT_ID, "acme/widgets"),
            json_http_response("200 OK", active_project_body()),
        ],
        &[],
        &[("PATH", git.path().to_str().unwrap())],
    );
    assert_eq!(
        assert_json_success(&output, "found")["project"]["id"],
        PROJECT_ID
    );
    assert_eq!(
        request_lines(&requests),
        [
            LIST_CURRENT_MEMBERSHIPS.trim_end(),
            &format!("GET /api/v1/organizations/{ORGANIZATION_ID}/projects HTTP/1.1"),
            &format!("GET /api/v1/organizations/{ORGANIZATION_ID}/projects/{PROJECT_ID} HTTP/1.1"),
        ]
    );
}

// REQ-PROJECT-100, INV-CLI-20
#[test]
fn two_projects_matching_the_checkout_do_not_select_a_project() {
    const OTHER_ORG: &str = "org_01k0z6r1w8f4jy2m7q9v3x5abd";
    const OTHER_PROJECT: &str = "prj_01k0z6r1w8f4jy2m7q9v3x5abd";
    let git = acme_widgets_checkout();
    let (output, requests) = run_in_effect(
        &["project", "show", "--json"],
        vec![
            active_memberships(&[(ORGANIZATION_ID, ORGANIZATION), (OTHER_ORG, "other")]),
            projects_of(ORGANIZATION_ID, PROJECT_ID, "acme/widgets"),
            projects_of(OTHER_ORG, OTHER_PROJECT, "acme/widgets"),
        ],
        &[],
        &[("PATH", git.path().to_str().unwrap())],
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
    assert_eq!(
        request_lines(&requests),
        [
            LIST_CURRENT_MEMBERSHIPS.trim_end(),
            &format!("GET /api/v1/organizations/{ORGANIZATION_ID}/projects HTTP/1.1"),
            &format!("GET /api/v1/organizations/{OTHER_ORG}/projects HTTP/1.1"),
        ]
    );
}

// REQ-PROJECT-81
#[test]
fn project_archive_retries_one_lost_response_with_the_same_key() {
    let (server, _directory, credential_path) = prepared_project(vec![
        Vec::new(),
        project_response("200 OK", archived_project_body(), false),
    ]);

    let output = run_project(
        &[
            "project",
            "archive",
            PROJECT_ID,
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );

    assert_json_success(&output, "archived");
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    for request in &requests {
        assert_bodyless_post(request, "archive");
    }
    assert_eq!(
        header_value(&requests[0], "idempotency-key"),
        header_value(&requests[1], "idempotency-key")
    );
}

// REQ-PROJECT-82
#[test]
fn project_archive_answered_with_another_project_is_an_invalid_response() {
    let mut other_project = archived_project_body();
    other_project["id"] = serde_json::json!("prj_01k0z6r1w8f4jy2m7q9v3x5abd");
    let (server, _directory, credential_path) =
        prepared_project(vec![project_response("200 OK", other_project, false)]);

    let output = run_project(
        &[
            "project",
            "archive",
            PROJECT_ID,
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["outcome"],
        "invalid_response"
    );
    server.finish();
}

// REQ-PROJECT-80
#[test]
fn project_api_errors_have_closed_json_outcomes_and_exit_codes() {
    let cases = [
        (
            vec![
                "project",
                "update",
                PROJECT_ID,
                "--default-branch",
                "stable",
                "--org",
                ORGANIZATION,
            ],
            "404 Not Found",
            "https://api.usefulmachinery.com/problems/repository-not-bound",
            "repository_not_bound",
            1,
        ),
        (
            vec![
                "project",
                "create",
                "widget",
                "--repository",
                REPOSITORY_ID,
                "--integration",
                INSTALLATION_ID,
                "--org",
                ORGANIZATION,
            ],
            "409 Conflict",
            "https://api.usefulmachinery.com/problems/project-name-unavailable",
            "name_unavailable",
            1,
        ),
        (
            vec![
                "project",
                "create",
                "widget",
                "--repository",
                REPOSITORY_ID,
                "--integration",
                INSTALLATION_ID,
                "--org",
                ORGANIZATION,
            ],
            "409 Conflict",
            "https://api.usefulmachinery.com/problems/source-connection-conflict",
            "source_conflict",
            1,
        ),
        (
            vec![
                "project",
                "create",
                "widget",
                "--repository",
                REPOSITORY_ID,
                "--integration",
                GITLAB_CONNECTION_ID,
                "--org",
                ORGANIZATION,
            ],
            "409 Conflict",
            "https://api.usefulmachinery.com/problems/repository-unavailable",
            "repository_unavailable",
            1,
        ),
        (
            vec![
                "project",
                "create",
                "widget",
                "--repository",
                REPOSITORY_ID,
                "--integration",
                INSTALLATION_ID,
                "--org",
                ORGANIZATION,
            ],
            "429 Too Many Requests",
            "https://api.usefulmachinery.com/problems/rate-limit-exceeded",
            "rate_limited",
            4,
        ),
        (
            vec![
                "project",
                "create",
                "widget",
                "--repository",
                REPOSITORY_ID,
                "--integration",
                INSTALLATION_ID,
                "--org",
                ORGANIZATION,
            ],
            "503 Service Unavailable",
            "https://api.usefulmachinery.com/problems/provider-unavailable",
            "provider_unavailable",
            4,
        ),
        (
            vec![
                "project",
                "update",
                PROJECT_ID,
                "--repository",
                REPOSITORY_ID,
                "--integration",
                INSTALLATION_ID,
                "--org",
                ORGANIZATION,
            ],
            "503 Service Unavailable",
            "https://api.usefulmachinery.com/problems/provider-unavailable",
            "provider_unavailable",
            4,
        ),
        (
            vec![
                "project",
                "update",
                PROJECT_ID,
                "--name",
                "widget",
                "--org",
                ORGANIZATION,
            ],
            "409 Conflict",
            "https://api.usefulmachinery.com/problems/project-archived",
            "project_archived",
            1,
        ),
        (
            vec!["project", "unarchive", PROJECT_ID, "--org", ORGANIZATION],
            "409 Conflict",
            "https://api.usefulmachinery.com/problems/quantity-limit-reached",
            "quantity_limit_reached",
            1,
        ),
    ];

    for (mut args, status, problem_type, expected_outcome, expected_status) in cases {
        let problem = serde_json::json!({
            "type": problem_type,
            "title": "private-project-problem-title",
            "status": status.split_whitespace().next().unwrap().parse::<u16>().unwrap(),
            "detail": "private-project-problem-detail"
        });
        let retry_after = match expected_outcome {
            "rate_limited" => Some(42),
            "provider_unavailable" => Some(60),
            _ => None,
        };
        let response = if let Some(retry_after) = retry_after {
            http_response_with_headers(
                status,
                Some("application/problem+json"),
                &[("Retry-After", retry_after.to_string().as_str())],
                &serde_json::to_vec(&problem).unwrap(),
            )
        } else {
            problem_http_response(status, problem)
        };
        let (server, _directory, credential_path) = prepared_project(vec![response]);
        args.extend(["--json", "--allow-insecure-http"]);

        let output = run_project(&args, &server, &credential_path);

        assert_eq!(output.status.code(), Some(expected_status));
        assert!(output.stderr.is_empty());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["outcome"], expected_outcome);
        if let Some(retry_after) = retry_after {
            assert_eq!(value["retryAfter"], retry_after);
        } else {
            assert!(value.get("retryAfter").is_none());
        }
        assert!(value.get("title").is_none());
        assert!(value.get("detail").is_none());
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(!text.contains("private-project-problem"));
        assert!(!text.contains(TOKEN));
        server.finish();
    }
}

// REQ-PROJECT-82
#[test]
fn project_mutation_rejects_a_different_project_identity() {
    let mut other_project = project_body(
        "other-project",
        true,
        Some(repository_body("acme/other", "main")),
    );
    other_project["id"] = serde_json::json!("prj_01k0z6r1w8f4jy2m7q9v3x5abd");
    let (server, _directory, credential_path) = prepared_project(vec![
        json_http_response("200 OK", pool_body()),
        json_http_response("200 OK", project_with_pools(&[])),
        project_response("200 OK", other_project, false),
    ]);

    let output = run_pool(&["add", POOL_ID], &server, &credential_path);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["outcome"],
        "invalid_response"
    );
    server.finish();
}

// REQ-PROJECT-82
#[test]
fn project_rate_limit_requires_a_positive_retry_after() {
    for retry_after in [None, Some("0"), Some("invalid")] {
        let body = serde_json::to_vec(&serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/rate-limit-exceeded",
            "title": "Rate limited",
            "status": 429
        }))
        .unwrap();
        let headers = retry_after
            .map(|value| vec![("Retry-After", value)])
            .unwrap_or_default();
        let response = http_response_with_headers(
            "429 Too Many Requests",
            Some("application/problem+json"),
            &headers,
            &body,
        );
        let (server, _directory, credential_path) = prepared_project(vec![response]);

        let output = run_project(
            &[
                "project",
                "create",
                "widget",
                "--repository",
                REPOSITORY_ID,
                "--integration",
                INSTALLATION_ID,
                "--org",
                ORGANIZATION,
                "--json",
                "--allow-insecure-http",
            ],
            &server,
            &credential_path,
        );

        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["outcome"],
            "invalid_response"
        );
        server.finish();
    }
}

// REQ-PROJECT-82
#[test]
fn project_provider_unavailable_requires_a_positive_retry_after() {
    for retry_after in [None, Some("0"), Some("invalid")] {
        let body = serde_json::to_vec(&serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/provider-unavailable",
            "title": "Provider unavailable",
            "status": 503
        }))
        .unwrap();
        let headers = retry_after
            .map(|value| vec![("Retry-After", value)])
            .unwrap_or_default();
        let response = http_response_with_headers(
            "503 Service Unavailable",
            Some("application/problem+json"),
            &headers,
            &body,
        );
        let (server, _directory, credential_path) = prepared_project(vec![response]);

        let output = run_project(
            &[
                "project",
                "create",
                "widget",
                "--repository",
                REPOSITORY_ID,
                "--integration",
                INSTALLATION_ID,
                "--org",
                ORGANIZATION,
                "--json",
                "--allow-insecure-http",
            ],
            &server,
            &credential_path,
        );

        assert_eq!(output.status.code(), Some(1));
        assert!(output.stderr.is_empty());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["outcome"],
            "invalid_response"
        );
        server.finish();
    }
}

// REQ-PROJECT-82
#[test]
fn inconsistent_project_readiness_is_an_invalid_response() {
    let mut project = project_body(
        "widget",
        false,
        Some(repository_body("acme/widget", "main")),
    );
    project["executionReadiness"] = serde_json::json!({"ready": true, "blockers": []});
    let (server, _directory, credential_path) =
        prepared_project(vec![json_http_response("200 OK", project)]);

    let output = run_project(
        &[
            "project",
            "show",
            PROJECT_ID,
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["outcome"],
        "invalid_response"
    );
    server.finish();
}

// REQ-PROJECT-82, REQ-PROJECT-107
#[test]
fn a_pool_set_that_disagrees_with_the_single_pool_is_an_invalid_response() {
    let repository = Some(repository_body("acme/widget", "main"));
    let mut first_differs = project_body("widget", true, repository.clone());
    first_differs["runnerPools"] = serde_json::json!([
        {"id": SHARED_POOL_ID, "name": "shared"},
        {"id": POOL_ID, "name": "builders"}
    ]);
    let mut set_without_single = project_body("widget", false, repository.clone());
    set_without_single["runnerPools"] = serde_json::json!([{"id": POOL_ID, "name": "builders"}]);
    let mut single_without_set = project_body("widget", true, repository);
    single_without_set["runnerPools"] = serde_json::json!([]);

    for project in [first_differs, set_without_single, single_without_set] {
        let (server, _directory, credential_path) =
            prepared_project(vec![json_http_response("200 OK", project.clone())]);
        let output = run_project(
            &[
                "project",
                "show",
                PROJECT_ID,
                "--org",
                ORGANIZATION,
                "--json",
                "--allow-insecure-http",
            ],
            &server,
            &credential_path,
        );

        assert_eq!(output.status.code(), Some(1), "{project}");
        assert!(output.stderr.is_empty());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["outcome"],
            "invalid_response",
            "{project}"
        );
        server.finish();
    }
}

// REQ-PROJECT-107
#[test]
fn a_project_without_a_pool_set_is_read_as_its_single_pool() {
    let project = project_body("widget", true, Some(repository_body("acme/widget", "main")));
    let (server, _directory, credential_path) =
        prepared_project(vec![json_http_response("200 OK", project)]);

    let output = run_project(
        &[
            "project",
            "show",
            PROJECT_ID,
            "--org",
            ORGANIZATION,
            "--json",
            "--allow-insecure-http",
        ],
        &server,
        &credential_path,
    );

    let result = assert_json_success(&output, "found");
    assert_eq!(
        result["project"]["runnerPools"],
        serde_json::json!([{"id": POOL_ID, "name": "builders"}])
    );
    server.finish();
}
