use super::*;

use super::workflow_doctor::{connection_page, held as held_grant, requirement};

pub(super) const TOKEN: &str = "unique-grant-list-session-token";
pub(super) const OAUTH_GRANT_ID: &str = "pgr_01k0z6r1w8f4jy2m7q9v3x5abc";
pub(super) const REVOKED_OAUTH_GRANT_ID: &str = "pgr_01k0z6r1w8f4jy2m7q9v3x5abd";
pub(super) const NATIVE_GRANT_ID: &str = "agl_01k0z6r1w8f4jy2m7q9v3x5abc";
const OTHER_NATIVE_GRANT_ID: &str = "agl_01k0z6r1w8f4jy2m7q9v3x5abd";
pub(super) const IDENTITY_ID: &str = "idn_01k0z6r1w8f4jy2m7q9v3x5abc";
pub(super) const ORGANIZATION_ID: &str = "org_01k0z6r1w8f4jy2m7q9v3x5abc";
pub(super) const RUNNER_ID: &str = "rnr_01k0z6r1w8f4jy2m7q9v3x5abc";
pub(super) const ENDED_RUNNER_ID: &str = "rnr_01k0z6r1w8f4jy2m7q9v3x5abd";
const RUN_ID: &str = "run_01k0z6r1w8f4jy2m7q9v3x5abc";
const EMAIL: &str = "ada@example.test";
// Material no fixture is meant to carry: every grant below carries it in a member no model
// names, so it stands for anything a response might wrongly add.
pub(super) const SENTINEL: &str = "private-grant-list-material-sentinel";

pub(super) fn prepared(
    responses: Vec<Vec<u8>>,
) -> (ScriptedServer, tempfile::TempDir, std::path::PathBuf) {
    let server = ScriptedServer::respond(responses);
    let directory = private_credential_directory();
    let path = directory.path().join("credentials.json");
    write_credential_fixture_for_deployment(
        &path,
        &server.api_url,
        &server.issuer,
        TOKEN,
        "2999-01-01T00:00:00Z",
    );
    (server, directory, path)
}

pub(super) fn run_grant(server: &ScriptedServer, credential: &Path, args: &[&str]) -> Output {
    let mut arguments = vec!["account", "integration"];
    arguments.extend_from_slice(args);
    arguments.push("--allow-insecure-http");
    let environment = deployment_environment_with_issuer(
        &server.api_url,
        &server.issuer,
        credential.to_str().unwrap(),
    );
    let output = run_with_env(&arguments, &environment);
    assert_no_secret_output(&output, &[SENTINEL, TOKEN]);
    output
}

fn with_material(mut grant: serde_json::Value) -> serde_json::Value {
    grant["material"] = SENTINEL.into();
    grant
}

pub(super) fn page(items: &[serde_json::Value], next_cursor: Option<&str>) -> Vec<u8> {
    let items: Vec<_> = items.iter().cloned().map(with_material).collect();
    let mut body = serde_json::json!({"items": items});
    if let Some(cursor) = next_cursor {
        body["nextCursor"] = cursor.into();
    }
    json_http_response("200 OK", body)
}

pub(super) fn one(grant: &serde_json::Value) -> Vec<u8> {
    json_http_response("200 OK", with_material(grant.clone()))
}

// A GitHub grant authorized for one runner.
pub(super) fn oauth_grant(id: &str, provider: &str, state: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "kind": "oauth",
        "provider": provider,
        "state": state,
        "generation": 1,
        "createdAt": "2026-11-01T08:00:00Z",
        "authorizations": [{
            "id": "pga_01k0z6r1w8f4jy2m7q9v3x5abc",
            "runnerId": RUNNER_ID,
            "organizationId": ORGANIZATION_ID,
            "createdAt": "2026-11-01T08:05:00Z"
        }],
        "identityId": IDENTITY_ID,
        "scopes": ["repo", "read:org"],
        "lastUsedAt": "2026-11-04T08:00:00Z",
        "accessExpiresAt": "2026-11-04T09:00:00Z",
        "refreshExpiresAt": "2027-05-01T08:00:00Z"
    })
}

// The GitHub grant with no runner authorized.
pub(super) fn oauth_grant_unauthorized(id: &str) -> serde_json::Value {
    let mut grant = oauth_grant(id, "github", "active");
    grant["authorizations"] = serde_json::json!([]);
    grant
}

// A Codex grant with no runner authorized.
fn native_grant(id: &str, state: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "kind": "native",
        "provider": "codex",
        "state": state,
        "generation": 2,
        "createdAt": "2026-11-01T09:00:00Z",
        "authorizations": [],
        "organizationId": ORGANIZATION_ID,
        "label": "build laptop",
        "recordSchemaVersion": 1,
        "keyVersion": 1,
        "importedAt": "2026-11-02T10:00:00Z",
        "endedAuthorizations": []
    })
}

// The Codex grant authorized for one runner, which reported it ready and accepted at its last
// use, after another runner's authorization ended while it was serving a run.
pub(super) fn native_grant_in_use() -> serde_json::Value {
    let mut grant = native_grant(NATIVE_GRANT_ID, "active");
    grant["authorizations"] = serde_json::json!([{
        "id": "aga_01k0z6r1w8f4jy2m7q9v3x5abc",
        "runnerId": RUNNER_ID,
        "organizationId": ORGANIZATION_ID,
        "createdAt": "2026-11-02T10:05:00Z",
        "delivery": {"generation": 2, "deliveredAt": "2026-11-02T10:06:00Z"},
        "report": {
            "state": "ready",
            "generation": 2,
            "lastUse": "accepted",
            "reportedAt": "2026-11-02T10:07:00Z"
        }
    }]);
    grant["endedAuthorizations"] = serde_json::json!([{
        "id": "aga_01k0z6r1w8f4jy2m7q9v3x5abd",
        "runnerId": ENDED_RUNNER_ID,
        "createdAt": "2026-11-01T09:10:00Z",
        "delivery": {"generation": 1, "deliveredAt": "2026-11-01T09:11:00Z"},
        "endedAt": "2026-11-03T09:00:00Z",
        "removal": {"state": "pending"},
        "stop": {
            "runId": RUN_ID,
            "cancellationRequestId": "cmd_01k0z6r1w8f4jy2m7q9v3x5abc",
            "requestedAt": "2026-11-03T09:00:01Z"
        }
    }]);
    grant
}

pub(super) fn identities(items: serde_json::Value) -> Vec<u8> {
    json_http_response("200 OK", serde_json::json!({"items": items}))
}

pub(super) fn ada() -> serde_json::Value {
    serde_json::json!([{
        "id": IDENTITY_ID,
        "kind": "oidc",
        "issuer": "https://github.com",
        "subject": "1024",
        "assertedEmail": EMAIL,
        "emailVerified": true,
        "createdAt": "2026-11-01T08:00:00Z",
        "current": false
    }])
}

pub(super) fn organization() -> Vec<u8> {
    json_http_response(
        "200 OK",
        serde_json::json!({
            "id": ORGANIZATION_ID,
            "state": "active",
            "displayName": "Acme",
            "slug": "acme",
            "createdAt": "2026-11-01T07:00:00Z",
            "updatedAt": "2026-11-01T07:00:00Z"
        }),
    )
}

pub(super) fn problem(status: &str, code: u16, slug: &str) -> Vec<u8> {
    problem_http_response(
        status,
        serde_json::json!({
            "type": format!("https://api.usefulmachinery.com/problems/{slug}"),
            "title": "Grant result",
            "status": code
        }),
    )
}

pub(super) fn json_output(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

pub(super) fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

pub(super) fn request_lines(requests: &[String]) -> Vec<&str> {
    requests
        .iter()
        .map(|request| request.lines().next().unwrap())
        .collect()
}

/// Every request carried the member's session, and none went to the earlier agent-login
/// resource.
fn assert_member_requests(requests: &[String]) {
    for request in requests {
        assert_eq!(
            header_value(request, "authorization"),
            format!("Bearer {TOKEN}")
        );
        assert!(!request.contains("/agent-logins"), "{request}");
    }
}

fn not_connected(provider: &str) -> serde_json::Value {
    serde_json::json!({
        "provider": provider,
        "availability": "not_connected",
        "nextAction": "connect"
    })
}

/// Every command a printed next action names is a `useful account integration` command or
/// `useful runner sync`, and none of the earlier commands is named anywhere in `text`.
pub(super) fn assert_next_actions_name_the_grant_commands(text: &str) {
    let mut commands = 0;
    for line in text.lines().filter(|line| line.contains("next action:")) {
        for command in line.split('`').skip(1).step_by(2) {
            commands += 1;
            assert!(
                command.starts_with("useful account integration ")
                    || command == "useful runner sync",
                "{line}"
            );
        }
    }
    assert!(commands > 0, "no next action names a command in\n{text}");
    for earlier in [
        "useful auth agent-login",
        "useful auth grant",
        "useful runner agent-login",
        "useful runner grant",
    ] {
        assert!(!text.contains(earlier), "{earlier} in\n{text}");
    }
}

// The two pages of the member's grants: an active GitHub grant, then an active Codex grant and
// a revoked Linear grant.
fn two_pages() -> [Vec<u8>; 2] {
    [
        page(
            &[oauth_grant(OAUTH_GRANT_ID, "github", "active")],
            Some("grants-2"),
        ),
        page(
            &[
                native_grant(NATIVE_GRANT_ID, "active"),
                oauth_grant(REVOKED_OAUTH_GRANT_ID, "linear", "revoked"),
            ],
            None,
        ),
    ]
}

pub(super) const LIST_FIRST_PAGE: &str =
    "GET /api/v1/me/grants?kind=all&limit=200&vocabulary=2 HTTP/1.1";
const LIST_SECOND_PAGE: &str =
    "GET /api/v1/me/grants?kind=all&limit=200&cursor=grants-2&vocabulary=2 HTTP/1.1";
pub(super) const READ_IDENTITIES: &str =
    "GET /api/v1/me/identities?limit=200&vocabulary=2 HTTP/1.1";
const READ_ORGANIZATION: &str = "GET /api/v1/organizations/org_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1";
const READ_USES: &str =
    "GET /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc/uses?limit=20&vocabulary=2 HTTP/1.1";

#[test]
fn list_prints_every_grant_with_its_account_runners_and_status_and_names_the_rest() {
    let mut responses = Vec::new();
    for _ in 0..2 {
        responses.extend(two_pages());
        responses.push(predating_served());
        responses.push(organization());
        responses.push(identities(ada()));
    }
    let (server, _directory, credential) = prepared(responses);
    let json = run_grant(&server, &credential, &["list", "--json"]);
    let human = run_grant(&server, &credential, &["list"]);

    assert_eq!(
        json.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    assert_eq!(
        json_output(&json),
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "outcome": "listed",
            "grants": [
                {
                    "id": OAUTH_GRANT_ID,
                    "provider": "github",
                    "kind": "oauth",
                    "side": "member",
                    "account": {"kind": "identity", "id": IDENTITY_ID, "name": EMAIL},
                    "state": "active",
                    "generation": 1,
                    "createdAt": "2026-11-01T08:00:00Z",
                    "authorizations": [{
                        "id": "pga_01k0z6r1w8f4jy2m7q9v3x5abc",
                        "runnerId": RUNNER_ID,
                        "organizationId": ORGANIZATION_ID,
                        "createdAt": "2026-11-01T08:05:00Z",
                        "access": "direct",
                        "availability": "available",
                        "nextAction": "none"
                    }]
                },
                {
                    "id": NATIVE_GRANT_ID,
                    "provider": "codex",
                    "kind": "native",
                    "side": "member",
                    "account": {"kind": "organization", "id": ORGANIZATION_ID, "name": "acme"},
                    "label": "build laptop",
                    "state": "active",
                    "generation": 2,
                    "createdAt": "2026-11-01T09:00:00Z",
                    "authorizations": [],
                    "availability": "not_connected",
                    "nextAction": "authorize_runner"
                }
            ],
            // A deployment that predates the served read serves no token service, so no token
            // list is read.
            "tokens": [],
            "notConnected": [
                not_connected("gitlab.com"),
                not_connected("linear"),
                not_connected("claude_code")
            ]
        })
    );
    assert!(json.stderr.is_empty());

    assert_eq!(human.status.code(), Some(0));
    let text = stdout(&human);
    let (grants, rest) = text.split_once("── not connected ──").unwrap();
    let (oauth, native) = grants.split_once(NATIVE_GRANT_ID).unwrap();
    for name in [
        OAUTH_GRANT_ID,
        "provider: github",
        "kind: oauth",
        EMAIL,
        IDENTITY_ID,
        "state: active",
        "generation: 1",
        RUNNER_ID,
        "availability: available",
    ] {
        assert!(oauth.contains(name), "missing {name:?} in\n{text}");
    }
    for name in [
        "provider: codex",
        "kind: native",
        "acme",
        ORGANIZATION_ID,
        "generation: 2",
        "authorizations: none",
        "availability: not_connected",
        "next action: authorize_runner",
    ] {
        assert!(native.contains(name), "missing {name:?} in\n{text}");
    }
    for name in ["gitlab.com", "linear", "claude_code"] {
        assert!(rest.contains(name), "missing {name:?} in\n{text}");
    }
    assert!(!text.contains(REVOKED_OAUTH_GRANT_ID), "{text}");
    assert_next_actions_name_the_grant_commands(&text);

    let requests = server.finish();
    assert_member_requests(&requests);
    let expected = [
        LIST_FIRST_PAGE,
        LIST_SECOND_PAGE,
        READ_SERVED,
        READ_ORGANIZATION,
        READ_IDENTITIES,
    ];
    assert_eq!(request_lines(&requests[..5]), expected);
    assert_eq!(request_lines(&requests[5..]), expected);
}

#[test]
fn an_account_the_member_cannot_name_is_printed_by_its_id() {
    let (server, _directory, credential) = prepared(vec![
        page(
            &[
                oauth_grant(OAUTH_GRANT_ID, "github", "active"),
                native_grant(NATIVE_GRANT_ID, "active"),
            ],
            None,
        ),
        predating_served(),
        problem("404 Not Found", 404, "not-found"),
        identities(serde_json::json!([])),
    ]);
    let output = run_grant(&server, &credential, &["list", "--json"]);

    assert_eq!(output.status.code(), Some(0));
    let document = json_output(&output);
    assert_eq!(
        document["grants"][0]["account"],
        serde_json::json!({"kind": "identity", "id": IDENTITY_ID})
    );
    assert_eq!(
        document["grants"][1]["account"],
        serde_json::json!({"kind": "organization", "id": ORGANIZATION_ID})
    );
    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [
            LIST_FIRST_PAGE,
            READ_SERVED,
            READ_ORGANIZATION,
            READ_IDENTITIES
        ]
    );
}

// SC-GRANTAUTH-1, SC-GRANTAUTH-4
#[test]
fn list_shows_empty_pool_and_each_runners_direct_or_pool_access() {
    let mut empty = oauth_grant_unauthorized(OAUTH_GRANT_ID);
    let mut pool = pool_authorization("pga_01k0z6r1w8f4jy2m7q9v3x5abf", ORGANIZATION_ID);
    empty["authorizations"] = serde_json::json!([pool]);
    let mut covered = oauth_grant(LINEAR_GRANT_ID, "linear", "active");
    let mut direct = covered["authorizations"][0].clone();
    direct["id"] = "pga_01k0z6r1w8f4jy2m7q9v3x5abd".into();
    direct["runnerId"] = GLOBEX_RUNNER_ID.into();
    pool["runners"] = serde_json::json!([{"runnerId": RUNNER_ID}, {"runnerId": ENDED_RUNNER_ID}]);
    covered["authorizations"]
        .as_array_mut()
        .unwrap()
        .extend([direct, pool]);
    let grants = page(&[empty, covered], None);
    let responses = [grants, predating_served(), identities(ada())];
    let (server, _directory, credential) = prepared([responses.clone(), responses].concat());
    let document = json_output(&run_grant(&server, &credential, &["list", "--json"]));
    let empty = &document["grants"][0];
    assert_eq!(empty["authorizations"][0]["runnerPoolId"], POOL_ID);
    assert_eq!(empty["authorizations"][0]["runners"], serde_json::json!([]));
    assert!(empty.get("nextAction").is_none());
    let authorizations = &document["grants"][1]["authorizations"];
    assert_eq!(authorizations[0]["access"], "both");
    assert_eq!(authorizations[1]["access"], "direct");
    let runners = &authorizations[2]["runners"];
    assert_eq!(runners[0]["runnerId"], RUNNER_ID);
    assert_eq!(runners[0]["access"], "both");
    assert_eq!(runners[1]["runnerId"], ENDED_RUNNER_ID);
    assert_eq!(runners[1]["access"], "pool");
    assert_eq!(runners[1]["availability"], "available");
    let human = stdout(&run_grant(&server, &credential, &["list"]));
    assert!(human.contains(&format!("pool: {POOL_ID} (personal)")));
    assert!(human.contains("runners: none"));
    server.finish();
}

// SC-GRANTAUTH-2, SC-GRANTAUTH-3
#[test]
fn show_reports_pool_runners_delivery_conflict_and_ended_removal() {
    let mut grant = native_grant_in_use();
    grant["provider"] = "claude_code".into();
    let moved = &mut grant["endedAuthorizations"][0];
    moved.as_object_mut().unwrap().remove("stop");
    moved["removal"] =
        serde_json::json!({"state": "confirmed", "confirmedAt": "2026-11-03T09:01:00Z"});
    let exchange = grant["authorizations"][0].clone();
    let mut pool = pool_authorization("aga_01k0z6r1w8f4jy2m7q9v3x5abf", ORGANIZATION_ID);
    pool["runners"] = serde_json::json!([
        {"runnerId": RUNNER_ID, "conflict": false, "delivery": exchange["delivery"], "report": exchange["report"]},
        {"runnerId": GLOBEX_RUNNER_ID, "conflict": true}
    ]);
    grant["authorizations"] = serde_json::json!([pool]);
    let (server, _directory, credential) = prepared(vec![one(&grant), organization()]);
    let document = json_output(&run_grant(
        &server,
        &credential,
        &["show", NATIVE_GRANT_ID, "--json"],
    ));
    let shown = &document["grant"];
    let runners = &shown["authorizations"][0]["runners"];
    assert_eq!(runners[0]["delivery"], exchange["delivery"]);
    assert_eq!(runners[0]["report"], exchange["report"]);
    assert!(runners[0].get("conflict").is_none());
    assert_eq!(runners[1]["conflict"], true);
    assert_eq!(runners[1]["availability"], "not_delivered");
    assert_eq!(runners[1]["nextAction"], "resolve_runner_conflict");
    let ended = &shown["endedAuthorizations"][0];
    assert_eq!(ended["runnerId"], ENDED_RUNNER_ID);
    assert_eq!(ended["removal"], grant["endedAuthorizations"][0]["removal"]);
    server.finish();
}

#[test]
fn list_names_the_command_that_authorizes_a_runner_for_an_oauth_grant_with_none() {
    let responses = vec![
        page(&[oauth_grant_unauthorized(OAUTH_GRANT_ID)], None),
        predating_served(),
        identities(ada()),
        page(&[oauth_grant_unauthorized(OAUTH_GRANT_ID)], None),
        predating_served(),
        identities(ada()),
    ];
    let (server, _directory, credential) = prepared(responses);
    let json = run_grant(&server, &credential, &["list", "--json"]);
    let human = run_grant(&server, &credential, &["list"]);

    assert_eq!(
        json.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let grant = &json_output(&json)["grants"][0];
    assert_eq!(grant["id"], OAUTH_GRANT_ID);
    assert_eq!(grant["authorizations"], serde_json::json!([]));
    assert_eq!(grant["availability"], "not_connected");
    assert_eq!(grant["nextAction"], "authorize_runner");

    assert_eq!(human.status.code(), Some(0));
    let text = stdout(&human);
    let (grants, _) = text.split_once("── not connected ──").unwrap();
    let line = grants
        .lines()
        .find(|line| line.contains("next action:"))
        .unwrap_or_else(|| panic!("no next action in\n{text}"));
    let commands: Vec<_> = line.split('`').skip(1).step_by(2).collect();
    assert!(
        line.trim_start()
            .starts_with("next action: authorize_runner"),
        "{line}"
    );
    assert_eq!(
        commands,
        [format!(
            "useful account integration authorize {OAUTH_GRANT_ID} --runner RUNNER --yes"
        )],
        "{line}"
    );
    server.finish();
}

#[test]
fn show_prints_a_native_grants_exchange_and_ended_authorizations() {
    let grant = native_grant_in_use();
    let (server, _directory, credential) = prepared(vec![
        one(&grant),
        organization(),
        one(&grant),
        organization(),
    ]);
    let json = run_grant(&server, &credential, &["show", NATIVE_GRANT_ID, "--json"]);
    let human = run_grant(&server, &credential, &["show", NATIVE_GRANT_ID]);

    assert_eq!(
        json.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let mut authorization = grant["authorizations"][0].clone();
    authorization["access"] = "direct".into();
    authorization["availability"] = "available".into();
    authorization["nextAction"] = "none".into();
    assert_eq!(
        json_output(&json),
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "outcome": "shown",
            "grant": {
                "id": NATIVE_GRANT_ID,
                "provider": "codex",
                "kind": "native",
                "side": "member",
                "account": {"kind": "organization", "id": ORGANIZATION_ID, "name": "acme"},
                "label": "build laptop",
                "state": "active",
                "generation": 2,
                "createdAt": "2026-11-01T09:00:00Z",
                "authorizations": [authorization],
                "recordSchemaVersion": 1,
                "keyVersion": 1,
                "importedAt": "2026-11-02T10:00:00Z",
                "endedAuthorizations": grant["endedAuthorizations"]
            }
        })
    );

    assert_eq!(human.status.code(), Some(0));
    let text = stdout(&human);
    let (in_force, ended) = text.split_once("ended authorizations: 1").unwrap();
    for name in [
        "delivered: generation 2 at 2026-11-02T10:06:00Z",
        "reported: ready, generation 2 at 2026-11-02T10:07:00Z",
        "last use: accepted",
        "availability: available",
    ] {
        assert!(in_force.contains(name), "missing {name:?} in\n{text}");
    }
    // A native grant issues no token, so its detail lists no uses.
    assert!(!text.contains("uses:"), "{text}");
    for name in [
        ENDED_RUNNER_ID,
        "ended: 2026-11-03T09:00:00Z",
        "removal: pending",
        RUN_ID,
    ] {
        assert!(ended.contains(name), "missing {name:?} in\n{text}");
    }

    let requests = server.finish();
    assert_member_requests(&requests);
    let read = "GET /api/v1/me/grants/agl_01k0z6r1w8f4jy2m7q9v3x5abc?vocabulary=2 HTTP/1.1";
    assert_eq!(
        request_lines(&requests),
        [read, READ_ORGANIZATION, read, READ_ORGANIZATION]
    );
}

// A runner authorized again keeps its last ended authorization listed, with its removal
// state, beside the one in force.
#[test]
fn show_prints_a_runners_ended_authorization_beside_its_authorization_in_force() {
    const ENDED_ID: &str = "aga_01k0z6r1w8f4jy2m7q9v3x5abd";
    const CONFIRMED_AT: &str = "2026-11-02T09:30:00Z";
    let mut grant = native_grant_in_use();
    grant["endedAuthorizations"] = serde_json::json!([{
        "id": ENDED_ID,
        "runnerId": RUNNER_ID,
        "createdAt": "2026-11-01T09:10:00Z",
        "delivery": {"generation": 1, "deliveredAt": "2026-11-01T09:11:00Z"},
        "endedAt": "2026-11-02T09:00:00Z",
        "removal": {"state": "confirmed", "confirmedAt": CONFIRMED_AT}
    }]);
    let in_force_id = grant["authorizations"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (server, _directory, credential) = prepared(vec![
        one(&grant),
        organization(),
        one(&grant),
        organization(),
    ]);
    let json = run_grant(&server, &credential, &["show", NATIVE_GRANT_ID, "--json"]);
    let human = run_grant(&server, &credential, &["show", NATIVE_GRANT_ID]);

    assert_eq!(
        json.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let shown = json_output(&json);
    assert_eq!(shown["grant"]["authorizations"][0]["id"], in_force_id);
    assert_eq!(shown["grant"]["authorizations"][0]["runnerId"], RUNNER_ID);
    assert_eq!(
        shown["grant"]["endedAuthorizations"],
        grant["endedAuthorizations"]
    );

    assert_eq!(human.status.code(), Some(0));
    let text = stdout(&human);
    let (in_force, ended) = text.split_once("ended authorizations: 1").unwrap();
    assert!(in_force.contains(&in_force_id), "{text}");
    assert!(in_force.contains(RUNNER_ID), "{text}");
    let removal = format!("removal: confirmed at {CONFIRMED_AT}");
    for name in [ENDED_ID, RUNNER_ID, removal.as_str()] {
        assert!(ended.contains(name), "missing {name:?} in\n{text}");
    }
    server.finish();
}

// `list` and `show` print the last use a runner reported for a native grant and, where Cloud holds
// it, when; a last use with no time prints alone.
#[test]
fn list_and_show_print_a_native_authorizations_last_use_and_when() {
    const LAST_USE_AT: &str = "2026-11-02T10:06:30Z";
    let untimed = native_grant_in_use();
    let mut timed = untimed.clone();
    timed["authorizations"][0]["report"]["lastUseAt"] = LAST_USE_AT.into();
    let cases = [
        (timed, format!("last use: accepted at {LAST_USE_AT}")),
        (untimed, "last use: accepted".to_owned()),
    ];
    for (grant, last_use) in &cases {
        let (server, _directory, credential) = prepared(vec![
            one(grant),
            organization(),
            one(grant),
            organization(),
            page(std::slice::from_ref(grant), None),
            predating_served(),
            organization(),
            page(std::slice::from_ref(grant), None),
            predating_served(),
            organization(),
        ]);
        let detail_json = run_grant(&server, &credential, &["show", NATIVE_GRANT_ID, "--json"]);
        let detail = run_grant(&server, &credential, &["show", NATIVE_GRANT_ID]);
        let summary_json = run_grant(&server, &credential, &["list", "--json"]);
        let summary = run_grant(&server, &credential, &["list"]);
        for output in [&detail_json, &detail, &summary_json, &summary] {
            assert_eq!(output.status.code(), Some(0), "{}", stderr(output));
        }
        let authorization = &grant["authorizations"][0];
        let report = &authorization["report"];

        // `show` carries the report as Cloud showed it and prints the last use with the
        // exchange.
        assert_eq!(
            json_output(&detail_json)["grant"]["authorizations"][0]["report"],
            *report
        );
        let text = stdout(&detail);
        let (in_force, _) = text.split_once("ended authorizations: 1").unwrap();
        assert!(
            in_force.lines().any(|line| line.trim() == last_use),
            "missing {last_use:?} in\n{text}"
        );

        // `list` carries the last use on the authorization and prints it between when the
        // runner was authorized and its availability.
        let mut expected = serde_json::json!({
            "id": authorization["id"],
            "runnerId": RUNNER_ID,
            "organizationId": ORGANIZATION_ID,
            "createdAt": authorization["createdAt"],
            "access": "direct",
            "lastUse": "accepted",
            "availability": "available",
            "nextAction": "none"
        });
        if let Some(time) = report.get("lastUseAt") {
            expected["lastUseAt"] = time.clone();
        }
        assert_eq!(
            json_output(&summary_json)["grants"][0]["authorizations"],
            serde_json::json!([expected])
        );
        let text = stdout(&summary);
        let lines: Vec<_> = text.lines().map(str::trim).collect();
        let authorized = lines
            .iter()
            .position(|line| *line == "authorized: 2026-11-02T10:05:00Z")
            .unwrap_or_else(|| panic!("no authorization in\n{text}"));
        assert_eq!(lines[authorized + 1], last_use, "{text}");
        assert_eq!(lines[authorized + 2], "availability: available", "{text}");
        server.finish();
    }
}

#[test]
fn show_prints_an_oauth_grants_scopes_last_use_and_expiries() {
    let grant = oauth_grant(OAUTH_GRANT_ID, "github", "active");
    let (server, _directory, credential) = prepared(vec![
        one(&grant),
        uses(&[]),
        identities(ada()),
        one(&grant),
        uses(&[]),
        identities(ada()),
    ]);
    let json = run_grant(&server, &credential, &["show", OAUTH_GRANT_ID, "--json"]);
    let human = run_grant(&server, &credential, &["show", OAUTH_GRANT_ID]);

    assert_eq!(json.status.code(), Some(0));
    let shown = &json_output(&json)["grant"];
    for member in [
        "scopes",
        "lastUsedAt",
        "accessExpiresAt",
        "refreshExpiresAt",
    ] {
        assert_eq!(shown[member], grant[member], "{member}");
    }
    assert_eq!(shown["authorizations"][0]["availability"], "available");
    assert!(shown["authorizations"][0].get("delivery").is_none());
    assert!(shown.get("endedAuthorizations").is_none());

    assert_eq!(human.status.code(), Some(0));
    let text = stdout(&human);
    for name in [
        "scopes: repo, read:org",
        "last used: 2026-11-04T08:00:00Z",
        "access expires: 2026-11-04T09:00:00Z",
        "refresh expires: 2027-05-01T08:00:00Z",
    ] {
        assert!(text.contains(name), "missing {name:?} in\n{text}");
    }
    assert!(!text.contains("delivered:"), "{text}");

    let requests = server.finish();
    assert_member_requests(&requests);
    let read = "GET /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc?vocabulary=2 HTTP/1.1";
    assert_eq!(
        request_lines(&requests),
        [
            read,
            READ_USES,
            READ_IDENTITIES,
            read,
            READ_USES,
            READ_IDENTITIES
        ]
    );
}

// A failed identity read still prints the grant, its account by identity ID, and says on
// standard error that the names could not be read.
#[test]
fn show_whose_identity_read_fails_prints_the_grant_and_a_diagnostic() {
    let grant = oauth_grant(OAUTH_GRANT_ID, "github", "active");
    let unavailable = || problem("503 Service Unavailable", 503, "service-unavailable");
    let (server, _directory, credential) = prepared(vec![
        one(&grant),
        uses(&[]),
        unavailable(),
        one(&grant),
        uses(&[]),
        unavailable(),
    ]);
    let human = run_grant(&server, &credential, &["show", OAUTH_GRANT_ID]);
    let json = run_grant(&server, &credential, &["show", OAUTH_GRANT_ID, "--json"]);

    assert_eq!(human.status.code(), Some(0), "{}", stderr(&human));
    let text = stdout(&human);
    assert!(text.contains(OAUTH_GRANT_ID), "{text}");
    assert!(text.contains(IDENTITY_ID), "{text}");
    assert!(
        stderr(&human).starts_with("warning: "),
        "{}",
        stderr(&human)
    );

    assert_eq!(json.status.code(), Some(0), "{}", stderr(&json));
    let document = json_output(&json);
    assert_eq!(document["outcome"], "shown");
    assert_eq!(document["grant"]["id"], OAUTH_GRANT_ID);
    assert!(stderr(&json).starts_with("warning: "), "{}", stderr(&json));

    let requests = server.finish();
    assert_member_requests(&requests);
    let read = "GET /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc?vocabulary=2 HTTP/1.1";
    assert_eq!(
        request_lines(&requests),
        [
            read,
            READ_USES,
            READ_IDENTITIES,
            read,
            READ_USES,
            READ_IDENTITIES
        ]
    );
}

// The tokens Cloud issued from the GitHub grant, newest first, as the uses route answers
// them.
fn three_uses() -> [serde_json::Value; 3] {
    [
        (
            "pgu_01k0z6r1w8f4jy2m7q9v3x5ab3",
            "2026-11-04T08:00:00Z",
            "ab3",
        ),
        (
            "pgu_01k0z6r1w8f4jy2m7q9v3x5ab2",
            "2026-11-03T08:00:00Z",
            "ab2",
        ),
        (
            "pgu_01k0z6r1w8f4jy2m7q9v3x5ab1",
            "2026-11-02T08:00:00Z",
            "ab1",
        ),
    ]
    .map(|(id, issued_at, suffix)| {
        serde_json::json!({
            "id": id,
            "grantId": OAUTH_GRANT_ID,
            "runId": format!("run_01k0z6r1w8f4jy2m7q9v3x5{suffix}"),
            "assignmentId": format!("asn_01k0z6r1w8f4jy2m7q9v3x5{suffix}"),
            "organizationId": ORGANIZATION_ID,
            "provider": "github",
            "issuedAt": issued_at
        })
    })
}

fn uses(items: &[serde_json::Value]) -> Vec<u8> {
    page(items, None)
}

#[test]
fn show_lists_the_tokens_issued_from_an_oauth_grant_newest_first_as_many_as_uses_names() {
    let grant = oauth_grant(OAUTH_GRANT_ID, "github", "active");
    let issued = three_uses();
    let (server, _directory, credential) = prepared(vec![
        one(&grant),
        uses(&issued),
        identities(ada()),
        one(&grant),
        uses(&issued),
        identities(ada()),
    ]);
    let json = run_grant(&server, &credential, &["show", OAUTH_GRANT_ID, "--json"]);
    let human = run_grant(
        &server,
        &credential,
        &["show", OAUTH_GRANT_ID, "--uses", "50"],
    );

    assert_eq!(json.status.code(), Some(0), "{}", stderr(&json));
    let shown: Vec<_> = issued
        .iter()
        .map(|item| {
            serde_json::json!({
                "id": item["id"],
                "runId": item["runId"],
                "assignmentId": item["assignmentId"],
                "organizationId": item["organizationId"],
                "issuedAt": item["issuedAt"]
            })
        })
        .collect();
    assert_eq!(
        json_output(&json)["grant"]["uses"],
        serde_json::json!(shown)
    );

    assert_eq!(human.status.code(), Some(0), "{}", stderr(&human));
    let text = stdout(&human);
    assert!(text.contains("uses: 3"), "{text}");
    // Each use is printed, with its time, run, assignment and organization, before the one
    // issued before it.
    let starts: Vec<_> = issued
        .iter()
        .map(|item| {
            text.find(item["id"].as_str().unwrap())
                .unwrap_or_else(|| panic!("missing {} in\n{text}", item["id"]))
        })
        .chain([text.len()])
        .collect();
    assert!(starts.is_sorted(), "{text}");
    for (item, bounds) in issued.iter().zip(starts.windows(2)) {
        let printed = &text[bounds[0]..bounds[1]];
        for member in ["issuedAt", "runId", "assignmentId", "organizationId"] {
            let value = item[member].as_str().unwrap();
            assert!(printed.contains(value), "missing {value} in\n{printed}");
        }
    }

    let requests = server.finish();
    assert_member_requests(&requests);
    let read = "GET /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc?vocabulary=2 HTTP/1.1";
    assert_eq!(
        request_lines(&requests),
        [
            read,
            READ_USES,
            READ_IDENTITIES,
            read,
            "GET /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc/uses?limit=50&vocabulary=2 HTTP/1.1",
            READ_IDENTITIES
        ]
    );
}

// A grant named by its provider has its uses read by its ID.
#[test]
fn a_grant_named_by_its_provider_has_its_uses_read_by_its_id() {
    let grant = oauth_grant(OAUTH_GRANT_ID, "github", "active");
    let (server, _directory, credential) = prepared(vec![
        page(&[grant], None),
        uses(&three_uses()),
        identities(ada()),
    ]);
    let output = run_grant(&server, &credential, &["show", "github", "--json"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        json_output(&output)["grant"]["uses"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [LIST_FIRST_PAGE, READ_USES, READ_IDENTITIES]
    );
}

// A failed uses read ends the command as a failed grant read does.
#[test]
fn show_whose_uses_read_fails_exits_1_as_a_failed_grant_read_does() {
    let grant = oauth_grant(OAUTH_GRANT_ID, "github", "active");
    let not_found = || problem("404 Not Found", 404, "grant-not-found");
    let (server, _directory, credential) = prepared(vec![not_found(), one(&grant), not_found()]);
    let read = run_grant(&server, &credential, &["show", OAUTH_GRANT_ID, "--json"]);
    let listed = run_grant(&server, &credential, &["show", OAUTH_GRANT_ID, "--json"]);

    assert_eq!(read.status.code(), Some(1));
    assert_eq!(json_output(&read)["outcome"], "grant_not_found");
    assert_eq!(listed.status.code(), Some(1));
    assert_eq!(json_output(&listed), json_output(&read));
    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(requests.len(), 3);
}

// `show` takes a grant and at most 200 uses, and `list` takes neither.
#[test]
fn show_without_a_grant_or_with_a_uses_limit_out_of_range_exits_2_before_anything_is_sent() {
    let (server, _directory, credential) = prepared(vec![]);
    for args in [
        &["show", OAUTH_GRANT_ID, "--uses", "0"][..],
        &["show", OAUTH_GRANT_ID, "--uses", "201"],
        &["show"],
        &["show", "--json"],
        &["show", "--uses", "20"],
        &["list", OAUTH_GRANT_ID, "--json"],
        &["list", "--uses", "20"],
        &["list", "--uses", "20", "--json"],
    ] {
        let output = run_grant(&server, &credential, args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    assert!(server.finish().is_empty());
}

#[test]
fn a_provider_name_resolves_to_the_members_one_unrevoked_grant_of_it() {
    let (server, _directory, credential) = prepared(vec![
        page(
            &[
                oauth_grant(OAUTH_GRANT_ID, "github", "active"),
                native_grant(OTHER_NATIVE_GRANT_ID, "revoked"),
                native_grant(NATIVE_GRANT_ID, "active"),
            ],
            None,
        ),
        organization(),
    ]);
    let output = run_grant(&server, &credential, &["show", "codex", "--json"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document = json_output(&output);
    assert_eq!(document["outcome"], "shown");
    assert_eq!(document["grant"]["id"], NATIVE_GRANT_ID);
    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [LIST_FIRST_PAGE, READ_ORGANIZATION]
    );
}

#[test]
fn a_provider_name_with_no_grant_is_not_found_and_one_with_several_is_refused_naming_them() {
    let (server, _directory, credential) = prepared(vec![
        page(&[native_grant(NATIVE_GRANT_ID, "active")], None),
        page(
            &[
                native_grant(NATIVE_GRANT_ID, "active"),
                native_grant(OTHER_NATIVE_GRANT_ID, "active"),
            ],
            None,
        ),
        problem("404 Not Found", 404, "grant-not-found"),
    ]);
    let none = run_grant(&server, &credential, &["show", "claude_code", "--json"]);
    let several = run_grant(&server, &credential, &["show", "codex"]);
    let unknown = run_grant(&server, &credential, &["show", NATIVE_GRANT_ID, "--json"]);

    assert_eq!(none.status.code(), Some(1));
    assert_eq!(json_output(&none)["outcome"], "grant_not_found");
    // An unknown ID is refused by Cloud with the same outcome.
    assert_eq!(unknown.status.code(), Some(1));
    assert_eq!(json_output(&unknown), json_output(&none));

    assert_eq!(several.status.code(), Some(2));
    assert!(several.stdout.is_empty());
    let stderr = String::from_utf8(several.stderr).unwrap();
    for id in [NATIVE_GRANT_ID, OTHER_NATIVE_GRANT_ID] {
        assert!(stderr.contains(id), "missing {id} in\n{stderr}");
    }

    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(requests.len(), 3);
}

#[test]
fn a_grant_that_is_no_grant_id_nor_provider_is_refused_before_anything_is_sent() {
    let (server, _directory, credential) = prepared(vec![]);
    let too_long = "a".repeat(64);
    for grant in [
        "grt_01k0z6r1w8f4jy2m7q9v3x5abc",
        "pgr_",
        "agl_not-an-id",
        "GitHub",
        "bit_bucket",
        "1password",
        too_long.as_str(),
    ] {
        let output = run_grant(&server, &credential, &["show", grant, "--json"]);
        assert_eq!(output.status.code(), Some(2), "{grant}");
        assert!(output.stdout.is_empty(), "{grant}");
    }
    assert!(server.finish().is_empty());
}

// Any name of the provider id shape may name a provider, so one the member holds no grant of
// is read for and not found. Such a name may also name a token service, which a deployment
// that predates the served read serves none of.
#[test]
fn a_provider_the_member_holds_no_grant_of_is_not_found_after_the_grants_are_read() {
    let (server, _directory, credential) = prepared(vec![
        page(&[oauth_grant(OAUTH_GRANT_ID, "github", "active")], None),
        predating_served(),
    ]);
    let output = run_grant(&server, &credential, &["show", "bitbucket", "--json"]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(json_output(&output)["outcome"], "grant_not_found");
    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(request_lines(&requests), [LIST_FIRST_PAGE, READ_SERVED]);
}

const EXAMPLE_GRANT_ID: &str = "pgr_01k0z6r1w8f4jy2m7q9v3x5abg";

#[test]
fn a_grant_of_any_provider_is_listed_shown_and_revoked_by_its_provider() {
    let github = oauth_grant(OAUTH_GRANT_ID, "github", "active");
    let mut example = oauth_grant(EXAMPLE_GRANT_ID, "example", "active");
    example["authorizations"][0]["id"] = "pga_01k0z6r1w8f4jy2m7q9v3x5abg".into();
    let grants = || page(&[github.clone(), example.clone()], None);
    let example_use = serde_json::json!({
        "id": "pgu_01k0z6r1w8f4jy2m7q9v3x5abg",
        "grantId": EXAMPLE_GRANT_ID,
        "runId": "run_01k0z6r1w8f4jy2m7q9v3x5abg",
        "assignmentId": "asn_01k0z6r1w8f4jy2m7q9v3x5abg",
        "organizationId": ORGANIZATION_ID,
        "provider": "example",
        "issuedAt": "2026-11-04T08:00:00Z"
    });
    let (server, _directory, credential) = prepared(vec![
        grants(),
        predating_served(),
        identities(ada()),
        grants(),
        uses(&[example_use]),
        identities(ada()),
        grants(),
        deleted(),
    ]);
    let listed = run_grant(&server, &credential, &["list", "--json"]);
    let shown = run_grant(&server, &credential, &["show", "example", "--json"]);
    let revoked = run_grant(
        &server,
        &credential,
        &["disconnect", "example", "--yes", "--json"],
    );

    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    let document = json_output(&listed);
    let grants = document["grants"].as_array().unwrap();
    assert_eq!(
        grants
            .iter()
            .map(|grant| (
                grant["id"].as_str().unwrap(),
                grant["provider"].as_str().unwrap()
            ))
            .collect::<Vec<_>>(),
        [(OAUTH_GRANT_ID, "github"), (EXAMPLE_GRANT_ID, "example")]
    );
    assert_eq!(grants[1]["account"]["name"], EMAIL);

    assert_eq!(shown.status.code(), Some(0), "{}", stderr(&shown));
    let document = json_output(&shown);
    assert_eq!(document["outcome"], "shown");
    assert_eq!(document["grant"]["id"], EXAMPLE_GRANT_ID);
    assert_eq!(document["grant"]["provider"], "example");
    assert_eq!(
        document["grant"]["uses"][0]["id"],
        "pgu_01k0z6r1w8f4jy2m7q9v3x5abg"
    );

    assert_eq!(revoked.status.code(), Some(0), "{}", stderr(&revoked));
    let document = json_output(&revoked);
    assert_eq!(document["outcome"], "revoked");
    assert_eq!(document["grantId"], EXAMPLE_GRANT_ID);
    assert_eq!(document["provider"], "example");

    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [
            "GET /api/v1/me/grants?kind=all&limit=200&vocabulary=2 HTTP/1.1",
            READ_SERVED,
            "GET /api/v1/me/identities?limit=200&vocabulary=2 HTTP/1.1",
            LIST_FIRST_PAGE,
            "GET /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abg/uses?limit=20&vocabulary=2 HTTP/1.1",
            READ_IDENTITIES,
            LIST_FIRST_PAGE,
            "DELETE /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abg HTTP/1.1",
        ]
    );
}

/// Acting as the GitHub App, the other choice `useful` names wherever the member's own GitHub
/// sign-in is missing, failed or cannot be made.
pub(super) const ACTING_AS_THE_APP: &str =
    "useful org integration authorize github --runner RUNNER --project PROJECT --runs all";

#[test]
fn list_names_acting_as_the_github_app_in_the_step_that_connects_github() {
    let (server, _directory, credential) = prepared(vec![nothing_held(), predating_served()]);
    let output = run_grant(&server, &credential, &["list"]);
    server.finish();

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    let (_, rest) = text.split_once("── not connected ──").unwrap();
    let lines: Vec<_> = rest.lines().collect();
    let at = |provider: &str| lines.iter().position(|line| *line == provider).unwrap();
    let commands = |provider: &str| -> Vec<&str> {
        lines[at(provider) + 2]
            .split('`')
            .skip(1)
            .step_by(2)
            .collect()
    };
    assert_eq!(
        commands("github"),
        [
            "useful account integration connect github",
            ACTING_AS_THE_APP
        ],
        "{text}"
    );
    assert_eq!(
        commands("gitlab.com"),
        ["useful account integration connect gitlab.com"],
        "{text}"
    );
}

#[test]
fn list_names_each_other_oauth_provider_served_that_the_member_holds_nothing_of() {
    let github = || page(&[oauth_grant(OAUTH_GRANT_ID, "github", "active")], None);
    let (server, _directory, credential) = prepared(vec![
        github(),
        serving_example_early(),
        identities(ada()),
        github(),
        serving_example_early(),
        identities(ada()),
        github(),
        uses(&[]),
        identities(ada()),
    ]);
    let json = run_grant(&server, &credential, &["list", "--json"]);
    let human = run_grant(&server, &credential, &["list"]);
    let shown = run_grant(&server, &credential, &["show", "github", "--json"]);

    assert_eq!(json.status.code(), Some(0), "{}", stderr(&json));
    assert_eq!(
        json_output(&json)["notConnected"],
        serde_json::json!([
            not_connected("gitlab.com"),
            not_connected("linear"),
            not_connected("example"),
            not_connected("claude_code"),
            not_connected("codex")
        ])
    );
    assert_eq!(human.status.code(), Some(0), "{}", stderr(&human));
    let text = stdout(&human);
    let (_, rest) = text.split_once("── not connected ──").unwrap();
    let lines: Vec<_> = rest.lines().collect();
    let at = |provider: &str| lines.iter().position(|line| *line == provider).unwrap();
    assert!(
        at("linear") < at("example") && at("example") < at("claude_code"),
        "{text}"
    );
    let next_action = lines[at("example") + 2];
    assert!(
        next_action.contains("`useful account integration connect example`"),
        "{text}"
    );
    assert_eq!(shown.status.code(), Some(0), "{}", stderr(&shown));
    assert_eq!(json_output(&shown)["outcome"], "shown");
    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [
            LIST_FIRST_PAGE,
            READ_SERVED,
            READ_IDENTITIES,
            LIST_FIRST_PAGE,
            READ_SERVED,
            READ_IDENTITIES,
            LIST_FIRST_PAGE,
            READ_USES,
            READ_IDENTITIES,
        ]
    );

    // A served read that fails fails the list as a failed grant list does.
    let failed = || problem("500 Internal Server Error", 500, "internal-error");
    let (server, _directory, credential) = prepared(vec![github(), failed(), failed()]);
    let served_failed = run_grant(&server, &credential, &["list", "--json"]);
    let list_failed = run_grant(&server, &credential, &["list", "--json"]);
    assert_ne!(served_failed.status.code(), Some(0));
    assert_eq!(served_failed.status.code(), list_failed.status.code());
    assert_eq!(json_output(&served_failed), json_output(&list_failed));
    assert_eq!(
        request_lines(&server.finish()),
        [LIST_FIRST_PAGE, READ_SERVED, LIST_FIRST_PAGE]
    );
}

#[test]
fn a_service_api_key_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("service.key");
    fs::write(&key, "umsk_unused\n").unwrap();
    fs::set_permissions(&key, Permissions::from_mode(0o600)).unwrap();
    let (server, _credentials, credential) = prepared(vec![]);
    let output = run_grant(
        &server,
        &credential,
        &["list", "--api-key-file", key.to_str().unwrap(), "--json"],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(server.finish().is_empty());
}

const LINEAR_GRANT_ID: &str = "pgr_01k0z6r1w8f4jy2m7q9v3x5abe";
const OTHER_ORGANIZATION_ID: &str = "org_01k0z6r1w8f4jy2m7q9v3x5abd";
pub(super) const NEW_RUNNER_ID: &str = "rnr_01k0z6r1w8f4jy2m7q9v3x5abe";
const CANCELLATION_REQUEST_ID: &str = "cmd_01k0z6r1w8f4jy2m7q9v3x5abc";

pub(super) fn request_body(request: &str) -> serde_json::Value {
    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
}

// The authorization Cloud makes of `grant_id` for `runner_id`, under the prefix its kind names.
pub(super) fn authorized(grant_id: &str, runner_id: &str) -> Vec<u8> {
    let prefix = if grant_id.starts_with("pgr_") {
        "pga_"
    } else {
        "aga_"
    };
    http_response_with_headers(
        "201 Created",
        Some("application/json"),
        &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
        &serde_json::to_vec(&serde_json::json!({
            "id": format!("{prefix}01k0z6r1w8f4jy2m7q9v3x5abf"),
            "runnerId": runner_id,
            "organizationId": ORGANIZATION_ID,
            "createdAt": "2026-11-06T09:00:00Z"
        }))
        .unwrap(),
    )
}

pub(super) fn deleted() -> Vec<u8> {
    http_response_with_headers(
        "204 No Content",
        None,
        &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
        b"",
    )
}

pub(super) fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

// What a leaf states on standard error before it acts: the line naming the grant it acts on,
// then each statement indented under it. The wording is not a contract, so a statement is
// identified by where it is printed and compared only with the refusal that states it too.
pub(super) fn statement(output: &Output, grant_id: &str) -> Vec<String> {
    let text = stderr(output);
    let mut lines = text.lines();
    let heading = lines.next().unwrap_or_default();
    assert!(heading.contains(grant_id), "{grant_id} not in\n{text}");
    lines
        .map_while(|line| line.strip_prefix("  "))
        .map(str::to_owned)
        .collect()
}

// Runs `args` without `--yes`, which is refused with exit 2 before anything is sent or printed
// on standard output, naming the option it lacks and the leaf's command; its standard error.
fn refusal_without_yes(server: &ScriptedServer, credential: &Path, args: &[&str]) -> String {
    let output = run_grant(server, credential, args);
    assert_eq!(output.status.code(), Some(2), "{args:?}");
    assert!(output.stdout.is_empty(), "{args:?}");
    let text = stderr(&output);
    assert!(text.contains("--yes"), "{args:?}: {text}");
    assert!(
        text.contains(&format!("useful account integration {}", args[0])),
        "{args:?}: {text}"
    );
    text
}

// A statement made before acting is one the refusal without `--yes` states for both kinds,
// each on a line of its own.
pub(super) fn assert_stated_by_the_refusal(statement: &[String], refusal: &str) {
    assert!(!statement.is_empty(), "no statement before acting");
    for line in statement {
        assert_eq!(
            refusal
                .lines()
                .filter(|refused| refused.ends_with(line.as_str()))
                .count(),
            1,
            "{line:?} not in\n{refusal}"
        );
    }
}

use super::runner_administration::{MEMBER_ID, POOL_ID, current_principal_response};

fn personal_pools(org: &str) -> Vec<u8> {
    json_http_response(
        "200 OK",
        serde_json::json!({"items": [{
            "id": POOL_ID, "name": "personal", "organizationId": org,
            "member": {"id": MEMBER_ID, "displayName": "Ada"},
            "createdAt": "2026-11-01T08:00:00Z", "updatedAt": "2026-11-01T08:00:00Z"
        }]}),
    )
}

pub(super) fn pool_authorization(id: &str, org: &str) -> serde_json::Value {
    serde_json::json!({"id": id, "runnerPoolId": POOL_ID, "organizationId": org,
        "createdAt": "2026-11-06T09:00:00Z", "runners": []})
}

// SC-GRANTAUTH-1, SC-GRANTAUTH-2
#[test]
fn authorize_personal_pool_binds_the_grants_organization_and_replays_the_same_key() {
    let mut native = native_grant(NATIVE_GRANT_ID, "active");
    native["provider"] = "claude_code".into();
    for (grant, id, org, requested_org, read, post) in [
        (
            native,
            "aga_01k0z6r1w8f4jy2m7q9v3x5abf",
            ORGANIZATION_ID,
            OTHER_ORGANIZATION_ID,
            READ_NATIVE,
            AUTHORIZE_NATIVE,
        ),
        (
            oauth_grant_unauthorized(OAUTH_GRANT_ID),
            "pga_01k0z6r1w8f4jy2m7q9v3x5abf",
            OTHER_ORGANIZATION_ID,
            OTHER_ORGANIZATION_ID,
            READ_OAUTH,
            AUTHORIZE_OAUTH,
        ),
    ] {
        let auth = pool_authorization(id, org);
        let (server, _directory, credential) = prepared(vec![
            one(&grant),
            current_principal_response(),
            personal_pools(org),
            Vec::new(),
            http_response_with_headers(
                "201 Created",
                Some("application/json"),
                &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
                &serde_json::to_vec(&auth).unwrap(),
            ),
        ]);
        let grant_id = grant["id"].as_str().unwrap();
        let args = [
            "authorize",
            grant_id,
            "--personal-pool",
            "--org",
            requested_org,
            "--json",
        ];
        let refusal = refusal_without_yes(&server, &credential, &args);
        let mut args = args.to_vec();
        args.push("--yes");
        let output = run_grant(&server, &credential, &args);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let lines = statement(&output, grant_id);
        assert!(lines.iter().any(|line| line.contains("pool")));
        assert_stated_by_the_refusal(&lines, &refusal);
        assert!(stderr(&output).lines().next().unwrap().contains(POOL_ID));
        assert_eq!(json_output(&output)["authorization"], auth);
        let requests = server.finish();
        let pools = format!("GET /api/v1/organizations/{org}/runner-pools?limit=200 HTTP/1.1");
        assert_eq!(
            request_lines(&requests),
            [read, "GET /api/v1/me HTTP/1.1", &pools, post, post]
        );
        for request in &requests[3..] {
            assert_eq!(
                request_body(request),
                serde_json::json!({"runnerPoolId": POOL_ID})
            );
        }
        let key = header_value(&requests[3], "idempotency-key");
        assert!(!key.is_empty());
        assert_eq!(key, header_value(&requests[4], "idempotency-key"));
    }
}

#[test]
fn personal_pool_options_refuse_conflicting_targets_before_any_request() {
    let (server, _directory, credential) = prepared(vec![]);
    for args in [
        vec!["authorize", "--all", "--personal-pool"],
        vec![
            "authorize",
            NATIVE_GRANT_ID,
            "--personal-pool",
            "--runner",
            RUNNER_ID,
        ],
        vec![
            "deauthorize",
            NATIVE_GRANT_ID,
            "--personal-pool",
            "--runner",
            RUNNER_ID,
        ],
        vec!["authorize", NATIVE_GRANT_ID, "--org", ORGANIZATION_ID],
        vec!["deauthorize", NATIVE_GRANT_ID, "--org", ORGANIZATION_ID],
    ] {
        let mut args = args;
        args.push("--yes");
        assert_eq!(
            run_grant(&server, &credential, &args).status.code(),
            Some(2),
            "{args:?}"
        );
    }
    assert!(server.finish().is_empty());
}

#[test]
fn personal_pool_refusals_name_the_outcome_and_its_remedy() {
    for (code, slug, outcome, remedy) in [
        (
            404,
            "grant-runner-pool-not-found",
            "runner_pool_not_found",
            "useful runner pool list --org",
        ),
        (
            409,
            "grant-runner-pool-unavailable",
            "runner_pool_unavailable",
            "authorize codex --runner",
        ),
        (
            409,
            "grant-runner-conflict",
            "runner_holds_login",
            "deauthorize INTEGRATION --personal-pool",
        ),
        (
            409,
            "grant-already-authorized",
            "already_authorized",
            "show INTEGRATION",
        ),
    ] {
        let status = if code == 404 {
            "404 Not Found"
        } else {
            "409 Conflict"
        };
        let answers = || {
            vec![
                one(&native_grant(NATIVE_GRANT_ID, "active")),
                current_principal_response(),
                personal_pools(ORGANIZATION_ID),
                problem(status, code, slug),
            ]
        };
        let (server, _directory, credential) = prepared([answers(), answers()].concat());
        let args = [
            "authorize",
            NATIVE_GRANT_ID,
            "--personal-pool",
            "--yes",
            "--json",
        ];
        let output = run_grant(&server, &credential, &args);
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert_eq!(json_output(&output)["outcome"], outcome);
        let human = run_grant(&server, &credential, &args[..4]);
        assert_eq!(human.status.code(), Some(1));
        assert!(stderr(&human).contains(remedy), "{human:?}");
        assert_eq!(
            request_lines(&server.finish()).last(),
            Some(&AUTHORIZE_NATIVE)
        );
    }
}

#[test]
fn authorize_states_who_can_use_the_grant_then_authorizes_the_runner_with_one_key() {
    let native = native_grant(NATIVE_GRANT_ID, "active");
    let oauth = oauth_grant(OAUTH_GRANT_ID, "github", "active");
    let (server, _directory, credential) = prepared(vec![
        one(&native),
        // The first answer is lost; the command replays the same key once.
        Vec::new(),
        authorized(NATIVE_GRANT_ID, RUNNER_ID),
        one(&oauth),
        authorized(OAUTH_GRANT_ID, NEW_RUNNER_ID),
    ]);
    let native_run = run_grant(
        &server,
        &credential,
        &[
            "authorize",
            NATIVE_GRANT_ID,
            "--runner",
            RUNNER_ID,
            "--yes",
            "--json",
        ],
    );
    let oauth_run = run_grant(
        &server,
        &credential,
        &[
            "authorize",
            OAUTH_GRANT_ID,
            "--runner",
            NEW_RUNNER_ID,
            "--yes",
        ],
    );

    // Before acting each states who can use the grant, as the refusal without `--yes` does:
    // for a native grant two exposures, the runs that runner serves and the steps on it that
    // can read the login, and for an OAuth grant the parts the next test counts.
    let refusal = refusal_without_yes(
        &server,
        &credential,
        &["authorize", NATIVE_GRANT_ID, "--runner", RUNNER_ID],
    );
    let native_statement = statement(&native_run, NATIVE_GRANT_ID);
    let oauth_statement = statement(&oauth_run, OAUTH_GRANT_ID);
    assert_eq!(native_statement.len(), 2, "{}", stderr(&native_run));
    assert!(
        oauth_statement
            .iter()
            .all(|line| !native_statement.contains(line)),
        "{oauth_statement:?} {native_statement:?}"
    );
    assert_stated_by_the_refusal(&native_statement, &refusal);
    assert_stated_by_the_refusal(&oauth_statement, &refusal);

    assert_eq!(native_run.status.code(), Some(0), "{}", stderr(&native_run));
    assert_eq!(
        json_output(&native_run),
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "outcome": "authorized",
            "grantId": NATIVE_GRANT_ID,
            "authorization": {
                "id": "aga_01k0z6r1w8f4jy2m7q9v3x5abf",
                "runnerId": RUNNER_ID,
                "organizationId": ORGANIZATION_ID,
                "createdAt": "2026-11-06T09:00:00Z"
            }
        })
    );

    assert_eq!(oauth_run.status.code(), Some(0), "{}", stderr(&oauth_run));
    let text = stdout(&oauth_run);
    for name in [
        OAUTH_GRANT_ID,
        "pga_01k0z6r1w8f4jy2m7q9v3x5abf",
        NEW_RUNNER_ID,
    ] {
        assert!(text.contains(name), "missing {name:?} in\n{text}");
    }

    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [
            "GET /api/v1/me/grants/agl_01k0z6r1w8f4jy2m7q9v3x5abc?vocabulary=2 HTTP/1.1",
            "POST /api/v1/me/grants/agl_01k0z6r1w8f4jy2m7q9v3x5abc/authorizations HTTP/1.1",
            "POST /api/v1/me/grants/agl_01k0z6r1w8f4jy2m7q9v3x5abc/authorizations HTTP/1.1",
            "GET /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc?vocabulary=2 HTTP/1.1",
            "POST /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc/authorizations HTTP/1.1",
        ]
    );
    assert_eq!(
        request_body(&requests[1]),
        serde_json::json!({"runnerId": RUNNER_ID})
    );
    assert_eq!(
        request_body(&requests[4]),
        serde_json::json!({"runnerId": NEW_RUNNER_ID})
    );
    let key = header_value(&requests[1], "idempotency-key");
    assert!(!key.is_empty());
    assert_eq!(header_value(&requests[2], "idempotency-key"), key);
    assert_ne!(header_value(&requests[4], "idempotency-key"), key);
}

#[test]
fn authorize_without_yes_states_the_runs_issued_oauth_tokens_and_the_steps_reading_them() {
    let oauth = oauth_grant(OAUTH_GRANT_ID, "github", "active");
    let (server, _directory, credential) =
        prepared(vec![one(&oauth), authorized(OAUTH_GRANT_ID, NEW_RUNNER_ID)]);

    // Refused with exit 2 before anything is sent: the only requests are the acting run's.
    let refusal = refusal_without_yes(
        &server,
        &credential,
        &["authorize", OAUTH_GRANT_ID, "--runner", NEW_RUNNER_ID],
    );
    let acting = run_grant(
        &server,
        &credential,
        &[
            "authorize",
            OAUTH_GRANT_ID,
            "--runner",
            NEW_RUNNER_ID,
            "--yes",
        ],
    );
    assert_eq!(acting.status.code(), Some(0), "{}", stderr(&acting));

    // An OAuth grant's statement has two parts, the runs that can be issued tokens from it and
    // the steps of such a run that can read the token, each stated by the refusal too.
    let oauth_statement = statement(&acting, OAUTH_GRANT_ID);
    assert_eq!(oauth_statement.len(), 2, "{}", stderr(&acting));
    assert_ne!(oauth_statement[0], oauth_statement[1]);
    assert_stated_by_the_refusal(&oauth_statement, &refusal);

    assert_eq!(
        request_lines(&server.finish()),
        [
            "GET /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc?vocabulary=2 HTTP/1.1",
            "POST /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc/authorizations HTTP/1.1",
        ]
    );
}

#[test]
fn a_missing_confirmation_or_a_malformed_target_exits_2_before_anything_is_sent() {
    let (server, _directory, credential) = prepared(vec![]);
    let refused = |args: &[&str]| {
        let output = run_grant(&server, &credential, args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    };

    // Without --yes, where it cannot ask, each leaf names the option and itself, before a
    // runner's name is looked up too; what it states for each kind is the statement it makes
    // before acting (each acting test compares the two).
    refusal_without_yes(
        &server,
        &credential,
        &["authorize", NATIVE_GRANT_ID, "--runner", RUNNER_ID],
    );
    refusal_without_yes(
        &server,
        &credential,
        &["authorize", "--all", "--runner", RUNNER_ID],
    );
    refusal_without_yes(
        &server,
        &credential,
        &["deauthorize", NATIVE_GRANT_ID, "--runner", RUNNER_ID],
    );
    refusal_without_yes(
        &server,
        &credential,
        &["deauthorize", "codex", "--runner", "build-1"],
    );
    refusal_without_yes(&server, &credential, &["disconnect", "codex"]);

    // INTEGRATION and --all exclude each other and one of them is required, a leaf takes one
    // runner, and only with --runner.
    refused(&[
        "authorize",
        NATIVE_GRANT_ID,
        "--all",
        "--runner",
        RUNNER_ID,
        "--yes",
    ]);
    refused(&["authorize", NATIVE_GRANT_ID, "--all", "--yes"]);
    refused(&[
        "authorize",
        "--all",
        "--runner",
        RUNNER_ID,
        "--runner",
        NEW_RUNNER_ID,
        "--yes",
    ]);
    refused(&["authorize", NATIVE_GRANT_ID, RUNNER_ID, "--yes"]);
    refused(&["deauthorize", "codex", "build-1", "--yes"]);
    refused(&["authorize", "--yes"]);
    refused(&["authorize", "--runner", RUNNER_ID, "--yes"]);
    refused(&["deauthorize", "--runner", RUNNER_ID, "--yes"]);
    refused(&["disconnect", "bit_bucket", "--yes"]);

    assert!(server.finish().is_empty());
}

// Four unrevoked grants of the member and a revoked one: a GitHub grant already authorized
// for the runner, a Linear grant, a Codex grant of the runner's organization and a Claude Code
// grant of another organization.
fn every_kind() -> Vec<u8> {
    let mut other_organization = native_grant(OTHER_NATIVE_GRANT_ID, "active");
    other_organization["provider"] = "claude_code".into();
    other_organization["organizationId"] = OTHER_ORGANIZATION_ID.into();
    let mut linear = oauth_grant(LINEAR_GRANT_ID, "linear", "active");
    linear["authorizations"] = serde_json::json!([]);
    page(
        &[
            oauth_grant(OAUTH_GRANT_ID, "github", "active"),
            linear,
            oauth_grant(REVOKED_OAUTH_GRANT_ID, "gitlab.com", "revoked"),
            native_grant(NATIVE_GRANT_ID, "active"),
            other_organization,
        ],
        None,
    )
}

const AUTHORIZE_LINEAR: &str =
    "POST /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abe/authorizations HTTP/1.1";
const AUTHORIZE_CODEX: &str =
    "POST /api/v1/me/grants/agl_01k0z6r1w8f4jy2m7q9v3x5abc/authorizations HTTP/1.1";
const AUTHORIZE_CLAUDE_CODE: &str =
    "POST /api/v1/me/grants/agl_01k0z6r1w8f4jy2m7q9v3x5abd/authorizations HTTP/1.1";

fn grant_outcomes(document: &serde_json::Value) -> Vec<(String, String)> {
    document["grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|grant| {
            (
                grant["grantId"].as_str().unwrap().to_owned(),
                grant["outcome"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
fn authorize_all_authorizes_every_grant_that_can_serve_the_runner() {
    let mut responses = Vec::new();
    for _ in 0..2 {
        responses.extend([
            every_kind(),
            predating_served(),
            authorized(LINEAR_GRANT_ID, RUNNER_ID),
            authorized(NATIVE_GRANT_ID, RUNNER_ID),
            problem("404 Not Found", 404, "grant-runner-not-found"),
        ]);
    }
    let (server, _directory, credential) = prepared(responses);
    let json = run_grant(
        &server,
        &credential,
        &[
            "authorize",
            "--all",
            "--runner",
            RUNNER_ID,
            "--yes",
            "--json",
        ],
    );
    let human = run_grant(
        &server,
        &credential,
        &["authorize", "--all", "--runner", RUNNER_ID, "--yes"],
    );

    assert_eq!(json.status.code(), Some(0), "{}", stderr(&json));
    let document = json_output(&json);
    assert_eq!(document["outcome"], "authorized");
    assert_eq!(document["runnerId"], RUNNER_ID);
    assert_eq!(
        grant_outcomes(&document),
        [
            (OAUTH_GRANT_ID.to_owned(), "already_authorized".to_owned()),
            (LINEAR_GRANT_ID.to_owned(), "authorized".to_owned()),
            (NATIVE_GRANT_ID.to_owned(), "authorized".to_owned()),
            (
                OTHER_NATIVE_GRANT_ID.to_owned(),
                "other_organization".to_owned()
            ),
        ]
    );
    assert_eq!(
        document["grants"][2]["authorization"]["id"],
        "aga_01k0z6r1w8f4jy2m7q9v3x5abf"
    );

    assert_eq!(human.status.code(), Some(0), "{}", stderr(&human));
    let text = stdout(&human);
    for (id, outcome) in [
        (OAUTH_GRANT_ID, "already_authorized"),
        (LINEAR_GRANT_ID, "authorized"),
        (NATIVE_GRANT_ID, "authorized"),
        (OTHER_NATIVE_GRANT_ID, "other_organization"),
    ] {
        assert!(
            text.lines()
                .any(|line| line.contains(id) && line.contains(outcome)),
            "missing {id} {outcome} in\n{text}"
        );
    }

    let requests = server.finish();
    assert_member_requests(&requests);
    // A deployment that predates the served read serves no token service, so no token list is
    // read.
    let expected = [
        LIST_FIRST_PAGE,
        READ_SERVED,
        AUTHORIZE_LINEAR,
        AUTHORIZE_CODEX,
        AUTHORIZE_CLAUDE_CODE,
    ];
    assert_eq!(request_lines(&requests[..5]), expected);
    assert_eq!(request_lines(&requests[5..]), expected);
    // Each grant's request carries a key of its own.
    let keys: std::collections::BTreeSet<_> = requests[2..5]
        .iter()
        .map(|request| header_value(request, "idempotency-key"))
        .collect();
    assert_eq!(keys.len(), 3);
}

#[test]
fn authorize_all_exits_1_when_a_grant_is_refused_for_another_reason() {
    let mut responses = Vec::new();
    for _ in 0..2 {
        responses.extend([
            every_kind(),
            predating_served(),
            authorized(LINEAR_GRANT_ID, RUNNER_ID),
            problem("409 Conflict", 409, "grant-runner-conflict"),
            problem("404 Not Found", 404, "grant-runner-not-found"),
        ]);
    }
    let (server, _directory, credential) = prepared(responses);
    let json = run_grant(
        &server,
        &credential,
        &[
            "authorize",
            "--all",
            "--runner",
            RUNNER_ID,
            "--yes",
            "--json",
        ],
    );
    let human = run_grant(
        &server,
        &credential,
        &["authorize", "--all", "--runner", RUNNER_ID, "--yes"],
    );

    assert_eq!(json.status.code(), Some(1), "{}", stderr(&json));
    let document = json_output(&json);
    assert_eq!(
        grant_outcomes(&document),
        [
            (OAUTH_GRANT_ID.to_owned(), "already_authorized".to_owned()),
            (LINEAR_GRANT_ID.to_owned(), "authorized".to_owned()),
            (NATIVE_GRANT_ID.to_owned(), "runner_holds_login".to_owned()),
            (
                OTHER_NATIVE_GRANT_ID.to_owned(),
                "other_organization".to_owned()
            ),
        ]
    );
    assert_ne!(document["outcome"], "authorized");

    assert_eq!(human.status.code(), Some(1));
    let text = format!("{}{}", stdout(&human), stderr(&human));
    assert!(text.contains("runner_holds_login"), "{text}");
    assert!(
        text.contains("useful account integration deauthorize"),
        "{text}"
    );
    assert_eq!(server.finish().len(), 10);
}

#[test]
fn authorize_all_tells_a_codex_grant_authorized_elsewhere_from_one_authorized_here() {
    // The GitHub grant is authorized for the runner already; the Codex grant is refused because
    // it is authorized for another runner.
    let grants = || {
        page(
            &[
                oauth_grant(OAUTH_GRANT_ID, "github", "active"),
                native_grant(NATIVE_GRANT_ID, "active"),
            ],
            None,
        )
    };
    let elsewhere = || problem("409 Conflict", 409, "grant-already-authorized");
    let (server, _directory, credential) = prepared(vec![
        grants(),
        predating_served(),
        elsewhere(),
        grants(),
        predating_served(),
        elsewhere(),
    ]);
    let json = run_grant(
        &server,
        &credential,
        &[
            "authorize",
            "--all",
            "--runner",
            RUNNER_ID,
            "--yes",
            "--json",
        ],
    );
    let human = run_grant(
        &server,
        &credential,
        &["authorize", "--all", "--runner", RUNNER_ID, "--yes"],
    );

    assert_eq!(json.status.code(), Some(1), "{}", stderr(&json));
    let document = json_output(&json);
    assert_eq!(document["outcome"], "refused");
    assert_eq!(
        grant_outcomes(&document),
        [
            (OAUTH_GRANT_ID.to_owned(), "already_authorized".to_owned()),
            (
                NATIVE_GRANT_ID.to_owned(),
                "authorized_elsewhere".to_owned()
            ),
        ]
    );

    assert_eq!(human.status.code(), Some(1), "{}", stderr(&human));
    let text = stdout(&human);
    let line = |id: &str| {
        text.lines()
            .find(|line| line.contains(id))
            .unwrap_or_else(|| panic!("missing {id} in\n{text}"))
    };
    assert!(
        line(OAUTH_GRANT_ID).contains("already_authorized"),
        "{text}"
    );
    assert!(
        line(NATIVE_GRANT_ID).contains("authorized_elsewhere"),
        "{text}"
    );
    assert!(
        !line(NATIVE_GRANT_ID).contains("already_authorized"),
        "{text}"
    );
    // The refusal's remedy names the command that frees the grant.
    assert!(
        stderr(&human).contains("useful account integration deauthorize"),
        "{}",
        stderr(&human)
    );

    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [
            LIST_FIRST_PAGE,
            READ_SERVED,
            AUTHORIZE_CODEX,
            LIST_FIRST_PAGE,
            READ_SERVED,
            AUTHORIZE_CODEX
        ]
    );
}

#[test]
fn authorize_all_reports_runner_not_found_when_no_grant_finds_the_runner() {
    let mut linear = oauth_grant(LINEAR_GRANT_ID, "linear", "active");
    linear["authorizations"] = serde_json::json!([]);
    let not_found = || problem("404 Not Found", 404, "grant-runner-not-found");
    let (server, _directory, credential) = prepared(vec![
        page(&[linear, native_grant(NATIVE_GRANT_ID, "active")], None),
        predating_served(),
        not_found(),
        not_found(),
    ]);
    let output = run_grant(
        &server,
        &credential,
        &[
            "authorize",
            "--all",
            "--runner",
            NEW_RUNNER_ID,
            "--yes",
            "--json",
        ],
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(json_output(&output)["outcome"], "runner_not_found");
    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [
            LIST_FIRST_PAGE,
            READ_SERVED,
            AUTHORIZE_LINEAR,
            AUTHORIZE_CODEX
        ]
    );
}

// Cloud's answer to a request over the rate limit: a failure that is no refusal of one grant or
// one runner.
fn rate_limited() -> Vec<u8> {
    http_response_with_headers(
        "429 Too Many Requests",
        Some("application/problem+json"),
        &[("Retry-After", "7")],
        &serde_json::to_vec(&serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/rate-limit-exceeded",
            "title": "Slow down",
            "status": 429
        }))
        .unwrap(),
    )
}

#[test]
fn authorize_all_reports_the_authorizations_made_before_a_failure_that_ends_it() {
    let mut linear = oauth_grant(LINEAR_GRANT_ID, "linear", "active");
    linear["authorizations"] = serde_json::json!([]);
    let mut claude_code = native_grant(OTHER_NATIVE_GRANT_ID, "active");
    claude_code["provider"] = "claude_code".into();
    // Linear and Codex are authorized, Claude Code is rate limited, and the GitHub grant
    // after it is never tried.
    let grants = || {
        page(
            &[
                linear.clone(),
                native_grant(NATIVE_GRANT_ID, "active"),
                claude_code.clone(),
                oauth_grant_unauthorized(OAUTH_GRANT_ID),
            ],
            None,
        )
    };
    let mut responses = Vec::new();
    for _ in 0..2 {
        responses.extend([
            grants(),
            predating_served(),
            authorized(LINEAR_GRANT_ID, RUNNER_ID),
            authorized(NATIVE_GRANT_ID, RUNNER_ID),
            rate_limited(),
        ]);
    }
    let (server, _directory, credential) = prepared(responses);
    let json = run_grant(
        &server,
        &credential,
        &[
            "authorize",
            "--all",
            "--runner",
            RUNNER_ID,
            "--yes",
            "--json",
        ],
    );
    let human = run_grant(
        &server,
        &credential,
        &["authorize", "--all", "--runner", RUNNER_ID, "--yes"],
    );

    assert_eq!(json.status.code(), Some(1), "{}", stderr(&json));
    let documents: Vec<serde_json::Value> = serde_json::Deserializer::from_slice(&json.stdout)
        .into_iter()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(documents.len(), 2, "{}", stdout(&json));
    assert_eq!(documents[0]["outcome"], "refused");
    assert_eq!(documents[0]["runnerId"], RUNNER_ID);
    assert_eq!(
        grant_outcomes(&documents[0]),
        [
            (LINEAR_GRANT_ID.to_owned(), "authorized".to_owned()),
            (NATIVE_GRANT_ID.to_owned(), "authorized".to_owned()),
        ]
    );
    assert_eq!(
        documents[0]["grants"][1]["authorization"]["id"],
        "aga_01k0z6r1w8f4jy2m7q9v3x5abf"
    );
    assert_eq!(documents[1]["outcome"], "rate_limited");
    assert_eq!(documents[1]["retryAfter"], 7);

    assert_eq!(human.status.code(), Some(1), "{}", stderr(&human));
    let text = stdout(&human);
    for id in [LINEAR_GRANT_ID, NATIVE_GRANT_ID] {
        assert!(
            text.lines()
                .any(|line| line.contains(id) && line.contains("authorized")),
            "missing {id} in\n{text}"
        );
    }
    assert!(!text.contains(OAUTH_GRANT_ID), "{text}");
    // The failure names the grant it ended at.
    assert!(
        stderr(&human).contains(OTHER_NATIVE_GRANT_ID),
        "{}",
        stderr(&human)
    );

    let requests = server.finish();
    assert_member_requests(&requests);
    let expected = [
        LIST_FIRST_PAGE,
        READ_SERVED,
        AUTHORIZE_LINEAR,
        AUTHORIZE_CODEX,
        AUTHORIZE_CLAUDE_CODE,
    ];
    assert_eq!(request_lines(&requests[..5]), expected);
    assert_eq!(request_lines(&requests[5..]), expected);
}

// A Codex grant whose authorization for the runner ended while it was serving a run, as the
// grant is read after the change.
fn native_grant_deauthorized() -> serde_json::Value {
    let mut grant = native_grant_in_use();
    let mut ended = grant["authorizations"][0].clone();
    ended["endedAt"] = "2026-11-06T09:00:00Z".into();
    ended["removal"] = serde_json::json!({"state": "pending"});
    ended["stop"] = serde_json::json!({
        "runId": RUN_ID,
        "cancellationRequestId": CANCELLATION_REQUEST_ID,
        "requestedAt": "2026-11-06T09:00:01Z"
    });
    ended.as_object_mut().unwrap().remove("organizationId");
    grant["authorizations"] = serde_json::json!([]);
    grant["endedAuthorizations"] = serde_json::json!([ended]);
    grant
}

// SC-GRANTAUTH-4
#[test]
fn deauthorize_personal_pool_selects_only_the_oauth_organization_in_effect() {
    let mut grant = oauth_grant(OAUTH_GRANT_ID, "github", "active");
    let id = "pga_01k0z6r1w8f4jy2m7q9v3x5abf";
    grant["authorizations"]
        .as_array_mut()
        .unwrap()
        .push(pool_authorization(id, OTHER_ORGANIZATION_ID));
    let (server, _dir, credential) = prepared(vec![one(&grant), one(&grant), deleted()]);
    let run = |org: &str| {
        run_grant(
            &server,
            &credential,
            &[
                "deauthorize",
                OAUTH_GRANT_ID,
                "--personal-pool",
                "--org",
                org,
                "--yes",
                "--json",
            ],
        )
    };
    let missing = run(ORGANIZATION_ID);
    assert_eq!(missing.status.code(), Some(1));
    assert_eq!(json_output(&missing)["outcome"], "authorization_not_found");
    let ended = run(OTHER_ORGANIZATION_ID);
    assert_eq!(ended.status.code(), Some(0));
    assert_eq!(json_output(&ended)["runnerPoolId"], POOL_ID);
    assert!(json_output(&ended).get("runners").is_none());
    let delete = format!("DELETE /api/v1/me/grants/{OAUTH_GRANT_ID}/authorizations/{id} HTTP/1.1");
    assert_eq!(
        request_lines(&server.finish()),
        [READ_OAUTH, READ_OAUTH, &delete]
    );
}

// SC-GRANTAUTH-4
#[test]
fn deauthorize_personal_pool_reports_only_new_removals_of_pool_runners() {
    let id = "aga_01k0z6r1w8f4jy2m7q9v3x5abf";
    let mut before = native_grant_in_use();
    before["provider"] = "claude_code".into();
    let mut pool = pool_authorization(id, ORGANIZATION_ID);
    pool["runners"] = serde_json::json!([{"runnerId": RUNNER_ID, "conflict": false}, {"runnerId": ENDED_RUNNER_ID, "conflict": false}, {"runnerId": NEW_RUNNER_ID, "conflict": false}]);
    before["authorizations"].as_array_mut().unwrap().push(pool);
    let mut after = before.clone();
    after["authorizations"].as_array_mut().unwrap().pop();
    let mut newly_ended = native_grant_deauthorized()["endedAuthorizations"][0].clone();
    newly_ended["runnerId"] = NEW_RUNNER_ID.into();
    newly_ended["id"] = "aga_01k0z6r1w8f4jy2m7q9v3x5abe".into();
    after["endedAuthorizations"]
        .as_array_mut()
        .unwrap()
        .push(newly_ended.clone());
    let (server, _dir, credential) = prepared(vec![one(&before), deleted(), one(&after)]);
    let args = ["deauthorize", NATIVE_GRANT_ID, "--personal-pool"];
    let refusal = refusal_without_yes(&server, &credential, &args);
    let mut args = args.to_vec();
    args.extend(["--yes", "--json"]);
    let output = run_grant(&server, &credential, &args);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_stated_by_the_refusal(&statement(&output, NATIVE_GRANT_ID), &refusal);
    let result = json_output(&output);
    assert_eq!(result["authorizationId"], id);
    assert_eq!(result["runnerPoolId"], POOL_ID);
    assert!(result.get("runnerId").is_none());
    assert_eq!(
        result["runners"],
        serde_json::json!([{
            "runnerId": NEW_RUNNER_ID, "removal": newly_ended["removal"], "stop": newly_ended["stop"]
        }])
    );
    let delete = format!("DELETE /api/v1/me/grants/{NATIVE_GRANT_ID}/authorizations/{id} HTTP/1.1");
    assert_eq!(
        request_lines(&server.finish()),
        [READ_NATIVE, &delete, READ_NATIVE]
    );
}

const DEAUTHORIZE_NATIVE: &str = "DELETE /api/v1/me/grants/agl_01k0z6r1w8f4jy2m7q9v3x5abc/authorizations/aga_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1";

#[test]
fn deauthorize_ends_a_native_grants_authorization_and_reports_its_removal_and_stop() {
    let read = "GET /api/v1/me/grants/agl_01k0z6r1w8f4jy2m7q9v3x5abc?vocabulary=2 HTTP/1.1";
    let (server, _directory, credential) = prepared(vec![
        one(&native_grant_in_use()),
        Vec::new(),
        deleted(),
        one(&native_grant_deauthorized()),
        one(&native_grant_in_use()),
        deleted(),
        one(&native_grant_deauthorized()),
    ]);
    let json = run_grant(
        &server,
        &credential,
        &[
            "deauthorize",
            NATIVE_GRANT_ID,
            "--runner",
            RUNNER_ID,
            "--yes",
            "--json",
        ],
    );
    let human = run_grant(
        &server,
        &credential,
        &[
            "deauthorize",
            NATIVE_GRANT_ID,
            "--runner",
            RUNNER_ID,
            "--yes",
        ],
    );

    assert_eq!(json.status.code(), Some(0), "{}", stderr(&json));
    // Before acting it states that the run the runner serves will be asked to stop, as the
    // refusal without `--yes` does; the stop it reports is the outcome.
    assert_stated_by_the_refusal(
        &statement(&json, NATIVE_GRANT_ID),
        &refusal_without_yes(
            &server,
            &credential,
            &["deauthorize", NATIVE_GRANT_ID, "--runner", RUNNER_ID],
        ),
    );
    assert_eq!(
        json_output(&json),
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "outcome": "deauthorized",
            "grantId": NATIVE_GRANT_ID,
            "authorizationId": "aga_01k0z6r1w8f4jy2m7q9v3x5abc",
            "runnerId": RUNNER_ID,
            "removal": {"state": "pending"},
            "stop": {
                "runId": RUN_ID,
                "cancellationRequestId": CANCELLATION_REQUEST_ID,
                "requestedAt": "2026-11-06T09:00:01Z"
            }
        })
    );
    assert_eq!(human.status.code(), Some(0));
    let text = stdout(&human);
    for name in ["removal: pending", RUN_ID, CANCELLATION_REQUEST_ID] {
        assert!(text.contains(name), "missing {name:?} in\n{text}");
    }

    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [
            read,
            DEAUTHORIZE_NATIVE,
            DEAUTHORIZE_NATIVE,
            read,
            read,
            DEAUTHORIZE_NATIVE,
            read
        ]
    );
    let key = header_value(&requests[1], "idempotency-key");
    assert!(!key.is_empty());
    assert_eq!(header_value(&requests[2], "idempotency-key"), key);
}

#[test]
fn deauthorize_ends_an_oauth_grants_authorization_without_a_stop() {
    let (server, _directory, credential) = prepared(vec![
        page(&[oauth_grant(OAUTH_GRANT_ID, "github", "active")], None),
        deleted(),
    ]);
    let output = run_grant(
        &server,
        &credential,
        &[
            "deauthorize",
            "github",
            "--runner",
            RUNNER_ID,
            "--yes",
            "--json",
        ],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_stated_by_the_refusal(
        &statement(&output, OAUTH_GRANT_ID),
        &refusal_without_yes(
            &server,
            &credential,
            &["deauthorize", "github", "--runner", RUNNER_ID],
        ),
    );
    // No removal and no stop: the document is the authorization ended and nothing else.
    assert_eq!(
        json_output(&output),
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "outcome": "deauthorized",
            "grantId": OAUTH_GRANT_ID,
            "authorizationId": "pga_01k0z6r1w8f4jy2m7q9v3x5abc",
            "runnerId": RUNNER_ID
        })
    );
    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [
            LIST_FIRST_PAGE,
            "DELETE /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc/authorizations/pga_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1"
        ]
    );
}

// The Codex grant revoked: both runners' authorizations ended, each with its removal state
// and the stop requested of its run.
fn native_grant_revoked() -> serde_json::Value {
    let mut grant = native_grant_deauthorized();
    grant["state"] = "revoked".into();
    grant["revokedAt"] = "2026-11-06T09:00:00Z".into();
    let earlier = native_grant_in_use()["endedAuthorizations"][0].clone();
    grant["endedAuthorizations"]
        .as_array_mut()
        .unwrap()
        .push(earlier);
    grant
}

#[test]
fn revoke_erases_a_native_grant_and_reports_each_runners_removal_and_stop() {
    let delete = "DELETE /api/v1/me/grants/agl_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1";
    let read = "GET /api/v1/me/grants/agl_01k0z6r1w8f4jy2m7q9v3x5abc?vocabulary=2 HTTP/1.1";
    let after = native_grant_revoked();
    let (server, _directory, credential) = prepared(vec![
        page(&[native_grant_in_use()], None),
        deleted(),
        one(&after),
        one(&native_grant_in_use()),
        Vec::new(),
        deleted(),
        one(&after),
    ]);
    let human = run_grant(&server, &credential, &["disconnect", "codex", "--yes"]);
    let json = run_grant(
        &server,
        &credential,
        &["disconnect", NATIVE_GRANT_ID, "--yes", "--json"],
    );

    assert_eq!(human.status.code(), Some(0), "{}", stderr(&human));
    assert_stated_by_the_refusal(
        &statement(&human, NATIVE_GRANT_ID),
        &refusal_without_yes(&server, &credential, &["disconnect", "codex"]),
    );
    let text = stdout(&human);
    for name in [
        RUNNER_ID,
        ENDED_RUNNER_ID,
        "removal: pending",
        RUN_ID,
        CANCELLATION_REQUEST_ID,
    ] {
        assert!(text.contains(name), "missing {name:?} in\n{text}");
    }
    // Each runner with its removal state and stop, then what those say, each a paragraph of
    // its own: what a removal confirms, how to follow a stop, and that the session at the
    // provider is not ended. Their wording is not a contract; the command one names is.
    let (_, runners) = text
        .split_once("runners: 2\n")
        .unwrap_or_else(|| panic!("no runners in\n{text}"));
    let mut paragraphs = runners.split("\n\n");
    let block = paragraphs.next().unwrap();
    for runner in [RUNNER_ID, ENDED_RUNNER_ID] {
        assert!(block.contains(&format!("runner: {runner}")), "{text}");
    }
    assert_eq!(block.matches("removal: pending").count(), 2, "{text}");
    assert_eq!(block.matches(CANCELLATION_REQUEST_ID).count(), 2, "{text}");
    let notes: Vec<_> = paragraphs.collect();
    assert_eq!(notes.len(), 3, "{text}");
    assert!(
        notes
            .iter()
            .flat_map(|note| note.lines())
            .any(|line| line.trim() == "useful workflow run cancel RUN --wait"),
        "{text}"
    );

    assert_eq!(json.status.code(), Some(0), "{}", stderr(&json));
    let document = json_output(&json);
    assert_eq!(document["outcome"], "revoked");
    assert_eq!(document["grantId"], NATIVE_GRANT_ID);
    assert_eq!(document["kind"], "native");
    assert_eq!(
        document["endedAuthorizations"],
        after["endedAuthorizations"]
    );

    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [LIST_FIRST_PAGE, delete, read, read, delete, delete, read]
    );
    assert_ne!(
        header_value(&requests[1], "idempotency-key"),
        header_value(&requests[4], "idempotency-key")
    );
    assert_eq!(
        header_value(&requests[4], "idempotency-key"),
        header_value(&requests[5], "idempotency-key")
    );
}

#[test]
fn revoke_revokes_an_oauth_grant_without_reading_it_after() {
    let (server, _directory, credential) = prepared(vec![
        one(&oauth_grant(OAUTH_GRANT_ID, "github", "active")),
        deleted(),
    ]);
    let output = run_grant(
        &server,
        &credential,
        &["disconnect", OAUTH_GRANT_ID, "--yes", "--json"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_stated_by_the_refusal(
        &statement(&output, OAUTH_GRANT_ID),
        &refusal_without_yes(&server, &credential, &["disconnect", OAUTH_GRANT_ID]),
    );
    assert_eq!(
        json_output(&output),
        serde_json::json!({
            "schemaVersion": 1,
            "deployment": server.api_url,
            "outcome": "revoked",
            "grantId": OAUTH_GRANT_ID,
            "provider": "github",
            "kind": "oauth"
        })
    );
    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [
            "GET /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc?vocabulary=2 HTTP/1.1",
            "DELETE /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1"
        ]
    );
    assert!(!header_value(&requests[1], "idempotency-key").is_empty());
    assert!(requests[1].ends_with("\r\n\r\n"), "{}", requests[1]);
}

#[test]
fn each_refusal_these_leaves_meet_exits_1_with_its_remedy() {
    let native = || one(&native_grant(NATIVE_GRANT_ID, "active"));
    let authorize: &[&str] = &["authorize", NATIVE_GRANT_ID, "--runner", RUNNER_ID, "--yes"];
    // The arguments, Cloud's answers in order, the outcome, and the command its remedy names,
    // if it names one.
    type Case<'a> = (&'a [&'a str], Vec<Vec<u8>>, &'a str, Option<&'a str>);
    let cases: [Case; 5] = [
        (
            &["disconnect", NATIVE_GRANT_ID, "--yes"],
            vec![problem("404 Not Found", 404, "grant-not-found")],
            "grant_not_found",
            Some("useful account integration list"),
        ),
        (
            authorize,
            vec![
                native(),
                problem("503 Service Unavailable", 503, "provider-unavailable"),
            ],
            "provider_unavailable",
            // Its remedy names no command: only the deployment changes what it serves.
            None,
        ),
        (
            authorize,
            vec![
                native(),
                problem("404 Not Found", 404, "grant-runner-not-found"),
            ],
            "runner_not_found",
            Some("useful runner list"),
        ),
        (
            authorize,
            vec![
                native(),
                problem("409 Conflict", 409, "grant-runner-conflict"),
            ],
            "runner_holds_login",
            // The other login may reach the runner through its personal pool alone.
            Some("useful account integration deauthorize INTEGRATION --personal-pool"),
        ),
        // The runner holds no authorization in force, so nothing is deleted.
        (
            &[
                "deauthorize",
                NATIVE_GRANT_ID,
                "--runner",
                RUNNER_ID,
                "--yes",
            ],
            vec![native()],
            "authorization_not_found",
            Some("useful account integration show"),
        ),
    ];
    for (args, responses, outcome, remedy) in cases {
        let sent = responses.len();
        let (server, _directory, credential) = prepared([responses.clone(), responses].concat());
        let json = run_grant(&server, &credential, &[args, &["--json"]].concat());
        let human = run_grant(&server, &credential, args);

        assert_eq!(json.status.code(), Some(1), "{outcome}");
        assert_eq!(json_output(&json)["outcome"], outcome);
        assert_eq!(human.status.code(), Some(1), "{outcome}");
        let text = stderr(&human);
        let commands: Vec<_> = text
            .lines()
            .map(str::trim_start)
            .filter(|line| line.starts_with("useful "))
            .collect();
        match remedy {
            Some(command) => assert!(
                commands.iter().any(|line| line.starts_with(command)),
                "{outcome}: {text}"
            ),
            None => assert!(commands.is_empty(), "{outcome}: {text}"),
        }
        let requests = server.finish();
        assert_member_requests(&requests);
        assert_eq!(requests.len(), 2 * sent, "{outcome}");
        assert!(
            requests
                .iter()
                .all(|request| !request.starts_with("DELETE")),
            "{outcome}"
        );
    }
}

#[test]
fn a_codex_grant_authorized_for_another_runner_names_the_deauthorize_that_moves_it() {
    // Cloud answers a Codex grant authorized for another runner `grant-already-authorized`.
    let answers = || {
        vec![
            one(&native_grant(NATIVE_GRANT_ID, "active")),
            problem("409 Conflict", 409, "grant-already-authorized"),
        ]
    };
    let (server, _directory, credential) = prepared([answers(), answers()].concat());
    let args = ["authorize", NATIVE_GRANT_ID, "--runner", RUNNER_ID, "--yes"];
    let json = run_grant(&server, &credential, &[&args[..], &["--json"]].concat());
    let human = run_grant(&server, &credential, &args);

    assert_eq!(json.status.code(), Some(1));
    assert_eq!(json_output(&json)["outcome"], "already_authorized");
    assert_eq!(human.status.code(), Some(1));
    let text = stderr(&human);
    assert!(
        text.contains("useful account integration deauthorize INTEGRATION --runner RUNNER --yes"),
        "{text}"
    );
    // Another sign-in cannot serve the other runner: the held grant is refused or replaced
    // in place.
    assert!(
        !text.contains("useful account integration connect codex"),
        "{text}"
    );
    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(requests.len(), 4);
    assert!(
        requests
            .iter()
            .all(|request| !request.starts_with("DELETE"))
    );
}

// `useful account integration authorize` and `deauthorize` given no `--runner`, which name the
// runners they can act on in its place, on a terminal or not.
const GLOBEX_RUNNER_ID: &str = "rnr_01k0z6r1w8f4jy2m7q9v3x5abf";
pub(super) const LIST_ACME_RUNNERS: &str = "GET /api/v1/organizations/org_01k0z6r1w8f4jy2m7q9v3x5abc/runner-registrations?limit=200 HTTP/1.1";
const LIST_GLOBEX_RUNNERS: &str = "GET /api/v1/organizations/org_01k0z6r1w8f4jy2m7q9v3x5abe/runner-registrations?limit=200 HTTP/1.1";

// A runner of `organization_id` in the pool `builders`, as the runner registrations list it.
pub(super) fn registration(
    (id, organization_id, name): (&str, &str, &str),
    connectivity: &str,
    mode: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "organizationId": organization_id,
        "runnerPool": {"id": "rpl_01k0z6r1w8f4jy2m7q9v3x5abc", "name": "builders"},
        "name": name,
        "administration": {
            "mode": mode,
            "createdAt": "2026-11-01T08:00:00Z",
            "updatedAt": "2026-11-01T08:00:00Z"
        },
        "enrollment": {"state": "credentialed", "validCredentialCount": 1},
        "connectivity": {"state": connectivity},
        "activity": {"state": "idle", "currentAssignmentCount": 0}
    })
}

pub(super) fn registrations(items: &[serde_json::Value]) -> Vec<u8> {
    json_http_response("200 OK", serde_json::json!({"items": items}))
}

pub(super) const ALPHA: (&str, &str, &str) = (ENDED_RUNNER_ID, ORGANIZATION_ID, "alpha");
pub(super) const BRAVO: (&str, &str, &str) = (NEW_RUNNER_ID, ORGANIZATION_ID, "bravo");
pub(super) const CHARLIE: (&str, &str, &str) = (RUNNER_ID, ORGANIZATION_ID, "charlie");
const DELTA: (&str, &str, &str) = (GLOBEX_RUNNER_ID, GLOBEX_ORGANIZATION_ID, "delta");

// Acme's three runners: an offline one, an online draining one, and, listed last, the one
// online and enabled.
fn acme_runners() -> Vec<u8> {
    registrations(&[
        registration(ALPHA, "offline", "enabled"),
        registration(BRAVO, "online", "draining"),
        registration(CHARLIE, "online", "enabled"),
    ])
}

// The runners `--json` names, by ID and name, in the order it names them.
pub(super) fn offered(document: &serde_json::Value) -> Vec<(String, serde_json::Value)> {
    document["runners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|runner| {
            (
                runner["id"].as_str().unwrap().to_owned(),
                runner["name"].clone(),
            )
        })
        .collect()
}

// Where in `output`'s standard error each runner is named, by the line that holds both its ID
// and its name; the runner each line names, in the order the lines come.
pub(super) fn named_runners(output: &Output, runners: &[(&str, &str, &str)]) -> Vec<String> {
    let text = stderr(output);
    let mut named: Vec<_> = runners
        .iter()
        .map(|(id, _, name)| {
            let line = text
                .lines()
                .position(|line| line.contains(id) && line.contains(name))
                .unwrap_or_else(|| panic!("{name} {id} not on one line of\n{text}"));
            (line, (*name).to_owned())
        })
        .collect();
    named.sort();
    named.into_iter().map(|(_, name)| name).collect()
}

#[test]
fn authorize_without_a_runner_names_each_runner_it_can_act_on() {
    let grants = || page(&[native_grant(NATIVE_GRANT_ID, "active")], None);
    let (server, _directory, credential) =
        prepared(vec![grants(), acme_runners(), grants(), acme_runners()]);
    let human = run_grant(&server, &credential, &["authorize", "codex"]);
    let json = run_grant(&server, &credential, &["authorize", "codex", "--json"]);

    // It exits as a missing argument does, naming each runner by its name and ID, the one
    // online and enabled first, though the server listed it last, and the rest by name.
    assert_eq!(human.status.code(), Some(2), "{}", stderr(&human));
    assert!(human.stdout.is_empty());
    assert_eq!(
        named_runners(&human, &[ALPHA, BRAVO, CHARLIE]),
        ["charlie", "alpha", "bravo"]
    );
    // It ends with the command line that names one of them.
    let text = stderr(&human);
    let last = text.lines().last().unwrap_or_default();
    assert!(
        last.contains("useful account integration authorize")
            && last.contains(RUNNER_ID)
            && last.contains("--yes"),
        "{text}"
    );

    assert_eq!(json.status.code(), Some(2), "{}", stderr(&json));
    let document = json_output(&json);
    assert_eq!(document["outcome"], "runner_required");
    assert_eq!(document["grantId"], NATIVE_GRANT_ID);
    assert_eq!(
        offered(&document),
        [
            (RUNNER_ID.to_owned(), "charlie".into()),
            (ENDED_RUNNER_ID.to_owned(), "alpha".into()),
            (NEW_RUNNER_ID.to_owned(), "bravo".into()),
        ]
    );
    assert_eq!(
        document["runners"][2],
        serde_json::json!({
            "id": NEW_RUNNER_ID,
            "name": "bravo",
            "pool": "builders",
            "connectivity": "online",
            "mode": "draining",
            "organizationId": ORGANIZATION_ID
        })
    );

    // It read the grant and the runners of its organization, and sent nothing.
    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [
            LIST_FIRST_PAGE,
            LIST_ACME_RUNNERS,
            LIST_FIRST_PAGE,
            LIST_ACME_RUNNERS
        ]
    );
}

#[test]
fn deauthorize_without_a_runner_names_only_the_runners_the_grant_is_authorized_for() {
    let (server, _directory, credential) = prepared(vec![
        one(&native_grant_in_use()),
        acme_runners(),
        // An OAuth grant authorized for a runner whose registration is gone.
        one(&oauth_grant(OAUTH_GRANT_ID, "github", "active")),
        registrations(&[]),
    ]);
    let human = run_grant(&server, &credential, &["deauthorize", NATIVE_GRANT_ID]);
    let unregistered = run_grant(
        &server,
        &credential,
        &["deauthorize", OAUTH_GRANT_ID, "--json"],
    );

    assert_eq!(human.status.code(), Some(2), "{}", stderr(&human));
    assert!(human.stdout.is_empty());
    assert_eq!(named_runners(&human, &[CHARLIE]), ["charlie"]);
    let text = stderr(&human);
    for other in [ENDED_RUNNER_ID, NEW_RUNNER_ID] {
        assert!(!text.contains(other), "{other} in\n{text}");
    }

    // A runner no registration is found for is named by its ID alone.
    assert_eq!(unregistered.status.code(), Some(2));
    let document = json_output(&unregistered);
    assert_eq!(document["outcome"], "runner_required");
    assert_eq!(document["grantId"], OAUTH_GRANT_ID);
    assert_eq!(
        offered(&document),
        [(RUNNER_ID.to_owned(), serde_json::Value::Null)]
    );
    assert_eq!(document["runners"][0]["organizationId"], ORGANIZATION_ID);

    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [
            "GET /api/v1/me/grants/agl_01k0z6r1w8f4jy2m7q9v3x5abc?vocabulary=2 HTTP/1.1",
            LIST_ACME_RUNNERS,
            "GET /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc?vocabulary=2 HTTP/1.1",
            LIST_ACME_RUNNERS,
        ]
    );
}

#[test]
fn authorize_all_without_a_runner_names_the_runners_of_every_active_organization() {
    let organizations = || {
        memberships(&[
            (ORGANIZATION_ID, "acme"),
            (GLOBEX_ORGANIZATION_ID, "globex"),
        ])
    };
    let globex = || registrations(&[registration(DELTA, "online", "enabled")]);
    let (server, _directory, credential) = prepared(vec![
        organizations(),
        acme_runners(),
        globex(),
        organizations(),
        acme_runners(),
        globex(),
    ]);
    let human = run_grant(&server, &credential, &["authorize", "--all"]);
    let json = run_grant(&server, &credential, &["authorize", "--all", "--json"]);

    assert_eq!(human.status.code(), Some(2), "{}", stderr(&human));
    assert!(human.stdout.is_empty());
    assert_eq!(
        named_runners(&human, &[ALPHA, BRAVO, CHARLIE, DELTA]),
        ["charlie", "delta", "alpha", "bravo"]
    );

    assert_eq!(json.status.code(), Some(2));
    let document = json_output(&json);
    assert_eq!(document["outcome"], "runner_required");
    // No one grant is named.
    assert!(document.get("grantId").is_none(), "{document}");
    assert_eq!(
        document["runners"][1]["organizationId"],
        GLOBEX_ORGANIZATION_ID
    );
    assert_eq!(offered(&document).len(), 4);

    // The ended membership's organization is not read.
    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [
            LIST_MEMBERSHIPS,
            LIST_ACME_RUNNERS,
            LIST_GLOBEX_RUNNERS,
            LIST_MEMBERSHIPS,
            LIST_ACME_RUNNERS,
            LIST_GLOBEX_RUNNERS,
        ]
    );
}

#[test]
fn a_command_with_no_runner_to_offer_exits_1_with_why() {
    let mut oauth = oauth_grant(OAUTH_GRANT_ID, "github", "active");
    oauth["authorizations"][0]["runnerId"] = ALPHA.0.into();
    // The arguments, Cloud's answers in order, and the outcome.
    type Case<'a> = (&'a [&'a str], Vec<Vec<u8>>, &'a str);
    let cases: [Case; 5] = [
        // The grant's organization holds no runner.
        (
            &["authorize", NATIVE_GRANT_ID],
            vec![
                one(&native_grant(NATIVE_GRANT_ID, "active")),
                registrations(&[]),
            ],
            "runner_not_found",
        ),
        (
            &["authorize", "--all"],
            vec![only_acme(), registrations(&[])],
            "runner_not_found",
        ),
        // The OAuth grant is authorized for every runner of the member's one organization.
        (
            &["authorize", OAUTH_GRANT_ID],
            vec![
                one(&oauth),
                only_acme(),
                registrations(&[registration(ALPHA, "online", "enabled")]),
            ],
            "already_authorized",
        ),
        // A Codex grant serves one runner, and this one is authorized for one already, so no
        // runner is read.
        (
            &["authorize", NATIVE_GRANT_ID],
            vec![one(&native_grant_in_use())],
            "authorized_elsewhere",
        ),
        (
            &["deauthorize", NATIVE_GRANT_ID],
            vec![one(&native_grant(NATIVE_GRANT_ID, "active"))],
            "authorization_not_found",
        ),
    ];
    for (args, responses, outcome) in cases {
        let sent = responses.len();
        let (server, _directory, credential) = prepared([responses.clone(), responses].concat());
        let json = run_grant(&server, &credential, &[args, &["--json"]].concat());
        let human = run_grant(&server, &credential, args);

        assert_eq!(json.status.code(), Some(1), "{outcome}: {}", stderr(&json));
        assert_eq!(json_output(&json)["outcome"], outcome);
        assert_eq!(human.status.code(), Some(1), "{outcome}");
        assert!(human.stdout.is_empty(), "{outcome}");
        let requests = server.finish();
        assert_member_requests(&requests);
        assert_eq!(requests.len(), 2 * sent, "{outcome}");
        assert!(
            requests.iter().all(|request| request.starts_with("GET ")),
            "{outcome}"
        );
    }
}

// A runner named `build-1` in Acme, and one of the same name in Globex.
const BUILD_1: (&str, &str, &str) = (RUNNER_ID, ORGANIZATION_ID, "build-1");
const GLOBEX_BUILD_1: (&str, &str, &str) = (GLOBEX_RUNNER_ID, GLOBEX_ORGANIZATION_ID, "build-1");

// Acme's runners: an offline one, an online draining one, and `build-1`.
fn acme_runners_with_build_1() -> Vec<u8> {
    registrations(&[
        registration(ALPHA, "offline", "enabled"),
        registration(BRAVO, "online", "draining"),
        registration(BUILD_1, "online", "enabled"),
    ])
}

const AUTHORIZE_NATIVE: &str =
    "POST /api/v1/me/grants/agl_01k0z6r1w8f4jy2m7q9v3x5abc/authorizations HTTP/1.1";
const AUTHORIZE_OAUTH: &str =
    "POST /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc/authorizations HTTP/1.1";
const READ_NATIVE: &str =
    "GET /api/v1/me/grants/agl_01k0z6r1w8f4jy2m7q9v3x5abc?vocabulary=2 HTTP/1.1";
const READ_OAUTH: &str =
    "GET /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc?vocabulary=2 HTTP/1.1";

#[test]
fn a_runner_named_by_its_exact_name_is_sent_by_the_id_of_the_one_runner_that_has_it() {
    // An OAuth grant already authorized for `build-1`, which the name still finds: Cloud
    // answers that the grant is authorized for it already.
    let oauth = oauth_grant(OAUTH_GRANT_ID, "github", "active");
    // The arguments, Cloud's answers in order, the exit status, and the requests made.
    type Case<'a> = (&'a [&'a str], Vec<Vec<u8>>, i32, Vec<&'a str>);
    let cases: [Case; 4] = [
        (
            &["authorize", NATIVE_GRANT_ID, "--runner", "build-1", "--yes"],
            vec![
                one(&native_grant(NATIVE_GRANT_ID, "active")),
                acme_runners_with_build_1(),
                authorized(NATIVE_GRANT_ID, RUNNER_ID),
            ],
            0,
            vec![READ_NATIVE, LIST_ACME_RUNNERS, AUTHORIZE_NATIVE],
        ),
        (
            &["authorize", OAUTH_GRANT_ID, "--runner", "build-1", "--yes"],
            vec![
                one(&oauth),
                only_acme(),
                acme_runners_with_build_1(),
                problem("409 Conflict", 409, "grant-already-authorized"),
            ],
            1,
            vec![
                READ_OAUTH,
                LIST_MEMBERSHIPS,
                LIST_ACME_RUNNERS,
                AUTHORIZE_OAUTH,
            ],
        ),
        (
            &["authorize", "--all", "--runner", "build-1", "--yes"],
            vec![
                only_acme(),
                acme_runners_with_build_1(),
                page(&[native_grant(NATIVE_GRANT_ID, "active")], None),
                predating_served(),
                authorized(NATIVE_GRANT_ID, RUNNER_ID),
            ],
            0,
            vec![
                LIST_MEMBERSHIPS,
                LIST_ACME_RUNNERS,
                LIST_FIRST_PAGE,
                READ_SERVED,
                AUTHORIZE_NATIVE,
            ],
        ),
        (
            &[
                "deauthorize",
                NATIVE_GRANT_ID,
                "--runner",
                "build-1",
                "--yes",
            ],
            vec![
                one(&native_grant_in_use()),
                acme_runners_with_build_1(),
                deleted(),
                one(&native_grant_deauthorized()),
            ],
            0,
            vec![
                READ_NATIVE,
                LIST_ACME_RUNNERS,
                DEAUTHORIZE_NATIVE,
                READ_NATIVE,
            ],
        ),
    ];
    for (args, responses, status, expected) in cases {
        let (server, _directory, credential) = prepared(responses);
        let output = run_grant(&server, &credential, &[args, &["--json"]].concat());

        assert_eq!(
            output.status.code(),
            Some(status),
            "{args:?}: {}",
            stderr(&output)
        );
        let requests = server.finish();
        assert_member_requests(&requests);
        assert_eq!(request_lines(&requests), expected, "{args:?}");
        // What is sent names the runner by its ID, as the command line with that ID would.
        if let Some(post) = requests.iter().find(|request| request.starts_with("POST ")) {
            assert_eq!(
                request_body(post),
                serde_json::json!({"runnerId": RUNNER_ID}),
                "{args:?}"
            );
        }
        let document = json_output(&output);
        if status == 1 {
            assert_eq!(document["outcome"], "already_authorized", "{args:?}");
        } else {
            assert!(document.to_string().contains(RUNNER_ID), "{document}");
        }
    }
}

#[test]
fn a_runner_name_that_names_no_runner_or_several_sends_nothing() {
    let organizations = || {
        memberships(&[
            (ORGANIZATION_ID, "acme"),
            (GLOBEX_ORGANIZATION_ID, "globex"),
        ])
    };
    let globex = || registrations(&[registration(GLOBEX_BUILD_1, "online", "enabled")]);
    let (server, _directory, credential) = prepared(vec![
        organizations(),
        acme_runners_with_build_1(),
        globex(),
        organizations(),
        acme_runners_with_build_1(),
        globex(),
        one(&native_grant(NATIVE_GRANT_ID, "active")),
        acme_runners_with_build_1(),
        one(&native_grant(NATIVE_GRANT_ID, "active")),
        acme_runners_with_build_1(),
    ]);
    let several = ["authorize", "--all", "--runner", "build-1", "--yes"];
    let human = run_grant(&server, &credential, &several);
    let json = run_grant(&server, &credential, &[&several[..], &["--json"]].concat());
    let none = ["authorize", NATIVE_GRANT_ID, "--runner", "build-9", "--yes"];
    let none_human = run_grant(&server, &credential, &none);
    let none_json = run_grant(&server, &credential, &[&none[..], &["--json"]].concat());

    // Two runners of different organizations named `build-1`: exit 2, naming each by its
    // name and ID with its organization, on a line of its own.
    assert_eq!(human.status.code(), Some(2), "{}", stderr(&human));
    assert!(human.stdout.is_empty());
    let text = stderr(&human);
    for (id, organization_id, _) in [BUILD_1, GLOBEX_BUILD_1] {
        assert!(
            text.lines().any(|line| line.contains(id)
                && line.contains(organization_id)
                && line.contains("build-1")),
            "{id} not in\n{text}"
        );
    }
    assert_eq!(json.status.code(), Some(2), "{}", stderr(&json));
    let document = json_output(&json);
    assert_eq!(document["outcome"], "runner_required");
    let mut named = offered(&document);
    named.sort_by(|(left, _), (right, _)| left.cmp(right));
    assert_eq!(
        named,
        [
            (RUNNER_ID.to_owned(), "build-1".into()),
            (GLOBEX_RUNNER_ID.to_owned(), "build-1".into()),
        ]
    );

    // A name no runner the command read has is `runner_not_found`.
    assert_eq!(none_human.status.code(), Some(1), "{}", stderr(&none_human));
    assert!(none_human.stdout.is_empty());
    assert_eq!(none_json.status.code(), Some(1));
    assert_eq!(json_output(&none_json)["outcome"], "runner_not_found");

    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [
            LIST_MEMBERSHIPS,
            LIST_ACME_RUNNERS,
            LIST_GLOBEX_RUNNERS,
            LIST_MEMBERSHIPS,
            LIST_ACME_RUNNERS,
            LIST_GLOBEX_RUNNERS,
            READ_NATIVE,
            LIST_ACME_RUNNERS,
            READ_NATIVE,
            LIST_ACME_RUNNERS,
        ]
    );
}

// `useful account integration authorize` and `deauthorize` on a terminal, where they show no list
// and ask only whether to go on.

/// `useful account integration` with `args`, to run on a terminal: as the leader of a new session whose
/// controlling terminal is its standard input, the terminal the list measures to draw on. The
/// CLI test environment includes Python.
fn grant_on_terminal(server: &ScriptedServer, credential: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("python3");
    command
        .args([
            "-c",
            "import fcntl, os, sys, termios; os.setsid(); \
             fcntl.ioctl(0, termios.TIOCSCTTY, 0); os.execv(sys.argv[1], sys.argv[1:])",
            crate::executable().to_str().unwrap(),
            "account",
            "integration",
        ])
        .args(args)
        .arg("--allow-insecure-http");
    for variable in DEPLOYMENT_VARIABLES
        .into_iter()
        .chain(RUNNER_TELEMETRY_VARIABLES)
    {
        command.env_remove(variable);
    }
    command.envs(deployment_environment_with_issuer(
        &server.api_url,
        &server.issuer,
        credential.to_str().unwrap(),
    ));
    command
}

#[test]
fn on_a_terminal_a_leaf_given_no_runner_names_the_runners_and_asks_nothing() {
    let grants = || page(&[native_grant(NATIVE_GRANT_ID, "active")], None);
    let (server, _directory, credential) =
        prepared(vec![grants(), acme_runners(), grants(), acme_runners()]);
    // Nothing is typed: the command neither draws a list nor asks, with or without `--json`.
    let (shown, human) = on_terminal(
        grant_on_terminal(&server, &credential, &["authorize", "codex"]),
        &[],
    );
    let (json_shown, json) = on_terminal(
        grant_on_terminal(&server, &credential, &["authorize", "codex", "--json"]),
        &[],
    );

    assert_eq!(human.status.code(), Some(2), "{shown}");
    assert!(human.stdout.is_empty());
    for (id, _, name) in [ALPHA, BRAVO, CHARLIE] {
        assert!(
            shown
                .lines()
                .any(|line| line.contains(id) && line.contains(name)),
            "{name} not in\n{shown}"
        );
    }
    assert!(!shown.contains("[y/N]"), "{shown}");

    assert_eq!(json.status.code(), Some(2), "{json_shown}");
    let document = json_output(&json);
    assert_eq!(document["outcome"], "runner_required");
    assert_eq!(offered(&document).len(), 3);
    assert!(!json_shown.contains(RUNNER_ID), "{json_shown}");

    assert_eq!(
        request_lines(&server.finish()),
        [
            LIST_FIRST_PAGE,
            LIST_ACME_RUNNERS,
            LIST_FIRST_PAGE,
            LIST_ACME_RUNNERS
        ]
    );
}

#[test]
fn without_yes_on_a_terminal_a_leaf_states_what_acting_does_then_asks_whether_to_go_on() {
    // The runner as `--runner` names it, the answer typed, and whether the runner is
    // authorized; the exit status follows.
    let cases = [
        ("build-1", "y\n", true),
        (RUNNER_ID, "y\n", true),
        (RUNNER_ID, "n\n", false),
        (RUNNER_ID, "\n", false),
    ];
    for (runner, answer, authorizes) in cases {
        let case = format!("{runner} {answer:?}");
        let by_name = !runner.starts_with("rnr_");
        let mut responses = vec![one(&native_grant(NATIVE_GRANT_ID, "active"))];
        if by_name {
            responses.push(acme_runners_with_build_1());
        }
        if authorizes {
            responses.push(authorized(NATIVE_GRANT_ID, RUNNER_ID));
        }
        let (server, _directory, credential) = prepared(responses);
        let command = grant_on_terminal(
            &server,
            &credential,
            &["authorize", NATIVE_GRANT_ID, "--runner", runner],
        );
        let (asked, output) = answered(command, answer);

        // Before the question, the statement names the grant and the runner, by its name and
        // ID when named by its name.
        let heading = asked
            .lines()
            .find(|line| line.contains(NATIVE_GRANT_ID))
            .unwrap_or_else(|| panic!("{case}: no statement in\n{asked}"));
        assert!(heading.contains(RUNNER_ID), "{case}: {heading}");
        assert_eq!(heading.contains("build-1"), by_name, "{case}: {heading}");
        assert!(asked.ends_with("[y/N]"), "{case}\n{asked}");

        let requests = server.finish();
        assert_member_requests(&requests);
        let mut expected = vec![READ_NATIVE];
        if by_name {
            expected.push(LIST_ACME_RUNNERS);
        }
        if authorizes {
            expected.push(AUTHORIZE_NATIVE);
        }
        assert_eq!(request_lines(&requests), expected, "{case}");
        let text = stdout(&output);
        if authorizes {
            assert_eq!(output.status.code(), Some(0), "{case}");
            assert!(
                text.contains("aga_01k0z6r1w8f4jy2m7q9v3x5abf"),
                "{case}: {text}"
            );
        } else {
            assert_eq!(output.status.code(), Some(2), "{case}");
            assert!(text.is_empty(), "{case}: {text}");
        }
    }
}

// `useful account integration connect`. Each case sets in its own environment whether this machine has a
// browser, so no case can open a real one: the only opener on `PATH` is a fake that records
// what it is given.

const SESSION_ID: &str = "pgs_01k0z6r1w8f4jy2m7q9v3x5abc";
const CONSENT_URL: &str = "https://linear.app/oauth/authorize?state=public-fixture-state";
const OPENER: &str = if cfg!(target_os = "macos") {
    "open"
} else {
    "xdg-open"
};
// Every variable the browser rule reads besides `PATH`, removed from each child so that only
// the case decides.
const BROWSER_VARIABLES: [&str; 5] = [
    "SSH_CONNECTION",
    "SSH_CLIENT",
    "SSH_TTY",
    "DISPLAY",
    "WAYLAND_DISPLAY",
];
pub(super) const LIST_OAUTH: &str =
    "GET /api/v1/me/grants?kind=oauth&limit=200&vocabulary=2 HTTP/1.1";
pub(super) const START_CONSENT: &str = "POST /api/v1/me/grants?vocabulary=2 HTTP/1.1";

/// Where `useful account integration connect` runs.
#[derive(Clone, Copy, Debug)]
pub(super) enum Place {
    /// No SSH variable, and on Linux a display.
    Desktop,
    /// A remote shell, which forwards a display on Linux.
    Remote,
    /// No SSH variable and no display.
    Headless,
}

/// A directory holding only the fake opener, which records how many arguments it was given
/// and the first, then exits with its status.
pub(super) struct Opener {
    directory: tempfile::TempDir,
}

impl Opener {
    pub(super) fn new(status: u8) -> Self {
        Self::running(&format!("exit {status}"))
    }

    /// An opener that, like `xdg-open` running a browser in the foreground, does not return
    /// until the browser quits: it records its process id in `pid` and sleeps.
    fn lingering() -> Self {
        use super::pi_installation::quote;
        Self::running(&format!(
            "PATH={}\nexport PATH\necho \"$$\" > pid\nexec sleep 600",
            quote(&std::env::var("PATH").unwrap_or_default())
        ))
    }

    // An opener that records its arguments, then runs `rest` in its directory.
    fn running(rest: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join(OPENER);
        fs::write(
            &script,
            format!(
                "#!/bin/sh\ncd '{}'\nprintf '%s %s\\n' \"$#\" \"$1\" >> opened\n{rest}\n",
                directory.path().display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, Permissions::from_mode(0o755)).unwrap();
        Self { directory }
    }

    /// Ends a lingering opener once it has recorded its process id.
    fn end(&self) {
        let record = self.directory.path().join("pid");
        let pid = poll_until(
            "the opener recording its process id",
            || fs::read_to_string(&record).unwrap_or_default(),
            |pid| pid.ends_with('\n'),
        );
        let _ = rustix::process::kill_process(
            rustix::process::Pid::from_raw(pid.trim().parse().unwrap()).unwrap(),
            rustix::process::Signal::KILL,
        );
    }

    /// What the openers recorded, sorted, once at least `count` have: `useful` starts an opener
    /// and goes on without it, so an opener may record after `useful` has returned.
    pub(super) fn opened(&self, count: usize) -> Vec<String> {
        let mut opened = poll_until(
            "the opener recording its arguments",
            || {
                fs::read_to_string(self.directory.path().join("opened"))
                    .map(|record| record.lines().map(str::to_owned).collect::<Vec<_>>())
                    .unwrap_or_default()
            },
            |opened| opened.len() >= count,
        );
        opened.sort();
        opened
    }
}

/// The leading words of `useful account integration connect`.
const GRANT_CREATE: &[&str] = &["account", "integration", "connect"];
/// The leading words of `useful workflow doctor`.
const WORKFLOW_DOCTOR: &[&str] = &["workflow", "doctor"];

fn create_command(
    server: &ScriptedServer,
    credential: &Path,
    opener: &Opener,
    place: Place,
    args: &[&str],
) -> Command {
    opener_command(
        server,
        credential,
        opener,
        place,
        &[GRANT_CREATE, args].concat(),
    )
}

/// `useful` with `arguments`, where `place` decides whether this machine has a browser and the
/// only opener on `PATH` is `opener`.
pub(super) fn opener_command(
    server: &ScriptedServer,
    credential: &Path,
    opener: &Opener,
    place: Place,
    arguments: &[&str],
) -> Command {
    let mut command = Command::new(crate::executable());
    command.args(arguments).arg("--allow-insecure-http");
    for variable in DEPLOYMENT_VARIABLES
        .into_iter()
        .chain(RUNNER_TELEMETRY_VARIABLES)
        .chain(BROWSER_VARIABLES)
    {
        command.env_remove(variable);
    }
    command
        .envs(deployment_environment_with_issuer(
            &server.api_url,
            &server.issuer,
            credential.to_str().unwrap(),
        ))
        .env("PATH", opener.directory.path());
    let display = cfg!(target_os = "linux").then_some(("DISPLAY", ":0"));
    match place {
        Place::Desktop => command.envs(display),
        Place::Remote => command
            .envs(display)
            .env("SSH_CONNECTION", "198.51.100.7 52000 192.0.2.10 22"),
        Place::Headless => &mut command,
    };
    command
}

/// Runs `useful account integration connect` with standard input that is not a terminal.
fn run_create(
    server: &ScriptedServer,
    credential: &Path,
    opener: &Opener,
    place: Place,
    args: &[&str],
) -> Output {
    let output = create_command(server, credential, opener, place, args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_no_secret_output(&output, &[SENTINEL, TOKEN]);
    output
}

// The Linear consent as the API presents it, carrying material the CLI must drop.
fn session(status: &str) -> serde_json::Value {
    let mut session = serde_json::json!({
        "id": SESSION_ID,
        "provider": "linear",
        "status": status,
        "createdAt": "2026-11-13T08:00:00Z",
        "expiresAt": "2026-11-13T08:15:00Z",
        "accessToken": SENTINEL
    });
    match status {
        "pending" => session["authorizationUrl"] = CONSENT_URL.into(),
        "completed" => {
            session["completedAt"] = "2026-11-13T08:01:00Z".into();
            session["resultGrant"] = serde_json::json!({
                "id": OAUTH_GRANT_ID,
                "identityId": IDENTITY_ID,
                "provider": "linear",
                "scopes": ["read"],
                "state": "active",
                "createdAt": "2026-11-13T08:01:00Z",
                "accessToken": SENTINEL
            });
        }
        _ => {}
    }
    session
}

fn started() -> Vec<u8> {
    json_http_response("201 Created", session("pending"))
}

fn polled(session: serde_json::Value) -> Vec<u8> {
    json_http_response("200 OK", session)
}

pub(super) fn nothing_held() -> Vec<u8> {
    page(&[], None)
}

fn events(output: &Output) -> Vec<serde_json::Value> {
    output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

fn poll_line() -> String {
    format!("GET /api/v1/me/grant-sessions/{SESSION_ID}?vocabulary=2 HTTP/1.1")
}

#[test]
fn create_starts_the_consent_opens_its_url_and_waits_for_the_grant() {
    // An opener that fails changes nothing: the URL is printed whatever it does.
    for (status, json) in [(0, false), (0, true), (1, false)] {
        let (server, _directory, credential) = prepared(vec![
            nothing_held(),
            started(),
            polled(session("pending")),
            polled(session("completed")),
        ]);
        let opener = Opener::new(status);
        let mut args = vec!["linear"];
        if json {
            args.push("--json");
        }
        let output = run_create(&server, &credential, &opener, Place::Desktop, &args);

        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(opener.opened(1), [format!("1 {CONSENT_URL}")]);
        if json {
            let events = events(&output);
            assert_eq!(events.len(), 2);
            assert_eq!(events[0]["event"], "consent_required");
            assert_eq!(events[0]["sessionId"], SESSION_ID);
            assert_eq!(events[0]["provider"], "linear");
            assert_eq!(events[0]["authorizationUrl"], CONSENT_URL);
            assert_eq!(events[1]["event"], "consent_result");
            assert_eq!(events[1]["outcome"], "completed");
            assert_eq!(events[1]["grant"]["id"], OAUTH_GRANT_ID);
            assert_eq!(events[1]["grant"]["provider"], "linear");
        } else {
            let text = stdout(&output);
            assert!(text.contains(CONSENT_URL), "{text}");
            assert!(text.contains(&format!("grant: {OAUTH_GRANT_ID}")), "{text}");
        }
        let requests = server.finish();
        assert_member_requests(&requests);
        let poll = poll_line();
        assert_eq!(
            request_lines(&requests),
            [LIST_OAUTH, START_CONSENT, poll.as_str(), poll.as_str()]
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                requests[1].split_once("\r\n\r\n").unwrap().1
            )
            .unwrap(),
            serde_json::json!({"provider": "linear"})
        );
        assert!(!header_value(&requests[1], "idempotency-key").is_empty());
    }
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "the bound on useful's return is far below the opener's own life, so real time only separates returning from waiting for the opener"
)]
fn an_opener_that_waits_for_the_browser_to_quit_does_not_keep_the_consent_waiting() {
    let mut responses = vec![nothing_held()];
    responses.extend(approved("github"));
    let (server, _directory, credential) = prepared(responses);
    let opener = Opener::lingering();
    let child = create_command(
        &server,
        &credential,
        &opener,
        Place::Desktop,
        &["github", "--json"],
    )
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();

    let (exited, exit) = mpsc::channel();
    let waiter = thread::spawn(move || {
        let output = child.wait_with_output();
        exited.send(()).ok();
        output
    });
    let returned = exit.recv_timeout(Duration::from_secs(20)).is_ok();
    opener.end();
    assert!(returned, "useful waited for the opener to return");
    let output = waiter.join().unwrap().unwrap();

    assert_no_secret_output(&output, &[SENTINEL, TOKEN]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let events = events(&output);
    assert_eq!(events.len(), 2);
    assert_eq!(events[1]["event"], "consent_result");
    assert_eq!(events[1]["outcome"], "completed");
    assert_eq!(events[1]["grant"]["provider"], "github");
    assert_eq!(opener.opened(1), [format!("1 {}", consent_url("github"))]);
    let poll = poll_line();
    assert_eq!(
        request_lines(&server.finish()),
        [LIST_OAUTH, START_CONSENT, poll.as_str()]
    );
}

#[test]
fn create_prints_the_url_without_opening_it_where_this_machine_has_no_browser() {
    // Only Linux needs a display for a browser.
    for (place, opened) in [
        (Place::Remote, false),
        (Place::Headless, !cfg!(target_os = "linux")),
    ] {
        let (server, _directory, credential) = prepared(vec![nothing_held(), started()]);
        let opener = Opener::new(0);
        let output = run_create(
            &server,
            &credential,
            &opener,
            place,
            &["linear", "--no-wait"],
        );

        assert_eq!(output.status.code(), Some(0), "{place:?}");
        assert!(stdout(&output).contains(CONSENT_URL), "{place:?}");
        assert_eq!(
            opener.opened(usize::from(opened)).len(),
            usize::from(opened),
            "{place:?}"
        );
        assert_eq!(request_lines(&server.finish()), [LIST_OAUTH, START_CONSENT]);
    }
}

#[test]
fn create_without_waiting_returns_after_the_start_event() {
    let (server, _directory, credential) = prepared(vec![nothing_held(), started()]);
    let opener = Opener::new(0);
    let output = run_create(
        &server,
        &credential,
        &opener,
        Place::Desktop,
        &["linear", "--no-wait", "--json"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let events = events(&output);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event"], "consent_required");
    assert_eq!(events[0]["outcome"], "pending");
    assert_eq!(events[0]["authorizationUrl"], CONSENT_URL);
    assert_eq!(opener.opened(1), [format!("1 {CONSENT_URL}")]);
    assert_eq!(request_lines(&server.finish()), [LIST_OAUTH, START_CONSENT]);
}

#[test]
fn create_replays_its_key_once_after_a_lost_start_response() {
    let (server, _directory, credential) = prepared(vec![nothing_held(), Vec::new(), started()]);
    let opener = Opener::new(0);
    let output = run_create(
        &server,
        &credential,
        &opener,
        Place::Remote,
        &["linear", "--no-wait", "--json"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let events = events(&output);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["outcome"], "pending");
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [LIST_OAUTH, START_CONSENT, START_CONSENT]
    );
    let key = header_value(&requests[1], "idempotency-key");
    assert!(!key.is_empty());
    assert_eq!(key, header_value(&requests[2], "idempotency-key"));
}

#[test]
fn create_waits_out_a_rate_limited_poll_and_then_reports_the_grant() {
    let limited = http_response_with_headers(
        "429 Too Many Requests",
        Some("application/problem+json"),
        &[("Retry-After", "1")],
        &serde_json::to_vec(&serde_json::json!({
            "type": "https://api.usefulmachinery.com/problems/rate-limit-exceeded",
            "title": "Slow down",
            "status": 429
        }))
        .unwrap(),
    );
    let (server, _directory, credential) = prepared(vec![
        nothing_held(),
        started(),
        limited,
        polled(session("completed")),
    ]);
    let opener = Opener::new(0);
    let output = run_create(
        &server,
        &credential,
        &opener,
        Place::Remote,
        &["linear", "--json"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let events = events(&output);
    assert_eq!(events.last().unwrap()["outcome"], "completed");
    let poll = poll_line();
    assert_eq!(
        request_lines(&server.finish()),
        [LIST_OAUTH, START_CONSENT, poll.as_str(), poll.as_str()]
    );
}

#[test]
fn create_reports_a_consent_that_did_not_complete_with_its_reason() {
    for (status, reason) in [("failed", "consent_denied"), ("expired", "session_expired")] {
        let mut settled = session(status);
        settled["reasonCode"] = reason.into();
        let responses = vec![nothing_held(), started(), polled(settled)];
        let (server, _directory, credential) = prepared([responses.clone(), responses].concat());
        let opener = Opener::new(0);
        let json = run_create(
            &server,
            &credential,
            &opener,
            Place::Remote,
            &["linear", "--json"],
        );
        let human = run_create(&server, &credential, &opener, Place::Remote, &["linear"]);

        assert_eq!(json.status.code(), Some(1), "{status}");
        let events = events(&json);
        assert_eq!(events.len(), 2, "{status}");
        assert_eq!(events[1]["event"], "consent_result");
        assert_eq!(events[1]["outcome"], status);
        assert_eq!(events[1]["reason"], reason);
        assert!(events[1]["grant"].is_null());
        assert_eq!(human.status.code(), Some(1), "{status}");
        assert!(
            stdout(&human).contains(&format!("reason: {reason}")),
            "{status}"
        );
        assert_eq!(server.finish().len(), 6, "{status}");
    }
}

#[test]
fn create_reports_a_refused_consent_without_polling() {
    for (slug, status, code, outcome, exit) in [
        (
            "provider-unavailable",
            "503 Service Unavailable",
            503,
            "provider_unavailable",
            4,
        ),
        (
            "grant-session-conflict",
            "409 Conflict",
            409,
            "consent_in_progress",
            1,
        ),
    ] {
        let (server, _directory, credential) =
            prepared(vec![nothing_held(), problem(status, code, slug)]);
        let opener = Opener::new(0);
        let output = run_create(
            &server,
            &credential,
            &opener,
            Place::Desktop,
            &["linear", "--json"],
        );

        assert_eq!(output.status.code(), Some(exit), "{outcome}");
        let events = events(&output);
        assert_eq!(events.len(), 1, "{outcome}");
        assert_eq!(events[0]["outcome"], outcome);
        assert!(opener.opened(0).is_empty(), "{outcome}");
        assert_eq!(
            request_lines(&server.finish()),
            [LIST_OAUTH, START_CONSENT],
            "{outcome}"
        );
    }
}

#[test]
fn a_github_consent_that_did_not_complete_names_acting_as_the_github_app() {
    let settled = |provider: &str, status: &str, reason: &str| {
        let mut session = consent_of(provider, status);
        session["reasonCode"] = reason.into();
        session
    };
    let started_for =
        |provider: &str| json_http_response("201 Created", consent_of(provider, "pending"));
    let mismatch = || polled(settled("github", "failed", "subject_mismatch"));
    let (server, _directory, credential) = prepared(vec![
        nothing_held(),
        started_for("github"),
        mismatch(),
        nothing_held(),
        started_for("github"),
        mismatch(),
    ]);
    let opener = Opener::new(0);
    let json = run_create(
        &server,
        &credential,
        &opener,
        Place::Remote,
        &["github", "--json"],
    );
    let human = run_create(&server, &credential, &opener, Place::Remote, &["github"]);
    server.finish();

    assert_eq!(json.status.code(), Some(1), "{}", stderr(&json));
    let lines = events(&json);
    assert_eq!(lines[1]["event"], "consent_result");
    assert_eq!(lines[1]["outcome"], "failed");
    assert_eq!(lines[1]["reason"], "subject_mismatch");
    assert_eq!(lines[1]["alternative"], ACTING_AS_THE_APP);
    assert!(lines[1]["grant"].is_null());
    // Consenting again as a GitHub user linked to another account cannot succeed, so the report
    // names acting as the GitHub App, and not the consent, as the step.
    assert_eq!(human.status.code(), Some(1));
    let text = stdout(&human);
    assert!(
        text.lines().any(|line| line.trim() == ACTING_AS_THE_APP),
        "{text}"
    );
    assert!(
        text.contains("linked to another Useful Machinery account"),
        "{text}"
    );
    assert!(!text.contains("connect github"), "{text}");

    // Any other GitHub consent that does not complete, and a refusal for want of GitHub, name it
    // too; another provider's names none.
    let (server, _directory, credential) = prepared(vec![
        nothing_held(),
        started_for("github"),
        polled(settled("github", "expired", "session_expired")),
        nothing_held(),
        problem("503 Service Unavailable", 503, "provider-unavailable"),
        nothing_held(),
        started_for("gitlab.com"),
        polled(settled("gitlab.com", "failed", "subject_mismatch")),
    ]);
    let expired = run_create(
        &server,
        &credential,
        &opener,
        Place::Remote,
        &["github", "--json"],
    );
    let unavailable = run_create(
        &server,
        &credential,
        &opener,
        Place::Remote,
        &["github", "--json"],
    );
    let gitlab = run_create(
        &server,
        &credential,
        &opener,
        Place::Remote,
        &["gitlab.com", "--json"],
    );
    server.finish();
    let result = |output: &Output| events(output).pop().unwrap();
    assert_eq!(expired.status.code(), Some(1), "{}", stderr(&expired));
    assert_eq!(result(&expired)["outcome"], "expired");
    assert_eq!(result(&expired)["alternative"], ACTING_AS_THE_APP);
    assert_eq!(
        unavailable.status.code(),
        Some(4),
        "{}",
        stderr(&unavailable)
    );
    assert_eq!(result(&unavailable)["outcome"], "provider_unavailable");
    assert_eq!(result(&unavailable)["alternative"], ACTING_AS_THE_APP);
    assert_eq!(gitlab.status.code(), Some(1), "{}", stderr(&gitlab));
    assert_eq!(result(&gitlab)["reason"], "subject_mismatch");
    assert!(result(&gitlab).get("alternative").is_none());
}

#[test]
fn a_consent_that_did_not_complete_names_the_command_that_started_it() {
    let mut denied = session("failed");
    denied["reasonCode"] = "consent_denied".into();
    let (server, _directory, credential) =
        prepared(vec![nothing_held(), started(), polled(denied.clone())]);
    let opener = Opener::new(0);
    let created = run_create(&server, &credential, &opener, Place::Remote, &["linear"]);

    assert_eq!(created.status.code(), Some(1), "{}", stderr(&created));
    let text = stdout(&created);
    assert!(
        text.contains("useful account integration connect linear"),
        "{text}"
    );
    server.finish();

    let (server, _directory, credential) = prepared(vec![
        one(&oauth_grant(OAUTH_GRANT_ID, "linear", "active")),
        started(),
        polled(denied),
    ]);
    let reconnected = run_reconnect_consent(&server, &credential, &["reconnect", OAUTH_GRANT_ID]);

    assert_eq!(
        reconnected.status.code(),
        Some(1),
        "{}",
        stderr(&reconnected)
    );
    let text = stdout(&reconnected);
    assert!(text.contains(&reconnect_line(OAUTH_GRANT_ID)), "{text}");
    assert!(!text.contains("grant create"), "{text}");
    server.finish();
}

/// The command line that signs in to the grant `id` again, as a refusal names it.
fn reconnect_line(id: &str) -> String {
    format!("useful account integration reconnect {id}")
}

#[test]
fn create_never_replaces_a_held_grant_and_names_the_reconnect_of_each() {
    for state in ["active", "reconnect_required"] {
        let held = page(
            &[
                oauth_grant(REVOKED_OAUTH_GRANT_ID, "github", "active"),
                oauth_grant(OAUTH_GRANT_ID, "linear", state),
            ],
            None,
        );
        let (server, _directory, credential) = prepared(vec![held.clone(), held]);
        let opener = Opener::new(0);
        for args in [&["linear"][..], &["linear", "--no-wait", "--json"]] {
            let refused = run_create(&server, &credential, &opener, Place::Remote, args);

            assert_eq!(refused.status.code(), Some(2), "{state}: {args:?}");
            let text = stderr(&refused);
            assert!(
                text.contains(&reconnect_line(OAUTH_GRANT_ID)),
                "{state}: {text}"
            );
            assert!(!text.contains(REVOKED_OAUTH_GRANT_ID), "{state}: {text}");
            assert!(refused.stdout.is_empty(), "{state}");
        }
        assert!(opener.opened(0).is_empty(), "{state}");
        assert_eq!(
            request_lines(&server.finish()),
            [LIST_OAUTH, LIST_OAUTH],
            "{state}"
        );
    }
}

#[test]
fn create_does_not_hold_a_revoked_grant_or_one_of_another_provider_against_a_consent() {
    let (server, _directory, credential) = prepared(vec![
        page(
            &[
                oauth_grant(OAUTH_GRANT_ID, "github", "active"),
                oauth_grant(REVOKED_OAUTH_GRANT_ID, "linear", "revoked"),
            ],
            None,
        ),
        started(),
    ]);
    let opener = Opener::new(0);
    let output = run_create(
        &server,
        &credential,
        &opener,
        Place::Remote,
        &["linear", "--no-wait"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(request_lines(&server.finish()), [LIST_OAUTH, START_CONSENT]);
}

/// The five providers `useful account integration connect` has a built-in name for.
const BUILT_IN: [&str; 5] = ["github", "gitlab.com", "linear", "claude_code", "codex"];

/// The answer of a deployment that serves the five and `example`, an OAuth provider titled
/// `title` when one is given.
fn serving_example(title: Option<&str>) -> Vec<u8> {
    serving_titled(
        &[
            "github",
            "gitlab.com",
            "linear",
            "example",
            "claude_code",
            "codex",
        ],
        &title
            .map(|title| ("example", title))
            .into_iter()
            .collect::<Vec<_>>(),
    )
}

/// The line that says where to approve a consent at `url`: the one before the URL's.
fn approval_line(text: &str, url: &str) -> String {
    let lines: Vec<_> = text.lines().collect();
    let at = lines
        .iter()
        .position(|line| line.trim() == url)
        .unwrap_or_else(|| panic!("no consent URL in {text}"));
    lines[at - 1].to_owned()
}

#[test]
fn create_connects_any_oauth_provider_the_deployment_serves_titled_as_it_serves_it() {
    for (title, json) in [
        (Some("Example Cloud"), false),
        (Some("Example Cloud"), true),
        (None, false),
    ] {
        let mut responses = vec![serving_example(title), nothing_held()];
        responses.extend(approved("example"));
        let (server, _directory, credential) = prepared(responses);
        let opener = Opener::new(0);
        let mut args = vec!["example"];
        if json {
            args.push("--json");
        }
        let output = run_create(&server, &credential, &opener, Place::Desktop, &args);

        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let url = consent_url("example");
        assert_eq!(opener.opened(1), [format!("1 {url}")]);
        if json {
            let events = events(&output);
            assert_eq!(events.len(), 2);
            assert_eq!(events[0]["event"], "consent_required");
            assert_eq!(events[0]["provider"], "example");
            assert_eq!(events[1]["outcome"], "completed");
            assert_eq!(events[1]["grant"]["id"], OAUTH_GRANT_ID);
            assert_eq!(events[1]["grant"]["provider"], "example");
        } else {
            let text = stdout(&output);
            let approval = approval_line(&text, &url);
            match title {
                Some(title) => assert!(approval.contains(title), "{approval}"),
                None => assert!(
                    approval.contains(" example ") && !approval.contains("Example Cloud"),
                    "{approval}"
                ),
            }
            assert!(text.contains(&format!("grant: {OAUTH_GRANT_ID}")), "{text}");
        }
        let requests = server.finish();
        assert_member_requests(&requests);
        let poll = poll_line();
        assert_eq!(
            request_lines(&requests),
            [READ_SERVED, LIST_OAUTH, START_CONSENT, poll.as_str()]
        );
        assert_eq!(
            request_body(&requests[2]),
            serde_json::json!({"provider": "example"})
        );
    }
}

#[test]
fn a_provider_the_deployment_does_not_serve_as_oauth_is_refused_naming_those_that_can_be_given() {
    let mut with_example = BUILT_IN.to_vec();
    with_example.push("example");
    let serving_aider = json_http_response(
        "200 OK",
        serde_json::json!({"items": [
            {"provider": "github", "kind": "oauth"},
            {"provider": "aider", "kind": "native"},
        ]}),
    );
    for (provider, answer, named) in [
        (
            "bitbucket",
            serving_example(Some("Example Cloud")),
            with_example.as_slice(),
        ),
        ("bitbucket", predating_served(), BUILT_IN.as_slice()),
        ("aider", serving_aider, BUILT_IN.as_slice()),
    ] {
        let (server, _directory, credential) = prepared(vec![answer.clone(), answer]);
        let opener = Opener::new(0);
        for args in [vec![provider], vec![provider, "--json"]] {
            let output = run_create(&server, &credential, &opener, Place::Desktop, &args);

            assert_eq!(output.status.code(), Some(2), "{args:?}");
            assert!(output.stdout.is_empty(), "{args:?}");
            let diagnostic = stderr(&output);
            for name in named {
                assert!(diagnostic.contains(name), "{args:?}: {diagnostic}");
            }
        }
        assert_eq!(
            request_lines(&server.finish()),
            [READ_SERVED, READ_SERVED],
            "{provider}"
        );
    }

    // A name that is no provider id, or an option an OAuth provider does not take, is refused
    // before anything is sent.
    let (server, _directory, credential) = prepared(vec![]);
    let opener = Opener::new(0);
    let too_long = "a".repeat(64);
    for args in [
        vec!["Example"],
        vec!["exa_mple"],
        vec![too_long.as_str()],
        vec!["example", "--organization", "acme"],
    ] {
        let output = run_create(&server, &credential, &opener, Place::Desktop, &args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    assert!(server.finish().is_empty());
}

#[test]
fn a_held_grant_of_a_served_provider_is_refused_by_create_and_consented_to_by_reconnect() {
    let held = page(&[oauth_grant(EXAMPLE_GRANT_ID, "example", "active")], None);
    let (server, _directory, credential) = prepared(vec![
        serving_example(None),
        held.clone(),
        held,
        serving_example(Some("Example Cloud")),
        json_http_response("201 Created", consent_of("example", "pending")),
    ]);
    let opener = Opener::new(0);
    let refused = run_create(&server, &credential, &opener, Place::Remote, &["example"]);
    let reconnected = run_reconnect_consent(
        &server,
        &credential,
        &["reconnect", "example", "--no-wait", "--json"],
    );

    assert_eq!(refused.status.code(), Some(2));
    assert!(refused.stdout.is_empty());
    let text = stderr(&refused);
    assert!(text.contains(&reconnect_line(EXAMPLE_GRANT_ID)), "{text}");
    assert_eq!(
        reconnected.status.code(),
        Some(0),
        "{}",
        stderr(&reconnected)
    );
    let events = events(&reconnected);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["sessionId"], SESSION_ID);
    assert_eq!(events[0]["provider"], "example");
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [
            READ_SERVED,
            LIST_OAUTH,
            LIST_EVERY_KIND,
            READ_SERVED,
            START_CONSENT
        ]
    );
    assert_eq!(start_body(&requests[4]), "example");
}

/// Runs `command` with a pseudo-terminal as its standard input and standard error, waits for
/// its `[y/N]` question, answers it with `answer`, and returns what the terminal showed up to
/// the question and the command's output.
pub(super) fn answered(command: Command, answer: &str) -> (String, Output) {
    const QUESTION: &str = "[y/N]";
    let (shown, output) = on_terminal(command, &[(QUESTION, answer)]);
    let asked = shown
        .find(QUESTION)
        .map_or(shown.len(), |at| at + QUESTION.len());
    (shown[..asked].to_owned(), output)
}

/// Where `needle` first appears in `haystack`.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Runs `command` with a pseudo-terminal of a real size as its standard input and standard
/// error and its standard output piped. At each step it waits until the terminal shows the
/// step's text, after what the step before waited for, then types the step's keys. Returns all
/// the terminal showed until the command ended, and the command's output.
pub(super) fn on_terminal(mut command: Command, steps: &[(&str, &str)]) -> (String, Output) {
    let size = rustix::termios::Winsize {
        ws_row: 40,
        ws_col: 160,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pty = open_test_pty(Some(&size)).unwrap();
    command
        .stdin(Stdio::from(pty.slave.try_clone().unwrap()))
        .stderr(Stdio::from(pty.slave))
        .stdout(Stdio::piped());
    let child = command.spawn().unwrap();
    // The command holds this process's copies of the terminal's peer; once they close,
    // reading the terminal ends when the child exits.
    drop(command);
    let (sender, chunks) = mpsc::channel();
    let mut reader = fs::File::from(rustix::io::dup(&pty.master).unwrap());
    let reading = thread::spawn(move || {
        let mut buffer = [0; 512];
        while let Ok(count) = reader.read(&mut buffer) {
            if count == 0 || sender.send(buffer[..count].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut shown = Vec::new();
    let mut seen = 0;
    let mut writer = fs::File::from(pty.master);
    for (text, keys) in steps {
        let at = loop {
            if let Some(at) = find_bytes(&shown[seen..], text.as_bytes()) {
                break seen + at;
            }
            let chunk = chunks.recv().unwrap_or_else(|_| {
                panic!(
                    "the terminal never showed {text:?}:\n{}",
                    String::from_utf8_lossy(&shown)
                )
            });
            shown.extend(chunk);
        };
        seen = at + text.len();
        writer.write_all(keys.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    drop(writer);
    shown.extend(chunks.iter().flatten());
    reading.join().unwrap();
    (String::from_utf8_lossy(&shown).into_owned(), output)
}

#[test]
fn create_on_a_terminal_asks_nothing_and_refuses_a_held_grant() {
    let (server, _directory, credential) = prepared(vec![page(
        &[oauth_grant(OAUTH_GRANT_ID, "linear", "active")],
        None,
    )]);
    let opener = Opener::new(0);
    let command = create_command(
        &server,
        &credential,
        &opener,
        Place::Remote,
        &["linear", "--no-wait"],
    );
    let (transcript, output) = on_terminal(command, &[]);

    assert_eq!(output.status.code(), Some(2), "{transcript}");
    assert!(!transcript.contains("[y/N]"), "{transcript}");
    assert!(
        transcript.contains(&reconnect_line(OAUTH_GRANT_ID)),
        "{transcript}"
    );
    assert!(output.stdout.is_empty());
    assert_eq!(request_lines(&server.finish()), [LIST_OAUTH]);
}

// `useful account integration reconnect INTEGRATION` of an OAuth grant: the provider's consent, which the
// account the member consents as decides.

/// Runs `useful account integration` with `args` where this machine has no browser and standard input
/// is no terminal.
fn run_reconnect_consent(server: &ScriptedServer, credential: &Path, args: &[&str]) -> Output {
    let opener = Opener::new(0);
    let output = opener_command(
        server,
        credential,
        &opener,
        Place::Remote,
        &[&["account", "integration"][..], args].concat(),
    )
    .stdin(Stdio::null())
    .output()
    .unwrap();
    assert_no_secret_output(&output, &[SENTINEL, TOKEN]);
    assert!(opener.opened(0).is_empty());
    output
}

/// The answers to a consent of `provider` that settles with the grant `made`.
fn approved_as(provider: &str, made: &str) -> [Vec<u8>; 2] {
    let mut completed = consent_of(provider, "completed");
    completed["resultGrant"]["id"] = made.into();
    [
        json_http_response("201 Created", consent_of(provider, "pending")),
        polled(completed),
    ]
}

#[test]
fn reconnect_consents_again_and_exits_1_when_the_consent_made_another_grant() {
    let held = || one(&oauth_grant(OAUTH_GRANT_ID, "github", "active"));
    for json in [true, false] {
        // The consent was given as the account the grant is linked to, so it renewed that grant.
        let mut responses = vec![held()];
        responses.extend(approved_as("github", OAUTH_GRANT_ID));
        // It was given as another account, which got a grant of its own.
        responses.push(held());
        responses.extend(approved_as("github", EXAMPLE_GRANT_ID));
        let (server, _directory, credential) = prepared(responses);
        let mut args = vec!["reconnect", OAUTH_GRANT_ID];
        if json {
            args.push("--json");
        }
        let reconnected = run_reconnect_consent(&server, &credential, &args);
        let other = run_reconnect_consent(&server, &credential, &args);

        assert_eq!(
            reconnected.status.code(),
            Some(0),
            "{}",
            stderr(&reconnected)
        );
        assert_eq!(other.status.code(), Some(1), "{}", stderr(&other));
        if json {
            let reconnected = events(&reconnected);
            assert_eq!(reconnected.len(), 2, "{reconnected:?}");
            assert_eq!(reconnected[1]["outcome"], "completed");
            assert_eq!(reconnected[1]["grant"]["id"], OAUTH_GRANT_ID);
            let other = events(&other);
            assert_eq!(other.len(), 3, "{other:?}");
            assert_eq!(other[1]["grant"]["id"], EXAMPLE_GRANT_ID);
            assert_eq!(other[2]["event"], "reconnect_result");
            assert_eq!(other[2]["outcome"], "not_reconnected");
            assert_eq!(other[2]["provider"], "github");
            assert_eq!(other[2]["grantId"], OAUTH_GRANT_ID);
        } else {
            assert!(
                stdout(&reconnected).contains(&format!("grant: {OAUTH_GRANT_ID}")),
                "{}",
                stdout(&reconnected)
            );
            assert!(stderr(&reconnected).is_empty(), "{}", stderr(&reconnected));
            let text = stderr(&other);
            for fact in [OAUTH_GRANT_ID, EXAMPLE_GRANT_ID] {
                assert!(text.contains(fact), "{fact}: {text}");
            }
            // The remedy's command is a line of its own, indented as every remedy's is.
            let again = format!("  useful account integration reconnect {OAUTH_GRANT_ID}");
            assert!(text.lines().any(|line| line == again), "{text}");
        }
        let requests = server.finish();
        assert_member_requests(&requests);
        let poll = poll_line();
        assert_eq!(
            request_lines(&requests),
            [
                READ_OAUTH,
                START_CONSENT,
                poll.as_str(),
                READ_OAUTH,
                START_CONSENT,
                poll.as_str()
            ]
        );
        assert_eq!(start_body(&requests[1]), "github");
    }
}

#[test]
fn reconnect_refuses_a_revoked_grant_and_an_option_its_provider_does_not_take() {
    let directory = tempfile::tempdir().unwrap();
    let login = private_file(directory.path(), "auth.json", CODEX_MATERIAL.as_bytes());
    let login = login.to_str().unwrap();
    let (server, _directory, credential) = prepared(vec![
        one(&oauth_grant(OAUTH_GRANT_ID, "github", "revoked")),
        one(&oauth_grant(OAUTH_GRANT_ID, "github", "active")),
        one(&oauth_grant(OAUTH_GRANT_ID, "github", "active")),
        one(&native_grant(NATIVE_GRANT_ID, "active")),
    ]);
    let revoked = run_grant(
        &server,
        &credential,
        &["reconnect", OAUTH_GRANT_ID, "--json"],
    );
    assert_eq!(revoked.status.code(), Some(1), "{}", stderr(&revoked));
    assert_eq!(events(&revoked)[0]["outcome"], "grant_not_found");
    for args in [
        &["reconnect", OAUTH_GRANT_ID, "--from-file", login][..],
        &["reconnect", OAUTH_GRANT_ID, "--device"],
        &["reconnect", NATIVE_GRANT_ID, "--no-wait"],
    ] {
        let output = run_grant(&server, &credential, args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    assert_eq!(
        request_lines(&server.finish()),
        [READ_OAUTH, READ_OAUTH, READ_OAUTH, READ_NATIVE]
    );
}

// `useful account integration connect codex`: Codex's own sign-in in a private home, or an auth.json the
// member names, imported for one organization. The fake `codex` and the member's home with its
// ambient Codex login are at the end of this file.

const GLOBEX_ORGANIZATION_ID: &str = "org_01k0z6r1w8f4jy2m7q9v3x5abe";
const THIRD_NATIVE_GRANT_ID: &str = "agl_01k0z6r1w8f4jy2m7q9v3x5abe";
pub(super) const LIST_MEMBERSHIPS: &str = "GET /api/v1/me/memberships?limit=200 HTTP/1.1";
const LIST_NATIVE: &str = "GET /api/v1/me/grants?kind=native&limit=200&vocabulary=2 HTTP/1.1";
const IMPORT_GRANT: &str = "POST /api/v1/me/grant-imports HTTP/1.1";
pub(super) const READ_ACME: &str = "GET /api/v1/organizations/acme HTTP/1.1";

fn replace_line(grant_id: &str) -> String {
    format!("POST /api/v1/me/grants/{grant_id}/generations HTTP/1.1")
}

// The member's memberships: an active one in each organization named, and an ended one, which
// names no slug and makes no organization the member's.
pub(super) fn memberships(organizations: &[(&str, &str)]) -> Vec<u8> {
    let mut items: Vec<_> = organizations
        .iter()
        .enumerate()
        .map(|(index, (id, slug))| {
            serde_json::json!({
                "id": format!("mem_01k0z6r1w8f4jy2m7q9v3x5ab{index}"),
                "organizationId": id,
                "organizationState": "active",
                "organizationDisplayName": slug,
                "organizationSlug": slug,
                "role": "member",
                "state": "active",
                "createdAt": "2026-11-01T08:00:00Z",
                "updatedAt": "2026-11-01T08:00:00Z"
            })
        })
        .collect();
    items.push(serde_json::json!({
        "id": "mem_01k0z6r1w8f4jy2m7q9v3x5abz",
        "organizationId": OTHER_ORGANIZATION_ID,
        "organizationState": "active",
        "role": "member",
        "state": "ended",
        "createdAt": "2026-10-01T08:00:00Z",
        "updatedAt": "2026-10-02T08:00:00Z",
        "terminalAt": "2026-10-02T08:00:00Z"
    }));
    json_http_response("200 OK", serde_json::json!({"items": items}))
}

fn only_acme() -> Vec<u8> {
    memberships(&[(ORGANIZATION_ID, "acme")])
}

fn acme() -> Vec<u8> {
    json_http_response(
        "200 OK",
        serde_json::json!({
            "id": ORGANIZATION_ID,
            "state": "active",
            "displayName": "Acme",
            "slug": "acme",
            "createdAt": "2026-11-01T09:00:00Z",
            "updatedAt": "2026-11-01T09:00:00Z"
        }),
    )
}

fn codex_grant(id: &str, organization_id: &str, state: &str) -> serde_json::Value {
    let mut grant = native_grant(id, state);
    grant["organizationId"] = organization_id.into();
    grant
}

// A coding agent's provider and the material the import of its login sends.
type Login = (&'static str, &'static str);
const CODEX: Login = ("codex", CODEX_MATERIAL);
const CLAUDE_CODE: Login = ("claude_code", CLAUDE_TOKEN);

// The grant of the provider an import or a replacement answers with, echoing the request's key.
fn stored(login: Login, status: &str, generation: i64) -> Vec<u8> {
    stored_in(ORGANIZATION_ID, login, status, generation)
}

fn stored_in(
    organization_id: &str,
    (provider, _): Login,
    status: &str,
    generation: i64,
) -> Vec<u8> {
    let mut grant = codex_grant(NATIVE_GRANT_ID, organization_id, "active");
    grant["provider"] = provider.into();
    grant["generation"] = generation.into();
    http_response_with_headers(
        status,
        Some("application/json"),
        &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
        &serde_json::to_vec(&with_material(grant)).unwrap(),
    )
}

/// Runs `useful account integration connect` from the member's `home` with the fake `program`, when
/// there is one, and the opener on `PATH`, and standard input `input`. Whatever the outcome, the
/// member's home is as it was, the temporary sign-in directory is gone and no login reached the
/// output.
fn run_native(
    server: &ScriptedServer,
    credential: &Path,
    home: &AmbientHome,
    program: Option<&FakeProgram>,
    place: Place,
    args: &[&str],
    input: Input<'_>,
) -> Output {
    let fake = Fake {
        program,
        environment: &[],
    };
    run_fake(server, credential, home, fake, place, args, input)
}

/// The leading words of `useful account integration reconnect`.
const GRANT_RECONNECT: &[&str] = &["account", "integration", "reconnect"];

/// Runs `useful account integration reconnect` with `args` as [`run_native`] runs `create`, where this
/// machine has a browser.
fn run_reconnect(
    server: &ScriptedServer,
    credential: &Path,
    home: &AmbientHome,
    program: Option<&FakeProgram>,
    args: &[&str],
    input: Input<'_>,
) -> Output {
    let opener = Opener::new(0);
    let programs: Vec<_> = program.into_iter().collect();
    let fakes = Fakes {
        opener: &opener,
        programs: &programs,
        environment: &[],
        checkout: None,
    };
    let arguments = [GRANT_RECONNECT, args].concat();
    let output = run_programs(
        server,
        credential,
        home,
        fakes,
        Place::Desktop,
        &arguments,
        input,
    );
    assert!(opener.opened(0).is_empty());
    output
}

/// The fake sign-in program on `PATH`, when there is one, and the variables that choose how it
/// behaves.
#[derive(Clone, Copy)]
struct Fake<'a> {
    program: Option<&'a FakeProgram>,
    environment: &'a [(&'a str, &'a str)],
}

/// [`run_native`] with the variables of `fake` set besides.
fn run_fake(
    server: &ScriptedServer,
    credential: &Path,
    home: &AmbientHome,
    Fake {
        program,
        environment,
    }: Fake<'_>,
    place: Place,
    args: &[&str],
    input: Input<'_>,
) -> Output {
    let opener = Opener::new(0);
    let programs: Vec<_> = program.into_iter().collect();
    let fakes = Fakes {
        opener: &opener,
        programs: &programs,
        environment,
        checkout: None,
    };
    let arguments = [GRANT_CREATE, args].concat();
    let output = run_programs(server, credential, home, fakes, place, &arguments, input);
    assert!(opener.opened(0).is_empty());
    output
}

/// The opener and the fake sign-in programs on `PATH`, and the variables that choose how they
/// behave, and the checkout the command runs in, if any.
#[derive(Clone, Copy)]
struct Fakes<'a> {
    opener: &'a Opener,
    programs: &'a [&'a FakeProgram],
    environment: &'a [(&'a str, &'a str)],
    checkout: Option<Checkout<'a>>,
}

/// The directory `useful` runs in and the directory of the fake `git` it finds there.
#[derive(Clone, Copy)]
struct Checkout<'a> {
    directory: &'a Path,
    git: &'a Path,
}

/// What `useful` reads on its standard input.
#[derive(Clone, Copy)]
enum Input<'a> {
    /// Nothing: standard input is null, so it is no terminal.
    Null,
    /// These bytes on a pipe, as `--token-file -` and `--from-file -` read them.
    Piped(&'a [u8]),
    /// A terminal these bytes are typed on, which Claude Code's sign-in needs.
    Typed(&'a [u8]),
}

/// Runs `command` with a new terminal as its standard input and its outputs piped, types
/// `typed` on the terminal and waits for it; the terminal stays open until the command ends.
fn typed_output(command: &mut Command, typed: &[u8]) -> Output {
    let pty = open_test_pty(None).unwrap();
    let child = command
        .stdin(Stdio::from(pty.slave))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut terminal = fs::File::from(pty.master);
    terminal.write_all(typed).unwrap();
    let output = child.wait_with_output().unwrap();
    drop(terminal);
    output
}

/// Runs `useful` with `arguments`, its command's leading words first, from the member's `home` with
/// `fakes` and standard input `input`, and checks what [`run_native`] promises of its outcome.
fn run_programs(
    server: &ScriptedServer,
    credential: &Path,
    home: &AmbientHome,
    Fakes {
        opener,
        programs,
        environment,
        checkout,
    }: Fakes<'_>,
    place: Place,
    arguments: &[&str],
    input: Input<'_>,
) -> Output {
    let path = std::env::join_paths(
        std::iter::once(opener.directory.path())
            .chain(programs.iter().map(|program| program.bin.as_path()))
            .chain(checkout.map(|checkout| checkout.git)),
    )
    .unwrap();
    let mut command = opener_command(server, credential, opener, place, arguments);
    command
        .env("PATH", path)
        .envs(home.variables())
        .envs(environment.iter().copied());
    if let Some(checkout) = checkout {
        command.current_dir(checkout.directory);
    }
    let output = match input {
        Input::Null => command.stdin(Stdio::null()).output().unwrap(),
        Input::Typed(typed) => typed_output(&mut command, typed),
        Input::Piped(input) => {
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(input).unwrap();
            child.wait_with_output().unwrap()
        }
    };
    assert_no_secret_output(
        &output,
        &[
            SENTINEL,
            TOKEN,
            CODEX_SENTINEL,
            AMBIENT_MARKER,
            &encoded(CODEX_MATERIAL.as_bytes()),
            CLAUDE_TOKEN_SENTINEL,
            &encoded(CLAUDE_TOKEN.as_bytes()),
        ],
    );
    home.assert_untouched_and_clean();
    output
}

fn assert_imported(request: &str, organization: &str, (provider, material): Login) {
    assert!(
        request.starts_with(&format!("{IMPORT_GRANT}\r\n")),
        "{request}"
    );
    assert!(!header_value(request, "idempotency-key").is_empty());
    assert_eq!(
        request_body(request),
        serde_json::json!({
            "organization": organization,
            "provider": provider,
            "recordSchemaVersion": 1,
            "material": encoded(material.as_bytes())
        })
    );
}

#[test]
fn create_codex_signs_in_in_a_private_codex_home_and_imports_the_login_it_wrote() {
    for args in [&["codex"][..], &["codex", "--login", "--json"]] {
        let (server, _directory, credential) = prepared(vec![
            serving_every(),
            only_acme(),
            nothing_held(),
            stored(CODEX, "201 Created", 1),
        ]);
        let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
        let home = AmbientHome::new();
        let output = run_native(
            &server,
            &credential,
            &home,
            Some(&codex),
            Place::Desktop,
            args,
            Input::Null,
        );

        assert_eq!(
            output.status.code(),
            Some(0),
            "{args:?}: {}",
            stderr(&output)
        );
        if args.contains(&"--json") {
            let events = events(&output);
            assert_eq!(events.len(), 1, "{events:?}");
            assert_eq!(events[0]["event"], "import_result");
            assert_eq!(events[0]["outcome"], "imported");
            assert_eq!(events[0]["grant"]["id"], NATIVE_GRANT_ID);
            assert_eq!(events[0]["grant"]["generation"], 1);
        } else {
            let text = stdout(&output);
            for fact in [NATIVE_GRANT_ID, "provider: codex", "generation: 1", "acme"] {
                assert!(text.contains(fact), "{fact}: {text}");
            }
        }
        // The sign-in's own output reaches the member on standard error.
        assert!(stderr(&output).contains("codex-sign-in-prompt"));
        assert_eq!(codex.recorded("arguments").unwrap(), "login\n", "{args:?}");
        let codex_home = std::path::PathBuf::from(codex.recorded("home").unwrap());
        assert_ne!(codex_home, home.ambient_codex());
        assert!(codex_home.starts_with(home.temporary.path()));
        assert!(!codex_home.exists());
        assert!(
            codex.recorded("mode").unwrap().starts_with("drwx------"),
            "{:?}",
            codex.recorded("mode")
        );
        let requests = server.finish();
        assert_eq!(
            request_lines(&requests),
            [READ_SERVED, LIST_MEMBERSHIPS, LIST_NATIVE, IMPORT_GRANT],
            "{args:?}"
        );
        assert_imported(&requests[3], ORGANIZATION_ID, CODEX);
    }
}

#[test]
fn create_codex_signs_in_by_device_code_with_device_or_where_this_machine_has_no_browser() {
    for (place, args) in [
        (Place::Remote, &["codex"][..]),
        (Place::Desktop, &["codex", "--device"]),
    ] {
        let (server, _directory, credential) = prepared(vec![
            serving_every(),
            only_acme(),
            nothing_held(),
            stored(CODEX, "201 Created", 1),
        ]);
        let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
        let home = AmbientHome::new();
        let output = run_native(
            &server,
            &credential,
            &home,
            Some(&codex),
            place,
            args,
            Input::Null,
        );

        assert_eq!(
            output.status.code(),
            Some(0),
            "{place:?}: {}",
            stderr(&output)
        );
        assert_eq!(
            codex.recorded("arguments").unwrap(),
            "login --device-auth\n",
            "{place:?}"
        );
        assert!(stderr(&output).contains(DEVICE_CODE_PROMPT), "{place:?}");
        let requests = server.finish();
        assert_eq!(
            request_lines(&requests),
            [READ_SERVED, LIST_MEMBERSHIPS, LIST_NATIVE, IMPORT_GRANT]
        );
        assert_imported(&requests[3], ORGANIZATION_ID, CODEX);
    }
}

#[test]
fn create_codex_imports_a_named_file_or_standard_input_without_running_codex() {
    let directory = tempfile::tempdir().unwrap();
    let file = private_file(directory.path(), "auth.json", CODEX_MATERIAL.as_bytes());
    for (path, input) in [
        (file.to_str().unwrap(), Input::Null),
        ("-", Input::Piped(CODEX_MATERIAL.as_bytes())),
    ] {
        let (server, _directory, credential) = prepared(vec![
            only_acme(),
            nothing_held(),
            stored(CODEX, "201 Created", 1),
        ]);
        let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
        let home = AmbientHome::new();
        let output = run_native(
            &server,
            &credential,
            &home,
            Some(&codex),
            Place::Desktop,
            &["codex", "--from-file", path],
            input,
        );

        assert_eq!(output.status.code(), Some(0), "{path}: {}", stderr(&output));
        assert!(stdout(&output).contains(NATIVE_GRANT_ID));
        assert_eq!(codex.recorded("arguments"), None, "{path}");
        let requests = server.finish();
        assert_eq!(
            request_lines(&requests),
            [LIST_MEMBERSHIPS, LIST_NATIVE, IMPORT_GRANT]
        );
        assert_imported(&requests[2], ORGANIZATION_ID, CODEX);
    }
}

#[test]
fn reconnect_stores_a_named_codex_file_or_standard_input_as_the_grants_next_generation() {
    let directory = tempfile::tempdir().unwrap();
    let file = private_file(directory.path(), "auth.json", CODEX_MATERIAL.as_bytes());
    for (path, input) in [
        (file.to_str().unwrap(), Input::Null),
        ("-", Input::Piped(CODEX_MATERIAL.as_bytes())),
    ] {
        let (server, _directory, credential) = prepared(vec![
            one(&codex_grant(NATIVE_GRANT_ID, ORGANIZATION_ID, "active")),
            stored(CODEX, "200 OK", 3),
        ]);
        let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
        let home = AmbientHome::new();
        let output = run_reconnect(
            &server,
            &credential,
            &home,
            Some(&codex),
            &[NATIVE_GRANT_ID, "--from-file", path],
            input,
        );

        assert_eq!(output.status.code(), Some(0), "{path}: {}", stderr(&output));
        let text = stdout(&output);
        for fact in [&format!("grant: {NATIVE_GRANT_ID}"), "generation: 3"] {
            assert!(text.contains(fact), "{path}: {fact}: {text}");
        }
        assert_eq!(codex.recorded("arguments"), None, "{path}");
        let requests = server.finish();
        let replace = replace_line(NATIVE_GRANT_ID);
        assert_eq!(request_lines(&requests), [READ_NATIVE, replace.as_str()]);
        assert_eq!(
            request_body(&requests[1]),
            serde_json::json!({
                "recordSchemaVersion": 1,
                "material": encoded(CODEX_MATERIAL.as_bytes())
            })
        );
    }
}

// `create codex` refuses a held grant, so the remedy of a sign-in `reconnect` started names
// `reconnect` with the file, not the `create` that would send the member back here.
#[test]
fn reconnect_whose_codex_sign_in_fails_names_reconnect_with_a_file_as_the_remedy() {
    let (server, _directory, credential) = prepared(vec![
        one(&codex_grant(NATIVE_GRANT_ID, ORGANIZATION_ID, "active")),
        serving_every(),
    ]);
    let home = AmbientHome::new();
    // No `codex` is on `PATH`.
    let output = run_reconnect(
        &server,
        &credential,
        &home,
        None,
        &[NATIVE_GRANT_ID],
        Input::Null,
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stderr(&output);
    let again =
        format!("  useful account integration reconnect {NATIVE_GRANT_ID} --from-file PATH");
    assert!(text.lines().any(|line| line == again), "{text}");
    assert!(!text.contains("grant create"), "{text}");
    assert_eq!(request_lines(&server.finish()), [READ_NATIVE, READ_SERVED]);
}

#[test]
fn reconnect_checks_a_named_file_before_any_request_and_its_provider_before_any_sign_in() {
    let directory = tempfile::tempdir().unwrap();
    let login = private_file(directory.path(), "auth.json", CODEX_MATERIAL.as_bytes());
    let login = login.to_str().unwrap();
    let token = private_file(directory.path(), "token", CLAUDE_TOKEN.as_bytes());
    let token = token.to_str().unwrap();
    let malformed = private_file(directory.path(), "malformed", b"not a token\n");
    let malformed = malformed.to_str().unwrap();
    let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
    let claude = FakeProgram::claude(SetupToken::Prints);
    let home = AmbientHome::new();

    // A malformed file is refused before anything is sent.
    let (server, _directory, credential) = prepared(vec![]);
    let output = run_reconnect(
        &server,
        &credential,
        &home,
        Some(&claude),
        &["claude_code", "--token-file", malformed],
        Input::Null,
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(server.finish().is_empty());

    // A Codex login is no Claude Code grant's, nor a Claude Code token a Codex grant's.
    let (server, _directory, credential) = prepared(vec![
        page(&[claude_grant(NATIVE_GRANT_ID, "active")], None),
        one(&codex_grant(NATIVE_GRANT_ID, ORGANIZATION_ID, "active")),
    ]);
    for (program, args) in [
        (&claude, &["claude_code", "--from-file", login][..]),
        (&codex, &[NATIVE_GRANT_ID, "--token-file", token]),
    ] {
        let output = run_reconnect(
            &server,
            &credential,
            &home,
            Some(program),
            args,
            Input::Null,
        );
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(output.stdout.is_empty(), "{args:?}");
        assert_eq!(program.recorded("arguments"), None, "{args:?}");
    }
    assert_eq!(
        request_lines(&server.finish()),
        [LIST_EVERY_KIND, READ_NATIVE]
    );
}

#[test]
fn create_reports_an_import_cloud_refuses_with_exit_1_and_its_remedy() {
    let directory = tempfile::tempdir().unwrap();
    let file = private_file(directory.path(), "auth.json", CODEX_MATERIAL.as_bytes());
    let file = file.to_str().unwrap();
    for (refusal, outcome, remedy) in [
        (
            problem("400 Bad Request", 400, "grant-material-invalid"),
            "material_invalid",
            None,
        ),
        (
            problem("409 Conflict", 409, "quantity-limit-reached"),
            "limit_reached",
            Some("useful account integration disconnect"),
        ),
    ] {
        for json in [false, true] {
            let (server, _directory, credential) =
                prepared(vec![only_acme(), nothing_held(), refusal.clone()]);
            let home = AmbientHome::new();
            let mut args = vec!["codex", "--from-file", file];
            if json {
                args.push("--json");
            }
            let output = run_native(
                &server,
                &credential,
                &home,
                None,
                Place::Desktop,
                &args,
                Input::Null,
            );

            assert_eq!(
                output.status.code(),
                Some(1),
                "{outcome}: {}",
                stderr(&output)
            );
            if json {
                let events = events(&output);
                assert_eq!(events.last().unwrap()["outcome"], outcome, "{events:?}");
            } else {
                let text = stderr(&output);
                let commands: Vec<_> = text
                    .lines()
                    .map(str::trim_start)
                    .filter(|line| line.starts_with("useful "))
                    .collect();
                match remedy {
                    Some(command) => assert!(
                        commands.iter().any(|line| line.starts_with(command)),
                        "{outcome}: {text}"
                    ),
                    None => assert!(commands.is_empty(), "{outcome}: {text}"),
                }
            }
            assert_eq!(
                request_lines(&server.finish()),
                [LIST_MEMBERSHIPS, LIST_NATIVE, IMPORT_GRANT],
                "{outcome}"
            );
        }
    }
}

#[test]
fn create_refuses_an_unsafe_file_or_an_option_the_provider_does_not_take_before_any_request() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str, contents: &[u8], mode: u32| {
        let file = private_file(directory.path(), name, contents);
        fs::set_permissions(&file, Permissions::from_mode(mode)).unwrap();
        file.to_str().unwrap().to_owned()
    };
    let readable = path("readable.json", CODEX_MATERIAL.as_bytes(), 0o644);
    let read_only = path("read-only.json", CODEX_MATERIAL.as_bytes(), 0o400);
    let oversized = path("oversized.json", &vec![b' '; 32 * 1024 + 1], 0o600);
    let array = path(
        "array.json",
        format!("[\"{CODEX_SENTINEL}\"]").as_bytes(),
        0o600,
    );
    let string = path(
        "string.json",
        format!("\"{CODEX_SENTINEL}\"").as_bytes(),
        0o600,
    );
    let login = path("auth.json", CODEX_MATERIAL.as_bytes(), 0o600);
    let alias = directory.path().join("alias.json");
    symlink(&login, &alias).unwrap();
    let alias = alias.to_str().unwrap().to_owned();
    // A token that is not one line of 1 to 4096 printable characters without spaces.
    let spaced = path("spaced", format!("{CLAUDE_TOKEN} more\n").as_bytes(), 0o600);
    let empty = path("empty", b"", 0o600);
    let wide = path("wide", "x".repeat(4097).as_bytes(), 0o600);
    let cases: [&[&str]; 19] = [
        &["codex", "--from-file", &readable],
        &["codex", "--from-file", &read_only],
        &["codex", "--from-file", &alias],
        &["codex", "--from-file", &oversized],
        &["codex", "--from-file", &array],
        &["codex", "--from-file", &string],
        &["claude_code", "--token-file", &spaced],
        &["claude_code", "--token-file", &empty],
        &["claude_code", "--token-file", &wide],
        &["codex", "--token-file", &login],
        &["codex", "--login", "--device"],
        &["codex", "--from-file", &login, "--login"],
        &["github", "--org", "acme"],
        &["linear", "--from-file", &login],
        &["gitlab.com", "--device"],
        &["github", "--token-file", &login],
        &["claude_code", "--from-file", &login],
        &["claude_code", "--login"],
        &["claude_code", "--device"],
    ];
    for args in cases {
        let (server, _directory, credential) = prepared(vec![]);
        let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
        let home = AmbientHome::new();
        let output = run_native(
            &server,
            &credential,
            &home,
            Some(&codex),
            Place::Desktop,
            args,
            Input::Null,
        );

        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(output.stdout.is_empty(), "{args:?}");
        assert_eq!(codex.recorded("arguments"), None, "{args:?}");
        assert!(server.finish().is_empty(), "{args:?}");
    }
}

#[test]
fn a_codex_sign_in_that_fails_stores_nothing_and_reports_provider_login_failed() {
    let cases = [
        ("exits nonzero", Some(SignIn::Exits(3))),
        ("writes no login", Some(SignIn::WritesNothing)),
        ("is interrupted", Some(SignIn::Interrupts)),
        ("cannot be started", Some(SignIn::CannotStart)),
        ("is not on PATH", None),
    ];
    for (case, sign_in) in cases {
        let codex = sign_in.map(FakeProgram::codex);
        for json in [false, true] {
            let (server, _directory, credential) =
                prepared(vec![serving_every(), only_acme(), nothing_held()]);
            let home = AmbientHome::new();
            let args: &[&str] = if json {
                &["codex", "--json"]
            } else {
                &["codex"]
            };
            let output = run_native(
                &server,
                &credential,
                &home,
                codex.as_ref(),
                Place::Desktop,
                args,
                Input::Null,
            );

            assert_eq!(output.status.code(), Some(1), "{case}: {}", stderr(&output));
            if json {
                let events = events(&output);
                assert_eq!(events.len(), 1, "{case}: {events:?}");
                assert_eq!(events[0]["outcome"], "provider_login_failed", "{case}");
            } else {
                assert!(output.stdout.is_empty(), "{case}");
                assert!(stderr(&output).contains("--from-file"), "{case}");
            }
            assert_eq!(
                request_lines(&server.finish()),
                [READ_SERVED, LIST_MEMBERSHIPS, LIST_NATIVE],
                "{case}"
            );
        }
    }
}

#[test]
fn create_codex_imports_for_the_named_organization_and_needs_one_when_the_member_has_several() {
    let (server, _directory, credential) = prepared(vec![
        serving_every(),
        memberships(&[
            (ORGANIZATION_ID, "acme"),
            (GLOBEX_ORGANIZATION_ID, "globex"),
        ]),
    ]);
    let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
    let home = AmbientHome::new();
    let refused = run_native(
        &server,
        &credential,
        &home,
        Some(&codex),
        Place::Desktop,
        &["codex"],
        Input::Null,
    );

    assert_eq!(refused.status.code(), Some(2), "{}", stderr(&refused));
    let text = stderr(&refused);
    for fact in ["--org ORG", "acme", "globex"] {
        assert!(text.contains(fact), "{fact}: {text}");
    }
    assert_eq!(codex.recorded("arguments"), None);
    assert_eq!(
        request_lines(&server.finish()),
        [READ_SERVED, LIST_MEMBERSHIPS]
    );

    let (server, _directory, credential) = prepared(vec![
        serving_every(),
        acme(),
        nothing_held(),
        stored(CODEX, "201 Created", 1),
    ]);
    let named = run_native(
        &server,
        &credential,
        &home,
        Some(&codex),
        Place::Desktop,
        &["codex", "--org", "acme"],
        Input::Null,
    );

    assert_eq!(named.status.code(), Some(0), "{}", stderr(&named));
    assert_eq!(codex.recorded("arguments").unwrap(), "login\n");
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [READ_SERVED, READ_ACME, LIST_NATIVE, IMPORT_GRANT]
    );
    assert_imported(&requests[3], ORGANIZATION_ID, CODEX);
}

#[test]
fn create_codex_imports_for_the_organization_in_effect() {
    let directory = tempfile::tempdir().unwrap();
    let login = private_file(directory.path(), "auth.json", CODEX_MATERIAL.as_bytes());
    let login = login.to_str().unwrap();
    let home = AmbientHome::new();

    // `--org` or else `USEFUL_ORG` names Acme by its slug, so no membership is read.
    for (option, environment) in [
        (&["--org", "acme"][..], &[][..]),
        (&[][..], &[("USEFUL_ORG", "acme")][..]),
    ] {
        let (server, _directory, credential) = prepared(vec![
            acme(),
            nothing_held(),
            stored(CODEX, "201 Created", 1),
        ]);
        let fake = Fake {
            program: None,
            environment,
        };
        let args = [&["codex", "--from-file", login][..], option].concat();
        let output = run_fake(
            &server,
            &credential,
            &home,
            fake,
            Place::Desktop,
            &args,
            Input::Null,
        );

        assert_eq!(
            output.status.code(),
            Some(0),
            "{environment:?}: {}",
            stderr(&output)
        );
        let requests = server.finish();
        assert_eq!(
            request_lines(&requests),
            [READ_ACME, LIST_NATIVE, IMPORT_GRANT],
            "{environment:?}"
        );
        assert_imported(&requests[2], ORGANIZATION_ID, CODEX);
    }

    // Neither: the member of two organizations works in a checkout whose remote names the
    // repository of Globex's project, which names the organization.
    let git = fake_git(
        "if [ \"$1 $2\" = 'remote -v' ]; then\n\
         printf 'origin\\tgit@github.com:globex/rockets.git (fetch)\\n'\n\
         else exit 1; fi",
    );
    let checkout = tempfile::tempdir().unwrap();
    let (server, _directory, credential) = prepared(vec![
        memberships(&[
            (ORGANIZATION_ID, "acme"),
            (GLOBEX_ORGANIZATION_ID, "globex"),
        ]),
        super::organization::projects_of(
            ORGANIZATION_ID,
            "prj_01k0z6r1w8f4jy2m7q9v3x5abc",
            "acme/widgets",
        ),
        super::organization::projects_of(
            GLOBEX_ORGANIZATION_ID,
            "prj_01k0z6r1w8f4jy2m7q9v3x5abd",
            "globex/rockets",
        ),
        nothing_held(),
        stored_in(GLOBEX_ORGANIZATION_ID, CODEX, "201 Created", 1),
    ]);
    let opener = Opener::new(0);
    let fakes = Fakes {
        opener: &opener,
        programs: &[],
        environment: &[],
        checkout: Some(Checkout {
            directory: checkout.path(),
            git: git.path(),
        }),
    };
    let output = run_programs(
        &server,
        &credential,
        &home,
        fakes,
        Place::Desktop,
        &[GRANT_CREATE, &["codex", "--from-file", login]].concat(),
        Input::Null,
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [
            LIST_MEMBERSHIPS,
            &format!("GET /api/v1/organizations/{ORGANIZATION_ID}/projects HTTP/1.1"),
            &format!("GET /api/v1/organizations/{GLOBEX_ORGANIZATION_ID}/projects HTTP/1.1"),
            LIST_NATIVE,
            IMPORT_GRANT
        ]
    );
    assert_imported(&requests[4], GLOBEX_ORGANIZATION_ID, CODEX);
}

#[test]
fn create_of_an_oauth_provider_reads_no_organization_the_variable_names() {
    // The variable is not an option: it is neither refused nor read, valid or not.
    for variable in ["acme", "Not an organization"] {
        let (server, _directory, credential) =
            prepared([vec![nothing_held()], approved("github").to_vec()].concat());
        let opener = Opener::new(0);
        let output = create_command(
            &server,
            &credential,
            &opener,
            Place::Remote,
            &["github", "--json"],
        )
        .env("USEFUL_ORG", variable)
        .stdin(Stdio::null())
        .output()
        .unwrap();

        assert_eq!(
            output.status.code(),
            Some(0),
            "{variable}: {}",
            stderr(&output)
        );
        let poll = poll_line();
        assert_eq!(
            request_lines(&server.finish()),
            [LIST_OAUTH, START_CONSENT, poll.as_str()],
            "{variable}"
        );
    }
}

#[test]
fn create_codex_refuses_the_grant_held_in_that_organization_and_reconnect_renews_it() {
    let held = || {
        page(
            &[
                codex_grant(NATIVE_GRANT_ID, ORGANIZATION_ID, "active"),
                codex_grant(OTHER_NATIVE_GRANT_ID, GLOBEX_ORGANIZATION_ID, "active"),
                codex_grant(THIRD_NATIVE_GRANT_ID, ORGANIZATION_ID, "revoked"),
            ],
            None,
        )
    };
    let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
    let home = AmbientHome::new();

    let (server, _directory, credential) = prepared(vec![serving_every(), only_acme(), held()]);
    let refused = run_native(
        &server,
        &credential,
        &home,
        Some(&codex),
        Place::Desktop,
        &["codex"],
        Input::Null,
    );
    assert_eq!(refused.status.code(), Some(2), "{}", stderr(&refused));
    let text = stderr(&refused);
    assert!(text.contains(&reconnect_line(NATIVE_GRANT_ID)), "{text}");
    assert!(!text.contains(OTHER_NATIVE_GRANT_ID), "{text}");
    assert_eq!(codex.recorded("arguments"), None);
    assert_eq!(
        request_lines(&server.finish()),
        [READ_SERVED, LIST_MEMBERSHIPS, LIST_NATIVE]
    );

    // On a terminal too, with no question.
    let (server, _directory, credential) = prepared(vec![serving_every(), only_acme(), held()]);
    let opener = Opener::new(0);
    let mut command = create_command(&server, &credential, &opener, Place::Desktop, &["codex"]);
    command
        .env(
            "PATH",
            std::env::join_paths([opener.directory.path(), codex.bin.as_path()]).unwrap(),
        )
        .envs(home.variables());
    let (transcript, output) = on_terminal(command, &[]);
    assert_eq!(output.status.code(), Some(2), "{transcript}");
    assert!(!transcript.contains("[y/N]"), "{transcript}");
    assert!(
        transcript.contains(&reconnect_line(NATIVE_GRANT_ID)),
        "{transcript}"
    );
    assert_eq!(codex.recorded("arguments"), None);
    assert_eq!(
        request_lines(&server.finish()),
        [READ_SERVED, LIST_MEMBERSHIPS, LIST_NATIVE]
    );

    // `reconnect` runs the sign-in and stores it as the grant's next generation; a lost answer
    // is replayed once under the same key.
    let (server, _directory, credential) = prepared(vec![
        one(&codex_grant(NATIVE_GRANT_ID, ORGANIZATION_ID, "active")),
        serving_every(),
        Vec::new(),
        stored(CODEX, "200 OK", 3),
    ]);
    let replaced = run_reconnect(
        &server,
        &credential,
        &home,
        Some(&codex),
        &[NATIVE_GRANT_ID, "--json"],
        Input::Null,
    );
    assert_eq!(replaced.status.code(), Some(0), "{}", stderr(&replaced));
    let events = events(&replaced);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["outcome"], "replaced");
    assert_eq!(events[0]["grant"]["id"], NATIVE_GRANT_ID);
    assert_eq!(events[0]["grant"]["generation"], 3);
    assert_eq!(codex.recorded("arguments").unwrap(), "login\n");
    let requests = server.finish();
    let replace = replace_line(NATIVE_GRANT_ID);
    assert_eq!(
        request_lines(&requests),
        [READ_NATIVE, READ_SERVED, &replace, &replace]
    );
    for request in &requests[2..] {
        assert_eq!(
            request_body(request),
            serde_json::json!({
                "recordSchemaVersion": 1,
                "material": encoded(CODEX_MATERIAL.as_bytes())
            })
        );
    }
    assert_eq!(
        header_value(&requests[2], "idempotency-key"),
        header_value(&requests[3], "idempotency-key")
    );
}

#[test]
fn create_codex_names_the_several_grants_held_in_that_organization_and_starts_no_sign_in() {
    let (server, _directory, credential) = prepared(vec![
        serving_every(),
        only_acme(),
        page(
            &[
                codex_grant(NATIVE_GRANT_ID, ORGANIZATION_ID, "active"),
                codex_grant(OTHER_NATIVE_GRANT_ID, ORGANIZATION_ID, "active"),
            ],
            None,
        ),
    ]);
    let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
    let home = AmbientHome::new();
    let output = run_native(
        &server,
        &credential,
        &home,
        Some(&codex),
        Place::Desktop,
        &["codex"],
        Input::Null,
    );

    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    let text = stderr(&output);
    for id in [NATIVE_GRANT_ID, OTHER_NATIVE_GRANT_ID] {
        assert!(text.contains(&reconnect_line(id)), "{id}: {text}");
    }
    assert_eq!(codex.recorded("arguments"), None);
    assert_eq!(
        request_lines(&server.finish()),
        [READ_SERVED, LIST_MEMBERSHIPS, LIST_NATIVE]
    );
}

#[test]
fn create_codex_starts_no_sign_in_without_a_session() {
    let server = ScriptedServer::respond(vec![]);
    let directory = private_credential_directory();
    let credential = directory.path().join("credentials.json");
    let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
    let home = AmbientHome::new();
    let output = run_native(
        &server,
        &credential,
        &home,
        Some(&codex),
        Place::Desktop,
        &["codex", "--json"],
        Input::Null,
    );

    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert_eq!(events(&output)[0]["outcome"], "unauthenticated");
    assert_eq!(codex.recorded("arguments"), None);
    assert!(server.finish().is_empty());
}

// `useful account integration connect claude_code`: `claude setup-token` on a terminal `useful` owns, its
// prompts passed through and the token it prints taken out of what the member sees, or a token the
// member names, imported for one organization.

fn claude_grant(id: &str, state: &str) -> serde_json::Value {
    let mut grant = codex_grant(id, ORGANIZATION_ID, state);
    grant["provider"] = "claude_code".into();
    grant
}

#[test]
fn create_claude_code_runs_setup_token_on_a_terminal_and_imports_the_token_without_showing_it() {
    let paste = format!("{PASTE_CODE}\n");
    for (flow, place, input) in [
        ("browser", Place::Desktop, Input::Typed(b"")),
        ("paste", Place::Remote, Input::Typed(paste.as_bytes())),
    ] {
        let (server, _directory, credential) = prepared(vec![
            serving_every(),
            only_acme(),
            nothing_held(),
            stored(CLAUDE_CODE, "201 Created", 1),
        ]);
        let claude = FakeProgram::claude(SetupToken::Prints);
        let home = AmbientHome::new();
        let fake = Fake {
            program: Some(&claude),
            environment: &[(CLAUDE_FLOW, flow)],
        };
        let output = run_fake(
            &server,
            &credential,
            &home,
            fake,
            place,
            &["claude_code"],
            input,
        );

        assert_eq!(output.status.code(), Some(0), "{flow}: {}", stderr(&output));
        let text = stdout(&output);
        for fact in [
            NATIVE_GRANT_ID,
            "provider: claude_code",
            "generation: 1",
            "acme",
        ] {
            assert!(text.contains(fact), "{flow}: {fact}: {text}");
        }
        // The sign-in's prompts and what follows the token reach the member on standard
        // error, the token does not (run_native checks every output for it).
        let shown = stderr(&output);
        assert!(shown.contains(CLAUDE_SIGN_IN_URL), "{flow}: {shown}");
        assert!(shown.contains(AFTER_TOKEN), "{flow}: {shown}");
        assert_eq!(
            shown.contains(PASTE_PROMPT),
            flow == "paste",
            "{flow}: {shown}"
        );
        assert!(!shown.contains("sk-ant-"), "{flow}: {shown}");
        assert_eq!(claude.recorded("arguments").unwrap(), "setup-token\n");
        assert_eq!(claude.recorded("terminal").unwrap(), "yes\n", "{flow}");
        let config = std::path::PathBuf::from(claude.recorded("config").unwrap());
        assert_ne!(config, home.ambient_claude());
        assert!(config.starts_with(home.temporary.path()), "{config:?}");
        assert!(!config.exists());
        assert!(
            claude.recorded("mode").unwrap().starts_with("drwx------"),
            "{:?}",
            claude.recorded("mode")
        );
        let requests = server.finish();
        assert_eq!(
            request_lines(&requests),
            [READ_SERVED, LIST_MEMBERSHIPS, LIST_NATIVE, IMPORT_GRANT],
            "{flow}"
        );
        assert_imported(&requests[3], ORGANIZATION_ID, CLAUDE_CODE);
    }
}

#[test]
fn a_claude_setup_token_that_fails_stores_nothing_and_reports_provider_login_failed() {
    let cases = [
        ("exits nonzero", Some(SetupToken::Exits(3))),
        ("prints no token", Some(SetupToken::PrintsNothing)),
        ("is interrupted", Some(SetupToken::Interrupts)),
        ("is not on PATH", None),
    ];
    for (case, setup_token) in cases {
        let claude = setup_token.map(FakeProgram::claude);
        for json in [false, true] {
            let (server, _directory, credential) =
                prepared(vec![serving_every(), only_acme(), nothing_held()]);
            let home = AmbientHome::new();
            let args: &[&str] = if json {
                &["claude_code", "--json"]
            } else {
                &["claude_code"]
            };
            let output = run_native(
                &server,
                &credential,
                &home,
                claude.as_ref(),
                Place::Desktop,
                args,
                Input::Typed(b""),
            );

            assert_eq!(output.status.code(), Some(1), "{case}: {}", stderr(&output));
            if json {
                let events = events(&output);
                assert_eq!(events.len(), 1, "{case}: {events:?}");
                assert_eq!(events[0]["outcome"], "provider_login_failed", "{case}");
            } else {
                assert!(output.stdout.is_empty(), "{case}");
                assert!(stderr(&output).contains("--token-file"), "{case}");
            }
            assert_eq!(
                request_lines(&server.finish()),
                [READ_SERVED, LIST_MEMBERSHIPS, LIST_NATIVE],
                "{case}"
            );
        }
    }
}

#[test]
fn create_claude_code_without_a_terminal_starts_no_sign_in_and_names_the_token_file() {
    let claude = FakeProgram::claude(SetupToken::Prints);
    for json in [false, true] {
        let (server, _directory, credential) = prepared(vec![]);
        let home = AmbientHome::new();
        let args: &[&str] = if json {
            &["claude_code", "--json"]
        } else {
            &["claude_code"]
        };
        let output = run_native(
            &server,
            &credential,
            &home,
            Some(&claude),
            Place::Desktop,
            args,
            Input::Null,
        );

        assert_eq!(output.status.code(), Some(1), "{json}: {}", stderr(&output));
        if json {
            let events = events(&output);
            assert_eq!(events.len(), 1, "{events:?}");
            assert_eq!(events[0]["outcome"], "provider_login_failed");
        } else {
            assert!(output.stdout.is_empty());
            assert!(
                stderr(&output).contains("--token-file"),
                "{}",
                stderr(&output)
            );
        }
        assert!(server.finish().is_empty(), "{json}");
    }
    assert_eq!(claude.recorded("arguments"), None);
}

/// `useful account integration connect claude_code` with the fake `claude` on `PATH` in the browser flow,
/// standard input `input`, a terminal's secondary side, and its outputs piped, started but not
/// waited for.
fn spawn_claude_sign_in(
    server: &ScriptedServer,
    credential: &Path,
    home: &AmbientHome,
    claude: &Path,
    input: Stdio,
) -> std::process::Child {
    let opener = Opener::new(0);
    let path = std::env::join_paths([opener.directory.path(), claude]).unwrap();
    create_command(
        server,
        credential,
        &opener,
        Place::Desktop,
        &["claude_code"],
    )
    .env("PATH", path)
    .envs(home.variables())
    .env(CLAUDE_FLOW, "browser")
    .stdin(input)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap()
}

#[test]
fn input_written_after_the_claude_sign_in_ends_is_left_for_the_next_reader() {
    let mut server = ScriptedServer::respond_with_paused_last_response(vec![
        serving_every(),
        only_acme(),
        nothing_held(),
        stored(CLAUDE_CODE, "201 Created", 1),
    ]);
    let directory = private_credential_directory();
    let credential = directory.path().join("credentials.json");
    write_credential_fixture_for_deployment(
        &credential,
        &server.api_url,
        &server.issuer,
        TOKEN,
        "2999-01-01T00:00:00Z",
    );
    let claude = FakeProgram::claude(SetupToken::Prints);
    let home = AmbientHome::new();
    let pty = open_test_pty(None).unwrap();
    // The test keeps its own copy of the terminal's secondary side, so what `useful` leaves unread
    // stays readable.
    let kept = fs::File::from(pty.slave.try_clone().unwrap());
    let child = spawn_claude_sign_in(
        &server,
        &credential,
        &home,
        &claude.bin,
        Stdio::from(pty.slave),
    );

    // The import is requested once the sign-in has ended; its answer waits for the input.
    let requests: Vec<_> = (0..4).map(|_| server.next_request()).collect();
    let typed = b"typed-after-the-sign-in\n";
    let mut terminal = fs::File::from(pty.master);
    terminal.write_all(typed).unwrap();
    server.release_paused_response();
    let output = child.wait_with_output().unwrap();

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    // The sign-in restored the terminal's line mode, so the typed line waits there whole.
    let mut ready = [rustix::event::PollFd::new(
        &kept,
        rustix::event::PollFlags::IN,
    )];
    let wait = rustix::event::Timespec {
        tv_sec: 20,
        tv_nsec: 0,
    };
    assert_eq!(rustix::event::poll(&mut ready, Some(&wait)).unwrap(), 1);
    let mut left = vec![0; typed.len() + 1];
    let count = (&kept).read(&mut left).unwrap();
    assert_eq!(&left[..count], typed);
    drop(terminal);
    assert_eq!(
        request_lines(&requests),
        [READ_SERVED, LIST_MEMBERSHIPS, LIST_NATIVE, IMPORT_GRANT]
    );
    assert_imported(&requests[3], ORGANIZATION_ID, CLAUDE_CODE);
    assert!(server.finish().is_empty());
    assert_no_secret_output(&output, &[TOKEN, CLAUDE_TOKEN_SENTINEL]);
    home.assert_untouched_and_clean();
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "the bound on useful's return is far below the descendant's own life, so real time only separates returning from waiting for the descendant"
)]
fn a_descendant_of_the_claude_sign_in_holding_its_terminal_does_not_keep_useful_running() {
    use super::pi_installation::quote;
    let (server, _directory, credential) = prepared(vec![
        serving_every(),
        only_acme(),
        nothing_held(),
        stored(CLAUDE_CODE, "201 Created", 1),
    ]);
    // A `claude` that leaves a descendant holding its terminal, deaf to the hangup its end
    // sends, then prints the token and exits.
    let fake = tempfile::tempdir().unwrap();
    let bin = fake.path().join("bin");
    let descendant = fake.path().join("descendant");
    fs::create_dir(&bin).unwrap();
    fs::write(
        bin.join("claude"),
        format!(
            "#!/bin/sh\nPATH={tools}\nexport PATH\n\
             (trap '' HUP; exec sleep 120) &\n\
             echo \"$!\" > {descendant}\n\
             printf '%s\\n' {token}\n",
            tools = quote(&std::env::var("PATH").unwrap_or_default()),
            descendant = quote(descendant.to_str().unwrap()),
            token = quote(CLAUDE_TOKEN),
        ),
    )
    .unwrap();
    fs::set_permissions(bin.join("claude"), Permissions::from_mode(0o755)).unwrap();
    let home = AmbientHome::new();
    let pty = open_test_pty(None).unwrap();
    let child = spawn_claude_sign_in(&server, &credential, &home, &bin, Stdio::from(pty.slave));

    let (exited, exit) = mpsc::channel();
    let waiter = thread::spawn(move || {
        let output = child.wait_with_output();
        exited.send(()).ok();
        output
    });
    let returned = exit.recv_timeout(Duration::from_secs(20)).is_ok();
    let holder: i32 = fs::read_to_string(&descendant)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let _ = rustix::process::kill_process(
        rustix::process::Pid::from_raw(holder).unwrap(),
        rustix::process::Signal::KILL,
    );
    assert!(
        returned,
        "useful waited for the descendant holding the terminal"
    );
    let output = waiter.join().unwrap().unwrap();

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stdout(&output).contains(NATIVE_GRANT_ID));
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [READ_SERVED, LIST_MEMBERSHIPS, LIST_NATIVE, IMPORT_GRANT]
    );
    assert_imported(&requests[3], ORGANIZATION_ID, CLAUDE_CODE);
    assert_no_secret_output(&output, &[TOKEN, CLAUDE_TOKEN_SENTINEL]);
    home.assert_untouched_and_clean();
}

#[test]
fn the_claude_sign_in_leads_its_own_session_with_the_terminal_useful_owns_as_its_controlling_terminal()
 {
    use super::pi_installation::quote;
    const ON_ITS_TERMINAL: &str = "claude-wrote-to-its-controlling-terminal";
    let (server, _directory, credential) = prepared(vec![
        serving_every(),
        only_acme(),
        nothing_held(),
        stored(CLAUDE_CODE, "201 Created", 1),
    ]);
    // A `claude` that goes on only when it leads its own session and has a controlling
    // terminal, which it writes to; what it writes there reaches the member only when that
    // terminal is the one `useful` relays.
    let fake = tempfile::tempdir().unwrap();
    let bin = fake.path().join("bin");
    fs::create_dir(&bin).unwrap();
    fs::write(
        bin.join("claude"),
        format!(
            "#!/bin/sh\nPATH={tools}\nexport PATH\n\
             python3 -c 'import os, sys; leader = int(sys.argv[1]); \
             sys.exit(os.getsid(leader) != leader)' \"$$\" || exit 7\n\
             {{ : < /dev/tty; }} 2>/dev/null || exit 8\n\
             echo {ON_ITS_TERMINAL} > /dev/tty\n\
             printf '%s\\n' {token}\n",
            tools = quote(&std::env::var("PATH").unwrap_or_default()),
            token = quote(CLAUDE_TOKEN),
        ),
    )
    .unwrap();
    fs::set_permissions(bin.join("claude"), Permissions::from_mode(0o755)).unwrap();
    let home = AmbientHome::new();
    let pty = open_test_pty(None).unwrap();
    let output = spawn_claude_sign_in(&server, &credential, &home, &bin, Stdio::from(pty.slave))
        .wait_with_output()
        .unwrap();

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stderr(&output).contains(ON_ITS_TERMINAL));
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [READ_SERVED, LIST_MEMBERSHIPS, LIST_NATIVE, IMPORT_GRANT]
    );
    assert_imported(&requests[3], ORGANIZATION_ID, CLAUDE_CODE);
    assert_no_secret_output(&output, &[TOKEN, CLAUDE_TOKEN_SENTINEL]);
    home.assert_untouched_and_clean();
}

#[test]
fn create_claude_code_imports_a_named_token_file_or_standard_input_without_running_claude() {
    let directory = tempfile::tempdir().unwrap();
    let line = format!("{CLAUDE_TOKEN}\n");
    let file = private_file(directory.path(), "token", line.as_bytes());
    // Neither source needs a terminal.
    for (path, input) in [
        (file.to_str().unwrap(), Input::Null),
        ("-", Input::Piped(line.as_bytes())),
    ] {
        let (server, _directory, credential) = prepared(vec![
            only_acme(),
            nothing_held(),
            stored(CLAUDE_CODE, "201 Created", 1),
        ]);
        let claude = FakeProgram::claude(SetupToken::Prints);
        let home = AmbientHome::new();
        let output = run_native(
            &server,
            &credential,
            &home,
            Some(&claude),
            Place::Desktop,
            &["claude_code", "--token-file", path],
            input,
        );

        assert_eq!(output.status.code(), Some(0), "{path}: {}", stderr(&output));
        assert!(stdout(&output).contains(NATIVE_GRANT_ID));
        assert_eq!(claude.recorded("arguments"), None, "{path}");
        let requests = server.finish();
        assert_eq!(
            request_lines(&requests),
            [LIST_MEMBERSHIPS, LIST_NATIVE, IMPORT_GRANT]
        );
        assert_imported(&requests[2], ORGANIZATION_ID, CLAUDE_CODE);
    }
}

#[test]
fn reconnect_claude_code_runs_setup_token_and_stores_the_token_as_the_grants_next_generation() {
    let (server, _directory, credential) = prepared(vec![
        page(&[claude_grant(NATIVE_GRANT_ID, "active")], None),
        serving_every(),
        stored(CLAUDE_CODE, "200 OK", 3),
    ]);
    let claude = FakeProgram::claude(SetupToken::Prints);
    let home = AmbientHome::new();
    let output = run_reconnect(
        &server,
        &credential,
        &home,
        Some(&claude),
        &["claude_code", "--json"],
        Input::Typed(b""),
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let events = events(&output);
    assert_eq!(events[0]["outcome"], "replaced");
    assert_eq!(events[0]["grant"]["id"], NATIVE_GRANT_ID);
    assert_eq!(events[0]["grant"]["generation"], 3);
    assert_eq!(claude.recorded("arguments").unwrap(), "setup-token\n");
    let requests = server.finish();
    let replace = replace_line(NATIVE_GRANT_ID);
    assert_eq!(
        request_lines(&requests),
        [LIST_EVERY_KIND, READ_SERVED, &replace]
    );
    assert_eq!(
        request_body(&requests[2]),
        serde_json::json!({
            "recordSchemaVersion": 1,
            "material": encoded(CLAUDE_TOKEN.as_bytes())
        })
    );
}

#[test]
fn reconnect_claude_code_takes_a_token_file_and_without_one_needs_a_terminal() {
    let directory = tempfile::tempdir().unwrap();
    let token = private_file(
        directory.path(),
        "token",
        format!("{CLAUDE_TOKEN}\n").as_bytes(),
    );
    let token = token.to_str().unwrap();
    let held = || one(&claude_grant(NATIVE_GRANT_ID, "active"));
    let (server, _directory, credential) =
        prepared(vec![held(), stored(CLAUDE_CODE, "200 OK", 3), held()]);
    let claude = FakeProgram::claude(SetupToken::Prints);
    let home = AmbientHome::new();
    let stored = run_reconnect(
        &server,
        &credential,
        &home,
        Some(&claude),
        &[NATIVE_GRANT_ID, "--token-file", token],
        Input::Null,
    );
    let refused = run_reconnect(
        &server,
        &credential,
        &home,
        Some(&claude),
        &[NATIVE_GRANT_ID],
        Input::Null,
    );

    assert_eq!(stored.status.code(), Some(0), "{}", stderr(&stored));
    assert!(stdout(&stored).contains(&format!("grant: {NATIVE_GRANT_ID}")));
    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
    let text = stderr(&refused);
    assert!(
        text.contains(&format!(
            "{} --token-file -",
            reconnect_line(NATIVE_GRANT_ID)
        )),
        "{text}"
    );
    assert_eq!(claude.recorded("arguments"), None);
    let requests = server.finish();
    let replace = replace_line(NATIVE_GRANT_ID);
    assert_eq!(
        request_lines(&requests),
        [READ_NATIVE, replace.as_str(), READ_NATIVE]
    );
    assert_eq!(
        request_body(&requests[1]),
        serde_json::json!({
            "recordSchemaVersion": 1,
            "material": encoded(CLAUDE_TOKEN.as_bytes())
        })
    );
}

// `useful account integration connect` with no provider: every provider the member lacks, one after
// another.

pub(super) const LIST_EVERY_KIND: &str = LIST_FIRST_PAGE;

// The URL a consent of `provider` asks the member to approve.
fn consent_url(provider: &str) -> String {
    format!("https://{provider}.example.test/oauth/authorize?state=public-fixture-state")
}

// The consent of `provider` as the API presents it, carrying material the CLI must drop.
pub(super) fn consent_of(provider: &str, status: &str) -> serde_json::Value {
    let mut consent = session(status);
    consent["provider"] = provider.into();
    match status {
        "pending" => consent["authorizationUrl"] = consent_url(provider).into(),
        "completed" => consent["resultGrant"]["provider"] = provider.into(),
        _ => {}
    }
    consent
}

// The answers to a consent of `provider` that the member approves.
fn approved(provider: &str) -> [Vec<u8>; 2] {
    [
        json_http_response("201 Created", consent_of(provider, "pending")),
        polled(consent_of(provider, "completed")),
    ]
}

fn claude_grant_of(id: &str) -> serde_json::Value {
    claude_grant(id, "active")
}

// The member's grants: an active one of each OAuth provider in `oauth`, and an active Codex and
// Claude Code grant in Acme when `natives` is set.
pub(super) fn holding(oauth: &[&str], natives: bool) -> Vec<u8> {
    let mut grants: Vec<_> = oauth
        .iter()
        .map(|provider| oauth_grant(OAUTH_GRANT_ID, provider, "active"))
        .collect();
    if natives {
        grants.push(native_grant(NATIVE_GRANT_ID, "active"));
        grants.push(claude_grant_of(OTHER_NATIVE_GRANT_ID));
    }
    page(&grants, None)
}

/// Runs `useful account integration connect` with the fake opener, `codex` and `claude` on `PATH` and a
/// terminal as its standard input.
fn run_every(
    server: &ScriptedServer,
    credential: &Path,
    opener: &Opener,
    programs: &[&FakeProgram],
    args: &[&str],
) -> Output {
    run_in(server, credential, opener, programs, None, args)
}

/// [`run_every`] in `checkout`, when there is one, with its fake `git` on `PATH` besides.
fn run_in(
    server: &ScriptedServer,
    credential: &Path,
    opener: &Opener,
    programs: &[&FakeProgram],
    checkout: Option<Checkout<'_>>,
    args: &[&str],
) -> Output {
    run_command_in(
        server,
        credential,
        opener,
        programs,
        checkout,
        GRANT_CREATE,
        args,
    )
}

/// [`run_in`] for the command whose leading words are `command`, such as [`WORKFLOW_DOCTOR`].
fn run_command_in(
    server: &ScriptedServer,
    credential: &Path,
    opener: &Opener,
    programs: &[&FakeProgram],
    checkout: Option<Checkout<'_>>,
    command: &[&str],
    args: &[&str],
) -> Output {
    let home = AmbientHome::new();
    let fakes = Fakes {
        opener,
        programs,
        environment: &[(CLAUDE_FLOW, "browser")],
        checkout,
    };
    let arguments = [command, args].concat();
    run_programs(
        server,
        credential,
        &home,
        fakes,
        Place::Desktop,
        &arguments,
        Input::Typed(b""),
    )
}

fn start_body(request: &str) -> serde_json::Value {
    request_body(request)["provider"].clone()
}

// The provider and outcome of each entry of the summary that ends the JSON output.
fn summary(events: &[serde_json::Value]) -> (String, Vec<(String, String)>) {
    let last = events.last().unwrap();
    assert_eq!(last["event"], "summary", "{events:?}");
    let providers = last["providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["provider"].as_str().unwrap().to_owned(),
                entry["outcome"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    (last["outcome"].as_str().unwrap().to_owned(), providers)
}

fn outcomes(entries: &[(&str, &str)]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|(provider, outcome)| ((*provider).to_owned(), (*outcome).to_owned()))
        .collect()
}

#[test]
fn create_without_a_provider_all_or_workflow_exits_2_naming_the_three() {
    let (server, _directory, credential) = prepared(vec![]);
    let opener = Opener::new(0);
    for args in [&[][..], &["--json"]] {
        let output = run_every(&server, &credential, &opener, &[], args);

        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(output.stdout.is_empty(), "{args:?}");
        let text = stderr(&output);
        for named in ["PROVIDER", "--all", "--workflow"] {
            assert!(text.contains(named), "{args:?}: {named}: {text}");
        }
    }
    assert!(opener.opened(0).is_empty());
    assert!(server.finish().is_empty());
}

#[test]
fn create_all_signs_in_to_each_provider_the_member_lacks_in_order() {
    let args: &[&str] = &["--all"];
    let (server, _directory, credential) = prepared(
        [
            vec![holding(&["github"], false), serving_every(), only_acme()],
            approved("gitlab.com").to_vec(),
            approved("linear").to_vec(),
            vec![
                stored(CLAUDE_CODE, "201 Created", 1),
                stored(CODEX, "201 Created", 1),
            ],
        ]
        .concat(),
    );
    let opener = Opener::new(0);
    let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
    let claude = FakeProgram::claude(SetupToken::Prints);
    let output = run_every(&server, &credential, &opener, &[&codex, &claude], args);

    assert_eq!(
        output.status.code(),
        Some(0),
        "{args:?}: {}",
        stderr(&output)
    );
    assert_eq!(
        opener.opened(2),
        [
            format!("1 {}", consent_url("gitlab.com")),
            format!("1 {}", consent_url("linear"))
        ],
        "{args:?}"
    );
    assert_eq!(claude.recorded("arguments").unwrap(), "setup-token\n");
    assert_eq!(codex.recorded("arguments").unwrap(), "login\n");
    let text = stdout(&output);
    for fact in [
        "gitlab.com: created",
        "linear: created",
        "claude_code: created",
        "codex: created",
    ] {
        assert!(text.contains(fact), "{args:?}: {fact}: {text}");
    }
    assert!(!text.contains("github:"), "{args:?}: {text}");
    let requests = server.finish();
    assert_member_requests(&requests);
    let poll = poll_line();
    assert_eq!(
        request_lines(&requests),
        [
            LIST_EVERY_KIND,
            READ_SERVED,
            LIST_MEMBERSHIPS,
            START_CONSENT,
            poll.as_str(),
            START_CONSENT,
            poll.as_str(),
            IMPORT_GRANT,
            IMPORT_GRANT
        ],
        "{args:?}"
    );
    assert_eq!(start_body(&requests[3]), "gitlab.com");
    assert_eq!(start_body(&requests[5]), "linear");
    assert_imported(&requests[7], ORGANIZATION_ID, CLAUDE_CODE);
    assert_imported(&requests[8], ORGANIZATION_ID, CODEX);
}

#[test]
fn a_sign_in_that_fails_is_reported_and_the_ones_after_it_still_run() {
    let mut denied = consent_of("linear", "failed");
    denied["reasonCode"] = "consent_denied".into();
    let (server, _directory, credential) = prepared(
        [
            vec![holding(&["github"], false), serving_every(), only_acme()],
            approved("gitlab.com").to_vec(),
            vec![
                json_http_response("201 Created", consent_of("linear", "pending")),
                polled(denied),
                stored(CLAUDE_CODE, "201 Created", 1),
                stored(CODEX, "201 Created", 1),
            ],
        ]
        .concat(),
    );
    let opener = Opener::new(0);
    let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
    let claude = FakeProgram::claude(SetupToken::Prints);
    let output = run_every(
        &server,
        &credential,
        &opener,
        &[&codex, &claude],
        &["--all", "--json"],
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    // Each provider's own events, newline-delimited, then the summary.
    let events = events(&output);
    let names: Vec<_> = events
        .iter()
        .map(|event| event["event"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "consent_required",
            "consent_result",
            "consent_required",
            "consent_result",
            "import_result",
            "import_result",
            "summary"
        ]
    );
    assert_eq!(events[1]["grant"]["provider"], "gitlab.com");
    assert_eq!(events[3]["outcome"], "failed");
    assert_eq!(events[3]["reason"], "consent_denied");
    assert_eq!(events[4]["grant"]["provider"], "claude_code");
    assert_eq!(events[5]["grant"]["provider"], "codex");
    assert_eq!(
        summary(&events),
        (
            "failed".to_owned(),
            outcomes(&[
                ("gitlab.com", "created"),
                ("linear", "failed"),
                ("claude_code", "created"),
                ("codex", "created")
            ])
        )
    );
    let requests = server.finish();
    assert_eq!(request_lines(&requests)[7..], [IMPORT_GRANT, IMPORT_GRANT]);
}

#[test]
fn without_a_terminal_the_claude_sign_in_fails_and_the_codex_sign_in_after_it_still_runs() {
    let (server, _directory, credential) = prepared(vec![
        holding(&["github", "gitlab.com", "linear"], false),
        serving_every(),
        only_acme(),
        stored(CODEX, "201 Created", 1),
    ]);
    let opener = Opener::new(0);
    let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
    let claude = FakeProgram::claude(SetupToken::Prints);
    let home = AmbientHome::new();
    let fakes = Fakes {
        opener: &opener,
        programs: &[&codex, &claude],
        environment: &[],
        checkout: None,
    };
    let arguments = [GRANT_CREATE, &["--all", "--json"]].concat();
    let output = run_programs(
        &server,
        &credential,
        &home,
        fakes,
        Place::Desktop,
        &arguments,
        Input::Null,
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let events = events(&output);
    assert_eq!(events[0]["outcome"], "provider_login_failed", "{events:?}");
    assert_eq!(
        summary(&events),
        (
            "failed".to_owned(),
            outcomes(&[("claude_code", "failed"), ("codex", "created")])
        )
    );
    assert_eq!(claude.recorded("arguments"), None);
    assert_eq!(codex.recorded("arguments").unwrap(), "login\n");
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [LIST_EVERY_KIND, READ_SERVED, LIST_MEMBERSHIPS, IMPORT_GRANT]
    );
    assert_imported(&requests[3], ORGANIZATION_ID, CODEX);
}

/// A directory holding a fake `claude` that runs `then` once it has started, for a sign-in a
/// signal ends; its `sleep` comes from the test's `PATH`, as `FakeProgram`'s tools do.
fn signalled_claude(then: &str) -> tempfile::TempDir {
    use super::pi_installation::quote;
    let directory = tempfile::tempdir().unwrap();
    let claude = directory.path().join("claude");
    let tools = std::env::var("PATH").unwrap_or_default();
    fs::write(
        &claude,
        format!(
            "#!/bin/sh\nPATH={}\nexport PATH\necho claude-sign-in-started\n{then}\n",
            quote(&tools)
        ),
    )
    .unwrap();
    fs::set_permissions(&claude, Permissions::from_mode(0o755)).unwrap();
    directory
}

#[test]
fn a_signal_that_ends_the_claude_sign_in_stops_the_command_with_its_status() {
    // How the sign-in ends, and the status and outcome it stops `useful account integration connect` with:
    // the member's interrupt reaches the sign-in's own terminal, so `claude` alone receives it,
    // while a signal sent to `useful` is passed to `claude`.
    let cases = [
        ("kill -INT $$", 130, "interrupted"),
        ("kill -TERM $$", 143, "terminated"),
        ("kill -HUP $$", 143, "terminated"),
        ("kill -INT \"$PPID\"\nexec sleep 30", 130, "interrupted"),
        ("kill -TERM \"$PPID\"\nexec sleep 30", 143, "terminated"),
    ];
    for (then, status, outcome) in cases {
        let claude = signalled_claude(then);
        let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
        let run = |server: &ScriptedServer, credential: &Path, args: &[&str]| {
            let opener = Opener::new(0);
            let home = AmbientHome::new();
            let path =
                std::env::join_paths([opener.directory.path(), claude.path(), &codex.bin]).unwrap();
            let output = typed_output(
                create_command(server, credential, &opener, Place::Desktop, args)
                    .env("PATH", path)
                    .envs(home.variables()),
                b"",
            );
            home.assert_untouched_and_clean();
            output
        };

        let (server, _directory, credential) = prepared(vec![
            holding(&["github", "gitlab.com", "linear"], false),
            serving_every(),
            only_acme(),
        ]);
        let output = run(&server, &credential, &["--all", "--json"]);
        assert_eq!(
            output.status.code(),
            Some(status),
            "{then}: {}",
            stderr(&output)
        );
        assert_eq!(
            summary(&events(&output)),
            (outcome.to_owned(), outcomes(&[("claude_code", outcome)])),
            "{then}"
        );
        assert_eq!(codex.recorded("arguments"), None, "{then}");
        assert_eq!(
            request_lines(&server.finish()),
            [LIST_EVERY_KIND, READ_SERVED, LIST_MEMBERSHIPS],
            "{then}"
        );

        // A single provider's sign-in that a signal ends is a failed sign-in.
        let (server, _directory, credential) =
            prepared(vec![serving_every(), only_acme(), nothing_held()]);
        let output = run(&server, &credential, &["claude_code", "--json"]);
        assert_eq!(output.status.code(), Some(1), "{then}: {}", stderr(&output));
        let events = events(&output);
        assert_eq!(events.len(), 1, "{then}: {events:?}");
        assert_eq!(events[0]["outcome"], "provider_login_failed", "{then}");
        assert_eq!(
            request_lines(&server.finish()),
            [READ_SERVED, LIST_MEMBERSHIPS, LIST_NATIVE],
            "{then}"
        );
    }
}

#[test]
fn a_provider_the_deployment_does_not_serve_is_reported_and_passed_over_without_a_sign_in() {
    let (server, _directory, credential) = prepared(
        [
            vec![
                holding(&["github"], true),
                predating_served(),
                problem("503 Service Unavailable", 503, "provider-unavailable"),
            ],
            approved("linear").to_vec(),
        ]
        .concat(),
    );
    let opener = Opener::new(0);
    let output = run_every(&server, &credential, &opener, &[], &["--all", "--json"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let events = events(&output);
    assert_eq!(events[0]["event"], "consent_result");
    assert_eq!(events[0]["outcome"], "provider_unavailable");
    assert_eq!(
        summary(&events),
        (
            "completed".to_owned(),
            outcomes(&[
                ("gitlab.com", "provider_unavailable"),
                ("linear", "created")
            ])
        )
    );
    assert_eq!(opener.opened(1), [format!("1 {}", consent_url("linear"))]);
    let requests = server.finish();
    let poll = poll_line();
    assert_eq!(
        request_lines(&requests),
        [
            LIST_EVERY_KIND,
            READ_SERVED,
            START_CONSENT,
            START_CONSENT,
            poll.as_str()
        ]
    );
    assert_eq!(start_body(&requests[2]), "gitlab.com");
    assert_eq!(start_body(&requests[3]), "linear");
}

pub(super) const READ_SERVED: &str = "GET /api/v1/me/grant-providers HTTP/1.1";

/// The deployment's answer naming the providers it serves, each with its kind.
fn serving(providers: &[&str]) -> Vec<u8> {
    serving_titled(providers, &[])
}

/// The deployment's answer naming `providers` in order, each with its kind, and each provider
/// `titles` names with that display name.
fn serving_titled(providers: &[&str], titles: &[(&str, &str)]) -> Vec<u8> {
    let items: Vec<_> = providers
        .iter()
        .map(|provider| {
            let kind = if matches!(*provider, "claude_code" | "codex") {
                "native"
            } else {
                "oauth"
            };
            let mut item = serde_json::json!({"provider": provider, "kind": kind});
            if let Some((_, title)) = titles.iter().find(|(named, _)| named == provider) {
                item["displayName"] = (*title).into();
            }
            item
        })
        .collect();
    json_http_response("200 OK", serde_json::json!({"items": items}))
}

/// The answer of a deployment that serves every provider.
fn serving_every() -> Vec<u8> {
    serving(&["github", "gitlab.com", "linear", "claude_code", "codex"])
}

/// The answer of a deployment that predates the read of the providers it serves.
pub(super) fn predating_served() -> Vec<u8> {
    problem("404 Not Found", 404, "not-found")
}

/// The outcome of each `import_result` event, in order.
fn import_outcomes(events: &[serde_json::Value]) -> Vec<&str> {
    events
        .iter()
        .filter(|event| event["event"] == "import_result")
        .map(|event| event["outcome"].as_str().unwrap())
        .collect()
}

#[test]
fn a_coding_agent_the_deployment_does_not_serve_is_passed_over_before_its_sign_in() {
    // Named alone, it is refused before its organization, its sign-in or an import.
    let (server, _directory, credential) = prepared(vec![serving(&["github", "codex"])]);
    let claude = FakeProgram::claude(SetupToken::Prints);
    let home = AmbientHome::new();
    let output = run_native(
        &server,
        &credential,
        &home,
        Some(&claude),
        Place::Desktop,
        &["claude_code", "--json"],
        Input::Typed(b""),
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert_eq!(import_outcomes(&events(&output)), ["provider_unavailable"]);
    assert_eq!(claude.recorded("arguments"), None);
    assert_eq!(request_lines(&server.finish()), [READ_SERVED]);

    // Without a provider, it is passed over and the coding agent the deployment serves is
    // signed in to.
    let (server, _directory, credential) = prepared(vec![
        holding(&["github", "gitlab.com", "linear"], false),
        serving(&["github", "gitlab.com", "linear", "codex"]),
        only_acme(),
        stored(CODEX, "201 Created", 1),
    ]);
    let opener = Opener::new(0);
    let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
    let claude = FakeProgram::claude(SetupToken::Prints);
    let output = run_every(
        &server,
        &credential,
        &opener,
        &[&codex, &claude],
        &["--all", "--json"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let events = events(&output);
    assert_eq!(
        import_outcomes(&events),
        ["provider_unavailable", "imported"]
    );
    assert_eq!(
        summary(&events).1,
        outcomes(&[
            ("claude_code", "provider_unavailable"),
            ("codex", "created")
        ])
    );
    assert_eq!(claude.recorded("arguments"), None);
    assert_eq!(codex.recorded("arguments").unwrap(), "login\n");
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [LIST_EVERY_KIND, READ_SERVED, LIST_MEMBERSHIPS, IMPORT_GRANT]
    );
    assert_imported(&requests[3], ORGANIZATION_ID, CODEX);
}

#[test]
fn a_deployment_that_predates_the_served_providers_read_is_signed_in_to_as_before() {
    let (server, _directory, credential) = prepared(vec![
        predating_served(),
        only_acme(),
        nothing_held(),
        stored(CLAUDE_CODE, "201 Created", 1),
    ]);
    let claude = FakeProgram::claude(SetupToken::Prints);
    let home = AmbientHome::new();
    let fake = Fake {
        program: Some(&claude),
        environment: &[(CLAUDE_FLOW, "browser")],
    };
    let output = run_fake(
        &server,
        &credential,
        &home,
        fake,
        Place::Desktop,
        &["claude_code"],
        Input::Typed(b""),
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(claude.recorded("arguments").unwrap(), "setup-token\n");
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [READ_SERVED, LIST_MEMBERSHIPS, LIST_NATIVE, IMPORT_GRANT]
    );
    assert_imported(&requests[3], ORGANIZATION_ID, CLAUDE_CODE);

    let (server, _directory, credential) = prepared(vec![
        holding(&["github", "gitlab.com", "linear"], false),
        predating_served(),
        only_acme(),
        stored(CLAUDE_CODE, "201 Created", 1),
        stored(CODEX, "201 Created", 1),
    ]);
    let opener = Opener::new(0);
    let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
    let claude = FakeProgram::claude(SetupToken::Prints);
    let output = run_every(
        &server,
        &credential,
        &opener,
        &[&codex, &claude],
        &["--all", "--json"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        summary(&events(&output)).1,
        outcomes(&[("claude_code", "created"), ("codex", "created")])
    );
    assert_eq!(
        request_lines(&server.finish()),
        [
            LIST_EVERY_KIND,
            READ_SERVED,
            LIST_MEMBERSHIPS,
            IMPORT_GRANT,
            IMPORT_GRANT
        ]
    );
}

/// The answer of a deployment that serves `example`, titled `Example Cloud`, between `github`
/// and `gitlab.com`: a command names the providers in its own order, not the deployment's.
fn serving_example_early() -> Vec<u8> {
    serving_titled(
        &[
            "github",
            "example",
            "gitlab.com",
            "linear",
            "claude_code",
            "codex",
        ],
        &[("example", "Example Cloud")],
    )
}

#[test]
fn create_without_a_provider_consents_to_each_other_oauth_provider_served_after_the_built_in_ones()
{
    for (held, served, consents) in [
        (
            &["github"][..],
            serving_example_early(),
            &["gitlab.com", "linear", "example"][..],
        ),
        (
            &["github", "example"],
            serving_example_early(),
            &["gitlab.com", "linear"],
        ),
        (&["github"], predating_served(), &["gitlab.com", "linear"]),
    ] {
        let mut responses = vec![holding(held, true), served];
        for provider in consents {
            responses.extend(approved(provider));
        }
        let (server, _directory, credential) = prepared(responses);
        let opener = Opener::new(0);
        let output = run_every(&server, &credential, &opener, &[], &["--all", "--json"]);

        assert_eq!(
            output.status.code(),
            Some(0),
            "{held:?}: {}",
            stderr(&output)
        );
        let created: Vec<_> = consents
            .iter()
            .map(|provider| (*provider, "created"))
            .collect();
        assert_eq!(
            summary(&events(&output)),
            ("completed".to_owned(), outcomes(&created)),
            "{held:?}"
        );
        let requests = server.finish();
        assert_member_requests(&requests);
        let poll = poll_line();
        let mut expected = vec![LIST_EVERY_KIND, READ_SERVED];
        for _ in consents {
            expected.extend([START_CONSENT, poll.as_str()]);
        }
        assert_eq!(request_lines(&requests), expected, "{held:?}");
        let started: Vec<_> = requests
            .iter()
            .filter(|request| request.starts_with("POST "))
            .map(|request| start_body(request))
            .collect();
        assert_eq!(started, consents, "{held:?}");
    }

    // The consent of a served provider is titled by its served display name.
    let mut responses = vec![
        holding(&["github", "gitlab.com", "linear"], true),
        serving_example_early(),
    ];
    responses.extend(approved("example"));
    let (server, _directory, credential) = prepared(responses);
    let opener = Opener::new(0);
    let output = run_every(&server, &credential, &opener, &[], &["--all"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let approval = approval_line(&stdout(&output), &consent_url("example"));
    assert!(approval.contains("Example Cloud"), "{approval}");
    assert_eq!(server.finish().len(), 4);
}

/// The report that ends the human output of `useful account integration connect` without a provider, whose
/// first outcome line names `first`: its verdict line, then the lines after it.
fn summary_report<'a>(text: &'a str, first: &str) -> Vec<&'a str> {
    let lines: Vec<_> = text.lines().collect();
    let entry = lines
        .iter()
        .rposition(|line| line.starts_with(&format!("{first}: ")))
        .unwrap_or_else(|| panic!("no outcome of {first}: {text}"));
    lines[entry - 1..].to_vec()
}

/// The lines of a summary report after its data fields: its remedies.
fn remedies<'a>(report: &[&'a str]) -> Vec<&'a str> {
    let fields = report
        .iter()
        .position(|line| line.starts_with("deployment: "))
        .unwrap();
    report[fields + 1..].to_vec()
}

#[test]
fn a_summary_with_a_provider_passed_over_is_no_success_verdict_and_names_it() {
    let (server, _directory, credential) = prepared(
        [
            vec![
                holding(&["github"], true),
                predating_served(),
                problem("503 Service Unavailable", 503, "provider-unavailable"),
            ],
            approved("linear").to_vec(),
        ]
        .concat(),
    );
    let opener = Opener::new(0);
    let output = run_every(&server, &credential, &opener, &[], &["--all"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    let report = summary_report(&text, "gitlab.com");
    assert!(!report[0].starts_with('✓'), "{text}");
    assert!(
        report.contains(&"gitlab.com: provider_unavailable") && report.contains(&"linear: created"),
        "{text}"
    );
    assert!(
        remedies(&report)
            .iter()
            .any(|line| line.contains("gitlab.com")),
        "{text}"
    );
    let poll = poll_line();
    assert_eq!(
        request_lines(&server.finish()),
        [
            LIST_EVERY_KIND,
            READ_SERVED,
            START_CONSENT,
            START_CONSENT,
            poll.as_str()
        ]
    );
}

#[test]
fn a_summary_of_consents_only_started_is_no_success_verdict_and_names_where_to_see_them() {
    let (server, _directory, credential) = prepared(vec![
        holding(&["github", "gitlab.com"], true),
        predating_served(),
        json_http_response("201 Created", consent_of("linear", "pending")),
    ]);
    let opener = Opener::new(0);
    let output = run_every(&server, &credential, &opener, &[], &["--all", "--no-wait"]);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    let report = summary_report(&text, "linear");
    assert!(!report[0].starts_with('✓'), "{text}");
    assert!(report.contains(&"linear: started"), "{text}");
    assert!(
        remedies(&report)
            .iter()
            .any(|line| line.trim() == "useful account integration list"),
        "{text}"
    );
    assert_eq!(
        request_lines(&server.finish()),
        [LIST_EVERY_KIND, READ_SERVED, START_CONSENT]
    );
}

#[test]
fn a_summary_with_codex_missing_names_installing_it_before_running_the_command_again() {
    let (server, _directory, credential) = prepared(vec![
        holding(&["github", "gitlab.com", "linear"], false),
        serving_every(),
        only_acme(),
        stored(CLAUDE_CODE, "201 Created", 1),
    ]);
    let opener = Opener::new(0);
    // `claude` alone is on `PATH`.
    let claude = FakeProgram::claude(SetupToken::Prints);
    let output = run_every(&server, &credential, &opener, &[&claude], &["--all"]);

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let text = stdout(&output);
    let report = summary_report(&text, "claude_code");
    assert!(report[0].starts_with('✗'), "{text}");
    assert!(report.contains(&"codex: failed"), "{text}");
    let remedies = remedies(&report);
    assert!(
        remedies.iter().any(|line| {
            !line.trim_start().starts_with("useful ")
                && line.contains("codex")
                && line.contains("PATH")
        }),
        "{text}"
    );
    for command in [
        "useful account integration connect codex --from-file PATH",
        "useful account integration connect --all",
    ] {
        assert!(
            remedies.iter().any(|line| line.trim() == command),
            "{command}: {text}"
        );
    }
    assert_eq!(
        request_lines(&server.finish()),
        [LIST_EVERY_KIND, READ_SERVED, LIST_MEMBERSHIPS, IMPORT_GRANT]
    );
}

#[test]
fn a_member_who_holds_every_provider_is_told_so_after_the_list_and_the_served_read() {
    for json in [false, true] {
        let (server, _directory, credential) = prepared(vec![
            holding(&["github", "gitlab.com", "linear"], true),
            predating_served(),
        ]);
        let opener = Opener::new(0);
        let args: &[&str] = if json {
            &["--all", "--json"]
        } else {
            &["--all"]
        };
        let output = run_every(&server, &credential, &opener, &[], args);

        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        if json {
            let events = events(&output);
            assert_eq!(events.len(), 1);
            assert_eq!(summary(&events), ("nothing_to_create".to_owned(), vec![]));
        } else {
            assert!(!output.stdout.is_empty());
        }
        assert!(opener.opened(0).is_empty());
        assert_eq!(
            request_lines(&server.finish()),
            [LIST_EVERY_KIND, READ_SERVED]
        );
    }
}

#[test]
fn an_unresolved_organization_passes_over_the_coding_agents_and_the_consents_still_run() {
    let cases = [
        (
            "several",
            memberships(&[
                (ORGANIZATION_ID, "acme"),
                (GLOBEX_ORGANIZATION_ID, "globex"),
            ]),
        ),
        ("none", memberships(&[])),
    ];
    for (case, organizations) in cases {
        for json in [true, false] {
            let (server, _directory, credential) = prepared(
                [
                    vec![holding(&[], false), serving_every(), organizations.clone()],
                    approved("github").to_vec(),
                    approved("gitlab.com").to_vec(),
                    approved("linear").to_vec(),
                ]
                .concat(),
            );
            let opener = Opener::new(0);
            let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
            let claude = FakeProgram::claude(SetupToken::Prints);
            let args: &[&str] = if json {
                &["--all", "--json"]
            } else {
                &["--all"]
            };
            let output = run_every(&server, &credential, &opener, &[&codex, &claude], args);

            // The grants made count as they do beside a provider the deployment does not serve.
            assert_eq!(output.status.code(), Some(0), "{case}: {}", stderr(&output));
            assert_eq!(opener.opened(3).len(), 3, "{case}");
            assert_eq!(codex.recorded("arguments"), None, "{case}");
            assert_eq!(claude.recorded("arguments"), None, "{case}");
            if json {
                let events = events(&output);
                let passed_over: Vec<_> = events
                    .iter()
                    .filter(|event| event["event"] == "import_result")
                    .map(|event| event["outcome"].as_str().unwrap())
                    .collect();
                assert_eq!(
                    passed_over,
                    ["organization_required", "organization_required"],
                    "{case}"
                );
                assert_eq!(
                    summary(&events),
                    (
                        "completed".to_owned(),
                        outcomes(&[
                            ("github", "created"),
                            ("gitlab.com", "created"),
                            ("linear", "created"),
                            ("claude_code", "organization_required"),
                            ("codex", "organization_required")
                        ])
                    ),
                    "{case}"
                );
            } else {
                let text = stderr(&output);
                assert!(
                    text.contains("useful account integration connect --all --org ORG"),
                    "{case}: {text}"
                );
            }
            let poll = poll_line();
            assert_eq!(
                request_lines(&server.finish()),
                [
                    LIST_EVERY_KIND,
                    READ_SERVED,
                    LIST_MEMBERSHIPS,
                    START_CONSENT,
                    poll.as_str(),
                    START_CONSENT,
                    poll.as_str(),
                    START_CONSENT,
                    poll.as_str()
                ],
                "{case}"
            );
        }

        // With nothing else to make, passing over the coding agents makes no grant.
        let (server, _directory, credential) = prepared(vec![
            holding(&["github", "gitlab.com", "linear"], false),
            serving_every(),
            organizations,
        ]);
        let opener = Opener::new(0);
        let output = run_every(&server, &credential, &opener, &[], &["--all", "--json"]);

        assert_eq!(output.status.code(), Some(1), "{case}: {}", stderr(&output));
        assert_eq!(
            summary(&events(&output)),
            (
                "failed".to_owned(),
                outcomes(&[
                    ("claude_code", "organization_required"),
                    ("codex", "organization_required")
                ])
            ),
            "{case}"
        );
        assert_eq!(
            request_lines(&server.finish()),
            [LIST_EVERY_KIND, READ_SERVED, LIST_MEMBERSHIPS],
            "{case}"
        );
    }
}

#[test]
fn a_coding_agent_held_only_in_another_organization_is_selected_for_the_one_named() {
    let mut claude_in_globex = claude_grant_of(OTHER_NATIVE_GRANT_ID);
    claude_in_globex["organizationId"] = GLOBEX_ORGANIZATION_ID.into();
    let held = page(
        &[
            oauth_grant(OAUTH_GRANT_ID, "github", "active"),
            oauth_grant(OAUTH_GRANT_ID, "gitlab.com", "active"),
            oauth_grant(OAUTH_GRANT_ID, "linear", "active"),
            codex_grant(NATIVE_GRANT_ID, ORGANIZATION_ID, "active"),
            claude_in_globex,
        ],
        None,
    );
    let (server, _directory, credential) = prepared(vec![
        held,
        serving_every(),
        stored_in(GLOBEX_ORGANIZATION_ID, CODEX, "201 Created", 1),
    ]);
    let opener = Opener::new(0);
    let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
    let claude = FakeProgram::claude(SetupToken::Prints);
    let output = run_every(
        &server,
        &credential,
        &opener,
        &[&codex, &claude],
        &["--all", "--org", GLOBEX_ORGANIZATION_ID, "--json"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        summary(&events(&output)),
        ("completed".to_owned(), outcomes(&[("codex", "created")]))
    );
    assert_eq!(codex.recorded("arguments").unwrap(), "login\n");
    assert_eq!(claude.recorded("arguments"), None);
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [LIST_EVERY_KIND, READ_SERVED, IMPORT_GRANT]
    );
    assert_imported(&requests[2], GLOBEX_ORGANIZATION_ID, CODEX);
}

#[test]
fn an_option_that_needs_a_provider_or_all_with_one_exits_2_before_any_request() {
    let directory = tempfile::tempdir().unwrap();
    let login = private_file(directory.path(), "auth.json", CODEX_MATERIAL.as_bytes());
    let login = login.to_str().unwrap();
    // A file is one coding agent's login, so it needs `PROVIDER`; each other selector is refused
    // beside it, since a bare `create` is refused whatever else it is given.
    let cases: [&[&str]; 6] = [
        &["--all", "--from-file", login],
        &["--all", "--token-file", login],
        &["--workflow", "workflow.yaml", "--from-file", login],
        &["--workflow", "workflow.yaml", "--token-file", login],
        &["--all", "linear"],
        &["codex", "--all"],
    ];
    for args in cases {
        let (server, _directory, credential) = prepared(vec![]);
        let opener = Opener::new(0);
        let output = run_every(&server, &credential, &opener, &[], args);

        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(server.finish().is_empty(), "{args:?}");
    }
}

#[test]
fn a_coding_agent_refuses_the_options_that_wait_for_a_consent_which_still_apply_without_one() {
    let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
    let claude = FakeProgram::claude(SetupToken::Prints);
    let programs: [&FakeProgram; 2] = [&codex, &claude];
    let cases: [&[&str]; 5] = [
        &["codex", "--no-wait"],
        &["codex", "--timeout", "30s"],
        &["claude_code", "--no-wait"],
        &["claude_code", "--timeout", "30s"],
        &["claude_code", "--login"],
    ];
    for args in cases {
        let (server, _directory, credential) = prepared(vec![]);
        let opener = Opener::new(0);
        let output = run_every(&server, &credential, &opener, &programs, args);

        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(output.stdout.is_empty(), "{args:?}");
        assert_eq!(codex.recorded("arguments"), None, "{args:?}");
        assert_eq!(claude.recorded("arguments"), None, "{args:?}");
        assert!(server.finish().is_empty(), "{args:?}");
    }

    // `--login` is Codex's: the remedy names Claude Code's own sign-in, the default.
    let (server, _directory, credential) = prepared(vec![]);
    let opener = Opener::new(0);
    let output = run_every(
        &server,
        &credential,
        &opener,
        &programs,
        &["claude_code", "--login"],
    );
    let shown = stderr(&output);
    assert!(
        shown
            .lines()
            .any(|line| line.trim() == "useful account integration connect claude_code"),
        "{shown}"
    );

    // Without a provider, both still apply to the consents.
    let (server, _directory, credential) = prepared(vec![
        holding(&["github", "gitlab.com"], true),
        predating_served(),
        json_http_response("201 Created", consent_of("linear", "pending")),
    ]);
    let output = run_every(
        &server,
        &credential,
        &opener,
        &programs,
        &["--all", "--no-wait", "--json"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        summary(&events(&output)).1,
        outcomes(&[("linear", "started")])
    );
    assert_eq!(
        request_lines(&server.finish()),
        [LIST_EVERY_KIND, READ_SERVED, START_CONSENT]
    );

    let (server, _directory, credential) = prepared(
        [
            vec![holding(&["github", "gitlab.com"], true), predating_served()],
            approved("linear").to_vec(),
        ]
        .concat(),
    );
    let output = run_every(
        &server,
        &credential,
        &opener,
        &programs,
        &["--all", "--timeout", "30s", "--json"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        summary(&events(&output)).1,
        outcomes(&[("linear", "created")])
    );
    assert_eq!(codex.recorded("arguments"), None);
    assert_eq!(claude.recorded("arguments"), None);
}

// A root workflow that runs `child.yaml` and forwards a Linear credential and a credential of no
// known kind.
const ROOT_WORKFLOW: &str = r#"schemaVersion: 1
environmentPassthrough: [LINEAR_API_KEY, BUILDKITE_API_TOKEN]
steps:
  stage:
    kind: workflow
    workflow: child.yaml
    on:
      succeeded: exit.succeeded
      failed: exit.failed
"#;

// The child workflow: a Claude Code agent step and a command step.
const CHILD_WORKFLOW: &str = r#"schemaVersion: 1
agentProfiles:
  writing:
    harness:
      kind: claude_code
      config:
        model: claude-opus-4-1
        effort: xhigh
steps:
  draft:
    kind: agent
    agent:
      profile: writing
      systemPrompt: prompts/system.md
      message:
        text:
          - file: prompts/message.md
  check:
    kind: cmd
    dependsOn: [draft]
    command:
      argv: ["./check"]
"#;

// A workflow that requires `glab`, which calls for the kind `gitlab`.
const GITLAB_WORKFLOW: &str = r#"schemaVersion: 1
requires:
  tools: [glab]
steps:
  build:
    kind: cmd
    command:
      argv: ["./build"]
"#;

/// A directory of workflow files, which is a Git repository, as the fake `git` finds one, when
/// it holds a `.git` marker.
struct Tree {
    _temporary: tempfile::TempDir,
    root: std::path::PathBuf,
}

impl Tree {
    fn new(files: &[(&str, &str)], repository: bool) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("source");
        fs::create_dir_all(root.join("prompts")).unwrap();
        for &(path, contents) in files {
            fs::write(root.join(path), contents).unwrap();
        }
        if repository {
            fs::create_dir(root.join(".git")).unwrap();
        }
        Self {
            _temporary: temporary,
            root,
        }
    }

    /// `root.yaml` running `child.yaml`: Linear, Claude Code, and as unknown a forwarded variable
    /// of no known kind and a command step.
    fn linear_and_claude_code(repository: bool) -> Self {
        Self::new(
            &[
                ("root.yaml", ROOT_WORKFLOW),
                ("child.yaml", CHILD_WORKFLOW),
                ("prompts/system.md", "System prompt."),
                ("prompts/message.md", "Message."),
            ],
            repository,
        )
    }

    fn gitlab() -> Self {
        Self::new(&[("gitlab.yaml", GITLAB_WORKFLOW)], true)
    }

    fn path(&self, file: &str) -> String {
        self.root.join(file).to_str().unwrap().to_owned()
    }
}

/// A fake `git` that records each invocation's arguments beside itself, answers
/// `rev-parse --show-toplevel` with the nearest directory at or above the physical working
/// directory that holds a `.git` marker, and fails anything else, so no `origin` remote is found.
pub(super) struct Git(pub(super) tempfile::TempDir);

impl Git {
    pub(super) fn new() -> Self {
        Self(fake_git(
            "printf '%s\\n' \"$*\" >> \"${0%/*}/invoked\"\n\
             if [ \"$1 $2\" = 'rev-parse --show-toplevel' ]; then\n\
             directory=$(pwd -P)\n\
             while [ -n \"$directory\" ]; do\n\
             if [ -e \"$directory/.git\" ]; then echo \"$directory\"; exit 0; fi\n\
             directory=${directory%/*}\n\
             done\n\
             echo 'fatal: not a git repository' >&2\n\
             exit 128\n\
             fi\n\
             exit 1",
        ))
    }

    fn in_tree<'a>(&'a self, tree: &'a Tree) -> Option<Checkout<'a>> {
        Some(Checkout {
            directory: &tree.root,
            git: self.0.path(),
        })
    }

    pub(super) fn invocations(&self) -> Vec<String> {
        fs::read_to_string(self.0.path().join("invoked"))
            .map(|record| record.lines().map(str::to_owned).collect())
            .unwrap_or_default()
    }
}

// The entry of the tree's plan for each provider in `entries`: its name, and its origins as the
// doctor's JSON carries them.
fn planned(event: &serde_json::Value, entries: &str) -> Vec<(String, serde_json::Value)> {
    event[entries]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["provider"].as_str().unwrap().to_owned(),
                entry["origins"].clone(),
            )
        })
        .collect()
}

fn providers_of(event: &serde_json::Value, entries: &str) -> Vec<String> {
    planned(event, entries)
        .into_iter()
        .map(|(provider, _)| provider)
        .collect()
}

const CLAUDE_CODE_ORIGINS: &str = r#"[{"declaration": "agent_profile", "workflow": "child.yaml", "node": {"kind": "step", "id": "draft"}, "name": "writing"}]"#;
const LINEAR_ORIGINS: &str =
    r#"[{"declaration": "forwarded_variable", "workflow": "root.yaml", "name": "LINEAR_API_KEY"}]"#;

fn origins(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap()
}

#[test]
fn create_workflow_signs_in_to_only_the_providers_its_tree_calls_for() {
    let tree = Tree::linear_and_claude_code(true);
    let git = Git::new();
    let (server, _directory, credential) = prepared(
        [
            vec![nothing_held(), serving_every(), only_acme()],
            approved("linear").to_vec(),
            vec![stored(CLAUDE_CODE, "201 Created", 1)],
        ]
        .concat(),
    );
    let opener = Opener::new(0);
    let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
    let claude = FakeProgram::claude(SetupToken::Prints);
    let output = run_in(
        &server,
        &credential,
        &opener,
        &[&codex, &claude],
        git.in_tree(&tree),
        &["--workflow", "root.yaml"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(opener.opened(1), [format!("1 {}", consent_url("linear"))]);
    assert_eq!(claude.recorded("arguments").unwrap(), "setup-token\n");
    assert_eq!(codex.recorded("arguments"), None);
    let text = stdout(&output);
    for fact in [
        "root.yaml",
        "child.yaml",
        "LINEAR_API_KEY",
        "BUILDKITE_API_TOKEN",
        "linear: created",
        "claude_code: created",
    ] {
        assert!(text.contains(fact), "{fact}: {text}");
    }
    for absent in ["github:", "gitlab.com:", "codex:"] {
        assert!(!text.contains(absent), "{absent}: {text}");
    }
    // Git is asked for the repository's root and its `origin` remote, then, since no option
    // names the organization of the Claude Code grant, for the checkout's remotes, which name
    // none here, so the only membership does; nothing else.
    assert_eq!(
        git.invocations(),
        [
            "rev-parse --show-toplevel",
            "remote get-url origin",
            "remote -v"
        ]
    );
    let requests = server.finish();
    assert_member_requests(&requests);
    let poll = poll_line();
    assert_eq!(
        request_lines(&requests),
        [
            LIST_EVERY_KIND,
            READ_SERVED,
            LIST_MEMBERSHIPS,
            START_CONSENT,
            poll.as_str(),
            IMPORT_GRANT
        ]
    );
    assert_eq!(start_body(&requests[3]), "linear");
    assert_imported(&requests[5], ORGANIZATION_ID, CLAUDE_CODE);
}

#[test]
fn a_held_provider_is_passed_over_and_json_carries_the_plan_before_the_sign_ins() {
    let tree = Tree::linear_and_claude_code(true);
    let git = Git::new();
    let (server, _directory, credential) = prepared(vec![
        holding(&["linear"], false),
        serving_every(),
        only_acme(),
        stored(CLAUDE_CODE, "201 Created", 1),
    ]);
    let opener = Opener::new(0);
    let claude = FakeProgram::claude(SetupToken::Prints);
    let output = run_in(
        &server,
        &credential,
        &opener,
        &[&claude],
        git.in_tree(&tree),
        &["--workflow", "root.yaml", "--json"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let events = events(&output);
    let plan = &events[0];
    assert_eq!(plan["event"], "workflow_requirements", "{events:?}");
    assert_eq!(
        plan["workflows"],
        serde_json::json!(["child.yaml", "root.yaml"])
    );
    assert_eq!(
        planned(plan, "selected"),
        [("claude_code".to_owned(), origins(CLAUDE_CODE_ORIGINS))]
    );
    assert_eq!(
        planned(plan, "held"),
        [("linear".to_owned(), origins(LINEAR_ORIGINS))]
    );
    // What the declarations cannot show is listed, never guessed at.
    assert_eq!(
        plan["unknown"],
        serde_json::json!([
            {"declaration": "command", "workflow": "child.yaml", "node": {"kind": "step", "id": "check"}},
            {"declaration": "agent", "workflow": "child.yaml", "node": {"kind": "step", "id": "draft"}},
            {"declaration": "forwarded_variable", "workflow": "root.yaml", "name": "BUILDKITE_API_TOKEN"},
            {"declaration": "repository", "name": "origin"}
        ])
    );
    assert_eq!(events[1]["event"], "import_result");
    assert_eq!(events[1]["grant"]["provider"], "claude_code");
    assert_eq!(
        summary(&events),
        (
            "completed".to_owned(),
            outcomes(&[("claude_code", "created")])
        )
    );
    assert!(opener.opened(0).is_empty());
    assert_eq!(
        request_lines(&server.finish()),
        [LIST_EVERY_KIND, READ_SERVED, LIST_MEMBERSHIPS, IMPORT_GRANT]
    );
}

// The Claude Code grant `id` in Acme, authorized for a runner that reported it ready at its
// generation and refused at its last use, so its status there is `reconnect_required`.
fn claude_grant_refused(id: &str) -> serde_json::Value {
    let mut grant = native_grant_in_use();
    grant["id"] = id.into();
    grant["provider"] = "claude_code".into();
    grant["authorizations"][0]["report"]["lastUse"] = "refused".into();
    grant
}

// The member's grants: a Linear grant whose consent lapsed and a Claude Code grant a runner
// reported refused.
fn needing_reconnect() -> Vec<u8> {
    page(
        &[
            oauth_grant(OAUTH_GRANT_ID, "linear", "reconnect_required"),
            claude_grant_refused(NATIVE_GRANT_ID),
        ],
        None,
    )
}

#[test]
fn create_workflow_passes_over_each_grant_that_needs_reconnecting_naming_its_reconnect() {
    let tree = Tree::linear_and_claude_code(true);
    let git = Git::new();
    let opener = Opener::new(0);
    let claude = FakeProgram::claude(SetupToken::Prints);
    let (server, _directory, credential) = prepared(vec![
        needing_reconnect(),
        serving_every(),
        needing_reconnect(),
        serving_every(),
    ]);
    let json = run_in(
        &server,
        &credential,
        &opener,
        &[&claude],
        git.in_tree(&tree),
        &["--workflow", "root.yaml", "--json"],
    );
    let human = run_in(
        &server,
        &credential,
        &opener,
        &[&claude],
        git.in_tree(&tree),
        &["--workflow", "root.yaml"],
    );

    // Both are passed over: the plan names them as needing reconnecting, and no sign-in starts.
    assert_eq!(json.status.code(), Some(1), "{}", stderr(&json));
    let events = events(&json);
    let plan = &events[0];
    assert_eq!(plan["event"], "workflow_requirements", "{events:?}");
    assert!(providers_of(plan, "selected").is_empty(), "{plan}");
    assert!(providers_of(plan, "held").is_empty(), "{plan}");
    assert_eq!(
        planned(plan, "reconnect"),
        [
            ("linear".to_owned(), origins(LINEAR_ORIGINS)),
            ("claude_code".to_owned(), origins(CLAUDE_CODE_ORIGINS))
        ]
    );
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(
        summary(&events),
        (
            "failed".to_owned(),
            outcomes(&[
                ("linear", "reconnect_required"),
                ("claude_code", "reconnect_required")
            ])
        )
    );
    // The report names the command that signs in to each grant again.
    assert_eq!(human.status.code(), Some(1), "{}", stderr(&human));
    let report = stdout(&human);
    for grant in [OAUTH_GRANT_ID, NATIVE_GRANT_ID] {
        assert!(report.contains(&reconnect_line(grant)), "{report}");
    }
    assert_eq!(claude.recorded("arguments"), None);
    assert!(opener.opened(0).is_empty());
    assert_eq!(
        request_lines(&server.finish()),
        [LIST_EVERY_KIND, READ_SERVED, LIST_EVERY_KIND, READ_SERVED]
    );
}

// A login that reaches its runner through the personal pool alone is judged by what that runner
// reported, as one the runner is authorized for itself is.
#[test]
fn create_workflow_passes_over_a_login_refused_on_a_runner_its_pool_reaches() {
    let tree = Tree::linear_and_claude_code(true);
    let git = Git::new();
    let opener = Opener::new(0);
    let claude = FakeProgram::claude(SetupToken::Prints);
    let mut grant = claude_grant_refused(NATIVE_GRANT_ID);
    let direct = grant["authorizations"][0].clone();
    let mut pool = pool_authorization("aga_01k0z6r1w8f4jy2m7q9v3x5abf", ORGANIZATION_ID);
    pool["runners"] = serde_json::json!([{
        "runnerId": RUNNER_ID,
        "conflict": false,
        "delivery": direct["delivery"],
        "report": direct["report"]
    }]);
    grant["authorizations"] = serde_json::json!([pool]);
    let grants = page(
        &[oauth_grant(OAUTH_GRANT_ID, "linear", "active"), grant],
        None,
    );
    let (server, _directory, credential) = prepared(vec![grants, serving_every()]);
    let output = run_in(
        &server,
        &credential,
        &opener,
        &[&claude],
        git.in_tree(&tree),
        &["--workflow", "root.yaml", "--json"],
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let events = events(&output);
    let plan = &events[0];
    assert_eq!(plan["event"], "workflow_requirements", "{events:?}");
    assert_eq!(providers_of(plan, "held"), ["linear"]);
    assert_eq!(providers_of(plan, "reconnect"), ["claude_code"]);
    assert_eq!(claude.recorded("arguments"), None);
    assert_eq!(
        request_lines(&server.finish()),
        [LIST_EVERY_KIND, READ_SERVED]
    );
}

#[test]
fn create_workflow_on_a_terminal_asks_nothing_and_passes_over_a_grant_that_needs_reconnecting() {
    let tree = Tree::linear_and_claude_code(true);
    let git = Git::new();
    for json in [true, false] {
        // The Claude Code grant is healthy, so it is held.
        let (server, _directory, credential) = prepared(vec![page(
            &[
                oauth_grant(OAUTH_GRANT_ID, "linear", "reconnect_required"),
                claude_grant_of(NATIVE_GRANT_ID),
            ],
            None,
        )]);
        let opener = Opener::new(0);
        let mut args = vec!["--workflow", "root.yaml"];
        if json {
            args.push("--json");
        }
        let mut command = create_command(&server, &credential, &opener, Place::Remote, &args);
        command
            .env(
                "PATH",
                std::env::join_paths([opener.directory.path(), git.0.path()]).unwrap(),
            )
            .current_dir(&tree.root);
        let (transcript, output) = on_terminal(command, &[]);

        assert_eq!(output.status.code(), Some(1), "{json}: {transcript}");
        assert!(!transcript.contains("[y/N]"), "{transcript}");
        assert!(!transcript.contains("── linear ──"), "{transcript}");
        if json {
            let events = events(&output);
            let plan = &events[0];
            assert_eq!(plan["event"], "workflow_requirements", "{events:?}");
            assert_eq!(providers_of(plan, "reconnect"), ["linear"]);
            assert_eq!(providers_of(plan, "held"), ["claude_code"]);
            assert_eq!(
                summary(&events),
                (
                    "failed".to_owned(),
                    outcomes(&[("linear", "reconnect_required")])
                )
            );
        } else {
            let report = stdout(&output);
            assert!(report.contains("linear: reconnect_required"), "{report}");
            assert!(report.contains(&reconnect_line(OAUTH_GRANT_ID)), "{report}");
        }
        assert!(opener.opened(0).is_empty());
        assert_eq!(request_lines(&server.finish()), [LIST_EVERY_KIND], "{json}");
    }
}

#[test]
fn create_workflow_holds_a_provider_with_a_healthy_grant_beside_one_that_needs_reconnecting() {
    let tree = Tree::linear_and_claude_code(true);
    let git = Git::new();
    // Linear is held through one working grant and one whose consent lapsed, so it is held;
    // Claude Code through two grants in Acme that both need reconnecting, so it is passed over.
    let (server, _directory, credential) = prepared(vec![
        page(
            &[
                oauth_grant(OAUTH_GRANT_ID, "linear", "active"),
                oauth_grant(LINEAR_GRANT_ID, "linear", "reconnect_required"),
                claude_grant_refused(NATIVE_GRANT_ID),
                claude_grant_refused(OTHER_NATIVE_GRANT_ID),
            ],
            None,
        ),
        serving_every(),
    ]);
    let opener = Opener::new(0);
    let claude = FakeProgram::claude(SetupToken::Prints);
    let output = run_in(
        &server,
        &credential,
        &opener,
        &[&claude],
        git.in_tree(&tree),
        &["--workflow", "root.yaml", "--json"],
    );

    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let events = events(&output);
    let plan = &events[0];
    assert_eq!(providers_of(plan, "reconnect"), ["claude_code"]);
    assert_eq!(providers_of(plan, "held"), ["linear"]);
    assert_eq!(
        summary(&events),
        (
            "failed".to_owned(),
            outcomes(&[("claude_code", "reconnect_required")])
        )
    );
    assert_eq!(claude.recorded("arguments"), None);
    assert!(opener.opened(0).is_empty());
    assert_eq!(
        request_lines(&server.finish()),
        [LIST_EVERY_KIND, READ_SERVED]
    );
}

// A Claude Code grant in Acme that needs reconnecting, since another runner reported it refused at
// its last use, and that is authorized for `RUNNER_ID` too, which last reported that its host
// holds a Claude Code sign-in of its own.
fn claude_grant_on_a_signed_in_host() -> serde_json::Value {
    let mut grant = claude_grant_refused(NATIVE_GRANT_ID);
    let mut on_host = grant["authorizations"][0].clone();
    grant["authorizations"][0]["runnerId"] = NEW_RUNNER_ID.into();
    on_host["id"] = "aga_01k0z6r1w8f4jy2m7q9v3x5abe".into();
    on_host["report"] = serde_json::json!({
        "state": "foreign_login",
        "reportedAt": "2026-11-02T10:07:00Z"
    });
    grant["authorizations"]
        .as_array_mut()
        .unwrap()
        .push(on_host);
    grant
}

#[test]
fn create_workflow_runner_passes_over_a_coding_agent_the_runners_host_supplies() {
    let tree = Tree::linear_and_claude_code(true);
    let git = Git::new();
    let grants = || page(&[claude_grant_on_a_signed_in_host()], None);
    let host = |reads: Vec<Vec<u8>>| [reads, approved("linear").to_vec()].concat();
    let poll = poll_line();
    // The runner, Cloud's answers in order, the requests made, and whether the host supplies
    // Claude Code. Without `--runner`, or with a runner the grant is not authorized for, the
    // grant is passed over as needing reconnecting, as ever.
    type Case<'a> = (Option<&'a str>, Vec<Vec<u8>>, Vec<&'a str>, bool);
    let cases: [Case; 4] = [
        (
            Some(RUNNER_ID),
            host(vec![grants()]),
            vec![LIST_EVERY_KIND, START_CONSENT, poll.as_str()],
            true,
        ),
        (
            None,
            host(vec![grants(), serving_every()]),
            vec![LIST_EVERY_KIND, READ_SERVED, START_CONSENT, poll.as_str()],
            false,
        ),
        (
            Some(GLOBEX_RUNNER_ID),
            host(vec![grants(), serving_every()]),
            vec![LIST_EVERY_KIND, READ_SERVED, START_CONSENT, poll.as_str()],
            false,
        ),
        // A name is looked up among the runners of the member's organizations first.
        (
            Some("build-1"),
            host(vec![only_acme(), acme_runners_with_build_1(), grants()]),
            vec![
                LIST_MEMBERSHIPS,
                LIST_ACME_RUNNERS,
                LIST_EVERY_KIND,
                START_CONSENT,
                poll.as_str(),
            ],
            true,
        ),
    ];
    for (runner, responses, expected, supplied) in cases {
        let (server, _directory, credential) = prepared(responses);
        let opener = Opener::new(0);
        let claude = FakeProgram::claude(SetupToken::Prints);
        let mut args = vec!["--workflow", "root.yaml", "--json"];
        args.extend(runner.iter().flat_map(|runner| ["--runner", runner]));
        let output = run_in(
            &server,
            &credential,
            &opener,
            &[&claude],
            git.in_tree(&tree),
            &args,
        );

        assert_eq!(
            output.status.code(),
            Some(0),
            "{runner:?}: {}",
            stderr(&output)
        );
        let events = events(&output);
        let plan = &events[0];
        assert_eq!(plan["event"], "workflow_requirements", "{events:?}");
        assert_eq!(providers_of(plan, "selected"), ["linear"], "{runner:?}");
        assert!(providers_of(plan, "held").is_empty(), "{plan}");
        let (host, reconnect) = if supplied {
            (
                vec![("claude_code".to_owned(), origins(CLAUDE_CODE_ORIGINS))],
                vec![],
            )
        } else {
            (
                vec![],
                vec![("claude_code".to_owned(), origins(CLAUDE_CODE_ORIGINS))],
            )
        };
        assert_eq!(planned(plan, "host"), host, "{runner:?}");
        assert_eq!(planned(plan, "reconnect"), reconnect, "{runner:?}");
        let mut ended = vec![("linear", "created")];
        if !supplied {
            ended.push(("claude_code", "reconnect_required"));
        }
        assert_eq!(
            summary(&events),
            ("completed".to_owned(), outcomes(&ended)),
            "{runner:?}"
        );
        assert_eq!(claude.recorded("arguments"), None, "{runner:?}");
        let requests = server.finish();
        assert_member_requests(&requests);
        assert_eq!(request_lines(&requests), expected, "{runner:?}");
        assert_eq!(start_body(&requests[expected.len() - 2]), "linear");
    }
}

#[test]
fn create_workflow_runner_refuses_a_name_no_runner_or_several_have_before_the_plan() {
    let tree = Tree::linear_and_claude_code(true);
    let git = Git::new();
    let globex = || registrations(&[registration(GLOBEX_BUILD_1, "online", "enabled")]);
    let organizations = || {
        memberships(&[
            (ORGANIZATION_ID, "acme"),
            (GLOBEX_ORGANIZATION_ID, "globex"),
        ])
    };
    let (server, _directory, credential) = prepared(vec![
        organizations(),
        acme_runners_with_build_1(),
        globex(),
        organizations(),
        acme_runners_with_build_1(),
        globex(),
    ]);
    let opener = Opener::new(0);
    let claude = FakeProgram::claude(SetupToken::Prints);
    let run = |runner: &str| {
        run_in(
            &server,
            &credential,
            &opener,
            &[&claude],
            git.in_tree(&tree),
            &["--workflow", "root.yaml", "--runner", runner, "--json"],
        )
    };
    let several = run("build-1");
    let none = run("build-9");

    // Each refusal is the one event the stream holds, the summary, and no grant is read.
    assert_eq!(several.status.code(), Some(2), "{}", stderr(&several));
    let refusal = events(&several);
    assert_eq!(refusal.len(), 1, "{refusal:?}");
    assert_eq!(summary(&refusal), ("runner_required".to_owned(), vec![]));
    let mut named = offered(&refusal[0]);
    named.sort_by(|(left, _), (right, _)| left.cmp(right));
    assert_eq!(
        named,
        [
            (RUNNER_ID.to_owned(), "build-1".into()),
            (GLOBEX_RUNNER_ID.to_owned(), "build-1".into()),
        ]
    );
    assert_eq!(none.status.code(), Some(1), "{}", stderr(&none));
    let refusal = events(&none);
    assert_eq!(refusal.len(), 1, "{refusal:?}");
    assert_eq!(summary(&refusal), ("runner_not_found".to_owned(), vec![]));
    assert_eq!(claude.recorded("arguments"), None);
    assert!(opener.opened(0).is_empty());
    let requests = server.finish();
    assert_member_requests(&requests);
    assert_eq!(
        request_lines(&requests),
        [
            LIST_MEMBERSHIPS,
            LIST_ACME_RUNNERS,
            LIST_GLOBEX_RUNNERS,
            LIST_MEMBERSHIPS,
            LIST_ACME_RUNNERS,
            LIST_GLOBEX_RUNNERS,
        ]
    );
}

#[test]
fn create_takes_runner_only_with_workflow() {
    let (server, _directory, credential) = prepared(vec![]);
    let opener = Opener::new(0);
    for args in [
        &["github", "--runner", RUNNER_ID][..],
        &["--all", "--runner", RUNNER_ID],
        &["--all", "--runner", RUNNER_ID, "--json"],
        // `--source-root` bounds the `--workflow` files alone.
        &["github", "--source-root", "."],
        &["--all", "--source-root", "."],
    ] {
        let output = run_every(&server, &credential, &opener, &[], args);

        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(stderr(&output).contains("--workflow"), "{args:?}");
    }
    assert!(opener.opened(0).is_empty());
    assert!(server.finish().is_empty());
}

#[test]
fn create_all_selects_nothing_for_a_grant_that_needs_reconnecting() {
    let (server, _directory, credential) = prepared(vec![
        page(
            &[
                oauth_grant(OAUTH_GRANT_ID, "github", "active"),
                oauth_grant(OAUTH_GRANT_ID, "gitlab.com", "active"),
                oauth_grant(LINEAR_GRANT_ID, "linear", "reconnect_required"),
                native_grant(OTHER_NATIVE_GRANT_ID, "active"),
                claude_grant_refused(NATIVE_GRANT_ID),
            ],
            None,
        ),
        predating_served(),
    ]);
    let opener = Opener::new(0);
    let claude = FakeProgram::claude(SetupToken::Prints);
    let output = run_every(
        &server,
        &credential,
        &opener,
        &[&claude],
        &["--all", "--json"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        summary(&events(&output)),
        ("nothing_to_create".to_owned(), Vec::new())
    );
    assert_eq!(claude.recorded("arguments"), None);
    assert_eq!(
        request_lines(&server.finish()),
        [LIST_EVERY_KIND, READ_SERVED]
    );
}

// SC-GRANT-4's workflow: GitHub through the `gh` it requires, Linear through a forwarded
// variable, Claude Code through `child.yaml`'s agent step, and a forwarded variable of no
// known kind.
const CONNECTING_WORKFLOW: &str = r#"schemaVersion: 1
requires:
  tools: [gh]
environmentPassthrough: [LINEAR_API_KEY, BUILDKITE_API_TOKEN]
steps:
  stage:
    kind: workflow
    workflow: child.yaml
    on:
      succeeded: exit.succeeded
      failed: exit.failed
"#;

fn authorize_line(grant_id: &str) -> String {
    format!("POST /api/v1/me/grants/{grant_id}/authorizations HTTP/1.1")
}

// SC-GRANT-4
#[test]
fn connecting_what_a_workflow_needs_leaves_grants_one_command_authorizes_a_runner_for() {
    let tree = Tree::new(
        &[
            ("workflow.yaml", CONNECTING_WORKFLOW),
            ("child.yaml", CHILD_WORKFLOW),
            ("prompts/system.md", "System prompt."),
            ("prompts/message.md", "Message."),
        ],
        true,
    );
    let git = Git::new();
    // Ada, a member of Acme alone, holds a GitHub grant; the Linear consent and the Claude Code
    // sign-in make the other two.
    let github = oauth_grant_unauthorized(OAUTH_GRANT_ID);
    let mut linear = oauth_grant(LINEAR_GRANT_ID, "linear", "active");
    linear["authorizations"] = serde_json::json!([]);
    let claude_code = claude_grant_of(NATIVE_GRANT_ID);
    let mut consented = consent_of("linear", "completed");
    consented["resultGrant"]["id"] = LINEAR_GRANT_ID.into();
    let held = [github.clone(), linear.clone(), claude_code.clone()];
    // Each grant as it reads once the runner is authorized for it.
    let after: Vec<_> = held
        .iter()
        .map(|grant| {
            let mut grant = grant.clone();
            let prefix = if grant["kind"] == "oauth" {
                "pga"
            } else {
                "aga"
            };
            grant["authorizations"] = serde_json::json!([{
                "id": format!("{prefix}_01k0z6r1w8f4jy2m7q9v3x5abf"),
                "runnerId": RUNNER_ID,
                "organizationId": ORGANIZATION_ID,
                "createdAt": "2026-11-06T09:00:00Z"
            }]);
            grant
        })
        .collect();
    let (server, _directory, credential) = prepared(vec![
        // useful account integration connect --workflow workflow.yaml
        page(&[github], None),
        serving_every(),
        only_acme(),
        json_http_response("201 Created", consent_of("linear", "pending")),
        polled(consented),
        stored(CLAUDE_CODE, "201 Created", 1),
        // useful account integration list
        page(&held, None),
        predating_served(),
        organization(),
        identities(ada()),
        // useful account integration authorize --all --runner RUNNER --yes
        page(&held, None),
        predating_served(),
        authorized(OAUTH_GRANT_ID, RUNNER_ID),
        authorized(LINEAR_GRANT_ID, RUNNER_ID),
        authorized(NATIVE_GRANT_ID, RUNNER_ID),
        // useful account integration list
        page(&after, None),
        predating_served(),
        organization(),
        identities(ada()),
    ]);
    let opener = Opener::new(0);
    let claude = FakeProgram::claude(SetupToken::Prints);
    // run_in checks that no output carries the token or Ada's own Claude Code configuration
    // changed.
    let created = run_in(
        &server,
        &credential,
        &opener,
        &[&claude],
        git.in_tree(&tree),
        &["--workflow", "workflow.yaml", "--json"],
    );
    let listed = run_grant(&server, &credential, &["list", "--json"]);
    let authorized_all = run_grant(
        &server,
        &credential,
        &[
            "authorize",
            "--all",
            "--runner",
            RUNNER_ID,
            "--yes",
            "--json",
        ],
    );
    let listed_after = run_grant(&server, &credential, &["list", "--json"]);

    // GitHub is passed over as held, Linear and Claude Code are signed in to, and the variable
    // of no known kind is listed as unknown.
    assert_eq!(created.status.code(), Some(0), "{}", stderr(&created));
    let events = events(&created);
    let plan = &events[0];
    assert_eq!(plan["event"], "workflow_requirements", "{events:?}");
    assert_eq!(providers_of(plan, "held"), ["github"]);
    assert_eq!(providers_of(plan, "selected"), ["linear", "claude_code"]);
    assert!(
        plan["unknown"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!({
                "declaration": "forwarded_variable",
                "workflow": "workflow.yaml",
                "name": "BUILDKITE_API_TOKEN"
            })),
        "{plan}"
    );
    assert_eq!(
        summary(&events),
        (
            "completed".to_owned(),
            outcomes(&[("linear", "created"), ("claude_code", "created")])
        )
    );
    // The Linear consent URL opens, and `claude setup-token` runs on a terminal and shows its
    // prompts.
    assert_eq!(opener.opened(1), [format!("1 {}", consent_url("linear"))]);
    assert_eq!(claude.recorded("arguments").unwrap(), "setup-token\n");
    assert_eq!(claude.recorded("terminal").unwrap(), "yes\n");
    assert!(
        stderr(&created).contains(CLAUDE_SIGN_IN_URL),
        "{}",
        stderr(&created)
    );

    // Three grants, none with a runner authorized, each naming the authorization as its next
    // action.
    let grant_ids = [OAUTH_GRANT_ID, LINEAR_GRANT_ID, NATIVE_GRANT_ID];
    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    let document = json_output(&listed);
    let grants = document["grants"].as_array().unwrap();
    assert_eq!(
        grants.iter().map(|grant| &grant["id"]).collect::<Vec<_>>(),
        grant_ids
    );
    for grant in grants {
        assert_eq!(grant["authorizations"], serde_json::json!([]), "{grant}");
        assert_eq!(grant["availability"], "not_connected", "{grant}");
        assert_eq!(grant["nextAction"], "authorize_runner", "{grant}");
    }

    // One command authorizes the runner for each, and the list shows it on each.
    assert_eq!(
        authorized_all.status.code(),
        Some(0),
        "{}",
        stderr(&authorized_all)
    );
    let document = json_output(&authorized_all);
    assert_eq!(document["outcome"], "authorized");
    assert_eq!(
        grant_outcomes(&document),
        grant_ids.map(|id| (id.to_owned(), "authorized".to_owned()))
    );
    assert_eq!(
        listed_after.status.code(),
        Some(0),
        "{}{}",
        stdout(&listed_after),
        stderr(&listed_after)
    );
    for grant in json_output(&listed_after)["grants"].as_array().unwrap() {
        let runners: Vec<_> = grant["authorizations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|authorization| &authorization["runnerId"])
            .collect();
        assert_eq!(runners, [RUNNER_ID], "{grant}");
    }

    let requests = server.finish();
    assert_member_requests(&requests);
    let poll = poll_line();
    let list = [
        LIST_FIRST_PAGE,
        READ_SERVED,
        READ_ORGANIZATION,
        READ_IDENTITIES,
    ];
    let authorizations = grant_ids.map(authorize_line);
    let expected: Vec<&str> = [
        LIST_EVERY_KIND,
        READ_SERVED,
        LIST_MEMBERSHIPS,
        START_CONSENT,
        poll.as_str(),
        IMPORT_GRANT,
    ]
    .into_iter()
    .chain(list)
    .chain([LIST_FIRST_PAGE, READ_SERVED])
    .chain(authorizations.iter().map(String::as_str))
    .chain(list)
    .collect();
    assert_eq!(request_lines(&requests), expected);
    assert_eq!(start_body(&requests[3]), "linear");
    // The Claude Code grant is made for Acme, which Ada did not name.
    assert_imported(&requests[5], ORGANIZATION_ID, CLAUDE_CODE);
    for request in &requests[12..15] {
        assert_eq!(
            request_body(request),
            serde_json::json!({"runnerId": RUNNER_ID})
        );
    }
}

// The child of SC-CREDREADY-3's workflow: its one step is a Codex agent, which would start the
// fake `codex` if it ran.
const CODEX_CHILD_WORKFLOW: &str = r#"schemaVersion: 1
agentProfiles:
  writing:
    harness:
      kind: codex
      config:
        model: gpt-5.4
        effort: xhigh
steps:
  draft:
    kind: agent
    agent:
      profile: writing
      systemPrompt: prompts/system.md
      message:
        text:
          - file: prompts/message.md
"#;

/// The Codex grant authorized for `RUNNER_ID`, which reported it ready at generation 2 and
/// refused at its last use, as it reads at `generation`.
fn codex_refused_at(generation: i64) -> serde_json::Value {
    let mut grant = native_grant_in_use();
    grant["generation"] = generation.into();
    grant["authorizations"][0]["report"]["lastUse"] = "refused".into();
    grant
}

/// A grant `grant` of a report's requirement carries with no runner authorized: none reported,
/// and its own status `not_connected` with `authorize_runner`.
fn assert_authorizes_no_runner(grant: &serde_json::Value) {
    assert_eq!(grant["authorizations"], serde_json::json!([]), "{grant}");
    assert_eq!(grant["availability"], "not_connected", "{grant}");
    assert_eq!(grant["nextAction"], "authorize_runner", "{grant}");
}

/// The state, code and what meets it of the requirement of `kind` in a doctor's `report`.
fn judged(report: &serde_json::Value, kind: &str) -> (String, String, Option<String>) {
    let requirement = requirement(report, kind);
    let text = |field: &str| requirement[field].as_str().map(str::to_owned);
    (text("state").unwrap(), text("code").unwrap(), text("metBy"))
}

fn met_by(by: &str, code: &str) -> (String, String, Option<String>) {
    ("met".to_owned(), code.to_owned(), Some(by.to_owned()))
}

fn failing(state: &str, code: &str) -> (String, String, Option<String>) {
    (state.to_owned(), code.to_owned(), None)
}

// The request lines of the doctor's reads in `acme`: the organization's GitHub installations
// and Linear connections, then the member's grants.
const LIST_ACME_INSTALLATIONS: &str =
    "GET /api/v1/organizations/acme/github/installations HTTP/1.1";
const LIST_ACME_LINEAR: &str =
    "GET /api/v1/organizations/acme/connections/linear?limit=100 HTTP/1.1";

// SC-CREDREADY-3
#[test]
fn connecting_what_a_tree_lacks_from_the_doctor_reports_the_grants_it_made_on_the_runner() {
    let tree = Tree::new(
        &[
            ("workflow.yaml", CONNECTING_WORKFLOW),
            ("child.yaml", CODEX_CHILD_WORKFLOW),
            ("prompts/system.md", "System prompt."),
            ("prompts/message.md", "Message."),
        ],
        true,
    );
    let git = Git::new();
    // Ada, a member of Acme alone, holds a GitHub grant and a Codex grant authorized for the
    // runner, where Codex was refused at its last use. Acme has no GitHub installation and no
    // Linear connection.
    let github = oauth_grant(OAUTH_GRANT_ID, "github", "active");
    let before = page(&[github.clone(), codex_refused_at(2)], None);
    // The Linear consent makes a grant with no runner authorized, and `reconnect` stores the
    // Codex sign-in as the grant's generation 3, which the runner has not yet reported
    // installing.
    let mut linear = oauth_grant(LINEAR_GRANT_ID, "linear", "active");
    linear["authorizations"] = serde_json::json!([]);
    let mut consented = consent_of("linear", "completed");
    consented["resultGrant"]["id"] = LINEAR_GRANT_ID.into();
    let connected_page = page(&[github.clone(), linear.clone(), codex_refused_at(2)], None);
    let after = page(&[github, linear, codex_refused_at(3)], None);
    let doctor_reads = |grants: Vec<u8>| {
        vec![
            connection_page(&[], None),
            connection_page(&[], None),
            organization(),
            grants,
        ]
    };
    let (server, _directory, credential) = prepared(
        [
            // useful workflow doctor workflow.yaml --org acme --runner RUNNER
            doctor_reads(before.clone()),
            // useful account integration connect --workflow workflow.yaml --runner RUNNER
            vec![
                before,
                serving_every(),
                json_http_response("201 Created", consent_of("linear", "pending")),
                polled(consented),
            ],
            // useful workflow doctor workflow.yaml --org acme --runner RUNNER
            doctor_reads(connected_page),
            // useful account integration reconnect INTEGRATION
            vec![
                one(&codex_refused_at(2)),
                serving_every(),
                stored(CODEX, "200 OK", 3),
            ],
            // useful workflow doctor workflow.yaml --org acme --runner RUNNER
            doctor_reads(after),
        ]
        .concat(),
    );
    let opener = Opener::new(0);
    let codex = FakeProgram::codex(SignIn::Writes(CODEX_MATERIAL));
    // run_command_in checks that no output carries the login and that Ada's own Codex home is
    // untouched.
    let run = |command: &[&str], args: &[&str], status: i32| {
        let output = run_command_in(
            &server,
            &credential,
            &opener,
            &[&codex],
            git.in_tree(&tree),
            command,
            &[args, &["--json"]].concat(),
        );
        assert_eq!(
            output.status.code(),
            Some(status),
            "{command:?} {args:?}: {}",
            stderr(&output)
        );
        output
    };
    let doctor = |status: i32| {
        json_output(&run(
            WORKFLOW_DOCTOR,
            &["workflow.yaml", "--org", "acme", "--runner", RUNNER_ID],
            status,
        ))
    };

    let report = doctor(1);

    // GitHub is met by the grant the runner can use; Linear is missing, as the organization's
    // connections show it, and the member holds no grant of it; Codex needs reconnecting on the
    // runner.
    assert_eq!(judged(&report, "github"), met_by("grant", "grant_usable"));
    assert_eq!(
        judged(&report, "linear"),
        failing("missing", "not_connected")
    );
    assert_eq!(
        judged(&report, "codex"),
        failing("reconnect_required", "grant_reconnect_required")
    );
    assert_eq!(
        requirement(&report, "linear")["grant"],
        serde_json::json!({"provider": "linear", "grants": [], "availability": "not_connected", "nextAction": "connect"})
    );
    assert_eq!(
        held_grant(&report, "codex")["authorizations"],
        serde_json::json!([{"runnerId": RUNNER_ID, "access": "direct", "availability": "reconnect_required", "nextAction": "reconnect"}])
    );

    let connected = run(
        GRANT_CREATE,
        &["--workflow", "workflow.yaml", "--runner", RUNNER_ID],
        0,
    );

    // The plan names Linear to sign in, Codex as needing reconnecting and GitHub as held; the
    // Linear consent is approved and Codex is passed over, asking nothing.
    let flow = events(&connected);
    let plan = &flow[0];
    assert_eq!(plan["event"], "workflow_requirements", "{flow:?}");
    assert_eq!(providers_of(plan, "selected"), ["linear"]);
    assert_eq!(providers_of(plan, "reconnect"), ["codex"]);
    assert_eq!(providers_of(plan, "held"), ["github"]);
    assert_eq!(opener.opened(1), [format!("1 {}", consent_url("linear"))]);
    assert_eq!(codex.recorded("arguments"), None);
    assert_eq!(
        summary(&flow),
        (
            "completed".to_owned(),
            outcomes(&[("linear", "created"), ("codex", "reconnect_required")])
        )
    );

    // The doctor again: the Linear grant has no runner authorized, and Linear still reads as the
    // organization's connections show it.
    let report = doctor(1);
    assert_eq!(
        judged(&report, "linear"),
        failing("missing", "not_connected")
    );
    let linear_grant = held_grant(&report, "linear");
    assert_eq!(linear_grant["id"], LINEAR_GRANT_ID);
    assert_authorizes_no_runner(linear_grant);

    // Ada signs in to Codex again, which stores the grant's next generation. `codex` was
    // last started for the sign-in, so the tree's agent step did not run.
    let reconnected = run(GRANT_RECONNECT, &[NATIVE_GRANT_ID], 0);
    assert_eq!(codex.recorded("arguments").unwrap(), "login\n");
    let import = events(&reconnected).pop().unwrap();
    assert_eq!(import["event"], "import_result");
    assert_eq!(import["outcome"], "replaced");
    assert_eq!(import["grant"]["id"], NATIVE_GRANT_ID);
    assert_eq!(import["grant"]["generation"], 3);

    // Codex is pending on the runner at its next generation, which meets the need.
    let report = doctor(1);
    assert_eq!(judged(&report, "codex"), met_by("grant", "grant_usable"));
    let codex_grant = held_grant(&report, "codex");
    assert_eq!(codex_grant["id"], NATIVE_GRANT_ID);
    assert_eq!(codex_grant["generation"], 3);
    assert_eq!(
        codex_grant["authorizations"],
        serde_json::json!([{"runnerId": RUNNER_ID, "access": "direct", "availability": "pending", "nextAction": "wait_for_runner"}])
    );

    let requests = server.finish();
    assert_member_requests(&requests);
    let poll = poll_line();
    let replace = replace_line(NATIVE_GRANT_ID);
    let doctor_lines = [
        LIST_ACME_INSTALLATIONS,
        LIST_ACME_LINEAR,
        READ_ACME,
        LIST_EVERY_KIND,
    ];
    assert_eq!(
        request_lines(&requests),
        [
            &doctor_lines[..],
            &[LIST_EVERY_KIND, READ_SERVED, START_CONSENT, poll.as_str()],
            &doctor_lines,
            &[READ_NATIVE, READ_SERVED, replace.as_str()],
            &doctor_lines,
        ]
        .concat()
    );
    assert_eq!(start_body(&requests[6]), "linear");
    assert_eq!(
        request_body(&requests[14]),
        serde_json::json!({
            "recordSchemaVersion": 1,
            "material": encoded(CODEX_MATERIAL.as_bytes())
        })
    );
}

#[test]
fn a_tree_that_calls_for_gitlab_selects_gitlab_com() {
    let tree = Tree::gitlab();
    let git = Git::new();
    let (server, _directory, credential) =
        prepared([vec![nothing_held()], approved("gitlab.com").to_vec()].concat());
    let opener = Opener::new(0);
    let output = run_in(
        &server,
        &credential,
        &opener,
        &[],
        git.in_tree(&tree),
        &["--workflow", "gitlab.yaml", "--json"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let events = events(&output);
    assert_eq!(
        planned(&events[0], "selected"),
        [(
            "gitlab.com".to_owned(),
            serde_json::json!([{"declaration": "required_tool", "workflow": "gitlab.yaml", "name": "glab"}])
        )]
    );
    assert_eq!(
        summary(&events),
        (
            "completed".to_owned(),
            outcomes(&[("gitlab.com", "created")])
        )
    );
    let requests = server.finish();
    let poll = poll_line();
    assert_eq!(
        request_lines(&requests),
        [LIST_EVERY_KIND, START_CONSENT, poll.as_str()]
    );
    assert_eq!(start_body(&requests[1]), "gitlab.com");
}

#[test]
fn the_plan_names_acting_as_the_github_app_beside_a_github_sign_in() {
    let tree = Tree::new(
        &[(
            "tools.yaml",
            &GITLAB_WORKFLOW.replace("tools: [glab]", "tools: [gh, glab]"),
        )],
        true,
    );
    let git = Git::new();
    let answers = || [vec![nothing_held()], approved("github").to_vec()].concat();
    let (server, _directory, credential) = prepared(
        [
            answers(),
            approved("gitlab.com").to_vec(),
            answers(),
            approved("gitlab.com").to_vec(),
        ]
        .concat(),
    );
    let opener = Opener::new(0);
    let connect =
        |args: &[&str]| run_in(&server, &credential, &opener, &[], git.in_tree(&tree), args);
    let json = connect(&["--workflow", "tools.yaml", "--json"]);
    let human = connect(&["--workflow", "tools.yaml"]);
    server.finish();

    assert_eq!(json.status.code(), Some(0), "{}", stderr(&json));
    let plan = &events(&json)[0];
    assert_eq!(providers_of(plan, "selected"), ["github", "gitlab.com"]);
    assert_eq!(
        plan["selected"][0]["alternative"], ACTING_AS_THE_APP,
        "{plan}"
    );
    assert!(plan["selected"][1].get("alternative").is_none(), "{plan}");
    assert_eq!(human.status.code(), Some(0), "{}", stderr(&human));
    // A completed consent names no other choice, so only the plan can.
    let text = stdout(&human);
    assert!(text.contains(ACTING_AS_THE_APP), "{text}");
}

#[test]
fn a_tree_directory_is_planned_from_its_root_file() {
    // The tree's root file calls for GitLab; the directory is its own boundary, so no Git is
    // asked for a repository root.
    let tree = Tree::new(&[("workflow.yaml", GITLAB_WORKFLOW)], false);
    let git = Git::new();
    let (server, _directory, credential) =
        prepared([vec![nothing_held()], approved("gitlab.com").to_vec()].concat());
    let opener = Opener::new(0);
    let elsewhere = tempfile::tempdir().unwrap();
    let output = run_in(
        &server,
        &credential,
        &opener,
        &[],
        Some(Checkout {
            directory: elsewhere.path(),
            git: git.0.path(),
        }),
        &["--workflow", tree.root.to_str().unwrap(), "--json"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let events = events(&output);
    assert_eq!(
        planned(&events[0], "selected"),
        [(
            "gitlab.com".to_owned(),
            serde_json::json!([{"declaration": "required_tool", "workflow": "workflow.yaml", "name": "glab"}])
        )]
    );
    assert!(
        !git.invocations()
            .iter()
            .any(|invocation| invocation.starts_with("rev-parse")),
        "{:?}",
        git.invocations()
    );
    let requests = server.finish();
    let poll = poll_line();
    assert_eq!(
        request_lines(&requests),
        [LIST_EVERY_KIND, START_CONSENT, poll.as_str()]
    );
}

#[test]
fn a_declared_integration_changes_nothing_the_grant_flow_selects() {
    let tree = Tree::new(
        &[(
            "gitlab.yaml",
            &GITLAB_WORKFLOW.replace(
                "  tools: [glab]\n",
                "  tools: [glab]\n  integrations:\n    linear: {}\n",
            ),
        )],
        true,
    );
    let git = Git::new();
    let (server, _directory, credential) =
        prepared([vec![nothing_held()], approved("gitlab.com").to_vec()].concat());
    let opener = Opener::new(0);
    let output = run_in(
        &server,
        &credential,
        &opener,
        &[],
        git.in_tree(&tree),
        &["--workflow", "gitlab.yaml", "--json"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let events = events(&output);
    assert_eq!(
        planned(&events[0], "selected"),
        [(
            "gitlab.com".to_owned(),
            serde_json::json!([{"declaration": "required_tool", "workflow": "gitlab.yaml", "name": "glab"}])
        )]
    );
    let command = serde_json::json!(
        {"declaration": "command", "workflow": "gitlab.yaml", "node": {"kind": "step", "id": "build"}}
    );
    assert!(
        events[0]["unknown"].as_array().unwrap().contains(&command),
        "{}",
        events[0]
    );
    let requests = server.finish();
    let poll = poll_line();
    assert_eq!(
        request_lines(&requests),
        [LIST_EVERY_KIND, START_CONSENT, poll.as_str()]
    );
    assert_eq!(start_body(&requests[1]), "gitlab.com");
}

#[test]
fn files_in_two_repositories_are_each_derived_under_their_own_root_and_merged() {
    let first = Tree::linear_and_claude_code(true);
    let second = Tree::gitlab();
    let git = Git::new();
    let (server, _directory, credential) = prepared(
        [
            vec![holding(&["linear"], true)],
            approved("gitlab.com").to_vec(),
        ]
        .concat(),
    );
    let opener = Opener::new(0);
    let other = second.path("gitlab.yaml");
    let output = run_in(
        &server,
        &credential,
        &opener,
        &[],
        git.in_tree(&first),
        &["--workflow", "root.yaml", "--workflow", &other, "--json"],
    );

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let events = events(&output);
    let plan = &events[0];
    assert_eq!(
        plan["workflows"],
        serde_json::json!(["child.yaml", "root.yaml", "gitlab.yaml"])
    );
    assert_eq!(providers_of(plan, "selected"), ["gitlab.com"]);
    assert_eq!(providers_of(plan, "held"), ["linear", "claude_code"]);
    // The two repositories' unknown `origin` remotes are one entry.
    let repositories = plan["unknown"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["declaration"] == "repository")
        .count();
    assert_eq!(repositories, 1, "{plan}");
    assert_eq!(
        git.invocations(),
        [
            "rev-parse --show-toplevel",
            "rev-parse --show-toplevel",
            "remote get-url origin",
            "remote get-url origin"
        ]
    );
    let poll = poll_line();
    assert_eq!(
        request_lines(&server.finish()),
        [LIST_EVERY_KIND, START_CONSENT, poll.as_str()]
    );
}

#[test]
fn a_named_source_root_is_used_as_given_and_a_tree_calling_for_nothing_lacked_exits_0() {
    for json in [false, true] {
        // No `.git` marker: only `--source-root` bounds the files.
        let tree = Tree::linear_and_claude_code(false);
        let git = Git::new();
        let (server, _directory, credential) = prepared(vec![holding(&["linear"], true)]);
        let opener = Opener::new(0);
        let root = tree.root.to_str().unwrap();
        let mut args = vec!["--workflow", "root.yaml", "--source-root", root];
        if json {
            args.push("--json");
        }
        let output = run_in(
            &server,
            &credential,
            &opener,
            &[],
            git.in_tree(&tree),
            &args,
        );

        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        if json {
            let events = events(&output);
            assert_eq!(events.len(), 2, "{events:?}");
            assert_eq!(providers_of(&events[0], "selected"), Vec::<String>::new());
            assert_eq!(providers_of(&events[0], "held"), ["linear", "claude_code"]);
            assert_eq!(summary(&events), ("nothing_to_create".to_owned(), vec![]));
        } else {
            assert!(stdout(&output).contains("root.yaml"));
        }
        assert_eq!(git.invocations(), ["remote get-url origin"]);
        assert!(opener.opened(0).is_empty());
        assert_eq!(request_lines(&server.finish()), [LIST_EVERY_KIND]);
    }
}

#[test]
fn a_file_in_no_repository_or_that_does_not_resolve_or_with_a_provider_starts_nothing() {
    let outside = Tree::linear_and_claude_code(false);
    let inside = Tree::linear_and_claude_code(true);
    let cases: [(&Tree, &[&str], i32); 6] = [
        (&outside, &["--workflow", "root.yaml"], 2),
        (&inside, &["--workflow", "absent.yaml"], 1),
        (&inside, &["--workflow", "absent.yaml", "--json"], 1),
        (&inside, &["--workflow", "root.yaml", "linear"], 2),
        (&inside, &["--workflow", "root.yaml", "--all"], 2),
        (&inside, &["--source-root", "."], 2),
    ];
    for (tree, args, code) in cases {
        let git = Git::new();
        let (server, _directory, credential) = prepared(vec![]);
        let opener = Opener::new(0);
        let claude = FakeProgram::claude(SetupToken::Prints);
        let output = run_in(
            &server,
            &credential,
            &opener,
            &[&claude],
            git.in_tree(tree),
            args,
        );

        assert_eq!(
            output.status.code(),
            Some(code),
            "{args:?}: {}",
            stderr(&output)
        );
        if args[1] == "absent.yaml" {
            // The rejection is the one `useful workflow validate` prints.
            let mut validate = vec!["workflow", "validate", "--source-root", "."];
            validate.extend(&args[2..]);
            validate.push("absent.yaml");
            let validated = run_with_env_from(&validate, &[], Some(&tree.root));
            assert_eq!(validated.status.code(), Some(1), "{validated:?}");
            assert_eq!(stdout(&output), stdout(&validated), "{args:?}");
        } else {
            assert!(output.stdout.is_empty(), "{args:?}");
        }
        if std::ptr::eq(tree, &outside) {
            assert!(stderr(&output).contains("--source-root"), "{args:?}");
        }
        assert!(opener.opened(0).is_empty(), "{args:?}");
        assert_eq!(claude.recorded("arguments"), None, "{args:?}");
        assert!(server.finish().is_empty(), "{args:?}");
    }
}

#[test]
fn a_file_whose_directory_is_missing_is_rejected_as_workflow_validate_rejects_it() {
    for json in [false, true] {
        let tree = Tree::linear_and_claude_code(true);
        let git = Git::new();
        let (server, _directory, credential) = prepared(vec![]);
        let opener = Opener::new(0);
        let mut args = vec!["--workflow", "missing-dir/root.yaml"];
        if json {
            args.push("--json");
        }
        let output = run_in(
            &server,
            &credential,
            &opener,
            &[],
            git.in_tree(&tree),
            &args,
        );

        let mut validate = vec!["workflow", "validate", "--source-root", "."];
        validate.extend(&args[2..]);
        validate.push("missing-dir/root.yaml");
        let validated = run_with_env_from(&validate, &[], Some(&tree.root));
        assert_eq!(
            output.status.code(),
            validated.status.code(),
            "{json}: {}",
            stderr(&output)
        );
        assert_eq!(stdout(&output), stdout(&validated), "{json}");
        assert!(opener.opened(0).is_empty(), "{json}");
        assert!(server.finish().is_empty(), "{json}");
    }
}

#[test]
fn git_missing_from_path_or_failing_is_reported_as_that_and_starts_nothing() {
    let tree = Tree::linear_and_claude_code(true);
    let file = tree.path("root.yaml");
    let directory = tree.root.to_str().unwrap();
    // No `git` at all on `PATH`, and a `git` that fails every command in a repository.
    let missing = tempfile::tempdir().unwrap();
    let failing = fake_git("exit 128");
    for (git, code) in [(missing.path(), 1), (failing.path(), 2)] {
        let (server, _directory, credential) = prepared(vec![]);
        let opener = Opener::new(0);
        let checkout = Checkout {
            directory: &tree.root,
            git,
        };
        let output = run_in(
            &server,
            &credential,
            &opener,
            &[],
            Some(checkout),
            &["--workflow", &file],
        );

        let text = stderr(&output);
        assert_eq!(output.status.code(), Some(code), "{text}");
        assert!(output.stdout.is_empty(), "{text}");
        if code == 1 {
            assert!(text.contains("git") && text.contains("PATH"), "{text}");
        } else {
            assert!(text.contains("git rev-parse --show-toplevel"), "{text}");
            assert!(text.contains(directory), "{text}");
        }
        assert!(text.contains("--source-root"), "{text}");
        assert!(opener.opened(0).is_empty());
        assert!(server.finish().is_empty());
    }
}

// The fake coding agent programs and the member's home a sign-in `useful` runs is checked
// against.

// The Codex login's sentinel, which `CODEX_MATERIAL` carries.
const CODEX_SENTINEL: &str = "private-agent-login-material-sentinel";

// The material a member imports: a Codex `auth.json` whose bytes, trailing newline and
// spacing included, are what Cloud must receive.
const CODEX_MATERIAL: &str =
    "{\"tokens\": {\"access_token\": \"private-agent-login-material-sentinel\"}}\n";

fn encoded(material: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(material)
}

pub(super) fn private_file(directory: &Path, name: &str, contents: &[u8]) -> std::path::PathBuf {
    let path = directory.join(name);
    fs::write(&path, contents).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    path
}

// How the fake `codex` behaves after it records its invocation.
enum SignIn {
    // Writes this auth.json into $CODEX_HOME with a group- and world-readable mode, as a
    // file codex writes need not be 0600 for useful to read it.
    Writes(&'static str),
    Exits(u8),
    WritesNothing,
    // Asks useful to terminate, as a member's interrupt would, and waits to be stopped.
    Interrupts,
    // Is executable and cannot be started: its interpreter does not exist.
    CannotStart,
}

// A fake coding agent program, alone in `bin` so that it is the only program on PATH, that
// records what it saw under `record`.
struct FakeProgram {
    _directory: tempfile::TempDir,
    bin: std::path::PathBuf,
    record: std::path::PathBuf,
}

const DEVICE_CODE_PROMPT: &str = "codex-device-code-prompt";

// How the fake `claude setup-token` ends after it records its invocation and shows the sign-in
// URL; it takes the flow, a browser or a pasted code, from `CLAUDE_FLOW`.
enum SetupToken {
    // Prints the token in colour, as its own line, and a line after it.
    Prints,
    Exits(u8),
    PrintsNothing,
    // Asks useful to terminate, as a member's interrupt would, and waits to be stopped.
    Interrupts,
}

// The token the fake `claude` prints, in the form `CLAUDE_CODE_OAUTH_TOKEN` takes; the part
// after `sk-ant-` is a sentinel of its own.
const CLAUDE_TOKEN: &str = "sk-ant-oat01-private_claude_code_token-sentinel";
const CLAUDE_TOKEN_SENTINEL: &str = "private_claude_code_token-sentinel";
const CLAUDE_SIGN_IN_URL: &str =
    "https://claude.example.test/oauth/authorize?code=true&state=public-fixture-state";
const CLAUDE_FLOW: &str = "USEFUL_TEST_CLAUDE_FLOW";
const PASTE_PROMPT: &str = "Paste code here if prompted > ";
const PASTE_CODE: &str = "public-fixture-paste-code";
const AFTER_TOKEN: &str = "claude-after-token";

impl FakeProgram {
    // A fake `codex` that records its arguments, CODEX_HOME, that home's mode and its
    // config.toml, and prints a line on standard output: the device code to enter when it is
    // given `--device-auth`, as Codex's device sign-in does.
    fn codex(sign_in: SignIn) -> Self {
        use super::pi_installation::quote;
        let then = match sign_in {
            SignIn::Writes(material) => format!(
                "umask 022\nprintf '%s' {} > \"$CODEX_HOME/auth.json\"",
                quote(material)
            ),
            SignIn::Exits(status) => format!("exit {status}"),
            SignIn::WritesNothing => "exit 0".to_owned(),
            SignIn::Interrupts => "kill -TERM \"$PPID\"\nexec sleep 30".to_owned(),
            SignIn::CannotStart => String::new(),
        };
        let interpreter = if matches!(sign_in, SignIn::CannotStart) {
            "/nonexistent/useful-test-interpreter"
        } else {
            "/bin/sh"
        };
        Self::new("codex", interpreter, |record| {
            format!(
                "printf '%s\\n' \"$*\" > {arguments}\n\
                 printf '%s' \"$CODEX_HOME\" > {home}\n\
                 ls -ld \"$CODEX_HOME\" > {mode}\n\
                 cp \"$CODEX_HOME/config.toml\" {config}\n\
                 case \" $* \" in *\" --device-auth \"*) echo {DEVICE_CODE_PROMPT} ;; \
                 *) echo codex-sign-in-prompt ;; esac\n\
                 {then}\n",
                arguments = record("arguments"),
                home = record("home"),
                mode = record("mode"),
                config = record("config.toml"),
            )
        })
    }

    // A fake `claude` that records its arguments, CLAUDE_CONFIG_DIR, that directory's mode and
    // whether its standard input is its controlling terminal, then shows the sign-in URL. In
    // the paste flow it then prompts without a line ending and reads a code from its terminal,
    // going on only when the code is `PASTE_CODE`; in the browser flow it waits a moment, as
    // the browser's callback would make it.
    fn claude(setup_token: SetupToken) -> Self {
        use super::pi_installation::quote;
        let then = match setup_token {
            SetupToken::Prints => format!(
                "printf '\\033[32m%s\\033[0m\\n' {}\necho {AFTER_TOKEN}",
                quote(CLAUDE_TOKEN)
            ),
            SetupToken::Exits(status) => format!("exit {status}"),
            SetupToken::PrintsNothing => "echo claude-printed-no-token".to_owned(),
            SetupToken::Interrupts => "kill -TERM \"$PPID\"\nexec sleep 30".to_owned(),
        };
        Self::new("claude", "/bin/sh", |record| {
            format!(
                "printf '%s\\n' \"$*\" > {arguments}\n\
                 printf '%s' \"$CLAUDE_CONFIG_DIR\" > {config}\n\
                 ls -ld \"$CLAUDE_CONFIG_DIR\" > {mode}\n\
                 if [ -t 0 ] && : < /dev/tty; then echo yes; else echo no; fi > {terminal}\n\
                 echo {url}\n\
                 if [ \"${CLAUDE_FLOW}\" = paste ]; then\n\
                 printf '%s' {prompt}\n\
                 IFS= read -r code\n\
                 [ \"$code\" = {PASTE_CODE} ] || {{ echo claude-rejected-the-code; exit 1; }}\n\
                 else sleep 0.2; fi\n\
                 {then}\n",
                arguments = record("arguments"),
                config = record("config"),
                mode = record("mode"),
                terminal = record("terminal"),
                url = quote(CLAUDE_SIGN_IN_URL),
                prompt = quote(PASTE_PROMPT),
            )
        })
    }

    // Writes `bin/NAME` as a script for `interpreter` whose body `script` makes, given a
    // function that quotes the path of a record. useful runs it with only `bin` on PATH; the
    // script's own `ls`, `cp` and `sleep` come from the test's PATH, since a build sandbox
    // may have nothing under /usr/bin or /bin.
    fn new(
        name: &str,
        interpreter: &str,
        script: impl FnOnce(&dyn Fn(&str) -> String) -> String,
    ) -> Self {
        use super::pi_installation::quote;
        let directory = tempfile::tempdir().unwrap();
        let bin = directory.path().join("bin");
        let record = directory.path().join("record");
        fs::create_dir(&bin).unwrap();
        fs::create_dir(&record).unwrap();
        let tools = std::env::var("PATH").unwrap_or_default();
        let body = script(&|name| quote(record.join(name).to_str().unwrap()));
        let executable = bin.join(name);
        fs::write(
            &executable,
            format!(
                "#!{interpreter}\nPATH={tools}\nexport PATH\n{body}",
                tools = quote(&tools)
            ),
        )
        .unwrap();
        fs::set_permissions(&executable, Permissions::from_mode(0o755)).unwrap();
        Self {
            _directory: directory,
            bin,
            record,
        }
    }

    fn recorded(&self, name: &str) -> Option<String> {
        fs::read_to_string(self.record.join(name)).ok()
    }
}

// A member's home with an ambient Codex login and an ambient Claude Code configuration, which a
// sign-in `useful` runs must neither read nor change.
struct AmbientHome {
    home: tempfile::TempDir,
    // Where the command may create its temporary Codex home or Claude Code configuration.
    temporary: tempfile::TempDir,
}

const AMBIENT_MARKER: &str = "ambient-member-login-marker";

// Each ambient login: its directory under HOME, the variable naming it and its one file.
const AMBIENT_LOGINS: [(&str, &str, &str); 2] = [
    (".codex", "CODEX_HOME", "auth.json"),
    (".claude", "CLAUDE_CONFIG_DIR", ".credentials.json"),
];

fn ambient_login() -> String {
    format!("{{\"marker\": \"{AMBIENT_MARKER}\"}}")
}

impl AmbientHome {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        for (directory, _, file) in AMBIENT_LOGINS {
            let directory = home.path().join(directory);
            fs::create_dir(&directory).unwrap();
            private_file(&directory, file, ambient_login().as_bytes());
        }
        Self {
            home,
            temporary: tempfile::tempdir().unwrap(),
        }
    }

    fn ambient_codex(&self) -> std::path::PathBuf {
        self.home.path().join(".codex")
    }

    fn ambient_claude(&self) -> std::path::PathBuf {
        self.home.path().join(".claude")
    }

    // The member's HOME, CODEX_HOME and CLAUDE_CONFIG_DIR, and the temporary directory the
    // command may use.
    fn variables(&self) -> [(&'static str, std::path::PathBuf); 4] {
        [
            ("HOME", self.home.path().to_owned()),
            ("CODEX_HOME", self.ambient_codex()),
            ("CLAUDE_CONFIG_DIR", self.ambient_claude()),
            ("TMPDIR", self.temporary.path().to_owned()),
        ]
    }

    // The member's home and ambient logins are untouched and the command left nothing in its
    // temporary directory.
    fn assert_untouched_and_clean(&self) {
        assert_eq!(
            fs::read_dir(self.home.path()).unwrap().count(),
            AMBIENT_LOGINS.len(),
            "HOME gained an entry"
        );
        for (directory, variable, file) in AMBIENT_LOGINS {
            let ambient = self.home.path().join(directory);
            assert_eq!(
                fs::read_dir(&ambient).unwrap().count(),
                1,
                "the ambient {variable} gained an entry"
            );
            assert_eq!(
                fs::read_to_string(ambient.join(file)).unwrap(),
                ambient_login()
            );
        }
        assert_eq!(
            fs::read_dir(self.temporary.path()).unwrap().count(),
            0,
            "a temporary sign-in directory was left behind"
        );
    }
}
