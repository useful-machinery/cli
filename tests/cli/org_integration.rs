//! `useful org integration` acting on the organization's token of a token service
//! (REQ-INTEGRATION-16 to REQ-INTEGRATION-20) and on a runner's authorization for one of the
//! organization's connections in one project (REQ-INTEGRATION-33, REQ-INTEGRATION-34). The
//! connection cases themselves are in `connection`, `github` and `gitlab`.

use super::*;

use super::grant::{
    ALPHA, BRAVO, CHARLIE, ENDED_RUNNER_ID, LIST_ACME_RUNNERS, LIST_EVERY_KIND, NEW_RUNNER_ID,
    OAUTH_GRANT_ID, ORGANIZATION_ID, READ_SERVED, RUNNER_ID, SENTINEL, TOKEN,
    assert_stated_by_the_refusal, deleted, json_output, oauth_grant, organization, page, prepared,
    private_file, problem, registration, registrations, request_body, run_grant, statement, stderr,
};

const KNOWN_TOKEN: &str = "mergify-known-org-token-1c2d";
const TOKEN_ID: &str = "itk_01k0z6r1w8f4jy2m7q9v3x5abc";
const BUILDKITE_TOKEN_ID: &str = "itk_01k0z6r1w8f4jy2m7q9v3x5abd";
const PRINCIPAL_ID: &str = "prn_01k0z6r1w8f4jy2m7q9v3x5abc";
const OTHER_PRINCIPAL_ID: &str = "prn_01k0z6r1w8f4jy2m7q9v3x5abd";
const OTHER_PRINCIPAL_NAME: &str = "Grace Hopper";
const PROJECT_ID: &str = "prj_01k0z6r1w8f4jy2m7q9v3x5abc";
const CONNECTION_AUTHORIZATION_ID: &str = "cna_01k0z6r1w8f4jy2m7q9v3x5abc";
const INSTALLATION_ID: &str = "ghi_01k0z6r1w8f4jy2m7q9v3x5abc";
const OTHER_INSTALLATION_ID: &str = "ghi_01k0z6r1w8f4jy2m7q9v3x5abd";
const LINEAR_CONNECTION_ID: &str = "lcn_01k0z6r1w8f4jy2m7q9v3x5abc";
const NEW_AUTHORIZATION_ID: &str = "ita_01k0z6r1w8f4jy2m7q9v3x5abf";

const LIST_ACME_TOKENS: &str =
    "GET /api/v1/organizations/acme/integration-tokens?limit=200 HTTP/1.1";
const STORE_ACME_TOKEN: &str = "POST /api/v1/organizations/acme/integration-tokens HTTP/1.1";
const REVOKE_ACME_TOKEN: &str =
    "DELETE /api/v1/organizations/acme/integration-tokens/itk_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1";
const AUTHORIZE_ACME_TOKEN: &str = "POST /api/v1/organizations/acme/integration-tokens/itk_01k0z6r1w8f4jy2m7q9v3x5abc/authorizations HTTP/1.1";
const DEAUTHORIZE_ACME_TOKEN: &str = "DELETE /api/v1/organizations/acme/integration-tokens/itk_01k0z6r1w8f4jy2m7q9v3x5abc/authorizations/ita_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1";
const READ_ACME_DIRECTORY: &str = "GET /api/v1/organizations/acme/memberships?limit=200 HTTP/1.1";
const LIST_MEMBER_TOKENS: &str = "GET /api/v1/me/integration-tokens?limit=200 HTTP/1.1";
const AUTHORIZE_MEMBER_TOKEN: &str =
    "POST /api/v1/me/integration-tokens/itk_01k0z6r1w8f4jy2m7q9v3x5abc/authorizations HTTP/1.1";
const LIST_ACME_INSTALLATIONS: &str =
    "GET /api/v1/organizations/acme/github/installations HTTP/1.1";
const LIST_ACME_GITLAB: &str =
    "GET /api/v1/organizations/acme/connections/gitlab?limit=100 HTTP/1.1";
const LIST_ACME_LINEAR: &str =
    "GET /api/v1/organizations/acme/connections/linear?limit=100 HTTP/1.1";
const LIST_ACME_AUTHORIZATIONS: &str =
    "GET /api/v1/organizations/acme/connection-authorizations?limit=200 HTTP/1.1";
const AUTHORIZE_ACME_CONNECTION: &str =
    "POST /api/v1/organizations/acme/connection-authorizations HTTP/1.1";
const LIST_ACME_PROJECT_AUTHORIZATIONS: &str = "GET /api/v1/organizations/acme/connection-authorizations?limit=200&projectId=prj_01k0z6r1w8f4jy2m7q9v3x5abc&provider=github HTTP/1.1";
const LIST_ACME_RUNNER_AUTHORIZATIONS: &str = "GET /api/v1/organizations/acme/connection-authorizations?limit=200&projectId=prj_01k0z6r1w8f4jy2m7q9v3x5abc&runnerId=rnr_01k0z6r1w8f4jy2m7q9v3x5abc&provider=github HTTP/1.1";
const LIST_ACME_RUNNER_CONNECTION_AUTHORIZATIONS: &str = "GET /api/v1/organizations/acme/connection-authorizations?limit=200&projectId=prj_01k0z6r1w8f4jy2m7q9v3x5abc&runnerId=rnr_01k0z6r1w8f4jy2m7q9v3x5abc&provider=github&connectionId=ghi_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1";
const END_ACME_CONNECTION_AUTHORIZATION: &str = "DELETE /api/v1/organizations/acme/connection-authorizations/cna_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1";
const LIST_RUNNERS_OF_ACME: &str =
    "GET /api/v1/organizations/acme/runner-registrations?limit=200 HTTP/1.1";
const READ_ACME: &str = "GET /api/v1/organizations/acme HTTP/1.1";

/// Runs `useful org integration args --org acme`, whose output carries no token.
fn org(server: &ScriptedServer, credential: &Path, args: &[&str]) -> Output {
    run_with_input(server, credential, args, b"")
}

/// Runs `useful org integration args --org acme` with `input` on standard input, which is no
/// terminal.
fn run_with_input(
    server: &ScriptedServer,
    credential: &Path,
    args: &[&str],
    input: &[u8],
) -> Output {
    let mut arguments = vec!["org", "integration"];
    arguments.extend_from_slice(args);
    arguments.extend(["--org", "acme", "--allow-insecure-http"]);
    let environment = deployment_environment_with_issuer(
        &server.api_url,
        &server.issuer,
        credential.to_str().unwrap(),
    );
    let output = run_with_stdin(&arguments, &environment, input);
    assert_no_secret_output(&output, &[SENTINEL, TOKEN, KNOWN_TOKEN]);
    output
}

/// The request lines of the server's requests, once it is finished.
fn sent(server: ScriptedServer) -> Vec<String> {
    server
        .finish()
        .iter()
        .map(|request| request.lines().next().unwrap().to_owned())
        .collect()
}

/// The body of `request`, as JSON.
fn body(request: &str) -> serde_json::Value {
    request_body(request)
}

/// The one JSON document of a command's standard output, on one line.
fn one_document(output: &Output) -> serde_json::Value {
    let text = String::from_utf8(output.stdout.clone()).unwrap();
    assert_eq!(text.trim_end().lines().count(), 1, "{text}");
    serde_json::from_str(&text).unwrap()
}

/// The answer of a deployment that serves GitHub and the token services `mergify` and
/// `buildkite` (REQ-GRANT-78).
fn serving_tokens() -> Vec<u8> {
    json_http_response(
        "200 OK",
        serde_json::json!({"items": [
            {"provider": "github", "kind": "oauth"},
            {"provider": "mergify", "kind": "token", "displayName": "Mergify"},
            {"provider": "buildkite", "kind": "token", "displayName": "Buildkite"}
        ]}),
    )
}

/// Acme's `mergify` token at `version`, authorized for charlie, carrying in a member no model
/// names what no answer may carry.
fn acme_mergify(version: i64) -> serde_json::Value {
    serde_json::json!({
        "id": TOKEN_ID,
        "provider": "mergify",
        "side": "org",
        "organizationId": ORGANIZATION_ID,
        "version": version,
        "connectedBy": PRINCIPAL_ID,
        "connectedAt": "2026-11-18T09:00:00Z",
        "createdAt": "2026-11-17T09:00:00Z",
        "authorizations": [{
            "id": "ita_01k0z6r1w8f4jy2m7q9v3x5abc",
            "runnerId": RUNNER_ID,
            "runnerName": "charlie",
            "organizationId": ORGANIZATION_ID,
            "createdAt": "2026-11-18T09:05:00Z"
        }],
        "token": SENTINEL
    })
}

/// Acme's `buildkite` token, which another member connected.
fn acme_buildkite() -> serde_json::Value {
    serde_json::json!({
        "id": BUILDKITE_TOKEN_ID,
        "provider": "buildkite",
        "side": "org",
        "organizationId": ORGANIZATION_ID,
        "version": 2,
        "connectedBy": OTHER_PRINCIPAL_ID,
        "connectedAt": "2026-11-16T09:00:00Z",
        "createdAt": "2026-11-15T09:00:00Z",
        "authorizations": [],
        "token": SENTINEL
    })
}

fn tokens(items: &[serde_json::Value]) -> Vec<u8> {
    json_http_response("200 OK", serde_json::json!({"items": items}))
}

/// The answer to a store of acme's `mergify` token, which echoes the request's key.
fn stored(status: &str, version: i64) -> Vec<u8> {
    http_response_with_headers(
        status,
        Some("application/json"),
        &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
        &serde_json::to_vec(&acme_mergify(version)).unwrap(),
    )
}

/// Acme's directory: the member who connected its Buildkite token.
fn directory() -> Vec<u8> {
    json_http_response(
        "200 OK",
        serde_json::json!({"items": [{
            "id": "mem_01k0z6r1w8f4jy2m7q9v3x5abd",
            "principalId": OTHER_PRINCIPAL_ID,
            "principalType": "human",
            "principalState": "active",
            "displayName": OTHER_PRINCIPAL_NAME,
            "state": "active",
            "role": "member"
        }]}),
    )
}

/// The authorization Cloud makes of a token for `runner_id`, which echoes the request's key.
fn token_authorized(runner_id: &str) -> Vec<u8> {
    http_response_with_headers(
        "201 Created",
        Some("application/json"),
        &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
        &serde_json::to_vec(&serde_json::json!({
            "id": NEW_AUTHORIZATION_ID,
            "runnerId": runner_id,
            "runnerName": "bravo",
            "organizationId": ORGANIZATION_ID,
            "createdAt": "2026-11-18T10:00:00Z"
        }))
        .unwrap(),
    )
}

// REQ-INTEGRATION-16
// REQ-INTEGRATION-17
// REQ-INTEGRATION-18
// REQ-INTEGRATION-60
#[test]
fn connect_stores_the_organizations_token_and_reconnect_stores_its_next_version() {
    let directory = tempfile::tempdir().unwrap();
    let file = private_file(directory.path(), "mergify.token", KNOWN_TOKEN.as_bytes());
    let file = file.to_str().unwrap();

    let (server, _credentials, credential) = prepared(vec![
        serving_tokens(),
        tokens(&[]),
        stored("201 Created", 1),
    ]);
    let connected = org(
        &server,
        &credential,
        &["connect", "mergify", "--from-file", file, "--json"],
    );
    let requests = server.finish();
    assert_eq!(connected.status.code(), Some(0), "{}", stderr(&connected));
    assert_eq!(
        requests
            .iter()
            .map(|request| request.lines().next().unwrap())
            .collect::<Vec<_>>(),
        [READ_SERVED, LIST_ACME_TOKENS, STORE_ACME_TOKEN]
    );
    assert_eq!(
        body(&requests[2]),
        serde_json::json!({"provider": "mergify", "token": KNOWN_TOKEN})
    );
    let document = one_document(&connected);
    assert_eq!(document["outcome"], "connected", "{document}");
    assert_eq!(document["token"]["side"], "org", "{document}");
    assert_eq!(
        document["token"]["organization"],
        serde_json::json!({"id": ORGANIZATION_ID, "slug": "acme"}),
        "{document}"
    );

    // A member who is not an owner is refused by Cloud, and nothing is printed on standard
    // output.
    let (server, _credentials, credential) = prepared(vec![
        serving_tokens(),
        tokens(&[]),
        problem("403 Forbidden", 403, "forbidden"),
    ]);
    let forbidden = org(
        &server,
        &credential,
        &["connect", "mergify", "--from-file", file],
    );
    assert_eq!(
        sent(server),
        [READ_SERVED, LIST_ACME_TOKENS, STORE_ACME_TOKEN]
    );
    assert_eq!(forbidden.status.code(), Some(1));
    assert!(forbidden.stdout.is_empty());

    // A token the organization holds is refused before any token is read, naming `reconnect`.
    let (server, _credentials, credential) =
        prepared(vec![serving_tokens(), tokens(&[acme_mergify(1)])]);
    let held = run_with_input(
        &server,
        &credential,
        &["connect", "mergify"],
        KNOWN_TOKEN.as_bytes(),
    );
    assert_eq!(sent(server), [READ_SERVED, LIST_ACME_TOKENS]);
    assert_eq!(held.status.code(), Some(2));
    assert!(held.stdout.is_empty());
    assert!(
        stderr(&held).contains("useful org integration reconnect mergify"),
        "{}",
        stderr(&held)
    );

    // `reconnect` stores the next version, which keeps the record's ID.
    let (server, _credentials, credential) = prepared(vec![
        serving_tokens(),
        tokens(&[acme_mergify(1)]),
        stored("200 OK", 2),
    ]);
    let replaced = org(
        &server,
        &credential,
        &["reconnect", "mergify", "--from-file", file, "--json"],
    );
    let requests = server.finish();
    assert_eq!(replaced.status.code(), Some(0), "{}", stderr(&replaced));
    assert_eq!(
        body(&requests[2]),
        serde_json::json!({"provider": "mergify", "token": KNOWN_TOKEN, "replace": true})
    );

    // `reconnect` makes no token: a service the organization holds none of is `connect`'s.
    let (server, _credentials, credential) = prepared(vec![
        serving_tokens(),
        tokens(&[]),
        serving_tokens(),
        tokens(&[]),
    ]);
    let not_held = org(
        &server,
        &credential,
        &["reconnect", "mergify", "--from-file", file, "--json"],
    );
    let not_held_human = org(
        &server,
        &credential,
        &["reconnect", "mergify", "--from-file", file],
    );
    assert_eq!(
        sent(server),
        [READ_SERVED, LIST_ACME_TOKENS, READ_SERVED, LIST_ACME_TOKENS]
    );
    assert_eq!(not_held.status.code(), Some(1), "{}", stderr(&not_held));
    assert_eq!(one_document(&not_held)["outcome"], "token_not_found");
    assert_eq!(not_held_human.status.code(), Some(1));
    assert!(
        stderr(&not_held_human).contains("useful org integration connect mergify"),
        "{}",
        stderr(&not_held_human)
    );
    let document = one_document(&replaced);
    assert_eq!(document["outcome"], "replaced", "{document}");
    assert_eq!(document["token"]["id"], TOKEN_ID, "{document}");
    assert_eq!(document["token"]["version"], 2, "{document}");

    // A name served as no token service is refused naming those that are, once the served read
    // is made; a connection's option and a token's are refused for the other before any request.
    let (server, _credentials, credential) = prepared(vec![serving_tokens()]);
    let unserved = org(&server, &credential, &["connect", "bitbucket"]);
    assert_eq!(sent(server), [READ_SERVED]);
    assert_eq!(unserved.status.code(), Some(2));
    for name in ["github", "mergify", "buildkite"] {
        assert!(
            stderr(&unserved).contains(name),
            "{name}: {}",
            stderr(&unserved)
        );
    }
    let (server, _credentials, credential) = prepared(vec![]);
    for args in [
        &["connect", "github", "--from-file", file][..],
        &["connect", "mergify", "--installation", "713"],
        &["connect", "codex"],
        &["reconnect", "mergify", "--timeout", "30s"],
        &["reconnect", INSTALLATION_ID, "--from-file", file],
    ] {
        let output = org(&server, &credential, args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    assert!(server.finish().is_empty());
}

// REQ-INTEGRATION-17
// REQ-INTEGRATION-20
// REQ-INTEGRATION-56
// REQ-INTEGRATION-57
// REQ-INTEGRATION-58
#[test]
fn each_leaf_acts_on_the_organizations_token_through_its_routes() {
    let held = || tokens(&[acme_mergify(1)]);
    let (server, _directory, credential) = prepared(vec![
        serving_tokens(),
        held(),
        deleted(),
        serving_tokens(),
        held(),
        token_authorized(NEW_RUNNER_ID),
        serving_tokens(),
        held(),
        deleted(),
        // No runner named: the organization's runners the token is not authorized for.
        serving_tokens(),
        held(),
        registrations(&[
            registration(ALPHA, "offline", "enabled"),
            registration(BRAVO, "online", "enabled"),
            registration(CHARLIE, "online", "enabled"),
        ]),
        // --all ranges over the organization's tokens alone.
        tokens(&[acme_buildkite()]),
        http_response_with_headers(
            "201 Created",
            Some("application/json"),
            &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
            &serde_json::to_vec(&serde_json::json!({
                "id": NEW_AUTHORIZATION_ID,
                "runnerId": NEW_RUNNER_ID,
                "runnerName": "bravo",
                "organizationId": ORGANIZATION_ID,
                "createdAt": "2026-11-18T10:00:00Z"
            }))
            .unwrap(),
        ),
        // The member's own token, whose statement is compared with the organization's.
        page(&[oauth_grant(OAUTH_GRANT_ID, "github", "active")], None),
        serving_tokens(),
        tokens(&[{
            let mut token = acme_mergify(1);
            token["side"] = "member".into();
            token.as_object_mut().unwrap().remove("organizationId");
            token
        }]),
        token_authorized(NEW_RUNNER_ID),
    ]);
    let revoked = org(
        &server,
        &credential,
        &["disconnect", "mergify", "--yes", "--json"],
    );
    let authorized_run = org(
        &server,
        &credential,
        &["authorize", "mergify", "--runner", NEW_RUNNER_ID, "--yes"],
    );
    let deauthorized = org(
        &server,
        &credential,
        &[
            "deauthorize",
            "mergify",
            "--runner",
            RUNNER_ID,
            "--yes",
            "--json",
        ],
    );
    let offered = org(&server, &credential, &["authorize", "mergify", "--json"]);
    let every = org(
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
    let member = run_grant(
        &server,
        &credential,
        &["authorize", "mergify", "--runner", NEW_RUNNER_ID, "--yes"],
    );
    // Without --yes and with --runner, refused before anything is sent.
    let refusal = org(
        &server,
        &credential,
        &["authorize", "mergify", "--runner", NEW_RUNNER_ID],
    );
    assert_eq!(
        sent(server),
        [
            READ_SERVED,
            LIST_ACME_TOKENS,
            REVOKE_ACME_TOKEN,
            READ_SERVED,
            LIST_ACME_TOKENS,
            AUTHORIZE_ACME_TOKEN,
            READ_SERVED,
            LIST_ACME_TOKENS,
            DEAUTHORIZE_ACME_TOKEN,
            READ_SERVED,
            LIST_ACME_TOKENS,
            LIST_ACME_RUNNERS,
            LIST_ACME_TOKENS,
            "POST /api/v1/organizations/acme/integration-tokens/itk_01k0z6r1w8f4jy2m7q9v3x5abd/authorizations HTTP/1.1",
            LIST_EVERY_KIND,
            READ_SERVED,
            LIST_MEMBER_TOKENS,
            AUTHORIZE_MEMBER_TOKEN,
        ]
    );
    assert_eq!(revoked.status.code(), Some(0), "{}", stderr(&revoked));
    let document = json_output(&revoked);
    assert_eq!(document["outcome"], "revoked", "{document}");
    assert_eq!(document["side"], "org", "{document}");
    assert_eq!(
        authorized_run.status.code(),
        Some(0),
        "{}",
        stderr(&authorized_run)
    );
    assert_eq!(
        deauthorized.status.code(),
        Some(0),
        "{}",
        stderr(&deauthorized)
    );
    let document = json_output(&deauthorized);
    assert_eq!(document["outcome"], "deauthorized", "{document}");
    assert_eq!(document["integrationTokenId"], TOKEN_ID, "{document}");

    // Given no runner, the organization's runners the token is not authorized for are named.
    assert_eq!(offered.status.code(), Some(2), "{}", stderr(&offered));
    let document = json_output(&offered);
    assert_eq!(document["outcome"], "runner_required", "{document}");
    assert_eq!(document["integrationTokenId"], TOKEN_ID, "{document}");
    let runners: Vec<_> = document["runners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|runner| runner["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(runners, [NEW_RUNNER_ID, ENDED_RUNNER_ID], "{document}");

    assert_eq!(every.status.code(), Some(0), "{}", stderr(&every));
    let document = json_output(&every);
    assert_eq!(document["grants"], serde_json::json!([]), "{document}");
    assert_eq!(
        document["tokens"][0]["integrationTokenId"], BUILDKITE_TOKEN_ID,
        "{document}"
    );
    assert_eq!(document["tokens"][0]["side"], "org", "{document}");
    assert_eq!(document["tokens"][0]["outcome"], "authorized", "{document}");
    assert_eq!(
        document["tokens"][0]["organizationId"], ORGANIZATION_ID,
        "{document}"
    );

    // Who can use the organization's token is stated before acting, as the refusal states it,
    // and is not who can use the member's.
    assert_eq!(refusal.status.code(), Some(2));
    assert!(refusal.stdout.is_empty());
    let org_statement = statement(&authorized_run, TOKEN_ID);
    let member_statement = statement(&member, TOKEN_ID);
    assert_stated_by_the_refusal(&org_statement, &stderr(&refusal));
    assert!(
        org_statement
            .iter()
            .all(|line| !member_statement.contains(line)),
        "{org_statement:?} {member_statement:?}"
    );
}

// REQ-INTEGRATION-17
// REQ-INTEGRATION-20
// REQ-INTEGRATION-81
#[test]
fn a_refusal_ends_the_leaf_and_a_token_the_organization_lacks_is_not_found() {
    let forbidden = || problem("403 Forbidden", 403, "forbidden");
    let (server, _directory, credential) = prepared(vec![
        serving_tokens(),
        forbidden(),
        serving_tokens(),
        forbidden(),
        serving_tokens(),
        forbidden(),
        forbidden(),
        serving_tokens(),
        tokens(&[acme_mergify(1)]),
        forbidden(),
        serving_tokens(),
        tokens(&[]),
        // A name that is no token service the deployment serves is a usage error.
        serving_tokens(),
    ]);
    let refused = [
        org(&server, &credential, &["disconnect", "mergify", "--yes"]),
        org(
            &server,
            &credential,
            &["authorize", "mergify", "--runner", NEW_RUNNER_ID, "--yes"],
        ),
        org(
            &server,
            &credential,
            &["deauthorize", "mergify", "--runner", RUNNER_ID, "--yes"],
        ),
        org(
            &server,
            &credential,
            &["authorize", "--all", "--runner", NEW_RUNNER_ID, "--yes"],
        ),
        org(&server, &credential, &["disconnect", "mergify", "--yes"]),
    ];
    let missing = org(&server, &credential, &["show", "mergify", "--json"]);
    let typo = org(&server, &credential, &["show", "gihub", "--json"]);
    assert_eq!(
        sent(server),
        [
            READ_SERVED,
            LIST_ACME_TOKENS,
            READ_SERVED,
            LIST_ACME_TOKENS,
            READ_SERVED,
            LIST_ACME_TOKENS,
            LIST_ACME_TOKENS,
            READ_SERVED,
            LIST_ACME_TOKENS,
            REVOKE_ACME_TOKEN,
            READ_SERVED,
            LIST_ACME_TOKENS,
            READ_SERVED,
        ]
    );
    assert_eq!(typo.status.code(), Some(2), "{}", stderr(&typo));
    assert!(typo.stdout.is_empty());
    for name in ["github", "gitlab", "linear", "mergify", "buildkite"] {
        assert!(stderr(&typo).contains(name), "{name}: {}", stderr(&typo));
    }
    for output in &refused {
        assert_eq!(output.status.code(), Some(1), "{}", stderr(output));
        assert!(output.stdout.is_empty(), "{}", stderr(output));
    }
    assert_eq!(missing.status.code(), Some(1), "{}", stderr(&missing));
    assert_eq!(json_output(&missing)["outcome"], "token_not_found");
}

/// One page of acme's GitHub App installations in `states`, the first on the account `acme` and
/// the second, where there is one, on `globex`.
fn installations_in(states: &[&str]) -> Vec<u8> {
    let items: Vec<_> = states
        .iter()
        .zip([(INSTALLATION_ID, "acme"), (OTHER_INSTALLATION_ID, "globex")])
        .map(|(state, (id, account))| {
            let mut item = super::github::installation_body(state);
            item["id"] = id.into();
            item["providerAccountLogin"] = account.into();
            item
        })
        .collect();
    json_http_response("200 OK", serde_json::json!({"items": items}))
}

/// The authorization Cloud answers of `runner_id` for acme's `provider` connection
/// `connection_id` in the project, with the installation's scope, carrying in members no model
/// names what no output may carry.
fn connection_authorization(
    runner_id: &str,
    provider: &str,
    connection_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": CONNECTION_AUTHORIZATION_ID,
        "organizationId": ORGANIZATION_ID,
        "provider": provider,
        "projectId": PROJECT_ID,
        "projectName": "Website",
        "runnerId": runner_id,
        "runnerName": "bravo",
        "connectionId": connection_id,
        "connectionAccount": "acme",
        "authorizedBy": PRINCIPAL_ID,
        "createdAt": "2026-11-19T09:00:00Z",
        "scope": {
            "state": "current",
            "github": {
                "repositorySelection": "selected",
                "permissions": [
                    {"name": "contents", "access": "write"},
                    {"name": "metadata", "access": "read"}
                ],
                "token": SENTINEL
            }
        },
        "token": SENTINEL
    })
}

/// The 201 that makes [`connection_authorization`], which echoes the request's key.
fn connection_authorized(runner_id: &str, connection_id: &str) -> Vec<u8> {
    http_response_with_headers(
        "201 Created",
        Some("application/json"),
        &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
        &serde_json::to_vec(&connection_authorization(
            runner_id,
            "github",
            connection_id,
        ))
        .unwrap(),
    )
}

/// One page of acme's connection authorizations in force: `runner_id`'s for its installation.
fn project_authorizations(runner_id: &str) -> Vec<u8> {
    json_http_response(
        "200 OK",
        serde_json::json!({"items": [connection_authorization(
            runner_id,
            "github",
            INSTALLATION_ID
        )]}),
    )
}

fn no_authorizations() -> Vec<u8> {
    json_http_response("200 OK", serde_json::json!({"items": []}))
}

/// Runs `useful org integration LEAF args --project PROJECT --org acme`.
fn in_project(leaf: &str, server: &ScriptedServer, credential: &Path, args: &[&str]) -> Output {
    org(
        server,
        credential,
        &[&[leaf], args, &["--project", PROJECT_ID]].concat(),
    )
}

// REQ-INTEGRATION-19
// REQ-INTEGRATION-22
// REQ-INTEGRATION-34
// REQ-INTEGRATION-32
// REQ-INTEGRATION-54
// REQ-INTEGRATION-55
// REQ-INTEGRATION-78
// REQ-INTEGRATION-79
#[test]
fn list_prints_each_connections_authorizations_and_then_the_organizations_tokens() {
    let answers = || {
        vec![
            installations_in(&["active"]),
            json_http_response(
                "200 OK",
                serde_json::json!({"items": [], "nextCursor": null}),
            ),
            json_http_response("200 OK", serde_json::json!({"items": []})),
            project_authorizations(RUNNER_ID),
            serving_tokens(),
            tokens(&[acme_buildkite()]),
            directory(),
        ]
    };
    let (server, _directory, credential) = prepared([answers(), answers()].concat());
    let listed = org(&server, &credential, &["list", "--json"]);
    let human = org(&server, &credential, &["list"]);
    let expected = [
        LIST_ACME_INSTALLATIONS,
        LIST_ACME_GITLAB,
        LIST_ACME_LINEAR,
        LIST_ACME_AUTHORIZATIONS,
        READ_SERVED,
        LIST_ACME_TOKENS,
        READ_ACME_DIRECTORY,
    ];
    assert_eq!(sent(server), [expected, expected].concat());

    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    let document = one_document(&listed);
    // The connection list keeps its own members (REQ-CONNECTION-104).
    assert_eq!(document["unlisted"], serde_json::json!([]), "{document}");
    let item = &document["items"][0];
    assert_eq!(item["id"], INSTALLATION_ID, "{document}");
    let authorization = &item["authorizations"][0];
    assert_eq!(authorization["id"], CONNECTION_AUTHORIZATION_ID, "{item}");
    assert_eq!(authorization["projectId"], PROJECT_ID, "{item}");
    assert_eq!(authorization["runnerId"], RUNNER_ID, "{item}");
    assert_eq!(
        authorization["scope"]["github"]["repositorySelection"],
        "selected"
    );
    let token = &document["tokens"][0];
    assert_eq!(token["id"], BUILDKITE_TOKEN_ID, "{document}");
    assert_eq!(token["side"], "org", "{document}");
    assert_eq!(token["connectedByName"], OTHER_PRINCIPAL_NAME, "{document}");
    assert_eq!(token["organization"]["slug"], "acme", "{document}");

    // The report prints the authorization under its connection and then the token.
    assert_eq!(human.status.code(), Some(0), "{}", stderr(&human));
    let text = String::from_utf8(human.stdout).unwrap();
    let at = |needle: &str| {
        text.lines()
            .position(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("{needle} not in\n{text}"))
    };
    assert!(
        at(INSTALLATION_ID) < at(CONNECTION_AUTHORIZATION_ID),
        "{text}"
    );
    assert!(
        at(CONNECTION_AUTHORIZATION_ID) < at(BUILDKITE_TOKEN_ID),
        "{text}"
    );
    assert!(text.contains(&format!("{OTHER_PRINCIPAL_NAME} ({OTHER_PRINCIPAL_ID})")));

    // An authorizations read Cloud refuses is passed over, and the connections carry none.
    let (server, _directory, credential) = prepared(vec![
        installations_in(&["active"]),
        json_http_response(
            "200 OK",
            serde_json::json!({"items": [], "nextCursor": null}),
        ),
        json_http_response("200 OK", serde_json::json!({"items": []})),
        problem("403 Forbidden", 403, "forbidden"),
        serving_tokens(),
        tokens(&[]),
    ]);
    let passed_over = org(&server, &credential, &["list", "--json"]);
    server.finish();
    assert_eq!(
        passed_over.status.code(),
        Some(0),
        "{}",
        stderr(&passed_over)
    );
    let document = one_document(&passed_over);
    assert!(
        document["items"][0].get("authorizations").is_none(),
        "{document}"
    );
    assert_eq!(document["tokens"], serde_json::json!([]));
}

// REQ-INTEGRATION-19
// REQ-INTEGRATION-34
// REQ-INTEGRATION-54
// REQ-INTEGRATION-65
#[test]
fn show_shows_the_organizations_token_or_a_connection_with_its_authorizations() {
    let (server, _directory, credential) = prepared(vec![
        serving_tokens(),
        tokens(&[acme_mergify(1), acme_buildkite()]),
        directory(),
    ]);
    let shown = org(&server, &credential, &["show", "buildkite", "--json"]);
    assert_eq!(
        sent(server),
        [READ_SERVED, LIST_ACME_TOKENS, READ_ACME_DIRECTORY]
    );
    assert_eq!(shown.status.code(), Some(0), "{}", stderr(&shown));
    let document = json_output(&shown);
    assert_eq!(document["outcome"], "shown", "{document}");
    assert_eq!(document["token"]["id"], BUILDKITE_TOKEN_ID, "{document}");
    assert_eq!(
        document["token"]["connectedByName"], OTHER_PRINCIPAL_NAME,
        "{document}"
    );

    let mut linear = connection_authorization(RUNNER_ID, "linear", LINEAR_CONNECTION_ID);
    linear["scope"] = serde_json::json!({"state": "unavailable"});
    let (server, _directory, credential) = prepared(vec![
        json_http_response("200 OK", serde_json::json!({"items": [linear]})),
        json_http_response("200 OK", super::connection::connection()),
    ]);
    let connection = org(
        &server,
        &credential,
        &["show", LINEAR_CONNECTION_ID, "--json"],
    );
    assert_eq!(
        sent(server),
        [
            "GET /api/v1/organizations/acme/connection-authorizations?limit=200&connectionId=lcn_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1",
            "GET /api/v1/organizations/acme/connections/linear/lcn_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1",
        ]
    );
    assert_eq!(connection.status.code(), Some(0), "{}", stderr(&connection));
    let document = one_document(&connection);
    assert_eq!(document["connectionId"], LINEAR_CONNECTION_ID, "{document}");
    assert_eq!(
        document["authorizations"][0]["id"], CONNECTION_AUTHORIZATION_ID,
        "{document}"
    );
    assert_eq!(
        document["authorizations"][0]["scope"],
        serde_json::json!({"state": "unavailable"})
    );
}

// REQ-INTEGRATION-33
// REQ-INTEGRATION-27
// REQ-INTEGRATION-32
// REQ-INTEGRATION-24
#[test]
fn authorize_with_a_project_authorizes_the_runner_for_the_organizations_active_connection() {
    let (server, _directory, credential) = prepared(vec![
        installations_in(&["active"]),
        connection_authorized(NEW_RUNNER_ID, INSTALLATION_ID),
        installations_in(&["active"]),
        connection_authorized(NEW_RUNNER_ID, INSTALLATION_ID),
    ]);
    let json = in_project(
        "authorize",
        &server,
        &credential,
        &["github", "--runner", NEW_RUNNER_ID, "--yes", "--json"],
    );
    let human = in_project(
        "authorize",
        &server,
        &credential,
        &["github", "--runner", NEW_RUNNER_ID, "--yes"],
    );
    // Without --yes each is refused before anything is sent.
    let refusal = in_project(
        "authorize",
        &server,
        &credential,
        &["github", "--runner", NEW_RUNNER_ID],
    );
    let token_refusal = org(
        &server,
        &credential,
        &["authorize", "mergify", "--runner", NEW_RUNNER_ID],
    );
    let requests = server.finish();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.lines().next().unwrap())
            .collect::<Vec<_>>(),
        [
            LIST_ACME_INSTALLATIONS,
            AUTHORIZE_ACME_CONNECTION,
            LIST_ACME_INSTALLATIONS,
            AUTHORIZE_ACME_CONNECTION,
        ]
    );
    for request in [&requests[1], &requests[3]] {
        assert!(!header_value(request, "idempotency-key").is_empty());
        assert_eq!(
            body(request),
            serde_json::json!({
                "projectId": PROJECT_ID,
                "runnerId": NEW_RUNNER_ID,
                "provider": "github",
                "connectionId": INSTALLATION_ID
            })
        );
    }

    assert_eq!(json.status.code(), Some(0), "{}", stderr(&json));
    let document = json_output(&json);
    assert_eq!(document["outcome"], "authorized", "{document}");
    assert_eq!(
        document["authorization"],
        serde_json::json!({
            "id": CONNECTION_AUTHORIZATION_ID,
            "provider": "github",
            "projectId": PROJECT_ID,
            "projectName": "Website",
            "runnerId": NEW_RUNNER_ID,
            "runnerName": "bravo",
            "connectionId": INSTALLATION_ID,
            "connectionAccount": "acme",
            "authorizedBy": PRINCIPAL_ID,
            "createdAt": "2026-11-19T09:00:00Z",
            "scope": {
                "state": "current",
                "github": {
                    "repositorySelection": "selected",
                    "permissions": [
                        {"name": "contents", "access": "write"},
                        {"name": "metadata", "access": "read"}
                    ]
                }
            }
        })
    );
    assert_eq!(human.status.code(), Some(0), "{}", stderr(&human));
    let report = String::from_utf8(human.stdout.clone()).unwrap();
    for field in [
        CONNECTION_AUTHORIZATION_ID,
        PROJECT_ID,
        INSTALLATION_ID,
        "contents",
    ] {
        assert_eq!(
            report.lines().filter(|line| line.contains(field)).count(),
            1,
            "{field} not on one line of\n{report}"
        );
    }

    // What the authorization permits is stated before acting, as the refusal states it, and
    // none of it is a token's statement.
    assert_eq!(refusal.status.code(), Some(2));
    let stated = statement(&json, INSTALLATION_ID);
    assert_eq!(stated, statement(&human, INSTALLATION_ID));
    assert_stated_by_the_refusal(&stated, &stderr(&refusal));
    let token_statement: Vec<_> = stderr(&token_refusal)
        .lines()
        .filter(|line| line.contains("for the organization's token, "))
        .map(str::to_owned)
        .collect();
    assert!(!token_statement.is_empty(), "{}", stderr(&token_refusal));
    assert!(
        stated.iter().all(|line| !token_statement
            .iter()
            .any(|token| token.ends_with(line.as_str()))),
        "{stated:?} {token_statement:?}"
    );
}

// REQ-INTEGRATION-33
// REQ-INTEGRATION-71
#[test]
fn authorize_with_a_project_takes_the_one_active_connection_or_the_one_named() {
    let (server, _directory, credential) = prepared(vec![
        installations_in(&["active", "active"]),
        installations_in(&["active", "active"]),
        installations_in(&["active", "active"]),
        connection_authorized(NEW_RUNNER_ID, OTHER_INSTALLATION_ID),
        installations_in(&["disconnected"]),
        installations_in(&["disconnected"]),
    ]);
    let several = in_project(
        "authorize",
        &server,
        &credential,
        &["github", "--runner", NEW_RUNNER_ID, "--yes", "--json"],
    );
    let several_human = in_project(
        "authorize",
        &server,
        &credential,
        &["github", "--runner", NEW_RUNNER_ID, "--yes"],
    );
    let named = in_project(
        "authorize",
        &server,
        &credential,
        &[
            OTHER_INSTALLATION_ID,
            "--runner",
            NEW_RUNNER_ID,
            "--yes",
            "--json",
        ],
    );
    let none_active = in_project(
        "authorize",
        &server,
        &credential,
        &["github", "--runner", NEW_RUNNER_ID, "--yes", "--json"],
    );
    let none_active_human = in_project(
        "authorize",
        &server,
        &credential,
        &["github", "--runner", NEW_RUNNER_ID, "--yes"],
    );
    let requests = server.finish();
    assert_eq!(body(&requests[3])["connectionId"], OTHER_INSTALLATION_ID);

    assert_eq!(several.status.code(), Some(2), "{}", stderr(&several));
    let document = json_output(&several);
    assert_eq!(document["outcome"], "connection_required", "{document}");
    assert_eq!(
        document["connections"],
        serde_json::json!([
            {"id": INSTALLATION_ID, "account": "acme"},
            {"id": OTHER_INSTALLATION_ID, "account": "globex"}
        ])
    );
    assert_eq!(several_human.status.code(), Some(2));
    assert!(several_human.stdout.is_empty());
    for named in [INSTALLATION_ID, OTHER_INSTALLATION_ID, "globex"] {
        assert!(stderr(&several_human).contains(named), "{named}");
    }

    assert_eq!(named.status.code(), Some(0), "{}", stderr(&named));
    assert_eq!(
        json_output(&named)["authorization"]["connectionId"],
        OTHER_INSTALLATION_ID
    );

    assert_eq!(
        none_active.status.code(),
        Some(1),
        "{}",
        stderr(&none_active)
    );
    assert_eq!(json_output(&none_active)["outcome"], "connection_not_found");
    assert_eq!(none_active_human.status.code(), Some(1));
    assert!(
        stderr(&none_active_human).contains("useful org integration connect github"),
        "{}",
        stderr(&none_active_human)
    );
}

// REQ-INTEGRATION-33
// REQ-GRANT-81
// REQ-INTEGRATION-72
#[test]
fn authorize_with_a_project_given_no_runner_names_those_without_an_authorization_there() {
    // Charlie holds the project's authorization, so bravo and alpha are named.
    let (server, _directory, credential) = prepared(vec![
        installations_in(&["active"]),
        project_authorizations(RUNNER_ID),
        registrations(&[
            registration(ALPHA, "offline", "enabled"),
            registration(BRAVO, "online", "enabled"),
            registration(CHARLIE, "online", "enabled"),
        ]),
    ]);
    let refused = in_project("authorize", &server, &credential, &["github", "--json"]);
    assert_eq!(
        sent(server),
        [
            LIST_ACME_INSTALLATIONS,
            LIST_ACME_PROJECT_AUTHORIZATIONS,
            LIST_RUNNERS_OF_ACME,
        ]
    );
    assert_eq!(refused.status.code(), Some(2), "{}", stderr(&refused));
    let document = json_output(&refused);
    assert_eq!(document["outcome"], "runner_required", "{document}");
    assert_eq!(document["connectionId"], INSTALLATION_ID, "{document}");
    let runners: Vec<_> = document["runners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|runner| runner["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(runners, [NEW_RUNNER_ID, ENDED_RUNNER_ID], "{document}");
}

// REQ-INTEGRATION-33
// REQ-INTEGRATION-27
// REQ-INTEGRATION-73
// REQ-INTEGRATION-77
#[test]
fn authorize_with_a_project_reports_each_of_clouds_refusals_with_its_own_outcome() {
    let refusals = [
        ("403 Forbidden", 403, "forbidden", "forbidden"),
        (
            "404 Not Found",
            404,
            "connection-authorization-project-not-found",
            "project_not_found",
        ),
        (
            "404 Not Found",
            404,
            "connection-authorization-runner-not-found",
            "runner_not_found",
        ),
        (
            "404 Not Found",
            404,
            "connection-authorization-connection-not-found",
            "connection_not_found",
        ),
        (
            "409 Conflict",
            409,
            "connection-authorization-connection-inactive",
            "connection_inactive",
        ),
        (
            "409 Conflict",
            409,
            "connection-authorization-provider-ineligible",
            "provider_ineligible",
        ),
        (
            "409 Conflict",
            409,
            "connection-authorization-already-authorized",
            "already_authorized",
        ),
    ];
    for (status, code, slug, outcome) in refusals {
        let (server, _directory, credential) = prepared(vec![
            installations_in(&["active"]),
            problem(status, code, slug),
        ]);
        let json = in_project(
            "authorize",
            &server,
            &credential,
            &["github", "--runner", NEW_RUNNER_ID, "--yes", "--json"],
        );
        assert_eq!(
            sent(server),
            [LIST_ACME_INSTALLATIONS, AUTHORIZE_ACME_CONNECTION],
            "{outcome}"
        );
        assert_eq!(json.status.code(), Some(1), "{outcome}: {}", stderr(&json));
        assert_eq!(json_output(&json)["outcome"], outcome);
    }

    // The generic not-found of a deployment that routes no connection authorization is told
    // from an organization the member cannot read by one read of the organization.
    for (organization_read, outcome) in [
        (organization(), "connection_authorizations_not_served"),
        (
            problem("404 Not Found", 404, "not-found"),
            "organization_not_found",
        ),
    ] {
        let (server, _directory, credential) = prepared(vec![
            installations_in(&["active"]),
            problem("404 Not Found", 404, "not-found"),
            organization_read,
        ]);
        let output = in_project(
            "authorize",
            &server,
            &credential,
            &["github", "--runner", NEW_RUNNER_ID, "--yes", "--json"],
        );
        assert_eq!(
            sent(server),
            [
                LIST_ACME_INSTALLATIONS,
                AUTHORIZE_ACME_CONNECTION,
                READ_ACME
            ]
        );
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert_eq!(json_output(&output)["outcome"], outcome);
    }
}

// REQ-INTEGRATION-33
// REQ-INTEGRATION-76
#[test]
fn project_is_required_for_a_connection_and_refused_for_a_token_before_any_request() {
    let (server, _directory, credential) = prepared(vec![]);
    for args in [
        &["authorize", "github", "--runner", NEW_RUNNER_ID, "--yes"][..],
        &[
            "deauthorize",
            INSTALLATION_ID,
            "--runner",
            RUNNER_ID,
            "--yes",
        ],
        &[
            "authorize",
            "mergify",
            "--runner",
            NEW_RUNNER_ID,
            "--project",
            PROJECT_ID,
            "--yes",
        ],
        &[
            "authorize",
            "--all",
            "--runner",
            NEW_RUNNER_ID,
            "--project",
            PROJECT_ID,
            "--yes",
        ],
        &[
            "authorize",
            "mergify",
            "--all",
            "--runner",
            NEW_RUNNER_ID,
            "--yes",
        ],
    ] {
        let output = org(&server, &credential, args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&output)
        );
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    assert!(server.finish().is_empty());
}

// REQ-INTEGRATION-33
#[test]
fn project_is_named_by_its_exact_name_among_the_organizations_projects() {
    let project = serde_json::json!({
        "id": PROJECT_ID,
        "organizationId": ORGANIZATION_ID,
        "name": "website",
        "runnerPool": null,
        "repository": null,
        "executionReadiness": {"ready": false, "blockers": ["runner_pool_unassigned", "repository_detached"]},
        "createdAt": "2026-09-05T12:00:00Z",
        "updatedAt": "2026-09-05T12:01:00Z"
    });
    let projects = || json_http_response("200 OK", serde_json::json!({"items": [project.clone()]}));
    let (server, _directory, credential) = prepared(vec![
        projects(),
        installations_in(&["active"]),
        connection_authorized(NEW_RUNNER_ID, INSTALLATION_ID),
        projects(),
    ]);
    let named = org(
        &server,
        &credential,
        &[
            "authorize",
            "github",
            "--runner",
            NEW_RUNNER_ID,
            "--project",
            "website",
            "--yes",
            "--json",
        ],
    );
    let unknown = org(
        &server,
        &credential,
        &[
            "authorize",
            "github",
            "--runner",
            NEW_RUNNER_ID,
            "--project",
            "docs",
            "--yes",
            "--json",
        ],
    );
    let requests = server.finish();
    assert!(
        requests[0].starts_with("GET /api/v1/organizations/acme/projects"),
        "{}",
        requests[0]
    );
    assert_eq!(named.status.code(), Some(0), "{}", stderr(&named));
    assert_eq!(body(&requests[2])["projectId"], PROJECT_ID);
    assert_eq!(unknown.status.code(), Some(1), "{}", stderr(&unknown));
    assert_eq!(json_output(&unknown)["outcome"], "project_not_found");
    assert_eq!(requests.len(), 4);
}

// REQ-INTEGRATION-33
// REQ-INTEGRATION-29
// REQ-INTEGRATION-74
#[test]
fn deauthorize_with_a_project_ends_the_runners_authorization_found_in_the_organizations_list() {
    let (server, _directory, credential) = prepared(vec![
        project_authorizations(RUNNER_ID),
        deleted(),
        project_authorizations(RUNNER_ID),
        deleted(),
        // Repeated, the list holds none.
        no_authorizations(),
        // Ended meanwhile: the route answers the authorization not found.
        project_authorizations(RUNNER_ID),
        problem("404 Not Found", 404, "connection-authorization-not-found"),
        // A connection named by its ID keeps that connection's alone.
        project_authorizations(RUNNER_ID),
        deleted(),
    ]);
    let deauthorize = |args: &[&str]| in_project("deauthorize", &server, &credential, args);
    let json = deauthorize(&["github", "--runner", RUNNER_ID, "--yes", "--json"]);
    let human = deauthorize(&["github", "--runner", RUNNER_ID, "--yes"]);
    let repeated = deauthorize(&["github", "--runner", RUNNER_ID, "--yes", "--json"]);
    let ended = deauthorize(&["github", "--runner", RUNNER_ID, "--yes", "--json"]);
    let named = deauthorize(&[INSTALLATION_ID, "--runner", RUNNER_ID, "--yes", "--json"]);
    let refusal = deauthorize(&["github", "--runner", RUNNER_ID]);
    assert_eq!(
        sent(server),
        [
            LIST_ACME_RUNNER_AUTHORIZATIONS,
            END_ACME_CONNECTION_AUTHORIZATION,
            LIST_ACME_RUNNER_AUTHORIZATIONS,
            END_ACME_CONNECTION_AUTHORIZATION,
            LIST_ACME_RUNNER_AUTHORIZATIONS,
            LIST_ACME_RUNNER_AUTHORIZATIONS,
            END_ACME_CONNECTION_AUTHORIZATION,
            LIST_ACME_RUNNER_CONNECTION_AUTHORIZATIONS,
            END_ACME_CONNECTION_AUTHORIZATION,
        ]
    );

    assert_eq!(json.status.code(), Some(0), "{}", stderr(&json));
    let document = json_output(&json);
    assert_eq!(document["outcome"], "deauthorized", "{document}");
    assert_eq!(
        document["authorization"],
        serde_json::json!({
            "id": CONNECTION_AUTHORIZATION_ID,
            "provider": "github",
            "projectId": PROJECT_ID,
            "projectName": "Website",
            "runnerId": RUNNER_ID,
            "runnerName": "bravo",
            "connectionId": INSTALLATION_ID,
            "connectionAccount": "acme"
        })
    );
    assert_eq!(human.status.code(), Some(0), "{}", stderr(&human));
    assert_eq!(named.status.code(), Some(0), "{}", stderr(&named));
    for output in [&repeated, &ended] {
        assert_eq!(output.status.code(), Some(1), "{}", stderr(output));
        assert_eq!(json_output(output)["outcome"], "authorization_not_found");
    }
    assert_eq!(refusal.status.code(), Some(2));
    let stated = statement(&json, INSTALLATION_ID);
    assert_stated_by_the_refusal(&stated, &stderr(&refusal));
}

// REQ-INTEGRATION-33
// REQ-GRANT-81
// REQ-INTEGRATION-75
#[test]
fn deauthorize_with_a_project_given_no_runner_names_those_that_hold_an_authorization_there() {
    let mut unregistered = connection_authorization(ENDED_RUNNER_ID, "github", INSTALLATION_ID);
    unregistered["id"] = "cna_01k0z6r1w8f4jy2m7q9v3x5abd".into();
    let held = json_http_response(
        "200 OK",
        serde_json::json!({"items": [
            connection_authorization(RUNNER_ID, "github", INSTALLATION_ID),
            unregistered
        ]}),
    );
    let (server, _directory, credential) = prepared(vec![
        held,
        registrations(&[
            registration(BRAVO, "online", "enabled"),
            registration(CHARLIE, "online", "enabled"),
        ]),
        no_authorizations(),
        problem("403 Forbidden", 403, "forbidden"),
    ]);
    let refused = in_project("deauthorize", &server, &credential, &["github", "--json"]);
    let none = in_project("deauthorize", &server, &credential, &["github", "--json"]);
    let forbidden = in_project("deauthorize", &server, &credential, &["github", "--json"]);
    assert_eq!(
        sent(server),
        [
            LIST_ACME_PROJECT_AUTHORIZATIONS,
            LIST_ACME_RUNNERS,
            LIST_ACME_PROJECT_AUTHORIZATIONS,
            LIST_ACME_PROJECT_AUTHORIZATIONS,
        ]
    );
    assert_eq!(refused.status.code(), Some(2), "{}", stderr(&refused));
    let document = json_output(&refused);
    assert_eq!(document["outcome"], "runner_required", "{document}");
    assert_eq!(document["connectionId"], INSTALLATION_ID, "{document}");
    let runners: Vec<_> = document["runners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|runner| runner["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(runners, [RUNNER_ID, ENDED_RUNNER_ID], "{document}");
    assert_eq!(none.status.code(), Some(1), "{}", stderr(&none));
    assert_eq!(json_output(&none)["outcome"], "authorization_not_found");
    assert_eq!(forbidden.status.code(), Some(1), "{}", stderr(&forbidden));
    assert_eq!(json_output(&forbidden)["outcome"], "forbidden");
}
