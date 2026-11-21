//! `useful account integration` acting on the member's token of a token service
//! (REQ-INTEGRATION-16 to REQ-INTEGRATION-20): `connect` and `reconnect` read it from a file,
//! standard input or a prompt that does not echo, and `list`, `show`, `authorize`,
//! `deauthorize` and `disconnect` find it by its service once no grant of that name is found. The
//! grant cases are in `grant`, whose helpers these share.

use super::*;

use super::grant::{
    ALPHA, BRAVO, CHARLIE, ENDED_RUNNER_ID, LIST_ACME_RUNNERS, LIST_EVERY_KIND, LIST_FIRST_PAGE,
    LIST_MEMBERSHIPS, LIST_OAUTH, NEW_RUNNER_ID, OAUTH_GRANT_ID, ORGANIZATION_ID, Opener, Place,
    READ_IDENTITIES, READ_SERVED, RUNNER_ID, SENTINEL, START_CONSENT, TOKEN, ada,
    assert_stated_by_the_refusal, authorized, consent_of, deleted, holding, identities,
    json_output, memberships, named_runners, nothing_held, oauth_grant, oauth_grant_unauthorized,
    offered, on_terminal, opener_command, page, predating_served, prepared, private_file, problem,
    registration, registrations, request_body, run_grant, statement, stderr,
};

/// The token the member gives in these cases, which no output may carry.
const KNOWN_TOKEN: &str = "mergify-known-token-7f3a9c";
const TOKEN_ID: &str = "itk_01k0z6r1w8f4jy2m7q9v3x5abc";
const PRINCIPAL_ID: &str = "prn_01k0z6r1w8f4jy2m7q9v3x5abc";
const RUNNER_NAME: &str = "build-1";
const LIST_MEMBER_TOKENS: &str = "GET /api/v1/me/integration-tokens?limit=200 HTTP/1.1";
const STORE_MEMBER_TOKEN: &str = "POST /api/v1/me/integration-tokens HTTP/1.1";
const REVOKE_MEMBER_TOKEN: &str =
    "DELETE /api/v1/me/integration-tokens/itk_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1";
const AUTHORIZE_MEMBER_TOKEN: &str =
    "POST /api/v1/me/integration-tokens/itk_01k0z6r1w8f4jy2m7q9v3x5abc/authorizations HTTP/1.1";
const DEAUTHORIZE_MEMBER_TOKEN: &str = "DELETE /api/v1/me/integration-tokens/itk_01k0z6r1w8f4jy2m7q9v3x5abc/authorizations/ita_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1";
const REVOKE_GITHUB: &str = "DELETE /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc HTTP/1.1";
const AUTHORIZE_GITHUB: &str =
    "POST /api/v1/me/grants/pgr_01k0z6r1w8f4jy2m7q9v3x5abc/authorizations HTTP/1.1";
/// The authorization Cloud makes of a token for a runner.
const NEW_AUTHORIZATION_ID: &str = "ita_01k0z6r1w8f4jy2m7q9v3x5abf";
/// What the prompt for a token shows.
const HIDDEN: &str = "(input is hidden)";

/// Runs `useful account integration args`, whose output carries no token.
fn run(server: &ScriptedServer, credential: &Path, args: &[&str]) -> Output {
    let output = run_grant(server, credential, args);
    assert_no_secret_output(&output, &[KNOWN_TOKEN]);
    output
}

/// Runs `useful account integration args` with `input` on standard input, which is no terminal,
/// and `variables` set besides the deployment's.
fn run_with_input(
    server: &ScriptedServer,
    credential: &Path,
    args: &[&str],
    input: &[u8],
    variables: &[(&str, &str)],
) -> Output {
    let mut arguments = vec!["account", "integration"];
    arguments.extend_from_slice(args);
    arguments.push("--allow-insecure-http");
    let mut environment = deployment_environment_with_issuer(
        &server.api_url,
        &server.issuer,
        credential.to_str().unwrap(),
    )
    .to_vec();
    environment.extend_from_slice(variables);
    let output = run_with_stdin(&arguments, &environment, input);
    assert_no_secret_output(&output, &[SENTINEL, TOKEN, KNOWN_TOKEN]);
    output
}

/// `useful account integration args`, for a pseudo-terminal to run.
fn on_a_terminal(server: &ScriptedServer, credential: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(crate::executable());
    command
        .args(["account", "integration"])
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

/// What each request asked: its request line and its body.
fn asked(requests: &[String]) -> Vec<(String, String)> {
    requests
        .iter()
        .map(|request| {
            let (head, body) = request.split_once("\r\n\r\n").unwrap_or((request, ""));
            (head.lines().next().unwrap().to_owned(), body.to_owned())
        })
        .collect()
}

/// The request lines of `requests`.
fn lines(requests: &[(String, String)]) -> Vec<&str> {
    requests.iter().map(|(line, _)| line.as_str()).collect()
}

/// The request lines of the server's requests, once it is finished.
fn sent(server: ScriptedServer) -> Vec<String> {
    lines(&asked(&server.finish()))
        .into_iter()
        .map(str::to_owned)
        .collect()
}

/// The one JSON document of a command's standard output, on one line.
fn one_document(output: &Output) -> serde_json::Value {
    let text = String::from_utf8(output.stdout.clone()).unwrap();
    assert_eq!(text.trim_end().lines().count(), 1, "{text}");
    serde_json::from_str(&text).unwrap()
}

/// Whether a human report names the token's ID and `version`, as its data fields do.
fn reports(output: &Output, version: i64) -> bool {
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .any(|line| line == format!("token: {TOKEN_ID}"))
        && text
            .lines()
            .any(|line| line == format!("version: {version}"))
}

/// The answer of a deployment that serves the five, the OAuth provider `example` and, with
/// `token`, `mergify` as a token service titled Mergify (REQ-GRANT-78).
fn serving_with(token: bool) -> Vec<u8> {
    let mut items = vec![
        serde_json::json!({"provider": "github", "kind": "oauth"}),
        serde_json::json!({"provider": "gitlab.com", "kind": "oauth"}),
        serde_json::json!({"provider": "linear", "kind": "oauth"}),
        serde_json::json!({"provider": "example", "kind": "oauth"}),
        serde_json::json!({"provider": "claude_code", "kind": "native"}),
        serde_json::json!({"provider": "codex", "kind": "native"}),
    ];
    if token {
        items.push(serde_json::json!({
            "provider": "mergify",
            "kind": "token",
            "displayName": "Mergify"
        }));
    }
    json_http_response("200 OK", serde_json::json!({"items": items}))
}

/// The member's `mergify` token at `version`, carrying in a member no model names what no
/// answer may carry.
fn mergify_token(version: i64) -> serde_json::Value {
    serde_json::json!({
        "id": TOKEN_ID,
        "provider": "mergify",
        "side": "member",
        "version": version,
        "connectedBy": PRINCIPAL_ID,
        "connectedAt": "2026-11-18T09:00:00Z",
        "createdAt": "2026-11-17T09:00:00Z",
        "authorizations": [],
        "token": SENTINEL
    })
}

/// The member's `mergify` token, authorized for one runner of acme.
fn authorized_mergify() -> serde_json::Value {
    let mut token = mergify_token(1);
    token["authorizations"] = serde_json::json!([{
        "id": "ita_01k0z6r1w8f4jy2m7q9v3x5abc",
        "runnerId": RUNNER_ID,
        "runnerName": RUNNER_NAME,
        "organizationId": ORGANIZATION_ID,
        "createdAt": "2026-11-18T09:05:00Z"
    }]);
    token
}

fn tokens(items: &[serde_json::Value]) -> Vec<u8> {
    json_http_response("200 OK", serde_json::json!({"items": items}))
}

/// The answer to a store, which echoes the request's key.
fn stored_token(status: &str, version: i64) -> Vec<u8> {
    http_response_with_headers(
        status,
        Some("application/json"),
        &[("Idempotency-Key", ECHO_IDEMPOTENCY_KEY)],
        &serde_json::to_vec(&mergify_token(version)).unwrap(),
    )
}

/// A member who holds a GitHub grant and no grant of `mergify`: the grant list, then the served
/// read naming `mergify` as a token service, then the member's tokens, `held`.
fn holding_token(held: serde_json::Value) -> Vec<Vec<u8>> {
    vec![
        page(&[oauth_grant(OAUTH_GRANT_ID, "github", "active")], None),
        serving_with(true),
        tokens(&[held]),
    ]
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

/// Runs `useful account integration args` without `--yes`, which is refused with exit 2 before
/// anything is sent or printed on standard output, naming the option; its standard error.
fn refused_without_yes(server: &ScriptedServer, credential: &Path, args: &[&str]) -> String {
    let output = run(server, credential, args);
    assert_eq!(output.status.code(), Some(2), "{args:?}");
    assert!(output.stdout.is_empty(), "{args:?}");
    let text = stderr(&output);
    assert!(text.contains("--yes"), "{args:?}: {text}");
    text
}

// REQ-INTEGRATION-16
#[test]
fn connect_stores_a_token_given_in_a_file_on_standard_input_or_at_a_prompt_that_does_not_echo() {
    let directory = tempfile::tempdir().unwrap();
    let file = private_file(
        directory.path(),
        "mergify.token",
        format!("{KNOWN_TOKEN}\n").as_bytes(),
    );
    let file = file.to_str().unwrap();
    let typed = format!("{KNOWN_TOKEN}\n");
    let answers = || {
        vec![
            serving_with(true),
            tokens(&[]),
            stored_token("201 Created", 1),
        ]
    };
    let cases: [(&[&str], Option<&[u8]>); 4] = [
        (&["connect", "mergify", "--from-file", file], Some(b"")),
        (
            &["connect", "mergify", "--from-file", "-", "--json"],
            Some(typed.as_bytes()),
        ),
        (&["connect", "mergify"], Some(typed.as_bytes())),
        (&["connect", "mergify", "--json"], None),
    ];
    for (args, input) in cases {
        let (server, _credentials, credential) = prepared(answers());
        let output = match input {
            Some(input) => run_with_input(&server, &credential, args, input, &[]),
            None => {
                let command = on_a_terminal(&server, &credential, args);
                let (transcript, output) = on_terminal(command, &[(HIDDEN, typed.as_str())]);
                assert!(!transcript.contains(KNOWN_TOKEN), "{transcript}");
                assert_no_secret_output(&output, &[SENTINEL, TOKEN, KNOWN_TOKEN]);
                output
            }
        };
        let requests = server.finish();

        assert_eq!(
            output.status.code(),
            Some(0),
            "{args:?}: {}",
            stderr(&output)
        );
        let asked = asked(&requests);
        assert_eq!(
            lines(&asked),
            [READ_SERVED, LIST_MEMBER_TOKENS, STORE_MEMBER_TOKEN],
            "{args:?}"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&asked[2].1).unwrap(),
            serde_json::json!({"provider": "mergify", "token": KNOWN_TOKEN}),
            "{args:?}"
        );
        assert!(!header_value(&requests[2], "idempotency-key").is_empty());
        if args.contains(&"--json") {
            let document = one_document(&output);
            assert_eq!(document["schemaVersion"], 1, "{document}");
            assert_eq!(document["outcome"], "connected", "{document}");
            assert_eq!(document["token"]["id"], TOKEN_ID, "{document}");
            assert_eq!(document["token"]["service"], "mergify", "{document}");
            assert_eq!(document["token"]["side"], "member", "{document}");
            assert_eq!(document["token"]["version"], 1, "{document}");
        } else {
            assert!(reports(&output, 1), "{args:?}");
        }
    }
}

// REQ-INTEGRATION-16
#[test]
fn connect_refuses_a_token_service_it_cannot_take_before_anything_is_read_or_stored() {
    // A deployment that serves no token service, or predates the read, is asked that alone,
    // and nothing is asked on a terminal.
    for served in [serving_with(false), predating_served()] {
        let (server, _credentials, credential) = prepared(vec![served.clone(), served]);
        let refused = run_with_input(&server, &credential, &["connect", "mergify"], b"", &[]);
        let command = on_a_terminal(&server, &credential, &["connect", "mergify"]);
        let (transcript, on_the_terminal) = on_terminal(command, &[]);

        assert_eq!(refused.status.code(), Some(2));
        assert!(refused.stdout.is_empty());
        assert_eq!(on_the_terminal.status.code(), Some(2));
        assert!(!transcript.contains(HIDDEN), "{transcript}");
        assert_eq!(sent(server), [READ_SERVED, READ_SERVED]);
    }

    // A token outside the form, or a file another user could read, is refused once the member's
    // tokens are read, and nothing is stored; a token in the environment is not read.
    let directory = tempfile::tempdir().unwrap();
    let readable = private_file(directory.path(), "readable.token", KNOWN_TOKEN.as_bytes());
    fs::set_permissions(&readable, Permissions::from_mode(0o644)).unwrap();
    let readable = readable.to_str().unwrap();
    let too_long = "a".repeat(4097);
    type Refused<'a> = (&'a [&'a str], &'a [u8], &'a [(&'a str, &'a str)]);
    let cases: [Refused; 5] = [
        (&["connect", "mergify"], b"", &[]),
        (&["connect", "mergify"], b"mergify token\n", &[]),
        (&["connect", "mergify"], too_long.as_bytes(), &[]),
        (&["connect", "mergify", "--from-file", readable], b"", &[]),
        (
            &["connect", "mergify"],
            b"",
            &[("MERGIFY_TOKEN", KNOWN_TOKEN)],
        ),
    ];
    for (args, input, variables) in cases {
        let (server, _credentials, credential) = prepared(vec![serving_with(true), tokens(&[])]);
        let output = run_with_input(&server, &credential, args, input, variables);

        assert_no_secret_output(&output, &[too_long.as_str()]);
        assert_eq!(output.status.code(), Some(2), "{args:?} {variables:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert_eq!(sent(server), [READ_SERVED, LIST_MEMBER_TOKENS], "{args:?}");
    }

    // The options of a sign-in are refused once the deployment is found to serve a token
    // service, before its tokens or the token are read.
    let token_file = private_file(directory.path(), "token", KNOWN_TOKEN.as_bytes());
    let token_file = token_file.to_str().unwrap();
    for option in [
        &["--login"][..],
        &["--device"],
        &["--token-file", token_file],
        &["--no-wait"],
        &["--timeout", "30s"],
        &["--org", "acme"],
    ] {
        let (server, _credentials, credential) = prepared(vec![serving_with(true)]);
        let args = [&["connect", "mergify"][..], option].concat();
        let output = run_with_input(&server, &credential, &args, KNOWN_TOKEN.as_bytes(), &[]);

        assert_eq!(output.status.code(), Some(2), "{option:?}");
        assert!(output.stdout.is_empty(), "{option:?}");
        assert_eq!(sent(server), [READ_SERVED], "{option:?}");
    }

    // Signing in to each provider the member lacks selects no token service.
    let (server, _credentials, credential) = prepared(vec![
        holding(&["github", "gitlab.com", "linear", "example"], true),
        serving_with(true),
    ]);
    let output = run(&server, &credential, &["connect", "--all", "--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(sent(server), [LIST_EVERY_KIND, READ_SERVED]);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("mergify"), "{text}");
}

// REQ-INTEGRATION-16
// A name outside the five is read for among what the deployment serves before its options are
// judged, so an OAuth provider's consent begins after one served read.
#[test]
fn connect_of_a_served_oauth_provider_begins_its_consent_after_the_served_read() {
    let (server, _directory, credential) = prepared(vec![
        serving_with(true),
        nothing_held(),
        json_http_response("201 Created", consent_of("example", "pending")),
    ]);
    let opener = Opener::new(0);
    let output = opener_command(
        &server,
        &credential,
        &opener,
        Place::Remote,
        &[
            "account",
            "integration",
            "connect",
            "example",
            "--no-wait",
            "--json",
        ],
    )
    .stdin(Stdio::null())
    .output()
    .unwrap();
    assert_no_secret_output(&output, &[SENTINEL, TOKEN]);
    let requests = asked(&server.finish());

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(lines(&requests), [READ_SERVED, LIST_OAUTH, START_CONSENT]);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&requests[2].1).unwrap(),
        serde_json::json!({"provider": "example"})
    );

    // An option an OAuth provider does not take is refused once the read names it one, and a
    // name the deployment serves as nothing is refused naming the token service it could be.
    let directory = tempfile::tempdir().unwrap();
    let file = private_file(directory.path(), "example.token", KNOWN_TOKEN.as_bytes());
    let (server, _credentials, credential) = prepared(vec![serving_with(true), serving_with(true)]);
    let unsuited = run_with_input(
        &server,
        &credential,
        &["connect", "example", "--from-file", file.to_str().unwrap()],
        b"",
        &[],
    );
    let unserved = run_with_input(&server, &credential, &["connect", "bitbucket"], b"", &[]);
    assert_eq!(sent(server), [READ_SERVED, READ_SERVED]);

    for refused in [&unsuited, &unserved] {
        assert_eq!(refused.status.code(), Some(2), "{}", stderr(refused));
        assert!(refused.stdout.is_empty());
    }
    let refusal = stderr(&unserved);
    for name in ["example", "mergify"] {
        assert!(refusal.contains(name), "{name}: {refusal}");
    }
}

// REQ-INTEGRATION-16
// REQ-INTEGRATION-18
#[test]
fn connect_refuses_a_held_token_naming_reconnect_which_stores_its_next_version() {
    let held = || tokens(&[mergify_token(1)]);
    let input = format!("{KNOWN_TOKEN}\n");

    // `connect` of a service the member holds a token of is refused before any token is read,
    // off a terminal and on one, where nothing is asked, and names `reconnect`.
    let (server, _credentials, credential) =
        prepared(vec![serving_with(true), held(), serving_with(true), held()]);
    let refused = run_with_input(
        &server,
        &credential,
        &["connect", "mergify"],
        input.as_bytes(),
        &[],
    );
    let (transcript, on_the_terminal) = on_terminal(
        on_a_terminal(&server, &credential, &["connect", "mergify"]),
        &[],
    );
    assert_eq!(
        sent(server),
        [
            READ_SERVED,
            LIST_MEMBER_TOKENS,
            READ_SERVED,
            LIST_MEMBER_TOKENS
        ]
    );
    for output in [&refused, &on_the_terminal] {
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    assert!(!transcript.contains(HIDDEN), "{transcript}");
    assert!(!transcript.contains("[y/N]"), "{transcript}");
    let refusal = stderr(&refused);
    assert!(refusal.contains(TOKEN_ID), "{refusal}");
    assert!(
        refusal.contains("useful account integration reconnect mergify"),
        "{refusal}"
    );

    // `reconnect` reads the token as `connect` does and stores the next version, which keeps
    // the record's ID.
    let (server, _credentials, credential) = prepared(vec![
        nothing_held(),
        serving_with(true),
        held(),
        stored_token("200 OK", 2),
    ]);
    let replaced = run_with_input(
        &server,
        &credential,
        &["reconnect", "mergify", "--json"],
        input.as_bytes(),
        &[],
    );
    let requests = asked(&server.finish());
    assert_eq!(replaced.status.code(), Some(0), "{}", stderr(&replaced));
    let document = one_document(&replaced);
    assert_eq!(document["outcome"], "replaced", "{document}");
    assert_eq!(document["token"]["id"], TOKEN_ID, "{document}");
    assert_eq!(document["token"]["version"], 2, "{document}");
    assert_eq!(
        lines(&requests),
        [
            LIST_EVERY_KIND,
            READ_SERVED,
            LIST_MEMBER_TOKENS,
            STORE_MEMBER_TOKEN
        ]
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&requests[3].1).unwrap(),
        serde_json::json!({"provider": "mergify", "token": KNOWN_TOKEN, "replace": true})
    );

    // On a terminal it prompts for the token without echoing it.
    let (server, _credentials, credential) = prepared(vec![
        nothing_held(),
        serving_with(true),
        held(),
        stored_token("200 OK", 2),
    ]);
    let (transcript, replaced) = on_terminal(
        on_a_terminal(&server, &credential, &["reconnect", "mergify"]),
        &[(HIDDEN, input.as_str())],
    );
    server.finish();
    assert_no_secret_output(&replaced, &[SENTINEL, TOKEN, KNOWN_TOKEN]);
    assert!(!transcript.contains(KNOWN_TOKEN), "{transcript}");
    assert_eq!(replaced.status.code(), Some(0), "{transcript}");
    assert!(reports(&replaced, 2));

    // The options of a sign-in are refused for a token once it is found, before it is read.
    let (server, _credentials, credential) =
        prepared(vec![nothing_held(), serving_with(true), held()]);
    let unsuited = run_with_input(
        &server,
        &credential,
        &["reconnect", "mergify", "--device"],
        input.as_bytes(),
        &[],
    );
    assert_eq!(unsuited.status.code(), Some(2));
    assert!(unsuited.stdout.is_empty());
    assert_eq!(
        sent(server),
        [LIST_EVERY_KIND, READ_SERVED, LIST_MEMBER_TOKENS]
    );
}

// REQ-INTEGRATION-16
// REQ-INTEGRATION-18
// REQ-INTEGRATION-20
#[test]
fn each_refusal_of_a_token_route_is_reported_with_its_outcome_and_remedy() {
    let problem_of =
        |status: &str, code: u16, slug: &str| problem(status, code, &format!("integration-{slug}"));
    // `connect` meets a token stored meanwhile, or one Cloud does not accept.
    for (answer, outcome) in [
        (
            problem_of("409 Conflict", 409, "token-exists"),
            "token_exists",
        ),
        (
            problem_of("400 Bad Request", 400, "token-invalid"),
            "token_invalid",
        ),
    ] {
        let (server, _credentials, credential) =
            prepared(vec![serving_with(true), tokens(&[]), answer.clone()]);
        let json = run_with_input(
            &server,
            &credential,
            &["connect", "mergify", "--json"],
            KNOWN_TOKEN.as_bytes(),
            &[],
        );
        server.finish();
        assert_eq!(json.status.code(), Some(1), "{outcome}");
        assert_eq!(one_document(&json)["outcome"], outcome);
    }
    let (server, _credentials, credential) = prepared(vec![
        serving_with(true),
        tokens(&[]),
        problem_of("409 Conflict", 409, "token-exists"),
    ]);
    let human = run_with_input(
        &server,
        &credential,
        &["connect", "mergify"],
        KNOWN_TOKEN.as_bytes(),
        &[],
    );
    server.finish();
    assert_eq!(human.status.code(), Some(1));
    assert!(
        stderr(&human).contains("useful account integration reconnect mergify"),
        "{}",
        stderr(&human)
    );

    // `authorize` meets a runner outside the member's organizations, a token authorized for
    // the runner meanwhile, and a token revoked meanwhile.
    for (answer, outcome) in [
        (
            problem_of("404 Not Found", 404, "token-runner-not-found"),
            "runner_not_found",
        ),
        (
            problem_of("409 Conflict", 409, "token-already-authorized"),
            "already_authorized",
        ),
        (
            problem_of("404 Not Found", 404, "token-not-found"),
            "token_not_found",
        ),
    ] {
        let mut answers = holding_token(mergify_token(1));
        answers.push(answer);
        let (server, _credentials, credential) = prepared(answers);
        let output = run(
            &server,
            &credential,
            &[
                "authorize",
                "mergify",
                "--runner",
                NEW_RUNNER_ID,
                "--yes",
                "--json",
            ],
        );
        server.finish();
        assert_eq!(output.status.code(), Some(1), "{outcome}");
        assert_eq!(json_output(&output)["outcome"], outcome);
    }
}

// REQ-INTEGRATION-19
#[test]
fn list_prints_the_members_tokens_after_the_grants_and_nothing_of_an_organization() {
    let answers = || {
        vec![
            page(&[oauth_grant(OAUTH_GRANT_ID, "github", "active")], None),
            serving_with(true),
            tokens(&[authorized_mergify()]),
            identities(ada()),
        ]
    };
    let (server, _directory, credential) = prepared([answers(), answers()].concat());
    let listed = run(&server, &credential, &["list", "--json"]);
    let human = run(&server, &credential, &["list"]);
    let expected = [
        LIST_FIRST_PAGE,
        READ_SERVED,
        LIST_MEMBER_TOKENS,
        READ_IDENTITIES,
    ];
    assert_eq!(sent(server), [expected, expected].concat());

    assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
    let document = json_output(&listed);
    assert_eq!(document["grants"].as_array().unwrap().len(), 1);
    assert!(document.get("connections").is_none(), "{document}");
    let listed_tokens = document["tokens"].as_array().unwrap();
    assert_eq!(listed_tokens.len(), 1, "{document}");
    let token = &listed_tokens[0];
    assert_eq!(token["id"], TOKEN_ID, "{token}");
    assert_eq!(token["service"], "mergify", "{token}");
    assert_eq!(token["side"], "member", "{token}");
    assert!(token.get("organization").is_none(), "{token}");
    assert_eq!(token["version"], 1, "{token}");
    assert_eq!(token["connectedBy"], PRINCIPAL_ID, "{token}");
    assert_eq!(token["connectedAt"], "2026-11-18T09:00:00Z", "{token}");
    assert_eq!(token["authorizations"][0]["runnerId"], RUNNER_ID, "{token}");
    assert_eq!(
        token["authorizations"][0]["runnerName"], RUNNER_NAME,
        "{token}"
    );

    // The report prints the same, the token after the grant.
    assert_eq!(human.status.code(), Some(0));
    let text = String::from_utf8(human.stdout).unwrap();
    let at = |line: &str| {
        text.lines()
            .position(|candidate| candidate == line)
            .unwrap_or_else(|| panic!("{line} not in\n{text}"))
    };
    let grant = at(&format!("grant: {OAUTH_GRANT_ID}"));
    let token = at(&format!("token: {TOKEN_ID}"));
    assert!(grant < token, "{text}");
    assert!(
        at(&format!("runner: {RUNNER_NAME} ({RUNNER_ID})")) > token,
        "{text}"
    );
}

// REQ-INTEGRATION-19
#[test]
fn list_reads_no_token_unless_the_deployment_serves_a_token_service() {
    for served in [serving_with(false), predating_served()] {
        let (server, _directory, credential) = prepared(vec![
            page(&[oauth_grant(OAUTH_GRANT_ID, "github", "active")], None),
            served,
            identities(ada()),
        ]);
        let listed = run(&server, &credential, &["list", "--json"]);
        assert_eq!(
            sent(server),
            [LIST_FIRST_PAGE, READ_SERVED, READ_IDENTITIES]
        );
        assert_eq!(listed.status.code(), Some(0), "{}", stderr(&listed));
        assert_eq!(json_output(&listed)["tokens"], serde_json::json!([]));
    }

    // A token list that fails fails the command as a failed read of the grants does.
    let refused = || problem("403 Forbidden", 403, "forbidden");
    let (server, _directory, credential) = prepared(vec![
        page(&[oauth_grant(OAUTH_GRANT_ID, "github", "active")], None),
        serving_with(true),
        refused(),
        refused(),
    ]);
    let failed = run(&server, &credential, &["list", "--json"]);
    let grants_failed = run(&server, &credential, &["list", "--json"]);
    assert_eq!(
        sent(server),
        [
            LIST_FIRST_PAGE,
            READ_SERVED,
            LIST_MEMBER_TOKENS,
            LIST_FIRST_PAGE
        ]
    );
    assert_ne!(failed.status.code(), Some(0));
    assert_eq!(failed.status.code(), grants_failed.status.code());
    assert_eq!(
        json_output(&failed)["outcome"],
        json_output(&grants_failed)["outcome"]
    );
}

// REQ-INTEGRATION-19
#[test]
fn show_of_a_service_shows_the_members_token_once_no_grant_of_it_is_found() {
    let (server, _directory, credential) = prepared(holding_token(authorized_mergify()));
    let shown = run(&server, &credential, &["show", "mergify", "--json"]);
    assert_eq!(
        sent(server),
        [LIST_FIRST_PAGE, READ_SERVED, LIST_MEMBER_TOKENS]
    );
    assert_eq!(shown.status.code(), Some(0), "{}", stderr(&shown));
    let document = json_output(&shown);
    assert_eq!(document["outcome"], "shown", "{document}");
    assert_eq!(document["token"]["id"], TOKEN_ID, "{document}");
    assert_eq!(document["token"]["side"], "member", "{document}");

    // A name that names neither a grant nor a token of the member's is not found as a grant.
    let (server, _directory, credential) = prepared(vec![
        page(&[oauth_grant(OAUTH_GRANT_ID, "github", "active")], None),
        serving_with(true),
        tokens(&[]),
    ]);
    let neither = run(&server, &credential, &["show", "buildkite", "--json"]);
    assert_eq!(
        sent(server),
        [LIST_FIRST_PAGE, READ_SERVED, LIST_MEMBER_TOKENS]
    );
    assert_eq!(neither.status.code(), Some(1));
    assert_eq!(json_output(&neither)["outcome"], "grant_not_found");

    // A token records no use, so `--uses` is refused for it once it is found.
    let (server, _directory, credential) = prepared(holding_token(authorized_mergify()));
    let uses = run(&server, &credential, &["show", "mergify", "--uses", "5"]);
    server.finish();
    assert_eq!(uses.status.code(), Some(2), "{}", stderr(&uses));
    assert!(uses.stdout.is_empty());
}

// REQ-INTEGRATION-20
#[test]
fn disconnect_erases_the_members_token_once_no_grant_of_its_service_is_found() {
    let mut answers = holding_token(mergify_token(1));
    answers.push(deleted());
    // A GitHub grant revoked by its provider name, whose statement is a grant's.
    answers.push(page(
        &[oauth_grant(OAUTH_GRANT_ID, "github", "active")],
        None,
    ));
    answers.push(deleted());
    let (server, _directory, credential) = prepared(answers);
    let revoked = run(
        &server,
        &credential,
        &["disconnect", "mergify", "--yes", "--json"],
    );
    let refusal = refused_without_yes(&server, &credential, &["disconnect", "mergify"]);
    let grant_revoked = run(&server, &credential, &["disconnect", "github", "--yes"]);
    let requests = server.finish();

    assert_eq!(
        lines(&asked(&requests)),
        [
            LIST_EVERY_KIND,
            READ_SERVED,
            LIST_MEMBER_TOKENS,
            REVOKE_MEMBER_TOKEN,
            LIST_EVERY_KIND,
            REVOKE_GITHUB,
        ]
    );
    assert!(!header_value(&requests[3], "idempotency-key").is_empty());
    assert_eq!(revoked.status.code(), Some(0), "{}", stderr(&revoked));
    let document = json_output(&revoked);
    assert_eq!(document["outcome"], "revoked", "{document}");
    assert_eq!(document["integrationTokenId"], TOKEN_ID, "{document}");
    assert_eq!(document["service"], "mergify", "{document}");
    assert_eq!(document["side"], "member", "{document}");

    // Before it acts it states what revoking a token does, as the refusal without --yes does,
    // and that is not what revoking a grant does.
    let token_statement = statement(&revoked, TOKEN_ID);
    let grant_statement = statement(&grant_revoked, OAUTH_GRANT_ID);
    assert_stated_by_the_refusal(&token_statement, &refusal);
    assert_stated_by_the_refusal(&grant_statement, &refusal);
    assert!(
        token_statement
            .iter()
            .all(|line| !grant_statement.contains(line)),
        "{token_statement:?} {grant_statement:?}"
    );
}

// REQ-INTEGRATION-20
#[test]
fn authorize_and_deauthorize_act_on_the_members_token_by_its_service() {
    let mut answers = holding_token(authorized_mergify());
    answers.push(token_authorized(NEW_RUNNER_ID));
    answers.extend(holding_token(authorized_mergify()));
    answers.push(deleted());
    // The token lists no authorization for the new runner.
    answers.extend(holding_token(authorized_mergify()));
    let (server, _directory, credential) = prepared(answers);
    let authorized_run = run(
        &server,
        &credential,
        &[
            "authorize",
            "mergify",
            "--runner",
            NEW_RUNNER_ID,
            "--yes",
            "--json",
        ],
    );
    let deauthorized = run(
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
    let not_found = run(
        &server,
        &credential,
        &[
            "deauthorize",
            "mergify",
            "--runner",
            NEW_RUNNER_ID,
            "--yes",
            "--json",
        ],
    );
    // Without --yes and with --runner each is refused before anything is sent, stating the
    // token's lines.
    let authorize_refusal = refused_without_yes(
        &server,
        &credential,
        &["authorize", "mergify", "--runner", NEW_RUNNER_ID],
    );
    let deauthorize_refusal = refused_without_yes(
        &server,
        &credential,
        &["deauthorize", "mergify", "--runner", RUNNER_ID],
    );
    let requests = server.finish();

    let reads = [LIST_EVERY_KIND, READ_SERVED, LIST_MEMBER_TOKENS];
    assert_eq!(
        lines(&asked(&requests)),
        [
            &reads[..],
            &[AUTHORIZE_MEMBER_TOKEN],
            &reads,
            &[DEAUTHORIZE_MEMBER_TOKEN],
            &reads
        ]
        .concat()
    );
    assert_eq!(
        request_body(&requests[3]),
        serde_json::json!({"runnerId": NEW_RUNNER_ID})
    );
    for request in [&requests[3], &requests[7]] {
        assert!(!header_value(request, "idempotency-key").is_empty());
    }

    assert_eq!(
        authorized_run.status.code(),
        Some(0),
        "{}",
        stderr(&authorized_run)
    );
    let document = json_output(&authorized_run);
    assert_eq!(document["outcome"], "authorized", "{document}");
    assert_eq!(document["integrationTokenId"], TOKEN_ID, "{document}");
    assert!(document.get("grantId").is_none(), "{document}");
    let authorization = &document["authorization"];
    assert_eq!(authorization["id"], NEW_AUTHORIZATION_ID, "{document}");
    assert_eq!(authorization["runnerId"], NEW_RUNNER_ID, "{document}");
    assert_eq!(authorization["runnerName"], "bravo", "{document}");
    assert_eq!(
        authorization["organizationId"], ORGANIZATION_ID,
        "{document}"
    );
    assert_stated_by_the_refusal(&statement(&authorized_run, TOKEN_ID), &authorize_refusal);

    assert_eq!(
        deauthorized.status.code(),
        Some(0),
        "{}",
        stderr(&deauthorized)
    );
    let document = json_output(&deauthorized);
    assert_eq!(document["outcome"], "deauthorized", "{document}");
    assert_eq!(document["integrationTokenId"], TOKEN_ID, "{document}");
    assert_eq!(
        document["authorizationId"], "ita_01k0z6r1w8f4jy2m7q9v3x5abc",
        "{document}"
    );
    assert_eq!(document["runnerId"], RUNNER_ID, "{document}");
    assert_stated_by_the_refusal(&statement(&deauthorized, TOKEN_ID), &deauthorize_refusal);

    assert_eq!(not_found.status.code(), Some(1));
    assert_eq!(
        json_output(&not_found)["outcome"],
        "authorization_not_found"
    );
}

// REQ-INTEGRATION-20
// REQ-GRANT-81
#[test]
fn authorize_without_a_runner_names_the_runners_the_members_token_is_not_authorized_for() {
    let mut answers = holding_token(authorized_mergify());
    answers.extend([
        memberships(&[(ORGANIZATION_ID, "acme")]),
        // The token is authorized for charlie already, so alpha and bravo are named.
        registrations(&[
            registration(ALPHA, "offline", "enabled"),
            registration(BRAVO, "online", "enabled"),
            registration(CHARLIE, "online", "enabled"),
        ]),
    ]);
    let (server, _directory, credential) = prepared([answers.clone(), answers].concat());
    let human = run(&server, &credential, &["authorize", "mergify"]);
    let json = run(&server, &credential, &["authorize", "mergify", "--json"]);
    let expected = [
        LIST_EVERY_KIND,
        READ_SERVED,
        LIST_MEMBER_TOKENS,
        LIST_MEMBERSHIPS,
        LIST_ACME_RUNNERS,
    ];
    assert_eq!(sent(server), [expected, expected].concat());

    // Bravo, online and enabled, is named first, and the command line names the token by its
    // service.
    assert_eq!(human.status.code(), Some(2), "{}", stderr(&human));
    assert!(human.stdout.is_empty());
    assert_eq!(named_runners(&human, &[ALPHA, BRAVO]), ["bravo", "alpha"]);
    let text = stderr(&human);
    assert!(!text.contains("charlie"), "{text}");
    assert!(
        text.contains(&format!(
            "useful account integration authorize mergify --runner {NEW_RUNNER_ID} --yes"
        )),
        "{text}"
    );

    assert_eq!(json.status.code(), Some(2));
    let document = json_output(&json);
    assert_eq!(document["outcome"], "runner_required", "{document}");
    assert_eq!(document["integrationTokenId"], TOKEN_ID, "{document}");
    assert!(document.get("grantId").is_none(), "{document}");
    assert_eq!(
        offered(&document)
            .into_iter()
            .map(|(id, _)| id)
            .collect::<Vec<_>>(),
        [NEW_RUNNER_ID, ENDED_RUNNER_ID]
    );
}

/// The outcome of each entry of `entries` of an `authorize --all` document, by `id`.
fn outcomes_by(entries: &serde_json::Value, id: &str) -> Vec<(String, String)> {
    entries
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry[id].as_str().unwrap().to_owned(),
                entry["outcome"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

// REQ-INTEGRATION-20
#[test]
fn authorize_all_includes_the_members_tokens() {
    let (server, _directory, credential) = prepared(vec![
        page(&[oauth_grant_unauthorized(OAUTH_GRANT_ID)], None),
        serving_with(true),
        tokens(&[mergify_token(1)]),
        authorized(OAUTH_GRANT_ID, NEW_RUNNER_ID),
        token_authorized(NEW_RUNNER_ID),
    ]);
    let every = run(
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
    assert_eq!(
        sent(server),
        [
            LIST_EVERY_KIND,
            READ_SERVED,
            LIST_MEMBER_TOKENS,
            AUTHORIZE_GITHUB,
            AUTHORIZE_MEMBER_TOKEN,
        ]
    );
    assert_eq!(every.status.code(), Some(0), "{}", stderr(&every));
    let document = json_output(&every);
    assert_eq!(document["outcome"], "authorized", "{document}");
    assert_eq!(
        outcomes_by(&document["grants"], "grantId"),
        [(OAUTH_GRANT_ID.to_owned(), "authorized".to_owned())]
    );
    assert_eq!(
        outcomes_by(&document["tokens"], "integrationTokenId"),
        [(TOKEN_ID.to_owned(), "authorized".to_owned())]
    );
    assert_eq!(document["tokens"][0]["service"], "mergify", "{document}");
    assert!(
        document["tokens"][0].get("organizationId").is_none(),
        "{document}"
    );
}

// REQ-INTEGRATION-19
// REQ-INTEGRATION-20
// A deployment that serves no token service, or predates the served read, may have no token
// route: a name that names no grant and `authorize --all` ask it for no token list.
#[test]
fn a_leaf_reads_no_token_list_unless_the_deployment_serves_a_token_service() {
    let grant = || page(&[oauth_grant_unauthorized(OAUTH_GRANT_ID)], None);
    for served in [serving_with(false), predating_served()] {
        let (server, _directory, credential) = prepared(vec![
            grant(),
            served.clone(),
            grant(),
            served.clone(),
            grant(),
            served,
            authorized(OAUTH_GRANT_ID, NEW_RUNNER_ID),
        ]);
        let revoked = run(
            &server,
            &credential,
            &["disconnect", "mergify", "--yes", "--json"],
        );
        let shown = run(&server, &credential, &["show", "mergify", "--json"]);
        let every = run(
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
        assert_eq!(
            sent(server),
            [
                LIST_EVERY_KIND,
                READ_SERVED,
                LIST_EVERY_KIND,
                READ_SERVED,
                LIST_EVERY_KIND,
                READ_SERVED,
                AUTHORIZE_GITHUB,
            ]
        );
        for not_found in [&revoked, &shown] {
            assert_eq!(not_found.status.code(), Some(1));
            assert_eq!(json_output(not_found)["outcome"], "grant_not_found");
        }
        assert_eq!(every.status.code(), Some(0), "{}", stderr(&every));
        let document = json_output(&every);
        assert_eq!(
            outcomes_by(&document["grants"], "grantId"),
            [(OAUTH_GRANT_ID.to_owned(), "authorized".to_owned())]
        );
        assert_eq!(document["tokens"], serde_json::json!([]), "{document}");
    }
}

// REQ-INTEGRATION-18
#[test]
fn reconnect_reads_a_file_as_the_token_and_never_makes_one() {
    // The file is read as the token, not as a Codex auth.json.
    let directory = tempfile::tempdir().unwrap();
    let file = private_file(
        directory.path(),
        "mergify.token",
        format!("{KNOWN_TOKEN}\n").as_bytes(),
    );
    let file = file.to_str().unwrap();
    let (server, _credentials, credential) = prepared(vec![
        nothing_held(),
        serving_with(true),
        tokens(&[mergify_token(1)]),
        stored_token("200 OK", 2),
    ]);
    let replaced = run(
        &server,
        &credential,
        &["reconnect", "mergify", "--from-file", file, "--json"],
    );
    let requests = asked(&server.finish());
    assert_eq!(replaced.status.code(), Some(0), "{}", stderr(&replaced));
    assert_eq!(one_document(&replaced)["outcome"], "replaced");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&requests[3].1).unwrap(),
        serde_json::json!({"provider": "mergify", "token": KNOWN_TOKEN, "replace": true})
    );

    // A token of a service the deployment no longer serves is still found, and Cloud answers
    // for it.
    let serving_buildkite = json_http_response(
        "200 OK",
        serde_json::json!({"items": [
            {"provider": "github", "kind": "oauth"},
            {"provider": "buildkite", "kind": "token"}
        ]}),
    );
    let (server, _credentials, credential) = prepared(vec![
        nothing_held(),
        serving_buildkite,
        tokens(&[mergify_token(1)]),
        problem("400 Bad Request", 400, "integration-token-invalid"),
    ]);
    let unserved = run(
        &server,
        &credential,
        &["reconnect", "mergify", "--from-file", file, "--json"],
    );
    assert_eq!(
        sent(server),
        [
            LIST_EVERY_KIND,
            READ_SERVED,
            LIST_MEMBER_TOKENS,
            STORE_MEMBER_TOKEN
        ]
    );
    assert_eq!(unserved.status.code(), Some(1), "{}", stderr(&unserved));
    assert_eq!(one_document(&unserved)["outcome"], "token_invalid");

    // A service the member holds no token of is `connect`'s: nothing is read or stored.
    for json in [true, false] {
        let (server, _credentials, credential) =
            prepared(vec![nothing_held(), serving_with(true), tokens(&[])]);
        let args: &[&str] = if json {
            &["reconnect", "mergify", "--from-file", file, "--json"]
        } else {
            &["reconnect", "mergify", "--from-file", file]
        };
        let output = run(&server, &credential, args);
        assert_eq!(
            sent(server),
            [LIST_EVERY_KIND, READ_SERVED, LIST_MEMBER_TOKENS]
        );
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        if json {
            assert_eq!(one_document(&output)["outcome"], "token_not_found");
        } else {
            assert!(
                stderr(&output).contains("useful account integration connect mergify"),
                "{}",
                stderr(&output)
            );
        }
    }
}
