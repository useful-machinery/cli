use super::*;

use super::grant::{Opener, Place, opener_command};

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

/// GitHub's user authorization a setup session answers for its verification.
fn authorization_url() -> String {
    "https://github.example/login/oauth/authorize?client_id=Iv1.setup&state=setup-verification"
        .to_owned()
}

/// A setup session as a begin is answered it, with a member the contract does not name.
pub(super) fn setup_session() -> serde_json::Value {
    serde_json::json!({
        "id": SETUP_SESSION,
        "state": "pending",
        "expiresAt": "2026-09-05T12:10:00Z",
        "setupUrl": setup_url(),
        "authorizationUrl": authorization_url(),
        "verification": {"state": "unverified"},
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
        "authorityVerifiedAt": "2026-09-05T12:01:00Z",
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

const LIST_INSTALLATIONS: &str =
    "GET /api/v1/organizations/acme-research/github/installations HTTP/1.1";
const BEGIN_SETUP: &str = "POST /api/v1/organizations/acme-research/github/setup-sessions HTTP/1.1";
const AUTHORITY_UNPROVEN: &str =
    "https://api.usefulmachinery.com/problems/github-installation-authority-unproven";

fn read_setup() -> String {
    format!(
        "GET /api/v1/organizations/{ORGANIZATION}/github/setup-sessions/{SETUP_SESSION} HTTP/1.1"
    )
}

fn complete_setup() -> String {
    format!(
        "POST /api/v1/organizations/{ORGANIZATION}/github/setup-sessions/{SETUP_SESSION}/completion HTTP/1.1"
    )
}

/// The request line of each request.
fn request_lines(requests: &[String]) -> Vec<String> {
    requests
        .iter()
        .map(|request| request.lines().next().unwrap().to_owned())
        .collect()
}

/// The environment of a deployment on a machine with no browser, a remote shell, so that the
/// guided setup opens nothing.
fn headless<'a>(api_url: &'a str, credential_path: &'a str) -> Vec<(&'static str, &'a str)> {
    let mut environment = deployment_environment(api_url, credential_path).to_vec();
    environment.push(("SSH_CONNECTION", "198.51.100.7 52000 192.0.2.10 22"));
    environment
}

/// The JSON documents a command printed, in order: the guided setup prints one as the session
/// begins and one as it ends.
pub(super) fn documents(output: &Output) -> Vec<serde_json::Value> {
    serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<serde_json::Value>()
        .map(Result::unwrap)
        .collect()
}

/// A setup session as a read answers it in `state` with `verification`, with a member the
/// contract does not name.
pub(super) fn setup_read(state: &str, verification: serde_json::Value) -> serde_json::Value {
    let mut session = setup_session();
    session["state"] = state.into();
    if !(state == "pending" && verification["state"] == "unverified") {
        session.as_object_mut().unwrap().remove("authorizationUrl");
    }
    session["verification"] = verification;
    session
}

/// A pending session whose verification waits for the proof at GitHub.
pub(super) fn unverified_read() -> serde_json::Value {
    setup_read("pending", serde_json::json!({"state": "unverified"}))
}

/// A verification of `octocat` listing `installations` (by GitHub installation ID, with whether
/// the organization holds it) and `requests`, the pending requests as GitHub answered them.
pub(super) fn verified(
    installations: &[(&str, bool)],
    requests: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "state": "verified",
        "githubLogin": "octocat",
        "installations": installations
            .iter()
            .map(|(id, held)| serde_json::json!({
                "providerInstallationId": id,
                "providerAccountLogin": "acme",
                "providerAccountType": "Organization",
                "heldByOrganization": held
            }))
            .collect::<Vec<_>>(),
        "pendingRequests": requests
    })
}

/// Pending requests GitHub answered, on the accounts `logins`.
pub(super) fn requests_on(logins: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "read": true,
        "items": logins
            .iter()
            .enumerate()
            .map(|(index, login)| serde_json::json!({
                "providerAccountId": (931 + index).to_string(),
                "providerAccountLogin": login,
                "providerAccountType": "Organization"
            }))
            .collect::<Vec<_>>()
    })
}

/// The binding Cloud answers a completion of the GitHub installation `id` with.
fn bound(id: &str) -> Vec<u8> {
    let mut installation = installation_body("active");
    installation["providerInstallationId"] = id.into();
    json_http_response("200 OK", installation)
}

/// The organization's installations: the one on `acme`, GitHub installation `713`, its
/// authority verified where `verified`.
fn held_installation(verified: bool) -> Vec<u8> {
    let mut installation = installation_body("active");
    if !verified {
        installation["authorityVerifiedAt"] = serde_json::Value::Null;
    }
    installation_list(installation)
}

fn setup_begun() -> Vec<u8> {
    json_http_response("201 Created", setup_session())
}

fn read(session: serde_json::Value) -> Vec<u8> {
    json_http_response("200 OK", session)
}

/// The installation the completion `request` named.
fn completed_installation(request: &str) -> serde_json::Value {
    assert!(request.starts_with(&complete_setup()), "{request}");
    serde_json::from_str::<serde_json::Value>(request_body(request)).unwrap()
        ["providerInstallationId"]
        .clone()
}

/// The command that runs the guided setup again.
fn guided_setup() -> String {
    format!("useful org integration connect github --org {ORGANIZATION}")
}

/// Runs `useful org integration connect github --org ORGANIZATION args` against `answers`,
/// where `place` decides whether this machine has a browser, with `opener` the only opener on
/// `PATH`; its output, and the requests.
fn guided(
    answers: Vec<Vec<u8>>,
    opener: &Opener,
    place: Place,
    args: &[&str],
) -> (Output, Vec<String>) {
    let (server, _directory, credential) = super::grant::prepared(answers);
    let output = opener_command(
        &server,
        &credential,
        opener,
        place,
        &[
            &[
                "org",
                "integration",
                "connect",
                "github",
                "--org",
                ORGANIZATION,
            ][..],
            args,
        ]
        .concat(),
    )
    .stdin(Stdio::null())
    .output()
    .unwrap();
    assert_no_secret_output(&output, &[super::grant::TOKEN, "setup-response-sentinel"]);
    (output, server.finish())
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn connect_github_waits_for_the_proof_and_completes_the_installation_it_can() {
    // The list holds 713 verified, so the session completes 717, the one it does not hold
    // verified, once a read answers it verified. A rate-limited read is read again.
    let answers = || {
        vec![
            held_installation(true),
            setup_begun(),
            github_problem(
                "429 Too Many Requests",
                429,
                "https://api.usefulmachinery.com/problems/rate-limit-exceeded",
            ),
            read(unverified_read()),
            read(setup_read(
                "pending",
                verified(&[("713", true), ("717", false)], requests_on(&[])),
            )),
            bound("717"),
        ]
    };
    for place in [Place::Desktop, Place::Headless] {
        let opener = Opener::new(0);
        let (output, requests) = guided(answers(), &opener, place, &["--json"]);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(
            request_lines(&requests),
            [
                LIST_INSTALLATIONS.to_owned(),
                BEGIN_SETUP.to_owned(),
                read_setup(),
                read_setup(),
                read_setup(),
                complete_setup()
            ]
        );
        assert_eq!(completed_installation(&requests[5]), "717");
        let documents = documents(&output);
        assert_eq!(documents.len(), 2, "{documents:?}");
        assert_eq!(documents[0]["outcome"], "pending");
        assert_eq!(documents[0]["session"]["id"], SETUP_SESSION);
        assert_eq!(
            documents[0]["installations"][0]["providerInstallationId"],
            "713"
        );
        assert_eq!(
            documents[0]["installations"][0]["authorityVerifiedAt"],
            "2026-09-05T12:01:00Z"
        );
        assert_eq!(documents[1]["outcome"], "completed");
        assert_eq!(
            documents[1]["installation"]["providerInstallationId"],
            "717"
        );
        // The authorization URL is opened where this machine has a browser, and only there.
        match place {
            Place::Desktop => assert_eq!(opener.opened(1), [format!("1 {}", authorization_url())]),
            _ => assert!(opener.opened(0).is_empty()),
        }
        for request in &requests {
            // The member's session, which `guided` prepares.
            assert_eq!(
                header_value(request, "authorization"),
                format!("Bearer {}", super::grant::TOKEN)
            );
            assert!(useful_test_support::request_header(request, "idempotency-key").is_none());
        }
    }

    // The report names both URLs and the command that shows the session, and no command to
    // complete it, since it completes it itself.
    let (output, _) = guided(answers(), &Opener::new(0), Place::Headless, &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.starts_with("✓ GitHub setup started.\n"), "{text}");
    for named in [
        setup_url(),
        authorization_url(),
        format!("useful org integration show {SETUP_SESSION} --org {ORGANIZATION}"),
    ] {
        assert!(text.contains(&named), "{named} {text}");
    }
    assert!(!text.contains("--installation"), "{text}");

    // A binding the list holds unverified is completed, which verifies it.
    let (output, requests) = guided(
        vec![
            held_installation(false),
            setup_begun(),
            read(setup_read(
                "pending",
                verified(&[("713", true)], requests_on(&[])),
            )),
            bound("713"),
        ],
        &Opener::new(0),
        Place::Headless,
        &["--json"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(completed_installation(&requests[3]), "713");

    // Several candidates and no choice: nothing is completed, and each is named with the
    // command that connects it.
    let choice = || {
        vec![
            held_installation(true),
            setup_begun(),
            read(setup_read(
                "pending",
                verified(&[("715", false), ("717", false)], requests_on(&[])),
            )),
        ]
    };
    let (output, requests) = guided(choice(), &Opener::new(0), Place::Headless, &["--json"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert_eq!(
        request_lines(&requests),
        [
            LIST_INSTALLATIONS.to_owned(),
            BEGIN_SETUP.to_owned(),
            read_setup()
        ]
    );
    assert_eq!(
        documents(&output)[1]["outcome"],
        "installation_choice_required"
    );
    let (output, _) = guided(choice(), &Opener::new(0), Place::Headless, &[]);
    assert_eq!(output.status.code(), Some(2));
    for id in ["715", "717"] {
        let command = format!(
            "useful org integration connect github --installation {id} --org {ORGANIZATION}"
        );
        assert!(stderr(&output).contains(&command), "{}", stderr(&output));
    }

    // The installation named is completed whatever the read lists.
    let (output, requests) = guided(
        vec![
            held_installation(true),
            setup_begun(),
            read(setup_read(
                "pending",
                verified(&[("715", false)], requests_on(&[])),
            )),
            bound("713"),
        ],
        &Opener::new(0),
        Place::Headless,
        &["--installation", "713", "--json"],
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(completed_installation(&requests[3]), "713");
}

#[test]
fn connect_github_ends_with_the_outcome_that_stopped_the_setup() {
    let nothing = || {
        read(setup_read(
            "pending",
            verified(
                &[("713", true)],
                serde_json::json!({"read": true, "items": []}),
            ),
        ))
    };
    let cases: [(&str, Vec<Vec<u8>>); 6] = [
        // A verified read with nothing to complete and no request, or whose requests GitHub did
        // not answer, keeps the wait going.
        (
            "awaiting_approval",
            vec![
                nothing(),
                read(setup_read(
                    "pending",
                    verified(&[], serde_json::json!({"read": false, "items": []})),
                )),
                read(setup_read(
                    "pending",
                    verified(&[], requests_on(&["acme-corp"])),
                )),
            ],
        ),
        (
            "consent_denied",
            vec![read(setup_read(
                "pending",
                serde_json::json!({"state": "denied"}),
            ))],
        ),
        (
            "verification_failed",
            vec![read(setup_read(
                "pending",
                serde_json::json!({"state": "failed"}),
            ))],
        ),
        (
            "expired",
            vec![
                read(unverified_read()),
                read(setup_read(
                    "expired",
                    serde_json::json!({"state": "unverified"}),
                )),
            ],
        ),
        (
            "installation_missing",
            vec![
                nothing(),
                read(setup_read(
                    "expired",
                    verified(&[("713", true)], requests_on(&[])),
                )),
            ],
        ),
        // A completion Cloud refuses is reported as its refusal.
        (
            "source_connection_conflict",
            vec![
                read(setup_read(
                    "pending",
                    verified(&[("717", false)], requests_on(&[])),
                )),
                github_problem(
                    "409 Conflict",
                    409,
                    "https://api.usefulmachinery.com/problems/source-connection-conflict",
                ),
            ],
        ),
    ];
    for (outcome, reads) in cases {
        let answers = [vec![held_installation(true), setup_begun()], reads.clone()].concat();
        let (output, requests) = guided(
            answers.clone(),
            &Opener::new(0),
            Place::Headless,
            &["--json"],
        );
        assert_eq!(
            output.status.code(),
            Some(1),
            "{outcome} {}",
            stderr(&output)
        );
        let documents = documents(&output);
        assert_eq!(documents.len(), 2, "{outcome} {documents:?}");
        assert_eq!(documents[1]["outcome"], outcome);
        assert_eq!(requests.len(), answers.len(), "{outcome} {requests:?}");

        let (output, _) = guided(answers, &Opener::new(0), Place::Headless, &[]);
        assert_eq!(output.status.code(), Some(1), "{outcome}");
        let diagnostic = stderr(&output);
        assert!(diagnostic.starts_with("error: "), "{diagnostic}");
        assert!(!diagnostic.contains("private-github"), "{diagnostic}");
        if outcome == "awaiting_approval" {
            assert!(diagnostic.contains("acme-corp"), "{diagnostic}");
        }
        if outcome != "source_connection_conflict" {
            assert!(diagnostic.contains(&guided_setup()), "{diagnostic}");
        }
        if outcome == "installation_missing" {
            assert!(diagnostic.contains(&setup_url()), "{diagnostic}");
        }
    }
}

#[test]
fn unproven_completion_is_reported_under_the_outcome_a_read_of_the_session_names() {
    let unproven = || github_problem("409 Conflict", 409, AUTHORITY_UNPROVEN);
    let ready = || {
        read(setup_read(
            "pending",
            verified(&[("713", false)], requests_on(&[])),
        ))
    };
    let rerun =
        format!("useful org integration connect github --installation 713 --org {ORGANIZATION}");
    // A verified session is unproven whatever its pending requests, and a read answering it
    // unverified names the URL that verifies it.
    for (after, outcome, named) in [
        (
            setup_read(
                "pending",
                verified(&[("715", false)], requests_on(&["acme-corp"])),
            ),
            "authority_unproven",
            vec![rerun.clone()],
        ),
        (
            unverified_read(),
            "verification_required",
            vec![authorization_url(), rerun.clone()],
        ),
    ] {
        let answers = vec![
            held_installation(true),
            setup_begun(),
            ready(),
            unproven(),
            read(after),
        ];
        let (output, requests) = guided(
            answers.clone(),
            &Opener::new(0),
            Place::Headless,
            &["--installation", "713", "--json"],
        );
        assert_eq!(output.status.code(), Some(1), "{outcome}");
        assert_eq!(documents(&output)[1]["outcome"], outcome);
        assert_eq!(
            request_lines(&requests),
            [
                LIST_INSTALLATIONS.to_owned(),
                BEGIN_SETUP.to_owned(),
                read_setup(),
                complete_setup(),
                read_setup()
            ]
        );
        let (output, _) = guided(
            answers,
            &Opener::new(0),
            Place::Headless,
            &["--installation", "713"],
        );
        let diagnostic = stderr(&output);
        for named in named {
            assert!(diagnostic.contains(&named), "{named} not in {diagnostic}");
        }
        assert!(!diagnostic.contains("private-github"), "{diagnostic}");
    }

    // The read's own failure is reported as `show` reports it.
    let (output, requests) = guided(
        vec![
            held_installation(true),
            setup_begun(),
            ready(),
            unproven(),
            github_problem(
                "404 Not Found",
                404,
                "https://api.usefulmachinery.com/problems/not-found",
            ),
        ],
        &Opener::new(0),
        Place::Headless,
        &["--installation", "713", "--json"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(documents(&output)[1]["outcome"], "not_found");
    assert_eq!(requests.len(), 5);
}

#[test]
fn connect_github_returns_once_begun_with_no_wait_and_stops_at_its_timeout() {
    for json in [true, false] {
        let args: &[&str] = if json {
            &["--no-wait", "--json"]
        } else {
            &["--no-wait"]
        };
        let opener = Opener::new(0);
        let (output, requests) = guided(
            vec![held_installation(true), setup_begun()],
            &opener,
            Place::Desktop,
            args,
        );
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(request_lines(&requests), [LIST_INSTALLATIONS, BEGIN_SETUP]);
        assert_eq!(opener.opened(1), [format!("1 {}", authorization_url())]);
        if json {
            let documents = documents(&output);
            assert_eq!(documents.len(), 1, "{documents:?}");
            assert_eq!(documents[0]["outcome"], "pending");
            assert_eq!(documents[0]["session"]["id"], SETUP_SESSION);
            assert_eq!(
                documents[0]["session"]["authorizationUrl"],
                authorization_url()
            );
            assert!(!String::from_utf8_lossy(&output.stdout).contains("setup-response-sentinel"));
        } else {
            // Nothing waits to complete the session, so the report names the command that
            // connects the installation once both steps are done.
            let stdout = String::from_utf8_lossy(&output.stdout);
            let command = format!(
                "useful org integration connect github --installation <INSTALLATION_ID> --org {ORGANIZATION}"
            );
            assert!(stdout.contains(&command), "{stdout}");
        }
    }

    // A refused begin sends no completion, and a member who is not an owner is refused before
    // any session begins; nothing is opened.
    for (answers, sent) in [
        (
            vec![
                held_installation(true),
                github_problem(
                    "403 Forbidden",
                    403,
                    "https://api.usefulmachinery.com/problems/forbidden",
                ),
            ],
            2,
        ),
        (
            vec![github_problem(
                "403 Forbidden",
                403,
                "https://api.usefulmachinery.com/problems/forbidden",
            )],
            1,
        ),
    ] {
        let opener = Opener::new(0);
        let (output, requests) = guided(answers, &opener, Place::Desktop, &["--json"]);
        assert_ne!(output.status.code(), Some(0));
        let documents = documents(&output);
        assert_eq!(documents.len(), 1, "{documents:?}");
        assert_eq!(documents[0]["outcome"], "forbidden");
        assert_eq!(requests.len(), sent);
        assert!(opener.opened(0).is_empty());
    }

    // A wait that outlasts --timeout ends `timed_out`, naming the session.
    for json in [true, false] {
        let mut server = ScriptedServer::respond_with_paused_last_response(vec![
            held_installation(true),
            setup_begun(),
            read(unverified_read()),
        ]);
        let directory = private_credential_directory();
        let credential = directory.path().join("credentials.json");
        write_credential_fixture(&credential, &server.api_url, TOKEN, "2999-01-01T00:00:00Z");
        let credential = credential.to_string_lossy().into_owned();
        let mut args = org_connection(&["connect", "github", "--timeout", "1s"]);
        if json {
            args.push("--json");
        }
        let output = run_with_env(&args, &headless(&server.api_url, &credential));
        server.release_paused_response();
        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        if json {
            let documents = documents(&output);
            assert_eq!(documents.len(), 2, "{documents:?}");
            assert_eq!(documents[1]["outcome"], "timed_out");
            assert_eq!(documents[1]["sessionId"], SETUP_SESSION);
        } else {
            assert!(
                stderr(&output).contains(SETUP_SESSION),
                "{}",
                stderr(&output)
            );
        }
        assert_eq!(
            request_lines(&server.finish()),
            [
                LIST_INSTALLATIONS.to_owned(),
                BEGIN_SETUP.to_owned(),
                read_setup()
            ]
        );
    }
}

/// The organization's list of bindings holding `installation` alone.
pub(super) fn installation_list(installation: serde_json::Value) -> Vec<u8> {
    json_http_response("200 OK", serde_json::json!({"items": [installation]}))
}

#[test]
fn reconnect_of_a_disconnected_binding_completes_a_session_for_its_own_installation() {
    let setup_url =
        format!("https://github.example/apps/scherzo/installations/new?state={SETUP_SESSION}");
    // The session is read until it is verified, and only then completed for the binding's own
    // installation, whatever else the verified login could complete.
    let (server, _directory, credential_path) = prepared_github(vec![
        installation_list(installation_body("disconnected")),
        setup_session_response(SETUP_SESSION, &setup_url),
        json_http_response("200 OK", unverified_read()),
        json_http_response(
            "200 OK",
            setup_read(
                "pending",
                verified(&[("713", true), ("717", false)], requests_on(&[])),
            ),
        ),
        json_http_response("200 OK", installation_body("active")),
    ]);

    let output = run_with_env(
        &org_connection(&["reconnect", INSTALLATION, "--json"]),
        &headless(&server.api_url, &credential_path),
    );

    assert!(output.status.success(), "{output:?}");
    let documents = documents(&output);
    assert_eq!(documents.len(), 2, "{documents:?}");
    assert_eq!(documents[0]["outcome"], "pending");
    assert_eq!(
        documents[0]["session"]["authorizationUrl"],
        authorization_url()
    );
    let document = &documents[1];
    assert_eq!(document["outcome"], "completed");
    assert_eq!(document["installation"]["id"], INSTALLATION);
    assert_eq!(document["installation"]["state"], "active");
    let requests = server.finish();
    assert_eq!(
        request_lines(&requests),
        [
            LIST_INSTALLATIONS.to_owned(),
            BEGIN_SETUP.to_owned(),
            read_setup(),
            read_setup(),
            complete_setup()
        ]
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request_body(&requests[4])).unwrap(),
        serde_json::json!({"providerInstallationId": "713"})
    );
}

#[test]
fn reconnect_of_a_completion_that_names_another_binding_is_a_protocol_failure() {
    let setup_url =
        format!("https://github.example/apps/scherzo/installations/new?state={SETUP_SESSION}");
    let mut other = installation_body("active");
    other["id"] = serde_json::Value::String("ghi_01k0z6r1w8f4jy2m7q9v3x5abd".to_owned());
    let (server, _directory, credential_path) = prepared_github(vec![
        installation_list(installation_body("disconnected")),
        setup_session_response(SETUP_SESSION, &setup_url),
        json_http_response(
            "200 OK",
            setup_read("pending", verified(&[("713", true)], requests_on(&[]))),
        ),
        json_http_response("200 OK", other),
    ]);

    let output = run_with_env(
        &org_connection(&["reconnect", INSTALLATION, "--json"]),
        &headless(&server.api_url, &credential_path),
    );

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(documents(&output)[1]["outcome"], "invalid_response");
    assert_eq!(server.finish().len(), 4);
}

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

#[test]
fn options_of_another_provider_are_refused_before_any_request() {
    let (server, _directory, credential_path) = prepared_github(Vec::new());
    let environment = deployment_environment(&server.api_url, &credential_path);

    for args in [
        &["connect", "github", "--state-updates"][..],
        &["connect", "github", "--no-wait", "--timeout", "5m"][..],
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
        &["reconnect", INSTALLATION, "--no-wait", "--timeout", "5m"][..],
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
    assert_eq!(
        installations_json["items"][0]["connection"]["authorityVerifiedAt"],
        "2026-09-05T12:01:00Z"
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
                "updatedAt": "2026-09-05T12:01:00Z",
                "authorityVerifiedAt": "2026-09-05T12:01:00Z"
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
    // The installations' authorizations in force are read after them.
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
        installation_list(installation_body("active")),
        setup_session_response(SETUP_SESSION, "https://github.example/apps/scherzo"),
        json_http_response(
            "200 OK",
            setup_read("pending", verified(&[("713", false)], requests_on(&[]))),
        ),
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
    let environment = headless(&server.api_url, &credential_path);

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
            // The guided setup prints the session it began before its ending.
            let body = documents(&output).pop().unwrap();
            (
                output.status.code(),
                body["outcome"].as_str().unwrap().to_owned(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(server.finish().len(), 6);
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

#[test]
fn replayable_connection_mutations_retry_one_ambiguous_transport_failure() {
    let setup = || setup_session_response(SETUP_SESSION, "https://github.example/apps/scherzo");
    let read = || {
        json_http_response(
            "200 OK",
            setup_read("pending", verified(&[("713", true)], requests_on(&[]))),
        )
    };
    let cases = [
        (
            org_connection(&["connect", "github", "--installation", "713", "--json"]),
            vec![
                installation_list(installation_body("active")),
                setup(),
                read(),
            ],
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
                read(),
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
        let environment = headless(&server.api_url, &credential_path);

        let output = run_with_env(&args, &environment);

        assert!(output.status.success(), "{args:?}: {output:?}");
        let value = documents(&output).pop().unwrap();
        assert_eq!(value["outcome"], expected_outcome);
        assert_eq!(value["installation"]["state"], state);
        assert!(output.stderr.is_empty());
        let requests = server.finish();
        assert_eq!(requests.len(), before + 2, "{args:?}");
        assert_eq!(requests[before], requests[before + 1]);
        assert!(requests[before].starts_with(&expected_request));
    }
}

#[test]
fn meaningful_api_failures_have_closed_json_and_exit_statuses() {
    let cases = [
        (
            github_problem(
                "409 Conflict",
                409,
                "https://api.usefulmachinery.com/problems/source-connection-conflict",
            ),
            list_repositories(INSTALLATION)[..7].to_vec(),
            "source_connection_conflict",
            1,
        ),
        // Only a completion can be refused for unproven authority.
        (
            github_problem("409 Conflict", 409, AUTHORITY_UNPROVEN),
            list_repositories(INSTALLATION)[..7].to_vec(),
            "invalid_response",
            1,
        ),
    ];

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

#[test]
fn setup_conflict_is_actionable_on_standard_error_without_problem_prose() {
    let response = github_problem(
        "409 Conflict",
        409,
        "https://api.usefulmachinery.com/problems/source-connection-conflict",
    );
    let (server, _directory, credential_path) = prepared_github(vec![
        installation_list(installation_body("active")),
        setup_session_response(SETUP_SESSION, "https://github.example/apps/scherzo"),
        json_http_response(
            "200 OK",
            setup_read("pending", verified(&[("713", true)], requests_on(&[]))),
        ),
        response,
    ]);
    let environment = headless(&server.api_url, &credential_path);

    let output = run_with_env(
        &org_connection(&["connect", "github", "--installation", "713"]),
        &environment,
    );

    assert_eq!(output.status.code(), Some(1));
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(diagnostic.starts_with("error: "), "{diagnostic}");
    let (_, remedy) = diagnostic.split_once("\n\n").unwrap();
    assert!(remedy.contains("\n  useful org integration list\n"));
    assert!(remedy.contains("\n  useful org integration connect github\n"));
    assert!(!diagnostic.contains("private-github"));
    assert!(!diagnostic.contains(TOKEN));
    assert_eq!(server.finish().len(), 4);
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

#[test]
fn remote_insecure_setup_url_is_rejected_before_browser_handoff() {
    let unsafe_setup_url = "http://github.example/private-setup-url-sentinel";
    let unsafe_authorization_url =
        "http://github.example/login/oauth/private-authorization-sentinel";
    for (setup_url, authorization_url) in [
        (unsafe_setup_url.to_owned(), authorization_url()),
        (setup_url(), unsafe_authorization_url.to_owned()),
    ] {
        for json in [true, false] {
            let response = json_http_response(
                "201 Created",
                serde_json::json!({
                    "id": SETUP_SESSION,
                    "state": "pending",
                    "expiresAt": "2026-09-05T12:10:00Z",
                    "setupUrl": setup_url,
                    "authorizationUrl": authorization_url,
                    "verification": {"state": "unverified"}
                }),
            );
            let opener = Opener::new(0);
            let mut args = vec!["--no-wait"];
            if json {
                args.push("--json");
            }
            let (output, requests) = guided(
                vec![held_installation(true), response],
                &opener,
                Place::Desktop,
                &args,
            );

            assert_eq!(output.status.code(), Some(1), "{args:?}");
            if json {
                assert_eq!(documents(&output)[0]["outcome"], "invalid_response");
                assert!(output.stderr.is_empty());
            } else {
                assert!(output.stdout.is_empty());
            }
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!combined.contains(&setup_url), "{combined}");
            assert!(!combined.contains(&authorization_url), "{combined}");
            assert_eq!(requests.len(), 2);
            assert!(opener.opened(0).is_empty());
        }
    }
}

#[test]
fn begin_answer_without_an_unverified_authorization_is_a_protocol_failure() {
    let mut without_authorization = setup_session();
    without_authorization
        .as_object_mut()
        .unwrap()
        .remove("authorizationUrl");
    let mut verified = setup_session();
    verified["verification"] = serde_json::json!({
        "state": "verified",
        "githubLogin": "octocat",
        "installations": []
    });
    let mut expired = setup_session();
    expired["state"] = serde_json::Value::String("expired".to_owned());
    for answer in [without_authorization, verified, expired] {
        let (output, requests) = guided(
            vec![
                held_installation(true),
                json_http_response("201 Created", answer.clone()),
            ],
            &Opener::new(0),
            Place::Headless,
            &["--json"],
        );

        assert_eq!(output.status.code(), Some(1), "{answer}");
        assert_eq!(
            documents(&output)[0]["outcome"],
            "invalid_response",
            "{answer}"
        );
        assert_eq!(requests.len(), 2);
    }
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

/// An installation whose authority Cloud has not verified.
fn unverified_installation_body() -> serde_json::Value {
    let mut installation = installation_body("active");
    installation["id"] = serde_json::Value::String("ghi_01k0z6r1w8f4jy2m7q9v3x5abd".to_owned());
    installation["providerInstallationId"] = serde_json::Value::String("714".to_owned());
    installation["authorityVerifiedAt"] = serde_json::Value::Null;
    installation
}

#[test]
fn installations_show_when_their_authority_was_verified() {
    let list = || {
        json_http_response(
            "200 OK",
            serde_json::json!({
                "items": [installation_body("active"), unverified_installation_body()]
            }),
        )
    };
    let repositories = || {
        json_http_response(
            "200 OK",
            serde_json::json!({"installation": unverified_installation_body(), "items": []}),
        )
    };
    let (server, _directory, credential_path) = prepared_github(vec![
        list(),
        super::connection::no_authorizations(),
        super::connection::no_authorizations(),
        list(),
        repositories(),
    ]);
    let environment = deployment_environment(&server.api_url, &credential_path);
    let list_args = [
        "org",
        "integration",
        "list",
        "--provider",
        "github",
        "--org",
        ORGANIZATION,
        "--allow-insecure-http",
    ];

    let listed = run_with_env(&list_args, &environment);
    assert!(listed.status.success(), "{listed:?}");
    let rows: Vec<String> = String::from_utf8(listed.stdout)
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("ghi_"))
        .map(str::to_owned)
        .collect();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows[0].contains("2026-09-05T12:01:00Z"), "{}", rows[0]);
    assert!(!rows[0].contains("not verified"), "{}", rows[0]);
    assert!(rows[1].contains("not verified"), "{}", rows[1]);

    let shown = run_with_env(
        &[
            "org",
            "integration",
            "show",
            "ghi_01k0z6r1w8f4jy2m7q9v3x5abd",
            "--org",
            ORGANIZATION,
            "--allow-insecure-http",
        ],
        &environment,
    );
    assert!(shown.status.success(), "{shown:?}");
    let shown = String::from_utf8(shown.stdout).unwrap();
    assert!(
        shown
            .lines()
            .any(|line| line.contains("Authority:") && line.contains("not verified")),
        "{shown}"
    );
    assert_eq!(server.finish().len(), 5);
}

fn show_setup_args(json: bool) -> Vec<&'static str> {
    let mut args = vec![
        "org",
        "integration",
        "show",
        SETUP_SESSION,
        "--org",
        ORGANIZATION,
        "--allow-insecure-http",
    ];
    if json {
        args.push("--json");
    }
    args
}

fn verified_with(pending_requests: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "state": "verified",
        "githubLogin": "octocat",
        "installations": [
            {
                "providerInstallationId": "713",
                "providerAccountLogin": "acme",
                "providerAccountType": "Organization",
                "heldByOrganization": false
            },
            {
                "providerInstallationId": "715",
                "providerAccountLogin": "octocat",
                "providerAccountType": "User",
                "heldByOrganization": true
            }
        ],
        "pendingRequests": pending_requests
    })
}

#[test]
fn show_of_a_setup_session_reads_where_its_verification_stands() {
    let unverified = unverified_read();
    let verified = setup_read(
        "pending",
        verified_with(serde_json::json!({
            "read": true,
            "items": [{
                "providerAccountId": "931",
                "providerAccountLogin": "acme-corp",
                "providerAccountType": "Organization"
            }]
        })),
    );
    let unanswered = setup_read(
        "pending",
        verified_with(serde_json::json!({"read": false, "items": []})),
    );
    let expired = setup_read("expired", serde_json::json!({"state": "unverified"}));

    for (answer, shown_in_report) in [
        (&unverified, vec![authorization_url()]),
        (
            &verified,
            vec![
                "octocat".to_owned(),
                "acme-corp".to_owned(),
                format!(
                    "useful org integration connect github --installation 713 --org {ORGANIZATION}"
                ),
                format!(
                    "useful org integration connect github --installation 715 --org {ORGANIZATION}"
                ),
            ],
        ),
        (
            &unanswered,
            vec!["octocat".to_owned(), "713".to_owned(), "715".to_owned()],
        ),
        (&expired, vec!["expired".to_owned(), guided_setup()]),
    ] {
        let (server, _directory, credential_path) = prepared_github(vec![
            json_http_response("200 OK", answer.clone()),
            json_http_response("200 OK", answer.clone()),
        ]);
        let environment = deployment_environment(&server.api_url, &credential_path);

        let shown = run_with_env(&show_setup_args(true), &environment);

        assert_eq!(shown.status.code(), Some(0), "{answer}");
        assert!(shown.stderr.is_empty());
        let mut expected_session = answer.clone();
        expected_session.as_object_mut().unwrap().remove("future");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&shown.stdout).unwrap(),
            serde_json::json!({
                "schemaVersion": 1,
                "deployment": server.api_url,
                "organizationRef": ORGANIZATION,
                "outcome": "shown",
                "session": expected_session
            })
        );

        let report = run_with_env(&show_setup_args(false), &environment);

        assert_eq!(report.status.code(), Some(0), "{answer}");
        assert!(report.stderr.is_empty());
        let report = String::from_utf8(report.stdout).unwrap();
        assert!(report.contains(SETUP_SESSION), "{report}");
        for expected in shown_in_report {
            assert!(report.contains(&expected), "{expected} in {report}");
        }
        assert!(!report.contains("setup-response-sentinel"), "{report}");

        let requests = server.finish();
        assert_eq!(request_lines(&requests), [read_setup(), read_setup()]);
        for request in requests {
            assert_eq!(
                header_value(&request, "authorization"),
                format!("Bearer {TOKEN}")
            );
        }
    }
}

#[test]
fn show_of_a_setup_session_reports_refusals_and_unsafe_reads_as_the_other_commands_do() {
    let mut other_session = unverified_read();
    other_session["id"] = serde_json::Value::String("ghs_01k0z6r1w8f4jy2m7q9v3x5abd".to_owned());
    let mut unsafe_authorization = unverified_read();
    unsafe_authorization["authorizationUrl"] = serde_json::Value::String(
        "http://github.example/login/oauth/private-authorization-sentinel".to_owned(),
    );
    let cases = [
        (
            github_problem(
                "404 Not Found",
                404,
                "https://api.usefulmachinery.com/problems/not-found",
            ),
            "not_found",
        ),
        (
            json_http_response("200 OK", other_session),
            "invalid_response",
        ),
        (
            json_http_response("200 OK", unsafe_authorization),
            "invalid_response",
        ),
    ];

    for (response, expected_outcome) in cases {
        let (server, _directory, credential_path) = prepared_github(vec![response]);
        let environment = deployment_environment(&server.api_url, &credential_path);

        let output = run_with_env(&show_setup_args(true), &environment);

        assert_eq!(output.status.code(), Some(1), "{expected_outcome}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["outcome"], expected_outcome);
        assert_eq!(value["organizationRef"], ORGANIZATION);
        let combined = String::from_utf8_lossy(&output.stdout);
        assert!(!combined.contains("private-"), "{combined}");
        assert!(output.stderr.is_empty());
        assert_eq!(server.finish().len(), 1);
    }
}
