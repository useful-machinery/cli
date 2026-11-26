use super::runner_enrollment::*;
use super::*;

fn start(host: &JoinHost) -> ServeProcess {
    host.serve(
        &[
            "--ephemeral",
            "--join-key-file",
            host.key_file.to_str().unwrap(),
        ],
        &[],
    )
}

fn connected(witness: &ConnectionWitness, mut serve: ServeProcess) -> (ServeProcess, String) {
    match witness.next_connection(&mut serve) {
        Some(request) => (serve, header_value(&request, "authorization").to_owned()),
        None => panic!("Runner Serve stopped before connecting: {}", serve.stop()),
    }
}

fn assert_clean(host: &JoinHost) {
    let directory = host.state.parent().unwrap().join("ephemeral");
    for name in [
        "runner-state.json",
        ".runner-enrollment.json",
        ".runner-agent-login",
    ] {
        assert!(!directory.join(name).exists(), "{name}");
    }
}

#[test]
fn a_file_or_environment_key_joins_and_a_stop_retires_with_the_joined_credential() {
    for from_variable in [false, true] {
        let witness = ConnectionWitness::retiring(http_response("204 No Content", None, b""));
        let answer = join_response_body(0, &witness.url);
        let server = api_test_support::ScriptedHttpServer::respond(join_response(0, &witness.url));
        let artifact = join_key_artifact(&join_base(&server), &future_expiry());
        let host = JoinHost::new(&artifact);
        let serve = if from_variable {
            host.serve(&["--ephemeral"], &[(JOIN_KEY_VARIABLE, &artifact)])
        } else {
            start(&host)
        };
        let (serve, bearer) = connected(&witness, serve);
        let (id, secret) = bearer
            .strip_prefix("Bearer ")
            .unwrap()
            .split_once('.')
            .unwrap();
        assert_eq!(id, answer["credentialId"]);
        assert_join_request(&server.finish_one(), secret);

        let (status, stderr) = serve.terminate();

        assert_eq!(status.code(), Some(0), "{stderr}");
        let requests = witness.received();
        let retirements: Vec<_> = requests.iter().filter(|r| r.starts_with("POST ")).collect();
        assert_eq!(retirements.len(), 1);
        let request = retirements[0];
        assert!(request.starts_with("POST /v1/runner/registration/retire HTTP/1.1\r\n"));
        assert_eq!(header_value(request, "authorization"), bearer);
        let body: serde_json::Value =
            serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"schemaVersion": 1, "runnerId": answer["runnerId"]})
        );
        assert!(!host.state.exists());
        assert_clean(&host);
    }
}

#[test]
fn serving_ephemerally_preserves_the_hosts_enrolled_identity() {
    let original = ConnectionWitness::new();
    let witness = ConnectionWitness::retiring(http_response("204 No Content", None, b""));
    let server = api_test_support::ScriptedHttpServer::respond(join_response(0, &witness.url));
    let host = JoinHost::new(&join_key_artifact(&join_base(&server), &future_expiry()));
    host.write_enrolled_state(&original.url);
    let state = fs::read(&host.state).unwrap();

    let (serve, bearer) = connected(&witness, start(&host));
    let (status, stderr) = serve.terminate();

    assert_eq!(status.code(), Some(0), "{stderr}");
    let (_, secret) = bearer
        .strip_prefix("Bearer ")
        .unwrap()
        .split_once('.')
        .unwrap();
    assert_join_request(&server.finish_one(), secret);
    assert_eq!(fs::read(&host.state).unwrap(), state);
    assert_eq!(
        connection_bearer(host.serve(&[], &[]), &original),
        format!("Bearer {CURRENT_CREDENTIAL_ID}.{CURRENT_SECRET}")
    );
}

#[test]
fn a_missing_retirement_endpoint_names_the_kept_runner_and_exits_successfully() {
    let witness = ConnectionWitness::retiring(http_response("404 Not Found", None, b""));
    let server = api_test_support::ScriptedHttpServer::respond(join_response(0, &witness.url));
    let host = JoinHost::new(&join_key_artifact(&join_base(&server), &future_expiry()));
    let (serve, _) = connected(&witness, start(&host));

    let (status, stderr) = serve.terminate();

    assert_eq!(status.code(), Some(0), "{stderr}");
    let runner = join_response_body(0, &witness.url);
    assert!(
        stderr.contains(&format!(
            "useful runner delete {}",
            runner["runnerId"].as_str().unwrap()
        )),
        "{stderr}"
    );
    server.finish_one();
    assert_clean(&host);
}

#[test]
fn a_refused_connection_exits_without_rejoining_or_retiring() {
    let witness = ConnectionWitness::rejecting();
    let join = ConnectionWitness::answering_every_request(join_response(0, &witness.url));
    let host = JoinHost::new(&join_key_artifact(&join.base, &future_expiry()));

    let (status, stderr) = start(&host).wait_for_exit();

    assert_eq!(status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("--ephemeral"), "{stderr}");
    assert_eq!(join.received().len(), 1);
    let requests = witness.received();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /v1/runner/connect "));
    assert_clean(&host);
}

#[test]
fn an_ephemeral_start_requires_a_pool_key_and_excludes_other_registration_modes() {
    let cloud = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", cloud.local_addr().unwrap());
    let host = JoinHost::new(&activation_artifact(&base, ACTIVATION_ID).to_string());
    for args in [
        vec![],
        vec!["--join-key-file", host.key_file.to_str().unwrap()],
        vec!["--personal"],
        vec!["--pool", "ci"],
        vec!["--replace-credential"],
    ] {
        let mut flags = vec!["--ephemeral"];
        flags.extend(args);
        let (status, stderr) = host.serve(&flags, &[]).wait_for_exit();
        assert_eq!(status.code(), Some(2), "{flags:?}: {stderr}");
        if flags.len() == 1 {
            assert!(stderr.contains("--join-key-file"), "{stderr}");
        }
        assert_clean(&host);
    }
    assert_silent(&cloud);
}

#[test]
fn a_second_ephemeral_start_is_refused_before_it_joins() {
    let witness = ConnectionWitness::retiring(http_response("204 No Content", None, b""));
    let join = ConnectionWitness::answering_every_request(join_response(0, &witness.url));
    let host = JoinHost::new(&join_key_artifact(&join.base, &future_expiry()));
    let (serve, _) = connected(&witness, start(&host));

    let (status, stderr) = start(&host).wait_for_exit();

    assert_eq!(status.code(), Some(1), "{stderr}");
    assert_eq!(join.received().len(), 1);
    let (status, stderr) = serve.terminate();
    assert_eq!(status.code(), Some(0), "{stderr}");
}

#[tokio::test]
async fn an_idle_timeout_ends_ephemeral_service_and_retires_the_registration() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    use super::runner_status::{
        accept_runner_connection_answering, accept_runner_socket, cloud_observation_ack,
        cloud_welcome,
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/v1/runner/connect", listener.local_addr().unwrap());
    let server = api_test_support::ScriptedHttpServer::respond(join_response(0, &url));
    let host = JoinHost::new(&join_key_artifact(&join_base(&server), &future_expiry()));
    let serve = host.serve(
        &[
            "--ephemeral",
            "--join-key-file",
            host.key_file.to_str().unwrap(),
            "--idle-timeout",
            "1s",
        ],
        &[],
    );
    let retirements = std::sync::Mutex::new(Vec::new());
    let routes = |request: &[u8]| {
        let request = String::from_utf8_lossy(request).into_owned();
        if request.starts_with("POST /v1/runner/registration/retire ") {
            retirements.lock().unwrap().push(request);
            http_response("204 No Content", None, b"")
        } else {
            http_response("404 Not Found", None, b"")
        }
    };
    let mut socket =
        accept_runner_socket(accept_runner_connection_answering(&listener, &routes).await).await;
    // The connection ends when the idle runner stops; no signal is sent to it.
    while let Some(Ok(Message::Text(text))) = socket.next().await {
        let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
        if frame["type"] == "hello" {
            socket.send(cloud_welcome()).await.unwrap();
        }
        if let Some(message_id) = frame["messageId"].as_str() {
            let sequence = frame["sequence"].as_u64().unwrap();
            socket
                .send(cloud_observation_ack(message_id, sequence))
                .await
                .unwrap();
        }
    }
    let mut exited = tokio::task::spawn_blocking(move || serve.wait_for_exit());
    let (status, stderr) = tokio::select! {
        _ = accept_runner_connection_answering(&listener, &routes) => {
            panic!("the idle ephemeral runner reconnected")
        }
        exited = &mut exited => exited.unwrap(),
    };

    assert_eq!(status.code(), Some(0), "{stderr}");
    let runner = join_response_body(0, &url);
    let retirements = retirements.into_inner().unwrap();
    assert_eq!(retirements.len(), 1, "{stderr}");
    let body: serde_json::Value =
        serde_json::from_str(retirements[0].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body["runnerId"], runner["runnerId"]);
    server.finish_one();
    assert_clean(&host);
}
