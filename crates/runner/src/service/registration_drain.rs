use std::time::Duration;

use reqwest::StatusCode;

use crate::control_protocol::ControlError;
use crate::runner_http::{self, Target};

const PATH: &str = "/v1/runner/registration/drain";
pub(crate) const CONTROL_TIMEOUT: Duration =
    runner_http::REQUEST_TIMEOUT.saturating_add(Duration::from_secs(2));

pub(super) async fn drain(target: Target) -> Result<(), ControlError> {
    let answer = tokio::task::spawn_blocking(move || {
        let credential = target.credential();
        let body = serde_json::json!({"schemaVersion": 1, "runnerId": credential.runner_id()});
        runner_http::post_json_with_client(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never()),
            &target.url(PATH),
            credential,
            body.to_string().into_bytes(),
            &[],
            runner_http::REQUEST_TIMEOUT,
            None,
        )
    })
    .await
    .map_err(|_| ControlError::DrainFailed)?;
    let status = answer
        .map_err(|failure| match failure {
            runner_http::Failure::Unavailable => ControlError::CloudUnreachable,
            runner_http::Failure::InvalidResponse | runner_http::Failure::Cancelled => {
                ControlError::DrainFailed
            }
        })?
        .status;
    match status {
        StatusCode::NO_CONTENT => Ok(()),
        StatusCode::UNAUTHORIZED => Err(ControlError::DrainCredentialRefused),
        StatusCode::NOT_FOUND => Err(ControlError::DrainNotServed),
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
            Err(ControlError::CloudUnreachable)
        }
        _ => Err(ControlError::DrainFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    use crate::credential::test_credential;
    use crate::runner_http::test_server::{broker_headers, read_request, write_response};
    use serde_json::Value;
    use url::Url;

    const REQUEST: &str =
        include_str!("../../../../tests/fixtures/runner-registration-retirement/v1/request.json");

    #[tokio::test]
    async fn registration_drain_posts_once_and_reports_what_cloud_answered() {
        for (reply, expected) in [
            (Some("204 No Content"), Ok(())),
            (
                Some("401 Unauthorized"),
                Err(ControlError::DrainCredentialRefused),
            ),
            (Some("404 Not Found"), Err(ControlError::DrainNotServed)),
            (
                Some("429 Too Many Requests"),
                Err(ControlError::CloudUnreachable),
            ),
            (
                Some("503 Service Unavailable"),
                Err(ControlError::CloudUnreachable),
            ),
            (
                Some("307 Temporary Redirect"),
                Err(ControlError::DrainFailed),
            ),
            (Some("200 OK"), Err(ControlError::DrainFailed)),
            (Some("400 Bad Request"), Err(ControlError::DrainFailed)),
            (None, Err(ControlError::CloudUnreachable)),
        ] {
            let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let endpoint = Url::parse(&format!(
                "ws://{}/v1/runner/connect",
                listener.local_addr().unwrap()
            ))
            .unwrap();
            let target = Target::new(&endpoint, &test_credential()).unwrap();
            let task = tokio::spawn(drain(target));
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_request(&mut stream);
                if let Some(status) = reply {
                    let additional = if status == "307 Temporary Redirect" {
                        "Location: /another-endpoint\r\n"
                    } else {
                        ""
                    };
                    write_response(&mut stream, status, &broker_headers(additional, ""), "");
                }
                (request, listener)
            });
            assert_eq!(task.await.unwrap(), expected, "{reply:?}");
            let (request, listener) = server.join().unwrap();
            listener.set_nonblocking(true).unwrap();
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert_eq!(
                request.head.lines().next(),
                Some("POST /v1/runner/registration/drain HTTP/1.1")
            );
            let bearer = request
                .head
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .and_then(|(_, value)| value.trim().strip_prefix("Bearer "));
            assert_eq!(bearer, Some(test_credential().bearer_value()));
            assert_eq!(
                serde_json::from_str::<Value>(&request.body).unwrap(),
                serde_json::from_str::<Value>(REQUEST).unwrap()
            );
        }
    }

    #[tokio::test]
    async fn registration_drain_reports_a_closed_listener_as_unreachable() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = Url::parse(&format!(
            "ws://{}/v1/runner/connect",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        drop(listener);
        let target = Target::new(&endpoint, &test_credential()).unwrap();
        assert_eq!(drain(target).await, Err(ControlError::CloudUnreachable));
    }
}
