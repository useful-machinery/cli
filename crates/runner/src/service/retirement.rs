use std::fmt;
use std::time::Duration;

use reqwest::StatusCode;
use serde::Deserialize;
use useful_execution::CaptureCancellation;

use super::{Backoff, Shutdown, Sleeper};
use crate::runner_http::{self, Target};

const RETIRE_PATH: &str = "/v1/runner/registration/retire";
const BUDGET: Duration = Duration::from_secs(60);

/// The result of giving back a runner's own registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Retirement {
    Retired,
    Kept(RetirementCause),
}

/// Why the runner could not confirm its retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementCause {
    CredentialNotAccepted,
    EndpointMissing,
    InvalidRequest,
    RegistrationNotJoined,
    UnsupportedAnswer,
    WorkHeld,
    Unreachable,
    Abandoned,
    CouldNotStart,
}

impl fmt::Display for RetirementCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CredentialNotAccepted => "Cloud refused the runner credential",
            Self::EndpointMissing => "Cloud does not serve the retirement endpoint",
            Self::InvalidRequest => "Cloud refused the retirement request",
            Self::RegistrationNotJoined => "Cloud reports that the runner did not join with a key",
            Self::UnsupportedAnswer => "Cloud returned an unsupported retirement answer",
            Self::WorkHeld => "Cloud still holds reserved or unfinished work for the runner",
            Self::Unreachable => "Cloud was unreachable",
            Self::Abandoned => "a further stop signal abandoned retirement",
            Self::CouldNotStart => "the runner could not start retirement",
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Refusal {
    schema_version: u32,
    reason: RefusalReason,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RefusalReason {
    RegistrationNotJoined,
    CapacityReserved,
    NonterminalAssignment,
}

enum Attempt {
    Done(Retirement),
    Retry(RetirementCause, Duration),
}

fn classify(response: Result<runner_http::Response, runner_http::Failure>) -> Attempt {
    use RetirementCause as Cause;
    let cause = match response {
        Err(runner_http::Failure::Unavailable) => {
            return Attempt::Retry(Cause::Unreachable, Duration::ZERO);
        }
        Err(runner_http::Failure::InvalidResponse) => Cause::UnsupportedAnswer,
        Err(runner_http::Failure::Cancelled) => Cause::Abandoned,
        Ok(response) => match response.status {
            StatusCode::NO_CONTENT => return Attempt::Done(Retirement::Retired),
            StatusCode::UNAUTHORIZED => Cause::CredentialNotAccepted,
            StatusCode::NOT_FOUND => Cause::EndpointMissing,
            StatusCode::BAD_REQUEST => Cause::InvalidRequest,
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
                return Attempt::Retry(
                    Cause::Unreachable,
                    response.retry_after.unwrap_or_default(),
                );
            }
            StatusCode::CONFLICT => match serde_json::from_slice::<Refusal>(&response.body) {
                Ok(Refusal {
                    schema_version: 1,
                    reason,
                }) => match reason {
                    RefusalReason::RegistrationNotJoined => Cause::RegistrationNotJoined,
                    RefusalReason::CapacityReserved | RefusalReason::NonterminalAssignment => {
                        return Attempt::Retry(Cause::WorkHeld, Duration::ZERO);
                    }
                },
                _ => Cause::UnsupportedAnswer,
            },
            _ => Cause::UnsupportedAnswer,
        },
    };
    Attempt::Done(Retirement::Kept(cause))
}

/// Run each HTTP request on the blocking pool. A stop reaches both the retry
/// wait and the blocking request, including a partially received refusal.
pub(super) async fn retire(
    target: Target,
    sleeper: &dyn Sleeper,
    shutdown: &mut dyn Shutdown,
    mut backoff: Backoff,
) -> Retirement {
    let deadline = sleeper.now() + BUDGET;
    let remaining = || deadline.saturating_duration_since(sleeper.now());
    let cancellation = CaptureCancellation::default();
    let mut last_cause = RetirementCause::Unreachable;
    loop {
        let timeout = remaining().min(runner_http::REQUEST_TIMEOUT);
        if timeout.is_zero() {
            return Retirement::Kept(last_cause);
        }
        let attempt = async {
            let target = target.clone();
            let fence = cancellation.clone();
            tokio::task::spawn_blocking(move || {
                let credential = target.credential();
                let body =
                    serde_json::json!({"schemaVersion": 1, "runnerId": credential.runner_id()});
                runner_http::post_json(
                    &target.url(RETIRE_PATH),
                    credential,
                    body.to_string().into_bytes(),
                    &[StatusCode::CONFLICT],
                    timeout,
                    Some(&fence),
                )
            })
            .await
        };
        let result = tokio::select! {
            biased;
            () = shutdown.wait() => {
                cancellation.cancel();
                return Retirement::Kept(RetirementCause::Abandoned);
            }
            result = attempt => result,
        };
        let Ok(result) = result else {
            return Retirement::Kept(RetirementCause::CouldNotStart);
        };
        match classify(result) {
            Attempt::Done(outcome) => return outcome,
            Attempt::Retry(cause, retry_after) => {
                last_cause = cause;
                let delay = backoff.next_delay().max(retry_after).min(remaining());
                tokio::select! {
                    biased;
                    () = shutdown.wait() => return Retirement::Kept(RetirementCause::Abandoned),
                    () = sleeper.sleep(delay) => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    use serde_json::Value;
    use url::Url;

    use super::*;
    use crate::credential::test_credential;
    use crate::runner_http::test_server::{broker_headers, read_request, write_response};
    use crate::service::test_support::{controlled_shutdown, controlled_sleeper, with_watchdog};

    const REQUEST: &str =
        include_str!("../../../../tests/fixtures/runner-registration-retirement/v1/request.json");
    const REFUSAL: &str =
        include_str!("../../../../tests/fixtures/runner-registration-retirement/v1/refusal.json");

    // None closes the connection after reading the request without giving an answer.
    type Reply<'a> = Option<(&'static str, &'static str, &'a str)>;

    async fn run(replies: &[Reply<'_>], delays: &[u64], stop_during_last_wait: bool) -> Retirement {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = Url::parse(&format!(
            "ws://{}/v1/runner/connect",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let replies = replies
            .iter()
            .map(|reply| reply.map(|(status, headers, body)| (status, headers, body.to_owned())))
            .collect::<Vec<_>>();
        let server = thread::spawn(move || {
            let credential = test_credential();
            let expected: Value = serde_json::from_str(REQUEST).unwrap();
            for reply in replies {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_request(&mut stream);
                assert_eq!(
                    request.head.lines().next(),
                    Some("POST /v1/runner/registration/retire HTTP/1.1")
                );
                let bearer = request
                    .head
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                    .and_then(|(_, value)| value.trim().strip_prefix("Bearer "));
                assert_eq!(bearer, Some(credential.bearer_value()));
                assert_eq!(
                    serde_json::from_str::<Value>(&request.body).unwrap(),
                    expected
                );
                if let Some((status, headers, body)) = reply {
                    write_response(&mut stream, status, &broker_headers(headers, &body), &body);
                }
            }
        });
        let target = Target::new(&endpoint, &test_credential()).unwrap();
        let (sleeper, mut sleeps) = controlled_sleeper();
        let (mut shutdown, stop) = controlled_shutdown();
        let task = tokio::spawn(async move {
            retire(
                target,
                sleeper.as_ref(),
                shutdown.as_mut(),
                Backoff::with_fixed_unit(1.0),
            )
            .await
        });
        for (index, delay) in delays.iter().enumerate() {
            let (duration, release) = with_watchdog(sleeps.recv()).await.unwrap().unwrap();
            assert_eq!(duration, Duration::from_secs(*delay));
            if stop_during_last_wait && index + 1 == delays.len() {
                stop.notify_one();
            } else {
                release.release();
            }
        }
        let result = with_watchdog(task).await.unwrap().unwrap();
        server.join().unwrap();
        result
    }

    #[tokio::test]
    async fn retirement_posts_the_fixture_and_accepts_no_content() {
        assert_eq!(
            run(&[Some(("204 No Content", "", ""))], &[], false).await,
            Retirement::Retired
        );
    }

    #[tokio::test]
    async fn retirement_retries_both_work_refusals() {
        let unfinished = REFUSAL.replace("capacity_reserved", "nonterminal_assignment");
        let replies = [
            Some(("409 Conflict", "", REFUSAL)),
            Some(("409 Conflict", "", &unfinished)),
            Some(("204 No Content", "", "")),
        ];
        assert_eq!(run(&replies, &[1, 2], false).await, Retirement::Retired);
    }

    #[tokio::test]
    async fn retirement_retries_a_lost_answer_and_observes_retry_after_within_its_budget() {
        let replies = [
            None,
            Some(("503 Service Unavailable", "Retry-After: 59\r\n", "")),
        ];
        assert_eq!(
            run(&replies, &[1, 59], false).await,
            Retirement::Kept(RetirementCause::Unreachable)
        );
    }

    #[tokio::test]
    async fn retirement_definite_refusals_keep_their_causes_without_retry() {
        let not_joined = REFUSAL.replace("capacity_reserved", "registration_not_joined");
        for (status, body, cause) in [
            (
                "401 Unauthorized",
                "",
                RetirementCause::CredentialNotAccepted,
            ),
            ("404 Not Found", "", RetirementCause::EndpointMissing),
            ("400 Bad Request", "", RetirementCause::InvalidRequest),
            (
                "409 Conflict",
                not_joined.as_str(),
                RetirementCause::RegistrationNotJoined,
            ),
            ("409 Conflict", "{}", RetirementCause::UnsupportedAnswer),
        ] {
            assert_eq!(
                run(&[Some((status, "", body))], &[], false).await,
                Retirement::Kept(cause)
            );
        }
    }

    #[tokio::test]
    async fn retirement_abandons_its_wait_on_shutdown() {
        assert_eq!(
            run(&[Some(("409 Conflict", "", REFUSAL))], &[1], true).await,
            Retirement::Kept(RetirementCause::Abandoned)
        );
    }
}
