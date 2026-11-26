//! The CLI lifecycle shared by providers that authorize a connection through a consent session.
use std::io::{self, Write};
use std::time::Duration;

use anyhow::Context;
use serde::Serialize;
use useful_human_auth::Deployment;

use crate::cli::{
    CommonArgs, JsonOutputKind, PrincipalAuthenticationArgs, PrincipalAuthenticationKind,
    ceremony_poll_interval, wait_for_poll,
};
use crate::exit_code::ExitCode;

/// The options of a leaf that starts an authorization session, whose `--json` writes one
/// document per state.
pub(super) type Options =
    CommonArgs<super::super::super::StreamingJson, PrincipalAuthenticationArgs>;

/// The provider operations used while starting, observing or removing a connection.
pub(super) trait Provider: Sized {
    const NAME: &'static str;
    const AUTHORIZATION_CONTEXT: &'static str;
    const LIFECYCLE_CONTEXT: &'static str;

    type Session;
    type Failure;
    type StartOptions: Send + 'static;

    fn with_api<F: JsonOutputKind, T>(
        deployment: &Deployment,
        options: &CommonArgs<F, PrincipalAuthenticationArgs>,
        f: impl FnMut(&Self) -> Result<T, Self::Failure>,
    ) -> anyhow::Result<Result<T, Self::Failure>>;

    fn start(
        &self,
        org: &str,
        connection: Option<&str>,
        key: &str,
        options: &Self::StartOptions,
    ) -> Result<Self::Session, Self::Failure>;
    fn session(&self, org: &str, id: &str) -> Result<Self::Session, Self::Failure>;
    fn session_id(session: &Self::Session) -> &str;
    fn pending(session: &Self::Session) -> bool;
    fn unreachable(failure: &Self::Failure) -> bool;
    fn polling_backoff(failure: &Self::Failure) -> Option<Duration>;
    fn session_output(
        deployment: &Deployment,
        org: &str,
        session: &Self::Session,
        json: bool,
    ) -> anyhow::Result<ExitCode>;
    fn failure_output(
        deployment: &Deployment,
        org: &str,
        id: Option<&str>,
        key: Option<&str>,
        failure: &Self::Failure,
        auth: PrincipalAuthenticationKind,
        json: bool,
    ) -> anyhow::Result<ExitCode>;
}

// A lost response may have committed the mutation. Replay only the original keyed request.
fn retry_unreachable<P: Provider, T>(
    mut call: impl FnMut() -> Result<T, P::Failure>,
) -> Result<T, P::Failure> {
    match call() {
        Err(error) if P::unreachable(&error) => call(),
        result => result,
    }
}

#[derive(Clone)]
struct Recovery {
    session: Option<String>,
}

/// Starts an authorization session in `organization`, connecting a new workspace, or with
/// `connection` reauthorizing that connection, and waits for it up to `timeout` unless
/// `--no-wait` was given.
pub(super) fn authorize<P: Provider>(
    deployment: Deployment,
    options: Options,
    organization: String,
    connection: Option<String>,
    start_options: P::StartOptions,
    no_wait: bool,
    timeout: Option<Duration>,
) -> super::super::super::CommandResult {
    let key = useful_support::generate_idempotency_key()
        .with_context(|| format!("generate {} authorization request key", P::NAME))?;
    let timeout = if no_wait {
        None
    } else {
        Some(timeout.unwrap_or(Duration::from_secs(900)))
    };
    let recovery = Recovery { session: None };
    let signal_deployment = deployment.clone();
    let signal_organization = organization.clone();
    let json = options.json;
    let timeout_deployment = signal_deployment.clone();
    let timeout_organization = signal_organization.clone();
    super::super::super::execute_mutation_with_signals_and_deferred_timeout(
        P::AUTHORIZATION_CONTEXT,
        recovery,
        timeout,
        move |control, timeout_start| {
            if !control.begin_dispatch() {
                return Ok(ExitCode::Interrupted);
            }
            let result = P::with_api(&deployment, &options, |api| {
                retry_unreachable::<P, _>(|| {
                    api.start(&organization, connection.as_deref(), &key, &start_options)
                })
            })?;
            let session = match result {
                Ok(session) => session,
                Err(failure) => {
                    return finish(control, || {
                        P::failure_output(
                            &deployment,
                            &organization,
                            None,
                            None,
                            &failure,
                            options.authentication.kind(),
                            json,
                        )
                    });
                }
            };
            if !control.update_recovery(Recovery {
                session: Some(P::session_id(&session).to_owned()),
            }) {
                return Ok(ExitCode::Interrupted);
            }
            if no_wait || !P::pending(&session) {
                return finish(control, || {
                    P::session_output(&deployment, &organization, &session, json)
                });
            }
            if control.is_cancelled() {
                return Ok(ExitCode::Interrupted);
            }
            P::session_output(&deployment, &organization, &session, json)?;
            timeout_start.start();
            observe::<P>(
                &deployment,
                &organization,
                P::session_id(&session),
                &options,
                control,
            )
        },
        move |signal, snapshot| {
            if !snapshot.dispatched {
                return Ok(signal);
            }
            stopped::<P>(
                &signal_deployment,
                &signal_organization,
                &snapshot.recovery,
                signal,
                json,
            )
        },
        {
            let d = timeout_deployment;
            let org = timeout_organization;
            move |snapshot| {
                stopped::<P>(&d, &org, &snapshot.recovery, ExitCode::GeneralFailure, json)
            }
        },
    )
}

fn finish<R>(
    control: &super::super::super::OperationControl<R>,
    output: impl FnOnce() -> anyhow::Result<ExitCode>,
) -> super::super::super::CommandResult {
    super::super::super::complete_operation(control, || output().map_err(Into::into))
}
fn stopped<P: Provider>(
    d: &Deployment,
    org: &str,
    recovery: &Recovery,
    signal: ExitCode,
    json: bool,
) -> super::super::super::CommandResult {
    status_output::<P>(
        d,
        org,
        stop_outcome(signal),
        recovery.session.as_deref(),
        json,
    )?;
    Ok(signal)
}

fn stop_outcome(signal: ExitCode) -> &'static str {
    if signal == ExitCode::GeneralFailure {
        "timed_out"
    } else {
        "observation_stopped"
    }
}

fn observe<P: Provider>(
    d: &Deployment,
    org: &str,
    id: &str,
    options: &Options,
    control: &super::super::super::OperationControl<Recovery>,
) -> super::super::super::CommandResult {
    let mut next = ceremony_poll_interval();
    loop {
        if !wait_for_poll(control, next, &super::super::super::SystemObservationClock) {
            return Ok(ExitCode::Interrupted);
        }
        let result = P::with_api(d, options, |api| api.session(org, id))?;
        match result {
            Ok(session) if P::pending(&session) => next = ceremony_poll_interval(),
            Ok(session) => {
                return finish(control, || {
                    P::session_output(d, org, &session, options.json)
                });
            }
            Err(failure) => {
                if let Some(delay) = P::polling_backoff(&failure) {
                    next = delay;
                    continue;
                }
                return finish(control, || {
                    P::failure_output(
                        d,
                        org,
                        Some(id),
                        None,
                        &failure,
                        options.authentication.kind(),
                        options.json,
                    )
                });
            }
        }
    }
}

/// Shows the authorization session `session` of `organization` to the owner who started
/// it.
pub(super) fn show_session<P: Provider, F: JsonOutputKind>(
    d: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    session: &str,
) -> anyhow::Result<ExitCode> {
    match P::with_api(d, options, |api| api.session(organization, session))? {
        Ok(read) => P::session_output(d, organization, &read, options.json),
        Err(failure) => P::failure_output(
            d,
            organization,
            Some(session),
            None,
            &failure,
            options.authentication.kind(),
            options.json,
        ),
    }
}
/// Disconnects or deletes the connection `connection` of `organization`, repeating the
/// request once with the same key after an ambiguous transport failure.
pub(super) fn remove<P: Provider, F: JsonOutputKind + Send + 'static, T>(
    d: Deployment,
    options: CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: String,
    connection: String,
    mutate: impl Fn(&P, &str, &str, &str) -> Result<T, P::Failure> + Send + 'static,
    output: impl FnOnce(&Deployment, &str, &str, T, bool) -> anyhow::Result<ExitCode> + Send + 'static,
) -> super::super::super::CommandResult {
    let key = useful_support::generate_idempotency_key()
        .with_context(|| format!("generate {} lifecycle request key", P::NAME))?;
    let signal_d = d.clone();
    let signal_org = organization.clone();
    let signal_id = connection.clone();
    let signal_key = key.clone();
    let json = options.json;
    super::super::super::execute_mutation_with_signals(
        P::LIFECYCLE_CONTEXT,
        (),
        move |control| {
            if !control.begin_dispatch() {
                return Ok(ExitCode::Interrupted);
            }
            let result = P::with_api(&d, &options, |api| {
                retry_unreachable::<P, _>(|| mutate(api, &organization, &connection, &key))
            })?;
            finish(control, || match result {
                Ok(read) => output(&d, &organization, &connection, read, json),
                Err(failure) => P::failure_output(
                    &d,
                    &organization,
                    None,
                    Some(&key),
                    &failure,
                    options.authentication.kind(),
                    json,
                ),
            })
        },
        move |signal, snapshot| {
            if !snapshot.dispatched {
                return Ok(signal);
            }
            lifecycle_stopped::<P>(
                &signal_d,
                &signal_org,
                &signal_id,
                &signal_key,
                signal,
                json,
            )
        },
    )
}
fn lifecycle_stopped<P: Provider>(
    d: &Deployment,
    org: &str,
    id: &str,
    key: &str,
    signal: ExitCode,
    json: bool,
) -> super::super::super::CommandResult {
    let output = || -> anyhow::Result<()> {
        if json {
            emit(
                &serde_json::json!({"schemaVersion":1,"deployment":d.fingerprint().api_url(),
                "organizationRef":org,"connectionId":id,"idempotencyKey":key,"outcome":"commitment_unknown"}),
            )?;
        } else {
            writeln!(
                io::stderr().lock(),
                "error: {} connection operation interrupted\nconnection: {id}\nrequest key: {key}\n\nShow the connection before repeating this operation.",
                P::NAME
            )?;
        }
        Ok(())
    };
    output().map_err(super::super::super::CommandFailure::from)?;
    Ok(signal)
}

fn status_output<P: Provider>(
    d: &Deployment,
    org: &str,
    outcome: &str,
    id: Option<&str>,
    json: bool,
) -> anyhow::Result<()> {
    if json {
        emit(
            &serde_json::json!({"schemaVersion":1,"deployment":d.fingerprint().api_url(),"organizationRef":org,"outcome":outcome,"sessionId":id}),
        )
    } else {
        let mut err = io::stderr().lock();
        writeln!(
            err,
            "error: {} authorization {}",
            P::NAME,
            outcome.replace('_', " ")
        )?;
        if let Some(id) = id {
            writeln!(err, "session: {id}")?;
        }
        writeln!(
            err,
            "\nIf a session is known, show it before starting another authorization. Otherwise, inspect existing connections with the initiating owner before retrying."
        )?;
        Ok(())
    }
}
pub(super) fn emit(value: &impl Serialize) -> anyhow::Result<()> {
    super::super::super::write_json_line(value).context("write JSON connection event")
}
#[cfg(test)]
mod tests {
    use super::super::super::super::{CEREMONY_POLL_INTERVAL, POLL_WAIT_SLICE};
    use super::*;
    use crate::cli::retry_delay;

    #[test]
    fn polling_rate_limit_never_precedes_retry_after() {
        assert_eq!(retry_delay(Some(9)), Duration::from_secs(9));
        assert_eq!(retry_delay(None), CEREMONY_POLL_INTERVAL);
        assert_eq!(retry_delay(Some(0)), CEREMONY_POLL_INTERVAL);
        assert_eq!(retry_delay(Some(3)), CEREMONY_POLL_INTERVAL);
        assert_eq!(retry_delay(Some(600)), Duration::from_secs(600));
        assert_eq!(stop_outcome(ExitCode::GeneralFailure), "timed_out");
        assert_eq!(stop_outcome(ExitCode::Interrupted), "observation_stopped");
    }

    #[test]
    fn poll_wait_honors_cadence_and_server_backoff_without_real_time() {
        let clock =
            super::super::super::super::observation_test_support::ControlledObservationClock::new(
                useful_support::monotonic_now(),
            );
        let control = super::super::super::super::OperationControl::new(Recovery { session: None });
        assert!(wait_for_poll(&control, CEREMONY_POLL_INTERVAL, &clock));
        assert!(wait_for_poll(&control, retry_delay(Some(9)), &clock));
        let sleeps = clock.into_sleeps();
        assert!(sleeps.iter().all(|slice| *slice <= POLL_WAIT_SLICE));
        assert_eq!(sleeps.iter().sum::<Duration>(), Duration::from_secs(14));
    }

    #[test]
    fn long_retry_after_stops_when_observation_is_cancelled() {
        use std::cell::Cell;
        use std::time::Instant;

        struct CancellingClock<'a> {
            now: Cell<Instant>,
            slices: Cell<usize>,
            control: &'a super::super::super::super::OperationControl<Recovery>,
        }
        impl super::super::super::super::ObservationClock for CancellingClock<'_> {
            fn now(&self) -> Instant {
                self.now.get()
            }
            fn sleep(&self, duration: Duration) {
                self.now.set(self.now.get() + duration);
                self.slices.set(self.slices.get() + 1);
                let _ = self.control.claim_signal();
            }
        }
        let control = super::super::super::super::OperationControl::new(Recovery {
            session: Some("known-session".into()),
        });
        let clock = CancellingClock {
            now: Cell::new(useful_support::monotonic_now()),
            slices: Cell::new(0),
            control: &control,
        };
        assert!(!wait_for_poll(&control, retry_delay(Some(3600)), &clock));
        assert_eq!(clock.slices.get(), 1);
        assert_eq!(control.recovery().session.as_deref(), Some("known-session"));
    }
}
