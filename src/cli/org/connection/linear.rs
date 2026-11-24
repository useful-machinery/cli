//! Linear through `useful org integration`: the authorization sessions `create linear` and
//! `reconnect` start and observe, and the reads and removals of a Linear connection.
use super::authorization::InForce;
use std::io::{self, Write};
use std::time::Duration;

use anyhow::{Context, anyhow};
use clap::Args;
use serde::Serialize;

use crate::exit_code::{ExitCode, OutcomeClass};
use useful_api::{
    HttpClient, LinearApi, LinearConnection, LinearFailure, LinearSession, LinearSessionStatus,
    linear_authorization_session::Operation,
};
use useful_human_auth::Deployment;

use super::super::super::{
    CommonArgs, JsonOutputKind, PrincipalAuthenticationArgs, ceremony_poll_interval, retry_delay,
    wait_for_poll,
};

/// The options of a leaf that starts a Linear authorization session, whose `--json` writes one
/// document per state.
pub(super) type Options =
    CommonArgs<super::super::super::StreamingJson, PrincipalAuthenticationArgs>;

/// How `create linear` and `reconnect` of a Linear connection authorize and whether they
/// wait; the command's `--timeout` bounds the wait.
#[derive(Debug, Args)]
pub(super) struct Authorization {
    #[arg(long, help = "Request Linear state-update write permission")]
    state_updates: bool,
    #[arg(
        long,
        conflicts_with = "timeout",
        help = "Return after starting consent instead of waiting for the callback"
    )]
    no_wait: bool,
}

impl Authorization {
    /// The first of these options given, which a connection of another provider
    /// refuses.
    pub(super) fn given(&self) -> Option<&'static str> {
        self.state_updates_given()
            .or_else(|| self.no_wait.then_some("--no-wait"))
    }

    /// `--state-updates`, where given, which Linear alone takes.
    pub(super) fn state_updates_given(&self) -> Option<&'static str> {
        self.state_updates.then_some("--state-updates")
    }

    /// Whether `--no-wait` was given, which GitHub's setup takes too.
    pub(super) const fn no_wait(&self) -> bool {
        self.no_wait
    }
}

/// A page of a Linear discovery read, as `--limit` and `--cursor` select it.
type Page = super::super::super::PaginationArgs<100>;

/// Runs `f` against Linear's routes under the credential `options` select.
pub(in crate::cli) fn with_api<F: JsonOutputKind, T>(
    deployment: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    mut f: impl FnMut(&LinearApi) -> Result<T, LinearFailure>,
) -> anyhow::Result<Result<T, LinearFailure>> {
    let policy = options.http.transport_policy();
    let client = HttpClient::new(policy)
        .map_err(|error| anyhow!(error))
        .context("prepare human session networking")?;
    super::super::super::execute_selected_api_operation(
        super::super::super::principal_api_context(
            &client,
            deployment,
            &options.authentication,
            "acquire human session",
        ),
        |token| {
            let api = LinearApi::new(deployment.fingerprint().api_url(), token, policy)
                .map_err(|error| anyhow!(error))
                .context("prepare Linear connection networking")?;
            Ok(f(&api))
        },
        LinearFailure::credential_rejected,
        || LinearFailure::Unauthenticated,
        |category| LinearFailure::Unreachable { category },
    )
}

#[derive(Clone)]
struct Recovery {
    session: Option<String>,
}

/// Starts a Linear authorization session in `organization`, connecting a new workspace, or with
/// `connection` reauthorizing that connection, and waits for it up to `timeout` unless
/// `--no-wait` was given.
pub(super) fn authorize(
    deployment: Deployment,
    options: Options,
    organization: String,
    connection: Option<String>,
    authorization: Authorization,
    timeout: Option<Duration>,
) -> super::super::super::CommandResult {
    let key = useful_support::generate_idempotency_key()
        .context("generate Linear authorization request key")?;
    let Authorization {
        state_updates,
        no_wait,
    } = authorization;
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
        "Linear authorization",
        recovery,
        timeout,
        move |control, timeout_start| {
            if !control.begin_dispatch() {
                return Ok(ExitCode::Interrupted);
            }
            let result = with_api(&deployment, &options, |api| {
                // A lost response may have committed the session. Replay only this key.
                match api.start(&organization, connection.as_deref(), &key, state_updates) {
                    Err(LinearFailure::Unreachable { .. }) => {
                        api.start(&organization, connection.as_deref(), &key, state_updates)
                    }
                    result => result,
                }
            })?;
            let session = match result {
                Ok(session) => session,
                Err(failure) => {
                    return finish(control, || {
                        failure_output(
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
                session: Some(session.id.clone()),
            }) {
                return Ok(ExitCode::Interrupted);
            }
            if no_wait || session.status != LinearSessionStatus::LinearSessionPending {
                return finish(control, || {
                    session_output(&deployment, &organization, &session, json)
                });
            }
            if control.is_cancelled() {
                return Ok(ExitCode::Interrupted);
            }
            session_output(&deployment, &organization, &session, json)?;
            timeout_start.start();
            observe(&deployment, &organization, &session.id, &options, control)
        },
        move |signal, snapshot| {
            if !snapshot.dispatched {
                return Ok(signal);
            }
            stopped(
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
            move |snapshot| stopped(&d, &org, &snapshot.recovery, ExitCode::GeneralFailure, json)
        },
    )
}

fn finish<R>(
    control: &super::super::super::OperationControl<R>,
    output: impl FnOnce() -> anyhow::Result<ExitCode>,
) -> super::super::super::CommandResult {
    super::super::super::complete_operation(control, || output().map_err(Into::into))
}
fn stopped(
    d: &Deployment,
    org: &str,
    recovery: &Recovery,
    signal: ExitCode,
    json: bool,
) -> super::super::super::CommandResult {
    status_output(
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

fn observe(
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
        let result = with_api(d, options, |api| api.session(org, id))?;
        match result {
            Ok(session) if session.status == LinearSessionStatus::LinearSessionPending => {
                next = ceremony_poll_interval()
            }
            Ok(session) => {
                return finish(control, || session_output(d, org, &session, options.json));
            }
            Err(LinearFailure::RateLimited { retry_after }) => next = retry_delay(retry_after),
            Err(failure) => {
                return finish(control, || {
                    failure_output(
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

#[cfg(test)]
mod tests {
    use super::super::super::super::{CEREMONY_POLL_INTERVAL, POLL_WAIT_SLICE};
    use super::*;

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

/// Shows the Linear authorization session `session` of `organization` to the owner who started
/// it.
pub(super) fn show_session<F: JsonOutputKind>(
    d: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    session: &str,
) -> anyhow::Result<ExitCode> {
    match with_api(d, options, |api| api.session(organization, session))? {
        Ok(read) => session_output(d, organization, &read, options.json),
        Err(failure) => failure_output(
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
/// Shows the Linear connection `connection` of `organization`.
pub(super) fn show<F: JsonOutputKind>(
    d: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    connection: &str,
    authorizations: Option<&InForce>,
) -> anyhow::Result<ExitCode> {
    match with_api(d, options, |api| api.connection(organization, connection))? {
        Ok(read) => connection_output(
            d,
            organization,
            connection,
            Some(&read),
            ("shown", authorizations),
            options.json,
        ),
        Err(failure) => failure_output(
            d,
            organization,
            None,
            None,
            &failure,
            options.authentication.kind(),
            options.json,
        ),
    }
}
/// What `useful org integration disconnect` does to a Linear connection.
#[derive(Clone, Copy)]
pub(super) enum Action {
    /// Disconnects it and keeps its workspace held.
    Disconnect,
    /// Deletes it and releases its workspace.
    Delete,
}
impl Action {
    const fn outcome(self) -> &'static str {
        match self {
            Self::Disconnect => "disconnected",
            Self::Delete => "deleted",
        }
    }
}
/// Disconnects or deletes the Linear connection `connection` of `organization`, repeating the
/// request once with the same key after an ambiguous transport failure.
pub(super) fn remove<F: JsonOutputKind + Send + 'static>(
    d: Deployment,
    options: CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: String,
    connection: String,
    action: Action,
) -> super::super::super::CommandResult {
    let key = useful_support::generate_idempotency_key()
        .context("generate Linear lifecycle request key")?;
    let signal_d = d.clone();
    let signal_org = organization.clone();
    let signal_id = connection.clone();
    let signal_key = key.clone();
    let json = options.json;
    super::super::super::execute_mutation_with_signals(
        "Linear connection lifecycle",
        (),
        move |control| {
            if !control.begin_dispatch() {
                return Ok(ExitCode::Interrupted);
            }
            let result = with_api(&d, &options, |api| {
                let call = || match action {
                    Action::Disconnect => {
                        api.disconnect(&organization, &connection, &key).map(Some)
                    }
                    Action::Delete => api.delete(&organization, &connection, &key).map(|()| None),
                };
                match call() {
                    Err(LinearFailure::Unreachable { .. }) => call(),
                    result => result,
                }
            })?;
            finish(control, || match result {
                Ok(read) => connection_output(
                    &d,
                    &organization,
                    &connection,
                    read.as_ref(),
                    (action.outcome(), None),
                    json,
                ),
                Err(failure) => failure_output(
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
            lifecycle_stopped(
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
/// Lists one page of the teams the Linear connection `connection` of `organization`
/// reaches.
pub(super) fn list_teams<F: JsonOutputKind>(
    d: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    connection: &str,
    page: &Page,
) -> anyhow::Result<ExitCode> {
    let read = with_api(d, options, |api| {
        api.teams(
            organization,
            connection,
            page.limit.map(i32::from),
            page.cursor.as_deref(),
        )
    })?;
    discovered(d, options, organization, read, |page| {
        if options.json {
            return emit(
                &serde_json::json!({"schemaVersion":1,"deployment":d.fingerprint().api_url(),"organizationRef":organization,"connectionId":connection,"outcome":"listed","items":page.items,"nextCursor":page.next_cursor}),
            );
        }
        let mut out = io::stdout().lock();
        for team in &page.items {
            writeln!(out, "{}  {}", team.id, team.name)?;
        }
        if let Some(cursor) = page.next_cursor {
            writeln!(out, "next cursor: {cursor}")?;
        }
        Ok(())
    })
}
/// Lists one page of the workflow states of the Linear team `team` that the connection
/// `connection` of `organization` reaches, with the states suggested for each preset.
pub(super) fn list_states<F: JsonOutputKind>(
    d: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    connection: &str,
    team: &str,
    page: &Page,
) -> anyhow::Result<ExitCode> {
    let read = with_api(d, options, |api| {
        api.states(
            organization,
            connection,
            team,
            page.limit.map(i32::from),
            page.cursor.as_deref(),
        )
    })?;
    discovered(d, options, organization, read, |page| {
        if options.json {
            return emit(
                &serde_json::json!({"schemaVersion":1,"deployment":d.fingerprint().api_url(),"organizationRef":organization,"connectionId":connection,"teamId":team,"outcome":"listed","items":page.items,"presetSuggestions":page.preset_suggestions,"nextCursor":page.next_cursor}),
            );
        }
        let mut out = io::stdout().lock();
        for state in &page.items {
            writeln!(out, "{}  {}  {}", state.id, state.name, state.r#type)?;
        }
        writeln!(
            out,
            "suggestions: {}",
            serde_json::to_string(&page.preset_suggestions)?
        )?;
        if let Some(cursor) = page.next_cursor {
            writeln!(out, "next cursor: {cursor}")?;
        }
        Ok(())
    })
}
/// Writes a discovery read: its page with `write`, or its refusal.
fn discovered<F: JsonOutputKind, T>(
    d: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    read: Result<T, LinearFailure>,
    write: impl FnOnce(T) -> anyhow::Result<()>,
) -> anyhow::Result<ExitCode> {
    match read {
        Ok(page) => {
            write(page)?;
            Ok(ExitCode::Success)
        }
        Err(failure) => failure_output(
            d,
            organization,
            None,
            None,
            &failure,
            options.authentication.kind(),
            options.json,
        ),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionView<'a> {
    id: &'a str,
    operation: &'a Operation,
    status: &'a LinearSessionStatus,
    connection_id: Option<&'a str>,
    reason_code: Option<&'a useful_api::linear_authorization_session::ReasonCode>,
    authorization_url: Option<&'a str>,
    expires_at: &'a str,
    requested_scopes: Option<Vec<&'static str>>,
    result_connection: Option<ConnectionView<'a>>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::cli) struct ConnectionView<'a> {
    id: &'a str,
    status: &'a useful_api::linear_connection::Status,
    workspace_id: Option<&'a str>,
    workspace_name: Option<&'a str>,
    app_user_id: Option<&'a str>,
    required_scopes: Vec<&'a useful_api::linear_connection::RequiredScopes>,
    granted_scopes: &'a [String],
    state_updates_consented: bool,
    lifecycle_generation: i64,
    activation_cutoff: Option<&'a str>,
    last_error: Option<&'a useful_api::linear_connection_error::LinearConnectionError>,
}
pub(in crate::cli) fn connection_view(c: &LinearConnection) -> ConnectionView<'_> {
    ConnectionView {
        id: &c.id,
        status: &c.status,
        workspace_id: c.workspace_id.as_deref(),
        workspace_name: c.workspace_name.as_deref(),
        app_user_id: c.app_user_id.as_deref(),
        required_scopes: c.required_scopes.iter().collect(),
        granted_scopes: &c.granted_scopes,
        state_updates_consented: c.state_updates_consented,
        lifecycle_generation: c.lifecycle_generation,
        activation_cutoff: c.activation_cutoff.as_deref(),
        last_error: c.last_error.as_deref(),
    }
}
fn session_view(s: &LinearSession) -> SessionView<'_> {
    SessionView {
        id: &s.id,
        operation: &s.operation,
        status: &s.status,
        connection_id: s.connection_id.as_deref(),
        reason_code: s.reason_code.as_ref(),
        authorization_url: s.authorization_url.as_deref(),
        expires_at: &s.expires_at,
        requested_scopes: s.requested_scopes.as_ref().map(|scopes| {
            let mut values: Vec<_> = scopes
                .iter()
                .map(|scope| match scope {
                    useful_api::linear_authorization_session::RequestedScopes::Read => "read",
                    useful_api::linear_authorization_session::RequestedScopes::Write => "write",
                })
                .collect();
            values.sort_unstable();
            values
        }),
        result_connection: s.result_connection.as_deref().map(connection_view),
    }
}
pub(in crate::cli) fn status(s: &useful_api::linear_connection::Status) -> &'static str {
    use useful_api::linear_connection::Status::*;
    match s {
        Active => "active",
        Disconnected => "disconnected",
        RecoveryRequired => "recovery_required",
        Deleted => "deleted",
    }
}
fn emit(value: &impl Serialize) -> anyhow::Result<()> {
    super::super::super::write_json_line(value).context("write JSON connection event")
}
fn session_output(
    d: &Deployment,
    org: &str,
    s: &LinearSession,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let outcome = match s.status {
        LinearSessionStatus::LinearSessionPending => "pending",
        LinearSessionStatus::LinearSessionCompleted => "completed",
        LinearSessionStatus::LinearSessionFailed => "failed",
        LinearSessionStatus::LinearSessionExpired => "expired",
        LinearSessionStatus::LinearSessionRecoveryRequired => "recovery_required",
    };
    if json {
        emit(
            &serde_json::json!({"schemaVersion":1,"deployment":d.fingerprint().api_url(),"organizationRef":org,"outcome":outcome,"session":session_view(s)}),
        )?;
    } else {
        let mut out = io::stdout().lock();
        writeln!(
            out,
            "Linear authorization: {}\nsession: {}\norganization: {org}\nexpires: {}",
            outcome.replace('_', " "),
            s.id,
            s.expires_at
        )?;
        if let Some(scopes) = session_view(s).requested_scopes {
            writeln!(out, "requested scopes: {}", scopes.join(", "))?;
        }
        if let Some(connection) = &s.result_connection {
            writeln!(
                out,
                "connection: {} ({})",
                connection.id,
                status(&connection.status)
            )?;
        }
        if let Some(reason) = &s.reason_code {
            writeln!(
                out,
                "reason: {}",
                serde_json::to_value(reason)?.as_str().unwrap_or("unknown")
            )?;
        }
        writeln!(out, "deployment: {}", d.fingerprint().api_url())?;
        if let Some(url) = &s.authorization_url {
            writeln!(out, "\nOpen this URL to approve the workspace:\n  {url}")?;
        } else if s.status == LinearSessionStatus::LinearSessionRecoveryRequired {
            writeln!(
                out,
                "\nShow the connection and deliberately reauthorize it if needed."
            )?;
        } else if matches!(
            s.status,
            LinearSessionStatus::LinearSessionFailed | LinearSessionStatus::LinearSessionExpired
        ) {
            match (&s.operation, &s.connection_id) {
                (Operation::Reauthorize, Some(connection)) => writeln!(
                    out,
                    "\nReauthorize the connection again:\n  useful org integration reconnect {connection}"
                )?,
                _ => writeln!(
                    out,
                    "\nConnect the workspace again:\n  useful org integration connect linear"
                )?,
            }
        }
    }
    Ok(
        if matches!(
            s.status,
            LinearSessionStatus::LinearSessionFailed
                | LinearSessionStatus::LinearSessionExpired
                | LinearSessionStatus::LinearSessionRecoveryRequired
        ) {
            ExitCode::GeneralFailure
        } else {
            ExitCode::Success
        },
    )
}
fn connection_output(
    d: &Deployment,
    org: &str,
    id: &str,
    connection: Option<&LinearConnection>,
    // The outcome, and the runners' authorizations in force for the connection where `show`
    // read them.
    (outcome, authorizations): (&str, Option<&InForce>),
    json: bool,
) -> anyhow::Result<ExitCode> {
    if json {
        let mut document = serde_json::json!({"schemaVersion":1,"deployment":d.fingerprint().api_url(),"organizationRef":org,"outcome":outcome,"connectionId":id,"connection":connection.map(connection_view)});
        if let Some(authorizations) = authorizations {
            document["authorizations"] =
                serde_json::to_value(authorizations).context("serialize the authorizations")?;
        }
        emit(&document)?;
    } else {
        let mut out = io::stdout().lock();
        writeln!(out, "Linear connection: {outcome}\nconnection: {id}")?;
        if let Some(c) = connection {
            writeln!(
                out,
                "status: {}\nworkspace: {} ({})\nrequired scopes: read\ngranted scopes: {}\nstate updates consented: {}\ngeneration: {}",
                status(&c.status),
                c.workspace_name.as_deref().unwrap_or("(none)"),
                c.workspace_id.as_deref().unwrap_or("(none)"),
                c.granted_scopes.join(", "),
                c.state_updates_consented,
                c.lifecycle_generation
            )?;
            if let Some(app_user) = &c.app_user_id {
                writeln!(out, "app user: {app_user}")?;
            }
            if let Some(cutoff) = &c.activation_cutoff {
                writeln!(out, "activation cutoff: {cutoff}")?;
            }
            if let Some(error) = &c.last_error {
                writeln!(
                    out,
                    "last error: {} ({})",
                    error.reason_code, error.observed_at
                )?;
            }
        }
        writeln!(out, "deployment: {}", d.fingerprint().api_url())?;
        if let Some(authorizations) = authorizations {
            authorizations.write_human(&mut out, "")?;
        }
    }
    Ok(ExitCode::Success)
}
fn lifecycle_stopped(
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
                "error: Linear connection operation interrupted\nconnection: {id}\nrequest key: {key}\n\nShow the connection before repeating this operation."
            )?;
        }
        Ok(())
    };
    output().map_err(super::super::super::CommandFailure::from)?;
    Ok(signal)
}

fn status_output(
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
            "error: Linear authorization {}",
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
pub(in crate::cli) fn failure_output(
    d: &Deployment,
    org: &str,
    id: Option<&str>,
    key: Option<&str>,
    failure: &LinearFailure,
    auth: super::super::super::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let (outcome, class, remedy) = match failure {
        LinearFailure::Unauthenticated => (
            "unauthenticated",
            OutcomeClass::Unauthenticated,
            auth.rejected_remedy("Sign in again with useful account login."),
        ),
        LinearFailure::Forbidden => (
            "forbidden",
            OutcomeClass::Forbidden,
            "Ask an active organization owner to inspect this connection or session.",
        ),
        LinearFailure::InvalidInput { .. } => (
            "invalid_input",
            OutcomeClass::GeneralFailure,
            "Check the organization and connection identifiers.",
        ),
        LinearFailure::NotFound => (
            "not_found",
            OutcomeClass::GeneralFailure,
            "Check the organization and identifier.",
        ),
        LinearFailure::Conflict => (
            "conflict",
            OutcomeClass::GeneralFailure,
            "Inspect existing connections and sessions before starting another authorization.",
        ),
        LinearFailure::Unreachable { category } => (
            "unreachable",
            super::super::super::unreachable_outcome_class(*category),
            "Check access to the deployment; inspect the session before retrying.",
        ),
        LinearFailure::RateLimited { .. } => (
            "rate_limited",
            OutcomeClass::RateLimited,
            "Wait before inspecting this session again.",
        ),
        LinearFailure::InvalidResponse { .. } => (
            "invalid_response",
            OutcomeClass::Protocol,
            "Use a CLI version supported by this deployment.",
        ),
    };
    let uncertain_key = key.filter(|_| {
        matches!(
            failure,
            LinearFailure::Unreachable { .. } | LinearFailure::InvalidResponse { .. }
        )
    });
    if json {
        emit(
            &serde_json::json!({"schemaVersion":1,"deployment":d.fingerprint().api_url(),"organizationRef":org,"outcome":outcome,"sessionId":id,"idempotencyKey":uncertain_key.filter(|_| id.is_none()),"category":match failure { LinearFailure::Unreachable { category } => Some(category.as_str()), _ => None }, "retryAfter":match failure { LinearFailure::RateLimited { retry_after } => *retry_after, _ => None }}),
        )?;
    } else {
        let mut err = io::stderr().lock();
        writeln!(
            err,
            "error: Linear connection {}",
            outcome.replace('_', " ")
        )?;
        if let Some(id) = id {
            writeln!(err, "session: {id}")?;
        } else if let Some(key) = uncertain_key {
            writeln!(err, "request key: {key}")?;
        }
        writeln!(err, "\n{remedy}")?;
    }
    Ok(class.exit_code())
}
