//! Organization Slack workspace connections and their owner consent sessions.
use std::io::{self, Write};
use std::time::Duration;

use anyhow::Context;
use serde_json::{Value, json};
use useful_api::{
    HttpClient, ResourceFailure, SlackApi, SlackConnection, SlackFailure, SlackSession,
    SlackSessionStatus, slack_connection::Status,
};
use useful_human_auth::Deployment;

use super::consent::{self, Options, emit};
use super::list::Record;
use super::target::Resolved;
use crate::cli::{
    CommandResult, CommonArgs, JsonOutputKind, PrincipalAuthenticationArgs,
    PrincipalAuthenticationKind, execute_selected_api_operation, principal_api_context,
    retry_delay, unreachable_outcome_class,
};
use crate::exit_code::{ExitCode, OutcomeClass};

pub(super) fn with_api<F: JsonOutputKind, T>(
    deployment: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    mut call: impl FnMut(&SlackApi) -> Result<T, SlackFailure>,
) -> anyhow::Result<Result<T, SlackFailure>> {
    let policy = options.http.transport_policy();
    let client = HttpClient::new(policy).context("prepare human session networking")?;
    execute_selected_api_operation(
        principal_api_context(
            &client,
            deployment,
            &options.authentication,
            "acquire human session",
        ),
        |token| {
            let api = SlackApi::new(deployment.fingerprint().api_url(), token, policy)?;
            Ok(call(&api))
        },
        SlackFailure::credential_rejected,
        SlackFailure::unauthenticated,
        SlackFailure::unreachable,
    )
}

impl consent::Provider for SlackApi {
    const NAME: &'static str = "Slack";
    const AUTHORIZATION_CONTEXT: &'static str = "Slack authorization";
    const LIFECYCLE_CONTEXT: &'static str = "Slack connection lifecycle";

    type Session = SlackSession;
    type Failure = SlackFailure;
    type StartOptions = ();

    fn with_api<F: JsonOutputKind, T>(
        deployment: &Deployment,
        options: &CommonArgs<F, PrincipalAuthenticationArgs>,
        f: impl FnMut(&Self) -> Result<T, SlackFailure>,
    ) -> anyhow::Result<Result<T, SlackFailure>> {
        with_api(deployment, options, f)
    }

    fn start(
        &self,
        org: &str,
        id: Option<&str>,
        key: &str,
        (): &(),
    ) -> Result<SlackSession, SlackFailure> {
        self.start(org, id, key)
    }

    fn session(&self, org: &str, id: &str) -> Result<SlackSession, SlackFailure> {
        self.session(org, id)
    }

    fn session_id(session: &SlackSession) -> &str {
        &session.id
    }

    fn pending(session: &SlackSession) -> bool {
        session.status == SlackSessionStatus::SlackSessionPending
    }

    fn unreachable(failure: &SlackFailure) -> bool {
        matches!(
            failure,
            SlackFailure::Resource(ResourceFailure::Unreachable { .. })
        )
    }

    fn polling_backoff(failure: &SlackFailure) -> Option<Duration> {
        match failure {
            SlackFailure::Resource(ResourceFailure::RateLimited { retry_after }) => {
                Some(retry_delay(*retry_after))
            }
            _ => None,
        }
    }

    fn session_output(
        d: &Deployment,
        org: &str,
        s: &SlackSession,
        json: bool,
    ) -> anyhow::Result<ExitCode> {
        use useful_api::slack_authorization_session::Status::*;
        let (outcome, exit) = match s.status {
            SlackSessionPending => ("pending", ExitCode::Success),
            SlackSessionCompleted => ("completed", ExitCode::Success),
            SlackSessionExpired => ("expired", ExitCode::GeneralFailure),
            SlackSessionFailed => ("failed", ExitCode::GeneralFailure),
            SlackSessionRecoveryRequired => ("recovery_required", ExitCode::GeneralFailure),
        };
        if json {
            let session = json!({"id":s.id,"operation":s.operation,"status":s.status,"connectionId":s.connection_id,
                "reasonCode":s.reason_code,"authorizationUrl":s.authorization_url,"expiresAt":s.expires_at,
                "resultConnection":s.result_connection.as_deref().map(connection_view)});
            emit(
                &json!({"schemaVersion":1,"deployment":d.fingerprint().api_url(),"organizationRef":org,"outcome":outcome,"session":session}),
            )?;
        } else {
            let mut out = io::stdout().lock();
            writeln!(
                out,
                "Slack authorization: {}\nsession: {}\norganization: {org}\nexpires: {}",
                outcome.replace('_', " "),
                s.id,
                s.expires_at
            )?;
            if let Some(c) = s.result_connection.as_deref() {
                writeln!(
                    out,
                    "connection: {} ({})\nworkspace: {} ({})",
                    c.id,
                    status(c.status),
                    c.workspace_name,
                    c.workspace_id
                )?;
            }
            if let Some(reason) = s.reason_code {
                writeln!(
                    out,
                    "reason: {}",
                    serde_json::to_value(reason)?.as_str().unwrap_or("unknown")
                )?;
            }
            writeln!(out, "deployment: {}", d.fingerprint().api_url())?;
            if let Some(url) = &s.authorization_url {
                writeln!(out, "\nOpen this URL to approve the workspace:\n  {url}")?;
            }
        }
        Ok(exit)
    }

    fn failure_output(
        d: &Deployment,
        org: &str,
        id: Option<&str>,
        key: Option<&str>,
        failure: &SlackFailure,
        auth: PrincipalAuthenticationKind,
        json: bool,
    ) -> anyhow::Result<ExitCode> {
        failure_output(d, org, id, key, failure, auth, json)
    }
}

pub(super) fn authorize(
    d: &Deployment,
    options: Options,
    org: &str,
    connection: Option<String>,
    no_wait: bool,
    timeout: Option<Duration>,
) -> CommandResult {
    consent::authorize::<SlackApi>(
        d.clone(),
        options,
        org.to_owned(),
        connection,
        (),
        no_wait,
        timeout,
    )
}

/// Provider targets already carry the record from the list. An explicit ID needs one read.
fn read<F: JsonOutputKind>(
    d: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    org: &str,
    resolved: Resolved,
) -> anyhow::Result<Result<SlackConnection, ExitCode>> {
    if let Resolved::Listed(Record::Slack(connection)) = resolved {
        return Ok(Ok(*connection));
    }
    match with_api(d, options, |api| api.connection(org, resolved.id()))? {
        Ok(connection) => Ok(Ok(connection)),
        Err(failure) => failure_output(
            d,
            org,
            None,
            None,
            &failure,
            options.authentication.kind(),
            options.json,
        )
        .map(Err),
    }
}

pub(super) fn reconnect(
    d: &Deployment,
    options: Options,
    org: &str,
    resolved: Resolved,
    no_wait: bool,
    timeout: Option<Duration>,
) -> CommandResult {
    let c = match read(d, &options, org, resolved)? {
        Ok(c) => c,
        Err(exit) => return Ok(exit),
    };
    if c.status == Status::Disconnected {
        let remedy = "Connect the workspace again with useful org integration connect slack.";
        if options.json {
            emit(
                &json!({"schemaVersion":1,"deployment":d.fingerprint().api_url(),"organizationRef":org,
                "connectionId":c.id,"outcome":"conflict","remedy":remedy}),
            )?;
        } else {
            writeln!(
                io::stderr().lock(),
                "error: Slack connection {} was disconnected\n\n{remedy}",
                c.id
            )
            .context("write Slack reconnect refusal")?;
        }
        return Ok(ExitCode::GeneralFailure);
    }
    authorize(d, options, org, Some(c.id), no_wait, timeout)
}

pub(super) fn show<F: JsonOutputKind>(
    d: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    org: &str,
    resolved: Resolved,
) -> anyhow::Result<ExitCode> {
    match read(d, options, org, resolved)? {
        Ok(c) => connection_output(d, org, "shown", &c, options.json),
        Err(exit) => Ok(exit),
    }
}

pub(super) fn disconnect<F: JsonOutputKind + Send + 'static>(
    d: &Deployment,
    options: CommonArgs<F, PrincipalAuthenticationArgs>,
    org: &str,
    id: &str,
) -> CommandResult {
    consent::remove::<SlackApi, F, _>(
        d.clone(),
        options,
        org.to_owned(),
        id.to_owned(),
        SlackApi::disconnect,
        |d, org, _, connection, json| connection_output(d, org, "disconnected", &connection, json),
    )
}

pub(super) const fn status(state: Status) -> &'static str {
    match state {
        Status::Active => "active",
        Status::RecoveryRequired => "recovery_required",
        Status::Disconnected => "disconnected",
    }
}

pub(super) fn connection_view(c: &SlackConnection) -> Value {
    json!({"id":c.id,"status":c.status,"workspaceId":c.workspace_id,"workspaceName":c.workspace_name,
        "grantedScopes":c.granted_scopes,"lifecycleGeneration":c.lifecycle_generation,"lastError":c.last_error,"disconnectedAt":c.disconnected_at})
}

fn connection_output(
    d: &Deployment,
    org: &str,
    outcome: &str,
    c: &SlackConnection,
    json: bool,
) -> anyhow::Result<ExitCode> {
    if json {
        emit(
            &json!({"schemaVersion":1,"deployment":d.fingerprint().api_url(),"organizationRef":org,
            "outcome":outcome,"connectionId":c.id,"connection":connection_view(c)}),
        )?;
    } else {
        let mut out = io::stdout().lock();
        writeln!(
            out,
            "Slack connection: {outcome}\nconnection: {}\nstatus: {}\nworkspace: {} ({})\ngranted scopes: {}\ngeneration: {}",
            c.id,
            status(c.status),
            c.workspace_name,
            c.workspace_id,
            c.granted_scopes.join(", "),
            c.lifecycle_generation
        )?;
        if let Some(error) = &c.last_error {
            writeln!(
                out,
                "last error: {} ({})",
                error.reason_code, error.observed_at
            )?;
        }
        if let Some(time) = &c.disconnected_at {
            writeln!(out, "disconnected at: {time}")?;
        }
        writeln!(out, "deployment: {}", d.fingerprint().api_url())?;
    }
    Ok(ExitCode::Success)
}

pub(super) fn failure_output(
    d: &Deployment,
    org: &str,
    session: Option<&str>,
    key: Option<&str>,
    failure: &SlackFailure,
    auth: PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    use ResourceFailure::*;
    let mut retry_after = None;
    let mut category = None;
    let mut uncertain_key = None;
    let (outcome, exit, remedy) = match failure {
        SlackFailure::NotServed => (
            "service_unavailable",
            ExitCode::Unavailable,
            "Ask the deployment operator to configure Slack.",
        ),
        SlackFailure::Resource(resource) => match resource {
            Unauthenticated => (
                "unauthenticated",
                ExitCode::AuthenticationRequired,
                auth.rejected_remedy("Sign in again with useful account login."),
            ),
            Forbidden => (
                "forbidden",
                ExitCode::GeneralFailure,
                "This command needs an organization owner.",
            ),
            NotFound => (
                "not_found",
                ExitCode::GeneralFailure,
                "Check the organization and identifier.",
            ),
            Conflict => (
                "conflict",
                ExitCode::GeneralFailure,
                "Inspect existing Slack connections and sessions before trying again.",
            ),
            InvalidInput { .. } => (
                "invalid_input",
                ExitCode::GeneralFailure,
                "Check the organization and connection identifiers.",
            ),
            InvalidResponse { .. } => {
                uncertain_key = key;
                (
                    "invalid_response",
                    ExitCode::GeneralFailure,
                    "Use a CLI version supported by this deployment.",
                )
            }
            RateLimited { retry_after: wait } => {
                retry_after = *wait;
                (
                    "rate_limited",
                    OutcomeClass::RateLimited.exit_code(),
                    "Wait before trying again.",
                )
            }
            Unreachable { category: cause } => {
                uncertain_key = key;
                category = Some(cause.as_str());
                (
                    "unreachable",
                    unreachable_outcome_class(*cause).exit_code(),
                    "Check access to the deployment and inspect the session before retrying.",
                )
            }
        },
    };
    if json {
        emit(
            &json!({"schemaVersion":1,"deployment":d.fingerprint().api_url(),"organizationRef":org,"sessionId":session,"outcome":outcome,"retryAfter":retry_after,"category":category,"idempotencyKey":uncertain_key}),
        )?;
    } else {
        let mut err = io::stderr().lock();
        writeln!(err, "error: Slack connection {}", outcome.replace('_', " "))?;
        if let Some(id) = session {
            writeln!(err, "session: {id}")?;
        }
        if let Some(key) = uncertain_key {
            writeln!(err, "request key: {key}")?;
        }
        writeln!(err, "\n{remedy}")?;
    }
    Ok(exit)
}
