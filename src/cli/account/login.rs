use std::io::{self, Write};
use std::time::Duration;

use anyhow::{Context, anyhow};
use clap::Args;
use serde::Serialize;
use time::OffsetDateTime;

use crate::exit_code::OutcomeClass;
use useful_api::{HttpClient, HttpTransportPolicy, UnreachableCategory};
use useful_human_auth::Cancellation;
use useful_human_auth::CredentialStore;
use useful_human_auth::Deployment;
use useful_human_auth::{AuthenticationState, AuthenticationStatus, StatusError};
use useful_human_auth::{AuthorizationError, DeviceAuthorization, IssuedToken};
use useful_human_auth::{DeviceFlowError, DeviceFlowOutcome, DeviceFlowPhase};

use super::show::{StatusResult, write_human_status};

pub(super) const ABOUT: &str = "Sign in";

#[derive(Debug, Args)]
pub(super) struct Command {
    // Login keeps its force option and three-way completion mapping local;
    // sharing this command shell with status would couple distinct result contracts.
    #[arg(long, help = "Start a new sign-in even if you're already signed in")]
    force: bool,

    #[command(flatten)]
    common:
        super::super::CommonArgs<super::super::StreamingJson, super::super::NoAuthenticationArgs>,
}

impl std::ops::Deref for Command {
    type Target =
        super::super::CommonArgs<super::super::StreamingJson, super::super::NoAuthenticationArgs>;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl Command {
    pub(super) fn execute(self, deployment: &Deployment) -> super::super::CommandResult {
        let deployment = deployment.clone();
        super::super::execute_cancellable_with_signals("sign-in", move |cancellation| {
            self.run(&deployment, cancellation)
                .map(OutcomeClass::exit_code)
        })
    }

    fn run(
        self,
        deployment: &Deployment,
        cancellation: &Cancellation,
    ) -> LoginResult<OutcomeClass> {
        let SignInSession {
            store,
            client,
            mut output,
        } = SignInSession::open(self.http.transport_policy(), self.json)?;

        if self.force {
            // Validate store access and prune an expired selected credential
            // before starting its replacement login.
            store
                .selected(deployment.fingerprint())
                .map_err(|error| anyhow!(error))
                .context("access credential store")?;
        } else {
            let existing_status = useful_human_auth::check_auth_status(&client, deployment);
            if cancellation.is_cancelled() {
                output.cancelled(deployment)?;
                return Ok(OutcomeClass::Interrupted);
            }
            match existing_status {
                Ok(existing) => match existing.state() {
                    AuthenticationState::Authenticated(_)
                    | AuthenticationState::SignupRequired { .. } => {
                        output.status(&existing)?;
                        return Ok(OutcomeClass::Success);
                    }
                    AuthenticationState::Forbidden { .. } => {
                        output.status(&existing)?;
                        return Ok(OutcomeClass::Forbidden);
                    }
                    AuthenticationState::Unauthenticated => {}
                    AuthenticationState::Unreachable(category) => {
                        return handle_unreachable(
                            &mut output,
                            deployment,
                            Phase::ExistingCredentialCheck,
                            *category,
                        );
                    }
                },
                Err(error) => {
                    return handle_status_error(
                        &mut output,
                        deployment,
                        Phase::ExistingCredentialCheck,
                        error,
                    );
                }
            }
        }

        match sign_in(&mut output, &client, deployment, &store, cancellation)? {
            SignIn::SignedIn(status) => {
                output.status(&status)?;
                Ok(OutcomeClass::Success)
            }
            SignIn::Ended(outcome) => Ok(outcome),
        }
    }
}

/// How a sign-in that `account login` started ended.
pub(super) enum SignIn {
    /// The deployment confirmed the new session as an account or an identity
    /// that still needs one; nothing about the confirmation is printed yet.
    SignedIn(AuthenticationStatus),
    /// The sign-in ended the command; its output is written.
    Ended(OutcomeClass),
}

/// Runs the sign-in `account login` starts when this device holds no sign-in,
/// with its human output, so a command that needs a session can sign in first
/// (REQ-ACCOUNT-16).
pub(super) fn sign_in_first(
    deployment: &Deployment,
    transport_policy: HttpTransportPolicy,
    cancellation: &Cancellation,
) -> LoginResult<SignIn> {
    let SignInSession {
        store,
        client,
        mut output,
    } = SignInSession::open(transport_policy, false)?;
    sign_in(&mut output, &client, deployment, &store, cancellation)
}

struct SignInSession {
    store: CredentialStore,
    client: HttpClient,
    output: LoginOutput,
}

impl SignInSession {
    fn open(transport_policy: HttpTransportPolicy, json: bool) -> anyhow::Result<Self> {
        let store = CredentialStore::from_environment()
            .map_err(|error| anyhow!(error))
            .context("access credential store")?;
        let client = HttpClient::new(transport_policy)
            .map_err(|error| anyhow!(error))
            .context("prepare sign-in networking")?;
        Ok(Self {
            store,
            client,
            output: LoginOutput { json },
        })
    }
}

fn sign_in(
    output: &mut LoginOutput,
    client: &HttpClient,
    deployment: &Deployment,
    store: &CredentialStore,
    cancellation: &Cancellation,
) -> LoginResult<SignIn> {
    let flow = useful_human_auth::begin_session(
        client,
        deployment,
        cancellation,
        |authorization, expires_at| output.activation(deployment, authorization, expires_at),
    );
    let ended = match flow {
        Ok(DeviceFlowOutcome::Issued(token)) => {
            return finish_login(output, client, deployment, store, cancellation, token);
        }
        Ok(DeviceFlowOutcome::Denied) => {
            output.failed(
                deployment,
                FailureOutcome::Denied,
                Phase::TokenPolling,
                None,
            )?;
            OutcomeClass::GeneralFailure
        }
        Ok(DeviceFlowOutcome::Expired) => {
            output.failed(
                deployment,
                FailureOutcome::Expired,
                Phase::TokenPolling,
                None,
            )?;
            OutcomeClass::GeneralFailure
        }
        Ok(DeviceFlowOutcome::Cancelled) => {
            output.cancelled(deployment)?;
            OutcomeClass::Interrupted
        }
        Err(DeviceFlowError::Authorization { phase, error }) => {
            if cancellation.is_cancelled() {
                output.cancelled(deployment)?;
                OutcomeClass::Interrupted
            } else {
                handle_authorization_error(output, deployment, phase.into(), error)?
            }
        }
        Err(DeviceFlowError::ExpirationOutOfRange) => handle_protocol_error(
            output,
            deployment,
            Phase::DeviceAuthorization,
            anyhow!("the device-authorization expiration is out of range"),
        )?,
        Err(DeviceFlowError::ActivationOutput(error)) => return Err(error.into()),
    };
    Ok(SignIn::Ended(ended))
}

fn finish_login(
    output: &mut LoginOutput,
    client: &HttpClient,
    deployment: &Deployment,
    store: &CredentialStore,
    cancellation: &Cancellation,
    token: IssuedToken,
) -> LoginResult<SignIn> {
    let Some(expires_at) = expiration_after(token.expires_in()) else {
        return handle_protocol_error(
            output,
            deployment,
            Phase::TokenPolling,
            anyhow!("the token expiration is out of range"),
        )
        .map(SignIn::Ended);
    };
    if cancellation.is_cancelled() {
        output.cancelled(deployment)?;
        return Ok(SignIn::Ended(OutcomeClass::Interrupted));
    }

    // Credential persistence commits the login. Ignore later interrupts so a
    // cancelled result can never conceal a newly stored token.
    store
        .replace(
            deployment.fingerprint(),
            token.access_token(),
            expires_at,
            token.refresh_token(),
        )
        .map_err(|error| anyhow!(error))
        .context("access credential store")?;

    let status = match useful_human_auth::check_auth_status(client, deployment) {
        Ok(status) => status,
        Err(error) => {
            return handle_status_error(output, deployment, Phase::PrincipalConfirmation, error)
                .map(SignIn::Ended);
        }
    };
    let ended = match status.state() {
        AuthenticationState::Authenticated(_) | AuthenticationState::SignupRequired { .. } => {
            return Ok(SignIn::SignedIn(status));
        }
        // A refused account keeps its newly issued sign-in: it works again once
        // deletion is cancelled or a suspension is lifted.
        AuthenticationState::Forbidden { .. } => {
            output.status(&status)?;
            OutcomeClass::Forbidden
        }
        AuthenticationState::Unauthenticated => {
            output.status(&status)?;
            OutcomeClass::Unauthenticated
        }
        AuthenticationState::Unreachable(category) => {
            handle_unreachable(output, deployment, Phase::PrincipalConfirmation, *category)?
        }
    };
    Ok(SignIn::Ended(ended))
}

fn handle_status_error(
    output: &mut LoginOutput,
    deployment: &Deployment,
    phase: Phase,
    error: StatusError,
) -> LoginResult<OutcomeClass> {
    match error {
        StatusError::Session(error) => Err(anyhow!(error).context("acquire human session").into()),
        StatusError::PublicApi(error) if error.is_local() => Err(anyhow!(error)
            .context(phase.operation_context(deployment))
            .into()),
        StatusError::PublicApi(error) => {
            handle_protocol_error(output, deployment, phase, anyhow!(error))
        }
    }
}

fn handle_unreachable(
    output: &mut LoginOutput,
    deployment: &Deployment,
    phase: Phase,
    category: UnreachableCategory,
) -> LoginResult<OutcomeClass> {
    let outcome = super::super::unreachable_outcome_class(category);
    if output.json {
        output.failed(
            deployment,
            FailureOutcome::Unreachable,
            phase,
            Some(category),
        )?;
        Ok(outcome)
    } else {
        let error = match phase {
            Phase::ExistingCredentialCheck | Phase::PrincipalConfirmation => {
                anyhow!("Useful Machinery is unreachable ({})", category.as_str())
            }
            Phase::DeviceAuthorization | Phase::TokenPolling => anyhow!(
                "authorization server is unreachable ({})",
                category.as_str()
            ),
        };
        Err(super::super::CommandFailure::for_outcome(
            error.context(phase.operation_context(deployment)),
            outcome,
        ))
    }
}

fn handle_protocol_error(
    output: &mut LoginOutput,
    deployment: &Deployment,
    phase: Phase,
    error: anyhow::Error,
) -> LoginResult<OutcomeClass> {
    if output.json {
        output.failed(deployment, FailureOutcome::ProtocolError, phase, None)?;
        Ok(OutcomeClass::Protocol)
    } else {
        Err(super::super::CommandFailure::for_outcome(
            error.context(phase.operation_context(deployment)),
            OutcomeClass::Protocol,
        ))
    }
}

fn handle_authorization_error(
    output: &mut LoginOutput,
    deployment: &Deployment,
    phase: Phase,
    error: AuthorizationError,
) -> LoginResult<OutcomeClass> {
    match error {
        AuthorizationError::Local(error) => Err(anyhow!(error)
            .context(phase.operation_context(deployment))
            .into()),
        AuthorizationError::Unreachable(category) => {
            handle_unreachable(output, deployment, phase, category)
        }
        error @ AuthorizationError::Protocol { .. } => {
            handle_protocol_error(output, deployment, phase, anyhow!(error))
        }
    }
}

type LoginResult<T> = Result<T, super::super::CommandFailure>;

fn expiration_after(duration: Duration) -> Option<OffsetDateTime> {
    let seconds = i64::try_from(duration.as_secs()).ok()?;
    useful_support::utc_now().checked_add(time::Duration::seconds(seconds))
}

#[derive(Clone, Copy)]
enum FailureOutcome {
    Denied,
    Expired,
    Unreachable,
    ProtocolError,
}

impl FailureOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Unreachable => "unreachable",
            Self::ProtocolError => "protocol_error",
        }
    }
}

#[derive(Clone, Copy)]
enum Phase {
    ExistingCredentialCheck,
    DeviceAuthorization,
    TokenPolling,
    PrincipalConfirmation,
}

impl From<DeviceFlowPhase> for Phase {
    fn from(value: DeviceFlowPhase) -> Self {
        match value {
            DeviceFlowPhase::DeviceAuthorization => Self::DeviceAuthorization,
            DeviceFlowPhase::TokenPolling => Self::TokenPolling,
        }
    }
}

impl Phase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ExistingCredentialCheck => "existing_credential_check",
            Self::DeviceAuthorization => "device_authorization",
            Self::TokenPolling => "token_polling",
            Self::PrincipalConfirmation => "principal_confirmation",
        }
    }

    fn operation_context(self, deployment: &Deployment) -> String {
        match self {
            Self::ExistingCredentialCheck => format!(
                "check existing sign-in through public API {}",
                deployment.fingerprint().api_url()
            ),
            Self::DeviceAuthorization => format!(
                "request device authorization from OAuth issuer {}",
                deployment.fingerprint().issuer()
            ),
            Self::TokenPolling => format!(
                "request sign-in token from OAuth issuer {}",
                deployment.fingerprint().issuer()
            ),
            Self::PrincipalConfirmation => format!(
                "confirm sign-in through public API {}",
                deployment.fingerprint().api_url()
            ),
        }
    }
}

struct LoginOutput {
    json: bool,
}

impl LoginOutput {
    fn activation(
        &mut self,
        deployment: &Deployment,
        authorization: &DeviceAuthorization,
        expires_at: OffsetDateTime,
    ) -> anyhow::Result<()> {
        // Keep login presentation and its error context next to this command.
        if self.json {
            let event =
                useful_human_auth::activation_event(deployment, authorization, expires_at, None)
                    .context("format sign-in expiration")?;
            self.json_line(&event)
        } else {
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            writeln!(stdout, "Sign in to Useful Machinery\n").context("write sign-in output")?;
            writeln!(stdout, "  Open: {}", authorization.activation_uri())
                .context("write sign-in output")?;
            writeln!(stdout, "  Code: {}", authorization.user_code())
                .context("write sign-in output")?;
            writeln!(stdout, "\nWaiting for authorization...\n").context("write sign-in output")?;
            stdout.flush().context("write sign-in output")
        }
    }

    fn status(&mut self, status: &AuthenticationStatus) -> anyhow::Result<()> {
        if self.json {
            self.json_line(&StatusEvent {
                schema_version: 1,
                event: "status",
                status: StatusResult::from_status(status),
            })
        } else {
            write_human_status(
                status,
                super::super::PrincipalAuthenticationKind::HumanSession,
            )
            .context("write sign-in status")
        }
    }

    fn failed(
        &mut self,
        deployment: &Deployment,
        outcome: FailureOutcome,
        phase: Phase,
        category: Option<UnreachableCategory>,
    ) -> anyhow::Result<()> {
        if self.json {
            self.json_line(&FailedEvent {
                schema_version: 1,
                event: "failed",
                deployment: deployment.fingerprint().api_url(),
                outcome: outcome.as_str(),
                phase: phase.as_str(),
                category: category.map(UnreachableCategory::as_str),
            })
        } else {
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            if let Some(category) = category {
                writeln!(
                    stdout,
                    "Sign-in failed during {}: {} ({}).",
                    phase.as_str(),
                    outcome.as_str(),
                    category.as_str()
                )
            } else {
                writeln!(
                    stdout,
                    "Sign-in failed during {}: {}.",
                    phase.as_str(),
                    outcome.as_str()
                )
            }
            .context("write sign-in output")
        }
    }

    fn cancelled(&mut self, deployment: &Deployment) -> anyhow::Result<()> {
        if self.json {
            self.json_line(&CancelledEvent {
                schema_version: 1,
                event: "cancelled",
                deployment: deployment.fingerprint().api_url(),
            })
        } else {
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            writeln!(stdout, "! Sign-in cancelled.").context("write sign-in output")
        }
    }

    fn json_line<T: Serialize>(&mut self, event: &T) -> anyhow::Result<()> {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        serde_json::to_writer(&mut stdout, event).context("write JSON sign-in event")?;
        writeln!(stdout).context("write sign-in output")?;
        stdout.flush().context("write sign-in output")
    }
}

#[derive(Serialize)]
struct StatusEvent<'a> {
    #[serde(rename = "schemaVersion")]
    schema_version: u8,
    event: &'static str,
    status: StatusResult<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FailedEvent<'a> {
    schema_version: u8,
    event: &'static str,
    deployment: &'a str,
    outcome: &'static str,
    phase: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CancelledEvent<'a> {
    schema_version: u8,
    event: &'static str,
    deployment: &'a str,
}
