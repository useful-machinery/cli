use std::io::{self, Write};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use clap::Args;
use serde::Serialize;

use crate::exit_code::{ExitCode, OutcomeClass};
#[cfg(test)]
use useful_api::RunRead;
use useful_api::{
    HttpTransportPolicy, RetryConflict, Run, RunApi, RunArtifactDelivery, RunCancellationMode,
    RunCancellationResolutionKind, RunFailure, RunLinearLifecycle, RunLinearLifecycleUpdate,
    RunObservation, RunState,
};
use useful_execution::visible_text;
use useful_human_auth::Deployment;

pub(in crate::cli) mod acquisition;
mod continuation;
pub(in crate::cli) mod observation;
pub(in crate::cli) mod output;
mod retry;
pub(super) use continuation::{
    Submission as ContinuationSubmission, parse_step as parse_continuation_step,
};
pub(in crate::cli) use output::CloudSnapshot;
pub(super) use output::{
    reported_field, reported_text, step_path, wait_phrase, write_automatic_publication,
    write_held_with, write_rejection, write_route, write_waiting, write_workflow_state,
};
pub(super) use retry::Request as RetryRequest;

// Keep the closed envelope fields grouped at the rendering boundary, without
// repeating its context at every signal, timeout and completion call site; `run create`
// (`src/cli/workflow/run/create/cloud.rs`) writes its document through it too.
macro_rules! write_cloud {
    ($operation:expr, $deployment:expr, $organization:expr, $snapshot:expr,
     $outcome:expr, $error:expr, $key:expr, $mode:expr, $json:expr, $exit:expr $(,)?) => {
        $crate::cli::workflow::run::cloud_api::output::write_cloud(
            $crate::cli::workflow::run::cloud_api::output::CloudOutput {
                operation: $operation,
                deployment: $deployment,
                organization: $organization,
                snapshot: $snapshot,
                json: $json,
            },
            $outcome,
            $error,
            $key,
            $mode,
            $exit,
        )
    };
}

pub(in crate::cli) use write_cloud;

pub(in crate::cli) type RunOptions =
    crate::cli::CommonArgs<crate::cli::RunJson, crate::cli::PrincipalAuthenticationArgs>;

#[derive(Debug, Args)]
pub(in crate::cli) struct RunWaitArgs {
    #[arg(long, help = "Observe the run until it settles")]
    pub(in crate::cli) wait: bool,
    #[arg(long, requires = "wait", value_name = "DURATION", value_parser = crate::cli::parse_wait_timeout,
        help = crate::cli::WAIT_TIMEOUT_HELP)]
    pub(in crate::cli) timeout: Option<Duration>,
}

/// The Cloud run a continuation or a rerun asks for: the organization reference the request
/// names and the run's ID, as the lookup found them.
struct RunReference {
    organization: String,
    run_id: String,
}

/// What a Cloud request sent to a run the lookup found writes in place of its failure's
/// document when Cloud's answer is the lookup's miss: given the request's failure and the
/// options it was sent under, the refusal to write once the operation completes, or `None`
/// for the failure's own document.
pub(in crate::cli) type Missed = Box<
    dyn FnOnce(
            &RunFailure,
            &RunOptions,
        ) -> anyhow::Result<Option<Box<dyn FnOnce() -> crate::cli::CommandResult>>>
        + Send,
>;

/// The cancellation request `useful workflow run cancel` sends a Cloud run: graceful, or
/// with `force` immediate containment, under `key`, followed with `wait` until it resolves,
/// and reported in the document of the `cancel` operation.
pub(in crate::cli) struct Cancellation {
    pub(in crate::cli) organization: String,
    pub(in crate::cli) run_id: String,
    pub(in crate::cli) force: bool,
    pub(in crate::cli) key: String,
    pub(in crate::cli) wait: RunWaitArgs,
    pub(in crate::cli) options: RunOptions,
}

/// An opaque request identity a caller reuses to reconcile an uncertain Cloud request: 1 to 255
/// visible ASCII characters (`workflow run cancel --idempotency-key`, `workflow run publication
/// create --idempotency-key`).
pub(in crate::cli) fn parse_idempotency_key(value: &str) -> Result<String, String> {
    if (1..=255).contains(&value.len()) && value.bytes().all(|byte| (b'!'..=b'~').contains(&byte)) {
        Ok(value.to_owned())
    } else {
        Err("must contain 1-255 visible ASCII characters without whitespace".to_owned())
    }
}

pub(in crate::cli) fn finish_operation<R>(
    control: &crate::cli::OperationControl<R>,
    write_result: impl FnOnce() -> anyhow::Result<ExitCode>,
) -> crate::cli::CommandResult {
    crate::cli::complete_operation(control, || write_result().map_err(Into::into))
}

pub(in crate::cli) fn start_cloud_observation(
    timeout_start: &crate::cli::DeferredObservationTimeoutStart,
) -> (crate::cli::SystemObservationClock, std::time::Instant) {
    timeout_start.start();
    (
        crate::cli::SystemObservationClock,
        useful_support::monotonic_now(),
    )
}

pub(in crate::cli) fn finish_accepted<R>(
    control: &crate::cli::OperationControl<R>,
    operation: &'static str,
    deployment: &Deployment,
    organization: &str,
    snapshot: &CloudSnapshot,
    json: bool,
) -> crate::cli::CommandResult {
    finish_operation(control, || {
        write_cloud!(
            operation,
            deployment.fingerprint().api_url(),
            organization,
            snapshot,
            "accepted",
            None,
            None,
            None,
            json,
            ExitCode::Success,
        )
    })
}

pub(in crate::cli) fn write_api_outcome<T>(
    result: Result<T, RunFailure>,
    write_success: impl FnOnce(T) -> anyhow::Result<()>,
    write_failure: impl FnOnce(&RunFailure) -> anyhow::Result<ExitCode>,
) -> anyhow::Result<ExitCode> {
    match result {
        Ok(value) => {
            write_success(value)?;
            Ok(ExitCode::Success)
        }
        Err(failure) => write_failure(&failure),
    }
}

#[derive(Clone, Debug)]
struct CancelRecovery {
    key: String,
    mode: &'static str,
    accepted: bool,
    snapshot: CloudSnapshot,
}

impl Cancellation {
    /// Sends the request under its key and reports it; `missed` gives, for a failure of the
    /// request Cloud answered, the result the command ends with in place of the failure's
    /// document, if any, written once the operation completes.
    pub(in crate::cli) fn execute(
        self,
        deployment: Deployment,
        missed: Missed,
    ) -> crate::cli::CommandResult {
        let mode = if self.force { "force" } else { "graceful" };
        let recovery = CancelRecovery {
            key: self.key.clone(),
            mode,
            accepted: false,
            snapshot: CloudSnapshot::for_run(self.run_id.clone()),
        };
        let signal_deployment = deployment.clone();
        let timeout_deployment = deployment.clone();
        let signal_organization = self.organization.clone();
        let timeout_organization = signal_organization.clone();
        let json = self.options.json;
        let timeout = self.wait.timeout.filter(|_| self.wait.wait);
        crate::cli::execute_mutation_with_signals_and_deferred_timeout(
            "Cloud run cancellation",
            recovery,
            timeout,
            move |control, timeout_start| {
                self.execute_blocking(&deployment, control, timeout_start, missed)
            },
            move |signal, snapshot| {
                let recovery = snapshot.recovery;
                let (outcome, code) = if recovery.accepted {
                    ("observation_stopped", "observation_stopped")
                } else {
                    ("acceptance_unknown", "acceptance_unknown")
                };
                write_cloud!(
                    "cancel",
                    signal_deployment.fingerprint().api_url(),
                    &signal_organization,
                    &recovery.snapshot,
                    outcome,
                    Some(code),
                    Some(&recovery.key),
                    Some(recovery.mode),
                    json,
                    signal,
                )
                .map_err(Into::into)
            },
            move |snapshot| {
                let recovery = snapshot.recovery;
                write_cloud!(
                    "cancel",
                    timeout_deployment.fingerprint().api_url(),
                    &timeout_organization,
                    &recovery.snapshot,
                    "timed_out",
                    Some("wait_timed_out"),
                    Some(&recovery.key),
                    Some(recovery.mode),
                    json,
                    ExitCode::GeneralFailure,
                )
                .map_err(Into::into)
            },
        )
    }

    fn execute_blocking(
        self,
        deployment: &Deployment,
        control: &crate::cli::OperationControl<CancelRecovery>,
        timeout_start: &crate::cli::DeferredObservationTimeoutStart,
        missed: Missed,
    ) -> crate::cli::CommandResult {
        let recovery = control.recovery();
        let mode = if self.force {
            RunCancellationMode::Force
        } else {
            RunCancellationMode::Graceful
        };
        let result = with_api(
            deployment,
            self.options.http.transport_policy(),
            &self.options.authentication,
            |api| {
                api.cancel(
                    &self.organization,
                    &self.run_id,
                    &recovery.key,
                    mode,
                    || control.begin_dispatch(),
                )
            },
        );
        let result = match result {
            Ok(result) => result,
            Err(_) => {
                let dispatched = control.dispatched();
                return finish_operation(control, || {
                    write_cloud!(
                        "cancel",
                        deployment.fingerprint().api_url(),
                        &self.organization,
                        &recovery.snapshot,
                        if dispatched {
                            "acceptance_unknown"
                        } else {
                            "error"
                        },
                        Some(if dispatched {
                            "acceptance_unknown"
                        } else {
                            "submission_failed"
                        }),
                        Some(&recovery.key),
                        Some(recovery.mode),
                        self.options.json,
                        if dispatched {
                            ExitCode::Unavailable
                        } else {
                            ExitCode::GeneralFailure
                        },
                    )
                });
            }
        };
        let envelope = match result {
            Ok(envelope) => envelope,
            Err(failure) => {
                if let Some(write) = missed(&failure, &self.options)? {
                    return crate::cli::complete_operation(control, write);
                }
                return finish_operation(control, || {
                    write_cancel_failure(
                        deployment.fingerprint().api_url(),
                        &self.organization,
                        &recovery,
                        &failure,
                        control.dispatched(),
                        self.options.authentication.kind(),
                        self.options.json,
                    )
                });
            }
        };
        let mut snapshot = recovery.snapshot.clone();
        snapshot.run = envelope.run;
        snapshot.cancellation_request = Some(envelope.request);
        let accepted = CancelRecovery {
            accepted: true,
            snapshot: snapshot.clone(),
            ..recovery
        };
        if !control.update_recovery(accepted.clone()) {
            return Ok(ExitCode::GeneralFailure);
        }
        if !self.wait.wait {
            return finish_accepted(
                control,
                "cancel",
                deployment,
                &self.organization,
                &snapshot,
                self.options.json,
            );
        }
        let (clock, started) = start_cloud_observation(timeout_start);
        let result = observation::wait_cancellation(
            observation::ObservationContext {
                deployment,
                options: &self.options,
                organization: &self.organization,
                snapshot: &snapshot,
                timeout: self.wait.timeout,
                started,
            },
            control,
            &clock,
            |latest| {
                control.update_recovery(CancelRecovery {
                    snapshot: latest,
                    ..accepted.clone()
                });
            },
        );
        finish_cloud_observation(
            deployment.fingerprint().api_url(),
            "cancel",
            &self.organization,
            result,
            control,
            || {
                let recovery = control.recovery();
                (recovery.snapshot, Some(recovery.key), Some(recovery.mode))
            },
            self.options.json,
        )
    }
}

pub(in crate::cli) fn finish_cloud_observation<R, S>(
    deployment: &str,
    operation: &'static str,
    organization: &str,
    result: Result<crate::cli::TerminalObservation<CloudSnapshot, S>, RunFailure>,
    control: &crate::cli::OperationControl<R>,
    latest: impl Fn() -> (CloudSnapshot, Option<String>, Option<&'static str>),
    json: bool,
) -> crate::cli::CommandResult {
    finish_operation(control, || match result {
        Ok(crate::cli::TerminalObservation::Terminal { resource, .. }) => {
            let rejected = operation == "cancel"
                && resource
                    .cancellation_request
                    .as_deref()
                    .and_then(|receipt| receipt.resolution.as_deref())
                    .is_some_and(|resolution| {
                        resolution.kind == RunCancellationResolutionKind::CreationRejected
                    });
            if rejected {
                let (_, key, mode) = latest();
                return write_cloud!(
                    operation,
                    deployment,
                    organization,
                    &resource,
                    "error",
                    Some("creation_rejected"),
                    key.as_deref(),
                    mode,
                    json,
                    ExitCode::GeneralFailure,
                );
            }
            let exit = if operation == "create"
                && resource
                    .run
                    .as_deref()
                    .is_some_and(|run| run.state != RunState::Succeeded)
            {
                ExitCode::GeneralFailure
            } else {
                ExitCode::Success
            };
            write_cloud!(
                operation,
                deployment,
                organization,
                &resource,
                "settled",
                None,
                None,
                None,
                json,
                exit,
            )
        }
        Ok(crate::cli::TerminalObservation::TimedOut) => {
            let (snapshot, key, mode) = latest();
            write_cloud!(
                operation,
                deployment,
                organization,
                &snapshot,
                "timed_out",
                Some("wait_timed_out"),
                key.as_deref(),
                mode,
                json,
                ExitCode::GeneralFailure
            )
        }
        Ok(crate::cli::TerminalObservation::Stopped) => Ok(ExitCode::GeneralFailure),
        Err(failure) => {
            let (code, exit) = failure_code(
                &failure,
                crate::cli::PrincipalAuthenticationKind::HumanSession,
            );
            let code = if matches!(failure, RunFailure::Unreachable(_)) {
                "observation_failed"
            } else {
                code
            };
            let (snapshot, key, mode) = latest();
            write_cloud!(
                operation,
                deployment,
                organization,
                &snapshot,
                "error",
                Some(code),
                key.as_deref(),
                mode,
                json,
                exit
            )
        }
    })
}

/// What a `path_run_retired` report tells the user to do instead; Cloud's own
/// problem prose is never relayed.
const PATH_RUN_RETIRED_GUIDANCE: &str = "Cloud no longer retries or continues a run created by workflow path; publish the workflow as a definition (`useful workflow definition publish --on project`) and start a run of it.";

/// The diagnostic code and exit status a run command reports `failure` under; the Cloud
/// leaves of `useful workflow run` take theirs from it too.
pub(in crate::cli) fn failure_code(
    failure: &RunFailure,
    _authentication: crate::cli::PrincipalAuthenticationKind,
) -> (&'static str, ExitCode) {
    match failure {
        RunFailure::Unauthenticated => {
            ("authentication_required", ExitCode::AuthenticationRequired)
        }
        RunFailure::Forbidden => ("forbidden", ExitCode::GeneralFailure),
        RunFailure::InvalidInput => ("invalid_input", ExitCode::GeneralFailure),
        RunFailure::NotFound => ("not_found", ExitCode::GeneralFailure),
        RunFailure::IdempotencyConflict => ("idempotency_conflict", ExitCode::GeneralFailure),
        RunFailure::ContinuationAdmissionInvalid(_) => {
            ("continuation_admission_invalid", ExitCode::GeneralFailure)
        }
        RunFailure::PathRunRetired => ("path_run_retired", ExitCode::GeneralFailure),
        RunFailure::RetryConflict(conflict) => (
            match conflict {
                RetryConflict::Pending => "retry_pending",
                RetryConflict::Idempotency => "idempotency_conflict",
                RetryConflict::SubjectBusy { .. } => "subject_busy",
                RetryConflict::SubjectSettled { .. } => "subject_settled",
            },
            ExitCode::GeneralFailure,
        ),
        RunFailure::Conflict => ("submission_failed", ExitCode::GeneralFailure),
        RunFailure::InputAdmissionRejected { .. } => {
            ("input_admission_rejected", ExitCode::GeneralFailure)
        }
        RunFailure::AdmissionRejected { .. } => ("admission_rejected", ExitCode::GeneralFailure),
        RunFailure::RetryAfter(_)
        | RunFailure::RetryAmbiguousRateLimited
        | RunFailure::RetryAmbiguousAuthentication
        | RunFailure::ContinuationAcceptanceUnknown => ("unavailable", ExitCode::Unavailable),
        RunFailure::CreationRejected => ("creation_rejected", ExitCode::GeneralFailure),
        RunFailure::Unreachable(_) => ("unavailable", ExitCode::Unavailable),
        RunFailure::Protocol { .. } => ("protocol_error", ExitCode::GeneralFailure),
        RunFailure::Gone | RunFailure::InputUploadRejected | RunFailure::InputDownloadRejected => {
            ("submission_failed", ExitCode::GeneralFailure)
        }
        RunFailure::Interrupted => ("acceptance_unknown", ExitCode::Interrupted),
    }
}

fn write_cancel_failure(
    deployment: &str,
    organization: &str,
    recovery: &CancelRecovery,
    failure: &RunFailure,
    dispatched: bool,
    authentication: crate::cli::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let (outcome, code, exit) = if dispatched
        && (matches!(
            failure,
            RunFailure::Unreachable(category) if *category != useful_api::UnreachableCategory::RateLimited
        ) || matches!(failure, RunFailure::Protocol { .. }))
    {
        (
            "acceptance_unknown",
            "acceptance_unknown",
            ExitCode::Unavailable,
        )
    } else {
        let (code, exit) = failure_code(failure, authentication);
        ("error", code, exit)
    };
    write_cloud!(
        "cancel",
        deployment,
        organization,
        &recovery.snapshot,
        outcome,
        Some(code),
        Some(&recovery.key),
        Some(recovery.mode),
        json,
        exit,
    )
}

#[cfg(test)]
trait RunObservationApi {
    fn get_run(&self, organization: &str, run_id: &str) -> Result<RunRead, RunFailure>;
}

#[cfg(test)]
impl<'a> RunObservationApi for RunApi<'a> {
    fn get_run(&self, organization: &str, run_id: &str) -> Result<RunRead, RunFailure> {
        self.get(organization, run_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::cli) enum TerminalRunState {
    Succeeded,
    Failed,
    Cancelled,
    Interrupted,
    Rejected,
}

#[cfg(test)]
type WaitObservation = crate::cli::TerminalObservation<Run, TerminalRunState>;

#[cfg(test)]
fn wait_for_terminal_run(
    api: &impl RunObservationApi,
    organization: &str,
    run_id: &str,
    timeout: Option<Duration>,
    control: &crate::cli::BlockingObservationControl,
    clock: &impl crate::cli::ObservationClock,
) -> Result<WaitObservation, RunFailure> {
    match crate::cli::wait_for_terminal_observation(
        || api.get_run(organization, run_id),
        |read| match read {
            RunRead::Materialized(run) => terminal_run_state(run.state),
            RunRead::Pending(_) => None,
        },
        RunFailure::retryable_observation,
        timeout,
        control,
        clock,
    )? {
        crate::cli::TerminalObservation::Terminal { resource, state } => match *resource {
            RunRead::Materialized(run) => Ok(crate::cli::TerminalObservation::Terminal {
                resource: run,
                state,
            }),
            RunRead::Pending(_) => Err(RunFailure::Protocol {
                credential_rejected: false,
            }),
        },
        crate::cli::TerminalObservation::TimedOut => Ok(crate::cli::TerminalObservation::TimedOut),
        crate::cli::TerminalObservation::Stopped => Ok(crate::cli::TerminalObservation::Stopped),
    }
}

const fn terminal_run_state(state: RunState) -> Option<TerminalRunState> {
    match state {
        RunState::Queued
        | RunState::Assigning
        | RunState::Preparing
        | RunState::Assigned
        | RunState::Running
        | RunState::Waiting
        | RunState::Cancelling => None,
        RunState::Succeeded => Some(TerminalRunState::Succeeded),
        RunState::Failed => Some(TerminalRunState::Failed),
        RunState::Cancelled => Some(TerminalRunState::Cancelled),
        RunState::Interrupted => Some(TerminalRunState::Interrupted),
        RunState::Rejected => Some(TerminalRunState::Rejected),
    }
}

fn run_api<'a>(
    client: &'a useful_api::HttpClient,
    deployment: &Deployment,
    access_token: &str,
    transport_policy: HttpTransportPolicy,
) -> anyhow::Result<RunApi<'a>> {
    RunApi::new(
        deployment.fingerprint().api_url(),
        access_token,
        transport_policy,
        client,
    )
    .map_err(|error| anyhow!(error))
    .context("prepare Cloud run networking")
}

// Keep the acting principal and semantic request pinned across a mutation
// replay; credential renewal never authorizes a different principal.
fn with_pinned_run_mutation<T>(
    deployment: &Deployment,
    options: &RunOptions,
    error_context: &'static str,
    operation: impl Fn(&RunApi<'_>) -> Result<T, RunFailure>,
) -> anyhow::Result<Result<T, RunFailure>> {
    let policy = options.http.transport_policy();
    let client = crate::cli::human_session_client(policy)?;
    let submit = |token: &str| {
        let api = run_api(&client, deployment, token, policy)?;
        Ok(operation(&api))
    };
    if let Some(api_key) = options.authentication.service_api_key()? {
        return submit(api_key.expose());
    }
    match useful_human_auth::execute_pinned_required(
        &client,
        deployment,
        |token| submit(token.expose()),
        |result| {
            result
                .as_ref()
                .is_ok_and(|value| value.as_ref().is_err_and(RunFailure::credential_rejected))
        },
    ) {
        Ok(useful_human_auth::BoundRequiredOperation::Completed { result, .. }) => result,
        Ok(
            useful_human_auth::BoundRequiredOperation::Unauthenticated { .. }
            | useful_human_auth::BoundRequiredOperation::ActingSessionChanged,
        ) => Ok(Err(RunFailure::Unauthenticated)),
        Err(error) => match error.unreachable_category() {
            Some(category) => Ok(Err(RunFailure::Unreachable(category))),
            None => Err(anyhow!(error).context(error_context)),
        },
    }
}

fn with_api_until<T>(
    deployment: &Deployment,
    transport_policy: HttpTransportPolicy,
    authentication: &crate::cli::PrincipalAuthenticationArgs,
    deadline: Option<Instant>,
    mut operation: impl FnMut(&RunApi<'_>, Option<Duration>) -> Result<T, RunFailure>,
) -> anyhow::Result<Result<T, RunFailure>> {
    let client = crate::cli::human_session_client(transport_policy)?;
    crate::cli::execute_selected_api_observation(
        crate::cli::principal_api_context(
            &client,
            deployment,
            authentication,
            "acquire human session for Cloud run observation",
        ),
        |access_token, _remaining| {
            let api = run_api(&client, deployment, access_token, transport_policy)?;
            let remaining = match crate::cli::observation_http_budget(deadline) {
                Ok(remaining) => remaining,
                Err(category) => return Ok(Err(RunFailure::Unreachable(category))),
            };
            Ok(operation(&api, remaining))
        },
        RunFailure::credential_rejected,
        || RunFailure::Unauthenticated,
        RunFailure::Unreachable,
        deadline,
    )
}

pub(in crate::cli) fn with_api<T>(
    deployment: &Deployment,
    transport_policy: HttpTransportPolicy,
    authentication: &crate::cli::PrincipalAuthenticationArgs,
    mut operation: impl FnMut(&RunApi<'_>) -> Result<T, RunFailure>,
) -> anyhow::Result<Result<T, RunFailure>> {
    let client = crate::cli::human_session_client(transport_policy)?;
    crate::cli::execute_selected_api_operation(
        crate::cli::principal_api_context(
            &client,
            deployment,
            authentication,
            "acquire human session for Cloud run operation",
        ),
        |access_token| {
            let api = run_api(&client, deployment, access_token, transport_policy)?;
            Ok(operation(&api))
        },
        RunFailure::credential_rejected,
        || RunFailure::Unauthenticated,
        RunFailure::Unreachable,
    )
}

fn write_observation_human(
    out: &mut impl io::Write,
    observation: &RunObservation,
    waiting: bool,
) -> anyhow::Result<()> {
    writeln!(out, "\nobserved at: {}", observation.observed_at)?;
    if waiting {
        write_waiting(out, observation)?;
    }
    writeln!(out, "placement (current attempt):")?;
    if let Some(place) = observation.placement.as_deref() {
        writeln!(out, "  runner: {} ({})", place.runner_name, place.runner_id)?;
        writeln!(out, "  pool: {} ({})", place.pool_name, place.pool_id)?;
    } else {
        writeln!(out, "  none")?;
    }
    if let Some(decline) = observation.last_decline.as_deref() {
        writeln!(out, "last placement decline:")?;
        writeln!(out, "  code: {}", enum_text(&decline.code)?)?;
        if let Some(reason) = &decline.reason {
            writeln!(out, "  reason: {}", enum_text(reason)?)?;
        }
        if let Some(cause) = decline
            .diagnostic
            .as_deref()
            .and_then(|diagnostic| diagnostic.decline_cause.as_deref())
        {
            writeln!(out, "  cause: {}", visible_text(cause))?;
        }
        writeln!(out, "  runner: {}", decline.runner_id)?;
        writeln!(out, "  declined at: {}", decline.declined_at)?;
    }
    writeln!(out, "Cloud assignment and runner connection:")?;
    if let Some(assignment) = observation.assignment.as_deref() {
        writeln!(
            out,
            "  assignment: {} ({})",
            assignment.id,
            enum_text(&assignment.state)?
        )?;
        writeln!(
            out,
            "  target: {} / {} / generation {}",
            assignment.runner_id, assignment.boot_id, assignment.presence_generation
        )?;
        writeln!(
            out,
            "  Cloud lease: sequence {}, expires {} ({})",
            assignment
                .lease_sequence
                .map_or_else(|| "none".to_owned(), |n| n.to_string()),
            assignment.lease_expires_at.as_deref().unwrap_or("none"),
            if assignment.lease_valid {
                "valid"
            } else {
                "not valid"
            }
        )?;
        writeln!(
            out,
            "  matching runner connected: {}",
            assignment.runner_connected
        )?;
        writeln!(
            out,
            "  matching runner last seen: {}",
            assignment.runner_last_seen_at.as_deref().unwrap_or("none")
        )?;
    } else {
        writeln!(out, "  no current assignment")?;
    }
    write_held_with(out, observation)?;
    writeln!(out, "last coordinator-accepted workflow transition:")?;
    if let Some(progress) = observation.last_transition.as_deref() {
        writeln!(
            out,
            "  recorded: {} (attempt {})",
            progress.recorded_at, progress.attempt_id
        )?;
        writeln!(
            out,
            "  kind: {} (transition {}, event {})",
            enum_text(&progress.kind)?,
            progress.transition_sequence,
            progress.event_sequence
        )?;
        writeln!(
            out,
            "  step: {}",
            progress.step_id.as_deref().unwrap_or("none")
        )?;
        writeln!(
            out,
            "  target state: {}",
            progress.target_state.as_deref().unwrap_or("unavailable")
        )?;
    } else {
        writeln!(out, "  none reported")?;
    }
    Ok(())
}

fn write_run_terminal_issue(out: &mut impl Write, run: &Run) -> anyhow::Result<()> {
    write_run_failure(out, run)?;
    if run.rejection.is_some() {
        writeln!(out)?;
    }
    write_rejection(out, run)?;
    Ok(())
}

/// The block naming the node a failed Cloud run failed at, nothing when it records none.
pub(in crate::cli) fn write_run_failure(out: &mut impl Write, run: &Run) -> anyhow::Result<()> {
    if let Some(failure) = run.failure.as_deref() {
        writeln!(out, "\nfailure:")?;
        writeln!(out, "  node: {}", visible_text(&failure.node.id))?;
        writeln!(out, "  role: {}", enum_text(&failure.node.role)?)?;
        writeln!(out, "  state: {}", enum_text(&failure.state)?)?;
        let detail = serde_json::to_value(&failure.detail)?;
        writeln!(out, "  detail: {}", visible_text(&detail.to_string()))?;
    }
    Ok(())
}

fn write_run_human(deployment: &str, heading: &str, run: &Run) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{heading}\n")?;
    writeln!(stdout, "run: {}", run.id)?;
    writeln!(
        stdout,
        "display name: {}",
        run.display_name.as_deref().unwrap_or("none")
    )?;
    writeln!(stdout, "organization: {}", run.organization_id)?;
    writeln!(stdout, "project: {}", run.project_id)?;
    writeln!(stdout, "execution spec: {}", run.execution_spec_id)?;
    writeln!(stdout, "state: {}", enum_text(&run.state)?)?;
    output::write_workflow_state(&mut stdout, run)?;
    write_run_attempt(&mut stdout, run)?;
    write_route(&mut stdout, run)?;
    write_run_sources_through_continuation(&mut stdout, run)?;
    write_run_terminal_issue(&mut stdout, run)?;
    write_run_delivery_and_times(&mut stdout, run)?;
    write_run_observation(&mut stdout, run, true)?;
    write_run_linear_lifecycle(&mut stdout, run)?;
    writeln!(stdout, "deployment: {deployment}")?;
    Ok(())
}

/// A Cloud run's version, current attempt, branches, actor and the sources of its credentials and
/// integrations.
pub(in crate::cli) fn write_run_attempt(out: &mut impl Write, run: &Run) -> anyhow::Result<()> {
    writeln!(out, "version: {}", run.version)?;
    writeln!(
        out,
        "attempt: {} (number {})",
        run.current_attempt_id, run.current_attempt_number
    )?;
    match run.source_branch.as_deref() {
        Some(branch) => writeln!(out, "source branch: {branch}")?,
        None => writeln!(out, "source: none")?,
    }
    writeln!(
        out,
        "workspace branch: {}",
        run.workspace_branch.as_deref().unwrap_or("none")
    )?;
    let actor = enum_text(&run.actor.kind)?;
    match run.actor.requester_principal_id.as_deref() {
        Some(principal) => writeln!(out, "actor: {actor} {principal}")?,
        None => writeln!(out, "actor: {actor}")?,
    }
    output::write_credential_sources(out, run)?;
    output::write_integration_sources(out, run)?;
    Ok(())
}

/// A Cloud run's workflow and workspace sources, inputs, integration context, cancellation,
/// automatic publication handoff, interruption and continuation, each a block of its own.
pub(in crate::cli) fn write_run_sources_through_continuation(
    out: &mut impl Write,
    run: &Run,
) -> anyhow::Result<()> {
    if let (Some(workflow), Some(workspace)) = (
        run.workflow_definition_source.as_deref(),
        run.primary_workspace_source.as_deref(),
    ) {
        writeln!(out, "\nworkflow source:")?;
        writeln!(
            out,
            "  repository connection: {}",
            workflow.repository_connection_id
        )?;
        writeln!(
            out,
            "  object format: {}",
            enum_text(&workflow.object_format)?
        )?;
        writeln!(out, "  commit: {}", workflow.commit_oid)?;
        writeln!(out, "  workflow: {}", workflow.workflow_path)?;
        writeln!(
            out,
            "  source closure: {}:{}",
            enum_text(&workflow.workflow_source_closure_digest.algorithm)?,
            workflow.workflow_source_closure_digest.value
        )?;
        writeln!(out, "\nprimary workspace source:")?;
        writeln!(out, "  kind: {}", enum_text(&workspace.kind)?)?;
        writeln!(out, "  provider: {}", enum_text(&workspace.provider_kind)?)?;
        writeln!(
            out,
            "  repository connection: {}",
            workspace.repository_connection_id
        )?;
        writeln!(
            out,
            "  object format: {}",
            enum_text(&workspace.object_format)?
        )?;
        writeln!(out, "  commit: {}", workspace.commit_oid)?;
        writeln!(
            out,
            "  materialization: {}",
            enum_text(&workspace.materialization_contract)?
        )?;
        if let Some(membership) = &run.workspace_membership {
            writeln!(out, "  membership ref: {}", membership.witness.r#ref)?;
            writeln!(out, "  membership tip: {}", membership.witness.tip_oid)?;
            writeln!(
                out,
                "  membership observed: {}",
                membership.witness.observed_at
            )?;
        }
    }
    writeln!(out, "\ninputs:")?;
    writeln!(
        out,
        "  input set: {}",
        run.inputs.input_set_id.as_deref().unwrap_or("none")
    )?;
    writeln!(out, "  named values: {}", run.inputs.input_count)?;
    writeln!(out, "  attachment members: {}", run.inputs.attachment_count)?;
    writeln!(out, "  bytes: {}", run.inputs.aggregate_bytes)?;
    writeln!(
        out,
        "  availability: {}",
        enum_text(&run.inputs.availability)?
    )?;
    writeln!(out, "\nintegration context:")?;
    if run.integration_context.is_empty() {
        writeln!(out, "  none")?;
    } else {
        let mut entries = run.integration_context.iter().collect::<Vec<_>>();
        entries.sort_by(|(first, _), (second, _)| first.as_bytes().cmp(second.as_bytes()));
        for (key, value) in entries {
            writeln!(out, "  {}: {}", visible_text(key), visible_text(value))?;
        }
    }
    writeln!(out, "\ncancellation:")?;
    if let Some(cancellation) = run.cancellation.as_deref() {
        writeln!(out, "  mode: {}", enum_text(&cancellation.mode)?)?;
        writeln!(
            out,
            "  graceful request: {}",
            cancellation
                .graceful_request_id
                .as_deref()
                .unwrap_or("none")
        )?;
        writeln!(
            out,
            "  force request: {}",
            cancellation.force_request_id.as_deref().unwrap_or("none")
        )?;
    } else {
        writeln!(out, "  none")?;
    }
    writeln!(out, "\nautomatic publication handoff:")?;
    if let Some(handoff) = run.publication.as_deref() {
        writeln!(out, "  export: {}", visible_text(&handoff.export_name))?;
        writeln!(out, "  state: {}", enum_text(&handoff.state)?)?;
        writeln!(
            out,
            "  publication: {}",
            handoff.publication_id.as_deref().unwrap_or("none")
        )?;
        if let Some(failure) = handoff.failure.as_deref() {
            writeln!(out, "  failure: {}", enum_text(&failure.code)?)?;
            writeln!(out, "  phase: {}", enum_text(&failure.phase)?)?;
            writeln!(out, "  retryable: {}", failure.retryable)?;
            if let Some(diagnostic) = failure.diagnostic.as_deref() {
                crate::cli::write_publication_diagnostic(out, diagnostic, "    ")?;
            }
        }
    } else {
        writeln!(out, "  none")?;
    }
    writeln!(out, "\ninterruption:")?;
    if let Some(interruption) = run.interruption.as_deref() {
        writeln!(out, "  phase: {}", enum_text(&interruption.phase)?)?;
        writeln!(out, "  cause: {}", enum_text(&interruption.cause)?)?;
        writeln!(
            out,
            "  executor fault: {}",
            interruption
                .executor_fault
                .as_ref()
                .map(enum_text)
                .transpose()?
                .as_deref()
                .unwrap_or("none")
        )?;
        if let Some(reason) = interruption.lease_loss.as_ref() {
            writeln!(out, "  lease loss: {}", enum_text(reason)?)?;
        }
        writeln!(
            out,
            "  stop confirmed: {}",
            if interruption.stop_confirmed {
                "yes"
            } else {
                "no"
            }
        )?;
    } else {
        writeln!(out, "  none")?;
    }
    continuation::write_run_continuation(out, run)?;
    Ok(())
}

/// A Cloud run's artifact delivery and when it was created and last updated.
pub(in crate::cli) fn write_run_delivery_and_times(
    out: &mut impl Write,
    run: &Run,
) -> anyhow::Result<()> {
    writeln!(out, "\nartifact delivery:")?;
    match run.artifact_delivery.as_deref() {
        None => writeln!(out, "  none")?,
        Some(RunArtifactDelivery::RunArtifactDeliverySucceeded(delivery)) => {
            writeln!(out, "  state: succeeded")?;
            writeln!(out, "  artifact set: {}", delivery.artifact_set_id)?;
        }
        Some(RunArtifactDelivery::RunArtifactDeliveryRegistrationFailed(delivery)) => {
            writeln!(out, "  state: failed")?;
            writeln!(out, "  phase: {}", enum_text(&delivery.phase)?)?;
            writeln!(out, "  code: {}", enum_text(&delivery.code)?)?;
        }
        Some(RunArtifactDelivery::RunArtifactDeliveryUploadFailed(delivery)) => {
            writeln!(out, "  state: failed")?;
            writeln!(out, "  phase: {}", enum_text(&delivery.phase)?)?;
            writeln!(out, "  code: {}", enum_text(&delivery.code)?)?;
        }
        Some(RunArtifactDelivery::RunArtifactDeliveryPreparationFailed(delivery)) => {
            writeln!(out, "  state: failed")?;
            writeln!(out, "  phase: {}", enum_text(&delivery.phase)?)?;
            writeln!(out, "  code: {}", enum_text(&delivery.code)?)?;
        }
    }
    writeln!(out, "\ncreated: {}", run.created_at)?;
    writeln!(out, "updated: {}", run.updated_at)?;
    Ok(())
}

/// A Cloud run's Linear lifecycle binding with its latest update, when it has
/// one.
pub(in crate::cli) fn write_run_linear_lifecycle(
    out: &mut impl Write,
    run: &Run,
) -> anyhow::Result<()> {
    if let Some(view) = run.linear_lifecycle.as_deref() {
        writeln!(out, "\nlinear lifecycle:")?;
        write_linear_lifecycle_view(out, view, "  ")?;
    }
    Ok(())
}

/// Writes one `key: value` line per present member of a Linear lifecycle binding, in the view's
/// contract order.
fn write_linear_lifecycle_view(
    out: &mut impl Write,
    view: &RunLinearLifecycle,
    indent: &str,
) -> anyhow::Result<()> {
    writeln!(out, "{indent}trigger: {}", view.trigger_id)?;
    writeln!(
        out,
        "{indent}configuration version: {}",
        view.configuration_version
    )?;
    writeln!(out, "{indent}connection: {}", view.connection_id)?;
    writeln!(
        out,
        "{indent}workspace: {}",
        visible_text(&view.workspace_id)
    )?;
    writeln!(out, "{indent}issue: {}", visible_text(&view.issue_id))?;
    writeln!(
        out,
        "{indent}ownership state: {}",
        enum_text(&view.ownership_state)?
    )?;
    if let Some(attempt_id) = &view.attempt_id {
        writeln!(out, "{indent}attempt: {attempt_id}")?;
    }
    if let Some(attempt_number) = view.attempt_number {
        writeln!(out, "{indent}attempt number: {attempt_number}")?;
    }
    if let Some(event) = view.ownership_event.as_deref() {
        let node = match event.node.as_deref() {
            Some(node) => format!(", node {}", node_text(&node.scope, &node.role, &node.id)?),
            None => String::new(),
        };
        writeln!(
            out,
            "{indent}ownership event: {} ({}, sequence {}, occurred {}, attempt {} number {}{node})",
            visible_text(&event.event_id),
            enum_text(&event.event_type)?,
            event.sequence,
            event.occurred_at,
            event.attempt_id,
            event.attempt_number,
        )?;
    }
    if let Some(run_id) = &view.controlling_run_id {
        writeln!(out, "{indent}controlling run: {run_id}")?;
    }
    if let Some(code) = &view.reason_code {
        writeln!(out, "{indent}reason code: {}", enum_text(code)?)?;
    }
    if let Some(update) = view.latest_update.as_deref() {
        writeln!(out, "{indent}latest update:")?;
        write_linear_lifecycle_update(out, update, &format!("{indent}  "))?;
    }
    Ok(())
}

/// Writes one `key: value` line per present member of a Linear lifecycle update, as `useful
/// workflow run show` and `useful workflow run linear list` write it.
pub(in crate::cli) fn write_linear_lifecycle_update(
    out: &mut impl Write,
    update: &RunLinearLifecycleUpdate,
    indent: &str,
) -> anyhow::Result<()> {
    writeln!(out, "{indent}id: {}", update.id)?;
    writeln!(out, "{indent}attempt: {}", update.attempt_id)?;
    writeln!(out, "{indent}attempt number: {}", update.attempt_number)?;
    writeln!(out, "{indent}event: {}", visible_text(&update.event_id))?;
    writeln!(
        out,
        "{indent}event type: {}",
        enum_text(&update.event_type)?
    )?;
    writeln!(out, "{indent}event sequence: {}", update.event_sequence)?;
    writeln!(out, "{indent}event occurred: {}", update.event_occurred_at)?;
    if let Some(node) = update.node.as_deref() {
        writeln!(
            out,
            "{indent}node: {}",
            node_text(&node.scope, &node.role, &node.id)?
        )?;
    }
    writeln!(out, "{indent}created: {}", update.created_at)?;
    writeln!(out, "{indent}updated: {}", update.updated_at)?;
    writeln!(out, "{indent}state: {}", enum_text(&update.state)?)?;
    if let Some(code) = &update.reason_code {
        writeln!(out, "{indent}reason code: {}", enum_text(code)?)?;
    }
    writeln!(out, "{indent}cycle number: {}", update.cycle_number)?;
    writeln!(out, "{indent}cycle deadline: {}", update.cycle_deadline)?;
    writeln!(out, "{indent}request count: {}", update.request_count)?;
    writeln!(out, "{indent}retryable: {}", update.retryable)?;
    for (label, state_id) in [
        ("desired state", &update.desired_state_id),
        ("observed state", &update.observed_state_id),
        ("confirmed state", &update.confirmed_state_id),
    ] {
        if let Some(state_id) = state_id {
            writeln!(out, "{indent}{label}: {}", visible_text(state_id))?;
        }
    }
    if let Some(next_attempt_at) = &update.next_attempt_at {
        writeln!(out, "{indent}next attempt: {next_attempt_at}")?;
    }
    if let Some(blocking) = update.blocking_update.as_deref() {
        writeln!(
            out,
            "{indent}blocking update: {} (run {})",
            blocking.update_id, blocking.run_id
        )?;
    }
    if let Some(facts) = update.diagnostic.as_deref() {
        let facts = [
            facts
                .cause
                .as_deref()
                .map(|cause| format!("cause {}", visible_text(cause))),
            facts
                .provider_status
                .map(|status| format!("provider status {status}")),
            facts
                .transport_error
                .as_deref()
                .map(|error| format!("transport error {}", visible_text(error))),
            facts
                .retry_after
                .as_deref()
                .map(|at| format!("retry after {at}")),
        ];
        let facts: Vec<String> = facts.into_iter().flatten().collect();
        writeln!(out, "{indent}diagnostic: {}", facts.join(", "))?;
    }
    Ok(())
}

/// A step node as its role and slash-joined scope path.
fn node_text(scope: &[String], role: &impl Serialize, id: &str) -> anyhow::Result<String> {
    let path = scope.iter().map(String::as_str).chain([id]);
    Ok(format!(
        "{} {}",
        enum_text(role)?,
        visible_text(&path.collect::<Vec<_>>().join("/"))
    ))
}

/// What Cloud observed of a run's placement, assignment, runner connection and latest workflow
/// transition, with what a queued run waits for unless `waiting` is false.
pub(in crate::cli) fn write_run_observation(
    out: &mut impl Write,
    run: &Run,
    waiting: bool,
) -> anyhow::Result<()> {
    if let Some(observation) = run.observation.as_deref() {
        write_observation_human(out, observation, waiting)?;
    } else {
        writeln!(out, "\nassignment and reported progress: unavailable")?;
    }
    Ok(())
}

fn enum_text(value: &impl Serialize) -> anyhow::Result<String> {
    match serde_json::to_value(value).context("serialize Cloud run field")? {
        serde_json::Value::String(value) => Ok(value),
        _ => Err(anyhow!("Cloud run field is not a contracted string")),
    }
}

pub(in crate::cli) fn write_failure(
    deployment: &str,
    organization: &str,
    run_id: Option<&str>,
    failure: &RunFailure,
    authentication: crate::cli::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    write_failure_with_input_set(
        deployment,
        organization,
        run_id,
        None,
        failure,
        authentication,
        json,
    )
}

pub(in crate::cli) fn write_failure_with_input_set(
    deployment: &str,
    organization: &str,
    run_id: Option<&str>,
    input_set_id: Option<&str>,
    failure: &RunFailure,
    authentication: crate::cli::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let (outcome, category, human, class) = match failure {
        RunFailure::Unauthenticated => (
            "unauthenticated",
            None,
            authentication
                .rejected_error(
                    "error: Cloud run access requires sign-in\n\nSign in first:\n  useful account login",
                )
                .to_owned(),
            OutcomeClass::Unauthenticated,
        ),
        RunFailure::Forbidden => (
            "forbidden",
            None,
            "error: Cloud run operation is not permitted for this account\n\nAsk an organization owner to perform this operation.".to_owned(),
            OutcomeClass::Forbidden,
        ),
        RunFailure::InvalidInput => (
            "invalid_input",
            None,
            format!("error: Cloud run input rejected by {deployment}\n\nCheck the organization, project, workflow path, and optional values, then try again."),
            OutcomeClass::GeneralFailure,
        ),
        RunFailure::NotFound => (
            "not_found",
            None,
            "error: Cloud run resource not found or unavailable\n\nCheck the organization and resource identifier, then try again.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        RunFailure::Conflict | RunFailure::IdempotencyConflict | RunFailure::RetryConflict(_)
        | RunFailure::ContinuationAdmissionInvalid(_) => (
            "conflict",
            None,
            "error: Cloud run request conflicts with current state\n\nCheck the resource state and try again.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        RunFailure::InputAdmissionRejected { .. } => (
            "input_admission_rejected", None,
            "error: Cloud run input admission rejected\n\nCorrect the named input and submit a corrected request.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        RunFailure::AdmissionRejected { .. } => (
            "admission_rejected", None,
            "error: Cloud run admission rejected\n\nCorrect the run's source selection and submit a new request.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        RunFailure::CreationRejected => (
            "creation_rejected",
            None,
            "error: Cloud run creation was rejected before the run materialized\n\nInspect the run request and create a new run after correcting the rejection cause.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        RunFailure::PathRunRetired => (
            "path_run_retired",
            None,
            format!("error: Cloud run is no longer retried or continued\n\n{PATH_RUN_RETIRED_GUIDANCE}"),
            OutcomeClass::GeneralFailure,
        ),
        RunFailure::Gone => (
            "gone",
            None,
            "error: Cloud run input content is no longer available\n\nStart a new input set or run instead.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        RunFailure::RetryAfter(_)
        | RunFailure::RetryAmbiguousRateLimited
        | RunFailure::RetryAmbiguousAuthentication
        | RunFailure::ContinuationAcceptanceUnknown => (
            "unreachable", None,
            "error: Cloud run API is temporarily unavailable\n\nTry again after the reported interval.".to_owned(),
            OutcomeClass::RateLimited,
        ),
        RunFailure::Unreachable(category) => (
            "unreachable",
            Some(category.as_str()),
            format!("error: contact Cloud run API at {deployment}: {}\n\nCheck network access to the deployment and try again.", category.as_str()),
            crate::cli::unreachable_outcome_class(*category),
        ),
        RunFailure::InputUploadRejected => (
            "conflict",
            None,
            "error: Cloud run input upload was not accepted\n\nInspect the input set and upload the selected member again.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        RunFailure::InputDownloadRejected => (
            "integrity_mismatch",
            None,
            "error: retained input download did not match its manifest\n\nNo downloaded result was committed. Try again later.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        RunFailure::Interrupted => (
            "interrupted",
            None,
            "error: retained input operation was interrupted\n\nRun the command again to start with fresh capabilities.".to_owned(),
            OutcomeClass::Interrupted,
        ),
        RunFailure::Protocol { .. } => (
            "invalid_response",
            None,
            "error: Cloud run API response does not match the public contract\n\nTry again later.".to_owned(),
            OutcomeClass::Protocol,
        ),
    };
    if json {
        write_json(&FailureResult {
            schema_version: 1,
            deployment,
            outcome,
            organization_ref: organization,
            run_id,
            input_set_id,
            category,
        })?;
    } else if let Some(input_set_id) = input_set_id {
        writeln!(
            io::stderr().lock(),
            "{human}\n\ninput set: {input_set_id}\n\nContinue explicitly with `useful workflow input-set show` before creating another set."
        )?;
    } else {
        writeln!(io::stderr().lock(), "{human}")?;
    }
    Ok(class.exit_code())
}

pub(in crate::cli) fn write_resource_mutation_unknown(
    operation: &str,
    deployment: &str,
    organization: &str,
    resource_kind: &str,
    resource_id: Option<&str>,
    json: bool,
    exit_code: ExitCode,
) -> anyhow::Result<ExitCode> {
    if json {
        write_json(&UnknownResourceMutationResult {
            schema_version: 1,
            deployment,
            outcome: "unknown",
            organization_ref: organization,
            operation,
            resource_kind,
            resource_id,
            commitment: "unknown",
        })?;
    } else {
        let resource = resource_id
            .map(|resource_id| format!("\n{resource_kind}: {resource_id}"))
            .unwrap_or_default();
        writeln!(
            io::stderr().lock(),
            "error: {operation} is unconfirmed after interruption\n{resource}\norganization: {organization}\ncommitment: unknown\n\nInspect the resource before repeating this operation."
        )?;
    }
    Ok(exit_code)
}

pub(in crate::cli) fn write_json(value: &impl Serialize) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer_pretty(&mut stdout, value).context("serialize JSON Cloud run result")?;
    writeln!(stdout).context("write Cloud run result")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FailureResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    #[serde(skip_serializing_if = "str::is_empty")]
    organization_ref: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    run_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input_set_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnknownResourceMutationResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    organization_ref: &'a str,
    operation: &'a str,
    resource_kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_id: Option<&'a str>,
    commitment: &'static str,
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;
    use crate::cli::observation_test_support::ControlledObservationClock as ControlledWaitClock;
    use useful_api::UnreachableCategory;

    #[test]
    fn run_show_renders_latest_decline_beside_placement_and_progress() {
        let observation: RunObservation = serde_json::from_value(serde_json::json!({
            "observedAt": "2026-08-03T12:00:00Z",
            "placement": {"runnerId": "runner-b", "runnerName": "second",
                "poolId": "pool-b", "poolName": "work"},
            "assignment": {"id": "assignment-b", "state": "active", "runnerId": "runner-b",
                "bootId": "boot-b", "presenceGeneration": 2, "leaseSequence": 9,
                "leaseExpiresAt": "2026-08-03T13:00:00Z", "leaseValid": false,
                "runnerConnected": true, "runnerLastSeenAt": null},
            "lastDecline": {"code": "runner_unable", "reason": "source_service_unavailable",
                "runnerId": "runner-c", "declinedAt": "2026-08-03T11:59:00Z",
                "diagnostic": {"stage": "decline-stage-sentinel",
                    "declineCause": "source_repository_unavailable",
                    "transportError": "decline-transport-sentinel"}},
            "lastTransition": {"attemptId": "attempt-a", "eventSequence": 3,
                "transitionSequence": 2, "recordedAt": "2026-08-03T11:00:00Z",
                "kind": "step_state_changed", "stepId": "build", "targetState": "running"}
        }))
        .expect("valid run observation");
        let mut output = Vec::new();
        write_observation_human(&mut output, &observation, true).expect("render observation");
        let output = String::from_utf8(output).expect("human report is UTF-8");
        for identifier in [
            "runner-b",
            "pool-b",
            "assignment-b",
            "attempt-a",
            "build",
            "runner_unable",
            "source_service_unavailable",
            "runner-c",
            "2026-08-03T11:59:00Z",
        ] {
            assert!(output.contains(identifier), "missing {identifier}");
        }
        assert_eq!(
            line_after(&output, "  reason: source_service_unavailable"),
            Some("  cause: source_repository_unavailable"),
            "decline cause belongs under its reason in {output}"
        );
        assert!(
            !output.contains("sentinel"),
            "runner diagnostic rendered in {output}"
        );
        // The public projection is serialized by the run-show command; the human
        // rendering must keep placement separate from coordinator progress.
    }

    fn line_after<'a>(output: &'a str, line: &str) -> Option<&'a str> {
        let mut lines = output.lines();
        lines.find(|candidate| *candidate == line)?;
        lines.next()
    }

    fn render_decline(decline: serde_json::Value) -> String {
        let observation: RunObservation = serde_json::from_value(serde_json::json!({
            "observedAt": "2026-08-03T12:00:00Z",
            "placement": null,
            "assignment": null,
            "lastTransition": null,
            "lastDecline": decline,
        }))
        .expect("valid run observation");
        let mut output = Vec::new();
        write_observation_human(&mut output, &observation, false).expect("render observation");
        String::from_utf8(output).expect("human report is UTF-8")
    }

    #[test]
    fn run_show_prints_decline_cause_after_code_when_decline_has_no_reason() {
        let output = render_decline(serde_json::json!({
            "code": "capacity_unavailable", "runnerId": "runner-c",
            "declinedAt": "2026-08-03T11:59:00Z",
            "diagnostic": {"stage": "host_disk", "declineCause": "disk_space_low"}
        }));
        assert_eq!(
            line_after(&output, "  code: capacity_unavailable"),
            Some("  cause: disk_space_low"),
            "decline cause belongs under its code in {output}"
        );
        assert!(!output.contains("host_disk"), "stage rendered in {output}");
    }

    #[test]
    fn run_show_prints_no_decline_cause_when_diagnostic_names_none() {
        for decline in [
            serde_json::json!({"code": "runner_unable", "reason": "source_service_unavailable",
                "runnerId": "runner-c", "declinedAt": "2026-08-03T11:59:00Z"}),
            serde_json::json!({"code": "runner_unable", "reason": "source_service_unavailable",
                "runnerId": "runner-c", "declinedAt": "2026-08-03T11:59:00Z",
                "diagnostic": {"stage": "source_materialization"}}),
        ] {
            let output = render_decline(decline);
            assert!(
                output.contains("last placement decline:"),
                "decline missing from {output}"
            );
            assert!(!output.contains("cause:"), "cause rendered in {output}");
        }
    }

    #[test]
    fn run_show_escapes_control_characters_in_decline_cause() {
        let output = render_decline(serde_json::json!({
            "code": "capacity_unavailable", "runnerId": "runner-c",
            "declinedAt": "2026-08-03T11:59:00Z",
            "diagnostic": {"declineCause": "disk\u{1b}[2Jlow"}
        }));
        assert!(
            !output.contains('\u{1b}'),
            "raw escape rendered in {output}"
        );
        assert_eq!(
            line_after(&output, "  code: capacity_unavailable"),
            Some("  cause: disk\\x1b[2Jlow"),
            "cause not escaped in {output}"
        );
    }

    struct ScriptedObservationApi {
        responses: RefCell<VecDeque<Result<RunRead, RunFailure>>>,
    }

    impl ScriptedObservationApi {
        fn new(responses: impl IntoIterator<Item = Result<Run, RunFailure>>) -> Self {
            Self {
                responses: RefCell::new(
                    responses
                        .into_iter()
                        .map(|response| response.map(Box::new).map(RunRead::Materialized))
                        .collect(),
                ),
            }
        }
    }

    impl RunObservationApi for ScriptedObservationApi {
        fn get_run(&self, _organization: &str, _run_id: &str) -> Result<RunRead, RunFailure> {
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("the polling scenario should provide another response")
        }
    }

    fn observe(
        api: &ScriptedObservationApi,
        timeout: Option<Duration>,
        clock: &ControlledWaitClock,
    ) -> Result<WaitObservation, RunFailure> {
        wait_for_terminal_run(
            api,
            "acme-research",
            "run_01k0z6r1w8f4jy2m7q9v3x5abc",
            timeout,
            &crate::cli::BlockingObservationControl::new(),
            clock,
        )
    }

    fn assert_succeeded_after_single_poll(
        result: Result<WaitObservation, RunFailure>,
        clock: ControlledWaitClock,
        context: &str,
    ) {
        assert!(matches!(
            result.unwrap_or_else(|failure| panic!("{context}: {failure:?}")),
            WaitObservation::Terminal {
                state: TerminalRunState::Succeeded,
                ..
            }
        ));
        clock.assert_single_poll();
    }

    fn run(state: RunState) -> Run {
        let state = serde_json::to_value(state).expect("run state should serialize");
        serde_json::from_value(serde_json::json!({
            "id": "run_01k0z6r1w8f4jy2m7q9v3x5abc",
            "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
            "projectId": "prj_01k0z6r1w8f4jy2m7q9v3x5abc",
            "displayName": null,
            "executionSpecId": "xsp_01k0z6r1w8f4jy2m7q9v3x5abc",
            "state": state,
            "version": 1,
            "currentAttemptId": "atm_01k0z6r1w8f4jy2m7q9v3x5abc",
            "currentAttemptNumber": 1,
            "sourceBranch": "main",
            "workspaceSource": null,
            "workspaceBranch": null,
            "workspaceMembership": null,
            "workflowDefinitionSource": {
                "repositoryConnectionId": "rpc_01k0z6r1w8f4jy2m7q9v3x5abc",
                "objectFormat": "sha1",
                "commitOid": "0123456789abcdef0123456789abcdef01234567",
                "workflowPath": "workflow.yaml",
                "workflowSourceClosureDigest": {
                    "algorithm": "sha256",
                    "value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                }
            },
            "primaryWorkspaceSource": {
                "kind": "connected_repository",
                "providerKind": "github",
                "repositoryConnectionId": "rpc_01k0z6r1w8f4jy2m7q9v3x5abc",
                "objectFormat": "sha1",
                "commitOid": "0123456789abcdef0123456789abcdef01234567",
                "materializationContract": "git_full_clone_v1"
            },
            "sourceDisplaySnapshot": null,
            "inputs": {
                "inputSetId": null,
                "inputCount": 0,
                "attachmentCount": 0,
                "aggregateBytes": 0,
                "availability": "available"
            },
            "integrationContext": {},
            "actor": {"kind": "app"},
            "publication": null,
            "cancellation": null,
            "interruption": null,
            "failure": null,
            "rejection": null,
            "artifactDelivery": null,
            "portableResult": "absent",
            "continuation": null,
            "createdAt": "2026-08-10T12:00:00Z",
            "updatedAt": "2026-08-10T12:00:00Z"
        }))
        .expect("run fixture should match the generated model")
    }

    #[test]
    fn cloud_run_reader_distinguishes_pending_preparation_from_portable_result() {
        let mut document = serde_json::to_value(run(RunState::Running)).unwrap();
        document["continuation"] = serde_json::json!({
            "runner": "retaining",
            "request": { "fromSteps": ["rerun"], "definition": "inherited" },
            "fromSteps": ["rerun"], "reexecutedSteps": ["rerun"],
            "inheritedSteps": [{"id": "produce", "priorState": "succeeded", "definitionChanged": false}],
            "definitionSource": {
                "kind": "inherited",
                "manifestDigest": {"algorithm": "sha256", "value": "a".repeat(64)},
                "priorManifestDigest": {"algorithm": "sha256", "value": "a".repeat(64)}
            },
            "workspace": {
                "executionRoot": "/runner/work", "priorExecutionRoot": "/runner/work",
                "preparation": "pending", "startSnapshot": null, "priorSettlementSnapshot": null,
                "modified": "unknown", "quiescence": null
            }
        });
        let pending: Run = serde_json::from_value(document.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(pending.portable_result).unwrap(),
            "absent"
        );
        let workspace = pending.continuation.unwrap().workspace.unwrap();
        assert!(workspace.start_snapshot.is_none());
        assert!(workspace.quiescence.is_none());
        document["state"] = serde_json::json!("interrupted");
        document["interruption"] = serde_json::json!({
            "phase": "accepted", "cause": "retained_workspace_unavailable",
            "executorFault": null, "leaseLoss": null, "stopConfirmed": false
        });
        document["continuation"]["workspace"]["preparation"] = serde_json::json!("unavailable");
        let unavailable: Run = serde_json::from_value(document).unwrap();
        assert!(
            unavailable
                .continuation
                .unwrap()
                .workspace
                .unwrap()
                .start_snapshot
                .is_none()
        );
    }

    /// The lines `write_run_terminal_issue` prints for a run rejected with `rejection`.
    fn rejection_lines(rejection: serde_json::Value) -> Vec<String> {
        let mut rejected = serde_json::to_value(run(RunState::Rejected)).unwrap();
        rejected["rejection"] = rejection;
        let mut output = Vec::new();
        super::write_run_terminal_issue(&mut output, &serde_json::from_value(rejected).unwrap())
            .unwrap();
        String::from_utf8(output)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    // A failure and a rejection print without their runner diagnostic, except that a
    // rejection prints, under its reason, each validation fact its diagnostic holds,
    // escaped, and nothing of a recovery reason it carries.
    #[test]
    fn terminal_run_human_output_includes_primary_issue_or_rejection() {
        let mut failed = serde_json::to_value(run(RunState::Failed)).unwrap();
        failed["failure"] = serde_json::json!({
            "node": {"id": "work", "role": "step"}, "state": "failed",
            "detail": {"code": "command_exit", "exitCode": 23,
                "input": {"name": "source"}, "output": {"name": "result"}},
            "diagnostic": {"stage": "failure-stage-sentinel",
                "harnessError": "failure-harness-sentinel",
                "gitCommand": "failure-git-sentinel"}
        });
        let mut output = Vec::new();
        super::write_run_terminal_issue(&mut output, &serde_json::from_value(failed).unwrap())
            .unwrap();
        let text = String::from_utf8(output).unwrap();
        for field in [
            "work",
            "step",
            "failed",
            "command_exit",
            "exitCode",
            "input",
            "output",
        ] {
            assert!(text.contains(field), "missing {field} in {text}");
        }
        assert!(
            !text.contains("sentinel"),
            "runner diagnostic rendered in {text}"
        );

        let text = rejection_lines(serde_json::json!({"reason": "source_commit_unavailable",
            "diagnostic": {"stage": "rejection-stage-sentinel",
                "transportError": "rejection-transport-sentinel"}}))
        .join("\n");
        assert!(text.contains("source_commit_unavailable"));
        assert!(
            !text.contains("sentinel"),
            "runner diagnostic rendered in {text}"
        );
        assert!(!text.contains("validation"), "{text}");

        let lines = rejection_lines(serde_json::json!({
            "reason": "workflow_source_invalid",
            "recoveryReason": "workspace_not_found",
            "diagnostic": {"stage": "workflow_tree_publication",
                "declineCause": "workflow_tree_publication_refused",
                "validationCode": "child_workflow_nested", "validationLocation": "step_workflow",
                "validationPath": "workflow.yaml", "validationStep": "parts"}
        }));
        let text = lines.join("\n");
        let reason = lines
            .iter()
            .position(|line| line.trim_start() == "reason: workflow_source_invalid")
            .unwrap_or_else(|| panic!("{text}"));
        assert_eq!(
            lines[reason + 1..]
                .iter()
                .map(|line| line.trim_start())
                .collect::<Vec<_>>(),
            [
                "validation code: child_workflow_nested",
                "validation location: step_workflow",
                "validation path: workflow.yaml",
                "validation step: parts",
            ],
            "{text}"
        );
        assert!(!text.contains("workflow_tree_publication"), "{text}");

        let lines = rejection_lines(serde_json::json!({
            "reason": "workflow_source_invalid",
            "diagnostic": {"validationCode": "child_workflow_nested"}
        }));
        let facts = lines
            .iter()
            .filter(|line| line.trim_start().starts_with("validation"))
            .map(|line| line.trim_start())
            .collect::<Vec<_>>();
        assert_eq!(
            facts,
            ["validation code: child_workflow_nested"],
            "{lines:?}"
        );

        let lines = rejection_lines(serde_json::json!({
            "reason": "workflow_source_invalid",
            "diagnostic": {"validationStep": "\u{1b}[2Jparts"}
        }));
        let text = lines.join("\n");
        assert!(!text.contains('\u{1b}'), "{text:?}");
        assert!(
            lines
                .iter()
                .any(|line| line.trim_start() == "validation step: \\x1b[2Jparts"),
            "{text}"
        );
    }

    #[test]
    fn publication_wait_uses_one_budget_across_run_handoff_and_linked_attempt() {
        let started = useful_support::monotonic_now();
        let clock = ControlledWaitClock::new(started);
        let mut pending = serde_json::to_value(run(RunState::Succeeded)).unwrap();
        pending["publication"] = serde_json::json!({
            "exportName": "changes", "state": "pending", "publicationId": null,
            "failure": null
        });
        let mut linked = pending.clone();
        linked["publication"]["state"] = serde_json::json!("started");
        linked["publication"]["publicationId"] =
            serde_json::json!("pub_01k0z6r1w8f4jy2m7q9v3x5abc");
        let pending: Run = serde_json::from_value(pending).unwrap();
        let linked: Run = serde_json::from_value(linked).unwrap();
        let mut reads = VecDeque::from([
            (Duration::from_secs(7), run(RunState::Running)),
            (Duration::from_secs(5), pending),
            (Duration::from_secs(3), linked.clone()),
        ]);
        let initial = CloudSnapshot::for_run(&linked.id);
        let mut latest = initial.clone();
        let mut publication_reads = 0;
        let result = observation::wait_run_with_reads(
            observation::WaitRunContext {
                snapshot: &initial,
                timeout: Some(Duration::from_secs(7)),
                started,
            },
            &crate::cli::BlockingObservationControl::new(),
            &clock,
            |snapshot| latest = snapshot,
            |remaining| {
                let (expected, run) = reads.pop_front().expect("no extra Run GET");
                assert_eq!(remaining, Some(expected));
                Ok(RunRead::Materialized(Box::new(run)))
            },
            |publication_id, remaining| {
                publication_reads += 1;
                assert_eq!(publication_id, "pub_01k0z6r1w8f4jy2m7q9v3x5abc");
                assert_eq!(remaining, Some(Duration::from_secs(3)));
                crate::cli::ObservationClock::sleep(&clock, Duration::from_secs(1));
                Err(RunFailure::Unreachable(UnreachableCategory::Server))
            },
        )
        .unwrap();
        assert!(matches!(result, crate::cli::TerminalObservation::TimedOut));
        assert!(reads.is_empty());
        assert_eq!(publication_reads, 1);
        assert_eq!(latest.run.as_deref(), Some(&linked));
        assert!(latest.publication.is_none());
        assert_eq!(
            clock.into_sleeps(),
            vec![
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_secs(1),
                Duration::from_secs(2)
            ]
        );
    }

    fn receipt(state: &str, run: Option<Run>) -> useful_api::RunCancellationEnvelope {
        let resolution = if state == "resolved" {
            serde_json::json!({"kind":"applied", "resolvedAt":"2026-08-10T12:05:00Z",
                "effectiveRequestId":"cmd_01k0z6r1w8f4jy2m7q9v3x5abc", "runVersion":1})
        } else {
            serde_json::Value::Null
        };
        serde_json::from_value(serde_json::json!({
            "request": {"id":"cmd_01k0z6r1w8f4jy2m7q9v3x5abc",
                "organizationId":"org_01k0z6r1w8f4jy2m7q9v3x5abc",
                "runId":"run_01k0z6r1w8f4jy2m7q9v3x5abc", "attemptId":null,
                "mode":"graceful", "acceptedAt":"2026-08-10T12:00:00Z",
                "state": state, "resolution": resolution},
            "run": run
        }))
        .unwrap()
    }

    fn scripted_cancellation(
        responses: impl IntoIterator<Item = Result<useful_api::RunCancellationEnvelope, RunFailure>>,
        mut record: impl FnMut(CloudSnapshot),
    ) -> (
        Result<crate::cli::TerminalObservation<CloudSnapshot, ()>, RunFailure>,
        Vec<Duration>,
        usize,
    ) {
        let mut snapshot = CloudSnapshot::for_run("run_01k0z6r1w8f4jy2m7q9v3x5abc");
        snapshot.cancellation_request = Some(receipt("pending", None).request);
        let responses = RefCell::new(responses.into_iter().collect::<VecDeque<_>>());
        let clock = ControlledWaitClock::new(useful_support::monotonic_now());
        let result = observation::wait_receipt_with(
            |_| responses.borrow_mut().pop_front().unwrap(),
            &snapshot,
            None,
            useful_support::monotonic_now(),
            &crate::cli::BlockingObservationControl::new(),
            &clock,
            &mut record,
        );
        (result, clock.into_sleeps(), responses.into_inner().len())
    }

    #[test]
    fn cancellation_observation_requires_both_resolved_receipt_and_terminal_run() {
        let recorded = RefCell::new(Vec::new());
        let (result, sleeps, remaining) = scripted_cancellation(
            [
                Ok(receipt("pending", Some(run(RunState::Succeeded)))),
                Ok(receipt("resolved", Some(run(RunState::Running)))),
                Ok(receipt("resolved", Some(run(RunState::Cancelled)))),
            ],
            |latest| recorded.borrow_mut().push(latest),
        );
        let result = result.unwrap();
        assert!(
            matches!(result, crate::cli::TerminalObservation::Terminal { resource, .. }
            if resource.run.as_deref().is_some_and(|run| run.state == RunState::Cancelled))
        );
        assert_eq!(recorded.borrow().len(), 3);
        assert_eq!(remaining, 0);
        assert_eq!(sleeps, vec![Duration::from_secs(2); 2]);
    }

    #[test]
    fn cancellation_observation_fails_on_second_consecutive_retryable_error() {
        let (result, sleeps, remaining) = scripted_cancellation(
            [
                Err(RunFailure::Unreachable(UnreachableCategory::Server)),
                Err(RunFailure::Unreachable(UnreachableCategory::Server)),
            ],
            |_| {},
        );
        assert!(matches!(
            result,
            Err(RunFailure::Unreachable(UnreachableCategory::Server))
        ));
        assert_eq!(remaining, 0);
        assert_eq!(sleeps, vec![Duration::from_secs(2)]);
    }

    #[test]
    fn wait_polls_every_nonterminal_state_until_each_terminal_state() {
        let nonterminal = [
            RunState::Queued,
            RunState::Assigning,
            RunState::Preparing,
            RunState::Assigned,
            RunState::Running,
            RunState::Waiting,
            RunState::Cancelling,
        ];
        let terminal = [
            (RunState::Succeeded, TerminalRunState::Succeeded),
            (RunState::Failed, TerminalRunState::Failed),
            (RunState::Cancelled, TerminalRunState::Cancelled),
            (RunState::Interrupted, TerminalRunState::Interrupted),
            (RunState::Rejected, TerminalRunState::Rejected),
        ];

        for (terminal_state, expected) in terminal {
            let responses = nonterminal
                .into_iter()
                .chain([terminal_state])
                .map(|state| Ok(run(state)));
            let api = ScriptedObservationApi::new(responses);
            let started_at = useful_support::monotonic_now();
            let clock = ControlledWaitClock::new(started_at);

            let result = observe(&api, None, &clock).expect("the polling scenario should complete");

            match result {
                WaitObservation::Terminal { resource, state } => {
                    assert_eq!(resource.state, terminal_state);
                    assert_eq!(state, expected);
                }
                WaitObservation::TimedOut | WaitObservation::Stopped => {
                    panic!("the polling scenario did not observe its terminal run")
                }
            }
            assert_eq!(
                clock.into_sleeps(),
                vec![crate::cli::OBSERVATION_POLL_INTERVAL; nonterminal.len()]
            );
        }
    }

    #[test]
    fn wait_treats_admitted_creation_as_nonterminal() {
        let api = ScriptedObservationApi {
            responses: RefCell::new(VecDeque::from([
                Ok(RunRead::Pending(useful_api::RunCreationPending::new(
                    "run_01k0z6r1w8f4jy2m7q9v3x5abc".to_owned(),
                ))),
                Ok(RunRead::Materialized(Box::new(run(RunState::Succeeded)))),
            ])),
        };
        let clock = ControlledWaitClock::new(useful_support::monotonic_now());

        assert_succeeded_after_single_poll(
            observe(&api, None, &clock),
            clock,
            "pending creation should remain observable",
        );
    }

    #[test]
    fn wait_recovers_from_one_retryable_observation_failure() {
        let api = ScriptedObservationApi::new([
            Err(RunFailure::Unreachable(UnreachableCategory::Server)),
            Ok(run(RunState::Succeeded)),
        ]);
        let started_at = useful_support::monotonic_now();
        let clock = ControlledWaitClock::new(started_at);

        assert_succeeded_after_single_poll(
            observe(&api, None, &clock),
            clock,
            "one recoverable failure should not end observation",
        );
    }

    #[test]
    fn wait_timeout_uses_the_remaining_duration_without_an_extra_request() {
        let api = ScriptedObservationApi::new([
            Ok(run(RunState::Queued)),
            Ok(run(RunState::Assigned)),
            Ok(run(RunState::Running)),
        ]);
        let started_at = useful_support::monotonic_now();
        let clock = ControlledWaitClock::new(started_at);

        let result = observe(&api, Some(Duration::from_secs(5)), &clock)
            .expect("timeout is a local wait outcome");

        assert!(matches!(result, WaitObservation::TimedOut));
        clock.assert_timeout_schedule();
        assert!(api.responses.into_inner().is_empty());
    }

    #[test]
    fn wait_bounds_retries_and_preserves_the_transport_failure() {
        let failure = RunFailure::Unreachable(UnreachableCategory::Connection);
        let api = ScriptedObservationApi::new([Err(failure.clone()), Err(failure.clone())]);
        let started_at = useful_support::monotonic_now();
        let clock = ControlledWaitClock::new(started_at);

        let result = observe(&api, None, &clock);

        assert_eq!(result.err(), Some(failure));
        clock.assert_single_poll();
    }

    #[test]
    fn wait_timeout_parser_accepts_documented_units_and_rejects_zero() {
        assert_eq!(
            crate::cli::parse_wait_timeout("250ms"),
            Ok(Duration::from_millis(250))
        );
        assert_eq!(
            crate::cli::parse_wait_timeout("30"),
            Ok(Duration::from_secs(30))
        );
        assert_eq!(
            crate::cli::parse_wait_timeout("10m"),
            Ok(Duration::from_secs(600))
        );
        assert_eq!(
            crate::cli::parse_wait_timeout("2h"),
            Ok(Duration::from_secs(7_200))
        );
        assert!(crate::cli::parse_wait_timeout("0s").is_err());
        assert!(crate::cli::parse_wait_timeout("1.5s").is_err());
    }
}
