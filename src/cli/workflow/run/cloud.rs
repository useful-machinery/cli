//! `answer`, `approve`, `hand-back`, `pause`, `unpause`, `resume`, `retry`, `cancel` and
//! `release` of a Cloud run the lookup found (REQ-LOCALRUN-180, REQ-LOCALRUN-187,
//! REQ-LOCALRUN-210, REQ-LOCALRUN-218): a control carried to its runner (REQ-RUN-91,
//! REQ-RUN-110), a continuation or a retry requested (REQ-CONTINUE-55, REQ-CONTINUE-85,
//! REQ-RETRY-30), a cancellation requested (REQ-CANCEL-38), or the run's subject claim released
//! by an owner (REQ-CLOUDDEF-97), through the public API under the CLI's session handling. A
//! verb refused for the run's state names it and the verbs that apply (REQ-LOCALRUN-223).
//! Nothing under the `useful` home is read or written. `useful workflow run show` reads a Cloud
//! run in `show`.
use std::io::{self, Write};
use std::time::Duration;

use anyhow::{Context, anyhow};
use serde::Serialize;
use useful_api::{
    HttpClient, Run, RunApi, RunClaimRelease, RunControl, RunControlAnswer, RunControlKind,
    RunControlRequest, RunControlSubmission, RunControlWait, RunFailure, RunRead, RunState,
    RunSubjectClaim,
};
use useful_execution::{ContinuingControl, WaitKind};
use useful_human_auth::Deployment;

use super::super::super::{
    self as cli, CommandFailure, CommonArgs, HttpOptions, PrincipalAuthenticationArgs,
    TerminalObservation,
};
use super::super::RunAddressError;
use super::cloud_api::observation::{self, ObservationContext};
use super::cloud_api::{
    Cancellation, CloudSnapshot, ContinuationSubmission, Missed, RetryRequest, RunOptions,
    RunWaitArgs, reported_text as text,
};
use super::control::{Placed, Refusal, Standing};
use super::target::{InCloud, Unread};
use crate::exit_code::ExitCode;

const RELEASE_COMMAND: &str = "useful workflow run release";
const CANCEL_COMMAND: &str = "useful workflow run cancel";
const RETRY_COMMAND: &str = "useful workflow run retry";
/// What a followed withdrawal reports when it ends before the run is final (REQ-RUN-62).
const TIMED_OUT: &str = "The run was not final before the timeout; it continues in Cloud.";
const STOPPED: &str = "Observation stopped; the run continues in Cloud.";
const UNREACHABLE: &str = "Cloud could not be reached twice in a row; observation stopped and the run continues in Cloud.";

/// The control a leaf asks Cloud to carry to the run's runner (REQ-LOCALRUN-210), with the
/// arguments its local form takes: `pause` sends the control kind `stop`, `unpause` the kind
/// `lift`, and `cancel` of a waiting run the kind `withdraw` (REQ-LOCALRUN-218).
pub(super) enum Control {
    Answer { question: String, text: String },
    Approve,
    HandBack { notes: String },
    Lift { before: Option<String> },
    Stop { before: String, reason: String },
    Retry,
    Withdraw,
}

/// The lookup's miss the failure of a request to the run `found` names stands for, written as
/// `command`'s refusal (REQ-LOCALRUN-180): Cloud has no such run, or nobody is signed in.
fn missed(found: InCloud, command: &'static str, json: bool) -> Missed {
    Box::new(move |failure, options| {
        Ok(found
            .missed_by(failure, &options.authentication, &options.http)?
            .map(|miss| -> Box<dyn FnOnce() -> cli::CommandResult> {
                Box::new(move || {
                    super::control::write_refusal(command, None, &Refusal::from(miss), json)
                })
            }))
    })
}

/// The hook of a request that is not the lookup's first: its failure is its own.
fn unmissed() -> Missed {
    Box::new(|_, _| Ok(None))
}

/// The step `run`'s latest progress report stood at: the first step identifier of its
/// position, if any.
fn positioned_step(run: &Run) -> Option<String> {
    let progress = run.workflow_progress.as_ref()?.as_deref()?;
    progress
        .position
        .iter()
        .find_map(|element| match serde_json::to_value(element) {
            Ok(serde_json::Value::String(step)) => Some(step),
            _ => None,
        })
}

/// The state of the Cloud run `read` reads (REQ-LOCALRUN-223): a final `state` is ended, a
/// wait its latest progress report carries is waiting on that kind, and anything else, a run
/// Cloud has not materialized among it, is running.
fn standing(read: &RunRead) -> Standing {
    let RunRead::Materialized(run) = read else {
        return Standing::Running;
    };
    match run.state {
        RunState::Succeeded => Standing::Ended { succeeded: true },
        RunState::Failed | RunState::Cancelled | RunState::Interrupted | RunState::Rejected => {
            Standing::Ended { succeeded: false }
        }
        _ => progress_wait(run).map_or(Standing::Running, |current| {
            Standing::Waiting(wait_kind(&current.wait))
        }),
    }
}

/// The kind of a wait a progress report names.
fn wait_kind(wait: &RunControlWait) -> WaitKind {
    match wire(wait.kind).as_str() {
        "approval" => WaitKind::Approval,
        "repair" => WaitKind::Repair,
        "host" => WaitKind::Host,
        "stop" => WaitKind::Stop,
        "external" => WaitKind::External,
        "children" => WaitKind::Children,
        _ => WaitKind::Answer,
    }
}

/// Why a control leaf sent nothing: the run does not wait on the wait its control resolves,
/// in the state it is in (REQ-LOCALRUN-223).
enum Unsent {
    NotWaiting(Standing),
    KindMismatch(Standing),
}

impl Control {
    fn leaf(&self) -> &'static str {
        match self {
            Self::Answer { .. } => "answer",
            Self::Approve => "approve",
            Self::HandBack { .. } => "hand-back",
            Self::Lift { .. } => "unpause",
            Self::Stop { .. } => "pause",
            Self::Retry => "retry",
            Self::Withdraw => "cancel",
        }
    }

    fn command(&self) -> &'static str {
        match self {
            Self::Answer { .. } => ContinuingControl::Answer.command(),
            Self::Approve => ContinuingControl::Approve.command(),
            Self::HandBack { .. } => ContinuingControl::HandBack.command(),
            Self::Lift { .. } => "useful workflow run unpause",
            Self::Stop { .. } => "useful workflow run pause",
            Self::Retry => RETRY_COMMAND,
            Self::Withdraw => CANCEL_COMMAND,
        }
    }

    /// The kinds of wait the control resolves, one of which the run must currently wait on
    /// (a `retry` resolves a `repair` or a `host` wait, REQ-LOCALRUN-210); a `lift` names the
    /// run's `stop` wait when it waits on one, and a `stop` and a `withdraw` name none.
    fn resolves(&self) -> Option<&'static [&'static str]> {
        match self {
            Self::Answer { .. } => Some(&["answer"]),
            Self::Approve | Self::HandBack { .. } => Some(&["approval"]),
            Self::Retry => Some(&["repair", "host"]),
            Self::Lift { .. } | Self::Stop { .. } | Self::Withdraw => None,
        }
    }

    /// The request naming `wait`, or the reason none is sent to the run in `standing`.
    fn request(
        &self,
        wait: Option<RunControlWait>,
        standing: Standing,
    ) -> Result<RunControlRequest, Unsent> {
        let wait = match self.resolves() {
            Some(kinds) => match wait {
                None => return Err(Unsent::NotWaiting(standing)),
                Some(wait) if !kinds.contains(&wire(wait.kind).as_str()) => {
                    return Err(Unsent::KindMismatch(standing));
                }
                wait => wait,
            },
            None if matches!(self, Self::Lift { .. }) => {
                wait.filter(|wait| wire(wait.kind) == "stop")
            }
            None => None,
        };
        let kind = match self {
            Self::Answer { .. } => RunControlKind::RunControlKindAnswer,
            Self::Approve => RunControlKind::RunControlKindApprove,
            Self::HandBack { .. } => RunControlKind::RunControlKindHandBack,
            Self::Lift { .. } => RunControlKind::RunControlKindLift,
            Self::Stop { .. } => RunControlKind::RunControlKindStop,
            Self::Retry => RunControlKind::RunControlKindRetry,
            Self::Withdraw => RunControlKind::RunControlKindWithdraw,
        };
        let mut request = RunControlRequest::new(kind);
        request.wait = wait.map(|wait| Some(Box::new(wait)));
        match self {
            Self::Answer { question, text } => {
                request.answers = Some(vec![RunControlAnswer::new(question.clone(), text.clone())]);
            }
            Self::HandBack { notes } => request.notes = Some(notes.clone()),
            Self::Lift { before } => request.before.clone_from(before),
            Self::Stop { before, reason } => {
                request.before = Some(before.clone());
                request.reason = Some(reason.clone());
            }
            Self::Approve | Self::Retry | Self::Withdraw => {}
        }
        Ok(request)
    }
}

/// A run's current wait as its latest progress report names it: the wait a control names, and
/// the ids of the questions it lists, `None` when it lists none.
pub(super) struct CurrentWait {
    wait: RunControlWait,
    questions: Option<Vec<String>>,
}

/// The run's current wait as its latest progress report names it, if it waits, and its state.
/// An ended run waits on nothing: the wait its last report may still carry, when no runner
/// reported the end of it, is not current.
fn current_wait(read: &RunRead) -> (Option<CurrentWait>, Standing) {
    let standing = standing(read);
    let wait = match read {
        RunRead::Materialized(run) if !matches!(standing, Standing::Ended { .. }) => {
            progress_wait(run)
        }
        RunRead::Materialized(_) | RunRead::Pending(_) => None,
    };
    (wait, standing)
}

/// The wait `run`'s latest progress report names, if any.
fn progress_wait(run: &Run) -> Option<CurrentWait> {
    let progress = run.workflow_progress.as_ref()?.as_deref()?;
    progress.wait.as_deref().map(|wait| CurrentWait {
        wait: RunControlWait::from(wait),
        questions: wait
            .questions
            .clone()
            .flatten()
            .map(|questions| questions.into_iter().map(|question| question.id).collect()),
    })
}

/// The question `answer` with no `--question` answers on a Cloud run (REQ-LOCALRUN-210): the
/// one question `wait` lists, or `1` when it lists none; several are `question_ambiguous`.
/// A run that does not wait on an answer is left to the request to refuse.
fn open_question(wait: Option<&CurrentWait>) -> Result<String, Refusal> {
    let listed = wait
        .filter(|current| wire(current.wait.kind) == "answer")
        .and_then(|current| current.questions.as_deref())
        .unwrap_or_default();
    match listed {
        [] => Ok("1".to_owned()),
        [question] => Ok(question.clone()),
        questions => Err(super::control::question_ambiguous(
            questions.iter().map(String::as_str),
        )),
    }
}

/// The Cloud run one leaf acts on and how it reports.
pub(super) struct CloudRun {
    organization: String,
    run_id: String,
    /// The lookup that found the run, whose first read of the run ends it
    /// (REQ-LOCALRUN-180); `None` once the leaf took it.
    found: Option<InCloud>,
    /// `--record-only`, which a Cloud run does not read: a usage error once the run is read.
    record_only: bool,
    authentication: PrincipalAuthenticationArgs,
    http: HttpOptions,
    json: bool,
}

impl CloudRun {
    /// The Cloud run the lookup found (REQ-LOCALRUN-180), through the leaf's authentication
    /// and transport; `record_only` is the leaf's `--record-only`, a usage error, exit 2, once
    /// the run is read.
    pub(super) fn found(
        found: InCloud,
        authentication: PrincipalAuthenticationArgs,
        http: HttpOptions,
        json: bool,
        record_only: bool,
    ) -> Self {
        Self {
            organization: found.organization.clone(),
            run_id: found.run_id.clone(),
            found: Some(found),
            record_only,
            authentication,
            http,
            json,
        }
    }

    /// Asks Cloud to release the current claim of the run the lookup found under one fresh
    /// key (REQ-LOCALRUN-187). The request is the run's first, unread; its `404` keeps
    /// release's own `not_found`, since Cloud answers a run that holds no claim the same way.
    pub(super) fn release(mut self) -> cli::CommandResult {
        let key = useful_support::generate_idempotency_key()
            .context("generate Cloud claim release request identity")?;
        let Some(found) = self.found.take() else {
            return Err(anyhow!("the Cloud run to release was not looked up").into());
        };
        let released = self.with_api(&found.deployment, |api| {
            api.release_claim(&self.organization, &self.run_id, &key)
        })?;
        match released {
            Ok(RunClaimRelease::Released(claim)) => self.write_released(&claim),
            Ok(RunClaimRelease::Live) => self.write_refusal(
                RELEASE_COMMAND,
                "claim_live",
                "The run is live and still holds its claim; nothing was released.",
                ExitCode::GeneralFailure,
            ),
            Ok(RunClaimRelease::Changed) => self.write_refusal(
                RELEASE_COMMAND,
                "claim_changed",
                "The run's current claim changed; nothing was released.",
                ExitCode::GeneralFailure,
            ),
            Ok(RunClaimRelease::IdempotencyConflict) => self.write_refusal(
                RELEASE_COMMAND,
                "idempotency_conflict",
                "Cloud answered this request's key for another request; nothing was released.",
                ExitCode::GeneralFailure,
            ),
            Err(failure) => self.write_failure(RELEASE_COMMAND, &failure),
        }
    }

    /// Reads the run for its current wait, unless the control is a `stop`, which names none,
    /// and asks Cloud to carry the control naming that wait to the run's runner under one
    /// fresh key.
    pub(super) fn control(self, control: Control) -> cli::CommandResult {
        let (leaf, command) = (control.leaf(), control.command());
        let reads = !matches!(control, Control::Stop { .. });
        self.send(leaf, command, reads, |_| Ok(control))
    }

    /// Ends the Cloud run the lookup found (REQ-LOCALRUN-218, REQ-CANCEL-38): with `force`
    /// the force cancellation request, sent unread, whose 404 is the lookup's miss; otherwise
    /// the run is read, and one whose progress carries a wait is sent a withdrawal, carried to
    /// its runner, and any other the graceful cancellation request, which also follows a
    /// withdrawal Cloud refuses `run_not_live` or `control_unsupported`. Whichever is sent goes
    /// under `--idempotency-key` or one fresh key.
    pub(super) fn cancel(mut self, cancel: Cancel) -> cli::CommandResult {
        let key = match cancel.idempotency_key.clone() {
            Some(key) => key,
            None => useful_support::generate_idempotency_key()
                .context("generate Cloud run cancellation request identity")?,
        };
        let Some(found) = self.found.take() else {
            return Err(anyhow!("the Cloud run to cancel was not looked up").into());
        };
        if cancel.force {
            return self.cancellation(found, cancel, key);
        }
        let read = |api: &RunApi<'_>| api.get(&self.organization, &self.run_id);
        let wait = match found.first_read(&self.authentication, &self.http, read)? {
            Ok(run) => current_wait(&run).0,
            Err(Unread::Missed(miss)) => return self.write_missed(CANCEL_COMMAND, miss),
            Err(Unread::Failed(failure)) => return self.write_failure(CANCEL_COMMAND, &failure),
        };
        if wait.is_none() {
            return self.cancellation(found, cancel, key);
        }
        let Ok(request) = Control::Withdraw.request(None, Standing::Running) else {
            return Err(anyhow!("a withdrawal names no wait").into());
        };
        let sent = self.with_api(&found.deployment, |api| {
            api.request_control(&self.organization, &self.run_id, &key, &request)
        })?;
        match sent {
            Ok(RunControlSubmission::Accepted(accepted)) if cancel.wait.wait => {
                self.follow(found, *accepted, cancel.wait.timeout)
            }
            Ok(RunControlSubmission::RunNotLive | RunControlSubmission::ControlUnsupported) => {
                self.cancellation(found, cancel, key)
            }
            sent => self.write_submission(CANCEL_COMMAND, sent),
        }
    }

    /// Sends the cancellation request of `cancel` under `key` and reports it in the document
    /// of the `cancel` operation; a forced one is the run's first request, so its 404, or
    /// nobody signed in to send it, is the lookup's miss.
    fn cancellation(self, found: InCloud, cancel: Cancel, key: String) -> cli::CommandResult {
        let (force, json) = (cancel.force, self.json);
        let deployment = found.deployment.clone();
        Cancellation {
            organization: self.organization,
            run_id: self.run_id,
            force,
            key,
            wait: cancel.wait,
            options: CommonArgs::new(json, self.authentication, self.http),
        }
        .execute(
            deployment,
            if force {
                missed(found, CANCEL_COMMAND, json)
            } else {
                unmissed()
            },
        )
    }

    /// The continuation of the Cloud run the lookup found from `steps`, none for `resume`
    /// (REQ-CONTINUE-55, REQ-CONTINUE-85): the request `useful workflow run retry --from`
    /// sends, unread, so its 404, or nobody signed in to send it, is the lookup's miss,
    /// reported as `command`.
    pub(super) fn continue_from(
        mut self,
        command: &'static str,
        steps: Vec<String>,
        expected_version: Option<i64>,
        wait: RunWaitArgs,
    ) -> cli::CommandResult {
        let Some(found) = self.found.take() else {
            return Err(anyhow!("the Cloud run to continue was not looked up").into());
        };
        let deployment = found.deployment.clone();
        let missed = missed(found, command, self.json);
        self.continuation(steps, expected_version, wait)
            .submit(deployment, missed)
    }

    /// The retry of every step of the Cloud run the lookup found (REQ-RETRY-30,
    /// REQ-RETRY-44), sent unread and followed within `timeout`: its 404, or nobody signed in
    /// to send it, is the lookup's miss.
    pub(super) fn rerun(
        mut self,
        expected_version: Option<i64>,
        timeout: Option<Duration>,
    ) -> cli::CommandResult {
        let Some(found) = self.found.take() else {
            return Err(anyhow!("the Cloud run to retry was not looked up").into());
        };
        let deployment = found.deployment.clone();
        let missed = missed(found, RETRY_COMMAND, self.json);
        RetryRequest::new(
            (self.organization, self.run_id),
            expected_version,
            timeout,
            CommonArgs::new(self.json, self.authentication, self.http),
        )
        .execute(deployment, missed)
    }

    /// `useful workflow run retry` with neither `--from` nor `--all` of the Cloud run the
    /// lookup found (REQ-LOCALRUN-210, REQ-CONTINUE-55): reads the run; one that waits is
    /// sent the carried `retry` for its wait, refused `wait_kind_mismatch` unless the wait is
    /// for repair; one that ended other than `succeeded` is continued from the first step its
    /// progress's position names, as `retry --from` continues it, and refused
    /// `continuation_step_required` when it names none; a succeeded run is refused
    /// `latest_attempt_succeeded` and any other `run_not_waiting`, nothing sent, each naming
    /// the run's state and the verbs that apply (REQ-LOCALRUN-223).
    pub(super) fn retry(
        mut self,
        expected_version: Option<i64>,
        wait: RunWaitArgs,
    ) -> cli::CommandResult {
        let key = useful_support::generate_idempotency_key()
            .context("generate Cloud run control request identity")?;
        let Some(found) = self.found.take() else {
            return Err(anyhow!("the Cloud run to retry was not looked up").into());
        };
        let read = |api: &RunApi<'_>| api.get(&self.organization, &self.run_id);
        let read = match found.first_read(&self.authentication, &self.http, read)? {
            Ok(read) => read,
            Err(Unread::Missed(miss)) => return self.write_missed(RETRY_COMMAND, miss),
            Err(Unread::Failed(failure)) => return self.write_failure(RETRY_COMMAND, &failure),
        };
        let (current, standing) = current_wait(&read);
        let RunRead::Materialized(run) = read else {
            return self.refuse_retry("run_not_waiting", standing);
        };
        if let Some(current) = current {
            return self.post(
                &found.deployment,
                None,
                RETRY_COMMAND,
                &Control::Retry,
                (Some(current.wait), standing),
                &key,
            );
        }
        match run.state {
            RunState::Failed | RunState::Cancelled | RunState::Interrupted | RunState::Rejected => {
                match positioned_step(&run) {
                    Some(step) => self
                        .continuation(vec![step], expected_version, wait)
                        .submit(found.deployment, unmissed()),
                    None => self.write_refusal(
                        RETRY_COMMAND,
                        "continuation_step_required",
                        "The run reports no step it stood at; name the steps to rerun with --from STEP, or rerun every step with --all.",
                        ExitCode::GeneralFailure,
                    ),
                }
            }
            RunState::Succeeded => self.refuse_retry("latest_attempt_succeeded", standing),
            _ => self.refuse_retry("run_not_waiting", standing),
        }
    }

    /// The continuation request of this run from `steps`.
    fn continuation(
        self,
        steps: Vec<String>,
        expected_version: Option<i64>,
        wait: RunWaitArgs,
    ) -> ContinuationSubmission {
        ContinuationSubmission::new(
            (self.organization, self.run_id),
            steps,
            expected_version,
            wait,
            CommonArgs::new(self.json, self.authentication, self.http),
        )
    }

    /// `retry` refused `code` for the run's state, naming it and the verbs that apply
    /// (REQ-LOCALRUN-223); nothing was sent.
    fn refuse_retry(&self, code: &'static str, standing: Standing) -> cli::CommandResult {
        self.write_refusal(
            RETRY_COMMAND,
            code,
            &standing.message(Placed::Cloud),
            ExitCode::GeneralFailure,
        )
    }

    /// Reads the run until it is final once Cloud accepted the withdrawal `accepted`, as
    /// `useful workflow run show --wait` reads it (REQ-RUN-61), and prints the `accepted`
    /// document with the run last read; a timeout, a signal and Cloud unreachable twice in a
    /// row end the observation with REQ-RUN-62's codes and exit statuses.
    fn follow(
        self,
        found: InCloud,
        accepted: RunControl,
        timeout: Option<Duration>,
    ) -> cli::CommandResult {
        let report = Followed {
            organization: self.organization,
            run_id: self.run_id,
            json: self.json,
            control: accepted,
        };
        let options: RunOptions = CommonArgs::new(self.json, self.authentication, self.http);
        let (signal_report, timeout_report) = (report.clone(), report.clone());
        cli::execute_mutation_with_signals_and_deferred_timeout(
            "Cloud run cancel",
            CloudSnapshot::for_run(found.run_id.clone()),
            timeout,
            move |control, timeout_start| {
                timeout_start.start();
                let started = useful_support::monotonic_now();
                let snapshot = control.recovery();
                let result = observation::wait_run(
                    ObservationContext {
                        deployment: &found.deployment,
                        options: &options,
                        organization: &found.organization,
                        snapshot: &snapshot,
                        timeout,
                        started,
                    },
                    control,
                    &cli::SystemObservationClock,
                    |latest| {
                        control.update_recovery(latest);
                    },
                );
                let last = control.recovery().run;
                let (ending, exit) = match result {
                    Ok(TerminalObservation::Terminal { resource, .. }) => {
                        let run = resource.run;
                        return super::cloud_api::finish_operation(control, || {
                            report.write(run.as_deref(), None, ExitCode::Success)
                        });
                    }
                    Ok(TerminalObservation::TimedOut) => (
                        Ending::of("timed_out", "wait_timed_out", TIMED_OUT),
                        ExitCode::GeneralFailure,
                    ),
                    Ok(TerminalObservation::Stopped) => return Ok(ExitCode::GeneralFailure),
                    Err(RunFailure::Unreachable(_)) => (
                        Ending::of("refused", "observation_failed", UNREACHABLE),
                        ExitCode::Unavailable,
                    ),
                    Err(failure) => {
                        let (code, message, exit) = failure_diagnostic(CANCEL_COMMAND, &failure);
                        (Ending::of("refused", code, message), exit)
                    }
                };
                super::cloud_api::finish_operation(control, || {
                    report.write(last.as_deref(), Some(&ending), exit)
                })
            },
            move |signal, snapshot| {
                signal_report
                    .write(
                        snapshot.recovery.run.as_deref(),
                        Some(&Ending::of(
                            "observation_stopped",
                            "observation_stopped",
                            STOPPED,
                        )),
                        signal,
                    )
                    .map_err(Into::into)
            },
            move |snapshot| {
                timeout_report
                    .write(
                        snapshot.recovery.run.as_deref(),
                        Some(&Ending::of("timed_out", "wait_timed_out", TIMED_OUT)),
                        ExitCode::GeneralFailure,
                    )
                    .map_err(Into::into)
            },
        )
    }

    /// Reads the run and answers its wait with `text`: the question `--question` names, or
    /// with none the one its wait lists (`open_question`), refused `question_ambiguous` with
    /// nothing sent when it lists several (REQ-LOCALRUN-210).
    pub(super) fn answer(self, question: Option<String>, text: String) -> cli::CommandResult {
        self.send(
            "answer",
            ContinuingControl::Answer.command(),
            true,
            |wait| {
                let question = match question {
                    Some(question) => question,
                    None => open_question(wait)?,
                };
                Ok(Control::Answer { question, text })
            },
        )
    }

    /// Reads the run when `reads`, chooses the control from its current wait, and asks Cloud
    /// to carry it to the run's runner under one fresh key, reported as leaf `leaf`'s
    /// `command`. A found run's first request, its read or the control a leaf that reads
    /// nothing sends, ends the lookup: a 404 is the lookup's miss.
    fn send(
        mut self,
        leaf: &'static str,
        command: &'static str,
        reads: bool,
        choose: impl FnOnce(Option<&CurrentWait>) -> Result<Control, Refusal>,
    ) -> cli::CommandResult {
        let key = useful_support::generate_idempotency_key()
            .context("generate Cloud run control request identity")?;
        let Some(found) = self.found.take() else {
            return Err(anyhow!("the Cloud run to {leaf} was not looked up").into());
        };
        let read = |api: &RunApi<'_>| api.get(&self.organization, &self.run_id);
        let (wait, standing) = if reads {
            match found.first_read(&self.authentication, &self.http, read)? {
                Ok(run) => current_wait(&run),
                Err(Unread::Missed(miss)) => return self.write_missed(command, miss),
                Err(Unread::Failed(failure)) => return self.write_failure(command, &failure),
            }
        } else {
            (None, Standing::Running)
        };
        if self.record_only {
            return Err(CommandFailure::with_exit_code(
                anyhow!(
                    "--record-only records a control on a run under the useful home, and RUN names a Cloud run\n\n\
                     Leave out --record-only: the runner executing the Cloud run applies the control."
                ),
                ExitCode::UsageError,
            ));
        }
        let control = match choose(wait.as_ref()) {
            Ok(control) => control,
            Err(refusal) => {
                return self.write_refusal(
                    command,
                    refusal.code,
                    &refusal.message,
                    ExitCode::GeneralFailure,
                );
            }
        };
        let wait = wait.map(|current| current.wait);
        self.post(
            &found.deployment,
            (!reads).then_some(&found),
            command,
            &control,
            (wait, standing),
            &key,
        )
    }

    /// Asks Cloud to carry `control` naming the run's current wait to its runner under `key`,
    /// reported as `command`; `first` is the lookup whose first request this is, whose 404, or
    /// nobody signed in to send it, is the lookup's miss (REQ-LOCALRUN-180). `current` is the
    /// run's wait and its state as the run read found them: a control the state does not
    /// admit is refused naming it and the verbs that apply (REQ-LOCALRUN-223).
    fn post(
        &self,
        deployment: &Deployment,
        first: Option<&InCloud>,
        command: &'static str,
        control: &Control,
        current: (Option<RunControlWait>, Standing),
        key: &str,
    ) -> cli::CommandResult {
        let (wait, standing) = current;
        let request = match control.request(wait, standing) {
            Ok(request) => request,
            Err(Unsent::NotWaiting(standing)) => {
                return self.write_refusal(
                    command,
                    "run_not_waiting",
                    &standing.message(Placed::Cloud),
                    ExitCode::GeneralFailure,
                );
            }
            Err(Unsent::KindMismatch(standing)) => {
                return self.write_refusal(
                    command,
                    "wait_kind_mismatch",
                    &standing.message(Placed::Cloud),
                    ExitCode::GeneralFailure,
                );
            }
        };
        let post =
            |api: &RunApi<'_>| api.request_control(&self.organization, &self.run_id, key, &request);
        let sent = match first {
            // The control is a found run's first request, which ends the lookup
            // (REQ-LOCALRUN-180): a 404, or nobody signed in to send it, is the lookup's miss.
            Some(found) => match found.first_read(&self.authentication, &self.http, post)? {
                Ok(submission) => Ok(submission),
                Err(Unread::Missed(miss)) => return self.write_missed(command, miss),
                Err(Unread::Failed(failure)) => Err(failure),
            },
            None => self.with_api(deployment, post)?,
        };
        self.write_submission(command, sent)
    }

    /// Reports what Cloud answered a control `command` asked it to carry.
    fn write_submission(
        &self,
        command: &'static str,
        sent: Result<RunControlSubmission, RunFailure>,
    ) -> cli::CommandResult {
        match sent {
            Ok(RunControlSubmission::Accepted(accepted)) => self.write_accepted(command, &accepted),
            Ok(RunControlSubmission::WaitNotCurrent) => self.write_refusal(
                command,
                "wait_not_current",
                "The run's wait changed before Cloud accepted the control; nothing was sent to the runner.",
                ExitCode::GeneralFailure,
            ),
            Ok(RunControlSubmission::RunNotLive) => self.write_refusal(
                command,
                "run_not_live",
                "No runner is executing the run's current attempt; nothing was sent.",
                ExitCode::GeneralFailure,
            ),
            Ok(RunControlSubmission::ControlUnsupported) => self.write_refusal(
                command,
                "control_unsupported",
                "The runner executing the run runs a useful that does not apply this control; nothing was sent.",
                ExitCode::GeneralFailure,
            ),
            Ok(RunControlSubmission::TooLarge) => self.write_refusal(
                command,
                "control_too_large",
                "The control is larger than a runner accepts; nothing was sent.",
                ExitCode::GeneralFailure,
            ),
            Ok(RunControlSubmission::IdempotencyConflict) => self.write_refusal(
                command,
                "idempotency_conflict",
                "Cloud answered this request's key for another request; nothing was sent.",
                ExitCode::GeneralFailure,
            ),
            Err(failure) => self.write_failure(command, &failure),
        }
    }

    /// The lookup's miss, as control `command` writes it (REQ-LOCALRUN-180).
    fn write_missed(&self, command: &'static str, miss: RunAddressError) -> cli::CommandResult {
        super::control::write_refusal(command, None, &Refusal::from(miss), self.json)
    }

    /// Runs `operation` against the deployment under the leaf's session, again with a
    /// refreshed session when the first is rejected.
    fn with_api<T>(
        &self,
        deployment: &Deployment,
        mut operation: impl FnMut(&RunApi<'_>) -> Result<T, RunFailure>,
    ) -> anyhow::Result<Result<T, RunFailure>> {
        let policy = self.http.transport_policy();
        let client = HttpClient::new(policy)
            .map_err(|error| anyhow!(error))
            .context("prepare Cloud run networking")?;
        cli::execute_selected_api_operation(
            cli::principal_api_context(
                &client,
                deployment,
                &self.authentication,
                "acquire human session for Cloud run operation",
            ),
            |token| {
                let api = RunApi::new(deployment.fingerprint().api_url(), token, policy, &client)
                    .map_err(|error| anyhow!(error))
                    .context("prepare Cloud run networking")?;
                Ok(operation(&api))
            },
            RunFailure::credential_rejected,
            || RunFailure::Unauthenticated,
            RunFailure::Unreachable,
        )
    }

    fn write_released(&self, claim: &RunSubjectClaim) -> cli::CommandResult {
        let written = if self.json {
            cli::write_pretty_json(&ReleasedDocument {
                schema_version: 1,
                command: RELEASE_COMMAND,
                outcome: "released",
                exit_status: ExitCode::Success.as_u8(),
                organization_ref: &self.organization,
                run_id: &self.run_id,
                claim,
            })
        } else {
            let mut stdout = io::stdout().lock();
            writeln!(
                stdout,
                "✓ Released claim {} of run {} for {} (cause {}).",
                text(&claim.claim_id),
                text(&self.run_id),
                text(&claim.subject),
                claim
                    .release_cause
                    .as_deref()
                    .map_or_else(|| "-".to_owned(), text)
            )
            .and_then(|()| stdout.flush())
        };
        written.with_context(|| format!("write {RELEASE_COMMAND} output"))?;
        Ok(ExitCode::Success)
    }

    fn write_accepted(&self, command: &'static str, control: &RunControl) -> cli::CommandResult {
        Ok(write_accepted(
            Accepted {
                command,
                organization: &self.organization,
                run_id: &self.run_id,
                json: self.json,
                control,
            },
            None,
        )?)
    }

    /// Reports `failure` as a refusal under [`failure_diagnostic`].
    fn write_failure(&self, command: &'static str, failure: &RunFailure) -> cli::CommandResult {
        let (code, message, exit) = failure_diagnostic(command, failure);
        self.write_refusal(command, code, message, exit)
    }

    fn write_refusal(
        &self,
        command: &'static str,
        code: &'static str,
        message: &str,
        exit: ExitCode,
    ) -> cli::CommandResult {
        let written = if self.json {
            cli::write_pretty_json(&RefusedDocument {
                schema_version: 1,
                command,
                outcome: "refused",
                exit_status: exit.as_u8(),
                organization_ref: &self.organization,
                run_id: &self.run_id,
                diagnostics: [Diagnostic { code, message }],
            })
        } else {
            let mut stderr = io::stderr().lock();
            writeln!(stderr, "{command} refused: {code}: {message}").and_then(|()| stderr.flush())
        };
        written.with_context(|| format!("write {command} output"))?;
        Ok(exit)
    }
}

/// The diagnostic code, message and exit status leaf `command` reports `failure` under: the
/// code and exit status the Cloud forms of the `useful workflow run` commands in `cloud_api`
/// report it under (`failure_code`), but for an unnamed conflict, which is `conflict`, and a
/// rejected session, which exits 3 (INV-CLI-17, REQ-LOCALRUN-215). The message is the leaf's
/// own, chosen by the code. Only `release` reads the run's subject claim, so only its not-found
/// names it, and its `404` is its own; `show` and the control leaves write a 404 of their first
/// request as the lookup's miss (REQ-LOCALRUN-180).
pub(super) fn failure_diagnostic(
    command: &str,
    failure: &RunFailure,
) -> (&'static str, &'static str, ExitCode) {
    let (code, exit) = if *failure == RunFailure::Conflict {
        ("conflict", ExitCode::GeneralFailure)
    } else if failure.credential_rejected() {
        ("authentication_required", ExitCode::AuthenticationRequired)
    } else {
        super::cloud_api::failure_code(failure, cli::PrincipalAuthenticationKind::HumanSession)
    };
    let message = match code {
        "authentication_required" => {
            "Cloud rejected the session; sign in with useful account login and try again."
        }
        "forbidden" => "The principal may not do this to the run.",
        "not_found" if command == RELEASE_COMMAND => {
            "Cloud has no such run in this organization, or the run has no subject claim."
        }
        "not_found" => "Cloud has no such run in this organization.",
        "invalid_input" => "Cloud refused the request as invalid.",
        "conflict" => "Cloud refused the request because of the run's state.",
        "creation_rejected" => "Cloud refused to create the run.",
        "unavailable" => "Cloud could not be reached or is limiting requests; try again.",
        "protocol_error" => "Cloud answered with a response this CLI does not accept.",
        _ => "The request to Cloud did not complete.",
    };
    (code, message, exit)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReleasedDocument<'a> {
    schema_version: u8,
    command: &'static str,
    outcome: &'static str,
    exit_status: u8,
    organization_ref: &'a str,
    run_id: &'a str,
    claim: &'a RunSubjectClaim,
}

/// What `cancel` sends a Cloud run (REQ-LOCALRUN-218): `--force`, `--idempotency-key`, and
/// `--wait` with its `--timeout`.
pub(super) struct Cancel {
    pub(super) force: bool,
    pub(super) idempotency_key: Option<String>,
    pub(super) wait: RunWaitArgs,
}

/// A withdrawal Cloud accepted that `cancel --wait` follows, and how it reports.
#[derive(Clone)]
struct Followed {
    organization: String,
    run_id: String,
    json: bool,
    control: RunControl,
}

impl Followed {
    /// The `accepted` document with `run`, the run last read, and `ending`, how the
    /// observation ended before the run was final, exiting `exit`.
    fn write(
        &self,
        run: Option<&Run>,
        ending: Option<&Ending>,
        exit: ExitCode,
    ) -> anyhow::Result<ExitCode> {
        write_accepted(
            Accepted {
                command: CANCEL_COMMAND,
                organization: &self.organization,
                run_id: &self.run_id,
                json: self.json,
                control: &self.control,
            },
            Some((run, ending, exit)),
        )
    }
}

/// How a followed withdrawal's observation ended before the run was final: the document's
/// outcome and its one diagnostic (REQ-RUN-62).
struct Ending {
    outcome: &'static str,
    code: &'static str,
    message: &'static str,
}

impl Ending {
    const fn of(outcome: &'static str, code: &'static str, message: &'static str) -> Self {
        Self {
            outcome,
            code,
            message,
        }
    }
}

/// The control Cloud accepted and whom the `accepted` document names.
struct Accepted<'a> {
    command: &'static str,
    organization: &'a str,
    run_id: &'a str,
    json: bool,
    control: &'a RunControl,
}

/// Prints the `accepted` document of a carried control (REQ-LOCALRUN-210), or its line; for a
/// withdrawal `cancel --wait` followed (REQ-LOCALRUN-218), `followed` is the run last read
/// under `run`, how the observation ended, if it ended before the run was final, and the
/// exit status.
fn write_accepted(
    accepted: Accepted<'_>,
    followed: Option<(Option<&Run>, Option<&Ending>, ExitCode)>,
) -> anyhow::Result<ExitCode> {
    let Accepted {
        command,
        organization,
        run_id,
        json,
        control,
    } = accepted;
    let (run, ending, exit) = match followed {
        Some((run, ending, exit)) => (Some(run), ending, exit),
        None => (None, None, ExitCode::Success),
    };
    let written = if json {
        cli::write_pretty_json(&AcceptedDocument {
            schema_version: 1,
            command,
            outcome: ending.map_or("accepted", |ending| ending.outcome),
            exit_status: exit.as_u8(),
            organization_ref: organization,
            run_id,
            control,
            run,
            diagnostics: ending.map(|ending| {
                [Diagnostic {
                    code: ending.code,
                    message: ending.message,
                }]
            }),
        })
    } else {
        let mut stdout = io::stdout().lock();
        writeln!(
            stdout,
            "✓ Cloud accepted {} control {} for run {} attempt {} (state {}); the runner executing the attempt applies it.",
            wire(control.kind),
            text(&control.id),
            text(run_id),
            control.attempt_number,
            wire(control.state),
        )
        .and_then(|()| match run.flatten() {
            Some(run) => writeln!(stdout, "run state: {}", wire(run.state)),
            None => Ok(()),
        })
        .and_then(|()| stdout.flush())
        .and_then(|()| match ending {
            Some(ending) => {
                let mut stderr = io::stderr().lock();
                writeln!(stderr, "{command} {}: {}: {}", ending.outcome, ending.code, ending.message)
                    .and_then(|()| stderr.flush())
            }
            None => Ok(()),
        })
    };
    written.with_context(|| format!("write {command} output"))?;
    Ok(exit)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AcceptedDocument<'a> {
    schema_version: u8,
    command: &'static str,
    outcome: &'static str,
    exit_status: u8,
    organization_ref: &'a str,
    run_id: &'a str,
    control: &'a RunControl,
    /// The run last read, for a withdrawal `cancel --wait` followed; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    run: Option<Option<&'a Run>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostics: Option<[Diagnostic<'a>; 1]>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RefusedDocument<'a> {
    schema_version: u8,
    command: &'static str,
    outcome: &'static str,
    exit_status: u8,
    organization_ref: &'a str,
    run_id: &'a str,
    diagnostics: [Diagnostic<'a>; 1],
}

#[derive(Serialize)]
struct Diagnostic<'a> {
    code: &'static str,
    message: &'a str,
}

pub(super) fn wire(value: impl Serialize) -> String {
    useful_support::wire_name(value).unwrap_or_else(|| "-".to_owned())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use useful_api::{
        ContinuationAdmissionViolation, RetryConflict, RunFailure, UnreachableCategory,
    };

    use super::{RELEASE_COMMAND, failure_diagnostic};
    use crate::cli::PrincipalAuthenticationKind;
    use crate::cli::workflow::run::cloud_api::failure_code;
    use crate::exit_code::ExitCode;

    // REQ-COMPAT-42, REQ-LOCALRUN-187, REQ-LOCALRUN-210: a refusal Cloud answers `409`
    // under a type this release does not name is reported as a conflict, exit 1.
    #[test]
    fn an_unnamed_conflict_is_reported_as_a_conflict() {
        let (code, _, exit) = failure_diagnostic(RELEASE_COMMAND, &RunFailure::Conflict);
        assert_eq!((code, exit), ("conflict", ExitCode::GeneralFailure));
    }

    // INV-CLI-17, REQ-LOCALRUN-215: the leaves report every failure under the code and exit
    // status the shared mapping gives it, but for an unnamed conflict and a rejected session.
    #[test]
    fn every_failure_takes_its_code_from_the_shared_mapping() {
        let samples = [
            RunFailure::Unauthenticated,
            RunFailure::Forbidden,
            RunFailure::InvalidInput,
            RunFailure::NotFound,
            RunFailure::Conflict,
            RunFailure::InputAdmissionRejected {
                status: 422,
                problem_type: "https://api.usefulmachinery.com/problems/input-rejected",
                diagnostic: None,
            },
            RunFailure::AdmissionRejected {
                status: 422,
                problem_type: "https://api.usefulmachinery.com/problems/source-rejected",
                request_id: None,
                blockers: vec![],
            },
            RunFailure::IdempotencyConflict,
            RunFailure::CreationRejected,
            RunFailure::RetryConflict(RetryConflict::Pending),
            RunFailure::RetryConflict(RetryConflict::Idempotency),
            RunFailure::RetryConflict(RetryConflict::SubjectBusy {
                holder_run_id: "run_01k0z6r1w8f4jy2m7q9v3x5abc".to_owned(),
            }),
            RunFailure::RetryConflict(RetryConflict::SubjectSettled {
                holder_run_id: "run_01k0z6r1w8f4jy2m7q9v3x5abc".to_owned(),
            }),
            RunFailure::RetryAfter(Duration::from_secs(1)),
            RunFailure::RetryAmbiguousRateLimited,
            RunFailure::RetryAmbiguousAuthentication,
            RunFailure::ContinuationAcceptanceUnknown,
            RunFailure::ContinuationAdmissionInvalid(vec![ContinuationAdmissionViolation {
                code: "node_unknown",
            }]),
            RunFailure::PathRunRetired,
            RunFailure::Gone,
            RunFailure::Unreachable(UnreachableCategory::Timeout),
            RunFailure::Unreachable(UnreachableCategory::RateLimited),
            RunFailure::InputUploadRejected,
            RunFailure::InputDownloadRejected,
            RunFailure::Interrupted,
            RunFailure::Protocol {
                credential_rejected: false,
            },
            RunFailure::Protocol {
                credential_rejected: true,
            },
        ];
        for failure in samples {
            let shared = failure_code(&failure, PrincipalAuthenticationKind::HumanSession);
            let expected = if failure == RunFailure::Conflict {
                ("conflict", ExitCode::GeneralFailure)
            } else if failure
                == (RunFailure::Protocol {
                    credential_rejected: true,
                })
            {
                ("authentication_required", ExitCode::AuthenticationRequired)
            } else {
                shared
            };
            let (code, _, exit) = failure_diagnostic(RELEASE_COMMAND, &failure);
            assert_eq!((code, exit), expected, "{failure:?}");
        }
    }
}
