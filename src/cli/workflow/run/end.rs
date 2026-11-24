//! `useful workflow run cancel` and `release`: each acts on the run `RUN` names wherever it
//! executes, found under the `useful` home and then in Cloud. `cancel` ends it, a Cloud run
//! through the API, and `release` records the release of an ended run under the home or releases
//! a Cloud run's subject claim.

use std::path::Path;
use std::time::Duration;

use anyhow::anyhow;
use clap::{Args, ValueEnum};
use rustix::process::{Pid, Signal, kill_process};
use useful_execution::{
    CANCELED_OUTCOME, CONTROL_CANCEL, CONTROL_RELEASE, CONTROL_WITHDRAW, LocalContinuationOpen,
    Mirror, PendingLocalContinuation, RetryIneligibilityReason, RunState, WITHDRAWN_OUTCOME,
    WaitInspection, WaitRecord, acquire_local_continuation, await_run_lock_gate, inspect_wait,
    lock_holder, read_controls,
};

use super::cloud_api::{RunWaitArgs, parse_idempotency_key};
use super::control::{Acted, ControlFailure, ControlTarget, Refusal};
use super::target::{Found, RunArg};
use crate::cli::context::OrgArgs;
use crate::cli::{CommandFailure, HttpOptions, PrincipalAuthenticationArgs};
use crate::exit_code::ExitCode;

pub(super) const CANCEL_ABOUT: &str = "End a run, on this machine or in Cloud";
pub(super) const CANCEL_AFTER_HELP: &str = "RUN is a run directory, a run ID or a subject. An ID or a subject is looked up under the useful home and, when the home holds no such run, in Cloud in the organization in effect.

The command applies to a run that is running, waiting or abandoned. An ended run under the home is refused, and the refusal names the commands that apply; Cloud answers the cancellation of an ended Cloud run with its receipt.

For a run under the home the command ends a waiting run at its wait, as withdrawn. It ends a run a live process holds by signalling that process, and a run whose process is gone, as canceled.

For a Cloud run the command reads the run first. One that waits is sent a withdrawal, which Cloud carries to the runner executing it; any other is sent a graceful cancellation request, and so is one whose runner cannot apply a withdrawal. --force requests immediate containment instead, without reading the run. Each request goes under one key, sent again if the response is lost; --idempotency-key reuses a key to reconcile an uncertain request. Cloud's acceptance is not the run's end: --wait follows the run until it settles, within --timeout.";
pub(super) const RELEASE_ABOUT: &str = "Free an ended run's subject, on this machine or in Cloud";
pub(super) const RELEASE_AFTER_HELP: &str = "RUN is a run directory, a run ID or a subject. An ID or a subject is looked up under the useful home and, when the home holds no such run, in Cloud in the organization in effect.

The command applies to an ended run. A run under the home that has not ended is refused, and the refusal names the commands that apply; Cloud refuses the release of a live Cloud run.

For a run under the home the command records the release, which frees the run's subject for a new run.

For a Cloud run the command asks Cloud, as an organization owner, to release the run's subject claim under one request key, sent again if the response is lost.";
const CANCEL_COMMAND: &str = "useful workflow run cancel";
const RELEASE_COMMAND: &str = "useful workflow run release";

/// How long `cancel` and `interrupt` wait for the process they signalled to release the
/// run: `RELEASE_POLLS` probes `RELEASE_POLL` apart, 60 seconds at the production cadence.
/// A `test-fixtures` build lets an end-to-end test shorten the cadence, and the wait with
/// it (`useful_support::poll_interval`).
const RELEASE_POLL: Duration = Duration::from_millis(200);
const RELEASE_POLLS: u32 = 300;

/// The one transition `cancel --control` applies to a run under the home whatever its state:
/// the runner passes it for a Cloud cancellation and a carried withdrawal.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Transition {
    /// End the run canceled, as cancel_run does
    Cancel,
    /// Withdraw the run, as withdraw_run does
    Withdraw,
}

/// `useful workflow run cancel RUN`: the run, the hidden transition a runner selects, and the
/// options a Cloud run's cancellation reads.
#[derive(Debug, Args)]
pub(super) struct Cancel {
    #[command(flatten)]
    run: RunArg,

    #[arg(
        long,
        value_enum,
        hide = true,
        value_name = "TRANSITION",
        help = "Apply this one transition to a run under the useful home whatever its state; the runner passes it"
    )]
    control: Option<Transition>,

    #[arg(
        long,
        help = "Request immediate containment of a Cloud run instead of graceful stopping"
    )]
    force: bool,

    #[arg(long, value_name = "KEY", value_parser = parse_idempotency_key,
        help = "Reuse this key to reconcile an uncertain request to Cloud")]
    idempotency_key: Option<String>,

    #[command(flatten)]
    wait: RunWaitArgs,

    #[command(flatten)]
    output: super::control::JsonOutput,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    authentication: PrincipalAuthenticationArgs,

    #[command(flatten)]
    http: HttpOptions,
}

impl Cancel {
    /// Finds the run and ends it: a run under the home as `cancel` (or `--control`'s
    /// transition) ends it, and a Cloud run as `CloudRun::cancel` does. An option the place
    /// the run is found in does not read is a usage error, exit 2.
    pub(super) fn execute(self) -> super::super::super::CommandResult {
        let json = self.output.json;
        let found = match super::control::find(
            CANCEL_COMMAND,
            &self.run,
            &self.org,
            &self.authentication,
            &self.http,
            json,
        ) {
            Ok(found) => found,
            Err(result) => return result,
        };
        match found {
            Found::Home(run_directory) => {
                if let Some(option) = self.cloud_option() {
                    return Err(usage(&format!(
                        "{option} applies to a Cloud run, and RUN names a run under the useful home\n\n\
                         Leave out {option}: the command ends a run under the home itself."
                    )));
                }
                let act = match self.control {
                    None => cancel,
                    Some(Transition::Cancel) => cancel_run,
                    Some(Transition::Withdraw) => withdraw_run,
                };
                match super::control::act_on(CANCEL_COMMAND, &run_directory, json, act) {
                    Ok((target, acted)) => {
                        super::control::write_recorded(CANCEL_COMMAND, &target, &acted, json)
                    }
                    Err(result) => result,
                }
            }
            Found::Cloud(_) if self.control.is_some() => Err(usage(
                "--control applies to a run under the useful home, and RUN names a Cloud run\n\n\
                 Leave out --control: the runner executing the Cloud run applies its cancellation.",
            )),
            Found::Cloud(run) => {
                super::cloud::CloudRun::found(*run, self.authentication, self.http, json, false)
                    .cancel(super::cloud::Cancel {
                        force: self.force,
                        idempotency_key: self.idempotency_key,
                        wait: self.wait,
                    })
            }
        }
    }

    /// The first option given that only a Cloud run's cancellation reads.
    fn cloud_option(&self) -> Option<&'static str> {
        if self.force {
            Some("--force")
        } else if self.wait.wait {
            Some("--wait")
        } else if self.idempotency_key.is_some() {
            Some("--idempotency-key")
        } else {
            None
        }
    }
}

/// A usage error, exit 2, of an option the run `RUN` names does not read.
fn usage(message: &str) -> CommandFailure {
    CommandFailure::with_exit_code(anyhow!("{message}"), ExitCode::UsageError)
}

/// `useful workflow run release RUN`: the run, and the options a Cloud run's claim release
/// reads.
#[derive(Debug, Args)]
pub(super) struct Release {
    #[command(flatten)]
    run: RunArg,

    #[command(flatten)]
    output: super::control::JsonOutput,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    authentication: PrincipalAuthenticationArgs,

    #[command(flatten)]
    http: HttpOptions,
}

impl Release {
    /// Finds the run and releases it: a run under the home by recording `control.release`,
    /// and a Cloud run by asking Cloud to release its subject claim.
    pub(super) fn execute(self) -> super::super::super::CommandResult {
        let json = self.output.json;
        let found = match super::control::find(
            RELEASE_COMMAND,
            &self.run,
            &self.org,
            &self.authentication,
            &self.http,
            json,
        ) {
            Ok(found) => found,
            Err(result) => return result,
        };
        match found {
            Found::Home(run_directory) => {
                match super::control::act_on(RELEASE_COMMAND, &run_directory, json, release) {
                    Ok((target, acted)) => {
                        super::control::write_recorded(RELEASE_COMMAND, &target, &acted, json)
                    }
                    Err(result) => result,
                }
            }
            Found::Cloud(run) => {
                super::cloud::CloudRun::found(*run, self.authentication, self.http, json, false)
                    .release()
            }
        }
    }
}

/// Records the release of the ended run `target` opened, once: a run that has not ended is
/// `run_live`, naming its state and the verbs that apply.
fn release(target: &ControlTarget) -> Result<Acted, ControlFailure> {
    if !matches!(
        target.inspection,
        WaitInspection::NoWait {
            state: Some(RunState::Exited),
            ..
        }
    ) {
        return Err(target.refusal("run_live").into());
    }
    if read_controls(&target.run_directory)?
        .iter()
        .any(|control| control.event == CONTROL_RELEASE)
    {
        return Err(Refusal::new("run_released", "The run is already released.").into());
    }
    let control = target.record(CONTROL_RELEASE, None, None)?;
    Ok(Acted::recorded(control, None))
}

/// Ends the run `target` opened as `useful workflow run cancel` does with no
/// `--control`: a run a live process holds through `cancel_live`, a waiting run
/// `withdrawn` at its wait, and anything else as `end_unheld` ends it `canceled`.
fn cancel(target: &ControlTarget) -> Result<Acted, ControlFailure> {
    match &target.inspection {
        WaitInspection::Locked(_) => cancel_live(target),
        WaitInspection::Held { .. }
        | WaitInspection::Satisfied { .. }
        | WaitInspection::RuleInvalid { .. }
        | WaitInspection::ConditionUnavailable { .. } => {
            end_unheld(target, CONTROL_WITHDRAW, WITHDRAWN_OUTCOME)
        }
        WaitInspection::NoWait { .. } | WaitInspection::Continued { .. } => {
            end_unheld(target, CONTROL_CANCEL, CANCELED_OUTCOME)
        }
    }
}

/// Withdraws the run `target` opened, as `useful workflow run cancel --control withdraw` does;
/// `useful workflow run event` applies a control trigger's `withdraw` through it. A run a live
/// process holds goes to `withdraw_live`, and so does a `running` one found without a lock holder,
/// which may be a process between the attempts it chains; anything else is ended as `end_unheld`
/// does.
pub(super) fn withdraw_run(target: &ControlTarget) -> Result<Acted, ControlFailure> {
    match &target.inspection {
        WaitInspection::Locked(_)
        | WaitInspection::Continued { .. }
        | WaitInspection::NoWait {
            state: Some(RunState::Running),
            ..
        } => withdraw_live(target),
        _ => end_unheld(target, CONTROL_WITHDRAW, WITHDRAWN_OUTCOME),
    }
}

/// Cancels the run `target` opened, as `useful workflow run cancel --control cancel` does; `useful
/// workflow run event` applies a control trigger's `cancel` through it: a live one through
/// `cancel_live`, and otherwise as `end_unheld` does.
pub(super) fn cancel_run(target: &ControlTarget) -> Result<Acted, ControlFailure> {
    match &target.inspection {
        WaitInspection::Locked(_) => cancel_live(target),
        _ => end_unheld(target, CONTROL_CANCEL, CANCELED_OUTCOME),
    }
}

/// Ends the run with `event` and `outcome` as `target` found it: a waiting one at its wait,
/// and one whose process is gone as abandoned, each appending `event` only as it ends the
/// run; a run a process holds is `run_locked` and an exited run `run_exited`, with nothing
/// appended.
fn end_unheld(
    target: &ControlTarget,
    event: &str,
    outcome: &'static str,
) -> Result<Acted, ControlFailure> {
    match &target.inspection {
        WaitInspection::Locked(_) => Err(super::control::run_locked().into()),
        WaitInspection::Held { wait }
        | WaitInspection::Satisfied { wait, .. }
        | WaitInspection::RuleInvalid { wait, .. }
        | WaitInspection::ConditionUnavailable { wait, .. } => {
            end_waiting(target, wait, event, outcome)
        }
        WaitInspection::NoWait {
            state: Some(RunState::Exited),
            ..
        } => Err(target.refusal("run_exited").into()),
        WaitInspection::NoWait { .. } | WaitInspection::Continued { .. } => {
            end_abandoned(target, event, outcome)
        }
    }
}

/// The run's continuation lock, or `run_locked` when a process took the run since it was
/// inspected.
fn acquire(run_directory: &Path) -> Result<PendingLocalContinuation, ControlFailure> {
    // A test seam between the inspection and the run lock; nothing outside `test-fixtures`.
    await_run_lock_gate()?;
    match acquire_local_continuation(run_directory)? {
        LocalContinuationOpen::Acquired(pending) => Ok(*pending),
        LocalContinuationOpen::Rejected(rejection)
            if rejection.reason() == RetryIneligibilityReason::RunLocked =>
        {
            Err(super::control::run_locked().into())
        }
        LocalContinuationOpen::Rejected(rejection) => {
            Err(anyhow!("the run cannot be ended: {}", rejection.reason().as_str()).into())
        }
    }
}

/// Ends a waiting run with `outcome`: under the run lock, once the run still waits on
/// `wait` and the mirror's write has its credentials, appends `event` naming the wait and
/// marks the record `exited`.
fn end_waiting(
    target: &ControlTarget,
    wait: &WaitRecord,
    event: &str,
    outcome: &'static str,
) -> Result<Acted, ControlFailure> {
    let pending = acquire(&target.run_directory)?;
    if !matches!(pending.wait(), Ok(Some(current)) if current.id() == wait.id()) {
        return Err(Refusal::new(
            "wait_changed",
            "The run's wait changed while the command inspected it; run the command again.",
        )
        .into());
    }
    let mirror = mirror(target, &pending);
    outcome_credentials(mirror.as_ref(), outcome)?;
    let control = target.record(event, Some(wait.id()), None)?;
    pending.end_waiting(outcome)?;
    write_outcome(mirror.as_ref(), outcome);
    Ok(Acted {
        control,
        wait: None,
        outcome,
    })
}

/// Ends a run whose record reads `running` but whose process is gone with `outcome`: under the
/// run lock, once the mirror's write has its credentials, appends `event` naming no wait and
/// ends the run through `PendingLocalContinuation::end_running`, which marks the record `exited`
/// and settles the abandoned attempt or, for a run interrupted between chained attempts, spends
/// the withdrawals recorded for it, creating no attempt. It takes the controls lock itself, so
/// this command holds none here.
fn end_abandoned(
    target: &ControlTarget,
    event: &str,
    outcome: &'static str,
) -> Result<Acted, ControlFailure> {
    let pending = acquire(&target.run_directory)?;
    let mirror = mirror(target, &pending);
    outcome_credentials(mirror.as_ref(), outcome)?;
    let control = target.record(event, None, None)?;
    pending.end_running(outcome)?;
    write_outcome(mirror.as_ref(), outcome);
    Ok(Acted {
        control,
        wait: None,
        outcome,
    })
}

/// Refuses `mirror_credentials_unavailable` when the run's mirror would write `onOutcome` for
/// `outcome` without a key. The caller drops its continuation unsettled on the refusal, which
/// releases the lock and leaves the run's record, wait, controls and `mirror/` as the command
/// found them.
fn outcome_credentials(mirror: Option<&Mirror>, outcome: &str) -> Result<(), ControlFailure> {
    super::mirror::outcome_credentials(mirror, outcome)
        .map_err(|failure| Refusal::new(failure.code, super::mirror::CREDENTIALS_REFUSAL).into())
}

/// The run's mirror, read before the continuation that holds its root workflow is consumed.
fn mirror(target: &ControlTarget, pending: &PendingLocalContinuation) -> Option<Mirror> {
    let (workflow, inputs) = pending.root_specification();
    super::mirror::run_mirror(
        &target.record,
        &workflow.definition,
        inputs,
        &target.run_directory,
    )
}

/// The root's `onOutcome` for `outcome`, once the record reads `exited`; its result never
/// changes the command's.
fn write_outcome(mirror: Option<&Mirror>, outcome: &'static str) {
    if let Some(mirror) = mirror {
        super::mirror::perform(
            mirror,
            Box::new(move |mirror, target| mirror.outcome(target, outcome)),
        );
    }
}

/// Withdraws a run a live process holds: under the run's controls lock, which that process
/// takes for its last read of the withdrawals and keeps until it releases the run, and which
/// a process that chains attempts keeps from the release of one until it holds the run for
/// the next, the command opens the run again. When a lock holds the run, whether or not the
/// system reports its holder's process, it appends `control.withdraw` naming no wait, so the
/// holder honors it before its next `workflow` step starts or, when it reaches none, as its
/// attempt settles; `withdraw_pending` when one it has not honored is already recorded. A run
/// no lock holds has been released for the last time, or its process is gone, so the command
/// appends nothing there and ends the run as it finds it again (`end_unheld`).
fn withdraw_live(target: &ControlTarget) -> Result<Acted, ControlFailure> {
    // A test seam between the inspection and the controls lock; nothing outside
    // `test-fixtures`.
    await_run_lock_gate()?;
    let probe = inspect_wait(&target.run_directory, &useful_execution::NoConditions)?;
    let controls = probe.lock_controls()?;
    let current = super::control::open(&target.run_directory)?;
    if !matches!(current.inspection, WaitInspection::Locked(_)) {
        drop(controls);
        return end_unheld(&current, CONTROL_WITHDRAW, WITHDRAWN_OUTCOME);
    }
    if probe.withdrawal_pending()? {
        return Err(super::control::withdraw_pending().into());
    }
    let control = current.record(CONTROL_WITHDRAW, None, None)?;
    drop(controls);
    Ok(Acted::recorded(control, None))
}

/// Cancels a run a live process holds: signals that process to terminate, whose own
/// cancellation marks the record `exited` `canceled`, and waits for it to release the
/// run; `cancel_pending` when it has not within the wait.
fn cancel_live(target: &ControlTarget) -> Result<Acted, ControlFailure> {
    let control = target.record(CONTROL_CANCEL, None, None)?;
    if let Some(pid) = lock_holder(&target.run_directory)?
        && !signal_and_await_release(&target.run_directory, pid, Signal::TERM)?
    {
        return Err(Refusal::new(
            "cancel_pending",
            "The run's process has not released the run; the cancel stays recorded.",
        )
        .into());
    }
    match super::mirror::read_run_record(&target.run_directory) {
        Some(record) if record.state == RunState::Exited => Ok(Acted {
            control,
            wait: None,
            outcome: CANCELED_OUTCOME,
        }),
        _ => Err(Refusal::new(
            "cancel_pending",
            "The run's process released the run without marking it exited; the cancel stays recorded.",
        )
        .into()),
    }
}

/// Sends `signal` to `pid`, the process that holds the run at `run_directory`, and waits for
/// it to release the run: false when it still holds the run after the wait. A process that
/// exited before the signal has released the run.
pub(super) fn signal_and_await_release(
    run_directory: &Path,
    pid: Pid,
    signal: Signal,
) -> Result<bool, ControlFailure> {
    match kill_process(pid, signal) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => {}
        Err(error) => {
            return Err(anyhow::Error::new(error)
                .context("signal the run's process")
                .into());
        }
    }
    let poll = useful_support::poll_interval(RELEASE_POLL);
    let deadline = useful_support::monotonic_now() + poll * RELEASE_POLLS;
    loop {
        if lock_holder(run_directory)? != Some(pid) {
            return Ok(true);
        }
        if useful_support::monotonic_now() >= deadline {
            return Ok(false);
        }
        useful_support::sleep(poll);
    }
}
