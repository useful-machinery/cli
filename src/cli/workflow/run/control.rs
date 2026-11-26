//! What every control command shares: finding the run `RUN` names, opening a run under the
//! home, appending one control event, continuing the run a resolving control completes the wait
//! of, the run's state and the verbs it takes, and the recorded and refused documents.

use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use serde::Serialize;
use serde_json::{Map, Value};
use useful_execution::{
    CancellationSource, ContinuingControl, ControlEvent, LocalRunDirectoryError, NoConditions,
    ResolvedWorkflow, RunState, ValidatedStep, WaitInspection, WaitKind, WaitRecord,
    WorkflowRunRecord, append_control, inspect_wait, normalize_terminal_path,
    normalize_terminal_scalar, read_local_run_status, resolve_workflow_file,
};

use super::super::{RUN_NOT_FOUND, RunAddressError};
use super::target::{Found, RunArg, Unfound};
use crate::cli::context::OrgArgs;
use crate::cli::{HttpOptions, PrincipalAuthenticationArgs};
use crate::exit_code::ExitCode;

/// The `after_help` paragraph of `answer`, `approve` and `hand-back`.
pub(super) const RESOLVING_AFTER_HELP: &str = "RUN is a run directory, a run ID or a subject. An ID or a subject is looked up under the useful home and, when the home holds no such run, in Cloud in the organization in effect.

answer applies to a run waiting for an answer, and approve and hand-back to a run waiting for approval; in any other state the command changes nothing and names the commands that apply.

For a run under the home the command records the control and, once the run's wait is resolved, continues the run as useful workflow run resume would. With --record-only it records the control alone and leaves the run for resume.

For a Cloud run the command reads the run and asks Cloud, under one request key sent again if the response is lost, to carry the control for the run's current wait to the runner executing it, which applies it and continues the run. Cloud's acceptance is not the runner's application.";

/// A control command's `--json` option.
pub(super) type JsonOutput = super::super::super::JsonArgs<super::super::super::WorkflowJson>;

/// A run a control command acts on: its record and its wait as `inspect_wait` found them
/// without taking the run lock. A control command observes no condition (`NoConditions`), so
/// an `external` wait reads as held whatever its provider would answer.
pub(super) struct ControlTarget {
    pub(super) run_directory: PathBuf,
    pub(super) record: WorkflowRunRecord,
    /// The run's `state.json`, as `useful workflow run show` reads it.
    pub(super) state: Value,
    pub(super) inspection: WaitInspection,
    /// The run's copy of the tree it was admitted from.
    pub(super) tree_copy: PathBuf,
}

/// A control that does not apply, refused before anything is written: one closed `code`.
#[derive(Debug)]
pub(super) struct Refusal {
    pub(super) code: &'static str,
    pub(super) message: String,
}

impl Refusal {
    pub(super) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// A run's state as the control verbs see it, which decides the verbs that apply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Standing {
    /// A process or a runner executes the run's steps.
    Running,
    /// The run waits on a wait of this kind; a `stop` wait is the run paused at a hold.
    Waiting(WaitKind),
    /// A run under the home whose process is gone or whose wait a recorded control resolves.
    Abandoned,
    /// The run ended, `succeeded` when its latest attempt succeeded.
    Ended { succeeded: bool },
}

/// Where the run a refusal names executes: Cloud carries no `interrupt` and no
/// `upgrade`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Placed {
    Home,
    Cloud,
}

impl Standing {
    /// The state of the run under the home `inspection` found: a run a live process holds is
    /// running, a held wait is waiting on its kind, a run whose wait a control resolves or
    /// whose process is gone is abandoned, and an exited one ended, succeeded when `succeeded`
    /// says its latest attempt did.
    pub(super) fn of(inspection: &WaitInspection, succeeded: impl FnOnce() -> bool) -> Self {
        match inspection {
            WaitInspection::Locked(_) => Self::Running,
            WaitInspection::Held { wait }
            | WaitInspection::RuleInvalid { wait, .. }
            | WaitInspection::ConditionUnavailable { wait, .. } => Self::Waiting(wait.kind),
            WaitInspection::NoWait {
                state: Some(RunState::Exited),
                ..
            } => Self::Ended {
                succeeded: succeeded(),
            },
            WaitInspection::Satisfied { .. }
            | WaitInspection::Continued { .. }
            | WaitInspection::NoWait { .. } => Self::Abandoned,
        }
    }

    /// The state as a refusal names it.
    const fn description(self) -> &'static str {
        match self {
            Self::Running => "is running",
            Self::Waiting(WaitKind::Answer) => "is waiting for an answer",
            Self::Waiting(WaitKind::Approval) => "is waiting for approval",
            Self::Waiting(WaitKind::Repair) => "is waiting for repair",
            Self::Waiting(WaitKind::Host) => "is waiting for its host",
            Self::Waiting(WaitKind::Stop) => "is paused at a hold",
            Self::Waiting(WaitKind::External) => "is waiting on an external condition",
            Self::Waiting(WaitKind::Children) => "is waiting on its child runs",
            Self::Abandoned => {
                "is abandoned: its process is gone or a recorded control resolves its wait"
            }
            Self::Ended { succeeded: true } => "has ended and succeeded",
            Self::Ended { succeeded: false } => "has ended",
        }
    }

    /// The control verbs of `useful workflow run` that apply to a run in this state where it
    /// is `placed`: the state's own, `pause` in every state but ended, and neither
    /// `interrupt` nor `upgrade` for a Cloud run.
    pub(super) fn verbs(self, placed: Placed) -> Vec<&'static str> {
        let own: &[&'static str] = match self {
            Self::Running => &["interrupt", "pause", "cancel"],
            Self::Waiting(WaitKind::Answer) => &["answer", "upgrade", "pause", "cancel"],
            Self::Waiting(WaitKind::Approval) => {
                &["approve", "hand-back", "upgrade", "pause", "cancel"]
            }
            Self::Waiting(WaitKind::Repair) => &["retry", "upgrade", "pause", "cancel"],
            Self::Waiting(WaitKind::Host) => &["resume", "retry", "upgrade", "pause", "cancel"],
            Self::Waiting(WaitKind::Stop) => &["unpause", "upgrade", "pause", "cancel"],
            Self::Waiting(WaitKind::External | WaitKind::Children) => {
                &["resume", "upgrade", "pause", "cancel"]
            }
            Self::Abandoned => &["resume", "pause", "cancel"],
            Self::Ended { succeeded: true } => &["release"],
            Self::Ended { succeeded: false } => &["retry", "release"],
        };
        own.iter()
            .copied()
            .filter(|verb| placed == Placed::Home || !matches!(*verb, "interrupt" | "upgrade"))
            .collect()
    }

    /// The refusal `code` of a verb that does not apply in this state: one sentence naming the
    /// state and the verbs that apply.
    pub(super) fn refusal(self, code: &'static str, placed: Placed) -> Refusal {
        Refusal::new(code, self.message(placed))
    }

    /// The sentence [`Standing::refusal`] writes.
    pub(super) fn message(self, placed: Placed) -> String {
        let verbs = self.verbs(placed);
        let listed = match verbs.as_slice() {
            [first @ .., last] if !first.is_empty() => format!("{} or {last}", first.join(", ")),
            verbs => verbs.join(""),
        };
        format!(
            "The run {}, where useful workflow run {listed} applies; nothing was changed.",
            self.description()
        )
    }
}

/// The refusal of an `answer` with no `--question` whose wait leaves several questions open,
/// naming their ids; nothing is appended or sent.
pub(super) fn question_ambiguous<'a>(ids: impl Iterator<Item = &'a str>) -> Refusal {
    let ids = ids
        .map(|id| normalize_terminal_scalar(id.as_bytes()))
        .collect::<Vec<_>>()
        .join(", ");
    Refusal::new(
        "question_ambiguous",
        format!("The wait asks several open questions ({ids}); name one with --question ID."),
    )
}

/// Why a control command did not act: a refusal, or an operational failure.
pub(super) enum ControlFailure {
    Refused(Refusal),
    Failed(anyhow::Error),
}

impl From<RunAddressError> for Refusal {
    fn from(error: RunAddressError) -> Self {
        Self::new(error.code, error.message)
    }
}

impl From<Refusal> for ControlFailure {
    fn from(refusal: Refusal) -> Self {
        Self::Refused(refusal)
    }
}

impl From<LocalRunDirectoryError> for ControlFailure {
    fn from(error: LocalRunDirectoryError) -> Self {
        Self::Failed(anyhow::Error::new(error))
    }
}

impl From<anyhow::Error> for ControlFailure {
    fn from(error: anyhow::Error) -> Self {
        Self::Failed(error)
    }
}

/// The control event a command appended, as its document reports it.
#[derive(Serialize)]
pub(super) struct RecordedControl {
    pub(super) ordinal: u64,
    pub(super) event: String,
    /// The control file relative to the run directory, `controls/<NNNN>-<event>.json`.
    pub(super) path: String,
    pub(super) wait: Option<String>,
}

/// What a control command did: the control it appended, the run's wait afterwards, and the
/// document's `outcome` (`recorded`, the outcome the command ended the run with, or
/// `interrupted`).
pub(super) struct Acted {
    pub(super) control: RecordedControl,
    pub(super) wait: Option<WaitRecord>,
    pub(super) outcome: &'static str,
}

impl Acted {
    pub(super) fn recorded(control: RecordedControl, wait: Option<WaitRecord>) -> Self {
        Self {
            control,
            wait,
            outcome: "recorded",
        }
    }
}

impl ControlTarget {
    /// The run's current wait, whether or not a control already resolves it.
    pub(super) fn wait(&self) -> Option<&WaitRecord> {
        inspected_wait(&self.inspection)
    }

    /// The wait of `kind` a resolving command (`answer`, `approve`, `hand-back`) acts on:
    /// refused while a live process holds the run, when it does not wait, when it waits on
    /// another kind, and when a recorded control already resolves the wait.
    pub(super) fn wait_to_resolve(&self, kind: WaitKind) -> Result<&WaitRecord, Refusal> {
        let wait = match &self.inspection {
            WaitInspection::Locked(_) => return Err(run_locked()),
            WaitInspection::NoWait { .. } | WaitInspection::Continued { .. } => {
                return Err(self.refusal("run_not_waiting"));
            }
            WaitInspection::Held { wait }
            | WaitInspection::Satisfied { wait, .. }
            | WaitInspection::RuleInvalid { wait, .. }
            | WaitInspection::ConditionUnavailable { wait, .. } => wait,
        };
        if wait.kind != kind {
            return Err(self.refusal("wait_kind_mismatch"));
        }
        if matches!(self.inspection, WaitInspection::Satisfied { .. }) {
            return Err(wait_resolved());
        }
        Ok(wait)
    }

    /// The run's state.
    pub(super) fn standing(&self) -> Standing {
        Standing::of(&self.inspection, || latest_attempt_succeeded(&self.state))
    }

    /// The refusal `code` of a verb that does not apply in the run's state.
    pub(super) fn refusal(&self, code: &'static str) -> Refusal {
        self.standing().refusal(code, Placed::Home)
    }

    /// The ids a stop may name and the ids the run knows, read from the workflow resolved
    /// again from the run's tree copy, since a nested run may not exist yet. A tree copy that
    /// does not resolve holds nothing, so every step the latest attempt's progress lists is
    /// then known and none holdable.
    pub(super) fn stop_steps(&self) -> StopSteps {
        let progress = self.state["attempts"]
            .as_array()
            .and_then(|attempts| attempts.last())
            .and_then(|attempt| attempt["progress"]["steps"].as_array())
            .into_iter()
            .flatten()
            .filter_map(|step| step["id"].as_str())
            .map(str::to_owned);
        let workflow =
            resolve_workflow_file(&self.tree_copy, &self.tree_copy.join(&self.record.workflow))
                .ok();
        let holdable = workflow
            .as_ref()
            .map(holdable_step_ids)
            .unwrap_or_default()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let own = workflow
            .into_iter()
            .flat_map(|workflow| workflow.definition.steps.into_keys());
        let known = progress
            .chain(own)
            .chain(holdable.iter().cloned())
            .collect();
        StopSteps { known, holdable }
    }

    /// Appends the control `event` naming `wait` with `payload`, by the invoking user.
    pub(super) fn record(
        &self,
        event: &str,
        wait: Option<String>,
        payload: Option<Map<String, Value>>,
    ) -> Result<RecordedControl, ControlFailure> {
        let control = ControlEvent::new(
            event,
            &self.record.id,
            &super::super::login_name(),
            wait,
            payload,
        )?;
        let path = append_control(&self.run_directory, &control)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow!("appended control file name is not UTF-8"))?;
        let ordinal = name
            .split_once('-')
            .and_then(|(ordinal, _)| ordinal.parse().ok())
            .ok_or_else(|| anyhow!("appended control file name has no ordinal"))?;
        Ok(RecordedControl {
            ordinal,
            event: control.event,
            path: format!("controls/{name}"),
            wait: control.wait,
        })
    }
}

/// The wait `inspection` found, whether or not a control already resolves it.
fn inspected_wait(inspection: &WaitInspection) -> Option<&WaitRecord> {
    match inspection {
        WaitInspection::Held { wait }
        | WaitInspection::Satisfied { wait, .. }
        | WaitInspection::RuleInvalid { wait, .. }
        | WaitInspection::ConditionUnavailable { wait, .. } => Some(wait),
        WaitInspection::Locked(_)
        | WaitInspection::NoWait { .. }
        | WaitInspection::Continued { .. } => None,
    }
}

/// The current wait of the run at `run_directory`, inspected again without taking the run
/// lock, for a command that reports where a run it signalled stopped.
pub(super) fn current_wait(run_directory: &Path) -> Result<Option<WaitRecord>, ControlFailure> {
    let probe = inspect_wait(run_directory, &NoConditions)?;
    Ok(inspected_wait(&probe.inspection).cloned())
}

/// Whether the latest attempt `state`, a run's `state.json`, lists succeeded.
pub(super) fn latest_attempt_succeeded(state: &Value) -> bool {
    state["attempts"]
        .as_array()
        .and_then(|attempts| attempts.last())
        .is_some_and(|attempt| attempt["state"] == "succeeded")
}

/// The state of the exited run at `run_directory`, succeeded when its `state.json` says
/// its latest attempt did; a run that cannot be read did not.
pub(super) fn ended(run_directory: &Path) -> Standing {
    Standing::Ended {
        succeeded: read_local_run_status(run_directory)
            .is_ok_and(|snapshot| latest_attempt_succeeded(&snapshot.state)),
    }
}

/// A run a live process holds, which is running.
pub(super) fn run_locked() -> Refusal {
    Standing::Running.refusal("run_locked", Placed::Home)
}

/// A `running` run no live process holds, which is abandoned, refused as `interrupt` and
/// `retry` refuse it.
pub(super) fn run_not_live() -> Refusal {
    Standing::Abandoned.refusal("run_not_live", Placed::Home)
}

/// A live run that already holds a withdrawal its process has not yet honored.
pub(super) fn withdraw_pending() -> Refusal {
    Refusal::new(
        "withdraw_pending",
        "A withdrawal is already recorded; the run ends once its running stage finishes.",
    )
}

/// A wait a recorded control already resolves, which leaves the run abandoned until it is
/// resumed.
pub(super) fn wait_resolved() -> Refusal {
    Standing::Abandoned.refusal("wait_resolved", Placed::Home)
}

/// Opens the run at `run_directory`: a run without a run record is
/// `run_record_missing`, and a directory that is not a run `run_directory_invalid`.
pub(super) fn open(run_directory: &Path) -> Result<ControlTarget, Refusal> {
    fn invalid<E>(_: E) -> Refusal {
        Refusal::new(
            "run_directory_invalid",
            "The directory is not a readable workflow run directory.",
        )
    }
    let snapshot = read_local_run_status(run_directory).map_err(invalid)?;
    let tree_copy = snapshot.tree_copy_directory();
    let record = snapshot.record.ok_or_else(|| {
        Refusal::new(
            "run_record_missing",
            "The run has no run record; only a run admitted from a tree or a definition takes controls.",
        )
    })?;
    let record: WorkflowRunRecord = serde_json::from_value(record).map_err(invalid)?;
    let probe = inspect_wait(run_directory, &NoConditions).map_err(invalid)?;
    Ok(ControlTarget {
        run_directory: probe.run_directory,
        record,
        tree_copy,
        state: snapshot.state,
        inspection: probe.inspection,
    })
}

/// The steps of a run `ControlTarget::stop_steps` read.
pub(super) struct StopSteps {
    /// Every step of the run's own workflow and of its latest attempt's progress, and the
    /// `holdable` ones: a stop naming any other is `step_unknown`.
    pub(super) known: BTreeSet<String>,
    /// The steps a stop may name (`holdable_step_ids`): a known step outside them is
    /// `step_not_holdable`.
    pub(super) holdable: BTreeSet<String>,
}

/// The steps of `workflow` a stop may name, the only steps the engine holds before:
/// its own `workflow` steps and the `workflow` steps of the nested workflows they
/// name (`nested_step_ids`). A step of `workflow` outside them is
/// `step_not_holdable`.
pub(super) fn holdable_step_ids(workflow: &ResolvedWorkflow) -> Vec<String> {
    workflow
        .definition
        .steps
        .iter()
        .filter(|(_, step)| matches!(step, ValidatedStep::Workflow(_)))
        .map(|(id, _)| id.clone())
        .chain(nested_step_ids(workflow))
        .collect()
}

/// A stop before a step of the run's workflow the engine does not hold before.
pub(super) fn step_not_holdable() -> Refusal {
    Refusal::new(
        "step_not_holdable",
        "The run holds only before a workflow step, and this step is not one.",
    )
}

/// The ids of the `workflow` steps of each nested workflow `workflow`'s `workflow` steps
/// name: each child resolved from `workflow`'s source root, and only a child that is itself
/// edge-scheduled, so it has `workflow` steps of its own. A child that does not resolve
/// contributes none.
pub(super) fn nested_step_ids(workflow: &ResolvedWorkflow) -> Vec<String> {
    let root = &workflow.source.source_root;
    workflow
        .definition
        .steps
        .values()
        .filter_map(|step| match step {
            ValidatedStep::Workflow(step) => {
                resolve_workflow_file(root, &root.join(&step.workflow)).ok()
            }
            _ => None,
        })
        .filter(super::create::has_workflow_steps)
        .flat_map(|child| {
            child
                .definition
                .steps
                .into_iter()
                .filter(|(_, step)| matches!(step, ValidatedStep::Workflow(_)))
                .map(|(id, _)| id)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The state of the run at `run_directory` when it waits, as `inspect_wait` reads it without
/// the run lock: its wait's kind, or abandoned for a wait a recorded control resolves; `None`
/// when it does not wait or cannot be probed. `retry --all` refuses a run that waits.
pub(super) fn waiting(run_directory: &Path) -> Option<Standing> {
    let probe = inspect_wait(run_directory, &NoConditions).ok()?;
    match probe.inspection {
        WaitInspection::Held { wait }
        | WaitInspection::RuleInvalid { wait, .. }
        | WaitInspection::ConditionUnavailable { wait, .. } => Some(Standing::Waiting(wait.kind)),
        WaitInspection::Satisfied { .. } => Some(Standing::Abandoned),
        WaitInspection::Locked(_)
        | WaitInspection::NoWait { .. }
        | WaitInspection::Continued { .. } => None,
    }
}

/// Runs control command `command` on `RUN`, looked up under the home alone, and prints its
/// document: `act` appends the control or refuses, after `RUN` resolves and the run opens. A
/// `RUN` the home does not hold is `run_not_found`, its message ending with `elsewhere`, which
/// says that a Cloud run takes no such command.
pub(super) fn execute_at_home(
    command: &'static str,
    run: &RunArg,
    elsewhere: &str,
    json: bool,
    act: impl FnOnce(&ControlTarget) -> Result<Acted, ControlFailure>,
) -> super::super::super::CommandResult {
    match run.home_only() {
        Ok(run_directory) => match act_on(command, &run_directory, json, act) {
            Ok((target, acted)) => write_recorded(command, &target, &acted, json),
            Err(result) => result,
        },
        Err(error) => write_refusal(
            command,
            None,
            &Refusal::from(home_miss(error, elsewhere)),
            json,
        ),
    }
}

/// `error`, the lookup under the home alone, with `elsewhere` added to a `run_not_found`: the
/// sentence that says a Cloud run takes no such command.
pub(super) fn home_miss(mut error: RunAddressError, elsewhere: &str) -> RunAddressError {
    if error.code == RUN_NOT_FOUND {
        error.message.push(' ');
        error.message.push_str(elsewhere);
    }
    error
}

/// The run control command `command` names, found under the home and then in Cloud: a
/// lookup that found none ends the leaf with its `refused` document, exit 1, or, when
/// Cloud failed a read the lookup made, with that failure's code and exit status, and
/// nothing is appended.
pub(super) fn find(
    command: &'static str,
    run: &RunArg,
    org: &OrgArgs,
    authentication: &PrincipalAuthenticationArgs,
    http: &HttpOptions,
    json: bool,
) -> Result<Found, super::super::super::CommandResult> {
    run.everywhere(org, authentication, http)
        .map_err(|unfound| match unfound {
            Unfound::Refused(error) => write_refusal(command, None, &Refusal::from(error), json),
            Unfound::Cloud { failure, .. } => {
                let (code, message, exit) = super::cloud::failure_diagnostic(command, &failure);
                write_refusal_exiting(command, None, &Refusal::new(code, message), json, exit)
            }
            Unfound::Failed(failure) => Err(failure),
        })
}

/// Opens the run at `run_directory` for control command `command` and lets `act` append the
/// control or refuse: the run and what `act` did, or the command's result once a refusal or
/// a failure was reported.
pub(super) fn act_on<A>(
    command: &'static str,
    run_directory: &Path,
    json: bool,
    act: impl FnOnce(&ControlTarget) -> Result<A, ControlFailure>,
) -> Result<(ControlTarget, A), super::super::super::CommandResult> {
    let target = match open(run_directory) {
        Ok(target) => target,
        Err(refusal) => return Err(write_refusal(command, Some(run_directory), &refusal, json)),
    };
    match act(&target) {
        Ok(acted) => Ok((target, acted)),
        Err(ControlFailure::Refused(refusal)) => Err(write_refusal(
            command,
            Some(&target.run_directory),
            &refusal,
            json,
        )),
        Err(ControlFailure::Failed(error)) => Err(Err(error
            .context(format!(
                "{command} {}",
                normalize_terminal_path(&target.run_directory)
            ))
            .into())),
    }
}

/// What `answer`, `approve` or `hand-back` did to a run under the home: the control it
/// appended, and whether the control completes the run's wait.
pub(super) struct Resolved {
    pub(super) acted: Acted,
    pub(super) completes: bool,
}

/// Runs `control` on the run at `run_directory`: `act` appends the control or refuses, and
/// a control that completes the wait continues the run in this command as `useful workflow
/// run resume` would, from the wait the control resolved, in the previous attempt's
/// execution root, its documents naming `control`'s command. With `record_only`, and for a
/// control that leaves the wait open, the command prints the `recorded` document and
/// continues nothing.
pub(super) fn resolve(
    control: ContinuingControl,
    run_directory: &Path,
    record_only: bool,
    presentation: &super::PresentationOptions,
    act: impl FnOnce(&ControlTarget) -> Result<Resolved, ControlFailure>,
) -> super::super::super::CommandResult {
    let command = control.command();
    let json = presentation.output.json;
    let (target, resolved) = match act_on(command, run_directory, json, act) {
        Ok(acted) => acted,
        Err(result) => return result,
    };
    if record_only || !resolved.completes {
        return write_recorded(command, &target, &resolved.acted, json);
    }
    let config = super::create::presentation_config(presentation);
    super::create::execute_with_runtime("start local workflow continuation runtime", async {
        let cancellation = CancellationSource::new();
        let signal_task = super::create::start_signal_observation(
            cancellation.clone(),
            super::create::UnixSignals::new()?,
        );
        super::resume::continue_run(
            super::resume::Continuation {
                run_directory: target.run_directory,
                from_steps: Vec::new(),
                workflow: None,
                execution_root: None,
                handover: false,
                leaf: super::create::ExecutionLeaf::Control(control),
                edge: None,
                bridge: None,
            },
            config,
            cancellation,
            signal_task,
        )
        .await
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordedDocument<'a> {
    schema_version: u8,
    command: &'static str,
    outcome: &'static str,
    exit_status: u8,
    run_directory: &'a str,
    run: &'a str,
    control: &'a RecordedControl,
    wait: Option<&'a WaitRecord>,
}

pub(super) fn write_recorded(
    command: &'static str,
    target: &ControlTarget,
    acted: &Acted,
    json: bool,
) -> super::super::super::CommandResult {
    if json {
        let run_directory = target
            .run_directory
            .to_str()
            .ok_or_else(|| anyhow!("normalized run path is not UTF-8"))?;
        super::super::super::write_pretty_json(&RecordedDocument {
            schema_version: 1,
            command,
            outcome: acted.outcome,
            exit_status: ExitCode::Success.as_u8(),
            run_directory,
            run: &target.record.id,
            control: &acted.control,
            wait: acted.wait.as_ref(),
        })
        .with_context(|| format!("write {command} output"))?;
    } else {
        let mut stdout = io::stdout().lock();
        write!(
            stdout,
            "recorded {} for {} as {}",
            acted.control.event,
            normalize_terminal_scalar(target.record.id.as_bytes()),
            acted.control.path
        )
        .and_then(|()| match acted.outcome {
            "recorded" => Ok(()),
            outcome => write!(stdout, " · run {outcome}"),
        })
        .and_then(|()| writeln!(stdout))
        .and_then(|()| stdout.flush())
        .with_context(|| format!("write {command} output"))?;
    }
    Ok(ExitCode::Success)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RefusedDocument<'a> {
    schema_version: u8,
    command: &'static str,
    outcome: &'static str,
    exit_status: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    run_directory: Option<&'a str>,
    diagnostics: [RefusalDiagnostic<'a>; 1],
}

#[derive(Serialize)]
struct RefusalDiagnostic<'a> {
    code: &'static str,
    message: &'a str,
}

/// Prints `refusal` of `command` and exits 1: with `--json` the `refused` document, naming
/// the run directory once one resolved, and otherwise a stderr line.
pub(super) fn write_refusal(
    command: &'static str,
    run_directory: Option<&Path>,
    refusal: &Refusal,
    json: bool,
) -> super::super::super::CommandResult {
    write_refusal_exiting(
        command,
        run_directory,
        refusal,
        json,
        ExitCode::GeneralFailure,
    )
}

/// [`write_refusal`] exiting `exit`.
fn write_refusal_exiting(
    command: &'static str,
    run_directory: Option<&Path>,
    refusal: &Refusal,
    json: bool,
    exit: ExitCode,
) -> super::super::super::CommandResult {
    if json {
        super::super::super::write_pretty_json(&RefusedDocument {
            schema_version: 1,
            command,
            outcome: "refused",
            exit_status: exit.as_u8(),
            run_directory: run_directory.and_then(Path::to_str),
            diagnostics: [RefusalDiagnostic {
                code: refusal.code,
                message: &refusal.message,
            }],
        })
        .with_context(|| format!("write {command} output"))?;
    } else {
        let mut stderr = io::stderr().lock();
        writeln!(
            stderr,
            "{command} refused: {}: {}",
            refusal.code, refusal.message
        )
        .and_then(|()| stderr.flush())
        .with_context(|| format!("write {command} output"))?;
    }
    Ok(exit)
}

/// Whether the run's record reads `exited`.
pub(super) fn exited(target: &ControlTarget) -> bool {
    target.record.state == RunState::Exited
}
