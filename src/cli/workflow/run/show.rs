//! `useful workflow run show`: the one read of a run, found under the `useful` home and then in
//! Cloud. A run under the home is read from its records, without taking its lock or changing its
//! directory once an already committed result publication is finished: its status, the current
//! attempt's state, result, recovery, retry and continuation eligibility, with its run record,
//! attempts, mirror writes and each running child's attempt and in-flight steps, read from the
//! child's records the same way, and under a child that is a nested run its `edges` counts and
//! its own children, read the same way again. A Cloud run is read by `cloud`.

mod cloud;

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow};
use clap::Args;
use serde::Serialize;
use serde_json::{Map, Value};
use useful_execution::{
    ArchivedAttemptLoadError, ChildRun, ColorChoice, ControlEvent, LocalRecoveryStatus,
    LocalRetryEligibility, LocalRunStatusSnapshot, LocalStatusAttempt, LocalStatusError,
    LocalStatusProgress, LocalStatusResult, LocalStatusStart, MirrorAction, MirrorSkipReason,
    MirrorWrite, MirrorWriteOutcome, PresentationConfig, RequestedPresentationMode,
    RetryIneligibilityReason, RunState, TerminalCapabilities, WaitRecord, WorkflowRunRecord,
    child_runs, failed_child_detail, human_duration, load_local_archived_attempt,
    normalize_terminal_path, normalize_terminal_scalar, operational_error_code,
    read_local_run_status, read_numbered_controls, read_numbered_mirror_writes,
    reconcile_current_result_publication, styled_terminal_text as styled,
};

use super::cloud_api::RunWaitArgs;
use super::list::{or_dash, position, state_name};
use super::target::{Found, RunArg, Unfound};
use crate::cli::context::OrgArgs;
use crate::cli::{CommandFailure, HttpOptions, PrincipalAuthenticationArgs};
use crate::exit_code::ExitCode;

pub(super) const ABOUT: &str = "Show a workflow run under the useful home or in Cloud";
pub(super) const AFTER_HELP: &str = "RUN is a run directory, a run ID or a subject. An ID or a subject is looked up under the useful home and, when the home holds no such run, in Cloud in the organization in effect: an ID names the Cloud run of that ID, and a subject the newest run, for each definition, whose subject claim names it, among the organization's 500 newest live runs and then, when every live run was read, its 500 newest ended ones. A run under the home is read from its records without a request; a Cloud run is read with its definition, subject claim, workflow state and outcome, latest progress, exits, newest controls and newest trigger deliveries.

--attempt reads a run under the home; --wait and --timeout follow a Cloud run until it is final.";
const COMMAND: &str = "useful workflow run show";
const ATTEMPT_NOT_FOUND: &str = "attempt_not_found";
const STYLE_ACTIVE: &str = "38;2;137;180;250";
const STYLE_SUCCESS: &str = "38;2;166;227;161";
const STYLE_FAILURE: &str = "38;2;243;139;168";
const STYLE_BLOCKED: &str = "38;2;250;179;135";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(flatten)]
    run: RunArg,

    #[arg(
        long,
        value_name = "NUMBER",
        value_parser = super::view::parse_attempt,
        help = "Attempt number to show alone, of a run under the useful home"
    )]
    attempt: Option<NonZeroU64>,

    #[command(flatten)]
    wait: RunWaitArgs,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    presentation: super::PresentationOptions,

    #[command(flatten)]
    authentication: PrincipalAuthenticationArgs,

    #[command(flatten)]
    http: HttpOptions,
}

/// Everything `show` prints about one run, read from one status snapshot.
struct Shown {
    snapshot: LocalRunStatusSnapshot,
    /// The run record, `None` for a run admitted from a workflow file's closure.
    record: Option<WorkflowRunRecord>,
    attempts: Vec<Attempt>,
    children: Vec<Child>,
    controls: Vec<(u64, ControlEvent)>,
    mirror: Vec<(u64, MirrorWrite)>,
}

/// An attempt with the continuation `reason` and `edge` and the `imported` source run its
/// `state.json` entry records, when it has them.
struct Attempt {
    attempt: LocalStatusAttempt,
    reason: Option<Value>,
    edge: Option<Value>,
    imported: Option<Value>,
}

/// A child run with its progress while its record is `running` and, for a nested run, its
/// own children.
struct Child {
    run: ChildRun,
    progress: Option<ChildProgress>,
    /// The nested run's children, `None` for a child that has none, as a plain stage.
    nested: Option<Vec<Child>>,
}

/// A running child's current attempt, read from its own records.
struct ChildProgress {
    attempt: u64,
    state: &'static str,
    recovery: &'static str,
    progress: LocalStatusProgress,
}

/// A run `show` cannot read, printed as the `error` document.
enum Unread {
    /// The status read refused the run directory `RUN` resolved to.
    Status(LocalStatusError, PathBuf),
    /// An already committed result publication could not be finished.
    Reconciliation(PathBuf, ArchivedAttemptLoadError),
    /// The run record, a child run, a control or a mirror write cannot be read: the
    /// directory is the run's, so a child's message names the child.
    Invalid(PathBuf, String),
    /// `--attempt` names a number the run has no attempt of.
    AttemptNotFound(PathBuf, NonZeroU64),
}

impl Unread {
    fn write_document(&self) -> io::Result<ExitCode> {
        let (run_directory, code, message) = match self {
            Self::Status(error, _) => (
                error.run_directory.as_deref(),
                error.code.as_str(),
                error.code.message(),
            ),
            Self::Reconciliation(run_directory, error) => (
                Some(run_directory.as_path()),
                reconciliation_error_code(error),
                "The workflow result could not be finalized. Check the run directory and try again.",
            ),
            Self::Invalid(run_directory, message) => (
                Some(run_directory.as_path()),
                "run_directory_invalid",
                message.as_str(),
            ),
            Self::AttemptNotFound(run_directory, _) => (
                Some(run_directory.as_path()),
                ATTEMPT_NOT_FOUND,
                "The run has no attempt of this number.",
            ),
        };
        write_json(&ErrorOutput {
            schema_version: 1,
            command: COMMAND,
            outcome: "error",
            exit_status: ExitCode::GeneralFailure.as_u8(),
            run_directory: run_directory.and_then(Path::to_str),
            error: ErrorDetail { code, message },
        })?;
        Ok(ExitCode::GeneralFailure)
    }

    fn into_error(self) -> anyhow::Error {
        let inspect = |run_directory: &Path| {
            format!(
                "inspect workflow run {}",
                normalize_terminal_path(run_directory)
            )
        };
        match self {
            Self::Status(error, run_directory) => {
                anyhow!(error.code.message()).context(inspect(&run_directory))
            }
            Self::Reconciliation(_, error) => anyhow!(reconciliation_error_code(&error))
                .context("finalize workflow result publication"),
            Self::Invalid(run_directory, message) => {
                anyhow!("run_directory_invalid: {message}").context(inspect(&run_directory))
            }
            Self::AttemptNotFound(run_directory, number) => {
                anyhow!("{ATTEMPT_NOT_FOUND}: the run has no attempt {number}")
                    .context(inspect(&run_directory))
            }
        }
    }
}

impl Command {
    pub(super) fn execute(self) -> super::super::super::CommandResult {
        let json = self.presentation.output.json;
        let found = match self
            .run
            .everywhere(&self.org, &self.authentication, &self.http)
        {
            Ok(found) => found,
            Err(Unfound::Refused(error)) => return write_missed(error, json),
            Err(Unfound::Cloud {
                deployment,
                organization,
                failure,
            }) => return cloud::write_lookup_failure(&deployment, organization, &failure, json),
            Err(Unfound::Failed(failure)) => return Err(failure),
        };
        match found {
            Found::Home(_) if self.wait.wait => Err(usage(
                "--wait follows a Cloud run, and RUN names a run under the useful home\n\n\
                 Read the run without --wait; the command that executes a local run follows it.",
            )),
            Found::Home(run_directory) => super::super::super::execute_read_only_with_signals(
                "workflow run show",
                move |control| self.execute_blocking(run_directory, control),
            ),
            Found::Cloud(_) if self.attempt.is_some() => Err(usage(
                "--attempt reads a run under the useful home, and RUN names a Cloud run\n\n\
                 Read the Cloud run without --attempt.",
            )),
            Found::Cloud(run) => cloud::show(
                *run,
                self.authentication,
                self.http,
                self.wait.wait.then_some(self.wait.timeout),
                json,
            ),
        }
    }

    fn execute_blocking(
        &self,
        run_directory: PathBuf,
        control: &super::super::super::OperationControl<()>,
    ) -> super::super::super::CommandResult {
        let json = self.presentation.output.json;
        let shown = read(run_directory, self.attempt);
        super::super::super::complete_read_only_output(control, || {
            let exit = match shown {
                Ok(shown) if json => document(&shown)
                    .and_then(|document| write_json(&document))
                    .map(|()| ExitCode::Success),
                Ok(shown) => {
                    write_plain(&shown, self.plain_color_enabled()).map(|()| ExitCode::Success)
                }
                Err(unread) if json => unread.write_document(),
                Err(unread) => return Err(unread.into_error().into()),
            };
            Ok(exit.with_context(|| format!("write {COMMAND} output"))?)
        })
    }

    fn plain_color_enabled(&self) -> bool {
        PresentationConfig {
            requested_mode: RequestedPresentationMode::Plain,
            color: match self.presentation.color {
                super::ColorArgument::Auto => ColorChoice::Auto,
                super::ColorArgument::Always => ColorChoice::Always,
                super::ColorArgument::Never => ColorChoice::Never,
            },
            capabilities: TerminalCapabilities::detect(),
            standard_input_reserved: false,
        }
        .color_enabled()
    }
}

/// A usage error, exit 2, of an option the run `RUN` names does not read.
fn usage(message: &str) -> CommandFailure {
    CommandFailure::with_exit_code(anyhow!("{message}"), ExitCode::UsageError)
}

/// The lookup's refusal, as `show` writes it.
fn write_missed(
    error: super::super::RunAddressError,
    json: bool,
) -> super::super::super::CommandResult {
    super::target::write_refused(error, COMMAND, json)
}

/// The run at `run_directory` from one status snapshot, read after an already committed result
/// publication is finished; a failure to finish it is reported once the snapshot reads. With
/// `attempt`, the attempts hold that attempt alone, and a number the run has no attempt of is
/// `attempt_not_found`.
fn read(run_directory: PathBuf, attempt: Option<NonZeroU64>) -> Result<Shown, Unread> {
    let reconciliation = reconcile_current_result_publication(&run_directory);
    let mut snapshot = read_local_run_status(&run_directory)
        .map_err(|error| Unread::Status(error, run_directory))?;
    let run_directory = snapshot.run_directory.clone();
    reconciliation.map_err(|error| Unread::Reconciliation(run_directory.clone(), error))?;
    let invalid = |message: String| Unread::Invalid(run_directory.clone(), message);
    let record = snapshot
        .record
        .clone()
        .map(serde_json::from_value::<WorkflowRunRecord>)
        .transpose()
        .map_err(|error| invalid(error.to_string()))?;
    let now = useful_support::utc_now();
    let children = children(
        child_runs(&run_directory).map_err(|error| invalid(error.to_string()))?,
        now,
    )
    .map_err(invalid)?;
    let controls =
        read_numbered_controls(&run_directory).map_err(|error| invalid(error.to_string()))?;
    let mirror =
        read_numbered_mirror_writes(&run_directory).map_err(|error| invalid(error.to_string()))?;
    let mut attempts = std::mem::take(&mut snapshot.attempts);
    if let Some(number) = attempt {
        attempts.retain(|attempt| attempt.attempt_number == number.get());
        if attempts.is_empty() {
            return Err(Unread::AttemptNotFound(run_directory.clone(), number));
        }
    }
    let attempts = attempts
        .into_iter()
        .map(|attempt| {
            let entry = state_attempt(&snapshot.state, attempt.attempt_number);
            let field = |name| {
                entry
                    .and_then(|entry| entry["continuation"].get(name))
                    .cloned()
            };
            Attempt {
                reason: field("reason"),
                edge: field("edge"),
                imported: entry.and_then(|entry| entry.get("imported")).cloned(),
                attempt,
            }
        })
        .collect();
    Ok(Shown {
        snapshot,
        record,
        attempts,
        children,
        controls,
        mirror,
    })
}

/// Each of `runs` with its progress while it is `running` and, when it has children of its
/// own, as a nested run does, those children read the same way, so the entries nest as the
/// directories do; or the reason a child's records cannot be read, naming the child.
fn children(runs: Vec<ChildRun>, now: time::OffsetDateTime) -> Result<Vec<Child>, String> {
    runs.into_iter()
        .map(|run| {
            let progress = (run.record.state == RunState::Running)
                .then(|| child_progress(&run, now))
                .transpose()?;
            let nested = child_runs(&run.directory).map_err(|error| {
                format!(
                    "Child run {}: {error}",
                    normalize_terminal_path(&run.directory)
                )
            })?;
            let nested = (!nested.is_empty())
                .then(|| children(nested, now))
                .transpose()?;
            Ok(Child {
                run,
                progress,
                nested,
            })
        })
        .collect()
}

/// A running child's current attempt and its in-flight nodes, with the time since each start
/// at `now`, or the reason its records cannot be read, naming the child: the refusal's run
/// directory is the parent's.
fn child_progress(child: &ChildRun, now: time::OffsetDateTime) -> Result<ChildProgress, String> {
    let unreadable = |reason: &dyn std::fmt::Display| {
        format!(
            "Child run {}: {reason}",
            normalize_terminal_path(&child.directory)
        )
    };
    let snapshot = read_local_run_status(&child.directory)
        .map_err(|error| unreadable(&error.code.message()))?;
    let progress = snapshot
        .status_state
        .in_flight(now)
        .map_err(|error| unreadable(&error))?;
    Ok(ChildProgress {
        attempt: snapshot.current_attempt_number,
        state: snapshot.current_attempt_state,
        recovery: snapshot.recovery.as_str(),
        progress,
    })
}

/// The `state.json` entry for attempt `number`, when it has one.
fn state_attempt(state: &Value, number: u64) -> Option<&Value> {
    state["attempts"]
        .as_array()?
        .iter()
        .find(|attempt| attempt["attemptNumber"] == number)
}

/// The `shown` document: the status read's members and the run's position, attempts,
/// children, controls and mirror writes.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ShowDocument<'a> {
    schema_version: u8,
    command: &'static str,
    outcome: &'static str,
    exit_status: u8,
    run_directory: &'a str,
    run: &'a Value,
    state: &'a Value,
    /// The run record `run.json`, or null for a run without one.
    record: &'a Option<Value>,
    /// The root wait record `wait.json`, or null while the run does not wait.
    wait: Option<&'a WaitRecord>,
    recovery: RecoveryOutput<'a>,
    retry: RetryOutput,
    continuation: ContinuationOutput,
    workspace_modified: Value,
    position: Option<String>,
    attempts: Vec<ShownAttempt<'a>>,
    children: Vec<ShownChild<'a>>,
    controls: Vec<ShownControl<'a>>,
    mirror: Vec<ShownMirror<'a>>,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RecoveryOutput<'a> {
    Active,
    Settled,
    Abandoned,
    OwnershipUnproven {
        #[serde(rename = "guardIds")]
        guard_ids: &'a [String],
        reason: &'static str,
    },
}

impl<'a> From<&'a LocalRecoveryStatus> for RecoveryOutput<'a> {
    fn from(recovery: &'a LocalRecoveryStatus) -> Self {
        match recovery {
            LocalRecoveryStatus::Active => Self::Active,
            LocalRecoveryStatus::Settled => Self::Settled,
            LocalRecoveryStatus::Abandoned => Self::Abandoned,
            LocalRecoveryStatus::OwnershipUnproven { guard_ids, reason } => {
                Self::OwnershipUnproven {
                    guard_ids,
                    reason: reason.as_str(),
                }
            }
        }
    }
}

#[derive(Serialize)]
struct RetryOutput {
    eligible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

impl From<LocalRetryEligibility> for RetryOutput {
    fn from(retry: LocalRetryEligibility) -> Self {
        match retry {
            LocalRetryEligibility::Eligible => Self {
                eligible: true,
                reason: None,
            },
            LocalRetryEligibility::Ineligible(reason) => Self {
                eligible: false,
                reason: Some(reason.as_str()),
            },
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContinuationOutput {
    eligible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    request_admission: &'static str,
}

impl From<LocalRetryEligibility> for ContinuationOutput {
    fn from(eligibility: LocalRetryEligibility) -> Self {
        match eligibility {
            LocalRetryEligibility::Eligible => Self {
                eligible: true,
                reason: None,
                request_admission: "not_evaluated",
            },
            LocalRetryEligibility::Ineligible(reason) => Self {
                eligible: false,
                reason: Some(continuation_reason(reason)),
                request_admission: "not_evaluated",
            },
        }
    }
}

/// Why a run cannot be continued: an attempt whose disposition admits no continuation is
/// `continuation_disposition_ineligible`, any other reason the retry's.
const fn continuation_reason(reason: RetryIneligibilityReason) -> &'static str {
    match reason {
        RetryIneligibilityReason::LatestAttemptSucceeded
        | RetryIneligibilityReason::LatestAttemptRejected
        | RetryIneligibilityReason::RunSuperseded => "continuation_disposition_ineligible",
        _ => reason.as_str(),
    }
}

/// The `error` document of a run `show` cannot read.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorOutput<'a> {
    schema_version: u8,
    command: &'static str,
    outcome: &'static str,
    exit_status: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    run_directory: Option<&'a str>,
    error: ErrorDetail<'a>,
}

#[derive(Serialize)]
struct ErrorDetail<'a> {
    code: &'static str,
    message: &'a str,
}

const fn reconciliation_error_code(error: &ArchivedAttemptLoadError) -> &'static str {
    match error {
        ArchivedAttemptLoadError::Operational(error) => operational_error_code(error.code),
        // A concurrent change to the selected attempt invalidated the
        // pending selection between the two stable snapshot reads.
        ArchivedAttemptLoadError::Ineligible(_) => "status_snapshot_unstable",
    }
}

fn write_json(value: &impl Serialize) -> io::Result<()> {
    super::super::super::write_pretty_json(value)
}

#[derive(Serialize)]
struct ShownAttempt<'a> {
    number: u64,
    trigger: &'static str,
    state: &'static str,
    reason: Option<&'a Value>,
    edge: Option<&'a Value>,
    /// The run a successor imported this attempt from, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    imported: Option<&'a Value>,
    result: ShownResult<'a>,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ShownResult<'a> {
    NotPublished { reason: &'static str },
    Published { directory: &'a str },
    PublicationFailed { phase: &'static str },
}

impl<'a> From<&'a LocalStatusResult> for ShownResult<'a> {
    fn from(result: &'a LocalStatusResult) -> Self {
        match result {
            LocalStatusResult::NotPublished { reason } => Self::NotPublished { reason },
            LocalStatusResult::Published { relative_directory } => Self::Published {
                directory: relative_directory,
            },
            LocalStatusResult::PublicationFailed { phase } => Self::PublicationFailed { phase },
        }
    }
}

#[derive(Serialize)]
struct ShownChild<'a> {
    step: &'a str,
    item: Option<u64>,
    ordinal: u64,
    id: &'a str,
    state: &'static str,
    outcome: Option<&'a str>,
    directory: &'a Path,
    progress: Option<ShownProgress<'a>>,
    /// A nested run's edge counts; absent for a plain stage's child.
    #[serde(skip_serializing_if = "Option::is_none")]
    edges: Option<&'a BTreeMap<String, u64>>,
    /// A nested run's own children; absent for a plain stage's child.
    #[serde(skip_serializing_if = "Option::is_none")]
    children: Option<Vec<ShownChild<'a>>>,
}

/// A running child's progress: the recorded start times, never an elapsed time.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ShownProgress<'a> {
    attempt: u64,
    state: &'static str,
    started_at: Option<&'a str>,
    recovery: &'static str,
    steps: Vec<ShownNode<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ShownNode<'a> {
    id: &'a str,
    role: &'a str,
    state: &'a str,
    started_at: Option<&'a str>,
}

#[derive(Serialize)]
struct ShownControl<'a> {
    ordinal: u64,
    event: &'a str,
    by: &'a str,
    at: &'a str,
    wait: Option<&'a str>,
    payload: Option<&'a Map<String, Value>>,
}

/// A mirror write with the ordinal of its file name.
#[derive(Serialize)]
struct ShownMirror<'a> {
    ordinal: u64,
    #[serde(flatten)]
    write: &'a MirrorWrite,
}

fn document(shown: &Shown) -> io::Result<ShowDocument<'_>> {
    let snapshot = &shown.snapshot;
    Ok(ShowDocument {
        schema_version: 1,
        command: COMMAND,
        outcome: "shown",
        exit_status: ExitCode::Success.as_u8(),
        run_directory: snapshot
            .run_directory
            .to_str()
            .ok_or_else(|| io::Error::other("normalized run path is not UTF-8"))?,
        run: &snapshot.run,
        state: &snapshot.state,
        record: &snapshot.record,
        wait: snapshot.wait.as_ref(),
        recovery: RecoveryOutput::from(&snapshot.recovery),
        retry: snapshot.retry.into(),
        continuation: snapshot.continuation.into(),
        workspace_modified: snapshot.status_state.workspace_modified()?,
        position: shown
            .record
            .as_ref()
            .and_then(|record| position(record, snapshot.wait.as_ref())),
        attempts: shown
            .attempts
            .iter()
            .map(|shown| ShownAttempt {
                number: shown.attempt.attempt_number,
                trigger: shown.attempt.trigger,
                state: shown.attempt.state,
                reason: shown.reason.as_ref(),
                edge: shown.edge.as_ref(),
                imported: shown.imported.as_ref(),
                result: (&shown.attempt.result).into(),
            })
            .collect(),
        children: shown.children.iter().map(shown_child).collect(),
        controls: shown
            .controls
            .iter()
            .map(|(ordinal, control)| ShownControl {
                ordinal: *ordinal,
                event: &control.event,
                by: &control.by,
                at: &control.at,
                wait: control.wait.as_deref(),
                payload: control.payload.as_ref(),
            })
            .collect(),
        mirror: shown
            .mirror
            .iter()
            .map(|(ordinal, write)| ShownMirror {
                ordinal: *ordinal,
                write,
            })
            .collect(),
    })
}

fn shown_child(child: &Child) -> ShownChild<'_> {
    let Child {
        run,
        progress,
        nested,
    } = child;
    ShownChild {
        step: &run.step,
        item: run.item,
        ordinal: run.ordinal,
        id: &run.record.id,
        state: state_name(run.record.state),
        outcome: run.record.outcome.as_deref(),
        directory: &run.directory,
        progress: progress.as_ref().map(shown_progress),
        edges: nested.as_ref().map(|_| &run.record.edges),
        children: nested
            .as_ref()
            .map(|nested| nested.iter().map(shown_child).collect()),
    }
}

fn started_at(start: Option<&LocalStatusStart>) -> Option<&str> {
    start.map(|start| start.at.as_str())
}

fn shown_progress(child: &ChildProgress) -> ShownProgress<'_> {
    ShownProgress {
        attempt: child.attempt,
        state: child.state,
        started_at: started_at(child.progress.started.as_ref()),
        recovery: child.recovery,
        steps: child
            .progress
            .nodes
            .iter()
            .map(|node| ShownNode {
                id: &node.id,
                role: &node.role,
                state: &node.state,
                started_at: started_at(node.started.as_ref()),
            })
            .collect(),
    }
}

/// The time since a recorded start, `-` when the state records none.
fn elapsed_text(start: Option<&LocalStatusStart>) -> String {
    start.map_or_else(|| "-".to_owned(), |start| human_duration(start.elapsed))
}

fn text(value: &str) -> String {
    normalize_terminal_scalar(value.as_bytes())
}

fn compact(value: &impl Serialize) -> String {
    serde_json::to_string(value).map_or_else(|_| "-".to_owned(), |value| text(&value))
}

/// The edge an attempt took as `<step>.<outcome> -> <target>`, `(counted)` when it counted
/// against the edge's limit, or its JSON when it has another shape.
fn edge_text(edge: &Value) -> String {
    match (
        edge["step"].as_str(),
        edge["outcome"].as_str(),
        edge["target"].as_str(),
    ) {
        (Some(step), Some(outcome), Some(target)) => format!(
            "{}.{} -> {}{}",
            text(step),
            text(outcome),
            text(target),
            if edge["counted"] == true {
                " (counted)"
            } else {
                ""
            }
        ),
        _ => compact(edge),
    }
}

/// A mirror write as `<hook> · comment <body>|state <value> · <result>`, the result
/// `written`, `skipped <reason>` or `failed <code>`; a state whose bound value could not be
/// read is `-`.
fn mirror_text(write: &MirrorWrite) -> String {
    let action = match &write.action {
        MirrorAction::Comment { body } => format!("comment {}", text(body)),
        MirrorAction::State { state, .. } => format!("state {}", or_dash(state.as_deref())),
    };
    let result = match write.outcome {
        MirrorWriteOutcome::Written => "written".to_owned(),
        MirrorWriteOutcome::Skipped => match write.reason {
            Some(MirrorSkipReason::GuardHeld) => "skipped guard_held".to_owned(),
            Some(MirrorSkipReason::StartAnnounced) => "skipped start_announced".to_owned(),
            None => "skipped -".to_owned(),
        },
        MirrorWriteOutcome::Failed => format!("failed {}", or_dash(write.code.as_deref())),
    };
    format!("{} · {action} · {result}", write.hook.as_str())
}

/// The run's edge counts as `<step>.<outcome>=<n>`, or `-` when it took none.
fn edges_text(record: &WorkflowRunRecord) -> String {
    if record.edges.is_empty() {
        return "-".to_owned();
    }
    record
        .edges
        .iter()
        .map(|(edge, count)| format!("{}={count}", text(edge)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Each child as a row indented by `indent`, with a running child's progress and a nested
/// run's `edges` counts two further in and its own children four further.
fn write_children(stdout: &mut impl Write, children: &[Child], indent: usize) -> io::Result<()> {
    let pad = " ".repeat(indent);
    for Child {
        run,
        progress,
        nested,
    } in children
    {
        writeln!(
            stdout,
            "{pad}{} {} {:06}  {}  {}  {}  {}",
            text(&run.step),
            run.item
                .map_or_else(|| "-".to_owned(), |item| item.to_string()),
            run.ordinal,
            text(&run.record.id),
            state_name(run.record.state),
            or_dash(run.record.outcome.as_deref()),
            normalize_terminal_path(&run.directory)
        )?;
        if let Some(child) = progress {
            writeln!(
                stdout,
                "{pad}  attempt {} · {} · {}",
                child.attempt,
                child.recovery,
                elapsed_text(child.progress.started.as_ref())
            )?;
            for node in &child.progress.nodes {
                writeln!(
                    stdout,
                    "{pad}  {} · {} · {}",
                    text(&node.id),
                    node.state,
                    elapsed_text(node.started.as_ref())
                )?;
            }
        }
        if let Some(nested) = nested {
            writeln!(stdout, "{pad}  edges: {}", edges_text(&run.record))?;
            write_children(stdout, nested, indent + 4)?;
        }
    }
    Ok(())
}

/// The report: the run record, the current attempt and its recovery, the wait, the
/// attempts, the children, the controls and the mirror writes, each fact once.
fn write_plain(shown: &Shown, color: bool) -> io::Result<()> {
    let snapshot = &shown.snapshot;
    let mut stdout = io::stdout().lock();
    match &shown.record {
        Some(record) => write_record(&mut stdout, record, snapshot)?,
        None => {
            writeln!(
                stdout,
                "directory: {}",
                normalize_terminal_path(&snapshot.run_directory)
            )?;
            writeln!(stdout, "run record: none")?;
        }
    }
    write_current_attempt(&mut stdout, snapshot, color)?;
    write_wait(&mut stdout, snapshot.wait.as_ref(), color)?;
    writeln!(stdout)?;
    writeln!(stdout, "attempts:")?;
    for Attempt {
        attempt,
        reason,
        edge,
        imported,
    } in &shown.attempts
    {
        write!(
            stdout,
            "  {}  {}  {}  {}",
            attempt.attempt_number,
            attempt.trigger,
            styled_state(attempt.state, color),
            styled_result(&attempt.result, color)
        )?;
        if let Some(reason) = reason {
            write!(stdout, "  reason {}", compact(reason))?;
        }
        if let Some(edge) = edge {
            write!(stdout, "  edge {}", edge_text(edge))?;
        }
        if let Some(run) = imported
            .as_ref()
            .and_then(|imported| imported["run"].as_str())
        {
            write!(stdout, "  imported from {}", text(run))?;
        }
        writeln!(stdout)?;
    }
    writeln!(stdout)?;
    writeln!(stdout, "children:")?;
    write_children(&mut stdout, &shown.children, 2)?;
    writeln!(stdout)?;
    writeln!(stdout, "controls:")?;
    for (ordinal, control) in &shown.controls {
        write!(
            stdout,
            "  {ordinal:04}  {}  by {}  at {}  wait {}",
            text(&control.event),
            text(&control.by),
            text(&control.at),
            or_dash(control.wait.as_deref())
        )?;
        if let Some(payload) = &control.payload {
            write!(stdout, "  {}", compact(payload))?;
        }
        writeln!(stdout)?;
    }
    writeln!(stdout)?;
    if shown.mirror.is_empty() {
        writeln!(stdout, "mirror: none")?;
    } else {
        writeln!(stdout, "mirror:")?;
        for (ordinal, write) in &shown.mirror {
            writeln!(stdout, "  {ordinal:04} · {}", mirror_text(write))?;
        }
    }
    stdout.flush()
}

/// The run record's lines, from its ID to its position.
fn write_record(
    stdout: &mut impl Write,
    record: &WorkflowRunRecord,
    snapshot: &LocalRunStatusSnapshot,
) -> io::Result<()> {
    writeln!(stdout, "run: {}", text(&record.id))?;
    writeln!(
        stdout,
        "directory: {}",
        normalize_terminal_path(&snapshot.run_directory)
    )?;
    match (&record.definition, record.revision) {
        (Some(definition), Some(revision)) => {
            writeln!(stdout, "definition: {}@{revision}", text(definition))?;
        }
        _ => writeln!(stdout, "definition: -")?,
    }
    writeln!(stdout, "workflow: {}", text(&record.workflow))?;
    writeln!(stdout, "subject: {}", or_dash(record.subject.as_deref()))?;
    writeln!(stdout, "owner: {}", text(&record.owner))?;
    writeln!(stdout, "state: {}", state_name(record.state))?;
    writeln!(stdout, "outcome: {}", or_dash(record.outcome.as_deref()))?;
    writeln!(stdout, "started: {}", text(&record.started_at))?;
    writeln!(stdout, "attempts: {}", record.attempts)?;
    writeln!(
        stdout,
        "predecessor: {}",
        or_dash(record.predecessor.as_deref())
    )?;
    writeln!(
        stdout,
        "successor: {}",
        or_dash(record.successor.as_deref())
    )?;
    writeln!(stdout, "edges: {}", edges_text(record))?;
    writeln!(
        stdout,
        "position: {}",
        or_dash(position(record, snapshot.wait.as_ref()).as_deref())
    )
}

/// The current attempt's number and state, its result, recovery, retry and continuation
/// eligibility, whether the workspace was modified, each step's recovery and, while ownership
/// is unproven, its reason, remedy and guards.
fn write_current_attempt(
    stdout: &mut impl Write,
    snapshot: &LocalRunStatusSnapshot,
    color: bool,
) -> io::Result<()> {
    writeln!(
        stdout,
        "attempt: {} · {}",
        snapshot.current_attempt_number,
        styled_state(snapshot.current_attempt_state, color)
    )?;
    writeln!(
        stdout,
        "result: {}",
        styled_result(&snapshot.current_result, color)
    )?;
    writeln!(
        stdout,
        "recovery: {}",
        styled_recovery(&snapshot.recovery, color)
    )?;
    writeln!(stdout, "retry: {}", styled_retry(snapshot.retry, color))?;
    let continuation = match snapshot.continuation {
        LocalRetryEligibility::Ineligible(
            reason @ (RetryIneligibilityReason::LatestAttemptSucceeded
            | RetryIneligibilityReason::LatestAttemptRejected
            | RetryIneligibilityReason::RunSuperseded),
        ) => styled(
            &format!("ineligible ({})", continuation_reason(reason)),
            STYLE_BLOCKED,
            color,
        ),
        other => styled_retry(other, color),
    };
    writeln!(stdout, "continuation (base eligibility): {continuation}")?;
    writeln!(
        stdout,
        "workspace modified: {}",
        snapshot.status_state.workspace_modified()?
    )?;
    let archived_result = if matches!(
        &snapshot.current_result,
        LocalStatusResult::Published { .. }
    ) {
        load_local_archived_attempt(&snapshot.run_directory, None)
            .ok()
            .map(|loaded| loaded.result)
    } else {
        None
    };
    snapshot
        .status_state
        .write_recovery(stdout, archived_result.as_ref())?;
    // The sources the current attempt's steps took.
    snapshot.status_state.write_input_sources(stdout)?;
    // The classified failures of the current attempt's steps.
    snapshot.status_state.write_failure_classes(stdout)?;
    if let LocalRecoveryStatus::OwnershipUnproven { guard_ids, reason } = &snapshot.recovery {
        writeln!(stdout, "ownership reason: {}", reason.as_str())?;
        writeln!(stdout, "remedy: {}", reason.remedy())?;
        let guard_ids = guard_ids
            .iter()
            .map(|id| normalize_terminal_scalar(id.as_bytes()))
            .collect::<Vec<_>>();
        writeln!(stdout, "guard ids: {}", guard_ids.join(", "))?;
    }
    Ok(())
}

/// The wait the run is in; for a wait for repair, directly under it, the failed stage it waits
/// at by the wait's full path; then its rule and payload.
fn write_wait(stdout: &mut impl Write, wait: Option<&WaitRecord>, color: bool) -> io::Result<()> {
    let Some(wait) = wait else {
        return writeln!(stdout, "wait: none");
    };
    let step = wait.step_path();
    writeln!(
        stdout,
        "wait: {} at step {} since {}",
        styled(&text(wait.kind_name()), STYLE_BLOCKED, color),
        text(&step),
        text(&wait.since)
    )?;
    if let Some(failed_child) = wait.failed_child() {
        writeln!(
            stdout,
            "{} {} · {}",
            styled("failed stage:", STYLE_FAILURE, color),
            text(&step),
            failed_child_detail(&step, &failed_child)
        )?;
    }
    writeln!(stdout, "  rule: {}", compact(&wait.rule))?;
    writeln!(stdout, "  payload: {}", compact(&wait.payload))
}

fn styled_state(state: &str, color: bool) -> String {
    let shown = if state == "workflow_failed" {
        "failed"
    } else {
        state
    };
    let style = match state {
        "created" | "running" | "cancelling" | "continued" => STYLE_ACTIVE,
        "succeeded" => STYLE_SUCCESS,
        "cancelled" | "waiting" => STYLE_BLOCKED,
        _ => STYLE_FAILURE,
    };
    styled(shown, style, color)
}

fn styled_result(result: &LocalStatusResult, color: bool) -> String {
    match result {
        LocalStatusResult::NotPublished { reason } => {
            styled(&format!("not_published ({reason})"), STYLE_BLOCKED, color)
        }
        LocalStatusResult::Published { relative_directory } => format!(
            "{} ({})",
            styled("published", STYLE_SUCCESS, color),
            text(relative_directory)
        ),
        LocalStatusResult::PublicationFailed { phase } => styled(
            &format!("publication_failed ({phase})"),
            STYLE_FAILURE,
            color,
        ),
    }
}

fn styled_recovery(recovery: &LocalRecoveryStatus, color: bool) -> String {
    let style = match recovery {
        LocalRecoveryStatus::Active => STYLE_ACTIVE,
        LocalRecoveryStatus::Settled => STYLE_SUCCESS,
        LocalRecoveryStatus::Abandoned => STYLE_BLOCKED,
        LocalRecoveryStatus::OwnershipUnproven { .. } => STYLE_FAILURE,
    };
    styled(recovery.as_str(), style, color)
}

fn styled_retry(retry: LocalRetryEligibility, color: bool) -> String {
    match retry {
        LocalRetryEligibility::Eligible => styled("eligible", STYLE_SUCCESS, color),
        LocalRetryEligibility::Ineligible(reason) => styled(
            &format!("ineligible ({})", reason.as_str()),
            retry_reason_style(reason),
            color,
        ),
    }
}

const fn retry_reason_style(reason: RetryIneligibilityReason) -> &'static str {
    match reason {
        RetryIneligibilityReason::RunLocked => STYLE_ACTIVE,
        RetryIneligibilityReason::LatestAttemptSucceeded => STYLE_SUCCESS,
        RetryIneligibilityReason::LatestAttemptRejected
        | RetryIneligibilityReason::OwnershipUnproven => STYLE_FAILURE,
        RetryIneligibilityReason::RunSuperseded => STYLE_BLOCKED,
    }
}
