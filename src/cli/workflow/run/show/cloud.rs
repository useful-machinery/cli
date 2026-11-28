//! The read of a Cloud run by `useful workflow run show RUN`: the run the lookup found in the
//! organization in effect, its Slack messages and the automatic Publication its hand-off
//! started. A definition-backed run also lists its controls and, when it holds a subject
//! claim, its trigger deliveries. With `--wait` the run is read every
//! two seconds, each observed state on standard error, until it and its hand-off are final.
//! Nothing under the `useful` home is read or written.

use std::io::{self, Write};
use std::time::Duration;

use anyhow::Context as _;
use serde::Serialize;
use serde_json::Value;
use useful_api::{Publication, Run, RunFailure, RunRead, RunSlackMessage, RunTriggerDelivery};

use super::super::cloud::{failure_diagnostic, wire};
use super::super::cloud_api::observation::{self, ObservationContext};
use super::super::cloud_api::{
    self, CloudSnapshot, RunOptions, reported_field as field, reported_text as text,
    step_path as path, wait_phrase,
};
use super::super::target::{InCloud, Unread};
use super::COMMAND;
use crate::cli::{
    self as cli, CommonArgs, HttpOptions, PrincipalAuthenticationArgs, TerminalObservation,
};
use crate::exit_code::ExitCode;

/// The most deliveries `show` reads, the API's page bound.
const SHOWN_DELIVERIES: u32 = 100;
/// The most controls `show` reads, the API's page bound.
const SHOWN_CONTROLS: u32 = 100;
/// The most Slack messages `show` reads, the API's page bound.
const SHOWN_SLACK_MESSAGES: u32 = 100;
/// The run fields a definition-backed run's read carries and a run by `workflowPath` may
/// leave out; `show` reports an absent one as null.
const OBSERVED_FIELDS: [&str; 6] = [
    "definition",
    "subjectClaim",
    "workflowState",
    "workflowOutcome",
    "workflowProgress",
    "exits",
];
const TIMED_OUT: &str = "The run was not final before the timeout; it continues in Cloud.";
const STOPPED: &str = "Observation stopped; the run continues in Cloud.";
const UNREACHABLE: &str = "Cloud could not be reached twice in a row; observation stopped and the run continues in Cloud.";

/// Reads `cloud` once, or with `wait` until it is final, and prints it: `json` the document,
/// otherwise the report.
pub(super) fn show(
    cloud: InCloud,
    authentication: PrincipalAuthenticationArgs,
    http: HttpOptions,
    wait: Option<Option<Duration>>,
    json: bool,
) -> cli::CommandResult {
    let options = CommonArgs::new(json, authentication, http);
    if let Some(timeout) = wait {
        return follow(cloud, options, timeout);
    }
    let report = Report::of(&cloud, json);
    let read = cloud.first_read(&options.authentication, &options.http, |api| {
        api.get(&cloud.organization, &cloud.run_id)
    })?;
    let exit = match read {
        Ok(RunRead::Materialized(run)) => {
            let publication = match publication(&cloud, &options, &run) {
                Ok(publication) => publication,
                Err(failure) => return Ok(report.refused(&failure)?),
            };
            let listings = listings(&cloud, &options, &run)?;
            report.shown(&run, publication.as_ref(), listings)
        }
        Ok(RunRead::Pending(_)) => report.pending(),
        Err(Unread::Missed(miss)) => return super::write_missed(miss, json),
        Err(Unread::Failed(failure)) => report.refused(&failure),
    };
    Ok(exit?)
}

/// Reads the run until it is final, then its listings, and prints it as `show` prints it; a
/// timeout, a signal and Cloud unreachable twice in a row end the observation.
fn follow(cloud: InCloud, options: RunOptions, timeout: Option<Duration>) -> cli::CommandResult {
    let json = options.json;
    let report = Report::of(&cloud, json);
    let (signal_report, timeout_report) = (report.clone(), report.clone());
    cli::execute_mutation_with_signals_and_deferred_timeout(
        "Cloud run show",
        CloudSnapshot::for_run(cloud.run_id.clone()),
        timeout,
        move |control, timeout_start| {
            timeout_start.start();
            let started = useful_support::monotonic_now();
            let snapshot = control.recovery();
            let result = observation::wait_run(
                ObservationContext {
                    deployment: &cloud.deployment,
                    options: &options,
                    organization: &cloud.organization,
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
            match result {
                Ok(TerminalObservation::Terminal { resource, .. }) => {
                    let Some(run) = resource.run else {
                        return cloud_api::finish_operation(control, || {
                            report.refused(&RunFailure::Protocol {
                                credential_rejected: false,
                            })
                        });
                    };
                    let listings = listings(&cloud, &options, &run)?;
                    cloud_api::finish_operation(control, || {
                        report.shown(&run, resource.publication.as_deref(), listings)
                    })
                }
                Ok(TerminalObservation::TimedOut) => cloud_api::finish_operation(control, || {
                    report.ended(
                        Ending::of("timed_out", "wait_timed_out", TIMED_OUT),
                        ExitCode::GeneralFailure,
                        control.recovery().run.as_deref(),
                    )
                }),
                Ok(TerminalObservation::Stopped) => Ok(ExitCode::GeneralFailure),
                Err(failure) => {
                    let last = control.recovery();
                    if last.run.is_none()
                        && let Some(miss) =
                            cloud.missed_by(&failure, &options.authentication, &options.http)?
                    {
                        return cli::complete_operation(control, || {
                            super::write_missed(miss, json)
                        });
                    }
                    let (code, message, exit) = if matches!(failure, RunFailure::Unreachable(_)) {
                        ("observation_failed", UNREACHABLE, ExitCode::Unavailable)
                    } else {
                        failure_diagnostic(COMMAND, &failure)
                    };
                    cloud_api::finish_operation(control, || {
                        report.ended(
                            Ending::of("refused", code, message),
                            exit,
                            last.run.as_deref(),
                        )
                    })
                }
            }
        },
        move |signal, snapshot| {
            signal_report
                .ended(
                    Ending::of("observation_stopped", "observation_stopped", STOPPED),
                    signal,
                    snapshot.recovery.run.as_deref(),
                )
                .map_err(Into::into)
        },
        move |snapshot| {
            timeout_report
                .ended(
                    Ending::of("timed_out", "wait_timed_out", TIMED_OUT),
                    ExitCode::GeneralFailure,
                    snapshot.recovery.run.as_deref(),
                )
                .map_err(Into::into)
        },
    )
}

/// A read the lookup made that Cloud failed, written as `show` writes any Cloud read it
/// failed: `organization` is the one in effect once it was known.
pub(super) fn write_lookup_failure(
    deployment: &str,
    organization: Option<String>,
    failure: &RunFailure,
    json: bool,
) -> cli::CommandResult {
    Ok(Report {
        deployment: deployment.to_owned(),
        organization,
        run_id: None,
        json,
    }
    .refused(failure)?)
}

/// One page of a listing `show` read and the next page's cursor.
type Page<T> = (Vec<T>, Option<String>);

/// The listings `show` read beside the run; `None` for one it did not read.
struct Listings {
    deliveries: Option<Page<RunTriggerDelivery>>,
    controls: Option<Page<Value>>,
    slack_messages: Option<Page<RunSlackMessage>>,
}

/// The first page of the run's Slack messages. A definition-backed run also has controls
/// and, when it holds a claim, trigger deliveries.
fn listings(
    cloud: &InCloud,
    options: &RunOptions,
    run: &Run,
) -> anyhow::Result<Result<Listings, RunFailure>> {
    let defined = matches!(run.definition, Some(Some(_)));
    let claimed = defined && matches!(run.subject_claim, Some(Some(_)));
    cloud_api::with_api(
        &cloud.deployment,
        options.http.transport_policy(),
        &options.authentication,
        |api| {
            let deliveries = if claimed {
                Some(api.list_trigger_deliveries(
                    &cloud.organization,
                    &cloud.run_id,
                    Some(SHOWN_DELIVERIES),
                    None,
                )?)
            } else {
                None
            };
            let controls = if defined {
                Some(api.list_run_controls(
                    &cloud.organization,
                    &cloud.run_id,
                    Some(SHOWN_CONTROLS),
                    None,
                )?)
            } else {
                None
            };
            let slack_messages = api.list_run_slack_messages(
                &cloud.organization,
                &cloud.run_id,
                Some(SHOWN_SLACK_MESSAGES),
                None,
            )?;
            Ok(Listings {
                deliveries,
                controls,
                slack_messages: Some(slack_messages),
            })
        },
    )
}

/// The automatic Publication the run's hand-off started, when it names one, read as
/// `--wait` reads it.
fn publication(
    cloud: &InCloud,
    options: &RunOptions,
    run: &Run,
) -> Result<Option<Publication>, RunFailure> {
    let Some(publication_id) = run
        .publication
        .as_deref()
        .and_then(|handoff| handoff.publication_id.as_deref())
    else {
        return Ok(None);
    };
    observation::read_publication(
        &cloud.deployment,
        options,
        &cloud.organization,
        &cloud.run_id,
        publication_id,
        None,
    )
    .map(Some)
}

/// A listing's items, if it was read, and whether more remain.
fn paged<T>(page: Option<Page<T>>) -> (Option<Vec<T>>, bool) {
    match page {
        Some((items, cursor)) => (Some(items), cursor.is_some()),
        None => (None, false),
    }
}

/// Where the run executes: `personal` for a run with an owner, `project` otherwise.
const fn on(run: &Run) -> &'static str {
    if matches!(run.owner, Some(Some(_))) {
        "personal"
    } else {
        "project"
    }
}

/// The run as the document carries it: the API's read unchanged, with each observed field
/// a run by `workflowPath` leaves out as null.
fn value(run: &Run) -> anyhow::Result<Value> {
    let mut value = serde_json::to_value(run).context("serialize the Cloud run")?;
    if let Some(fields) = value.as_object_mut() {
        for field in OBSERVED_FIELDS {
            fields.entry(field).or_insert(Value::Null);
        }
    }
    Ok(value)
}

/// How an observation or a read ended without the run: the document's outcome and its one
/// diagnostic.
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

/// The Cloud run's document: the run as Cloud read it, where it executes, the deployment and
/// organization it was read in, its listings, and the diagnostic of a read that ended
/// without it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Document<'a> {
    schema_version: u8,
    command: &'static str,
    outcome: &'static str,
    exit_status: u8,
    on: Option<&'static str>,
    deployment: &'a str,
    organization_ref: Option<&'a str>,
    run_id: Option<&'a str>,
    run: Option<&'a Value>,
    publication: Option<&'a Publication>,
    deliveries: Option<&'a [RunTriggerDelivery]>,
    more_deliveries: bool,
    controls: Option<&'a [Value]>,
    more_controls: bool,
    slack_messages: Option<&'a [RunSlackMessage]>,
    more_slack_messages: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostics: Option<[Diagnostic; 1]>,
}

#[derive(Serialize)]
struct Diagnostic {
    code: &'static str,
    message: &'static str,
}

/// What `show` prints of one Cloud run: the deployment, organization and run it read, and
/// whether as the document.
#[derive(Clone)]
struct Report {
    deployment: String,
    organization: Option<String>,
    run_id: Option<String>,
    json: bool,
}

impl Report {
    fn of(cloud: &InCloud, json: bool) -> Self {
        Self {
            deployment: cloud.deployment.fingerprint().api_url().to_owned(),
            organization: Some(cloud.organization.clone()),
            run_id: Some(cloud.run_id.clone()),
            json,
        }
    }

    fn document<'a>(&'a self, outcome: &'static str, exit: ExitCode) -> Document<'a> {
        Document {
            schema_version: 1,
            command: COMMAND,
            outcome,
            exit_status: exit.as_u8(),
            on: None,
            deployment: &self.deployment,
            organization_ref: self.organization.as_deref(),
            run_id: self.run_id.as_deref(),
            run: None,
            publication: None,
            deliveries: None,
            more_deliveries: false,
            controls: None,
            more_controls: false,
            slack_messages: None,
            more_slack_messages: false,
            diagnostics: None,
        }
    }

    /// The run, its automatic Publication and its listings, exit 0; a listing Cloud failed is
    /// the read's failure.
    fn shown(
        &self,
        typed: &Run,
        publication: Option<&Publication>,
        listings: Result<Listings, RunFailure>,
    ) -> anyhow::Result<ExitCode> {
        let listings = match listings {
            Ok(listings) => listings,
            Err(failure) => return self.refused(&failure),
        };
        let run = value(typed)?;
        let (deliveries, more_deliveries) = paged(listings.deliveries);
        let (controls, more_controls) = paged(listings.controls);
        let (slack_messages, more_slack_messages) = paged(listings.slack_messages);
        if self.json {
            cli::write_pretty_json(&Document {
                on: Some(on(typed)),
                run: Some(&run),
                publication,
                deliveries: deliveries.as_deref(),
                more_deliveries,
                controls: controls.as_deref(),
                more_controls,
                slack_messages: slack_messages.as_deref(),
                more_slack_messages,
                ..self.document("shown", ExitCode::Success)
            })
        } else {
            write_plain(
                self,
                (typed, &run, publication),
                (deliveries.as_deref(), more_deliveries),
                (controls.as_deref(), more_controls),
                (slack_messages.as_deref(), more_slack_messages),
            )
        }
        .with_context(|| format!("write {COMMAND} output"))?;
        Ok(ExitCode::Success)
    }

    /// A run whose creation Cloud has accepted but not yet materialized.
    fn pending(&self) -> anyhow::Result<ExitCode> {
        if self.json {
            cli::write_pretty_json(&self.document("pending", ExitCode::Success))
        } else {
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "run: {}", self.named(self.run_id.as_ref()))
                .and_then(|()| {
                    writeln!(
                        stdout,
                        "organization: {}",
                        self.named(self.organization.as_ref())
                    )
                })
                .and_then(|()| writeln!(stdout, "state: creation pending"))
                .and_then(|()| writeln!(stdout, "deployment: {}", self.deployment))
                .and_then(|()| stdout.flush())
        }
        .with_context(|| format!("write {COMMAND} output"))?;
        Ok(ExitCode::Success)
    }

    /// `value` as the report prints it, `-` when it is not known.
    fn named(&self, value: Option<&String>) -> String {
        value.map_or_else(|| "-".to_owned(), |value| text(value))
    }

    /// A read Cloud failed, under [`failure_diagnostic`].
    fn refused(&self, failure: &RunFailure) -> anyhow::Result<ExitCode> {
        let (code, message, exit) = failure_diagnostic(COMMAND, failure);
        self.ended(Ending::of("refused", code, message), exit, None)
    }

    /// A read or an observation that ended without the run, with the last run read, if any.
    fn ended(
        &self,
        ending: Ending,
        exit: ExitCode,
        last: Option<&Run>,
    ) -> anyhow::Result<ExitCode> {
        let run = last.map(value).transpose()?;
        if self.json {
            cli::write_pretty_json(&Document {
                on: last.map(on),
                run: run.as_ref(),
                diagnostics: Some([Diagnostic {
                    code: ending.code,
                    message: ending.message,
                }]),
                ..self.document(ending.outcome, exit)
            })
        } else {
            let mut stderr = io::stderr().lock();
            writeln!(
                stderr,
                "{COMMAND} {}: {}: {}",
                ending.outcome, ending.code, ending.message
            )
            .and_then(|()| match &run {
                Some(run) => writeln!(stderr, "last observed run state: {}", field(run, "state")),
                None => Ok(()),
            })
            .and_then(|()| stderr.flush())
        }
        .with_context(|| format!("write {COMMAND} output"))?;
        Ok(exit)
    }
}

/// The run as `show` prints it without `--json`: its identity and state, what it is and was
/// asked to run, its owner, route and what it waits for, its definition and claim, workflow
/// outcome, rejection, latest progress, exits with their mirror results, its controls,
/// deliveries and Slack messages, then its sources, inputs, context, cancellation, hand-off, automatic
/// Publication, interruption, continuation, failure, artifact delivery, times, placement,
/// assignment and connection, and its Linear binding, each fact once. Each listing carries
/// the items read and whether more remain. A held claim of an exited
/// run adds what it holds and the release command.
fn write_plain(
    report: &Report,
    read: (&Run, &Value, Option<&Publication>),
    deliveries: (Option<&[RunTriggerDelivery]>, bool),
    controls: (Option<&[Value]>, bool),
    slack_messages: (Option<&[RunSlackMessage]>, bool),
) -> io::Result<()> {
    let mut out = Vec::new();
    write_report(&mut out, report, read, deliveries, controls, slack_messages)
        .map_err(io::Error::other)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&out)?;
    stdout.flush()
}

fn write_report(
    out: &mut Vec<u8>,
    report: &Report,
    (typed, run, publication): (&Run, &Value, Option<&Publication>),
    deliveries: (Option<&[RunTriggerDelivery]>, bool),
    controls: (Option<&[Value]>, bool),
    slack_messages: (Option<&[RunSlackMessage]>, bool),
) -> anyhow::Result<()> {
    writeln!(out, "run: {}", field(run, "id"))?;
    writeln!(
        out,
        "organization: {}",
        report.named(report.organization.as_ref())
    )?;
    writeln!(
        out,
        "display name: {}",
        typed
            .display_name
            .as_deref()
            .map_or_else(|| "none".to_owned(), text)
    )?;
    writeln!(out, "project: {}", text(&typed.project_id))?;
    writeln!(out, "execution spec: {}", text(&typed.execution_spec_id))?;
    writeln!(out, "state: {}", field(run, "state"))?;
    cloud_api::write_workflow_state(out, typed)?;
    writeln!(out, "workflow outcome: {}", field(run, "workflowOutcome"))?;
    cloud_api::write_run_attempt(out, typed)?;
    cloud_api::write_route(out, typed)?;
    if let Some(observation) = typed.observation.as_deref() {
        cloud_api::write_waiting(out, observation)?;
        cloud_api::write_held_with(out, observation)?;
    }
    let definition = &run["definition"];
    if definition.is_object() {
        writeln!(
            out,
            "definition: {} revision {}",
            field(definition, "definitionId"),
            definition["revision"]
        )?;
        writeln!(out, "tree: {}", field(definition, "treeDigest"))?;
        writeln!(out, "workflow: {}", field(definition, "workflowPath"))?;
    } else {
        writeln!(out, "definition: none")?;
    }
    write_claim(out, report, run)?;
    cloud_api::write_rejection(out, typed)?;
    write_progress(out, &run["workflowProgress"])?;
    write_exits(out, &run["exits"])?;
    write_controls(out, controls.0, controls.1)?;
    write_deliveries(out, deliveries.0, deliveries.1)?;
    write_slack_messages(out, slack_messages.0, slack_messages.1)?;
    cloud_api::write_run_sources_through_continuation(out, typed)?;
    cloud_api::write_automatic_publication(out, Some(typed), publication)?;
    cloud_api::write_run_failure(out, typed)?;
    cloud_api::write_run_delivery_and_times(out, typed)?;
    cloud_api::write_run_observation(out, typed, false)?;
    cloud_api::write_run_linear_lifecycle(out, typed)?;
    writeln!(out, "deployment: {}", report.deployment)?;
    Ok(())
}

/// The run's subject claim, or that it has none; a held claim of an exited run adds what it
/// holds and the command an organization owner releases it with.
fn write_claim(out: &mut impl Write, report: &Report, run: &Value) -> io::Result<()> {
    let claim = &run["subjectClaim"];
    if !claim.is_object() {
        return writeln!(out, "subject claim: none");
    }
    write!(
        out,
        "subject claim: {} · {} · {}",
        field(claim, "claimId"),
        field(claim, "subject"),
        field(claim, "state")
    )?;
    if let Some(cause) = claim["releaseCause"].as_str() {
        write!(out, " ({})", text(cause))?;
    }
    writeln!(out)?;
    if claim["state"] == "held" && run["workflowState"] == "exited" {
        let subject = field(claim, "subject");
        writeln!(
            out,
            "  this exited run still holds the slot of {subject}; a start Cloud refuses for {subject} reads subject-settled and names this run"
        )?;
        writeln!(
            out,
            "  an organization owner releases the claim with: useful workflow run release {}",
            report.named(report.run_id.as_ref()),
        )?;
    }
    Ok(())
}

fn write_progress(out: &mut impl Write, progress: &Value) -> io::Result<()> {
    if !progress.is_object() {
        return writeln!(out, "progress: none");
    }
    write!(
        out,
        "progress: attempt {} at {}",
        progress["attempt"],
        path(&progress["position"])
    )?;
    let wait = &progress["wait"];
    if wait.is_object() {
        write!(out, " · waiting {}", wait_phrase(wait))?;
    } else {
        write!(out, " · running")?;
    }
    writeln!(out, " · reported {}", field(progress, "reportedAt"))?;
    write_failed_stage(out, wait)?;
    if wait["kind"] == "answer" {
        write_questions(out, &wait["questions"])?;
    }
    Ok(())
}

/// The failed stage the runner reported for a wait of any kind, in the order `useful workflow
/// run show` prints a local run's: the stage's path, the outcome, the failing node by its path
/// under the stage with its state, then the phase and the code when each is a string. A null
/// or absent `failedChild` prints nothing, since it never says the stage succeeded.
fn write_failed_stage(out: &mut impl Write, wait: &Value) -> io::Result<()> {
    let failed_child = &wait["failedChild"];
    if !failed_child.is_object() {
        return Ok(());
    }
    let stage = path(&wait["step"]);
    write!(
        out,
        "failed stage: {stage} · child outcome {} · {stage}.{} {}",
        field(failed_child, "outcome"),
        field(&failed_child["node"], "id"),
        field(failed_child, "state")
    )?;
    for key in ["phase", "code"] {
        if let Some(value) = failed_child[key].as_str() {
            write!(out, " · {}", text(value))?;
        }
    }
    writeln!(out)
}

/// An answer wait's questions, one indented line each as `<id>: <text>` or the id alone,
/// `unknown` when Cloud sent null or omitted them and `none` when the wait asks none.
fn write_questions(out: &mut impl Write, questions: &Value) -> io::Result<()> {
    let Some(questions) = questions.as_array() else {
        return writeln!(out, "questions: unknown");
    };
    if questions.is_empty() {
        return writeln!(out, "questions: none");
    }
    writeln!(out, "questions:")?;
    for question in questions {
        write!(out, "  {}", field(question, "id"))?;
        if let Some(question_text) = question["text"].as_str() {
            write!(out, ": {}", text(question_text))?;
        }
        writeln!(out)?;
    }
    Ok(())
}

fn write_exits(out: &mut impl Write, exits: &Value) -> io::Result<()> {
    let Some(exits) = exits.as_array() else {
        return writeln!(out, "exits: none");
    };
    if exits.is_empty() {
        return writeln!(out, "exits: none");
    }
    writeln!(out, "exits:")?;
    for exit in exits {
        writeln!(
            out,
            "  attempt {} · outcome {} · claim release {}",
            exit["attemptNumber"],
            field(exit, "workflowOutcome"),
            if exit["claimRelease"] == true {
                "yes"
            } else {
                "no"
            }
        )?;
        match exit["mirror"].as_array() {
            None => writeln!(out, "    mirror: not attempted")?,
            Some(results) => {
                for result in results {
                    writeln!(out, "    mirror {}", mirror_text(result))?;
                }
            }
        }
    }
    Ok(())
}

/// A mirror result as `<hook> <issue> · comment <body>|state <state> · <outcome>`, with a
/// skip's reason, a failure's code and its diagnostic when present.
fn mirror_text(result: &Value) -> String {
    let action = &result["action"];
    let action = match action["kind"].as_str() {
        Some("comment") => format!("comment {}", field(action, "body")),
        Some("state") => format!("state {}", field(action, "state")),
        _ => "-".to_owned(),
    };
    let mut line = format!(
        "{} {} · {action} · {}",
        field(result, "hook"),
        field(result, "issue"),
        field(result, "outcome")
    );
    for key in ["reason", "code", "diagnostic"] {
        if let Some(value) = result[key].as_str() {
            line.push(' ');
            line.push_str(&text(value));
        }
    }
    line
}

/// The run's controls as Cloud listed them, newest first, one indented line each as
/// `<id> · <kind> · <state> [<actionOutcome>|<code>] · attempt <n> · accepted <time>`.
fn write_controls(out: &mut impl Write, controls: Option<&[Value]>, more: bool) -> io::Result<()> {
    let Some(controls) = controls.filter(|controls| !controls.is_empty()) else {
        return writeln!(out, "controls: none");
    };
    writeln!(out, "controls:")?;
    for control in controls {
        write!(
            out,
            "  {} · {} · {}",
            field(control, "id"),
            field(control, "kind"),
            field(control, "state")
        )?;
        if let Some(settled) = control["actionOutcome"]
            .as_str()
            .or_else(|| control["code"].as_str())
        {
            write!(out, " {}", text(settled))?;
        }
        writeln!(
            out,
            " · attempt {} · accepted {}",
            control["attemptNumber"],
            field(control, "acceptedAt")
        )?;
    }
    if more {
        writeln!(out, "older controls: not shown")?;
    }
    Ok(())
}

fn write_deliveries(
    out: &mut impl Write,
    deliveries: Option<&[RunTriggerDelivery]>,
    more: bool,
) -> io::Result<()> {
    let Some(deliveries) = deliveries.filter(|deliveries| !deliveries.is_empty()) else {
        return writeln!(out, "deliveries: none");
    };
    writeln!(out, "deliveries:")?;
    for delivery in deliveries {
        let event = serde_json::to_value(&delivery.event).unwrap_or(Value::Null);
        write!(
            out,
            "  {} · {} revision {} · {} {} · claim {} · accepted {} · ",
            text(&delivery.id),
            text(&delivery.trigger_name),
            delivery.revision,
            wire(delivery.event_name),
            field(&event["issue"], "identifier"),
            text(&delivery.claim.claim_id),
            text(&delivery.accepted_at)
        )?;
        let state = wire(delivery.state);
        match (&delivery.action, &delivery.reason) {
            (Some(action), _) => write!(out, "{state} {}", wire(action))?,
            (None, Some(reason)) => write!(out, "{state} {}", text(reason))?,
            (None, None) => write!(out, "{state}")?,
        }
        if let Some(delivered) = &delivery.delivered_at {
            write!(out, " · delivered {}", text(delivered))?;
        }
        if let Some(settled) = &delivery.settled_at {
            write!(out, " · settled {}", text(settled))?;
        }
        writeln!(out)?;
    }
    if more {
        writeln!(out, "older deliveries: not shown")?;
    }
    Ok(())
}

fn write_slack_messages(
    out: &mut impl Write,
    messages: Option<&[RunSlackMessage]>,
    more: bool,
) -> io::Result<()> {
    let Some(messages) = messages.filter(|messages| !messages.is_empty()) else {
        return Ok(());
    };
    writeln!(out, "slack messages:")?;
    for message in messages {
        write!(
            out,
            "  {} · attempt {}",
            wire(message.kind),
            message.attempt
        )?;
        if let (Some(step), Some(transition)) = (&message.step, message.transition) {
            write!(out, " · {step} {}", wire(transition))?;
        }
        if let Some(outcome) = message.outcome {
            write!(out, " · outcome {}", wire(outcome))?;
        }
        write!(out, " · {}", wire(message.state))?;
        if let Some(reason) = message.reason {
            write!(out, " {}", wire(reason))?;
        }
        writeln!(out)?;
    }
    if more {
        writeln!(out, "newer slack messages: not shown")?;
    }
    Ok(())
}
