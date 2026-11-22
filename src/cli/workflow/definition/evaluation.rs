//! `useful workflow definition evaluation list` and `show` (REQ-CLOUDDEF-63): a Cloud
//! definition's retained start evaluations (REQ-TRIGGER-132) in evaluation vocabulary 4
//! (REQ-TRIGGER-166), listed with the exact `state` and `runId` filters and read one at a
//! time, each with its stored reason, what its event names (a Linear issue, a push's branch
//! and commit, or an ended run with its attempt and outcome) and, when it waited for its
//! issue's blockers, that blocker wait (REQ-TRIGGER-181) and, when it could not read its
//! issue, its diagnostic (REQ-TRIGGER-190). The definition is one of the project in effect,
//! named as REQ-CLOUDDEF-42 states.

use std::io::{self, Write};

use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::Value;

use super::cloud_report::{self as report, Scope};
use super::report::display;
use super::target::{self, InEffect, Leaf, Named, Options};
use super::with_api;
use crate::cli::{CommandResult, PaginationArgs};
use useful_api::{WorkflowDefinitionEvaluation, WorkflowEvaluationFilter};

pub(super) const ABOUT: &str = "List and show a Cloud workflow definition's start evaluations";
const COMMAND_PATH: &[&str] = &["workflow", "definition", "evaluation"];

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<EvaluationCommand>,
}

#[derive(Debug, Subcommand)]
enum EvaluationCommand {
    #[command(about = "List a Cloud workflow definition's start evaluations, newest first")]
    List(List),
    #[command(about = "Show one start evaluation of a Cloud workflow definition")]
    Show(Show),
}

#[derive(Debug, Args)]
struct List {
    #[arg(value_name = target::DEFINITION, help = target::DEFINITION_HELP)]
    definition: Named,
    #[arg(
        long,
        value_parser = [
            "pending",
            "processing",
            "retry_waiting",
            "run_created",
            "not_matched",
            "skipped",
            "skipped_active",
            "stopped",
            "failed",
        ],
        help = "List only evaluations in this state"
    )]
    state: Option<String>,
    #[arg(
        long,
        value_name = "RUN",
        help = "List only the evaluation that created this run"
    )]
    run: Option<String>,
    #[command(flatten)]
    page: PaginationArgs<100>,
    #[command(flatten)]
    in_effect: InEffect,
    #[command(flatten)]
    options: Options,
}

#[derive(Debug, Args)]
struct Show {
    #[arg(value_name = "EVALUATION", help = "Start evaluation ID")]
    evaluation: String,
    // One long option holds one value shape across the tree, and `workflow run list` names its
    // `--definition` value `ID`.
    #[arg(long, value_name = "ID", help = target::DEFINITION_HELP)]
    definition: Named,
    #[command(flatten)]
    in_effect: InEffect,
    #[command(flatten)]
    options: Options,
}

impl Command {
    pub(super) fn execute(self) -> CommandResult {
        match self.command {
            None => super::super::super::print_help(COMMAND_PATH),
            Some(EvaluationCommand::List(list)) => list.execute(),
            Some(EvaluationCommand::Show(show)) => show.execute(),
        }
    }
}

/// The `evaluation` leaf `name`, with whether `--json` was given.
const fn leaf(name: &'static str, command: &'static str, json: bool) -> Leaf {
    Leaf {
        name,
        command,
        refused: "Evaluation refused.",
        json,
    }
}

impl List {
    fn execute(self) -> CommandResult {
        let leaf = leaf(
            "evaluation list",
            "useful workflow definition evaluation list",
            self.options.json,
        );
        if let Err(ended) = target::cloud_only(&self.definition, leaf) {
            return ended;
        }
        let filter = WorkflowEvaluationFilter {
            state: self.state.as_deref(),
            run_id: self.run.as_deref(),
        };
        let page = &self.page;
        target::in_project(
            self.definition,
            self.in_effect,
            self.options,
            leaf,
            |deployment, options, project, definition| {
                let read = with_api(deployment, options, |api| {
                    api.evaluations(
                        &project.organization,
                        &project.project,
                        definition,
                        filter,
                        page.limit.map(i32::from),
                        page.cursor.as_deref(),
                    )
                })?;
                let scope = Scope::of(leaf, Some(project));
                report::finish(&scope, read.as_ref(), |(evaluations, cursor)| {
                    if scope.json {
                        return scope.write(
                            "listed",
                            ListedBody {
                                definition_id: definition,
                                evaluations,
                                next_cursor: cursor.as_deref(),
                            },
                        );
                    }
                    let mut stdout = io::stdout().lock();
                    if evaluations.is_empty() {
                        writeln!(stdout, "No start evaluations.")?;
                    }
                    for evaluation in evaluations {
                        writeln!(stdout, "{}", summary(evaluation))?;
                    }
                    if let Some(cursor) = cursor {
                        writeln!(stdout, "next cursor: {}", display(cursor))?;
                    }
                    Ok(())
                })
            },
        )
    }
}

impl Show {
    fn execute(self) -> CommandResult {
        let leaf = leaf(
            "evaluation show",
            "useful workflow definition evaluation show",
            self.options.json,
        );
        if let Err(ended) = target::cloud_only(&self.definition, leaf) {
            return ended;
        }
        let id = self.evaluation.as_str();
        target::in_project(
            self.definition,
            self.in_effect,
            self.options,
            leaf,
            |deployment, options, project, definition| {
                let read = with_api(deployment, options, |api| {
                    api.evaluation(&project.organization, &project.project, definition, id)
                })?;
                let scope = Scope::of(leaf, Some(project));
                report::finish(&scope, read.as_ref(), |evaluation| {
                    if scope.json {
                        return scope.write(
                            "shown",
                            ShownBody {
                                definition_id: definition,
                                evaluation,
                            },
                        );
                    }
                    write_evaluation(&mut io::stdout().lock(), evaluation)?;
                    Ok(())
                })
            },
        )
    }
}

/// One evaluation on a line in vocabulary 4: id, state with its reason, trigger, revision,
/// event, run, the run blocking it and, when Cloud observed them, its project's readiness
/// blockers, its blocker wait and its diagnostic.
fn summary(evaluation: &WorkflowDefinitionEvaluation) -> String {
    let line = format!(
        "{} · {} · reason {} · trigger {} · revision {} · {} {} · accepted {} · run {} · blocking run {}",
        display(&evaluation.id),
        report::wire(evaluation.state),
        or_dash(evaluation.reason.as_deref()),
        display(&evaluation.trigger_name),
        evaluation.revision,
        report::wire(evaluation.event_name),
        event_subject(evaluation),
        display(&evaluation.accepted_at),
        or_dash(evaluation.run_id.as_deref()),
        or_dash(evaluation.blocking_run_id.as_deref()),
    );
    let line = match project_blockers(evaluation) {
        Some(blockers) => format!("{line} · project blockers {blockers}"),
        None => line,
    };
    let line = match blocker_wait(evaluation) {
        Some(wait) => format!("{line} · blocker wait {wait}"),
        None => line,
    };
    match diagnostic(evaluation) {
        Some(facts) => format!("{line} · diagnostic {facts}"),
        None => line,
    }
}

fn write_evaluation(
    out: &mut impl Write,
    evaluation: &WorkflowDefinitionEvaluation,
) -> io::Result<()> {
    writeln!(out, "evaluation: {}", display(&evaluation.id))?;
    writeln!(out, "definition: {}", display(&evaluation.definition_id))?;
    writeln!(out, "revision: {}", evaluation.revision)?;
    writeln!(out, "trigger: {}", display(&evaluation.trigger_name))?;
    writeln!(
        out,
        "event: {} {}",
        report::wire(evaluation.event_name),
        event_subject(evaluation)
    )?;
    writeln!(
        out,
        "connection: {}",
        or_dash(evaluation.connection_id.as_deref())
    )?;
    writeln!(
        out,
        "execution principal: {}",
        display(&evaluation.execution_principal_id)
    )?;
    writeln!(out, "state: {}", report::wire(evaluation.state))?;
    writeln!(out, "reason: {}", or_dash(evaluation.reason.as_deref()))?;
    writeln!(out, "run: {}", or_dash(evaluation.run_id.as_deref()))?;
    writeln!(
        out,
        "blocking run: {}",
        or_dash(evaluation.blocking_run_id.as_deref())
    )?;
    writeln!(
        out,
        "project blockers: {}",
        project_blockers(evaluation).unwrap_or_else(|| "-".to_owned())
    )?;
    writeln!(
        out,
        "blocker wait: {}",
        blocker_wait(evaluation).unwrap_or_else(|| "-".to_owned())
    )?;
    writeln!(
        out,
        "diagnostic: {}",
        diagnostic(evaluation).unwrap_or_else(|| "-".to_owned())
    )?;
    writeln!(
        out,
        "cycle: {} · attempt {} · started {} · deadline {}",
        evaluation.cycle_number,
        evaluation.attempt_number,
        display(&evaluation.cycle_started_at),
        display(&evaluation.cycle_deadline)
    )?;
    writeln!(
        out,
        "next attempt: {}",
        or_dash(evaluation.next_attempt_at.as_deref())
    )?;
    writeln!(out, "accepted: {}", display(&evaluation.accepted_at))?;
    writeln!(
        out,
        "settled: {}",
        or_dash(evaluation.settled_at.as_deref())
    )?;
    writeln!(out, "expires: {}", display(&evaluation.expires_at))
}

/// What the evaluation's event names: a push's branch and commit as `<branch> <commit>`, a
/// run's end as `<run id> attempt <n> <outcome>`, a Linear event's issue identifier, `-` for a
/// schedule's event.
fn event_subject(evaluation: &WorkflowDefinitionEvaluation) -> String {
    let event = serde_json::to_value(&evaluation.event).unwrap_or(Value::Null);
    if let (Some(branch), Some(commit)) = (event["branch"].as_str(), event["commit"].as_str()) {
        return format!("{} {}", display(branch), display(commit));
    }
    if let (Some(run), Some(attempt), Some(outcome)) = (
        event["runId"].as_str(),
        event["attempt"].as_i64(),
        event["outcome"].as_str(),
    ) {
        return format!("{} attempt {attempt} {}", display(run), display(outcome));
    }
    or_dash(event["issue"]["identifier"].as_str())
}

/// The readiness blockers Cloud observed on the evaluation's project, joined with `, `;
/// `None` when it observed none (REQ-TRIGGER-164).
fn project_blockers(evaluation: &WorkflowDefinitionEvaluation) -> Option<String> {
    let blockers = &evaluation.observations.as_ref()?.project.as_ref()?.blockers;
    (!blockers.is_empty()).then(|| {
        blockers
            .iter()
            .map(|blocker| display(blocker))
            .collect::<Vec<_>>()
            .join(", ")
    })
}

/// The wait Cloud observed for the evaluation's issue's blockers, as `since <since> · blocked
/// by <blockers>`, each open blocker by its identifier or else its Linear id, `-` when none is
/// open; `None` when the evaluation never waited (REQ-TRIGGER-181).
fn blocker_wait(evaluation: &WorkflowDefinitionEvaluation) -> Option<String> {
    let wait = evaluation.observations.as_ref()?.blocker_wait.as_ref()?;
    let blockers = if wait.blockers.is_empty() {
        "-".to_owned()
    } else {
        wait.blockers
            .iter()
            .map(|blocker| display(blocker.identifier.as_deref().unwrap_or(&blocker.id)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    Some(format!(
        "since {} · blocked by {blockers}",
        display(&wait.since)
    ))
}

/// The safe facts of the failure the evaluation's reason names, each member Cloud returned as
/// `stage <stage>`, `error type <errorType>` and `http status <httpStatus>`, joined with `, `;
/// `None` when Cloud returned no diagnostic or one with no member (REQ-TRIGGER-190,
/// REQ-DIAG-43).
fn diagnostic(evaluation: &WorkflowDefinitionEvaluation) -> Option<String> {
    let diagnostic = evaluation.observations.as_ref()?.diagnostic.as_ref()?;
    let facts = [
        diagnostic
            .stage
            .as_deref()
            .map(|stage| format!("stage {}", display(stage))),
        diagnostic
            .error_type
            .as_deref()
            .map(|error_type| format!("error type {}", display(error_type))),
        diagnostic
            .http_status
            .map(|status| format!("http status {status}")),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    (!facts.is_empty()).then(|| facts.join(", "))
}

fn or_dash(value: Option<&str>) -> String {
    value.map_or_else(|| "-".to_owned(), display)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListedBody<'a> {
    definition_id: &'a str,
    evaluations: &'a [WorkflowDefinitionEvaluation],
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ShownBody<'a> {
    definition_id: &'a str,
    evaluation: &'a WorkflowDefinitionEvaluation,
}
