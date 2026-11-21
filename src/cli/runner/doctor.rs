use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, anyhow};
use clap::Args;
use serde::Serialize;

use crate::exit_code::ExitCode;
use useful_runner::{AgentLoginProvider, CheckResult, Report, Status, built_in_registry};
use useful_support::{Availability, CredentialStatus, NextAction};

pub(super) const ABOUT: &str = "Check local runner prerequisites";
const COMMAND_NAME: &str = "useful runner doctor";

// What a workflow needs is `useful workflow doctor` (REQ-CREDREADY-1); this command checks the
// host alone and makes no request, so it takes no authentication or HTTP option
// (REQ-RUNNERENROLL-45). Its report names every check, run or not, so nothing else lists them
// (REQ-RUNNERENROLL-47).
#[derive(Debug, Args)]
pub(super) struct Command {
    #[arg(long = "check", value_name = "ID", help = "Run only the named check")]
    checks: Vec<String>,

    /// Read the runner operator configuration for a selected check that needs it.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(flatten)]
    output: super::super::JsonArgs<super::super::RunnerJson>,
}

impl Command {
    pub(super) fn execute(self) -> super::super::CommandResult {
        let config = super::doctor_operator_config(self.config.as_deref())?;
        let registry = built_in_registry(config).map_err(|error| anyhow!(error))?;
        let report = registry.run(&self.checks).map_err(|error| {
            super::super::CommandFailure::with_exit_code(anyhow!(error), ExitCode::UsageError)
        })?;
        if self.output.json {
            write_json_report(&report)?;
        } else {
            write_human_report(&report).context("write runner doctor report")?;
        }
        Ok(if report.has_failures() {
            ExitCode::GeneralFailure
        } else {
            ExitCode::Success
        })
    }
}

fn write_human_report(report: &Report) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    write_human_report_to(&mut stdout, report)
}

fn write_human_report_to(output: &mut impl Write, report: &Report) -> anyhow::Result<()> {
    writeln!(output, "Useful Machinery runner doctor")?;
    writeln!(output)?;

    for result in &report.results {
        let marker = match result.outcome.status {
            Status::Pass => '✓',
            Status::Fail => '✗',
        };
        writeln!(
            output,
            "{marker} {} · {}",
            result.descriptor.title, result.descriptor.id
        )?;
        writeln!(output, "  {}", result.outcome.message)?;
        if result.outcome.status == Status::Fail {
            writeln!(output, "  code: {}", result.outcome.code)?;
        }
        write_harness_compatibility_details(output, &result.outcome.details)?;
        write_agent_login_details(output, &result.outcome.details)?;
        writeln!(output)?;
    }

    if !report.not_run.is_empty() {
        writeln!(output, "── not run ──")?;
        for descriptor in &report.not_run {
            writeln!(output, "{} · {}", descriptor.title, descriptor.id)?;
            writeln!(output, "  run: {COMMAND_NAME} --check {}", descriptor.id)?;
        }
        writeln!(output)?;
    }

    let summary = report.summary();
    writeln!(output, "── summary ──")?;
    writeln!(output, "passed: {}", summary.passed)?;
    writeln!(output, "failed: {}", summary.failed)?;
    Ok(())
}

fn write_harness_compatibility_details(
    output: &mut impl Write,
    details: &std::collections::BTreeMap<String, String>,
) -> io::Result<()> {
    if !details.contains_key("profile") {
        return Ok(());
    }

    for (key, label) in [
        ("profile", "profile"),
        ("version", "observed version"),
        ("supportedRange", "supported range"),
        ("expectedVersion", "required version"),
        ("qualificationVersion", "qualification version"),
        ("qualification", "qualification"),
    ] {
        if let Some(value) = details.get(key) {
            writeln!(output, "  {label}: {value}")?;
        }
    }
    Ok(())
}

/// Writes each provider's availability and next action, with the step it
/// names, where a result's details carry them (REQ-GRANT-53).
fn write_agent_login_details(
    output: &mut impl Write,
    details: &std::collections::BTreeMap<String, String>,
) -> io::Result<()> {
    for provider in AgentLoginProvider::ALL {
        let provider = provider.as_str();
        let detail = |suffix: &str| details.get(&format!("{provider}_{suffix}"));
        let availability = detail("availability").and_then(|value| {
            Availability::ALL
                .into_iter()
                .find(|availability| availability.as_str() == value)
        });
        let next_action = detail("next_action").and_then(|value| {
            NextAction::ALL
                .into_iter()
                .find(|next_action| next_action.as_str() == value)
        });
        let (Some(availability), Some(next_action)) = (availability, next_action) else {
            continue;
        };
        let status = CredentialStatus {
            availability,
            next_action,
        };
        let step = super::sync::runner_step(status, None);
        writeln!(
            output,
            "  {provider} login: {}",
            status.text(step.as_deref())
        )?;
    }
    Ok(())
}

fn write_json_report(report: &Report) -> anyhow::Result<()> {
    let output = JsonReport::from_report(report);
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer_pretty(&mut stdout, &output)
        .context("write JSON runner doctor report")?;
    writeln!(stdout).context("write runner doctor report")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonReport<'a> {
    schema_version: u8,
    command: &'static str,
    deployment: Option<&'static str>,
    checks: Vec<JsonCheck<'a>>,
    not_run: Vec<JsonNotRun>,
    summary: JsonSummary,
}

impl<'a> JsonReport<'a> {
    fn from_report(report: &'a Report) -> Self {
        let summary = report.summary();
        Self {
            schema_version: 1,
            command: COMMAND_NAME,
            // Local prerequisite checks do not load a Cloud deployment.
            deployment: None,
            checks: report.results.iter().map(JsonCheck::from_result).collect(),
            not_run: report
                .not_run
                .iter()
                .map(|descriptor| JsonNotRun {
                    id: descriptor.id,
                    title: descriptor.title,
                })
                .collect(),
            summary: JsonSummary {
                passed: summary.passed,
                failed: summary.failed,
            },
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonCheck<'a> {
    id: &'static str,
    title: &'static str,
    status: &'static str,
    code: &'static str,
    message: &'a str,
    details: &'a std::collections::BTreeMap<String, String>,
}

impl<'a> JsonCheck<'a> {
    fn from_result(result: &'a CheckResult) -> Self {
        Self {
            id: result.descriptor.id,
            title: result.descriptor.title,
            status: result.outcome.status.as_str(),
            code: result.outcome.code,
            message: &result.outcome.message,
            details: &result.outcome.details,
        }
    }
}

/// A check the run did not select (REQ-RUNNERENROLL-47).
#[derive(Serialize)]
struct JsonNotRun {
    id: &'static str,
    title: &'static str,
}

#[derive(Serialize)]
struct JsonSummary {
    passed: usize,
    failed: usize,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::write_human_report_to;
    use useful_runner::{CheckDescriptor, CheckResult, Outcome, Report, Status};

    fn result(
        id: &'static str,
        title: &'static str,
        details: BTreeMap<String, String>,
    ) -> CheckResult {
        CheckResult {
            descriptor: CheckDescriptor {
                id,
                title,
                default: false,
            },
            outcome: Outcome {
                status: Status::Pass,
                code: "ok",
                message: "Fixture result".to_owned(),
                details,
            },
        }
    }

    // REQ-AGENT-49, REQ-AGENT-68
    #[test]
    fn human_harness_details_render_structured_compatibility_policy() {
        let report = Report {
            results: vec![
                result(
                    "execution.harness.range-fixture",
                    "Range fixture",
                    BTreeMap::from([
                        ("profile".to_owned(), "RangeProfile".to_owned()),
                        ("version".to_owned(), "2.3.5".to_owned()),
                        ("supportedRange".to_owned(), ">=2.3.4 <2.4.0".to_owned()),
                        ("qualificationVersion".to_owned(), "2.3.4".to_owned()),
                        ("qualification".to_owned(), "untested".to_owned()),
                    ]),
                ),
                result(
                    "execution.harness.exact-fixture",
                    "Exact fixture",
                    BTreeMap::from([
                        ("profile".to_owned(), "ExactProfile".to_owned()),
                        ("expectedVersion".to_owned(), "7.8.9".to_owned()),
                    ]),
                ),
                result(
                    "environment.command.fixture",
                    "Environment fixture",
                    BTreeMap::from([("version".to_owned(), "1.2.3".to_owned())]),
                ),
            ],
            not_run: Vec::new(),
        };
        let mut output = Vec::new();

        write_human_report_to(&mut output, &report).unwrap();

        let output = String::from_utf8(output).unwrap();
        for field in [
            "profile: RangeProfile",
            "observed version: 2.3.5",
            "supported range: >=2.3.4 <2.4.0",
            "qualification version: 2.3.4",
            "qualification: untested",
            "profile: ExactProfile",
            "required version: 7.8.9",
        ] {
            assert!(output.lines().any(|line| line.trim() == field), "{field}");
        }
        assert!(!output.contains("observed version: 1.2.3"));
    }
}
