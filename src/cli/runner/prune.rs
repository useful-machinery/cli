use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, anyhow};
use clap::Args;
use serde::Serialize;

use crate::exit_code::{ExitCode, OutcomeClass};
use useful_runner::{
    ControlError, KeptAnswer, KeptCache, KeptCacheState, KeptReport, KeptRunsBounds, KeptWorkspace,
    KeptWorkspaceState, PruneAnswer, PruneReport, PruneScope, PrunedCache, PrunedDirectory,
    PrunedOutcome, RequestFailure,
};

use super::super::{CommandFailure, CommandResult, JsonArgs, RunnerJson};
use super::show::enum_json;

pub(super) const ABOUT: &str = "Show what Runner Serve keeps on disk and remove it on request";

#[derive(Debug, Args)]
pub(super) struct Command {
    /// Read the control socket path from the closed runner operator
    /// configuration; the runner home under the useful home is the default, read
    /// without creating anything.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    #[arg(
        long,
        help = "Cover every kept run directory not in use and every build cache file, whatever the bounds"
    )]
    all: bool,

    #[arg(long, help = "Confirm this action")]
    yes: bool,

    #[command(flatten)]
    output: JsonArgs<RunnerJson>,
}

impl Command {
    // REQ-RUNNERENROLL-166: the command asks only the live runner, through the control
    // socket its configuration names, and itself changes nothing on the host.
    pub(super) fn execute(self) -> CommandResult {
        let socket_path = super::configured_control_socket_path(self.config.as_deref())?;
        let scope = if self.all {
            PruneScope::All
        } else {
            PruneScope::Bounds
        };
        let mut stdout = io::stdout().lock();
        if self.yes {
            let report = match useful_runner::request_prune(&socket_path, scope) {
                Ok(PruneAnswer::Pruned(report)) => report,
                Ok(PruneAnswer::Refused(error)) => return Err(refusal(error)),
                Err(error) => return Err(request_failure(error)),
            };
            if self.output.json {
                write_document(
                    &mut stdout,
                    &PrunedDocument {
                        schema_version: 1,
                        outcome: "pruned",
                        pruned: &report,
                    },
                )
            } else {
                write_result(&mut stdout, &report, &self.confirmed())
            }
            .context("write prune result")?;
            Ok(result_exit_code(&report))
        } else {
            let report = match useful_runner::request_kept(&socket_path, scope) {
                Ok(KeptAnswer::Kept(report)) => report,
                Ok(KeptAnswer::Refused(error)) => return Err(refusal(error)),
                Err(error) => return Err(request_failure(error)),
            };
            if self.output.json {
                write_document(
                    &mut stdout,
                    &KeptDocument {
                        schema_version: 1,
                        outcome: "kept",
                        kept: &report,
                    },
                )
            } else {
                write_report(&mut stdout, &report, &self.confirmed())
            }
            .context("write kept report")?;
            Ok(ExitCode::Success)
        }
    }

    /// This invocation with `--yes`: the command that removes what a report shows due, or
    /// that runs an unfinished pass again.
    fn confirmed(&self) -> String {
        let mut command = "useful runner prune".to_owned();
        if let Some(config) = &self.config {
            command.push_str(&format!(" --config {}", config.display()));
        }
        if self.all {
            command.push_str(" --all");
        }
        command.push_str(" --yes");
        command
    }
}

fn request_failure(error: RequestFailure) -> CommandFailure {
    let outcome = match error {
        RequestFailure::NotReachable => OutcomeClass::Unreachable,
        RequestFailure::Protocol(_) => OutcomeClass::Protocol,
    };
    CommandFailure::for_outcome(anyhow::Error::new(error), outcome)
}

fn refusal(error: ControlError) -> CommandFailure {
    match error {
        ControlError::RunnerBusy => CommandFailure::with_exit_code(
            anyhow!(
                "Runner Serve removed nothing because a run it holds is working (runner_busy); retry once every run it holds is waiting or has ended"
            ),
            ExitCode::Unavailable,
        ),
        // Only a serving process older than this release refuses the well-formed
        // request this command sends.
        ControlError::InvalidRequest => CommandFailure::new(anyhow!(
            "Runner Serve does not offer pruning (invalid_request); restart the running `useful runner serve` on this release"
        )),
        error => CommandFailure::new(anyhow!(
            "Runner Serve refused the request ({})",
            enum_json(error).unwrap_or_else(|_| "unknown".to_owned())
        )),
    }
}

/// A result exits 1 when any removal failed, else 4 when the pass did not finish, else 0
/// (REQ-RUNNERENROLL-166).
fn result_exit_code(report: &PruneReport) -> ExitCode {
    if failed(report) {
        ExitCode::GeneralFailure
    } else if !report.complete {
        ExitCode::Unavailable
    } else {
        ExitCode::Success
    }
}

fn failed(report: &PruneReport) -> bool {
    report.failed_directories > 0
        || report
            .build_caches
            .iter()
            .any(|cache| cache.failed_files > 0)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeptDocument<'a> {
    schema_version: u8,
    outcome: &'static str,
    kept: &'a KeptReport,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrunedDocument<'a> {
    schema_version: u8,
    outcome: &'static str,
    pruned: &'a PruneReport,
}

/// Prints the decoded answer again as one document.
fn write_document(output: &mut impl Write, document: &impl Serialize) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *output, document)?;
    writeln!(output)
}

/// The kept report: a verdict, the bounds, each workspace with its directories below it,
/// the workspaces omitted, each cache, and, when something is due, the command that
/// removes it.
fn write_report(output: &mut impl Write, report: &KeptReport, confirmed: &str) -> io::Result<()> {
    let workspaces = u64::try_from(report.workspaces.len())
        .unwrap_or(u64::MAX)
        .saturating_add(report.workspaces_omitted);
    writeln!(
        output,
        "Runner Serve keeps {} and {}; a prune would free {}.",
        count(workspaces, "workspace", "workspaces"),
        count(
            u64::try_from(report.build_caches.len()).unwrap_or(u64::MAX),
            "build cache",
            "build caches"
        ),
        format_bytes(report.due_bytes)
    )?;
    writeln!(output, "bounds: {}", format_bounds(&report.kept_runs))?;
    for workspace in &report.workspaces {
        write_workspace(output, workspace)?;
    }
    if report.workspaces_omitted > 0 {
        writeln!(
            output,
            "omitted: {}",
            count(report.workspaces_omitted, "workspace", "workspaces")
        )?;
    }
    for cache in &report.build_caches {
        write_kept_cache(output, cache)?;
    }
    let due = report.due_bytes > 0
        || report
            .workspaces
            .iter()
            .any(|workspace| workspace.state == KeptWorkspaceState::Due);
    if due {
        writeln!(output)?;
        writeln!(output, "Remove what is due now:")?;
        writeln!(output, "  {confirmed}")?;
    }
    Ok(())
}

fn format_bounds(bounds: &KeptRunsBounds) -> String {
    let age = bounds
        .maximum_age_days
        .map_or_else(|| "none".to_owned(), |days| count(days, "day", "days"));
    let total = bounds
        .maximum_total_bytes
        .map_or_else(|| "none".to_owned(), format_bytes);
    format!("age {age} · total {total}")
}

fn write_workspace(output: &mut impl Write, workspace: &KeptWorkspace) -> io::Result<()> {
    let run = workspace.run_id.as_deref().unwrap_or("run unknown");
    let size = match (workspace.bytes, workspace.state) {
        (Some(bytes), _) => format_bytes(bytes),
        (None, KeptWorkspaceState::InUse) => "in use".to_owned(),
        (None, _) => "unknown".to_owned(),
    };
    let state = match workspace.bound {
        Some(bound) => format!("{} ({})", enum_json(workspace.state)?, enum_json(bound)?),
        None => enum_json(workspace.state)?,
    };
    writeln!(
        output,
        "workspace: {run} · reason: {} · age: {} · size: {size} · state: {state}",
        enum_json(workspace.reason)?,
        format_age(workspace.age_seconds),
    )?;
    for directory in &workspace.directories {
        writeln!(output, "  {directory}")?;
    }
    Ok(())
}

fn write_kept_cache(output: &mut impl Write, cache: &KeptCache) -> io::Result<()> {
    match (cache.state, cache.bytes) {
        (KeptCacheState::Measured, Some(bytes)) => {
            let due = cache
                .due_bytes
                .filter(|due| *due > 0)
                .map(|due| format!(" · due: {}", format_bytes(due)))
                .unwrap_or_default();
            writeln!(
                output,
                "cache: {} · size: {} of {}{due}",
                cache.path,
                format_bytes(bytes),
                format_bytes(cache.maximum_bytes)
            )
        }
        (state, _) => writeln!(
            output,
            "cache: {} · bound: {} · state: {}",
            cache.path,
            format_bytes(cache.maximum_bytes),
            enum_json(state)?
        ),
    }
}

/// The prune result: a verdict, each directory, the directories omitted, each cache, and
/// a remedy for a failed removal or an unfinished pass.
fn write_result(output: &mut impl Write, report: &PruneReport, confirmed: &str) -> io::Result<()> {
    let listed = u64::try_from(report.directories.len()).unwrap_or(u64::MAX);
    let removed_directories = listed
        .saturating_add(report.directories_omitted)
        .saturating_sub(report.failed_directories);
    let removed_files = report.build_caches.iter().fold(0_u64, |files, cache| {
        files.saturating_add(cache.removed_files)
    });
    let removed = format!(
        "removed {} and {}, {}",
        count(removed_directories, "run directory", "run directories"),
        count(removed_files, "cache file", "cache files"),
        format_bytes(report.removed_bytes)
    );
    let failed = failed(report);
    if failed {
        writeln!(output, "✗ Runner Serve {removed}; some removals failed.")?;
    } else if !report.complete {
        writeln!(
            output,
            "! Runner Serve {removed}; the pass stopped before it finished."
        )?;
    } else {
        writeln!(output, "✓ Runner Serve {removed}.")?;
    }
    for directory in &report.directories {
        write_pruned_directory(output, directory)?;
    }
    if report.directories_omitted > 0 {
        writeln!(
            output,
            "omitted: {}",
            count(
                report.directories_omitted,
                "run directory",
                "run directories"
            )
        )?;
    }
    for cache in &report.build_caches {
        write_pruned_cache(output, cache)?;
    }
    if failed || !report.complete {
        writeln!(output)?;
    }
    if failed {
        writeln!(
            output,
            "Remove what is left by hand once the runner is stopped."
        )?;
    }
    if !report.complete {
        writeln!(
            output,
            "Run it again once every run the runner holds is waiting or has ended:"
        )?;
        writeln!(output, "  {confirmed}")?;
    }
    Ok(())
}

fn write_pruned_directory(output: &mut impl Write, directory: &PrunedDirectory) -> io::Result<()> {
    let outcome = match directory.result {
        PrunedOutcome::Removed => "removed",
        PrunedOutcome::Failed => "failed",
    };
    writeln!(
        output,
        "directory: {} · {} · size: {} · bound: {} · {outcome}",
        directory.path,
        directory.run_id.as_deref().unwrap_or("run unknown"),
        format_bytes(directory.bytes),
        enum_json(directory.bound)?
    )
}

fn write_pruned_cache(output: &mut impl Write, cache: &PrunedCache) -> io::Result<()> {
    writeln!(
        output,
        "cache: {} · removed: {}, {} · left: {} · failed: {}",
        cache.path,
        count(cache.removed_files, "file", "files"),
        format_bytes(cache.removed_bytes),
        format_bytes(cache.bytes),
        count(cache.failed_files, "file", "files")
    )
}

fn count(value: u64, one: &str, many: &str) -> String {
    if value == 1 {
        format!("1 {one}")
    } else {
        format!("{value} {many}")
    }
}

/// Bytes in binary units with one decimal, `8.2 GiB`, or whole bytes below one KiB.
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if bytes < 1_024 {
        return format!("{bytes} B");
    }
    let bytes = u128::from(bytes);
    let mut unit = 1_u128;
    let mut tenths = 0;
    for (index, name) in UNITS.iter().enumerate() {
        unit *= 1_024;
        tenths = (bytes * 10 + unit / 2) / unit;
        // A value that rounds up to 1024 of this unit reads as 1.0 of the next.
        if tenths < 10_240 || index + 1 == UNITS.len() {
            return format!("{}.{} {name}", tenths / 10, tenths % 10);
        }
    }
    format!("{}.{} EiB", tenths / 10, tenths % 10)
}

/// An age in its largest whole unit, `16 days`.
fn format_age(seconds: u64) -> String {
    match seconds {
        86_400.. => count(seconds / 86_400, "day", "days"),
        3_600.. => count(seconds / 3_600, "hour", "hours"),
        60.. => count(seconds / 60, "minute", "minutes"),
        _ => count(seconds, "second", "seconds"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_read_in_binary_units_with_one_decimal() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1_023), "1023 B");
        assert_eq!(format_bytes(1_024), "1.0 KiB");
        assert_eq!(format_bytes(8_804_682_956), "8.2 GiB");
        assert_eq!(format_bytes(53_687_091_200), "50.0 GiB");
        // Just under a MiB rounds to the next unit rather than to 1024.0 KiB.
        assert_eq!(format_bytes(1_048_575), "1.0 MiB");
        assert_eq!(format_bytes(u64::MAX), "16.0 EiB");
    }

    #[test]
    fn ages_read_in_their_largest_whole_unit() {
        assert_eq!(format_age(0), "0 seconds");
        assert_eq!(format_age(59), "59 seconds");
        assert_eq!(format_age(3_600), "1 hour");
        assert_eq!(format_age(7_199), "1 hour");
        assert_eq!(format_age(1_382_400), "16 days");
    }

    fn report(complete: bool, failed_directories: u64, failed_files: u64) -> PruneReport {
        PruneReport {
            all: false,
            complete,
            directories: Vec::new(),
            directories_omitted: 0,
            failed_directories,
            build_caches: vec![PrunedCache {
                path: "/srv/cache".to_owned(),
                maximum_bytes: 1_024,
                removed_files: 0,
                removed_bytes: 0,
                failed_files,
                bytes: 0,
            }],
            removed_bytes: 0,
        }
    }

    // REQ-RUNNERENROLL-166: a failed removal outranks an unfinished pass.
    #[test]
    fn a_result_exits_1_on_any_failure_before_4_for_an_unfinished_pass() {
        assert_eq!(
            result_exit_code(&report(false, 1, 0)),
            ExitCode::GeneralFailure
        );
        assert_eq!(
            result_exit_code(&report(false, 0, 1)),
            ExitCode::GeneralFailure
        );
        assert_eq!(
            result_exit_code(&report(false, 0, 0)),
            ExitCode::Unavailable
        );
        assert_eq!(result_exit_code(&report(true, 0, 0)), ExitCode::Success);
    }
}
