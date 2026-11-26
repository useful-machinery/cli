//! The runner records one Cloud delivery. Resume decides whether the recorded event
//! satisfies the current wait.
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::Args;
use serde_json::json;
use useful_execution::{
    RunEvent, RunEventDelivery, WaitInspection, deliver_run_event, normalize_terminal_path,
};

use super::control::{self, ControlTarget, Refusal};
use crate::exit_code::ExitCode;

pub(super) const ABOUT: &str = "Record a delivered Cloud event for a run's wait";
const COMMAND: &str = "useful workflow run deliver";
const MAXIMUM_EVENT_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(flatten)]
    run: super::target::RunArg,

    #[arg(long, value_name = "FILE", help = "Delivered Cloud event record")]
    event: PathBuf,

    #[command(flatten)]
    output: control::JsonOutput,
}

fn read_event(path: &Path) -> Result<RunEvent, Refusal> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAXIMUM_EVENT_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| Refusal::new("event_invalid", "The event file could not be read."))?;
    if bytes.len() as u64 > MAXIMUM_EVENT_BYTES {
        return Err(Refusal::new(
            "event_invalid",
            "The event file exceeds the size limit.",
        ));
    }
    serde_json::from_slice::<RunEvent>(&bytes)
        .ok()
        .filter(RunEvent::is_valid)
        .ok_or_else(|| {
            Refusal::new(
                "event_invalid",
                "The file does not contain a valid Cloud run event.",
            )
        })
}

impl Command {
    pub(super) fn execute(self) -> super::super::super::CommandResult {
        let json = self.output.json;
        let run_directory = match self.run.home_only() {
            Ok(path) => path,
            Err(error) => {
                let error = control::home_miss(
                    error,
                    "A Cloud run receives deliveries through its runner.",
                );
                return control::write_refusal(COMMAND, None, &error.into(), json);
            }
        };
        let target = match control::open(&run_directory) {
            Ok(target) => target,
            Err(refusal) => {
                return control::write_refusal(COMMAND, Some(&run_directory), &refusal, json);
            }
        };
        let refused = |refusal: Refusal| write_refused(&target, &refusal, json);
        if matches!(target.inspection, WaitInspection::Locked(_)) {
            return refused(control::run_locked());
        }
        let event = match read_event(&self.event) {
            Ok(event) => event,
            Err(refusal) => return refused(refusal),
        };
        let result = deliver_run_event(&target.run_directory, &event).with_context(|| {
            format!(
                "{COMMAND} {}",
                normalize_terminal_path(&target.run_directory)
            )
        })?;
        let (outcome, written) = match result {
            RunEventDelivery::Recorded { ordinal, path } => ("recorded", Some((ordinal, path))),
            RunEventDelivery::Unchanged => ("unchanged", None),
            RunEventDelivery::RunLocked => return refused(control::run_locked()),
            RunEventDelivery::WaitNotCurrent => {
                return refused(Refusal::new(
                    "wait_not_current",
                    "The delivery does not name the run's current wait.",
                ));
            }
            RunEventDelivery::EventNotAccepted => {
                return refused(Refusal::new(
                    "event_not_accepted",
                    "The current wait does not accept this Cloud event.",
                ));
            }
        };
        let mut document = json!({
            "schemaVersion": 1, "command": COMMAND, "outcome": outcome, "exitStatus": 0,
            "runDirectory": target.run_directory, "run": target.record.id,
        });
        let line = if let Some((ordinal, path)) = written {
            let relative = path
                .strip_prefix(&target.run_directory)
                .context("locate recorded run event")?;
            document["ordinal"] = ordinal.into();
            document["path"] = json!(relative);
            format!(
                "{outcome} {} (ordinal {ordinal})",
                normalize_terminal_path(relative)
            )
        } else {
            outcome.to_owned()
        };
        if json {
            super::super::super::write_pretty_json(&document)
        } else {
            writeln!(std::io::stdout().lock(), "{line}")
        }
        .with_context(|| format!("write {COMMAND} output"))?;
        Ok(ExitCode::Success)
    }
}

fn write_refused(
    target: &ControlTarget,
    refusal: &Refusal,
    json: bool,
) -> super::super::super::CommandResult {
    if !json {
        return control::write_refusal(COMMAND, Some(&target.run_directory), refusal, false);
    }
    super::super::super::write_pretty_json(&json!({
        "schemaVersion": 1, "command": COMMAND, "outcome": "refused", "exitStatus": 1,
        "runDirectory": target.run_directory, "run": target.record.id,
        "diagnostics": [{"code": refusal.code, "message": refusal.message}],
    }))
    .with_context(|| format!("write {COMMAND} output"))?;
    Ok(ExitCode::GeneralFailure)
}
