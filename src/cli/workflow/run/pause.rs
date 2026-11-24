//! `useful workflow run pause` and `useful workflow run unpause`: hold the run `RUN` names
//! before a step and release the hold, the run found under the `useful` home and then in
//! Cloud. A run under the home records the `control.stop` or `control.lift` the run reads; a
//! Cloud run's control is carried to its runner instead.

use std::collections::BTreeSet;

use clap::Args;
use serde_json::{Map, Value};
use useful_execution::{CONTROL_LIFT, CONTROL_STOP, WaitKind, read_controls, stop_in_force};

use super::control::{Acted, ControlFailure, ControlTarget, Refusal};
use super::target::{Found, RunArg};
use crate::cli::context::OrgArgs;
use crate::cli::{HttpOptions, PrincipalAuthenticationArgs};

pub(super) const PAUSE_ABOUT: &str = "Pause a run before a workflow step";
pub(super) const UNPAUSE_ABOUT: &str = "Release a pause so the run may continue past its step";
/// The `after_help` paragraph of `pause` and `unpause`.
pub(super) const AFTER_HELP: &str = "RUN is a run directory, a run ID or a subject. An ID or a subject is looked up under the useful home and, when the home holds no such run, in Cloud in the organization in effect.

pause applies to a run in every state but ended, and unpause wherever a pause is in force, reached or not.

For a run under the home the command records the control, which the run reads when it reaches the step or is resumed.

For a Cloud run the command asks Cloud, under one request key sent again if the response is lost, to carry the control to the runner executing the run, which applies it as this command applies it to a run under the home. Cloud's acceptance is not the runner's application.";
const PAUSE_COMMAND: &str = "useful workflow run pause";
const UNPAUSE_COMMAND: &str = "useful workflow run unpause";

/// `RUN` of `pause` and `unpause` and the options both take.
#[derive(Debug, Args)]
struct Held {
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

#[derive(Debug, Args)]
pub(super) struct Pause {
    #[arg(long, value_name = "STEP", help = "Workflow step the run waits before")]
    before: String,

    #[arg(long, value_name = "TEXT", help = "Why the run is paused")]
    reason: String,

    #[command(flatten)]
    held: Held,
}

#[derive(Debug, Args)]
pub(super) struct Unpause {
    #[arg(
        long,
        value_name = "STEP",
        help = "Step whose pause to release; required when several are in force"
    )]
    before: Option<String>,

    #[command(flatten)]
    held: Held,
}

impl Held {
    /// Finds the run and, under the home, lets `act` append the control or refuse; a Cloud run
    /// is sent `control` instead.
    fn execute(
        self,
        command: &'static str,
        control: super::cloud::Control,
        act: impl FnOnce(&ControlTarget) -> Result<Acted, ControlFailure>,
    ) -> super::super::super::CommandResult {
        let json = self.output.json;
        let found = match super::control::find(
            command,
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
                match super::control::act_on(command, &run_directory, json, act) {
                    Ok((target, acted)) => {
                        super::control::write_recorded(command, &target, &acted, json)
                    }
                    Err(result) => result,
                }
            }
            Found::Cloud(run) => {
                super::cloud::CloudRun::found(*run, self.authentication, self.http, json, false)
                    .control(control)
            }
        }
    }
}

impl Pause {
    pub(super) fn execute(self) -> super::super::super::CommandResult {
        let control = super::cloud::Control::Stop {
            before: self.before.clone(),
            reason: self.reason.clone(),
        };
        let (before, reason) = (self.before, self.reason);
        self.held.execute(PAUSE_COMMAND, control, |target| {
            pause(target, &before, &reason)
        })
    }
}

fn pause(target: &ControlTarget, before: &str, reason: &str) -> Result<Acted, ControlFailure> {
    if super::control::exited(target) {
        return Err(target.refusal("run_exited").into());
    }
    let steps = target.stop_steps();
    if !steps.known.contains(before) {
        return Err(Refusal::new("step_unknown", "The run's workflow has no such step.").into());
    }
    if !steps.holdable.contains(before) {
        return Err(super::control::step_not_holdable().into());
    }
    let controls = read_controls(&target.run_directory)?;
    if stop_in_force(&controls, before).is_some() {
        return Err(Refusal::new(
            "stop_in_force",
            "A pause is already in force before this step.",
        )
        .into());
    }
    let payload = Map::from_iter([
        ("before".to_owned(), Value::String(before.to_owned())),
        ("reason".to_owned(), Value::String(reason.to_owned())),
    ]);
    let control = target.record(CONTROL_STOP, None, Some(payload))?;
    Ok(Acted::recorded(control, target.wait().cloned()))
}

impl Unpause {
    pub(super) fn execute(self) -> super::super::super::CommandResult {
        let control = super::cloud::Control::Lift {
            before: self.before.clone(),
        };
        let before = self.before;
        self.held.execute(UNPAUSE_COMMAND, control, |target| {
            unpause(target, before.as_deref())
        })
    }
}

fn unpause(target: &ControlTarget, before: Option<&str>) -> Result<Acted, ControlFailure> {
    let controls = read_controls(&target.run_directory)?;
    let in_force = controls
        .iter()
        .filter(|control| control.event == CONTROL_STOP)
        .filter_map(|control| control.payload.as_ref()?.get("before")?.as_str())
        .filter(|step| stop_in_force(&controls, step).is_some())
        .collect::<BTreeSet<_>>();
    let step = match (before, in_force.len()) {
        (Some(step), _) if in_force.contains(step) => step,
        (None, 1) => in_force.first().copied().unwrap_or_default(),
        (None, 2..) => {
            return Err(Refusal::new(
                "stop_ambiguous",
                "Several pauses are in force; name the one to release with --before STEP.",
            )
            .into());
        }
        _ => {
            return Err(Refusal::new(
                "stop_not_in_force",
                "No pause is in force for the run or the named step.",
            )
            .into());
        }
    };
    let Some(stop) = stop_in_force(&controls, step) else {
        return Err(Refusal::new("stop_not_in_force", "No pause is in force for the step.").into());
    };
    // The run's `stop` wait for this step, when it is in one, is the wait the lift acts on:
    // the root's own before the step, or the one it carries from a nested run, whose `step`
    // path ends in the nested step.
    let wait = target
        .wait()
        .filter(|wait| {
            wait.kind == WaitKind::Stop
                && if wait.is_carried() {
                    wait.step.last().and_then(Value::as_str) == Some(step)
                } else {
                    wait.then == step
                }
        })
        .map(useful_execution::WaitRecord::id);
    let payload = Map::from_iter([
        ("before".to_owned(), Value::String(step.to_owned())),
        ("stop".to_owned(), Value::String(stop.at.clone())),
    ]);
    let control = target.record(CONTROL_LIFT, wait, Some(payload))?;
    Ok(Acted::recorded(control, target.wait().cloned()))
}
