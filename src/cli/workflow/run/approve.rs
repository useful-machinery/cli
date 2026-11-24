//! `useful workflow run approve` and `useful workflow run hand-back`: resolve the approval of
//! the run `RUN` names, found under the `useful` home and then in Cloud. A run under the home
//! records the control and continues in this command from the wait's `then` or `onHandBack`; a
//! Cloud run's control is carried to its runner instead.

use clap::Args;
use serde_json::{Map, Value};
use useful_execution::{CONTROL_APPROVE, CONTROL_HAND_BACK, ContinuingControl, WaitKind};

use super::control::{Acted, ControlFailure, ControlTarget, Resolved};
use super::target::{Found, RunArg};
use crate::cli::context::OrgArgs;
use crate::cli::{HttpOptions, PrincipalAuthenticationArgs};

pub(super) const APPROVE_ABOUT: &str = "Approve a run waiting for approval";
pub(super) const HAND_BACK_ABOUT: &str = "Hand a run waiting for approval back with notes";

/// `RUN` of `approve` and `hand-back` and the options both take.
#[derive(Debug, Args)]
pub(super) struct Approving {
    #[command(flatten)]
    run: RunArg,

    #[arg(
        long,
        help = "Record the control and leave the run for resume, for a run under the useful home"
    )]
    record_only: bool,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    presentation: super::PresentationOptions,

    #[command(flatten)]
    authentication: PrincipalAuthenticationArgs,

    #[command(flatten)]
    http: HttpOptions,
}

#[derive(Debug, Args)]
pub(super) struct Approve {
    #[command(flatten)]
    approving: Approving,
}

#[derive(Debug, Args)]
pub(super) struct HandBack {
    #[arg(
        long,
        value_name = "TEXT",
        help = "What the step the run returns to should change"
    )]
    notes: String,

    #[command(flatten)]
    approving: Approving,
}

impl Approve {
    pub(super) fn execute(self) -> super::super::super::CommandResult {
        self.approving.execute(
            ContinuingControl::Approve,
            super::cloud::Control::Approve,
            CONTROL_APPROVE,
            None,
        )
    }
}

impl HandBack {
    pub(super) fn execute(self) -> super::super::super::CommandResult {
        let payload = Map::from_iter([("notes".to_owned(), Value::String(self.notes.clone()))]);
        self.approving.execute(
            ContinuingControl::HandBack,
            super::cloud::Control::HandBack { notes: self.notes },
            CONTROL_HAND_BACK,
            Some(payload),
        )
    }
}

impl Approving {
    /// Appends `event` with `payload` naming the run's `approval` wait and continues the run,
    /// for a run under the home, or sends `cloud` for a Cloud run.
    fn execute(
        self,
        control: ContinuingControl,
        cloud: super::cloud::Control,
        event: &str,
        payload: Option<Map<String, Value>>,
    ) -> super::super::super::CommandResult {
        let json = self.presentation.output.json;
        let found = match super::control::find(
            control.command(),
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
            Found::Home(run_directory) => super::control::resolve(
                control,
                &run_directory,
                self.record_only,
                &self.presentation,
                |target| resolve_approval(target, event, payload),
            ),
            Found::Cloud(run) => super::cloud::CloudRun::found(
                *run,
                self.authentication,
                self.http,
                json,
                self.record_only,
            )
            .control(cloud),
        }
    }
}

/// Appends `event` naming the run's `approval` wait, which it completes.
fn resolve_approval(
    target: &ControlTarget,
    event: &str,
    payload: Option<Map<String, Value>>,
) -> Result<Resolved, ControlFailure> {
    let wait = target.wait_to_resolve(WaitKind::Approval)?;
    let control = target.record(event, Some(wait.id()), payload)?;
    Ok(Resolved {
        acted: Acted::recorded(control, Some(wait.clone())),
        completes: true,
    })
}
