use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::mirror::{Template, TemplateSegment};
use super::runtime::StepStateKind;

/// The root's Slack block. Message templates stay as written for tree validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackBlock {
    /// The channel binding key without its `$` prefix.
    pub channel: Option<String>,
    /// Message templates by step or finalizer id and transition.
    pub on_step: BTreeMap<String, BTreeMap<SlackTransition, String>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SlackTransition {
    Started,
    Succeeded,
    Failed,
    Skipped,
    Cancelled,
    Blocked,
    NotRun,
}

impl SlackTransition {
    pub fn as_str(self) -> &'static str {
        self.message_key().trim_start_matches("onStep.")
    }

    pub(crate) fn message_key(self) -> &'static str {
        match self {
            Self::Started => "onStep.started",
            Self::Succeeded => "onStep.succeeded",
            Self::Failed => "onStep.failed",
            Self::Skipped => "onStep.skipped",
            Self::Cancelled => "onStep.cancelled",
            Self::Blocked => "onStep.blocked",
            Self::NotRun => "onStep.notRun",
        }
    }

    fn for_state(state: StepStateKind) -> Option<Self> {
        Some(match state {
            StepStateKind::Starting => Self::Started,
            StepStateKind::Succeeded => Self::Succeeded,
            StepStateKind::Failed => Self::Failed,
            StepStateKind::Skipped => Self::Skipped,
            StepStateKind::Cancelled => Self::Cancelled,
            StepStateKind::Blocked => Self::Blocked,
            StepStateKind::NotRun => Self::NotRun,
            StepStateKind::Pending
            | StepStateKind::Running
            | StepStateKind::CapturingOutputs
            | StepStateKind::Recovering
            | StepStateKind::Cancelling
            | StepStateKind::Inherited => return None,
        })
    }
}

/// Hooks for one attempt's progress stream.
#[derive(Clone)]
pub(super) struct SlackProgress {
    hooks: BTreeMap<String, BTreeMap<SlackTransition, String>>,
    run_id: String,
    run_url: String,
    started: BTreeSet<String>,
}

impl SlackProgress {
    pub(super) fn new(block: &SlackBlock, run_id: String, run_url: String) -> Self {
        Self {
            hooks: block.on_step.clone(),
            run_id,
            run_url,
            started: BTreeSet::new(),
        }
    }

    pub(super) fn message(&mut self, step: &str, state: StepStateKind) -> Option<String> {
        let transition = SlackTransition::for_state(state)?;
        let message = self.hooks.get(step)?.get(&transition)?;
        if transition == SlackTransition::Started && !self.started.insert(step.to_owned()) {
            return None;
        }
        let template = Template::parse(message).ok()?;
        let mut rendered = String::new();
        for segment in template.segments() {
            rendered.push_str(match segment {
                TemplateSegment::Literal(text) => text,
                TemplateSegment::Variable(name) => match name.as_str() {
                    "run.id" => &self.run_id,
                    "run.url" => &self.run_url,
                    "step" => step,
                    _ => return None,
                },
            });
        }
        Some(rendered)
    }
}
