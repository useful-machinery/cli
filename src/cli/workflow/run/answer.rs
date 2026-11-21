//! `useful workflow run answer` (REQ-LOCALRUN-182): answers the run `RUN` names, found under
//! the `useful` home and then in Cloud (REQ-LOCALRUN-180). A run under the home records the
//! answer and, once the answers complete the wait, continues in this command; a Cloud run's
//! answer is carried to its runner instead (REQ-LOCALRUN-210).

use clap::Args;
use serde_json::{Map, Value};
use useful_execution::{
    CONTROL_ANSWER, ContinuingControl, WaitKind, WaitQuestions, read_controls, wait_questions,
};

use super::control::{Acted, ControlFailure, ControlTarget, Refusal, Resolved};
use super::target::{Found, RunArg};
use crate::cli::context::OrgArgs;
use crate::cli::{HttpOptions, PrincipalAuthenticationArgs};

pub(super) const ABOUT: &str = "Answer a question a waiting run asks";
const CONTROL: ContinuingControl = ContinuingControl::Answer;

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(flatten)]
    run: RunArg,

    #[arg(
        long,
        value_name = "ID",
        help = "Question to answer, as the wait lists it; required when several are open"
    )]
    question: Option<String>,

    #[arg(long, value_name = "TEXT", help = "The answer")]
    text: String,

    #[arg(
        long,
        help = "Record the answer and leave the run for resume, for a run under the useful home"
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

impl Command {
    pub(super) fn execute(self) -> super::super::super::CommandResult {
        let json = self.presentation.output.json;
        let found = match super::control::find(
            CONTROL.command(),
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
                CONTROL,
                &run_directory,
                self.record_only,
                &self.presentation,
                |target| self.answer(target),
            ),
            Found::Cloud(run) => super::cloud::CloudRun::found(
                *run,
                self.authentication,
                self.http,
                json,
                self.record_only,
            )
            .answer(self.question, self.text),
        }
    }

    fn answer(&self, target: &ControlTarget) -> Result<Resolved, ControlFailure> {
        let wait = target.wait_to_resolve(WaitKind::Answer)?;
        // The listed questions' ids; a wait that lists none asks one question any id answers.
        let questions = match wait_questions(&wait.payload) {
            WaitQuestions::Listed(questions) => Some(
                questions
                    .into_iter()
                    .map(|question| question.id)
                    .collect::<Vec<_>>(),
            ),
            WaitQuestions::Unlisted { .. } => None,
        };
        let wait_id = wait.id();
        // The answers recorded for this wait so far, the latest text per question.
        let mut answers = Map::new();
        for control in read_controls(&target.run_directory)?
            .iter()
            .filter(|control| {
                control.event == CONTROL_ANSWER && control.wait.as_deref() == Some(&wait_id)
            })
        {
            if let Some(payload) = &control.payload
                && let (Some(Value::String(question)), Some(text)) =
                    (payload.get("question"), payload.get("text"))
            {
                answers.insert(question.clone(), text.clone());
            }
        }
        let question = match (&self.question, &questions) {
            (Some(question), Some(questions)) if !questions.contains(question) => {
                return Err(Refusal::new(
                    "question_unknown",
                    "The wait asks no question with this id.",
                )
                .into());
            }
            (Some(question), _) => question.clone(),
            // A wait that lists no question asks one, answered as `1`.
            (None, None) => "1".to_owned(),
            (None, Some(questions)) => {
                let open = questions
                    .iter()
                    .filter(|question| !answers.contains_key(question.as_str()))
                    .collect::<Vec<_>>();
                match open.as_slice() {
                    [] => "1".to_owned(),
                    [question] => (*question).clone(),
                    _ => {
                        return Err(super::control::question_ambiguous(
                            open.iter().map(|question| question.as_str()),
                        )
                        .into());
                    }
                }
            }
        };
        answers.insert(question.clone(), Value::String(self.text.clone()));
        let complete = questions.is_none_or(|questions| {
            questions
                .iter()
                .all(|question| answers.contains_key(question))
        });
        let payload = Map::from_iter([
            ("question".to_owned(), Value::String(question)),
            ("text".to_owned(), Value::String(self.text.clone())),
            ("answers".to_owned(), Value::Object(answers)),
            ("complete".to_owned(), Value::Bool(complete)),
        ]);
        let control = target.record(CONTROL_ANSWER, Some(wait_id), Some(payload))?;
        Ok(Resolved {
            acted: Acted::recorded(control, Some(wait.clone())),
            completes: complete,
        })
    }
}
