mod answer;
mod approve;
mod artifact;
mod child_recovery;
mod cloud;
pub(super) mod cloud_api;
mod condition;
mod control;
mod create;
mod deliver;
mod end;
mod event;
mod handover;
mod input;
mod interrupt;
mod linear;
mod list;
mod mirror;
mod pause;
mod publication;
mod record;
mod resume;
mod retry;
mod show;
mod successor;
mod target;
mod upgrade;
mod view;

use clap::{Args, Subcommand};

pub(super) use super::{
    ColorArgument, LocalExecutionRoot, PresentationOptions, execute_with_abandonable_runtime,
    observe_workflow_signals,
};
pub(super) use create::{acquire_agent_profile_replacement, write_input_acquisition_failure};

pub(super) const ABOUT: &str =
    "Create, control and inspect workflow runs, on this machine and in Cloud";
const COMMAND_PATH: &[&str] = &["workflow", "run"];

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<RunCommand>,
}

#[derive(Debug, Subcommand)]
enum RunCommand {
    #[command(about = answer::ABOUT, after_help = control::RESOLVING_AFTER_HELP)]
    Answer(answer::Command),
    #[command(about = approve::APPROVE_ABOUT, after_help = control::RESOLVING_AFTER_HELP)]
    Approve(approve::Approve),
    #[command(about = artifact::ABOUT)]
    Artifact(artifact::Command),
    #[command(about = end::CANCEL_ABOUT, after_help = end::CANCEL_AFTER_HELP)]
    Cancel(end::Cancel),
    #[command(about = create::ABOUT, after_help = create::AFTER_HELP)]
    Create(Box<create::Command>),
    #[command(about = deliver::ABOUT, hide = true)]
    Deliver(deliver::Command),
    // The runner's own, hidden: it applies a delivered provider event.
    #[command(about = event::ABOUT, hide = true)]
    Event(event::Command),
    #[command(about = approve::HAND_BACK_ABOUT, after_help = control::RESOLVING_AFTER_HELP)]
    HandBack(approve::HandBack),
    #[command(about = handover::ABOUT, after_help = handover::AFTER_HELP)]
    Handover(handover::Command),
    #[command(about = input::ABOUT)]
    Input(input::Command),
    #[command(about = interrupt::ABOUT, after_help = interrupt::AFTER_HELP)]
    Interrupt(interrupt::Command),
    #[command(about = linear::ABOUT)]
    Linear(linear::Command),
    #[command(about = list::ABOUT, after_help = list::AFTER_HELP)]
    List(list::Command),
    #[command(about = pause::PAUSE_ABOUT, after_help = pause::AFTER_HELP)]
    Pause(pause::Pause),
    #[command(about = publication::ABOUT)]
    Publication(publication::Command),
    #[command(about = record::ABOUT)]
    Record(record::Command),
    #[command(about = end::RELEASE_ABOUT, after_help = end::RELEASE_AFTER_HELP)]
    Release(end::Release),
    #[command(about = resume::ABOUT, after_help = resume::AFTER_HELP)]
    Resume(resume::Command),
    #[command(about = retry::ABOUT, after_help = retry::AFTER_HELP)]
    Retry(retry::Command),
    #[command(about = show::ABOUT, after_help = show::AFTER_HELP)]
    Show(show::Command),
    #[command(about = pause::UNPAUSE_ABOUT, after_help = pause::AFTER_HELP)]
    Unpause(pause::Unpause),
    #[command(about = upgrade::ABOUT, after_help = upgrade::AFTER_HELP)]
    Upgrade(upgrade::Command),
    #[command(about = view::ABOUT, after_help = view::AFTER_HELP)]
    View(view::Command),
}

impl Command {
    pub(super) fn execute(self) -> super::super::CommandResult {
        match self.command {
            None => super::super::print_help(COMMAND_PATH),
            Some(RunCommand::Answer(command)) => command.execute(),
            Some(RunCommand::Approve(command)) => command.execute(),
            Some(RunCommand::Artifact(command)) => command.execute(),
            Some(RunCommand::Cancel(command)) => command.execute(),
            Some(RunCommand::Create(command)) => command.execute(),
            Some(RunCommand::Deliver(command)) => command.execute(),
            Some(RunCommand::Event(command)) => command.execute(),
            Some(RunCommand::HandBack(command)) => command.execute(),
            Some(RunCommand::Handover(command)) => command.execute(),
            Some(RunCommand::Input(command)) => command.execute(),
            Some(RunCommand::Interrupt(command)) => command.execute(),
            Some(RunCommand::Linear(command)) => command.execute(),
            Some(RunCommand::List(command)) => command.execute(),
            Some(RunCommand::Pause(command)) => command.execute(),
            Some(RunCommand::Publication(command)) => command.execute(),
            Some(RunCommand::Record(command)) => command.execute(),
            Some(RunCommand::Release(command)) => command.execute(),
            Some(RunCommand::Resume(command)) => command.execute(),
            Some(RunCommand::Retry(command)) => command.execute(),
            Some(RunCommand::Show(command)) => command.execute(),
            Some(RunCommand::Unpause(command)) => command.execute(),
            Some(RunCommand::Upgrade(command)) => command.execute(),
            Some(RunCommand::View(command)) => command.execute(),
        }
    }
}
