//! `useful org integration`: the organization's connections to GitHub, GitLab, Linear and Slack, its
//! tokens of token services, and the runners authorized for either. Each provider keeps its own
//! client, failures and output in its module here; a token is acted on through
//! `integration_token` and a connection authorization in `authorization`.
mod authorization;
mod authorize;
mod consent;
mod create;
mod github;
mod gitlab;
pub(in crate::cli) mod linear;
pub(in crate::cli) mod list;
pub(in crate::cli) mod reach;
mod reconnect;
mod remove;
mod repository;
mod show;
mod slack;
pub(in crate::cli) mod target;
mod team;
mod token;

use clap::{Args, Subcommand};

pub(super) const ABOUT: &str = "Manage the organization's connections and tokens";
const NAME: &str = "integration";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<ConnectionCommand>,
}

#[derive(Debug, Subcommand)]
enum ConnectionCommand {
    #[command(about = authorize::ABOUT)]
    Authorize(authorize::Command),
    #[command(about = create::ABOUT)]
    Connect(create::Command),
    #[command(about = authorize::deauthorize::ABOUT)]
    Deauthorize(authorize::deauthorize::Command),
    #[command(about = remove::ABOUT)]
    Disconnect(remove::Command),
    #[command(about = list::ABOUT)]
    List(list::Command),
    #[command(about = reconnect::ABOUT)]
    Reconnect(reconnect::Command),
    #[command(about = repository::ABOUT)]
    Repository(repository::Command),
    #[command(about = show::ABOUT)]
    Show(show::Command),
    #[command(about = team::ABOUT)]
    Team(team::Command),
}

impl Command {
    pub(super) fn execute(self) -> super::super::CommandResult {
        super::super::execute_deployment_command(
            self.command,
            &[super::NAME, NAME],
            "configure Useful Machinery connection access",
            |command, deployment| match command {
                ConnectionCommand::Authorize(command) => command.execute(deployment),
                ConnectionCommand::Connect(command) => command.execute(deployment),
                ConnectionCommand::Deauthorize(command) => command.execute(deployment),
                ConnectionCommand::List(command) => command.execute(deployment),
                ConnectionCommand::Reconnect(command) => command.execute(deployment),
                ConnectionCommand::Disconnect(command) => command.execute(deployment),
                ConnectionCommand::Repository(command) => command.execute(deployment),
                ConnectionCommand::Show(command) => command.execute(deployment),
                ConnectionCommand::Team(command) => command.execute(deployment),
            },
        )
    }
}
