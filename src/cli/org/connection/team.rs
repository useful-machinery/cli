//! `useful org integration team`: the Linear teams a Linear connection reaches and their
//! workflow states.
use clap::{Args, Subcommand};
use useful_human_auth::Deployment;

use super::linear;
use super::list::{Options, Provider};
use super::target::{self, Target};
use crate::cli::context::OrgArgs;
use crate::cli::{CommandResult, PaginationArgs};

pub(super) const ABOUT: &str = "Work with the Linear teams a connection reaches";
const LIST_ABOUT: &str = "List the Linear teams a connection reaches";
const SHOW_ABOUT: &str = "Show a Linear team's workflow states";
const AUTHORIZATION: &str = "Authorization:\n  Only an organization owner can read a connection's teams and their workflow states.";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<Leaf>,
}

#[derive(Debug, Subcommand)]
enum Leaf {
    #[command(about = LIST_ABOUT, after_help = AUTHORIZATION)]
    List(List),
    #[command(about = SHOW_ABOUT, after_help = AUTHORIZATION)]
    Show(Show),
}

impl Command {
    pub(super) fn execute(self, deployment: &Deployment) -> CommandResult {
        match self.command {
            None => crate::cli::print_help(&[super::super::NAME, super::NAME, "team"]),
            Some(Leaf::List(command)) => {
                let List {
                    connection,
                    page,
                    org,
                    options,
                } = command;
                read(
                    "team list",
                    connection,
                    org,
                    options,
                    deployment,
                    |o, organization, id| {
                        linear::list_teams(deployment, o, organization, id, &page)
                    },
                )
            }
            Some(Leaf::Show(command)) => {
                let Show {
                    team,
                    connection,
                    page,
                    org,
                    options,
                } = command;
                read(
                    "team show",
                    connection,
                    org,
                    options,
                    deployment,
                    |o, organization, id| {
                        linear::list_states(deployment, o, organization, id, &team, &page)
                    },
                )
            }
        }
    }
}

#[derive(Debug, Args)]
struct List {
    #[arg(value_name = target::VALUE_NAME, value_parser = Target::parse, help = target::HELP)]
    connection: Target,

    #[command(flatten)]
    page: PaginationArgs<100>,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: Options,
}

#[derive(Debug, Args)]
struct Show {
    #[arg(value_name = "TEAM", help = "Linear team ID, as team list prints it")]
    team: String,

    #[arg(
        long = "integration",
        value_name = target::VALUE_NAME,
        value_parser = Target::parse,
        help = target::HELP
    )]
    connection: Target,

    #[command(flatten)]
    page: PaginationArgs<100>,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: Options,
}

/// Runs `discover` on the Linear connection `connection` names, refusing one of another
/// provider before any request.
fn read(
    command: &str,
    connection: Target,
    org: OrgArgs,
    options: Options,
    deployment: &Deployment,
    discover: impl FnOnce(&Options, &str, &str) -> anyhow::Result<crate::exit_code::ExitCode>,
) -> CommandResult {
    let given = connection.provider();
    if given != Provider::Linear {
        return target::refuse(command, &[Provider::Linear], given, target::NAME_ANOTHER);
    }
    target::execute(
        connection,
        org,
        options,
        deployment,
        |options, organization, resolved| discover(&options, organization, resolved.id()),
    )
}
