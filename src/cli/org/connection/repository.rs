//! `useful org integration repository`: the repositories a GitHub binding or a GitLab connection
//! reaches, and the GitLab repositories a GitLab connection selects (REQ-CONNECTION-73).
use clap::{Args, Subcommand};
use useful_human_auth::Deployment;

use super::list::{Options, Provider};
use super::target::{self, Target};
use super::{github, gitlab};
use crate::cli::context::OrgArgs;
use crate::cli::{CommandResult, ConfirmationArgs};

pub(super) const ABOUT: &str = "Manage the repositories a connection reaches";
const ADD_ABOUT: &str = "Select GitLab repositories for a GitLab connection";
const REMOVE_ABOUT: &str = "Remove GitLab repositories from a GitLab connection's selection";
const SELECTION_AFTER_HELP: &str = "Providers:\n  Only a GitLab connection selects repositories; a GitHub installation's repositories are\n  chosen on GitHub.\n\nGitLab setup guide: https://docs.usefulmachinery.com/agent/gitlab-setup.md";
const LIST_ABOUT: &str = "List the repositories a connection reaches";
const LIST_AFTER_HELP: &str = "Providers:\n  For a GitHub binding the command lists every repository its installation grants, and takes\n  none of --limit, --cursor, --search, --repository-id or --selected. For a GitLab connection\n  it lists one page.\n\nGitLab setup guide: https://docs.usefulmachinery.com/agent/gitlab-setup.md";
/// The providers whose connections reach repositories.
const PROVIDERS: [Provider; 2] = [Provider::Github, Provider::Gitlab];

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<Leaf>,
}

#[derive(Debug, Subcommand)]
enum Leaf {
    #[command(about = ADD_ABOUT, after_help = SELECTION_AFTER_HELP)]
    Add(Selection),
    #[command(about = LIST_ABOUT, after_help = LIST_AFTER_HELP)]
    List(List),
    #[command(about = REMOVE_ABOUT, after_help = SELECTION_AFTER_HELP)]
    Remove(Removal),
}

impl Command {
    pub(super) fn execute(self, deployment: &Deployment) -> CommandResult {
        match self.command {
            None => crate::cli::print_help(&[super::super::NAME, super::NAME, "repository"]),
            Some(Leaf::Add(command)) => command.execute(deployment, "repository add", true),
            Some(Leaf::List(command)) => command.execute(deployment),
            Some(Leaf::Remove(command)) => {
                command
                    .selection
                    .execute(deployment, "repository remove", false)
            }
        }
    }
}

/// `repository add` and, with confirmation, `repository remove`.
#[derive(Debug, Args)]
struct Selection {
    #[arg(
        value_name = "REPOSITORY",
        required = true,
        num_args = 1..,
        help = "GitLab project ID, as repository list prints it"
    )]
    repositories: Vec<String>,

    #[arg(
        long = "integration",
        value_name = target::VALUE_NAME,
        value_parser = Target::parse,
        help = target::HELP
    )]
    connection: Target,

    #[command(flatten)]
    mutation: gitlab::Mutation,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: Options,
}

#[derive(Debug, Args)]
struct Removal {
    #[command(flatten)]
    selection: Selection,

    #[command(flatten)]
    confirmation: ConfirmationArgs,
}

impl Selection {
    /// Adds the repositories to the connection's selection, or with `add` false removes them
    /// (REQ-CONNECTION-73, REQ-CONNECTION-74).
    fn execute(self, deployment: &Deployment, command: &str, add: bool) -> CommandResult {
        let Self {
            repositories,
            connection,
            mutation,
            org,
            options,
        } = self;
        let given = connection.provider();
        if given != Provider::Gitlab {
            let remedy = match given {
                Provider::Github => {
                    "A GitHub installation's repositories are chosen on GitHub. List the ones it grants:\n  useful org integration repository list INTEGRATION"
                }
                Provider::Gitlab | Provider::Linear => target::NAME_ANOTHER,
            };
            return target::refuse(command, &[Provider::Gitlab], given, remedy);
        }
        gitlab::check_repositories(&repositories)?;
        let mutation = mutation.check()?;
        target::execute(
            connection,
            org,
            options,
            deployment,
            |options, organization, resolved| {
                gitlab::select(
                    deployment,
                    options,
                    organization,
                    &resolved,
                    repositories,
                    add,
                    mutation,
                )
            },
        )
    }
}

#[derive(Debug, Args)]
struct List {
    #[arg(value_name = target::VALUE_NAME, value_parser = Target::parse, help = target::HELP)]
    connection: Target,

    #[command(flatten)]
    query: gitlab::RepositoryQuery,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: Options,
}

/// How the repositories of the connection named are read.
enum Read {
    /// Every repository a GitHub installation grants, in one answer.
    Github,
    /// One page of a GitLab connection's repositories.
    Gitlab(gitlab::RepositoryQuery),
}

impl List {
    fn execute(self, deployment: &Deployment) -> CommandResult {
        let Self {
            connection,
            query,
            org,
            options,
        } = self;
        let given = connection.provider();
        let read = match given {
            Provider::Linear => {
                return target::refuse("repository list", &PROVIDERS, given, target::NAME_ANOTHER);
            }
            Provider::Github => match query.given() {
                Some(option) => {
                    return target::refuse(
                        option,
                        &[Provider::Gitlab],
                        given,
                        &format!(
                            "A GitHub binding's installation grants its repositories as one list. Run the command without {option}."
                        ),
                    );
                }
                None => Read::Github,
            },
            Provider::Gitlab => {
                query.check()?;
                Read::Gitlab(query)
            }
        };
        target::execute(
            connection,
            org,
            options,
            deployment,
            |options, organization, resolved| match read {
                Read::Github => {
                    github::list_repositories(deployment, &options, organization, resolved.id())
                }
                Read::Gitlab(query) => gitlab::list_repositories(
                    deployment,
                    &options,
                    organization,
                    resolved.id(),
                    &query,
                ),
            },
        )
    }
}
