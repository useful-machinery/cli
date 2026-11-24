//! `useful org integration reconnect`: renews a connection's access, keeping its ID, a
//! GitHub binding's once its setup session is verified, or stores the next version of the
//! organization's token of a token service, keeping its ID and authorizations.
use std::path::PathBuf;

use anyhow::anyhow;
use clap::Args;
use useful_human_auth::Deployment;

use super::create::{FROM_FILE_HELP, from_file_refused};
use super::list::Provider;
use super::target::{self, Integration, Target};
use super::token::{OrgTokens, member_session};
use super::{github, gitlab, linear};
use crate::cli::context::OrgArgs;
use crate::cli::{CommandFailure, CommandResult, WaitTimeoutArgs};
use crate::exit_code::ExitCode;

pub(super) const ABOUT: &str =
    "Renew the access of one of the organization's connections, or store its token's next version";
const AFTER_HELP: &str = "Providers:\n  A GitHub binding is renewed for its own installation once you prove at GitHub that you\n  administer it: the command prints the URL to open, opens it where this machine has a\n  browser and waits for the proof unless --no-wait is given. A disconnected binding becomes\n  active again and an active one has its repositories refreshed. A binding GitHub revoked cannot be reconnected; make a new connection instead:\n    useful org integration connect github\n  A GitLab connection is given the token --token-file names: the command stages it, waits\n  for GitLab to verify it, asks for the verified identity to be confirmed and activates it.\n  Without a terminal, confirm it with --expected-provider-user-id and --dedicated-automation.\n  A Linear connection is reauthorized: the command prints the URL to open and waits for the\n  approval unless --no-wait is given. Show a session it stopped observing:\n    useful org integration show SESSION\n\nGitLab setup guide: https://docs.usefulmachinery.com/agent/gitlab-setup.md";

#[derive(Debug, Args)]
#[command(after_help = AFTER_HELP)]
pub(super) struct Command {
    #[arg(value_name = target::VALUE_NAME, value_parser = Integration::parse, help = Integration::HELP)]
    connection: Integration,

    #[arg(long, value_name = "PATH", help = FROM_FILE_HELP)]
    from_file: Option<PathBuf>,

    #[command(flatten)]
    version: gitlab::ExpectedVersion,

    #[command(flatten)]
    gitlab: gitlab::Credential,

    #[command(flatten)]
    linear: linear::Authorization,

    #[command(flatten)]
    wait: WaitTimeoutArgs,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: linear::Options,
}

impl Command {
    pub(super) fn execute(self, deployment: &Deployment) -> CommandResult {
        let Self {
            connection,
            from_file,
            version,
            gitlab,
            linear,
            wait,
            org,
            options,
        } = self;
        let connection: Target = match connection {
            Integration::Connection(connection) => connection,
            Integration::Token(service) => {
                let unsuited = [
                    version.given(),
                    gitlab.given(),
                    linear.given(),
                    wait.timeout.is_some().then_some("--timeout"),
                ]
                .into_iter()
                .flatten()
                .next();
                if let Some(option) = unsuited {
                    return Err(CommandFailure::with_exit_code(
                        anyhow!(
                            "{option} does not apply to a token\n\nThe next version of the \
                             organization's {service} token is read from --from-file PATH, from \
                             standard input or at a prompt:\n  useful org integration reconnect \
                             {service}"
                        ),
                        ExitCode::UsageError,
                    ));
                }
                member_session(
                    &options.authentication,
                    &format!(
                        "{service}, which is not github, gitlab or linear and so can only name a token service"
                    ),
                )?;
                return target::execute_in(org, options, deployment, |options, organization| {
                    OrgTokens {
                        deployment,
                        policy: options.http.transport_policy(),
                        json: options.json,
                        organization,
                    }
                    .reconnect(&service, from_file.as_deref())
                });
            }
        };
        let given = connection.provider();
        if from_file.is_some() {
            return Err(from_file_refused(given));
        }
        if let Some(refused) = target::refuse_options(
            given,
            &[
                (version.given(), &[Provider::Gitlab]),
                (gitlab.given(), &[Provider::Gitlab]),
                (linear.state_updates_given(), &[Provider::Linear]),
                (
                    linear.no_wait().then_some("--no-wait"),
                    &[Provider::Github, Provider::Linear],
                ),
            ],
        ) {
            return refused;
        }
        match given {
            Provider::Github => {
                let no_wait = linear.no_wait();
                target::execute(
                    connection,
                    org,
                    options,
                    deployment,
                    |options, organization, resolved| {
                        github::reconnect(
                            deployment,
                            options,
                            organization,
                            resolved,
                            (no_wait, wait.timeout),
                        )
                    },
                )
            }
            Provider::Gitlab => {
                let version = version.check()?;
                let staged = gitlab.check(&options)?;
                target::execute(
                    connection,
                    org,
                    options,
                    deployment,
                    |options, organization, resolved| {
                        gitlab::reconnect(
                            deployment,
                            options,
                            organization,
                            &resolved,
                            version,
                            staged,
                            wait.timeout,
                        )
                    },
                )
            }
            Provider::Linear => target::execute(
                connection,
                org,
                options,
                deployment,
                |options, organization, resolved| {
                    linear::authorize(
                        deployment.clone(),
                        options,
                        organization.to_owned(),
                        Some(resolved.id().to_owned()),
                        linear,
                        wait.timeout,
                    )
                },
            ),
        }
    }
}
