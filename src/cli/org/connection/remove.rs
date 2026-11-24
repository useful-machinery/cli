//! `useful org integration disconnect`: disconnects a GitHub binding, a GitLab connection or a
//! Linear connection, or deletes a Linear connection and releases its workspace.
use clap::Args;
use useful_human_auth::Deployment;

use super::list::{Options, Provider};
use super::target::{self, Integration};
use super::token::{OrgTokens, member_session};
use super::{github, gitlab, linear};
use crate::cli::context::OrgArgs;
use crate::cli::{CommandResult, ConfirmationArgs};

pub(super) const ABOUT: &str =
    "Remove one of the organization's connections, or erase its token of a token service";
const AFTER_HELP: &str = "Providers:\n  A GitHub binding or a GitLab connection is disconnected. A Linear connection is disconnected\n  and keeps its workspace held, or with --release-workspace is deleted and releases it.\n  --expected-version, --idempotency-key and --delegator-principal-id belong to a GitLab\n  connection; without --expected-version the command reads the connection's current version.\n\nGitLab setup guide: https://docs.usefulmachinery.com/agent/gitlab-setup.md";

#[derive(Debug, Args)]
#[command(after_help = AFTER_HELP)]
pub(super) struct Command {
    #[arg(value_name = target::VALUE_NAME, value_parser = Integration::parse, help = Integration::HELP)]
    connection: Integration,

    #[arg(
        long,
        help = "Delete a Linear connection and release its workspace instead of disconnecting it"
    )]
    release_workspace: bool,

    #[command(flatten)]
    mutation: gitlab::Mutation,

    #[command(flatten)]
    confirmation: ConfirmationArgs,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: Options,
}

impl Command {
    pub(super) fn execute(self, deployment: &Deployment) -> CommandResult {
        let Self {
            connection,
            release_workspace,
            mutation,
            confirmation: _,
            org,
            options,
        } = self;
        let connection = match connection {
            Integration::Connection(connection) => connection,
            Integration::Token(service) => {
                let unsuited = release_workspace
                    .then_some("--release-workspace")
                    .or_else(|| mutation.given());
                if let Some(option) = unsuited {
                    return Err(crate::cli::CommandFailure::with_exit_code(
                        anyhow::anyhow!(
                            "{option} does not apply to a token\n\nErase the organization's \
                             {service} token with:\n  useful org integration disconnect \
                             {service} --yes"
                        ),
                        crate::exit_code::ExitCode::UsageError,
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
                    .disconnect(&service)
                });
            }
        };
        let given = connection.provider();
        if release_workspace && given != Provider::Linear {
            return target::refuse(
                "--release-workspace",
                &[Provider::Linear],
                given,
                "Run the command without --release-workspace.",
            );
        }
        if given != Provider::Gitlab
            && let Some(option) = mutation.given()
        {
            return target::refuse(
                option,
                &[Provider::Gitlab],
                given,
                &format!("Run the command without {option}."),
            );
        }
        match given {
            Provider::Github => target::execute(
                connection,
                org,
                options,
                deployment,
                |options, organization, resolved| {
                    github::remove(deployment, &options, organization, resolved.id())
                },
            ),
            Provider::Gitlab => {
                let mutation = mutation.check()?;
                target::execute(
                    connection,
                    org,
                    options,
                    deployment,
                    |options, organization, resolved| {
                        gitlab::remove(deployment, options, organization, &resolved, mutation)
                    },
                )
            }
            Provider::Linear => {
                let action = if release_workspace {
                    linear::Action::Delete
                } else {
                    linear::Action::Disconnect
                };
                target::execute(
                    connection,
                    org,
                    options,
                    deployment,
                    |options, organization, resolved| {
                        linear::remove(
                            deployment.clone(),
                            options,
                            organization.to_owned(),
                            resolved.id().to_owned(),
                            action,
                        )
                    },
                )
            }
        }
    }
}
