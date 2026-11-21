//! `useful org integration connect`: connects a provider to the organization (REQ-CONNECTION-17,
//! REQ-CONNECTION-40, REQ-CONNECTION-56), or stores the organization's token of a token service
//! (REQ-INTEGRATION-16, REQ-INTEGRATION-17).
use std::path::PathBuf;

use anyhow::anyhow;
use clap::{Args, ValueEnum};
use useful_api::{MemberGrantApi, ServedTokenService};
use useful_human_auth::Deployment;

use super::list::Provider;
use super::token::{OrgTokens, member_session};
use super::{github, gitlab, linear, target};
use crate::cli::context::OrgArgs;
use crate::cli::integration_token;
use crate::cli::{CommandFailure, CommandResult, WaitTimeoutArgs, with_human_session_api};
use crate::exit_code::ExitCode;

pub(super) const ABOUT: &str =
    "Connect a provider to the organization, or store its token of a token service";
/// The help of `--from-file`, which `connect` and `reconnect` share.
pub(super) const FROM_FILE_HELP: &str = "Read the organization's token of a token service from an owned mode-0600 file, or - for standard input";
const AFTER_HELP: &str = "Providers:\n  github prints the URL to open to install the GitHub App. The page GitHub returns to shows\n  the installation ID; then complete the connection with it:\n    useful org integration connect github --installation <INSTALLATION_ID>\n  gitlab creates a connection, stages the token --token-file names, waits for GitLab to\n  verify it, asks for the verified identity to be confirmed and activates it. Without a\n  terminal, confirm it with --expected-provider-user-id and --dedicated-automation.\n  linear prints the URL to open to approve a Linear workspace and waits for the approval\n  unless --no-wait is given. Show a session it stopped observing:\n    useful org integration show SESSION\n\nGitLab setup guide: https://docs.usefulmachinery.com/agent/gitlab-setup.md";

#[derive(Debug, Args)]
#[command(after_help = AFTER_HELP)]
pub(super) struct Command {
    #[arg(
        value_name = "PROVIDER",
        value_parser = Connected::parse,
        help = "Provider to connect, github, gitlab or linear, or a token service your deployment serves"
    )]
    provider: Connected,

    #[arg(long, value_name = "PATH", help = FROM_FILE_HELP)]
    from_file: Option<PathBuf>,

    #[arg(
        long,
        value_name = "ID",
        value_parser = github::installation_id,
        help = "Complete a GitHub connection for this decimal GitHub installation ID"
    )]
    installation: Option<String>,

    #[command(flatten)]
    instance: gitlab::Instance,

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

/// What `connect` connects: a provider, or the organization's token of a token service.
#[derive(Clone, Debug)]
enum Connected {
    Provider(Provider),
    Service(String),
}

impl Connected {
    fn parse(value: &str) -> Result<Self, String> {
        if let Ok(provider) = Provider::from_str(value, false) {
            return Ok(Self::Provider(provider));
        }
        if useful_api::valid_provider_id(value)
            && useful_api::MemberGrantProvider::from_wire(value).is_none()
        {
            return Ok(Self::Service(value.to_owned()));
        }
        Err("provider must be github, gitlab or linear, or a token service's name".to_owned())
    }
}

impl Command {
    pub(super) fn execute(self, deployment: &Deployment) -> CommandResult {
        let provider = match self.provider {
            Connected::Provider(provider) => provider,
            Connected::Service(ref service) => {
                let service = service.clone();
                return self.connect_token(deployment, &service);
            }
        };
        if self.from_file.is_some() {
            return Err(from_file_refused(provider));
        }
        let Self {
            installation,
            instance,
            gitlab,
            linear,
            wait,
            org,
            options,
            ..
        } = self;
        if let Some(refused) = target::refuse_options(
            provider,
            &[
                (
                    installation.is_some().then_some("--installation"),
                    &[Provider::Github],
                ),
                (instance.given(), &[Provider::Gitlab]),
                (gitlab.given(), &[Provider::Gitlab]),
                (linear.given(), &[Provider::Linear]),
                (
                    wait.timeout.is_some().then_some("--timeout"),
                    &[Provider::Gitlab, Provider::Linear],
                ),
            ],
        ) {
            return refused;
        }
        match provider {
            Provider::Github => {
                target::execute_in(org, options, deployment, |options, organization| {
                    match installation {
                        None => github::begin(deployment, &options, organization),
                        Some(id) => github::complete(deployment, &options, organization, &id),
                    }
                })
            }
            Provider::Gitlab => {
                let staged = gitlab.check(&options)?;
                target::execute_in(org, options, deployment, |options, organization| {
                    gitlab::create(
                        deployment,
                        options,
                        organization,
                        instance,
                        staged,
                        wait.timeout,
                    )
                })
            }
            Provider::Linear => {
                target::execute_in(org, options, deployment, |options, organization| {
                    linear::authorize(
                        deployment.clone(),
                        options,
                        organization.to_owned(),
                        None,
                        linear,
                        wait.timeout,
                    )
                })
            }
        }
    }
}

impl Command {
    /// Stores the organization's token of `service` (REQ-INTEGRATION-16, REQ-INTEGRATION-17):
    /// the options of a connection are refused with exit 2 before any request, then the
    /// providers the deployment serves are read, and a name it serves as no token service is
    /// refused with exit 2, naming those it does, before any token is read.
    fn connect_token(self, deployment: &Deployment, service: &str) -> CommandResult {
        let unsuited = [
            self.installation.is_some().then_some("--installation"),
            self.instance.given(),
            self.gitlab.given(),
            self.linear.given(),
            self.wait.timeout.is_some().then_some("--timeout"),
        ]
        .into_iter()
        .flatten()
        .next();
        if let Some(option) = unsuited {
            return Err(CommandFailure::with_exit_code(
                anyhow!(
                    "{option} does not apply to a token service\n\nThe organization's {service} \
                     token is read from --from-file PATH, from standard input or at a prompt:\n  \
                     useful org integration connect {service}"
                ),
                ExitCode::UsageError,
            ));
        }
        member_session(
            &self.options.authentication,
            &format!(
                "{service}, which is not github, gitlab or linear and so can only name a token service"
            ),
        )?;
        let from_file = self.from_file;
        target::execute_in(
            self.org,
            self.options,
            deployment,
            |options, organization| {
                let policy = options.http.transport_policy();
                let served =
                    match with_human_session_api(deployment, policy, |api: &MemberGrantApi| {
                        integration_token::served(api)
                    })? {
                        Ok(served) => served,
                        Err(failure) => {
                            let api_url = deployment.fingerprint().api_url();
                            return Ok(integration_token::write_refusal(
                                api_url,
                                &crate::cli::account::grant::output::report(api_url, &failure),
                                options.json,
                            )?);
                        }
                    };
                let Some(served) = served.iter().find(|served| served.name == service) else {
                    return Err(not_served(service, &served));
                };
                OrgTokens {
                    deployment,
                    policy,
                    json: options.json,
                    organization,
                }
                .connect(served, from_file.as_deref())
            },
        )
    }
}

/// The refusal of `service`, which the deployment serves as no token service, naming the
/// providers and the token services that can be given.
fn not_served(service: &str, served: &[ServedTokenService]) -> CommandFailure {
    CommandFailure::with_exit_code(
        anyhow!(
            "{}",
            super::token::not_served(service, served, "useful org integration connect PROVIDER")
        ),
        ExitCode::UsageError,
    )
}

/// The refusal of `--from-file` for a connection at `provider`, which reads no token from it.
pub(super) fn from_file_refused(provider: Provider) -> CommandFailure {
    CommandFailure::with_exit_code(
        anyhow!(
            "--from-file does not apply to {}\n\n--from-file reads the organization's token of \
             a token service. Run the command without it.",
            provider.as_str()
        ),
        ExitCode::UsageError,
    )
}
