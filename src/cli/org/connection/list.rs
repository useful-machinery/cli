//! `useful org integration list`: the organization's connections to every provider in one
//! list, each with the runners' authorizations in force for it, then the organization's
//! tokens.
use std::io::{self, Write};

use anyhow::Context;
use clap::{Args, ValueEnum};
use serde::Serialize;
use serde_json::Value;
use useful_api::{
    GitHubFailure, GitHubInstallation, GitLabFailure, LinearConnection, LinearFailure,
    ResourceFailure, SlackConnection, SlackFailure, UnreachableCategory,
};
use useful_human_auth::Deployment;

use super::authorization::{self, InForce};
use super::token::OrgTokens;
use super::{github, gitlab, linear, slack};
use crate::cli::account::grant::output as grant_output;
use crate::cli::context::{self, OrgArgs};
use crate::cli::integration_token::Tokens;
use crate::cli::paging::every_page;
use crate::cli::{
    CommandResult, CommonArgs, ConnectionJson, JsonOutputKind, PrincipalAuthenticationArgs,
    PrincipalAuthenticationKind,
};
use crate::exit_code::ExitCode;

pub(super) const ABOUT: &str =
    "List the organization's connections with their authorizations, and its tokens";
/// The page size the paginated connection routes serve.
const PAGE: i32 = 100;

pub(super) type Options = CommonArgs<ConnectionJson, PrincipalAuthenticationArgs>;

#[derive(Debug, Args)]
pub(super) struct Command {
    #[arg(
        long,
        value_enum,
        value_name = "PROVIDER",
        help = "List only this provider's connections"
    )]
    provider: Option<Provider>,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: Options,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(in crate::cli) enum Provider {
    Github,
    Gitlab,
    Linear,
    Slack,
}

impl Provider {
    /// Every provider, in the order the list prints them.
    pub(super) const ALL: [Self; 4] = [Self::Github, Self::Gitlab, Self::Linear, Self::Slack];

    pub(in crate::cli) const fn as_str(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Gitlab => "gitlab",
            Self::Linear => "linear",
            Self::Slack => "slack",
        }
    }

    /// The provider id a connection authorization names: GitLab's is `gitlab.com`.
    pub(in crate::cli) const fn wire(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Gitlab => "gitlab.com",
            Self::Linear => "linear",
            Self::Slack => "slack",
        }
    }
}

/// One connection as the list prints it, with the record its provider's route returned.
#[derive(Serialize)]
struct Item {
    provider: &'static str,
    id: String,
    state: String,
    name: Option<String>,
    connection: Value,
    // When a GitHub installation's authority was verified, or that it was not, which the report
    // prints on its row; `connection` carries `authorityVerifiedAt`.
    #[serde(skip)]
    authority: Option<String>,
    // The runners' authorizations in force for the connection, where the organization's were
    // read and answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    authorizations: Option<InForce>,
}

/// A provider whose list was not read, and why.
#[derive(Serialize)]
struct Unlisted {
    provider: &'static str,
    reason: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Listed<'a> {
    schema_version: u8,
    deployment: &'a str,
    organization_ref: &'a str,
    outcome: &'static str,
    items: &'a [Item],
    unlisted: &'a [Unlisted],
    tokens: &'a Tokens,
}

/// A provider's refusal of its list, written as that provider's own commands write it.
pub(in crate::cli) enum Refusal {
    Github(GitHubFailure),
    Gitlab(GitLabFailure),
    Linear(LinearFailure),
    Slack(SlackFailure),
}

impl Refusal {
    /// Why the provider is named as not listed: the caller may not read its list, or the
    /// deployment does not serve it. `None` for a refusal that ends the command.
    pub(in crate::cli) const fn unlisted_reason(&self) -> Option<&'static str> {
        match self {
            Self::Github(GitHubFailure::Forbidden)
            | Self::Gitlab(GitLabFailure::Forbidden)
            | Self::Slack(SlackFailure::Resource(ResourceFailure::Forbidden))
            | Self::Linear(LinearFailure::Forbidden) => Some("forbidden"),
            // GitHub's and Linear's clients classify every 5xx answer, a 503 among them, as an
            // unreachable server; GitLab's names a deployment without the capability apart.
            Self::Github(GitHubFailure::Unreachable(UnreachableCategory::Server))
            | Self::Slack(SlackFailure::NotServed)
            | Self::Gitlab(GitLabFailure::ServiceUnavailable)
            | Self::Linear(LinearFailure::Unreachable {
                category: UnreachableCategory::Server,
            }) => Some("service_unavailable"),
            _ => None,
        }
    }

    pub(in crate::cli) fn write<F: JsonOutputKind>(
        self,
        deployment: &Deployment,
        organization: &str,
        options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    ) -> anyhow::Result<ExitCode> {
        let authentication = options.authentication.kind();
        match self {
            Self::Github(failure) => github::write_list_failure(
                deployment.fingerprint().api_url(),
                organization,
                &failure,
                authentication,
                options.json,
            ),
            Self::Gitlab(failure) => {
                gitlab::failure(deployment, organization, options.json, failure, None)
            }
            Self::Slack(failure) => slack::failure_output(
                deployment,
                organization,
                None,
                None,
                &failure,
                authentication,
                options.json,
            ),
            Self::Linear(failure) => linear::failure_output(
                deployment,
                organization,
                None,
                None,
                &failure,
                authentication,
                options.json,
            ),
        }
    }
}

impl Command {
    pub(super) fn execute(self, deployment: &Deployment) -> CommandResult {
        let Self {
            provider,
            org,
            options,
        } = self;
        context::execute_in(
            org,
            options,
            deployment,
            super::super::output::write_context_failure,
            |options, organization| list(deployment, &options, organization, provider),
        )
    }
}

/// Reads each provider's list, or `only`'s, and prints the connections in one list. A provider
/// refused as forbidden or unserved is named as not listed while another was read; any other
/// refusal, or a refusal of every provider read, ends the command with the first.
fn list(
    deployment: &Deployment,
    options: &Options,
    organization: &str,
    only: Option<Provider>,
) -> anyhow::Result<ExitCode> {
    let providers = only
        .as_ref()
        .map_or(&Provider::ALL[..], std::slice::from_ref);
    let mut items = Vec::new();
    let mut unlisted = Vec::new();
    let mut first_refusal = None;
    let mut listed_any = false;
    for &provider in providers {
        match read(provider, deployment, options, organization)? {
            Ok(listed) => {
                for record in &listed {
                    items.push(record.item()?);
                }
                listed_any = true;
            }
            Err(refusal) => {
                let Some(reason) = refusal.unlisted_reason() else {
                    return refusal.write(deployment, organization, options);
                };
                unlisted.push(Unlisted {
                    provider: provider.as_str(),
                    reason,
                });
                first_refusal.get_or_insert(refusal);
            }
        }
    }
    if !listed_any && let Some(refusal) = first_refusal {
        return refusal.write(deployment, organization, options);
    }
    let api_url = deployment.fingerprint().api_url();
    // The authorizations and the tokens are read under the member's session alone: a service
    // API key reaches neither.
    let session = options.authentication.kind() == PrincipalAuthenticationKind::HumanSession;
    let policy = options.http.transport_policy();
    let mut authorizable = items
        .iter_mut()
        .filter(|item| item.provider != Provider::Slack.as_str())
        .peekable();
    if session && authorizable.peek().is_some() {
        match authorization::in_force(deployment, policy, organization, None)? {
            Ok(Some(authorizations)) => {
                for item in authorizable {
                    item.authorizations = Some(InForce::of(&authorizations, &item.id));
                }
            }
            Ok(None) => {}
            Err(failure) => {
                return grant_output::report(api_url, &failure).write(api_url, options.json);
            }
        }
    }
    // `--provider` keeps one provider's connections, and no token.
    let tokens = if session && only.is_none() {
        let tokens = OrgTokens {
            deployment,
            policy,
            json: options.json,
            organization,
        };
        match tokens.listed()? {
            Ok(tokens) => tokens,
            Err(failure) => {
                return grant_output::report(api_url, &failure).write(api_url, options.json);
            }
        }
    } else {
        Tokens::default()
    };
    write_list(
        api_url,
        organization,
        &items,
        &unlisted,
        &tokens,
        options.json,
    )?;
    Ok(ExitCode::Success)
}

/// A connection as its provider's list returned it.
pub(in crate::cli) enum Record {
    Github(GitHubInstallation),
    Gitlab(Value),
    // Boxed: a Linear connection is several times the size of the other records.
    Linear(Box<LinearConnection>),
    Slack(Box<SlackConnection>),
}

impl Record {
    pub(in crate::cli) const fn provider(&self) -> Provider {
        match self {
            Self::Github(_) => Provider::Github,
            Self::Gitlab(_) => Provider::Gitlab,
            Self::Linear(_) => Provider::Linear,
            Self::Slack(_) => Provider::Slack,
        }
    }

    pub(in crate::cli) fn id(&self) -> &str {
        match self {
            Self::Github(installation) => &installation.id,
            Self::Gitlab(connection) => connection["id"].as_str().unwrap_or_default(),
            Self::Linear(connection) => &connection.id,
            Self::Slack(connection) => &connection.id,
        }
    }

    pub(in crate::cli) fn state(&self) -> &str {
        match self {
            Self::Github(installation) => github::installation_state(installation.state),
            Self::Gitlab(connection) => connection["state"].as_str().unwrap_or_default(),
            Self::Linear(connection) => linear::status(&connection.status),
            Self::Slack(connection) => slack::status(connection.status),
        }
    }

    /// The GitHub account's login, the GitLab instance's URL or the Linear workspace's name.
    fn name(&self) -> Option<&str> {
        match self {
            Self::Github(installation) => Some(&installation.provider_account_login),
            Self::Gitlab(connection) => connection["instanceUrl"].as_str(),
            Self::Linear(connection) => connection.workspace_name.as_deref(),
            Self::Slack(connection) => Some(&connection.workspace_name),
        }
    }

    /// The account the connection acts as: the GitHub account's login, the GitLab bot user's
    /// username or the Linear workspace's name, where the record names one.
    pub(in crate::cli) fn account(&self) -> Option<&str> {
        match self {
            Self::Github(installation) => Some(&installation.provider_account_login),
            Self::Gitlab(connection) => connection["providerUser"]["username"].as_str(),
            Self::Linear(connection) => connection.workspace_name.as_deref(),
            Self::Slack(connection) => Some(&connection.workspace_name),
        }
    }

    /// The connection's ID, provider, state and name as a list row prints them.
    pub(in crate::cli) fn row(&self) -> String {
        row(
            self.id(),
            self.provider().as_str(),
            self.state(),
            self.name(),
        )
    }

    fn item(&self) -> anyhow::Result<Item> {
        let connection = match self {
            Self::Github(installation) => serde_json::to_value(installation)
                .context("serialize GitHub installation binding")?,
            Self::Gitlab(connection) => connection.clone(),
            Self::Slack(connection) => slack::connection_view(connection),
            Self::Linear(connection) => serde_json::to_value(linear::connection_view(connection))
                .context("serialize Linear connection")?,
        };
        Ok(Item {
            provider: self.provider().as_str(),
            id: self.id().to_owned(),
            state: self.state().to_owned(),
            name: self.name().map(str::to_owned),
            connection,
            authority: match self {
                Self::Github(installation) => Some(github::authority(installation)),
                Self::Gitlab(_) | Self::Linear(_) | Self::Slack(_) => None,
            },
            authorizations: None,
        })
    }
}

/// The connections of `provider` in the order its route returned them, every page read.
pub(in crate::cli) fn read<F: JsonOutputKind>(
    provider: Provider,
    deployment: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
) -> anyhow::Result<Result<Vec<Record>, Refusal>> {
    Ok(match provider {
        Provider::Github => github::with_api(
            deployment,
            options.http.transport_policy(),
            &options.authentication,
            |api| api.list_installations(organization),
        )?
        .map(|installations| installations.into_iter().map(Record::Github).collect())
        .map_err(Refusal::Github),
        Provider::Gitlab => gitlab::with_api(deployment, options, |api| {
            every_page(GitLabFailure::Protocol, |cursor| {
                let page = api.list(organization, Some(PAGE), cursor)?;
                let items = page["items"]
                    .as_array()
                    .ok_or(GitLabFailure::Protocol)?
                    .clone();
                Ok((items, page["nextCursor"].as_str().map(str::to_owned)))
            })
        })?
        .map(|connections| connections.into_iter().map(Record::Gitlab).collect())
        .map_err(Refusal::Gitlab),
        Provider::Slack => slack::with_api(deployment, options, |api| {
            let invalid = ResourceFailure::InvalidResponse {
                credential_rejected: false,
            }
            .into();
            every_page(invalid, |cursor| {
                let page = api.list(organization, Some(PAGE), cursor)?;
                Ok((page.items, page.next_cursor))
            })
        })?
        .map(|connections| {
            connections
                .into_iter()
                .map(|connection| Record::Slack(Box::new(connection)))
                .collect()
        })
        .map_err(Refusal::Slack),
        Provider::Linear => linear::with_api(deployment, options, |api| {
            let invalid = LinearFailure::InvalidResponse {
                credential_rejected: false,
            };
            every_page(invalid, |cursor| {
                let page = api.list(organization, Some(PAGE), cursor)?;
                Ok((page.items, page.next_cursor))
            })
        })?
        .map(|connections| {
            connections
                .into_iter()
                .map(|connection| Record::Linear(Box::new(connection)))
                .collect()
        })
        .map_err(Refusal::Linear),
    })
}

fn row(id: &str, provider: &str, state: &str, name: Option<&str>) -> String {
    format!(
        "{id}  {provider}  {state}  {}",
        name.unwrap_or("(no workspace)")
    )
}

fn write_list(
    deployment: &str,
    organization: &str,
    items: &[Item],
    unlisted: &[Unlisted],
    tokens: &Tokens,
    json: bool,
) -> anyhow::Result<()> {
    if json {
        return crate::cli::write_json_line(&Listed {
            schema_version: 1,
            deployment,
            organization_ref: organization,
            outcome: "listed",
            items,
            unlisted,
            tokens,
        })
        .context("write connection list");
    }
    let mut output = io::stdout().lock();
    writeln!(output, "✓ Connections listed.")?;
    for item in items {
        let row = row(&item.id, item.provider, &item.state, item.name.as_deref());
        match &item.authority {
            Some(authority) => writeln!(output, "{row}  authority {authority}")?,
            None => writeln!(output, "{row}")?,
        }
        if let Some(authorizations) = &item.authorizations {
            authorizations.write_human(&mut output, "  ")?;
        }
    }
    for provider in unlisted {
        writeln!(
            output,
            "not listed: {} ({})",
            provider.provider,
            provider.reason.replace('_', " ")
        )?;
    }
    tokens.write_human(&mut output)?;
    writeln!(output, "deployment: {deployment}")?;
    Ok(())
}
