//! `INTEGRATION`: the connection a `useful org integration` leaf acts on, named by its ID or by
//! its provider.
use std::io::{self, Write};

use clap::ValueEnum;
use useful_api::{GitHubInstallationState, linear_connection::Status as LinearStatus};
use useful_human_auth::Deployment;

use super::list::{self, Provider, Record};
use crate::cli::context::{self, OrgArgs};
use crate::cli::{
    CommandFailure, CommandResult, CommonArgs, JsonOutputKind, PrincipalAuthenticationArgs,
};
use crate::exit_code::ExitCode;

pub(in crate::cli) const VALUE_NAME: &str = "INTEGRATION";
pub(super) const HELP: &str = "Connection ID (ghi_, glc_, lcn_ or scn_), or github, gitlab, linear or slack for the organization's connection to it";

/// A connection as the command line names it, parsed with no request.
#[derive(Clone, Debug)]
pub(in crate::cli) enum Target {
    /// A connection's ID, whose prefix names its provider.
    Id(Provider, String),
    /// A provider, naming the organization's one connection to it still in use.
    Provider(Provider),
}

impl Target {
    pub(in crate::cli) fn parse(value: &str) -> Result<Self, String> {
        if let Ok(provider) = Provider::from_str(value, false) {
            return Ok(Self::Provider(provider));
        }
        Provider::ALL
            .into_iter()
            .find(|provider| useful_support::valid_typed_id(value, prefix(*provider)))
            .map(|provider| Self::Id(provider, value.to_owned()))
            .ok_or_else(|| {
                "connection must be an exact ghi_, glc_, lcn_ or scn_ identifier, or github, gitlab, linear or \
                 slack"
                    .to_owned()
            })
    }

    /// The provider the target names, known before any request.
    pub(in crate::cli) const fn provider(&self) -> Provider {
        match self {
            Self::Id(provider, _) | Self::Provider(provider) => *provider,
        }
    }
}

/// What `INTEGRATION` names on a leaf that also acts on the organization's token of a token
/// service: a connection, or a token by its service, any provider id that is neither a built-in
/// provider's nor `github`, `gitlab`, `linear` or `slack`.
#[derive(Clone, Debug)]
pub(in crate::cli) enum Integration {
    Connection(Target),
    Token(String),
}

impl Integration {
    pub(super) const HELP: &'static str = "Connection ID (ghi_, glc_, lcn_ or scn_), github, gitlab, linear or slack for the organization's connection to it, or a token service for the organization's token of it";

    pub(super) fn parse(value: &str) -> Result<Self, String> {
        Target::parse(value).map(Self::Connection).or_else(|_| {
            (useful_api::valid_provider_id(value)
                && useful_api::MemberGrantProvider::from_wire(value).is_none())
            .then(|| Self::Token(value.to_owned()))
            .ok_or_else(|| {
                "integration must be an exact ghi_, glc_, lcn_ or scn_ identifier, github, gitlab, linear or \
                 slack, or a token service's name"
                    .to_owned()
            })
        })
    }
}

/// What a connection of `provider` is called in a refusal.
const fn noun(provider: Provider) -> &'static str {
    match provider {
        Provider::Github => "a GitHub binding",
        Provider::Gitlab => "a GitLab connection",
        Provider::Linear => "a Linear connection",
        Provider::Slack => "a Slack connection",
    }
}

/// Refuses `subject`, a command or one of its options, given a connection of `given` where it
/// takes a connection of `needed` alone: a usage error written before any request, naming the
/// provider it needs, with `remedy` as its remedy.
pub(in crate::cli) fn refuse(
    subject: &str,
    needed: &[Provider],
    given: Provider,
    remedy: &str,
) -> CommandResult {
    let needed = needed
        .iter()
        .map(|provider| noun(*provider))
        .collect::<Vec<_>>()
        .join(" or ");
    writeln!(
        io::stderr().lock(),
        "error: {subject} takes {needed}, not {}\n\n{remedy}",
        noun(given)
    )
    .map_err(anyhow::Error::from)?;
    Ok(ExitCode::UsageError)
}

/// Refuses the first of `options` given, each paired with the providers that take it, that a
/// connection of `given` does not take; `None` when there is none.
pub(super) fn refuse_options(
    given: Provider,
    options: &[(Option<&'static str>, &[Provider])],
) -> Option<CommandResult> {
    options.iter().find_map(|(option, takes)| {
        option.filter(|_| !takes.contains(&given)).map(|option| {
            refuse(
                option,
                takes,
                given,
                &format!("Run the command without {option}."),
            )
        })
    })
}

/// The remedy of a command refused a connection of another provider.
pub(in crate::cli) const NAME_ANOTHER: &str = "Name the connection by its ID or its provider. List the organization's connections:\n  useful org integration list";

/// Runs `run` in the organization in effect. A failure `run` ends with keeps its exit code.
pub(super) fn execute_in<F: JsonOutputKind, E: Into<CommandFailure>>(
    org: OrgArgs,
    options: CommonArgs<F, PrincipalAuthenticationArgs>,
    deployment: &Deployment,
    run: impl FnOnce(CommonArgs<F, PrincipalAuthenticationArgs>, &str) -> Result<ExitCode, E>,
) -> CommandResult {
    context::execute_in_keeping_exit(
        org,
        options,
        deployment,
        super::super::output::write_context_failure,
        run,
    )
}

/// Runs `run` on the connection `target` names in the organization in effect, once resolved. A
/// failure `run` ends with keeps its exit code.
pub(super) fn execute<F: JsonOutputKind, E: Into<CommandFailure>>(
    target: Target,
    org: OrgArgs,
    options: CommonArgs<F, PrincipalAuthenticationArgs>,
    deployment: &Deployment,
    run: impl FnOnce(CommonArgs<F, PrincipalAuthenticationArgs>, &str, Resolved) -> Result<ExitCode, E>,
) -> CommandResult {
    execute_in(
        org,
        options,
        deployment,
        |options, organization| match resolve(target, deployment, &options, organization)? {
            Ok(resolved) => run(options, organization, resolved).map_err(Into::into),
            Err(exit) => Ok(exit),
        },
    )
}

const fn prefix(provider: Provider) -> &'static str {
    match provider {
        Provider::Github => "ghi_",
        Provider::Gitlab => "glc_",
        Provider::Linear => "lcn_",
        Provider::Slack => "scn_",
    }
}

/// The connection a target names: an ID as given, or the record its provider's list holds.
pub(in crate::cli) enum Resolved {
    Id(Provider, String),
    Listed(Record),
}

impl Resolved {
    pub(in crate::cli) const fn provider(&self) -> Provider {
        match self {
            Self::Id(provider, _) => *provider,
            Self::Listed(record) => record.provider(),
        }
    }

    pub(in crate::cli) fn id(&self) -> &str {
        match self {
            Self::Id(_, id) => id,
            Self::Listed(record) => record.id(),
        }
    }
}

/// The connection `target` names in `organization`. An ID resolves with no request. A provider
/// reads that provider's list and names its one connection in use, or else its only one; when
/// the list is refused, or names no or several connections, the refusal is written and the exit
/// code the leaf ends with is returned, and nothing more is sent.
pub(in crate::cli) fn resolve<F: JsonOutputKind>(
    target: Target,
    deployment: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
) -> anyhow::Result<Result<Resolved, ExitCode>> {
    let provider = match target {
        Target::Id(provider, id) => return Ok(Ok(Resolved::Id(provider, id))),
        Target::Provider(provider) => provider,
    };
    let records = match list::read(provider, deployment, options, organization)? {
        Ok(records) => records,
        Err(refusal) => {
            return refusal.write(deployment, organization, options).map(Err);
        }
    };
    let (in_use, removed): (Vec<_>, Vec<_>) = records.into_iter().partition(in_use);
    let mut named = if in_use.is_empty() { removed } else { in_use };
    match named.len() {
        0 => {
            let name = provider.as_str();
            // The options `create` requires for the provider, so the remedy runs as written.
            let required = match provider {
                Provider::Gitlab => " --token-file PATH --kind KIND",
                Provider::Github | Provider::Linear | Provider::Slack => "",
            };
            writeln!(
                io::stderr().lock(),
                "error: the organization has no {name} connection\n\nCreate one:\n  useful org integration connect {name}{required}"
            )?;
            Ok(Err(ExitCode::GeneralFailure))
        }
        1 => Ok(Ok(Resolved::Listed(named.swap_remove(0)))),
        _ => {
            let mut error = io::stderr().lock();
            writeln!(
                error,
                "error: {} names more than one connection\n\nName the connection by its ID:",
                provider.as_str()
            )?;
            for record in &named {
                writeln!(error, "  {}", record.row())?;
            }
            Ok(Err(ExitCode::UsageError))
        }
    }
}

/// Whether a connection is still in use: not removed or revoked.
pub(in crate::cli) fn in_use(record: &Record) -> bool {
    match record {
        Record::Github(installation) => {
            matches!(installation.state, GitHubInstallationState::Active)
        }
        Record::Gitlab(connection) => {
            matches!(
                connection["state"].as_str(),
                Some("active" | "credential_required")
            )
        }
        Record::Slack(connection) => matches!(
            connection.status,
            useful_api::slack_connection::Status::Active
                | useful_api::slack_connection::Status::RecoveryRequired
        ),
        Record::Linear(connection) => matches!(
            connection.status,
            LinearStatus::Active | LinearStatus::RecoveryRequired
        ),
    }
}
