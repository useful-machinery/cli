//! Slack connection and channel reads, reported as warnings beside credential requirements.

use std::collections::{HashMap, hash_map::Entry};
use std::io::{self, Write};

use anyhow::anyhow;
use serde::Serialize;
use useful_api::{
    ResourceFailure, SlackApi, SlackChannelCheck, SlackChannelCheckReason, SlackChannelCheckState,
    SlackConnection, SlackFailure, UnreachableCategory, slack_connection::Status,
};
use useful_runner::{SlackChannelBinding, SlackDeclaration};

use crate::cli::CommandFailure;
use crate::cli::paging::every_page;
use crate::exit_code::ExitCode;

use super::readiness::{Ending, FamilyFailure, Session};

const PAGE_LIMIT: i32 = 100;
const CHANNEL_SCOPES: [&str; 3] = ["chat:write.public", "channels:read", "groups:read"];
const NETWORKING: &str = "prepare Slack connection networking";

pub(super) type Bindings = HashMap<String, String>;

/// Refuses an option that would not apply, or two options for the same binding.
pub(super) fn bindings(
    options: Vec<(String, String)>,
    declarations: &[SlackDeclaration],
) -> Result<Bindings, CommandFailure> {
    let mut bindings = Bindings::new();
    for (key, value) in options {
        if !declarations.iter().any(|declaration| {
            declaration
                .channel
                .as_ref()
                .is_some_and(|channel| channel.binding == key)
        }) {
            return Err(CommandFailure::with_exit_code(
                anyhow!(
                    "--binding {key:?} does not name a Slack channel binding in any named workflow"
                ),
                ExitCode::UsageError,
            ));
        }
        let Entry::Vacant(binding) = bindings.entry(key) else {
            return Err(CommandFailure::with_exit_code(
                anyhow!("--binding was given more than once for the same key"),
                ExitCode::UsageError,
            ));
        };
        binding.insert(value);
    }
    Ok(bindings)
}

impl FamilyFailure for SlackFailure {
    fn unauthenticated() -> Self {
        Self::unauthenticated()
    }

    fn unreachable(category: UnreachableCategory) -> Self {
        Self::unreachable(category)
    }

    fn invalid_response() -> Self {
        ResourceFailure::invalid_response().into()
    }

    fn credential_rejected(&self) -> bool {
        self.credential_rejected()
    }

    fn ending(&self) -> Option<Ending> {
        match self {
            Self::Resource(failure) => failure.ending(),
            Self::NotServed => Some(Ending::Unreachable(UnreachableCategory::Server)),
        }
    }
}

/// A failed Slack read or an unresolved organization. These never end the doctor.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ReadFailure {
    NotSignedIn,
    NoOrganization,
    NotPermitted,
    NotServed,
    RateLimited,
    Unreachable,
    InvalidResponse,
}

impl ReadFailure {
    fn verdict(self) -> Verdict {
        let (code, next_action) = match self {
            Self::NotSignedIn => ("not_signed_in", "Sign in with useful account login."),
            Self::NoOrganization => ("no_organization", "Name an organization with --org."),
            Self::NotPermitted => ("not_permitted", "Ask an organization owner to check Slack."),
            Self::NotServed => (
                "not_served",
                "Ask the deployment operator to configure Slack.",
            ),
            Self::RateLimited => ("rate_limited", "Try the doctor again later."),
            Self::Unreachable => ("unreachable", "Try again when Cloud can be reached."),
            Self::InvalidResponse => (
                "invalid_response",
                "Try again or report the unexpected Cloud response.",
            ),
        };
        Verdict::new("unverified", code, next_action)
    }
}

impl From<SlackFailure> for ReadFailure {
    fn from(failure: SlackFailure) -> Self {
        match failure {
            SlackFailure::NotServed => Self::NotServed,
            SlackFailure::Resource(ResourceFailure::Unauthenticated) => Self::NotSignedIn,
            SlackFailure::Resource(ResourceFailure::Forbidden) => Self::NotPermitted,
            SlackFailure::Resource(ResourceFailure::Unreachable { .. }) => Self::Unreachable,
            SlackFailure::Resource(ResourceFailure::RateLimited { .. }) => Self::RateLimited,
            SlackFailure::Resource(_) => Self::InvalidResponse,
        }
    }
}

pub(super) fn read(
    session: &Session<'_>,
    organization: &str,
    declarations: &[SlackDeclaration],
    bindings: &Bindings,
) -> Result<Option<Vec<SlackFinding>>, ReadFailure> {
    if declarations.is_empty() {
        return Ok(None);
    }
    let connections = session
        .call(SlackApi::new, NETWORKING, |api, org| {
            every_page(SlackFailure::invalid_response(), |cursor| {
                api.list(org, Some(PAGE_LIMIT), cursor)
                    .map(|page| (page.items, page.next_cursor))
            })
        })
        .map_err(|_| ReadFailure::Unreachable)??;
    // Cloud reserves at most one connection that is still in use for an organization.
    let connection = connections
        .iter()
        .find(|connection| connection.status != Status::Disconnected);
    let mut checks = HashMap::new();
    if let Some(connection) = connection.filter(|connection| can_check_channel(connection)) {
        for channel in declarations
            .iter()
            .filter_map(|declaration| declaration.channel.as_ref())
        {
            if let Some((value, _)) = channel_value(channel, bindings) {
                checks.entry(value).or_insert_with(|| {
                    session
                        .call(SlackApi::new, NETWORKING, |api, org| {
                            api.check_channel(org, &connection.id, value)
                        })
                        .map_err(|_| ReadFailure::Unreachable)?
                        .map_err(ReadFailure::from)
                });
            }
        }
    }
    Ok(Some(
        declarations
            .iter()
            .map(|declaration| {
                finding(
                    declaration,
                    bindings,
                    organization,
                    ConnectionRead::Listed(connection),
                    &checks,
                )
            })
            .collect(),
    ))
}

pub(super) fn unread(
    declarations: &[SlackDeclaration],
    bindings: &Bindings,
    failure: ReadFailure,
) -> Option<Vec<SlackFinding>> {
    without_checks(declarations, bindings, ConnectionRead::Unread(failure))
}

pub(super) fn list_failed(
    declarations: &[SlackDeclaration],
    bindings: &Bindings,
    failure: ReadFailure,
) -> Option<Vec<SlackFinding>> {
    without_checks(declarations, bindings, ConnectionRead::Failed(failure))
}

fn without_checks(
    declarations: &[SlackDeclaration],
    bindings: &Bindings,
    connection: ConnectionRead<'_>,
) -> Option<Vec<SlackFinding>> {
    (!declarations.is_empty()).then(|| {
        let checks = HashMap::new();
        declarations
            .iter()
            .map(|declaration| finding(declaration, bindings, "", connection, &checks))
            .collect()
    })
}

fn can_check_channel(connection: &SlackConnection) -> bool {
    connection.status == Status::Active
        && CHANNEL_SCOPES.iter().all(|scope| {
            connection
                .granted_scopes
                .iter()
                .any(|granted| granted == scope)
        })
}

fn channel_value<'a>(
    channel: &'a SlackChannelBinding,
    bindings: &'a Bindings,
) -> Option<(&'a str, &'static str)> {
    bindings
        .get(&channel.binding)
        .map(|value| (value.as_str(), "option"))
        .or_else(|| channel.default.as_deref().map(|value| (value, "default")))
}

#[derive(Serialize)]
pub(super) struct SlackFinding {
    workflow: String,
    connection: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<Channel>,
}

#[derive(Serialize)]
struct Channel {
    binding: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<&'static str>,
    #[serde(flatten)]
    verdict: Verdict,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Verdict {
    state: &'static str,
    code: &'static str,
    next_action: String,
}

impl Verdict {
    fn new(state: &'static str, code: &'static str, next_action: impl Into<String>) -> Self {
        Self {
            state,
            code,
            next_action: next_action.into(),
        }
    }

    fn write_human(&self, output: &mut impl Write, label: &str) -> io::Result<()> {
        let mark = if matches!(self.state, "ready" | "usable") {
            '✓'
        } else {
            '!'
        };
        writeln!(output, "  {mark} {label} · {} · {}", self.state, self.code)?;
        writeln!(output, "    {}", self.next_action)
    }
}

#[derive(Clone, Copy)]
enum ConnectionRead<'a> {
    Listed(Option<&'a SlackConnection>),
    Failed(ReadFailure),
    Unread(ReadFailure),
}

fn finding(
    declaration: &SlackDeclaration,
    bindings: &Bindings,
    organization: &str,
    connection: ConnectionRead<'_>,
    checks: &HashMap<&str, Result<SlackChannelCheck, ReadFailure>>,
) -> SlackFinding {
    let connection_verdict = match connection {
        ConnectionRead::Listed(connection) => {
            connection_verdict(connection, declaration.channel.is_some(), organization)
        }
        ConnectionRead::Failed(failure) | ConnectionRead::Unread(failure) => failure.verdict(),
    };
    let channel = declaration.channel.as_ref().map(|channel| {
        let value = channel_value(channel, bindings);
        let verdict = match (connection, value) {
            (ConnectionRead::Unread(failure), _) => failure.verdict(),
            (_, None) => Verdict::new(
                "not_checked",
                "no_value",
                format!("Give the channel with --binding {}=VALUE.", channel.binding),
            ),
            (_, Some((value, _))) => match checks.get(value) {
                Some(Ok(check)) => channel_verdict(check),
                Some(Err(failure)) => failure.verdict(),
                None => Verdict::new(
                    "not_checked",
                    "connection_not_ready",
                    connection_verdict.next_action.as_str(),
                ),
            },
        };
        Channel {
            binding: channel.binding.clone(),
            value: value.map(|(value, _)| value.to_owned()),
            from: value.map(|(_, from)| from),
            verdict,
        }
    });
    SlackFinding {
        workflow: declaration.workflow.clone(),
        connection: connection_verdict,
        channel,
    }
}

fn connection_verdict(
    connection: Option<&SlackConnection>,
    has_channel: bool,
    organization: &str,
) -> Verdict {
    let Some(connection) = connection else {
        return Verdict::new(
            "missing",
            "not_connected",
            format!("Run useful org integration connect slack --org {organization}."),
        );
    };
    let code = if connection.status == Status::RecoveryRequired {
        "connection_inactive"
    } else if has_channel && !can_check_channel(connection) {
        "channel_access_missing"
    } else {
        return Verdict::new(
            "ready",
            "connection_ready",
            "Cloud holds a ready Slack connection.",
        );
    };
    Verdict::new(
        "reconnect_required",
        code,
        format!(
            "Ask an organization owner to run useful org integration reconnect {} --org {organization}.",
            connection.id
        ),
    )
}

fn channel_verdict(check: &SlackChannelCheck) -> Verdict {
    use SlackChannelCheckReason as Reason;

    let state = match check.state {
        SlackChannelCheckState::Usable => {
            return Verdict::new(
                "usable",
                "channel_usable",
                "The Slack app can post to this channel.",
            );
        }
        SlackChannelCheckState::Unusable => "unusable",
        SlackChannelCheckState::Unverified => "unverified",
    };
    let (code, next_action) = match check.reason {
        Some(Reason::ChannelNotFound) => (
            "channel_not_found",
            "The channel may be private with the app outside it. Invite the app or bind the channel's ID.",
        ),
        Some(Reason::ChannelArchived) => ("channel_archived", "Choose an active Slack channel."),
        Some(Reason::NotInChannel) => ("not_in_channel", "Invite the Slack app to the channel."),
        Some(Reason::ChannelRestricted) => (
            "channel_restricted",
            "Allow the Slack app to post to this channel or choose another channel.",
        ),
        Some(Reason::PermissionMissing) => (
            "permission_missing",
            "Ask an organization owner to reconnect Slack with channel access.",
        ),
        Some(Reason::CredentialRefused) => (
            "credential_refused",
            "Ask an organization owner to reconnect Slack.",
        ),
        Some(Reason::CredentialUnavailable) => (
            "credential_unavailable",
            "Check the Slack connection and try again.",
        ),
        Some(Reason::RateLimited) => ("rate_limited", "Try the doctor again later."),
        Some(Reason::SlackUnavailable) => {
            ("slack_unavailable", "Try again when Slack can be reached.")
        }
        Some(Reason::SlackRejected) => (
            "slack_rejected",
            "Check the channel in Slack and try again.",
        ),
        None => return ReadFailure::InvalidResponse.verdict(),
    };
    Verdict::new(state, code, next_action)
}

pub(super) fn write_human(output: &mut impl Write, findings: &[SlackFinding]) -> io::Result<()> {
    writeln!(output, "── slack ──")?;
    writeln!(
        output,
        "Slack never blocks a run. These findings are warnings."
    )?;
    for finding in findings {
        writeln!(output, "{}", finding.workflow.escape_debug())?;
        finding.connection.write_human(output, "connection")?;
        if let Some(channel) = &finding.channel {
            let mut label = format!("channel {}", channel.binding.escape_debug());
            if let Some((value, from)) = channel.value.as_deref().zip(channel.from) {
                label.push_str(&format!(" = {} ({from})", value.escape_debug()));
            }
            channel.verdict.write_human(output, &label)?;
        }
    }
    writeln!(output)
}
