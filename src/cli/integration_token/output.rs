//! How a token service's token is printed: the record's view, which every command that shows a
//! token prints, the report of a token connected, replaced, shown or revoked, and a refusal with
//! its remedy. Only the record's named fields are printed, so nothing an answer adds beyond the
//! model, a token least of all, reaches output.

use std::collections::BTreeMap;
use std::io::{self, Write};

use anyhow::Context;
use serde::{Serialize, Serializer};

use super::super::ApiFailureReport;
use crate::exit_code::ExitCode;
use useful_api::{IntegrationToken, IntegrationTokenAuthorization, IntegrationTokenSide};
use useful_execution::visible_text;

/// The organization whose token it is: its ID, which a token always states, and its slug where
/// the command was given one.
#[derive(Serialize)]
struct OrganizationView<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slug: Option<&'a str>,
}

impl<'a> OrganizationView<'a> {
    /// The view of the organization `id` names, with `slug` where it says more than the ID.
    fn new(id: Option<&'a str>, slug: Option<&'a str>) -> Self {
        Self {
            id,
            slug: slug.filter(|slug| Some(*slug) != id),
        }
    }
}

/// Writes the line that states a token's side and, for an organization's, the organization,
/// whose slug is another party's text and is printed visibly.
fn write_side(
    output: &mut impl Write,
    side: &str,
    organization: Option<&OrganizationView<'_>>,
) -> io::Result<()> {
    match organization.map(|organization| (organization.id, organization.slug)) {
        Some((Some(id), Some(slug))) => {
            writeln!(output, "side: {side} · {} ({id})", visible_text(slug))
        }
        Some((Some(id), None)) => writeln!(output, "side: {side} · {id}"),
        Some((None, Some(slug))) => writeln!(output, "side: {side} · {}", visible_text(slug)),
        Some((None, None)) | None => writeln!(output, "side: {side}"),
    }
}

/// A token's record as a command prints it: its ID, service, side and organization, version,
/// who connected it and when, and the runners it is authorized for.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenView<'a> {
    id: &'a str,
    service: &'a str,
    side: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization: Option<OrganizationView<'a>>,
    version: i64,
    connected_by: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    connected_by_name: Option<&'a str>,
    connected_at: &'a str,
    created_at: &'a str,
    authorizations: Vec<TokenAuthorizationView<'a>>,
}

/// A runner a token is authorized for.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenAuthorizationView<'a> {
    id: &'a str,
    runner_id: &'a str,
    runner_name: &'a str,
    organization_id: &'a str,
    created_at: &'a str,
}

impl<'a> TokenAuthorizationView<'a> {
    fn new(authorization: &'a IntegrationTokenAuthorization) -> Self {
        Self {
            id: &authorization.id,
            runner_id: &authorization.runner_id,
            runner_name: &authorization.runner_name,
            organization_id: &authorization.organization_id,
            created_at: &authorization.created_at,
        }
    }
}

/// The side a token states: `member` for the member's own, `org` for an organization's.
pub(in crate::cli) const fn side(token: &IntegrationToken) -> &'static str {
    match token.side {
        IntegrationTokenSide::IntegrationTokenSideMember => "member",
        IntegrationTokenSide::IntegrationTokenSideOrg => "org",
    }
}

impl<'a> TokenView<'a> {
    /// The view of `token`; for an organization's token `slug` is its slug where that is known,
    /// and `connected_by_name` the name the organization's directory gives who connected it.
    fn new(
        token: &'a IntegrationToken,
        slug: Option<&'a str>,
        connected_by_name: Option<&'a str>,
    ) -> Self {
        let organization = match token.side {
            IntegrationTokenSide::IntegrationTokenSideMember => None,
            IntegrationTokenSide::IntegrationTokenSideOrg => token
                .organization_id
                .as_deref()
                .map(|id| OrganizationView::new(Some(id), slug)),
        };
        Self {
            id: &token.id,
            service: &token.provider,
            side: side(token),
            organization,
            version: token.version,
            connected_by: &token.connected_by,
            connected_by_name,
            connected_at: &token.connected_at,
            created_at: &token.created_at,
            authorizations: token
                .authorizations
                .iter()
                .map(TokenAuthorizationView::new)
                .collect(),
        }
    }

    /// Writes the line that states the token's side and, for an organization's, the
    /// organization.
    fn write_side(&self, output: &mut impl Write) -> io::Result<()> {
        write_side(output, self.side, self.organization.as_ref())
    }

    /// Writes the view's lines of a human report. What Cloud names, a slug, a person and a
    /// runner, is another party's text and is printed visibly; the member's own token is said to
    /// be theirs.
    fn write_human(&self, output: &mut impl Write) -> io::Result<()> {
        writeln!(output, "token: {}", self.id)?;
        writeln!(output, "service: {}", self.service)?;
        self.write_side(output)?;
        writeln!(output, "version: {}", self.version)?;
        let by = self.connected_by;
        match (self.organization.is_some(), self.connected_by_name) {
            (false, _) => writeln!(output, "connected by: you ({by})")?,
            (true, Some(name)) => writeln!(output, "connected by: {} ({by})", visible_text(name))?,
            (true, None) => writeln!(output, "connected by: {by}")?,
        }
        writeln!(output, "connected at: {}", self.connected_at)?;
        if self.authorizations.is_empty() {
            writeln!(output, "runners: none")?;
        }
        for authorization in &self.authorizations {
            writeln!(
                output,
                "runner: {} ({})",
                visible_text(authorization.runner_name),
                authorization.runner_id
            )?;
        }
        Ok(())
    }
}

/// A token as a command prints it: the record, the slug of its organization where a read gave
/// one, and the name the organization's directory gives who connected it.
pub(in crate::cli) struct ListedToken {
    token: IntegrationToken,
    slug: Option<String>,
    connected_by_name: Option<String>,
}

impl ListedToken {
    /// The member's own token, which they connected: no directory names them.
    pub(in crate::cli) const fn member(token: IntegrationToken) -> Self {
        Self {
            token,
            slug: None,
            connected_by_name: None,
        }
    }

    /// An organization's token, of the organization a command named by `slug`, an ID or a slug,
    /// with who connected it named from `names`, the organization's directory by principal ID.
    pub(in crate::cli) fn organization(
        token: IntegrationToken,
        slug: &str,
        names: &BTreeMap<String, String>,
    ) -> Self {
        Self {
            connected_by_name: names.get(&token.connected_by).cloned(),
            slug: Some(slug.to_owned()),
            token,
        }
    }

    fn view(&self) -> TokenView<'_> {
        TokenView::new(
            &self.token,
            self.slug.as_deref(),
            self.connected_by_name.as_deref(),
        )
    }

    /// Reports the one token `show INTEGRATION` names, as the one document or a
    /// report.
    pub(in crate::cli) fn write_shown(
        &self,
        deployment: &str,
        json: bool,
    ) -> anyhow::Result<ExitCode> {
        let view = self.view();
        if json {
            write_json(&TokenResult {
                token: Some(view),
                ..TokenResult::new(deployment, "shown")
            })?;
            return Ok(ExitCode::Success);
        }
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "✓ Token shown.")?;
        view.write_human(&mut stdout)?;
        writeln!(stdout, "deployment: {deployment}")?;
        stdout.flush()?;
        Ok(ExitCode::Success)
    }
}

/// The tokens a list read, in the order it prints them.
#[derive(Default)]
pub(in crate::cli) struct Tokens(Vec<ListedToken>);

impl Tokens {
    /// The member's own tokens.
    pub(in crate::cli) fn member(tokens: Vec<IntegrationToken>) -> Self {
        Self(tokens.into_iter().map(ListedToken::member).collect())
    }

    /// The tokens of the organization a command named by `slug`, as
    /// [`ListedToken::organization`] names each.
    pub(in crate::cli) fn organization(
        tokens: Vec<IntegrationToken>,
        slug: &str,
        names: &BTreeMap<String, String>,
    ) -> Self {
        Self(
            tokens
                .into_iter()
                .map(|token| ListedToken::organization(token, slug, names))
                .collect(),
        )
    }

    /// Writes each token's section of a human report.
    pub(in crate::cli) fn write_human(&self, output: &mut impl Write) -> io::Result<()> {
        for token in &self.0 {
            writeln!(output, "\n── token ──")?;
            token.view().write_human(output)?;
        }
        Ok(())
    }
}

impl Serialize for Tokens {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(ListedToken::view))
    }
}

/// The one document `connect`, `reconnect` and `show` print for a token service: the token
/// connected, replaced or shown, or the refusal that stored nothing.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenResult<'a> {
    schema_version: u8,
    event: &'static str,
    deployment: &'a str,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<TokenView<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after: Option<u64>,
}

impl<'a> TokenResult<'a> {
    const fn new(deployment: &'a str, outcome: &'static str) -> Self {
        Self {
            schema_version: 1,
            event: "token_result",
            deployment,
            outcome,
            token: None,
            category: None,
            retry_after: None,
        }
    }
}

/// Reports the token `connect` stored, or the next version `reconnect` stored where it
/// `replaced` the one held, of the organization `slug` names where one was named.
pub(super) fn write_connected(
    deployment: &str,
    token: &IntegrationToken,
    slug: Option<&str>,
    replaced: bool,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let view = TokenView::new(token, slug, None);
    let outcome = if replaced { "replaced" } else { "connected" };
    if json {
        write_json_line(&TokenResult {
            token: Some(view),
            ..TokenResult::new(deployment, outcome)
        })?;
        return Ok(ExitCode::Success);
    }
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "✓ Token {outcome}.")?;
    view.write_human(&mut stdout)?;
    writeln!(stdout, "deployment: {deployment}")?;
    if replaced {
        writeln!(
            stdout,
            "\nA runner authorized for this token takes the new version at its next request, \
             within five minutes on a running assignment."
        )?;
    }
    stdout.flush()?;
    Ok(ExitCode::Success)
}

/// Reports a refusal that stored no token: as the command's one document, or on standard error
/// with its remedy.
pub(in crate::cli) fn write_refusal(
    deployment: &str,
    report: &ApiFailureReport,
    json: bool,
) -> anyhow::Result<ExitCode> {
    if json {
        write_json_line(&TokenResult {
            category: report.category,
            retry_after: report.retry_after,
            ..TokenResult::new(deployment, report.outcome)
        })?;
    } else {
        writeln!(
            io::stderr().lock(),
            "{}\n\n{}",
            report.summary,
            report.remedy
        )?;
    }
    Ok(report.class.exit_code())
}

/// The document `disconnect` prints for a token.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RevokedResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    integration_token_id: &'a str,
    service: &'a str,
    side: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization: Option<OrganizationView<'a>>,
}

/// Reports `token`, of the organization `slug` names where one was named, which `disconnect`
/// erased from Cloud; it stays valid at the service.
pub(in crate::cli) fn write_revoked(
    deployment: &str,
    token: &IntegrationToken,
    slug: Option<&str>,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let view = TokenView::new(token, slug, None);
    if json {
        write_json(&RevokedResult {
            schema_version: 1,
            deployment,
            outcome: "revoked",
            integration_token_id: view.id,
            service: view.service,
            side: view.side,
            organization: view.organization,
        })?;
        return Ok(ExitCode::Success);
    }
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "✓ Token revoked.")?;
    writeln!(stdout, "token: {}", view.id)?;
    writeln!(stdout, "service: {}", view.service)?;
    view.write_side(&mut stdout)?;
    writeln!(stdout, "deployment: {deployment}")?;
    writeln!(
        stdout,
        "\nThis does not end the token at the service. To end it, revoke it there."
    )?;
    stdout.flush()?;
    Ok(ExitCode::Success)
}

/// Writes one indented document, as a token's list, show and revocation print it.
fn write_json(value: &impl Serialize) -> anyhow::Result<()> {
    super::super::write_pretty_json(value).context("write JSON integration token result")
}

/// Writes one compact event line, as `connect` and `reconnect` print theirs.
fn write_json_line(value: &impl Serialize) -> anyhow::Result<()> {
    super::super::write_json_line(value).context("write JSON integration token event")
}
