//! A runner's authorization of a grant as the member reads it: what was last delivered to the
//! runner and what it reported, its availability and next action, and, once it ended, whether the
//! runner has confirmed removing its copy and the stop requested of the run it was serving.
//! `useful account integration list` prints it for a grant of either kind. The authorization of a
//! token `useful account integration authorize` makes is printed here too.

use std::collections::BTreeMap;
use std::io::{self, Write};

use anyhow::Context;
use serde::Serialize;

use crate::exit_code::ExitCode;

use useful_api::{
    AgentLoginReportState, GrantEndedAuthorization, IntegrationTokenAuthorization, MemberGrant,
    MemberGrantAuthorization,
};
use useful_execution::visible_text;

use super::projection::{Access, GrantRunner, MemberStatus, grant_subject};

/// A runner's authorization of a grant or agent login, in force or ended: the model's named
/// fields only, enums as their wire strings. Nothing a response adds beyond the model reaches
/// output.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::cli) struct AuthorizationView<'a> {
    pub(in crate::cli) id: &'a str,
    pub(in crate::cli) runner_id: &'a str,
    // The runner's name, which a token's authorization names.
    #[serde(skip_serializing_if = "Option::is_none")]
    runner_name: Option<&'a str>,
    // The runner's organization, which a grant's authorization names.
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_id: Option<&'a str>,
    created_at: &'a str,
    #[serde(flatten)]
    exchange: ExchangeView<'a>,
    #[serde(flatten)]
    status: Option<AccessStatus>,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExchangeView<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    delivery: Option<DeliveryView<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<ReportView<'a>>,
    #[serde(flatten)]
    last_use: Option<LastUseView<'a>>,
    #[serde(skip)]
    detailed: bool,
}

#[derive(Serialize)]
struct AccessStatus {
    access: Access,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    conflict: bool,
    #[serde(flatten)]
    status: MemberStatus,
}

impl AccessStatus {
    fn new(grant: &MemberGrant, runner: &GrantRunner<'_>) -> Self {
        Self {
            access: runner.access,
            conflict: runner.conflict,
            status: MemberStatus::new(runner.status(grant), grant_subject(grant)),
        }
    }

    fn write_human(&self, output: &mut impl Write, indent: &str) -> io::Result<()> {
        self.status.write_human(output, indent)?;
        writeln!(output, "{indent}access: {}", self.access.as_str())
    }
}

/// The runner's last authorization of the agent login, ended, with whether that runner has
/// confirmed removing the copy it kept and the stop requested of the run it was serving.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::cli) struct EndedAuthorizationView<'a> {
    #[serde(flatten)]
    pub(in crate::cli) authorization: AuthorizationView<'a>,
    ended_at: &'a str,
    pub(in crate::cli) removal: RemovalView<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::cli) stop: Option<StopView<'a>>,
}

/// The graceful cancellation Cloud requested of the run the runner was serving.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::cli) struct StopView<'a> {
    run_id: &'a str,
    cancellation_request_id: &'a str,
    requested_at: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::cli) struct RemovalView<'a> {
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    confirmed_at: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeliveryView<'a> {
    generation: i64,
    delivered_at: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportView<'a> {
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<i64>,
    #[serde(flatten)]
    last_use: Option<LastUseView<'a>>,
    reported_at: &'a str,
}

/// The last use the runner reported and, where Cloud holds it, when.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
struct LastUseView<'a> {
    last_use: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_use_at: Option<&'a str>,
}

// Native holds, including ended ones, carry the same exchange in each target's API model.
macro_rules! exchange_view {
    ($hold:expr, $detailed:expr) => {{
        let hold = $hold;
        let detailed = $detailed;
        let report = hold.report.as_deref();
        let last_use = report.and_then(|report| {
            report.last_use.map(|last_use| LastUseView {
                last_use: last_use.as_str(),
                last_use_at: report.last_use_at.as_deref(),
            })
        });
        ExchangeView {
            detailed,
            delivery: hold
                .delivery
                .as_deref()
                .filter(|_| detailed)
                .map(|delivery| DeliveryView {
                    generation: delivery.generation,
                    delivered_at: &delivery.delivered_at,
                }),
            report: report.filter(|_| detailed).map(|report| ReportView {
                state: report_state(report.state),
                generation: report.generation,
                last_use,
                reported_at: &report.reported_at,
            }),
            last_use: last_use.filter(|_| !detailed),
        }
    }};
}

/// A native grant's ended authorizations, as the agent login's are read.
pub(in crate::cli) fn ended_authorization_views(
    ended: &[GrantEndedAuthorization],
) -> Vec<EndedAuthorizationView<'_>> {
    ended
        .iter()
        .map(|ended| EndedAuthorizationView {
            authorization: AuthorizationView {
                id: &ended.id,
                runner_id: &ended.runner_id,
                runner_name: None,
                organization_id: None,
                created_at: &ended.created_at,
                exchange: exchange_view!(ended, true),
                status: None,
            },
            ended_at: &ended.ended_at,
            removal: RemovalView {
                state: ended.removal.state.as_str(),
                confirmed_at: ended.removal.confirmed_at.as_deref(),
            },
            stop: ended.stop.as_deref().map(|stop| StopView {
                run_id: &stop.run_id,
                cancellation_request_id: &stop.cancellation_request_id,
                requested_at: &stop.requested_at,
            }),
        })
        .collect()
}

impl EndedAuthorizationView<'_> {
    pub(in crate::cli) fn write_human(&self, output: &mut impl Write) -> io::Result<()> {
        self.authorization.write_heading(output)?;
        writeln!(output, "    ended: {}", self.ended_at)?;
        self.authorization.exchange.write_human(output, "    ")?;
        self.write_outcome(output, "    ")
    }

    /// The runner's removal state and the stop requested there, if any.
    pub(in crate::cli) fn write_outcome(
        &self,
        output: &mut impl Write,
        indent: &str,
    ) -> io::Result<()> {
        self.removal.write_human(output, indent)?;
        match &self.stop {
            Some(stop) => stop.write_human(output, indent),
            None => Ok(()),
        }
    }
}

impl StopView<'_> {
    pub(in crate::cli) fn write_human(
        &self,
        output: &mut impl Write,
        indent: &str,
    ) -> io::Result<()> {
        writeln!(
            output,
            "{indent}stop: run {} asked to stop at {} (cancellation request {})",
            self.run_id, self.requested_at, self.cancellation_request_id
        )
    }
}

impl RemovalView<'_> {
    pub(in crate::cli) fn write_human(
        &self,
        output: &mut impl Write,
        indent: &str,
    ) -> io::Result<()> {
        match self.confirmed_at {
            Some(confirmed_at) => {
                writeln!(output, "{indent}removal: {} at {confirmed_at}", self.state)
            }
            None => writeln!(output, "{indent}removal: {}", self.state),
        }
    }
}

impl<'a> AuthorizationView<'a> {
    /// The authorization of a token `useful account integration authorize` just made: the
    /// runner by ID and name, its organization and when. A token's runner reports nothing
    /// back, so there is no delivery or report.
    pub(in crate::cli) fn of_token(authorization: &'a IntegrationTokenAuthorization) -> Self {
        Self {
            id: &authorization.id,
            runner_id: &authorization.runner_id,
            runner_name: Some(&authorization.runner_name),
            organization_id: Some(&authorization.organization_id),
            created_at: &authorization.created_at,
            exchange: ExchangeView::default(),
            status: None,
        }
    }

    pub(in crate::cli) fn write_human(&self, output: &mut impl Write) -> io::Result<()> {
        self.write_heading(output)?;
        self.exchange.write_human(output, "    ")?;
        match &self.status {
            Some(status) => status.write_human(output, "    "),
            None => Ok(()),
        }
    }

    fn write_heading(&self, output: &mut impl Write) -> io::Result<()> {
        writeln!(output, "  authorization: {}", self.id)?;
        match self.runner_name {
            // Another party's text bound for a terminal.
            Some(name) => writeln!(
                output,
                "    runner: {} ({})",
                visible_text(name),
                self.runner_id
            )?,
            None => writeln!(output, "    runner: {}", self.runner_id)?,
        }
        if let Some(organization_id) = self.organization_id {
            writeln!(output, "    organization: {organization_id}")?;
        }
        writeln!(output, "    authorized: {}", self.created_at)
    }
}

impl ExchangeView<'_> {
    /// What was last delivered to the runner and what it last reported.
    fn write_human(&self, output: &mut impl Write, indent: &str) -> io::Result<()> {
        if !self.detailed {
            return self
                .last_use
                .map_or(Ok(()), |last_use| last_use.write_human(output, indent));
        }
        match &self.delivery {
            Some(delivery) => writeln!(
                output,
                "{indent}delivered: generation {} at {}",
                delivery.generation, delivery.delivered_at
            )?,
            None => writeln!(output, "{indent}delivered: never")?,
        }
        match &self.report {
            Some(ReportView {
                state,
                generation: Some(generation),
                reported_at,
                ..
            }) => writeln!(
                output,
                "{indent}reported: {state}, generation {generation} at {reported_at}"
            )?,
            Some(ReportView {
                state,
                generation: None,
                reported_at,
                ..
            }) => writeln!(output, "{indent}reported: {state} at {reported_at}")?,
            None => writeln!(output, "{indent}reported: never")?,
        }
        match self.report.as_ref().and_then(|report| report.last_use) {
            Some(last_use) => last_use.write_human(output, indent),
            None => Ok(()),
        }
    }
}

impl LastUseView<'_> {
    fn write_human(&self, output: &mut impl Write, indent: &str) -> io::Result<()> {
        match self.last_use_at {
            Some(last_use_at) => {
                writeln!(
                    output,
                    "{indent}last use: {} at {last_use_at}",
                    self.last_use
                )
            }
            None => writeln!(output, "{indent}last use: {}", self.last_use),
        }
    }
}

const fn report_state(state: AgentLoginReportState) -> &'static str {
    match state {
        AgentLoginReportState::AgentLoginReportStateReady => "ready",
        AgentLoginReportState::AgentLoginReportStateNotAuthorized => "not_authorized",
        AgentLoginReportState::AgentLoginReportStateRevoked => "revoked",
        AgentLoginReportState::AgentLoginReportStateForeignLogin => "foreign_login",
        AgentLoginReportState::AgentLoginReportStateUnsupportedTarget => "unsupported_target",
        AgentLoginReportState::AgentLoginReportStateStaleGeneration => "stale_generation",
        AgentLoginReportState::AgentLoginReportStateCloudUnavailable => "cloud_unavailable",
        AgentLoginReportState::AgentLoginReportStateInstallFailed => "install_failed",
    }
}

/// What a runner's removal state says, and no more.
pub(in crate::cli) fn write_removal_note(output: &mut impl Write) -> io::Result<()> {
    writeln!(
        output,
        "\nA runner whose removal is confirmed has removed the copy it kept; one still pending has not \
         yet confirmed. A confirmation covers only that copy: a step that ran there while the login \
         was installed could have copied it."
    )
}

/// What a stop is, and how to follow it with a command the CLI has.
pub(in crate::cli) fn write_stop_note(output: &mut impl Write) -> io::Result<()> {
    writeln!(
        output,
        "\nEach run asked to stop was sent a graceful cancellation request, whichever member started \
         it. To wait for a run's cancellation to settle:\n  useful workflow run cancel RUN --wait"
    )
}

/// Each runner a revoked native grant was authorized for, with its removal state and the stop
/// requested there, then what those say.
pub(in crate::cli) fn write_revoked_runners(
    output: &mut impl Write,
    ended: &[EndedAuthorizationView<'_>],
) -> io::Result<()> {
    writeln!(output, "\nrunners: {}", ended.len())?;
    for authorization in ended {
        writeln!(
            output,
            "  runner: {}",
            authorization.authorization.runner_id
        )?;
        authorization.write_outcome(output, "    ")?;
    }
    write_removal_note(output)?;
    if ended
        .iter()
        .any(|authorization| authorization.stop.is_some())
    {
        write_stop_note(output)?;
    }
    Ok(())
}

/// That revoking a native grant in Cloud leaves its session at the provider.
pub(in crate::cli) fn write_session_note(output: &mut impl Write) -> io::Result<()> {
    writeln!(
        output,
        "\nThis does not end the session at the provider. To end it, sign out of the coding agent there."
    )
}

/// What a runner's authorization was made or ended on, under the member its result names: a
/// grant, an integration token, or an organization's connection.
#[derive(Clone, Copy, Serialize)]
pub(in crate::cli) enum Holder<'a> {
    #[serde(rename = "grantId")]
    Grant(&'a str),
    #[serde(rename = "integrationTokenId")]
    IntegrationToken(&'a str),
    #[serde(rename = "connectionId")]
    Connection(&'a str),
}

impl Holder<'_> {
    /// What the holder is called in a sentence.
    pub(in crate::cli) const fn noun(self) -> &'static str {
        match self {
            Self::Grant(_) => "grant",
            Self::IntegrationToken(_) => "token",
            Self::Connection(_) => "connection",
        }
    }

    fn write_human(self, output: &mut impl Write) -> io::Result<()> {
        match self {
            Self::Grant(id) | Self::IntegrationToken(id) | Self::Connection(id) => {
                writeln!(output, "{}: {id}", self.noun())
            }
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub(super) enum AuthorizationTargetView<'a> {
    Runner(AuthorizationView<'a>),
    Pool(PoolAuthorizationView<'a>),
}

// The authorize command returns the target it just made, without a grant-status projection.
pub(super) use AuthorizationTargetView as MadeView;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PoolAuthorizationView<'a> {
    id: &'a str,
    runner_pool_id: &'a str,
    organization_id: &'a str,
    created_at: &'a str,
    runners: Vec<PoolRunner<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PoolRunner<'a> {
    runner_id: &'a str,
    #[serde(flatten)]
    status: Option<AccessStatus>,
    #[serde(flatten)]
    exchange: Option<ExchangeView<'a>>,
}

impl<'a> AuthorizationTargetView<'a> {
    pub(super) fn grant(authorization: &'a MemberGrantAuthorization) -> anyhow::Result<Self> {
        Self::new(authorization, None, false).context("authorization response omitted its target")
    }

    pub(super) fn new(
        authorization: &'a MemberGrantAuthorization,
        coverage: Option<(&MemberGrant, &BTreeMap<&str, GrantRunner<'_>>)>,
        detailed: bool,
    ) -> Option<Self> {
        let status = |id: &str| {
            let (grant, runners) = coverage?;
            Some(AccessStatus::new(grant, runners.get(id)?))
        };
        if let Some(pool) = &authorization.runner_pool_id {
            return Some(Self::Pool(PoolAuthorizationView {
                id: &authorization.id,
                runner_pool_id: pool,
                organization_id: &authorization.organization_id,
                created_at: &authorization.created_at,
                runners: authorization
                    .runners
                    .as_deref()?
                    .iter()
                    .map(|runner| PoolRunner {
                        runner_id: &runner.runner_id,
                        status: status(&runner.runner_id),
                        exchange: coverage.map(|_| exchange_view!(runner, detailed)),
                    })
                    .collect(),
            }));
        }
        let runner_id = authorization.runner_id.as_deref()?;
        // The creation response also carries the exchange on an idempotent replay.
        let mut exchange = exchange_view!(authorization, detailed || coverage.is_none());
        exchange.detailed = detailed;
        Some(Self::Runner(AuthorizationView {
            id: &authorization.id,
            runner_id,
            runner_name: None,
            organization_id: Some(&authorization.organization_id),
            created_at: &authorization.created_at,
            exchange,
            status: status(runner_id),
        }))
    }

    pub(super) fn write_human(&self, output: &mut impl Write) -> io::Result<()> {
        match self {
            Self::Runner(runner) => runner.write_human(output),
            Self::Pool(pool) => {
                writeln!(output, "  authorization: {}", pool.id)?;
                writeln!(output, "    pool: {} (personal)", pool.runner_pool_id)?;
                writeln!(output, "    organization: {}", pool.organization_id)?;
                writeln!(output, "    authorized: {}", pool.created_at)?;
                if pool.runners.is_empty() {
                    return writeln!(output, "    runners: none");
                }
                writeln!(output, "    runners: {}", pool.runners.len())?;
                for runner in &pool.runners {
                    if let Some(status) = &runner.status {
                        writeln!(output, "      runner: {}", runner.runner_id)?;
                        status.write_human(output, "        ")?;
                    }
                    if let Some(exchange) = &runner.exchange {
                        exchange.write_human(output, "        ")?;
                    }
                }
                Ok(())
            }
        }
    }

    pub(super) fn id(&self) -> &str {
        match self {
            Self::Runner(runner) => runner.id,
            Self::Pool(pool) => pool.id,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizeResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    #[serde(flatten)]
    holder: Holder<'a>,
    authorization: MadeView<'a>,
}

/// Reports the authorization `authorize` made.
pub(super) fn write_authorized(
    deployment: &str,
    holder: Holder<'_>,
    authorization: MadeView<'_>,
    json: bool,
) -> anyhow::Result<ExitCode> {
    if json {
        write_json(&AuthorizeResult {
            schema_version: 1,
            deployment,
            outcome: "authorized",
            holder,
            authorization,
        })?;
        return Ok(ExitCode::Success);
    }
    let mut stdout = io::stdout().lock();
    match authorization {
        MadeView::Runner(_) => writeln!(stdout, "✓ Runner authorized.")?,
        MadeView::Pool(_) => writeln!(stdout, "✓ Personal pool authorized.")?,
    }
    holder.write_human(&mut stdout)?;
    authorization.write_human(&mut stdout)?;
    writeln!(stdout, "deployment: {deployment}")?;
    stdout.flush()?;
    Ok(ExitCode::Success)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeauthorizeResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    #[serde(flatten)]
    holder: Holder<'a>,
    authorization_id: &'a str,
    #[serde(flatten)]
    target: EndedTarget<'a>,
}

#[derive(Serialize)]
#[serde(untagged)]
pub(super) enum EndedTarget<'a> {
    #[serde(rename_all = "camelCase")]
    Runner {
        runner_id: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        removal: Option<RemovalView<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        stop: Option<StopView<'a>>,
    },
    #[serde(rename_all = "camelCase")]
    Pool {
        runner_pool_id: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        runners: Option<Vec<RemovedRunner<'a>>>,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RemovedRunner<'a> {
    runner_id: &'a str,
    removal: RemovalView<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<StopView<'a>>,
}

impl<'a> EndedTarget<'a> {
    pub(super) fn runner(id: &'a str, ended: Option<EndedAuthorizationView<'a>>) -> Self {
        let (removal, stop) = ended.map_or((None, None), |ended| (Some(ended.removal), ended.stop));
        Self::Runner {
            runner_id: id,
            removal,
            stop,
        }
    }

    pub(super) fn pool(id: &'a str, runners: Option<Vec<EndedAuthorizationView<'a>>>) -> Self {
        Self::Pool {
            runner_pool_id: id,
            runners: runners.map(|ended| {
                ended
                    .into_iter()
                    .map(|ended| RemovedRunner {
                        runner_id: ended.authorization.runner_id,
                        removal: ended.removal,
                        stop: ended.stop,
                    })
                    .collect()
            }),
        }
    }
}

/// Reports an ended authorization with its removal state and stop, as the read after the
/// change gives them in `ended`: `None` when that read failed, which leaves the change done,
/// or when there was none to make.
pub(super) fn write_deauthorized(
    deployment: &str,
    holder: Holder<'_>,
    authorization_id: &str,
    target: EndedTarget<'_>,
    json: bool,
) -> anyhow::Result<ExitCode> {
    if json {
        write_json(&DeauthorizeResult {
            schema_version: 1,
            deployment,
            outcome: "deauthorized",
            holder,
            authorization_id,
            target,
        })?;
        return Ok(ExitCode::Success);
    }
    let mut stdout = io::stdout().lock();
    let who = match &target {
        EndedTarget::Runner { .. } => "Runner",
        EndedTarget::Pool { .. } => "Personal pool",
    };
    writeln!(stdout, "✓ {who} authorization ended.")?;
    holder.write_human(&mut stdout)?;
    writeln!(stdout, "authorization: {authorization_id}")?;
    match target {
        EndedTarget::Runner {
            runner_id,
            removal,
            stop,
        } => {
            writeln!(stdout, "runner: {runner_id}")?;
            if let Some(removal) = &removal {
                removal.write_human(&mut stdout, "")?;
            }
            if let Some(stop) = &stop {
                stop.write_human(&mut stdout, "")?;
            }
            writeln!(stdout, "deployment: {deployment}")?;
            if removal.is_some() {
                write_removal_note(&mut stdout)?;
            }
            if stop.is_some() {
                write_stop_note(&mut stdout)?;
            }
        }
        EndedTarget::Pool {
            runner_pool_id,
            runners,
        } => {
            writeln!(stdout, "pool: {runner_pool_id} (personal)")?;
            writeln!(stdout, "deployment: {deployment}")?;
            if let Some(runners) = runners {
                writeln!(stdout, "runners: {}", runners.len())?;
                for runner in &runners {
                    writeln!(stdout, "  runner: {}", runner.runner_id)?;
                    runner.removal.write_human(&mut stdout, "    ")?;
                    if let Some(stop) = &runner.stop {
                        stop.write_human(&mut stdout, "    ")?;
                    }
                }
                if !runners.is_empty() {
                    write_removal_note(&mut stdout)?;
                }
                if runners.iter().any(|r| r.stop.is_some()) {
                    write_stop_note(&mut stdout)?;
                }
            }
        }
    }
    stdout.flush()?;
    Ok(ExitCode::Success)
}

fn write_json(value: &impl Serialize) -> anyhow::Result<()> {
    super::super::super::write_pretty_json(value).context("write JSON authorization result")
}
