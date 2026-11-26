//! The member's view of a credential: what Cloud's API returns for a grant and its authorizations,
//! mapped to one availability and one next action, with the command or step that next action names.
//! `useful account integration list` prints it; Cloud's API carries the facts only.

use std::collections::BTreeMap;
use std::io::{self, Write};

use serde::Serialize;

use useful_api::{
    AgentLoginReportState, Grant, GrantReport, MemberGrant, MemberGrantAuthorization,
    MemberGrantKind, MemberGrantState, ServedGrantProvider,
};
use useful_runner::CredentialKind;
use useful_support::{Availability, CredentialStatus, NextAction};

/// The status of a grant's authorization in force, or of the grant when it has none
/// (`authorization` is `None`), as its owner reads it. An OAuth grant is `available` on each
/// runner it is authorized for while it is `active`; Cloud issues its tokens per run.
pub(in crate::cli) fn grant_authorization_status(
    grant: &MemberGrant,
    authorization: Option<&MemberGrantAuthorization>,
) -> CredentialStatus {
    status_from_report(grant, authorization.map(|auth| auth.report.as_deref()))
}

/// How the owner's grant reaches a runner.
#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(in crate::cli) enum Access {
    Direct,
    Pool,
    Both,
}

impl Access {
    pub(in crate::cli) const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Pool => "pool",
            Self::Both => "both",
        }
    }
}

/// The single hold both authorization targets describe for the same runner.
pub(in crate::cli) struct GrantRunner<'a> {
    pub(in crate::cli) access: Access,
    pub(in crate::cli) report: Option<&'a GrantReport>,
    pub(in crate::cli) conflict: bool,
}

impl GrantRunner<'_> {
    pub(in crate::cli) fn status(&self, grant: &MemberGrant) -> CredentialStatus {
        if self.conflict && grant.state == MemberGrantState::GrantStateActive {
            return CredentialStatus {
                availability: Availability::NotDelivered,
                next_action: NextAction::ResolveRunnerConflict,
            };
        }
        status_from_report(grant, Some(self.report))
    }
}

pub(in crate::cli) fn grant_runners(grant: &MemberGrant) -> BTreeMap<&str, GrantRunner<'_>> {
    let mut runners: BTreeMap<_, _> = grant
        .authorizations
        .iter()
        .filter_map(|auth| {
            Some((
                auth.runner_id.as_deref()?,
                GrantRunner {
                    access: Access::Direct,
                    report: auth.report.as_deref(),
                    conflict: false,
                },
            ))
        })
        .collect();
    for runner in grant
        .authorizations
        .iter()
        .filter_map(|auth| auth.runners.as_deref())
        .flatten()
    {
        runners
            .entry(runner.runner_id.as_str())
            .and_modify(|entry| entry.access = Access::Both)
            .or_insert_with(|| GrantRunner {
                access: Access::Pool,
                report: runner.report.as_deref(),
                conflict: runner.conflict == Some(true),
            });
    }
    runners
}

fn status_from_report(
    grant: &MemberGrant,
    authorization: Option<Option<&GrantReport>>,
) -> CredentialStatus {
    if grant.kind == MemberGrantKind::GrantKindNative {
        return native_status(
            grant.state == MemberGrantState::GrantStateActive,
            grant.generation,
            authorization,
        );
    }
    let (availability, next_action) = match (grant.state, authorization) {
        (MemberGrantState::GrantStateRevoked, _) => (Availability::NotConnected, NextAction::None),
        (MemberGrantState::GrantStateReconnectRequired, _) => {
            (Availability::ReconnectRequired, NextAction::Reconnect)
        }
        (MemberGrantState::GrantStateActive, None) => {
            (Availability::NotConnected, NextAction::AuthorizeRunner)
        }
        (MemberGrantState::GrantStateActive, Some(_)) => {
            (Availability::Available, NextAction::None)
        }
    };
    CredentialStatus {
        availability,
        next_action,
    }
}

/// What a grant is, as far as its next action's step names it: a grant of either kind by its
/// ID and provider.
pub(in crate::cli) fn grant_subject(grant: &MemberGrant) -> Subject<'_> {
    let provider = grant.provider.as_str();
    match grant.kind {
        MemberGrantKind::GrantKindOAuth => Subject::OAuthGrant {
            id: &grant.id,
            provider,
        },
        MemberGrantKind::GrantKindNative => Subject::AgentLogin {
            id: &grant.id,
            provider,
        },
    }
}

/// The status of a native grant's authorization in force, given its runner's report if any
/// (`authorization` is `Some(report)`), or of the grant when it has none (`None`).
fn native_status(
    active: bool,
    generation: i64,
    authorization: Option<Option<&GrantReport>>,
) -> CredentialStatus {
    let (availability, next_action) = match (active, authorization) {
        (false, _) => (Availability::NotConnected, NextAction::None),
        (true, None) => (Availability::NotConnected, NextAction::AuthorizeRunner),
        (true, Some(report)) => {
            match report {
                // Cloud holds what the runner has not reported installing.
                None => (Availability::Pending, NextAction::WaitForRunner),
                Some(report) => match report.state {
                    AgentLoginReportState::AgentLoginReportStateReady
                        if report.generation == Some(generation) =>
                    {
                        match report.last_use.map(|last_use| last_use.as_str()) {
                            None => (Availability::Unverified, NextAction::None),
                            Some("refused") => {
                                (Availability::ReconnectRequired, NextAction::Reconnect)
                            }
                            Some(_) => (Availability::Available, NextAction::None),
                        }
                    }
                    AgentLoginReportState::AgentLoginReportStateReady
                    | AgentLoginReportState::AgentLoginReportStateNotAuthorized
                    | AgentLoginReportState::AgentLoginReportStateRevoked => {
                        (Availability::Pending, NextAction::WaitForRunner)
                    }
                    AgentLoginReportState::AgentLoginReportStateInstallFailed
                    | AgentLoginReportState::AgentLoginReportStateStaleGeneration
                    | AgentLoginReportState::AgentLoginReportStateCloudUnavailable => {
                        (Availability::DeliveryFailed, NextAction::SyncRunner)
                    }
                    AgentLoginReportState::AgentLoginReportStateUnsupportedTarget => {
                        (Availability::DeliveryFailed, NextAction::CheckTarget)
                    }
                    AgentLoginReportState::AgentLoginReportStateForeignLogin => {
                        (Availability::NotDelivered, NextAction::ResolveServiceLogin)
                    }
                },
            }
        }
    };
    CredentialStatus {
        availability,
        next_action,
    }
}

/// The status of a provider the member has nothing unrevoked for.
const NOT_CONNECTED: CredentialStatus = CredentialStatus {
    availability: Availability::NotConnected,
    next_action: NextAction::Connect,
};

/// The providers a workflow can use a credential of, grant providers first: the baseline of
/// [`providers`], named whether or not the deployment serves them.
pub(in crate::cli) const PROVIDERS: [Provider<'static>; 5] = [
    Provider::Grant("github"),
    Provider::Grant("gitlab.com"),
    Provider::Grant("linear"),
    Provider::CodingAgent("claude_code"),
    Provider::CodingAgent("codex"),
];

/// The providers a command names in turn, in the order it prints or signs in to them:
/// `github`, `gitlab.com` and `linear`, each other OAuth provider `served` names, in its
/// order, then `claude_code` and `codex`. The five of [`PROVIDERS`] are named whether or not
/// the deployment serves them, and `served` is empty for a deployment that predates its read.
pub(in crate::cli) fn providers(served: &[ServedGrantProvider]) -> Vec<Provider<'_>> {
    let (oauth, agents): (Vec<_>, Vec<_>) = PROVIDERS
        .into_iter()
        .partition(|provider| matches!(provider, Provider::Grant(_)));
    let others = served.iter().filter(|served| {
        served.kind == MemberGrantKind::GrantKindOAuth
            && !PROVIDERS
                .iter()
                .any(|provider| provider.name() == served.name)
    });
    oauth
        .into_iter()
        .chain(others.map(|served| Provider::Grant(&served.name)))
        .chain(agents)
        .collect()
}

/// A provider by its wire name: one an OAuth grant is made for, or a coding agent.
#[derive(Clone, Copy)]
pub(in crate::cli) enum Provider<'a> {
    Grant(&'a str),
    CodingAgent(&'a str),
}

impl<'a> Provider<'a> {
    /// The provider whose grant a kind a workflow calls for names; `gitlab` is
    /// GitLab.com. A token service has none.
    pub(in crate::cli) const fn of_kind(kind: CredentialKind) -> Option<Self> {
        Some(match kind {
            CredentialKind::Github => Self::Grant("github"),
            CredentialKind::Gitlab => Self::Grant("gitlab.com"),
            CredentialKind::Linear => Self::Grant("linear"),
            CredentialKind::ClaudeCode => Self::CodingAgent("claude_code"),
            CredentialKind::Codex => Self::CodingAgent("codex"),
            CredentialKind::Mergify | CredentialKind::Buildkite | CredentialKind::Cloudflare => {
                return None;
            }
        })
    }

    pub(in crate::cli) const fn name(self) -> &'a str {
        match self {
            Self::Grant(name) | Self::CodingAgent(name) => name,
        }
    }

    /// The status of this provider when the member has nothing unrevoked for it.
    pub(in crate::cli) fn not_connected(self) -> MemberStatus {
        let subject = match self {
            Self::Grant(provider) => Subject::Grant { provider },
            Self::CodingAgent(provider) => Subject::CodingAgent { provider },
        };
        MemberStatus::new(NOT_CONNECTED, subject)
    }
}

/// What a credential is, as far as its next action's step names it.
#[derive(Clone, Copy)]
pub(in crate::cli) enum Subject<'a> {
    /// A provider grant, or a grant provider the member has none for, by its provider.
    Grant { provider: &'a str },
    /// An OAuth grant of the member's, by its ID, which names it whatever else they hold of
    /// its provider, and its provider.
    OAuthGrant { id: &'a str, provider: &'a str },
    /// An agent login, a native grant, by its ID and its coding agent.
    AgentLogin { id: &'a str, provider: &'a str },
    /// A coding agent the member has no agent login for.
    CodingAgent { provider: &'a str },
}

/// A grant provider's name on the wire: any provider id `GrantApi` admits.
pub(in crate::cli) fn grant_provider(grant: &Grant) -> &str {
    &grant.provider
}

/// A credential's status with the command or step its next action names, which only the text
/// form prints.
#[derive(Serialize)]
pub(in crate::cli) struct MemberStatus {
    #[serde(flatten)]
    status: CredentialStatus,
    #[serde(skip)]
    step: Option<String>,
}

impl MemberStatus {
    pub(in crate::cli) fn new(status: CredentialStatus, subject: Subject<'_>) -> Self {
        Self {
            status,
            step: member_step(status.next_action, subject),
        }
    }

    /// The availability and the next action, a line each.
    pub(in crate::cli) fn write_human(
        &self,
        output: &mut impl Write,
        indent: &str,
    ) -> io::Result<()> {
        writeln!(
            output,
            "{indent}availability: {}",
            self.status.availability.as_str()
        )?;
        writeln!(output, "{indent}next action: {}", self.next_action_text())
    }

    /// The next action as the text form prints it: the action, then the command or step it
    /// names when it names one.
    pub(in crate::cli) fn next_action_text(&self) -> String {
        let next_action = self.status.next_action.as_str();
        match &self.step {
            Some(step) => format!("{next_action}: {step}"),
            None => next_action.to_owned(),
        }
    }
}

/// The command or step a member's next action names, each a `useful account integration` command or
/// `useful runner sync`. Waiting for a runner names none.
fn member_step(next_action: NextAction, subject: Subject<'_>) -> Option<String> {
    match (next_action, subject) {
        (NextAction::Reconnect, Subject::AgentLogin { provider, .. }) => Some(format!(
            "sign in again with `useful account integration reconnect {provider}`"
        )),
        (
            NextAction::Reconnect,
            Subject::Grant { provider } | Subject::OAuthGrant { provider, .. },
        ) => Some(naming_the_app(
            provider,
            format!("consent again with `useful account integration reconnect {provider}`"),
        )),
        (NextAction::Connect, Subject::Grant { provider }) => Some(naming_the_app(
            provider,
            format!("consent with `useful account integration connect {provider}`"),
        )),
        (NextAction::Connect, Subject::CodingAgent { provider }) => {
            Some(format!("sign in with `useful account integration connect {provider}`"))
        }
        (
            NextAction::AuthorizeRunner,
            Subject::AgentLogin { id, .. } | Subject::OAuthGrant { id, .. },
        ) => Some(format!(
            "authorize a runner with `useful account integration authorize {id} --runner RUNNER --yes`"
        )),
        (NextAction::SyncRunner, _) => Some(
            "on the runner's host, set grants up again with `useful runner sync`"
                .to_owned(),
        ),
        (NextAction::CheckTarget, _) => Some(
            "the deployment does not serve this coding agent for the runner's operating system"
                .to_owned(),
        ),
        (NextAction::ResolveRunnerConflict, _) => Some(
            "the runner holds another login for this coding agent. Its owner can end that authorization with `useful account integration deauthorize INTEGRATION --runner RUNNER --yes`".to_owned(),
        ),
        (NextAction::ResolveServiceLogin, _) => Some(
            "the runner's service uses its own login; remove it from the service's environment or home to use the agent login"
                .to_owned(),
        ),
        _ => None,
    }
}

/// `step`, the member's own sign-in to `provider`, and for `github` the other choice, acting as
/// the GitHub App, which an owner of the organization takes.
fn naming_the_app(provider: &str, step: String) -> String {
    match super::github_app_alternative(provider) {
        Some(command) => format!("{step}, or have an owner act as the GitHub App with `{command}`"),
        None => step,
    }
}

#[cfg(test)]
mod tests {
    use useful_api::MemberGrant;
    use useful_support::{Availability, CredentialStatus, NextAction};

    use super::grant_authorization_status;

    const fn status(availability: Availability, next_action: NextAction) -> CredentialStatus {
        CredentialStatus {
            availability,
            next_action,
        }
    }

    // A native grant at generation 3 whose one authorization in force carries `report`.
    fn native(state: &str, report: Option<serde_json::Value>) -> MemberGrant {
        let mut authorization = serde_json::json!({
            "id": "aga_01k0z6r1w8f4jy2m7q9v3x5abc",
            "runnerId": "rnr_01k0z6r1w8f4jy2m7q9v3x5abc",
            "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
            "createdAt": "2026-11-01T09:05:00Z"
        });
        if let Some(report) = report {
            authorization["report"] = report;
        }
        serde_json::from_value(serde_json::json!({
            "id": "agl_01k0z6r1w8f4jy2m7q9v3x5abc",
            "kind": "native",
            "provider": "codex",
            "state": state,
            "generation": 3,
            "createdAt": "2026-11-01T09:00:00Z",
            "authorizations": [authorization]
        }))
        .unwrap()
    }

    fn report(state: &str, generation: Option<i64>, last_use: Option<&str>) -> serde_json::Value {
        let mut report = serde_json::json!({
            "state": state,
            "reportedAt": "2026-11-02T10:02:00Z"
        });
        if let Some(generation) = generation {
            report["generation"] = generation.into();
        }
        if let Some(last_use) = last_use {
            report["lastUse"] = last_use.into();
        }
        report
    }

    #[test]
    fn native_pool_runners_map_their_report_or_conflict() {
        let mut grant = native("active", None);
        let pool = serde_json::json!({
            "id": "aga_01k0z6r1w8f4jy2m7q9v3x5abc",
            "runnerPoolId": "rpl_01k0z6r1w8f4jy2m7q9v3x5abc",
            "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
            "createdAt": "2026-11-01T09:05:00Z",
            "runners": [
                {"runnerId": "ready", "conflict": false, "report": report("ready", Some(3), Some("accepted"))},
                {"runnerId": "conflict", "conflict": true}
            ]
        });
        grant.authorizations = vec![serde_json::from_value(pool).unwrap()];
        let runners = super::grant_runners(&grant);
        assert_eq!(
            runners["ready"].status(&grant),
            status(Availability::Available, NextAction::None)
        );
        let conflict = runners["conflict"].status(&grant);
        assert_eq!(conflict.availability, Availability::NotDelivered);
        assert_eq!(conflict.next_action.as_str(), "resolve_runner_conflict");
    }

    // The owner's view of a native grant's authorization and of the grant.
    #[test]
    fn an_authorization_maps_cloud_facts_to_the_owners_column() {
        use Availability::{
            Available, DeliveryFailed, NotConnected, NotDelivered, Pending, ReconnectRequired,
            Unverified,
        };
        use NextAction::{
            AuthorizeRunner, CheckTarget, Reconnect, ResolveServiceLogin, SyncRunner, WaitForRunner,
        };
        let cases = [
            (None, status(Pending, WaitForRunner)),
            (
                Some(report("ready", Some(2), Some("accepted"))),
                status(Pending, WaitForRunner),
            ),
            (
                Some(report("ready", None, None)),
                status(Pending, WaitForRunner),
            ),
            (
                Some(report("not_authorized", None, None)),
                status(Pending, WaitForRunner),
            ),
            (
                Some(report("revoked", None, None)),
                status(Pending, WaitForRunner),
            ),
            (
                Some(report("ready", Some(3), Some("accepted"))),
                status(Available, NextAction::None),
            ),
            (
                Some(report("ready", Some(3), None)),
                status(Unverified, NextAction::None),
            ),
            (
                Some(report("ready", Some(3), Some("refused"))),
                status(ReconnectRequired, Reconnect),
            ),
            (
                Some(report("install_failed", Some(2), None)),
                status(DeliveryFailed, SyncRunner),
            ),
            (
                Some(report("stale_generation", Some(2), None)),
                status(DeliveryFailed, SyncRunner),
            ),
            (
                Some(report("cloud_unavailable", None, None)),
                status(DeliveryFailed, SyncRunner),
            ),
            (
                Some(report("unsupported_target", None, None)),
                status(DeliveryFailed, CheckTarget),
            ),
            (
                Some(report("foreign_login", None, None)),
                status(NotDelivered, ResolveServiceLogin),
            ),
        ];
        for (report, expected) in cases {
            let grant = native("active", report.clone());
            assert_eq!(
                grant_authorization_status(&grant, grant.authorizations.first()),
                expected,
                "{report:?}"
            );
        }

        let active = native("active", None);
        assert_eq!(
            grant_authorization_status(&active, None),
            status(NotConnected, AuthorizeRunner)
        );
        let revoked = native("revoked", None);
        assert_eq!(
            grant_authorization_status(&revoked, None),
            status(NotConnected, NextAction::None)
        );
    }

    #[test]
    fn a_grants_authorization_maps_its_kind_and_state_to_the_owners_column() {
        let authorization = serde_json::json!({
            "id": "pga_01k0z6r1w8f4jy2m7q9v3x5abc",
            "runnerId": "rnr_01k0z6r1w8f4jy2m7q9v3x5abc",
            "organizationId": "org_01k0z6r1w8f4jy2m7q9v3x5abc",
            "createdAt": "2026-11-01T09:05:00Z",
            "report": {"state": "ready", "generation": 1, "reportedAt": "2026-11-01T09:06:00Z"}
        });
        let grant = |kind: &str, state: &str| -> MemberGrant {
            serde_json::from_value(serde_json::json!({
                "id": "pgr_01k0z6r1w8f4jy2m7q9v3x5abc",
                "kind": kind,
                "provider": if kind == "oauth" { "github" } else { "codex" },
                "state": state,
                "generation": 1,
                "createdAt": "2026-11-01T09:00:00Z",
                "authorizations": [authorization.clone()]
            }))
            .unwrap()
        };
        use Availability::{Available, NotConnected, ReconnectRequired, Unverified};
        use NextAction::{AuthorizeRunner, Reconnect};
        for (kind, state, authorized, expected) in [
            ("oauth", "active", true, status(Available, NextAction::None)),
            (
                "oauth",
                "active",
                false,
                status(NotConnected, AuthorizeRunner),
            ),
            (
                "oauth",
                "reconnect_required",
                true,
                status(ReconnectRequired, Reconnect),
            ),
            (
                "oauth",
                "reconnect_required",
                false,
                status(ReconnectRequired, Reconnect),
            ),
            (
                "oauth",
                "revoked",
                false,
                status(NotConnected, NextAction::None),
            ),
            // A native grant reads its runner's report, as an agent login does.
            (
                "native",
                "active",
                true,
                status(Unverified, NextAction::None),
            ),
            (
                "native",
                "active",
                false,
                status(NotConnected, AuthorizeRunner),
            ),
            (
                "native",
                "revoked",
                false,
                status(NotConnected, NextAction::None),
            ),
        ] {
            let grant = grant(kind, state);
            let authorization = grant.authorizations.first().filter(|_| authorized);
            assert_eq!(
                grant_authorization_status(&grant, authorization),
                expected,
                "{kind} {state} {authorized}"
            );
        }
    }
}
