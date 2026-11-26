//! The grants read of `useful workflow doctor`: the signed-in member's own unrevoked grants,
//! each requirement shown beside what the member holds of its provider, with the availability
//! and next action of the member's projection on each runner a grant is authorized for, or on
//! the one `--runner` names. It lives in the command because `useful-runner` reaches neither the
//! API nor the human session. Without `--runner` it changes no requirement's state or code; with
//! it, it says whether that runner's host or a grant meets a requirement, and why no grant does.

use std::io::{self, Write};

use serde::Serialize;

use useful_api::{MemberGrant, MemberGrantKind};
use useful_runner::CredentialKind;
use useful_support::Availability;

use super::super::super::account::grant;
use super::super::super::account::grant::projection::{
    Access, MemberStatus, Provider, grant_authorization_status, grant_runners, grant_subject,
};

/// The member's unrevoked grants, as read for one invocation, and the runner `--runner` named.
pub(super) struct Held<'a> {
    grants: Vec<MemberGrant>,
    runner: Option<&'a str>,
}

/// What the runner `--runner` names makes of a requirement.
pub(super) enum OnRunner {
    /// The runner's host supplies the coding agent itself.
    Host,
    /// A grant of the member's is usable there.
    Grant,
    /// No grant is usable there, for the reason given.
    Shortfall(Shortfall),
}

impl<'a> Held<'a> {
    pub(super) const fn new(grants: Vec<MemberGrant>, runner: Option<&'a str>) -> Self {
        Self { grants, runner }
    }

    /// The runner `--runner` named, by ID.
    pub(super) const fn runner(&self) -> Option<&'a str> {
        self.runner
    }
}

impl Held<'_> {
    /// The member's grants of `provider`.
    fn of_provider(&self, provider: Provider) -> impl Iterator<Item = &MemberGrant> {
        self.grants
            .iter()
            .filter(move |grant| grant.provider.as_str() == provider.name())
    }

    /// What the member holds of the provider `kind` names, or `None` for a kind with no grant
    /// provider, a token service.
    pub(super) fn of(&self, kind: CredentialKind) -> Option<ProviderView<'_>> {
        let provider = Provider::of_kind(kind)?;
        let grants: Vec<_> = self
            .of_provider(provider)
            .map(|grant| GrantView::new(grant, self.runner))
            .collect();
        Some(ProviderView {
            provider: provider.name(),
            status: grants.is_empty().then(|| provider.not_connected()),
            grants,
        })
    }

    /// What the runner `--runner` names makes of the requirement of `kind`, or `None` when no
    /// runner is named. A coding agent the runner's host supplies itself, as `useful account
    /// integration connect --workflow --runner` reads it, is the host's; this is tested first,
    /// since a host's own login projects as `not_delivered`. Otherwise a grant is usable there
    /// when its availability is `available`, `unverified` or `pending`: a runner sets a login up
    /// for each assignment it admits before offering anything. Of several grants the one nearest
    /// to usable is reported, one authorized for the runner before one that is not. A kind with no
    /// grant provider, a token service, has nothing to report.
    pub(super) fn on_runner(&self, kind: CredentialKind) -> Option<OnRunner> {
        let runner = self.runner?;
        if matches!(kind, CredentialKind::ClaudeCode | CredentialKind::Codex)
            && grant::host_supplies(&self.grants, kind, runner)
        {
            return Some(OnRunner::Host);
        }
        let provider = Provider::of_kind(kind)?;
        let nearest = self
            .of_provider(provider)
            .map(|grant| {
                let runners = grant_runners(grant);
                let authorized = runners.get(runner);
                let status = authorized.map_or_else(
                    || grant_authorization_status(grant, None),
                    |entry| entry.status(grant),
                );
                (grant, authorized.is_some(), status)
            })
            .min_by_key(|(_, authorized, status)| (!usable(status.availability), !authorized));
        let Some((grant, _, status)) = nearest else {
            return Some(OnRunner::Shortfall(Shortfall::new(
                "grant_not_connected",
                Failing::Missing,
                &provider.not_connected(),
            )));
        };
        let (code, failing) = match status.availability {
            Availability::Available | Availability::Unverified | Availability::Pending => {
                return Some(OnRunner::Grant);
            }
            Availability::NotConnected => ("grant_not_authorized", Failing::Missing),
            Availability::ReconnectRequired => {
                ("grant_reconnect_required", Failing::ReconnectRequired)
            }
            Availability::DeliveryFailed | Availability::NotDelivered => {
                ("grant_not_ready", Failing::Missing)
            }
        };
        Some(OnRunner::Shortfall(Shortfall::new(
            code,
            failing,
            &MemberStatus::new(status, grant_subject(grant)),
        )))
    }
}

/// Whether a grant with `availability` on a runner is in place for a run's step there.
const fn usable(availability: Availability) -> bool {
    matches!(
        availability,
        Availability::Available | Availability::Unverified | Availability::Pending
    )
}

/// The failing state a grant gives a requirement.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Failing {
    Missing,
    ReconnectRequired,
}

impl Failing {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::ReconnectRequired => "reconnect_required",
        }
    }
}

/// A requirement no grant meets on the runner `--runner` names: its state, its code and the next
/// action of the grant status that fails it, with the command it names.
pub(super) struct Shortfall {
    pub(super) code: &'static str,
    pub(super) state: Failing,
    pub(super) next_action: String,
}

impl Shortfall {
    fn new(code: &'static str, state: Failing, status: &MemberStatus) -> Self {
        Self {
            code,
            state,
            next_action: status.next_action_text(),
        }
    }
}

/// What the member holds of one provider: each unrevoked grant, or, holding none, the status
/// that names how to make one.
#[derive(Serialize)]
pub(super) struct ProviderView<'a> {
    provider: &'static str,
    grants: Vec<GrantView<'a>>,
    #[serde(flatten)]
    status: Option<MemberStatus>,
}

/// A grant as the doctor shows it: the fields of `useful account integration list`'s view that say
/// which grant it is and whose account, and its status on each runner reported.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantView<'a> {
    id: &'a str,
    state: &'static str,
    generation: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_id: Option<&'a str>,
    authorizations: Vec<RunnerView<'a>>,
    // The grant's own availability and next action when no authorization is reported.
    #[serde(flatten)]
    status: Option<MemberStatus>,
}

/// A grant's status on one runner it is authorized for.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunnerView<'a> {
    runner_id: &'a str,
    access: Access,
    #[serde(flatten)]
    status: MemberStatus,
}

impl<'a> GrantView<'a> {
    /// The grant's authorizations in force, only that of `runner` when one is named, and the
    /// grant's own status when none is reported.
    fn new(grant: &'a MemberGrant, runner: Option<&str>) -> Self {
        let subject = grant_subject(grant);
        let authorizations: Vec<_> = grant_runners(grant)
            .into_iter()
            .filter(|(id, _)| runner.is_none_or(|wanted| *id == wanted))
            .map(|(runner_id, entry)| RunnerView {
                runner_id,
                access: entry.access,
                status: MemberStatus::new(entry.status(grant), subject),
            })
            .collect();
        let (organization_id, identity_id) = match grant.kind {
            MemberGrantKind::GrantKindOAuth => (None, grant.identity_id.as_deref()),
            MemberGrantKind::GrantKindNative => (grant.organization_id.as_deref(), None),
        };
        Self {
            id: &grant.id,
            state: grant.state.as_str(),
            generation: grant.generation,
            organization_id,
            identity_id,
            status: (authorizations.is_empty()
                && (runner.is_some() || grant.authorizations.is_empty()))
            .then(|| MemberStatus::new(grant_authorization_status(grant, None), subject)),
            authorizations,
        }
    }
}

impl ProviderView<'_> {
    /// The grants beneath a requirement, each next action with the command it names.
    pub(super) fn write_human(&self, output: &mut impl Write) -> io::Result<()> {
        writeln!(output, "  grants of {}:", self.provider)?;
        if let Some(status) = &self.status {
            writeln!(output, "    none held")?;
            status.write_human(output, "    ")?;
        }
        for grant in &self.grants {
            write!(
                output,
                "    grant {} · {} · generation {}",
                grant.id, grant.state, grant.generation
            )?;
            match (grant.identity_id, grant.organization_id) {
                (Some(id), _) => writeln!(output, " · identity {id}")?,
                (None, Some(id)) => writeln!(output, " · organization {id}")?,
                (None, None) => writeln!(output)?,
            }
            for authorization in &grant.authorizations {
                writeln!(
                    output,
                    "      runner {} ({})",
                    authorization.runner_id,
                    authorization.access.as_str()
                )?;
                authorization.status.write_human(output, "        ")?;
            }
            if let Some(status) = &grant.status {
                status.write_human(output, "      ")?;
            }
        }
        Ok(())
    }
}
