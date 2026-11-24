//! The agent-login models a native grant carries unchanged: its runner's exchange with Cloud
//! and its ended authorizations, with the checks `MemberGrantApi` makes of them. Responses
//! decode leniently into the generated models, which name no material.
use super::generated::models;

pub type AgentLoginReportState = models::agent_login_report::State;
// Reached through a native grant's fields; a caller reads their states by `as_str`.
type AgentLoginEndedAuthorization = models::AgentLoginEndedAuthorization;
type AgentLoginRemoval = models::AgentLoginRemoval;
type AgentLoginRemovalState = models::agent_login_removal::State;
type AgentLoginReport = models::AgentLoginReport;
type AgentLoginReportLastUse = models::agent_login_report::LastUse;
type AgentLoginStop = models::AgentLoginStop;

impl AgentLoginRemovalState {
    /// The removal state's wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentLoginRemovalStateNotDelivered => "not_delivered",
            Self::AgentLoginRemovalStatePending => "pending",
            Self::AgentLoginRemovalStateConfirmed => "confirmed",
        }
    }
}

impl AgentLoginReportLastUse {
    /// The last use's wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AgentLoginReportLastUseAccepted => "accepted",
            Self::AgentLoginReportLastUseRefused => "refused",
        }
    }
}

/// An ended authorization of an agent login, the native grant it is, whose removal and
/// stop are well formed.
pub(crate) fn valid_ended_authorization(value: &AgentLoginEndedAuthorization) -> bool {
    valid_authorization_record(
        "aga_",
        &value.id,
        &value.runner_id,
        &value.created_at,
        value.delivery.as_deref(),
        value.report.as_deref(),
    ) && !value.ended_at.is_empty()
        && valid_removal(&value.removal)
        && value.stop.as_deref().is_none_or(valid_stop)
}

// A stop names the run asked to stop and the cancellation request made of
// it.
fn valid_stop(value: &AgentLoginStop) -> bool {
    useful_support::valid_typed_id(&value.run_id, "run_")
        && useful_support::valid_typed_id(&value.cancellation_request_id, "cmd_")
        && !value.requested_at.is_empty()
}

/// An authorization whose ID has `prefix`, which names its runner and creation time and whose
/// exchange with the runner, delivery and report, is well formed.
pub(crate) fn valid_authorization_record(
    prefix: &str,
    id: &str,
    runner_id: &str,
    created_at: &str,
    delivery: Option<&models::AgentLoginDelivery>,
    report: Option<&AgentLoginReport>,
) -> bool {
    useful_support::valid_typed_id(id, prefix)
        && useful_support::valid_typed_id(runner_id, "rnr_")
        && !created_at.is_empty()
        && delivery
            .is_none_or(|delivery| delivery.generation >= 1 && !delivery.delivered_at.is_empty())
        && report.is_none_or(|report| {
            report.generation.is_none_or(|generation| generation >= 1)
                && !report.reported_at.is_empty()
                // The time of a last use comes only with it.
                && report
                    .last_use_at
                    .as_deref()
                    .is_none_or(|time| !time.is_empty() && report.last_use.is_some())
        })
}

// A removal carries its confirmation time exactly when it is confirmed.
fn valid_removal(value: &AgentLoginRemoval) -> bool {
    match (value.state, value.confirmed_at.as_deref()) {
        (AgentLoginRemovalState::AgentLoginRemovalStateConfirmed, Some(time)) => !time.is_empty(),
        (AgentLoginRemovalState::AgentLoginRemovalStateConfirmed, None) | (_, Some(_)) => false,
        (_, None) => true,
    }
}

#[cfg(test)]
#[allow(
    clippy::disallowed_macros,
    clippy::unwrap_used,
    reason = "agent login model unit tests use Rust test assertions"
)]
mod tests {
    use super::*;

    fn well_formed(ended: &serde_json::Value) -> bool {
        valid_ended_authorization(&serde_json::from_value(ended.clone()).unwrap())
    }

    fn ended(runner_id: &str, ended_at: &str, removal: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "id": "aga_01k0z6r1w8f4jy2m7q9v3x5abc",
            "runnerId": runner_id,
            "createdAt": "2026-11-01T09:05:00Z",
            "endedAt": ended_at,
            "delivery": {"generation": 1, "deliveredAt": "2026-11-01T09:06:00Z"},
            "report": {"state": "ready", "generation": 1, "lastUse": "refused", "reportedAt": "2026-11-01T09:07:00Z"},
            "removal": removal
        })
    }

    #[test]
    fn an_ended_authorization_is_checked_and_a_removal_time_comes_only_with_confirmed() {
        const RUNNER: &str = "rnr_01k0z6r1w8f4jy2m7q9v3x5abc";
        const ENDED_AT: &str = "2026-11-02T09:00:00Z";
        let confirmed =
            serde_json::json!({"state": "confirmed", "confirmedAt": "2026-11-02T09:01:00Z"});
        for (ended, valid) in [
            (
                ended(RUNNER, ENDED_AT, serde_json::json!({"state": "pending"})),
                true,
            ),
            (
                ended(
                    RUNNER,
                    ENDED_AT,
                    serde_json::json!({"state": "not_delivered"}),
                ),
                true,
            ),
            (ended(RUNNER, ENDED_AT, confirmed.clone()), true),
            (
                ended(RUNNER, ENDED_AT, serde_json::json!({"state": "confirmed"})),
                false,
            ),
            (
                ended(
                    RUNNER,
                    ENDED_AT,
                    serde_json::json!({"state": "pending", "confirmedAt": "2026-11-02T09:01:00Z"}),
                ),
                false,
            ),
            (ended("builder", ENDED_AT, confirmed.clone()), false),
            (ended(RUNNER, "", confirmed), false),
        ] {
            assert_eq!(well_formed(&ended), valid, "{ended}");
        }
    }

    #[test]
    fn an_ended_authorizations_stop_names_a_run_and_a_cancellation_request() {
        const RUN: &str = "run_01k0z6r1w8f4jy2m7q9v3x5abc";
        const REQUEST: &str = "cmd_01k0z6r1w8f4jy2m7q9v3x5abc";
        const REQUESTED_AT: &str = "2026-11-02T09:00:01Z";
        for (run_id, request_id, requested_at, valid) in [
            (RUN, REQUEST, REQUESTED_AT, true),
            (REQUEST, REQUEST, REQUESTED_AT, false),
            (RUN, RUN, REQUESTED_AT, false),
            (RUN, REQUEST, "", false),
        ] {
            let mut ended = ended(
                "rnr_01k0z6r1w8f4jy2m7q9v3x5abc",
                "2026-11-02T09:00:00Z",
                serde_json::json!({"state": "pending"}),
            );
            ended["stop"] = serde_json::json!({
                "runId": run_id,
                "cancellationRequestId": request_id,
                "requestedAt": requested_at
            });
            assert_eq!(well_formed(&ended), valid, "{ended}");
        }
    }
}
