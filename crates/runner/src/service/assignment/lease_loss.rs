use std::sync::{Arc, OnceLock};

use super::{CancellationReason, CancellationSource, RunEvent};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::service) enum LeaseLossReason {
    StartLate,
    RenewalLate,
    RenewalUnreachable,
    RevokedByCloud,
    ClockFailed,
    AuthorityMissing,
}

impl LeaseLossReason {
    pub(in crate::service) const fn as_str(self) -> &'static str {
        match self {
            Self::StartLate => "lease_start_late",
            Self::RenewalUnreachable => "lease_renewal_unreachable",
            Self::RenewalLate => "lease_renewal_late",
            Self::RevokedByCloud => "lease_revoked_by_cloud",
            Self::ClockFailed => "lease_clock_failed",
            Self::AuthorityMissing => "lease_authority_missing",
        }
    }
}

/// The first lease loss for one assignment, shared by its manager and execution job.
#[derive(Clone)]
pub(in crate::service) struct LeaseLoss {
    reason: Arc<OnceLock<LeaseLossReason>>,
    cancellation: CancellationSource,
    run_event: RunEvent,
}

impl LeaseLoss {
    pub(in crate::service) fn new(cancellation: CancellationSource, run_event: RunEvent) -> Self {
        Self {
            reason: Arc::default(),
            cancellation,
            run_event,
        }
    }

    pub(in crate::service) fn name(&self, reason: LeaseLossReason) {
        self.reason.get_or_init(|| {
            self.run_event.lease_loss(reason);
            reason
        });
    }

    pub(in crate::service) fn lose(&self, reason: LeaseLossReason) {
        self.name(reason);
        self.cancellation
            .request_cancellation(CancellationReason::ExecutionLeaseExpired);
    }

    pub(in crate::service) fn reason(&self) -> Option<LeaseLossReason> {
        self.reason.get().copied()
    }
}
