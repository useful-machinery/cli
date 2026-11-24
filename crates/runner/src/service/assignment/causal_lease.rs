use super::*;

#[derive(Clone)]
pub(in crate::service) struct CausalLease {
    pub(super) state: Arc<Mutex<CausalLeaseState>>,
}

pub(super) struct CausalLeaseState {
    pub(super) bases: BTreeMap<u64, LeaseInstant>,
    /// The last request for each next lease sequence asked for.
    pub(super) renewal_requests: BTreeMap<u64, RenewalRequest>,
}

/// The last `LeaseRenewalRequested` enqueued for one next lease sequence.
#[derive(Clone, Copy)]
pub(super) struct RenewalRequest {
    /// The outbox id of the request's observation, retained until Cloud acknowledges it.
    pub(super) observation_id: u64,
    /// When, on the lease clock, the request was enqueued.
    pub(super) enqueued_at: LeaseInstant,
    /// Whether Cloud has acknowledged any request for this sequence; a repeat keeps it.
    pub(super) acknowledged: bool,
}

impl RenewalRequest {
    /// Enqueues `observation`, this request asked again, once Cloud has acknowledged the
    /// last one, and records it as the last request. A refused repeat leaves the last
    /// request standing to be asked again later.
    fn repeat(
        &mut self,
        observation: AssignmentObservation,
        now: LeaseInstant,
        outbox: &ObservationOutbox,
    ) {
        if outbox.contains(self.observation_id) {
            return;
        }
        if let Ok(observation_id) = outbox.enqueue(observation) {
            *self = Self {
                observation_id,
                enqueued_at: now,
                acknowledged: self.acknowledged,
            };
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::service) enum RenewalRequestFailure {
    LeaseClock,
    Outbox,
    Sequence,
}

impl CausalLease {
    pub(in crate::service) fn new(acceptance_basis: LeaseInstant) -> Self {
        Self {
            state: Arc::new(Mutex::new(CausalLeaseState {
                bases: BTreeMap::from([(1, acceptance_basis)]),
                renewal_requests: BTreeMap::new(),
            })),
        }
    }

    pub(super) fn basis(&self, sequence: u64) -> Option<LeaseInstant> {
        self.lock().bases.get(&sequence).copied()
    }

    /// Asks Cloud for lease `current_sequence + 1`, recording the lease clock's time as
    /// that lease's causal basis. Asked again for a sequence already requested, it enqueues
    /// the same request once more only when `retry_interval` has passed since the last one
    /// and Cloud has acknowledged it (its observation has left the outbox); otherwise it
    /// changes nothing. A repeat never moves the basis, and one the outbox refuses is not a
    /// failure: the earlier request may still be answered.
    pub(in crate::service) fn request_renewal(
        &self,
        current_sequence: u64,
        retry_interval: Duration,
        assignment_id: &str,
        attempt_id: &str,
        lease_clock: &LeaseClock,
        outbox: &ObservationOutbox,
    ) -> Result<(), RenewalRequestFailure> {
        let next_sequence = current_sequence
            .checked_add(1)
            .ok_or(RenewalRequestFailure::Sequence)?;
        let mut state = self.lock();
        let now = lease_clock
            .now()
            .map_err(|_| RenewalRequestFailure::LeaseClock)?;
        let observation = AssignmentObservation::LeaseRenewalRequested {
            assignment_id: assignment_id.to_owned(),
            attempt_id: attempt_id.to_owned(),
            current_lease_sequence: current_sequence,
        };
        if let Some(request) = state.renewal_requests.get_mut(&next_sequence) {
            let due = request
                .enqueued_at
                .checked_add(retry_interval)
                .and_then(|due| now.checked_cmp(due))
                .map_err(|_| RenewalRequestFailure::LeaseClock)?;
            if due != std::cmp::Ordering::Less {
                request.repeat(observation, now, outbox);
            }
            return Ok(());
        }
        state.bases.entry(next_sequence).or_insert(now);
        let observation_id = outbox
            .enqueue(observation)
            .map_err(|_| RenewalRequestFailure::Outbox)?;
        state.renewal_requests.insert(
            next_sequence,
            RenewalRequest {
                observation_id,
                enqueued_at: now,
                acknowledged: false,
            },
        );
        Ok(())
    }

    /// Asks Cloud again, without waiting for any retry interval, for lease
    /// `current_sequence + 1` when it has been requested and Cloud has acknowledged the last
    /// request (its observation has left the outbox); otherwise it changes nothing. It never
    /// makes a first request and never moves the basis.
    pub(super) fn repeat_renewal_request(
        &self,
        current_sequence: u64,
        assignment_id: &str,
        attempt_id: &str,
        lease_clock: &LeaseClock,
        outbox: &ObservationOutbox,
    ) -> Result<(), LeaseClockError> {
        let Some(next_sequence) = current_sequence.checked_add(1) else {
            return Ok(());
        };
        let mut state = self.lock();
        let Some(request) = state.renewal_requests.get_mut(&next_sequence) else {
            return Ok(());
        };
        if outbox.contains(request.observation_id) {
            return Ok(());
        }
        let now = lease_clock.now()?;
        request.repeat(
            AssignmentObservation::LeaseRenewalRequested {
                assignment_id: assignment_id.to_owned(),
                attempt_id: attempt_id.to_owned(),
                current_lease_sequence: current_sequence,
            },
            now,
            outbox,
        );
        Ok(())
    }

    /// Records that Cloud acknowledged a request for lease `current_sequence + 1`. Outbox ids
    /// only grow, so the acknowledged request is the last one or one it repeated: a repeat
    /// may replace the last request between Cloud's acknowledgement and this call.
    pub(super) fn acknowledge_renewal(&self, current_sequence: u64, observation_id: u64) {
        if let Some(next_sequence) = current_sequence.checked_add(1)
            && let Some(request) = self.lock().renewal_requests.get_mut(&next_sequence)
            && observation_id <= request.observation_id
        {
            request.acknowledged = true;
        }
    }

    pub(in crate::service) fn deadline_reason(&self, current_sequence: u64) -> LeaseLossReason {
        let state = self.lock();
        let request = current_sequence
            .checked_add(1)
            .and_then(|next| state.renewal_requests.get(&next));
        if request.is_some_and(|request| request.acknowledged) {
            LeaseLossReason::RenewalLate
        } else {
            LeaseLossReason::RenewalUnreachable
        }
    }

    pub(super) fn lock(&self) -> std::sync::MutexGuard<'_, CausalLeaseState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deadline_counts_gateway_acknowledgement_and_ignores_outbox_fencing() {
        let (_temporary, mut manager, offer, _) =
            super::super::tests::cancellable_running_fixture().await;
        let lease = manager
            .running(&offer.assignment_id)
            .unwrap()
            .causal_lease
            .clone();
        for (sequence, fence, expected) in [
            (1, true, LeaseLossReason::RenewalUnreachable),
            (2, false, LeaseLossReason::RenewalLate),
        ] {
            lease
                .request_renewal(
                    sequence,
                    MINIMUM_RENEWAL_HEADROOM,
                    &offer.assignment_id,
                    &offer.attempt_id,
                    &manager.lease_clock,
                    &manager.outbox,
                )
                .unwrap();
            let request = manager
                .pending_observations(&BTreeSet::new(), 100)
                .into_iter()
                .find(|entry| {
                    matches!(&entry.observation,
                        AssignmentObservation::LeaseRenewalRequested { current_lease_sequence, .. }
                            if *current_lease_sequence == sequence
                    )
                })
                .unwrap();
            if fence {
                manager.outbox.fence_assignment(&offer.assignment_id);
                assert!(!manager.outbox.contains(request.id));
            }
            manager.acknowledge_observation(request.id);
            assert_eq!(lease.deadline_reason(sequence), expected);
        }
    }
}
