use super::*;

#[derive(Clone, Copy)]
pub(super) struct LeaseFailureContext<'a> {
    lease_loss: &'a LeaseLoss,
    causal_lease: &'a CausalLease,
    post_stop_fence: &'a PostStopFence,
    process_guards: &'a AssignmentProcessGuards,
}

pub(super) enum LeaseExecution<Output> {
    Completed {
        output: Output,
        infrastructure_interruption: Option<InfrastructureInterruption>,
    },
    ContainmentDeadline,
    LeaseClockFailed {
        quiescent: bool,
        error: LeaseClockError,
    },
}

#[expect(
    clippy::too_many_arguments,
    reason = "lease supervision receives every authority and containment boundary explicitly"
)]
pub(super) async fn run_under_lease<F, Output>(
    execution: F,
    lease_loss: &LeaseLoss,
    lease_clock: &LeaseClock,
    mut authority_updates: tokio::sync::watch::Receiver<LeaseAuthority>,
    mut infrastructure_updates: tokio::sync::watch::Receiver<Option<InfrastructureInterruption>>,
    mut initial_wait: Option<(u64, LeaseWait)>,
    causal_lease: &CausalLease,
    outbox: &ObservationOutbox,
    assignment_id: &str,
    attempt_id: &str,
    post_stop_fence: &PostStopFence,
    process_guards: &AssignmentProcessGuards,
) -> LeaseExecution<Output>
where
    F: Future<Output = Output>,
{
    tokio::pin!(execution);
    let mut infrastructure_interruption = *infrastructure_updates.borrow_and_update();
    let mut first_check = true;
    let failure = LeaseFailureContext {
        lease_loss,
        causal_lease,
        post_stop_fence,
        process_guards,
    };
    'supervision: loop {
        let authority = authority_updates.borrow_and_update().clone();
        if let Some(interruption) = *infrastructure_updates.borrow_and_update() {
            infrastructure_interruption = Some(interruption);
        }
        let now = match lease_clock.now() {
            Ok(now) => now,
            Err(error) => {
                return fail_lease_clock(error, failure);
            }
        };
        let cancellation_due = match now.checked_cmp(authority.cancellation_start) {
            Ok(ordering) => ordering != std::cmp::Ordering::Less,
            Err(error) => {
                return fail_lease_clock(error, failure);
            }
        };
        if authority.revoked || cancellation_due {
            let reason = if first_check {
                LeaseLossReason::StartLate
            } else {
                causal_lease.deadline_reason(authority.sequence)
            };
            return finish_after_lease_loss(
                &mut execution,
                failure,
                lease_clock,
                &authority,
                reason,
            )
            .await;
        }
        first_check = false;
        let armed_wait = match initial_wait.take() {
            Some((sequence, wait)) if sequence == authority.sequence => Some(wait),
            Some(_) | None => None,
        };
        tokio::select! {
            biased;
            wait = wait_for_lease_deadline_or_armed(
                lease_clock,
                authority.renewal_request,
                armed_wait,
            ) => {
                if let Err(error) = wait {
                    return fail_lease_timer(&mut execution, failure, error).await;
                }
                let now = match lease_clock.now() {
                    Ok(now) => now,
                    Err(error) => return fail_lease_clock(error, failure),
                };
                if !matches!(
                    now.checked_cmp(authority.cancellation_start),
                    Ok(std::cmp::Ordering::Less)
                ) {
                    return finish_after_lease_loss(
                        &mut execution,
                        failure,
                        lease_clock,
                        &authority,
                        causal_lease.deadline_reason(authority.sequence),
                    ).await;
                }
                match causal_lease.request_renewal(
                    authority.sequence,
                    authority.renewal_retry_interval,
                    assignment_id,
                    attempt_id,
                    lease_clock,
                    outbox,
                ) {
                    Ok(()) => {}
                    Err(RenewalRequestFailure::LeaseClock) => {
                        return fail_lease_clock(LeaseClockError::ClockUnavailable, failure);
                    }
                    Err(RenewalRequestFailure::Outbox | RenewalRequestFailure::Sequence) => {
                        return finish_after_lease_loss(
                            &mut execution,
                            failure,
                            lease_clock,
                            &authority,
                            LeaseLossReason::RenewalUnreachable,
                        ).await;
                    }
                }
                let mut asked_at = now;
                let cancellation_wait = wait_for_lease_deadline(lease_clock, authority.cancellation_start);
                tokio::pin!(cancellation_wait);
                // Until a grant replaces the authority, ask again every retry interval;
                // `CausalLease` withholds a repeat while the last request is retained.
                loop {
                    tokio::select! {
                        biased;
                        wait = &mut cancellation_wait => {
                            if let Err(error) = wait {
                                return fail_lease_timer(&mut execution, failure, error).await;
                            }
                            let latest_authority = authority_updates.borrow_and_update().clone();
                            if latest_authority != authority {
                                continue 'supervision;
                            }
                            return finish_after_lease_loss(
                                &mut execution,
                                failure,
                                lease_clock,
                                &authority,
                                causal_lease.deadline_reason(authority.sequence),
                            ).await;
                        }
                        wait = wait_to_ask_again(
                            lease_clock,
                            asked_at,
                            authority.renewal_retry_interval,
                            authority.cancellation_start,
                        ) => {
                            asked_at = match wait {
                                Ok(asked_at) => asked_at,
                                Err(error) => return fail_lease_timer(&mut execution, failure, error).await,
                            };
                            if causal_lease.request_renewal(
                                authority.sequence,
                                authority.renewal_retry_interval,
                                assignment_id,
                                attempt_id,
                                lease_clock,
                                outbox,
                            ) == Err(RenewalRequestFailure::LeaseClock) {
                                return fail_lease_clock(LeaseClockError::ClockUnavailable, failure);
                            }
                        }
                        changed = authority_updates.changed() => {
                            if changed.is_err() {
                                return finish_after_lease_loss(
                                    &mut execution,
                                    failure,
                                    lease_clock,
                                    &authority,
                                    LeaseLossReason::AuthorityMissing,
                                ).await;
                            }
                            continue 'supervision;
                        }
                        changed = infrastructure_updates.changed() => {
                            if changed.is_ok()
                                && let Some(interruption) = *infrastructure_updates.borrow_and_update()
                            {
                                infrastructure_interruption = Some(interruption);
                            }
                        }
                        result = &mut execution => {
                            return complete_ready_execution(
                                result,
                                failure,
                                lease_clock,
                                &authority,
                                infrastructure_interruption,
                                None,
                            );
                        }
                    }
                }
            }
            changed = authority_updates.changed() => {
                if changed.is_err() {
                    return finish_after_lease_loss(
                        &mut execution,
                        failure,
                        lease_clock,
                        &authority,
                        LeaseLossReason::AuthorityMissing,
                    ).await;
                }
            }
            changed = infrastructure_updates.changed() => {
                if changed.is_ok()
                    && let Some(interruption) = *infrastructure_updates.borrow_and_update()
                {
                    infrastructure_interruption = Some(interruption);
                }
            }
            result = &mut execution => {
                return complete_ready_execution(
                    result,
                    failure,
                    lease_clock,
                    &authority,
                    infrastructure_interruption,
                    None,
                );
            }
        }
    }
}

pub(super) fn complete_ready_execution<Output>(
    output: Output,
    failure: LeaseFailureContext<'_>,
    lease_clock: &LeaseClock,
    authority: &LeaseAuthority,
    infrastructure_interruption: Option<InfrastructureInterruption>,
    prior_loss: Option<LeaseLossReason>,
) -> LeaseExecution<Output> {
    let LeaseFailureContext {
        lease_loss,
        post_stop_fence,
        process_guards,
        ..
    } = failure;
    let now = match lease_clock.now() {
        Ok(now) => now,
        Err(error) => {
            return fail_lease_clock(error, failure);
        }
    };
    let reason = if let Some(reason) = prior_loss {
        reason
    } else {
        match now.checked_cmp(authority.cancellation_start) {
            Ok(std::cmp::Ordering::Less) if !authority.revoked => {
                return LeaseExecution::Completed {
                    output,
                    infrastructure_interruption,
                };
            }
            Ok(_) => failure.causal_lease.deadline_reason(authority.sequence),
            Err(error) => {
                return fail_lease_clock(error, failure);
            }
        }
    };
    lease_loss.lose(reason);
    match now.checked_cmp(authority.force_stop_start) {
        Ok(std::cmp::Ordering::Less) => {
            return LeaseExecution::Completed {
                output,
                infrastructure_interruption: Some(
                    InfrastructureInterruption::ExecutionLeaseExpired,
                ),
            };
        }
        Ok(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater) => {
            begin_forced_containment(lease_loss, reason, post_stop_fence, process_guards);
        }
        Err(error) => {
            return fail_lease_clock(error, failure);
        }
    }
    match lease_clock
        .now()
        .and_then(|now| now.checked_cmp(authority.force_stop_end))
    {
        Ok(std::cmp::Ordering::Greater) => LeaseExecution::ContainmentDeadline,
        Ok(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
            if process_guards.is_quiescent() =>
        {
            LeaseExecution::Completed {
                output,
                infrastructure_interruption: Some(
                    InfrastructureInterruption::ExecutionLeaseExpired,
                ),
            }
        }
        Ok(std::cmp::Ordering::Less | std::cmp::Ordering::Equal) => {
            LeaseExecution::ContainmentDeadline
        }
        Err(error) => LeaseExecution::LeaseClockFailed {
            quiescent: process_guards.is_quiescent(),
            error,
        },
    }
}

pub(super) async fn finish_after_lease_loss<F, Output>(
    execution: &mut std::pin::Pin<&mut F>,
    failure: LeaseFailureContext<'_>,
    lease_clock: &LeaseClock,
    authority: &LeaseAuthority,
    reason: LeaseLossReason,
) -> LeaseExecution<Output>
where
    F: Future<Output = Output>,
{
    let LeaseFailureContext {
        lease_loss,
        post_stop_fence,
        process_guards,
        ..
    } = failure;
    lease_loss.lose(reason);
    let now = match lease_clock.now() {
        Ok(now) => now,
        Err(error) => {
            return fail_lease_clock(error, failure);
        }
    };
    let before_force_stop = match now.checked_cmp(authority.force_stop_start) {
        Ok(std::cmp::Ordering::Less) => true,
        Ok(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater) => false,
        Err(error) => {
            return fail_lease_clock(error, failure);
        }
    };
    if before_force_stop {
        tokio::select! {
            biased;
            wait = wait_for_lease_deadline(lease_clock, authority.force_stop_start) => {
                if let Err(error) = wait {
                    return fail_lease_timer(execution, failure, error).await;
                }
            }
            output = execution.as_mut() => {
                return complete_ready_execution(
                    output,
                    failure,
                    lease_clock,
                    authority,
                    Some(InfrastructureInterruption::ExecutionLeaseExpired),
                    Some(reason),
                );
            }
        }
    }

    begin_forced_containment(lease_loss, reason, post_stop_fence, process_guards);
    let now = match lease_clock.now() {
        Ok(now) => now,
        Err(error) => {
            return LeaseExecution::LeaseClockFailed {
                quiescent: process_guards.is_quiescent(),
                error,
            };
        }
    };
    match now.checked_cmp(authority.force_stop_end) {
        Ok(std::cmp::Ordering::Greater) => return LeaseExecution::ContainmentDeadline,
        Ok(std::cmp::Ordering::Less | std::cmp::Ordering::Equal) => {}
        Err(error) => {
            return LeaseExecution::LeaseClockFailed {
                quiescent: process_guards.is_quiescent(),
                error,
            };
        }
    }
    tokio::select! {
        biased;
        output = execution.as_mut() => complete_ready_execution(
            output,
            failure,
            lease_clock,
            authority,
            Some(InfrastructureInterruption::ExecutionLeaseExpired),
            Some(reason),
        ),
        wait = wait_for_lease_deadline(lease_clock, authority.force_stop_end) => {
            match wait {
                Ok(()) => LeaseExecution::ContainmentDeadline,
                Err(error) => fail_lease_timer(execution, failure, error).await,
            }
        }
    }
}

pub(super) async fn fail_lease_timer<F, Output>(
    execution: &mut std::pin::Pin<&mut F>,
    failure: LeaseFailureContext<'_>,
    error: LeaseClockError,
) -> LeaseExecution<Output>
where
    F: Future<Output = Output>,
{
    let LeaseFailureContext {
        lease_loss,
        post_stop_fence,
        process_guards,
        ..
    } = failure;
    begin_forced_containment(
        lease_loss,
        LeaseLossReason::ClockFailed,
        post_stop_fence,
        process_guards,
    );
    if !process_guards.is_quiescent() {
        let _ = execution.as_mut().await;
    }
    LeaseExecution::LeaseClockFailed {
        quiescent: process_guards.is_quiescent(),
        error,
    }
}

pub(super) fn fail_lease_clock<Output>(
    error: LeaseClockError,
    failure: LeaseFailureContext<'_>,
) -> LeaseExecution<Output> {
    let LeaseFailureContext {
        lease_loss,
        post_stop_fence,
        process_guards,
        ..
    } = failure;
    begin_forced_containment(
        lease_loss,
        LeaseLossReason::ClockFailed,
        post_stop_fence,
        process_guards,
    );
    LeaseExecution::LeaseClockFailed {
        quiescent: process_guards.is_quiescent(),
        error,
    }
}

pub(super) fn begin_forced_containment(
    lease_loss: &LeaseLoss,
    reason: LeaseLossReason,
    post_stop_fence: &PostStopFence,
    process_guards: &AssignmentProcessGuards,
) {
    post_stop_fence.fence();
    lease_loss.lose(reason);
    process_guards.begin_forced_containment();
}

pub(super) async fn wait_for_lease_deadline(
    lease_clock: &LeaseClock,
    deadline: LeaseInstant,
) -> Result<(), LeaseClockError> {
    wait_for_lease_deadline_or_armed(lease_clock, deadline, None).await
}

/// Waits until `retry_interval` after `asked_at`, when the renewal was last asked for, and
/// returns the lease clock's time then, when it is asked for again. It never completes when
/// that instant is not before `bound`, where the caller stops asking.
pub(super) async fn wait_to_ask_again(
    lease_clock: &LeaseClock,
    asked_at: LeaseInstant,
    retry_interval: Duration,
    bound: LeaseInstant,
) -> Result<LeaseInstant, LeaseClockError> {
    let next_ask = asked_at.checked_add(retry_interval)?;
    if next_ask.checked_cmp(bound)? != std::cmp::Ordering::Less {
        return std::future::pending().await;
    }
    wait_for_lease_deadline(lease_clock, next_ask).await?;
    lease_clock.now()
}

pub(super) async fn wait_for_lease_deadline_or_armed(
    lease_clock: &LeaseClock,
    deadline: LeaseInstant,
    armed: Option<LeaseWait>,
) -> Result<(), LeaseClockError> {
    let wait = match armed {
        Some(wait) => wait,
        None => lease_clock.start_wait(deadline)?,
    };
    let cancellation = LeaseWaitCancellation::default();
    wait.wait(&cancellation).await.map(|_| ())
}
