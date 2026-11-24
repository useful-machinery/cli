//! The runner's command fence: every `useful` command a tree run starts enters it once its
//! run's activity lets it start, and a single-workflow run's execution enters it for the
//! whole of its engine's execution. A holder takes it only while nothing is in it, and
//! while it is held nothing enters: an entry that asks marks the hold wanted and waits
//! until the hold is dropped. It gives the exclusion agent-login setup's write level gives
//! without the assignment manager's lock.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

/// The fence the runner's commands and single-workflow executions pass, shared as
/// `Arc<CommandFence>`.
pub(in crate::service) struct CommandFence {
    state: Mutex<FenceState>,
    /// Signalled when a hold is dropped.
    released: Condvar,
}

#[derive(Default)]
struct FenceState {
    /// The entries not yet dropped.
    in_flight: usize,
    /// Whether a holder holds the fence.
    held: bool,
    /// Whether an entry asked while the fence was held; cleared when a hold is taken and
    /// when it is dropped.
    wanted: bool,
}

impl CommandFence {
    /// A fence nothing is in and nothing holds.
    pub(in crate::service) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(FenceState::default()),
            released: Condvar::new(),
        })
    }

    /// The fence's state, held for the read or change alone and never across anything else.
    fn state(&self) -> MutexGuard<'_, FenceState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Counts one entry in the fence until the answer is dropped, first marking the hold
    /// wanted and waiting, blocking the calling thread, while the fence is held. Call it on
    /// a blocking worker.
    pub(in crate::service) fn enter(self: &Arc<Self>) -> FenceEntry {
        let mut state = self.state();
        while state.held {
            state.wanted = true;
            state = self
                .released
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        state.in_flight += 1;
        drop(state);
        FenceEntry(Arc::clone(self))
    }

    /// Holds the fence, unwanted, while nothing is in it and nothing holds it, so nothing
    /// enters until the hold is dropped; `None` otherwise.
    pub(in crate::service) fn try_hold(self: &Arc<Self>) -> Option<FenceHold> {
        let mut state = self.state();
        if state.in_flight > 0 || state.held {
            return None;
        }
        state.held = true;
        state.wanted = false;
        drop(state);
        Some(FenceHold(Arc::clone(self)))
    }
}

/// One entry in the fence, counted until it is dropped.
pub(in crate::service) struct FenceEntry(Arc<CommandFence>);

impl Drop for FenceEntry {
    fn drop(&mut self) {
        let mut state = self.0.state();
        state.in_flight = state.in_flight.saturating_sub(1);
    }
}

/// A holder's hold on the fence; dropping it lets every waiting entry in.
pub(in crate::service) struct FenceHold(Arc<CommandFence>);

impl FenceHold {
    /// Whether an entry has asked since the hold was taken.
    pub(in crate::service) fn wanted(&self) -> bool {
        self.0.state().wanted
    }
}

impl Drop for FenceHold {
    fn drop(&mut self) {
        let mut state = self.0.state();
        state.held = false;
        state.wanted = false;
        drop(state);
        self.0.released.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::CommandFence;
    use crate::service::test_support::with_watchdog;
    use crate::service::{Sleeper as _, TokioSleeper};

    // The fence is held only while nothing is in it.
    #[test]
    fn the_fence_is_held_only_while_nothing_is_in_it() {
        let fence = CommandFence::new();
        let entry = fence.enter();
        assert!(fence.try_hold().is_none());
        drop(entry);
        assert!(fence.try_hold().is_some());
    }

    // One holder holds the fence at a time.
    #[test]
    fn a_held_fence_is_not_held_again() {
        let fence = CommandFence::new();
        let _hold = fence.try_hold().unwrap();
        assert!(fence.try_hold().is_none());
    }

    // An entry that asks while the fence is held marks the hold wanted and enters only
    // once the hold is dropped; a later hold starts unwanted.
    #[tokio::test]
    async fn an_entry_waits_for_the_hold_and_marks_it_wanted() {
        let fence = CommandFence::new();
        let hold = fence.try_hold().unwrap();
        assert!(!hold.wanted());
        let entering = tokio::task::spawn_blocking({
            let fence = std::sync::Arc::clone(&fence);
            move || fence.enter()
        });
        // An entry that did not wait would return in this time.
        TokioSleeper.sleep(Duration::from_millis(100)).await;
        assert!(!entering.is_finished());
        assert!(hold.wanted());

        drop(hold);
        let entry = with_watchdog(entering)
            .await
            .expect("the entry did not return once the hold was dropped")
            .unwrap();
        drop(entry);
        assert!(!fence.try_hold().unwrap().wanted());
    }
}
