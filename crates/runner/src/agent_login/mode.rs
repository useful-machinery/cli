//! The credential mode the runner goes by: one cell, built with
//! the live status and shared with the connection and the agent-login setup,
//! that every `welcome` and every `assignment_offer` frame the runner reads
//! writes, that the status snapshot reads, and that a
//! periodic or `sync` setup reads once where it begins. The
//! schedule waits for its first write before its first setup, and the control
//! socket refuses a sync until then.

use std::sync::{Mutex, MutexGuard, PoisonError};

use tokio::sync::Notify;

use crate::control_protocol::CredentialMode;

/// What the runner has learned of its credential mode since it started.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Learned {
    /// No `welcome` or `assignment_offer` has named a mode or its absence yet.
    #[default]
    Nothing,
    /// The last frame that names it said this: a mode, or none.
    Mode(Option<CredentialMode>),
}

/// The credential mode the runner goes by, shared by everything that reads or
/// writes it.
#[derive(Debug, Default)]
pub(crate) struct CredentialModeCell {
    learned: Mutex<Learned>,
    /// Wakes each wait for the first write.
    written: Notify,
}

impl CredentialModeCell {
    /// Records the mode the frame just read names; `None` where it names none.
    pub(crate) fn learn(&self, mode: Option<CredentialMode>) {
        *self.lock() = Learned::Mode(mode);
        self.written.notify_waiters();
    }

    /// The mode the runner goes by: none while it has learned nothing, or
    /// learned that it goes by none.
    pub(crate) fn mode(&self) -> Option<CredentialMode> {
        match *self.lock() {
            Learned::Nothing => None,
            Learned::Mode(mode) => mode,
        }
    }

    /// Whether a frame has written the cell since the runner started, a
    /// mode or none: a sync is refused until one has.
    pub(crate) fn learned(&self) -> bool {
        *self.lock() != Learned::Nothing
    }

    /// Returns once a frame has written the cell, at once when one already
    /// has.
    pub(crate) async fn wait_until_learned(&self) {
        loop {
            // Registered before the check, so a write between the check and
            // the wait still wakes it.
            let written = self.written.notified();
            if self.learned() {
                return;
            }
            written.await;
        }
    }

    fn lock(&self) -> MutexGuard<'_, Learned> {
        self.learned.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
