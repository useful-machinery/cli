use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{FutureExt, future::Fuse};
use opentelemetry::KeyValue;
use tokio::sync::oneshot;

use super::{AssignmentManager, LiveStatus, Shutdown, ShutdownFuture, Sleeper};
use crate::telemetry::{self, Recorder};

/// Adds a single idle expiry to the service's usual shutdown signals.
pub(super) struct IdleStop<'a> {
    shutdown: &'a mut dyn Shutdown,
    expiry: Fuse<oneshot::Receiver<()>>,
    watcher: tokio::task::JoinHandle<()>,
}

impl<'a> IdleStop<'a> {
    pub(super) fn start(
        shutdown: &'a mut dyn Shutdown,
        timeout: Duration,
        manager: Arc<Mutex<AssignmentManager>>,
        status: Arc<LiveStatus>,
        sleeper: Arc<dyn Sleeper>,
        recorder: Arc<Recorder>,
    ) -> Self {
        let (expired, expiry) = oneshot::channel();
        let watcher = tokio::spawn(async move {
            let run_ended = manager
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .idle_run_ended();
            status.wait_until_connected().await;
            loop {
                let ended = run_ended.notified();
                tokio::pin!(ended);
                ended.as_mut().enable();
                let holds = manager
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .idle_holds();
                let Some(holds) = holds else {
                    ended.await;
                    continue;
                };
                tokio::select! {
                    _ = ended => continue,
                    _ = sleeper.sleep(timeout) => {}
                }
                // A failed clock read leaves the runner serving. A later full
                // interval can try again, just as when observations still need sending.
                let stopped = manager
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .begin_idle_shutdown(holds);
                if let Ok(true) = stopped {
                    recorder.record(
                        "runner.idle_timeout",
                        [KeyValue::new(
                            telemetry::attribute::RUNNER_IDLE_TIMEOUT_SECONDS,
                            telemetry::integer(timeout.as_secs()),
                        )],
                    );
                    let _ = expired.send(());
                    return;
                }
            }
        });
        Self {
            shutdown,
            expiry: expiry.fuse(),
            watcher,
        }
    }
}

impl Shutdown for IdleStop<'_> {
    fn wait(&mut self) -> ShutdownFuture<'_> {
        Box::pin(async {
            // The fused receiver stays pending after its one delivery. Only a
            // subsequent operator signal can force the graceful shutdown.
            tokio::select! {
                () = self.shutdown.wait() => {}
                Ok(()) = &mut self.expiry => {}
            }
        })
    }
}

impl Drop for IdleStop<'_> {
    fn drop(&mut self) {
        self.watcher.abort();
    }
}
