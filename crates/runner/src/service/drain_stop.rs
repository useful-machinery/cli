use std::future::pending;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opentelemetry::KeyValue;
use useful_runner_protocol::RegistrationMode;

use super::{AssignmentManager, DrainExit, LiveStatus, Sleeper};
use crate::telemetry::{self, Recorder};

pub(super) const DRAIN_RETRY_INTERVAL: Duration = Duration::from_secs(1);

pub(super) async fn watch(
    exit: DrainExit,
    manager: Arc<Mutex<AssignmentManager>>,
    status: Arc<LiveStatus>,
    sleeper: Arc<dyn Sleeper>,
    recorder: Arc<Recorder>,
) {
    let mut mode = status.registration_mode.subscribe();
    let run_ended = manager
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .drain_run_ended();
    loop {
        if *mode.borrow_and_update() != Some(RegistrationMode::Draining) {
            if mode.changed().await.is_err() {
                return;
            }
            continue;
        }
        let deadline = async {
            match exit.deadline {
                Some(limit) => {
                    sleeper.sleep(limit).await;
                    limit
                }
                None => pending().await,
            }
        };
        tokio::pin!(deadline);
        loop {
            let ended = run_ended.notified();
            tokio::pin!(ended);
            ended.as_mut().enable();
            // Hold this read across the admission fence so a mode change that
            // already reached the runner always takes precedence.
            let retry = {
                let current = mode.borrow();
                if current.has_changed() {
                    break;
                }
                let mut manager = manager
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(holds) = manager.idle_holds() {
                    if matches!(manager.begin_idle_shutdown(holds), Ok(true)) {
                        recorder.record("runner.drained", []);
                        return;
                    }
                    true
                } else {
                    false
                }
            };
            tokio::select! {
                biased;
                _ = mode.changed() => break,
                limit = &mut deadline => {
                    // A change can arrive between the two polls of this select.
                    let current = mode.borrow();
                    if current.has_changed() {
                        break;
                    }
                    recorder.record(
                        "runner.drain_deadline",
                        [KeyValue::new(
                            telemetry::attribute::RUNNER_DRAIN_DEADLINE_SECONDS,
                            telemetry::integer(limit.as_secs()),
                        )],
                    );
                    return;
                }
                _ = ended => {}
                _ = sleeper.sleep(DRAIN_RETRY_INTERVAL), if retry => {}
            }
        }
    }
}
