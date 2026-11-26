use std::sync::{Arc, Mutex};
use std::time::Duration;

use opentelemetry::KeyValue;

use super::{AssignmentManager, LiveStatus, Sleeper};
use crate::telemetry::{self, Recorder};

pub(super) async fn watch(
    timeout: Duration,
    manager: Arc<Mutex<AssignmentManager>>,
    status: Arc<LiveStatus>,
    sleeper: Arc<dyn Sleeper>,
    recorder: Arc<Recorder>,
) {
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
            return;
        }
    }
}
