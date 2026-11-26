mod artifact_delivery;
mod assignment;
mod backoff;
mod build_caches;
mod command_fence;
mod config;
mod connection;
mod control;
#[cfg(test)]
mod conversation;
#[cfg(test)]
mod determinism_spike;
mod disk;
mod drain_stop;
mod execution;
mod history;
mod idle_stop;
mod kept_runs;
mod lease_clock;
pub(crate) mod registration_drain;
mod retirement;
mod run_inputs;
mod source;
#[cfg(test)]
mod test_support;
mod tree_run;
mod workflow_git;
mod workspace;

use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use opentelemetry::KeyValue;

#[cfg(feature = "test-fixtures")]
pub(crate) use assignment::run_nested_workflow_delivery_failure_scenario;
#[cfg(test)]
pub(crate) use config::AssignmentConfig;
pub(crate) use config::BuildCache;
pub(crate) use config::KeptRunBounds;
pub(crate) use config::LOG_DIRECTORY;
pub use config::{Config, ConfigError, DrainExit};
pub use retirement::{Retirement, RetirementCause};
#[cfg(test)]
pub(crate) use test_support::{
    CountedGate, FAKE_AGENT_LOGIN_ID, FAKE_AGENT_LOGIN_SENTINEL, FAKE_GRANT_ID,
    FAKE_GRANT_TOKEN_SENTINEL, FakeAgentLoginCloud, FakeGrantToken, FakeLoginCheck, SleepRelease,
    controlled_sleeper, fake_agent_login_material, fake_codex_authorized, fake_grant_expiry,
    fake_grant_token, with_watchdog,
};

use crate::agent_login::check::ProgramLoginCheck;
use crate::agent_login::setup::{AgentLoginSetup, AssignmentGate, SetupCaller, SetupDependencies};
use crate::control_protocol::{AssignmentCounts, ConnectionFailure, ControlError, PruneScope};
use crate::runner_http::{ServingTarget, Target};
use crate::telemetry::{self, Event, Outcome, Recorder};
use assignment::{AssignmentDependencies, AssignmentManager};
// Enrollment resends an ambiguous join with the same reconnect backoff.
pub(crate) use backoff::Backoff;
use connection::{
    ActiveEffectEvent, ConnectionCause, ConnectionDependencies, ConnectionError,
    ConnectionProgress, FailureKind, FrameSource, OpeningHello, SystemFrameSource, opening_hello,
    record_progress,
};
use control::{
    AdmissionAgentLogins, ControlContext, ControlServer, ControlServerError, ControlTimeouts,
    LiveStatus, RUN_READ_PLACES, ReloadRequest,
};
use kept_runs::{Busy, KeptRunPrune, KeptRunReport, KeptRunRequest};
use lease_clock::{LeaseClock, LeaseClockError};
use useful_execution::MAXIMUM_CANCELLATION_GRACE;
use useful_execution::untested_harness_advisories;

type SleepFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
type ConnectionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ConnectionProgress, ConnectionError>> + Send + 'a>>;
type ShutdownFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

struct Sequence {
    next: Mutex<u64>,
    emission: tokio::sync::Mutex<()>,
}

impl Sequence {
    const fn new(next: u64) -> Self {
        Self {
            next: Mutex::new(next),
            emission: tokio::sync::Mutex::const_new(()),
        }
    }

    fn next(&self) -> Result<u64, ConnectionError> {
        let mut next = self
            .next
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let value = *next;
        *next = next.checked_add(1).ok_or_else(sequence_overflow)?;
        Ok(value)
    }

    fn peek(&self) -> u64 {
        *self
            .next
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    async fn lock_emission(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.emission.lock().await
    }
}

/// How long the runner waits between agent-login setups.
const AGENT_LOGIN_SETUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5 * 60);
/// How long a serving runner with no held run working goes without a kept-run
/// pass.
const KEPT_RUN_PASS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60 * 60);
const SHUTDOWN_DELIVERY_RESERVE: std::time::Duration = std::time::Duration::from_secs(10);
const SHUTDOWN_CLEANUP_RESERVE: std::time::Duration = std::time::Duration::from_secs(5);
/// A stop interrupts every held run at once, each within its own cancellation grace, so one
/// bound sized to the largest grace holds however many runs the runner holds.
const SHUTDOWN_CLEANUP_START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(
    MAXIMUM_CANCELLATION_GRACE.as_secs() + SHUTDOWN_DELIVERY_RESERVE.as_secs(),
);
const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(
    SHUTDOWN_CLEANUP_START_TIMEOUT.as_secs() + SHUTDOWN_CLEANUP_RESERVE.as_secs(),
);

/// What a start holds of the join key its host joined with, which decides
/// what the service does once Cloud refuses its credential.
pub enum JoinKeyMode {
    /// No key was given, or the host's credential came from an activation:
    /// a refused credential parks the runner at `authentication_failed`.
    None,
    /// A key was given but cannot be used; its report says why, once, when
    /// the credential is refused, and the runner then parks.
    Unusable(Box<dyn FnOnce() + Send>),
    /// A key held in memory for a rejoin. It is dropped, and the mode becomes
    /// `Spent`, once a connection completes its handshake.
    Held(Box<dyn Rejoin>),
    /// The process no longer holds the key it was started with: a refused
    /// credential ends the service as `ServiceEnd::CredentialRefused`.
    Spent,
}

impl JoinKeyMode {
    const fn holds_key(&self) -> bool {
        matches!(self, Self::Unusable(_) | Self::Held(_))
    }

    /// A connection's handshake completed: a connected runner holds no key.
    fn handshake_completed(&mut self) {
        *self = match std::mem::replace(self, Self::None) {
            Self::Held(_) | Self::Spent => Self::Spent,
            Self::Unusable(_) | Self::None => Self::None,
        };
    }
}

impl Config {
    /// The runner the host's enrolled state names, the one a rejoin
    /// replaces.
    pub fn runner_id(&self) -> &str {
        self.credential().runner_id()
    }

    /// The host's enrollment journal, beside its state file, where a rejoin
    /// is staged before it is sent.
    pub fn enrollment_journal_path(&self) -> Option<PathBuf> {
        let state = self.state_access()?.path();
        Some(state.parent()?.join(crate::enrollment::JOURNAL_FILE))
    }
}

/// The rejoin a held join key sends when Cloud refuses the runner's
/// credential. `attempt` blocks for one send and is run on the blocking pool.
pub trait Rejoin: Send {
    fn attempt(&mut self) -> RejoinAnswer;
    /// The attempt went unanswered and is sent again after `retry.delay`.
    fn retrying(&mut self, retry: crate::enrollment::JoinRetry);
}

/// The answer to one rejoin attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejoinAnswer {
    /// Cloud registered the host as a new runner, whose state replaced the
    /// host's.
    Rejoined,
    /// Cloud gave no definite answer; the staged rejoin is sent again.
    Unanswered(crate::enrollment::AmbiguousCause),
    /// Cloud refused the rejoin, or it could not be sent.
    Refused,
}

/// How a service run ended without an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceEnd {
    /// A stop signal ended it.
    Stopped,
    /// The host rejoined as a new runner, which a new service run serves.
    Rejoined,
    /// Cloud refused the credential of a process that no longer holds its
    /// join key.
    CredentialRefused,
}

/// What the loop does, parked behind a refused credential, given its mode
/// and the assignments it holds: nothing while it holds one.
#[derive(Debug, Eq, PartialEq)]
enum RefusalStep {
    Wait,
    Report,
    Rejoin,
    End,
}

fn refusal_step(join_key: &JoinKeyMode, counts: AssignmentCounts) -> RefusalStep {
    if counts != AssignmentCounts::default() {
        return RefusalStep::Wait;
    }
    match join_key {
        JoinKeyMode::None => RefusalStep::Wait,
        JoinKeyMode::Unusable(_) => RefusalStep::Report,
        JoinKeyMode::Held(_) => RefusalStep::Rejoin,
        JoinKeyMode::Spent => RefusalStep::End,
    }
}

/// How answering a refused credential left the loop.
enum RefusalAnswer {
    /// The loop parks, as it does with no key.
    Parked,
    /// A stop signal arrived while a rejoin was sent or waited to be sent.
    Shutdown,
    Ended(ServiceEnd),
}

pub(crate) trait Sleeper: Send + Sync {
    fn now(&self) -> std::time::Instant;
    fn utc_now(&self) -> time::OffsetDateTime;
    fn sleep(&self, duration: std::time::Duration) -> SleepFuture<'_>;
}

trait Shutdown: Send {
    fn wait(&mut self) -> ShutdownFuture<'_>;

    fn disarm_automatic_stops(&mut self) {}
}

/// An automatic stop is a first signal only. Once shutdown starts, disarm
/// every nested watcher so only another operator signal can force an exit.
struct AutomaticStop<'a> {
    shutdown: &'a mut dyn Shutdown,
    expiry: futures_util::future::Fuse<tokio::sync::oneshot::Receiver<()>>,
    watcher: Option<tokio::task::JoinHandle<()>>,
}

impl<'a> AutomaticStop<'a> {
    fn new(
        shutdown: &'a mut dyn Shutdown,
        watch: impl Future<Output = ()> + Send + 'static,
    ) -> Self {
        use futures_util::FutureExt as _;

        let (expired, expiry) = tokio::sync::oneshot::channel();
        let watcher = tokio::spawn(async move {
            watch.await;
            let _ = expired.send(());
        });
        Self {
            shutdown,
            expiry: expiry.fuse(),
            watcher: Some(watcher),
        }
    }
}

impl Shutdown for AutomaticStop<'_> {
    fn wait(&mut self) -> ShutdownFuture<'_> {
        Box::pin(async {
            tokio::select! {
                () = self.shutdown.wait() => {}
                Ok(()) = &mut self.expiry, if self.watcher.is_some() => {}
            }
        })
    }

    fn disarm_automatic_stops(&mut self) {
        if let Some(watcher) = self.watcher.take() {
            watcher.abort();
        }
        self.shutdown.disarm_automatic_stops();
    }
}

impl Drop for AutomaticStop<'_> {
    fn drop(&mut self) {
        self.disarm_automatic_stops();
    }
}

struct ProcessShutdown {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

impl ProcessShutdown {
    fn new() -> Result<Self, ServiceError> {
        let interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .map_err(|_| ServiceError::BuildRuntime)?;
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|_| ServiceError::BuildRuntime)?;
        Ok(Self {
            interrupt,
            terminate,
        })
    }
}

impl Shutdown for ProcessShutdown {
    fn wait(&mut self) -> ShutdownFuture<'_> {
        Box::pin(async {
            tokio::select! {
                _ = self.interrupt.recv() => {}
                _ = self.terminate.recv() => {}
            }
        })
    }
}

struct TokioSleeper;

impl Sleeper for TokioSleeper {
    #[expect(
        clippy::disallowed_methods,
        reason = "TokioSleeper is the production boundary for monotonic runner time"
    )]
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }

    fn utc_now(&self) -> time::OffsetDateTime {
        useful_support::utc_now()
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "TokioSleeper is the production boundary for wall-clock sleeps"
    )]
    fn sleep(&self, duration: std::time::Duration) -> SleepFuture<'_> {
        Box::pin(tokio::time::sleep(duration))
    }
}

struct ConnectionAttempt<'a> {
    dependencies: ConnectionDependencies<'a>,
    opening: OpeningHello<'a>,
    next_sequence: &'a Sequence,
}

struct PromotedAttempt {
    config: Config,
    opening: Vec<u8>,
    opening_message_id: String,
    opening_sequence: u64,
    attempt: u64,
    connection: connection::CandidateConnection,
    connection_event: Event,
    active_effect_event: ActiveEffectEvent,
}

enum ActiveAttemptResult {
    Finished(Result<ConnectionProgress, ConnectionError>),
    Promoted(Box<PromotedAttempt>),
}

enum ActiveEvent {
    ManualReload(ReloadRequest),
    Handshake,
    StartupReload,
    AssignmentNotification,
    Shutdown,
    Finished(Result<ConnectionProgress, ConnectionError>),
}

enum ConnectedReloadResult {
    Continue,
    Promoted(Box<PromotedAttempt>),
    Shutdown,
    Finished(Result<ConnectionProgress, ConnectionError>),
}

struct PreparedReload {
    target: Target,
    state_access: crate::enrollment::RunnerStateAccess,
    expected_runner_id: String,
    expected_current_credential_id: String,
    candidate: PromotedAttempt,
}

struct ReloadDependencies {
    target: ServingTarget,
    boot_id: String,
    /// Whether the service has its agent-login setup, so a candidate's hello advertises the
    /// credential mode as the connection loop's does.
    credential_mode: bool,
    frame_source: Arc<dyn FrameSource>,
    sleeper: Arc<dyn Sleeper>,
    recorder: Arc<Recorder>,
    assignment_manager: Arc<Mutex<AssignmentManager>>,
    live_status: Arc<LiveStatus>,
}

/// The assignment manager as the periodic and `sync` agent-login passes and login checks see
/// it: every assignment it holds, read under its lock. Asking Cloud and checking a login need
/// only that no held run is working; an install or removal also that none has a command in
/// flight, and runs under the manager's lock holding each waiting run's activity, so no
/// assignment is admitted and no held run starts a command during it. An admission's own pass
/// does not consult it: it is gated on the other runs held when its preparation began, never
/// under the manager's lock.
struct HeldRunGate {
    assignment_manager: Arc<Mutex<AssignmentManager>>,
    // Setup runs on a thread of its own, and reading the manager's state may
    // hand work to the runtime.
    runtime: tokio::runtime::Handle,
}

impl HeldRunGate {
    fn new(assignment_manager: Arc<Mutex<AssignmentManager>>) -> Self {
        Self {
            assignment_manager,
            runtime: tokio::runtime::Handle::current(),
        }
    }

    /// Answers `answer` of what the manager holds, under its lock.
    fn with_held_runs<T>(&self, answer: impl FnOnce(&tree_run::HeldRuns) -> T) -> T {
        let _runtime = self.runtime.enter();
        let mut manager = self
            .assignment_manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        answer(&manager.held_runs())
    }
}

impl AssignmentGate for HeldRunGate {
    fn none_working(&self) -> bool {
        self.with_held_runs(tree_run::HeldRuns::none_working)
    }

    fn while_still(&self, change: &mut dyn FnMut()) -> bool {
        self.with_held_runs(|held| held.while_still(change))
    }
}

/// The serving process's repeating agent-login setup: a setup once Cloud has
/// first welcomed the runner, when the credential mode it goes by is first
/// written, then one every
/// `AGENT_LOGIN_SETUP_INTERVAL` on the service's sleeper, each checking a
/// login it installed and publishing the readiness it
/// recorded in the live status. A setup that finds a held run working is
/// skipped, not queued. Dropping the schedule stops it.
struct AgentLoginSchedule {
    task: tokio::task::JoinHandle<()>,
}

impl AgentLoginSchedule {
    fn start(
        setup: Arc<AgentLoginSetup>,
        status: Arc<LiveStatus>,
        sleeper: Arc<dyn Sleeper>,
    ) -> Self {
        Self {
            task: tokio::spawn(async move {
                status.credential_mode().wait_until_learned().await;
                loop {
                    let _ =
                        control::set_up_agent_logins(&setup, &status, SetupCaller::Schedule).await;
                    sleeper.sleep(AGENT_LOGIN_SETUP_INTERVAL).await;
                }
            }),
        }
    }
}

impl Drop for AgentLoginSchedule {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The serving process's kept-run passes: one when it starts, one once no held run is
/// working after a run has ended, and one when `KEPT_RUN_PASS_INTERVAL` passes, the hour
/// starting again after each pass. A pass is due only while no held run is working, at the
/// read level of its own held-run gate: one due at the hour while a run works is skipped,
/// not queued, and one due after a run's end waits for the next end or the hour. Each runs
/// on the blocking pool and asks again before each directory, so a run that starts working,
/// or the schedule's stop, ends it before its next removal. Stopping lets the directory
/// being removed finish and starts nothing else; the service joins the pass in flight before
/// it releases its boot root or returns, since the pass holds the work-root lease's
/// lock-bearing trees.
///
/// A pass first applies the kept-run bounds, which need no exclusion from a command: the
/// claim fence covers their one race. It then evicts from the build caches, which holds
/// the command fence: it is skipped while a command is in the fence, and ends once a
/// command asks to enter, the schedule stops or a held run is working, the next pass
/// beginning it again.
///
/// The schedule's task also serves the control socket's `kept` and `prune` requests from
/// its channel, one at a time and only between its passes, each on the blocking pool as
/// a pass is, so no two passes or reports overlap and its stop ends and joins an
/// operator's pass as it does its own. A `prune` asks the pass's own question first and
/// is answered `runner_busy` when a held run is working; a report asks only whether the
/// schedule is stopping. A request leaves the hour as it is. A request the schedule no
/// longer takes, once it has stopped, is dropped, and its connection closed unanswered.
struct KeptRunSchedule {
    stopping: Arc<AtomicBool>,
    stopped: Arc<tokio::sync::Notify>,
    task: Option<tokio::task::JoinHandle<()>>,
}

/// What one kept-run pass is run with.
struct KeptRunPass {
    work_root: Arc<workspace::WorkRootLease>,
    bounds: KeptRunBounds,
    build_caches: Arc<BuildCacheEviction>,
    gate: Arc<HeldRunGate>,
    stopping: Arc<AtomicBool>,
    sleeper: Arc<dyn Sleeper>,
    recorder: Arc<Recorder>,
}

impl KeptRunPass {
    /// Runs a scheduled pass under the bounds on the blocking pool when no held run is
    /// working and the schedule is not stopped, and answers whether it ran.
    async fn run(&self) -> bool {
        matches!(self.prune(PruneScope::Bounds).await, Some(Ok(_)))
    }

    /// Serves one control socket request, dropping its answer's sender when the request
    /// cannot be answered.
    async fn serve(&self, request: KeptRunRequest) {
        match request {
            KeptRunRequest::Report { scope, answer } => {
                if let Some(report) = self.report(scope).await {
                    let _ = answer.send(report);
                }
            }
            KeptRunRequest::Prune { scope, answer } => {
                if let Some(result) = self.prune(scope).await {
                    let _ = answer.send(result);
                }
            }
        }
    }

    /// Reports the kept workspaces and the build caches under `scope` on the blocking pool,
    /// whatever the held runs are doing; none once the schedule is stopping.
    async fn report(&self, scope: PruneScope) -> Option<KeptRunReport> {
        let work_root = Arc::clone(&self.work_root);
        let stopping = Arc::clone(&self.stopping);
        let eviction = Arc::clone(&self.build_caches);
        let bounds = self.bounds;
        let now = self.sleeper.utc_now();
        tokio::task::spawn_blocking(move || {
            let may_continue = || !stopping.load(Ordering::Acquire);
            let workspaces = kept_runs::kept_report(&work_root, bounds, scope, now, &may_continue)?;
            let caches = build_caches::measure_build_caches(
                &eviction.caches,
                &eviction.protected,
                scope,
                &may_continue,
            )?;
            Some(KeptRunReport {
                scope,
                bounds,
                now,
                workspaces,
                caches,
            })
        })
        .await
        .ok()
        .flatten()
    }

    /// Applies the kept-run bounds, or removes every kept workspace under `All`, and evicts
    /// from the build caches on the blocking pool: `Busy`, touching nothing, when a held
    /// run is working or the schedule is stopping; otherwise what it did, not `complete`
    /// once either ended it or the command fence ended or skipped the eviction. None when
    /// the pass did not return.
    async fn prune(&self, scope: PruneScope) -> Option<Result<KeptRunPrune, Busy>> {
        let work_root = Arc::clone(&self.work_root);
        let gate = Arc::clone(&self.gate);
        let stopping = Arc::clone(&self.stopping);
        let recorder = Arc::clone(&self.recorder);
        let eviction = Arc::clone(&self.build_caches);
        let bounds = self.bounds;
        let now = self.sleeper.utc_now();
        tokio::task::spawn_blocking(move || {
            let ended = std::cell::Cell::new(false);
            let may_continue = || {
                let more = !stopping.load(Ordering::Acquire) && gate.none_working();
                if !more {
                    ended.set(true);
                }
                more
            };
            if !may_continue() {
                return Err(Busy);
            }
            let directories = kept_runs::prune_kept_runs(
                &work_root,
                bounds,
                scope,
                now,
                &may_continue,
                Some(&recorder),
            );
            let mut caches = Vec::new();
            let mut evicted = true;
            if !eviction.caches.is_empty() && may_continue() {
                match build_caches::evict_under_fence(
                    &eviction.caches,
                    &eviction.protected,
                    scope,
                    &eviction.fence,
                    &may_continue,
                    Some(&recorder),
                ) {
                    Some(evictions) => caches = evictions,
                    None => evicted = false,
                }
            }
            let complete =
                evicted && !ended.get() && caches.iter().all(|cache| !cache.evicted.stopped);
            Ok(KeptRunPrune {
                scope,
                complete,
                directories,
                caches,
            })
        })
        .await
        .ok()
    }
}

/// What a kept-run pass evicts from its build caches with.
struct BuildCacheEviction {
    caches: Vec<BuildCache>,
    /// The work root and the directories that hold the state file and the control socket.
    protected: Vec<PathBuf>,
    fence: Arc<command_fence::CommandFence>,
}

impl KeptRunSchedule {
    fn new() -> Self {
        Self {
            stopping: Arc::new(AtomicBool::new(false)),
            stopped: Arc::new(tokio::sync::Notify::new()),
            task: None,
        }
    }

    /// Starts the passes over the kept directories of `assignment_manager`'s work root,
    /// under `config`'s kept-run bounds, and over its build caches, whose eviction enters
    /// none of its protected directories (`protected_paths`), and serves `requests` between
    /// them until the channel closes or the schedule stops.
    fn start(
        &mut self,
        assignment_manager: &Arc<Mutex<AssignmentManager>>,
        config: &Config,
        sleeper: Arc<dyn Sleeper>,
        recorder: Arc<Recorder>,
        requests: tokio::sync::mpsc::Receiver<KeptRunRequest>,
    ) {
        let (work_root, run_ended, fence) = {
            let manager = assignment_manager
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (
                manager.work_root(),
                manager.run_ended(),
                manager.command_fence(),
            )
        };
        let pass = KeptRunPass {
            work_root,
            bounds: config.assignment().kept_runs(),
            build_caches: Arc::new(BuildCacheEviction {
                caches: config.assignment().build_caches().to_vec(),
                protected: protected_paths(config),
                fence,
            }),
            gate: Arc::new(HeldRunGate::new(Arc::clone(assignment_manager))),
            stopping: Arc::clone(&self.stopping),
            sleeper: Arc::clone(&sleeper),
            recorder,
        };
        let stopped = Arc::clone(&self.stopped);
        self.task = Some(tokio::spawn(async move {
            // Cleared once the channel closes, so a closed channel neither ends the schedule
            // nor is polled again.
            let mut requests = Some(requests);
            pass.run().await;
            loop {
                let mut hour = sleeper.sleep(KEPT_RUN_PASS_INTERVAL);
                loop {
                    tokio::select! {
                        biased;
                        () = stopped.notified() => return,
                        request = next_request(&mut requests), if requests.is_some() => {
                            match request {
                                Some(request) => pass.serve(request).await,
                                None => requests = None,
                            }
                        }
                        () = run_ended.notified() => {
                            if pass.run().await {
                                break;
                            }
                        }
                        () = &mut hour => {
                            pass.run().await;
                            break;
                        }
                    }
                }
            }
        }));
    }

    /// Stops the schedule: the pass in flight ends after the directory it is removing, and
    /// no other starts.
    fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.stopped.notify_one();
    }

    /// Stops the schedule and waits until its pass in flight, if any, has ended.
    async fn stop_and_join(&mut self) {
        self.stop();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

/// The next request on the schedule's channel; none once it has closed.
async fn next_request(
    requests: &mut Option<tokio::sync::mpsc::Receiver<KeptRunRequest>>,
) -> Option<KeptRunRequest> {
    match requests {
        Some(requests) => requests.recv().await,
        None => None,
    }
}

impl Drop for KeptRunSchedule {
    fn drop(&mut self) {
        self.stop();
    }
}

/// What a build-cache eviction never enters: the work root and the directories that hold
/// the state file and the control socket, each `config` holds.
fn protected_paths(config: &Config) -> Vec<PathBuf> {
    let state = config
        .state_access()
        .and_then(|access| access.path().parent());
    let socket = config.control_socket_path().and_then(Path::parent);
    std::iter::once(config.assignment().work_root())
        .chain(state)
        .chain(socket)
        .map(Path::to_path_buf)
        .collect()
}

trait Connector: Send + Sync {
    fn connect<'a>(&'a self, attempt: ConnectionAttempt<'a>) -> ConnectionFuture<'a>;
}

struct WebSocketConnector;

impl Connector for WebSocketConnector {
    fn connect<'a>(&'a self, attempt: ConnectionAttempt<'a>) -> ConnectionFuture<'a> {
        Box::pin(connection::run(
            attempt.dependencies,
            attempt.opening,
            attempt.next_sequence,
        ))
    }
}

struct ConnectionLoopDependencies {
    target: ServingTarget,
    config: Config,
    frame_source: Arc<dyn FrameSource>,
    sleeper: Arc<dyn Sleeper>,
    recorder: Arc<Recorder>,
    lease_clock: LeaseClock,
    boot_id: String,
    source_broker: Option<Arc<dyn source::SourceCredentialBroker>>,
    /// Agent-login setup, for a runner with protected state to record its
    /// readiness beside.
    agent_login_setup: Option<SetupDependencies>,
    /// The disk monitor's reader and sleeper; a loop without them starts no monitor.
    disk: Option<disk::DiskMonitorDependencies>,
}

#[derive(Debug)]
pub(crate) enum ServiceError {
    BuildRuntime,
    AssignmentShutdown,
    ShutdownForced,
    ShutdownDeadlineExceeded,
    Connection(ConnectionError),
    Control(ControlServerError),
    LeaseClock(LeaseClockError),
    WorkRootInUse,
    WorkRootIsolation,
    WorkspaceCleanupFailed(Option<Vec<String>>),
    BrokerConfiguration(url::Url),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuildRuntime => formatter.write_str("start runner service"),
            Self::AssignmentShutdown => formatter.write_str("prepare runner assignment shutdown"),
            Self::ShutdownForced => {
                formatter.write_str("runner shutdown forced by repeated signal")
            }
            Self::ShutdownDeadlineExceeded => {
                formatter.write_str("runner graceful shutdown deadline exceeded")
            }
            Self::Connection(error) => {
                write!(formatter, "runner service stopped unexpectedly: {error}")
            }
            Self::Control(error) => write!(formatter, "start runner local control: {error}"),
            Self::LeaseClock(error) => write!(formatter, "runner lease clock failed: {error}"),
            Self::WorkRootInUse => formatter.write_str("runner work root is already in use"),
            Self::WorkRootIsolation => {
                formatter.write_str("runner work-root isolation could not be established")
            }
            Self::WorkspaceCleanupFailed(Some(surviving)) => write!(
                formatter,
                "runner process quiescence unproven: surviving guards {surviving:?}\n\nInspect the retained workspace and stop surviving processes before restarting the runner."
            ),
            Self::WorkspaceCleanupFailed(None) => {
                formatter.write_str("runner workspace cleanup failed")
            }
            Self::BrokerConfiguration(endpoint) => write!(
                formatter,
                "start runner HTTP brokers: unsupported {} endpoint scheme\n\nUse a ws or wss runner endpoint.",
                endpoint.scheme()
            ),
        }
    }
}

impl ServiceError {
    pub(crate) const fn requires_operator_recovery(&self) -> bool {
        matches!(
            self,
            Self::WorkRootInUse | Self::WorkRootIsolation | Self::WorkspaceCleanupFailed(_)
        )
    }
}

impl std::error::Error for ServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BuildRuntime
            | Self::AssignmentShutdown
            | Self::ShutdownForced
            | Self::ShutdownDeadlineExceeded
            | Self::WorkRootInUse
            | Self::WorkRootIsolation
            | Self::WorkspaceCleanupFailed(_)
            | Self::BrokerConfiguration(_) => None,
            Self::Connection(error) => Some(error),
            Self::Control(error) => Some(error),
            Self::LeaseClock(error) => Some(error),
        }
    }
}

pub(crate) fn workflow_git_helper_requested() -> bool {
    workflow_git::internal_helper_requested()
}

pub(crate) fn run_workflow_git_helper() -> bool {
    workflow_git::run_internal_helper()
}

/// Serves `config` until a stop or an end. Every task the run started, the
/// blocking pool's included, ends with its runtime, and a run that ends
/// `Rejoined` has first waited for the threads of its agent-login setup,
/// which the runtime does not own, so the work root it leased can be
/// leased again by the next run once it returns.
pub(crate) fn run(
    config: Config,
    service_version: &str,
    join_key: JoinKeyMode,
) -> Result<ServiceEnd, ServiceError> {
    service_runtime()?.block_on(async {
        let mut shutdown = ProcessShutdown::new()?;
        let target = serving_target(&config)?;
        run_until_cancelled(config, service_version, join_key, target, &mut shutdown).await
    })
}

fn service_runtime() -> Result<tokio::runtime::Runtime, ServiceError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ServiceError::BuildRuntime)
}

pub(crate) fn run_ephemeral(
    config: Config,
    service_version: &str,
) -> Result<(Result<ServiceEnd, ServiceError>, Retirement), ServiceError> {
    service_runtime()?.block_on(async {
        let mut shutdown = ProcessShutdown::new()?;
        let target = serving_target(&config)?;
        let service = run_until_cancelled(
            config,
            service_version,
            JoinKeyMode::Spent,
            target.clone(),
            &mut shutdown,
        )
        .await;
        let retirement = match service {
            Ok(ServiceEnd::CredentialRefused) => {
                Retirement::Kept(RetirementCause::CredentialNotAccepted)
            }
            Err(ServiceError::ShutdownForced) => Retirement::Kept(RetirementCause::Abandoned),
            _ => {
                retirement::retire(
                    target.current(),
                    &TokioSleeper,
                    &mut shutdown,
                    Backoff::new(),
                )
                .await
            }
        };
        Ok((service, retirement))
    })
}

fn serving_target(config: &Config) -> Result<ServingTarget, ServiceError> {
    Target::new(config.endpoint(), config.credential())
        .map(ServingTarget::new)
        .ok_or_else(|| ServiceError::BrokerConfiguration(config.endpoint().clone()))
}

async fn run_until_cancelled(
    config: Config,
    service_version: &str,
    join_key: JoinKeyMode,
    target: ServingTarget,
    shutdown: &mut dyn Shutdown,
) -> Result<ServiceEnd, ServiceError> {
    let frame_source: Arc<dyn FrameSource> = Arc::new(SystemFrameSource);
    let sleeper: Arc<dyn Sleeper> = Arc::new(TokioSleeper);
    let boot_id = frame_source.public_id("rbt_");
    let clock_sleeper = Arc::clone(&sleeper);
    let recorder = Recorder::open(
        &boot_id,
        service_version,
        Arc::new(move || clock_sleeper.utc_now()),
        config.log_directory().map(Path::to_path_buf),
    );
    let lease_clock = LeaseClock::system().map_err(ServiceError::LeaseClock)?;
    let agent_login_setup = config.state_access().map(|state| {
        // A login is checked with the programs `serve` validated when it
        // started.
        let check = ProgramLoginCheck::new(
            config.claude_code_installation().cloned(),
            config.codex_installation().cloned(),
            state.path(),
            service_version,
            execution::RunnerExecutionClock,
        );
        SetupDependencies::enrolled(
            target.clone(),
            Arc::new(check),
            state.path(),
            Arc::clone(&recorder),
        )
    });
    let disk = Some(disk::DiskMonitorDependencies {
        reader: Arc::new(disk::SystemDiskReader),
        sleeper: Arc::clone(&sleeper),
    });
    Box::pin(run_connection_loop(
        ConnectionLoopDependencies {
            target,
            config,
            frame_source,
            sleeper,
            recorder,
            lease_clock,
            boot_id,
            source_broker: None,
            agent_login_setup,
            disk,
        },
        &WebSocketConnector,
        Backoff::new(),
        shutdown,
        join_key,
    ))
    .await
}

/// The loop's dependencies for a test of the whole service: no agent-login setup.
#[cfg(test)]
fn fixture_loop_dependencies(
    config: Config,
    frame_source: Arc<dyn FrameSource>,
    sleeper: Arc<dyn Sleeper>,
    recorder: Arc<Recorder>,
    source_broker: Option<Arc<dyn source::SourceCredentialBroker>>,
) -> Result<ConnectionLoopDependencies, ServiceError> {
    let boot_id = frame_source.public_id("rbt_");
    let lease_clock = LeaseClock::system().map_err(ServiceError::LeaseClock)?;
    Ok(ConnectionLoopDependencies {
        target: serving_target(&config)?,
        config,
        frame_source,
        sleeper,
        recorder,
        lease_clock,
        boot_id,
        source_broker,
        agent_login_setup: None,
        disk: None,
    })
}

#[cfg(test)]
async fn run_until_cancelled_with_dependencies(
    config: Config,
    frame_source: Arc<dyn FrameSource>,
    sleeper: Arc<dyn Sleeper>,
    recorder: Arc<Recorder>,
    source_broker: Option<Arc<dyn source::SourceCredentialBroker>>,
    mut shutdown: Box<dyn Shutdown>,
    join_key: JoinKeyMode,
) -> Result<ServiceEnd, ServiceError> {
    run_connection_loop_with_filesystem(
        fixture_loop_dependencies(config, frame_source, sleeper, recorder, source_broker)?,
        &WebSocketConnector,
        Backoff::new(),
        shutdown.as_mut(),
        workspace::WorkspaceFilesystem::testing(),
        join_key,
    )
    .await
}

async fn run_connection_loop(
    dependencies: ConnectionLoopDependencies,
    connector: &dyn Connector,
    backoff: Backoff,
    shutdown: &mut dyn Shutdown,
    join_key: JoinKeyMode,
) -> Result<ServiceEnd, ServiceError> {
    Box::pin(run_connection_loop_acquiring(
        dependencies,
        connector,
        backoff,
        shutdown,
        |root, boot| workspace::WorkRootLease::acquire(&root, &boot),
        join_key,
    ))
    .await
}

#[cfg(test)]
async fn run_connection_loop_with_filesystem(
    dependencies: ConnectionLoopDependencies,
    connector: &dyn Connector,
    backoff: Backoff,
    shutdown: &mut dyn Shutdown,
    filesystem: workspace::WorkspaceFilesystem,
    join_key: JoinKeyMode,
) -> Result<ServiceEnd, ServiceError> {
    run_connection_loop_acquiring(
        dependencies,
        connector,
        backoff,
        shutdown,
        move |root, boot| workspace::WorkRootLease::acquire_with(&root, &boot, filesystem),
        join_key,
    )
    .await
}

async fn run_connection_loop_acquiring<Acquire>(
    dependencies: ConnectionLoopDependencies,
    connector: &dyn Connector,
    backoff: Backoff,
    shutdown: &mut dyn Shutdown,
    acquire: Acquire,
    join_key: JoinKeyMode,
) -> Result<ServiceEnd, ServiceError>
where
    Acquire: FnOnce(PathBuf, String) -> Result<Arc<workspace::WorkRootLease>, workspace::WorkRootError>
        + Send
        + 'static,
{
    // Recorded before work-root acquisition and the first connection attempt so an
    // operator sees the advisory even when startup or the gateway then fails.
    record_untested_harnesses(&dependencies.recorder, &dependencies.config);
    let work_root_path = dependencies.config.assignment().work_root().to_owned();
    let boot_id = dependencies.boot_id.clone();
    let work_root =
        match tokio::task::spawn_blocking(move || acquire(work_root_path, boot_id)).await {
            Ok(Ok(work_root)) => work_root,
            Ok(Err(error)) => {
                record_non_admitting_failure(&dependencies.recorder, error.error_type());
                return Err(work_root_service_error(error));
            }
            Err(_) => return Err(ServiceError::BuildRuntime),
        };
    record_startup_retention(&dependencies.recorder, work_root.startup_retained());
    let result = Box::pin(run_connection_loop_in_mode(
        dependencies,
        connector,
        backoff,
        shutdown,
        Arc::clone(&work_root),
        join_key,
    ))
    .await;
    if result.is_err() {
        work_root.cancel_cleanup();
    }
    result
}

/// Boxes the connection loop's state (about 39 KB in a debug build, growing with
/// the runner-protocol types it holds across await points). Returned by value,
/// it was copied into each awaiting caller's frame, and with frame decoding on
/// top that overflowed a two-megabyte test-thread stack.
fn run_connection_loop_in_mode<'a>(
    dependencies: ConnectionLoopDependencies,
    connector: &'a dyn Connector,
    backoff: Backoff,
    shutdown: &'a mut dyn Shutdown,
    work_root: Arc<workspace::WorkRootLease>,
    join_key: JoinKeyMode,
) -> Pin<Box<impl Future<Output = Result<ServiceEnd, ServiceError>> + 'a>> {
    Box::pin(async move {
        let mut kept_runs = KeptRunSchedule::new();
        let result = Box::pin(connection_loop_with_work_root(
            dependencies,
            connector,
            backoff,
            shutdown,
            work_root,
            join_key,
            &mut kept_runs,
        ))
        .await;
        // Every end, an early one's included, waits for the kept-run pass in flight, so a
        // rejoined runner's next service can lease the work root again.
        kept_runs.stop_and_join().await;
        result
    })
}

/// The loop of a start that holds no join key, whose only end is a stop.
#[cfg(test)]
async fn run_connection_loop_with_work_root(
    dependencies: ConnectionLoopDependencies,
    connector: &dyn Connector,
    backoff: Backoff,
    shutdown: &mut dyn Shutdown,
    work_root: Arc<workspace::WorkRootLease>,
) -> Result<(), ServiceError> {
    run_connection_loop_in_mode(
        dependencies,
        connector,
        backoff,
        shutdown,
        work_root,
        JoinKeyMode::None,
    )
    .await
    .map(|_stopped| ())
}

async fn connection_loop_with_work_root(
    dependencies: ConnectionLoopDependencies,
    connector: &dyn Connector,
    mut backoff: Backoff,
    shutdown: &mut dyn Shutdown,
    work_root: Arc<workspace::WorkRootLease>,
    mut join_key: JoinKeyMode,
    kept_runs: &mut KeptRunSchedule,
) -> Result<ServiceEnd, ServiceError> {
    let ConnectionLoopDependencies {
        target,
        mut config,
        frame_source,
        sleeper,
        recorder,
        lease_clock,
        boot_id,
        source_broker,
        agent_login_setup,
        disk,
    } = dependencies;
    // The monitor publishes its reading of the work root's disk in this handle, which the
    // control socket's answers and the offer rule copy from; a service without a monitor
    // has none, its answers carry no reading and its offer rule never finds the disk low.
    let disk_reading = disk.as_ref().map(|_| disk::DiskReadingHandle::new());
    let mut live_status = LiveStatus::new(
        boot_id.clone(),
        config.credential().credential_id().to_owned(),
        config
            .startup_pending()
            .map(|pending| pending.credential_id.clone()),
    )
    .with_log_path(recorder.log_path());
    if let Some(reading) = &disk_reading {
        live_status = live_status.with_disk(reading.clone());
    }
    let live_status = Arc::new(live_status);
    // The monitor reads the work root's disk from here until the loop returns.
    let _disk_monitor = disk
        .zip(disk_reading.clone())
        .map(|(dependencies, reading)| {
            disk::DiskMonitor::start(
                dependencies,
                reading,
                config.assignment().work_root().to_owned(),
                config.minimum_free_disk_bytes(),
                Arc::clone(live_status.events()),
                Arc::clone(&recorder),
            )
        });
    recorder.set_dropped_record_observer(Arc::<history::EventLog>::clone(live_status.events()));
    let assignment_dependencies = AssignmentDependencies::production(
        target.clone(),
        config.repository_url_policy(),
        &boot_id,
        Arc::clone(&sleeper),
        Arc::clone(&work_root),
        Arc::clone(&recorder),
        source_broker,
    )
    .with_events(Arc::clone(live_status.events()));
    // The offer rule declines new runs while the monitor's reading is low, and a running
    // run holds its next step while it is: a single-workflow run on the monitor's reading,
    // a tree run's `useful` commands on the same disk and minimum, which they read
    // themselves and are given only above 0.
    let assignment_dependencies = match disk_reading {
        Some(reading) => {
            // The configuration already refuses what `RunnerDiskGate::new` refuses: its work
            // root is canonical and its minimum at most the largest allowed.
            let tree_gate = match config.minimum_free_disk_bytes() {
                0 => None,
                minimum => useful_execution::RunnerDiskGate::new(
                    config.assignment().work_root().to_owned(),
                    minimum,
                )
                .ok(),
            };
            assignment_dependencies.with_disk(reading, tree_gate)
        }
        None => assignment_dependencies,
    };
    let assignment_manager = Arc::new(Mutex::new(AssignmentManager::new(
        &config,
        lease_clock,
        assignment_dependencies,
    )));
    let found = work_root.startup_retained().len();
    if found != 0 {
        live_status
            .events()
            .record(history::LoggedEvent::WorkspacesFound {
                workspaces: u64::try_from(found).unwrap_or(u64::MAX),
            });
    }
    let credential_mode = agent_login_setup.is_some();
    let reload_dependencies = ReloadDependencies {
        target: target.clone(),
        boot_id: boot_id.clone(),
        credential_mode,
        frame_source: Arc::clone(&frame_source),
        sleeper: Arc::clone(&sleeper),
        recorder: Arc::clone(&recorder),
        assignment_manager: Arc::clone(&assignment_manager),
        live_status: Arc::clone(&live_status),
    };
    let agent_login_setup = agent_login_setup.map(|dependencies| {
        let clock = Arc::clone(&sleeper);
        Arc::new(AgentLoginSetup::new(
            // A periodic or `sync` setup goes by the mode the connection
            // writes.
            dependencies.with_credential_mode(Arc::clone(live_status.credential_mode())),
            Arc::new(HeldRunGate::new(Arc::clone(&assignment_manager))),
            move || clock.utc_now(),
        ))
    });
    // Each admission sets agent logins up for itself before it offers
    // them, and keeps its grant token files current while its assignment
    // runs.
    if let Some(setup) = &agent_login_setup {
        let mut manager = assignment_manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        manager
            .set_up_agent_logins_with(AdmissionAgentLogins::new(setup, Arc::clone(&live_status)));
        manager.refresh_grant_tokens_with(Arc::clone(&sleeper), Arc::clone(&live_status));
    }
    let (reload_sender, mut reload_requests) = tokio::sync::mpsc::channel::<ReloadRequest>(1);
    // Made whether or not a control socket is configured: without one the sender is dropped
    // and the schedule's channel is closed.
    let (kept_run_sender, kept_run_requests) = tokio::sync::mpsc::channel::<KeptRunRequest>(1);
    let _control_server = config
        .control_socket_path()
        .map(|path| {
            ControlServer::bind(
                path,
                ControlContext {
                    target,
                    status: Arc::clone(&live_status),
                    assignments: Arc::clone(&assignment_manager),
                    run_reads: Arc::new(tokio::sync::Semaphore::new(RUN_READ_PLACES)),
                    reloads: reload_sender,
                    kept_runs: kept_run_sender,
                    agent_logins: agent_login_setup.clone(),
                    timeouts: ControlTimeouts::production(),
                    runner_id: config.credential().runner_id().to_owned(),
                    version: recorder.service_version().to_owned(),
                },
            )
        })
        .transpose()
        .map_err(ServiceError::Control)?;
    // Setup never delays connecting: its schedule starts once the control
    // socket is bound, on a task of its own, and makes its first pass once
    // the connection has read Cloud's first welcome; the connection loop
    // below never waits for it.
    let _agent_login_schedule = agent_login_setup.as_ref().map(|setup| {
        AgentLoginSchedule::start(
            Arc::clone(setup),
            Arc::clone(&live_status),
            Arc::clone(&sleeper),
        )
    });
    let mut drain_stop;
    let shutdown: &mut dyn Shutdown = match config.drain_exit() {
        Some(exit) => {
            drain_stop = AutomaticStop::new(
                shutdown,
                drain_stop::watch(
                    exit,
                    Arc::clone(&assignment_manager),
                    Arc::clone(&live_status),
                    Arc::clone(&sleeper),
                    Arc::clone(&recorder),
                ),
            );
            &mut drain_stop
        }
        None => shutdown,
    };
    let mut idle_stop;
    let shutdown: &mut dyn Shutdown = match config.idle_timeout() {
        Some(timeout) => {
            idle_stop = AutomaticStop::new(
                shutdown,
                idle_stop::watch(
                    timeout,
                    Arc::clone(&assignment_manager),
                    Arc::clone(&live_status),
                    Arc::clone(&sleeper),
                    Arc::clone(&recorder),
                ),
            );
            &mut idle_stop
        }
        None => shutdown,
    };
    // The kept-run passes start after the startup report of what earlier processes
    // left, on tasks of their own that connecting never waits for.
    kept_runs.start(
        &assignment_manager,
        &config,
        Arc::clone(&sleeper),
        Arc::clone(&recorder),
        kept_run_requests,
    );
    let mut opening_sequence = 1;
    let sequence = Sequence::new(2);
    let mut opening_message_id = frame_source.public_id("rmsg_");
    let mut opening = opening_hello(
        frame_source.as_ref(),
        config.credential().runner_id(),
        &boot_id,
        opening_message_id.clone(),
        opening_sequence,
        recorder.service_version(),
        credential_mode,
    )
    .map_err(ServiceError::Connection)?;
    let mut attempt = 1_u64;
    let mut startup_reload_pending = config.startup_pending().is_some();
    let mut promoted_attempt: Option<PromotedAttempt> = None;
    let mut shutting_down = false;
    // What a graceful stop returns: a rejoin's end or a refused credential's
    // takes the stop's path out of the loop.
    let mut ending = ServiceEnd::Stopped;
    let mut shutdown_deadline: Option<Pin<Box<dyn Future<Output = ()> + Send>>> = None;

    loop {
        if assignment_manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .cleanup_failure_ready_to_exit()
        {
            let detail = assignment_manager
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .quiescence_failure();
            return Err(workspace_cleanup_failure(&recorder, detail));
        }
        if assignment_manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .lease_clock_failure_ready_to_exit()
        {
            return Err(ServiceError::LeaseClock(LeaseClockError::ClockUnavailable));
        }
        if shutting_down
            && assignment_manager
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .shutdown_complete()
        {
            let Some(deadline) = shutdown_deadline.as_mut() else {
                return Err(ServiceError::AssignmentShutdown);
            };
            return finish_shutdown_cleanup(&work_root, &recorder, shutdown, deadline, kept_runs)
                .await
                .map(|()| ending);
        }
        if shutting_down
            && assignment_manager
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .shutdown_waiting_only_for_cleanup()
        {
            let Some(deadline) = shutdown_deadline.as_mut() else {
                return Err(ServiceError::AssignmentShutdown);
            };
            wait_for_shutdown_progress(&assignment_manager, &work_root, shutdown, deadline, None)
                .await?;
            continue;
        }
        live_status.connecting();
        let (connection_event, active_effect_event, candidate) = match promoted_attempt.take() {
            Some(promoted) => (
                promoted.connection_event,
                promoted.active_effect_event,
                Some(promoted.connection),
            ),
            None => (
                connection_event(&recorder, &config, &boot_id, attempt),
                ActiveEffectEvent::new(),
                None,
            ),
        };
        let result = {
            let dependencies = ConnectionDependencies::new(
                &config,
                frame_source.as_ref(),
                sleeper.as_ref(),
                &recorder,
                &connection_event,
                &active_effect_event,
                &assignment_manager,
                attempt,
            )
            .with_live_status(&live_status)
            .with_credential_mode(live_status.credential_mode())
            .with_registration_mode(&live_status.registration_mode);
            let opening_frame = OpeningHello {
                boot_id: &boot_id,
                encoded: &opening,
                message_id: &opening_message_id,
                sequence: opening_sequence,
            };
            let connection: ConnectionFuture<'_> = match candidate {
                Some(candidate) => Box::pin(connection::run_promoted(
                    dependencies,
                    opening_frame,
                    &sequence,
                    candidate,
                )),
                None => connector.connect(ConnectionAttempt {
                    dependencies,
                    opening: opening_frame,
                    next_sequence: &sequence,
                }),
            };
            tokio::pin!(connection);
            loop {
                let notification = assignment_manager
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .notification();
                let notified = notification.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if assignment_manager
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .cleanup_failure_ready_to_exit()
                {
                    cancel_attempt(&connection_event, &active_effect_event);
                    let detail = assignment_manager
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .quiescence_failure();
                    return Err(workspace_cleanup_failure(&recorder, detail));
                }
                if shutting_down
                    && assignment_manager
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .shutdown_complete()
                {
                    cancel_attempt(&connection_event, &active_effect_event);
                    let Some(deadline) = shutdown_deadline.as_mut() else {
                        return Err(ServiceError::AssignmentShutdown);
                    };
                    return finish_shutdown_cleanup(
                        &work_root, &recorder, shutdown, deadline, kept_runs,
                    )
                    .await
                    .map(|()| ending);
                }
                if shutting_down {
                    let Some(deadline) = shutdown_deadline.as_mut() else {
                        return Err(ServiceError::AssignmentShutdown);
                    };
                    tokio::select! {
                        biased;
                        _ = shutdown.wait() => {
                            cancel_attempt(&connection_event, &active_effect_event);
                            return Err(ServiceError::ShutdownForced);
                        }
                        result = &mut connection => {
                            break ActiveAttemptResult::Finished(result);
                        }
                        () = &mut notified => continue,
                        () = deadline => {
                            cancel_attempt(&connection_event, &active_effect_event);
                            return Err(ServiceError::ShutdownDeadlineExceeded);
                        }
                    }
                } else {
                    let event = tokio::select! {
                        biased;
                        Some(request) = reload_requests.recv() => {
                            ActiveEvent::ManualReload(request)
                        }
                        // A connected runner holds no join key.
                        () = live_status.wait_until_connected(), if join_key.holds_key() => {
                            ActiveEvent::Handshake
                        }
                        () = live_status.wait_until_connected(), if startup_reload_pending => {
                            ActiveEvent::StartupReload
                        }
                        _ = shutdown.wait() => ActiveEvent::Shutdown,
                        () = &mut notified => ActiveEvent::AssignmentNotification,
                        result = &mut connection => ActiveEvent::Finished(result),
                    };
                    let reload = match event {
                        ActiveEvent::ManualReload(request) => Some((Some(request), false)),
                        ActiveEvent::StartupReload => Some((None, true)),
                        ActiveEvent::Handshake => {
                            join_key.handshake_completed();
                            None
                        }
                        ActiveEvent::AssignmentNotification => None,
                        ActiveEvent::Shutdown => {
                            shutdown_deadline = Some(begin_shutdown(
                                shutdown,
                                &live_status,
                                &assignment_manager,
                                &sleeper,
                                kept_runs,
                            )?);
                            shutting_down = true;
                            None
                        }
                        ActiveEvent::Finished(result) => {
                            break ActiveAttemptResult::Finished(result);
                        }
                    };
                    let Some((request, startup)) = reload else {
                        continue;
                    };
                    if startup {
                        startup_reload_pending = false;
                    }
                    match Box::pin(reload_dependencies.perform_while_connected(
                        &config,
                        &sequence,
                        attempt.saturating_add(1),
                        request,
                        &mut connection,
                        shutdown,
                    ))
                    .await
                    {
                        ConnectedReloadResult::Continue => {}
                        ConnectedReloadResult::Promoted(promoted) => {
                            cancel_attempt(&connection_event, &active_effect_event);
                            startup_reload_pending = false;
                            break ActiveAttemptResult::Promoted(promoted);
                        }
                        ConnectedReloadResult::Shutdown => {
                            shutdown_deadline = Some(begin_shutdown(
                                shutdown,
                                &live_status,
                                &assignment_manager,
                                &sleeper,
                                kept_runs,
                            )?);
                            shutting_down = true;
                        }
                        ConnectedReloadResult::Finished(result) => {
                            break ActiveAttemptResult::Finished(result);
                        }
                    }
                }
            }
        };
        let result = match result {
            ActiveAttemptResult::Finished(result) => result,
            ActiveAttemptResult::Promoted(promoted) => {
                install_promoted_attempt(
                    *promoted,
                    &mut config,
                    &mut opening,
                    &mut opening_message_id,
                    &mut opening_sequence,
                    &mut attempt,
                    &mut promoted_attempt,
                );
                continue;
            }
        };
        let (progress, cause, kind) = match result {
            Ok(progress) => (
                progress,
                ConnectionCause::GatewayClosedConnection,
                FailureKind::Retryable,
            ),
            Err(error) if error.is_terminal() => {
                if error.kind() == FailureKind::TerminalAuthentication && startup_reload_pending {
                    startup_reload_pending = false;
                    if let Some(promoted) = reload_dependencies
                        .perform(&config, &sequence, attempt.saturating_add(1), None)
                        .await
                    {
                        finish_connection_event(
                            &connection_event,
                            error.progress,
                            error.kind(),
                            error.connection_cause(),
                            None,
                            Outcome::Failure,
                        );
                        install_promoted_attempt(
                            promoted,
                            &mut config,
                            &mut opening,
                            &mut opening_message_id,
                            &mut opening_sequence,
                            &mut attempt,
                            &mut promoted_attempt,
                        );
                        continue;
                    }
                }
                match error.kind() {
                    FailureKind::TerminalAuthentication => live_status.authentication_failed(),
                    FailureKind::TerminalProtocol => live_status.protocol_failed(),
                    FailureKind::Retryable => {}
                }
                finish_connection_event(
                    &connection_event,
                    error.progress,
                    error.kind(),
                    error.connection_cause(),
                    None,
                    Outcome::Failure,
                );
                if error.kind() != FailureKind::TerminalAuthentication {
                    return Err(ServiceError::Connection(error));
                }
                loop {
                    let notification = assignment_manager
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .notification();
                    let notified = notification.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if assignment_manager
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .cleanup_failure_ready_to_exit()
                    {
                        let detail = assignment_manager
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .quiescence_failure();
                        return Err(workspace_cleanup_failure(&recorder, detail));
                    }
                    if shutting_down {
                        // The credential cannot hold a session, so the stop can only
                        // end here: at once when nothing is owed, otherwise at the
                        // deadline or a second signal, never on a reload.
                        let Some(deadline) = shutdown_deadline.as_mut() else {
                            return Err(ServiceError::AssignmentShutdown);
                        };
                        if assignment_manager
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .shutdown_complete()
                        {
                            return finish_shutdown_cleanup(
                                &work_root, &recorder, shutdown, deadline, kept_runs,
                            )
                            .await
                            .map(|()| ending);
                        }
                        wait_for_shutdown_progress(
                            &assignment_manager,
                            &work_root,
                            shutdown,
                            deadline,
                            None,
                        )
                        .await?;
                        continue;
                    }
                    // A runner that holds no assignment answers the refusal by
                    // its start's mode; one that holds work waits for it to be
                    // let go and looks again.
                    let (counts, _) = assignment_manager
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .status_assignments();
                    if refusal_step(&join_key, counts) != RefusalStep::Wait {
                        let answer = Box::pin(answer_refusal(
                            &mut join_key,
                            &mut backoff,
                            sleeper.as_ref(),
                            shutdown,
                        ))
                        .await?;
                        let end = match answer {
                            RefusalAnswer::Parked => None,
                            RefusalAnswer::Shutdown => Some(ServiceEnd::Stopped),
                            RefusalAnswer::Ended(end) => Some(
                                Box::pin(end_after_setup(
                                    end,
                                    agent_login_setup.as_deref(),
                                    shutdown,
                                ))
                                .await,
                            ),
                        };
                        if let Some(end) = end {
                            ending = end;
                            shutdown_deadline = Some(begin_shutdown(
                                shutdown,
                                &live_status,
                                &assignment_manager,
                                &sleeper,
                                kept_runs,
                            )?);
                            shutting_down = true;
                            continue;
                        }
                    }
                    tokio::select! {
                        () = &mut notified => {}
                        Some(request) = reload_requests.recv() => {
                            if let Some(promoted) = reload_dependencies
                                .perform(
                                    &config,
                                    &sequence,
                                    attempt.saturating_add(1),
                                    Some(request),
                                )
                                .await
                            {
                                install_promoted_attempt(
                                    promoted,
                                    &mut config,
                                    &mut opening,
                                    &mut opening_message_id,
                                    &mut opening_sequence,
                                    &mut attempt,
                                    &mut promoted_attempt,
                                );
                                break;
                            }
                        }
                        _ = shutdown.wait() => {
                            shutdown_deadline = Some(begin_shutdown(
                                shutdown,
                                &live_status,
                                &assignment_manager,
                                &sleeper,
                                kept_runs,
                            )?);
                            shutting_down = true;
                            break;
                        }
                    }
                }
                continue;
            }
            Err(error) => (error.progress, error.connection_cause(), error.kind()),
        };
        if progress.handshake_completed {
            backoff.reset();
            join_key.handshake_completed();
        }
        let delay = backoff.next_delay();
        live_status.backing_off(connection_failure(cause), delay);
        let outcome = if cause.is_timeout() {
            Outcome::Timeout
        } else {
            Outcome::Disconnected
        };
        finish_connection_event(
            &connection_event,
            progress,
            kind,
            cause,
            Some(delay),
            outcome,
        );
        if progress.opening_acknowledged {
            opening_message_id = frame_source.public_id("rmsg_");
            opening_sequence = sequence.next().map_err(ServiceError::Connection)?;
            opening = opening_hello(
                frame_source.as_ref(),
                config.credential().runner_id(),
                &boot_id,
                opening_message_id.clone(),
                opening_sequence,
                recorder.service_version(),
                credential_mode,
            )
            .map_err(ServiceError::Connection)?;
        }
        attempt = attempt.saturating_add(1);
        if shutting_down {
            let Some(deadline) = shutdown_deadline.as_mut() else {
                return Err(ServiceError::AssignmentShutdown);
            };
            wait_for_shutdown_progress(
                &assignment_manager,
                &work_root,
                shutdown,
                deadline,
                Some(sleeper.sleep(delay)),
            )
            .await?;
        } else {
            let notification = assignment_manager
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .notification();
            let notified = notification.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if assignment_manager
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .cleanup_failure_ready_to_exit()
            {
                continue;
            }
            tokio::select! {
                () = &mut notified => {}
                Some(request) = reload_requests.recv() => {
                    if let Some(promoted) = reload_dependencies
                        .perform(
                            &config,
                            &sequence,
                            attempt.saturating_add(1),
                            Some(request),
                        )
                        .await
                    {
                        // Both connected and backoff reload entry points install the
                        // same prepared transport through the shared state transition.
                        install_promoted_attempt(
                            promoted,
                            &mut config,
                            &mut opening,
                            &mut opening_message_id,
                            &mut opening_sequence,
                            &mut attempt,
                            &mut promoted_attempt,
                        );
                        continue;
                    }
                }
                _ = shutdown.wait() => {
                    shutdown_deadline = Some(begin_shutdown(
                        shutdown,
                        &live_status,
                        &assignment_manager,
                        &sleeper,
                        kept_runs,
                    )?);
                    shutting_down = true;
                }
                _ = sleeper.sleep(delay) => {}
            }
        }
    }
}

/// Answers a refused credential by the start's mode, leaving the mode as the
/// answer leaves the process: an unusable key's report runs once, a held
/// key's rejoin is sent one attempt at a time on the blocking pool until it
/// is answered, and a spent key ends the service. A stop signal is answered
/// while a rejoin is sent or waits: the staged journal stays on disk, so the
/// answer it would have read can be abandoned.
async fn answer_refusal(
    join_key: &mut JoinKeyMode,
    backoff: &mut Backoff,
    sleeper: &dyn Sleeper,
    shutdown: &mut dyn Shutdown,
) -> Result<RefusalAnswer, ServiceError> {
    let mut rejoin = match std::mem::replace(join_key, JoinKeyMode::None) {
        JoinKeyMode::None => return Ok(RefusalAnswer::Parked),
        JoinKeyMode::Spent => {
            *join_key = JoinKeyMode::Spent;
            return Ok(RefusalAnswer::Ended(ServiceEnd::CredentialRefused));
        }
        JoinKeyMode::Unusable(report) => {
            tokio::task::spawn_blocking(report)
                .await
                .map_err(|_| ServiceError::BuildRuntime)?;
            return Ok(RefusalAnswer::Parked);
        }
        JoinKeyMode::Held(rejoin) => rejoin,
    };
    loop {
        let attempt = tokio::task::spawn_blocking(move || {
            let answer = rejoin.attempt();
            (rejoin, answer)
        });
        let (returned, answer) = tokio::select! {
            biased;
            () = shutdown.wait() => return Ok(RefusalAnswer::Shutdown),
            joined = attempt => joined.map_err(|_| ServiceError::BuildRuntime)?,
        };
        rejoin = returned;
        match answer {
            RejoinAnswer::Rejoined => {
                *join_key = JoinKeyMode::Spent;
                return Ok(RefusalAnswer::Ended(ServiceEnd::Rejoined));
            }
            RejoinAnswer::Refused => return Ok(RefusalAnswer::Parked),
            RejoinAnswer::Unanswered(cause) => {
                let delay = backoff.next_delay();
                rejoin.retrying(crate::enrollment::JoinRetry { cause, delay });
                tokio::select! {
                    biased;
                    () = shutdown.wait() => return Ok(RefusalAnswer::Shutdown),
                    () = sleeper.sleep(delay) => {}
                }
            }
        }
    }
}

/// The end a refused credential's answer `end` leaves the service with. The
/// process serves the rejoined runner next on the same work root, so a
/// `Rejoined` end first ends the agent-login `setup` and waits until no
/// thread of it still runs and holds the root; a stop signal during the wait
/// ends the service `Stopped` instead, waiting for none. Every other end
/// exits the process, which ends the threads.
async fn end_after_setup(
    end: ServiceEnd,
    setup: Option<&AgentLoginSetup>,
    shutdown: &mut dyn Shutdown,
) -> ServiceEnd {
    let Some(setup) = setup.filter(|_| end == ServiceEnd::Rejoined) else {
        return end;
    };
    setup.close();
    tokio::select! {
        biased;
        () = shutdown.wait() => ServiceEnd::Stopped,
        () = setup.threads_exited() => end,
    }
}

async fn wait_for_shutdown_progress(
    assignment_manager: &Mutex<AssignmentManager>,
    work_root: &workspace::WorkRootLease,
    shutdown: &mut dyn Shutdown,
    deadline: &mut Pin<Box<dyn Future<Output = ()> + Send>>,
    delay: Option<SleepFuture<'_>>,
) -> Result<(), ServiceError> {
    let notification = assignment_manager
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .notification();
    let optional_delay = async move {
        match delay {
            Some(delay) => delay.await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(optional_delay);
    tokio::select! {
        biased;
        () = shutdown.wait() => {
            work_root.cancel_cleanup();
            Err(ServiceError::ShutdownForced)
        }
        () = deadline.as_mut() => {
            work_root.cancel_cleanup();
            Err(ServiceError::ShutdownDeadlineExceeded)
        }
        () = notification.notified() => Ok(()),
        () = &mut optional_delay => Ok(()),
    }
}

async fn finish_shutdown_cleanup(
    work_root: &workspace::WorkRootLease,
    recorder: &Recorder,
    shutdown: &mut dyn Shutdown,
    deadline: &mut Pin<Box<dyn Future<Output = ()> + Send>>,
    kept_runs: &mut KeptRunSchedule,
) -> Result<(), ServiceError> {
    // The boot root is released only once the kept-run pass in flight has ended.
    let completion = async {
        kept_runs.stop_and_join().await;
        let pending = work_root.release_boot_root_pending();
        pending.wait_async().await
    };
    tokio::pin!(completion);
    tokio::select! {
        biased;
        () = shutdown.wait() => {
            work_root.cancel_cleanup();
            Err(ServiceError::ShutdownForced)
        }
        result = &mut completion => match result {
            workspace::CleanupResult::Released | workspace::CleanupResult::Retained => Ok(()),
            workspace::CleanupResult::Quarantined(_) | workspace::CleanupResult::Preempted => {
                Err(workspace_cleanup_failure(recorder, None))
            }
        },
        () = deadline.as_mut() => {
            work_root.cancel_cleanup();
            Err(ServiceError::ShutdownDeadlineExceeded)
        }
    }
}

fn begin_shutdown(
    shutdown: &mut dyn Shutdown,
    live_status: &LiveStatus,
    assignment_manager: &Mutex<AssignmentManager>,
    sleeper: &Arc<dyn Sleeper>,
    kept_runs: &KeptRunSchedule,
) -> Result<Pin<Box<dyn Future<Output = ()> + Send>>, ServiceError> {
    shutdown.disarm_automatic_stops();
    live_status.stopping();
    kept_runs.stop();
    assignment_manager
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .begin_shutdown()
        .map_err(|_| ServiceError::AssignmentShutdown)?;
    let deadline_sleeper = Arc::clone(sleeper);
    Ok(Box::pin(async move {
        deadline_sleeper.sleep(SHUTDOWN_TIMEOUT).await;
    }))
}

fn install_promoted_attempt(
    promoted: PromotedAttempt,
    config: &mut Config,
    opening: &mut Vec<u8>,
    opening_message_id: &mut String,
    opening_sequence: &mut u64,
    attempt: &mut u64,
    promoted_attempt: &mut Option<PromotedAttempt>,
) {
    *config = promoted.config.clone();
    opening.clone_from(&promoted.opening);
    opening_message_id.clone_from(&promoted.opening_message_id);
    *opening_sequence = promoted.opening_sequence;
    *attempt = promoted.attempt;
    *promoted_attempt = Some(promoted);
}

impl ReloadDependencies {
    async fn perform(
        &self,
        config: &Config,
        sequence: &Sequence,
        attempt: u64,
        mut request: Option<ReloadRequest>,
    ) -> Option<PromotedAttempt> {
        let result = self.reload_candidate(config, sequence, attempt).await;
        let response = result
            .as_ref()
            .map(promoted_credential_id)
            .map_err(|error| *error);
        respond_to_reload(&self.live_status, &mut request, response);
        result.ok()
    }

    async fn perform_while_connected<F>(
        &self,
        config: &Config,
        sequence: &Sequence,
        attempt: u64,
        request: Option<ReloadRequest>,
        connection: &mut F,
        shutdown: &mut dyn Shutdown,
    ) -> ConnectedReloadResult
    where
        F: Future<Output = Result<ConnectionProgress, ConnectionError>> + Unpin,
    {
        let mut request = request;
        if !self.live_status.is_connected() {
            tokio::select! {
                biased;
                () = self.live_status.wait_until_connected() => {}
                result = &mut *connection => {
                    respond_to_reload(
                        &self.live_status,
                        &mut request,
                        Err(ControlError::PendingConnectionFailed),
                    );
                    return ConnectedReloadResult::Finished(result);
                }
                _ = shutdown.wait() => {
                    respond_to_reload(
                        &self.live_status,
                        &mut request,
                        Err(ControlError::PendingConnectionFailed),
                    );
                    return ConnectedReloadResult::Shutdown;
                }
            }
        }
        let preparation = self.prepare_candidate(config, sequence, attempt);
        tokio::pin!(preparation);
        // Superseding the old session can precede the candidate welcome.
        // Preserve the bounded handshake, and retain the old result for failure.
        let mut prior_result = None;
        let prepared = loop {
            tokio::select! {
                biased;
                result = &mut preparation => break result,
                result = &mut *connection, if prior_result.is_none() => {
                    prior_result = Some(result);
                }
                _ = shutdown.wait() => {
                    respond_to_reload(
                        &self.live_status,
                        &mut request,
                        Err(ControlError::PendingConnectionFailed),
                    );
                    return ConnectedReloadResult::Shutdown;
                }
            }
        };
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                respond_to_reload(&self.live_status, &mut request, Err(error));
                return prior_result.map_or(
                    ConnectedReloadResult::Continue,
                    ConnectedReloadResult::Finished,
                );
            }
        };
        match self.commit_candidate(prepared).await {
            Ok(promoted) => {
                respond_to_reload(
                    &self.live_status,
                    &mut request,
                    Ok(promoted_credential_id(&promoted)),
                );
                ConnectedReloadResult::Promoted(Box::new(promoted))
            }
            Err(error) => {
                let recovery = self
                    .prepare_connection(config.clone(), sequence, attempt.saturating_add(1))
                    .await;
                respond_to_reload(&self.live_status, &mut request, Err(error));
                match recovery {
                    Ok(recovered) => ConnectedReloadResult::Promoted(Box::new(recovered)),
                    Err(_) => prior_result.map_or(
                        ConnectedReloadResult::Continue,
                        ConnectedReloadResult::Finished,
                    ),
                }
            }
        }
    }

    async fn reload_candidate(
        &self,
        config: &Config,
        sequence: &Sequence,
        attempt: u64,
    ) -> Result<PromotedAttempt, ControlError> {
        let prepared = self.prepare_candidate(config, sequence, attempt).await?;
        self.commit_candidate(prepared).await
    }

    async fn prepare_candidate(
        &self,
        config: &Config,
        sequence: &Sequence,
        attempt: u64,
    ) -> Result<PreparedReload, ControlError> {
        let state_access = config
            .state_access()
            .cloned()
            .ok_or(ControlError::NoPendingCredential)?;
        let expected_runner_id = config.credential().runner_id().to_owned();
        let load_access = state_access.clone();
        let load_runner_id = expected_runner_id.clone();
        let pending =
            tokio::task::spawn_blocking(move || load_access.load_pending(&load_runner_id))
                .await
                .map_err(|_| ControlError::StateUpdateFailed)?
                .map_err(control_state_error)?;
        let Some(pending) = pending else {
            self.live_status.pending(None);
            return Err(ControlError::NoPendingCredential);
        };
        if pending.runner_id != expected_runner_id {
            return Err(ControlError::PendingRegistrationMismatch);
        }
        self.live_status
            .pending(Some(pending.credential_id.clone()));
        let pending_config = config
            .with_pending_credential(pending)
            .map_err(|_| ControlError::StateUpdateFailed)?;
        let target = Target::new(pending_config.endpoint(), pending_config.credential())
            .ok_or(ControlError::StateUpdateFailed)?;
        let candidate = self
            .prepare_connection(pending_config, sequence, attempt)
            .await?;
        Ok(PreparedReload {
            target,
            state_access,
            expected_runner_id,
            expected_current_credential_id: config.credential().credential_id().to_owned(),
            candidate,
        })
    }

    async fn prepare_connection(
        &self,
        config: Config,
        sequence: &Sequence,
        attempt: u64,
    ) -> Result<PromotedAttempt, ControlError> {
        let connection_event = connection_event(&self.recorder, &config, &self.boot_id, attempt);
        let active_effect_event = ActiveEffectEvent::new();
        let dependencies = ConnectionDependencies::new(
            &config,
            self.frame_source.as_ref(),
            self.sleeper.as_ref(),
            &self.recorder,
            &connection_event,
            &active_effect_event,
            &self.assignment_manager,
            attempt,
        )
        .with_credential_mode(self.live_status.credential_mode())
        .with_registration_mode(&self.live_status.registration_mode);
        let transport = connection::connect_candidate_transport(dependencies)
            .await
            .map_err(|error| candidate_control_error(&connection_event, error))?;
        let emission = sequence.lock_emission().await;
        let opening_sequence = sequence
            .next()
            .map_err(|error| candidate_control_error(&connection_event, error))?;
        let opening_message_id = self.frame_source.public_id("rmsg_");
        let opening = opening_hello(
            self.frame_source.as_ref(),
            config.credential().runner_id(),
            &self.boot_id,
            opening_message_id.clone(),
            opening_sequence,
            self.recorder.service_version(),
            self.credential_mode,
        )
        .map_err(|error| candidate_control_error(&connection_event, error))?;
        let candidate = connection::authenticate_candidate(
            dependencies,
            transport,
            OpeningHello {
                boot_id: &self.boot_id,
                encoded: &opening,
                message_id: &opening_message_id,
                sequence: opening_sequence,
            },
        )
        .await
        .map_err(|error| candidate_control_error(&connection_event, error))?;
        drop(emission);
        Ok(PromotedAttempt {
            config,
            opening,
            opening_message_id,
            opening_sequence,
            attempt,
            connection: candidate,
            connection_event,
            active_effect_event,
        })
    }

    async fn commit_candidate(
        &self,
        prepared: PreparedReload,
    ) -> Result<PromotedAttempt, ControlError> {
        let state_access = prepared.state_access.clone();
        let expected_runner_id = prepared.expected_runner_id.clone();
        let expected_current_credential_id = prepared.expected_current_credential_id.clone();
        let expected_pending_credential_id = prepared
            .candidate
            .config
            .credential()
            .credential_id()
            .to_owned();
        let promotion = tokio::task::spawn_blocking(move || {
            state_access.promote(
                &expected_runner_id,
                &expected_current_credential_id,
                &expected_pending_credential_id,
            )
        })
        .await
        .map_err(|_| ControlError::StateUpdateFailed)
        .and_then(|result| result.map_err(control_state_error));
        if let Err(error) = promotion {
            prepared.candidate.connection_event.finish(Outcome::Failure);
            return Err(error);
        }
        self.target.replace(prepared.target);
        self.live_status.promoted(
            prepared
                .candidate
                .config
                .credential()
                .credential_id()
                .to_owned(),
        );
        Ok(prepared.candidate)
    }
}

fn candidate_control_error(connection_event: &Event, error: ConnectionError) -> ControlError {
    let category = match error.kind() {
        FailureKind::TerminalAuthentication => ControlError::PendingAuthenticationFailed,
        FailureKind::TerminalProtocol => ControlError::PendingProtocolFailed,
        FailureKind::Retryable => ControlError::PendingConnectionFailed,
    };
    finish_connection_event(
        connection_event,
        error.progress,
        error.kind(),
        error.connection_cause(),
        None,
        if error.connection_cause().is_timeout() {
            Outcome::Timeout
        } else {
            Outcome::Failure
        },
    );
    category
}

fn promoted_credential_id(promoted: &PromotedAttempt) -> String {
    promoted.config.credential().credential_id().to_owned()
}

/// Answers the waiting `request`, if any, with `result`; a failed reload is one of the
/// runner's events whether or not a request waits.
fn respond_to_reload(
    status: &LiveStatus,
    request: &mut Option<ReloadRequest>,
    result: Result<String, ControlError>,
) {
    if let Err(error) = result {
        status
            .events()
            .record(history::LoggedEvent::CredentialReloadFailed { error });
    }
    if let Some(request) = request.take() {
        let _ = request.response.send(result);
    }
}

const fn control_state_error(error: crate::enrollment::ReloadStateError) -> ControlError {
    match error {
        crate::enrollment::ReloadStateError::RegistrationMismatch => {
            ControlError::PendingRegistrationMismatch
        }
        crate::enrollment::ReloadStateError::StateUpdate => ControlError::StateUpdateFailed,
    }
}

const fn connection_failure(cause: ConnectionCause) -> ConnectionFailure {
    match cause {
        ConnectionCause::CredentialRejected => ConnectionFailure::Authentication,
        ConnectionCause::GatewayRateLimited => ConnectionFailure::RateLimited,
        ConnectionCause::GatewayUnavailable | ConnectionCause::GatewayHttpError => {
            ConnectionFailure::CloudUnavailable
        }
        ConnectionCause::GatewayPolicyViolation
        | ConnectionCause::GatewayUnsupportedFrames
        | ConnectionCause::GatewayOversizedFrames
        | ConnectionCause::RequiredSubprotocolNotSelected
        | ConnectionCause::OversizedGatewayFrame
        | ConnectionCause::UndecodableGatewayFrame
        | ConnectionCause::UnexpectedObservationAcknowledgement
        | ConnectionCause::MismatchedEffectAcknowledgement
        | ConnectionCause::UnexpectedGatewayFrame
        | ConnectionCause::BinaryGatewayFrame
        | ConnectionCause::UnexpectedRawGatewayFrame
        | ConnectionCause::InvalidExecutionLeasePolicy
        | ConnectionCause::ChangedExecutionLeasePolicy
        | ConnectionCause::ConflictingAssignmentOffer
        | ConnectionCause::RunnerLeaseClockFailure => ConnectionFailure::Protocol,
        _ => ConnectionFailure::Network,
    }
}

fn connection_event(recorder: &Recorder, config: &Config, boot_id: &str, attempt: u64) -> Event {
    let mut attributes = vec![
        KeyValue::new(
            telemetry::attribute::RUNNER_ID,
            config.credential().runner_id().to_owned(),
        ),
        KeyValue::new(telemetry::attribute::RUNNER_BOOT_ID, boot_id.to_owned()),
        KeyValue::new(
            telemetry::attribute::RUNNER_VERSION,
            recorder.service_version().to_owned(),
        ),
        KeyValue::new(
            telemetry::attribute::CONNECTION_ATTEMPT,
            telemetry::integer(attempt),
        ),
    ];
    if let Some(address) = config.endpoint().host_str() {
        attributes.push(KeyValue::new(
            telemetry::attribute::SERVER_ADDRESS,
            address.to_owned(),
        ));
    }
    if let Some(port) = config.endpoint().port_or_known_default() {
        attributes.push(KeyValue::new(
            telemetry::attribute::SERVER_PORT,
            i64::from(port),
        ));
    }
    let event = recorder.start("runner.gateway_connection", attributes);
    record_progress(&event, ConnectionProgress::unacknowledged());
    event
}

fn cancel_attempt(connection_event: &Event, active_effect_event: &ActiveEffectEvent) {
    active_effect_event.finish(Outcome::Cancelled, None);
    connection_event.finish(Outcome::Cancelled);
}

fn finish_connection_event(
    event: &Event,
    progress: ConnectionProgress,
    kind: FailureKind,
    cause: ConnectionCause,
    backoff: Option<std::time::Duration>,
    outcome: Outcome,
) {
    record_progress(event, progress);
    event.set(KeyValue::new(
        telemetry::attribute::FAILURE_KIND,
        kind.as_str(),
    ));
    event.set(KeyValue::new(
        telemetry::attribute::ERROR_TYPE,
        cause.error_type(),
    ));
    if let Some(backoff) = backoff {
        event.set(KeyValue::new(
            telemetry::attribute::BACKOFF_MS,
            telemetry::integer_u128(backoff.as_millis()),
        ));
    }
    event.finish(outcome);
}

fn record_startup_retention(recorder: &Recorder, retained: &[workspace::RetainedWorkspace]) {
    for workspace in retained {
        let mut attributes = vec![
            KeyValue::new(
                telemetry::attribute::WORKSPACE_PATH,
                workspace.path.to_string_lossy().into_owned(),
            ),
            KeyValue::new(
                telemetry::attribute::RETENTION_REASON,
                workspace.reason.as_str(),
            ),
        ];
        if let Some(assignment_id) = &workspace.assignment_id {
            attributes.push(KeyValue::new(
                telemetry::attribute::ASSIGNMENT_ID,
                assignment_id.clone(),
            ));
        }
        if let Some(run_id) = &workspace.run_id {
            attributes.push(KeyValue::new(telemetry::attribute::RUN_ID, run_id.clone()));
        }
        if let Some(attempt_id) = &workspace.attempt_id {
            attributes.push(KeyValue::new(
                telemetry::attribute::ATTEMPT_ID,
                attempt_id.clone(),
            ));
        }
        recorder.record("runner.workspace_retained", attributes);
    }
}

fn workspace_cleanup_failure(recorder: &Recorder, detail: Option<Vec<String>>) -> ServiceError {
    record_non_admitting_failure(
        recorder,
        if detail.is_some() {
            "process_quiescence_failed"
        } else {
            "workspace_cleanup_failed"
        },
    );
    ServiceError::WorkspaceCleanupFailed(detail)
}

fn record_untested_harnesses(recorder: &Recorder, config: &Config) {
    let advisories = untested_harness_advisories(
        config.pi_installation(),
        config.claude_code_installation(),
        config.codex_installation(),
    );
    for advisory in advisories {
        recorder.record(
            "runner.harness_untested",
            [
                KeyValue::new(
                    telemetry::attribute::HARNESS_PROFILE,
                    advisory.profile().as_str(),
                ),
                KeyValue::new(
                    telemetry::attribute::HARNESS_VERSION,
                    advisory.version().to_owned(),
                ),
                KeyValue::new(
                    telemetry::attribute::HARNESS_QUALIFICATION_VERSION,
                    advisory.qualification_version(),
                ),
            ],
        );
    }
}

fn record_non_admitting_failure(recorder: &Recorder, error_type: &'static str) {
    recorder
        .start(
            "runner.work_root",
            [KeyValue::new(telemetry::attribute::ERROR_TYPE, error_type)],
        )
        .finish(Outcome::Failure);
}

const fn work_root_service_error(error: workspace::WorkRootError) -> ServiceError {
    match error {
        workspace::WorkRootError::WorkRootInUse => ServiceError::WorkRootInUse,
        workspace::WorkRootError::UnsafeWorkRoot | workspace::WorkRootError::CreateBootRoot => {
            ServiceError::WorkRootIsolation
        }
    }
}

const fn sequence_overflow() -> ConnectionError {
    ConnectionError::terminal(
        ConnectionProgress::unacknowledged(),
        ConnectionCause::RunnerSequenceOverflow,
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::ExitStatusExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use base64::Engine as _;
    use futures_util::{SinkExt, StreamExt};
    use rustix::process::{Signal, getpgid, kill_process_group};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::accept_hdr_async;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::handshake::server::{
        Request as HandshakeRequest, Response as HandshakeResponse,
    };
    use tokio_tungstenite::tungstenite::http::{HeaderValue, header};

    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    use super::DrainExit;
    use super::drain_stop::DRAIN_RETRY_INTERVAL;
    use super::sequence_overflow;
    use super::source::{
        SourceCredentialBroker,
        test_support::{fixture_source_broker, unavailable_source_broker},
    };
    use super::test_support::{
        ConfigFixture, ControlledShutdownTrigger, FixtureSocket, SleepRelease,
        accept_fixture_socket, accept_fixture_socket_with_headers, accept_opened_fixture_socket,
        assignment_offer, begin_assignment_preparation, controlled_shutdown, controlled_sleeper,
        deterministic_frame_source, effect_acknowledgement, effect_observation_acknowledgement,
        expect_close_frame, expect_opening_hello, fixture_lease_clock, fixture_listener,
        fixture_sleeper, guarded_processes, holding_step_workflow, observation_acknowledgement,
        offer_assignment_after_handshake, process_exists, require_internal_worker_executable,
        run_fixture_git, scripted_connector, sleep_request, terminal_observation_acknowledgement,
        welcome, welcome_with_registration_mode, with_watchdog,
    };
    use super::workspace::{
        CleanupCancellation, CleanupSleeper, OwnedTree, TreeRemover, WorkRootHook, WorkRootLease,
        WorkspaceFilesystem,
    };
    use super::{
        AssignmentConfig, Config, ConnectionCause, ConnectionLoopDependencies, FailureKind,
        JoinKeyMode, LiveStatus, RefusalStep, Rejoin, RejoinAnswer, ReloadDependencies,
        ReloadRequest, Sequence, ServiceEnd, ServiceError, Sleeper, TokioSleeper,
        record_startup_retention, refusal_step, run_connection_loop_with_work_root,
        run_until_cancelled_with_dependencies,
    };
    use crate::control_protocol::{
        AssignmentCounts, ConnectionState, ControlError, KeptAnswer, KeptBound, KeptCacheState,
        KeptReason, KeptReport, KeptWorkspaceState, Operation, PruneAnswer, PruneReport,
        PruneScope, PrunedOutcome, Response, StatusSnapshot,
    };
    use crate::credential::test_credential;
    use crate::enrollment::{AmbiguousCause, JoinRetry};
    use crate::service::assignment::test_support::manager_with_dependencies as assignment_manager_with_dependencies;
    use crate::service::config::RepositoryUrlPolicy;
    use crate::telemetry::{TestCapture, test_recorder};
    use useful_execution::{
        ValidatedClaudeCodeInstallation, ValidatedCodexInstallation, ValidatedPiInstallation,
        resolve,
    };
    use useful_runner_protocol::RegistrationMode;

    #[test]
    fn recovery_required_failures_are_closed_to_work_root_ownership() {
        for error in [
            ServiceError::WorkRootInUse,
            ServiceError::WorkRootIsolation,
            ServiceError::WorkspaceCleanupFailed(None),
        ] {
            assert!(error.requires_operator_recovery());
        }
        assert!(!ServiceError::BuildRuntime.requires_operator_recovery());
    }

    struct FailingBootRemover {
        calls: AtomicUsize,
    }

    impl TreeRemover for FailingBootRemover {
        fn remove_tree(&self, _tree: &OwnedTree) -> io::Result<()> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Err(io::Error::other("injected boot cleanup failure"))
        }
    }

    struct ImmediateCleanupSleeper;

    impl CleanupSleeper for ImmediateCleanupSleeper {
        fn sleep(&self, _duration: Duration, cancellation: &CleanupCancellation) -> bool {
            !cancellation.is_cancelled()
        }
    }

    struct BlockingCleanupSleeper {
        started: tokio::sync::mpsc::UnboundedSender<()>,
        cancelled: tokio::sync::mpsc::UnboundedSender<()>,
    }

    impl CleanupSleeper for BlockingCleanupSleeper {
        fn sleep(&self, _duration: Duration, cancellation: &CleanupCancellation) -> bool {
            let _ = self.started.send(());
            let result = cancellation.wait(Duration::from_secs(60));
            let _ = self.cancelled.send(());
            result
        }
    }

    struct NoopWorkRootHook;

    impl WorkRootHook for NoopWorkRootHook {
        fn before_child_enumeration(&self) {}
    }

    #[test]
    fn startup_retains_an_interrupted_cleanup_and_allows_a_fresh_assignment() {
        const STALE_BOOT: &str = "rbt_01k0z6r1w8f4jy2m7q9v3x5abc";

        let config = ConfigFixture::new(
            "ws://127.0.0.1:1/v1/runner/connect",
            test_credential(),
            true,
        )
        .unwrap();
        let first_remover = Arc::new(FailingBootRemover {
            calls: AtomicUsize::new(0),
        });
        let first = WorkRootLease::acquire_with(
            config.assignment().work_root(),
            STALE_BOOT,
            WorkspaceFilesystem::injected(
                first_remover,
                Arc::new(ImmediateCleanupSleeper),
                Arc::new(NoopWorkRootHook),
            ),
        )
        .unwrap();
        let stale_path = first.boot_path().to_owned();
        assert!(matches!(
            first.release_boot_root_pending().wait(),
            super::workspace::CleanupResult::Quarantined(
                super::workspace::CleanupFailure::OrdinaryRemovalExhausted
            )
        ));
        drop(first);

        let frame_source = deterministic_frame_source();
        let boot_id = frame_source.public_id("rbt_");
        let (recorder, capture) = test_recorder(&boot_id);
        let persistent_remover = Arc::new(FailingBootRemover {
            calls: AtomicUsize::new(0),
        });
        let current = WorkRootLease::acquire_with(
            config.assignment().work_root(),
            &boot_id,
            WorkspaceFilesystem::injected(
                persistent_remover.clone(),
                Arc::new(ImmediateCleanupSleeper),
                Arc::new(NoopWorkRootHook),
            ),
        )
        .unwrap();
        record_startup_retention(&recorder, current.startup_retained());
        let fresh = current
            .create_assignment_for_attempt(
                "asn_01k0z6r1w8f4jy2m7q9v3x5abd",
                "run_01k0z6r1w8f4jy2m7q9v3x5abd",
                "atm_01k0z6r1w8f4jy2m7q9v3x5abd",
                None,
            )
            .unwrap();

        assert_eq!(persistent_remover.calls.load(Ordering::Relaxed), 0);
        assert!(stale_path.exists());
        assert!(fresh.workspace.path().starts_with(current.boot_path()));
        let event = capture
            .records()
            .into_iter()
            .find(|event| event["event.name"] == "runner.workspace_retained")
            .expect("startup retention diagnostic");
        assert_eq!(
            event["um.workspace.path"],
            stale_path.to_string_lossy().as_ref()
        );
        assert_eq!(event["um.workspace.retention_reason"], "outcome_unknown");
    }

    #[tokio::test]
    async fn second_signal_preempts_final_boot_root_retry() {
        let config = ConfigFixture::new(
            "ws://127.0.0.1:1/v1/runner/connect",
            test_credential(),
            true,
        )
        .unwrap();
        let frame_source = deterministic_frame_source();
        let boot_id = frame_source.public_id("rbt_");
        let (recorder, _capture) = test_recorder(&boot_id);
        let (sleeper, _sleep_requests) = controlled_sleeper();
        let dependencies = ConnectionLoopDependencies {
            target: crate::service::serving_target(&config).unwrap(),
            config: config.cloned_config(),
            frame_source,
            sleeper,
            recorder,
            lease_clock: fixture_lease_clock(),
            boot_id: boot_id.clone(),
            source_broker: None,
            agent_login_setup: None,
            disk: None,
        };
        let remover = Arc::new(FailingBootRemover {
            calls: AtomicUsize::new(0),
        });
        let (started, mut cleanup_started) = tokio::sync::mpsc::unbounded_channel();
        let (cancelled, mut cleanup_cancelled) = tokio::sync::mpsc::unbounded_channel();
        let work_root = WorkRootLease::acquire_with(
            config.assignment().work_root(),
            &boot_id,
            WorkspaceFilesystem::injected(
                remover.clone(),
                Arc::new(BlockingCleanupSleeper { started, cancelled }),
                Arc::new(NoopWorkRootHook),
            ),
        )
        .unwrap();
        let boot_path = work_root.boot_path().to_owned();
        let (connector, _attempts) = scripted_connector(Default::default());
        let (mut shutdown, shutdown_trigger) = controlled_shutdown();
        shutdown_trigger.notify_one();
        let service = run_connection_loop_with_work_root(
            dependencies,
            &connector,
            super::Backoff::with_fixed_unit(1.0),
            shutdown.as_mut(),
            work_root,
        );
        let force = async {
            cleanup_started
                .recv()
                .await
                .expect("boot cleanup did not reach its retry wait");
            shutdown_trigger.notify_one();
            cleanup_cancelled
                .recv()
                .await
                .expect("forced shutdown did not cancel boot cleanup");
        };

        let (result, ()) = tokio::join!(service, force);

        assert!(matches!(result, Err(ServiceError::ShutdownForced)));
        assert_eq!(remover.calls.load(Ordering::Relaxed), 1);
        assert!(boot_path.exists());
    }

    #[test]
    fn preserves_connection_failure_classification() {
        let ServiceError::Connection(error) = ServiceError::Connection(sequence_overflow()) else {
            panic!("connection failure changed service error variant");
        };
        assert_eq!(
            error.connection_cause(),
            ConnectionCause::RunnerSequenceOverflow
        );
        assert_eq!(error.kind(), FailureKind::TerminalProtocol);
    }

    fn current_credential_secret() -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0_u8; 32])
    }

    fn pending_credential_secret() -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2_u8; 32])
    }

    #[allow(
        clippy::result_large_err,
        reason = "tungstenite's handshake callback requires its large error type"
    )]
    async fn accept_fixture_stream(stream: tokio::net::TcpStream) -> FixtureSocket {
        accept_hdr_async(
            stream,
            |_request: &HandshakeRequest, mut response: HandshakeResponse| {
                response.headers_mut().insert(
                    header::SEC_WEBSOCKET_PROTOCOL,
                    HeaderValue::from_static("um.runner.v1"),
                );
                Ok(response)
            },
        )
        .await
        .unwrap()
    }

    struct RotationFixture {
        _root: tempfile::TempDir,
        _runtime: tempfile::TempDir,
        config: Config,
        config_path: PathBuf,
        state_path: PathBuf,
    }

    impl RotationFixture {
        fn new(endpoint: &str) -> Self {
            let root = tempfile::tempdir().unwrap();
            let runtime = tempfile::tempdir_in("/tmp").unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let state_directory = root.path().join("state");
            let source = root.path().join("source");
            let work = root.path().join("work");
            fs::create_dir(&state_directory).unwrap();
            fs::set_permissions(&state_directory, fs::Permissions::from_mode(0o700)).unwrap();
            fs::create_dir(&source).unwrap();
            fs::create_dir(&work).unwrap();
            fs::set_permissions(&work, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(
                source.join("workflow.yaml"),
                "schemaVersion: 1\nsteps:\n  check:\n    kind: cmd\n    command:\n      argv: [\"true\"]\n",
            )
            .unwrap();
            let state_path = state_directory.join("runner.json");
            let connection_endpoint = endpoint.to_owned();
            fs::write(
                &state_path,
                serde_json::to_vec_pretty(&serde_json::json!({
                    "schemaVersion": 1,
                    "runnerId": "rnr_01k0z6r1w8f4jy2m7q9v3x5abc",
                    "connectionUrl": connection_endpoint,
                    "currentCredential": {
                        "id": "rrc_01k0z6r1w8f4jy2m7q9v3x5abc",
                        "secret": current_credential_secret(),
                        "activationId": "rna_01k0z6r1w8f4jy2m7q9v3x5abc",
                        "enrolledAt": "2026-08-06T12:00:00Z"
                    },
                    "pendingCredential": {
                        "id": "rrc_01k0z6r1w8f4jy2m7q9v3x5abd",
                        "secret": pending_credential_secret(),
                        "activationId": "rna_01k0z6r1w8f4jy2m7q9v3x5abd",
                        "enrolledAt": "2026-08-06T13:00:00Z"
                    },
                    "updatedAt": "2026-08-06T13:00:00Z"
                }))
                .unwrap(),
            )
            .unwrap();
            fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600)).unwrap();
            let config_path = root.path().join("config.json");
            fs::write(
                &config_path,
                serde_json::to_vec_pretty(&serde_json::json!({
                    "schemaVersion": 1,
                    "deploymentMode": "development",
                    "runnerStatePath": state_path,
                    "controlSocketPath": runtime.path().join("runner.sock"),
                    "workRoot": work
                }))
                .unwrap(),
            )
            .unwrap();
            crate::enrollment::load_runner_service_configuration(&config_path).unwrap();
            let config = Config::load(&config_path).unwrap();
            Self {
                _root: root,
                _runtime: runtime,
                config,
                config_path,
                state_path,
            }
        }
        fn without_pending(endpoint: &str) -> Self {
            let mut fixture = Self::new(endpoint);
            let mut state: serde_json::Value =
                serde_json::from_slice(&fs::read(&fixture.state_path).unwrap()).unwrap();
            state.as_object_mut().unwrap().remove("pendingCredential");
            fs::write(
                &fixture.state_path,
                serde_json::to_vec_pretty(&state).unwrap(),
            )
            .unwrap();
            fs::set_permissions(&fixture.state_path, fs::Permissions::from_mode(0o600)).unwrap();
            fixture.config = Config::load(&fixture.config_path).unwrap();
            fixture
        }

        fn accepted_source(&self) -> (Arc<dyn SourceCredentialBroker>, Message) {
            let source = self._root.path().join("source");
            initialize_accepted_repository(&source);
            (
                fixture_source_broker(&source),
                accepted_assignment_offer(&source),
            )
        }

        fn stage_pending(&self) {
            let mut state: serde_json::Value =
                serde_json::from_slice(&fs::read(&self.state_path).unwrap()).unwrap();
            state["pendingCredential"] = serde_json::json!({
                "id": "rrc_01k0z6r1w8f4jy2m7q9v3x5abd",
                "secret": pending_credential_secret(),
                "activationId": "rna_01k0z6r1w8f4jy2m7q9v3x5abd",
                "enrolledAt": "2026-08-06T13:00:00Z"
            });
            fs::write(&self.state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
            fs::set_permissions(&self.state_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    async fn reload_fixture(
        config: &Config,
    ) -> (
        Option<super::PromotedAttempt>,
        Result<String, ControlError>,
        TestCapture,
        super::ServingTarget,
    ) {
        let frame_source = deterministic_frame_source();
        let (recorder, capture) = test_recorder("rbt_01k0z6r1w8f4jy2m7q9v3x5abe");
        let assignments = Arc::new(std::sync::Mutex::new(assignment_manager_with_dependencies(
            config,
            "rbt_01k0z6r1w8f4jy2m7q9v3x5abe".to_owned(),
            fixture_lease_clock(),
            fixture_sleeper(),
            Some(Arc::clone(&recorder)),
            None,
            true,
        )));
        let status = Arc::new(LiveStatus::new(
            "rbt_01k0z6r1w8f4jy2m7q9v3x5abe".to_owned(),
            config.credential().credential_id().to_owned(),
            config
                .startup_pending()
                .map(|pending| pending.credential_id.clone()),
        ));
        let target = super::serving_target(config).unwrap();
        let reload = ReloadDependencies {
            target: target.clone(),
            boot_id: "rbt_01k0z6r1w8f4jy2m7q9v3x5abe".to_owned(),
            credential_mode: true,
            frame_source,
            sleeper: fixture_sleeper(),
            recorder,
            assignment_manager: assignments,
            live_status: status,
        };
        let (response, receive) = tokio::sync::oneshot::channel();
        let promoted = reload
            .perform(
                config,
                &Sequence::new(2),
                2,
                Some(ReloadRequest { response }),
            )
            .await;
        (promoted, receive.await.unwrap(), capture, target)
    }

    async fn request_control(socket_path: PathBuf, operation: Operation) -> Response {
        tokio::task::spawn_blocking(move || crate::control_client::request(&socket_path, operation))
            .await
            .unwrap()
            .unwrap()
    }

    async fn request_staged_reload(fixture: &RotationFixture, socket_path: PathBuf) -> Response {
        fixture.stage_pending();
        request_control(socket_path, Operation::ReloadCredential).await
    }

    async fn accept_rotation_connections(
        listener: &tokio::net::TcpListener,
        current_ready: Option<tokio::sync::oneshot::Sender<()>>,
        supersede_current: bool,
    ) -> (FixtureSocket, FixtureSocket) {
        let (mut current, current_headers) = accept_fixture_socket_with_headers(listener).await;
        assert!(
            current_headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("Bearer rrc_01k0z6r1w8f4jy2m7q9v3x5abc."))
        );
        let Some(Ok(Message::Text(current_hello))) = current.next().await else {
            panic!("current connection omitted hello");
        };
        let current_hello: serde_json::Value = serde_json::from_str(&current_hello).unwrap();
        current.send(welcome()).await.unwrap();
        current
            .send(observation_acknowledgement(
                current_hello["messageId"].as_str().unwrap(),
                current_hello["sequence"].as_u64().unwrap(),
            ))
            .await
            .unwrap();
        if let Some(current_ready) = current_ready {
            current_ready.send(()).unwrap();
        }

        let (mut pending, pending_headers) = accept_fixture_socket_with_headers(listener).await;
        assert!(
            pending_headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("Bearer rrc_01k0z6r1w8f4jy2m7q9v3x5abd."))
        );
        let Some(Ok(Message::Text(pending_hello))) = pending.next().await else {
            panic!("pending connection omitted hello");
        };
        let pending_hello: serde_json::Value = serde_json::from_str(&pending_hello).unwrap();
        assert_eq!(pending_hello["bootId"], current_hello["bootId"]);
        if supersede_current {
            current.close(None).await.unwrap();
            // Complete the old session before sending the candidate welcome.
            while current.next().await.is_some() {}
        }
        pending.send(welcome()).await.unwrap();
        pending
            .send(observation_acknowledgement(
                pending_hello["messageId"].as_str().unwrap(),
                pending_hello["sequence"].as_u64().unwrap(),
            ))
            .await
            .unwrap();
        (current, pending)
    }

    #[tokio::test]
    async fn reload_promotes_a_valid_pending_credential_without_changing_boot() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::new(&endpoint);
        let server = tokio::spawn(async move {
            let (mut socket, headers) = accept_fixture_socket_with_headers(&listener).await;
            let expected_authorization = format!(
                "Bearer rrc_01k0z6r1w8f4jy2m7q9v3x5abd.{}",
                pending_credential_secret()
            );
            assert_eq!(
                headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok()),
                Some(expected_authorization.as_str())
            );
            let Some(Ok(Message::Text(hello))) = socket.next().await else {
                panic!("pending connection omitted hello");
            };
            let hello: serde_json::Value = serde_json::from_str(&hello).unwrap();
            assert_eq!(hello["bootId"], "rbt_01k0z6r1w8f4jy2m7q9v3x5abe");
            socket.send(welcome()).await.unwrap();
        });

        let (promoted, response, capture, target) = reload_fixture(&fixture.config).await;
        assert_eq!(
            target.current().credential().credential_id(),
            "rrc_01k0z6r1w8f4jy2m7q9v3x5abd"
        );
        assert_eq!(response, Ok("rrc_01k0z6r1w8f4jy2m7q9v3x5abd".to_owned()));
        let promoted = promoted.unwrap();
        assert_eq!(
            promoted.config.credential().credential_id(),
            "rrc_01k0z6r1w8f4jy2m7q9v3x5abd"
        );
        let state: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.state_path).unwrap()).unwrap();
        assert_eq!(
            state["currentCredential"]["id"],
            "rrc_01k0z6r1w8f4jy2m7q9v3x5abd"
        );
        assert!(state.get("pendingCredential").is_none());
        let telemetry = serde_json::to_string(&capture.records()).unwrap();
        for secret in [current_credential_secret(), pending_credential_secret()] {
            assert!(!telemetry.contains(&secret));
        }
        drop(promoted);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn control_socket_reload_promotes_the_live_same_boot_connection() {
        for supersede_current in [false, true] {
            let (listener, endpoint) = fixture_listener().await;
            let fixture = RotationFixture::without_pending(&endpoint);
            let socket_path = fixture.config.control_socket_path().unwrap().to_owned();
            let (current_sent, current_received) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (current, mut pending) =
                    accept_rotation_connections(&listener, Some(current_sent), supersede_current)
                        .await;
                while pending.next().await.is_some() {}
                drop(current);
            });
            let (service, _capture, shutdown_trigger) =
                spawn_configured_service(fixture.config.clone(), fixture_sleeper());
            with_watchdog(current_received).await.unwrap().unwrap();
            assert_eq!(
                request_staged_reload(&fixture, socket_path).await,
                Response::Reloaded {
                    credential_id: "rrc_01k0z6r1w8f4jy2m7q9v3x5abd".to_owned()
                }
            );
            let state: serde_json::Value =
                serde_json::from_slice(&fs::read(&fixture.state_path).unwrap()).unwrap();
            assert!(state.get("pendingCredential").is_none());
            shutdown_trigger.notify_one();
            with_watchdog(service).await.unwrap().unwrap().unwrap();
            with_watchdog(server).await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn brokers_send_the_promoted_credential_after_a_live_reload() {
        use tokio::io::{AsyncBufReadExt as _, BufReader};

        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        let socket_path = fixture.config.control_socket_path().unwrap().to_owned();
        let (ready, connected) = tokio::sync::oneshot::channel();
        let (reloaded, promoted) = tokio::sync::oneshot::channel();
        let (head_sender, head_receiver) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (_current, mut pending) =
                accept_rotation_connections(&listener, Some(ready), false).await;
            promoted.await.unwrap();
            pending.send(assignment_offer()).await.unwrap();
            let offered = effect_acknowledgement(&mut pending).await;
            acknowledge_runner_frame(&mut pending, &offered, "acknowledge offer").await;
            let prepare = begin_assignment_preparation(&mut pending).await;
            acknowledge_runner_frame(&mut pending, &prepare, "acknowledge preparation").await;
            let mut first = Some(head_sender);
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let (mut socket, _) = result.unwrap();
                        let mut reader = BufReader::new(&mut socket);
                        let mut head = String::new();
                        while reader.read_line(&mut head).await.unwrap() != 0
                            && !head.ends_with("\r\n\r\n") {}
                        socket.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                        if let Some(sender) = first.take() {
                            sender.send(head).unwrap();
                        }
                    }
                    frame = pending.next() => {
                        match frame {
                            Some(Ok(Message::Text(frame))) => {
                                let frame = serde_json::from_str(&frame).unwrap();
                                acknowledge_runner_frame(&mut pending, &frame, "acknowledge observation").await;
                            }
                            Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                            Some(Ok(_)) => {}
                        }
                    }
                }
            }
        });
        let (service, _capture, shutdown_trigger) = spawn_configured_service_with_source(
            fixture.config.clone(),
            fixture_sleeper(),
            None,
            None,
        );
        with_watchdog(connected).await.unwrap().unwrap();
        assert_eq!(
            request_staged_reload(&fixture, socket_path).await,
            Response::Reloaded {
                credential_id: "rrc_01k0z6r1w8f4jy2m7q9v3x5abd".to_owned()
            }
        );
        reloaded.send(()).unwrap();
        let head = with_watchdog(head_receiver).await.unwrap().unwrap();
        shutdown_trigger.notify_one();
        with_watchdog(service).await.unwrap().unwrap().unwrap();
        with_watchdog(server).await.unwrap().unwrap();
        assert!(head.starts_with("POST /v1/runner/"));
        let expected = format!(
            "Bearer rrc_01k0z6r1w8f4jy2m7q9v3x5abd.{}",
            pending_credential_secret()
        );
        assert_eq!(
            head.lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .map(|(_, value)| value.trim()),
            Some(expected.as_str())
        );
    }

    #[tokio::test]
    async fn live_reload_retains_the_boot_and_accepted_assignment_manager() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        let (source_broker, offer) = fixture.accepted_source();
        let socket_path = fixture.config.control_socket_path().unwrap().to_owned();
        let (accepted_sent, accepted_received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut current = accept_fixture_socket(&listener).await;
            let Some(Ok(Message::Text(current_hello))) = current.next().await else {
                panic!("current connection omitted hello");
            };
            let current_hello: serde_json::Value = serde_json::from_str(&current_hello).unwrap();
            current.send(welcome()).await.unwrap();
            current
                .send(observation_acknowledgement(
                    current_hello["messageId"].as_str().unwrap(),
                    current_hello["sequence"].as_u64().unwrap(),
                ))
                .await
                .unwrap();
            current.send(offer).await.unwrap();
            let offer_acknowledgement = effect_acknowledgement(&mut current).await;
            acknowledge_runner_frame(
                &mut current,
                &offer_acknowledgement,
                "acknowledge assignment offer",
            )
            .await;
            let prepare_acknowledgement = begin_assignment_preparation(&mut current).await;
            acknowledge_runner_frame(
                &mut current,
                &prepare_acknowledgement,
                "acknowledge assignment prepare effect",
            )
            .await;
            let _accepted =
                next_semantic_assignment_frame(&mut current, "assignment_accepted", true).await;
            current
                .send(Message::Ping(vec![1, 2, 3].into()))
                .await
                .unwrap();
            // Registration is optional and can be emitted after acceptance. The
            // barrier is the matching pong, not the next frame on the wire.
            loop {
                match with_watchdog(current.next()).await.unwrap() {
                    Some(Ok(Message::Pong(payload))) if payload.as_ref() == [4, 5, 6] => {
                        // A keepalive sent during source admission can still be in flight.
                    }
                    Some(Ok(Message::Pong(payload))) => {
                        assert_eq!(payload.as_ref(), &[1, 2, 3]);
                        break;
                    }
                    Some(Ok(Message::Text(frame))) => {
                        let frame: serde_json::Value =
                            serde_json::from_str(&frame).expect("decode current observation");
                        assert_eq!(frame["type"], "assignment_preparation_progress");
                        acknowledge_runner_frame(
                            &mut current,
                            &frame,
                            "acknowledge preparation progress",
                        )
                        .await;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => panic!("current connection failed: {error}"),
                    None => panic!("current connection closed before preparation barrier"),
                }
            }
            accepted_sent.send(()).unwrap();

            let mut pending = accept_fixture_socket(&listener).await;
            let Some(Ok(Message::Text(pending_hello))) = pending.next().await else {
                panic!("pending connection omitted hello");
            };
            let pending_hello: serde_json::Value = serde_json::from_str(&pending_hello).unwrap();
            assert_eq!(pending_hello["bootId"], current_hello["bootId"]);
            pending.send(welcome()).await.unwrap();
            pending
                .send(observation_acknowledgement(
                    pending_hello["messageId"].as_str().unwrap(),
                    pending_hello["sequence"].as_u64().unwrap(),
                ))
                .await
                .unwrap();
            let mut interrupted = false;
            let mut retention_reported = false;
            while let Some(Ok(Message::Text(frame))) = pending.next().await {
                let frame: serde_json::Value = serde_json::from_str(&frame).unwrap();
                // Promotion can replay a preparation-progress observation whose
                // acknowledgement was still buffered on the retired transport.
                // Acknowledge every expected observation in FIFO order instead
                // of assuming the accepted observation is replayed first.
                if matches!(
                    frame["type"].as_str(),
                    Some(
                        "assignment_preparation_progress"
                            | "assignment_accepted"
                            | "assignment_interrupted"
                    )
                ) {
                    acknowledge_runner_frame(
                        &mut pending,
                        &frame,
                        "acknowledge replayed assignment observation",
                    )
                    .await;
                }
                // The retention report follows acknowledged interruption and
                // cleanup. Shutdown waits for its dispatch, not acknowledgement,
                // so writing an ack for it can race the runner closing the socket.
                interrupted |= frame["type"] == "assignment_interrupted";
                retention_reported |= frame["type"] == "workspace_retention_report";
                if interrupted && retention_reported {
                    break;
                }
            }
            drop(current);
        });
        let (service, _capture, shutdown_trigger) = spawn_configured_service_with_source(
            fixture.config.clone(),
            fixture_sleeper(),
            Some(source_broker),
            None,
        );
        with_watchdog(accepted_received).await.unwrap().unwrap();
        let Response::Status(before) =
            request_control(socket_path.clone(), Operation::Status).await
        else {
            panic!("control status was not available before reload");
        };
        assert_eq!(before.assignment_counts.accepted, 1);

        assert_eq!(
            request_staged_reload(&fixture, socket_path.clone()).await,
            Response::Reloaded {
                credential_id: "rrc_01k0z6r1w8f4jy2m7q9v3x5abd".to_owned()
            }
        );
        let Response::Status(after) = request_control(socket_path, Operation::Status).await else {
            panic!("control status was not available after reload");
        };
        assert_eq!(after.boot_id, before.boot_id);
        assert_eq!(after.assignment_counts, before.assignment_counts);
        assert_eq!(after.assignment_counts.accepted, 1);

        shutdown_trigger.notify_one();
        with_watchdog(service).await.unwrap().unwrap().unwrap();
        with_watchdog(server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn terminal_authentication_remains_locally_inspectable() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        let socket_path = fixture.config.control_socket_path().unwrap().to_owned();
        let (rejected_sent, rejected_received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut current, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = current.read(&mut request).await.unwrap();
            current
                .write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n")
                .await
                .unwrap();
            rejected_sent.send(()).unwrap();

            let (mut pending, headers) = accept_fixture_socket_with_headers(&listener).await;
            assert!(
                headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| {
                        value.starts_with("Bearer rrc_01k0z6r1w8f4jy2m7q9v3x5abd.")
                    })
            );
            let Some(Ok(Message::Text(hello))) = pending.next().await else {
                panic!("pending connection omitted hello");
            };
            let hello: serde_json::Value = serde_json::from_str(&hello).unwrap();
            pending.send(welcome()).await.unwrap();
            pending
                .send(observation_acknowledgement(
                    hello["messageId"].as_str().unwrap(),
                    hello["sequence"].as_u64().unwrap(),
                ))
                .await
                .unwrap();
            while pending.next().await.is_some() {}
        });
        let (service, _capture, shutdown_trigger) =
            spawn_configured_service(fixture.config.clone(), fixture_sleeper());
        with_watchdog(rejected_received).await.unwrap().unwrap();

        with_watchdog(async {
            loop {
                let response = request_control(socket_path.clone(), Operation::Status).await;
                if let Response::Status(status) = response
                    && status.connection_state == ConnectionState::AuthenticationFailed
                {
                    break;
                }
                TokioSleeper.sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            request_staged_reload(&fixture, socket_path).await,
            Response::Reloaded {
                credential_id: "rrc_01k0z6r1w8f4jy2m7q9v3x5abd".to_owned()
            }
        );

        shutdown_trigger.notify_one();
        with_watchdog(service).await.unwrap().unwrap().unwrap();
        with_watchdog(server).await.unwrap().unwrap();
    }

    /// A call the service made on a test rejoin object, or its drop.
    #[derive(Debug, Eq, PartialEq)]
    enum RejoinCall {
        Attempt,
        Retrying(JoinRetry),
        Dropped,
    }

    #[derive(Clone, Default)]
    struct RejoinCalls(Arc<std::sync::Mutex<Vec<RejoinCall>>>);

    impl RejoinCalls {
        fn record(&self, call: RejoinCall) {
            self.0.lock().unwrap().push(call);
        }

        fn take(&self) -> Vec<RejoinCall> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }

        fn contains(&self, call: &RejoinCall) -> bool {
            self.0.lock().unwrap().contains(call)
        }

        fn retry(&self) -> Option<JoinRetry> {
            self.0.lock().unwrap().iter().find_map(|call| match call {
                RejoinCall::Retrying(retry) => Some(*retry),
                RejoinCall::Attempt | RejoinCall::Dropped => None,
            })
        }

        async fn wait_until_dropped(&self) {
            with_watchdog(async {
                while !self.contains(&RejoinCall::Dropped) {
                    TokioSleeper.sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("the service did not drop its rejoin object");
        }
    }

    /// A rejoin that answers its attempts from a script and records its calls.
    struct ScriptedRejoin {
        answers: std::collections::VecDeque<RejoinAnswer>,
        calls: RejoinCalls,
    }

    impl Rejoin for ScriptedRejoin {
        fn attempt(&mut self) -> RejoinAnswer {
            self.calls.record(RejoinCall::Attempt);
            self.answers
                .pop_front()
                .expect("the service sent a rejoin the test did not script")
        }

        fn retrying(&mut self, retry: JoinRetry) {
            self.calls.record(RejoinCall::Retrying(retry));
        }
    }

    impl Drop for ScriptedRejoin {
        fn drop(&mut self) {
            self.calls.record(RejoinCall::Dropped);
        }
    }

    fn held_join_key(answers: &[RejoinAnswer]) -> (JoinKeyMode, RejoinCalls) {
        let calls = RejoinCalls::default();
        let rejoin = ScriptedRejoin {
            answers: answers.iter().copied().collect(),
            calls: calls.clone(),
        };
        (JoinKeyMode::Held(Box::new(rejoin)), calls)
    }

    /// Answers every connection's upgrade 401, as Cloud answers the credential
    /// of a runner it removed.
    fn refuse_every_upgrade(listener: tokio::net::TcpListener) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.expect("accept fixture connection");
                let mut request = [0_u8; 4096];
                let _ = stream
                    .read(&mut request)
                    .await
                    .expect("read upgrade request");
                stream
                    .write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n")
                    .await
                    .expect("refuse the runner credential");
            }
        })
    }

    fn spawn_refused_service(
        fixture: &RotationFixture,
        sleeper: Arc<dyn Sleeper>,
        join_key: JoinKeyMode,
    ) -> (
        tokio::task::JoinHandle<Result<ServiceEnd, ServiceError>>,
        ControlledShutdownTrigger,
    ) {
        let (service, _capture, shutdown_trigger) = spawn_service_with_join_key(
            fixture.config.clone(),
            sleeper,
            Some(unavailable_source_broker()),
            None,
            join_key,
        );
        (service, shutdown_trigger)
    }

    async fn wait_for_connection_state(
        socket_path: &Path,
        state: ConnectionState,
    ) -> StatusSnapshot {
        with_watchdog(async {
            loop {
                if let Response::Status(status) =
                    request_control(socket_path.to_owned(), Operation::Status).await
                    && status.connection_state == state
                {
                    return status;
                }
                TokioSleeper.sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the runner's status did not reach the expected connection state")
    }

    /// Makes a parked runner's loop look again, as a further event would: a
    /// reload request with no pending credential is answered and changes
    /// nothing.
    async fn look_again(socket_path: &Path) {
        assert_eq!(
            request_control(socket_path.to_owned(), Operation::ReloadCredential).await,
            Response::Error(ControlError::NoPendingCredential)
        );
    }

    /// The controlled sleep the service requested for the retry it told its
    /// rejoin object about.
    async fn retry_sleep(
        sleeps: &mut tokio::sync::mpsc::UnboundedReceiver<(Duration, SleepRelease)>,
        calls: &RejoinCalls,
    ) -> (JoinRetry, SleepRelease) {
        loop {
            let (delay, release) = with_watchdog(sleeps.recv())
                .await
                .expect("the service requested no retry delay")
                .expect("controlled sleeper closed");
            if let Some(retry) = calls.retry()
                && retry.delay == delay
            {
                return (retry, release);
            }
        }
    }

    #[tokio::test]
    async fn a_held_key_rejoins_at_the_first_refusal_and_ends_the_service() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        let server = refuse_every_upgrade(listener);
        let (join_key, calls) = held_join_key(&[RejoinAnswer::Rejoined]);
        let (service, _shutdown_trigger) =
            spawn_refused_service(&fixture, fixture_sleeper(), join_key);

        let end = with_watchdog(service).await.unwrap().unwrap().unwrap();

        assert_eq!(end, ServiceEnd::Rejoined);
        assert_eq!(calls.take(), [RejoinCall::Attempt, RejoinCall::Dropped]);
        // The service that serves the rejoined runner leases the same work root.
        WorkRootLease::acquire_for_test(
            fixture.config.assignment().work_root(),
            "rbt_00000000000000000000000009",
        )
        .expect("the ended service still holds its work root");
        server.abort();
    }

    #[tokio::test]
    async fn a_refused_rejoin_parks_the_runner_and_is_not_sent_again() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        let socket_path = fixture.config.control_socket_path().unwrap().to_owned();
        let server = refuse_every_upgrade(listener);
        let (join_key, calls) = held_join_key(&[RejoinAnswer::Refused]);
        let (service, shutdown_trigger) =
            spawn_refused_service(&fixture, fixture_sleeper(), join_key);

        calls.wait_until_dropped().await;
        wait_for_connection_state(&socket_path, ConnectionState::AuthenticationFailed).await;
        look_again(&socket_path).await;

        assert_eq!(calls.take(), [RejoinCall::Attempt, RejoinCall::Dropped]);
        assert!(!service.is_finished());
        shutdown_trigger.notify_one();
        assert_eq!(
            with_watchdog(service).await.unwrap().unwrap().unwrap(),
            ServiceEnd::Stopped
        );
        server.abort();
    }

    #[tokio::test]
    async fn an_unanswered_rejoin_is_sent_again_after_the_reconnect_delay() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        let server = refuse_every_upgrade(listener);
        let (join_key, calls) = held_join_key(&[
            RejoinAnswer::Unanswered(AmbiguousCause::CloudUnavailable(503)),
            RejoinAnswer::Rejoined,
        ]);
        let (sleeper, mut sleeps) = controlled_sleeper();
        let (service, _shutdown_trigger) = spawn_refused_service(&fixture, sleeper, join_key);

        let (retry, release) = retry_sleep(&mut sleeps, &calls).await;
        assert_eq!(retry.cause, AmbiguousCause::CloudUnavailable(503));
        assert_eq!(
            calls.take(),
            [RejoinCall::Attempt, RejoinCall::Retrying(retry)]
        );
        release.release();

        assert_eq!(
            with_watchdog(service).await.unwrap().unwrap().unwrap(),
            ServiceEnd::Rejoined
        );
        assert_eq!(calls.take(), [RejoinCall::Attempt, RejoinCall::Dropped]);
        server.abort();
    }

    #[tokio::test]
    async fn a_stop_between_rejoin_attempts_ends_the_service_without_another() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        let server = refuse_every_upgrade(listener);
        let (join_key, calls) = held_join_key(&[RejoinAnswer::Unanswered(AmbiguousCause::Network)]);
        let (sleeper, mut sleeps) = controlled_sleeper();
        let (service, shutdown_trigger) = spawn_refused_service(&fixture, sleeper, join_key);

        // The retry's delay is never released: only the stop can end the wait.
        let (retry, _held_delay) = retry_sleep(&mut sleeps, &calls).await;
        shutdown_trigger.notify_one();

        assert_eq!(
            with_watchdog(service).await.unwrap().unwrap().unwrap(),
            ServiceEnd::Stopped
        );
        assert_eq!(
            calls.take(),
            [
                RejoinCall::Attempt,
                RejoinCall::Retrying(retry),
                RejoinCall::Dropped
            ]
        );
        server.abort();
    }

    #[tokio::test]
    async fn a_completed_handshake_drops_the_key_and_a_later_refusal_ends_the_service() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        let socket_path = fixture.config.control_socket_path().unwrap().to_owned();
        let (connected_sent, connected) = tokio::sync::oneshot::channel();
        let (close_sent, close) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let mut socket = accept_opened_fixture_socket(&listener).await;
            socket.send(welcome()).await.unwrap();
            socket
                .send(observation_acknowledgement(
                    "rmsg_00000000000000000000000002",
                    1,
                ))
                .await
                .unwrap();
            connected_sent.send(()).unwrap();
            close.await.unwrap();
            socket.close(None).await.unwrap();
            while socket.next().await.is_some() {}
            refuse_every_upgrade(listener).await.unwrap();
        });
        let (join_key, calls) = held_join_key(&[]);
        let (service, _shutdown_trigger) =
            spawn_refused_service(&fixture, fixture_sleeper(), join_key);

        with_watchdog(connected).await.unwrap().unwrap();
        calls.wait_until_dropped().await;
        wait_for_connection_state(&socket_path, ConnectionState::Connected).await;
        assert_eq!(calls.take(), [RejoinCall::Dropped]);
        close_sent.send(()).unwrap();

        assert_eq!(
            with_watchdog(service).await.unwrap().unwrap().unwrap(),
            ServiceEnd::CredentialRefused
        );
        assert_eq!(calls.take(), []);
        server.abort();
    }

    #[tokio::test]
    async fn a_process_without_its_key_ends_at_a_refused_credential() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        let server = refuse_every_upgrade(listener);
        let (service, _shutdown_trigger) =
            spawn_refused_service(&fixture, fixture_sleeper(), JoinKeyMode::Spent);

        assert_eq!(
            with_watchdog(service).await.unwrap().unwrap().unwrap(),
            ServiceEnd::CredentialRefused
        );
        server.abort();
    }

    #[tokio::test]
    async fn a_promoted_pending_credential_is_not_answered_with_a_rejoin() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::new(&endpoint);
        let server = tokio::spawn(async move {
            let (mut current, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = current.read(&mut request).await.unwrap();
            current
                .write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n")
                .await
                .unwrap();
            let mut pending = accept_fixture_socket(&listener).await;
            let Some(Ok(Message::Text(hello))) = pending.next().await else {
                panic!("pending connection omitted hello");
            };
            let hello: serde_json::Value = serde_json::from_str(&hello).unwrap();
            pending.send(welcome()).await.unwrap();
            pending
                .send(observation_acknowledgement(
                    hello["messageId"].as_str().unwrap(),
                    hello["sequence"].as_u64().unwrap(),
                ))
                .await
                .unwrap();
            while pending.next().await.is_some() {}
        });
        let (join_key, calls) = held_join_key(&[]);
        let (service, shutdown_trigger) =
            spawn_refused_service(&fixture, fixture_sleeper(), join_key);

        // The pending credential's handshake drops the key unused.
        calls.wait_until_dropped().await;
        shutdown_trigger.notify_one();

        assert_eq!(
            with_watchdog(service).await.unwrap().unwrap().unwrap(),
            ServiceEnd::Stopped
        );
        assert_eq!(calls.take(), [RejoinCall::Dropped]);
        with_watchdog(server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn an_unusable_key_is_reported_once_and_the_runner_parks() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        let socket_path = fixture.config.control_socket_path().unwrap().to_owned();
        let server = refuse_every_upgrade(listener);
        let reports = Arc::new(AtomicUsize::new(0));
        let reported = Arc::clone(&reports);
        let report = Box::new(move || {
            reported.fetch_add(1, Ordering::SeqCst);
        });
        let (service, shutdown_trigger) =
            spawn_refused_service(&fixture, fixture_sleeper(), JoinKeyMode::Unusable(report));

        with_watchdog(async {
            while reports.load(Ordering::SeqCst) == 0 {
                TokioSleeper.sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the unusable key's report did not run");
        wait_for_connection_state(&socket_path, ConnectionState::AuthenticationFailed).await;
        look_again(&socket_path).await;

        assert_eq!(reports.load(Ordering::SeqCst), 1);
        assert!(!service.is_finished());
        shutdown_trigger.notify_one();
        assert_eq!(
            with_watchdog(service).await.unwrap().unwrap().unwrap(),
            ServiceEnd::Stopped
        );
        server.abort();
    }

    #[tokio::test]
    async fn a_refused_credential_does_not_end_a_runner_that_holds_an_assignment() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        let (source_broker, offer) = fixture.accepted_source();
        let socket_path = fixture.config.control_socket_path().unwrap().to_owned();
        let (accepted_sent, accepted_received) = tokio::sync::oneshot::channel();
        let (close_sent, mut close) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (mut socket, _accepted) = accept_offered_assignment(&listener, offer).await;
            accepted_sent.send(()).unwrap();
            loop {
                tokio::select! {
                    _ = &mut close => break,
                    frame = socket.next() => {
                        let Some(Ok(Message::Text(frame))) = frame else {
                            continue;
                        };
                        let frame: serde_json::Value = serde_json::from_str(&frame).unwrap();
                        acknowledge_runner_frame(&mut socket, &frame, "acknowledge observation")
                            .await;
                    }
                }
            }
            socket.close(None).await.unwrap();
            while socket.next().await.is_some() {}
            refuse_every_upgrade(listener).await.unwrap();
        });
        let (join_key, calls) = held_join_key(&[]);
        let (service, _capture, _shutdown_trigger) = spawn_service_with_join_key(
            fixture.config.clone(),
            fixture_sleeper(),
            Some(source_broker),
            None,
            join_key,
        );
        with_watchdog(accepted_received).await.unwrap().unwrap();
        calls.wait_until_dropped().await;
        close_sent.send(()).unwrap();

        let status =
            wait_for_connection_state(&socket_path, ConnectionState::AuthenticationFailed).await;
        assert_eq!(status.assignment_counts.accepted, 1);
        look_again(&socket_path).await;

        assert!(!service.is_finished());
        assert_eq!(calls.take(), [RejoinCall::Dropped]);
        abort_service(service).await;
        server.abort();
    }

    const KEPT_BOOT: &str = "rbt_01k0z6r1w8f4jy2m7q9v3x5abc";
    const KEPT_ASSIGNMENT: &str = "asn_01k0z6r1w8f4jy2m7q9v3x5abk";

    /// Leaves in `work_root` an earlier boot holding one kept attempt, as a process that
    /// ended without removing it leaves them, its directory dated `modified`, and answers
    /// the boot's and the kept directory's paths.
    fn keep_earlier_boot_attempt(
        work_root: &Path,
        modified: time::OffsetDateTime,
    ) -> (PathBuf, PathBuf) {
        let earlier = WorkRootLease::acquire_for_test(work_root, KEPT_BOOT).unwrap();
        let kept = earlier
            .create_assignment_for_attempt(
                KEPT_ASSIGNMENT,
                "run_01k0z6r1w8f4jy2m7q9v3x5abk",
                "atm_01k0z6r1w8f4jy2m7q9v3x5abk",
                None,
            )
            .unwrap();
        assert_eq!(
            kept.release_pending(
                super::workspace::ProcessQuiescence::Proven,
                super::workspace::WorkspaceDisposition::Retain(
                    super::workspace::RetentionReason::Failed
                ),
            )
            .wait(),
            super::workspace::CleanupResult::Retained
        );
        let boot = earlier.boot_path().to_owned();
        drop(earlier);
        let directory = boot.join(KEPT_ASSIGNMENT);
        let stamp = rustix::fs::Timespec {
            tv_sec: modified.unix_timestamp(),
            tv_nsec: 0,
        };
        rustix::fs::utimensat(
            rustix::fs::CWD,
            &directory,
            &rustix::fs::Timestamps {
                last_access: stamp,
                last_modification: stamp,
            },
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap();
        (boot, directory)
    }

    /// A serving runner on the controlled sleeper whose work root holds an earlier boot's
    /// kept attempt, and a Cloud that opens its session, offers an assignment when asked
    /// to, sends what the test hands it and acknowledges every runner frame.
    struct KeptRunService {
        _fixture: RotationFixture,
        socket: PathBuf,
        cache: Option<FilledCache>,
        boot: PathBuf,
        directory: PathBuf,
        capture: TestCapture,
        sleeps: tokio::sync::mpsc::UnboundedReceiver<(Duration, SleepRelease)>,
        cloud: tokio::sync::mpsc::UnboundedSender<Message>,
        connected: tokio::sync::oneshot::Receiver<()>,
        task: tokio::task::JoinHandle<Result<ServiceEnd, ServiceError>>,
        server: tokio::task::JoinHandle<()>,
        _shutdown: ControlledShutdownTrigger,
    }

    impl KeptRunService {
        /// `age` is how old the kept directory is by the service's clock when it starts.
        async fn start(age: time::Duration, offer_assignment: bool) -> Self {
            Self::start_with_cache(age, offer_assignment, None).await
        }

        /// As `start`, with a configuration that names `cache` as its one build cache.
        async fn start_with_cache(
            age: time::Duration,
            offer_assignment: bool,
            cache: Option<FilledCache>,
        ) -> Self {
            let (listener, endpoint) = fixture_listener().await;
            let fixture = RotationFixture::without_pending(&endpoint);
            let config = match &cache {
                Some(cache) => fixture
                    .config
                    .clone()
                    .with_build_caches(vec![cache.build_cache()]),
                None => fixture.config.clone(),
            };
            let (sleeper, sleeps) = controlled_sleeper();
            let (boot, directory) = keep_earlier_boot_attempt(
                fixture.config.assignment().work_root(),
                sleeper.utc_now() - age,
            );
            let (source_broker, offer) = fixture.accepted_source();
            let offer = offer_assignment.then_some(offer);
            let (cloud, mut sent) = tokio::sync::mpsc::unbounded_channel::<Message>();
            let (connected_sent, connected) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let mut socket = match offer {
                    Some(offer) => {
                        let (mut socket, accepted) =
                            accept_offered_assignment(&listener, offer).await;
                        acknowledge_runner_frame(&mut socket, &accepted, "acknowledge acceptance")
                            .await;
                        socket
                    }
                    None => {
                        let mut socket = accept_opened_fixture_socket(&listener).await;
                        socket.send(welcome()).await.unwrap();
                        socket
                            .send(observation_acknowledgement(
                                "rmsg_00000000000000000000000002",
                                1,
                            ))
                            .await
                            .unwrap();
                        socket
                    }
                };
                connected_sent.send(()).unwrap();
                loop {
                    tokio::select! {
                        Some(message) = sent.recv() => socket.send(message).await.unwrap(),
                        frame = socket.next() => match frame {
                            Some(Ok(Message::Text(frame))) => {
                                let frame: serde_json::Value =
                                    serde_json::from_str(&frame).unwrap();
                                if frame["messageId"].is_string() && frame["sequence"].is_u64() {
                                    acknowledge_runner_frame(&mut socket, &frame, "acknowledge")
                                        .await;
                                }
                            }
                            Some(Ok(_)) => {}
                            _ => break,
                        },
                    }
                }
            });
            let (task, capture, shutdown) = spawn_service_with_join_key(
                config,
                sleeper,
                Some(source_broker),
                None,
                JoinKeyMode::None,
            );
            Self {
                socket: fixture.config.control_socket_path().unwrap().to_owned(),
                _fixture: fixture,
                cache,
                boot,
                directory,
                capture,
                sleeps,
                cloud,
                connected,
                task,
                server,
                _shutdown: shutdown,
            }
        }

        /// Asks the control socket what the runner keeps under `scope`, and answers its
        /// report.
        async fn kept(&self, scope: PruneScope) -> KeptReport {
            let socket = self.socket.clone();
            let answer = with_watchdog(tokio::task::spawn_blocking(move || {
                crate::control_client::request_kept(&socket, scope)
            }))
            .await
            .expect("the kept report was not answered")
            .unwrap()
            .unwrap();
            let KeptAnswer::Kept(report) = answer else {
                panic!("a kept report: {answer:?}");
            };
            *report
        }

        /// Asks the control socket to prune what `scope` covers, and answers its answer.
        async fn prune(&self, scope: PruneScope) -> PruneAnswer {
            let socket = self.socket.clone();
            with_watchdog(tokio::task::spawn_blocking(move || {
                crate::control_client::request_prune(&socket, scope)
            }))
            .await
            .expect("the prune was not answered")
            .unwrap()
            .unwrap()
        }

        /// Asks the control socket to prune what `scope` covers, and answers its result.
        async fn pruned_by_operator(&self, scope: PruneScope) -> PruneReport {
            let answer = self.prune(scope).await;
            let PruneAnswer::Pruned(report) = answer else {
                panic!("a prune result: {answer:?}");
            };
            *report
        }

        /// Waits until the runner has connected, or accepted the offered assignment.
        async fn connected(&mut self) {
            with_watchdog(&mut self.connected)
                .await
                .expect("the runner did not connect")
                .expect("the fixture Cloud ended");
        }

        /// Waits until the pass in flight has ended, which the schedule shows by waiting
        /// for the next hour, and answers that hour's sleep.
        async fn pass_ended(&mut self) -> SleepRelease {
            with_watchdog(sleep_request(
                &mut self.sleeps,
                super::KEPT_RUN_PASS_INTERVAL,
            ))
            .await
            .expect("the kept-run schedule did not wait for its next hour")
        }

        fn pruned(&self) -> Vec<serde_json::Map<String, serde_json::Value>> {
            self.capture
                .records()
                .into_iter()
                .filter(|record| record["event.name"] == "runner.workspace_pruned")
                .collect()
        }

        /// Asserts that the kept directory and its emptied boot are gone and that one
        /// record says the age bound removed the directory.
        fn assert_removed_by_age(&self) {
            assert!(!self.directory.exists());
            assert!(!self.boot.exists());
            let pruned = self.pruned();
            let [record] = pruned.as_slice() else {
                panic!("one pruned record: {pruned:?}");
            };
            assert_eq!(
                record["um.workspace.path"],
                self.directory.to_string_lossy().as_ref()
            );
            assert_eq!(record["um.assignment.id"], KEPT_ASSIGNMENT);
            assert_eq!(record["um.workspace.prune_bound"], "age");
            assert_eq!(record["um.workspace.prune_outcome"], "removed");
        }

        fn assert_kept(&self) {
            assert!(self.directory.is_dir());
            assert!(self.pruned().is_empty());
        }

        /// Has Cloud let the offered assignment go, which ends it.
        fn release_assignment(&self) {
            self.cloud
                .send(cloud_frame(
                    "assignment_release",
                    "cmsg_01k0z6r1w8f4jy2m7q9v3x5abt",
                    serde_json::json!({
                        "effectId": "eff_01k0z6r1w8f4jy2m7q9v3x5abt",
                        "assignmentId": "asn_01k0z6r1w8f4jy2m7q9v3x5abh",
                        "runId": "run_01k0z6r1w8f4jy2m7q9v3x5abj",
                        "attemptId": "atm_01k0z6r1w8f4jy2m7q9v3x5abc",
                        "reason": "stale_or_invalid_acceptance",
                    }),
                ))
                .unwrap();
        }

        fn evicted(&self) -> Vec<serde_json::Map<String, serde_json::Value>> {
            self.capture
                .records()
                .into_iter()
                .filter(|record| record["event.name"] == "runner.build_cache_evicted")
                .collect()
        }

        fn cache(&self) -> &FilledCache {
            self.cache
                .as_ref()
                .expect("the service names a build cache")
        }

        /// Asserts that the cache occupies at most nine tenths of its bound and that one
        /// record says so.
        fn assert_evicted(&self) {
            let cache = self.cache();
            assert!(cache.occupied() <= cache.maximum_bytes * 9 / 10);
            let evicted = self.evicted();
            let [record] = evicted.as_slice() else {
                panic!("one evicted record: {evicted:?}");
            };
            assert_eq!(
                record["um.build_cache.path"],
                cache.path.to_string_lossy().as_ref()
            );
            assert!(record["um.build_cache.removed_files"].as_u64() > Some(0));
        }

        /// Asserts that every file of the cache stays and that no record says otherwise.
        fn assert_cache_untouched(&self) {
            let cache = self.cache();
            assert_eq!(cache.files(), cache.written);
            assert!(self.evicted().is_empty());
        }

        async fn end(self) {
            abort_service(self.task).await;
            self.server.abort();
        }
    }

    const CACHE_FILES: usize = 8;

    /// A build cache in a directory of its own, outside the work root, of `CACHE_FILES`
    /// files of 64 KiB, each last used a minute after the one before.
    struct FilledCache {
        _root: tempfile::TempDir,
        path: PathBuf,
        maximum_bytes: u64,
        written: usize,
    }

    impl FilledCache {
        /// Bounded at half of what its files occupy when `over`, at twice that otherwise.
        fn new(over: bool) -> Self {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("cargo-target");
            fs::create_dir(&path).unwrap();
            let mut cache = Self {
                _root: root,
                path,
                maximum_bytes: 0,
                written: 0,
            };
            cache.write(CACHE_FILES);
            let occupied = cache.occupied();
            cache.maximum_bytes = if over { occupied / 2 } else { occupied * 2 };
            cache
        }

        /// Writes `count` more files, each last used a minute after the one before.
        fn write(&mut self, count: usize) {
            for index in self.written..self.written + count {
                let file = self.path.join(format!("artifact-{index}"));
                fs::write(&file, vec![7_u8; 64 * 1024]).unwrap();
                // 2026-01-01, a minute apart; eviction orders by use, so the service's
                // clock does not matter.
                let stamp = rustix::fs::Timespec {
                    tv_sec: 1_767_225_600 + 60 * i64::try_from(index).unwrap(),
                    tv_nsec: 0,
                };
                rustix::fs::utimensat(
                    rustix::fs::CWD,
                    &file,
                    &rustix::fs::Timestamps {
                        last_access: stamp,
                        last_modification: stamp,
                    },
                    rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
                )
                .unwrap();
            }
            self.written += count;
        }

        fn build_cache(&self) -> super::BuildCache {
            super::BuildCache {
                path: self.path.clone(),
                maximum_bytes: self.maximum_bytes,
            }
        }

        fn files(&self) -> usize {
            fs::read_dir(&self.path).unwrap().count()
        }

        /// What the files below the cache's `path` occupy.
        fn occupied(&self) -> u64 {
            use std::os::unix::fs::MetadataExt as _;
            fs::read_dir(&self.path)
                .unwrap()
                .map(|entry| entry.unwrap().metadata().unwrap().blocks() * 512)
                .sum()
        }
    }

    /// Thirty minutes short of the default age bound, 14 days.
    fn short_of_the_age_bound() -> time::Duration {
        14 * time::Duration::DAY - 30 * time::Duration::MINUTE
    }

    #[tokio::test]
    async fn a_starting_runner_removes_a_kept_run_past_the_age_bound_after_reporting_it() {
        // Dated 2026-07-01, 22 days before the clock's origin.
        let mut service = KeptRunService::start(22 * time::Duration::DAY, false).await;
        service.connected().await;
        let _hour = service.pass_ended().await;

        service.assert_removed_by_age();
        let records = service.capture.records();
        let retained = records
            .iter()
            .position(|record| {
                record["event.name"] == "runner.workspace_retained"
                    && record["um.workspace.path"]
                        .as_str()
                        .is_some_and(|path| Path::new(path).starts_with(&service.boot))
            })
            .expect("the startup report of the kept directory");
        let pruned = records
            .iter()
            .position(|record| record["event.name"] == "runner.workspace_pruned")
            .expect("the record of its removal");
        assert!(retained < pruned);
        service.end().await;
    }

    #[tokio::test]
    async fn a_starting_runner_keeps_a_kept_run_within_its_bounds() {
        // Dated 2026-07-20, 3 days before the clock's origin.
        let mut service = KeptRunService::start(3 * time::Duration::DAY, false).await;
        service.connected().await;
        let _hour = service.pass_ended().await;

        service.assert_kept();
        service.end().await;
    }

    #[tokio::test]
    async fn an_idle_runner_applies_the_kept_run_bounds_each_hour() {
        let mut service = KeptRunService::start(short_of_the_age_bound(), false).await;
        service.connected().await;
        let hour = service.pass_ended().await;
        service.assert_kept();

        hour.release();
        let _next = service.pass_ended().await;

        service.assert_removed_by_age();
        service.end().await;
    }

    #[tokio::test]
    async fn a_working_runner_applies_the_kept_run_bounds_once_its_run_ends() {
        let mut service = KeptRunService::start(short_of_the_age_bound(), true).await;
        service.connected().await;
        let hour = service.pass_ended().await;

        // The hour passes while the accepted assignment works.
        hour.release();
        let _next = service.pass_ended().await;
        service.assert_kept();

        service.release_assignment();
        let _after_the_run = service.pass_ended().await;

        service.assert_removed_by_age();
        service.end().await;
    }

    #[tokio::test]
    async fn a_starting_runner_evicts_a_build_cache_over_its_bound_after_reporting_kept_runs() {
        let mut service = KeptRunService::start_with_cache(
            3 * time::Duration::DAY,
            false,
            Some(FilledCache::new(true)),
        )
        .await;
        service.connected().await;
        let _hour = service.pass_ended().await;

        service.assert_kept();
        service.assert_evicted();
        let records = service.capture.records();
        let evicted = records
            .iter()
            .position(|record| record["event.name"] == "runner.build_cache_evicted")
            .expect("the record of the eviction");
        let retained = records
            .iter()
            .rposition(|record| record["event.name"] == "runner.workspace_retained")
            .expect("the startup report of the kept directory");
        assert!(retained < evicted);
        service.end().await;
    }

    #[tokio::test]
    async fn a_starting_runner_leaves_a_build_cache_within_its_bound() {
        let mut service = KeptRunService::start_with_cache(
            3 * time::Duration::DAY,
            false,
            Some(FilledCache::new(false)),
        )
        .await;
        service.connected().await;
        let _hour = service.pass_ended().await;

        service.assert_cache_untouched();
        service.end().await;
    }

    #[tokio::test]
    async fn a_working_runner_evicts_its_build_caches_once_its_run_ends() {
        let mut service = KeptRunService::start_with_cache(
            3 * time::Duration::DAY,
            true,
            Some(FilledCache::new(false)),
        )
        .await;
        service.connected().await;
        let hour = service.pass_ended().await;
        service.assert_cache_untouched();

        // While the accepted assignment works, the cache grows past its bound and the hour
        // passes.
        service.cache.as_mut().unwrap().write(2 * CACHE_FILES);
        assert!(service.cache().occupied() > service.cache().maximum_bytes);
        hour.release();
        let _next = service.pass_ended().await;
        service.assert_cache_untouched();

        service.release_assignment();
        let _after_the_run = service.pass_ended().await;

        service.assert_evicted();
        service.end().await;
    }

    // A report never meets a pass in flight.
    #[tokio::test]
    async fn a_kept_report_asked_for_at_startup_is_answered_after_the_startup_pass() {
        let mut service = KeptRunService::start(22 * time::Duration::DAY, false).await;
        // The startup pass runs beside connecting, so it may be in flight still.
        service.connected().await;
        let report = service.kept(PruneScope::Bounds).await;

        assert!(report.workspaces.is_empty(), "{report:?}");
        service.assert_removed_by_age();
        service.end().await;
    }

    #[tokio::test]
    async fn an_operator_reports_and_prunes_a_kept_run_within_its_bounds() {
        let mut service = KeptRunService::start(3 * time::Duration::DAY, false).await;
        service.connected().await;
        let directory = service.directory.to_string_lossy().into_owned();

        let report = service.kept(PruneScope::Bounds).await;
        let [workspace] = report.workspaces.as_slice() else {
            panic!("one kept workspace: {report:?}");
        };
        assert_eq!(workspace.directories, std::slice::from_ref(&directory));
        assert_eq!(workspace.state, KeptWorkspaceState::Kept);
        assert_eq!(workspace.reason, KeptReason::Failed);
        assert_eq!(workspace.assignment_id.as_deref(), Some(KEPT_ASSIGNMENT));
        assert!(workspace.bytes > Some(0));
        assert_eq!(report.due_bytes, 0);

        let report = service.kept(PruneScope::All).await;
        let [workspace] = report.workspaces.as_slice() else {
            panic!("one kept workspace: {report:?}");
        };
        assert_eq!(workspace.state, KeptWorkspaceState::Due);
        assert_eq!(workspace.bound, Some(KeptBound::Operator));
        assert_eq!(workspace.bytes, Some(report.due_bytes));
        service.assert_kept();

        let pruned = service.pruned_by_operator(PruneScope::All).await;
        assert!(pruned.complete);
        let [removed] = pruned.directories.as_slice() else {
            panic!("one pruned directory: {pruned:?}");
        };
        assert_eq!(removed.path, directory);
        assert_eq!(removed.bound, KeptBound::Operator);
        assert_eq!(removed.result, PrunedOutcome::Removed);
        assert!(!service.directory.exists());
        assert!(!service.boot.exists());
        let records = service.pruned();
        let [record] = records.as_slice() else {
            panic!("one pruned record: {records:?}");
        };
        assert_eq!(record["um.workspace.path"], directory.as_str());
        assert_eq!(record["um.workspace.prune_bound"], "operator");
        service.end().await;
    }

    #[tokio::test]
    async fn a_working_runner_refuses_a_prune_and_still_reports_what_it_keeps() {
        let mut service = KeptRunService::start(3 * time::Duration::DAY, true).await;
        service.connected().await;

        assert_eq!(
            service.prune(PruneScope::All).await,
            PruneAnswer::Refused(ControlError::RunnerBusy)
        );
        service.assert_kept();

        let report = service.kept(PruneScope::Bounds).await;
        let directory = service.directory.to_string_lossy().into_owned();
        assert!(
            report
                .workspaces
                .iter()
                .any(|workspace| workspace.directories == std::slice::from_ref(&directory)),
            "{report:?}"
        );
        service.end().await;
    }

    #[tokio::test]
    async fn an_operator_reports_and_empties_a_build_cache_within_its_bound() {
        let mut service = KeptRunService::start_with_cache(
            3 * time::Duration::DAY,
            false,
            Some(FilledCache::new(false)),
        )
        .await;
        service.connected().await;

        let report = service.kept(PruneScope::Bounds).await;
        let [cache] = report.build_caches.as_slice() else {
            panic!("one build cache: {report:?}");
        };
        assert_eq!(cache.state, KeptCacheState::Measured);
        assert_eq!(cache.due_bytes, Some(0));

        let pruned = service.pruned_by_operator(PruneScope::All).await;
        let [cache] = pruned.build_caches.as_slice() else {
            panic!("one evicted build cache: {pruned:?}");
        };
        assert_eq!(cache.removed_files, u64::try_from(CACHE_FILES).unwrap());
        assert_eq!(service.cache().files(), 0);
        service.end().await;
    }

    #[test]
    fn a_refused_credential_is_answered_only_once_no_assignment_is_held() {
        let held = AssignmentCounts {
            accepted: 1,
            ..AssignmentCounts::default()
        };
        let idle = AssignmentCounts::default();
        let (rejoin, _calls) = held_join_key(&[]);
        let unusable = JoinKeyMode::Unusable(Box::new(|| {}));
        for (mode, answer) in [
            (JoinKeyMode::Spent, RefusalStep::End),
            (rejoin, RefusalStep::Rejoin),
            (unusable, RefusalStep::Report),
            (JoinKeyMode::None, RefusalStep::Wait),
        ] {
            assert_eq!(refusal_step(&mode, held), RefusalStep::Wait);
            assert_eq!(refusal_step(&mode, idle), answer);
        }
    }

    // These integration proofs intentionally exercise different interleavings
    // against the same closed handshake; keeping each scenario explicit makes
    // its ordering contract auditable.
    #[tokio::test]
    async fn pending_handshake_preserves_contiguous_current_boot_sequences() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        let socket_path = fixture.config.control_socket_path().unwrap().to_owned();
        let (current_sent, current_received) = tokio::sync::oneshot::channel();
        let (sequences_sent, sequences_received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut current = accept_fixture_socket(&listener).await;
            let Some(Ok(Message::Text(current_hello))) = current.next().await else {
                panic!("current connection omitted hello");
            };
            let current_hello: serde_json::Value = serde_json::from_str(&current_hello).unwrap();
            current.send(welcome()).await.unwrap();
            current
                .send(observation_acknowledgement(
                    current_hello["messageId"].as_str().unwrap(),
                    current_hello["sequence"].as_u64().unwrap(),
                ))
                .await
                .unwrap();
            current_sent.send(()).unwrap();

            let (pending_stream, _) = listener.accept().await.unwrap();
            current.send(assignment_offer()).await.unwrap();
            let offer_acknowledgement = effect_acknowledgement(&mut current).await;
            acknowledge_runner_frame(
                &mut current,
                &offer_acknowledgement,
                "acknowledge assignment offer",
            )
            .await;
            let prepare_acknowledgement = begin_assignment_preparation(&mut current).await;
            acknowledge_runner_frame(
                &mut current,
                &prepare_acknowledgement,
                "acknowledge assignment prepare effect",
            )
            .await;
            let rejection =
                next_semantic_assignment_frame(&mut current, "assignment_rejected", true).await;
            let latest_current_sequence = rejection["sequence"].as_u64().unwrap();
            acknowledge_runner_frame(&mut current, &rejection, "acknowledge assignment rejection")
                .await;

            let mut pending = accept_fixture_stream(pending_stream).await;
            let Some(Ok(Message::Text(pending_hello))) = pending.next().await else {
                panic!("pending connection omitted hello");
            };
            let pending_hello: serde_json::Value = serde_json::from_str(&pending_hello).unwrap();
            // The credential-promotion hello advertises no recovery.
            assert_hello_advertises_no_recovery(&pending_hello);
            sequences_sent
                .send((
                    latest_current_sequence,
                    pending_hello["sequence"].as_u64().unwrap(),
                ))
                .unwrap();
            pending
                .send(Message::Text("invalid-pending-frame".into()))
                .await
                .unwrap();
            while current.next().await.is_some() {}
        });
        let (service, _capture, shutdown_trigger) =
            spawn_configured_service(fixture.config.clone(), fixture_sleeper());
        with_watchdog(current_received).await.unwrap().unwrap();
        assert_eq!(
            request_staged_reload(&fixture, socket_path).await,
            Response::Error(ControlError::PendingProtocolFailed)
        );
        let (latest_current_sequence, pending_hello_sequence) =
            with_watchdog(sequences_received).await.unwrap().unwrap();
        assert!(
            pending_hello_sequence > latest_current_sequence,
            "pending hello sequence {pending_hello_sequence} regressed behind current sequence {latest_current_sequence}"
        );

        shutdown_trigger.notify_one();
        with_watchdog(service).await.unwrap().unwrap().unwrap();
        with_watchdog(server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn pending_handshake_keeps_the_current_transport_live() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        let socket_path = fixture.config.control_socket_path().unwrap().to_owned();
        let (current_sent, current_received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut current = accept_fixture_socket(&listener).await;
            let Some(Ok(Message::Text(current_hello))) = current.next().await else {
                panic!("current connection omitted hello");
            };
            let current_hello: serde_json::Value = serde_json::from_str(&current_hello).unwrap();
            current.send(welcome()).await.unwrap();
            current
                .send(observation_acknowledgement(
                    current_hello["messageId"].as_str().unwrap(),
                    current_hello["sequence"].as_u64().unwrap(),
                ))
                .await
                .unwrap();
            current_sent.send(()).unwrap();

            let mut pending = accept_fixture_socket(&listener).await;
            expect_opening_hello(&mut pending).await;
            current
                .send(Message::Ping(vec![1, 2, 3].into()))
                .await
                .unwrap();
            loop {
                match with_watchdog(current.next()).await.unwrap() {
                    Some(Ok(Message::Pong(payload))) => {
                        assert_eq!(payload.as_ref(), &[1, 2, 3]);
                        break;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => panic!("current connection failed: {error}"),
                    None => panic!("current connection closed during pending handshake"),
                }
            }
            pending
                .send(Message::Text("invalid-pending-frame".into()))
                .await
                .unwrap();
            while current.next().await.is_some() {}
        });
        let (service, _capture, shutdown_trigger) =
            spawn_configured_service(fixture.config.clone(), fixture_sleeper());
        with_watchdog(current_received).await.unwrap().unwrap();
        assert_eq!(
            request_staged_reload(&fixture, socket_path).await,
            Response::Error(ControlError::PendingProtocolFailed)
        );
        shutdown_trigger.notify_one();
        with_watchdog(service).await.unwrap().unwrap().unwrap();
        with_watchdog(server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn startup_establishes_current_before_promoting_pending_in_the_same_boot() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::new(&endpoint);
        let state_path = fixture.state_path.clone();
        let (promoted_sent, promoted_received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (current, mut pending) = accept_rotation_connections(&listener, None, false).await;
            promoted_sent.send(()).unwrap();
            while pending.next().await.is_some() {}
            drop(current);
        });
        let (service, _capture, shutdown_trigger) =
            spawn_configured_service(fixture.config, fixture_sleeper());
        with_watchdog(promoted_received).await.unwrap().unwrap();
        loop {
            let state: serde_json::Value =
                serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
            if state.get("pendingCredential").is_none() {
                break;
            }
            TokioSleeper.sleep(Duration::from_millis(1)).await;
        }
        shutdown_trigger.notify_one();
        with_watchdog(service).await.unwrap().unwrap().unwrap();
        with_watchdog(server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn reload_state_write_failure_preserves_current_and_pending_state() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::new(&endpoint);
        let original = fs::read(&fixture.state_path).unwrap();
        let state_path = fixture.state_path.clone();
        let hard_link = state_path.with_extension("hard-link");
        let server = tokio::spawn(async move {
            let mut socket = accept_fixture_socket(&listener).await;
            expect_opening_hello(&mut socket).await;
            fs::hard_link(&state_path, &hard_link).unwrap();
            socket.send(welcome()).await.unwrap();
            hard_link
        });

        let (promoted, response, _capture, target) = reload_fixture(&fixture.config).await;
        assert_eq!(
            target.current().credential().credential_id(),
            fixture.config.credential().credential_id()
        );
        assert!(promoted.is_none());
        assert_eq!(response, Err(ControlError::StateUpdateFailed));
        assert_eq!(fs::read(&fixture.state_path).unwrap(), original);
        let hard_link = server.await.unwrap();
        fs::remove_file(hard_link).unwrap();
    }

    #[tokio::test]
    async fn reload_state_write_failure_restores_current_transport() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        fixture.stage_pending();
        let staged_state = fs::read(&fixture.state_path).unwrap();
        let state_path = fixture.state_path.clone();
        let hard_link = state_path.with_extension("hard-link");
        let socket_path = fixture.config.control_socket_path().unwrap().to_owned();
        let (current_sent, current_received) = tokio::sync::oneshot::channel();
        let (recovered_sent, recovered_received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut current, _) = accept_fixture_socket_with_headers(&listener).await;
            let Some(Ok(Message::Text(current_hello))) = current.next().await else {
                panic!("current connection omitted hello");
            };
            let current_hello: serde_json::Value = serde_json::from_str(&current_hello).unwrap();
            current.send(welcome()).await.unwrap();
            current
                .send(observation_acknowledgement(
                    current_hello["messageId"].as_str().unwrap(),
                    current_hello["sequence"].as_u64().unwrap(),
                ))
                .await
                .unwrap();
            current_sent.send(()).unwrap();

            let (mut pending, pending_headers) =
                accept_fixture_socket_with_headers(&listener).await;
            assert!(
                pending_headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| {
                        value.starts_with("Bearer rrc_01k0z6r1w8f4jy2m7q9v3x5abd.")
                    })
            );
            let Some(Ok(Message::Text(pending_hello))) = pending.next().await else {
                panic!("pending connection omitted hello");
            };
            let pending_hello: serde_json::Value = serde_json::from_str(&pending_hello).unwrap();
            fs::hard_link(&state_path, &hard_link).unwrap();
            pending.send(welcome()).await.unwrap();
            pending
                .send(observation_acknowledgement(
                    pending_hello["messageId"].as_str().unwrap(),
                    pending_hello["sequence"].as_u64().unwrap(),
                ))
                .await
                .unwrap();
            drop(current);

            let (mut recovered, recovered_headers) =
                accept_fixture_socket_with_headers(&listener).await;
            assert!(
                recovered_headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| {
                        value.starts_with("Bearer rrc_01k0z6r1w8f4jy2m7q9v3x5abc.")
                    })
            );
            let Some(Ok(Message::Text(recovered_hello))) = recovered.next().await else {
                panic!("recovered current connection omitted hello");
            };
            let recovered_hello: serde_json::Value =
                serde_json::from_str(&recovered_hello).unwrap();
            assert_eq!(recovered_hello["bootId"], pending_hello["bootId"]);
            assert!(
                recovered_hello["sequence"].as_u64().unwrap()
                    > pending_hello["sequence"].as_u64().unwrap()
            );
            recovered.send(welcome()).await.unwrap();
            recovered
                .send(observation_acknowledgement(
                    recovered_hello["messageId"].as_str().unwrap(),
                    recovered_hello["sequence"].as_u64().unwrap(),
                ))
                .await
                .unwrap();
            recovered_sent.send(()).unwrap();
            while recovered.next().await.is_some() {}
            hard_link
        });
        let (service, _capture, shutdown_trigger) =
            spawn_configured_service(fixture.config.clone(), fixture_sleeper());
        with_watchdog(current_received).await.unwrap().unwrap();
        assert_eq!(
            request_control(socket_path, Operation::ReloadCredential).await,
            Response::Error(ControlError::StateUpdateFailed)
        );
        with_watchdog(recovered_received).await.unwrap().unwrap();
        assert_eq!(fs::read(&fixture.state_path).unwrap(), staged_state);

        shutdown_trigger.notify_one();
        with_watchdog(service).await.unwrap().unwrap().unwrap();
        let hard_link = with_watchdog(server).await.unwrap().unwrap();
        fs::remove_file(hard_link).unwrap();
    }

    #[tokio::test]
    async fn reload_authentication_failure_preserves_pending_state() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::new(&endpoint);
        let original = fs::read(&fixture.state_path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let (promoted, response, capture, _) = reload_fixture(&fixture.config).await;
        assert!(promoted.is_none());
        assert_eq!(response, Err(ControlError::PendingAuthenticationFailed));
        assert_eq!(fs::read(&fixture.state_path).unwrap(), original);
        let telemetry = serde_json::to_string(&capture.records()).unwrap();
        assert!(!telemetry.contains(&pending_credential_secret()));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn reload_network_failure_preserves_pending_state() {
        let fixture = RotationFixture::new("ws://127.0.0.1:1/v1/runner/connect");
        let original = fs::read(&fixture.state_path).unwrap();
        let (promoted, response, capture, _) = reload_fixture(&fixture.config).await;
        assert!(promoted.is_none());
        assert_eq!(response, Err(ControlError::PendingConnectionFailed));
        assert_eq!(fs::read(&fixture.state_path).unwrap(), original);
        let telemetry = serde_json::to_string(&capture.records()).unwrap();
        assert!(!telemetry.contains(&pending_credential_secret()));
    }

    #[tokio::test]
    async fn reload_protocol_failure_preserves_pending_state_without_raw_diagnostics() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::new(&endpoint);
        let original = fs::read(&fixture.state_path).unwrap();
        let server = tokio::spawn(async move {
            let mut socket = accept_fixture_socket(&listener).await;
            expect_opening_hello(&mut socket).await;
            socket
                .send(Message::Text(
                    "RAW-PROTOCOL-DIAGNOSTIC-MUST-NOT-LEAK".into(),
                ))
                .await
                .unwrap();
        });

        let (promoted, response, capture, _) = reload_fixture(&fixture.config).await;
        assert!(promoted.is_none());
        assert_eq!(response, Err(ControlError::PendingProtocolFailed));
        assert_eq!(fs::read(&fixture.state_path).unwrap(), original);
        assert!(
            !serde_json::to_string(&capture.records())
                .unwrap()
                .contains("RAW-PROTOCOL-DIAGNOSTIC-MUST-NOT-LEAK")
        );
        server.await.unwrap();
    }

    struct AcceptedAssignmentFixture {
        temporary: tempfile::TempDir,
        config: Config,
        source_broker: Arc<dyn SourceCredentialBroker>,
        offer: Message,
    }

    fn initialize_accepted_repository(source: &Path) {
        run_fixture_git(source, &["init", "--quiet", "--object-format=sha1"]);
        run_fixture_git(source, &["config", "user.name", "Scherzo Fixture"]);
        run_fixture_git(
            source,
            &["config", "user.email", "fixture@usefulmachinery.invalid"],
        );
        run_fixture_git(source, &["add", "."]);
        run_fixture_git(source, &["commit", "--quiet", "-m", "fixture"]);
    }

    fn accepted_assignment_offer(source: &Path) -> Message {
        let commit_oid = run_fixture_git(source, &["rev-parse", "HEAD"]);
        let workflow = resolve(source, Path::new("workflow.yaml"))
            .expect("resolve accepted assignment workflow");
        let requirements = workflow.capacity.requirements;
        let digest = &workflow.capacity.source_closure_digest;
        let Message::Text(encoded) = assignment_offer() else {
            panic!("assignment offer fixture should be text");
        };
        let mut offer: serde_json::Value =
            serde_json::from_str(&encoded).expect("decode assignment offer fixture");
        let execution = &mut offer["payload"]["executionSpec"];
        execution["workflowDefinitionSource"]["commitOid"] = commit_oid.clone().into();
        execution["primaryWorkspaceSource"]["commitOid"] = commit_oid.into();
        execution["workflowDefinitionSource"]["workflowSourceClosureDigest"] = serde_json::json!({
            "algorithm": digest.algorithm.as_str(),
            "value": digest.value,
        });
        execution["capacity"] = serde_json::json!({
            "executionContract": "workflow_v1_cloud_inputs_artifacts@1",
            "sourceClosureDigest": {
                "algorithm": digest.algorithm.as_str(),
                "value": digest.value,
            },
            "generalMaximumTransitions": requirements.general_maximum_transitions,
            "selectedMaximumTransitions": requirements.cloud_maximum_transitions,
            "maximumInvocations": requirements.maximum_invocations,
            "maximumRetainedBytesPerInvocation": requirements.maximum_retained_bytes_per_invocation,
            "diagnosticRetentionBytes": requirements.diagnostic_retention_bytes,
            "nativeSessionRetentionBytes": requirements.native_session_retention_bytes,
            "aggregateRetentionBytes": requirements.aggregate_retention_bytes,
            "conditionTransitionCount": requirements.condition_transition_count,
            "aggregateConditionTransitionBytes": requirements.aggregate_condition_transition_bytes,
            "terminalResultStructureBytes": requirements.terminal_result_structure_bytes,
            "portableResultBytes": requirements.portable_result_bytes,
            "encodedOutboxBytes": requirements.encoded_outbox_bytes,
        });
        Message::Text(offer.to_string().into())
    }

    /// Commits `workflow` to a materialized source repository under `root` beside a
    /// private runner work root, and returns both paths.
    fn materialize_accepted_source(root: &Path, workflow: &str) -> (PathBuf, PathBuf) {
        let source = root.join("source");
        let work = root.join("work");
        fs::create_dir(&source).expect("create materialized source fixture");
        fs::create_dir(&work).expect("create runner work root");
        fs::set_permissions(&work, fs::Permissions::from_mode(0o700))
            .expect("make runner work root private");
        fs::write(source.join("workflow.yaml"), workflow)
            .expect("write materialized workflow fixture");
        initialize_accepted_repository(&source);
        (source, work)
    }

    fn accepted_assignment_service_config(endpoint: &str, work: &Path) -> Config {
        let assignment = AssignmentConfig::new(work).expect("configure assignment");
        Config::new(
            endpoint,
            test_credential(),
            true,
            assignment,
            RepositoryUrlPolicy::with_file_repositories(true),
        )
        .expect("configure gateway")
    }

    fn accepted_assignment_config(endpoint: &str) -> AcceptedAssignmentFixture {
        let temporary = tempfile::tempdir().expect("create service fixture root");
        let (source, work) = materialize_accepted_source(
            temporary.path(),
            "schemaVersion: 1\nsteps:\n  check:\n    kind: cmd\n    command:\n      argv: [\"true\"]\n",
        );
        AcceptedAssignmentFixture {
            config: accepted_assignment_service_config(endpoint, &work),
            source_broker: fixture_source_broker(&source),
            offer: accepted_assignment_offer(&source),
            temporary,
        }
    }

    async fn acknowledge_runner_frame(
        socket: &mut FixtureSocket,
        frame: &serde_json::Value,
        description: &str,
    ) {
        socket
            .send(effect_observation_acknowledgement(
                frame["messageId"].as_str().unwrap(),
                frame["sequence"].as_u64().unwrap(),
            ))
            .await
            .unwrap_or_else(|error| panic!("{description}: {error}"));
    }

    async fn next_semantic_assignment_frame(
        socket: &mut FixtureSocket,
        expected_type: &str,
        acknowledge_progress: bool,
    ) -> serde_json::Value {
        // Source admission performs real Git I/O. Under a concurrent suite it can
        // outlast the two-second fixture liveness window; the fake gateway must
        // keep responding to the runner rather than waiting silently for admission.
        let sleeper = fixture_sleeper();
        loop {
            let next = tokio::select! {
                frame = socket.next() => frame,
                _ = sleeper.sleep(Duration::from_millis(500)) => {
                    socket.send(Message::Ping(vec![4, 5, 6].into())).await
                        .expect("send fixture keepalive");
                    continue;
                }
            };
            let frame = match next {
                Some(Ok(Message::Text(frame))) => frame,
                Some(Ok(Message::Pong(payload))) if payload.as_ref() == [4, 5, 6] => continue,
                Some(Ok(Message::Ping(payload))) => {
                    socket
                        .send(Message::Pong(payload))
                        .await
                        .expect("answer runner keepalive");
                    continue;
                }
                other => panic!("connection ended before {expected_type}: {other:?}"),
            };
            let frame: serde_json::Value =
                serde_json::from_str(&frame).expect("decode assignment observation");
            assert_ne!(frame["type"], "workspace_inventory");
            if frame["type"] == "assignment_preparation_progress" {
                if acknowledge_progress {
                    acknowledge_runner_frame(socket, &frame, "acknowledge preparation progress")
                        .await;
                }
                continue;
            }
            assert_eq!(frame["type"], expected_type);
            return frame;
        }
    }

    async fn accept_assignment_interruption(
        listener: &tokio::net::TcpListener,
        accepted_sent: tokio::sync::oneshot::Sender<()>,
        offer: Message,
    ) -> (FixtureSocket, serde_json::Value, serde_json::Value) {
        let (mut socket, accepted) = accept_offered_assignment(listener, offer).await;
        accepted_sent
            .send(())
            .expect("report assignment acceptance");

        let interrupted =
            next_semantic_assignment_frame(&mut socket, "assignment_interrupted", true).await;
        assert_eq!(interrupted["payload"]["reason"], "graceful_shutdown");
        (socket, accepted, interrupted)
    }

    /// Opens the runner's session, offers and prepares `offer`, and returns the
    /// unacknowledged `assignment_accepted` frame.
    async fn accept_offered_assignment(
        listener: &tokio::net::TcpListener,
        offer: Message,
    ) -> (FixtureSocket, serde_json::Value) {
        let socket = welcome_assignment_socket(listener).await;
        prepare_offered_assignment(socket, offer).await
    }

    async fn welcome_assignment_socket(listener: &tokio::net::TcpListener) -> FixtureSocket {
        let mut socket = accept_opened_fixture_socket(listener).await;
        socket.send(welcome()).await.expect("send welcome");
        socket
            .send(observation_acknowledgement(
                "rmsg_00000000000000000000000002",
                1,
            ))
            .await
            .expect("acknowledge opening hello");
        socket
    }

    async fn prepare_offered_assignment(
        mut socket: FixtureSocket,
        offer: Message,
    ) -> (FixtureSocket, serde_json::Value) {
        socket.send(offer).await.expect("send assignment offer");
        let effect = effect_acknowledgement(&mut socket).await;
        acknowledge_runner_frame(&mut socket, &effect, "acknowledge offer receipt").await;
        let prepare_acknowledgement = begin_assignment_preparation(&mut socket).await;
        acknowledge_runner_frame(
            &mut socket,
            &prepare_acknowledgement,
            "acknowledge assignment prepare effect",
        )
        .await;
        let accepted =
            next_semantic_assignment_frame(&mut socket, "assignment_accepted", true).await;
        (socket, accepted)
    }

    fn spawn_fixture_service(
        endpoint: &str,
        sleeper: Arc<dyn Sleeper>,
    ) -> (
        tokio::task::JoinHandle<Result<ServiceEnd, ServiceError>>,
        TestCapture,
        ControlledShutdownTrigger,
    ) {
        let fixture =
            ConfigFixture::new(endpoint, test_credential(), true).expect("configure gateway");
        spawn_configured_service_with_source(
            fixture.cloned_config(),
            sleeper,
            Some(unavailable_source_broker()),
            Some(fixture),
        )
    }

    fn spawn_configured_service(
        config: Config,
        sleeper: Arc<dyn Sleeper>,
    ) -> (
        tokio::task::JoinHandle<Result<ServiceEnd, ServiceError>>,
        TestCapture,
        ControlledShutdownTrigger,
    ) {
        spawn_configured_service_with_source(
            config,
            sleeper,
            Some(unavailable_source_broker()),
            None,
        )
    }

    fn spawn_configured_service_with_source(
        config: Config,
        sleeper: Arc<dyn Sleeper>,
        source_broker: Option<Arc<dyn SourceCredentialBroker>>,
        config_fixture: Option<ConfigFixture>,
    ) -> (
        tokio::task::JoinHandle<Result<ServiceEnd, ServiceError>>,
        TestCapture,
        ControlledShutdownTrigger,
    ) {
        spawn_service_with_join_key(
            config,
            sleeper,
            source_broker,
            config_fixture,
            JoinKeyMode::None,
        )
    }

    fn spawn_service_with_join_key(
        config: Config,
        sleeper: Arc<dyn Sleeper>,
        source_broker: Option<Arc<dyn SourceCredentialBroker>>,
        config_fixture: Option<ConfigFixture>,
        join_key: JoinKeyMode,
    ) -> (
        tokio::task::JoinHandle<Result<ServiceEnd, ServiceError>>,
        TestCapture,
        ControlledShutdownTrigger,
    ) {
        let (recorder, capture) = test_recorder("rbt_00000000000000000000000001");
        let (shutdown, shutdown_trigger) = controlled_shutdown();
        let service = tokio::spawn(async move {
            let _config_fixture = config_fixture;
            run_until_cancelled_with_dependencies(
                config,
                deterministic_frame_source(),
                sleeper,
                recorder,
                source_broker,
                shutdown,
                join_key,
            )
            .await
        });
        (service, capture, shutdown_trigger)
    }

    struct AcceptedAssignmentService {
        _temporary: tempfile::TempDir,
        task: tokio::task::JoinHandle<Result<ServiceEnd, ServiceError>>,
        shutdown_trigger: ControlledShutdownTrigger,
        _sleep_requests: tokio::sync::mpsc::UnboundedReceiver<(Duration, SleepRelease)>,
    }

    fn spawn_accepted_assignment_service(
        fixture: AcceptedAssignmentFixture,
    ) -> AcceptedAssignmentService {
        let (sleeper, sleep_requests) = controlled_sleeper();
        let AcceptedAssignmentFixture {
            temporary,
            config,
            source_broker,
            offer: _,
        } = fixture;
        let (task, _capture, shutdown_trigger) =
            spawn_configured_service_with_source(config, sleeper, Some(source_broker), None);
        AcceptedAssignmentService {
            _temporary: temporary,
            task,
            shutdown_trigger,
            _sleep_requests: sleep_requests,
        }
    }

    async fn begin_accepted_assignment_shutdown(
        fixture: AcceptedAssignmentFixture,
        accepted_received: tokio::sync::oneshot::Receiver<()>,
    ) -> AcceptedAssignmentService {
        let service = spawn_accepted_assignment_service(fixture);
        with_watchdog(accepted_received)
            .await
            .expect("runner did not accept assignment")
            .expect("fixture dropped acceptance signal");
        service.shutdown_trigger.notify_one();
        service
    }

    async fn backoff_request(
        requests: &mut tokio::sync::mpsc::UnboundedReceiver<(Duration, SleepRelease)>,
    ) -> (Duration, SleepRelease) {
        loop {
            let (delay, release) = with_watchdog(requests.recv())
                .await
                .expect("runner did not request backoff")
                .expect("controlled sleeper closed");
            if delay < Duration::from_secs(1) {
                return (delay, release);
            }
            drop(release);
        }
    }

    async fn abort_service(service: tokio::task::JoinHandle<Result<ServiceEnd, ServiceError>>) {
        service.abort();
        assert!(
            service
                .await
                .expect_err("service task should be aborted")
                .is_cancelled()
        );
    }

    fn assert_attempt_event_pair(
        capture: &TestCapture,
        effect_outcome: &str,
        effect_error_type: Option<&str>,
        expected_effect_count: usize,
        expected_event_count: usize,
    ) -> serde_json::Map<String, serde_json::Value> {
        // Assignment notifications can start a reconnect before the test aborts
        // the service. Its connection event belongs to a later attempt, not the
        // effect/connection pair under test. Keep exact counts for the first
        // attempt and all effect events so duplicate timeout records still fail.
        let events: Vec<_> = capture
            .events()
            .into_iter()
            .filter(|event| {
                event["event.name"] != "runner.gateway_connection"
                    || event["um.connection.attempt"] == 1
            })
            .collect();
        assert_eq!(events.len(), expected_event_count);
        let effect = events
            .iter()
            .find(|event| {
                event["event.name"] == "runner.effect_acknowledgement"
                    && event["um.outcome"] == effect_outcome
            })
            .expect("captured effect acknowledgement outcome should exist");
        assert_eq!(
            effect.get("error.type").and_then(serde_json::Value::as_str),
            effect_error_type,
        );
        assert_eq!(
            capture.span_count("runner.effect_acknowledgement"),
            expected_effect_count
        );
        events
            .into_iter()
            .find(|event| event["event.name"] == "runner.gateway_connection")
            .expect("captured gateway connection should exist")
    }

    #[tokio::test]
    async fn exits_when_the_gateway_closes_with_policy_violation() {
        let (listener, endpoint) = fixture_listener().await;
        let (headers_sent, headers_received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, headers) = accept_fixture_socket_with_headers(&listener).await;
            headers_sent
                .send(headers)
                .expect("send captured upgrade headers");
            expect_opening_hello(&mut socket).await;
            socket
                .send(Message::Close(Some(CloseFrame {
                    code: CloseCode::Policy,
                    reason: "PEER-CLOSE-REASON-MUST-NOT-LEAK".into(),
                })))
                .await
                .expect("send policy close");
            while let Some(Ok(_)) = socket.next().await {}
        });

        let endpoint = format!("{endpoint}?secret=URL-QUERY-MUST-NOT-LEAK");
        let config =
            ConfigFixture::new(&endpoint, test_credential(), true).expect("configure gateway");
        let (sleeper, _sleep_requests) = controlled_sleeper();
        let (recorder, capture) = test_recorder("rbt_00000000000000000000000001");
        let (shutdown, _shutdown_trigger) = controlled_shutdown();
        let error = with_watchdog(run_until_cancelled_with_dependencies(
            config.cloned_config(),
            deterministic_frame_source(),
            sleeper,
            recorder,
            None,
            shutdown,
            JoinKeyMode::None,
        ))
        .await
        .expect("runner retried a terminal policy close")
        .expect_err("policy close did not stop the service");
        let ServiceError::Connection(connection_error) = error else {
            panic!("policy close changed service error variant");
        };
        assert_eq!(
            connection_error.connection_cause(),
            ConnectionCause::GatewayPolicyViolation
        );
        assert_eq!(connection_error.kind(), FailureKind::TerminalProtocol);
        server.await.expect("fixture server failed");
        let headers = headers_received
            .await
            .expect("receive captured upgrade headers");

        let events: Vec<_> = capture
            .events()
            .into_iter()
            .filter(|event| event["event.name"] == "runner.gateway_connection")
            .collect();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event["event.name"], "runner.gateway_connection");
        assert_eq!(event["um.connection.attempt"], 1);
        assert_eq!(event["um.connection.failure_kind"], "terminal_protocol");
        assert_eq!(event["error.type"], "gateway_policy_violation");
        assert_eq!(event["um.outcome"], "failure");
        assert_eq!(event["um.cloud.text_frames_received"], 0);
        assert_eq!(event["um.runner.text_frames_sent"], 1);
        assert!(event.get("um.connection.backoff_ms").is_none());
        let encoded = serde_json::to_string(event).expect("encode terminal connection event");
        for sentinel in [
            "URL-QUERY-MUST-NOT-LEAK",
            "PEER-CLOSE-REASON-MUST-NOT-LEAK",
            "abcdefghijklmnopqrstuvwxyzABCDEFG-012345678",
        ] {
            assert!(!encoded.contains(sentinel));
        }
        assert_eq!(capture.span_count("runner.gateway_connection"), 1);
        let expected_traceparent = format!(
            "00-{}-{}-01",
            event["trace_id"].as_str().expect("connection trace ID"),
            event["span_id"].as_str().expect("connection span ID"),
        );
        assert_eq!(
            headers
                .get("traceparent")
                .and_then(|value| value.to_str().ok()),
            Some(expected_traceparent.as_str())
        );
        assert!(headers.get("tracestate").is_none());
        assert!(headers.get("baggage").is_none());
    }

    async fn records_through_one_policy_closed_connection(
        configure: impl FnOnce(Config) -> Config,
    ) -> Vec<serde_json::Map<String, serde_json::Value>> {
        let (listener, endpoint) = fixture_listener().await;
        let server = tokio::spawn(async move {
            let mut socket = accept_fixture_socket(&listener).await;
            expect_opening_hello(&mut socket).await;
            socket
                .send(Message::Close(Some(CloseFrame {
                    code: CloseCode::Policy,
                    reason: "".into(),
                })))
                .await
                .expect("send policy close");
            while let Some(Ok(_)) = socket.next().await {}
        });
        let fixture =
            ConfigFixture::new(&endpoint, test_credential(), true).expect("configure gateway");
        let (sleeper, _sleep_requests) = controlled_sleeper();
        let (recorder, capture) = test_recorder("rbt_00000000000000000000000001");
        let (shutdown, _shutdown_trigger) = controlled_shutdown();
        with_watchdog(run_until_cancelled_with_dependencies(
            configure(fixture.cloned_config()),
            deterministic_frame_source(),
            sleeper,
            recorder,
            None,
            shutdown,
            JoinKeyMode::None,
        ))
        .await
        .expect("runner retried a terminal policy close")
        .expect_err("policy close did not stop the service");
        server.await.expect("fixture server failed");
        capture.records()
    }

    fn record_names(records: &[serde_json::Map<String, serde_json::Value>]) -> Vec<&str> {
        records
            .iter()
            .filter_map(|record| record["event.name"].as_str())
            .collect()
    }

    #[tokio::test]
    async fn startup_records_harness_untested_once_per_untested_installation_before_connecting() {
        let records = records_through_one_policy_closed_connection(|config| {
            config
                .with_pi_installation(ValidatedPiInstallation::fixture_with_version(
                    PathBuf::from("/validated/pi"),
                    (1, 4, 0),
                    "1.4.0",
                ))
                .with_claude_code_installation(ValidatedClaudeCodeInstallation::fixture(
                    PathBuf::from("/validated/claude"),
                ))
        })
        .await;

        let names = record_names(&records);
        let untested: Vec<_> = records
            .iter()
            .filter(|record| record["event.name"] == "runner.harness_untested")
            .collect();
        assert_eq!(untested.len(), 1);
        let record = untested[0];
        assert_eq!(record["um.harness.profile"], "PiJsonV1");
        assert_eq!(record["um.harness.version"], "1.4.0");
        assert_eq!(record["um.harness.qualification_version"], "1.3.0");
        assert_eq!(record["um.main"], false);
        let untested_index = names
            .iter()
            .position(|name| *name == "runner.harness_untested")
            .expect("untested record position");
        let connection_index = names
            .iter()
            .position(|name| *name == "runner.gateway_connection")
            .expect("gateway connection record");
        assert!(untested_index < connection_index);
    }

    #[tokio::test]
    async fn startup_records_no_harness_untested_for_qualified_installations() {
        let records = records_through_one_policy_closed_connection(|config| {
            config
                .with_pi_installation(ValidatedPiInstallation::fixture(PathBuf::from(
                    "/validated/pi",
                )))
                .with_claude_code_installation(ValidatedClaudeCodeInstallation::fixture(
                    PathBuf::from("/validated/claude"),
                ))
                .with_codex_installation(ValidatedCodexInstallation::fixture(PathBuf::from(
                    "/validated/codex",
                )))
        })
        .await;

        let names = record_names(&records);
        assert!(names.contains(&"runner.gateway_connection"));
        assert!(!names.contains(&"runner.harness_untested"));
    }

    // The hello members through which a runner advertised recovery.
    fn assert_hello_advertises_no_recovery(hello: &serde_json::Value) {
        assert_eq!(hello["type"], "hello");
        let payload = hello["payload"].as_object().expect("hello payload");
        assert!(!payload.contains_key("workspaceRecoveryVersion"));
        assert!(!payload.contains_key("workspaceRecoveryRoot"));
    }

    #[tokio::test]
    async fn a_start_over_a_work_root_advertises_and_reports_no_recovery() {
        let (listener, endpoint) = fixture_listener().await;
        let (disconnected, observed_disconnect) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut socket = accept_fixture_socket(&listener).await;
            let Some(Ok(Message::Text(first))) = socket.next().await else {
                panic!("missing opening hello")
            };
            let first: serde_json::Value = serde_json::from_str(&first).unwrap();
            assert_hello_advertises_no_recovery(&first);
            socket.send(welcome()).await.unwrap();
            socket
                .send(observation_acknowledgement(
                    first["messageId"].as_str().unwrap(),
                    first["sequence"].as_u64().unwrap(),
                ))
                .await
                .unwrap();
            // Pong is a causal barrier: the runner sent nothing between the
            // acknowledged hello and this ping, so no inventory came first.
            socket
                .send(Message::Ping(b"no-inventory".to_vec().into()))
                .await
                .unwrap();
            let Some(Ok(Message::Pong(payload))) = socket.next().await else {
                panic!("runner sent a frame before answering the barrier")
            };
            assert_eq!(payload.as_ref(), b"no-inventory");
            drop(socket);
            disconnected.send(()).unwrap();

            let mut socket = accept_fixture_socket(&listener).await;
            let Some(Ok(Message::Text(second))) = socket.next().await else {
                panic!("missing reconnect hello")
            };
            let second: serde_json::Value = serde_json::from_str(&second).unwrap();
            assert_hello_advertises_no_recovery(&second);
        });
        let (sleeper, mut sleep_requests) = controlled_sleeper();
        let (service, _capture, _shutdown) = spawn_fixture_service(&endpoint, sleeper);
        with_watchdog(observed_disconnect).await.unwrap().unwrap();
        backoff_request(&mut sleep_requests).await.1.release();
        let result = with_watchdog(server).await;
        abort_service(service).await;
        result.unwrap().unwrap();
    }

    const REPLACED_RUNNER: &str = "rnr_01k0z6r1w8f4jy2m7q9v3x5abe";
    const RECOVERY_ROOT_RECORD: &str = ".useful-recovery-root-v1.json";

    // Runs the service through the one handshake the listener offers, stops it,
    // and answers the service's records.
    async fn serve_one_handshake(
        fixture: &RotationFixture,
        listener: tokio::net::TcpListener,
    ) -> TestCapture {
        let socket_path = fixture.config.control_socket_path().unwrap().to_owned();
        let (hello_sent, hello_received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut socket = accept_fixture_socket(&listener).await;
            let Some(Ok(Message::Text(hello))) = socket.next().await else {
                panic!("missing opening hello")
            };
            let hello: serde_json::Value = serde_json::from_str(&hello).unwrap();
            socket.send(welcome()).await.unwrap();
            socket
                .send(observation_acknowledgement(
                    hello["messageId"].as_str().unwrap(),
                    hello["sequence"].as_u64().unwrap(),
                ))
                .await
                .unwrap();
            hello_sent.send(()).unwrap();
            while let Some(Ok(_)) = socket.next().await {}
        });
        let (service, capture, shutdown_trigger) =
            spawn_configured_service(fixture.config.clone(), fixture_sleeper());
        // The runner binds its control socket before it sends its hello.
        with_watchdog(hello_received).await.unwrap().unwrap();
        wait_for_connection_state(&socket_path, ConnectionState::Connected).await;
        shutdown_trigger.notify_one();
        with_watchdog(service).await.unwrap().unwrap().unwrap();
        with_watchdog(server).await.unwrap().unwrap();
        capture
    }

    #[tokio::test]
    async fn a_start_neither_writes_nor_reads_a_recovery_root_record() {
        let replaced = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "runnerId": REPLACED_RUNNER
        }))
        .unwrap();
        for record in [None, Some(replaced.as_slice()), Some(&b"not json"[..])] {
            let (listener, endpoint) = fixture_listener().await;
            let fixture = RotationFixture::without_pending(&endpoint);
            let path = fixture
                .config
                .assignment()
                .work_root()
                .join(RECOVERY_ROOT_RECORD);
            if let Some(record) = record {
                fs::write(&path, record).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }

            let capture = serve_one_handshake(&fixture, listener).await;

            match record {
                None => assert_eq!(
                    fs::symlink_metadata(&path).unwrap_err().kind(),
                    io::ErrorKind::NotFound
                ),
                Some(record) => assert_eq!(fs::read(&path).unwrap(), record),
            }
            assert!(
                capture
                    .records()
                    .iter()
                    .all(|record| record["event.name"] != "runner.workspace_recovery")
            );
        }
    }

    #[tokio::test]
    async fn an_ordinary_assignment_journals_to_v1_and_writes_no_recovery_record() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        let (source_broker, offer) = fixture.accepted_source();
        let (accepted_sent, accepted_received) = tokio::sync::oneshot::channel();
        let (close_sent, close) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (socket, accepted) = accept_offered_assignment(&listener, offer).await;
            accepted_sent.send(accepted).unwrap();
            let _ = close.await;
            drop(socket);
        });
        let (service, _capture, _shutdown_trigger) = spawn_configured_service_with_source(
            fixture.config.clone(),
            fixture_sleeper(),
            Some(source_broker),
            None,
        );
        let accepted = with_watchdog(accepted_received).await.unwrap().unwrap();

        let work_root = fixture.config.assignment().work_root();
        let boots: Vec<_> = fs::read_dir(work_root)
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("rbt_"))
            .collect();
        assert_eq!(boots.len(), 1);
        let private = boots[0]
            .path()
            .join(accepted["payload"]["assignmentId"].as_str().unwrap())
            .join("private");
        assert!(private.join("process-guards-v1.json").is_file());
        for absent in [
            private.join("process-guards-v2.json"),
            private.join(".useful-recovery-manifest-v1.json"),
            work_root.join(RECOVERY_ROOT_RECORD),
        ] {
            assert_eq!(
                fs::symlink_metadata(&absent).unwrap_err().kind(),
                io::ErrorKind::NotFound,
                "{}",
                absent.display()
            );
        }
        close_sent.send(()).unwrap();
        abort_service(service).await;
        server.abort();
    }

    #[tokio::test]
    async fn projects_resolved_build_version_across_initial_and_reconnect_telemetry() {
        let (listener, endpoint) = fixture_listener().await;
        let (failure_sent, failure_received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut socket = accept_fixture_socket(&listener).await;
            let Some(Ok(Message::Text(first_hello))) = socket.next().await else {
                panic!("fixture did not receive first opening hello");
            };
            let first_hello: serde_json::Value =
                serde_json::from_str(&first_hello).expect("decode first opening hello");
            let first_message_id = first_hello["messageId"]
                .as_str()
                .expect("first opening message ID")
                .to_owned();
            assert_eq!(first_message_id, "rmsg_00000000000000000000000002");
            assert_eq!(first_hello["bootId"], "rbt_00000000000000000000000001");
            assert_eq!(first_hello["sentAt"], "2026-07-23T00:00:00Z");
            assert_eq!(
                first_hello["payload"]["runnerVersion"],
                crate::telemetry::TEST_SERVICE_VERSION
            );
            let first_sequence = first_hello["sequence"]
                .as_u64()
                .expect("first opening sequence");
            assert_eq!(first_sequence, 1);

            socket.send(welcome()).await.expect("send welcome");
            socket
                .send(observation_acknowledgement(
                    &first_message_id,
                    first_sequence,
                ))
                .await
                .expect("send opening acknowledgement");
            socket
                .send(assignment_offer())
                .await
                .expect("send assignment offer");
            let effect_acknowledgement = effect_acknowledgement(&mut socket).await;
            let effect_sequence = effect_acknowledgement["sequence"].as_u64().unwrap();
            assert!(effect_sequence >= 2);
            let Some(Ok(Message::Text(preparing))) = socket.next().await else {
                panic!("fixture did not receive assignment preparation acknowledgement");
            };
            let preparing: serde_json::Value =
                serde_json::from_str(&preparing).expect("decode assignment preparation");
            assert_eq!(preparing["type"], "assignment_preparing");
            assert_eq!(preparing["sequence"], effect_sequence + 1);

            failure_sent
                .send(())
                .expect("report first connection failure");
            drop(socket);

            let mut socket = accept_fixture_socket(&listener).await;
            let Some(Ok(Message::Text(second_hello))) = socket.next().await else {
                panic!("fixture did not receive replacement opening hello");
            };
            let second_hello: serde_json::Value =
                serde_json::from_str(&second_hello).expect("decode replacement opening hello");
            assert!(
                second_hello["messageId"]
                    .as_str()
                    .unwrap()
                    .starts_with("rmsg_")
            );
            assert_ne!(second_hello["messageId"], first_message_id);
            assert_eq!(second_hello["sequence"], effect_sequence + 2);
            assert_eq!(second_hello["sentAt"], "2026-07-23T00:00:00Z");
            assert_eq!(
                second_hello["payload"]["runnerVersion"],
                crate::telemetry::TEST_SERVICE_VERSION
            );
        });

        let (sleeper, mut sleep_requests) = controlled_sleeper();
        let (service, capture, _shutdown_trigger) = spawn_fixture_service(&endpoint, sleeper);
        with_watchdog(failure_received)
            .await
            .expect("first connection did not reach its failure")
            .expect("fixture server dropped failure signal");
        let (backoff_delay, release_sleep) = backoff_request(&mut sleep_requests).await;
        let records = capture.records();
        assert!(records.iter().all(|record| {
            record["service.version"] == crate::telemetry::TEST_SERVICE_VERSION
                && record
                    .get("um.runner.version")
                    .is_none_or(|version| version == crate::telemetry::TEST_SERVICE_VERSION)
        }));
        let events = capture.events();
        let connection_events: Vec<_> = events
            .iter()
            .filter(|event| event["event.name"] == "runner.gateway_connection")
            .collect();
        assert_eq!(connection_events.len(), 1);
        let event = connection_events[0];
        assert_eq!(event["um.connection.failure_kind"], "retryable");
        assert_eq!(
            event["um.runner.version"],
            crate::telemetry::TEST_SERVICE_VERSION
        );
        assert_eq!(event["error.type"], "read_gateway_frame");
        assert_eq!(event["um.outcome"], "disconnected");
        assert_eq!(
            event["um.connection.backoff_ms"],
            i64::try_from(backoff_delay.as_millis()).expect("fixture backoff fits i64")
        );
        assert_eq!(event["um.runner.opening_acknowledged"], true);
        assert_eq!(event["um.runner.handshake_completed"], true);
        assert_eq!(event["um.cloud.text_frames_received"], 3);
        assert_eq!(event["um.runner.text_frames_sent"], 3);
        assert_eq!(event["um.runner.effects_received"], 1);
        assert_eq!(event["um.runner.effect_acknowledgements_confirmed"], 0);
        assert_eq!(
            events
                .iter()
                .filter(|event| event["event.name"] == "runner.effect_acknowledgement")
                .count(),
            1
        );
        assert_eq!(capture.span_count("runner.gateway_connection"), 1);
        release_sleep.release();
        let server_result = with_watchdog(server).await;
        abort_service(service).await;
        server_result
            .expect("runner did not reconnect")
            .expect("fixture server failed");
    }

    #[tokio::test]
    async fn records_retryable_connection_failure_once_with_backoff() {
        for (error_type, outcome) in [
            ("gateway_closed_connection", "disconnected"),
            ("connect_timeout", "timeout"),
        ] {
            let (listener, endpoint) = fixture_listener().await;
            let server = if error_type == "connect_timeout" {
                tokio::spawn(async move {
                    let (_stream, _) = listener.accept().await.expect("accept fixture connection");
                    std::future::pending::<()>().await;
                })
            } else {
                tokio::spawn(async move {
                    let mut socket = accept_fixture_socket(&listener).await;
                    expect_opening_hello(&mut socket).await;
                    socket
                        .send(Message::Close(Some(CloseFrame {
                            code: CloseCode::Normal,
                            reason: "normal fixture close".into(),
                        })))
                        .await
                        .expect("send normal close");
                    while let Some(Ok(_)) = socket.next().await {}
                })
            };

            let (sleeper, mut sleep_requests) = controlled_sleeper();
            let (service, capture, _shutdown_trigger) = spawn_fixture_service(&endpoint, sleeper);
            if error_type == "connect_timeout" {
                sleep_request(&mut sleep_requests, Duration::from_secs(10))
                    .await
                    .release();
            }
            let (_delay, release_backoff) = backoff_request(&mut sleep_requests).await;

            let events: Vec<_> = capture
                .events()
                .into_iter()
                .filter(|event| event["event.name"] == "runner.gateway_connection")
                .collect();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["event.name"], "runner.gateway_connection");
            assert_eq!(events[0]["error.type"], error_type);
            assert_eq!(events[0]["um.connection.failure_kind"], "retryable");
            assert_eq!(events[0]["um.outcome"], outcome);
            assert!(events[0].get("um.connection.backoff_ms").is_some());
            assert_eq!(capture.span_count("runner.gateway_connection"), 1);

            abort_service(service).await;
            drop(release_backoff);
            if error_type == "connect_timeout" {
                server.abort();
                assert!(
                    server
                        .await
                        .expect_err("fixture server should be aborted")
                        .is_cancelled()
                );
            } else {
                with_watchdog(server)
                    .await
                    .expect("fixture server did not close")
                    .expect("fixture server failed");
            }
        }
    }

    #[tokio::test]
    async fn classifies_pending_effect_event_timeout() {
        let (listener, endpoint) = fixture_listener().await;
        let (sleeper, mut sleep_requests) = controlled_sleeper();
        let server = tokio::spawn(async move {
            let mut socket = accept_opened_fixture_socket(&listener).await;

            let welcome_timer = sleep_request(&mut sleep_requests, Duration::from_secs(5)).await;
            socket.send(welcome()).await.expect("send welcome");
            let first_liveness_timer =
                sleep_request(&mut sleep_requests, Duration::from_secs(2)).await;
            drop(welcome_timer);
            socket
                .send(observation_acknowledgement(
                    "rmsg_00000000000000000000000002",
                    1,
                ))
                .await
                .expect("send opening acknowledgement");
            let second_liveness_timer =
                sleep_request(&mut sleep_requests, Duration::from_secs(2)).await;
            drop(first_liveness_timer);
            socket
                .send(assignment_offer())
                .await
                .expect("send assignment offer");
            let _acknowledgement = effect_acknowledgement(&mut socket).await;
            let pending_liveness_timer =
                sleep_request(&mut sleep_requests, Duration::from_secs(2)).await;
            drop(second_liveness_timer);
            pending_liveness_timer.release();

            let close = expect_close_frame(&mut socket).await;
            assert_eq!(close.code, CloseCode::Away);
            sleep_requests
        });

        let (service, capture, _shutdown_trigger) = spawn_fixture_service(&endpoint, sleeper);
        let sleep_requests = with_watchdog(server)
            .await
            .expect("runner did not close after the pending acknowledgement timed out")
            .expect("fixture server failed");

        // The connection event is finished before the runner chooses whether to
        // sleep for backoff or immediately handle an assignment notification.
        // Observe that event directly; backoff is not guaranteed in this path.
        with_watchdog(capture.wait_for_event("runner.gateway_connection"))
            .await
            .expect("runner did not record the timed-out connection");
        abort_service(service).await;

        let connection =
            assert_attempt_event_pair(&capture, "timeout", Some("gateway_liveness_timeout"), 1, 3);
        // Aborting the service drops the offered run unprepared.
        assert_eq!(capture.event("runner.run")["um.run.result"], "aborted");
        assert_eq!(connection["um.outcome"], "timeout");
        assert_eq!(connection["error.type"], "gateway_liveness_timeout");

        drop(sleep_requests);
    }

    async fn ping_serving_runner(socket: &mut FixtureSocket, byte: u8) {
        let ping = vec![byte];
        socket
            .send(Message::Ping(ping.clone().into()))
            .await
            .unwrap();
        let Some(Ok(Message::Pong(pong))) = socket.next().await else {
            panic!("expected a pong on the open connection");
        };
        assert_eq!(pong.as_ref(), ping);
    }

    #[tokio::test]
    async fn idle_stop_arms_after_welcome_and_expires_despite_gateway_traffic() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = ConfigFixture::new(&endpoint, test_credential(), true).unwrap();
        let timeout = Duration::from_secs(17);
        let config = fixture.cloned_config().with_idle_timeout(Some(timeout));
        let (sleeper, mut requests) = controlled_sleeper();
        let (service, capture, _shutdown) = spawn_configured_service(config, sleeper);
        with_watchdog(async {
            let mut socket = accept_fixture_socket(&listener).await;
            expect_opening_hello(&mut socket).await;
            while let Ok((duration, _)) = requests.try_recv() {
                assert_ne!(duration, timeout);
            }
            socket.send(welcome()).await.unwrap();
            socket
                .send(observation_acknowledgement(
                    "rmsg_00000000000000000000000002",
                    1,
                ))
                .await
                .unwrap();
            let release = sleep_request(&mut requests, timeout).await;
            for byte in [1, 2, 3] {
                ping_serving_runner(&mut socket, byte).await;
            }
            while let Ok((duration, _)) = requests.try_recv() {
                assert_ne!(duration, timeout);
            }
            release.release();
            assert_eq!(service.await.unwrap().unwrap(), ServiceEnd::Stopped);
        })
        .await
        .unwrap();
        let timeouts: Vec<_> = capture
            .records()
            .into_iter()
            .filter(|r| r["event.name"] == "runner.idle_timeout")
            .collect();
        assert_eq!(timeouts.len(), 1);
        assert_eq!(
            timeouts[0]["um.runner.idle_timeout_seconds"],
            timeout.as_secs()
        );
    }

    #[tokio::test]
    async fn idle_stop_expiry_spares_an_accepted_assignment_until_operator_shutdown() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = accepted_assignment_config(&endpoint);
        let timeout = Duration::from_secs(17);
        let (sleeper, mut requests) = controlled_sleeper();
        let (service, capture, stop) = spawn_configured_service_with_source(
            fixture.config.with_idle_timeout(Some(timeout)),
            sleeper,
            Some(fixture.source_broker),
            None,
        );
        with_watchdog(async {
            let socket = welcome_assignment_socket(&listener).await;
            let expiry = sleep_request(&mut requests, timeout).await;
            let (mut socket, accepted) = prepare_offered_assignment(socket, fixture.offer).await;
            acknowledge_runner_frame(&mut socket, &accepted, "acknowledge acceptance").await;
            expiry.release();
            ping_serving_runner(&mut socket, 7).await;
            stop.notify_one();
            let interrupted =
                next_semantic_assignment_frame(&mut socket, "assignment_interrupted", true).await;
            assert_eq!(interrupted["payload"]["reason"], "graceful_shutdown");
            socket
                .send(terminal_observation_acknowledgement(
                    interrupted["messageId"].as_str().unwrap(),
                    interrupted["sequence"].as_u64().unwrap(),
                ))
                .await
                .unwrap();
            assert_eq!(service.await.unwrap().unwrap(), ServiceEnd::Stopped);
        })
        .await
        .unwrap();
        assert!(
            capture
                .records()
                .iter()
                .all(|r| r["event.name"] != "runner.idle_timeout")
        );
    }

    // The interval an assignment outlived is gone: the runner stops only for one that
    // begins once the assignment has ended.
    #[tokio::test]
    async fn idle_stop_expires_after_a_new_interval_once_its_assignment_ends() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = accepted_assignment_config(&endpoint);
        let timeout = Duration::from_secs(17);
        let (sleeper, mut requests) = controlled_sleeper();
        let (mut service, capture, _stop) = spawn_configured_service_with_source(
            fixture.config.with_idle_timeout(Some(timeout)),
            sleeper,
            Some(fixture.source_broker),
            None,
        );
        with_watchdog(async {
            let socket = welcome_assignment_socket(&listener).await;
            let outlived = sleep_request(&mut requests, timeout).await;
            let (mut socket, accepted) = prepare_offered_assignment(socket, fixture.offer).await;
            acknowledge_runner_frame(&mut socket, &accepted, "acknowledge acceptance").await;
            outlived.release();
            ping_serving_runner(&mut socket, 7).await;
            socket
                .send(assignment_release_frame(
                    &accepted["payload"]["assignmentId"],
                ))
                .await
                .unwrap();
            // An interval that ends before the runner has sent what the release left it to
            // send is refused, so every one the runner asks for is let to elapse. The
            // service's end closes the sleeper, so it is read first.
            let end = loop {
                tokio::select! {
                    biased;
                    end = &mut service => break end,
                    interval = sleep_request(&mut requests, timeout) => interval.release(),
                    Some(Ok(Message::Text(frame))) = socket.next() => {
                        let frame: serde_json::Value = serde_json::from_str(&frame).unwrap();
                        if frame["messageId"].is_string() {
                            acknowledge_runner_frame(&mut socket, &frame, "acknowledge frame")
                                .await;
                        }
                    }
                }
            };
            assert_eq!(end.unwrap().unwrap(), ServiceEnd::Stopped);
        })
        .await
        .unwrap();
        let timeouts = capture
            .records()
            .into_iter()
            .filter(|r| r["event.name"] == "runner.idle_timeout")
            .count();
        assert_eq!(timeouts, 1);
    }

    fn assignment_release_frame(assignment_id: &serde_json::Value) -> Message {
        cloud_frame(
            "assignment_release",
            "cmsg_01k0z6r1w8f4jy2m7q9v3x5abt",
            serde_json::json!({
                "effectId": "eff_01k0z6r1w8f4jy2m7q9v3x5abt",
                "assignmentId": assignment_id,
                "runId": "run_01k0z6r1w8f4jy2m7q9v3x5abj",
                "attemptId": "atm_01k0z6r1w8f4jy2m7q9v3x5abc",
                "reason": "stale_or_invalid_acceptance",
            }),
        )
    }

    async fn send_registration_mode(socket: &mut FixtureSocket, mode: RegistrationMode) {
        socket
            .send(cloud_frame(
                "registration_mode",
                match mode {
                    RegistrationMode::Enabled => "cmsg_01k0z6r1w8f4jy2m7q9v3x5abv",
                    RegistrationMode::Draining => "cmsg_01k0z6r1w8f4jy2m7q9v3x5abw",
                },
                serde_json::json!({"mode": mode}),
            ))
            .await
            .unwrap();
    }

    async fn welcome_with_mode(
        listener: &tokio::net::TcpListener,
        mode: RegistrationMode,
    ) -> FixtureSocket {
        let mut socket = accept_opened_fixture_socket(listener).await;
        socket
            .send(welcome_with_registration_mode(mode))
            .await
            .unwrap();
        socket
            .send(observation_acknowledgement(
                "rmsg_00000000000000000000000002",
                1,
            ))
            .await
            .unwrap();
        socket
    }

    fn drain_records(
        capture: &TestCapture,
        event: &str,
    ) -> Vec<serde_json::Map<String, serde_json::Value>> {
        capture
            .records()
            .into_iter()
            .filter(|r| r["event.name"] == event)
            .collect()
    }

    #[tokio::test]
    async fn drain_stop_exits_once_an_empty_enabled_service_learns_it_is_draining() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = ConfigFixture::new(&endpoint, test_credential(), true).unwrap();
        let (sleeper, _requests) = controlled_sleeper();
        let config = fixture
            .cloned_config()
            .with_drain_exit(Some(DrainExit { deadline: None }));
        let (service, capture, _stop) = spawn_configured_service(config, sleeper);
        with_watchdog(async {
            let mut socket = welcome_with_mode(&listener, RegistrationMode::Enabled).await;
            ping_serving_runner(&mut socket, 1).await;
            send_registration_mode(&mut socket, RegistrationMode::Draining).await;
            assert_eq!(service.await.unwrap().unwrap(), ServiceEnd::Stopped);
        })
        .await
        .unwrap();
        assert_eq!(drain_records(&capture, "runner.drained").len(), 1);
    }

    #[tokio::test]
    async fn drain_stop_is_opt_in_even_when_the_welcome_names_draining() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = ConfigFixture::new(&endpoint, test_credential(), true).unwrap();
        let (sleeper, _requests) = controlled_sleeper();
        let (service, capture, stop) = spawn_configured_service(fixture.cloned_config(), sleeper);
        with_watchdog(async {
            let mut socket = welcome_with_mode(&listener, RegistrationMode::Draining).await;
            ping_serving_runner(&mut socket, 1).await;
            stop.notify_one();
            assert_eq!(service.await.unwrap().unwrap(), ServiceEnd::Stopped);
        })
        .await
        .unwrap();
        assert!(drain_records(&capture, "runner.drained").is_empty());
    }

    struct HeldDrain {
        _temporary: tempfile::TempDir,
        service: tokio::task::JoinHandle<Result<ServiceEnd, ServiceError>>,
        capture: TestCapture,
        stop: ControlledShutdownTrigger,
        sleeps: tokio::sync::mpsc::UnboundedReceiver<(Duration, SleepRelease)>,
        socket: FixtureSocket,
        accepted: serde_json::Value,
    }

    impl HeldDrain {
        async fn start(deadline: Option<Duration>) -> Self {
            Self::start_with_idle_timeout(deadline, None).await
        }

        async fn start_with_idle_timeout(
            deadline: Option<Duration>,
            idle_timeout: Option<Duration>,
        ) -> Self {
            let (listener, endpoint) = fixture_listener().await;
            let fixture = accepted_assignment_config(&endpoint);
            let (sleeper, sleeps) = controlled_sleeper();
            let (service, capture, stop) = spawn_configured_service_with_source(
                fixture
                    .config
                    .with_drain_exit(Some(DrainExit { deadline }))
                    .with_idle_timeout(idle_timeout),
                sleeper,
                Some(fixture.source_broker),
                None,
            );
            let socket = welcome_assignment_socket(&listener).await;
            let (mut socket, accepted) = prepare_offered_assignment(socket, fixture.offer).await;
            acknowledge_runner_frame(&mut socket, &accepted, "acknowledge acceptance").await;
            send_registration_mode(&mut socket, RegistrationMode::Draining).await;
            ping_serving_runner(&mut socket, 1).await;
            Self {
                _temporary: fixture.temporary,
                service,
                capture,
                stop,
                sleeps,
                socket,
                accepted,
            }
        }

        async fn release_assignment(&mut self) {
            self.socket
                .send(assignment_release_frame(
                    &self.accepted["payload"]["assignmentId"],
                ))
                .await
                .unwrap();
        }

        async fn acknowledge(&mut self, frame: &str) {
            let frame: serde_json::Value = serde_json::from_str(frame).unwrap();
            if frame["messageId"].is_string() {
                acknowledge_runner_frame(&mut self.socket, &frame, "acknowledge frame").await;
            }
        }

        /// Answers the runner until it answers a ping, letting every retry interval the
        /// drain watcher asks for elapse.
        async fn serve_through_ping(&mut self, byte: u8) {
            self.socket
                .send(Message::Ping(vec![byte].into()))
                .await
                .unwrap();
            loop {
                tokio::select! {
                    biased;
                    Some((duration, interval)) = self.sleeps.recv() => {
                        if duration == DRAIN_RETRY_INTERVAL {
                            interval.release();
                        }
                    }
                    message = self.socket.next() => match message {
                        Some(Ok(Message::Pong(_))) => return,
                        Some(Ok(Message::Text(frame))) => self.acknowledge(&frame).await,
                        other => panic!("the runner stopped serving: {other:?}"),
                    },
                }
            }
        }

        async fn expect_interruption(&mut self) -> serde_json::Value {
            let interrupted =
                next_semantic_assignment_frame(&mut self.socket, "assignment_interrupted", true)
                    .await;
            assert_eq!(interrupted["payload"]["reason"], "graceful_shutdown");
            interrupted
        }

        async fn acknowledge_interruption(&mut self, frame: &serde_json::Value) {
            self.socket
                .send(terminal_observation_acknowledgement(
                    frame["messageId"].as_str().unwrap(),
                    frame["sequence"].as_u64().unwrap(),
                ))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn drain_stop_waits_for_the_held_assignment_to_end() {
        with_watchdog(async {
            let mut runner = HeldDrain::start(None).await;
            runner.release_assignment().await;
            let end = loop {
                tokio::select! {
                    biased;
                    end = &mut runner.service => break end,
                    interval = sleep_request(&mut runner.sleeps, DRAIN_RETRY_INTERVAL) => interval.release(),
                    Some(Ok(Message::Text(frame))) = runner.socket.next() => {
                        runner.acknowledge(&frame).await;
                    }
                }
            };
            assert_eq!(end.unwrap().unwrap(), ServiceEnd::Stopped);
            assert_eq!(drain_records(&runner.capture, "runner.drained").len(), 1);
        }).await.unwrap();
    }

    // The idle watcher asks for an interval only once the runner holds nothing, which is
    // when a drained exit would be taken, so its request marks the moment to look.
    #[tokio::test]
    async fn drain_stop_cancels_when_enabled_before_the_release() {
        let idle_timeout = Duration::from_secs(17);
        with_watchdog(async {
            let mut runner = HeldDrain::start_with_idle_timeout(None, Some(idle_timeout)).await;
            send_registration_mode(&mut runner.socket, RegistrationMode::Enabled).await;
            runner.serve_through_ping(2).await;
            // The interval asked for before the assignment was held is not the signal.
            while runner.sleeps.try_recv().is_ok() {}
            runner.release_assignment().await;
            loop {
                tokio::select! {
                    biased;
                    end = &mut runner.service => panic!("the runner exited: {end:?}"),
                    Some((duration, interval)) = runner.sleeps.recv() => {
                        if duration == idle_timeout {
                            break;
                        }
                        if duration == DRAIN_RETRY_INTERVAL {
                            interval.release();
                        }
                    }
                    Some(Ok(Message::Text(frame))) = runner.socket.next() => {
                        runner.acknowledge(&frame).await;
                    }
                }
            }
            for byte in [3, 4, 5] {
                runner.serve_through_ping(byte).await;
            }
            assert!(drain_records(&runner.capture, "runner.drained").is_empty());
            runner.stop.notify_one();
            assert_eq!(runner.service.await.unwrap().unwrap(), ServiceEnd::Stopped);
        })
        .await
        .unwrap();
    }

    const TEST_DRAIN_DEADLINE: Duration = Duration::from_secs(23);

    #[tokio::test]
    async fn drain_stop_deadline_interrupts_the_assignment_and_waits_for_its_acknowledgement() {
        with_watchdog(async {
            let mut runner = HeldDrain::start(Some(TEST_DRAIN_DEADLINE)).await;
            sleep_request(&mut runner.sleeps, TEST_DRAIN_DEADLINE)
                .await
                .release();
            let interrupted = runner.expect_interruption().await;
            runner.acknowledge_interruption(&interrupted).await;
            assert_eq!(runner.service.await.unwrap().unwrap(), ServiceEnd::Stopped);
            let records = drain_records(&runner.capture, "runner.drain_deadline");
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["um.runner.drain_deadline_seconds"], 23);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn drain_stop_reenabling_cancels_the_deadline() {
        with_watchdog(async {
            let mut runner = HeldDrain::start(Some(TEST_DRAIN_DEADLINE)).await;
            let deadline = sleep_request(&mut runner.sleeps, TEST_DRAIN_DEADLINE).await;
            send_registration_mode(&mut runner.socket, RegistrationMode::Enabled).await;
            ping_serving_runner(&mut runner.socket, 2).await;
            deadline.release();
            ping_serving_runner(&mut runner.socket, 3).await;
            assert!(drain_records(&runner.capture, "runner.drain_deadline").is_empty());
            runner.stop.notify_one();
            let interrupted = runner.expect_interruption().await;
            runner.acknowledge_interruption(&interrupted).await;
            assert_eq!(runner.service.await.unwrap().unwrap(), ServiceEnd::Stopped);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn drain_stop_deadline_cannot_force_an_operator_shutdown() {
        with_watchdog(async {
            let mut runner = HeldDrain::start(Some(TEST_DRAIN_DEADLINE)).await;
            let deadline = sleep_request(&mut runner.sleeps, TEST_DRAIN_DEADLINE).await;
            runner.stop.notify_one();
            let interrupted = runner.expect_interruption().await;
            deadline.release();
            ping_serving_runner(&mut runner.socket, 3).await;
            runner.acknowledge_interruption(&interrupted).await;
            assert_eq!(runner.service.await.unwrap().unwrap(), ServiceEnd::Stopped);
            assert!(drain_records(&runner.capture, "runner.drain_deadline").is_empty());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn shutdown_reports_and_waits_for_an_accepted_assignment_interruption() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = accepted_assignment_config(&endpoint);
        let offer = fixture.offer.clone();
        let (accepted_sent, accepted_received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, accepted, interrupted) =
                accept_assignment_interruption(&listener, accepted_sent, offer).await;
            socket
                .send(observation_acknowledgement(
                    accepted["messageId"].as_str().unwrap(),
                    accepted["sequence"].as_u64().unwrap(),
                ))
                .await
                .expect("acknowledge assignment acceptance");
            socket
                .send(terminal_observation_acknowledgement(
                    interrupted["messageId"].as_str().unwrap(),
                    interrupted["sequence"].as_u64().unwrap(),
                ))
                .await
                .expect("acknowledge shutdown interruption");
            while let Some(Ok(_)) = socket.next().await {}
        });

        let service = begin_accepted_assignment_shutdown(fixture, accepted_received).await;

        with_watchdog(service.task)
            .await
            .expect("runner ignored shutdown acknowledgement")
            .expect("runner service task failed")
            .expect("runner service returned an error");
        with_watchdog(server)
            .await
            .expect("gateway fixture did not observe service exit")
            .expect("gateway fixture failed");
    }

    #[tokio::test]
    async fn second_shutdown_signal_forces_exit_without_another_observation() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = accepted_assignment_config(&endpoint);
        let offer = fixture.offer.clone();
        let (accepted_sent, accepted_received) = tokio::sync::oneshot::channel();
        let (interrupted_sent, interrupted_received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _accepted, _interrupted) =
                accept_assignment_interruption(&listener, accepted_sent, offer).await;
            interrupted_sent
                .send(())
                .expect("report shutdown interruption");

            while let Some(frame) = socket.next().await {
                match frame {
                    Ok(Message::Text(_)) => {
                        panic!("repeated shutdown signal produced another observation");
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });

        let service = begin_accepted_assignment_shutdown(fixture, accepted_received).await;
        with_watchdog(interrupted_received)
            .await
            .expect("runner did not begin graceful shutdown")
            .expect("fixture dropped interruption signal");
        service.shutdown_trigger.notify_one();

        let error = with_watchdog(service.task)
            .await
            .expect("runner ignored repeated shutdown signal")
            .expect("runner service task failed")
            .expect_err("runner treated a repeated shutdown signal as successful exit");
        assert!(matches!(error, ServiceError::ShutdownForced));
        with_watchdog(server)
            .await
            .expect("gateway fixture did not observe forced exit")
            .expect("gateway fixture failed");
    }

    #[tokio::test]
    async fn stop_signal_during_reconnect_backoff_exits_without_a_session() {
        let (listener, endpoint) = fixture_listener().await;
        let server = tokio::spawn(async move {
            // Every session ends before welcome, as a Gateway whose store cannot
            // admit the hello closes it: the runner never completes a handshake.
            loop {
                let mut socket = accept_fixture_socket(&listener).await;
                expect_opening_hello(&mut socket).await;
                socket
                    .send(Message::Close(Some(CloseFrame {
                        code: CloseCode::Error,
                        reason: "store_failure".into(),
                    })))
                    .await
                    .expect("send pre-welcome close");
                while let Some(Ok(_)) = socket.next().await {}
            }
        });

        let (sleeper, mut sleep_requests) = controlled_sleeper();
        let (service, _capture, shutdown_trigger) = spawn_fixture_service(&endpoint, sleeper);
        let (_delay, _held_backoff) = backoff_request(&mut sleep_requests).await;
        shutdown_trigger.notify_one();

        // No controlled sleep is released: neither the backoff nor the shutdown
        // deadline can elapse, so a return here is an exit that waited on nothing.
        with_watchdog(service)
            .await
            .expect("runner kept running past a stop signal received in reconnect backoff")
            .expect("runner service task failed")
            .expect("runner service returned an error");
        server.abort();
    }

    // While the service backs off from a refused session, the control socket's overview
    // gives the attempt, the time to the next and who is serving, and `status` still
    // answers its snapshot.
    #[tokio::test]
    async fn the_overview_of_a_service_in_reconnect_backoff_gives_its_attempts() {
        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        let socket_path = fixture.config.control_socket_path().unwrap().to_owned();
        let server = tokio::spawn(async move {
            // Every session ends before welcome, so the runner never connects.
            loop {
                let mut socket = accept_fixture_socket(&listener).await;
                expect_opening_hello(&mut socket).await;
                socket
                    .send(Message::Close(Some(CloseFrame {
                        code: CloseCode::Error,
                        reason: "store_failure".into(),
                    })))
                    .await
                    .expect("send pre-welcome close");
                while let Some(Ok(_)) = socket.next().await {}
            }
        });

        let (sleeper, mut sleep_requests) = controlled_sleeper();
        let (service, _capture, shutdown_trigger) =
            spawn_configured_service(fixture.config.clone(), sleeper);
        let (delay, _held_backoff) = backoff_request(&mut sleep_requests).await;
        let overview_socket = socket_path.clone();
        let answer = tokio::task::spawn_blocking(move || {
            crate::control_client::request_overview(&overview_socket)
        })
        .await
        .unwrap()
        .unwrap();
        let crate::control_protocol::OverviewAnswer::Overview(overview) = answer else {
            panic!("the serving process refused the overview: {answer:?}");
        };
        assert_eq!(
            overview.connection.state,
            crate::control_protocol::OpenWord::Known(ConnectionState::BackingOff)
        );
        assert_eq!(overview.connection.attempts_since_connected, Some(1));
        let next = overview
            .connection
            .next_attempt_in_milliseconds
            .expect("a backing-off service gives the time to its next attempt");
        assert!(next <= u64::try_from(delay.as_millis()).unwrap(), "{next}");
        assert_eq!(
            overview.runner.runner_id,
            fixture.config.credential().runner_id()
        );
        assert_eq!(
            overview.runner.version,
            crate::telemetry::TEST_SERVICE_VERSION
        );
        assert!(matches!(
            request_control(socket_path, Operation::Status).await,
            Response::Status(_)
        ));

        shutdown_trigger.notify_one();
        with_watchdog(service)
            .await
            .expect("runner kept running past a stop signal received in reconnect backoff")
            .expect("runner service task failed")
            .expect("runner service returned an error");
        server.abort();
    }

    // A service backing off from refused sessions lists its failed attempts as one
    // event, and a reload that fails is answered as before and listed.
    #[tokio::test]
    async fn the_overview_of_a_service_in_reconnect_backoff_lists_its_events() {
        use crate::control_protocol::{OpenWord, OverviewAnswer, RunnerEventKind};

        let (listener, endpoint) = fixture_listener().await;
        let fixture = RotationFixture::without_pending(&endpoint);
        let socket_path = fixture.config.control_socket_path().unwrap().to_owned();
        let server = tokio::spawn(async move {
            // Every session ends before welcome, so the runner never connects.
            loop {
                let mut socket = accept_fixture_socket(&listener).await;
                expect_opening_hello(&mut socket).await;
                socket
                    .send(Message::Close(Some(CloseFrame {
                        code: CloseCode::Error,
                        reason: "store_failure".into(),
                    })))
                    .await
                    .expect("send pre-welcome close");
                while let Some(Ok(_)) = socket.next().await {}
            }
        });
        let events = || {
            let socket_path = socket_path.clone();
            async move {
                let answer = tokio::task::spawn_blocking(move || {
                    crate::control_client::request_overview(&socket_path)
                })
                .await
                .unwrap()
                .unwrap();
                let OverviewAnswer::Overview(overview) = answer else {
                    panic!("the serving process refused the overview: {answer:?}");
                };
                (overview.events, overview.connection.last_failure)
            }
        };

        let (sleeper, mut sleep_requests) = controlled_sleeper();
        let (recorder, _capture) = test_recorder("rbt_00000000000000000000000001");
        let dependencies = super::fixture_loop_dependencies(
            fixture.config.clone(),
            deterministic_frame_source(),
            sleeper,
            recorder,
            Some(unavailable_source_broker()),
        )
        .unwrap();
        let (mut shutdown, shutdown_trigger) = controlled_shutdown();
        // A fixed unit keeps every delay under the second `backoff_request` waits for.
        let service = tokio::spawn(async move {
            super::run_connection_loop_with_filesystem(
                dependencies,
                &super::WebSocketConnector,
                super::Backoff::with_fixed_unit(0.1),
                shutdown.as_mut(),
                super::workspace::WorkspaceFilesystem::testing(),
                JoinKeyMode::None,
            )
            .await
        });
        for _ in 0..2 {
            let (_delay, held_backoff) = backoff_request(&mut sleep_requests).await;
            held_backoff.release();
        }
        let (delay, _held_backoff) = backoff_request(&mut sleep_requests).await;
        let (listed, last_failure) = events().await;
        let [failed] = listed.as_slice() else {
            panic!("the three failed attempts are one event: {listed:?}");
        };
        assert_eq!(
            failed.kind,
            OpenWord::Known(RunnerEventKind::ConnectionFailed)
        );
        assert_eq!(failed.count, 3);
        assert_eq!(failed.failure, last_failure);
        assert_eq!(
            failed.next_attempt_in_milliseconds,
            Some(u64::try_from(delay.as_millis()).unwrap())
        );

        assert_eq!(
            request_control(socket_path.clone(), Operation::ReloadCredential).await,
            Response::Error(ControlError::NoPendingCredential)
        );
        let (listed, _) = events().await;
        let reload_failed = listed
            .iter()
            .position(|event| {
                event.kind == OpenWord::Known(RunnerEventKind::CredentialReloadFailed)
            })
            .unwrap_or_else(|| panic!("the failed reload is listed: {listed:?}"));
        assert_eq!(
            listed[reload_failed].error,
            Some(OpenWord::Known(ControlError::NoPendingCredential))
        );
        assert!(
            listed[..reload_failed]
                .iter()
                .all(|event| event.kind == OpenWord::Known(RunnerEventKind::ConnectionFailed)),
            "{listed:?}"
        );

        shutdown_trigger.notify_one();
        with_watchdog(service)
            .await
            .expect("runner kept running past a stop signal received in reconnect backoff")
            .expect("runner service task failed")
            .expect("runner service returned an error");
        server.abort();
    }

    #[tokio::test]
    async fn stop_signal_after_credential_revocation_exits_without_a_session() {
        let (listener, endpoint) = fixture_listener().await;
        let server = tokio::spawn(async move {
            // A revoked credential is refused at every upgrade.
            loop {
                let (mut stream, _) = listener.accept().await.expect("accept fixture connection");
                let mut request = [0_u8; 4096];
                let _ = stream
                    .read(&mut request)
                    .await
                    .expect("read upgrade request");
                stream
                    .write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n")
                    .await
                    .expect("refuse revoked credential");
            }
        });

        let (sleeper, _sleep_requests) = controlled_sleeper();
        let (service, capture, shutdown_trigger) = spawn_fixture_service(&endpoint, sleeper);
        with_watchdog(capture.wait_for_event("runner.gateway_connection"))
            .await
            .expect("runner did not record the refused connection");
        assert_eq!(
            capture.event("runner.gateway_connection")["um.connection.failure_kind"],
            "terminal_authentication"
        );
        shutdown_trigger.notify_one();

        with_watchdog(service)
            .await
            .expect("runner kept running past a stop signal received after revocation")
            .expect("runner service task failed")
            .expect("runner service returned an error");
        server.abort();
    }

    const SERVING_OWNER_FIXTURE: &str = "service::tests::serving_owner_fixture";
    const SERVING_OWNER_ENDPOINT: &str = "USEFUL_TEST_SERVING_OWNER_ENDPOINT";
    const SERVING_OWNER_SOURCE: &str = "USEFUL_TEST_SERVING_OWNER_SOURCE";
    const SERVING_OWNER_WORK_ROOT: &str = "USEFUL_TEST_SERVING_OWNER_WORK_ROOT";

    /// The serving runner that `abrupt_serving_owner_death_terminates_guarded_processes`
    /// kills: the production connection loop, assignment manager and engine in a process
    /// of their own, with only the source broker replaced by the fixture repository.
    #[test]
    #[ignore = "launched only as the serving runner that the abrupt owner-death test kills"]
    fn serving_owner_fixture() {
        let variable = |name| std::env::var_os(name).expect("serving owner fixture variable");
        let endpoint = variable(SERVING_OWNER_ENDPOINT)
            .into_string()
            .expect("serving owner endpoint should be UTF-8");
        let config = accepted_assignment_service_config(
            &endpoint,
            Path::new(&variable(SERVING_OWNER_WORK_ROOT)),
        );
        let source_broker = fixture_source_broker(Path::new(&variable(SERVING_OWNER_SOURCE)));
        let (recorder, _capture) = test_recorder("rbt_00000000000000000000000001");
        // The held trigger keeps shutdown pending, so only the kill ends this process.
        let (shutdown, _shutdown_trigger) = controlled_shutdown();
        let outcome = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build serving owner runtime")
            .block_on(run_until_cancelled_with_dependencies(
                config,
                deterministic_frame_source(),
                fixture_sleeper(),
                recorder,
                Some(source_broker),
                shutdown,
                JoinKeyMode::None,
            ));
        panic!("serving owner stopped before it was killed: {outcome:?}");
    }

    struct ServingOwner {
        child: std::process::Child,
        log: PathBuf,
    }

    impl ServingOwner {
        fn spawn(root: &Path, endpoint: &str, source: &Path, work: &Path) -> Self {
            // The owner runs a guarded command step, so it needs the built worker
            // executable that `cli/scripts/check-suite` supplies; without it the step
            // would fail at launch and never hold, which would surface only as the
            // watchdog firing, so the fixture refuses first and names the build command.
            let worker = require_internal_worker_executable();
            let log = root.join("serving-owner.stderr");
            let child = std::process::Command::new(
                std::env::current_exe().expect("locate the runner test executable"),
            )
            .args(["--ignored", "--exact", SERVING_OWNER_FIXTURE, "--nocapture"])
            .env("USEFUL_TEST_INTERNAL_WORKER_EXECUTABLE", &worker)
            .env(SERVING_OWNER_ENDPOINT, endpoint)
            .env(SERVING_OWNER_SOURCE, source)
            .env(SERVING_OWNER_WORK_ROOT, work)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log).expect("create serving owner log"))
            .spawn()
            .expect("launch the serving owner fixture");
            Self { child, log }
        }

        fn diagnostics(&self) -> String {
            fs::read_to_string(&self.log).unwrap_or_default()
        }
    }

    impl Drop for ServingOwner {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn cloud_frame(message_type: &str, message_id: &str, payload: serde_json::Value) -> Message {
        Message::Text(
            serde_json::json!({
                "protocolVersion": 1,
                "direction": "cloud_to_runner",
                "messageId": message_id,
                "sentAt": "2026-07-23T00:00:05Z",
                "type": message_type,
                "payloadVersion": 1,
                "payload": payload,
            })
            .to_string()
            .into(),
        )
    }

    /// The leader and descendant process ids the guarded step records once it holds.
    /// Acknowledges every runner observation and keeps the session live until `observe`
    /// yields, answering the runner's `execution_started` with `authorization`.
    async fn serve_started_assignment<T>(
        socket: &mut FixtureSocket,
        mut authorization: Option<Message>,
        mut observe: impl FnMut() -> Option<T>,
    ) -> T {
        let sleeper = fixture_sleeper();
        let mut polls = 0_u32;
        loop {
            if let Some(observed) = observe() {
                return observed;
            }
            let next = tokio::select! {
                frame = socket.next() => frame,
                _ = sleeper.sleep(Duration::from_millis(10)) => {
                    polls += 1;
                    if polls.is_multiple_of(50) {
                        socket.send(Message::Ping(vec![4, 5, 6].into())).await
                            .expect("send fixture keepalive");
                    }
                    continue;
                }
            };
            match next {
                Some(Ok(Message::Text(frame))) => {
                    let frame: serde_json::Value =
                        serde_json::from_str(&frame).expect("decode runner frame");
                    if let (Some(message_id), Some(sequence)) =
                        (frame["messageId"].as_str(), frame["sequence"].as_u64())
                    {
                        socket
                            .send(observation_acknowledgement(message_id, sequence))
                            .await
                            .expect("acknowledge runner observation");
                    }
                    if frame["type"] == "execution_started"
                        && let Some(authorization) = authorization.take()
                    {
                        socket
                            .send(authorization)
                            .await
                            .expect("authorize execution start");
                    }
                }
                Some(Ok(Message::Ping(payload))) => socket
                    .send(Message::Pong(payload))
                    .await
                    .expect("answer runner keepalive"),
                Some(Ok(_)) => {}
                other => panic!("runner connection ended before the guarded step held: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn abrupt_serving_owner_death_terminates_guarded_processes() {
        let temporary = tempfile::tempdir().expect("create owner-death fixture root");
        // The step's shell leads its guarded process group and holds a descendant in it.
        let record = temporary.path().join("guarded-processes");
        let (source, work) =
            materialize_accepted_source(temporary.path(), &holding_step_workflow(&record));
        let offer = accepted_assignment_offer(&source);
        let Message::Text(encoded) = &offer else {
            panic!("assignment offer fixture should be text");
        };
        let offered: serde_json::Value =
            serde_json::from_str(encoded).expect("decode assignment offer fixture");
        let identity = |effect_id: &str| {
            let offered = &offered["payload"];
            serde_json::json!({
                "effectId": effect_id,
                "assignmentId": offered["assignmentId"],
                "runId": offered["runId"],
                "attemptId": offered["attemptId"],
            })
        };
        let mut start = identity("eff_01k0z6r1w8f4jy2m7q9v3x5abj");
        start["executionSpecId"] = offered["payload"]["executionSpec"]["executionSpecId"].clone();
        start["lease"] = serde_json::json!({ "leaseSequence": 1 });
        let authorization = cloud_frame(
            "execution_start_authorized",
            "cmsg_01k0z6r1w8f4jy2m7q9v3x5abr",
            identity("eff_01k0z6r1w8f4jy2m7q9v3x5abk"),
        );

        let (listener, endpoint) = fixture_listener().await;
        let mut owner = ServingOwner::spawn(temporary.path(), &endpoint, &source, &work);
        let (mut socket, accepted) = with_watchdog(accept_offered_assignment(&listener, offer))
            .await
            .unwrap_or_else(|expired| {
                panic!(
                    "serving owner did not accept the assignment: {expired}: {}",
                    owner.diagnostics()
                )
            });
        socket
            .send(observation_acknowledgement(
                accepted["messageId"].as_str().unwrap(),
                accepted["sequence"].as_u64().unwrap(),
            ))
            .await
            .expect("acknowledge assignment acceptance");
        socket
            .send(cloud_frame(
                "assignment_start",
                "cmsg_01k0z6r1w8f4jy2m7q9v3x5abn",
                start,
            ))
            .await
            .expect("start the accepted assignment");
        let (leader, descendant) = with_watchdog(serve_started_assignment(
            &mut socket,
            Some(authorization),
            || guarded_processes(&record),
        ))
        .await
        .unwrap_or_else(|expired| {
            panic!(
                "guarded step did not hold: {expired}: {}",
                owner.diagnostics()
            )
        });
        for member in [leader, descendant] {
            assert_eq!(
                getpgid(Some(member)),
                Ok(leader),
                "the step must run in its own guarded process group"
            );
        }

        owner.child.kill().expect("kill the serving owner");
        let status = owner.child.wait().expect("reap the serving owner");
        assert_eq!(status.signal(), Some(Signal::KILL.as_raw()));
        let quiesced = with_watchdog(async {
            let sleeper = fixture_sleeper();
            while [leader, descendant].into_iter().any(process_exists) {
                sleeper.sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        if let Err(expired) = quiesced {
            let _ = kill_process_group(leader, Signal::KILL);
            panic!("guarded processes outlived the serving owner: {expired}");
        }
    }

    #[tokio::test]
    async fn classifies_pending_effect_event_cancellation() {
        let (listener, endpoint) = fixture_listener().await;
        let (pending_sent, pending_received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut socket = accept_opened_fixture_socket(&listener).await;
            let offer_acknowledgement =
                offer_assignment_after_handshake(&mut socket, "rmsg_00000000000000000000000002", 1)
                    .await;
            acknowledge_runner_frame(
                &mut socket,
                &offer_acknowledgement,
                "acknowledge assignment offer",
            )
            .await;
            let _pending_prepare_receipt = begin_assignment_preparation(&mut socket).await;
            // The production gateway reads, persists, and acknowledges runner frames
            // serially. Leave later progress and rejection frames unacknowledged so
            // the fixture cannot confirm them ahead of the pending prepare receipt.
            let _pending_rejection =
                next_semantic_assignment_frame(&mut socket, "assignment_rejected", false).await;
            pending_sent
                .send(())
                .expect("report pending prepare effect acknowledgement");
            while let Some(Ok(_)) = socket.next().await {}
        });

        let (sleeper, _sleep_requests) = controlled_sleeper();
        let (service, capture, shutdown_trigger) = spawn_fixture_service(&endpoint, sleeper);
        with_watchdog(pending_received)
            .await
            .expect("effect acknowledgement did not become pending")
            .expect("fixture server dropped pending signal");

        shutdown_trigger.notify_one();
        with_watchdog(service)
            .await
            .expect("runner service ignored termination")
            .expect("runner service task failed")
            .expect("runner service returned an error");
        with_watchdog(server)
            .await
            .expect("fixture server did not observe shutdown")
            .expect("fixture server failed");

        let connection = assert_attempt_event_pair(&capture, "cancelled", None, 2, 6);
        assert_eq!(capture.event("runner.run")["um.run.result"], "rejected");
        let checkout = capture.event("runner.run.checkout");
        assert_eq!(checkout["um.outcome"], "failure");
        assert_eq!(checkout["error.type"], "runner_phase_failed");
        assert!(
            capture
                .events()
                .iter()
                .all(|event| event["event.name"] != "runner.run.preparation")
        );
        assert_eq!(capture.span_count("runner.assignment_preparation"), 1);
        assert_eq!(connection["um.outcome"], "cancelled");
        assert_eq!(connection["um.runner.opening_acknowledged"], true);
        assert_eq!(connection["um.runner.handshake_completed"], true);
        assert!(connection.get("error.type").is_none());
        assert!(connection.get("um.connection.failure_kind").is_none());
        assert!(connection.get("um.connection.backoff_ms").is_none());
        assert_eq!(capture.span_count("runner.gateway_connection"), 1);
    }

    mod agent_login_setup {
        use std::fs;
        use std::os::unix::fs::PermissionsExt as _;
        use std::path::PathBuf;
        use std::sync::Arc;
        use std::time::Duration;

        use futures_util::{SinkExt as _, StreamExt as _};
        use tokio_tungstenite::tungstenite::Message;

        use super::super::source::test_support::unavailable_source_broker;
        use super::super::test_support::{
            ConfigFixture, ControlledShutdownTrigger, FAKE_AGENT_LOGIN_SENTINEL,
            FakeAgentLoginCloud, ScriptedConnection, SleepRelease, accept_fixture_socket,
            assignment_offer, assignment_prepare, begin_assignment_preparation,
            controlled_shutdown, controlled_sleeper, deterministic_frame_source,
            effect_acknowledgement, effect_observation_acknowledgement, fake_agent_login_material,
            fake_agent_login_setup, fake_codex_answer, fake_codex_authorized, fixture_lease_clock,
            fixture_listener, observation_acknowledgement, scripted_connector, sleep_request,
            welcome, welcome_with_credential_mode, with_bound, with_watchdog,
        };
        use super::super::workspace::WorkRootLease;
        use super::super::{
            AGENT_LOGIN_SETUP_INTERVAL, Backoff, ConnectionLoopDependencies, Connector,
            JoinKeyMode, RejoinAnswer, ServiceEnd, ServiceError, WebSocketConnector,
            run_connection_loop_in_mode,
        };
        use super::{
            acknowledge_runner_frame, held_join_key, next_semantic_assignment_frame,
            refuse_every_upgrade,
        };
        use crate::agent_login::cloud::{CloudFailure, LoginStatus};
        use crate::agent_login::readiness::{LoginReadiness, ReadinessDocument, readiness_path};
        use crate::control_protocol::{AgentLoginProvider, AgentLoginState, CredentialMode};
        use crate::credential::test_credential;
        use crate::telemetry::{TestCapture, test_recorder};

        const SETUP_RECORD: &str = "runner.agent_login_setup";

        /// A serving runner whose agent-login setup asks `cloud`, on the
        /// controlled sleeper, with its own `HOME` and state directory.
        struct SetupService {
            home: tempfile::TempDir,
            state: tempfile::TempDir,
            capture: TestCapture,
            sleeps: tokio::sync::mpsc::UnboundedReceiver<(Duration, SleepRelease)>,
            pending_setup: Option<SleepRelease>,
            task: tokio::task::JoinHandle<Result<ServiceEnd, ServiceError>>,
            shutdown: ControlledShutdownTrigger,
            config: ConfigFixture,
        }

        impl SetupService {
            fn spawn(
                endpoint: &str,
                connector: impl Connector + 'static,
                cloud: Arc<FakeAgentLoginCloud>,
            ) -> Self {
                Self::spawn_in_mode(endpoint, connector, cloud, JoinKeyMode::None)
            }

            /// `spawn`, for a start in `join_key`'s mode.
            fn spawn_in_mode(
                endpoint: &str,
                connector: impl Connector + 'static,
                cloud: Arc<FakeAgentLoginCloud>,
                join_key: JoinKeyMode,
            ) -> Self {
                let config =
                    ConfigFixture::new(endpoint, test_credential(), true).expect("configure");
                let home = tempfile::tempdir().expect("service home");
                let state = tempfile::tempdir().expect("state directory");
                fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700))
                    .expect("private state directory");
                let frame_source = deterministic_frame_source();
                let boot_id = frame_source.public_id("rbt_");
                let (recorder, capture) = test_recorder(&boot_id);
                let (sleeper, sleeps) = controlled_sleeper();
                let (mut shutdown, shutdown_trigger) = controlled_shutdown();
                let dependencies = ConnectionLoopDependencies {
                    target: crate::service::serving_target(&config).unwrap(),
                    config: config.cloned_config(),
                    frame_source,
                    sleeper,
                    recorder: Arc::clone(&recorder),
                    lease_clock: fixture_lease_clock(),
                    boot_id: boot_id.clone(),
                    source_broker: Some(unavailable_source_broker()),
                    agent_login_setup: Some(fake_agent_login_setup(
                        Arc::clone(&cloud),
                        home.path(),
                        state.path(),
                        recorder,
                    )),
                    disk: None,
                };
                let work_root =
                    WorkRootLease::acquire_for_test(config.assignment().work_root(), &boot_id)
                        .expect("acquire work root");
                let task = tokio::spawn(async move {
                    run_connection_loop_in_mode(
                        dependencies,
                        &connector,
                        Backoff::with_fixed_unit(1.0),
                        shutdown.as_mut(),
                        work_root,
                        join_key,
                    )
                    .await
                });
                Self {
                    home,
                    state,
                    capture,
                    sleeps,
                    pending_setup: None,
                    task,
                    shutdown: shutdown_trigger,
                    config,
                }
            }

            /// Waits until the pass in flight has ended, which it shows by
            /// waiting for the next one.
            async fn pass_ended(&mut self) {
                let release =
                    with_watchdog(sleep_request(&mut self.sleeps, AGENT_LOGIN_SETUP_INTERVAL))
                        .await
                        .expect("agent-login setup did not wait for its next pass");
                self.pending_setup = Some(release);
            }

            /// Lets the setup interval elapse and waits for that pass to end.
            async fn next_pass(&mut self) {
                self.pending_setup
                    .take()
                    .expect("no agent-login setup is waiting")
                    .release();
                self.pass_ended().await;
            }

            fn auth_path(&self) -> PathBuf {
                self.state
                    .path()
                    .join(".runner-agent-login/codex/auth.json")
            }

            fn installed_material(&self) -> Option<Vec<u8>> {
                fs::read(self.auth_path()).ok()
            }

            fn codex(&self) -> LoginReadiness {
                self.recorded_codex().expect("codex readiness")
            }

            fn recorded_codex(&self) -> Option<LoginReadiness> {
                ReadinessDocument::load(&readiness_path(
                    &self.state.path().join("runner-state.json"),
                ))
                .expect("read readiness")
                .and_then(|document| document.login(AgentLoginProvider::Codex).cloned())
            }

            fn generation(&self) -> Option<u64> {
                self.codex()
                    .installation()
                    .map(|installation| installation.generation)
            }

            fn setup_records(&self) -> Vec<serde_json::Map<String, serde_json::Value>> {
                self.capture
                    .events()
                    .into_iter()
                    .filter(|event| event["event.name"] == SETUP_RECORD)
                    .collect()
            }

            async fn stop(self) {
                self.shutdown.notify_one();
                let _ = with_watchdog(self.task)
                    .await
                    .expect("runner ignored controlled shutdown");
            }
        }

        fn assert_no_material_outside_the_login(service: &SetupService) {
            let readiness = fs::read_to_string(readiness_path(
                &service.state.path().join("runner-state.json"),
            ))
            .expect("read readiness document");
            assert!(!readiness.contains(FAKE_AGENT_LOGIN_SENTINEL));
            let records = serde_json::to_string(&service.capture.records()).unwrap();
            assert!(!records.contains(FAKE_AGENT_LOGIN_SENTINEL));
            let spans = format!("{:?}", service.capture.spans());
            assert!(!spans.contains(FAKE_AGENT_LOGIN_SENTINEL));
        }

        async fn next_text(
            outbound: &mut tokio::sync::mpsc::UnboundedReceiver<Message>,
            message_type: &str,
        ) -> serde_json::Value {
            loop {
                let message = with_watchdog(outbound.recv())
                    .await
                    .expect("runner sent nothing")
                    .expect("runner connection closed");
                let Message::Text(text) = message else {
                    continue;
                };
                let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
                if frame["type"] == message_type {
                    return frame;
                }
            }
        }

        /// Takes the runner's next connection, reads its hello and welcomes
        /// it, naming `mode` as its credential mode or naming none, and
        /// acknowledging the hello.
        async fn welcomed(
            attempts: &mut tokio::sync::mpsc::UnboundedReceiver<ScriptedConnection>,
            mode: Option<CredentialMode>,
        ) -> ScriptedConnection {
            let mut connection = with_watchdog(attempts.recv())
                .await
                .expect("the runner did not connect")
                .expect("connection attempt");
            let hello = next_text(&mut connection.outbound, "hello").await;
            connection.inbound.send(welcome_with_credential_mode(mode));
            connection.inbound.send(observation_acknowledgement(
                hello["messageId"].as_str().unwrap(),
                hello["sequence"].as_u64().unwrap(),
            ));
            connection
        }

        #[tokio::test]
        async fn the_schedule_makes_its_first_setup_once_cloud_first_welcomes_the_runner() {
            let cloud = FakeAgentLoginCloud::new(fake_codex_authorized(1));
            let (connector, mut attempts) = scripted_connector(Default::default());
            let mut service = SetupService::spawn(
                "ws://127.0.0.1:1/v1/runner/connect",
                connector,
                Arc::clone(&cloud),
            );
            let mut connection = with_watchdog(attempts.recv())
                .await
                .expect("the runner did not connect")
                .expect("connection attempt");
            let hello = next_text(&mut connection.outbound, "hello").await;

            // Connected but not yet welcomed, the runner has made no setup
            // and waits for no next one.
            assert_eq!(cloud.status_requests(), 0);
            let mut waiting = Vec::new();
            while let Ok((duration, release)) = service.sleeps.try_recv() {
                assert_ne!(duration, AGENT_LOGIN_SETUP_INTERVAL);
                waiting.push(release);
            }

            connection.inbound.send(welcome());
            connection.inbound.send(observation_acknowledgement(
                hello["messageId"].as_str().unwrap(),
                hello["sequence"].as_u64().unwrap(),
            ));
            service.pass_ended().await;
            assert!(cloud.status_requests() >= 1);
            assert_eq!(service.codex().state, AgentLoginState::Ready);
            assert_eq!(
                service.installed_material(),
                Some(fake_agent_login_material(1))
            );
            drop(waiting);
            service.stop().await;
        }

        #[tokio::test]
        async fn a_runner_welcomed_in_host_asks_cloud_nothing_at_any_setup() {
            let cloud = FakeAgentLoginCloud::new(fake_codex_authorized(1));
            let (connector, mut attempts) = scripted_connector(Default::default());
            let mut service = SetupService::spawn(
                "ws://127.0.0.1:1/v1/runner/connect",
                connector,
                Arc::clone(&cloud),
            );
            let _connection = welcomed(&mut attempts, Some(CredentialMode::Host)).await;

            // The first setup and those of two intervals after it.
            service.pass_ended().await;
            service.next_pass().await;
            service.next_pass().await;

            assert_eq!(cloud.status_requests(), 0);
            assert_eq!(cloud.deliveries(), 0);
            assert_eq!(service.installed_material(), None);
            assert_eq!(service.codex().state, AgentLoginState::ForeignLogin);
            service.stop().await;
        }

        #[tokio::test]
        async fn starting_installs_an_authorized_login_without_holding_up_the_connection() {
            let cloud = FakeAgentLoginCloud::new(fake_codex_authorized(1));
            let status_held = cloud.hold_next_status();
            let (connector, mut attempts) = scripted_connector(Default::default());
            let mut service = SetupService::spawn(
                "ws://127.0.0.1:1/v1/runner/connect",
                connector,
                Arc::clone(&cloud),
            );

            // Cloud has not answered setup, and the runner is connecting.
            let mut connection = with_watchdog(attempts.recv())
                .await
                .expect("the runner did not connect while setup waited")
                .expect("connection attempt");
            let hello = next_text(&mut connection.outbound, "hello").await;
            assert_eq!(hello["type"], "hello");
            connection.inbound.send(welcome());
            connection.inbound.send(observation_acknowledgement(
                hello["messageId"].as_str().unwrap(),
                hello["sequence"].as_u64().unwrap(),
            ));
            assert_eq!(cloud.status_requests(), 0);
            drop(status_held);
            service.pass_ended().await;

            assert_eq!(
                service.installed_material(),
                Some(fake_agent_login_material(1))
            );
            assert_eq!(
                fs::metadata(service.auth_path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(service.codex().state, AgentLoginState::Ready);
            assert_eq!(service.generation(), Some(1));
            let records = service.setup_records();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["um.agent_login.codex.state"], "ready");
            assert_eq!(records[0]["um.agent_login.codex.generation"], 1);
            assert_eq!(records[0]["um.outcome"], "success");

            // Five minutes later, with no assignment, setup runs again; it
            // finds the installed generation and changes nothing.
            service.next_pass().await;
            assert_eq!(cloud.status_requests(), 3);
            assert_eq!(cloud.deliveries(), 1);
            assert_eq!(service.codex().state, AgentLoginState::Ready);
            assert_eq!(service.setup_records().len(), 1);
            assert_no_material_outside_the_login(&service);
            service.stop().await;
        }

        #[tokio::test]
        async fn an_unavailable_cloud_neither_stops_serving_nor_runs_setup_during_an_assignment() {
            let cloud = FakeAgentLoginCloud::new(Err(CloudFailure::Transport));
            let (connector, mut attempts) = scripted_connector(Default::default());
            let mut service = SetupService::spawn(
                "ws://127.0.0.1:1/v1/runner/connect",
                connector,
                Arc::clone(&cloud),
            );
            // The runner still connects and serves.
            let mut connection = welcomed(&mut attempts, None).await;
            service.pass_ended().await;
            // Nothing was authorized, so an unanswered Cloud changes
            // nothing.
            assert_eq!(service.recorded_codex(), None);
            assert!(service.setup_records().is_empty());

            // It takes an assignment.
            connection.inbound.send(assignment_offer());
            let offered = next_text(&mut connection.outbound, "effect_acknowledged").await;
            let preparing = next_text(&mut connection.outbound, "assignment_preparing").await;

            // While it holds the assignment, a setup that falls due does
            // not run.
            cloud.answer(fake_codex_authorized(1));
            service.next_pass().await;
            assert_eq!(cloud.status_requests(), 1);
            assert_eq!(cloud.deliveries(), 0);
            assert_eq!(service.installed_material(), None);
            assert_eq!(service.recorded_codex(), None);
            assert!(service.setup_records().is_empty());

            // A runner holding a preparation stops only once Cloud has its
            // answer, so let the assignment go before stopping: with no
            // source broker it rejects the preparation.
            let acknowledge = |frame: &serde_json::Value| {
                connection.inbound.send(effect_observation_acknowledgement(
                    frame["messageId"].as_str().unwrap(),
                    frame["sequence"].as_u64().unwrap(),
                ));
            };
            acknowledge(&offered);
            acknowledge(&preparing);
            connection.inbound.send(assignment_prepare());
            let rejection = next_text(&mut connection.outbound, "assignment_rejected").await;
            acknowledge(&rejection);
            service.stop().await;
        }

        #[tokio::test]
        async fn an_ended_login_is_removed_and_an_unrecorded_one_is_the_runners_own() {
            let cloud = FakeAgentLoginCloud::new(fake_codex_authorized(1));
            let (connector, mut attempts) = scripted_connector(Default::default());
            let mut service = SetupService::spawn(
                "ws://127.0.0.1:1/v1/runner/connect",
                connector,
                Arc::clone(&cloud),
            );
            let _connection = welcomed(&mut attempts, None).await;
            service.pass_ended().await;
            assert_eq!(service.generation(), Some(1));

            let ended = [
                (fake_codex_answer(LoginStatus::Revoked), "revoked"),
                (
                    fake_codex_answer(LoginStatus::Unauthorized),
                    "not_authorized",
                ),
                (Ok(Vec::new()), "not_authorized"),
            ];
            for (generation, (answer, state)) in (2..).zip(ended) {
                cloud.answer(answer);
                service.next_pass().await;
                assert_eq!(service.installed_material(), None, "{state}");
                assert_eq!(service.codex().state.as_str(), state);
                assert_eq!(service.generation(), None);
                let records = service.setup_records();
                let last = records.last().unwrap();
                assert_eq!(last["um.agent_login.codex.state"], state);
                assert!(last.get("um.agent_login.codex.generation").is_none());

                cloud.answer(fake_codex_authorized(generation));
                service.next_pass().await;
                assert_eq!(
                    service.installed_material(),
                    Some(fake_agent_login_material(generation))
                );
                assert_eq!(service.generation(), Some(generation));
            }

            // A file in the runner's directory it has no record of is its
            // own: replaced by a delivery, and removed when the login ends.
            cloud.answer(Ok(Vec::new()));
            service.next_pass().await;
            // The ending removed the whole Codex home.
            fs::create_dir_all(service.auth_path().parent().unwrap()).unwrap();
            fs::write(service.auth_path(), b"{\"unrecorded\":true}").unwrap();
            cloud.answer(fake_codex_authorized(5));
            service.next_pass().await;
            assert_eq!(service.codex().state, AgentLoginState::Ready);
            assert_eq!(
                service.installed_material(),
                Some(fake_agent_login_material(5))
            );
            cloud.answer(fake_codex_answer(LoginStatus::Revoked));
            service.next_pass().await;
            assert_eq!(service.codex().state, AgentLoginState::Revoked);
            assert_eq!(service.installed_material(), None);
            assert_eq!(fs::read_dir(service.home.path()).unwrap().count(), 0);
            assert_no_material_outside_the_login(&service);
            service.stop().await;
        }

        #[tokio::test]
        async fn a_setup_due_during_an_assignment_waits_for_its_release() {
            let (listener, endpoint) = fixture_listener().await;
            let (offer_sent, offer) = tokio::sync::oneshot::channel::<()>();
            let (held_sent, held) = tokio::sync::oneshot::channel();
            let (release_sent, release) = tokio::sync::oneshot::channel::<()>();
            let (released_sent, released) = tokio::sync::oneshot::channel();
            let gateway = tokio::spawn(async move {
                let mut socket = accept_fixture_socket(&listener).await;
                let Some(Ok(Message::Text(hello))) = socket.next().await else {
                    panic!("the runner sent no hello");
                };
                let hello: serde_json::Value = serde_json::from_str(&hello).unwrap();
                socket.send(welcome()).await.unwrap();
                socket
                    .send(observation_acknowledgement(
                        hello["messageId"].as_str().unwrap(),
                        hello["sequence"].as_u64().unwrap(),
                    ))
                    .await
                    .unwrap();
                offer.await.unwrap();
                socket.send(assignment_offer()).await.unwrap();
                let offered = effect_acknowledgement(&mut socket).await;
                acknowledge_runner_frame(&mut socket, &offered, "acknowledge offer").await;
                held_sent.send(()).unwrap();
                release.await.unwrap();
                let prepare = begin_assignment_preparation(&mut socket).await;
                acknowledge_runner_frame(&mut socket, &prepare, "acknowledge prepare").await;
                let rejection =
                    next_semantic_assignment_frame(&mut socket, "assignment_rejected", true).await;
                acknowledge_runner_frame(&mut socket, &rejection, "acknowledge rejection").await;
                released_sent.send(()).unwrap();
                while let Some(Ok(_)) = socket.next().await {}
            });
            let cloud = FakeAgentLoginCloud::new(fake_codex_authorized(1));
            let mut service =
                SetupService::spawn(&endpoint, WebSocketConnector, Arc::clone(&cloud));
            service.pass_ended().await;
            assert_eq!(service.generation(), Some(1));
            offer_sent.send(()).unwrap();
            with_watchdog(held).await.unwrap().unwrap();

            cloud.answer(fake_codex_answer(LoginStatus::Revoked));
            service.next_pass().await;
            assert_eq!(cloud.status_requests(), 2);
            assert_eq!(
                service.installed_material(),
                Some(fake_agent_login_material(1))
            );
            assert_eq!(service.codex().state, AgentLoginState::Ready);

            release_sent.send(()).unwrap();
            with_watchdog(released).await.unwrap().unwrap();
            // The runner lets the assignment go once its rejection is
            // acknowledged; the first pass after that removes the login.
            with_watchdog(async {
                while cloud.status_requests() == 2 {
                    service.next_pass().await;
                }
            })
            .await
            .expect("setup did not run after the assignment was released");
            assert_eq!(service.installed_material(), None);
            assert_eq!(service.codex().state, AgentLoginState::Revoked);
            service.stop().await;
            gateway.abort();
        }

        /// How long a rejoined service has to stay running while its setup's
        /// request is held. Without the wait for the setup's thread the
        /// service ends within milliseconds of the rejoin's answer; with it,
        /// it cannot end at all until the request is released.
        const HELD_SETUP_BOUND: Duration = Duration::from_secs(1);

        /// A runner welcomed before its hello is acknowledged. Its first setup is still
        /// in flight when the next connection is refused and its held key rejoins.
        struct HeldRejoin {
            service: SetupService,
            cloud: Arc<FakeAgentLoginCloud>,
            held: std::sync::mpsc::SyncSender<()>,
            server: tokio::task::JoinHandle<()>,
        }

        impl HeldRejoin {
            async fn start() -> Self {
                let (listener, endpoint) = fixture_listener().await;
                let cloud = FakeAgentLoginCloud::new(fake_codex_authorized(1));
                let (held, arrival) = cloud.hold_next_status_arrival();
                let (join_key, calls) = held_join_key(&[RejoinAnswer::Rejoined]);
                let mut service = SetupService::spawn_in_mode(
                    &endpoint,
                    WebSocketConnector,
                    Arc::clone(&cloud),
                    join_key,
                );
                let mut socket =
                    super::super::test_support::accept_opened_fixture_socket(&listener).await;
                socket.send(welcome()).await.unwrap();
                with_watchdog(tokio::task::spawn_blocking(move || arrival.recv()))
                    .await
                    .expect("the setup did not ask Cloud")
                    .unwrap()
                    .expect("the setup asked Cloud");
                // The welcome starts setup. Withhold the hello acknowledgement so the
                // runner still holds its join key when its next connection is refused.
                socket.close(None).await.unwrap();
                drop(socket);
                let server = refuse_every_upgrade(listener);
                with_watchdog(sleep_request(&mut service.sleeps, Duration::from_secs(1)))
                    .await
                    .expect("the runner did not back off after the incomplete handshake")
                    .release();
                calls.wait_until_dropped().await;
                Self {
                    service,
                    cloud,
                    held,
                    server,
                }
            }
        }

        #[tokio::test]
        async fn a_rejoined_service_ends_only_once_its_setup_thread_has_let_the_work_root_go() {
            let HeldRejoin {
                mut service,
                cloud,
                held,
                server,
            } = HeldRejoin::start().await;

            with_bound(HELD_SETUP_BOUND, &mut service.task)
                .await
                .expect_err("the rejoined service ended while its setup's request was held");
            drop(held);
            let end = with_watchdog(&mut service.task)
                .await
                .expect("the rejoined service did not end once its setup's request was released")
                .unwrap()
                .unwrap();

            assert_eq!(end, ServiceEnd::Rejoined);
            // The service that serves the rejoined runner leases the same
            // work root at once.
            WorkRootLease::acquire_for_test(
                service.config.assignment().work_root(),
                "rbt_00000000000000000000000009",
            )
            .expect("the ended service's setup still holds its work root");
            // The ended setup asked Cloud for no delivery after its request.
            assert_eq!(cloud.status_requests(), 1);
            assert_eq!(cloud.deliveries(), 0);
            server.abort();
        }

        #[tokio::test]
        async fn a_stop_while_a_rejoined_service_waits_for_its_setup_ends_it_as_stopped() {
            let HeldRejoin {
                mut service,
                cloud: _cloud,
                held,
                server,
            } = HeldRejoin::start().await;

            service.shutdown.notify_one();
            let end = with_watchdog(&mut service.task)
                .await
                .expect("the stop did not end the service while its setup's request was held")
                .unwrap()
                .unwrap();

            assert_eq!(end, ServiceEnd::Stopped);
            drop(held);
            server.abort();
        }
    }
}
