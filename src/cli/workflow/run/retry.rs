use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::anyhow;
use clap::Args;

use useful_execution::{
    CONTROL_RETRY, CancellationSource, LocalRetryBeginError, LocalRetryOpen, NoConditions,
    PendingLocalRetry, RunState, WITHDRAWN_OUTCOME, WaitInspection, WaitKind, WorkflowRunOutput,
    acquire_local_retry, admit_local_workflow, await_begin_gate, await_run_lock_gate, inspect_wait,
    reconcile_current_result_publication,
};

use super::cloud_api::{RunWaitArgs, parse_continuation_step};
use super::control::{ControlFailure, ControlTarget, Refusal};
use super::target::{Found, InCloud, RunArg};
use crate::cli::context::OrgArgs;
use crate::cli::{HttpOptions, PrincipalAuthenticationArgs};
use crate::exit_code::ExitCode;

pub(super) const ABOUT: &str = "Rerun steps of a run, on this machine or in Cloud";
pub(super) const AFTER_HELP: &str = "RUN is a run directory, a run ID or a subject. An ID or a subject is looked up under the useful home and, when the home holds no such run, in Cloud in the organization in effect.

With --from STEP, repeatable, the run continues from the named ordinary steps: their downstream ordinary dependents run again, other eligible ordinary steps are inherited, and every finalizer runs again. --workflow names a replacement workflow file within the run's original source root.

With --all, every step runs again as a new attempt, from the run's retained workflow and inputs. The attempt runs in --execution-root, or in the previous attempt's execution root when it is omitted, and a root an earlier attempt used is reported with a warning.

With neither, a run waiting for repair or for its host is retried from the stage that failed: the retry is recorded, with the replacement profiles of --agent-profiles when given, and the run continues in the same command; a host wait's retry runs no requires.check. On either wait, a stage whose child run failed continues that child in place, inheriting its completed steps and rerunning the rest. An ended run that did not succeed continues from the stage it stood at: for a workflow of edges the step its latest attempt started last, for a Cloud run the step of the position it reported, and otherwise every step its latest attempt left unfinished; a run that names none is refused, naming --from and --all. In any other state, a run that is running or waits on another kind of wait, the command changes nothing and names the commands that apply.

A run under the home runs in the previous attempt's execution root unless --execution-root names another. For a Cloud run the command asks Cloud for the continuation, the retry, or the repair the runner applies, under one request key sent again if the response is lost; --expected-version requires the run's version, and --wait follows a continuation until it settles, within --timeout. A retry with --all is always followed. Cloud's acceptance is not the runner's application. If the Cloud run lost its runner, request a replacement with useful workflow run handover RUN.";

const COMMAND: &str = "useful workflow run retry";

// Run, retry, and status intentionally compose different subsets of shared workflow options.
#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(flatten)]
    run: RunArg,

    #[arg(
        long = "from",
        value_name = "STEP",
        help = "Ordinary step to rerun from (repeatable)"
    )]
    from_steps: Vec<String>,

    #[arg(
        long,
        conflicts_with_all = ["from_steps", "workflow"],
        help = "Rerun every step as a new attempt"
    )]
    all: bool,

    #[arg(
        long,
        value_name = "FILE",
        help = "Replacement workflow file within the run's original source root, for a run under the useful home"
    )]
    workflow: Option<PathBuf>,

    #[arg(
        long,
        value_name = "PATH",
        help = "Existing execution root, for a run under the useful home; defaults to the previous attempt's root"
    )]
    execution_root: Option<PathBuf>,

    #[arg(
        long,
        requires = "execution_root",
        conflicts_with = "all",
        help = "Continue only if the selected work can run without the previous execution root"
    )]
    handover: bool,

    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["from_steps", "all"],
        help = "Replace declared agent profiles with the closed replacement document at PATH"
    )]
    agent_profiles: Option<PathBuf>,

    #[arg(long, value_name = "VERSION", value_parser = clap::value_parser!(i64).range(1..),
        help = "Require this positive run version at admission, for a Cloud run")]
    expected_version: Option<i64>,

    #[arg(long, help = "Observe a Cloud run's continuation until it settles")]
    wait: bool,

    #[arg(long, value_name = "DURATION", value_parser = super::super::super::parse_wait_timeout,
        help = super::super::super::WAIT_TIMEOUT_HELP)]
    timeout: Option<Duration>,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    presentation: super::PresentationOptions,

    #[command(flatten)]
    authentication: PrincipalAuthenticationArgs,

    #[command(flatten)]
    http: HttpOptions,
}

/// What a local `retry` reruns.
enum Rerun {
    /// `--from`: a continuation from the named steps.
    From(Vec<String>),
    /// `--all`: a new attempt of every step.
    All,
    /// Neither: a repair wait's retry or an ended run's continuation.
    Default,
}

impl Command {
    /// Finds the run and reruns it: a run under the home as `rerun` selects, and a Cloud run
    /// through the API. An option the place the run is found in does not read is a usage
    /// error, exit 2.
    pub(super) fn execute(mut self) -> super::super::super::CommandResult {
        let json = self.presentation.output.json;
        let found = match super::control::find(
            COMMAND,
            &self.run,
            &self.org,
            &self.authentication,
            &self.http,
            json,
        ) {
            Ok(found) => found,
            Err(result) => return result,
        };
        let run = match found {
            Found::Home(run_directory) => run_directory,
            Found::Cloud(run) => return self.in_cloud(*run),
        };
        if let Some(option) = [
            self.expected_version.map(|_| "--expected-version"),
            self.wait.then_some("--wait"),
            self.timeout.map(|_| "--timeout"),
        ]
        .into_iter()
        .flatten()
        .next()
        {
            return Err(usage(format!(
                "{option} applies to a Cloud run, and RUN names a run under the useful home\n\n\
                 Leave out {option}: the command reruns a run under the home itself."
            )));
        }
        let rerun = if self.all {
            Rerun::All
        } else if self.from_steps.is_empty() {
            Rerun::Default
        } else {
            Rerun::From(std::mem::take(&mut self.from_steps))
        };
        super::create::execute_with_runtime(
            "start local workflow retry runtime",
            self.execute_async(run, rerun),
        )
    }

    /// Reruns the Cloud run the lookup found: `--from` as the continuation request, `--all` as
    /// the retry request, and neither as `CloudRun::retry` chooses.
    fn in_cloud(self, run: InCloud) -> super::super::super::CommandResult {
        if self.handover {
            return Err(super::handover::local_option_on_cloud());
        }
        if let Some(option) = [
            self.workflow.as_ref().map(|_| "--workflow"),
            self.execution_root.as_ref().map(|_| "--execution-root"),
            self.agent_profiles.as_ref().map(|_| "--agent-profiles"),
        ]
        .into_iter()
        .flatten()
        .next()
        {
            return Err(usage(format!(
                "{option} applies to a run under the useful home, and RUN names a Cloud run\n\n\
                 Leave out {option}: the runner executing the Cloud run reruns it."
            )));
        }
        // A retry of every step is always followed; a continuation only with `--wait`.
        if !self.all && self.timeout.is_some() && !self.wait {
            return Err(usage(
                "--timeout bounds --wait, and --wait is not given\n\n\
                 Give --wait with --timeout, or leave out --timeout."
                    .to_owned(),
            ));
        }
        for step in &self.from_steps {
            parse_continuation_step(step).map_err(|reason| {
                usage(format!(
                    "invalid value '{step}' for '--from <STEP>': {reason}"
                ))
            })?;
        }
        let json = self.presentation.output.json;
        let cloud = super::cloud::CloudRun::found(run, self.authentication, self.http, json, false);
        let wait = RunWaitArgs {
            wait: self.wait,
            timeout: self.timeout,
        };
        if self.all {
            cloud.rerun(self.expected_version, self.timeout)
        } else if self.from_steps.is_empty() {
            cloud.retry(self.expected_version, wait)
        } else {
            cloud.continue_from(COMMAND, self.from_steps, self.expected_version, wait, None)
        }
    }

    async fn execute_async(
        self,
        run_directory: PathBuf,
        rerun: Rerun,
    ) -> super::super::super::CommandResult {
        let presentation_config = super::create::presentation_config(&self.presentation);
        let json = self.presentation.output.json;
        match rerun {
            Rerun::From(from_steps) => {
                return self
                    .continue_from(run_directory, from_steps, presentation_config)
                    .await;
            }
            Rerun::All => {}
            Rerun::Default => {
                let inspected = {
                    let run_directory = run_directory.clone();
                    tokio::task::spawn_blocking(move || inspect_wait(&run_directory, &NoConditions))
                        .await
                        .map_err(anyhow::Error::new)?
                        .map_err(anyhow::Error::new)?
                };
                let refuse = |refusal: &Refusal| {
                    super::control::write_refusal(
                        COMMAND,
                        Some(&inspected.run_directory),
                        refusal,
                        json,
                    )
                };
                return match &inspected.inspection {
                    WaitInspection::Held { .. }
                    | WaitInspection::Satisfied { .. }
                    | WaitInspection::RuleInvalid { .. }
                    | WaitInspection::ConditionUnavailable { .. } => {
                        let target = super::control::open(&run_directory);
                        self.retry_wait(&run_directory, target, presentation_config)
                            .await
                    }
                    WaitInspection::Locked(_) => refuse(&super::control::run_locked()),
                    // A run whose process is gone continues with `resume`.
                    WaitInspection::NoWait {
                        state: Some(RunState::Running),
                        ..
                    }
                    | WaitInspection::Continued { .. } => refuse(&super::control::run_not_live()),
                    WaitInspection::NoWait {
                        state: Some(RunState::Waiting),
                        ..
                    } => refuse(&Refusal::new(
                        "wait_record_missing",
                        "The run reads waiting but holds no wait record; rerun it from a step with --from STEP.",
                    )),
                    WaitInspection::NoWait { .. } => {
                        self.continue_from(run_directory, Vec::new(), presentation_config)
                            .await
                    }
                };
            }
        }
        // `--all` of a run that waits is refused before anything is written, naming its state
        // and the verbs that apply.
        let waiting = {
            let run_directory = run_directory.clone();
            tokio::task::spawn_blocking(move || super::control::waiting(&run_directory))
                .await
                .map_err(anyhow::Error::new)?
        };
        if let Some(standing) = waiting {
            return super::control::write_refusal(
                COMMAND,
                Some(&run_directory),
                &standing.refusal("run_waiting", super::control::Placed::Home),
                json,
            );
        }
        let execution_root = self.execution_root.clone();
        let cancellation = CancellationSource::new();
        let signal_task = super::create::start_signal_observation(
            cancellation.clone(),
            super::create::UnixSignals::new()?,
        );
        // A signal reads the run's control journal from here on, before the attempt begins,
        // as `continue_run` does for a resume.
        let _journal = signal_task.watch(&run_directory);
        let opened = match tokio::task::spawn_blocking(move || {
            reconcile_current_result_publication(&run_directory).map_err(|error| {
                anyhow::anyhow!("finalize workflow result publication: {error:?}")
            })?;
            // A test seam between the inspection and the lock; nothing outside `test-fixtures`.
            await_run_lock_gate()?;
            acquire_local_retry(&run_directory).map_err(anyhow::Error::new)
        })
        .await
        {
            Ok(opened) => opened,
            Err(_) => {
                signal_task.abort();
                return Err(anyhow::anyhow!("inspect local workflow retry state").into());
            }
        };
        let pending = match opened {
            Ok(LocalRetryOpen::Acquired(pending)) => *pending,
            Ok(LocalRetryOpen::Rejected(rejection)) => {
                signal_task.abort();
                return render_retry_rejection(presentation_config, &rejection);
            }
            Err(error) => {
                signal_task.abort();
                return Err(error.into());
            }
        };
        // With no `--execution-root` the attempt runs where the previous one ran, which the
        // reuse warning then names.
        let execution_root = match execution_root {
            Some(execution_root) => execution_root,
            None => match pending.prior_execution_root() {
                Ok(execution_root) => execution_root,
                Err(error) => {
                    signal_task.abort();
                    return super::create::diagnose(error);
                }
            },
        };
        // A withdrawal no process honored over the run's open latest attempt ends the run
        // `withdrawn` without an attempt, as `resume` ends it; the settlement `begin` makes
        // would spend it.
        if matches!(pending.withdrawal_unhonored(), Ok(true)) {
            return end_withdrawn(pending, &signal_task, &presentation_config).await;
        }
        let (workflow, inputs, maximum_parallel_steps) = {
            let (workflow, inputs, maximum_parallel_steps) = pending.execution_specification();
            (workflow.clone(), inputs.clone(), maximum_parallel_steps)
        };
        // A run admitted from a tree retries only from an unchanged copy.
        let (pending, verified) = match tokio::task::spawn_blocking(move || {
            let verified = pending.verify_tree_copy();
            (pending, verified)
        })
        .await
        {
            Ok(verified) => verified,
            Err(_) => {
                signal_task.abort();
                return Err(anyhow::anyhow!("verify local workflow tree copy").into());
            }
        };
        let tree = match verified {
            None => None,
            Some(Ok(tree)) => Some(tree),
            Some(Err(mismatch)) => {
                signal_task.abort();
                let output =
                    WorkflowRunOutput::new(presentation_config, io::stdout(), io::stderr())
                        .for_retry(pending.run_directory());
                return super::create::rejection_exit(
                    output.render_tree_copy_rejection(&workflow.source.workflow_path, &mismatch),
                );
            }
        };
        let tree_copy = pending.tree_copy().map(|(copy_root, _)| copy_root);
        let workflow_for_context = workflow.clone();
        let context_cancellation = cancellation.clone();
        let mut context = match super::create::blocking_operation(move || {
            super::create::execution_context_for_workflow(
                &workflow_for_context,
                execution_root,
                maximum_parallel_steps,
                context_cancellation,
            )
        })
        .await
        {
            Ok(context) => context,
            Err(super::create::BlockingOperationError::Operation(failure)) => {
                signal_task.abort();
                let output =
                    WorkflowRunOutput::new(presentation_config, io::stdout(), io::stderr())
                        .for_retry(pending.run_directory());
                return super::create::rejection_exit(
                    output.render_agent_harness_installation_rejection(&workflow, &failure),
                );
            }
            Err(super::create::BlockingOperationError::WorkerUnavailable) => {
                signal_task.abort();
                return Err(anyhow::anyhow!("prepare local workflow retry context").into());
            }
        };
        if workflow.requires_git_capture() {
            context = context.with_local_git_baseline(pending.git_baseline().cloned());
        }
        if let Some(tree) = tree {
            context = context.with_tree(tree);
        }
        // The revision the run was created with.
        if let Some(source_revision) = pending.source_revision() {
            context = context.with_source_revision(source_revision.clone());
        }
        let untested_advisories = context.untested_harness_advisories();
        let workflow_for_admission = workflow.clone();
        let admitted = match super::create::blocking_operation(move || {
            admit_local_workflow(workflow_for_admission, inputs, context)
        })
        .await
        {
            Ok(admitted) => admitted,
            Err(super::create::BlockingOperationError::Operation(failure)) => {
                signal_task.abort();
                let output =
                    WorkflowRunOutput::new(presentation_config, io::stdout(), io::stderr())
                        .for_retry(pending.run_directory());
                return super::create::rejection_exit(
                    output.render_admission_rejection(&workflow, &failure),
                );
            }
            Err(super::create::BlockingOperationError::WorkerUnavailable) => {
                signal_task.abort();
                return Err(anyhow::anyhow!("admit local workflow retry").into());
            }
        };
        if workflow.source.source_root.to_str().is_none()
            || admitted.execution().root().to_str().is_none()
        {
            signal_task.abort();
            return Err(anyhow::anyhow!("prepare local workflow retry paths").into());
        }
        let admitted = match tree_copy {
            Some(copy_root) => match super::create::bind_tree_copy(admitted, &copy_root) {
                Ok(admitted) => admitted,
                Err(error) => {
                    signal_task.abort();
                    return Err(error.into());
                }
            },
            None => admitted,
        };
        super::create::write_untested_advisories(&untested_advisories);

        let reused_attempts = match pending.reused_execution_root_attempts(&admitted) {
            Ok(attempts) => attempts,
            Err(error) => {
                signal_task.abort();
                return super::create::diagnose(error);
            }
        };
        if !reused_attempts.is_empty()
            && let Err(error) = write_reuse_warning(admitted.execution().root(), &reused_attempts)
        {
            signal_task.abort();
            return Err(anyhow::Error::new(error)
                .context("write workflow retry warning")
                .into());
        }

        // An interruption held before the attempt begins starts none, and the run is released
        // as it was; a signal that carries a recorded `control.cancel` is a cancellation, which
        // begins the attempt and cancels it.
        if cancellation.interruption_requested() {
            drop(pending);
            signal_task.abort();
            return Err(super::create::signalled_before_attempt(
                cancellation.cancellation_reason(),
            ));
        }
        let admitted_for_begin = admitted.clone();
        // The attempt begins under the controls lock only once no withdrawal is unhonored over
        // the run, one recorded since the check above included; otherwise the retry is handed
        // back to end the run `withdrawn`.
        let begun = tokio::task::spawn_blocking(move || {
            // A test seam before the controls lock; nothing outside `test-fixtures`.
            await_begin_gate()?;
            let controls = pending.lock_controls()?;
            if matches!(pending.withdrawal_unhonored(), Ok(true)) {
                drop(controls);
                return Ok(super::resume::Begun::Withdrawn(Box::new(pending)));
            }
            let owned_run = pending.begin(&admitted_for_begin);
            drop(controls);
            owned_run.map(|owned_run| super::resume::Begun::Owned(Box::new(owned_run)))
        })
        .await;
        let owned_run = match begun {
            Ok(Ok(super::resume::Begun::Owned(owned_run))) => *owned_run,
            Ok(Ok(super::resume::Begun::Withdrawn(pending))) => {
                return end_withdrawn(*pending, &signal_task, &presentation_config).await;
            }
            Ok(Err(LocalRetryBeginError::Rejected(rejection))) => {
                signal_task.abort();
                return render_retry_rejection(presentation_config, &rejection);
            }
            Ok(Err(LocalRetryBeginError::Operational(error))) => {
                signal_task.abort();
                return super::create::diagnose(error);
            }
            Err(_) => {
                signal_task.abort();
                return Err(anyhow::anyhow!("commit local workflow retry attempt").into());
            }
        };
        super::create::execute_owned_attempt(
            workflow,
            admitted,
            owned_run,
            cancellation,
            signal_task,
            presentation_config,
            super::create::ExecutionLeaf::Retry,
        )
        .await
    }
}

impl Command {
    /// `retry --from`, or `retry` of an ended run with `from_steps` empty, which continues
    /// from the stage it stood at: the continuation `resume::continue_run` starts, its
    /// documents naming `retry`.
    async fn continue_from(
        &self,
        run_directory: PathBuf,
        from_steps: Vec<String>,
        config: useful_execution::PresentationConfig,
    ) -> super::super::super::CommandResult {
        if from_steps.is_empty() && self.agent_profiles.is_some() {
            return Err(usage(
                "--agent-profiles replaces the profiles of a retry of a run waiting for repair, and the run does not wait\n\n\
                 Leave out --agent-profiles."
                    .to_owned(),
            ));
        }
        let cancellation = CancellationSource::new();
        let signal_task = super::create::start_signal_observation(
            cancellation.clone(),
            super::create::UnixSignals::new()?,
        );
        super::resume::continue_run(
            super::resume::Continuation {
                run_directory,
                from_steps,
                workflow: self.workflow.clone(),
                execution_root: self.execution_root.clone(),
                handover: self.handover,
                leaf: super::create::ExecutionLeaf::Retry,
                edge: None,
                bridge: None,
            },
            config,
            cancellation,
            signal_task,
        )
        .await
    }

    /// `retry` on a waiting run: on a `repair` or `host` wait, records `control.retry`
    /// naming it and continues the run as `resume` does.
    async fn retry_wait(
        &self,
        run_directory: &Path,
        target: Result<ControlTarget, Refusal>,
        config: useful_execution::PresentationConfig,
    ) -> super::super::super::CommandResult {
        let json = self.presentation.output.json;
        let refuse = |run_directory: &Path, refusal: &Refusal| {
            super::control::write_refusal(COMMAND, Some(run_directory), refusal, json)
        };
        let target = match target {
            Ok(target) => target,
            Err(refusal) => return refuse(run_directory, &refusal),
        };
        // A wait whose rule the matcher refuses is left to the continuation to report.
        let wait = match &target.inspection {
            WaitInspection::Held { wait }
            | WaitInspection::Satisfied { wait, .. }
            | WaitInspection::RuleInvalid { wait, .. }
            | WaitInspection::ConditionUnavailable { wait, .. }
                if !matches!(wait.kind, WaitKind::Repair | WaitKind::Host) =>
            {
                return refuse(&target.run_directory, &target.refusal("wait_kind_mismatch"));
            }
            WaitInspection::Held { wait } => Some(wait),
            WaitInspection::RuleInvalid { .. } | WaitInspection::ConditionUnavailable { .. } => {
                None
            }
            WaitInspection::Satisfied { .. } => {
                return refuse(&target.run_directory, &super::control::wait_resolved());
            }
            WaitInspection::Locked(_) => {
                return refuse(&target.run_directory, &super::control::run_locked());
            }
            WaitInspection::NoWait { .. } | WaitInspection::Continued { .. } => {
                return refuse(
                    &target.run_directory,
                    &Refusal::new(
                        "wait_changed",
                        "The run's wait changed while the command inspected it; run the command again.",
                    ),
                );
            }
        };
        let cancellation = CancellationSource::new();
        if let Some(wait) = wait {
            let payload = match &self.agent_profiles {
                Some(path) => Some(replacement_payload(path, &cancellation)?),
                None => None,
            };
            match target.record(CONTROL_RETRY, Some(wait.id()), payload) {
                Ok(_) => {}
                Err(ControlFailure::Refused(refusal)) => {
                    return refuse(&target.run_directory, &refusal);
                }
                Err(ControlFailure::Failed(error)) => return Err(error.into()),
            }
        }
        let signal_task = super::create::start_signal_observation(
            cancellation.clone(),
            super::create::UnixSignals::new()?,
        );
        super::resume::continue_run(
            super::resume::Continuation {
                run_directory: target.run_directory,
                from_steps: Vec::new(),
                workflow: self.workflow.clone(),
                execution_root: self.execution_root.clone(),
                handover: self.handover,
                leaf: super::create::ExecutionLeaf::Retry,
                edge: None,
                bridge: None,
            },
            config,
            cancellation,
            signal_task,
        )
        .await
    }
}

/// A usage error, exit 2.
fn usage(message: String) -> super::super::super::CommandFailure {
    super::super::super::CommandFailure::with_exit_code(anyhow!(message), ExitCode::UsageError)
}

/// The `control.retry` payload for the replacement document at `path`: its
/// `agentProfiles` member as `agentProfiles`.
fn replacement_payload(
    path: &Path,
    cancellation: &CancellationSource,
) -> Result<serde_json::Map<String, serde_json::Value>, super::super::super::CommandFailure> {
    let document = super::create::acquire_agent_profile_replacement(path, cancellation)?;
    let profiles = serde_json::from_slice::<serde_json::Value>(document.bytes())
        .ok()
        .and_then(|mut document| document.get_mut("agentProfiles").map(serde_json::Value::take))
        .filter(serde_json::Value::is_object)
        .ok_or_else(|| {
            anyhow!(
                "agent profile replacement document: not a JSON document with an agentProfiles object"
            )
        })?;
    Ok(serde_json::Map::from_iter([(
        "agentProfiles".to_owned(),
        profiles,
    )]))
}

/// Ends the `running` run `pending` holds `withdrawn` without an attempt through
/// `PendingLocalRetry::end_running`, as `resume` ends it (`resume::end_withdrawn`), reported on
/// the retry's own documents. The caller holds no controls lock.
async fn end_withdrawn(
    pending: PendingLocalRetry,
    signal_task: &super::create::SignalObservation,
    config: &useful_execution::PresentationConfig,
) -> super::super::super::CommandResult {
    let attempt_number = match pending.prior_attempt_number() {
        Ok(attempt_number) => attempt_number,
        Err(error) => {
            signal_task.abort();
            return super::create::diagnose(error);
        }
    };
    let (workflow, inputs, _) = pending.execution_specification();
    let unattempted = super::resume::Unattempted::new(
        pending.run_directory(),
        attempt_number,
        (workflow, inputs),
        WorkflowRunOutput::new(config.clone(), io::stdout(), io::stderr())
            .for_retry(pending.run_directory()),
    );
    super::resume::end_withdrawn(
        pending,
        unattempted,
        signal_task,
        config,
        super::create::ExecutionLeaf::Retry,
        |pending| pending.end_running(WITHDRAWN_OUTCOME),
    )
    .await
}

fn render_retry_rejection(
    config: useful_execution::PresentationConfig,
    rejection: &useful_execution::LocalRetryRejection,
) -> super::super::super::CommandResult {
    let output = WorkflowRunOutput::new(config, io::stdout(), io::stderr())
        .for_retry(rejection.run_directory());
    super::create::rejection_exit(output.render_retry_rejection(rejection))
}

fn write_reuse_warning(execution_root: &std::path::Path, attempts: &[u64]) -> io::Result<()> {
    let standard_error = io::stderr();
    let mut standard_error = standard_error.lock();
    let attempts = attempts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    writeln!(
        standard_error,
        "! Execution root {execution_root:?} was used by earlier attempt(s) {attempts} and may contain prior changes; Useful Machinery does not check cleanliness or mutations."
    )?;
    standard_error.flush()
}
