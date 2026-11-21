//! The host condition (REQ-WFEXEC-81): what `useful workflow run resume` evaluates for a run
//! waiting on `host`. It observes `host.healthy` once every `requires.tools` name of the
//! run's root resolves, as admission resolves it, and the root's `requires.check`, when
//! declared, exits zero within its bound. It reads the run's own records and tree copy, runs
//! the check in the latest attempt's execution root with the environment a root step has,
//! and writes nothing in the run directory.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;

use super::admission::{
    EnvironmentSnapshot, declared_integration_environment_names, find_program, program_directories,
    program_search_directories, unavailable_required_tool,
};
use super::local_run::{LocalRunDirectoryError, host_condition_run};
use super::resolution::{ResolvedWorkflow, resolve};
use super::wait::{ExternalEvent, HOST_HEALTHY, HOST_SOURCE, WaitRecord};
use crate::process::ManagedProcessGroup;

/// How long `requires.check` may run before its process group is killed and the wait holds
/// (REQ-WFEXEC-81).
pub const HOST_CHECK_BOUND: Duration = Duration::from_secs(60);

/// How often a running check is polled for its exit.
const CHECK_POLL: Duration = Duration::from_millis(20);

/// The root workflow file of a tree copy (REQ-WFDEF-8).
const ROOT_WORKFLOW: &str = "workflow.yaml";

/// Evaluates the host condition for the run at `run_directory`, waiting on the `host` wait
/// `wait`, from `environment`, the environment `resume` was given, with `bound` on the
/// check (`HOST_CHECK_BOUND`). A healthy host answers one `host.healthy` event naming the
/// run and the wait, which the wait's derived rule matches (REQ-WFEXEC-80); a host that is
/// not answers none, so the wait holds. A run whose records or tree copy cannot be read is
/// the run's own error.
pub fn observe_host_condition(
    run_directory: &Path,
    wait: &WaitRecord,
    environment: &EnvironmentSnapshot,
    bound: Duration,
) -> Result<Vec<ExternalEvent>, LocalRunDirectoryError> {
    let run = host_condition_run(run_directory)?;
    let root = resolve(&run.tree_copy, Path::new(ROOT_WORKFLOW)).map_err(|_| {
        LocalRunDirectoryError::StateFile {
            path: run.tree_copy.join(ROOT_WORKFLOW),
            operation: "resolve",
            source: Box::new(LocalRunDirectoryError::StateInvalid),
        }
    })?;
    let healthy = HostContext::of(&root, &run.tree_copy, &run.execution_root, environment)
        .is_some_and(|context| context.is_healthy(bound));
    Ok(if healthy {
        vec![healthy_event(&run.run_id, wait)]
    } else {
        Vec::new()
    })
}

/// What the condition reads of the root and the run.
struct HostContext<'a> {
    tools: &'a [String],
    check: Option<&'a [String]>,
    /// The run's copy of each `programs` directory, in declared order.
    programs: Vec<PathBuf>,
    execution_root: &'a Path,
    /// The environment `resume` was given, narrowed as a root step's is (REQ-WFEXEC-71).
    inherited: EnvironmentSnapshot,
    /// `inherited` with the tree copy's `PATH` and `USEFUL_WORKFLOW_ROOT` (REQ-WFEXEC-53).
    check_environment: EnvironmentSnapshot,
}

impl<'a> HostContext<'a> {
    /// `None` when the copy root cannot be a `PATH` entry, which holds the wait as an
    /// unlaunchable check does.
    fn of(
        root: &'a ResolvedWorkflow,
        tree_copy: &Path,
        execution_root: &'a Path,
        environment: &EnvironmentSnapshot,
    ) -> Option<Self> {
        let blocks = root.definition.root.as_ref();
        let requires = blocks.and_then(|blocks| blocks.requires.as_ref());
        let programs = blocks.map_or(&[][..], |blocks| &blocks.programs[..]);
        let inherited = environment.for_workflow_children(
            &root.definition.environment_passthrough,
            &declared_integration_environment_names(None, root),
        );
        let check_environment = inherited.with_tree_copy(tree_copy, programs).ok()?;
        Some(Self {
            tools: requires.map_or(&[][..], |requires| &requires.tools[..]),
            check: requires.and_then(|requires| requires.check.as_deref()),
            programs: program_directories(programs, tree_copy).collect(),
            execution_root,
            inherited,
            check_environment,
        })
    }

    fn is_healthy(&self, bound: Duration) -> bool {
        if unavailable_required_tool(
            self.programs.iter().cloned(),
            self.tools,
            &self.inherited,
            self.execution_root,
        )
        .is_some()
        {
            return false;
        }
        let Some((program, arguments)) = self.check.and_then(<[String]>::split_first) else {
            return true;
        };
        let directories = program_search_directories(
            self.programs.iter().cloned(),
            &self.inherited,
            self.execution_root,
        );
        find_program(&directories, program).is_some_and(|program| {
            run_check(
                &program,
                arguments,
                self.execution_root,
                &self.check_environment,
                bound,
            )
            .is_some_and(|status| status.success())
        })
    }
}

/// Runs the check in its own process group in `execution_root`, with standard input and
/// output null and standard error inherited, and answers its exit status. The group is
/// killed once the leader exits (`ManagedProcessGroup`). A check that cannot be launched
/// answers `None`; so does one that outlives `bound`, whose process group is killed and
/// whose leader is reaped.
fn run_check(
    program: &Path,
    arguments: &[String],
    execution_root: &Path,
    environment: &EnvironmentSnapshot,
    bound: Duration,
) -> Option<ExitStatus> {
    let mut check = ManagedProcessGroup::spawn(
        Command::new(program)
            .args(arguments)
            .current_dir(execution_root)
            .env_clear()
            .envs(environment.variables())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit()),
    )
    .ok()?;
    let started = useful_support::monotonic_now();
    loop {
        match check.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if useful_support::elapsed(started) < bound => {
                useful_support::sleep(CHECK_POLL);
            }
            Ok(None) | Err(_) => {
                check.terminate();
                return None;
            }
        }
    }
}

/// `{source: host, event: host.healthy, payload: {run, wait}}` (REQ-WFEXEC-80).
fn healthy_event(run_id: &str, wait: &WaitRecord) -> ExternalEvent {
    let mut payload = Map::new();
    payload.insert("run".to_owned(), Value::String(run_id.to_owned()));
    payload.insert("wait".to_owned(), Value::String(wait.id()));
    ExternalEvent {
        source: HOST_SOURCE.to_owned(),
        event: HOST_HEALTHY.to_owned(),
        at: useful_support::utc_now()
            .format(&Rfc3339)
            .unwrap_or_default(),
        payload,
    }
}

#[cfg(test)]
mod tests;
