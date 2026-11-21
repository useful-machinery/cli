use std::env;
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Map, Value, json};

use super::*;
use crate::workflow::admission::{
    CancellationPolicy, CancellationSource, CaptureLimits, ExecutionContext, ExecutionPolicyLimits,
    InputLimits, ResolvedInputs, admit_workflow,
};
use crate::workflow::local_run::InitialLocalRun;
use crate::workflow::run_record::WorkflowRunRecord;
use crate::workflow::wait::{WaitKind, derive_rule, evaluate};

/// A bound short enough for a test of a check that outlives it and long enough for the
/// check's shell to start on a loaded host.
const SHORT_BOUND: Duration = Duration::from_secs(1);

/// A tree run's directory, created by `InitialLocalRun` from a root that declares
/// `programs: [bin]` and the given blocks, with the tree's read-only copy made writable
/// again when the fixture drops so the temporary directory can be removed.
struct HostRun {
    temporary: tempfile::TempDir,
    run: PathBuf,
    execution_root: PathBuf,
}

impl HostRun {
    fn create(blocks: &str, programs: &[(&str, &str)]) -> Self {
        Self::admitted_in(blocks, programs, EnvironmentSnapshot::default())
    }

    fn admitted_in(
        blocks: &str,
        programs: &[(&str, &str)],
        environment: EnvironmentSnapshot,
    ) -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(temporary.path()).unwrap();
        let source = base.join("source");
        let execution_root = base.join("execution");
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::create_dir(&execution_root).unwrap();
        fs::write(
            source.join("workflow.yaml"),
            format!(
                "schemaVersion: 1\nprograms: [bin]\n{blocks}steps:\n  build:\n    kind: cmd\n    command:\n      argv: [\"true\"]\n"
            ),
        )
        .unwrap();
        fs::write(source.join("bin/readme.txt"), "").unwrap();
        for (name, script) in programs {
            let path = source.join("bin").join(name);
            fs::write(&path, script).unwrap();
            fs::set_permissions(&path, Permissions::from_mode(0o755)).unwrap();
        }
        let tree = crate::workflow::validate_workflow_tree(&source)
            .unwrap_or_else(|diagnostics| panic!("tree should be valid: {diagnostics:?}"));
        let digest = format!("sha256:{}", tree.digest.value);
        let workflow =
            crate::workflow::resolution::resolve(&source, Path::new("workflow.yaml")).unwrap();
        let context = ExecutionContext::new(
            execution_root.clone(),
            ExecutionPolicyLimits::new(
                2,
                CaptureLimits::new(16, 1024, 4096),
                InputLimits::new(16, 1024, 4096, 4096),
                1024,
            ),
            environment,
            CancellationPolicy::new(CancellationSource::new(), Duration::from_secs(10)),
        )
        .with_tree(tree);
        let admitted = admit_workflow(workflow, ResolvedInputs::default(), context).unwrap();
        let run = base.join("run");
        let record = WorkflowRunRecord::new(None, &digest, "workflow.yaml", "tester");
        drop(InitialLocalRun::create_with_record(&run, &admitted, Some(&record)).unwrap());
        Self {
            temporary,
            run,
            execution_root,
        }
    }

    fn copy(&self) -> PathBuf {
        self.run.join("workflow/tree")
    }

    fn run_id(&self) -> String {
        let record: Value =
            serde_json::from_slice(&fs::read(self.run.join("run.json")).unwrap()).unwrap();
        record["id"].as_str().unwrap().to_owned()
    }

    fn observe(&self, environment: &EnvironmentSnapshot, bound: Duration) -> Vec<ExternalEvent> {
        observe_host_condition(&self.run, &host_wait(), environment, bound).unwrap()
    }

    /// Whether the host condition, over `environment`, finds the host healthy: one
    /// `host.healthy` event naming the run and the wait, which the wait's rule matches.
    fn healthy(&self, environment: &EnvironmentSnapshot) -> bool {
        let events = self.observe(environment, HOST_CHECK_BOUND);
        let wait = host_wait();
        let matched = evaluate(&wait.rule, &self.run_id(), &wait, &events)
            .unwrap()
            .is_some();
        if let [event] = &events[..] {
            assert_eq!(event.source, "host");
            assert_eq!(event.event, "host.healthy");
            assert_eq!(
                Value::Object(event.payload.clone()),
                json!({"run": self.run_id(), "wait": wait.id()})
            );
            assert!(matched, "{event:?}");
        } else {
            assert!(events.is_empty(), "{events:?}");
        }
        matched
    }
}

impl Drop for HostRun {
    fn drop(&mut self) {
        fn restore(directory: &Path) {
            if fs::set_permissions(directory, Permissions::from_mode(0o755)).is_err() {
                return;
            }
            for entry in fs::read_dir(directory).into_iter().flatten().flatten() {
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    restore(&entry.path());
                }
            }
        }
        restore(&self.temporary.path().join("run/workflow/tree"));
    }
}

/// The `host` wait the run waits on, as an edge enters it (REQ-WFEXEC-80).
fn host_wait() -> WaitRecord {
    WaitRecord {
        kind: WaitKind::Host,
        since: "2026-11-21T09:00:00Z".to_owned(),
        step: vec![json!("build")],
        then: "build".to_owned(),
        on_hand_back: None,
        rule: derive_rule(WaitKind::Host, false).unwrap(),
        payload: Map::new(),
    }
}

/// The environment `resume` is given: this process's `PATH`, so a check's shell finds the
/// host's programs, and `extra`.
fn resume_environment(extra: &[(&str, &str)]) -> EnvironmentSnapshot {
    let mut variables = vec![("PATH".to_owned(), env::var("PATH").unwrap())];
    variables.extend(
        extra
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    EnvironmentSnapshot::new(variables)
}

// REQ-WFEXEC-81: a root that declares neither tools nor a check is healthy at once.
#[test]
fn a_root_without_tools_or_a_check_is_healthy() {
    let run = HostRun::create("", &[]);
    assert!(run.healthy(&resume_environment(&[])));
}

// REQ-WFEXEC-81, REQ-WFEXEC-55: each required tool resolves on the run's copy of its
// programs or on the given `PATH`; one that resolves on neither holds the wait.
#[test]
fn a_required_tool_missing_from_the_copy_and_path_holds() {
    let run = HostRun::create(
        "requires:\n  tools: [copied]\n",
        &[("copied", "#!/bin/sh\n")],
    );
    assert!(run.healthy(&EnvironmentSnapshot::default()));

    let host = tempfile::tempdir().unwrap();
    let tool = host.path().join("host-tool");
    fs::write(&tool, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&tool, Permissions::from_mode(0o755)).unwrap();
    let on_path = EnvironmentSnapshot::new([("PATH", host.path().as_os_str())]);
    let run = HostRun::admitted_in("requires:\n  tools: [host-tool]\n", &[], on_path.clone());
    assert!(run.healthy(&on_path));
    assert!(!run.healthy(&resume_environment(&[])));
}

// REQ-WFEXEC-81: the check's exit status decides, and a check that cannot be launched holds.
#[test]
fn the_check_is_healthy_only_when_it_exits_zero() {
    let run = HostRun::create(
        "requires:\n  check: {argv: [host-check, pass]}\n",
        &[("host-check", "#!/bin/sh\ntest -e \"$1\"\n")],
    );
    let environment = resume_environment(&[]);
    assert!(!run.healthy(&environment));
    fs::write(run.execution_root.join("pass"), "").unwrap();
    assert!(run.healthy(&environment));

    let missing = HostRun::create("requires:\n  check: {argv: [absent]}\n", &[]);
    assert!(!missing.healthy(&environment));
}

// REQ-WFEXEC-81: a check that outlives its bound holds the wait, and its process group is
// killed, so a process it started does nothing after the bound.
#[test]
fn a_check_past_its_bound_holds_and_its_process_group_is_killed() {
    let run = HostRun::create(
        "requires:\n  check: {argv: [slow]}\n",
        &[(
            "slow",
            "#!/bin/sh\n: > started\n(sleep 3; : > late) &\nsleep 30\n",
        )],
    );
    let started = useful_support::monotonic_now();
    assert!(
        run.observe(&resume_environment(&[]), SHORT_BOUND)
            .is_empty()
    );
    assert!(useful_support::elapsed(started) < Duration::from_secs(10));
    // The check ran, so the bound is what ended it.
    assert!(run.execution_root.join("started").exists());
    useful_support::sleep(Duration::from_secs(3));
    assert!(!run.execution_root.join("late").exists());
}

// REQ-WFEXEC-81, REQ-WFEXEC-53, REQ-WFEXEC-71: the check runs in the execution root with a
// root step's environment, the copy's programs leading `PATH`, and its standard input closed.
#[test]
fn the_check_runs_in_the_execution_root_with_a_root_steps_environment() {
    let run = HostRun::create(
        "environmentPassthrough: [KEPT]\nrequires:\n  check: {argv: [observe]}\n",
        &[(
            "observe",
            "#!/bin/sh\n\
             pwd -P > observed-cwd\n\
             printf '%s' \"$PATH\" > observed-path\n\
             printf '%s' \"$USEFUL_WORKFLOW_ROOT\" > observed-root\n\
             printf '%s' \"${KEPT-unset}\" > observed-kept\n\
             printf '%s' \"${OMITTED-unset}\" > observed-omitted\n\
             if read -r line; then printf open > observed-stdin; else printf closed > observed-stdin; fi\n\
             echo discarded\n",
        )],
    );
    assert!(run.healthy(&resume_environment(&[
        ("KEPT", "kept"),
        ("OMITTED", "omitted")
    ])));
    let observed = |name: &str| fs::read_to_string(run.execution_root.join(name)).unwrap();
    assert_eq!(
        observed("observed-cwd").trim_end(),
        run.execution_root.to_str().unwrap()
    );
    let copy = run.copy();
    assert_eq!(
        observed("observed-path"),
        format!(
            "{}:{}",
            copy.join("bin").display(),
            env::var("PATH").unwrap()
        )
    );
    assert_eq!(observed("observed-root"), copy.to_str().unwrap());
    assert_eq!(observed("observed-kept"), "kept");
    assert_eq!(observed("observed-omitted"), "unset");
    assert_eq!(observed("observed-stdin"), "closed");
}
