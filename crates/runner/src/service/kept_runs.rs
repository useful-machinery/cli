//! The kept-run pass (REQ-WORKSPACE-44, REQ-WORKSPACE-45, REQ-RUNNERENROLL-159,
//! REQ-RUNNERENROLL-165, INV-RUNNER-52): it chooses the kept workspaces the bounds remove,
//! or every one under an operator's `all`, removes each through the work root lease and
//! records each removal or failure; the service's kept-run schedule runs it
//! (REQ-RUNNERENROLL-158). The kept report (REQ-RUNNERENROLL-164) states what a pass would
//! remove now and removes nothing. The control socket's `kept` and `prune` requests reach the
//! schedule as a `KeptRunRequest` (INV-RUNNER-54).

use std::path::PathBuf;
use std::time::Duration;

use opentelemetry::KeyValue;
use time::OffsetDateTime;
use tokio::sync::oneshot;

use super::KeptRunBounds;
use super::build_caches::{CacheEviction, CacheMeasure};
use super::workspace::{KeptAttempt, KeptGroup, RetentionReason, WorkRootLease};
use crate::control_protocol::PruneScope;
use crate::telemetry::{Recorder, attribute};

/// The bound that chose a kept workspace.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum PruneBound {
    Age,
    TotalSize,
    /// An operator's prune of every kept workspace, `useful runner prune --all`.
    Operator,
}

impl PruneBound {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Age => "age",
            Self::TotalSize => "total_size",
            Self::Operator => "operator",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum PruneResult {
    Removed,
    Failed,
}

impl PruneResult {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::Failed => "failed",
        }
    }
}

/// One kept directory the pass removed or failed to remove.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PruneOutcome {
    /// The assignment directory.
    pub(super) path: PathBuf,
    /// The IDs its attempt record gives, when it reads.
    pub(super) attempt: Option<KeptAttempt>,
    pub(super) bytes: u64,
    pub(super) bound: PruneBound,
    pub(super) result: PruneResult,
}

/// What a pass would do with a kept workspace now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReportedState {
    /// Kept: no bound chooses it.
    Kept,
    /// Chosen by the bound.
    Due(PruneBound),
    /// A continuation holds it, so no pass takes it.
    InUse,
    /// Its removal failed earlier in this process and is not tried again.
    Failed,
}

/// One kept workspace as the report gives it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReportedWorkspace {
    /// Its assignment directories, the deepest parent link, the newest attempt, first.
    pub(super) paths: Vec<PathBuf>,
    /// The IDs the first directory's attempt record gives, when it reads.
    pub(super) attempt: Option<KeptAttempt>,
    /// Why the first directory's attempt was kept.
    pub(super) reason: RetentionReason,
    /// The newest modification time of its directories, from which it ages.
    pub(super) modified: OffsetDateTime,
    /// The bytes its directories hold; none while it is in use or once its removal failed.
    pub(super) bytes: Option<u64>,
    pub(super) state: ReportedState,
}

/// A control socket request the kept-run schedule serves between its passes
/// (INV-RUNNER-54). An answer's sender dropped unanswered closes the connection unanswered.
pub(super) enum KeptRunRequest {
    /// The `kept` report (REQ-RUNNERENROLL-164).
    Report {
        scope: PruneScope,
        answer: oneshot::Sender<KeptRunReport>,
    },
    /// The `prune` pass (REQ-RUNNERENROLL-165), refused while a held run is working.
    Prune {
        scope: PruneScope,
        answer: oneshot::Sender<Result<KeptRunPrune, Busy>>,
    },
}

/// What a `kept` request found: the kept workspaces and the build caches, as of `now`
/// under `scope` and `bounds`.
#[derive(Debug)]
pub(super) struct KeptRunReport {
    pub(super) scope: PruneScope,
    pub(super) bounds: KeptRunBounds,
    pub(super) now: OffsetDateTime,
    pub(super) workspaces: Vec<ReportedWorkspace>,
    pub(super) caches: Vec<CacheMeasure>,
}

/// What a `prune` pass under `scope` did, and whether it finished.
#[derive(Debug)]
pub(super) struct KeptRunPrune {
    pub(super) scope: PruneScope,
    pub(super) complete: bool,
    pub(super) directories: Vec<PruneOutcome>,
    pub(super) caches: Vec<CacheEviction>,
}

/// A `prune` refused because the pass may not run: a held run is working or the schedule
/// is stopping.
#[derive(Debug)]
pub(super) struct Busy;

/// How long ago `modified` was at `now`; a time after `now` ages as zero.
pub(super) fn age(modified: OffsetDateTime, now: OffsetDateTime) -> Duration {
    Duration::try_from(now - modified).unwrap_or(Duration::ZERO)
}

/// Chooses the kept workspaces the bounds remove, each given as the newest modification
/// time of its directories and the bytes they hold, and answers their indices in removal
/// order: those older than the age bound, oldest first, and then, while the rest hold more
/// than the size bound, the oldest of them, never the newest. A modification time after
/// `now` ages as zero.
pub(super) fn select(
    groups: &[(OffsetDateTime, u64)],
    now: OffsetDateTime,
    bounds: KeptRunBounds,
) -> Vec<(usize, PruneBound)> {
    let mut chosen = Vec::new();
    let mut rest = Vec::new();
    for (index, (newest, bytes)) in oldest_first(groups) {
        if bounds
            .maximum_age
            .is_some_and(|maximum| age(newest, now) > maximum)
        {
            chosen.push((index, PruneBound::Age));
        } else {
            rest.push((index, bytes));
        }
    }
    if let Some(maximum) = bounds.maximum_total_bytes {
        let mut total = rest
            .iter()
            .fold(0_u64, |total, &(_, bytes)| total.saturating_add(bytes));
        let newest = rest.len().saturating_sub(1);
        for &(index, bytes) in rest.iter().take(newest) {
            if total <= maximum {
                break;
            }
            chosen.push((index, PruneBound::TotalSize));
            total = total.saturating_sub(bytes);
        }
    }
    chosen
}

/// The groups with their indices, oldest first, ties in index order.
fn oldest_first(groups: &[(OffsetDateTime, u64)]) -> Vec<(usize, (OffsetDateTime, u64))> {
    let mut oldest_first = groups.iter().copied().enumerate().collect::<Vec<_>>();
    oldest_first.sort_by_key(|&(index, (newest, _))| (newest, index));
    oldest_first
}

/// Chooses as the scope says: by the bounds through `select`, or, under `all`, every
/// group, oldest first, by the operator.
fn choose(
    groups: &[(OffsetDateTime, u64)],
    now: OffsetDateTime,
    bounds: KeptRunBounds,
    scope: PruneScope,
) -> Vec<(usize, PruneBound)> {
    match scope {
        PruneScope::Bounds => select(groups, now, bounds),
        PruneScope::All => oldest_first(groups)
            .into_iter()
            .map(|(index, _)| (index, PruneBound::Operator))
            .collect(),
    }
}

/// The lease's kept workspaces with the newest modification time of each, those a pass
/// may take apart from those a continuation holds. A group whose directories are no longer
/// the ones the inventory recorded is in neither.
struct Gathered {
    candidates: Vec<(KeptGroup, OffsetDateTime)>,
    in_use: Vec<(KeptGroup, OffsetDateTime)>,
}

fn gather(lease: &WorkRootLease) -> Gathered {
    let mut gathered = Gathered {
        candidates: Vec::new(),
        in_use: Vec::new(),
    };
    for group in lease.kept_groups() {
        let in_use = lease.kept_group_in_use(&group);
        let Some(newest) = lease.kept_group_newest_modification(&group) else {
            continue;
        };
        if in_use {
            gathered.in_use.push((group, newest));
        } else {
            gathered.candidates.push((group, newest));
        }
    }
    gathered
}

/// The bytes the group's directories hold, each measured once by the lease; none once
/// `may_continue` has answered false.
fn group_bytes(
    lease: &WorkRootLease,
    group: &KeptGroup,
    may_continue: &dyn Fn() -> bool,
) -> Option<u64> {
    let mut bytes = 0_u64;
    for member in &group.members {
        if !may_continue() {
            return None;
        }
        bytes = bytes.saturating_add(lease.kept_member_bytes(member));
    }
    Some(bytes)
}

/// Applies the scope to the lease's kept workspaces once and answers what it removed or
/// failed to remove, writing one `runner.workspace_pruned` record for each. Under
/// `PruneScope::Bounds` it removes what the kept-run bounds choose; under `All`, every
/// kept workspace not in use, the newest included, by `PruneBound::Operator`. A directory
/// whose removal failed is not tried again.
///
/// It blocks on the file system and on the cleanup engine's removals, so a caller on an
/// async runtime runs it on a blocking thread. `may_continue` is asked before each
/// directory is measured or removed and before each emptied earlier boot is removed; once
/// it answers false the pass returns, and a later pass goes on with what is left.
pub(super) fn prune_kept_runs(
    lease: &WorkRootLease,
    bounds: KeptRunBounds,
    scope: PruneScope,
    now: OffsetDateTime,
    may_continue: &dyn Fn() -> bool,
    recorder: Option<&Recorder>,
) -> Vec<PruneOutcome> {
    let mut outcomes = Vec::new();
    let measured = scope == PruneScope::Bounds && bounds.maximum_total_bytes.is_some();
    let mut candidates = Vec::new();
    let mut facts = Vec::new();
    for (group, newest) in gather(lease).candidates {
        let bytes = if measured {
            let Some(bytes) = group_bytes(lease, &group, may_continue) else {
                return outcomes;
            };
            bytes
        } else {
            0
        };
        facts.push((newest, bytes));
        candidates.push(group);
    }
    'groups: for (index, bound) in choose(&facts, now, bounds, scope) {
        let Some(group) = candidates.get(index) else {
            continue;
        };
        if !lease.withdraw_kept_group(group) {
            continue;
        }
        for (position, member) in group.members.iter().enumerate() {
            if !may_continue() {
                lease.restore_kept_members(group.members.get(position..).unwrap_or_default());
                return outcomes;
            }
            let bytes = lease.kept_member_bytes(member);
            let result = if lease.remove_kept_member(member) {
                PruneResult::Removed
            } else {
                PruneResult::Failed
            };
            let outcome = PruneOutcome {
                path: member.path.clone(),
                attempt: member.attempt.clone(),
                bytes,
                bound,
                result,
            };
            if let Some(recorder) = recorder {
                record_pruned(recorder, &outcome);
            }
            outcomes.push(outcome);
            if result == PruneResult::Failed {
                lease.fail_kept_members(group.members.get(position + 1..).unwrap_or_default());
                continue 'groups;
            }
        }
    }
    lease.remove_emptied_kept_boots(may_continue);
    outcomes
}

/// What a pass under `scope` would do now with each of the lease's kept workspaces
/// (REQ-RUNNERENROLL-164), removing nothing and writing no record: those a pass may take,
/// each measured and chosen as the pass would choose them, and those a continuation holds,
/// never measured since it is writing to them, oldest first, ties by first path; then each
/// directory whose removal failed, a workspace of its own. A failed directory that is no
/// longer the one the inventory recorded is left out. It answers none once `may_continue`
/// has answered false, asked before each directory is measured. It blocks on the file
/// system, as the pass does.
pub(super) fn kept_report(
    lease: &WorkRootLease,
    bounds: KeptRunBounds,
    scope: PruneScope,
    now: OffsetDateTime,
    may_continue: &dyn Fn() -> bool,
) -> Option<Vec<ReportedWorkspace>> {
    let gathered = gather(lease);
    let mut facts = Vec::with_capacity(gathered.candidates.len());
    for (group, newest) in &gathered.candidates {
        facts.push((*newest, group_bytes(lease, group, may_continue)?));
    }
    let mut states = vec![ReportedState::Kept; facts.len()];
    for (index, bound) in choose(&facts, now, bounds, scope) {
        if let Some(state) = states.get_mut(index) {
            *state = ReportedState::Due(bound);
        }
    }
    let reported = |group: &KeptGroup, modified, bytes, state| {
        let first = group.members.first()?;
        Some(ReportedWorkspace {
            paths: group
                .members
                .iter()
                .map(|member| member.path.clone())
                .collect(),
            attempt: first.attempt.clone(),
            reason: first.reason,
            modified,
            bytes,
            state,
        })
    };
    let mut workspaces =
        gathered
            .candidates
            .iter()
            .zip(facts.iter().zip(states))
            .filter_map(|((group, _), (&(modified, bytes), state))| {
                reported(group, modified, Some(bytes), state)
            })
            .chain(gathered.in_use.iter().filter_map(|(group, modified)| {
                reported(group, *modified, None, ReportedState::InUse)
            }))
            .collect::<Vec<_>>();
    let mut failed = lease
        .failed_kept_members()
        .into_iter()
        .filter_map(|member| {
            Some(ReportedWorkspace {
                modified: lease.kept_member_modification(&member)?,
                paths: vec![member.path],
                attempt: member.attempt,
                reason: member.reason,
                bytes: None,
                state: ReportedState::Failed,
            })
        })
        .collect::<Vec<_>>();
    for list in [&mut workspaces, &mut failed] {
        list.sort_by(|left, right| {
            (left.modified, left.paths.first()).cmp(&(right.modified, right.paths.first()))
        });
    }
    workspaces.append(&mut failed);
    Some(workspaces)
}

/// Writes the outcome as `record_retention` writes `runner.workspace_retained`, its IDs
/// only when the directory's attempt record gave them (REQ-RUNNERENROLL-159).
fn record_pruned(recorder: &Recorder, outcome: &PruneOutcome) {
    let mut attributes = Vec::with_capacity(7);
    if let Some(attempt) = &outcome.attempt {
        attributes.extend([
            KeyValue::new(attribute::ASSIGNMENT_ID, attempt.assignment_id.clone()),
            KeyValue::new(attribute::RUN_ID, attempt.run_id.clone()),
            KeyValue::new(attribute::ATTEMPT_ID, attempt.attempt_id.clone()),
        ]);
    }
    attributes.extend([
        KeyValue::new(
            attribute::WORKSPACE_PATH,
            outcome.path.to_string_lossy().into_owned(),
        ),
        KeyValue::new(
            attribute::WORKSPACE_BYTES,
            i64::try_from(outcome.bytes).unwrap_or(i64::MAX),
        ),
        KeyValue::new(attribute::WORKSPACE_PRUNE_BOUND, outcome.bound.as_str()),
        KeyValue::new(attribute::WORKSPACE_PRUNE_OUTCOME, outcome.result.as_str()),
    ]);
    recorder.record("runner.workspace_pruned", attributes);
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::Duration;

    use time::OffsetDateTime;

    use super::super::KeptRunBounds;
    use super::super::execution::AssignmentProcessGuards;
    use super::super::workspace::{
        CleanupCancellation, CleanupResult, CleanupSleeper, OwnedTree, ProcessQuiescence,
        RetainedClaimRequest, RetentionReason, TreeRemover, WorkRootHook, WorkRootLease,
        WorkspaceDisposition, WorkspaceFilesystem,
    };
    use super::*;
    use crate::telemetry::test_recorder;

    const DAY: time::Duration = time::Duration::DAY;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap()
    }

    fn bounds(age_days: Option<u64>, total_bytes: Option<u64>) -> KeptRunBounds {
        KeptRunBounds {
            maximum_age: age_days.map(|days| Duration::from_secs(days * 86_400)),
            maximum_total_bytes: total_bytes,
        }
    }

    // REQ-WORKSPACE-44
    #[test]
    fn selection_chooses_past_the_age_bound_even_the_only_and_newest_group() {
        let now = now();
        assert_eq!(
            select(&[(now - 15 * DAY, 1)], now, bounds(Some(14), None)),
            [(0, PruneBound::Age)]
        );
        assert!(select(&[(now - 14 * DAY, 1)], now, bounds(Some(14), None)).is_empty());
        assert_eq!(
            select(
                &[(now - 15 * DAY, 1), (now - 20 * DAY, 1), (now - DAY, 1)],
                now,
                bounds(Some(14), None)
            ),
            [(1, PruneBound::Age), (0, PruneBound::Age)]
        );
    }

    // REQ-WORKSPACE-44
    #[test]
    fn selection_chooses_the_oldest_beyond_the_size_bound_and_never_the_newest() {
        let now = now();
        assert_eq!(
            select(
                &[(now - 2 * DAY, 10), (now - DAY, 10), (now - 3 * DAY, 10)],
                now,
                bounds(None, Some(15))
            ),
            [(2, PruneBound::TotalSize), (0, PruneBound::TotalSize)]
        );
        assert_eq!(
            select(
                &[(now - 2 * DAY, 10), (now - DAY, 10), (now - 3 * DAY, 10)],
                now,
                bounds(None, Some(20))
            ),
            [(2, PruneBound::TotalSize)]
        );
        assert_eq!(
            select(
                &[(now - DAY, 100), (now - 2 * DAY, 5)],
                now,
                bounds(None, Some(50))
            ),
            [(1, PruneBound::TotalSize)]
        );
        assert!(select(&[(now - DAY, 100)], now, bounds(None, Some(50))).is_empty());
    }

    // REQ-WORKSPACE-44
    #[test]
    fn selection_applies_only_the_bounds_set_and_age_before_size() {
        let now = now();
        let groups = [
            (now - 3 * DAY, 10),
            (now - 20 * DAY, 10),
            (now - DAY, 10),
            (now - 2 * DAY, 10),
        ];
        assert!(select(&groups, now, bounds(None, None)).is_empty());
        assert_eq!(
            select(&groups, now, bounds(Some(14), None)),
            [(1, PruneBound::Age)]
        );
        assert_eq!(
            select(&groups, now, bounds(None, Some(25))),
            [(1, PruneBound::TotalSize), (0, PruneBound::TotalSize)]
        );
        assert_eq!(
            select(&groups, now, bounds(Some(14), Some(15))),
            [
                (1, PruneBound::Age),
                (0, PruneBound::TotalSize),
                (3, PruneBound::TotalSize)
            ]
        );
    }

    // REQ-WORKSPACE-44
    #[test]
    fn selection_ages_a_modification_time_after_now_as_zero() {
        let now = now();
        let zero = KeptRunBounds {
            maximum_age: Some(Duration::ZERO),
            maximum_total_bytes: None,
        };
        assert!(select(&[(now + 5 * DAY, 1)], now, zero).is_empty());
        assert_eq!(
            select(&[(now - time::Duration::SECOND, 1)], now, zero),
            [(0, PruneBound::Age)]
        );
    }

    // REQ-RUNNERENROLL-159
    #[test]
    fn a_pass_writes_one_pruned_record_per_removal_and_none_when_it_removes_nothing() {
        const BOOT: &str = "rbt_01k0z6r1w8f4jy2m7q9v3x5abc";
        const ASSIGNMENT: &str = "asn_01k0z6r1w8f4jy2m7q9v3x5abc";
        const RUN: &str = "run_01k0z6r1w8f4jy2m7q9v3x5abc";
        const ATTEMPT: &str = "atm_01k0z6r1w8f4jy2m7q9v3x5abc";
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), Permissions::from_mode(0o700)).unwrap();
        let owner = WorkRootLease::acquire_for_test(root.path(), BOOT).unwrap();
        let assignment = owner
            .create_assignment_for_attempt(ASSIGNMENT, RUN, ATTEMPT, None)
            .unwrap();
        assert_eq!(
            assignment
                .release_pending(
                    ProcessQuiescence::Proven,
                    WorkspaceDisposition::Retain(RetentionReason::Failed),
                )
                .wait(),
            CleanupResult::Retained
        );
        let path = owner.boot_path().join(ASSIGNMENT);
        let modified =
            OffsetDateTime::from(fs::symlink_metadata(&path).unwrap().modified().unwrap());
        let (recorder, capture) = test_recorder(BOOT);
        let pruned_records = || {
            capture
                .records()
                .into_iter()
                .filter(|record| record["event.name"] == "runner.workspace_pruned")
                .collect::<Vec<_>>()
        };

        let kept = prune_kept_runs(
            &owner,
            KeptRunBounds::default(),
            PruneScope::Bounds,
            modified,
            &|| true,
            Some(&recorder),
        );
        assert!(kept.is_empty());
        assert!(pruned_records().is_empty());

        let outcomes = prune_kept_runs(
            &owner,
            KeptRunBounds::default(),
            PruneScope::Bounds,
            modified + 15 * DAY,
            &|| true,
            Some(&recorder),
        );
        let [outcome] = outcomes.as_slice() else {
            panic!("one outcome: {}", outcomes.len());
        };
        let records = pruned_records();
        let [record] = records.as_slice() else {
            panic!("one record: {}", records.len());
        };
        assert_eq!(record["um.assignment.id"], ASSIGNMENT);
        assert_eq!(record["um.run.id"], RUN);
        assert_eq!(record["um.attempt.id"], ATTEMPT);
        assert_eq!(record["um.workspace.path"], path.to_string_lossy().as_ref());
        assert_eq!(outcome.path, path);
        assert!(outcome.bytes > 0);
        assert_eq!(record["um.workspace.bytes"], outcome.bytes);
        assert_eq!(record["um.workspace.prune_bound"], "age");
        assert_eq!(record["um.workspace.prune_outcome"], "removed");
        assert!(!path.exists());
    }

    const RUN: &str = "run_01k0z6r1w8f4jy2m7q9v3x5abc";
    const EARLIER_BOOT: &str = "rbt_01k0z6r1w8f4jy2m7q9v3x5abc";
    const LIVE_BOOT: &str = "rbt_01k0z6r1w8f4jy2m7q9v3x5abd";
    const OLDEST: &str = "asn_01k0z6r1w8f4jy2m7q9v3x5aba";
    const OLDER: &str = "asn_01k0z6r1w8f4jy2m7q9v3x5abb";
    const NEWEST: &str = "asn_01k0z6r1w8f4jy2m7q9v3x5abc";
    const HELD: &str = "asn_01k0z6r1w8f4jy2m7q9v3x5abd";
    const CONTINUATION: &str = "asn_01k0z6r1w8f4jy2m7q9v3x5abe";
    const PAYLOAD_BYTES: u64 = 1 << 20;

    fn attempt_of(assignment_id: &str) -> String {
        assignment_id.replacen("asn_", "atm_", 1)
    }

    fn private_work_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), Permissions::from_mode(0o700)).unwrap();
        root
    }

    /// Keeps a failed attempt of `RUN` holding a payload of `PAYLOAD_BYTES` and answers
    /// its assignment directory.
    fn keep(owner: &WorkRootLease, assignment_id: &str) -> PathBuf {
        let assignment = owner
            .create_assignment_for_attempt(assignment_id, RUN, &attempt_of(assignment_id), None)
            .unwrap();
        AssignmentProcessGuards::durable(&assignment.private).unwrap();
        fs::write(
            assignment.workspace.path().join("payload"),
            vec![7_u8; 1 << 20],
        )
        .unwrap();
        assert_eq!(
            assignment
                .release_pending(
                    ProcessQuiescence::Proven,
                    WorkspaceDisposition::Retain(RetentionReason::Failed),
                )
                .wait(),
            CleanupResult::Retained
        );
        owner.boot_path().join(assignment_id)
    }

    fn set_modified(path: &std::path::Path, time: OffsetDateTime) {
        let stamp = rustix::fs::Timespec {
            tv_sec: time.unix_timestamp(),
            tv_nsec: 0,
        };
        rustix::fs::utimensat(
            rustix::fs::CWD,
            path,
            &rustix::fs::Timestamps {
                last_access: stamp,
                last_modification: stamp,
            },
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap();
    }

    fn report(
        lease: &WorkRootLease,
        bounds: KeptRunBounds,
        scope: PruneScope,
        now: OffsetDateTime,
    ) -> Vec<(PathBuf, ReportedState, Option<u64>)> {
        kept_report(lease, bounds, scope, now, &|| true)
            .expect("a report that is never stopped")
            .into_iter()
            .map(|workspace| {
                let [path] = workspace.paths.as_slice() else {
                    panic!("one directory: {:?}", workspace.paths);
                };
                (path.clone(), workspace.state, workspace.bytes)
            })
            .collect()
    }

    /// Removes every tree but the one named `failing`, whose removal fails.
    struct FailingFor(&'static str);

    impl TreeRemover for FailingFor {
        fn remove_tree(&self, tree: &OwnedTree) -> std::io::Result<()> {
            if tree.path().file_name() == Some(std::ffi::OsStr::new(self.0)) {
                return Err(std::io::Error::other("injected removal failure"));
            }
            fs::remove_dir_all(tree.path())
        }
    }

    struct NoWait;

    impl CleanupSleeper for NoWait {
        fn sleep(&self, _: Duration, cancellation: &CleanupCancellation) -> bool {
            !cancellation.is_cancelled()
        }
    }

    struct NoHook;

    impl WorkRootHook for NoHook {
        fn before_child_enumeration(&self) {}
    }

    // REQ-RUNNERENROLL-164: the report states what each scope would remove, never measures
    // a workspace a continuation holds, and removes nothing.
    #[test]
    fn a_report_lists_what_each_scope_would_remove_and_removes_nothing() {
        let now = now();
        let root = private_work_root();
        let earlier = WorkRootLease::acquire_for_test(root.path(), EARLIER_BOOT).unwrap();
        let kept = [OLDEST, OLDER, NEWEST].map(|assignment_id| keep(&earlier, assignment_id));
        drop(earlier);
        for (days, path) in [20, 5, 1].into_iter().zip(&kept) {
            set_modified(path, now - days * DAY);
        }
        let owner = WorkRootLease::acquire_for_test(root.path(), LIVE_BOOT).unwrap();
        let held = keep(&owner, HELD);
        let attempt_id = attempt_of(CONTINUATION);
        let mut continuation = owner
            .create_assignment_for_attempt(CONTINUATION, RUN, &attempt_id, None)
            .unwrap();
        owner
            .claim_retained_for_attempt(
                &mut continuation,
                RetainedClaimRequest {
                    assignment_id: CONTINUATION,
                    run_id: RUN,
                    attempt_id: &attempt_id,
                    prior_assignment_id: HELD,
                    prior_attempt_id: &attempt_of(HELD),
                    recorded_root: &held.join("workspace"),
                },
            )
            .expect("claim the kept attempt");
        set_modified(&held, now - 3 * DAY);
        let bounds = bounds(Some(14), Some(PAYLOAD_BYTES * 3 / 2));

        let workspaces = kept_report(&owner, bounds, PruneScope::Bounds, now, &|| true)
            .expect("a report that is never stopped");

        let listed = workspaces
            .iter()
            .map(|workspace| (workspace.paths.clone(), workspace.state))
            .collect::<Vec<_>>();
        assert_eq!(
            listed,
            [
                (vec![kept[0].clone()], ReportedState::Due(PruneBound::Age)),
                (
                    vec![kept[1].clone()],
                    ReportedState::Due(PruneBound::TotalSize)
                ),
                (vec![held.clone()], ReportedState::InUse),
                (vec![kept[2].clone()], ReportedState::Kept),
            ]
        );
        for (workspace, (assignment_id, days)) in
            workspaces
                .iter()
                .zip([(OLDEST, 20), (OLDER, 5), (HELD, 3), (NEWEST, 1)])
        {
            let attempt = workspace.attempt.as_ref().expect("the attempt's IDs");
            assert_eq!(attempt.assignment_id, assignment_id);
            assert_eq!(attempt.run_id, RUN);
            assert_eq!(attempt.attempt_id, attempt_of(assignment_id));
            assert_eq!(workspace.reason, RetentionReason::Failed);
            assert_eq!(workspace.modified, now - days * DAY);
            if workspace.state == ReportedState::InUse {
                assert_eq!(workspace.bytes, None);
            } else {
                assert!(workspace.bytes.is_some_and(|bytes| bytes >= PAYLOAD_BYTES));
            }
        }
        assert_eq!(
            report(&owner, bounds, PruneScope::All, now),
            [
                (
                    kept[0].clone(),
                    ReportedState::Due(PruneBound::Operator),
                    workspaces[0].bytes
                ),
                (
                    kept[1].clone(),
                    ReportedState::Due(PruneBound::Operator),
                    workspaces[1].bytes
                ),
                (held.clone(), ReportedState::InUse, None),
                (
                    kept[2].clone(),
                    ReportedState::Due(PruneBound::Operator),
                    workspaces[3].bytes
                ),
            ]
        );
        assert!(
            kept.iter()
                .chain([&held])
                .all(|path| path.join("workspace/payload").is_file())
        );
        assert!(kept_report(&owner, bounds, PruneScope::Bounds, now, &|| false).is_none());
    }

    // REQ-RUNNERENROLL-165, REQ-RUNNERENROLL-159, REQ-RUNNERENROLL-164: an operator's pass
    // removes every kept workspace, the newest included, but one whose removal failed.
    #[test]
    fn an_operator_pass_removes_every_kept_workspace_but_one_that_failed() {
        let now = now();
        let root = private_work_root();
        let owner = WorkRootLease::acquire_with(
            root.path(),
            LIVE_BOOT,
            WorkspaceFilesystem::injected(
                std::sync::Arc::new(FailingFor(OLDEST)),
                std::sync::Arc::new(NoWait),
                std::sync::Arc::new(NoHook),
            ),
        )
        .unwrap();
        let kept = [OLDEST, OLDER, NEWEST].map(|assignment_id| keep(&owner, assignment_id));
        for (days, path) in [20, 5, 1].into_iter().zip(&kept) {
            set_modified(path, now - days * DAY);
        }
        let (recorder, capture) = test_recorder(LIVE_BOOT);
        let age = bounds(Some(14), None);

        let failed = prune_kept_runs(&owner, age, PruneScope::Bounds, now, &|| true, None);
        assert_eq!(
            failed
                .iter()
                .map(|outcome| (outcome.path.clone(), outcome.result))
                .collect::<Vec<_>>(),
            [(kept[0].clone(), PruneResult::Failed)]
        );
        assert_eq!(
            report(&owner, age, PruneScope::All, now)
                .into_iter()
                .map(|(path, state, _)| (path, state))
                .collect::<Vec<_>>(),
            [
                (kept[1].clone(), ReportedState::Due(PruneBound::Operator)),
                (kept[2].clone(), ReportedState::Due(PruneBound::Operator)),
                (kept[0].clone(), ReportedState::Failed),
            ]
        );
        let reported = kept_report(&owner, age, PruneScope::Bounds, now, &|| true).unwrap();
        let failed = reported.last().unwrap();
        assert_eq!(failed.bytes, None);
        assert_eq!(failed.reason, RetentionReason::Failed);
        assert_eq!(failed.modified, now - 20 * DAY);

        let outcomes = prune_kept_runs(
            &owner,
            KeptRunBounds::default(),
            PruneScope::All,
            now,
            &|| true,
            Some(&recorder),
        );

        assert_eq!(
            outcomes
                .iter()
                .map(|outcome| (outcome.path.clone(), outcome.bound, outcome.result))
                .collect::<Vec<_>>(),
            [
                (kept[1].clone(), PruneBound::Operator, PruneResult::Removed),
                (kept[2].clone(), PruneBound::Operator, PruneResult::Removed),
            ]
        );
        assert!(!kept[1].exists() && !kept[2].exists());
        assert!(kept[0].join("workspace").is_dir());
        let records = capture
            .records()
            .into_iter()
            .filter(|record| record["event.name"] == "runner.workspace_pruned")
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .all(|record| record["um.workspace.prune_bound"] == "operator")
        );
    }
}
