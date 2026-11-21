//! Build-cache eviction (REQ-RUNNERENROLL-161, REQ-RUNNERENROLL-165, INV-RUNNER-52): each
//! cache the operator configuration names (REQ-RUNNERENROLL-160) that occupies more than its
//! bound loses its least recently used files down to nine tenths of it, or under an
//! operator's `all` every file but its `CACHEDIR.TAG`, through
//! `useful_execution::evict_least_recently_used`, with one record per cache. The measure
//! (REQ-RUNNERENROLL-164) states what an eviction would find and removes nothing.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentelemetry::KeyValue;
use rustix::fs::{AtFlags, CWD, Mode, OFlags, Stat, fstat, openat, statat};
use rustix::io::Errno;
use useful_execution::{Evicted, Eviction, evict_least_recently_used};

use super::BuildCache;
use super::command_fence::CommandFence;
use crate::control_protocol::PruneScope;
use crate::telemetry::{Recorder, attribute};

/// The names an eviction keeps directly in a cache.
const KEPT_NAMES: &[&str] = &["CACHEDIR.TAG"];

/// What one eviction did to one cache.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CacheEviction {
    pub(super) path: PathBuf,
    pub(super) maximum_bytes: u64,
    pub(super) evicted: Evicted,
}

/// What the measure found at one configured cache's `path`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CacheMeasure {
    pub(super) path: PathBuf,
    pub(super) maximum_bytes: u64,
    pub(super) state: CacheState,
}

/// Whether an eviction would enter a cache, and what it would find there.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CacheState {
    /// The bytes the tree occupies, as an eviction measures it before removing anything,
    /// and the bytes an eviction under the scope would remove now.
    Measured { bytes: u64, due_bytes: u64 },
    /// Nothing is at the `path`.
    Missing,
    /// A symbolic link, or anything but a directory, is.
    NotADirectory,
    /// The directory cannot be opened or read.
    Unreadable,
    /// The directory is the work root or holds the state file or the control socket.
    Protected,
}

/// Evicts from each cache in turn and answers one entry for each cache it opened and
/// walked, writing one `runner.build_cache_evicted` record for each from which it removed
/// a file or failed to remove one (REQ-RUNNERENROLL-161). Under `PruneScope::Bounds` a
/// cache over its bound loses files down to nine tenths of it; under `All` every cache
/// loses every file but its `CACHEDIR.TAG` (REQ-RUNNERENROLL-165).
///
/// A `path` at which nothing exists, or a symbolic link or anything but a directory is,
/// is left as it is. `protected` names the work root and the directories that hold the
/// state file and the control socket; no directory with the identity one of them has when
/// the eviction starts is evicted or entered. It blocks on the file system, so a caller on
/// an async runtime runs it on a blocking thread. `may_continue` is asked before each cache,
/// and by the eviction before each directory it opens and each removal; once it answers
/// false the driver returns.
pub(super) fn evict_build_caches(
    caches: &[BuildCache],
    protected: &[PathBuf],
    scope: PruneScope,
    may_continue: &dyn Fn() -> bool,
    recorder: Option<&Recorder>,
) -> Vec<CacheEviction> {
    let protected = protected_identities(protected);
    let mut evictions = Vec::new();
    for cache in caches {
        if !may_continue() {
            break;
        }
        let Some(evicted) = evict_cache(cache, &protected, scope, may_continue) else {
            continue;
        };
        let eviction = CacheEviction {
            path: cache.path.clone(),
            maximum_bytes: cache.maximum_bytes,
            evicted,
        };
        if let Some(recorder) = recorder
            && (evicted.removed_files > 0 || evicted.failed_files > 0)
        {
            record_evicted(recorder, &eviction);
        }
        evictions.push(eviction);
        if evicted.stopped {
            break;
        }
    }
    evictions
}

/// The cache half of a kept-run pass (REQ-RUNNERENROLL-162, INV-RUNNER-53): evicts as
/// `evict_build_caches` does while holding `fence`, and answers its evictions.
///
/// It evicts nothing, and answers none, when the fence cannot be held because a command is
/// in it. Holding it, it continues while `may_continue` answers true and no command has
/// asked to enter, so a command that asks ends the eviction before its next removal and
/// enters once the hold is dropped on return. It blocks, as `evict_build_caches` does.
pub(super) fn evict_under_fence(
    caches: &[BuildCache],
    protected: &[PathBuf],
    scope: PruneScope,
    fence: &Arc<CommandFence>,
    may_continue: &dyn Fn() -> bool,
    recorder: Option<&Recorder>,
) -> Option<Vec<CacheEviction>> {
    let hold = fence.try_hold()?;
    let evictions = evict_build_caches(
        caches,
        protected,
        scope,
        &|| may_continue() && !hold.wanted(),
        recorder,
    );
    drop(hold);
    Some(evictions)
}

/// Measures each configured cache, in configuration order, as an eviction under `scope`
/// would find it, and answers none once `may_continue` has answered false. It removes
/// nothing and writes no record; it takes no fence, so a build may run beside it, and it
/// blocks on the file system, as an eviction does.
pub(super) fn measure_build_caches(
    caches: &[BuildCache],
    protected: &[PathBuf],
    scope: PruneScope,
    may_continue: &dyn Fn() -> bool,
) -> Option<Vec<CacheMeasure>> {
    let protected = protected_identities(protected);
    let mut measures = Vec::with_capacity(caches.len());
    for cache in caches {
        if !may_continue() {
            return None;
        }
        let state = match cache_directory(&cache.path, &protected) {
            Err(state) => state,
            Ok(directory) => {
                // A tree at most `above` loses nothing; its first measure is what an
                // eviction starts from.
                let measured = evict_least_recently_used(
                    &directory,
                    &Eviction {
                        above: u64::MAX,
                        down_to: u64::MAX,
                        keep: KEPT_NAMES,
                        protected: &protected,
                        may_continue,
                    },
                );
                if measured.stopped {
                    return None;
                }
                let bytes = measured.bytes_before;
                let due_bytes = match scope {
                    PruneScope::Bounds if bytes > cache.maximum_bytes => {
                        bytes.saturating_sub(bounded_target(cache.maximum_bytes))
                    }
                    PruneScope::Bounds => 0,
                    PruneScope::All => bytes.saturating_sub(kept_bytes(&directory)),
                };
                CacheState::Measured { bytes, due_bytes }
            }
        };
        measures.push(CacheMeasure {
            path: cache.path.clone(),
            maximum_bytes: cache.maximum_bytes,
            state,
        });
    }
    Some(measures)
}

/// The identities of the `protected` directories as they are now; one that cannot be
/// read protects nothing, since no directory has its identity.
fn protected_identities(protected: &[PathBuf]) -> Vec<(u64, u64)> {
    protected
        .iter()
        .filter_map(|path| statat(CWD, path, AtFlags::empty()).ok())
        .filter_map(|metadata| identity(&metadata))
        .collect()
}

/// The bytes the names an eviction keeps directly in the opened cache occupy, as its
/// measure counts them, so that an operator's measure leaves them out of what is due.
fn kept_bytes(directory: &OwnedFd) -> u64 {
    KEPT_NAMES
        .iter()
        .filter_map(|name| statat(directory, *name, AtFlags::SYMLINK_NOFOLLOW).ok())
        .map(|metadata| {
            u64::try_from(metadata.st_blocks)
                .unwrap_or(0)
                .saturating_mul(512)
        })
        .fold(0, u64::saturating_add)
}

/// Nine tenths of a cache's bound, which an eviction under the bounds reaches.
fn bounded_target(maximum_bytes: u64) -> u64 {
    u64::try_from(u128::from(maximum_bytes) * 9 / 10).unwrap_or(u64::MAX)
}

/// Opens the cache's `path` without following a link and evicts from it as the scope says;
/// none when it opens no directory or is protected.
fn evict_cache(
    cache: &BuildCache,
    protected: &[(u64, u64)],
    scope: PruneScope,
    may_continue: &dyn Fn() -> bool,
) -> Option<Evicted> {
    let directory = cache_directory(&cache.path, protected).ok()?;
    let (above, down_to) = match scope {
        PruneScope::Bounds => (cache.maximum_bytes, bounded_target(cache.maximum_bytes)),
        PruneScope::All => (0, 0),
    };
    Some(evict_least_recently_used(
        &directory,
        &Eviction {
            above,
            down_to,
            keep: KEPT_NAMES,
            protected,
            may_continue,
        },
    ))
}

/// The cache's directory, or why no eviction enters it: what opening it answered, or that
/// it is protected.
fn cache_directory(path: &Path, protected: &[(u64, u64)]) -> Result<OwnedFd, CacheState> {
    let directory = open_cache(path).map_err(|error| match error {
        Errno::NOENT => CacheState::Missing,
        Errno::LOOP | Errno::NOTDIR => CacheState::NotADirectory,
        _ => CacheState::Unreadable,
    })?;
    let opened = fstat(&directory)
        .ok()
        .as_ref()
        .and_then(identity)
        .ok_or(CacheState::Unreadable)?;
    if protected.contains(&opened) {
        return Err(CacheState::Protected);
    }
    Ok(directory)
}

/// Opens the cache's directory without following a link: `NOENT` when nothing is at
/// `path`, `LOOP` when a symbolic link is and `NOTDIR` when something other than a
/// directory is.
fn open_cache(path: &Path) -> Result<OwnedFd, Errno> {
    openat(
        CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// A directory's `(st_dev, st_ino)` as `Eviction::protected` holds it.
fn identity(metadata: &Stat) -> Option<(u64, u64)> {
    fn widened<T: TryInto<u64>>(value: T) -> Option<u64> {
        value.try_into().ok()
    }
    Some((widened(metadata.st_dev)?, widened(metadata.st_ino)?))
}

/// Writes the cache's record, its integers saturating at `i64::MAX` as `record_pruned`'s.
fn record_evicted(recorder: &Recorder, eviction: &CacheEviction) {
    let integer = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
    let evicted = &eviction.evicted;
    recorder.record(
        "runner.build_cache_evicted",
        [
            KeyValue::new(
                attribute::BUILD_CACHE_PATH,
                eviction.path.to_string_lossy().into_owned(),
            ),
            KeyValue::new(
                attribute::BUILD_CACHE_MAXIMUM_BYTES,
                integer(eviction.maximum_bytes),
            ),
            KeyValue::new(
                attribute::BUILD_CACHE_REMOVED_FILES,
                integer(evicted.removed_files),
            ),
            KeyValue::new(
                attribute::BUILD_CACHE_REMOVED_BYTES,
                integer(evicted.removed_bytes),
            ),
            KeyValue::new(
                attribute::BUILD_CACHE_REMAINING_BYTES,
                integer(evicted.bytes_after),
            ),
            KeyValue::new(
                attribute::BUILD_CACHE_FAILED_FILES,
                integer(evicted.failed_files),
            ),
        ],
    );
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Path;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;
    use crate::service::test_support::with_watchdog;
    use crate::service::{Sleeper as _, TokioSleeper};
    use crate::telemetry::test_recorder;

    fn allocated(path: &Path) -> u64 {
        fs::symlink_metadata(path).unwrap().blocks() * 512
    }

    /// A directory holding four files of 64 KiB, and the bytes they occupy.
    fn filled(path: &Path) -> u64 {
        fs::create_dir(path).unwrap();
        (0..4)
            .map(|index| {
                let file = path.join(format!("file-{index}"));
                fs::write(&file, vec![7_u8; 64 * 1024]).unwrap();
                allocated(&file)
            })
            .sum()
    }

    // REQ-RUNNERENROLL-161
    #[test]
    fn eviction_records_each_cache_it_removed_from_and_follows_no_link() {
        let temporary = tempfile::tempdir().unwrap();
        let over = temporary.path().join("over");
        let over_bytes = filled(&over);
        let within = temporary.path().join("within");
        let within_bytes = filled(&within);
        let missing = temporary.path().join("missing");
        let target = temporary.path().join("target");
        let target_bytes = filled(&target);
        let link = temporary.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let cache = |path: &Path, maximum_bytes| BuildCache {
            path: path.to_path_buf(),
            maximum_bytes,
        };
        let caches = [
            cache(&over, over_bytes / 2),
            cache(&within, within_bytes),
            cache(&missing, 1),
            cache(&link, target_bytes / 2),
        ];
        let (recorder, capture) = test_recorder("rbt_fixture");

        let evictions =
            evict_build_caches(&caches, &[], PruneScope::Bounds, &|| true, Some(&recorder));

        let records = capture
            .records()
            .into_iter()
            .filter(|record| record["event.name"] == "runner.build_cache_evicted")
            .collect::<Vec<_>>();
        let [record] = records.as_slice() else {
            panic!("one record: {}", records.len());
        };
        let Some(eviction) = evictions.iter().find(|eviction| eviction.path == over) else {
            panic!("no eviction of the cache over its bound: {evictions:?}");
        };
        assert!(
            evictions
                .iter()
                .all(|eviction| eviction.path != missing && eviction.path != link)
        );
        let evicted = eviction.evicted;
        assert!(evicted.removed_files > 0);
        assert!(evicted.bytes_after <= over_bytes / 2 * 9 / 10);
        assert_eq!(
            record["um.build_cache.path"],
            over.to_string_lossy().as_ref()
        );
        assert_eq!(record["um.build_cache.maximum_bytes"], over_bytes / 2);
        assert_eq!(
            record["um.build_cache.removed_files"],
            evicted.removed_files
        );
        assert_eq!(
            record["um.build_cache.removed_bytes"],
            evicted.removed_bytes
        );
        assert_eq!(
            record["um.build_cache.remaining_bytes"],
            evicted.bytes_after
        );
        assert_eq!(record["um.build_cache.failed_files"], evicted.failed_files);
        assert_eq!(fs::read_dir(&within).unwrap().count(), 4);
        assert_eq!(fs::read_dir(&target).unwrap().count(), 4);
        assert!(fs::symlink_metadata(&missing).is_err());
    }

    // REQ-RUNNERENROLL-164: the measure states each configured cache, in order, as an
    // eviction would start from it, and removes nothing.
    #[test]
    fn the_measure_states_each_cache_as_an_eviction_would_find_it_and_removes_nothing() {
        let temporary = tempfile::tempdir().unwrap();
        let over = temporary.path().join("over");
        let over_bytes = filled(&over);
        let within = temporary.path().join("within");
        let within_bytes = filled(&within);
        let missing = temporary.path().join("missing");
        let target = temporary.path().join("target");
        let target_bytes = filled(&target);
        let link = temporary.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let file = temporary.path().join("file");
        fs::write(&file, b"not a cache").unwrap();
        let work_root = temporary.path().join("work-root");
        filled(&work_root);
        let cache = |path: &Path, maximum_bytes| BuildCache {
            path: path.to_path_buf(),
            maximum_bytes,
        };
        let caches = [
            cache(&over, over_bytes / 2),
            cache(&within, within_bytes),
            cache(&missing, 1),
            cache(&link, target_bytes / 2),
            cache(&file, 1),
            cache(&work_root, 1),
        ];
        let protected = [work_root.clone()];
        let states = |scope| {
            measure_build_caches(&caches, &protected, scope, &|| true)
                .expect("a measure that is never stopped")
                .into_iter()
                .map(|measure| {
                    assert_eq!(
                        caches
                            .iter()
                            .find(|cache| cache.path == measure.path)
                            .map(|cache| cache.maximum_bytes),
                        Some(measure.maximum_bytes)
                    );
                    (measure.path, measure.state)
                })
                .collect::<Vec<_>>()
        };

        let bounded = states(PruneScope::Bounds);
        let all = states(PruneScope::All);

        let Some((_, CacheState::Measured { bytes, .. })) = bounded.first() else {
            panic!("the cache over its bound is not measured: {bounded:?}");
        };
        let bytes = *bytes;
        let within_measured = match bounded.get(1) {
            Some((_, CacheState::Measured { bytes, .. })) => *bytes,
            other => panic!("the cache within its bound is not measured: {other:?}"),
        };
        assert_eq!(
            bounded,
            [
                (
                    over.clone(),
                    CacheState::Measured {
                        bytes,
                        due_bytes: bytes - over_bytes / 2 * 9 / 10,
                    }
                ),
                (
                    within.clone(),
                    CacheState::Measured {
                        bytes: within_measured,
                        due_bytes: 0,
                    }
                ),
                (missing.clone(), CacheState::Missing),
                (link.clone(), CacheState::NotADirectory),
                (file.clone(), CacheState::NotADirectory),
                (work_root.clone(), CacheState::Protected),
            ]
        );
        assert_eq!(
            all[..2],
            [
                (
                    over.clone(),
                    CacheState::Measured {
                        bytes,
                        due_bytes: bytes,
                    }
                ),
                (
                    within.clone(),
                    CacheState::Measured {
                        bytes: within_measured,
                        due_bytes: within_measured,
                    }
                ),
            ]
        );
        assert_eq!(all[2..], bounded[2..]);
        for path in [&over, &within, &target, &work_root] {
            assert_eq!(fs::read_dir(path).unwrap().count(), 4);
        }
        assert!(measure_build_caches(&caches, &protected, PruneScope::Bounds, &|| false).is_none());

        let evictions = evict_build_caches(&caches, &protected, PruneScope::Bounds, &|| true, None);
        assert_eq!(
            evictions
                .iter()
                .map(|eviction| (eviction.path.clone(), eviction.evicted.bytes_before))
                .collect::<Vec<_>>(),
            [(over, bytes), (within, within_measured)]
        );
    }

    // REQ-RUNNERENROLL-165: an operator's eviction removes every file of a cache within
    // its bound but its tag.
    #[test]
    fn an_operator_eviction_leaves_only_the_cache_and_its_tag() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("cache");
        filled(&path);
        filled(&path.join("nested"));
        fs::write(
            path.join("CACHEDIR.TAG"),
            b"Signature: 8a477f597d28d172789f06886806bc55\n",
        )
        .unwrap();
        let caches = [BuildCache {
            path: path.clone(),
            maximum_bytes: u64::MAX,
        }];
        let measures = measure_build_caches(&caches, &[], PruneScope::All, &|| true)
            .expect("a measure that is never stopped");

        let evictions = evict_build_caches(&caches, &[], PruneScope::All, &|| true, None);

        let [eviction] = evictions.as_slice() else {
            panic!("one eviction: {evictions:?}");
        };
        // REQ-RUNNERENROLL-164: what the report says is due is what the eviction frees,
        // the tag it keeps left out.
        let [
            CacheMeasure {
                state: CacheState::Measured { bytes, due_bytes },
                ..
            },
        ] = measures.as_slice()
        else {
            panic!("one measured cache: {measures:?}");
        };
        assert_eq!(*bytes, eviction.evicted.bytes_before);
        assert_eq!(*due_bytes, eviction.evicted.removed_bytes);
        assert!(due_bytes < bytes);
        assert_eq!(eviction.evicted.removed_files, 8);
        assert_eq!(eviction.evicted.failed_files, 0);
        assert_eq!(
            listed(&path),
            BTreeSet::from([OsString::from("CACHEDIR.TAG")])
        );
    }

    /// The names in `path`.
    fn listed(path: &Path) -> BTreeSet<OsString> {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect()
    }

    /// A cache at `path` of 32 files of 64 KiB, each last used a minute after the one
    /// before from 2026-01-01, bounded by what one of them occupies, so that every file lies
    /// beyond nine tenths of the bound.
    fn old_cache(path: &Path) -> BuildCache {
        fs::create_dir(path).unwrap();
        let mut maximum_bytes = 0;
        for index in 0..32_i64 {
            let file = path.join(format!("file-{index:02}"));
            fs::write(&file, vec![7_u8; 64 * 1024]).unwrap();
            let stamp = rustix::fs::Timespec {
                tv_sec: 1_767_225_600 + index * 60,
                tv_nsec: 0,
            };
            rustix::fs::utimensat(
                CWD,
                &file,
                &rustix::fs::Timestamps {
                    last_access: stamp,
                    last_modification: stamp,
                },
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .unwrap();
            maximum_bytes = allocated(&file);
        }
        BuildCache {
            path: path.to_path_buf(),
            maximum_bytes,
        }
    }

    // REQ-RUNNERENROLL-162, INV-RUNNER-53: a command that asks while the cache half holds
    // the command fence ends the eviction before its next removal and starts only once the
    // eviction has returned, and while a command is in the fence the cache half removes
    // nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_command_that_asks_during_an_eviction_ends_it_and_starts_after_it() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("cache");
        let caches = [old_cache(&path)];
        let bound = caches[0].maximum_bytes;
        let fence = CommandFence::new();

        let entry = fence.enter();
        assert!(
            evict_under_fence(&caches, &[], PruneScope::Bounds, &fence, &|| true, None).is_none()
        );
        assert_eq!(listed(&path).len(), 32);
        drop(entry);

        let runtime = tokio::runtime::Handle::current();
        let entered = Arc::new(AtomicBool::new(false));
        let evicting = tokio::task::spawn_blocking({
            let fence = Arc::clone(&fence);
            let entered = Arc::clone(&entered);
            let path = path.clone();
            move || {
                let calls = AtomicUsize::new(0);
                let command = Mutex::new(None);
                let may_continue = || {
                    assert!(
                        !entered.load(Ordering::SeqCst),
                        "a command entered the fence while the eviction held it"
                    );
                    let call = calls.fetch_add(1, Ordering::SeqCst) + 1;
                    if call > 5 {
                        // A command slow to mark the hold wanted has more time at each
                        // later ask.
                        runtime.block_on(TokioSleeper.sleep(Duration::from_millis(20)));
                    }
                    if call == 5 {
                        let (asking, asked) = tokio::sync::oneshot::channel();
                        let fence = Arc::clone(&fence);
                        let entered = Arc::clone(&entered);
                        let path = path.clone();
                        *command.lock().unwrap() = Some(runtime.spawn_blocking(move || {
                            asking.send(()).unwrap();
                            let _entry = fence.enter();
                            entered.store(true, Ordering::SeqCst);
                            listed(&path)
                        }));
                        runtime
                            .block_on(with_watchdog(asked))
                            .expect("the command did not ask to enter")
                            .unwrap();
                        // The hold reads wanted once the command waits; an entry that did
                        // not wait would have entered in this time.
                        runtime.block_on(TokioSleeper.sleep(Duration::from_millis(100)));
                    }
                    true
                };
                let evictions = evict_under_fence(
                    &caches,
                    &[],
                    PruneScope::Bounds,
                    &fence,
                    &may_continue,
                    None,
                )
                .expect("the fence was free");
                let after = listed(&path);
                let command = command.lock().unwrap().take();
                (evictions, after, command)
            }
        });
        let (evictions, after, command) = with_watchdog(evicting)
            .await
            .expect("the eviction did not end")
            .unwrap();

        let command = command.expect("the eviction did not ask a fifth time");
        let listing = with_watchdog(command)
            .await
            .expect("the command did not enter once the eviction returned")
            .unwrap();
        assert!(entered.load(Ordering::SeqCst));
        let [eviction] = evictions.as_slice() else {
            panic!("one eviction: {evictions:?}");
        };
        assert!(eviction.evicted.stopped);
        assert!(eviction.evicted.bytes_after > bound * 9 / 10);
        assert!(!after.is_empty());
        assert_eq!(listing, after);
    }
}
