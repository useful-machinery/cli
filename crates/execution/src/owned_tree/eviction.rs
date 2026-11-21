//! Least-recently-used eviction from a directory tree (REQ-RUNNERENROLL-161, INV-RUNNER-52).
//!
//! A measuring walk counts the tree and keeps a histogram of the removable bytes by the
//! minute of each file's last use; the cutoff is the minute by which the oldest bytes reach
//! what must be freed; a removing walk then unlinks the files up to it and the directories
//! that leaves empty. Both walks are `super::walk_tree`'s, so neither follows a link nor
//! leaves the directory's device. A file that cannot be removed is remembered, and a further
//! pair of walks then frees what it would have.

use std::collections::{BTreeMap, HashSet};
use std::os::fd::{BorrowedFd, OwnedFd};

use rustix::ffi::CStr;
use rustix::fs::{AtFlags, FileType, Stat, fstat, unlinkat};
use rustix::io::Errno;

use super::{Next, TreeVisitor, walk_tree, widened};

/// What `evict_least_recently_used` is asked to do.
pub struct Eviction<'a> {
    /// The size past which anything is removed.
    pub above: u64,
    /// The size an eviction reaches.
    pub down_to: u64,
    /// Names kept directly in the directory.
    pub keep: &'a [&'a str],
    /// The `(st_dev, st_ino)` of directories never entered nor counted.
    pub protected: &'a [(u64, u64)],
    /// Asked before each directory a walk opens and before each removal; once it answers
    /// false the eviction returns at once.
    pub may_continue: &'a dyn Fn() -> bool,
}

/// What `evict_least_recently_used` did.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Evicted {
    /// The bytes the tree below the directory occupied before the eviction.
    pub bytes_before: u64,
    /// The bytes it occupies after: the last measure less what that walk freed.
    pub bytes_after: u64,
    /// The files removed, a file with several names counted once.
    pub removed_files: u64,
    /// The bytes the removed files and the directories their removal emptied held.
    pub removed_bytes: u64,
    /// The files the eviction could not remove.
    pub failed_files: u64,
    /// Whether `may_continue` stopped the eviction.
    pub stopped: bool,
}

/// Removes the least recently used files below the opened `directory` when the tree there
/// occupies more than `request.above`, until it occupies at most `request.down_to`, and then
/// the directories below it that the removals left empty.
///
/// The tree occupies `st_blocks * 512` of every directory and other file below `directory`,
/// a file with several names counted once, leaving out what lies on another device and each
/// directory `request.protected` names with what is in it. A file's last use is the later of
/// its access and modification times, to the minute. A name in `request.keep` directly in
/// `directory` is never removed, nor is `directory` itself. Everything is removed through
/// `unlinkat` relative to the directory the entry was read from.
pub fn evict_least_recently_used(directory: &OwnedFd, request: &Eviction<'_>) -> Evicted {
    let mut evicted = Evicted::default();
    let Ok(root) = fstat(directory) else {
        return evicted;
    };
    let mut failed = HashSet::new();
    let mut first = true;
    loop {
        let mut measure = Measure {
            request,
            failed: &failed,
            linked: HashSet::new(),
            total: 0,
            minutes: BTreeMap::new(),
            stopped: false,
        };
        walk_tree(directory, &root, (), &mut measure);
        if measure.stopped {
            evicted.stopped = true;
            return evicted;
        }
        let total = measure.total;
        if first {
            evicted.bytes_before = total;
            evicted.bytes_after = total;
            if total <= request.above {
                return evicted;
            }
            first = false;
        }
        if total <= request.down_to {
            return evicted;
        }
        let need = total - request.down_to;
        let Some((cutoff, cutoff_bytes)) = cutoff(&measure.minutes, need) else {
            return evicted;
        };
        let failed_before = failed.len();
        let mut removal = Removal {
            request,
            failed: &mut failed,
            cutoff,
            cutoff_bytes,
            need,
            freed: 0,
            freed_directories: 0,
            removed_linked: HashSet::new(),
            removed_files: 0,
            stopped: false,
        };
        walk_tree(directory, &root, Changed::default(), &mut removal);
        let freed = removal.freed.saturating_add(removal.freed_directories);
        evicted.removed_files = evicted.removed_files.saturating_add(removal.removed_files);
        evicted.removed_bytes = evicted.removed_bytes.saturating_add(freed);
        evicted.bytes_after = total.saturating_sub(freed);
        if removal.stopped {
            evicted.stopped = true;
        }
        let enough = removal.freed >= need;
        evicted.failed_files = widened(failed.len()).unwrap_or(u64::MAX);
        if evicted.stopped || enough || failed.len() == failed_before {
            return evicted;
        }
    }
}

/// The last minute the oldest removable bytes are taken through to reach `need`, and the
/// bytes still to free within it; every minute, without a limit within the last, when the
/// histogram holds less than `need`.
fn cutoff(minutes: &BTreeMap<i64, u64>, need: u64) -> Option<(i64, u64)> {
    let mut taken = 0_u64;
    for (&minute, &bytes) in minutes {
        let short = need.saturating_sub(taken);
        taken = taken.saturating_add(bytes);
        if taken >= need {
            return Some((minute, short));
        }
    }
    minutes
        .last_key_value()
        .map(|(&minute, _)| (minute, u64::MAX))
}

/// The minute of a file's last use: the later of its access and modification times.
fn last_used_minute(metadata: &Stat) -> i64 {
    seconds(metadata.st_atime)
        .max(seconds(metadata.st_mtime))
        .div_euclid(60)
}

/// `stat` time widths differ across Unix targets; each fits an `i64` where the runner runs.
fn seconds<T: TryInto<i64>>(value: T) -> i64 {
    value.try_into().unwrap_or(i64::MAX)
}

fn allocated(metadata: &Stat) -> u64 {
    widened(metadata.st_blocks).unwrap_or(0).saturating_mul(512)
}

fn identity(metadata: &Stat) -> Option<(u64, u64)> {
    Some((widened(metadata.st_dev)?, widened(metadata.st_ino)?))
}

fn is_directory(metadata: &Stat) -> bool {
    FileType::from_raw_mode(metadata.st_mode) == FileType::Directory
}

fn is_protected(request: &Eviction<'_>, metadata: &Stat) -> bool {
    identity(metadata).is_some_and(|identity| request.protected.contains(&identity))
}

fn is_kept(request: &Eviction<'_>, name: &CStr, top: bool) -> bool {
    top && request
        .keep
        .iter()
        .any(|kept| kept.as_bytes() == name.to_bytes())
}

/// The measuring walk: the total and the histogram of removable bytes by minute.
struct Measure<'a, 'r> {
    request: &'a Eviction<'r>,
    failed: &'a HashSet<(u64, u64)>,
    /// Files with several names already counted.
    linked: HashSet<(u64, u64)>,
    total: u64,
    minutes: BTreeMap<i64, u64>,
    stopped: bool,
}

impl TreeVisitor for Measure<'_, '_> {
    type Frame = ();

    fn entry(
        &mut self,
        _: &mut (),
        _: BorrowedFd<'_>,
        name: &CStr,
        top: bool,
        metadata: &Stat,
    ) -> Next<()> {
        if is_directory(metadata) {
            if is_protected(self.request, metadata) {
                return Next::Skip;
            }
            self.total = self.total.saturating_add(allocated(metadata));
            if !(self.request.may_continue)() {
                self.stopped = true;
                return Next::Abandon;
            }
            return Next::Enter(());
        }
        let identity = identity(metadata);
        if metadata.st_nlink > 1 && !identity.is_some_and(|identity| self.linked.insert(identity)) {
            return Next::Skip;
        }
        let bytes = allocated(metadata);
        self.total = self.total.saturating_add(bytes);
        if is_kept(self.request, name, top)
            || identity.is_some_and(|identity| self.failed.contains(&identity))
        {
            return Next::Skip;
        }
        let minute = self.minutes.entry(last_used_minute(metadata)).or_default();
        *minute = minute.saturating_add(bytes);
        Next::Skip
    }
}

/// Whether the removing walk removed anything from an open directory, and the bytes the
/// directory itself holds.
#[derive(Default)]
struct Changed {
    removed: bool,
    bytes: u64,
}

/// The removing walk: the files up to the cutoff, then the directories that leaves empty.
struct Removal<'a, 'r> {
    request: &'a Eviction<'r>,
    failed: &'a mut HashSet<(u64, u64)>,
    cutoff: i64,
    /// What is still to free from files last used in the cutoff minute.
    cutoff_bytes: u64,
    need: u64,
    freed: u64,
    freed_directories: u64,
    /// Removed names of files that had others, which go whenever the walk meets them.
    removed_linked: HashSet<(u64, u64)>,
    removed_files: u64,
    stopped: bool,
}

impl Removal<'_, '_> {
    fn may_continue(&mut self) -> bool {
        if !(self.request.may_continue)() {
            self.stopped = true;
        }
        !self.stopped
    }

    fn chosen(&self, metadata: &Stat) -> bool {
        let minute = last_used_minute(metadata);
        minute < self.cutoff || (minute == self.cutoff && self.cutoff_bytes > 0)
    }
}

impl TreeVisitor for Removal<'_, '_> {
    type Frame = Changed;

    fn entry(
        &mut self,
        frame: &mut Changed,
        parent: BorrowedFd<'_>,
        name: &CStr,
        top: bool,
        metadata: &Stat,
    ) -> Next<Changed> {
        if self.freed >= self.need {
            return Next::Finish;
        }
        if is_directory(metadata) {
            if is_protected(self.request, metadata) {
                return Next::Skip;
            }
            if !self.may_continue() {
                return Next::Abandon;
            }
            return Next::Enter(Changed {
                removed: false,
                bytes: allocated(metadata),
            });
        }
        if is_kept(self.request, name, top) {
            return Next::Skip;
        }
        let identity = identity(metadata);
        if identity.is_some_and(|identity| self.failed.contains(&identity)) {
            return Next::Skip;
        }
        let other_name = identity.is_some_and(|identity| self.removed_linked.contains(&identity));
        if !other_name && !self.chosen(metadata) {
            return Next::Skip;
        }
        if !self.may_continue() {
            return Next::Abandon;
        }
        match unlinkat(parent, name, AtFlags::empty()) {
            Ok(()) => {
                frame.removed = true;
                if !other_name {
                    self.removed_files = self.removed_files.saturating_add(1);
                }
                // A file's bytes are freed with its last name; until then its other names
                // go whenever the walk meets them.
                if metadata.st_nlink > 1 {
                    if let Some(identity) = identity {
                        self.removed_linked.insert(identity);
                    }
                    return Next::Skip;
                }
                let bytes = allocated(metadata);
                self.freed = self.freed.saturating_add(bytes);
                if last_used_minute(metadata) == self.cutoff {
                    self.cutoff_bytes = self.cutoff_bytes.saturating_sub(bytes);
                }
            }
            Err(Errno::NOENT) => {}
            Err(_) => {
                if !other_name && let Some(identity) = identity {
                    self.failed.insert(identity);
                }
            }
        }
        Next::Skip
    }

    fn leave(
        &mut self,
        parent_frame: &mut Changed,
        parent: BorrowedFd<'_>,
        name: &CStr,
        frame: Changed,
    ) -> bool {
        if !frame.removed {
            return true;
        }
        if !self.may_continue() {
            return false;
        }
        // A directory that still holds anything, or was replaced, stays (`NOTEMPTY`, `EXIST`).
        if unlinkat(parent, name, AtFlags::REMOVEDIR).is_ok() {
            parent_frame.removed = true;
            self.freed_directories = self.freed_directories.saturating_add(frame.bytes);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use rustix::fs::{AtFlags, CWD, Mode, Timespec, Timestamps, open, utimensat};

    use super::super::directory_open_flags;
    use super::*;

    const NOW: i64 = 1_700_000_000;
    const HOUR: i64 = 3_600;
    const DAY: i64 = 86_400;

    fn allocated(path: &Path) -> u64 {
        fs::symlink_metadata(path).unwrap().blocks() * 512
    }

    fn allocated_sum(paths: &[&Path]) -> u64 {
        paths.iter().map(|path| allocated(path)).sum()
    }

    fn set_times(path: &Path, accessed: i64, modified: i64) {
        let at = |seconds| Timespec {
            tv_sec: seconds,
            tv_nsec: 0,
        };
        utimensat(
            CWD,
            path,
            &Timestamps {
                last_access: at(accessed),
                last_modification: at(modified),
            },
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .unwrap();
    }

    /// Writes a file of 64 KiB last used `ago` seconds before `NOW`.
    fn file(path: &Path, ago: i64) -> PathBuf {
        fs::write(path, vec![7_u8; 64 * 1024]).unwrap();
        set_times(path, NOW - ago, NOW - ago);
        path.to_path_buf()
    }

    fn directory(path: &Path) -> PathBuf {
        fs::create_dir_all(path).unwrap();
        path.to_path_buf()
    }

    fn opened(path: &Path) -> OwnedFd {
        open(path, directory_open_flags(), Mode::empty()).unwrap()
    }

    fn evict(path: &Path, above: u64, down_to: u64) -> Evicted {
        evict_least_recently_used(
            &opened(path),
            &Eviction {
                above,
                down_to,
                keep: &["CACHEDIR.TAG"],
                protected: &[],
                may_continue: &|| true,
            },
        )
    }

    fn cache() -> (tempfile::TempDir, PathBuf) {
        let temporary = tempfile::tempdir().unwrap();
        let cache = directory(&temporary.path().join("cache"));
        (temporary, cache)
    }

    // REQ-RUNNERENROLL-161, INV-RUNNER-52
    #[test]
    fn eviction_removes_the_least_recently_used_files_down_to_the_target() {
        let (_temporary, cache) = cache();
        let first = directory(&cache.join("first"));
        let second = directory(&cache.join("second"));
        let oldest = file(&first.join("oldest"), 4 * DAY);
        let older = file(&cache.join("older"), 3 * DAY);
        let newer = file(&first.join("newer"), 2 * DAY);
        let newest = file(&second.join("newest"), DAY);
        let total = allocated_sum(&[&first, &second, &oldest, &older, &newer, &newest]);
        let kept = allocated_sum(&[&first, &second, &newer, &newest]);
        assert!(allocated(&oldest) > 0);

        let evicted = evict(&cache, total - 1, kept);

        assert!(!oldest.exists());
        assert!(!older.exists());
        assert!(newer.exists() && newest.exists());
        assert_eq!(evicted.bytes_before, total);
        assert_eq!(evicted.removed_files, 2);
        assert_eq!(
            evicted.removed_bytes,
            total - kept,
            "the removed files' bytes"
        );
        assert_eq!(evicted.bytes_after, kept);
        assert_eq!(evicted.failed_files, 0);
        assert!(!evicted.stopped);
    }

    // REQ-RUNNERENROLL-161
    #[test]
    fn a_files_last_use_is_the_later_of_its_access_and_modification() {
        let (_temporary, cache) = cache();
        let read_lately = cache.join("read-lately");
        file(&read_lately, 0);
        set_times(&read_lately, NOW - HOUR, NOW - 5 * DAY);
        let used_earlier = file(&cache.join("used-earlier"), 2 * DAY);
        let total = allocated_sum(&[&read_lately, &used_earlier]);

        evict(&cache, total - 1, allocated(&read_lately));

        assert!(read_lately.exists());
        assert!(!used_earlier.exists());
    }

    // REQ-RUNNERENROLL-161
    #[test]
    fn a_tree_within_its_bound_loses_nothing() {
        let (_temporary, cache) = cache();
        let old = file(&cache.join("old"), 9 * DAY);
        let total = allocated(&old);

        let evicted = evict(&cache, total, 0);

        assert!(old.exists());
        assert_eq!(evicted.bytes_before, total);
        assert_eq!(evicted.bytes_after, total);
        assert_eq!((evicted.removed_files, evicted.removed_bytes), (0, 0));
    }

    // REQ-RUNNERENROLL-161, INV-RUNNER-52
    #[test]
    fn a_file_with_two_names_counts_once_and_loses_both() {
        let (_temporary, cache) = cache();
        let first = directory(&cache.join("first"));
        let second = directory(&cache.join("second"));
        let linked = file(&first.join("linked"), 4 * DAY);
        let other_name = second.join("other-name");
        fs::hard_link(&linked, &other_name).unwrap();
        let first_kept = file(&first.join("kept"), DAY);
        let second_kept = file(&second.join("kept"), DAY);
        let kept = allocated_sum(&[&first, &second, &first_kept, &second_kept]);
        let total = kept + allocated(&linked);

        let evicted = evict(&cache, total - 1, kept);

        assert_eq!(evicted.bytes_before, total);
        assert!(!linked.exists());
        assert!(!other_name.exists());
        assert!(first_kept.exists() && second_kept.exists());
        assert_eq!(evicted.removed_bytes, total - kept);
        assert_eq!(evicted.removed_files, 1);
    }

    // REQ-RUNNERENROLL-161, INV-RUNNER-52
    #[test]
    fn a_symbolic_link_counts_and_goes_alone_and_is_never_entered() {
        let temporary = tempfile::tempdir().unwrap();
        let cache = directory(&temporary.path().join("cache"));
        let outside = directory(&temporary.path().join("outside"));
        let large = outside.join("large");
        fs::write(&large, vec![7_u8; 4 * 1024 * 1024]).unwrap();
        let outside_old = file(&outside.join("old"), 9 * DAY);
        let file_link = cache.join("file-link");
        std::os::unix::fs::symlink(&large, &file_link).unwrap();
        set_times(&file_link, NOW - 6 * DAY, NOW - 6 * DAY);
        let directory_link = cache.join("directory-link");
        std::os::unix::fs::symlink(&outside, &directory_link).unwrap();
        set_times(&directory_link, NOW - 5 * DAY, NOW - 5 * DAY);
        // The tag can never go, so a target of 0 is never reached and every entry is met.
        let tag = file(&cache.join("CACHEDIR.TAG"), DAY);
        let total = allocated_sum(&[&file_link, &directory_link, &tag]);

        let evicted = evict(&cache, 0, 0);

        assert_eq!(evicted.bytes_before, total);
        assert!(total < allocated(&large));
        assert!(fs::symlink_metadata(&file_link).is_err());
        assert!(fs::symlink_metadata(&directory_link).is_err());
        assert_eq!(fs::read(&large).unwrap().len(), 4 * 1024 * 1024);
        assert!(outside_old.exists());
        assert_eq!(evicted.removed_files, 2);
    }

    // REQ-RUNNERENROLL-161, INV-RUNNER-52
    #[test]
    fn the_cache_directory_tag_directly_in_it_stays_even_at_target_zero() {
        let (_temporary, cache) = cache();
        let tag = file(&cache.join("CACHEDIR.TAG"), 30 * DAY);
        let nested = directory(&cache.join("nested"));
        let nested_tag = file(&nested.join("CACHEDIR.TAG"), 20 * DAY);
        let other = file(&cache.join("other"), DAY);

        let evicted = evict(&cache, 0, 0);

        assert!(tag.exists());
        assert!(!nested_tag.exists());
        assert!(!other.exists());
        assert_eq!(evicted.removed_files, 2);
        assert_eq!(evicted.bytes_after, allocated(&tag));
    }

    // REQ-RUNNERENROLL-161, INV-RUNNER-52
    #[test]
    fn only_the_directories_the_removals_emptied_go_and_never_the_cache() {
        let (_temporary, cache) = cache();
        let outer = directory(&cache.join("outer"));
        let inner = directory(&outer.join("inner"));
        let deepest = file(&inner.join("deepest"), 4 * DAY);
        let holding = directory(&cache.join("holding"));
        let held_old = file(&holding.join("old"), 3 * DAY);
        let held_new = file(&holding.join("new"), DAY);
        let empty = directory(&cache.join("empty"));
        let total = allocated_sum(&[
            &outer, &inner, &deepest, &holding, &held_old, &held_new, &empty,
        ]);
        let need = allocated_sum(&[&deepest, &held_old]);
        let emptied = allocated_sum(&[&outer, &inner]);

        let evicted = evict(&cache, total - 1, total - need);

        assert!(!inner.exists());
        assert!(!outer.exists());
        assert!(held_new.exists());
        assert!(!held_old.exists());
        assert!(empty.is_dir());
        assert_eq!(evicted.removed_files, 2);
        assert_eq!(evicted.removed_bytes, emptied + need);

        evict(&cache, 0, 0);

        assert!(!holding.exists());
        assert!(empty.is_dir());
        assert!(cache.is_dir());
        assert_eq!(fs::read_dir(&cache).unwrap().count(), 1);
    }

    // REQ-RUNNERENROLL-161
    #[test]
    fn a_file_that_cannot_be_removed_fails_and_the_next_oldest_goes() {
        let (_temporary, cache) = cache();
        let locked = directory(&cache.join("locked"));
        let stuck = file(&locked.join("stuck"), 4 * DAY);
        let next = file(&cache.join("next"), 3 * DAY);
        let newer = file(&cache.join("newer"), 2 * DAY);
        let newest = file(&cache.join("newest"), DAY);
        fs::set_permissions(&locked, Permissions::from_mode(0o500)).unwrap();
        let total = allocated_sum(&[&locked, &stuck, &next, &newer, &newest]);

        let evicted = evict(&cache, total - 1, total - allocated(&next));
        fs::set_permissions(&locked, Permissions::from_mode(0o700)).unwrap();

        assert!(stuck.exists());
        assert!(!next.exists());
        assert!(newer.exists() && newest.exists());
        assert_eq!(evicted.failed_files, 1);
        assert_eq!(evicted.removed_files, 1);
    }

    // REQ-RUNNERENROLL-161, INV-RUNNER-52
    #[test]
    fn a_protected_directory_is_neither_entered_nor_counted() {
        let (_temporary, cache) = cache();
        let protected = directory(&cache.join("protected"));
        let inside = file(&protected.join("inside"), 9 * DAY);
        let outside = file(&cache.join("outside"), DAY);
        let metadata = fs::symlink_metadata(&protected).unwrap();
        let total = allocated(&outside);

        let evicted = evict_least_recently_used(
            &opened(&cache),
            &Eviction {
                above: 0,
                down_to: 0,
                keep: &[],
                protected: &[(metadata.dev(), metadata.ino())],
                may_continue: &|| true,
            },
        );

        assert_eq!(evicted.bytes_before, total);
        assert!(inside.exists());
        assert!(!outside.exists());
        assert_eq!(evicted.removed_files, 1);
    }

    // REQ-RUNNERENROLL-161, INV-RUNNER-52
    #[test]
    fn a_stopped_eviction_removes_nothing_more_and_says_so() {
        let (_temporary, cache) = cache();
        let first = directory(&cache.join("first"));
        let second = directory(&cache.join("second"));
        let files = [
            file(&first.join("only"), 3 * DAY),
            file(&second.join("only"), 2 * DAY),
            file(&cache.join("top"), DAY),
        ];

        let evicted = evict_least_recently_used(
            &opened(&cache),
            &Eviction {
                above: 0,
                down_to: 0,
                keep: &[],
                protected: &[],
                may_continue: &|| files.iter().all(|path| path.exists()),
            },
        );

        assert!(evicted.stopped);
        assert_eq!(files.iter().filter(|path| !path.exists()).count(), 1);
        assert!(first.is_dir() && second.is_dir());
        assert_eq!(evicted.removed_files, 1);
    }
}
