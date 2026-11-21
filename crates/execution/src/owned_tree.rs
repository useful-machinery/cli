use std::os::fd::{BorrowedFd, OwnedFd};

use rustix::ffi::{CStr, CString};
use rustix::fs::{
    AtFlags, Dir, FileType, Mode, OFlags, Stat, fchmod, fstat, openat, statat, unlinkat,
};
use rustix::io::Errno;
use rustix::path::Arg;

mod eviction;

pub use eviction::{Evicted, Eviction, evict_least_recently_used};

const DIRECTORY_ENTRY_BATCH_SIZE: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemovalError {
    Filesystem(Errno),
    Replaced,
}

impl From<Errno> for RemovalError {
    fn from(error: Errno) -> Self {
        Self::Filesystem(error)
    }
}

pub fn open_directory_at(parent: &OwnedFd, identity: &str) -> Result<OwnedFd, Errno> {
    openat(parent, identity, directory_open_flags(), Mode::empty())
}

pub fn open_regular_file_at(parent: &OwnedFd, identity: &str) -> Result<(OwnedFd, Stat), Errno> {
    let descriptor = openat(
        parent,
        identity,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let opened = fstat(&descriptor)?;
    let named = statat(parent, identity, AtFlags::SYMLINK_NOFOLLOW)?;
    if FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
        || FileType::from_raw_mode(named.st_mode) != FileType::RegularFile
        || !same_identity(&opened, &named)
    {
        return Err(Errno::INVAL);
    }
    Ok((descriptor, opened))
}

/// The bytes the tree under the opened `directory` occupies: the allocated blocks of the
/// directory and of every entry below it, each file system object `(st_dev, st_ino)` counted
/// once. The walk is descriptor-relative, follows no symbolic link and does not descend into
/// another device. A subtree it cannot open or read is skipped, and what it could read is
/// counted.
pub fn allocated_tree_bytes(directory: &OwnedFd) -> u64 {
    let Ok(root) = fstat(directory) else {
        return 0;
    };
    let mut tally = AllocatedTally::default();
    count_allocated(&root, &mut tally.counted, &mut tally.total);
    walk_tree(directory, &root, (), &mut tally);
    tally.total
}

#[derive(Default)]
struct AllocatedTally {
    counted: std::collections::HashSet<(u64, u64)>,
    total: u64,
}

impl TreeVisitor for AllocatedTally {
    type Frame = ();

    fn entry(
        &mut self,
        _: &mut (),
        _: BorrowedFd<'_>,
        _: &CStr,
        _: bool,
        metadata: &Stat,
    ) -> Next<()> {
        if count_allocated(metadata, &mut self.counted, &mut self.total) {
            Next::Enter(())
        } else {
            Next::Skip
        }
    }
}

/// What `walk_tree` does after its visitor has seen an entry.
enum Next<F> {
    /// Go on with the next entry; a directory is not entered.
    Skip,
    /// Enter the entry if it is a directory, keeping `F` for it while it is open.
    Enter(F),
    /// Read no more entries, and leave each open directory, deepest first.
    Finish,
    /// Return at once, leaving no further directory.
    Abandon,
}

/// The decisions of one `walk_tree`.
trait TreeVisitor {
    /// What the visitor keeps for each open directory.
    type Frame;

    /// An entry below the root on the root's device, as `statat` without following a link
    /// read it from `parent`; `top` when `parent` is the root.
    fn entry(
        &mut self,
        frame: &mut Self::Frame,
        parent: BorrowedFd<'_>,
        name: &CStr,
        top: bool,
        metadata: &Stat,
    ) -> Next<Self::Frame>;

    /// A directory the walk entered, once its entries are done or the walk finishes, with
    /// what was kept for it and for `parent`, the directory it was read from. Answers false to
    /// return at once.
    fn leave(
        &mut self,
        _parent_frame: &mut Self::Frame,
        _parent: BorrowedFd<'_>,
        _name: &CStr,
        _frame: Self::Frame,
    ) -> bool {
        true
    }
}

/// An open directory of a walk, the root's without a name.
struct OpenDirectory<F> {
    entries: Dir,
    name: Option<CString>,
    frame: F,
}

/// Walks the tree below the opened `directory`, whose metadata is `root`, depth first and
/// descriptor-relative: it reads each entry with `statat` and `SYMLINK_NOFOLLOW`, skips one
/// on another device than the root's, and enters a directory its visitor asks it to enter
/// only through `openat` with `O_NOFOLLOW` and when the opened directory is the one it read.
/// A directory it cannot open or read is skipped.
fn walk_tree<V: TreeVisitor>(directory: &OwnedFd, root: &Stat, frame: V::Frame, visitor: &mut V) {
    let Ok(entries) = Dir::read_from(directory) else {
        return;
    };
    let mut open = vec![OpenDirectory {
        entries,
        name: None,
        frame,
    }];
    loop {
        let top = open.len() == 1;
        let Some(current) = open.last_mut() else {
            return;
        };
        let Some(Ok(entry)) = current.entries.next() else {
            if !leave_directory(&mut open, visitor) {
                return;
            }
            continue;
        };
        if matches!(entry.file_name().to_bytes(), b"." | b"..") {
            continue;
        }
        let Ok(parent) = current.entries.fd() else {
            if !leave_directory(&mut open, visitor) {
                return;
            }
            continue;
        };
        let Ok(observed) = statat(parent, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW) else {
            continue;
        };
        if observed.st_dev != root.st_dev {
            continue;
        }
        let frame = match visitor.entry(
            &mut current.frame,
            parent,
            entry.file_name(),
            top,
            &observed,
        ) {
            Next::Skip => continue,
            Next::Enter(frame) => frame,
            Next::Finish => {
                while !open.is_empty() {
                    if !leave_directory(&mut open, visitor) {
                        return;
                    }
                }
                return;
            }
            Next::Abandon => return,
        };
        if FileType::from_raw_mode(observed.st_mode) != FileType::Directory {
            continue;
        }
        let Ok(child) = openat(
            parent,
            entry.file_name(),
            directory_open_flags(),
            Mode::empty(),
        ) else {
            continue;
        };
        if !fstat(&child).is_ok_and(|opened| same_identity(&opened, &observed)) {
            continue;
        }
        if let Ok(entries) = Dir::new(child) {
            open.push(OpenDirectory {
                entries,
                name: Some(entry.file_name().to_owned()),
                frame,
            });
        }
    }
}

/// Closes the deepest open directory and gives it to the visitor's `leave`; answers false
/// when the walk is to return at once.
fn leave_directory<V: TreeVisitor>(
    open: &mut Vec<OpenDirectory<V::Frame>>,
    visitor: &mut V,
) -> bool {
    let Some(OpenDirectory {
        entries,
        name,
        frame,
    }) = open.pop()
    else {
        return false;
    };
    drop(entries);
    let (Some(name), Some(parent)) = (name, open.last_mut()) else {
        return true;
    };
    let Ok(descriptor) = parent.entries.fd() else {
        return true;
    };
    visitor.leave(&mut parent.frame, descriptor, &name, frame)
}

/// Adds the allocated bytes of `metadata` to `total` unless its object was counted before,
/// and answers whether it was new.
fn count_allocated(
    metadata: &Stat,
    counted: &mut std::collections::HashSet<(u64, u64)>,
    total: &mut u64,
) -> bool {
    let (Some(device), Some(inode)) = (widened(metadata.st_dev), widened(metadata.st_ino)) else {
        return false;
    };
    if !counted.insert((device, inode)) {
        return false;
    }
    let blocks = widened(metadata.st_blocks).unwrap_or(0);
    *total = total.saturating_add(blocks.saturating_mul(512));
    true
}

/// `stat` field widths differ across Unix targets; every field read here fits a `u64`.
fn widened<T: TryInto<u64>>(value: T) -> Option<u64> {
    value.try_into().ok()
}

pub(crate) fn remove_tree_at(parent: &OwnedFd, identity: &str) -> Result<(), RemovalError> {
    let directory = match openat(parent, identity, directory_open_flags(), Mode::empty()) {
        Ok(directory) => directory,
        Err(Errno::NOENT) => return Ok(()),
        Err(failure) => return Err(failure.into()),
    };
    remove_open_tree_at(parent, identity, &directory)
}

pub fn remove_open_tree_at(
    parent: &OwnedFd,
    identity: &str,
    directory: &OwnedFd,
) -> Result<(), RemovalError> {
    let identity = identity.into_c_str()?;
    remove_open_tree_named(parent, &identity, directory, &mut |_, _| {})
}

fn remove_open_tree_named<H>(
    parent: &OwnedFd,
    identity: &CStr,
    directory: &OwnedFd,
    before_permission_restore: &mut H,
) -> Result<(), RemovalError>
where
    H: FnMut(&OwnedFd, &CStr),
{
    validate_named_directory(parent, identity, directory)?;
    before_permission_restore(parent, identity);
    validate_named_directory(parent, identity, directory)?;
    fchmod(directory, Mode::RWXU)?;
    validate_named_directory(parent, identity, directory)?;
    remove_directory_contents(directory, before_permission_restore)?;
    validate_named_directory(parent, identity, directory)?;
    unlinkat(parent, identity, AtFlags::REMOVEDIR).map_err(classify_unlink_error)
}

fn remove_directory_contents<H>(
    directory: &OwnedFd,
    before_permission_restore: &mut H,
) -> Result<(), RemovalError>
where
    H: FnMut(&OwnedFd, &CStr),
{
    loop {
        let entries = directory_entry_batch(directory)?;
        if entries.is_empty() {
            return Ok(());
        }
        for name in entries {
            remove_entry(directory, &name, before_permission_restore)?;
        }
    }
}

fn directory_entry_batch(directory: &OwnedFd) -> Result<Vec<CString>, RemovalError> {
    let mut entries = Vec::with_capacity(DIRECTORY_ENTRY_BATCH_SIZE);
    for entry in Dir::read_from(directory)? {
        let entry = entry?;
        if matches!(entry.file_name().to_bytes(), b"." | b"..") {
            continue;
        }
        entries.push(entry.file_name().to_owned());
        if entries.len() == DIRECTORY_ENTRY_BATCH_SIZE {
            break;
        }
    }
    Ok(entries)
}

fn remove_entry<H>(
    parent: &OwnedFd,
    name: &CStr,
    before_permission_restore: &mut H,
) -> Result<(), RemovalError>
where
    H: FnMut(&OwnedFd, &CStr),
{
    let observed =
        statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(classify_restat_error)?;
    if FileType::from_raw_mode(observed.st_mode) == FileType::Directory {
        let child = openat(parent, name, directory_open_flags(), Mode::empty())
            .map_err(classify_open_after_stat_error)?;
        let opened = fstat(&child)?;
        if !same_identity(&observed, &opened) {
            return Err(RemovalError::Replaced);
        }
        remove_open_tree_named(parent, name, &child, before_permission_restore)
    } else {
        let current =
            statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(classify_restat_error)?;
        if !same_identity(&observed, &current) {
            return Err(RemovalError::Replaced);
        }
        unlinkat(parent, name, AtFlags::empty()).map_err(classify_unlink_error)
    }
}

fn validate_named_directory(
    parent: &OwnedFd,
    identity: &CStr,
    directory: &OwnedFd,
) -> Result<(), RemovalError> {
    let parent_metadata = fstat(parent)?;
    let opened = fstat(directory)?;
    let named =
        statat(parent, identity, AtFlags::SYMLINK_NOFOLLOW).map_err(classify_restat_error)?;
    if FileType::from_raw_mode(named.st_mode) != FileType::Directory
        || opened.st_uid != rustix::process::geteuid().as_raw()
        || opened.st_dev != parent_metadata.st_dev
        || !same_identity(&opened, &named)
    {
        return Err(RemovalError::Replaced);
    }
    Ok(())
}

fn same_identity(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && FileType::from_raw_mode(left.st_mode) == FileType::from_raw_mode(right.st_mode)
}

fn classify_open_after_stat_error(error: Errno) -> RemovalError {
    match error {
        Errno::NOENT | Errno::NOTDIR | Errno::LOOP => RemovalError::Replaced,
        _ => RemovalError::Filesystem(error),
    }
}

fn classify_restat_error(error: Errno) -> RemovalError {
    match error {
        Errno::NOENT | Errno::NOTDIR | Errno::LOOP => RemovalError::Replaced,
        _ => RemovalError::Filesystem(error),
    }
}

fn classify_unlink_error(error: Errno) -> RemovalError {
    match error {
        Errno::NOENT | Errno::NOTDIR | Errno::ISDIR | Errno::NOTEMPTY | Errno::EXIST => {
            RemovalError::Replaced
        }
        _ => RemovalError::Filesystem(error),
    }
}

fn directory_open_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    use rustix::fs::open;

    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn allocated_bytes_count_each_inode_once_and_follow_no_link() {
        use std::os::unix::fs::MetadataExt as _;

        let allocated = |path: &Path| fs::symlink_metadata(path).unwrap().blocks() * 512;
        let temporary = tempfile::tempdir().unwrap();
        let tree = temporary.path().join("tree");
        let nested = tree.join("nested");
        fs::create_dir_all(&nested).unwrap();
        let file = tree.join("file");
        fs::write(&file, vec![7_u8; 64 * 1024]).unwrap();
        fs::hard_link(&file, nested.join("second-link")).unwrap();
        let outside = temporary.path().join("outside");
        fs::write(&outside, vec![7_u8; 4 * 1024 * 1024]).unwrap();
        std::os::unix::fs::symlink(&outside, tree.join("outside-link")).unwrap();
        let directory = open(&tree, directory_open_flags(), Mode::empty()).unwrap();

        let counted = [&tree, &file, &nested, &tree.join("outside-link")]
            .into_iter()
            .map(|path| allocated(path))
            .sum::<u64>();

        assert!(allocated(&file) > 0);
        assert_eq!(allocated_tree_bytes(&directory), counted);
        assert!(counted < allocated(&outside));
    }

    #[test]
    fn removal_reenumerates_directories_larger_than_one_batch() {
        let temporary = tempfile::tempdir().unwrap();
        let owned = temporary.path().join("owned");
        fs::create_dir(&owned).unwrap();
        for index in 0..DIRECTORY_ENTRY_BATCH_SIZE * 2 + 1 {
            let path = owned.join(format!("entry-{index:03}"));
            fs::write(&path, b"value").unwrap();
            fs::set_permissions(path, Permissions::from_mode(0o400)).unwrap();
        }
        fs::set_permissions(&owned, Permissions::from_mode(0o500)).unwrap();
        let parent = open(temporary.path(), directory_open_flags(), Mode::empty()).unwrap();

        remove_tree_at(&parent, "owned").unwrap();

        assert!(!owned.exists());
    }

    #[test]
    fn relocated_directory_is_rejected_before_permission_restoration() {
        let temporary = tempfile::tempdir().unwrap();
        let owned = temporary.path().join("owned");
        let nested = owned.join("nested");
        let outside = temporary.path().join("outside");
        let relocated = outside.join("relocated");
        fs::create_dir(&owned).unwrap();
        fs::create_dir(&nested).unwrap();
        fs::create_dir(&outside).unwrap();
        let sentinel = nested.join("sentinel");
        fs::write(&sentinel, b"outside authority").unwrap();
        fs::set_permissions(&sentinel, Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(&nested, Permissions::from_mode(0o500)).unwrap();
        let parent = open(temporary.path(), directory_open_flags(), Mode::empty()).unwrap();
        let directory = openat(&parent, "owned", directory_open_flags(), Mode::empty()).unwrap();

        let result = remove_open_tree_named(&parent, c"owned", &directory, &mut |_, identity| {
            if identity.to_bytes() == b"nested" {
                assert_eq!(mode(&owned), 0o700);
                assert_ne!(mode(&outside) & 0o200, 0);
                fs::set_permissions(&nested, Permissions::from_mode(0o700)).unwrap();
                fs::rename(&nested, &relocated).unwrap();
                fs::set_permissions(&relocated, Permissions::from_mode(0o500)).unwrap();
            }
        });

        assert_eq!(result, Err(RemovalError::Replaced));
        assert_eq!(
            fs::read(relocated.join("sentinel")).unwrap(),
            b"outside authority"
        );
        assert_eq!(mode(&relocated), 0o500);
        assert_eq!(mode(&relocated.join("sentinel")), 0o400);

        fs::set_permissions(&relocated, Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn replacement_is_rejected_before_permission_restoration() {
        let temporary = tempfile::tempdir().unwrap();
        let owned = temporary.path().join("owned");
        let nested = owned.join("nested");
        let outside = temporary.path().join("outside");
        let replacement = outside.join("replacement");
        let displaced = outside.join("displaced");
        fs::create_dir(&owned).unwrap();
        fs::create_dir(&nested).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::create_dir(&replacement).unwrap();
        fs::write(nested.join("original"), b"original").unwrap();
        let sentinel = replacement.join("sentinel");
        fs::write(&sentinel, b"outside authority").unwrap();
        fs::set_permissions(&sentinel, Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(&nested, Permissions::from_mode(0o500)).unwrap();
        fs::set_permissions(&replacement, Permissions::from_mode(0o500)).unwrap();

        let parent = open(temporary.path(), directory_open_flags(), Mode::empty()).unwrap();
        let directory = open_directory_at(&parent, "owned").unwrap();

        let result = remove_open_tree_named(&parent, c"owned", &directory, &mut |_, identity| {
            if identity.to_bytes() == b"nested" {
                fs::set_permissions(&nested, Permissions::from_mode(0o700)).unwrap();
                fs::rename(&nested, &displaced).unwrap();
                fs::set_permissions(&displaced, Permissions::from_mode(0o500)).unwrap();
                fs::set_permissions(&replacement, Permissions::from_mode(0o700)).unwrap();
                fs::rename(&replacement, &nested).unwrap();
                fs::set_permissions(&nested, Permissions::from_mode(0o500)).unwrap();
            }
        });

        assert_eq!(result, Err(RemovalError::Replaced));
        let replacement_mode = mode(&nested);
        let displaced_mode = mode(&displaced);
        let sentinel_mode = mode(&nested.join("sentinel"));
        let sentinel_contents = fs::read(nested.join("sentinel")).unwrap();
        fs::set_permissions(&nested, Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&displaced, Permissions::from_mode(0o700)).unwrap();

        assert_eq!(
            replacement_mode, 0o500,
            "cleanup changed permissions on the unvalidated replacement"
        );
        assert_eq!(displaced_mode, 0o500);
        assert_eq!(sentinel_mode, 0o400);
        assert_eq!(sentinel_contents, b"outside authority");
    }
}
