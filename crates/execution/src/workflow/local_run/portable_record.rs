//! Portable copies of the durable part of a run directory.

use super::*;
use std::fs::Metadata;
use std::os::unix::fs::MetadataExt as _;

#[derive(Debug)]
pub struct CreatedPortableRecord {
    pub run: String,
    pub record_directory: PathBuf,
    pub file_count: u64,
    pub total_bytes: u64,
}

#[derive(Debug)]
pub enum PortableRecordError {
    RunLocked,
    RunChanging,
    OwnershipUnproven {
        guards: Vec<String>,
        reason: OwnershipUnprovenReason,
    },
    ChildRun,
    RunRecordMissing,
    RunDirectoryInvalid(Box<LocalRunDirectoryError>),
    DestinationExists,
    RecordIncomplete(PathBuf),
    RecordAltered(PathBuf),
    RecordInvalid(PathBuf),
    RecordUnavailable {
        path: PathBuf,
        source: io::Error,
    },
}

impl PortableRecordError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::RunChanging => "run_changing",
            Self::RunLocked => "run_locked",
            Self::OwnershipUnproven { .. } => "ownership_unproven",
            Self::ChildRun => "child_run",
            Self::RunRecordMissing => "run_record_missing",
            Self::RunDirectoryInvalid(_) => "run_directory_invalid",
            Self::DestinationExists => "destination_exists",
            Self::RecordIncomplete(_) => "record_incomplete",
            Self::RecordAltered(_) => "record_altered",
            Self::RecordInvalid(_) => "record_invalid",
            Self::RecordUnavailable { .. } => "record_unavailable",
        }
    }

    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::RecordIncomplete(path)
            | Self::RecordAltered(path)
            | Self::RecordInvalid(path)
            | Self::RecordUnavailable { path, .. } => Some(path),
            _ => None,
        }
    }

    fn io(path: &Path, source: impl Into<io::Error>) -> Self {
        Self::RecordUnavailable {
            path: path.to_owned(),
            source: source.into(),
        }
    }
}

impl fmt::Display for PortableRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordUnavailable { path, source } => {
                write!(f, "{}: {}: {source}", self.code(), path.display())
            }
            Self::RunDirectoryInvalid(cause) => write!(f, "{}: {cause}", self.code()),
            Self::OwnershipUnproven { guards, reason } => {
                write!(f, "{}: {}", self.code(), reason.as_str())?;
                if !guards.is_empty() {
                    write!(f, ": {}", guards.join(", "))?;
                }
                Ok(())
            }
            _ if let Some(path) = self.path() => write!(f, "{}: {}", self.code(), path.display()),
            _ => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for PortableRecordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RecordUnavailable { source, .. } => Some(source),
            Self::RunDirectoryInvalid(cause) => Some(cause),
            _ => None,
        }
    }
}

impl From<LocalRunDirectoryError> for PortableRecordError {
    fn from(error: LocalRunDirectoryError) -> Self {
        match error {
            LocalRunDirectoryError::File { ref source, .. }
                if matches!(source.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) =>
            {
                Self::RunDirectoryInvalid(Box::new(error))
            }
            LocalRunDirectoryError::File { path, source, .. } => {
                Self::RecordUnavailable { path, source }
            }
            LocalRunDirectoryError::StateFile { source, .. }
                if matches!(*source, LocalRunDirectoryError::File { .. }) =>
            {
                Self::from(*source)
            }
            // The cause names the file and what was wrong with it.
            error => Self::RunDirectoryInvalid(Box::new(error)),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordManifest {
    schema_version: u32,
    run: String,
    created_at: String,
    entries: Vec<RecordEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum RecordEntry {
    Directory {
        path: String,
        mode: String,
    },
    File {
        path: String,
        mode: String,
        size_bytes: u64,
        sha256: String,
    },
}

impl RecordEntry {
    fn path(&self) -> &str {
        match self {
            Self::Directory { path, .. } | Self::File { path, .. } => path,
        }
    }
}

type RecordResult<T> = Result<T, PortableRecordError>;

/// The entry `name` of `parent` is not one a run directory may hold.
fn invalid_entry(parent: &OwnedFd, name: impl AsRef<std::ffi::OsStr>) -> PortableRecordError {
    PortableRecordError::RunDirectoryInvalid(Box::new(LocalRunDirectoryError::StateFile {
        path: file_locator(parent, name),
        operation: "validate",
        source: Box::new(LocalRunDirectoryError::StateInvalid),
    }))
}

fn entry_name(parent: &OwnedFd, name: Vec<u8>) -> RecordResult<String> {
    use std::os::unix::ffi::OsStringExt as _;
    String::from_utf8(name)
        .map_err(|error| invalid_entry(parent, OsString::from_vec(error.into_bytes())))
}

pub fn create_portable_record(
    run: &Path,
    destination: &Path,
) -> RecordResult<CreatedPortableRecord> {
    create_with_authority(run, destination, &SystemLocalRecoveryAuthority)
}

pub(super) fn create_with_authority(
    run: &Path,
    destination: &Path,
    authority: &impl LocalQuiescenceAuthority,
) -> RecordResult<CreatedPortableRecord> {
    let (source, root) = open_run_root(run)?;
    let mut locks = Vec::new();
    let record = lock_run(&root, &mut locks, authority, true)?;
    let children = selected_children(&root, &mut |child| {
        lock_run(child, &mut locks, authority, false).map(drop)
    })?;

    let (record_directory, (file_count, total_bytes)) =
        publish_portable_directory(&source, destination, ".record", |stage| {
            mkdir(stage, PAYLOAD)?;
            let target = open_directory_at(stage, PAYLOAD)?;
            let mut writer = CopyRecord {
                entries: Vec::new(),
            };
            walk_run(&root, &target, "", children, &mut writer)?;
            let (bytes, file_count, total_bytes) = encode_manifest(&record.id, writer.entries)?;
            write_manifest(stage, &bytes)?;
            Ok((file_count, total_bytes))
        })?;
    Ok(CreatedPortableRecord {
        run: record.id,
        record_directory,
        file_count,
        total_bytes,
    })
}

fn write_manifest(stage: &OwnedFd, bytes: &[u8]) -> RecordResult<()> {
    let mut index = create_file(stage, INDEX, Mode::RUSR | Mode::WUSR)?;
    index
        .write_all(bytes)
        .and_then(|()| index.sync_all())
        .map_err(|e| file_error(stage, INDEX, "write and sync", e))?;
    Ok(())
}

/// The run and distinct digest-named files needed to assemble a portable record.
#[derive(Debug)]
pub struct PortableRecordFiles {
    pub run: String,
    pub files: Vec<(String, u64)>,
}

pub fn portable_record_files(manifest: &[u8]) -> RecordResult<PortableRecordFiles> {
    let record = RecordManifest::decode(manifest)?;
    let mut files = BTreeMap::new();
    for entry in record.entries {
        if let RecordEntry::File {
            sha256, size_bytes, ..
        } = entry
            && files
                .insert(sha256, size_bytes)
                .is_some_and(|previous| previous != size_bytes)
        {
            return Err(invalid_index());
        }
    }
    Ok(PortableRecordFiles {
        run: record.run,
        files: files.into_iter().collect(),
    })
}

/// Assemble a captured manifest and its digest-named files into a portable record.
pub fn assemble_portable_record(
    manifest: &[u8],
    files: &Path,
    destination: &Path,
) -> RecordResult<CreatedPortableRecord> {
    let record = RecordManifest::decode(manifest)?;
    let files = std::fs::canonicalize(files).map_err(|e| PortableRecordError::io(files, e))?;
    let source = open_directory_path(&files).map_err(|e| PortableRecordError::io(&files, e))?;
    let (record_directory, (file_count, total_bytes)) =
        publish_portable_directory(&files, destination, ".record", |stage| {
            mkdir(stage, PAYLOAD)?;
            let payload = open_directory_at(stage, PAYLOAD)?;
            let mut file_count = 0;
            let mut total_bytes = 0;
            // Parent paths sort before their children. Finish and sync each directory in
            // turn, keeping the number of open descriptors independent of the tree size.
            for (relative, children) in record.children() {
                let mut target = open_directory_at(&payload, ".")?;
                for component in Path::new(relative).components() {
                    target = open_directory_at(&target, component.as_os_str())?;
                }
                for (name, entry) in children {
                    match entry {
                        RecordEntry::Directory { .. } => mkdir(&target, name)?,
                        RecordEntry::File {
                            path,
                            size_bytes,
                            sha256,
                            ..
                        } => {
                            let mut output = create_file(&target, name, Mode::RUSR | Mode::WUSR)?;
                            let path = Path::new(path);
                            copy_verified_file(
                                &source,
                                sha256,
                                path,
                                *size_bytes,
                                sha256,
                                &mut output,
                            )?;
                            output
                                .sync_all()
                                .map_err(|e| PortableRecordError::io(path, e))?;
                            file_count += 1;
                            total_bytes += size_bytes;
                        }
                    }
                }
                sync_directory(&target)?;
            }
            write_manifest(stage, manifest)?;
            Ok((file_count, total_bytes))
        })?;
    Ok(CreatedPortableRecord {
        run: record.run,
        record_directory,
        file_count,
        total_bytes,
    })
}

/// Stage in the destination parent and publish with one no-replace rename. Never place
/// staging or the published directory inside the tree this operation must leave untouched.
fn publish_portable_directory<T>(
    source: &Path,
    destination: &Path,
    prefix: &str,
    fill: impl FnOnce(&OwnedFd) -> RecordResult<T>,
) -> RecordResult<(PathBuf, T)> {
    let Some(name) = destination.file_name() else {
        return Err(match std::fs::symlink_metadata(destination) {
            Ok(_) => PortableRecordError::DestinationExists,
            Err(error) => PortableRecordError::io(destination, error),
        });
    };
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent_path =
        std::fs::canonicalize(parent).map_err(|e| PortableRecordError::io(parent, e))?;
    let record_directory = parent_path.join(name);
    let parent =
        open_directory_path(&parent_path).map_err(|e| PortableRecordError::io(&parent_path, e))?;
    match statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => return Err(PortableRecordError::DestinationExists),
        Err(Errno::NOENT) => {}
        Err(e) => return Err(PortableRecordError::io(&record_directory, e)),
    }
    if parent_path.starts_with(source) {
        return Err(PortableRecordError::io(
            &record_directory,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the destination lies inside the directory being copied",
            ),
        ));
    }
    let (stage_name, stage_root) =
        create_staging_root(&parent, prefix, STAGING_ATTEMPTS).map_err(|()| {
            PortableRecordError::io(
                &parent_path,
                io::Error::other("could not create record staging directory"),
            )
        })?;
    let mut stage = InitialStaging {
        parent: &parent,
        name: stage_name,
        root: stage_root,
        committed: false,
    };
    let result = fill(&stage.root)?;
    sync_directory(&stage.root)?;
    renameat_with(
        &parent,
        stage.name.as_ref(),
        &parent,
        name,
        RenameFlags::NOREPLACE,
    )
    .map_err(|e| match e {
        Errno::EXIST | Errno::NOTEMPTY => PortableRecordError::DestinationExists,
        _ => PortableRecordError::io(&record_directory, e),
    })?;
    stage.committed = true;
    sync_directory(&parent)?;
    Ok((record_directory, result))
}

fn encode_manifest(run: &str, mut entries: Vec<RecordEntry>) -> RecordResult<(Vec<u8>, u64, u64)> {
    entries.sort_unstable_by(|a, b| a.path().cmp(b.path()));
    let (file_count, total_bytes) = entries
        .iter()
        .filter_map(|entry| match entry {
            RecordEntry::File { size_bytes, .. } => Some(*size_bytes),
            RecordEntry::Directory { .. } => None,
        })
        .fold((0, 0), |(count, total), size| (count + 1, total + size));
    let bytes = encode_json(&RecordManifest {
        schema_version: 1,
        run: run.to_owned(),
        created_at: timestamp(useful_support::utc_now())?,
        entries,
    })?;
    if bytes.len() as u64 > MAXIMUM_DURABLE_JSON_BYTES {
        return Err(PortableRecordError::io(
            Path::new(INDEX),
            io::Error::other("portable manifest exceeds the durable JSON size limit"),
        ));
    }
    Ok((bytes, file_count, total_bytes))
}

fn lock_run(
    root: &OwnedFd,
    locks: &mut Vec<File>,
    authority: &impl LocalQuiescenceAuthority,
    standalone: bool,
) -> RecordResult<WorkflowRunRecord> {
    let lock = open_retry_lock(root)?;
    match fcntl_lock(&lock, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(Errno::AGAIN | Errno::ACCESS) => return Err(PortableRecordError::RunLocked),
        Err(e) => return Err(file_error(root, LOCK_FILE, "lock", e).into()),
    }
    verify_retry_lock_identity(root, &lock)?;
    // A carried hard link to run.lock would release this process's lock when closed.
    if fstat(&lock)
        .map_err(|e| file_error(root, LOCK_FILE, "stat", e))?
        .st_nlink
        != 1
    {
        return Err(invalid_entry(root, LOCK_FILE));
    }
    locks.push(lock);
    let (record, state) = validate_record_run(root, standalone)?;
    quiesce_run(&state, authority)
        .map_err(|(guards, reason)| PortableRecordError::OwnershipUnproven { guards, reason })?;
    Ok(record)
}

fn validate_record_run(
    root: &OwnedFd,
    standalone: bool,
) -> RecordResult<(WorkflowRunRecord, LocalRunStateV1)> {
    verify_existing_run_layout(root)?;
    let state = read_state(root)?;
    validate_run_state_pair(&read_run(root)?, &state)?;
    let record = read_optional_run_record(root)?.ok_or(PortableRecordError::RunRecordMissing)?;
    if standalone && record.parent.is_some() {
        return Err(PortableRecordError::ChildRun);
    }
    Ok((record, state))
}

// Pin the selected directories for a walk. Creation also holds every selected run lock.
struct ChildDirectory {
    root: OwnedFd,
    contents: ChildContents,
}

enum ChildContents {
    Group(Vec<(String, ChildDirectory)>),
    Run(Option<Box<ChildDirectory>>),
}

fn selected_children(
    run: &OwnedFd,
    visit: &mut impl FnMut(&OwnedFd) -> RecordResult<()>,
) -> RecordResult<Option<Box<ChildDirectory>>> {
    let Some(children) = open_optional_directory(run, CHILDREN_DIRECTORY)? else {
        return Ok(None);
    };
    let mut steps = Vec::new();
    for step in directory_entries(&children)? {
        let Ok(step) = String::from_utf8(step) else {
            continue;
        };
        if !super::super::schema_common::is_identifier(&step) {
            continue;
        }
        let dir = child_directory(&children, &step)?;
        let mut entries = Vec::new();
        for ordinal in ordinals_in(&dir)? {
            let name = ordinal_name(&dir, ordinal)?;
            let entry = child_directory(&dir, &name)?;
            let child = if read_if_present(&entry, RUN_RECORD_FILE, |_| Ok(()))?.is_some() {
                select_child(entry, visit)?
            } else {
                let mut runs = Vec::new();
                for ordinal in ordinals_in(&entry)? {
                    let name = ordinal_name(&entry, ordinal)?;
                    let run = child_directory(&entry, &name)?;
                    runs.push((name, select_child(run, visit)?));
                }
                ChildDirectory {
                    root: entry,
                    contents: ChildContents::Group(runs),
                }
            };
            entries.push((name, child));
        }
        steps.push((
            step,
            ChildDirectory {
                root: dir,
                contents: ChildContents::Group(entries),
            },
        ));
    }
    Ok(Some(Box::new(ChildDirectory {
        root: children,
        contents: ChildContents::Group(steps),
    })))
}

fn ordinal_name(parent: &OwnedFd, ordinal: u64) -> RecordResult<String> {
    attempt_directory_name(ordinal).ok_or_else(|| invalid_entry(parent, ordinal.to_string()))
}

fn child_directory(parent: &OwnedFd, name: &str) -> RecordResult<OwnedFd> {
    let stat = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| file_error(parent, name, "stat", e))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(invalid_entry(parent, name));
    }
    Ok(open_directory_at(parent, name)?)
}

fn select_child(
    root: OwnedFd,
    visit: &mut impl FnMut(&OwnedFd) -> RecordResult<()>,
) -> RecordResult<ChildDirectory> {
    visit(&root)?;
    let children = selected_children(&root, visit)?;
    Ok(ChildDirectory {
        root,
        contents: ChildContents::Run(children),
    })
}

fn child_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

trait RecordSink {
    type Directory;

    fn directory(
        &mut self,
        parent: &Self::Directory,
        name: &str,
        path: &str,
        mode: rustix::fs::RawMode,
    ) -> RecordResult<Self::Directory>;
    fn file(
        &mut self,
        parent: &Self::Directory,
        name: &str,
        path: &str,
        input: File,
        metadata: &Metadata,
    ) -> RecordResult<()>;
    fn finish(directory: &Self::Directory) -> RecordResult<()>;
}

fn directory_mode(source: &OwnedFd) -> RecordResult<rustix::fs::RawMode> {
    Ok(fstat(source)
        .map_err(|e| file_error(source, ".", "stat", e))?
        .st_mode
        & 0o777)
}

struct CopyRecord {
    entries: Vec<RecordEntry>,
}

impl RecordSink for CopyRecord {
    type Directory = OwnedFd;

    fn directory(
        &mut self,
        parent: &OwnedFd,
        name: &str,
        path: &str,
        mode: rustix::fs::RawMode,
    ) -> RecordResult<OwnedFd> {
        self.entries.push(RecordEntry::Directory {
            path: path.to_owned(),
            mode: format!("{mode:03o}"),
        });
        mkdir(parent, name)?;
        Ok(open_directory_at(parent, name)?)
    }

    fn file(
        &mut self,
        parent: &OwnedFd,
        name: &str,
        path: &str,
        input: File,
        metadata: &Metadata,
    ) -> RecordResult<()> {
        let mut output = create_file(parent, name, Mode::RUSR | Mode::WUSR)?;
        let (size_bytes, sha256) = copy_and_digest(input, &mut output, Path::new(path))?;
        output
            .sync_all()
            .map_err(|e| file_error(parent, name, "sync", e))?;
        self.entries.push(RecordEntry::File {
            path: path.to_owned(),
            mode: format!("{:03o}", metadata.mode() & 0o777),
            size_bytes,
            sha256,
        });
        Ok(())
    }

    fn finish(directory: &OwnedFd) -> RecordResult<()> {
        Ok(sync_directory(directory)?)
    }
}

fn walk_run<S: RecordSink>(
    root: &OwnedFd,
    target: &S::Directory,
    path: &str,
    children: Option<Box<ChildDirectory>>,
    sink: &mut S,
) -> RecordResult<()> {
    for name in directory_entries(root)? {
        let name = entry_name(root, name)?;
        match name.as_str() {
            LOCK_FILE | PRIVATE_DIRECTORY | CHILDREN_DIRECTORY | WORKSPACES_DIRECTORY => continue,
            _ => walk_carried(
                root,
                target,
                &name,
                &child_path(path, &name),
                if name == ATTEMPTS_DIRECTORY {
                    Content::Attempts
                } else {
                    Content::All
                },
                sink,
            )?,
        }
    }
    if let Some(children) = children {
        walk_children(
            *children,
            target,
            CHILDREN_DIRECTORY,
            &child_path(path, CHILDREN_DIRECTORY),
            sink,
        )?;
    }
    S::finish(target)?;
    Ok(())
}

fn walk_children<S: RecordSink>(
    source: ChildDirectory,
    target: &S::Directory,
    name: &str,
    path: &str,
    sink: &mut S,
) -> RecordResult<()> {
    let target = sink.directory(target, name, path, directory_mode(&source.root)?)?;
    match source.contents {
        ChildContents::Run(children) => walk_run(&source.root, &target, path, children, sink),
        ChildContents::Group(children) => {
            for (name, source) in children {
                walk_children(source, &target, &name, &child_path(path, &name), sink)?;
            }
            S::finish(&target)?;
            Ok(())
        }
    }
}

#[derive(Clone, Copy)]
enum Content {
    Attempts,
    Attempt,
    All,
}

fn walk_carried<S: RecordSink>(
    source: &OwnedFd,
    target: &S::Directory,
    name: &str,
    path: &str,
    contents: Content,
    sink: &mut S,
) -> RecordResult<()> {
    let stat = statat(source, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| file_error(source, name, "stat", e))?;
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Directory => {
            let source = open_directory_at(source, name)?;
            let target = sink.directory(target, name, path, directory_mode(&source)?)?;
            for child in directory_entries(&source)? {
                let child = entry_name(&source, child)?;
                if matches!(contents, Content::Attempt)
                    && matches!(child.as_str(), "diagnostics" | "continuation-context.json")
                {
                    continue;
                }
                walk_carried(
                    &source,
                    &target,
                    &child,
                    &child_path(path, &child),
                    if matches!(contents, Content::Attempts) {
                        Content::Attempt
                    } else {
                        Content::All
                    },
                    sink,
                )?;
            }
            S::finish(&target)?;
        }
        FileType::RegularFile => {
            let (input, _) = open_regular_file(source, name)?;
            let metadata = input
                .metadata()
                .map_err(|e| file_error(source, name, "stat", e))?;
            sink.file(target, name, path, input, &metadata)?;
        }
        _ => return Err(invalid_entry(source, name)),
    }
    Ok(())
}

/// A capture's manifest and the distinct digest-named files it references.
#[derive(Debug)]
pub struct CapturedPortableRecord {
    pub run: String,
    pub manifest: Vec<u8>,
    pub files: Vec<(String, u64)>,
    pub file_count: u64,
    pub total_bytes: u64,
}

/// Reuses files across successive captures into a caller-owned, private files directory.
pub struct PortableRecordCapture {
    files: PathBuf,
    digests: BTreeMap<FileIdentity, String>,
}

pub(super) trait CaptureObserver {
    fn now(&self) -> OffsetDateTime;
    fn between_readings(&self) {}
}

struct SystemCaptureObserver;

impl CaptureObserver for SystemCaptureObserver {
    fn now(&self) -> OffsetDateTime {
        useful_support::utc_now()
    }
}

const CAPTURE_RECENCY_MARGIN: time::Duration = time::Duration::milliseconds(100);

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified: i128,
    changed: i128,
}

impl FileIdentity {
    fn of(metadata: &Metadata) -> Self {
        let nanos = |seconds: i64, fraction: i64| {
            i128::from(seconds) * 1_000_000_000 + i128::from(fraction)
        };
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified: nanos(metadata.mtime(), metadata.mtime_nsec()),
            changed: nanos(metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

#[derive(PartialEq)]
enum ObservedEntry {
    Directory(rustix::fs::RawMode),
    File { mode: u32, identity: FileIdentity },
}

// Relative paths encode the set of carried entry names in each directory, including
// empty directories. Directory timestamps would also observe writes to excluded entries.
struct CaptureReading<F> {
    entries: BTreeMap<String, ObservedEntry>,
    read_file: F,
}

impl<F: FnMut(&str, File, &FileIdentity) -> RecordResult<()>> RecordSink for CaptureReading<F> {
    type Directory = ();

    fn directory(
        &mut self,
        _: &(),
        _: &str,
        path: &str,
        mode: rustix::fs::RawMode,
    ) -> RecordResult<()> {
        self.entries
            .insert(path.to_owned(), ObservedEntry::Directory(mode));
        Ok(())
    }

    fn file(
        &mut self,
        _: &(),
        _: &str,
        path: &str,
        input: File,
        metadata: &Metadata,
    ) -> RecordResult<()> {
        let identity = FileIdentity::of(metadata);
        (self.read_file)(path, input, &identity)?;
        self.entries.insert(
            path.to_owned(),
            ObservedEntry::File {
                mode: metadata.mode() & 0o777,
                identity,
            },
        );
        Ok(())
    }

    fn finish(_: &()) -> RecordResult<()> {
        Ok(())
    }
}

fn read_capture(
    root: &OwnedFd,
    visit_child: &mut impl FnMut(&OwnedFd) -> RecordResult<()>,
    read_file: impl FnMut(&str, File, &FileIdentity) -> RecordResult<()>,
) -> RecordResult<BTreeMap<String, ObservedEntry>> {
    let children = selected_children(root, visit_child)?;
    let mut reading = CaptureReading {
        entries: BTreeMap::new(),
        read_file,
    };
    walk_run(root, &(), "", children, &mut reading)?;
    Ok(reading.entries)
}

fn capture_error(error: PortableRecordError, source_root: &Path) -> PortableRecordError {
    match &error {
        PortableRecordError::RecordUnavailable { path, source }
            if path.starts_with(source_root) && source.kind() == io::ErrorKind::NotFound =>
        {
            PortableRecordError::RunChanging
        }
        _ => error,
    }
}

impl PortableRecordCapture {
    pub fn new(files: &Path) -> Self {
        Self {
            files: files.to_owned(),
            digests: BTreeMap::new(),
        }
    }

    pub fn capture(&mut self, run: &Path) -> RecordResult<CapturedPortableRecord> {
        self.capture_observed(run, &SystemCaptureObserver)
    }

    pub(super) fn capture_observed(
        &mut self,
        run: &Path,
        observer: &impl CaptureObserver,
    ) -> RecordResult<CapturedPortableRecord> {
        let (source, root) = open_run_root(run)?;
        let files = std::fs::canonicalize(&self.files)
            .map_err(|e| PortableRecordError::io(&self.files, e))?;
        if files.starts_with(&source) {
            return Err(PortableRecordError::io(
                &files,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the files directory lies inside the run being captured",
                ),
            ));
        }
        let directory =
            open_directory_path(&files).map_err(|e| PortableRecordError::io(&files, e))?;
        let first = read_capture(&root, &mut |_| Ok(()), |path, input, identity| {
            let cutoff =
                observer.now().unix_timestamp_nanos() - CAPTURE_RECENCY_MARGIN.whole_nanoseconds();
            if identity.modified.max(identity.changed) >= cutoff {
                return Err(PortableRecordError::RunChanging);
            }
            self.retain_file(&files, &source.join(path), input, identity)
        })
        .map_err(|e| capture_error(e, &source))?;
        observer.between_readings();

        // Reopen the named root. Defer validation errors until the second reading tells
        // whether they describe a still directory or one that changed beneath us.
        let (_, root) = open_run_root(run).map_err(|e| capture_error(e.into(), run))?;
        let mut validated = validate_record_run(&root, true).map(|(record, _)| record);
        let mut validate_child = |child: &OwnedFd| {
            if validated.is_ok()
                && let Err(error) = validate_record_run(child, false)
            {
                validated = Err(error);
            }
            Ok(())
        };
        let second =
            read_capture(&root, &mut validate_child, |_, _, _| Ok(())).map_err(|e| match e {
                PortableRecordError::RunDirectoryInvalid(_) => PortableRecordError::RunChanging,
                other => capture_error(other, &source),
            })?;
        if first != second {
            return Err(PortableRecordError::RunChanging);
        }
        let run = validated?.id;
        let mut distinct = BTreeMap::new();
        let mut entries = Vec::with_capacity(first.len());
        for (path, observation) in first {
            entries.push(match observation {
                ObservedEntry::Directory(mode) => RecordEntry::Directory {
                    path,
                    mode: format!("{mode:03o}"),
                },
                ObservedEntry::File { mode, identity } => {
                    let sha256 = self
                        .digests
                        .get(&identity)
                        .ok_or(PortableRecordError::RunChanging)?
                        .clone();
                    distinct.insert(sha256.clone(), identity.size);
                    RecordEntry::File {
                        path,
                        mode: format!("{mode:03o}"),
                        size_bytes: identity.size,
                        sha256,
                    }
                }
            });
        }
        let (manifest, file_count, total_bytes) = encode_manifest(&run, entries)?;
        sync_directory(&directory)?;
        Ok(CapturedPortableRecord {
            run,
            manifest,
            files: distinct.into_iter().collect(),
            file_count,
            total_bytes,
        })
    }

    fn retain_file(
        &mut self,
        files: &Path,
        path: &Path,
        mut input: File,
        identity: &FileIdentity,
    ) -> RecordResult<()> {
        if let Some(digest) = self.digests.get(identity)
            && digest_present(&files.join(digest), identity.size)?
        {
            return Ok(());
        }
        let mut temp = tempfile::Builder::new()
            .prefix(".capture-")
            .tempfile_in(files)
            .map_err(|e| PortableRecordError::io(files, e))?;
        let (size, digest) = copy_and_digest(&mut input, &mut temp, path)?;
        let after = input
            .metadata()
            .map_err(|e| PortableRecordError::io(path, e))?;
        if size != identity.size || FileIdentity::of(&after) != *identity {
            return Err(PortableRecordError::RunChanging);
        }
        let target = files.join(&digest);
        if !digest_present(&target, size)? {
            temp.as_file()
                .sync_all()
                .map_err(|e| PortableRecordError::io(temp.path(), e))?;
            if let Err(error) = temp.persist_noclobber(&target)
                && (error.error.kind() != io::ErrorKind::AlreadyExists
                    || !digest_present(&target, size)?)
            {
                return Err(PortableRecordError::io(&target, error.error));
            }
        }
        self.digests.insert(identity.clone(), digest);
        Ok(())
    }
}

fn digest_present(path: &Path, size: u64) -> RecordResult<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.len() == size => Ok(true),
        Ok(_) => Err(PortableRecordError::io(
            path,
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the stored digest is not a regular file of the expected size",
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(PortableRecordError::io(path, error)),
    }
}

fn copy_and_digest(
    mut input: impl Read,
    mut output: impl Write,
    path: &Path,
) -> RecordResult<(u64, String)> {
    let mut digest = DigestContext::new(&SHA256);
    let mut size_bytes = 0;
    let mut buffer = [0; 16 * 1024];
    loop {
        let n = match input.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(PortableRecordError::io(path, e)),
        };
        output
            .write_all(&buffer[..n])
            .map_err(|e| PortableRecordError::io(path, e))?;
        digest.update(&buffer[..n]);
        size_bytes += n as u64;
    }
    Ok((size_bytes, lowercase_hex(digest.finish().as_ref())))
}

const INDEX: &str = "record.json";
const PAYLOAD: &str = "run";

/// A validated manifest and its run identity. The directory handle pins the source, and
/// restoring checks the copied bytes against the same manifest used to choose placement.
pub struct OpenedPortableRecord {
    directory: OwnedFd,
    manifest: RecordManifest,
    run: WorkflowRunRecord,
}

impl OpenedPortableRecord {
    pub fn run(&self) -> &WorkflowRunRecord {
        &self.run
    }
}

impl RecordEntry {
    fn mode(&self) -> RecordResult<Mode> {
        let (Self::Directory { mode, .. } | Self::File { mode, .. }) = self;
        if mode.len() != 3 || !mode.bytes().all(|c| (b'0'..=b'7').contains(&c)) {
            return Err(invalid_index());
        }
        libc::mode_t::from_str_radix(mode, 8)
            .map(Mode::from_raw_mode)
            .map_err(|_| invalid_index())
    }
}

fn invalid_index() -> PortableRecordError {
    PortableRecordError::RecordInvalid(INDEX.into())
}

impl RecordManifest {
    fn decode(bytes: &[u8]) -> RecordResult<Self> {
        if bytes.len() as u64 > MAXIMUM_DURABLE_JSON_BYTES {
            return Err(invalid_index());
        }
        let manifest: Self = serde_json::from_slice(bytes).map_err(|_| invalid_index())?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn children(&self) -> BTreeMap<&str, Vec<(&str, &RecordEntry)>> {
        let mut children = BTreeMap::from([("", Vec::new())]);
        for entry in &self.entries {
            let path = entry.path();
            let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
            children.entry(parent).or_default().push((name, entry));
            if matches!(entry, RecordEntry::Directory { .. }) {
                children.entry(path).or_default();
            }
        }
        children
    }

    fn validate(&self) -> RecordResult<()> {
        if self.schema_version != 1 || !valid_timestamp(&self.created_at) || !is_run_id(&self.run) {
            return Err(invalid_index());
        }
        let mut directories = BTreeSet::from([""]);
        let mut previous = "";
        for entry in &self.entries {
            let path = entry.path();
            let (parent, _) = path.rsplit_once('/').unwrap_or(("", path));
            if path <= previous
                || !is_canonical_relative_path(path)
                || path.contains('\0')
                || !directories.contains(parent)
            {
                return Err(invalid_index());
            }
            entry.mode()?;
            match entry {
                RecordEntry::Directory { .. } => {
                    directories.insert(path);
                }
                RecordEntry::File { sha256, .. } if !is_lowercase_hex(sha256, 64) => {
                    return Err(invalid_index());
                }
                _ => {}
            }
            previous = path;
        }
        Ok(())
    }
}

pub fn open_portable_record(directory: &Path) -> RecordResult<OpenedPortableRecord> {
    // The operator names the record; only what lies under it is opened without following links.
    let resolved =
        std::fs::canonicalize(directory).map_err(|e| PortableRecordError::io(directory, e))?;
    let directory =
        open_directory_path(&resolved).map_err(|e| PortableRecordError::io(&resolved, e))?;
    let manifest = RecordManifest::decode(
        &read_regular_file(&directory, INDEX).map_err(|_| invalid_index())?,
    )?;
    let payload = open_payload(&directory)?;
    let path = Path::new(PAYLOAD).join(RUN_RECORD_FILE);
    let mut bytes = Vec::new();
    match manifest
        .entries
        .binary_search_by(|entry| entry.path().cmp(RUN_RECORD_FILE))
        .ok()
        .map(|index| &manifest.entries[index])
    {
        Some(RecordEntry::File {
            size_bytes, sha256, ..
        }) if *size_bytes <= MAXIMUM_DURABLE_RECORD_BYTES => {
            copy_verified_file(
                &payload,
                RUN_RECORD_FILE,
                &path,
                *size_bytes,
                sha256,
                &mut bytes,
            )?;
        }
        Some(RecordEntry::Directory { .. }) => {
            open_directory_at(&payload, RUN_RECORD_FILE).map_err(|e| source_error(&path, e))?;
            return Err(PortableRecordError::RecordInvalid(path));
        }
        None if directory_entries(&payload)?.contains(RUN_RECORD_FILE.as_bytes()) => {
            return Err(PortableRecordError::RecordAltered(path));
        }
        _ => return Err(PortableRecordError::RecordInvalid(path)),
    }
    let run = serde_json::from_slice::<WorkflowRunRecord>(&bytes)
        .ok()
        .filter(|run| run.is_valid() && run.id == manifest.run && run.parent.is_none())
        .ok_or(PortableRecordError::RecordInvalid(path))?;
    Ok(OpenedPortableRecord {
        directory,
        manifest,
        run,
    })
}

fn source_error(path: &Path, error: LocalRunDirectoryError) -> PortableRecordError {
    match error {
        LocalRunDirectoryError::File { source, .. } => match source.raw_os_error() {
            Some(libc::ENOENT) => PortableRecordError::RecordIncomplete(path.into()),
            Some(libc::ELOOP | libc::ENOTDIR) => PortableRecordError::RecordAltered(path.into()),
            _ => PortableRecordError::io(path, source),
        },
        _ => PortableRecordError::RecordAltered(path.into()),
    }
}

fn open_payload(directory: &OwnedFd) -> RecordResult<OwnedFd> {
    let mut names = directory_entries(directory)?;
    names.remove(INDEX.as_bytes());
    names.remove(PAYLOAD.as_bytes());
    refuse_extra(names, Path::new(""))?;
    open_directory_at(directory, PAYLOAD).map_err(|e| source_error(Path::new(PAYLOAD), e))
}

fn refuse_extra(names: BTreeSet<Vec<u8>>, parent: &Path) -> RecordResult<()> {
    use std::os::unix::ffi::OsStringExt as _;
    if let Some(name) = names.into_iter().next() {
        return Err(PortableRecordError::RecordAltered(
            parent.join(OsString::from_vec(name)),
        ));
    }
    Ok(())
}

fn copy_verified_file(
    source: &OwnedFd,
    name: &str,
    path: &Path,
    size: u64,
    sha256: &str,
    output: impl Write,
) -> RecordResult<()> {
    let named = statat(source, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| source_error(path, file_error(source, name, "stat", e)))?;
    if FileType::from_raw_mode(named.st_mode) != FileType::RegularFile {
        return Err(PortableRecordError::RecordAltered(path.into()));
    }
    let (file, actual) = open_regular_file(source, name).map_err(|e| source_error(path, e))?;
    if actual != size {
        return Err(PortableRecordError::RecordAltered(path.into()));
    }
    let (count, digest) = copy_and_digest(file.take(size.saturating_add(1)), output, path)?;
    if count != size || digest != sha256 {
        return Err(PortableRecordError::RecordAltered(path.into()));
    }
    Ok(())
}

pub fn restore_portable_record(
    record: &OpenedPortableRecord,
    destination: &Path,
) -> RecordResult<()> {
    let payload = open_payload(&record.directory)?;
    let children = record.manifest.children();
    publish_portable_directory(
        &file_locator(&record.directory, "."),
        destination,
        ".run",
        |stage| {
            restore_directory(
                &payload,
                stage,
                "",
                &children,
                RestoreLocation::Run,
                &record.run,
            )
        },
    )?;
    Ok(())
}

// Only child-run positions identify nested runs. A workflow can itself contain a
// local-run.json, which is ordinary carried data in the retained tree.
#[derive(Clone, Copy)]
enum RestoreLocation {
    Run,
    Steps,
    Ordinals,
    ElementOrRun,
    Payload,
}

impl RestoreLocation {
    fn child(self, name: &str) -> Self {
        match self {
            Self::Run if name == CHILDREN_DIRECTORY => Self::Steps,
            Self::Steps => Self::Ordinals,
            Self::Ordinals => Self::ElementOrRun,
            Self::ElementOrRun => Self::Run,
            _ => Self::Payload,
        }
    }
}

fn restore_directory(
    source: &OwnedFd,
    target: &OwnedFd,
    relative: &str,
    children: &BTreeMap<&str, Vec<(&str, &RecordEntry)>>,
    location: RestoreLocation,
    root_record: &WorkflowRunRecord,
) -> RecordResult<()> {
    let path = Path::new(PAYLOAD).join(relative);
    let mut names = directory_entries(source)?;
    let location = match location {
        RestoreLocation::ElementOrRun
            if names.contains(LOCAL_RUN_FILE.as_bytes())
                || names.contains(RUN_RECORD_FILE.as_bytes()) =>
        {
            RestoreLocation::Run
        }
        location => location,
    };
    for &(name, entry) in children.get(relative).into_iter().flatten() {
        let entry_path = path.join(name);
        if !names.remove(name.as_bytes()) {
            return Err(PortableRecordError::RecordIncomplete(entry_path));
        }
        if matches!(location, RestoreLocation::Run) && matches!(name, LOCK_FILE | PRIVATE_DIRECTORY)
        {
            return Err(PortableRecordError::RecordInvalid(entry_path));
        }
        match entry {
            RecordEntry::Directory { .. } => {
                let input =
                    open_directory_at(source, name).map_err(|e| source_error(&entry_path, e))?;
                mkdir(target, name)?;
                let output = open_directory_at(target, name)?;
                restore_directory(
                    &input,
                    &output,
                    entry.path(),
                    children,
                    location.child(name),
                    root_record,
                )?;
                fchmod(&output, entry.mode()?)
                    .map_err(|e| PortableRecordError::io(&entry_path, e))?;
                sync_directory(&output)?;
            }
            RecordEntry::File {
                size_bytes, sha256, ..
            } => {
                let mut output = create_file(target, name, Mode::RUSR | Mode::WUSR)?;
                copy_verified_file(source, name, &entry_path, *size_bytes, sha256, &mut output)?;
                fchmod(&output, entry.mode()?)
                    .map_err(|e| PortableRecordError::io(&entry_path, e))?;
                output
                    .sync_all()
                    .map_err(|e| PortableRecordError::io(&entry_path, e))?;
            }
        }
    }
    refuse_extra(names, &path)?;
    if matches!(location, RestoreLocation::Run) {
        create_file(target, LOCK_FILE, Mode::RUSR | Mode::WUSR)?
            .sync_all()
            .map_err(|e| PortableRecordError::io(&path.join(LOCK_FILE), e))?;
        mkdir(target, PRIVATE_DIRECTORY)?;
        validate_restored_run(target, &path, relative.is_empty().then_some(root_record))?;
    }
    Ok(())
}

fn validate_restored_run(
    root: &OwnedFd,
    path: &Path,
    expected: Option<&WorkflowRunRecord>,
) -> RecordResult<()> {
    let invalid = |name: &str| PortableRecordError::RecordInvalid(path.join(name));
    verify_existing_run_layout(root).map_err(|err| {
        let name = match &err {
            LocalRunDirectoryError::StateFile { path, .. }
            | LocalRunDirectoryError::File { path, .. } => path
                .strip_prefix(file_locator(root, "."))
                .unwrap_or(Path::new("")),
            _ => Path::new(""),
        };
        PortableRecordError::RecordInvalid(path.join(name))
    })?;
    let run = read_run(root).map_err(|_| invalid(LOCAL_RUN_FILE))?;
    let state = read_state(root).map_err(|_| invalid(STATE_FILE))?;
    validate_run_state_pair(&run, &state).map_err(|_| invalid(STATE_FILE))?;
    let record = read_run_record(root).map_err(|_| invalid(RUN_RECORD_FILE))?;
    if expected.is_some_and(|expected| *expected != record) {
        return Err(invalid(RUN_RECORD_FILE));
    }
    Ok(())
}
