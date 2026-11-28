//! The roots that bound the files of `useful workflow doctor` and `useful account integration
//! connect --workflow`: a directory named in place of a file stands for its tree's `workflow.yaml`
//! and bounds it; otherwise `--source-root`, or the root of the Git repository that holds each
//! file, with each root's derivation merged into one. `useful workflow validate FILE` finds a
//! file's root the same way.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::anyhow;

use crate::cli::CommandFailure;
use crate::exit_code::ExitCode;
use useful_execution::{CommandProbeError, CommandRunner, SystemCommandRunner};
use useful_runner::{
    Declaration, DerivedCredentials, IntegrationDifference, RepositoryRootError, RepositorySource,
    WorkflowCredentials,
};

/// The file a tree directory names: the tree's root workflow.
const TREE_ROOT_FILE: &str = "workflow.yaml";

/// The named workflow files grouped by the root that bounds them, in the order first named.
pub(in crate::cli) struct Roots {
    /// The runner that asked Git for the roots, which also asks for each root's `origin` remote.
    runner: Arc<dyn CommandRunner>,
    groups: Vec<(PathBuf, Vec<PathBuf>)>,
}

impl Roots {
    /// Each path that is a directory stands for its tree's `workflow.yaml`, bounded by
    /// `source_root` or else by the directory itself. Any other path is a file, bounded by
    /// `source_root` or else by the root of the Git repository that holds it; a file whose
    /// `git rev-parse --show-toplevel` fails is refused with exit 2, before any file is derived,
    /// naming `remedy`: the command line that names the boundary instead.
    pub(in crate::cli) fn find(
        paths: &[PathBuf],
        source_root: Option<&Path>,
        remedy: &str,
    ) -> Result<Self, CommandFailure> {
        let runner: Arc<dyn CommandRunner> = Arc::new(SystemCommandRunner);
        let mut groups: Vec<(PathBuf, Vec<PathBuf>)> = Vec::new();
        for path in paths {
            let (root, file) = if path.is_dir() {
                (
                    source_root.unwrap_or(path).to_owned(),
                    path.join(TREE_ROOT_FILE),
                )
            } else {
                let root = match source_root {
                    Some(root) => root.to_owned(),
                    None => repository_of(runner.as_ref(), path, remedy)?,
                };
                (root, path.clone())
            };
            match groups.iter_mut().find(|(known, _)| *known == root) {
                Some((_, files)) => files.push(file),
                None => groups.push((root, vec![file])),
            }
        }
        Ok(Self { runner, groups })
    }

    /// The root of the Git repository that holds `file`, found and refused as [`Roots::find`]
    /// finds and refuses each file's root without a `source_root`.
    pub(in crate::cli) fn of_file(file: &Path, remedy: &str) -> Result<PathBuf, CommandFailure> {
        repository_of(&SystemCommandRunner, file, remedy)
    }

    /// Each root's `origin` remote, asked of Git through the runner that asked for the
    /// roots.
    pub(in crate::cli) fn origin_remote(&self) -> RepositorySource {
        RepositorySource::OriginRemote(Arc::clone(&self.runner))
    }

    /// The credentials the named workflows and the workflows their `workflow` steps name need, or
    /// `None` once the first file that does not resolve was rejected as `useful workflow validate`
    /// rejects it. The files of one root are derived together under it, each reading its
    /// repository's provider from `source`, and the derivations are merged by kind, the roots'
    /// inferences and reports each into their own. The roots' differences are concatenated,
    /// present when any root's are. The Slack declarations are concatenated in root order.
    pub(in crate::cli) fn derive(
        &self,
        source: &RepositorySource,
        json: bool,
    ) -> anyhow::Result<Option<DerivedCredentials>> {
        let mut merged: Option<DerivedCredentials> = None;
        for (root, files) in &self.groups {
            let Some(derived) = super::report::derive(root, files, again(source), json)? else {
                return Ok(None);
            };
            match &mut merged {
                Some(into) => {
                    merge(&mut into.inferred, derived.inferred);
                    merge(&mut into.reported, derived.reported);
                    concatenate(&mut into.differences, derived.differences);
                    into.slack.extend(derived.slack);
                }
                None => merged = Some(derived),
            }
        }
        Ok(Some(merged.unwrap_or_else(|| DerivedCredentials {
            inferred: nothing(),
            reported: nothing(),
            differences: None,
            slack: Vec::new(),
        })))
    }
}

/// The derivation of no file.
const fn nothing() -> WorkflowCredentials {
    WorkflowCredentials {
        workflows: Vec::new(),
        requirements: Vec::new(),
        unknown: Vec::new(),
    }
}

/// `source` for one more root.
fn again(source: &RepositorySource) -> RepositorySource {
    match source {
        RepositorySource::OriginRemote(runner) => {
            RepositorySource::OriginRemote(Arc::clone(runner))
        }
        RepositorySource::Project(kind) => RepositorySource::Project(*kind),
    }
}

/// The root of the Git repository that holds `file`, or the working directory when the file's
/// directory does not exist.
fn repository_of(
    runner: &dyn CommandRunner,
    file: &Path,
    remedy: &str,
) -> Result<PathBuf, CommandFailure> {
    let directory = file
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if directory.is_dir() {
        useful_runner::repository_root(runner, directory)
            .map_err(|error| refusal(file, directory, error, remedy))
    } else {
        Ok(PathBuf::from("."))
    }
}

/// Why `file` has no repository root, and `remedy` as the way out. A failed
/// `git rev-parse --show-toplevel` is named as that command failing in `directory`, since its
/// exit status does not say why, and refused with exit 2.
fn refusal(
    file: &Path,
    directory: &Path,
    error: RepositoryRootError,
    remedy: &str,
) -> CommandFailure {
    let (cause, code) = match error {
        RepositoryRootError::Probe(error) => {
            (probe_failure(error).to_owned(), ExitCode::GeneralFailure)
        }
        RepositoryRootError::Failed => (
            format!(
                "`git rev-parse --show-toplevel` failed in {}",
                directory.display()
            ),
            ExitCode::UsageError,
        ),
        RepositoryRootError::NoRoot => (
            "git printed no repository root".to_owned(),
            ExitCode::GeneralFailure,
        ),
    };
    CommandFailure::with_exit_code(
        anyhow!(
            "find the Git repository of {}: {cause}\n\n\
             Name the directory that bounds the workflow files:\n  \
             {remedy}",
            file.display()
        ),
        code,
    )
}

const fn probe_failure(error: CommandProbeError) -> &'static str {
    match error {
        CommandProbeError::CommandNotFound => "git was not found on PATH",
        CommandProbeError::Spawn => "start git",
        CommandProbeError::Timeout => "git timed out",
        CommandProbeError::Wait | CommandProbeError::PipeRead => "read git's answer",
    }
}

/// Merges one repository's derivation into the others': its files after theirs, its origins
/// into the requirement of their kind, and the unknown entries they lack.
fn merge(into: &mut WorkflowCredentials, from: WorkflowCredentials) {
    into.workflows.extend(from.workflows);
    for requirement in from.requirements {
        match into
            .requirements
            .iter_mut()
            .find(|known| known.kind == requirement.kind)
        {
            Some(known) => add(&mut known.origins, requirement.origins),
            None => into.requirements.push(requirement),
        }
    }
    into.requirements
        .sort_by_key(|requirement| requirement.kind);
    add(&mut into.unknown, from.unknown);
}

/// Appends one root's differences to the others', present when either is.
fn concatenate(
    into: &mut Option<Vec<IntegrationDifference>>,
    from: Option<Vec<IntegrationDifference>>,
) {
    if let Some(from) = from {
        into.get_or_insert_with(Vec::new).extend(from);
    }
}

/// Adds the declarations `into` lacks, keeping those of no workflow file last, as a report
/// lists them.
fn add<K: PartialEq>(into: &mut Vec<Declaration<K>>, from: Vec<Declaration<K>>) {
    for entry in from {
        if !into.contains(&entry) {
            into.push(entry);
        }
    }
    into.sort_by_key(|entry| entry.workflow.is_none());
}
