use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;

use rustix::fs::{Mode, mkdirat};

use super::admission::AdmittedWorkflow;
use super::execution_root::AdmittedExecutionRoot;
use super::local_run::{LocalRunDirectoryError, create_or_open_directory, open_directory_at};
use super::step_runtime::WorkingDirectoryFailure;
use super::validated::StepWorkspace;
use crate::owned_tree::remove_tree_at;

pub(super) const WORKSPACES_DIRECTORY: &str = "workspaces";

/// The run directory that owns a local attempt's established step workspaces.
#[derive(Clone, Debug)]
pub struct StepWorkspaces {
    directory: Arc<OwnedFd>,
    path: PathBuf,
}

impl StepWorkspaces {
    pub fn new(directory: Arc<OwnedFd>, path: PathBuf) -> Self {
        Self { directory, path }
    }

    pub(super) fn validate(
        &self,
        execution_root: &AdmittedExecutionRoot,
    ) -> Result<(), LocalRunDirectoryError> {
        let directory = rustix::io::dup(&self.directory)
            .map_err(|_| LocalRunDirectoryError::ParentUnavailable)?;
        let run = AdmittedExecutionRoot::admit_workspace(self.path.clone(), directory)
            .map_err(|_| LocalRunDirectoryError::ParentUnavailable)?;
        if execution_root
            .contains_directory(&self.directory)
            .map_err(|_| LocalRunDirectoryError::ParentUnavailable)?
            || run
                .contains_directory(execution_root.directory())
                .map_err(|_| LocalRunDirectoryError::ParentUnavailable)?
        {
            return Err(LocalRunDirectoryError::ExecutionRootOverlap);
        }
        Ok(())
    }

    pub(super) fn establish(&self, step: &str) -> Result<(), WorkingDirectoryFailure> {
        let workspaces = create_or_open_directory(&self.directory, WORKSPACES_DIRECTORY)
            .map_err(|_| WorkingDirectoryFailure::Unavailable)?;
        remove_tree_at(&workspaces, step).map_err(|_| WorkingDirectoryFailure::Unavailable)?;
        mkdirat(&workspaces, step, Mode::RWXU).map_err(|_| WorkingDirectoryFailure::Unavailable)
    }

    fn admit(&self, by: &str) -> Result<AdmittedExecutionRoot, WorkingDirectoryFailure> {
        let workspaces = open_directory_at(&self.directory, WORKSPACES_DIRECTORY)
            .map_err(|_| WorkingDirectoryFailure::Unavailable)?;
        let directory =
            open_directory_at(&workspaces, by).map_err(|_| WorkingDirectoryFailure::Unavailable)?;
        AdmittedExecutionRoot::admit_workspace(
            self.path.join(WORKSPACES_DIRECTORY).join(by),
            directory,
        )
        .map_err(|_| WorkingDirectoryFailure::Unavailable)
    }
}

/// Select a workspace without establishing it. Inheriting steps and handlers see the
/// directory as its establishing step left it.
pub(super) fn workspace_root(
    admitted: &AdmittedWorkflow,
    workspace: &StepWorkspace,
) -> Result<AdmittedExecutionRoot, WorkingDirectoryFailure> {
    match workspace {
        StepWorkspace::Starting => Ok(admitted.execution().root_identity().clone()),
        StepWorkspace::Established { by } => admitted
            .step_workspaces()
            .ok_or(WorkingDirectoryFailure::Unavailable)?
            .admit(by),
    }
}
