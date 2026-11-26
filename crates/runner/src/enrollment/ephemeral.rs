//! A serving process's disposable identity, kept under a separate, locked state directory.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use fs4::{FileExt, TryLockError};

use super::{
    EnrollmentError, JOURNAL_FILE, REGISTRATION_FILE, STATE_TEMPORARY_PREFIX,
    ensure_private_directory, load_operator_config, open_or_create_private_file,
    remove_leftover_temporary_files, state_directory, sync_directory_io, write_private_json,
};
use crate::agent_login::directory::DIRECTORY as AGENT_LOGIN_DIRECTORY;

const DIRECTORY: &str = "ephemeral";
const CONFIG: &str = "runner.json";
const STATE: &str = "runner-state.json";
const SESSION_LOCK: &str = ".ephemeral-session.lock";

/// Holds the session lock from before the join until its credential has been removed.
pub struct EphemeralSession {
    directory: PathBuf,
    config_path: PathBuf,
    lock: Option<File>,
}

impl EphemeralSession {
    /// Discards a previous process's credentials and derives a configuration for this start.
    pub fn begin(config_path: &Path) -> Result<Self, EnrollmentError> {
        let mut config = load_operator_config(config_path)?;
        let host = state_directory(&config.runner_state_path)?;
        let directory = host.join(DIRECTORY);
        if config.runner_state_path == directory {
            return Err(EnrollmentError::UnsafePath(
                "the configured state file occupies the ephemeral directory",
            ));
        }
        ensure_private_directory(host)?;
        ensure_private_directory(&directory)?;
        // The operator may supply a relative path, or reach the configuration
        // through a different name for its parent directory.
        let configured =
            fs::canonicalize(config_path).map_err(session_io("resolve runner configuration"))?;
        let resolved_directory =
            fs::canonicalize(&directory).map_err(session_io("resolve ephemeral directory"))?;
        if configured.starts_with(&resolved_directory) {
            return Err(EnrollmentError::UnsafePath(
                "the operator configuration must be outside the ephemeral directory",
            ));
        }

        config.runner_state_path = directory.join(STATE);
        if !config.build_caches_valid() {
            return Err(EnrollmentError::InvalidConfig);
        }
        let lock = open_or_create_private_file(&directory.join(SESSION_LOCK))?;
        FileExt::try_lock(&lock).map_err(|error| match error {
            TryLockError::WouldBlock => EnrollmentError::StateLock,
            TryLockError::Error(source) => session_io("lock ephemeral session")(source),
        })?;
        let session = Self {
            config_path: directory.join(CONFIG),
            directory,
            lock: Some(lock),
        };
        session.clear_credentials()?;
        write_private_json(&session.config_path, &config, STATE_TEMPORARY_PREFIX)
            .map_err(session_io("write ephemeral runner configuration"))?;
        Ok(session)
    }

    /// The derived configuration for both enrollment and serving.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Removes the session's credentials before releasing the lock.
    pub fn end(mut self) -> Result<(), EnrollmentError> {
        self.clear_credentials()?;
        self.lock.take();
        Ok(())
    }

    fn clear_credentials(&self) -> Result<(), EnrollmentError> {
        for file in [STATE, JOURNAL_FILE, REGISTRATION_FILE] {
            if_present(fs::remove_file(self.directory.join(file)))
                .map_err(session_io("remove ephemeral runner state"))?;
        }
        if_present(fs::remove_dir_all(
            self.directory.join(AGENT_LOGIN_DIRECTORY),
        ))
        .map_err(session_io("remove ephemeral agent logins"))?;
        remove_leftover_temporary_files(&self.directory, &[STATE_TEMPORARY_PREFIX]);
        sync_directory_io(&self.directory).map_err(session_io("sync ephemeral directory"))
    }
}

impl Drop for EphemeralSession {
    fn drop(&mut self) {
        if self.lock.is_some() {
            let _ = self.clear_credentials();
        }
    }
}

fn if_present(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn session_io(operation: &'static str) -> impl FnOnce(io::Error) -> EnrollmentError {
    move |source| EnrollmentError::EphemeralSessionIo { operation, source }
}
