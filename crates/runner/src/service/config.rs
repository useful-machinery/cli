use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use url::Url;

use crate::credential::Credential;
use crate::enrollment::{PendingCredential, RunnerStateAccess};
use useful_execution::{
    ValidatedClaudeCodeInstallation, ValidatedCodexInstallation, ValidatedPiInstallation,
};

/// The directory beside the state file that holds the runner's log.
pub(crate) const LOG_DIRECTORY: &str = "logs";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RepositoryUrlPolicy {
    allow_file: bool,
}

impl RepositoryUrlPolicy {
    pub(super) const fn production() -> Self {
        Self::with_file_repositories(false)
    }

    pub(super) const fn with_file_repositories(allow_file: bool) -> Self {
        Self { allow_file }
    }

    pub(super) const fn allows_file_repositories(self) -> bool {
        self.allow_file
    }
}

/// The kept-run bounds the operator configuration's `keptRuns` resolves to
/// (REQ-RUNNERENROLL-157): `None` sets no bound of that kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeptRunBounds {
    pub(crate) maximum_age: Option<Duration>,
    pub(crate) maximum_total_bytes: Option<u64>,
}

impl Default for KeptRunBounds {
    /// The bound of each kind a configuration takes when it does not name
    /// one: 14 days and 50 GiB.
    fn default() -> Self {
        Self {
            maximum_age: Some(Duration::from_secs(14 * 86_400)),
            maximum_total_bytes: Some(53_687_091_200),
        }
    }
}

/// A build cache the operator configuration's `buildCaches` names
/// (REQ-RUNNERENROLL-160): the directory as written and its bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BuildCache {
    pub(crate) path: PathBuf,
    pub(crate) maximum_bytes: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct AssignmentConfig {
    work_root: PathBuf,
    kept_runs: KeptRunBounds,
    build_caches: Vec<BuildCache>,
}

impl AssignmentConfig {
    pub(crate) fn new(work_root: &Path) -> Result<Self, ConfigError> {
        Ok(Self {
            work_root: canonical_directory(work_root, ConfigError::WorkRootUnavailable)?,
            kept_runs: KeptRunBounds::default(),
            build_caches: Vec::new(),
        })
    }

    pub(crate) fn with_kept_runs(self, kept_runs: KeptRunBounds) -> Self {
        Self { kept_runs, ..self }
    }

    pub(crate) fn with_build_caches(self, build_caches: Vec<BuildCache>) -> Self {
        Self {
            build_caches,
            ..self
        }
    }

    pub(crate) fn work_root(&self) -> &Path {
        &self.work_root
    }

    pub(crate) fn kept_runs(&self) -> KeptRunBounds {
        self.kept_runs
    }

    pub(crate) fn build_caches(&self) -> &[BuildCache] {
        &self.build_caches
    }
}

#[derive(Clone)]
pub struct Config {
    endpoint: Url,
    credential: Credential,
    startup_pending: Option<PendingCredential>,
    state_access: Option<RunnerStateAccess>,
    control_socket_path: Option<PathBuf>,
    log_directory: Option<PathBuf>,
    assignment: AssignmentConfig,
    /// The free space kept on the work root's disk (REQ-RUNNERENROLL-152).
    minimum_free_disk_bytes: u64,
    repository_url_policy: RepositoryUrlPolicy,
    pi_installation: Option<ValidatedPiInstallation>,
    claude_code_installation: Option<ValidatedClaudeCodeInstallation>,
    codex_installation: Option<ValidatedCodexInstallation>,
}

impl fmt::Debug for Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Config")
            .field("endpoint", &self.endpoint)
            .field("credential", &self.credential)
            .field("kept_runs", &self.assignment.kept_runs())
            .field("build_caches", &self.assignment.build_caches())
            .field(
                "agent_capable",
                &(self.pi_installation.is_some()
                    || self.claude_code_installation.is_some()
                    || self.codex_installation.is_some()),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ConfigError {
    InvalidOperatorConfiguration,
    StateLockUnavailable,
    InvalidGatewayUrl,
    InsecureGatewayUrl,
    WorkRootUnavailable,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOperatorConfiguration => {
                formatter.write_str("runner operator configuration or protected state is invalid")
            }
            Self::StateLockUnavailable => {
                fmt::Display::fmt(&crate::enrollment::EnrollmentError::StateLock, formatter)
            }
            Self::InvalidGatewayUrl => formatter.write_str("invalid runner gateway URL"),
            Self::InsecureGatewayUrl => {
                formatter.write_str("insecure runner gateway URL is not allowed")
            }
            Self::WorkRootUnavailable => {
                formatter.write_str("runner work root is not an existing directory")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Whether the host the operator configuration at `path` describes holds
    /// enrolled state: anything at its `runnerStatePath`, judged without the
    /// state lock and without reading the state. Only a path that does not
    /// exist answers `false`; a file of any kind, a dangling link or a path
    /// that cannot be inspected answers `true`, so the load that follows names
    /// the failure rather than the host being joined over.
    pub fn holds_enrolled_state(path: &Path) -> Result<bool, ConfigError> {
        let state_path = crate::enrollment::load_runner_state_path(path)
            .map_err(|_| ConfigError::InvalidOperatorConfiguration)?;
        match fs::symlink_metadata(state_path) {
            Ok(_) => Ok(true),
            Err(error) => Ok(error.kind() != io::ErrorKind::NotFound),
        }
    }

    /// Validates, for a host that holds no state yet, what [`Config::load`]
    /// validates of the host before any state exists: that the operator
    /// configuration at `path` reads and that its work root is an existing
    /// directory. A host that fails here cannot serve, so it must not join.
    pub fn validate_before_join(path: &Path) -> Result<(), ConfigError> {
        let work_root = crate::enrollment::load_work_root(path)
            .map_err(|_| ConfigError::InvalidOperatorConfiguration)?;
        AssignmentConfig::new(&work_root).map(|_| ())
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let enrolled = crate::enrollment::load_runner_service_configuration(path).map_err(
            |error| match error {
                crate::enrollment::EnrollmentError::StateLock => ConfigError::StateLockUnavailable,
                _ => ConfigError::InvalidOperatorConfiguration,
            },
        )?;
        let credential = Credential::from_enrolled_state(
            &enrolled.runner_id,
            &enrolled.credential_id,
            &enrolled.credential_secret,
        )
        .map_err(|_| ConfigError::InvalidOperatorConfiguration)?;
        let endpoint = Url::parse(&enrolled.connection_url)
            .map_err(|_| ConfigError::InvalidOperatorConfiguration)?;
        if let Some(pending) = enrolled.pending_credential.clone() {
            let _ = validate_pending_credential(pending)?;
        }
        let startup_pending = enrolled.pending_credential;
        let assignment = AssignmentConfig::new(&enrolled.work_root)?
            .with_kept_runs(enrolled.kept_runs)
            .with_build_caches(enrolled.build_caches);
        let mut config = Self::new(
            endpoint.as_str(),
            credential,
            true,
            assignment,
            RepositoryUrlPolicy::production(),
        )
        .map_err(|_| ConfigError::InvalidOperatorConfiguration)?;
        config.startup_pending = startup_pending;
        config.log_directory = enrolled
            .state_access
            .path()
            .parent()
            .map(|directory| directory.join(LOG_DIRECTORY));
        config.state_access = Some(enrolled.state_access);
        config.control_socket_path = Some(enrolled.control_socket_path);
        config.minimum_free_disk_bytes = enrolled.minimum_free_disk_bytes;
        Ok(config)
    }

    pub(super) fn new(
        gateway_url: &str,
        credential: Credential,
        allow_insecure_http: bool,
        assignment: AssignmentConfig,
        repository_url_policy: RepositoryUrlPolicy,
    ) -> Result<Self, ConfigError> {
        let endpoint = Url::parse(gateway_url).map_err(|_| ConfigError::InvalidGatewayUrl)?;
        if endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.host_str().is_none()
        {
            return Err(ConfigError::InvalidGatewayUrl);
        }
        match endpoint.scheme() {
            "wss" => {}
            "ws" if allow_insecure_http && crate::is_loopback(&endpoint) => {}
            "ws" => return Err(ConfigError::InsecureGatewayUrl),
            _ => return Err(ConfigError::InvalidGatewayUrl),
        }
        Ok(Self {
            endpoint,
            credential,
            startup_pending: None,
            state_access: None,
            control_socket_path: None,
            log_directory: None,
            assignment,
            minimum_free_disk_bytes: useful_execution::DEFAULT_MINIMUM_FREE_DISK_BYTES,
            repository_url_policy,
            pi_installation: None,
            claude_code_installation: None,
            codex_installation: None,
        })
    }

    pub(crate) fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    pub(crate) fn credential(&self) -> &Credential {
        &self.credential
    }

    pub(crate) fn startup_pending(&self) -> Option<&PendingCredential> {
        self.startup_pending.as_ref()
    }

    pub(crate) fn state_access(&self) -> Option<&RunnerStateAccess> {
        self.state_access.as_ref()
    }

    pub(crate) fn control_socket_path(&self) -> Option<&Path> {
        self.control_socket_path.as_deref()
    }

    /// The directory the serving runner keeps its log in, `logs` beside its
    /// state file (REQ-TELEMETRY-52); none for a configuration that names no
    /// state, so it writes no log.
    pub(crate) fn log_directory(&self) -> Option<&Path> {
        self.log_directory.as_deref()
    }

    pub(crate) fn with_pending_credential(
        &self,
        pending: PendingCredential,
    ) -> Result<Self, ConfigError> {
        let (endpoint, credential) = validate_pending_credential(pending)?;
        let mut config = self.clone();
        config.endpoint = endpoint;
        config.credential = credential;
        config.startup_pending = None;
        Ok(config)
    }

    pub(crate) fn assignment(&self) -> &AssignmentConfig {
        &self.assignment
    }

    /// The free space the serving runner keeps on its work root's disk: the operator
    /// configuration's `minimumFreeDiskBytes`, or the default (REQ-RUNNERENROLL-152).
    pub(crate) fn minimum_free_disk_bytes(&self) -> u64 {
        self.minimum_free_disk_bytes
    }

    /// The configuration with `build_caches` in place of its build caches.
    #[cfg(test)]
    pub(crate) fn with_build_caches(mut self, build_caches: Vec<BuildCache>) -> Self {
        self.assignment = self.assignment.with_build_caches(build_caches);
        self
    }

    pub(super) fn repository_url_policy(&self) -> RepositoryUrlPolicy {
        self.repository_url_policy
    }

    pub fn pi_installation(&self) -> Option<&ValidatedPiInstallation> {
        self.pi_installation.as_ref()
    }

    pub fn with_pi_installation(mut self, installation: ValidatedPiInstallation) -> Self {
        self.pi_installation = Some(installation);
        self
    }

    // Runner service configuration snapshots and workflow admission intentionally retain
    // parallel typed builders; sharing their containers would merge separate lifecycle layers.
    pub fn claude_code_installation(&self) -> Option<&ValidatedClaudeCodeInstallation> {
        self.claude_code_installation.as_ref()
    }

    pub fn with_claude_code_installation(
        mut self,
        installation: ValidatedClaudeCodeInstallation,
    ) -> Self {
        self.claude_code_installation = Some(installation);
        self
    }

    pub fn codex_installation(&self) -> Option<&ValidatedCodexInstallation> {
        self.codex_installation.as_ref()
    }

    pub fn with_codex_installation(mut self, installation: ValidatedCodexInstallation) -> Self {
        self.codex_installation = Some(installation);
        self
    }

    #[cfg(feature = "test-fixtures")]
    pub fn fixture_for_command_tests(
        gateway_url: &str,
        work_root: &Path,
    ) -> Result<Self, ConfigError> {
        let credential = Credential::from_enrolled_state(
            "rnr_01k0z6r1w8f4jy2m7q9v3x5abd",
            "rrc_01k0z6r1w8f4jy2m7q9v3x5abd",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .map_err(|_| ConfigError::InvalidOperatorConfiguration)?;
        Self::new(
            gateway_url,
            credential,
            true,
            AssignmentConfig::new(work_root)?,
            RepositoryUrlPolicy::production(),
        )
    }
}

fn validate_pending_credential(
    pending: PendingCredential,
) -> Result<(Url, Credential), ConfigError> {
    let endpoint = Url::parse(&pending.connection_url)
        .map_err(|_| ConfigError::InvalidOperatorConfiguration)?;
    let credential = Credential::from_enrolled_state(
        &pending.runner_id,
        &pending.credential_id,
        &pending.credential_secret,
    )
    .map_err(|_| ConfigError::InvalidOperatorConfiguration)?;
    Ok((endpoint, credential))
}

fn canonical_directory(path: &Path, failure: ConfigError) -> Result<PathBuf, ConfigError> {
    let canonical = fs::canonicalize(path).map_err(|_| failure)?;
    if !fs::metadata(&canonical).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(failure);
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::Duration;
    use tempfile::TempDir;

    use super::{
        AssignmentConfig, BuildCache, Config, ConfigError, KeptRunBounds, RepositoryUrlPolicy,
    };
    use crate::credential::test_credential;

    fn assignment_fixture(temporary: &TempDir) -> AssignmentConfig {
        let work = temporary.path().join("work");
        fs::create_dir_all(&work).unwrap();
        AssignmentConfig::new(&work).unwrap()
    }

    // REQ-RUNNERENROLL-30, REQ-RUNNERENROLL-31
    #[test]
    fn permits_wss_and_explicit_loopback_ws_only() {
        let temporary = tempfile::tempdir().unwrap();
        assert!(
            Config::new(
                "wss://gateway.example.test/v1/runner/connect",
                test_credential(),
                false,
                assignment_fixture(&temporary),
                RepositoryUrlPolicy::production(),
            )
            .is_ok()
        );
        assert!(
            Config::new(
                "ws://127.0.0.1:8081/v1/runner/connect",
                test_credential(),
                true,
                assignment_fixture(&temporary),
                RepositoryUrlPolicy::production(),
            )
            .is_ok()
        );
        assert_eq!(
            Config::new(
                "ws://127.0.0.1:8081/v1/runner/connect",
                test_credential(),
                false,
                assignment_fixture(&temporary),
                RepositoryUrlPolicy::production(),
            )
            .unwrap_err(),
            ConfigError::InsecureGatewayUrl,
        );
        assert_eq!(
            Config::new(
                "ws://gateway.example.test/v1/runner/connect",
                test_credential(),
                true,
                assignment_fixture(&temporary),
                RepositoryUrlPolicy::production(),
            )
            .unwrap_err(),
            ConfigError::InsecureGatewayUrl,
        );
    }

    // REQ-RUNNERENROLL-30
    #[test]
    fn requires_an_existing_work_root() {
        let temporary = tempfile::tempdir().unwrap();
        assert_eq!(
            AssignmentConfig::new(&temporary.path().join("missing")).unwrap_err(),
            ConfigError::WorkRootUnavailable,
        );
    }

    /// An operator configuration in a private directory whose state file and
    /// work root do not exist yet.
    struct Host {
        _root: TempDir,
        config: PathBuf,
        state: PathBuf,
    }

    impl Host {
        fn new() -> Self {
            Self::with_member(None)
        }

        /// A host whose operator configuration carries `keptRuns`.
        fn with_kept_runs(kept_runs: serde_json::Value) -> Self {
            Self::with_member(Some(("keptRuns", kept_runs)))
        }

        /// A host whose operator configuration carries the optional member
        /// given, by name and value.
        fn with_member(member: Option<(&str, serde_json::Value)>) -> Self {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), Permissions::from_mode(0o700)).unwrap();
            let config = root.path().join("runner.json");
            let state = root.path().join("state/runner-state.json");
            let mut document = serde_json::json!({
                "schemaVersion": 1,
                "deploymentMode": "development",
                "runnerStatePath": state,
                "controlSocketPath": root.path().join("run/runner.sock"),
                "workRoot": root.path().join("work")
            });
            if let Some((name, value)) = member {
                document[name] = value;
            }
            fs::write(&config, serde_json::to_vec(&document).unwrap()).unwrap();
            Self {
                _root: root,
                config,
                state,
            }
        }

        fn write_state(&self, document: &serde_json::Value) {
            let directory = self.state.parent().unwrap();
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, Permissions::from_mode(0o700)).unwrap();
            fs::write(&self.state, serde_json::to_vec(document).unwrap()).unwrap();
            fs::set_permissions(&self.state, Permissions::from_mode(0o600)).unwrap();
        }

        /// Writes valid enrolled state; the work root stays absent.
        fn write_enrolled_state(&self) {
            self.write_state(&serde_json::json!({
                "schemaVersion": 1,
                "runnerId": "rnr_01k0z6r1w8f4jy2m7q9v3x5abc",
                "connectionUrl": "ws://127.0.0.1:8765/v1/runner/connect",
                "currentCredential": {
                    "id": "rrc_01k0z6r1w8f4jy2m7q9v3x5abc",
                    "secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "activationId": "rna_01k0z6r1w8f4jy2m7q9v3x5abc",
                    "enrolledAt": "2026-08-06T12:00:00Z"
                },
                "updatedAt": "2026-08-06T12:00:00Z"
            }));
        }

        /// Writes valid enrolled state and creates the work root, so that
        /// `Config::load` succeeds.
        fn enroll(&self) {
            self.write_enrolled_state();
            fs::create_dir(self.config.parent().unwrap().join("work")).unwrap();
        }
    }

    // REQ-RUNNERENROLL-157
    #[test]
    fn a_loaded_configuration_carries_its_kept_run_bounds_to_assignments() {
        let bounded = Host::with_kept_runs(serde_json::json!({
            "maximumAgeDays": null,
            "maximumTotalBytes": 1_073_741_824_u64
        }));
        bounded.enroll();
        assert_eq!(
            Config::load(&bounded.config)
                .unwrap()
                .assignment()
                .kept_runs(),
            KeptRunBounds {
                maximum_age: None,
                maximum_total_bytes: Some(1_073_741_824),
            },
        );

        let defaulted = Host::new();
        defaulted.enroll();
        assert_eq!(
            Config::load(&defaulted.config)
                .unwrap()
                .assignment()
                .kept_runs(),
            KeptRunBounds {
                maximum_age: Some(Duration::from_secs(14 * 86_400)),
                maximum_total_bytes: Some(53_687_091_200),
            },
        );
    }

    // REQ-RUNNERENROLL-160
    #[test]
    fn a_loaded_configuration_carries_its_build_caches_to_assignments() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cache");
        let cached = Host::with_member(Some((
            "buildCaches",
            serde_json::json!([{"path": path, "maximumBytes": 1_073_741_824_u64}]),
        )));
        cached.enroll();
        assert_eq!(
            Config::load(&cached.config)
                .unwrap()
                .assignment()
                .build_caches(),
            [BuildCache {
                path,
                maximum_bytes: 1_073_741_824,
            }],
        );

        let uncached = Host::new();
        uncached.enroll();
        assert_eq!(
            Config::load(&uncached.config)
                .unwrap()
                .assignment()
                .build_caches(),
            [],
        );
    }

    // REQ-RUNNERENROLL-104
    #[test]
    fn a_host_holds_enrolled_state_when_its_state_file_is_present() {
        let unenrolled = Host::new();
        assert_eq!(Config::holds_enrolled_state(&unenrolled.config), Ok(false));

        let empty = Host::new();
        empty.write_state(&serde_json::json!({}));
        assert_eq!(Config::holds_enrolled_state(&empty.config), Ok(true));
        assert_eq!(
            Config::load(&empty.config).unwrap_err(),
            ConfigError::InvalidOperatorConfiguration,
        );

        let without_work_root = Host::new();
        without_work_root.write_enrolled_state();
        assert_eq!(
            Config::load(&without_work_root.config).unwrap_err(),
            ConfigError::WorkRootUnavailable,
        );
        assert_eq!(
            Config::holds_enrolled_state(&without_work_root.config),
            Ok(true)
        );
    }

    // REQ-RUNNERENROLL-104
    #[test]
    fn a_host_whose_operator_configuration_does_not_parse_holds_no_answer() {
        let host = Host::new();
        fs::write(&host.config, b"{").unwrap();
        assert_eq!(
            Config::holds_enrolled_state(&host.config),
            Err(ConfigError::InvalidOperatorConfiguration),
        );
    }

    // REQ-RUNNERENROLL-105
    #[test]
    fn a_host_is_checked_before_it_joins_for_a_work_root_that_is_a_directory() {
        let host = Host::new();
        let work_root = host.config.parent().unwrap().join("work");
        assert_eq!(
            Config::validate_before_join(&host.config),
            Err(ConfigError::WorkRootUnavailable),
        );

        fs::write(&work_root, b"").unwrap();
        assert_eq!(
            Config::validate_before_join(&host.config),
            Err(ConfigError::WorkRootUnavailable),
        );

        fs::remove_file(&work_root).unwrap();
        fs::create_dir(&work_root).unwrap();
        assert_eq!(Config::validate_before_join(&host.config), Ok(()));
    }

    #[test]
    fn constructor_retains_the_production_repository_url_policy() {
        let temporary = tempfile::tempdir().unwrap();
        let config = Config::new(
            "wss://gateway.example.test/v1/runner/connect",
            test_credential(),
            false,
            assignment_fixture(&temporary),
            RepositoryUrlPolicy::production(),
        )
        .unwrap();

        assert_eq!(
            config.repository_url_policy(),
            RepositoryUrlPolicy::production()
        );
    }
}
