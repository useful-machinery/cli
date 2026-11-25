//! The runner's check of a login it holds: the coding agent's own program,
//! run once through the execution component's login check with the
//! environment an admission would be offered for that login. The check
//! writes nothing; setup notes what it found as the login's last use and a
//! pass records it.

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use useful_execution::{
    CLAUDE_CODE_LOGIN_VARIABLE, CODEX_LOGIN_VARIABLE, CoordinatorClock, EnvironmentSnapshot,
    HarnessLoginCheck, HarnessLoginCheckCause, MINIMUM_CANCELLATION_GRACE,
    ValidatedClaudeCodeInstallation, ValidatedCodexInstallation, check_claude_code_login,
    check_codex_login,
};

use super::blocked::BlockedNames;
use super::directory::LoginDirectory;
use super::readiness::{Installation, UseOutcome};
use super::{ServiceEnvironment, claude_code, codex};
use crate::control_protocol::{AgentLoginCheckCause, AgentLoginProvider, CredentialMode};

/// How long a check waits for the program to end its turn.
pub(crate) const CHECK_BOUND: Duration = Duration::from_secs(60);

/// The longest a check takes: its bound, and the grace a program stopped at
/// the bound has to exit before it is forced.
pub(crate) const CHECK_ALLOWANCE: Duration = CHECK_BOUND.saturating_add(MINIMUM_CANCELLATION_GRACE);

/// What a check of a login found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoginCheckOutcome {
    /// The provider accepted or refused the login: its last use.
    Answered(UseOutcome),
    /// The check gave no answer, which says nothing of the login.
    NoAnswer(AgentLoginCheckCause),
}

/// Checks a login the runner holds with its provider.
pub(crate) trait LoginCheck: Send + Sync {
    /// Checks `login`, the provider's install the readiness document
    /// records, going by `mode`, the credential mode of the setup that asks, and blocks until the check ends.
    fn check(
        &self,
        provider: AgentLoginProvider,
        login: &Installation,
        mode: Option<CredentialMode>,
    ) -> LoginCheckOutcome;
}

/// The serving runner's check: the `claude` and `codex` installations it
/// validated when it started, run with the process environment and the
/// login's variable as the offer sets it from the runner's directory. A
/// provider whose program it has none of answers `program_unavailable`.
pub(crate) struct ProgramLoginCheck<Clock> {
    claude_code: Option<ValidatedClaudeCodeInstallation>,
    codex: Option<ValidatedCodexInstallation>,
    process: EnvironmentSnapshot,
    directory: LoginDirectory,
    client_version: Arc<str>,
    clock: Clock,
}

impl<Clock: CoordinatorClock> ProgramLoginCheck<Clock> {
    /// The check of the runner whose protected state is at
    /// `runner_state_path`, from the process's own environment;
    /// `client_version` is the version the Codex adapter introduces itself
    /// with.
    pub(crate) fn new(
        claude_code: Option<ValidatedClaudeCodeInstallation>,
        codex: Option<ValidatedCodexInstallation>,
        runner_state_path: &Path,
        client_version: &str,
        clock: Clock,
    ) -> Self {
        Self {
            claude_code,
            codex,
            process: EnvironmentSnapshot::new(std::env::vars_os()),
            directory: LoginDirectory::beside(runner_state_path),
            client_version: Arc::from(client_version),
            clock,
        }
    }

    /// The environment a check of the login the offer sets as `variable`
    /// runs with under `mode` (`checked_environment`).
    fn offered(
        &self,
        mode: Option<CredentialMode>,
        variable: &str,
        offered: OfferedLogin,
    ) -> EnvironmentSnapshot {
        checked_environment(&self.process, mode, &self.directory, variable, offered)
    }
}

/// How an offer reads the variable of a coding agent's login from the
/// service environment and the runner's directory:
/// `claude_code::offered_token` or `codex::offered_home`.
type OfferedLogin = fn(&ServiceEnvironment, &LoginDirectory) -> Option<(OsString, OsString)>;

/// The environment a check runs with under `mode`, the credential mode of
/// the setup that asks, from the process snapshot `process`: `variable` as
/// `offered` sets it from the runner's `directory`, or unset where it sets
/// none, so the check never falls back to a login of the host's own, and
/// every other name as the process has it. Under `cloud` the fixed blocked
/// names are removed first and `offered` is asked of a service environment
/// that provides nothing, so the login is the runner's and no key or
/// configuration directory of the host's reaches the check. A standing setup has no assignment and so no list of
/// Cloud's: the fixed names are the whole set.
fn checked_environment(
    process: &EnvironmentSnapshot,
    mode: Option<CredentialMode>,
    directory: &LoginDirectory,
    variable: &str,
    offered: OfferedLogin,
) -> EnvironmentSnapshot {
    let service = ServiceEnvironment::of(process);
    let login = offered(service.under(mode), directory);
    let process = match mode {
        Some(CredentialMode::Cloud) => BlockedNames::fixed().remove_from(process),
        None | Some(CredentialMode::Host) => process.clone(),
    };
    EnvironmentSnapshot::new(
        process
            .variables()
            .iter()
            .filter(|(name, _)| name.as_os_str() != OsStr::new(variable))
            .map(|(name, value)| (name.clone(), value.clone()))
            .chain(login),
    )
}

impl<Clock: CoordinatorClock> LoginCheck for ProgramLoginCheck<Clock> {
    // The offer reads the login from the runner's directory, where the pass
    // that recorded `_login` installed it.
    fn check(
        &self,
        provider: AgentLoginProvider,
        _login: &Installation,
        mode: Option<CredentialMode>,
    ) -> LoginCheckOutcome {
        // The check's spawned work needs a runtime, and the setup's thread
        // is not one of the service's workers.
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return LoginCheckOutcome::NoAnswer(AgentLoginCheckCause::StartFailed);
        };
        let found = match provider {
            AgentLoginProvider::ClaudeCode => {
                let Some(installation) = &self.claude_code else {
                    return LoginCheckOutcome::NoAnswer(AgentLoginCheckCause::ProgramUnavailable);
                };
                let environment =
                    self.offered(mode, CLAUDE_CODE_LOGIN_VARIABLE, claude_code::offered_token);
                runtime.block_on(check_claude_code_login(
                    installation,
                    environment,
                    CHECK_BOUND,
                    self.clock.clone(),
                ))
            }
            // The runner's Codex home itself, so a login Codex refreshes
            // during the check is kept.
            AgentLoginProvider::Codex => {
                let Some(installation) = &self.codex else {
                    return LoginCheckOutcome::NoAnswer(AgentLoginCheckCause::ProgramUnavailable);
                };
                let environment = self.offered(mode, CODEX_LOGIN_VARIABLE, codex::offered_home);
                runtime.block_on(check_codex_login(
                    installation,
                    environment,
                    CHECK_BOUND,
                    self.clock.clone(),
                    &self.client_version,
                ))
            }
            AgentLoginProvider::Github
            | AgentLoginProvider::Gitlab
            | AgentLoginProvider::Linear => {
                return LoginCheckOutcome::NoAnswer(AgentLoginCheckCause::ProgramUnavailable);
            }
        };
        outcome(found)
    }
}

/// What the execution component's check found, as the runner records it.
fn outcome(found: HarnessLoginCheck) -> LoginCheckOutcome {
    match found {
        HarnessLoginCheck::Accepted => LoginCheckOutcome::Answered(UseOutcome::Accepted),
        HarnessLoginCheck::Refused => LoginCheckOutcome::Answered(UseOutcome::Refused),
        HarnessLoginCheck::NoAnswer(cause) => LoginCheckOutcome::NoAnswer(match cause {
            HarnessLoginCheckCause::Preparation { .. }
            | HarnessLoginCheckCause::StartFailed { .. } => AgentLoginCheckCause::StartFailed,
            HarnessLoginCheckCause::TimedOut => AgentLoginCheckCause::TimedOut,
            HarnessLoginCheckCause::HarnessError { .. }
            | HarnessLoginCheckCause::HarnessFailed { .. } => AgentLoginCheckCause::HarnessError,
        }),
    }
}

#[cfg(test)]
mod tests;
