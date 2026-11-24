//! GitHub setup on `useful org integration`, verified through GitHub's user authorization: where
//! a setup session stands, as `show ghs_SESSION` prints it, and the guided setup `connect github`
//! and `reconnect` of a GitHub binding run, which begins a session, waits for its verification
//! and completes it, saying why where it does not. `authorize github --project` runs the same
//! setup for the installation it authorizes.

use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use useful_api::{
    GitHubApi, GitHubFailure, GitHubInstallation, GitHubInstallationState, GitHubSetupInstallation,
    GitHubSetupSession, GitHubSetupState, GitHubSetupVerificationState,
};
use useful_human_auth::Deployment;

use super::super::linear::Options;
use super::{output, with_api};
use crate::cli::account::grant::browser;
use crate::cli::{
    CommandFailure, CommandResult, DeferredObservationTimeoutStart, OperationControl,
    SystemObservationClock, ceremony_poll_interval, complete_operation,
    execute_mutation_with_signals_and_deferred_timeout, retry_delay, wait_for_poll,
};
use crate::exit_code::{ExitCode, OutcomeClass};

/// Where a setup session read stands, which names its next step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SetupStanding {
    /// The session completed.
    Completed,
    /// The verified login could complete one or more installations.
    Completable,
    /// Something keeps the session from completing.
    Blocked(SetupObstacle),
}

/// What keeps a setup session from completing, each under its own outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SetupObstacle {
    /// The session expired before it completed.
    Expired,
    /// The verification waits for the proof at GitHub or its confirmation.
    VerificationRequired,
    /// GitHub's authorization was refused.
    ConsentDenied,
    /// The verification failed.
    VerificationFailed,
    /// The session is verified, and Cloud refused the installation the completion named.
    AuthorityUnproven,
    /// The verified login could complete none, and GitHub holds its request to install the App.
    AwaitingApproval,
    /// The verified login could complete none, and GitHub holds no request of its.
    InstallationMissing,
}

/// Why the guided setup did not complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SetupRefusal {
    /// No installation was named, and the session could complete several.
    InstallationChoiceRequired,
    Blocked(SetupObstacle),
}

impl SetupStanding {
    pub(super) fn of(session: &GitHubSetupSession) -> Self {
        if session.state == GitHubSetupState::Completed {
            Self::Completed
        } else if session.state == GitHubSetupState::Pending && !installations(session).is_empty() {
            Self::Completable
        } else {
            Self::Blocked(SetupObstacle::of(session, false))
        }
    }
}

impl SetupObstacle {
    /// What keeps `session` from completing, where a completion of it was refused or none could
    /// be sent; `installation_named` says whether the completion named an installation.
    pub(super) fn of(session: &GitHubSetupSession, installation_named: bool) -> Self {
        if session.state == GitHubSetupState::Expired {
            return Self::Expired;
        }
        match session.verification.state {
            GitHubSetupVerificationState::Unverified => Self::VerificationRequired,
            GitHubSetupVerificationState::Denied => Self::ConsentDenied,
            GitHubSetupVerificationState::Failed => Self::VerificationFailed,
            // The refusal is of the installation the completion named, whether or not GitHub
            // reports one, so a request elsewhere does not explain it.
            GitHubSetupVerificationState::Verified if installation_named => Self::AuthorityUnproven,
            GitHubSetupVerificationState::Verified
                if !pending_request_accounts(session).is_empty() =>
            {
                Self::AwaitingApproval
            }
            GitHubSetupVerificationState::Verified => Self::InstallationMissing,
        }
    }

    pub(super) const fn outcome(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::VerificationRequired => "verification_required",
            Self::ConsentDenied => "consent_denied",
            Self::VerificationFailed => "verification_failed",
            Self::AuthorityUnproven => "authority_unproven",
            Self::AwaitingApproval => "awaiting_approval",
            Self::InstallationMissing => "installation_missing",
        }
    }
}

impl SetupRefusal {
    pub(super) const fn outcome(self) -> &'static str {
        match self {
            Self::InstallationChoiceRequired => "installation_choice_required",
            Self::Blocked(obstacle) => obstacle.outcome(),
        }
    }

    pub(super) const fn exit_code(self) -> ExitCode {
        match self {
            Self::InstallationChoiceRequired => ExitCode::UsageError,
            Self::Blocked(_) => OutcomeClass::GeneralFailure.exit_code(),
        }
    }
}

/// The installations a verified session read lists, including those the organization holds.
pub(super) fn installations(session: &GitHubSetupSession) -> &[GitHubSetupInstallation] {
    session
        .verification
        .installations
        .as_deref()
        .unwrap_or_default()
}

/// The accounts where GitHub holds the verified login's request to install the App.
pub(super) fn pending_request_accounts(session: &GitHubSetupSession) -> Vec<&str> {
    session
        .verification
        .pending_requests
        .iter()
        .flat_map(|requests| &requests.items)
        .map(|request| request.provider_account_login.as_str())
        .collect()
}

/// What a completion came to: Cloud's answer, or, where Cloud refused the installation for
/// unproven authority, a read of the session after the refusal.
enum Completion {
    Answered(Result<GitHubInstallation, GitHubFailure>),
    Unproven(Result<GitHubSetupSession, GitHubFailure>),
}

/// The setup routes of `organization` under the credential `options` select, and the reports of
/// their answers.
struct Client<'a> {
    deployment: &'a Deployment,
    organization: &'a str,
    options: &'a Options,
}

impl Client<'_> {
    fn call<T>(
        &self,
        operation: impl FnMut(&GitHubApi) -> Result<T, GitHubFailure>,
    ) -> anyhow::Result<Result<T, GitHubFailure>> {
        with_api(
            self.deployment,
            self.options.http.transport_policy(),
            &self.options.authentication,
            operation,
        )
    }

    fn api_url(&self) -> &str {
        self.deployment.fingerprint().api_url()
    }

    fn read(
        &self,
        setup_session: &str,
    ) -> anyhow::Result<Result<GitHubSetupSession, GitHubFailure>> {
        self.call(|api| api.setup_session(self.organization, setup_session))
    }

    /// Completes `setup_session` with `installation`, reading the session after a refusal for
    /// unproven authority. Where `binding` is given, an answer that names another binding is a
    /// protocol failure, since a reconnection never makes a new connection.
    fn complete(
        &self,
        setup_session: &str,
        installation: &str,
        binding: Option<&str>,
    ) -> anyhow::Result<Completion> {
        // GitHub setup keeps its multi-field completion request explicit rather than sharing
        // project repository mutation plumbing with a different failure and output contract.
        let completed =
            self.call(|api| api.complete_setup(self.organization, setup_session, installation))?;
        Ok(match completed {
            Err(GitHubFailure::AuthorityUnproven) => {
                Completion::Unproven(self.read(setup_session)?)
            }
            Ok(answered) if binding.is_some_and(|binding| answered.id != binding) => {
                Completion::Answered(Err(GitHubFailure::Protocol {
                    credential_rejected: false,
                }))
            }
            answered => Completion::Answered(answered),
        })
    }

    /// A failed read, reported as `show ghs_SESSION` reports it.
    fn report_read_failure(&self, failure: &GitHubFailure) -> anyhow::Result<ExitCode> {
        output::write_setup_show(
            self.api_url(),
            self.organization,
            &Err(failure.clone()),
            self.options.authentication.kind(),
            self.options.json,
        )
    }

    fn report_refusal(
        &self,
        session: &GitHubSetupSession,
        refusal: SetupRefusal,
        steps: &output::Steps<'_>,
    ) -> anyhow::Result<ExitCode> {
        output::write_setup_refusal(
            self.api_url(),
            self.organization,
            session,
            refusal,
            steps,
            self.options.json,
        )
    }

    /// Reports `completion`: the binding Cloud answered, or a refusal naming the commands
    /// `steps` names.
    fn report_completion(
        &self,
        completion: &Completion,
        steps: &output::Steps<'_>,
    ) -> anyhow::Result<ExitCode> {
        match completion {
            Completion::Answered(answered) => output::write_installation(
                self.api_url(),
                self.organization,
                answered,
                output::InstallationAction::SetupCompleted,
                self.options.authentication.kind(),
                self.options.json,
            ),
            Completion::Unproven(Ok(session)) => self.report_refusal(
                session,
                SetupRefusal::Blocked(SetupObstacle::of(session, true)),
                steps,
            ),
            Completion::Unproven(Err(failure)) => self.report_read_failure(failure),
        }
    }
}

/// Reads the setup session `setup_session` of `organization` and prints where it
/// stands, changing nothing.
pub(in crate::cli::org::connection) fn show(
    deployment: &Deployment,
    options: &super::super::list::Options,
    organization: &str,
    setup_session: &str,
) -> anyhow::Result<ExitCode> {
    let result = with_api(
        deployment,
        options.http.transport_policy(),
        &options.authentication,
        |api| api.setup_session(organization, setup_session),
    )?;
    output::write_setup_show(
        deployment.fingerprint().api_url(),
        organization,
        &result,
        options.authentication.kind(),
        options.json,
    )
}

/// What the guided setup is given.
pub(in crate::cli::org::connection) struct Guidance<'a> {
    pub(in crate::cli::org::connection) organization: &'a str,
    /// The GitHub installation to complete, whatever the session lists: `--installation`, or the
    /// installation of the binding `reconnect` renews.
    pub(in crate::cli::org::connection) installation: Option<&'a str>,
    /// The binding `reconnect` renews, which the completion must answer.
    pub(in crate::cli::org::connection) binding: Option<&'a str>,
    /// The organization's installations, where the command read them already.
    pub(in crate::cli::org::connection) listed: Option<Vec<GitHubInstallation>>,
    /// Whether to return once the session begins.
    pub(in crate::cli::org::connection) no_wait: bool,
    /// How long to wait, when not [`GUIDED_TIMEOUT`].
    pub(in crate::cli::org::connection) timeout: Option<Duration>,
}

/// How long the guided setup waits by default, as `connect linear` does; the session's own ten
/// minutes end it sooner.
const GUIDED_TIMEOUT: Duration = Duration::from_secs(900);

/// The session this invocation began, once known.
#[derive(Clone)]
struct Recovery {
    session: Option<String>,
}

/// How a guided setup ended: its status, and the binding it completed where it ended
/// `completed`, on which `authorize` resumes.
pub(in crate::cli::org::connection) struct Guided {
    pub(in crate::cli::org::connection) status: ExitCode,
    pub(in crate::cli::org::connection) completed: Option<GitHubInstallation>,
}

/// Runs the guided setup: reads the organization's installations, where `guidance` does not hold
/// them, begins a setup session and prints both, opens the authorization URL where this machine
/// has a browser, and unless `no_wait` reads the session until its verification lets it complete
/// an installation or ends it, as `connect linear` polls its session. Begin carries no
/// idempotency key, so it is never replayed. The binding a completion answered is returned
/// beside the status only where the setup exits 0, having reported it.
pub(in crate::cli::org::connection) fn guide(
    deployment: &Deployment,
    options: Options,
    guidance: Guidance<'_>,
) -> Result<Guided, CommandFailure> {
    let organization = guidance.organization.to_owned();
    let again = match guidance.binding {
        Some(binding) => output::reconnect_command(&organization, binding),
        None => output::connect_command(&organization, guidance.installation),
    };
    let stop = Stop {
        api_url: deployment.fingerprint().api_url().to_owned(),
        organization: organization.clone(),
        again: again.clone(),
        json: options.json,
    };
    let signal_stop = stop.clone();
    let completed = Arc::new(OnceLock::new());
    let timeout = (!guidance.no_wait).then(|| guidance.timeout.unwrap_or(GUIDED_TIMEOUT));
    let run = Run {
        deployment: deployment.clone(),
        organization,
        installation: guidance.installation.map(str::to_owned),
        binding: guidance.binding.map(str::to_owned),
        listed: guidance.listed,
        no_wait: guidance.no_wait,
        again,
        options,
        completed: Arc::clone(&completed),
    };
    let status = execute_mutation_with_signals_and_deferred_timeout(
        "GitHub setup",
        Recovery { session: None },
        timeout,
        move |control, timeout_start| run.run(control, timeout_start),
        move |signal, snapshot| {
            if !snapshot.dispatched {
                return Ok(signal);
            }
            signal_stop.stopped(signal, &snapshot.recovery)
        },
        move |snapshot| stop.stopped(ExitCode::GeneralFailure, &snapshot.recovery),
    )?;
    Ok(Guided {
        status,
        completed: (status == ExitCode::Success)
            .then(|| completed.get().cloned())
            .flatten(),
    })
}

/// What reports a guided setup that `--timeout` or a signal stopped.
#[derive(Clone)]
struct Stop {
    api_url: String,
    organization: String,
    again: String,
    json: bool,
}

impl Stop {
    fn stopped(&self, signal: ExitCode, recovery: &Recovery) -> CommandResult {
        let outcome = if signal == ExitCode::GeneralFailure {
            "timed_out"
        } else {
            "observation_stopped"
        };
        output::write_guided_stopped(
            &self.api_url,
            &self.organization,
            outcome,
            recovery.session.as_deref(),
            &self.again,
            self.json,
        )?;
        Ok(signal)
    }
}

/// The guided setup as it runs, apart from the command that began it.
struct Run {
    deployment: Deployment,
    organization: String,
    installation: Option<String>,
    binding: Option<String>,
    listed: Option<Vec<GitHubInstallation>>,
    no_wait: bool,
    /// The command that runs this setup again.
    again: String,
    options: Options,
    /// The binding Cloud answered the completion with, which [`guide`] returns.
    completed: Arc<OnceLock<GitHubInstallation>>,
}

/// What the guided setup does with a read of its session.
#[derive(Debug, Eq, PartialEq)]
enum Move<'a> {
    /// Read the session again.
    Wait,
    /// Complete this installation.
    Complete(&'a str),
    /// End, completing nothing; a choice is among these installations.
    Refuse(SetupRefusal, Vec<&'a str>),
}

/// Prints `output` once no signal has claimed the output.
fn end(
    control: &OperationControl<Recovery>,
    output: impl FnOnce() -> anyhow::Result<ExitCode>,
) -> CommandResult {
    complete_operation(control, || Ok(output()?))
}

impl Run {
    fn client(&self) -> Client<'_> {
        Client {
            deployment: &self.deployment,
            organization: &self.organization,
            options: &self.options,
        }
    }

    fn steps<'a>(&self, choices: Vec<&'a str>) -> output::Steps<'a> {
        output::Steps::new(self.again.clone(), choices)
    }

    fn run(
        mut self,
        control: &OperationControl<Recovery>,
        timeout_start: &DeferredObservationTimeoutStart,
    ) -> CommandResult {
        let listed = match self.listed.take() {
            Some(listed) => listed,
            None => {
                let client = self.client();
                match client.call(|api| api.list_installations(&self.organization))? {
                    Ok(listed) => listed,
                    Err(failure) => {
                        return end(control, || {
                            output::write_list_failure(
                                client.api_url(),
                                &self.organization,
                                &failure,
                                self.options.authentication.kind(),
                                self.options.json,
                            )
                        });
                    }
                }
            }
        };
        let client = self.client();
        if !control.begin_dispatch() {
            return Ok(ExitCode::Interrupted);
        }
        let session = match client.call(|api| api.begin_setup(&self.organization))? {
            Ok(session) => session,
            Err(failure) => {
                return end(control, || {
                    output::write_begin_failure(
                        client.api_url(),
                        &self.organization,
                        &failure,
                        self.options.authentication.kind(),
                        self.options.json,
                    )
                });
            }
        };
        if !control.update_recovery(Recovery {
            session: Some(session.id.clone()),
        }) {
            return Ok(ExitCode::Interrupted);
        }
        // With --no-wait nothing completes the session, so the report names the command that
        // connects the installation once GitHub holds it.
        let then = self
            .no_wait
            .then(|| match (&self.installation, &self.binding) {
                (None, None) => {
                    output::connect_command(&self.organization, Some("<INSTALLATION_ID>"))
                }
                _ => self.again.clone(),
            });
        // The URLs are printed first, so a browser that does not open loses nothing, and the
        // browser is only started, so the wait does not wait on it.
        let show = || {
            let code = output::write_guided_pending(
                client.api_url(),
                &self.organization,
                &listed,
                &session,
                then.as_deref(),
                self.options.json,
            )?;
            if let Some(url) = &session.authorization_url
                && browser::available(|name| std::env::var_os(name))
            {
                browser::open(url);
            }
            Ok(code)
        };
        if self.no_wait {
            return end(control, show);
        }
        if control.is_cancelled() {
            return Ok(ExitCode::Interrupted);
        }
        show()?;
        timeout_start.start();
        self.wait(control, &listed, &session.id)
    }

    /// Reads the session at the ceremony cadence, waiting out a rate limit, until a read ends
    /// the wait.
    fn wait(
        &self,
        control: &OperationControl<Recovery>,
        listed: &[GitHubInstallation],
        setup_session: &str,
    ) -> CommandResult {
        let client = self.client();
        let held_verified: HashSet<&str> = listed
            .iter()
            .filter(|binding| {
                binding.state == GitHubInstallationState::Active
                    && binding.authority_verified_at.is_some()
            })
            .map(|binding| binding.provider_installation_id.as_str())
            .collect();
        let mut verified = false;
        let mut next = ceremony_poll_interval();
        loop {
            if !wait_for_poll(control, next, &SystemObservationClock) {
                return Ok(ExitCode::Interrupted);
            }
            let session = match client.read(setup_session)? {
                Ok(session) => session,
                Err(GitHubFailure::RateLimited { retry_after }) => {
                    next = retry_delay(retry_after);
                    continue;
                }
                Err(failure) => return end(control, || client.report_read_failure(&failure)),
            };
            verified |= session.verification.state == GitHubSetupVerificationState::Verified;
            match next_move(
                &session,
                &held_verified,
                self.installation.as_deref(),
                verified,
            ) {
                Move::Wait => next = ceremony_poll_interval(),
                Move::Refuse(refusal, choices) => {
                    let steps = self.steps(choices);
                    return end(control, || client.report_refusal(&session, refusal, &steps));
                }
                Move::Complete(installation) => {
                    let completion =
                        client.complete(&session.id, installation, self.binding.as_deref())?;
                    if let Completion::Answered(Ok(binding)) = &completion {
                        // Set once: the run completes one session once.
                        let _set = self.completed.set(binding.clone());
                    }
                    let steps = self.steps(Vec::new());
                    return end(control, || client.report_completion(&completion, &steps));
                }
            }
        }
    }
}

/// What the guided setup does with `session`, read after it was verified where `verified`.
/// `held_verified` holds the GitHub installation IDs the organization held `active` and verified
/// as the setup began; `named` is the installation `--installation` or the binding `reconnect`
/// renews names.
fn next_move<'a>(
    session: &'a GitHubSetupSession,
    held_verified: &HashSet<&str>,
    named: Option<&'a str>,
    verified: bool,
) -> Move<'a> {
    let refuse = |obstacle| Move::Refuse(SetupRefusal::Blocked(obstacle), Vec::new());
    if session.state == GitHubSetupState::Expired {
        return refuse(if verified {
            SetupObstacle::InstallationMissing
        } else {
            SetupObstacle::Expired
        });
    }
    match session.verification.state {
        GitHubSetupVerificationState::Unverified => return Move::Wait,
        GitHubSetupVerificationState::Denied | GitHubSetupVerificationState::Failed => {
            return refuse(SetupObstacle::of(session, false));
        }
        GitHubSetupVerificationState::Verified => {}
    }
    if let Some(named) = named {
        // The verified login cannot complete a named installation the read does not list, and
        // while GitHub holds its request to install the App, an owner's approval is the next step.
        let listed = installations(session)
            .iter()
            .any(|installation| installation.provider_installation_id == named);
        if !listed && !pending_request_accounts(session).is_empty() {
            return refuse(SetupObstacle::AwaitingApproval);
        }
        return Move::Complete(named);
    }
    // A binding held unverified stays a candidate: completing it verifies it.
    let candidates: Vec<&str> = installations(session)
        .iter()
        .filter(|installation| {
            !(installation.held_by_organization
                && held_verified.contains(installation.provider_installation_id.as_str()))
        })
        .map(|installation| installation.provider_installation_id.as_str())
        .collect();
    match candidates.as_slice() {
        [installation] => Move::Complete(installation),
        [] if !pending_request_accounts(session).is_empty() => {
            refuse(SetupObstacle::AwaitingApproval)
        }
        // A completed session no longer changes, so nothing is left to wait for.
        [] if session.state == GitHubSetupState::Completed => {
            refuse(SetupObstacle::InstallationMissing)
        }
        // The App may still be installed, and its origin record then lists the installation;
        // while GitHub has not answered for requests, they may yet be read.
        [] => Move::Wait,
        _ => Move::Refuse(SetupRefusal::InstallationChoiceRequired, candidates),
    }
}
