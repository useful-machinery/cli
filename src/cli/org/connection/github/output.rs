use std::io::{self, Write};

use anyhow::Context;
use serde::Serialize;

use super::super::authorization::InForce;
use super::setup::{self, SetupObstacle, SetupRefusal, SetupStanding};
use crate::exit_code::{ExitCode, OutcomeClass};
use useful_api::{
    GitHubAccountType, GitHubFailure, GitHubInstallation, GitHubInstallationState,
    GitHubRepository, GitHubRepositoryList, GitHubSetupSession, GitHubSetupState,
    GitHubSetupVerificationState,
};

#[derive(Clone, Copy)]
pub(super) enum InstallationAction {
    SetupCompleted,
    Disconnected,
}

#[derive(Clone, Copy)]
enum FailureAction {
    BeginSetup,
    ShowSetup,
    CompleteSetup,
    ListInstallations,
    DisconnectInstallation,
    ListRepositories,
    /// The refusal of `reconnect` for a binding GitHub revoked.
    Reconnect,
}

/// The refusal of a begin of a setup session, as the guided setup reports it.
pub(super) fn write_begin_failure(
    deployment: &str,
    organization: &str,
    failure: &GitHubFailure,
    authentication: super::super::super::super::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    write_failure(
        deployment,
        organization,
        failure,
        FailureAction::BeginSetup,
        authentication,
        json,
    )
}

/// The command that runs the guided setup in `organization` again, naming `installation` where
/// one is named.
pub(super) fn connect_command(organization: &str, installation: Option<&str>) -> String {
    let installation = installation.map_or_else(String::new, |installation| {
        format!(" --installation {installation}")
    });
    format!("useful org integration connect github{installation} --org {organization}")
}

/// The command that renews the binding `binding` of `organization`.
pub(super) fn reconnect_command(organization: &str, binding: &str) -> String {
    format!("useful org integration reconnect {binding} --org {organization}")
}

/// The command that shows the setup session `session` of `organization`.
fn show_command(organization: &str, session: &str) -> String {
    format!("useful org integration show {session} --org {organization}")
}

/// Where a person goes from a session begun: the GitHub App installation URL, the authorization
/// URL and the command that shows the session; with `then`, the command to run once the App is
/// installed, which asks for the proof again on a session of its own.
fn write_setup_handoff(
    output: &mut impl Write,
    organization: &str,
    session: &GitHubSetupSession,
    then: Option<&str>,
) -> io::Result<()> {
    writeln!(
        output,
        "Open this URL in a browser to install the GitHub App and approve the repositories, or to ask an owner of the GitHub account for it:\n  {}\n",
        session.setup_url
    )?;
    writeln!(
        output,
        "The Useful Machinery page GitHub returns to shows the installation ID.\n"
    )?;
    if let Some(authorization_url) = &session.authorization_url {
        writeln!(
            output,
            "Open this URL in a browser to prove which GitHub account you are, then confirm on the page it leads to:\n  {authorization_url}\n"
        )?;
    }
    writeln!(
        output,
        "Show where the verification stands:\n  {}",
        show_command(organization, &session.id)
    )?;
    if let Some(then) = then {
        writeln!(
            output,
            "\nNothing waits to complete this session. Once the App is installed, run this, which asks for the proof again on a session of its own:\n  {then}"
        )?;
    }
    Ok(())
}

/// Reports the guided setup's session as it begins: the organization's installations from
/// `listed`, each with whether its authority was verified, and the session, its URLs and the
/// command that shows it; with `then`, the command to run once the App is installed, since
/// nothing waits to complete the session, and otherwise that the command now waits for the
/// verification. `--json` prints one document with outcome `pending`.
pub(super) fn write_guided_pending(
    deployment: &str,
    organization: &str,
    listed: &[GitHubInstallation],
    session: &GitHubSetupSession,
    then: Option<&str>,
    json: bool,
) -> anyhow::Result<ExitCode> {
    if json {
        write_json(&GuidedPendingResult {
            schema_version: 1,
            deployment,
            organization_ref: organization,
            outcome: "pending",
            installations: listed,
            session,
        })?;
        return Ok(ExitCode::Success);
    }
    let mut output = io::stdout().lock();
    writeln!(output, "✓ GitHub setup started.\n")?;
    for installation in listed {
        write_installation_row(&mut output, installation)?;
    }
    if listed.is_empty() {
        writeln!(output, "  Installations: none")?;
    }
    writeln!(output, "  Organization:  {organization}")?;
    writeln!(output, "  Setup session: {}", session.id)?;
    writeln!(output, "  Expires:       {}", session.expires_at)?;
    writeln!(output, "  Deployment:    {deployment}\n")?;
    write_setup_handoff(&mut output, organization, session, then)?;
    if then.is_none() {
        writeln!(
            output,
            "\nWaiting for the verification at GitHub; setup completes once it is verified.\n"
        )?;
    }
    output.flush()?;
    Ok(ExitCode::Success)
}

/// Reports the guided setup stopped by its `--timeout` or a signal: `outcome` with the
/// session, where one began, the command that shows it and `again`, the command that runs
/// the setup again.
pub(super) fn write_guided_stopped(
    deployment: &str,
    organization: &str,
    outcome: &str,
    session: Option<&str>,
    again: &str,
    json: bool,
) -> anyhow::Result<()> {
    if json {
        return write_json(&GuidedStoppedResult {
            schema_version: 1,
            deployment,
            organization_ref: organization,
            outcome,
            session_id: session,
        });
    }
    let mut output = io::stderr().lock();
    writeln!(output, "error: GitHub setup {}", outcome.replace('_', " "))?;
    if let Some(session) = session {
        writeln!(
            output,
            "  Setup session: {session}\n\nShow where the verification stands:\n  {}",
            show_command(organization, session)
        )?;
    }
    writeln!(output, "\nRun the setup again:\n  {again}")?;
    Ok(())
}

/// Reports a setup session read: its state, its verification and what the verification
/// carries, then the next step for where it stands.
pub(super) fn write_setup_show(
    deployment: &str,
    organization: &str,
    result: &Result<GitHubSetupSession, GitHubFailure>,
    authentication: super::super::super::super::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    match result {
        Ok(session) => {
            if json {
                write_json(&SetupResult {
                    schema_version: 1,
                    deployment,
                    organization_ref: organization,
                    outcome: "shown",
                    session,
                })?;
            } else {
                let mut output = io::stdout().lock();
                writeln!(output, "✓ GitHub setup session read.\n")?;
                writeln!(output, "  Organization:  {organization}")?;
                write_setup_session_fields(&mut output, session)?;
                writeln!(output, "  Deployment:    {deployment}\n")?;
                write_setup_next_step(
                    &mut output,
                    SetupStanding::of(session),
                    organization,
                    session,
                    &Steps::new(
                        connect_command(organization, None),
                        setup::installations(session)
                            .iter()
                            .map(|installation| installation.provider_installation_id.as_str())
                            .collect(),
                    ),
                )?;
            }
            Ok(ExitCode::Success)
        }
        Err(failure) => write_failure(
            deployment,
            organization,
            failure,
            FailureAction::ShowSetup,
            authentication,
            json,
        ),
    }
}

/// The commands a next step names.
pub(super) struct Steps<'a> {
    /// The command that runs the setup again, which also begins it again.
    again: String,
    /// The GitHub installation IDs a completion chooses among.
    choices: Vec<&'a str>,
}

impl<'a> Steps<'a> {
    /// The steps whose command `again` runs the setup again, the choice among `choices`.
    pub(super) const fn new(again: String, choices: Vec<&'a str>) -> Self {
        Self { again, choices }
    }
}

/// Writes the next step for where `session` stands, naming the commands of `steps`.
fn write_setup_next_step(
    output: &mut impl Write,
    standing: SetupStanding,
    organization: &str,
    session: &GitHubSetupSession,
    steps: &Steps<'_>,
) -> io::Result<()> {
    let Steps { again, choices } = steps;
    let login = session
        .verification
        .github_login
        .as_deref()
        .unwrap_or("The verified GitHub login");
    match standing {
        SetupStanding::Completed => writeln!(
            output,
            "List the organization's connections:\n  useful org integration list --org {organization}"
        ),
        SetupStanding::Completable => {
            writeln!(
                output,
                "A command waiting on this session completes it by itself. Otherwise connect an installation:"
            )?;
            for installation in choices {
                writeln!(
                    output,
                    "  {}",
                    connect_command(organization, Some(installation))
                )?;
            }
            Ok(())
        }
        SetupStanding::Blocked(SetupObstacle::Expired) => writeln!(
            output,
            "The setup session expired. Run the setup again:\n  {again}"
        ),
        SetupStanding::Blocked(SetupObstacle::VerificationRequired) => {
            match &session.authorization_url {
                Some(authorization_url) => writeln!(
                    output,
                    "A command waiting on this session completes it once you open this URL in a browser, prove which GitHub account you are and confirm on the page it leads to:\n  {authorization_url}\nIf no command is waiting, run the setup again, which asks for the proof on a session of its own:\n  {again}"
                ),
                None => writeln!(
                    output,
                    "A command waiting on this session completes it once you confirm which GitHub account you are on the Useful Machinery page the authorization URL opened. If no command is waiting, run the setup again, which asks for the proof on a session of its own:\n  {again}"
                ),
            }
        }
        SetupStanding::Blocked(SetupObstacle::ConsentDenied) => writeln!(
            output,
            "GitHub's authorization was refused. Run the setup again and approve it:\n  {again}"
        ),
        SetupStanding::Blocked(SetupObstacle::VerificationFailed) => writeln!(
            output,
            "The verification failed. Run the setup again:\n  {again}"
        ),
        SetupStanding::Blocked(SetupObstacle::AuthorityUnproven) => writeln!(
            output,
            "{login} proved no authority over that installation at GitHub. An administrator of the GitHub account that holds it completes GitHub setup with:\n  {again}"
        ),
        SetupStanding::Blocked(SetupObstacle::AwaitingApproval) => writeln!(
            output,
            "GitHub holds {login}'s request to install the App on {}. An owner of that account approves the request at GitHub. Then run the setup again:\n  {again}",
            setup::pending_request_accounts(session).join(", ")
        ),
        SetupStanding::Blocked(SetupObstacle::InstallationMissing) => writeln!(
            output,
            "{login} could complete no GitHub App installation. Install the App on an account {login} administers:\n  {}\nThen run:\n  {again}",
            session.setup_url
        ),
    }
}

fn write_setup_session_fields(
    output: &mut impl Write,
    session: &GitHubSetupSession,
) -> io::Result<()> {
    let verification = &session.verification;
    writeln!(output, "  Setup session: {}", session.id)?;
    writeln!(output, "  State:         {}", setup_state(session.state))?;
    writeln!(output, "  Expires:       {}", session.expires_at)?;
    writeln!(
        output,
        "  Verification:  {}",
        verification_state(verification.state)
    )?;
    if let Some(login) = &verification.github_login {
        writeln!(output, "  GitHub login:  {login}")?;
    }
    for installation in verification.installations.iter().flatten() {
        writeln!(
            output,
            "  Installation:  {}  Account: {} ({})  Held by this organization: {}",
            installation.provider_installation_id,
            installation.provider_account_login,
            account_type(installation.provider_account_type),
            if installation.held_by_organization {
                "yes"
            } else {
                "no"
            },
        )?;
    }
    match &verification.pending_requests {
        Some(requests) if !requests.read => {
            writeln!(output, "  Pending requests: GitHub did not answer")?;
        }
        Some(requests) => {
            for request in &requests.items {
                writeln!(
                    output,
                    "  Pending request: {} ({})",
                    request.provider_account_login,
                    account_type(request.provider_account_type),
                )?;
            }
        }
        None => {}
    }
    Ok(())
}

/// Reports why the guided setup did not complete: the outcome with the session as `show
/// ghs_SESSION` prints it, or on standard error what stopped it and its next step, naming the
/// commands of `steps`.
pub(super) fn write_setup_refusal(
    deployment: &str,
    organization: &str,
    session: &GitHubSetupSession,
    refusal: SetupRefusal,
    steps: &Steps<'_>,
    json: bool,
) -> anyhow::Result<ExitCode> {
    if json {
        write_json(&SetupResult {
            schema_version: 1,
            deployment,
            organization_ref: organization,
            outcome: refusal.outcome(),
            session,
        })?;
    } else {
        let mut output = io::stderr().lock();
        let (heading, standing) = match refusal {
            SetupRefusal::InstallationChoiceRequired => (
                "the GitHub setup session could complete several installations",
                SetupStanding::Completable,
            ),
            SetupRefusal::Blocked(obstacle) => {
                (obstacle_heading(obstacle), SetupStanding::Blocked(obstacle))
            }
        };
        writeln!(output, "error: {heading}\n")?;
        write_setup_next_step(&mut output, standing, organization, session, steps)?;
    }
    Ok(refusal.exit_code())
}

const fn obstacle_heading(obstacle: SetupObstacle) -> &'static str {
    match obstacle {
        SetupObstacle::Expired => "the GitHub setup session expired",
        SetupObstacle::VerificationRequired => "the GitHub setup session is not verified yet",
        SetupObstacle::ConsentDenied => "GitHub's authorization was refused",
        SetupObstacle::VerificationFailed => "the GitHub setup verification failed",
        SetupObstacle::AuthorityUnproven => {
            "the verified GitHub login has no authority over the installation"
        }
        SetupObstacle::AwaitingApproval => {
            "GitHub holds a request to install the App that no owner has approved"
        }
        SetupObstacle::InstallationMissing => {
            "the verified GitHub login could complete no installation"
        }
    }
}

/// One installation binding as the guided setup lists it, with whether its authority was
/// verified.
fn write_installation_row(
    output: &mut impl Write,
    installation: &GitHubInstallation,
) -> io::Result<()> {
    writeln!(
        output,
        "  Installation: {}  State: {}  Account: {} ({}, {})  Provider installation: {}  Authority: {}",
        installation.id,
        installation_state(installation.state),
        installation.provider_account_login,
        account_type(installation.provider_account_type),
        installation.provider_account_id,
        installation.provider_installation_id,
        authority(installation),
    )
}

/// When Cloud verified the organization's authority over `installation`, or that it has
/// not.
pub(in crate::cli) fn authority(installation: &GitHubInstallation) -> String {
    installation
        .authority_verified_at
        .as_ref()
        .map_or_else(|| "not verified".to_owned(), |at| format!("verified {at}"))
}

/// The refusal of `reconnect` for a binding GitHub revoked: outcome `source_connection_conflict`,
/// written before any session is begun.
pub(super) fn write_revoked(
    deployment: &str,
    organization: &str,
    authentication: super::super::super::super::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    write_failure(
        deployment,
        organization,
        &GitHubFailure::SourceConnectionConflict,
        FailureAction::Reconnect,
        authentication,
        json,
    )
}

/// The failure of a read of the organization's installation bindings, as `useful org integration
/// list` ends with it.
pub(in crate::cli) fn write_list_failure(
    deployment: &str,
    organization: &str,
    failure: &GitHubFailure,
    authentication: super::super::super::super::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    write_failure(
        deployment,
        organization,
        failure,
        FailureAction::ListInstallations,
        authentication,
        json,
    )
}

pub(super) fn write_installation(
    deployment: &str,
    organization: &str,
    result: &Result<GitHubInstallation, GitHubFailure>,
    action: InstallationAction,
    authentication: super::super::super::super::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    match result {
        Ok(installation) => {
            let (outcome, heading) = match action {
                InstallationAction::SetupCompleted => ("completed", "✓ GitHub setup completed."),
                InstallationAction::Disconnected => {
                    ("disconnected", "✓ GitHub installation disconnected.")
                }
            };
            if json {
                write_json(&InstallationResult {
                    schema_version: 1,
                    deployment,
                    organization_ref: organization,
                    outcome,
                    installation,
                })?;
            } else {
                let mut output = io::stdout().lock();
                writeln!(output, "{heading}\n")?;
                write_installation_fields(&mut output, installation)?;
                writeln!(output, "  Organization:          {organization}")?;
                writeln!(output, "  Deployment:            {deployment}")?;
            }
            Ok(ExitCode::Success)
        }
        Err(failure) => write_failure(
            deployment,
            organization,
            failure,
            match action {
                InstallationAction::SetupCompleted => FailureAction::CompleteSetup,
                InstallationAction::Disconnected => FailureAction::DisconnectInstallation,
            },
            authentication,
            json,
        ),
    }
}

pub(super) fn write_repository_list(
    deployment: &str,
    organization: &str,
    result: &Result<GitHubRepositoryList, GitHubFailure>,
    authentication: super::super::super::super::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    match result {
        Ok(page) => {
            if json {
                write_json(&RepositoryListResult {
                    schema_version: 1,
                    deployment,
                    organization_ref: organization,
                    outcome: "listed",
                    installation: &page.installation,
                    items: &page.items,
                })?;
            } else {
                write_repositories_human(deployment, organization, page)?;
            }
            Ok(ExitCode::Success)
        }
        Err(failure) => write_failure(
            deployment,
            organization,
            failure,
            FailureAction::ListRepositories,
            authentication,
            json,
        ),
    }
}

/// A binding as `useful org integration show` prints it, with the repositories it grants when it
/// is active and `repositories` therefore were read.
pub(super) fn write_installation_shown(
    deployment: &str,
    organization: &str,
    installation: &GitHubInstallation,
    repositories: Option<&[GitHubRepository]>,
    authorizations: Option<&InForce>,
    json: bool,
) -> anyhow::Result<ExitCode> {
    if json {
        write_json(&ShownResult {
            schema_version: 1,
            deployment,
            organization_ref: organization,
            outcome: "shown",
            installation,
            items: repositories,
            authorizations,
        })?;
        return Ok(ExitCode::Success);
    }
    let mut output = io::stdout().lock();
    writeln!(output, "✓ GitHub installation shown.\n")?;
    write_installation_fields(&mut output, installation)?;
    writeln!(output, "  Organization:          {organization}")?;
    writeln!(output, "  Deployment:            {deployment}")?;
    match repositories {
        Some(repositories) if !repositories.is_empty() => {
            writeln!(output)?;
            for repository in repositories {
                write_repository_row(&mut output, repository)?;
            }
        }
        Some(_) => {}
        None => writeln!(
            output,
            "\nIts repositories cannot be read while the installation is {}.",
            installation_state(installation.state)
        )?,
    }
    if let Some(authorizations) = authorizations {
        authorizations.write_human(&mut output, "")?;
    }
    Ok(ExitCode::Success)
}

fn write_installation_fields(
    output: &mut impl Write,
    installation: &GitHubInstallation,
) -> anyhow::Result<()> {
    writeln!(output, "  Installation:          {}", installation.id)?;
    writeln!(
        output,
        "  Provider installation: {}",
        installation.provider_installation_id
    )?;
    writeln!(
        output,
        "  Provider account:      {} ({}, {})",
        installation.provider_account_login,
        account_type(installation.provider_account_type),
        installation.provider_account_id
    )?;
    writeln!(
        output,
        "  State:                 {}",
        installation_state(installation.state)
    )?;
    writeln!(
        output,
        "  Created:               {}",
        installation.created_at
    )?;
    writeln!(
        output,
        "  Updated:               {}",
        installation.updated_at
    )?;
    writeln!(
        output,
        "  Authority:             {}",
        authority(installation)
    )?;
    Ok(())
}

fn write_repositories_human(
    deployment: &str,
    organization: &str,
    page: &GitHubRepositoryList,
) -> anyhow::Result<()> {
    let mut output = io::stdout().lock();
    writeln!(output, "✓ GitHub repositories listed.\n")?;
    for repository in &page.items {
        write_repository_row(&mut output, repository)?;
    }
    if !page.items.is_empty() {
        writeln!(output)?;
    }
    writeln!(output, "  Installation: {}", page.installation.id)?;
    writeln!(output, "  Organization: {organization}")?;
    writeln!(output, "  Deployment:   {deployment}")?;
    Ok(())
}

fn write_repository_row(
    output: &mut impl Write,
    repository: &GitHubRepository,
) -> anyhow::Result<()> {
    writeln!(
        output,
        "  Repository: {}  Provider repository: {}  Default branch: {}",
        repository.full_name, repository.provider_repository_id, repository.default_branch
    )?;
    Ok(())
}

fn write_failure(
    deployment: &str,
    organization: &str,
    failure: &GitHubFailure,
    action: FailureAction,
    authentication: super::super::super::super::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let (category, human, class) = match failure {
        GitHubFailure::Unauthenticated => (
            None,
            authentication
                .rejected_error(
                    "error: GitHub connection management requires sign-in\n\nSign in first:\n  useful account login",
                )
                .to_owned(),
            OutcomeClass::Unauthenticated,
        ),
        GitHubFailure::Forbidden => (
            None,
            "error: GitHub connection operation is not permitted for this account\n\nAsk an active organization owner to perform this operation.".to_owned(),
            OutcomeClass::Forbidden,
        ),
        GitHubFailure::InvalidInput => (
            None,
            format!(
                "error: GitHub connection input rejected by {deployment}\n\n{}",
                action.invalid_input_remedy()
            ),
            OutcomeClass::GeneralFailure,
        ),
        GitHubFailure::NotFound => (
            None,
            "error: GitHub connection not found or unavailable\n\nCheck the organization and connection identifiers, then try again.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        GitHubFailure::SourceConnectionConflict => (
            None,
            action.conflict_message().to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        // A completion reports this refusal from a read of the session; this is its report where
        // no read follows.
        GitHubFailure::AuthorityUnproven => (
            None,
            "error: the verified GitHub login has no authority over the installation\n\nAn administrator of the GitHub account that holds it completes GitHub setup.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        GitHubFailure::RateLimited { .. } => (
            None,
            format!(
                "error: GitHub connection API at {deployment} is limiting requests\n\nWait a moment, then try again."
            ),
            OutcomeClass::RateLimited,
        ),
        GitHubFailure::Unreachable(category) => (
            Some(category.as_str()),
            format!(
                "error: contact GitHub connection API at {deployment}: {}\n\nCheck network access to the deployment and try again.",
                category.as_str()
            ),
            super::super::super::super::unreachable_outcome_class(*category),
        ),
        GitHubFailure::Protocol { .. } => (
            None,
            "error: GitHub connection API response does not match the public contract\n\nTry again later.".to_owned(),
            OutcomeClass::Protocol,
        ),
    };
    if json {
        write_json(&FailureResult {
            schema_version: 1,
            deployment,
            organization_ref: organization,
            outcome: failure_outcome(failure),
            category,
            retry_after: match failure {
                GitHubFailure::RateLimited { retry_after } => *retry_after,
                _ => None,
            },
        })?;
    } else {
        writeln!(io::stderr().lock(), "{human}")?;
    }
    Ok(class.exit_code())
}

/// The outcome a failure is reported under.
const fn failure_outcome(failure: &GitHubFailure) -> &'static str {
    match failure {
        GitHubFailure::Unauthenticated => "unauthenticated",
        GitHubFailure::Forbidden => "forbidden",
        GitHubFailure::InvalidInput => "invalid_input",
        GitHubFailure::NotFound => "not_found",
        GitHubFailure::SourceConnectionConflict => "source_connection_conflict",
        GitHubFailure::AuthorityUnproven => "authority_unproven",
        GitHubFailure::RateLimited { .. } => "rate_limited",
        GitHubFailure::Unreachable(_) => "unreachable",
        GitHubFailure::Protocol { .. } => "invalid_response",
    }
}

impl FailureAction {
    const fn invalid_input_remedy(self) -> &'static str {
        match self {
            Self::BeginSetup | Self::ListInstallations | Self::Reconnect => {
                "Check the organization reference, then try again."
            }
            Self::ShowSetup => "Check the organization and setup session, then try again.",
            Self::CompleteSetup => {
                "Check the organization and the decimal installation ID, then try again."
            }
            Self::DisconnectInstallation | Self::ListRepositories => {
                "Check the organization and installation binding ID, then try again."
            }
        }
    }

    const fn conflict_message(self) -> &'static str {
        match self {
            Self::CompleteSetup => {
                "error: GitHub setup conflicts with the current source connection\n\nCheck that the GitHub installation belongs to this organization and is not suspended on GitHub. List the organization's connections:\n  useful org integration list\nTo start over, install the GitHub App again:\n  useful org integration connect github"
            }
            Self::DisconnectInstallation => {
                "error: GitHub installation is unavailable for disconnection\n\nList the organization's connections:\n  useful org integration list\nReconnect a disconnected binding with useful org integration reconnect INTEGRATION; a revoked installation requires useful org integration connect github."
            }
            Self::ListRepositories => {
                "error: GitHub installation is unavailable for repository discovery\n\nList the organization's connections:\n  useful org integration list\nReconnect a disconnected binding with useful org integration reconnect INTEGRATION; a revoked installation requires useful org integration connect github."
            }
            Self::Reconnect => {
                "error: GitHub removed the installation of this binding\n\nA revoked binding cannot be reconnected. Make a new connection:\n  useful org integration connect github\nThen bind each project bound through the old connection to a repository again:\n  useful project update PROJECT --repository REPOSITORY"
            }
            Self::BeginSetup | Self::ShowSetup | Self::ListInstallations => {
                "error: GitHub connection state conflicts with this operation\n\nList installation bindings and begin a new setup session if needed."
            }
        }
    }
}

const fn account_type(account_type: GitHubAccountType) -> &'static str {
    match account_type {
        GitHubAccountType::Organization => "organization",
        GitHubAccountType::User => "user",
    }
}

const fn setup_state(state: GitHubSetupState) -> &'static str {
    match state {
        GitHubSetupState::Pending => "pending",
        GitHubSetupState::Completed => "completed",
        GitHubSetupState::Expired => "expired",
    }
}

const fn verification_state(state: GitHubSetupVerificationState) -> &'static str {
    match state {
        GitHubSetupVerificationState::Unverified => "unverified",
        GitHubSetupVerificationState::Verified => "verified",
        GitHubSetupVerificationState::Denied => "denied",
        GitHubSetupVerificationState::Failed => "failed",
    }
}

pub(in crate::cli) const fn installation_state(state: GitHubInstallationState) -> &'static str {
    match state {
        GitHubInstallationState::Active => "active",
        GitHubInstallationState::Disconnected => "disconnected",
        GitHubInstallationState::Revoked => "revoked",
    }
}

fn write_json(value: &impl Serialize) -> anyhow::Result<()> {
    super::super::super::super::write_json_line(value)
        .context("write JSON GitHub connection result")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetupResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    organization_ref: &'a str,
    outcome: &'static str,
    session: &'a GitHubSetupSession,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallationResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    organization_ref: &'a str,
    outcome: &'static str,
    installation: &'a GitHubInstallation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RepositoryListResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    organization_ref: &'a str,
    outcome: &'static str,
    installation: &'a GitHubInstallation,
    items: &'a [GitHubRepository],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FailureResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    organization_ref: &'a str,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GuidedPendingResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    organization_ref: &'a str,
    outcome: &'static str,
    installations: &'a [GitHubInstallation],
    session: &'a GitHubSetupSession,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GuidedStoppedResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    organization_ref: &'a str,
    outcome: &'a str,
    session_id: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ShownResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    organization_ref: &'a str,
    outcome: &'static str,
    installation: &'a GitHubInstallation,
    #[serde(skip_serializing_if = "Option::is_none")]
    items: Option<&'a [GitHubRepository]>,
    // The runners' authorizations in force for the installation, where they were
    // read.
    #[serde(skip_serializing_if = "Option::is_none")]
    authorizations: Option<&'a InForce>,
}
