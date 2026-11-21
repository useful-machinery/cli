use std::io::{self, Write};

use anyhow::Context;
use serde::Serialize;

use super::super::authorization::InForce;
use crate::exit_code::{ExitCode, OutcomeClass};
use useful_api::{
    GitHubAccountType, GitHubFailure, GitHubInstallation, GitHubInstallationState,
    GitHubRepository, GitHubRepositoryList, GitHubSetupSession,
};

#[derive(Clone, Copy)]
pub(super) enum InstallationAction {
    SetupCompleted,
    Disconnected,
}

#[derive(Clone, Copy)]
enum FailureAction {
    BeginSetup,
    CompleteSetup,
    ListInstallations,
    DisconnectInstallation,
    ListRepositories,
    /// The refusal of `reconnect` for a binding GitHub revoked.
    Reconnect,
}

pub(super) fn write_setup_begin(
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
                    outcome: "pending",
                    session,
                })?;
            } else {
                let mut output = io::stdout().lock();
                writeln!(output, "✓ GitHub setup started.\n")?;
                writeln!(output, "  Organization: {organization}")?;
                writeln!(output, "  Expires:      {}", session.expires_at)?;
                writeln!(output, "  Deployment:   {deployment}\n")?;
                writeln!(
                    output,
                    "Open this URL in a browser and approve the repositories:\n  {}",
                    session.setup_url
                )?;
                writeln!(
                    output,
                    "\nThe Useful Machinery page GitHub returns to shows the installation ID.\nThen run this command with that installation ID:\n  useful org integration connect github --installation <INSTALLATION_ID> --org {organization}"
                )?;
            }
            Ok(ExitCode::Success)
        }
        Err(failure) => write_failure(
            deployment,
            organization,
            failure,
            FailureAction::BeginSetup,
            authentication,
            json,
        ),
    }
}

/// The refusal of `reconnect` for a binding GitHub revoked: outcome `source_connection_conflict`,
/// written before any session is begun (REQ-CONNECTION-108).
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
    let (outcome, category, human, class) = match failure {
        GitHubFailure::Unauthenticated => (
            "unauthenticated",
            None,
            authentication
                .rejected_error(
                    "error: GitHub connection management requires sign-in\n\nSign in first:\n  useful account login",
                )
                .to_owned(),
            OutcomeClass::Unauthenticated,
        ),
        GitHubFailure::Forbidden => (
            "forbidden",
            None,
            "error: GitHub connection operation is not permitted for this account\n\nAsk an active organization owner to perform this operation.".to_owned(),
            OutcomeClass::Forbidden,
        ),
        GitHubFailure::InvalidInput => (
            "invalid_input",
            None,
            format!(
                "error: GitHub connection input rejected by {deployment}\n\n{}",
                action.invalid_input_remedy()
            ),
            OutcomeClass::GeneralFailure,
        ),
        GitHubFailure::NotFound => (
            "not_found",
            None,
            "error: GitHub connection not found or unavailable\n\nCheck the organization and connection identifiers, then try again.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        GitHubFailure::SourceConnectionConflict => (
            "source_connection_conflict",
            None,
            action.conflict_message().to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        GitHubFailure::Unreachable(category) => (
            "unreachable",
            Some(category.as_str()),
            format!(
                "error: contact GitHub connection API at {deployment}: {}\n\nCheck network access to the deployment and try again.",
                category.as_str()
            ),
            super::super::super::super::unreachable_outcome_class(*category),
        ),
        GitHubFailure::Protocol { .. } => (
            "invalid_response",
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
            outcome,
            category,
        })?;
    } else {
        writeln!(io::stderr().lock(), "{human}")?;
    }
    Ok(class.exit_code())
}

impl FailureAction {
    const fn invalid_input_remedy(self) -> &'static str {
        match self {
            Self::BeginSetup | Self::ListInstallations | Self::Reconnect => {
                "Check the organization reference, then try again."
            }
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
            Self::BeginSetup | Self::ListInstallations => {
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
    // The runners' authorizations in force for the installation, where they were read
    // (REQ-INTEGRATION-34).
    #[serde(skip_serializing_if = "Option::is_none")]
    authorizations: Option<&'a InForce>,
}
