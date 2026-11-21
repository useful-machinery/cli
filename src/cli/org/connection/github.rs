//! GitHub through `useful org integration`: the setup sessions `create github` and `reconnect`
//! complete, and the reads and removal of an installation binding.
mod output;

pub(in crate::cli) use output::{installation_state, write_list_failure};

use super::authorization::InForce;
use anyhow::{Context, anyhow};

use crate::cli::{CommonArgs, JsonOutputKind, PrincipalAuthenticationArgs};
use crate::exit_code::ExitCode;
use useful_api::{
    GitHubApi, GitHubFailure, GitHubInstallation, GitHubInstallationState, HttpClient,
    HttpTransportPolicy,
};
use useful_human_auth::Deployment;

use super::list::Record;
use super::target::Resolved;

/// The value of `create github --installation`: a decimal GitHub installation ID, checked
/// before any request.
pub(super) fn installation_id(value: &str) -> Result<String, String> {
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(value.to_owned())
    } else {
        Err("installation must be a decimal GitHub installation ID".to_owned())
    }
}

/// Begins a setup session in `organization` and prints the page to open and the command to run
/// once GitHub has installed the App (REQ-CONNECTION-17).
pub(super) fn begin<F: JsonOutputKind>(
    deployment: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
) -> anyhow::Result<ExitCode> {
    let result = with_api(
        deployment,
        options.http.transport_policy(),
        &options.authentication,
        |api| api.begin_setup(organization),
    )?;
    output::write_setup_begin(
        deployment.fingerprint().api_url(),
        organization,
        &result,
        options.authentication.kind(),
        options.json,
    )
}

/// Begins a setup session of its own in `organization` and completes it at once for the GitHub
/// installation `provider_installation_id`, so nothing is carried over from an earlier
/// invocation (REQ-CONNECTION-17, REQ-CONNECTION-19).
pub(super) fn complete<F: JsonOutputKind>(
    deployment: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    provider_installation_id: &str,
) -> anyhow::Result<ExitCode> {
    complete_for(
        deployment,
        options,
        organization,
        provider_installation_id,
        None,
    )
}

/// Renews the binding `resolved` names by completing a new setup session for its own
/// installation, which keeps its ID; a binding GitHub revoked is refused before any session is
/// begun (REQ-CONNECTION-108).
pub(super) fn reconnect<F: JsonOutputKind>(
    deployment: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    resolved: Resolved,
) -> anyhow::Result<ExitCode> {
    let installation = match resolved {
        Resolved::Listed(Record::Github(installation)) => installation,
        resolved => match find_binding(deployment, options, organization, resolved.id())? {
            Ok(installation) => installation,
            Err(failure) => {
                return write_list_failure(
                    deployment.fingerprint().api_url(),
                    organization,
                    &failure,
                    options.authentication.kind(),
                    options.json,
                );
            }
        },
    };
    if matches!(installation.state, GitHubInstallationState::Revoked) {
        return output::write_revoked(
            deployment.fingerprint().api_url(),
            organization,
            options.authentication.kind(),
            options.json,
        );
    }
    complete_for(
        deployment,
        options,
        organization,
        &installation.provider_installation_id,
        Some(&installation.id),
    )
}

/// Begins a setup session and completes it for `provider_installation_id`. When `binding` is
/// given, a completion that names another binding is a protocol failure, since a reconnection
/// never makes a new connection.
fn complete_for<F: JsonOutputKind>(
    deployment: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    provider_installation_id: &str,
    binding: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let api_url = deployment.fingerprint().api_url();
    let policy = options.http.transport_policy();
    let session = match with_api(deployment, policy, &options.authentication, |api| {
        api.begin_setup(organization)
    })? {
        Ok(session) => session,
        failed @ Err(_) => {
            return output::write_setup_begin(
                api_url,
                organization,
                &failed,
                options.authentication.kind(),
                options.json,
            );
        }
    };
    let result = with_api(deployment, policy, &options.authentication, |api| {
        api.complete_setup(organization, &session.id, provider_installation_id)
    })?
    .and_then(|installation| match binding {
        Some(binding) if installation.id != binding => Err(GitHubFailure::Protocol {
            credential_rejected: false,
        }),
        _ => Ok(installation),
    });
    output::write_installation(
        api_url,
        organization,
        &result,
        output::InstallationAction::SetupCompleted,
        options.authentication.kind(),
        options.json,
    )
}

/// Disconnects the binding `id`, repeating the request once after an ambiguous transport
/// failure (REQ-CONNECTION-16, REQ-CONNECTION-19).
pub(super) fn remove(
    deployment: &Deployment,
    options: &super::list::Options,
    organization: &str,
    id: &str,
) -> anyhow::Result<ExitCode> {
    let result = with_api(
        deployment,
        options.http.transport_policy(),
        &options.authentication,
        |api| api.disconnect_installation(organization, id),
    )?;
    output::write_installation(
        deployment.fingerprint().api_url(),
        organization,
        &result,
        output::InstallationAction::Disconnected,
        options.authentication.kind(),
        options.json,
    )
}

/// Lists every repository the installation of the binding `id` grants (REQ-CONNECTION-73).
pub(super) fn list_repositories(
    deployment: &Deployment,
    options: &super::list::Options,
    organization: &str,
    id: &str,
) -> anyhow::Result<ExitCode> {
    let result = with_api(
        deployment,
        options.http.transport_policy(),
        &options.authentication,
        |api| api.list_repositories(organization, id),
    )?;
    output::write_repository_list(
        deployment.fingerprint().api_url(),
        organization,
        &result,
        options.authentication.kind(),
        options.json,
    )
}

/// Shows the binding `id` as the organization's list of bindings holds it, since the route
/// reads no single binding; an ID the list does not hold is not found (REQ-CONNECTION-105).
pub(super) fn show_binding(
    deployment: &Deployment,
    options: &super::list::Options,
    organization: &str,
    id: &str,
    authorizations: Option<&InForce>,
) -> anyhow::Result<ExitCode> {
    match find_binding(deployment, options, organization, id)? {
        Ok(installation) => show_installation(
            deployment,
            options,
            organization,
            installation,
            authorizations,
        ),
        Err(failure) => write_list_failure(
            deployment.fingerprint().api_url(),
            organization,
            &failure,
            options.authentication.kind(),
            options.json,
        ),
    }
}

/// The binding `id` as the organization's list of bindings holds it; an ID the list does not
/// hold is not found.
fn find_binding<F: JsonOutputKind>(
    deployment: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    id: &str,
) -> anyhow::Result<Result<GitHubInstallation, GitHubFailure>> {
    Ok(with_api(
        deployment,
        options.http.transport_policy(),
        &options.authentication,
        |api| api.list_installations(organization),
    )?
    .and_then(|installations| {
        installations
            .into_iter()
            .find(|installation| installation.id == id)
            .ok_or(GitHubFailure::NotFound)
    }))
}

/// Shows `installation` with, when it is active, the repositories it grants, read from GitHub.
pub(super) fn show_installation(
    deployment: &Deployment,
    options: &super::list::Options,
    organization: &str,
    installation: GitHubInstallation,
    authorizations: Option<&InForce>,
) -> anyhow::Result<ExitCode> {
    let api_url = deployment.fingerprint().api_url();
    let repositories = if matches!(installation.state, GitHubInstallationState::Active) {
        let read = with_api(
            deployment,
            options.http.transport_policy(),
            &options.authentication,
            |api| api.list_repositories(organization, &installation.id),
        )?;
        match read {
            Ok(page) => Some(page.items),
            Err(failure) => {
                return output::write_repository_list(
                    api_url,
                    organization,
                    &Err(failure),
                    options.authentication.kind(),
                    options.json,
                );
            }
        }
    } else {
        None
    };
    output::write_installation_shown(
        api_url,
        organization,
        &installation,
        repositories.as_deref(),
        authorizations,
        options.json,
    )
}

/// Runs `operation` against GitHub's routes under the credential `authentication` selects.
pub(in crate::cli) fn with_api<T>(
    deployment: &Deployment,
    transport_policy: HttpTransportPolicy,
    authentication: &PrincipalAuthenticationArgs,
    mut operation: impl FnMut(&GitHubApi) -> Result<T, GitHubFailure>,
) -> anyhow::Result<Result<T, GitHubFailure>> {
    let session_client = HttpClient::new(transport_policy)
        .map_err(|error| anyhow!(error))
        .context("prepare human session networking")?;
    super::super::super::execute_selected_api_operation(
        super::super::super::principal_api_context(
            &session_client,
            deployment,
            authentication,
            "acquire human session",
        ),
        |access_token| {
            let api = GitHubApi::new(
                deployment.fingerprint().api_url(),
                access_token,
                transport_policy,
            )
            .map_err(|error| anyhow!(error))
            .context("prepare GitHub connection networking")?;
            Ok(operation(&api))
        },
        GitHubFailure::credential_rejected,
        || GitHubFailure::Unauthenticated,
        GitHubFailure::Unreachable,
    )
}
