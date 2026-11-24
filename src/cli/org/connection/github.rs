//! GitHub through `useful org integration`: the guided, verified setup `connect github` and
//! `reconnect` run, a setup session `show ghs_SESSION` reads, and the reads and removal of an
//! installation binding.
mod output;
mod setup;

pub(in crate::cli) use output::{authority, installation_state, write_list_failure};
pub(super) use setup::{Guidance, guide, show as show_setup_session};

use std::time::Duration;

use anyhow::{Context, anyhow};

use super::authorization::InForce;
use super::linear::Options;
use crate::cli::{CommandResult, CommonArgs, JsonOutputKind, PrincipalAuthenticationArgs};
use crate::exit_code::ExitCode;
use useful_api::{
    GitHubApi, GitHubFailure, GitHubInstallation, GitHubInstallationState, HttpClient,
    HttpTransportPolicy,
};
use useful_human_auth::Deployment;

use super::list::Record;
use super::target::Resolved;

/// The value of `connect github --installation`: a decimal GitHub installation ID, checked
/// before any request.
pub(super) fn installation_id(value: &str) -> Result<String, String> {
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(value.to_owned())
    } else {
        Err("installation must be a decimal GitHub installation ID".to_owned())
    }
}

/// Connects the organization at GitHub through the guided, verified setup: with
/// `installation`, `--installation`, that installation whatever the session lists. The binding
/// a completed setup answered is reported already; the status alone is the command's.
pub(super) fn connect(
    deployment: &Deployment,
    options: Options,
    organization: &str,
    installation: Option<&str>,
    (no_wait, timeout): (bool, Option<Duration>),
) -> CommandResult {
    setup::guide(
        deployment,
        options,
        Guidance {
            organization,
            installation,
            binding: None,
            listed: None,
            no_wait,
            timeout,
        },
    )
    .map(|guided| guided.status)
}

/// Renews the binding `resolved` names through the guided setup for its own installation, which
/// keeps its ID, completing it only once the session is verified; a binding GitHub revoked is
/// refused before any session is begun.
pub(super) fn reconnect(
    deployment: &Deployment,
    options: Options,
    organization: &str,
    resolved: Resolved,
    (no_wait, timeout): (bool, Option<Duration>),
) -> CommandResult {
    let (installation, listed) = match resolved {
        Resolved::Listed(Record::Github(installation)) => (installation, None),
        resolved => {
            match list_bindings(deployment, &options, organization)?.and_then(|installations| {
                let installation = held(&installations, resolved.id())?.clone();
                Ok((installation, Some(installations)))
            }) {
                Ok(found) => found,
                Err(failure) => {
                    return Ok(write_list_failure(
                        deployment.fingerprint().api_url(),
                        organization,
                        &failure,
                        options.authentication.kind(),
                        options.json,
                    )?);
                }
            }
        }
    };
    if matches!(installation.state, GitHubInstallationState::Revoked) {
        return Ok(output::write_revoked(
            deployment.fingerprint().api_url(),
            organization,
            options.authentication.kind(),
            options.json,
        )?);
    }
    setup::guide(
        deployment,
        options,
        Guidance {
            organization,
            installation: Some(&installation.provider_installation_id),
            binding: Some(&installation.id),
            listed,
            no_wait,
            timeout,
        },
    )
    .map(|guided| guided.status)
}

/// Disconnects the binding `id`, repeating the request once after an ambiguous transport
/// failure.
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

/// Lists every repository the installation of the binding `id` grants.
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
/// reads no single binding; an ID the list does not hold is not found.
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

/// The organization's list of installation bindings.
fn list_bindings<F: JsonOutputKind>(
    deployment: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
) -> anyhow::Result<Result<Vec<GitHubInstallation>, GitHubFailure>> {
    with_api(
        deployment,
        options.http.transport_policy(),
        &options.authentication,
        |api| api.list_installations(organization),
    )
}

/// The binding `id` as `installations`, the organization's list, holds it; an ID the list does
/// not hold is not found.
fn held<'a>(
    installations: &'a [GitHubInstallation],
    id: &str,
) -> Result<&'a GitHubInstallation, GitHubFailure> {
    installations
        .iter()
        .find(|installation| installation.id == id)
        .ok_or(GitHubFailure::NotFound)
}

/// The binding `id` as the organization's list of bindings holds it; an ID the list does not
/// hold is not found.
fn find_binding<F: JsonOutputKind>(
    deployment: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    id: &str,
) -> anyhow::Result<Result<GitHubInstallation, GitHubFailure>> {
    Ok(list_bindings(deployment, options, organization)?
        .and_then(|installations| held(&installations, id).cloned()))
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
