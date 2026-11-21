//! `useful workflow run artifact` (REQ-ARTIFACTSET-12, REQ-ARTIFACTSET-29): a Cloud run's
//! Artifact Set, which `list` and `download` find by `RUN` in Cloud alone in the organization in
//! effect (REQ-LOCALRUN-180), reading nothing under the `useful` home, and the offline check of a
//! downloaded artifact directory, which reads no credential and sends no request.

mod assembly;
mod download;
mod list;
mod validate;

use anyhow::{Context, anyhow};
use clap::{Args, Subcommand};

use super::target::{CloudOptions, CloudRunArg, InCloud};
use crate::cli::context::OrgArgs;
use useful_api::{ArtifactApi, ArtifactApiError, HttpClient, HttpTransportPolicy};
use useful_human_auth::Deployment;

pub(super) const ABOUT: &str = "List, download and check a run's artifacts";
const PATH: &[&str] = &["workflow", "run", "artifact"];

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<ArtifactCommand>,
}

#[derive(Debug, Subcommand)]
enum ArtifactCommand {
    #[command(about = download::ABOUT)]
    Download(download::Command),
    #[command(about = list::ABOUT)]
    List(list::Command),
    #[command(about = validate::ABOUT)]
    Validate(validate::Command),
}

/// A leaf that reads a Cloud run's Artifact Set: `RUN`, the operation's own options, the
/// organization in effect and the authentication and transport options.
#[derive(Debug, Args)]
pub(super) struct RemoteArtifactCommand<O: Args> {
    #[command(flatten)]
    run: CloudRunArg,

    #[command(flatten)]
    operation: O,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: CloudOptions,
}

pub(super) trait RemoteArtifactError: From<ArtifactApiError> {
    fn credential_rejected(&self) -> bool;
}

impl RemoteArtifactError for ArtifactApiError {
    fn credential_rejected(&self) -> bool {
        self.credential_rejected()
    }
}

pub(super) struct RemoteArtifactResult<'a, T, E> {
    deployment: &'a str,
    run: &'a InCloud,
    authentication: crate::cli::PrincipalAuthenticationKind,
    result: Result<T, E>,
    json: bool,
}

pub(super) trait RemoteArtifactOperation {
    type Output;
    type Error: RemoteArtifactError;

    /// The leaf's full command name, as a refused lookup's document names it.
    const COMMAND: &'static str;
    const SESSION_CONTEXT: &'static str;

    fn request(&self, api: &mut ArtifactApi, run: &InCloud) -> Result<Self::Output, Self::Error>;
    fn write_result(
        &self,
        output: RemoteArtifactResult<'_, Self::Output, Self::Error>,
    ) -> anyhow::Result<crate::exit_code::ExitCode>;
}

impl<O: RemoteArtifactOperation + Args> RemoteArtifactCommand<O> {
    /// Finds the Cloud run `RUN` names, whose miss ends the leaf before its own read, and then
    /// reads its Artifact Set.
    fn execute(self) -> crate::cli::CommandResult {
        let cloud = match self.run.find(
            &self.org,
            &self.options.authentication,
            &self.options.http,
            O::COMMAND,
            self.options.json,
        ) {
            Ok(cloud) => cloud,
            Err(result) => return result,
        };
        Ok(execute_with_api(
            &cloud.deployment,
            self.options.http.transport_policy(),
            &self.options.authentication,
            O::SESSION_CONTEXT,
            |api| self.operation.request(api, &cloud),
            RemoteArtifactError::credential_rejected,
            |deployment, result| {
                self.operation.write_result(RemoteArtifactResult {
                    deployment,
                    run: &cloud,
                    authentication: self.options.authentication.kind(),
                    result,
                    json: self.options.json,
                })
            },
        )?)
    }
}

impl Command {
    pub(super) fn execute(self) -> crate::cli::CommandResult {
        match self.command {
            None => crate::cli::print_help(PATH),
            Some(ArtifactCommand::Download(command)) => command.execute(),
            Some(ArtifactCommand::List(command)) => command.execute(),
            Some(ArtifactCommand::Validate(command)) => command.execute(),
        }
    }
}

fn execute_with_api<T, E>(
    deployment: &Deployment,
    transport_policy: HttpTransportPolicy,
    authentication: &crate::cli::PrincipalAuthenticationArgs,
    session_context: &'static str,
    operation: impl FnMut(&mut ArtifactApi) -> Result<T, E>,
    credential_rejected: impl Fn(&E) -> bool,
    write_result: impl FnOnce(&str, Result<T, E>) -> anyhow::Result<crate::exit_code::ExitCode>,
) -> anyhow::Result<crate::exit_code::ExitCode>
where
    E: From<ArtifactApiError>,
{
    let result = with_api(
        deployment,
        transport_policy,
        authentication,
        session_context,
        operation,
        credential_rejected,
    )?;
    write_result(deployment.fingerprint().api_url(), result)
}

fn with_api<T, E>(
    deployment: &Deployment,
    transport_policy: HttpTransportPolicy,
    authentication: &crate::cli::PrincipalAuthenticationArgs,
    session_context: &'static str,
    mut operation: impl FnMut(&mut ArtifactApi) -> Result<T, E>,
    credential_rejected: impl Fn(&E) -> bool,
) -> anyhow::Result<Result<T, E>>
where
    E: From<ArtifactApiError>,
{
    let session_client = HttpClient::new(transport_policy)
        .map_err(|error| anyhow!(error))
        .context("prepare Artifact Set networking")?;
    crate::cli::execute_selected_api_operation(
        crate::cli::principal_api_context(
            &session_client,
            deployment,
            authentication,
            session_context,
        ),
        |access_token| {
            let mut api = match ArtifactApi::new(
                deployment.fingerprint().api_url(),
                access_token,
                transport_policy,
            ) {
                Ok(api) => api,
                Err(error) => return Ok(Err(E::from(error))),
            };
            Ok(operation(&mut api))
        },
        credential_rejected,
        || E::from(ArtifactApiError::Unauthenticated),
        |category| E::from(ArtifactApiError::Unreachable(category)),
    )
}
