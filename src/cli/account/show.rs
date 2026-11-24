use std::io::{self, Write};

use anyhow::{Context, anyhow};
use clap::Args;
use serde::Serialize;

use crate::cli::context::{
    self, InEffect, NoProject, OrgArgs, ProjectArgs, ProjectInEffect, Unresolved,
};
use crate::exit_code::{ExitCode, OutcomeClass};
use useful_api::{CommonOrganizationFailure, HttpClient};
use useful_human_auth::Deployment;
use useful_human_auth::{AuthenticationState, AuthenticationStatus};

use super::super::principal::PrincipalResult;

pub(super) const ABOUT: &str =
    "Show your sign-in status and the organization and project in effect";

type Options =
    super::super::CommonArgs<super::super::SignInJson, super::super::PrincipalAuthenticationArgs>;

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    project: ProjectArgs,

    #[command(flatten)]
    options: Options,
}

impl Command {
    pub(super) fn execute(self, deployment: &Deployment) -> super::super::CommandResult {
        self.run(deployment).map_err(Into::into)
    }

    /// Reports the sign-in status, whose state alone decides the exit status, and for an
    /// authenticated caller the organization and the project in effect.
    fn run(self, deployment: &Deployment) -> anyhow::Result<ExitCode> {
        let Self {
            org,
            project,
            options,
        } = self;
        let client = HttpClient::new(options.http.transport_policy())
            .map_err(|error| anyhow!(error))
            .context("prepare status networking")?;
        let authentication = options.authentication.kind();
        let service_api_key = options.authentication.service_api_key()?;
        let status = match service_api_key {
            Some(api_key) => {
                useful_human_auth::check_with_service_api_key(&client, deployment, api_key.expose())
            }
            None => useful_human_auth::check_auth_status(&client, deployment),
        }
        .map_err(|error| anyhow!(error))
        .with_context(|| {
            format!(
                "check sign-in status through {}",
                deployment.fingerprint().api_url()
            )
        })?;
        let outcome = match status.state() {
            AuthenticationState::Authenticated(_) | AuthenticationState::SignupRequired { .. } => {
                OutcomeClass::Success
            }
            AuthenticationState::Forbidden { .. } => OutcomeClass::Forbidden,
            AuthenticationState::Unauthenticated => OutcomeClass::Unauthenticated,
            AuthenticationState::Unreachable(category) => {
                super::super::unreachable_outcome_class(*category)
            }
        };
        let in_effect = match status.state() {
            AuthenticationState::Authenticated(_) => {
                Some(in_effect(org, project, &options, deployment)?)
            }
            _ => None,
        };
        if options.json {
            write_json_status(&status, in_effect.as_ref())?;
        } else {
            write_human_status(&status, authentication)?;
            if let Some(in_effect) = &in_effect {
                write_human_context(in_effect)?;
            }
        }
        Ok(outcome.exit_code())
    }
}

/// The organization and the project in effect, each none when no source names a usable one.
type InEffectPair = (Option<InEffect>, Option<ProjectInEffect>);

/// Resolves the organization and the project in effect. A source that names something
/// unusable and a failed read are said on standard error and leave none in effect; neither
/// changes the exit status.
fn in_effect(
    org: OrgArgs,
    project: ProjectArgs,
    options: &Options,
    deployment: &Deployment,
) -> anyhow::Result<InEffectPair> {
    let (warning, in_effect) = match context::in_effect(org, project, options, deployment) {
        Ok(context::Context {
            organization,
            project,
        }) => {
            let organization = organization.ok();
            match project {
                Ok(project) => (None, (organization, Some(project))),
                Err(NoProject::Unnamed) => (None, (organization, None)),
                Err(none) => (Some(none.to_string()), (organization, None)),
            }
        }
        Err(Unresolved::Variable(failure)) => {
            (Some(format!("{:#}", failure.error())), (None, None))
        }
        Err(Unresolved::Refused(failure)) => (Some(refused(&failure)), (None, None)),
        Err(Unresolved::Failed(error)) => (
            Some(format!(
                "read the organization and project in effect: {error:#}"
            )),
            (None, None),
        ),
    };
    if let Some(warning) = warning {
        writeln!(io::stderr().lock(), "warning: {warning}")
            .context("write the organization and project in effect")?;
    }
    Ok(in_effect)
}

fn refused(failure: &CommonOrganizationFailure) -> String {
    let reason = match failure {
        CommonOrganizationFailure::Unauthenticated => "the sign-in was rejected".to_owned(),
        CommonOrganizationFailure::Forbidden => "forbidden".to_owned(),
        CommonOrganizationFailure::InvalidInput => "rejected as invalid".to_owned(),
        CommonOrganizationFailure::Unreachable(category) => {
            format!("Useful Machinery unreachable ({})", category.as_str())
        }
    };
    format!("read the organization and project in effect: {reason}")
}

fn write_human_context((organization, project): &InEffectPair) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    match organization {
        Some(in_effect) => writeln!(
            stdout,
            "organization in effect: {} · source: {}",
            in_effect.organization,
            in_effect.source.label()
        ),
        None => writeln!(stdout, "organization in effect: none"),
    }
    .context("write the organization in effect")?;
    match project {
        Some(in_effect) => writeln!(
            stdout,
            "project in effect: {} · source: {}",
            in_effect.project,
            in_effect.source.label()
        ),
        None => writeln!(stdout, "project in effect: none"),
    }
    .context("write the project in effect")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct StatusResult<'a> {
    schema_version: u8,
    #[serde(flatten)]
    body: StatusBody<'a>,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum StatusBody<'a> {
    #[serde(rename_all = "camelCase")]
    Authenticated {
        deployment: &'a str,
        principal: PrincipalResult<'a>,
        #[serde(skip_serializing_if = "Option::is_none")]
        actions: Option<&'a [serde_json::Value]>,
        // Only `account show` reports these; the login's status omits them.
        #[serde(skip_serializing_if = "Option::is_none")]
        organization_in_effect: Option<&'a InEffect>,
        #[serde(skip_serializing_if = "Option::is_none")]
        project_in_effect: Option<&'a ProjectInEffect>,
    },
    SignupRequired {
        deployment: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        actions: Option<&'a [serde_json::Value]>,
    },
    Forbidden {
        deployment: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        actions: Option<&'a [serde_json::Value]>,
    },
    Unauthenticated {
        deployment: &'a str,
    },
    Unreachable {
        deployment: &'a str,
        category: &'static str,
    },
}

impl<'a> StatusResult<'a> {
    pub(super) fn from_status(status: &'a AuthenticationStatus) -> Self {
        let body = match status.state() {
            AuthenticationState::Authenticated(authenticated) => StatusBody::Authenticated {
                deployment: status.deployment(),
                principal: PrincipalResult::from_profile(&authenticated.principal),
                actions: authenticated.actions.as_deref(),
                organization_in_effect: None,
                project_in_effect: None,
            },
            AuthenticationState::SignupRequired { actions } => StatusBody::SignupRequired {
                deployment: status.deployment(),
                actions: actions.as_deref(),
            },
            AuthenticationState::Forbidden { actions } => StatusBody::Forbidden {
                deployment: status.deployment(),
                actions: actions.as_deref(),
            },
            AuthenticationState::Unauthenticated => StatusBody::Unauthenticated {
                deployment: status.deployment(),
            },
            AuthenticationState::Unreachable(category) => StatusBody::Unreachable {
                deployment: status.deployment(),
                category: category.as_str(),
            },
        };
        Self {
            schema_version: 1,
            body,
        }
    }
}

impl<'a> StatusResult<'a> {
    /// The status with the organization and the project in effect, which only an
    /// authenticated status carries.
    fn in_effect(mut self, (organization, project): &'a InEffectPair) -> Self {
        if let StatusBody::Authenticated {
            organization_in_effect,
            project_in_effect,
            ..
        } = &mut self.body
        {
            *organization_in_effect = organization.as_ref();
            *project_in_effect = project.as_ref();
        }
        self
    }
}

fn write_json_status(
    status: &AuthenticationStatus,
    in_effect: Option<&InEffectPair>,
) -> anyhow::Result<()> {
    let result = StatusResult::from_status(status);
    let result = match in_effect {
        Some(in_effect) => result.in_effect(in_effect),
        None => result,
    };
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer_pretty(&mut stdout, &result).context("write JSON sign-in status")?;
    writeln!(stdout).context("write sign-in status")
}

pub(super) fn write_human_status(
    status: &AuthenticationStatus,
    authentication: super::super::PrincipalAuthenticationKind,
) -> anyhow::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    match status.state() {
        AuthenticationState::Authenticated(authenticated) => {
            let account = authenticated
                .principal
                .display_name
                .as_ref()
                .unwrap_or(&authenticated.principal.id);
            if authenticated.principal.r#type == "service" {
                writeln!(stdout, "✓ Authenticated as service {account}.")
                    .context("write sign-in status")?;
            } else {
                writeln!(stdout, "✓ Signed in as {account}.").context("write sign-in status")?;
            }
            write_human_actions(&mut stdout, authenticated.actions.as_deref())
        }
        AuthenticationState::SignupRequired { actions } => {
            writeln!(stdout, "✓ Signed in to Useful Machinery.").context("write sign-in status")?;
            writeln!(
                stdout,
                "! Your Useful Machinery account still needs to be set up."
            )
            .context("write sign-in status")?;
            write_human_actions(&mut stdout, actions.as_deref())
        }
        AuthenticationState::Forbidden { actions } => {
            writeln!(
                stdout,
                "! Useful Machinery refuses this sign-in's account: it may be suspended, deleted or scheduled for deletion."
            )
            .context("write sign-in status")?;
            if matches!(
                authentication,
                super::super::PrincipalAuthenticationKind::HumanSession
            ) {
                writeln!(
                    stdout,
                    "\nTo keep an account scheduled for deletion, cancel before its deadline:\n  useful account restore"
                )
                .context("write sign-in status")?;
            }
            write_human_actions(&mut stdout, actions.as_deref())
        }
        AuthenticationState::Unauthenticated => writeln!(
            stdout,
            "{}",
            authentication.rejected_notice("! You're not signed in to Useful Machinery.")
        )
        .context("write sign-in status"),
        AuthenticationState::Unreachable(category) => writeln!(
            stdout,
            "! Couldn't reach Useful Machinery ({}).",
            category.as_str()
        )
        .context("write sign-in status"),
    }
}

fn write_human_actions(
    output: &mut impl Write,
    actions: Option<&[serde_json::Value]>,
) -> anyhow::Result<()> {
    if let Some(actions) = actions {
        for action in actions {
            serde_json::to_writer(&mut *output, action).context("write sign-in status action")?;
            writeln!(output).context("write sign-in status")?;
        }
    }
    Ok(())
}
