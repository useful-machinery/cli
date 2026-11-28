//! `useful workflow doctor PATH... [--runner RUNNER] [--binding KEY=VALUE]`: what workflows need and what
//! meets each need. It derives the requirements, then, when a workflow calls for a kind, reads
//! the organization and the project in effect, the organization's connections, with `--runner`
//! and a project the GitHub connection authorization in force for them and, with a human
//! session, the member's grants, and judges each requirement on them. It sends reads alone: the
//! grant flow is `useful account integration connect --workflow`'s.

mod authorizations;
mod grants;
mod readiness;
pub(in crate::cli) mod report;
pub(in crate::cli) mod roots;
mod slack;

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context as _, anyhow};
use clap::Args;

use crate::cli::account::grant::{self, output, runner_choice};
use crate::cli::context::{self, Context, NoProject, OrgArgs, ProjectArgs, Unresolved};
use crate::cli::{
    CommandFailure, CommandResult, CommonArgs, HttpOptions, NoAuthenticationArgs,
    PrincipalAuthenticationArgs, WorkflowJson,
};
use crate::exit_code::ExitCode;
use useful_api::{CommonOrganizationFailure, MemberGrantFailure};
use useful_human_auth::Deployment;
use useful_runner::{CredentialKind, DerivedCredentials, RepositorySource, UnknownDeclaration};

use super::definition::parse_binding;
use grants::Held;
use readiness::{Ending, Readiness};
use report::Report;
use roots::Roots;
use slack::{Bindings, ReadFailure};

pub(super) const ABOUT: &str = "Report what a workflow needs to run and whether each need is met";
const COMMAND_NAME: &str = "useful workflow doctor";
const COMMAND_PATH: &[&str] = &["workflow", "doctor"];
const DEPLOYMENT_CONTEXT: &str = "configure the doctor's Cloud access";
const SOURCE_ROOT_REMEDY: &str = "useful workflow doctor FILE --source-root ROOT";

type Options = CommonArgs<WorkflowJson, PrincipalAuthenticationArgs>;

#[derive(Debug, Args)]
pub(super) struct Command {
    #[arg(
        value_name = "PATH",
        required = true,
        help = "Workflow file, or tree directory whose workflow.yaml is its root; repeats"
    )]
    paths: Vec<PathBuf>,

    // The runner each requirement is judged on.
    #[arg(long, value_name = "RUNNER", help = grant::RUNNER_HELP)]
    runner: Option<String>,

    #[arg(
        long = "binding",
        value_name = "KEY=VALUE",
        value_parser = parse_binding,
        help = "Channel VALUE for the slack.channel binding KEY that the doctor checks (repeatable)"
    )]
    bindings: Vec<(String, String)>,

    #[arg(
        long,
        value_name = "ROOT",
        help = "Directory that bounds the workflow files"
    )]
    source_root: Option<PathBuf>,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    project: ProjectArgs,

    #[command(flatten)]
    options: Options,
}

impl Command {
    /// Derives the requirements with the `origin` remote naming the repository's provider. A
    /// tree that needs no credentials and declares no Slack block is reported without loading
    /// anything; any other is checked against the deployment.
    pub(super) fn execute(mut self) -> CommandResult {
        // A runner is judged by the member's own grants, which a service API key cannot
        // read.
        if self.runner.is_some() && self.options.authentication.api_key_file.is_some() {
            return Err(CommandFailure::with_exit_code(
                anyhow!(
                    "--api-key-file cannot be used with --runner, which judges the runner by your own grants\n\n\
                     Sign in with useful account login and leave out --api-key-file."
                ),
                ExitCode::UsageError,
            ));
        }
        let json = self.options.json;
        let roots = Roots::find(&self.paths, self.source_root.as_deref(), SOURCE_ROOT_REMEDY)?;
        let Some(derived) = roots.derive(&roots.origin_remote(), json)? else {
            return Ok(ExitCode::GeneralFailure);
        };
        let bindings = slack::bindings(std::mem::take(&mut self.bindings), &derived.slack)?;
        if derived.reported.requirements.is_empty() && derived.slack.is_empty() {
            return Report::unread(derived, &bindings)
                .write(json)
                .map_err(Into::into);
        }
        super::super::execute_deployment_command(
            Some((self, roots, derived, bindings)),
            COMMAND_PATH,
            DEPLOYMENT_CONTEXT,
            |(command, roots, derived, bindings), deployment| {
                command.check(deployment, &roots, derived, &bindings)
            },
        )
    }

    /// Resolves `--runner`, the organization and the project in effect, makes the connection reads, with
    /// `--runner` and a project the GitHub connection authorization read and, with a human session, the
    /// grants read, and writes the report. A caller who is not signed in gets the report of `derived` unless
    /// `--runner` was given; any other failure ends the command with no report. Workflows that call for
    /// token services alone are reported with nothing read.
    fn check(
        self,
        deployment: &Deployment,
        roots: &Roots,
        derived: DerivedCredentials,
        bindings: &Bindings,
    ) -> CommandResult {
        let Self {
            runner,
            org,
            project,
            options,
            ..
        } = self;
        let api_url = deployment.fingerprint().api_url();
        let json = options.json;
        let authentication = options.authentication.kind();
        let human = options.authentication.api_key_file.is_none();
        let signed_out = SignedOut {
            api_url,
            runner: runner.is_some(),
            json,
        };
        // Nothing is asked of Cloud about a token service, so workflows that call for no
        // other kind ask Cloud nothing, with or without `--runner`, unless the repository is
        // unknown, which the project in effect may name: its repository's provider can add a
        // requirement.
        let repository_unknown = derived
            .reported
            .unknown
            .iter()
            .any(|unknown| unknown.declaration == UnknownDeclaration::Repository);
        if derived.reported.requirements.is_empty()
            || (!repository_unknown && token_services_alone(&derived))
        {
            if derived.slack.is_empty() {
                return Report::unread(derived, bindings)
                    .write(json)
                    .map_err(Into::into);
            }
            return check_slack_only(deployment, &org, &options, derived, bindings);
        }
        // The runner is named before anything else is read.
        let runner = match &runner {
            Some(runner) => {
                // The runners are read with the member's human session, as the grant leaves
                // read them.
                let grant_options = CommonArgs::<WorkflowJson, _>::new(
                    json,
                    NoAuthenticationArgs::default(),
                    HttpOptions {
                        allow_insecure_http: options.http.allow_insecure_http,
                    },
                );
                match runner_choice::resolve(
                    deployment,
                    json,
                    output::Family::Document,
                    runner,
                    None,
                    || {
                        runner_choice::in_active_organizations(
                            deployment,
                            grant_options.http.transport_policy(),
                        )
                    },
                    |id| format!("useful workflow doctor PATH --runner {id}"),
                )? {
                    Ok(acting) => Some(acting.id),
                    Err(code) => return Ok(code),
                }
            }
            None => None,
        };
        let (organization, project) = match context::in_effect(org, project, &options, deployment) {
            Ok(Context {
                organization: Ok(organization),
                project,
            }) => {
                let project = match project {
                    Ok(project) => Some(project.project),
                    Err(NoProject::Unnamed) => None,
                    Err(none) => {
                        return Err(CommandFailure::with_exit_code(
                            anyhow!("{none}"),
                            ExitCode::UsageError,
                        ));
                    }
                };
                (organization.organization, project)
            }
            Ok(Context {
                organization: Err(organizations),
                ..
            }) => return Err(context::unresolved(&organizations)),
            Err(Unresolved::Variable(failure)) => return Err(failure),
            Err(Unresolved::Refused(CommonOrganizationFailure::Unauthenticated)) if human => {
                return signed_out.end(derived, bindings).map_err(Into::into);
            }
            Err(Unresolved::Refused(failure)) => {
                return Ending::of_context(failure)
                    .write(api_url, authentication, json)
                    .map_err(Into::into);
            }
            Err(Unresolved::Failed(error)) => return Err(error.into()),
        };
        let policy = options.http.transport_policy();
        let readiness = Readiness {
            organization: &organization,
            authentication: &options.authentication,
            policy,
        };
        let session = readiness::Session::new(deployment, &readiness)?;
        let ended = |ending: Ending, derived: DerivedCredentials| match ending {
            Ending::Unauthenticated if human => signed_out.end(derived, bindings),
            ending => ending.write(api_url, authentication, json),
        };
        // The project in effect, not the `origin` remote, names the repository's provider, so
        // the files are derived again with its repository.
        let (mut reported, repository) = match &project {
            Some(project) => match session.read_project(project)? {
                Ok(repository) => {
                    let source =
                        RepositorySource::Project(repository.map(|repository| repository.kind));
                    let Some(again) = roots.derive(&source, json)? else {
                        return Ok(ExitCode::GeneralFailure);
                    };
                    (again, repository)
                }
                Err(ending) => return ended(ending, derived).map_err(Into::into),
            },
            None => (derived.clone(), None),
        };
        // The project named no other kind: the only remaining read is Slack, if declared.
        if token_services_alone(&reported) {
            let slack = read_slack(&session, &organization, &reported, bindings);
            return Report {
                deployment: (project.is_some() || slack.is_some()).then_some(api_url),
                organization: Some(&organization),
                project: project.as_deref(),
                ..Report::from_derived(reported, slack)
            }
            .write(json)
            .map_err(Into::into);
        }
        for requirement in &mut reported.reported.requirements {
            let Some(read) = readiness::read_for(requirement.kind) else {
                continue;
            };
            match read(&session)? {
                Ok(code) => {
                    requirement.code = repository
                        .filter(|repository| repository.kind == requirement.kind)
                        .map_or(code, |repository| repository.code(code));
                }
                Err(ending) => return ended(ending, derived).map_err(Into::into),
            }
        }
        // The GitHub connection authorization in force for the project on the runner, shown
        // beside `github`.
        let authorization = match (&project, &runner) {
            (Some(project), Some(runner))
                if reported
                    .reported
                    .requirements
                    .iter()
                    .any(|requirement| requirement.kind == CredentialKind::Github) =>
            {
                match authorizations::read(&session, project, runner)? {
                    Ok(authorization) => authorization,
                    Err(ending) => return ended(ending, derived).map_err(Into::into),
                }
            }
            _ => None,
        };
        let slack = read_slack(&session, &organization, &reported, bindings);
        // The member's grants, of the coding agents those of the organization in
        // effect; a service principal holds none.
        let held = if human {
            match grant::held(deployment, policy, Some(&organization))? {
                Ok(grants) => Some(Held::new(grants, runner.as_deref())),
                Err(MemberGrantFailure::Unauthenticated) => {
                    return signed_out.end(derived, bindings).map_err(Into::into);
                }
                Err(failure) => {
                    return output::failure(api_url, &failure, json).map_err(Into::into);
                }
            }
        } else {
            None
        };
        Report {
            credentials: reported.reported,
            differences: reported.differences,
            slack,
            organization: Some(&organization),
            project: project.as_deref(),
            authorization,
            grants: held,
            deployment: Some(api_url),
        }
        .write(json)
        .map_err(Into::into)
    }
}

/// The Slack-only path resolves no runner, project or grant. A failed read leaves a warning.
fn check_slack_only(
    deployment: &Deployment,
    org: &OrgArgs,
    options: &Options,
    derived: DerivedCredentials,
    bindings: &Bindings,
) -> CommandResult {
    let api_url = deployment.fingerprint().api_url();
    let policy = options.http.transport_policy();
    let read = || {
        let organization =
            match context::organization_in_effect(org, policy, &options.authentication, deployment)
            {
                Ok(Ok(organization)) => organization,
                Ok(Err(CommonOrganizationFailure::Unauthenticated)) => {
                    return Err(ReadFailure::NotSignedIn);
                }
                Ok(Err(CommonOrganizationFailure::Forbidden)) => {
                    return Err(ReadFailure::NotPermitted);
                }
                Ok(Err(CommonOrganizationFailure::Unreachable(_))) => {
                    return Err(ReadFailure::Unreachable);
                }
                Ok(Err(CommonOrganizationFailure::InvalidInput)) => {
                    return Err(ReadFailure::NoOrganization);
                }
                Err(error) if error.exit_code() == ExitCode::UsageError => {
                    return Err(ReadFailure::NoOrganization);
                }
                Err(_) => return Err(ReadFailure::Unreachable),
            };
        let readiness = Readiness {
            organization: &organization,
            authentication: &options.authentication,
            policy,
        };
        let session = readiness::Session::new(deployment, &readiness)
            .map_err(|_| ReadFailure::Unreachable)?;
        let findings = slack::read(&session, &organization, &derived.slack, bindings);
        Ok((organization, findings))
    };
    let report = match read() {
        Ok((_, Err(ReadFailure::NotSignedIn))) | Err(ReadFailure::NotSignedIn) => {
            return SignedOut {
                api_url,
                runner: false,
                json: options.json,
            }
            .end(derived, bindings)
            .map_err(Into::into);
        }
        Ok((organization, findings)) => {
            let slack = findings
                .unwrap_or_else(|failure| slack::list_failed(&derived.slack, bindings, failure));
            return Report {
                deployment: Some(api_url),
                organization: Some(&organization),
                ..Report::from_derived(derived, slack)
            }
            .write(options.json)
            .map_err(Into::into);
        }
        Err(failure) => {
            let slack = slack::unread(&derived.slack, bindings, failure);
            Report::from_derived(derived, slack)
        }
    };
    report.write(options.json).map_err(Into::into)
}

fn read_slack(
    session: &readiness::Session<'_>,
    organization: &str,
    derived: &DerivedCredentials,
    bindings: &Bindings,
) -> Option<Vec<slack::SlackFinding>> {
    slack::read(session, organization, &derived.slack, bindings)
        .unwrap_or_else(|failure| slack::list_failed(&derived.slack, bindings, failure))
}

/// Whether the workflows call for token services alone, of which Cloud is asked
/// nothing.
fn token_services_alone(derived: &DerivedCredentials) -> bool {
    let requirements = &derived.reported.requirements;
    !requirements.is_empty()
        && requirements
            .iter()
            .all(|requirement| requirement.kind.is_token_service())
}

/// How the command ends for a caller who is not signed in.
#[derive(Clone, Copy)]
struct SignedOut<'a> {
    api_url: &'a str,
    /// Whether `--runner` was given.
    runner: bool,
    json: bool,
}

impl SignedOut<'_> {
    /// With `--runner`, as `useful account integration list` ends for a caller who is not signed
    /// in, exit 3; otherwise the report of `derived`, of which Cloud was asked nothing, after one
    /// line on standard error that says so.
    fn end(self, derived: DerivedCredentials, bindings: &Bindings) -> anyhow::Result<ExitCode> {
        if self.runner {
            return output::failure(
                self.api_url,
                &MemberGrantFailure::Unauthenticated,
                self.json,
            );
        }
        writeln!(
            io::stderr().lock(),
            "! You're not signed in, so Cloud was not asked. Sign in with useful account login."
        )
        .context("write workflow doctor note")?;
        Report::unread(derived, bindings).write(self.json)
    }
}
