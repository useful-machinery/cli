mod output;
mod pool;
mod webhook;

use anyhow::{Context, anyhow, bail};
use clap::{ArgGroup, Args, Subcommand, builder::NonEmptyStringValueParser};

use crate::exit_code::ExitCode;
use useful_api::{
    CommonOrganizationFailure, CreateProjectInput, HttpClient, HttpTransportPolicy, Project,
    ProjectApi, ProjectFailure, RunnerFailure,
};
use useful_human_auth::Deployment;

use super::context::{self, ContextFailure, OrgArgs, ProjectArgs, ProjectRef, ProjectSubject};
use super::org::connection::{self, target::Target};
use super::{PoolArg, RepositoryRef};

/// How `useful project show` joins readiness blockers, shared with run creation's
/// `project-not-ready` rejection.
pub(super) use output::blocker_list;

pub(super) const ABOUT: &str = "Manage Useful Machinery projects";
/// What to do about a refusal that names an archived project, shared by the
/// commands whose refusal is not a project outcome of its own: `useful project
/// webhook` and run creation.
pub(super) const ARCHIVED_REMEDY: &str = "The project is archived. As an organization owner, unarchive it with `useful project unarchive` first.";
const NAME: &str = "project";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<ProjectCommand>,
}

#[derive(Debug, Subcommand)]
enum ProjectCommand {
    #[command(about = "Archive a project")]
    Archive(ArchiveCommand),
    #[command(
        about = "Create a project",
        after_help = "GitLab setup: https://docs.usefulmachinery.com/agent/gitlab-setup.md"
    )]
    Create(CreateCommand),
    #[command(about = "List projects")]
    List(ListCommand),
    #[command(about = "Manage a project's runner pools")]
    Pool(pool::Command),
    #[command(about = "Show a project")]
    Show(ShowCommand),
    #[command(about = "Unarchive a project")]
    Unarchive(ArchiveCommand),
    #[command(
        about = "Change a project's name, repository or branch",
        after_help = "GitLab setup: https://docs.usefulmachinery.com/agent/gitlab-setup.md"
    )]
    Update(UpdateCommand),
    #[command(about = "Manage a project's signed webhooks")]
    Webhook(webhook::Command),
}

type Options = super::CommonArgs<super::ProjectJson, super::PrincipalAuthenticationArgs>;

// `create NAME --repository REPOSITORY` in the organization in effect; the connection that
// reaches the repository is found unless `--integration` names it (REQ-PROJECT-101).
#[derive(Debug, Args)]
struct CreateCommand {
    #[arg(value_name = "NAME", help = "The project's canonical name")]
    name: String,

    #[arg(
        long,
        value_name = RepositoryRef::VALUE_NAME,
        help = RepositoryRef::HELP
    )]
    repository: RepositoryRef,

    #[arg(
        long = "integration",
        value_name = connection::target::VALUE_NAME,
        value_parser = Target::parse,
        help = connection::reach::HELP
    )]
    connection: Option<Target>,

    #[arg(
        long,
        value_name = "BRANCH",
        value_parser = NonEmptyStringValueParser::new(),
        help = "Set the configured default branch (the provider default when omitted)"
    )]
    default_branch: Option<String>,

    #[arg(
        long,
        value_name = PoolArg::VALUE_NAME,
        help = "Runner pool ID or exact name; repeat to assign several"
    )]
    pool: Vec<PoolArg>,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: Options,
}

// Project leaves intentionally keep their Clap identities explicit so each help page
// names the exact resource accepted by the corresponding public API operation.
#[derive(Debug, Args)]
struct ListCommand {
    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    pagination: super::PaginationArgs,

    #[arg(long, help = "Include archived projects")]
    include_archived: bool,

    #[command(flatten)]
    options: Options,
}

// `show [PROJECT]` names its project as its subject or else shows the project in effect, as
// `org show [ORG]` does with `--org`; the subject's ID must not be `project`, `--project`'s own.
#[derive(Debug, Args)]
struct ShowCommand {
    #[arg(
        value_name = ProjectRef::VALUE_NAME,
        help = ProjectRef::HELP,
        conflicts_with = "project"
    )]
    subject: Option<ProjectRef>,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    project: ProjectArgs,

    #[command(flatten)]
    options: Options,
}

// Archive and unarchive share their arguments and reverse each other, so neither asks for
// confirmation. Each takes its project as its subject alone, never the project in effect.
#[derive(Debug, Args)]
struct ArchiveCommand {
    #[arg(value_name = ProjectRef::VALUE_NAME, help = ProjectRef::HELP)]
    subject: ProjectRef,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: Options,
}

// `update PROJECT` changes the project its argument names: at most one repository request,
// then at most one rename, so a project named by name keeps that name until the last request
// and the command can be run again as typed (REQ-PROJECT-102).
#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("change")
        .args(["name", "repository", "default_branch", "clear_repository"])
        .required(true)
        .multiple(true)
))]
struct UpdateCommand {
    #[arg(value_name = ProjectRef::VALUE_NAME, help = ProjectRef::HELP)]
    subject: ProjectRef,

    #[arg(long, help = "Set the canonical project name")]
    name: Option<String>,

    #[arg(
        long,
        value_name = RepositoryRef::VALUE_NAME,
        help = RepositoryRef::HELP
    )]
    repository: Option<RepositoryRef>,

    #[arg(
        long = "integration",
        requires = "repository",
        value_name = connection::target::VALUE_NAME,
        value_parser = Target::parse,
        help = connection::reach::HELP
    )]
    connection: Option<Target>,

    #[arg(
        long,
        value_name = "BRANCH",
        value_parser = NonEmptyStringValueParser::new(),
        help = "Set the configured default branch (with --repository, the provider default when omitted)"
    )]
    default_branch: Option<String>,

    #[arg(
        long,
        conflicts_with_all = ["repository", "connection", "default_branch"],
        requires = "yes",
        help = "Remove the project's repository binding"
    )]
    clear_repository: bool,

    // `--yes` confirms `--clear-repository` alone, so it is never accepted and ignored.
    #[arg(long, requires = "clear_repository", help = "Confirm this action")]
    yes: bool,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: Options,
}

impl Command {
    pub(super) fn execute(self) -> super::CommandResult {
        let Some(command) = self.command else {
            return super::print_help(&[NAME]);
        };
        match command {
            ProjectCommand::Archive(command) => execute_command(command, ArchiveCommand::archive),
            ProjectCommand::Create(command) => execute_command(command, CreateCommand::execute),
            ProjectCommand::List(command) => execute_command(command, ListCommand::execute),
            ProjectCommand::Pool(command) => command.execute(),
            ProjectCommand::Show(command) => execute_command(command, ShowCommand::execute),
            ProjectCommand::Unarchive(command) => {
                execute_command(command, ArchiveCommand::unarchive)
            }
            ProjectCommand::Update(command) => execute_command(command, UpdateCommand::execute),
            ProjectCommand::Webhook(command) => command.execute(),
        }
    }
}

// This wrapper supplies project-specific deployment diagnostics while organization
// commands retain their independent organization wording; a leaf may end with a usage error
// of its own, as one that acts in the organization or the project in effect does.
fn execute_command<T>(
    command: T,
    execute: impl FnOnce(T, &Deployment) -> super::CommandResult,
) -> super::CommandResult {
    super::execute_deployment_command(
        Some(command),
        &[NAME],
        "configure Useful Machinery project access",
        execute,
    )
}

/// Runs `run` with `options`, the organization reference to send and the project's ID, in the
/// organization in effect and on `project` (REQ-PROJECT-75, REQ-PROJECT-100); a refused read
/// of either is written as this family writes its own failures.
fn execute_in_project(
    org: OrgArgs,
    project: ProjectSubject,
    options: Options,
    deployment: &Deployment,
    run: impl FnOnce(Options, &str, &str) -> anyhow::Result<ExitCode>,
) -> super::CommandResult {
    context::execute_in_project(
        org,
        project,
        options,
        deployment,
        write_context_failure,
        run,
    )
}

/// A failed read of the organization or the project a leaf acts in, written with the closed
/// outcomes every `useful project` leaf reports: a refusal as the project route's own, and a
/// `PROJECT` name no project of the organization has as `not_found`.
fn write_context_failure(
    deployment: &str,
    failure: &ContextFailure,
    authentication: super::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let failure = match failure {
        ContextFailure::Refused(failure) => refused(failure),
        ContextFailure::UnknownProject => ProjectFailure::NotFound,
    };
    output::write_failure(deployment, failure, authentication, json)
}

/// A refused read of the organization or the project in effect, as the project outcome that
/// names the same refusal.
const fn refused(failure: &CommonOrganizationFailure) -> ProjectFailure {
    match failure {
        CommonOrganizationFailure::Unauthenticated => ProjectFailure::Unauthenticated,
        CommonOrganizationFailure::Forbidden => ProjectFailure::Forbidden,
        CommonOrganizationFailure::InvalidInput => ProjectFailure::InvalidInput,
        CommonOrganizationFailure::Unreachable(category) => ProjectFailure::Unreachable(*category),
    }
}

impl CreateCommand {
    fn execute(self, deployment: &Deployment) -> super::CommandResult {
        if let Some(refusal) = connection::reach::refuse_linear(self.connection.as_ref()) {
            return refusal;
        }
        let Self {
            name,
            repository,
            connection,
            default_branch,
            pool,
            org,
            options,
        } = self;
        context::execute_in(
            org,
            options,
            deployment,
            |deployment, failure, authentication, json| {
                output::write_failure(deployment, refused(failure), authentication, json)
            },
            |options, organization| {
                let creation = Creation {
                    name: &name,
                    repository: &repository,
                    default_branch: default_branch.as_deref(),
                    pools: &pool,
                };
                creation.send(deployment, &options, organization, connection)
            },
        )
    }
}

/// What `useful project create` sends, once the organization it acts in is known.
struct Creation<'a> {
    name: &'a str,
    repository: &'a RepositoryRef,
    default_branch: Option<&'a str>,
    pools: &'a [PoolArg],
}

impl Creation<'_> {
    /// Resolves every pool, finds the connection that reaches the repository and creates the
    /// project with the first pool; with several pools, then assigns them all as one set
    /// (REQ-PROJECT-76, REQ-PROJECT-101).
    fn send(
        self,
        deployment: &Deployment,
        options: &Options,
        organization: &str,
        connection: Option<Target>,
    ) -> anyhow::Result<ExitCode> {
        let api_url = deployment.fingerprint().api_url();
        let transport_policy = options.http.transport_policy();
        let mut pool_ids = Vec::with_capacity(self.pools.len());
        for pool in self.pools {
            let pool_id = match resolve_pool_id(
                deployment,
                transport_policy,
                &options.authentication,
                organization,
                pool,
            )? {
                Ok(pool_id) => pool_id,
                Err(failure) => {
                    return super::runner::write_failure(
                        deployment,
                        &failure,
                        &options.authentication,
                        options.json,
                    );
                }
            };
            // The pools form a set: naming one pool twice, by ID and by name, names it once.
            if !pool_ids.contains(&pool_id) {
                pool_ids.push(pool_id);
            }
        }
        let reached = match connection::reach::find(
            deployment,
            options,
            organization,
            self.repository,
            connection,
        )? {
            Ok(reached) => reached,
            Err(exit) => return Ok(exit),
        };
        let key = useful_support::generate_idempotency_key()
            .context("generate project creation request identity")?;
        let created = with_api(
            deployment,
            transport_policy,
            &options.authentication,
            |api| {
                api.create(
                    organization,
                    &key,
                    CreateProjectInput {
                        name: self.name,
                        repository: reached.selector(),
                        repository_id: reached.repository_id(),
                        default_branch: self.default_branch,
                        runner_pool_id: pool_ids.first().map(String::as_str),
                    },
                )
            },
        )?;
        let result = match created {
            Ok(project) if pool_ids.len() > 1 => {
                let key = useful_support::generate_idempotency_key()
                    .context("generate project runner pool request identity")?;
                let assigned = with_api(
                    deployment,
                    transport_policy,
                    &options.authentication,
                    |api| api.set_runner_pools(organization, &project.id, &key, &pool_ids),
                )?;
                match assigned {
                    Ok(project) => Ok(project),
                    Err(failure) => {
                        let pool = project
                            .runner_pools
                            .as_deref()
                            .and_then(<[_]>::first)
                            .map_or_else(
                                || pool_ids[0].clone(),
                                |pool| format!("{} ({})", pool.name, pool.id),
                            );
                        return output::write_partial_failure(
                            api_url,
                            failure,
                            &["created"],
                            &project,
                            &format!(
                                "The project {} was created with the runner pool {pool} alone. Add the others:\n  useful project pool add POOL --project {}",
                                project.id, project.id
                            ),
                            options.authentication.kind(),
                            options.json,
                        );
                    }
                }
            }
            created => created,
        };
        output::write_project(
            api_url,
            result,
            "created",
            "✓ Project created.",
            options.authentication.kind(),
            options.json,
        )
    }
}

// Each read command binds a distinct public projection and machine envelope; keeping
// these mappings explicit makes the user-visible outcome contract reviewable.
impl ListCommand {
    fn execute(self, deployment: &Deployment) -> super::CommandResult {
        let Self {
            org,
            pagination,
            include_archived,
            options,
        } = self;
        context::execute_in(
            org,
            options,
            deployment,
            |deployment, failure, authentication, json| {
                output::write_failure(deployment, refused(failure), authentication, json)
            },
            |options, organization| {
                let result = with_api(
                    deployment,
                    options.http.transport_policy(),
                    &options.authentication,
                    |api| {
                        api.list(
                            organization,
                            pagination.limit,
                            pagination.cursor.as_deref(),
                            include_archived,
                        )
                    },
                )?;
                output::write_project_list(
                    deployment.fingerprint().api_url(),
                    result,
                    options.authentication.kind(),
                    options.json,
                )
            },
        )
    }
}

impl ShowCommand {
    fn execute(self, deployment: &Deployment) -> super::CommandResult {
        let project = match self.subject {
            Some(subject) => ProjectSubject::Named(subject),
            None => ProjectSubject::InEffect(self.project),
        };
        execute_in_project(
            self.org,
            project,
            self.options,
            deployment,
            |options, organization, project| {
                let result = with_api(
                    deployment,
                    options.http.transport_policy(),
                    &options.authentication,
                    |api| api.get(organization, project),
                )?;
                output::write_project(
                    deployment.fingerprint().api_url(),
                    result,
                    "found",
                    "✓ Project found.",
                    options.authentication.kind(),
                    options.json,
                )
            },
        )
    }
}

impl ArchiveCommand {
    fn archive(self, deployment: &Deployment) -> super::CommandResult {
        self.execute(
            deployment,
            ProjectApi::archive,
            "generate project archive request identity",
            "archived",
            "✓ Project archived.",
        )
    }

    fn unarchive(self, deployment: &Deployment) -> super::CommandResult {
        self.execute(
            deployment,
            ProjectApi::unarchive,
            "generate project unarchive request identity",
            "unarchived",
            "✓ Project unarchived.",
        )
    }

    fn execute(
        self,
        deployment: &Deployment,
        change: impl Fn(&ProjectApi, &str, &str, &str) -> Result<Project, ProjectFailure>,
        key_context: &'static str,
        outcome: &'static str,
        heading: &'static str,
    ) -> super::CommandResult {
        execute_in_project(
            self.org,
            ProjectSubject::Named(self.subject),
            self.options,
            deployment,
            |options, organization, project| {
                let key = useful_support::generate_idempotency_key().context(key_context)?;
                let result = with_api(
                    deployment,
                    options.http.transport_policy(),
                    &options.authentication,
                    |api| change(api, organization, project, &key),
                )?;
                output::write_project(
                    deployment.fingerprint().api_url(),
                    result,
                    outcome,
                    heading,
                    options.authentication.kind(),
                    options.json,
                )
            },
        )
    }
}

/// The repository request of `useful project update`, the first it sends (REQ-PROJECT-102).
enum RepositoryChange {
    /// `--repository`, bound through the connection that reaches it, with `--default-branch` as
    /// its branch or else the provider's default.
    Set {
        repository: RepositoryRef,
        connection: Option<Target>,
        default_branch: Option<String>,
    },
    /// `--default-branch` alone.
    Branch(String),
    /// `--clear-repository`.
    Clear,
}

impl UpdateCommand {
    fn execute(self, deployment: &Deployment) -> super::CommandResult {
        if let Some(refusal) = connection::reach::refuse_linear(self.connection.as_ref()) {
            return refusal;
        }
        let Self {
            subject,
            name,
            repository,
            connection,
            default_branch,
            clear_repository,
            yes: _,
            org,
            options,
        } = self;
        let repository = match (repository, default_branch) {
            (Some(repository), default_branch) => Some(RepositoryChange::Set {
                repository,
                connection,
                default_branch,
            }),
            (None, Some(branch)) => Some(RepositoryChange::Branch(branch)),
            (None, None) => clear_repository.then_some(RepositoryChange::Clear),
        };
        execute_in_project(
            org,
            ProjectSubject::Named(subject),
            options,
            deployment,
            |options, organization, project| {
                update(
                    deployment,
                    &options,
                    organization,
                    project,
                    repository,
                    name.as_deref(),
                )
            },
        )
    }
}

/// One request `useful project update` sends, given the API and its idempotency key.
type UpdateRequest<'a> = Box<dyn Fn(&ProjectApi, &str) -> Result<Project, ProjectFailure> + 'a>;

/// Sends the repository request, then the rename, each only when asked and each under its own
/// key; the finder reads before either, so its refusals change nothing. A request that fails
/// after another succeeded is reported with what was applied (REQ-PROJECT-102).
fn update(
    deployment: &Deployment,
    options: &Options,
    organization: &str,
    project: &str,
    repository: Option<RepositoryChange>,
    name: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let api_url = deployment.fingerprint().api_url();
    let mut requests: Vec<(&'static str, UpdateRequest<'_>)> = Vec::with_capacity(2);
    match repository {
        Some(RepositoryChange::Set {
            repository,
            connection,
            default_branch,
        }) => {
            let reached = match connection::reach::find(
                deployment,
                options,
                organization,
                &repository,
                connection,
            )? {
                Ok(reached) => reached,
                Err(exit) => return Ok(exit),
            };
            requests.push((
                "repository_set",
                Box::new(move |api, key| {
                    api.set_repository(
                        organization,
                        project,
                        key,
                        reached.selector(),
                        reached.repository_id(),
                        default_branch.as_deref(),
                    )
                }),
            ));
        }
        Some(RepositoryChange::Branch(branch)) => requests.push((
            "repository_updated",
            Box::new(move |api, key| api.update_repository(organization, project, key, &branch)),
        )),
        Some(RepositoryChange::Clear) => requests.push((
            "repository_detached",
            Box::new(|api, key| api.detach_repository(organization, project, key)),
        )),
        None => {}
    }
    if let Some(name) = name {
        requests.push((
            "renamed",
            Box::new(move |api, key| api.rename(organization, project, key, name)),
        ));
    }
    let mut applied = Vec::with_capacity(requests.len());
    let mut updated = None;
    for (word, request) in requests {
        let key = useful_support::generate_idempotency_key()
            .context("generate project update request identity")?;
        let result = with_api(
            deployment,
            options.http.transport_policy(),
            &options.authentication,
            |api| request(api, &key),
        )?;
        match (result, &updated) {
            (Ok(project), _) => {
                applied.push(word);
                updated = Some(project);
            }
            (Err(failure), None) => {
                return output::write_failure(
                    api_url,
                    failure,
                    options.authentication.kind(),
                    options.json,
                );
            }
            (Err(failure), Some(project)) => {
                return output::write_partial_failure(
                    api_url,
                    failure,
                    &applied,
                    project,
                    &format!(
                        "Applied to the project {}: {}.\nRun the same command again to apply the rest.",
                        project.id,
                        applied.join(", ")
                    ),
                    options.authentication.kind(),
                    options.json,
                );
            }
        }
    }
    let Some(project) = updated else {
        bail!("project update names no change");
    };
    output::write_updated(api_url, &applied, &project, options.json)
}

fn resolve_pool_id(
    deployment: &Deployment,
    transport_policy: HttpTransportPolicy,
    authentication: &super::PrincipalAuthenticationArgs,
    organization: &str,
    pool: &PoolArg,
) -> anyhow::Result<Result<String, RunnerFailure>> {
    super::runner::with_api(deployment, transport_policy, authentication, |api| {
        pool.resolve_id(api, organization)
    })
}

// Human-session orchestration stays failure-domain-specific so project protocol
// rejection cannot be confused with a Cloud run outcome.
pub(in crate::cli) fn with_api<T>(
    deployment: &Deployment,
    transport_policy: HttpTransportPolicy,
    authentication: &super::PrincipalAuthenticationArgs,
    mut operation: impl FnMut(&ProjectApi) -> Result<T, ProjectFailure>,
) -> anyhow::Result<Result<T, ProjectFailure>> {
    let client = HttpClient::new(transport_policy)
        .map_err(|error| anyhow!(error))
        .context("prepare human session networking")?;
    super::execute_selected_api_operation(
        super::principal_api_context(
            &client,
            deployment,
            authentication,
            "acquire human session for project operation",
        ),
        |access_token| {
            let api = ProjectApi::new(
                deployment.fingerprint().api_url(),
                access_token,
                transport_policy,
            )
            .map_err(|error| anyhow!(error))
            .context("prepare project management networking")?;
            Ok(operation(&api))
        },
        ProjectFailure::credential_rejected,
        || ProjectFailure::Unauthenticated,
        ProjectFailure::Unreachable,
    )
}
