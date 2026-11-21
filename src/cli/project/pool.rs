//! `useful project pool add|remove`: one pool of the set of the project in effect
//! (REQ-PROJECT-90).

use anyhow::Context;
use clap::{Args, Subcommand};
use useful_api::{HttpTransportPolicy, Project, ProjectFailure};
use useful_human_auth::Deployment;

use super::{Options, OrgArgs, ProjectArgs, ProjectSubject};
use crate::cli::PoolArg;

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<Leaf>,
}

#[derive(Debug, Subcommand)]
enum Leaf {
    #[command(about = "Add a runner pool to the project's pools")]
    Add(Target),
    #[command(about = "Remove a runner pool from the project's pools")]
    Remove(Remove),
}

/// The pool to change and the organization and the project in effect it changes in.
#[derive(Debug, Args)]
struct Target {
    #[arg(value_name = PoolArg::VALUE_NAME, help = PoolArg::HELP)]
    pool: PoolArg,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    project: ProjectArgs,

    #[command(flatten)]
    options: Options,
}

#[derive(Debug, Args)]
struct Remove {
    #[command(flatten)]
    target: Target,

    #[command(flatten)]
    confirmation: crate::cli::ConfirmationArgs,
}

/// The one change a leaf makes to the set.
#[derive(Clone, Copy)]
enum Change {
    Add,
    Remove,
}

/// The request that applies a [`Change`] to the set read.
enum Write {
    /// `PUT …/runner-pools` with these pool IDs, in their order.
    Set(Vec<String>),
    /// `DELETE …/runner-pool`, which clears the set.
    Clear,
}

impl Change {
    /// The write that applies the change to `set`, or none when `set` already reflects it.
    fn write(self, set: &[String], pool_id: &str) -> Option<Write> {
        let held = set.iter().any(|id| id == pool_id);
        match self {
            Self::Add if held => None,
            Self::Add => Some(Write::Set(
                set.iter().cloned().chain([pool_id.to_owned()]).collect(),
            )),
            Self::Remove if !held => None,
            Self::Remove if set.len() == 1 => Some(Write::Clear),
            Self::Remove => Some(Write::Set(
                set.iter().filter(|id| *id != pool_id).cloned().collect(),
            )),
        }
    }

    const fn outcome(self) -> (&'static str, &'static str) {
        match self {
            Self::Add => ("runner_pool_added", "✓ Project runner pool added."),
            Self::Remove => ("runner_pool_removed", "✓ Project runner pool removed."),
        }
    }
}

impl Command {
    pub(super) fn execute(self) -> crate::cli::CommandResult {
        let Some(command) = self.command else {
            return crate::cli::print_help(&["project", "pool"]);
        };
        super::execute_command(command, |leaf, deployment| match leaf {
            Leaf::Add(target) => target.execute(deployment, Change::Add),
            Leaf::Remove(remove) => remove.target.execute(deployment, Change::Remove),
        })
    }
}

impl Target {
    /// Resolves the pool, then reads the project immediately before writing its set with the
    /// one change: the pool routes take no precondition, so a change made to the set between
    /// the read and the write is replaced (REQ-PROJECT-90).
    fn execute(self, deployment: &Deployment, change: Change) -> crate::cli::CommandResult {
        let Self {
            pool,
            org,
            project,
            options,
        } = self;
        super::execute_in_project(
            org,
            ProjectSubject::InEffect(project),
            options,
            deployment,
            |options, organization, project_id| {
                let transport_policy = options.http.transport_policy();
                let authentication = &options.authentication;
                let pool_id = match super::resolve_pool_id(
                    deployment,
                    transport_policy,
                    authentication,
                    organization,
                    &pool,
                )? {
                    Ok(pool_id) => pool_id,
                    Err(failure) => {
                        return crate::cli::runner::write_failure(
                            deployment,
                            &failure,
                            authentication,
                            options.json,
                        );
                    }
                };
                let result = change_set(
                    deployment,
                    transport_policy,
                    authentication,
                    (organization, project_id),
                    &pool_id,
                    change,
                )?;
                let (outcome, heading) = change.outcome();
                super::output::write_project(
                    deployment.fingerprint().api_url(),
                    result,
                    outcome,
                    heading,
                    authentication.kind(),
                    options.json,
                )
            },
        )
    }
}

/// Reads the project and sends the one write that applies `change` with `pool_id` to its set,
/// or none when the set already reflects it, which reports the project as read.
fn change_set(
    deployment: &Deployment,
    transport_policy: HttpTransportPolicy,
    authentication: &crate::cli::PrincipalAuthenticationArgs,
    (organization, project_id): (&str, &str),
    pool_id: &str,
    change: Change,
) -> anyhow::Result<Result<Project, ProjectFailure>> {
    let project = match super::with_api(deployment, transport_policy, authentication, |api| {
        api.get(organization, project_id)
    })? {
        Ok(project) => project,
        Err(failure) => return Ok(Err(failure)),
    };
    let set: Vec<String> = project
        .runner_pools
        .iter()
        .flatten()
        .map(|pool| pool.id.clone())
        .collect();
    let Some(write) = change.write(&set, pool_id) else {
        return Ok(Ok(project));
    };
    let key = useful_support::generate_idempotency_key()
        .context("generate project runner pool request identity")?;
    super::with_api(
        deployment,
        transport_policy,
        authentication,
        |api| match &write {
            Write::Set(ids) => api.set_runner_pools(organization, project_id, &key, ids),
            Write::Clear => api.remove_runner_pool(organization, project_id, &key),
        },
    )
}
