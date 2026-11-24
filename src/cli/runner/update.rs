//! `useful runner update`: moves a runner to another pool, renames it, or both.

use anyhow::Context;
use clap::{ArgGroup, Args};

use super::{
    CloudOptions, Deployment, ExitCode, OrgArgs, PoolArg, cloud, generate_idempotency_key,
};

pub(super) const ABOUT: &str = "Move or rename a runner registration";
pub(super) const AFTER_HELP: &str =
    "Eligibility:\n  The runner registration must be quiescent before moving it.";

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("change").args(["pool", "name"]).required(true).multiple(true)))]
pub(super) struct Command {
    #[arg(value_name = "RUNNER", help = "Runner ID or exact name")]
    runner: String,

    #[arg(
        long,
        value_name = PoolArg::VALUE_NAME,
        help = "Move the runner to this pool, by runner pool ID or exact name"
    )]
    pool: Option<PoolArg>,

    #[arg(long, help = "Set the exact runner name")]
    name: Option<String>,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: CloudOptions,
}

impl Command {
    pub(super) fn execute(self, deployment: &Deployment) -> super::super::CommandResult {
        let Self {
            runner,
            pool,
            name,
            org,
            options,
        } = self;
        super::execute_in(org, options, deployment, |options, organization| {
            Update {
                deployment,
                options: &options,
                organization,
            }
            .send(&runner, pool.as_ref(), name.as_deref())
        })
    }
}

/// What `useful runner update` sends, once the organization it acts in is known.
struct Update<'a> {
    deployment: &'a Deployment,
    options: &'a CloudOptions,
    organization: &'a str,
}

impl Update<'_> {
    /// Resolves `runner` once and sends its ID to both requests, since a rename would leave a
    /// name that no longer finds the runner: the move first and the rename last, each under a
    /// key of its own.
    fn send(
        &self,
        runner: &str,
        pool: Option<&PoolArg>,
        name: Option<&str>,
    ) -> anyhow::Result<ExitCode> {
        let runner = match self.request(|api, _| api.get_registration(self.organization, runner))? {
            Ok(runner) => runner,
            Err(failure) => return self.write_failure(&failure),
        };
        let mut applied = Vec::with_capacity(2);
        let mut updated = None;
        if let Some(pool) = pool {
            match self.request(|api, key| {
                api.move_registration(self.organization, &runner.id, pool, key)
            })? {
                Ok(moved) => {
                    applied.push("pool");
                    updated = Some(moved);
                }
                Err(failure) => return self.write_failure(&failure),
            }
        }
        if let Some(name) = name {
            match self.request(|api, key| {
                api.rename_registration(self.organization, &runner.id, key, name)
            })? {
                Ok(renamed) => {
                    applied.push("name");
                    updated = Some(renamed);
                }
                Err(failure) => {
                    let Some(moved) = &updated else {
                        return self.write_failure(&failure);
                    };
                    return cloud::write_partial_failure(
                        self.deployment.fingerprint().api_url(),
                        &failure,
                        &applied,
                        moved,
                        &format!(
                            "Runner {} moved to runner pool {} ({}); its name was not changed. Rename it with:\n  useful runner update {} --name {name} --org {}",
                            moved.id,
                            moved.runner_pool.name,
                            moved.runner_pool.id,
                            moved.id,
                            self.organization
                        ),
                        self.options.authentication.kind(),
                        self.options.json,
                    );
                }
            }
        }
        let Some(runner) = updated else {
            anyhow::bail!("runner update names no change");
        };
        cloud::write_runner_update(
            self.deployment.fingerprint().api_url(),
            &applied,
            &runner,
            self.options.json,
        )
    }

    /// Sends one request under a new key, which a refreshed sign-in resends unchanged.
    fn request<T>(
        &self,
        operation: impl Fn(&useful_api::RunnerApi, &str) -> Result<T, useful_api::RunnerFailure>,
    ) -> anyhow::Result<Result<T, useful_api::RunnerFailure>> {
        let key = generate_idempotency_key().context("generate runner update request identity")?;
        cloud::with_api(
            self.deployment,
            self.options.http.transport_policy(),
            &self.options.authentication,
            |api| operation(api, &key),
        )
    }

    fn write_failure(&self, failure: &useful_api::RunnerFailure) -> anyhow::Result<ExitCode> {
        self.options.write_failure(self.deployment, failure)
    }
}
