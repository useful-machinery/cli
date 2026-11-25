mod cloud;
mod credential;
mod doctor;
mod join_key;
mod pool;
mod prune;
mod serve;
mod show;
mod sync;
mod update;
mod watch;

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand, ValueEnum};

use crate::exit_code::ExitCode;
use useful_human_auth::Deployment;
use useful_support::generate_idempotency_key;

use super::context::OrgArgs;
use super::{PaginationArgs, PoolArg};

pub(super) const ABOUT: &str = "Manage the Useful Machinery runner";
const NAME: &str = "runner";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<RunnerCommand>,
}

#[derive(Debug, Subcommand)]
enum RunnerCommand {
    #[command(about = credential::ABOUT, after_help = CREDENTIAL_AFTER_HELP)]
    Credential(credential::Command),
    #[command(
        about = "Set whether a runner's runs use Cloud or host credentials",
        after_help = CREDENTIALS_AFTER_HELP
    )]
    Credentials(CredentialsCommand),
    #[command(
        about = "Delete a runner registration",
        after_help = "Eligibility:\n  The runner registration must be quiescent before deletion."
    )]
    Delete(DeleteCommand),
    #[command(about = "Disable a runner registration")]
    Disable(ModeCommand),
    #[command(about = doctor::ABOUT)]
    Doctor(doctor::Command),
    #[command(about = "Drain a runner registration")]
    Drain(ModeCommand),
    #[command(about = "Enable a runner registration")]
    Enable(ModeCommand),
    #[command(about = join_key::ABOUT)]
    JoinKey(join_key::Command),
    #[command(
        about = "List runner registrations",
        after_help = "Pool:\n  With --pool, the command reads every page and prints the pool's runners with no cursor."
    )]
    List(ListCommand),
    #[command(about = pool::ABOUT)]
    Pool(pool::Command),
    #[command(about = prune::ABOUT)]
    Prune(prune::Command),
    #[command(about = serve::ABOUT)]
    Serve(serve::Command),
    #[command(about = show::ABOUT, after_help = show::AFTER_HELP)]
    Show(show::Command),
    #[command(about = sync::ABOUT)]
    Sync(sync::Command),
    #[command(about = update::ABOUT, after_help = update::AFTER_HELP)]
    Update(update::Command),
    #[command(about = watch::ABOUT)]
    Watch(watch::Command),
}

// `runner credential` and `runner credentials` differ by one letter, so each help names
// the other.
const CREDENTIAL_AFTER_HELP: &str = "Credential mode:\n  To set where the credentials of a runner's runs come from, use useful runner credentials.";
const CREDENTIALS_AFTER_HELP: &str = "Credential mode:\n  Once set, the mode can change between cloud and host but cannot be cleared.\n\nEnrollment credentials:\n  To manage the credentials the runner itself authenticates to Cloud with, use useful runner credential.";

type CloudOptions = super::CommonArgs<super::RunnerJson, super::PrincipalAuthenticationArgs>;

impl CloudOptions {
    fn write_failure(
        &self,
        deployment: &Deployment,
        failure: &useful_api::RunnerFailure,
    ) -> anyhow::Result<ExitCode> {
        cloud::write_failure(
            deployment.fingerprint().api_url(),
            failure,
            self.authentication.kind(),
            self.json,
        )
    }
}

#[derive(Debug, Args)]
struct ListCommand {
    // The API's registration list takes no pool, so `--pool` reads every page and keeps the
    // pool's runners; a page and a cursor mean nothing then.
    #[arg(
        long,
        value_name = PoolArg::VALUE_NAME,
        help = "List only this pool's runners, by runner pool ID or exact name",
        conflicts_with_all = ["limit", "cursor"]
    )]
    pool: Option<PoolArg>,

    #[command(flatten)]
    pagination: PaginationArgs,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: CloudOptions,
}

// The runner a Cloud leaf acts on, in the organization in effect.
#[derive(Debug, Args)]
struct RunnerTarget {
    #[arg(value_name = "RUNNER", help = "Runner ID or exact name")]
    runner: String,

    #[command(flatten)]
    org: OrgArgs,
}

#[derive(Debug, Args)]
struct ModeCommand {
    #[command(flatten)]
    target: RunnerTarget,

    #[command(flatten)]
    options: CloudOptions,
}

#[derive(Debug, Args)]
struct CredentialsCommand {
    #[command(flatten)]
    target: RunnerTarget,

    #[arg(
        value_enum,
        value_name = "MODE",
        help = "Source of the credentials the runner's runs use"
    )]
    mode: CredentialModeArgument,

    #[command(flatten)]
    options: CloudOptions,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CredentialModeArgument {
    Cloud,
    Host,
}

impl From<CredentialModeArgument> for useful_api::RunnerCredentialMode {
    fn from(mode: CredentialModeArgument) -> Self {
        match mode {
            CredentialModeArgument::Cloud => Self::Cloud,
            CredentialModeArgument::Host => Self::Host,
        }
    }
}

#[derive(Debug, Args)]
struct DeleteCommand {
    #[command(flatten)]
    target: RunnerTarget,

    #[command(flatten)]
    confirmation: super::ConfirmationArgs,

    #[command(flatten)]
    options: CloudOptions,
}

impl Command {
    pub(super) fn execute(self) -> super::CommandResult {
        match self.command {
            None => super::print_help(&[NAME]),
            Some(RunnerCommand::Pool(command)) => command.execute(),
            Some(RunnerCommand::Prune(command)) => command.execute(),
            Some(RunnerCommand::Credential(command)) => command.execute(),
            Some(RunnerCommand::Credentials(command)) => {
                execute_in_cloud(command, CredentialsCommand::execute)
            }
            Some(RunnerCommand::JoinKey(command)) => command.execute(),
            Some(RunnerCommand::List(command)) => execute_in_cloud(command, ListCommand::execute),
            Some(RunnerCommand::Show(command)) => command.execute(),
            Some(RunnerCommand::Enable(command)) => {
                execute_in_cloud(command, |command, deployment| {
                    command.execute(
                        deployment,
                        useful_api::RunnerRegistrationMode::Enabled,
                        "enabled",
                        "✓ Runner enabled.",
                    )
                })
            }
            Some(RunnerCommand::Drain(command)) => {
                execute_in_cloud(command, |command, deployment| {
                    command.execute(
                        deployment,
                        useful_api::RunnerRegistrationMode::Draining,
                        "draining",
                        "✓ Runner draining.",
                    )
                })
            }
            Some(RunnerCommand::Disable(command)) => {
                execute_in_cloud(command, |command, deployment| {
                    command.execute(
                        deployment,
                        useful_api::RunnerRegistrationMode::Disabled,
                        "disabled",
                        "✓ Runner disabled.",
                    )
                })
            }
            Some(RunnerCommand::Update(command)) => {
                execute_in_cloud(command, update::Command::execute)
            }
            Some(RunnerCommand::Delete(command)) => command.execute(),
            Some(RunnerCommand::Doctor(command)) => command.execute(),
            Some(RunnerCommand::Serve(command)) => command.execute(),
            Some(RunnerCommand::Sync(command)) => command.execute(),
            Some(RunnerCommand::Watch(command)) => command.execute(),
        }
    }
}

fn operator_config_path(path: &Path) -> anyhow::Result<PathBuf> {
    std::path::absolute(path)
        .with_context(|| format!("resolve runner operator configuration {}", path.display()))
}

/// The operator configuration of the command that prepares the host, `serve`:
/// the file `--config` names, which touches no runner home, or else the runner
/// home's, created where it is missing.
fn initialized_operator_config_path(config: Option<&Path>) -> anyhow::Result<PathBuf> {
    match config {
        Some(path) => operator_config_path(path),
        None => runner_home()?.initialize().map_err(runner_home_failure),
    }
}

/// The control socket of a command that only asks the live runner, `show` with no `RUNNER`,
/// `watch`, `prune` and `sync`: the one the file `--config` names, which touches no runner home, or
/// else the one the runner home's configuration names, the home's `runner/control.sock` when it
/// holds none. Creates nothing.
fn configured_control_socket_path(config: Option<&Path>) -> anyhow::Result<PathBuf> {
    match config {
        Some(path) => {
            let config_path = operator_config_path(path)?;
            useful_runner::load_control_socket_path(&config_path).with_context(|| {
                format!(
                    "load runner operator configuration {}",
                    config_path.display()
                )
            })
        }
        None => runner_home()?
            .configured_control_socket_path()
            .map_err(runner_home_failure),
    }
}

/// Where `doctor`'s check that needs the operator configuration finds it when
/// it runs: the file `--config` names, which touches no runner home, or else
/// the runner home's; `None` when there is no `--config` and the `useful` home
/// cannot be located. Reads and creates nothing.
fn doctor_operator_config(
    config: Option<&Path>,
) -> anyhow::Result<Option<useful_runner::OperatorConfigSource>> {
    Ok(match config {
        Some(path) => Some(useful_runner::OperatorConfigSource::File(
            operator_config_path(path)?,
        )),
        None => located_runner_home()?.map(useful_runner::OperatorConfigSource::Home),
    })
}

/// The runner home of the `useful` home the environment selects, for a command
/// given no `--config`. Resolving it reads and creates nothing.
fn runner_home() -> anyhow::Result<useful_runner::RunnerHome> {
    located_runner_home()?
        .ok_or_else(|| unlocated_useful_home(&useful_execution::DefinitionError::HomeUnavailable))
}

/// The runner home of the `useful` home the environment selects, `None` when
/// neither `USEFUL_HOME` nor `HOME` names one.
fn located_runner_home() -> anyhow::Result<Option<useful_runner::RunnerHome>> {
    match useful_execution::WorkflowHome::from_environment() {
        Ok(useful_home) => useful_runner::RunnerHome::new(useful_home.root())
            .map(Some)
            .map_err(runner_home_failure),
        Err(useful_execution::DefinitionError::HomeUnavailable) => Ok(None),
        Err(error) => Err(unlocated_useful_home(&error)),
    }
}

fn unlocated_useful_home(error: &useful_execution::DefinitionError) -> anyhow::Error {
    anyhow::anyhow!(
        "locate the useful home: {error}\n\nSet USEFUL_HOME or HOME, or name the runner operator configuration with --config PATH."
    )
}

fn runner_home_failure(error: useful_runner::RunnerHomeError) -> anyhow::Error {
    use useful_runner::RunnerHomeError;
    let remedy = match &error {
        RunnerHomeError::UnsafeDirectory { path, .. } => format!(
            "Make {} a directory owned by the current user with mode 0700, or name a runner operator configuration with --config PATH.",
            path.display()
        ),
        RunnerHomeError::InvalidConfiguration { path, .. } => format!(
            "Correct {}, or name another runner operator configuration with --config PATH.",
            path.display()
        ),
        RunnerHomeError::StateConflict { config, .. } => format!(
            "Correct runnerStatePath in {}, or name the runner operator configuration to use with --config PATH.",
            config.display()
        ),
        _ => "Name a runner operator configuration with --config PATH.".to_owned(),
    };
    anyhow::anyhow!("{error}\n\n{remedy}")
}

fn completed_cloud_result<T>(
    deployment: &Deployment,
    result: Result<T, useful_api::RunnerFailure>,
    authentication: super::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<Result<T, ExitCode>> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(failure) => Ok(Err(cloud::write_failure(
            deployment.fingerprint().api_url(),
            &failure,
            authentication,
            json,
        )?)),
    }
}

/// The activation artifact a host enrolls with, from an issuance that carries
/// its secret; a replayed issuance carries none. The translation happens here
/// because the runner crate never references the human API client.
fn host_activation_artifact(
    issuance: &useful_api::RunnerActivationIssuance,
) -> Option<useful_runner::ActivationArtifact> {
    let issued = issuance.artifact.as_ref()?;
    Some(useful_runner::ActivationArtifact::from_parts(
        useful_runner::ActivationArtifactParts {
            activation_url: issued.activation_url.clone(),
            activation_token: issued.activation_token.clone(),
            runner_id: issued.runner_id.clone(),
            expires_at: issued.expires_at.clone(),
        },
    ))
}

impl ListCommand {
    fn execute(self, deployment: &Deployment) -> super::CommandResult {
        let Self {
            pool,
            pagination,
            org,
            options,
        } = self;
        execute_in(org, options, deployment, |options, organization| {
            let result = cloud::with_api(
                deployment,
                options.http.transport_policy(),
                &options.authentication,
                |api| match &pool {
                    Some(pool) => pool_registrations(api, organization, pool),
                    None => api.list_registrations(
                        organization,
                        pagination.limit,
                        pagination.cursor.as_deref(),
                    ),
                },
            )?;
            cloud::write_runner_list(
                deployment.fingerprint().api_url(),
                &result,
                options.authentication.kind(),
                options.json,
            )
        })
    }
}

/// Every runner of `pool` in `organization`, as one page with no cursor.
fn pool_registrations(
    api: &useful_api::RunnerApi,
    organization: &str,
    pool: &PoolArg,
) -> Result<useful_api::RunnerRegistrationList, useful_api::RunnerFailure> {
    let pool_id = pool.resolve_id(api, organization)?;
    Ok(useful_api::RunnerRegistrationList {
        items: every_registration(api, organization, Some(&pool_id))?,
        next_cursor: None,
    })
}

/// The runners of `organization`, the registration list read to its last page, keeping those
/// in the pool `pool_id` names when one is given: the list takes no pool of its own.
fn every_registration(
    api: &useful_api::RunnerApi,
    organization: &str,
    pool_id: Option<&str>,
) -> Result<Vec<useful_api::RunnerRegistration>, useful_api::RunnerFailure> {
    let mut items = super::paging::every_page(useful_api::RunnerFailure::Protocol, |cursor| {
        api.list_registrations(organization, Some(LIST_PAGE), cursor)
            .map(|page| (page.items, page.next_cursor))
    })?;
    if let Some(pool_id) = pool_id {
        items.retain(|runner| runner.runner_pool.id == pool_id);
    }
    Ok(items)
}

// The largest page the runner lists serve.
const LIST_PAGE: u16 = 200;

impl ModeCommand {
    fn execute(
        self,
        deployment: &Deployment,
        mode: useful_api::RunnerRegistrationMode,
        outcome: &'static str,
        heading: &'static str,
    ) -> super::CommandResult {
        let Self { target, options } = self;
        let RunnerTarget { runner, org } = target;
        execute_in(org, options, deployment, |options, organization| {
            let key =
                generate_idempotency_key().context("generate runner mode request identity")?;
            let result = cloud::with_api(
                deployment,
                options.http.transport_policy(),
                &options.authentication,
                |api| api.update_registration_mode(organization, &runner, &key, mode),
            )?;
            cloud::write_runner_transition(
                deployment.fingerprint().api_url(),
                &result,
                outcome,
                heading,
                options.authentication.kind(),
                options.json,
            )
        })
    }
}

impl CredentialsCommand {
    fn execute(self, deployment: &Deployment) -> super::CommandResult {
        let Self {
            target: RunnerTarget { runner, org },
            mode,
            options,
        } = self;
        execute_in(org, options, deployment, |options, organization| {
            let key = generate_idempotency_key()
                .context("generate runner credential mode request identity")?;
            let result = cloud::with_api(
                deployment,
                options.http.transport_policy(),
                &options.authentication,
                |api| {
                    api.update_registration_credential_mode(
                        organization,
                        &runner,
                        &key,
                        mode.into(),
                    )
                },
            )?;
            cloud::write_runner_transition(
                deployment.fingerprint().api_url(),
                &result,
                "credential_mode_set",
                "✓ Runner credential mode set.",
                options.authentication.kind(),
                options.json,
            )
        })
    }
}

impl DeleteCommand {
    fn execute(self) -> super::CommandResult {
        execute_deletion_command(
            self.target.org,
            self.target.runner,
            self.options,
            DeletionKind::Runner,
        )
    }
}

#[derive(Clone, Copy)]
enum DeletionKind {
    Runner,
    Pool,
}

/// A deletion once the organization it acts in is known: the reference sent, the value `--org`
/// or `USEFUL_ORG` gave or else the organization's ID.
struct DeletionInvocation {
    organization: String,
    resource_ref: String,
    options: CloudOptions,
    kind: DeletionKind,
}

fn execute_pool_deletion(
    org: OrgArgs,
    pool: PoolArg,
    options: CloudOptions,
) -> super::CommandResult {
    execute_deletion_command(org, pool.into_string(), options, DeletionKind::Pool)
}

// The organization in effect is resolved before the deletion's first request and outside its
// signal handling, so an interrupted read of the memberships commits nothing to report.
fn execute_deletion_command(
    org: OrgArgs,
    resource_ref: String,
    options: CloudOptions,
    kind: DeletionKind,
) -> super::CommandResult {
    super::execute_deployment_command(
        Some((org, resource_ref, options)),
        &[NAME],
        "configure Useful Machinery runner deletion",
        |(org, resource_ref, options), deployment| {
            execute_in(org, options, deployment, |options, organization| {
                execute_deletion_with_signals(
                    DeletionInvocation {
                        organization: organization.to_owned(),
                        resource_ref,
                        options,
                        kind,
                    },
                    deployment.clone(),
                )
            })
        },
    )
}

fn execute_deletion_with_signals(
    invocation: DeletionInvocation,
    deployment: Deployment,
) -> super::CommandResult {
    let signal_kind = invocation.kind;
    let signal_json = invocation.options.json;
    let signal_deployment = deployment.clone();
    super::execute_mutation_with_signals(
        "runner deletion",
        None::<String>,
        move |control| execute_deletion_blocking(invocation, &deployment, control),
        move |signal, snapshot| {
            super::report_dispatched_signal(signal, snapshot, |resource_id| {
                let Some(resource_id) = resource_id else {
                    return Ok(signal);
                };
                cloud::write_deletion_unknown(
                    signal_deployment.fingerprint().api_url(),
                    deletion_target(signal_kind, &resource_id),
                    signal_json,
                    signal,
                )
                .map_err(Into::into)
            })
        },
    )
}

fn execute_deletion_blocking(
    invocation: DeletionInvocation,
    deployment: &Deployment,
    control: &super::OperationControl<Option<String>>,
) -> super::CommandResult {
    let transport = invocation.options.http.transport_policy();
    let resolved = cloud::with_api(
        deployment,
        transport,
        &invocation.options.authentication,
        |api| match invocation.kind {
            DeletionKind::Runner => api
                .get_registration(&invocation.organization, &invocation.resource_ref)
                .map(|runner| runner.id),
            DeletionKind::Pool => api
                .get_pool(&invocation.organization, &invocation.resource_ref)
                .map(|pool| pool.id),
        },
    )?;
    let resource_id = match resolved {
        Ok(resource_id) => resource_id,
        Err(failure) => {
            return super::complete_operation(control, || {
                cloud::write_failure(
                    deployment.fingerprint().api_url(),
                    &failure,
                    invocation.options.authentication.kind(),
                    invocation.options.json,
                )
                .map_err(Into::into)
            });
        }
    };
    control.update_recovery(Some(resource_id.clone()));
    if control.is_cancelled() {
        return Ok(ExitCode::GeneralFailure);
    }
    let key = generate_idempotency_key().context("generate runner deletion request identity")?;
    let result = cloud::with_api(
        deployment,
        transport,
        &invocation.options.authentication,
        |api| {
            if !control.begin_dispatch() {
                return Err(useful_api::RunnerFailure::Unreachable(
                    useful_api::UnreachableCategory::Connection,
                ));
            }
            match invocation.kind {
                DeletionKind::Runner => {
                    api.delete_registration(&invocation.organization, &resource_id, &key)
                }
                DeletionKind::Pool => api.delete_pool(&invocation.organization, &resource_id, &key),
            }
        },
    )?;
    let target = deletion_target(invocation.kind, &resource_id);
    super::complete_operation(control, || {
        match result {
            Ok(()) => cloud::write_deletion_success(
                deployment.fingerprint().api_url(),
                target,
                invocation.options.json,
            ),
            Err(
                failure @ (useful_api::RunnerFailure::Unreachable(_)
                | useful_api::RunnerFailure::Protocol),
            ) => {
                let _ = failure;
                cloud::write_deletion_unknown(
                    deployment.fingerprint().api_url(),
                    target,
                    invocation.options.json,
                    ExitCode::Unavailable,
                )
            }
            Err(failure) => cloud::write_deletion_failure(
                deployment.fingerprint().api_url(),
                target,
                &failure,
                invocation.options.authentication.kind(),
                invocation.options.json,
            ),
        }
        .map_err(Into::into)
    })
}

fn deletion_target<'a>(kind: DeletionKind, resource_id: &'a str) -> cloud::DeletionTarget<'a> {
    match kind {
        DeletionKind::Runner => cloud::DeletionTarget::Runner(resource_id),
        DeletionKind::Pool => cloud::DeletionTarget::Pool(resource_id),
    }
}

pub(super) fn with_api<T>(
    deployment: &Deployment,
    transport_policy: useful_api::HttpTransportPolicy,
    authentication: &super::PrincipalAuthenticationArgs,
    operation: impl FnMut(&useful_api::RunnerApi) -> Result<T, useful_api::RunnerFailure>,
) -> anyhow::Result<Result<T, useful_api::RunnerFailure>> {
    cloud::with_api(deployment, transport_policy, authentication, operation)
}

pub(super) fn write_failure(
    deployment: &Deployment,
    failure: &useful_api::RunnerFailure,
    authentication: &super::PrincipalAuthenticationArgs,
    json: bool,
) -> anyhow::Result<ExitCode> {
    cloud::write_failure(
        deployment.fingerprint().api_url(),
        failure,
        authentication.kind(),
        json,
    )
}

/// Runs a Cloud leaf that acts in the organization in effect, once the deployment is loaded.
fn execute_in_cloud<T>(
    command: T,
    execute: impl FnOnce(T, &Deployment) -> super::CommandResult,
) -> super::CommandResult {
    super::execute_deployment_command(Some(command), &[NAME], CLOUD_CONTEXT, execute)
}

const CLOUD_CONTEXT: &str = "configure Useful Machinery runner administration";

/// Runs `run` with `options` and the organization reference to send, the value `--org` or
/// `USEFUL_ORG` gave or else the organization's ID, in the organization in effect. A
/// refused read of the memberships is written as the family writes its own failures, and
/// a failure `run` ends with keeps its exit code.
fn execute_in<E: Into<super::CommandFailure>>(
    org: OrgArgs,
    options: CloudOptions,
    deployment: &Deployment,
    run: impl FnOnce(CloudOptions, &str) -> Result<ExitCode, E>,
) -> super::CommandResult {
    super::context::execute_in_keeping_exit(
        org,
        options,
        deployment,
        cloud::write_context_failure,
        run,
    )
}

use anyhow::Context as _;
