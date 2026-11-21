//! `useful runner join-key`: a pool's join keys and the runners' single-runner keys
//! (REQ-RUNNERENROLL-1, REQ-RUNNERENROLL-10, REQ-RUNNERENROLL-11, REQ-RUNNERENROLL-93,
//! REQ-RUNNERENROLL-94).

mod single;

use std::io::{self, Write};

use anyhow::{Context, anyhow};
use clap::{Args, Subcommand};
use serde::Serialize;
use zeroize::Zeroizing;

use super::{CloudOptions, LIST_PAGE, OrgArgs, PoolArg, cloud, completed_cloud_result};
use crate::cli::{CommandFailure, CommandResult};
use crate::exit_code::ExitCode;
use useful_api::{RunnerActivation, RunnerApi, RunnerFailure};
use useful_human_auth::Deployment;
use useful_runner::ArtifactDestination;
use useful_support::generate_idempotency_key;

pub(super) const ABOUT: &str = "Manage runner join keys and single-runner keys";
const COMMAND_PATH: &[&str] = &["runner", "join-key"];
// The same help as the `account integration` and `runner credential` leaves' `--runner`, one help
// class.
const RUNNER_HELP: &str = "Runner ID or exact name";
// Largest unit first, so a removal time prints as it is usually written.
const DURATION_UNITS: [(&str, u32); 3] = [("d", 86_400), ("h", 3_600), ("m", 60)];

// useful-api does not name its join-key models, so these documents borrow them generically.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinKeyResult<'a, K> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    join_key: &'a K,
    #[serde(skip_serializing_if = "Option::is_none")]
    join_key_file: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinKeyListResult<'a, K> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    items: &'a [K],
    single_runner_keys: &'a [RunnerActivation],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SingleRunnerKeyRevocationResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    activation: &'a RunnerActivation,
}

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<JoinKeyCommand>,
}

#[derive(Debug, Subcommand)]
enum JoinKeyCommand {
    #[command(
        about = "Issue a runner join key or single-runner key",
        after_help = "Keys:\n  Without --runner, the key is the pool's join key: any number of hosts can join the pool with it until it expires or is revoked.\n  With --runner, the key is a single-runner key: one host enrolls that runner with it within an hour. A name no runner has registers the runner first."
    )]
    Issue(IssueCommand),
    #[command(
        about = "List runner join keys and single-runner keys",
        after_help = "Reads:\n  Without --runner, the command reads every page of the join keys, of the runners and of each runner's single-runner keys, and passes over a runner whose keys you may not read."
    )]
    List(ListCommand),
    #[command(
        about = "Revoke a runner join key or single-runner key",
        after_help = "Revocation:\n  The runners that joined with a pool's join key stay in the pool. Without --runner, a single-runner key is found by reading the runners' keys."
    )]
    Revoke(RevokeCommand),
}

// `--member` requires `--runner` through this group, since clap passes over an argument that
// is missing when one it conflicts with, such as `--expires-in`, is present.
#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("single_runner").args(["runner"])))]
struct IssueCommand {
    // With neither a pool nor a member named, the key is for the caller's own personal pool.
    #[arg(
        long,
        value_name = PoolArg::VALUE_NAME,
        conflicts_with = "member",
        help = "Runner pool ID or exact name; with neither --pool nor --member, your own personal pool"
    )]
    pool: Option<PoolArg>,

    #[arg(
        long,
        value_name = "MEMBER",
        value_parser = single::parse_member,
        requires = "single_runner",
        help = "Register the runner in this member's personal pool: principal ID, membership ID or verified email address"
    )]
    member: Option<single::MemberArg>,

    #[arg(
        long,
        value_name = "RUNNER",
        conflicts_with_all = ["expires_in", "remove_after"],
        help = "Issue a single-runner key for this runner ID or exact name; a name no runner has registers the runner"
    )]
    runner: Option<String>,

    #[arg(
        long,
        value_name = "DURATION",
        value_parser = parse_expiry,
        required_unless_present = "runner",
        help = "Set how long the pool's key admits hosts, from 1m to 365d"
    )]
    expires_in: Option<i32>,

    #[arg(
        long,
        value_name = "DURATION",
        value_parser = parse_removal_time,
        // The API requires a removal time, and 30 days is the longest it admits.
        default_value = "30d",
        help = "Set how long a runner that joined may stay offline before removal, from 5m to 30d"
    )]
    remove_after: i32,

    #[arg(
        long,
        value_name = "PATH|-",
        help = "Create the protected key file, or with - or when omitted write only the key to standard output"
    )]
    key_file: Option<String>,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: CloudOptions,
}

#[derive(Debug, Args)]
struct ListCommand {
    #[arg(
        long,
        value_name = PoolArg::VALUE_NAME,
        conflicts_with = "runner",
        help = "List only this pool's keys and runners, by runner pool ID or exact name"
    )]
    pool: Option<PoolArg>,

    #[arg(long, value_name = "RUNNER", help = RUNNER_HELP)]
    runner: Option<String>,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: CloudOptions,
}

#[derive(Debug, Args)]
struct RevokeCommand {
    #[arg(
        value_name = "KEY",
        value_parser = parse_key_id,
        help = "Runner join key ID or single-runner key ID"
    )]
    key: KeyId,

    #[arg(long, value_name = "RUNNER", help = RUNNER_HELP)]
    runner: Option<String>,

    #[command(flatten)]
    confirmation: super::super::ConfirmationArgs,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: CloudOptions,
}

/// A key as `revoke` names it; the two kinds are told apart by the ID alone.
#[derive(Clone, Debug)]
enum KeyId {
    Pool(String),
    SingleRunner(String),
}

fn parse_key_id(value: &str) -> Result<KeyId, String> {
    if useful_support::valid_typed_id(value, "rjk_") {
        Ok(KeyId::Pool(value.to_owned()))
    } else if useful_support::valid_typed_id(value, "rna_") {
        Ok(KeyId::SingleRunner(value.to_owned()))
    } else {
        Err("must be an exact runner join key ID (rjk_) or single-runner key ID (rna_)".to_owned())
    }
}

impl Command {
    pub(super) fn execute(self) -> CommandResult {
        let Some(command) = self.command else {
            return super::super::print_help(COMMAND_PATH);
        };
        super::execute_in_cloud(command, |command, deployment| match command {
            JoinKeyCommand::Issue(command) => command.execute(deployment),
            JoinKeyCommand::List(command) => command.execute(deployment),
            JoinKeyCommand::Revoke(command) => command.execute(deployment),
        })
    }
}

impl IssueCommand {
    fn execute(self, deployment: &Deployment) -> CommandResult {
        let Self {
            pool,
            member,
            runner,
            expires_in,
            remove_after,
            key_file,
            org,
            options,
        } = self;
        // The file exists before the key does, so a refused path costs no key.
        let destination = prepare_destination(key_file.as_deref(), options.json)?;
        if let Some(runner) = runner {
            return single::issue(
                single::Request {
                    runner,
                    pool,
                    member,
                },
                destination,
                org,
                options,
                deployment,
            );
        }
        let expires_in =
            expires_in.ok_or_else(|| anyhow!("--expires-in is required without --runner"))?;
        super::execute_in(org, options, deployment, |options, organization| {
            PoolKey {
                pool,
                expires_in,
                remove_after,
            }
            .issue(deployment, &options, organization, destination)
        })
    }
}

/// A pool's join key to issue (REQ-RUNNERENROLL-93).
struct PoolKey {
    pool: Option<PoolArg>,
    expires_in: i32,
    remove_after: i32,
}

impl PoolKey {
    fn issue(
        self,
        deployment: &Deployment,
        options: &CloudOptions,
        organization: &str,
        destination: ArtifactDestination,
    ) -> anyhow::Result<ExitCode> {
        let key = generate_idempotency_key().context("generate join key request identity")?;
        let result = cloud::with_api(
            deployment,
            options.http.transport_policy(),
            &options.authentication,
            |api| {
                let pool_id = match &self.pool {
                    Some(pool) => pool.resolve_id(api, organization)?,
                    None => api.get_personal_pool(organization)?.id,
                };
                api.issue_join_key(
                    organization,
                    &pool_id,
                    &key,
                    self.expires_in,
                    self.remove_after,
                )
            },
        )?;
        let issuance = match completed_cloud_result(
            deployment,
            result,
            options.authentication.kind(),
            options.json,
        )? {
            Ok(issuance) => issuance,
            Err(exit_code) => return Ok(exit_code),
        };
        let artifact = issuance.artifact.as_deref().ok_or_else(|| {
            anyhow!(
                "join key issuance replay omitted its secret; issue a replacement join key with a new command"
            )
        })?;
        let mut line = Zeroizing::new(serde_json::to_vec(artifact).context("serialize join key")?);
        line.push(b'\n');
        let join_key_file = write_key(destination, &line)?;
        let join_key = &*issuance.join_key;
        let Some(join_key_file) = join_key_file else {
            // Standard output carries the key alone, so the status goes to stderr.
            writeln!(
                io::stderr().lock(),
                "✓ Runner join key {} issued for pool {}.",
                join_key.id,
                join_key.runner_pool_id
            )?;
            return Ok(ExitCode::Success);
        };
        if options.json {
            cloud::write_json(&JoinKeyResult {
                schema_version: 1,
                deployment: deployment.fingerprint().api_url(),
                outcome: "issued",
                join_key,
                join_key_file: Some(&join_key_file),
            })?;
        } else {
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            writeln!(stdout, "✓ Runner join key issued.\n")?;
            writeln!(stdout, "  Join key:      {}", join_key.id)?;
            writeln!(stdout, "  Pool:          {}", join_key.runner_pool_id)?;
            writeln!(stdout, "  Expires:       {}", join_key.expires_at)?;
            writeln!(
                stdout,
                "  Remove after:  {}",
                duration_text(join_key.offline_removal_seconds)
            )?;
            writeln!(stdout, "  Join key file: {join_key_file}")?;
        }
        Ok(ExitCode::Success)
    }
}

/// The keys `list` prints: the pool keys, then the single-runner keys of every runner in scope.
struct Listing<K> {
    join_keys: Vec<K>,
    single_runner_keys: Vec<RunnerActivation>,
}

impl ListCommand {
    fn execute(self, deployment: &Deployment) -> CommandResult {
        let Self {
            pool,
            runner,
            org,
            options,
        } = self;
        super::execute_in(org, options, deployment, |options, organization| {
            let result = cloud::with_api(
                deployment,
                options.http.transport_policy(),
                &options.authentication,
                |api| match &runner {
                    Some(runner) => {
                        let runner = api.get_registration(organization, runner)?;
                        Ok(Listing {
                            join_keys: Vec::new(),
                            single_runner_keys: every_activation(api, organization, &runner.id)?,
                        })
                    }
                    None => {
                        let pool_id = pool
                            .as_ref()
                            .map(|pool| pool.resolve_id(api, organization))
                            .transpose()?;
                        let join_keys =
                            crate::cli::paging::every_page(RunnerFailure::Protocol, |cursor| {
                                api.list_join_keys(
                                    organization,
                                    pool_id.as_deref(),
                                    Some(LIST_PAGE),
                                    cursor,
                                )
                                .map(|page| (page.items, page.next_cursor))
                            })?;
                        Ok(Listing {
                            join_keys,
                            single_runner_keys: readable_keys(
                                api,
                                organization,
                                pool_id.as_deref(),
                            )?,
                        })
                    }
                },
            )?;
            let listing = match result {
                Ok(listing) => listing,
                Err(failure) => return options.write_failure(deployment, &failure),
            };
            let api_url = deployment.fingerprint().api_url();
            if options.json {
                cloud::write_json(&JoinKeyListResult {
                    schema_version: 1,
                    deployment: api_url,
                    outcome: "listed",
                    items: &listing.join_keys,
                    single_runner_keys: &listing.single_runner_keys,
                })?;
                return Ok(ExitCode::Success);
            }
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            writeln!(stdout, "✓ Runner join keys listed.\n")?;
            for join_key in &listing.join_keys {
                writeln!(
                    stdout,
                    "  Join key: {}  Pool: {}  Issuer: {}  State: {}  Expires: {}  Remove after: {}",
                    join_key.id,
                    join_key.runner_pool_id,
                    join_key.issued_by_principal_id,
                    cloud::enum_text(&join_key.state)?,
                    join_key.expires_at,
                    duration_text(join_key.offline_removal_seconds)
                )?;
            }
            for key in &listing.single_runner_keys {
                writeln!(
                    stdout,
                    "  Single-runner key: {}  Runner: {}  State: {}  Expires: {}",
                    key.id,
                    key.runner_id,
                    cloud::enum_text(&key.state)?,
                    key.expires_at
                )?;
            }
            if !listing.join_keys.is_empty() || !listing.single_runner_keys.is_empty() {
                writeln!(stdout)?;
            }
            writeln!(stdout, "  Deployment: {api_url}")?;
            Ok(ExitCode::Success)
        })
    }
}

/// Every single-runner key of `runner_id`, its activation list read to its last page.
fn every_activation(
    api: &RunnerApi,
    organization: &str,
    runner_id: &str,
) -> Result<Vec<RunnerActivation>, RunnerFailure> {
    crate::cli::paging::every_page(RunnerFailure::Protocol, |cursor| {
        api.list_activations(organization, runner_id, Some(LIST_PAGE), cursor)
            .map(|page| (page.items, page.next_cursor))
    })
}

/// The single-runner keys of each runner of `organization`, of the pool `pool_id` names when
/// one is given; a runner whose keys the caller may not read is passed over
/// (REQ-RUNNERENROLL-10, REQ-RUNNERENROLL-12).
fn readable_keys(
    api: &RunnerApi,
    organization: &str,
    pool_id: Option<&str>,
) -> Result<Vec<RunnerActivation>, RunnerFailure> {
    let mut readable = Vec::new();
    for runner in super::every_registration(api, organization, pool_id)? {
        match every_activation(api, organization, &runner.id) {
            Ok(keys) => readable.extend(keys),
            Err(RunnerFailure::Forbidden) => {}
            Err(failure) => return Err(failure),
        }
    }
    Ok(readable)
}

/// The runner that holds the single-runner key `activation_id`: the runners read in order,
/// each runner's keys to their last page, stopping at the first that holds it; a runner whose
/// keys the caller may not read is passed over, and a key none holds is `NotFound`
/// (REQ-RUNNERENROLL-11).
fn holder_of(
    api: &RunnerApi,
    organization: &str,
    activation_id: &str,
) -> Result<String, RunnerFailure> {
    for runner in super::every_registration(api, organization, None)? {
        match every_activation(api, organization, &runner.id) {
            Ok(keys) if keys.iter().any(|key| key.id == activation_id) => return Ok(runner.id),
            Ok(_) | Err(RunnerFailure::Forbidden) => {}
            Err(failure) => return Err(failure),
        }
    }
    Err(RunnerFailure::NotFound)
}

impl RevokeCommand {
    fn execute(self, deployment: &Deployment) -> CommandResult {
        let Self {
            key,
            runner,
            confirmation: _,
            org,
            options,
        } = self;
        if matches!(key, KeyId::Pool(_)) && runner.is_some() {
            return Err(CommandFailure::with_exit_code(
                anyhow!(
                    "--runner names the runner of a single-runner key (rna_), and a pool's join key (rjk_) has none; nothing was revoked\n\nRun the command again without --runner."
                ),
                ExitCode::UsageError,
            ));
        }
        super::execute_in(
            org,
            options,
            deployment,
            |options, organization| match key {
                KeyId::Pool(join_key) => {
                    revoke_pool_key(deployment, &options, organization, &join_key)
                }
                KeyId::SingleRunner(activation) => revoke_single_runner_key(
                    deployment,
                    &options,
                    organization,
                    &activation,
                    runner.as_deref(),
                ),
            },
        )
    }
}

fn revoke_pool_key(
    deployment: &Deployment,
    options: &CloudOptions,
    organization: &str,
    join_key: &str,
) -> anyhow::Result<ExitCode> {
    let key = generate_idempotency_key().context("generate join key revocation identity")?;
    let result = cloud::with_api(
        deployment,
        options.http.transport_policy(),
        &options.authentication,
        |api| api.revoke_join_key(organization, join_key, &key),
    )?;
    let join_key = match result {
        Ok(join_key) => join_key,
        Err(failure) => return options.write_failure(deployment, &failure),
    };
    let api_url = deployment.fingerprint().api_url();
    if options.json {
        cloud::write_json(&JoinKeyResult {
            schema_version: 1,
            deployment: api_url,
            outcome: "revoked",
            join_key: &join_key,
            join_key_file: None,
        })?;
    } else {
        writeln!(
            io::stdout().lock(),
            "✓ Runner join key revoked.\n\n  Join key:   {}\n  Deployment: {api_url}",
            join_key.id
        )?;
    }
    Ok(ExitCode::Success)
}

fn revoke_single_runner_key(
    deployment: &Deployment,
    options: &CloudOptions,
    organization: &str,
    activation: &str,
    runner: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let key =
        generate_idempotency_key().context("generate single-runner key revocation identity")?;
    let result = cloud::with_api(
        deployment,
        options.http.transport_policy(),
        &options.authentication,
        |api| {
            let runner_id = match runner {
                Some(runner) => api.get_registration(organization, runner)?.id,
                None => holder_of(api, organization, activation)?,
            };
            api.revoke_activation(organization, &runner_id, activation, &key)
        },
    )?;
    let activation = match result {
        Ok(activation) => activation,
        Err(failure) => return options.write_failure(deployment, &failure),
    };
    let api_url = deployment.fingerprint().api_url();
    if options.json {
        cloud::write_json(&SingleRunnerKeyRevocationResult {
            schema_version: 1,
            deployment: api_url,
            outcome: "revoked",
            activation: &activation,
        })?;
    } else {
        writeln!(
            io::stdout().lock(),
            "✓ Single-runner key revoked.\n\n  Single-runner key: {}\n  Runner:            {}\n  Deployment:        {api_url}",
            activation.id,
            activation.runner_id
        )?;
    }
    Ok(ExitCode::Success)
}

/// Prepares where an issued key goes (REQ-RUNNERENROLL-5, REQ-RUNNERENROLL-62,
/// REQ-RUNNERENROLL-93): no `--key-file`, like `-`, means standard output, which structured
/// output never shares with a token; a path is a new file only its owner can read.
fn prepare_destination(
    destination: Option<&str>,
    json: bool,
) -> anyhow::Result<ArtifactDestination> {
    match destination {
        None if json => Err(anyhow!("--json requires --key-file PATH")),
        Some("-") if json => Err(anyhow!("--json cannot be combined with --key-file -")),
        None => Ok(ArtifactDestination::Stdout),
        Some(path) => {
            ArtifactDestination::prepare(path).with_context(|| format!("create key file {path}"))
        }
    }
}

/// Writes `line`, one line of JSON, to the prepared destination, so the same text can be
/// pasted at the `--join-key` prompt or held in an environment variable; answers the file's
/// path, or none for standard output.
fn write_key(destination: ArtifactDestination, line: &[u8]) -> anyhow::Result<Option<String>> {
    let path = destination
        .file_path()
        .map(|path| path.display().to_string());
    destination.write(line).with_context(|| match &path {
        Some(path) => format!("write key file {path}"),
        None => "write key to stdout".to_owned(),
    })?;
    Ok(path)
}

fn parse_expiry(value: &str) -> Result<i32, String> {
    parse_duration_within(value, 60..=31_536_000, "from 1m to 365d")
}

fn parse_removal_time(value: &str) -> Result<i32, String> {
    parse_duration_within(value, 300..=2_592_000, "from 5m to 30d")
}

/// Reads a whole number of minutes, hours or days, such as `30m`, `12h` or
/// `7d`, as seconds within `bounds`.
fn parse_duration_within(
    value: &str,
    bounds: std::ops::RangeInclusive<u32>,
    range: &str,
) -> Result<i32, String> {
    let invalid = || {
        format!("must be a whole number of minutes, hours or days, {range}, such as 30m, 12h or 7d")
    };
    let (quantity, unit_seconds) =
        super::super::split_unit_suffix(value, &DURATION_UNITS).ok_or_else(invalid)?;
    if quantity.is_empty() || !quantity.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    quantity
        .parse::<u32>()
        .ok()
        .and_then(|quantity| quantity.checked_mul(unit_seconds))
        .filter(|seconds| bounds.contains(seconds))
        .and_then(|seconds| i32::try_from(seconds).ok())
        .ok_or_else(invalid)
}

fn duration_text(seconds: i32) -> String {
    let Ok(unsigned) = u32::try_from(seconds) else {
        return format!("{seconds}s");
    };
    DURATION_UNITS
        .into_iter()
        .find(|(_, unit_seconds)| unsigned % unit_seconds == 0)
        .map_or_else(
            || format!("{seconds}s"),
            |(suffix, unit_seconds)| format!("{}{suffix}", unsigned / unit_seconds),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ-RUNNERENROLL-93
    #[test]
    fn join_key_durations_read_minutes_hours_and_days_within_their_bounds() {
        assert_eq!(parse_expiry("1m"), Ok(60));
        assert_eq!(parse_expiry("7d"), Ok(604_800));
        assert_eq!(parse_expiry("365d"), Ok(31_536_000));
        assert_eq!(parse_removal_time("5m"), Ok(300));
        assert_eq!(parse_removal_time("30d"), Ok(2_592_000));
        for refused in [
            "",
            "d",
            "0m",
            "366d",
            "60",
            "60s",
            "+5m",
            "1.5h",
            "4294967296m",
            "7dé",
        ] {
            assert!(parse_expiry(refused).is_err(), "{refused:?}");
        }
        assert!(parse_removal_time("4m").is_err());
        assert!(parse_removal_time("31d").is_err());
        assert_eq!(duration_text(3_600), "1h");
        assert_eq!(duration_text(604_800), "7d");
        assert_eq!(duration_text(5_400), "90m");
        assert_eq!(duration_text(301), "301s");
    }
}
