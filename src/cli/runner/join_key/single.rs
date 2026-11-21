//! The single-runner key of `useful runner join-key issue --runner`: a runner the organization
//! holds gets a new key, and a name no runner has registers the runner and issues its first
//! (REQ-RUNNERENROLL-1, REQ-RUNNERENROLL-2, REQ-RUNNERENROLL-8, REQ-RUNNERPOOL-86).

use std::io::{self, Write};

use anyhow::{Context, anyhow};
use serde::Serialize;
use zeroize::Zeroizing;

use super::super::{CloudOptions, OrgArgs, PoolArg, cloud, completed_cloud_result};
use crate::cli::org::member::{self, Member, Resolution, Unresolved};
use crate::cli::{CommandFailure, CommandResult};
use crate::exit_code::ExitCode;
use useful_api::{
    RunnerActivation, RunnerActivationIssuance, RunnerApi, RunnerFailure, RunnerRegistration,
};
use useful_human_auth::Deployment;
use useful_runner::ArtifactDestination;
use useful_support::generate_idempotency_key;

/// The result of a single-runner key, for a runner it registered or one that existed; never
/// the token.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SingleRunnerKeyResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    runner: &'a RunnerRegistration,
    activation: &'a RunnerActivation,
    activation_file: &'a str,
}

/// A member as `--member` names one: a principal ID, sent as it is, or a membership ID or a
/// verified email address, which the organization's directory resolves (REQ-MEMBER-48).
#[derive(Clone, Debug)]
pub(super) enum MemberArg {
    Principal(String),
    Directory(Member),
}

pub(super) fn parse_member(value: &str) -> Result<MemberArg, String> {
    if useful_support::valid_typed_id(value, "prn_") {
        return Ok(MemberArg::Principal(value.to_owned()));
    }
    member::parse_member(value).map(MemberArg::Directory).map_err(|_| {
        "member must be an exact prn_ principal ID, an exact mem_ membership ID or a verified email address"
            .to_owned()
    })
}

/// What `--runner`, `--pool` and `--member` name.
pub(super) struct Request {
    pub(super) runner: String,
    pub(super) pool: Option<PoolArg>,
    pub(super) member: Option<MemberArg>,
}

/// How the single-runner key's requests ended.
enum Outcome {
    Issued {
        runner: RunnerRegistration,
        issuance: RunnerActivationIssuance,
        registered: bool,
    },
    /// The runner was registered and its key was not issued.
    ActivationFailed {
        runner: RunnerRegistration,
        failure: RunnerFailure,
    },
    /// The runner exists in a pool other than the one `--pool` or `--member` names.
    OtherPool(RunnerRegistration),
}

impl Outcome {
    fn credential_rejected(&self) -> bool {
        matches!(
            self,
            Self::ActivationFailed { failure, .. } if failure.credential_rejected()
        )
    }
}

/// Issues the single-runner key `request` names in the organization in effect, written to
/// `destination`.
pub(super) fn issue(
    request: Request,
    destination: ArtifactDestination,
    org: OrgArgs,
    options: CloudOptions,
    deployment: &Deployment,
) -> CommandResult {
    let org_named = org.given();
    super::super::execute_in(org, options, deployment, |options, organization| {
        Issue {
            deployment,
            options: &options,
            organization,
            org_named,
        }
        .run(&request, destination)
    })
}

struct Issue<'a> {
    deployment: &'a Deployment,
    options: &'a CloudOptions,
    organization: &'a str,
    /// Whether `--org` named the organization, so the remedy of a failed key names it too.
    org_named: bool,
}

impl Issue<'_> {
    fn run(
        &self,
        request: &Request,
        destination: ArtifactDestination,
    ) -> Result<ExitCode, CommandFailure> {
        let principal = match &request.member {
            None => None,
            Some(MemberArg::Principal(principal)) => Some(principal.clone()),
            Some(MemberArg::Directory(member)) => match member.directory_row(
                self.deployment,
                self.options.http.transport_policy(),
                &self.options.authentication,
                self.organization,
            )? {
                Resolution::Member(row) => Some(row.principal_id),
                Resolution::Unresolved(Unresolved::NotFound) => {
                    return Ok(self.write_failure(&RunnerFailure::NotFound)?);
                }
                Resolution::Unresolved(Unresolved::Common(failure)) => {
                    return Ok(cloud::write_context_failure(
                        self.api_url(),
                        &failure,
                        self.options.authentication.kind(),
                        self.options.json,
                    )?);
                }
                Resolution::Ambiguous(refusal) => return Err(refusal),
            },
        };
        let registration_key =
            generate_idempotency_key().context("generate runner registration request identity")?;
        let activation_key =
            generate_idempotency_key().context("generate single-runner key request identity")?;
        // A registration that succeeded is not sent again when a rejected credential replays the
        // requests: the replay issues the key for the runner it registered.
        let mut registered = None;
        let result = cloud::with_api_retrying_rejected_result(
            self.deployment,
            self.options.http.transport_policy(),
            &self.options.authentication,
            |api| {
                let keys = Keys {
                    registration: &registration_key,
                    activation: &activation_key,
                };
                self.attempt(api, request, principal.as_deref(), keys, &mut registered)
            },
            Outcome::credential_rejected,
        )?;
        let result = match (result, registered) {
            (Err(failure), Some(runner)) => Ok(Outcome::ActivationFailed { runner, failure }),
            (result, _) => result,
        };
        let outcome = match completed_cloud_result(
            self.deployment,
            result,
            self.options.authentication.kind(),
            self.options.json,
        )? {
            Ok(outcome) => outcome,
            Err(exit_code) => return Ok(exit_code),
        };
        match outcome {
            Outcome::Issued {
                runner,
                issuance,
                registered,
            } => Ok(self.write_issued(&runner, &issuance, registered, destination)?),
            Outcome::ActivationFailed { runner, failure } => {
                let org = self.org_named.then_some(self.organization);
                Ok(cloud::write_activation_failure(
                    self.api_url(),
                    &failure,
                    org,
                    &runner.id,
                    self.options.authentication.kind(),
                    self.options.json,
                )?)
            }
            Outcome::OtherPool(runner) => Err(other_pool(&request.runner, &runner)),
        }
    }

    /// One pass of the requests: the runner looked up, registered when no runner has the name,
    /// checked against `--pool` or `--member` when it exists, and its key issued.
    fn attempt(
        &self,
        api: &RunnerApi,
        request: &Request,
        principal: Option<&str>,
        keys: Keys<'_>,
        registered: &mut Option<RunnerRegistration>,
    ) -> Result<Outcome, RunnerFailure> {
        let organization = self.organization;
        if let Some(runner) = registered.clone() {
            return Ok(activate_registered(
                api,
                organization,
                runner,
                keys.activation,
            ));
        }
        let runner = match api.get_registration(organization, &request.runner) {
            Ok(runner) => runner,
            // A name no runner has registers the runner; an ID names only a runner that exists.
            Err(RunnerFailure::NotFound)
                if !useful_support::valid_typed_id(&request.runner, "rnr_") =>
            {
                let pool_id = request
                    .pool
                    .as_ref()
                    .map(|pool| pool.resolve_id(api, organization))
                    .transpose()?;
                let runner = api.create_registration(
                    organization,
                    keys.registration,
                    pool_id.as_deref(),
                    principal,
                    Some(&request.runner),
                )?;
                *registered = Some(runner.clone());
                return Ok(activate_registered(
                    api,
                    organization,
                    runner,
                    keys.activation,
                ));
            }
            Err(failure) => return Err(failure),
        };
        if let Some(pool) = &request.pool
            && pool.resolve_id(api, organization)? != runner.runner_pool.id
        {
            return Ok(Outcome::OtherPool(runner));
        }
        if let Some(principal) = principal {
            let pool = api.get_pool(organization, &runner.runner_pool.id)?;
            if pool.member.as_ref().map(|member| member.id.as_str()) != Some(principal) {
                return Ok(Outcome::OtherPool(runner));
            }
        }
        let issuance = api.create_activation(organization, &runner.id, keys.activation)?;
        Ok(Outcome::Issued {
            runner,
            issuance,
            registered: false,
        })
    }

    fn write_issued(
        &self,
        runner: &RunnerRegistration,
        issuance: &RunnerActivationIssuance,
        registered: bool,
        destination: ArtifactDestination,
    ) -> anyhow::Result<ExitCode> {
        let artifact = super::super::host_activation_artifact(issuance).ok_or_else(|| {
            anyhow!(
                "single-runner key issuance replay omitted its secret; issue a replacement key with a new command"
            )
        })?;
        let mut line = Zeroizing::new(Vec::new());
        artifact
            .write_json(&mut *line)
            .map_err(|error| anyhow!(error))
            .context("serialize single-runner key")?;
        let Some(key_file) = super::write_key(destination, &line)? else {
            // Standard output carries the key alone, so the status goes to stderr.
            let status = if registered {
                format!(
                    "✓ Runner {} ({}) registered with a single-runner key.",
                    runner.name, runner.id
                )
            } else {
                format!("✓ Single-runner key issued for runner {}.", runner.id)
            };
            writeln!(io::stderr().lock(), "{status}")?;
            return Ok(ExitCode::Success);
        };
        if self.options.json {
            cloud::write_json(&SingleRunnerKeyResult {
                schema_version: 1,
                deployment: self.api_url(),
                outcome: "created",
                runner,
                activation: &issuance.activation,
                activation_file: &key_file,
            })?;
            return Ok(ExitCode::Success);
        }
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        if registered {
            writeln!(stdout, "✓ Runner registered with a single-runner key.\n")?;
        } else {
            writeln!(stdout, "✓ Single-runner key issued.\n")?;
        }
        writeln!(stdout, "  Runner:            {}", runner.id)?;
        writeln!(stdout, "  Name:              {}", runner.name)?;
        writeln!(stdout, "  Single-runner key: {}", issuance.activation.id)?;
        writeln!(
            stdout,
            "  Expires:           {}",
            issuance.activation.expires_at
        )?;
        writeln!(stdout, "  Key file:          {key_file}")?;
        Ok(ExitCode::Success)
    }

    fn api_url(&self) -> &str {
        self.deployment.fingerprint().api_url()
    }

    fn write_failure(&self, failure: &RunnerFailure) -> anyhow::Result<ExitCode> {
        self.options.write_failure(self.deployment, failure)
    }
}

/// The request identities of the registration and of the key, kept across a replay.
#[derive(Clone, Copy)]
struct Keys<'a> {
    registration: &'a str,
    activation: &'a str,
}

/// Issues the first key of a runner the command registered; a failure is reported with the
/// runner, which stays registered (REQ-RUNNERENROLL-8).
fn activate_registered(
    api: &RunnerApi,
    organization: &str,
    runner: RunnerRegistration,
    key: &str,
) -> Outcome {
    match api.create_activation(organization, &runner.id, key) {
        Ok(issuance) => Outcome::Issued {
            runner,
            issuance,
            registered: true,
        },
        Err(failure) => Outcome::ActivationFailed { runner, failure },
    }
}

/// The usage refusal of `--pool` or `--member` for a runner in another pool: nothing is issued,
/// and the runner is moved with `useful runner update` (REQ-RUNNERENROLL-2).
fn other_pool(reference: &str, runner: &RunnerRegistration) -> CommandFailure {
    CommandFailure::with_exit_code(
        anyhow!(
            "runner {} is in pool {} ({}), not the pool --pool or --member names; no key was issued\n\n\
             Move the runner first, or issue its key without --pool and --member:\n  useful runner update {reference} --pool POOL",
            runner.name,
            runner.runner_pool.name,
            runner.runner_pool.id
        ),
        ExitCode::UsageError,
    )
}
