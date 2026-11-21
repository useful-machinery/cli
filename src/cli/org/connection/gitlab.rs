//! GitLab through `useful org integration`: `create gitlab` and `reconnect` stage a token as a
//! credential candidate, wait for its verification, have its identity confirmed and activate it
//! in one command, and the reads and changes of a GitLab connection.
use super::authorization::InForce;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use clap::{Args, ValueEnum};
use serde_json::{Value, json};
use useful_api::{
    GitLabAccountUse, GitLabApi, GitLabFailure, GitLabRepositoryQuery, GitLabSelection,
    GitLabSubmission, GitLabTokenKind, HttpClient, UnreachableCategory,
};
use useful_human_auth::Deployment;
use zeroize::Zeroizing;

use super::super::super::secret_file::{SecretInput, trim_line_ending};
use super::super::super::{
    CommandFailure, CommandResult, CommonArgs, JsonOutputKind, ObservationClock, OperationControl,
    POLL_WAIT_SLICE, PrincipalAuthenticationArgs, StopSignal, SystemObservationClock,
    ceremony_poll_interval, wait_for_poll,
};
use super::list::Record;
use super::target::Resolved;
use crate::exit_code::ExitCode;

/// The GitLab setup guide, which the help of every leaf that takes a GitLab connection names.
pub(super) const GUIDE: &str = "https://docs.usefulmachinery.com/agent/gitlab-setup.md";
const MAX_TOKEN: u64 = 16 * 1024;
/// The longest request key of a single request (REQ-CONNECTION-74).
const KEY: usize = 255;
/// The longest request key of `create gitlab` and `reconnect`, whose requests each send it with
/// the suffix of their step (REQ-CONNECTION-74).
const STEPPED_KEY: usize = 240;
/// How long `create gitlab` and `reconnect` wait for a candidate's verification unless
/// `--timeout` says otherwise: its review window (REQ-CONNECTION-56).
const VERIFICATION_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Args)]
struct Key {
    #[arg(
        long,
        value_name = "KEY",
        help = "Request key for replaying an uncertain result (generated when omitted)"
    )]
    idempotency_key: Option<String>,
}
impl Key {
    /// The key given, or one generated, refused unless it has 1 to `longest` visible ASCII
    /// characters.
    fn value(&self, longest: usize) -> anyhow::Result<String> {
        let value = match &self.idempotency_key {
            Some(key) => key.clone(),
            None => useful_support::generate_idempotency_key().context("generate request key")?,
        };
        if value.is_empty()
            || value.len() > longest
            || !value.bytes().all(|b| (b'!'..=b'~').contains(&b))
        {
            bail!(
                "invalid idempotency key: use 1–{longest} visible ASCII characters without whitespace"
            );
        }
        Ok(value)
    }
}
/// `--expected-version`, which a GitLab connection's `remove`, `reconnect`, `repository add` and
/// `repository remove` take (REQ-CONNECTION-74).
#[derive(Debug, Args)]
pub(super) struct ExpectedVersion {
    #[arg(
        long,
        value_name = "VERSION",
        help = "Connection version shown by useful org integration show (read when omitted)"
    )]
    expected_version: Option<i64>,
}
impl ExpectedVersion {
    /// The option, when given, which another provider's connection refuses.
    pub(super) fn given(&self) -> Option<&'static str> {
        self.expected_version
            .is_some()
            .then_some("--expected-version")
    }

    /// The version given, refused before any request unless it is a positive safe JSON integer.
    pub(super) fn check(&self) -> Result<Option<i64>, CommandFailure> {
        self.expected_version
            .map(version)
            .transpose()
            .map_err(usage)
    }
}
#[derive(Debug, Args)]
struct Attribution {
    #[arg(
        long,
        value_name = "PRINCIPAL",
        help = "Human delegator for service-action attribution (must be active)"
    )]
    delegator_principal_id: Option<String>,
}
/// The options of a `useful org integration` mutation that only a GitLab connection takes
/// (REQ-CONNECTION-74, REQ-CONNECTION-106).
#[derive(Debug, Args)]
pub(super) struct Mutation {
    #[command(flatten)]
    precondition: ExpectedVersion,
    #[command(flatten)]
    attribution: Attribution,
    #[command(flatten)]
    key: Key,
}
/// A mutation's options once checked, before any request: the version given, if any, and the
/// request key, generated when none was given.
pub(super) struct Checked {
    version: Option<i64>,
    delegator: Option<String>,
    key: String,
}
/// The options of `useful org integration repository list` that only a GitLab connection takes
/// (REQ-CONNECTION-73, REQ-CONNECTION-106).
#[derive(Debug, Args)]
pub(super) struct RepositoryQuery {
    #[command(flatten)]
    page: super::super::super::PaginationArgs<200>,
    #[arg(long, conflicts_with_all = ["provider_repository_id", "selected"], help = "Filter by repository name")]
    search: Option<String>,
    #[arg(
        long = "repository-id",
        value_name = super::super::super::RepositoryArg::VALUE_NAME,
        conflicts_with = "selected",
        help = super::super::super::RepositoryArg::HELP
    )]
    provider_repository_id: Option<String>,
    #[arg(
        long,
        help = "Show only selected repositories (also works when GitLab is unavailable)"
    )]
    selected: bool,
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum CredentialKind {
    GroupAccessToken,
    ServiceAccount,
    DedicatedUser,
}
impl CredentialKind {
    /// The token declaration a submission of this kind sends (REQ-CONNECTION-57).
    const fn declaration(self) -> (GitLabTokenKind, Option<GitLabAccountUse>) {
        match self {
            Self::GroupAccessToken => (GitLabTokenKind::GroupAccessToken, None),
            Self::ServiceAccount => (
                GitLabTokenKind::PersonalAccessToken,
                Some(GitLabAccountUse::ServiceAccount),
            ),
            Self::DedicatedUser => (
                GitLabTokenKind::PersonalAccessToken,
                Some(GitLabAccountUse::DedicatedUser),
            ),
        }
    }
}
/// `--instance-url`, which only `create gitlab` takes (REQ-CONNECTION-56).
#[derive(Debug, Args)]
pub(super) struct Instance {
    #[arg(
        long = "instance-url",
        value_name = "URL",
        help = "GitLab instance to connect (default https://gitlab.com; see the setup guide)"
    )]
    url: Option<String>,
}
impl Instance {
    /// The option, when given, which another provider refuses.
    pub(super) fn given(&self) -> Option<&'static str> {
        self.url.is_some().then_some("--instance-url")
    }
}
/// The options of `create gitlab` and `reconnect` that only a GitLab connection takes: the token
/// to stage, how its identity is confirmed and the requests' key (REQ-CONNECTION-57,
/// REQ-CONNECTION-58, REQ-CONNECTION-74).
#[derive(Debug, Args)]
pub(super) struct Credential {
    #[arg(
        long,
        value_name = "PATH",
        help = "Read the GitLab token from an owned mode-0600 file, or - for standard input"
    )]
    token_file: Option<PathBuf>,
    #[arg(
        long,
        value_enum,
        value_name = "KIND",
        help = "GitLab token kind (see the setup guide)"
    )]
    kind: Option<CredentialKind>,
    #[arg(
        long,
        value_name = "ID",
        requires = "dedicated_automation",
        help = "GitLab user ID the token must verify as, confirmed without a terminal"
    )]
    expected_provider_user_id: Option<String>,
    #[arg(
        long,
        requires = "expected_provider_user_id",
        help = "Attest that the GitLab user is a dedicated automation identity"
    )]
    dedicated_automation: bool,
    #[command(flatten)]
    attribution: Attribution,
    #[command(flatten)]
    key: Key,
}
/// How the identity a candidate verified as is confirmed (REQ-CONNECTION-58).
enum Confirmation {
    /// By `--expected-provider-user-id` with `--dedicated-automation`.
    Given(String),
    /// On the terminal, open since the command began.
    Terminal(File),
}
/// The token `create gitlab` or `reconnect` stages and how it goes on, checked before any
/// request.
pub(super) struct Staged {
    token: Zeroizing<String>,
    kind: CredentialKind,
    confirmation: Confirmation,
    delegator: Option<String>,
    key: String,
    /// Whether the key was given, which lets a replay activate a candidate already settled.
    explicit_key: bool,
}
/// Runs `call` against GitLab's routes under the credential `options` select.
pub(super) fn with_api<F: JsonOutputKind, T>(
    d: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    mut call: impl FnMut(&GitLabApi) -> Result<T, GitLabFailure>,
) -> anyhow::Result<Result<T, GitLabFailure>> {
    let policy = options.http.transport_policy();
    let client = HttpClient::new(policy)
        .map_err(|e| anyhow!(e))
        .context("prepare human session networking")?;
    super::super::super::execute_selected_api_operation(
        super::super::super::principal_api_context(
            &client,
            d,
            &options.authentication,
            "acquire human session",
        ),
        |token| {
            let api =
                GitLabApi::new(d.fingerprint().api_url(), token, policy).map_err(|e| anyhow!(e))?;
            Ok(call(&api))
        },
        GitLabFailure::credential_rejected,
        || GitLabFailure::Unauthenticated,
        GitLabFailure::Unreachable,
    )
}
fn usage(error: anyhow::Error) -> CommandFailure {
    CommandFailure::with_exit_code(error, ExitCode::UsageError)
}
fn version(value: i64) -> anyhow::Result<i64> {
    if !(1..=9_007_199_254_740_991).contains(&value) {
        bail!(
            "invalid expected version: use the positive safe JSON integer from useful org integration show"
        );
    }
    Ok(value)
}
fn repository_id(value: &str) -> anyhow::Result<&str> {
    if !crate::cli::entity::provider_repository_id(value) {
        bail!("invalid provider repository ID: use a positive decimal GitLab project ID");
    }
    Ok(value)
}
// Results and failures share one JSON envelope (REQ-CONNECTION-75, REQ-CONNECTION-77).
fn envelope(d: &Deployment, organization: &str, outcome: &str, key: Option<&str>) -> Value {
    json!({"schemaVersion":1,"deployment":d.fingerprint().api_url(),"organizationRef":organization,"outcome":outcome,"idempotencyKey":key})
}
fn write_document(document: &Value) -> anyhow::Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, document)?;
    writeln!(out)?;
    Ok(())
}
/// The answer to a GitLab request in `organization`: its result, or its refusal.
fn write_result(
    d: &Deployment,
    organization: &str,
    json: bool,
    outcome: &str,
    value: Result<Value, GitLabFailure>,
    key: Option<&str>,
) -> anyhow::Result<ExitCode> {
    match value {
        Ok(value) => {
            let write = || -> anyhow::Result<()> {
                if json {
                    let mut document = envelope(d, organization, outcome, key);
                    document["result"] = value.clone();
                    write_document(&document)?;
                } else {
                    let mut out = io::stdout().lock();
                    let kind = if outcome == "repositories_listed" {
                        "GitLab repositories"
                    } else if value.get("connectionId").is_some() {
                        "GitLab credential candidate"
                    } else {
                        "GitLab connection"
                    };
                    writeln!(out, "{kind}: {}", outcome.replace('_', " "))?;
                    if let Some(items) = value.get("items").and_then(Value::as_array) {
                        for item in items {
                            if outcome == "repositories_listed" {
                                writeln!(
                                    out,
                                    "{}  {}  {}  {}  {}",
                                    item["providerRepositoryId"].as_str().unwrap_or("?"),
                                    item["fullName"].as_str().unwrap_or("?"),
                                    item["defaultBranch"].as_str().unwrap_or("-"),
                                    if item["selected"] == true {
                                        "selected"
                                    } else {
                                        "not selected"
                                    },
                                    item["availability"].as_str().unwrap_or("?")
                                )?;
                            } else {
                                writeln!(
                                    out,
                                    "{}  {}  {}  {}",
                                    item["id"].as_str().unwrap_or("?"),
                                    item["state"].as_str().unwrap_or("?"),
                                    item["instanceUrl"].as_str().unwrap_or("?"),
                                    item["credential"]["expiryNotice"].as_str().unwrap_or("-")
                                )?;
                            }
                        }
                        if let Some(cursor) = value["nextCursor"].as_str() {
                            writeln!(out, "next cursor: {cursor}")?;
                        }
                    } else {
                        for (field, label) in [
                            ("id", "id"),
                            ("connectionId", "connection"),
                            ("instanceUrl", "instance"),
                            ("state", "state"),
                            ("version", "version"),
                            ("providerUserId", "provider user id"),
                            ("providerUsername", "provider username"),
                            ("previousProviderUserId", "previous provider user id"),
                            ("previousProviderUsername", "previous provider username"),
                            ("kind", "kind"),
                            ("accountUse", "account use"),
                            ("permissionProfile", "permission profile"),
                            ("tokenExpiresAt", "token expires (UTC instant)"),
                            ("failureCode", "failure code"),
                            ("expiresAt", "review expires"),
                        ] {
                            if let Some(v) = value.get(field).filter(|v| !v.is_null()) {
                                writeln!(
                                    out,
                                    "{}: {}",
                                    label,
                                    v.as_str()
                                        .map(str::to_owned)
                                        .unwrap_or_else(|| v.to_string())
                                )?;
                            }
                        }
                    }
                    if let Some(ids) = value.get("selectedRepositoryIds").and_then(Value::as_array)
                    {
                        writeln!(
                            out,
                            "selected repositories: {}",
                            ids.iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(", ")
                        )?;
                    }
                    if let Some(user) = value.get("providerUser").filter(|v| !v.is_null()) {
                        if let Some(id) = user["id"].as_str() {
                            writeln!(out, "provider user id: {id}")?;
                        }
                        if let Some(username) = user["username"].as_str() {
                            writeln!(out, "provider username: {username}")?;
                        }
                    }
                    if let Some(credential) = value.get("credential").filter(|v| !v.is_null()) {
                        for (field, label) in [
                            ("kind", "kind"),
                            ("accountUse", "account use"),
                            ("permissionProfile", "permission profile"),
                            ("expiresAt", "expires (UTC instant)"),
                            ("expiryNotice", "expiry notice"),
                        ] {
                            if let Some(v) = credential.get(field).filter(|v| !v.is_null()) {
                                writeln!(
                                    out,
                                    "credential {label}: {}",
                                    v.as_str().unwrap_or("unknown")
                                )?;
                            }
                        }
                    }
                    writeln!(out, "deployment: {}", d.fingerprint().api_url())?;
                    if let Some(key) = key {
                        writeln!(out, "request key: {key}")?;
                    }
                }
                Ok(())
            };
            write()?;
            Ok(ExitCode::Success)
        }
        Err(refusal) => failure(d, organization, json, refusal, key),
    }
}
/// What a refusal reports: its outcome, its diagnostic, its remedy and the exit code.
struct Report {
    outcome: &'static str,
    name: String,
    remedy: &'static str,
    exit: ExitCode,
}
impl Report {
    fn new(outcome: &'static str, name: &str, remedy: &'static str, exit: ExitCode) -> Self {
        Self {
            outcome,
            name: name.to_owned(),
            remedy,
            exit,
        }
    }
}
/// What the refusal of a GitLab request reports (REQ-CONNECTION-77).
fn report(refusal: GitLabFailure) -> Report {
    match refusal {
        GitLabFailure::Unauthenticated => Report::new(
            "unauthenticated",
            "authentication required",
            "Sign in again or supply a current service API key.",
            ExitCode::AuthenticationRequired,
        ),
        GitLabFailure::Forbidden => Report::new(
            "forbidden",
            "access denied",
            "Ask an organization owner for access.",
            ExitCode::GeneralFailure,
        ),
        GitLabFailure::Conflict => Report::new(
            "conflict",
            "connection conflict",
            "Show the current connection before retrying with a new request key.",
            ExitCode::Conflict,
        ),
        GitLabFailure::CandidateUnavailable => Report::new(
            "candidate_unavailable",
            "candidate unavailable",
            "The credential candidate failed, expired or was settled and cannot be activated. Stage the token again.",
            ExitCode::CandidateUnavailable,
        ),
        GitLabFailure::IdentityMismatch => Report::new(
            "identity_mismatch",
            "identity mismatch",
            "Review the verified provider user and provide its exact ID.",
            ExitCode::IdentityMismatch,
        ),
        GitLabFailure::Unreachable(_) => Report::new(
            "unreachable",
            "gitlab connection API unavailable",
            "Show the resource before replaying a mutation with the same request key.",
            ExitCode::Unavailable,
        ),
        GitLabFailure::ProviderUnavailable => Report::new(
            "provider_unavailable",
            "gitlab provider unavailable",
            "GitLab is temporarily unavailable or asked Cloud to wait. Show the resource, then repeat the request with the same request key.",
            ExitCode::Unavailable,
        ),
        GitLabFailure::ServiceUnavailable => Report::new(
            "service_unavailable",
            "gitlab connection service unavailable",
            "This deployment cannot serve this GitLab operation. Review the setup guide.",
            ExitCode::Unavailable,
        ),
        GitLabFailure::InvalidInput => Report::new(
            "invalid_input",
            "invalid gitlab connection request",
            "Review the setup guide and correct the request.",
            ExitCode::UsageError,
        ),
        GitLabFailure::NotFound => Report::new(
            "not_found",
            "gitlab connection or candidate not found",
            "Check the organization and resource IDs.",
            ExitCode::GeneralFailure,
        ),
        GitLabFailure::Protocol => Report::new(
            "invalid_response",
            "invalid gitlab connection response",
            "Check the deployment and try again later.",
            ExitCode::GeneralFailure,
        ),
    }
}
/// A refused GitLab request in `organization`, written as REQ-CONNECTION-77 has it.
pub(super) fn failure(
    d: &Deployment,
    organization: &str,
    json: bool,
    refusal: GitLabFailure,
    key: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let report = report(refusal);
    if json {
        let mut document = envelope(d, organization, report.outcome, key);
        if let GitLabFailure::Unreachable(category) = refusal {
            document["category"] = category.as_str().into();
        }
        write_document(&document)?;
    } else {
        write_refusal(&report, &[], key, None)?;
    }
    Ok(report.exit)
}
/// Writes a refusal to standard error: its diagnostic, `facts` as labelled lines and the request
/// key, then its remedy, `next` and the setup guide.
fn write_refusal(
    report: &Report,
    facts: &[(&str, String)],
    key: Option<&str>,
    next: Option<&str>,
) -> anyhow::Result<()> {
    let mut error = io::stderr().lock();
    writeln!(error, "error: {}", report.name)?;
    for (label, value) in facts {
        writeln!(error, "{label}: {value}")?;
    }
    if let Some(key) = key {
        writeln!(error, "request key: {key}")?;
    }
    writeln!(error, "\n{}", report.remedy)?;
    if let Some(next) = next {
        writeln!(error, "{next}")?;
    }
    writeln!(error, "{GUIDE}")?;
    Ok(())
}
/// Sends `call`, and once more after an ambiguous transport failure, with the same key and body
/// (REQ-CONNECTION-74).
fn repeat_if_lost<T>(
    mut call: impl FnMut() -> Result<T, GitLabFailure>,
) -> Result<T, GitLabFailure> {
    let first = call();
    if matches!(
        first,
        Err(GitLabFailure::Unreachable(category)) if category.retryable_mutation()
    ) {
        call()
    } else {
        first
    }
}
/// Sends `call` with `key` in `organization`, once more with the same key after an ambiguous
/// transport failure, and writes its answer as `outcome` (REQ-CONNECTION-74).
fn mutate<F: JsonOutputKind + Send + 'static>(
    d: Deployment,
    organization: String,
    options: CommonArgs<F, PrincipalAuthenticationArgs>,
    key: String,
    outcome: &'static str,
    mut call: impl FnMut(&GitLabApi, &str) -> Result<Value, GitLabFailure> + Send + 'static,
) -> CommandResult {
    let stopped_key = key.clone();
    super::super::super::execute_mutation_with_signals(
        "GitLab connection mutation",
        (),
        move |control| {
            if !control.begin_dispatch() {
                return Ok(ExitCode::Interrupted);
            }
            let value = with_api(&d, &options, |api| repeat_if_lost(|| call(api, &key)))?;
            super::super::super::complete_operation(control, || {
                write_result(&d, &organization, options.json, outcome, value, Some(&key))
                    .map_err(Into::into)
            })
        },
        move |signal, snapshot| {
            if snapshot.dispatched {
                writeln!(io::stderr().lock(),
                    "error: gitlab request interrupted after dispatch\nrequest key: {stopped_key}\n\nShow the resource before replaying this request with the same key."
                ).map_err(anyhow::Error::from)?;
            }
            Ok(signal)
        },
    )
}
impl RepositoryQuery {
    /// The first of these options given, each of which a GitHub binding refuses.
    pub(super) fn given(&self) -> Option<&'static str> {
        [
            ("--limit", self.page.limit.is_some()),
            ("--cursor", self.page.cursor.is_some()),
            ("--search", self.search.is_some()),
            ("--repository-id", self.provider_repository_id.is_some()),
            ("--selected", self.selected),
        ]
        .into_iter()
        .find_map(|(option, given)| given.then_some(option))
    }

    /// Refuses a malformed `--repository-id` before any request.
    pub(super) fn check(&self) -> Result<(), CommandFailure> {
        if let Some(id) = self.provider_repository_id.as_deref() {
            repository_id(id).map_err(usage)?;
        }
        Ok(())
    }
}
/// Lists one page of the repositories the GitLab connection `connection` of `organization`
/// reaches (REQ-CONNECTION-73).
pub(super) fn list_repositories<F: JsonOutputKind>(
    d: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    connection: &str,
    query: &RepositoryQuery,
) -> anyhow::Result<ExitCode> {
    let value = with_api(d, options, |api| {
        api.repositories(
            organization,
            connection,
            GitLabRepositoryQuery {
                limit: query.page.limit.map(i32::from),
                cursor: query.page.cursor.as_deref(),
                search: query.search.as_deref(),
                repository_id: query.provider_repository_id.as_deref(),
                selected: query.selected,
            },
        )
    })?;
    write_result(
        d,
        organization,
        options.json,
        "repositories_listed",
        value,
        None,
    )
}
impl Mutation {
    /// The first of these options given, each of which another provider's connection refuses.
    pub(super) fn given(&self) -> Option<&'static str> {
        self.precondition.given().or_else(|| {
            [
                ("--idempotency-key", self.key.idempotency_key.is_some()),
                (
                    "--delegator-principal-id",
                    self.attribution.delegator_principal_id.is_some(),
                ),
            ]
            .into_iter()
            .find_map(|(option, given)| given.then_some(option))
        })
    }

    /// Refuses a malformed version or request key before any request, and generates the key
    /// when none was given.
    pub(super) fn check(self) -> Result<Checked, CommandFailure> {
        let version = self.precondition.check()?;
        let key = self.key.value(KEY).map_err(usage)?;
        Ok(Checked {
            version,
            delegator: self.attribution.delegator_principal_id,
            key,
        })
    }
}
/// Refuses a repository that is not a GitLab project ID before any request.
pub(super) fn check_repositories(repositories: &[String]) -> Result<(), CommandFailure> {
    for id in repositories {
        repository_id(id).map_err(usage)?;
    }
    Ok(())
}
/// The version a mutation of the connection `resolved` sends: the one given, else the one the
/// resolver read from the connection list, else the one read now (REQ-CONNECTION-74). The read
/// is not part of the mutation: it carries no request key and is not repeated.
fn current_version<F: JsonOutputKind>(
    d: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    resolved: &Resolved,
    given: Option<i64>,
) -> anyhow::Result<Result<i64, GitLabFailure>> {
    if let Some(version) = given {
        return Ok(Ok(version));
    }
    let read_version = |connection: &Value| connection["version"].as_i64();
    if let Resolved::Listed(Record::Gitlab(connection)) = resolved
        && let Some(version) = read_version(connection)
    {
        return Ok(Ok(version));
    }
    Ok(
        with_api(d, options, |api| api.show(organization, resolved.id()))?
            .and_then(|connection| read_version(&connection).ok_or(GitLabFailure::Protocol)),
    )
}
/// Disconnects the GitLab connection `resolved` of `organization` (REQ-CONNECTION-56).
pub(super) fn remove<F: JsonOutputKind + Send + 'static>(
    d: &Deployment,
    options: CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    resolved: &Resolved,
    checked: Checked,
) -> CommandResult {
    let Checked {
        version,
        delegator,
        key,
    } = checked;
    let version = match current_version(d, &options, organization, resolved, version)? {
        Ok(version) => version,
        Err(refusal) => return Ok(failure(d, organization, options.json, refusal, None)?),
    };
    let org = organization.to_owned();
    let id = resolved.id().to_owned();
    mutate(
        d.clone(),
        org.clone(),
        options,
        key,
        "disconnected",
        move |api, key| api.remove(&org, &id, key, version, delegator.as_deref()),
    )
}
/// Adds `repositories` to the selection of the GitLab connection `resolved` of `organization`,
/// or with `link` false removes them (REQ-CONNECTION-73).
pub(super) fn select<F: JsonOutputKind + Send + 'static>(
    d: &Deployment,
    options: CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    resolved: &Resolved,
    repositories: Vec<String>,
    link: bool,
    checked: Checked,
) -> CommandResult {
    let Checked {
        version,
        delegator,
        key,
    } = checked;
    let version = match current_version(d, &options, organization, resolved, version)? {
        Ok(version) => version,
        Err(refusal) => return Ok(failure(d, organization, options.json, refusal, None)?),
    };
    let org = organization.to_owned();
    let id = resolved.id().to_owned();
    mutate(
        d.clone(),
        org.clone(),
        options,
        key,
        if link { "linked" } else { "removed" },
        move |api, key| {
            api.select_repository(
                &org,
                &id,
                key,
                GitLabSelection {
                    version,
                    repository_ids: &repositories,
                    link,
                    delegator: delegator.as_deref(),
                },
            )
        },
    )
}
/// Shows the GitLab connection `connection` of `organization` (REQ-CONNECTION-105).
pub(super) fn show<F: JsonOutputKind>(
    d: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    connection: &str,
    authorizations: Option<&InForce>,
) -> anyhow::Result<ExitCode> {
    let value = with_api(d, options, |api| api.show(organization, connection))?;
    match (value, authorizations) {
        (Ok(result), Some(authorizations)) if options.json => {
            let mut document = envelope(d, organization, "shown", None);
            document["result"] = result;
            document["authorizations"] =
                serde_json::to_value(authorizations).context("serialize the authorizations")?;
            write_document(&document)?;
            Ok(ExitCode::Success)
        }
        (Ok(result), authorizations) => {
            let shown = write_result(d, organization, options.json, "shown", Ok(result), None)?;
            if let Some(authorizations) = authorizations {
                authorizations.write_human(&mut io::stdout().lock(), "")?;
            }
            Ok(shown)
        }
        (failed, _) => write_result(d, organization, options.json, "shown", failed, None),
    }
}
impl Credential {
    /// The first of these options given, which another provider refuses (REQ-CONNECTION-106).
    pub(super) fn given(&self) -> Option<&'static str> {
        [
            ("--token-file", self.token_file.is_some()),
            ("--kind", self.kind.is_some()),
            (
                "--expected-provider-user-id",
                self.expected_provider_user_id.is_some(),
            ),
            ("--dedicated-automation", self.dedicated_automation),
            (
                "--delegator-principal-id",
                self.attribution.delegator_principal_id.is_some(),
            ),
            ("--idempotency-key", self.key.idempotency_key.is_some()),
        ]
        .into_iter()
        .find_map(|(option, given)| given.then_some(option))
    }

    /// Checks the options before any request: makes the request key, decides how the verified
    /// identity will be confirmed and reads the token (REQ-CONNECTION-57, REQ-CONNECTION-58).
    pub(super) fn check<F: JsonOutputKind>(
        self,
        options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    ) -> Result<Staged, CommandFailure> {
        let (Some(path), Some(kind)) = (self.token_file, self.kind) else {
            return Err(usage(anyhow!(
                "a GitLab connection requires --token-file PATH and --kind KIND"
            )));
        };
        let explicit_key = self.key.idempotency_key.is_some();
        let key = self.key.value(STEPPED_KEY).map_err(usage)?;
        if path == Path::new("-") && options.authentication.uses_stdin() {
            return Err(usage(anyhow!(
                "standard input cannot contain both a service API key and a GitLab token"
            )));
        }
        let confirmation = match self.expected_provider_user_id {
            Some(user) => Confirmation::Given(user),
            None if options.json => {
                return Err(usage(anyhow!(
                    "JSON output requires --expected-provider-user-id and --dedicated-automation to confirm the verified GitLab identity"
                )));
            }
            None => Confirmation::Terminal(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/tty")
                    .context("confirming the verified GitLab identity requires a terminal; otherwise supply --expected-provider-user-id and --dedicated-automation")
                    .map_err(usage)?,
            ),
        };
        let token = read_token(&path).map_err(usage)?;
        Ok(Staged {
            token,
            kind,
            confirmation,
            delegator: self.attribution.delegator_principal_id,
            key,
            explicit_key,
        })
    }
}

/// Creates a GitLab connection in `organization` for the instance `instance` names, GitLab.com
/// by default, and gives it the staged token (REQ-CONNECTION-56).
pub(super) fn create<F: JsonOutputKind + Send + 'static>(
    d: &Deployment,
    options: CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    instance: Instance,
    staged: Staged,
    timeout: Option<Duration>,
) -> CommandResult {
    let instance = instance
        .url
        .unwrap_or_else(|| "https://gitlab.com".to_owned());
    connect(
        d,
        options,
        organization,
        Start::Create(instance),
        staged,
        timeout,
    )
}

/// Gives the GitLab connection `resolved` of `organization` the staged token, at the version
/// given or else its current one (REQ-CONNECTION-108).
pub(super) fn reconnect<F: JsonOutputKind + Send + 'static>(
    d: &Deployment,
    options: CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    resolved: &Resolved,
    version: Option<i64>,
    staged: Staged,
    timeout: Option<Duration>,
) -> CommandResult {
    let version = match current_version(d, &options, organization, resolved, version)? {
        Ok(version) => version,
        Err(refusal) => return Ok(failure(d, organization, options.json, refusal, None)?),
    };
    let start = Start::Submit {
        connection: resolved.id().to_owned(),
        version,
    };
    connect(d, options, organization, start, staged, timeout)
}

/// Where `create gitlab` and `reconnect` begin.
enum Start {
    /// Creating a connection for this instance.
    Create(String),
    /// Submitting the token for this connection at this version.
    Submit { connection: String, version: i64 },
}

/// The connection and the candidate a command holds, which its ending names.
#[derive(Clone, Default)]
struct Held {
    connection: Option<String>,
    candidate: Option<String>,
}

/// How `create gitlab` or `reconnect` ended.
enum Ending {
    Activated(Value),
    /// A request was refused.
    Refused(GitLabFailure),
    /// The candidate failed, expired or was settled, with the failure code it read.
    Unavailable(Option<String>),
    /// The identity confirmed is not the one the candidate verified as.
    Mismatch,
    /// The confirmation on the terminal was refused.
    Unconfirmed(anyhow::Error),
    TimedOut,
    Interrupted,
}

/// What a candidate's wait ended with, short of an ending.
enum Verified {
    /// The candidate verified, as read.
    Shown(Value),
    /// A candidate already settled, which an explicitly keyed command given the identity
    /// activates again to replay its activation.
    Replay(String),
}

/// What the terminal's confirmation answered.
enum Review {
    Answered(String),
    Refused(anyhow::Error),
    Stopped,
}

/// Where and how a command writes, which its ending after a second signal needs too.
#[derive(Clone)]
struct Writer {
    d: Deployment,
    organization: String,
    json: bool,
    key: String,
}

impl Writer {
    /// Writes a step's result.
    fn step(&self, outcome: &str, result: Value) -> anyhow::Result<()> {
        write_result(
            &self.d,
            &self.organization,
            self.json,
            outcome,
            Ok(result),
            Some(&self.key),
        )
        .map(drop)
    }

    /// Writes how a command ended short of activation: `report`, the connection and candidate it
    /// held, the candidate's failure code and whether its cancellation was acknowledged
    /// (REQ-CONNECTION-56, REQ-CONNECTION-77).
    fn ending(
        &self,
        report: &Report,
        held: &Held,
        failure_code: Option<&str>,
        cancellation: Option<bool>,
        category: Option<UnreachableCategory>,
    ) -> anyhow::Result<()> {
        let cancellation = cancellation.map(|acknowledged| {
            if acknowledged {
                "acknowledged"
            } else {
                "failed"
            }
        });
        if self.json {
            let mut document =
                envelope(&self.d, &self.organization, report.outcome, Some(&self.key));
            if let Some(category) = category {
                document["category"] = category.as_str().into();
            }
            for (field, value) in [
                ("connectionId", held.connection.as_deref()),
                ("candidateId", held.candidate.as_deref()),
                ("failureCode", failure_code),
                ("cancellation", cancellation),
            ] {
                if let Some(value) = value {
                    document[field] = value.into();
                }
            }
            return write_document(&document);
        }
        let mut facts = Vec::new();
        for (label, value) in [
            ("connection", held.connection.as_deref()),
            ("candidate", held.candidate.as_deref()),
            ("failure code", failure_code),
        ] {
            if let Some(value) = value {
                facts.push((label, value.to_owned()));
            }
        }
        match cancellation {
            Some("acknowledged") => facts.push(("candidate cancellation", "acknowledged".into())),
            Some(_) => facts.push((
                "candidate cancellation",
                "failed; the candidate expires within ten minutes of its submission".into(),
            )),
            None => {}
        }
        let next = held.connection.as_ref().map(|connection| {
            format!(
                "Supply another token:\n  useful org integration reconnect {connection} --token-file PATH --kind KIND"
            )
        });
        write_refusal(report, &facts, Some(&self.key), next.as_deref())
    }
}

/// What an interruption by `signal` reports.
fn interrupted(signal: ExitCode) -> Report {
    Report::new(
        "interrupted",
        "gitlab connection command interrupted",
        "The token was not activated. A candidate the command staged and did not cancel expires within ten minutes of its submission.",
        signal,
    )
}

/// Stages the token, waits up to `timeout` for its verification, has the identity confirmed and
/// activates it, from `start`; every other ending cancels a candidate still open
/// (REQ-CONNECTION-56, REQ-CONNECTION-58, REQ-CONNECTION-74).
fn connect<F: JsonOutputKind + Send + 'static>(
    d: &Deployment,
    options: CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    start: Start,
    staged: Staged,
    timeout: Option<Duration>,
) -> CommandResult {
    let writer = Writer {
        d: d.clone(),
        organization: organization.to_owned(),
        json: options.json,
        key: staged.key.clone(),
    };
    let abandoned = writer.clone();
    let timeout = timeout.unwrap_or(VERIFICATION_TIMEOUT);
    super::super::super::execute_mutation_with_signal_cleanup(
        "GitLab connection",
        Held::default(),
        move |control, stop| {
            if !control.begin_dispatch() {
                return Ok(stop.exit_code());
            }
            let mut flow = Flow {
                writer: &writer,
                options: &options,
                staged: &staged,
                control,
                held: Held::default(),
                open: false,
                timeout,
                clock: SystemObservationClock,
            };
            let ending = flow.run(start);
            flow.end(ending, stop)
        },
        move |signal, held| {
            abandoned.ending(&interrupted(signal), &held, None, None, None)?;
            Ok(signal)
        },
    )
}

/// One run of `create gitlab` or `reconnect`.
struct Flow<'a, F: JsonOutputKind> {
    writer: &'a Writer,
    options: &'a CommonArgs<F, PrincipalAuthenticationArgs>,
    staged: &'a Staged,
    control: &'a OperationControl<Held>,
    held: Held,
    /// Whether the candidate staged may still be pending or verified, so that an ending short of
    /// activation cancels it.
    open: bool,
    timeout: Duration,
    clock: SystemObservationClock,
}

impl<F: JsonOutputKind> Flow<'_, F> {
    /// Sends the mutation of `step` with the command's key suffixed by the step, once more with it
    /// after an ambiguous transport failure (REQ-CONNECTION-74).
    fn mutation(
        &self,
        step: &str,
        mut call: impl FnMut(&GitLabApi, &str) -> Result<Value, GitLabFailure>,
    ) -> anyhow::Result<Result<Value, GitLabFailure>> {
        let key = format!("{}.{step}", self.staged.key);
        with_api(&self.writer.d, self.options, |api| {
            repeat_if_lost(|| call(api, &key))
        })
    }

    /// Keeps what the command holds as its recovery state; false once it was interrupted. A step
    /// that completed is reported even then, since the interruption's ending follows it.
    fn hold(&self) -> bool {
        self.control.update_recovery(self.held.clone())
    }

    /// The time left until `deadline`.
    fn remaining(&self, deadline: Option<std::time::Instant>) -> Duration {
        deadline.map_or(Duration::MAX, |deadline| {
            deadline.saturating_duration_since(self.clock.now())
        })
    }

    /// The identity an explicitly keyed command was given, with which it replays the activation
    /// of a candidate already settled.
    fn replay_identity(&self) -> Option<String> {
        match &self.staged.confirmation {
            Confirmation::Given(user) if self.staged.explicit_key && !user.is_empty() => {
                Some(user.clone())
            }
            Confirmation::Given(_) | Confirmation::Terminal(_) => None,
        }
    }

    fn run(&mut self, start: Start) -> anyhow::Result<Ending> {
        let staged = self.staged;
        let organization = self.writer.organization.clone();
        let delegator = staged.delegator.as_deref();
        let (connection, version) = match start {
            Start::Create(instance) => {
                let created = match self.mutation("create", |api, key| {
                    api.create(&organization, key, &instance, delegator)
                })? {
                    Ok(created) => created,
                    Err(refusal) => return Ok(Ending::Refused(refusal)),
                };
                let (Some(id), Some(version)) =
                    (created["id"].as_str(), created["version"].as_i64())
                else {
                    return Ok(Ending::Refused(GitLabFailure::Protocol));
                };
                let id = id.to_owned();
                self.held.connection = Some(id.clone());
                let held = self.hold();
                self.writer.step("created", created)?;
                if !held {
                    return Ok(Ending::Interrupted);
                }
                (id, version)
            }
            Start::Submit {
                connection,
                version,
            } => {
                self.held.connection = Some(connection.clone());
                if !self.hold() {
                    return Ok(Ending::Interrupted);
                }
                (connection, version)
            }
        };
        let (kind, account_use) = staged.kind.declaration();
        let submitted = match self.mutation("submit", |api, key| {
            api.submit(
                &organization,
                &connection,
                key,
                GitLabSubmission {
                    version,
                    kind,
                    account_use,
                    token: &staged.token,
                    delegator,
                },
            )
        })? {
            Ok(submitted) => submitted,
            Err(refusal) => return Ok(Ending::Refused(refusal)),
        };
        let Some(candidate) = submitted["id"].as_str().map(str::to_owned) else {
            return Ok(Ending::Refused(GitLabFailure::Protocol));
        };
        self.held.candidate = Some(candidate.clone());
        self.open = true;
        let held = self.hold();
        self.writer.step("submitted", submitted)?;
        if !held {
            return Ok(Ending::Interrupted);
        }
        let deadline = self.clock.now().checked_add(self.timeout);
        let verified = loop {
            let wait = ceremony_poll_interval().min(self.remaining(deadline));
            if !wait_for_poll(self.control, wait, &self.clock) {
                return Ok(Ending::Interrupted);
            }
            let read = with_api(&self.writer.d, self.options, |api| {
                api.candidate(&organization, &connection, &candidate)
            })?;
            if self.control.is_cancelled() {
                return Ok(Ending::Interrupted);
            }
            let shown = match read {
                Ok(shown) => shown,
                Err(GitLabFailure::NotFound) => {
                    self.open = false;
                    match self.replay_identity() {
                        Some(user) => break Verified::Replay(user),
                        None => return Ok(Ending::Unavailable(None)),
                    }
                }
                Err(refusal) => return Ok(Ending::Refused(refusal)),
            };
            match shown["state"].as_str() {
                Some("pending") if self.remaining(deadline).is_zero() => {
                    return Ok(Ending::TimedOut);
                }
                Some("pending") => {}
                Some("verified") => break Verified::Shown(shown),
                Some(state @ ("activated" | "failed" | "expired" | "cancelled")) => {
                    self.open = false;
                    if let Some(user) = self.replay_identity().filter(|_| state == "activated") {
                        break Verified::Replay(user);
                    }
                    let code = shown["failureCode"].as_str().map(str::to_owned);
                    return Ok(Ending::Unavailable(code));
                }
                _ => return Ok(Ending::Refused(GitLabFailure::Protocol)),
            }
        };
        let identity = match verified {
            Verified::Replay(user) => user,
            Verified::Shown(shown) => {
                let Some(user) = shown["providerUserId"]
                    .as_str()
                    .filter(|user| !user.is_empty())
                    .map(str::to_owned)
                else {
                    return Ok(Ending::Refused(GitLabFailure::CandidateUnavailable));
                };
                if !self.writer.json {
                    self.writer.step("verified", shown.clone())?;
                }
                // New activations always review the verified identity; the flags attest a
                // separate, explicitly reviewed automation identity.
                let identity = match &staged.confirmation {
                    Confirmation::Given(expected) => expected.clone(),
                    Confirmation::Terminal(terminal) => match self.review(terminal, &shown) {
                        Review::Answered(answer) => answer,
                        Review::Refused(error) => return Ok(Ending::Unconfirmed(error)),
                        Review::Stopped => return Ok(Ending::Interrupted),
                    },
                };
                if identity != user {
                    return Ok(Ending::Mismatch);
                }
                identity
            }
        };
        loop {
            let activated = self.mutation("activate", |api, key| {
                api.activate(&organization, &connection, &candidate, key, &identity)
                    .map_err(|failure| {
                        if failure == GitLabFailure::NotFound {
                            GitLabFailure::CandidateUnavailable
                        } else {
                            failure
                        }
                    })
            })?;
            match activated {
                Ok(active) => {
                    self.open = false;
                    return Ok(Ending::Activated(active));
                }
                // A recheck GitLab could not complete changed nothing (REQ-CONNECTION-89).
                Err(GitLabFailure::ProviderUnavailable) if !self.remaining(deadline).is_zero() => {
                    let wait = ceremony_poll_interval().min(self.remaining(deadline));
                    if !wait_for_poll(self.control, wait, &self.clock) {
                        return Ok(Ending::Interrupted);
                    }
                }
                Err(GitLabFailure::CandidateUnavailable) => {
                    self.open = false;
                    return Ok(Ending::Unavailable(None));
                }
                Err(refusal) => return Ok(Ending::Refused(refusal)),
            }
        }
    }

    /// Asks on `terminal` for the confirmation of the identity `shown` verified as. The prompt
    /// blocks on the terminal, so it runs on a thread of its own and a signal still stops the
    /// command; a prompt left waiting ends with the process.
    fn review(&self, terminal: &File, shown: &Value) -> Review {
        let terminal = match terminal.try_clone() {
            Ok(terminal) => terminal,
            Err(error) => return Review::Refused(anyhow!(error).context("open the terminal")),
        };
        let shown = shown.clone();
        let (sender, answer) = mpsc::channel();
        std::thread::spawn(move || sender.send(review_identity(terminal, &shown)));
        loop {
            match answer.try_recv() {
                Ok(Ok(identity)) => return Review::Answered(identity),
                Ok(Err(error)) => return Review::Refused(error),
                Err(mpsc::TryRecvError::Empty) => {
                    if !wait_for_poll(self.control, POLL_WAIT_SLICE, &self.clock) {
                        return Review::Stopped;
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Review::Refused(anyhow!("identity review ended without an answer"));
                }
            }
        }
    }

    /// Cancels the candidate held, with the command's key suffixed `.cancel`; whether Cloud
    /// acknowledged it.
    fn cancel(&self) -> bool {
        let (Some(connection), Some(candidate)) = (&self.held.connection, &self.held.candidate)
        else {
            return false;
        };
        let organization = &self.writer.organization;
        matches!(
            self.mutation("cancel", |api, key| api.cancel(
                organization,
                connection,
                candidate,
                key
            )),
            Ok(Ok(_))
        )
    }

    /// Writes how the command ended and the exit code it ends with. Every ending but activation
    /// cancels a candidate still open first.
    fn end(self, ending: anyhow::Result<Ending>, stop: &StopSignal) -> CommandResult {
        let ending = match ending {
            Ok(ending) => ending,
            Err(error) => {
                if self.open {
                    self.cancel();
                }
                return Err(error.into());
            }
        };
        let mut failure_code = None;
        let mut category = None;
        let report = match ending {
            Ending::Activated(active) => {
                self.writer.step("activated", active)?;
                return Ok(ExitCode::Success);
            }
            Ending::Refused(GitLabFailure::Conflict)
                if self.held.connection.is_some() && self.held.candidate.is_none() =>
            {
                Report::new(
                    "conflict",
                    "credential candidate conflict",
                    "The connection changed, or another credential candidate of it is still in review; a candidate left behind expires within ten minutes of its submission. Show the connection, then run the command again.",
                    ExitCode::Conflict,
                )
            }
            Ending::Refused(refusal) => {
                if let GitLabFailure::Unreachable(unreachable) = refusal {
                    category = Some(unreachable);
                }
                report(refusal)
            }
            Ending::Unavailable(code) => {
                failure_code = code;
                Report::new(
                    "candidate_unavailable",
                    "credential candidate unavailable",
                    "GitLab did not verify the token, or the candidate expired or was settled. Check the token and its kind against the setup guide.",
                    ExitCode::CandidateUnavailable,
                )
            }
            Ending::Mismatch => Report::new(
                "identity_mismatch",
                "identity mismatch",
                "The token verified as another GitLab user than the one confirmed. Confirm the user ID of the verified identity.",
                ExitCode::IdentityMismatch,
            ),
            Ending::Unconfirmed(error) => Report {
                outcome: "invalid_input",
                name: format!("{error:#}"),
                remedy: "Confirm the verified identity on the terminal, or supply --expected-provider-user-id and --dedicated-automation.",
                exit: ExitCode::UsageError,
            },
            Ending::TimedOut => Report::new(
                "timed_out",
                "gitlab token verification timed out",
                "GitLab did not verify the token within the timeout. Run the command again, with a longer --timeout if needed.",
                ExitCode::GeneralFailure,
            ),
            Ending::Interrupted => interrupted(stop.exit_code()),
        };
        let cancellation = self.open.then(|| self.cancel());
        self.writer.ending(
            &report,
            &self.held,
            failure_code.as_deref(),
            cancellation,
            category,
        )?;
        Ok(report.exit)
    }
}

fn review_identity(mut tty: File, shown: &Value) -> anyhow::Result<String> {
    let user = shown["providerUserId"]
        .as_str()
        .ok_or_else(|| anyhow!("verified provider identity is unavailable"))?;
    writeln!(
        tty,
        "GitLab identity: {} ({user})",
        shown["providerUsername"].as_str().unwrap_or("unknown")
    )?;
    writeln!(
        tty,
        "Credential: {} / {}",
        shown["kind"].as_str().unwrap_or("unknown"),
        shown["accountUse"].as_str().unwrap_or("not applicable")
    )?;
    writeln!(
        tty,
        "Permission profile: {}; token expires (UTC instant): {}",
        shown["permissionProfile"].as_str().unwrap_or("unknown"),
        shown["tokenExpiresAt"].as_str().unwrap_or("unknown")
    )?;
    writeln!(
        tty,
        "Previous identity: {} ({})",
        shown["previousProviderUsername"].as_str().unwrap_or("none"),
        shown["previousProviderUserId"].as_str().unwrap_or("none")
    )?;
    write!(tty, "Enter the verified provider user ID: ")?;
    tty.flush()?;
    let mut reader = BufReader::new(tty.try_clone()?.take(512));
    let mut input = String::new();
    reader.read_line(&mut input)?;
    if input.trim_end_matches(['\r', '\n']) != user {
        return Ok(input.trim_end_matches(['\r', '\n']).to_owned());
    }
    write!(
        tty,
        "Type 'dedicated automation' to attest this identity is reserved for automation: "
    )?;
    tty.flush()?;
    let mut attestation = String::new();
    reader.read_line(&mut attestation)?;
    if attestation.trim_end_matches(['\r', '\n']) != "dedicated automation" {
        bail!("activation requires an explicit dedicated automation attestation");
    }
    Ok(user.to_owned())
}

const TOKEN_INPUT: SecretInput = SecretInput {
    name: "GitLab token",
    max_bytes: MAX_TOKEN + 2,
    max_text: "16 KiB",
};

fn read_token(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let mut bytes = TOKEN_INPUT.read(path)?;
    trim_line_ending(&mut bytes);
    if bytes.is_empty() || bytes.len() as u64 > MAX_TOKEN {
        bail!("GitLab token must contain 1–16384 UTF-8 bytes");
    }
    let token = std::str::from_utf8(&bytes).context("GitLab token must be UTF-8")?;
    if token.chars().any(char::is_control) {
        bail!("GitLab token cannot contain control characters");
    }
    Ok(Zeroizing::new(token.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn private_token_file_rejects_a_different_owner() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("token");
        fs::write(&path, b"fixture")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let metadata = fs::symlink_metadata(path)?;
        assert!(TOKEN_INPUT.validate(&metadata, metadata.uid()).is_ok());
        assert!(
            TOKEN_INPUT
                .validate(&metadata, metadata.uid().wrapping_add(1))
                .is_err()
        );
        Ok(())
    }
}
