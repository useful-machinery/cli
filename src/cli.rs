macro_rules! impl_organization_human_credential_outcome {
    ($($outcome:ty),+ $(,)?) => {
        $(
            impl super::HumanCredentialOutcome for $outcome {
                type Error = useful_api::OrganizationError;

                fn unauthenticated() -> Self {
                    Self::Common(useful_api::CommonOrganizationFailure::Unauthenticated)
                }

                fn unreachable(category: useful_api::UnreachableCategory) -> Self {
                    Self::Common(useful_api::CommonOrganizationFailure::Unreachable(category))
                }

                fn is_unauthenticated(&self) -> bool {
                    matches!(
                        self,
                        Self::Common(useful_api::CommonOrganizationFailure::Unauthenticated)
                    )
                }

                fn credential_rejected(error: &Self::Error) -> bool {
                    error.credential_rejected()
                }
            }
        )+
    };
}
pub(super) use impl_organization_human_credential_outcome;

pub(crate) mod account;
mod atomic_directory;
mod context;
mod deletion;
mod entity;
mod integration_token;
mod invitation;
mod org;
mod paging;
mod principal;
mod project;
mod runner;
mod secret_file;
mod version;
mod workflow;

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::marker::PhantomData;
use std::ops::Deref;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use serde::Serialize;

use self::entity::{OrganizationArg, PoolArg, RepositoryArg, RepositoryRef};
use crate::exit_code::{ExitCode, OutcomeClass};
use crate::service_auth::{ServiceApiKey, read_api_key};
use useful_api::{
    HttpClient, HttpTransportPolicy, MembershipRole, MembershipState, UnreachableCategory,
};
use useful_human_auth::Cancellation;
use useful_human_auth::Deployment;
use useful_human_auth::RequiredOperation;

pub(crate) type CommandResult = Result<ExitCode, CommandFailure>;

#[derive(Debug, Args)]
struct NamedInputArgs {
    #[arg(
        long,
        value_names = ["NAME", "TEXT"],
        num_args = 2,
        action = clap::ArgAction::Append,
        help = "Supply one required named Text value"
    )]
    input_text: Vec<OsString>,

    #[arg(
        long,
        value_names = ["NAME", "PATH|-"],
        num_args = 2,
        action = clap::ArgAction::Append,
        help = "Supply one required named Text value from a regular file, or - for standard input"
    )]
    input_text_file: Vec<OsString>,

    #[arg(
        long,
        value_names = ["NAME", "JSON"],
        num_args = 2,
        action = clap::ArgAction::Append,
        help = "Supply one required named JSON value"
    )]
    input_json: Vec<OsString>,

    #[arg(
        long,
        value_names = ["NAME", "PATH|-"],
        num_args = 2,
        action = clap::ArgAction::Append,
        help = "Supply one required named JSON value from a regular file, or - for standard input"
    )]
    input_json_file: Vec<OsString>,

    #[arg(
        long,
        value_names = ["NAME", "MEDIA_TYPE", "PATH"],
        num_args = 3,
        action = clap::ArgAction::Append,
        help = "Supply one required named File value with an explicit media type (maximum 64 MiB)"
    )]
    input_file: Vec<OsString>,

    #[arg(
        long,
        value_names = ["NAME", "MEDIA_TYPE", "PATH"],
        num_args = 3,
        action = clap::ArgAction::Append,
        help = "Append an immutable member to a named attachment collection"
    )]
    input_attachment: Vec<OsString>,

    #[arg(
        long,
        value_name = "NAME",
        action = clap::ArgAction::Append,
        help = "Supply a present named attachment collection with no members"
    )]
    input_attachments_empty: Vec<String>,
}

impl NamedInputArgs {
    fn is_empty(&self) -> bool {
        self.input_text.is_empty()
            && self.input_text_file.is_empty()
            && self.input_json.is_empty()
            && self.input_json_file.is_empty()
            && self.input_file.is_empty()
            && self.input_attachment.is_empty()
            && self.input_attachments_empty.is_empty()
    }
}

#[derive(Debug)]
enum OpenRegularFileError {
    Open(io::Error),
    Metadata(io::Error),
    NotRegular,
}

fn open_regular_file_nonblocking(path: &Path) -> Result<File, OpenRegularFileError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(OpenRegularFileError::Open)?;
    if !file
        .metadata()
        .map_err(OpenRegularFileError::Metadata)?
        .is_file()
    {
        return Err(OpenRegularFileError::NotRegular);
    }
    Ok(file)
}

#[derive(Clone, Debug)]
struct ContinuationCursor(String);

impl FromStr for ContinuationCursor {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            Err("must be a nonempty opaque cursor".to_owned())
        } else {
            Ok(Self(value.to_owned()))
        }
    }
}

impl Deref for ContinuationCursor {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub(crate) struct CommandFailure {
    error: anyhow::Error,
    exit_code: ExitCode,
}

impl CommandFailure {
    pub(crate) fn new(error: anyhow::Error) -> Self {
        Self {
            error,
            exit_code: ExitCode::GeneralFailure,
        }
    }

    pub(crate) fn with_exit_code(error: anyhow::Error, exit_code: ExitCode) -> Self {
        Self { error, exit_code }
    }

    pub(crate) fn for_outcome(error: anyhow::Error, outcome: OutcomeClass) -> Self {
        Self::with_exit_code(error, outcome.exit_code())
    }

    pub(crate) fn error(&self) -> &anyhow::Error {
        &self.error
    }

    pub(crate) fn exit_code(&self) -> ExitCode {
        self.exit_code
    }
}

impl From<anyhow::Error> for CommandFailure {
    fn from(error: anyhow::Error) -> Self {
        Self::new(error)
    }
}

const AFTER_HELP: &str = "Documentation:\n  Public API contract: https://docs.usefulmachinery.com/openapi/public-api.yaml";

#[derive(Debug, Args)]
#[command(
    name = "useful",
    about = "Useful Machinery CLI",
    version = crate::build_info::VERSION,
    after_help = AFTER_HELP
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

impl CommandFactory for Cli {
    fn command() -> clap::Command {
        with_pagination_after_help(<Self as Args>::augment_args(clap::Command::new("useful")))
    }

    fn command_for_update() -> clap::Command {
        with_pagination_after_help(<Self as Args>::augment_args_for_update(clap::Command::new(
            "useful",
        )))
    }
}

impl Parser for Cli {}

const PAGINATION_AFTER_HELP: &str =
    "Pagination:\n  This command returns one page. Pass --cursor <CURSOR> to continue.";

fn with_pagination_after_help(mut command: clap::Command) -> clap::Command {
    for subcommand in command.get_subcommands_mut() {
        *subcommand = with_pagination_after_help(std::mem::take(subcommand));
    }

    let paginates = command
        .get_arguments()
        .any(|argument| argument.get_id() == "cursor");
    if paginates {
        let existing = command.get_after_help().map(ToString::to_string);
        if !existing
            .as_deref()
            .is_some_and(|help| help.contains(PAGINATION_AFTER_HELP))
        {
            let help = existing.map_or_else(
                || PAGINATION_AFTER_HELP.to_owned(),
                |help| format!("{help}\n\n{PAGINATION_AFTER_HELP}"),
            );
            command = command.after_help(help);
        }
    }
    command
}

#[derive(Clone, Copy, Debug)]
enum JsonOutput {
    Family(&'static str),
    StreamingEvents,
}

trait JsonOutputKind: std::fmt::Debug {
    const OUTPUT: JsonOutput;
}

macro_rules! json_family {
    ($name:ident, $noun:literal) => {
        #[derive(Debug)]
        struct $name;

        impl JsonOutputKind for $name {
            const OUTPUT: JsonOutput = JsonOutput::Family($noun);
        }
    };
}

json_family!(AccountJson, "account");
json_family!(ConnectionJson, "connection");
json_family!(DelegationJson, "delegation");
json_family!(DeletionJson, "deletion");
json_family!(GrantJson, "grant");
json_family!(IdentityJson, "identity");
json_family!(InvitationJson, "invitation");
json_family!(OrganizationJson, "organization");
json_family!(ProjectJson, "project");
json_family!(RunJson, "run");
json_family!(RunnerJson, "runner");
json_family!(ServicePrincipalJson, "service-principal");
json_family!(SignInJson, "sign-in");
json_family!(VersionJson, "version");
json_family!(WorkflowJson, "workflow");

#[derive(Debug)]
struct StreamingJson;

impl JsonOutputKind for StreamingJson {
    const OUTPUT: JsonOutput = JsonOutput::StreamingEvents;
}

fn json_help<F: JsonOutputKind>() -> String {
    match F::OUTPUT {
        JsonOutput::Family(noun) => format!("Print the {noun} result as JSON"),
        JsonOutput::StreamingEvents => "Emit newline-delimited JSON events".to_owned(),
    }
}

#[derive(Debug, Args)]
struct JsonArgs<F: JsonOutputKind> {
    #[arg(long, help = json_help::<F>())]
    json: bool,

    #[arg(skip)]
    output: PhantomData<F>,
}

#[derive(Debug, Args)]
struct ConfirmationArgs {
    #[arg(long, required = true, help = "Confirm this action")]
    _yes: bool,
}

#[derive(Debug, Args, Default)]
struct NoAuthenticationArgs {}

#[derive(Debug, Args)]
struct CommonArgs<F: JsonOutputKind, A: Args> {
    #[command(flatten)]
    output: JsonArgs<F>,

    #[command(flatten)]
    authentication: A,

    #[command(flatten)]
    http: HttpOptions,
}

impl<F: JsonOutputKind, A: Args> CommonArgs<F, A> {
    fn new(json: bool, authentication: A, http: HttpOptions) -> Self {
        Self {
            output: JsonArgs {
                json,
                output: PhantomData,
            },
            authentication,
            http,
        }
    }
}

impl<F: JsonOutputKind, A: Args> Deref for CommonArgs<F, A> {
    type Target = JsonArgs<F>;

    fn deref(&self) -> &Self::Target {
        &self.output
    }
}

#[derive(Debug, Args)]
struct HttpOptions {
    #[arg(
        long,
        help = "Allow this command's Useful Machinery requests over insecure HTTP connections"
    )]
    allow_insecure_http: bool,
}

impl HttpOptions {
    fn transport_policy(&self) -> HttpTransportPolicy {
        if self.allow_insecure_http {
            HttpTransportPolicy::AllowInsecureHttp
        } else {
            HttpTransportPolicy::HttpsOnly
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrincipalAuthenticationKind {
    HumanSession,
    ServiceApiKey,
}

impl PrincipalAuthenticationKind {
    const fn rejected_error(self, human_session: &'static str) -> &'static str {
        match self {
            Self::HumanSession => human_session,
            Self::ServiceApiKey => {
                "error: service API key rejected\n\nUse a different active service API key."
            }
        }
    }

    const fn rejected_remedy(self, human_session: &'static str) -> &'static str {
        match self {
            Self::HumanSession => human_session,
            Self::ServiceApiKey => "Use a different active service API key.",
        }
    }

    const fn rejected_notice(self, human_session: &'static str) -> &'static str {
        match self {
            Self::HumanSession => human_session,
            Self::ServiceApiKey => {
                "! The service API key was rejected.\n\nUse a different active service API key."
            }
        }
    }
}

#[derive(Debug, Args, Default)]
struct PrincipalAuthenticationArgs {
    #[arg(
        long,
        value_name = "PATH|-",
        help = "Authenticate with a service API key from a private file, or - for standard input"
    )]
    api_key_file: Option<PathBuf>,

    #[arg(skip)]
    resolved_service_api_key: Mutex<Option<Arc<ServiceApiKey>>>,
}

#[derive(Debug, Args)]
struct RequiredServiceAuthenticationArgs {
    #[arg(
        long,
        value_name = "PATH|-",
        help = "Authenticate with a service API key from a private file, or - for standard input"
    )]
    api_key_file: PathBuf,
}

impl RequiredServiceAuthenticationArgs {
    fn api_key(&self) -> anyhow::Result<ServiceApiKey> {
        read_api_key(&self.api_key_file).context("read service API key")
    }
}

impl PrincipalAuthenticationArgs {
    const fn kind(&self) -> PrincipalAuthenticationKind {
        if self.api_key_file.is_some() {
            PrincipalAuthenticationKind::ServiceApiKey
        } else {
            PrincipalAuthenticationKind::HumanSession
        }
    }

    fn service_api_key(&self) -> anyhow::Result<Option<Arc<ServiceApiKey>>> {
        let Some(path) = self.api_key_file.as_deref() else {
            return Ok(None);
        };
        let mut resolved = self
            .resolved_service_api_key
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(api_key) = resolved.as_ref() {
            return Ok(Some(Arc::clone(api_key)));
        }
        let api_key = Arc::new(read_api_key(path).context("read service API key")?);
        *resolved = Some(Arc::clone(&api_key));
        Ok(Some(api_key))
    }

    fn required_service_api_key(&self) -> anyhow::Result<Arc<ServiceApiKey>> {
        self.service_api_key()?
            .ok_or_else(|| anyhow!("--api-key-file is required for service credential management"))
    }

    fn uses_stdin(&self) -> bool {
        self.api_key_file.as_deref() == Some(Path::new("-"))
    }
}

const WAIT_TIMEOUT_HELP: &str =
    "Stop waiting after a positive duration (units: ms, s, m, or h; a bare number means seconds)";

#[derive(Debug, Args)]
struct WaitTimeoutArgs {
    #[arg(
        long,
        value_name = "DURATION",
        value_parser = parse_wait_timeout,
        help = WAIT_TIMEOUT_HELP
    )]
    timeout: Option<Duration>,
}

#[derive(Debug, Args)]
#[command(after_help = PAGINATION_AFTER_HELP)]
struct PaginationArgs<const MAX: u16 = 200> {
    #[arg(
        long,
        value_parser = clap::value_parser!(u16).range(1..=i64::from(MAX)),
        help = format!("Maximum items to return (1-{MAX})")
    )]
    limit: Option<u16>,

    #[arg(long, help = "Opaque continuation cursor")]
    cursor: Option<ContinuationCursor>,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = account::ABOUT)]
    Account(account::Command),
    #[command(about = org::ABOUT)]
    Org(org::Command),
    #[command(about = project::ABOUT)]
    Project(project::Command),
    #[command(about = runner::ABOUT)]
    Runner(runner::Command),
    #[command(about = version::ABOUT)]
    Version(version::Command),
    #[command(about = workflow::ABOUT)]
    Workflow(workflow::Command),
}

pub(crate) fn parse<I, S>(args: I) -> Result<Cli, clap::Error>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString> + Clone,
{
    let mut command = Cli::command();
    let matches = command.try_get_matches_from_mut(args)?;
    Cli::from_arg_matches(&matches).map_err(|error| error.format(&mut command))
}

impl Cli {
    pub(crate) fn execute(self) -> CommandResult {
        useful_api::identify_client(crate::build_info::VERSION);
        match self.command {
            None => print_help(&[]),
            Some(Command::Account(command)) => command.execute(),
            Some(Command::Org(command)) => command.execute(),
            Some(Command::Project(command)) => command.execute(),
            Some(Command::Version(command)) => command.execute(),
            Some(Command::Runner(command)) => command.execute(),
            Some(Command::Workflow(command)) => command.execute(),
        }
    }
}

pub(crate) const fn unreachable_outcome_class(
    category: useful_api::UnreachableCategory,
) -> OutcomeClass {
    match category {
        useful_api::UnreachableCategory::RateLimited => OutcomeClass::RateLimited,
        useful_api::UnreachableCategory::Dns
        | useful_api::UnreachableCategory::Timeout
        | useful_api::UnreachableCategory::Connection
        | useful_api::UnreachableCategory::Tls
        | useful_api::UnreachableCategory::Server => OutcomeClass::Unreachable,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiFailureResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CloudListResult<'a, T> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    items: &'a [T],
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<&'a str>,
}

impl<'a, T> CloudListResult<'a, T> {
    /// One listed page of `items`, which a list whose document has its own members flattens
    /// into that document.
    const fn listed(
        schema_version: u8,
        deployment: &'a str,
        items: &'a [T],
        next_cursor: Option<&'a str>,
    ) -> Self {
        Self {
            schema_version,
            deployment,
            outcome: "listed",
            items,
            next_cursor,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ObservationResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    organization_ref: &'a str,
    run_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    publication_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    idempotency_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<&'static str>,
}

impl<'a> ApiFailureResult<'a> {
    const fn new(
        deployment: &'a str,
        outcome: &'static str,
        category: Option<&'static str>,
    ) -> Self {
        Self {
            schema_version: 1,
            deployment,
            outcome,
            category,
            retry_after: None,
        }
    }

    const fn with_retry_after(
        deployment: &'a str,
        outcome: &'static str,
        category: Option<&'static str>,
        retry_after: Option<u64>,
    ) -> Self {
        Self {
            schema_version: 1,
            deployment,
            outcome,
            category,
            retry_after,
        }
    }
}

/// An API operation's failure as a member reads it: the closed outcome and the facts a script
/// needs, which `--json` prints, and the human summary and remedy.
struct ApiFailureReport {
    outcome: &'static str,
    category: Option<&'static str>,
    retry_after: Option<u64>,
    summary: String,
    remedy: String,
    class: OutcomeClass,
}

impl ApiFailureReport {
    fn new(
        outcome: &'static str,
        summary: impl Into<String>,
        remedy: impl Into<String>,
        class: OutcomeClass,
    ) -> Self {
        Self {
            outcome,
            category: None,
            retry_after: None,
            summary: summary.into(),
            remedy: remedy.into(),
            class,
        }
    }

    // The failures every member API reports alike, worded for its `subject`: "grant" or
    // "provider grant".
    fn unauthenticated(subject: &str) -> Self {
        Self::new(
            "unauthenticated",
            format!("! You must sign in before managing {subject}s."),
            "Run:\n  useful account login",
            OutcomeClass::Unauthenticated,
        )
    }

    fn forbidden(subject: &str) -> Self {
        Self::new(
            "forbidden",
            format!("! Your account is not permitted to manage {subject}s."),
            "Sign in as an active member:\n  useful account login",
            OutcomeClass::Forbidden,
        )
    }

    fn idempotency_conflict(subject: &str) -> Self {
        Self::new(
            "idempotency_conflict",
            format!("error: {subject} request key already used for another request"),
            "Run the command again; it sends a new request key.",
            OutcomeClass::GeneralFailure,
        )
    }

    fn rate_limited(subject: &str, retry_after: Option<u64>) -> Self {
        let summary = match retry_after {
            Some(seconds) => {
                format!("error: {subject} requests rate limited\nretry after: {seconds}s")
            }
            None => format!("error: {subject} requests rate limited"),
        };
        Self {
            retry_after,
            ..Self::new(
                "rate_limited",
                summary,
                "Wait, then run the command again.",
                OutcomeClass::RateLimited,
            )
        }
    }

    fn unreachable(deployment: &str, category: UnreachableCategory) -> Self {
        Self {
            category: Some(category.as_str()),
            ..Self::new(
                "unreachable",
                format!(
                    "error: Useful Machinery deployment unreachable: {deployment}\ncategory: {}",
                    category.as_str()
                ),
                "Check access to the deployment, then run the command again.",
                unreachable_outcome_class(category),
            )
        }
    }

    fn invalid_response(subject: &str) -> Self {
        Self::new(
            "invalid_response",
            format!("error: invalid {subject} response from the deployment"),
            "Use a CLI version supported by this deployment.",
            OutcomeClass::Protocol,
        )
    }

    /// Prints the closed result with `--json`, otherwise the summary and remedy on stderr.
    fn write(&self, deployment: &str, json: bool) -> anyhow::Result<ExitCode> {
        write_api_failure(
            deployment,
            self.outcome,
            self.category,
            self.retry_after,
            &format!("{}\n\n{}", self.summary, self.remedy),
            self.class,
            json,
        )
    }
}

// Publication and handoff diagnostics have different closed member sets but the same
// human presentation: show each returned fact without interpreting its open value.
fn write_publication_diagnostic(
    output: &mut impl Write,
    diagnostic: &impl Serialize,
    indent: &str,
) -> anyhow::Result<()> {
    let serde_json::Value::Object(fields) = serde_json::to_value(diagnostic)? else {
        return Err(anyhow::anyhow!("publication diagnostic is not an object"));
    };
    for (key, value) in fields {
        let mut label = String::with_capacity(key.len() + 3);
        for character in key.chars() {
            if character.is_ascii_uppercase() {
                label.push(' ');
                label.push(character.to_ascii_lowercase());
            } else {
                label.push(character);
            }
        }
        let text = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        writeln!(output, "{indent}diagnostic {label}: {text}")?;
    }
    Ok(())
}

fn write_pretty_json(value: &impl Serialize) -> io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(&bytes)?;
    stdout.flush()
}

/// One compact JSON document on its own line, for commands whose output is a stream of events.
fn write_json_line(value: &impl Serialize) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(&bytes)?;
    stdout.flush()
}

fn write_api_failure(
    deployment: &str,
    outcome: &'static str,
    category: Option<&'static str>,
    retry_after: Option<u64>,
    human: &str,
    outcome_class: OutcomeClass,
    json: bool,
) -> anyhow::Result<ExitCode> {
    if json {
        write_pretty_json(&ApiFailureResult::with_retry_after(
            deployment,
            outcome,
            category,
            retry_after,
        ))?;
    } else {
        writeln!(io::stderr().lock(), "{human}")?;
    }
    Ok(outcome_class.exit_code())
}

fn write_cloud_list_json(
    deployment: &str,
    items: &[impl Serialize],
    next_cursor: Option<&str>,
) -> io::Result<()> {
    write_cloud_list_json_version(1, deployment, items, next_cursor)
}

fn write_cloud_list_json_version(
    version: u8,
    deployment: &str,
    items: &[impl Serialize],
    next_cursor: Option<&str>,
) -> io::Result<()> {
    write_pretty_json(&CloudListResult::listed(
        version,
        deployment,
        items,
        next_cursor,
    ))
}

fn write_cloud_failure_json(
    deployment: &str,
    outcome: &'static str,
    category: Option<&'static str>,
    retry_after: Option<u64>,
) -> io::Result<()> {
    write_pretty_json(&ApiFailureResult::with_retry_after(
        deployment,
        outcome,
        category,
        retry_after,
    ))
}

fn write_page_footer(
    output: &mut impl Write,
    deployment: &str,
    next_cursor: Option<&str>,
) -> io::Result<()> {
    if let Some(next_cursor) = next_cursor {
        writeln!(output, "next cursor: {next_cursor}")?;
    }
    writeln!(output, "deployment: {deployment}")
}

const fn membership_role(role: MembershipRole) -> &'static str {
    match role {
        MembershipRole::Owner => "owner",
        MembershipRole::Member => "member",
    }
}

const fn membership_state(state: MembershipState) -> &'static str {
    match state {
        MembershipState::Active => "active",
        MembershipState::Suspended => "suspended",
        MembershipState::Ended => "ended",
    }
}

struct ProcessSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

impl ProcessSignals {
    fn install(context: &str) -> anyhow::Result<Self> {
        (|| -> io::Result<_> {
            Ok(Self {
                interrupt: tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::interrupt(),
                )?,
                terminate: tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::terminate(),
                )?,
            })
        })()
        .with_context(|| format!("install {context} signal observation"))
    }

    async fn recv(&mut self) -> ExitCode {
        tokio::select! {
            biased;
            _ = self.interrupt.recv() => OutcomeClass::Interrupted.exit_code(),
            _ = self.terminate.recv() => OutcomeClass::Terminated.exit_code(),
        }
    }
}

fn execute_read_only_with_signals(
    context: &'static str,
    operation: impl FnOnce(&OperationControl<()>) -> CommandResult + Send + 'static,
) -> CommandResult {
    execute_mutation_with_signals(context, (), operation, |signal, _| Ok(signal))
}

fn execute_cancellable_with_signals(
    context: &'static str,
    operation: impl FnOnce(&Cancellation) -> CommandResult + Send + 'static,
) -> CommandResult {
    run_blocking_signal_runtime(context, async move {
        let mut signals = ProcessSignals::install(context)?;
        let cancellation = Cancellation::new();
        let operation_cancellation = cancellation.clone();
        let mut running = tokio::task::spawn_blocking(move || operation(&operation_cancellation));
        tokio::select! {
            biased;
            signal = signals.recv() => {
                cancellation.cancel();
                let result = finish_read_only_operation(context, running.await);
                match result {
                    Ok(ExitCode::Interrupted) => Ok(signal),
                    result => result,
                }
            }
            result = &mut running => finish_read_only_operation(context, result),
        }
    })
}

fn execute_cancellable_mutation_with_signals(
    context: &'static str,
    operation: impl FnOnce(&useful_api::HttpCancellation, &OperationControl<()>) -> CommandResult
    + Send
    + 'static,
    interrupt_operation: impl FnOnce() -> bool + 'static,
    incomplete_signal: impl FnOnce(ExitCode, bool) -> CommandResult + 'static,
) -> CommandResult {
    run_blocking_signal_runtime(context, async move {
        let mut signals = ProcessSignals::install(context)?;
        let cancellation = useful_api::HttpCancellation::new();
        let control = Arc::new(OperationControl::new(()));
        let operation_cancellation = cancellation.clone();
        let operation_control = Arc::clone(&control);
        let mut running = tokio::task::spawn_blocking(move || {
            operation(&operation_cancellation, &operation_control)
        });
        tokio::select! {
            biased;
            signal = signals.recv() => match control.claim_signal() {
                Some(_) => {
                    cancellation.cancel();
                    let commitment_unknown = interrupt_operation();
                    finish_read_only_operation(context, running.await)?;
                    incomplete_signal(signal, commitment_unknown)
                }
                None => finish_read_only_operation(context, running.await),
            },
            result = &mut running => finish_read_only_operation(context, result),
        }
    })
}

fn execute_bounded_mutation_with_signals(
    context: &'static str,
    operation: impl FnOnce(&OperationControl<()>) -> CommandResult + Send + 'static,
) -> CommandResult {
    execute_cancellable_mutation_with_signals(
        context,
        move |_, control| operation(control),
        || false,
        |signal, _| Ok(signal),
    )
}

// A terminal result and a local stop compete for one output claim so timeout/signal
// races cannot emit two machine documents or replace a terminal result after it wins.
const OBSERVATION_ACTIVE: u8 = 0;
const OBSERVATION_COMPLETING: u8 = 1;
const OBSERVATION_STOPPED: u8 = 2;

trait ObservationControl {
    fn is_stopped(&self) -> bool;
    // This is the read's admission point. A stop that wins first bars the read;
    // a read admitted first may finish while the stop owns the local output.
    fn admit_read(&self) -> bool;
}

struct BlockingObservationControl {
    state: AtomicU8,
}

impl BlockingObservationControl {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(OBSERVATION_ACTIVE),
        }
    }

    fn is_stopped(&self) -> bool {
        self.state.load(Ordering::Acquire) == OBSERVATION_STOPPED
    }

    fn begin_completion(&self) -> bool {
        self.state
            .compare_exchange(
                OBSERVATION_ACTIVE,
                OBSERVATION_COMPLETING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    fn stop(&self) -> bool {
        self.state
            .compare_exchange(
                OBSERVATION_ACTIVE,
                OBSERVATION_STOPPED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

impl ObservationControl for BlockingObservationControl {
    fn is_stopped(&self) -> bool {
        self.is_stopped()
    }

    fn admit_read(&self) -> bool {
        self.state
            .compare_exchange(
                OBSERVATION_ACTIVE,
                OBSERVATION_ACTIVE,
                Ordering::Acquire,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

struct ObservationTimeout {
    duration: Option<Duration>,
}

impl ObservationTimeout {
    async fn wait(self) {
        match self.duration {
            Some(duration) => useful_support::async_sleep(duration).await,
            None => std::future::pending().await,
        }
    }
}

struct DeferredObservationTimeoutStart {
    sender: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl DeferredObservationTimeoutStart {
    fn start(&self) {
        if let Some(sender) = self
            .sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = sender.send(());
        }
    }
}

struct DeferredObservationTimeout {
    duration: Option<Duration>,
    started: tokio::sync::oneshot::Receiver<()>,
}

impl DeferredObservationTimeout {
    async fn wait(self) {
        let Some(duration) = self.duration else {
            return std::future::pending().await;
        };
        if self.started.await.is_err() {
            return std::future::pending().await;
        }
        useful_support::async_sleep(duration).await;
    }
}

const OBSERVATION_POLL_INTERVAL: Duration = Duration::from_secs(2);
const MAXIMUM_CONSECUTIVE_OBSERVATION_FAILURES: usize = 2;

fn observation_poll_interval() -> Duration {
    useful_support::poll_interval(OBSERVATION_POLL_INTERVAL)
}

trait ObservationClock {
    fn now(&self) -> Instant;
    fn sleep(&self, duration: Duration);
}

struct SystemObservationClock;

impl ObservationClock for SystemObservationClock {
    fn now(&self) -> Instant {
        useful_support::monotonic_now()
    }

    fn sleep(&self, duration: Duration) {
        useful_support::sleep(duration);
    }
}

// A ceremony the member completes elsewhere (a Linear authorization, a provider grant
// consent) is polled at this cadence.
const CEREMONY_POLL_INTERVAL: Duration = Duration::from_secs(5);
const POLL_WAIT_SLICE: Duration = Duration::from_millis(100);

fn ceremony_poll_interval() -> Duration {
    useful_support::poll_interval(CEREMONY_POLL_INTERVAL)
}

/// Waits `delay` in short slices so a signal ends the wait; false once the operation is
/// cancelled.
fn wait_for_poll<R>(
    control: &OperationControl<R>,
    delay: Duration,
    clock: &impl ObservationClock,
) -> bool {
    let started = clock.now();
    loop {
        if control.is_cancelled() {
            return false;
        }
        let remaining = delay.saturating_sub(clock.now().saturating_duration_since(started));
        if remaining.is_zero() {
            return true;
        }
        clock.sleep(remaining.min(POLL_WAIT_SLICE));
    }
}

/// The wait after a rate-limited poll: the server's `Retry-After`, never under the cadence.
fn retry_delay(retry_after: Option<u64>) -> Duration {
    Duration::from_secs(retry_after.unwrap_or(0)).max(ceremony_poll_interval())
}

#[cfg(test)]
mod observation_test_support {
    use std::cell::{Cell, RefCell};
    use std::time::{Duration, Instant};

    pub(super) struct ControlledObservationClock {
        now: Cell<Instant>,
        sleeps: RefCell<Vec<Duration>>,
    }

    impl ControlledObservationClock {
        pub(super) fn new(now: Instant) -> Self {
            Self {
                now: Cell::new(now),
                sleeps: RefCell::new(Vec::new()),
            }
        }

        pub(super) fn assert_timeout_schedule(self) {
            assert_eq!(
                self.sleeps.into_inner(),
                vec![
                    Duration::from_secs(2),
                    Duration::from_secs(2),
                    Duration::from_secs(1)
                ]
            );
        }

        pub(super) fn assert_single_poll(self) {
            assert_eq!(
                self.sleeps.into_inner(),
                vec![super::OBSERVATION_POLL_INTERVAL]
            );
        }

        pub(super) fn into_sleeps(self) -> Vec<Duration> {
            self.sleeps.into_inner()
        }

        pub(super) fn advance(&self, duration: Duration) {
            self.now.set(self.now.get() + duration);
        }
    }

    impl super::ObservationClock for ControlledObservationClock {
        fn now(&self) -> Instant {
            self.now.get()
        }

        fn sleep(&self, duration: Duration) {
            self.sleeps.borrow_mut().push(duration);
            self.now.set(self.now.get() + duration);
        }
    }
}

enum TerminalObservation<T, S> {
    Terminal { resource: Box<T>, state: S },
    TimedOut,
    Stopped,
}

fn wait_for_terminal_observation<T, S, E>(
    mut observe: impl FnMut() -> Result<T, E>,
    terminal_state: impl Fn(&T) -> Option<S>,
    retryable_failure: impl Fn(&E) -> bool,
    timeout: Option<Duration>,
    control: &impl ObservationControl,
    clock: &impl ObservationClock,
) -> Result<TerminalObservation<T, S>, E> {
    wait_for_terminal_observation_bounded(
        |_| observe(),
        terminal_state,
        retryable_failure,
        timeout,
        clock.now(),
        control,
        clock,
    )
}

fn wait_for_terminal_observation_bounded<T, S, E>(
    mut observe: impl FnMut(Option<Duration>) -> Result<T, E>,
    terminal_state: impl Fn(&T) -> Option<S>,
    retryable_failure: impl Fn(&E) -> bool,
    timeout: Option<Duration>,
    started_at: Instant,
    control: &impl ObservationControl,
    clock: &impl ObservationClock,
) -> Result<TerminalObservation<T, S>, E> {
    let mut consecutive_failures = 0;
    loop {
        if control.is_stopped() {
            return Ok(TerminalObservation::Stopped);
        }
        let remaining = remaining_observation_wait(timeout, started_at, clock.now());
        // Stop can win while the deadline is sampled. Admit no new read in that case.
        if control.is_stopped() {
            return Ok(TerminalObservation::Stopped);
        }
        let Some(remaining) = remaining else {
            return Ok(TerminalObservation::TimedOut);
        };

        // Linearize read admission with signal/timeout stop, not with an earlier
        // status sample. Do not hold the control lock across a blocking GET.
        if !control.admit_read() {
            return Ok(TerminalObservation::Stopped);
        }
        match observe(timeout.map(|_| remaining)) {
            Ok(resource) => {
                consecutive_failures = 0;
                if let Some(state) = terminal_state(&resource) {
                    return Ok(TerminalObservation::Terminal {
                        resource: Box::new(resource),
                        state,
                    });
                }
            }
            Err(failure)
                if retryable_failure(&failure)
                    && consecutive_failures + 1 < MAXIMUM_CONSECUTIVE_OBSERVATION_FAILURES =>
            {
                consecutive_failures += 1;
            }
            Err(failure) => return Err(failure),
        }

        if control.is_stopped() {
            return Ok(TerminalObservation::Stopped);
        }
        let Some(remaining) = remaining_observation_wait(timeout, started_at, clock.now()) else {
            return Ok(TerminalObservation::TimedOut);
        };
        clock.sleep(observation_poll_interval().min(remaining));
    }
}

fn remaining_observation_wait(
    timeout: Option<Duration>,
    started_at: Instant,
    now: Instant,
) -> Option<Duration> {
    match timeout {
        Some(timeout) => timeout
            .checked_sub(now.saturating_duration_since(started_at))
            .filter(|remaining| !remaining.is_zero()),
        None => Some(observation_poll_interval()),
    }
}

/// The first unit of `units`, in table order, whose suffix `value` ends with, as the text
/// in front of that suffix and the unit's scale.
fn split_unit_suffix<'a, S: Copy>(value: &'a str, units: &[(&str, S)]) -> Option<(&'a str, S)> {
    units
        .iter()
        .find_map(|&(suffix, scale)| value.strip_suffix(suffix).map(|quantity| (quantity, scale)))
}

fn parse_wait_timeout(value: &str) -> Result<Duration, String> {
    // `ms` precedes `s`, which it ends with.
    let (quantity, milliseconds) = split_unit_suffix(
        value,
        &[("ms", 1), ("s", 1_000), ("m", 60_000), ("h", 3_600_000)],
    )
    .unwrap_or((value, 1_000));
    let total_milliseconds = quantity
        .parse::<u64>()
        .ok()
        .and_then(|quantity| quantity.checked_mul(milliseconds))
        .filter(|duration| *duration > 0)
        .ok_or_else(|| {
            "duration must be a positive integer, optionally followed by ms, s, m, or h".to_owned()
        })?;
    Ok(Duration::from_millis(total_milliseconds))
}

fn blocking_signal_runtime(context: &str) -> anyhow::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .with_context(|| format!("start {context} runtime"))
}

fn run_blocking_signal_runtime(
    context: &str,
    operation: impl std::future::Future<Output = CommandResult>,
) -> CommandResult {
    let runtime = blocking_signal_runtime(context)?;
    let result = runtime.block_on(operation);
    runtime.shutdown_timeout(Duration::ZERO);
    result
}

fn spawn_controlled_blocking<C>(
    control: Arc<C>,
    operation: impl FnOnce(&C) -> CommandResult + Send + 'static,
) -> tokio::task::JoinHandle<CommandResult>
where
    C: Send + Sync + 'static,
{
    tokio::task::spawn_blocking(move || operation(&control))
}

async fn finish_stopped_operation(
    context: &str,
    running: &mut tokio::task::JoinHandle<CommandResult>,
    stopped: Option<CommandResult>,
) -> CommandResult {
    match stopped {
        Some(result) => result,
        None => finish_read_only_operation(context, running.await),
    }
}

fn execute_observation_with_signals_and_timeout(
    context: &'static str,
    timeout: Option<Duration>,
    operation: impl FnOnce(&BlockingObservationControl) -> CommandResult + Send + 'static,
    timed_out: impl FnOnce() -> CommandResult + 'static,
) -> CommandResult {
    run_blocking_signal_runtime(context, async move {
        let mut signals = ProcessSignals::install(context)?;
        let control = Arc::new(BlockingObservationControl::new());
        let mut running = spawn_controlled_blocking(Arc::clone(&control), operation);
        tokio::select! {
            biased;
            signal = signals.recv() => {
                let stopped = control.stop().then(|| Ok(signal));
                finish_stopped_operation(context, &mut running, stopped).await
            }
            () = (ObservationTimeout { duration: timeout }).wait() => {
                let stopped = control.stop().then(timed_out);
                finish_stopped_operation(context, &mut running, stopped).await
            }
            result = &mut running => finish_read_only_operation(context, result),
        }
    })
}

// Dispatch, recovery, and output ownership are linearized by one state lock. Mutations claim
// Completion before rendering so a signal cannot add a second receipt. A bounded one-time-secret
// mutation may claim Completion at dispatch and retain it through delivery. Read-only commands
// enter ReadOnlyOutput instead: a signal may abandon a blocked writer until output finishes and
// claims Completion. The lock is released before requests, joins, rendering, and callbacks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationOwner {
    Active,
    ReadOnlyOutput,
    Completion,
    Signal,
}

struct OperationState<R> {
    owner: OperationOwner,
    dispatched: bool,
    recovery: R,
}

struct OperationControl<R> {
    // A derived cooperative-stop notification for CPU-bound helpers. It is set only while
    // transitioning the authoritative state to Signal and never grants dispatch/output authority.
    cooperative_stop: AtomicBool,
    state: Mutex<OperationState<R>>,
}

impl<R> ObservationControl for OperationControl<R> {
    fn is_stopped(&self) -> bool {
        self.is_cancelled()
    }

    fn admit_read(&self) -> bool {
        self.lock_owned_state(OperationOwner::Active).is_some()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SignalSnapshot<R> {
    dispatched: bool,
    recovery: R,
}

fn report_dispatched_signal<R>(
    signal: ExitCode,
    snapshot: SignalSnapshot<R>,
    report: impl FnOnce(R) -> CommandResult,
) -> CommandResult {
    if snapshot.dispatched {
        report(snapshot.recovery)
    } else {
        Ok(signal)
    }
}

impl<R> OperationControl<R> {
    fn new(recovery: R) -> Self {
        Self {
            cooperative_stop: AtomicBool::new(false),
            state: Mutex::new(OperationState {
                owner: OperationOwner::Active,
                dispatched: false,
                recovery,
            }),
        }
    }

    fn cancellation(&self) -> &AtomicBool {
        &self.cooperative_stop
    }

    fn is_cancelled(&self) -> bool {
        self.cooperative_stop.load(Ordering::Acquire)
    }

    fn lock_owned_state(
        &self,
        expected_owner: OperationOwner,
    ) -> Option<std::sync::MutexGuard<'_, OperationState<R>>> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (state.owner == expected_owner).then_some(state)
    }

    fn begin_dispatch(&self) -> bool {
        let Some(mut state) = self.lock_owned_state(OperationOwner::Active) else {
            return false;
        };
        state.dispatched = true;
        true
    }

    fn begin_bounded_dispatch(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match state.owner {
            OperationOwner::Active => {
                state.owner = OperationOwner::Completion;
                state.dispatched = true;
                true
            }
            OperationOwner::Completion if state.dispatched => true,
            OperationOwner::ReadOnlyOutput
            | OperationOwner::Completion
            | OperationOwner::Signal => false,
        }
    }

    fn dispatched(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .dispatched
    }

    fn begin_dispatch_with_recovery(&self, recovery: R) -> bool {
        let Some(mut state) = self.lock_owned_state(OperationOwner::Active) else {
            return false;
        };
        state.recovery = recovery;
        state.dispatched = true;
        true
    }

    fn update_recovery(&self, recovery: R) -> bool {
        let Some(mut state) = self.lock_owned_state(OperationOwner::Active) else {
            return false;
        };
        state.recovery = recovery;
        true
    }

    fn recovery(&self) -> R
    where
        R: Clone,
    {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recovery
            .clone()
    }

    fn transition_owner(&self, from: OperationOwner, to: OperationOwner) -> bool {
        let Some(mut state) = self.lock_owned_state(from) else {
            return false;
        };
        state.owner = to;
        true
    }

    fn begin_completion(&self) -> bool {
        self.transition_owner(OperationOwner::Active, OperationOwner::Completion)
    }

    fn begin_read_only_output(&self) -> bool {
        self.transition_owner(OperationOwner::Active, OperationOwner::ReadOnlyOutput)
    }

    fn finish_read_only_output(&self) -> bool {
        self.transition_owner(OperationOwner::ReadOnlyOutput, OperationOwner::Completion)
    }

    fn claim_signal(&self) -> Option<SignalSnapshot<R>>
    where
        R: Clone,
    {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(
            state.owner,
            OperationOwner::Active | OperationOwner::ReadOnlyOutput
        ) {
            return None;
        }
        state.owner = OperationOwner::Signal;
        self.cooperative_stop.store(true, Ordering::Release);
        Some(SignalSnapshot {
            dispatched: state.dispatched,
            recovery: state.recovery.clone(),
        })
    }
}

fn complete_operation<R>(
    control: &OperationControl<R>,
    output: impl FnOnce() -> CommandResult,
) -> CommandResult {
    if control.begin_completion() {
        output()
    } else {
        Ok(ExitCode::GeneralFailure)
    }
}

fn complete_read_only_output<R>(
    control: &OperationControl<R>,
    output: impl FnOnce() -> CommandResult,
) -> CommandResult {
    if !control.begin_read_only_output() {
        return Ok(ExitCode::GeneralFailure);
    }
    let result = output();
    if control.finish_read_only_output() {
        result
    } else {
        Ok(ExitCode::GeneralFailure)
    }
}

fn execute_mutation_with_signals<R>(
    context: &'static str,
    recovery: R,
    operation: impl FnOnce(&OperationControl<R>) -> CommandResult + Send + 'static,
    incomplete_signal: impl FnOnce(ExitCode, SignalSnapshot<R>) -> CommandResult + 'static,
) -> CommandResult
where
    R: Clone + Send + 'static,
{
    execute_mutation_with_signals_and_deferred_timeout(
        context,
        recovery,
        None,
        move |control, _| operation(control),
        incomplete_signal,
        |_| Ok(ExitCode::GeneralFailure),
    )
}

fn execute_mutation_with_signals_and_deferred_timeout<R>(
    context: &'static str,
    recovery: R,
    timeout: Option<Duration>,
    operation: impl FnOnce(&OperationControl<R>, &DeferredObservationTimeoutStart) -> CommandResult
    + Send
    + 'static,
    incomplete_signal: impl FnOnce(ExitCode, SignalSnapshot<R>) -> CommandResult + 'static,
    timed_out: impl FnOnce(SignalSnapshot<R>) -> CommandResult + 'static,
) -> CommandResult
where
    R: Clone + Send + 'static,
{
    run_blocking_signal_runtime(context, async move {
        let mut signals = ProcessSignals::install(context)?;
        let control = Arc::new(OperationControl::new(recovery));
        let (timeout_sender, timeout_started) = tokio::sync::oneshot::channel();
        let timeout_start = Arc::new(DeferredObservationTimeoutStart {
            sender: Mutex::new(Some(timeout_sender)),
        });
        let operation_timeout_start = Arc::clone(&timeout_start);
        let mut running = spawn_controlled_blocking(Arc::clone(&control), move |control| {
            operation(control, &operation_timeout_start)
        });
        tokio::select! {
            biased;
            signal = signals.recv() => {
                let stopped = control
                    .claim_signal()
                    .map(|snapshot| incomplete_signal(signal, snapshot));
                finish_stopped_operation(context, &mut running, stopped).await
            }
            () = (DeferredObservationTimeout {
                duration: timeout,
                started: timeout_started,
            }).wait() => {
                let stopped = control.claim_signal().map(timed_out);
                finish_stopped_operation(context, &mut running, stopped).await
            }
            result = &mut running => finish_read_only_operation(context, result),
        }
    })
}

/// The signal that stopped an operation run by `execute_mutation_with_signal_cleanup`, which
/// the operation reads once it sees itself cancelled.
struct StopSignal(std::sync::OnceLock<ExitCode>);

impl StopSignal {
    /// The exit code of the signal that stopped the operation.
    fn exit_code(&self) -> ExitCode {
        self.0
            .get()
            .copied()
            .unwrap_or_else(|| OutcomeClass::Interrupted.exit_code())
    }
}

/// Runs a mutation that cleans up after a signal. The first signal stops the operation unless it
/// has not dispatched, which ends the command at once: the operation sees `is_cancelled` (its
/// dispatch, recovery and completion are refused), sends what undoes its work from its own
/// thread, writes its ending and ends the command with its own result. A second signal ends the
/// command at once with `abandoned`, given the operation's recovery state.
fn execute_mutation_with_signal_cleanup<R>(
    context: &'static str,
    recovery: R,
    operation: impl FnOnce(&OperationControl<R>, &StopSignal) -> CommandResult + Send + 'static,
    abandoned: impl FnOnce(ExitCode, R) -> CommandResult + 'static,
) -> CommandResult
where
    R: Clone + Send + 'static,
{
    run_blocking_signal_runtime(context, async move {
        let mut signals = ProcessSignals::install(context)?;
        let control = Arc::new(OperationControl::new(recovery));
        let stop = Arc::new(StopSignal(std::sync::OnceLock::new()));
        let operation_stop = Arc::clone(&stop);
        let mut running = spawn_controlled_blocking(Arc::clone(&control), move |control| {
            operation(control, &operation_stop)
        });
        tokio::select! {
            biased;
            signal = signals.recv() => {
                let _ = stop.0.set(signal);
                if control
                    .claim_signal()
                    .is_some_and(|snapshot| !snapshot.dispatched)
                {
                    return Ok(signal);
                }
                tokio::select! {
                    biased;
                    again = signals.recv() => abandoned(again, control.recovery()),
                    result = &mut running => finish_read_only_operation(context, result),
                }
            }
            result = &mut running => finish_read_only_operation(context, result),
        }
    })
}

fn finish_read_only_operation(
    context: &str,
    result: Result<CommandResult, tokio::task::JoinError>,
) -> CommandResult {
    result.with_context(|| format!("complete {context} operation"))?
}

struct HumanApiOutcomeAdapters<O, E> {
    unauthenticated: fn() -> O,
    unreachable: fn(useful_api::UnreachableCategory) -> O,
    operation_error: fn(E) -> anyhow::Error,
}

fn human_session_client(transport_policy: HttpTransportPolicy) -> anyhow::Result<HttpClient> {
    HttpClient::new(transport_policy)
        .map_err(|error| anyhow!(error))
        .context("prepare human session networking")
}

struct PrincipalApiContext<'a> {
    client: &'a HttpClient,
    deployment: &'a Deployment,
    authentication: &'a PrincipalAuthenticationArgs,
    session_context: &'static str,
}

fn principal_api_context<'a>(
    client: &'a HttpClient,
    deployment: &'a Deployment,
    authentication: &'a PrincipalAuthenticationArgs,
    session_context: &'static str,
) -> PrincipalApiContext<'a> {
    PrincipalApiContext {
        client,
        deployment,
        authentication,
        session_context,
    }
}

fn execute_selected_api_operation<T, E>(
    context: PrincipalApiContext<'_>,
    operation: impl FnMut(&str) -> anyhow::Result<Result<T, E>>,
    credential_rejected: impl Fn(&E) -> bool,
    unauthenticated: impl Fn() -> E,
    unreachable: impl Fn(UnreachableCategory) -> E,
) -> anyhow::Result<Result<T, E>> {
    execute_selected_api_operation_retrying_result(
        context,
        operation,
        |operation| operation.as_ref().is_err_and(&credential_rejected),
        unauthenticated,
        unreachable,
    )
}

// Observation uses one deadline for session acquisition, refresh and every read/retry.
fn execute_selected_api_observation<T, E>(
    context: PrincipalApiContext<'_>,
    mut operation: impl FnMut(&str, Option<Duration>) -> anyhow::Result<Result<T, E>>,
    credential_rejected: impl Fn(&E) -> bool,
    unauthenticated: impl Fn() -> E,
    unreachable: impl Fn(UnreachableCategory) -> E,
    deadline: Option<Instant>,
) -> anyhow::Result<Result<T, E>> {
    if observation_http_budget(deadline).is_err() {
        return Ok(Err(unreachable(UnreachableCategory::Timeout)));
    }
    if let Some(api_key) = context.authentication.service_api_key()? {
        if let Ok(remaining) = observation_http_budget(deadline) {
            operation(api_key.expose(), remaining)
        } else {
            Ok(Err(unreachable(UnreachableCategory::Timeout)))
        }
    } else {
        match useful_human_auth::execute_required_until(
            context.client,
            context.deployment,
            |access_token, budget| operation(access_token.expose(), budget),
            |result| {
                result
                    .as_ref()
                    .is_ok_and(|value| value.as_ref().is_err_and(&credential_rejected))
            },
            deadline,
        ) {
            Ok(RequiredOperation::Unauthenticated) => Ok(Err(unauthenticated())),
            Ok(RequiredOperation::Completed(result)) => result,
            Err(error) => match error.unreachable_category() {
                Some(category) => Ok(Err(unreachable(category))),
                None => Err(anyhow!(error).context(context.session_context)),
            },
        }
    }
}

fn observation_http_budget(
    deadline: Option<Instant>,
) -> Result<Option<Duration>, UnreachableCategory> {
    match deadline {
        Some(end) => end
            .checked_duration_since(useful_support::monotonic_now())
            .filter(|duration| !duration.is_zero())
            .map(Some)
            .ok_or(UnreachableCategory::Timeout),
        None => Ok(None),
    }
}

fn execute_selected_api_operation_retrying_result<T, E>(
    context: PrincipalApiContext<'_>,
    mut operation: impl FnMut(&str) -> anyhow::Result<Result<T, E>>,
    credential_rejected: impl Fn(&Result<T, E>) -> bool,
    unauthenticated: impl Fn() -> E,
    unreachable: impl Fn(UnreachableCategory) -> E,
) -> anyhow::Result<Result<T, E>> {
    if let Some(api_key) = context.authentication.service_api_key()? {
        operation(api_key.expose())
    } else {
        execute_required_api_operation_retrying_result(
            context.client,
            context.deployment,
            operation,
            credential_rejected,
            unauthenticated,
            unreachable,
            context.session_context,
        )
    }
}

fn execute_required_api_operation_retrying_result<T, E>(
    client: &HttpClient,
    deployment: &Deployment,
    mut operation: impl FnMut(&str) -> anyhow::Result<Result<T, E>>,
    credential_rejected: impl Fn(&Result<T, E>) -> bool,
    unauthenticated: impl Fn() -> E,
    unreachable: impl Fn(UnreachableCategory) -> E,
    session_context: &'static str,
) -> anyhow::Result<Result<T, E>> {
    match useful_human_auth::execute_required(
        client,
        deployment,
        |access_token| operation(access_token.expose()),
        |result| result.as_ref().is_ok_and(&credential_rejected),
    ) {
        Ok(RequiredOperation::Unauthenticated) => Ok(Err(unauthenticated())),
        Ok(RequiredOperation::Completed(result)) => result,
        Err(error) => match error.unreachable_category() {
            Some(category) => Ok(Err(unreachable(category))),
            None => Err(anyhow!(error).context(session_context)),
        },
    }
}

/// A member API that admits only the signed-in human session.
trait HumanSessionApi: Sized {
    type Failure;
    type BuildError: std::error::Error + Send + Sync + 'static;

    fn build(
        api_url: &str,
        token: &str,
        policy: HttpTransportPolicy,
    ) -> Result<Self, Self::BuildError>;
    fn credential_rejected(failure: &Self::Failure) -> bool;
    fn unauthenticated() -> Self::Failure;
    fn unreachable(category: UnreachableCategory) -> Self::Failure;
}

/// Runs `f` against a member API with the signed-in human session, refreshing a rejected
/// session once.
fn with_human_session_api<A: HumanSessionApi, T>(
    deployment: &Deployment,
    policy: HttpTransportPolicy,
    mut f: impl FnMut(&A) -> Result<T, A::Failure>,
) -> anyhow::Result<Result<T, A::Failure>> {
    let client = human_session_client(policy)?;
    execute_required_api_operation_retrying_result(
        &client,
        deployment,
        |token| {
            let api = A::build(deployment.fingerprint().api_url(), token, policy)
                .map_err(anyhow::Error::new)?;
            Ok(f(&api))
        },
        |result| result.as_ref().is_err_and(A::credential_rejected),
        A::unauthenticated,
        A::unreachable,
        "acquire human session",
    )
}

fn execute_human_api_operation<O, E>(
    client: &useful_api::HttpClient,
    deployment: &Deployment,
    mut operation: impl FnMut(&str) -> Result<O, E>,
    credential_rejected: impl Fn(&Result<O, E>) -> bool,
    adapters: HumanApiOutcomeAdapters<O, E>,
    api_context: String,
) -> anyhow::Result<O> {
    match useful_human_auth::execute_required(
        client,
        deployment,
        |access_token| operation(access_token.expose()),
        credential_rejected,
    ) {
        Ok(RequiredOperation::Unauthenticated) => Ok((adapters.unauthenticated)()),
        Ok(RequiredOperation::Completed(result)) => result
            .map_err(adapters.operation_error)
            .context(api_context),
        Err(error) => match error.unreachable_category() {
            Some(category) => Ok((adapters.unreachable)(category)),
            None => Err(anyhow!(error).context("acquire human session")),
        },
    }
}

trait HumanCredentialOutcome: Sized {
    type Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static;

    fn unauthenticated() -> Self;
    fn unreachable(category: UnreachableCategory) -> Self;
    fn is_unauthenticated(&self) -> bool;
    fn credential_rejected(error: &Self::Error) -> bool;
}

fn execute_with_human_credential<O>(
    deployment: &Deployment,
    transport_policy: HttpTransportPolicy,
    network_context: &'static str,
    api_context: &'static str,
    operation: impl FnMut(&HttpClient, &str, &str) -> Result<O, O::Error>,
) -> anyhow::Result<O>
where
    O: HumanCredentialOutcome,
{
    execute_with_principal_credential(
        deployment,
        transport_policy,
        &PrincipalAuthenticationArgs::default(),
        network_context,
        api_context,
        operation,
    )
}

fn execute_with_principal_credential<O>(
    deployment: &Deployment,
    transport_policy: HttpTransportPolicy,
    authentication: &PrincipalAuthenticationArgs,
    network_context: &'static str,
    api_context: &'static str,
    mut operation: impl FnMut(&HttpClient, &str, &str) -> Result<O, O::Error>,
) -> anyhow::Result<O>
where
    O: HumanCredentialOutcome,
{
    let client = HttpClient::new(transport_policy)
        .map_err(|error| anyhow!(error))
        .context(network_context)?;
    if let Some(api_key) = authentication.service_api_key()? {
        return operation(
            &client,
            deployment.fingerprint().api_url(),
            api_key.expose(),
        )
        .map_err(|error| anyhow!(error))
        .with_context(|| format!("{api_context} {}", deployment.fingerprint().api_url()));
    }
    execute_human_api_operation(
        &client,
        deployment,
        |access_token| operation(&client, deployment.fingerprint().api_url(), access_token),
        |result| {
            result.as_ref().is_ok_and(O::is_unauthenticated)
                || result.as_ref().is_err_and(O::credential_rejected)
        },
        HumanApiOutcomeAdapters {
            unauthenticated: O::unauthenticated,
            unreachable: O::unreachable,
            operation_error: |error: O::Error| anyhow!(error),
        },
        format!("{api_context} {}", deployment.fingerprint().api_url()),
    )
}

fn execute_deployment_leaf<T>(
    command: T,
    command_path: &[&str],
    error_context: &'static str,
    execute: impl FnOnce(T, &Deployment) -> anyhow::Result<ExitCode>,
) -> CommandResult {
    execute_deployment_command(
        Some(command),
        command_path,
        error_context,
        |command, deployment| execute(command, deployment).map_err(Into::into),
    )
}

fn execute_deployment_command<T>(
    command: Option<T>,
    command_path: &[&str],
    error_context: &'static str,
    execute: impl FnOnce(T, &Deployment) -> CommandResult,
) -> CommandResult {
    let Some(command) = command else {
        return print_help(command_path);
    };
    let deployment = Deployment::load()
        .map_err(|error| anyhow!(error))
        .context(error_context)?;
    execute(command, &deployment)
}

fn print_help(command_path: &[&str]) -> CommandResult {
    let mut root = Cli::command();
    root.build();
    let mut command = &mut root;

    for name in command_path {
        let Some(subcommand) = command.find_subcommand_mut(name) else {
            return Err(anyhow!("command help metadata is unavailable for {name}").into());
        };
        command = subcommand;
    }

    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    command
        .write_help(&mut stdout)
        .context("failed to write command help")?;
    Ok(ExitCode::Success)
}

#[cfg(test)]
#[path = "cli/grammar_tests.rs"]
mod grammar_tests;

#[cfg(test)]
mod migration_tests;

#[cfg(test)]
mod scenario_tests;

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;
    use std::sync::{Arc, Barrier, Mutex};

    use clap::CommandFactory;
    use serde_json::Value;

    use super::{Cli, parse, unreachable_outcome_class};
    use crate::exit_code::{ExitCode, OutcomeClass};
    use useful_api::UnreachableCategory;

    #[test]
    fn a_unit_test_harness_is_never_its_own_internal_worker() {
        match useful_execution::unsupplied_internal_worker_executable() {
            Ok(worker) => {
                assert_ne!(worker, std::env::current_exe().unwrap());
                assert!(
                    worker.ends_with("examples/internal-worker"),
                    "an unsupplied worker must be the example beside the harness: {worker:?}"
                );
            }
            Err(error) => assert_eq!(error.raw_os_error(), None),
        }
    }

    #[test]
    fn completion_and_cancellation_each_win_one_controlled_output_race() {
        for signal_wins in [true, false] {
            let control = Arc::new(super::OperationControl::new(()));
            let at_boundary = Arc::new(Barrier::new(2));
            let release = Arc::new(Barrier::new(2));
            let documents = Arc::new(Mutex::new(Vec::new()));

            let worker_control = Arc::clone(&control);
            let worker_boundary = Arc::clone(&at_boundary);
            let worker_release = Arc::clone(&release);
            let worker_documents = Arc::clone(&documents);
            let worker = std::thread::spawn(move || {
                if signal_wins {
                    worker_boundary.wait();
                    worker_release.wait();
                }
                super::complete_operation(&worker_control, || {
                    if !signal_wins {
                        worker_boundary.wait();
                        worker_release.wait();
                    }
                    worker_documents.lock().unwrap().push(
                        serde_json::to_vec(&serde_json::json!({"outcome": "completed"})).unwrap(),
                    );
                    Ok(ExitCode::Success)
                })
                .unwrap_or_else(|failure| panic!("{}", failure.error()))
            });

            at_boundary.wait();
            let exit = if control.claim_signal().is_some() {
                documents.lock().unwrap().push(
                    serde_json::to_vec(&serde_json::json!({"outcome": "interrupted"})).unwrap(),
                );
                ExitCode::Interrupted
            } else {
                ExitCode::Success
            };
            release.wait();
            let worker_exit = worker.join().unwrap();

            let documents = documents.lock().unwrap();
            assert_eq!(documents.len(), 1);
            let document: Value = serde_json::from_slice(&documents[0]).unwrap();
            if signal_wins {
                assert_eq!(exit, ExitCode::Interrupted);
                assert_eq!(worker_exit, ExitCode::GeneralFailure);
                assert_eq!(document["outcome"], "interrupted");
            } else {
                assert_eq!(exit, ExitCode::Success);
                assert_eq!(worker_exit, ExitCode::Success);
                assert_eq!(document["outcome"], "completed");
            }
        }
    }

    fn observe_at_read_boundary(
        clock: &impl super::ObservationClock,
        control: &impl super::ObservationControl,
        started: std::time::Instant,
    ) -> (
        super::TerminalObservation<(), ()>,
        Vec<Option<std::time::Duration>>,
    ) {
        let mut requests = Vec::new();
        let outcome = super::wait_for_terminal_observation_bounded(
            |remaining| {
                requests.push(remaining);
                Ok::<_, ()>(())
            },
            |_| None::<()>,
            |_| false,
            Some(std::time::Duration::from_millis(10)),
            started,
            control,
            clock,
        )
        .unwrap();
        (outcome, requests)
    }

    #[test]
    fn cloud_run_observation_expiry_before_read_admission_sends_no_request() {
        use super::observation_test_support::ControlledObservationClock;
        use std::time::Duration;

        let started = useful_support::monotonic_now();
        let clock = ControlledObservationClock::new(started);
        let control = super::OperationControl::new(());
        // The timeout wins after observation starts, before its first GET is admitted.
        clock.advance(Duration::from_millis(10));
        let (result, requests) = observe_at_read_boundary(&clock, &control, started);
        assert!(matches!(result, super::TerminalObservation::TimedOut));
        assert!(requests.is_empty());
        let mut outputs = Vec::new();
        assert_eq!(
            super::complete_operation(&control, || {
                outputs.push("timed_out");
                Ok(ExitCode::GeneralFailure)
            })
            .unwrap_or_else(|failure| panic!("{}", failure.error())),
            ExitCode::GeneralFailure
        );
        assert_eq!(outputs, ["timed_out"]);
    }

    #[test]
    fn cloud_run_observation_stop_at_read_boundary_prevents_dispatch() {
        use std::sync::{Arc, mpsc};

        struct PauseBeforeAdmission<'a> {
            control: &'a super::OperationControl<()>,
            at_boundary: mpsc::Sender<()>,
            resume: mpsc::Receiver<()>,
        }
        impl super::ObservationControl for PauseBeforeAdmission<'_> {
            fn is_stopped(&self) -> bool {
                self.control.is_cancelled()
            }
            fn admit_read(&self) -> bool {
                self.at_boundary.send(()).unwrap();
                self.resume.recv().unwrap();
                super::ObservationControl::admit_read(self.control)
            }
        }

        let started = useful_support::monotonic_now();
        let control = Arc::new(super::OperationControl::new(()));
        let (at_boundary, reached) = mpsc::channel();
        let (resume, continue_read) = mpsc::channel();
        let worker_control = Arc::clone(&control);
        let worker = std::thread::spawn(move || {
            let clock = super::observation_test_support::ControlledObservationClock::new(started);
            let gate = PauseBeforeAdmission {
                control: &worker_control,
                at_boundary,
                resume: continue_read,
            };
            observe_at_read_boundary(&clock, &gate, started)
        });
        // Both status checks and the deadline sample have completed. Stop wins
        // the actual read-admission claim before the worker can make its GET.
        reached.recv().unwrap();
        let mut outputs = Vec::new();
        if control.claim_signal().is_some() {
            outputs.push("observation_stopped");
        }
        resume.send(()).unwrap();
        let (result, requests) = worker.join().unwrap();
        assert!(matches!(result, super::TerminalObservation::Stopped));
        assert!(requests.is_empty());
        assert_eq!(
            super::complete_operation(&control, || Ok(ExitCode::Success))
                .unwrap_or_else(|failure| panic!("{}", failure.error())),
            ExitCode::GeneralFailure
        );
        assert_eq!(outputs, ["observation_stopped"]);
    }

    #[test]
    fn cloud_run_observation_timeout_and_stop_after_get_do_not_dispatch_another() {
        use super::observation_test_support::ControlledObservationClock;
        use std::time::Duration;

        for signal_after_get in [false, true] {
            let started = useful_support::monotonic_now();
            let clock = ControlledObservationClock::new(started);
            let control = super::OperationControl::new(());
            let mut requests = Vec::new();
            let mut outputs = Vec::new();
            let result = super::wait_for_terminal_observation_bounded(
                |remaining| {
                    requests.push(remaining);
                    // This GET has started. The timeout or stop wins before another poll.
                    if signal_after_get {
                        assert!(control.claim_signal().is_some());
                        outputs.push("observation_stopped");
                    } else {
                        clock.advance(Duration::from_millis(10));
                    }
                    Ok::<_, ()>(())
                },
                |_| None::<()>,
                |_| false,
                Some(Duration::from_millis(10)),
                started,
                &control,
                &clock,
            )
            .unwrap();
            if signal_after_get {
                assert!(matches!(result, super::TerminalObservation::Stopped));
                assert_eq!(
                    super::complete_operation(&control, || Ok(ExitCode::Success))
                        .unwrap_or_else(|failure| panic!("{}", failure.error())),
                    ExitCode::GeneralFailure
                );
                assert_eq!(outputs, ["observation_stopped"]);
            } else {
                assert!(matches!(result, super::TerminalObservation::TimedOut));
                assert_eq!(
                    super::complete_operation(&control, || {
                        outputs.push("timed_out");
                        Ok(ExitCode::GeneralFailure)
                    })
                    .unwrap_or_else(|failure| panic!("{}", failure.error())),
                    ExitCode::GeneralFailure
                );
                assert_eq!(outputs, ["timed_out"]);
            }
            assert_eq!(requests, [Some(Duration::from_millis(10))]);
        }
    }

    #[test]
    fn bounded_dispatch_and_signal_have_one_ordered_owner() {
        let signal_first = super::OperationControl::new(());
        assert!(signal_first.claim_signal().is_some());
        assert!(!signal_first.begin_bounded_dispatch());
        assert!(!signal_first.dispatched());

        let dispatch_first = super::OperationControl::new(());
        assert!(dispatch_first.begin_bounded_dispatch());
        assert!(dispatch_first.begin_bounded_dispatch());
        assert!(dispatch_first.dispatched());
        assert!(dispatch_first.claim_signal().is_none());
    }

    #[test]
    fn nested_workflow_delivery_failure_retains_evidence_for_continuations() {
        // The workflow command has an isolated environment. Supply the worker
        // contract to the nested fixture explicitly rather than relying on
        // the test runner's environment surviving the command boundary.
        let worker = std::env::var("USEFUL_TEST_INTERNAL_WORKER_EXECUTABLE")
            .expect("test worker executable must be supplied by the test runner");
        assert!(
            Path::new(&worker).is_file(),
            "test worker executable is unavailable: {worker}"
        );
        let fixture_arguments = vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "export USEFUL_TEST_INTERNAL_WORKER_EXECUTABLE=\"$1\"; shift; exec \"$@\"".to_owned(),
            "sh".to_owned(),
            worker,
            std::env::current_exe()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned(),
            "--ignored".to_owned(),
            "--exact".to_owned(),
            "cli::tests::nested_workflow_fixture_process".to_owned(),
            "--nocapture".to_owned(),
        ];
        useful_runner::run_nested_workflow_delivery_failure_fixture(&fixture_arguments).unwrap();
    }

    #[test]
    #[ignore = "launched only as the nested assignment workflow fixture"]
    fn nested_workflow_fixture_process() {
        let workspace = std::env::current_dir().unwrap();
        let round = workspace.join("delivery-rounds/0001");
        let execution = round.join("workspace");
        let run = round.join("run");
        fs::create_dir_all(&execution).unwrap();
        // The assignment workspace holds `workflow.yaml`, so `--path` on it would admit it as
        // a tree and refuse the fixture's path programs. The nested run takes its file from a
        // directory of its own, admitted from the file's closure.
        let source = round.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::copy(workspace.join("nested.yaml"), source.join("nested.yaml")).unwrap();
        let arguments = vec![
            OsString::from("useful"),
            OsString::from("workflow"),
            OsString::from("run"),
            OsString::from("create"),
            OsString::from("--path"),
            source.into_os_string(),
            OsString::from("--workflow"),
            OsString::from("nested.yaml"),
            OsString::from("--execution-root"),
            execution.into_os_string(),
            OsString::from("--run-dir"),
            run.clone().into_os_string(),
            OsString::from("--json"),
            OsString::from("--color"),
            OsString::from("never"),
        ];
        let outcome = match parse(arguments).unwrap().execute() {
            Ok(outcome) => outcome,
            Err(failure) => panic!("nested workflow fixture failed: {}", failure.error()),
        };
        assert_eq!(outcome, ExitCode::Success);

        let result_root = run.join("attempts/000001/result");
        let result: Value =
            serde_json::from_slice(&fs::read(result_root.join("result.json")).unwrap()).unwrap();
        assert_eq!(result["outcome"], "succeeded");
        let export = result["exports"]["portable"]["path"].as_str().unwrap();
        let bytes = fs::read(result_root.join(export)).unwrap();
        assert_eq!(bytes, b"nested portable result");
        fs::write(round.join("nested-result.txt"), bytes).unwrap();

        let retained =
            run.join(".private/workflow-retained/.inputs-retained/view-retained/values/payload");
        assert_eq!(
            fs::symlink_metadata(&retained)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o400
        );
        for directory in [
            retained.parent().unwrap(),
            retained.parent().unwrap().parent().unwrap(),
        ] {
            assert_eq!(
                fs::symlink_metadata(directory)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o500
            );
        }
    }

    #[test]
    fn controlled_completion_preserves_output_failures() {
        let mutation = super::OperationControl::new(());
        let result = super::complete_operation(&mutation, || {
            mutation.recovery();
            Err(anyhow::anyhow!("fixture mutation output failure").into())
        });
        assert!(result.is_err());
        assert!(mutation.claim_signal().is_none());

        let read_only = super::OperationControl::new(());
        let result = super::complete_read_only_output(&read_only, || {
            Err(anyhow::anyhow!("fixture read-only output failure").into())
        });
        assert!(result.is_err());
        assert!(read_only.claim_signal().is_none());
    }

    fn collect_command_paths(command: &clap::Command, prefix: &str, paths: &mut Vec<String>) {
        assert!(
            !command.is_allow_external_subcommands_set(),
            "customer command {prefix:?} accepts external subcommands"
        );
        for child in command
            .get_subcommands()
            .filter(|child| child.get_name() != "help")
        {
            for name in std::iter::once(child.get_name()).chain(child.get_all_aliases()) {
                let path = if prefix.is_empty() {
                    name.to_owned()
                } else {
                    format!("{prefix} {name}")
                };
                paths.push(path.clone());
                collect_command_paths(child, &path, paths);
            }
        }
    }

    fn assert_command_order(command: &clap::Command, prefix: &str) {
        let children = command.get_subcommands().collect::<Vec<_>>();
        let names = children
            .iter()
            .map(|child| child.get_name())
            .collect::<Vec<_>>();
        let mut expected = names.clone();
        expected.sort_unstable_by(|left, right| match (*left == "help", *right == "help") {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => left.cmp(right),
        });
        assert_eq!(names, expected, "command order at {prefix}");

        for child in children
            .into_iter()
            .filter(|child| child.get_name() != "help")
        {
            let path = format!("{prefix} {}", child.get_name());
            assert_command_order(child, &path);
        }
    }

    #[test]
    fn command_groups_are_alphabetical_with_help_last() {
        assert_command_order(&Cli::command(), "useful");
    }

    /// Every path of the tree, hidden ones and aliases included, sorted and without `useful`.
    pub(super) fn customer_command_paths() -> Vec<String> {
        let mut paths = Vec::new();
        collect_command_paths(&Cli::command(), "", &mut paths);
        paths.sort();
        paths.dedup();
        paths
    }

    #[test]
    fn every_unreachable_category_uses_the_shared_outcome_table() {
        for category in [
            UnreachableCategory::Dns,
            UnreachableCategory::Timeout,
            UnreachableCategory::Connection,
            UnreachableCategory::Tls,
            UnreachableCategory::Server,
        ] {
            assert_eq!(
                unreachable_outcome_class(category),
                OutcomeClass::Unreachable
            );
        }
        assert_eq!(
            unreachable_outcome_class(UnreachableCategory::RateLimited),
            OutcomeClass::RateLimited
        );
    }

    #[test]
    fn service_authentication_is_explicit_and_human_only_leaves_reject_it() {
        assert!(
            parse([
                "useful",
                "account",
                "service",
                "key",
                "list",
                "--api-key-file",
                "service.key",
            ])
            .is_ok()
        );
        assert!(
            parse([
                "useful",
                "org",
                "show",
                "example",
                "--api-key-file",
                "service.key",
            ])
            .is_ok()
        );
        assert!(
            parse([
                "useful",
                "account",
                "service",
                "create",
                "--name",
                "Build agent",
                "--key-file",
                "new.key",
                "--api-key-file",
                "service.key",
            ])
            .is_err()
        );
        assert!(
            parse([
                "useful",
                "org",
                "delete",
                "example",
                "--yes",
                "--api-key-file",
                "service.key",
            ])
            .is_err()
        );
    }

    #[test]
    fn customer_command_surface_is_exact_and_has_no_operator_entrypoint() {
        let actual = customer_command_paths();
        let expected: Vec<_> = include_str!("../tests/fixtures/command-tree.txt")
            .lines()
            .collect();

        assert_eq!(actual, expected);
        // A command is a path with no subcommand; every other path is a group.
        let commands: Vec<_> = expected
            .iter()
            .filter(|path| {
                !expected.iter().any(|other| {
                    other
                        .strip_prefix(**path)
                        .is_some_and(|rest| rest.starts_with(' '))
                })
            })
            .collect();
        assert_eq!((commands.len(), expected.len() - commands.len()), (151, 34));
        let root = Cli::command();
        let visible = commands
            .iter()
            .filter(|path| {
                let mut node = &root;
                path.split(' ').all(|token| {
                    node = node
                        .find_subcommand(token)
                        .expect("every listed path is in the tree");
                    !node.is_hide_set()
                })
            })
            .count();
        assert_eq!(visible, 150);
    }

    #[test]
    fn the_earlier_account_paths_and_options_are_unknown() {
        for (arguments, kind) in [
            (
                &["useful", "auth", "grant", "list"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "grant", "list"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "grant", "create", "github"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "grant", "revoke", "codex", "--yes"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &[
                    "useful",
                    "account",
                    "integration",
                    "list",
                    "pgr_01k0z6r1w8f4jy2m7q9v3x5abc",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["useful", "account", "integration", "list", "--uses", "20"][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "account",
                    "integration",
                    "connect",
                    "github",
                    "--replace",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "account",
                    "integration",
                    "connect",
                    "codex",
                    "--organization",
                    "acme",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "doctor",
                    "--workflow",
                    "workflow.yaml",
                    "--connect",
                    "--replace",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["useful", "auth", "agent-login", "list"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "auth", "credential", "status"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "auth", "login"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "auth", "status"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "auth", "logout"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "auth", "identity", "list"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "account", "status"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "account", "deletion", "request", "--yes"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "account", "update", "--display-name", "X"][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["useful", "account", "update", "--clear-display-name"][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "org",
                    "show",
                    "example",
                    "--service-api-key-file",
                    "service.key",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "account",
                    "service",
                    "create",
                    "--name",
                    "X",
                    "--api-key-file",
                    "new.key",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["useful", "invitation", "list"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &[
                    "useful",
                    "account",
                    "invitation",
                    "preview",
                    "inv_01k0z6r1w8f4jy2m7q9v3x5abc",
                ][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &[
                    "useful",
                    "service-principal",
                    "create",
                    "--display-name",
                    "ci",
                    "--key-file",
                    "ci.key",
                ][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &[
                    "useful",
                    "account",
                    "service",
                    "credential",
                    "list",
                    "--api-key-file",
                    "ci.key",
                ][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "delegation", "list"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &[
                    "useful",
                    "account",
                    "service",
                    "create",
                    "--display-name",
                    "ci",
                    "--key-file",
                    "ci.key",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
        ] {
            let error = parse(arguments).expect_err("an earlier spelling must not parse");
            assert_eq!(error.kind(), kind, "{arguments:?}");
        }
    }

    #[test]
    fn the_earlier_connection_paths_are_unknown() {
        for arguments in [
            &[
                "useful",
                "connection",
                "github",
                "installation",
                "list",
                "acme",
            ][..],
            &["useful", "connection", "gitlab", "list", "acme"][..],
            &["useful", "connection", "linear", "list", "acme"][..],
            &[
                "useful",
                "connection",
                "gitlab",
                "show",
                "acme",
                "glc_01k0z6r1w8f4jy2m7q9v3x5abc",
            ][..],
            &[
                "useful",
                "connection",
                "linear",
                "show",
                "acme",
                "lcn_01k0z6r1w8f4jy2m7q9v3x5abc",
            ][..],
            &[
                "useful",
                "connection",
                "linear",
                "authorization",
                "show",
                "acme",
                "las_01k0z6r1w8f4jy2m7q9v3x5abc",
            ][..],
            &[
                "useful",
                "connection",
                "github",
                "repository",
                "list",
                "acme",
                "ghi_01k0z6r1w8f4jy2m7q9v3x5abc",
            ][..],
            &[
                "useful",
                "connection",
                "linear",
                "team",
                "list",
                "acme",
                "lcn_01k0z6r1w8f4jy2m7q9v3x5abc",
            ][..],
            &[
                "useful",
                "connection",
                "linear",
                "state",
                "list",
                "acme",
                "lcn_01k0z6r1w8f4jy2m7q9v3x5abc",
                "team",
            ][..],
            &[
                "useful",
                "connection",
                "github",
                "installation",
                "remove",
                "acme",
                "ghi_01k0z6r1w8f4jy2m7q9v3x5abc",
                "--yes",
            ][..],
            &[
                "useful",
                "connection",
                "linear",
                "delete",
                "acme",
                "lcn_01k0z6r1w8f4jy2m7q9v3x5abc",
                "--yes",
            ][..],
            &[
                "useful",
                "connection",
                "gitlab",
                "repository",
                "link",
                "acme",
                "glc_01k0z6r1w8f4jy2m7q9v3x5abc",
                "--repository-id",
                "7",
                "--expected-version",
                "1",
            ][..],
            &[
                "useful",
                "connection",
                "linear",
                "authorization",
                "create",
                "acme",
            ][..],
            &["useful", "connection", "github", "setup", "begin", "acme"][..],
            &["useful", "connection"][..],
            &[
                "useful",
                "connection",
                "gitlab",
                "create",
                "acme",
                "https://gitlab.com",
            ][..],
            &["useful", "gitlab"][..],
        ] {
            let error = parse(arguments).expect_err("an earlier connection path must not parse");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::InvalidSubcommand,
                "{arguments:?}"
            );
        }
        let error = parse([
            "useful",
            "org",
            "integration",
            "connect",
            "linear",
            "--enable-state-updates",
        ])
        .expect_err("the earlier state-updates spelling must not parse");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        let error = parse([
            "useful",
            "org",
            "integration",
            "connect",
            "github",
            "--provider-installation-id",
            "7",
        ])
        .expect_err("the earlier installation spelling must not parse");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn the_earlier_project_paths_and_options_are_unknown() {
        const PROJECT: &str = "prj_01k0z6r1w8f4jy2m7q9v3x5abc";
        const WEBHOOK: &str = "whs_01k0z6r1w8f4jy2m7q9v3x5abc";
        for (arguments, kind) in [
            (
                &["useful", "project", "list", "acme"][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["useful", "project", "show", "acme", PROJECT][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "project",
                    "create",
                    "acme",
                    "--name",
                    "widget",
                    "--installation-id",
                    "ghi_01k0z6r1w8f4jy2m7q9v3x5abc",
                    "--repository-id",
                    "123",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["useful", "project", "archive", "acme", PROJECT][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "project",
                    "archive",
                    PROJECT,
                    "--project",
                    PROJECT,
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["useful", "project", "action", "list", "acme", PROJECT][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "project", "repository", "show", "acme", PROJECT][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "project", "show", "widget", "--project", "widget"][..],
                clap::error::ErrorKind::ArgumentConflict,
            ),
            (
                &[
                    "useful", "project", "rename", "acme", PROJECT, "--name", "gadget",
                ][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &[
                    "useful",
                    "project",
                    "repository",
                    "set",
                    "acme",
                    PROJECT,
                    "--installation-id",
                    "ghi_01k0z6r1w8f4jy2m7q9v3x5abc",
                    "--repository-id",
                    "123",
                ][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &[
                    "useful",
                    "project",
                    "runner-pool",
                    "set",
                    "acme",
                    PROJECT,
                    "builders",
                ][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &[
                    "useful",
                    "project",
                    "runner-pool",
                    "remove",
                    "acme",
                    PROJECT,
                    "--yes",
                ][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "project", "webhook", "rotate-secret", WEBHOOK][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &[
                    "useful",
                    "project",
                    "webhook",
                    "revoke-previous-secret",
                    WEBHOOK,
                ][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &[
                    "useful", "project", "webhook", "show", "acme", PROJECT, WEBHOOK,
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "project",
                    "webhook",
                    "delivery",
                    "list",
                    WEBHOOK,
                    "--run-id",
                    "run_01k0z6r1w8f4jy2m7q9v3x5abc",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "project",
                    "webhook",
                    "delivery",
                    "show",
                    "dlv_01jcqe",
                ][..],
                clap::error::ErrorKind::MissingRequiredArgument,
            ),
        ] {
            let error = parse(arguments).expect_err("an earlier project spelling must not parse");
            assert_eq!(error.kind(), kind, "{arguments:?}");
        }
    }

    #[test]
    fn the_earlier_runner_paths_and_options_are_unknown() {
        for (arguments, kind) in [
            (
                &["useful", "runner", "list", "acme"][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["useful", "runner", "show", "acme", "builder-one"][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["useful", "runner", "drain", "acme", "builder-one"][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["useful", "runner", "pool", "list", "acme"][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["useful", "runner", "pool", "create", "--name", "builders"][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "update",
                    "builder-one",
                    "--pool-id",
                    "builders",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "move",
                    "builder-one",
                    "--pool",
                    "builders",
                ][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "runner", "rename", "builder-one", "--name", "b"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &[
                    "useful", "runner", "pool", "rename", "builders", "--name", "b",
                ][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &[
                    "useful", "runner", "list", "--pool", "builders", "--limit", "5",
                ][..],
                clap::error::ErrorKind::ArgumentConflict,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "credential",
                    "retire",
                    "rrc_01k0z6r1w8f4jy2m7q9v3x5abd",
                    "--runner",
                    "builder-one",
                    "--yes",
                ][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "credential",
                    "list",
                    "acme",
                    "builder-one",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "credential",
                    "revoke",
                    "acme",
                    "builder-one",
                    "rrc_01k0z6r1w8f4jy2m7q9v3x5abd",
                    "--yes",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["useful", "runner", "create", "--key-file", "-"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "activation",
                    "issue",
                    "builder-one",
                    "--key-file",
                    "-",
                ][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "join-key",
                    "issue",
                    "acme",
                    "--pool",
                    "builders",
                    "--expires-in",
                    "1d",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "join-key",
                    "issue",
                    "--pool-id",
                    "builders",
                    "--expires-in",
                    "1d",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "join-key",
                    "issue",
                    "--pool",
                    "builders",
                    "--expires-in",
                    "1d",
                    "--join-key-file",
                    "k",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["useful", "runner", "join-key", "list", "--limit", "5"][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "join-key",
                    "issue",
                    "--runner",
                    "builder-one",
                    "--expires-in",
                    "1d",
                ][..],
                clap::error::ErrorKind::ArgumentConflict,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "join-key",
                    "list",
                    "--runner",
                    "builder-one",
                    "--pool",
                    "builders",
                ][..],
                clap::error::ErrorKind::ArgumentConflict,
            ),
            (
                &[
                    "useful", "runner", "join-key", "issue", "--pool", "builders",
                ][..],
                clap::error::ErrorKind::MissingRequiredArgument,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "join-key",
                    "issue",
                    "--member",
                    "pam@dundermifflin.com",
                    "--expires-in",
                    "1d",
                ][..],
                clap::error::ErrorKind::MissingRequiredArgument,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "join-key",
                    "revoke",
                    "rrc_01k0z6r1w8f4jy2m7q9v3x5abd",
                    "--yes",
                ][..],
                clap::error::ErrorKind::ValueValidation,
            ),
            (
                &["useful", "runner", "status"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "runner", "grant", "sync"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "runner", "agent-login", "sync"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "show",
                    "builder-one",
                    "--config",
                    "runner.json",
                ][..],
                clap::error::ErrorKind::ArgumentConflict,
            ),
            (
                &["useful", "runner", "show", "--json"][..],
                clap::error::ErrorKind::MissingRequiredArgument,
            ),
            (
                &["useful", "runner", "show", "--org", "acme"][..],
                clap::error::ErrorKind::MissingRequiredArgument,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "serve",
                    "--personal",
                    "--organization",
                    "acme",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "serve",
                    "--pool-id",
                    "builders",
                    "--org",
                    "acme",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "enroll",
                    "--activation-file",
                    "key.json",
                ][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "runner", "serve", "--activation-file", "key.json"][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["useful", "runner", "serve", "--resume"][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "serve",
                    "--replace-credential",
                    "--personal",
                ][..],
                clap::error::ErrorKind::ArgumentConflict,
            ),
            (
                &[
                    "useful",
                    "runner",
                    "serve",
                    "--replace-credential",
                    "--join-key",
                ][..],
                clap::error::ErrorKind::ArgumentConflict,
            ),
            (
                &["useful", "runner", "serve", "--json"][..],
                clap::error::ErrorKind::MissingRequiredArgument,
            ),
        ] {
            let error = parse(arguments).expect_err("an earlier runner spelling must not parse");
            assert_eq!(error.kind(), kind, "{arguments:?}");
        }
    }

    #[test]
    fn the_earlier_workflow_paths_and_options_are_unknown() {
        use clap::error::ErrorKind::{
            ArgumentConflict, InvalidSubcommand, InvalidValue, MissingRequiredArgument,
            UnknownArgument,
        };
        const RUNNER_DOCTOR: &[&str] = &["useful", "runner", "doctor"];
        const WORKFLOW_DOCTOR: &[&str] = &["useful", "workflow", "doctor", "workflow.yaml"];
        const PUBLISH: &[&str] = &[
            "useful",
            "workflow",
            "definition",
            "publish",
            ".useful/engineering",
        ];
        // `runner doctor` checks the host alone, and `workflow doctor` reads and never signs
        // in.
        let runner_doctor: &[&[&str]] = &[
            // The report lists every check.
            &["--list-checks"],
            &["--workflow", "workflow.yaml"],
            &["--readiness"],
            &["--grants"],
            &["--connect"],
            &["--require-grants"],
            &["--runner-id", "rnr_01k0z6r1w8f4jy2m7q9v3x5abd"],
            &["--organization-id", "acme"],
            &["--project-id", "prj_01k0z6r1w8f4jy2m7q9v3x5abd"],
            &["--source-root", "."],
            &["--api-key-file", "key"],
            &["--allow-insecure-http"],
        ];
        let workflow_doctor: &[&[&str]] = &[
            &["--readiness"],
            &["--grants"],
            &["--connect"],
            &["--require-grants"],
            &["--runner-id", "rnr_01k0z6r1w8f4jy2m7q9v3x5abd"],
            &["--organization-id", "acme"],
        ];
        // `publish --on project` finds its Cloud definition by the tree's name and records no
        // link to it.
        let publish: &[&[&str]] = &[
            &["--cloud", "acme"],
            &["--cloud-to", "def_01k0z6r1w8f4jy2m7q9v3x5abd"],
            &["--cloud-new"],
        ];
        let options = runner_doctor
            .iter()
            .map(|options| ([RUNNER_DOCTOR, options].concat(), UnknownArgument))
            .chain(
                workflow_doctor
                    .iter()
                    .map(|options| ([WORKFLOW_DOCTOR, options].concat(), UnknownArgument)),
            )
            .chain(
                publish
                    .iter()
                    .map(|options| ([PUBLISH, options].concat(), UnknownArgument)),
            );
        let cases: Vec<(Vec<&str>, clap::error::ErrorKind)> = [
            (
                vec![
                    "useful",
                    "workflow",
                    "definition",
                    "validate",
                    ".useful/engineering",
                ],
                InvalidSubcommand,
            ),
            (
                vec!["useful", "workflow", "doctor"],
                MissingRequiredArgument,
            ),
            // A definition is named by ID or name wherever it lives, and `list` reads the home
            // and the project in effect to the last page.
            (
                vec![
                    "useful",
                    "workflow",
                    "definition",
                    "cloud",
                    "list",
                    "acme",
                    "prj_01k0z6r1w8f4jy2m7q9v3x5abd",
                ],
                InvalidSubcommand,
            ),
            (
                vec![
                    "useful",
                    "workflow",
                    "definition",
                    "cloud",
                    "show",
                    "acme",
                    "def_01k0z6r1w8f4jy2m7q9v3x5abd",
                    "--project-id",
                    "prj_01k0z6r1w8f4jy2m7q9v3x5abd",
                ],
                InvalidSubcommand,
            ),
            (
                vec!["useful", "workflow", "definition", "list", "--limit", "5"],
                UnknownArgument,
            ),
            // The verbs that change a definition act on it where it lives, in the project in
            // effect, and `update --run-as` names the service principal.
            (
                vec![
                    "useful",
                    "workflow",
                    "definition",
                    "cloud",
                    "enable",
                    "acme",
                    "def_01k0z6r1w8f4jy2m7q9v3x5abd",
                    "--project-id",
                    "prj_01k0z6r1w8f4jy2m7q9v3x5abd",
                ],
                InvalidSubcommand,
            ),
            (
                vec![
                    "useful",
                    "workflow",
                    "definition",
                    "set-principal",
                    "engineering",
                    "prn_01k0z6r1w8f4jy2m7q9v3x5abd",
                ],
                InvalidSubcommand,
            ),
            (
                vec![
                    "useful",
                    "workflow",
                    "definition",
                    "evaluation",
                    "list",
                    "engineering",
                    "--run-id",
                    "run_01k0z6r1w8f4jy2m7q9v3x5abd",
                ],
                UnknownArgument,
            ),
            (
                vec![
                    "useful",
                    "workflow",
                    "definition",
                    "evaluation",
                    "show",
                    "wev_01k0z6r1w8f4jy2m7q9v3x5abd",
                ],
                MissingRequiredArgument,
            ),
            (
                vec!["useful", "workflow", "definition", "update", "engineering"],
                MissingRequiredArgument,
            ),
            (
                vec![
                    "useful",
                    "workflow",
                    "definition",
                    "list",
                    "--on",
                    "personal",
                ],
                InvalidValue,
            ),
            // `publish` reaches Cloud with `--on project`, to the project's definition of the
            // tree's name, and never records the link.
            ([PUBLISH, &["--on", "personal"]].concat(), InvalidValue),
            (
                [PUBLISH, &["--to", "engineering", "--new"]].concat(),
                ArgumentConflict,
            ),
            // Input sets are workflow inputs, staged in the organization and the project in
            // effect.
            (
                vec![
                    "useful",
                    "run",
                    "input-set",
                    "show",
                    "acme",
                    "ris_01k0z6r1w8f4jy2m7q9v3x5abd",
                ],
                InvalidSubcommand,
            ),
            (
                vec![
                    "useful",
                    "workflow",
                    "input-set",
                    "show",
                    "acme",
                    "ris_01k0z6r1w8f4jy2m7q9v3x5abd",
                ],
                UnknownArgument,
            ),
            (
                vec![
                    "useful",
                    "workflow",
                    "input-set",
                    "create",
                    "--project-id",
                    "prj_01k0z6r1w8f4jy2m7q9v3x5abd",
                    "--input-text",
                    "request",
                    "hello",
                ],
                UnknownArgument,
            ),
        ]
        .into_iter()
        .chain(options)
        .collect();
        for (arguments, kind) in cases {
            let error = parse(&arguments).expect_err("an earlier workflow spelling must not parse");
            assert_eq!(error.kind(), kind, "{arguments:?}");
        }
    }

    #[test]
    fn the_earlier_run_paths_and_options_are_unknown() {
        use clap::error::ErrorKind::{
            InvalidSubcommand, InvalidValue, MissingRequiredArgument, UnknownArgument,
        };
        const RUN: &str = "run_01jcq3m8x2k9v7t4r6p0w5n8yz";
        const DEFINITION: &str = "def_01k0z6r1w8f4jy2m7q9v3x5abd";
        // `show` is the one read of a run, local or Cloud, and finds the run itself.
        let cases: Vec<(Vec<&str>, clap::error::ErrorKind)> = vec![
            (
                vec!["useful", "workflow", "run", "status", RUN],
                InvalidSubcommand,
            ),
            (
                vec!["useful", "run", "show", "acme", RUN],
                InvalidSubcommand,
            ),
            (
                vec!["useful", "run", "linear", "show", "acme", RUN],
                InvalidSubcommand,
            ),
            (
                vec!["useful", "workflow", "run", "show", RUN, "--cloud", "acme"],
                UnknownArgument,
            ),
            // `list` is one listing of the runs under the home and in Cloud.
            (vec!["useful", "run", "list", "acme"], InvalidSubcommand),
            (
                vec![
                    "useful",
                    "workflow",
                    "run",
                    "list",
                    "--project-id",
                    "prj_01k0z6r1w8f4jy2m7q9v3x5abd",
                ],
                UnknownArgument,
            ),
            (
                vec!["useful", "workflow", "run", "list", "--on", "cloud"],
                InvalidValue,
            ),
            // `create --on personal|project` starts a Cloud run in the organization and
            // project in effect.
            (
                vec![
                    "useful", "workflow", "run", "create", DEFINITION, "--cloud", "acme",
                ],
                UnknownArgument,
            ),
            (
                vec![
                    "useful",
                    "workflow",
                    "run",
                    "create",
                    DEFINITION,
                    "--no-owner",
                ],
                UnknownArgument,
            ),
            (
                vec![
                    "useful",
                    "workflow",
                    "run",
                    "create",
                    DEFINITION,
                    "--input-set-id",
                    "ris_01k0z6r1w8f4jy2m7q9v3x5abd",
                ],
                UnknownArgument,
            ),
            (
                vec![
                    "useful",
                    "workflow",
                    "run",
                    "create",
                    "engineering",
                    "--on",
                    "cloud",
                ],
                InvalidValue,
            ),
            // A run's retained inputs and Linear updates are read under `workflow run`, in
            // the organization in effect.
            (
                vec!["useful", "run", "input", "show", "acme", RUN],
                InvalidSubcommand,
            ),
            (
                vec!["useful", "run", "linear", "history", "acme", RUN],
                InvalidSubcommand,
            ),
            (
                vec!["useful", "workflow", "run", "linear", "history", RUN],
                InvalidSubcommand,
            ),
            (
                vec!["useful", "workflow", "run", "input", "delete", RUN],
                MissingRequiredArgument,
            ),
            // A run's artifacts are listed, downloaded and checked under `workflow
            // run`.
            (
                vec!["useful", "artifact", "validate", "out"],
                InvalidSubcommand,
            ),
            (
                vec!["useful", "artifact", "list", "acme", RUN],
                InvalidSubcommand,
            ),
            // A run's publications are created and read under `workflow run`, the run named
            // by `RUN` or `--run`.
            (
                vec!["useful", "publication", "list", "acme", RUN],
                InvalidSubcommand,
            ),
            (
                vec![
                    "useful",
                    "workflow",
                    "run",
                    "publication",
                    "show",
                    "pub_01k0z6r1w8f4jy2m7q9v3x5abd",
                ],
                MissingRequiredArgument,
            ),
            (
                vec![
                    "useful",
                    "workflow",
                    "run",
                    "publication",
                    "create",
                    "--export",
                    "review",
                ],
                MissingRequiredArgument,
            ),
            // `answer`, `approve` and `hand-back` find their run under the home and then in
            // Cloud, and take no `--cloud`.
            (
                vec![
                    "useful", "workflow", "run", "answer", RUN, "--text", "x", "--cloud", "acme",
                ],
                UnknownArgument,
            ),
            (
                vec![
                    "useful", "workflow", "run", "approve", RUN, "--cloud", "acme",
                ],
                UnknownArgument,
            ),
            (
                vec![
                    "useful",
                    "workflow",
                    "run",
                    "hand-back",
                    RUN,
                    "--notes",
                    "x",
                    "--cloud",
                    "acme",
                ],
                UnknownArgument,
            ),
            // `pause` and `unpause` hold a run before a step and release the hold, and
            // `create --pause-before` holds it from the start.
            (
                vec![
                    "useful", "workflow", "run", "stop", RUN, "--before", "deploy", "--reason", "x",
                ],
                InvalidSubcommand,
            ),
            (
                vec!["useful", "workflow", "run", "lift", RUN],
                InvalidSubcommand,
            ),
            (
                vec![
                    "useful",
                    "workflow",
                    "run",
                    "create",
                    "engineering",
                    "--stop-before",
                    "deploy",
                ],
                UnknownArgument,
            ),
            // `cancel` ends a run wherever it executes, and finds it itself.
            (
                vec!["useful", "run", "cancel", "acme", RUN],
                InvalidSubcommand,
            ),
            (
                vec!["useful", "workflow", "run", "withdraw", RUN],
                InvalidSubcommand,
            ),
            (
                vec![
                    "useful", "workflow", "run", "cancel", RUN, "--cloud", "acme",
                ],
                UnknownArgument,
            ),
            // `retry` is the one verb that reruns steps, and `resume` reruns none, for a run
            // under the home and a Cloud run alike.
            (
                vec!["useful", "run", "continue", "acme", RUN, "--from", "build"],
                InvalidSubcommand,
            ),
            (
                vec!["useful", "run", "retry", "acme", RUN],
                InvalidSubcommand,
            ),
            (
                vec![
                    "useful", "workflow", "run", "resume", RUN, "--from", "build",
                ],
                UnknownArgument,
            ),
            (
                vec![
                    "useful", "workflow", "run", "resume", RUN, "--cloud", "acme",
                ],
                UnknownArgument,
            ),
            (
                vec!["useful", "workflow", "run", "retry", RUN, "--cloud", "acme"],
                UnknownArgument,
            ),
            // `upgrade --from` moves a waiting run to its definition's current revision and
            // runs the named step again.
            (
                vec![
                    "useful", "workflow", "run", "restart", RUN, "--at", "review",
                ],
                InvalidSubcommand,
            ),
            (
                vec![
                    "useful", "workflow", "run", "upgrade", RUN, "--at", "review",
                ],
                UnknownArgument,
            ),
            // `release` finds its run under the home and then in Cloud, so it takes no
            // `--cloud`.
            (
                vec![
                    "useful", "workflow", "run", "release", RUN, "--cloud", "acme",
                ],
                UnknownArgument,
            ),
            (
                vec!["useful", "run", "release", "acme", RUN],
                InvalidSubcommand,
            ),
        ];
        for (arguments, kind) in cases {
            let error = parse(&arguments).expect_err("an earlier run spelling must not parse");
            assert_eq!(error.kind(), kind, "{arguments:?}");
        }
    }

    // `workflow run event`, which the runner passes a delivered event, is the tree's one
    // hidden path.
    #[test]
    fn workflow_run_event_is_the_one_hidden_path() {
        fn hidden(command: &clap::Command, prefix: &str, paths: &mut Vec<String>) {
            for child in command.get_subcommands() {
                let path = format!("{prefix} {}", child.get_name());
                if child.is_hide_set() {
                    paths.push(path.trim_start().to_owned());
                }
                hidden(child, &path, paths);
            }
        }
        let mut paths = Vec::new();
        hidden(&Cli::command(), "", &mut paths);
        assert_eq!(paths, ["workflow run event"]);
    }

    // `--control` of `workflow run cancel`, which the runner passes, is the tree's one hidden
    // argument.
    #[test]
    fn workflow_run_cancel_control_is_the_one_hidden_argument() {
        fn hidden(command: &clap::Command, prefix: &str, arguments: &mut Vec<String>) {
            for argument in command.get_arguments().filter(|arg| arg.is_hide_set()) {
                let name = argument
                    .get_long()
                    .map_or_else(|| argument.get_id().to_string(), |long| format!("--{long}"));
                arguments.push(format!("{prefix} {name}").trim_start().to_owned());
            }
            for child in command.get_subcommands() {
                hidden(child, &format!("{prefix} {}", child.get_name()), arguments);
            }
        }
        let mut arguments = Vec::new();
        hidden(&Cli::command(), "", &mut arguments);
        assert_eq!(arguments, ["workflow run cancel --control"]);
    }

    #[test]
    fn the_earlier_organization_paths_and_options_are_unknown() {
        for (arguments, kind) in [
            (
                &["useful", "organization", "list"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "org", "deletion", "request", "acme", "--yes"][..],
                clap::error::ErrorKind::InvalidSubcommand,
            ),
            (
                &["useful", "org", "create", "--display-name", "X"][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &[
                    "useful",
                    "org",
                    "invitation",
                    "issue",
                    "--principal-id",
                    "prn_01k0z6r1w8f4jy2m7q9v3x5abc",
                ][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
        ] {
            let error = parse(arguments).expect_err("an earlier spelling must not parse");
            assert_eq!(error.kind(), kind, "{arguments:?}");
        }
    }
}
