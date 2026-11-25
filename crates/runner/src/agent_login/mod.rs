//! Agent-login setup for the serving runner: asking Cloud which agent logins
//! the runner may hold, fetching one delivery at a time, keeping it in the
//! runner's own agent-login directory, recording each provider's readiness,
//! and offering what it keeps to each assignment it admits, once it has set
//! them up for that admission, noting how the provider answered each use of
//! what it offered, and checking a login it holds with its provider. Each
//! admission also asks Cloud for the grant tokens of its own assignment and
//! keeps them, in a directory of that assignment's own, until the assignment
//! ends. Where each provider's credential comes from, the host, a grant or
//! for `github` the organization's installation, is settled by one rule,
//! `credential_source`, which the readiness document, the offer and what the
//! runner reports all take.

pub(crate) mod blocked;
pub(crate) mod check;
pub(crate) mod claude_code;
pub(crate) mod cloud;
pub(crate) mod codex;
pub(crate) mod directory;
pub(crate) mod grant_token;
pub(crate) mod mode;
pub(crate) mod readiness;
pub(crate) mod required;
pub(crate) mod setup;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use useful_execution::{
    CLAUDE_CODE_LOGIN_VARIABLE, CODEX_LOGIN_VARIABLE, EnvironmentSnapshot,
    USEFUL_RUNNER_CREDENTIAL_MODE,
};

use crate::control_protocol::{
    AgentLoginCheckCause, AgentLoginProvider, AgentLoginState, CredentialMode, CredentialSource,
};
use crate::telemetry;
use blocked::AdmittedMode;
use directory::LoginDirectory;

/// A token the runner keeps in a file of its own, a Claude Code login or a
/// grant access token, is one line of at most this many printable
/// characters.
pub(crate) const TOKEN_LIMIT: usize = 4096;

/// Whether `bytes` are one such token: one line of 1 to `TOKEN_LIMIT`
/// printable characters without spaces, the form Cloud accepts and an
/// environment variable can carry.
pub(crate) fn valid_token(bytes: &[u8]) -> bool {
    (1..=TOKEN_LIMIT).contains(&bytes.len()) && bytes.iter().all(u8::is_ascii_graphic)
}

/// The serving process's environment as far as standing back for the
/// service's own credentials needs it. Setup takes it as a value so that the
/// decision rests on the service's environment, which only the serving
/// process has. It keeps the name of every variable the service carries,
/// never a value, so that whether the host provides an OAuth provider can be
/// answered for any name, one first seen in Cloud's list of an assignment's
/// providers included; whether the service carries `CLAUDE_CODE_OAUTH_TOKEN`
/// or `CODEX_HOME`; and where its `HOME` and `CLAUDE_CONFIG_DIR` are, so
/// that a login file under them can be looked for.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ServiceEnvironment {
    home: Option<OsString>,
    claude_config_dir: Option<OsString>,
    claude_code_oauth_token: bool,
    codex_home: bool,
    /// The name of every variable the service carries.
    names: BTreeSet<OsString>,
}

impl ServiceEnvironment {
    /// The environment of a service whose variables are `variables`, for
    /// example `std::env::vars_os()`: the name of each, and the values of
    /// `HOME` and `CLAUDE_CONFIG_DIR` alone.
    pub(crate) fn from_variables<I, Name, Value>(variables: I) -> Self
    where
        I: IntoIterator<Item = (Name, Value)>,
        Name: Into<OsString>,
        Value: Into<OsString>,
    {
        let mut environment = Self::default();
        for (name, value) in variables {
            let name = name.into();
            if name == "HOME" {
                environment.home = Some(value.into());
            } else if name == "CLAUDE_CONFIG_DIR" {
                environment.claude_config_dir = Some(value.into());
            }
            environment.names.insert(name);
        }
        environment.claude_code_oauth_token = environment.carries(CLAUDE_CODE_LOGIN_VARIABLE);
        environment.codex_home = environment.carries(CODEX_LOGIN_VARIABLE);
        environment
    }

    /// The environment of the service whose process environment is
    /// `process`.
    pub(crate) fn of(process: &EnvironmentSnapshot) -> Self {
        Self::from_variables(
            process
                .variables()
                .iter()
                .map(|(name, value)| (name.clone(), value.clone())),
        )
    }

    /// Whether the service carries the variable `name`, whatever its value.
    pub(crate) fn carries(&self, name: &str) -> bool {
        self.names.contains(OsStr::new(name))
    }

    /// Whether the host provides the OAuth provider: the service carries
    /// either of its two names, so the runner asks for and offers no grant
    /// token of it, and both names stay as the service has them.
    pub(crate) fn provides(&self, provider: AgentLoginProvider) -> bool {
        grant_token::OFFERED_VARIABLES
            .iter()
            .any(|&(offered, variable, file_variable)| {
                offered == provider && (self.carries(variable) || self.carries(file_variable))
            })
    }

    /// The service environment each rule that asks what the host provides
    /// is asked of for an assignment admitted under `mode`: this one, but in
    /// `cloud` one that carries no name and has no home, so that the host
    /// provides nothing, no login of the service's own counts and no source
    /// is `host`.
    pub(crate) fn under(&self, mode: Option<CredentialMode>) -> &Self {
        match mode {
            Some(CredentialMode::Cloud) => &PROVIDES_NOTHING,
            None | Some(CredentialMode::Host) => self,
        }
    }

    /// `relative` under the service's `HOME`; none while `HOME` is unset or
    /// not absolute.
    fn under_home(&self, relative: &str) -> Option<PathBuf> {
        self.home
            .as_ref()
            .map(PathBuf::from)
            .filter(|home| home.is_absolute())
            .map(|home| home.join(relative))
    }
}

/// The service environment that provides nothing: no name, no home
/// (`ServiceEnvironment::under`).
static PROVIDES_NOTHING: ServiceEnvironment = ServiceEnvironment {
    home: None,
    claude_config_dir: None,
    claude_code_oauth_token: false,
    codex_home: false,
    names: BTreeSet::new(),
};

/// Whether a file of the service's own login is present at `path`. It is
/// only looked at, never opened or followed, and one the runner cannot tell
/// is absent counts as present.
fn login_file_present(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) => error.kind() != io::ErrorKind::NotFound,
    }
}

/// Why a delivery was not kept.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InstallRefusal {
    /// The delivery is older than the generation the runner installed.
    StaleGeneration,
    /// The runner's directory or the file could not be written, or the
    /// material is not a login of the provider's form.
    InstallFailed(StepFailure),
}

impl InstallRefusal {
    pub(crate) const fn state(self) -> AgentLoginState {
        match self {
            Self::StaleGeneration => AgentLoginState::StaleGeneration,
            Self::InstallFailed(_) => AgentLoginState::InstallFailed,
        }
    }

    /// The step that failed, for a refusal that is a failure.
    pub(crate) const fn failure(self) -> Option<StepFailure> {
        match self {
            Self::StaleGeneration => None,
            Self::InstallFailed(failure) => Some(failure),
        }
    }

    /// The refusal of an install whose `stage` failed with `error`.
    pub(crate) fn failed(stage: FailureStage, error: &io::Error) -> Self {
        Self::InstallFailed(StepFailure {
            stage,
            cause: FailureCause::Io(error.kind()),
        })
    }
}

/// A step of agent-login setup for one provider that failed, as the
/// `runner.agent_login_setup` record names it: closed values only, never
/// a path, a message or material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StepFailure {
    pub(crate) stage: FailureStage,
    pub(crate) cause: FailureCause,
}

/// Where a provider's setup failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureStage {
    /// Asking Cloud for the runner's status.
    Status,
    /// Asking Cloud for a delivery, or keeping material that is not a login
    /// of the provider's form.
    Delivery,
    /// Making the runner's directory or its Codex home.
    Directory,
    /// Writing a file in it.
    Write,
    /// Removing the provider's file from it.
    Remove,
    /// Checking the provider's installed login with its provider, which
    /// gave no answer.
    Check,
}

impl FailureStage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Delivery => "delivery",
            Self::Directory => "directory",
            Self::Write => "write",
            Self::Remove => "remove",
            Self::Check => "check",
        }
    }
}

/// Why a step failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureCause {
    /// An operating-system call failed with this kind.
    Io(io::ErrorKind),
    /// Cloud answered with a status the request does not expect.
    HttpStatus(u16),
    /// Cloud gave no answer: the connection failed or timed out.
    Transport,
    /// Cloud's answer, or the material it delivered, is not one the runner
    /// may trust.
    InvalidResponse,
    /// A check of the login gave no answer for this reason.
    Check(AgentLoginCheckCause),
}

impl FailureCause {
    /// The closed class the record carries; an HTTP status's code is a
    /// separate attribute.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Io(kind) => telemetry::io_error_class(kind),
            Self::HttpStatus(_) => "http_status",
            Self::Transport => "transport",
            Self::InvalidResponse => "invalid_response",
            Self::Check(cause) => cause.as_str(),
        }
    }
}

/// The source the admission can actually offer. Cloud mode ignores the host, and host
/// mode never inspects the runner's installed logins or assignment token files.
pub(crate) fn credential_source(
    provider: AgentLoginProvider,
    mode: Option<CredentialMode>,
    service: &ServiceEnvironment,
    directory: Option<&LoginDirectory>,
    grant_tokens: Option<&grant_token::AssignmentGrantTokens>,
) -> Option<CredentialSource> {
    let service = service.under(mode);
    let host = match provider {
        AgentLoginProvider::Codex => codex::foreign_login(service),
        AgentLoginProvider::ClaudeCode => claude_code::foreign_login(service),
        _ => service.provides(provider),
    };
    if host {
        return Some(CredentialSource::Host);
    }
    if mode == Some(CredentialMode::Host) {
        return None;
    }
    match provider {
        AgentLoginProvider::Codex => directory
            .filter(|directory| codex::offered_home(service, directory).is_some())
            .map(|_| CredentialSource::Grant),
        AgentLoginProvider::ClaudeCode => directory
            .filter(|directory| claude_code::offered_token(service, directory).is_some())
            .map(|_| CredentialSource::Grant),
        AgentLoginProvider::Github | AgentLoginProvider::Gitlab | AgentLoginProvider::Linear => {
            grant_tokens
                .filter(|tokens| tokens.holds(provider))
                .and_then(|tokens| tokens.issuer(provider))
                .map(|issuer| match issuer {
                    cloud::Issuer::ConnectionAuthorization(_) => CredentialSource::OrgConnection,
                    cloud::Issuer::Grant(_) | cloud::Issuer::IntegrationToken(_) => {
                        CredentialSource::Grant
                    }
                })
        }
    }
}

/// A provider's credential source as an admission settled it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProviderSource {
    pub(crate) provider: AgentLoginProvider,
    pub(crate) source: CredentialSource,
}

/// What an admission is offered: the environment its steps draw from, and
/// where each provider's credential in it comes from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Offer {
    /// The process environment, with each agent login the runner offers
    /// added as the variable its coding agent reads; for an assignment
    /// admitted in `cloud`, without its blocked names first.
    pub(crate) environment: EnvironmentSnapshot,
    /// Each variable added to `environment` whose login the readiness
    /// document records as installed, with that install: the uses an
    /// admission notes.
    pub(crate) offered: Vec<OfferedLogin>,
    /// Each provider that has a source, in `AgentLoginProvider::ALL`'s
    /// order, as `credential_source` settles it from the process
    /// environment, the directory and the grant tokens the offer is built
    /// from.
    pub(crate) sources: Vec<ProviderSource>,
    /// Each token service Cloud listed for the assignment that has a
    /// source, in the list's order, as `grant_token::token_service_sources`
    /// settles it from the environment and the grant tokens the offer is
    /// built from; none where Cloud did not answer the list.
    pub(crate) token_services: Vec<cloud::ReportedTokenService>,
    /// What each command a tree run of the admission starts is offered,
    /// built when it starts: from the same process environment and
    /// directory as `environment`, with the grant token variables
    /// `environment` added.
    pub(crate) commands: CommandEnvironment,
}

/// What each `useful` command of a tree run is offered, built when the
/// command starts: the process environment, with each agent
/// login the runner keeps in `directory` then added as `with_agent_logins`
/// adds it, and with the grant token variables of the assignment's admission
/// as that admission offered them (`grant_token::offer`). A token variable
/// keeps the admission's value while the file its file variable names is
/// kept current, so a build reads no grant token file and no
/// readiness document; only the agent logins are looked at again. The
/// admission's own environment, its credential sources and its observer
/// stay as the admission settled them. An assignment
/// admitted in `host` is offered the process environment unchanged at
/// every command, whatever the directory holds then. One admitted in `cloud` has its blocked names removed
/// from the process environment at every build, before anything is added,
/// and is offered the agent logins the directory holds then whatever the
/// service has. Every build
/// sets `USEFUL_RUNNER_CREDENTIAL_MODE` to `cloud` for an assignment
/// admitted in `cloud` and removes an inherited value otherwise.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommandEnvironment {
    process: EnvironmentSnapshot,
    directory: Option<LoginDirectory>,
    /// Each grant token variable the admission's offer added, with its value.
    grant_tokens: Vec<(OsString, OsString)>,
    /// The credential mode the assignment was admitted under, with the
    /// names it blocks in `cloud`.
    mode: AdmittedMode,
}

impl CommandEnvironment {
    /// What a runner that keeps no agent login offers: the process
    /// environment, unchanged.
    pub(crate) fn process(process: EnvironmentSnapshot) -> Self {
        Self {
            process,
            directory: None,
            grant_tokens: Vec::new(),
            mode: AdmittedMode::Unnamed,
        }
    }

    /// The environment a command starting now is given. It reads the agent
    /// login files the runner keeps, small private files, so it runs on a
    /// blocking worker.
    pub(crate) fn build(&self) -> EnvironmentSnapshot {
        let mut variables = self.offered_variables();
        // Only the runner's word on the mode reaches the command, which then
        // makes its own provider calls with the offered names alone.
        let mode = OsStr::new(USEFUL_RUNNER_CREDENTIAL_MODE);
        match self.mode {
            AdmittedMode::Cloud(_) => {
                variables.insert(mode.to_owned(), OsString::from("cloud"));
            }
            AdmittedMode::Unnamed | AdmittedMode::Host => {
                variables.remove(mode);
            }
        }
        EnvironmentSnapshot::new(variables)
    }

    /// What `build` offers before it settles the credential mode variable.
    fn offered_variables(&self) -> BTreeMap<OsString, OsString> {
        let base = match &self.mode {
            AdmittedMode::Host => return self.process.variables().clone(),
            AdmittedMode::Unnamed => self.process.clone(),
            AdmittedMode::Cloud(blocked) => blocked.remove_from(&self.process),
        };
        let service = ServiceEnvironment::of(&self.process);
        let service = service.under(self.mode.credential_mode());
        let logins = self
            .directory
            .as_ref()
            .map(|directory| agent_logins(service, directory))
            .unwrap_or_default();
        let mut variables = base.variables().clone();
        variables.extend(logins.into_iter().map(|login| login.added));
        for (name, value) in &self.grant_tokens {
            match self.mode {
                // Its names were removed, so the token takes their place.
                AdmittedMode::Cloud(_) => {
                    variables.insert(name.clone(), value.clone());
                }
                // The admission added a token only under names its
                // environment did not carry, so none of them replaces a
                // value here either.
                AdmittedMode::Unnamed | AdmittedMode::Host => {
                    variables
                        .entry(name.clone())
                        .or_insert_with(|| value.clone());
                }
            }
        }
        variables
    }
}

/// A login the runner added to an admission's environment, as the
/// readiness document records its install.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OfferedLogin {
    /// The variable its coding agent reads.
    pub(crate) variable: &'static str,
    pub(crate) provider: AgentLoginProvider,
    pub(crate) agent_login_id: String,
    pub(crate) generation: u64,
}

/// What the admission of an assignment admitted under `mode` is offered
/// with the agent logins the runner keeps in `directory`
/// (`with_agent_logins`), and each provider's source as `credential_source`
/// settles it under `mode` from the same environment and directory with no
/// grant token held; an admission is offered its grant tokens through
/// `offer_with_grant_tokens`, which builds on this. In `host` it is offered
/// the process environment unchanged, and nothing the runner keeps. In `cloud` it starts from the process environment
/// without the names `mode` blocks, and adds each agent login the runner
/// keeps as the rules asked of a service that provides nothing offer it,
/// whatever login the service has.
pub(crate) fn offer(
    process: &EnvironmentSnapshot,
    directory: Option<&LoginDirectory>,
    mode: AdmittedMode,
) -> Offer {
    let service = ServiceEnvironment::of(process);
    let (environment, offered) = match &mode {
        AdmittedMode::Host => (process.clone(), Vec::new()),
        AdmittedMode::Unnamed => with_agent_logins(process, &service, directory),
        AdmittedMode::Cloud(blocked) => with_agent_logins(
            &blocked.remove_from(process),
            service.under(mode.credential_mode()),
            directory,
        ),
    };
    Offer {
        environment,
        offered,
        sources: sources(&service, mode.credential_mode(), directory, None),
        token_services: Vec::new(),
        commands: CommandEnvironment {
            process: process.clone(),
            directory: directory.cloned(),
            grant_tokens: Vec::new(),
            mode,
        },
    }
}

/// What an assignment's admission is offered: `offer`'s, with the grant
/// tokens it holds, `grant_tokens`, and their files offered as well
/// (`grant_token::offer`), and each provider's source settled
/// with them, each token service Cloud
/// listed for the assignment included. With no mode the
/// admission holds no token of a provider the host provides, whose names
/// stay as the process environment has them, and nothing is withheld. In
/// `cloud` the set of blocked names is settled here, once, from the tokens
/// the admission holds, the token services it checked and the names of
/// Cloud's provider table it was answered (`AdmittedMode::of`), the offer starts from the process environment
/// without them, and each token is offered under its two names whatever
/// the service carried. No
/// `OfferedLogin` records a grant token, whose uses are not noted. Its
/// `commands` keep the token variables it added, as values, so the
/// environment the admission reports its sources from and the one its tree
/// run's first command is given come from this one call.
/// It goes by the assignment's credential mode, `mode`, read once by the
/// admission: in `host` it is `offer`'s, since the
/// admission asked for no token and Cloud listed no token service.
pub(crate) fn offer_with_grant_tokens(
    process: &EnvironmentSnapshot,
    directory: Option<&LoginDirectory>,
    grant_tokens: Option<&grant_token::AssignmentGrantTokens>,
    mode: Option<CredentialMode>,
) -> Offer {
    let offered = offer(process, directory, AdmittedMode::of(mode, grant_tokens));
    match mode {
        Some(CredentialMode::Host) => return offered,
        None | Some(CredentialMode::Cloud) => {}
    }
    let environment = grant_token::offer(&offered.environment, grant_tokens);
    // `grant_token::offer` only adds names, and only ones its input did not
    // carry: in `cloud` its input carries no name of a token held.
    let added = environment
        .variables()
        .iter()
        .filter(|(name, _)| offered.environment.variable(name).is_none())
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    Offer {
        environment,
        sources: sources(
            &ServiceEnvironment::of(process),
            mode,
            directory,
            grant_tokens,
        ),
        token_services: grant_token::token_service_sources(&offered.environment, grant_tokens),
        commands: CommandEnvironment {
            grant_tokens: added,
            ..offered.commands
        },
        ..offered
    }
}

/// `process`, the environment of the service `service` describes, with each
/// agent login the runner keeps in `directory` added as the variable its
/// coding agent reads (`CODEX_HOME`, `CLAUDE_CODE_OAUTH_TOKEN`) where the
/// service has no login of that agent's own, and each added
/// variable whose login the readiness document records as installed. Where
/// the runner keeps none either, nothing is added and nothing withheld: the
/// variable is as the process environment has it. A variable the process
/// environment carries, a grant token name included, is never replaced or removed, and the process
/// environment itself is never changed. For an assignment admitted in
/// `cloud`, `process` is the process environment without the blocked names
/// and `service` one that provides nothing. A missing or unreadable readiness
/// document records no install of what is added. Which steps receive a
/// variable is the workflow's `environmentPassthrough` and its declared
/// integrations.
fn with_agent_logins(
    process: &EnvironmentSnapshot,
    service: &ServiceEnvironment,
    directory: Option<&LoginDirectory>,
) -> (EnvironmentSnapshot, Vec<OfferedLogin>) {
    let Some(directory) = directory else {
        return (process.clone(), Vec::new());
    };
    let logins = agent_logins(service, directory);
    let document = recorded_readiness(directory);
    let offered = logins
        .iter()
        .filter_map(|login| {
            let installation = document
                .as_ref()
                .and_then(|document| document.login(login.provider))
                .and_then(readiness::LoginReadiness::installation)?;
            Some(OfferedLogin {
                variable: login.variable,
                provider: login.provider,
                agent_login_id: installation.agent_login_id.clone(),
                generation: installation.generation,
            })
        })
        .collect();
    let environment = if logins.is_empty() {
        process.clone()
    } else {
        let mut variables = process.variables().clone();
        variables.extend(logins.into_iter().map(|login| login.added));
        EnvironmentSnapshot::new(variables)
    };
    (environment, offered)
}

/// An agent login the runner keeps that an environment is offered.
struct AddedLogin {
    provider: AgentLoginProvider,
    /// The variable its coding agent reads.
    variable: &'static str,
    /// That variable with the login.
    added: (OsString, OsString),
}

/// Each agent login the runner keeps in `directory` that the environment of
/// the service `service` describes is offered, where the service has no
/// login of that agent's own, in `INSTALLABLE`'s order.
fn agent_logins(service: &ServiceEnvironment, directory: &LoginDirectory) -> Vec<AddedLogin> {
    AgentLoginProvider::INSTALLABLE
        .into_iter()
        .filter_map(|provider| {
            let (variable, added) = match provider {
                AgentLoginProvider::Codex => (
                    CODEX_LOGIN_VARIABLE,
                    codex::offered_home(service, directory)?,
                ),
                AgentLoginProvider::ClaudeCode => (
                    CLAUDE_CODE_LOGIN_VARIABLE,
                    claude_code::offered_token(service, directory)?,
                ),
                AgentLoginProvider::Github
                | AgentLoginProvider::Gitlab
                | AgentLoginProvider::Linear => return None,
            };
            Some(AddedLogin {
                provider,
                variable,
                added,
            })
        })
        .collect()
}

/// Each provider's source under the assignment's credential mode `mode`, in
/// `AgentLoginProvider::ALL`'s order, leaving out those with none
/// (`credential_source`).
fn sources(
    service: &ServiceEnvironment,
    mode: Option<CredentialMode>,
    directory: Option<&LoginDirectory>,
    grant_tokens: Option<&grant_token::AssignmentGrantTokens>,
) -> Vec<ProviderSource> {
    AgentLoginProvider::ALL
        .into_iter()
        .filter_map(|provider| {
            credential_source(provider, mode, service, directory, grant_tokens)
                .map(|source| ProviderSource { provider, source })
        })
        .collect()
}

/// What an admission reports to Cloud of the sources its offer settled,
/// in one request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReportedSources {
    /// Each provider's that has one, in `AgentLoginProvider::ALL`'s order.
    pub(crate) sources: Vec<cloud::ReportedSource>,
    /// Each token service's that has one, in Cloud's list's order, after
    /// the providers'.
    pub(crate) token_services: Vec<cloud::ReportedTokenService>,
}

/// What an admission reports to Cloud of `offer`'s sources: each provider
/// that has one, an OAuth grant by the ID of the grant its token in
/// `grant_tokens` was issued from, `github`'s `org_connection` by the ID of
/// the connection authorization it was issued under, and a coding agent's
/// grant by the agent login the offer's `offered` records for it, absent when
/// the readiness document records no install; then each token service the
/// offer settled a source of, a token by the `itk_` ID it was issued from. An
/// OAuth source whose token's issuer is not known is left out, since Cloud
/// records no such entry; `offer` gives it a source only for a token it
/// holds.
pub(crate) fn reported_sources(
    offer: &Offer,
    grant_tokens: Option<&grant_token::AssignmentGrantTokens>,
) -> ReportedSources {
    let offered = &offer.offered;
    let sources = offer
        .sources
        .iter()
        .filter_map(|&ProviderSource { provider, source }| {
            let issuer = || grant_tokens?.issuer(provider);
            let (grant_id, connection_authorization_id, agent_login_id) = match source {
                CredentialSource::Host => (None, None, None),
                CredentialSource::OrgConnection => (
                    None,
                    Some(issuer()?.connection_authorization_id()?.to_owned()),
                    None,
                ),
                CredentialSource::Grant if provider.is_brokered() => {
                    (Some(issuer()?.grant_id()?.to_owned()), None, None)
                }
                CredentialSource::Grant => (
                    None,
                    None,
                    offered
                        .iter()
                        .find(|login| login.provider == provider)
                        .map(|login| login.agent_login_id.clone()),
                ),
            };
            Some(cloud::ReportedSource {
                provider,
                source,
                grant_id,
                connection_authorization_id,
                agent_login_id,
            })
        })
        .collect();
    ReportedSources {
        sources,
        token_services: offer.token_services.clone(),
    }
}

/// The readiness document beside `directory`; none when there is none or it
/// cannot be read, since the pass that read it has recorded that failure.
fn recorded_readiness(directory: &LoginDirectory) -> Option<readiness::ReadinessDocument> {
    // The directory and the document are both beside the runner state.
    readiness::ReadinessDocument::load(&readiness::readiness_path(directory.path()))
        .ok()
        .flatten()
}

/// The agent-login side of the control protocol's provider: which of them
/// this build of the runner can install, and in what form.
impl AgentLoginProvider {
    /// Every provider this build can install, in a stable order.
    pub(crate) const INSTALLABLE: [Self; 2] = [Self::Codex, Self::ClaudeCode];

    /// The installable provider `name` names on the wire; `None` for a
    /// brokered provider or one this build does not know.
    pub(crate) fn installable(name: &str) -> Option<Self> {
        Self::named(name).filter(|provider| !provider.is_brokered())
    }

    /// The record schema versions of the provider's material this build can
    /// install; none for a brokered provider.
    pub(crate) const fn record_schema_versions(self) -> &'static [u32] {
        match self {
            Self::Codex | Self::ClaudeCode => &[1],
            Self::Github | Self::Gitlab | Self::Linear => &[],
        }
    }
}

/// The runner host's operating system as Cloud lists it for a provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperatingSystem {
    Linux,
    Macos,
}

impl OperatingSystem {
    /// The operating system this build runs on; the runner is built only for
    /// Linux and macOS.
    pub(crate) const fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::Macos
        } else {
            Self::Linux
        }
    }
}
