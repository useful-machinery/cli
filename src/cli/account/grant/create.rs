mod workflow;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, anyhow};
use clap::{ArgGroup, Args};
use zeroize::Zeroizing;

use crate::cli::context::{self, InEffect, OrgArgs};
use crate::cli::integration_token;
use crate::cli::workflow::doctor::roots::Roots;
use crate::cli::{CommandFailure, HttpOptions, NoAuthenticationArgs};
use crate::exit_code::ExitCode;
use useful_api::{
    AgentLoginReportState, IntegrationTokenOwner, MemberGrant, MemberGrantApi, MemberGrantFailure,
    MemberGrantKind, MemberGrantProvider, ServedGrantProvider, ServedTokenService,
};
use useful_human_auth::Deployment;
use useful_runner::{CredentialKind, WorkflowCredentials};

use super::super::super::secret_file::FileMode;
use super::consent::{Consent, ConsentProvider, Ended, Options, write_refusal};
use super::organization::Organization;
use super::program::Stop;
use super::projection::{self, Provider};
use super::{
    browser, claude_setup_token, codex_login, material, organization, output, replacement,
    replayed, runner_choice,
};

pub(super) const ABOUT: &str =
    "Connect a service through the provider's own sign-in or with your token of it";

// The help of the options `create` and `reconnect` share.
pub(super) const LOGIN_HELP: &str = "Run Codex's sign-in, as when no other source is named";
pub(super) const DEVICE_HELP: &str =
    "Sign in to Codex with a device code, which any browser can complete";
pub(super) const FROM_FILE_HELP: &str = "Read a Codex auth.json or a token service's token from an owned mode-0600 file, or - for standard input";
pub(super) const TOKEN_FILE_HELP: &str = "Read the token claude setup-token printed from an owned mode-0600 file, or - for standard input";
pub(super) const NO_WAIT_HELP: &str =
    "Return after starting a consent instead of waiting for the callback; OAuth providers only";

// One of PROVIDER, `--all` and `--workflow` says what to sign in to; without one the command is
// refused before any request.
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("source").multiple(false)))]
#[command(group(
    ArgGroup::new("selector")
        .args(["provider", "all", "workflows"])
        .required(true)
))]
pub(super) struct Command {
    #[arg(
        value_name = "PROVIDER",
        value_parser = parse_provider,
        help = "Service to connect: github, gitlab.com, linear, claude_code, codex or the id of another OAuth provider or token service your deployment serves"
    )]
    provider: Option<ProviderName>,

    #[arg(
        long,
        conflicts_with = "provider",
        help = "Sign in to each provider you hold no grant of"
    )]
    all: bool,

    #[arg(
        long = "workflow",
        value_name = "FILE",
        conflicts_with_all = ["provider", "all"],
        help = "Sign in to only the providers this workflow file, or the tree a directory holds, and the workflows it runs call for; repeats"
    )]
    workflows: Vec<PathBuf>,

    // Clap waives `requires` where the option required conflicts with one given, as `--workflow`
    // does with PROVIDER and `--all`, so those conflicts are stated here too, as they are for
    // each option below that needs one selector.
    #[arg(
        long,
        value_name = "ROOT",
        requires = "workflows",
        conflicts_with_all = ["provider", "all"],
        help = "Directory boundary for the --workflow files"
    )]
    source_root: Option<PathBuf>,

    // The runner whose host's own coding agent sign-ins the workflows' sign-ins pass
    // over.
    #[arg(
        long,
        value_name = "RUNNER",
        requires = "workflows",
        conflicts_with_all = ["provider", "all"],
        help = super::RUNNER_HELP
    )]
    runner: Option<String>,

    #[command(flatten)]
    org: OrgArgs,

    #[arg(long, group = "source", help = LOGIN_HELP)]
    login: bool,

    #[arg(long, group = "source", help = DEVICE_HELP)]
    device: bool,

    #[arg(
        long,
        value_name = "PATH",
        group = "source",
        requires = "provider",
        conflicts_with_all = ["all", "workflows"],
        help = FROM_FILE_HELP
    )]
    from_file: Option<PathBuf>,

    #[arg(
        long,
        value_name = "PATH",
        group = "source",
        requires = "provider",
        conflicts_with_all = ["all", "workflows"],
        help = TOKEN_FILE_HELP
    )]
    token_file: Option<PathBuf>,

    #[command(flatten)]
    wait: super::super::super::WaitTimeoutArgs,

    #[arg(long, conflicts_with = "timeout", help = NO_WAIT_HELP)]
    no_wait: bool,

    #[command(flatten)]
    options: Options,
}

/// What the flow of `useful account integration connect` reads of the command that runs it, besides
/// the providers: `create` builds it from its options and `reconnect` from its own, taking the
/// defaults for the rest.
#[derive(Clone, Copy, Default)]
pub(in crate::cli) struct Flow<'a> {
    /// Whether each line printed is a JSON event.
    pub(in crate::cli) json: bool,
    /// Whether the requests may use insecure HTTP.
    pub(in crate::cli) allow_insecure_http: bool,
    /// The organization a coding agent's grant is for, by ID or exact slug, as `--org` or
    /// `USEFUL_ORG` named it; without one, the checkout or the member's only active membership
    /// names it.
    pub(in crate::cli) organization: Option<&'a str>,
    /// Whether Codex signs in by device code even where this machine has a browser.
    pub(in crate::cli) device: bool,
    /// Whether a consent returns once started instead of waiting for its callback.
    pub(in crate::cli) no_wait: bool,
    /// How long a consent is waited for, when not its default.
    pub(in crate::cli) timeout: Option<Duration>,
    /// The `rnr_` ID of the runner `--runner` named, whose host's own sign-in of a coding agent
    /// the flow over workflow files passes over.
    pub(in crate::cli) runner: Option<&'a str>,
}

/// A provider `useful account integration connect` has a built-in name for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProviderArg {
    Github,
    GitlabCom,
    Linear,
    ClaudeCode,
    Codex,
}

/// The `PROVIDER` `useful account integration connect` is given: one of the five it has a built-in
/// name for, or any other provider id, taken for an OAuth provider the deployment serves, which the
/// command reads before it begins anything.
#[derive(Clone, Debug, Eq, PartialEq)]
enum ProviderName {
    BuiltIn(ProviderArg),
    Other(String),
}

/// Parses `PROVIDER`: one of the five by its wire name, or any other name of the provider id
/// shape; anything else is a usage error before any request.
fn parse_provider(value: &str) -> Result<ProviderName, String> {
    if let Some(provider) = ProviderArg::from_name(value) {
        return Ok(ProviderName::BuiltIn(provider));
    }
    if useful_api::valid_provider_id(value) {
        return Ok(ProviderName::Other(value.to_owned()));
    }
    Err(
        "provider must be github, gitlab.com, linear, claude_code or codex, or the id of another \
         OAuth provider or token service your deployment serves"
            .to_owned(),
    )
}

/// An OAuth provider beyond `github`, `gitlab.com` and `linear` that the deployment serves: its
/// id, and its title, the display name the deployment serves for it or else its id.
#[derive(Clone, Debug, Eq, PartialEq)]
struct NamedProvider {
    name: String,
    title: String,
}

impl NamedProvider {
    /// The provider `served` names, when it is an OAuth provider with no built-in name.
    fn of(served: &ServedGrantProvider) -> Option<Self> {
        (served.kind == MemberGrantKind::GrantKindOAuth
            && ProviderArg::from_name(&served.name).is_none())
        .then(|| Self {
            name: served.name.clone(),
            title: served
                .display_name
                .clone()
                .unwrap_or_else(|| served.name.clone()),
        })
    }

    /// The consent that makes its grant.
    fn consent(&self) -> ConsentProvider<'_> {
        ConsentProvider {
            name: &self.name,
            title: &self.title,
            reconnects: None,
        }
    }
}

/// The OAuth provider with no built-in name whose id is `name`, among those `served` names.
fn served_oauth(served: &[ServedGrantProvider], name: &str) -> Option<NamedProvider> {
    served
        .iter()
        .filter_map(NamedProvider::of)
        .find(|provider| provider.name == name)
}

/// A provider in the order `useful account integration connect` signs in to several in: one of the
/// five it has a built-in name for, or another OAuth provider the deployment serves.
enum Ordered {
    BuiltIn(ProviderArg),
    Served(NamedProvider),
}

impl Ordered {
    /// The consent of an OAuth provider; a coding agent has none.
    fn consent(&self) -> Option<ConsentProvider<'_>> {
        match self {
            Self::BuiltIn(provider) => provider.consent(),
            Self::Served(provider) => Some(provider.consent()),
        }
    }

    /// The provider when it is one of the five.
    const fn built_in(&self) -> Option<ProviderArg> {
        match self {
            Self::BuiltIn(provider) => Some(*provider),
            Self::Served(_) => None,
        }
    }
}

/// The order `useful account integration connect` signs in to several providers in, that of
/// [`projection::providers`] for the providers `served` names: the OAuth providers first, whose
/// consents need only a browser anywhere, the deployment's other OAuth providers after the built-in
/// ones, then the coding agents, whose sign-ins run on this machine.
fn order(served: &[ServedGrantProvider]) -> Vec<Ordered> {
    projection::providers(served)
        .into_iter()
        .filter_map(|provider| {
            let name = provider.name();
            ProviderArg::from_name(name)
                .map(Ordered::BuiltIn)
                .or_else(|| {
                    served
                        .iter()
                        .find(|served| served.name == name)
                        .and_then(NamedProvider::of)
                        .map(Ordered::Served)
                })
        })
        .collect()
}

/// What a selection chooses among.
#[derive(Clone, Copy)]
enum Wanted<'a> {
    /// Every provider of the [`order`], the deployment's other OAuth providers among
    /// them.
    Every,
    /// Only these of the five, as workflows call for them.
    Only(&'a [ProviderArg]),
}

impl Wanted<'_> {
    fn wants(self, provider: &Ordered) -> bool {
        match (self, provider) {
            (Self::Every, _) => true,
            (Self::Only(wanted), Ordered::BuiltIn(provider)) => wanted.contains(provider),
            (Self::Only(_), Ordered::Served(_)) => false,
        }
    }
}

impl ProviderArg {
    const ALL: [Self; 5] = [
        Self::Github,
        Self::GitlabCom,
        Self::Linear,
        Self::ClaudeCode,
        Self::Codex,
    ];

    /// The provider whose wire name is `name`, when it is one of the five.
    pub(super) fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|provider| provider.grant().as_str() == name)
    }

    const fn grant(self) -> MemberGrantProvider {
        match self {
            Self::Github => MemberGrantProvider::GrantProviderGithub,
            Self::GitlabCom => MemberGrantProvider::GrantProviderGitlabCom,
            Self::Linear => MemberGrantProvider::GrantProviderLinear,
            Self::ClaudeCode => MemberGrantProvider::GrantProviderClaudeCode,
            Self::Codex => MemberGrantProvider::GrantProviderCodex,
        }
    }

    /// The consent of an OAuth provider; a coding agent has none.
    pub(super) const fn consent(self) -> Option<ConsentProvider<'static>> {
        match self {
            Self::Github => Some(ConsentProvider::GITHUB),
            Self::GitlabCom => Some(ConsentProvider::GITLAB_COM),
            Self::Linear => Some(ConsentProvider::LINEAR),
            Self::ClaudeCode | Self::Codex => None,
        }
    }

    pub(super) const fn native(self) -> bool {
        self.consent().is_none()
    }

    /// The provider whose grant a kind a workflow calls for names; `gitlab` is
    /// GitLab.com. A token service has none.
    const fn of_kind(kind: CredentialKind) -> Option<Self> {
        Some(match kind {
            CredentialKind::Github => Self::Github,
            CredentialKind::Gitlab => Self::GitlabCom,
            CredentialKind::Linear => Self::Linear,
            CredentialKind::ClaudeCode => Self::ClaudeCode,
            CredentialKind::Codex => Self::Codex,
            CredentialKind::Mergify | CredentialKind::Buildkite | CredentialKind::Cloudflare => {
                return None;
            }
        })
    }
}

/// How this invocation makes the grant of one of the five.
enum SignIn {
    /// The consent of `github`, `gitlab.com` or `linear`.
    Consent(ConsentProvider<'static>),
    /// A coding agent's login, imported for one organization.
    Native(ProviderArg, Login),
}

/// A coding agent's login: read from a file or stream the member names, before any network
/// use, or made by a sign-in `useful` runs in a directory it made once the command has settled
/// where the login is stored.
pub(super) enum Login {
    Read(Zeroizing<Vec<u8>>),
    /// `codex` with these arguments.
    Codex(&'static [&'static str]),
    /// `claude setup-token` on a terminal `useful` owns.
    ClaudeCode,
}

/// The providers one invocation signs in to, in [`order`]: the OAuth providers' consents, then
/// the coding agents', among them those the deployment does not serve, which are passed over,
/// and with `--workflow` the providers whose every held grant needs reconnecting, which are passed
/// over too.
struct Selection {
    /// The providers wanted, in [`order`].
    order: Vec<Ordered>,
    /// The OAuth providers consented to, by name.
    consents: Vec<String>,
    natives: Option<Natives>,
    /// The coding agents passed over without a sign-in because the deployment does not serve
    /// them.
    unavailable: Vec<ProviderArg>,
    /// The providers whose every held grant needs reconnecting, in [`order`].
    reconnects: Vec<Reconnect>,
    /// The coding agents the host of the runner [`Flow::runner`] names supplies, which get no
    /// step.
    host: Vec<ProviderArg>,
}

/// The coding agents a [`Selection`] takes, in [`order`].
enum Natives {
    /// Signed in to for the one organization their grants are for.
    For(Organization, Vec<ProviderArg>),
    /// Passed over, since no organization was resolved: the refusal that says why and names
    /// how to name one.
    Unresolved(String, Vec<ProviderArg>),
}

impl Natives {
    fn providers(&self) -> &[ProviderArg] {
        match self {
            Self::For(_, providers) | Self::Unresolved(_, providers) => providers,
        }
    }
}

/// A provider every grant of which the member holds needs reconnecting, and those grants' IDs,
/// which the summary names with `useful account integration reconnect`.
struct Reconnect {
    provider: ProviderArg,
    grants: Vec<String>,
}

impl Selection {
    const NONE: Self = Self {
        order: Vec::new(),
        consents: Vec::new(),
        natives: None,
        unavailable: Vec::new(),
        reconnects: Vec::new(),
        host: Vec::new(),
    };

    /// The step that signs in to or passes over `provider`, or none when it is held.
    fn step<'a>(&'a self, provider: &'a Ordered) -> Option<Step<'a>> {
        let provider = match provider {
            Ordered::BuiltIn(provider) => *provider,
            Ordered::Served(provider) => {
                return self
                    .consents
                    .contains(&provider.name)
                    .then(|| Step::Consent(provider.consent()));
            }
        };
        if let Some(reconnect) = self
            .reconnects
            .iter()
            .find(|reconnect| reconnect.provider == provider)
        {
            return Some(Step::Kept(provider, &reconnect.grants));
        }
        if let Some(consent) = provider.consent() {
            return self
                .consents
                .iter()
                .any(|selected| selected == consent.name)
                .then_some(Step::Consent(consent));
        }
        if self.unavailable.contains(&provider) {
            return Some(Step::Unavailable(provider));
        }
        let natives = self.natives.as_ref()?;
        natives
            .providers()
            .contains(&provider)
            .then(|| match natives {
                Natives::For(organization, _) => Step::Native(provider, organization),
                Natives::Unresolved(refusal, _) => Step::PassedOver(provider, refusal),
            })
    }

    /// What the plan says the run does about `provider`.
    fn planned(&self, provider: ProviderArg) -> workflow::State {
        if self.host.contains(&provider) {
            return workflow::State::Host;
        }
        match self.step(&Ordered::BuiltIn(provider)) {
            None => workflow::State::Held,
            Some(Step::Kept(..)) => workflow::State::Reconnect,
            Some(_) => workflow::State::SignIn,
        }
    }
}

/// One provider's sign-in in a [`Selection`].
#[derive(Clone, Copy)]
enum Step<'a> {
    Consent(ConsentProvider<'a>),
    Native(ProviderArg, &'a Organization),
    /// A coding agent passed over for want of an organization, with the refusal that says so.
    PassedOver(ProviderArg, &'a str),
    /// A coding agent passed over because the deployment does not serve it.
    Unavailable(ProviderArg),
    /// A provider whose grants, these, need reconnecting, passed over.
    Kept(ProviderArg, &'a [String]),
}

impl<'a> Step<'a> {
    const fn provider(self) -> &'a str {
        match self {
            Self::Consent(consent) => consent.name,
            Self::Native(provider, _)
            | Self::PassedOver(provider, _)
            | Self::Unavailable(provider)
            | Self::Kept(provider, _) => provider.grant().as_str(),
        }
    }
}

/// How one provider's sign-in ended, as the summary names it.
#[derive(Clone, Copy)]
enum Outcome {
    Created,
    /// A consent started under `--no-wait`.
    Started,
    /// The deployment does not serve the provider, which is passed over.
    Unavailable,
    /// A coding agent passed over because no organization was resolved for its grant.
    OrganizationRequired,
    /// A provider passed over because its grants need reconnecting.
    ReconnectRequired,
    Failed,
    /// A signal ended the command with this status.
    Stopped(ExitCode),
}

/// How an import ended, and the signal that stopped its sign-in when one did.
pub(super) struct Imported {
    pub(super) ended: Ended,
    stopped: Option<Stop>,
}

/// Where an import stores a coding agent's login.
#[derive(Clone, Copy)]
pub(super) enum Store<'a> {
    /// As a new grant of the provider for the organization.
    New(ProviderArg, &'a Organization),
    /// As the next generation of the member's grant, in its own organization.
    Next(&'a MemberGrant),
}

impl Store<'_> {
    /// The command line that imports a Codex `auth.json` where this stores a login, which a
    /// Codex sign-in that failed names in place of running it again: `create` refuses a held
    /// grant, so one `reconnect` started names `reconnect`.
    fn codex_import(self) -> String {
        match self {
            Self::New(..) => "useful account integration connect codex --from-file PATH".to_owned(),
            Self::Next(grant) => {
                format!(
                    "useful account integration reconnect {} --from-file PATH",
                    grant.id
                )
            }
        }
    }
}

impl Outcome {
    /// How a sign-in that `waits` for its grant ended.
    fn of(ended: &Ended, waits: bool) -> Self {
        match ended.code {
            ExitCode::Success if waits => Self::Created,
            ExitCode::Success => Self::Started,
            ExitCode::Interrupted | ExitCode::Terminated => Self::Stopped(ended.code),
            _ if ended.unavailable => Self::Unavailable,
            _ => Self::Failed,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Started => "started",
            Self::Unavailable => "provider_unavailable",
            Self::OrganizationRequired => output::ORGANIZATION_REQUIRED,
            Self::ReconnectRequired => output::RECONNECT_REQUIRED,
            Self::Failed => "failed",
            Self::Stopped(ExitCode::Terminated) => "terminated",
            Self::Stopped(_) => "interrupted",
        }
    }
}

/// The usage error, exit 2, of `option` given for `name`, which does not take it, with `remedy`.
fn unsuited(option: &str, name: &str, remedy: &str) -> CommandFailure {
    CommandFailure::with_exit_code(
        anyhow!("{option} does not apply to {name}\n\n{remedy}"),
        ExitCode::UsageError,
    )
}

/// The refusal of `name`, which the deployment serves as neither an OAuth provider nor a token
/// service, exit 2, naming the providers `served` lists, the built-in ones first, then the
/// coding agents, then `token_services`.
fn not_served(
    name: &str,
    served: &[ServedGrantProvider],
    token_services: &[ServedTokenService],
) -> CommandFailure {
    let mut given: Vec<_> = projection::providers(served)
        .into_iter()
        .map(Provider::name)
        .chain(token_services.iter().map(|service| service.name.as_str()))
        .collect();
    let last = given.pop().unwrap_or_default();
    CommandFailure::with_exit_code(
        anyhow!(
            "this deployment does not serve {name} as an OAuth provider or a token service\n\n\
             Name {} or {last} instead:\n  useful account integration connect PROVIDER",
            given.join(", ")
        ),
        ExitCode::UsageError,
    )
}

/// The first of `options` that was given.
pub(super) fn first_given<const N: usize>(
    options: [(bool, &'static str); N],
) -> Option<&'static str> {
    options
        .into_iter()
        .find_map(|(given, option)| given.then_some(option))
}

/// The exit status of several sign-ins: a signal's when one stopped them, 1 when any failed or
/// when every one was passed over, as unavailable, for want of an organization or as needing
/// reconnecting, and otherwise 0, as when there were none.
fn summary_code(outcomes: impl Iterator<Item = Outcome> + Clone) -> ExitCode {
    if let Some(code) = outcomes.clone().find_map(|outcome| match outcome {
        Outcome::Stopped(code) => Some(code),
        _ => None,
    }) {
        return code;
    }
    let mut made = false;
    let mut passed_over = false;
    for outcome in outcomes {
        match outcome {
            Outcome::Failed => return ExitCode::GeneralFailure,
            Outcome::Unavailable | Outcome::OrganizationRequired | Outcome::ReconnectRequired => {
                passed_over = true
            }
            _ => made = true,
        }
    }
    if passed_over && !made {
        ExitCode::GeneralFailure
    } else {
        ExitCode::Success
    }
}

/// Whether the host of the runner `runner_id` supplies the coding agent `provider` itself: an
/// unrevoked grant of it among `grants` has an authorization in force for that runner on which the
/// runner last reported `foreign_login`, its host's own sign-in, which it uses in place of the
/// grant. Cloud serves a runner's report there alone, so nothing else is read for it.
fn supplied_on(grants: &[MemberGrant], provider: ProviderArg, runner_id: &str) -> bool {
    grants
        .iter()
        .filter(|grant| replacement::holds(grant, provider.grant().as_str(), None))
        .any(|grant| {
            projection::grant_runners(grant)
                .get(runner_id)
                .and_then(|runner| runner.report)
                .is_some_and(|report| {
                    report.state == AgentLoginReportState::AgentLoginReportStateForeignLogin
                })
        })
}

/// Whether the host of the runner `runner_id` supplies the coding agent `kind` names itself, as
/// [`supplied_on`] reads it, for `useful workflow doctor --runner`.
pub(in crate::cli) fn host_supplies(
    grants: &[MemberGrant],
    kind: CredentialKind,
    runner_id: &str,
) -> bool {
    ProviderArg::of_kind(kind).is_some_and(|provider| supplied_on(grants, provider, runner_id))
}

impl Command {
    /// With `PROVIDER`, checks which options suit it before anything is run, read or sent, then
    /// makes its grant: by the provider's consent, for a provider outside the five once the
    /// deployment is found to serve it, or by importing a coding agent's login. With `--all`,
    /// makes a grant of each provider the member lacks, and with `--workflow` of each the
    /// workflows call for. The organization `--org` or `USEFUL_ORG` names is read before any
    /// request, except for an OAuth `PROVIDER`, whose grant is the member's alone.
    pub(super) fn run(self, deployment: &Deployment) -> super::super::super::CommandResult {
        let Some(provider) = &self.provider else {
            let named = self.org.named_in_process()?;
            let flow = self.flow(named.as_ref());
            if !self.all {
                return self.run_workflows(deployment, &flow);
            }
            let scope = output::Scope::Every;
            return match flow.select(deployment, Wanted::Every, scope, false)? {
                Ok(selection) => flow.run_selection(deployment, selection, scope),
                Err(refused) => Ok(refused),
            };
        };
        let provider = match provider {
            ProviderName::BuiltIn(provider) => *provider,
            ProviderName::Other(name) => return self.connect_served(deployment, name),
        };
        match self.sign_in(provider)? {
            SignIn::Consent(consent) => self.flow(None).consent_unheld(deployment, consent),
            SignIn::Native(provider, login) => {
                let named = self.org.named_in_process()?;
                let flow = self.flow(named.as_ref());
                // A Claude Code sign-in the member could not answer is refused before the first
                // request.
                if matches!(login, Login::ClaudeCode)
                    && let Some(failure) = claude_setup_token::unanswerable()
                {
                    return Ok(output::write_import_refusal(
                        deployment.fingerprint().api_url(),
                        &failure.report(),
                        self.options.json,
                    )?);
                }
                let signs_in = !matches!(login, Login::Read(_));
                let organization = match flow.settle(deployment, provider, signs_in)? {
                    Ok(organization) => organization,
                    Err(refused) => return Ok(refused),
                };
                flow.import(deployment, login, Store::New(provider, &organization))
                    .map(|imported| imported.ended.code)
            }
        }
    }

    /// What the flow reads of this invocation's options, with the organization `named` by
    /// `--org` or `USEFUL_ORG`, when one was.
    fn flow<'a>(&'a self, named: Option<&'a InEffect>) -> Flow<'a> {
        Flow {
            json: self.options.json,
            allow_insecure_http: self.options.http.allow_insecure_http,
            organization: named.map(|named| named.organization.as_str()),
            device: self.device,
            no_wait: self.no_wait,
            timeout: self.wait.timeout,
            runner: None,
        }
    }

    /// The sign-in the provider and options name; a file or stream is read here, so that an
    /// insecurely held or malformed one is refused with exit 2 before any network use, as is an
    /// option that does not suit the provider: a source of another provider, or for a coding
    /// agent, whose sign-in has no consent, `--no-wait` or `--timeout`.
    fn sign_in(&self, provider: ProviderArg) -> Result<SignIn, CommandFailure> {
        let name = provider.grant().as_str();
        let unsuited = |option: &str, remedy: &str| unsuited(option, name, remedy);
        if provider.native()
            && let Some(option) = first_given([
                (self.no_wait, "--no-wait"),
                (self.wait.timeout.is_some(), "--timeout"),
            ])
        {
            return Err(unsuited(
                option,
                &format!(
                    "A {name} grant is made by the coding agent's own sign-in, which has no \
                     consent to wait for:\n  useful account integration connect {name}"
                ),
            ));
        }
        let consent = match provider {
            ProviderArg::Github => ConsentProvider::GITHUB,
            ProviderArg::GitlabCom => ConsentProvider::GITLAB_COM,
            ProviderArg::Linear => ConsentProvider::LINEAR,
            ProviderArg::Codex => {
                if self.token_file.is_some() {
                    return Err(unsuited(
                        "--token-file",
                        "Import a Codex auth.json with --from-file PATH, or sign in with --login or --device.",
                    ));
                }
                return Ok(SignIn::Native(
                    ProviderArg::Codex,
                    match &self.from_file {
                        Some(path) => Login::Read(
                            material::read_codex_login(path, FileMode::Private).map_err(
                                |error| CommandFailure::with_exit_code(error, ExitCode::UsageError),
                            )?,
                        ),
                        None => self.flow(None).codex_sign_in(),
                    },
                ));
            }
            ProviderArg::ClaudeCode => {
                if let Some(option) = first_given([
                    (self.from_file.is_some(), "--from-file"),
                    (self.login, "--login"),
                    (self.device, "--device"),
                ]) {
                    return Err(unsuited(
                        option,
                        "Run Claude Code's sign-in, or import the token claude setup-token \
                         printed with --token-file PATH:\n  useful account integration connect claude_code",
                    ));
                }
                return Ok(SignIn::Native(
                    ProviderArg::ClaudeCode,
                    match &self.token_file {
                        Some(path) => Login::Read(material::read_claude_code_token(path).map_err(
                            |error| CommandFailure::with_exit_code(error, ExitCode::UsageError),
                        )?),
                        None => Login::ClaudeCode,
                    },
                ));
            }
        };
        self.refuse_unsuited_to_consent(name)?;
        Ok(SignIn::Consent(consent))
    }

    /// Refuses with exit 2 an option an OAuth provider's consent, `name`'s, does not take: a
    /// source of a coding agent's login, and `--org`, since the grant is the member's alone.
    fn refuse_unsuited_to_consent(&self, name: &str) -> Result<(), CommandFailure> {
        match first_given([
            (self.org.given(), "--org"),
            (self.login, "--login"),
            (self.device, "--device"),
            (self.from_file.is_some(), "--from-file"),
            (self.token_file.is_some(), "--token-file"),
        ]) {
            Some(option) => Err(unsuited(
                option,
                name,
                &format!(
                    "A {name} grant is made by the provider's consent and is yours alone:\n  \
                     useful account integration connect {name}"
                ),
            )),
            None => Ok(()),
        }
    }

    /// Connects `name`, a provider id outside the five, once one read of what the deployment
    /// serves says what it is: a token service's token, once the options of a sign-in are
    /// refused; or an OAuth provider's consent. Any other name, on a deployment that predates
    /// the read included, is refused with exit 2, naming the providers and token services that
    /// can be given, before anything is read from a file, standard input or the terminal.
    fn connect_served(
        &self,
        deployment: &Deployment,
        name: &str,
    ) -> super::super::super::CommandResult {
        let flow = self.flow(None);
        let (served, token_services) =
            match flow.with_api(deployment, MemberGrantApi::served_integrations)? {
                Ok(served) => served
                    .map(|served| (served.providers, served.token_services))
                    .unwrap_or_default(),
                Err(failure) => return flow.write_read_refusal(deployment, &failure),
            };
        if let Some(service) = token_services.iter().find(|service| service.name == name) {
            return self.connect_token(deployment, service);
        }
        let Some(provider) = served_oauth(&served, name) else {
            return Err(not_served(name, &served, &token_services));
        };
        self.refuse_unsuited_to_consent(name)?;
        flow.consent_unheld(deployment, provider.consent())
    }

    /// Connects the member's token of `service`, once the options of a sign-in are refused
    /// with exit 2: reads the member's tokens, refuses with exit 2 naming `reconnect` where
    /// one of the service is held, before any token is read, and otherwise reads the token
    /// and stores it.
    fn connect_token(
        &self,
        deployment: &Deployment,
        service: &ServedTokenService,
    ) -> super::super::super::CommandResult {
        let name = service.name.as_str();
        if let Some(option) = first_given([
            (self.login, "--login"),
            (self.device, "--device"),
            (self.token_file.is_some(), "--token-file"),
            (self.no_wait, "--no-wait"),
            (self.wait.timeout.is_some(), "--timeout"),
            (self.org.given(), "--org"),
        ]) {
            return Err(unsuited(
                option,
                name,
                &format!(
                    "A {name} token is yours, read from --from-file PATH, from standard input or \
                     at a prompt:\n  useful account integration connect {name}"
                ),
            ));
        }
        let api_url = deployment.fingerprint().api_url();
        integration_token::Store {
            deployment,
            policy: self.options.http.transport_policy(),
            json: self.options.json,
            owner: IntegrationTokenOwner::Member,
            slug: None,
            service,
            from_file: self.from_file.as_deref(),
        }
        .connect(
            |failure| output::token_report(api_url, failure, name),
            |held| {
                CommandFailure::with_exit_code(
                    anyhow!(
                        "you already hold a {name} token: {}\n\nStore a new token as its next \
                         version, which keeps its ID and the runners it is authorized for:\n  \
                         useful account integration reconnect {name}",
                        held.id
                    ),
                    ExitCode::UsageError,
                )
            },
        )
    }

    /// Signs in to what the `--workflow` files call for through the flow over their derivation.
    /// The files are derived before any request, so a file that does not resolve, or one in no
    /// Git repository without `--source-root`, ends the command before any sign-in. The runner
    /// `--runner` names is resolved next, before the plan: an ID as given, a name among the
    /// runners of every organization the member is an active member of, its refusals printed as
    /// the summary event that ends the stream.
    fn run_workflows(
        &self,
        deployment: &Deployment,
        flow: &Flow<'_>,
    ) -> super::super::super::CommandResult {
        let roots = Roots::find(
            &self.workflows,
            self.source_root.as_deref(),
            "useful account integration connect --workflow FILE --source-root ROOT",
        )?;
        let Some(derived) = roots.derive(&roots.origin_remote(), self.options.json)? else {
            return Ok(ExitCode::GeneralFailure);
        };
        let runner = match &self.runner {
            Some(runner) => match runner_choice::resolve(
                deployment,
                self.options.json,
                output::Family::Events,
                runner,
                None,
                || {
                    runner_choice::in_active_organizations(
                        deployment,
                        self.options.http.transport_policy(),
                    )
                },
                |id| format!("useful account integration connect --workflow FILE --runner {id}"),
            )? {
                Ok(acting) => Some(acting.id),
                Err(code) => return Ok(code),
            },
            None => None,
        };
        let flow = Flow {
            runner: runner.as_deref(),
            ..*flow
        };
        // The sign-ins select by the inference, not by a declared block.
        flow.run_workflows(deployment, &derived.inferred, output::Scope::Workflows)
    }
}

impl Flow<'_> {
    /// Codex's own sign-in: by device code with `--device` or where this machine has no
    /// browser, and otherwise in this machine's browser.
    pub(super) fn codex_sign_in(&self) -> Login {
        if self.device || !browser::available(|name| std::env::var_os(name)) {
            Login::Codex(codex_login::DEVICE)
        } else {
            Login::Codex(codex_login::BROWSER)
        }
    }

    /// The flow over a derivation of workflow files, which `useful account integration connect
    /// --workflow` runs and nothing else does: signs in to the providers the files call for that
    /// the member lacks, and passes over those whose every held grant needs reconnecting, which it
    /// never signs in to, and with [`Flow::runner`] each coding agent that runner's host supplies.
    /// It asks nothing. A tree that calls for no provider is not taken to Cloud. The plan is
    /// printed once the grants are read and before any sign-in; then the selection runs as without
    /// `--workflow`, its summary naming the command of `scope` to run again. Returns its status.
    pub(in crate::cli) fn run_workflows(
        &self,
        deployment: &Deployment,
        credentials: &WorkflowCredentials,
        scope: output::Scope,
    ) -> Result<ExitCode, CommandFailure> {
        let wanted: Vec<_> = credentials
            .requirements
            .iter()
            .filter_map(|requirement| ProviderArg::of_kind(requirement.kind))
            .collect();
        let selection = if wanted.is_empty() {
            Selection::NONE
        } else {
            match self.select(deployment, Wanted::Only(&wanted), scope, true)? {
                Ok(selection) => selection,
                Err(code) => return Ok(code),
            }
        };
        let planned: Vec<_> = credentials
            .requirements
            .iter()
            .filter_map(|requirement| {
                let provider = ProviderArg::of_kind(requirement.kind)?;
                Some(workflow::Planned {
                    provider: provider.grant().as_str(),
                    state: selection.planned(provider),
                    requirement,
                })
            })
            .collect();
        workflow::write_plan(
            deployment.fingerprint().api_url(),
            credentials,
            &planned,
            self.json,
        )?;
        self.run_selection(deployment, selection, scope)
    }

    /// Selects, among `wanted` and in [`order`], the providers the member lacks: those it holds no
    /// grant of that is `active` or `reconnect_required`, for a native provider in the organization
    /// a new grant would be for. The member's grants of both kinds are read once. With every
    /// provider wanted, the providers the deployment serves are read next, every time, and each
    /// other OAuth provider among them is wanted after the built-in ones; with only some of the
    /// five wanted, they are read next only where a coding agent might be signed in to. A coding
    /// agent the deployment does not serve is selected to be passed over without a sign-in; a
    /// deployment that predates that read is taken to serve each one and no other OAuth provider.
    /// The organization in effect is resolved once, and only for the native providers it serves,
    /// when [`Flow::organization`] names it or one of those in `wanted` is held in no organization,
    /// so a member who holds every provider wanted is asked for nothing more and no `git` runs.
    /// When neither the checkout nor an only active membership names one, each native provider held
    /// in no organization is selected to be passed over with the refusal, which names the command
    /// of `scope` with an organization, and the consents are selected as ever. With `reconnect`, a
    /// provider held, a coding agent in that organization when one was resolved and in any
    /// otherwise, every grant of which so held needs reconnecting is selected to be passed over, a
    /// coding agent the deployment serves only, with the IDs of those grants. With
    /// [`Flow::runner`], a coding agent wanted that the runner's host supplies ([`supplied_on`]) is
    /// set apart before all of this, as if not wanted: no organization or served provider is read
    /// for it. The inner error is the exit status of a reported failure.
    fn select(
        &self,
        deployment: &Deployment,
        wanted: Wanted<'_>,
        scope: output::Scope,
        reconnect: bool,
    ) -> Result<Result<Selection, ExitCode>, CommandFailure> {
        let natives: Vec<_> = order(&[])
            .iter()
            .filter(|provider| wanted.wants(provider))
            .filter_map(Ordered::built_in)
            .filter(|provider| provider.native())
            .collect();
        let api_url = deployment.fingerprint().api_url();
        let refused = |failure: MemberGrantFailure| {
            output::write_create_refusal(api_url, &output::report(api_url, &failure), self.json)
                .map(Err)
                .map_err(CommandFailure::from)
        };
        let read = self.with_api(deployment, |api| {
            let grants = super::every_grant(api)?;
            // With every provider wanted, what the deployment serves names the other OAuth
            // providers too, so it is read every time, right after the grants.
            let every = match wanted {
                Wanted::Every => Some(api.served_providers()?),
                Wanted::Only(_) => None,
            };
            Ok((grants, every))
        })?;
        let (grants, every) = match read {
            Ok(read) => read,
            Err(failure) => return refused(failure),
        };
        let (host, natives): (Vec<_>, Vec<_>) = natives.into_iter().partition(|provider| {
            self.runner
                .is_some_and(|runner| supplied_on(&grants, *provider, runner))
        });
        let held_by_name = |name: &str, organization_id: Option<&str>| {
            grants
                .iter()
                .filter(|grant| replacement::holds(grant, name, organization_id))
                .collect::<Vec<_>>()
        };
        let held_of = |provider: ProviderArg, organization_id: Option<&str>| {
            held_by_name(provider.grant().as_str(), organization_id)
        };
        let held = |provider: ProviderArg, organization_id: Option<&str>| {
            !held_of(provider, organization_id).is_empty()
        };
        let reconnects = |provider: ProviderArg, organization_id: Option<&str>| {
            reconnect && {
                let held = held_of(provider, organization_id);
                !held.is_empty()
                    && held
                        .iter()
                        .all(|grant| replacement::needs_reconnecting(grant))
            }
        };
        let unheld: Vec<_> = natives
            .iter()
            .copied()
            .filter(|provider| !held(*provider, None))
            .collect();
        let signs_in = |natives: &[ProviderArg], unheld: &[ProviderArg]| {
            !natives.is_empty() && (self.organization.is_some() || !unheld.is_empty())
        };
        let served = match every {
            Some(served) => served,
            None if signs_in(&natives, &unheld)
                || natives.iter().any(|provider| reconnects(*provider, None)) =>
            {
                match self.with_api(deployment, MemberGrantApi::served_providers)? {
                    Ok(served) => served,
                    Err(failure) => return refused(failure),
                }
            }
            None => None,
        };
        let ordered: Vec<_> = order(served.as_deref().unwrap_or_default())
            .into_iter()
            .filter(|provider| wanted.wants(provider))
            .collect();
        let serves = |provider: &ProviderArg| {
            served.as_ref().is_none_or(|served| {
                served
                    .iter()
                    .any(|served| served.name == provider.grant().as_str())
            })
        };
        let (natives, unserved): (Vec<_>, Vec<_>) = natives.iter().copied().partition(serves);
        let unheld: Vec<_> = unheld.into_iter().filter(serves).collect();
        let mut resolved = None;
        let selected_natives = if signs_in(&natives, &unheld) {
            match self.resolve_organization(deployment)? {
                Ok(Ok(organization)) => {
                    resolved = Some(organization.id.clone());
                    let lacked = natives
                        .iter()
                        .copied()
                        .filter(|provider| !held(*provider, Some(&organization.id)))
                        .collect::<Vec<_>>();
                    (!lacked.is_empty()).then_some(Natives::For(organization, lacked))
                }
                Ok(Err(organizations)) => Some(Natives::Unresolved(
                    context::unresolved_message(&organizations, Some(scope.organization())),
                    unheld,
                )),
                Err(failure) => return refused(failure),
            }
        } else {
            None
        };
        let organization_id = resolved.as_deref();
        let unavailable = unserved
            .into_iter()
            .filter(|provider| !held(*provider, organization_id))
            .collect();
        let consents = ordered
            .iter()
            .filter_map(Ordered::consent)
            .filter(|consent| held_by_name(consent.name, None).is_empty())
            .map(|consent| consent.name.to_owned())
            .collect();
        let selected = ordered
            .iter()
            .filter_map(Ordered::built_in)
            .filter_map(|provider| {
                let organization_id = match provider.consent() {
                    Some(_) => None,
                    None if natives.contains(&provider) => organization_id,
                    None => return None,
                };
                reconnects(provider, organization_id).then(|| Reconnect {
                    provider,
                    grants: held_of(provider, organization_id)
                        .into_iter()
                        .map(|grant| grant.id.clone())
                        .collect(),
                })
            })
            .collect();
        Ok(Ok(Selection {
            order: ordered,
            consents,
            natives: selected_natives,
            unavailable,
            reconnects: selected,
            host,
        }))
    }

    /// Runs the sign-in of each selected provider in turn, naming the provider on standard error
    /// before its prompts, then prints one outcome per provider. A held provider is never selected,
    /// and one whose grants need reconnecting is passed over as `reconnect_required`, the summary
    /// naming `useful account integration reconnect` with each of those grants' IDs. A sign-in that
    /// fails does not stop the ones after it; a signal does, whether `useful` received it or it
    /// ended a coding agent's sign-in on its own terminal. A coding agent the deployment does not
    /// serve, or one no organization was resolved for, is reported and passed over without a
    /// sign-in. Exits 0 when each provider ended with a grant or was passed over, as unavailable,
    /// for want of an organization or as needing reconnecting, and at least one grant was made or
    /// none was to be, 1 when any sign-in failed or nothing was made, and the signal's status when
    /// one stopped the command.
    fn run_selection(
        &self,
        deployment: &Deployment,
        selection: Selection,
        scope: output::Scope,
    ) -> super::super::super::CommandResult {
        let mut outcomes = Vec::new();
        let mut reconnect: Vec<&str> = Vec::new();
        for step in selection
            .order
            .iter()
            .filter_map(|provider| selection.step(provider))
        {
            let name = step.provider();
            if !matches!(step, Step::Kept(..)) {
                let after = outcomes
                    .iter()
                    .any(|(_, outcome)| !matches!(outcome, Outcome::ReconnectRequired));
                output::write_provider_heading(name, after, self.json)?;
            }
            let outcome = match step {
                Step::Consent(consent) => {
                    Outcome::of(&self.consent(deployment, consent)?, !self.no_wait)
                }
                Step::Native(provider, organization) => {
                    self.sign_in_native(deployment, provider, organization)?
                }
                Step::PassedOver(_, refusal) => {
                    output::write_organization_required(
                        deployment.fingerprint().api_url(),
                        refusal,
                        self.json,
                    )?;
                    Outcome::OrganizationRequired
                }
                Step::Unavailable(_) => {
                    let api_url = deployment.fingerprint().api_url();
                    output::write_import_refusal(
                        api_url,
                        &output::report(api_url, &MemberGrantFailure::ProviderUnavailable),
                        self.json,
                    )?;
                    Outcome::Unavailable
                }
                Step::Kept(_, grants) => {
                    reconnect.extend(grants.iter().map(String::as_str));
                    Outcome::ReconnectRequired
                }
            };
            outcomes.push((name, outcome));
            if matches!(outcome, Outcome::Stopped(_)) {
                break;
            }
        }
        let code = summary_code(outcomes.iter().map(|(_, outcome)| *outcome));
        let named: Vec<_> = outcomes
            .iter()
            .map(|(provider, outcome)| (*provider, outcome.name()))
            .collect();
        output::write_create_summary(
            deployment.fingerprint().api_url(),
            &named,
            &reconnect,
            code,
            scope,
            self.json,
        )?;
        Ok(code)
    }

    /// Runs a coding agent's own sign-in in a selection and imports its login for
    /// `organization`.
    fn sign_in_native(
        &self,
        deployment: &Deployment,
        provider: ProviderArg,
        organization: &Organization,
    ) -> Result<Outcome, CommandFailure> {
        let imported = self.import(
            deployment,
            self.sign_in_of(provider),
            Store::New(provider, organization),
        )?;
        Ok(match imported.stopped {
            Some(stop) => Outcome::Stopped(stop.exit_code()),
            None => Outcome::of(&imported.ended, true),
        })
    }

    /// The coding agent's own sign-in, as no source option names another.
    pub(super) fn sign_in_of(&self, provider: ProviderArg) -> Login {
        match provider {
            ProviderArg::Codex => self.codex_sign_in(),
            _ => Login::ClaudeCode,
        }
    }

    /// Runs the consent once the member's grants of the provider are read in the member's
    /// session and none is held: `create` never replaces one, and refuses, naming `useful
    /// account integration reconnect` for each.
    fn consent_unheld(
        &self,
        deployment: &Deployment,
        consent: ConsentProvider<'_>,
    ) -> super::super::super::CommandResult {
        let read = self.with_api(deployment, |api| {
            replacement::held(api, consent.name, MemberGrantKind::GrantKindOAuth, None)
        })?;
        let held = match read {
            Ok(held) => held,
            Err(failure) => return self.write_read_refusal(deployment, &failure),
        };
        replacement::refuse_held(consent.name, &held)?;
        self.consent(deployment, consent).map(|ended| ended.code)
    }

    /// The title of `name`, an OAuth provider with no built-in name: the display name the
    /// deployment serves for it, read first, and otherwise its id. A failed read is reported as
    /// the consent's result, and its exit status is the inner error.
    pub(super) fn served_title(
        &self,
        deployment: &Deployment,
        name: &str,
    ) -> Result<Result<String, ExitCode>, CommandFailure> {
        match self.with_api(deployment, MemberGrantApi::served_providers)? {
            Ok(served) => Ok(Ok(served_oauth(&served.unwrap_or_default(), name)
                .map_or_else(|| name.to_owned(), |provider| provider.title))),
            Err(failure) => self.write_read_refusal(deployment, &failure).map(Err),
        }
    }

    /// Reports a read that failed before a consent began, as the consent's result.
    fn write_read_refusal(
        &self,
        deployment: &Deployment,
        failure: &MemberGrantFailure,
    ) -> super::super::super::CommandResult {
        let api_url = deployment.fingerprint().api_url();
        write_refusal(api_url, None, &output::report(api_url, failure), self.json)
            .map_err(Into::into)
    }

    /// Runs the consent with no identity named, opening its URL when this machine has a
    /// browser.
    pub(super) fn consent(
        &self,
        deployment: &Deployment,
        consent: ConsentProvider<'_>,
    ) -> Result<Ended, CommandFailure> {
        Consent {
            provider: consent,
            open: browser::available(|name| std::env::var_os(name)),
            no_wait: self.no_wait,
            timeout: self.timeout,
            options: Options::new(
                self.json,
                NoAuthenticationArgs::default(),
                HttpOptions {
                    allow_insecure_http: self.allow_insecure_http,
                },
            ),
        }
        .run_to_end(deployment)
    }

    /// Imports a coding agent's login where `store` says: as a new grant for an organization,
    /// or as the next generation of the member's grant. The session, and the organization or
    /// the grant, are settled before this is called, so a refusal leaves no provider session
    /// behind. A sign-in a signal ended is reported as one that failed, with the signal's stop
    /// besides.
    pub(super) fn import(
        &self,
        deployment: &Deployment,
        login: Login,
        store: Store<'_>,
    ) -> Result<Imported, CommandFailure> {
        let api_url = deployment.fingerprint().api_url();
        let json = self.json;
        let ended = |code| Imported {
            ended: Ended {
                code,
                unavailable: false,
                grant: None,
            },
            stopped: None,
        };
        let signed_in = match login {
            Login::Read(material) => Ok(material),
            Login::Codex(arguments) => codex_login::sign_in(arguments, material::read_codex_login)?
                .map_err(|failure| (failure.report(&store.codex_import()), failure.stop())),
            Login::ClaudeCode => {
                claude_setup_token::sign_in()?.map_err(|failure| (failure.report(), failure.stop()))
            }
        };
        let material = match signed_in {
            Ok(material) => material,
            Err((report, stopped)) => {
                return Ok(Imported {
                    stopped,
                    ..ended(output::write_import_refusal(api_url, &report, json)?)
                });
            }
        };
        let key =
            useful_support::generate_idempotency_key().context("generate grant request key")?;
        let stored = self.with_api(deployment, |api| {
            replayed(|| match store {
                Store::Next(grant) => api.replace(&grant.id, &material, &key),
                Store::New(provider, organization) => {
                    api.import(&organization.id, provider.grant(), &material, &key)
                }
            })
        })?;
        let (slug, replaced) = match store {
            Store::New(_, organization) => (organization.slug.as_deref(), false),
            Store::Next(_) => (None, true),
        };
        match stored {
            Ok(grant) => Ok(ended(output::write_imported(
                api_url, &grant, slug, replaced, json,
            )?)),
            Err(failure) => Ok(Imported {
                ended: Ended {
                    code: output::write_import_refusal(
                        api_url,
                        &output::report(api_url, &failure),
                        json,
                    )?,
                    unavailable: matches!(failure, MemberGrantFailure::ProviderUnavailable),
                    grant: None,
                },
                stopped: None,
            }),
        }
    }

    /// Establishes the session, resolves the organization in effect and reads the grants of the
    /// provider held there, returning the exit status of a reported refusal instead; when no
    /// source names an organization it refuses with exit 2, naming `--org` and the member's
    /// organizations. Before a sign-in, `signs_in`, the providers the deployment serves are read
    /// first, and one it does not serve is refused as unavailable before anything else is asked
    /// or run; a deployment that predates that read is taken to serve it. A grant held there is
    /// refused, naming `useful account integration reconnect` for each: `create` never replaces
    /// one.
    fn settle(
        &self,
        deployment: &Deployment,
        provider: ProviderArg,
        signs_in: bool,
    ) -> Result<Result<Organization, ExitCode>, CommandFailure> {
        let provider = provider.grant();
        let name = provider.as_str();
        let api_url = deployment.fingerprint().api_url();
        let refused = |failure: MemberGrantFailure| {
            output::write_import_refusal(api_url, &output::report(api_url, &failure), self.json)
                .map(Err)
                .map_err(CommandFailure::from)
        };
        if signs_in
            && let Err(failure) = self.with_api(deployment, |api| Self::check_served(api, name))?
        {
            return refused(failure);
        }
        let organization = match self.resolve_organization(deployment)? {
            Ok(Ok(organization)) => organization,
            Ok(Err(organizations)) => return Err(context::unresolved(&organizations)),
            Err(failure) => return refused(failure),
        };
        let held = self.with_api(deployment, |api| {
            replacement::held(api, name, provider.kind(), Some(&organization.id))
        })?;
        match held {
            Ok(held) => {
                replacement::refuse_held(name, &held)?;
                Ok(Ok(organization))
            }
            Err(failure) => refused(failure),
        }
    }

    /// The organization in effect a coding agent's grant is for: the one
    /// [`Flow::organization`] names, or else the one the checkout or the member's only active
    /// membership names, or else the member's active organizations, none or several.
    fn resolve_organization(
        &self,
        deployment: &Deployment,
    ) -> anyhow::Result<Result<Result<Organization, Vec<Organization>>, MemberGrantFailure>> {
        organization::resolve(
            deployment,
            HttpOptions {
                allow_insecure_http: self.allow_insecure_http,
            },
            self.organization,
        )
    }

    /// Refuses as unavailable a coding agent, by its wire name `name`, that the providers the
    /// deployment serves do not name, before its sign-in runs; a deployment that predates
    /// that read is taken to serve it.
    pub(super) fn check_served(api: &MemberGrantApi, name: &str) -> Result<(), MemberGrantFailure> {
        if api
            .served_providers()?
            .is_some_and(|served| !served.iter().any(|served| served.name == name))
        {
            return Err(MemberGrantFailure::ProviderUnavailable);
        }
        Ok(())
    }

    /// Runs `f` against the grants resource with the signed-in human session, refreshing a
    /// rejected session once.
    pub(super) fn with_api<T>(
        &self,
        deployment: &Deployment,
        f: impl FnMut(&MemberGrantApi) -> Result<T, MemberGrantFailure>,
    ) -> anyhow::Result<Result<T, MemberGrantFailure>> {
        let http = HttpOptions {
            allow_insecure_http: self.allow_insecure_http,
        };
        super::super::super::with_human_session_api(deployment, http.transport_policy(), f)
    }
}
