//! `useful account integration`: what Useful Machinery may do as the member at other providers, a
//! grant of either kind over the grants resource, and the member's token of a token service,
//! which a leaf reaches through `integration_token`. The resources admit only active humans, so
//! every leaf takes a human session only.

mod accounts;
pub(in crate::cli) mod authorization;
pub(in crate::cli) mod authorize;
pub(in crate::cli) mod browser;
mod claude_setup_token;
pub(super) mod codex_login;
pub(in crate::cli) mod confirmation;
pub(super) mod consent;
pub(crate) mod controlling_terminal;
mod create;
pub(in crate::cli) mod deauthorize;
mod list;
pub(super) mod material;
mod organization;
pub(in crate::cli) mod output;
mod program;
pub(in crate::cli) mod projection;
mod reconnect;
mod replacement;
pub(super) mod revoke;
pub(in crate::cli) mod runner_choice;
mod show;

use std::collections::BTreeSet;

use clap::{Args, Subcommand};

use super::super::integration_token;
use crate::exit_code::ExitCode;
use useful_api::{
    GrantApi, GrantFailure, IntegrationToken, IntegrationTokenOwner, IntegrationTokenSide,
    MEMBER_GRANT_PAGE, MemberGrant, MemberGrantApi, MemberGrantFailure, MemberGrantKind,
    MemberGrantProvider, MemberGrantState,
};
use useful_human_auth::Deployment;

use authorization::Holder;
use confirmation::Stated;

pub(in crate::cli) use create::host_supplies;

pub(super) const ABOUT: &str = "Manage what Useful Machinery may do as you at other providers";

/// Acting as the GitHub App, which an owner of the organization chooses with a connection
/// authorization: the other choice the consent's report, the plan of `connect --workflow` and the
/// `connect` and `reconnect` steps of `github` name wherever the member's own GitHub sign-in is
/// missing, failed or cannot be made. Nothing takes it for the member.
const ACT_AS_GITHUB_APP: &str =
    "useful org integration authorize github --runner RUNNER --project PROJECT --runs all";

/// [`ACT_AS_GITHUB_APP`] where `provider` is `github`, and nothing for any other provider.
fn github_app_alternative(provider: &str) -> Option<&'static str> {
    (provider == "github").then_some(ACT_AS_GITHUB_APP)
}

// The grants resource admits only active humans, so these leaves take no service API key.
type Options =
    super::super::CommonArgs<super::super::GrantJson, super::super::NoAuthenticationArgs>;

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<GrantCommand>,
}

#[derive(Debug, Subcommand)]
enum GrantCommand {
    #[command(about = authorize::ABOUT)]
    Authorize(authorize::Command),
    #[command(about = create::ABOUT)]
    Connect(create::Command),
    #[command(about = deauthorize::ABOUT)]
    Deauthorize(deauthorize::Command),
    #[command(about = revoke::ABOUT)]
    Disconnect(revoke::Command),
    #[command(about = list::ABOUT)]
    List(list::Command),
    #[command(about = reconnect::ABOUT)]
    Reconnect(reconnect::Command),
    #[command(about = show::ABOUT)]
    Show(show::Command),
}

impl Command {
    pub(super) fn execute(self) -> super::super::CommandResult {
        super::super::execute_deployment_command(
            self.command,
            &["account", "integration"],
            "configure Useful Machinery grant access",
            |command, deployment| match command {
                GrantCommand::Authorize(command) => command.run(deployment).map_err(Into::into),
                GrantCommand::Connect(command) => command.run(deployment),
                GrantCommand::Deauthorize(command) => command.run(deployment).map_err(Into::into),
                GrantCommand::List(command) => command.run(deployment).map_err(Into::into),
                GrantCommand::Reconnect(command) => command.run(deployment),
                GrantCommand::Disconnect(command) => command.run(deployment).map_err(Into::into),
                GrantCommand::Show(command) => command.run(deployment),
            },
        )
    }
}

impl super::super::HumanSessionApi for MemberGrantApi {
    type Failure = MemberGrantFailure;
    type BuildError = useful_api::MemberGrantApiError;

    fn build(
        api_url: &str,
        token: &str,
        policy: useful_api::HttpTransportPolicy,
    ) -> Result<Self, Self::BuildError> {
        Self::new(api_url, token, policy)
    }

    fn credential_rejected(failure: &MemberGrantFailure) -> bool {
        failure.credential_rejected()
    }

    fn unauthenticated() -> MemberGrantFailure {
        MemberGrantFailure::Unauthenticated
    }

    fn unreachable(category: useful_api::UnreachableCategory) -> MemberGrantFailure {
        MemberGrantFailure::Unreachable { category }
    }
}

// The OAuth grant routes, which the consent and a grant's uses read.
impl super::super::HumanSessionApi for GrantApi {
    type Failure = GrantFailure;
    type BuildError = useful_api::GrantApiError;

    fn build(
        api_url: &str,
        token: &str,
        policy: useful_api::HttpTransportPolicy,
    ) -> Result<Self, Self::BuildError> {
        Self::new(api_url, token, policy)
    }

    fn credential_rejected(failure: &GrantFailure) -> bool {
        failure.credential_rejected()
    }

    fn unauthenticated() -> GrantFailure {
        GrantFailure::Unauthenticated
    }

    fn unreachable(category: useful_api::UnreachableCategory) -> GrantFailure {
        GrantFailure::Unreachable { category }
    }
}

/// Runs `f` against the grants resource with the signed-in human session, refreshing a
/// rejected session once.
fn with_api<T, F: super::super::JsonOutputKind>(
    deployment: &Deployment,
    options: &super::super::CommonArgs<F, super::super::NoAuthenticationArgs>,
    f: impl FnMut(&MemberGrantApi) -> Result<T, MemberGrantFailure>,
) -> anyhow::Result<Result<T, MemberGrantFailure>> {
    super::super::with_human_session_api(deployment, options.http.transport_policy(), f)
}

/// The command group of the member's integrations, which a remedy names.
const GROUP: &str = "useful account integration";

const GRANT_HELP: &str =
    "Provider you hold one grant of, a grant's ID, or a token service you hold a token of";
// As the `useful runner` commands word a runner they take by ID or name.
pub(in crate::cli) const RUNNER_HELP: &str = "Runner ID or exact name";

/// A grant as a command names it: its ID, `pgr_` for an OAuth grant and `agl_` for a native
/// one, or the wire name of a provider the member holds one grant of, which is any provider
/// id or `claude_code`.
#[derive(Clone, Debug)]
enum GrantArg {
    Id(String),
    Provider(String),
}

impl GrantArg {
    /// The token service the name can name: a provider name that is no built-in provider's,
    /// which a token service's never is.
    fn token_service(&self) -> Option<&str> {
        match self {
            Self::Provider(name) if MemberGrantProvider::from_wire(name).is_none() => Some(name),
            Self::Id(_) | Self::Provider(_) => None,
        }
    }

    /// Whether the grant named is a native one, as its name alone tells: an `agl_` ID, or a
    /// coding agent's provider.
    fn native(&self) -> bool {
        match self {
            Self::Id(id) => id.starts_with("agl_"),
            Self::Provider(provider) => MemberGrantProvider::from_wire(provider)
                .is_some_and(|provider| provider.kind() == MemberGrantKind::GrantKindNative),
        }
    }
}

fn parse_grant(value: &str) -> Result<GrantArg, String> {
    if useful_support::valid_typed_id(value, "pgr_")
        || useful_support::valid_typed_id(value, "agl_")
    {
        return Ok(GrantArg::Id(value.to_owned()));
    }
    if useful_api::valid_provider_id(value)
        || value == MemberGrantProvider::GrantProviderClaudeCode.as_str()
    {
        return Ok(GrantArg::Provider(value.to_owned()));
    }
    Err(
        "grant must be an exact pgr_ or agl_ identifier, as useful account integration list prints it, or a \
         provider name: claude_code, or a lowercase letter followed by at most 62 lowercase \
         letters, digits, dots and hyphens, such as github"
            .to_owned(),
    )
}

/// The grant a `GrantArg` names, or the IDs of the several unrevoked grants of the provider it
/// names, which a command refuses to choose between.
enum Resolved {
    Grant(Box<MemberGrant>),
    Ambiguous { provider: String, ids: Vec<String> },
}

/// Reads the grant `grant` names: by its ID, or among the member's unrevoked grants of the
/// provider it names, `grant_not_found` when there is none.
fn resolve(api: &MemberGrantApi, grant: &GrantArg) -> Result<Resolved, MemberGrantFailure> {
    let provider = match grant {
        GrantArg::Id(id) => return api.get(id).map(|grant| Resolved::Grant(Box::new(grant))),
        GrantArg::Provider(provider) => provider.as_str(),
    };
    let mut held: Vec<_> = every_grant(api)?
        .into_iter()
        .filter(|grant| unrevoked(grant) && grant.provider.as_str() == provider)
        .collect();
    match held.len() {
        0 => Err(MemberGrantFailure::GrantNotFound),
        1 => Ok(Resolved::Grant(Box::new(held.remove(0)))),
        _ => Ok(Resolved::Ambiguous {
            provider: provider.to_owned(),
            ids: held.into_iter().map(|grant| grant.id).collect(),
        }),
    }
}

/// The signed-in member's unrevoked grants of both kinds, read as `useful account integration list`
/// reads them with the human session alone; with `organization`, an ID or a slug, only that
/// organization's among the coding agents' grants.
pub(in crate::cli) fn held(
    deployment: &Deployment,
    policy: useful_api::HttpTransportPolicy,
    organization: Option<&str>,
) -> anyhow::Result<Result<Vec<MemberGrant>, MemberGrantFailure>> {
    super::super::with_human_session_api(deployment, policy, |api: &MemberGrantApi| {
        let organization = organization
            .map(|named| organization::named(api, named))
            .transpose()?;
        Ok(every_grant(api)?
            .into_iter()
            .filter(|grant| {
                unrevoked(grant)
                    && (grant.kind == MemberGrantKind::GrantKindOAuth
                        || organization.as_ref().is_none_or(|organization| {
                            grant.organization_id.as_deref() == Some(organization.id.as_str())
                        }))
            })
            .collect())
    })
}

fn unrevoked(grant: &MemberGrant) -> bool {
    grant.state != MemberGrantState::GrantStateRevoked
}

/// Every grant of the member, of both kinds, OAuth grants first.
fn every_grant(api: &MemberGrantApi) -> Result<Vec<MemberGrant>, MemberGrantFailure> {
    let invalid = MemberGrantFailure::InvalidResponse {
        credential_rejected: false,
    };
    super::super::paging::every_page(invalid, |cursor| {
        api.list(None, Some(MEMBER_GRANT_PAGE), cursor)
            .map(|page| (page.items, page.next_cursor))
    })
}

/// What a name finds: a grant, or the several unrevoked grants of the provider it names, as
/// [`resolve`] answers; or the member's token of the token service it names.
enum Found {
    Grant(Resolved),
    Token(Box<IntegrationToken>),
}

/// Finds what `name` names: among the member's grants first, so a name that names a grant sends
/// what it sent before tokens were in reach, and a name that names none and can name a token
/// service among the member's tokens, once the served read names a token service, so that
/// against a deployment that serves none no token list is read. Not found is `grant_not_found`.
fn lookup(api: &MemberGrantApi, name: &GrantArg) -> Result<Found, MemberGrantFailure> {
    match (resolve(api, name), name.token_service()) {
        (Err(MemberGrantFailure::GrantNotFound), Some(service)) => {
            if integration_token::served(api)?.is_empty() {
                return Err(MemberGrantFailure::GrantNotFound);
            }
            integration_token::held(api, IntegrationTokenOwner::Member, service)?
                .map(|token| Found::Token(Box::new(token)))
                .ok_or(MemberGrantFailure::GrantNotFound)
        }
        (resolved, _) => resolved.map(Found::Grant),
    }
}

/// Sends a mutation, and once more under the same key when its answer was lost: the first may
/// have taken effect. A grant's and an integration token's mutations are sent this way.
pub(in crate::cli) fn replayed<T>(
    mut send: impl FnMut() -> Result<T, MemberGrantFailure>,
) -> Result<T, MemberGrantFailure> {
    match send() {
        Err(MemberGrantFailure::Unreachable { .. }) => send(),
        result => result,
    }
}

/// What a mutating leaf acts on: a grant of either kind, or the member's token of a token
/// service. The helpers below read of it only its ID, the kind its statement depends on, its
/// authorizations in force and the organizations whose runners it may serve.
pub(in crate::cli) enum Subject {
    Grant(Box<MemberGrant>),
    Token(Box<IntegrationToken>),
}

/// One authorization in force of a subject: its ID, the runner's and the runner's organization's.
pub(in crate::cli) struct InForce<'a> {
    pub(in crate::cli) id: &'a str,
    pub(in crate::cli) runner_id: &'a str,
    pub(in crate::cli) organization_id: &'a str,
}

impl Subject {
    pub(in crate::cli) fn id(&self) -> &str {
        match self {
            Self::Grant(grant) => &grant.id,
            Self::Token(token) => &token.id,
        }
    }

    /// The provider of the grant, or the token service of the token.
    pub(in crate::cli) fn provider(&self) -> &str {
        match self {
            Self::Grant(grant) => grant.provider.as_str(),
            Self::Token(token) => &token.provider,
        }
    }

    /// What the statement of acting on it depends on.
    pub(in crate::cli) const fn kind(&self) -> confirmation::Kind {
        match self {
            Self::Grant(grant) => confirmation::Kind::Grant(grant.kind),
            Self::Token(token) => match token.side {
                IntegrationTokenSide::IntegrationTokenSideMember => confirmation::Kind::Token,
                IntegrationTokenSide::IntegrationTokenSideOrg => confirmation::Kind::OrgToken,
            },
        }
    }

    /// What a result names the authorization's holder by.
    pub(in crate::cli) fn holder(&self) -> Holder<'_> {
        match self {
            Self::Grant(grant) => Holder::Grant(&grant.id),
            Self::Token(token) => Holder::IntegrationToken(&token.id),
        }
    }

    /// Its authorizations in force: a grant lists only those, and so does a token.
    pub(in crate::cli) fn in_force(&self) -> Vec<InForce<'_>> {
        match self {
            Self::Grant(grant) => grant
                .authorizations
                .iter()
                .map(|authorization| InForce {
                    id: &authorization.id,
                    runner_id: &authorization.runner_id,
                    organization_id: &authorization.organization_id,
                })
                .collect(),
            Self::Token(token) => token
                .authorizations
                .iter()
                .map(|authorization| InForce {
                    id: &authorization.id,
                    runner_id: &authorization.runner_id,
                    organization_id: &authorization.organization_id,
                })
                .collect(),
        }
    }

    /// The organizations whose runners alone it may serve: a native grant's and an
    /// organization's token's; `None` for those of every organization the member is an active
    /// member of, which an OAuth grant and the member's token serve.
    fn serving(&self) -> Option<BTreeSet<String>> {
        match self {
            Self::Grant(grant) => (grant.kind == MemberGrantKind::GrantKindNative)
                .then(|| grant.organization_id.iter().cloned().collect()),
            Self::Token(token) => (token.side == IntegrationTokenSide::IntegrationTokenSideOrg)
                .then(|| token.organization_id.iter().cloned().collect()),
        }
    }

    /// How a statement's heading names it: a grant by its ID, a token by its service and ID.
    pub(in crate::cli) fn named(&self) -> String {
        match self {
            Self::Grant(grant) => format!("grant {}", grant.id),
            Self::Token(token) => format!("{} token {}", token.provider, token.id),
        }
    }

    /// How a command line names it: a grant by its ID, a token by its service.
    fn argument(&self) -> &str {
        match self {
            Self::Grant(grant) => &grant.id,
            Self::Token(token) => &token.provider,
        }
    }
}

/// Reads what `name` names, or reports why the leaf has nothing to act on: a provider name that
/// names several grants is refused, naming them with `example`, the leaf's command line for one
/// grant ID, and a failure is reported with its remedy.
fn read_subject(
    deployment: &Deployment,
    options: &Options,
    name: &GrantArg,
    example: impl FnOnce(&str) -> String,
) -> anyhow::Result<Result<Subject, ExitCode>> {
    let api_url = deployment.fingerprint().api_url();
    let json = options.json;
    Ok(
        match with_api(deployment, options, |api| lookup(api, name))? {
            Ok(Found::Grant(Resolved::Grant(grant))) => Ok(Subject::Grant(grant)),
            Ok(Found::Grant(Resolved::Ambiguous { provider, ids })) => Err(
                output::write_ambiguous(api_url, &provider, &ids, example, json, false)?,
            ),
            Ok(Found::Token(token)) => Ok(Subject::Token(token)),
            Err(failure) => Err(output::failure(api_url, &failure, json)?),
        },
    )
}

/// Runs the mutating leaf `C` on what `name` names: reads it, states on standard error what
/// acting on a subject of its kind does, then acts and reports the result, or the failure. A
/// provider name that names several grants is refused, naming them, before anything is stated
/// or sent.
fn act_on<C: Stated, T>(
    deployment: &Deployment,
    options: &Options,
    name: &GrantArg,
    heading: impl FnOnce(&Subject) -> String,
    act: impl FnMut(&MemberGrantApi, &Subject) -> Result<T, MemberGrantFailure>,
    write: impl FnOnce(&str, &Subject, T, bool) -> anyhow::Result<ExitCode>,
    // The leaf's command line for one grant ID, which an ambiguous provider name is refused
    // with.
    example: impl FnOnce(&str) -> String,
) -> anyhow::Result<ExitCode> {
    let subject = match read_subject(deployment, options, name, example)? {
        Ok(subject) => subject,
        Err(exit) => return Ok(exit),
    };
    state_then_act::<C, _>(
        deployment,
        options,
        &subject,
        &heading(&subject),
        false,
        act,
        write,
    )
}

/// States on standard error under `heading` what the leaf `C` does to `subject`, asks whether to
/// go on when `asks`, then acts and reports the result, or the failure.
fn state_then_act<C: Stated, T>(
    deployment: &Deployment,
    options: &Options,
    subject: &Subject,
    heading: &str,
    asks: bool,
    mut act: impl FnMut(&MemberGrantApi, &Subject) -> Result<T, MemberGrantFailure>,
    write: impl FnOnce(&str, &Subject, T, bool) -> anyhow::Result<ExitCode>,
) -> anyhow::Result<ExitCode> {
    let api_url = deployment.fingerprint().api_url();
    let json = options.json;
    confirmation::state(format_args!("{heading}"), C::STATEMENT.of(subject.kind()))?;
    if let Err(exit) = confirmation::go_on(asks)? {
        return Ok(exit);
    }
    match with_api(deployment, options, |api| act(api, subject))? {
        Ok(value) => write(api_url, subject, value, json),
        Err(failure) => output::failure(api_url, &failure, json),
    }
}

/// What the command line of `authorize` or `deauthorize` names of the runner: the value of
/// `--runner`, an ID or a name, or none, and whether `--yes` was given.
struct RunnerArgs<'a> {
    named: Option<&'a str>,
    yes: bool,
}

/// What `authorize INTEGRATION` and `deauthorize INTEGRATION` act on: the grant or token, the
/// runner, and whether to ask before acting.
struct Target {
    subject: Subject,
    runner: runner_choice::Acting,
    asks: bool,
}

/// Reads what `name` names and the runner the leaf `C` acts on, the one `--runner` names: an
/// ID as given, or a name looked up among the runners `candidates` reads for the subject.
/// Without `--yes` it asks before acting where it can, and elsewhere refuses before anything
/// is read. Given no runner it names those `offered` reads for the subject, under `purpose`,
/// and exits. A provider name that names several grants is refused, naming them, before any
/// runner is read.
fn subject_and_runner<C: Stated>(
    deployment: &Deployment,
    options: &Options,
    name: &GrantArg,
    runner: &RunnerArgs<'_>,
    offered: impl FnOnce(&Subject) -> anyhow::Result<runner_choice::Offer>,
    candidates: impl FnOnce(&Subject) -> runner_choice::Read,
    purpose: impl FnOnce(&Subject) -> String,
) -> anyhow::Result<Result<Target, ExitCode>> {
    let json = options.json;
    let asks = match runner.named {
        Some(_) => match confirmation::asks::<C>(runner.yes, json)? {
            Ok(asks) => asks,
            Err(exit) => return Ok(Err(exit)),
        },
        None => false,
    };
    let subject = match read_subject(deployment, options, name, |id| match runner.named {
        Some(named) => format!("{} {id} --runner {named} --yes", C::COMMAND),
        None => format!("{} {id}", C::COMMAND),
    })? {
        Ok(subject) => subject,
        Err(exit) => return Ok(Err(exit)),
    };
    let example = |runner_id: &str| {
        format!(
            "{} {} --runner {runner_id} --yes",
            C::COMMAND,
            subject.argument()
        )
    };
    let holder = Some(subject.holder());
    let Some(named) = runner.named else {
        let offer = offered(&subject)?;
        let purpose = purpose(&subject);
        return runner_choice::refuse(deployment, json, offer, holder, GROUP, &purpose, example)
            .map(Err);
    };
    let runner = match runner_choice::resolve(
        deployment,
        json,
        output::Family::Document,
        named,
        holder,
        || candidates(&subject),
        example,
    )? {
        Ok(runner) => runner,
        Err(exit) => return Ok(Err(exit)),
    };
    Ok(Ok(Target {
        subject,
        runner,
        asks,
    }))
}
