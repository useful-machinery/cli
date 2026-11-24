//! The organization's token of a token service, as `useful org integration` acts on it:
//! connected and reconnected through `integration_token`, shown and listed with who connected
//! it named from the organization's directory, authorized for a runner of the organization,
//! alone or with every token of the organization, and disconnected. Each is read and sent
//! under the member's session, which Cloud admits for an owner alone; a service API key
//! reaches none of them.

use std::io::{self, Write as _};

use anyhow::{Context as _, anyhow};
use useful_api::{
    HttpTransportPolicy, IntegrationToken, IntegrationTokenOwner, MemberGrantApi,
    MemberGrantFailure, ServedTokenService,
};
use useful_human_auth::Deployment;

use super::list::Provider;
use crate::cli::account::grant::confirmation::{self, TOKEN_DEAUTHORIZE, TOKEN_REVOKE};
use crate::cli::account::grant::output::{self as grant_output, Family};
use crate::cli::account::grant::{Subject, authorize, deauthorize, replayed, runner_choice};
use crate::cli::integration_token::{self, ListedToken, Tokens};
use crate::cli::{
    ApiFailureReport, CommandFailure, CommandResult, PrincipalAuthenticationArgs,
    PrincipalAuthenticationKind, with_human_session_api,
};
use crate::exit_code::{ExitCode, OutcomeClass};

/// The command group of the organization's integrations, which a remedy names.
pub(super) const GROUP: &str = "useful org integration";

/// Who can use the organization's token once a runner is authorized for it.
pub(super) const ORG_TOKEN_AUTHORIZE: &[&str] = &[
    "every run of the organization on the runner whose workflow declares the service as org can \
     be issued the token, whoever caused the run",
    "every step of such a run can read the organization's token",
];

/// Refuses a service API key for what only a member's session reaches: the organization's
/// tokens and its connection authorizations, exit 2 before any request.
pub(super) fn member_session(
    authentication: &PrincipalAuthenticationArgs,
    what: &str,
) -> Result<(), CommandFailure> {
    match authentication.kind() {
        PrincipalAuthenticationKind::HumanSession => Ok(()),
        PrincipalAuthenticationKind::ServiceApiKey => Err(CommandFailure::with_exit_code(
            anyhow!(
                "--api-key-file does not apply to {what}\n\nThe organization's tokens and \
                 connection authorizations are managed by an owner's own session: a service API \
                 key reaches neither. Name a connection, or run the command without \
                 --api-key-file."
            ),
            ExitCode::UsageError,
        )),
    }
}

/// The organization in effect's tokens, as a leaf acts on them: where, under which session
/// policy, how it prints, and the organization by the reference in effect.
#[derive(Clone, Copy)]
pub(super) struct OrgTokens<'a> {
    pub(super) deployment: &'a Deployment,
    pub(super) policy: HttpTransportPolicy,
    pub(super) json: bool,
    pub(super) organization: &'a str,
}

impl OrgTokens<'_> {
    fn owner(&self) -> IntegrationTokenOwner<'_> {
        IntegrationTokenOwner::Organization(self.organization)
    }

    fn api_url(&self) -> &str {
        self.deployment.fingerprint().api_url()
    }

    /// `failure` of an operation on the token of `service` as the member reads it: an
    /// owner's refusal, a token stored meanwhile, a service the organization holds no token
    /// of and the refusals that name the token's authorizations, each with a remedy that
    /// names the organization; any other as a grant's.
    pub(super) fn report(&self, failure: &MemberGrantFailure, service: &str) -> ApiFailureReport {
        let org = self.organization;
        let refused = |outcome, summary: String, remedy: String| {
            ApiFailureReport::new(outcome, summary, remedy, OutcomeClass::GeneralFailure)
        };
        let shown =
            format!("Show the token's authorizations:\n  {GROUP} show {service} --org {org}");
        match failure {
            MemberGrantFailure::Forbidden => ApiFailureReport::new(
                "forbidden",
                format!("! Only an owner of the organization {org} can manage its tokens."),
                format!(
                    "Ask an owner of {org} to connect it, or connect your own:\n  \
                     useful account integration connect {service}"
                ),
                OutcomeClass::Forbidden,
            ),
            MemberGrantFailure::IntegrationTokenNotFound => refused(
                "token_not_found",
                format!("error: the organization {org} holds no {service} token"),
                format!(
                    "A token is named by its service. List the organization's integrations:\n  \
                     {GROUP} list --org {org}"
                ),
            ),
            MemberGrantFailure::IntegrationTokenExists => refused(
                "token_exists",
                format!("error: a {service} token was connected while this command ran"),
                format!(
                    "Store the organization's token as its next version instead:\n  \
                     {GROUP} reconnect {service} --org {org}"
                ),
            ),
            MemberGrantFailure::IntegrationTokenAlreadyAuthorized => refused(
                "already_authorized",
                "error: this token is already authorized for that runner".to_owned(),
                shown,
            ),
            MemberGrantFailure::IntegrationTokenAuthorizationNotFound => refused(
                "authorization_not_found",
                "error: that runner holds no authorization of this token".to_owned(),
                shown,
            ),
            _ => grant_output::report(self.api_url(), failure),
        }
    }

    /// The organization's token of `service`, which `leaf` acts on, or the exit status of the
    /// refusal reported in its place. The providers the deployment serves are read first: a name
    /// that is no token service it serves is a usage error, exit 2, naming the three providers
    /// and the token services, with no token read. A service the organization holds no token of
    /// is `token_not_found`, whose remedy for `reconnect`, which makes no token, is `connect`.
    fn find(
        &self,
        service: &str,
        leaf: &str,
    ) -> anyhow::Result<Result<IntegrationToken, ExitCode>> {
        let read = with_human_session_api(self.deployment, self.policy, |api: &MemberGrantApi| {
            let served = integration_token::served(api)?;
            if !served.iter().any(|served| served.name == service) {
                return Ok(Err(served));
            }
            Ok(Ok(integration_token::held(api, self.owner(), service)?))
        })?;
        match read {
            Ok(Ok(Some(token))) => Ok(Ok(token)),
            Ok(Ok(None)) if leaf == "reconnect" => integration_token::write_refusal(
                self.api_url(),
                &integration_token::not_held(
                    &format!(
                        "the organization {} holds no {service} token",
                        self.organization
                    ),
                    &format!("{GROUP} connect {service} --org {}", self.organization),
                ),
                self.json,
            )
            .map(Err),
            Ok(Ok(None)) => self
                .report(&MemberGrantFailure::IntegrationTokenNotFound, service)
                .write(self.api_url(), self.json)
                .map(Err),
            Ok(Err(served)) => {
                writeln!(
                    io::stderr().lock(),
                    "error: {}",
                    not_served(service, &served, &format!("{GROUP} {leaf} INTEGRATION"))
                )?;
                Ok(Err(ExitCode::UsageError))
            }
            Err(failure) => self
                .report(&failure, service)
                .write(self.api_url(), self.json)
                .map(Err),
        }
    }

    /// `show SERVICE`: the organization's token of it, with who connected it named from the
    /// organization's directory, whose failed read names nobody.
    pub(super) fn show(&self, service: &str) -> anyhow::Result<ExitCode> {
        let token = match self.find(service, "show")? {
            Ok(token) => token,
            Err(exit) => return Ok(exit),
        };
        let names =
            with_human_session_api(self.deployment, self.policy, |api: &MemberGrantApi| {
                Ok(integration_token::directory(api, self.organization))
            })?
            .unwrap_or_default();
        ListedToken::organization(token, self.organization, &names)
            .write_shown(self.api_url(), self.json)
    }

    /// The organization's tokens, which `list` prints after its connections, read only where
    /// the deployment serves a token service, each with who connected it named from the
    /// organization's directory, which is read only for an organization that holds a token.
    /// A failed read of the tokens is the inner error.
    pub(super) fn listed(&self) -> anyhow::Result<Result<Tokens, MemberGrantFailure>> {
        with_human_session_api(self.deployment, self.policy, |api: &MemberGrantApi| {
            if integration_token::served(api)?.is_empty() {
                return Ok(Tokens::default());
            }
            let tokens = integration_token::every(api, self.owner())?;
            let names = if tokens.is_empty() {
                Default::default()
            } else {
                integration_token::directory(api, self.organization)
            };
            Ok(Tokens::organization(tokens, self.organization, &names))
        })
    }

    /// `connect SERVICE`: stores the organization's first token of `service`, read from
    /// `from_file`, standard input or a prompt that does not echo; one the organization holds is
    /// refused with exit 2 before any token is read, naming `reconnect`.
    pub(super) fn connect(
        &self,
        service: &ServedTokenService,
        from_file: Option<&std::path::Path>,
    ) -> CommandResult {
        let name = service.name.as_str();
        let org = self.organization;
        self.store(service, from_file).connect(
            |failure| self.report(failure, name),
            |held| {
                CommandFailure::with_exit_code(
                    anyhow!(
                        "the organization {org} already holds a {name} token: {}\n\nStore a new \
                         token as its next version, which keeps its ID and the runners it is \
                         authorized for:\n  {GROUP} reconnect {name} --org {org}",
                        held.id
                    ),
                    ExitCode::UsageError,
                )
            },
        )
    }

    /// `reconnect SERVICE`: stores the next version of the organization's token of `service`,
    /// which keeps its ID and its authorizations.
    pub(super) fn reconnect(
        &self,
        service: &str,
        from_file: Option<&std::path::Path>,
    ) -> CommandResult {
        if let Err(exit) = self.find(service, "reconnect")? {
            return Ok(exit);
        }
        let served = ServedTokenService {
            name: service.to_owned(),
            display_name: None,
        };
        self.store(&served, from_file)
            .store(true, |failure| self.report(failure, service))
    }

    fn store<'a>(
        &'a self,
        service: &'a ServedTokenService,
        from_file: Option<&'a std::path::Path>,
    ) -> integration_token::Store<'a> {
        integration_token::Store {
            deployment: self.deployment,
            policy: self.policy,
            json: self.json,
            owner: self.owner(),
            slug: Some(self.organization),
            service,
            from_file,
        }
    }

    /// `disconnect SERVICE --yes`: states what revoking a token does, then erases the
    /// organization's token of `service` from Cloud; it stays valid at the service.
    pub(super) fn disconnect(&self, service: &str) -> anyhow::Result<ExitCode> {
        let token = match self.find(service, "disconnect")? {
            Ok(token) => token,
            Err(exit) => return Ok(exit),
        };
        confirmation::state(
            format_args!(
                "Revoking {} token {} of the organization {}:",
                token.provider, token.id, self.organization
            ),
            TOKEN_REVOKE,
        )?;
        let key = useful_support::generate_idempotency_key()
            .context("generate integration token revocation request key")?;
        let revoked =
            with_human_session_api(self.deployment, self.policy, |api: &MemberGrantApi| {
                replayed(|| api.revoke_integration_token(self.owner(), &token.id, &key))
            })?;
        match revoked {
            Ok(()) => integration_token::write_revoked(
                self.api_url(),
                &token,
                Some(self.organization),
                self.json,
            ),
            Err(failure) => self
                .report(&failure, service)
                .write(self.api_url(), self.json),
        }
    }

    /// The organization's token of `service` as the subject of `authorize` or `deauthorize`, or
    /// the exit status of the refusal reported in its place.
    fn subject(&self, service: &str, leaf: &str) -> anyhow::Result<Result<Subject, ExitCode>> {
        Ok(self
            .find(service, leaf)?
            .map(|token| Subject::Token(Box::new(token))))
    }

    /// The command line of `leaf` for the token of `service` and `runner`.
    fn command_line(&self, leaf: &str, service: &str, runner: &str) -> String {
        format!(
            "{GROUP} {leaf} {service} --runner {runner} --org {} --yes",
            self.organization
        )
    }

    /// `authorize SERVICE --runner RUNNER`: authorizes the runner `runner` names, an ID or a name
    /// among the organization's runners, for the organization's token of `service`, stating who
    /// can use it and asking first where `asks`. Given no runner it names the organization's
    /// runners the token is not authorized for, and exits 2.
    pub(super) fn authorize(
        &self,
        service: &str,
        runner: Option<&str>,
        asks: bool,
    ) -> anyhow::Result<ExitCode> {
        let subject = match self.subject(service, "authorize")? {
            Ok(subject) => subject,
            Err(exit) => return Ok(exit),
        };
        let example = |runner_id: &str| self.command_line("authorize", service, runner_id);
        let holder = Some(subject.holder());
        let Some(named) = runner else {
            let offer = runner_choice::to_authorize(self.deployment, self.policy, &subject)?;
            return runner_choice::refuse(
                self.deployment,
                self.json,
                offer,
                holder,
                GROUP,
                &format!("to authorize for {}", subject.named()),
                example,
            );
        };
        let runner = match runner_choice::resolve(
            self.deployment,
            self.json,
            Family::Document,
            named,
            holder,
            || runner_choice::authorizable(self.deployment, self.policy, &subject),
            example,
        )? {
            Ok(runner) => runner,
            Err(exit) => return Ok(exit),
        };
        confirmation::state(
            format_args!(
                "Authorizing runner {} for {}:",
                runner.named,
                subject.named()
            ),
            ORG_TOKEN_AUTHORIZE,
        )?;
        if let Err(exit) = confirmation::go_on(asks)? {
            return Ok(exit);
        }
        let key = useful_support::generate_idempotency_key()
            .context("generate integration token authorization request key")?;
        let made = with_human_session_api(self.deployment, self.policy, |api: &MemberGrantApi| {
            authorize::authorize(api, self.owner(), &subject, &runner.id, &key)
        })?;
        match made {
            Ok(made) => authorize::write(self.api_url(), &subject, &made, self.json),
            Err(failure) => self
                .report(&failure, service)
                .write(self.api_url(), self.json),
        }
    }

    /// `authorize --all --runner RUNNER`: authorizes the runner for every token of the
    /// organization, and for no connection. The tokens are read first: an organization that
    /// holds none is `token_not_found`. Given no runner it names the organization's runners
    /// and exits 2.
    pub(super) fn authorize_all(
        &self,
        runner: Option<&str>,
        asks: bool,
    ) -> anyhow::Result<ExitCode> {
        let org = self.organization;
        let example = |runner_id: &str| {
            format!("{GROUP} authorize --all --runner {runner_id} --org {org} --yes")
        };
        let every = format!("every token of the organization {org}");
        // The tokens first: an organization that holds none is told so before any runner is
        // named, stated or asked about.
        let read = with_human_session_api(self.deployment, self.policy, |api: &MemberGrantApi| {
            integration_token::every(api, self.owner())
        })?;
        let subjects: Vec<_> = match read {
            Ok(tokens) if tokens.is_empty() => {
                return ApiFailureReport::new(
                    "token_not_found",
                    format!("error: the organization {org} holds no token"),
                    format!("Connect one for it first:\n  {GROUP} connect SERVICE --org {org}"),
                    OutcomeClass::GeneralFailure,
                )
                .write(self.api_url(), self.json);
            }
            Ok(tokens) => tokens
                .into_iter()
                .map(|token| Subject::Token(Box::new(token)))
                .collect(),
            Err(failure) => {
                return self
                    .report(&failure, "SERVICE")
                    .write(self.api_url(), self.json);
            }
        };
        let Some(named) = runner else {
            let offer = runner_choice::to_authorize_all(runner_choice::in_organization(
                self.deployment,
                self.policy,
                org,
            ))?;
            return runner_choice::refuse(
                self.deployment,
                self.json,
                offer,
                None,
                GROUP,
                &format!("to authorize for {every}"),
                example,
            );
        };
        let runner = match runner_choice::resolve(
            self.deployment,
            self.json,
            Family::Document,
            named,
            None,
            || runner_choice::in_organization(self.deployment, self.policy, org),
            example,
        )? {
            Ok(runner) => runner,
            Err(exit) => return Ok(exit),
        };
        confirmation::state(
            format_args!("Authorizing runner {} for {every}:", runner.named),
            ORG_TOKEN_AUTHORIZE,
        )?;
        if let Err(exit) = confirmation::go_on(asks)? {
            return Ok(exit);
        }
        authorize::authorize_every(
            self.deployment,
            self.policy,
            self.json,
            self.owner(),
            &subjects,
            &runner.id,
            |failure| self.report(failure, "SERVICE"),
        )
    }

    /// `deauthorize SERVICE --runner RUNNER`: ends the authorization of the runner `runner`
    /// names, an ID or a name among the runners the token is authorized for, stating that it is
    /// issued the token no more and asking first where `asks`. Given no runner it names those
    /// runners and exits 2.
    pub(super) fn deauthorize(
        &self,
        service: &str,
        runner: Option<&str>,
        asks: bool,
    ) -> anyhow::Result<ExitCode> {
        let subject = match self.subject(service, "deauthorize")? {
            Ok(subject) => subject,
            Err(exit) => return Ok(exit),
        };
        let example = |runner_id: &str| self.command_line("deauthorize", service, runner_id);
        let holder = Some(subject.holder());
        let Some(named) = runner else {
            let offer = runner_choice::to_deauthorize(runner_choice::authorized(
                self.deployment,
                self.policy,
                &subject,
            ))?;
            return runner_choice::refuse(
                self.deployment,
                self.json,
                offer,
                holder,
                GROUP,
                &format!("whose authorization for {} to end", subject.named()),
                example,
            );
        };
        let runner = match runner_choice::resolve(
            self.deployment,
            self.json,
            Family::Document,
            named,
            holder,
            || runner_choice::authorized(self.deployment, self.policy, &subject),
            example,
        )? {
            Ok(runner) => runner,
            Err(exit) => return Ok(exit),
        };
        confirmation::state(
            format_args!(
                "Ending runner {}'s authorization for {}:",
                runner.named,
                subject.named()
            ),
            TOKEN_DEAUTHORIZE,
        )?;
        if let Err(exit) = confirmation::go_on(asks)? {
            return Ok(exit);
        }
        let key = useful_support::generate_idempotency_key()
            .context("generate integration token deauthorization request key")?;
        let ended =
            with_human_session_api(self.deployment, self.policy, |api: &MemberGrantApi| {
                deauthorize::deauthorize(api, self.owner(), &subject, &runner.id, &key)
            })?;
        match ended {
            Ok(ended) => deauthorize::write(self.api_url(), &subject, &runner.id, ended, self.json),
            Err(failure) => self
                .report(&failure, service)
                .write(self.api_url(), self.json),
        }
    }
}

/// Why `service` names nothing of the organization's: it is neither `github`, `gitlab` nor
/// `linear`, nor a token service the deployment serves, which are those `served` names; with the
/// command line `example` that names one.
pub(super) fn not_served(service: &str, served: &[ServedTokenService], example: &str) -> String {
    let given: Vec<_> = Provider::ALL
        .iter()
        .map(|provider| provider.as_str())
        .chain(served.iter().map(|served| served.name.as_str()))
        .collect();
    format!(
        "{service} is neither github, gitlab nor linear, nor a token service this deployment \
         serves\n\nName one of {}:\n  {example}",
        given.join(", ")
    )
}
