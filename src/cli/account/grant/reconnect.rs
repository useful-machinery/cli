//! `useful account integration reconnect INTEGRATION`: signs in again to a grant the member holds,
//! which keeps its ID and the runners it is authorized for (REQ-GRANT-73), or stores the next
//! version of the member's token of a token service, which keeps its ID and authorizations too
//! (REQ-INTEGRATION-18). Naming the grant or the token is the decision, so it asks nothing. A
//! coding agent's login is read or signed in to as `create` does and stored as the grant's next
//! generation; an OAuth grant's provider is consented to, and the account the member consents as
//! decides which grant the consent renews (REQ-GRANT-2); a token is read as `connect` reads one.

use std::path::PathBuf;

use anyhow::anyhow;
use clap::{ArgGroup, Args};
use zeroize::Zeroizing;

use crate::cli::integration_token;
use crate::cli::{CommandFailure, CommandResult};
use crate::exit_code::ExitCode;
use useful_api::{
    IntegrationToken, IntegrationTokenOwner, MemberGrant, MemberGrantFailure, MemberGrantKind,
    ServedTokenService,
};
use useful_human_auth::Deployment;

use super::super::super::secret_file::FileMode;
use super::consent::{ConsentProvider, Options, write_not_reconnected, write_refusal};
use super::create::{self, Flow, Login, ProviderArg, Store, first_given};
use super::{GRANT_HELP, GrantArg, Resolved, claude_setup_token, material, output};

pub(super) const ABOUT: &str = "Sign in again to a grant you hold, or store your token's next version, keeping its ID and the runners it is authorized for";

/// What `reconnect` acts on: the member's unrevoked grant, or the member's token with the token
/// service the deployment serves it as.
enum Reconnecting {
    Grant(Box<MemberGrant>),
    Token(Box<IntegrationToken>, ServedTokenService),
}

/// What the name read: a grant, or the several of one provider, or a token.
enum Read {
    Grant(Resolved),
    Token(Box<IntegrationToken>, ServedTokenService),
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("source").multiple(false)))]
pub(super) struct Command {
    #[arg(value_name = "INTEGRATION", value_parser = super::parse_grant, help = GRANT_HELP)]
    grant: GrantArg,

    #[arg(long, group = "source", help = create::LOGIN_HELP)]
    login: bool,

    #[arg(long, group = "source", help = create::DEVICE_HELP)]
    device: bool,

    #[arg(long, value_name = "PATH", group = "source", help = create::FROM_FILE_HELP)]
    from_file: Option<PathBuf>,

    #[arg(long, value_name = "PATH", group = "source", help = create::TOKEN_FILE_HELP)]
    token_file: Option<PathBuf>,

    #[command(flatten)]
    wait: super::super::super::WaitTimeoutArgs,

    #[arg(long, conflicts_with = "timeout", help = create::NO_WAIT_HELP)]
    no_wait: bool,

    #[command(flatten)]
    options: Options,
}

impl Command {
    /// Reads the file or stream a source option names, before any request, so that an insecurely
    /// held or malformed one is refused with exit 2 (INV-CLI-13), where the name can name a
    /// coding agent's grant; then reads the grant or token, refuses an option that does not suit
    /// it with exit 2 before any sign-in or token read, and signs in to it again (REQ-GRANT-73)
    /// or stores the token's next version (REQ-INTEGRATION-18).
    pub(super) fn run(self, deployment: &Deployment) -> CommandResult {
        // A provider name that is no coding agent's names an OAuth grant, which takes no source,
        // or a token, whose `--from-file` is read as a token once it is found.
        let read = match &self.grant {
            GrantArg::Provider(_) if !self.grant.native() => None,
            _ => self.read_login()?,
        };
        let found = match self.read_grant(deployment)? {
            Ok(found) => found,
            Err(exit) => return Ok(exit),
        };
        match found {
            Reconnecting::Grant(grant) => match grant.kind {
                MemberGrantKind::GrantKindOAuth => self.reconsent(deployment, &grant),
                MemberGrantKind::GrantKindNative => self.renew(deployment, &grant, read),
            },
            Reconnecting::Token(token, service) => self.replace_token(deployment, &token, &service),
        }
    }

    fn flow(&self) -> Flow<'_> {
        Flow {
            json: self.options.json,
            allow_insecure_http: self.options.http.allow_insecure_http,
            organization: None,
            device: self.device,
            no_wait: self.no_wait,
            timeout: self.wait.timeout,
            runner: None,
        }
    }

    /// The login `--from-file` or `--token-file` names, read and checked by the reader of that
    /// option's coding agent.
    fn read_login(&self) -> Result<Option<Zeroizing<Vec<u8>>>, CommandFailure> {
        let read = match (&self.from_file, &self.token_file) {
            (Some(path), _) => material::read_codex_login(path, FileMode::Private),
            (None, Some(path)) => material::read_claude_code_token(path),
            (None, None) => return Ok(None),
        };
        read.map(Some)
            .map_err(|error| CommandFailure::with_exit_code(error, ExitCode::UsageError))
    }

    /// The unrevoked grant `INTEGRATION` names, or where a provider name names none the member's
    /// token of the token service it names, read once the served read names a token service; or
    /// the exit status of the refusal reported in its place: a revoked grant is
    /// `grant_not_found`, and a provider that names several grants is refused with exit 2,
    /// naming them. Before the grant is read its kind is known from its name alone, so a refusal
    /// is reported as the event of a grant of that kind.
    fn read_grant(
        &self,
        deployment: &Deployment,
    ) -> anyhow::Result<Result<Reconnecting, ExitCode>> {
        let api_url = deployment.fingerprint().api_url();
        let json = self.options.json;
        let read = super::with_api(deployment, &self.options, |api| {
            match (super::resolve(api, &self.grant), self.grant.token_service()) {
                (Ok(Resolved::Grant(grant)), _) if !super::unrevoked(&grant) => {
                    Err(MemberGrantFailure::GrantNotFound)
                }
                // A name that names no grant is looked up among the member's tokens as the other
                // leaves look it up, once the served read names a token service; one the
                // deployment no longer serves is still found, and Cloud answers for it.
                (Err(MemberGrantFailure::GrantNotFound), Some(name)) => {
                    let served = integration_token::served(api)?;
                    if served.is_empty() {
                        return Err(MemberGrantFailure::GrantNotFound);
                    }
                    let service = served.iter().find(|service| service.name == name).cloned();
                    match integration_token::held(api, IntegrationTokenOwner::Member, name)? {
                        Some(token) => Ok(Read::Token(
                            Box::new(token),
                            service.unwrap_or_else(|| ServedTokenService {
                                name: name.to_owned(),
                                display_name: None,
                            }),
                        )),
                        // `reconnect` never makes a token: a service the member holds none of
                        // is `connect`'s.
                        None if service.is_some() => {
                            Err(MemberGrantFailure::IntegrationTokenNotFound)
                        }
                        None => Err(MemberGrantFailure::GrantNotFound),
                    }
                }
                (resolved, _) => resolved.map(Read::Grant),
            }
        })?;
        Ok(match read {
            Ok(Read::Token(token, service)) => Ok(Reconnecting::Token(token, service)),
            Ok(Read::Grant(Resolved::Grant(grant))) => Ok(Reconnecting::Grant(grant)),
            Ok(Read::Grant(Resolved::Ambiguous { provider, ids })) => Err(output::write_ambiguous(
                api_url,
                &provider,
                &ids,
                |id| format!("useful account integration reconnect {id}"),
                json,
                true,
            )?),
            Err(MemberGrantFailure::IntegrationTokenNotFound) => {
                let service = self.grant.token_service().unwrap_or("SERVICE");
                Err(integration_token::write_refusal(
                    api_url,
                    &integration_token::not_held(
                        &format!("you hold no {service} token"),
                        &format!("useful account integration connect {service}"),
                    ),
                    json,
                )?)
            }
            Err(failure) => {
                let report = output::report(api_url, &failure);
                Err(if self.grant.native() {
                    output::write_import_refusal(api_url, &report, json)?
                } else {
                    write_refusal(api_url, None, &report, json)?
                })
            }
        })
    }

    /// Refuses with exit 2 the first option given of `options`, which do not apply to the grant's
    /// provider `name`, with `remedy`.
    fn refuse_unsuited<const N: usize>(
        name: &str,
        options: [(bool, &'static str); N],
        remedy: impl FnOnce() -> String,
    ) -> Result<(), CommandFailure> {
        Self::refuse_unsuited_to("grant", name, options, remedy)
    }

    /// Refuses with exit 2 the first option given of `options`, which do not apply to a `what`,
    /// a grant or a token, of `name`, with `remedy`.
    fn refuse_unsuited_to<const N: usize>(
        what: &str,
        name: &str,
        options: [(bool, &'static str); N],
        remedy: impl FnOnce() -> String,
    ) -> Result<(), CommandFailure> {
        match first_given(options) {
            Some(option) => Err(CommandFailure::with_exit_code(
                anyhow!("{option} does not apply to a {name} {what}\n\n{}", remedy()),
                ExitCode::UsageError,
            )),
            None => Ok(()),
        }
    }

    /// Stores the next version of the member's `token` of `service` (REQ-INTEGRATION-18): the
    /// options of a sign-in are refused with exit 2, then the token is read from `--from-file`,
    /// standard input or a prompt that does not echo, as `connect` reads one, and stored as the
    /// next version, which keeps the record's ID and its authorizations.
    fn replace_token(
        &self,
        deployment: &Deployment,
        token: &IntegrationToken,
        service: &ServedTokenService,
    ) -> CommandResult {
        let name = token.provider.as_str();
        Self::refuse_unsuited_to(
            "token",
            name,
            [
                (self.login, "--login"),
                (self.device, "--device"),
                (self.token_file.is_some(), "--token-file"),
                (self.no_wait, "--no-wait"),
                (self.wait.timeout.is_some(), "--timeout"),
            ],
            || {
                format!(
                    "A {name} token's next version is read from --from-file PATH, from standard \
                     input or at a prompt:\n  useful account integration reconnect {name}"
                )
            },
        )?;
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
        .store(true, |failure| output::token_report(api_url, failure, name))
    }

    /// Runs the consent of the OAuth grant's provider (REQ-GRANT-69), titled as `create` titles
    /// it. When the consent made a grant other than the one named, it was given as another
    /// account: the named grant is as it was, which is reported, naming the grant made, with
    /// exit 1 (REQ-GRANT-73, REQ-GRANT-2). With `--no-wait` it ends once the consent started.
    fn reconsent(&self, deployment: &Deployment, grant: &MemberGrant) -> CommandResult {
        let name = grant.provider.as_str();
        Self::refuse_unsuited(
            name,
            [
                (self.login, "--login"),
                (self.device, "--device"),
                (self.from_file.is_some(), "--from-file"),
                (self.token_file.is_some(), "--token-file"),
            ],
            || {
                format!(
                    "A {name} grant is signed in to again by the provider's consent:\n  \
                     useful account integration reconnect {}",
                    grant.id
                )
            },
        )?;
        let flow = self.flow();
        let title = match ProviderArg::from_name(name).and_then(ProviderArg::consent) {
            Some(consent) => consent.title.to_owned(),
            None => match flow.served_title(deployment, name)? {
                Ok(title) => title,
                Err(exit) => return Ok(exit),
            },
        };
        // A consent that does not complete names this command again, not `create`.
        let consent = ConsentProvider {
            name,
            title: &title,
            reconnects: Some(&grant.id),
        };
        let ended = flow.consent(deployment, consent)?;
        match ended.grant {
            Some(made) if ended.code == ExitCode::Success && made != grant.id => {
                Ok(write_not_reconnected(
                    deployment.fingerprint().api_url(),
                    consent,
                    &grant.id,
                    &made,
                    self.options.json,
                )?)
            }
            _ => Ok(ended.code),
        }
    }

    /// Stores a coding agent's login as the native grant's next generation, in the grant's own
    /// organization (REQ-GRANT-73): the login `read` from the file or stream named, or the coding
    /// agent's own sign-in, run once the checks `create` makes before one pass (REQ-GRANT-70,
    /// REQ-GRANT-71, REQ-GRANT-75).
    fn renew(
        &self,
        deployment: &Deployment,
        grant: &MemberGrant,
        read: Option<Zeroizing<Vec<u8>>>,
    ) -> CommandResult {
        let api_url = deployment.fingerprint().api_url();
        let json = self.options.json;
        let name = grant.provider.as_str();
        let Some(provider) = ProviderArg::from_name(name).filter(|provider| provider.native())
        else {
            let report = output::report(api_url, &MemberGrantFailure::ProviderUnavailable);
            return Ok(output::write_import_refusal(api_url, &report, json)?);
        };
        let again = || format!("useful account integration reconnect {}", grant.id);
        Self::refuse_unsuited(
            name,
            [
                (self.no_wait, "--no-wait"),
                (self.wait.timeout.is_some(), "--timeout"),
            ],
            || {
                format!(
                    "A {name} grant is signed in to again by the coding agent's own sign-in, \
                     which has no consent to wait for:\n  {}",
                    again()
                )
            },
        )?;
        match provider {
            ProviderArg::Codex => {
                Self::refuse_unsuited(name, [(self.token_file.is_some(), "--token-file")], || {
                    format!(
                        "Import a Codex auth.json with --from-file PATH, or sign in with --login \
                         or --device:\n  {} --from-file PATH",
                        again()
                    )
                })?
            }
            _ => Self::refuse_unsuited(
                name,
                [
                    (self.from_file.is_some(), "--from-file"),
                    (self.login, "--login"),
                    (self.device, "--device"),
                ],
                || {
                    format!(
                        "Run Claude Code's sign-in, or import the token claude setup-token \
                         printed with --token-file PATH:\n  {}",
                        again()
                    )
                },
            )?,
        }
        let flow = self.flow();
        let login = match read {
            Some(material) => Login::Read(material),
            None => flow.sign_in_of(provider),
        };
        // A Claude Code sign-in the member could not answer is refused before it starts
        // (REQ-GRANT-71).
        if matches!(login, Login::ClaudeCode)
            && let Some(failure) = claude_setup_token::unanswerable()
        {
            let mut report = failure.report();
            report.remedy = format!(
                "Run claude setup-token where you can answer it and import the token it prints:\n  \
                 {} --token-file -",
                again()
            );
            return Ok(output::write_import_refusal(api_url, &report, json)?);
        }
        if !matches!(login, Login::Read(_))
            && let Err(failure) = flow.with_api(deployment, |api| Flow::check_served(api, name))?
        {
            let report = output::report(api_url, &failure);
            return Ok(output::write_import_refusal(api_url, &report, json)?);
        }
        flow.import(deployment, login, Store::Next(grant))
            .map(|imported| imported.ended.code)
    }
}
