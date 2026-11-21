macro_rules! impl_authenticated_account_outcome {
    ($outcome:ty, $error:ty) => {
        impl super::super::HumanCredentialOutcome for $outcome {
            type Error = $error;

            fn unauthenticated() -> Self {
                Self::Unauthenticated
            }

            fn unreachable(category: useful_api::UnreachableCategory) -> Self {
                Self::Unreachable(category)
            }

            fn is_unauthenticated(&self) -> bool {
                matches!(self, Self::Unauthenticated)
            }

            fn credential_rejected(error: &Self::Error) -> bool {
                error.credential_rejected()
            }
        }
    };
}

mod delegation;
mod delete;
pub(crate) mod grant;
mod identity;
mod invitation;
mod login;
mod logout;
mod restore;
mod service;
mod show;
mod signup;
mod update;

use anyhow::Context;
use clap::{ArgGroup, Args, Subcommand};

use useful_api::{
    HttpClient, HttpTransportPolicy, SignupOutcome, signup_human, update_current_principal,
};
use useful_human_auth::Deployment;
use useful_support::generate_idempotency_key;

pub(super) const ABOUT: &str = "Manage your Useful Machinery account";
const NAME: &str = "account";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<AccountCommand>,
}

#[derive(Debug, Subcommand)]
enum AccountCommand {
    #[command(about = delegation::ABOUT)]
    Delegation(delegation::Command),
    #[command(about = delete::ABOUT, after_help = delete::AFTER_HELP)]
    Delete(delete::Command),
    #[command(about = identity::ABOUT)]
    Identity(identity::Command),
    #[command(about = grant::ABOUT)]
    Integration(grant::Command),
    #[command(about = invitation::ABOUT)]
    Invitation(invitation::Command),
    #[command(about = login::ABOUT)]
    Login(login::Command),
    #[command(about = logout::ABOUT)]
    Logout(logout::Command),
    #[command(about = restore::ABOUT, after_help = restore::AFTER_HELP)]
    Restore(restore::Command),
    #[command(about = service::ABOUT)]
    Service(service::Command),
    #[command(about = show::ABOUT)]
    Show(show::Command),
    #[command(about = signup::ABOUT)]
    Signup(SignupCommand),
    #[command(about = update::ABOUT)]
    Update(UpdateCommand),
}

#[derive(Debug, Args)]
struct SignupCommand {
    #[command(flatten)]
    options: LeafOptions,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("name_change")
        .required(true)
        .multiple(false)
        .args(["name", "clear_name"])
))]
struct UpdateCommand {
    #[arg(long, value_name = "NAME", help = "Set your account display name")]
    name: Option<String>,

    #[arg(long, help = "Clear your account display name")]
    clear_name: bool,

    #[command(flatten)]
    options: PrincipalLeafOptions,
}

type LeafOptions = super::CommonArgs<super::AccountJson, super::NoAuthenticationArgs>;
type PrincipalLeafOptions =
    super::CommonArgs<super::AccountJson, super::PrincipalAuthenticationArgs>;

fn execute_mutation<O>(
    deployment: &Deployment,
    transport_policy: HttpTransportPolicy,
    request_identity_context: &'static str,
    network_context: &'static str,
    api_context: &'static str,
    mut operation: impl FnMut(&HttpClient, &str, &str, &str) -> Result<O, O::Error>,
) -> anyhow::Result<O>
where
    O: super::HumanCredentialOutcome,
{
    let idempotency_key = generate_idempotency_key().context(request_identity_context)?;
    super::execute_with_human_credential(
        deployment,
        transport_policy,
        network_context,
        api_context,
        |client, api_url, access_token| operation(client, api_url, access_token, &idempotency_key),
    )
}

fn execute_signup(command: SignupCommand, deployment: &Deployment) -> super::CommandResult {
    let transport_policy = command.options.http.transport_policy();
    let json = command.options.json;
    let outcome = attempt_signup(deployment, transport_policy)?;
    if json || !matches!(outcome, SignupOutcome::Unauthenticated) {
        return signup::write_outcome(json, deployment.fingerprint().api_url(), &outcome)
            .map_err(Into::into);
    }
    // REQ-ACCOUNT-16: a person without a sign-in signs in as `account login`
    // does and then asks once more.
    let deployment = deployment.clone();
    super::execute_cancellable_with_signals("sign-in", move |cancellation| {
        match login::sign_in_first(&deployment, transport_policy, cancellation)? {
            login::SignIn::Ended(outcome) => Ok(outcome.exit_code()),
            login::SignIn::SignedIn(_) => {
                signup::write_signed_in()?;
                let outcome = attempt_signup(&deployment, transport_policy)?;
                signup::write_outcome(false, deployment.fingerprint().api_url(), &outcome)
                    .map_err(Into::into)
            }
        }
    })
}

fn attempt_signup(
    deployment: &Deployment,
    transport_policy: HttpTransportPolicy,
) -> anyhow::Result<SignupOutcome> {
    execute_mutation(
        deployment,
        transport_policy,
        "create signup request identity",
        "prepare signup networking",
        "create Useful Machinery account through",
        signup_human,
    )
}

fn execute_update(
    command: UpdateCommand,
    deployment: &Deployment,
) -> anyhow::Result<crate::exit_code::ExitCode> {
    let idempotency_key =
        generate_idempotency_key().context("create account update request identity")?;
    let outcome = super::execute_with_principal_credential(
        deployment,
        command.options.http.transport_policy(),
        &command.options.authentication,
        "prepare account update networking",
        "update Useful Machinery account through",
        |client, api_url, access_token| {
            update_current_principal(
                client,
                api_url,
                access_token,
                &idempotency_key,
                command.name.as_deref(),
            )
        },
    )?;
    update::write_outcome(
        command.options.json,
        command.options.authentication.api_key_file.is_some(),
        command.clear_name,
        deployment.fingerprint().api_url(),
        &outcome,
    )
}

impl Command {
    pub(super) fn execute(self) -> super::CommandResult {
        match self.command {
            None => super::print_help(&[NAME]),
            Some(AccountCommand::Delegation(command)) => command.execute(),
            Some(AccountCommand::Delete(command)) => command.execute(),
            Some(AccountCommand::Integration(command)) => command.execute(),
            Some(AccountCommand::Identity(command)) => command.execute(),
            Some(AccountCommand::Invitation(command)) => command.execute(),
            Some(AccountCommand::Login(command)) => {
                execute_sign_in_leaf(command, login::Command::execute)
            }
            Some(AccountCommand::Logout(command)) => {
                execute_sign_in_leaf(command, logout::Command::execute)
            }
            Some(AccountCommand::Restore(command)) => command.execute(),
            Some(AccountCommand::Service(command)) => command.execute(),
            Some(AccountCommand::Show(command)) => {
                execute_sign_in_leaf(command, show::Command::execute)
            }
            Some(AccountCommand::Signup(command)) => super::execute_deployment_command(
                Some(command),
                &[NAME],
                "configure Useful Machinery account",
                execute_signup,
            ),
            Some(AccountCommand::Update(command)) => super::execute_deployment_leaf(
                command,
                &[NAME],
                "configure Useful Machinery account",
                execute_update,
            ),
        }
    }
}

fn execute_sign_in_leaf<T>(
    command: T,
    execute: impl FnOnce(T, &Deployment) -> super::CommandResult,
) -> super::CommandResult {
    super::execute_deployment_command(
        Some(command),
        &[NAME],
        "configure Useful Machinery sign-in",
        execute,
    )
}
