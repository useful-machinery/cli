//! `useful org integration show`: one connection with the runners' authorizations in force for
//! it, a Linear authorization session, a GitHub setup session, or the organization's token of
//! a token service.
use clap::Args;
use useful_human_auth::Deployment;

use super::authorization::{self, InForce};
use super::list::{Options, Provider, Record};
use super::target::{self, Integration, Resolved, Target};
use super::token::{OrgTokens, member_session};
use super::{github, gitlab, linear};
use crate::cli::CommandResult;
use crate::cli::context::{self, OrgArgs};
use crate::exit_code::ExitCode;

pub(super) const ABOUT: &str = "Show one of the organization's connections or tokens";
const AFTER_HELP: &str = "INTEGRATION may also be the ID of a Linear authorization session or a GitHub setup session that connecting or reconnecting printed; only the owner who started that session can read it.";

#[derive(Debug, Args)]
#[command(after_help = AFTER_HELP)]
pub(super) struct Command {
    #[arg(value_name = target::VALUE_NAME, value_parser = parse, help = Integration::HELP)]
    connection: Shown,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: Options,
}

/// What `show` reads: a connection, a Linear authorization session or a GitHub setup session by
/// its ID, or the organization's token of a token service.
#[derive(Clone, Debug)]
enum Shown {
    Connection(Target),
    Session(String),
    SetupSession(String),
    Token(String),
}

fn parse(value: &str) -> Result<Shown, String> {
    if useful_support::valid_typed_id(value, "las_") {
        return Ok(Shown::Session(value.to_owned()));
    }
    if useful_support::valid_typed_id(value, "ghs_") {
        return Ok(Shown::SetupSession(value.to_owned()));
    }
    match Integration::parse(value) {
        Ok(Integration::Connection(target)) => Ok(Shown::Connection(target)),
        Ok(Integration::Token(service)) => Ok(Shown::Token(service)),
        Err(_) => Err(
            "integration must be an exact ghi_, glc_, lcn_, las_ or ghs_ identifier, github, \
             gitlab or linear, or a token service's name"
                .to_owned(),
        ),
    }
}

impl Command {
    pub(super) fn execute(self, deployment: &Deployment) -> CommandResult {
        let Self {
            connection,
            org,
            options,
        } = self;
        if let Shown::Token(service) = &connection {
            member_session(
                &options.authentication,
                &format!(
                    "{service}, which is not github, gitlab or linear and so can only name a token service"
                ),
            )?;
        }
        context::execute_in(
            org,
            options,
            deployment,
            super::super::output::write_context_failure,
            |options, organization| match connection {
                Shown::Session(session) => {
                    linear::show_session(deployment, &options, organization, &session)
                }
                Shown::SetupSession(session) => {
                    github::show_setup_session(deployment, &options, organization, &session)
                }
                Shown::Token(service) => OrgTokens {
                    deployment,
                    policy: options.http.transport_policy(),
                    json: options.json,
                    organization,
                }
                .show(&service),
                Shown::Connection(target) => {
                    let resolved =
                        match target::resolve(target, deployment, &options, organization)? {
                            Ok(resolved) => resolved,
                            Err(exit) => return Ok(exit),
                        };
                    match authorization::of_connection(
                        deployment,
                        &options,
                        organization,
                        resolved.id(),
                    )? {
                        Ok(authorizations) => show(
                            deployment,
                            &options,
                            organization,
                            resolved,
                            authorizations.as_ref(),
                        ),
                        Err(exit) => Ok(exit),
                    }
                }
            },
        )
    }
}

fn show(
    deployment: &Deployment,
    options: &Options,
    organization: &str,
    resolved: Resolved,
    authorizations: Option<&InForce>,
) -> anyhow::Result<ExitCode> {
    if let Resolved::Listed(Record::Github(installation)) = resolved {
        return github::show_installation(
            deployment,
            options,
            organization,
            installation,
            authorizations,
        );
    }
    let id = resolved.id();
    match resolved.provider() {
        Provider::Github => {
            github::show_binding(deployment, options, organization, id, authorizations)
        }
        Provider::Gitlab => gitlab::show(deployment, options, organization, id, authorizations),
        Provider::Linear => linear::show(deployment, options, organization, id, authorizations),
    }
}
