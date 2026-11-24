//! The plan `useful account integration connect --workflow` prints before any sign-in: the
//! providers a workflow tree calls for, derived by `useful workflow doctor`'s grouping
//! ([`Roots`](crate::cli::workflow::doctor::roots::Roots)).

use std::io::{self, Write};

use anyhow::Context;
use serde::Serialize;

use crate::cli::workflow::doctor::report::{
    self as doctor, JsonDeclaration, describe, group_label,
};
use useful_runner::{CredentialRequirement, Declaration, WorkflowCredentials};

/// A provider the tree calls for: what the run does about it, and the requirement whose origins
/// call for it.
pub(super) struct Planned<'a> {
    pub(super) provider: &'static str,
    pub(super) state: State,
    pub(super) requirement: &'a CredentialRequirement,
}

impl Planned<'_> {
    /// Acting as the GitHub App, for `github` selected for a sign-in or needing reconnecting: the
    /// other choice than the member's own sign-in.
    fn alternative(&self) -> Option<&'static str> {
        match self.state {
            State::SignIn | State::Reconnect => super::super::github_app_alternative(self.provider),
            State::Held | State::Host => None,
        }
    }
}

/// What the run does about a provider the tree calls for.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum State {
    /// Selected for a sign-in, since the member lacks it.
    SignIn,
    /// Passed over without a sign-in, since every grant held of it needs reconnecting, which
    /// `useful account integration reconnect` does and this run does not.
    Reconnect,
    /// Passed over as held.
    Held,
    /// Passed over without a sign-in, since the host of the runner `--runner` names supplies it:
    /// the runner last reported its host's own sign-in on an authorization of a grant of the
    /// member's.
    Host,
}

impl State {
    const fn label(self) -> &'static str {
        match self {
            Self::SignIn => "sign in",
            Self::Reconnect => "needs reconnecting",
            Self::Held => "held",
            Self::Host => "host",
        }
    }
}

/// Prints, before any sign-in, the workflow files covered, each provider selected, each passed
/// over as needing reconnecting, each passed over as held and each passed over as supplied by the
/// runner's host, with the origins that call for it, and what the declarations cannot show: as the
/// first JSON event, or as a report on standard output. Without `--runner` no provider is the
/// host's, and the event's `host` is empty.
pub(super) fn write_plan(
    deployment: &str,
    credentials: &WorkflowCredentials,
    planned: &[Planned<'_>],
    json: bool,
) -> anyhow::Result<()> {
    if json {
        let providers = |state: State| {
            planned
                .iter()
                .filter(|entry| entry.state == state)
                .map(|entry| JsonProvider {
                    provider: entry.provider,
                    alternative: entry.alternative(),
                    origins: entry
                        .requirement
                        .origins
                        .iter()
                        .map(JsonDeclaration::from_declaration)
                        .collect(),
                })
                .collect()
        };
        return crate::cli::write_json_line(&JsonPlan {
            schema_version: 1,
            event: "workflow_requirements",
            deployment,
            workflows: &credentials.workflows,
            selected: providers(State::SignIn),
            reconnect: providers(State::Reconnect),
            held: providers(State::Held),
            host: providers(State::Host),
            unknown: credentials
                .unknown
                .iter()
                .map(JsonDeclaration::from_declaration)
                .collect(),
        })
        .context("write JSON grant event");
    }
    let mut stdout = io::stdout().lock();
    write_human_plan_to(&mut stdout, credentials, planned)?;
    stdout.flush()?;
    Ok(())
}

fn write_human_plan_to(
    output: &mut impl Write,
    credentials: &WorkflowCredentials,
    planned: &[Planned<'_>],
) -> io::Result<()> {
    for workflow in &credentials.workflows {
        writeln!(output, "workflow: {workflow}")?;
    }
    writeln!(output)?;
    for entry in planned {
        writeln!(output, "{}: {}", entry.state.label(), entry.provider)?;
        for origin in &entry.requirement.origins {
            write_declaration(output, "  needed by", origin)?;
        }
        if let Some(command) = entry.alternative() {
            writeln!(
                output,
                "  or act as the GitHub App, run by an owner: {command}"
            )?;
        }
    }
    if !planned.is_empty() {
        writeln!(output)?;
    }
    if !credentials.unknown.is_empty() {
        writeln!(
            output,
            "These declarations may use credentials the workflows do not name, and no sign-in is run for them:"
        )?;
        for entry in &credentials.unknown {
            write_declaration(output, "unknown", entry)?;
        }
        writeln!(output)?;
    }
    Ok(())
}

/// `<key>: <workflow file> · <node> · <declaration> [<name>]`, as the doctor names a declaration.
fn write_declaration<K: useful_runner::DeclarationKind + doctor::HumanLabel>(
    output: &mut impl Write,
    key: &str,
    entry: &Declaration<K>,
) -> io::Result<()> {
    writeln!(
        output,
        "{key}: {} · {}",
        group_label(entry),
        describe(entry)
    )
}

/// The first event of `useful account integration connect --workflow --json`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonPlan<'a> {
    schema_version: u8,
    event: &'static str,
    deployment: &'a str,
    workflows: &'a [String],
    selected: Vec<JsonProvider<'a>>,
    reconnect: Vec<JsonProvider<'a>>,
    held: Vec<JsonProvider<'a>>,
    host: Vec<JsonProvider<'a>>,
    unknown: Vec<JsonDeclaration<'a>>,
}

#[derive(Serialize)]
struct JsonProvider<'a> {
    provider: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    alternative: Option<&'static str>,
    origins: Vec<JsonDeclaration<'a>>,
}
