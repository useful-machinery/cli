//! The report of `useful workflow doctor`: the credentials a workflow tree declares, each judged
//! met, failing or unverified on what Cloud showed of the organization's connections and, with
//! `--runner`, of the member's grants on that runner, with what the member holds of each provider
//! beside it and where a declaring file's integrations and the inference differ, printed as a
//! checklist or a JSON document.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Serialize;

use crate::exit_code::ExitCode;
use useful_runner::{
    CredentialKind, CredentialRequirement, Declaration, DeclarationKind, DerivedCredentials,
    Difference, IntegrationDifference, Node, NodeKind, OriginDeclaration, ReadinessCode,
    RepositorySource, UnknownDeclaration, WorkflowCredentials, read_workflow_credentials,
};

use super::authorizations::{Authorization, InForce};
use super::grants::{Held, OnRunner, ProviderView};
use super::slack::{self, Bindings, ReadFailure, SlackFinding};

/// The credentials the tree under `source_root` needs, or `None` once the first file that does
/// not resolve was rejected as `useful workflow validate` rejects it.
pub(super) fn derive(
    source_root: &Path,
    workflow_files: &[PathBuf],
    repository: RepositorySource,
    json: bool,
) -> anyhow::Result<Option<DerivedCredentials>> {
    match read_workflow_credentials(source_root, workflow_files, repository) {
        Ok(derived) => Ok(Some(derived)),
        Err(failure) => {
            if json {
                crate::cli::workflow::validate::write_json_invalid(&failure)
            } else {
                crate::cli::workflow::validate::write_human_invalid(&failure)
            }
            .context("write workflow validation result")?;
            Ok(None)
        }
    }
}

const MET: &str = "met";

/// What meets a requirement: the runner's host, a grant the runner can use, or a connection Cloud
/// holds ready, named in that order when several do.
#[derive(Clone, Copy)]
enum MetBy {
    Host,
    Grant,
    Connection,
}

impl MetBy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Grant => "grant",
            Self::Connection => "connection",
        }
    }

    const fn code(self) -> &'static str {
        match self {
            Self::Host => "host_login",
            Self::Grant => "grant_usable",
            Self::Connection => "connection_ready",
        }
    }
}

/// A requirement as the report judges it: its state, its code, what meets it when it is met,
/// and what the operator can do about it.
struct Verdict {
    state: &'static str,
    code: &'static str,
    met_by: Option<MetBy>,
    next_action: String,
}

impl Verdict {
    /// Whether the requirement fails the report.
    fn fails(&self) -> bool {
        !matches!(self.state, MET | "unverified")
    }
}

/// The derivation's result, after any Cloud reads, and what the report names beside it.
pub(super) struct Report<'a> {
    pub(super) credentials: WorkflowCredentials,
    /// Where a declaring file's integrations and the inference differ, when a named file
    /// declares them; they change no requirement, count or exit status.
    pub(super) differences: Option<Vec<IntegrationDifference>>,
    /// Slack warnings, present when a named file declares a Slack block.
    pub(super) slack: Option<Vec<SlackFinding>>,
    /// The organization in effect, for the next actions, when Cloud was asked.
    pub(super) organization: Option<&'a str>,
    /// The project in effect, for the next actions.
    pub(super) project: Option<&'a str>,
    /// The GitHub connection authorization read for the project in effect and `--runner`:
    /// `None` when it was not read or the read was passed over, else the one in force or
    /// none.
    pub(super) authorization: Option<Authorization<'a>>,
    /// The member's grants, when they were read.
    pub(super) grants: Option<Held<'a>>,
    /// The deployment asked, when a read was made.
    pub(super) deployment: Option<&'a str>,
}

impl<'a> Report<'a> {
    /// The report of a derivation no Cloud read was made for.
    pub(super) fn unread(derived: DerivedCredentials, bindings: &Bindings) -> Self {
        let slack = slack::unread(&derived.slack, bindings, ReadFailure::NotSignedIn);
        Self::from_derived(derived, slack)
    }

    pub(super) fn from_derived(
        derived: DerivedCredentials,
        slack: Option<Vec<SlackFinding>>,
    ) -> Self {
        Self {
            credentials: derived.reported,
            differences: derived.differences,
            slack,
            organization: None,
            project: None,
            authorization: None,
            grants: None,
            deployment: None,
        }
    }

    /// The connection authorization read beside the requirement, which only `github`
    /// has.
    fn authorization(&self, requirement: &CredentialRequirement) -> Option<&Authorization<'a>> {
        self.authorization
            .as_ref()
            .filter(|_| requirement.kind == CredentialKind::Github)
    }

    /// What the report makes of `requirement`. With a runner named, its host and then a grant it
    /// can use meet a requirement; then a connection Cloud holds ready does. A requirement
    /// nothing meets keeps the failing state its connection read gave it; else, with a runner
    /// named and a read that could be made, it takes the state of the member's grants on that
    /// runner; else it stays as its read left it.
    fn verdict(&self, requirement: &CredentialRequirement) -> Verdict {
        let runner = self.grants.as_ref().and_then(Held::runner);
        let on_runner = self
            .grants
            .as_ref()
            .and_then(|held| held.on_runner(requirement.kind));
        let title = requirement.kind.title();
        let met = |met_by: MetBy, next_action: String| Verdict {
            state: MET,
            code: met_by.code(),
            met_by: Some(met_by),
            next_action,
        };
        let runner_name = runner.unwrap_or("RUNNER");
        let shortfall = match on_runner {
            Some(OnRunner::Host) => {
                return met(
                    MetBy::Host,
                    format!(
                        "The host of runner {runner_name} supplies its own {title} login, which the runner uses before a grant."
                    ),
                );
            }
            Some(OnRunner::Grant) => {
                return met(
                    MetBy::Grant,
                    format!("A {title} grant of yours is in place on runner {runner_name}."),
                );
            }
            Some(OnRunner::Shortfall(shortfall)) => Some(shortfall),
            None => None,
        };
        let read = || requirement.next_action(self.organization, self.project);
        if requirement.code == ReadinessCode::RunnerUnverified && requirement.cloud().is_some() {
            return met(MetBy::Connection, read());
        }
        match shortfall {
            Some(shortfall)
                if !requirement.fails()
                    && !matches!(
                        requirement.code,
                        ReadinessCode::NotPermitted | ReadinessCode::ProviderUnavailable
                    ) =>
            {
                Verdict {
                    state: shortfall.state.as_str(),
                    code: shortfall.code,
                    met_by: None,
                    next_action: shortfall.next_action,
                }
            }
            _ => Verdict {
                state: requirement.state(),
                code: requirement.code.as_str(),
                met_by: None,
                next_action: read(),
            },
        }
    }

    /// The requirements by state, and the unknown entries.
    fn summary(&self) -> Summary {
        let mut summary = Summary {
            unknown: self.credentials.unknown.len(),
            ..Summary::default()
        };
        for requirement in &self.credentials.requirements {
            let count = match self.verdict(requirement).state {
                MET => &mut summary.met,
                "missing" => &mut summary.missing,
                "reconnect_required" => &mut summary.reconnect_required,
                "insufficient_permission" => &mut summary.insufficient_permission,
                _ => &mut summary.unverified,
            };
            *count += 1;
        }
        summary
    }

    /// Whether a requirement reads `missing`, `reconnect_required` or
    /// `insufficient_permission`.
    fn fails(&self) -> bool {
        self.credentials
            .requirements
            .iter()
            .any(|requirement| self.verdict(requirement).fails())
    }

    /// Writes the report; the command fails when a requirement does.
    pub(super) fn write(&self, json: bool) -> anyhow::Result<ExitCode> {
        if json {
            super::super::super::write_pretty_json(&JsonReport::from_report(self))
                .context("write JSON workflow doctor report")?;
        } else {
            let stdout = io::stdout();
            let mut stdout = stdout.lock();
            write_human_report_to(&mut stdout, self).context("write workflow doctor report")?;
        }
        Ok(if self.fails() {
            ExitCode::GeneralFailure
        } else {
            ExitCode::Success
        })
    }
}

/// The requirements counted by state, and the unknown entries.
#[derive(Default)]
struct Summary {
    met: usize,
    missing: usize,
    reconnect_required: usize,
    insufficient_permission: usize,
    unverified: usize,
    unknown: usize,
}

fn write_human_report_to(output: &mut impl Write, report: &Report<'_>) -> io::Result<()> {
    let credentials = &report.credentials;
    writeln!(output, "Useful Machinery workflow doctor")?;
    writeln!(output)?;
    for workflow in &credentials.workflows {
        writeln!(output, "workflow: {workflow}")?;
    }
    if let Some(deployment) = report.deployment {
        writeln!(output, "deployment: {deployment}")?;
    }
    writeln!(output)?;

    if credentials.requirements.is_empty() {
        writeln!(output, "✓ The workflows declare no credentials.")?;
        writeln!(output)?;
    }
    for requirement in &credentials.requirements {
        write_requirement(output, requirement, report)?;
    }

    if !credentials.unknown.is_empty() {
        writeln!(output, "── unknown ──")?;
        writeln!(
            output,
            "These declarations may use credentials the workflows do not name."
        )?;
        // The entries of no workflow file come last, under their own heading.
        let mut current_group = None;
        for entry in &credentials.unknown {
            let group = group_label(entry);
            if current_group != Some(group) {
                writeln!(output, "{group}")?;
                current_group = Some(group);
            }
            writeln!(output, "  {}", describe(entry))?;
        }
        writeln!(output)?;
    }

    if let Some(differences) = report.differences.as_deref()
        && !differences.is_empty()
    {
        writeln!(output, "── differences ──")?;
        writeln!(
            output,
            "The declared integrations differ from what the workflows' other declarations call for."
        )?;
        let mut current_workflow = None;
        for difference in differences {
            if current_workflow != Some(&difference.workflow) {
                writeln!(output, "{}", difference.workflow)?;
                current_workflow = Some(&difference.workflow);
            }
            writeln!(output, "  ! {}", describe_difference(difference))?;
        }
        writeln!(output)?;
    }

    if let Some(findings) = &report.slack {
        slack::write_human(output, findings)?;
    }

    let summary = report.summary();
    writeln!(output, "── summary ──")?;
    writeln!(output, "met: {}", summary.met)?;
    writeln!(output, "missing: {}", summary.missing)?;
    writeln!(output, "reconnect required: {}", summary.reconnect_required)?;
    writeln!(
        output,
        "insufficient permission: {}",
        summary.insufficient_permission
    )?;
    writeln!(output, "unverified: {}", summary.unverified)?;
    writeln!(output, "unknown: {}", summary.unknown)?;
    if let Some(differences) = &report.differences {
        writeln!(output, "differences: {}", differences.len())?;
    }
    Ok(())
}

/// `<provider id> · not declared · needed by: <origins>`, or `<provider id> · declared · not
/// otherwise called for`, without the workflow file. The provider id is the key of
/// `requires.integrations` to declare or the one declared, `gitlab.com` for the kind
/// `gitlab`.
fn describe_difference(difference: &IntegrationDifference) -> String {
    let provider = difference.integration.as_str();
    match difference.difference {
        Difference::InferredNotDeclared => {
            let origins = difference
                .origins
                .iter()
                .map(|origin| format!("{} · {}", group_label(origin), describe(origin)))
                .collect::<Vec<_>>();
            format!(
                "{provider} · not declared · needed by: {}",
                origins.join("; ")
            )
        }
        Difference::DeclaredNotInferred => {
            format!("{provider} · declared · not otherwise called for")
        }
    }
}

fn write_requirement(
    output: &mut impl Write,
    requirement: &CredentialRequirement,
    report: &Report<'_>,
) -> io::Result<()> {
    let verdict = report.verdict(requirement);
    let marker = match verdict.met_by {
        Some(_) => '✓',
        None if verdict.fails() => '✗',
        None => '!',
    };
    writeln!(output, "{marker} {}", requirement.kind.title())?;
    writeln!(output, "  kind: {}", requirement.kind.as_str())?;
    writeln!(output, "  state: {}", verdict.state)?;
    if let Some(met_by) = verdict.met_by {
        writeln!(output, "  met by: {}", met_by.as_str())?;
    }
    writeln!(output, "  code: {}", verdict.code)?;
    if let Some(cloud) = requirement.cloud() {
        writeln!(output, "  cloud: {cloud}")?;
    }
    if let Some(authorization) = report.authorization(requirement) {
        authorization.write_human(output)?;
    }
    for origin in &requirement.origins {
        writeln!(
            output,
            "  needed by: {} · {}",
            group_label(origin),
            describe(origin)
        )?;
    }
    writeln!(output)?;
    writeln!(output, "  {}", verdict.next_action)?;
    // A kind with no grant provider, a token service, has no grants to show.
    if let Some(held) = report
        .grants
        .as_ref()
        .and_then(|held| held.of(requirement.kind))
    {
        writeln!(output)?;
        held.write_human(output)?;
    }
    writeln!(output)
}

/// The human label of a declaration; the JSON document carries its stable identifier.
pub(in crate::cli) trait HumanLabel {
    fn label(self) -> &'static str;
}

impl HumanLabel for OriginDeclaration {
    fn label(self) -> &'static str {
        match self {
            Self::Integration => "declared integration",
            Self::AgentProfile => "agent profile",
            Self::ForwardedVariable => "forwarded variable",
            Self::Binding => "binding",
            Self::Mirror => "Linear mirror",
            Self::RequiredTool => "required tool",
            Self::Repository => "repository",
        }
    }
}

impl HumanLabel for UnknownDeclaration {
    fn label(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::Agent => "agent",
            Self::PiHarness => "Pi harness",
            Self::ForwardedVariable => "forwarded variable",
            Self::ConnectionBinding => "connection binding",
            Self::Repository => "repository",
        }
    }
}

/// The workflow file a declaration sits in, or the source root for the repository's.
pub(in crate::cli) fn group_label<K>(entry: &Declaration<K>) -> &str {
    entry.workflow.as_deref().unwrap_or("source root")
}

/// `<node> · <declaration> [<name>]`, without the workflow file.
pub(in crate::cli) fn describe<K: DeclarationKind + HumanLabel>(entry: &Declaration<K>) -> String {
    let mut parts = Vec::new();
    if let Some(node) = &entry.node {
        parts.push(format!("{} {}", node_label(node.kind), node.id));
    }
    parts.push(match &entry.name {
        Some(name) => format!("{} {name}", entry.declaration.label()),
        None => entry.declaration.label().to_owned(),
    });
    parts.join(" · ")
}

const fn node_label(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::Step => "step",
        NodeKind::Finalizer => "finalizer",
        NodeKind::RecoveryHandler => "recovery handler",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonReport<'a> {
    schema_version: u8,
    command: &'static str,
    deployment: Option<&'a str>,
    workflows: &'a [String],
    requirements: Vec<JsonRequirement<'a>>,
    unknown: Vec<JsonDeclaration<'a>>,
    /// Present when a named file declares its integrations.
    #[serde(skip_serializing_if = "Option::is_none")]
    differences: Option<Vec<JsonDifference<'a>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slack: Option<&'a [SlackFinding]>,
    summary: JsonSummary,
}

impl<'a> JsonReport<'a> {
    fn from_report(report: &'a Report<'a>) -> Self {
        let credentials = &report.credentials;
        let summary = report.summary();
        Self {
            schema_version: 1,
            command: super::COMMAND_NAME,
            deployment: report.deployment,
            workflows: &credentials.workflows,
            requirements: credentials
                .requirements
                .iter()
                .map(|requirement| JsonRequirement::from_requirement(requirement, report))
                .collect(),
            unknown: credentials
                .unknown
                .iter()
                .map(JsonDeclaration::from_declaration)
                .collect(),
            differences: report.differences.as_ref().map(|differences| {
                differences
                    .iter()
                    .map(JsonDifference::from_difference)
                    .collect()
            }),
            slack: report.slack.as_deref(),
            summary: JsonSummary {
                met: summary.met,
                missing: summary.missing,
                reconnect_required: summary.reconnect_required,
                insufficient_permission: summary.insufficient_permission,
                unverified: summary.unverified,
                unknown: summary.unknown,
                differences: report.differences.as_ref().map(Vec::len),
            },
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonRequirement<'a> {
    kind: &'static str,
    state: &'static str,
    /// What meets the requirement, present only when it is met.
    #[serde(skip_serializing_if = "Option::is_none")]
    met_by: Option<&'static str>,
    code: &'static str,
    /// Present on the kinds Cloud holds: `github`, `gitlab` and `linear`.
    #[serde(skip_serializing_if = "Option::is_none")]
    cloud: Option<&'static str>,
    next_action: String,
    origins: Vec<JsonDeclaration<'a>>,
    /// On `github`, where it was read, the connection authorization in force, or `null` where
    /// none is.
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_authorization: Option<Option<&'a InForce>>,
    /// What the member holds of the kind's provider, when the grants were
    /// read.
    #[serde(skip_serializing_if = "Option::is_none")]
    grant: Option<ProviderView<'a>>,
}

impl<'a> JsonRequirement<'a> {
    fn from_requirement(requirement: &'a CredentialRequirement, report: &'a Report<'a>) -> Self {
        let verdict = report.verdict(requirement);
        Self {
            kind: requirement.kind.as_str(),
            state: verdict.state,
            met_by: verdict.met_by.map(MetBy::as_str),
            code: verdict.code,
            cloud: requirement.cloud(),
            next_action: verdict.next_action,
            origins: requirement
                .origins
                .iter()
                .map(JsonDeclaration::from_declaration)
                .collect(),
            connection_authorization: report
                .authorization(requirement)
                .map(Authorization::in_force),
            grant: report
                .grants
                .as_ref()
                .and_then(|held| held.of(requirement.kind)),
        }
    }
}

#[derive(Serialize)]
struct JsonDifference<'a> {
    difference: &'static str,
    workflow: &'a str,
    kind: &'static str,
    integration: &'static str,
    /// The declarations that call for the kind, on `inferred_not_declared`.
    #[serde(skip_serializing_if = "Option::is_none")]
    origins: Option<Vec<JsonDeclaration<'a>>>,
}

impl<'a> JsonDifference<'a> {
    fn from_difference(difference: &'a IntegrationDifference) -> Self {
        Self {
            difference: difference.difference.as_str(),
            workflow: &difference.workflow,
            kind: difference.kind.as_str(),
            integration: difference.integration.as_str(),
            origins: match difference.difference {
                Difference::InferredNotDeclared => Some(
                    difference
                        .origins
                        .iter()
                        .map(JsonDeclaration::from_declaration)
                        .collect(),
                ),
                Difference::DeclaredNotInferred => None,
            },
        }
    }
}

#[derive(Serialize)]
pub(in crate::cli) struct JsonDeclaration<'a> {
    declaration: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    workflow: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<JsonNode<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
}

impl<'a> JsonDeclaration<'a> {
    pub(in crate::cli) fn from_declaration<K: DeclarationKind>(entry: &'a Declaration<K>) -> Self {
        Self {
            declaration: entry.declaration.as_str(),
            workflow: entry.workflow.as_deref(),
            node: entry.node.as_ref().map(JsonNode::from_node),
            name: entry.name.as_deref(),
        }
    }
}

#[derive(Serialize)]
struct JsonNode<'a> {
    kind: &'static str,
    id: &'a str,
}

impl<'a> JsonNode<'a> {
    fn from_node(node: &'a Node) -> Self {
        Self {
            kind: node.kind.as_str(),
            id: &node.id,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonSummary {
    met: usize,
    missing: usize,
    reconnect_required: usize,
    insufficient_permission: usize,
    unverified: usize,
    unknown: usize,
    /// Present when a named file declares its integrations.
    #[serde(skip_serializing_if = "Option::is_none")]
    differences: Option<usize>,
}
