use std::io::{self, Write};

use anyhow::{Context, anyhow};
use serde::Serialize;

use crate::exit_code::{ExitCode, OutcomeClass};
use useful_api::{
    Project, ProjectFailure, ProjectList, ProjectReadinessBlocker, ProjectRepository,
};

pub(super) fn write_project(
    deployment: &str,
    result: Result<Project, ProjectFailure>,
    outcome: &'static str,
    heading: &'static str,
    authentication: super::super::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    match result {
        Ok(project) => write_success(deployment, outcome, heading, None, &project, json),
        Err(failure) => write_failure(deployment, failure, authentication, json),
    }
}

/// The result of `useful project update`: outcome `updated` with `applied`, what it sent and
/// succeeded in order, and the project as its last request returned it (REQ-PROJECT-102).
pub(super) fn write_updated(
    deployment: &str,
    applied: &[&'static str],
    project: &Project,
    json: bool,
) -> anyhow::Result<ExitCode> {
    write_success(
        deployment,
        "updated",
        "✓ Project updated.",
        Some(applied),
        project,
        json,
    )
}

fn write_success(
    deployment: &str,
    outcome: &'static str,
    heading: &'static str,
    applied: Option<&[&'static str]>,
    project: &Project,
    json: bool,
) -> anyhow::Result<ExitCode> {
    if json {
        write_json(&ProjectResult {
            schema_version: 1,
            deployment,
            outcome,
            applied,
            project,
        })?;
    } else {
        write_project_human(deployment, heading, project)?;
    }
    Ok(ExitCode::Success)
}

pub(super) fn write_project_list(
    deployment: &str,
    result: Result<ProjectList, ProjectFailure>,
    authentication: super::super::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    match result {
        Ok(page) => {
            if json {
                write_paginated_list_json(deployment, &page.items, page.next_cursor.as_deref())?;
            } else {
                let mut stdout = io::stdout().lock();
                writeln!(stdout, "✓ Projects listed.\n")?;
                for project in &page.items {
                    writeln!(
                        stdout,
                        "project: {} · name: {} · readiness: {}{}",
                        project.id,
                        project.name,
                        readiness(project),
                        if project.archived_at.is_some() {
                            " · archived"
                        } else {
                            ""
                        }
                    )?;
                    if !project.execution_readiness.blockers.is_empty() {
                        writeln!(
                            stdout,
                            "  blockers: {}",
                            blocker_list(&project.execution_readiness.blockers)
                        )?;
                    }
                    if project.repository.as_deref().is_some_and(admission_closed) {
                        writeln!(stdout, "  admission: GitLab run admission is closed")?;
                    }
                }
                write_list_footer(
                    &mut stdout,
                    !page.items.is_empty(),
                    page.next_cursor.as_deref(),
                    deployment,
                )?;
            }
            Ok(ExitCode::Success)
        }
        Err(failure) => write_failure(deployment, failure, authentication, json),
    }
}

fn write_paginated_list_json(
    deployment: &str,
    items: &[impl Serialize],
    next_cursor: Option<&str>,
) -> anyhow::Result<()> {
    super::super::write_cloud_list_json(deployment, items, next_cursor)
        .context("write JSON project list result")
}

fn write_list_footer(
    output: &mut impl Write,
    has_items: bool,
    next_cursor: Option<&str>,
    deployment: &str,
) -> io::Result<()> {
    if has_items {
        writeln!(output)?;
    }
    if let Some(cursor) = next_cursor {
        writeln!(output, "next cursor: {cursor}")?;
    }
    writeln!(output, "deployment: {deployment}")
}

fn write_project_human(deployment: &str, heading: &str, project: &Project) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{heading}\n")?;
    writeln!(stdout, "project: {}", project.id)?;
    writeln!(stdout, "name: {}", project.name)?;
    writeln!(stdout, "organization: {}", project.organization_id)?;
    let runner_pools = project.runner_pools.as_deref().unwrap_or_default();
    if runner_pools.is_empty() {
        writeln!(stdout, "runner pool: none")?;
    }
    for pool in runner_pools {
        writeln!(stdout, "runner pool: {} ({})", pool.name, pool.id)?;
    }
    match project.repository.as_deref() {
        Some(repository) => {
            writeln!(stdout, "repository: {}", repository.full_name)?;
            writeln!(
                stdout,
                "provider: {}",
                enum_text(&repository.provider_kind)?
            )?;
            writeln!(
                stdout,
                "repository connection: {}",
                repository.connection_id
            )?;
            if let Some(installation) = &repository.installation_binding_id {
                writeln!(stdout, "installation: {installation}")?;
            }
            if let Some(connection) = &repository.gitlab_connection_id {
                writeln!(stdout, "GitLab connection: {connection}")?;
            }
            if let Some(instance_url) = &repository.instance_url {
                writeln!(stdout, "GitLab instance: {instance_url}")?;
            }
            writeln!(
                stdout,
                "provider repository: {}",
                repository.provider_repository_id
            )?;
            writeln!(stdout, "default branch: {}", repository.default_branch)?;
            if admission_closed(repository) {
                writeln!(stdout, "admission: GitLab run admission is closed")?;
            }
            writeln!(
                stdout,
                "repository availability: {}",
                enum_text(&repository.availability)?
            )?;
        }
        None => writeln!(stdout, "repository: none")?,
    }
    writeln!(stdout, "readiness: {}", readiness(project))?;
    writeln!(
        stdout,
        "blockers: {}",
        if project.execution_readiness.blockers.is_empty() {
            "none".to_owned()
        } else {
            blocker_list(&project.execution_readiness.blockers)
        }
    )?;
    writeln!(stdout, "created: {}", project.created_at)?;
    writeln!(stdout, "updated: {}", project.updated_at)?;
    if let Some(archived_at) = &project.archived_at {
        writeln!(stdout, "archived: {archived_at}")?;
    }
    writeln!(stdout, "deployment: {deployment}")?;
    Ok(())
}

fn admission_closed(repository: &ProjectRepository) -> bool {
    repository.admission_diagnostic.is_some()
}

fn readiness(project: &Project) -> &'static str {
    if project.execution_readiness.ready {
        "ready"
    } else {
        "blocked"
    }
}

pub(in crate::cli) fn blocker_list(blockers: &[ProjectReadinessBlocker]) -> String {
    blockers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn enum_text(value: &impl Serialize) -> anyhow::Result<String> {
    match serde_json::to_value(value).context("serialize project field")? {
        serde_json::Value::String(value) => Ok(value),
        _ => Err(anyhow!("project field is not a contracted string")),
    }
}

pub(super) fn write_failure(
    deployment: &str,
    failure: ProjectFailure,
    authentication: super::super::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let failure = Failure::of(deployment, &failure, authentication);
    super::super::write_api_failure(
        deployment,
        failure.outcome,
        failure.category,
        failure.retry_after,
        &failure.human,
        failure.class,
        json,
    )
    .context("write project failure")
}

/// A request that failed after an earlier request of the same command succeeded, whose change
/// stays (REQ-PROJECT-76): the command exits with the failure's code. Under `--json` the result
/// is the failure's document with `applied`, what was sent and succeeded in order, and
/// `project`, the project as the last successful request returned it; in human output the
/// failure's diagnostic is followed by `kept`, what stays and how to finish.
pub(super) fn write_partial_failure(
    deployment: &str,
    failure: ProjectFailure,
    applied: &[&'static str],
    project: &Project,
    kept: &str,
    authentication: super::super::PrincipalAuthenticationKind,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let failure = Failure::of(deployment, &failure, authentication);
    if json {
        write_json(&PartialFailure {
            failure: super::super::ApiFailureResult::with_retry_after(
                deployment,
                failure.outcome,
                failure.category,
                failure.retry_after,
            ),
            applied,
            project,
        })?;
    } else {
        writeln!(io::stderr().lock(), "{}\n\n{kept}", failure.human)
            .context("write project failure")?;
    }
    Ok(failure.class.exit_code())
}

/// A project failure as its closed outcome, its category and retry delay, its human
/// diagnostic and its outcome class.
struct Failure {
    outcome: &'static str,
    category: Option<&'static str>,
    retry_after: Option<u64>,
    human: String,
    class: OutcomeClass,
}

impl Failure {
    fn of(
        deployment: &str,
        failure: &ProjectFailure,
        authentication: super::super::PrincipalAuthenticationKind,
    ) -> Self {
        let (outcome, category, human, class) = match *failure {
        ProjectFailure::Unauthenticated => (
            "unauthenticated",
            None,
            authentication
                .rejected_error(
                    "error: Useful Machinery access requires sign-in\n\nSign in first:\n  useful account login",
                )
                .to_owned(),
            OutcomeClass::Unauthenticated,
        ),
        ProjectFailure::Forbidden => (
            "forbidden",
            None,
            "error: Useful Machinery operation is not permitted for this account\n\nAsk an organization owner to perform this operation.".to_owned(),
            OutcomeClass::Forbidden,
        ),
        ProjectFailure::InvalidInput => (
            "invalid_input",
            None,
            format!("error: request input rejected by {deployment}\n\nCheck the organization, project, repository, pool, and option values, then try again."),
            OutcomeClass::GeneralFailure,
        ),
        ProjectFailure::NotFound => (
            "not_found",
            None,
            "error: Useful Machinery resource not found or unavailable\n\nCheck the organization and resource identifier, then try again.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        ProjectFailure::RepositoryNotBound => (
            "repository_not_bound",
            None,
            "error: project has no repository binding\n\nBind a repository first:\n  useful project update PROJECT --repository REPOSITORY".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        ProjectFailure::NameUnavailable => (
            "name_unavailable",
            None,
            "error: project name unavailable\n\nChoose another name and try again.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        ProjectFailure::QuantityLimitReached => (
            "quantity_limit_reached",
            None,
            "error: project quantity limit reached\n\nArchive a project that is no longer needed or ask the deployment operator to raise the limit.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        ProjectFailure::RateLimited { retry_after } => (
            "rate_limited",
            None,
            format!(
                "error: project creation rate limited\n\nTry again in {retry_after} seconds."
            ),
            OutcomeClass::RateLimited,
        ),
        ProjectFailure::ProviderUnavailable { retry_after } => (
            "provider_unavailable",
            None,
            format!(
                "error: GitHub or GitLab is temporarily unavailable\n\nTry again in {retry_after} seconds."
            ),
            OutcomeClass::Unreachable,
        ),
        ProjectFailure::IdempotencyConflict => (
            "idempotency_conflict",
            None,
            "error: project request identity conflicted with another request\n\nRun the command again to use a new request identity.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        ProjectFailure::SourceConflict => (
            "source_conflict",
            None,
            "error: selected GitHub repository or branch is unavailable\n\nList the installation repositories and choose an available repository and branch.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        ProjectFailure::RepositoryUnavailable => (
            "repository_unavailable",
            None,
            "error: selected GitLab repository or branch is unavailable\n\nCheck the GitLab connection, selection, and branch before retrying.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        ProjectFailure::ProjectArchived => (
            "project_archived",
            None,
            "error: project is archived\n\nAs an organization owner, unarchive the project first:\n  useful project unarchive PROJECT".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        ProjectFailure::Conflict => (
            "conflict",
            None,
            "error: project request conflicts with current state\n\nShow the project and try again with its current configuration.".to_owned(),
            OutcomeClass::GeneralFailure,
        ),
        ProjectFailure::Unreachable(category) => (
            "unreachable",
            Some(category.as_str()),
            format!(
                "error: contact Useful Machinery API at {deployment}: {}\n\nCheck network access to the deployment and try again.",
                category.as_str()
            ),
            super::super::unreachable_outcome_class(category),
        ),
        ProjectFailure::Protocol { .. } => (
            "invalid_response",
            None,
            "error: Useful Machinery API response does not match the public contract\n\nTry again later.".to_owned(),
            OutcomeClass::Protocol,
        ),
    };
        let retry_after = match *failure {
            ProjectFailure::RateLimited { retry_after }
            | ProjectFailure::ProviderUnavailable { retry_after } => Some(retry_after),
            _ => None,
        };
        Self {
            outcome,
            category,
            retry_after,
            human,
            class,
        }
    }
}

fn write_json(value: &impl Serialize) -> anyhow::Result<()> {
    super::super::write_pretty_json(value).context("write JSON project result")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectResult<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    applied: Option<&'a [&'static str]>,
    project: &'a Project,
}

#[derive(Serialize)]
struct PartialFailure<'a> {
    #[serde(flatten)]
    failure: super::super::ApiFailureResult<'a>,
    applied: &'a [&'static str],
    project: &'a Project,
}
