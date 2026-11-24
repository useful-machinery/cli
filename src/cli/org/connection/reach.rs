//! The connection that reaches a repository: the one GitHub binding or GitLab connection of an
//! organization through which `useful project create` and `useful project update` bind the
//! repository they name.
use std::io::{self, Write};

use anyhow::bail;
use useful_api::{GitLabFailure, GitLabRepositoryQuery, ProjectRepositorySelector};
use useful_human_auth::Deployment;

use super::list::{self, Provider, Record, Refusal};
use super::target::{self, Target};
use super::{github, gitlab};
use crate::cli::entity::RepositoryRef;
use crate::cli::paging::every_page;
use crate::cli::{CommandResult, CommonArgs, JsonOutputKind, PrincipalAuthenticationArgs};
use crate::exit_code::ExitCode;

/// The help of the `--integration` that names the connection a repository is bound through.
pub(in crate::cli) const HELP: &str = "GitHub binding or GitLab connection ID, or github or gitlab for the organization's connection to it (default: the one connection that reaches the repository)";
/// The providers whose connections reach repositories.
const PROVIDERS: [Provider; 2] = [Provider::Github, Provider::Gitlab];
/// The page size a GitLab connection's selected repositories are read in, the most the route
/// serves.
const PAGE: i32 = 200;

/// The connection a repository is bound through, and the provider's ID of the repository.
pub(in crate::cli) struct Reached {
    gitlab: bool,
    connection: String,
    repository_id: String,
}

impl Reached {
    fn new(provider: Provider, connection: &str, repository_id: &str) -> Self {
        Self {
            gitlab: provider == Provider::Gitlab,
            connection: connection.to_owned(),
            repository_id: repository_id.to_owned(),
        }
    }

    /// The connection, as a project's repository selection names it.
    pub(in crate::cli) fn selector(&self) -> ProjectRepositorySelector<'_> {
        if self.gitlab {
            ProjectRepositorySelector::GitLab(&self.connection)
        } else {
            ProjectRepositorySelector::GitHub(&self.connection)
        }
    }

    /// The provider's ID of the repository.
    pub(in crate::cli) fn repository_id(&self) -> &str {
        &self.repository_id
    }
}

/// Refuses a `--integration` that names a Linear connection, a usage error written before any
/// request; `None` for any other connection, or none.
pub(in crate::cli) fn refuse_linear(connection: Option<&Target>) -> Option<CommandResult> {
    let given = connection?.provider();
    (given == Provider::Linear)
        .then(|| target::refuse("--integration", &PROVIDERS, given, target::NAME_ANOTHER))
}

/// The connection of `organization` that reaches `repository`, the one `connection` names or
/// else the one among the organization's GitHub bindings and GitLab connections in use. A
/// connection ID with a repository ID is answered with no request. When no connection or
/// several reach the repository, or a read is refused, the refusal is written and the exit
/// code the command ends with is returned.
pub(in crate::cli) fn find<F: JsonOutputKind>(
    deployment: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    repository: &RepositoryRef,
    connection: Option<Target>,
) -> anyhow::Result<Result<Reached, ExitCode>> {
    let Some(connection) = connection else {
        return among_all(deployment, options, organization, repository);
    };
    if connection.provider() == Provider::Linear {
        bail!("a Linear connection reaches no repository");
    }
    if let (Target::Id(provider, id), RepositoryRef::Id(repository_id)) = (&connection, repository)
    {
        return Ok(Ok(Reached::new(*provider, id, repository_id)));
    }
    let resolved = match target::resolve(connection, deployment, options, organization)? {
        Ok(resolved) => resolved,
        Err(exit) => return Ok(Err(exit)),
    };
    let (provider, id) = (resolved.provider(), resolved.id());
    if let RepositoryRef::Id(repository_id) = repository {
        return Ok(Ok(Reached::new(provider, id, repository_id)));
    }
    match reaches(provider, id, deployment, options, organization)? {
        Ok(repositories) => match matching(&repositories, repository) {
            Some(repository_id) => Ok(Ok(Reached::new(provider, id, &repository_id))),
            None => unreached(
                &format!("the connection {id} does not reach"),
                repository,
                &[],
            ),
        },
        Err(refusal) => refusal.write(deployment, organization, options).map(Err),
    }
}

/// The one connection among the organization's GitHub bindings and GitLab connections in use
/// that reaches `repository`. A provider, or a connection, whose read is refused as forbidden
/// or unserved is passed over; any other refusal, or a refusal of both providers' lists, ends
/// the command as that provider's own failure.
fn among_all<F: JsonOutputKind>(
    deployment: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
    repository: &RepositoryRef,
) -> anyhow::Result<Result<Reached, ExitCode>> {
    let mut reaching: Vec<(Record, String)> = Vec::new();
    let mut passed_over = Vec::new();
    let mut first_refusal = None;
    let mut listed_any = false;
    for provider in PROVIDERS {
        let records = match list::read(provider, deployment, options, organization)? {
            Ok(records) => records,
            Err(refusal) => {
                let Some(reason) = refusal.unlisted_reason() else {
                    return refusal.write(deployment, organization, options).map(Err);
                };
                passed_over.push((provider.as_str().to_owned(), reason));
                first_refusal.get_or_insert(refusal);
                continue;
            }
        };
        listed_any = true;
        for record in records.into_iter().filter(target::in_use) {
            match reaches(provider, record.id(), deployment, options, organization)? {
                Ok(repositories) => {
                    if let Some(repository_id) = matching(&repositories, repository) {
                        reaching.push((record, repository_id));
                    }
                }
                Err(refusal) => {
                    let Some(reason) = refusal.unlisted_reason() else {
                        return refusal.write(deployment, organization, options).map(Err);
                    };
                    passed_over.push((format!("{} {}", provider.as_str(), record.id()), reason));
                }
            }
        }
    }
    if !listed_any && let Some(refusal) = first_refusal {
        return refusal.write(deployment, organization, options).map(Err);
    }
    match reaching.as_slice() {
        [] => unreached(
            "no connection of the organization reaches",
            repository,
            &passed_over,
        ),
        [(record, repository_id)] => Ok(Ok(Reached::new(
            record.provider(),
            record.id(),
            repository_id,
        ))),
        several => {
            let mut error = io::stderr().lock();
            writeln!(
                error,
                "error: more than one connection reaches the repository {repository}\n"
            )?;
            for (record, _) in several {
                writeln!(error, "  {}", record.row())?;
            }
            writeln!(error, "\nName one with --integration INTEGRATION.")?;
            Ok(Err(ExitCode::UsageError))
        }
    }
}

/// The repositories the connection `id` of `provider` reaches, each as its provider ID and
/// path: those a GitHub binding's installation grants, or those selected for a GitLab
/// connection, every page read.
fn reaches<F: JsonOutputKind>(
    provider: Provider,
    id: &str,
    deployment: &Deployment,
    options: &CommonArgs<F, PrincipalAuthenticationArgs>,
    organization: &str,
) -> anyhow::Result<Result<Vec<(String, String)>, Refusal>> {
    Ok(match provider {
        Provider::Github => github::with_api(
            deployment,
            options.http.transport_policy(),
            &options.authentication,
            |api| api.list_repositories(organization, id),
        )?
        .map(|granted| {
            granted
                .items
                .into_iter()
                .map(|repository| (repository.provider_repository_id, repository.full_name))
                .collect()
        })
        .map_err(Refusal::Github),
        Provider::Gitlab => gitlab::with_api(deployment, options, |api| {
            every_page(GitLabFailure::Protocol, |cursor| {
                let page = api.repositories(
                    organization,
                    id,
                    GitLabRepositoryQuery {
                        limit: Some(PAGE),
                        cursor,
                        search: None,
                        repository_id: None,
                        selected: true,
                    },
                )?;
                let items = page["items"]
                    .as_array()
                    .ok_or(GitLabFailure::Protocol)?
                    .iter()
                    .map(|item| {
                        match (
                            item["providerRepositoryId"].as_str(),
                            item["fullName"].as_str(),
                        ) {
                            (Some(id), Some(full_name)) => {
                                Ok((id.to_owned(), full_name.to_owned()))
                            }
                            _ => Err(GitLabFailure::Protocol),
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok((items, page["nextCursor"].as_str().map(str::to_owned)))
            })
        })?
        .map_err(Refusal::Gitlab),
        Provider::Linear => bail!("a Linear connection reaches no repository"),
    })
}

/// The provider ID of the repository of `repositories` that `repository` names: a path
/// compared without regard to ASCII case, as a remote's path is, and an ID exactly.
fn matching(repositories: &[(String, String)], repository: &RepositoryRef) -> Option<String> {
    repositories
        .iter()
        .find(|(id, full_name)| match repository {
            RepositoryRef::Id(wanted) => id == wanted,
            RepositoryRef::Path(path) => full_name.eq_ignore_ascii_case(path),
        })
        .map(|(id, _)| id.clone())
}

/// Writes that `subject` (a connection and its verb) `repository`, naming each connection or provider passed over
/// and why, with the remedies, and returns the exit code the command ends with.
fn unreached(
    subject: &str,
    repository: &RepositoryRef,
    passed_over: &[(String, &'static str)],
) -> anyhow::Result<Result<Reached, ExitCode>> {
    let mut error = io::stderr().lock();
    writeln!(error, "error: {subject} the repository {repository}")?;
    for (passed, reason) in passed_over {
        writeln!(error, "not read: {passed} ({})", reason.replace('_', " "))?;
    }
    writeln!(
        error,
        "\nList the repositories a connection reaches:\n  useful org integration repository list INTEGRATION\nSelect a repository for a GitLab connection:\n  useful org integration repository add REPOSITORY --integration INTEGRATION"
    )?;
    Ok(Err(ExitCode::GeneralFailure))
}
