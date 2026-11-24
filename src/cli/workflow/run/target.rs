//! A run named by `RUN` wherever it executes: a run directory, a run ID or a subject, looked up
//! under the `useful` home without a request and, when the home holds none, in Cloud in the
//! organization in effect. [`RunArg::everywhere`] looks in both places and
//! [`RunArg::home_only`] under the home alone; [`CloudRunArg`], the `RUN` of a leaf that acts
//! on a Cloud run alone, looks in Cloud alone and reads nothing under the home. Under the home
//! the lookup is `resolve_under_home`'s, and only its `run_not_found` goes on to Cloud. In
//! Cloud an ID is not read here: the leaf's first read of the run ([`InCloud::first_read`]) is
//! the lookup, and a read Cloud answers 404, or one nobody is signed in to send, is the miss. A
//! subject is read from the organization's runs listing, newest first, its live runs before its
//! ended ones and at most `PAGES` pages of `PAGE` runs of each, taking for each definition the
//! newest run whose subject claim names it. Live runs read to that bound with no run of the
//! subject end the lookup as a miss: an ended run never answers while a live one may lie past
//! the bound.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow};
use clap::{Args, ValueEnum};
use useful_api::{CommonOrganizationFailure, HttpClient, RunApi, RunFailure, RunListFilter};
use useful_execution::{WorkflowHome, normalize_terminal_path, normalize_terminal_scalar};
use useful_human_auth::Deployment;

use super::super::{RUN_NOT_FOUND, RunAddressError, SUBJECT_AMBIGUOUS, resolve_under_home};
use crate::cli::context::{self, OrgArgs};
use crate::cli::{
    self as cli, CommandFailure, CommonArgs, HttpOptions, PrincipalAuthenticationArgs, WorkflowJson,
};

/// The runs one page of the listing holds, the API's bound.
const PAGE: u16 = 100;
/// The pages of each state group a subject's lookup reads at most.
const PAGES: usize = 5;
/// The state groups a subject's lookup reads, in order, with the word a miss names each by.
const GROUPS: [(&str, &str); 2] = [("active", "live"), ("terminal", "ended")];
const DEPLOYMENT_CONTEXT: &str = "configure Useful Machinery runs";

/// Where a run executes, as `--on` names it: under the `useful` home, or in Cloud with an owner
/// or with none.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum Place {
    /// The useful home
    Local,
    /// Cloud, a run with an owner, placed on its owner's runners
    Personal,
    /// Cloud, a run with no owner, placed on the project's pools
    Project,
}

impl Place {
    /// The place's word, as a listing's row and its `on` member name it.
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Personal => "personal",
            Self::Project => "project",
        }
    }
}

/// `RUN`: a run directory, a run ID or a subject.
#[derive(Debug, Args)]
pub(super) struct RunArg {
    #[arg(value_name = "RUN", help = "Run directory, run ID or subject")]
    run: PathBuf,
}

/// `--json` and the authentication and transport options of a leaf that acts on a Cloud run
/// alone.
pub(super) type CloudOptions = CommonArgs<WorkflowJson, PrincipalAuthenticationArgs>;

/// `RUN` of a leaf that acts on a Cloud run alone (`input`, `linear list`, `artifact`,
/// `publication list`): a run ID or a subject, looked up in Cloud in the organization in
/// effect.
#[derive(Debug, Args)]
pub(super) struct CloudRunArg {
    #[arg(value_name = "RUN", help = "Run ID or subject, in Cloud")]
    run: PathBuf,
}

/// `--run RUN` of a leaf whose positional names something else, or nothing yet, under a Cloud
/// run (`publication create`, `publication show`): a run ID or a subject, required, looked up
/// as [`CloudRunArg`]'s.
#[derive(Debug, Args)]
pub(super) struct CloudRunOption {
    #[arg(long, value_name = "RUN", help = "Run ID or subject, in Cloud")]
    run: PathBuf,
}

impl CloudRunArg {
    /// The Cloud run `RUN` names in the organization in effect, nothing under the home read:
    /// an ID as given, which the leaf's own read answers, and a subject the runs listing names.
    /// A lookup that found none ends the leaf with its result: a refusal written as
    /// [`write_refused`] writes it for `command`, a Cloud read the lookup made that failed as
    /// the run failure document, or the command's failure.
    pub(super) fn find(
        &self,
        org: &OrgArgs,
        authentication: &PrincipalAuthenticationArgs,
        http: &HttpOptions,
        command: &'static str,
        json: bool,
    ) -> Result<InCloud, cli::CommandResult> {
        find_in_cloud(&self.run, org, authentication, http, command, json)
    }
}

impl CloudRunOption {
    /// The Cloud run `--run` names, as [`CloudRunArg::find`] finds it.
    pub(super) fn find(
        &self,
        org: &OrgArgs,
        authentication: &PrincipalAuthenticationArgs,
        http: &HttpOptions,
        command: &'static str,
        json: bool,
    ) -> Result<InCloud, cli::CommandResult> {
        find_in_cloud(&self.run, org, authentication, http, command, json)
    }
}

fn find_in_cloud(
    run: &Path,
    org: &OrgArgs,
    authentication: &PrincipalAuthenticationArgs,
    http: &HttpOptions,
    command: &'static str,
    json: bool,
) -> Result<InCloud, cli::CommandResult> {
    let run = RunArg {
        run: run.to_path_buf(),
    };
    run.in_cloud(None, org, authentication, http)
        .map_err(|unfound| match unfound {
            Unfound::Refused(error) => write_refused(error, command, json),
            Unfound::Cloud {
                deployment,
                organization,
                failure,
            } => Ok(super::cloud_api::write_failure(
                &deployment,
                organization.as_deref().unwrap_or_default(),
                None,
                &failure,
                authentication.kind(),
                json,
            )?),
            Unfound::Failed(failure) => Err(failure),
        })
}

/// The lookup's refusal as `command` writes it: under `--json` the `error` document with its
/// code and no `runDirectory`, otherwise the error on standard error; exit 1.
pub(super) fn write_refused(
    error: RunAddressError,
    command: &'static str,
    json: bool,
) -> cli::CommandResult {
    if json {
        Ok(error
            .write_error_document(command)
            .with_context(|| format!("write {command} output"))?)
    } else {
        Err(anyhow::Error::new(error).into())
    }
}

/// Where the lookup found the run.
pub(super) enum Found {
    /// The run directory under the home or named by its path, read without a request.
    Home(PathBuf),
    /// A Cloud run, read through the public API.
    Cloud(Box<InCloud>),
}

/// Why the lookup found no run.
pub(super) enum Unfound {
    /// A refusal the leaf writes as its own (`run_not_found`, `subject_ambiguous`,
    /// `home_unavailable` or `run_directory_unavailable`), exit 1.
    Refused(RunAddressError),
    /// Cloud failed a read the lookup made, as any Cloud read fails: `deployment` is the API's
    /// URL, and `organization` the one in effect once it was known.
    Cloud {
        deployment: String,
        organization: Option<String>,
        failure: RunFailure,
    },
    /// The command ends: a usage error or an operational failure.
    Failed(CommandFailure),
}

/// A Cloud run the lookup found: the deployment, the organization reference the leaf sends and
/// the run's ID, with where the lookup looked, which the leaf's first read writes as the miss.
pub(super) struct InCloud {
    pub(super) deployment: Deployment,
    pub(super) organization: String,
    pub(super) run_id: String,
    looked: Looked,
}

/// Why the leaf's first read of a Cloud run answered no run.
pub(super) enum Unread {
    /// The lookup's miss: Cloud has no such run, or nobody is signed in to ask.
    Missed(RunAddressError),
    /// Cloud failed the read otherwise.
    Failed(RunFailure),
}

/// Where a lookup looked: `RUN` as given, the home it read, the organization it asked Cloud
/// in, and the state group of the runs listing it read to the bound, if any.
#[derive(Clone)]
struct Looked {
    run: String,
    home: Option<PathBuf>,
    organization: Option<String>,
    bounded: Option<&'static str>,
}

impl Looked {
    /// `run_not_found`, saying where the command looked and, when a listing was read to its
    /// bound, that the run's ID finds an older run.
    fn missed(&self) -> RunAddressError {
        let mut places = Vec::new();
        if let Some(home) = &self.home {
            places.push(format!(
                "under the useful home {}",
                normalize_terminal_path(home)
            ));
        }
        if let Some(organization) = &self.organization {
            places.push(format!(
                "in Cloud in organization {}",
                normalize_terminal_scalar(organization.as_bytes())
            ));
        }
        let mut message = format!("No run {} is {}.", self.run, places.join(" or "));
        if let Some(group) = self.bounded {
            message.push_str(&format!(
                " Only the {} newest {group} runs of the organization were read; name the run by its ID to find an older one.",
                usize::from(PAGE) * PAGES
            ));
        }
        RunAddressError::new(RUN_NOT_FOUND, message)
    }

    /// `run_not_found` of a lookup that did not ask Cloud, saying `why`.
    fn not_asked(&self, why: &str) -> RunAddressError {
        let home = self.home.as_ref().map_or_else(String::new, |home| {
            format!(" under the useful home {}", normalize_terminal_path(home))
        });
        RunAddressError::new(
            RUN_NOT_FOUND,
            format!(
                "No run {}{home} was found, and Cloud was not asked because {why}",
                self.run
            ),
        )
    }

    fn signed_out(&self) -> RunAddressError {
        self.not_asked("nobody is signed in. Sign in with useful account login.")
    }
}

impl RunArg {
    /// The run `RUN` names under the home and then, when the home holds none, in Cloud in the
    /// organization in effect. A run under the home costs no request and loads no deployment.
    pub(super) fn everywhere(
        &self,
        org: &OrgArgs,
        authentication: &PrincipalAuthenticationArgs,
        http: &HttpOptions,
    ) -> Result<Found, Unfound> {
        match resolve_under_home(&self.run) {
            Ok(directory) => Ok(Found::Home(directory)),
            Err(error) if error.code == RUN_NOT_FOUND => {
                let home = WorkflowHome::from_environment().map_err(|_| Unfound::Refused(error))?;
                self.in_cloud(Some(home.root().to_path_buf()), org, authentication, http)
                    .map(|run| Found::Cloud(Box::new(run)))
            }
            Err(error) => Err(Unfound::Refused(error)),
        }
    }

    /// The run directory `RUN` names under the home alone (`resolve_under_home`), for
    /// `view`, `interrupt`, `upgrade` and `event`, which a Cloud run takes none of.
    pub(super) fn home_only(&self) -> Result<PathBuf, RunAddressError> {
        resolve_under_home(&self.run)
    }

    /// The Cloud run `RUN` names in the organization in effect, `home` being the home the
    /// command already looked under, if any: an ID as given, read by the leaf, and a subject
    /// the runs listing names.
    fn in_cloud(
        &self,
        home: Option<PathBuf>,
        org: &OrgArgs,
        authentication: &PrincipalAuthenticationArgs,
        http: &HttpOptions,
    ) -> Result<InCloud, Unfound> {
        let mut looked = Looked {
            run: normalize_terminal_scalar(self.run.as_os_str().as_encoded_bytes()),
            home,
            organization: None,
            bounded: None,
        };
        let named = org.named_in_process().map_err(Unfound::Failed)?;
        let deployment = Deployment::load()
            .map_err(|error| anyhow!(error))
            .context(DEPLOYMENT_CONTEXT)
            .map_err(|error| Unfound::Failed(error.into()))?;
        let api_url = deployment.fingerprint().api_url().to_owned();
        let refused = |organization: Option<String>, failure| Unfound::Cloud {
            deployment: api_url.clone(),
            organization,
            failure,
        };
        let organization = match named {
            Some(named) => named.organization,
            None => match context::unnamed_organization_as(
                http.transport_policy(),
                authentication,
                &deployment,
                None,
            ) {
                Err(error) => return Err(Unfound::Failed(error.into())),
                Ok(Ok(Ok((organization, _)))) => organization.id,
                Ok(Ok(Err(organizations))) => {
                    return Err(Unfound::Refused(looked.not_asked(&format!(
                        "no organization is in effect: {}",
                        context::unresolved_message(&organizations, None)
                    ))));
                }
                Ok(Err(CommonOrganizationFailure::Unauthenticated)) => {
                    return Err(Unfound::Refused(looked.signed_out()));
                }
                Ok(Err(CommonOrganizationFailure::Unreachable(category))) => {
                    return Err(refused(None, RunFailure::Unreachable(category)));
                }
                Ok(Err(CommonOrganizationFailure::Forbidden)) => {
                    return Err(refused(None, RunFailure::Forbidden));
                }
                Ok(Err(CommonOrganizationFailure::InvalidInput)) => {
                    return Err(refused(None, RunFailure::InvalidInput));
                }
            },
        };
        looked.organization = Some(organization.clone());
        let value = self.run.to_str().unwrap_or_default();
        let run_id = if useful_execution::is_run_id(value) {
            value.to_owned()
        } else if useful_execution::is_subject(value) {
            let listed = session(&deployment, authentication, http, |api| {
                by_subject(api, &organization, value)
            })
            .map_err(|error| Unfound::Failed(error.into()))?;
            match listed {
                Ok(Listed::One(run_id)) => run_id,
                listed => return Err(subject_missed(listed, looked, &organization, refused)),
            }
        } else {
            return Err(Unfound::Refused(looked.missed()));
        };
        Ok(InCloud {
            deployment,
            organization,
            run_id,
            looked,
        })
    }
}

/// The refusal of a subject the runs listing did not name one run of.
fn subject_missed(
    listed: Result<Listed, Unsent>,
    mut looked: Looked,
    organization: &str,
    refused: impl FnOnce(Option<String>, RunFailure) -> Unfound,
) -> Unfound {
    match listed {
        Ok(Listed::One(_)) => Unfound::Refused(looked.missed()),
        Ok(Listed::Several(ids)) => Unfound::Refused(RunAddressError::new(
            SUBJECT_AMBIGUOUS,
            format!(
                "Several Cloud runs of organization {} hold this subject: {}.",
                normalize_terminal_scalar(organization.as_bytes()),
                ids.join(", ")
            ),
        )),
        Ok(Listed::None(bounded)) => {
            looked.bounded = bounded;
            Unfound::Refused(looked.missed())
        }
        Err(Unsent::SignedOut) => {
            looked.organization = None;
            Unfound::Refused(looked.signed_out())
        }
        Err(Unsent::Failed(failure)) => refused(Some(organization.to_owned()), failure),
    }
}

impl InCloud {
    /// The leaf's first read of the run, which ends the lookup: a read Cloud answers 404 is
    /// the miss, and one nobody is signed in to send the miss saying so.
    pub(super) fn first_read<T>(
        &self,
        authentication: &PrincipalAuthenticationArgs,
        http: &HttpOptions,
        operation: impl FnMut(&RunApi<'_>) -> Result<T, RunFailure>,
    ) -> anyhow::Result<Result<T, Unread>> {
        Ok(
            session(&self.deployment, authentication, http, operation)?.map_err(|unsent| {
                match unsent {
                    Unsent::SignedOut => Unread::Missed(
                        Looked {
                            organization: None,
                            ..self.looked.clone()
                        }
                        .signed_out(),
                    ),
                    Unsent::Failed(RunFailure::NotFound) => Unread::Missed(self.looked.missed()),
                    Unsent::Failed(failure) => Unread::Failed(failure),
                }
            }),
        )
    }
}

impl InCloud {
    /// The lookup's miss a read of the run that failed with `failure` before any read
    /// answered it stands for: Cloud has no such run, or Cloud refused the session because
    /// nobody is signed in, which a read under no session tells without a request.
    pub(super) fn missed_by(
        &self,
        failure: &RunFailure,
        authentication: &PrincipalAuthenticationArgs,
        http: &HttpOptions,
    ) -> anyhow::Result<Option<RunAddressError>> {
        Ok(match failure {
            RunFailure::NotFound => Some(self.looked.missed()),
            RunFailure::Unauthenticated => {
                match session(&self.deployment, authentication, http, |_| Ok(()))? {
                    Err(Unsent::SignedOut) => Some(
                        Looked {
                            organization: None,
                            ..self.looked.clone()
                        }
                        .signed_out(),
                    ),
                    _ => None,
                }
            }
            _ => None,
        })
    }
}

/// What the runs listing names for a subject: the one run, the runs of several definitions,
/// or none, with the state group read to the bound, if any.
enum Listed {
    One(String),
    Several(Vec<String>),
    None(Option<&'static str>),
}

/// The newest run of each definition whose subject claim names `subject`, among the live runs
/// of `organization` and, when none is live, its ended ones, each group read newest first to
/// its last page or `PAGES` pages. A group read to that bound with no run of the subject ends
/// the lookup with none, since the subject's run may lie past the bound and a later group's
/// run would answer in its place. A next cursor already followed is an invalid response.
fn by_subject(api: &RunApi<'_>, organization: &str, subject: &str) -> Result<Listed, RunFailure> {
    for (group, word) in GROUPS {
        let mut definitions = BTreeSet::new();
        let mut ids = Vec::new();
        let mut cursors = BTreeSet::new();
        let mut cursor: Option<String> = None;
        let mut stopped = true;
        for _ in 0..PAGES {
            let page = api.list(
                organization,
                RunListFilter {
                    limit: Some(PAGE),
                    cursor: cursor.as_deref(),
                    project_id: None,
                    state_group: Some(group),
                    created_after: None,
                    context: &[],
                },
            )?;
            for row in page.items {
                let claims = row
                    .subject_claim
                    .as_ref()
                    .and_then(Option::as_deref)
                    .is_some_and(|claim| claim.subject == subject);
                let definition = row
                    .definition
                    .flatten()
                    .map(|definition| definition.definition_id);
                if claims && definitions.insert(definition) {
                    ids.push(row.id);
                }
            }
            let Some(next) = page.next_cursor else {
                stopped = false;
                break;
            };
            if !cursors.insert(next.clone()) {
                return Err(RunFailure::Protocol {
                    credential_rejected: false,
                });
            }
            cursor = Some(next);
        }
        match ids.len() {
            0 if stopped => return Ok(Listed::None(Some(word))),
            0 => {}
            1 => return Ok(Listed::One(ids.remove(0))),
            _ => return Ok(Listed::Several(ids)),
        }
    }
    Ok(Listed::None(None))
}

/// Why a read under the leaf's session answered nothing.
pub(super) enum Unsent {
    SignedOut,
    Failed(RunFailure),
}

/// Runs `operation` against the deployment under the leaf's session, again with a refreshed
/// session when the first is rejected; no session at all is `SignedOut`, never a request.
pub(super) fn session<T>(
    deployment: &Deployment,
    authentication: &PrincipalAuthenticationArgs,
    http: &HttpOptions,
    mut operation: impl FnMut(&RunApi<'_>) -> Result<T, RunFailure>,
) -> anyhow::Result<Result<T, Unsent>> {
    let policy = http.transport_policy();
    let client = HttpClient::new(policy)
        .map_err(|error| anyhow!(error))
        .context("prepare Cloud run networking")?;
    cli::execute_selected_api_operation(
        cli::principal_api_context(
            &client,
            deployment,
            authentication,
            "acquire human session for Cloud run lookup",
        ),
        |token| {
            let api = RunApi::new(deployment.fingerprint().api_url(), token, policy, &client)
                .map_err(|error| anyhow!(error))
                .context("prepare Cloud run networking")?;
            Ok(operation(&api).map_err(Unsent::Failed))
        },
        |unsent| matches!(unsent, Unsent::Failed(failure) if failure.credential_rejected()),
        || Unsent::SignedOut,
        |category| Unsent::Failed(RunFailure::Unreachable(category)),
    )
}
