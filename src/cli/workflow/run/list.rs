//! `useful workflow run list`: the runs under the `useful` home, the live ones or every run
//! under `--all`, read without taking a run lock or changing a directory, and then one page of
//! the Cloud runs of the organization in effect, those of the project in effect when one is, in
//! one listing whose every row says where the run executes, followed by the held starts.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::path::Path;

use anyhow::{Context as _, anyhow};
use clap::Args;
use serde::Serialize;
use serde_json::Value;
use useful_api::{CommonOrganizationFailure, HeldStart, RunApi, RunFailure, RunListFilter};
use useful_execution::{
    ListedRun, LocalRunDirectoryError, RunState, WaitRecord, WorkflowHome, WorkflowRunRecord,
    list_runs, normalize_terminal_path, normalize_terminal_scalar, position_path, read_definition,
    visible_text,
};
use useful_human_auth::Deployment;

use super::target::{self, Place, Unsent};
use crate::cli::context::{self, Context, NoProject, OrgArgs, ProjectArgs, Unresolved};
use crate::cli::workflow::definition::target::{NotAsked as Why, PLACE};
use crate::cli::{
    CommandFailure, CommandResult, CommonArgs, PrincipalAuthenticationArgs, WorkflowJson,
};
use crate::exit_code::ExitCode;

pub(super) const ABOUT: &str = "List workflow runs under the useful home and in Cloud";
pub(super) const AFTER_HELP: &str = "The runs under the useful home are listed first, and then one page of the Cloud runs of the organization in effect, those of the project in effect when one is. --owner, --definition and --drift select among the runs under the home, so they list those alone. --limit and --cursor page the Cloud runs. The runs under the home are listed with the first page alone.

Held starts for blocked tickets follow the runs, in the places selected by --on. The listing omits held starts when it reads only the local runs or uses --cursor, --state-group, --created-after or --integration-context.";
const COMMAND: &str = "useful workflow run list";
const ON_HELP: &str = "List only the runs of one place (default: every place)";
const DEPLOYMENT_CONTEXT: &str = "configure Useful Machinery runs";
/// The options of the Cloud half, which `--owner`, `--definition` and `--drift` refuse.
const CLOUD_FILTERS: [&str; 5] = [
    "state_group",
    "created_after",
    "integration_context",
    "limit",
    "cursor",
];

#[derive(Debug, Args)]
pub(super) struct Command {
    #[arg(long, value_enum, value_name = PLACE, help = ON_HELP)]
    on: Option<Place>,

    #[arg(
        long,
        conflicts_with_all = ["waiting", "drift"],
        help = "List every run, the exited ones included"
    )]
    all: bool,

    #[arg(long, help = "List only runs that wait")]
    waiting: bool,

    #[arg(
        long,
        conflicts_with_all = CLOUD_FILTERS,
        help = "List only live runs behind their definition's current revision"
    )]
    drift: bool,

    #[arg(
        long,
        value_name = "OWNER",
        conflicts_with_all = CLOUD_FILTERS,
        help = "List only the runs of OWNER; `me` is the invoking user"
    )]
    owner: Option<String>,

    #[arg(
        long,
        value_name = "ID",
        conflicts_with_all = CLOUD_FILTERS,
        help = "List only the runs of the definition ID"
    )]
    definition: Option<String>,

    #[arg(
        long,
        value_parser = ["active", "terminal"],
        conflicts_with_all = ["all", "waiting"],
        help = "Filter by run state group"
    )]
    state_group: Option<String>,

    #[arg(
        long,
        value_name = "RFC3339",
        help = "List runs created strictly after this time"
    )]
    created_after: Option<String>,

    #[arg(
        long = "integration-context",
        value_name = "KEY=VALUE",
        help = "Match an exact integration context entry (repeatable)"
    )]
    integration_context: Vec<String>,

    #[arg(
        long,
        value_parser = clap::value_parser!(u16).range(1..=100),
        help = "Maximum runs to return (1-100)"
    )]
    limit: Option<u16>,

    #[arg(long, help = "Opaque continuation cursor")]
    cursor: Option<String>,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    project: ProjectArgs,

    #[command(flatten)]
    options: CommonArgs<WorkflowJson, PrincipalAuthenticationArgs>,
}

/// The local rows: each run with its definition's current revision under `--drift`, and the
/// exited runs the default left out.
#[derive(Default)]
struct Local {
    runs: Vec<(ListedRun, Option<u64>)>,
    hidden: usize,
}

/// Whether Cloud was asked, and where, with the runs and held starts the options keep,
/// each item as Cloud returned it, and the run page's next cursor; or why not.
enum Cloud {
    Asked {
        organization: String,
        project: Option<String>,
        rows: Vec<(Place, Value)>,
        held_starts: Vec<(Place, Value)>,
        next_cursor: Option<String>,
    },
    NotAsked(Why),
}

impl Command {
    pub(super) fn execute(self) -> CommandResult {
        let context = self.checked_filters()?;
        let json = self.options.json;
        let local = if self.cursor.is_some() || self.on.is_some_and(|on| on != Place::Local) {
            Local::default()
        } else {
            let home = match WorkflowHome::from_environment() {
                Ok(home) => home,
                Err(error) => {
                    return super::control::write_refusal(
                        COMMAND,
                        None,
                        &super::control::Refusal::new(
                            error.code(),
                            "The useful home cannot be located: neither USEFUL_HOME nor HOME is set.",
                        ),
                        json,
                    );
                }
            };
            self.local(&home)?
        };
        let cloud = if self.on == Some(Place::Local)
            || self.owner.is_some()
            || self.definition.is_some()
            || self.drift
        {
            Cloud::NotAsked(Why::LocalOnly)
        } else {
            match self.cloud(&context)? {
                Ok(cloud) => cloud,
                Err(exit) => return Ok(exit),
            }
        };
        match cloud {
            Cloud::NotAsked(why) if self.on.is_some_and(|on| on != Place::Local) => {
                self.cloud_failed(why)
            }
            Cloud::NotAsked(why) => {
                if !matches!(why, Why::LocalOnly) {
                    writeln!(io::stderr().lock(), "! Cloud was not asked: {}", why.why())
                        .with_context(|| format!("write {COMMAND} note"))?;
                }
                self.write(&local, &Cloud::NotAsked(why))
            }
            cloud => self.write(&local, &cloud),
        }
    }

    /// The integration context filters, each `KEY=VALUE`, after the options that name another
    /// place than `--on`'s, each refused with exit 2 before anything is read, as `clap` refuses
    /// two options that conflict.
    fn checked_filters(&self) -> Result<Vec<(String, String)>, CommandFailure> {
        let first = |options: &[(bool, &'static str)]| {
            options
                .iter()
                .find_map(|(given, option)| given.then_some(*option))
        };
        let refused = match self.on {
            None => None,
            Some(Place::Local) => first(&[
                (self.state_group.is_some(), "--state-group"),
                (self.created_after.is_some(), "--created-after"),
                (
                    !self.integration_context.is_empty(),
                    "--integration-context",
                ),
                (self.limit.is_some(), "--limit"),
                (self.cursor.is_some(), "--cursor"),
                (self.org.given(), "--org"),
                (self.project.given(), "--project"),
            ]),
            Some(_) => first(&[
                (self.owner.is_some(), "--owner"),
                (self.definition.is_some(), "--definition"),
                (self.drift, "--drift"),
            ]),
        };
        if let Some(option) = refused {
            let place = self.on.map_or("", Place::as_str);
            return Err(usage(format!(
                "{option} cannot be used with --on {place}\n\n\
                 {option} selects runs of another place; drop it or --on."
            )));
        }
        self.integration_context
            .iter()
            .map(|pair| {
                pair.split_once('=')
                    .filter(|(key, _)| !key.is_empty())
                    .map(|(key, value)| (key.to_owned(), value.to_owned()))
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                usage(
                    "--integration-context takes KEY=VALUE\n\n\
                     Name each entry as a key, =, and its value.",
                )
            })
    }

    /// The runs under `home` that the local filters select.
    fn local(&self, home: &WorkflowHome) -> anyhow::Result<Local> {
        let listing = list_runs(home)
            .map_err(|error| anyhow!(error).context("list the runs under the useful home"))?;
        write_unreadable(&listing.unreadable).with_context(|| format!("write {COMMAND} output"))?;
        let owner = self.owner.as_ref().map(|owner| {
            if owner == "me" {
                super::super::login_name()
            } else {
                owner.clone()
            }
        });
        let runs = listing
            .runs
            .into_iter()
            .filter(|run| !self.waiting || run.record.state == RunState::Waiting)
            .filter(|run| {
                owner
                    .as_ref()
                    .is_none_or(|owner| run.record.owner == *owner)
            })
            .filter(|run| {
                self.definition
                    .as_ref()
                    .is_none_or(|id| run.record.definition.as_ref() == Some(id))
            })
            .collect::<Vec<_>>();
        let selected = runs.len();
        let runs = runs
            .into_iter()
            .filter(|run| self.all || run.record.state != RunState::Exited)
            .collect::<Vec<_>>();
        // `--waiting` and `--drift` select among the live runs, so they hide
        // none.
        let hidden = if self.all || self.waiting || self.drift {
            0
        } else {
            selected - runs.len()
        };
        let runs = if self.drift {
            let currents = current_revisions(home, &runs)
                .with_context(|| format!("write {COMMAND} output"))?;
            runs.into_iter()
                .filter_map(|run| {
                    let current = *currents.get(run.record.definition.as_deref()?)?;
                    run.drifted(current).then_some((run, Some(current)))
                })
                .collect()
        } else {
            runs.into_iter().map(|run| (run, None)).collect()
        };
        Ok(Local { runs, hidden })
    }

    /// One page of Cloud runs and the held starts of the organization and any project in
    /// effect; `Err` with the exit of a failure already written.
    fn cloud(
        &self,
        context: &[(String, String)],
    ) -> Result<Result<Cloud, ExitCode>, CommandFailure> {
        let deployment = Deployment::load()
            .map_err(|error| anyhow!(error))
            .context(DEPLOYMENT_CONTEXT)?;
        let in_effect = context::in_effect(
            self.org.clone(),
            self.project.clone(),
            &self.options,
            &deployment,
        );
        let (organization, project) = match in_effect {
            Ok(Context {
                organization: Ok(organization),
                project,
            }) => {
                let project = match project {
                    Ok(project) => Some(project.project),
                    Err(NoProject::Unnamed) => None,
                    Err(none) => return Err(usage(none.to_string())),
                };
                (organization.organization, project)
            }
            Ok(Context {
                organization: Err(organizations),
                ..
            }) => {
                return Ok(Ok(Cloud::NotAsked(Why::NoProject(context::unresolved(
                    &organizations,
                )))));
            }
            Err(Unresolved::Variable(failure)) => return Err(failure),
            Err(Unresolved::Refused(CommonOrganizationFailure::Unauthenticated)) => {
                return Ok(Ok(Cloud::NotAsked(Why::SignedOut)));
            }
            Err(Unresolved::Refused(CommonOrganizationFailure::Unreachable(category))) => {
                return Ok(Ok(Cloud::NotAsked(Why::Unreachable(category))));
            }
            Err(Unresolved::Refused(CommonOrganizationFailure::Forbidden)) => {
                return self.refused(&RunFailure::Forbidden).map(Err);
            }
            Err(Unresolved::Refused(CommonOrganizationFailure::InvalidInput)) => {
                return self.refused(&RunFailure::InvalidInput).map(Err);
            }
            Err(Unresolved::Failed(error)) => return Err(error.into()),
        };
        let state_group = self
            .state_group
            .as_deref()
            .or((!self.all).then_some("active"));
        let include_held_starts = self.cursor.is_none()
            && self.state_group.is_none()
            && self.created_after.is_none()
            && context.is_empty();
        let listing = target::session(
            &deployment,
            &self.options.authentication,
            &self.options.http,
            |api| {
                let page = api.list(
                    &organization,
                    RunListFilter {
                        limit: self.limit,
                        cursor: self.cursor.as_deref(),
                        project_id: project.as_deref(),
                        state_group,
                        created_after: self.created_after.as_deref(),
                        context,
                    },
                )?;
                let held_starts = if include_held_starts {
                    list_held_starts(api, &organization, project.as_deref())?
                } else {
                    Vec::new()
                };
                Ok((page, held_starts))
            },
        )?;
        Ok(Ok(match listing {
            Ok((page, held_starts)) => Cloud::Asked {
                organization,
                project,
                rows: self.kept(&page.items)?,
                held_starts: self.kept_held_starts(&held_starts)?,
                next_cursor: page.next_cursor,
            },
            // A session Cloud rejects again once refreshed is nobody signed in, as a missing one.
            Err(Unsent::SignedOut | Unsent::Failed(RunFailure::Unauthenticated)) => {
                Cloud::NotAsked(Why::SignedOut)
            }
            Err(Unsent::Failed(RunFailure::Unreachable(category))) => {
                Cloud::NotAsked(Why::Unreachable(category))
            }
            Err(Unsent::Failed(failure)) => return self.refused(&failure).map(Err),
        }))
    }

    /// `--on personal` or `--on project` with Cloud not asked, which ends the command as a
    /// Cloud read that failed: no organization in effect is its usage error.
    fn cloud_failed(&self, why: Why) -> CommandResult {
        match why {
            Why::NoProject(failure) => Err(failure),
            Why::Unreachable(category) => Ok(self.refused(&RunFailure::Unreachable(category))?),
            Why::SignedOut | Why::LocalOnly => Ok(self.refused(&RunFailure::Unauthenticated)?),
        }
    }

    /// A Cloud read that failed, written as a `workflow run` leaf writes one.
    fn refused(&self, failure: &RunFailure) -> Result<ExitCode, CommandFailure> {
        let (code, message, exit) = super::cloud::failure_diagnostic(COMMAND, failure);
        if self.options.json {
            super::super::super::write_pretty_json(&Refused {
                schema_version: 1,
                command: COMMAND,
                outcome: "refused",
                exit_status: exit.as_u8(),
                diagnostics: [Diagnostic { code, message }],
            })
        } else {
            writeln!(io::stderr().lock(), "{COMMAND} refused: {code}: {message}")
        }
        .with_context(|| format!("write {COMMAND} output"))?;
        Ok(exit)
    }

    /// The rows of a Cloud page, each where it executes, that `--on` keeps and `--waiting`,
    /// which keeps those whose `workflowState` is `waiting`, so a page can hold fewer rows than
    /// `--limit`.
    fn kept(&self, items: &[impl Serialize]) -> anyhow::Result<Vec<(Place, Value)>> {
        let mut rows = Vec::new();
        for item in items {
            let item = serde_json::to_value(item).context("encode a listed Cloud run")?;
            // A Cloud run with an owner is placed on its owner's runners; one with none on the
            // project's pools.
            let place = if item["owner"].is_string() {
                Place::Personal
            } else {
                Place::Project
            };
            if (!self.waiting || item["workflowState"] == "waiting")
                && self.on.is_none_or(|on| on == place)
            {
                rows.push((place, item));
            }
        }
        Ok(rows)
    }

    /// The held starts whose place `--on` keeps.
    fn kept_held_starts(&self, items: &[HeldStart]) -> anyhow::Result<Vec<(Place, Value)>> {
        let mut rows = Vec::new();
        for item in items {
            let place = if item.owner_principal_id.is_some() {
                Place::Personal
            } else {
                Place::Project
            };
            if self.on.is_none_or(|on| on == place) {
                let item = serde_json::to_value(item).context("encode a held start")?;
                rows.push((place, item));
            }
        }
        Ok(rows)
    }

    /// The listing: the local rows, the Cloud rows, then the held starts.
    fn write(&self, local: &Local, cloud: &Cloud) -> CommandResult {
        let (rows, held_starts, next) = match cloud {
            Cloud::Asked {
                rows,
                held_starts,
                next_cursor,
                ..
            } => (
                rows.as_slice(),
                held_starts.as_slice(),
                next_cursor.as_deref(),
            ),
            Cloud::NotAsked(_) => ([].as_slice(), [].as_slice(), None),
        };
        if self.options.json {
            super::super::super::write_pretty_json(&ListDocument {
                schema_version: 1,
                command: COMMAND,
                exited_hidden: local.hidden,
                runs: local
                    .runs
                    .iter()
                    .map(|(run, current)| {
                        Row::Local(Box::new(Placed {
                            on: Place::Local.as_str(),
                            row: listed(run, *current),
                        }))
                    })
                    .chain(rows.iter().map(|(place, item)| {
                        Row::Cloud(Placed {
                            on: place.as_str(),
                            row: item,
                        })
                    }))
                    .collect(),
                held_starts: held_starts
                    .iter()
                    .map(|(place, item)| Placed {
                        on: place.as_str(),
                        row: item,
                    })
                    .collect(),
                cloud: asked(cloud),
            })
        } else {
            write_plain(local, rows, held_starts, next, self.all)
        }
        .with_context(|| format!("write {COMMAND} output"))?;
        Ok(ExitCode::Success)
    }
}

fn list_held_starts(
    api: &RunApi<'_>,
    organization: &str,
    project: Option<&str>,
) -> Result<Vec<HeldStart>, RunFailure> {
    crate::cli::paging::every_page(
        RunFailure::Protocol {
            credential_rejected: false,
        },
        |cursor| api.list_held_starts(organization, project, Some(100), cursor),
    )
}

fn usage(message: impl Into<String>) -> CommandFailure {
    CommandFailure::with_exit_code(anyhow!(message.into()), ExitCode::UsageError)
}

/// The `cloud` member: `asked` true with where and the next cursor, or false with why not.
fn asked(cloud: &Cloud) -> Asked<'_> {
    match cloud {
        Cloud::Asked {
            organization,
            project,
            next_cursor,
            ..
        } => Asked {
            asked: true,
            organization_ref: Some(organization),
            project_id: project.as_deref(),
            next_cursor: next_cursor.as_deref(),
            reason: None,
        },
        Cloud::NotAsked(why) => Asked {
            asked: false,
            organization_ref: None,
            project_id: None,
            next_cursor: None,
            // No organization in effect is the one way a listing finds no place to ask in.
            reason: Some(match why {
                Why::NoProject(_) => "no_organization",
                why => why.reason(),
            }),
        },
    }
}

/// The run's position: the wait's step path while it waits, else the record's `position`
/// joined by `.`, or `None` when it has none.
pub(super) fn position(record: &WorkflowRunRecord, wait: Option<&WaitRecord>) -> Option<String> {
    if let Some(wait) = wait.filter(|_| record.state == RunState::Waiting) {
        return Some(wait.step_path());
    }
    (!record.position.is_empty()).then(|| position_path(&record.position))
}

/// The closed code an unreadable `runs/` entry is named with: `run_record_missing` for a
/// directory without `run.json`, `run_directory_invalid` otherwise.
fn unreadable_code(error: &LocalRunDirectoryError) -> &'static str {
    match error {
        LocalRunDirectoryError::File { path, source, .. }
            if source.kind() == io::ErrorKind::NotFound
                && path.file_name().is_some_and(|name| name == "run.json") =>
        {
            "run_record_missing"
        }
        _ => "run_directory_invalid",
    }
}

fn write_unreadable(unreadable: &[(std::path::PathBuf, LocalRunDirectoryError)]) -> io::Result<()> {
    if unreadable.is_empty() {
        return Ok(());
    }
    let mut stderr = io::stderr().lock();
    for (path, error) in unreadable {
        writeln!(
            stderr,
            "! {}: {}",
            normalize_terminal_path(path),
            unreadable_code(error)
        )?;
    }
    stderr.flush()
}

/// The current revision of each definition `runs` names, each record read once; a
/// definition whose record cannot be read is named on stderr with its code and left out, so
/// its runs are omitted.
fn current_revisions(home: &WorkflowHome, runs: &[ListedRun]) -> io::Result<BTreeMap<String, u64>> {
    let definitions = runs
        .iter()
        .filter_map(|run| run.record.definition.as_deref())
        .collect::<BTreeSet<_>>();
    let mut currents = BTreeMap::new();
    let mut stderr = io::stderr().lock();
    for id in definitions {
        match read_definition(home, id) {
            Ok(definition) => {
                currents.insert(id.to_owned(), definition.record.current);
            }
            Err(error) => writeln!(
                stderr,
                "! {}: {}",
                normalize_terminal_path(&home.definition_directory(id)),
                error.code()
            )?,
        }
    }
    stderr.flush()?;
    Ok(currents)
}

/// `value` made safe for a terminal, or `-` for none.
pub(super) fn or_dash(value: Option<&str>) -> String {
    value.map_or_else(
        || "-".to_owned(),
        |value| normalize_terminal_scalar(value.as_bytes()),
    )
}

/// The listing's lines, each led by where its run executes: the local runs, then the Cloud
/// runs, then the next cursor of the Cloud page, the held starts and any count of hidden
/// exited local runs.
fn write_plain(
    local: &Local,
    cloud: &[(Place, Value)],
    held_starts: &[(Place, Value)],
    next: Option<&str>,
    all: bool,
) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    if local.runs.is_empty() && cloud.is_empty() {
        if all {
            writeln!(stdout, "No workflow runs.")?;
        } else {
            writeln!(stdout, "No live workflow runs.")?;
        }
    }
    for (run, current) in &local.runs {
        write_local(&mut stdout, run, *current)?;
    }
    for (place, item) in cloud {
        write_cloud(&mut stdout, *place, item)?;
    }
    if let Some(cursor) = next {
        writeln!(stdout, "next cursor: {}", visible_text(cursor))?;
    }
    if !held_starts.is_empty() {
        writeln!(stdout, "\n── held starts ──")?;
        for (place, item) in held_starts {
            write_held_start(&mut stdout, *place, item)?;
        }
    }
    if local.hidden > 0 {
        let hidden = local.hidden;
        let runs = if hidden == 1 { "run" } else { "runs" };
        writeln!(
            stdout,
            "\n{hidden} exited {runs} hidden. Pass --all to list every run."
        )?;
    }
    stdout.flush()
}

/// A run under the home on one line, led by `local`.
fn write_local(out: &mut impl Write, run: &ListedRun, current: Option<u64>) -> io::Result<()> {
    let record = &run.record;
    let definition = match (&record.definition, record.revision) {
        (Some(definition), Some(revision)) => {
            format!(
                "{}@{revision}",
                normalize_terminal_scalar(definition.as_bytes())
            )
        }
        _ => "path".to_owned(),
    };
    write!(
        out,
        "{} · {} · {definition} · {} · {} · {} · {} · {} · {}",
        Place::Local.as_str(),
        normalize_terminal_scalar(record.id.as_bytes()),
        or_dash(record.subject.as_deref()),
        state_name(record.state),
        or_dash(position(record, run.wait.as_ref()).as_deref()),
        or_dash(run.wait.as_ref().map(WaitRecord::kind_name)),
        normalize_terminal_scalar(record.owner.as_bytes()),
        or_dash(record.outcome.as_deref()),
    )?;
    for (label, run) in [("pred", &record.predecessor), ("succ", &record.successor)] {
        if let Some(run) = run {
            write!(
                out,
                " · {label} {}",
                normalize_terminal_scalar(run.as_bytes())
            )?;
        }
    }
    match current {
        Some(current) => writeln!(out, " · current {current}"),
        None => writeln!(out),
    }
}

/// A Cloud run led by its place, then its name, project, workflow, update time, wait, placement
/// and integration context on lines of their own; `item` is the run as Cloud returned it.
fn write_cloud(out: &mut impl Write, place: Place, item: &Value) -> io::Result<()> {
    let text = cloud_text;
    writeln!(
        out,
        "{} · {}  {}  {}",
        place.as_str(),
        text(&item["id"]),
        text(&item["state"]),
        text(&item["createdAt"])
    )?;
    writeln!(out, "  name: {}", text(&item["displayName"]))?;
    writeln!(out, "  project: {}", text(&item["projectId"]))?;
    writeln!(out, "  workflow: {}", text(&item["workflowPath"]))?;
    writeln!(out, "  updated: {}", text(&item["updatedAt"]))?;
    if item["workflowWait"].is_object() {
        writeln!(
            out,
            "  workflow wait: {}",
            super::cloud_api::wait_phrase(&item["workflowWait"])
        )?;
    }
    if let Some(placement) = item["placement"].as_object() {
        for (label, name, id) in [
            ("runner", "runnerName", "runnerId"),
            ("pool", "poolName", "poolId"),
        ] {
            writeln!(
                out,
                "  {label}: {} ({})",
                placement.get(name).map_or_else(|| "—".to_owned(), text),
                placement.get(id).map_or_else(|| "—".to_owned(), text)
            )?;
        }
    }
    let mut context = item["integrationContext"]
        .as_object()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    context.sort_by_key(|(key, _)| *key);
    for (key, value) in context {
        writeln!(out, "  context {}: {}", visible_text(key), text(value))?;
    }
    Ok(())
}

fn cloud_text(value: &Value) -> String {
    value.as_str().map_or_else(|| "—".to_owned(), visible_text)
}

fn held_issue_name(issue: &Value) -> String {
    if issue["identifier"].is_null() {
        cloud_text(&issue["id"])
    } else {
        cloud_text(&issue["identifier"])
    }
}

fn write_held_start(out: &mut impl Write, place: Place, item: &Value) -> io::Result<()> {
    writeln!(
        out,
        "{} · {}",
        place.as_str(),
        cloud_text(&item["evaluationId"])
    )?;
    writeln!(out, "  ticket: {}", held_issue_name(&item["issue"]))?;
    writeln!(
        out,
        "  definition: {} ({})",
        cloud_text(&item["definitionName"]),
        cloud_text(&item["definitionId"])
    )?;
    let blockers = item["blockers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(held_issue_name)
        .collect::<Vec<_>>()
        .join(", ");
    writeln!(out, "  blockers: {blockers}")?;
    writeln!(out, "  held since: {}", cloud_text(&item["heldSince"]))?;
    writeln!(out, "  expires: {}", cloud_text(&item["expiresAt"]))
}

pub(super) use super::super::state_name;

fn listed(run: &ListedRun, current: Option<u64>) -> Listed<'_> {
    let record = &run.record;
    Listed {
        id: &record.id,
        directory: &run.directory,
        definition: record.definition.as_deref(),
        revision: record.revision,
        subject: record.subject.as_deref(),
        workflow: &record.workflow,
        owner: &record.owner,
        state: record.state,
        outcome: record.outcome.as_deref(),
        predecessor: record.predecessor.as_deref(),
        successor: record.successor.as_deref(),
        position: position(record, run.wait.as_ref()),
        wait: run.wait.as_ref().map(|wait| ListedWait {
            kind: wait.kind_name(),
            since: &wait.since,
            step: &wait.step,
        }),
        attempts: record.attempts,
        started_at: &record.started_at,
        current,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListDocument<'a> {
    schema_version: u8,
    command: &'static str,
    /// The exited local runs the default left out.
    exited_hidden: usize,
    runs: Vec<Row<'a>>,
    held_starts: Vec<Placed<&'a Value>>,
    cloud: Asked<'a>,
}

/// A listed run: one under the home as its record says, or a Cloud run as Cloud returned it.
#[derive(Serialize)]
#[serde(untagged)]
enum Row<'a> {
    Local(Box<Placed<Listed<'a>>>),
    Cloud(Placed<&'a Value>),
}

/// A row and the place it belongs to, `on`.
#[derive(Serialize)]
struct Placed<B: Serialize> {
    on: &'static str,
    #[serde(flatten)]
    row: B,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Asked<'a> {
    asked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_ref: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Refused {
    schema_version: u8,
    command: &'static str,
    outcome: &'static str,
    exit_status: u8,
    diagnostics: [Diagnostic; 1],
}

#[derive(Serialize)]
struct Diagnostic {
    code: &'static str,
    message: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Listed<'a> {
    id: &'a str,
    directory: &'a Path,
    definition: Option<&'a str>,
    revision: Option<u64>,
    subject: Option<&'a str>,
    workflow: &'a str,
    owner: &'a str,
    state: RunState,
    outcome: Option<&'a str>,
    predecessor: Option<&'a str>,
    successor: Option<&'a str>,
    position: Option<String>,
    wait: Option<ListedWait<'a>>,
    attempts: u64,
    started_at: &'a str,
    /// The definition's current revision, under `--drift` only.
    #[serde(skip_serializing_if = "Option::is_none")]
    current: Option<u64>,
}

#[derive(Serialize)]
struct ListedWait<'a> {
    kind: &'static str,
    since: &'a str,
    step: &'a [Value],
}
