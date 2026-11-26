//! The runners `useful account integration authorize` and `useful account integration deauthorize`
//! read for a grant or the member's token: those they name when given no `--runner`, in the order
//! they name them, and the outcome when there is none to name; and the one runner `--runner` names,
//! by its ID or by its exact name among them, as it names the runner of `useful account integration
//! connect --workflow` and of `useful workflow doctor`. No grant command shows a list to choose
//! from.

use std::collections::BTreeSet;

use anyhow::Context;

use crate::exit_code::ExitCode;
use useful_api::{
    HttpTransportPolicy, MemberGrantApi, MemberGrantFailure, MemberGrantProvider, RunnerFailure,
    RunnerRegistration,
};
use useful_human_auth::Deployment;

use super::super::super::PrincipalAuthenticationArgs;
use super::super::super::paging::every_page;
use super::authorization::Holder;
use super::output::Family;
use super::{InForce, Subject, organization, output};

// The largest page the runner registration list serves.
const PAGE: u16 = 200;

/// A runner a command reads: its registration, or, for an authorization whose runner the
/// command found no registration of, its ID and organization alone.
pub(in crate::cli) struct Runner {
    pub(super) id: String,
    pub(super) organization_id: String,
    pub(super) registration: Option<Registration>,
}

/// What a runner's registration says of it, each state by its wire name.
pub(super) struct Registration {
    pub(super) name: String,
    pub(super) pool: String,
    /// `online` or `offline`.
    pub(super) connectivity: String,
    /// `enabled`, `draining` or `disabled`.
    pub(super) mode: String,
}

impl Runner {
    fn registered(registration: RunnerRegistration) -> anyhow::Result<Self> {
        // Each state by its wire name, as the runner registrations carry it.
        let state = |name: Option<String>| name.context("runner state is not a contracted string");
        Ok(Self {
            registration: Some(Registration {
                connectivity: state(useful_support::wire_name(&registration.connectivity.state))?,
                mode: state(useful_support::wire_name(&registration.administration.mode))?,
                name: registration.name,
                pool: registration.runner_pool.name,
            }),
            id: registration.id,
            organization_id: registration.organization_id,
        })
    }

    /// The runner as a command names it among those it can act on: its name, pool, `online` or
    /// `offline`, its mode when that is not `enabled`, its ID, and with `organization` its
    /// organization's ID. A runner with no registration is named by its ID alone.
    pub(super) fn line(&self, organization: bool) -> String {
        let registration = self.registration.as_ref();
        let mode = registration
            .map(|registration| registration.mode.as_str())
            .filter(|mode| *mode != "enabled");
        [
            registration.map(|registration| registration.name.as_str()),
            registration.map(|registration| registration.pool.as_str()),
            registration.map(|registration| registration.connectivity.as_str()),
            mode,
            Some(self.id.as_str()),
            organization.then_some(self.organization_id.as_str()),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ")
    }

    /// The runner as a statement or an outcome names it: by its name and ID, or by its ID
    /// alone when it has no registration.
    fn named(&self) -> String {
        match &self.registration {
            Some(registration) => format!("{} ({})", registration.name, self.id),
            None => self.id.clone(),
        }
    }

    /// Whether the runner is online and enabled, which a command names first.
    fn ready(&self) -> bool {
        self.registration.as_ref().is_some_and(|registration| {
            registration.connectivity == "online" && registration.mode == "enabled"
        })
    }
}

/// Why a command has no runner to name.
#[derive(Clone, Copy)]
pub(in crate::cli) enum Nothing {
    /// The organizations it reads hold no runner.
    RunnerNotFound,
    /// The grant, token or connection is authorized for every runner of those organizations.
    AlreadyAuthorized,
    /// A Codex grant, which serves one runner at a time, has an authorization in force.
    AuthorizedElsewhere,
    /// The grant, token or connection is authorized for no runner.
    AuthorizationNotFound,
}

/// Why a command could not read the runners: the read of the member's organizations failed,
/// or the read of their runners.
pub(in crate::cli) enum Unread {
    Grant(MemberGrantFailure),
    Runner(RunnerFailure),
}

/// The runners a command read, or why it could not.
pub(in crate::cli) type Read = anyhow::Result<Result<Vec<Runner>, Unread>>;

/// What a command given no `--runner` names: the runners in order, why there is none, or the
/// failure of a read.
pub(in crate::cli) enum Offer {
    Runners(Vec<Runner>),
    Nothing(Nothing),
    Unread(Unread),
}

/// The runners `authorize INTEGRATION` can name `--runner` among: those of the grant's or the
/// token's organization for a native grant and an organization's token, of every organization
/// the member is an active member of for an OAuth grant and for the member's token, the
/// runners it is authorized for already included.
pub(in crate::cli) fn authorizable(
    deployment: &Deployment,
    policy: HttpTransportPolicy,
    subject: &Subject,
) -> Read {
    let organizations = match subject.serving() {
        Some(organizations) => organizations,
        None => match active_organizations(deployment, policy)? {
            Ok(organizations) => organizations,
            Err(failure) => return Ok(Err(Unread::Grant(failure))),
        },
    };
    registered(deployment, policy, &organizations)
}

/// The runners `authorize INTEGRATION` given no `--runner` names: those [`authorizable`] reads,
/// less those the grant or token is authorized for already. A Codex grant with an authorization
/// in force names none, and nothing is read.
pub(in crate::cli) fn to_authorize(
    deployment: &Deployment,
    policy: HttpTransportPolicy,
    subject: &Subject,
) -> anyhow::Result<Offer> {
    let in_force = subject.in_force();
    if subject.provider() == MemberGrantProvider::GrantProviderCodex.as_str()
        && !in_force.is_empty()
    {
        return Ok(Offer::Nothing(Nothing::AuthorizedElsewhere));
    }
    unauthorized(authorizable(deployment, policy, subject), |runner_id| {
        in_force
            .iter()
            .any(|authorization| authorization.runner_id == runner_id)
    })
}

/// The runners `read` read less those `authorized` names, as a command authorizing one names
/// them: none registered is no runner found, and every one authorized already is nothing more to
/// authorize.
pub(in crate::cli) fn unauthorized(
    read: Read,
    authorized: impl Fn(&str) -> bool,
) -> anyhow::Result<Offer> {
    Ok(match read? {
        Err(unread) => Offer::Unread(unread),
        Ok(runners) if runners.is_empty() => Offer::Nothing(Nothing::RunnerNotFound),
        Ok(runners) => offered(
            Ok(runners
                .into_iter()
                .filter(|runner| !authorized(&runner.id))
                .collect()),
            Nothing::AlreadyAuthorized,
        ),
    })
}

/// The runners of every organization the member is an active member of, which `authorize
/// --all` names given no `--runner` and names `--runner` among, as does `connect --workflow`.
pub(in crate::cli) fn in_active_organizations(
    deployment: &Deployment,
    policy: HttpTransportPolicy,
) -> Read {
    match active_organizations(deployment, policy)? {
        Ok(organizations) => registered(deployment, policy, &organizations),
        Err(failure) => Ok(Err(Unread::Grant(failure))),
    }
}

/// The runners of the organization `organization` names, by ID or slug, which a command acting
/// on the organization's token or connection names `--runner` among.
pub(in crate::cli) fn in_organization(
    deployment: &Deployment,
    policy: HttpTransportPolicy,
    organization: &str,
) -> Read {
    registered(
        deployment,
        policy,
        &BTreeSet::from([organization.to_owned()]),
    )
}

/// The runners `authorize --all` given no `--runner` names, of `read`.
pub(in crate::cli) fn to_authorize_all(read: Read) -> anyhow::Result<Offer> {
    Ok(offered(read?, Nothing::RunnerNotFound))
}

/// The runners the grant or token is authorized for, which `deauthorize` names given no
/// `--runner` and names `--runner` among: those [`holding`] reads.
pub(in crate::cli) fn authorized(
    deployment: &Deployment,
    policy: HttpTransportPolicy,
    subject: &Subject,
) -> Read {
    holding(deployment, policy, &subject.in_force())
}

/// The runners `in_force` names, each with the registration read from its authorization's
/// organization, or by its ID alone when there is none. For none in force nothing is read.
pub(in crate::cli) fn holding(
    deployment: &Deployment,
    policy: HttpTransportPolicy,
    in_force: &[InForce<'_>],
) -> Read {
    if in_force.is_empty() {
        return Ok(Ok(Vec::new()));
    }
    let organizations = in_force
        .iter()
        .map(|authorization| authorization.organization_id.to_owned())
        .collect();
    let mut registered = match registered(deployment, policy, &organizations)? {
        Ok(registered) => registered,
        Err(unread) => return Ok(Err(unread)),
    };
    Ok(Ok(in_force
        .iter()
        .map(|authorization| {
            match registered
                .iter()
                .position(|runner| runner.id == authorization.runner_id)
            {
                Some(index) => registered.swap_remove(index),
                None => Runner {
                    id: authorization.runner_id.to_owned(),
                    organization_id: authorization.organization_id.to_owned(),
                    registration: None,
                },
            }
        })
        .collect()))
}

/// The runners `deauthorize` given no `--runner` names, of `read`.
pub(in crate::cli) fn to_deauthorize(read: Read) -> anyhow::Result<Offer> {
    Ok(offered(read?, Nothing::AuthorizationNotFound))
}

/// The runner a leaf acts on, which `--runner` names.
pub(in crate::cli) struct Acting {
    pub(in crate::cli) id: String,
    /// The runner as the statement names it: by its ID, or, named by its name, by its name and
    /// ID.
    pub(in crate::cli) named: String,
}

/// The runner `runner`, the value of `--runner`, names. An exact `rnr_` ID is taken as given and
/// nothing is read. Any other value is a name, as the `useful runner` commands take it, looked up
/// once among the runners `read` reads, before anything is sent: the one runner of that name; none
/// is reported `runner_not_found` with exit 1, and several, which runners of different
/// organizations can be, are refused with exit 2, each named with its ID and organization, ending
/// with the command line `example` makes for one runner ID (`runner_required` under `--json`, with
/// `holder`'s ID). A failed read is reported as the read's failure. Each is printed as `family`
/// prints a refusal.
pub(in crate::cli) fn resolve(
    deployment: &Deployment,
    json: bool,
    family: Family,
    runner: &str,
    holder: Option<Holder<'_>>,
    read: impl FnOnce() -> Read,
    example: impl FnOnce(&str) -> String,
) -> anyhow::Result<Result<Acting, ExitCode>> {
    if useful_support::valid_typed_id(runner, "rnr_") {
        return Ok(Ok(Acting {
            id: runner.to_owned(),
            named: runner.to_owned(),
        }));
    }
    let api_url = deployment.fingerprint().api_url();
    let mut named = match read()? {
        Ok(runners) => runners
            .into_iter()
            .filter(|candidate| {
                candidate
                    .registration
                    .as_ref()
                    .is_some_and(|registration| registration.name == runner)
            })
            .collect::<Vec<_>>(),
        Err(unread) => return report_unread(deployment, json, family, unread).map(Err),
    };
    match named.len() {
        0 => family
            .write(
                api_url,
                &output::report(api_url, &MemberGrantFailure::RunnerNotFound),
                json,
            )
            .map(Err),
        1 => {
            let runner = named.remove(0);
            Ok(Ok(Acting {
                named: runner.named(),
                id: runner.id,
            }))
        }
        count => {
            in_order(&mut named);
            let example = example(named.first().map_or("RUNNER", |runner| &runner.id));
            let diagnostic = format!("{count} runners are named {runner}:");
            match family {
                Family::Document => output::write_runner_required(
                    api_url,
                    holder,
                    &named,
                    true,
                    &diagnostic,
                    &example,
                    json,
                ),
                Family::Events => output::write_create_runner_required(
                    api_url,
                    &named,
                    &diagnostic,
                    &example,
                    json,
                ),
            }
            .map(Err)
        }
    }
}

/// Refuses a command given no `--runner`: with exit 2, naming each runner `offer` holds under a
/// diagnostic that names the runner `purpose` asks for and ending with the command line
/// `example` makes for one runner ID, or with the outcome of having none to name or of a failed
/// read. It asks nothing, on a terminal or not.
pub(in crate::cli) fn refuse(
    deployment: &Deployment,
    json: bool,
    offer: Offer,
    holder: Option<Holder<'_>>,
    group: &str,
    purpose: &str,
    example: impl FnOnce(&str) -> String,
) -> anyhow::Result<ExitCode> {
    let api_url = deployment.fingerprint().api_url();
    match offer {
        Offer::Runners(runners) => {
            let example = example(runners.first().map_or("RUNNER", |runner| &runner.id));
            output::write_runner_required(
                api_url,
                holder,
                &runners,
                false,
                &format!("name the runner {purpose}, one of:"),
                &example,
                json,
            )
        }
        Offer::Nothing(nothing) => {
            output::write_nothing_offered(api_url, nothing, holder, group, json)
        }
        Offer::Unread(unread) => report_unread(deployment, json, Family::Document, unread),
    }
}

/// Reports the failure of a read of the runners, with its remedy, as `family` prints a refusal.
fn report_unread(
    deployment: &Deployment,
    json: bool,
    family: Family,
    unread: Unread,
) -> anyhow::Result<ExitCode> {
    let api_url = deployment.fingerprint().api_url();
    match (unread, family) {
        (Unread::Grant(failure), family) => {
            family.write(api_url, &output::report(api_url, &failure), json)
        }
        (Unread::Runner(failure), Family::Document) => super::super::super::runner::write_failure(
            deployment,
            &failure,
            &PrincipalAuthenticationArgs::default(),
            json,
        ),
        (Unread::Runner(failure), Family::Events) => {
            family.write(api_url, &output::runner_report(api_url, &failure), json)
        }
    }
}

/// The runners `read` read in the order a command names them, or `nothing` when there are
/// none.
fn offered(read: Result<Vec<Runner>, Unread>, nothing: Nothing) -> Offer {
    match read {
        Err(unread) => Offer::Unread(unread),
        Ok(runners) if runners.is_empty() => Offer::Nothing(nothing),
        Ok(mut runners) => {
            in_order(&mut runners);
            Offer::Runners(runners)
        }
    }
}

/// Puts `runners` in the order a command names them: the runners online and enabled first,
/// then the rest, each group by name, then ID.
fn in_order(runners: &mut [Runner]) {
    let key = |runner: &Runner| {
        let name = runner
            .registration
            .as_ref()
            .map(|registration| registration.name.clone());
        (!runner.ready(), name.is_none(), name, runner.id.clone())
    };
    runners.sort_by_cached_key(key);
}

/// The organizations the member is an active member of, by ID.
fn active_organizations(
    deployment: &Deployment,
    policy: HttpTransportPolicy,
) -> anyhow::Result<Result<BTreeSet<String>, MemberGrantFailure>> {
    super::super::super::with_human_session_api(deployment, policy, |api: &MemberGrantApi| {
        let organizations = organization::active(api)?;
        Ok(organizations.into_iter().map(|(id, _)| id).collect())
    })
}

pub(super) fn personal_pool(
    deployment: &Deployment,
    options: &super::Options,
    organization: &str,
) -> anyhow::Result<Result<String, ExitCode>> {
    match super::super::super::runner::with_api(
        deployment,
        options.http.transport_policy(),
        &PrincipalAuthenticationArgs::default(),
        |api| api.get_personal_pool(organization),
    )? {
        Ok(pool) => Ok(Ok(pool.id)),
        Err(failure) => report_unread(
            deployment,
            options.json,
            Family::Document,
            Unread::Runner(failure),
        )
        .map(Err),
    }
}

/// Every runner registered in `organizations`, each read to its last page with the member's
/// human session.
fn registered(
    deployment: &Deployment,
    policy: HttpTransportPolicy,
    organizations: &BTreeSet<String>,
) -> Read {
    let read = super::super::super::runner::with_api(
        deployment,
        policy,
        &PrincipalAuthenticationArgs::default(),
        |api| {
            let mut registrations = Vec::new();
            for organization in organizations {
                registrations.extend(every_page(RunnerFailure::Protocol, |cursor| {
                    api.list_registrations(organization, Some(PAGE), cursor)
                        .map(|page| (page.items, page.next_cursor))
                })?);
            }
            Ok(registrations)
        },
    )?;
    match read {
        Ok(registrations) => registrations
            .into_iter()
            .map(Runner::registered)
            .collect::<anyhow::Result<_>>()
            .map(Ok),
        Err(failure) => Ok(Err(Unread::Runner(failure))),
    }
}
