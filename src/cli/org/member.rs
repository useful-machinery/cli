use anyhow::{Context, anyhow};
use clap::{Args, Subcommand, ValueEnum};

use crate::exit_code::ExitCode;
use useful_api::{
    CommonOrganizationFailure, HttpClient, ListOrganizationMembershipsOutcome, MembershipRole,
    OrganizationError, OrganizationMembershipDirectoryEntry, PrincipalType, UnreachableCategory,
    end_organization_membership, list_organization_membership_history,
    list_organization_memberships, update_organization_membership_role,
};
use useful_human_auth::Deployment;

use super::{LeafOptions, output};
use crate::cli::context::OrgArgs;
use crate::cli::{CommandFailure, CommandResult, HumanCredentialOutcome, PaginationArgs};

pub(super) const ABOUT: &str = "Manage Useful Machinery organization members";
const LIST_ABOUT: &str = "List organization members";
const EVENT_ABOUT: &str = "Work with organization membership events";
const HISTORY_ABOUT: &str = "List organization membership history";
const UPDATE_ABOUT: &str = "Update an organization member's role";
const REMOVE_ABOUT: &str = "Remove an organization member";
const HISTORY_AFTER_HELP: &str =
    "Authorization:\n  Only an active organization owner can list membership history.";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[command(subcommand)]
    command: Option<MembersCommand>,
}

#[derive(Debug, Subcommand)]
enum MembersCommand {
    #[command(about = EVENT_ABOUT)]
    Event(EventCommand),
    #[command(about = LIST_ABOUT)]
    List(PageCommand),
    #[command(about = REMOVE_ABOUT)]
    Remove(RemoveCommand),
    #[command(about = UPDATE_ABOUT)]
    Update(UpdateCommand),
}

#[derive(Debug, Args)]
struct EventCommand {
    #[command(subcommand)]
    command: Option<EventSubcommand>,
}

#[derive(Debug, Subcommand)]
enum EventSubcommand {
    #[command(about = HISTORY_ABOUT, after_help = HISTORY_AFTER_HELP)]
    List(PageCommand),
}

impl Command {
    pub(super) fn execute(self) -> super::super::CommandResult {
        let Some(command) = self.command else {
            return super::super::print_help(&[super::NAME, "member"]);
        };
        match command {
            MembersCommand::Event(command) => command.execute(),
            MembersCommand::List(command) => super::execute_leaf(command, |command, deployment| {
                command.execute(
                    deployment,
                    |client, api_url, access_token, organization_ref, pagination| {
                        list_organization_memberships(
                            client,
                            api_url,
                            access_token,
                            organization_ref,
                            pagination.limit,
                            pagination.cursor.as_deref(),
                        )
                    },
                    output::write_members_list,
                )
            }),
            MembersCommand::Remove(command) => super::execute_leaf(command, RemoveCommand::execute),
            MembersCommand::Update(command) => super::execute_leaf(command, UpdateCommand::execute),
        }
    }
}

impl EventCommand {
    fn execute(self) -> super::super::CommandResult {
        let Some(EventSubcommand::List(command)) = self.command else {
            return super::super::print_help(&[super::NAME, "member", "event"]);
        };
        super::execute_leaf(command, |command, deployment| {
            command.execute(
                deployment,
                |client, api_url, access_token, organization_ref, pagination| {
                    list_organization_membership_history(
                        client,
                        api_url,
                        access_token,
                        organization_ref,
                        pagination.limit,
                        pagination.cursor.as_deref(),
                    )
                },
                output::write_members_history,
            )
        })
    }
}

#[derive(Debug, Args)]
struct PageCommand {
    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    pagination: PaginationArgs,

    #[command(flatten)]
    options: LeafOptions,
}

impl PageCommand {
    fn execute<O>(
        self,
        deployment: &Deployment,
        mut operation: impl FnMut(
            &HttpClient,
            &str,
            &str,
            &str,
            &PaginationArgs,
        ) -> Result<O, OrganizationError>,
        write: impl FnOnce(
            &str,
            &O,
            super::super::PrincipalAuthenticationKind,
            bool,
        ) -> anyhow::Result<ExitCode>,
    ) -> CommandResult
    where
        O: super::super::HumanCredentialOutcome<Error = OrganizationError>,
    {
        let Self {
            org,
            pagination,
            options,
        } = self;
        options.execute_in(org, deployment, |options, organization| {
            options.execute(
                deployment,
                |client, api_url, access_token| {
                    operation(client, api_url, access_token, organization, &pagination)
                },
                write,
            )
        })
    }
}

#[derive(Debug, Args)]
struct MembershipTarget {
    #[command(flatten)]
    org: OrgArgs,

    #[arg(
        value_name = "MEMBER",
        value_parser = parse_member,
        help = "Membership ID, or the member's verified email address"
    )]
    member: Member,
}

/// A member as a person names one (REQ-MEMBER-48): an exact membership ID, or an email address
/// that the directory resolves to one.
#[derive(Clone, Debug)]
pub(crate) enum Member {
    Id(String),
    Address(String),
}

pub(crate) fn parse_member(value: &str) -> Result<Member, String> {
    if useful_support::valid_typed_id(value, "mem_") {
        Ok(Member::Id(value.to_owned()))
    } else if value.contains('@') {
        Ok(Member::Address(value.to_owned()))
    } else {
        Err("member must be an exact mem_ identifier or an email address".to_owned())
    }
}

/// The page size of a directory read for an address.
const DIRECTORY_PAGE: u16 = 200;

/// Why an address names no membership a change can be sent for; written as the change's own
/// answer of that kind is (`output::write_member_unresolved`).
pub(crate) enum Unresolved {
    NotFound,
    Common(CommonOrganizationFailure),
}

/// The organization's directory read to its last page, or the answer that ended the read.
enum Directory {
    Read(Vec<OrganizationMembershipDirectoryEntry>),
    Unresolved(Unresolved),
    RepeatedCursor,
}

impl HumanCredentialOutcome for Directory {
    type Error = OrganizationError;

    fn unauthenticated() -> Self {
        Self::Unresolved(Unresolved::Common(
            CommonOrganizationFailure::Unauthenticated,
        ))
    }

    fn unreachable(category: UnreachableCategory) -> Self {
        Self::Unresolved(Unresolved::Common(CommonOrganizationFailure::Unreachable(
            category,
        )))
    }

    fn is_unauthenticated(&self) -> bool {
        matches!(
            self,
            Self::Unresolved(Unresolved::Common(
                CommonOrganizationFailure::Unauthenticated
            ))
        )
    }

    fn credential_rejected(error: &Self::Error) -> bool {
        error.credential_rejected()
    }
}

/// The member a command names, `T` (its membership ID, or its whole directory row), or why
/// there is none.
pub(crate) enum Resolution<T> {
    Member(T),
    Unresolved(Unresolved),
    /// The usage refusal of an address more than one member holds verified.
    Ambiguous(CommandFailure),
}

impl Member {
    /// The membership this names in `organization`. An ID names itself without a request; an
    /// address is looked up in the organization's whole directory under the leaf's credential.
    fn resolve(
        self,
        options: &LeafOptions,
        deployment: &Deployment,
        organization: &str,
    ) -> anyhow::Result<Resolution<String>> {
        if let Self::Id(membership_id) = self {
            return Ok(Resolution::Member(membership_id));
        }
        Ok(
            match self.directory_row(
                deployment,
                options.http.transport_policy(),
                &options.authentication,
                organization,
            )? {
                Resolution::Member(row) => Resolution::Member(row.id),
                Resolution::Unresolved(unresolved) => Resolution::Unresolved(unresolved),
                Resolution::Ambiguous(failure) => Resolution::Ambiguous(failure),
            },
        )
    }

    /// The directory row of the member this names in `organization`, read to its last page
    /// under `authentication`: the row of the membership ID, or of the one member who holds
    /// the address verified. `useful runner join-key issue --member` reads it for the
    /// member's principal ID (REQ-RUNNERENROLL-1).
    pub(crate) fn directory_row(
        &self,
        deployment: &Deployment,
        transport_policy: useful_api::HttpTransportPolicy,
        authentication: &crate::cli::PrincipalAuthenticationArgs,
        organization: &str,
    ) -> anyhow::Result<Resolution<OrganizationMembershipDirectoryEntry>> {
        let rows = match directory(deployment, transport_policy, authentication, organization)? {
            Ok(rows) => rows,
            Err(unresolved) => return Ok(Resolution::Unresolved(unresolved)),
        };
        Ok(match self {
            Self::Id(membership_id) => rows
                .into_iter()
                .find(|row| &row.id == membership_id)
                .map_or(
                    Resolution::Unresolved(Unresolved::NotFound),
                    Resolution::Member,
                ),
            Self::Address(address) => holder(rows, address),
        })
    }
}

/// The principal ID of the one service principal of `organization` whose display name is `name`
/// exactly, read from the whole directory under `authentication`; `useful workflow definition
/// update --run-as` names a service principal so (REQ-CLOUDDEF-15). A name several service
/// principals have is refused as a usage error naming their principal IDs.
pub(crate) fn service_principal(
    deployment: &Deployment,
    transport_policy: useful_api::HttpTransportPolicy,
    authentication: &crate::cli::PrincipalAuthenticationArgs,
    organization: &str,
    name: &str,
) -> anyhow::Result<Resolution<String>> {
    let rows = match directory(deployment, transport_policy, authentication, organization)? {
        Ok(rows) => rows,
        Err(unresolved) => return Ok(Resolution::Unresolved(unresolved)),
    };
    let mut named = rows
        .into_iter()
        .filter(|row| {
            row.principal_type == PrincipalType::Service
                && row.display_name.as_deref() == Some(name)
        })
        .map(|row| row.principal_id)
        .collect::<Vec<_>>();
    Ok(match named.len() {
        0 => Resolution::Unresolved(Unresolved::NotFound),
        1 => Resolution::Member(named.swap_remove(0)),
        _ => Resolution::Ambiguous(CommandFailure::with_exit_code(
            anyhow!(
                "{name} is the display name of more than one service principal: {}\n\n\
                 Name the service principal by its ID instead.",
                named.join(", ")
            ),
            ExitCode::UsageError,
        )),
    })
}

/// The directory of `organization` read to its last page under `authentication`, or the answer
/// that ended the read.
fn directory(
    deployment: &Deployment,
    transport_policy: useful_api::HttpTransportPolicy,
    authentication: &crate::cli::PrincipalAuthenticationArgs,
    organization: &str,
) -> anyhow::Result<Result<Vec<OrganizationMembershipDirectoryEntry>, Unresolved>> {
    let directory = crate::cli::execute_with_principal_credential(
        deployment,
        transport_policy,
        authentication,
        "prepare organization networking",
        "contact organization API at",
        |client, api_url, access_token| read_directory(client, api_url, access_token, organization),
    )?;
    match directory {
        Directory::Read(rows) => Ok(Ok(rows)),
        Directory::Unresolved(unresolved) => Ok(Err(unresolved)),
        Directory::RepeatedCursor => Err(anyhow!(
            "list organization members: a page repeated an earlier cursor"
        )),
    }
}

/// The directory of `organization` read to its last page. A page that ends the read early
/// stops `every_page` with the directory's answer, or with the request's error.
fn read_directory(
    client: &HttpClient,
    api_url: &str,
    access_token: &str,
    organization: &str,
) -> Result<Directory, OrganizationError> {
    let stopped = |unresolved| Err(Ok(Directory::Unresolved(unresolved)));
    let read = super::super::paging::every_page(Ok(Directory::RepeatedCursor), |cursor| {
        match list_organization_memberships(
            client,
            api_url,
            access_token,
            organization,
            Some(DIRECTORY_PAGE),
            cursor,
        ) {
            Ok(ListOrganizationMembershipsOutcome::Listed(page)) => {
                Ok((page.items, page.next_cursor))
            }
            Ok(ListOrganizationMembershipsOutcome::NotFound) => stopped(Unresolved::NotFound),
            Ok(ListOrganizationMembershipsOutcome::Common(failure)) => {
                stopped(Unresolved::Common(failure))
            }
            Err(error) => Err(Err(error)),
        }
    });
    read.map_or_else(|stopped| stopped, |rows| Ok(Directory::Read(rows)))
}

/// The membership whose human row holds `address` as a verified linked address, compared
/// without regard to ASCII case. Only an owner's read carries linked addresses
/// (REQ-MEMBER-6), so a directory whose human rows carry none was read by a caller who may
/// not change a member, and the change would be refused as forbidden.
fn holder(
    rows: Vec<OrganizationMembershipDirectoryEntry>,
    address: &str,
) -> Resolution<OrganizationMembershipDirectoryEntry> {
    let linked = rows
        .into_iter()
        .filter(|row| row.principal_type == PrincipalType::Human && row.linked_emails.is_some())
        .collect::<Vec<_>>();
    if linked.is_empty() {
        return Resolution::Unresolved(Unresolved::Common(CommonOrganizationFailure::Forbidden));
    }
    let mut holders = linked
        .into_iter()
        .filter(|row| {
            row.linked_emails.iter().flatten().any(|linked| {
                linked.verified == Some(true) && linked.email.eq_ignore_ascii_case(address)
            })
        })
        .collect::<Vec<_>>();
    match holders.len() {
        0 => Resolution::Unresolved(Unresolved::NotFound),
        1 => Resolution::Member(holders.swap_remove(0)),
        _ => Resolution::Ambiguous(ambiguous(
            address,
            &holders.into_iter().map(|row| row.id).collect::<Vec<_>>(),
        )),
    }
}

/// Runs `change` in the organization in effect for the membership `target` names, resolved
/// before the change is sent. An address two members hold is refused as a usage error naming
/// both, and nothing is sent.
fn execute_for_member(
    target: MembershipTarget,
    options: LeafOptions,
    deployment: &Deployment,
    change: impl FnOnce(LeafOptions, &str, Result<String, Unresolved>) -> anyhow::Result<ExitCode>,
) -> CommandResult {
    let MembershipTarget { org, member } = target;
    let mut refusal = None;
    let exit_code = options.execute_in(org, deployment, |options, organization| {
        match member.resolve(&options, deployment, organization)? {
            Resolution::Member(membership_id) => change(options, organization, Ok(membership_id)),
            Resolution::Unresolved(unresolved) => change(options, organization, Err(unresolved)),
            Resolution::Ambiguous(failure) => {
                refusal = Some(failure);
                Ok(ExitCode::UsageError)
            }
        }
    })?;
    refusal.map_or(Ok(exit_code), Err)
}

fn ambiguous(address: &str, holders: &[String]) -> CommandFailure {
    CommandFailure::with_exit_code(
        anyhow!(
            "{address} is a verified address of more than one member: {}\n\n\
             Name the member by its membership ID instead.",
            holders.join(", ")
        ),
        ExitCode::UsageError,
    )
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum RoleArgument {
    Owner,
    Member,
}

impl From<RoleArgument> for MembershipRole {
    fn from(value: RoleArgument) -> Self {
        match value {
            RoleArgument::Owner => Self::Owner,
            RoleArgument::Member => Self::Member,
        }
    }
}

#[derive(Debug, Args)]
struct UpdateCommand {
    #[command(flatten)]
    target: MembershipTarget,

    #[arg(long, value_enum, help = "Set the organization role")]
    role: RoleArgument,

    #[command(flatten)]
    options: LeafOptions,
}

impl UpdateCommand {
    fn execute(self, deployment: &Deployment) -> CommandResult {
        let Self {
            target,
            role,
            options,
        } = self;
        execute_for_member(
            target,
            options,
            deployment,
            |options, organization, membership| {
                let membership_id = match membership {
                    Ok(membership_id) => membership_id,
                    Err(unresolved) => {
                        return output::write_member_unresolved(
                            deployment.fingerprint().api_url(),
                            &unresolved,
                            options.authentication.kind(),
                            options.json,
                        )
                        .context("write organization result");
                    }
                };
                options.execute_mutation(
                    deployment,
                    |client, api_url, access_token, idempotency_key| {
                        update_organization_membership_role(
                            client,
                            api_url,
                            access_token,
                            organization,
                            &membership_id,
                            idempotency_key,
                            role.into(),
                        )
                    },
                    output::write_members_update,
                )
            },
        )
    }
}

#[derive(Debug, Args)]
struct RemoveCommand {
    #[command(flatten)]
    target: MembershipTarget,

    #[command(flatten)]
    confirmation: super::super::ConfirmationArgs,

    #[command(flatten)]
    options: LeafOptions,
}

impl RemoveCommand {
    fn execute(self, deployment: &Deployment) -> CommandResult {
        let Self {
            target,
            confirmation: _,
            options,
        } = self;
        execute_for_member(
            target,
            options,
            deployment,
            |options, organization, membership| {
                let membership_id = match membership {
                    Ok(membership_id) => membership_id,
                    Err(unresolved) => {
                        return output::write_member_unresolved(
                            deployment.fingerprint().api_url(),
                            &unresolved,
                            options.authentication.kind(),
                            options.json,
                        )
                        .context("write organization result");
                    }
                };
                options.execute_mutation(
                    deployment,
                    |client, api_url, access_token, idempotency_key| {
                        end_organization_membership(
                            client,
                            api_url,
                            access_token,
                            organization,
                            &membership_id,
                            idempotency_key,
                        )
                    },
                    |deployment, outcome, authentication, json| {
                        output::write_member_removal(
                            deployment,
                            organization,
                            &membership_id,
                            outcome,
                            authentication,
                            json,
                        )
                    },
                )
            },
        )
    }
}
