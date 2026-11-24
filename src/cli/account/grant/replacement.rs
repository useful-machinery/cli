//! The grants of a provider the member already holds, which `useful account integration connect`
//! never replaces: `create PROVIDER` refuses to start a sign-in while one is held, naming `useful
//! account integration reconnect` for each, and `create --workflow` passes over a provider whose
//! every held grant needs reconnecting.

use anyhow::anyhow;

use crate::cli::CommandFailure;
use crate::exit_code::ExitCode;
use useful_api::{
    MEMBER_GRANT_PAGE, MemberGrant, MemberGrantApi, MemberGrantFailure, MemberGrantKind,
    MemberGrantState,
};
use useful_support::Availability;

use super::projection;

/// The member's grants of the provider `provider` names, of `kind`, that keep `create` from a new
/// sign-in: those that are `active` or `reconnect_required`, and for a native provider those of
/// the organization `organization_id` names. A revoked grant is not held.
pub(super) fn held(
    api: &MemberGrantApi,
    provider: &str,
    kind: MemberGrantKind,
    organization_id: Option<&str>,
) -> Result<Vec<MemberGrant>, MemberGrantFailure> {
    let invalid = MemberGrantFailure::InvalidResponse {
        credential_rejected: false,
    };
    let grants = super::super::super::paging::every_page(invalid, |cursor| {
        api.list(Some(kind), Some(MEMBER_GRANT_PAGE), cursor)
            .map(|page| (page.items, page.next_cursor))
    })?;
    Ok(grants
        .into_iter()
        .filter(|grant| holds(grant, provider, organization_id))
        .collect())
}

/// Whether `grant` is one the member holds of the provider `provider` names: `active` or
/// `reconnect_required`, and for `organization_id` when that is named. A revoked grant is not
/// held.
pub(super) fn holds(grant: &MemberGrant, provider: &str, organization_id: Option<&str>) -> bool {
    grant.provider == provider
        && organization_id.is_none_or(|id| grant.organization_id.as_deref() == Some(id))
        && matches!(
            grant.state,
            MemberGrantState::GrantStateActive | MemberGrantState::GrantStateReconnectRequired
        )
}

/// Whether `grant`, one the member holds, needs reconnecting: its state is
/// `reconnect_required`, or its status on a runner it is authorized for is.
pub(super) fn needs_reconnecting(grant: &MemberGrant) -> bool {
    grant.state == MemberGrantState::GrantStateReconnectRequired
        || grant.authorizations.iter().any(|authorization| {
            matches!(
                projection::grant_authorization_status(grant, Some(authorization)).availability,
                Availability::ReconnectRequired
            )
        })
}

/// Refuses `useful account integration connect PROVIDER` when the member already holds grants
/// `held` of the provider `provider` names: `create` never replaces. Exit 2, naming each held grant
/// with the `useful account integration reconnect` that signs in to it again; nothing held lets the
/// command go on.
pub(super) fn refuse_held(provider: &str, held: &[MemberGrant]) -> Result<(), CommandFailure> {
    let Some(first) = held.first() else {
        return Ok(());
    };
    let ids = held
        .iter()
        .map(|grant| grant.id.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let (diagnostic, remedy) = if held.len() == 1 {
        (
            format!("you already hold a {provider} grant: {}", first.id),
            "Sign in to it again, which keeps its ID and the runners it is authorized for:",
        )
    } else {
        (
            format!("you already hold {} {provider} grants: {ids}", held.len()),
            "Sign in to one of them again, which keeps its ID and the runners it is authorized for:",
        )
    };
    let commands = held
        .iter()
        .map(|grant| format!("\n  useful account integration reconnect {}", grant.id))
        .collect::<String>();
    Err(CommandFailure::with_exit_code(
        anyhow!("{diagnostic}\n\n{remedy}{commands}"),
        ExitCode::UsageError,
    ))
}
