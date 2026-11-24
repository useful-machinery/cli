//! The names `useful account integration list` and `show` print for the account each grant is held
//! for: an organization by its slug, a linked identity by its email or subject.

use std::collections::BTreeMap;
use std::io::{self, Write as _};

use useful_api::{
    CommonIdentityFailure, HttpTransportPolicy, IdentityApiError, ListIdentitiesOutcome,
    MemberGrant, MemberGrantApi, MemberGrantKind, list_identities,
};
use useful_human_auth::Deployment;

use super::super::super::paging::every_page;
use super::output::Accounts;

// The largest page the identity list serves.
const IDENTITY_PAGE: u16 = 200;

/// The names of the accounts `grants` are held for: `organizations`, which the leaf read with
/// the grants, and the member's linked identities, read only when an OAuth grant is among them.
pub(super) fn named(
    deployment: &Deployment,
    policy: HttpTransportPolicy,
    grants: &[MemberGrant],
    organizations: BTreeMap<String, String>,
) -> anyhow::Result<Accounts> {
    let identities = if grants
        .iter()
        .any(|grant| grant.kind == MemberGrantKind::GrantKindOAuth)
    {
        identity_names(deployment, policy)?
    } else {
        BTreeMap::new()
    };
    Ok(Accounts {
        identities,
        organizations,
    })
}

/// The slug of each organization a native grant of `grants` is for, where the member's
/// organization read resolves it; the grant's account is printed by ID otherwise.
pub(super) fn organization_slugs(
    api: &MemberGrantApi,
    grants: &[MemberGrant],
) -> BTreeMap<String, String> {
    let mut slugs = BTreeMap::new();
    for organization_id in grants
        .iter()
        .filter(|grant| grant.kind == MemberGrantKind::GrantKindNative)
        .filter_map(|grant| grant.organization_id.as_deref())
    {
        if slugs.contains_key(organization_id) {
            continue;
        }
        if let Ok(slug) = api.organization_slug(organization_id) {
            slugs.insert(organization_id.to_owned(), slug);
        }
    }
    slugs
}

/// Each of the member's linked identities by ID, named as `useful account identity list` shows it:
/// by the email the identity asserted, or else by its subject. A failed read names none, so each
/// OAuth grant's account is then printed by ID, and says so on standard error.
fn identity_names(
    deployment: &Deployment,
    policy: HttpTransportPolicy,
) -> anyhow::Result<BTreeMap<String, String>> {
    let identities = every_page(IdentityReadFailure::RepeatedCursor, |cursor| {
        match super::super::super::execute_with_human_credential(
            deployment,
            policy,
            "prepare identity networking",
            "contact identity API at",
            |client, api_url, access_token| {
                list_identities(client, api_url, access_token, Some(IDENTITY_PAGE), cursor)
            },
        ) {
            Ok(ListIdentitiesOutcome::Listed(page)) => Ok((page.items, page.next_cursor)),
            Ok(ListIdentitiesOutcome::Common(failure)) => {
                Err(IdentityReadFailure::Refused(failure))
            }
            Err(error) => Err(IdentityReadFailure::Request(error)),
        }
    });
    let identities = match identities {
        Ok(identities) => identities,
        Err(failure) => {
            writeln!(
                io::stderr().lock(),
                "warning: {}\n\nEach OAuth grant's account is shown by its identity ID instead.",
                failure.diagnostic(deployment.fingerprint().api_url()),
            )?;
            Vec::new()
        }
    };
    Ok(identities
        .into_iter()
        .map(|identity| {
            let name = identity.asserted_email.unwrap_or(identity.subject);
            (identity.id, name)
        })
        .collect())
}

/// Why the member's linked identities could not be read.
enum IdentityReadFailure {
    /// The request did not complete: no session, no client, or no answer the API defines.
    Request(anyhow::Error),
    /// The identity API answered with a failure.
    Refused(CommonIdentityFailure),
    /// A page named a next cursor already followed.
    RepeatedCursor,
}

impl IdentityReadFailure {
    /// The diagnostic line, without its `warning:` prefix.
    fn diagnostic(&self, api_url: &str) -> String {
        let reason = match self {
            Self::Request(error) => return format!("read linked identities: {error:#}"),
            Self::Refused(CommonIdentityFailure::Unreachable(category)) => {
                return format!(
                    "read linked identities: contact {api_url}: {}",
                    category.as_str()
                );
            }
            Self::Refused(CommonIdentityFailure::Unauthenticated) => "session rejected",
            Self::Refused(CommonIdentityFailure::Forbidden) => "forbidden",
            Self::Refused(CommonIdentityFailure::InvalidInput) => "request rejected",
            Self::RepeatedCursor => "response repeats a page cursor",
        };
        format!("read linked identities from {api_url}: {reason}")
    }
}

impl super::super::super::HumanCredentialOutcome for ListIdentitiesOutcome {
    type Error = IdentityApiError;

    fn unauthenticated() -> Self {
        Self::Common(CommonIdentityFailure::Unauthenticated)
    }

    fn unreachable(category: useful_api::UnreachableCategory) -> Self {
        Self::Common(CommonIdentityFailure::Unreachable(category))
    }

    fn is_unauthenticated(&self) -> bool {
        matches!(self, Self::Common(CommonIdentityFailure::Unauthenticated))
    }

    fn credential_rejected(error: &IdentityApiError) -> bool {
        error.credential_rejected()
    }
}
