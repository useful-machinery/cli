//! The one organization a native grant `useful account integration connect` makes is for (REQ-GRANT-72):
//! the organization in effect, resolved as `cli::context` resolves it (REQ-ORG-87, INV-CLI-20).
//! The organization `--org` or `USEFUL_ORG` named, or the organization in effect whose coding
//! agent grants `useful workflow doctor` keeps, is read through the member grant API, and
//! otherwise the checkout and the member's only active membership name it through
//! `cli::context`, with the member's human session. The runner choice of `authorize` and
//! `deauthorize` reads the member's active organizations here too (REQ-GRANT-81).

use useful_api::{CommonOrganizationFailure, MemberGrantApi, MemberGrantFailure};
use useful_human_auth::Deployment;

use super::super::super::context;
pub(super) use super::super::super::context::Organization;
use super::super::super::{
    CommonArgs, HttpOptions, PrincipalAuthenticationArgs, StreamingJson, with_human_session_api,
};

// The largest page the membership list serves.
const PAGE: i32 = 200;

/// Resolves the organization in effect: `named`, what an option or `USEFUL_ORG` named, an ID as
/// given and a slug to the ID of the organization it names among the member's memberships;
/// without it, the organization the checkout names, or else the member's only active
/// membership. Nothing is read or run until this is called. The inner error is every active
/// organization of the member's when no source names one, which the caller refuses with.
pub(super) fn resolve(
    deployment: &Deployment,
    http: HttpOptions,
    named: Option<&str>,
) -> anyhow::Result<Result<Result<Organization, Vec<Organization>>, MemberGrantFailure>> {
    if let Some(named) = named {
        let read = with_human_session_api(deployment, http.transport_policy(), |api| {
            self::named(api, named)
        })?;
        return Ok(read.map(Ok));
    }
    // The member grant leaves take no API key, so the member's human session reads the
    // memberships and projects.
    let options =
        CommonArgs::<StreamingJson, _>::new(false, PrincipalAuthenticationArgs::default(), http);
    Ok(context::unnamed_organization(&options, deployment, None)?
        .map(|unnamed| unnamed.map(|(organization, _)| organization))
        .map_err(|failure| match failure {
            CommonOrganizationFailure::Unauthenticated => MemberGrantFailure::Unauthenticated,
            CommonOrganizationFailure::Forbidden => MemberGrantFailure::Forbidden,
            CommonOrganizationFailure::InvalidInput => MemberGrantFailure::InvalidInput,
            CommonOrganizationFailure::Unreachable(category) => {
                MemberGrantFailure::Unreachable { category }
            }
        }))
}

/// Every organization the member is an active member of, by ID and slug, read to the last
/// page.
pub(super) fn active(api: &MemberGrantApi) -> Result<Vec<(String, String)>, MemberGrantFailure> {
    let invalid = MemberGrantFailure::InvalidResponse {
        credential_rejected: false,
    };
    super::super::super::paging::every_page(invalid, |cursor| {
        api.active_organizations(Some(PAGE), cursor)
    })
}

/// The organization `named` names: an ID as given, a slug to the ID of the organization it
/// names among the member's.
pub(super) fn named(api: &MemberGrantApi, named: &str) -> Result<Organization, MemberGrantFailure> {
    if useful_support::valid_typed_id(named, "org_") {
        return Ok(Organization {
            id: named.to_owned(),
            slug: None,
        });
    }
    api.organization_id(named).map(|id| Organization {
        id,
        slug: Some(named.to_owned()),
    })
}
