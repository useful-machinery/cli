use anyhow::Context;
use clap::Args;

use crate::cli::context::{self, OrgArgs};
use useful_api::ListCurrentPrincipalMembershipsOutcome;
use useful_human_auth::Deployment;

use super::{LeafOptions, output};

pub(super) const ABOUT: &str = "List your organization memberships";
const AFTER_HELP: &str = "Visibility:\n  Organization names and slugs appear only for active memberships in active\n  organizations. Historical rows retain organization IDs and lifecycle states.";

#[derive(Debug, Args)]
#[command(after_help = AFTER_HELP)]
pub(super) struct Command {
    #[command(flatten)]
    pagination: super::super::PaginationArgs,

    #[command(flatten)]
    org: OrgArgs,

    #[command(flatten)]
    options: LeafOptions,
}

impl Command {
    /// Lists one page of the caller's memberships and marks the organization in
    /// effect, which, unlike a command that acts in it, the list does not need.
    pub(super) fn execute(self, deployment: &Deployment) -> crate::cli::CommandResult {
        let Self {
            pagination,
            org,
            options,
        } = self;
        let named = org.named_in_process()?;
        let outcome = options.read(deployment, |client, api_url, access_token| {
            useful_api::list_current_principal_memberships(
                client,
                api_url,
                access_token,
                pagination.limit,
                pagination.cursor.as_deref(),
            )
        })?;
        let api_url = deployment.fingerprint().api_url();
        let in_effect = match (named, &outcome) {
            (Some(named), _) => Some(named),
            (None, ListCurrentPrincipalMembershipsOutcome::Listed(page)) => {
                // A first page with no next page holds every membership, so the organization in
                // effect is chosen among them without reading them again.
                let known = (pagination.cursor.is_none() && page.next_cursor.is_none())
                    .then(|| context::active_organizations(&page.items));
                match context::unnamed_in_effect(&options, deployment, known)? {
                    Ok(in_effect) => in_effect.ok(),
                    Err(failure) => {
                        return output::write_context_failure(
                            api_url,
                            &failure,
                            options.authentication.kind(),
                            options.json,
                        )
                        .context("write organization result")
                        .map_err(Into::into);
                    }
                }
            }
            (None, ListCurrentPrincipalMembershipsOutcome::Common(_)) => None,
        };
        output::write_list(
            api_url,
            &outcome,
            in_effect.as_ref(),
            options.authentication.kind(),
            options.json,
        )
        .context("write organization result")
        .map_err(Into::into)
    }
}
