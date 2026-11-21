use clap::Args;

use crate::cli::OrganizationArg;
use crate::cli::context::OrgArgs;
use useful_api::get_organization;
use useful_human_auth::Deployment;

use super::{LeafOptions, output};

pub(super) const ABOUT: &str = "Show an organization";

#[derive(Debug, Args)]
pub(super) struct Command {
    #[arg(
        value_name = super::ORG,
        help = "Organization ID or exact slug (default: the organization in effect)",
        conflicts_with = "org"
    )]
    organization_ref: Option<OrganizationArg>,

    #[command(flatten)]
    org: OrgArgs,

    // Clap input ownership remains operation-local; shared execution policy lives in LeafOptions.
    #[command(flatten)]
    options: LeafOptions,
}

impl Command {
    pub(super) fn execute(self, deployment: &Deployment) -> crate::cli::CommandResult {
        let Self {
            organization_ref,
            org,
            options,
        } = self;
        let show = |options: LeafOptions, organization: &str| {
            options.execute(
                deployment,
                |client, api_url, access_token| {
                    get_organization(client, api_url, access_token, organization)
                },
                output::write_show,
            )
        };
        match organization_ref {
            Some(organization_ref) => show(options, &organization_ref).map_err(Into::into),
            None => options.execute_in(org, deployment, show),
        }
    }
}
