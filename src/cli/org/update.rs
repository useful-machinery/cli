use clap::{ArgGroup, Args};

use crate::cli::OrganizationArg;
use crate::exit_code::ExitCode;
use useful_api::update_organization;
use useful_human_auth::Deployment;

use super::{LeafOptions, output};

pub(super) const ABOUT: &str = "Update an organization";

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("profile")
        .required(true)
        .multiple(true)
        .args(["name", "slug"])
))]
pub(super) struct Command {
    #[arg(value_name = super::ORG, help = OrganizationArg::HELP)]
    organization_ref: OrganizationArg,

    #[arg(long, help = "Set the organization display name")]
    name: Option<String>,

    #[arg(long, help = "Set the exact organization slug")]
    slug: Option<String>,

    // Clap input ownership remains operation-local; shared execution policy lives in LeafOptions.
    #[command(flatten)]
    options: LeafOptions,
}

impl Command {
    pub(super) fn execute(self, deployment: &Deployment) -> anyhow::Result<ExitCode> {
        let Self {
            organization_ref,
            name,
            slug,
            options,
        } = self;
        options.execute_mutation(
            deployment,
            |client, api_url, access_token, idempotency_key| {
                update_organization(
                    client,
                    api_url,
                    access_token,
                    &organization_ref,
                    idempotency_key,
                    name.as_deref(),
                    slug.as_deref(),
                )
            },
            output::write_update,
        )
    }
}
