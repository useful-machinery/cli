use std::convert::Infallible;
use std::ops::Deref;
use std::str::FromStr;

macro_rules! identifier_arg {
    ($name:ident, $value_name:literal, $help:literal) => {
        identifier_arg!($name, $value_name);

        impl $name {
            pub(super) const HELP: &'static str = $help;
        }
    };
    ($name:ident, $value_name:literal) => {
        #[derive(Clone, Debug)]
        pub(super) struct $name(String);

        impl $name {
            pub(super) const VALUE_NAME: &'static str = $value_name;
        }

        impl FromStr for $name {
            type Err = Infallible;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Ok(Self(value.to_owned()))
            }
        }

        impl Deref for $name {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    };
}

#[derive(Clone, Debug)]
pub(super) struct OrganizationArg(String);

impl OrganizationArg {
    pub(super) const HELP: &'static str = "Organization ID or exact slug";

    pub(super) fn into_string(self) -> String {
        self.0
    }
}

impl FromStr for OrganizationArg {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if useful_support::valid_organization_ref(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err("must be an organization ID or lowercase organization slug".to_owned())
        }
    }
}

impl Deref for OrganizationArg {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

identifier_arg!(PoolArg, "POOL", "Runner pool ID or exact name");

impl PoolArg {
    pub(super) fn into_string(self) -> String {
        self.0
    }

    pub(super) fn resolve_id(
        &self,
        api: &useful_api::RunnerApi,
        organization: &str,
    ) -> Result<String, useful_api::RunnerFailure> {
        api.get_pool(organization, self).map(|pool| pool.id)
    }
}

identifier_arg!(RepositoryArg, "REPOSITORY", "Provider repository ID");

/// Whether `value` is a provider repository ID as GitHub and GitLab number one: decimal digits
/// with no leading zero, a positive 64-bit integer.
pub(super) fn provider_repository_id(value: &str) -> bool {
    !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && matches!(value.parse::<i64>(), Ok(1..=i64::MAX))
}

/// A repository as `useful project create` and `update` name it, parsed with no
/// request.
#[derive(Clone, Debug)]
pub(super) enum RepositoryRef {
    /// The provider's repository ID.
    Id(String),
    /// The repository's path: `owner/name`, or a GitLab project's full path.
    Path(String),
}

impl RepositoryRef {
    pub(super) const VALUE_NAME: &'static str = "REPOSITORY";
    pub(super) const HELP: &'static str =
        "Repository path (owner/name, or a GitLab project's full path) or provider repository ID";
}

impl FromStr for RepositoryRef {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if provider_repository_id(value) {
            Ok(Self::Id(value.to_owned()))
        } else if value.contains('/') {
            Ok(Self::Path(value.to_owned()))
        } else {
            Err(
                "must be a repository path such as owner/name, or a provider repository ID"
                    .to_owned(),
            )
        }
    }
}

impl std::fmt::Display for RepositoryRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Id(value) | Self::Path(value) => formatter.write_str(value),
        }
    }
}
