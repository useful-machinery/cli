//! The names an assignment admitted in `cloud` mode blocks: the service environment's value of each reaches no step
//! of the run and no `useful` command the runner starts for it, so each
//! carries only what the runner offers from Cloud. The set is settled once
//! per admission and carried with the assignment's mode (`AdmittedMode`),
//! and one function, `BlockedNames::remove_from`, removes it from the
//! process snapshot wherever an environment is built for the assignment:
//! the admission's offer and each command environment alike. An admission
//! whose hold carries no list of the provider table's names it can trust
//! has no set: it is declined before anything is offered
//! (`provider_table_untrusted`).

use std::collections::BTreeSet;
use std::ffi::OsString;

use useful_execution::{
    CLAUDE_CODE_LOGIN_VARIABLE, CODEX_LOGIN_VARIABLE, EnvironmentSnapshot,
    is_declared_only_environment_name,
};

use super::cloud::GrantProvidersFailure;
use super::grant_token::{self, AssignmentGrantTokens};
use crate::control_protocol::CredentialMode;

/// The fixed names that are neither a name the runner offers a grant token
/// under nor one it offers an agent login as: the aliases a program reads a
/// provider's token from in their place, and the two names Claude Code reads
/// a key or a configuration directory of the host's from.
const ALIASES_AND_CLAUDE_CODE_EXTRAS: [&str; 7] = [
    "GITHUB_TOKEN",
    "LINEAR_API_KEY",
    "GITHUB_PUBLISH_TOKEN_FILE",
    "UM_LINEAR_ACCESS_TOKEN",
    "UM_LINEAR_ACCESS_TOKEN_FILE",
    "ANTHROPIC_API_KEY",
    "CLAUDE_CONFIG_DIR",
];

/// Every name a `cloud` admission blocks whatever it holds: both names of
/// `github`, `gitlab.com` and `linear`, the two agent-login variables, and
/// the aliases and Claude Code's extras.
fn fixed_names() -> impl Iterator<Item = &'static str> {
    grant_token::OFFERED_VARIABLES
        .into_iter()
        .flat_map(|(_, variable, file_variable)| [variable, file_variable])
        .chain([CLAUDE_CODE_LOGIN_VARIABLE, CODEX_LOGIN_VARIABLE])
        .chain(ALIASES_AND_CLAUDE_CODE_EXTRAS)
}

/// Both names of every row of Cloud's provider table the admission of
/// `grant_tokens` was answered, each that is a name a step
/// receives only by declaring it; any
/// other listed name is skipped and the rest are used. A row is not checked
/// as the names a token is offered under are (`usable_names`): a row whose
/// two names are equal, or repeat another row's, has them blocked all the
/// same. None where the admission holds no rows it can trust.
fn listed_names(grant_tokens: &AssignmentGrantTokens) -> impl Iterator<Item = &str> {
    grant_tokens
        .credential_providers()
        .and_then(|answer| answer.as_ref().ok())
        .into_iter()
        .flatten()
        .flat_map(|row| [row.token.as_str(), row.token_file.as_str()])
        .filter(|name| is_declared_only_environment_name(name))
}

/// The blocked names of one assignment admitted in `cloud` mode: the fixed names, both names of every token its
/// admission holds or token service it checked, and both names of every row
/// of Cloud's provider table it was answered that a step receives only by
/// declaring it. Nothing outside the set is blocked, `HOME` and the
/// `USEFUL_` names included.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlockedNames {
    names: BTreeSet<OsString>,
}

impl BlockedNames {
    /// The fixed names alone, which need no list: the whole set where there
    /// is no assignment, as for the check of a login a setup governed by
    /// `cloud` made.
    pub(crate) fn fixed() -> Self {
        Self {
            names: fixed_names().map(OsString::from).collect(),
        }
    }

    /// The set of an admission that holds `grant_tokens`: the fixed names,
    /// both names of each token the hold keeps and each token service it
    /// checked (`AssignmentGrantTokens::offered_names`), and the checked
    /// names of the provider table's rows it was answered (`listed_names`).
    pub(crate) fn of_admission(grant_tokens: Option<&AssignmentGrantTokens>) -> Self {
        let Self { mut names } = Self::fixed();
        if let Some(tokens) = grant_tokens {
            names.extend(
                tokens
                    .offered_names()
                    .chain(listed_names(tokens))
                    .map(OsString::from),
            );
        }
        Self { names }
    }

    /// Whether the set holds `name`, which a step of the assignment then receives only from
    /// what the runner offers.
    pub(crate) fn blocks(&self, name: &str) -> bool {
        self.names.contains(std::ffi::OsStr::new(name))
    }

    /// `environment` without any of the blocked names, as a new snapshot;
    /// `environment` itself is never changed.
    pub(crate) fn remove_from(&self, environment: &EnvironmentSnapshot) -> EnvironmentSnapshot {
        EnvironmentSnapshot::new(
            environment
                .variables()
                .iter()
                .filter(|(name, _)| !self.names.contains(*name))
                .map(|(name, value)| (name.clone(), value.clone())),
        )
    }
}

/// The credential mode an assignment was admitted under, as
/// its offer and each command environment built for it go by it: an
/// assignment admitted in `cloud` carries the names it blocks, settled once
/// by its admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AdmittedMode {
    /// The offer named no mode.
    Unnamed,
    /// `host`.
    Host,
    /// `cloud`, with the assignment's blocked names.
    Cloud(BlockedNames),
}

impl AdmittedMode {
    /// The mode `mode` an offer named, for an admission that holds
    /// `grant_tokens`.
    pub(crate) fn of(
        mode: Option<CredentialMode>,
        grant_tokens: Option<&AssignmentGrantTokens>,
    ) -> Self {
        match mode {
            None => Self::Unnamed,
            Some(CredentialMode::Host) => Self::Host,
            Some(CredentialMode::Cloud) => Self::Cloud(BlockedNames::of_admission(grant_tokens)),
        }
    }

    /// The credential mode the offer named.
    pub(crate) const fn credential_mode(&self) -> Option<CredentialMode> {
        match self {
            Self::Unnamed => None,
            Self::Host => Some(CredentialMode::Host),
            Self::Cloud(_) => Some(CredentialMode::Cloud),
        }
    }
}

/// Why an assignment admitted in `cloud` mode, whose admission holds
/// `grant_tokens`, offers nothing and is declined: without a list of the provider table's names it can
/// trust, the runner cannot know what to block. The cause is closed:
/// `no_route` for a Cloud without the route, `assignment_not_current` for
/// Cloud's refusal, `http_status`, `transport` or `invalid_response` for a
/// list Cloud did not answer usefully, and `setup_unavailable` where there is
/// no hold, since the runner has no agent-login setup, the setup is gone or
/// its call panicked, or the hold asked for no list. `None` where the hold
/// carries rows it can trust.
pub(crate) fn provider_table_untrusted(
    grant_tokens: Option<&AssignmentGrantTokens>,
) -> Option<&'static str> {
    match grant_tokens.and_then(AssignmentGrantTokens::credential_providers) {
        Some(Ok(_)) => None,
        Some(Err(GrantProvidersFailure::NoRoute)) => Some("no_route"),
        Some(Err(GrantProvidersFailure::AssignmentNotCurrent)) => Some("assignment_not_current"),
        Some(Err(GrantProvidersFailure::Cloud(failure))) => Some(failure.cause().as_str()),
        None => Some("setup_unavailable"),
    }
}
