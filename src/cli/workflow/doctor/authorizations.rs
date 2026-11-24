//! The connection authorization read of `useful workflow doctor --runner` with a project in
//! effect: the organization's GitHub connection authorization in force for that project on
//! that runner, shown beside the `github` requirement. It is made through the readiness
//! session, after the connection reads, and changes no requirement's state, code or `metBy`.

use std::io::{self, Write};

use serde::{Serialize, Serializer};
use useful_api::{
    ConnectionAuthorization, ConnectionAuthorizationFilter, ConnectionAuthorizationRuns,
    MemberGrantApi,
};

use useful_execution::visible_text;

use super::readiness::{Ending, FamilyFailure, Session};

/// The provider whose authorizations are read: Cloud issues only the GitHub App installation
/// to a runner through one.
const PROVIDER: &str = "github";

/// A page larger than the one authorization that can be in force for a project, a runner and a
/// provider.
const PAGE_LIMIT: i32 = 200;

/// The authorization read for a project and a runner: the one in force, or none.
pub(super) struct Authorization<'a> {
    project: &'a str,
    runner: &'a str,
    in_force: Option<InForce>,
}

/// An authorization in force, as the doctor shows it.
#[derive(Serialize)]
pub(super) struct InForce {
    id: String,
    #[serde(serialize_with = "runs_name")]
    runs: ConnectionAuthorizationRuns,
    repository: Option<String>,
}

fn runs_name<S: Serializer>(
    runs: &ConnectionAuthorizationRuns,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(runs.name())
}

/// Reads the organization's GitHub connection authorizations in force for `project` on
/// `runner`: the authorization read, `None` when Cloud refused the read or could not serve it,
/// which is passed over, or the failure that ends the command.
pub(super) fn read<'a>(
    session: &Session<'_>,
    project: &'a str,
    runner: &'a str,
) -> anyhow::Result<Result<Option<Authorization<'a>>, Ending>> {
    let filter = ConnectionAuthorizationFilter {
        project_id: Some(project),
        runner_id: Some(runner),
        provider: Some(PROVIDER),
        connection_id: None,
    };
    let listed = session.call(
        MemberGrantApi::new,
        "prepare connection authorization networking",
        |api, organization| {
            api.connection_authorizations(organization, filter, Some(PAGE_LIMIT), None)
        },
    )?;
    let items = match listed {
        Ok(page) if page.next_cursor.is_none() => page.items,
        Ok(_) => return Ok(Err(Ending::InvalidResponse)),
        Err(failure) => return Ok(failure.ending().map_or(Ok(None), Err)),
    };
    // At most one is in force for a project, a runner and a provider.
    let mut items = items.into_iter();
    let in_force = items.next().map(InForce::from);
    if items.next().is_some() {
        return Ok(Err(Ending::InvalidResponse));
    }
    Ok(Ok(Some(Authorization {
        project,
        runner,
        in_force,
    })))
}

impl From<ConnectionAuthorization> for InForce {
    fn from(authorization: ConnectionAuthorization) -> Self {
        Self {
            runs: ConnectionAuthorizationRuns::of(authorization.runs),
            id: authorization.id,
            repository: authorization.repository,
        }
    }
}

impl Authorization<'_> {
    /// The authorization in force, or `None` where none is, as the JSON document carries it.
    pub(super) const fn in_force(&self) -> Option<&InForce> {
        self.in_force.as_ref()
    }

    /// The line beside the `github` requirement.
    pub(super) fn write_human(&self, output: &mut impl Write) -> io::Result<()> {
        let Some(in_force) = &self.in_force else {
            return writeln!(
                output,
                "  authorization: none in force for project {} on runner {}",
                self.project, self.runner
            );
        };
        write!(
            output,
            "  authorization: {} · runs {}",
            in_force.id,
            in_force.runs.name()
        )?;
        match &in_force.repository {
            Some(repository) => writeln!(output, " · repository {}", visible_text(repository)),
            None => writeln!(output),
        }
    }
}
