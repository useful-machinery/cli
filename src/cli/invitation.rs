mod output;

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::Context;
use zeroize::Zeroizing;

use crate::exit_code::ExitCode;
use useful_api::{
    AcceptInvitationOutcome, HttpClient, InvitationTarget, InvitationTerminationOutcome,
    IssueInvitationOutcome, ListInvitationInboxOutcome, ListOrganizationInvitationsOutcome,
    OrganizationError, PreviewInvitationOutcome, accept_invitation, decline_invitation,
    issue_invitation, list_invitation_inbox, list_organization_invitations, preview_invitation,
    revoke_invitation,
};
use useful_human_auth::Deployment;
use useful_human_auth::SecretToken;

use super::context::{self, OrgArgs};
use super::{CommandResult, PaginationArgs};

const MAX_CAPABILITY_BYTES: u64 = 128;

pub(super) type InvitationOptions =
    super::CommonArgs<super::InvitationJson, super::PrincipalAuthenticationArgs>;

// Invitation leaves keep operation-local execution and error context rather than exposing
// organization-profile terminology through a shared operation abstraction. The leaves parse
// where the tree puts them: the organization's (`useful org invitation`) in `org`, which run
// through `issue`, `list_for_organization` and `revoke` here, and the invited person's
// (`useful account invitation`) in `account`, which run through `list_inbox` and `Access`
// here, beside the renderer both sides share.

impl InvitationOptions {
    fn execute<O>(
        self,
        deployment: &Deployment,
        operation: impl FnMut(&HttpClient, &str, &str) -> Result<O, OrganizationError>,
        write: impl FnOnce(
            &str,
            &O,
            super::PrincipalAuthenticationKind,
            bool,
        ) -> anyhow::Result<ExitCode>,
    ) -> anyhow::Result<ExitCode>
    where
        O: super::HumanCredentialOutcome<Error = OrganizationError>,
    {
        let outcome = super::execute_with_principal_credential(
            deployment,
            self.http.transport_policy(),
            &self.authentication,
            "prepare invitation networking",
            "contact invitation API at",
            operation,
        )?;
        write(
            deployment.fingerprint().api_url(),
            &outcome,
            self.authentication.kind(),
            self.json,
        )
        .context("write invitation result")
    }

    fn execute_mutation<O>(
        self,
        deployment: &Deployment,
        mut operation: impl FnMut(&HttpClient, &str, &str, &str) -> Result<O, OrganizationError>,
        write: impl FnOnce(
            &str,
            &O,
            super::PrincipalAuthenticationKind,
            bool,
        ) -> anyhow::Result<ExitCode>,
    ) -> anyhow::Result<ExitCode>
    where
        O: super::HumanCredentialOutcome<Error = OrganizationError>,
    {
        let idempotency_key = useful_support::generate_idempotency_key()
            .context("generate invitation mutation request identity")?;
        self.execute(
            deployment,
            |client, api_url, access_token| {
                operation(client, api_url, access_token, &idempotency_key)
            },
            write,
        )
    }
}

pub(super) fn list_inbox(
    options: InvitationOptions,
    deployment: &Deployment,
    pagination: &PaginationArgs,
) -> CommandResult {
    options
        .execute(
            deployment,
            |client, api_url, access_token| {
                list_invitation_inbox(
                    client,
                    api_url,
                    access_token,
                    pagination.limit,
                    pagination.cursor.as_deref(),
                )
            },
            output::write_inbox,
        )
        .map_err(Into::into)
}

/// The invited person's access to one invitation: its ID, the optional source of an email
/// invitation's capability, and the leaf's options.
pub(super) struct Access {
    pub(super) invitation_id: String,
    pub(super) capability_file: Option<PathBuf>,
    pub(super) options: InvitationOptions,
}

impl Access {
    pub(super) fn show(self, deployment: &Deployment) -> CommandResult {
        self.execute(
            deployment,
            preview_invitation,
            |deployment, _, outcome, authentication, json| {
                output::write_preview(deployment, outcome, authentication, json)
            },
        )
        .map_err(Into::into)
    }

    pub(super) fn accept(self, deployment: &Deployment) -> CommandResult {
        self.execute_mutation(
            deployment,
            accept_invitation,
            |deployment, _, outcome, authentication, json| {
                output::write_accept(deployment, outcome, authentication, json)
            },
        )
        .map_err(Into::into)
    }

    pub(super) fn decline(self, deployment: &Deployment) -> CommandResult {
        self.execute_mutation(
            deployment,
            decline_invitation,
            |deployment, invitation_id, outcome, authentication, json| {
                output::write_termination(
                    deployment,
                    invitation_id,
                    outcome,
                    output::TerminationAction::Decline,
                    authentication,
                    json,
                )
            },
        )
        .map_err(Into::into)
    }

    // Read access and mutation access intentionally keep different capability and request-
    // identity signatures even though their final renderer forwarding is parallel.
    fn execute<O>(
        self,
        deployment: &Deployment,
        mut operation: impl FnMut(
            &HttpClient,
            &str,
            &str,
            &str,
            Option<&str>,
        ) -> Result<O, OrganizationError>,
        write: impl FnOnce(
            &str,
            &str,
            &O,
            super::PrincipalAuthenticationKind,
            bool,
        ) -> anyhow::Result<ExitCode>,
    ) -> anyhow::Result<ExitCode>
    where
        O: super::HumanCredentialOutcome<Error = OrganizationError>,
    {
        self.with_access(deployment, |options, invitation_id, capability| {
            options.execute(
                deployment,
                |client, api_url, access_token| {
                    operation(
                        client,
                        api_url,
                        access_token,
                        &invitation_id,
                        capability.as_ref().map(SecretToken::expose),
                    )
                },
                |deployment, outcome, authentication, json| {
                    write(deployment, &invitation_id, outcome, authentication, json)
                },
            )
        })
    }

    // The mutation variant stays separate because its operation receives the generated
    // idempotency key; merging it with reads would make that security boundary optional.
    fn execute_mutation<O>(
        self,
        deployment: &Deployment,
        mut operation: impl FnMut(
            &HttpClient,
            &str,
            &str,
            &str,
            Option<&str>,
            &str,
        ) -> Result<O, OrganizationError>,
        write: impl FnOnce(
            &str,
            &str,
            &O,
            super::PrincipalAuthenticationKind,
            bool,
        ) -> anyhow::Result<ExitCode>,
    ) -> anyhow::Result<ExitCode>
    where
        O: super::HumanCredentialOutcome<Error = OrganizationError>,
    {
        self.with_access(deployment, |options, invitation_id, capability| {
            options.execute_mutation(
                deployment,
                |client, api_url, access_token, idempotency_key| {
                    operation(
                        client,
                        api_url,
                        access_token,
                        &invitation_id,
                        capability.as_ref().map(SecretToken::expose),
                        idempotency_key,
                    )
                },
                |deployment, outcome, authentication, json| {
                    write(deployment, &invitation_id, outcome, authentication, json)
                },
            )
        })
    }

    fn with_access(
        self,
        deployment: &Deployment,
        execute: impl FnOnce(InvitationOptions, String, Option<SecretToken>) -> anyhow::Result<ExitCode>,
    ) -> anyhow::Result<ExitCode> {
        if self.options.authentication.uses_stdin()
            && self.capability_file.as_deref() == Some(Path::new("-"))
        {
            return Err(anyhow::anyhow!(
                "standard input cannot supply both a service API key and an invitation capability"
            ));
        }
        match self.read_capability() {
            Ok(capability) => execute(self.options, self.invitation_id, capability),
            Err(error) => output::write_capability_error(
                deployment.fingerprint().api_url(),
                &error,
                self.options.json,
            ),
        }
    }

    fn read_capability(&self) -> Result<Option<SecretToken>, CapabilityError> {
        self.capability_file
            .as_deref()
            .map(|path| read_capability(path, &self.invitation_id))
            .transpose()
    }
}

/// Runs `run` in the organization in effect, for the organization's own leaves.
fn execute_in(
    options: InvitationOptions,
    deployment: &Deployment,
    org: OrgArgs,
    run: impl FnOnce(InvitationOptions, &str) -> anyhow::Result<ExitCode>,
) -> CommandResult {
    context::execute_in(org, options, deployment, output::write_common, run)
}

pub(super) fn issue(
    options: InvitationOptions,
    deployment: &Deployment,
    org: OrgArgs,
    target: InvitationTarget<'_>,
) -> CommandResult {
    execute_in(options, deployment, org, |options, organization| {
        options.execute_mutation(
            deployment,
            |client, api_url, access_token, idempotency_key| {
                issue_invitation(
                    client,
                    api_url,
                    access_token,
                    organization,
                    idempotency_key,
                    target,
                )
            },
            output::write_issue,
        )
    })
}

pub(super) fn list_for_organization(
    options: InvitationOptions,
    deployment: &Deployment,
    org: OrgArgs,
    pagination: &PaginationArgs,
) -> CommandResult {
    execute_in(options, deployment, org, |options, organization| {
        options.execute(
            deployment,
            |client, api_url, access_token| {
                list_organization_invitations(
                    client,
                    api_url,
                    access_token,
                    organization,
                    pagination.limit,
                    pagination.cursor.as_deref(),
                )
            },
            output::write_organization_list,
        )
    })
}

pub(super) fn revoke(
    options: InvitationOptions,
    deployment: &Deployment,
    org: OrgArgs,
    invitation_id: &str,
) -> CommandResult {
    execute_in(options, deployment, org, |options, organization| {
        options.execute_mutation(
            deployment,
            |client, api_url, access_token, idempotency_key| {
                revoke_invitation(
                    client,
                    api_url,
                    access_token,
                    organization,
                    invitation_id,
                    idempotency_key,
                )
            },
            |deployment, outcome, authentication, json| {
                output::write_termination(
                    deployment,
                    invitation_id,
                    outcome,
                    output::TerminationAction::Revoke { organization },
                    authentication,
                    json,
                )
            },
        )
    })
}

pub(super) fn parse_invitation_id(value: &str) -> Result<String, String> {
    parse_typed_id(value, "inv_", "invitation")
}

pub(super) fn parse_principal_id(value: &str) -> Result<String, String> {
    parse_typed_id(value, "prn_", "principal")
}

fn parse_typed_id(value: &str, prefix: &str, name: &str) -> Result<String, String> {
    if useful_support::valid_typed_id(value, prefix) {
        Ok(value.to_owned())
    } else {
        Err(format!("{name} must be an exact {prefix} identifier"))
    }
}

fn read_capability(path: &Path, invitation_id: &str) -> Result<SecretToken, CapabilityError> {
    let source = if path == Path::new("-") {
        CapabilitySource::Stdin
    } else {
        CapabilitySource::File(path.to_owned())
    };
    let mut bytes = Zeroizing::new(Vec::new());
    if path == Path::new("-") {
        io::stdin()
            .lock()
            .take(MAX_CAPABILITY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| CapabilityError::io(source.clone(), "read", error))?;
    } else {
        read_private_capability_file(path, &source, &mut bytes)?;
    }
    if bytes.len() as u64 > MAX_CAPABILITY_BYTES {
        return Err(CapabilityError::invalid(
            source,
            "capability input exceeds 128 bytes",
        ));
    }
    super::secret_file::trim_line_ending(&mut bytes);
    let capability = std::str::from_utf8(&bytes)
        .map_err(|_| CapabilityError::invalid(source.clone(), "capability input is not UTF-8"))?;
    if !valid_capability(capability, invitation_id) {
        return Err(CapabilityError::invalid(
            source,
            "capability does not match the invitation ID or required syntax",
        ));
    }
    Ok(SecretToken::new(capability.to_owned()))
}

fn read_private_capability_file(
    path: &Path,
    source: &CapabilitySource,
    bytes: &mut Vec<u8>,
) -> Result<(), CapabilityError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| CapabilityError::io(source.clone(), "inspect", error))?;
    validate_private_capability_file(source, &metadata)?;
    if metadata.len() > MAX_CAPABILITY_BYTES {
        return Err(CapabilityError::invalid(
            source.clone(),
            "capability file exceeds 128 bytes",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| CapabilityError::io(source.clone(), "open", error))?;
    let opened = file
        .metadata()
        .map_err(|error| CapabilityError::io(source.clone(), "inspect opened", error))?;
    validate_private_capability_file(source, &opened)?;
    file.take(MAX_CAPABILITY_BYTES + 1)
        .read_to_end(bytes)
        .map_err(|error| CapabilityError::io(source.clone(), "read", error))?;
    Ok(())
}

fn validate_private_capability_file(
    source: &CapabilitySource,
    metadata: &fs::Metadata,
) -> Result<(), CapabilityError> {
    if !metadata.file_type().is_file() {
        return Err(CapabilityError::unsafe_source(
            source.clone(),
            "expected a regular non-symbolic-link file",
        ));
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(CapabilityError::unsafe_source(
            source.clone(),
            "file must be owned by the current user",
        ));
    }
    if metadata.mode() & 0o7777 != 0o600 {
        return Err(CapabilityError::unsafe_source(
            source.clone(),
            "file mode must be 0600",
        ));
    }
    Ok(())
}

fn valid_capability(value: &str, invitation_id: &str) -> bool {
    let Some((embedded_id, secret)) = value.split_once('.') else {
        return false;
    };
    embedded_id == invitation_id
        && useful_support::valid_typed_id(embedded_id, "inv_")
        && secret.len() == 43
        && secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[derive(Clone, Debug)]
enum CapabilitySource {
    Stdin,
    File(PathBuf),
}

impl fmt::Display for CapabilitySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdin => formatter.write_str("stdin"),
            Self::File(path) => write!(formatter, "{}", path.display()),
        }
    }
}

#[derive(Debug)]
pub(super) struct CapabilityError {
    source: CapabilitySource,
    kind: CapabilityErrorKind,
}

impl CapabilityError {
    fn io(source: CapabilitySource, operation: &'static str, error: io::Error) -> Self {
        Self {
            source,
            kind: CapabilityErrorKind::Io { operation, error },
        }
    }

    fn unsafe_source(source: CapabilitySource, requirement: &'static str) -> Self {
        Self {
            source,
            kind: CapabilityErrorKind::Unsafe { requirement },
        }
    }

    fn invalid(source: CapabilitySource, reason: &'static str) -> Self {
        Self {
            source,
            kind: CapabilityErrorKind::Invalid { reason },
        }
    }

    pub(super) const fn outcome(&self) -> &'static str {
        match self.kind {
            CapabilityErrorKind::Invalid { .. } => "invalid_capability",
            CapabilityErrorKind::Io { .. } | CapabilityErrorKind::Unsafe { .. } => {
                "capability_source_unavailable"
            }
        }
    }
}

#[derive(Debug)]
enum CapabilityErrorKind {
    Io {
        operation: &'static str,
        error: io::Error,
    },
    Unsafe {
        requirement: &'static str,
    },
    Invalid {
        reason: &'static str,
    },
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            CapabilityErrorKind::Io { operation, error } => write!(
                formatter,
                "{operation} invitation capability source {}: {error}",
                self.source
            ),
            CapabilityErrorKind::Unsafe { requirement } => write!(
                formatter,
                "invitation capability source {} is unsafe: {requirement}",
                self.source
            ),
            CapabilityErrorKind::Invalid { reason } => write!(
                formatter,
                "invalid invitation capability from {}: {reason}",
                self.source
            ),
        }
    }
}

impl std::error::Error for CapabilityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            CapabilityErrorKind::Io { error, .. } => Some(error),
            CapabilityErrorKind::Unsafe { .. } | CapabilityErrorKind::Invalid { .. } => None,
        }
    }
}

super::impl_organization_human_credential_outcome!(
    IssueInvitationOutcome,
    ListOrganizationInvitationsOutcome,
    ListInvitationInboxOutcome,
    PreviewInvitationOutcome,
    AcceptInvitationOutcome,
    InvitationTerminationOutcome,
);
