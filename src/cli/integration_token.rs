//! A token service's token, as both `integration` groups act on it: `useful account integration`
//! on the member's and `useful org integration` on the organization's (REQ-INTEGRATION-16 to
//! REQ-INTEGRATION-20). Here are the reads of an owner's tokens and of the token services the
//! deployment serves, the token read from a file, standard input or a prompt that does not echo
//! and stored under one request key, and the views and documents of a token in `output`. The
//! token stays in zeroizing storage from the read to the request body and is dropped once sent;
//! no view names it.

mod output;

use std::collections::BTreeMap;
use std::io::{self, IsTerminal};
use std::path::Path;

use anyhow::Context as _;
use zeroize::Zeroizing;

use super::account::grant::replayed;
use super::paging::every_page;
use super::secret_file::{SecretInput, one_line, prompt_without_echo};
use super::{ApiFailureReport, CommandFailure, CommandResult};
use crate::exit_code::ExitCode;
use useful_api::{
    HttpTransportPolicy, IntegrationToken, IntegrationTokenOwner, MEMBER_GRANT_PAGE,
    MemberGrantApi, MemberGrantFailure, ServedTokenService,
};
use useful_human_auth::Deployment;

pub(in crate::cli) use output::{ListedToken, Tokens, side, write_refusal, write_revoked};

/// The most bytes of a token: REQ-INTEGRATION-1's bound.
const MAX_TOKEN: usize = 4096;

/// A token read from a file or standard input: REQ-INTEGRATION-1's bound, and one trailing LF or
/// CRLF, which is trimmed after reading.
const TOKEN_INPUT: SecretInput = SecretInput {
    name: "integration token",
    max_bytes: MAX_TOKEN as u64 + 2,
    max_text: "4 KiB",
};

/// Every unrevoked token of `owner`, read to the last page.
pub(in crate::cli) fn every(
    api: &MemberGrantApi,
    owner: IntegrationTokenOwner<'_>,
) -> Result<Vec<IntegrationToken>, MemberGrantFailure> {
    let invalid = MemberGrantFailure::InvalidResponse {
        credential_rejected: false,
    };
    every_page(invalid, |cursor| {
        api.integration_tokens(owner, Some(MEMBER_GRANT_PAGE), cursor)
            .map(|page| (page.items, page.next_cursor))
    })
}

/// The owner's unrevoked token of `service`, read from every page of the owner's tokens.
pub(in crate::cli) fn held(
    api: &MemberGrantApi,
    owner: IntegrationTokenOwner<'_>,
    service: &str,
) -> Result<Option<IntegrationToken>, MemberGrantFailure> {
    Ok(every(api, owner)?
        .into_iter()
        .find(|token| token.provider == service))
}

/// The token services the deployment serves (REQ-GRANT-78): none from one that serves none or
/// predates the served read, which is then asked for no token list.
pub(in crate::cli) fn served(
    api: &MemberGrantApi,
) -> Result<Vec<ServedTokenService>, MemberGrantFailure> {
    Ok(api
        .served_integrations()?
        .map(|served| served.token_services)
        .unwrap_or_default())
}

/// The display name the directory of the organization `reference` names, an ID or a slug, gives
/// each principal, by ID, read to the last page (REQ-INTEGRATION-19). A read that fails names
/// nobody, so each principal is shown by ID.
pub(in crate::cli) fn directory(api: &MemberGrantApi, reference: &str) -> BTreeMap<String, String> {
    let invalid = MemberGrantFailure::InvalidResponse {
        credential_rejected: false,
    };
    every_page(invalid, |cursor| {
        api.organization_directory(reference, Some(MEMBER_GRANT_PAGE), cursor)
    })
    .map(|entries| {
        entries
            .into_iter()
            .filter_map(|(principal, name)| Some((principal, name?)))
            .collect()
    })
    .unwrap_or_default()
}

/// The refusal of `reconnect` for a service whose token is not held, `token_not_found` with
/// exit 1: `reconnect` never makes a token, and `connect`, the command that does, is the remedy
/// (REQ-INTEGRATION-18).
pub(in crate::cli) fn not_held(held: &str, connect: &str) -> ApiFailureReport {
    ApiFailureReport::new(
        "token_not_found",
        format!("error: {held}"),
        format!("Connect it first:\n  {connect}"),
        crate::exit_code::OutcomeClass::GeneralFailure,
    )
}

/// What a token service is called for people: the name the deployment gives it, else its id.
fn title(service: &ServedTokenService) -> &str {
    service.display_name.as_deref().unwrap_or(&service.name)
}

/// Storing an owner's token of one service: where, as whom, how its result is printed and where
/// the token is read from.
pub(in crate::cli) struct Store<'a> {
    pub(in crate::cli) deployment: &'a Deployment,
    pub(in crate::cli) policy: HttpTransportPolicy,
    pub(in crate::cli) json: bool,
    pub(in crate::cli) owner: IntegrationTokenOwner<'a>,
    /// The slug the command named the owner organization by, which the record's view states
    /// beside its ID; none for the member's token.
    pub(in crate::cli) slug: Option<&'a str>,
    pub(in crate::cli) service: &'a ServedTokenService,
    /// `--from-file`: a private file, or `-` for standard input.
    pub(in crate::cli) from_file: Option<&'a Path>,
}

impl Store<'_> {
    /// Connects the owner's first token of the service (REQ-INTEGRATION-16): reads the owner's
    /// tokens, and where one of the service is held refuses with `refuse_held`, exit 2, before
    /// any token is read; otherwise reads the token and stores it. A failure is reported with
    /// `report`'s remedy and status.
    pub(in crate::cli) fn connect(
        &self,
        report: impl Fn(&MemberGrantFailure) -> ApiFailureReport,
        refuse_held: impl FnOnce(&IntegrationToken) -> CommandFailure,
    ) -> CommandResult {
        let api_url = self.deployment.fingerprint().api_url();
        let held =
            super::with_human_session_api(self.deployment, self.policy, |api: &MemberGrantApi| {
                held(api, self.owner, &self.service.name)
            })?;
        match held {
            Ok(None) => self.store(false, report),
            Ok(Some(token)) => Err(refuse_held(&token)),
            Err(failure) => Ok(write_refusal(api_url, &report(&failure), self.json)?),
        }
    }

    /// Reads the token and stores it once, again under the same key when the answer was lost:
    /// with `replace` as the next version of the token the owner holds, which keeps its ID and
    /// its authorizations (REQ-INTEGRATION-18). A failure is reported with `report`'s remedy
    /// and status; a token that cannot be read or is outside REQ-INTEGRATION-1's form is exit 2
    /// with nothing sent.
    pub(in crate::cli) fn store(
        &self,
        replace: bool,
        report: impl Fn(&MemberGrantFailure) -> ApiFailureReport,
    ) -> CommandResult {
        let api_url = self.deployment.fingerprint().api_url();
        let token = self.read()?;
        let key = useful_support::generate_idempotency_key()
            .context("generate integration token request key")?;
        let stored =
            super::with_human_session_api(self.deployment, self.policy, |api: &MemberGrantApi| {
                replayed(|| {
                    api.store_integration_token(
                        self.owner,
                        &self.service.name,
                        &token,
                        replace,
                        &key,
                    )
                })
            })?;
        drop(token);
        Ok(match stored {
            Ok(record) => output::write_connected(api_url, &record, self.slug, replace, self.json)?,
            Err(failure) => write_refusal(api_url, &report(&failure), self.json)?,
        })
    }

    /// Reads the token: from `--from-file`, a private file or `-` for standard input; without it
    /// from standard input when that is no terminal, and otherwise at a prompt on the terminal
    /// that does not echo. One trailing line ending is trimmed, and a read that fails or a token
    /// outside REQ-INTEGRATION-1's form is exit 2, whose message never quotes the input.
    fn read(&self) -> Result<Zeroizing<Vec<u8>>, CommandFailure> {
        let title = title(self.service);
        let read = match self.from_file {
            Some(path) => TOKEN_INPUT.read(path),
            None if !io::stdin().is_terminal() => TOKEN_INPUT.read(Path::new("-")),
            None => prompt_without_echo(&format!("Paste the {title} token (input is hidden): ")),
        };
        read.and_then(|bytes| one_line(&format!("{title} token"), MAX_TOKEN, bytes))
            .map_err(|error| CommandFailure::with_exit_code(error, ExitCode::UsageError))
    }
}
