//! Slack connection management over the generated source-connection client.
use reqwest::StatusCode;

use super::generated::{apis, apis::source_connections_api, models};
use super::http_client::zeroize_generated_bearer_access_token;
use super::resource::{
    ProblemFailure, ProblemRow, ProviderRecord, ResourceFailure, classify_problem_error,
    expect_problem_status, invalid, receive_raw, resource_configuration, validate_json_media_type,
};
use super::{HttpTransportPolicy, UnreachableCategory, generated_api_request, problem};

pub type SlackSession = models::SlackAuthorizationSession;
pub type SlackConnection = models::SlackConnection;
pub type SlackConnectionList = models::SlackConnectionList;
pub type SlackChannelCheck = models::SlackChannelCheck;
pub type SlackChannelCheckState = models::slack_channel_check::State;
pub type SlackChannelCheckReason = models::slack_channel_check::Reason;
pub type SlackSessionStatus = models::slack_authorization_session::Status;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SlackFailure {
    Resource(ResourceFailure),
    NotServed,
}

impl SlackFailure {
    pub const fn credential_rejected(&self) -> bool {
        matches!(self, Self::Resource(failure) if failure.credential_rejected())
    }

    pub const fn unauthenticated() -> Self {
        Self::Resource(ResourceFailure::Unauthenticated)
    }

    pub const fn unreachable(category: UnreachableCategory) -> Self {
        Self::Resource(ResourceFailure::Unreachable { category })
    }
}

impl From<ResourceFailure> for SlackFailure {
    fn from(failure: ResourceFailure) -> Self {
        Self::Resource(failure)
    }
}

impl ProblemFailure for SlackFailure {
    fn rate_limited(retry_after: Option<u64>) -> Self {
        ResourceFailure::RateLimited { retry_after }.into()
    }

    fn unreachable(category: UnreachableCategory) -> Self {
        Self::unreachable(category)
    }

    fn invalid_response(credential_rejected: bool) -> Self {
        ResourceFailure::InvalidResponse {
            credential_rejected,
        }
        .into()
    }
}

const PROBLEMS: &[ProblemRow<SlackFailure>] = &[
    (
        StatusCode::BAD_REQUEST,
        problem::BAD_REQUEST,
        SlackFailure::Resource(ResourceFailure::InvalidInput { problem: None }),
    ),
    (
        StatusCode::UNAUTHORIZED,
        problem::UNAUTHORIZED,
        SlackFailure::unauthenticated(),
    ),
    (
        StatusCode::FORBIDDEN,
        problem::FORBIDDEN,
        SlackFailure::Resource(ResourceFailure::Forbidden),
    ),
    (
        StatusCode::NOT_FOUND,
        problem::NOT_FOUND,
        SlackFailure::Resource(ResourceFailure::NotFound),
    ),
    (
        StatusCode::CONFLICT,
        "https://api.usefulmachinery.com/problems/source-connection-conflict",
        SlackFailure::Resource(ResourceFailure::Conflict),
    ),
    (
        StatusCode::CONFLICT,
        problem::IDEMPOTENCY_CONFLICT,
        SlackFailure::Resource(ResourceFailure::Conflict),
    ),
    (
        StatusCode::SERVICE_UNAVAILABLE,
        problem::SERVICE_UNAVAILABLE,
        SlackFailure::NotServed,
    ),
];

fn failure<E>(error: apis::Error<E>) -> SlackFailure {
    classify_problem_error(error, PROBLEMS)
}

pub struct SlackApi {
    configuration: apis::configuration::Configuration,
}

impl SlackApi {
    pub fn new(api_url: &str, token: &str, policy: HttpTransportPolicy) -> anyhow::Result<Self> {
        let configuration = resource_configuration(
            api_url,
            token,
            policy,
            anyhow::anyhow!(
                "invalid Slack connection API endpoint; check the deployment URL and HTTP policy"
            ),
            |error| anyhow::Error::new(error).context("prepare Slack connection networking"),
        )?;
        Ok(Self { configuration })
    }

    pub fn start(
        &self,
        organization: &str,
        connection_id: Option<&str>,
        key: &str,
    ) -> Result<SlackSession, SlackFailure> {
        use models::create_slack_authorization_session_request::Operation;
        let request = models::CreateSlackAuthorizationSessionRequest {
            operation: if connection_id.is_some() {
                Operation::Reauthorize
            } else {
                Operation::Connect
            },
            connection_id: connection_id.map(str::to_owned),
        };
        let session = source_connections_api::create_slack_authorization_session(
            &self.configuration,
            organization,
            key,
            request,
        )
        .map_err(failure)?;
        validate_session(&session, None)?;
        let reauthorize =
            session.operation == models::slack_authorization_session::Operation::Reauthorize;
        if reauthorize != connection_id.is_some()
            || session.connection_id.as_deref() != connection_id
        {
            return Err(invalid().into());
        }
        Ok(session)
    }

    pub fn session(&self, organization: &str, id: &str) -> Result<SlackSession, SlackFailure> {
        let endpoint = format!(
            "{}/v1/organizations/{}/connections/slack/authorization-sessions/{}",
            self.configuration.base_path.trim_end_matches('/'),
            apis::urlencode(organization),
            apis::urlencode(id)
        );
        // Poll through the configured client so a rate limit retains its Retry-After.
        let request = generated_api_request(&self.configuration, reqwest::Method::GET, &endpoint);
        let response = expect_problem_status(receive_raw(request)?, StatusCode::OK, PROBLEMS)?;
        validate_json_media_type(&response.headers)?;
        let session = serde_json::from_slice(&response.body).map_err(|_| invalid())?;
        validate_session(&session, Some(id))?;
        Ok(session)
    }

    pub fn connection(
        &self,
        organization: &str,
        id: &str,
    ) -> Result<SlackConnection, SlackFailure> {
        let connection =
            source_connections_api::get_slack_connection(&self.configuration, organization, id)
                .map_err(failure)?;
        validate_connection(&connection, Some(id))?;
        Ok(connection)
    }

    pub fn check_channel(
        &self,
        organization: &str,
        connection: &str,
        channel: &str,
    ) -> Result<SlackChannelCheck, SlackFailure> {
        let check = source_connections_api::check_slack_channel(
            &self.configuration,
            organization,
            connection,
            channel,
        )
        .map_err(failure)?;
        let usable = check.state == SlackChannelCheckState::Usable;
        if check.channel != channel
            || check.channel_id.is_some() != usable
            || check.reason.is_some() == usable
        {
            return Err(invalid().into());
        }
        Ok(check)
    }

    pub fn list(
        &self,
        organization: &str,
        limit: Option<i32>,
        cursor: Option<&str>,
    ) -> Result<SlackConnectionList, SlackFailure> {
        let page = source_connections_api::list_slack_connections(
            &self.configuration,
            organization,
            limit,
            cursor,
        )
        .map_err(failure)?;
        for connection in &page.items {
            validate_connection(connection, None)?;
        }
        Ok(page)
    }

    pub fn disconnect(
        &self,
        organization: &str,
        id: &str,
        key: &str,
    ) -> Result<SlackConnection, SlackFailure> {
        let connection = source_connections_api::disconnect_slack_connection(
            &self.configuration,
            organization,
            id,
            key,
        )
        .map_err(failure)?;
        validate_connection(&connection, Some(id))?;
        Ok(connection)
    }
}

impl Drop for SlackApi {
    fn drop(&mut self) {
        zeroize_generated_bearer_access_token(&mut self.configuration);
    }
}

fn validate_connection(value: &SlackConnection, id: Option<&str>) -> Result<(), ResourceFailure> {
    ProviderRecord {
        id: &value.id,
        organization_id: &value.organization_id,
        created_at: &value.created_at,
    }
    .validate_connection("scn_", id, &value.updated_at, value.lifecycle_generation)
}

fn validate_session(value: &SlackSession, id: Option<&str>) -> Result<(), ResourceFailure> {
    ProviderRecord {
        id: &value.id,
        organization_id: &value.organization_id,
        created_at: &value.created_at,
    }
    .validate_session(
        "sas_",
        id,
        &value.expires_at,
        value.status == SlackSessionStatus::SlackSessionPending,
        value.authorization_url.as_deref(),
    )?;
    if let Some(connection) = value.result_connection.as_deref() {
        validate_connection(connection, None)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::disallowed_macros,
    clippy::expect_used,
    reason = "Slack client unit tests use Rust test assertions"
)]
mod tests {
    use super::*;
    use crate::resource::{classify_problem, problem_fixture};

    #[test]
    fn slack_channel_check_refuses_inconsistent_answers() {
        use useful_test_support::ScriptedHttpServer;

        let _ = rustls::crypto::ring::default_provider().install_default();
        for body in [
            r##"{"channel":"#runs","state":"usable"}"##,
            r##"{"channel":"#runs","state":"unusable"}"##,
            r##"{"channel":"#other","state":"usable","channelId":"C0123ABCD"}"##,
        ] {
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let server = ScriptedHttpServer::respond(response.into_bytes());
            let api = SlackApi::new(
                &server.api_url,
                "fixture-token",
                HttpTransportPolicy::AllowInsecureHttp,
            )
            .expect("fixture Slack API client");
            let result = api.check_channel("example", "scn_01k0z6r1w8f4jy2m7q9v3x5abc", "#runs");
            let request = server.finish_one();
            assert!(request.starts_with(
                "GET /api/v1/organizations/example/connections/slack/scn_01k0z6r1w8f4jy2m7q9v3x5abc/channel-check?channel=%23runs "
            ));
            assert_eq!(
                result,
                Err(SlackFailure::Resource(ResourceFailure::InvalidResponse {
                    credential_rejected: false,
                })),
                "{body}"
            );
        }
    }

    #[test]
    fn slack_problem_status_and_type_must_match() {
        use ResourceFailure::{Conflict, Unreachable};

        for (status, kind, expected) in [
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "service-unavailable",
                SlackFailure::NotServed,
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "retryable-conflict",
                SlackFailure::Resource(Unreachable {
                    category: UnreachableCategory::Server,
                }),
            ),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "service-unavailable",
                SlackFailure::Resource(Unreachable {
                    category: UnreachableCategory::Server,
                }),
            ),
            (
                StatusCode::CONFLICT,
                "source-connection-conflict",
                SlackFailure::Resource(Conflict),
            ),
            (
                StatusCode::CONFLICT,
                "idempotency-conflict",
                SlackFailure::Resource(Conflict),
            ),
            (
                StatusCode::CONFLICT,
                "candidate-conflict",
                SlackFailure::Resource(invalid()),
            ),
        ] {
            assert_eq!(
                classify_problem(
                    status,
                    &problem_fixture(status.as_u16(), kind),
                    None,
                    PROBLEMS
                ),
                expected,
                "{status} {kind}"
            );
        }
    }

    #[test]
    fn slack_session_requires_its_id_and_a_safe_pending_authorization_url() {
        let mut session = SlackSession {
            id: "sas_00000000000000000000000001".into(),
            organization_id: "org_00000000000000000000000001".into(),
            created_at: "2026-11-26T12:00:00Z".into(),
            expires_at: "2026-11-26T12:15:00Z".into(),
            authorization_url: Some("https://slack.com/oauth/v2/authorize".into()),
            ..Default::default()
        };
        assert!(validate_session(&session, None).is_ok());
        session.id = "las_00000000000000000000000001".into();
        assert!(validate_session(&session, None).is_err());
        session.id = "sas_00000000000000000000000001".into();
        session.status = SlackSessionStatus::SlackSessionCompleted;
        assert!(validate_session(&session, None).is_err());
        session.status = SlackSessionStatus::SlackSessionPending;
        for url in [
            "http://slack.com/authorize",
            "https://user@slack.com/authorize",
            "https://:password@slack.com/authorize",
            "https://slack.com/authorize#fragment",
        ] {
            session.authorization_url = Some(url.into());
            assert!(validate_session(&session, None).is_err(), "{url}");
        }
    }

    #[test]
    fn slack_connection_requires_its_id_and_positive_generation() {
        let mut connection = SlackConnection {
            id: "scn_00000000000000000000000001".into(),
            organization_id: "org_00000000000000000000000001".into(),
            workspace_name: "Engineering".into(),
            workspace_id: "T001".into(),
            created_at: "2026-11-26T12:00:00Z".into(),
            updated_at: "2026-11-26T12:00:00Z".into(),
            lifecycle_generation: 1,
            ..Default::default()
        };
        assert!(validate_connection(&connection, None).is_ok());
        connection.id = "lcn_00000000000000000000000001".into();
        assert!(validate_connection(&connection, None).is_err());
        connection.id = "scn_00000000000000000000000001".into();
        connection.lifecycle_generation = 0;
        assert!(validate_connection(&connection, None).is_err());
    }
}
