//! Read and download a Cloud run's kept record.

use super::generated::{apis, models};
use super::problem::{self, JSON_MEDIA_TYPE};
use super::run_inputs::{
    ValidatedCapabilityBatch, closed_object, decode_closed_model, decode_sha256, parse_timestamp,
    require_private_no_store, validate_capability_url,
};
use super::runs::{
    ReceivedResponse, RunApi, RunFailure, RunOperation, classify_failure, require_media_type,
};
use super::{HttpCancellation, HttpTransportPolicy};
use reqwest::{Method, StatusCode, Url, header::CONTENT_TYPE};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

pub type RunRecordFacts = models::RunRecord;

pub enum RunRecordRead<T = RunRecordFacts> {
    Kept(T),
    Absent,
    Gone,
}

pub struct RecordDownloadCapability {
    url: Url,
    sha256: [u8; 32],
    size_bytes: u64,
}

impl RunApi<'_> {
    fn record_endpoint(&self, organization: &str, run_id: &str) -> String {
        format!(
            "{}/v1/organizations/{}/runs/{}/record",
            self.configuration.base_path.trim_end_matches('/'),
            apis::urlencode(organization),
            apis::urlencode(run_id)
        )
    }

    pub fn get_run_record(
        &self,
        organization: &str,
        run_id: &str,
    ) -> Result<RunRecordRead, RunFailure> {
        let endpoint = self.record_endpoint(organization, run_id);
        let response = self.send_api_request(
            StatusCode::OK,
            None,
            || true,
            || self.request(Method::GET, &endpoint),
        )?;
        read_response(response, |body| {
            let facts: RunRecordFacts = decode_closed_model(body, |value| {
                closed_object(
                    value,
                    &[
                        "runId",
                        "attemptNumber",
                        "sequence",
                        "storedAt",
                        "engineRunId",
                        "manifest",
                        "fileCount",
                        "totalSizeBytes",
                        "expiresAt",
                    ],
                    &[],
                )
                .is_some()
                    && closed_object(&value["manifest"], &["sha256", "sizeBytes"], &[]).is_some()
            })?;
            if facts.run_id != run_id
                || !useful_support::valid_typed_id(&facts.engine_run_id, "run_")
                || facts.attempt_number < 1
                || facts.sequence < 1
                || !(0..=65_536).contains(&facts.file_count)
                || !(0..=4_294_967_296).contains(&facts.total_size_bytes)
                || decode_sha256(&facts.manifest.sha256).is_none()
                || !(0..=16_777_216).contains(&facts.manifest.size_bytes)
                || parse_timestamp(&facts.stored_at).is_none()
                || facts
                    .expires_at
                    .as_deref()
                    .is_some_and(|value| parse_timestamp(value).is_none())
            {
                return Err(RunFailure::protocol(false));
            }
            Ok(facts)
        })
    }

    pub fn issue_record_download_capabilities(
        &self,
        organization: &str,
        run_id: &str,
        files: &[(String, u64)],
    ) -> Result<RunRecordRead<ValidatedCapabilityBatch<RecordDownloadCapability>>, RunFailure> {
        let mut distinct = BTreeSet::new();
        if !(1..=100).contains(&files.len())
            || files.iter().any(|(sha, size)| {
                !distinct.insert(sha) || decode_sha256(sha).is_none() || *size > 256 << 20
            })
        {
            return Err(RunFailure::InvalidInput);
        }
        let endpoint = format!(
            "{}/download-capabilities",
            self.record_endpoint(organization, run_id)
        );
        let request = models::RunRecordDownloadCapabilityRequest::new(
            files.iter().map(|(sha, _)| sha.clone()).collect(),
        );
        let body = serde_json::to_vec(&request).map_err(|_| RunFailure::protocol(false))?;
        let response = self.send_api_request(
            StatusCode::OK,
            None,
            || true,
            || {
                self.request(Method::POST, &endpoint)
                    .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
                    .body(body.clone())
            },
        )?;
        read_response(response, |body| {
            decode_capabilities(body, files, self.transport_policy)
        })
    }

    pub fn download_record_file(
        &self,
        capability: &RecordDownloadCapability,
        cancellation: &HttpCancellation,
    ) -> Result<Zeroizing<Vec<u8>>, RunFailure> {
        self.download_verified_file(
            &capability.url,
            capability.size_bytes,
            capability.sha256,
            cancellation,
        )
    }
}

fn read_response<T>(
    response: ReceivedResponse,
    decode: impl FnOnce(&[u8]) -> Result<T, RunFailure>,
) -> Result<RunRecordRead<T>, RunFailure> {
    if response.status != StatusCode::OK {
        if matches!(response.status, StatusCode::NOT_FOUND | StatusCode::GONE) {
            let problem = problem::decode_header_parts(
                &response.body,
                response.status,
                response.content_type.as_ref(),
            )
            .map_err(|_| RunFailure::protocol(false))?;
            match (response.status, problem.r#type.as_str()) {
                (
                    StatusCode::NOT_FOUND,
                    "https://api.usefulmachinery.com/problems/run-record-absent",
                ) => return Ok(RunRecordRead::Absent),
                (StatusCode::GONE, "https://api.usefulmachinery.com/problems/run-record-gone") => {
                    return Ok(RunRecordRead::Gone);
                }
                (StatusCode::NOT_FOUND, _) => return Err(RunFailure::NotFound),
                _ => {}
            }
        }
        return Err(classify_failure(&response, RunOperation::Input));
    }
    require_media_type(&response, JSON_MEDIA_TYPE, false)?;
    require_private_no_store(&response)?;
    decode(&response.body).map(RunRecordRead::Kept)
}

fn decode_capabilities(
    body: &[u8],
    requested: &[(String, u64)],
    policy: HttpTransportPolicy,
) -> Result<ValidatedCapabilityBatch<RecordDownloadCapability>, RunFailure> {
    let issued: models::RunRecordDownloadCapabilityResponse = decode_closed_model(body, |value| {
        closed_object(value, &["capabilityExpiresAt", "files"], &[]).is_some()
            && value["files"].as_array().is_some_and(|files| {
                files
                    .iter()
                    .all(|file| closed_object(file, &["sha256", "sizeBytes", "url"], &[]).is_some())
            })
    })?;
    let expires_at = parse_timestamp(&issued.capability_expires_at)
        .ok_or_else(|| RunFailure::protocol(false))?;
    if issued.files.len() != requested.len() {
        return Err(RunFailure::protocol(false));
    }
    let members = issued
        .files
        .into_iter()
        .zip(requested)
        .map(|(file, (sha, size))| {
            if file.sha256 != *sha || u64::try_from(file.size_bytes).ok() != Some(*size) {
                return Err(RunFailure::protocol(false));
            }
            Ok(RecordDownloadCapability {
                url: validate_capability_url(&file.url, policy)?,
                sha256: decode_sha256(sha).ok_or_else(|| RunFailure::protocol(false))?,
                size_bytes: *size,
            })
        })
        .collect::<Result<_, _>>()?;
    Ok(ValidatedCapabilityBatch {
        expires_at,
        members,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::disallowed_macros,
    reason = "record client contract assertions"
)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn run_records_capabilities_bind_order_size_and_transport() {
        let requested = vec![("a".repeat(64), 1), ("b".repeat(64), 2)];
        let files: Vec<_> = requested.iter().map(|(sha, size)| json!({
            "sha256": sha, "sizeBytes": size, "url": format!("https://store.example/{sha}?signed=yes")
        })).collect();
        let issued = json!({"capabilityExpiresAt": "2999-01-01T00:00:00Z", "files": files});
        let check = |issued: &serde_json::Value| {
            decode_capabilities(
                &serde_json::to_vec(issued).unwrap(),
                &requested,
                HttpTransportPolicy::HttpsOnly,
            )
        };
        assert!(check(&issued).is_ok());
        let mut reordered = issued.clone();
        reordered["files"].as_array_mut().unwrap().reverse();
        assert!(check(&reordered).is_err());
        let mut wrong_size = issued.clone();
        wrong_size["files"][0]["sizeBytes"] = json!(2);
        assert!(check(&wrong_size).is_err());
        let mut insecure = issued;
        insecure["files"][0]["url"] = json!("http://store.example/object?signed=yes");
        assert!(check(&insecure).is_err());
    }
}
