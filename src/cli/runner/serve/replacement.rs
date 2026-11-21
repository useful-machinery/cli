//! `useful runner serve --replace-credential`: a second credential for the host's own runner,
//! enrolled with a single-runner key or resent as staged, and the live runner's switch to it. The
//! command reports both and exits; it never serves (REQ-RUNNERENROLL-48 to REQ-RUNNERENROLL-51).
use std::io::{self, Write};
use std::path::Path;

use crate::exit_code::{ExitCode, OutcomeClass};
use useful_runner::{
    ControlError, EnrollmentError, EnrollmentOutcome, EnrollmentResponse, JoinKey, Operation,
    ReplacementDisposition, RequestFailure, Response,
};

use super::super::super::{CommandFailure, CommandResult};

/// Enrolls the replacement `key` names, or with none resends the one the host has staged, then
/// asks the live runner to switch to it and prints the report, a document with `json`.
pub(super) fn execute(config: &Path, key: Option<JoinKey>, json: bool) -> CommandResult {
    let outcome = match key {
        Some(JoinKey::Pool(key)) => {
            return Err(CommandFailure::with_exit_code(
                anyhow::anyhow!(
                    "{REPLACE_CREDENTIAL}: join key {} is a pool's join key\n\nA replacement enrolls with a single-runner key for this host's runner. Issue one with useful runner join-key issue --runner RUNNER.",
                    key.join_key_id()
                ),
                ExitCode::UsageError,
            ));
        }
        Some(JoinKey::SingleRunner(key)) => useful_runner::enroll_replacement(config, key),
        None => useful_runner::resend_staged_replacement(config),
    };
    let enrollment = match outcome.map_err(replacement_failure)? {
        EnrollmentOutcome::Enrolled {
            response,
            deployment,
            ..
        } => ReplacementEnrollment::from_response(response, deployment),
        EnrollmentOutcome::ReplacementCredential {
            runner_id,
            credential_id,
            deployment,
        } => ReplacementEnrollment {
            deployment,
            runner_id,
            credential_id,
            runner_name: None,
            runner_pool_name: None,
            cloud_outcome: "already_enrolled",
        },
        EnrollmentOutcome::Gone { activation_id, .. } => {
            return Err(super::gone_activation(REPLACE_CREDENTIAL, &activation_id).into());
        }
        // A replacement is enrolled beside the state the host holds and never answers this.
        EnrollmentOutcome::AlreadyEnrolled => {
            return Err(anyhow::anyhow!(
                "{REPLACE_CREDENTIAL}: no replacement credential was enrolled"
            )
            .into());
        }
    };
    let promotion = promote_replacement(config, &enrollment);
    if json {
        write_replacement_json(&mut io::stdout().lock(), &enrollment, promotion)?;
    } else {
        write_replacement_human(&mut io::stdout().lock(), &enrollment, promotion)
            .map_err(anyhow::Error::from)?;
    }
    Ok(promotion.exit_code())
}

const REPLACE_CREDENTIAL: &str = "replace the runner's credential";

/// A replacement that did not reach a definite answer keeps its journal, which a replacement
/// start resends; a host with none staged is told how to stage one.
fn replacement_failure(error: EnrollmentError) -> anyhow::Error {
    let remedy = match &error {
        EnrollmentError::NoStagedReplacement => {
            "Start useful runner serve --replace-credential --join-key-file PATH|- with a single-runner key for this host's runner."
        }
        error if super::resendable(error) => {
            "The enrollment journal is kept. Start useful runner serve --replace-credential again, with the same single-runner key or with none, to resend the same request."
        }
        _ => return anyhow::Error::new(error).context(REPLACE_CREDENTIAL),
    };
    super::with_cause_and_remedy(REPLACE_CREDENTIAL, &error, remedy)
}

#[derive(serde::Serialize)]
struct OutcomeOutput<'a> {
    outcome: &'a str,
}

#[derive(serde::Serialize)]
struct PromotionOutput<'a> {
    outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplacementOutput<'a> {
    schema_version: u8,
    deployment: &'a str,
    outcome: &'static str,
    runner_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    runner_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runner_pool_name: Option<&'a str>,
    credential_id: &'a str,
    cloud_enrollment: OutcomeOutput<'a>,
    live_promotion: PromotionOutput<'a>,
}

struct ReplacementEnrollment {
    deployment: String,
    runner_id: String,
    credential_id: String,
    runner_name: Option<String>,
    runner_pool_name: Option<String>,
    cloud_outcome: &'static str,
}

impl ReplacementEnrollment {
    fn from_response(response: EnrollmentResponse, deployment: String) -> Self {
        Self {
            deployment,
            runner_id: response.runner_id().to_owned(),
            credential_id: response.credential_id().to_owned(),
            runner_name: Some(response.runner_name().to_owned()),
            runner_pool_name: Some(response.pool_name().to_owned()),
            cloud_outcome: "enrolled",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PromotionOutcome {
    Promoted,
    Incomplete(PromotionFailure),
}

impl PromotionOutcome {
    const fn exit_code(self) -> ExitCode {
        match self {
            Self::Promoted => OutcomeClass::Success.exit_code(),
            Self::Incomplete(failure) => failure.outcome_class().exit_code(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PromotionFailure {
    RunnerServeUnreachable,
    Control(ControlError),
    InvalidControlResponse,
    StateUnavailable,
}

impl PromotionFailure {
    const fn category(self) -> &'static str {
        match self {
            Self::RunnerServeUnreachable => "runner_serve_unreachable",
            Self::Control(ControlError::InvalidRequest) => "invalid_request",
            Self::Control(ControlError::UnsupportedVersion) => "unsupported_version",
            Self::Control(ControlError::RunnerBusy) => "runner_busy",
            Self::Control(ControlError::NoPendingCredential) => "no_pending_credential",
            Self::Control(ControlError::PendingRegistrationMismatch) => {
                "pending_registration_mismatch"
            }
            Self::Control(ControlError::PendingAuthenticationFailed) => {
                "pending_authentication_failed"
            }
            Self::Control(ControlError::PendingProtocolFailed) => "pending_protocol_failed",
            Self::Control(ControlError::PendingConnectionFailed) => "pending_connection_failed",
            Self::Control(ControlError::StateUpdateFailed) => "state_update_failed",
            Self::InvalidControlResponse => "invalid_control_response",
            Self::StateUnavailable => "state_unavailable",
        }
    }

    const fn outcome_class(self) -> OutcomeClass {
        match self {
            Self::RunnerServeUnreachable | Self::Control(ControlError::PendingConnectionFailed) => {
                OutcomeClass::Unreachable
            }
            Self::Control(
                ControlError::InvalidRequest
                | ControlError::UnsupportedVersion
                | ControlError::RunnerBusy,
            )
            | Self::Control(ControlError::PendingProtocolFailed)
            | Self::InvalidControlResponse => OutcomeClass::Protocol,
            Self::Control(_) | Self::StateUnavailable => OutcomeClass::GeneralFailure,
        }
    }

    const fn remedy(self) -> &'static str {
        match self {
            Self::RunnerServeUnreachable => {
                "Confirm that Runner Serve is running and the configured local socket is reachable, then start useful runner serve --replace-credential again with the same single-runner key."
            }
            Self::Control(ControlError::PendingAuthenticationFailed) => {
                "Keep the current credential active, verify the replacement credential in Cloud, then start useful runner serve --replace-credential again with the same single-runner key."
            }
            Self::Control(ControlError::PendingProtocolFailed)
            | Self::Control(ControlError::UnsupportedVersion)
            | Self::Control(ControlError::InvalidRequest)
            | Self::Control(ControlError::RunnerBusy)
            | Self::InvalidControlResponse => {
                "Verify that the CLI and Runner Serve versions agree, then start useful runner serve --replace-credential again with the same single-runner key."
            }
            Self::Control(ControlError::PendingConnectionFailed) => {
                "Keep the current credential active, restore Runner Serve network access to Cloud, then start useful runner serve --replace-credential again with the same single-runner key."
            }
            Self::Control(ControlError::StateUpdateFailed) | Self::StateUnavailable => {
                "Keep the current credential active, correct the protected runner state access problem, then start useful runner serve --replace-credential again with the same single-runner key."
            }
            Self::Control(ControlError::NoPendingCredential)
            | Self::Control(ControlError::PendingRegistrationMismatch) => {
                "Keep the current credential active and inspect the configured protected runner state before retrying rotation."
            }
        }
    }
}

fn promote_replacement(config: &Path, enrollment: &ReplacementEnrollment) -> PromotionOutcome {
    let Ok(socket) = useful_runner::load_control_socket_path(config) else {
        return PromotionOutcome::Incomplete(PromotionFailure::StateUnavailable);
    };
    match useful_runner::request(&socket, Operation::ReloadCredential) {
        Ok(Response::Reloaded { credential_id }) if credential_id == enrollment.credential_id => {
            PromotionOutcome::Promoted
        }
        Ok(Response::Error(error)) => {
            PromotionOutcome::Incomplete(PromotionFailure::Control(error))
        }
        Ok(Response::Reloaded { .. } | Response::Status(_) | Response::AgentLoginsSynced(_))
        | Err(RequestFailure::Protocol(_)) => {
            PromotionOutcome::Incomplete(PromotionFailure::InvalidControlResponse)
        }
        Err(RequestFailure::NotReachable) => {
            match useful_runner::replacement_disposition(
                config,
                &enrollment.runner_id,
                &enrollment.credential_id,
            ) {
                Ok(ReplacementDisposition::Current) => PromotionOutcome::Promoted,
                Ok(ReplacementDisposition::Pending | ReplacementDisposition::Missing) | Err(_) => {
                    PromotionOutcome::Incomplete(PromotionFailure::RunnerServeUnreachable)
                }
            }
        }
    }
}

fn write_replacement_json(
    output: &mut impl Write,
    enrollment: &ReplacementEnrollment,
    promotion: PromotionOutcome,
) -> anyhow::Result<()> {
    let report = ReplacementOutput {
        schema_version: 1,
        deployment: &enrollment.deployment,
        outcome: if promotion == PromotionOutcome::Promoted {
            "rotation_completed"
        } else {
            "rotation_incomplete"
        },
        runner_id: &enrollment.runner_id,
        runner_name: enrollment.runner_name.as_deref(),
        runner_pool_name: enrollment.runner_pool_name.as_deref(),
        credential_id: &enrollment.credential_id,
        cloud_enrollment: OutcomeOutput {
            outcome: enrollment.cloud_outcome,
        },
        live_promotion: match promotion {
            PromotionOutcome::Promoted => PromotionOutput {
                outcome: "promoted",
                error: None,
            },
            PromotionOutcome::Incomplete(failure) => PromotionOutput {
                outcome: "pending",
                error: Some(failure.category()),
            },
        },
    };
    serde_json::to_writer_pretty(&mut *output, &report)?;
    writeln!(output)?;
    Ok(())
}

fn write_replacement_human(
    output: &mut impl Write,
    enrollment: &ReplacementEnrollment,
    promotion: PromotionOutcome,
) -> io::Result<()> {
    writeln!(output, "✓ Replacement credential is enrolled in Cloud.\n")?;
    writeln!(output, "runner:           {}", enrollment.runner_id)?;
    if let Some(name) = &enrollment.runner_name {
        writeln!(output, "name:             {name}")?;
    }
    if let Some(name) = &enrollment.runner_pool_name {
        writeln!(output, "pool:             {name}")?;
    }
    writeln!(output, "credential:       {}", enrollment.credential_id)?;
    writeln!(output, "cloud enrollment: {}", enrollment.cloud_outcome)?;
    match promotion {
        PromotionOutcome::Promoted => {
            writeln!(
                output,
                "\n✓ Replacement credential promoted in Runner Serve.\n"
            )?;
            writeln!(output, "live promotion: promoted")
        }
        PromotionOutcome::Incomplete(failure) => {
            writeln!(output, "\n✗ Live credential promotion did not complete.\n")?;
            writeln!(output, "live promotion: pending")?;
            writeln!(output, "error:          {}\n", failure.category())?;
            writeln!(output, "{}", failure.remedy())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replacement() -> ReplacementEnrollment {
        ReplacementEnrollment {
            deployment: "https://example.test".to_owned(),
            runner_id: "rnr_01k0z6r1w8f4jy2m7q9v3x5abc".to_owned(),
            credential_id: "rrc_01k0z6r1w8f4jy2m7q9v3x5abd".to_owned(),
            runner_name: None,
            runner_pool_name: None,
            cloud_outcome: "already_enrolled",
        }
    }

    // REQ-RUNNERENROLL-50
    #[test]
    fn replacement_reports_cloud_and_live_outcomes_separately() {
        let mut output = Vec::new();
        write_replacement_json(
            &mut output,
            &replacement(),
            PromotionOutcome::Incomplete(PromotionFailure::Control(
                ControlError::PendingAuthenticationFailed,
            )),
        )
        .unwrap();
        let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(report["cloudEnrollment"]["outcome"], "already_enrolled");
        assert_eq!(report["livePromotion"]["outcome"], "pending");
        assert_eq!(
            report["livePromotion"]["error"],
            "pending_authentication_failed"
        );
        assert_eq!(
            PromotionOutcome::Incomplete(PromotionFailure::RunnerServeUnreachable).exit_code(),
            OutcomeClass::Unreachable.exit_code()
        );
    }
}
