#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodexConfig {
    pub(crate) model: String,
    pub(crate) effort: String,
}

/// The model a login check asks for, which has no workflow profile. The adapter names the
/// model when it starts a thread and checks the thread's answer against it, so the
/// installation's configured default cannot stand in: this is the fast, lowest-cost model
/// of the GPT-5.6 family and the model the live login smoke pins. A login whose account
/// may not use it is refused.
pub(crate) const LOGIN_CHECK_MODEL: &str = "gpt-5.6-luna";
/// The lowest effort the adapter is qualified with.
pub(crate) const LOGIN_CHECK_EFFORT: &str = "low";

// Codex keeps native effort as a string and must not inherit Claude's closed effort enum.
pub(crate) fn resolve_config(value: &Value) -> Option<CodexConfig> {
    let config = serde_json::from_value::<CodexConfig>(value.clone()).ok()?;
    (!config.model.is_empty() && !config.effort.is_empty()).then_some(config)
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn future_configuration_is_exact_and_uses_native_nonempty_effort() {
        // Keep native strings visible rather than coupling this contract to Claude's enum tests.
        for effort in ["low", "xhigh", "future-native-effort", " "] {
            assert_eq!(
                resolve_config(&serde_json::json!({
                    "model": "gpt-5.4",
                    "effort": effort,
                })),
                Some(CodexConfig {
                    model: "gpt-5.4".to_owned(),
                    effort: effort.to_owned(),
                })
            );
        }

        for invalid in [
            serde_json::json!({"effort": "high"}),
            serde_json::json!({"model": "", "effort": "high"}),
            serde_json::json!({"model": "gpt-5.4", "effort": ""}),
            serde_json::json!({"model": "gpt-5.4"}),
            serde_json::json!({
                "model": "gpt-5.4",
                "effort": "high",
                "modelProvider": "openai",
            }),
            serde_json::json!({
                "model": "gpt-5.4",
                "effort": "high",
                "apiKey": "credential-is-not-workflow-configuration",
            }),
        ] {
            assert_eq!(resolve_config(&invalid), None);
        }
    }
}

pub(crate) mod adapter;
mod input;

use std::cell::Cell;
use std::collections::{BTreeSet, VecDeque};
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::agent::{
    AgentDiagnosticLevel, AgentFailureCause, AgentHarnessFailureDetail, AgentHarnessSetupStage,
    AgentLifecycleMilestone, AgentObservation, AgentOutcome, AgentProtocolRejectionDiagnostic,
    AgentToolCallPhase, AgentValueKind, BoundedAgentResponse, CanonicalHarnessFailure,
    CapturedJson, CompletedAgentInvocation, HarnessFailureDiagnostic,
};

const MAXIMUM_FRAME_BYTES: u64 = 16 * 1024 * 1024;
const MAXIMUM_CORRELATION_BYTES: u64 = 64 * 1024;
const MAXIMUM_RETAINED_DIAGNOSTIC_BYTES: u64 = 64 * 1024;
const MAXIMUM_IDENTITY_BYTES: usize = 256;
const MAXIMUM_UNRECOGNIZED_METHODS: usize = 64;
const MAXIMUM_UNRECOGNIZED_METHOD_BYTES: usize = 64;
const STANDARD_INPUT_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const POST_FAILURE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const INITIALIZE_REQUEST_ID: RequestId = RequestId(1);
const CONFIG_READ_REQUEST_ID: RequestId = RequestId(2);
const THREAD_START_REQUEST_ID: RequestId = RequestId(3);
const TURN_START_REQUEST_ID: RequestId = RequestId(4);
const TURN_INTERRUPT_REQUEST_ID: RequestId = RequestId(5);
const CORRECTION_TURN_START_REQUEST_ID: RequestId = RequestId(6);
const MAXIMUM_CORRECTION_TURNS: u8 = 1;
const CLIENT_NAME: &str = "useful";
const SCHEMA_REJECTION_PREFIX: &str = "Result rejected by the workflow schema:\n";
const CODEX_SCHEMA_CORRECTION_PREFIX: &str = "Correct the inner workflow JSON encoded in the outer `result` string; the harness owns the envelope. Schema diagnostics:\n";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodexAppServerV1ProtocolLimits {
    maximum_frame_bytes: NonZeroU64,
    maximum_correlation_bytes: NonZeroU64,
    maximum_retained_diagnostic_bytes: NonZeroU64,
    standard_input_write_timeout: Duration,
    post_failure_cleanup_timeout: Duration,
}

impl CodexAppServerV1ProtocolLimits {
    pub(crate) const fn profile() -> Self {
        let maximum_frame_bytes = match NonZeroU64::new(MAXIMUM_FRAME_BYTES) {
            Some(value) => value,
            None => NonZeroU64::MIN,
        };
        let maximum_correlation_bytes = match NonZeroU64::new(MAXIMUM_CORRELATION_BYTES) {
            Some(value) => value,
            None => NonZeroU64::MIN,
        };
        let maximum_retained_diagnostic_bytes =
            match NonZeroU64::new(MAXIMUM_RETAINED_DIAGNOSTIC_BYTES) {
                Some(value) => value,
                None => NonZeroU64::MIN,
            };
        Self {
            maximum_frame_bytes,
            maximum_correlation_bytes,
            maximum_retained_diagnostic_bytes,
            standard_input_write_timeout: STANDARD_INPUT_WRITE_TIMEOUT,
            post_failure_cleanup_timeout: POST_FAILURE_CLEANUP_TIMEOUT,
        }
    }

    #[cfg(test)]
    const fn with_limits(
        maximum_frame_bytes: NonZeroU64,
        maximum_correlation_bytes: NonZeroU64,
    ) -> Self {
        Self {
            maximum_frame_bytes,
            maximum_correlation_bytes,
            maximum_retained_diagnostic_bytes: maximum_frame_bytes,
            standard_input_write_timeout: STANDARD_INPUT_WRITE_TIMEOUT,
            post_failure_cleanup_timeout: POST_FAILURE_CLEANUP_TIMEOUT,
        }
    }

    pub(crate) const fn maximum_frame_bytes(self) -> NonZeroU64 {
        self.maximum_frame_bytes
    }

    pub(crate) const fn maximum_correlation_bytes(self) -> NonZeroU64 {
        self.maximum_correlation_bytes
    }

    pub(crate) const fn standard_input_write_timeout(self) -> Duration {
        self.standard_input_write_timeout
    }

    pub(crate) const fn post_failure_cleanup_timeout(self) -> Duration {
        self.post_failure_cleanup_timeout
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ThreadId(Arc<str>);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TurnId(Arc<str>);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RequestId(u64);

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ServerRequestId {
    Number(i64),
    String(Arc<str>),
}

impl ServerRequestId {
    fn value(&self) -> Value {
        match self {
            Self::Number(value) => Value::from(*value),
            Self::String(value) => Value::String(value.to_string()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SetupState {
    Initialize,
    ConfigRead,
    ThreadStart,
    TurnStart,
    StartAcknowledgement,
    Running,
    ResultValidation,
    Terminal,
}

impl SetupState {
    const fn protocol_stage(self) -> CodexAppServerV1ProtocolStage {
        match self {
            Self::Initialize => CodexAppServerV1ProtocolStage::Initialize,
            Self::ConfigRead => CodexAppServerV1ProtocolStage::ConfigRead,
            Self::ThreadStart => CodexAppServerV1ProtocolStage::ThreadStart,
            Self::TurnStart => CodexAppServerV1ProtocolStage::TurnStart,
            Self::StartAcknowledgement => CodexAppServerV1ProtocolStage::StartAcknowledgement,
            Self::Running => CodexAppServerV1ProtocolStage::Running,
            Self::ResultValidation => CodexAppServerV1ProtocolStage::ResultValidation,
            Self::Terminal => CodexAppServerV1ProtocolStage::Terminal,
        }
    }

    const fn failure_stage(self) -> Option<AgentHarnessSetupStage> {
        match self {
            Self::Initialize => Some(AgentHarnessSetupStage::Initialization),
            Self::ConfigRead => Some(AgentHarnessSetupStage::EffectiveConfiguration),
            Self::ThreadStart => Some(AgentHarnessSetupStage::ThreadStart),
            Self::TurnStart => Some(AgentHarnessSetupStage::TurnStart),
            Self::StartAcknowledgement => Some(AgentHarnessSetupStage::StartAcknowledgement),
            Self::Running | Self::ResultValidation | Self::Terminal => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CodexAppServerV1ProtocolRejection {
    reason: CodexAppServerV1RejectionReason,
    stage: CodexAppServerV1ProtocolStage,
    thread_established: bool,
    turn_established: bool,
    start_acknowledged: bool,
}

impl CodexAppServerV1ProtocolRejection {
    pub(super) const fn reason(&self) -> CodexAppServerV1RejectionReason {
        self.reason
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CodexAppServerV1RejectionReason {
    FrameEmpty,
    FrameTooLarge,
    FrameDecodeFailed,
    FrameNotObject,
    JsonRpcEnvelopeUnsupported,
    FrameEnvelopeInvalid,
    ResponseEnvelopeInvalid,
    ResponseCorrelationInvalid,
    ResponseRejected,
    ResponseTransitionInvalid,
    InitializationResponseInvalid,
    ConfigurationResponseInvalid,
    EffectiveInstructionsInvalid,
    ThreadStartResponseInvalid,
    ThreadCorrelationInvalid,
    TurnStartResponseInvalid,
    TurnCorrelationInvalid,
    ServerRequestEnvelopeInvalid,
    ServerRequestRepeated,
    NotificationEnvelopeInvalid,
    NotificationTransitionInvalid,
    ItemCorrelationInvalid,
    MessageInvalid,
    NativeErrorInvalid,
    TurnCompletionInvalid,
    ResultTransitionInvalid,
    IdentityInvalid,
    RetainedCorrelationLimitExceeded,
    OutboundLimitExceeded,
    OutboundTransitionInvalid,
    PartialFrameAtEndOfStream,
    TerminalInvariantInvalid,
    StandardInputWriteFailed,
    StandardInputWriteTimedOut,
    StandardInputCloseFailed,
    ObservationDeliveryFailed,
    StartAcknowledgementFailed,
    ProcessOutputReadFailed,
    ProcessWaitFailed,
    ProcessSettlementFailed,
    ResultValidatorMissing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum CodexAppServerV1ProtocolStage {
    Initialize,
    ConfigRead,
    ThreadStart,
    TurnStart,
    StartAcknowledgement,
    Running,
    ResultValidation,
    Terminal,
}

#[derive(Clone, Debug)]
struct CompletedAgentMessage {
    text: Arc<str>,
    phase: Option<AgentMessagePhase>,
    delivery: Option<AgentMessageDelivery>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentMessagePhase {
    Commentary,
    PartialAnswer,
    FinalAnswer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentMessageDelivery {
    Async,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeTerminal {
    Completed,
    Failed(AgentHarnessFailureDetail),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CodexErrorKind {
    ContextWindowExceeded,
    SessionBudgetExceeded,
    UsageLimitExceeded,
    RateLimitExceeded,
    FlexUnavailable,
    ServerOverloaded,
    ModelNotFound,
    PolicyCapacityUnavailable,
    CyberPolicy,
    BioPolicy,
    MisalignmentPolicyViolation,
    InferenceHookDenied,
    TooManyDenials,
    InternalServerError,
    Unauthorized,
    BadRequest,
    ThreadRollbackFailed,
    SandboxError,
    Other,
    HttpConnectionFailed,
    ResponseStreamConnectionFailed,
    ResponseStreamDisconnected,
    ResponseTooManyFailedAttempts,
    ActiveTurnNotSteerable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActiveTurnKind {
    Review,
    Compact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CodexErrorInfo {
    kind: CodexErrorKind,
    http_status_code: Option<u16>,
    active_turn_kind: Option<ActiveTurnKind>,
}

impl CodexErrorInfo {
    fn failure_detail(self, truncated: bool) -> AgentHarnessFailureDetail {
        let code = match self.kind {
            CodexErrorKind::ContextWindowExceeded => "contextWindowExceeded",
            CodexErrorKind::UsageLimitExceeded => "usageLimitExceeded",
            CodexErrorKind::RateLimitExceeded => "rateLimitExceeded",
            CodexErrorKind::Unauthorized => "unauthorized",
            CodexErrorKind::ServerOverloaded => "serverOverloaded",
            CodexErrorKind::BadRequest | CodexErrorKind::ModelNotFound => "badRequest",
            CodexErrorKind::InternalServerError => "internalServerError",
            CodexErrorKind::SandboxError => "sandboxError",
            CodexErrorKind::ResponseStreamDisconnected => "responseStreamDisconnected",
            _ => "other",
        };
        AgentHarnessFailureDetail::Classified {
            canonical: if truncated || self.kind == CodexErrorKind::ResponseStreamDisconnected {
                CanonicalHarnessFailure::ModelOutputTruncated
            } else {
                CanonicalHarnessFailure::ModelError
            },
            diagnostic: HarnessFailureDiagnostic::from_code(code, self.http_status_code),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeErrorObservation {
    info: Option<CodexErrorInfo>,
    will_retry: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ParserProgress {
    pub(super) start_acknowledged: bool,
    pub(super) close_standard_input: bool,
}

#[derive(Clone, Debug)]
pub(super) struct CodexAppServerV1Parser {
    expected_cwd: Arc<str>,
    codex_home: Arc<str>,
    sqlite_home: Arc<str>,
    codex_version: Arc<str>,
    model: Arc<str>,
    effort: Arc<str>,
    system_prompt: Arc<str>,
    initial_input: Vec<Value>,
    synthetic_model_provider: Option<Arc<str>>,
    value_kind: AgentValueKind,
    maximum_response_bytes: NonZeroU64,
    maximum_result_rejection_feedback_bytes: NonZeroU64,
    limits: CodexAppServerV1ProtocolLimits,
    frame: Vec<u8>,
    state: SetupState,
    outstanding_request: Option<RequestId>,
    turn_start_request: RequestId,
    correction_turns_started: u8,
    invocation_start_acknowledged: bool,
    completed_requests: BTreeSet<RequestId>,
    completed_server_requests: BTreeSet<ServerRequestId>,
    outbound: VecDeque<Vec<u8>>,
    pending_outbound_bytes: u64,
    thread_id: Option<ThreadId>,
    turn_id: Option<TurnId>,
    effective_model_provider: Option<Arc<str>>,
    thread_started_seen: bool,
    turn_started_seen: bool,
    held_turn_frames: VecDeque<Vec<u8>>,
    held_turn_frame_bytes: u64,
    previous_turn_id: Option<TurnId>,
    result_message: Option<(Arc<str>, Arc<str>)>,
    other_result_messages: usize,
    retained_correlation_bytes: u64,
    retained_diagnostic_bytes: u64,
    selected_response: Option<Arc<str>>,
    final_answer_seen: bool,
    values_enabled: bool,
    interrupt_requested: bool,
    retry_active: bool,
    native_error: Option<NativeErrorObservation>,
    truncated_provider_stream_seen: bool,
    pending_result_candidate: Option<Arc<Value>>,
    accepted_result: Option<CapturedJson>,
    native_terminal: Option<NativeTerminal>,
    active_rejection_reason: Cell<CodexAppServerV1RejectionReason>,
    rejection_reason: Cell<Option<CodexAppServerV1RejectionReason>>,
    completion_rejection_reason: Cell<Option<CodexAppServerV1RejectionReason>>,
    failure: Option<AgentFailureCause>,
    unrecognized_methods: BTreeSet<Box<str>>,
    unrecognized_overflow_observed: bool,
    observations: Vec<AgentObservation>,
}

impl CodexAppServerV1Parser {
    #[expect(
        clippy::too_many_arguments,
        reason = "the parser retains each admitted transport boundary explicitly"
    )]
    pub(super) fn profile(
        expected_cwd: Arc<str>,
        codex_home: Arc<str>,
        sqlite_home: Arc<str>,
        client_version: Arc<str>,
        codex_version: Arc<str>,
        model: Arc<str>,
        effort: Arc<str>,
        system_prompt: Arc<str>,
        initial_input: Vec<Value>,
        synthetic_model_provider: Option<Arc<str>>,
        value_kind: AgentValueKind,
        maximum_response_bytes: NonZeroU64,
        maximum_result_rejection_feedback_bytes: NonZeroU64,
        limits: CodexAppServerV1ProtocolLimits,
    ) -> Result<Self, AgentFailureCause> {
        let mut parser = Self {
            expected_cwd,
            codex_home,
            sqlite_home,
            codex_version,
            model,
            effort,
            system_prompt,
            initial_input,
            synthetic_model_provider,
            value_kind,
            maximum_response_bytes,
            maximum_result_rejection_feedback_bytes,
            limits,
            frame: Vec::new(),
            state: SetupState::Initialize,
            outstanding_request: None,
            turn_start_request: TURN_START_REQUEST_ID,
            correction_turns_started: 0,
            invocation_start_acknowledged: false,
            completed_requests: BTreeSet::new(),
            completed_server_requests: BTreeSet::new(),
            outbound: VecDeque::new(),
            pending_outbound_bytes: 0,
            thread_id: None,
            turn_id: None,
            effective_model_provider: None,
            thread_started_seen: false,
            turn_started_seen: false,
            held_turn_frames: VecDeque::new(),
            held_turn_frame_bytes: 0,
            previous_turn_id: None,
            result_message: None,
            other_result_messages: 0,
            retained_correlation_bytes: 0,
            retained_diagnostic_bytes: 0,
            selected_response: None,
            final_answer_seen: false,
            values_enabled: true,
            interrupt_requested: false,
            retry_active: false,
            native_error: None,
            truncated_provider_stream_seen: false,
            pending_result_candidate: None,
            accepted_result: None,
            native_terminal: None,
            active_rejection_reason: Cell::new(
                CodexAppServerV1RejectionReason::OutboundTransitionInvalid,
            ),
            rejection_reason: Cell::new(None),
            completion_rejection_reason: Cell::new(None),
            failure: None,
            unrecognized_methods: BTreeSet::new(),
            unrecognized_overflow_observed: false,
            observations: Vec::new(),
        };
        parser.queue_request(
            INITIALIZE_REQUEST_ID,
            "initialize",
            json!({
                "clientInfo": {
                    "name": CLIENT_NAME,
                    "version": client_version.as_ref(),
                }
            }),
        )?;
        Ok(parser)
    }

    pub(super) fn take_outbound(&mut self) -> Option<Vec<u8>> {
        let frame = self.outbound.pop_front()?;
        self.pending_outbound_bytes = self
            .pending_outbound_bytes
            .saturating_sub(u64::try_from(frame.len()).unwrap_or(u64::MAX));
        Some(frame)
    }

    pub(super) fn prevent_value_commit(&mut self) {
        self.values_enabled = false;
        self.invalidate_value();
    }

    pub(super) fn request_turn_interrupt(&mut self) -> Result<bool, AgentFailureCause> {
        self.prepare_rejection(CodexAppServerV1RejectionReason::OutboundTransitionInvalid);
        self.prevent_value_commit();
        if self.interrupt_requested
            || !matches!(
                self.state,
                SetupState::StartAcknowledgement | SetupState::Running
            )
        {
            return Ok(false);
        }
        let thread_id = self
            .thread_id
            .as_ref()
            .ok_or_else(|| self.failure_for_current_phase())?;
        let turn_id = self
            .turn_id
            .as_ref()
            .ok_or_else(|| self.failure_for_current_phase())?;
        let params = json!({
            "threadId": thread_id.0.as_ref(),
            "turnId": turn_id.0.as_ref(),
        });
        self.queue_request(TURN_INTERRUPT_REQUEST_ID, "turn/interrupt", params)?;
        self.interrupt_requested = true;
        Ok(true)
    }

    pub(super) const fn start_acknowledged(&self) -> bool {
        self.invocation_start_acknowledged
    }

    pub(super) fn take_result_candidate(&mut self) -> Option<Arc<Value>> {
        self.pending_result_candidate.take()
    }

    pub(super) fn take_observations(&mut self) -> Vec<AgentObservation> {
        self.observations.drain(..).collect()
    }

    pub(super) fn accept_result(
        &mut self,
        result: CapturedJson,
    ) -> Result<ParserProgress, AgentFailureCause> {
        if !self.result_validation_is_ready() {
            return self
                .fail_current_phase(CodexAppServerV1RejectionReason::ResultTransitionInvalid);
        }
        self.accepted_result = Some(result);
        self.state = SetupState::Terminal;
        self.observations
            .push(lifecycle(AgentLifecycleMilestone::HarnessCompleted));
        Ok(ParserProgress {
            start_acknowledged: false,
            close_standard_input: true,
        })
    }

    pub(super) fn reject_result(
        &mut self,
        feedback: Arc<str>,
    ) -> Result<ParserProgress, AgentFailureCause> {
        if !self.result_validation_is_ready() {
            return self
                .fail_current_phase(CodexAppServerV1RejectionReason::ResultTransitionInvalid);
        }
        let limit = usize::try_from(self.maximum_result_rejection_feedback_bytes.get())
            .unwrap_or(usize::MAX);
        let feedback = if feedback.len() > limit {
            Arc::from(&feedback[..feedback.floor_char_boundary(limit)])
        } else {
            feedback
        };
        self.observations.push(AgentObservation::ValueRejected {
            kind: AgentValueKind::Result,
            feedback: Arc::clone(&feedback),
        });
        if self.correction_turns_started >= MAXIMUM_CORRECTION_TURNS {
            self.state = SetupState::Terminal;
            self.observations
                .push(lifecycle(AgentLifecycleMilestone::HarnessCompleted));
            return Ok(ParserProgress {
                start_acknowledged: false,
                close_standard_input: true,
            });
        }

        self.correction_turns_started += 1;
        self.turn_start_request = RequestId(
            CORRECTION_TURN_START_REQUEST_ID
                .0
                .checked_add(u64::from(self.correction_turns_started - 1))
                .ok_or_else(|| self.failure_for_current_phase())?,
        );
        self.reset_completed_turn();
        let feedback = codex_result_correction_feedback(
            feedback,
            self.maximum_result_rejection_feedback_bytes,
        );
        self.queue_turn_start(vec![json!({
            "type": "text",
            "text": feedback.as_ref(),
        })])?;
        self.state = SetupState::TurnStart;
        Ok(ParserProgress::default())
    }

    fn result_validation_is_ready(&self) -> bool {
        self.value_kind == AgentValueKind::Result
            && self.state == SetupState::ResultValidation
            && self.pending_result_candidate.is_none()
            && self.accepted_result.is_none()
            && self.native_terminal == Some(NativeTerminal::Completed)
    }

    pub(super) fn prepare_completion_rejection(&self) {
        if self.completion_rejection_reason.get().is_none() {
            let reason = if self.frame.is_empty() {
                CodexAppServerV1RejectionReason::TerminalInvariantInvalid
            } else {
                CodexAppServerV1RejectionReason::PartialFrameAtEndOfStream
            };
            self.completion_rejection_reason.set(Some(reason));
        }
    }

    fn protocol_rejection(&self) -> AgentProtocolRejectionDiagnostic {
        let reason = self
            .rejection_reason
            .get()
            .or(self.completion_rejection_reason.get())
            .unwrap_or(CodexAppServerV1RejectionReason::TerminalInvariantInvalid);
        AgentProtocolRejectionDiagnostic::codex_app_server_v1(CodexAppServerV1ProtocolRejection {
            reason,
            stage: self.state.protocol_stage(),
            thread_established: self.thread_id.is_some(),
            turn_established: self.turn_id.is_some(),
            start_acknowledged: self.invocation_start_acknowledged,
        })
    }

    fn prepare_rejection(&self, reason: CodexAppServerV1RejectionReason) {
        self.active_rejection_reason.set(reason);
    }

    pub(super) fn record_rejection(&self, reason: CodexAppServerV1RejectionReason) {
        if self.rejection_reason.get().is_none() {
            self.rejection_reason.set(Some(reason));
        }
    }

    pub(super) fn failure_for(&self, reason: CodexAppServerV1RejectionReason) -> AgentFailureCause {
        self.record_rejection(reason);
        self.phase_failure_cause()
    }

    pub(super) fn failure_for_current_phase(&self) -> AgentFailureCause {
        self.record_rejection(self.active_rejection_reason.get());
        self.phase_failure_cause()
    }

    fn phase_failure_cause(&self) -> AgentFailureCause {
        if self.invocation_start_acknowledged {
            return AgentFailureCause::HarnessProtocolFailed;
        }
        self.state
            .failure_stage()
            .map_or(AgentFailureCause::HarnessProtocolFailed, |stage| {
                AgentFailureCause::HarnessSetupFailed { stage }
            })
    }

    pub(super) fn push_stdout(
        &mut self,
        bytes: &[u8],
        mut observe: impl FnMut(AgentObservation),
    ) -> Result<ParserProgress, AgentFailureCause> {
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        let mut progress = ParserProgress::default();
        for &byte in bytes {
            if byte == b'\n' {
                let frame = std::mem::take(&mut self.frame);
                self.apply_frame(&frame, &mut progress, &mut observe)?;
                if self.state != SetupState::TurnStart {
                    // Frames held while the `turn/start` response was outstanding are
                    // parsed directly after it, in arrival order.
                    while let Some(held) = self.held_turn_frames.pop_front() {
                        self.apply_frame(&held, &mut progress, &mut observe)?;
                    }
                    self.held_turn_frame_bytes = 0;
                }
                continue;
            }
            let retained = u64::try_from(self.frame.len()).unwrap_or(u64::MAX);
            if retained >= self.limits.maximum_frame_bytes().get() {
                return self.fail_current_phase(CodexAppServerV1RejectionReason::FrameTooLarge);
            }
            self.frame.push(byte);
        }
        Ok(progress)
    }

    fn apply_frame(
        &mut self,
        frame: &[u8],
        progress: &mut ParserProgress,
        observe: &mut impl FnMut(AgentObservation),
    ) -> Result<(), AgentFailureCause> {
        match self.parse_frame(frame) {
            Ok(frame_progress) => {
                progress.start_acknowledged |= frame_progress.start_acknowledged;
                progress.close_standard_input |= frame_progress.close_standard_input;
            }
            Err(failure) => {
                self.invalidate_value();
                self.observations.clear();
                self.failure = Some(failure.clone());
                return Err(failure);
            }
        }
        for observation in self.observations.drain(..) {
            observe(observation);
        }
        Ok(())
    }

    pub(super) fn finish(&mut self, exit_success: bool) -> AgentOutcome {
        if self.failure.is_none() && !self.frame.is_empty() {
            self.failure =
                Some(self.failure_for(CodexAppServerV1RejectionReason::PartialFrameAtEndOfStream));
            self.invalidate_value();
        }
        if let Some(failure) = self.failure.take() {
            return failed(failure);
        }
        if !matches!(self.state, SetupState::Terminal)
            || self.outstanding_request.is_some()
            || !self.outbound.is_empty()
        {
            return failed(
                self.failure_for(CodexAppServerV1RejectionReason::TerminalInvariantInvalid),
            );
        }
        match self.native_terminal {
            Some(NativeTerminal::Failed(detail)) => {
                return failed(AgentFailureCause::HarnessFailed { detail });
            }
            Some(NativeTerminal::Completed) => {}
            None => return failed(AgentFailureCause::HarnessProtocolFailed),
        }
        // Codex keeps native terminal/exit precedence and no-response semantics local;
        // sharing this final match would couple independent harness protocol authority.
        if !exit_success {
            return failed(AgentFailureCause::HarnessFailed {
                detail: AgentHarnessFailureDetail::UnsuccessfulExit,
            });
        }
        match self.value_kind {
            AgentValueKind::None => AgentOutcome::Completed(CompletedAgentInvocation::NoValue),
            AgentValueKind::Response => self.selected_response.take().map_or_else(
                || AgentOutcome::Completed(CompletedAgentInvocation::NoResponse),
                |response| {
                    AgentOutcome::Completed(CompletedAgentInvocation::Response(
                        BoundedAgentResponse::from_bounded(response),
                    ))
                },
            ),
            AgentValueKind::Result => self.accepted_result.take().map_or_else(
                || failed(AgentFailureCause::MissingResult),
                |result| AgentOutcome::Completed(CompletedAgentInvocation::Result(result)),
            ),
        }
    }

    fn parse_frame(&mut self, frame: &[u8]) -> Result<ParserProgress, AgentFailureCause> {
        if frame.is_empty() {
            return Err(self.failure_for(CodexAppServerV1RejectionReason::FrameEmpty));
        }
        let value = useful_support::strict_json_from_slice(frame)
            .map_err(|_| self.failure_for(CodexAppServerV1RejectionReason::FrameDecodeFailed))?;
        let object = value
            .as_object()
            .ok_or_else(|| self.failure_for(CodexAppServerV1RejectionReason::FrameNotObject))?;
        let response = object.contains_key("id") && !object.contains_key("method");
        if !response && self.state == SetupState::TurnStart && self.turn_started_seen {
            return self.hold_turn_frame(frame);
        }
        if object.contains_key("jsonrpc") {
            return Err(
                self.failure_for(CodexAppServerV1RejectionReason::JsonRpcEnvelopeUnsupported)
            );
        }
        match (object.get("id"), object.get("method")) {
            (Some(_), None) => self.parse_response(object),
            (Some(_), Some(_)) => self.parse_server_request(object, &value),
            (None, Some(_)) => self.parse_notification(object, &value),
            _ => Err(self.failure_for(CodexAppServerV1RejectionReason::FrameEnvelopeInvalid)),
        }
    }

    /// Holds a frame of the started turn that overtook the `turn/start` response; the
    /// held frames together stay within the frame limit.
    fn hold_turn_frame(&mut self, frame: &[u8]) -> Result<ParserProgress, AgentFailureCause> {
        let Some(held_bytes) = u64::try_from(frame.len())
            .ok()
            .and_then(|bytes| self.held_turn_frame_bytes.checked_add(bytes))
            .filter(|&bytes| bytes <= self.limits.maximum_frame_bytes().get())
        else {
            return self.fail_current_phase(
                CodexAppServerV1RejectionReason::NotificationTransitionInvalid,
            );
        };
        self.held_turn_frame_bytes = held_bytes;
        self.held_turn_frames.push_back(frame.to_vec());
        Ok(ParserProgress::default())
    }

    fn parse_response(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<ParserProgress, AgentFailureCause> {
        self.prepare_rejection(CodexAppServerV1RejectionReason::ResponseEnvelopeInvalid);
        let id = RequestId(
            object
                .get("id")
                .and_then(Value::as_u64)
                .ok_or_else(|| self.failure_for_current_phase())?,
        );
        if self.completed_requests.contains(&id) || self.outstanding_request != Some(id) {
            return Err(
                self.failure_for(CodexAppServerV1RejectionReason::ResponseCorrelationInvalid)
            );
        }
        let result = object.get("result");
        let error = object.get("error");
        if result.is_some() == error.is_some() {
            return Err(self.failure_for_current_phase());
        }
        if let Some(error) = error {
            self.record_rejection(CodexAppServerV1RejectionReason::ResponseRejected);
            if let (false, Some(stage), Some(message)) = (
                self.invocation_start_acknowledged,
                self.state.failure_stage(),
                error.get("message").and_then(Value::as_str),
            ) {
                return Err(AgentFailureCause::HarnessSetupRejected {
                    stage,
                    message: message.to_owned(),
                });
            }
            return Err(self.phase_failure_cause());
        }
        let result = result
            .and_then(Value::as_object)
            .ok_or_else(|| self.failure_for_current_phase())?;
        self.completed_requests.insert(id);
        self.outstanding_request = None;
        let mut progress = ParserProgress::default();
        match id {
            INITIALIZE_REQUEST_ID if self.state == SetupState::Initialize => {
                self.parse_initialize_response(result)?;
                self.state = SetupState::ConfigRead;
                self.queue_notification("initialized", json!({}))?;
                self.queue_request(
                    CONFIG_READ_REQUEST_ID,
                    "config/read",
                    json!({
                        "cwd": self.expected_cwd.as_ref(),
                        "includeLayers": true,
                    }),
                )?;
            }
            CONFIG_READ_REQUEST_ID if self.state == SetupState::ConfigRead => {
                self.parse_config_read_response(result)?;
                let developer_instructions = self.effective_developer_instructions(result)?;
                let mut params = json!({
                    "model": self.model.as_ref(),
                    "cwd": self.expected_cwd.as_ref(),
                    "approvalPolicy": "never",
                    "sandbox": "danger-full-access",
                    "developerInstructions": developer_instructions,
                    "ephemeral": true,
                    "config": {
                        "bypass_hook_trust": true,
                    },
                });
                if let Some(provider) = &self.synthetic_model_provider {
                    params["modelProvider"] = Value::String(provider.to_string());
                }
                self.queue_request(THREAD_START_REQUEST_ID, "thread/start", params)?;
                self.state = SetupState::ThreadStart;
            }
            THREAD_START_REQUEST_ID if self.state == SetupState::ThreadStart => {
                self.parse_thread_start_response(result)?;
                self.state = SetupState::TurnStart;
                let initial_input = std::mem::take(&mut self.initial_input);
                self.queue_turn_start(initial_input)?;
            }
            request
                if request == self.turn_start_request && self.state == SetupState::TurnStart =>
            {
                self.parse_turn_start_response(result)?;
                if self.turn_started_seen {
                    progress = self.acknowledge_turn_started();
                } else {
                    self.state = SetupState::StartAcknowledgement;
                }
            }
            TURN_INTERRUPT_REQUEST_ID
                if self.interrupt_requested
                    && matches!(
                        self.state,
                        SetupState::StartAcknowledgement
                            | SetupState::Running
                            | SetupState::Terminal
                    )
                    && result.is_empty() => {}
            _ => {
                return Err(
                    self.failure_for(CodexAppServerV1RejectionReason::ResponseTransitionInvalid)
                );
            }
        }
        Ok(progress)
    }

    fn parse_server_request(
        &mut self,
        object: &Map<String, Value>,
        value: &Value,
    ) -> Result<ParserProgress, AgentFailureCause> {
        self.prepare_rejection(CodexAppServerV1RejectionReason::ServerRequestEnvelopeInvalid);
        let id = self.retain_server_request_id(object.get("id").ok_or_else(|| {
            self.failure_for(CodexAppServerV1RejectionReason::ServerRequestEnvelopeInvalid)
        })?)?;
        if self.completed_server_requests.contains(&id) {
            return Err(self.failure_for(CodexAppServerV1RejectionReason::ServerRequestRepeated));
        }
        let method = required_nonempty_string(object, "method").ok_or_else(|| {
            self.failure_for(CodexAppServerV1RejectionReason::ServerRequestEnvelopeInvalid)
        })?;
        let response = match method {
            "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
                Some(json!({"decision": "decline"}))
            }
            "item/permissions/requestApproval" => Some(json!({"permissions": {}})),
            "item/tool/requestUserInput" => Some(json!({"answers": {}})),
            "mcpServer/elicitation/request" => Some(json!({"action": "decline"})),
            _ => None,
        };
        if response.is_some() {
            required_object(object, "params").ok_or_else(|| {
                self.failure_for(CodexAppServerV1RejectionReason::ServerRequestEnvelopeInvalid)
            })?;
        }
        // The adapter closes Codex's input once the invocation is terminal, so a request
        // that arrives then is recorded and gets no answer.
        if self.state != SetupState::Terminal {
            match response {
                Some(response) => self.queue_server_response(&id, response)?,
                None => self.queue_server_error(&id, -32601, "Method not found")?,
            }
        }
        self.completed_server_requests.insert(id);
        self.record_unrecognized(value);
        Ok(ParserProgress::default())
    }

    fn parse_initialize_response(
        &self,
        result: &Map<String, Value>,
    ) -> Result<(), AgentFailureCause> {
        self.prepare_rejection(CodexAppServerV1RejectionReason::InitializationResponseInvalid);
        if !result
            .get("userAgent")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
            || required_string(result, "codexHome") != Some(self.codex_home.as_ref())
        {
            return Err(self.failure_for_current_phase());
        }
        Ok(())
    }

    fn parse_config_read_response(
        &mut self,
        result: &Map<String, Value>,
    ) -> Result<(), AgentFailureCause> {
        self.prepare_rejection(CodexAppServerV1RejectionReason::ConfigurationResponseInvalid);
        let config =
            required_object(result, "config").ok_or_else(|| self.failure_for_current_phase())?;
        optional_string(config, "developer_instructions")
            .ok_or_else(|| self.failure_for_current_phase())?;
        if required_string(config, "sqlite_home") != Some(self.sqlite_home.as_ref()) {
            return Err(self.failure_for_current_phase());
        }
        let provider = optional_string(config, "model_provider")
            .ok_or_else(|| self.failure_for_current_phase())?;
        // Codex leaves the setting null when it uses its built-in OpenAI provider.
        self.effective_model_provider = provider
            .or(Some("openai"))
            .filter(|provider| !provider.is_empty())
            .map(Arc::from);
        if self.synthetic_model_provider.is_some()
            && self.synthetic_model_provider.as_deref() != self.effective_model_provider.as_deref()
        {
            return Err(self.failure_for_current_phase());
        }
        if !result.get("origins").is_some_and(Value::is_object) {
            return Err(self.failure_for_current_phase());
        }
        Ok(())
    }

    fn effective_developer_instructions(
        &self,
        result: &Map<String, Value>,
    ) -> Result<String, AgentFailureCause> {
        self.prepare_rejection(CodexAppServerV1RejectionReason::EffectiveInstructionsInvalid);
        let config =
            required_object(result, "config").ok_or_else(|| self.failure_for_current_phase())?;
        let native = optional_string(config, "developer_instructions")
            .ok_or_else(|| self.failure_for_current_phase())?
            .filter(|instructions| !instructions.is_empty());
        let system = (!self.system_prompt.is_empty()).then_some(self.system_prompt.as_ref());
        let combined = match (native, system) {
            (Some(native), Some(system)) => format!("{native}\n\n{system}"),
            (Some(native), None) => native.to_owned(),
            (None, Some(system)) => system.to_owned(),
            (None, None) => return Err(self.failure_for_current_phase()),
        };
        let combined_bytes = u64::try_from(combined.len()).unwrap_or(u64::MAX);
        if combined_bytes > self.limits.maximum_frame_bytes().get() {
            return Err(self.failure_for_current_phase());
        }
        Ok(combined)
    }

    fn parse_thread_start_response(
        &mut self,
        result: &Map<String, Value>,
    ) -> Result<(), AgentFailureCause> {
        self.prepare_rejection(CodexAppServerV1RejectionReason::ThreadStartResponseInvalid);
        let thread = required_object(result, "thread").ok_or_else(|| {
            self.failure_for(CodexAppServerV1RejectionReason::ThreadStartResponseInvalid)
        })?;
        let raw_thread_id = required_nonempty_string(thread, "id")
            .filter(|id| is_codex_thread_id(id))
            .ok_or_else(|| {
                self.failure_for(CodexAppServerV1RejectionReason::ThreadCorrelationInvalid)
            })?;
        if self
            .thread_id
            .as_ref()
            .is_some_and(|started| started.0.as_ref() != raw_thread_id)
        {
            return Err(self.failure_for(CodexAppServerV1RejectionReason::ThreadCorrelationInvalid));
        }
        self.validate_thread_document(thread, raw_thread_id)?;
        if required_string(result, "model") != Some(self.model.as_ref())
            || required_string(result, "modelProvider") != self.effective_model_provider.as_deref()
            || required_string(result, "cwd") != Some(self.expected_cwd.as_ref())
            || required_string(result, "approvalPolicy") != Some("never")
            || required_object(result, "sandbox")
                .and_then(|sandbox| required_string(sandbox, "type"))
                != Some("dangerFullAccess")
        {
            return Err(self.failure_for_current_phase());
        }
        if self.thread_id.is_none() {
            self.thread_id = Some(self.retain_thread_id(raw_thread_id)?);
        }
        self.observations
            .push(lifecycle(AgentLifecycleMilestone::SessionEstablished));
        Ok(())
    }

    fn parse_turn_start_response(
        &mut self,
        result: &Map<String, Value>,
    ) -> Result<(), AgentFailureCause> {
        self.prepare_rejection(CodexAppServerV1RejectionReason::TurnStartResponseInvalid);
        let turn = required_object(result, "turn").ok_or_else(|| {
            self.failure_for(CodexAppServerV1RejectionReason::TurnStartResponseInvalid)
        })?;
        let raw_turn_id = required_nonempty_string(turn, "id").ok_or_else(|| {
            self.failure_for(CodexAppServerV1RejectionReason::TurnCorrelationInvalid)
        })?;
        self.correlate_turn_id(raw_turn_id)?;
        Ok(())
    }

    fn required_notification_params<'a>(
        &self,
        object: &'a Map<String, Value>,
    ) -> Result<&'a Map<String, Value>, AgentFailureCause> {
        required_object(object, "params").ok_or_else(|| {
            self.failure_for(CodexAppServerV1RejectionReason::NotificationEnvelopeInvalid)
        })
    }

    fn parse_notification(
        &mut self,
        object: &Map<String, Value>,
        value: &Value,
    ) -> Result<ParserProgress, AgentFailureCause> {
        self.prepare_rejection(CodexAppServerV1RejectionReason::NotificationEnvelopeInvalid);
        let method = required_nonempty_string(object, "method")
            .ok_or_else(|| self.failure_for_current_phase())?;
        let frame_thread = if method == "thread/started" {
            value.pointer("/params/thread/id")
        } else {
            value.pointer("/params/threadId")
        };
        if let (Some(root), Some(thread)) = (&self.thread_id, frame_thread.and_then(Value::as_str))
            && (root.0.as_ref() != thread
                || (method == "thread/started" && self.thread_started_seen))
        {
            self.observe_unrecognized(method, value);
            return Ok(ParserProgress::default());
        }
        match method {
            "thread/started" => {
                self.parse_thread_started(self.required_notification_params(object)?)?
            }
            "thread/project/updated"
                if frame_thread.and_then(Value::as_str).is_some() && self.thread_id.is_some() =>
            {
                return Err(self
                    .failure_for(CodexAppServerV1RejectionReason::NotificationTransitionInvalid));
            }
            "turn/started" | "turn/completed" | "error" | "item/completed" => {
                return self.parse_turn_notification(
                    method,
                    self.required_notification_params(object)?,
                    value,
                );
            }
            _ => {
                if required_object(object, "params")
                    .and_then(|params| self.observe_progress(method, params))
                    .is_none()
                {
                    self.observe_unrecognized(method, value);
                }
            }
        }
        Ok(ParserProgress::default())
    }

    fn parse_turn_notification(
        &mut self,
        method: &str,
        params: &Map<String, Value>,
        value: &Value,
    ) -> Result<ParserProgress, AgentFailureCause> {
        // Only an `agentMessage` completion decides. A completion of any other type is
        // progress, whatever else it carries or omits.
        let message = if method == "item/completed" {
            let (item, kind) = self.required_item(params)?;
            if kind != "agentMessage" {
                if self.observe_completed_item(params, item, kind).is_none() {
                    self.observe_unrecognized(method, value);
                }
                return Ok(ParserProgress::default());
            }
            Some(item)
        } else {
            None
        };
        self.require_thread(params)?;
        let turn_id = match method {
            "turn/started" | "turn/completed" => required_object(params, "turn")
                .and_then(|turn| required_nonempty_string(turn, "id")),
            _ => required_nonempty_string(params, "turnId"),
        }
        .ok_or_else(|| self.failure_for(CodexAppServerV1RejectionReason::TurnCorrelationInvalid))?;
        if self
            .previous_turn_id
            .as_ref()
            .is_some_and(|id| id.0.as_ref() == turn_id)
            || (self.native_terminal.is_some() && self.turn_matches(turn_id))
        {
            self.observe_unrecognized(method, value);
            return Ok(ParserProgress::default());
        }
        if method == "turn/started" {
            return self.parse_turn_started(turn_id);
        }
        if !self.is_open_turn(turn_id) {
            return Err(self.failure_for(CodexAppServerV1RejectionReason::TurnCorrelationInvalid));
        }
        if let Some(item) = message {
            self.complete_agent_message(item)?;
        } else if method == "turn/completed" {
            return self.parse_turn_completed(params);
        } else {
            self.parse_native_error(params)?;
        }
        Ok(ParserProgress::default())
    }

    fn turn_matches(&self, turn_id: &str) -> bool {
        self.turn_id
            .as_ref()
            .is_some_and(|id| id.0.as_ref() == turn_id)
    }

    fn is_open_turn(&self, turn_id: &str) -> bool {
        self.native_terminal.is_none() && self.turn_matches(turn_id)
    }

    fn parse_turn_started(&mut self, turn_id: &str) -> Result<ParserProgress, AgentFailureCause> {
        if self.turn_started_seen && self.is_open_turn(turn_id) {
            return Ok(ParserProgress::default());
        }
        if !matches!(
            self.state,
            SetupState::TurnStart | SetupState::StartAcknowledgement
        ) {
            return Err(self.failure_for(CodexAppServerV1RejectionReason::TurnCorrelationInvalid));
        }
        self.correlate_turn_id(turn_id)?;
        self.turn_started_seen = true;
        if self.state == SetupState::TurnStart {
            return Ok(ParserProgress::default());
        }
        Ok(self.acknowledge_turn_started())
    }

    fn acknowledge_turn_started(&mut self) -> ParserProgress {
        self.state = SetupState::Running;
        let first_turn = !self.invocation_start_acknowledged;
        if first_turn {
            self.invocation_start_acknowledged = true;
            self.observations
                .push(lifecycle(AgentLifecycleMilestone::HarnessStarted));
        }
        self.observations
            .push(lifecycle(AgentLifecycleMilestone::TurnStarted));
        ParserProgress {
            start_acknowledged: first_turn,
            close_standard_input: false,
        }
    }

    fn parse_thread_started(
        &mut self,
        params: &Map<String, Value>,
    ) -> Result<(), AgentFailureCause> {
        self.prepare_rejection(CodexAppServerV1RejectionReason::ThreadCorrelationInvalid);
        if !matches!(
            self.state,
            SetupState::ThreadStart
                | SetupState::TurnStart
                | SetupState::StartAcknowledgement
                | SetupState::Running
                | SetupState::ResultValidation
                | SetupState::Terminal
        ) {
            return Err(self.failure_for_current_phase());
        }
        let thread =
            required_object(params, "thread").ok_or_else(|| self.failure_for_current_phase())?;
        let raw_thread_id = required_nonempty_string(thread, "id")
            .filter(|id| is_codex_thread_id(id))
            .ok_or_else(|| {
                self.failure_for(CodexAppServerV1RejectionReason::ThreadCorrelationInvalid)
            })?;
        self.validate_thread_document(thread, raw_thread_id)?;
        self.correlate_thread_value(raw_thread_id)?;
        self.thread_started_seen = true;
        Ok(())
    }

    fn validate_thread_document(
        &self,
        thread: &Map<String, Value>,
        thread_id: &str,
    ) -> Result<(), AgentFailureCause> {
        if required_string(thread, "sessionId") != Some(thread_id)
            || required_bool(thread, "ephemeral") != Some(true)
            || optional_string(thread, "path") != Some(None)
            || optional_string(thread, "forkedFromId") != Some(None)
            || optional_string(thread, "parentThreadId") != Some(None)
            || optional_string(thread, "projectId") != Some(None)
            || required_array(thread, "turns").is_none_or(|turns| !turns.is_empty())
            || required_string(thread, "cliVersion") != Some(self.codex_version.as_ref())
            || required_string(thread, "cwd") != Some(self.expected_cwd.as_ref())
            || required_string(thread, "modelProvider") != self.effective_model_provider.as_deref()
        {
            return Err(
                self.failure_for(CodexAppServerV1RejectionReason::ThreadStartResponseInvalid)
            );
        }
        Ok(())
    }

    fn observe_progress(&mut self, method: &str, params: &Map<String, Value>) -> Option<()> {
        let thread = optional_string(params, "threadId")?;
        let turn = optional_string(params, "turnId")?;
        if matches!(
            method,
            "warning" | "configWarning" | "mcpServer/startupStatus/updated"
        ) {
            if let Some(turn) = turn {
                if thread.is_none() || !self.is_open_turn(turn) {
                    return None;
                }
            } else if thread.is_some() && self.native_terminal.is_some() {
                return None;
            }
            return match method {
                "mcpServer/startupStatus/updated" => self.observe_mcp_status(params),
                "warning" => self.observe_warning(required_nonempty_string(params, "message")?),
                _ => self.observe_warning(required_nonempty_string(params, "summary")?),
            };
        }
        if !self.is_root_thread(thread?) {
            return None;
        }
        let hook = matches!(method, "hook/started" | "hook/completed");
        let turnless_hook =
            hook && params.get("turnId") == Some(&Value::Null) && self.native_terminal.is_none();
        if !turnless_hook && !turn.is_some_and(|id| self.is_open_turn(id)) {
            return None;
        }
        match method {
            "item/started" => self.observe_item_started(params),
            "item/agentMessage/delta" => self.observe_delta(params, ItemDeltaKind::Assistant),
            "item/reasoning/summaryTextDelta" | "item/reasoning/textDelta" => {
                self.observe_delta(params, ItemDeltaKind::Reasoning)
            }
            "thread/tokenUsage/updated" => {
                let total = required_object(required_object(params, "tokenUsage")?, "total")?;
                self.observations.push(AgentObservation::Usage {
                    input_tokens: required_u64(total, "inputTokens")?,
                    output_tokens: required_u64(total, "outputTokens")?,
                });
                Some(())
            }
            "hook/started" | "hook/completed" => {
                self.observe_hook(params, method == "hook/completed")
            }
            _ => None,
        }
    }

    fn observe_item_started(&mut self, params: &Map<String, Value>) -> Option<()> {
        let item = required_object(params, "item")?;
        let id = required_nonempty_string(item, "id")?;
        let kind = required_nonempty_string(item, "type")?;
        self.complete_retry(true);
        match kind {
            "agentMessage" => self
                .observations
                .push(lifecycle(AgentLifecycleMilestone::MessageStarted)),
            "commandExecution" | "fileChange" | "mcpToolCall" => {
                self.observations.push(AgentObservation::ToolCall {
                    call_id: Arc::from(id),
                    name: Arc::from(kind),
                    phase: AgentToolCallPhase::Started,
                })
            }
            "userMessage" | "reasoning" => {}
            _ => return None,
        }
        Some(())
    }

    fn observe_completed_item(
        &mut self,
        params: &Map<String, Value>,
        item: &Map<String, Value>,
        kind: &str,
    ) -> Option<()> {
        if !self.is_root_thread(required_nonempty_string(params, "threadId")?)
            || !self.is_open_turn(required_nonempty_string(params, "turnId")?)
        {
            return None;
        }
        let id = required_nonempty_string(item, "id")?;
        match kind {
            "reasoning" => self.observe_completed_reasoning(item),
            "commandExecution" | "fileChange" | "mcpToolCall" => {
                self.observe_completed_tool(id, kind, item)
            }
            "userMessage" => Some(()),
            _ => None,
        }
    }

    fn complete_agent_message(
        &mut self,
        item: &Map<String, Value>,
    ) -> Result<(), AgentFailureCause> {
        let id = required_nonempty_string(item, "id").ok_or_else(|| {
            self.failure_for(CodexAppServerV1RejectionReason::ItemCorrelationInvalid)
        })?;
        let message = self.parse_completed_agent_message(item)?;
        if message.delivery == Some(AgentMessageDelivery::Async) {
            self.result_message = None;
            self.other_result_messages = 0;
            self.selected_response = None;
            self.final_answer_seen = false;
        } else if self.value_kind == AgentValueKind::Result
            && !matches!(
                message.phase,
                Some(AgentMessagePhase::Commentary | AgentMessagePhase::PartialAnswer)
            )
        {
            if self
                .result_message
                .as_ref()
                .is_some_and(|(retained, _)| retained.as_ref() != id)
            {
                self.other_result_messages = self.other_result_messages.saturating_add(1);
            } else {
                self.result_message = Some((Arc::from(id), message.text));
            }
        } else {
            self.select_response_candidate(&message)?;
        }
        self.observations
            .push(lifecycle(AgentLifecycleMilestone::MessageCompleted));
        Ok(())
    }

    fn parse_completed_agent_message(
        &self,
        item: &Map<String, Value>,
    ) -> Result<CompletedAgentMessage, AgentFailureCause> {
        self.prepare_rejection(CodexAppServerV1RejectionReason::MessageInvalid);
        let text = required_string(item, "text").ok_or_else(|| self.failure_for_current_phase())?;
        let phase = match item.get("phase") {
            None | Some(Value::Null) => None,
            Some(Value::String(phase)) if phase == "commentary" => {
                Some(AgentMessagePhase::Commentary)
            }
            Some(Value::String(phase)) if phase == "partial_answer" => {
                Some(AgentMessagePhase::PartialAnswer)
            }
            Some(Value::String(phase)) if phase == "final_answer" => {
                Some(AgentMessagePhase::FinalAnswer)
            }
            _ => return Err(self.failure_for_current_phase()),
        };
        let delivery = match item.get("delivery") {
            None | Some(Value::Null) => None,
            Some(Value::String(delivery)) if delivery == "async" => {
                Some(AgentMessageDelivery::Async)
            }
            _ => return Err(self.failure_for_current_phase()),
        };
        Ok(CompletedAgentMessage {
            text: Arc::from(text),
            phase,
            delivery,
        })
    }

    fn select_response_candidate(
        &mut self,
        message: &CompletedAgentMessage,
    ) -> Result<(), AgentFailureCause> {
        if !self.values_enabled
            || self.value_kind != AgentValueKind::Response
            || message.delivery == Some(AgentMessageDelivery::Async)
        {
            return Ok(());
        }
        if matches!(
            message.phase,
            Some(AgentMessagePhase::Commentary | AgentMessagePhase::PartialAnswer)
        ) {
            return Ok(());
        }
        let is_final = message.phase == Some(AgentMessagePhase::FinalAnswer);
        if self.final_answer_seen && !is_final {
            return Ok(());
        }
        let observed_bytes = u64::try_from(message.text.len()).unwrap_or(u64::MAX);
        if observed_bytes > self.maximum_response_bytes.get() {
            return Err(AgentFailureCause::CapturedValueTooLarge);
        }
        if is_final {
            self.final_answer_seen = true;
        }
        self.selected_response = (!message.text.is_empty()).then(|| Arc::clone(&message.text));
        Ok(())
    }

    fn observe_completed_reasoning(&mut self, item: &Map<String, Value>) -> Option<()> {
        let summary = required_array(item, "summary")?;
        let content = required_array(item, "content")?;
        let parts = summary.iter().chain(content);
        if !parts.clone().all(Value::is_string) {
            return None;
        }
        self.observations.extend(
            parts
                .filter_map(Value::as_str)
                .filter(|text| !text.is_empty())
                .map(|text| AgentObservation::Reasoning {
                    text: Arc::from(text),
                }),
        );
        Some(())
    }

    fn observe_completed_tool(
        &mut self,
        id: &str,
        kind: &str,
        item: &Map<String, Value>,
    ) -> Option<()> {
        let status = required_nonempty_string(item, "status")?;
        let is_error = match (kind, status) {
            ("commandExecution" | "fileChange", "completed") | ("mcpToolCall", "completed") => {
                false
            }
            ("commandExecution" | "fileChange", "failed" | "declined")
            | ("mcpToolCall", "failed") => true,
            _ => return None,
        };
        let content = if kind == "commandExecution" {
            optional_string(item, "aggregatedOutput")?.unwrap_or_default()
        } else {
            status
        };
        self.observations.push(AgentObservation::ToolCall {
            call_id: Arc::from(id),
            name: Arc::from(kind),
            phase: AgentToolCallPhase::Completed,
        });
        self.observations.push(AgentObservation::ToolResult {
            call_id: Arc::from(id),
            is_error,
            content: Arc::from(content),
        });
        Some(())
    }

    fn observe_delta(&mut self, params: &Map<String, Value>, kind: ItemDeltaKind) -> Option<()> {
        required_nonempty_string(params, "itemId")?;
        let delta = required_string(params, "delta")?;
        if !delta.is_empty() {
            self.observations.push(match kind {
                ItemDeltaKind::Assistant => AgentObservation::AssistantText {
                    text: Arc::from(delta),
                },
                ItemDeltaKind::Reasoning => AgentObservation::Reasoning {
                    text: Arc::from(delta),
                },
            });
        }
        Some(())
    }

    fn observe_hook(&mut self, params: &Map<String, Value>, completed: bool) -> Option<()> {
        let run = required_object(params, "run")?;
        let id = required_nonempty_string(run, "id")?;
        let event = required_nonempty_string(run, "eventName")?;
        let mut failure = None;
        let phase = if completed {
            match optional_string(run, "status")? {
                None | Some("completed") => {}
                Some("failed" | "blocked" | "stopped") => {
                    failure = Some(optional_string(run, "statusMessage")?.unwrap_or("hook failed"));
                }
                _ => return None,
            }
            AgentToolCallPhase::Completed
        } else {
            AgentToolCallPhase::Started
        };
        self.observations.push(AgentObservation::ToolCall {
            call_id: Arc::from(id),
            name: Arc::from(format!("hook:{event}")),
            phase,
        });
        if let Some(message) = failure.and_then(|message| self.retain_diagnostic(message)) {
            self.observations.push(AgentObservation::Diagnostic {
                level: AgentDiagnosticLevel::Error,
                message,
            });
        }
        Some(())
    }

    fn observe_mcp_status(&mut self, params: &Map<String, Value>) -> Option<()> {
        let name = required_nonempty_string(params, "name")
            .filter(|name| name.len() <= MAXIMUM_IDENTITY_BYTES)
            .filter(|name| !name.chars().any(char::is_control))?;
        let status = required_nonempty_string(params, "status")
            .filter(|status| matches!(*status, "starting" | "ready" | "failed" | "cancelled"))?;
        let error = optional_string(params, "error")?;
        let failure_reason = optional_string(params, "failureReason")?;
        if failure_reason.is_some_and(|reason| reason != "reauthenticationRequired")
            || status != "failed" && (error.is_some() || failure_reason.is_some())
        {
            return None;
        }
        let summary = format!("MCP server {name}: {status}");
        let level = if status == "failed" {
            AgentDiagnosticLevel::Error
        } else {
            AgentDiagnosticLevel::Information
        };
        let message = self.retain_diagnostic(&summary);
        if let Some(message) = message {
            self.observations
                .push(AgentObservation::Diagnostic { level, message });
        }
        if let Some(error) = error
            && let Some(message) = self.retain_diagnostic(error)
        {
            self.observations.push(AgentObservation::Diagnostic {
                level: AgentDiagnosticLevel::Error,
                message,
            });
        }
        Some(())
    }

    fn observe_warning(&mut self, message: &str) -> Option<()> {
        if let Some(message) = self.retain_diagnostic(message) {
            self.observations.push(AgentObservation::Diagnostic {
                level: AgentDiagnosticLevel::Warning,
                message,
            });
        }
        Some(())
    }

    fn parse_native_error(&mut self, params: &Map<String, Value>) -> Result<(), AgentFailureCause> {
        self.prepare_rejection(CodexAppServerV1RejectionReason::NativeErrorInvalid);
        let error =
            required_object(params, "error").ok_or_else(|| self.failure_for_current_phase())?;
        let message = required_nonempty_string(error, "message")
            .ok_or_else(|| self.failure_for_current_phase())?;
        let info = self.parse_optional_codex_error_info(error.get("codexErrorInfo"))?;
        let will_retry =
            required_bool(params, "willRetry").ok_or_else(|| self.failure_for_current_phase())?;
        self.complete_retry(false);
        if info.is_some_and(|info| info.kind == CodexErrorKind::ResponseStreamDisconnected) {
            self.truncated_provider_stream_seen = true;
        }
        self.native_error = Some(NativeErrorObservation { info, will_retry });
        if will_retry {
            self.retry_active = true;
            self.observations
                .push(lifecycle(AgentLifecycleMilestone::RetryStarted));
        }
        if let Some(message) = self.retain_diagnostic(message) {
            self.observations.push(AgentObservation::Diagnostic {
                level: AgentDiagnosticLevel::Error,
                message,
            });
        }
        Ok(())
    }

    fn parse_turn_completed(
        &mut self,
        params: &Map<String, Value>,
    ) -> Result<ParserProgress, AgentFailureCause> {
        self.prepare_rejection(CodexAppServerV1RejectionReason::TurnCompletionInvalid);
        if !matches!(
            self.state,
            SetupState::StartAcknowledgement | SetupState::Running
        ) {
            return Err(self.failure_for_current_phase());
        }
        let turn =
            required_object(params, "turn").ok_or_else(|| self.failure_for_current_phase())?;
        let status = required_nonempty_string(turn, "status")
            .ok_or_else(|| self.failure_for_current_phase())?;
        let terminal_has_error = matches!(turn.get("error"), Some(Value::Object(_)));
        let terminal_info = match turn.get("error") {
            None | Some(Value::Null) => None,
            Some(Value::Object(error)) if matches!(status, "failed" | "interrupted") => {
                let message = required_nonempty_string(error, "message")
                    .ok_or_else(|| self.failure_for_current_phase())?;
                let info = self.parse_optional_codex_error_info(error.get("codexErrorInfo"))?;
                if let Some(message) = self.retain_diagnostic(message) {
                    self.observations.push(AgentObservation::Diagnostic {
                        level: AgentDiagnosticLevel::Error,
                        message,
                    });
                }
                info
            }
            _ => return Err(self.failure_for_current_phase()),
        };
        let terminal = match status {
            "completed"
                if self.state == SetupState::Running
                    && terminal_info.is_none()
                    && (self.retry_active || self.native_error.is_none()) =>
            {
                self.complete_retry(true);
                NativeTerminal::Completed
            }
            "interrupted" => {
                self.complete_retry(false);
                NativeTerminal::Failed(if terminal_has_error {
                    self.correlate_native_failure(terminal_info)?
                } else {
                    AgentHarnessFailureDetail::ModelAborted
                })
            }
            "failed" => {
                self.complete_retry(false);
                NativeTerminal::Failed(self.correlate_native_failure(terminal_info)?)
            }
            _ => return Err(self.failure_for_current_phase()),
        };
        self.native_terminal = Some(terminal);
        if status != "completed" {
            self.invalidate_value();
        }
        self.observations
            .push(lifecycle(AgentLifecycleMilestone::TurnCompleted));
        if status == "completed" && self.value_kind == AgentValueKind::Result {
            self.state = SetupState::ResultValidation;
            match self.extract_result_candidate() {
                Ok(Some(candidate)) => {
                    self.pending_result_candidate = Some(candidate);
                    return Ok(ParserProgress::default());
                }
                Err(feedback) => return self.reject_result(Arc::from(feedback)),
                Ok(None) => {}
            }
        }
        self.state = SetupState::Terminal;
        self.observations
            .push(lifecycle(AgentLifecycleMilestone::HarnessCompleted));
        Ok(ParserProgress {
            start_acknowledged: false,
            close_standard_input: true,
        })
    }

    fn extract_result_candidate(&mut self) -> Result<Option<Arc<Value>>, &'static str> {
        let Some((_, text)) = self.result_message.take() else {
            return Ok(None);
        };
        if self.other_result_messages > 0 {
            return Err(
                "Multiple final messages supplied a result. Return a single final message with one result envelope for the completed work.",
            );
        }
        parse_weak_result_envelope(&text).map(Arc::new).map(Some)
    }

    fn reset_completed_turn(&mut self) {
        self.previous_turn_id = self.turn_id.take();
        self.other_result_messages = 0;
        self.turn_started_seen = false;
        self.result_message = None;
        self.selected_response = None;
        self.final_answer_seen = false;
        self.pending_result_candidate = None;
        self.native_terminal = None;
    }

    fn required_item<'a>(
        &self,
        params: &'a Map<String, Value>,
    ) -> Result<(&'a Map<String, Value>, &'a str), AgentFailureCause> {
        self.prepare_rejection(CodexAppServerV1RejectionReason::ItemCorrelationInvalid);
        let item =
            required_object(params, "item").ok_or_else(|| self.failure_for_current_phase())?;
        let kind = required_nonempty_string(item, "type")
            .ok_or_else(|| self.failure_for_current_phase())?;
        Ok((item, kind))
    }

    fn require_thread(&self, params: &Map<String, Value>) -> Result<(), AgentFailureCause> {
        let thread_id = required_nonempty_string(params, "threadId").ok_or_else(|| {
            self.failure_for(CodexAppServerV1RejectionReason::ThreadCorrelationInvalid)
        })?;
        self.require_thread_value(thread_id)
    }

    fn is_root_thread(&self, thread_id: &str) -> bool {
        self.thread_id.as_ref().map(|id| id.0.as_ref()) == Some(thread_id)
    }

    fn require_thread_value(&self, thread_id: &str) -> Result<(), AgentFailureCause> {
        if self.is_root_thread(thread_id) {
            Ok(())
        } else {
            Err(self.failure_for(CodexAppServerV1RejectionReason::ThreadCorrelationInvalid))
        }
    }

    fn correlate_thread_value(&mut self, thread_id: &str) -> Result<(), AgentFailureCause> {
        if self.thread_id.is_some() {
            return self.require_thread_value(thread_id);
        }
        if self.state != SetupState::ThreadStart || !is_codex_thread_id(thread_id) {
            return Err(self.failure_for(CodexAppServerV1RejectionReason::ThreadCorrelationInvalid));
        }
        self.thread_id = Some(self.retain_thread_id(thread_id)?);
        Ok(())
    }

    fn correlate_turn_id(&mut self, turn_id: &str) -> Result<(), AgentFailureCause> {
        if let Some(expected) = &self.turn_id {
            if expected.0.as_ref() != turn_id {
                return Err(
                    self.failure_for(CodexAppServerV1RejectionReason::TurnCorrelationInvalid)
                );
            }
        } else {
            self.turn_id = Some(self.retain_turn_id(turn_id)?);
        }
        Ok(())
    }

    fn parse_optional_codex_error_info(
        &self,
        value: Option<&Value>,
    ) -> Result<Option<CodexErrorInfo>, AgentFailureCause> {
        self.prepare_rejection(CodexAppServerV1RejectionReason::NativeErrorInvalid);
        let Some(value) = value.filter(|value| !value.is_null()) else {
            return Ok(None);
        };
        let kind = if let Some(value) = value.as_str() {
            let kind = match value {
                "contextWindowExceeded" => CodexErrorKind::ContextWindowExceeded,
                "sessionBudgetExceeded" => CodexErrorKind::SessionBudgetExceeded,
                "usageLimitExceeded" => CodexErrorKind::UsageLimitExceeded,
                "rateLimitExceeded" => CodexErrorKind::RateLimitExceeded,
                "flexUnavailable" => CodexErrorKind::FlexUnavailable,
                "serverOverloaded" => CodexErrorKind::ServerOverloaded,
                "modelNotFound" => CodexErrorKind::ModelNotFound,
                "policyCapacityUnavailable" => CodexErrorKind::PolicyCapacityUnavailable,
                "cyberPolicy" => CodexErrorKind::CyberPolicy,
                "bioPolicy" => CodexErrorKind::BioPolicy,
                "misalignmentPolicyViolation" => CodexErrorKind::MisalignmentPolicyViolation,
                "inferenceHookDenied" => CodexErrorKind::InferenceHookDenied,
                "tooManyDenials" => CodexErrorKind::TooManyDenials,
                "internalServerError" => CodexErrorKind::InternalServerError,
                "unauthorized" => CodexErrorKind::Unauthorized,
                "badRequest" => CodexErrorKind::BadRequest,
                "threadRollbackFailed" => CodexErrorKind::ThreadRollbackFailed,
                "sandboxError" => CodexErrorKind::SandboxError,
                "other" => CodexErrorKind::Other,
                _ => return Err(self.failure_for_current_phase()),
            };
            return Ok(Some(CodexErrorInfo {
                kind,
                http_status_code: None,
                active_turn_kind: None,
            }));
        } else {
            value
                .as_object()
                .ok_or_else(|| self.failure_for_current_phase())?
        };
        if kind.len() != 1 {
            return Err(self.failure_for_current_phase());
        }
        let (name, detail) = kind
            .iter()
            .next()
            .ok_or_else(|| self.failure_for_current_phase())?;
        let detail = detail
            .as_object()
            .ok_or_else(|| self.failure_for_current_phase())?;
        if name == "activeTurnNotSteerable" {
            if !has_exact_fields(detail, &["turnKind"])
                || !matches!(
                    required_string(detail, "turnKind"),
                    Some("review" | "compact")
                )
            {
                return Err(self.failure_for_current_phase());
            }
            let active_turn_kind = match required_string(detail, "turnKind") {
                Some("review") => ActiveTurnKind::Review,
                Some("compact") => ActiveTurnKind::Compact,
                _ => return Err(self.failure_for_current_phase()),
            };
            return Ok(Some(CodexErrorInfo {
                kind: CodexErrorKind::ActiveTurnNotSteerable,
                http_status_code: None,
                active_turn_kind: Some(active_turn_kind),
            }));
        }
        if !has_exact_fields(detail, &[]) && !has_exact_fields(detail, &["httpStatusCode"]) {
            return Err(self.failure_for_current_phase());
        }
        let http_status_code = match detail.get("httpStatusCode") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .and_then(|value| u16::try_from(value).ok())
                    .ok_or_else(|| self.failure_for_current_phase())?,
            ),
        };
        let kind = match name.as_str() {
            "httpConnectionFailed" => CodexErrorKind::HttpConnectionFailed,
            "responseStreamConnectionFailed" => CodexErrorKind::ResponseStreamConnectionFailed,
            "responseStreamDisconnected" => CodexErrorKind::ResponseStreamDisconnected,
            "responseTooManyFailedAttempts" => CodexErrorKind::ResponseTooManyFailedAttempts,
            _ => return Err(self.failure_for_current_phase()),
        };
        Ok(Some(CodexErrorInfo {
            kind,
            http_status_code,
            active_turn_kind: None,
        }))
    }

    fn correlate_native_failure(
        &self,
        terminal: Option<CodexErrorInfo>,
    ) -> Result<AgentHarnessFailureDetail, AgentFailureCause> {
        self.prepare_rejection(CodexAppServerV1RejectionReason::NativeErrorInvalid);
        let native = self.native_error.and_then(|error| error.info);
        if let (Some(native), Some(terminal)) = (native, terminal)
            && native != terminal
            && !(terminal.kind == CodexErrorKind::ResponseTooManyFailedAttempts
                && self.native_error.is_some_and(|error| error.will_retry))
        {
            return Err(self.failure_for_current_phase());
        }
        if terminal.is_none() && self.native_error.is_some_and(|error| error.will_retry) {
            return Err(self.failure_for_current_phase());
        }
        let selected = terminal.or(native);
        let truncated = selected.is_some_and(|info| {
            info.kind == CodexErrorKind::ResponseStreamDisconnected
                || info.kind == CodexErrorKind::ResponseTooManyFailedAttempts
                    && self.truncated_provider_stream_seen
        });
        Ok(selected.map_or(
            if truncated {
                AgentHarnessFailureDetail::ModelOutputTruncated
            } else {
                AgentHarnessFailureDetail::ModelError
            },
            |info| info.failure_detail(truncated),
        ))
    }

    fn complete_retry(&mut self, recovered: bool) {
        let retry_was_active = self.retry_active;
        if retry_was_active {
            self.retry_active = false;
            self.observations
                .push(lifecycle(AgentLifecycleMilestone::RetryCompleted));
        }
        if recovered && retry_was_active {
            self.native_error = None;
            self.truncated_provider_stream_seen = false;
        }
    }

    fn retain_server_request_id(
        &mut self,
        value: &Value,
    ) -> Result<ServerRequestId, AgentFailureCause> {
        match value {
            Value::String(value) => self.retain_identity(value).map(ServerRequestId::String),
            Value::Number(value) => {
                let value = value
                    .as_i64()
                    .ok_or_else(|| self.failure_for_current_phase())?;
                self.retain_correlation(std::mem::size_of::<i64>())?;
                Ok(ServerRequestId::Number(value))
            }
            _ => Err(self.failure_for_current_phase()),
        }
    }

    fn retain_thread_id(&mut self, raw: &str) -> Result<ThreadId, AgentFailureCause> {
        self.retain_identity(raw).map(ThreadId)
    }

    fn retain_turn_id(&mut self, raw: &str) -> Result<TurnId, AgentFailureCause> {
        self.retain_identity(raw).map(TurnId)
    }

    fn retain_identity(&mut self, raw: &str) -> Result<Arc<str>, AgentFailureCause> {
        if raw.is_empty() || raw.len() > MAXIMUM_IDENTITY_BYTES || raw.chars().any(char::is_control)
        {
            return Err(self.failure_for(CodexAppServerV1RejectionReason::IdentityInvalid));
        }
        self.retain_correlation(raw.len())?;
        Ok(Arc::from(raw))
    }

    fn retain_correlation(&mut self, bytes: usize) -> Result<(), AgentFailureCause> {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        self.retained_correlation_bytes = self
            .retained_correlation_bytes
            .checked_add(bytes)
            .filter(|retained| *retained <= self.limits.maximum_correlation_bytes().get())
            .ok_or_else(|| {
                self.failure_for(CodexAppServerV1RejectionReason::RetainedCorrelationLimitExceeded)
            })?;
        Ok(())
    }

    fn retain_diagnostic(&mut self, message: &str) -> Option<Arc<str>> {
        let remaining = self
            .limits
            .maximum_retained_diagnostic_bytes
            .get()
            .saturating_sub(self.retained_diagnostic_bytes);
        let remaining = usize::try_from(remaining).unwrap_or(usize::MAX);
        let (message, _) = content_safe_diagnostic(message, remaining);
        if message.is_empty() {
            return None;
        }
        let bytes = u64::try_from(message.len()).ok()?;
        self.retained_diagnostic_bytes = self.retained_diagnostic_bytes.checked_add(bytes)?;
        Some(Arc::from(message))
    }

    fn queue_turn_start(&mut self, input: Vec<Value>) -> Result<(), AgentFailureCause> {
        let thread_id = self
            .thread_id
            .as_ref()
            .ok_or_else(|| self.failure_for_current_phase())?;
        let mut params = json!({
            "threadId": thread_id.0.as_ref(),
            "input": input,
            "cwd": self.expected_cwd.as_ref(),
            "approvalPolicy": "never",
            "sandboxPolicy": {
                "type": "externalSandbox",
                "networkAccess": "enabled",
            },
            "model": self.model.as_ref(),
            "effort": self.effort.as_ref(),
        });
        if self.value_kind == AgentValueKind::Result {
            params["outputSchema"] = weak_json_schema();
        }
        self.queue_request(self.turn_start_request, "turn/start", params)
    }
    fn queue_request(
        &mut self,
        id: RequestId,
        method: &str,
        params: Value,
    ) -> Result<(), AgentFailureCause> {
        if self.outstanding_request.is_some() || self.completed_requests.contains(&id) {
            return Err(self.failure_for_current_phase());
        }
        let frame = framed_json(&json!({"id": id.0, "method": method, "params": params}))?;
        self.queue_frame(frame);
        self.outstanding_request = Some(id);
        Ok(())
    }

    fn queue_notification(&mut self, method: &str, params: Value) -> Result<(), AgentFailureCause> {
        let frame = framed_json(&json!({"method": method, "params": params}))?;
        self.queue_frame(frame);
        Ok(())
    }

    fn queue_server_response(
        &mut self,
        id: &ServerRequestId,
        result: Value,
    ) -> Result<(), AgentFailureCause> {
        self.queue_bounded_server_frame(json!({"id": id.value(), "result": result}))
    }

    fn queue_server_error(
        &mut self,
        id: &ServerRequestId,
        code: i64,
        message: &str,
    ) -> Result<(), AgentFailureCause> {
        self.queue_bounded_server_frame(json!({
            "id": id.value(),
            "error": {"code": code, "message": message},
        }))
    }

    fn queue_bounded_server_frame(&mut self, value: Value) -> Result<(), AgentFailureCause> {
        let frame = framed_json(&value)?;
        let frame_bytes = u64::try_from(frame.len()).unwrap_or(u64::MAX);
        let payload_bytes = frame_bytes.saturating_sub(1);
        if payload_bytes > self.limits.maximum_frame_bytes().get()
            || self
                .pending_outbound_bytes
                .checked_add(frame_bytes)
                .is_none_or(|pending| {
                    pending > self.limits.maximum_frame_bytes().get().saturating_add(1)
                })
        {
            return Err(self.failure_for(CodexAppServerV1RejectionReason::OutboundLimitExceeded));
        }
        self.queue_frame(frame);
        Ok(())
    }

    fn queue_frame(&mut self, frame: Vec<u8>) {
        // Trusted generated requests may exceed the inbound native-frame limit when they
        // contain valid Workflow V1 attachments. Untrusted server-triggered responses are
        // bounded separately before reaching this queue.
        self.pending_outbound_bytes = self
            .pending_outbound_bytes
            .saturating_add(u64::try_from(frame.len()).unwrap_or(u64::MAX));
        self.outbound.push_back(frame);
    }

    // Codex owns additive-event retention and provisional-value invalidation locally so
    // another harness cannot silently change this profile's protocol authority.
    fn observe_unrecognized(&mut self, method: &str, value: &Value) {
        if self.unrecognized_methods.contains(method) {
            return;
        }
        if self.unrecognized_methods.len() < MAXIMUM_UNRECOGNIZED_METHODS
            && method.len() <= MAXIMUM_UNRECOGNIZED_METHOD_BYTES
            && method
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-/.:".contains(&byte))
        {
            self.unrecognized_methods.insert(Box::from(method));
        } else if self.unrecognized_overflow_observed {
            return;
        } else {
            self.unrecognized_overflow_observed = true;
        }
        self.record_unrecognized(value);
    }

    fn record_unrecognized(&mut self, value: &Value) {
        self.observations
            .push(AgentObservation::UnrecognizedHarnessEvent {
                event: Arc::new(value.clone()),
            });
    }

    fn invalidate_value(&mut self) {
        self.selected_response = None;
        self.pending_result_candidate = None;
        self.accepted_result = None;
    }

    fn fail_current_phase<T>(
        &mut self,
        reason: CodexAppServerV1RejectionReason,
    ) -> Result<T, AgentFailureCause> {
        let failure = self.failure_for(reason);
        self.invalidate_value();
        self.failure = Some(failure.clone());
        Err(failure)
    }
}

#[derive(Clone, Copy)]
enum ItemDeltaKind {
    Assistant,
    Reasoning,
}

fn content_safe_diagnostic(message: &str, maximum_bytes: usize) -> (String, bool) {
    let mut safe = String::with_capacity(message.len().min(maximum_bytes));
    for character in message.chars() {
        if character.is_control() {
            let escaped = character.escape_default().to_string();
            if safe.len().saturating_add(escaped.len()) > maximum_bytes {
                return (safe, true);
            }
            safe.push_str(&escaped);
        } else {
            if safe.len().saturating_add(character.len_utf8()) > maximum_bytes {
                return (safe, true);
            }
            safe.push(character);
        }
    }
    (safe, false)
}

struct WeakResultEnvelope(String);

impl<'de> Deserialize<'de> for WeakResultEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(WeakResultEnvelopeVisitor)
    }
}

struct WeakResultEnvelopeVisitor;

impl<'de> Visitor<'de> for WeakResultEnvelopeVisitor {
    type Value = WeakResultEnvelope;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("one structured-result envelope")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut result = None;
        while let Some(key) = map.next_key::<String>()? {
            if key != "result" {
                return Err(de::Error::unknown_field(&key, &["result"]));
            }
            if result.is_some() {
                return Err(de::Error::duplicate_field("result"));
            }
            result = Some(map.next_value::<String>()?);
        }
        result
            .map(WeakResultEnvelope)
            .ok_or_else(|| de::Error::missing_field("result"))
    }
}

fn parse_weak_result_envelope(text: &str) -> Result<Value, &'static str> {
    let envelope = serde_json::from_str::<WeakResultEnvelope>(text).map_err(|_| {
        "Return one JSON object with exactly one field named result. Its string value must JSON-encode the completed work's structured workflow result."
    })?;
    useful_support::strict_json_from_str(&envelope.0).map_err(|_| {
        "The result string must encode one complete JSON value with unique object keys. Resubmit the structured result for the completed work."
    })
}

fn codex_result_correction_feedback(feedback: Arc<str>, maximum_bytes: NonZeroU64) -> Arc<str> {
    let Some(diagnostics) = feedback.strip_prefix(SCHEMA_REJECTION_PREFIX) else {
        return feedback;
    };
    let maximum_bytes = usize::try_from(maximum_bytes.get()).unwrap_or(usize::MAX);
    let mut correction = String::with_capacity(maximum_bytes.min(feedback.len()));
    push_bounded(
        &mut correction,
        CODEX_SCHEMA_CORRECTION_PREFIX,
        maximum_bytes,
    );
    push_bounded(&mut correction, diagnostics, maximum_bytes);
    Arc::from(correction)
}

fn push_bounded(destination: &mut String, value: &str, maximum_bytes: usize) {
    let remaining = maximum_bytes.saturating_sub(destination.len());
    destination.push_str(&value[..value.floor_char_boundary(remaining)]);
}

fn weak_json_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "result": {
                "type": "string",
                "description": "JSON-encode the structured workflow result as one string.",
            }
        },
        "required": ["result"],
        "additionalProperties": false,
    })
}
fn framed_json(value: &Value) -> Result<Vec<u8>, AgentFailureCause> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|_| AgentFailureCause::HarnessProtocolFailed)?;
    bytes.push(b'\n');
    Ok(bytes)
}

// App Server's admitted field shapes remain in its private parser rather than coupling
// native schema evolution to the Pi or Claude transport parsers.
fn required_object<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Option<&'a Map<String, Value>> {
    object.get(key)?.as_object()
}

fn has_exact_fields(object: &Map<String, Value>, expected: &[&str]) -> bool {
    object.len() == expected.len() && expected.iter().all(|field| object.contains_key(*field))
}

fn required_array<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a [Value]> {
    object.get(key)?.as_array().map(Vec::as_slice)
}

fn is_codex_thread_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
        })
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

fn required_string<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key)?.as_str()
}

fn required_nonempty_string<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    required_string(object, key).filter(|value| !value.is_empty())
}

fn optional_string<'a>(object: &'a Map<String, Value>, key: &str) -> Option<Option<&'a str>> {
    match object.get(key) {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(value)) => Some(Some(value)),
        _ => None,
    }
}

fn required_bool(object: &Map<String, Value>, key: &str) -> Option<bool> {
    object.get(key)?.as_bool()
}

fn required_u64(object: &Map<String, Value>, key: &str) -> Option<u64> {
    object.get(key)?.as_u64()
}

// These small constructors preserve Codex-specific terminal and observation authority
// without introducing a shared native-parser result layer.
fn lifecycle(milestone: AgentLifecycleMilestone) -> AgentObservation {
    AgentObservation::Lifecycle { milestone }
}

fn failed(cause: AgentFailureCause) -> AgentOutcome {
    AgentOutcome::Failed(cause.into())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod adapter_tests;
