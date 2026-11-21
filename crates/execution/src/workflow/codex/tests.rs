use std::num::NonZeroU64;
use std::sync::Arc;

use serde_json::{Value, json};

use super::*;

const THREAD_ID: &str = "018f7f1e-7b5a-7d13-8f19-2b6a4c8d0e12";
const CODEX_HOME: &str = "/synthetic/codex-home";
const SQLITE_HOME: &str = "/synthetic/sqlite-home";
const CLIENT_VERSION: &str = "0.0.0-test";

fn parser(
    value_kind: AgentValueKind,
    maximum_response_bytes: u64,
    synthetic_model_provider: Option<&str>,
) -> CodexAppServerV1Parser {
    parser_with_system_prompt(
        value_kind,
        maximum_response_bytes,
        synthetic_model_provider,
        "scherzo system",
    )
}

fn parser_with_system_prompt(
    value_kind: AgentValueKind,
    maximum_response_bytes: u64,
    synthetic_model_provider: Option<&str>,
    system_prompt: &str,
) -> CodexAppServerV1Parser {
    CodexAppServerV1Parser::profile(
        Arc::from("/synthetic/project"),
        Arc::from(CODEX_HOME),
        Arc::from(SQLITE_HOME),
        Arc::from(CLIENT_VERSION),
        Arc::from("0.147.0"),
        Arc::from("scherzo-loopback"),
        Arc::from("high"),
        Arc::from(system_prompt),
        vec![json!({"type": "text", "text": "user request"})],
        synthetic_model_provider.map(Arc::from),
        value_kind,
        NonZeroU64::new(maximum_response_bytes).unwrap(),
        NonZeroU64::new(512).unwrap(),
        CodexAppServerV1ProtocolLimits::profile(),
    )
    .unwrap()
}

fn take_json(parser: &mut CodexAppServerV1Parser) -> Value {
    let frame = parser.take_outbound().unwrap();
    assert_eq!(frame.last(), Some(&b'\n'));
    serde_json::from_slice(&frame[..frame.len() - 1]).unwrap()
}

fn result_envelope(result: Value) -> String {
    json!({"result": serde_json::to_string(&result).unwrap()}).to_string()
}

fn rejection_reason(parser: &CodexAppServerV1Parser) -> Value {
    serde_json::to_value(parser.protocol_rejection()).unwrap()["detail"]["reason"].clone()
}

fn feed(
    parser: &mut CodexAppServerV1Parser,
    mut value: Value,
) -> Result<(ParserProgress, Vec<AgentObservation>), AgentFailureCause> {
    replace_fixture_thread_id(&mut value);
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    let mut observations = Vec::new();
    let progress = parser.push_stdout(&bytes, |observation| observations.push(observation))?;
    Ok((progress, observations))
}

fn replace_fixture_thread_id(value: &mut Value) {
    match value {
        Value::String(value) if value == "thread-1" => *value = THREAD_ID.to_owned(),
        Value::Array(values) => values.iter_mut().for_each(replace_fixture_thread_id),
        Value::Object(values) => values.values_mut().for_each(replace_fixture_thread_id),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn initialize(parser: &mut CodexAppServerV1Parser) {
    assert_eq!(
        take_json(parser),
        json!({
            "id": 1,
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "useful",
                    "version": CLIENT_VERSION,
                }
            }
        })
    );
    feed(
        parser,
        json!({
            "id": 1,
            "result": {"userAgent": "codex/0.147.0", "codexHome": CODEX_HOME}
        }),
    )
    .unwrap();
    assert_eq!(
        take_json(parser),
        json!({"method": "initialized", "params": {}})
    );
    assert_eq!(
        take_json(parser),
        json!({
            "id": 2,
            "method": "config/read",
            "params": {"cwd": "/synthetic/project", "includeLayers": true}
        })
    );
}

fn effective_config(parser: &mut CodexAppServerV1Parser, provider: &str) -> Value {
    feed(
        parser,
        json!({
            "id": 2,
            "result": {
                "config": {
                    "developer_instructions": "native developer",
                    "sqlite_home": SQLITE_HOME,
                    "model_provider": provider,
                    "model_providers": {provider: {"wire_api": "responses"}},
                    "projects": {
                        "/synthetic/project": {"trust_level": "trusted"}
                    },
                    "hooks": {"enabled": true},
                    "mcp_servers": {"native": {"required": true}},
                },
                "origins": {"developer_instructions": {"name": {"type": "user"}}},
                "layers": [{"name": {"type": "user"}}],
            }
        }),
    )
    .unwrap();
    take_json(parser)
}

fn thread_start_response(provider: &str) -> Value {
    json!({
        "id": 3,
        "result": {
            "thread": {
                "id": "thread-1",
                "sessionId": "thread-1",
                "ephemeral": true,
                "path": null,
                "cliVersion": "0.147.0",
                "turns": [],
                "cwd": "/synthetic/project",
                "modelProvider": provider,
            },
            "model": "scherzo-loopback",
            "modelProvider": provider,
            "cwd": "/synthetic/project",
            "approvalPolicy": "never",
            "sandbox": {"type": "dangerFullAccess"},
        }
    })
}

fn thread_started_notification() -> Value {
    json!({
        "method": "thread/started",
        "params": {"thread": {
            "id": "thread-1",
            "sessionId": "thread-1",
            "ephemeral": true,
            "path": null,
            "cliVersion": "0.147.0",
            "turns": [],
            "cwd": "/synthetic/project",
            "modelProvider": "native-provider",
        }}
    })
}

fn thread_response(parser: &mut CodexAppServerV1Parser, provider: &str) {
    feed(parser, thread_start_response(provider)).unwrap();
    let turn = take_json(parser);
    assert_eq!(turn["id"], 4);
    assert_eq!(turn["method"], "turn/start");
    assert_eq!(turn["params"]["threadId"], THREAD_ID);
    assert_eq!(turn["params"]["approvalPolicy"], "never");
    assert_eq!(
        turn["params"]["sandboxPolicy"],
        json!({"type": "externalSandbox", "networkAccess": "enabled"})
    );
    assert_eq!(turn["params"]["model"], "scherzo-loopback");
    assert_eq!(turn["params"]["effort"], "high");
    if parser.value_kind == AgentValueKind::Result {
        assert_eq!(turn["params"]["outputSchema"], weak_json_schema());
    } else {
        assert!(turn["params"].get("outputSchema").is_none());
    }
}

fn turn_response(parser: &mut CodexAppServerV1Parser) {
    feed(parser, thread_started_notification()).unwrap();
    feed(
        parser,
        json!({
            "id": 4,
            "result": {"turn": {"id": "turn-1", "items": [], "status": "inProgress"}}
        }),
    )
    .unwrap();
}

fn start(parser: &mut CodexAppServerV1Parser) -> Vec<AgentObservation> {
    let (progress, observations) = feed(
        parser,
        json!({
            "method": "turn/started",
            "params": {
                "threadId": "thread-1",
                "turn": {"id": "turn-1", "items": [], "status": "inProgress"},
            }
        }),
    )
    .unwrap();
    assert!(progress.start_acknowledged);
    observations
}

fn running_parser(
    value_kind: AgentValueKind,
    maximum_response_bytes: u64,
) -> CodexAppServerV1Parser {
    let mut parser = parser(value_kind, maximum_response_bytes, None);
    initialize(&mut parser);
    let thread = effective_config(&mut parser, "native-provider");
    assert!(thread["params"].get("modelProvider").is_none());
    assert_eq!(
        thread["params"]["developerInstructions"],
        "native developer\n\nscherzo system"
    );
    assert_eq!(thread["params"]["ephemeral"], true);
    assert_eq!(
        thread["params"]["config"],
        json!({"bypass_hook_trust": true})
    );
    thread_response(&mut parser, "native-provider");
    turn_response(&mut parser);
    start(&mut parser);
    parser
}

fn item_started(id: &str, kind: &str) -> Value {
    json!({
        "method": "item/started",
        "params": {
            "threadId": "thread-1",
            "turnId": "turn-1",
            "item": {"id": id, "type": kind, "text": ""},
        }
    })
}

fn item_completed(id: &str, text: &str, phase: Value) -> Value {
    json!({
        "method": "item/completed",
        "params": {
            "threadId": "thread-1",
            "turnId": "turn-1",
            "item": {"id": id, "type": "agentMessage", "text": text, "phase": phase},
        }
    })
}

fn turn_completed(items: Vec<Value>, status: &str) -> Value {
    json!({
        "method": "turn/completed",
        "params": {
            "threadId": "thread-1",
            "turn": {"id": "turn-1", "items": items, "status": status},
        }
    })
}

fn turn_completed_with_items_view(items: Vec<Value>, status: &str, items_view: &str) -> Value {
    let mut completed = turn_completed(items, status);
    completed["params"]["turn"]["itemsView"] = json!(items_view);
    completed
}

// REQ-AGENT-15, REQ-AGENT-16
#[test]
fn setup_requests_preserve_native_resources_and_only_fixtures_select_a_provider() {
    let mut production = parser(AgentValueKind::None, 1024, None);
    initialize(&mut production);
    let thread = effective_config(&mut production, "host-provider");
    assert!(thread["params"].get("modelProvider").is_none());
    assert!(thread["params"].get("baseInstructions").is_none());
    assert_eq!(
        thread["params"]["developerInstructions"],
        "native developer\n\nscherzo system"
    );

    let mut synthetic = parser(AgentValueKind::None, 1024, Some("loopback"));
    initialize(&mut synthetic);
    let thread = effective_config(&mut synthetic, "loopback");
    assert_eq!(thread["params"]["modelProvider"], "loopback");
}

// REQ-AGENT-15
#[test]
fn implicit_openai_provider_matches_the_native_thread() {
    let mut parser = parser(AgentValueKind::None, 1024, None);
    initialize(&mut parser);
    feed(
        &mut parser,
        json!({
            "id": 2,
            "result": {
                "config": {"model_provider": null, "sqlite_home": SQLITE_HOME},
                "origins": {}
            }
        }),
    )
    .unwrap();
    let thread = take_json(&mut parser);
    assert!(thread["params"].get("modelProvider").is_none());
    thread_response(&mut parser, "openai");
}

#[test]
fn admitted_text_attachment_fits_the_initial_native_turn() {
    let attachment = "x".repeat(usize::try_from(MAXIMUM_FRAME_BYTES).unwrap());
    let mut parser = CodexAppServerV1Parser::profile(
        Arc::from("/synthetic/project"),
        Arc::from(CODEX_HOME),
        Arc::from(SQLITE_HOME),
        Arc::from(CLIENT_VERSION),
        Arc::from("0.147.0"),
        Arc::from("scherzo-loopback"),
        Arc::from("high"),
        Arc::from("scherzo system"),
        vec![
            json!({"type": "text", "text": "user request"}),
            json!({
                "type": "text",
                "text": format!(
                    "Scherzo attachment 000000 (text/plain) follows:\n{attachment}"
                ),
            }),
        ],
        None,
        AgentValueKind::None,
        NonZeroU64::new(1024).unwrap(),
        NonZeroU64::new(512).unwrap(),
        CodexAppServerV1ProtocolLimits::profile(),
    )
    .unwrap();
    initialize(&mut parser);
    let _ = effective_config(&mut parser, "native-provider");

    feed(
        &mut parser,
        json!({
            "id": 3,
            "result": {
                "thread": {
                    "id": "thread-1",
                    "sessionId": "thread-1",
                    "ephemeral": true,
                    "path": null,
                    "cliVersion": "0.147.0",
                    "turns": [],
                    "cwd": "/synthetic/project",
                    "modelProvider": "native-provider",
                },
                "model": "scherzo-loopback",
                "modelProvider": "native-provider",
                "cwd": "/synthetic/project",
                "approvalPolicy": "never",
                "sandbox": {"type": "dangerFullAccess"},
            }
        }),
    )
    .expect("an attachment below the admitted 256-MiB limit must reach Codex");
}

#[test]
fn empty_or_oversized_effective_instructions_fail_during_configuration() {
    let mut empty = parser_with_system_prompt(AgentValueKind::None, 1024, None, "");
    initialize(&mut empty);
    assert_eq!(
        feed(
            &mut empty,
            json!({
                "id": 2,
                "result": {
                    "config": {
                        "developer_instructions": "",
                        "sqlite_home": SQLITE_HOME,
                        "model_provider": "native-provider",
                    },
                    "origins": {},
                },
            }),
        )
        .unwrap_err(),
        AgentFailureCause::HarnessSetupFailed {
            stage: AgentHarnessSetupStage::EffectiveConfiguration,
        }
    );

    let mut oversized = parser_with_system_prompt(AgentValueKind::None, 1024, None, "12345");
    initialize(&mut oversized);
    oversized.limits.maximum_frame_bytes = NonZeroU64::new(4).unwrap();
    let response = json!({
        "id": 2,
        "result": {
            "config": {
                "developer_instructions": "",
                "sqlite_home": SQLITE_HOME,
                "model_provider": "native-provider",
            },
            "origins": {},
        },
    });
    assert_eq!(
        oversized
            .parse_response(response.as_object().unwrap())
            .unwrap_err(),
        AgentFailureCause::HarnessSetupFailed {
            stage: AgentHarnessSetupStage::EffectiveConfiguration,
        }
    );
}

#[test]
fn matching_thread_notification_and_response_may_arrive_in_either_order() {
    let mut response_first = parser(AgentValueKind::None, 1024, None);
    initialize(&mut response_first);
    effective_config(&mut response_first, "native-provider");
    let (progress, observations) = feed(
        &mut response_first,
        thread_start_response("native-provider"),
    )
    .unwrap();
    assert!(!progress.start_acknowledged);
    assert!(observations.iter().any(|observation| matches!(
        observation,
        AgentObservation::Lifecycle {
            milestone: AgentLifecycleMilestone::SessionEstablished,
        }
    )));
    assert_eq!(take_json(&mut response_first)["method"], "turn/start");
    let (progress, observations) =
        feed(&mut response_first, thread_started_notification()).unwrap();
    assert!(!progress.start_acknowledged);
    assert!(observations.is_empty());

    let mut notification_first = parser(AgentValueKind::None, 1024, None);
    initialize(&mut notification_first);
    effective_config(&mut notification_first, "native-provider");
    let (progress, observations) =
        feed(&mut notification_first, thread_started_notification()).unwrap();
    assert!(!progress.start_acknowledged);
    assert!(observations.is_empty());
    let (progress, observations) = feed(
        &mut notification_first,
        thread_start_response("native-provider"),
    )
    .unwrap();
    assert!(!progress.start_acknowledged);
    assert!(observations.iter().any(|observation| matches!(
        observation,
        AgentObservation::Lifecycle {
            milestone: AgentLifecycleMilestone::SessionEstablished,
        }
    )));
    assert_eq!(take_json(&mut notification_first)["method"], "turn/start");

    let mut mismatched = parser(AgentValueKind::None, 1024, None);
    initialize(&mut mismatched);
    effective_config(&mut mismatched, "native-provider");
    feed(&mut mismatched, thread_started_notification()).unwrap();
    let mut response = thread_start_response("native-provider");
    response["result"]["thread"]["id"] =
        Value::String("018f7f1e-7b5a-7d13-8f19-2b6a4c8d0e13".to_owned());
    assert_eq!(
        feed(&mut mismatched, response).unwrap_err(),
        AgentFailureCause::HarnessSetupFailed {
            stage: AgentHarnessSetupStage::ThreadStart,
        }
    );
}

// REQ-AGENT-17
// INV-HARNESS-4
#[test]
fn thread_start_requires_a_fresh_unassigned_root_and_accepts_nullable_metadata() {
    for notification_first in [false, true] {
        let mut parser = parser(AgentValueKind::None, 1024, None);
        initialize(&mut parser);
        effective_config(&mut parser, "native-provider");
        let mut notification = thread_started_notification();
        notification["params"]["thread"]["projectId"] = Value::Null;
        notification["params"]["thread"]["model"] = Value::Null;
        notification["params"]["thread"]["reasoningEffort"] = Value::Null;
        notification["params"]["thread"]["futureField"] = json!({"nested": true});
        let mut response = thread_start_response("native-provider");
        response["result"]["thread"]["projectId"] = Value::Null;
        response["result"]["thread"]["model"] = Value::Null;
        response["result"]["thread"]["reasoningEffort"] = Value::Null;
        response["result"]["futureField"] = json!(true);
        if notification_first {
            feed(&mut parser, notification).unwrap();
            feed(&mut parser, response).unwrap();
        } else {
            feed(&mut parser, response).unwrap();
            feed(&mut parser, notification).unwrap();
        }
    }

    for (field, value) in [
        ("projectId", json!("project-1")),
        ("forkedFromId", json!("parent-thread")),
        ("parentThreadId", json!("parent-thread")),
        ("path", json!("/ambient/rollout.jsonl")),
        ("ephemeral", json!(false)),
        ("turns", json!([{"id": "prior-turn"}])),
    ] {
        let mut parser = parser(AgentValueKind::None, 1024, None);
        initialize(&mut parser);
        effective_config(&mut parser, "native-provider");
        let mut response = thread_start_response("native-provider");
        response["result"]["thread"][field] = value;
        assert_eq!(
            feed(&mut parser, response).unwrap_err(),
            AgentFailureCause::HarnessSetupFailed {
                stage: AgentHarnessSetupStage::ThreadStart,
            },
            "{field}",
        );
    }
}

#[test]
fn thread_scoped_warning_may_precede_thread_response() {
    let mut matching = parser(AgentValueKind::None, 1024, None);
    initialize(&mut matching);
    effective_config(&mut matching, "native-provider");
    let (progress, observations) = feed(
        &mut matching,
        json!({"method": "warning", "params": {
            "threadId": "thread-1",
            "message": "native startup warning",
        }}),
    )
    .unwrap();
    assert!(!progress.start_acknowledged);
    assert!(matches!(
        observations.as_slice(),
        [AgentObservation::Diagnostic {
            level: AgentDiagnosticLevel::Warning,
            message,
        }] if message.as_ref() == "native startup warning"
    ));
    feed(&mut matching, thread_start_response("native-provider")).unwrap();
    assert_eq!(take_json(&mut matching)["method"], "turn/start");

    let mut mismatched = parser(AgentValueKind::None, 1024, None);
    initialize(&mut mismatched);
    effective_config(&mut mismatched, "native-provider");
    feed(
        &mut mismatched,
        json!({"method": "warning", "params": {
            "threadId": "018f7f1e-7b5a-7d13-8f19-2b6a4c8d0e13",
            "message": "native startup warning",
        }}),
    )
    .unwrap();
    feed(&mut mismatched, thread_start_response("native-provider")).unwrap();
    assert_eq!(take_json(&mut mismatched)["method"], "turn/start");
}

#[test]
fn matching_turn_notification_acknowledges_start_after_the_response_in_either_order() {
    let mut response_first = parser(AgentValueKind::None, 1024, None);
    initialize(&mut response_first);
    effective_config(&mut response_first, "native-provider");
    thread_response(&mut response_first, "native-provider");
    turn_response(&mut response_first);
    let observations = start(&mut response_first);
    assert!(observations.iter().any(|observation| matches!(
        observation,
        AgentObservation::Lifecycle {
            milestone: AgentLifecycleMilestone::HarnessStarted,
        }
    )));

    let mut notification_first = parser(AgentValueKind::None, 1024, None);
    initialize(&mut notification_first);
    effective_config(&mut notification_first, "native-provider");
    thread_response(&mut notification_first, "native-provider");
    let (progress, observations) = feed(
        &mut notification_first,
        json!({
            "method": "turn/started",
            "params": {"threadId": "thread-1", "turn": {
                "id": "turn-1", "items": [], "status": "inProgress"
            }}
        }),
    )
    .unwrap();
    assert!(!progress.start_acknowledged);
    assert!(observations.is_empty());
    let (progress, observations) = feed(
        &mut notification_first,
        json!({
            "id": 4,
            "result": {"turn": {"id": "turn-1", "items": [], "status": "inProgress"}}
        }),
    )
    .unwrap();
    assert!(progress.start_acknowledged);
    assert!(observations.iter().any(|observation| matches!(
        observation,
        AgentObservation::Lifecycle {
            milestone: AgentLifecycleMilestone::HarnessStarted,
        }
    )));

    let mut mismatched = parser(AgentValueKind::None, 1024, None);
    initialize(&mut mismatched);
    effective_config(&mut mismatched, "native-provider");
    thread_response(&mut mismatched, "native-provider");
    feed(
        &mut mismatched,
        json!({
            "method": "turn/started",
            "params": {"threadId": "thread-1", "turn": {
                "id": "turn-1", "items": [], "status": "inProgress"
            }}
        }),
    )
    .unwrap();
    assert_eq!(
        feed(
            &mut mismatched,
            json!({
                "id": 4,
                "result": {"turn": {"id": "other-turn", "items": [], "status": "inProgress"}}
            }),
        )
        .unwrap_err(),
        AgentFailureCause::HarnessSetupFailed {
            stage: AgentHarnessSetupStage::TurnStart,
        }
    );

    let mut batched = parser(AgentValueKind::None, 1024, None);
    initialize(&mut batched);
    effective_config(&mut batched, "native-provider");
    thread_response(&mut batched, "native-provider");
    turn_response(&mut batched);
    let frames = [
        json!({
            "method": "turn/started",
            "params": {
                "threadId": THREAD_ID,
                "turn": {"id": "turn-1", "items": [], "status": "inProgress"},
            }
        }),
        json!({
            "method": "turn/completed",
            "params": {
                "threadId": THREAD_ID,
                "turn": {"id": "unknown-turn", "status": "completed", "items": []},
            }
        }),
    ];
    let mut bytes = Vec::new();
    for frame in frames {
        serde_json::to_writer(&mut bytes, &frame).unwrap();
        bytes.push(b'\n');
    }
    let mut observations = Vec::new();
    assert_eq!(
        batched
            .push_stdout(&bytes, |observation| observations.push(observation))
            .unwrap_err(),
        AgentFailureCause::HarnessProtocolFailed
    );
    assert!(batched.start_acknowledged());
    assert!(observations.iter().any(|observation| matches!(
        observation,
        AgentObservation::Lifecycle {
            milestone: AgentLifecycleMilestone::HarnessStarted,
        }
    )));
}

fn first_turn_start_response() -> Value {
    json!({
        "id": 4,
        "result": {"turn": {"id": "turn-1", "items": [], "status": "inProgress"}}
    })
}

fn user_message_item(method: &str, turn_id: &str) -> Value {
    json!({
        "method": method,
        "params": {
            "threadId": "thread-1",
            "turnId": turn_id,
            "item": {
                "id": "user-1",
                "type": "userMessage",
                "content": [{"type": "text", "text": "user request"}],
            },
        }
    })
}

fn turn_started_ahead_of_its_response(parser: &mut CodexAppServerV1Parser) {
    initialize(parser);
    effective_config(parser, "native-provider");
    thread_response(parser, "native-provider");
    for frame in [
        thread_started_notification(),
        json!({
            "method": "turn/started",
            "params": {"threadId": "thread-1", "turn": {
                "id": "turn-1", "items": [], "status": "inProgress"
            }}
        }),
    ] {
        assert_eq!(
            feed(parser, frame).unwrap(),
            (ParserProgress::default(), Vec::new())
        );
    }
}

fn held_feed(parser: &mut CodexAppServerV1Parser, frame: Value) {
    assert_eq!(
        feed(parser, frame).unwrap(),
        (ParserProgress::default(), Vec::new())
    );
    assert!(!parser.start_acknowledged());
}

// INV-HARNESS-20
#[test]
fn turn_frames_that_overtake_the_turn_start_response_are_parsed_after_it() {
    let mut overtaken = parser(AgentValueKind::None, 1024, None);
    turn_started_ahead_of_its_response(&mut overtaken);
    held_feed(&mut overtaken, user_message_item("item/started", "turn-1"));
    held_feed(
        &mut overtaken,
        user_message_item("item/completed", "turn-1"),
    );
    held_feed(&mut overtaken, item_started("commentary", "agentMessage"));
    held_feed(
        &mut overtaken,
        item_completed("commentary", "looking", json!("commentary")),
    );
    let (progress, observations) = feed(&mut overtaken, first_turn_start_response()).unwrap();
    assert!(progress.start_acknowledged);
    assert_eq!(
        observations,
        [
            AgentLifecycleMilestone::HarnessStarted,
            AgentLifecycleMilestone::TurnStarted,
            AgentLifecycleMilestone::MessageStarted,
            AgentLifecycleMilestone::MessageCompleted,
        ]
        .map(lifecycle)
    );
    let (progress, _) = feed(
        &mut overtaken,
        turn_completed(
            vec![
                user_message_item("item/completed", "turn-1")["params"]["item"].clone(),
                json!({
                    "id": "commentary",
                    "type": "agentMessage",
                    "text": "looking",
                    "phase": "commentary",
                }),
            ],
            "completed",
        ),
    )
    .unwrap();
    assert!(progress.close_standard_input);
    assert_eq!(
        overtaken.finish(true),
        AgentOutcome::Completed(CompletedAgentInvocation::NoValue)
    );

    let mut unanswered = parser(AgentValueKind::None, 1024, None);
    turn_started_ahead_of_its_response(&mut unanswered);
    held_feed(&mut unanswered, user_message_item("item/started", "turn-1"));
    assert_eq!(
        unanswered.finish(true),
        AgentOutcome::Failed(
            AgentFailureCause::HarnessSetupFailed {
                stage: AgentHarnessSetupStage::TurnStart,
            }
            .into()
        )
    );
    assert!(!unanswered.start_acknowledged());

    let mut running = running_parser(AgentValueKind::None, 1024);
    let mut wrong_turn = item_completed("foreign", "unexpected", json!("final_answer"));
    wrong_turn["params"]["turnId"] = json!("other-turn");
    let running_failure = feed(&mut running, wrong_turn.clone()).unwrap_err();
    let mut cross_turn = parser(AgentValueKind::None, 1024, None);
    turn_started_ahead_of_its_response(&mut cross_turn);
    held_feed(&mut cross_turn, wrong_turn);
    assert_eq!(
        feed(&mut cross_turn, first_turn_start_response()).unwrap_err(),
        running_failure
    );
    assert_eq!(
        cross_turn.rejection_reason.get(),
        running.rejection_reason.get()
    );
    assert!(cross_turn.start_acknowledged());

    let held = [
        user_message_item("item/started", "turn-1"),
        user_message_item("item/completed", "turn-1"),
    ];
    let held_bytes = held
        .iter()
        .map(|frame| {
            let mut frame = frame.clone();
            replace_fixture_thread_id(&mut frame);
            u64::try_from(serde_json::to_vec(&frame).unwrap().len()).unwrap()
        })
        .sum::<u64>();
    for (maximum_frame_bytes, within) in [(held_bytes, true), (held_bytes - 1, false)] {
        let mut bounded = parser(AgentValueKind::None, 1024, None);
        turn_started_ahead_of_its_response(&mut bounded);
        bounded.limits = CodexAppServerV1ProtocolLimits::with_limits(
            NonZeroU64::new(maximum_frame_bytes).unwrap(),
            CodexAppServerV1ProtocolLimits::profile().maximum_correlation_bytes,
        );
        held_feed(&mut bounded, held[0].clone());
        if within {
            held_feed(&mut bounded, held[1].clone());
            continue;
        }
        assert_eq!(
            feed(&mut bounded, held[1].clone()).unwrap_err(),
            AgentFailureCause::HarnessSetupFailed {
                stage: AgentHarnessSetupStage::TurnStart,
            }
        );
        assert_eq!(
            bounded.rejection_reason.get(),
            Some(CodexAppServerV1RejectionReason::NotificationTransitionInvalid)
        );
        assert!(!bounded.start_acknowledged());
    }
}

// REQ-AGENT-90, REQ-AGENT-25, REQ-AGENT-26
// INV-HARNESS-26
#[test]
fn a_thread_other_than_the_leads_decides_nothing_announced_or_not() {
    const CHILD: &str = "018f7f1e-7b5a-7d13-8f19-2b6a4c8d0e13";
    let mut parser = running_parser(AgentValueKind::Result, 1024);
    let child_turn = json!({"id": "child-turn", "items": [], "status": "inProgress"});
    for frame in [
        json!({"method": "thread/started", "params": {"thread": {"id": CHILD}}}),
        json!({"method": "turn/started", "params": {"threadId": CHILD, "turn": child_turn}}),
        json!({"method": "item/completed", "params": {"threadId": CHILD, "turnId": "child-turn",
            "item": {"id": "answer", "type": "agentMessage", "phase": "final_answer",
                "text": result_envelope(json!("child"))}}}),
        json!({"method": "error", "params": {"threadId": CHILD, "turnId": "child-turn",
            "error": {"message": "child error"}, "willRetry": false}}),
        json!({"method": "turn/completed", "params": {"threadId": CHILD,
            "turn": {"id": "child-turn", "items": [], "status": "completed"}}}),
    ] {
        feed(&mut parser, frame)
            .unwrap_or_else(|err| panic!("{err:?}: {}", rejection_reason(&parser)));
    }
    feed(
        &mut parser,
        json!({"id": 12, "method": "item/commandExecution/requestApproval",
        "params": {"threadId": CHILD, "turnId": "child-turn", "itemId": "child-command"}}),
    )
    .unwrap();
    assert_eq!(
        take_json(&mut parser),
        json!({"id": 12, "result": {"decision": "decline"}})
    );
    assert_eq!(parser.state, SetupState::Running);
    assert!(parser.pending_result_candidate.is_none());

    let mut missing = parser.clone();
    feed(&mut missing, turn_completed(vec![], "completed")).unwrap();
    assert_eq!(
        missing.finish(true),
        AgentOutcome::Failed(AgentFailureCause::MissingResult.into())
    );
    let mut failed = parser.clone();
    let mut terminal = turn_completed(vec![], "failed");
    terminal["params"]["turn"]["error"] = json!({"message": "lead failed"});
    feed(&mut failed, terminal).unwrap();
    assert!(matches!(failed.finish(true), AgentOutcome::Failed(failure)
        if matches!(failure.cause(), AgentFailureCause::HarnessFailed { .. })));

    let mut announced = parser.clone();
    let mut spawn = item_started("spawn", "collabAgentToolCall");
    spawn["params"]["item"]["tool"] = json!("spawnAgent");
    spawn["params"]["item"]["senderThreadId"] = json!(THREAD_ID);
    feed(&mut announced, spawn.clone()).unwrap();
    spawn["method"] = json!("item/completed");
    spawn["params"]["item"]["receiverThreadIds"] = json!([]);
    feed(&mut announced, spawn).unwrap();
    for mut lead in [parser, announced] {
        feed(&mut lead, item_started("answer", "agentMessage")).unwrap();
        let message = item_completed(
            "answer",
            &result_envelope(json!("parent")),
            json!("final_answer"),
        );
        feed(&mut lead, message.clone()).unwrap();
        feed(
            &mut lead,
            turn_completed(vec![message["params"]["item"].clone()], "completed"),
        )
        .unwrap();
        assert_eq!(
            lead.pending_result_candidate.as_deref(),
            Some(&json!("parent"))
        );
    }
}

// REQ-AGENT-90
#[test]
fn subagent_activity_and_early_child_status_decide_nothing() {
    const CHILD: &str = "018f7f1e-7b5a-7d13-8f19-2b6a4c8d0e13";
    let mut parser = running_parser(AgentValueKind::Result, 1024);
    feed(
        &mut parser,
        json!({"method":"thread/status/changed", "params":{"threadId": CHILD}}),
    )
    .unwrap();
    let mut activity = item_started("activity", "subAgentActivity");
    activity["params"]["item"]["agentThreadId"] = json!(CHILD);
    activity["params"]["item"]["kind"] = json!("started");
    feed(&mut parser, activity.clone()).unwrap();
    activity["method"] = json!("item/completed");
    feed(&mut parser, activity).unwrap();
    let mut child_completion = turn_completed(vec![], "completed");
    child_completion["params"]["threadId"] = json!(CHILD);
    feed(&mut parser, child_completion).unwrap();
    assert_eq!(parser.state, SetupState::Running);
    assert!(parser.pending_result_candidate.is_none());
}

// REQ-AGENT-90, REQ-AGENT-25, REQ-AGENT-26
#[test]
fn a_delegated_codex_thread_cannot_settle_the_leads_turn() {
    const CHILD: &str = "018f7f1e-7b5a-7d13-8f19-2b6a4c8d0e13";
    let mut parser = running_parser(AgentValueKind::Result, 1024);
    let mut spawn = item_started("spawn", "collabAgentToolCall");
    spawn["params"]["item"]["tool"] = json!("spawnAgent");
    spawn["params"]["item"]["senderThreadId"] = json!(THREAD_ID);
    feed(&mut parser, spawn.clone()).unwrap();

    // Native Codex may publish child status while a spawn is in progress.
    feed(
        &mut parser,
        json!({"method":"thread/status/changed", "params":{"threadId": CHILD}}),
    )
    .unwrap();
    spawn["method"] = json!("item/completed");
    let mut unmatched = parser.clone();
    spawn["params"]["item"]["receiverThreadIds"] = json!([]);
    feed(&mut unmatched, spawn.clone()).unwrap();
    feed(&mut unmatched, turn_completed(vec![], "completed")).unwrap();
    assert_eq!(
        unmatched.finish(true),
        AgentOutcome::Failed(AgentFailureCause::MissingResult.into())
    );
    spawn["params"]["item"]["receiverThreadIds"] = json!([CHILD]);
    feed(&mut parser, spawn).unwrap();

    feed(
        &mut parser,
        json!({"id": 12, "method":"item/commandExecution/requestApproval",
        "params":{"threadId":CHILD,"turnId":"child-turn","itemId":"child-command"}}),
    )
    .unwrap();
    assert_eq!(
        take_json(&mut parser)["result"],
        json!({"decision":"decline"})
    );
    let mut child_message = item_completed(
        "answer",
        &result_envelope(json!("child")),
        json!("final_answer"),
    );
    child_message["params"]["threadId"] = json!(CHILD);
    let mut child_done = turn_completed(vec![], "completed");
    child_done["params"]["threadId"] = json!(CHILD);
    feed(&mut parser, child_message).unwrap();
    feed(&mut parser, child_done).unwrap();
    assert!(parser.pending_result_candidate.is_none());
    assert_eq!(parser.state, SetupState::Running);

    let parent_text = result_envelope(json!("parent"));
    feed(&mut parser, item_started("answer", "agentMessage")).unwrap();
    let parent_message = item_completed("answer", &parent_text, json!("final_answer"));
    feed(&mut parser, parent_message.clone()).unwrap();
    feed(
        &mut parser,
        turn_completed(vec![parent_message["params"]["item"].clone()], "completed"),
    )
    .unwrap();
    assert_eq!(
        parser.pending_result_candidate.as_deref(),
        Some(&json!("parent"))
    );
}

#[test]
fn stale_and_duplicate_responses_fail_even_when_progress_is_ignored() {
    let mut stale = parser(AgentValueKind::None, 1024, None);
    initialize(&mut stale);
    assert_eq!(
        feed(&mut stale, json!({"id": 1, "result": {}})).unwrap_err(),
        AgentFailureCause::HarnessSetupFailed {
            stage: AgentHarnessSetupStage::EffectiveConfiguration,
        }
    );

    let mut cross_thread = running_parser(AgentValueKind::None, 1024);
    let mut child = item_started("item-1", "agentMessage");
    child["params"]["threadId"] = json!("other");
    feed(&mut cross_thread, child).unwrap();

    let mut duplicate_response = running_parser(AgentValueKind::None, 1024);
    assert_eq!(
        feed(
            &mut duplicate_response,
            json!({"id": 4, "result": {"turn": {"id": "turn-1", "items": [], "status": "inProgress"}}})
        )
        .unwrap_err(),
        AgentFailureCause::HarnessProtocolFailed
    );
}

// REQ-AGENT-26
#[test]
fn completed_final_answer_is_authoritative_and_deltas_are_observations_only() {
    let mut parser = running_parser(AgentValueKind::Response, 5);
    feed(&mut parser, item_started("commentary", "agentMessage")).unwrap();
    feed(
        &mut parser,
        json!({
            "method": "item/agentMessage/delta",
            "params": {"threadId": "thread-1", "turnId": "turn-1", "itemId": "commentary", "delta": "provisional"}
        }),
    )
    .unwrap();
    feed(
        &mut parser,
        item_completed("commentary", "ignore", json!("commentary")),
    )
    .unwrap();
    feed(&mut parser, item_started("final", "agentMessage")).unwrap();
    feed(
        &mut parser,
        item_completed("final", "12345", json!("final_answer")),
    )
    .unwrap();
    let (progress, _) = feed(
        &mut parser,
        turn_completed(
            vec![
                json!({"id": "commentary", "type": "agentMessage", "text": "ignore", "phase": "commentary"}),
                json!({"id": "final", "type": "agentMessage", "text": "12345", "phase": "final_answer"}),
            ],
            "completed",
        ),
    )
    .unwrap();
    assert!(progress.close_standard_input);
    let AgentOutcome::Completed(CompletedAgentInvocation::Response(response)) = parser.finish(true)
    else {
        panic!("exact-limit completed final answer must be authoritative");
    };
    assert_eq!(response.as_str(), "12345");
}

#[test]
fn partial_answers_have_no_response_or_result_authority() {
    for value_kind in [AgentValueKind::Response, AgentValueKind::Result] {
        for final_follows in [false, true] {
            let mut parser = running_parser(value_kind, 5);
            let partial_text = result_envelope(json!(99));
            let partial = json!({
                "id": "partial",
                "type": "agentMessage",
                "text": partial_text,
                "phase": "partial_answer",
            });
            feed(&mut parser, item_started("partial", "agentMessage")).unwrap();
            let (_, observations) = feed(
                &mut parser,
                item_completed("partial", &partial_text, json!("partial_answer")),
            )
            .unwrap();
            assert!(observations.iter().any(|observation| matches!(
                observation,
                AgentObservation::Lifecycle {
                    milestone: AgentLifecycleMilestone::MessageCompleted,
                }
            )));

            let mut items = vec![partial];
            if final_follows {
                let text = if value_kind == AgentValueKind::Result {
                    result_envelope(json!(7))
                } else {
                    "final".to_owned()
                };
                feed(&mut parser, item_started("final", "agentMessage")).unwrap();
                feed(
                    &mut parser,
                    item_completed("final", &text, json!("final_answer")),
                )
                .unwrap();
                items.push(json!({
                    "id": "final", "type": "agentMessage", "text": text, "phase": "final_answer",
                }));
            }
            feed(&mut parser, turn_completed(items, "completed")).unwrap();
            match (value_kind, final_follows) {
                (AgentValueKind::Response, true) => {
                    let AgentOutcome::Completed(CompletedAgentInvocation::Response(response)) =
                        parser.finish(true)
                    else {
                        panic!("ordinary final must settle after a partial answer");
                    };
                    assert_eq!(response.as_str(), "final");
                }
                (AgentValueKind::Response, false) => assert_eq!(
                    parser.finish(true),
                    AgentOutcome::Completed(CompletedAgentInvocation::NoResponse),
                ),
                (AgentValueKind::Result, true) => {
                    assert_eq!(parser.take_result_candidate().unwrap().as_ref(), &json!(7));
                }
                (AgentValueKind::Result, false) => {
                    assert!(parser.take_result_candidate().is_none());
                    assert_eq!(
                        parser.finish(true),
                        AgentOutcome::Failed(AgentFailureCause::MissingResult.into()),
                    );
                }
                _ => panic!("only response and result modes are exercised"),
            }
        }
    }

    let mut mismatched = running_parser(AgentValueKind::Response, 1024);
    feed(&mut mismatched, item_started("partial", "agentMessage")).unwrap();
    feed(
        &mut mismatched,
        item_completed("partial", "provisional", json!("partial_answer")),
    )
    .unwrap();
    feed(
        &mut mismatched,
        turn_completed(
            vec![json!({
                "id":"partial","type":"agentMessage","text":"provisional","phase":"final_answer"
            })],
            "completed",
        ),
    )
    .unwrap();
    assert_eq!(
        mismatched.finish(true),
        AgentOutcome::Completed(CompletedAgentInvocation::NoResponse)
    );
}

#[test]
fn the_streamed_message_decides_regardless_of_the_terminal_items_view() {
    for view in [
        None,
        Some("full"),
        Some("summary"),
        Some("notLoaded"),
        Some("future"),
    ] {
        let mut parser = running_parser(AgentValueKind::Response, 1024);
        feed(
            &mut parser,
            item_completed("final", "streamed response", json!("final_answer")),
        )
        .unwrap();
        let items = vec![json!({"id":"final", "type":"agentMessage", "text":"another response"})];
        let completed = match view {
            Some(view) => turn_completed_with_items_view(items, "completed", view),
            None => turn_completed(items, "completed"),
        };
        feed(&mut parser, completed).unwrap();
        let AgentOutcome::Completed(CompletedAgentInvocation::Response(response)) =
            parser.finish(true)
        else {
            panic!("expected the streamed response for {view:?}");
        };
        assert_eq!(response.as_str(), "streamed response");
    }
}

#[test]
fn async_delivery_is_observable_but_has_no_response_or_result_authority() {
    let async_item = |text: &str| {
        json!({
            "id": "async",
            "type": "agentMessage",
            "text": text,
            "phase": "final_answer",
            "delivery": "async",
        })
    };

    let mut response = running_parser(AgentValueKind::Response, 5);
    feed(&mut response, item_started("async", "agentMessage")).unwrap();
    let (_, observations) = feed(
        &mut response,
        json!({
            "method": "item/completed",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "item": async_item("not a bounded response"),
            },
        }),
    )
    .unwrap();
    assert!(observations.iter().any(|observation| matches!(
        observation,
        AgentObservation::Lifecycle {
            milestone: AgentLifecycleMilestone::MessageCompleted,
        }
    )));
    feed(
        &mut response,
        turn_completed(vec![async_item("not a bounded response")], "completed"),
    )
    .unwrap();
    assert_eq!(
        response.finish(true),
        AgentOutcome::Completed(CompletedAgentInvocation::NoResponse)
    );

    let mut later_final = running_parser(AgentValueKind::Response, 5);
    feed(&mut later_final, item_started("async", "agentMessage")).unwrap();
    feed(
        &mut later_final,
        json!({
            "method": "item/completed",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "item": async_item("ignore this"),
            },
        }),
    )
    .unwrap();
    feed(&mut later_final, item_started("final", "agentMessage")).unwrap();
    feed(
        &mut later_final,
        item_completed("final", "12345", json!("final_answer")),
    )
    .unwrap();
    feed(
        &mut later_final,
        turn_completed(
            vec![
                async_item("ignore this"),
                json!({
                    "id": "final",
                    "type": "agentMessage",
                    "text": "12345",
                    "phase": "final_answer",
                }),
            ],
            "completed",
        ),
    )
    .unwrap();
    let AgentOutcome::Completed(CompletedAgentInvocation::Response(selected)) =
        later_final.finish(true)
    else {
        panic!("the later ordinary final message must remain authoritative");
    };
    assert_eq!(selected.as_str(), "12345");

    let mut result = running_parser(AgentValueKind::Result, 1024);
    feed(&mut result, item_started("async", "agentMessage")).unwrap();
    feed(
        &mut result,
        json!({
            "method": "item/completed",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "item": async_item("not a result envelope"),
            },
        }),
    )
    .unwrap();
    feed(&mut result, item_started("result", "agentMessage")).unwrap();
    let ordinary_result = result_envelope(json!(7));
    feed(
        &mut result,
        item_completed("result", &ordinary_result, json!("final_answer")),
    )
    .unwrap();
    feed(
        &mut result,
        turn_completed(
            vec![
                async_item("not a result envelope"),
                json!({
                    "id": "result",
                    "type": "agentMessage",
                    "text": ordinary_result,
                    "phase": "final_answer",
                }),
            ],
            "completed",
        ),
    )
    .unwrap();
    assert_eq!(result.take_result_candidate().unwrap().as_ref(), &json!(7));

    let mut missing = running_parser(AgentValueKind::Result, 1024);
    feed(&mut missing, item_started("async", "agentMessage")).unwrap();
    feed(
        &mut missing,
        json!({
            "method": "item/completed",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "item": async_item("not a result envelope"),
            },
        }),
    )
    .unwrap();
    feed(
        &mut missing,
        turn_completed(vec![async_item("not a result envelope")], "completed"),
    )
    .unwrap();
    assert_eq!(
        missing.finish(true),
        AgentOutcome::Failed(AgentFailureCause::MissingResult.into())
    );
}

#[test]
fn async_delivery_invalidates_earlier_value_candidates() {
    let mut parser = running_parser(AgentValueKind::Response, 1024);
    feed(&mut parser, item_started("ordinary", "agentMessage")).unwrap();
    feed(
        &mut parser,
        item_completed("ordinary", "must not commit", json!("final_answer")),
    )
    .unwrap();

    let async_item = json!({
        "id": "async",
        "type": "agentMessage",
        "text": "non-terminal update",
        "phase": "final_answer",
        "delivery": "async",
    });
    feed(&mut parser, item_started("async", "agentMessage")).unwrap();
    feed(
        &mut parser,
        json!({
            "method": "item/completed",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "item": async_item.clone(),
            },
        }),
    )
    .unwrap();
    feed(
        &mut parser,
        turn_completed(
            vec![
                json!({
                    "id": "ordinary",
                    "type": "agentMessage",
                    "text": "must not commit",
                    "phase": "final_answer",
                }),
                async_item,
            ],
            "completed",
        ),
    )
    .unwrap();

    let mut result = running_parser(AgentValueKind::Result, 1024);
    let ordinary_result = result_envelope(json!(7));
    feed(&mut result, item_started("ordinary-result", "agentMessage")).unwrap();
    feed(
        &mut result,
        item_completed("ordinary-result", &ordinary_result, json!("final_answer")),
    )
    .unwrap();
    let async_result = json!({
        "id": "async-result",
        "type": "agentMessage",
        "text": "non-terminal update",
        "phase": "final_answer",
        "delivery": "async",
    });
    feed(&mut result, item_started("async-result", "agentMessage")).unwrap();
    feed(
        &mut result,
        json!({
            "method": "item/completed",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "item": async_result.clone(),
            },
        }),
    )
    .unwrap();
    feed(
        &mut result,
        turn_completed(
            vec![
                json!({
                    "id": "ordinary-result",
                    "type": "agentMessage",
                    "text": ordinary_result,
                    "phase": "final_answer",
                }),
                async_result,
            ],
            "completed",
        ),
    )
    .unwrap();

    assert_eq!(
        (parser.finish(true), result.take_result_candidate()),
        (
            AgentOutcome::Completed(CompletedAgentInvocation::NoResponse),
            None,
        )
    );
}

#[test]
fn async_delivery_cannot_survive_native_failure() {
    let mut parser = running_parser(AgentValueKind::Response, 1024);
    feed(&mut parser, item_started("async", "agentMessage")).unwrap();
    let item = json!({
        "id": "async",
        "type": "agentMessage",
        "text": "must not commit",
        "phase": "final_answer",
        "delivery": "async",
    });
    feed(
        &mut parser,
        json!({
            "method": "item/completed",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "item": item.clone(),
            },
        }),
    )
    .unwrap();
    feed(&mut parser, turn_completed(vec![item], "failed")).unwrap();
    assert!(matches!(parser.finish(true), AgentOutcome::Failed(_)));
}

#[test]
fn project_and_strict_review_notifications_are_bounded_nonsettling_metadata() {
    let mut parser = running_parser(AgentValueKind::Response, 1024);
    let mut project_changes = Vec::new();
    for change_type in ["created", "updated", "deleted"] {
        let (progress, observations) = feed(
            &mut parser,
            json!({
                "method": "project/changed",
                "params": {"projectId": "project-1", "changeType": change_type},
                "emittedAtMs": 20,
            }),
        )
        .unwrap();
        assert_eq!(progress, ParserProgress::default());
        project_changes.extend(observations);
    }
    assert!(matches!(
        project_changes.as_slice(),
        [AgentObservation::UnrecognizedHarnessEvent { event }]
            if event["params"]["changeType"] == "created"
    ));
    let (progress, observations) = feed(
        &mut parser,
        json!({
            "method": "autoApprovalReview/strictReviewRequired",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "startedAtMs": 19,
            },
            "emittedAtMs": 20,
        }),
    )
    .unwrap();
    assert_eq!(progress, ParserProgress::default());
    assert!(matches!(
        observations.as_slice(),
        [AgentObservation::UnrecognizedHarnessEvent { .. }]
    ));
    assert!(parser.take_outbound().is_none());

    feed(&mut parser, item_started("final", "agentMessage")).unwrap();
    feed(
        &mut parser,
        item_completed("final", "ordinary", json!("final_answer")),
    )
    .unwrap();
    feed(
        &mut parser,
        turn_completed(
            vec![json!({
                "id": "final",
                "type": "agentMessage",
                "text": "ordinary",
                "phase": "final_answer",
            })],
            "completed",
        ),
    )
    .unwrap();
    let AgentOutcome::Completed(CompletedAgentInvocation::Response(response)) = parser.finish(true)
    else {
        panic!("metadata must not prevent the ordinary final response from settling");
    };
    assert_eq!(response.as_str(), "ordinary");

    for additive in [
        json!({
            "method": "project/changed",
            "params": {"projectId": "project-1", "changeType": "renamed"},
            "emittedAtMs": 20,
        }),
        json!({
            "method": "autoApprovalReview/strictReviewRequired",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "startedAtMs": 21,
                "futureField": true,
            },
            "emittedAtMs": 20,
        }),
    ] {
        let mut parser = running_parser(AgentValueKind::None, 1024);
        let (_, observations) = feed(&mut parser, additive).unwrap();
        assert!(matches!(
            observations.as_slice(),
            [AgentObservation::UnrecognizedHarnessEvent { .. }]
        ));
    }

    let mut assigned = running_parser(AgentValueKind::None, 1024);
    assert_eq!(
        feed(
            &mut assigned,
            json!({
                "method": "thread/project/updated",
                "params": {"threadId": "thread-1", "projectId": "project-1"},
                "emittedAtMs": 20,
            }),
        )
        .unwrap_err(),
        AgentFailureCause::HarnessProtocolFailed,
    );

    let mut review = json!({"method": "autoApprovalReview/strictReviewRequired",
        "params": {"threadId": "other", "turnId": "turn-1"}});
    let mut parser = running_parser(AgentValueKind::None, 1024);
    feed(&mut parser, review.clone()).unwrap();
    review["params"] = json!({"threadId": "thread-1", "turnId": "other"});
    let (progress, _) = feed(&mut parser, review).unwrap();
    assert_eq!(progress, ParserProgress::default());
}

#[test]
fn candidate_additive_events_are_bounded_nonsettling_observations() {
    let mut parser = running_parser(AgentValueKind::Response, 1024);
    feed(&mut parser, item_started("mcp-item", "mcpToolCall")).unwrap();
    let realtime_item = json!({
        "id": "realtime-item",
        "realtimeSessionId": "realtime-session",
        "type": "transcriptSegment",
        "role": "assistant",
        "text": "must not become a response",
    });
    for event in [
        json!({
            "method": "thread/prediction/updated",
            "params": {
                "threadId": "thread-1",
                "sourceTurnId": "turn-1",
                "result": {"type": "completed", "text": "not a settled response"},
            },
        }),
        json!({
            "method": "thread/readState/changed",
            "params": {
                "threadId": "thread-1",
                "readState": {"revision": "rev-1", "firstUnread": null},
            },
        }),
        json!({
            "method": "thread/compacted",
            "params": {"threadId": "thread-1", "turnId": "turn-1"},
        }),
        json!({
            "method": "guardianWarning",
            "params": {"threadId": "thread-1", "message": "fixture warning"},
        }),
        json!({
            "method": "model/rerouted",
            "params": {"threadId": "thread-1", "turnId": "turn-1",
                "fromModel": "selected", "toModel": "daybreak", "reason": "fixture"},
        }),
        json!({
            "method": "item/mcpToolCall/progress",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "itemId": "mcp-item",
                "message": "native progress",
            },
        }),
        json!({
            "method": "mcpServer/event/stream/notification",
            "params": {
                "subscriptionId": "subscription-1",
                "notification": {
                    "method": "notifications/progress",
                    "params": {"progress": 1},
                },
            },
        }),
        json!({
            "method": "thread/realtime/item/started",
            "params": {"threadId": "thread-1", "item": realtime_item.clone()},
        }),
        json!({
            "method": "thread/realtime/item/transcript/delta",
            "params": {
                "threadId": "thread-1",
                "itemId": "realtime-item",
                "delta": "provisional",
            },
        }),
        json!({
            "method": "thread/realtime/item/completed",
            "params": {"threadId": "thread-1", "item": realtime_item},
        }),
        json!({
            "method": "modelProvider/authRecoveryStarted",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "provider": "native-provider",
                "message": "recovering",
            },
        }),
        json!({
            "method": "modelProvider/authRecoveryCompleted",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "provider": "native-provider",
                "message": "recovered",
            },
        }),
    ] {
        let (progress, observations) = feed(&mut parser, event).unwrap();
        assert_eq!(progress, ParserProgress::default());
        assert!(matches!(
            observations.as_slice(),
            [AgentObservation::UnrecognizedHarnessEvent { .. }]
        ));
        assert!(parser.take_outbound().is_none());
    }
    feed(
        &mut parser,
        json!({
            "method": "item/completed",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "item": {
                    "id": "mcp-item",
                    "type": "mcpToolCall",
                    "status": "completed",
                },
            },
        }),
    )
    .unwrap();

    feed(&mut parser, item_started("final", "agentMessage")).unwrap();
    feed(
        &mut parser,
        item_completed("final", "ordinary", json!("final_answer")),
    )
    .unwrap();
    feed(
        &mut parser,
        turn_completed(
            vec![
                json!({
                    "id": "mcp-item",
                    "type": "mcpToolCall",
                    "status": "completed",
                }),
                json!({
                    "id": "final",
                    "type": "agentMessage",
                    "text": "ordinary",
                    "phase": "final_answer",
                }),
            ],
            "completed",
        ),
    )
    .unwrap();
    let AgentOutcome::Completed(CompletedAgentInvocation::Response(response)) = parser.finish(true)
    else {
        panic!("candidate events must not settle or replace the ordinary response");
    };
    assert_eq!(response.as_str(), "ordinary");

    let mut result = running_parser(AgentValueKind::Result, 1024);
    let (progress, observations) = feed(
        &mut result,
        json!({
            "method": "thread/prediction/updated",
            "params": {
                "threadId": "thread-1",
                "sourceTurnId": "turn-1",
                "result": {"type": "completed", "text": result_envelope(json!(7))},
            },
        }),
    )
    .unwrap();
    assert_eq!(progress, ParserProgress::default());
    assert!(matches!(
        observations.as_slice(),
        [AgentObservation::UnrecognizedHarnessEvent { .. }]
    ));
    assert!(result.take_result_candidate().is_none());
    feed(&mut result, turn_completed(vec![], "completed")).unwrap();
    assert_eq!(
        result.finish(true),
        AgentOutcome::Failed(AgentFailureCause::MissingResult.into()),
    );

    for event in [
        json!({
            "method": "thread/realtime/item/transcript/delta",
            "params": {
                "threadId": "other-thread",
                "itemId": "realtime-item",
                "delta": "provisional",
            },
        }),
        json!({
            "method": "thread/readState/changed",
            "params": {
                "threadId": "other-thread",
                "readState": {"revision": "rev-1", "firstUnread": null},
            },
        }),
    ] {
        let mut mismatched = running_parser(AgentValueKind::None, 1024);
        feed(&mut mismatched, event).unwrap();
    }
}

#[test]
fn realtime_items_with_different_session_ids_remain_progress() {
    let mut parser = running_parser(AgentValueKind::None, 1024);
    let started_item = json!({
        "id": "realtime-item",
        "realtimeSessionId": "session-a",
        "type": "transcriptSegment",
        "role": "assistant",
        "text": "provisional",
    });
    feed(
        &mut parser,
        json!({
            "method": "thread/realtime/item/started",
            "params": {"threadId": "thread-1", "item": started_item.clone()},
        }),
    )
    .unwrap();
    let mut completed_item = started_item;
    completed_item["realtimeSessionId"] = json!("session-b");
    let (progress, observations) = feed(&mut parser, json!({
        "method":"thread/realtime/item/completed", "params":{"threadId":"thread-1","item":completed_item}
    })).unwrap();
    assert_eq!(progress, ParserProgress::default());
    assert!(matches!(
        observations.as_slice(),
        [AgentObservation::UnrecognizedHarnessEvent { .. }]
    ));
}

#[test]
fn interrupted_turns_with_finished_or_unfinished_hooks_commit_no_provisional_value() {
    let started_hook = json!({
        "id": "interrupt-hook",
        "eventName": "interrupt",
        "displayOrder": 0,
        "entries": [],
        "executionMode": "sync",
        "handlerType": "command",
        "scope": "turn",
        "sourcePath": "/synthetic/interrupt-hook",
        "startedAt": 1,
        "status": "running",
    });
    let mut completed_hook = started_hook.clone();
    completed_hook["completedAt"] = json!(2);
    completed_hook["durationMs"] = json!(1);
    completed_hook["status"] = json!("completed");

    let mut parser = running_parser(AgentValueKind::Response, 1024);
    feed(&mut parser, item_started("provisional", "agentMessage")).unwrap();
    feed(
        &mut parser,
        item_completed("provisional", "must not commit", json!("final_answer")),
    )
    .unwrap();
    assert!(parser.request_turn_interrupt().unwrap());
    assert_eq!(take_json(&mut parser)["method"], "turn/interrupt");
    feed(&mut parser, json!({"id": 5, "result": {}})).unwrap();
    feed(
        &mut parser,
        json!({
            "method": "hook/started",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "run": started_hook.clone(),
            },
        }),
    )
    .unwrap();
    feed(
        &mut parser,
        json!({
            "method": "hook/completed",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "run": completed_hook,
            },
        }),
    )
    .unwrap();
    feed(
        &mut parser,
        turn_completed(
            vec![json!({
                "id": "provisional",
                "type": "agentMessage",
                "text": "must not commit",
                "phase": "final_answer",
            })],
            "interrupted",
        ),
    )
    .unwrap();
    assert_eq!(
        parser.finish(true),
        AgentOutcome::Failed(
            AgentFailureCause::HarnessFailed {
                detail: AgentHarnessFailureDetail::ModelAborted,
            }
            .into(),
        ),
    );

    let mut premature = running_parser(AgentValueKind::None, 1024);
    assert!(premature.request_turn_interrupt().unwrap());
    let _ = take_json(&mut premature);
    feed(&mut premature, json!({"id": 5, "result": {}})).unwrap();
    feed(
        &mut premature,
        json!({
            "method": "hook/started",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "run": started_hook,
            },
        }),
    )
    .unwrap();
    feed(&mut premature, turn_completed(Vec::new(), "interrupted")).unwrap();
    assert_eq!(
        premature.finish(true),
        AgentOutcome::Failed(
            AgentFailureCause::HarnessFailed {
                detail: AgentHarnessFailureDetail::ModelAborted,
            }
            .into()
        )
    );
}

#[test]
fn completed_turn_with_native_error_fails_closed_without_committing_response() {
    let mut parser = running_parser(AgentValueKind::Response, 1024);
    feed(&mut parser, item_started("final", "agentMessage")).unwrap();
    feed(
        &mut parser,
        item_completed("final", "response", json!("final_answer")),
    )
    .unwrap();

    assert_eq!(
        feed(
            &mut parser,
            json!({
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turn": {
                        "id": "turn-1",
                        "items": [{
                            "id": "final",
                            "type": "agentMessage",
                            "text": "response",
                            "phase": "final_answer",
                        }],
                        "status": "completed",
                        "error": {"message": "native terminal failure"},
                    },
                },
            }),
        )
        .unwrap_err(),
        AgentFailureCause::HarnessProtocolFailed
    );
    assert_eq!(
        parser.finish(true),
        AgentOutcome::Failed(AgentFailureCause::HarnessProtocolFailed.into())
    );
}

#[test]
fn unsupported_tool_status_is_observed_as_unrecognized() {
    for (kind, status) in [
        ("commandExecution", "unsupported"),
        ("fileChange", "unsupported"),
        ("mcpToolCall", "unsupported"),
        ("mcpToolCall", "declined"),
    ] {
        let mut parser = running_parser(AgentValueKind::None, 1024);
        let tool = |status| {
            json!({
                "id": "tool",
                "type": kind,
                "status": status,
                "aggregatedOutput": "",
            })
        };
        feed(
            &mut parser,
            json!({
                "method": "item/started",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": tool("inProgress"),
                },
            }),
        )
        .unwrap();

        let (_, observations) = feed(
            &mut parser,
            json!({
                "method": "item/completed",
                "params": {"threadId":"thread-1","turnId":"turn-1","item":tool(status)},
            }),
        )
        .unwrap();
        assert!(matches!(
            observations.as_slice(),
            [AgentObservation::UnrecognizedHarnessEvent { .. }]
        ));
    }
}

#[test]
fn repeated_result_message_replaces_the_retained_text() {
    let mut parser = running_parser(AgentValueKind::Result, 1024);
    for number in [1, 7] {
        feed(
            &mut parser,
            item_completed(
                "final",
                &result_envelope(json!(number)),
                json!("final_answer"),
            ),
        )
        .unwrap();
    }
    feed(&mut parser, turn_completed(vec![], "completed")).unwrap();
    assert_eq!(parser.take_result_candidate().as_deref(), Some(&json!(7)));
}

// REQ-AGENT-27
#[test]
fn absent_empty_oversized_delta_only_and_failed_outputs_never_commit() {
    for messages in [
        vec![],
        vec![json!({
            "id": "empty", "type": "agentMessage", "text": "", "phase": "final_answer"
        })],
    ] {
        let mut parser = running_parser(AgentValueKind::Response, 5);
        if !messages.is_empty() {
            feed(&mut parser, item_started("empty", "agentMessage")).unwrap();
            feed(
                &mut parser,
                item_completed("empty", "", json!("final_answer")),
            )
            .unwrap();
        }
        feed(&mut parser, turn_completed(messages, "completed")).unwrap();
        assert_eq!(
            parser.finish(true),
            AgentOutcome::Completed(CompletedAgentInvocation::NoResponse)
        );
    }

    let mut oversized = running_parser(AgentValueKind::Response, 5);
    feed(&mut oversized, item_started("large", "agentMessage")).unwrap();
    assert_eq!(
        feed(
            &mut oversized,
            item_completed("large", "123456", json!("final_answer"))
        )
        .unwrap_err(),
        AgentFailureCause::CapturedValueTooLarge
    );

    let mut delta_only = running_parser(AgentValueKind::Response, 5);
    feed(&mut delta_only, item_started("delta", "agentMessage")).unwrap();
    feed(
        &mut delta_only,
        json!({
            "method": "item/agentMessage/delta",
            "params": {"threadId": "thread-1", "turnId": "turn-1", "itemId": "delta", "delta": "12345"}
        }),
    )
    .unwrap();
    feed(&mut delta_only, turn_completed(vec![], "completed")).unwrap();
    assert_eq!(
        delta_only.finish(true),
        AgentOutcome::Completed(CompletedAgentInvocation::NoResponse)
    );

    for status in ["failed", "interrupted"] {
        let mut parser = running_parser(AgentValueKind::Response, 5);
        feed(&mut parser, item_started("final", "agentMessage")).unwrap();
        feed(
            &mut parser,
            item_completed("final", "12345", json!("final_answer")),
        )
        .unwrap();
        feed(
            &mut parser,
            turn_completed(
                vec![json!({"id": "final", "type": "agentMessage", "text": "12345", "phase": "final_answer"})],
                status,
            ),
        )
        .unwrap();
        assert!(matches!(
            parser.finish(true),
            AgentOutcome::Failed(failure)
                if matches!(failure.cause(), AgentFailureCause::HarnessFailed { .. })
        ));
    }
}

// REQ-AGENT-31
#[test]
fn malformed_or_ambiguous_submissions_get_a_correction_but_absent_submissions_end() {
    for text in [
        "not-json",
        "```json\n{\"result\":\"1\"}\n```",
        "{\"result\":\"1\",\"result\":\"2\"}",
        "{\"result\":\"1\",\"extra\":true}",
        "{\"result\":\"not-json\"}",
        "{\"result\":\"{\\\"decision\\\":\\\"recheck\\\",\\\"decision\\\":\\\"gave_up\\\"}\"}",
    ] {
        let mut parser = running_parser(AgentValueKind::Result, 1024);
        feed(&mut parser, item_started("result", "agentMessage")).unwrap();
        feed(
            &mut parser,
            item_completed("result", text, json!("final_answer")),
        )
        .unwrap();
        feed(
            &mut parser,
            turn_completed(
                vec![json!({
                    "id": "result",
                    "type": "agentMessage",
                    "text": text,
                    "phase": "final_answer",
                })],
                "completed",
            ),
        )
        .unwrap();
        assert!(parser.take_result_candidate().is_none());
        let correction = take_json(&mut parser);
        assert_eq!(correction["method"], "turn/start", "{text}");
        assert_eq!(correction["params"]["threadId"], THREAD_ID);
    }

    let mut duplicate = running_parser(AgentValueKind::Result, 1024);
    let mut items = Vec::new();
    for id in ["first", "second"] {
        feed(&mut duplicate, item_started(id, "agentMessage")).unwrap();
        let completed = item_completed(id, r#"{"result":"1"}"#, json!("final_answer"));
        items.push(completed["params"]["item"].clone());
        feed(&mut duplicate, completed).unwrap();
    }
    feed(&mut duplicate, turn_completed(items, "completed")).unwrap();
    assert!(duplicate.take_result_candidate().is_none());
    assert_eq!(take_json(&mut duplicate)["method"], "turn/start");

    let mut missing = running_parser(AgentValueKind::Result, 1024);
    let (progress, _) = feed(&mut missing, turn_completed(vec![], "completed")).unwrap();
    assert!(progress.close_standard_input);
    assert_eq!(
        missing.finish(true),
        AgentOutcome::Failed(AgentFailureCause::MissingResult.into()),
    );
}

// REQ-AGENT-31
// INV-HARNESS-7
#[test]
fn one_rejection_queues_one_same_thread_correction_then_exhausts() {
    let mut parser = running_parser(AgentValueKind::Result, 1024);
    for (id, value, turn_id) in [("first", -1, "turn-1"), ("second", 0, "turn-2")] {
        let text = result_envelope(json!(value));
        feed(
            &mut parser,
            json!({
                "method": "item/started",
                "params": {
                    "threadId": "thread-1",
                    "turnId": turn_id,
                    "item": {"id": id, "type": "agentMessage", "text": ""},
                },
            }),
        )
        .unwrap();
        feed(
            &mut parser,
            json!({
                "method": "item/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": turn_id,
                    "item": {"id": id, "type": "agentMessage", "text": text, "phase": "final_answer"},
                },
            }),
        )
        .unwrap();
        feed(
            &mut parser,
            json!({
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turn": {
                        "id": turn_id,
                        "items": [{
                            "id": id,
                            "type": "agentMessage",
                            "text": text,
                            "phase": "final_answer",
                        }],
                        "status": "completed",
                    },
                },
            }),
        )
        .unwrap();
        assert_eq!(
            parser.take_result_candidate().unwrap().as_ref(),
            &json!(value)
        );
        let progress = parser
            .reject_result(Arc::from("bounded authoritative feedback"))
            .unwrap();
        if id == "first" {
            assert!(!progress.close_standard_input);
            let correction = take_json(&mut parser);
            assert_eq!(correction["id"], 6);
            assert_eq!(correction["method"], "turn/start");
            assert_eq!(correction["params"]["threadId"], THREAD_ID);
            assert_eq!(
                correction["params"]["input"],
                json!([{"type": "text", "text": "bounded authoritative feedback"}]),
            );
            assert_eq!(correction["params"]["outputSchema"], weak_json_schema());
            feed(
                &mut parser,
                json!({"id": 6, "result": {"turn": {"id": "turn-2", "items": [], "status": "inProgress"}}}),
            )
            .unwrap();
            let (started, _) = feed(
                &mut parser,
                json!({
                    "method": "turn/started",
                    "params": {
                        "threadId": "thread-1",
                        "turn": {"id": "turn-2", "items": [], "status": "inProgress"},
                    },
                }),
            )
            .unwrap();
            assert!(!started.start_acknowledged);
        } else {
            assert!(progress.close_standard_input);
            assert_eq!(
                parser.finish(true),
                AgentOutcome::Failed(AgentFailureCause::MissingResult.into()),
            );
            break;
        }
    }
}

#[test]
fn schema_rejection_correction_identifies_the_inner_weak_envelope_value() {
    let mut parser = running_parser(AgentValueKind::Result, 1024);
    let invalid = json!({
        "schemaVersion": 1,
        "verdict": "fail",
        "findings": [{"message": "blocking"}],
    });
    let text = result_envelope(invalid.clone());
    feed(&mut parser, item_started("review", "agentMessage")).unwrap();
    feed(
        &mut parser,
        item_completed("review", &text, json!("final_answer")),
    )
    .unwrap();
    feed(
        &mut parser,
        turn_completed(
            vec![json!({
                "id": "review",
                "type": "agentMessage",
                "text": text,
                "phase": "final_answer",
            })],
            "completed",
        ),
    )
    .unwrap();
    assert_eq!(parser.take_result_candidate().unwrap().as_ref(), &invalid);

    parser
        .reject_result(Arc::from(
            "Result rejected by the workflow schema:\n1. instance /findings/0 violates `type` at schema /properties/findings/items/type\n2. instance $ violates `additionalProperties` at schema /additionalProperties\n",
        ))
        .unwrap();
    let correction = take_json(&mut parser);
    let feedback = correction["params"]["input"][0]["text"].as_str().unwrap();
    assert!(feedback.contains("inner workflow JSON"));
    assert!(feedback.contains("outer `result` string"));
    assert!(feedback.contains("/findings/0 violates `type`"));
    assert!(feedback.contains("violates `additionalProperties`"));
    assert!(feedback.len() <= 512);
}

#[test]
fn rejected_correction_turn_remains_a_post_start_protocol_failure() {
    let mut parser = running_parser(AgentValueKind::Result, 1024);
    let text = result_envelope(json!(-1));
    feed(&mut parser, item_started("first", "agentMessage")).unwrap();
    feed(
        &mut parser,
        item_completed("first", &text, json!("final_answer")),
    )
    .unwrap();
    feed(
        &mut parser,
        turn_completed(
            vec![json!({
                "id": "first", "type": "agentMessage", "text": text, "phase": "final_answer"
            })],
            "completed",
        ),
    )
    .unwrap();
    parser.take_result_candidate().unwrap();
    parser.reject_result(Arc::from("feedback")).unwrap();
    assert_eq!(take_json(&mut parser)["id"], 6);
    assert_eq!(
        feed(
            &mut parser,
            json!({"id": 6, "error": {"code": -32603, "message": "turn failed"}})
        )
        .unwrap_err(),
        AgentFailureCause::HarnessProtocolFailed
    );
    assert_eq!(
        parser.finish(false),
        AgentOutcome::Failed(AgentFailureCause::HarnessProtocolFailed.into())
    );
}

#[test]
fn malformed_oversized_truncated_and_correlation_inputs_are_bounded_by_phase() {
    let mut malformed = parser(AgentValueKind::None, 1024, None);
    assert_eq!(
        malformed.push_stdout(b"not-json\n", |_| {}).unwrap_err(),
        AgentFailureCause::HarnessSetupFailed {
            stage: AgentHarnessSetupStage::Initialization,
        }
    );

    let mut invalid_utf8 = parser(AgentValueKind::None, 1024, None);
    assert_eq!(
        invalid_utf8
            .push_stdout(&[0xff, b'\n'], |_| {})
            .unwrap_err(),
        AgentFailureCause::HarnessSetupFailed {
            stage: AgentHarnessSetupStage::Initialization,
        }
    );

    let limits = CodexAppServerV1ProtocolLimits::with_limits(
        NonZeroU64::new(8).unwrap(),
        NonZeroU64::new(64).unwrap(),
    );
    let mut oversized = parser(AgentValueKind::None, 8, None);
    oversized.limits = limits;
    assert_eq!(
        oversized.push_stdout(b"123456789", |_| {}).unwrap_err(),
        AgentFailureCause::HarnessSetupFailed {
            stage: AgentHarnessSetupStage::Initialization,
        }
    );

    let mut truncated = parser(AgentValueKind::None, 1024, None);
    truncated.push_stdout(b"{\"id\":1", |_| {}).unwrap();
    assert_eq!(
        truncated.finish(true),
        AgentOutcome::Failed(
            AgentFailureCause::HarnessSetupFailed {
                stage: AgentHarnessSetupStage::Initialization,
            }
            .into(),
        )
    );

    let mut correlation_limited = parser(AgentValueKind::None, 1024, None);
    correlation_limited.limits = CodexAppServerV1ProtocolLimits::with_limits(
        CodexAppServerV1ProtocolLimits::profile().maximum_frame_bytes(),
        NonZeroU64::new(7).unwrap(),
    );
    initialize(&mut correlation_limited);
    effective_config(&mut correlation_limited, "native-provider");
    assert_eq!(
        feed(
            &mut correlation_limited,
            json!({
                "id": 3,
                "result": {
                    "thread": {
                        "id": "thread-1",
                        "sessionId": "thread-1",
                        "ephemeral": true,
                        "path": null,
                        "cliVersion": "0.147.0",
                        "turns": [],
                        "cwd": "/synthetic/project",
                        "modelProvider": "native-provider",
                    },
                    "model": "scherzo-loopback",
                    "modelProvider": "native-provider",
                    "cwd": "/synthetic/project",
                    "approvalPolicy": "never",
                    "sandbox": {"type": "dangerFullAccess"},
                }
            })
        )
        .unwrap_err(),
        AgentFailureCause::HarnessSetupFailed {
            stage: AgentHarnessSetupStage::ThreadStart,
        }
    );

    assert_eq!(
        rejection_reason(&correlation_limited),
        "retained_correlation_limit_exceeded"
    );

    let mut diagnostic_limited = running_parser(AgentValueKind::None, 1024);
    diagnostic_limited.limits.maximum_retained_diagnostic_bytes = NonZeroU64::new(5).unwrap();
    let (_, observations) = feed(
        &mut diagnostic_limited,
        json!({"method": "warning", "params": {
            "threadId": "thread-1", "message": "123456"
        }}),
    )
    .unwrap();
    assert!(matches!(
        observations.as_slice(),
        [AgentObservation::Diagnostic { message, .. }] if message.as_ref() == "12345"
    ));
    for diagnostic in [
        json!({"method": "configWarning", "params": {"summary": "more"}}),
        json!({"method": "mcpServer/startupStatus/updated", "params": {
            "threadId": "thread-1", "name": "future", "status": "ready"
        }}),
    ] {
        let (_, observations) = feed(&mut diagnostic_limited, diagnostic).unwrap();
        assert!(observations.is_empty());
    }

    let mut unsafe_diagnostic = running_parser(AgentValueKind::None, 1024);
    let (_, observations) = feed(
        &mut unsafe_diagnostic,
        json!({"method": "warning", "params": {
            "threadId": "thread-1", "message": "unsafe\u{1b}diagnostic"
        }}),
    )
    .unwrap();
    assert!(matches!(
        observations.as_slice(),
        [AgentObservation::Diagnostic { message, .. }]
            if message.as_ref() == "unsafe\\u{1b}diagnostic"
    ));
}

#[test]
fn malformed_diagnostic_payloads_are_observed_without_failing() {
    for diagnostic in [
        json!({"method": "warning"}),
        json!({"method": "warning", "params": {
            "threadId": "thread-1", "message": {"future": true}
        }}),
        json!({"method": "configWarning", "params": {
            "summary": {"future": true}
        }}),
        json!({"method": "mcpServer/startupStatus/updated", "params": {
            "threadId": "thread-1", "name": "future", "status": {"future": true}
        }}),
    ] {
        let mut parser = running_parser(AgentValueKind::None, 1024);
        let (_, observations) = feed(&mut parser, diagnostic).unwrap();
        assert!(matches!(
            observations.as_slice(),
            [AgentObservation::UnrecognizedHarnessEvent { .. }]
        ));
    }

    let mut mismatch = running_parser(AgentValueKind::None, 1024);
    feed(
        &mut mismatch,
        json!({"method": "warning", "params": {
            "threadId": "other-thread", "message": "warning"
        }}),
    )
    .unwrap();
}

#[test]
fn frame_limit_is_enforced_while_reading_bytes() {
    let mut at_limit = parser_with_system_prompt(AgentValueKind::None, 1024, None, "system");
    at_limit.limits.maximum_frame_bytes = NonZeroU64::new(8).unwrap();
    at_limit.push_stdout(b"{}      ", drop).unwrap();
    assert!(at_limit.push_stdout(b"\n", drop).is_err());
    assert_ne!(
        at_limit.rejection_reason.get(),
        Some(CodexAppServerV1RejectionReason::FrameTooLarge)
    );

    let mut over_limit = parser_with_system_prompt(AgentValueKind::None, 1024, None, "system");
    over_limit.limits.maximum_frame_bytes = NonZeroU64::new(8).unwrap();
    assert!(over_limit.push_stdout(b"{}      X", drop).is_err());
    assert_eq!(
        over_limit.rejection_reason.get(),
        Some(CodexAppServerV1RejectionReason::FrameTooLarge)
    );
}

#[test]
fn protocol_rejections_identify_distinct_failure_conditions() {
    let mut malformed = parser(AgentValueKind::None, 1024, None);
    assert!(malformed.push_stdout(b"not-json\n", |_| {}).is_err());
    assert_eq!(rejection_reason(&malformed), "frame_decode_failed");

    let mut missing_thread = running_parser(AgentValueKind::None, 1024);
    let mut completed = turn_completed(vec![], "completed");
    completed["params"]
        .as_object_mut()
        .unwrap()
        .remove("threadId");
    assert!(feed(&mut missing_thread, completed).is_err());
    assert_eq!(
        rejection_reason(&missing_thread),
        "thread_correlation_invalid"
    );

    let mut malformed_request = running_parser(AgentValueKind::None, 1024);
    assert!(
        feed(
            &mut malformed_request,
            json!({
                "id": "request",
                "method": "item/commandExecution/requestApproval",
            })
        )
        .is_err()
    );
    assert_eq!(
        rejection_reason(&malformed_request),
        "server_request_envelope_invalid"
    );
}

#[test]
fn a_summary_without_a_streamed_message_has_no_authority() {
    let mut parser = running_parser(AgentValueKind::Result, 1024);
    let summary = json!({"id":"message", "type":"agentMessage", "text":result_envelope(json!(7)), "phase":"final_answer"});
    feed(
        &mut parser,
        turn_completed(vec![summary.clone(), summary], "completed"),
    )
    .unwrap();
    assert_eq!(
        parser.finish(true),
        AgentOutcome::Failed(AgentFailureCause::MissingResult.into())
    );
}

#[test]
fn completion_fallback_does_not_preempt_an_actual_adapter_failure() {
    let mut parser = running_parser(AgentValueKind::None, 1024);
    feed(&mut parser, turn_completed(Vec::new(), "completed")).unwrap();
    parser.prepare_completion_rejection();
    let _ = parser.failure_for(CodexAppServerV1RejectionReason::ProcessSettlementFailed);
    assert_eq!(rejection_reason(&parser), "process_settlement_failed");
}

#[test]
fn terminal_invariant_rejection_is_not_replaced_by_stale_parser_phase() {
    let mut parser = running_parser(AgentValueKind::None, 1024);
    assert!(matches!(parser.finish(true), AgentOutcome::Failed(_)));
    parser.prepare_completion_rejection();
    assert_eq!(rejection_reason(&parser), "terminal_invariant_invalid");
}

#[test]
fn completed_terminal_before_start_acknowledgement_fails_closed() {
    let mut parser = parser(AgentValueKind::None, 1024, None);
    initialize(&mut parser);
    effective_config(&mut parser, "native-provider");
    thread_response(&mut parser, "native-provider");
    turn_response(&mut parser);

    let _ = feed(&mut parser, turn_completed(vec![], "completed"));
    let outcome = parser.finish(true);
    assert!(
        matches!(outcome, AgentOutcome::Failed(_)),
        "completion before the authoritative turn/started boundary must fail closed: {outcome:?}",
    );
}

// INV-HARNESS-5
#[test]
fn nonretry_native_error_cannot_be_erased_by_completed_terminal() {
    let mut parser = running_parser(AgentValueKind::Response, 1024);
    feed(&mut parser, item_started("final", "agentMessage")).unwrap();
    let final_item = json!({
        "id": "final",
        "type": "agentMessage",
        "text": "must not commit",
        "phase": "final_answer",
    });
    feed(
        &mut parser,
        item_completed("final", "must not commit", json!("final_answer")),
    )
    .unwrap();
    feed(
        &mut parser,
        json!({"method": "error", "params": {
            "threadId": "thread-1",
            "turnId": "turn-1",
            "error": {"message": "native failure", "codexErrorInfo": "unauthorized"},
            "willRetry": false,
        }}),
    )
    .unwrap();

    let _ = feed(&mut parser, turn_completed(vec![final_item], "completed"));
    let outcome = parser.finish(true);
    assert!(
        matches!(outcome, AgentOutcome::Failed(_)),
        "a non-retryable native failure must survive a contradictory completed terminal: {outcome:?}",
    );
}

#[test]
fn bounded_native_error_prose_does_not_replace_structured_identity() {
    let mut parser = running_parser(AgentValueKind::None, 1024);
    parser.limits.maximum_retained_diagnostic_bytes = NonZeroU64::new(5).unwrap();
    let native_error = feed(
        &mut parser,
        json!({"method": "error", "params": {
            "threadId": "thread-1",
            "turnId": "turn-1",
            "error": {"message": "123456", "codexErrorInfo": "unauthorized"},
            "willRetry": false,
        }}),
    );
    assert!(
        native_error.is_ok(),
        "bounded diagnostic prose must not replace codexErrorInfo identity: {native_error:?}",
    );
    feed(
        &mut parser,
        json!({"method": "turn/completed", "params": {
            "threadId": "thread-1",
            "turn": {
                "id": "turn-1",
                "items": [],
                "status": "failed",
                "error": {"message": "x", "codexErrorInfo": "unauthorized"},
            },
        }}),
    )
    .unwrap();
    assert_eq!(
        parser.finish(true),
        AgentOutcome::Failed(
            AgentFailureCause::HarnessFailed {
                detail: AgentHarnessFailureDetail::Classified {
                    canonical: CanonicalHarnessFailure::ModelError,
                    diagnostic: HarnessFailureDiagnostic::from_code("unauthorized", None),
                },
            }
            .into(),
        ),
    );
}

// REQ-DIAG-24, REQ-DIAG-36, REQ-AGENT-45, REQ-AGENT-70
#[test]
fn structured_codex_failures_project_safe_runner_diagnostics() {
    use crate::workflow::evidence::{FailurePhase, failure_detail};
    use crate::workflow::step_runtime::{StepExecutionFailure, StepFailureCause};

    for (info, expected) in [
        (
            json!("contextWindowExceeded"),
            json!({"harnessError": "context_window_exceeded", "harnessFailure": "model_error"}),
        ),
        (
            json!("usageLimitExceeded"),
            json!({"harnessError": "usage_limit_exceeded", "harnessFailure": "model_error"}),
        ),
        (
            json!("rateLimitExceeded"),
            json!({"harnessError": "rate_limited", "harnessFailure": "model_error"}),
        ),
        (
            json!("modelNotFound"),
            json!({"harnessError": "bad_request", "harnessFailure": "model_error"}),
        ),
        (
            json!("inferenceHookDenied"),
            json!({"harnessError": "other", "harnessFailure": "model_error"}),
        ),
        (
            json!("unauthorized"),
            json!({"harnessError": "unauthorized", "harnessFailure": "model_error"}),
        ),
        (
            json!("serverOverloaded"),
            json!({"harnessError": "overloaded", "harnessFailure": "model_error"}),
        ),
        (
            json!({"responseStreamDisconnected": {"httpStatusCode": 503}}),
            json!({
                "harnessError": "stream_disconnected",
                "harnessFailure": "model_output_truncated",
                "httpStatus": 503
            }),
        ),
        (
            json!("flexUnavailable"),
            json!({"harnessError": "other", "harnessFailure": "model_error"}),
        ),
    ] {
        let mut parser = running_parser(AgentValueKind::None, 1024);
        feed(
            &mut parser,
            json!({"method": "turn/completed", "params": {
                "threadId": "thread-1",
                "turn": {"id": "turn-1", "items": [], "status": "failed",
                    "error": {"message": "private sentinel /path token", "codexErrorInfo": info}},
            }}),
        )
        .unwrap();
        let AgentOutcome::Failed(failure) = parser.finish(true) else {
            panic!("expected harness failure");
        };
        let detail = failure_detail(
            FailurePhase::Execution,
            &StepFailureCause::Execution(StepExecutionFailure::Agent(failure)),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&detail).unwrap()["code"],
            "harness_failed"
        );
        assert_eq!(detail.runner_diagnostic(), Some(expected));
        assert!(
            !serde_json::to_string(&detail.runner_diagnostic())
                .unwrap()
                .contains("sentinel")
        );
        assert!(
            serde_json::to_value(&detail)
                .unwrap()
                .get("diagnostic")
                .is_none()
        );
    }
}

#[test]
fn flex_unavailable_preserves_native_failure_and_retry_correlation() {
    for notify in [false, true] {
        let mut parser = running_parser(AgentValueKind::None, 1024);
        if notify {
            let (_, observations) = feed(
                &mut parser,
                json!({"method": "error", "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "error": {"message": "capacity diagnostic", "codexErrorInfo": "flexUnavailable"},
                    "willRetry": false,
                }}),
            )
            .unwrap();
            assert!(matches!(observations.as_slice(),
                [AgentObservation::Diagnostic { level: AgentDiagnosticLevel::Error, message }]
                    if message.as_ref() == "capacity diagnostic"));
        }
        feed(
            &mut parser,
            json!({"method": "turn/completed", "params": {
                "threadId": "thread-1",
                "turn": {
                    "id": "turn-1",
                    "items": [],
                    "status": "failed",
                    "error": {"message": "terminal diagnostic", "codexErrorInfo": "flexUnavailable"},
                },
            }}),
        )
        .unwrap();
        assert_eq!(
            parser.finish(true),
            AgentOutcome::Failed(
                AgentFailureCause::HarnessFailed {
                    detail: AgentHarnessFailureDetail::Classified {
                        canonical: CanonicalHarnessFailure::ModelError,
                        diagnostic: HarnessFailureDiagnostic::from_code("other", None),
                    },
                }
                .into()
            ),
        );
    }

    let mut parser = running_parser(AgentValueKind::None, 1024);
    let (_, observations) = feed(
        &mut parser,
        json!({"method": "error", "params": {
            "threadId": "thread-1",
            "turnId": "turn-1",
            "error": {"message": "capacity diagnostic", "codexErrorInfo": "flexUnavailable"},
            "willRetry": true,
        }}),
    )
    .unwrap();
    assert!(observations.iter().any(|observation| matches!(
        observation,
        AgentObservation::Lifecycle {
            milestone: AgentLifecycleMilestone::RetryStarted
        }
    )));
    let (_, observations) = feed(&mut parser, turn_completed(vec![], "completed")).unwrap();
    assert!(observations.iter().any(|observation| matches!(
        observation,
        AgentObservation::Lifecycle {
            milestone: AgentLifecycleMilestone::RetryCompleted
        }
    )));
    assert_eq!(
        parser.finish(true),
        AgentOutcome::Completed(CompletedAgentInvocation::NoValue)
    );
}

// REQ-AGENT-25, REQ-AGENT-90
// INV-HARNESS-6
#[test]
fn server_requests_are_answered_whatever_they_name() {
    let mut parser = running_parser(AgentValueKind::None, 1024);
    let params = json!({"threadId": THREAD_ID, "turnId": "other-turn", "itemId": "unseen",
        "futureField": {"nested": true}});
    // Codex's input is closed once the invocation is terminal: a request is recorded,
    // gets no answer and leaves the outcome alone.
    let mut closed = parser.clone();
    feed(&mut closed, turn_completed(vec![], "completed")).unwrap();
    for (id, method) in [(13, "item/tool/requestUserInput"), (14, "future/request")] {
        let (_, observations) = feed(
            &mut closed,
            json!({"id": id, "method": method, "params": params}),
        )
        .unwrap();
        assert!(matches!(
            observations.as_slice(),
            [AgentObservation::UnrecognizedHarnessEvent { .. }]
        ));
        assert!(closed.take_outbound().is_none());
    }
    assert_eq!(
        closed.finish(true),
        AgentOutcome::Completed(CompletedAgentInvocation::NoValue)
    );
    for (method, expected) in [
        (
            "item/commandExecution/requestApproval",
            json!({"decision": "decline"}),
        ),
        (
            "item/fileChange/requestApproval",
            json!({"decision": "decline"}),
        ),
        (
            "item/permissions/requestApproval",
            json!({"permissions": {}}),
        ),
        ("item/tool/requestUserInput", json!({"answers": {}})),
        (
            "mcpServer/elicitation/request",
            json!({"action": "decline"}),
        ),
    ] {
        let (_, observations) = feed(
            &mut parser,
            json!({"id": method, "method": method, "params": params}),
        )
        .unwrap();
        assert!(matches!(
            observations.as_slice(),
            [AgentObservation::UnrecognizedHarnessEvent { .. }]
        ));
        assert_eq!(
            take_json(&mut parser),
            json!({"id": method, "result": expected})
        );
    }
    let unknown = json!({"id": 12, "method": "future/request", "params": params});
    feed(&mut parser, unknown.clone()).unwrap();
    assert_eq!(take_json(&mut parser)["error"]["code"], -32601);
    assert_eq!(
        feed(&mut parser, unknown).unwrap_err(),
        AgentFailureCause::HarnessProtocolFailed
    );
    assert_eq!(rejection_reason(&parser), "server_request_repeated");
}

#[test]
fn mcp_elicitation_with_explicit_null_turn_id_is_declined() {
    let mut parser = running_parser(AgentValueKind::None, 1024);
    let (_, observations) = feed(
        &mut parser,
        json!({
            "id": "standalone-mcp-request",
            "method": "mcpServer/elicitation/request",
            "params": {
                "threadId": "thread-1",
                "turnId": null,
                "itemId": "other-item",
                "serverName": "fixture-mcp",
                "mode": "form",
                "message": "Provide structured input",
                "requestedSchema": {
                    "type": "object",
                    "properties": {"choice": {"type": "string"}},
                },
            },
        }),
    )
    .expect("schema-valid standalone elicitation should be declined");
    assert!(matches!(
        observations.as_slice(),
        [AgentObservation::UnrecognizedHarnessEvent { .. }]
    ));
    assert_eq!(
        take_json(&mut parser),
        json!({
            "id": "standalone-mcp-request",
            "result": {"action": "decline"},
        }),
    );
}

// REQ-AGENT-38, INV-HARNESS-28
#[test]
fn each_method_useful_cannot_show_is_recorded_once() {
    fn records(parser: &mut CodexAppServerV1Parser, frame: Value) -> Vec<Value> {
        let (progress, observations) = feed(parser, frame).unwrap();
        assert_eq!(progress, ParserProgress::default());
        observations
            .into_iter()
            .map(|event| match event {
                AgentObservation::UnrecognizedHarnessEvent { event } => (*event).clone(),
                other => panic!("unexpected lead activity: {other:?}"),
            })
            .collect()
    }

    let mut parser = running_parser(AgentValueKind::None, 1024);
    let mut delta = json!({"method": "item/agentMessage/delta", "params": {
        "threadId": "builder", "turnId": "builder-turn", "itemId": "message", "delta": "first"
    }});
    let first = delta.clone();
    let mut observed = records(&mut parser, first.clone());
    delta["params"]["delta"] = json!("later");
    for _ in 1..100 {
        observed.extend(records(&mut parser, delta.clone()));
    }
    let completed = json!({"method": "turn/completed", "params": {
        "threadId": "builder", "turn": {"id": "builder-turn", "status": "completed"}
    }});
    observed.extend(records(&mut parser, completed.clone()));
    let status = json!({"method": "thread/status/changed", "params": {"threadId": THREAD_ID}});
    for _ in 0..2 {
        observed.extend(records(&mut parser, status.clone()));
    }
    assert_eq!(observed, [first, completed, status]);

    let mut bounded = running_parser(AgentValueKind::None, 1024);
    let methods = (0..70).map(|n| json!({"method": format!("future/{n}")}));
    let expected: Vec<_> = methods.clone().take(65).collect();
    let observed: Vec<_> = methods
        .flat_map(|frame| records(&mut bounded, frame))
        .collect();
    assert_eq!(observed, expected);
    for id in [7, 8] {
        let request = json!({"id": id, "method": "future/0"});
        assert_eq!(records(&mut bounded, request.clone()), [request]);
        assert_eq!(take_json(&mut bounded)["error"]["code"], -32601);
    }

    let mut invalid = running_parser(AgentValueKind::None, 1024);
    let long = json!({"method": "m".repeat(65)});
    assert_eq!(records(&mut invalid, long.clone()), [long]);
    assert!(records(&mut invalid, json!({"method": "invalid method"})).is_empty());
    let valid = json!({"method": "m".repeat(64)});
    assert_eq!(records(&mut invalid, valid.clone()), [valid]);
}

// REQ-AGENT-38
#[test]
fn unknown_notifications_and_requests_are_observed_without_settling() {
    let mut parser = running_parser(AgentValueKind::None, 1024);
    feed(&mut parser, item_started("active", "reasoning")).unwrap();
    for event in [
        json!({
            "method": "future/notification",
            "params": {
                "threadId": "thread-1",
                "turnId": "turn-1",
                "itemId": "active",
                "futureField": true,
            },
            "futureEnvelopeField": true,
        }),
        json!({
            "id": "future-request",
            "method": "future/request",
            "params": {"threadId": "thread-1", "turnId": "turn-1"},
        }),
    ] {
        let (_, observations) = feed(&mut parser, event).unwrap();
        assert!(matches!(
            observations.as_slice(),
            [AgentObservation::UnrecognizedHarnessEvent { .. }]
        ));
    }
    assert_eq!(
        take_json(&mut parser),
        json!({
            "id": "future-request",
            "error": {"code": -32601, "message": "Method not found"},
        }),
    );
}

#[test]
fn method_only_unknown_notifications_and_requests_are_observed() {
    for (event, response) in [
        (json!({"method": "future/notification"}), None),
        (
            json!({"id": "future-request", "method": "future/request"}),
            Some(json!({
                "id": "future-request",
                "error": {"code": -32601, "message": "Method not found"},
            })),
        ),
    ] {
        let mut parser = running_parser(AgentValueKind::None, 1024);
        let (_, observations) = feed(&mut parser, event).unwrap();
        assert!(matches!(
            observations.as_slice(),
            [AgentObservation::UnrecognizedHarnessEvent { .. }]
        ));
        if let Some(response) = response {
            assert_eq!(take_json(&mut parser), response);
        }
    }
}

#[test]
fn root_project_updates_remain_fatal_and_elicitation_is_declined() {
    for mismatch in [
        json!({"turnId": "other-turn"}),
        json!({"itemId": "other-item"}),
    ] {
        let mut params = mismatch;
        params["threadId"] = json!(THREAD_ID);
        params["projectId"] = json!("project-1");
        let mut parser = running_parser(AgentValueKind::None, 1024);
        assert_eq!(
            feed(
                &mut parser,
                json!({"method": "thread/project/updated", "params": params})
            )
            .unwrap_err(),
            AgentFailureCause::HarnessProtocolFailed
        );
    }
    let mut parser = running_parser(AgentValueKind::None, 1024);
    feed(
        &mut parser,
        json!({"id": "mcp-request", "method": "mcpServer/elicitation/request",
        "params": {"threadId": THREAD_ID, "turnId": "turn-1", "itemId": "other-item"}}),
    )
    .unwrap();
    assert_eq!(
        take_json(&mut parser)["result"],
        json!({"action": "decline"})
    );
}

#[test]
fn active_turn_subtype_is_part_of_correlated_error_identity() {
    let mut parser = running_parser(AgentValueKind::None, 1024);
    feed(
        &mut parser,
        json!({"method": "error", "params": {
            "threadId": "thread-1",
            "turnId": "turn-1",
            "error": {"message": "native", "codexErrorInfo": {
                "activeTurnNotSteerable": {"turnKind": "review"}
            }},
            "willRetry": false,
        }}),
    )
    .unwrap();
    assert_eq!(
        feed(
            &mut parser,
            json!({"method": "turn/completed", "params": {
                "threadId": "thread-1",
                "turn": {
                    "id": "turn-1",
                    "items": [],
                    "status": "failed",
                    "error": {"message": "terminal", "codexErrorInfo": {
                        "activeTurnNotSteerable": {"turnKind": "compact"}
                    }},
                },
            }}),
        )
        .unwrap_err(),
        AgentFailureCause::HarnessProtocolFailed,
    );
}

#[test]
fn retry_exhaustion_requires_a_retrying_native_observation() {
    let mut parser = running_parser(AgentValueKind::None, 1024);
    feed(
        &mut parser,
        json!({"method": "error", "params": {
            "threadId": "thread-1",
            "turnId": "turn-1",
            "error": {"message": "native", "codexErrorInfo": "unauthorized"},
            "willRetry": false,
        }}),
    )
    .unwrap();
    assert_eq!(
        feed(
            &mut parser,
            json!({"method": "turn/completed", "params": {
                "threadId": "thread-1",
                "turn": {
                    "id": "turn-1",
                    "items": [],
                    "status": "failed",
                    "error": {"message": "terminal", "codexErrorInfo": {
                        "responseTooManyFailedAttempts": {}
                    }},
                },
            }}),
        )
        .unwrap_err(),
        AgentFailureCause::HarnessProtocolFailed,
    );
}

#[test]
fn pending_server_responses_are_aggregate_bounded() {
    let mut parser = running_parser(AgentValueKind::None, 1024);
    parser.limits.maximum_frame_bytes = NonZeroU64::new(1024).unwrap();
    feed(&mut parser, item_started("command", "commandExecution")).unwrap();
    let mut requests = Vec::new();
    for id in 0..40 {
        serde_json::to_writer(
            &mut requests,
            &json!({
                "id": id,
                "method": "item/commandExecution/requestApproval",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "itemId": "command",
                    "startedAtMs": 1,
                },
            }),
        )
        .unwrap();
        requests.push(b'\n');
    }
    assert_eq!(
        parser.push_stdout(&requests, |_| {}).unwrap_err(),
        AgentFailureCause::HarnessProtocolFailed,
    );
}

#[test]
fn contradictory_native_and_terminal_error_identity_fails_closed() {
    let mut parser = running_parser(AgentValueKind::Response, 1024);
    feed(
        &mut parser,
        json!({"method": "error", "params": {
            "threadId": "thread-1",
            "turnId": "turn-1",
            "error": {"message": "diagnostic one", "codexErrorInfo": "unauthorized"},
            "willRetry": false,
        }}),
    )
    .unwrap();
    assert_eq!(
        feed(
            &mut parser,
            json!({"method": "turn/completed", "params": {
                "threadId": "thread-1",
                "turn": {
                    "id": "turn-1",
                    "items": [],
                    "status": "failed",
                    "error": {"message": "diagnostic two", "codexErrorInfo": "badRequest"},
                },
            }}),
        )
        .unwrap_err(),
        AgentFailureCause::HarnessProtocolFailed,
    );
    assert_eq!(
        parser.finish(true),
        AgentOutcome::Failed(AgentFailureCause::HarnessProtocolFailed.into()),
    );
}

// REQ-AGENT-91, REQ-AGENT-26, REQ-AGENT-31
#[test]
fn the_leads_result_is_the_same_with_or_without_progress_noise() {
    let noise = progress_noise("thread-1", "turn-1");
    for kind in [AgentValueKind::Result, AgentValueKind::Response] {
        check_noisy_turn(kind, &[], false);
        for frames in &noise {
            check_noisy_turn(kind, frames, false);
        }
        check_noisy_turn(kind, &[], true);
        check_noisy_turn(kind, &noise.concat(), true);
    }
}

pub(super) fn progress_noise(thread: &str, turn: &str) -> Vec<Vec<Value>> {
    let frame = |method: &str, mut params: Value| {
        params["threadId"] = json!(thread);
        params["turnId"] = json!(turn);
        json!({"method": method, "params": params})
    };
    let delta = json!({"itemId":"unannounced", "delta":"progress"});
    let mut other_turn = frame("item/agentMessage/delta", delta.clone());
    other_turn["params"]["turnId"] = json!("another-turn");
    let command = frame(
        "item/started",
        json!({"item":{"id":"open", "type":"commandExecution"}}),
    );
    vec![
        vec![frame("thread/tokenUsage/updated", json!({"tokenUsage":{}}))],
        vec![frame("item/agentMessage/delta", delta.clone())],
        vec![frame("item/reasoning/textDelta", delta)],
        vec![other_turn],
        vec![frame(
            "hook/started",
            json!({"run":{"id":"unfinished", "eventName":"Stop"}}),
        )],
        vec![command.clone()],
        vec![frame(
            "item/completed",
            json!({"item":{"id":"orphan","type":"commandExecution","status":"completed"}}),
        )],
        vec![frame(
            "item/completed",
            json!({"item":{"id":"surprise","type":"commandExecution","status":"future"}}),
        )],
        vec![command.clone(), command],
        vec![frame(
            "thread/realtime/item/completed",
            json!({"sessionId":"s", "itemId":"unseen"}),
        )],
        // A completion that is not an assistant message decides nothing, whatever it omits.
        ["/params/threadId", "/params/turnId", "/params/item/id"]
            .into_iter()
            .map(|omitted| {
                let mut completion = frame(
                    "item/completed",
                    json!({"item":{"id":"partial","type":"commandExecution","status":"completed"}}),
                );
                let (parent, key) = omitted.rsplit_once('/').unwrap();
                let fields = completion.pointer_mut(parent).unwrap();
                fields.as_object_mut().unwrap().remove(key);
                completion
            })
            .collect(),
    ]
}

fn check_noisy_turn(kind: AgentValueKind, noise: &[Value], noisy_summary: bool) {
    let mut parser = running_parser(kind, 1024);
    for frame in noise {
        feed(&mut parser, frame.clone()).unwrap();
    }
    let text = result_envelope(json!(7));
    let message = item_completed("lead", &text, json!("final_answer"));
    feed(&mut parser, item_started("lead", "agentMessage")).unwrap();
    feed(&mut parser, message.clone()).unwrap();
    let mut terminal = turn_completed(vec![message["params"]["item"].clone()], "completed");
    if noisy_summary {
        terminal["params"]["turn"]["items"] = json!([{"id":"unseen","type":"future"}]);
        terminal["params"]["turn"]["itemsView"] = json!("future");
    }
    feed(&mut parser, terminal).unwrap();
    if kind == AgentValueKind::Result {
        let candidate = parser.take_result_candidate().unwrap();
        assert_eq!(*candidate, json!(7));
        let result = CapturedJson::fixture(candidate);
        parser.accept_result(result.clone()).unwrap();
        assert_eq!(
            parser.finish(true),
            AgentOutcome::Completed(CompletedAgentInvocation::Result(result))
        );
    } else {
        let AgentOutcome::Completed(CompletedAgentInvocation::Response(response)) =
            parser.finish(true)
        else {
            panic!("expected a response");
        };
        assert_eq!(response.as_str(), text);
    }
}

// REQ-AGENT-91, INV-HARNESS-27
#[test]
fn deciding_notifications_on_the_leads_thread_are_read_strictly() {
    let message = item_completed("lead", &result_envelope(json!(7)), json!("final_answer"));
    let terminal = turn_completed(vec![], "completed");
    let error = json!({"method":"error","params":{"threadId":"thread-1","turnId":"turn-1","willRetry":false,"error":{"message":"failed"}}});
    let started =
        json!({"method":"turn/started","params":{"threadId":"thread-1","turn":{"id":"turn-1"}}});
    for (frame, pointer) in [
        (&message, "/params/turnId"),
        (&error, "/params/turnId"),
        (&terminal, "/params/turn/id"),
        (&started, "/params/turn/id"),
    ] {
        for turn in [Value::Null, json!("unexpected")] {
            let mut parser = running_parser(AgentValueKind::Result, 1024);
            let mut invalid = frame.clone();
            *invalid.pointer_mut(pointer).unwrap() = turn;
            feed(&mut parser, invalid).unwrap_err();
            assert_eq!(rejection_reason(&parser), "turn_correlation_invalid");
        }
    }
    for (field, invalid) in [("text", json!(7)), ("phase", json!("future"))] {
        let mut parser = running_parser(AgentValueKind::Result, 1024);
        let mut unreadable = message.clone();
        unreadable["params"]["item"][field] = invalid;
        feed(&mut parser, unreadable).unwrap_err();
        assert_eq!(rejection_reason(&parser), "message_invalid");
    }
    // A completion whose type cannot be read may be the lead's message, and a message
    // needs its id.
    for field in ["type", "id"] {
        let mut parser = running_parser(AgentValueKind::Result, 1024);
        let mut unreadable = message.clone();
        unreadable["params"]["item"][field] = json!(7);
        feed(&mut parser, unreadable).unwrap_err();
        assert_eq!(rejection_reason(&parser), "item_correlation_invalid");
    }
    let mut parser = running_parser(AgentValueKind::Result, 1024);
    feed(&mut parser, message.clone()).unwrap();
    feed(&mut parser, terminal.clone()).unwrap();
    for frame in [&terminal, &error, &message] {
        feed(&mut parser, frame.clone()).unwrap();
        assert_eq!(parser.native_terminal, Some(NativeTerminal::Completed));
        assert_eq!(parser.pending_result_candidate.as_deref(), Some(&json!(7)));
    }
    parser.take_result_candidate().unwrap();
    parser.reject_result(Arc::from("try again")).unwrap();
    for frame in [terminal, error, message] {
        feed(&mut parser, frame).unwrap();
        assert_eq!(parser.state, SetupState::TurnStart);
        assert!(parser.native_terminal.is_none());
        assert!(parser.pending_result_candidate.is_none());
    }
}

// INV-HARNESS-27, REQ-AGENT-91
#[test]
fn a_long_lead_turn_exhausts_no_budget() {
    let mut parser = running_parser(AgentValueKind::Result, 1024);
    parser.limits = CodexAppServerV1ProtocolLimits::with_limits(
        NonZeroU64::new(2048).unwrap(),
        NonZeroU64::new(256).unwrap(),
    );
    for index in 0..1000 {
        let id = format!("command-{index}");
        feed(&mut parser, item_started(&id, "commandExecution")).unwrap();
        feed(&mut parser, json!({"method":"item/completed","params":{"threadId":"thread-1","turnId":"turn-1","item":{"id":id,"type":"commandExecution","status":"completed"}}})).unwrap();
        for method in ["hook/started", "hook/completed"] {
            feed(&mut parser, json!({"method":method,"params":{"threadId":"thread-1","turnId":"turn-1","run":{"id":format!("hook-{index}"),"eventName":"Stop","status":"completed"}}})).unwrap();
        }
        let id = format!("commentary-{index}");
        feed(&mut parser, item_started(&id, "agentMessage")).unwrap();
        feed(
            &mut parser,
            item_completed(&id, "working", json!("commentary")),
        )
        .unwrap();
    }
    feed(
        &mut parser,
        item_completed("final", &result_envelope(json!(7)), json!("final_answer")),
    )
    .unwrap();
    feed(&mut parser, turn_completed(vec![], "completed")).unwrap();
    assert_eq!(parser.take_result_candidate().as_deref(), Some(&json!(7)));
}
