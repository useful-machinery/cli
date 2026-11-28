use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Arc;

use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::*;
use crate::workflow::admission::CancellationReason;
use crate::workflow::admission::{ResolvedInput, ResolvedInputs};
use crate::workflow::local_run::LocalRunDirectoryError;
use crate::workflow::runtime::{ChildInterruption, EnteredWait};
use crate::{AttemptControls, ContinuationReasonV1, replayed_nested_wait};

const RUN: &str = "run_01jcf9a4r7t2m8k3v6x1z5n0pq";
const OTHER_RUN: &str = "run_01jcfa3m6p9q2r5s8t1v4w7x0y";
const SINCE: &str = "2026-11-07T21:41:58Z";

fn validator(schema: &str) -> jsonschema::Validator {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas")
        .join(schema);
    let schema = serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap();
    jsonschema::draft202012::new(&schema).unwrap()
}

fn assert_valid(validator: &jsonschema::Validator, document: &Value) {
    assert!(
        validator.is_valid(document),
        "{document}: {:?}",
        validator.iter_errors(document).collect::<Vec<_>>()
    );
}

fn since() -> OffsetDateTime {
    OffsetDateTime::parse(SINCE, &Rfc3339).unwrap()
}

fn entered(kind: WaitKind, step: &str, then: &str, on_hand_back: Option<&str>) -> EnteredWait {
    EnteredWait {
        step: step.to_owned(),
        outcome: (kind != WaitKind::Stop).then(|| "blocked".to_owned()),
        kind,
        runner: crate::workflow::document::WaitRunner::Keep,
        then: then.to_owned(),
        on_hand_back: on_hand_back.map(str::to_owned),
        rule: None,
        interrupted: None,
        kept: None,
        counted: false,
    }
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn control(event: &str, run: &str, wait: Option<&str>, payload: Option<Value>) -> ControlEvent {
    ControlEvent {
        source: "um".to_owned(),
        event: event.to_owned(),
        run: run.to_owned(),
        by: "saeed".to_owned(),
        at: "2026-11-07T22:00:00Z".to_owned(),
        wait: wait.map(str::to_owned),
        payload: payload.map(object),
    }
}

fn record(kind: WaitKind, step: &str, then: &str, on_hand_back: Option<&str>) -> WaitRecord {
    WaitRecord::entered(
        &entered(kind, step, then, on_hand_back),
        None,
        Map::new(),
        since(),
        &ResolvedInputs::default(),
        &BTreeMap::new(),
    )
    .unwrap()
}

#[test]
fn a_carried_wait_records_a_distinct_nested_continuation_step() {
    let prefix = [json!("part"), json!({"item": 2})];
    let nested = record(WaitKind::Answer, "review", "review", None);
    let same_step = WaitRecord::carried(&nested, &prefix, "part", None).unwrap();
    assert_eq!(same_step.nested_then, None);
    let previous = r#"{"kind":"answer","since":"2026-11-07T21:41:58Z","step":["part",{"item":2},"review"],"then":"part","rule":{"source":"um","event":["control.answer"],"where":"event.run == run.id and event.wait == wait.id and event.payload.complete == true"},"payload":{}}"#;
    assert_eq!(serde_json::to_string(&same_step).unwrap(), previous);

    let nested = record(WaitKind::Answer, "review", "fix", None);
    let other_step = WaitRecord::carried(&nested, &prefix, "part", None).unwrap();
    assert_eq!(other_step.nested_then.as_deref(), Some("fix"));
    let document = serde_json::to_value(&other_step).unwrap();
    assert_eq!(document["nestedThen"], "fix");
    assert!(other_step.is_valid());
    assert_valid(&validator("workflow-run-wait-v1.schema.json"), &document);
}

#[test]
fn a_nested_continuation_target_must_be_a_distinct_step_of_a_carried_wait() {
    let nested = record(WaitKind::Answer, "review", "fix", None);
    let carried = WaitRecord::carried(&nested, &[json!("part")], "part", None).unwrap();
    for (record, target) in [
        (carried.clone(), "exit.failed"),
        (carried, "review"),
        (nested, "fix"),
    ] {
        let mut document = serde_json::to_value(record).unwrap();
        document["nestedThen"] = json!(target);
        let invalid = serde_json::from_value::<WaitRecord>(document).unwrap();
        assert!(!invalid.is_valid(), "{invalid:?}");
    }
}

#[test]
fn release_matches_the_steps_that_require_the_execution_root() {
    let previous = r#"{"kind":"repair","since":"2026-11-07T21:41:58Z","step":["build"],"then":"build","rule":{"source":"um","event":["control.retry","control.withdraw"],"where":"event.run == run.id and event.wait == wait.id"},"payload":{}}"#;
    let record: WaitRecord = serde_json::from_str(previous).unwrap();
    assert!(record.is_valid());
    assert_eq!(serde_json::to_string(&record).unwrap(), previous);
    for release in [
        json!({"permitted": true, "executionRootSteps": [{"id": "build"}]}),
        json!({"permitted": false}),
    ] {
        let mut value: Value = serde_json::from_str(previous).unwrap();
        value["release"] = release;
        assert!(
            !serde_json::from_value::<WaitRecord>(value)
                .unwrap()
                .is_valid()
        );
    }
}

#[test]
fn an_entered_wait_derives_its_rule_from_the_kind_and_writes_the_published_record() {
    let validator = validator("workflow-run-wait-v1.schema.json");
    let correlated = "event.run == run.id and event.wait == wait.id";
    for (kind, name, step, then, on_hand_back, events, where_) in [
        (
            WaitKind::Answer,
            "answer",
            "design",
            "design",
            None,
            json!(["control.answer"]),
            "event.run == run.id and event.wait == wait.id and event.payload.complete == true",
        ),
        (
            WaitKind::Approval,
            "approval",
            "review",
            "merge",
            Some("fix"),
            json!(["control.approve", "control.hand_back"]),
            correlated,
        ),
        (
            WaitKind::Repair,
            "repair",
            "build",
            "build",
            None,
            json!(["control.retry", "control.withdraw"]),
            correlated,
        ),
        (
            WaitKind::Stop,
            "stop",
            "merge",
            "merge",
            None,
            json!(["control.lift"]),
            "event.run == run.id and event.payload.before == wait.then and event.payload.stop == wait.payload.at",
        ),
    ] {
        let payload = object(json!({"outcome": "blocked", "child": "children/design/000001"}));
        let record = WaitRecord::entered(
            &entered(kind, step, then, on_hand_back),
            None,
            payload.clone(),
            since(),
            &ResolvedInputs::default(),
            &BTreeMap::new(),
        )
        .unwrap();
        let document = serde_json::to_value(&record).unwrap();
        assert_valid(&validator, &document);
        let mut expected = json!({
            "kind": name,
            "since": SINCE,
            "step": [step],
            "then": then,
            "rule": {"source": "um", "event": events, "where": where_},
            "payload": payload,
        });
        if let Some(on_hand_back) = on_hand_back {
            expected["onHandBack"] = json!(on_hand_back);
        }
        assert_eq!(document, expected, "{name}");
        assert_eq!(record.id(), format!("{name}@{SINCE}"));
        assert!(record.is_valid());
        let parsed = serde_json::from_value::<WaitRecord>(document).unwrap();
        assert_eq!(parsed, record);
    }
}

#[test]
fn a_wait_entered_at_a_fan_out_element_names_the_element_in_its_step() {
    let validator = validator("workflow-run-wait-v1.schema.json");
    for (item, step, path) in [
        (Some(2), json!(["build", {"item": 2}]), "build[2]"),
        (None, json!(["build"]), "build"),
    ] {
        let record = WaitRecord::entered(
            &entered(WaitKind::Answer, "build", "build", None),
            item,
            Map::new(),
            since(),
            &ResolvedInputs::default(),
            &BTreeMap::new(),
        )
        .unwrap();
        let document = serde_json::to_value(&record).unwrap();
        assert_valid(&validator, &document);
        assert_eq!(document["step"], step);
        assert_eq!(record.step_path(), path);
        assert!(record.is_valid());
        assert_eq!(
            serde_json::from_value::<WaitRecord>(document).unwrap(),
            record
        );
    }
    // An element below 1, or a first position element that is not a step, is no record.
    let mut record = record(WaitKind::Answer, "build", "build", None);
    for step in [
        json!(["build", {"item": 0}]),
        json!([{"item": 2}]),
        json!(["build", {"item": 2, "index": 1}]),
    ] {
        record.step = step.as_array().unwrap().clone();
        assert!(!record.is_valid(), "{step}");
    }
}

#[test]
fn a_position_names_a_fan_out_element_only_as_its_step_and_one_item() {
    let mut record = record(WaitKind::Answer, "build", "build", None);
    for (position, expected) in [
        (json!(["build", {"item": 2}]), Some(("build", 2))),
        (json!(["build"]), None),
        (json!(["build", {"item": 2}, {"item": 3}]), None),
        (json!(["build", {"item": "2"}]), None),
        (json!(["build", {}]), None),
        (json!([{"item": 2}]), None),
    ] {
        let position = position.as_array().unwrap().clone();
        assert_eq!(fan_out_element(&position), expected, "{position:?}");
        record.step = position;
        assert_eq!(record.fan_out_element(), expected, "{:?}", record.step);
    }
}

/// A run directory holding `run.json` and attempt 1's copy of `wait`, the wait an answer
/// with `answers` and the string field `summary` resolves.
fn answered_run(wait: &WaitRecord) -> tempfile::TempDir {
    resolved_run(
        wait,
        "control.answer",
        json!({"complete": true, "answers": {"q1": "yes"}, "summary": "ship it"}),
    )
}

/// A run directory holding `run.json` and attempt 1's copy of `wait`, resolved by a control
/// of `event` with `payload`.
fn resolved_run(wait: &WaitRecord, event: &str, payload: Value) -> tempfile::TempDir {
    let root = waiting_run(wait);
    resolve_wait(root.path(), wait, event, Some(payload));
    root
}

fn waiting_run(wait: &WaitRecord) -> tempfile::TempDir {
    let root = run_root();
    let record = crate::workflow::run_record::WorkflowRunRecord::new(
        None,
        &format!("sha256:{}", "a".repeat(64)),
        "workflow.yaml",
        "saeed",
    );
    fs::write(
        root.path().join("run.json"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    write_attempt_wait(root.path(), 1, Some(wait));
    root
}

#[test]
fn attempt_controls_supply_wait_fields_only_to_the_attempt_continuing_the_wait() {
    let wait = record(WaitKind::Answer, "review", "build", None);
    let run = answered_run(&wait);
    // The attempt that continues the resolved wait reads the control payload's string fields.
    let controls = crate::workflow::local_run::attempt_controls(run.path(), 2, None)
        .unwrap()
        .controls;
    assert_eq!(
        controls.wait,
        Some((
            "build".to_owned(),
            BTreeMap::from([("summary".to_owned(), "ship it".to_owned())])
        ))
    );
    // An attempt after one that ended without a wait (a backward or limited edge ending
    // `continued`, an abandoned attempt) does not continue from that wait: `build` reached
    // again has no `wait.<field>`, while `controls.answers` still carries the latest answer.
    fs::create_dir_all(run.path().join("attempts/000002")).unwrap();
    let controls = crate::workflow::local_run::attempt_controls(run.path(), 3, None)
        .unwrap()
        .controls;
    assert_eq!(controls.wait, None);
    assert_eq!(
        controls
            .answers
            .get("build")
            .map(|answers| (**answers).clone()),
        Some(json!({"q1": "yes"}))
    );
    // The agent-profile replacement a `control.retry` carried is retained for every later
    // attempt, however many attempts back the wait it resolved is.
    let wait = record(WaitKind::Repair, "build", "build", None);
    let profiles = json!({"builder": "claude-code"});
    let run = resolved_run(
        &wait,
        "control.retry",
        json!({"agentProfiles": profiles, "note": "again"}),
    );
    fs::create_dir_all(run.path().join("attempts/000002")).unwrap();
    let resolved = crate::workflow::local_run::attempt_controls(run.path(), 3, None).unwrap();
    assert_eq!(resolved.controls.wait, None);
    assert_eq!(resolved.replacement, Some(("build".to_owned(), profiles)));
}

#[test]
fn attempt_controls_resume_the_element_of_a_wait_continuing_at_the_waiting_step() {
    for (then, item, expected) in [
        ("build", Some(2), Some(("build".to_owned(), 2))),
        ("design", Some(2), None),
        ("build", None, None),
    ] {
        let wait = WaitRecord::entered(
            &entered(WaitKind::Answer, "build", then, None),
            item,
            Map::new(),
            since(),
            &ResolvedInputs::default(),
            &BTreeMap::new(),
        )
        .unwrap();
        let run = answered_run(&wait);
        let controls = crate::workflow::local_run::attempt_controls(run.path(), 2, None)
            .unwrap()
            .controls;
        assert_eq!(controls.resume_item, expected, "{then} {item:?}");
        assert_eq!(
            controls.wait.map(|(target, _)| target).as_deref(),
            Some(then)
        );
    }
    // Only the attempt that continues the wait resumes at its element: an attempt that
    // reaches the step after a later attempt ended without a wait (a backward edge, an
    // abandoned attempt) starts at the first element.
    let wait = WaitRecord::entered(
        &entered(WaitKind::Answer, "build", "build", None),
        Some(2),
        Map::new(),
        since(),
        &ResolvedInputs::default(),
        &BTreeMap::new(),
    )
    .unwrap();
    let run = answered_run(&wait);
    fs::create_dir_all(run.path().join("attempts/000002")).unwrap();
    let controls = crate::workflow::local_run::attempt_controls(run.path(), 3, None)
        .unwrap()
        .controls;
    assert_eq!(controls.resume_item, None);
}

// An attempt that kept the wait it continued from holds a second copy of that wait, so the
// attempt the still-resolved wait starts next reads the same control fields and resumes the same
// fan-out element.
#[test]
fn attempt_controls_carry_a_kept_wait_to_the_attempt_it_starts_next() {
    let wait = WaitRecord::entered(
        &entered(WaitKind::Answer, "build", "build", None),
        Some(2),
        Map::new(),
        since(),
        &ResolvedInputs::default(),
        &BTreeMap::new(),
    )
    .unwrap();
    let run = answered_run(&wait);
    fs::create_dir_all(run.path().join("attempts/000002")).unwrap();
    fs::write(
        run.path().join("attempts/000002/wait.json"),
        serde_json::to_vec(&wait).unwrap(),
    )
    .unwrap();
    for attempt in [2, 3] {
        let controls = crate::workflow::local_run::attempt_controls(run.path(), attempt, None)
            .unwrap()
            .controls;
        assert_eq!(
            controls.wait,
            Some((
                "build".to_owned(),
                BTreeMap::from([("summary".to_owned(), "ship it".to_owned())])
            )),
            "attempt {attempt}"
        );
        assert_eq!(
            controls.resume_item,
            Some(("build".to_owned(), 2)),
            "attempt {attempt}"
        );
    }
}

/// A wait of `kind` entered at `step` and continuing at `then`, `minutes` after `since()`, so
/// that two waits of one kind in a run have different identities.
fn wait_at(
    kind: WaitKind,
    step: &str,
    then: &str,
    on_hand_back: Option<&str>,
    minutes: i64,
) -> WaitRecord {
    WaitRecord::entered(
        &entered(kind, step, then, on_hand_back),
        None,
        Map::new(),
        since() + time::Duration::minutes(minutes),
        &ResolvedInputs::default(),
        &BTreeMap::new(),
    )
    .unwrap()
}

/// Creates attempt `attempt`'s directory in the run at `run`, holding `wait` as its copy.
fn write_attempt_wait(run: &Path, attempt: u64, wait: Option<&WaitRecord>) {
    let directory = run.join(format!("attempts/{attempt:06}"));
    fs::create_dir_all(&directory).unwrap();
    if let Some(wait) = wait {
        fs::write(
            directory.join("wait.json"),
            serde_json::to_vec(wait).unwrap(),
        )
        .unwrap();
    }
}

fn record_attempt_count(run: &Path, attempts: u64) {
    let path = run.join("run.json");
    let mut run_json: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    run_json["attempts"] = json!(attempts);
    fs::write(path, serde_json::to_vec(&run_json).unwrap()).unwrap();
}

/// Appends to the run at `run` the control of `event` with `payload` resolving `wait`.
fn resolve_wait(run: &Path, wait: &WaitRecord, event: &str, payload: Option<Value>) {
    let record: Value = serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
    append_control(
        run,
        &control(
            event,
            record["id"].as_str().unwrap(),
            Some(&wait.id()),
            payload,
        ),
    )
    .unwrap();
}

/// A run whose attempt 1 waited for approval at `review`, continuing at `merge` or, handed
/// back, at `fix`, and was handed back with `{"notes": "tighten it"}`.
fn handed_back_run() -> tempfile::TempDir {
    resolved_run(
        &record(WaitKind::Approval, "review", "merge", Some("fix")),
        "control.hand_back",
        json!({"notes": "tighten it"}),
    )
}

/// A run handed back as `handed_back_run`, whose attempt 2 waited at `wait`, resolved by a
/// control of `event` with `payload`.
fn handed_back_then(wait: &WaitRecord, event: &str, payload: Option<Value>) -> tempfile::TempDir {
    let run = handed_back_run();
    write_attempt_wait(run.path(), 2, Some(wait));
    resolve_wait(run.path(), wait, event, payload);
    run
}

#[test]
fn nested_attempt_controls_replay_the_root_answer_at_the_continuation_step() {
    let prefix = [json!("part")];
    let mut original = record(WaitKind::Answer, "prepareChange", "applyDecision", None);
    original
        .payload
        .insert("questions".to_owned(), json!("Is this draft accurate?"));
    let carrier = WaitRecord::carried(&original, &prefix, "part", None).unwrap();
    let root = answered_run(&carrier);
    record_attempt_count(root.path(), 2);
    let mut repeated = wait_at(WaitKind::Answer, "prepareChange", "applyDecision", None, 1);
    repeated.payload = original.payload.clone();
    let nested = waiting_run(&repeated);

    assert_eq!(
        replayed_nested_wait(root.path(), nested.path(), &prefix).unwrap(),
        Some(ContinuationReasonV1::Resume)
    );
    let resolved = AttemptControls::nested(root.path(), nested.path(), 2, &prefix, None).unwrap();
    assert_eq!(
        resolved.controls.wait,
        Some((
            "applyDecision".to_owned(),
            BTreeMap::from([("summary".to_owned(), "ship it".to_owned())]),
        ))
    );
    assert_eq!(
        resolved
            .controls
            .answers
            .get("applyDecision")
            .map(Arc::as_ref),
        Some(&json!({"q1": "yes"}))
    );

    let mut repeated_again = wait_at(WaitKind::Answer, "prepareChange", "applyDecision", None, 2);
    repeated_again.payload = original.payload;
    write_attempt_wait(nested.path(), 2, None);
    write_attempt_wait(nested.path(), 3, Some(&repeated_again));
    record_attempt_count(nested.path(), 3);
    assert_eq!(
        replayed_nested_wait(root.path(), nested.path(), &prefix).unwrap(),
        None
    );
}

#[test]
fn nested_wait_replay_requires_the_same_answer_questions() {
    let prefix = [json!("part")];
    let listed = json!([
        {"id": "q1", "text": "Is this draft accurate?"},
        {"id": "q2", "text": "May this draft be published?"}
    ]);
    let mut changed_id = listed.clone();
    changed_id[1]["id"] = json!("q3");
    let mut changed_text = listed.clone();
    changed_text[1]["text"] = json!("Who may publish this draft?");
    for (original_questions, new_questions) in [
        (
            json!("Is this draft accurate?"),
            json!("May this draft be published?"),
        ),
        (listed.clone(), changed_id),
        (listed, changed_text),
    ] {
        let mut original = record(WaitKind::Answer, "prepareChange", "applyDecision", None);
        original
            .payload
            .insert("questions".to_owned(), original_questions);
        let carrier = WaitRecord::carried(&original, &prefix, "part", None).unwrap();
        let root = resolved_run(
            &carrier,
            CONTROL_ANSWER,
            json!({"complete": true, "answers": {"q1": "yes", "q2": "no"}}),
        );
        record_attempt_count(root.path(), 2);
        let mut changed = wait_at(WaitKind::Answer, "prepareChange", "applyDecision", None, 1);
        changed
            .payload
            .insert("questions".to_owned(), new_questions);
        let nested = waiting_run(&changed);

        assert_eq!(
            replayed_nested_wait(root.path(), nested.path(), &prefix).unwrap(),
            None,
            "changed questions: {:?}",
            changed.payload["questions"]
        );
        let resolved =
            AttemptControls::nested(root.path(), nested.path(), 2, &prefix, None).unwrap();
        assert!(!resolved.controls.answers.contains_key("applyDecision"));
    }
}

// A step that receives another step's answer and then asks its own question continues with
// the answer to its own question, the later of the two.
#[test]
fn nested_attempt_controls_keep_the_later_answer_of_a_step_that_asks_after_receiving_one() {
    let prefix = [json!("part")];
    let asked = record(WaitKind::Answer, "prepareChange", "applyDecision", None);
    let asked_again = wait_at(WaitKind::Answer, "applyDecision", "applyDecision", None, 1);
    let root = resolved_run(
        &WaitRecord::carried(&asked, &prefix, "part", None).unwrap(),
        CONTROL_ANSWER,
        json!({"complete": true, "answers": {"q1": "first"}}),
    );
    let carrier = WaitRecord::carried(&asked_again, &prefix, "part", None).unwrap();
    write_attempt_wait(root.path(), 2, Some(&carrier));
    resolve_wait(
        root.path(),
        &carrier,
        CONTROL_ANSWER,
        Some(json!({"complete": true, "answers": {"q1": "second"}})),
    );
    record_attempt_count(root.path(), 3);
    let nested = waiting_run(&asked);
    write_attempt_wait(nested.path(), 2, Some(&asked_again));

    let resolved = AttemptControls::nested(root.path(), nested.path(), 3, &prefix, None).unwrap();
    assert_eq!(
        resolved
            .controls
            .answers
            .get("applyDecision")
            .map(Arc::as_ref),
        Some(&json!({"q1": "second"}))
    );
}

#[test]
fn nested_wait_replay_requires_the_same_element_and_distinct_continuation_target() {
    let prefix = [json!("part"), json!({"item": 2})];
    let original = record(WaitKind::Answer, "prepareChange", "applyDecision", None);
    let repeated = wait_at(WaitKind::Answer, "prepareChange", "applyDecision", None, 1);
    let same_step = record(WaitKind::Answer, "prepareChange", "prepareChange", None);
    let different_target = wait_at(WaitKind::Answer, "prepareChange", "applyOther", None, 1);
    let other_element = [json!("part"), json!({"item": 1})];
    for (carried, carried_prefix, entered) in [
        (&original, &other_element, &repeated),
        (&same_step, &prefix, &repeated),
        (&original, &prefix, &different_target),
    ] {
        let carrier = WaitRecord::carried(carried, carried_prefix, "part", None).unwrap();
        let root = answered_run(&carrier);
        record_attempt_count(root.path(), 2);
        let nested = waiting_run(entered);
        assert_eq!(
            replayed_nested_wait(root.path(), nested.path(), &prefix).unwrap(),
            None,
            "carrier at {:?} with target {:?}, nested target {:?}",
            carrier.step,
            carrier.nested_then,
            entered.then
        );
    }
}

#[test]
fn nested_wait_replay_only_looks_at_the_unbroken_chain_and_uses_its_latest_match() {
    let prefix = [json!("part")];
    let original = record(WaitKind::Answer, "prepareChange", "applyDecision", None);
    let later = wait_at(WaitKind::Answer, "prepareChange", "applyDecision", None, 1);
    let repeated = wait_at(WaitKind::Answer, "prepareChange", "applyDecision", None, 2);
    let carrier = WaitRecord::carried(&original, &prefix, "part", None).unwrap();
    let later_carrier = WaitRecord::carried(&later, &prefix, "part", None).unwrap();
    let root = answered_run(&carrier);
    let nested = waiting_run(&repeated);

    write_attempt_wait(root.path(), 2, None);
    record_attempt_count(root.path(), 3);
    assert_eq!(
        replayed_nested_wait(root.path(), nested.path(), &prefix).unwrap(),
        None
    );

    write_attempt_wait(root.path(), 2, Some(&later_carrier));
    assert_eq!(
        replayed_nested_wait(root.path(), nested.path(), &prefix).unwrap(),
        None
    );

    resolve_wait(
        root.path(),
        &later_carrier,
        CONTROL_ANSWER,
        Some(json!({"complete": true, "answers": {"q1": "no"}, "summary": "latest"})),
    );

    // The newest root wait can be at a different step, even if it continues to the same
    // target. The replayed attempt reads the matching wait's answer as well as its text.
    let unrelated = wait_at(WaitKind::Answer, "seekAdvice", "applyDecision", None, 3);
    let unrelated_carrier = WaitRecord::carried(&unrelated, &prefix, "part", None).unwrap();
    write_attempt_wait(root.path(), 3, Some(&unrelated_carrier));
    resolve_wait(
        root.path(),
        &unrelated_carrier,
        CONTROL_ANSWER,
        Some(json!({"complete": true, "answers": {"q1": "unrelated"}})),
    );
    record_attempt_count(root.path(), 4);
    assert_eq!(
        replayed_nested_wait(root.path(), nested.path(), &prefix).unwrap(),
        Some(ContinuationReasonV1::Resume)
    );
    let resolved = AttemptControls::nested(root.path(), nested.path(), 2, &prefix, None).unwrap();
    assert_eq!(
        resolved.controls.wait,
        Some((
            "applyDecision".to_owned(),
            BTreeMap::from([("summary".to_owned(), "latest".to_owned())]),
        ))
    );
    assert_eq!(
        resolved
            .controls
            .answers
            .get("applyDecision")
            .map(Arc::as_ref),
        Some(&json!({"q1": "no"}))
    );
    let repeated_again = wait_at(WaitKind::Answer, "prepareChange", "applyDecision", None, 4);
    write_attempt_wait(nested.path(), 2, Some(&repeated_again));
    record_attempt_count(nested.path(), 2);
    assert_eq!(
        replayed_nested_wait(root.path(), nested.path(), &prefix).unwrap(),
        None
    );
}

#[test]
fn nested_wait_replay_requires_a_retry_for_repair_and_respects_exact_pairings() {
    let prefix = [json!("part")];
    let mut original = record(WaitKind::Repair, "prepareChange", "applyDecision", None);
    original
        .payload
        .insert("questions".to_owned(), json!("What must be fixed?"));
    let mut repeated = wait_at(WaitKind::Repair, "prepareChange", "applyDecision", None, 1);
    repeated
        .payload
        .insert("questions".to_owned(), json!("What still must be fixed?"));
    let carrier = WaitRecord::carried(&original, &prefix, "part", None).unwrap();
    let withdrawn = resolved_run(&carrier, CONTROL_WITHDRAW, json!({}));
    record_attempt_count(withdrawn.path(), 2);
    let nested = waiting_run(&repeated);
    assert_eq!(
        replayed_nested_wait(withdrawn.path(), nested.path(), &prefix).unwrap(),
        None
    );

    let root = resolved_run(&carrier, CONTROL_RETRY, json!({}));
    record_attempt_count(root.path(), 2);
    assert_eq!(
        replayed_nested_wait(root.path(), nested.path(), &prefix).unwrap(),
        Some(ContinuationReasonV1::Retry)
    );

    let nested = waiting_run(&original);
    assert_eq!(
        replayed_nested_wait(root.path(), nested.path(), &prefix).unwrap(),
        None
    );
    write_attempt_wait(nested.path(), 2, Some(&repeated));
    record_attempt_count(nested.path(), 2);
    assert_eq!(
        replayed_nested_wait(root.path(), nested.path(), &prefix).unwrap(),
        None
    );
}

// A `control.retry` of a repair wait entered at the step it continues at keeps, for that
// step, the `wait.<field>` values the attempt that entered the wait had there, through
// retries in a row and a kept wait's second copy, under the retry's own string fields; any
// other wait or control, or an attempt without a wait between, keeps nothing. A nested run
// reads the same from the wait copies its root carried.
#[test]
fn attempt_controls_keep_a_hand_back_field_across_repair_retries_at_its_step() {
    let fields = |notes: Option<&str>| {
        notes
            .map(|notes| BTreeMap::from([("notes".to_owned(), notes.to_owned())]))
            .unwrap_or_default()
    };
    let at_fix = |notes| Some(("fix".to_owned(), fields(notes)));
    let wait_of = |run: &tempfile::TempDir, attempt| {
        crate::workflow::local_run::attempt_controls(run.path(), attempt, None)
            .unwrap()
            .controls
            .wait
    };
    let repair = wait_at(WaitKind::Repair, "fix", "fix", None, 1);

    let run = handed_back_then(&repair, "control.retry", None);
    assert_eq!(wait_of(&run, 3), at_fix(Some("tighten it")));
    // A second repair wait at `fix`, also retried, keeps them for attempt 4.
    let again = wait_at(WaitKind::Repair, "fix", "fix", None, 2);
    write_attempt_wait(run.path(), 3, Some(&again));
    resolve_wait(run.path(), &again, "control.retry", None);
    assert_eq!(wait_of(&run, 4), at_fix(Some("tighten it")));

    // An interrupted attempt 3 that kept the retried wait holds its second
    // copy: attempt 4 still reads the hand-back's notes.
    let run = handed_back_then(&repair, "control.retry", None);
    write_attempt_wait(run.path(), 3, Some(&repair));
    assert_eq!(wait_of(&run, 4), at_fix(Some("tighten it")));

    // The retry's own string field takes the place of the kept one.
    let run = handed_back_then(&repair, "control.retry", Some(json!({"notes": "changed"})));
    assert_eq!(wait_of(&run, 3), at_fix(Some("changed")));

    // A repair wait entered at another step than the one it continues at, here a later step
    // whose repair goes back to `fix`, and an answer wait at `fix`, keep nothing.
    let elsewhere = wait_at(WaitKind::Repair, "review", "fix", None, 1);
    let run = handed_back_then(&elsewhere, "control.retry", None);
    assert_eq!(wait_of(&run, 3), at_fix(None));
    let answer = wait_at(WaitKind::Answer, "fix", "fix", None, 1);
    let run = handed_back_then(
        &answer,
        "control.answer",
        Some(json!({"complete": true, "answers": {"q1": "yes"}})),
    );
    assert_eq!(wait_of(&run, 3), at_fix(None));

    // An attempt that entered no wait between the hand-back and the repair keeps nothing.
    let run = handed_back_run();
    write_attempt_wait(run.path(), 2, None);
    write_attempt_wait(run.path(), 3, Some(&repair));
    resolve_wait(run.path(), &repair, "control.retry", None);
    assert_eq!(wait_of(&run, 4), at_fix(None));

    // A nested run at `part` reads the kept field through the copies its root carried. A
    // carried approval admits no hand-back, so here an answer whose control carries `notes`
    // starts `fix`.
    let review = record(WaitKind::Answer, "review", "fix", None);
    let prefix = [json!("part")];
    let root = resolved_run(
        &WaitRecord::carried(&review, &prefix, "part", None).unwrap(),
        "control.answer",
        json!({"complete": true, "answers": {"q1": "yes"}, "notes": "tighten it"}),
    );
    let carried = WaitRecord::carried(&repair, &prefix, "part", None).unwrap();
    assert_eq!(carried.step, [json!("part"), json!("fix")]);
    write_attempt_wait(root.path(), 2, Some(&carried));
    resolve_wait(root.path(), &carried, "control.retry", None);
    record_attempt_count(root.path(), 2);
    let nested = tempfile::tempdir().unwrap();
    write_attempt_wait(nested.path(), 1, Some(&review));
    write_attempt_wait(nested.path(), 2, Some(&repair));
    let controls = crate::workflow::local_run::AttemptControls::nested(
        root.path(),
        nested.path(),
        3,
        &prefix,
        None,
    )
    .unwrap()
    .controls;
    assert_eq!(controls.wait, at_fix(Some("tighten it")));
    assert_eq!(
        controls.answers.get("fix").map(Arc::as_ref),
        Some(&json!({"q1": "yes"}))
    );
    assert!(!controls.answers.contains_key("review"));

    let fresh = tempfile::tempdir().unwrap();
    let controls = crate::workflow::local_run::AttemptControls::nested(
        root.path(),
        fresh.path(),
        1,
        &prefix,
        None,
    )
    .unwrap()
    .controls;
    assert!(!controls.answers.contains_key("fix"));
    assert!(!controls.answers.contains_key("review"));

    let at_own_step = WaitRecord::carried(&answer, &prefix, "part", None).unwrap();
    let root = answered_run(&at_own_step);
    let controls = AttemptControls::nested(root.path(), fresh.path(), 1, &prefix, None)
        .unwrap()
        .controls;
    assert_eq!(
        controls.answers.get("fix").map(Arc::as_ref),
        Some(&json!({"q1": "yes"}))
    );
}

#[test]
fn a_wait_without_a_derived_rule_or_continuing_at_an_exit_has_no_record() {
    // A `children` wait, and an `external` wait without its authored rule, have no rule.
    assert_eq!(
        WaitRecord::entered(
            &entered(WaitKind::External, "merge", "merge", None),
            None,
            Map::new(),
            since(),
            &ResolvedInputs::default(),
            &BTreeMap::new()
        ),
        Err(LocalRunDirectoryError::WaitRecordInvalid)
    );
    // The published record's `then` is a step identifier (`wait/invalid/then-exit.json`).
    assert_eq!(
        WaitRecord::entered(
            &entered(WaitKind::Answer, "design", "exit.landed", None),
            None,
            Map::new(),
            since(),
            &ResolvedInputs::default(),
            &BTreeMap::new()
        ),
        Err(LocalRunDirectoryError::WaitRecordInvalid)
    );
}

const PULL_REQUEST: &str = "https://github.com/useful-machinery/platform/pull/3958";

// A `repair` wait an interrupted child routed to carries the interruption, and the
// engine's `summary`, which begins `interrupted`, replaces one the step committed.
#[test]
fn an_interrupted_repair_wait_payload_names_the_interruption_over_a_committed_summary() {
    let wait = EnteredWait {
        interrupted: Some(ChildInterruption {
            reason: CancellationReason::TerminationRequest,
            step: "implement".to_owned(),
        }),
        ..entered(WaitKind::Repair, "build", "build", None)
    };
    let steps = BTreeMap::from([(
        "build".to_owned(),
        StepState::Succeeded {
            outputs: BTreeMap::from([
                (
                    "outcome".to_owned(),
                    CapturedValue::text(Arc::from("failed")),
                ),
                (
                    "summary".to_owned(),
                    CapturedValue::text(Arc::from("the child's own summary")),
                ),
            ]),
        },
    )]);
    let payload = wait_payload(&wait, &steps, Some("children/build/000001"), None, None);

    assert_eq!(payload["outcome"], "failed");
    assert_eq!(payload["child"], "children/build/000001");
    assert_eq!(
        payload["interrupted"],
        json!({"reason": "termination_request", "step": "implement"})
    );
    let summary = payload["summary"].as_str().unwrap();
    assert_eq!(summary.split_whitespace().next(), Some("interrupted"));
    assert_ne!(summary, "the child's own summary");

    // An interruption a `control.interrupt` requested carries that control's `by`, `at`
    // and `payload`, and the summary names its reason.
    let interrupt = control(
        "control.interrupt",
        RUN,
        None,
        Some(json!({"reason": "pausing for a fix"})),
    );
    let payload = wait_payload(&wait, &steps, None, None, Some(&interrupt));
    assert_eq!(
        payload["interrupted"],
        json!({
            "reason": "termination_request",
            "step": "implement",
            "control": {
                "by": "saeed",
                "at": "2026-11-07T22:00:00Z",
                "payload": {"reason": "pausing for a fix"},
            },
        })
    );
    let summary = payload["summary"].as_str().unwrap();
    assert_eq!(summary.split_whitespace().next(), Some("interrupted"));
    assert!(summary.contains("pausing for a fix"), "{summary}");

    let plain = wait_payload(
        &entered(WaitKind::Repair, "build", "build", None),
        &steps,
        None,
        None,
        None,
    );
    assert_eq!(plain["summary"], "the child's own summary");
    assert!(!plain.contains_key("interrupted"));
}

// The waiting step's failed child is the payload's `failedChild`, which replaces an
// export of that name as `child` does; a `stop` wait's payload names only its control.
#[test]
fn a_wait_payload_carries_the_steps_failed_child_over_an_export_of_its_name() {
    let record = FailedChild {
        outcome: "failed".to_owned(),
        item: None,
        primary_issue: Box::new(crate::workflow::evidence::PrimaryIssue::failed(
            crate::workflow::validated::WorkflowNode {
                id: "route".to_owned(),
                role: crate::workflow::validated::WorkflowNodeRole::Step,
            },
            crate::workflow::evidence::FailureDetail::interrupted_in_execution(),
        )),
    };
    let steps = BTreeMap::from([(
        "build".to_owned(),
        StepState::Succeeded {
            outputs: BTreeMap::from([
                (
                    "outcome".to_owned(),
                    CapturedValue::text(Arc::from("failed")),
                ),
                (
                    "failedChild".to_owned(),
                    CapturedValue::text(Arc::from("the child's own export")),
                ),
            ]),
        },
    )]);
    let payload = wait_payload(
        &entered(WaitKind::Repair, "build", "build", None),
        &steps,
        Some("children/build/000001"),
        Some(&record),
        None,
    );
    assert_eq!(payload["outcome"], "failed");
    assert_eq!(
        payload["failedChild"],
        serde_json::to_value(&record).unwrap()
    );
    assert_eq!(
        payload["failedChild"]["primaryIssue"]["node"]["id"],
        "route"
    );
    assert!(payload["failedChild"].get("item").is_none());

    let stop = wait_payload(
        &entered(WaitKind::Stop, "build", "build", None),
        &steps,
        None,
        Some(&record),
        None,
    );
    assert!(!stop.contains_key("failedChild"));

    let mut wait = self::record(WaitKind::Repair, "build", "build", None);
    wait.payload = payload;
    assert_eq!(wait.failed_child(), Some(record));
}

// A payload without `failedChild`, or whose `failedChild` does not read as the record, has no
// failed child.
#[test]
fn a_wait_payload_without_a_failed_child_record_reads_none() {
    let mut wait = record(WaitKind::Repair, "build", "build", None);
    assert_eq!(wait.failed_child(), None);
    wait.payload = object(json!({"failedChild": "the child's own export"}));
    assert_eq!(wait.failed_child(), None);
}

/// The `merge` step's `admitted` edge: an `external` wait on the queue of the pull request
/// `design` exported, continuing at `merge`.
fn external_wait(where_: &str) -> EnteredWait {
    EnteredWait {
        rule: Some(WaitRule {
            source: "github".to_owned(),
            event: vec!["pull_request.queue_settled".to_owned()],
            where_: where_.to_owned(),
        }),
        ..entered(WaitKind::External, "merge", "merge", None)
    }
}

/// The run's step states: `design` succeeded exporting text `pullRequest`.
fn design_outputs() -> BTreeMap<String, StepState<CapturedValue>> {
    BTreeMap::from([(
        "design".to_owned(),
        StepState::Succeeded {
            outputs: BTreeMap::from([(
                "pullRequest".to_owned(),
                CapturedValue::text(Arc::from(PULL_REQUEST)),
            )]),
        },
    )])
}

fn external_record(where_: &str) -> Result<WaitRecord, LocalRunDirectoryError> {
    WaitRecord::entered(
        &external_wait(where_),
        None,
        object(json!({"outcome": "admitted"})),
        since(),
        &ResolvedInputs::new(BTreeMap::from([(
            "ticket".to_owned(),
            ResolvedInput::Text(Arc::from("AUTO-208")),
        )])),
        &design_outputs(),
    )
}

fn queue_settled(pull_request: &str, state: &str) -> ExternalEvent {
    ExternalEvent {
        source: "github".to_owned(),
        event: "pull_request.queue_settled".to_owned(),
        at: "2026-11-07T22:30:00Z".to_owned(),
        payload: object(json!({"pullRequest": pull_request, "state": state, "headSha": "4f2a"})),
    }
}

// An `external` wait's record carries the authored rule with its run-value operands resolved
// to quoted literals, so the matcher reads the rule alone.
#[test]
fn an_external_wait_writes_its_authored_rule_with_run_values_resolved() {
    let record = external_record(
        "event.pullRequest == outputs.design.pullRequest and event.state == \"merged\"",
    )
    .unwrap();
    let document = serde_json::to_value(&record).unwrap();
    assert_valid(&validator("workflow-run-wait-v1.schema.json"), &document);
    assert_eq!(
        document["rule"],
        json!({
            "source": "github",
            "event": ["pull_request.queue_settled"],
            "where": format!(
                "event.pullRequest == \"{PULL_REQUEST}\" and event.state == \"merged\""
            ),
        })
    );
    assert_eq!(document["kind"], "external");
    assert_eq!(document["then"], "merge");
    assert_eq!(
        serde_json::from_value::<WaitRecord>(document).unwrap(),
        record
    );

    // An input operand resolves the same way, on either side of an equality.
    let record = external_record("inputs.ticket == event.ticket").unwrap();
    assert_eq!(record.rule.where_, "\"AUTO-208\" == event.ticket");

    // An operand whose value the run does not hold (its producer did not run, or the input
    // was omitted) leaves no record.
    for where_ in [
        "event.pullRequest == outputs.review.pullRequest",
        "event.pullRequest == outputs.design.branch",
        "event.ticket == inputs.title",
    ] {
        assert_eq!(
            external_record(where_),
            Err(LocalRunDirectoryError::WaitRecordInvalid),
            "{where_}"
        );
    }
}

// The one matcher resolves an `external` wait against the events its condition observed, as it
// resolves a local wait against the controls.
#[test]
fn evaluate_matches_observed_external_events_through_the_rule() {
    let record = external_record(
        "event.pullRequest == outputs.design.pullRequest and event.state == \"merged\"",
    )
    .unwrap();
    let merged = queue_settled(PULL_REQUEST, "merged");
    assert_eq!(
        evaluate(&record.rule, RUN, &record, std::slice::from_ref(&merged)),
        Ok(Some(&merged))
    );
    let other = queue_settled(
        "https://github.com/useful-machinery/platform/pull/1",
        "merged",
    );
    let dequeued = queue_settled(PULL_REQUEST, "dequeued");
    assert_eq!(
        evaluate(&record.rule, RUN, &record, &[other, dequeued]),
        Ok(None)
    );
    let mut elsewhere = merged.clone();
    elsewhere.source = "gitlab".to_owned();
    assert_eq!(evaluate(&record.rule, RUN, &record, &[elsewhere]), Ok(None));
    let no_events: [ExternalEvent; 0] = [];
    assert_eq!(evaluate(&record.rule, RUN, &record, &no_events), Ok(None));
}

/// A directory shaped like a run root as far as controls need: `.private/` beside them.
fn run_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join(".private")).unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

fn assert_control_invalid(root: &Path, name: &str) {
    match read_controls(root) {
        Err(LocalRunDirectoryError::StateFile { path, source, .. })
            if path.ends_with(Path::new("controls").join(name))
                && matches!(*source, LocalRunDirectoryError::ControlEventInvalid) => {}
        other => panic!("{name} was not refused as a control event: {other:?}"),
    }
}

#[test]
fn delivered_events_are_private_idempotent_and_read_in_order() {
    let root = run_root();
    let event: RunEvent = serde_json::from_value(json!({
        "source": "cloud", "event": "run.ended", "at": SINCE,
        "wait": format!("external@{SINCE}"), "delivery": "run-ended:41",
        "payload": { "runId": RUN, "definitionId": "def_01jcf9a4r7t2m8k3v6x1z5n0pq",
                     "attempt": 2, "outcome": "ok" }
    }))
    .unwrap();
    let (ordinal, path) = append_run_event(root.path(), &event).unwrap().unwrap();
    assert_eq!(ordinal, 1);
    let events = root.path().canonicalize().unwrap().join("events");
    assert_eq!(path, events.join("0001-run_ended.json"));
    assert_eq!(mode(&events), 0o700);
    assert_eq!(mode(&path) & 0o077, 0);
    assert_valid(
        &validator("workflow-run-event-v1.schema.json"),
        &serde_json::from_slice(&fs::read(path).unwrap()).unwrap(),
    );
    assert_eq!(append_run_event(root.path(), &event).unwrap(), None);
    assert_eq!(read_run_events(root.path()).unwrap(), [event]);
    let invalid = events.join("0002-run_ended.json");
    fs::write(&invalid, b"{}").unwrap();
    assert!(
        matches!(read_run_events(root.path()), Err(LocalRunDirectoryError::StateFile {path, source, ..})
        if path == invalid && *source == LocalRunDirectoryError::RunEventInvalid)
    );
}

#[test]
fn append_control_writes_ordinal_files_that_read_controls_returns_in_order() {
    let validator = validator("workflow-run-control-v1.schema.json");
    let root = run_root();
    assert_eq!(read_controls(root.path()).unwrap(), []);

    let wait = format!("approval@{SINCE}");
    let approve = control("control.approve", RUN, Some(&wait), None);
    let hand_back = control(
        "control.hand_back",
        RUN,
        Some(&wait),
        Some(json!({"notes": "tighten the test"})),
    );
    let first = append_control(root.path(), &approve).unwrap();
    let second = append_control(root.path(), &hand_back).unwrap();

    let controls = root.path().join("controls");
    assert_eq!(
        first,
        controls.canonicalize().unwrap().join("0001-approve.json")
    );
    assert_eq!(
        second,
        controls.canonicalize().unwrap().join("0002-hand_back.json")
    );
    assert_eq!(mode(&controls), 0o700);
    for path in [&first, &second] {
        assert_eq!(mode(path) & 0o077, 0, "{}", path.display());
        assert_valid(
            &validator,
            &serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap(),
        );
    }
    assert_eq!(
        fs::read_dir(root.path().join(".private")).unwrap().count(),
        0
    );
    assert_eq!(
        read_controls(root.path()).unwrap(),
        [approve.clone(), hand_back]
    );

    // `ControlEvent::new` stamps `at` with the current UTC time and refuses an event the
    // published schema does not name.
    let release = ControlEvent::new(CONTROL_RELEASE, RUN, "saeed", None, None).unwrap();
    assert!(
        parse_canonical_utc_timestamp(&release.at).is_some(),
        "{}",
        release.at
    );
    assert_eq!(
        ControlEvent::new("control.approved", RUN, "saeed", Some(wait.clone()), None),
        Err(LocalRunDirectoryError::ControlEventInvalid)
    );

    // An event the published schema does not name is refused and writes nothing.
    let mut approved = approve.clone();
    approved.event = "control.approved".to_owned();
    assert_eq!(
        append_control(root.path(), &approved),
        Err(LocalRunDirectoryError::ControlEventInvalid)
    );
    assert_eq!(fs::read_dir(&controls).unwrap().count(), 2);

    // A file under `controls/` that is not a control event makes the controls unreadable.
    fs::write(controls.join("0003-lift.json"), b"not json").unwrap();
    assert_control_invalid(root.path(), "0003-lift.json");
    fs::remove_file(controls.join("0003-lift.json")).unwrap();
    fs::write(
        controls.join("0003-lift.json"),
        serde_json::to_vec(&approve).unwrap(),
    )
    .unwrap();
    assert_control_invalid(root.path(), "0003-lift.json");
    fs::remove_file(controls.join("0003-lift.json")).unwrap();
    fs::write(controls.join("notes.txt"), b"").unwrap();
    assert_control_invalid(root.path(), "notes.txt");
}

// `control.interrupt` is a control event of the published schema, written as
// `controls/<NNNN>-interrupt.json`, and no wait's rule resolves on it.
#[test]
fn an_interrupt_is_a_recorded_control_that_resolves_no_wait() {
    let validator = validator("workflow-run-control-v1.schema.json");
    let root = run_root();
    let interrupt = ControlEvent::new(
        "control.interrupt",
        RUN,
        "saeed",
        None,
        Some(object(json!({"reason": "pausing for a fix"}))),
    )
    .unwrap();
    let path = append_control(root.path(), &interrupt).unwrap();
    assert_eq!(
        path,
        root.path()
            .join("controls")
            .canonicalize()
            .unwrap()
            .join("0001-interrupt.json")
    );
    assert_valid(
        &validator,
        &serde_json::from_slice::<Value>(&fs::read(&path).unwrap()).unwrap(),
    );
    assert_eq!(
        read_numbered_controls(root.path()).unwrap(),
        [(1, interrupt)]
    );

    for (kind, on_hand_back) in [
        (WaitKind::Answer, None),
        (WaitKind::Approval, Some("fix")),
        (WaitKind::Repair, None),
        (WaitKind::Stop, None),
    ] {
        let wait = record(kind, "design", "design", on_hand_back);
        let interrupt = control(
            "control.interrupt",
            RUN,
            Some(&wait.id()),
            Some(json!({"reason": "pausing", "before": "design", "complete": true})),
        );
        assert_eq!(
            evaluate(&wait.rule, RUN, &wait, std::slice::from_ref(&interrupt)),
            Ok(None),
            "{kind:?}"
        );
    }
}

#[test]
fn evaluate_resolves_a_wait_only_through_its_rule() {
    let approval = record(WaitKind::Approval, "review", "merge", Some("fix"));
    let wait = approval.id();
    let approve = control("control.approve", RUN, Some(&wait), None);
    assert_eq!(
        evaluate(
            &approval.rule,
            RUN,
            &approval,
            std::slice::from_ref(&approve)
        ),
        Ok(Some(&approve))
    );
    // Another run, another wait identity and an event the rule does not name never match;
    // the first control that does, in order, resolves the wait.
    let hand_back = control(
        "control.hand_back",
        RUN,
        Some(&wait),
        Some(json!({"notes": "keep it"})),
    );
    let events = [
        control("control.approve", OTHER_RUN, Some(&wait), None),
        control(
            "control.approve",
            RUN,
            Some("approval@2026-11-06T13:40:11Z"),
            None,
        ),
        control("control.answer", RUN, Some(&wait), None),
        hand_back.clone(),
        approve,
    ];
    assert_eq!(
        evaluate(&approval.rule, RUN, &approval, &events),
        Ok(Some(&hand_back))
    );
    assert_eq!(
        evaluate(&approval.rule, RUN, &approval, &events[..3]),
        Ok(None)
    );

    let stop = WaitRecord::entered(
        &entered(WaitKind::Stop, "design", "design", None),
        None,
        object(json!({"by": "saeed", "at": "2026-11-07T21:00:00Z"})),
        since(),
        &ResolvedInputs::default(),
        &BTreeMap::new(),
    )
    .unwrap();
    let lift_design = control(
        "control.lift",
        RUN,
        None,
        Some(json!({"before": "design", "stop": "2026-11-07T21:00:00Z"})),
    );
    let lift_build = control(
        "control.lift",
        RUN,
        None,
        Some(json!({"before": "build", "stop": "2026-11-07T21:00:00Z"})),
    );
    assert_eq!(
        evaluate(
            &stop.rule,
            RUN,
            &stop,
            &[lift_build.clone(), lift_design.clone()]
        ),
        Ok(Some(&lift_design))
    );
    assert_eq!(evaluate(&stop.rule, RUN, &stop, &[lift_build]), Ok(None));

    // Quoted literals and every `wait.<field>` are operands.
    let mut literal = stop.rule.clone();
    literal.where_ = "event.payload.before == \"design\" and wait.kind == \"stop\" and wait.step == wait.then and wait.since == \"2026-11-07T21:41:58Z\"".to_owned();
    assert_eq!(
        evaluate(&literal, RUN, &stop, std::slice::from_ref(&lift_design)),
        Ok(Some(&lift_design))
    );

    // A `where` outside the grammar is an error, never a match or a miss.
    for where_ in [
        "event.payload.complete == maybe",
        "wait.payload == \"merge\"",
        "wait.payload.payload..before == \"merge\"",
        "event.run != run.id",
        "event.run == run.id or event.wait == wait.id",
        "event.pullRequest == steps.design.outputs.pullRequest",
        "event.run == wait.owner",
        "",
    ] {
        let mut rule = stop.rule.clone();
        rule.where_ = where_.to_owned();
        assert!(
            evaluate(&rule, RUN, &stop, std::slice::from_ref(&lift_design)).is_err(),
            "{where_:?} parsed"
        );
        assert!(
            evaluate::<ControlEvent>(&rule, RUN, &stop, &[]).is_err(),
            "{where_:?} parsed"
        );
    }
}

#[test]
fn run_value_operands_parse_and_an_unresolved_one_never_matches() {
    let conjuncts = parse_where(
        "event.ticket == inputs.ticket and event.pullRequest == outputs.design.pullRequest",
    )
    .unwrap();
    assert!(
        matches!(
            conjuncts.as_slice(),
            [
                (Operand::Event(_), Operand::Inputs(input)),
                (Operand::Event(_), Operand::Outputs { step, output }),
            ] if input == "ticket" && step == "design" && output == "pullRequest"
        ),
        "{conjuncts:?}"
    );
    for operand in [
        "inputs.",
        "inputs.ticket.id",
        "outputs.design",
        "outputs.design.pullRequest.url",
        "outputs..pullRequest",
    ] {
        assert!(
            parse_where(&format!("event.ticket == {operand}")).is_err(),
            "{operand:?} parsed"
        );
    }

    // Validation admits these operands and the record substitutes them, so the matcher
    // never resolves one: a conjunct naming it never holds.
    let repair = record(WaitKind::Repair, "merge", "merge", None);
    let retry = control(
        "control.retry",
        RUN,
        Some(&repair.id()),
        Some(json!({"ticket": "AUTO-208"})),
    );
    let mut rule = repair.rule.clone();
    rule.where_ = "event.run == run.id and event.payload.ticket == \"AUTO-208\"".to_owned();
    assert_eq!(
        evaluate(&rule, RUN, &repair, std::slice::from_ref(&retry)),
        Ok(Some(&retry))
    );
    for unresolved in ["inputs.ticket", "outputs.design.ticket"] {
        rule.where_ = format!("event.run == run.id and event.payload.ticket == {unresolved}");
        assert_eq!(
            evaluate(&rule, RUN, &repair, std::slice::from_ref(&retry)),
            Ok(None),
            "{unresolved} matched"
        );
    }
}

#[test]
fn an_answer_resolves_only_when_complete_and_a_lift_only_for_the_stop_in_force() {
    let answer = record(WaitKind::Answer, "design", "design", None);
    let wait = answer.id();
    let answered = |complete: bool| {
        control(
            "control.answer",
            RUN,
            Some(&wait),
            Some(json!({
                "question": "q1",
                "text": "yes",
                "answers": {"q1": "yes"},
                "complete": complete,
            })),
        )
    };
    let (open, complete) = (answered(false), answered(true));
    assert_eq!(
        evaluate(&answer.rule, RUN, &answer, std::slice::from_ref(&open)),
        Ok(None)
    );
    assert_eq!(
        evaluate(
            &answer.rule,
            RUN,
            &answer,
            &[open.clone(), complete.clone()]
        ),
        Ok(Some(&complete))
    );
    // A quoted `"true"` is a string and never equals the boolean `true`.
    let mut quoted = answer.rule.clone();
    quoted.where_ = "event.payload.complete == \"true\"".to_owned();
    assert_eq!(
        evaluate(&quoted, RUN, &answer, std::slice::from_ref(&complete)),
        Ok(None)
    );
    let mut literal = answer.rule.clone();
    literal.where_ = "event.payload.complete == true and false == false".to_owned();
    assert_eq!(
        evaluate(&literal, RUN, &answer, &[open, complete.clone()]),
        Ok(Some(&complete))
    );
    let mut bare = answer.rule.clone();
    bare.where_ = "event.payload.complete == maybe".to_owned();
    assert!(matches!(
        evaluate(&bare, RUN, &answer, std::slice::from_ref(&complete)),
        Err(error) if error.clause == "event.payload.complete == maybe"
    ));

    let stop = WaitRecord::entered(
        &entered(WaitKind::Stop, "merge", "merge", None),
        None,
        object(json!({
            "by": "saeed",
            "at": "2026-11-06T16:01:17Z",
            "payload": {"before": "merge", "reason": "hold for the release"},
        })),
        since(),
        &ResolvedInputs::default(),
        &BTreeMap::new(),
    )
    .unwrap();
    let lift = |at: &str| {
        control(
            "control.lift",
            RUN,
            None,
            Some(json!({"before": "merge", "stop": at})),
        )
    };
    let (earlier, current) = (lift("2026-11-06T15:00:00Z"), lift("2026-11-06T16:01:17Z"));
    assert_eq!(
        evaluate(&stop.rule, RUN, &stop, std::slice::from_ref(&earlier)),
        Ok(None)
    );
    assert_eq!(
        evaluate(&stop.rule, RUN, &stop, &[earlier, current.clone()]),
        Ok(Some(&current))
    );
    // `wait.payload.<path>` folds every segment over the record's payload.
    let mut nested = stop.rule.clone();
    nested.where_ = "wait.payload.payload.before == \"merge\" and event.payload.before == wait.payload.payload.before".to_owned();
    assert_eq!(
        evaluate(&nested, RUN, &stop, std::slice::from_ref(&current)),
        Ok(Some(&current))
    );
    nested.where_ = "wait.payload.payload.reason == \"merge\"".to_owned();
    assert_eq!(
        evaluate(&nested, RUN, &stop, std::slice::from_ref(&current)),
        Ok(None)
    );
}

#[test]
fn a_stop_is_in_force_until_a_later_lift_for_the_same_step() {
    let stop = |before: &str| {
        control(
            "control.stop",
            RUN,
            None,
            Some(json!({"before": before, "reason": "hold"})),
        )
    };
    let lift = |before: &str| control("control.lift", RUN, None, Some(json!({"before": before})));

    assert_eq!(stop_in_force(&[], "design"), None);
    let mut events = vec![stop("design")];
    assert_eq!(stop_in_force(&events, "design"), Some(&events[0]));
    events.push(lift("design"));
    assert_eq!(stop_in_force(&events, "design"), None);
    events.push(stop("design"));
    assert_eq!(stop_in_force(&events, "design"), Some(&events[2]));

    let build = [stop("build"), lift("design")];
    assert_eq!(stop_in_force(&build, "design"), None);
    assert_eq!(stop_in_force(&build, "build"), Some(&build[0]));
}

// The questions `useful workflow run answer` accepts and the runner reports are one derivation
// over the wait's payload.
#[test]
fn a_wait_payload_lists_its_questions_by_id_and_text_or_asks_one() {
    let listed = |questions: &[(&str, Option<&str>)]| {
        WaitQuestions::Listed(
            questions
                .iter()
                .map(|(id, text)| WaitQuestion {
                    id: (*id).to_owned(),
                    text: text.map(str::to_owned),
                })
                .collect(),
        )
    };
    let many = (1..=65)
        .map(|n| json!({"id": format!("q{n}"), "text": format!("Question {n}?")}))
        .collect::<Vec<_>>();
    let many_ids = (1..=65).map(|n| format!("q{n}")).collect::<Vec<_>>();
    let many_texts = (1..=65)
        .map(|n| format!("Question {n}?"))
        .collect::<Vec<_>>();
    let cases = [
        (
            json!({"questions": [{"id": "scope", "text": "A"}, {"id": "q2", "text": "B"}]}),
            listed(&[("scope", Some("A")), ("q2", Some("B"))]),
        ),
        (
            json!({"questions": [
                {"question": "A", "default": "x"},
                {"question": "B", "default": "y"},
            ]}),
            listed(&[("1", Some("A")), ("2", Some("B"))]),
        ),
        (
            json!({"questions": "Which scope?"}),
            WaitQuestions::Unlisted {
                text: Some("Which scope?".to_owned()),
            },
        ),
        (json!({}), WaitQuestions::Unlisted { text: None }),
        (
            json!({"questions": {"id": "scope"}}),
            WaitQuestions::Unlisted { text: None },
        ),
        (json!({"questions": []}), listed(&[])),
        (
            json!({"questions": many}),
            listed(
                &many_ids
                    .iter()
                    .zip(&many_texts)
                    .map(|(id, text)| (id.as_str(), Some(text.as_str())))
                    .collect::<Vec<_>>(),
            ),
        ),
        (
            json!({"questions": [{"id": "scope", "text": "A\u{0}B"}]}),
            listed(&[("scope", Some("A\u{0}B"))]),
        ),
        (
            json!({"questions": [
                "Plain?",
                {"id": 7, "text": "Numbered"},
                {"id": "both", "text": "T", "question": "Q"},
                {"default": "x"},
            ]}),
            listed(&[
                ("1", Some("Plain?")),
                ("2", Some("Numbered")),
                ("both", Some("T")),
                ("4", None),
            ]),
        ),
    ];
    for (payload, expected) in cases {
        assert_eq!(
            wait_questions(&object(payload.clone())),
            expected,
            "{payload}"
        );
    }
}
