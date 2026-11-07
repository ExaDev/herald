//! The published result schemas accept what the service really returns and refuse what it never does.

use herald::{
    CapabilityId, Outcome,
    contract_schema::{call_result, shared_schemas, start_result},
    runtime::{OperationEvent, OperationId, OperationState, OperationView},
    service::{CallResult, StartResult},
    wire::{ErrorCode, WireError},
};
use serde_json::{Value, json};

const BASE: &str = "#/$defs/";

/// A validator for `schema` with the shared schemas reachable under `$defs`.
fn validator(schema: Value) -> jsonschema::Validator {
    let mut root = schema;
    root["$defs"] = Value::Object(shared_schemas(BASE));
    jsonschema::validator_for(&root).expect("a valid schema")
}

fn shared(name: &str) -> Value {
    json!({"$ref": format!("{BASE}{name}")})
}

fn call(outcome: Outcome, operation: Option<&str>) -> CallResult {
    let failed = matches!(outcome, Outcome::Error(_));
    let uncertain = matches!(outcome, Outcome::Unknown(_));
    CallResult {
        operation: operation.map(|id| OperationId(id.into())),
        outcome,
        recorded: operation.map(|_| true),
        failed,
        uncertain,
    }
}

#[test]
fn a_call_result_of_every_outcome_matches_its_schema() {
    let schema = validator(call_result(
        &json!({"type": "object", "required": ["n"]}),
        &json!({"type": "object", "required": ["why"]}),
    ));
    for (result, valid) in [
        (call(Outcome::Success(json!({"n": 1})), Some("op-1")), true),
        (call(Outcome::Success(json!({"n": 1})), None), true),
        (
            call(Outcome::Error(json!({"why": "x"})), Some("op-1")),
            true,
        ),
        (
            call(Outcome::Unknown(json!("anything")), Some("op-1")),
            true,
        ),
        (call(Outcome::Success(json!({})), None), false),
        (call(Outcome::Error(json!({})), None), false),
    ] {
        assert_eq!(schema.is_valid(&json!(result)), valid, "{result:?}");
    }
    assert!(!schema.is_valid(&json!({"outcome": {"Success": {"n": 1}}, "extra": 1})));
}

#[test]
fn a_start_result_matches_whether_running_or_finished() {
    let call_schema = call_result(&json!(true), &json!(true));
    let schema = validator(start_result(&call_schema));
    let running = json!(StartResult::Running {
        operation: OperationId("op-1".into())
    });
    let finished = json!(StartResult::Finished(call(
        Outcome::Success(json!({})),
        Some("op-1")
    )));
    assert_eq!(finished["state"], "finished");
    assert!(schema.is_valid(&running), "{running}");
    assert!(schema.is_valid(&finished), "{finished}");
    assert!(
        !schema.is_valid(&json!({"outcome": {"Success": {}}})),
        "a call result has no state"
    );
}

#[test]
fn errors_and_operation_views_match_the_shared_schemas() {
    let error = json!({"error": WireError::new(ErrorCode::NotFound, "no such capability")});
    assert!(validator(shared("ErrorResponse")).is_valid(&error));
    let with_detail = json!({"error": {
        "code": "invalid_input", "message": "m", "detail": "d"
    }});
    assert!(validator(shared("ErrorResponse")).is_valid(&with_detail));
    assert!(!validator(shared("ErrorResponse")).is_valid(&json!({"code": "x"})));

    let view = OperationView {
        id: OperationId("op-1".into()),
        capability: CapabilityId {
            name: "write".into(),
            version: 1,
        },
        events: vec![
            OperationEvent {
                seq: 0,
                state: OperationState::Accepted,
            },
            OperationEvent {
                seq: 1,
                state: OperationState::Completed(Outcome::Success(json!({"a": 1}))),
            },
            OperationEvent {
                seq: 2,
                state: OperationState::Interrupted,
            },
        ],
    };
    assert!(validator(shared("OperationView")).is_valid(&json!(view)));
    assert!(validator(shared("OperationEvents")).is_valid(&json!({"events": view.events})));
    assert!(!validator(shared("OperationView")).is_valid(&json!({"id": "x"})));
}
