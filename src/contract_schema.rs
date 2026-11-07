//! JSON Schemas for what the service returns, shared by every adapter that publishes a contract (the OpenAPI document and the MCP tool output schemas), so the two describe one shape. Each is checked against real [`crate::service`] values in the tests.

use crate::{service::Descriptor, wire::ErrorCode};
use serde_json::{Map, Value, json};

/// The reusable shapes, stored once per document: `ErrorResponse`, `OperationView`, `OperationEvents` and `OperationEvent`. `base` is where the store is reachable from the document root, and the returned map is what an adapter places there.
pub fn shared_schemas(base: &str) -> Map<String, Value> {
    let outcome = json!({
        "oneOf": [
            {"type": "object", "required": ["Success"], "additionalProperties": false, "properties": {"Success": {}}},
            {"type": "object", "required": ["Error"], "additionalProperties": false, "properties": {"Error": {}}},
            {"type": "object", "required": ["Unknown"], "additionalProperties": false, "properties": {"Unknown": {}}}
        ]
    });
    let mut schemas = Map::new();
    schemas.insert(
        "ErrorResponse".into(),
        json!({
            "type": "object",
            "required": ["error"],
            "additionalProperties": false,
            "properties": {"error": {
                "type": "object",
                "required": ["code", "message"],
                "additionalProperties": false,
                "properties": {
                    "code": {"enum": ErrorCode::ALL},
                    "message": {"type": "string"},
                    "detail": {}
                }
            }}
        }),
    );
    schemas.insert(
        "OperationEvent".into(),
        json!({
            "type": "object",
            "required": ["seq", "state"],
            "additionalProperties": false,
            "properties": {
                "seq": {"type": "integer", "minimum": 0},
                "state": {"oneOf": [
                    {"const": "Accepted"},
                    {"const": "Interrupted"},
                    {"type": "object", "required": ["Completed"], "additionalProperties": false,
                     "properties": {"Completed": outcome}}
                ]}
            }
        }),
    );
    schemas.insert(
        "OperationView".into(),
        json!({
            "type": "object",
            "required": ["id", "capability", "events"],
            "additionalProperties": false,
            "properties": {
                "id": {"type": "string"},
                "capability": {
                    "type": "object",
                    "required": ["name", "version"],
                    "additionalProperties": false,
                    "properties": {"name": {"type": "string"}, "version": {"type": "integer", "minimum": 0}}
                },
                "events": {"type": "array", "items": {"$ref": format!("{base}OperationEvent")}}
            }
        }),
    );
    schemas.insert(
        "OperationEvents".into(),
        json!({
            "type": "object",
            "required": ["events"],
            "additionalProperties": false,
            "properties": {"events": {"type": "array", "items": {"$ref": format!("{base}OperationEvent")}}}
        }),
    );
    schemas
}

/// The result of running a capability to completion, with the capability's own output and error schemas in the outcome. `output` and `error` are references to the lifted schemas.
pub fn call_result(output: &Value, error: &Value) -> Value {
    json!({
        "type": "object",
        "required": ["outcome"],
        "additionalProperties": false,
        "properties": {
            "operation": {"type": "string"},
            "outcome": {"oneOf": [
                {"type": "object", "required": ["Success"], "additionalProperties": false, "properties": {"Success": output}},
                {"type": "object", "required": ["Error"], "additionalProperties": false, "properties": {"Error": error}},
                {"type": "object", "required": ["Unknown"], "additionalProperties": false, "properties": {"Unknown": {}}}
            ]},
            "recorded": {"type": "boolean"},
            "failed": {"type": "boolean"},
            "uncertain": {"type": "boolean"}
        }
    })
}

/// The two results of starting an operation: running, and already finished with the call's result. A finished start carries `state: "finished"` beside the call's own fields. An adapter that answers them with different statuses documents each arm for its own status.
pub fn start_arms(call: &Value) -> (Value, Value) {
    let running = json!({
        "type": "object",
        "required": ["state", "operation"],
        "additionalProperties": false,
        "properties": {"state": {"const": "running"}, "operation": {"type": "string"}}
    });
    let mut finished = call.clone();
    finished["required"] = json!(["state", "outcome"]);
    finished["properties"]["state"] = json!({"const": "finished"});
    (running, finished)
}

/// The result of starting an operation, whichever arm it is.
pub fn start_result(call: &Value) -> Value {
    let (running, finished) = start_arms(call);
    json!({"oneOf": [running, finished]})
}

/// Whether the descriptor's input schema declares `"type": "object"` at its root (a root that only has a `oneOf` or a `$ref` does not), which is the root type an MCP tool needs and the body an adapter can send for a direct-shape call. A query that does not is not offered as a tool, though a call to it by name is still checked against its schema.
pub fn input_is_object(descriptor: &Descriptor) -> bool {
    matches!(&descriptor.input_schema, Value::Object(map)
        if map.get("type").and_then(Value::as_str) == Some("object"))
}
