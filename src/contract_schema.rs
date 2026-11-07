//! JSON Schemas for what the service returns, shared by every adapter that publishes a contract (the
//! OpenAPI document and the MCP tool output schemas), so the two describe one shape. Each is checked
//! against real [`crate::service`] values in the tests.

use crate::service::Descriptor;
use serde_json::{Map, Value, json};

/// The reusable shapes, stored once per document: `ErrorResponse`, `OperationView` and
/// `OperationEvent`. `base` is where the store is reachable from the document root, and the returned
/// map is what an adapter places there.
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
                    "code": {"type": "string"},
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

/// The result of running `descriptor`'s capability to completion: its own output and error schemas
/// in the outcome. `output` and `error` are references to the lifted schemas.
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

/// The result of starting an operation: running, or already finished with the call's result. A
/// finished start carries `state: "finished"` beside the call's own fields.
pub fn start_result(call: &Value) -> Value {
    let mut finished = call.clone();
    finished["required"] = json!(["state", "outcome"]);
    finished["properties"]["state"] = json!({"const": "finished"});
    json!({"oneOf": [
        {
            "type": "object",
            "required": ["state", "operation"],
            "additionalProperties": false,
            "properties": {"state": {"const": "running"}, "operation": {"type": "string"}}
        },
        finished
    ]})
}

/// Whether the descriptor's input schema can describe a JSON object, which is the root type an MCP
/// tool needs and the body an adapter can send for a direct-shape call.
pub fn input_is_object(descriptor: &Descriptor) -> bool {
    matches!(&descriptor.input_schema, Value::Object(map)
        if map.get("type").and_then(Value::as_str) == Some("object"))
}
