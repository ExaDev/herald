//! Rewriting the `$ref` pointers of a JSON Schema when the schema is moved inside a larger document,
//! as the adapters do when they embed a capability's schema in a tool or an OpenAPI document.

use serde_json::Value;

/// Keywords whose value is instance data, not a schema: a `$ref` key inside it is data.
const DATA_KEYWORDS: [&str; 4] = ["enum", "const", "default", "examples"];

/// Keywords whose value maps names to schemas, so their keys are names and not keywords.
const SCHEMA_MAPS: [&str; 5] = [
    "properties",
    "$defs",
    "definitions",
    "patternProperties",
    "dependentSchemas",
];

/// Replaces every `$ref` in `schema` for which `rewrite` returns a new pointer. A `$ref` inside
/// instance data (`enum`, `const`, `default`, `examples`) is left alone, and a property that happens
/// to be named like a keyword is treated as a property.
pub fn rewrite_refs(schema: &mut Value, rewrite: &dyn Fn(&str) -> Option<String>) {
    match schema {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if key == "$ref" {
                    if let Value::String(reference) = value
                        && let Some(new) = rewrite(reference)
                    {
                        *reference = new;
                    }
                } else if DATA_KEYWORDS.contains(&key.as_str()) {
                } else if SCHEMA_MAPS.contains(&key.as_str()) {
                    if let Value::Object(children) = value {
                        for child in children.values_mut() {
                            rewrite_refs(child, rewrite);
                        }
                    }
                } else {
                    rewrite_refs(value, rewrite);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                rewrite_refs(item, rewrite);
            }
        }
        _ => {}
    }
}

/// Stores `schema` in `store` under `name`, with the definitions it carries beside it under
/// `<name>_<definition>`, and returns a reference to it. `base` is where `store` is reachable from
/// the final document root (`#/components/schemas/` or `#/$defs/`). Every pointer inside the schema is
/// rewritten to its new location, so `#`, `#/$defs/X`, `#/definitions/X` and `#/properties/y` still
/// resolve. `name` must be unique within `store`.
pub fn lift_schema(
    schema: &Value,
    name: &str,
    store: &mut serde_json::Map<String, Value>,
    base: &str,
) -> Value {
    let mut schema = schema.clone();
    let root = format!("{base}{name}");
    let rewrite = |reference: &str| -> Option<String> {
        if reference == "#" {
            return Some(root.clone());
        }
        for definitions in ["#/$defs/", "#/definitions/"] {
            if let Some(segment) = reference.strip_prefix(definitions) {
                return Some(format!("{base}{name}_{segment}"));
            }
        }
        reference
            .strip_prefix("#/")
            .map(|pointer| format!("{root}/{pointer}"))
    };
    if let Value::Object(map) = &mut schema {
        for definitions in ["$defs", "definitions"] {
            if let Some(Value::Object(found)) = map.remove(definitions) {
                for (key, mut definition) in found {
                    rewrite_refs(&mut definition, &rewrite);
                    store.insert(format!("{name}_{key}"), definition);
                }
            }
        }
    }
    rewrite_refs(&mut schema, &rewrite);
    store.insert(name.to_owned(), schema);
    serde_json::json!({ "$ref": root })
}
