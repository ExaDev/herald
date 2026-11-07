//! Rewriting the `$ref` pointers of a JSON Schema when the schema is moved inside a larger document, as the adapters do when they embed a capability's schema in a tool or an OpenAPI document.

use serde_json::Value;

/// Keywords whose value is instance data, not a schema: a `$ref` key inside it is data.
const DATA_KEYWORDS: [&str; 4] = ["enum", "const", "default", "examples"];

/// Keywords whose value maps names to schemas, so their keys are names and not keywords.
const SCHEMA_MAPS: [&str; 6] = [
    "properties",
    "$defs",
    "definitions",
    "patternProperties",
    "dependentSchemas",
    "dependencies",
];

/// Replaces every `$ref` in `schema` for which `rewrite` returns a new pointer. A `$ref` inside instance data (`enum`, `const`, `default`, `examples`) is left alone, and a property that happens to be named like a keyword is treated as a property.
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

/// Stores `schema` in `store` under `name`, with the definitions it carries beside it, and returns a reference to it. `base` is where `store` is reachable from the final document root (`#/components/schemas/` or `#/$defs/`). Every pointer inside the schema is rewritten to its new location, so `#`, `#/$defs/X`, `#/definitions/X` and `#/properties/y` still resolve. Definitions are named by keyword and position (`<name>_d0`, `<name>_f0`), not by their own names, which may repeat across `$defs` and `definitions` or contain characters a document's component names do not allow. `name` must be unique within `store` and made of such characters.
pub fn lift_schema(
    schema: &Value,
    name: &str,
    store: &mut serde_json::Map<String, Value>,
    base: &str,
) -> Value {
    /// The two keywords that hold definitions, with the letter each is named by.
    const KEYWORDS: [(&str, &str, char); 2] = [
        ("$defs", "#/$defs/", 'd'),
        ("definitions", "#/definitions/", 'f'),
    ];
    let mut schema = schema.clone();
    strip_resource_keywords(&mut schema);
    let root = format!("{base}{name}");
    // (pointer prefix, definition key) -> the component it becomes
    let mut renamed: Vec<(&str, String, String)> = Vec::new();
    let mut lifted: Vec<(String, Value)> = Vec::new();
    if let Value::Object(map) = &mut schema {
        for (keyword, prefix, letter) in KEYWORDS {
            if let Some(Value::Object(found)) = map.remove(keyword) {
                for (index, (key, definition)) in found.into_iter().enumerate() {
                    let component = format!("{name}_{letter}{index}");
                    renamed.push((prefix, key, component.clone()));
                    lifted.push((component, definition));
                }
            }
        }
    }
    let rewrite = |reference: &str| -> Option<String> {
        let decoded = percent_decode(reference);
        let reference = decoded.as_str();
        if reference == "#" {
            return Some(root.clone());
        }
        for (prefix, key, component) in &renamed {
            // A pointer segment escapes `~` as `~0` and `/` as `~1`.
            let escaped = key.replace('~', "~0").replace('/', "~1");
            if let Some(rest) = reference.strip_prefix(&format!("{prefix}{escaped}"))
                && (rest.is_empty() || rest.starts_with('/'))
            {
                return Some(format!("{base}{component}{rest}"));
            }
        }
        reference
            .strip_prefix("#/")
            .map(|pointer| format!("{root}/{pointer}"))
    };
    for (component, mut definition) in lifted {
        rewrite_refs(&mut definition, &rewrite);
        store.insert(component, definition);
    }
    rewrite_refs(&mut schema, &rewrite);
    store.insert(name.to_owned(), schema);
    serde_json::json!({ "$ref": root })
}

/// Removes `$schema` from the root of a schema about to be embedded in a larger document. A schema generator emits it at the root, and a schema nested in a document does not name its own dialect.
pub fn strip_resource_keywords(schema: &mut Value) {
    if let Value::Object(map) = schema {
        map.remove("$schema");
    }
}

/// The only dialect a contract schema may name. The published copy of a schema is read as this dialect by every document it is embedded in, so a schema written for another would be enforced one way and described another.
pub const DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// Keywords that make a schema, or part of it, a resource of its own or a target for anchored references. Embedding moves a schema into another document, where such a keyword would change what its references mean or collide with another schema's.
const RESOURCE_KEYWORDS: [&str; 6] = [
    "$id",
    "$anchor",
    "$dynamicRef",
    "$dynamicAnchor",
    "$recursiveRef",
    "$recursiveAnchor",
];

/// Whether `schema` can be published inside another document and mean the same there: it names no dialect other than [`DIALECT`], and nothing in it makes a part of it a resource of its own. Returns what is wrong, for a registration error.
pub fn check_publishable(schema: &Value) -> Result<(), String> {
    fn walk(schema: &Value, root: bool) -> Result<(), String> {
        match schema {
            Value::Object(map) => {
                for (key, value) in map {
                    if key == "$schema" {
                        match value.as_str() {
                            Some(dialect) if root && dialect.trim_end_matches('#') == DIALECT => {}
                            _ if root => {
                                return Err(format!("only the {DIALECT} dialect is supported"));
                            }
                            _ => return Err("`$schema` is only allowed at a schema's root".into()),
                        }
                    } else if RESOURCE_KEYWORDS.contains(&key.as_str()) {
                        return Err(format!("`{key}` is not supported in a contract schema"));
                    } else if DATA_KEYWORDS.contains(&key.as_str()) {
                    } else if SCHEMA_MAPS.contains(&key.as_str()) {
                        if let Value::Object(children) = value {
                            for child in children.values() {
                                walk(child, false)?;
                            }
                        }
                    } else {
                        walk(value, false)?;
                    }
                }
                Ok(())
            }
            Value::Array(items) => items.iter().try_for_each(|item| walk(item, false)),
            _ => Ok(()),
        }
    }
    walk(schema, true)
}

/// A URI fragment with its `%XX` escapes decoded, so a pointer such as `#/$defs/a%20b` matches the definition `a b`. A sequence that is not a valid escape is left as it is.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(high), Some(low)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push(high * 16 + low);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(byte: u8) -> Option<u8> {
    (byte as char).to_digit(16).map(|digit| digit as u8)
}
