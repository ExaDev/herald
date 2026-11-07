use herald::schema_refs::rewrite_refs;
use serde_json::json;

fn to_components(reference: &str) -> Option<String> {
    reference
        .strip_prefix("#/$defs/")
        .map(|name| format!("#/components/{name}"))
}

#[test]
fn references_are_rewritten_in_schema_positions_only() {
    let mut schema = json!({
        "properties": {
            "a": {"$ref": "#/$defs/A"},
            "enum": {"$ref": "#/$defs/B"},
            "list": {"items": [{"$ref": "#/$defs/C"}]}
        },
        "enum": [{"$ref": "#/$defs/data"}],
        "default": {"$ref": "#/$defs/data"},
        "$defs": {"A": {"$ref": "#/$defs/D"}},
        "$ref": "#/$defs/Root"
    });
    rewrite_refs(&mut schema, &to_components);
    assert_eq!(schema["properties"]["a"]["$ref"], "#/components/A");
    assert_eq!(
        schema["properties"]["enum"]["$ref"], "#/components/B",
        "a property named like a keyword is still a property"
    );
    assert_eq!(
        schema["properties"]["list"]["items"][0]["$ref"],
        "#/components/C"
    );
    assert_eq!(
        schema["enum"][0]["$ref"], "#/$defs/data",
        "data is left alone"
    );
    assert_eq!(schema["default"]["$ref"], "#/$defs/data");
    assert_eq!(schema["$defs"]["A"]["$ref"], "#/components/D");
    assert_eq!(schema["$ref"], "#/components/Root");
}

#[test]
fn a_reference_the_rewrite_declines_is_unchanged() {
    let mut schema = json!({"$ref": "#"});
    rewrite_refs(&mut schema, &to_components);
    assert_eq!(schema["$ref"], "#");
}

#[test]
fn a_lifted_schema_and_its_definitions_resolve_from_the_new_base() {
    use herald::schema_refs::lift_schema;
    let schema = json!({
        "type": "object",
        "properties": {"p": {"$ref": "#/$defs/P"}, "me": {"$ref": "#"}, "q": {"$ref": "#/properties/p"}},
        "$defs": {"P": {"properties": {"back": {"$ref": "#"}, "d": {"$ref": "#/definitions/D"}}}},
        "definitions": {"D": {"type": "integer"}}
    });
    let mut store = serde_json::Map::new();
    let reference = lift_schema(&schema, "c0_input", &mut store, "#/components/schemas/");
    assert_eq!(reference, json!({"$ref": "#/components/schemas/c0_input"}));
    let root = &store["c0_input"];
    assert!(root.get("$defs").is_none() && root.get("definitions").is_none());
    assert_eq!(
        root["properties"]["p"]["$ref"],
        "#/components/schemas/c0_input_P"
    );
    assert_eq!(
        root["properties"]["me"]["$ref"],
        "#/components/schemas/c0_input"
    );
    assert_eq!(
        root["properties"]["q"]["$ref"],
        "#/components/schemas/c0_input/properties/p"
    );
    assert_eq!(
        store["c0_input_P"]["properties"]["back"]["$ref"],
        "#/components/schemas/c0_input"
    );
    assert_eq!(
        store["c0_input_P"]["properties"]["d"]["$ref"],
        "#/components/schemas/c0_input_D"
    );
    assert_eq!(store["c0_input_D"]["type"], "integer");
}
