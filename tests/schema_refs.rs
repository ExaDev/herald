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
