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
        "#/components/schemas/c0_input_d0"
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
        store["c0_input_d0"]["properties"]["back"]["$ref"],
        "#/components/schemas/c0_input"
    );
    assert_eq!(
        store["c0_input_d0"]["properties"]["d"]["$ref"],
        "#/components/schemas/c0_input_f0"
    );
    assert_eq!(store["c0_input_f0"]["type"], "integer");
}

#[test]
fn definitions_with_awkward_or_repeated_names_get_distinct_component_names() {
    use herald::schema_refs::lift_schema;
    let schema = json!({
        "properties": {
            "a": {"$ref": "#/$defs/A"},
            "b": {"$ref": "#/definitions/A"},
            "c": {"$ref": "#/$defs/Foo Bar"},
            "d": {"$ref": "#/$defs/x~1y/properties/z"}
        },
        "$defs": {"A": {"type": "string"}, "Foo Bar": {"type": "integer"}, "x/y": {"properties": {"z": {"type": "null"}}}},
        "definitions": {"A": {"type": "boolean"}}
    });
    let mut store = serde_json::Map::new();
    lift_schema(&schema, "n", &mut store, "#/components/schemas/");
    let root = &store["n"];
    let target = |property: &str| {
        let reference = root["properties"][property]["$ref"].as_str().unwrap();
        let rest = reference.strip_prefix("#/components/schemas/").unwrap();
        assert!(
            rest.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'/' | b'-' | b'.')),
            "{rest}"
        );
        rest.to_owned()
    };
    assert_eq!(store[target("a").as_str()]["type"], "string");
    assert_eq!(store[target("b").as_str()]["type"], "boolean");
    assert_eq!(store[target("c").as_str()]["type"], "integer");
    let nested = target("d");
    let (component, pointer) = nested.split_once('/').unwrap();
    assert_eq!(pointer, "properties/z");
    assert!(store[component]["properties"]["z"].is_object());
}

#[test]
fn a_schema_embedded_in_a_document_loses_its_root_dialect() {
    use herald::schema_refs::lift_schema;
    // What a schema generator emits: the dialect at the root.
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"p": {"$ref": "#/$defs/P"}},
        "$defs": {"P": {"type": "integer"}}
    });
    let mut store = serde_json::Map::new();
    lift_schema(&schema, "n", &mut store, "#/components/schemas/");
    for (name, lifted) in &store {
        assert!(lifted.get("$schema").is_none(), "{name}");
    }
    assert_eq!(store["n"]["type"], "object");
    assert_eq!(store["n_d0"]["type"], "integer");
}

#[test]
fn a_fragment_with_escapes_and_a_dependency_named_like_data_are_still_rewritten() {
    use herald::schema_refs::lift_schema;
    let schema = json!({
        "properties": {"a": {"$ref": "#/$defs/a%20b"}},
        "dependencies": {"enum": {"$ref": "#/$defs/a%20b"}},
        "$defs": {"a b": {"type": "integer"}}
    });
    let mut store = serde_json::Map::new();
    lift_schema(&schema, "n", &mut store, "#/components/schemas/");
    assert_eq!(
        store["n"]["properties"]["a"]["$ref"],
        "#/components/schemas/n_d0"
    );
    assert_eq!(
        store["n"]["dependencies"]["enum"]["$ref"],
        "#/components/schemas/n_d0"
    );
}

#[test]
fn only_a_schema_that_publishes_as_the_same_thing_it_enforces_is_publishable() {
    use herald::schema_refs::check_publishable;
    for good in [
        json!({"type": "object"}),
        json!({"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}),
        json!({"$schema": "https://json-schema.org/draft/2020-12/schema#"}),
        // A property that happens to be called `$id` is a property, not a keyword.
        json!({"properties": {"$id": {"type": "string"}, "$anchor": true}}),
        json!({"enum": [{"$id": "data"}]}),
        json!(true),
    ] {
        assert!(check_publishable(&good).is_ok(), "{good}");
    }
    for bad in [
        json!({"$schema": "http://json-schema.org/draft-07/schema#"}),
        json!({"properties": {"a": {"$schema": "https://json-schema.org/draft/2020-12/schema"}}}),
        json!({"$id": "https://example.test/x"}),
        json!({"$defs": {"A": {"$id": "a.json"}}}),
        json!({"properties": {"a": {"$anchor": "x"}}}),
        json!({"$dynamicRef": "#x"}),
        json!({"$recursiveRef": "#"}),
        json!({"items": [{"$id": "x"}]}),
    ] {
        assert!(check_publishable(&bad).is_err(), "{bad}");
    }
}
