//! Contract test: the committed schema file must match what the Rust types generate.
//!
//! If this test fails, run `cargo run -p mapr-schema --example gen_schema`
//! to regenerate `schema/mapr-trace.schema.json`, then commit the result.

#![allow(clippy::unwrap_used, clippy::expect_used)]

const COMMITTED: &str = include_str!("../../../schema/mapr-trace.schema.json");

#[test]
fn committed_schema_matches_generated() {
    let generated = mapr_schema::generate_schema();
    // Normalise both through Value so whitespace differences don't matter.
    let committed_value: serde_json::Value =
        serde_json::from_str(COMMITTED).expect("committed schema is valid JSON");
    let generated_value: serde_json::Value =
        serde_json::from_str(&generated).expect("generated schema is valid JSON");

    if committed_value != generated_value {
        // Pretty-print the generated schema to help the developer see what changed.
        eprintln!(
            "Generated schema:\n{}",
            serde_json::to_string_pretty(&generated_value).unwrap_or_default()
        );
        panic!(
            "Committed schema (schema/mapr-trace.schema.json) is out of date.\n\
             Run `cargo run -p mapr-schema --example gen_schema` and commit the result."
        );
    }
}

#[test]
fn schema_has_required_top_level_fields() {
    let schema: serde_json::Value =
        serde_json::from_str(COMMITTED).expect("committed schema is valid JSON");
    // Verify the top-level object describes our Trace type.
    assert_eq!(schema["title"], "Trace", "schema title should be 'Trace'");
    let props = &schema["properties"];
    for field in &[
        "schema_version",
        "target",
        "generated_at",
        "stages_run",
        "nodes",
        "edges",
        "gaps",
        "paths",
    ] {
        assert!(props.get(field).is_some(), "schema missing field '{field}'");
    }
}
