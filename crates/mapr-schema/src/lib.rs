#![forbid(unsafe_code)]

pub mod exit_code;
pub mod node_id;
pub mod paths;
pub mod types;

pub use exit_code::ExitCode;
pub use node_id::{NodeId, NodeIdError};
pub use paths::derive_paths;
pub use types::*;

/// Current mapr trace schema version.
///
/// Bump this when making breaking changes to the output format.
/// Additive changes (new optional fields, new enum variants) do not require a bump.
pub const SCHEMA_VERSION: &str = "1";

/// Generate the JSON Schema for [`Trace`] as a pretty-printed JSON string.
///
/// The schema is derived from the Rust types via `schemars`. Never hand-edit
/// the committed schema file; regenerate it with this function instead.
pub fn generate_schema() -> String {
    let schema = schemars::schema_for!(Trace);
    serde_json::to_string_pretty(&schema).unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_codes() {
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::Error.as_i32(), 1);
        assert_eq!(ExitCode::PartialTrace.as_i32(), 2);
        assert_eq!(ExitCode::DiffChanges.as_i32(), 3);
        assert_eq!(ExitCode::ProbeHopFailure.as_i32(), 4);
    }

    #[test]
    fn schema_version_constant() {
        assert_eq!(SCHEMA_VERSION, "1");
    }

    #[test]
    fn generate_schema_is_valid_json() {
        let s = generate_schema();
        let v: serde_json::Value = serde_json::from_str(&s).expect("schema must be valid JSON");
        assert_eq!(v["title"], "Trace");
    }
}
