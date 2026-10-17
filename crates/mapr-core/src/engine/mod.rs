use mapr_schema::{ExitCode, TraceGraph, SCHEMA_VERSION};

use crate::error::CoreError;

/// Configuration options for the trace engine.
#[derive(Debug, Clone, Default)]
pub struct EngineConfig {
    pub offline: bool,
    pub no_prompt: bool,
    pub timeout_seconds: Option<u64>,
}

/// Trace engine entrypoint stub.
pub fn execute_trace(
    target: &str,
    _config: &EngineConfig,
) -> Result<(TraceGraph, ExitCode), CoreError> {
    let graph = TraceGraph {
        schema_version: SCHEMA_VERSION.to_string(),
        target: target.to_string(),
        nodes: Vec::new(),
        edges: Vec::new(),
        gaps: Vec::new(),
        paths: Vec::new(),
    };
    Ok((graph, ExitCode::Success))
}
