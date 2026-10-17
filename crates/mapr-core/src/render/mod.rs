use mapr_schema::TraceGraph;
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// Supported output render formats.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Text,
    Json,
    Mermaid,
    Dot,
    Html,
}

impl std::str::FromStr for OutputFormat {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "mermaid" => Ok(Self::Mermaid),
            "dot" => Ok(Self::Dot),
            "html" => Ok(Self::Html),
            other => Err(CoreError::Render(format!(
                "Unsupported output format '{other}', expected one of: text, json, mermaid, dot, html"
            ))),
        }
    }
}

/// Pure function rendering a trace graph into the specified format.
pub fn render_trace(trace: &TraceGraph, format: OutputFormat) -> Result<String, CoreError> {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(trace).map_err(CoreError::from),
        OutputFormat::Text => Ok(render_text(trace)),
        OutputFormat::Mermaid => Ok(render_mermaid(trace)),
        OutputFormat::Dot => Ok(render_dot(trace)),
        OutputFormat::Html => Ok(render_html(trace)),
    }
}

fn render_text(trace: &TraceGraph) -> String {
    let mut out = String::new();
    out.push_str(&format!("Target: {}\n", trace.target));
    out.push_str(&format!("Schema Version: {}\n", trace.schema_version));
    out.push_str(&format!("Nodes: {}\n", trace.nodes.len()));
    for node in &trace.nodes {
        let identifier = node.identifier.as_deref().unwrap_or("none");
        let service = node.service.as_deref().unwrap_or("generic");
        out.push_str(&format!(
            "  [{:?}] {} (service: {}, identifier: {})\n",
            node.kind, node.id, service, identifier
        ));
    }
    out.push_str(&format!("Edges: {}\n", trace.edges.len()));
    for edge in &trace.edges {
        out.push_str(&format!(
            "  {} -> {} [{:?}]\n",
            edge.from, edge.to, edge.confidence
        ));
    }
    if !trace.gaps.is_empty() {
        out.push_str(&format!("Gaps: {}\n", trace.gaps.len()));
        for gap in &trace.gaps {
            let detail = gap.detail.as_deref().unwrap_or("no details");
            out.push_str(&format!(
                "  At node {}: {:?} ({})\n",
                gap.at_node, gap.reason, detail
            ));
        }
    }
    out
}

fn render_mermaid(trace: &TraceGraph) -> String {
    let mut out = String::from("flowchart TD\n");
    for node in &trace.nodes {
        let label = node.identifier.as_deref().unwrap_or(&node.id);
        out.push_str(&format!("  {}[\"{}\"]\n", node.id, label));
    }
    for edge in &trace.edges {
        out.push_str(&format!(
            "  {} -->|{:?}| {}\n",
            edge.from, edge.confidence, edge.to
        ));
    }
    out
}

fn render_dot(trace: &TraceGraph) -> String {
    let mut out = String::from("digraph trace {\n  rankdir=LR;\n");
    for node in &trace.nodes {
        let label = node.identifier.as_deref().unwrap_or(&node.id);
        out.push_str(&format!("  \"{}\" [label=\"{}\"];\n", node.id, label));
    }
    for edge in &trace.edges {
        out.push_str(&format!(
            "  \"{}\" -> \"{}\" [label=\"{:?}\"];\n",
            edge.from, edge.to, edge.confidence
        ));
    }
    out.push_str("}\n");
    out
}

fn render_html(trace: &TraceGraph) -> String {
    let text = render_text(trace);
    format!(
        "<!DOCTYPE html>\n<html>\n<head><title>Trace: {}</title></head>\n<body>\n<pre>{}</pre>\n</body>\n</html>\n",
        trace.target, text
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mapr_schema::SCHEMA_VERSION;

    fn sample_trace() -> TraceGraph {
        TraceGraph {
            schema_version: SCHEMA_VERSION.to_string(),
            target: "example.com".to_string(),
            nodes: Vec::new(),
            edges: Vec::new(),
            gaps: Vec::new(),
            paths: Vec::new(),
        }
    }

    #[test]
    fn test_render_formats() {
        let trace = sample_trace();
        assert!(render_trace(&trace, OutputFormat::Json).is_ok());
        assert!(render_trace(&trace, OutputFormat::Text).is_ok());
        assert!(render_trace(&trace, OutputFormat::Mermaid).is_ok());
        assert!(render_trace(&trace, OutputFormat::Dot).is_ok());
        assert!(render_trace(&trace, OutputFormat::Html).is_ok());
    }
}
