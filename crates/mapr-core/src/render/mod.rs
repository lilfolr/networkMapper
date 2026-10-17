use mapr_schema::Trace;
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

/// Pure function: render a trace into the specified format string.
///
/// Takes a `Trace` and returns a `String`. No network, no credentials, no side effects.
pub fn render_trace(trace: &Trace, format: OutputFormat) -> Result<String, CoreError> {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(trace).map_err(CoreError::from),
        OutputFormat::Text => Ok(render_text(trace)),
        OutputFormat::Mermaid => Ok(render_mermaid(trace)),
        OutputFormat::Dot => Ok(render_dot(trace)),
        OutputFormat::Html => Ok(render_html(trace)),
    }
}

fn render_text(trace: &Trace) -> String {
    let mut out = String::new();
    out.push_str(&format!("Target: {}\n", trace.target.input));
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
            "  {} -> {} [{:?}|{:?}]\n",
            edge.from, edge.to, edge.relation, edge.confidence
        ));
    }
    if !trace.gaps.is_empty() {
        out.push_str(&format!("Gaps: {}\n", trace.gaps.len()));
        for gap in &trace.gaps {
            let at = gap
                .at
                .as_ref()
                .map(|n| n.as_str().to_owned())
                .unwrap_or_else(|| "unknown".to_owned());
            out.push_str(&format!("  At {at}: {:?} ({})\n", gap.reason, gap.detail));
        }
    }
    out
}

fn render_mermaid(trace: &Trace) -> String {
    let mut out = String::from("flowchart TD\n");
    for node in &trace.nodes {
        let label = node.identifier.as_deref().unwrap_or(node.id.as_str());
        out.push_str(&format!("  {}[\"{}\"]\n", node.id, label));
    }
    for edge in &trace.edges {
        out.push_str(&format!(
            "  {} -->|{:?}| {}\n",
            edge.from, edge.relation, edge.to
        ));
    }
    out
}

fn render_dot(trace: &Trace) -> String {
    let mut out = String::from("digraph trace {\n  rankdir=LR;\n");
    for node in &trace.nodes {
        let label = node.identifier.as_deref().unwrap_or(node.id.as_str());
        out.push_str(&format!("  \"{}\" [label=\"{}\"];\n", node.id, label));
    }
    for edge in &trace.edges {
        out.push_str(&format!(
            "  \"{}\" -> \"{}\" [label=\"{:?}\"];\n",
            edge.from, edge.to, edge.relation
        ));
    }
    out.push_str("}\n");
    out
}

fn render_html(trace: &Trace) -> String {
    let text = render_text(trace);
    format!(
        "<!DOCTYPE html>\n<html>\n<head><title>Trace: {}</title></head>\n<body>\n<pre>{}</pre>\n</body>\n</html>\n",
        trace.target.input, text
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use mapr_schema::{Target, TargetKind, Timestamp, SCHEMA_VERSION};

    fn sample_trace() -> Trace {
        Trace {
            schema_version: SCHEMA_VERSION.to_string(),
            target: Target {
                input: "example.com".to_string(),
                kind: TargetKind::Hostname,
            },
            generated_at: Timestamp::from(Utc::now()),
            stages_run: Vec::new(),
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
