use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Confidence level for trace edges.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Confirmed via provider API inspection.
    Verified,
    /// Seen on the wire: DNS, response headers, TLS certs.
    Observed,
    /// Heuristic or statistical inference.
    Inferred,
}

/// Structured evidence supporting a node or edge in the graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    /// Source of the evidence (e.g. dns, http_header, tls_cert, aws_api).
    pub source: String,
    /// Detailed observation data or raw response snippet.
    pub detail: String,
    /// Timestamp when evidence was recorded (ISO 8601 string).
    pub observed_at: String,
}

/// Reasons why a trace path cannot be continued further.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    NoCredentials,
    AccessDenied,
    UnsupportedService,
    Timeout,
    ResolutionFailure,
    Unknown,
}

/// A recorded gap in the trace where inspection stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Gap {
    /// Identifier or placeholder of the node where traversal halted.
    pub at_node: String,
    /// Categorized reason for the gap.
    pub reason: GapReason,
    /// Detailed diagnostic message explaining what failed.
    pub detail: Option<String>,
}

/// High-level categorization of a network or cloud entity.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    DnsName,
    IpAddress,
    Cdn,
    LoadBalancer,
    Compute,
    Storage,
    ApiGateway,
    Unknown,
}

/// A node in the trace graph representing an infrastructure component.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Node {
    /// Internal graph ID (unique within the trace).
    pub id: String,
    /// Real provider identifier (e.g. ARN or resource ID) when known.
    pub identifier: Option<String>,
    /// Closed classification of node type.
    pub kind: NodeKind,
    /// Specific service name (e.g. cloudfront, route53, alb).
    pub service: Option<String>,
    /// Provider or network specific attributes.
    pub attributes: serde_json::Map<String, serde_json::Value>,
    /// Evidentiary records backing this node.
    pub evidence: Vec<Evidence>,
}

/// A directed edge connecting two infrastructure nodes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Edge {
    /// Source node ID.
    pub from: String,
    /// Destination node ID.
    pub to: String,
    /// Confidence level in this hop.
    pub confidence: Confidence,
    /// Evidentiary records backing this connection.
    pub evidence: Vec<Evidence>,
}

/// Complete trace graph representing request routing to a target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TraceGraph {
    /// Schema version for format stability.
    pub schema_version: String,
    /// Target queried (hostname, IP, CIDR, etc.).
    pub target: String,
    /// Discovered nodes.
    pub nodes: Vec<Node>,
    /// Discovered edges connecting nodes.
    pub edges: Vec<Edge>,
    /// Unresolved gaps encountered during tracing.
    pub gaps: Vec<Gap>,
    /// Derived end-to-end paths derived from the graph topology.
    pub paths: Vec<Vec<String>>,
}
