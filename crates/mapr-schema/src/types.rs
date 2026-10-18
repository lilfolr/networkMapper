//! Core output types for the mapr trace schema.
//!
//! All types derive `Serialize`/`Deserialize` with `snake_case` and
//! `JsonSchema`. Public enums are `#[non_exhaustive]` so adding a variant is
//! not a breaking change for downstream consumers.

use chrono::{DateTime, Utc};
use schemars::schema::{InstanceType, SchemaObject};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::NodeId;

// ---------------------------------------------------------------------------
// Timestamp newtype
//
// schemars 0.8 does not implement JsonSchema for chrono::DateTime<Utc>.
// We wrap it in a newtype and provide a hand-written impl that describes it
// as an ISO 8601 / RFC 3339 string. The serde impl delegates to chrono so
// the wire format is unchanged.
// ---------------------------------------------------------------------------

/// An RFC 3339 / ISO 8601 UTC timestamp.
///
/// Serializes as a string (e.g. `"2025-01-02T03:04:05Z"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(pub DateTime<Utc>);

impl Timestamp {
    /// Returns the inner `DateTime<Utc>`.
    pub fn inner(&self) -> DateTime<Utc> {
        self.0
    }
}

impl From<DateTime<Utc>> for Timestamp {
    fn from(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }
}

impl JsonSchema for Timestamp {
    fn schema_name() -> String {
        "Timestamp".to_owned()
    }

    fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::Schema::Object(SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            format: Some("date-time".to_owned()),
            ..Default::default()
        })
    }
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Cloud or network provider.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Aws,
    Cloudflare,
    Fastly,
    Akamai,
    Unknown,
}

/// High-level categorization of a network or cloud entity.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Hostname,
    Ip,
    Cidr,
    Cdn,
    LoadBalancer,
    Gateway,
    Compute,
    Unknown,
}

/// The semantic relationship captured by an edge.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Relation {
    /// A CNAME record pointing from one name to another.
    Cname,
    /// An A or AAAA record resolving a name to an IP.
    ResolvesTo,
    /// An IP or hostname is fronted by a CDN or load balancer.
    ServedBy,
    /// Traffic is routed from one node to another (e.g. ALB to ECS task).
    RoutesTo,
}

/// Confidence level for nodes and edges.
///
/// Ordered from weakest to strongest: `Inferred < Observed < Verified`.
#[non_exhaustive]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Heuristic or statistical inference.
    Inferred,
    /// Seen on the wire: DNS, response headers, TLS certs.
    Observed,
    /// Confirmed via provider API inspection.
    Verified,
}

/// Where a piece of evidence came from.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    DnsQuery,
    IpRange,
    ReverseDns,
    Reachability,
    Tls,
    Http,
    AwsApi,
    Unknown,
}

/// Reasons why a trace path could not be continued.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GapReason {
    NoCredentials,
    AccessDenied,
    UnsupportedService,
    Timeout,
    BudgetExceeded,
    Nxdomain,
    DnsFailure,
    NetworkError,
    NoRangeData,
    Private,
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// A provider and the IAM permissions needed to fill a gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Needs {
    /// Provider that holds the missing information.
    pub provider: Provider,
    /// IAM actions (or equivalent) required to fill the gap.
    pub permissions: Vec<String>,
}

/// A recorded gap: a point where the trace could not continue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Gap {
    /// Node where traversal halted, if known.
    pub at: Option<NodeId>,
    /// Categorized reason.
    pub reason: GapReason,
    /// Human-readable diagnostic message.
    pub detail: String,
    /// Provider and permissions needed to fill this gap (for later phases).
    pub needs: Option<Needs>,
}

/// Structured evidence backing a node or edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    /// Where the evidence came from.
    pub source: EvidenceSource,
    /// Raw observation or summary string.
    pub detail: String,
    /// When the evidence was recorded (RFC 3339 UTC string on the wire).
    pub observed_at: Timestamp,
    /// Source-specific extra data (resolver address, TTL, range sync token, ...).
    pub attributes: serde_json::Map<String, serde_json::Value>,
}

/// A node in the trace graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Node {
    /// Stable, canonical identifier for this node.
    pub id: NodeId,
    /// High-level classification.
    pub kind: NodeKind,
    /// Cloud provider, if known.
    pub provider: Option<Provider>,
    /// Specific service name (e.g. "cloudfront", "ec2", "alb").
    pub service: Option<String>,
    /// Human-readable label (hostname, IP string, ARN short name, ...).
    pub name: String,
    /// Real provider identifier (ARN, resource ID) when known.
    pub identifier: Option<String>,
    /// Provider- or service-specific attributes.
    pub attributes: serde_json::Map<String, serde_json::Value>,
    /// Evidence records that support this node.
    pub evidence: Vec<Evidence>,
}

/// A directed edge connecting two nodes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Edge {
    /// Source node.
    pub from: NodeId,
    /// Destination node.
    pub to: NodeId,
    /// Semantic relationship.
    pub relation: Relation,
    /// How confident we are in this edge.
    pub confidence: Confidence,
    /// Evidence records that support this edge.
    pub evidence: Vec<Evidence>,
}

/// The original input and its inferred kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Target {
    /// The raw string the user supplied.
    pub input: String,
    /// How the input was interpreted.
    pub kind: TargetKind,
}

/// Classification of the user's input.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Hostname,
    Ip,
    Cidr,
}

/// Complete trace graph representing how a request reaches its destination.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Trace {
    /// Schema format version. Bump on breaking changes.
    pub schema_version: String,
    /// The original input that was traced.
    pub target: Target,
    /// When the trace was generated (RFC 3339 UTC string on the wire).
    pub generated_at: Timestamp,
    /// Names of the stages that ran, in execution order.
    pub stages_run: Vec<String>,
    /// All nodes discovered, sorted by id.
    pub nodes: Vec<Node>,
    /// All edges discovered, sorted by (from, to, relation).
    pub edges: Vec<Edge>,
    /// Gaps where the trace could not continue.
    pub gaps: Vec<Gap>,
    /// Derived end-to-end paths (computed from the graph, never hand-built).
    pub paths: Vec<Vec<NodeId>>,
}
