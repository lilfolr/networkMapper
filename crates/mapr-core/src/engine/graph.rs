//! In-memory graph state for the frontier loop.
//!
//! `GraphState` accumulates nodes, edges, and gaps as stages run. It handles
//! deduplication by `NodeId` (for nodes) and by `(from, to, relation)` (for
//! edges). Evidence is merged onto existing records rather than creating
//! duplicates.

use std::collections::{HashMap, HashSet};

use mapr_schema::{Edge, Evidence, Gap, Node, NodeId, Relation};

/// Mutable graph state built up during an engine run.
///
/// Not publicly exposed; the engine owns it and converts it to a `Trace` at
/// the end.
#[derive(Debug, Default)]
pub struct GraphState {
    /// Nodes indexed by id for fast deduplication.
    nodes: HashMap<NodeId, Node>,
    /// Edges stored as a set keyed by (from, to, relation).
    edges: HashMap<(NodeId, NodeId, Relation), Edge>,
    /// Gaps accumulated across all stages.
    gaps: Vec<Gap>,
    /// Names of stages that ran, in order of first execution.
    stages_run: Vec<String>,
    /// Set used to deduplicate stage names.
    stages_run_set: HashSet<String>,
}

impl GraphState {
    /// Create an empty graph with a known seed node already inserted.
    pub fn with_seed(seed_node: Node) -> Self {
        let mut state = Self::default();
        state.nodes.insert(seed_node.id.clone(), seed_node);
        state
    }

    // -----------------------------------------------------------------------
    // Merging helpers
    // -----------------------------------------------------------------------

    /// Insert a node, or merge it with the existing one if the id is already
    /// known.
    ///
    /// Merging: evidence is appended; other fields from the incoming node are
    /// kept only if the existing node has no value for them (first-write wins
    /// for scalar fields, accumulate for evidence).
    pub fn merge_node(&mut self, incoming: Node) {
        let entry = self.nodes.entry(incoming.id.clone()).or_insert_with(|| {
            // Brand-new node: insert as-is.
            Node {
                id: incoming.id.clone(),
                kind: incoming.kind.clone(),
                provider: incoming.provider.clone(),
                service: incoming.service.clone(),
                name: incoming.name.clone(),
                identifier: incoming.identifier.clone(),
                attributes: incoming.attributes.clone(),
                evidence: Vec::new(),
            }
        });

        // Always append incoming evidence (avoid exact duplicates below).
        for ev in incoming.evidence {
            if !entry.evidence.iter().any(|e| {
                e.source == ev.source && e.detail == ev.detail && e.observed_at == ev.observed_at
            }) {
                entry.evidence.push(ev);
            }
        }

        // Fill in scalar fields that the existing node is missing.
        if entry.provider.is_none() {
            entry.provider = incoming.provider.clone();
        }
        if entry.service.is_none() {
            entry.service = incoming.service.clone();
        }
        if entry.identifier.is_none() {
            entry.identifier = incoming.identifier.clone();
        }
        // Merge attributes: incoming keys that don't already exist are added.
        for (k, v) in incoming.attributes {
            entry.attributes.entry(k).or_insert(v);
        }
    }

    /// Insert an edge, or merge evidence onto it if it already exists.
    pub fn merge_edge(&mut self, incoming: Edge) {
        let key = (
            incoming.from.clone(),
            incoming.to.clone(),
            incoming.relation.clone(),
        );
        let entry = self.edges.entry(key).or_insert_with(|| Edge {
            from: incoming.from.clone(),
            to: incoming.to.clone(),
            relation: incoming.relation.clone(),
            confidence: incoming.confidence,
            evidence: Vec::new(),
        });

        // Upgrade confidence to the stronger value (Verified > Observed > Inferred).
        if incoming.confidence > entry.confidence {
            entry.confidence = incoming.confidence;
        }

        for ev in incoming.evidence {
            if !entry.evidence.iter().any(|e| {
                e.source == ev.source && e.detail == ev.detail && e.observed_at == ev.observed_at
            }) {
                entry.evidence.push(ev);
            }
        }
    }

    /// Attach additional evidence to an existing node.
    ///
    /// If the node does not exist yet, this is a no-op (evidence without a
    /// node is dropped).
    pub fn attach_evidence(&mut self, node_id: &NodeId, ev: Evidence) {
        if let Some(node) = self.nodes.get_mut(node_id) {
            if !node.evidence.iter().any(|e| {
                e.source == ev.source && e.detail == ev.detail && e.observed_at == ev.observed_at
            }) {
                node.evidence.push(ev);
            }
        }
    }

    /// Push a gap onto the gap list.
    pub fn push_gap(&mut self, gap: Gap) {
        self.gaps.push(gap);
    }

    /// Record that a stage ran (deduplicates by name).
    pub fn record_stage(&mut self, name: &str) {
        if self.stages_run_set.insert(name.to_owned()) {
            self.stages_run.push(name.to_owned());
        }
    }

    // -----------------------------------------------------------------------
    // Query helpers
    // -----------------------------------------------------------------------

    /// Returns a reference to the node with this id if it exists.
    pub fn get_node(&self, id: &NodeId) -> Option<&Node> {
        self.nodes.get(id)
    }

    /// Returns `true` if a node with this id is already in the graph.
    pub fn contains_node(&self, id: &NodeId) -> bool {
        self.nodes.contains_key(id)
    }

    /// Number of nodes currently in the graph.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    // -----------------------------------------------------------------------
    // Finalisation
    // -----------------------------------------------------------------------

    /// Consume the graph state and return sorted, deterministic collections.
    ///
    /// Nodes are sorted by id; edges by (from, to, relation); gaps are in
    /// insertion order (first gap wins chronologically).
    pub fn finalise(self) -> (Vec<Node>, Vec<Edge>, Vec<Gap>, Vec<String>) {
        let mut nodes: Vec<Node> = self.nodes.into_values().collect();
        nodes.sort_by(|a, b| a.id.cmp(&b.id));

        // Sort evidence within each node for determinism.
        for node in &mut nodes {
            node.evidence.sort_by(|a, b| {
                a.source
                    .partial_cmp(&b.source)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.detail.cmp(&b.detail))
                    .then_with(|| a.observed_at.inner().cmp(&b.observed_at.inner()))
            });
        }

        let mut edges: Vec<Edge> = self.edges.into_values().collect();
        edges.sort_by(|a, b| {
            a.from
                .cmp(&b.from)
                .then_with(|| a.to.cmp(&b.to))
                .then_with(|| {
                    // Relation does not impl Ord; use the debug string as a proxy.
                    format!("{:?}", a.relation).cmp(&format!("{:?}", b.relation))
                })
        });

        // Sort evidence within each edge.
        for edge in &mut edges {
            edge.evidence.sort_by(|a, b| {
                a.source
                    .partial_cmp(&b.source)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.detail.cmp(&b.detail))
            });
        }

        (nodes, edges, self.gaps, self.stages_run)
    }
}

// ---------------------------------------------------------------------------
// PartialOrd for EvidenceSource (needed for sort in finalise).
// EvidenceSource is #[non_exhaustive] in schema; we use debug-string ordering.
// ---------------------------------------------------------------------------
trait PartialCmpDebug {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering>;
}

impl PartialCmpDebug for mapr_schema::EvidenceSource {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(format!("{self:?}").cmp(&format!("{other:?}")))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chrono::Utc;
    use mapr_schema::{Confidence, EvidenceSource, NodeKind, Relation, Timestamp};

    fn make_node(id_str: &str) -> Node {
        Node {
            id: NodeId::from_raw(id_str),
            kind: NodeKind::Hostname,
            provider: None,
            service: None,
            name: id_str.to_owned(),
            identifier: None,
            attributes: serde_json::Map::new(),
            evidence: Vec::new(),
        }
    }

    fn make_edge(from: &str, to: &str) -> Edge {
        Edge {
            from: NodeId::from_raw(from),
            to: NodeId::from_raw(to),
            relation: Relation::Cname,
            confidence: Confidence::Observed,
            evidence: Vec::new(),
        }
    }

    fn make_evidence(detail: &str) -> Evidence {
        Evidence {
            source: EvidenceSource::DnsQuery,
            detail: detail.to_owned(),
            observed_at: Timestamp::from(Utc::now()),
            attributes: serde_json::Map::new(),
        }
    }

    #[test]
    fn merge_new_node_is_inserted() {
        let seed = make_node("hostname:a");
        let mut g = GraphState::with_seed(seed);
        g.merge_node(make_node("hostname:b"));
        assert_eq!(g.node_count(), 2);
    }

    #[test]
    fn merge_duplicate_node_merges_evidence() {
        let seed = make_node("hostname:a");
        let mut g = GraphState::with_seed(seed);

        let mut dup = make_node("hostname:a");
        dup.evidence.push(make_evidence("first"));
        g.merge_node(dup);

        let mut dup2 = make_node("hostname:a");
        dup2.evidence.push(make_evidence("second"));
        g.merge_node(dup2);

        assert_eq!(g.node_count(), 1);
        let (nodes, _, _, _) = g.finalise();
        assert_eq!(nodes[0].evidence.len(), 2);
    }

    #[test]
    fn merge_duplicate_node_does_not_duplicate_evidence() {
        let seed = make_node("hostname:a");
        let mut g = GraphState::with_seed(seed);
        let ev = make_evidence("same");

        let mut dup = make_node("hostname:a");
        dup.evidence.push(ev.clone());
        g.merge_node(dup);

        let mut dup2 = make_node("hostname:a");
        dup2.evidence.push(ev);
        g.merge_node(dup2);

        let (nodes, _, _, _) = g.finalise();
        // Same source + detail + timestamp: only one evidence record.
        assert_eq!(nodes[0].evidence.len(), 1);
    }

    #[test]
    fn edge_deduplication_merges_evidence() {
        let seed = make_node("hostname:a");
        let mut g = GraphState::with_seed(seed);

        let edge = make_edge("hostname:a", "hostname:b");
        g.merge_edge(edge.clone());
        g.merge_edge(edge);

        let (_, edges, _, _) = g.finalise();
        assert_eq!(edges.len(), 1);
    }

    #[test]
    fn finalise_sorts_nodes_by_id() {
        let seed = make_node("hostname:z");
        let mut g = GraphState::with_seed(seed);
        g.merge_node(make_node("hostname:a"));
        g.merge_node(make_node("hostname:m"));

        let (nodes, _, _, _) = g.finalise();
        let ids: Vec<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, vec!["hostname:a", "hostname:m", "hostname:z"]);
    }

    #[test]
    fn finalise_sorts_edges() {
        let seed = make_node("hostname:a");
        let mut g = GraphState::with_seed(seed);
        g.merge_edge(make_edge("hostname:z", "hostname:a"));
        g.merge_edge(make_edge("hostname:a", "hostname:b"));

        let (_, edges, _, _) = g.finalise();
        assert_eq!(edges[0].from.as_str(), "hostname:a");
        assert_eq!(edges[1].from.as_str(), "hostname:z");
    }

    #[test]
    fn stages_run_deduplicates() {
        let seed = make_node("hostname:a");
        let mut g = GraphState::with_seed(seed);
        g.record_stage("dns");
        g.record_stage("dns");
        g.record_stage("classify");

        let (_, _, _, stages) = g.finalise();
        assert_eq!(stages, vec!["dns", "classify"]);
    }

    #[test]
    fn attach_evidence_to_existing_node() {
        let seed = make_node("hostname:a");
        let id = seed.id.clone();
        let mut g = GraphState::with_seed(seed);
        g.attach_evidence(&id, make_evidence("extra"));

        let (nodes, _, _, _) = g.finalise();
        assert_eq!(nodes[0].evidence.len(), 1);
    }

    #[test]
    fn attach_evidence_to_unknown_node_is_noop() {
        let seed = make_node("hostname:a");
        let mut g = GraphState::with_seed(seed);
        g.attach_evidence(&NodeId::from_raw("hostname:x"), make_evidence("lost"));

        let (nodes, _, _, _) = g.finalise();
        assert!(nodes[0].evidence.is_empty());
    }
}
