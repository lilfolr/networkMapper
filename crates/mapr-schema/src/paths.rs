//! Path derivation over the trace graph.
//!
//! Given nodes, edges, and a start node, computes all root-to-leaf paths.
//! Safe against cycles: each path tracks its visited set.

use crate::NodeId;
use std::collections::{HashMap, HashSet};

/// An adjacency list mapping each node to its outgoing neighbors.
type AdjMap = HashMap<NodeId, Vec<NodeId>>;

/// Derive all simple paths from `start` to any leaf node in the graph.
///
/// A leaf is a node with no outgoing edges. If `start` is itself a leaf the
/// result is a single one-element path `[[start]]`.
///
/// The function is cycle-safe: a path never visits the same `NodeId` twice.
/// Branching (multiple outgoing edges) produces one path per branch.
/// Paths are returned in a deterministic order: edges are sorted before
/// traversal so repeated calls with the same input always return the same
/// output.
pub fn derive_paths(
    node_ids: &[NodeId],
    edges: &[(NodeId, NodeId)],
    start: &NodeId,
) -> Vec<Vec<NodeId>> {
    // Build adjacency map from the provided edges, filtering to nodes we know.
    let known: HashSet<&NodeId> = node_ids.iter().collect();
    let mut adj: AdjMap = HashMap::new();

    // Sort edges for determinism before building the map.
    let mut sorted_edges = edges.to_vec();
    sorted_edges.sort();

    for (from, to) in &sorted_edges {
        if known.contains(from) && known.contains(to) {
            adj.entry(from.clone()).or_default().push(to.clone());
        }
    }

    if !known.contains(start) {
        return vec![];
    }

    let mut results: Vec<Vec<NodeId>> = Vec::new();
    let mut path: Vec<NodeId> = vec![start.clone()];
    let mut visited: HashSet<NodeId> = HashSet::from([start.clone()]);

    dfs(start, &adj, &mut path, &mut visited, &mut results);

    results
}

fn dfs(
    node: &NodeId,
    adj: &AdjMap,
    path: &mut Vec<NodeId>,
    visited: &mut HashSet<NodeId>,
    results: &mut Vec<Vec<NodeId>>,
) {
    let neighbors = adj.get(node).map(Vec::as_slice).unwrap_or(&[]);

    // Filter out neighbors already on the current path (cycle prevention).
    let reachable: Vec<&NodeId> = neighbors.iter().filter(|n| !visited.contains(*n)).collect();

    if reachable.is_empty() {
        // Leaf node (or all neighbors would create a cycle): record the path.
        results.push(path.clone());
        return;
    }

    for next in reachable {
        path.push(next.clone());
        visited.insert(next.clone());
        dfs(next, adj, path, visited, results);
        path.pop();
        visited.remove(next);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn id(s: &str) -> NodeId {
        NodeId::from_raw(s)
    }

    fn edge(a: &str, b: &str) -> (NodeId, NodeId) {
        (id(a), id(b))
    }

    // Helper: sort paths for deterministic comparison.
    fn sorted(mut paths: Vec<Vec<NodeId>>) -> Vec<Vec<NodeId>> {
        paths.sort();
        paths
    }

    // --- Linear chain: A -> B -> C ---
    #[test]
    fn linear_chain() {
        let nodes = vec![id("a"), id("b"), id("c")];
        let edges = vec![edge("a", "b"), edge("b", "c")];
        let paths = derive_paths(&nodes, &edges, &id("a"));
        assert_eq!(paths, vec![vec![id("a"), id("b"), id("c")]]);
    }

    // --- Single node (leaf) ---
    #[test]
    fn single_node_leaf() {
        let nodes = vec![id("a")];
        let edges = vec![];
        let paths = derive_paths(&nodes, &edges, &id("a"));
        assert_eq!(paths, vec![vec![id("a")]]);
    }

    // --- Branching: A -> B, A -> C ---
    #[test]
    fn branching() {
        let nodes = vec![id("a"), id("b"), id("c")];
        let edges = vec![edge("a", "b"), edge("a", "c")];
        let paths = sorted(derive_paths(&nodes, &edges, &id("a")));
        assert_eq!(paths, vec![vec![id("a"), id("b")], vec![id("a"), id("c")],]);
    }

    // --- Diamond: A -> B -> D, A -> C -> D (two routes to one node) ---
    #[test]
    fn diamond() {
        let nodes = vec![id("a"), id("b"), id("c"), id("d")];
        let edges = vec![
            edge("a", "b"),
            edge("a", "c"),
            edge("b", "d"),
            edge("c", "d"),
        ];
        let paths = sorted(derive_paths(&nodes, &edges, &id("a")));
        assert_eq!(
            paths,
            vec![
                vec![id("a"), id("b"), id("d")],
                vec![id("a"), id("c"), id("d")],
            ]
        );
    }

    // --- Cycle: A -> B -> C -> A ---
    // The cycle should be broken; we emit only the prefix up to the repeated node.
    #[test]
    fn cycle_does_not_loop() {
        let nodes = vec![id("a"), id("b"), id("c")];
        let edges = vec![edge("a", "b"), edge("b", "c"), edge("c", "a")];
        let paths = derive_paths(&nodes, &edges, &id("a"));
        // C has only one outgoing edge back to A which is already visited,
        // so C is treated as a leaf. The single path is A -> B -> C.
        assert_eq!(paths, vec![vec![id("a"), id("b"), id("c")]]);
    }

    // --- Self-loop: A -> A ---
    #[test]
    fn self_loop() {
        let nodes = vec![id("a")];
        let edges = vec![edge("a", "a")];
        let paths = derive_paths(&nodes, &edges, &id("a"));
        // A's only neighbor is itself, already visited: treat as leaf.
        assert_eq!(paths, vec![vec![id("a")]]);
    }

    // --- Start not in node list ---
    #[test]
    fn start_not_in_nodes_returns_empty() {
        let nodes = vec![id("a"), id("b")];
        let edges = vec![edge("a", "b")];
        let paths = derive_paths(&nodes, &edges, &id("x"));
        assert!(paths.is_empty());
    }

    // --- Determinism across repeated calls ---
    #[test]
    fn deterministic_output() {
        let nodes = vec![id("a"), id("b"), id("c"), id("d")];
        let edges = vec![
            edge("a", "b"),
            edge("a", "c"),
            edge("b", "d"),
            edge("c", "d"),
        ];
        let first = sorted(derive_paths(&nodes, &edges, &id("a")));
        let second = sorted(derive_paths(&nodes, &edges, &id("a")));
        assert_eq!(first, second);
    }
}
