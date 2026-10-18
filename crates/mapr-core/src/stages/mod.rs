//! Stage trait and supporting types.
//!
//! Each stage is an independent, composable unit of discovery. It accepts a
//! node, queries external systems via the trait objects in `Context`, and
//! returns additions (new nodes, edges, evidence) and gaps. A stage never
//! mutates the graph in place; the engine merges the output.

pub mod aws;
pub mod classify;
pub mod dns;
pub mod fingerprint;
pub mod reachability;
pub mod reverse_dns;

use std::sync::Arc;

use async_trait::async_trait;
use mapr_schema::{Edge, Evidence, Gap, Node, NodeId};

use crate::engine::context::Context;

/// Privilege tier of a stage.
///
/// The engine takes a maximum allowed `Tier` and skips stages above it.
/// `--offline` caps at `Offline`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Fully offline: no network, no credentials.
    Offline,
    /// May use the network but requires no credentials.
    Network,
    /// Requires provider credentials.
    Credentialed,
}

/// The output produced by a single stage run against one node.
///
/// All fields are additions to the graph. The engine merges them.
/// A stage never removes or mutates existing graph elements.
#[derive(Debug, Default)]
pub struct StageOutput {
    /// New nodes discovered by this stage.
    pub nodes: Vec<Node>,
    /// New edges discovered by this stage.
    pub edges: Vec<Edge>,
    /// Evidence to attach to existing nodes.
    pub evidence: Vec<(NodeId, Evidence)>,
    /// Gaps recorded by this stage (blocked paths, errors, budget exceeded).
    pub gaps: Vec<Gap>,
}

impl StageOutput {
    /// Returns true when the output contains no additions.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
            && self.edges.is_empty()
            && self.evidence.is_empty()
            && self.gaps.is_empty()
    }
}

/// A discovery stage.
///
/// Stages are run concurrently by the engine against each frontier node.
/// They communicate via `Context` trait objects so the engine can be tested
/// with fakes.
#[async_trait]
pub trait Stage: Send + Sync {
    /// A stable name, used in `stages_run` on the output trace.
    fn name(&self) -> &'static str;

    /// The privilege tier required by this stage.
    fn tier(&self) -> Tier;

    /// Execution order group for this stage.
    ///
    /// Stages in lower order groups run first and their outputs are merged
    /// into the node before stages in higher order groups are run on that node.
    /// Default order is 0.
    fn order(&self) -> u8 {
        0
    }

    /// Returns true if this stage can process the given node.
    ///
    /// The engine only calls `run` when this returns `true`.
    fn accepts(&self, node: &Node) -> bool;

    /// Run the stage against one node and return any additions.
    ///
    /// A stage must not panic. An unexpected error should be returned as a
    /// `Gap` in the output, not propagated as a Rust error.
    async fn run(&self, cx: &Arc<Context>, node: &Node) -> StageOutput;
}
