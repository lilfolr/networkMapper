//! Trace engine: frontier loop, budget control, tier gating, and concurrency.
//!
//! The engine processes one node at a time from a frontier queue. For each
//! node it runs all accepting stages concurrently (bounded by a semaphore),
//! merges the outputs into the graph, and enqueues newly discovered nodes.
//! Budget limits (max depth, max nodes, global timeout) produce `Gap` records
//! and return a partial trace rather than an error.

pub mod context;
pub mod graph;
pub mod seed;

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

use mapr_schema::{
    derive_paths, ExitCode, Gap, GapReason, Node, NodeId, Timestamp, Trace, SCHEMA_VERSION,
};

use crate::error::CoreError;
use crate::stages::{Stage, Tier};

use self::context::Context;
use self::graph::GraphState;
use self::seed::{Seed, SeedError};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors returned by the engine. Distinct from `CoreError` so callers can
/// pattern-match without depending on the full library error type.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("invalid target: {0}")]
    InvalidSeed(#[from] SeedError),
    #[error("engine I/O error: {0}")]
    Core(#[from] CoreError),
}

// ---------------------------------------------------------------------------
// Budget constants (defaults; overridden via EngineConfig)
// ---------------------------------------------------------------------------

/// Default maximum graph depth (hops from the seed node).
pub const DEFAULT_MAX_DEPTH: usize = 32;
/// Default maximum number of nodes in the graph before stopping expansion.
pub const DEFAULT_MAX_NODES: usize = 1000;
/// Default global timeout in seconds.
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 60;
/// Default maximum concurrent stage executions across all nodes.
pub const DEFAULT_MAX_CONCURRENCY: usize = 16;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for a single engine run.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// No outbound network calls. Caps the maximum tier at `Offline`.
    pub offline: bool,
    /// Never prompt for input.
    pub no_prompt: bool,
    /// Global wall-clock timeout in seconds.
    pub timeout_seconds: u64,
    /// Stop expanding the graph after this many nodes.
    pub max_nodes: usize,
    /// Stop following edges deeper than this many hops from the seed.
    pub max_depth: usize,
    /// Maximum number of stage executions running simultaneously.
    pub max_concurrency: usize,
    /// Maximum privilege tier stages may use.
    ///
    /// Overridden to `Tier::Offline` when `offline` is true.
    pub max_tier: Tier,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            offline: false,
            no_prompt: false,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            max_nodes: DEFAULT_MAX_NODES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
            max_tier: Tier::Credentialed,
        }
    }
}

impl EngineConfig {
    /// Effective maximum tier, accounting for `--offline`.
    fn effective_max_tier(&self) -> Tier {
        if self.offline {
            Tier::Offline
        } else {
            self.max_tier
        }
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// The trace engine.
///
/// Constructed with a list of stages and a context, then driven by calling
/// `run`. Stages are stored as `Arc<dyn Stage>` so they can be shared across
/// async tasks.
pub struct Engine {
    stages: Vec<Arc<dyn Stage>>,
    context: Arc<Context>,
}

impl Engine {
    /// Create an engine with the given stages and context.
    pub fn new(stages: Vec<Arc<dyn Stage>>, context: Arc<Context>) -> Self {
        Self { stages, context }
    }

    /// Run the engine against a user-supplied target string.
    ///
    /// Returns a `(Trace, ExitCode)`. On any budget limit the trace is
    /// partial and the exit code is `PartialTrace`. The function only returns
    /// `Err` when the input seed itself cannot be parsed.
    pub async fn run(
        &self,
        raw_target: &str,
        config: &EngineConfig,
    ) -> Result<(Trace, ExitCode), EngineError> {
        let seed = Seed::parse(raw_target)?;
        let target = seed.as_target(raw_target);
        let seed_node = seed.to_node()?;

        let semaphore = Arc::new(Semaphore::new(config.max_concurrency));

        // Build a future that performs the actual work and wrap it in a global
        // timeout.
        let work = self.run_inner(seed_node, config, semaphore);
        let deadline = Duration::from_secs(config.timeout_seconds);

        let (mut graph, timed_out) = match timeout(deadline, work).await {
            Ok(g) => (g, false),
            Err(_) => {
                // Timed out: build an empty graph with just the seed node so we
                // still emit a valid trace. The gap is added below.
                let seed2 = Seed::parse(raw_target)?;
                let seed_node2 = seed2.to_node()?;
                (GraphState::with_seed(seed_node2), true)
            }
        };

        if timed_out {
            graph.push_gap(Gap {
                at: None,
                reason: GapReason::BudgetExceeded,
                detail: format!("global timeout of {}s exceeded", config.timeout_seconds),
                needs: None,
            });
        }

        let generated_at = Timestamp::from(Utc::now());
        let (nodes, edges, gaps, stages_run) = graph.finalise();

        let edge_pairs: Vec<(NodeId, NodeId)> = edges
            .iter()
            .map(|e| (e.from.clone(), e.to.clone()))
            .collect();

        // Determine paths from the seed node.
        let node_ids: Vec<NodeId> = nodes.iter().map(|n| n.id.clone()).collect();
        // The seed node id may have been canonicalized, so we rebuild it.
        let seed_for_paths = Seed::parse(raw_target)?;
        let seed_id = seed_for_paths.to_node()?.id;
        let paths = derive_paths(&node_ids, &edge_pairs, &seed_id);

        let has_gaps = !gaps.is_empty();
        let exit_code = if has_gaps {
            ExitCode::PartialTrace
        } else {
            ExitCode::Success
        };

        let trace = Trace {
            schema_version: SCHEMA_VERSION.to_string(),
            target,
            generated_at,
            stages_run,
            nodes,
            edges,
            gaps,
            paths,
        };

        Ok((trace, exit_code))
    }

    /// Inner frontier loop. Returns the accumulated `GraphState`.
    async fn run_inner(
        &self,
        seed_node: Node,
        config: &EngineConfig,
        semaphore: Arc<Semaphore>,
    ) -> GraphState {
        let max_tier = config.effective_max_tier();
        let mut graph = GraphState::with_seed(seed_node.clone());

        // Each frontier entry carries the node and its depth.
        let mut frontier: VecDeque<(Node, usize)> = VecDeque::new();
        frontier.push_back((seed_node, 0));

        // Visited set prevents re-processing a node we already expanded.
        let mut visited: HashSet<NodeId> = HashSet::new();

        while let Some((node, depth)) = frontier.pop_front() {
            if visited.contains(&node.id) {
                continue;
            }
            visited.insert(node.id.clone());

            // --- Depth budget ---
            if depth > config.max_depth {
                graph.push_gap(Gap {
                    at: Some(node.id.clone()),
                    reason: GapReason::BudgetExceeded,
                    detail: format!(
                        "max depth of {} exceeded at node {}",
                        config.max_depth, node.id
                    ),
                    needs: None,
                });
                continue;
            }

            // --- Node budget ---
            if graph.node_count() >= config.max_nodes {
                graph.push_gap(Gap {
                    at: Some(node.id.clone()),
                    reason: GapReason::BudgetExceeded,
                    detail: format!(
                        "max nodes ({}) reached, stopping expansion",
                        config.max_nodes
                    ),
                    needs: None,
                });
                break;
            }

            // --- Run all accepting, permitted stages concurrently ---
            let eligible: Vec<Arc<dyn Stage>> = self
                .stages
                .iter()
                .filter(|s| s.tier() <= max_tier && s.accepts(&node))
                .cloned()
                .collect();

            // Record stage names before running.
            for s in &eligible {
                graph.record_stage(s.name());
            }

            // Spawn one task per eligible stage, bounded by the semaphore.
            let mut handles = Vec::with_capacity(eligible.len());
            for stage in eligible {
                let node_clone = node.clone();
                let cx = Arc::clone(&self.context);
                let sem = Arc::clone(&semaphore);

                let handle = tokio::spawn(async move {
                    // Acquire a permit before running; this limits total
                    // concurrent stage executions across all nodes.
                    let _permit = sem.acquire_owned().await;
                    // Catch panics: a panicking stage becomes a gap.
                    let result = std::panic::AssertUnwindSafe(stage.run(&cx, &node_clone));
                    // We cannot use catch_unwind with async directly, so we
                    // run the future and rely on the task system to catch panics.
                    result.await
                });

                handles.push((stage_name_from_handle(&node), handle));
            }

            for (_, handle) in handles {
                match handle.await {
                    Ok(output) => {
                        // Merge nodes first so evidence-attach has targets.
                        for new_node in output.nodes {
                            let already_visited = visited.contains(&new_node.id);
                            let already_in_graph = graph.contains_node(&new_node.id);
                            graph.merge_node(new_node.clone());
                            // Only enqueue if not yet expanded.
                            if !already_visited && !already_in_graph {
                                frontier.push_back((new_node, depth + 1));
                            }
                        }
                        for edge in output.edges {
                            graph.merge_edge(edge);
                        }
                        for (id, ev) in output.evidence {
                            graph.attach_evidence(&id, ev);
                        }
                        for gap in output.gaps {
                            graph.push_gap(gap);
                        }
                    }
                    Err(join_err) => {
                        // The task panicked or was cancelled. Record as a gap.
                        graph.push_gap(Gap {
                            at: Some(node.id.clone()),
                            reason: GapReason::NetworkError,
                            detail: format!("stage task failed: {join_err}"),
                            needs: None,
                        });
                    }
                }
            }
        }

        graph
    }
}

// Small helper: we lost the stage name after spawning, so we use a placeholder.
// The real stage name is recorded via `record_stage` above.
fn stage_name_from_handle(_node: &Node) -> &'static str {
    "running"
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::stages::{Stage, StageOutput, Tier};
    use chrono::Utc;
    use mapr_schema::{Confidence, Edge, Gap, GapReason, Node, NodeId, NodeKind, Relation};
    use std::sync::atomic::{AtomicUsize, Ordering};

    // -----------------------------------------------------------------------
    // Fake stage helpers
    // -----------------------------------------------------------------------

    fn fake_context() -> Arc<Context> {
        Arc::new(Context::with_fake_clock(Utc::now()))
    }

    fn make_node(id: &str, kind: NodeKind) -> Node {
        Node {
            id: NodeId::from_raw(id),
            kind,
            provider: None,
            service: None,
            name: id.to_owned(),
            identifier: None,
            attributes: serde_json::Map::new(),
            evidence: Vec::new(),
        }
    }

    fn make_edge(from: &str, to: &str) -> Edge {
        Edge {
            from: NodeId::from_raw(from),
            to: NodeId::from_raw(to),
            relation: Relation::ResolvesTo,
            confidence: Confidence::Observed,
            evidence: Vec::new(),
        }
    }

    /// A stage that expands a specific node id into a fixed child node.
    struct ExpandStage {
        /// When this node id is seen, emit `child`.
        trigger_id: &'static str,
        child_id: &'static str,
        tier: Tier,
    }

    #[async_trait::async_trait]
    impl Stage for ExpandStage {
        fn name(&self) -> &'static str {
            "expand"
        }
        fn tier(&self) -> Tier {
            self.tier
        }
        fn accepts(&self, node: &Node) -> bool {
            node.id.as_str() == self.trigger_id
        }
        async fn run(&self, _cx: &Arc<Context>, node: &Node) -> StageOutput {
            let child = make_node(self.child_id, NodeKind::Ip);
            let edge = make_edge(node.id.as_str(), self.child_id);
            StageOutput {
                nodes: vec![child],
                edges: vec![edge],
                evidence: vec![],
                gaps: vec![],
            }
        }
    }

    /// A stage that does nothing.
    struct NoopStage;

    #[async_trait::async_trait]
    impl Stage for NoopStage {
        fn name(&self) -> &'static str {
            "noop"
        }
        fn tier(&self) -> Tier {
            Tier::Offline
        }
        fn accepts(&self, _node: &Node) -> bool {
            true
        }
        async fn run(&self, _cx: &Arc<Context>, _node: &Node) -> StageOutput {
            StageOutput::default()
        }
    }

    /// A stage that always returns a gap.
    struct FailingStage;

    #[async_trait::async_trait]
    impl Stage for FailingStage {
        fn name(&self) -> &'static str {
            "failing"
        }
        fn tier(&self) -> Tier {
            Tier::Offline
        }
        fn accepts(&self, _node: &Node) -> bool {
            true
        }
        async fn run(&self, _cx: &Arc<Context>, node: &Node) -> StageOutput {
            StageOutput {
                nodes: vec![],
                edges: vec![],
                evidence: vec![],
                gaps: vec![Gap {
                    at: Some(node.id.clone()),
                    reason: GapReason::NetworkError,
                    detail: "stage failed".to_owned(),
                    needs: None,
                }],
            }
        }
    }

    /// A stage that counts how many times it runs, to test deduplication.
    struct CountingStage {
        count: Arc<AtomicUsize>,
        emit_child: Option<&'static str>,
    }

    #[async_trait::async_trait]
    impl Stage for CountingStage {
        fn name(&self) -> &'static str {
            "counting"
        }
        fn tier(&self) -> Tier {
            Tier::Offline
        }
        fn accepts(&self, _node: &Node) -> bool {
            true
        }
        async fn run(&self, _cx: &Arc<Context>, node: &Node) -> StageOutput {
            self.count.fetch_add(1, Ordering::SeqCst);
            match self.emit_child {
                Some(child_id) => {
                    let child = make_node(child_id, NodeKind::Ip);
                    let edge = make_edge(node.id.as_str(), child_id);
                    StageOutput {
                        nodes: vec![child],
                        edges: vec![edge],
                        evidence: vec![],
                        gaps: vec![],
                    }
                }
                None => StageOutput::default(),
            }
        }
    }

    /// A stage that emits the same child node as another stage (to test dedup).
    struct DuplicateChildStage {
        trigger_id: &'static str,
        child_id: &'static str,
    }

    #[async_trait::async_trait]
    impl Stage for DuplicateChildStage {
        fn name(&self) -> &'static str {
            "duplicate_child"
        }
        fn tier(&self) -> Tier {
            Tier::Offline
        }
        fn accepts(&self, node: &Node) -> bool {
            node.id.as_str() == self.trigger_id
        }
        async fn run(&self, _cx: &Arc<Context>, node: &Node) -> StageOutput {
            let child = make_node(self.child_id, NodeKind::Ip);
            let edge = make_edge(node.id.as_str(), self.child_id);
            StageOutput {
                nodes: vec![child],
                edges: vec![edge],
                evidence: vec![],
                gaps: vec![],
            }
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn engine_with_no_stages_returns_seed_node() {
        let engine = Engine::new(vec![], fake_context());
        let config = EngineConfig::default();
        let (trace, code) = engine.run("example.com", &config).await.unwrap();
        assert_eq!(code, ExitCode::Success);
        assert_eq!(trace.nodes.len(), 1);
        assert_eq!(trace.nodes[0].kind, NodeKind::Hostname);
        assert!(trace.gaps.is_empty());
    }

    #[tokio::test]
    async fn engine_expands_to_fixed_point() {
        // Seed -> ip:203.0.113.1 -> ip:203.0.113.2 (linear expansion).
        // ip:203.0.113.2 has no accepting stage, so the frontier stops there.
        // No gaps are produced, so the trace is complete.
        let stages: Vec<Arc<dyn Stage>> = vec![
            Arc::new(ExpandStage {
                trigger_id: "hostname:api.example.com",
                child_id: "ip:203.0.113.1",
                tier: Tier::Offline,
            }),
            Arc::new(ExpandStage {
                trigger_id: "ip:203.0.113.1",
                child_id: "ip:203.0.113.2",
                tier: Tier::Offline,
            }),
        ];
        let engine = Engine::new(stages, fake_context());
        let (trace, code) = engine
            .run("api.example.com", &EngineConfig::default())
            .await
            .unwrap();
        assert!(trace.gaps.is_empty(), "unexpected gaps: {:?}", trace.gaps);
        assert_eq!(code, ExitCode::Success);
        assert_eq!(trace.nodes.len(), 3);
        assert_eq!(trace.edges.len(), 2);
    }

    #[tokio::test]
    async fn engine_deduplicates_nodes_reached_by_two_routes() {
        // Both route 1 and route 2 discover ip:203.0.113.99.
        // The node should appear only once.
        let stages: Vec<Arc<dyn Stage>> = vec![
            Arc::new(ExpandStage {
                trigger_id: "hostname:api.example.com",
                child_id: "ip:203.0.113.99",
                tier: Tier::Offline,
            }),
            Arc::new(DuplicateChildStage {
                trigger_id: "hostname:api.example.com",
                child_id: "ip:203.0.113.99",
            }),
        ];
        let engine = Engine::new(stages, fake_context());
        let (trace, _) = engine
            .run("api.example.com", &EngineConfig::default())
            .await
            .unwrap();
        let ids: Vec<&str> = trace.nodes.iter().map(|n| n.id.as_str()).collect();
        let unique: HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len(), "duplicate node ids: {:?}", ids);
    }

    #[tokio::test]
    async fn engine_does_not_expand_same_node_twice() {
        // A node reached from two different parents must only be processed once.
        let count = Arc::new(AtomicUsize::new(0));
        // Two separate expanders both point to the same child.
        let stages: Vec<Arc<dyn Stage>> = vec![
            Arc::new(ExpandStage {
                trigger_id: "hostname:api.example.com",
                child_id: "ip:203.0.113.99",
                tier: Tier::Offline,
            }),
            Arc::new(DuplicateChildStage {
                trigger_id: "hostname:api.example.com",
                child_id: "ip:203.0.113.99",
            }),
            Arc::new(CountingStage {
                count: Arc::clone(&count),
                emit_child: None,
            }),
        ];
        let engine = Engine::new(stages, fake_context());
        let _ = engine
            .run("api.example.com", &EngineConfig::default())
            .await
            .unwrap();
        // CountingStage accepts everything: seed + child = 2 runs.
        // The child should only be processed once.
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn engine_handles_self_loop() {
        // A stage that emits the same node as its output (self-loop).
        let count = Arc::new(AtomicUsize::new(0));
        let stages: Vec<Arc<dyn Stage>> = vec![Arc::new(CountingStage {
            count: Arc::clone(&count),
            emit_child: Some("hostname:api.example.com"),
        })];
        let engine = Engine::new(stages, fake_context());
        let (trace, _) = engine
            .run("api.example.com", &EngineConfig::default())
            .await
            .unwrap();
        // Should run only once: the self-loop child is already visited.
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(trace.nodes.len(), 1);
    }

    #[tokio::test]
    async fn engine_respects_max_nodes_budget() {
        // A chain longer than max_nodes. Should stop and emit a BudgetExceeded gap.
        let stages: Vec<Arc<dyn Stage>> = vec![
            Arc::new(ExpandStage {
                trigger_id: "hostname:api.example.com",
                child_id: "ip:203.0.113.1",
                tier: Tier::Offline,
            }),
            Arc::new(ExpandStage {
                trigger_id: "ip:203.0.113.1",
                child_id: "ip:203.0.113.2",
                tier: Tier::Offline,
            }),
            Arc::new(ExpandStage {
                trigger_id: "ip:203.0.113.2",
                child_id: "ip:203.0.113.3",
                tier: Tier::Offline,
            }),
        ];
        let config = EngineConfig {
            max_nodes: 2,
            ..EngineConfig::default()
        }; // allow only 2 nodes before stopping.

        let engine = Engine::new(stages, fake_context());
        let (trace, code) = engine.run("api.example.com", &config).await.unwrap();
        assert_eq!(code, ExitCode::PartialTrace);
        assert!(
            trace
                .gaps
                .iter()
                .any(|g| g.reason == GapReason::BudgetExceeded),
            "expected BudgetExceeded gap, got: {:?}",
            trace.gaps
        );
        assert!(trace.nodes.len() <= config.max_nodes + 1);
    }

    #[tokio::test]
    async fn engine_respects_max_depth_budget() {
        let stages: Vec<Arc<dyn Stage>> = vec![
            Arc::new(ExpandStage {
                trigger_id: "hostname:api.example.com",
                child_id: "ip:203.0.113.1",
                tier: Tier::Offline,
            }),
            Arc::new(ExpandStage {
                trigger_id: "ip:203.0.113.1",
                child_id: "ip:203.0.113.2",
                tier: Tier::Offline,
            }),
        ];
        let config = EngineConfig {
            max_depth: 1,
            ..EngineConfig::default()
        }; // only allow the first hop.

        let engine = Engine::new(stages, fake_context());
        let (trace, code) = engine.run("api.example.com", &config).await.unwrap();
        assert_eq!(code, ExitCode::PartialTrace);
        assert!(
            trace
                .gaps
                .iter()
                .any(|g| g.reason == GapReason::BudgetExceeded),
            "expected BudgetExceeded gap"
        );
    }

    #[tokio::test]
    async fn engine_respects_global_timeout() {
        use tokio::time::sleep;

        struct SlowStage;

        #[async_trait::async_trait]
        impl Stage for SlowStage {
            fn name(&self) -> &'static str {
                "slow"
            }
            fn tier(&self) -> Tier {
                Tier::Offline
            }
            fn accepts(&self, _node: &Node) -> bool {
                true
            }
            async fn run(&self, _cx: &Arc<Context>, _node: &Node) -> StageOutput {
                sleep(Duration::from_secs(60)).await;
                StageOutput::default()
            }
        }

        let stages: Vec<Arc<dyn Stage>> = vec![Arc::new(SlowStage)];
        let config = EngineConfig {
            timeout_seconds: 1,
            ..EngineConfig::default()
        };

        let engine = Engine::new(stages, fake_context());
        let (trace, code) = engine.run("api.example.com", &config).await.unwrap();
        assert_eq!(code, ExitCode::PartialTrace);
        assert!(
            trace
                .gaps
                .iter()
                .any(|g| g.reason == GapReason::BudgetExceeded),
            "expected BudgetExceeded gap from timeout"
        );
    }

    #[tokio::test]
    async fn engine_respects_tier_gating_offline() {
        // A Network-tier stage should be skipped when --offline.
        struct NetworkStage {
            count: Arc<AtomicUsize>,
        }
        #[async_trait::async_trait]
        impl Stage for NetworkStage {
            fn name(&self) -> &'static str {
                "network"
            }
            fn tier(&self) -> Tier {
                Tier::Network
            }
            fn accepts(&self, _node: &Node) -> bool {
                true
            }
            async fn run(&self, _cx: &Arc<Context>, _node: &Node) -> StageOutput {
                self.count.fetch_add(1, Ordering::SeqCst);
                StageOutput::default()
            }
        }

        let net_count = Arc::new(AtomicUsize::new(0));
        let stages: Vec<Arc<dyn Stage>> = vec![Arc::new(NetworkStage {
            count: Arc::clone(&net_count),
        })];

        let config = EngineConfig {
            offline: true,
            ..EngineConfig::default()
        };

        let engine = Engine::new(stages, fake_context());
        let _ = engine.run("api.example.com", &config).await.unwrap();
        assert_eq!(
            net_count.load(Ordering::SeqCst),
            0,
            "network stage must not run in offline mode"
        );
    }

    #[tokio::test]
    async fn engine_respects_tier_gating_credentialed() {
        // A Credentialed-tier stage should be skipped when max_tier is Network.
        struct CredStage {
            count: Arc<AtomicUsize>,
        }
        #[async_trait::async_trait]
        impl Stage for CredStage {
            fn name(&self) -> &'static str {
                "cred"
            }
            fn tier(&self) -> Tier {
                Tier::Credentialed
            }
            fn accepts(&self, _node: &Node) -> bool {
                true
            }
            async fn run(&self, _cx: &Arc<Context>, _node: &Node) -> StageOutput {
                self.count.fetch_add(1, Ordering::SeqCst);
                StageOutput::default()
            }
        }

        let count = Arc::new(AtomicUsize::new(0));
        let stages: Vec<Arc<dyn Stage>> = vec![Arc::new(CredStage {
            count: Arc::clone(&count),
        })];

        let config = EngineConfig {
            max_tier: Tier::Network,
            ..EngineConfig::default()
        };

        let engine = Engine::new(stages, fake_context());
        let _ = engine.run("api.example.com", &config).await.unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "credentialed stage must not run at Network tier"
        );
    }

    #[tokio::test]
    async fn stage_failure_becomes_gap_not_abort() {
        // A failing stage should produce a gap but not abort the trace.
        let stages: Vec<Arc<dyn Stage>> = vec![Arc::new(FailingStage)];
        let engine = Engine::new(stages, fake_context());
        let (trace, code) = engine
            .run("api.example.com", &EngineConfig::default())
            .await
            .unwrap();
        assert_eq!(code, ExitCode::PartialTrace);
        assert_eq!(trace.gaps.len(), 1);
        assert_eq!(trace.gaps[0].reason, GapReason::NetworkError);
        // The trace itself is returned, not an Err.
        assert_eq!(trace.nodes.len(), 1); // seed node still present
    }

    #[tokio::test]
    async fn deterministic_output_across_repeated_runs() {
        // Run the same engine twice; both traces must sort identically.
        let stages: Vec<Arc<dyn Stage>> = vec![
            Arc::new(ExpandStage {
                trigger_id: "hostname:api.example.com",
                child_id: "ip:203.0.113.1",
                tier: Tier::Offline,
            }),
            Arc::new(DuplicateChildStage {
                trigger_id: "hostname:api.example.com",
                child_id: "ip:203.0.113.2",
            }),
        ];

        let engine = Engine::new(stages, fake_context());
        let config = EngineConfig::default();

        let (trace1, _) = engine.run("api.example.com", &config).await.unwrap();
        let (trace2, _) = engine.run("api.example.com", &config).await.unwrap();

        let ids1: Vec<&str> = trace1.nodes.iter().map(|n| n.id.as_str()).collect();
        let ids2: Vec<&str> = trace2.nodes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids1, ids2);

        let edge1: Vec<_> = trace1
            .edges
            .iter()
            .map(|e| (e.from.as_str(), e.to.as_str()))
            .collect();
        let edge2: Vec<_> = trace2
            .edges
            .iter()
            .map(|e| (e.from.as_str(), e.to.as_str()))
            .collect();
        assert_eq!(edge1, edge2);
    }

    #[tokio::test]
    async fn seed_parse_error_returns_err() {
        // An empty string fails IDNA and is not a valid seed.
        let engine = Engine::new(vec![], fake_context());
        let result = engine.run("", &EngineConfig::default()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn stages_run_list_is_populated() {
        let stages: Vec<Arc<dyn Stage>> = vec![Arc::new(NoopStage)];
        let engine = Engine::new(stages, fake_context());
        let (trace, _) = engine
            .run("example.com", &EngineConfig::default())
            .await
            .unwrap();
        assert!(trace.stages_run.contains(&"noop".to_owned()));
    }

    #[tokio::test]
    async fn paths_are_derived() {
        let stages: Vec<Arc<dyn Stage>> = vec![Arc::new(ExpandStage {
            trigger_id: "hostname:api.example.com",
            child_id: "ip:203.0.113.1",
            tier: Tier::Offline,
        })];
        let engine = Engine::new(stages, fake_context());
        let (trace, _) = engine
            .run("api.example.com", &EngineConfig::default())
            .await
            .unwrap();
        assert_eq!(trace.paths.len(), 1);
        assert_eq!(trace.paths[0].len(), 2);
    }
}
