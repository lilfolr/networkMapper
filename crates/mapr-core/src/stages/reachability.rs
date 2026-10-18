//! TCP Reachability client and stage.
//!
//! Measures and records TCP connection outcomes to IP nodes across target ports
//! (default 443, 80).
//!
//! Reachability outcomes:
//! - `Connected { elapsed_ms }`
//! - `Refused`
//! - `TimedOut`
//! - `Unreachable`
//! - `Other(String)`
//!
//! Gaps:
//! If all probed ports fail:
//! - `Timeout` if every port timed out.
//! - `NetworkError` otherwise.
//!
//! Node Attributes set:
//! `tcp`: Map<port, outcome_str> where outcome_str is "connected", "refused", "timed_out", "unreachable", "other".

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use mapr_schema::{Evidence, EvidenceSource, Gap, GapReason, Node, NodeKind, Timestamp};
use tokio::net::TcpStream;
use tokio::time::Instant;

use super::{Stage, StageOutput, Tier};
use crate::engine::context::Context;

/// Maximum allowed ports per IP node probe.
pub const MAX_REACHABILITY_PORTS: usize = 8;

/// Outcome of a single TCP connect attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectOutcome {
    Connected { elapsed_ms: u64 },
    Refused,
    TimedOut,
    Unreachable,
    Other(String),
}

impl ConnectOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Connected { .. } => "connected",
            Self::Refused => "refused",
            Self::TimedOut => "timed_out",
            Self::Unreachable => "unreachable",
            Self::Other(_) => "other",
        }
    }
}

/// Trait for performing TCP reachability checks.
#[async_trait]
pub trait ReachabilityClient: Send + Sync {
    async fn connect(&self, addr: SocketAddr, timeout: Duration) -> ConnectOutcome;
}

/// Real implementation using tokio::net::TcpStream.
pub struct TokioReachability;

#[async_trait]
impl ReachabilityClient for TokioReachability {
    async fn connect(&self, addr: SocketAddr, timeout_dur: Duration) -> ConnectOutcome {
        let start = Instant::now();
        match tokio::time::timeout(timeout_dur, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => {
                let elapsed_ms = start.elapsed().as_millis() as u64;
                ConnectOutcome::Connected { elapsed_ms }
            }
            Ok(Err(io_err)) => {
                let kind = io_err.kind();
                match kind {
                    std::io::ErrorKind::ConnectionRefused => ConnectOutcome::Refused,
                    std::io::ErrorKind::TimedOut => ConnectOutcome::TimedOut,
                    std::io::ErrorKind::HostUnreachable
                    | std::io::ErrorKind::NetworkUnreachable => ConnectOutcome::Unreachable,
                    _ => ConnectOutcome::Other(io_err.to_string()),
                }
            }
            Err(_) => ConnectOutcome::TimedOut,
        }
    }
}

/// Fake Reachability Client for testing.
pub struct FakeReachability {
    answers: HashMap<SocketAddr, ConnectOutcome>,
}

impl FakeReachability {
    pub fn new(answers: HashMap<SocketAddr, ConnectOutcome>) -> Self {
        Self { answers }
    }
}

#[async_trait]
impl ReachabilityClient for FakeReachability {
    async fn connect(&self, addr: SocketAddr, _timeout: Duration) -> ConnectOutcome {
        self.answers
            .get(&addr)
            .cloned()
            .unwrap_or(ConnectOutcome::Refused)
    }
}

/// TCP Reachability stage (`order() -> 0`).
pub struct TcpReachabilityStage {
    client: Arc<dyn ReachabilityClient>,
    ports: Vec<u16>,
    connect_timeout: Duration,
}

impl TcpReachabilityStage {
    pub fn new(
        client: Arc<dyn ReachabilityClient>,
        ports: Vec<u16>,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            client,
            ports,
            connect_timeout,
        }
    }

    pub fn default_ports() -> Vec<u16> {
        vec![443, 80]
    }
}

#[async_trait]
impl Stage for TcpReachabilityStage {
    fn name(&self) -> &'static str {
        "reachability"
    }

    fn tier(&self) -> Tier {
        Tier::Network
    }

    fn order(&self) -> u8 {
        0
    }

    fn accepts(&self, node: &Node) -> bool {
        if node.kind != NodeKind::Ip {
            return false;
        }

        // Skip private or non-routable nodes
        if node
            .attributes
            .get("non_routable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return false;
        }

        true
    }

    async fn run(&self, _cx: &Arc<Context>, node: &Node) -> StageOutput {
        if self.ports.len() > MAX_REACHABILITY_PORTS {
            return StageOutput {
                nodes: vec![],
                edges: vec![],
                evidence: vec![],
                gaps: vec![Gap {
                    at: Some(node.id.clone()),
                    reason: GapReason::BudgetExceeded,
                    detail: format!(
                        "Exceeded maximum port check limit of {} (requested {})",
                        MAX_REACHABILITY_PORTS,
                        self.ports.len()
                    ),
                    needs: None,
                }],
            };
        }

        let ip_addr: IpAddr = match node.name.parse() {
            Ok(ip) => ip,
            Err(_) => match node
                .id
                .as_str()
                .strip_prefix("ip:")
                .and_then(|s| s.parse().ok())
            {
                Some(ip) => ip,
                None => return StageOutput::default(),
            },
        };

        let now = Timestamp::from(Utc::now());
        let mut evidence_list = Vec::new();
        let mut tcp_attr_map = serde_json::Map::new();
        let mut outcomes = Vec::new();

        for &port in &self.ports {
            let addr = SocketAddr::new(ip_addr, port);
            let outcome = self.client.connect(addr, self.connect_timeout).await;

            tcp_attr_map.insert(
                port.to_string(),
                serde_json::Value::String(outcome.as_str().to_owned()),
            );

            let detail = match &outcome {
                ConnectOutcome::Connected { elapsed_ms } => {
                    format!(
                        "TCP connect to {}:{} succeeded in {}ms from local machine",
                        ip_addr, port, elapsed_ms
                    )
                }
                ConnectOutcome::Refused => {
                    format!(
                        "TCP connect to {}:{} refused from local machine",
                        ip_addr, port
                    )
                }
                ConnectOutcome::TimedOut => {
                    format!("TCP connect to {}:{} timed out (no response within {}s from local machine)", ip_addr, port, self.connect_timeout.as_secs())
                }
                ConnectOutcome::Unreachable => {
                    format!(
                        "TCP connect to {}:{} host/network unreachable from local machine",
                        ip_addr, port
                    )
                }
                ConnectOutcome::Other(msg) => {
                    format!(
                        "TCP connect to {}:{} failed: {} from local machine",
                        ip_addr, port, msg
                    )
                }
            };

            let mut ev_attrs = serde_json::Map::new();
            ev_attrs.insert("port".to_owned(), serde_json::Value::Number(port.into()));
            ev_attrs.insert(
                "outcome".to_owned(),
                serde_json::Value::String(outcome.as_str().to_owned()),
            );
            if let ConnectOutcome::Connected { elapsed_ms } = outcome {
                ev_attrs.insert(
                    "elapsed_ms".to_owned(),
                    serde_json::Value::Number(elapsed_ms.into()),
                );
            }
            ev_attrs.insert(
                "vantage".to_owned(),
                serde_json::Value::String("local".to_owned()),
            );

            evidence_list.push(Evidence {
                source: EvidenceSource::Reachability,
                detail,
                observed_at: now.clone(),
                attributes: ev_attrs,
            });

            outcomes.push((port, outcome));
        }

        let mut updated_node = node.clone();
        updated_node
            .attributes
            .insert("tcp".to_owned(), serde_json::Value::Object(tcp_attr_map));

        let mut node_evidence: Vec<(mapr_schema::NodeId, Evidence)> = Vec::new();
        for ev in evidence_list {
            node_evidence.push((node.id.clone(), ev));
        }

        let any_connected = outcomes
            .iter()
            .any(|(_, o)| matches!(o, ConnectOutcome::Connected { .. }));
        let mut gaps = Vec::new();

        if !any_connected && !outcomes.is_empty() {
            let all_timed_out = outcomes
                .iter()
                .all(|(_, o)| matches!(o, ConnectOutcome::TimedOut));
            let reason = if all_timed_out {
                GapReason::Timeout
            } else {
                GapReason::NetworkError
            };

            let summary = outcomes
                .iter()
                .map(|(p, o)| format!("port {}: {}", p, o.as_str()))
                .collect::<Vec<_>>()
                .join(", ");

            gaps.push(Gap {
                at: Some(node.id.clone()),
                reason,
                detail: format!(
                    "TCP connection failed for all probed ports on {}: ({}) from local machine",
                    ip_addr, summary
                ),
                needs: None,
            });
        }

        StageOutput {
            nodes: vec![updated_node],
            edges: vec![],
            evidence: node_evidence,
            gaps,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use mapr_schema::NodeId;

    fn make_ip_node(ip_str: &str) -> Node {
        let ip: IpAddr = ip_str.parse().unwrap();
        Node {
            id: NodeId::from_ip(ip),
            kind: NodeKind::Ip,
            provider: None,
            service: None,
            name: ip_str.to_owned(),
            identifier: None,
            attributes: serde_json::Map::new(),
            evidence: Vec::new(),
        }
    }

    #[tokio::test]
    async fn forbidden_words_test() {
        // Assert "alive", "dead", "down" as conclusions never appear in strings
        let mut answers = HashMap::new();
        let addr: SocketAddr = "198.51.100.1:443".parse().unwrap();
        answers.insert(addr, ConnectOutcome::Connected { elapsed_ms: 10 });

        let client = Arc::new(FakeReachability::new(answers));
        let stage = TcpReachabilityStage::new(client, vec![443], Duration::from_secs(3));
        let node = make_ip_node("198.51.100.1");
        let output = stage
            .run(&Arc::new(Context::with_fake_clock(Utc::now())), &node)
            .await;

        for (_, ev) in &output.evidence {
            let lower = ev.detail.to_lowercase();
            assert!(
                !lower.contains("alive"),
                "detail contains forbidden word 'alive': {}",
                ev.detail
            );
            assert!(
                !lower.contains("dead"),
                "detail contains forbidden word 'dead': {}",
                ev.detail
            );
            assert!(
                !lower.contains("down"),
                "detail contains forbidden word 'down': {}",
                ev.detail
            );
        }
        for gap in &output.gaps {
            let lower = gap.detail.to_lowercase();
            assert!(
                !lower.contains("alive"),
                "gap detail contains forbidden word 'alive'"
            );
            assert!(
                !lower.contains("dead"),
                "gap detail contains forbidden word 'dead'"
            );
            assert!(
                !lower.contains("down"),
                "gap detail contains forbidden word 'down'"
            );
        }
    }

    #[tokio::test]
    async fn connected_port_emits_attribute_and_no_gap() {
        let mut answers = HashMap::new();
        let addr443: SocketAddr = "198.51.100.1:443".parse().unwrap();
        let addr80: SocketAddr = "198.51.100.1:80".parse().unwrap();
        answers.insert(addr443, ConnectOutcome::Connected { elapsed_ms: 12 });
        answers.insert(addr80, ConnectOutcome::Refused);

        let client = Arc::new(FakeReachability::new(answers));
        let stage = TcpReachabilityStage::new(client, vec![443, 80], Duration::from_secs(3));
        let node = make_ip_node("198.51.100.1");

        let output = stage
            .run(&Arc::new(Context::with_fake_clock(Utc::now())), &node)
            .await;

        assert_eq!(output.nodes.len(), 1);
        let tcp_map = output.nodes[0]
            .attributes
            .get("tcp")
            .unwrap()
            .as_object()
            .unwrap();
        assert_eq!(tcp_map.get("443").unwrap(), "connected");
        assert_eq!(tcp_map.get("80").unwrap(), "refused");
        assert!(
            output.gaps.is_empty(),
            "Mix of connected and failed ports must emit no gap"
        );
    }

    #[tokio::test]
    async fn all_timeouts_emits_timeout_gap() {
        let mut answers = HashMap::new();
        let addr443: SocketAddr = "198.51.100.2:443".parse().unwrap();
        answers.insert(addr443, ConnectOutcome::TimedOut);

        let client = Arc::new(FakeReachability::new(answers));
        let stage = TcpReachabilityStage::new(client, vec![443], Duration::from_secs(3));
        let node = make_ip_node("198.51.100.2");

        let output = stage
            .run(&Arc::new(Context::with_fake_clock(Utc::now())), &node)
            .await;

        assert_eq!(output.gaps.len(), 1);
        assert_eq!(output.gaps[0].reason, GapReason::Timeout);
    }

    #[tokio::test]
    async fn private_ip_is_skipped() {
        let mut node = make_ip_node("10.0.0.1");
        node.attributes
            .insert("non_routable".to_owned(), serde_json::Value::Bool(true));

        let client = Arc::new(FakeReachability::new(HashMap::new()));
        let stage = TcpReachabilityStage::new(client, vec![443], Duration::from_secs(3));
        assert!(!stage.accepts(&node));
    }

    #[tokio::test]
    async fn exceeded_port_cap_emits_gap() {
        let client = Arc::new(FakeReachability::new(HashMap::new()));
        let ports = vec![80, 443, 8080, 8443, 8000, 8888, 9000, 9090, 9999]; // 9 ports > 8
        let stage = TcpReachabilityStage::new(client, ports, Duration::from_secs(3));
        let node = make_ip_node("198.51.100.1");

        let output = stage
            .run(&Arc::new(Context::with_fake_clock(Utc::now())), &node)
            .await;

        assert_eq!(output.gaps.len(), 1);
        assert_eq!(output.gaps[0].reason, GapReason::BudgetExceeded);
    }

    #[tokio::test]
    async fn real_loopback_connect_and_refused() {
        // Test real TcpStream connect against loopback
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        let real_client = Arc::new(TokioReachability);
        let outcome = real_client
            .connect(local_addr, Duration::from_secs(1))
            .await;
        assert!(matches!(outcome, ConnectOutcome::Connected { .. }));

        // Now pick an unused port that will refuse
        let unused_addr: SocketAddr = "127.0.0.1:59999".parse().unwrap();
        let outcome_refused = real_client
            .connect(unused_addr, Duration::from_secs(1))
            .await;
        assert!(matches!(
            outcome_refused,
            ConnectOutcome::Refused | ConnectOutcome::TimedOut
        ));
    }
}
