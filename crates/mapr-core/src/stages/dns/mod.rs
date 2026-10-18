//! DNS discovery stage.
//!
//! Accepts `Hostname` nodes and performs the full CNAME walk followed by A
//! and AAAA lookups. Each CNAME hop becomes a `Hostname` node linked by a
//! `Cname` edge. Each resolved IP becomes an `Ip` node linked by a
//! `ResolvesTo` edge.
//!
//! ## Apex domains
//!
//! An apex domain (e.g. `example.com`) may not have a CNAME record but
//! could still have A/AAAA records directly. After a NODATA CNAME response we
//! always fall through to A/AAAA queries rather than assuming the name does
//! not exist. We do NOT assume that a missing CNAME is the whole story: some
//! resolvers suppress CNAME queries at the apex and only serve synthetic A
//! records, or ALIAS/ANAME records that look like A records on the wire.
//! The stage records what it observes; it does not infer beyond that.
//!
//! ## Loop detection
//!
//! A CNAME chain that refers back to a name already in the current walk is
//! detected immediately. The loop is recorded as a gap and the walk stops.
//! The max chain depth (16) provides a second guard against pathological
//! chains.

pub mod client;

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use mapr_schema::{
    Confidence, Edge, EvidenceSource, Gap, GapReason, Node, NodeId, NodeKind, Relation, Timestamp,
};

use crate::engine::context::Context;
use crate::stages::{Stage, StageOutput, Tier};
use client::{DnsClient, DnsRData, DnsResponse, QueryRecordType};

/// Maximum CNAME chain depth before we stop following and record a gap.
const MAX_CNAME_DEPTH: usize = 16;

// ---------------------------------------------------------------------------
// Stage
// ---------------------------------------------------------------------------

/// DNS discovery stage.
///
/// Queries CNAME, A and AAAA records for `Hostname` nodes and emits the
/// resulting graph additions.
pub struct DnsStage {
    client: Arc<dyn DnsClient>,
}

impl DnsStage {
    /// Create a stage backed by the given DNS client.
    pub fn new(client: Arc<dyn DnsClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Stage for DnsStage {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn tier(&self) -> Tier {
        Tier::Network
    }

    fn accepts(&self, node: &Node) -> bool {
        node.kind == NodeKind::Hostname
    }

    async fn run(&self, cx: &Arc<Context>, node: &Node) -> StageOutput {
        let hostname = node.name.as_str();
        let now = cx.now();
        let mut out = StageOutput::default();
        walk_cname_chain(hostname, node, &self.client, now, &mut out).await;
        out
    }
}

// ---------------------------------------------------------------------------
// CNAME walk
// ---------------------------------------------------------------------------

/// Walk the CNAME chain starting from `start_name` / `start_node`, then
/// query A and AAAA at the terminal name.
async fn walk_cname_chain(
    start_name: &str,
    start_node: &Node,
    client: &Arc<dyn DnsClient>,
    now: chrono::DateTime<chrono::Utc>,
    out: &mut StageOutput,
) {
    let resolver = client.resolver_addr().to_owned();
    let mut current_name = start_name.to_owned();
    let mut current_node_id = start_node.id.clone();
    let mut seen: HashSet<String> = HashSet::new();
    seen.insert(normalize_name(&current_name));

    for depth in 0..=MAX_CNAME_DEPTH {
        if depth == MAX_CNAME_DEPTH {
            out.gaps.push(Gap {
                at: Some(current_node_id.clone()),
                reason: GapReason::DnsFailure,
                detail: format!(
                    "CNAME chain exceeded maximum depth of {MAX_CNAME_DEPTH} at {current_name}"
                ),
                needs: None,
            });
            return;
        }

        // Query CNAME for the current name.
        let result = client.lookup(&current_name, QueryRecordType::Cname).await;

        match result.response {
            DnsResponse::Records(records) => {
                // Expect exactly one CNAME record. Take the first one.
                let cname_target = records.iter().find_map(|r| {
                    if let DnsRData::Cname(ref target) = r.data {
                        Some((target.clone(), r.ttl))
                    } else {
                        None
                    }
                });

                match cname_target {
                    None => {
                        // Response had records but no CNAME data (unexpected).
                        // Fall through to A/AAAA queries at the current name.
                        break;
                    }
                    Some((target, ttl)) => {
                        // Strip trailing dot from target for our node names.
                        let target_clean = target.trim_end_matches('.').to_lowercase();

                        // Build the target node and edge.
                        let target_id = match NodeId::from_hostname(&target_clean) {
                            Ok(id) => id,
                            Err(_) => {
                                out.gaps.push(Gap {
                                    at: Some(current_node_id.clone()),
                                    reason: GapReason::DnsFailure,
                                    detail: format!(
                                        "CNAME target {target_clean:?} is not a valid hostname"
                                    ),
                                    needs: None,
                                });
                                return;
                            }
                        };

                        let target_node = Node {
                            id: target_id.clone(),
                            kind: NodeKind::Hostname,
                            provider: None,
                            service: None,
                            name: target_clean.clone(),
                            identifier: None,
                            attributes: serde_json::Map::new(),
                            evidence: Vec::new(),
                        };

                        let mut ev_attrs = serde_json::Map::new();
                        ev_attrs.insert(
                            "resolver".to_owned(),
                            serde_json::Value::String(resolver.clone()),
                        );
                        ev_attrs.insert("ttl".to_owned(), serde_json::Value::Number(ttl.into()));

                        let edge = Edge {
                            from: current_node_id.clone(),
                            to: target_id.clone(),
                            relation: Relation::Cname,
                            confidence: Confidence::Observed,
                            evidence: vec![mapr_schema::Evidence {
                                source: EvidenceSource::DnsQuery,
                                detail: format!(
                                    "CNAME {current_name} -> {target_clean} (TTL {ttl})"
                                ),
                                observed_at: Timestamp::from(now),
                                attributes: ev_attrs,
                            }],
                        };

                        out.nodes.push(target_node);
                        out.edges.push(edge);

                        // Loop detection.
                        let key = normalize_name(&target_clean);
                        if seen.contains(&key) {
                            out.gaps.push(Gap {
                                at: Some(target_id.clone()),
                                reason: GapReason::DnsFailure,
                                detail: format!(
                                    "CNAME loop detected: {target_clean} was already seen in this chain"
                                ),
                                needs: None,
                            });
                            return;
                        }
                        seen.insert(key);

                        // Advance to the next hop.
                        current_name = target_clean;
                        current_node_id = target_id;
                    }
                }
            }

            DnsResponse::NxDomain => {
                // The name we tried to CNAME-resolve does not exist.
                out.gaps.push(Gap {
                    at: Some(current_node_id.clone()),
                    reason: GapReason::Nxdomain,
                    detail: format!("NXDOMAIN for {current_name}"),
                    needs: None,
                });
                return;
            }

            DnsResponse::NoData => {
                // No CNAME at this name. It might have A/AAAA records directly.
                // Fall through to the address queries below.
                break;
            }

            DnsResponse::ServerFailure(msg) => {
                out.gaps.push(Gap {
                    at: Some(current_node_id.clone()),
                    reason: GapReason::DnsFailure,
                    detail: format!("DNS server failure for {current_name}: {msg}"),
                    needs: None,
                });
                return;
            }

            DnsResponse::Timeout => {
                out.gaps.push(Gap {
                    at: Some(current_node_id.clone()),
                    reason: GapReason::Timeout,
                    detail: format!("DNS timeout querying CNAME for {current_name}"),
                    needs: None,
                });
                return;
            }
        }
    }

    // Query A and AAAA at the terminal name (current_name after walking any CNAMEs).
    query_address_records(&current_name, &current_node_id, client, &resolver, now, out).await;
}

/// Query A and AAAA records for `name` and emit `Ip` nodes with `ResolvesTo` edges.
async fn query_address_records(
    name: &str,
    from_id: &NodeId,
    client: &Arc<dyn DnsClient>,
    resolver: &str,
    now: chrono::DateTime<chrono::Utc>,
    out: &mut StageOutput,
) {
    // Query A and AAAA separately so we record each independently.
    for rtype in [QueryRecordType::A, QueryRecordType::Aaaa] {
        let result = client.lookup(name, rtype).await;
        match result.response {
            DnsResponse::Records(records) => {
                for rec in records {
                    let ip: Option<IpAddr> = match &rec.data {
                        DnsRData::A(v4) => Some(IpAddr::V4(*v4)),
                        DnsRData::Aaaa(v6) => Some(IpAddr::V6(*v6)),
                        _ => None,
                    };
                    let ip = match ip {
                        Some(a) => a,
                        None => continue,
                    };

                    let ip_id = NodeId::from_ip(ip);
                    let ip_node = Node {
                        id: ip_id.clone(),
                        kind: NodeKind::Ip,
                        provider: None,
                        service: None,
                        name: ip.to_string(),
                        identifier: None,
                        attributes: serde_json::Map::new(),
                        evidence: Vec::new(),
                    };

                    let mut ev_attrs = serde_json::Map::new();
                    ev_attrs.insert(
                        "resolver".to_owned(),
                        serde_json::Value::String(resolver.to_owned()),
                    );
                    ev_attrs.insert("ttl".to_owned(), serde_json::Value::Number(rec.ttl.into()));

                    let record_type_str = match rtype {
                        QueryRecordType::A => "A",
                        QueryRecordType::Aaaa => "AAAA",
                        QueryRecordType::Cname => "CNAME",
                        QueryRecordType::Ptr => "PTR",
                    };

                    let edge = Edge {
                        from: from_id.clone(),
                        to: ip_id.clone(),
                        relation: Relation::ResolvesTo,
                        confidence: Confidence::Observed,
                        evidence: vec![mapr_schema::Evidence {
                            source: EvidenceSource::DnsQuery,
                            detail: format!("{record_type_str} {name} -> {ip} (TTL {})", rec.ttl),
                            observed_at: Timestamp::from(now),
                            attributes: ev_attrs,
                        }],
                    };

                    out.nodes.push(ip_node);
                    out.edges.push(edge);
                }
            }

            DnsResponse::NxDomain => {
                // NXDOMAIN on A/AAAA after a successful CNAME chain is unusual
                // but possible. Record it as a gap.
                out.gaps.push(Gap {
                    at: Some(from_id.clone()),
                    reason: GapReason::Nxdomain,
                    detail: format!("NXDOMAIN when querying {rtype:?} records for {name}"),
                    needs: None,
                });
            }

            DnsResponse::NoData => {
                // No records of this type is normal (e.g. IPv6-only host has no A).
                // Not a gap: simply nothing to emit.
            }

            DnsResponse::ServerFailure(msg) => {
                out.gaps.push(Gap {
                    at: Some(from_id.clone()),
                    reason: GapReason::DnsFailure,
                    detail: format!("DNS server failure querying {rtype:?} for {name}: {msg}"),
                    needs: None,
                });
            }

            DnsResponse::Timeout => {
                out.gaps.push(Gap {
                    at: Some(from_id.clone()),
                    reason: GapReason::Timeout,
                    detail: format!("DNS timeout querying {rtype:?} for {name}"),
                    needs: None,
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Normalize a hostname for loop-detection comparison.
fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_lowercase()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::engine::context::Context;
    use crate::stages::{Stage, Tier};
    use client::{FakeAnswer, FakeDnsClient, QueryRecordType};
    use mapr_schema::{GapReason, NodeKind, Relation};
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn make_hostname_node(name: &str) -> Node {
        Node {
            id: NodeId::from_hostname(name).unwrap(),
            kind: NodeKind::Hostname,
            provider: None,
            service: None,
            name: name.to_owned(),
            identifier: None,
            attributes: serde_json::Map::new(),
            evidence: Vec::new(),
        }
    }

    fn fake_context() -> Arc<Context> {
        use chrono::Utc;
        Arc::new(Context::with_fake_clock(Utc::now()))
    }

    fn stage(answers: Vec<FakeAnswer>) -> DnsStage {
        DnsStage::new(Arc::new(FakeDnsClient::new(answers)))
    }

    // ------------------------------------------------------------------
    // No CNAME, direct A record
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn no_cname_single_a_record() {
        let answers = vec![FakeAnswer::a(
            "api.example.com",
            Ipv4Addr::new(203, 0, 113, 1),
            300,
        )];
        let s = stage(answers);
        let node = make_hostname_node("api.example.com");
        let out = s.run(&fake_context(), &node).await;

        assert_eq!(out.nodes.len(), 1);
        assert_eq!(out.edges.len(), 1);
        assert_eq!(out.gaps.len(), 0);
        assert_eq!(out.nodes[0].kind, NodeKind::Ip);
        assert_eq!(out.nodes[0].name, "203.0.113.1");
        assert_eq!(out.edges[0].relation, Relation::ResolvesTo);
    }

    // ------------------------------------------------------------------
    // Single CNAME then A record
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn single_cname_then_a() {
        let answers = vec![
            FakeAnswer::cname("api.example.com", "backend.example.com", 300),
            FakeAnswer::a("backend.example.com", Ipv4Addr::new(203, 0, 113, 2), 60),
        ];
        let s = stage(answers);
        let node = make_hostname_node("api.example.com");
        let out = s.run(&fake_context(), &node).await;

        // One hostname node for backend, one IP node.
        assert_eq!(out.nodes.len(), 2);
        assert_eq!(out.edges.len(), 2);
        assert_eq!(out.gaps.len(), 0);

        let cname_edge = out
            .edges
            .iter()
            .find(|e| e.relation == Relation::Cname)
            .expect("expected a CNAME edge");
        assert_eq!(
            cname_edge.from,
            NodeId::from_hostname("api.example.com").unwrap()
        );
        assert_eq!(
            cname_edge.to,
            NodeId::from_hostname("backend.example.com").unwrap()
        );

        let resolve_edge = out
            .edges
            .iter()
            .find(|e| e.relation == Relation::ResolvesTo)
            .expect("expected a ResolvesTo edge");
        assert_eq!(
            resolve_edge.from,
            NodeId::from_hostname("backend.example.com").unwrap()
        );
    }

    // ------------------------------------------------------------------
    // Long CNAME chain (3 hops)
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn long_cname_chain() {
        let answers = vec![
            FakeAnswer::cname("a.example.com", "b.example.com", 300),
            FakeAnswer::cname("b.example.com", "c.example.com", 300),
            FakeAnswer::cname("c.example.com", "d.example.com", 300),
            FakeAnswer::a("d.example.com", Ipv4Addr::new(203, 0, 113, 9), 60),
        ];
        let s = stage(answers);
        let node = make_hostname_node("a.example.com");
        let out = s.run(&fake_context(), &node).await;

        // 3 hostname nodes (b, c, d) + 1 IP node
        assert_eq!(out.nodes.len(), 4);
        // 3 CNAME edges + 1 ResolvesTo edge
        assert_eq!(out.edges.len(), 4);
        assert_eq!(out.gaps.len(), 0);
    }

    // ------------------------------------------------------------------
    // CNAME loop
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn cname_loop_produces_gap() {
        let answers = vec![
            FakeAnswer::cname("loop-a.example.com", "loop-b.example.com", 300),
            FakeAnswer::cname("loop-b.example.com", "loop-a.example.com", 300),
        ];
        let s = stage(answers);
        let node = make_hostname_node("loop-a.example.com");
        let out = s.run(&fake_context(), &node).await;

        // We should have emitted loop-b as a node and a CNAME edge, then hit the loop.
        assert!(!out.gaps.is_empty(), "expected a gap for loop detection");
        assert_eq!(out.gaps[0].reason, GapReason::DnsFailure);
        assert!(out.gaps[0].detail.contains("loop"));
    }

    // ------------------------------------------------------------------
    // Dangling CNAME (NXDOMAIN at the end of the chain)
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn dangling_cname_nxdomain_is_gap() {
        let answers = vec![
            FakeAnswer::cname("a.example.com", "dangling.example.com", 300),
            FakeAnswer::nxdomain("dangling.example.com", QueryRecordType::Cname),
        ];
        let s = stage(answers);
        let node = make_hostname_node("a.example.com");
        let out = s.run(&fake_context(), &node).await;

        // The intermediate hostname node for dangling.example.com is emitted.
        assert_eq!(out.nodes.len(), 1);
        assert!(
            out.gaps.iter().any(|g| g.reason == GapReason::Nxdomain),
            "expected Nxdomain gap"
        );
    }

    // ------------------------------------------------------------------
    // Multiple A records
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn multiple_a_records() {
        use client::{DnsRData, DnsRecord, DnsResponse, FakeAnswer};
        let multi = FakeAnswer {
            name: "multi.example.com".to_owned(),
            record_type: QueryRecordType::A,
            response: DnsResponse::Records(vec![
                DnsRecord {
                    name: "multi.example.com".to_owned(),
                    data: DnsRData::A(Ipv4Addr::new(203, 0, 113, 1)),
                    ttl: 60,
                },
                DnsRecord {
                    name: "multi.example.com".to_owned(),
                    data: DnsRData::A(Ipv4Addr::new(203, 0, 113, 2)),
                    ttl: 60,
                },
            ]),
        };
        let s = stage(vec![multi]);
        let node = make_hostname_node("multi.example.com");
        let out = s.run(&fake_context(), &node).await;

        assert_eq!(out.nodes.len(), 2);
        assert_eq!(out.edges.len(), 2);
        assert_eq!(out.gaps.len(), 0);
    }

    // ------------------------------------------------------------------
    // Both A and AAAA records
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn both_a_and_aaaa_records() {
        let answers = vec![
            FakeAnswer::a("dual.example.com", Ipv4Addr::new(203, 0, 113, 5), 60),
            FakeAnswer::aaaa(
                "dual.example.com",
                Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
                60,
            ),
        ];
        let s = stage(answers);
        let node = make_hostname_node("dual.example.com");
        let out = s.run(&fake_context(), &node).await;

        assert_eq!(out.nodes.len(), 2);
        assert_eq!(out.edges.len(), 2);
        assert_eq!(out.gaps.len(), 0);

        let kinds: Vec<_> = out.nodes.iter().map(|n| n.name.as_str()).collect();
        assert!(kinds.contains(&"203.0.113.5"), "missing IPv4 node");
        assert!(kinds.contains(&"2001:db8::1"), "missing IPv6 node");
    }

    // ------------------------------------------------------------------
    // NODATA (no A, no AAAA, no CNAME): no nodes, no gaps
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn nodata_produces_no_nodes_and_no_gaps() {
        let s = stage(vec![]); // empty fake = NoData for everything
        let node = make_hostname_node("norecords.example.com");
        let out = s.run(&fake_context(), &node).await;

        assert_eq!(out.nodes.len(), 0);
        assert_eq!(out.gaps.len(), 0);
    }

    // ------------------------------------------------------------------
    // SERVFAIL on CNAME query
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn servfail_on_cname_becomes_gap() {
        let answers = vec![FakeAnswer::servfail(
            "fail.example.com",
            QueryRecordType::Cname,
        )];
        let s = stage(answers);
        let node = make_hostname_node("fail.example.com");
        let out = s.run(&fake_context(), &node).await;

        assert_eq!(out.gaps.len(), 1);
        assert_eq!(out.gaps[0].reason, GapReason::DnsFailure);
    }

    // ------------------------------------------------------------------
    // Timeout on CNAME query
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn timeout_on_cname_becomes_gap() {
        let answers = vec![FakeAnswer::timeout(
            "slow.example.com",
            QueryRecordType::Cname,
        )];
        let s = stage(answers);
        let node = make_hostname_node("slow.example.com");
        let out = s.run(&fake_context(), &node).await;

        assert_eq!(out.gaps.len(), 1);
        assert_eq!(out.gaps[0].reason, GapReason::Timeout);
    }

    // ------------------------------------------------------------------
    // SERVFAIL on A record query
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn servfail_on_a_query_becomes_gap() {
        let answers = vec![FakeAnswer::servfail(
            "afail.example.com",
            QueryRecordType::A,
        )];
        let s = stage(answers);
        let node = make_hostname_node("afail.example.com");
        let out = s.run(&fake_context(), &node).await;

        assert!(out.gaps.iter().any(|g| g.reason == GapReason::DnsFailure));
    }

    // ------------------------------------------------------------------
    // Timeout on A record query
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn timeout_on_a_query_becomes_gap() {
        let answers = vec![FakeAnswer::timeout(
            "slowaddr.example.com",
            QueryRecordType::A,
        )];
        let s = stage(answers);
        let node = make_hostname_node("slowaddr.example.com");
        let out = s.run(&fake_context(), &node).await;

        assert!(out.gaps.iter().any(|g| g.reason == GapReason::Timeout));
    }

    // ------------------------------------------------------------------
    // Stage does not accept non-Hostname nodes
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn stage_does_not_accept_ip_nodes() {
        let s = stage(vec![]);
        let ip_node = Node {
            id: NodeId::from_ip_str("203.0.113.1").unwrap(),
            kind: NodeKind::Ip,
            provider: None,
            service: None,
            name: "203.0.113.1".to_owned(),
            identifier: None,
            attributes: serde_json::Map::new(),
            evidence: Vec::new(),
        };
        assert!(!s.accepts(&ip_node));
    }

    // ------------------------------------------------------------------
    // Stage tier
    // ------------------------------------------------------------------
    #[test]
    fn stage_tier_is_network() {
        let s = stage(vec![]);
        assert_eq!(s.tier(), Tier::Network);
    }

    // ------------------------------------------------------------------
    // Evidence includes resolver address and TTL
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn evidence_includes_resolver_and_ttl() {
        let answers = vec![FakeAnswer::a(
            "ev.example.com",
            Ipv4Addr::new(203, 0, 113, 7),
            120,
        )];
        let s = stage(answers);
        let node = make_hostname_node("ev.example.com");
        let out = s.run(&fake_context(), &node).await;

        assert_eq!(out.edges.len(), 1);
        let ev = &out.edges[0].evidence[0];
        assert_eq!(ev.source, EvidenceSource::DnsQuery);
        assert!(
            ev.attributes.contains_key("resolver"),
            "evidence missing resolver"
        );
        assert!(ev.attributes.contains_key("ttl"), "evidence missing ttl");
        let ttl = ev.attributes["ttl"].as_u64().unwrap();
        assert_eq!(ttl, 120);
    }
}
