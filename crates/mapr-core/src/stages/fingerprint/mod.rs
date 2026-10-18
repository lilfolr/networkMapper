//! IP range classification stage (Phase 5).
//!
//! Accepts `Ip` and `Cidr` nodes and classifies them against a loaded
//! `RangeDatabase`. Emits a classified node (`Cdn`, `Compute`, etc.) linked
//! from the `Ip`/`Cidr` node by a `ServedBy` edge with `Observed` confidence.
//!
//! ## Service priority
//!
//! An AWS IP commonly matches both `AMAZON` (the umbrella) and a more
//! specific service (`EC2`, `CLOUDFRONT`, etc.). After collecting all matches
//! the stage picks the single best entry using these rules:
//!
//! 1. Longest prefix (most specific network) wins.
//! 2. When prefix lengths tie, specific services beat `EC2`, which beats
//!    `AMAZON`. Other values sort alphabetically for stability.
//!
//! All matching entries are placed in the evidence regardless.
//!
//! ## Non-routable IPs
//!
//! The classify stage (Phase 3) sets `non_routable: true` in node attributes
//! for private/loopback/etc. addresses. This stage skips those nodes; there
//! is nothing useful to look up.

pub mod loader;
pub mod providers;
pub mod range_db;

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use mapr_schema::{
    Confidence, Edge, EvidenceSource, Gap, GapReason, Node, NodeId, NodeKind, Provider, Relation,
    Timestamp,
};

use crate::engine::context::Context;
use crate::stages::{Stage, StageOutput, Tier};
use range_db::RangeDatabase;

// ---------------------------------------------------------------------------
// Stage
// ---------------------------------------------------------------------------

/// IP range classification stage.
///
/// Constructed with a pre-loaded `RangeDatabase`. The database is built by
/// the CLI (or tests) and injected here; the stage itself does no I/O.
pub struct IpRangeStage {
    db: Arc<RangeDatabase>,
}

impl IpRangeStage {
    /// Create the stage with the given database.
    pub fn new(db: Arc<RangeDatabase>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl Stage for IpRangeStage {
    fn name(&self) -> &'static str {
        "ip_range"
    }

    fn tier(&self) -> Tier {
        // The database is pre-loaded; the stage itself is offline.
        Tier::Offline
    }

    fn accepts(&self, node: &Node) -> bool {
        // Only Ip and Cidr nodes.
        if !matches!(node.kind, NodeKind::Ip | NodeKind::Cidr) {
            return false;
        }
        // Skip non-routable nodes (set by the classify stage).
        if node
            .attributes
            .get("non_routable")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return false;
        }
        true
    }

    async fn run(&self, cx: &Arc<Context>, node: &Node) -> StageOutput {
        let now = cx.now();
        let mut out = StageOutput::default();

        // Parse the IP from the node name. For Cidr nodes take the network
        // address; for Ip nodes parse directly.
        let ip: IpAddr = match parse_ip_from_node(node) {
            Some(ip) => ip,
            None => return out,
        };

        let all_matches = self.db.matches(ip);

        if all_matches.is_empty() {
            // IP not in any known range: no nodes to emit, no gap needed.
            return out;
        }

        // Pick the best entry for node classification.
        let best = match select_best(&all_matches) {
            Some(b) => b,
            None => return out,
        };

        // Build evidence from all matching entries.
        let mut ev_attrs = serde_json::Map::new();
        let all_services: Vec<serde_json::Value> = all_matches
            .iter()
            .map(|e| {
                let mut m = serde_json::Map::new();
                m.insert("prefix".to_owned(), e.prefix.to_string().into());
                m.insert("service".to_owned(), e.service.clone().into());
                if let Some(ref r) = e.region {
                    m.insert("region".to_owned(), r.clone().into());
                }
                if let Some(ref t) = e.sync_token {
                    m.insert("sync_token".to_owned(), t.clone().into());
                }
                serde_json::Value::Object(m)
            })
            .collect();
        ev_attrs.insert(
            "matched_ranges".to_owned(),
            serde_json::Value::Array(all_services),
        );
        if best.shared_edge {
            ev_attrs.insert("shared_edge".to_owned(), serde_json::Value::Bool(true));
        }

        let evidence = mapr_schema::Evidence {
            source: EvidenceSource::IpRange,
            detail: format!(
                "{} {} ({}) matched {} range(s)",
                ip,
                best.service,
                best.region.as_deref().unwrap_or("unknown region"),
                all_matches.len(),
            ),
            observed_at: Timestamp::from(now),
            attributes: ev_attrs,
        };

        // Build the classified node.
        let kind = service_to_node_kind(&best.service, &best.provider);
        let svc_name = best.service.to_lowercase();
        let classified_id = NodeId::from_provider_id(
            &format!("{}-range", provider_tag(&best.provider)),
            &format!("{}-{}", svc_name, best.prefix),
        );

        let mut classified_attrs = serde_json::Map::new();
        if best.shared_edge {
            classified_attrs.insert("shared_edge".to_owned(), serde_json::Value::Bool(true));
        }
        if let Some(ref region) = best.region {
            classified_attrs.insert("region".to_owned(), region.clone().into());
        }

        let classified_node = Node {
            id: classified_id.clone(),
            kind,
            provider: Some(best.provider.clone()),
            service: Some(svc_name.clone()),
            name: format!(
                "{} {} ({})",
                provider_tag(&best.provider).to_uppercase(),
                best.service,
                best.region.as_deref().unwrap_or("global"),
            ),
            identifier: None,
            attributes: classified_attrs,
            evidence: vec![evidence.clone()],
        };

        let edge = Edge {
            from: node.id.clone(),
            to: classified_id.clone(),
            relation: Relation::ServedBy,
            confidence: Confidence::Observed,
            evidence: vec![evidence],
        };

        // Also attach the evidence to the original IP node.
        out.evidence.push((
            node.id.clone(),
            mapr_schema::Evidence {
                source: EvidenceSource::IpRange,
                detail: format!("matched {}", best.prefix),
                observed_at: Timestamp::from(now),
                attributes: serde_json::Map::new(),
            },
        ));

        out.nodes.push(classified_node);
        out.edges.push(edge);

        // If the database is empty but we somehow got here, or if any
        // required data was missing, emit a gap. (Belt-and-suspenders; the
        // early return above should have caught the empty-match case.)
        if self.db.is_empty() {
            out.gaps.push(Gap {
                at: Some(node.id.clone()),
                reason: GapReason::NoRangeData,
                detail: "range database is empty".to_owned(),
                needs: None,
            });
        }

        out
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract an `IpAddr` from a node's name field.
fn parse_ip_from_node(node: &Node) -> Option<IpAddr> {
    // For Ip nodes the name is the dotted/colon address string.
    // For Cidr nodes we take the network address from the id (cidr:x.x.x.x/y).
    match node.kind {
        NodeKind::Ip => node.name.parse().ok(),
        NodeKind::Cidr => {
            // id is "cidr:x.x.x.x/y" - parse the prefix and take network addr.
            let id_str = node.id.as_str();
            let cidr_str = id_str.strip_prefix("cidr:")?;
            let net: ipnet::IpNet = cidr_str.parse().ok()?;
            Some(net.network())
        }
        _ => None,
    }
}

/// Select the best `RangeEntry` from a non-empty slice.
///
/// Priority: longest prefix, then service specificity.
fn select_best<'a>(matches: &[&'a range_db::RangeEntry]) -> Option<&'a range_db::RangeEntry> {
    matches.iter().copied().max_by(|a, b| {
        a.prefix_len()
            .cmp(&b.prefix_len())
            .then_with(|| service_rank(&a.service).cmp(&service_rank(&b.service)))
    })
}

/// Higher rank = more specific. Used only when prefix lengths tie.
fn service_rank(service: &str) -> u8 {
    match service {
        "AMAZON" => 0,
        "EC2" => 1,
        _ => 2, // specific services (CLOUDFRONT, S3, GLOBALACCELERATOR, etc.)
    }
}

/// Map a service name and provider to the most appropriate `NodeKind`.
fn service_to_node_kind(service: &str, provider: &Provider) -> NodeKind {
    match provider {
        Provider::Cloudflare => NodeKind::Cdn,
        Provider::Aws => match service {
            "CLOUDFRONT" => NodeKind::Cdn,
            "GLOBALACCELERATOR" => NodeKind::LoadBalancer,
            "EC2" | "AMAZON" => NodeKind::Compute,
            _ => NodeKind::Compute,
        },
        _ => NodeKind::Unknown,
    }
}

fn provider_tag(provider: &Provider) -> &'static str {
    match provider {
        Provider::Aws => "aws",
        Provider::Cloudflare => "cloudflare",
        Provider::Fastly => "fastly",
        Provider::Akamai => "akamai",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::net::Ipv4Addr;

    use mapr_schema::{NodeKind, Provider};

    use super::*;
    use crate::engine::context::Context;
    use range_db::RangeEntry;

    fn fixed_context() -> Arc<Context> {
        use chrono::{TimeZone, Utc};
        let t = Utc.with_ymd_and_hms(2025, 1, 2, 3, 4, 5).unwrap();
        Arc::new(Context::with_fake_clock(t))
    }

    fn ip_node(addr: &str) -> Node {
        let ip: IpAddr = addr.parse().unwrap();
        Node {
            id: NodeId::from_ip(ip),
            kind: NodeKind::Ip,
            provider: None,
            service: None,
            name: addr.to_owned(),
            identifier: None,
            attributes: serde_json::Map::new(),
            evidence: Vec::new(),
        }
    }

    fn non_routable_ip_node(addr: &str) -> Node {
        let mut n = ip_node(addr);
        n.attributes
            .insert("non_routable".to_owned(), serde_json::Value::Bool(true));
        n
    }

    fn db_with(entries: Vec<RangeEntry>) -> Arc<RangeDatabase> {
        let mut db = RangeDatabase::new();
        db.extend(entries);
        Arc::new(db)
    }

    fn aws_entry(cidr: &str, service: &str, shared: bool) -> RangeEntry {
        RangeEntry {
            prefix: cidr.parse().unwrap(),
            provider: Provider::Aws,
            service: service.to_owned(),
            region: Some("us-east-1".to_owned()),
            shared_edge: shared,
            sync_token: Some("1700000000".to_owned()),
        }
    }

    fn cf_entry(cidr: &str) -> RangeEntry {
        RangeEntry {
            prefix: cidr.parse().unwrap(),
            provider: Provider::Cloudflare,
            service: "cloudflare".to_owned(),
            region: None,
            shared_edge: true,
            sync_token: None,
        }
    }

    // ------------------------------------------------------------------
    // No match
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn ip_not_in_any_range_emits_nothing() {
        let db = db_with(vec![aws_entry("13.32.0.0/15", "AMAZON", false)]);
        let stage = IpRangeStage::new(db);
        let node = ip_node("198.51.100.1");
        let out = stage.run(&fixed_context(), &node).await;
        assert!(out.nodes.is_empty());
        assert!(out.edges.is_empty());
        assert!(out.gaps.is_empty());
    }

    // ------------------------------------------------------------------
    // Single match
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn single_match_emits_classified_node_and_servedby_edge() {
        let db = db_with(vec![aws_entry("13.32.0.0/15", "CLOUDFRONT", true)]);
        let stage = IpRangeStage::new(db);
        let node = ip_node("13.32.0.1");
        let out = stage.run(&fixed_context(), &node).await;
        assert_eq!(out.nodes.len(), 1);
        assert_eq!(out.edges.len(), 1);
        assert_eq!(out.edges[0].relation, Relation::ServedBy);
        assert_eq!(out.edges[0].confidence, Confidence::Observed);
    }

    // ------------------------------------------------------------------
    // Overlapping services: longest prefix wins
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn longest_prefix_wins_for_classification() {
        let db = db_with(vec![
            aws_entry("13.32.0.0/15", "AMAZON", false),
            aws_entry("13.32.0.0/24", "CLOUDFRONT", true),
        ]);
        let stage = IpRangeStage::new(db);
        let node = ip_node("13.32.0.1");
        let out = stage.run(&fixed_context(), &node).await;

        // One classified node using the /24 entry (CLOUDFRONT).
        assert_eq!(out.nodes.len(), 1);
        assert_eq!(out.nodes[0].service.as_deref(), Some("cloudfront"));
        assert_eq!(out.nodes[0].kind, NodeKind::Cdn);
    }

    // ------------------------------------------------------------------
    // Overlapping services: specific beats AMAZON at same prefix length
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn specific_service_beats_amazon_at_same_prefix_len() {
        let db = db_with(vec![
            aws_entry("13.32.0.0/15", "AMAZON", false),
            aws_entry("13.32.0.0/15", "EC2", false),
        ]);
        let stage = IpRangeStage::new(db);
        let node = ip_node("13.32.0.1");
        let out = stage.run(&fixed_context(), &node).await;

        assert_eq!(out.nodes[0].service.as_deref(), Some("ec2"));
    }

    // ------------------------------------------------------------------
    // All matching entries appear in evidence
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn all_matches_in_evidence() {
        let db = db_with(vec![
            aws_entry("13.32.0.0/15", "AMAZON", false),
            aws_entry("13.32.0.0/15", "CLOUDFRONT", true),
        ]);
        let stage = IpRangeStage::new(db);
        let node = ip_node("13.32.0.1");
        let out = stage.run(&fixed_context(), &node).await;

        let ev = &out.edges[0].evidence[0];
        let matched = ev.attributes["matched_ranges"].as_array().unwrap();
        assert_eq!(matched.len(), 2);
    }

    // ------------------------------------------------------------------
    // Anycast marking
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn anycast_node_has_shared_edge_attribute() {
        let db = db_with(vec![aws_entry("13.32.0.0/15", "CLOUDFRONT", true)]);
        let stage = IpRangeStage::new(db);
        let node = ip_node("13.32.0.1");
        let out = stage.run(&fixed_context(), &node).await;

        let n = &out.nodes[0];
        assert_eq!(
            n.attributes.get("shared_edge").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    // ------------------------------------------------------------------
    // Non-routable nodes are skipped
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn non_routable_node_is_skipped() {
        let db = db_with(vec![aws_entry("10.0.0.0/8", "AMAZON", false)]);
        let stage = IpRangeStage::new(db);
        let node = non_routable_ip_node("10.0.0.1");
        assert!(!stage.accepts(&node));
    }

    // ------------------------------------------------------------------
    // Non-Ip/Cidr nodes are rejected
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn hostname_node_not_accepted() {
        let db = db_with(vec![]);
        let stage = IpRangeStage::new(db);
        let node = Node {
            id: NodeId::from_hostname("example.com").unwrap(),
            kind: NodeKind::Hostname,
            provider: None,
            service: None,
            name: "example.com".to_owned(),
            identifier: None,
            attributes: serde_json::Map::new(),
            evidence: Vec::new(),
        };
        assert!(!stage.accepts(&node));
    }

    // ------------------------------------------------------------------
    // IPv6 match
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn ipv6_address_matched() {
        let db = db_with(vec![RangeEntry {
            prefix: "2600:1f00::/25".parse().unwrap(),
            provider: Provider::Aws,
            service: "EC2".to_owned(),
            region: Some("us-east-1".to_owned()),
            shared_edge: false,
            sync_token: None,
        }]);
        let stage = IpRangeStage::new(db);
        let node = ip_node("2600:1f00::1");
        let out = stage.run(&fixed_context(), &node).await;
        assert_eq!(out.nodes.len(), 1);
        assert_eq!(out.nodes[0].provider, Some(Provider::Aws));
    }

    // ------------------------------------------------------------------
    // Cloudflare: Cdn kind
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn cloudflare_ip_gets_cdn_kind() {
        let db = db_with(vec![cf_entry("104.16.0.0/13")]);
        let stage = IpRangeStage::new(db);
        let node = ip_node("104.16.0.1");
        let out = stage.run(&fixed_context(), &node).await;
        assert_eq!(out.nodes[0].kind, NodeKind::Cdn);
        assert_eq!(out.nodes[0].provider, Some(Provider::Cloudflare));
    }

    // ------------------------------------------------------------------
    // Stage name and tier
    // ------------------------------------------------------------------
    #[test]
    fn stage_name_and_tier() {
        let stage = IpRangeStage::new(Arc::new(RangeDatabase::new()));
        assert_eq!(stage.name(), "ip_range");
        assert_eq!(stage.tier(), Tier::Offline);
    }

    // ------------------------------------------------------------------
    // Loading from fixture files via the parsers
    // ------------------------------------------------------------------
    #[test]
    fn aws_fixture_loads_into_database() {
        use providers::aws::AwsRangeSource;
        use range_db::RangeSource;

        let src = AwsRangeSource;
        let data = include_bytes!("../../../../../tests/fixtures/ip-ranges-aws.json");
        let entries = src.parse(data).unwrap();
        let mut db = RangeDatabase::new();
        db.extend(entries);

        // 13.32.0.1 should be in the fixture (13.32.0.0/15 CLOUDFRONT + AMAZON)
        let ip: IpAddr = "13.32.0.1".parse().unwrap();
        let matches = db.matches(ip);
        assert!(!matches.is_empty());
    }

    #[test]
    fn cloudflare_fixture_loads_into_database() {
        use providers::cloudflare::CloudflareV4Source;
        use range_db::RangeSource;

        let src = CloudflareV4Source;
        let data = include_bytes!("../../../../../tests/fixtures/ip-ranges-cloudflare-v4.txt");
        let entries = src.parse(data).unwrap();
        let mut db = RangeDatabase::new();
        db.extend(entries);

        // 104.16.0.1 is in Cloudflare's 104.16.0.0/13
        let ip: IpAddr = Ipv4Addr::new(104, 16, 0, 1).into();
        assert!(db.best_match(ip).is_some());
    }
}
