//! IP classification stage.
//!
//! This stage runs on `Ip` and `Cidr` nodes and checks whether the address
//! falls in a non-routable range (private, loopback, link-local, CGNAT,
//! multicast, unspecified, documentation, or IPv6 ULA). When a match is
//! found it emits a `Private` gap and sets the `non_routable` attribute on
//! the node, which downstream stages should respect by not running further
//! network discovery against such addresses.
//!
//! Public addresses pass through without any gap or attribute.
//!
//! Tier: `Offline`. This stage does zero I/O and never accesses the network.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::OnceLock;

use async_trait::async_trait;
use ipnet::IpNet;
use mapr_schema::{Gap, GapReason, Node, NodeKind};

use super::{Stage, StageOutput, Tier};
use crate::engine::context::Context;

// ---------------------------------------------------------------------------
// Range tables
// ---------------------------------------------------------------------------

/// A single classified IP range.
struct Range {
    net: IpNet,
    label: &'static str,
}

impl Range {
    fn new(cidr: &'static str, label: &'static str) -> Self {
        // All CIDR strings here are compile-time constants; parsing failure is
        // a programming error caught by the tests below.
        let net = IpNet::from_str(cidr)
            .unwrap_or_else(|_| panic!("BUG: invalid built-in CIDR constant '{cidr}'"));
        Self { net, label }
    }
}

/// Returns the static table of non-routable ranges.
///
/// Built once via `OnceLock` and shared for the lifetime of the process.
fn non_routable_ranges() -> &'static Vec<Range> {
    static RANGES: OnceLock<Vec<Range>> = OnceLock::new();
    RANGES.get_or_init(|| {
        vec![
            // --- RFC 1918 private ---
            Range::new("10.0.0.0/8", "private (RFC 1918)"),
            Range::new("172.16.0.0/12", "private (RFC 1918)"),
            Range::new("192.168.0.0/16", "private (RFC 1918)"),
            // --- CGNAT (RFC 6598) ---
            Range::new("100.64.0.0/10", "CGNAT (RFC 6598)"),
            // --- Loopback ---
            Range::new("127.0.0.0/8", "loopback (IPv4)"),
            Range::new("::1/128", "loopback (IPv6)"),
            // --- Link-local ---
            Range::new("169.254.0.0/16", "link-local (IPv4, RFC 3927)"),
            Range::new("fe80::/10", "link-local (IPv6, RFC 4291)"),
            // --- Multicast ---
            Range::new("224.0.0.0/4", "multicast (IPv4)"),
            Range::new("ff00::/8", "multicast (IPv6)"),
            // --- Unspecified ---
            Range::new("0.0.0.0/8", "unspecified (IPv4)"),
            // IPv6 unspecified is the single address ::/128.
            Range::new("::/128", "unspecified (IPv6)"),
            // --- Documentation (RFC 5737, IPv4) ---
            Range::new("192.0.2.0/24", "documentation (RFC 5737, TEST-NET-1)"),
            Range::new("198.51.100.0/24", "documentation (RFC 5737, TEST-NET-2)"),
            Range::new("203.0.113.0/24", "documentation (RFC 5737, TEST-NET-3)"),
            // --- Documentation (RFC 3849, IPv6) ---
            Range::new("2001:db8::/32", "documentation (RFC 3849)"),
            // --- IPv6 ULA (RFC 4193) ---
            Range::new("fc00::/7", "unique local address (IPv6 ULA, RFC 4193)"),
            // --- Benchmarking (RFC 2544) ---
            Range::new("198.18.0.0/15", "benchmarking (RFC 2544)"),
            // --- Reserved for future use / IETF protocol assignments ---
            Range::new("192.0.0.0/24", "IETF protocol assignments (RFC 6890)"),
        ]
    })
}

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

/// Returns the label of the first non-routable range that contains `ip`, or
/// `None` if the address is globally routable.
fn classify_ip(ip: IpAddr) -> Option<&'static str> {
    for range in non_routable_ranges() {
        if range.net.contains(&ip) {
            return Some(range.label);
        }
    }
    None
}

/// Returns the label of the first non-routable range whose network address
/// matches `net`, or `None` if the CIDR starts in a globally routable space.
///
/// We classify by the network address only. A /8 starting at 10.x is private
/// regardless of how large it is. A CIDR that spans both routable and
/// non-routable space is uncommon in practice; we err on the side of flagging
/// it as non-routable.
fn classify_cidr(net: IpNet) -> Option<&'static str> {
    classify_ip(net.network())
}

// ---------------------------------------------------------------------------
// Stage
// ---------------------------------------------------------------------------

/// Offline stage that classifies IP and CIDR nodes as non-routable.
///
/// For non-routable addresses it emits a `Private` gap and sets the attribute
/// `non_routable: true` on the node so downstream stages skip it.
/// Public addresses pass through without any output.
pub struct ClassifyStage;

#[async_trait]
impl Stage for ClassifyStage {
    fn name(&self) -> &'static str {
        "classify"
    }

    fn tier(&self) -> Tier {
        Tier::Offline
    }

    fn accepts(&self, node: &Node) -> bool {
        matches!(node.kind, NodeKind::Ip | NodeKind::Cidr)
    }

    async fn run(&self, _cx: &Arc<Context>, node: &Node) -> StageOutput {
        let label = match &node.kind {
            NodeKind::Ip => {
                // Parse the IP from the node name. The seed builder always
                // puts the canonical IP string in `name`, so this should not
                // fail in practice. If it does, return an empty output rather
                // than crashing.
                match node.name.parse::<IpAddr>() {
                    Ok(ip) => classify_ip(ip),
                    Err(_) => {
                        // Try extracting from the id "ip:<addr>".
                        node.id
                            .as_str()
                            .strip_prefix("ip:")
                            .and_then(|s| s.parse::<IpAddr>().ok())
                            .and_then(classify_ip)
                    }
                }
            }
            NodeKind::Cidr => {
                // Try the node name first (canonical CIDR string), then id.
                match node.name.parse::<IpNet>() {
                    Ok(net) => classify_cidr(net),
                    Err(_) => node
                        .id
                        .as_str()
                        .strip_prefix("cidr:")
                        .and_then(|s| s.parse::<IpNet>().ok())
                        .and_then(classify_cidr),
                }
            }
            // accepts() guards this; the branch is unreachable in practice.
            _ => return StageOutput::default(),
        };

        if let Some(label) = label {
            // Mark the node so downstream stages know it is non-routable.
            let mut updated_node = node.clone();
            updated_node
                .attributes
                .insert("non_routable".to_owned(), serde_json::Value::Bool(true));
            updated_node.attributes.insert(
                "non_routable_reason".to_owned(),
                serde_json::Value::String(label.to_owned()),
            );

            StageOutput {
                nodes: vec![updated_node],
                edges: vec![],
                evidence: vec![],
                gaps: vec![Gap {
                    at: Some(node.id.clone()),
                    reason: GapReason::Private,
                    detail: format!("{} is in a non-routable range: {}", node.name, label),
                    needs: None,
                }],
            }
        } else {
            // Globally routable: nothing to add.
            StageOutput::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::engine::context::Context;
    use chrono::Utc;
    use mapr_schema::{GapReason, NodeId, NodeKind};

    fn fake_context() -> Arc<Context> {
        Arc::new(Context::with_fake_clock(Utc::now()))
    }

    fn ip_node(addr: &str) -> Node {
        Node {
            id: NodeId::from_ip(addr.parse().unwrap()),
            kind: NodeKind::Ip,
            provider: None,
            service: None,
            name: addr.to_owned(),
            identifier: None,
            attributes: serde_json::Map::new(),
            evidence: Vec::new(),
        }
    }

    fn cidr_node(cidr: &str) -> Node {
        let net: IpNet = cidr.parse().unwrap();
        Node {
            id: NodeId::from_cidr(net),
            kind: NodeKind::Cidr,
            provider: None,
            service: None,
            name: net.to_string(),
            identifier: None,
            attributes: serde_json::Map::new(),
            evidence: Vec::new(),
        }
    }

    async fn classify(addr: &str) -> StageOutput {
        let node = ip_node(addr);
        ClassifyStage.run(&fake_context(), &node).await
    }

    async fn classify_cidr(cidr: &str) -> StageOutput {
        let node = cidr_node(cidr);
        ClassifyStage.run(&fake_context(), &node).await
    }

    fn is_private_gap(output: &StageOutput) -> bool {
        output.gaps.iter().any(|g| g.reason == GapReason::Private)
    }

    fn is_clean(output: &StageOutput) -> bool {
        output.gaps.is_empty() && output.nodes.is_empty()
    }

    // -----------------------------------------------------------------------
    // Stage metadata
    // -----------------------------------------------------------------------

    #[test]
    fn stage_name_and_tier() {
        assert_eq!(ClassifyStage.name(), "classify");
        assert_eq!(ClassifyStage.tier(), Tier::Offline);
    }

    #[test]
    fn accepts_ip_and_cidr_only() {
        let ip = ip_node("1.2.3.4");
        let cidr = cidr_node("1.0.0.0/8");
        let hostname = Node {
            id: NodeId::from_raw("hostname:example.com"),
            kind: NodeKind::Hostname,
            provider: None,
            service: None,
            name: "example.com".to_owned(),
            identifier: None,
            attributes: serde_json::Map::new(),
            evidence: Vec::new(),
        };
        assert!(ClassifyStage.accepts(&ip));
        assert!(ClassifyStage.accepts(&cidr));
        assert!(!ClassifyStage.accepts(&hostname));
    }

    // -----------------------------------------------------------------------
    // RFC 1918 private ranges
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rfc1918_10_first() {
        assert!(is_private_gap(&classify("10.0.0.0").await));
    }

    #[tokio::test]
    async fn rfc1918_10_last() {
        assert!(is_private_gap(&classify("10.255.255.255").await));
    }

    #[tokio::test]
    async fn rfc1918_172_first() {
        assert!(is_private_gap(&classify("172.16.0.0").await));
    }

    #[tokio::test]
    async fn rfc1918_172_last() {
        assert!(is_private_gap(&classify("172.31.255.255").await));
    }

    #[tokio::test]
    async fn rfc1918_192_168_first() {
        assert!(is_private_gap(&classify("192.168.0.0").await));
    }

    #[tokio::test]
    async fn rfc1918_192_168_last() {
        assert!(is_private_gap(&classify("192.168.255.255").await));
    }

    // -----------------------------------------------------------------------
    // CGNAT (RFC 6598): 100.64.0.0/10
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn cgnat_first() {
        assert!(is_private_gap(&classify("100.64.0.0").await));
    }

    #[tokio::test]
    async fn cgnat_last() {
        assert!(is_private_gap(&classify("100.127.255.255").await));
    }

    #[tokio::test]
    async fn cgnat_boundary_just_before() {
        // 100.63.255.255 is just outside CGNAT: public.
        assert!(is_clean(&classify("100.63.255.255").await));
    }

    #[tokio::test]
    async fn cgnat_boundary_just_after() {
        // 100.128.0.0 is just outside CGNAT: public.
        assert!(is_clean(&classify("100.128.0.0").await));
    }

    // -----------------------------------------------------------------------
    // Loopback
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn loopback_ipv4_127_0_0_1() {
        assert!(is_private_gap(&classify("127.0.0.1").await));
    }

    #[tokio::test]
    async fn loopback_ipv4_first() {
        assert!(is_private_gap(&classify("127.0.0.0").await));
    }

    #[tokio::test]
    async fn loopback_ipv4_last() {
        assert!(is_private_gap(&classify("127.255.255.255").await));
    }

    #[tokio::test]
    async fn loopback_ipv6() {
        assert!(is_private_gap(&classify("::1").await));
    }

    // -----------------------------------------------------------------------
    // Link-local
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn link_local_ipv4_first() {
        assert!(is_private_gap(&classify("169.254.0.0").await));
    }

    #[tokio::test]
    async fn link_local_ipv4_last() {
        assert!(is_private_gap(&classify("169.254.255.255").await));
    }

    #[tokio::test]
    async fn link_local_ipv6_first() {
        // fe80::
        assert!(is_private_gap(&classify("fe80::").await));
    }

    #[tokio::test]
    async fn link_local_ipv6_last() {
        // febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff is the last address in fe80::/10.
        assert!(is_private_gap(
            &classify("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff").await
        ));
    }

    // -----------------------------------------------------------------------
    // Multicast
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn multicast_ipv4_first() {
        assert!(is_private_gap(&classify("224.0.0.0").await));
    }

    #[tokio::test]
    async fn multicast_ipv4_last() {
        assert!(is_private_gap(&classify("239.255.255.255").await));
    }

    #[tokio::test]
    async fn multicast_ipv6_first() {
        assert!(is_private_gap(&classify("ff00::").await));
    }

    #[tokio::test]
    async fn multicast_ipv6_last() {
        assert!(is_private_gap(
            &classify("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").await
        ));
    }

    // -----------------------------------------------------------------------
    // Unspecified
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unspecified_ipv4_0_0_0_0() {
        assert!(is_private_gap(&classify("0.0.0.0").await));
    }

    #[tokio::test]
    async fn unspecified_ipv4_last_of_range() {
        // 0.x.x.x is the 0.0.0.0/8 range.
        assert!(is_private_gap(&classify("0.255.255.255").await));
    }

    #[tokio::test]
    async fn unspecified_ipv6() {
        assert!(is_private_gap(&classify("::").await));
    }

    // -----------------------------------------------------------------------
    // Documentation ranges
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn documentation_rfc5737_net1_first() {
        assert!(is_private_gap(&classify("192.0.2.0").await));
    }

    #[tokio::test]
    async fn documentation_rfc5737_net1_last() {
        assert!(is_private_gap(&classify("192.0.2.255").await));
    }

    #[tokio::test]
    async fn documentation_rfc5737_net2_first() {
        assert!(is_private_gap(&classify("198.51.100.0").await));
    }

    #[tokio::test]
    async fn documentation_rfc5737_net2_last() {
        assert!(is_private_gap(&classify("198.51.100.255").await));
    }

    #[tokio::test]
    async fn documentation_rfc5737_net3_first() {
        assert!(is_private_gap(&classify("203.0.113.0").await));
    }

    #[tokio::test]
    async fn documentation_rfc5737_net3_last() {
        assert!(is_private_gap(&classify("203.0.113.255").await));
    }

    #[tokio::test]
    async fn documentation_rfc3849_ipv6_first() {
        assert!(is_private_gap(&classify("2001:db8::").await));
    }

    #[tokio::test]
    async fn documentation_rfc3849_ipv6_last() {
        assert!(is_private_gap(
            &classify("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff").await
        ));
    }

    // -----------------------------------------------------------------------
    // IPv6 ULA (fc00::/7)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ula_fc00_first() {
        assert!(is_private_gap(&classify("fc00::").await));
    }

    #[tokio::test]
    async fn ula_fc00_last() {
        assert!(is_private_gap(
            &classify("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").await
        ));
    }

    #[tokio::test]
    async fn ula_fd00_typical() {
        // fd00::/8 is the most commonly seen ULA prefix.
        assert!(is_private_gap(&classify("fd00::1").await));
    }

    // -----------------------------------------------------------------------
    // Public (globally routable) addresses - must pass through clean
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn public_ipv4_1_1_1_1() {
        assert!(is_clean(&classify("1.1.1.1").await));
    }

    #[tokio::test]
    async fn public_ipv4_8_8_8_8() {
        assert!(is_clean(&classify("8.8.8.8").await));
    }

    #[tokio::test]
    async fn public_ipv6_2606() {
        assert!(is_clean(&classify("2606:4700::1111").await));
    }

    #[tokio::test]
    async fn public_boundary_just_after_172_31() {
        // 172.32.0.0 is just outside 172.16.0.0/12: public.
        assert!(is_clean(&classify("172.32.0.0").await));
    }

    #[tokio::test]
    async fn public_boundary_just_before_192_168() {
        // 192.167.255.255 is just before 192.168.0.0/16: public.
        assert!(is_clean(&classify("192.167.255.255").await));
    }

    // -----------------------------------------------------------------------
    // CIDR node classification
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn cidr_private_10_slash_8() {
        assert!(is_private_gap(&classify_cidr("10.0.0.0/8").await));
    }

    #[tokio::test]
    async fn cidr_private_192_168() {
        assert!(is_private_gap(&classify_cidr("192.168.1.0/24").await));
    }

    #[tokio::test]
    async fn cidr_documentation_203() {
        assert!(is_private_gap(&classify_cidr("203.0.113.0/24").await));
    }

    #[tokio::test]
    async fn cidr_public_passes_through() {
        assert!(is_clean(&classify_cidr("1.0.0.0/8").await));
    }

    #[tokio::test]
    async fn cidr_public_ipv6() {
        assert!(is_clean(&classify_cidr("2606:4700::/32").await));
    }

    #[tokio::test]
    async fn cidr_ula_ipv6() {
        assert!(is_private_gap(&classify_cidr("fd00::/8").await));
    }

    // -----------------------------------------------------------------------
    // Output correctness: attributes set on the returned node
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn private_ip_sets_non_routable_attribute() {
        let output = classify("10.0.0.1").await;
        assert_eq!(output.nodes.len(), 1);
        let node = &output.nodes[0];
        assert_eq!(
            node.attributes.get("non_routable"),
            Some(&serde_json::Value::Bool(true))
        );
        assert!(node.attributes.contains_key("non_routable_reason"));
    }

    #[tokio::test]
    async fn gap_references_correct_node_id() {
        let addr = "10.0.0.1";
        let output = classify(addr).await;
        let gap = output.gaps.first().expect("expected a gap");
        assert_eq!(gap.at.as_ref().map(|id| id.as_str()), Some("ip:10.0.0.1"));
        assert_eq!(gap.reason, GapReason::Private);
    }

    #[tokio::test]
    async fn public_ip_emits_no_nodes_no_gaps() {
        let output = classify("93.184.216.34").await;
        assert!(output.nodes.is_empty());
        assert!(output.gaps.is_empty());
        assert!(output.edges.is_empty());
        assert!(output.evidence.is_empty());
    }
}
