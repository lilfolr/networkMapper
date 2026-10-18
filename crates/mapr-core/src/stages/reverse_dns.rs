//! Reverse DNS (PTR) stage.
//!
//! Accepts `Ip` nodes that are globally routable (skips non-routable / private addresses).
//! Performs a PTR lookup on the IP address.
//!
//! For each returned PTR hostname:
//! - Performs forward resolution (A and AAAA queries) on the hostname.
//! - If forward resolution returns the original IP address (forward-confirmed):
//!   - Attaches `ReverseDns` evidence with `Confidence::Observed`.
//!   - Emits a `Hostname` node and `ResolvesTo` edge with `Confidence::Observed`.
//! - If forward resolution does not include the original IP (unconfirmed):
//!   - Attaches `ReverseDns` evidence with `Confidence::Inferred` and detail explaining unconfirmed PTR.
//!   - NEVER emits a `Hostname` node.
//!
//! Tier: `Network`.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use mapr_schema::{
    Confidence, Edge, Evidence, EvidenceSource, Node, NodeId, NodeKind, Relation, Timestamp,
};

use super::{Stage, StageOutput, Tier};
use crate::engine::context::Context;
use crate::stages::dns::client::{DnsRData, DnsResponse, QueryRecordType};

/// Convert an `IpAddr` to its canonical in-addr.arpa or ip6.arpa domain name.
pub fn ip_to_ptr_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.octets();
            let mut nibbles = Vec::with_capacity(32);
            for byte in segments.iter().rev() {
                nibbles.push(format!("{:x}", byte & 0x0f));
                nibbles.push(format!("{:x}", (byte >> 4) & 0x0f));
            }
            format!("{}.ip6.arpa", nibbles.join("."))
        }
    }
}

/// Stage that resolves PTR records for IP nodes and forward-confirms them.
pub struct ReverseDnsStage;

#[async_trait]
impl Stage for ReverseDnsStage {
    fn name(&self) -> &'static str {
        "reverse_dns"
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

        // Skip private or non-routable nodes.
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

    async fn run(&self, cx: &Arc<Context>, node: &Node) -> StageOutput {
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

        let ptr_query_name = ip_to_ptr_name(ip_addr);
        let ptr_result = cx
            .dns_client
            .lookup(&ptr_query_name, QueryRecordType::Ptr)
            .await;

        let records = match ptr_result.response {
            DnsResponse::Records(recs) => recs,
            _ => return StageOutput::default(),
        };

        let mut output = StageOutput::default();
        let now = Timestamp::from(Utc::now());

        for rec in records {
            let ptr_domain = match rec.data {
                DnsRData::Ptr(domain) => domain,
                _ => continue,
            };

            let clean_domain = ptr_domain.trim_end_matches('.').to_lowercase();
            if clean_domain.is_empty() {
                continue;
            }

            // Forward lookup A and AAAA
            let a_res = cx
                .dns_client
                .lookup(&clean_domain, QueryRecordType::A)
                .await;
            let aaaa_res = cx
                .dns_client
                .lookup(&clean_domain, QueryRecordType::Aaaa)
                .await;

            let mut resolved_ips = Vec::new();
            if let DnsResponse::Records(recs) = a_res.response {
                for r in recs {
                    if let DnsRData::A(ip) = r.data {
                        resolved_ips.push(IpAddr::V4(ip));
                    }
                }
            }
            if let DnsResponse::Records(recs) = aaaa_res.response {
                for r in recs {
                    if let DnsRData::Aaaa(ip) = r.data {
                        resolved_ips.push(IpAddr::V6(ip));
                    }
                }
            }

            let is_confirmed = resolved_ips.contains(&ip_addr);

            let mut attrs = serde_json::Map::new();
            attrs.insert(
                "ptr".to_owned(),
                serde_json::Value::String(clean_domain.clone()),
            );
            attrs.insert(
                "confirmed".to_owned(),
                serde_json::Value::Bool(is_confirmed),
            );
            attrs.insert(
                "resolver".to_owned(),
                serde_json::Value::String(ptr_result.resolver.0.clone()),
            );

            if is_confirmed {
                attrs.insert(
                    "confidence".to_owned(),
                    serde_json::Value::String("observed".to_owned()),
                );
                let detail = format!("Reverse DNS PTR {} (forward confirmed)", clean_domain);
                output.evidence.push((
                    node.id.clone(),
                    Evidence {
                        source: EvidenceSource::ReverseDns,
                        detail: detail.clone(),
                        observed_at: now.clone(),
                        attributes: attrs,
                    },
                ));

                // Create confirmed Hostname node and edge
                if let Ok(hostname_node_id) = NodeId::from_hostname(&clean_domain) {
                    let hostname_node = Node {
                        id: hostname_node_id.clone(),
                        kind: NodeKind::Hostname,
                        provider: None,
                        service: None,
                        name: clean_domain.clone(),
                        identifier: None,
                        attributes: serde_json::Map::new(),
                        evidence: vec![],
                    };
                    let edge = Edge {
                        from: hostname_node_id,
                        to: node.id.clone(),
                        relation: Relation::ResolvesTo,
                        confidence: Confidence::Observed,
                        evidence: vec![Evidence {
                            source: EvidenceSource::ReverseDns,
                            detail,
                            observed_at: now.clone(),
                            attributes: serde_json::Map::new(),
                        }],
                    };
                    output.nodes.push(hostname_node);
                    output.edges.push(edge);
                }
            } else {
                attrs.insert(
                    "confidence".to_owned(),
                    serde_json::Value::String("inferred".to_owned()),
                );
                let detail = format!(
                    "Reverse DNS PTR {} (unconfirmed, forward lookup did not match {})",
                    clean_domain, ip_addr
                );
                output.evidence.push((
                    node.id.clone(),
                    Evidence {
                        source: EvidenceSource::ReverseDns,
                        detail,
                        observed_at: now.clone(),
                        attributes: attrs,
                    },
                ));
            }
        }

        output
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use crate::stages::dns::client::{FakeAnswer, FakeDnsClient};

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

    #[test]
    fn test_ip_to_ptr_name() {
        assert_eq!(
            ip_to_ptr_name("1.2.3.4".parse().unwrap()),
            "4.3.2.1.in-addr.arpa"
        );
        assert_eq!(
            ip_to_ptr_name("2001:db8::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[tokio::test]
    async fn confirmed_ptr_emits_hostname_and_evidence() {
        let ip_str = "198.51.100.1";
        let ip: Ipv4Addr = ip_str.parse().unwrap();
        let ptr_name = "1.100.51.198.in-addr.arpa";
        let hostname = "host1.example.com";

        let fake_dns = FakeDnsClient::new(vec![
            FakeAnswer {
                name: ptr_name.to_owned(),
                record_type: QueryRecordType::Ptr,
                response: DnsResponse::Records(vec![crate::stages::dns::client::DnsRecord {
                    name: ptr_name.to_owned(),
                    data: DnsRData::Ptr(hostname.to_owned()),
                    ttl: 300,
                }]),
            },
            FakeAnswer::a(hostname, ip, 300),
        ]);

        let cx = Arc::new(Context::with_fake_clock(Utc::now()).with_dns_client(fake_dns));
        let stage = ReverseDnsStage;
        let node = make_ip_node(ip_str);

        let output = stage.run(&cx, &node).await;

        assert_eq!(output.evidence.len(), 1);
        assert!(output.evidence[0].1.detail.contains("forward confirmed"));
        assert_eq!(output.nodes.len(), 1);
        assert_eq!(output.nodes[0].name, hostname);
        assert_eq!(output.edges.len(), 1);
        assert_eq!(output.edges[0].confidence, Confidence::Observed);
    }

    #[tokio::test]
    async fn unconfirmed_ptr_emits_inferred_evidence_only() {
        let ip_str = "198.51.100.2";
        let ptr_name = "2.100.51.198.in-addr.arpa";
        let hostname = "mismatch.example.com";
        let different_ip: Ipv4Addr = "198.51.100.99".parse().unwrap();

        let fake_dns = FakeDnsClient::new(vec![
            FakeAnswer {
                name: ptr_name.to_owned(),
                record_type: QueryRecordType::Ptr,
                response: DnsResponse::Records(vec![crate::stages::dns::client::DnsRecord {
                    name: ptr_name.to_owned(),
                    data: DnsRData::Ptr(hostname.to_owned()),
                    ttl: 300,
                }]),
            },
            FakeAnswer::a(hostname, different_ip, 300),
        ]);

        let cx = Arc::new(Context::with_fake_clock(Utc::now()).with_dns_client(fake_dns));
        let stage = ReverseDnsStage;
        let node = make_ip_node(ip_str);

        let output = stage.run(&cx, &node).await;

        assert_eq!(output.evidence.len(), 1);
        assert!(output.evidence[0].1.detail.contains("unconfirmed"));
        assert!(
            output.nodes.is_empty(),
            "Unconfirmed PTR must NEVER create a Hostname node"
        );
        assert!(output.edges.is_empty());
    }

    #[tokio::test]
    async fn private_node_is_not_accepted() {
        let mut node = make_ip_node("10.0.0.1");
        node.attributes
            .insert("non_routable".to_owned(), serde_json::Value::Bool(true));

        let stage = ReverseDnsStage;
        assert!(!stage.accepts(&node));
    }
}
