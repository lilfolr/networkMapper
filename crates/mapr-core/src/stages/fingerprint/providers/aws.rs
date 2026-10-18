//! AWS IP range provider.
//!
//! Parses the `ip-ranges.json` file published by AWS at:
//! <https://ip-ranges.amazonaws.com/ip-ranges.json>
//!
//! Fields used: `ip_prefix` / `ipv6_prefix`, `region`, `service`,
//! `network_border_group`. The top-level `syncToken` is stored in evidence.
//!
//! Overlap handling: an IP commonly matches `AMAZON` (the umbrella) and a
//! more specific service (`EC2`, `CLOUDFRONT`, `GLOBALACCELERATOR`, `S3`,
//! etc.). All matching entries are kept; `best_match` selects by prefix
//! length. When prefix lengths are equal, service specificity is used by
//! the stage (not by this parser).
//!
//! Shared-edge services: `CLOUDFRONT` and `GLOBALACCELERATOR` are marked
//! `shared_edge: true` because a single IP serves many customers and does
//! not identify an origin.

use mapr_schema::Provider;
use serde::Deserialize;

use crate::stages::fingerprint::range_db::{RangeEntry, RangeSource};

// ---------------------------------------------------------------------------
// JSON shapes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AwsRangeFile {
    #[serde(rename = "syncToken")]
    sync_token: String,
    prefixes: Vec<AwsPrefix>,
    ipv6_prefixes: Vec<AwsIpv6Prefix>,
}

#[derive(Debug, Deserialize)]
struct AwsPrefix {
    ip_prefix: String,
    region: String,
    service: String,
    network_border_group: String,
}

#[derive(Debug, Deserialize)]
struct AwsIpv6Prefix {
    ipv6_prefix: String,
    region: String,
    service: String,
    network_border_group: String,
}

// ---------------------------------------------------------------------------
// Shared-edge service names
// ---------------------------------------------------------------------------

/// Services whose IPs are shared-edge (anycast) and do not identify an origin.
fn is_shared_edge(service: &str) -> bool {
    matches!(service, "CLOUDFRONT" | "GLOBALACCELERATOR")
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// AWS IP range source.
pub struct AwsRangeSource;

impl RangeSource for AwsRangeSource {
    fn name(&self) -> &'static str {
        "aws"
    }

    fn url(&self) -> &'static str {
        "https://ip-ranges.amazonaws.com/ip-ranges.json"
    }

    fn parse(&self, data: &[u8]) -> Result<Vec<RangeEntry>, String> {
        let file: AwsRangeFile = serde_json::from_slice(data)
            .map_err(|e| format!("failed to parse AWS ip-ranges.json: {e}"))?;

        let mut entries = Vec::with_capacity(file.prefixes.len() + file.ipv6_prefixes.len());

        for p in &file.prefixes {
            let prefix = p
                .ip_prefix
                .parse()
                .map_err(|e| format!("invalid AWS prefix '{}': {e}", p.ip_prefix))?;
            entries.push(RangeEntry {
                prefix,
                provider: Provider::Aws,
                service: p.service.clone(),
                region: Some(p.region.clone()),
                shared_edge: is_shared_edge(&p.service),
                sync_token: Some(file.sync_token.clone()),
            });
            // Suppress unused field warning; we keep network_border_group
            // available for future use but do not store it yet.
            let _ = &p.network_border_group;
        }

        for p in &file.ipv6_prefixes {
            let prefix = p
                .ipv6_prefix
                .parse()
                .map_err(|e| format!("invalid AWS IPv6 prefix '{}': {e}", p.ipv6_prefix))?;
            entries.push(RangeEntry {
                prefix,
                provider: Provider::Aws,
                service: p.service.clone(),
                region: Some(p.region.clone()),
                shared_edge: is_shared_edge(&p.service),
                sync_token: Some(file.sync_token.clone()),
            });
            let _ = &p.network_border_group;
        }

        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn fixture() -> &'static [u8] {
        include_bytes!("../../../../../../tests/fixtures/ip-ranges-aws.json")
    }

    #[test]
    fn parses_fixture_without_error() {
        let src = AwsRangeSource;
        let entries = src.parse(fixture()).expect("fixture must parse");
        // Fixture has 10 IPv4 prefixes + 2 IPv6 prefixes
        assert_eq!(entries.len(), 12);
    }

    #[test]
    fn cloudfront_is_shared_edge() {
        let src = AwsRangeSource;
        let entries = src.parse(fixture()).unwrap();
        let cf = entries.iter().find(|e| e.service == "CLOUDFRONT").unwrap();
        assert!(cf.shared_edge);
    }

    #[test]
    fn ec2_is_not_shared_edge() {
        let src = AwsRangeSource;
        let entries = src.parse(fixture()).unwrap();
        let ec2 = entries.iter().find(|e| e.service == "EC2").unwrap();
        assert!(!ec2.shared_edge);
    }

    #[test]
    fn globalaccelerator_is_shared_edge() {
        let src = AwsRangeSource;
        let entries = src.parse(fixture()).unwrap();
        let ga = entries
            .iter()
            .find(|e| e.service == "GLOBALACCELERATOR")
            .unwrap();
        assert!(ga.shared_edge);
    }

    #[test]
    fn sync_token_propagated() {
        let src = AwsRangeSource;
        let entries = src.parse(fixture()).unwrap();
        assert!(entries[0].sync_token.is_some());
        assert_eq!(entries[0].sync_token.as_deref(), Some("1700000000"));
    }

    #[test]
    fn ipv6_entries_parsed() {
        let src = AwsRangeSource;
        let entries = src.parse(fixture()).unwrap();
        let v6: Vec<_> = entries
            .iter()
            .filter(|e| e.prefix.addr().is_ipv6())
            .collect();
        assert_eq!(v6.len(), 2);
    }

    #[test]
    fn malformed_json_returns_error() {
        let src = AwsRangeSource;
        assert!(src.parse(b"not json").is_err());
    }

    #[test]
    fn region_propagated() {
        let src = AwsRangeSource;
        let entries = src.parse(fixture()).unwrap();
        assert!(entries.iter().all(|e| e.region.is_some()));
    }
}
