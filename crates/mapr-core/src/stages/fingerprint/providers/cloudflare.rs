//! Cloudflare IP range provider.
//!
//! Cloudflare publishes two plain-text files, one per address family:
//! - IPv4: <https://www.cloudflare.com/ips-v4>
//! - IPv6: <https://www.cloudflare.com/ips-v6>
//!
//! Each file is one CIDR per line, with no header or metadata. There is no
//! sync token; we use an empty string for the token field.
//!
//! All Cloudflare IPs are shared-edge (anycast); `shared_edge` is always
//! `true`. There is no per-prefix region information.

use mapr_schema::Provider;

use crate::stages::fingerprint::range_db::{RangeEntry, RangeSource};

// ---------------------------------------------------------------------------
// IPv4 source
// ---------------------------------------------------------------------------

/// Cloudflare IPv4 range source.
pub struct CloudflareV4Source;

impl RangeSource for CloudflareV4Source {
    fn name(&self) -> &'static str {
        "cloudflare-v4"
    }

    fn url(&self) -> &'static str {
        "https://www.cloudflare.com/ips-v4"
    }

    fn parse(&self, data: &[u8]) -> Result<Vec<RangeEntry>, String> {
        parse_cidr_list(data)
    }
}

// ---------------------------------------------------------------------------
// IPv6 source
// ---------------------------------------------------------------------------

/// Cloudflare IPv6 range source.
pub struct CloudflareV6Source;

impl RangeSource for CloudflareV6Source {
    fn name(&self) -> &'static str {
        "cloudflare-v6"
    }

    fn url(&self) -> &'static str {
        "https://www.cloudflare.com/ips-v6"
    }

    fn parse(&self, data: &[u8]) -> Result<Vec<RangeEntry>, String> {
        parse_cidr_list(data)
    }
}

// ---------------------------------------------------------------------------
// Shared parser
// ---------------------------------------------------------------------------

fn parse_cidr_list(data: &[u8]) -> Result<Vec<RangeEntry>, String> {
    let text = std::str::from_utf8(data)
        .map_err(|e| format!("Cloudflare range file is not valid UTF-8: {e}"))?;

    let mut entries = Vec::new();

    for (line_num, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Lines may be bare IPs without a prefix length; treat them as /32
        // or /128. `IpNet::from_str` handles both CIDR and bare IP forms.
        let prefix = line
            .parse()
            .map_err(|e| format!("invalid CIDR on line {}: {e}", line_num + 1))?;

        entries.push(RangeEntry {
            prefix,
            provider: Provider::Cloudflare,
            service: "cloudflare".to_owned(),
            region: None,
            shared_edge: true,
            sync_token: None,
        });
    }

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn v4_fixture() -> &'static [u8] {
        include_bytes!("../../../../../../tests/fixtures/ip-ranges-cloudflare-v4.txt")
    }

    fn v6_fixture() -> &'static [u8] {
        include_bytes!("../../../../../../tests/fixtures/ip-ranges-cloudflare-v6.txt")
    }

    #[test]
    fn parses_v4_fixture() {
        let entries = CloudflareV4Source.parse(v4_fixture()).unwrap();
        assert_eq!(entries.len(), 15);
        assert!(entries.iter().all(|e| e.prefix.addr().is_ipv4()));
    }

    #[test]
    fn parses_v6_fixture() {
        let entries = CloudflareV6Source.parse(v6_fixture()).unwrap();
        assert_eq!(entries.len(), 7);
        assert!(entries.iter().all(|e| e.prefix.addr().is_ipv6()));
    }

    #[test]
    fn all_cloudflare_are_shared_edge() {
        let entries = CloudflareV4Source.parse(v4_fixture()).unwrap();
        assert!(entries.iter().all(|e| e.shared_edge));
    }

    #[test]
    fn all_cloudflare_provider() {
        let entries = CloudflareV4Source.parse(v4_fixture()).unwrap();
        assert!(entries.iter().all(|e| e.provider == Provider::Cloudflare));
    }

    #[test]
    fn skip_blank_lines() {
        let data = b"103.21.244.0/22\n\n103.22.200.0/22\n";
        let entries = CloudflareV4Source.parse(data).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn skip_comment_lines() {
        let data = b"# comment\n103.21.244.0/22\n";
        let entries = CloudflareV4Source.parse(data).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn malformed_cidr_returns_error() {
        let data = b"not-a-cidr\n";
        assert!(CloudflareV4Source.parse(data).is_err());
    }
}
