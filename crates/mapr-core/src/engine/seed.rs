//! Seed parsing: convert a user-supplied string into a typed starting point.
//!
//! A seed is the single piece of input the user provides. The engine converts
//! it into a starting `Node` and places it on the frontier.

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use mapr_schema::{Node, NodeId, NodeIdError, NodeKind, Target, TargetKind};
use thiserror::Error;

/// The parsed form of the user's target input.
#[derive(Debug, Clone)]
pub enum Seed {
    Hostname(String),
    Ip(IpAddr),
    Cidr(IpNet),
}

/// Errors that can occur when parsing a seed from a string.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SeedError {
    #[error("invalid hostname: {0}")]
    InvalidHostname(String),
    #[error("invalid input (not a hostname, IP, or CIDR): {0}")]
    Unparseable(String),
}

impl From<NodeIdError> for SeedError {
    fn from(e: NodeIdError) -> Self {
        match e {
            NodeIdError::InvalidHostname(h) => SeedError::InvalidHostname(h),
            other => SeedError::Unparseable(other.to_string()),
        }
    }
}

impl Seed {
    /// Parse a raw string into a seed.
    ///
    /// Precedence:
    /// 1. If the string contains '/' and parses as CIDR, it is a CIDR.
    /// 2. If it parses as an IP address, it is an IP.
    /// 3. Otherwise it is treated as a hostname.
    ///
    /// The hostname path will return an error if the string is empty or not
    /// valid IDNA.
    pub fn parse(input: &str) -> Result<Self, SeedError> {
        let trimmed = input.trim();

        if trimmed.is_empty() {
            return Err(SeedError::InvalidHostname(input.to_owned()));
        }

        // CIDR: must contain a '/' and parse as a valid CIDR range.
        if trimmed.contains('/') {
            if let Ok(net) = IpNet::from_str(trimmed) {
                return Ok(Seed::Cidr(net));
            }
        }

        // IP address: try parsing without a prefix length.
        if let Ok(ip) = IpAddr::from_str(trimmed) {
            return Ok(Seed::Ip(ip));
        }

        // Hostname: validate via IDNA. This also rejects obvious garbage.
        // We strip a trailing dot before validation (valid in DNS but not IDNA).
        let hostname = trimmed.strip_suffix('.').unwrap_or(trimmed);
        let ascii = idna::domain_to_ascii(hostname)
            .map_err(|_| SeedError::InvalidHostname(trimmed.to_owned()))?;
        if ascii.is_empty() {
            return Err(SeedError::InvalidHostname(trimmed.to_owned()));
        }

        Ok(Seed::Hostname(trimmed.to_owned()))
    }

    /// Return a `Target` struct describing the original input and its kind.
    pub fn as_target(&self, raw_input: &str) -> Target {
        let kind = match self {
            Seed::Hostname(_) => TargetKind::Hostname,
            Seed::Ip(_) => TargetKind::Ip,
            Seed::Cidr(_) => TargetKind::Cidr,
        };
        Target {
            input: raw_input.to_owned(),
            kind,
        }
    }

    /// Build the starting `Node` for this seed.
    pub fn to_node(&self) -> Result<Node, SeedError> {
        match self {
            Seed::Hostname(h) => {
                let id = NodeId::from_hostname(h)?;
                Ok(Node {
                    id,
                    kind: NodeKind::Hostname,
                    provider: None,
                    service: None,
                    name: h.clone(),
                    identifier: None,
                    attributes: serde_json::Map::new(),
                    evidence: Vec::new(),
                })
            }
            Seed::Ip(ip) => {
                let id = NodeId::from_ip(*ip);
                Ok(Node {
                    id,
                    kind: NodeKind::Ip,
                    provider: None,
                    service: None,
                    name: ip.to_string(),
                    identifier: None,
                    attributes: serde_json::Map::new(),
                    evidence: Vec::new(),
                })
            }
            Seed::Cidr(net) => {
                let id = NodeId::from_cidr(*net);
                Ok(Node {
                    id,
                    kind: NodeKind::Cidr,
                    provider: None,
                    service: None,
                    name: net.to_string(),
                    identifier: None,
                    attributes: serde_json::Map::new(),
                    evidence: Vec::new(),
                })
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    // --- Hostname ---

    #[test]
    fn parses_plain_hostname() {
        let s = Seed::parse("api.example.com").unwrap();
        assert!(matches!(s, Seed::Hostname(_)));
    }

    #[test]
    fn parses_hostname_with_trailing_dot() {
        // Trailing dot is valid DNS notation; should parse as hostname.
        let s = Seed::parse("api.example.com.").unwrap();
        assert!(matches!(s, Seed::Hostname(_)));
    }

    #[test]
    fn parses_unicode_hostname() {
        let s = Seed::parse("例え.jp").unwrap();
        assert!(matches!(s, Seed::Hostname(_)));
    }

    #[test]
    fn invalid_hostname_returns_error() {
        // An empty string fails IDNA processing.
        let err = Seed::parse("").unwrap_err();
        assert!(matches!(err, SeedError::InvalidHostname(_)));
    }

    // --- IP ---

    #[test]
    fn parses_ipv4() {
        let s = Seed::parse("203.0.113.5").unwrap();
        assert!(matches!(s, Seed::Ip(IpAddr::V4(_))));
    }

    #[test]
    fn parses_ipv6() {
        let s = Seed::parse("2001:db8::1").unwrap();
        assert!(matches!(s, Seed::Ip(IpAddr::V6(_))));
    }

    // --- CIDR ---

    #[test]
    fn parses_cidr_v4() {
        let s = Seed::parse("203.0.113.0/24").unwrap();
        assert!(matches!(s, Seed::Cidr(_)));
    }

    #[test]
    fn parses_cidr_v6() {
        let s = Seed::parse("2001:db8::/32").unwrap();
        assert!(matches!(s, Seed::Cidr(_)));
    }

    #[test]
    fn slash_in_non_cidr_string_is_invalid() {
        // "example.com/path" - not a valid CIDR and not a valid IP.
        // IDNA may or may not accept it as a hostname; what matters is it
        // is never parsed as Seed::Cidr.
        let result = Seed::parse("example.com/path");
        if let Ok(s) = result {
            assert!(
                !matches!(s, Seed::Cidr(_)),
                "example.com/path must not parse as CIDR"
            );
        }
        // An error result is also acceptable: the input is not meaningful.
    }

    // --- to_node ---

    #[test]
    fn hostname_seed_builds_node() {
        let seed = Seed::parse("api.example.com").unwrap();
        let node = seed.to_node().unwrap();
        assert_eq!(node.kind, NodeKind::Hostname);
        assert_eq!(node.id.as_str(), "hostname:api.example.com");
        assert_eq!(node.name, "api.example.com");
    }

    #[test]
    fn ip_seed_builds_node() {
        let seed = Seed::parse("203.0.113.5").unwrap();
        let node = seed.to_node().unwrap();
        assert_eq!(node.kind, NodeKind::Ip);
        assert_eq!(node.id.as_str(), "ip:203.0.113.5");
    }

    #[test]
    fn cidr_seed_builds_node() {
        // Non-normalized input: host bits are set.
        let seed = Seed::parse("10.0.0.5/8").unwrap();
        let node = seed.to_node().unwrap();
        assert_eq!(node.kind, NodeKind::Cidr);
        // NodeId normalizes the network address.
        assert_eq!(node.id.as_str(), "cidr:10.0.0.0/8");
    }

    #[test]
    fn as_target_hostname() {
        let seed = Seed::parse("example.com").unwrap();
        let target = seed.as_target("example.com");
        assert_eq!(target.input, "example.com");
        assert_eq!(target.kind, TargetKind::Hostname);
    }

    #[test]
    fn as_target_ip() {
        let seed = Seed::parse("1.2.3.4").unwrap();
        let target = seed.as_target("1.2.3.4");
        assert_eq!(target.kind, TargetKind::Ip);
    }

    #[test]
    fn as_target_cidr() {
        let seed = Seed::parse("10.0.0.0/8").unwrap();
        let target = seed.as_target("10.0.0.0/8");
        assert_eq!(target.kind, TargetKind::Cidr);
    }

    // --- IPv4-mapped IPv6 ---

    #[test]
    fn ipv4_mapped_ipv6_parses_as_ip() {
        // "::ffff:203.0.113.5" is a valid IpAddr
        let s = Seed::parse("::ffff:203.0.113.5").unwrap();
        assert!(matches!(s, Seed::Ip(IpAddr::V6(_))));
        // The node id should normalize to IPv4.
        let node = s.to_node().unwrap();
        assert_eq!(node.id.as_str(), "ip:203.0.113.5");
    }
}
