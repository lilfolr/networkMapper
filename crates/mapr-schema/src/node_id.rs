//! NodeId construction and canonicalization rules.
//!
//! Rules:
//! - Hostnames: lowercase, strip trailing dot, convert via IDNA to ASCII (punycode).
//! - IPv4: dotted-quad canonical form.
//! - IPv6: compressed lowercase. IPv4-mapped IPv6 (::ffff:a.b.c.d) normalizes to
//!   the plain IPv4 form.
//! - CIDR: normalized to the network address (host bits zeroed).
//! - Provider resources: the real identifier (ARN, resource ID) as-is.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A stable string identifier for a graph node.
///
/// Built from a canonical key so that the same real-world entity always
/// produces the same `NodeId` regardless of how it was discovered.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct NodeId(String);

impl NodeId {
    /// Returns the raw string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Build a `NodeId` from a hostname string.
    ///
    /// Applies IDNA processing (lowercase + punycode) and strips any trailing
    /// dot. Returns an error when the hostname is invalid per IDNA rules.
    pub fn from_hostname(hostname: &str) -> Result<Self, NodeIdError> {
        let stripped = hostname.strip_suffix('.').unwrap_or(hostname);
        // idna::domain_to_ascii lowercases and converts unicode labels to punycode.
        let ascii = idna::domain_to_ascii(stripped)
            .map_err(|_| NodeIdError::InvalidHostname(hostname.to_owned()))?;
        if ascii.is_empty() {
            return Err(NodeIdError::InvalidHostname(hostname.to_owned()));
        }
        Ok(Self(format!("hostname:{ascii}")))
    }

    /// Build a `NodeId` from an IP address.
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are normalized to their
    /// plain IPv4 form. IPv6 is stored in compressed lowercase.
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self(format!("ip:{v4}")),
            IpAddr::V6(v6) => {
                // Normalize IPv4-mapped IPv6 to plain IPv4.
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return Self(format!("ip:{v4}"));
                }
                // std Display for Ipv6Addr uses compressed lowercase form.
                Self(format!("ip:{v6}"))
            }
        }
    }

    /// Build a `NodeId` from an `IpAddr` parsed from a string.
    ///
    /// Returns an error on parse failure.
    pub fn from_ip_str(s: &str) -> Result<Self, NodeIdError> {
        let ip = IpAddr::from_str(s).map_err(|_| NodeIdError::InvalidIp(s.to_owned()))?;
        Ok(Self::from_ip(ip))
    }

    /// Build a `NodeId` from a CIDR range, normalizing to the network address.
    ///
    /// `10.0.0.5/8` becomes `cidr:10.0.0.0/8`.
    pub fn from_cidr(net: IpNet) -> Self {
        // `trunc()` zeros the host bits to give the true network address.
        Self(format!("cidr:{}", net.trunc()))
    }

    /// Build a `NodeId` from a CIDR string.
    ///
    /// Returns an error on parse failure.
    pub fn from_cidr_str(s: &str) -> Result<Self, NodeIdError> {
        let net = IpNet::from_str(s).map_err(|_| NodeIdError::InvalidCidr(s.to_owned()))?;
        Ok(Self::from_cidr(net))
    }

    /// Build a `NodeId` for a provider resource using its real identifier.
    ///
    /// `kind` is a short tag such as `"arn"` or `"resource"`.
    pub fn from_provider_id(kind: &str, id: &str) -> Self {
        Self(format!("{kind}:{id}"))
    }

    /// Build a `NodeId` directly from an already-canonical string.
    ///
    /// Prefer the typed constructors. This exists for deserialization and
    /// testing only.
    pub fn from_raw(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<NodeId> for String {
    fn from(id: NodeId) -> Self {
        id.0
    }
}

/// Errors that can occur when constructing a `NodeId`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NodeIdError {
    #[error("invalid hostname: {0}")]
    InvalidHostname(String),
    #[error("invalid IP address: {0}")]
    InvalidIp(String),
    #[error("invalid CIDR: {0}")]
    InvalidCidr(String),
}

// ---------------------------------------------------------------------------
// Helper: build a NodeId from a plain IPv6 address (unambiguously IPv6 form).
// Exposed so other modules can construct IPv6 node IDs from Ipv6Addr directly.
// ---------------------------------------------------------------------------
impl From<Ipv4Addr> for NodeId {
    fn from(v4: Ipv4Addr) -> Self {
        Self::from_ip(IpAddr::V4(v4))
    }
}

impl From<Ipv6Addr> for NodeId {
    fn from(v6: Ipv6Addr) -> Self {
        Self::from_ip(IpAddr::V6(v6))
    }
}

impl From<IpAddr> for NodeId {
    fn from(ip: IpAddr) -> Self {
        Self::from_ip(ip)
    }
}

impl From<IpNet> for NodeId {
    fn from(net: IpNet) -> Self {
        Self::from_cidr(net)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // --- Hostname canonicalization ---

    #[test]
    fn hostname_lowercase() {
        let id = NodeId::from_hostname("API.Example.COM").unwrap();
        assert_eq!(id.as_str(), "hostname:api.example.com");
    }

    #[test]
    fn hostname_trailing_dot_stripped() {
        let id = NodeId::from_hostname("api.example.com.").unwrap();
        assert_eq!(id.as_str(), "hostname:api.example.com");
    }

    #[test]
    fn hostname_trailing_dot_and_uppercase() {
        let id = NodeId::from_hostname("API.EXAMPLE.COM.").unwrap();
        assert_eq!(id.as_str(), "hostname:api.example.com");
    }

    #[test]
    fn hostname_punycode_converted() {
        // Unicode label should be converted to xn-- punycode form.
        let id = NodeId::from_hostname("例え.jp").unwrap();
        assert_eq!(id.as_str(), "hostname:xn--r8jz45g.jp");
    }

    #[test]
    fn hostname_already_punycode_unchanged() {
        let id = NodeId::from_hostname("xn--r8jz45g.jp").unwrap();
        assert_eq!(id.as_str(), "hostname:xn--r8jz45g.jp");
    }

    #[test]
    fn hostname_plain_ascii_unchanged() {
        let id = NodeId::from_hostname("www.example.com").unwrap();
        assert_eq!(id.as_str(), "hostname:www.example.com");
    }

    // --- IPv4 ---

    #[test]
    fn ipv4_dotted_quad() {
        let id = NodeId::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
        assert_eq!(id.as_str(), "ip:203.0.113.5");
    }

    #[test]
    fn ipv4_from_str() {
        let id = NodeId::from_ip_str("10.0.0.1").unwrap();
        assert_eq!(id.as_str(), "ip:10.0.0.1");
    }

    // --- IPv6 ---

    #[test]
    fn ipv6_compressed_lowercase() {
        // 2001:0db8:0000:0000:0000:0000:0000:0001 -> 2001:db8::1
        let v6: Ipv6Addr = "2001:0db8:0000:0000:0000:0000:0000:0001".parse().unwrap();
        let id = NodeId::from_ip(IpAddr::V6(v6));
        assert_eq!(id.as_str(), "ip:2001:db8::1");
    }

    #[test]
    fn ipv6_already_compressed_unchanged() {
        let id = NodeId::from_ip_str("2001:db8::1").unwrap();
        assert_eq!(id.as_str(), "ip:2001:db8::1");
    }

    #[test]
    fn ipv4_mapped_ipv6_normalizes_to_ipv4() {
        // ::ffff:203.0.113.5
        let v6: Ipv6Addr = "::ffff:203.0.113.5".parse().unwrap();
        let id = NodeId::from_ip(IpAddr::V6(v6));
        assert_eq!(id.as_str(), "ip:203.0.113.5");
    }

    #[test]
    fn ipv4_mapped_full_hex_normalizes_to_ipv4() {
        // ::ffff:cb00:7105 = ::ffff:203.0.113.5
        let v6: Ipv6Addr = "::ffff:cb00:7105".parse().unwrap();
        let id = NodeId::from_ip(IpAddr::V6(v6));
        assert_eq!(id.as_str(), "ip:203.0.113.5");
    }

    // --- CIDR normalization ---

    #[test]
    fn cidr_host_bits_zeroed() {
        // 10.0.0.5/8 should normalize to 10.0.0.0/8
        let id = NodeId::from_cidr_str("10.0.0.5/8").unwrap();
        assert_eq!(id.as_str(), "cidr:10.0.0.0/8");
    }

    #[test]
    fn cidr_already_normalized() {
        let id = NodeId::from_cidr_str("192.168.1.0/24").unwrap();
        assert_eq!(id.as_str(), "cidr:192.168.1.0/24");
    }

    #[test]
    fn cidr_ipv6_normalized() {
        // 2001:db8::/32 is already canonical
        let id = NodeId::from_cidr_str("2001:db8::/32").unwrap();
        assert_eq!(id.as_str(), "cidr:2001:db8::/32");
    }

    #[test]
    fn cidr_ipv6_host_bits_zeroed() {
        let id = NodeId::from_cidr_str("2001:db8::1/32").unwrap();
        assert_eq!(id.as_str(), "cidr:2001:db8::/32");
    }

    // --- Provider IDs ---

    #[test]
    fn provider_id_arn() {
        let id = NodeId::from_provider_id(
            "arn",
            "arn:aws:cloudfront::123456789012:distribution/ABCDEFGHIJ",
        );
        assert_eq!(
            id.as_str(),
            "arn:arn:aws:cloudfront::123456789012:distribution/ABCDEFGHIJ"
        );
    }

    // --- Error cases ---

    #[test]
    fn invalid_ip_returns_error() {
        assert!(NodeId::from_ip_str("not-an-ip").is_err());
    }

    #[test]
    fn invalid_cidr_returns_error() {
        assert!(NodeId::from_cidr_str("999.0.0.0/8").is_err());
    }

    // --- Round-trip serde ---

    #[test]
    fn node_id_serde_round_trip() {
        let id = NodeId::from_hostname("api.example.com").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let back: NodeId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }
}
