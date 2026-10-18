//! In-memory IP range database with longest-prefix match.
//!
//! `RangeDatabase` holds a flat list of `RangeEntry` records. Lookups scan
//! all entries and return every match, then the caller selects the most
//! specific (longest prefix) entry for node classification while keeping all
//! matches in the evidence.
//!
//! We use a flat scan rather than a trie because the total number of AWS +
//! Cloudflare prefixes is in the low thousands and lookup only happens once
//! per IP node. A trie would be premature optimisation here; it can be added
//! later without changing the public API.

use std::net::IpAddr;

use ipnet::IpNet;
use mapr_schema::Provider;

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

/// A single classified IP prefix.
#[derive(Debug, Clone)]
pub struct RangeEntry {
    /// The network prefix.
    pub prefix: IpNet,
    /// Cloud/network provider.
    pub provider: Provider,
    /// Provider-specific service name (e.g. "CLOUDFRONT", "EC2", "AMAZON").
    pub service: String,
    /// Provider region, if known (e.g. "us-east-1").
    pub region: Option<String>,
    /// True for anycast / shared-edge services (CloudFront, Global Accelerator,
    /// Cloudflare). An IP in one of these ranges does not identify an origin.
    pub shared_edge: bool,
    /// Opaque sync token or publish date from the source (for evidence).
    pub sync_token: Option<String>,
}

impl RangeEntry {
    /// Returns the prefix length (used for longest-prefix selection).
    pub fn prefix_len(&self) -> u8 {
        self.prefix.prefix_len()
    }
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

/// An in-memory collection of IP range entries supporting longest-prefix
/// match lookups.
#[derive(Debug, Default, Clone)]
pub struct RangeDatabase {
    entries: Vec<RangeEntry>,
}

impl RangeDatabase {
    /// Create an empty database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add all entries from `other` into this database.
    pub fn extend(&mut self, entries: impl IntoIterator<Item = RangeEntry>) {
        self.entries.extend(entries);
    }

    /// Return all entries whose prefix contains `ip`.
    ///
    /// An empty `Vec` means the IP is not in any known range.
    pub fn matches(&self, ip: IpAddr) -> Vec<&RangeEntry> {
        self.entries
            .iter()
            .filter(|e| e.prefix.contains(&ip))
            .collect()
    }

    /// Return the single best match for `ip` using longest-prefix selection,
    /// or `None` if the IP is not in any range.
    ///
    /// When multiple entries share the same prefix length the one encountered
    /// first wins (stable, deterministic for a given load order).
    pub fn best_match(&self, ip: IpAddr) -> Option<&RangeEntry> {
        self.matches(ip).into_iter().max_by_key(|e| e.prefix_len())
    }

    /// Number of entries in the database.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true when no entries have been loaded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// RangeSource trait
// ---------------------------------------------------------------------------

/// A provider of IP range data.
///
/// Each cloud provider implements this trait. The loader calls `parse` with
/// the raw bytes fetched from the provider's URL (or read from cache) and
/// receives a list of `RangeEntry` values.
pub trait RangeSource {
    /// Human-readable name for log messages and evidence.
    fn name(&self) -> &'static str;

    /// URL to fetch the range file from in the `Network` tier.
    fn url(&self) -> &'static str;

    /// Parse raw bytes from the range file into entries.
    ///
    /// Returns an error string on malformed input. Must not make network
    /// calls; only parse the bytes given.
    fn parse(&self, data: &[u8]) -> Result<Vec<RangeEntry>, String>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn entry(cidr: &str, service: &str, shared: bool) -> RangeEntry {
        RangeEntry {
            prefix: cidr.parse().unwrap(),
            provider: Provider::Aws,
            service: service.to_owned(),
            region: Some("us-east-1".to_owned()),
            shared_edge: shared,
            sync_token: None,
        }
    }

    #[test]
    fn no_match_returns_empty() {
        let mut db = RangeDatabase::new();
        db.extend([entry("10.0.0.0/8", "AMAZON", false)]);
        // 192.0.2.1 is not in 10/8
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        assert!(db.matches(ip).is_empty());
        assert!(db.best_match(ip).is_none());
    }

    #[test]
    fn single_match() {
        let mut db = RangeDatabase::new();
        db.extend([entry("13.32.0.0/15", "CLOUDFRONT", true)]);
        let ip: IpAddr = Ipv4Addr::new(13, 32, 0, 1).into();
        assert_eq!(db.matches(ip).len(), 1);
        assert_eq!(db.best_match(ip).unwrap().service, "CLOUDFRONT");
    }

    #[test]
    fn longest_prefix_wins() {
        let mut db = RangeDatabase::new();
        // /15 covers 13.32.0.0 - 13.33.255.255
        db.extend([entry("13.32.0.0/15", "AMAZON", false)]);
        // /24 is more specific and also covers 13.32.0.1
        db.extend([entry("13.32.0.0/24", "CLOUDFRONT", true)]);

        let ip: IpAddr = Ipv4Addr::new(13, 32, 0, 1).into();
        let best = db.best_match(ip).unwrap();
        assert_eq!(best.service, "CLOUDFRONT");
        assert_eq!(best.prefix_len(), 24);
    }

    #[test]
    fn all_overlapping_matches_returned() {
        let mut db = RangeDatabase::new();
        db.extend([
            entry("13.32.0.0/15", "AMAZON", false),
            entry("13.32.0.0/15", "CLOUDFRONT", true),
        ]);
        let ip: IpAddr = Ipv4Addr::new(13, 32, 0, 1).into();
        assert_eq!(db.matches(ip).len(), 2);
    }

    #[test]
    fn ipv6_match() {
        let mut db = RangeDatabase::new();
        db.extend([RangeEntry {
            prefix: "2600:1f00::/25".parse().unwrap(),
            provider: Provider::Aws,
            service: "EC2".to_owned(),
            region: Some("us-east-1".to_owned()),
            shared_edge: false,
            sync_token: None,
        }]);
        let ip: IpAddr = "2600:1f00::1".parse().unwrap();
        assert!(db.best_match(ip).is_some());
    }

    #[test]
    fn ip_outside_range_boundary() {
        let mut db = RangeDatabase::new();
        // 13.32.0.0/15 ends at 13.33.255.255
        db.extend([entry("13.32.0.0/15", "AMAZON", false)]);
        let ip_inside: IpAddr = Ipv4Addr::new(13, 33, 255, 255).into();
        let ip_outside: IpAddr = Ipv4Addr::new(13, 34, 0, 0).into();
        assert!(db.best_match(ip_inside).is_some());
        assert!(db.best_match(ip_outside).is_none());
    }
}
