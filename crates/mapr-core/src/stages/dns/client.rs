//! DNS client trait and production/fake implementations.
//!
//! The trait is the seam between the DNS stage and the network. Tests inject a
//! `FakeDnsClient`; production code uses `HickoryDnsClient`.
//!
//! ## What we discovered about hickory-resolver 0.26.3
//!
//! - `resolver.lookup(name, RecordType::CNAME)` returns only the CNAME record
//!   for that exact name. It does NOT automatically follow the chain when you
//!   query for CNAME specifically. We therefore walk the chain ourselves,
//!   one hop at a time.
//! - `resolver.lookup_ip()` does follow CNAMEs internally, but it flattens the
//!   chain: only A/AAAA records come back. We avoid it for CNAME discovery.
//! - NXDOMAIN surfaces as a `NetError` with `is_nx_domain() == true`.
//! - NODATA (name exists, no records of this type) also surfaces as a
//!   `NetError` but with `is_no_records_found() == true` and
//!   `is_nx_domain() == false`.
//! - `NetError::Timeout` is its own variant; checked with `matches!`.
//! - `NameServerConfig::udp_and_tcp(ip: IpAddr)` is the constructor in 0.26.3;
//!   there is no `socket_addr` field.
//! - `RData::CNAME(cname)` wraps a `CNAME` newtype; `.0` gives the `Name`.
//! - `RData::A(a)` wraps an `A` newtype; `.0` gives `Ipv4Addr`.
//! - `RData::AAAA(aaaa)` wraps an `AAAA` newtype; `.0` gives `Ipv6Addr`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::Resolver;

use crate::error::CoreError;

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// A single DNS resource record extracted from an answer section.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// Owner name of this record (the name that was queried).
    pub name: String,
    /// Parsed record data.
    pub data: DnsRData,
    /// Time-to-live in seconds.
    pub ttl: u32,
}

/// Parsed record data for the types the DNS stage cares about.
#[derive(Debug, Clone)]
pub enum DnsRData {
    /// CNAME target name.
    Cname(String),
    /// A record (IPv4 address).
    A(Ipv4Addr),
    /// AAAA record (IPv6 address).
    Aaaa(Ipv6Addr),
    /// PTR record target name.
    Ptr(String),
    /// Any other record type we do not process further.
    Other,
}

/// Outcome of a single DNS lookup.
#[derive(Debug, Clone)]
pub enum DnsResponse {
    /// One or more answer records were returned.
    Records(Vec<DnsRecord>),
    /// NXDOMAIN: the queried name does not exist.
    NxDomain,
    /// NODATA: the name exists but has no records of the requested type.
    NoData,
    /// SERVFAIL or another error response code from the upstream server.
    ServerFailure(String),
    /// Transport-level or resolver-level timeout.
    Timeout,
}

/// Which record type to query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryRecordType {
    Cname,
    A,
    Aaaa,
    Ptr,
}

impl From<QueryRecordType> for RecordType {
    fn from(qt: QueryRecordType) -> Self {
        match qt {
            QueryRecordType::Cname => RecordType::CNAME,
            QueryRecordType::A => RecordType::A,
            QueryRecordType::Aaaa => RecordType::AAAA,
            QueryRecordType::Ptr => RecordType::PTR,
        }
    }
}

/// The resolver address string used in evidence attribution.
#[derive(Debug, Clone)]
pub struct ResolverAddr(pub String);

/// Result of a single DNS query: the DNS response plus the resolver that answered.
pub struct QueryResult {
    pub response: DnsResponse,
    pub resolver: ResolverAddr,
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// A DNS client that can look up a name for a given record type.
///
/// Always `Send + Sync` so it can be stored in `Context` and shared across
/// async tasks. Errors (NXDOMAIN, SERVFAIL, timeout) are encoded in
/// `DnsResponse` rather than returned as `Err`; the stage never sees a
/// transport error directly.
#[async_trait]
pub trait DnsClient: Send + Sync {
    /// Look up `name` for `record_type`.
    ///
    /// Must not panic. Network or server errors become the appropriate
    /// `DnsResponse` variant.
    async fn lookup(&self, name: &str, record_type: QueryRecordType) -> QueryResult;

    /// Human-readable address string of the resolver this client uses.
    fn resolver_addr(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Production implementation backed by hickory-resolver
// ---------------------------------------------------------------------------

/// Production DNS client backed by hickory-resolver 0.26.3.
pub struct HickoryDnsClient {
    resolver: Resolver<TokioRuntimeProvider>,
    addr: String,
}

impl HickoryDnsClient {
    /// Build a client using the host system resolver configuration
    /// (`/etc/resolv.conf` on Unix, registry on Windows).
    pub fn from_system_config() -> Result<Self, CoreError> {
        let resolver = Resolver::builder_tokio()
            .map_err(|e| CoreError::Other(format!("failed to read system DNS config: {e}")))?
            .build()
            .map_err(|e| CoreError::Other(format!("failed to build DNS resolver: {e}")))?;
        Ok(Self {
            resolver,
            addr: "system".to_owned(),
        })
    }

    /// Build a client pointing at a specific resolver IP address (UDP+TCP, port 53).
    pub fn from_addr(ip: IpAddr) -> Result<Self, CoreError> {
        let ns = NameServerConfig::udp_and_tcp(ip);
        let config = ResolverConfig::from_name_servers(vec![ns]);
        let opts = ResolverOpts::default();
        let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
            .map_err(|e| CoreError::Other(format!("failed to build DNS resolver: {e}")))?;
        Ok(Self {
            resolver,
            addr: format!("{ip}:53"),
        })
    }
}

#[async_trait]
impl DnsClient for HickoryDnsClient {
    async fn lookup(&self, name: &str, record_type: QueryRecordType) -> QueryResult {
        let resolver_addr = ResolverAddr(self.addr.clone());

        // Append a trailing dot to make the name fully-qualified. This
        // prevents the resolver from appending search domains, which would
        // give us wrong CNAME hops.
        let fqdn = if name.ends_with('.') {
            name.to_owned()
        } else {
            format!("{name}.")
        };

        let rt: RecordType = record_type.into();
        let result = self.resolver.lookup(fqdn.as_str(), rt).await;
        let response = map_hickory_result(result);
        QueryResult {
            response,
            resolver: resolver_addr,
        }
    }

    fn resolver_addr(&self) -> &str {
        &self.addr
    }
}

/// Map a hickory `Result<Lookup, NetError>` to our `DnsResponse`.
fn map_hickory_result(result: Result<hickory_resolver::lookup::Lookup, NetError>) -> DnsResponse {
    match result {
        Ok(lookup) => {
            let records: Vec<DnsRecord> = lookup
                .answers()
                .iter()
                .map(|rec: &hickory_resolver::proto::rr::Record| {
                    let ttl = rec.ttl;
                    let name = rec.name.to_string();
                    let data = match &rec.data {
                        RData::CNAME(cname) => DnsRData::Cname(cname.0.to_string()),
                        RData::A(a) => DnsRData::A(a.0),
                        RData::AAAA(aaaa) => DnsRData::Aaaa(aaaa.0),
                        RData::PTR(ptr) => DnsRData::Ptr(ptr.0.to_string()),
                        _ => DnsRData::Other,
                    };
                    DnsRecord { name, data, ttl }
                })
                .collect();

            if records.is_empty() {
                DnsResponse::NoData
            } else {
                DnsResponse::Records(records)
            }
        }
        Err(err) => {
            if err.is_nx_domain() {
                DnsResponse::NxDomain
            } else if matches!(err, NetError::Timeout) {
                DnsResponse::Timeout
            } else if err.is_no_records_found() {
                // NoError response code but no records: NODATA.
                DnsResponse::NoData
            } else {
                DnsResponse::ServerFailure(err.to_string())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Fake client for tests
// ---------------------------------------------------------------------------

/// A pre-programmed answer for one (name, record_type) query.
#[derive(Debug, Clone)]
pub struct FakeAnswer {
    /// Exact name to match (trailing dot and case are ignored).
    pub name: String,
    pub record_type: QueryRecordType,
    pub response: DnsResponse,
}

impl FakeAnswer {
    /// Convenience constructor for a CNAME answer.
    pub fn cname(from: &str, to: &str, ttl: u32) -> Self {
        Self {
            name: from.to_owned(),
            record_type: QueryRecordType::Cname,
            response: DnsResponse::Records(vec![DnsRecord {
                name: from.to_owned(),
                data: DnsRData::Cname(to.to_owned()),
                ttl,
            }]),
        }
    }

    /// Convenience constructor for an A record answer.
    pub fn a(name: &str, ip: Ipv4Addr, ttl: u32) -> Self {
        Self {
            name: name.to_owned(),
            record_type: QueryRecordType::A,
            response: DnsResponse::Records(vec![DnsRecord {
                name: name.to_owned(),
                data: DnsRData::A(ip),
                ttl,
            }]),
        }
    }

    /// Convenience constructor for an AAAA record answer.
    pub fn aaaa(name: &str, ip: Ipv6Addr, ttl: u32) -> Self {
        Self {
            name: name.to_owned(),
            record_type: QueryRecordType::Aaaa,
            response: DnsResponse::Records(vec![DnsRecord {
                name: name.to_owned(),
                data: DnsRData::Aaaa(ip),
                ttl,
            }]),
        }
    }

    /// Convenience constructor for a multi-A answer.
    pub fn multi_a(name: &str, ips: &[Ipv4Addr], ttl: u32) -> Self {
        Self {
            name: name.to_owned(),
            record_type: QueryRecordType::A,
            response: DnsResponse::Records(
                ips.iter()
                    .map(|ip| DnsRecord {
                        name: name.to_owned(),
                        data: DnsRData::A(*ip),
                        ttl,
                    })
                    .collect(),
            ),
        }
    }

    /// Convenience constructor for NXDOMAIN.
    pub fn nxdomain(name: &str, record_type: QueryRecordType) -> Self {
        Self {
            name: name.to_owned(),
            record_type,
            response: DnsResponse::NxDomain,
        }
    }

    /// Convenience constructor for SERVFAIL.
    pub fn servfail(name: &str, record_type: QueryRecordType) -> Self {
        Self {
            name: name.to_owned(),
            record_type,
            response: DnsResponse::ServerFailure("SERVFAIL".to_owned()),
        }
    }

    /// Convenience constructor for a timeout.
    pub fn timeout(name: &str, record_type: QueryRecordType) -> Self {
        Self {
            name: name.to_owned(),
            record_type,
            response: DnsResponse::Timeout,
        }
    }
}

/// A deterministic fake DNS client driven by a list of pre-programmed answers.
///
/// If no entry matches a query, returns `DnsResponse::NoData`.
pub struct FakeDnsClient {
    answers: Vec<FakeAnswer>,
    addr: String,
}

impl FakeDnsClient {
    /// Create a fake with no answers (every query returns NoData).
    pub fn empty() -> Self {
        Self {
            answers: Vec::new(),
            addr: "fake:53".to_owned(),
        }
    }

    /// Create a fake from a list of pre-programmed answers.
    pub fn new(answers: Vec<FakeAnswer>) -> Self {
        Self {
            answers,
            addr: "fake:53".to_owned(),
        }
    }
}

#[async_trait]
impl DnsClient for FakeDnsClient {
    async fn lookup(&self, name: &str, record_type: QueryRecordType) -> QueryResult {
        // Normalize for matching: strip trailing dot, lowercase.
        let clean = name.trim_end_matches('.').to_lowercase();
        let response = self
            .answers
            .iter()
            .find(|a| {
                a.record_type == record_type && a.name.trim_end_matches('.').to_lowercase() == clean
            })
            .map(|a| a.response.clone())
            .unwrap_or(DnsResponse::NoData);

        QueryResult {
            response,
            resolver: ResolverAddr(self.addr.clone()),
        }
    }

    fn resolver_addr(&self) -> &str {
        &self.addr
    }
}
