//! Engine context.
//!
//! `Context` holds all injectable dependencies (clock, range database).
//! Stages receive an `Arc<Context>` so the engine can be driven entirely from
//! fakes in tests.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::stages::fingerprint::range_db::RangeDatabase;

/// A clock that the engine and stages can use to obtain the current time.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

/// Real-time clock backed by `chrono::Utc::now()`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Fixed-time fake clock for tests.
pub struct FakeClock(pub DateTime<Utc>);

impl Clock for FakeClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

use crate::stages::dns::client::{DnsClient, HickoryDnsClient};

/// Shared context passed to every stage at run time.
pub struct Context {
    /// Clock used to timestamp evidence.
    pub clock: Box<dyn Clock>,
    /// Pre-loaded IP range database. `None` when range data is unavailable
    /// (e.g. `--offline` with no cache). Stages that need it check for `None`
    /// and emit a `NoRangeData` gap.
    pub range_db: Option<Arc<RangeDatabase>>,
    /// DNS client used for DNS lookups in stages.
    pub dns_client: Arc<dyn DnsClient>,
}

impl Context {
    /// Construct a context with the system clock and no range database.
    pub fn with_system_clock() -> Self {
        let dns_client = Arc::new(
            HickoryDnsClient::from_system_config()
                .unwrap_or_else(|_| panic!("failed to initialize default system DNS client")),
        );
        Self {
            clock: Box::new(SystemClock),
            range_db: None,
            dns_client,
        }
    }

    /// Construct a context with a fixed fake clock. Useful in tests.
    pub fn with_fake_clock(at: DateTime<Utc>) -> Self {
        let dns_client = Arc::new(
            HickoryDnsClient::from_system_config()
                .unwrap_or_else(|_| panic!("failed to initialize default system DNS client")),
        );
        Self {
            clock: Box::new(FakeClock(at)),
            range_db: None,
            dns_client,
        }
    }

    /// Attach a range database to the context.
    pub fn with_range_db(mut self, db: Arc<RangeDatabase>) -> Self {
        self.range_db = Some(db);
        self
    }

    /// Attach a custom DNS client to the context.
    pub fn with_dns_client(mut self, dns_client: impl DnsClient + 'static) -> Self {
        self.dns_client = Arc::new(dns_client);
        self
    }

    /// Attach a shared Arc<dyn DnsClient> to the context.
    pub fn with_arc_dns_client(mut self, dns_client: Arc<dyn DnsClient>) -> Self {
        self.dns_client = dns_client;
        self
    }

    /// Returns the current time from the injected clock.
    pub fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }
}
