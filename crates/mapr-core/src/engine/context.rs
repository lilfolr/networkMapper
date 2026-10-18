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

/// Shared context passed to every stage at run time.
pub struct Context {
    /// Clock used to timestamp evidence.
    pub clock: Box<dyn Clock>,
    /// Pre-loaded IP range database. `None` when range data is unavailable
    /// (e.g. `--offline` with no cache). Stages that need it check for `None`
    /// and emit a `NoRangeData` gap.
    pub range_db: Option<Arc<RangeDatabase>>,
}

impl Context {
    /// Construct a context with the system clock and no range database.
    pub fn with_system_clock() -> Self {
        Self {
            clock: Box::new(SystemClock),
            range_db: None,
        }
    }

    /// Construct a context with a fixed fake clock. Useful in tests.
    pub fn with_fake_clock(at: DateTime<Utc>) -> Self {
        Self {
            clock: Box::new(FakeClock(at)),
            range_db: None,
        }
    }

    /// Attach a range database to the context.
    pub fn with_range_db(mut self, db: Arc<RangeDatabase>) -> Self {
        self.range_db = Some(db);
        self
    }

    /// Returns the current time from the injected clock.
    pub fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }
}
