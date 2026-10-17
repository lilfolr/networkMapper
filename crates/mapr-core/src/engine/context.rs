//! Engine context.
//!
//! `Context` holds all injectable dependencies (clock, config). Stages receive
//! an `Arc<Context>` so the engine can be driven entirely from fakes in tests.
//! Concrete I/O clients (DNS, HTTP, TLS) will be added here in later phases.

use chrono::{DateTime, Utc};

/// A clock that the engine and stages can use to obtain the current time.
///
/// Injecting a fake clock makes all timestamps deterministic in tests.
pub trait Clock: Send + Sync {
    /// Returns the current UTC time.
    fn now(&self) -> DateTime<Utc>;
}

/// A real-time clock backed by `chrono::Utc::now()`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// A fixed-time fake clock for tests.
///
/// Always returns the timestamp it was created with.
pub struct FakeClock(pub DateTime<Utc>);

impl Clock for FakeClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

/// Shared context passed to every stage at run time.
///
/// All fields are trait objects so concrete implementations can be swapped for
/// fakes in tests. The engine constructs one `Arc<Context>` and shares it
/// across all concurrent stage executions.
pub struct Context {
    /// Clock used to timestamp evidence.
    pub clock: Box<dyn Clock>,
}

impl Context {
    /// Construct a context with the system clock.
    pub fn with_system_clock() -> Self {
        Self {
            clock: Box::new(SystemClock),
        }
    }

    /// Construct a context with a fixed fake clock. Useful in tests.
    pub fn with_fake_clock(at: DateTime<Utc>) -> Self {
        Self {
            clock: Box::new(FakeClock(at)),
        }
    }

    /// Returns the current time from the injected clock.
    pub fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }
}
