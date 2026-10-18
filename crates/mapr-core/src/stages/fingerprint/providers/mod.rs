//! Provider parsers for IP range files.
//!
//! Each provider lives in its own module and implements `RangeSource`.
//! Adding a new provider means adding a module here without touching any
//! other provider's code.

pub mod aws;
pub mod cloudflare;
