pub mod aws;
pub mod dns;
pub mod fingerprint;

use crate::error::CoreError;
use mapr_schema::Trace;

/// Shared trait for trace discovery stages (placeholder until Phase 2).
pub trait Stage {
    fn name(&self) -> &'static str;
    fn execute(&self, graph: &mut Trace) -> Result<(), CoreError>;
}
