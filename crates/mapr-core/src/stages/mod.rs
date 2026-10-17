pub mod aws;
pub mod dns;
pub mod fingerprint;

use crate::error::CoreError;
use mapr_schema::TraceGraph;

/// Shared trait for trace discovery stages.
pub trait Stage {
    fn name(&self) -> &'static str;
    fn execute(&self, graph: &mut TraceGraph) -> Result<(), CoreError>;
}
