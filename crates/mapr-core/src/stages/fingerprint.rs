use super::Stage;
use crate::error::CoreError;
use mapr_schema::TraceGraph;

pub struct FingerprintStage;

impl Stage for FingerprintStage {
    fn name(&self) -> &'static str {
        "fingerprint"
    }

    fn execute(&self, _graph: &mut TraceGraph) -> Result<(), CoreError> {
        Ok(())
    }
}
