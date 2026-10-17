use super::Stage;
use crate::error::CoreError;
use mapr_schema::Trace;

pub struct DnsStage;

impl Stage for DnsStage {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn execute(&self, _graph: &mut Trace) -> Result<(), CoreError> {
        Ok(())
    }
}
