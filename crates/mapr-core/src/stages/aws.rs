use super::Stage;
use crate::error::CoreError;
use mapr_schema::Trace;

pub struct AwsStage;

impl Stage for AwsStage {
    fn name(&self) -> &'static str {
        "aws"
    }

    fn execute(&self, _graph: &mut Trace) -> Result<(), CoreError> {
        Ok(())
    }
}
