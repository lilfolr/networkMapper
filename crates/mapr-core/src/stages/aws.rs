//! AWS-specific discovery stages (placeholder until Phase 5+).

use std::sync::Arc;

use async_trait::async_trait;
use mapr_schema::Node;

use super::{Stage, StageOutput, Tier};
use crate::engine::context::Context;

/// Placeholder AWS stage that does nothing. Replaced in Phase 5+.
pub struct AwsStage;

#[async_trait]
impl Stage for AwsStage {
    fn name(&self) -> &'static str {
        "aws"
    }

    fn tier(&self) -> Tier {
        Tier::Credentialed
    }

    fn accepts(&self, _node: &Node) -> bool {
        false
    }

    async fn run(&self, _cx: &Arc<Context>, _node: &Node) -> StageOutput {
        StageOutput::default()
    }
}
