//! DNS discovery stage (placeholder until Phase 4).

use std::sync::Arc;

use async_trait::async_trait;
use mapr_schema::Node;

use super::{Stage, StageOutput, Tier};
use crate::engine::context::Context;

/// Placeholder DNS stage that does nothing. Replaced in Phase 4.
pub struct DnsStage;

#[async_trait]
impl Stage for DnsStage {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn tier(&self) -> Tier {
        Tier::Network
    }

    fn accepts(&self, _node: &Node) -> bool {
        false
    }

    async fn run(&self, _cx: &Arc<Context>, _node: &Node) -> StageOutput {
        StageOutput::default()
    }
}
