//! IP range / fingerprint discovery stage (placeholder until Phase 5).

use std::sync::Arc;

use async_trait::async_trait;
use mapr_schema::Node;

use super::{Stage, StageOutput, Tier};
use crate::engine::context::Context;

/// Placeholder fingerprint stage that does nothing. Replaced in Phase 5.
pub struct FingerprintStage;

#[async_trait]
impl Stage for FingerprintStage {
    fn name(&self) -> &'static str {
        "fingerprint"
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
