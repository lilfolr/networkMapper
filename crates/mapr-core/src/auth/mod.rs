use serde::{Deserialize, Serialize};

/// Provider auth status summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderStatus {
    pub provider: String,
    pub profile: Option<String>,
    pub reachable: bool,
    pub details: String,
}

/// Profile detection and permission checks stub.
pub fn check_provider_status() -> Vec<ProviderStatus> {
    vec![ProviderStatus {
        provider: "aws".to_string(),
        profile: None,
        reachable: false,
        details: "No active AWS credentials found in environment or default chain (placeholder)"
            .to_string(),
    }]
}
