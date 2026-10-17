use thiserror::Error;

/// Core library error types.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Render error: {0}")]
    Render(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Engine error: {0}")]
    Engine(String),
}
