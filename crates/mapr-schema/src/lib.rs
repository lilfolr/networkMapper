#![forbid(unsafe_code)]

pub mod exit_code;
pub mod types;

pub use exit_code::ExitCode;
pub use types::*;

/// Current mapr trace schema version.
pub const SCHEMA_VERSION: &str = "1.0.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_codes() {
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::Error.as_i32(), 1);
        assert_eq!(ExitCode::PartialTrace.as_i32(), 2);
        assert_eq!(ExitCode::DiffChanges.as_i32(), 3);
        assert_eq!(ExitCode::ProbeHopFailure.as_i32(), 4);
    }
}
