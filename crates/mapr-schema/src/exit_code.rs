use std::process::Termination;

/// Process exit codes for mapr CLI invocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ExitCode {
    /// 0: Complete trace or successful operation.
    Success = 0,
    /// 1: General error.
    Error = 1,
    /// 2: Partial trace (gaps present in graph).
    PartialTrace = 2,
    /// 3: Diff found changes (when run with --exit-code).
    DiffChanges = 3,
    /// 4: Probe reached target but a hop reported failure.
    ProbeHopFailure = 4,
}

impl ExitCode {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(code: ExitCode) -> Self {
        Self::from(code.as_i32() as u8)
    }
}

impl Termination for ExitCode {
    fn report(self) -> std::process::ExitCode {
        self.into()
    }
}
