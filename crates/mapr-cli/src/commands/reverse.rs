use anyhow::Result;
use mapr_schema::ExitCode;

use crate::cli::GlobalArgs;

pub fn run(resource: &str, global: &GlobalArgs) -> Result<ExitCode> {
    if !global.quiet {
        eprintln!("Reverse tracing dependencies for resource: {resource} (deferred/placeholder)");
    }
    println!("Reverse trace for resource '{resource}' is deferred for v1. No incoming references discovered.");
    Ok(ExitCode::Success)
}
