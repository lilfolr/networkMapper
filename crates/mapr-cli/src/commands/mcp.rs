use anyhow::Result;
use mapr_schema::ExitCode;

use crate::cli::GlobalArgs;

pub fn run(global: &GlobalArgs) -> Result<ExitCode> {
    if !global.quiet {
        eprintln!("Starting mapr MCP server (deferred/placeholder)");
    }
    println!("MCP server mode is deferred for v1. No active listeners started.");
    Ok(ExitCode::Success)
}
