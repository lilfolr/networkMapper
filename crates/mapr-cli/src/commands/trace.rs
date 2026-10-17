use anyhow::Result;
use mapr_core::engine::{execute_trace, EngineConfig};
use mapr_core::render::{render_trace, OutputFormat};
use mapr_schema::ExitCode;

use crate::cli::{CliOutputFormat, GlobalArgs};

pub fn run(target: &str, global: &GlobalArgs) -> Result<ExitCode> {
    if !global.quiet {
        eprintln!("Tracing request flow for target: {target} (placeholder)");
    }

    let config = EngineConfig {
        offline: global.offline,
        no_prompt: global.no_prompt,
        timeout_seconds: None,
    };

    let (graph, exit_code) = execute_trace(target, &config)?;

    let format = match global.output {
        Some(CliOutputFormat::Json) => OutputFormat::Json,
        Some(CliOutputFormat::Text) => OutputFormat::Text,
        Some(CliOutputFormat::Mermaid) => OutputFormat::Mermaid,
        Some(CliOutputFormat::Dot) => OutputFormat::Dot,
        Some(CliOutputFormat::Html) => OutputFormat::Html,
        None => OutputFormat::Text,
    };

    let rendered = render_trace(&graph, format).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{rendered}");

    if let Some(save_path) = &global.save {
        std::fs::write(save_path, &rendered)?;
        if !global.quiet {
            eprintln!("Saved trace output to: {}", save_path.display());
        }
    }

    Ok(exit_code)
}
