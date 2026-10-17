use anyhow::{Context, Result};
use mapr_core::render::{render_trace, OutputFormat};
use mapr_schema::{ExitCode, TraceGraph};
use std::fs;
use std::path::Path;

use crate::cli::{CliOutputFormat, GlobalArgs};

pub fn run(file: &Path, global: &GlobalArgs) -> Result<ExitCode> {
    if !global.quiet {
        eprintln!("Rendering trace from file: {}", file.display());
    }

    let contents = fs::read_to_string(file)
        .with_context(|| format!("Failed to read trace file: {}", file.display()))?;

    let trace: TraceGraph = serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse trace JSON from: {}", file.display()))?;

    let format = match global.output {
        Some(CliOutputFormat::Json) => OutputFormat::Json,
        Some(CliOutputFormat::Text) => OutputFormat::Text,
        Some(CliOutputFormat::Mermaid) => OutputFormat::Mermaid,
        Some(CliOutputFormat::Dot) => OutputFormat::Dot,
        Some(CliOutputFormat::Html) => OutputFormat::Html,
        None => OutputFormat::Text,
    };

    let rendered = render_trace(&trace, format).map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{rendered}");

    if let Some(save_path) = &global.save {
        fs::write(save_path, &rendered)?;
        if !global.quiet {
            eprintln!("Saved rendered output to: {}", save_path.display());
        }
    }

    Ok(ExitCode::Success)
}
