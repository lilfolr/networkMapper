use std::sync::Arc;

use anyhow::Result;
use mapr_core::engine::context::Context;
use mapr_core::render::{render_trace, OutputFormat};
use mapr_core::stages::aws::AwsStage;
use mapr_core::stages::dns::DnsStage;
use mapr_core::stages::fingerprint::FingerprintStage;
use mapr_core::stages::Stage;
use mapr_core::{Engine, EngineConfig};
use mapr_schema::ExitCode;

use crate::cli::{CliOutputFormat, GlobalArgs};

pub fn run(target: &str, global: &GlobalArgs) -> Result<ExitCode> {
    if !global.quiet {
        eprintln!("Tracing request flow for target: {target}");
    }

    // Parse an optional timeout string (e.g. "10s", "2m") into seconds.
    // For now accept plain integer seconds only; duration parsing is Phase 6.
    let timeout_seconds = global
        .timeout
        .as_deref()
        .and_then(|t| t.parse::<u64>().ok())
        .unwrap_or(mapr_core::engine::DEFAULT_TIMEOUT_SECONDS);

    let config = EngineConfig {
        offline: global.offline,
        no_prompt: global.no_prompt,
        timeout_seconds,
        ..EngineConfig::default()
    };

    let stages: Vec<Arc<dyn Stage>> = vec![
        Arc::new(DnsStage),
        Arc::new(FingerprintStage),
        Arc::new(AwsStage),
    ];
    let context = Arc::new(Context::with_system_clock());
    let engine = Engine::new(stages, context);

    // The engine is async; run it on a single-threaded tokio runtime here.
    // The CLI entry point is synchronous so we create a runtime inline.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build async runtime: {e}"))?;

    let (trace, exit_code) = rt
        .block_on(engine.run(target, &config))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

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
        std::fs::write(save_path, &rendered)?;
        if !global.quiet {
            eprintln!("Saved trace output to: {}", save_path.display());
        }
    }

    Ok(exit_code)
}
