use std::sync::Arc;

use anyhow::Result;
use mapr_core::engine::context::Context;
use mapr_core::render::{render_trace, OutputFormat};
use mapr_core::stages::aws::AwsStage;
use mapr_core::stages::classify::ClassifyStage;
use mapr_core::stages::dns::client::HickoryDnsClient;
use mapr_core::stages::dns::DnsStage;
use mapr_core::stages::fingerprint::loader::{load, LoadConfig, LoadResult};
use mapr_core::stages::fingerprint::providers::aws::AwsRangeSource;
use mapr_core::stages::fingerprint::providers::cloudflare::{
    CloudflareV4Source, CloudflareV6Source,
};
use mapr_core::stages::fingerprint::range_db::{RangeDatabase, RangeSource};
use mapr_core::stages::fingerprint::IpRangeStage;
use mapr_core::stages::Stage;
use mapr_core::{Engine, EngineConfig};
use mapr_schema::ExitCode;

use crate::cli::{CliOutputFormat, GlobalArgs};

pub fn run(target: &str, global: &GlobalArgs) -> Result<ExitCode> {
    if !global.quiet {
        eprintln!("Tracing request flow for target: {target}");
    }

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

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build async runtime: {e}"))?;

    // Load range databases (best-effort; missing data becomes a gap at run time).
    let range_db = rt.block_on(build_range_db(global.offline))?;

    let dns_client = Arc::new(
        HickoryDnsClient::from_system_config()
            .map_err(|e| anyhow::anyhow!("failed to initialise DNS client: {e}"))?,
    );

    let stages: Vec<Arc<dyn Stage>> = vec![
        Arc::new(DnsStage::new(dns_client)),
        Arc::new(ClassifyStage),
        Arc::new(IpRangeStage::new(Arc::clone(&range_db))),
        Arc::new(AwsStage),
    ];

    let context = Arc::new(Context::with_system_clock().with_range_db(range_db));
    let engine = Engine::new(stages, context);

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

/// Load all provider range databases, returning a shared `RangeDatabase`.
///
/// Missing or failed sources produce warnings on stderr but do not abort;
/// the stage will emit `NoRangeData` gaps for IPs it cannot classify.
async fn build_range_db(offline: bool) -> Result<Arc<RangeDatabase>> {
    let load_cfg = LoadConfig {
        offline,
        ..LoadConfig::default()
    };

    let mut db = RangeDatabase::new();

    async fn load_source(source: &dyn RangeSource, cfg: &LoadConfig, db: &mut RangeDatabase) {
        match load(source, cfg).await {
            LoadResult::Data { bytes, .. } => match source.parse(&bytes) {
                Ok(entries) => db.extend(entries),
                Err(e) => eprintln!("warning: failed to parse {} ranges: {e}", source.name()),
            },
            LoadResult::NoData => {
                eprintln!(
                    "warning: no range data for {} (offline or fetch failed)",
                    source.name()
                );
            }
        }
    }

    load_source(&AwsRangeSource, &load_cfg, &mut db).await;
    load_source(&CloudflareV4Source, &load_cfg, &mut db).await;
    load_source(&CloudflareV6Source, &load_cfg, &mut db).await;

    Ok(Arc::new(db))
}
