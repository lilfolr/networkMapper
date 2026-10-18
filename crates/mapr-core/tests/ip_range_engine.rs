//! End-to-end engine snapshot tests for the IP range stage.
//!
//! Loads the sanitized fixtures, builds a RangeDatabase, then runs the engine
//! from a hostname seed through DNS + classify + ip_range stages and snapshots
//! the resulting trace with insta.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::Ipv4Addr;
use std::sync::Arc;

use chrono::{TimeZone, Utc};
use mapr_core::engine::context::Context;
use mapr_core::engine::{Engine, EngineConfig};
use mapr_core::stages::classify::ClassifyStage;
use mapr_core::stages::dns::client::{FakeAnswer, FakeDnsClient};
use mapr_core::stages::dns::DnsStage;
use mapr_core::stages::fingerprint::providers::aws::AwsRangeSource;
use mapr_core::stages::fingerprint::providers::cloudflare::CloudflareV4Source;
use mapr_core::stages::fingerprint::range_db::{RangeDatabase, RangeSource};
use mapr_core::stages::fingerprint::IpRangeStage;
use mapr_core::stages::Tier;

fn fixed_context(db: Arc<RangeDatabase>) -> Arc<Context> {
    let t = Utc.with_ymd_and_hms(2025, 1, 2, 3, 4, 5).unwrap();
    Arc::new(Context::with_fake_clock(t).with_range_db(db))
}

fn load_fixture_db() -> Arc<RangeDatabase> {
    let mut db = RangeDatabase::new();

    let aws_data = include_bytes!("../../../tests/fixtures/ip-ranges-aws.json");
    db.extend(AwsRangeSource.parse(aws_data).unwrap());

    let cf_data = include_bytes!("../../../tests/fixtures/ip-ranges-cloudflare-v4.txt");
    db.extend(CloudflareV4Source.parse(cf_data).unwrap());

    Arc::new(db)
}

fn engine_with_stages(answers: Vec<FakeAnswer>, db: Arc<RangeDatabase>) -> Engine {
    let client = Arc::new(FakeDnsClient::new(answers));
    let stages: Vec<Arc<dyn mapr_core::stages::Stage>> = vec![
        Arc::new(DnsStage::new(client)),
        Arc::new(ClassifyStage),
        Arc::new(IpRangeStage::new(Arc::clone(&db))),
    ];
    Engine::new(stages, fixed_context(db))
}

fn zero_timestamps(val: &mut serde_json::Value) {
    match val {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if k == "observed_at" || k == "generated_at" {
                    *v = serde_json::Value::String("1970-01-01T00:00:00Z".to_owned());
                } else {
                    zero_timestamps(v);
                }
            }
        }
        serde_json::Value::Array(arr) => arr.iter_mut().for_each(zero_timestamps),
        _ => {}
    }
}

/// Hostname resolves to an AWS CloudFront IP (13.32.0.1 is in 13.32.0.0/15).
#[tokio::test]
async fn snapshot_hostname_resolves_to_cloudfront_ip() {
    let db = load_fixture_db();
    let answers = vec![FakeAnswer::a(
        "cdn.example.com",
        Ipv4Addr::new(13, 32, 0, 1),
        60,
    )];
    let engine = engine_with_stages(answers, db);
    let config = EngineConfig {
        max_tier: Tier::Network,
        ..EngineConfig::default()
    };

    let (trace, _) = engine.run("cdn.example.com", &config).await.unwrap();

    let mut value = serde_json::to_value(&trace).unwrap();
    zero_timestamps(&mut value);
    insta::assert_json_snapshot!("hostname_resolves_to_cloudfront", value);
}

/// Hostname resolves to a Cloudflare IP (104.16.0.1 is in 104.16.0.0/13).
#[tokio::test]
async fn snapshot_hostname_resolves_to_cloudflare_ip() {
    let db = load_fixture_db();
    let answers = vec![FakeAnswer::a(
        "site.example.com",
        Ipv4Addr::new(104, 16, 0, 1),
        60,
    )];
    let engine = engine_with_stages(answers, db);
    let config = EngineConfig {
        max_tier: Tier::Network,
        ..EngineConfig::default()
    };

    let (trace, _) = engine.run("site.example.com", &config).await.unwrap();

    let mut value = serde_json::to_value(&trace).unwrap();
    zero_timestamps(&mut value);
    insta::assert_json_snapshot!("hostname_resolves_to_cloudflare", value);
}

/// IP not in any known range produces no classified node and no gap.
#[tokio::test]
async fn snapshot_ip_not_in_any_range() {
    let db = load_fixture_db();
    // 192.0.2.1 is RFC 5737 documentation space, not in the fixture ranges.
    // Note: the classify stage will emit a Private gap for this address.
    let answers = vec![FakeAnswer::a(
        "doc.example.com",
        Ipv4Addr::new(192, 0, 2, 1),
        60,
    )];
    let engine = engine_with_stages(answers, db);
    let config = EngineConfig {
        max_tier: Tier::Network,
        ..EngineConfig::default()
    };

    let (trace, _) = engine.run("doc.example.com", &config).await.unwrap();

    let mut value = serde_json::to_value(&trace).unwrap();
    zero_timestamps(&mut value);
    insta::assert_json_snapshot!("ip_not_in_any_range", value);
}
