//! End-to-end engine test for the DNS stage using a fake resolver.
//!
//! Runs the engine from a hostname seed through the DNS stage with a
//! pre-programmed fake client and snapshots the resulting trace with insta.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use chrono::{TimeZone, Utc};
use mapr_core::engine::context::Context;
use mapr_core::engine::{Engine, EngineConfig};
use mapr_core::stages::dns::client::{FakeAnswer, FakeDnsClient};
use mapr_core::stages::dns::DnsStage;
use mapr_core::stages::Tier;

fn fixed_context() -> Arc<Context> {
    // Pin the clock so snapshot timestamps are stable.
    let t = Utc.with_ymd_and_hms(2025, 1, 2, 3, 4, 5).unwrap();
    Arc::new(Context::with_fake_clock(t))
}

fn engine_with_dns(answers: Vec<FakeAnswer>) -> Engine {
    let client = Arc::new(FakeDnsClient::new(answers));
    let stage = Arc::new(DnsStage::new(client));
    Engine::new(vec![stage], fixed_context())
}

/// Simple linear chain: api.example.com CNAME backend.example.com A 203.0.113.1
#[tokio::test]
async fn snapshot_cname_to_single_a() {
    let answers = vec![
        FakeAnswer::cname("api.example.com", "backend.example.com", 300),
        FakeAnswer::a("backend.example.com", Ipv4Addr::new(203, 0, 113, 1), 60),
    ];
    let engine = engine_with_dns(answers);
    let config = EngineConfig {
        max_tier: Tier::Network,
        ..EngineConfig::default()
    };

    let (trace, _) = engine
        .run("api.example.com", &config)
        .await
        .expect("engine must not error");

    // Normalize away timestamps before snapshotting.
    let mut value = serde_json::to_value(&trace).expect("serializable");
    zero_timestamps(&mut value);

    insta::assert_json_snapshot!("cname_to_single_a", value);
}

/// No CNAME; dual-stack A + AAAA.
#[tokio::test]
async fn snapshot_dual_stack_direct() {
    let answers = vec![
        FakeAnswer::a("dual.example.com", Ipv4Addr::new(203, 0, 113, 5), 60),
        FakeAnswer::aaaa(
            "dual.example.com",
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            60,
        ),
    ];
    let engine = engine_with_dns(answers);
    let config = EngineConfig {
        max_tier: Tier::Network,
        ..EngineConfig::default()
    };

    let (trace, _) = engine
        .run("dual.example.com", &config)
        .await
        .expect("engine must not error");

    let mut value = serde_json::to_value(&trace).expect("serializable");
    zero_timestamps(&mut value);

    insta::assert_json_snapshot!("dual_stack_direct", value);
}

/// Dangling CNAME: chain ends in NXDOMAIN. The chain is kept, gap emitted.
#[tokio::test]
async fn snapshot_dangling_cname() {
    use mapr_core::stages::dns::client::QueryRecordType;

    let answers = vec![
        FakeAnswer::cname("api.example.com", "dangling.example.com", 300),
        FakeAnswer::nxdomain("dangling.example.com", QueryRecordType::Cname),
    ];
    let engine = engine_with_dns(answers);
    let config = EngineConfig {
        max_tier: Tier::Network,
        ..EngineConfig::default()
    };

    let (trace, _) = engine
        .run("api.example.com", &config)
        .await
        .expect("engine must not error");

    let mut value = serde_json::to_value(&trace).expect("serializable");
    zero_timestamps(&mut value);

    insta::assert_json_snapshot!("dangling_cname", value);
}

// ---------------------------------------------------------------------------
// Helper: replace all timestamp strings with a stable placeholder so that
// insta snapshots do not change on every run.
// ---------------------------------------------------------------------------
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
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                zero_timestamps(v);
            }
        }
        _ => {}
    }
}
