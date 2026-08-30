//! Build a resolver entirely in code: cache sizing, engine tuning, client
//! rate limits and a blocklist. No JSON involved.
//!
//! This shows the configuration surface of the crate and how a strict
//! deployment (fewer upstream attempts, lower rate limits, blocked names)
//! is expressed programmatically.
//!
//! Run: `cargo run --no-default-features --features std --example custom_config`

use std::time::Duration;

use recurse_x::policy::{BlockRule, PolicyConfig};
use recurse_x::qtype::RrType;
use recurse_x::{Name, Question, Resolver, ResolverConfig, RrClass};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Engine: tuned for a small, strict resolver ------------------------
    let engine = recurse_x::resolver::EngineConfig {
        timeout_ms: 800,
        max_attempts_per_server: 1,
        max_servers_tried: 3,
        max_total_attempts: 6,
        use_0x20: true,
        qname_minimization: true,
        ..recurse_x::resolver::EngineConfig::default()
    };

    // --- Cache: small footprint, short stale window ------------------------
    let cache = recurse_x::cache::CacheConfig {
        hot_capacity: 512,
        warm_capacity: 16_384,
        cold_capacity: 4_096,
        stale_window_secs: 60,
        ..recurse_x::cache::CacheConfig::default()
    };

    // --- Policy: block two names, refuse non-QUERY opcodes -----------------
    let policy = PolicyConfig {
        block: vec![
            BlockRule::subtree(Name::from_ascii("ads.example")?),
            BlockRule::exact(Name::from_ascii("tracker.invalid")?),
        ],
        ..PolicyConfig::default()
    };

    let cfg = ResolverConfig {
        engine,
        cache,
        policy,
        maintenance_interval_ms: 2000,
        stale_serve_ttl: 5,
        rate_limit: recurse_x::resolver::RateLimitConfig {
            client_capacity: 20.0,
            client_refill_per_sec: 10.0,
            ..recurse_x::resolver::RateLimitConfig::default()
        },
        ..ResolverConfig::default()
    };

    let resolver = Resolver::new(cfg);
    let _maintenance = resolver.spawn_maintenance();

    // A blocked name must be refused before any network I/O happens.
    let blocked = Name::from_ascii("sub.ads.example")?;
    let started = std::time::Instant::now();
    match resolver.resolve(&blocked, RrType::A) {
        Ok(res) => println!(
            "blocked query -> rcode={:?} (should be REFUSED/FORMERR) [{}ms]",
            res.rcode,
            started.elapsed().as_millis()
        ),
        Err(e) => println!("blocked query -> error {e:?} (expected)"),
    }

    // A normal query still works.
    let ok = Name::from_ascii("example.com")?;
    match resolver.resolve(&ok, RrType::A) {
        Ok(res) => println!(
            "example.com A -> answers={} ttl={} [{}ms]",
            res.answers.len(),
            res.ttl,
            started.elapsed().as_millis()
        ),
        Err(e) => println!("example.com A -> error {e:?}"),
    }

    // Direct wire-level check: send a multi-question query; policy refuses it.
    let mut m = recurse_x::Message::query(1, ok.clone(), RrType::A, true);
    m.questions.push(Question {
        qname: ok,
        qtype: RrType::AAAA,
        qclass: RrClass::IN,
    });
    let resp = resolver.handle_query(&m, Some("192.0.2.1".parse()?));
    println!(
        "multi-question query -> rcode={:?} (policy enforces a single question)",
        resp.rcode()
    );

    // Let the maintenance thread run once, then show counters.
    std::thread::sleep(Duration::from_millis(2200));
    let s = resolver.stats_snapshot();
    println!(
        "\nstats: queries={} blocked={} rate_limited={} hits={} upstream={}",
        s.queries, s.policy_blocked, s.rate_limited, s.cache_hits, s.upstream_queries
    );
    Ok(())
}
