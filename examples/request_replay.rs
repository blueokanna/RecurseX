//! Replay: cargo run --release --example request_replay -- config.json trace.tsv incremental
//! Trace rows: offset_ms name rr_type; whitespace separated, # comments allowed.
//! This is a sequential client replay. Reported lateness exposes saturation;
//! it must not be presented as a fixed-QPS open-loop load test.
#[path = "support/legacy_refresh.rs"]
mod legacy;
use recurse_x::{config::Config, Name, Resolver, RrType};
use std::time::{Duration, Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: request_replay config.json trace.tsv legacy|off|incremental".into());
    }
    let mode = args[3].as_str();
    if !matches!(mode, "legacy" | "off" | "incremental") {
        return Err("unknown scheduler".into());
    }
    let mut config =
        Config::from_json_str(&std::fs::read_to_string(&args[1])?)?.into_resolver_config()?;
    // Shared tie-breaking conditions; benchmark compares scheduling, not secrets.
    config.engine.decorrelate_refresh = false;
    let resolver = Resolver::new(config);
    let mut rows = Vec::new();
    for (line, row) in std::fs::read_to_string(&args[2])?.lines().enumerate() {
        let row = row.split('#').next().unwrap_or("").trim();
        if row.is_empty() {
            continue;
        }
        let fields: Vec<_> = row.split_whitespace().collect();
        if fields.len() != 3 {
            return Err(format!("invalid trace row {}", line + 1).into());
        }
        let at: u64 = fields[0].parse()?;
        let rr_type = match fields[2] {
            "A" => RrType::A,
            "AAAA" => RrType::AAAA,
            "CNAME" => RrType::CNAME,
            "MX" => RrType::MX,
            "NS" => RrType::NS,
            "TXT" => RrType::TXT,
            "PTR" => RrType::PTR,
            "SRV" => RrType::SRV,
            "SOA" => RrType::SOA,
            _ => return Err(format!("unsupported type on row {}", line + 1).into()),
        };
        rows.push((at, Name::from_ascii(fields[1])?, rr_type));
    }
    if rows.is_empty() || rows.windows(2).any(|w| w[0].0 > w[1].0) {
        return Err("trace must be nonempty with ordered offsets".into());
    }
    let worker = resolver.clone();
    let mode_owned = mode.to_owned();
    let maintenance = std::thread::spawn(move || {
        let interval = Duration::from_millis(worker.config().maintenance_interval_ms.max(1));
        let mut next = Instant::now() + interval;
        while !worker.is_shutting_down() {
            std::thread::sleep(Duration::from_millis(1));
            if Instant::now() < next {
                continue;
            }
            next = Instant::now() + interval;
            let now = worker.now();
            if mode_owned == "incremental" {
                worker.schedule_refresh_tick(now);
            } else if mode_owned == "legacy" {
                let shared = worker.shared();
                let cache = shared.cache.lock();
                let estimator = shared.estimator.lock();
                let candidates = legacy::schedule(
                    &cache,
                    &worker.config().planner.prefetch_policy(),
                    worker.config().max_prefetch_per_tick,
                    now,
                    |name, horizon| recurse_x::cache::RefreshInputs {
                        query_probability: estimator.probability(name, now, horizon),
                        value_ms: estimator.est_cost_ms(name),
                    },
                );
                drop(estimator);
                drop(cache);
                for key in candidates {
                    worker.refresh_with_dependents(&key, worker.config().max_chain_refresh);
                }
            }
        }
    });
    let start = Instant::now();
    let mut latencies = Vec::new();
    let mut lateness = 0u128;
    let mut errors = 0;
    for (offset, name, rr_type) in rows {
        let due = start + Duration::from_millis(offset);
        if let Some(wait) = due.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }
        lateness = lateness.max(Instant::now().saturating_duration_since(due).as_micros());
        let query_start = Instant::now();
        if resolver.resolve(&name, rr_type).is_err() {
            errors += 1;
        }
        latencies.push(query_start.elapsed().as_micros());
    }
    resolver.shutdown();
    maintenance.join().map_err(|_| "maintenance panic")?;
    let end =
        Instant::now() + Duration::from_millis(resolver.config().engine.query_budget_ms + 5000);
    while resolver.refreshes_in_flight() > 0 && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(1));
    }
    latencies.sort_unstable();
    let quantile = |p: f64| latencies[((latencies.len() - 1) as f64 * p) as usize];
    let count = latencies.len();
    let (attempts, bytes) = resolver.exchange_work();
    let (background, denied) = resolver.background_work();
    let stats = resolver.stats_snapshot();
    let shared = resolver.shared();
    let cache = shared.cache.lock();
    println!("scheduler,queries,errors,p50_us,p95_us,p99_us,max_lateness_us,exchange_attempts,dns_bytes,exchanges_per_query,bytes_per_query,background_exchanges,budget_denied,index_len,refresh_peak,duplicate_rejected,queue_ns,cache_wait_ns,cache_hold_ns,stale_answers,stale_versions_changed,background_remaining");
    println!("{mode},{count},{errors},{},{},{},{lateness},{attempts},{bytes},{:.4},{:.4},{},{denied},{},{},{},{},{},{},{},{},{}",
        quantile(0.5), quantile(0.95), quantile(0.99), attempts as f64/count as f64, bytes as f64/count as f64,
        background.subqueries, cache.refresh_index_len(), stats.refresh_peak, stats.refresh_duplicate_rejected,
        stats.refresh_queue_ns, stats.refresh_cache_wait_ns, stats.refresh_cache_hold_ns,
        stats.served_stale, cache.stats().stale_later_changed, resolver.refreshes_in_flight());
    eprintln!("content model: {}", cache.content_calibration());
    eprintln!("DNS bytes exclude framing/partial failed reads; RSS and CPU require an external sampler. Legacy mode reproduces the old scorer on the new engine, not the full old release.");
    Ok(())
}
