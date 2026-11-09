//! Offline lock-contention microbenchmark. No DNS latency/performance claim.
#[path = "support/legacy_refresh.rs"]
mod legacy;
use recurse_x::cache::{score::ScoreInputs, CacheConfig, CacheKey, RefreshInputs, SemanticCache};
use recurse_x::planner::PrefetchPolicy;
use recurse_x::rrset::RrSet;
use recurse_x::{Name, RrClass, RrType};
use std::sync::{Arc, Barrier, Mutex};
use std::time::Instant;

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "10000".into())
        .parse()
        .unwrap();
    let rounds: usize = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "10".into())
        .parse()
        .unwrap();
    println!("mode,entries,rounds,checks,lock_hold_us,score_us,lookup_p50_us,lookup_p95_us,lookup_p99_us,index_len");
    for mode in ["legacy", "off", "incremental"] {
        let now = 1_800_000_000_000_000_000i128;
        let config = CacheConfig {
            hot_capacity: n,
            warm_capacity: n,
            cold_capacity: n,
            min_admit_score: 0.0,
            ..CacheConfig::default()
        };
        let mut cache = SemanticCache::new(config);
        for i in 0..n {
            let name = format!("h{i}.example.com");
            let key = CacheKey::plain(Name::from_ascii(&name).unwrap(), RrType::A, RrClass::IN);
            for step in 0..8 {
                let mut rrset = RrSet::new(key.name.clone(), RrType::A, RrClass::IN, 3600);
                rrset.add_record(recurse_x::Record {
                    name: key.name.clone(),
                    rr_type: RrType::A,
                    class: RrClass::IN,
                    ttl: 3600,
                    rdata: recurse_x::RData::A("192.0.2.1".parse().unwrap()),
                });
                cache.insert_positive(
                    &key,
                    rrset,
                    now - (8 - step) * 60_000_000_000,
                    ScoreInputs::default(),
                    false,
                );
            }
        }
        let cache = Arc::new(Mutex::new(cache));
        let barrier = Arc::new(Barrier::new(2));
        let worker_cache = cache.clone();
        let worker_barrier = barrier.clone();
        let worker = std::thread::spawn(move || {
            let key = CacheKey::plain(
                Name::from_ascii("h0.example.com").unwrap(),
                RrType::A,
                RrClass::IN,
            );
            let mut times = Vec::new();
            for _ in 0..rounds {
                worker_barrier.wait();
                for _ in 0..100 {
                    let started = Instant::now();
                    let _ = worker_cache.lock().unwrap().lookup(&key, now);
                    times.push(started.elapsed().as_micros());
                }
                worker_barrier.wait();
            }
            times.sort_unstable();
            times
        });
        let policy = PrefetchPolicy {
            horizon_secs: 60,
            target_freshness: 0.999999,
            min_probability: 0.5,
            min_evidence_secs: 1.0,
        };
        let supplied = RefreshInputs {
            query_probability: 0.99,
            value_ms: 50.0,
        };
        let mut hold = 0;
        let mut scoring = 0;
        let mut checks = 0;
        for tick in 0..rounds {
            barrier.wait();
            let at = now + tick as i128 * 1_000_000_000;
            if mode == "legacy" {
                let locked = cache.lock().unwrap();
                let start = Instant::now();
                checks += locked.len();
                let _ = legacy::schedule(&locked, &policy, 64, at, |_, _| supplied);
                hold += start.elapsed().as_micros();
                scoring += start.elapsed().as_micros();
            } else if mode == "incremental" {
                let mut locked = cache.lock().unwrap();
                let start = Instant::now();
                let snapshots = locked.refresh_snapshots(at, 256, 1_000_000_000);
                let scheduling = locked.config().refresh_scheduling;
                hold += start.elapsed().as_micros();
                drop(locked);
                checks += snapshots.len();
                let start = Instant::now();
                let _ = recurse_x::cache::rank_refresh_snapshots(
                    snapshots.into_iter().map(|s| (s, supplied)),
                    &policy,
                    scheduling,
                    None,
                    64,
                    at,
                );
                scoring += start.elapsed().as_micros();
            }
            barrier.wait();
        }
        let times = worker.join().unwrap();
        let quantile = |p: f64| {
            times
                .get(((times.len().saturating_sub(1)) as f64 * p) as usize)
                .copied()
                .unwrap_or(0)
        };
        println!(
            "{mode},{n},{rounds},{checks},{hold},{scoring},{},{},{},{}",
            quantile(0.5),
            quantile(0.95),
            quantile(0.99),
            cache.lock().unwrap().refresh_index_len()
        );
    }
}
