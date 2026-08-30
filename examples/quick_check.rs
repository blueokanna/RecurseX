//! Quick live-DNS validation: resolve a few names through the full
//! iterative pipeline (root → TLD → authoritative, UDP + TCP fallback).
//!
//! Run: `cargo run --no-default-features --features std --example quick_check`

use recurse_x::qtype::RrType;
use recurse_x::{Name, Resolver, ResolverConfig};

fn main() {
    let resolver = Resolver::new(ResolverConfig::default());

    let names = [
        "example.com",
        "www.example.com",
        "google.com",
        "ietf.org",
        "nonexistent.invalid",
    ];

    for name in names {
        let n = match Name::from_ascii(name) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let started = std::time::Instant::now();
        match resolver.resolve(&n, RrType::A) {
            Ok(res) => {
                let ms = started.elapsed().as_millis();
                println!(
                    "{} A -> rcode={:?} validated={} ttl={} answers={} [{}ms]",
                    name,
                    res.rcode,
                    res.validated,
                    res.ttl,
                    res.answers.len(),
                    ms
                );
                for r in &res.answers {
                    println!("    {} {:?}", r.name, r.rdata);
                }
            }
            Err(e) => {
                println!(
                    "{} A -> ERROR {:?} [{}ms]",
                    name,
                    e,
                    started.elapsed().as_millis()
                );
            }
        }
    }

    // Second pass: everything should be served from cache.
    for name in names {
        let n = Name::from_ascii(name).unwrap();
        let started = std::time::Instant::now();
        match resolver.resolve(&n, RrType::A) {
            Ok(res) => {
                println!(
                    "{} (cached) -> from_cache={} stale={} ttl={} [{}ms]",
                    name,
                    res.from_cache,
                    res.stale,
                    res.ttl,
                    started.elapsed().as_millis()
                );
            }
            Err(e) => println!("{} (cached) -> ERROR {:?}", name, e),
        }
    }

    let s = resolver.stats_snapshot();
    println!(
        "stats: queries={} hits={} misses={} upstream={} timeouts={} stale={} avg_resolve={}us",
        s.queries,
        s.cache_hits,
        s.cache_misses,
        s.upstream_queries,
        s.upstream_timeouts,
        s.served_stale,
        s.avg_resolve_us
    );
}
