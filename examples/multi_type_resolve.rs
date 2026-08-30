//! Resolve several record types for a name and print the answers.
//!
//! This exercises the public `Resolver::resolve` API across A, AAAA, MX,
//! TXT, NS and SOA, and shows the metadata a `Resolution` carries
//! (validated, TTL, cache hit, stale).
//!
//! Run: `cargo run --no-default-features --features std --example multi_type_resolve`

use recurse_x::qtype::RrType;
use recurse_x::{Name, Resolver, ResolverConfig};

fn main() {
    let resolver = Resolver::new(ResolverConfig::default());
    // Put the maintenance loop in the background: sweeps dead cache
    // entries, prunes the resolution graph and runs predictive prefetch.
    let _maintenance = resolver.spawn_maintenance();

    let host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".to_string());
    let name = match Name::from_ascii(&host) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("bad name {host:?}: {e}");
            std::process::exit(2);
        }
    };

    let types = [
        (RrType::A, "A"),
        (RrType::AAAA, "AAAA"),
        (RrType::MX, "MX"),
        (RrType::TXT, "TXT"),
        (RrType::NS, "NS"),
        (RrType::SOA, "SOA"),
    ];

    println!("resolving {host}:");
    for (ty, label) in types {
        let started = std::time::Instant::now();
        match resolver.resolve(&name, ty) {
            Ok(res) => {
                let ms = started.elapsed().as_millis();
                print!(
                    "  {label:<4} rcode={:?} answers={} ttl={} cache={} stale={} validated={} [{ms}ms]",
                    res.rcode,
                    res.answers.len(),
                    res.ttl,
                    res.from_cache,
                    res.stale,
                    res.validated
                );
                if res.answers.is_empty() {
                    println!("  (no data)");
                } else {
                    println!();
                }
                for r in &res.answers {
                    println!("        {} {:?} ttl={}", r.name, r.rdata, r.ttl);
                }
            }
            Err(e) => {
                println!(
                    "  {label:<4} ERROR {:?} [{}ms]",
                    e,
                    started.elapsed().as_millis()
                );
            }
        }
    }

    // Second pass: everything should be served from the cache (0 ms).
    println!("\ncached pass:");
    let started = std::time::Instant::now();
    match resolver.resolve(&name, RrType::A) {
        Ok(res) => println!(
            "  A again -> from_cache={} stale={} ttl={} [{}ms]",
            res.from_cache,
            res.stale,
            res.ttl,
            started.elapsed().as_millis()
        ),
        Err(e) => println!("  A again -> ERROR {e:?}"),
    }

    let s = resolver.stats_snapshot();
    println!(
        "\nstats: queries={} cache_hits={} upstream={} timeouts={} prefetches={} avg_resolve={}us",
        s.queries,
        s.cache_hits,
        s.upstream_queries,
        s.upstream_timeouts,
        s.prefetches,
        s.avg_resolve_us
    );
}
