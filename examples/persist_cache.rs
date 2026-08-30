//! Demonstrate the L3 persistent cache: resolve, snapshot to disk, then
//! start a *new* resolver that loads the snapshot and serves from it.
//!
//! This is what makes a warm cache survive a restart — the stability
//! models, admission scores and tier assignments are all serialized, not
//! just the records.
//!
//! Run: `cargo run --example persist_cache`
//! (the `persist` feature is on by default; needs network for the first pass)

use std::time::Instant;

use recurse_x::cache::persist::PersistConfig;
use recurse_x::{Name, Resolver, ResolverConfig, RrType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cache_path = std::env::temp_dir().join("recursex_persist_demo.rxc");
    let _ = std::fs::remove_file(&cache_path);

    // --- First process: resolve, then persist ------------------------------
    let name = Name::from_ascii("ietf.org")?;
    println!("[pass 1] cold resolver (no cache file yet)");

    let cfg1 = ResolverConfig {
        persist: Some(PersistConfig::new(&cache_path, 0)),
        ..ResolverConfig::default()
    };
    let r1 = Resolver::new(cfg1);

    let t = Instant::now();
    let res = r1.resolve(&name, RrType::A)?;
    println!(
        "  resolved ietf.org A -> answers={} ttl={} from_cache={} [{}ms]",
        res.answers.len(),
        res.ttl,
        res.from_cache,
        t.elapsed().as_millis()
    );
    for r in &res.answers {
        println!("    {} {:?}", r.name, r.rdata);
    }

    let written = r1.persist_cache()?;
    println!(
        "  persisted {written} cache entries -> {}",
        cache_path.display()
    );
    drop(r1); // the first resolver is gone, as if the process restarted

    // --- Second process: load the snapshot and serve from it ----------------
    println!("\n[pass 2] warm resolver (loads the snapshot at construction)");
    let cfg2 = ResolverConfig {
        persist: Some(PersistConfig::new(&cache_path, 0)),
        ..ResolverConfig::default()
    };
    let r2 = Resolver::new(cfg2); // <-- load_from happens here

    let t = Instant::now();
    let res = r2.resolve(&name, RrType::A)?;
    println!(
        "  resolved ietf.org A -> answers={} ttl={} from_cache={} [{}ms]",
        res.answers.len(),
        res.ttl,
        res.from_cache,
        t.elapsed().as_millis()
    );
    if !res.from_cache {
        eprintln!("warning: expected a cache hit from the restored snapshot");
        std::process::exit(1);
    }

    let _ = std::fs::remove_file(&cache_path);
    println!("\npersistence demo OK");
    Ok(())
}
