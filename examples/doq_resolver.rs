//! A DNS-over-QUIC (RFC 9250) forwarding resolver: every query goes to a
//! DoQ upstream with RD=1, with automatic fallback to iterative resolution
//! if the DoQ forwarder fails.
//!
//! The DoQ client is implemented from the RFCs (RFC 9000 / 9001 / 9002 /
//! 9250) on top of courierust's public wire codecs — see
//! `recurse_x::transports::doq`. No provider wiring is needed.
//!
//! Run: `cargo run --example doq_resolver [name]`
//!
//! The default forwarder is Cloudflare (`1.1.1.1:853`, certificate name
//! `cloudflare-dns.com`). To verify the certificate, call
//! `resolver.set_forwarder_roots(roots, true)` with your trust anchors;
//! without roots the encrypted transport runs with verification disabled
//! (matching the DoT/DoH transports' default).

use recurse_x::config::Config;
use recurse_x::{Name, Resolver, RrType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".to_string());

    let json = r#"
        {
            "engine": {
                "forwarders": [
                    { "proto": "doq", "ip": "1.1.1.1", "port": 853, "host": "cloudflare-dns.com" }
                ]
            }
        }
    "#;
    let cfg = Config::from_json_str(json)?;
    let rc = cfg.into_resolver_config()?;
    let resolver = Resolver::new(rc);

    let name = Name::from_ascii(&host)?;
    let started = std::time::Instant::now();
    let res = resolver.resolve(&name, RrType::A)?;
    println!(
        "{host} A -> rcode={:?} answers={} ttl={} from_cache={} [{}ms]",
        res.rcode,
        res.answers.len(),
        res.ttl,
        res.from_cache,
        started.elapsed().as_millis()
    );
    for r in &res.answers {
        println!("    {} {:?}", r.name, r.rdata);
    }

    let s = resolver.stats_snapshot();
    println!(
        "\nstats: queries={} upstream={} timeouts={} avg_resolve={}us",
        s.queries, s.upstream_queries, s.upstream_timeouts, s.avg_resolve_us
    );
    Ok(())
}
