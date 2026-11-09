//! A DNS-over-QUIC (RFC 9250) forwarding resolver: every query goes to a
//! DoQ upstream with RD=1, and fails closed if the forwarder fails.
//!
//! The DoQ client is implemented from the RFCs (RFC 9000 / 9001 / 9002 /
//! 9250) on top of courierust's public wire codecs — see
//! `recurse_x::transports::doq`. No provider wiring is needed.
//!
//! Set RECURSEX_CA_FILE to a PEM trust bundle before running.
//! Run: `cargo run --example doq_resolver [name]`
//!
//! The default forwarder is Cloudflare (`1.1.1.1:853`, certificate name
//! `cloudflare-dns.com`). Certificate verification is enabled; missing or
//! invalid roots reject configuration before any query is sent.

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
    let mut cfg = Config::from_json_str(json)?;
    cfg.forwarder_ca_file = Some(
        std::env::var("RECURSEX_CA_FILE")
            .map_err(|_| "set RECURSEX_CA_FILE to a PEM trust bundle")?,
    );
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
