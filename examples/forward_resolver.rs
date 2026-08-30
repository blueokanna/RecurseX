//! A forwarding resolver: every query goes to a configured upstream with
//! RD=1 (instead of iterating from the root), with automatic fallback to
//! iterative resolution if the forwarder fails.
//!
//! With the default features (`dot`, `doh`) the example forwards over DNS
//! over TLS to Cloudflare. Built with only `--features std` it forwards
//! over plain UDP to 8.8.8.8.
//!
//! Run: `cargo run --example forward_resolver [name]`

use recurse_x::config::Config;
use recurse_x::{Name, Resolver, RrType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".to_string());

    // Forwarder JSON depends on which encrypted transports are compiled in.
    #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
    let forwarder_json = r#"
        { "proto": "dot", "ip": "1.1.1.1", "port": 853, "host": "cloudflare-dns.com" }
    "#;
    #[cfg(not(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq")))]
    let forwarder_json = r#"
        { "proto": "udp", "ip": "8.8.8.8", "port": 53 }
    "#;

    let json = format!(
        r#"{{
            "listen": [{{ "addr": "127.0.0.1:5354", "proto": "udp" }}],
            "engine": {{
                "forwarders": [ {forwarder_json} ]
            }}
        }}"#
    );
    let cfg = Config::from_json_str(&json)?;
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
