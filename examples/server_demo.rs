//! Run RecurseX as a local DNS server on 127.0.0.1:5353 (UDP + TCP).
//!
//! This wires together the pieces you would deploy: a resolver with a
//! persistent cache (default features), a background maintenance loop, and
//! the client-facing `Server`. It then sends a query to its own UDP socket
//! and prints the parsed answer, so the example is self-verifying.
//!
//! Run: `cargo run --example server_demo`
//! Query it from another shell: `dig @127.0.0.1 -p 5353 example.com A`

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use recurse_x::config::Config;
use recurse_x::{Message, Name, RrType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Configure the resolver from a JSON document (nextjson) ----------
    let json = r#"{
        "listen": [{ "addr": "127.0.0.1:5353", "proto": "udp" }],
        "cache": { "hotCapacity": 2048, "warmCapacity": 131072 },
        "engine": { "qnameMinimization": true, "use0x20": true },
        "clientQps": 200.0,
        "clientBurst": 400.0,
        "maintenanceIntervalMs": 1000
    }"#;
    let cfg = Config::from_json_str(json)?;
    let rc = cfg.into_resolver_config()?;
    let resolver = recurse_x::Resolver::new(rc);

    // Background maintenance: cache sweep, graph prune, predictive prefetch.
    let _maintenance = resolver.spawn_maintenance();

    // --- Client-facing server (UDP + TCP on the same port) ---------------
    let server = recurse_x::Server::new(resolver.clone());
    let udp_addr: SocketAddr = "127.0.0.1:5353".parse()?;
    let bound_udp = server.bind_udp(udp_addr)?;
    let bound_tcp = server.bind_tcp(udp_addr)?;
    println!("server listening: udp={bound_udp} tcp={bound_tcp}");

    // --- Self-test: query our own server over UDP -------------------------
    let sock = UdpSocket::bind("127.0.0.1:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(30)))?;

    let qname = Name::from_ascii("example.com")?;
    let query = Message::query(0x4242, qname.clone(), RrType::A, true);
    let qbytes = query.to_bytes()?;
    sock.send_to(&qbytes, bound_udp)?;

    let mut buf = [0u8; 4096];
    let (n, _) = sock.recv_from(&mut buf)?;
    let resp = Message::parse(&buf[..n])?;
    println!(
        "self-test: id=0x{:04x} rcode={:?} answers={} tc={}",
        resp.id,
        resp.rcode(),
        resp.answers.len(),
        resp.is_truncated()
    );
    for r in &resp.answers {
        println!("    {} {:?} ttl={}", r.name, r.rdata, r.ttl);
    }
    assert_eq!(resp.id, query.id, "response ID must match the query");

    // --- Report -----------------------------------------------------------
    let s = resolver.stats_snapshot();
    println!(
        "\nstats: queries={} hits={} upstream={} timeouts={} avg_resolve={}us",
        s.queries, s.cache_hits, s.upstream_queries, s.upstream_timeouts, s.avg_resolve_us
    );

    // Keep serving until Ctrl+C.
    println!("\nserving on 127.0.0.1:5353 — press Ctrl+C to stop");
    server.join();
    Ok(())
}
