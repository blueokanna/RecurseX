//! End-to-end tests against the public API, as an embedder sees it.
//!
//! These drive the same surface the README documents — JSON configuration,
//! a resolver, a client-facing server — with a local stub upstream, so they
//! are hermetic: no test in this crate touches the public Internet, and a
//! failure here is a failure of the resolver, not of the network.

#![cfg(feature = "std")]

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "persist")]
use recurse_x::cache::persist::PersistConfig;
use recurse_x::config::Config;
use recurse_x::qtype::{Rcode, RrClass};
use recurse_x::rdata::{RData, Record};
use recurse_x::{Message, Name, Resolver, ResolverConfig, RrType, Server, ServerConfig};

/// A stub authoritative server.
///
/// Answers `a.example.com` with a CNAME to `b.example.com`, `b.example.com`
/// with one A record, and everything else with NODATA — enough shape for a
/// real resolution (including QNAME minimization, which asks for a
/// non-existent parent first). `seen` counts the queries it was asked, which
/// lets a test prove that a later answer came from cache.
struct Stub {
    addr: SocketAddr,
    seen: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Stub {
    fn start() -> Stub {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind stub");
        let addr = sock.local_addr().expect("stub addr");
        let seen = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let counters = seen.clone();
        let flag = stop.clone();
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("stub timeout");
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while !flag.load(Ordering::Relaxed) {
                let Ok((n, src)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                counters.fetch_add(1, Ordering::Relaxed);
                let Ok(query) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let Some(question) = query.question() else {
                    continue;
                };
                let mut resp = Message::new(query.id);
                resp.flags.qr = true;
                resp.flags.aa = true;
                resp.flags.ra = true;
                resp.flags.rd = query.flags.rd;
                resp.questions.clone_from(&query.questions);
                match (question.qname.to_ascii().as_str(), question.qtype) {
                    ("a.example.com", RrType::A) => resp.answers.push(Record {
                        name: question.qname.clone(),
                        rr_type: RrType::CNAME,
                        class: RrClass::IN,
                        ttl: 60,
                        rdata: RData::Cname(Name::from_ascii("b.example.com").unwrap()),
                    }),
                    ("b.example.com", RrType::A) => resp.answers.push(Record {
                        name: question.qname.clone(),
                        rr_type: RrType::A,
                        class: RrClass::IN,
                        ttl: 60,
                        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 7)),
                    }),
                    _ => {}
                }
                if let Ok(bytes) = resp.to_bytes() {
                    let _ = sock.send_to(&bytes, src);
                }
            }
        });
        Stub { addr, seen, stop }
    }

    fn queries_seen(&self) -> usize {
        self.seen.load(Ordering::Relaxed)
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn query_bytes(name: &str, id: u16) -> Vec<u8> {
    Message::query(id, Name::from_ascii(name).unwrap(), RrType::A, true)
        .to_bytes()
        .unwrap()
}

/// A JSON document is the documented way to configure a deployment, so it
/// has to survive the whole path: parse → resolver → server → wire.
#[test]
fn json_configuration_drives_a_working_server() {
    let stub = Stub::start();
    let json = format!(
        r#"{{
            "cache": {{ "hotCapacity": 64, "warmCapacity": 256 }},
            "engine": {{
                "qnameMinimization": true,
                "use0x20": true,
                "rootServers": ["{root}"]
            }}
        }}"#,
        root = stub.addr
    );
    let cfg = Config::from_json_str(&json).expect("config parses");
    let resolver_cfg: ResolverConfig = cfg.into_resolver_config().expect("resolver config");

    let resolver = Resolver::new(resolver_cfg);
    let server = Server::with_config(
        resolver.clone(),
        ServerConfig {
            udp_workers: 1,
            udp_handlers: 2,
            udp_queue: 16,
            ..ServerConfig::default()
        },
    );
    let udp_addr = server.bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
    let tcp_addr = server.bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();

    // 1. UDP: a full resolution (CNAME plus the target's address).
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
        .send_to(&query_bytes("a.example.com", 0x1111), udp_addr)
        .unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = client.recv_from(&mut buf).expect("udp answer");
    let resp = Message::parse(&buf[..n]).unwrap();
    assert_eq!(resp.id, 0x1111);
    assert_eq!(resp.rcode(), Rcode::NOERROR.0 as u16);
    assert_eq!(resp.answers.len(), 2, "CNAME plus A");
    assert!(resp
        .answers
        .iter()
        .any(|r| r.rdata == RData::A(Ipv4Addr::new(192, 0, 2, 7))));

    // 2. The same query again must not reach the upstream.
    let before = stub.queries_seen();
    client
        .send_to(&query_bytes("a.example.com", 0x2222), udp_addr)
        .unwrap();
    let (n, _) = client.recv_from(&mut buf).expect("udp answer (cached)");
    let resp = Message::parse(&buf[..n]).unwrap();
    assert_eq!(resp.id, 0x2222);
    assert_eq!(
        stub.queries_seen(),
        before,
        "the second answer must come from cache"
    );
    assert!(resolver.stats_snapshot().cache_hits >= 1);

    // 3. TCP carries the same answer (length-prefixed, unfragmented).
    let tcp = std::net::TcpStream::connect(tcp_addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let q = query_bytes("a.example.com", 0x3333);
    let mut framed = Vec::new();
    framed.extend_from_slice(&(q.len() as u16).to_be_bytes());
    framed.extend_from_slice(&q);
    std::io::Write::write_all(&mut &tcp, &framed).unwrap();
    let mut header = [0u8; 2];
    std::io::Read::read_exact(&mut &tcp, &mut header).unwrap();
    let mut body = vec![0u8; u16::from_be_bytes(header) as usize];
    std::io::Read::read_exact(&mut &tcp, &mut body).unwrap();
    let resp = Message::parse(&body).unwrap();
    assert_eq!(resp.id, 0x3333);
    assert_eq!(resp.answers.len(), 2);

    // 4. Shutdown is the documented contract: after it, join returns.
    assert_eq!(server.udp_shed(), 0, "a light load must not shed");
    server.shutdown();
    resolver.shutdown();
    assert!(server.is_shutting_down());
    assert!(resolver.is_shutting_down());
    let (tx, rx) = std::sync::mpsc::channel();
    let joiner = std::thread::spawn(move || {
        server.join();
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(5))
        .expect("join must return after shutdown");
    joiner.join().unwrap();
}

/// A snapshot written on shutdown must be usable by the next process: the
/// restart answers from cache without asking any upstream.
#[cfg(feature = "persist")]
#[test]
fn persistent_cache_survives_a_restart() {
    let stub = Stub::start();
    let path = std::env::temp_dir().join(format!(
        "recursex-e2e-{}-{:?}.rxc",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&path);

    let mut cfg = ResolverConfig::default();
    cfg.engine.root_servers = vec![stub.addr];
    cfg.engine.timeout_ms = 1_000;
    cfg.persist = Some(PersistConfig::new(path.clone(), 0));

    let first = Resolver::new(cfg.clone());
    let name = Name::from_ascii("a.example.com").unwrap();
    let res = first.resolve(&name, RrType::A).unwrap();
    assert!(!res.from_cache);
    assert!(stub.queries_seen() > 0);
    first.shutdown();
    first.persist_cache().unwrap();
    drop(first);

    // "Restart": a fresh resolver over the same snapshot.
    let second = Resolver::new(cfg);
    let before = stub.queries_seen();
    let res = second.resolve(&name, RrType::A).unwrap();
    assert!(
        res.from_cache,
        "the snapshot must serve the chain from cache"
    );
    assert_eq!(
        stub.queries_seen(),
        before,
        "a restart must not need the network"
    );
    second.shutdown();
    let _ = std::fs::remove_file(&path);
}

/// Forwarding mode: the resolver must ask the configured forwarder with
/// RD=1 and return its answer.
#[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
#[test]
fn configured_forwarder_is_used() {
    let stub = Stub::start();
    let cfg = Config::from_json_str(&format!(
        r#"{{ "engine": {{ "forwarders": [
            {{ "proto": "udp", "ip": "127.0.0.1", "port": {} }}
        ] }} }}"#,
        stub.addr.port()
    ))
    .expect("config parses");
    let mut resolver_cfg = cfg.into_resolver_config().unwrap();
    resolver_cfg.engine.timeout_ms = 1_000;
    // Nothing listens on port 53 here; the forwarder must answer.
    resolver_cfg.engine.forwarders[0].endpoint = recurse_x::upstream::Endpoint::new(
        std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
        stub.addr.port(),
        recurse_x::upstream::Proto::Udp,
    );

    let resolver = Resolver::new(resolver_cfg);
    let res = resolver
        .resolve(&Name::from_ascii("b.example.com").unwrap(), RrType::A)
        .unwrap();
    assert_eq!(res.answers.len(), 1);
    assert_eq!(res.answers[0].rdata, RData::A(Ipv4Addr::new(192, 0, 2, 7)));
    // The forwarder was asked directly (no traversal from the root).
    assert_eq!(stub.queries_seen(), 1, "forwarding resolves in one query");
    resolver.shutdown();
}
