#![cfg(feature = "std")]

#[path = "support/sockets.rs"]
mod sockets;

use recurse_x::{Message, Name, RData, Record, Resolver, ResolverConfig, RrClass, RrType};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum Mode {
    Answer,
    Silent,
    Truncated,
}

struct Authority {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    udp_seen: Arc<AtomicUsize>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

fn answer(bytes: &[u8], truncated: bool) -> Vec<u8> {
    let mut response = Message::parse(bytes).unwrap();
    response.flags.qr = true;
    response.flags.aa = true;
    response.flags.tc = truncated;
    response.answers.push(Record {
        name: response.question().unwrap().qname.clone(),
        rr_type: RrType::A,
        class: RrClass::IN,
        ttl: 60,
        rdata: RData::A("192.0.2.42".parse().unwrap()),
    });
    response.to_bytes().unwrap()
}

impl Authority {
    fn new(udp_mode: Mode, tcp_mode: Mode) -> Self {
        let (tcp, udp) = sockets::bind_dns_pair().unwrap();
        let address = tcp.local_addr().unwrap();
        tcp.set_nonblocking(true).unwrap();
        udp.set_read_timeout(Some(Duration::from_millis(25)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let udp_seen = Arc::new(AtomicUsize::new(0));
        let stopped = stop.clone();
        let seen = udp_seen.clone();
        let udp_thread = std::thread::spawn(move || {
            let mut bytes = [0; 4096];
            while !stopped.load(Ordering::Relaxed) {
                if let Ok((size, peer)) = udp.recv_from(&mut bytes) {
                    seen.fetch_add(1, Ordering::Relaxed);
                    if !matches!(udp_mode, Mode::Silent) {
                        let _ = udp.send_to(
                            &answer(&bytes[..size], matches!(udp_mode, Mode::Truncated)),
                            peer,
                        );
                    }
                }
            }
        });
        let stopped = stop.clone();
        let tcp_thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let Ok((mut stream, _)) = tcp.accept() else {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                };
                stream
                    .set_read_timeout(Some(Duration::from_millis(200)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_millis(200)))
                    .unwrap();
                if matches!(tcp_mode, Mode::Silent) {
                    continue;
                }
                let mut length = [0; 2];
                if stream.read_exact(&mut length).is_err() {
                    continue;
                }
                let mut bytes = vec![0; u16::from_be_bytes(length) as usize];
                if stream.read_exact(&mut bytes).is_err() {
                    continue;
                }
                let bytes = answer(&bytes, matches!(tcp_mode, Mode::Truncated));
                let _ = stream.write_all(&(bytes.len() as u16).to_be_bytes());
                let _ = stream.write_all(&bytes);
            }
        });
        Self {
            address,
            stop,
            udp_seen,
            threads: vec![udp_thread, tcp_thread],
        }
    }
}

impl Drop for Authority {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            thread.join().unwrap();
        }
    }
}

fn resolver(roots: Vec<SocketAddr>) -> Resolver {
    let mut config = ResolverConfig::default();
    config.engine.root_servers = roots;
    config.engine.qname_minimization = false;
    config.engine.timeout_ms = 1000;
    config.engine.query_budget_ms = 500;
    config.engine.max_attempts_per_server = 1;
    Resolver::new(config)
}

#[test]
fn udp_blackhole_can_resolve_over_tcp_inside_the_original_deadline() {
    let upstream = Authority::new(Mode::Silent, Mode::Answer);
    let resolver = resolver(vec![upstream.address]);
    let began = Instant::now();
    let result = resolver
        .resolve(&Name::from_ascii("tcp.test").unwrap(), RrType::A)
        .unwrap();
    assert_eq!(result.answers.len(), 1);
    assert!(began.elapsed() < Duration::from_millis(1000));
    assert_eq!(resolver.stats_snapshot().upstream_queries, 2);
}

#[test]
fn a_truncated_answer_is_never_cached_when_tcp_fails_or_is_also_truncated() {
    for tcp in [Mode::Silent, Mode::Truncated] {
        let upstream = Authority::new(Mode::Truncated, tcp);
        let resolver = resolver(vec![upstream.address]);
        let name = Name::from_ascii("partial.test").unwrap();
        assert!(resolver.resolve(&name, RrType::A).is_err());
        assert!(resolver.resolve(&name, RrType::A).is_err());
        assert_eq!(resolver.stats_snapshot().cache_hits, 0);
    }
}

#[test]
fn an_unreachable_first_authority_leaves_time_for_a_healthy_alternate() {
    use recurse_x::upstream::Endpoint;
    let dead = Authority::new(Mode::Silent, Mode::Silent);
    let healthy = Authority::new(Mode::Answer, Mode::Answer);
    let resolver = resolver(vec![dead.address, healthy.address]);
    // Establish an unambiguous rank: the currently dead server used to be fast.
    let shared = resolver.shared();
    let now = recurse_x::time::from_secs(0);
    shared.selector.lock().record_success(
        Endpoint::new(
            dead.address.ip(),
            dead.address.port(),
            recurse_x::upstream::Proto::Udp,
        ),
        1.0,
        now,
    );
    shared.selector.lock().record_success(
        Endpoint::new(
            healthy.address.ip(),
            healthy.address.port(),
            recurse_x::upstream::Proto::Udp,
        ),
        1000.0,
        now,
    );
    let result = resolver
        .resolve(&Name::from_ascii("alternate.test").unwrap(), RrType::A)
        .unwrap();
    assert_eq!(result.answers.len(), 1);
    assert!(dead.udp_seen.load(Ordering::Relaxed) > 0);
    assert!(healthy.udp_seen.load(Ordering::Relaxed) > 0);
}

#[cfg(feature = "doh")]
#[test]
fn failed_loopback_is_bypassed_temporarily_and_retried_after_network_change() {
    use recurse_x::{
        forward::{Forwarder, ForwarderSet},
        upstream::{Endpoint, Proto},
    };
    let dead = Authority::new(Mode::Silent, Mode::Silent);
    let healthy = Authority::new(Mode::Answer, Mode::Answer);
    let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), true, 0);
    let group: Vec<_> = [dead.address, healthy.address]
        .into_iter()
        .map(|addr| Forwarder::plain(Endpoint::new(addr.ip(), addr.port(), Proto::Udp)))
        .collect();
    let query = Message::query(
        42,
        Name::from_ascii("fallback.test").unwrap(),
        RrType::A,
        true,
    );
    let bytes = query.to_bytes().unwrap();
    for _ in 0..2 {
        assert_eq!(
            set.exchange_with(&group, &query, &bytes, 200)
                .unwrap()
                .answers
                .len(),
            1
        );
    }
    assert_eq!(dead.udp_seen.load(Ordering::Relaxed), 1);
    courierust::courierust_net::outbound::network_changed();
    set.exchange_with(&group, &query, &bytes, 200).unwrap();
    assert_eq!(dead.udp_seen.load(Ordering::Relaxed), 2);
}
