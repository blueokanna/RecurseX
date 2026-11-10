//! Routing and disclosure regressions against real loopback UDP sockets.
#![cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]

use recurse_x::forward::Forwarder;
use recurse_x::privacy::UpstreamPrivacy;
use recurse_x::qtype::{Rcode, RrClass};
use recurse_x::rdata::{RData, Record};
use recurse_x::routing::{FallbackFilter, NameserverPolicy};
use recurse_x::upstream::{Endpoint, Proto};
use recurse_x::{ErrorKind, Message, Name, Resolver, ResolverConfig, RrType};
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct Upstream {
    forwarder: Forwarder,
    seen: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Upstream {
    fn start(ip: &str, rcode: Rcode, answer: Ipv4Addr) -> Self {
        let socket = UdpSocket::bind((ip, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let seen = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let observed = seen.clone();
        let stopped = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut buffer = [0; 4096];
            while !stopped.load(Ordering::Acquire) {
                let Ok((length, peer)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                observed.fetch_add(1, Ordering::Relaxed);
                let mut response = Message::parse(&buffer[..length]).unwrap();
                response.flags.qr = true;
                response.flags.ra = true;
                response.flags.rcode = rcode;
                if rcode == Rcode::NOERROR {
                    response.answers.push(Record {
                        name: response.questions[0].qname.clone(),
                        rr_type: RrType::A,
                        class: RrClass::IN,
                        ttl: 60,
                        rdata: RData::A(answer),
                    });
                }
                socket.send_to(&response.to_bytes().unwrap(), peer).unwrap();
            }
        });
        Self {
            forwarder: Forwarder::plain(Endpoint::new(address.ip(), address.port(), Proto::Udp)),
            seen,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap();
    }
}

fn config(primary: &Upstream, fallback: &Upstream) -> ResolverConfig {
    let mut config = ResolverConfig::default();
    config.engine.dnssec = false;
    config.engine.timeout_ms = 1000;
    config.engine.query_budget_ms = 2000;
    config.dns.upstreams.default = vec![primary.forwarder.clone()];
    config.dns.upstreams.fallback = vec![fallback.forwarder.clone()];
    config
}

#[test]
fn default_group_failure_reaches_fallback() {
    let primary = Upstream::start("127.0.0.1", Rcode::SERVFAIL, Ipv4Addr::UNSPECIFIED);
    let fallback = Upstream::start("127.0.0.1", Rcode::NOERROR, Ipv4Addr::new(203, 0, 113, 7));
    let resolver = Resolver::new(config(&primary, &fallback));
    let result = resolver
        .resolve(&Name::from_ascii("public.example").unwrap(), RrType::A)
        .unwrap();
    assert_eq!(
        result.answers[0].rdata,
        RData::A(Ipv4Addr::new(203, 0, 113, 7))
    );
    assert_eq!(primary.seen.load(Ordering::Relaxed), 1);
    assert_eq!(fallback.seen.load(Ordering::Relaxed), 1);
}

#[test]
fn fallback_cannot_reset_the_disclosure_allowance() {
    let primary = Upstream::start("127.0.0.1", Rcode::SERVFAIL, Ipv4Addr::UNSPECIFIED);
    let fallback = Upstream::start("127.0.0.2", Rcode::NOERROR, Ipv4Addr::new(203, 0, 113, 7));
    let mut config = config(&primary, &fallback);
    config.dns.privacy = UpstreamPrivacy {
        max_upstreams: 1,
        ..UpstreamPrivacy::default()
    };
    let resolver = Resolver::new(config);
    let error = resolver
        .resolve(&Name::from_ascii("private.example").unwrap(), RrType::A)
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Policy);
    assert_eq!(primary.seen.load(Ordering::Relaxed), 1);
    assert_eq!(fallback.seen.load(Ordering::Relaxed), 0);
}

#[test]
fn explicit_route_outranks_forced_fallback_and_its_address_filter() {
    let primary = Upstream::start("127.0.0.1", Rcode::NOERROR, Ipv4Addr::LOCALHOST);
    let fallback = Upstream::start("127.0.0.1", Rcode::NOERROR, Ipv4Addr::new(203, 0, 113, 7));
    let mut config = config(&primary, &fallback);
    config.dns.upstreams.extra = vec![vec![primary.forwarder.clone()]];
    config.dns.policy = NameserverPolicy::new(&[("+.private.example".into(), 2)]).unwrap();
    config.dns.fallback = FallbackFilter::new(&["+.private.example".into()], None, false).unwrap();
    let resolver = Resolver::new(config);
    let response = resolver
        .resolve(
            &Name::from_ascii("node.private.example").unwrap(),
            RrType::A,
        )
        .unwrap();
    assert_eq!(response.answers[0].rdata, RData::A(Ipv4Addr::LOCALHOST));
    assert_eq!(primary.seen.load(Ordering::Relaxed), 1);
    assert_eq!(fallback.seen.load(Ordering::Relaxed), 0);
}

#[test]
fn invalid_explicit_route_never_uses_the_default_group() {
    let primary = Upstream::start("127.0.0.1", Rcode::NOERROR, Ipv4Addr::LOCALHOST);
    let fallback = Upstream::start("127.0.0.1", Rcode::NOERROR, Ipv4Addr::LOCALHOST);
    let mut config = config(&primary, &fallback);
    config.dns.policy = NameserverPolicy::new(&[("+.private.example".into(), 99)]).unwrap();
    let resolver = Resolver::new(config);
    assert_eq!(
        resolver
            .resolve(
                &Name::from_ascii("node.private.example").unwrap(),
                RrType::A
            )
            .unwrap_err()
            .kind,
        ErrorKind::NoUpstream
    );
    assert_eq!(primary.seen.load(Ordering::Relaxed), 0);
    assert_eq!(fallback.seen.load(Ordering::Relaxed), 0);
}

#[test]
fn zero_timeout_does_not_gain_time_from_fallback_reservation() {
    let primary = Upstream::start("127.0.0.1", Rcode::SERVFAIL, Ipv4Addr::UNSPECIFIED);
    let fallback = Upstream::start("127.0.0.1", Rcode::NOERROR, Ipv4Addr::LOCALHOST);
    let mut config = config(&primary, &fallback);
    config.engine.timeout_ms = 0;
    let resolver = Resolver::new(config);
    assert_eq!(
        resolver
            .resolve(&Name::from_ascii("timeout.example").unwrap(), RrType::A)
            .unwrap_err()
            .kind,
        ErrorKind::Timeout
    );
    assert_eq!(primary.seen.load(Ordering::Relaxed), 0);
    assert_eq!(fallback.seen.load(Ordering::Relaxed), 0);
}

#[test]
fn strict_programmatic_configuration_cannot_fall_back_to_recursion() {
    let mut config = ResolverConfig::default();
    config.dns.privacy = UpstreamPrivacy::strict();
    let resolver = Resolver::new(config);
    assert_eq!(
        resolver
            .resolve(&Name::from_ascii("private.example").unwrap(), RrType::A)
            .unwrap_err()
            .kind,
        ErrorKind::Config
    );
}
