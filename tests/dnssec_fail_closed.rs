#![cfg(feature = "dnssec")]

#[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
use recurse_x::cache::LookupOutcome;
use recurse_x::cache::{score::ScoreInputs, CacheKey};
use recurse_x::qtype::{DnssecAlgorithm, RrClass};
use recurse_x::rrset::RrSet;
use recurse_x::{Name, RData, Record, Resolver, ResolverConfig, RrType};

fn resolver() -> Resolver {
    let mut config = ResolverConfig::default();
    config.engine.dnssec = true;
    config.engine.root_servers = vec!["127.0.0.1:1".parse().unwrap()];
    config.engine.timeout_ms = 5;
    config.engine.query_budget_ms = 20;
    let resolver = Resolver::new(config);
    let owner = Name::from_ascii("example.test").unwrap();
    let mut keys = RrSet::new(owner.clone(), RrType::DNSKEY, RrClass::IN, 300);
    keys.add_record(Record {
        name: owner.clone(),
        rr_type: RrType::DNSKEY,
        class: RrClass::IN,
        ttl: 300,
        rdata: RData::Dnskey {
            flags: 256,
            protocol: 3,
            algorithm: DnssecAlgorithm::RSASHA256,
            public_key: vec![1, 3, 1],
        },
    });
    resolver.shared().cache.lock().insert_positive(
        &CacheKey::plain(owner, RrType::DNSKEY, RrClass::IN),
        keys,
        resolver.now(),
        ScoreInputs::default(),
        false,
    );
    resolver
}

fn signed_answer() -> RrSet {
    let owner = Name::from_ascii("bad.example.test").unwrap();
    let mut answer = RrSet::new(owner.clone(), RrType::A, RrClass::IN, 300);
    answer.add_record(Record {
        name: owner.clone(),
        rr_type: RrType::A,
        class: RrClass::IN,
        ttl: 300,
        rdata: RData::A("192.0.2.1".parse().unwrap()),
    });
    answer.rrsigs.push(Record {
        name: owner,
        rr_type: RrType::RRSIG,
        class: RrClass::IN,
        ttl: 300,
        rdata: RData::Rrsig {
            type_covered: RrType::A,
            algorithm: DnssecAlgorithm::RSASHA256,
            labels: 3,
            original_ttl: 300,
            expiration: 1,
            inception: 0,
            key_tag: recurse_x::dnssec::key_tag(256, 3, 8, &[1, 3, 1]),
            signer: Name::from_ascii("example.test").unwrap(),
            signature: vec![0; 256],
        },
    });
    answer
}

#[test]
fn cached_expired_signature_is_rejected_even_if_marked_validated() {
    for validated in [false, true] {
        let resolver = resolver();
        let answer = signed_answer();
        let key = CacheKey::plain(answer.name.clone(), RrType::A, RrClass::IN);
        resolver.shared().cache.lock().insert_positive(
            &key,
            answer,
            resolver.now(),
            ScoreInputs::default(),
            validated,
        );
        assert_eq!(
            resolver.resolve(&key.name, RrType::A).unwrap_err().kind,
            recurse_x::ErrorKind::Dnssec
        );
    }
}

#[test]
fn refresh_failure_cannot_serve_an_expired_signature_or_charge_stale_metrics() {
    let seed = resolver();
    let mut config = seed.config().clone();
    config.planner.stale_policy = recurse_x::planner::StalePolicy::OnRefreshFailure;
    config.planner.risk.base_min_freshness = 0.0;
    let resolver = Resolver::new(config);
    let keys = seed
        .shared()
        .cache
        .lock()
        .iter_entries()
        .next()
        .unwrap()
        .clone();
    resolver
        .shared()
        .cache
        .lock()
        .restore_entry(keys, resolver.now());
    let answer = signed_answer();
    let key = CacheKey::plain(answer.name.clone(), RrType::A, RrClass::IN);
    for observation in 0..40 {
        let mut answer = answer.clone();
        answer.ttl = 60;
        resolver.shared().cache.lock().insert_positive(
            &key,
            answer,
            resolver.now() - 70_000_000_000 - (39 - observation) * 60_000_000_000,
            ScoreInputs::default(),
            true,
        );
    }
    assert_eq!(
        resolver.resolve(&key.name, RrType::A).unwrap_err().kind,
        recurse_x::ErrorKind::Dnssec
    );
    assert_eq!(resolver.stats_snapshot().served_stale, 0);
    assert_eq!(resolver.shared().cache.lock().stats().stale_served, 0);
}

#[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
#[test]
fn invalid_forwarded_answer_is_never_admitted_to_cache() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(20)))
        .unwrap();
    let address = socket.local_addr().unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = std::thread::spawn(move || {
        while !server_stop.load(std::sync::atomic::Ordering::Relaxed) {
            let mut bytes = [0; 4096];
            let Ok((length, peer)) = socket.recv_from(&mut bytes) else {
                continue;
            };
            let query = recurse_x::Message::parse(&bytes[..length]).unwrap();
            let mut response = recurse_x::Message::new(query.id);
            response.flags.qr = true;
            response.questions = query.questions;
            let answer = signed_answer();
            response.answers = answer.records;
            response.answers.extend(answer.rrsigs);
            socket.send_to(&response.to_bytes().unwrap(), peer).unwrap();
        }
    });
    let mut config = resolver().config().clone();
    config.engine.query_budget_ms = 1000;
    config.engine.timeout_ms = 500;
    config.dns.upstreams.default = vec![recurse_x::forward::Forwarder::plain(
        recurse_x::upstream::Endpoint::new(
            address.ip(),
            address.port(),
            recurse_x::upstream::Proto::Udp,
        ),
    )];
    let forwarding = Resolver::new(config);
    let owner = Name::from_ascii("example.test").unwrap();
    let seed = resolver();
    let keys = seed
        .shared()
        .cache
        .lock()
        .iter_entries()
        .find(|entry| entry.key.name == owner)
        .unwrap()
        .rrset()
        .unwrap()
        .clone();
    forwarding.shared().cache.lock().insert_positive(
        &CacheKey::plain(owner, RrType::DNSKEY, RrClass::IN),
        keys,
        forwarding.now(),
        ScoreInputs::default(),
        false,
    );
    let key = CacheKey::plain(
        Name::from_ascii("bad.example.test").unwrap(),
        RrType::A,
        RrClass::IN,
    );
    for _ in 0..2 {
        assert_eq!(
            forwarding.resolve(&key.name, RrType::A).unwrap_err().kind,
            recurse_x::ErrorKind::Dnssec
        );
        assert!(matches!(
            forwarding
                .shared()
                .cache
                .lock()
                .lookup(&key, forwarding.now()),
            LookupOutcome::Miss
        ));
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    server.join().unwrap();
}
