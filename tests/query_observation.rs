#![cfg(feature = "std")]

use recurse_x::{observation, Name, Resolver, ResolverConfig, RrType};

#[test]
fn observations_are_opt_in_bounded_and_include_errors_and_local_answers() {
    let mut config = ResolverConfig::default();
    config.engine.query_budget_ms = 0;
    let resolver = Resolver::new(config);
    let name = Name::from_ascii("observation.test").unwrap();
    assert!(resolver.resolve(&name, RrType::A).is_err());
    assert!(observation::snapshot().events.is_empty());
    observation::configure(2);
    for _ in 0..3 {
        assert!(resolver.resolve(&name, RrType::A).is_err());
    }
    let snapshot = observation::snapshot();
    assert_eq!(snapshot.total, 3);
    assert_eq!(snapshot.events.len(), 2);
    assert_eq!(snapshot.dropped, 0);
    assert!(snapshot.events[0].id < snapshot.events[1].id);
    assert_eq!(snapshot.events[0].outcome, "Timeout");
    assert_eq!(snapshot.events[0].rr_type, "A");
    assert!(!snapshot.events[0].from_cache);
    // An actual wire response followed by a cache hit must keep its provenance.
    observation::configure(2);
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let server = std::thread::spawn(move || {
        let mut bytes = [0; 4096];
        let (size, peer) = socket.recv_from(&mut bytes).unwrap();
        let mut response = recurse_x::Message::parse(&bytes[..size]).unwrap();
        response.flags.qr = true;
        response.flags.aa = true;
        response.answers.push(recurse_x::Record {
            name: response.question().unwrap().qname.clone(),
            rr_type: RrType::A,
            class: recurse_x::RrClass::IN,
            ttl: 60,
            rdata: recurse_x::RData::A("192.0.2.8".parse().unwrap()),
        });
        socket.send_to(&response.to_bytes().unwrap(), peer).unwrap();
    });
    let mut config = ResolverConfig::default();
    config.engine.root_servers = vec![address];
    config.engine.qname_minimization = false;
    let resolver = Resolver::new(config);
    assert!(!resolver.resolve(&name, RrType::A).unwrap().from_cache);
    assert!(resolver.resolve(&name, RrType::A).unwrap().from_cache);
    server.join().unwrap();
    let observed = observation::snapshot();
    assert_eq!(observed.events[0].answers, ["192.0.2.8"]);
    assert_eq!(observed.events[1].answers, ["192.0.2.8"]);
    assert!(!observed.events[0].from_cache);
    assert!(observed.events[1].from_cache);
    assert_eq!(observed.events[1].outcome, "NOERROR");
    observation::configure(0);
    assert!(observation::snapshot().events.is_empty());
    assert_eq!(observation::snapshot().total, 0);
}
