//! Hermetic tests for the *iterative* path — the delegation walk.
//!
//! `end_to_end.rs` drives the resolver through a configured forwarder and a
//! stub *root*, which covers the transports, the cache and the CNAME chase but
//! never a referral. The referral walk is where the interesting failures live:
//! a chain that does not converge, a server that answers with nothing, a name
//! in a zone that does not exist. None of that can be tested against the public
//! Internet, because the Internet is not a fixture — this project's own
//! development machine measured 26 timeouts out of 45 upstream queries and an
//! interceptor that answers UDP/53 with empty replies in 8 ms. A test that
//! passes here and fails there measures the network, not the code.
//!
//! So the stub in this file is the root *and* every child zone at once, on a
//! single loopback port. `engine.authPort` is what makes that possible: without
//! it, the next hop of a referral would always be `ip:53`, and standing up a
//! fake delegation would need a privileged port that CI does not have.
//!
//! Every test here is deterministic: no real network, no sleeps waiting for the
//! Internet, and the stub's replies are chosen by the query name it receives.

#![cfg(feature = "std")]

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use recurse_x::error::ErrorKind;
use recurse_x::qtype::{Rcode, RrClass};
use recurse_x::rdata::{RData, Record};
use recurse_x::{Message, Name, Resolver, ResolverConfig, RrType};

/// The A record the delegation chain ends at.
const ANSWER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

/// How the stub behind the root address behaves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Behaviour {
    /// Serve a real two-level delegation: the root refers to `test.`, `test.`
    /// refers to `example.test.`, and `example.test.` answers for
    /// `www.example.test`. The glue is the loopback address the stub itself is
    /// bound to, so the walk comes back to this same stub one zone deeper.
    Delegate,
    /// Answer everything NXDOMAIN.
    Nxdomain,
    /// Refuse the first query and behave afterwards. The refusal is what a
    /// recursive resolver must not mistake for an answer: it carries no
    /// authority section, so it classifies as `Empty`, and treating it as an
    /// answer ends the walk at the first server asked.
    RefuseOnce,
    /// Answer the first query with a completely empty NOERROR response — no
    /// answer, no authority, no additional — and behave afterwards. That is
    /// what an intercepting resolver sends, and RFC 2308 §2.2 forbids it for a
    /// real negative answer (which must carry the SOA).
    EmptyOnce,
}

/// A stub that answers UDP DNS on loopback. It records every query name it was
/// asked, which is how a test proves *which* walk happened rather than only
/// that something came back.
struct Stub {
    addr: SocketAddr,
    seen: Arc<AtomicUsize>,
    asked: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl Stub {
    fn start(behaviour: Behaviour) -> Stub {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind stub");
        let addr = sock.local_addr().expect("stub addr");
        let seen = Arc::new(AtomicUsize::new(0));
        let asked = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let counters = seen.clone();
        let log = asked.clone();
        let flag = stop.clone();
        sock.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("stub timeout");
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while !flag.load(Ordering::Relaxed) {
                let Ok((n, src)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                let count = counters.fetch_add(1, Ordering::Relaxed);
                let Ok(query) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let Some(question) = query.question() else {
                    continue;
                };
                if let Ok(mut names) = log.lock() {
                    names.push(question.qname.to_ascii());
                }
                let mut resp = Message::new(query.id);
                resp.flags.qr = true;
                resp.flags.aa = true;
                resp.flags.ra = true;
                resp.flags.rd = query.flags.rd;
                resp.questions.clone_from(&query.questions);

                let first = count == 0;
                match behaviour {
                    Behaviour::Nxdomain => {
                        resp.flags.rcode = Rcode::NXDOMAIN;
                        // A real negative answer carries the SOA (RFC 2308
                        // §2.2), and it has to: the SOA is where the negative
                        // TTL comes from. Without one there is no TTL to cache
                        // under, so refusing to cache is correct — which is why
                        // this stub sends it rather than omitting it.
                        resp.authorities.push(soa("invalid"));
                    }
                    Behaviour::RefuseOnce if first => resp.flags.rcode = Rcode::REFUSED,
                    Behaviour::EmptyOnce if first => {
                        // Nothing in any section, rcode NOERROR: the shape a
                        // broken or intercepting upstream sends.
                    }
                    Behaviour::Delegate | Behaviour::RefuseOnce | Behaviour::EmptyOnce => {
                        delegate(&mut resp, &question.qname, addr.port());
                    }
                }

                if let Ok(bytes) = resp.to_bytes() {
                    let _ = sock.send_to(&bytes, src);
                }
            }
        });
        Stub { addr, seen, asked, stop }
    }

    /// A stub that receives and **discards**: queries are never answered, and
    /// because the socket reads them the kernel has no reason to send ICMP port
    /// unreachable, so each attempt ends in a clean read timeout. That is what
    /// makes `dead_walk` measure the budget rather than the operating system's
    /// error reporting.
    fn black_hole() -> Stub {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind black hole");
        let addr = sock.local_addr().expect("black hole addr");
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        sock.set_read_timeout(Some(Duration::from_millis(50)))
            .expect("black hole timeout");
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while !flag.load(Ordering::Relaxed) {
                // Read and drop: no reply, ever.
                let _ = sock.recv_from(&mut buf);
            }
        });
        Stub {
            addr,
            seen: Arc::new(AtomicUsize::new(0)),
            asked: Arc::new(Mutex::new(Vec::new())),
            stop,
        }
    }

    fn queries_seen(&self) -> usize {
        self.seen.load(Ordering::Relaxed)
    }

    fn names_asked(&self) -> Vec<String> {
        self.asked.lock().map(|n| n.clone()).unwrap_or_default()
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Build the reply for one query of the delegation chain.
fn delegate(resp: &mut Message, qname: &Name, port: u16) {
    let class = RrClass::IN;
    let ttl = 60;
    match qname.to_ascii().as_str() {
        "www.example.test" => resp.answers.push(Record {
            name: qname.clone(),
            rr_type: RrType::A,
            class,
            ttl,
            rdata: RData::A(ANSWER_IP),
        }),
        // Root refers to the TLD.
        "test" => referral(resp, "test", "ns.test", port),
        // The TLD refers one label deeper.
        "example.test" => referral(resp, "example.test", "ns.example.test", port),
        // A well-formed resolver must never ask anything else in this test.
        _ => resp.flags.rcode = Rcode::REFUSED,
    }
}

/// The SOA of a zone, for the authority section of a negative answer.
fn soa(zone: &str) -> Record {
    Record {
        name: Name::from_ascii(zone).unwrap(),
        rr_type: RrType::SOA,
        class: RrClass::IN,
        ttl: 300,
        rdata: RData::Soa {
            mname: Name::from_ascii(zone).unwrap(),
            rname: Name::from_ascii(zone).unwrap(),
            serial: 1,
            refresh: 3_600,
            retry: 600,
            expire: 604_800,
            minimum: 60,
        },
    }
}

/// A referral: the child's NS in the authority section and its address in the
/// additional section, which is what makes the next hop known without a second
/// lookup. The port is the stub's own, reached through `engine.authPort`.
fn referral(resp: &mut Message, zone: &str, ns_name: &str, port: u16) {
    let class = RrClass::IN;
    let ttl = 60;
    let ns = Name::from_ascii(ns_name).unwrap();
    resp.authorities.push(Record {
        name: Name::from_ascii(zone).unwrap(),
        rr_type: RrType::NS,
        class,
        ttl,
        rdata: RData::Ns(ns.clone()),
    });
    resp.additionals.push(Record {
        name: ns,
        rr_type: RrType::A,
        class,
        ttl,
        rdata: RData::A(Ipv4Addr::LOCALHOST),
    });
    // The port has to travel in the glue for the stub to be the next hop, and
    // A records carry no port — so the config does it. Asserted here so the
    // dependency is explicit rather than surprising.
    assert_ne!(port, 0);
}

fn config(root: SocketAddr) -> ResolverConfig {
    let mut cfg = ResolverConfig::default();
    cfg.engine.root_servers = vec![root];
    cfg.engine.auth_port = root.port();
    // A short timeout keeps the tests quick; the budget is what bounds the
    // walk, and it is set per test.
    cfg.engine.timeout_ms = 400;
    cfg
}

fn resolve(cfg: ResolverConfig, name: &str) -> Result<recurse_x::Resolution, recurse_x::Error> {
    let r = Resolver::new(cfg);
    r.resolve(&Name::from_ascii(name).unwrap(), RrType::A)
}

/// The walk a referral chain describes: root → TLD → authoritative, answering
/// at the end. With minimization on, the chain is the *only* way to get there,
/// so reaching `www.example.test` proves every hop worked.
#[test]
fn a_referral_chain_is_walked_to_the_answer() {
    let stub = Stub::start(Behaviour::Delegate);
    let mut cfg = config(stub.addr);
    cfg.engine.qname_minimization = true;
    let res = resolve(cfg, "www.example.test").expect("the chain must resolve");

    assert_eq!(res.rcode, Rcode::NOERROR);
    assert_eq!(res.answers.len(), 1, "one A record, and nothing invented");
    assert_eq!(res.answers[0].rdata, RData::A(ANSWER_IP));
    assert!(!res.from_cache);

    // The delegation was actually walked, one zone at a time, in order.
    let asked = stub.names_asked();
    assert_eq!(
        asked,
        vec!["test", "example.test", "www.example.test"],
        "minimization must descend the delegation, not jump to the qname"
    );
}

/// The same answer with minimization off: the full name goes to the root
/// address, which answers directly. Both modes must produce the same
/// resolution — a resolver whose answer depends on a query-shaping option is a
/// resolver with a bug.
#[test]
fn minimization_changes_the_queries_but_not_the_answer() {
    let stub = Stub::start(Behaviour::Delegate);
    let mut cfg = config(stub.addr);
    cfg.engine.qname_minimization = false;
    let res = resolve(cfg, "www.example.test").expect("must resolve");

    assert_eq!(res.rcode, Rcode::NOERROR);
    assert_eq!(res.answers.len(), 1);
    assert_eq!(res.answers[0].rdata, RData::A(ANSWER_IP));
    assert_eq!(
        stub.names_asked(),
        vec!["www.example.test"],
        "without minimization the qname goes straight out"
    );
}

/// A name inside a zone that does not exist is an **answer** (NXDOMAIN), not a
/// failure. This is the shape `nonexistent.invalid` takes in the live example,
/// where it surfaced as `Transport("empty response from upstream")` instead —
/// which is a wrong error for a correct response, and a caller cannot tell them
/// apart.
#[test]
fn an_nxdomain_zone_is_a_negative_answer_not_an_error() {
    let stub = Stub::start(Behaviour::Nxdomain);
    let mut cfg = config(stub.addr);
    cfg.engine.qname_minimization = false;
    let res = resolve(cfg, "nope.invalid").expect("NXDOMAIN is a resolution, not an error");
    assert_eq!(res.rcode, Rcode::NXDOMAIN);
    assert!(res.answers.is_empty());
}

/// The negative answer is cached, so the second query does not reach the
/// upstream. A negative answer that is not cached is a resolver that re-asks
/// the same question for every client.
#[test]
fn an_nxdomain_is_cached_and_not_re_asked() {
    let stub = Stub::start(Behaviour::Nxdomain);
    let mut cfg = config(stub.addr);
    cfg.engine.qname_minimization = false;
    let r = Resolver::new(cfg);
    let name = Name::from_ascii("nope.invalid").unwrap();

    let first = r.resolve(&name, RrType::A).expect("first answer");
    assert_eq!(first.rcode, Rcode::NXDOMAIN);
    let after_first = stub.queries_seen();

    let second = r.resolve(&name, RrType::A).expect("second answer");
    assert_eq!(second.rcode, Rcode::NXDOMAIN);
    assert!(second.from_cache, "the negative answer must come from cache");
    assert_eq!(
        stub.queries_seen(),
        after_first,
        "a cached NXDOMAIN must not reach the upstream"
    );
}

/// A server that refuses has not answered the question. The walk must move on
/// rather than hand the refusal back: a recursive query has no REFUSED answer
/// to pass to a client, and one uncooperative server out of a zone's thirteen
/// must not be able to end the resolution.
#[test]
fn a_refusal_is_retried_rather_than_returned() {
    let stub = Stub::start(Behaviour::RefuseOnce);
    let mut cfg = config(stub.addr);
    cfg.engine.qname_minimization = true;
    let res = resolve(cfg, "www.example.test").expect("the refusal must be retried");

    assert_eq!(res.rcode, Rcode::NOERROR);
    assert_eq!(res.answers[0].rdata, RData::A(ANSWER_IP));
    // The refusal was the first query and the walk then proceeded normally.
    let asked = stub.names_asked();
    assert_eq!(asked.first().map(String::as_str), Some("test"));
    assert!(
        asked.contains(&"www.example.test".to_string()),
        "the walk must continue past the refusal, asked: {asked:?}"
    );
}

/// A NOERROR response with every section empty is not an answer, not a
/// referral, and not a valid negative answer (RFC 2308 §2.2 requires the SOA),
/// so there is nothing in it to give a client. The walk must treat it as "this
/// server did not answer" — otherwise one intercepting resolver ends the whole
/// resolution, which is exactly what happens on a hijacked UDP/53.
#[test]
fn an_empty_answer_is_not_an_answer() {
    let stub = Stub::start(Behaviour::EmptyOnce);
    let mut cfg = config(stub.addr);
    cfg.engine.qname_minimization = true;
    let res = resolve(cfg, "www.example.test").expect("an empty reply must be retried");

    assert_eq!(res.rcode, Rcode::NOERROR);
    assert_eq!(res.answers[0].rdata, RData::A(ANSWER_IP));
    assert!(
        stub.names_asked().len() > 1,
        "the empty reply must have been followed by another query"
    );
}

/// A name whose queries are never answered must end at the deadline, not at the
/// sum of every retry. `timeout_ms` is 400 and the budget is 500, so the walk
/// must come back after roughly one attempt rather than 400 ms × attempts ×
/// servers.
#[test]
fn a_dead_walk_ends_at_the_query_budget() {
    let stub = Stub::black_hole();
    let mut cfg = config(stub.addr);
    cfg.engine.timeout_ms = 400;
    cfg.engine.query_budget_ms = 500;

    let started = Instant::now();
    let err = resolve(cfg, "www.example.test").expect_err("a dead upstream must fail");
    let elapsed = started.elapsed();

    assert_eq!(err.kind, ErrorKind::Timeout, "got {err:?}");
    assert!(
        elapsed < Duration::from_millis(2_500),
        "the budget must bound the walk, took {elapsed:?}"
    );
}

/// Every query the stub sees must be for the name under test, or for one of its
/// ancestors. A resolver that asks about a name it was not asked about is
/// leaking the client's question to third parties — the reason QNAME
/// minimization exists.
#[test]
fn the_walk_never_asks_about_an_unrelated_name() {
    let stub = Stub::start(Behaviour::Delegate);
    let mut cfg = config(stub.addr);
    cfg.engine.qname_minimization = true;
    resolve(cfg, "www.example.test").expect("must resolve");

    let qname = Name::from_ascii("www.example.test").unwrap();
    for asked in stub.names_asked() {
        let candidate = Name::from_ascii(&asked).unwrap();
        assert!(
            qname.is_subdomain_of(&candidate) || candidate == qname,
            "{asked} is neither the qname nor one of its ancestors"
        );
    }
}
