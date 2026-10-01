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
    /// Refer every query to a child zone that names twelve name servers and
    /// glues **none** of them. That is the NXNSAttack shape (Shafir et al.,
    /// USENIX Security 2020): cheap to enter, expensive to finish, because
    /// each unglued name obliges an independent address resolution. A
    /// resolver that only bounds *depth* walks straight into it.
    NxnsReferral,
    /// Serve the delegation chain and answer `www.example.test` with an
    /// ECS option whose SCOPE PREFIX-LENGTH is 24, i.e. "this answer is valid
    /// for the whole /24 you asked from".
    EcsScoped,
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
                    Behaviour::NxnsReferral => {
                        unglued_referral(&mut resp, &question.qname.to_ascii(), UNGLUED_NS_COUNT);
                    }
                    Behaviour::EcsScoped => {
                        delegate(&mut resp, &question.qname, addr.port());
                        echo_ecs_scope(&mut resp, &query, ECS_SCOPE);
                    }
                }

                if let Ok(bytes) = resp.to_bytes() {
                    let _ = sock.send_to(&bytes, src);
                }
            }
        });
        Stub {
            addr,
            seen,
            asked,
            stop,
        }
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

/// How many name servers the NXNS stub publishes without glue.
const UNGLUED_NS_COUNT: usize = 12;

/// The SCOPE PREFIX-LENGTH the ECS stub declares on its answers.
const ECS_SCOPE: u8 = 24;

/// A referral to `zone` that names `count` name servers and glues none of
/// them — the NXNSAttack shape. The zone is a child of whatever was asked, so
/// the walk accepts it as a delegation before the gate sees it.
fn unglued_referral(resp: &mut Message, qname: &str, count: usize) {
    let class = RrClass::IN;
    let ttl = 60;
    let zone = format!("nxns.{qname}");
    let zone_name = Name::from_ascii(&zone).unwrap();
    debug_assert!(count > 2, "the gate's escape hatch is for small referrals");
    for i in 0..count {
        resp.authorities.push(Record {
            name: zone_name.clone(),
            rr_type: RrType::NS,
            class,
            ttl,
            rdata: RData::Ns(Name::from_ascii(&format!("ns{i}.evil.test")).unwrap()),
        });
    }
    // No `additionals` at all: that absence is the attack.
}

/// Add an EDNS Client Subnet option to a response, echoing the request's
/// address but declaring a scope — i.e. "valid for this whole network".
fn echo_ecs_scope(resp: &mut Message, query: &Message, scope: u8) {
    let Some(asked) = query.edns.as_ref().and_then(|e| e.ecs()) else {
        return;
    };
    let echo = recurse_x::edns::Ecs {
        family: asked.family,
        source_prefix: asked.source_prefix,
        scope_prefix: scope,
        address: asked.address.clone(),
    };
    let mut edns = recurse_x::edns::Edns::new(1232);
    edns.options.push(recurse_x::edns::EdnsOption::Ecs(echo));
    edns.dnssec_ok = query.edns.as_ref().map(|e| e.dnssec_ok).unwrap_or(false);
    resp.edns = Some(edns);
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
    assert!(
        second.from_cache,
        "the negative answer must come from cache"
    );
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

/// A referral that names many name servers and glues none of them must be
/// refused **before** any address lookup is attempted.
///
/// The assertion that matters is the query count, not the error: a resolver
/// that bounds only *depth* answers this referral with twelve independent
/// resolutions, each of which could itself be referral-shaped. The gate has to
/// reject the referral itself, so the work stays at the handful of packets the
/// walk has already spent.
#[test]
fn an_unglued_referral_is_refused_before_any_address_lookup() {
    let stub = Stub::start(Behaviour::NxnsReferral);
    let err = resolve(config(stub.addr), "www.nxns.test")
        .expect_err("a delegation with no glue and twelve servers is not usable");

    assert_eq!(err.kind, ErrorKind::Transport, "got {err:?}");
    assert!(
        err.msg.contains("unusable delegation"),
        "the error must name the cause, got {}",
        err.msg
    );
    // The root query plus the referral that carried it: nothing else may have
    // been asked, and in particular no `ns*.evil.test` address lookups.
    assert!(
        stub.queries_seen() <= 4,
        "the gate must stop the fan-out; saw {} queries",
        stub.queries_seen()
    );
    for asked in stub.names_asked() {
        assert!(
            !asked.contains("evil.test"),
            "the resolver chased {asked}, which is exactly the NXNS fan-out"
        );
    }
}

/// RFC 7871: an answer is filed under the **scope the server declared**, not
/// under the prefix the client happened to ask with — and a client that sent
/// no ECS must never be handed a subnet-scoped answer.
///
/// This is the end-to-end form of the cache-level rule, and the query count is
/// the proof: a client inside the declared `/24` must be served with *zero*
/// further upstream queries, while a client outside it (or one with no ECS at
/// all) must go and ask.
#[test]
fn ecs_scope_controls_who_may_reuse_an_answer() {
    use recurse_x::edns::{Ecs, Edns, EdnsOption};

    let stub = Stub::start(Behaviour::EcsScoped);
    let r = Resolver::new(config(stub.addr));

    let ask = |ip: &str, prefix: u8| {
        let mut msg = Message::query(
            0x2200,
            Name::from_ascii("www.example.test").unwrap(),
            RrType::A,
            true,
        );
        let mut edns = Edns::new(1232);
        edns.options.push(EdnsOption::Ecs(
            Ecs::ipv4(ip.parse().unwrap(), prefix).unwrap(),
        ));
        msg.edns = Some(edns);
        r.handle_query(&msg, None)
    };

    // First client: 10.0.0.0/24. The server declares the answer valid for that
    // whole /24, so it is filed in the /24 partition.
    let first = ask("10.0.0.1", 24);
    assert_eq!(first.flags.rcode, Rcode::NOERROR);
    let after_first = stub.queries_seen();
    assert!(after_first >= 3, "the walk must have happened");

    // A client inside the declared scope, at a *different* granularity: served
    // entirely from cache. Nothing new goes upstream.
    let inside = ask("10.0.0.200", 25);
    assert_eq!(inside.flags.rcode, Rcode::NOERROR);
    assert_eq!(
        stub.queries_seen(),
        after_first,
        "a client inside the declared /24 must reuse the answer"
    );

    // A client outside the scope: a different /24 is a different network, so
    // it has to resolve for itself.
    let outside = ask("10.9.9.1", 24);
    assert_eq!(outside.flags.rcode, Rcode::NOERROR);
    let after_outside = stub.queries_seen();
    assert!(
        after_outside > after_first,
        "a different subnet must not reuse a subnet-scoped answer"
    );

    // A client with no ECS at all must not be handed the scoped answer either.
    // It still gets an answer — it simply has to ask for it.
    let mut plain = Message::query(
        0x2201,
        Name::from_ascii("www.example.test").unwrap(),
        RrType::A,
        true,
    );
    plain.edns = Some(Edns::new(1232));
    let unscoped = r.handle_query(&plain, None);
    assert_eq!(unscoped.flags.rcode, Rcode::NOERROR);
    assert!(
        stub.queries_seen() > after_outside,
        "a client without ECS must not read an ECS partition"
    );
}
