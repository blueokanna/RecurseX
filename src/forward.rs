//! Forwarding mode: resolve through configured upstreams (UDP/TCP/DoT/
//! DoH/DoH3/DoQ) with RD=1, instead of iterating from the root.
//!
//! This is the "upstream transport" layer of the architecture: the same
//! `ForwarderSet` serves forwarding deployments and can be extended to
//! query authoritative servers over encrypted transports.

use crate::sync::Mutex;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Error, ErrorKind, Result};
use crate::message::Message;
use crate::prng::SplitMix64;
use crate::qtype::Rcode;
use crate::query::response_matches_query;
use crate::transport::{DnsTransport, Transports};
use crate::upstream::{Endpoint, Proto};

/// A forwarding upstream.
#[derive(Clone, Debug)]
pub struct Forwarder {
    /// The upstream endpoint.
    pub endpoint: Endpoint,
    /// TLS server name for DoT / DoH / DoH3 / DoQ (SNI + verification).
    pub host: Option<String>,
    /// The DoH URI path; `None` means the RFC 8484 default, `/dns-query`.
    pub path: Option<String>,
}

impl Forwarder {
    /// A plain UDP/TCP forwarder.
    pub fn plain(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            host: None,
            path: None,
        }
    }

    /// An encrypted forwarder with its TLS identity.
    pub fn encrypted(endpoint: Endpoint, host: impl Into<String>) -> Self {
        Self {
            endpoint,
            host: Some(host.into()),
            path: None,
        }
    }

    /// Use a non-default DoH URI path.
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// The DoH path actually used on the wire.
    pub fn doh_path(&self) -> &str {
        self.path.as_deref().unwrap_or("/dns-query")
    }
}

/// The identity a pooled encrypted transport is built for.
///
/// Not the endpoint alone. The TLS name and the DoH path are part of *what a
/// transport is*: two forwarders that share an address but differ in SNI or
/// path must not share a connection, or one of them presents the other's TLS
/// identity. That configuration is not exotic — it is what
/// `nameserver-policy` produces when two node domains resolve to the same
/// host over different SNI names.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct TransportKey {
    endpoint: Endpoint,
    host: Option<String>,
    path: Option<String>,
}

impl TransportKey {
    /// The key for one forwarder, with `path` normalized so an explicit
    /// `/dns-query` and an omitted path share one pooled transport instead of
    /// building two identical ones.
    fn of(f: &Forwarder) -> Self {
        let path = match f.path.as_deref() {
            None | Some("/dns-query") => None,
            Some(p) => Some(p.to_string()),
        };
        Self {
            endpoint: f.endpoint,
            host: f.host.clone(),
            path,
        }
    }
}

/// The set of forwarding upstreams with cached per-endpoint transports.
pub struct ForwarderSet {
    forwarders: Vec<Forwarder>,
    #[cfg(feature = "dot")]
    dot: Mutex<BTreeMap<TransportKey, crate::transports::dot::DotTransport>>,
    #[cfg(feature = "doh")]
    doh: Mutex<BTreeMap<TransportKey, crate::transports::doh::DohTransport>>,
    #[cfg(feature = "doh3")]
    doh3: Mutex<BTreeMap<TransportKey, crate::transports::doh3::Doh3Transport>>,
    #[cfg(feature = "doq")]
    doq: Mutex<BTreeMap<TransportKey, crate::transports::doq::DoqTransport>>,
    plain: Transports,
    roots: courierust::courierust_tls::RootStore,
    verify: bool,
    now: i64,
}

/// Which upstreams are configured and whether certificates are verified;
/// the pooled transports are not touched (`Debug` must not block).
impl core::fmt::Debug for ForwarderSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ForwarderSet(forwarders={}, verify={}, roots={})",
            self.forwarders.len(),
            self.verify,
            self.roots.len()
        )
    }
}

impl ForwarderSet {
    /// An empty set.
    pub fn new(roots: courierust::courierust_tls::RootStore, verify: bool, now: i64) -> Self {
        Self {
            forwarders: Vec::new(),
            #[cfg(feature = "dot")]
            dot: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "doh")]
            doh: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "doh3")]
            doh3: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "doq")]
            doq: Mutex::new(BTreeMap::new()),
            plain: Transports::new(),
            roots,
            verify,
            now,
        }
    }

    /// The configured forwarders.
    pub fn forwarders(&self) -> &[Forwarder] {
        &self.forwarders
    }

    /// Add a forwarder.
    ///
    /// A server already present — same address, TLS name and path — is
    /// ignored, so the same upstream may be declared in several groups
    /// without being dialled once per group it appears in.
    pub fn add(&mut self, f: Forwarder) {
        let key = TransportKey::of(&f);
        if self.forwarders.iter().any(|e| TransportKey::of(e) == key) {
            return;
        }
        self.forwarders.push(f);
    }

    /// Whether any forwarders are configured.
    pub fn is_enabled(&self) -> bool {
        !self.forwarders.is_empty()
    }

    /// Send a query to the forwarders until one answers, validating the
    /// response against the query (ID + question echo).
    pub fn exchange(
        &self,
        query: &Message,
        query_bytes: &[u8],
        timeout_ms: u64,
    ) -> Result<Message> {
        self.exchange_with(&self.forwarders, query, query_bytes, timeout_ms)
    }

    /// Send a query to `group` until one of its servers *answers*.
    ///
    /// The pool is shared across groups: a server that appears in two groups
    /// keeps one transport, because the transport is a property of the
    /// (address, TLS name, path) triple and not of the group that named it.
    /// Which group a query *uses* is the caller's decision; this only tries
    /// the servers it is handed, in order.
    ///
    /// A response carrying a server-side failure code (SERVFAIL, REFUSED,
    /// FORMERR, NOTIMP, NOTAUTH, NOTZONE) is a statement about *that server*,
    /// not about the name: the next server in the group is asked instead. A
    /// subscription commonly names several public resolvers, and a resolver
    /// that refuses or fails this network (or this name) must not be able to
    /// veto the ones behind it — that is exactly how a query ends up
    /// "resolved" to nothing while six working servers sit unused.
    ///
    /// When every server in the group either failed at the transport level or
    /// answered a failure code, the error is the *last* failure observed, so
    /// the caller logs a reason ("SERVFAIL from 119.29.29.29") instead of a
    /// bare "no address".
    pub fn exchange_with(
        &self,
        group: &[Forwarder],
        query: &Message,
        query_bytes: &[u8],
        timeout_ms: u64,
    ) -> Result<Message> {
        let mut last_err: Option<Error> = None;
        for f in group {
            let resp_bytes = match self.exchange_one(f, query_bytes, timeout_ms) {
                Ok(b) => b,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            let resp = match Message::parse(&resp_bytes) {
                Ok(m) => m,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            if !response_matches_query(query, &resp) {
                last_err = Some(Error::transport("forwarder response did not match query"));
                continue;
            }
            let rcode = resp.rcode();
            if rcode <= u16::from(u8::MAX) && Rcode(rcode as u8).is_failure() {
                let code = Rcode(rcode as u8);
                last_err = Some(Error::new(
                    if code == Rcode::REFUSED {
                        ErrorKind::Refused
                    } else {
                        ErrorKind::Servfail
                    },
                    format!("the upstream {} answered {code}", f.endpoint.ip),
                ));
                continue;
            }
            return Ok(resp);
        }
        Err(last_err.unwrap_or_else(|| Error::new(ErrorKind::NoUpstream, "no forwarder answered")))
    }

    fn exchange_one(&self, f: &Forwarder, query: &[u8], timeout_ms: u64) -> Result<Vec<u8>> {
        let key = TransportKey::of(f);
        match f.endpoint.proto {
            Proto::Udp | Proto::Tcp => self.plain.exchange(&f.endpoint, query, timeout_ms),
            #[cfg(feature = "dot")]
            Proto::Tls => {
                let mut cache = self.dot.lock();
                let t = cache.entry(key).or_insert_with(|| {
                    let host = f.host.clone().unwrap_or_else(|| f.endpoint.ip.to_string());
                    crate::transports::dot::DotTransport::for_host(
                        host,
                        self.roots.clone(),
                        self.verify,
                        self.now,
                    )
                });
                t.exchange(query, &f.endpoint, timeout_ms)
            }
            #[cfg(feature = "doh")]
            Proto::DoH => {
                let mut cache = self.doh.lock();
                let t = cache.entry(key).or_insert_with(|| {
                    let host = f.host.clone().unwrap_or_else(|| f.endpoint.ip.to_string());
                    let mut t = crate::transports::doh::DohTransport::for_host(
                        host,
                        self.roots.clone(),
                        self.verify,
                        self.now,
                    );
                    t.path = f.doh_path().to_string();
                    t
                });
                t.exchange(query, &f.endpoint, timeout_ms)
            }
            #[cfg(feature = "doh3")]
            Proto::DoH3 => {
                let mut cache = self.doh3.lock();
                let t = cache.entry(key).or_insert_with(|| {
                    let host = f.host.clone().unwrap_or_else(|| f.endpoint.ip.to_string());
                    crate::transports::doh3::Doh3Transport::for_host(
                        host,
                        self.roots.clone(),
                        self.verify,
                        self.now,
                    )
                });
                t.exchange(query, &f.endpoint, timeout_ms)
            }
            #[cfg(feature = "doq")]
            Proto::DoQ => {
                let mut cache = self.doq.lock();
                let t = cache.entry(key).or_insert_with(|| {
                    let host = f.host.clone().unwrap_or_else(|| f.endpoint.ip.to_string());
                    crate::transports::doq::DoqTransport::for_host(
                        host,
                        self.roots.clone(),
                        self.verify,
                        self.now,
                    )
                });
                t.exchange(query, &f.endpoint, timeout_ms)
            }
            #[cfg(not(feature = "dot"))]
            Proto::Tls => Err(Error::new(
                ErrorKind::Unsupported,
                "DoT forwarder not compiled in (enable `dot`)",
            )),
            #[cfg(not(feature = "doh"))]
            Proto::DoH => Err(Error::new(
                ErrorKind::Unsupported,
                "DoH forwarder not compiled in (enable `doh`)",
            )),
            #[cfg(not(feature = "doh3"))]
            Proto::DoH3 => Err(Error::new(
                ErrorKind::Unsupported,
                "DoH3 forwarder not compiled in (enable `doh3`)",
            )),
            #[cfg(not(feature = "doq"))]
            Proto::DoQ => Err(Error::new(
                ErrorKind::Unsupported,
                "DoQ forwarder not compiled in (enable `doq`)",
            )),
        }
    }
}

/// Build a query message for a forwarder (RD=1, EDNS as requested).
///
/// Returns the message itself; the caller serializes it once. Building it by
/// serializing and re-parsing would be lossy in exactly the way that matters
/// here — the question echo used for response validation must be the same
/// message that goes on the wire.
pub fn build_forward_query(
    key: &crate::query::QueryKey,
    edns_udp_size: u16,
    dnssec: bool,
    rng: &mut SplitMix64,
) -> Message {
    let mut m = Message::new((rng.next_u32() & 0xffff) as u16);
    m.flags.rd = true;
    m.questions.push(crate::message::Question {
        qname: key.name.clone(),
        qtype: key.rr_type,
        qclass: key.class,
    });
    m.edns = Some(
        crate::engine::EdnsSpec {
            udp_size: edns_udp_size,
            dnssec_ok: dnssec || key.want_dnssec,
            ecs: crate::query::ecs_option(key),
            client_cookie: None,
        }
        .to_edns(),
    );
    m
}

/// Convert a forwarder response into a [`crate::resolver::Resolution`].
pub fn response_to_resolution(
    key: &crate::query::QueryKey,
    resp: &Message,
) -> crate::resolver::Resolution {
    let mut ttl = u32::MAX;
    let mut answers = Vec::new();
    let mut rrsigs = Vec::new();
    for r in &resp.answers {
        ttl = ttl.min(r.ttl);
        if r.rr_type == crate::qtype::RrType::RRSIG {
            rrsigs.push(r.clone());
        } else {
            answers.push(r.clone());
        }
    }
    if ttl == u32::MAX {
        ttl = 0;
    }

    let rcode = u8::try_from(resp.rcode())
        .map(crate::qtype::Rcode)
        .unwrap_or(crate::qtype::Rcode::SERVFAIL);
    crate::resolver::Resolution {
        name: key.name.clone(),
        rr_type: key.rr_type,
        class: key.class,
        rcode,
        answers,
        authorities: resp.authorities.clone(),
        rrsigs,
        validated: false,
        ttl,
        from_cache: false,
        stale: false,
        served_at: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Question;
    use crate::name::Name;
    use crate::qtype::{RrClass, RrType};
    use crate::rdata::{RData, Record};
    use std::net::Ipv4Addr;
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn forwarder_defaults() {
        let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), false, 0);
        assert!(!set.is_enabled());
        let mut set = set;
        set.add(Forwarder::plain(Endpoint::udp("1.1.1.1".parse().unwrap())));
        assert!(set.is_enabled());
        assert_eq!(set.forwarders().len(), 1);
    }

    /// A loopback upstream that replies to every query with `build`.
    ///
    /// Returns its port and the number of queries it saw, so a test can assert
    /// that a server was *not* asked. The thread parks in `recv_from` with a
    /// read timeout, so a test that finishes early simply detaches it.
    fn spawn_upstream(
        build: impl Fn(&Message) -> Message + Send + 'static,
    ) -> (u16, Arc<AtomicUsize>) {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind a loopback UDP socket");
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("a read timeout, so the thread cannot outlive the test forever");
        let port = socket.local_addr().expect("bound address").port();
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buf) {
                let Ok(query) = Message::parse(&buf[..len]) else {
                    continue;
                };
                counter.fetch_add(1, Ordering::Relaxed);
                if let Ok(bytes) = build(&query).to_bytes() {
                    let _ = socket.send_to(&bytes, peer);
                }
            }
        });
        (port, seen)
    }

    /// A response with the query's id and question, and nothing else.
    fn response_for(query: &Message, rcode: Rcode) -> Message {
        let mut response = Message::new(query.id);
        response.flags.qr = true;
        response.flags.rd = query.flags.rd;
        response.flags.ra = true;
        response.flags.rcode = rcode;
        response.questions = query.questions.clone();
        response
    }

    fn answer_for(query: &Message, address: Ipv4Addr) -> Message {
        let mut response = response_for(query, Rcode::NOERROR);
        let question = query.question().expect("the query carries a question");
        response.answers.push(Record {
            name: question.qname.clone(),
            rr_type: RrType::A,
            class: RrClass::IN,
            ttl: 60,
            rdata: RData::A(address),
        });
        response
    }

    fn query_for(name: &str) -> (Message, Vec<u8>) {
        let mut query = Message::new(0x4242);
        query.flags.rd = true;
        query.questions.push(Question {
            qname: Name::from_ascii(name).expect("a valid name"),
            qtype: RrType::A,
            qclass: RrClass::IN,
        });
        let bytes = query.to_bytes().expect("the query serializes");
        (query, bytes)
    }

    fn plain(port: u16) -> Forwarder {
        Forwarder::plain(Endpoint::new(
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Proto::Udp,
        ))
    }

    /// The regression this fixes: the first upstream that *answered* used to
    /// end the loop regardless of what it said, so one refusing server vetoed
    /// every server behind it and the name resolved to nothing.
    #[test]
    fn a_refusing_upstream_does_not_veto_the_others() {
        let (refuser, _) = spawn_upstream(|query| response_for(query, Rcode::REFUSED));
        let (worker, _) = spawn_upstream(|query| answer_for(query, Ipv4Addr::new(203, 0, 113, 7)));
        let group = [plain(refuser), plain(worker)];
        let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), false, 0);
        let (query, bytes) = query_for("node.example.com");

        let resp = set
            .exchange_with(&group, &query, &bytes, 2_000)
            .expect("the working upstream answers");
        assert_eq!(resp.answers.len(), 1);
        assert!(matches!(resp.answers[0].rdata, RData::A(a) if a == Ipv4Addr::new(203, 0, 113, 7)));
    }

    /// The same rule for SERVFAIL, which is what a resolver answers when its
    /// own recursion is broken: still a statement about the server.
    #[test]
    fn a_failing_upstream_does_not_veto_the_others() {
        let (failing, _) = spawn_upstream(|query| response_for(query, Rcode::SERVFAIL));
        let (worker, _) = spawn_upstream(|query| answer_for(query, Ipv4Addr::new(203, 0, 113, 8)));
        let group = [plain(failing), plain(worker)];
        let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), false, 0);
        let (query, bytes) = query_for("node.example.com");

        let resp = set
            .exchange_with(&group, &query, &bytes, 2_000)
            .expect("the working upstream answers");
        assert_eq!(resp.answers.len(), 1);
    }

    /// NXDOMAIN is an answer *about the name*, so it is final: the servers
    /// behind the one that answered do not get asked.
    #[test]
    fn nxdomain_is_a_final_answer() {
        let (denier, _) = spawn_upstream(|query| response_for(query, Rcode::NXDOMAIN));
        let (behind, behind_seen) =
            spawn_upstream(|query| answer_for(query, Ipv4Addr::new(203, 0, 113, 9)));
        let group = [plain(denier), plain(behind)];
        let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), false, 0);
        let (query, bytes) = query_for("node.example.com");

        let resp = set
            .exchange_with(&group, &query, &bytes, 2_000)
            .expect("NXDOMAIN is a valid answer");
        assert_eq!(resp.rcode(), u16::from(Rcode::NXDOMAIN.to_u8()));
        assert_eq!(
            behind_seen.load(Ordering::Relaxed),
            0,
            "the server behind a final answer must not be asked"
        );
    }

    /// When every upstream fails, the caller gets an error that names the last
    /// failure instead of a silent empty answer.
    #[test]
    fn all_upstreams_failing_surfaces_the_failure_code() {
        let (first, _) = spawn_upstream(|query| response_for(query, Rcode::SERVFAIL));
        let (second, _) = spawn_upstream(|query| response_for(query, Rcode::REFUSED));
        let group = [plain(first), plain(second)];
        let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), false, 0);
        let (query, bytes) = query_for("node.example.com");

        let error = set
            .exchange_with(&group, &query, &bytes, 2_000)
            .expect_err("no upstream produced an answer");
        assert_eq!(error.kind(), ErrorKind::Refused);
        assert!(
            error.msg.contains("REFUSED"),
            "the message must name the code: {}",
            error.msg
        );
    }
}
