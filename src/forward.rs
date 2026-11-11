//! Forwarding mode: resolve through configured upstreams (UDP/TCP/DoT/
//! DoH/DoH3/DoQ) with RD=1, instead of iterating from the root.
//!
//! This is the "upstream transport" layer of the architecture: the same
//! `ForwarderSet` serves forwarding deployments and can be extended to
//! query authoritative servers over encrypted transports.

use crate::sync::Mutex;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::error::{Error, ErrorKind, Result};
use crate::message::Message;
use crate::prng::RandomSource;
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
    /// Validate transport availability and identity before enabling an upstream.
    pub fn validate(&self) -> Result<()> {
        let available = match self.endpoint.proto {
            Proto::Udp | Proto::Tcp => true,
            Proto::Tls => cfg!(feature = "dot"),
            Proto::DoH => cfg!(feature = "doh"),
            Proto::DoH3 => cfg!(feature = "doh3"),
            Proto::DoQ => cfg!(feature = "doq"),
        };
        if !available {
            return Err(Error::config(
                "upstream transport is not enabled in this build",
            ));
        }
        if !matches!(self.endpoint.proto, Proto::Udp | Proto::Tcp)
            && self.host.as_deref().map_or(true, str::is_empty)
        {
            return Err(Error::config("encrypted upstream requires a TLS identity"));
        }
        #[cfg(any(feature = "doh", feature = "doh3"))]
        if matches!(self.endpoint.proto, Proto::DoH | Proto::DoH3) {
            crate::transports::validate_http_endpoint(
                self.host.as_deref().unwrap_or_default(),
                &self.endpoint,
            )?;
        }
        Ok(())
    }

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
    generation: u64,
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
            generation: courierust::courierust_net::outbound::generation(),
            endpoint: f.endpoint,
            host: f.host.clone(),
            path,
        }
    }
}

fn pooled_transport<T>(
    cache: &Mutex<BTreeMap<TransportKey, Arc<T>>>,
    key: TransportKey,
    build: impl FnOnce() -> T,
) -> Arc<T> {
    let mut cache = cache.lock();
    // A TUN transition changes socket binding. Retain no idle connection from
    // the old path; in-flight exchanges keep their own Arc until they finish.
    cache.retain(|existing, _| existing.generation == key.generation);
    Arc::clone(cache.entry(key).or_insert_with(|| Arc::new(build())))
}

/// The set of forwarding upstreams with cached per-endpoint transports.
#[derive(Clone)]
pub struct ForwarderSet {
    forwarders: Vec<Forwarder>,
    privacy: crate::privacy::UpstreamPrivacy,
    #[cfg(feature = "dot")]
    dot: Arc<Mutex<BTreeMap<TransportKey, Arc<crate::transports::dot::DotTransport>>>>,
    #[cfg(feature = "doh")]
    doh: Arc<Mutex<BTreeMap<TransportKey, Arc<crate::transports::doh::DohTransport>>>>,
    #[cfg(feature = "doh3")]
    doh3: Arc<Mutex<BTreeMap<TransportKey, Arc<crate::transports::doh3::Doh3Transport>>>>,
    #[cfg(feature = "doq")]
    doq: Arc<Mutex<BTreeMap<TransportKey, Arc<crate::transports::doq::DoqTransport>>>>,
    plain: Arc<Transports>,
    roots: courierust::courierust_tls::RootStore,
    verify: bool,
    now: i64,
    // Only loopback transport failures enter this short cooldown. No domain
    // answers (including NXDOMAIN) are treated as endpoint health failures.
    local_cooldowns: Arc<Mutex<BTreeMap<TransportKey, std::time::Instant>>>,
}

/// Which upstreams are configured and whether certificates are verified;
/// the pooled transports are not touched (`Debug` must not block).
impl core::fmt::Debug for ForwarderSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ForwarderSet(forwarders={}, verify={}, roots={}, privacy={:?})",
            self.forwarders.len(),
            self.verify,
            self.roots.len(),
            self.privacy
        )
    }
}

impl ForwarderSet {
    /// An empty set.
    pub fn new(roots: courierust::courierust_tls::RootStore, verify: bool, now: i64) -> Self {
        Self {
            forwarders: Vec::new(),
            privacy: crate::privacy::UpstreamPrivacy::default(),
            #[cfg(feature = "dot")]
            dot: Arc::new(Mutex::new(BTreeMap::new())),
            #[cfg(feature = "doh")]
            doh: Arc::new(Mutex::new(BTreeMap::new())),
            #[cfg(feature = "doh3")]
            doh3: Arc::new(Mutex::new(BTreeMap::new())),
            #[cfg(feature = "doq")]
            doq: Arc::new(Mutex::new(BTreeMap::new())),
            plain: Arc::new(Transports::new()),
            roots,
            verify,
            now,
            local_cooldowns: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Set disclosure limits. They are validated again before any network I/O.
    pub fn with_privacy(mut self, privacy: crate::privacy::UpstreamPrivacy) -> Self {
        self.privacy = privacy;
        self
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
        self.privacy.validate()?;
        let _scope = crate::background::TaskScope::enter_query(
            crate::budget::FetchLimits::default(),
            timeout_ms,
        );
        // Validate the complete group before sending anything. A typo must not
        // silently switch a strict query to another privacy boundary.
        for forwarder in group {
            forwarder.validate()?;
            if self.privacy.encrypted_only
                && (matches!(forwarder.endpoint.proto, Proto::Udp | Proto::Tcp)
                    || !self.verify
                    || self.roots.is_empty())
            {
                return Err(Error::config(
                    "strict DNS privacy requires verified encrypted upstreams",
                ));
            }
        }
        if Message::parse(query_bytes)? != *query {
            return Err(Error::config(
                "forwarding query bytes differ from the validation message",
            ));
        }
        if query.flags.qr
            || query.flags.opcode != crate::qtype::Opcode::QUERY
            || query.questions.len() != 1
            || !query.answers.is_empty()
            || !query.authorities.is_empty()
            || !query.additionals.is_empty()
        {
            return Err(Error::config(
                "forwarding requires one unsigned DNS question",
            ));
        }
        let mut private_query;
        let private_bytes;
        let (query, query_bytes) = if self.privacy.encrypted_only {
            private_query = query.clone();
            let edns = private_query
                .edns
                .get_or_insert_with(|| crate::edns::Edns::new(1232));
            // Do not relay client subnet, cookies, tags or unknown identifiers.
            edns.options.clear();
            let length = private_query.to_bytes()?.len();
            let padding = (128 - (length + 4) % 128) % 128;
            private_query
                .edns
                .as_mut()
                .ok_or_else(|| Error::internal("missing private query EDNS"))?
                .options
                .push(crate::edns::EdnsOption::Padding(padding as u16));
            private_bytes = private_query.to_bytes()?;
            (&private_query, private_bytes.as_slice())
        } else {
            (query, query_bytes)
        };
        // A local recursive resolver has explicit precedence.
        if !self.privacy.parallel
            || self.privacy.max_upstreams == 1
            || group.len() < 2
            || group.first().is_some_and(|f| f.endpoint.ip.is_loopback())
        {
            return self.exchange_sequential(group, query, query_bytes, timeout_ms);
        }
        self.exchange_racing(group, query, query_bytes, timeout_ms)
    }

    fn exchange_racing(
        &self,
        group: &[Forwarder],
        query: &Message,
        query_bytes: &[u8],
        timeout_ms: u64,
    ) -> Result<Message> {
        let _scope = crate::background::TaskScope::enter_query(
            crate::budget::FetchLimits::default(),
            timeout_ms,
        );
        let Some(permits) = RacePermit::pair() else {
            return self.exchange_sequential(group, query, query_bytes, timeout_ms);
        };
        let deadline = query_deadline(timeout_ms)?;
        let cancellation = RaceCancellation(Arc::new(std::sync::atomic::AtomicBool::new(false)));
        let (send, receive) = std::sync::mpsc::channel();
        for (lane, permit) in permits.into_iter().enumerate() {
            let servers: Vec<_> = group.iter().skip(lane).step_by(2).cloned().collect();
            let pool = self.clone();
            let message = query.clone();
            let bytes = query_bytes.to_vec();
            let send = send.clone();
            let context = crate::background::WorkerContext::capture();
            let canceled = Arc::clone(&cancellation.0);
            let spawned = std::thread::Builder::new()
                .name("dns-race".into())
                .stack_size(512 * 1024)
                .spawn(move || {
                    let _permit = permit;
                    let _context = context.enter();
                    let answer = pool.exchange_sequential_until(
                        &servers,
                        &message,
                        &bytes,
                        deadline,
                        Some(&canceled),
                    );
                    let _ = send.send(answer);
                });
            if let Err(error) = spawned {
                // Dropping the failed spawn's closure releases its permit.
                return Err(Error::io(format!("cannot start DNS worker: {error}")));
            }
        }
        drop(send);
        let mut last = Error::new(ErrorKind::Timeout, "DNS query deadline exhausted");
        while let Ok(answer) =
            receive.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
        {
            match answer {
                Ok(message) => return Ok(message),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    fn exchange_sequential(
        &self,
        group: &[Forwarder],
        query: &Message,
        query_bytes: &[u8],
        timeout_ms: u64,
    ) -> Result<Message> {
        let _scope = crate::background::TaskScope::enter_query(
            crate::budget::FetchLimits::default(),
            timeout_ms,
        );
        self.exchange_sequential_until(group, query, query_bytes, query_deadline(timeout_ms)?, None)
    }

    fn exchange_sequential_until(
        &self,
        group: &[Forwarder],
        query: &Message,
        query_bytes: &[u8],
        deadline: std::time::Instant,
        canceled: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<Message> {
        let mut last_err: Option<Error> = None;
        for (index, f) in group.iter().enumerate() {
            let local_with_alternative = f.endpoint.ip.is_loopback() && group.len() > 1;
            let local_key = TransportKey::of(f);
            if local_with_alternative {
                let mut cooldowns = self.local_cooldowns.lock();
                let now = std::time::Instant::now();
                cooldowns
                    .retain(|key, until| key.generation == local_key.generation && *until > now);
                if cooldowns.contains_key(&local_key) {
                    continue;
                }
            }
            if canceled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire)) {
                return Err(Error::new(
                    ErrorKind::Canceled,
                    "another DNS worker completed",
                ));
            }
            let remaining = deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_millis() as u64;
            if remaining == 0 {
                last_err = Some(Error::new(
                    ErrorKind::Timeout,
                    "DNS query deadline exhausted",
                ));
                break;
            }
            let timeout_ms = if index == 0 && local_with_alternative {
                (remaining / 2).max(1)
            } else {
                (remaining / (group.len() - index) as u64).max(1)
            };
            let attempt_deadline = query_deadline(timeout_ms)?.min(deadline);
            let mut resp = match self.exchange_message(f, query, query_bytes, timeout_ms) {
                Ok(m) => m,
                Err(e) => {
                    if local_with_alternative
                        && matches!(e.kind, ErrorKind::Timeout | ErrorKind::Io)
                    {
                        let mut cooldowns = self.local_cooldowns.lock();
                        if cooldowns.len() < 32 {
                            cooldowns.insert(
                                local_key,
                                std::time::Instant::now() + std::time::Duration::from_secs(5),
                            );
                        }
                    }
                    last_err = Some(e);
                    continue;
                }
            };
            if resp.flags.tc && f.endpoint.proto == Proto::Udp {
                if canceled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire)) {
                    return Err(Error::new(
                        ErrorKind::Canceled,
                        "another DNS worker completed",
                    ));
                }
                let tcp =
                    Forwarder::plain(Endpoint::new(f.endpoint.ip, f.endpoint.port, Proto::Tcp));
                resp = match self.exchange_message(
                    &tcp,
                    query,
                    query_bytes,
                    attempt_deadline
                        .saturating_duration_since(std::time::Instant::now())
                        .as_millis() as u64,
                ) {
                    Ok(message) => message,
                    Err(error) => {
                        last_err = Some(error);
                        continue;
                    }
                };
            }
            if resp.flags.tc {
                last_err = Some(Error::new(
                    ErrorKind::Truncated,
                    "upstream returned a truncated stream response",
                ));
                continue;
            }
            let rcode = resp.rcode();
            if rcode != u16::from(Rcode::NOERROR.to_u8())
                && rcode != u16::from(Rcode::NXDOMAIN.to_u8())
                && rcode != u16::from(Rcode::YXDOMAIN.to_u8())
            {
                let code = Rcode(u8::try_from(rcode).unwrap_or(Rcode::SERVFAIL.to_u8()));
                last_err = Some(Error::new(
                    if code == Rcode::REFUSED {
                        ErrorKind::Refused
                    } else {
                        ErrorKind::Servfail
                    },
                    format!(
                        "the upstream {} answered {code} (RCODE {rcode})",
                        f.endpoint.ip
                    ),
                ));
                continue;
            }
            return Ok(resp);
        }
        Err(last_err.unwrap_or_else(|| Error::new(ErrorKind::NoUpstream, "no forwarder answered")))
    }

    fn exchange_message(
        &self,
        forwarder: &Forwarder,
        query: &Message,
        bytes: &[u8],
        timeout_ms: u64,
    ) -> Result<Message> {
        let message = Message::parse(&self.exchange_one(forwarder, bytes, timeout_ms)?)?;
        if !response_matches_query(query, &message) {
            return Err(Error::transport("forwarder response did not match query"));
        }
        Ok(message)
    }

    fn exchange_one(&self, f: &Forwarder, query: &[u8], timeout_ms: u64) -> Result<Vec<u8>> {
        if matches!(f.endpoint.proto, Proto::Udp | Proto::Tcp) {
            return self.exchange_one_unmetered(f, query, timeout_ms);
        }
        crate::background::exchange(&f.endpoint, query.len(), timeout_ms, |timeout| {
            self.exchange_one_unmetered(f, query, timeout)
        })
    }

    fn exchange_one_unmetered(
        &self,
        f: &Forwarder,
        query: &[u8],
        timeout_ms: u64,
    ) -> Result<Vec<u8>> {
        f.validate()?;
        if !matches!(f.endpoint.proto, Proto::Udp | Proto::Tcp)
            && self.verify
            && (self.roots.is_empty() || f.host.as_deref().map_or(true, str::is_empty))
        {
            return Err(Error::new(
                ErrorKind::Config,
                "encrypted upstream requires trust roots and a TLS identity",
            ));
        }
        crate::background::admit_forwarder(f.endpoint.ip, self.privacy.max_upstreams)?;
        let key = TransportKey::of(f);
        match f.endpoint.proto {
            Proto::Udp | Proto::Tcp => self.plain.exchange(&f.endpoint, query, timeout_ms),
            #[cfg(feature = "dot")]
            Proto::Tls => {
                let transport = pooled_transport(&self.dot, key, || {
                    let host = f.host.clone().unwrap_or_else(|| f.endpoint.ip.to_string());
                    crate::transports::dot::DotTransport::for_host(
                        host,
                        self.roots.clone(),
                        self.verify,
                        self.now,
                    )
                });
                transport.exchange(query, &f.endpoint, timeout_ms)
            }
            #[cfg(feature = "doh")]
            Proto::DoH => {
                let transport = pooled_transport(&self.doh, key, || {
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
                transport.exchange(query, &f.endpoint, timeout_ms)
            }
            #[cfg(feature = "doh3")]
            Proto::DoH3 => {
                let transport = pooled_transport(&self.doh3, key, || self.build_doh3_transport(f));
                transport.exchange(query, &f.endpoint, timeout_ms)
            }
            #[cfg(feature = "doq")]
            Proto::DoQ => {
                let transport = pooled_transport(&self.doq, key, || {
                    let host = f.host.clone().unwrap_or_else(|| f.endpoint.ip.to_string());
                    crate::transports::doq::DoqTransport::for_host(
                        host,
                        self.roots.clone(),
                        self.verify,
                        self.now,
                    )
                });
                transport.exchange(query, &f.endpoint, timeout_ms)
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

    #[cfg(feature = "doh3")]
    fn build_doh3_transport(
        &self,
        forwarder: &Forwarder,
    ) -> crate::transports::doh3::Doh3Transport {
        let host = forwarder
            .host
            .clone()
            .unwrap_or_else(|| forwarder.endpoint.ip.to_string());
        let mut transport = crate::transports::doh3::Doh3Transport::for_host(
            host,
            self.roots.clone(),
            self.verify,
            self.now,
        );
        transport.path = forwarder.doh_path().to_string();
        transport
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
    rng: &mut impl RandomSource,
) -> Message {
    let mut m = Message::new((rng.next_u32() & 0xffff) as u16);
    m.flags.rd = true;
    m.flags.cd = key.cd;
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
    // Admit only records reachable from this question. A forwarded response
    // must not seed unrelated names into the shared cache or bypass policy.
    use crate::qtype::RrType;
    use crate::rdata::RData;
    let mut owner = key.name.clone();
    let mut visited = alloc::collections::BTreeSet::new();
    for _ in 0..64 {
        if !visited.insert(owner.clone()) {
            break;
        }
        let matching: Vec<_> = resp
            .answers
            .iter()
            .filter(|r| {
                r.class == key.class
                    && r.name == owner
                    && r.rr_type != RrType::RRSIG
                    && (r.rr_type == key.rr_type || key.rr_type == RrType::ANY)
            })
            .collect();
        if !matching.is_empty() {
            answers.extend(matching.into_iter().cloned());
            break;
        }
        let aliases: Vec<_> = resp
            .answers
            .iter()
            .filter(|r| r.class == key.class && r.name == owner && r.rr_type == RrType::CNAME)
            .collect();
        if let [alias] = aliases.as_slice() {
            if let RData::Cname(target) = &alias.rdata {
                answers.push((*alias).clone());
                // Keep a covering DNAME too; CNAME is its wire synthesis.
                if let Some(dname) = resp
                    .answers
                    .iter()
                    .filter(|r| {
                        r.class == key.class
                            && r.rr_type == RrType::DNAME
                            && owner.is_strict_subdomain_of(&r.name)
                    })
                    .max_by_key(|r| r.name.label_count())
                {
                    if let RData::Dname(suffix) = &dname.rdata {
                        if crate::engine::synthesize_dname_cname(&owner, &dname.name, suffix)
                            .as_ref()
                            == Some(target)
                        {
                            answers.push(dname.clone());
                        }
                    }
                }
                owner = target.clone();
                continue;
            }
        }
        break;
    }
    for r in &answers {
        ttl = ttl.min(r.ttl);
    }
    for sig in &resp.answers {
        if sig.class == key.class && sig.rr_type == RrType::RRSIG {
            if let RData::Rrsig { type_covered, .. } = &sig.rdata {
                if answers
                    .iter()
                    .any(|r| r.name == sig.name && r.rr_type == *type_covered)
                {
                    rrsigs.push(sig.clone());
                }
            }
        }
    }
    let authorities = resp
        .authorities
        .iter()
        .filter(|r| r.class == key.class && owner.is_subdomain_of(&r.name))
        .cloned()
        .collect();
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
        authorities,
        rrsigs,
        validated: false,
        ttl,
        from_cache: false,
        stale: false,
        ecs_scope: resp
            .edns
            .as_ref()
            .and_then(|e| e.ecs())
            .map(|e| e.scope_prefix),
        served_at: 0,
    }
}

fn query_deadline(timeout_ms: u64) -> Result<std::time::Instant> {
    if timeout_ms == 0 {
        return Err(Error::new(
            ErrorKind::Timeout,
            "DNS query deadline exhausted",
        ));
    }
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(timeout_ms))
        .ok_or_else(|| Error::config("DNS query timeout is too large"))?;
    Ok(crate::background::task_deadline().map_or(deadline, |outer| deadline.min(outer)))
}

// Bounded independently of each resolver's inflight limit: multiple profiles
// and bootstrap/client resolvers all share the same thread budget.
static RACE_WORKERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
struct RacePermit;
impl RacePermit {
    fn pair() -> Option<[Self; 2]> {
        use std::sync::atomic::Ordering;
        let mut count = RACE_WORKERS.load(Ordering::Relaxed);
        loop {
            if count > 30 {
                return None;
            }
            match RACE_WORKERS.compare_exchange_weak(
                count,
                count + 2,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => count = current,
            }
        }
        Some([Self, Self])
    }
}
impl Drop for RacePermit {
    fn drop(&mut self) {
        RACE_WORKERS.fetch_sub(1, std::sync::atomic::Ordering::Release);
    }
}

// Returning a winner stops further retries in the losing lane. Already-sent
// synchronous I/O remains bounded by the original deadline.
struct RaceCancellation(Arc<std::sync::atomic::AtomicBool>);
impl Drop for RaceCancellation {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
#[path = "../tests/support/sockets.rs"]
mod test_sockets;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn racing_cannot_bypass_background_or_task_limits() {
        let budget = Arc::new(crate::background::BackgroundBudget::new(
            crate::background::BackgroundLimits::default(),
        ));
        let scope = crate::background::TaskScope::enter(
            budget.clone(),
            crate::budget::FetchLimits {
                max_subqueries: 1,
                ..crate::budget::FetchLimits::default()
            },
            2000,
        );
        let (first, seen_first) = spawn_upstream(|query| response_for(query, Rcode::SERVFAIL));
        let (second, seen_second) = spawn_upstream(|query| response_for(query, Rcode::SERVFAIL));
        let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), true, 0);
        let (query, bytes) = query_for("bounded.example");
        assert!(set
            .exchange_racing(&[plain(first), plain(second)], &query, &bytes, 1000)
            .is_err());
        assert_eq!(
            seen_first.load(Ordering::Relaxed) + seen_second.load(Ordering::Relaxed),
            1
        );
        assert_eq!(scope.work().subqueries, 1);
        assert_eq!(budget.snapshot().0.subqueries, 1);
    }

    #[test]
    fn cancellation_prevents_a_losing_lane_from_contacting_more_servers() {
        let (server, seen) = spawn_upstream(|query| answer_for(query, Ipv4Addr::LOCALHOST));
        let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), true, 0);
        let (query, bytes) = query_for("canceled.example");
        let canceled = std::sync::atomic::AtomicBool::new(true);
        let result = set.exchange_sequential_until(
            &[plain(server)],
            &query,
            &bytes,
            query_deadline(1000).unwrap(),
            Some(&canceled),
        );
        assert_eq!(result.unwrap_err().kind, ErrorKind::Canceled);
        assert_eq!(seen.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn extended_failure_rcode_does_not_become_a_successful_answer() {
        let (bad, _) = spawn_upstream(|query| {
            let mut response = response_for(query, Rcode::NOERROR);
            let mut edns = crate::edns::Edns::new(1232);
            edns.ext_rcode = 16; // Full RCODE 256, not NOERROR.
            response.edns = Some(edns);
            response
        });
        let (good, _) = spawn_upstream(|query| answer_for(query, Ipv4Addr::new(203, 0, 113, 5)));
        let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), true, 0);
        let (query, bytes) = query_for("rcode.example");
        let response = set
            .exchange_with(&[plain(bad), plain(good)], &query, &bytes, 1000)
            .unwrap();
        assert_eq!(response.answers.len(), 1);
    }

    #[test]
    fn dname_overflow_is_a_terminal_answer() {
        // RFC 6672 section 2.2: DNAME substitution can produce YXDOMAIN.
        let (first, _) = spawn_upstream(|query| response_for(query, Rcode::YXDOMAIN));
        let (second, seen) = spawn_upstream(|query| answer_for(query, Ipv4Addr::LOCALHOST));
        let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), true, 0);
        let (query, bytes) = query_for("overflow.example");
        let response = set
            .exchange_with(&[plain(first), plain(second)], &query, &bytes, 1000)
            .unwrap();
        assert_eq!(response.rcode(), u16::from(Rcode::YXDOMAIN.to_u8()));
        assert_eq!(seen.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn strict_policy_rejects_plaintext_before_sending() {
        let (server, seen) = spawn_upstream(|query| answer_for(query, Ipv4Addr::LOCALHOST));
        let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), true, 0)
            .with_privacy(crate::privacy::UpstreamPrivacy::strict());
        let (query, bytes) = query_for("private.example");
        assert_eq!(
            set.exchange_with(&[plain(server)], &query, &bytes, 1000)
                .unwrap_err()
                .kind,
            ErrorKind::Config
        );
        assert_eq!(seen.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn truncated_udp_forwarding_retries_tcp_on_the_same_upstream() {
        use std::io::{Read, Write};
        let (tcp, udp) = super::test_sockets::bind_dns_pair()
            .expect("reserve UDP and TCP on the same upstream endpoint");
        let address = tcp.local_addr().unwrap();
        udp.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let udp_server = std::thread::spawn(move || {
            let mut bytes = [0; 4096];
            let (length, peer) = udp.recv_from(&mut bytes).unwrap();
            let mut response = Message::parse(&bytes[..length]).unwrap();
            response.flags.qr = true;
            response.flags.tc = true;
            udp.send_to(&response.to_bytes().unwrap(), peer).unwrap();
        });
        let tcp_server = std::thread::spawn(move || {
            let (mut stream, _) = tcp.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut prefix = [0; 2];
            stream.read_exact(&mut prefix).unwrap();
            let mut bytes = vec![0; u16::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut bytes).unwrap();
            let mut response = Message::parse(&bytes).unwrap();
            response.flags.qr = true;
            let bytes = response.to_bytes().unwrap();
            stream
                .write_all(&(bytes.len() as u16).to_be_bytes())
                .unwrap();
            stream.write_all(&bytes).unwrap();
        });
        let forwarder = Forwarder::plain(Endpoint::new(address.ip(), address.port(), Proto::Udp));
        let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), true, 0);
        let query = Message::query(
            23,
            crate::name::Name::from_ascii("tcp.example").unwrap(),
            crate::qtype::RrType::A,
            true,
        );
        let response = set
            .exchange_with(&[forwarder], &query, &query.to_bytes().unwrap(), 1000)
            .unwrap();
        assert!(!response.flags.tc);
        assert_eq!(response.questions, query.questions);
        udp_server.join().unwrap();
        tcp_server.join().unwrap();
    }
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

    #[test]
    fn pooled_transports_are_reused_without_holding_the_pool_lock() {
        let pool = Mutex::new(BTreeMap::new());
        let key = TransportKey {
            generation: 0,
            endpoint: Endpoint::udp("192.0.2.1".parse().unwrap()),
            host: None,
            path: None,
        };
        let mut builds = 0;

        let first = pooled_transport(&pool, key.clone(), || {
            builds += 1;
            7
        });
        let second = pooled_transport(&pool, key.clone(), || {
            builds += 1;
            9
        });

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(*first, 7);
        assert_eq!(builds, 1);
        assert!(pool.try_lock().is_some());
        let next = pooled_transport(
            &pool,
            TransportKey {
                generation: 1,
                ..key
            },
            || {
                builds += 1;
                11
            },
        );
        assert!(!Arc::ptr_eq(&first, &next));
        assert_eq!(*next, 11);
        assert_eq!(builds, 2);
        assert_eq!(pool.lock().len(), 1);
    }

    #[cfg(feature = "doh3")]
    #[test]
    fn doh3_transport_uses_the_configured_path() {
        let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), false, 0);
        let forwarder = Forwarder::encrypted(
            Endpoint::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 443, Proto::DoH3),
            "resolver.example",
        )
        .with_path("/custom-dns");

        let transport = set.build_doh3_transport(&forwarder);

        assert_eq!(transport.path, "/custom-dns");
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
        response.questions.clone_from(&query.questions);
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

    #[test]
    fn racing_returns_fast_answer_without_waiting_for_slow_peer() {
        let (slow, worker) = spawn_upstream(|query| {
            std::thread::sleep(std::time::Duration::from_millis(700));
            answer_for(query, Ipv4Addr::new(203, 0, 113, 1))
        });
        let (fast, fast_worker) =
            spawn_upstream(|query| answer_for(query, Ipv4Addr::new(203, 0, 113, 2)));
        let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), true, 0);
        let (query, bytes) = query_for("race.example");
        let start = std::time::Instant::now();
        let response = set
            .exchange_racing(&[plain(slow), plain(fast)], &query, &bytes, 1500)
            .unwrap();
        assert_eq!(
            response.answers[0].rdata,
            RData::A(Ipv4Addr::new(203, 0, 113, 2))
        );
        assert!(start.elapsed() < std::time::Duration::from_millis(600));
        let _ = worker;
        assert!(fast_worker.load(std::sync::atomic::Ordering::Relaxed) > 0);
    }

    #[test]
    fn zero_budget_is_a_timeout_without_starting_io() {
        let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), true, 0);
        let (query, bytes) = query_for("timeout.example");
        let error = set
            .exchange_sequential(&[plain(9)], &query, &bytes, 0)
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout);
    }

    #[test]
    fn sequential_failures_share_one_deadline() {
        let (one, worker_one) = spawn_upstream(|query| {
            std::thread::sleep(std::time::Duration::from_millis(600));
            answer_for(query, Ipv4Addr::new(203, 0, 113, 1))
        });
        let (two, worker_two) = spawn_upstream(|query| {
            std::thread::sleep(std::time::Duration::from_millis(600));
            answer_for(query, Ipv4Addr::new(203, 0, 113, 2))
        });
        let set = ForwarderSet::new(courierust::courierust_tls::RootStore::new(), true, 0);
        let (query, bytes) = query_for("timeout.example");
        let start = std::time::Instant::now();
        assert!(set
            .exchange_sequential(&[plain(one), plain(two)], &query, &bytes, 250)
            .is_err());
        assert!(start.elapsed() < std::time::Duration::from_millis(500));
        assert!(worker_one.load(std::sync::atomic::Ordering::Relaxed) > 0);
        assert!(worker_two.load(std::sync::atomic::Ordering::Relaxed) > 0);
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
