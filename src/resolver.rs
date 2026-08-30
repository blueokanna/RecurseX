//! The recursive resolver: shared state, the resolution loop, cache
//! integration, coalescing, and background maintenance.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use crate::cache::{CacheConfig, CacheKey, EntryKind, LookupOutcome, SemanticCache};
use crate::engine::{self, EdnsSpec, ResponseKind};
use crate::error::{Error, ErrorKind, Result};
use crate::estimator::QueryEstimator;
use crate::graph::{EdgeKind, GraphConfig, NodeId, NodeKind, ResolutionGraph};
use crate::message::{HeaderFlags, Message};
use crate::name::Name;
use crate::planner::{PlannerConfig, ResolutionPlanner};
use crate::policy::{PolicyConfig, PolicyEngine, RateLimiter};
use crate::prng::SplitMix64;
use crate::qtype::{Rcode, RrClass, RrType};
use crate::query::{ecs_option, response_matches_query, Coalescer, QueryKey};
use crate::rdata::{RData, Record};
use crate::rrset::RrSet;
use crate::stats::{Stats, StatsSnapshot};
use crate::time::{Clock, SystemClock, Ts};
use crate::transport::Transports;
use crate::upstream::{Endpoint, Proto, UpstreamSelector};

/// Engine tuning.
#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// Root server addresses (empty = IANA defaults).
    pub root_servers: Vec<IpAddr>,
    /// Per-attempt exchange timeout in ms.
    pub timeout_ms: u64,
    /// Attempts per server before moving on.
    pub max_attempts_per_server: u32,
    /// RFC 9156 QNAME minimization.
    pub qname_minimization: bool,
    /// 0x20 case randomization (RFC 6840 §5.6).
    pub use_0x20: bool,
    /// Maximum CNAME/DNAME chases.
    pub max_cname_depth: usize,
    /// Maximum referrals per resolution (loop protection).
    pub max_referrals: usize,
    /// EDNS UDP payload size to advertise.
    pub edns_udp_size: u16,
    /// Whether to request and validate DNSSEC.
    pub dnssec: bool,
    /// Fall back to TCP on truncation.
    pub tcp_fallback: bool,
    /// Retransmit budget for the expected-cost model.
    pub retransmit_budget: u32,
    /// Maximum NS-address resolution recursion depth.
    pub max_ns_depth: usize,
    /// Maximum number of ranked servers tried per query.
    pub max_servers_tried: usize,
    /// Maximum total wire attempts per query (bounds worst-case latency).
    pub max_total_attempts: u32,
    /// Forwarding upstreams (when set, queries go through these instead of
    /// iterative resolution).
    #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
    pub forwarders: Vec<crate::forward::Forwarder>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            root_servers: Vec::new(),
            timeout_ms: 1500,
            max_attempts_per_server: 2,
            qname_minimization: true,
            use_0x20: true,
            max_cname_depth: 8,
            max_referrals: 32,
            edns_udp_size: 1232,
            dnssec: false,
            tcp_fallback: true,
            retransmit_budget: 2,
            max_ns_depth: 6,
            max_servers_tried: 6,
            max_total_attempts: 10,
            #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
            forwarders: Vec::new(),
        }
    }
}

/// Client rate limiting.
#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    /// Token-bucket capacity per client (burst size).
    pub client_capacity: f64,
    /// Token refill rate per second per client.
    pub client_refill_per_sec: f64,
    /// Maximum number of tracked client buckets (bound memory).
    pub max_client_buckets: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            client_capacity: 100.0,
            client_refill_per_sec: 50.0,
            max_client_buckets: 65_536,
        }
    }
}

/// Resolver configuration.
#[derive(Clone, Debug)]
pub struct ResolverConfig {
    /// Cache tuning.
    pub cache: CacheConfig,
    /// Planner tuning.
    pub planner: PlannerConfig,
    /// Policy (blocklist) tuning.
    pub policy: PolicyConfig,
    /// Engine tuning.
    pub engine: EngineConfig,
    /// Client rate limiting.
    pub rate_limit: RateLimitConfig,
    /// Maximum distinct in-flight queries (coalescer bound).
    pub max_inflight: usize,
    /// Maintenance (sweep + prefetch) interval in ms.
    pub maintenance_interval_ms: u64,
    /// Maximum prefetches spawned per maintenance tick.
    pub max_prefetch_per_tick: usize,
    /// Serve-stale TTL reported to clients (RFC 8767 recommends 30 s).
    pub stale_serve_ttl: u32,
    /// Optional L3 persistent cache tier (persist feature).
    #[cfg(feature = "persist")]
    pub persist: Option<crate::cache::persist::PersistConfig>,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            cache: CacheConfig::default(),
            planner: PlannerConfig::default(),
            policy: PolicyConfig::default(),
            engine: EngineConfig::default(),
            rate_limit: RateLimitConfig::default(),
            max_inflight: 4096,
            maintenance_interval_ms: 1000,
            max_prefetch_per_tick: 64,
            stale_serve_ttl: 30,
            #[cfg(feature = "persist")]
            persist: None,
        }
    }
}

/// The outcome of a resolution.
#[derive(Clone, Debug)]
pub struct Resolution {
    /// The queried name.
    pub name: Name,
    /// The queried type.
    pub rr_type: RrType,
    /// The queried class.
    pub class: RrClass,
    /// The response code.
    pub rcode: Rcode,
    /// The answer chain (CNAME/DNAME + final records), in order.
    pub answers: Vec<Record>,
    /// Authority records (SOA for negative answers).
    pub authorities: Vec<Record>,
    /// RRSIG records (when DNSSEC was requested).
    pub rrsigs: Vec<Record>,
    /// Whether the answer chain was DNSSEC-validated.
    pub validated: bool,
    /// The TTL to report (remaining for cached data).
    pub ttl: u32,
    /// Whether the answer came from cache.
    pub from_cache: bool,
    /// Whether the answer was served stale.
    pub stale: bool,
    /// Wall time when the resolution was served.
    pub served_at: Ts,
}

/// Shared resolver state (everything behind locks).
pub struct SharedState {
    /// The multi-tier semantic cache.
    pub cache: Mutex<SemanticCache>,
    /// The query estimator (popularity / locality model).
    pub estimator: Mutex<QueryEstimator>,
    /// The upstream selector (path statistics).
    pub selector: Mutex<UpstreamSelector>,
    /// The resolution graph.
    pub graph: Mutex<ResolutionGraph>,
    /// The query coalescer.
    pub coalescer: Mutex<Coalescer>,
    /// The per-client rate limiter.
    pub client_limiter: Mutex<RateLimiter>,
}

impl SharedState {
    fn new(config: &ResolverConfig) -> Self {
        Self {
            cache: Mutex::new(SemanticCache::new(config.cache)),
            estimator: Mutex::new(QueryEstimator::new(100_000)),
            selector: Mutex::new(UpstreamSelector::new(4096)),
            graph: Mutex::new(ResolutionGraph::new(GraphConfig::default())),
            coalescer: Mutex::new(Coalescer::new(config.max_inflight)),
            client_limiter: Mutex::new(RateLimiter::new(
                config.rate_limit.client_capacity,
                config.rate_limit.client_refill_per_sec,
                config.rate_limit.max_client_buckets,
            )),
        }
    }
}

/// Reseed the query-ID / 0x20 PRNG from OS entropy after this many draws,
/// so an observer who recovered part of the SplitMix64 stream cannot
/// predict far ahead (anti cache-poisoning hardening).
const RNG_RESEED_EVERY: u64 = 4096;

/// A slot a coalesced waiter blocks on.
struct Slot {
    result: Mutex<Option<Result<Resolution>>>,
    cv: Condvar,
}

/// The resolver.
///
/// `Resolver` is a cheap clone over an `Arc<ResolverInner>` so background
/// threads (maintenance, prefetch, serve-stale refresh) can hold their own
/// handle.
#[derive(Clone)]
pub struct Resolver {
    inner: Arc<ResolverInner>,
}

/// All resolver state.
pub struct ResolverInner {
    /// The resolver configuration.
    pub config: ResolverConfig,
    /// The shared (locked) state.
    pub shared: Arc<SharedState>,
    /// The policy engine.
    pub policy: PolicyEngine,
    /// The clock.
    pub clock: Arc<dyn Clock>,
    /// The available transports.
    pub transports: Transports,
    /// The statistics counters.
    pub stats: Stats,
    /// The forwarding upstream set.
    #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
    pub forwarder_set: Mutex<crate::forward::ForwarderSet>,
    inflight: Mutex<BTreeMap<QueryKey, Arc<Slot>>>,
    rng: Mutex<SplitMix64>,
    /// How many draws have been taken from `rng` (drives periodic reseed).
    rng_draws: std::sync::atomic::AtomicU64,
}

impl Resolver {
    /// A resolver with the given configuration.
    pub fn new(config: ResolverConfig) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let rng = SplitMix64::seeded();
        let shared = Arc::new(SharedState::new(&config));
        #[cfg(feature = "persist")]
        if let Some(p) = &config.persist {
            // Warm the cache from the L3 tier; a corrupt/absent file is a
            // cold start, never a startup failure.
            let now = clock.now();
            let _ = crate::cache::persist::load_from_limit(
                &mut shared.cache.lock().unwrap(),
                &p.path,
                now,
                p.frame_limit,
            );
        }
        let policy = PolicyEngine::new(config.policy.clone());
        #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
        let mut forwarder_set = crate::forward::ForwarderSet::new(
            courierust::courierust_tls::RootStore::new(),
            false,
            now_secs,
        );
        #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
        {
            for f in &config.engine.forwarders {
                forwarder_set.add(f.clone());
            }
        }
        Self {
            inner: Arc::new(ResolverInner {
                config,
                shared,
                policy,
                clock,
                transports: Transports::new(),
                stats: Stats::default(),
                #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
                forwarder_set: Mutex::new(forwarder_set),
                inflight: Mutex::new(BTreeMap::new()),
                rng: Mutex::new(rng),
                rng_draws: std::sync::atomic::AtomicU64::new(0),
            }),
        }
    }

    /// Run `f` with the shared PRNG locked, reseeding it from OS entropy
    /// every [`RNG_RESEED_EVERY`] draws. The query-ID / 0x20 generator is a
    /// seeded SplitMix64, which is unpredictable to an off-path attacker;
    /// periodic reseeding additionally bounds what an *on-path* observer
    /// (e.g. a server we query) can learn about the stream and predict.
    fn with_rng<T>(&self, f: impl FnOnce(&mut SplitMix64) -> T) -> T {
        let mut rng = self.inner.rng.lock().unwrap();
        let draws = self.inner.rng_draws.fetch_add(1, Ordering::Relaxed);
        if draws % RNG_RESEED_EVERY == 0 {
            rng.reseed(crate::entropy::seed_u64());
        }
        f(&mut rng)
    }

    /// Replace the trust roots used for encrypted forwarders
    /// (DoT/DoH/DoH3/DoQ). By default encrypted forwarders run with
    /// certificate verification disabled (an empty root store plus
    /// `verify: true` would reject every server). To enable real
    /// verification, supply trust anchors **and** set `verify: true`;
    /// the hostname and chain are then validated against them.
    #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
    pub fn set_forwarder_roots(&self, roots: courierust::courierust_tls::RootStore, verify: bool) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let mut fs = crate::forward::ForwarderSet::new(roots, verify, now);
        for f in &self.inner.config.engine.forwarders {
            fs.add(f.clone());
        }
        *self.inner.forwarder_set.lock().unwrap() = fs;
    }

    /// The wall clock this resolver uses.
    pub fn now(&self) -> Ts {
        self.inner.clock.now()
    }

    /// The underlying shared state.
    pub fn shared(&self) -> Arc<SharedState> {
        self.inner.shared.clone()
    }

    /// The configuration.
    pub fn config(&self) -> &ResolverConfig {
        &self.inner.config
    }

    /// The live counters.
    pub fn stats(&self) -> &Stats {
        &self.inner.stats
    }

    // -----------------------------------------------------------------
    // Public entry points
    // -----------------------------------------------------------------

    /// Resolve a name/type programmatically.
    pub fn resolve(&self, name: &Name, rr_type: RrType) -> Result<Resolution> {
        let key = QueryKey {
            name: name.clone(),
            rr_type,
            class: RrClass::IN,
            ecs: None,
            want_dnssec: self.inner.config.engine.dnssec,
            cd: false,
        };
        self.resolve_key(&key)
    }

    /// Resolve a query key.
    pub fn resolve_key(&self, key: &QueryKey) -> Result<Resolution> {
        let started = Instant::now();
        let now = self.inner.clock.now();
        self.inner.stats.queries.fetch_add(1, Ordering::Relaxed);
        self.inner
            .shared
            .estimator
            .lock()
            .unwrap()
            .observe_query(&key.name, now);

        if self.inner.policy.is_blocked(&key.name) {
            self.inner
                .stats
                .policy_blocked
                .fetch_add(1, Ordering::Relaxed);
            return Err(Error::new(
                ErrorKind::Policy,
                format!("name blocked by policy: {}", key.name),
            ));
        }

        // Coalesce identical in-flight queries.
        let (slot, owner) = {
            let mut inflight = self.inner.inflight.lock().unwrap();
            match inflight.get(&key.clone()) {
                Some(s) => (s.clone(), false),
                None => {
                    let s = Arc::new(Slot {
                        result: Mutex::new(None),
                        cv: Condvar::new(),
                    });
                    inflight.insert(key.clone(), s.clone());
                    (s, true)
                }
            }
        };

        if !owner {
            self.inner.stats.coalesced.fetch_add(1, Ordering::Relaxed);
            let res = {
                let mut guard = slot.result.lock().unwrap();
                while guard.is_none() {
                    guard = slot.cv.wait(guard).unwrap();
                }
                guard.as_ref().unwrap().clone()
            };
            return res;
        }

        let result = self.resolve_inner(key, 0);
        *slot.result.lock().unwrap() = Some(result.clone());
        slot.cv.notify_all();
        self.inner.inflight.lock().unwrap().remove(key);

        let elapsed = started.elapsed().as_micros() as u64;
        self.inner
            .stats
            .resolve_count
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .stats
            .resolve_time_us_sum
            .fetch_add(elapsed, Ordering::Relaxed);
        result
    }

    /// Handle a client message (rate limiting + response construction).
    /// `client_ip` enables per-client rate limiting and ECS synthesis.
    pub fn handle_query(&self, query: &Message, client_ip: Option<IpAddr>) -> Message {
        let now = self.inner.clock.now();
        if let Err(_e) = self.inner.policy.validate_query(query) {
            self.inner
                .stats
                .policy_blocked
                .fetch_add(1, Ordering::Relaxed);
            return query.error_response(Rcode::FORMERR);
        }
        if let Some(ip) = client_ip {
            let allowed = {
                let mut lim = self.inner.shared.client_limiter.lock().unwrap();
                self.inner.policy.client_allowed(&mut lim, &ip, now)
            };
            if !allowed {
                self.inner
                    .stats
                    .rate_limited
                    .fetch_add(1, Ordering::Relaxed);
                return query.error_response(Rcode::REFUSED);
            }
        }
        let Some(q) = query.question() else {
            return query.error_response(Rcode::FORMERR);
        };
        let key = QueryKey {
            name: q.qname.clone(),
            rr_type: q.qtype,
            class: q.qclass,
            ecs: query
                .edns
                .as_ref()
                .and_then(|e| e.ecs())
                .and_then(crate::cache::EcsKey::from_ecs),
            want_dnssec: query.edns.as_ref().map(|e| e.dnssec_ok).unwrap_or(false),
            cd: query.flags.cd,
        };
        match self.resolve_key(&key) {
            Ok(res) => self.build_response(query, &res),
            Err(e) => {
                self.inner.stats.errors.fetch_add(1, Ordering::Relaxed);
                let rcode = match e.kind() {
                    ErrorKind::NxDomain => Rcode::NXDOMAIN,
                    ErrorKind::NoData => Rcode::NOERROR,
                    ErrorKind::Servfail | ErrorKind::NoUpstream => Rcode::SERVFAIL,
                    ErrorKind::Policy => Rcode::REFUSED,
                    ErrorKind::RateLimited => Rcode::REFUSED,
                    _ => Rcode::SERVFAIL,
                };
                query.error_response(rcode)
            }
        }
    }

    /// Build a client response message from a resolution.
    pub fn build_response(&self, query: &Message, res: &Resolution) -> Message {
        let mut m = Message::new(query.id);
        m.flags = HeaderFlags {
            qr: true,
            rd: query.flags.rd,
            ra: true,
            rcode: res.rcode,
            ad: res.validated,
            ..HeaderFlags::default()
        };
        m.questions.clone_from(&query.questions);
        for r in &res.answers {
            let mut rec = r.clone();
            rec.ttl = res.ttl;
            m.answers.push(rec);
        }
        // RRSIGs only when the client asked for DNSSEC.
        let want_dnssec = query.edns.as_ref().map(|e| e.dnssec_ok).unwrap_or(false);
        if want_dnssec {
            for r in &res.rrsigs {
                let mut rec = r.clone();
                rec.ttl = res.ttl;
                m.answers.push(rec);
            }
        }
        for r in &res.authorities {
            let mut rec = r.clone();
            rec.ttl = res.ttl;
            m.authorities.push(rec);
        }
        // EDNS echo.
        if let Some(e) = &query.edns {
            m.edns = Some(crate::edns::Edns {
                udp_payload_size: e.udp_payload_size.max(512),
                ext_rcode: 0,
                version: 0,
                dnssec_ok: e.dnssec_ok,
                options: Vec::new(),
            });
        }
        m
    }

    // -----------------------------------------------------------------
    // Internal resolution
    // -----------------------------------------------------------------

    fn resolve_inner(&self, key: &QueryKey, ns_depth: usize) -> Result<Resolution> {
        let now = self.inner.clock.now();

        // Cache-first path.
        if let Some(res) = self.resolve_from_cache(key, now) {
            self.inner.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(res);
        }
        self.inner
            .stats
            .cache_misses
            .fetch_add(1, Ordering::Relaxed);

        #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
        let mut res = self
            .forward_resolve(key)
            .or_else(|_| self.iterative_resolve(key, ns_depth))?;
        #[cfg(not(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq")))]
        let mut res = self.iterative_resolve(key, ns_depth)?;
        res.served_at = now;

        // DNSSEC validation of the wire answer.
        #[cfg(feature = "dnssec")]
        if self.inner.config.engine.dnssec && !res.answers.is_empty() {
            let verdict = crate::dnssec::validate_resolution(self, &res);
            res.validated = verdict == crate::dnssec::Verdict::Secure;
        }

        // Populate the cache from the resolution.
        self.cache_resolution(key, &res, now);
        Ok(res)
    }

    /// Resolve through the configured forwarders (RD=1).
    #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
    fn forward_resolve(&self, key: &QueryKey) -> Result<Resolution> {
        let query = self.with_rng(|rng| {
            crate::forward::build_forward_query(
                key,
                self.inner.config.engine.edns_udp_size,
                self.inner.config.engine.dnssec,
                rng,
            )
        });
        let bytes = query.to_bytes()?;
        let resp = self.inner.forwarder_set.lock().unwrap().exchange(
            &query,
            &bytes,
            self.inner.config.engine.timeout_ms,
        )?;
        #[cfg(feature = "dnssec")]
        if self.inner.config.engine.dnssec {
            let verdict = crate::dnssec::validate_message(self, key, &resp);
            let mut res = crate::forward::response_to_resolution(key, &resp);
            res.validated = verdict == crate::dnssec::Verdict::Secure;
            return Ok(res);
        }
        Ok(crate::forward::response_to_resolution(key, &resp))
    }

    /// Attempt to satisfy a query purely from cache, walking CNAME chains.
    /// Returns `None` when the chain cannot be completed from cache.
    fn resolve_from_cache(&self, key: &QueryKey, now: Ts) -> Option<Resolution> {
        let planner = ResolutionPlanner::new(self.inner.config.planner);
        let mut current = key.clone();
        let mut answers: Vec<Record> = Vec::new();
        let mut rrsigs: Vec<Record> = Vec::new();
        let mut authorities: Vec<Record> = Vec::new();
        let mut rcode = Rcode::NOERROR;
        let mut validated = true;
        let mut ttl = u32::MAX;
        let mut stale = false;
        let mut refresh_keys: Vec<CacheKey> = Vec::new();
        let mut depth = 0usize;

        loop {
            if depth > self.inner.config.engine.max_cname_depth {
                return None;
            }
            let cache_key = current.cache_key();
            let outcome = self
                .inner
                .shared
                .cache
                .lock()
                .unwrap()
                .lookup(&cache_key, now);
            match outcome {
                LookupOutcome::Fresh(entry) => {
                    validated &= entry.validated;
                    ttl = ttl.min(entry.remaining_ttl(now).max(1));
                    match entry.kind {
                        EntryKind::Positive(rrset) => {
                            if rrset.rr_type == RrType::CNAME && current.rr_type != RrType::CNAME {
                                let target = rrset.cname_target()?.clone();
                                let rec = rrset.records.first()?.clone();
                                answers.push(rec);
                                rrsigs.extend(rrset.rrsigs.iter().cloned());
                                current.name = target;
                                depth += 1;
                                continue;
                            }
                            answers.extend(rrset.records.iter().cloned());
                            rrsigs.extend(rrset.rrsigs.iter().cloned());
                            break;
                        }
                        EntryKind::Negative { rcode: r, soa, .. } => {
                            rcode = r;
                            if let Some(s) = soa {
                                authorities.push(s);
                            }
                            break;
                        }
                    }
                }
                LookupOutcome::Stale(entry) => {
                    let plan = planner.plan(
                        &LookupOutcome::Stale(entry.clone()),
                        now,
                        &self.inner.shared.estimator.lock().unwrap(),
                    );
                    if plan == crate::planner::Plan::Resolve {
                        return None;
                    }
                    stale = true;
                    ttl = ttl.min(self.inner.config.stale_serve_ttl.max(1));
                    validated &= entry.validated;
                    refresh_keys.push(cache_key);
                    match entry.kind {
                        EntryKind::Positive(rrset) => {
                            if rrset.rr_type == RrType::CNAME && current.rr_type != RrType::CNAME {
                                let target = rrset.cname_target()?.clone();
                                let rec = rrset.records.first()?.clone();
                                answers.push(rec);
                                current.name = target;
                                depth += 1;
                                continue;
                            }
                            answers.extend(rrset.records.iter().cloned());
                            rrsigs.extend(rrset.rrsigs.iter().cloned());
                            break;
                        }
                        EntryKind::Negative { rcode: r, soa, .. } => {
                            rcode = r;
                            if let Some(s) = soa {
                                authorities.push(s);
                            }
                            break;
                        }
                    }
                }
                LookupOutcome::Cname {
                    target, ttl_secs, ..
                } => {
                    // Fetch the actual CNAME record.
                    let ck = CacheKey::plain(current.name.clone(), RrType::CNAME, current.class);
                    match self.inner.shared.cache.lock().unwrap().lookup(&ck, now) {
                        LookupOutcome::Fresh(e) => {
                            validated &= e.validated;
                            if let EntryKind::Positive(rrset) = e.kind {
                                if let Some(rec) = rrset.records.first().cloned() {
                                    answers.push(rec);
                                    rrsigs.extend(rrset.rrsigs.iter().cloned());
                                }
                            }
                            ttl = ttl.min(ttl_secs.max(1));
                            current.name = target;
                            depth += 1;
                            continue;
                        }
                        _ => return None,
                    }
                }
                LookupOutcome::NxDomain { soa, .. } => {
                    rcode = Rcode::NXDOMAIN;
                    if let Some(s) = soa {
                        authorities.push(s);
                    }
                    break;
                }
                LookupOutcome::Miss => return None,
            }
        }

        if ttl == u32::MAX {
            ttl = 0;
        }
        // Queue background refresh of the stale chain.
        if stale {
            for k in refresh_keys {
                self.queue_background_refresh(&k);
            }
        }
        Some(Resolution {
            name: key.name.clone(),
            rr_type: key.rr_type,
            class: key.class,
            rcode,
            answers,
            authorities,
            rrsigs,
            validated,
            ttl,
            from_cache: true,
            stale,
            served_at: now,
        })
    }

    /// The iterative resolution loop (root → TLD → authoritative).
    fn iterative_resolve(&self, key: &QueryKey, ns_depth: usize) -> Result<Resolution> {
        let now = self.inner.clock.now();
        let mut current_name = key.name.clone();
        let current_type = key.rr_type;
        let mut answers: Vec<Record> = Vec::new();
        let mut rrsigs: Vec<Record> = Vec::new();
        let mut authorities: Vec<Record> = Vec::new();
        let mut rcode = Rcode::NOERROR;
        let mut ttl = u32::MAX;
        let mut zone = Name::root();
        let mut servers = self.root_endpoints();
        let mut depth = 0usize;
        let mut referrals = 0usize;
        let mut cached_rrsigs: Vec<Record> = Vec::new();
        let mut minimized: Option<Name> = None;

        loop {
            if depth > self.inner.config.engine.max_cname_depth {
                return Err(Error::internal("CNAME/DNAME loop during resolution"));
            }
            if referrals > self.inner.config.engine.max_referrals {
                return Err(Error::internal("referral loop during resolution"));
            }

            // Cache check during CNAME chasing.
            if depth > 0 {
                let ck = CacheKey::plain(current_name.clone(), current_type, key.class);
                match self.inner.shared.cache.lock().unwrap().lookup(&ck, now) {
                    LookupOutcome::Fresh(entry) => {
                        if let EntryKind::Positive(rrset) = entry.kind {
                            ttl = ttl.min(rrset.ttl);
                            cached_rrsigs.extend(rrset.rrsigs.iter().cloned());
                            answers.extend(rrset.records.iter().cloned());
                            break;
                        }
                    }
                    LookupOutcome::Miss => {}
                    _ => {}
                }
            }

            // Graph bookkeeping.
            {
                let mut g = self.inner.shared.graph.lock().unwrap();
                g.touch(NodeId::Domain(current_name.clone()), NodeKind::Domain, now);
                if zone != Name::root() {
                    g.edge(
                        NodeId::Domain(zone.clone()),
                        NodeId::Domain(current_name.clone()),
                        EdgeKind::DependsOn,
                        now,
                    );
                }
            }

            let query_name = match minimized.take() {
                Some(q) => q,
                None => {
                    if self.inner.config.engine.qname_minimization {
                        minimized_name(&current_name, &zone)
                    } else {
                        current_name.clone()
                    }
                }
            };

            let (resp, endpoint, rtt_ms) =
                self.query_servers(&servers, &query_name, current_type, &zone, key)?;

            {
                let mut est = self.inner.shared.estimator.lock().unwrap();
                est.observe_upstream(&zone, rtt_ms as f64);
            }
            {
                let mut g = self.inner.shared.graph.lock().unwrap();
                g.edge(
                    NodeId::Server(endpoint.ip, endpoint.port),
                    NodeId::Domain(current_name.clone()),
                    EdgeKind::ReachableVia,
                    now,
                );
            }

            match engine::classify_response(&resp, &current_name, current_type, &zone) {
                ResponseKind::Answer {
                    records,
                    rrsigs: sigs,
                } => {
                    let keep: Vec<Record> = records
                        .into_iter()
                        .filter(|r| engine::in_bailiwick(&r.name, &zone))
                        .collect();
                    if keep.is_empty() {
                        return Err(Error::transport("answer out of bailiwick"));
                    }
                    for r in &keep {
                        ttl = ttl.min(r.ttl);
                    }
                    answers.extend(keep);
                    rrsigs.extend(sigs);
                    break;
                }
                ResponseKind::Cname {
                    record,
                    rrsigs: sigs,
                } => {
                    let target = match &record.rdata {
                        RData::Cname(t) => t.clone(),
                        _ => return Err(Error::internal("classify said CNAME but it is not")),
                    };
                    ttl = ttl.min(record.ttl);
                    answers.push(record.clone());
                    rrsigs.extend(sigs);
                    // Cache the CNAME RRset for future queries.
                    let mut set =
                        RrSet::new(record.name.clone(), RrType::CNAME, key.class, record.ttl);
                    set.add_record(record);
                    let ck = CacheKey::plain(current_name.clone(), RrType::CNAME, key.class);
                    let inputs = self
                        .inner
                        .shared
                        .estimator
                        .lock()
                        .unwrap()
                        .score_inputs(&current_name, now);
                    self.inner
                        .shared
                        .cache
                        .lock()
                        .unwrap()
                        .insert_positive(&ck, set, now, inputs, false);
                    if !target.is_subdomain_of(&zone) || zone == Name::root() {
                        zone = Name::root();
                        servers = self.root_endpoints();
                    }
                    minimized = None;
                    current_name = target;
                    depth += 1;
                }
                ResponseKind::Dname { record } => {
                    let dname_owner = record.name.clone();
                    let target = match &record.rdata {
                        RData::Dname(t) => t.clone(),
                        _ => return Err(Error::internal("classify said DNAME but it is not")),
                    };
                    let synthesized =
                        engine::synthesize_dname_cname(&current_name, &dname_owner, &target)
                            .ok_or_else(|| Error::wire("bad DNAME synthesis"))?;
                    ttl = ttl.min(record.ttl);
                    let cname = engine::make_cname_record(&current_name, &synthesized, record.ttl);
                    answers.push(cname);
                    current_name = synthesized;
                    if !current_name.is_subdomain_of(&zone) || zone == Name::root() {
                        zone = Name::root();
                        servers = self.root_endpoints();
                    }
                    minimized = None;
                    depth += 1;
                }
                ResponseKind::Negative { rcode: r, soa } => {
                    if r.is_nxdomain() {
                        rcode = r;
                        if let Some(s) = &soa {
                            authorities.push(s.clone());
                            ttl = ttl.min(negative_ttl(s));
                        }
                        let soa_ttl = soa.as_ref().map(negative_ttl).unwrap_or(0);
                        let mut cache = self.inner.shared.cache.lock().unwrap();
                        cache.insert_nxdomain(&query_name, r, soa.clone(), soa_ttl, now);
                        break;
                    }
                    let is_prefix = query_name != current_name;
                    let soa_ttl = soa.as_ref().map(negative_ttl).unwrap_or(0);
                    let inputs = self
                        .inner
                        .shared
                        .estimator
                        .lock()
                        .unwrap()
                        .score_inputs(&query_name, now);
                    {
                        let mut cache = self.inner.shared.cache.lock().unwrap();
                        let ck = CacheKey::plain(query_name.clone(), current_type, key.class);
                        cache.insert_negative(&ck, r, soa.clone(), soa_ttl, now, inputs);
                    }
                    if is_prefix {
                        // exist; query one label deeper.
                        minimized = Some(deepen_minimized(&current_name, &query_name));
                        continue;
                    }
                    rcode = r;
                    if let Some(s) = &soa {
                        authorities.push(s.clone());
                        ttl = ttl.min(negative_ttl(s));
                    }
                    break;
                }
                ResponseKind::Referral {
                    zone: new_zone,
                    ns,
                    glue,
                } => {
                    referrals += 1;
                    if !new_zone.is_strict_subdomain_of(&zone) {
                        return Err(Error::transport(format!(
                            "referral to {} not below {}",
                            new_zone, zone
                        )));
                    }
                    let ns_names: Vec<Name> = ns
                        .iter()
                        .filter_map(|n| match &n.rdata {
                            RData::Ns(x) => Some(x.clone()),
                            _ => None,
                        })
                        .collect();
                    // Cache the NS RRset and in-bailiwick glue.
                    {
                        let mut cache = self.inner.shared.cache.lock().unwrap();
                        let ns_set =
                            RrSet::from_records(ns.clone(), self.inner.config.cache.max_ttl_cap)
                                .map_err(|e| Error::internal(e.msg))?;
                        let nsk = CacheKey::plain(new_zone.clone(), RrType::NS, key.class);
                        let inputs = self
                            .inner
                            .shared
                            .estimator
                            .lock()
                            .unwrap()
                            .score_inputs(&new_zone, now);
                        cache.insert_positive(&nsk, ns_set, now, inputs, false);
                        for g in &glue {
                            // Only in-bailiwick glue is cached; out-of-zone
                            // glue is used transiently for this resolution.
                            if !engine::in_bailiwick(&g.name, &new_zone) {
                                continue;
                            }
                            if let Ok(set) = RrSet::from_records(
                                vec![g.clone()],
                                self.inner.config.cache.max_ttl_cap,
                            ) {
                                let gk = CacheKey::plain(g.name.clone(), g.rr_type, key.class);
                                cache.insert_positive(&gk, set, now, inputs, false);
                            }
                        }
                    }
                    {
                        let mut g = self.inner.shared.graph.lock().unwrap();
                        g.edge(
                            NodeId::Domain(zone.clone()),
                            NodeId::Domain(new_zone.clone()),
                            EdgeKind::DelegatesTo,
                            now,
                        );
                        for n in &ns {
                            if let RData::Ns(nsname) = &n.rdata {
                                g.edge(
                                    NodeId::Domain(new_zone.clone()),
                                    NodeId::Ns(nsname.clone()),
                                    EdgeKind::ServedBy,
                                    now,
                                );
                            }
                        }
                    }
                    zone = new_zone;
                    minimized = None;

                    let mut endpoints: Vec<Endpoint> = Vec::new();
                    for g in &glue {
                        let is_ns_glue = ns_names.contains(&g.name);
                        if !is_ns_glue && !engine::in_bailiwick(&g.name, &zone) {
                            continue;
                        }
                        match g.rdata {
                            RData::A(ip) => {
                                endpoints.push(Endpoint::new(ip.into(), 53, Proto::Udp))
                            }
                            RData::Aaaa(ip) => {
                                endpoints.push(Endpoint::new(ip.into(), 53, Proto::Udp))
                            }
                            _ => {}
                        }
                    }
                    if endpoints.is_empty() {
                        endpoints = self.resolve_ns_addresses(&ns_names, ns_depth)?;
                    }
                    dedup_endpoints(&mut endpoints);
                    if endpoints.is_empty() {
                        return Err(Error::new(
                            ErrorKind::NoUpstream,
                            format!("no usable servers for zone {zone}"),
                        ));
                    }
                    servers = endpoints;
                }
                ResponseKind::Empty => {
                    if query_name != current_name {
                        minimized = Some(deepen_minimized(&current_name, &query_name));
                        continue;
                    }
                    return Err(Error::transport("empty response from upstream"));
                }
            }
        }

        if ttl == u32::MAX {
            ttl = 0;
        }
        rrsigs.extend(cached_rrsigs);
        Ok(Resolution {
            name: key.name.clone(),
            rr_type: key.rr_type,
            class: key.class,
            rcode,
            answers,
            authorities,
            rrsigs,
            validated: false, // set after DNSSEC validation
            ttl,
            from_cache: false,
            stale: false,
            served_at: now,
        })
    }

    /// Resolve the addresses of NS names for the next delegation level.
    fn resolve_ns_addresses(&self, ns_names: &[Name], ns_depth: usize) -> Result<Vec<Endpoint>> {
        if ns_depth >= self.inner.config.engine.max_ns_depth {
            return Ok(Vec::new());
        }
        let mut endpoints = Vec::new();
        for ns in ns_names {
            if let Some(ips) = self.resolve_host_addresses(ns, ns_depth + 1) {
                for ip in ips {
                    endpoints.push(Endpoint::new(ip, 53, Proto::Udp));
                }
            }
            if endpoints.len() >= 16 {
                break;
            }
        }
        Ok(endpoints)
    }

    /// Resolve a hostname to IP addresses (cache first, then A/AAAA).
    fn resolve_host_addresses(&self, name: &Name, ns_depth: usize) -> Option<Vec<IpAddr>> {
        let now = self.inner.clock.now();
        let mut out = Vec::new();
        for t in [RrType::A, RrType::AAAA] {
            let key = QueryKey {
                name: name.clone(),
                rr_type: t,
                class: RrClass::IN,
                ecs: None,
                want_dnssec: false,
                cd: false,
            };
            if let Ok(res) = self.resolve_inner(&key, ns_depth) {
                for r in res.answers {
                    match r.rdata {
                        RData::A(ip) => out.push(IpAddr::V4(ip)),
                        RData::Aaaa(ip) => out.push(IpAddr::V6(ip)),
                        _ => {}
                    }
                }
            }
            if !out.is_empty() {
                break;
            }
        }
        let _ = now;
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    /// Send the query to the best-ranked servers until one answers.
    fn query_servers(
        &self,
        servers: &[Endpoint],
        qname: &Name,
        qtype: RrType,
        zone: &Name,
        key: &QueryKey,
    ) -> Result<(Message, Endpoint, u64)> {
        if servers.is_empty() {
            return Err(Error::new(ErrorKind::NoUpstream, "no servers to query"));
        }
        let now = self.inner.clock.now();
        let ranked = {
            let sel = self.inner.shared.selector.lock().unwrap();
            sel.sort_by_cost(servers, now, self.inner.config.engine.retransmit_budget)
        };

        let mut last_err: Option<Error> = None;
        let mut total_attempts = 0u32;
        let max_servers = servers
            .len()
            .min(self.inner.config.engine.max_servers_tried.max(1));
        for (endpoint, _) in ranked.into_iter().take(max_servers) {
            let mut attempts = 0u32;
            while attempts < self.inner.config.engine.max_attempts_per_server {
                if total_attempts >= self.inner.config.engine.max_total_attempts {
                    break;
                }
                total_attempts += 1;
                attempts += 1;
                self.inner
                    .stats
                    .upstream_queries
                    .fetch_add(1, Ordering::Relaxed);
                let id = self.with_rng(|rng| (rng.next_u32() & 0xffff) as u16);
                let edns = EdnsSpec {
                    udp_size: self.inner.config.engine.edns_udp_size,
                    dnssec_ok: self.inner.config.engine.dnssec || key.want_dnssec,
                    ecs: ecs_option(key),
                    client_cookie: None,
                };
                let q = self.with_rng(|rng| {
                    engine::build_query(
                        id,
                        qname,
                        qtype,
                        false,
                        Some(&edns),
                        self.inner.config.engine.use_0x20,
                        rng,
                    )
                });

                let t0 = Instant::now();
                let resp_bytes = match self.inner.transports.exchange(
                    &endpoint,
                    &q.bytes,
                    self.inner.config.engine.timeout_ms,
                ) {
                    Ok(b) => b,
                    Err(e) => {
                        last_err = Some(e.clone());
                        self.inner
                            .stats
                            .upstream_timeouts
                            .fetch_add(1, Ordering::Relaxed);
                        self.inner
                            .shared
                            .selector
                            .lock()
                            .unwrap()
                            .record_timeout(endpoint, now);
                        continue;
                    }
                };
                let rtt_ms = t0.elapsed().as_millis() as u64;

                let msg = match Message::parse(&resp_bytes) {
                    Ok(m) => m,
                    Err(e) => {
                        last_err = Some(e);
                        continue;
                    }
                };
                // Anti-spoofing: ID and question must match.
                let query_msg = Message::parse(&q.bytes).unwrap_or_default();
                if !response_matches_query(&query_msg, &msg) {
                    continue;
                }

                // Truncated over UDP → retry over TCP.
                if msg.is_truncated() && self.inner.config.engine.tcp_fallback {
                    let tcp_ep = Endpoint {
                        proto: Proto::Tcp,
                        ..endpoint
                    };
                    if let Ok(b) = self.inner.transports.exchange(
                        &tcp_ep,
                        &q.bytes,
                        self.inner.config.engine.timeout_ms,
                    ) {
                        if let Ok(m) = Message::parse(&b) {
                            if response_matches_query(&query_msg, &m) {
                                self.inner.shared.selector.lock().unwrap().record_success(
                                    tcp_ep,
                                    rtt_ms as f64,
                                    now,
                                );
                                return Ok((m, tcp_ep, rtt_ms));
                            }
                        }
                    }
                }

                if msg.flags.rcode == Rcode::SERVFAIL {
                    self.inner.stats.servfails.fetch_add(1, Ordering::Relaxed);
                    self.inner
                        .shared
                        .selector
                        .lock()
                        .unwrap()
                        .record_servfail(endpoint, now);
                    self.inner
                        .shared
                        .estimator
                        .lock()
                        .unwrap()
                        .observe_failure(qname);
                    last_err = Some(Error::new(ErrorKind::Servfail, "upstream SERVFAIL"));
                    continue;
                }

                self.inner.shared.selector.lock().unwrap().record_success(
                    endpoint,
                    rtt_ms as f64,
                    now,
                );
                let _ = zone;
                return Ok((msg, endpoint, rtt_ms));
            }
        }
        Err(last_err.unwrap_or_else(|| Error::new(ErrorKind::Timeout, "no upstream answered")))
    }

    /// Populate the cache from a wire resolution.
    fn cache_resolution(&self, key: &QueryKey, res: &Resolution, now: Ts) {
        // Group answer records by (name, type).
        let mut groups: BTreeMap<(Name, RrType), Vec<Record>> = BTreeMap::new();
        for r in &res.answers {
            groups
                .entry((r.name.clone(), r.rr_type))
                .or_default()
                .push(r.clone());
        }
        let inputs = self
            .inner
            .shared
            .estimator
            .lock()
            .unwrap()
            .score_inputs(&res.name, now);
        let mut cache = self.inner.shared.cache.lock().unwrap();
        for ((name, rr_type), recs) in groups {
            if rr_type == RrType::RRSIG {
                continue;
            }
            let Ok(mut set) = RrSet::from_records(recs, self.inner.config.cache.max_ttl_cap) else {
                continue;
            };
            set.validated = res.validated;
            // Attach matching RRSIGs (type_covered == rr_type).
            for sig in &res.rrsigs {
                if let RData::Rrsig { type_covered, .. } = &sig.rdata {
                    if *type_covered == rr_type {
                        set.add_rrsig(sig.clone());
                    }
                }
            }
            let ck = CacheKey::plain(name, rr_type, key.class);
            cache.insert_positive(&ck, set, now, inputs, res.validated);
        }
        // Negative answers.
        if res.rcode.is_nxdomain() {
            let soa_ttl = res
                .authorities
                .iter()
                .find(|r| r.rr_type == RrType::SOA)
                .map(negative_ttl)
                .unwrap_or(0);
            cache.insert_nxdomain(
                &res.name,
                res.rcode,
                res.authorities
                    .iter()
                    .find(|r| r.rr_type == RrType::SOA)
                    .cloned(),
                soa_ttl,
                now,
            );
        } else if res.answers.is_empty() {
            let soa_ttl = res
                .authorities
                .iter()
                .find(|r| r.rr_type == RrType::SOA)
                .map(negative_ttl)
                .unwrap_or(0);
            let ck = CacheKey::plain(res.name.clone(), res.rr_type, res.class);
            cache.insert_negative(
                &ck,
                res.rcode,
                res.authorities
                    .iter()
                    .find(|r| r.rr_type == RrType::SOA)
                    .cloned(),
                soa_ttl,
                now,
                inputs,
            );
        }
        drop(cache);
    }

    /// Queue a background refresh for a cache key (from serve-stale or
    /// prefetch decisions).
    pub fn queue_background_refresh(&self, key: &CacheKey) {
        {
            let mut cache = self.inner.shared.cache.lock().unwrap();
            if !cache.mark_refreshing(key) {
                return;
            }
        }
        self.inner.stats.prefetches.fetch_add(1, Ordering::Relaxed);
        let this = self.clone();
        let key = key.clone();
        std::thread::spawn(move || {
            let _ = this.refresh_key(key.clone());
            // Clear the refreshing flag and reap the result.
            this.inner
                .shared
                .cache
                .lock()
                .unwrap()
                .lookup(&key, this.inner.clock.now());
        });
    }

    fn refresh_key(&self, key: CacheKey) -> Result<()> {
        let qk = QueryKey {
            name: key.name.clone(),
            rr_type: key.rr_type,
            class: key.class,
            ecs: key.ecs.clone(),
            want_dnssec: self.inner.config.engine.dnssec,
            cd: false,
        };
        let res = self.resolve_inner(&qk, 0)?;
        let now = self.inner.clock.now();
        self.cache_resolution(&qk, &res, now);
        Ok(())
    }

    fn root_endpoints(&self) -> Vec<Endpoint> {
        if self.inner.config.engine.root_servers.is_empty() {
            return engine::root_endpoints();
        }
        self.inner
            .config
            .engine
            .root_servers
            .iter()
            .map(|ip| Endpoint::new(*ip, 53, Proto::Udp))
            .collect()
    }

    // -----------------------------------------------------------------
    // Maintenance
    // -----------------------------------------------------------------

    /// Spawn the background maintenance task (cache sweep, graph prune,
    /// predictive prefetch). Returns the thread handle.
    pub fn spawn_maintenance(&self) -> std::thread::JoinHandle<()> {
        let this = self.clone();
        let interval = self.inner.config.maintenance_interval_ms;
        #[cfg(feature = "persist")]
        let save_interval = self
            .inner
            .config
            .persist
            .as_ref()
            .map(|p| p.save_interval_ms)
            .unwrap_or(0);
        std::thread::spawn(move || {
            #[cfg(feature = "persist")]
            let mut last_save = std::time::Instant::now();
            loop {
                std::thread::sleep(std::time::Duration::from_millis(interval));
                let r = &this;
                let now = r.inner.clock.now();
                r.inner.shared.cache.lock().unwrap().sweep(now);
                r.inner.shared.graph.lock().unwrap().prune(now, 0);
                let candidates = {
                    let mut cache = r.inner.shared.cache.lock().unwrap();
                    let est = r.inner.shared.estimator.lock().unwrap();
                    cache.prefetch_candidates(now, |apex, horizon| {
                        est.probability(apex, now, horizon)
                    })
                };
                for key in candidates
                    .into_iter()
                    .take(r.inner.config.max_prefetch_per_tick)
                {
                    r.queue_background_refresh(&key);
                }
                #[cfg(feature = "persist")]
                if save_interval > 0 && last_save.elapsed().as_millis() as u64 >= save_interval {
                    let _ = r.persist_cache();
                    last_save = std::time::Instant::now();
                }
            }
        })
    }

    /// A snapshot of the resolver's live counters.
    pub fn stats_snapshot(&self) -> StatsSnapshot {
        self.inner.stats.snapshot()
    }

    /// Write the current cache to the configured persistent tier. Returns
    /// the number of entries saved (0 when no tier is configured).
    #[cfg(feature = "persist")]
    pub fn persist_cache(&self) -> Result<usize> {
        let Some(p) = &self.inner.config.persist else {
            return Ok(0);
        };
        let now = self.inner.clock.now();
        let unix = (now / 1_000_000_000) as i64;
        let cache = self.inner.shared.cache.lock().unwrap();
        crate::cache::persist::save_to(&cache, &p.path, unix)?;
        Ok(cache.len())
    }
}

impl Resolver {
    /// Resolve the addresses of a name directly (used by tests).
    pub fn resolve_addresses(&self, name: &Name) -> Vec<IpAddr> {
        self.resolve_host_addresses(name, 0).unwrap_or_default()
    }
}

/// RFC 9156: the minimal name to query for `qname` given the current zone.
/// Returns the suffix of `qname` exactly one label deeper than `zone`
/// (or the full `qname` when it is already that deep).
fn minimized_name(qname: &Name, zone: &Name) -> Name {
    let zlabels = zone.label_count();
    let nlabels = qname.label_count();
    if nlabels <= zlabels {
        return qname.clone();
    }
    // Take the last (zlabels + 1) labels of qname.
    let keep = zlabels + 1;
    let skip = nlabels - keep;
    let labels = qname.labels();
    let mut out: Vec<u8> = Vec::with_capacity(64);
    for l in &labels[skip..] {
        out.push(l.len() as u8);
        out.extend_from_slice(l);
    }
    out.push(0);
    Name::from_wire(&out, 0)
        .map(|(n, _)| n)
        .unwrap_or_else(|_| qname.clone())
}

/// The next QNAME-minimized query: one label deeper than the current
/// minimized prefix, still a suffix of `qname`. Used when a prefix answer
/// is NODATA/empty and the full qname has not been reached yet.
fn deepen_minimized(qname: &Name, current: &Name) -> Name {
    let qlabels = qname.label_count();
    let clabels = current.label_count();
    if clabels >= qlabels {
        return qname.clone();
    }
    let keep = clabels + 1;
    let skip = qlabels - keep;
    let labels = qname.labels();
    let mut out: Vec<u8> = Vec::with_capacity(64);
    for l in &labels[skip..] {
        out.push(l.len() as u8);
        out.extend_from_slice(l);
    }
    out.push(0);
    Name::from_wire(&out, 0)
        .map(|(n, _)| n)
        .unwrap_or_else(|_| qname.clone())
}

/// RFC 2308: the negative TTL is min(SOA TTL, SOA MINIMUM).
fn negative_ttl(soa: &Record) -> u32 {
    let minimum = match &soa.rdata {
        RData::Soa { minimum, .. } => *minimum,
        _ => 0,
    };
    soa.ttl.min(minimum)
}

/// Remove duplicate endpoints (same address + transport).
fn dedup_endpoints(endpoints: &mut Vec<Endpoint>) {
    let mut seen = std::collections::HashSet::new();
    endpoints.retain(|ep| seen.insert((ep.ip, ep.port, ep.proto)));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    #[test]
    fn minimized_name_steps() {
        let q = Name::from_ascii("www.example.com").unwrap();
        let root = Name::root();
        assert_eq!(minimized_name(&q, &root).to_ascii(), "com");
        let com = Name::from_ascii("com").unwrap();
        assert_eq!(minimized_name(&q, &com).to_ascii(), "example.com");
        let example = Name::from_ascii("example.com").unwrap();
        assert_eq!(minimized_name(&q, &example).to_ascii(), "www.example.com");
    }

    #[test]
    fn deepen_minimized_steps_toward_qname() {
        let q = Name::from_ascii("ns1.ams1.afilias-nst.info").unwrap();
        let info = Name::from_ascii("info").unwrap();
        let a1 = deepen_minimized(&q, &info);
        assert_eq!(a1.to_ascii(), "afilias-nst.info");
        let a2 = deepen_minimized(&q, &a1);
        assert_eq!(a2.to_ascii(), "ams1.afilias-nst.info");
        let a3 = deepen_minimized(&q, &a2);
        assert_eq!(a3.to_ascii(), "ns1.ams1.afilias-nst.info");
        // At the full qname, deepening is idempotent (loop terminates).
        let a4 = deepen_minimized(&q, &a3);
        assert_eq!(a4, q);
    }

    #[test]
    fn negative_ttl_uses_min() {
        let mut soa = Record {
            name: Name::from_ascii("example.com").unwrap(),
            rr_type: RrType::SOA,
            class: RrClass::IN,
            ttl: 3600,
            rdata: RData::Soa {
                mname: Name::from_ascii("ns1.example.com").unwrap(),
                rname: Name::from_ascii("host.example.com").unwrap(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 86400,
                minimum: 300,
            },
        };
        assert_eq!(negative_ttl(&soa), 300);
        soa.ttl = 60;
        assert_eq!(negative_ttl(&soa), 60);
    }

    #[test]
    fn resolver_constructs() {
        let r = Resolver::new(ResolverConfig::default());
        assert!(r.shared().cache.lock().unwrap().is_empty());
        let _ = now();
    }

    #[test]
    fn handle_query_forms_response() {
        let r = Resolver::new(ResolverConfig::default());
        let mut q = Message::query(
            1,
            Name::from_ascii("nonexistent.invalid").unwrap(),
            RrType::A,
            true,
        );
        q.id = 0xbeef;
        let resp = r.handle_query(&q, Some("127.0.0.1".parse().unwrap()));
        assert!(resp.flags.qr);
        assert_eq!(resp.id, 0xbeef);
        assert_eq!(resp.questions, q.questions);
        // The outcome depends on network availability: SERVFAIL when no
        // upstream is reachable, NXDOMAIN when the real DNS is reachable
        // (`.invalid` is reserved and never delegated). Either is a valid
        // response; the important thing is the plumbing works.
        assert!(matches!(
            resp.flags.rcode,
            Rcode::SERVFAIL | Rcode::NXDOMAIN | Rcode::REFUSED
        ));
    }
}
