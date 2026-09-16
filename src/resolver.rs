//! The recursive resolver: shared state, the resolution loop, cache
//! integration, coalescing, and background maintenance.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use crate::alias::{AliasConfig, AliasGraph};
use crate::cache::{CacheConfig, CacheKey, EntryKind, LookupOutcome, SemanticCache};
use crate::engine::{self, EdnsSpec, ResponseKind};
use crate::error::{Error, ErrorKind, Result};
use crate::estimator::QueryEstimator;
use crate::message::{HeaderFlags, Message};
use crate::name::Name;
use crate::planner::{PlannerConfig, ResolutionPlanner};
use crate::policy::{PolicyConfig, PolicyEngine, RateLimiter};
use crate::prng::SplitMix64;
use crate::qtype::{Rcode, RrClass, RrType};
use crate::query::{ecs_option, response_matches_query, QueryKey};
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
    pub root_servers: Vec<std::net::SocketAddr>,
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
    /// Maximum concurrent background refreshes across the whole resolver.
    /// Serve-stale hits queue refreshes from the request path, so this is
    /// the bound that keeps a stale-heavy query stream from spawning an
    /// unbounded number of threads.
    pub max_concurrent_refreshes: usize,
    /// Maximum alias entries refreshed alongside one target (see
    /// [`Resolver::refresh_with_dependents`]).
    pub max_chain_refresh: usize,
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
            max_concurrent_refreshes: 8,
            max_chain_refresh: 4,
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
    /// The alias-dependency graph (which cached answers are derived from
    /// which other keys).
    pub aliases: Mutex<AliasGraph>,
    /// The per-client rate limiter.
    pub client_limiter: Mutex<RateLimiter>,
}

/// Table gauges, read with `try_lock`: a `Debug` impl that waits on a lock
/// can deadlock (it runs inside panic messages and while a caller already
/// holds one of these), so a busy table reports `<busy>` instead of blocking.
impl fmt::Debug for SharedState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SharedState(cache={}, estimator={}, selector={}, aliases={}, clients={})",
            gauge(&self.cache, |c| c.len()),
            gauge(&self.estimator, |e| e.len()),
            gauge(&self.selector, |s| s.len()),
            gauge(&self.aliases, |a| a.key_count()),
            gauge(&self.client_limiter, |l| l.len()),
        )
    }
}

/// Format one table's length without ever blocking on its lock.
fn gauge<T>(lock: &Mutex<T>, len: impl Fn(&T) -> usize) -> alloc::string::String {
    match lock.try_lock() {
        Ok(guard) => alloc::format!("{}", len(&guard)),
        Err(_) => "<busy>".to_string(),
    }
}

impl SharedState {
    fn new(config: &ResolverConfig) -> Self {
        Self {
            cache: Mutex::new(SemanticCache::new(config.cache)),
            estimator: Mutex::new(QueryEstimator::new(100_000)),
            selector: Mutex::new(UpstreamSelector::new(4096)),
            aliases: Mutex::new(AliasGraph::new(AliasConfig::default())),
            client_limiter: Mutex::new(RateLimiter::new(
                config.rate_limit.client_capacity,
                config.rate_limit.client_refill_per_sec,
                config.rate_limit.max_client_buckets,
            )),
        }
    }
}

/// Holds one background-refresh slot for as long as the refresh thread
/// lives; releases it on drop, including when that thread unwinds.
struct RefreshSlot(Resolver);

impl Drop for RefreshSlot {
    fn drop(&mut self) {
        self.0.inner.refreshing.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Reseed the query-ID / 0x20 PRNG from OS entropy after this many draws,
/// so an observer who recovered part of the SplitMix64 stream cannot
/// predict far ahead (anti cache-poisoning hardening).
const RNG_RESEED_EVERY: u64 = 4096;

/// A slot that the waiters for one in-flight query block on.
struct Slot {
    result: Mutex<Option<Result<Resolution>>>,
    cv: Condvar,
    /// Set once a result has been published. A slot that is done but still
    /// present in the in-flight table is a slot whose owner could not take
    /// the table lock on its way out; the next claim for that key reaps it.
    done: std::sync::atomic::AtomicBool,
}

impl Slot {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            cv: Condvar::new(),
            done: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Publish the outcome and wake every waiter. Idempotent: the first
    /// result wins, so a late publish cannot overwrite an earlier one.
    fn publish(&self, r: Result<Resolution>) {
        let mut guard = self.result.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard = Some(r);
            self.done.store(true, Ordering::Release);
        }
        drop(guard);
        self.cv.notify_all();
    }

    /// Block until the owner publishes.
    fn read(&self) -> Result<Resolution> {
        let mut guard = self.result.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(r) = guard.as_ref() {
                return r.clone();
            }
            guard = self.cv.wait(guard).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// The right to resolve one key — and the obligation to publish a result.
///
/// [`Owner`] publishes from [`Owner::publish`] and, if that never happens
/// (the resolution unwound, or a lock was poisoned), from its `Drop`. That
/// obligation is the whole point: a waiter parked on a slot that nobody
/// completes is a permanently stuck client, and — since the key stays in the
/// in-flight table — every later query for the same name would park on the
/// same dead slot.
struct Owner {
    inner: Arc<ResolverInner>,
    key: QueryKey,
    slot: Arc<Slot>,
    published: bool,
}

impl Owner {
    /// Publish a result and release the key.
    fn publish(mut self, result: Result<Resolution>) {
        self.published = true;
        self.slot.publish(result);
        self.release();
    }

    /// Drop this key from the in-flight table *without blocking*.
    ///
    /// This runs from `Drop`, which may execute while the caller still holds
    /// the table lock (or during an unwind), so it must never block on that
    /// lock: a blocking `Drop` there is a self-deadlock. If the lock is busy,
    /// the entry is reaped later by [`Inflight::claim`], which notices the
    /// slot is done; the table is bounded either way.
    fn release(&self) {
        if let Ok(mut inflight) = self.inner.inflight.try_lock() {
            inflight.slots.remove(&self.key);
        }
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        self.slot
            .publish(Err(Error::internal("resolution aborted before completion")));
        self.release();
    }
}

/// The result of claiming a key.
enum Claim {
    /// This caller owns the resolution.
    Owner(Owner),
    /// Another caller owns it; wait on this slot.
    Waiter(Arc<Slot>),
}

/// Coalescing of identical in-flight resolutions.
///
/// One thread resolves a key, everyone else waits for its result. The table
/// is bounded by `max`: claiming a new key while it is full evicts one slot.
/// That is safe by construction — the evicted owner keeps running and still
/// publishes to the waiters already parked on *its* slot; only the
/// de-duplication entry is lost, so a concurrent duplicate of the evicted key
/// would resolve again (bounded extra work) instead of being joined.
struct Inflight {
    slots: BTreeMap<QueryKey, Arc<Slot>>,
    max: usize,
}

impl Inflight {
    fn new(max: usize) -> Self {
        Self {
            slots: BTreeMap::new(),
            max: max.max(1),
        }
    }

    /// The number of keys currently in flight.
    fn len(&self) -> usize {
        self.slots.len()
    }

    fn claim(&mut self, key: &QueryKey, inner: &Arc<ResolverInner>) -> Claim {
        if let Some(slot) = self.slots.get(key) {
            if !slot.done.load(Ordering::Acquire) {
                return Claim::Waiter(slot.clone());
            }
            // The previous owner finished but could not reap its entry (it
            // was unwinding, or the table lock was busy). Replace it.
            self.slots.remove(key);
        }
        if self.slots.len() >= self.max {
            // O(log n) eviction with no auxiliary structure: which key is
            // dropped does not matter for correctness, only that the table
            // stays bounded.
            self.slots.pop_first();
        }
        let slot = Arc::new(Slot::new());
        self.slots.insert(key.clone(), slot.clone());
        Claim::Owner(Owner {
            inner: inner.clone(),
            key: key.clone(),
            slot: slot.clone(),
            published: false,
        })
    }
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

impl fmt::Debug for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Resolver({:?})", self.inner)
    }
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
    inflight: Mutex<Inflight>,
    /// Live background refreshes (bounded by `max_concurrent_refreshes`).
    refreshing: std::sync::atomic::AtomicU64,
    /// Set by [`Resolver::shutdown`]: background loops exit at their next
    /// tick instead of running until the process dies.
    shutting_down: std::sync::atomic::AtomicBool,
    rng: Mutex<SplitMix64>,
    /// How many draws have been taken from `rng` (drives periodic reseed).
    rng_draws: std::sync::atomic::AtomicU64,
}

/// Configuration summary plus the shared-table gauges; the resolver's own
/// settings (timeouts, capacities, transport list) are what a log line needs.
impl fmt::Debug for ResolverInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ResolverInner(shared={:?}, transports={:?}, dnssec={}, minimization={}, 0x20={}, timeout={}ms, inflight={}, refreshes={})",
            self.shared,
            self.transports,
            self.config.engine.dnssec,
            self.config.engine.qname_minimization,
            self.config.engine.use_0x20,
            self.config.engine.timeout_ms,
            gauge(&self.inflight, |i| i.len()),
            self.refreshing.load(Ordering::Relaxed),
        )
    }
}

impl Resolver {
    /// A resolver with the given configuration.
    pub fn new(config: ResolverConfig) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let rng = SplitMix64::seeded();
        let shared = Arc::new(SharedState::new(&config));
        #[cfg(feature = "persist")]
        if let Some(p) = &config.persist {
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
                config: config.clone(),
                shared,
                policy,
                clock,
                transports: Transports::new(),
                stats: Stats::default(),
                #[cfg(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq"))]
                forwarder_set: Mutex::new(forwarder_set),
                inflight: Mutex::new(Inflight::new(config.max_inflight)),
                refreshing: std::sync::atomic::AtomicU64::new(0),
                shutting_down: std::sync::atomic::AtomicBool::new(false),
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
    ///
    /// This is the library entry point (the server calls
    /// [`handle_query`](Resolver::handle_query) instead, which adds the
    /// client-facing checks). Resolution needs reachable upstreams, so the
    /// example is marked `no_run`:
    ///
    /// ```no_run
    /// use recurse_x::{Name, Resolver, ResolverConfig, RrType};
    ///
    /// let resolver = Resolver::new(ResolverConfig::default());
    /// let res = resolver.resolve(&Name::from_ascii("www.example.com")?, RrType::A)?;
    /// for record in &res.answers {
    ///     println!("{} {}", record.name.to_ascii(), record.rr_type);
    /// }
    /// # Ok::<(), recurse_x::Error>(())
    /// ```
    ///
    /// The returned [`Resolution`] reports whether it was served from cache
    /// (`from_cache`), whether DNSSEC validated it (`validated`), and the
    /// TTL the cache will honour (`ttl`).
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

        let claim = self
            .inner
            .inflight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .claim(key, &self.inner);
        let owner = match claim {
            Claim::Waiter(slot) => {
                self.inner.stats.coalesced.fetch_add(1, Ordering::Relaxed);
                return slot.read();
            }
            Claim::Owner(owner) => owner,
        };

        let result = self.resolve_inner(key, 0);
        owner.publish(result.clone());

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
        let want_dnssec = query.edns.as_ref().map(|e| e.dnssec_ok).unwrap_or(false);
        let mut m = Message::new(query.id);
        m.flags = HeaderFlags {
            qr: true,
            rd: query.flags.rd,
            ra: true,
            // RFC 6840 §5.7: a response must not claim authenticity unless
            // the client asked for it (DO) or explicitly asked about it (AD).
            ad: res.validated && (want_dnssec || query.flags.ad),
            // Echo CD: the client asked us not to check, and that stays
            // visible to it (and to any downstream cache).
            cd: query.flags.cd,
            rcode: res.rcode,
            ..HeaderFlags::default()
        };
        m.questions.clone_from(&query.questions);
        for r in &res.answers {
            let mut rec = r.clone();
            rec.ttl = res.ttl;
            m.answers.push(rec);
        }
        // RRSIGs only when the client asked for DNSSEC.
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
        let mut res = {
            // Forwarding is a mode, not a fallback: if a forwarder is
            // configured, its failure must be reported, never hidden behind
            // an iterative resolution that would bypass the operator's
            // chosen upstream (and its filtering).
            let forwarding = self.inner.forwarder_set.lock().unwrap().is_enabled();
            if forwarding {
                self.forward_resolve(key)?
            } else {
                self.iterative_resolve(key, ns_depth)?
            }
        };
        #[cfg(not(any(feature = "dot", feature = "doh", feature = "doh3", feature = "doq")))]
        let mut res = self.iterative_resolve(key, ns_depth)?;
        res.served_at = now;

        // DNSSEC validation of the wire answer. CD=1 means the client asked
        // us not to check, so the data is returned unvalidated (and the AD
        // bit stays clear) rather than being turned into a failure.
        #[cfg(feature = "dnssec")]
        if self.inner.config.engine.dnssec && !key.cd && !res.answers.is_empty() {
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
        if self.inner.config.engine.dnssec && !key.cd {
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
                                self.link_alias(
                                    &current.name,
                                    &target,
                                    current.rr_type,
                                    current.class,
                                    now,
                                );
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
                                self.link_alias(
                                    &current.name,
                                    &target,
                                    current.rr_type,
                                    current.class,
                                    now,
                                );
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
                            // Cached hits record the alias relation too, so a
                            // chain first seen through the network and later
                            // served from cache keeps the same dependencies.
                            self.link_alias(
                                &current.name,
                                &target,
                                current.rr_type,
                                current.class,
                                now,
                            );
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
        // Queue background refresh of the stale chain — together with the
        // aliases each refreshed entry keeps servable, so the whole chain
        // (not one hop of it) comes back fresh.
        if stale {
            for k in refresh_keys {
                self.refresh_with_dependents(&k, self.inner.config.max_chain_refresh);
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

            let (resp, rtt_ms) = self.query_servers(&servers, &query_name, current_type, key)?;

            {
                let mut est = self.inner.shared.estimator.lock().unwrap();
                est.observe_upstream(&zone, rtt_ms as f64);
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
                    // The answer for (name, type) is now derived from the
                    // target's data: record the dependency so a later change
                    // to the target can pull this alias along.
                    self.link_alias(&current_name, &target, current_type, key.class, now);
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

    /// Send the query to the best-ranked servers until one answers. Returns
    /// the response and the RTT of the exchange that produced it.
    fn query_servers(
        &self,
        servers: &[Endpoint],
        qname: &Name,
        qtype: RrType,
        key: &QueryKey,
    ) -> Result<(Message, u64)> {
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
                                return Ok((m, rtt_ms));
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
                return Ok((msg, rtt_ms));
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
    /// prefetch decisions). Returns whether a refresh was actually queued:
    /// `false` means the key is not cached, is already refreshing, or the
    /// concurrency cap is reached.
    ///
    /// Three bounds apply, because this is reachable from the request path
    /// (a stale hit) as well as from the maintenance tick: the key itself is
    /// marked in flight, the number of concurrent refreshes is capped by
    /// [`ResolverConfig::max_concurrent_refreshes`], and the refresh slot is
    /// released even if the thread unwinds. A refresh that fails resets the
    /// mark and records the failure, so one bad refresh does not disable
    /// prefetch for that entry forever.
    pub fn queue_background_refresh(&self, key: &CacheKey) -> bool {
        {
            let mut cache = self
                .inner
                .shared
                .cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !cache.mark_refreshing(key) {
                return false;
            }
        }
        if !self.acquire_refresh_slot() {
            self.inner
                .shared
                .cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear_refreshing(key);
            return false;
        }
        self.inner.stats.prefetches.fetch_add(1, Ordering::Relaxed);
        let this = self.clone();
        let key = key.clone();
        let _ = std::thread::Builder::new()
            .name("dns-refresh".into())
            .spawn(move || {
                let _slot = RefreshSlot(this.clone());
                match this.refresh_key(key.clone()) {
                    Ok(()) => {}
                    Err(_) => {
                        let now = this.inner.clock.now();
                        this.inner
                            .shared
                            .cache
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .record_refresh_failure(&key, now);
                    }
                }
            });
        true
    }

    /// Take one of the `max_concurrent_refreshes` slots, if any is free.
    fn acquire_refresh_slot(&self) -> bool {
        let max = self.inner.config.max_concurrent_refreshes.max(1) as u64;
        let mut cur = self.inner.refreshing.load(Ordering::Relaxed);
        loop {
            if cur >= max {
                return false;
            }
            match self.inner.refreshing.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(seen) => cur = seen,
            }
        }
    }

    /// Live background refreshes (diagnostics).
    pub fn refreshes_in_flight(&self) -> u64 {
        self.inner.refreshing.load(Ordering::Relaxed)
    }

    /// Record that the CNAME entry at `(name, CNAME)` is only servable while
    /// the data at `(target, rr_type)` is fresh — one alias edge.
    fn link_alias(&self, name: &Name, target: &Name, rr_type: RrType, class: RrClass, now: Ts) {
        let alias = CacheKey::plain(name.clone(), RrType::CNAME, class);
        let data = CacheKey::plain(target.clone(), rr_type, class);
        self.inner
            .shared
            .aliases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .link(&alias, &data, now);
    }

    /// Refresh `key` and the alias entries it keeps servable.
    ///
    /// This is what the alias graph pays for. A CNAME is only useful from
    /// cache while *both* hops are fresh, so refreshing the target's data
    /// while letting the CNAME expire a minute later buys nothing: the next
    /// client query still walks the chain and pays for a resolution. Two
    /// events call this — a predictive prefetch about to refresh a target,
    /// and a serve-stale hit refreshing a chain member — and both go through
    /// the same bounded, de-duplicated refresh path.
    pub fn refresh_with_dependents(&self, key: &CacheKey, max_dependents: usize) {
        self.queue_background_refresh(key);
        let dependents = self
            .inner
            .shared
            .aliases
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .dependents(key);
        let mut queued = 0usize;
        for dep_key in dependents {
            if queued >= max_dependents {
                break;
            }
            if self.queue_background_refresh(&dep_key) {
                queued += 1;
            }
        }
        if queued > 0 {
            self.inner
                .stats
                .propagated
                .fetch_add(queued as u64, Ordering::Relaxed);
        }
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
            .map(|sa| Endpoint::new(sa.ip(), sa.port(), Proto::Udp))
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
            // Sleep in slices so `shutdown()` is noticed within one slice
            // rather than after a full (possibly long) maintenance interval.
            let slice = interval.min(100);
            let mut slept = 0u64;
            while !this.inner.shutting_down.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(slice.max(1)));
                slept += slice.max(1);
                if slept < interval {
                    continue;
                }
                slept = 0;
                let r = &this;
                let now = r.inner.clock.now();
                r.inner
                    .shared
                    .cache
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .sweep(now);
                {
                    let mut aliases = r
                        .inner
                        .shared
                        .aliases
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    aliases.prune(now, 0);
                    r.inner
                        .stats
                        .alias_edges
                        .store(aliases.edge_count() as u64, Ordering::Relaxed);
                }
                let candidates = {
                    let mut cache = r
                        .inner
                        .shared
                        .cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let est = r
                        .inner
                        .shared
                        .estimator
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    cache.prefetch_candidates(now, |apex, horizon| {
                        est.probability(apex, now, horizon)
                    })
                };
                for key in candidates
                    .into_iter()
                    .take(r.inner.config.max_prefetch_per_tick)
                {
                    r.refresh_with_dependents(&key, r.inner.config.max_chain_refresh);
                }
                #[cfg(feature = "persist")]
                if save_interval > 0 && last_save.elapsed().as_millis() as u64 >= save_interval {
                    let _ = r.persist_cache();
                    last_save = std::time::Instant::now();
                }
            }
            // Final flush: a clean shutdown is the best moment to leave a
            // consistent snapshot behind, and the maintenance thread is the
            // only writer.
            #[cfg(feature = "persist")]
            if this.inner.config.persist.is_some() {
                let _ = this.persist_cache();
            }
        })
    }

    /// Ask background work to stop.
    ///
    /// The maintenance loop exits at its next tick (at most 100 ms away, or
    /// one interval if that is shorter), writing a final persistent snapshot
    /// if one is configured. Background refreshes already running are not
    /// cancelled — they are single resolutions with their own timeouts, and
    /// killing a thread mid-resolution is not something Rust does safely;
    /// they finish and then the process can exit.
    pub fn shutdown(&self) {
        self.inner.shutting_down.store(true, Ordering::SeqCst);
    }

    /// Whether a shutdown has been requested.
    pub fn is_shutting_down(&self) -> bool {
        self.inner.shutting_down.load(Ordering::Relaxed)
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

    fn key(name: &str) -> QueryKey {
        QueryKey {
            name: Name::from_ascii(name).unwrap(),
            rr_type: RrType::A,
            class: RrClass::IN,
            ecs: None,
            want_dnssec: false,
            cd: false,
        }
    }

    /// A resolver whose only upstream is a local address nothing listens on:
    /// every resolution fails fast instead of reaching the network.
    fn offline_resolver() -> Resolver {
        let mut cfg = ResolverConfig::default();
        cfg.engine.root_servers = vec!["127.0.0.1:1".parse().unwrap()];
        cfg.engine.timeout_ms = 50;
        cfg.engine.max_total_attempts = 1;
        cfg.engine.max_attempts_per_server = 1;
        Resolver::new(cfg)
    }

    /// A stub upstream that aliases `a.example.com` to `b.example.com` and
    /// serves an address for the target — the smallest real CNAME chain.
    fn stub_cname_server() -> std::net::SocketAddr {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                let Ok((n, src)) = sock.recv_from(&mut buf) else {
                    continue;
                };
                let Ok(q) = Message::parse(&buf[..n]) else {
                    continue;
                };
                let Some(question) = q.question() else {
                    continue;
                };
                let mut m = Message::new(q.id);
                m.flags.qr = true;
                m.flags.aa = true;
                m.flags.ra = true;
                m.flags.rd = q.flags.rd;
                m.questions.clone_from(&q.questions);
                let owner = question.qname.clone();
                if owner.to_ascii() == "a.example.com" && question.qtype == RrType::A {
                    m.answers.push(Record {
                        name: owner,
                        rr_type: RrType::CNAME,
                        class: RrClass::IN,
                        ttl: 60,
                        rdata: RData::Cname(Name::from_ascii("b.example.com").unwrap()),
                    });
                } else if owner.to_ascii() == "b.example.com" && question.qtype == RrType::A {
                    m.answers.push(Record {
                        name: owner,
                        rr_type: RrType::A,
                        class: RrClass::IN,
                        ttl: 60,
                        rdata: RData::A("192.0.2.7".parse().unwrap()),
                    });
                }
                if let Ok(bytes) = m.to_bytes() {
                    let _ = sock.send_to(&bytes, src);
                }
            }
        });
        addr
    }

    /// Resolving through a CNAME must leave the alias relation behind, and
    /// refreshing the target must pull the alias along — the two halves of
    /// the chain-coherence feature.
    #[test]
    fn cname_resolution_records_and_uses_the_alias_edge() {
        let mut cfg = ResolverConfig::default();
        cfg.engine.root_servers = vec![stub_cname_server()];
        cfg.engine.timeout_ms = 1_000;
        let r = Resolver::new(cfg);

        let name = Name::from_ascii("a.example.com").unwrap();
        let res = r.resolve(&name, RrType::A).unwrap();
        assert_eq!(res.answers.len(), 2, "CNAME plus the target's A record");

        let alias = CacheKey::plain(name.clone(), RrType::CNAME, RrClass::IN);
        let data = CacheKey::plain(
            Name::from_ascii("b.example.com").unwrap(),
            RrType::A,
            RrClass::IN,
        );
        let shared = r.shared();
        {
            let aliases = shared.aliases.lock().unwrap();
            assert_eq!(aliases.edge_count(), 1);
            assert_eq!(aliases.dependents(&data), vec![alias.clone()]);
            assert_eq!(aliases.depends_on(&alias), vec![data.clone()]);
        }
        {
            let cache = shared.cache.lock().unwrap();
            assert!(cache.len() >= 2, "the chain must be cached");
        }

        // Refreshing the target queues the alias with it.
        r.refresh_with_dependents(&data, 4);
        assert!(r.stats().propagated.load(Ordering::Relaxed) >= 1);
    }

    /// Join a thread with a deadline, so a broken shutdown fails the test
    /// instead of hanging the suite.
    fn join_within(handle: std::thread::JoinHandle<()>, secs: u64) -> bool {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = handle.join();
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(secs))
            .is_ok()
    }

    /// The maintenance loop must exit on request rather than running until
    /// the process dies.
    #[test]
    fn maintenance_loop_stops_on_shutdown() {
        let cfg = ResolverConfig {
            maintenance_interval_ms: 1_000,
            ..ResolverConfig::default()
        };
        let r = Resolver::new(cfg);
        let handle = r.spawn_maintenance();
        // Give the loop a moment to reach its first sleep.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!r.is_shutting_down());
        r.shutdown();
        assert!(r.is_shutting_down());
        assert!(
            join_within(handle, 5),
            "a 1s maintenance interval must not delay shutdown by more than one slice"
        );
    }

    /// A clean shutdown is the last chance to leave a consistent snapshot,
    /// so the maintenance thread writes one before it exits.
    #[cfg(feature = "persist")]
    #[test]
    fn shutdown_writes_a_final_snapshot() {
        let path =
            std::env::temp_dir().join(format!("recursex-shutdown-{}.rxc", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let cfg = ResolverConfig {
            maintenance_interval_ms: 50,
            engine: crate::resolver::EngineConfig {
                root_servers: vec![stub_cname_server()],
                timeout_ms: 1_000,
                ..crate::resolver::EngineConfig::default()
            },
            persist: Some(crate::cache::persist::PersistConfig::new(path.clone(), 0)),
            ..ResolverConfig::default()
        };
        let r = Resolver::new(cfg);
        r.resolve(&Name::from_ascii("a.example.com").unwrap(), RrType::A)
            .unwrap();

        let handle = r.spawn_maintenance();
        r.shutdown();
        assert!(join_within(handle, 5));

        let mut restored = crate::cache::SemanticCache::new(crate::cache::CacheConfig::default());
        let n = crate::cache::persist::load_from(&mut restored, &path, now()).unwrap();
        assert!(n >= 2, "the chain must survive the shutdown, restored {n}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolver_constructs() {
        let r = Resolver::new(ResolverConfig::default());
        assert!(r.shared().cache.lock().unwrap().is_empty());
        let _ = now();
    }

    /// Coalescing: a duplicate key joins the live owner, an abandoned slot
    /// is replaced rather than joined, and the table never exceeds
    /// `max_inflight`.
    #[test]
    fn inflight_coalesces_and_stays_bounded() {
        let cfg = ResolverConfig {
            max_inflight: 2,
            ..ResolverConfig::default()
        };
        let r = Resolver::new(cfg);
        let k1 = key("a.example.com");
        let k2 = key("b.example.com");
        let k3 = key("c.example.com");
        let mut owners = Vec::new();
        {
            let mut inf = r.inner.inflight.lock().unwrap();
            // Abandon an owner without publishing: its entry goes stale.
            match inf.claim(&k1, &r.inner) {
                Claim::Owner(o) => drop(o),
                Claim::Waiter(_) => panic!("first claim must own the key"),
            }
            // The next claim replaces the dead slot instead of joining it…
            match inf.claim(&k1, &r.inner) {
                Claim::Owner(o) => owners.push(o),
                Claim::Waiter(_) => panic!("a done slot must be reaped"),
            }
            // …and now a second claim does join it.
            assert!(matches!(inf.claim(&k1, &r.inner), Claim::Waiter(_)));
            // The table stays bounded when more keys arrive.
            for k in [&k2, &k3] {
                if let Claim::Owner(o) = inf.claim(k, &r.inner) {
                    owners.push(o);
                }
            }
            assert!(inf.len() <= 2, "in-flight table must stay bounded");
        }
        drop(owners);
        assert_eq!(r.inner.inflight.lock().unwrap().len(), 0);
    }

    /// An owner that never publishes (an unwinding resolution, a poisoned
    /// lock) must still release its waiters — otherwise every later query
    /// for that name parks on a slot nobody will ever fill. The table entry
    /// is reaped either by the drop itself or by the next claim.
    #[test]
    fn abandoned_owner_releases_waiters() {
        let r = offline_resolver();
        let k = key("abandoned.example.com");
        let mut inf = r.inner.inflight.lock().unwrap();
        let owner = match inf.claim(&k, &r.inner) {
            Claim::Owner(o) => o,
            Claim::Waiter(_) => panic!("first claim must own the key"),
        };
        let slot = owner.slot.clone();
        // While the owner is alive, a second claim joins its slot.
        assert!(matches!(inf.claim(&k, &r.inner), Claim::Waiter(_)));
        // Abandon it without publishing. `Drop` runs while this test still
        // holds the table lock, so it must not deadlock on it.
        drop(owner);
        // The waiter is released with an error, not left hanging.
        assert!(slot.read().is_err());
        assert!(slot.done.load(Ordering::Acquire));
        // And the next claim gets a live slot, not the dead one.
        let _owner2 = match inf.claim(&k, &r.inner) {
            Claim::Owner(o) => o,
            Claim::Waiter(_) => panic!("dead slot must be reaped"),
        };
        assert!(!inf.slots[&k].done.load(Ordering::Acquire));
        assert_eq!(inf.len(), 1);
    }

    #[test]
    fn handle_query_forms_response() {
        // Hermetic: the upstream is a local port with nothing behind it, so
        // the resolution fails without touching the public DNS.
        let r = offline_resolver();
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
        assert_eq!(resp.flags.rcode, Rcode::SERVFAIL);
    }

    /// The server path must not hand out an answer that exceeds the client's
    /// advertised buffer, and must clear AD unless the client asked.
    #[test]
    fn response_flags_follow_the_request() {
        let r = offline_resolver();
        let q = Message::query(7, Name::from_ascii("example.com").unwrap(), RrType::A, true);
        let res = Resolution {
            name: Name::from_ascii("example.com").unwrap(),
            rr_type: RrType::A,
            class: RrClass::IN,
            rcode: Rcode::NOERROR,
            answers: Vec::new(),
            authorities: Vec::new(),
            rrsigs: Vec::new(),
            validated: true,
            ttl: 60,
            from_cache: false,
            stale: false,
            served_at: now(),
        };
        // No DO, no AD in the request → no AD in the response, even for
        // data we consider authentic (RFC 6840 §5.7).
        let plain = r.build_response(&q, &res);
        assert!(!plain.flags.ad);
        let mut asked = q.clone();
        asked.flags.ad = true;
        assert!(r.build_response(&asked, &res).flags.ad);
        // CD is echoed.
        let mut cd = q.clone();
        cd.flags.cd = true;
        assert!(r.build_response(&cd, &res).flags.cd);
    }
}
