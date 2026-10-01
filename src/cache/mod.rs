//! The multi-tier semantic DNS cache.
//!
//! This is not a `HashMap<Query, Rrset>`. Entries carry a stability model,
//! an admission score, and a tier, and the whole structure is partitioned:
//!
//! * **Hot** — a small, high-score tier served on the hot path.
//! * **Warm** — the main working set.
//! * **Cold** — aged and expired-but-within-the-stale-window entries kept
//!   for serve-stale (RFC 8767) and eviction.
//! * **NXDOMAIN store** — negative answers for a name, shared across types.
//!
//! Admission is score-driven ([`score::score`]); eviction picks the
//! lowest-scored entry by sampling, so the cache is honest about what it
//! keeps. TTLs are authoritative values — the cache never invents TTLs; it
//! only decides *internal* timing (refresh, stale fallback, admission).

#[cfg(feature = "persist")]
pub mod persist;
pub mod score;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use crate::edns::Ecs;
use crate::hazard::HazardConfig;
use crate::name::Name;
use crate::planner::PrefetchPolicy;
use crate::qtype::{Rcode, RrClass, RrType};
use crate::rdata::Record;
use crate::risk::{Consequence, TrustLevel};
use crate::rrset::RrSet;
use crate::stability::StabilityModel;
use crate::time::Ts;

/// Eviction stride for a table that is full of live entries.
const EVICT_STRIDE: usize = 8;

/// Observation weight for a refresh whose answer could not be authenticated.
///
/// A resolver that accepted an answer on the strength of its ID, port and
/// 0x20 case alone has a real but weaker reason to believe the answer is
/// honest than one that verified a signature chain. Feeding both into the
/// refresh model with the same weight would let an off-path attacker buy
/// confidence cheaply; `0.5` makes an unauthenticated observation worth half
/// an authenticated one, and — because forgetting bounds the total exposure
/// — it also halves the ceiling on how much confidence that channel can ever
/// accumulate.
pub const UNVERIFIED_OBSERVATION_TRUST: f64 = 0.5;

/// The external signals a refresh-scheduling decision needs from the estimator.
///
/// The cache stays decoupled from [`crate::estimator`], exactly as it does for
/// admission via [`score::ScoreInputs`]: it is handed the two numbers it cannot
/// compute and decides nothing else on their behalf.
#[derive(Clone, Copy, Debug, Default)]
pub struct RefreshInputs {
    /// The estimator's `P(a query for this zone within the horizon)`.
    ///
    /// The default of `0.0` means "no demand is known", which admits no
    /// candidate. That is the safe direction: a scheduler that guessed demand
    /// would spend the refresh budget on names nobody asks for.
    pub query_probability: f64,
    /// The value of serving this entry from memory rather than resolving it,
    /// in milliseconds.
    ///
    /// This is the `V` of the risk functional, so it is the term that stops the
    /// scheduler from spending the same effort on a record whose absence would
    /// cost nothing as on one whose absence costs a second of latency.
    pub value_ms: f64,
}

/// Which policy drives the refresh budget, and how it may be traded.
///
/// Kept as two knobs rather than a whole [`crate::voi::VoiConfig`] because the
/// other fields of that struct are *derived* — the horizon comes from
/// [`crate::planner::PrefetchPolicy`] and the tail probability from the entry's
/// own model. Copying them into configuration would create a second source for
/// a value that must have exactly one.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RefreshScheduling {
    /// Candidates whose value does not exceed this are not scheduled.
    pub min_value: f64,
    /// Slots reserved per behaviour class, against starvation. See
    /// [`crate::voi::schedule`].
    pub reservation_per_class: usize,
}

impl Default for RefreshScheduling {
    fn default() -> Self {
        Self {
            min_value: 0.0,
            reservation_per_class: 1,
        }
    }
}

/// Mask `addr` to `bits` bits and return exactly `ceil(bits / 8)` bytes.
///
/// The length is part of the partition's identity, not an implementation
/// detail: `Ecs` encodes an address in exactly `ceil(prefix / 8)` octets
/// (RFC 7871 §6), so `10.0.0.0/24` is the three bytes `[10, 0, 0]` and
/// `10.0.0.0/25` is the four bytes `[10, 0, 0, 0]`. A `truncate_to` that
/// kept the input's length would produce `[10, 0, 0, 0]` for the first and
/// `[10, 0, 0, 0]` for the second — equal, and therefore silently *wrong*,
/// because two different partitions would collide into one key. Normalising
/// the length is what keeps distinct scopes distinct.
fn truncate_to(addr: &[u8], bits: u8) -> Vec<u8> {
    let len = usize::from(bits).div_ceil(8);
    let mut out = alloc::vec![0u8; len];
    for (dst, src) in out.iter_mut().zip(addr.iter()) {
        *dst = *src;
    }
    let rem = bits % 8;
    if rem != 0 {
        if let Some(byte) = out.get_mut(len.saturating_sub(1)) {
            *byte &= 0xffu8 << (8 - rem);
        }
    }
    out
}

/// A compact, hashable representation of the ECS network used as part of
/// the cache key (RFC 7871 §7.2: ECS and non-ECS answers must not mix).
///
/// `prefix` is the **scope** of the partition, not the prefix length the
/// client asked with. An answer a server declared valid for a `/24` is
/// stored under `/24` and is reusable by any client whose network falls
/// inside it (RFC 7871 §7.3.1). Storing it under the *requester's* prefix
/// instead — which is what a naive implementation does — is both wrong and
/// wasteful: it fragments the cache along a dimension the servers never
/// asked for, so a `/25` client never sees the `/24` answer that covers it.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct EcsKey {
    /// The address family (1 = IPv4, 2 = IPv6, RFC 7871).
    pub family: u16,
    /// The prefix length of this partition, in bits.
    pub prefix: u8,
    /// The address bytes, truncated to the prefix length.
    pub addr: Vec<u8>,
}

impl EcsKey {
    /// Build a cache key from an ECS option. `None` for family 0 or a
    /// zero-length prefix (those are equivalent to "no ECS").
    pub fn from_ecs(ecs: &Ecs) -> Option<EcsKey> {
        if ecs.family == 0 || ecs.source_prefix == 0 {
            return None;
        }
        Some(EcsKey {
            family: ecs.family,
            prefix: ecs.source_prefix,
            addr: truncate_to(&ecs.address, ecs.source_prefix),
        })
    }

    /// This partition narrowed to `scope` bits.
    ///
    /// `None` means "the global partition", i.e. the key carries no ECS at
    /// all. A response whose SCOPE PREFIX-LENGTH is 0 is valid for every
    /// client (RFC 7871 §7.2.2), so it belongs in the same partition as data
    /// learned without ECS; a separate `/0` key would split one answer in
    /// two and make each half miss for the other half's readers.
    pub fn with_scope(&self, scope: u8) -> Option<EcsKey> {
        let scope = scope.min(self.prefix);
        if scope == 0 {
            return None;
        }
        Some(EcsKey {
            family: self.family,
            prefix: scope,
            addr: truncate_to(&self.addr, scope),
        })
    }

    /// The scope a response may be cached under.
    ///
    /// A server may return a SCOPE PREFIX-LENGTH *longer* than the source
    /// prefix we sent; RFC 7871 §7.3.1 requires the resolver to use the
    /// minimum of the two, because the answer was only ever computed for the
    /// network we asked about. Trusting the longer scope would claim a wider
    /// validity than the resolver has evidence for.
    #[inline]
    pub fn effective_scope(&self, response_scope: u8) -> u8 {
        response_scope.min(self.prefix)
    }
}

/// The partition an answer belongs in, given what the requester asked with
/// and what scope the server declared back.
///
/// `response_scope` is `None` when the response carried no ECS option at
/// all, which RFC 7871 §7.2.2 says to treat as a SCOPE PREFIX-LENGTH of 0 —
/// the server computed an answer without the subnet information, so it is a
/// global answer and belongs in the global partition.
///
/// The three cases this collapses are the whole of ECS cache placement:
///
/// * no ECS in the query → the global partition, whatever came back;
/// * ECS in the query, response scope 0 → the global partition (the server
///   declared the answer is valid for everyone, so sharing it *heals* the
///   fragmentation the other partitions create);
/// * ECS in the query, response scope `S > 0` → the partition of
///   `min(S, P)` bits, which is the widest network the answer is known to be
///   valid for.
pub fn answer_partition(query_ecs: Option<&EcsKey>, response_scope: Option<u8>) -> Option<EcsKey> {
    let ecs = query_ecs?;
    let scope = ecs.effective_scope(response_scope.unwrap_or(0));
    ecs.with_scope(scope)
}

/// The key of a cached entry.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct CacheKey {
    /// The owner name.
    pub name: Name,
    /// The record type.
    pub rr_type: RrType,
    /// The record class.
    pub class: RrClass,
    /// The ECS partition (None = non-ECS data).
    pub ecs: Option<EcsKey>,
}

impl CacheKey {
    /// A non-ECS key.
    pub fn plain(name: Name, rr_type: RrType, class: RrClass) -> Self {
        Self {
            name,
            rr_type,
            class,
            ecs: None,
        }
    }

    /// The same key with a different record type (used for CNAME lookups).
    pub fn with_type(&self, rr_type: RrType) -> Self {
        Self {
            name: self.name.clone(),
            rr_type,
            class: self.class,
            ecs: self.ecs.clone(),
        }
    }

    /// The same key in a different ECS partition (`None` = the global one).
    pub fn with_ecs(&self, ecs: Option<EcsKey>) -> Self {
        Self {
            name: self.name.clone(),
            rr_type: self.rr_type,
            class: self.class,
            ecs,
        }
    }

    /// Whether this key carries an ECS partition.
    pub fn is_ecs(&self) -> bool {
        self.ecs.is_some()
    }
}

/// Which tier an entry lives in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tier {
    /// Small, high-score tier served on the hot path.
    Hot,
    /// The main working set.
    Warm,
    /// Aged or expired-but-within-stale-window entries (serve-stale).
    Cold,
}

/// What a cached entry holds.
#[derive(Clone, Debug)]
pub enum EntryKind {
    /// A positive RRset.
    Positive(RrSet),
    /// A NODATA (NOERROR, empty) or other negative answer for the key.
    Negative {
        /// The negative response code (NXDOMAIN, NOERROR/NODATA, ...).
        rcode: Rcode,
        /// The SOA from the authority section, if present (RFC 2308).
        soa: Option<Record>,
        /// The effective negative TTL in seconds.
        ttl_secs: u32,
    },
}

/// A cache entry.
#[derive(Clone, Debug)]
pub struct CacheEntry {
    /// The key this entry is stored under.
    pub key: CacheKey,
    /// What the entry holds (positive RRset or negative answer).
    pub kind: EntryKind,
    /// When the entry was inserted (or last refreshed).
    pub inserted: Ts,
    /// Absolute expiry (inserted + TTL).
    pub expires: Ts,
    /// Number of times served.
    pub served: u64,
    /// When the entry was last served (admission locality signal).
    pub last_served: Ts,
    /// The stability model of this entry.
    pub stability: StabilityModel,
    /// DNSSEC validation state.
    pub validated: bool,
    /// The last computed admission score.
    pub score: f64,
    /// Current tier.
    pub tier: Tier,
    /// Whether a refresh is currently in flight (prevents duplicate
    /// prefetch).
    pub refreshing: bool,
    /// The estimated resolution cost recorded when the entry was last written,
    /// in milliseconds.
    ///
    /// Kept on the entry rather than re-read from the estimator because the
    /// entry's *behavioural* identity has to be a function of the entry, not of
    /// whatever the estimator happens to believe now. Two entries written under
    /// the same cost estimate must remain comparable even after the estimate
    /// moves, or the refresh ordering would reshuffle every time the estimator
    /// was updated.
    pub cost_ms: f64,
}

impl CacheEntry {
    /// The entry's TTL in seconds.
    pub fn ttl_secs(&self) -> u32 {
        match &self.kind {
            EntryKind::Positive(s) => s.ttl,
            EntryKind::Negative { ttl_secs, .. } => *ttl_secs,
        }
    }

    /// The underlying RRset, if positive.
    pub fn rrset(&self) -> Option<&RrSet> {
        match &self.kind {
            EntryKind::Positive(s) => Some(s),
            _ => None,
        }
    }

    /// The underlying RRset, mutably.
    pub fn rrset_mut(&mut self) -> Option<&mut RrSet> {
        match &mut self.kind {
            EntryKind::Positive(s) => Some(s),
            _ => None,
        }
    }

    /// Remaining TTL in seconds at `now` (floor, never negative).
    pub fn remaining_ttl(&self, now: Ts) -> u32 {
        if self.expires <= now {
            0
        } else {
            (((self.expires - now) / 1_000_000_000).min(u32::MAX as Ts)) as u32
        }
    }

    /// Whether the entry is live at `now`.
    pub fn is_fresh(&self, now: Ts) -> bool {
        now < self.expires
    }

    /// Whether the entry is expired but still within the stale window.
    pub fn is_stale_servable(&self, now: Ts, stale_window_secs: u32) -> bool {
        let end = self
            .expires
            .saturating_add(stale_window_secs as Ts * 1_000_000_000);
        now >= self.expires && now < end
    }

    /// Estimated footprint in bytes.
    pub fn estimated_bytes(&self) -> usize {
        match &self.kind {
            EntryKind::Positive(s) => s.estimated_bytes(),
            EntryKind::Negative { soa, .. } => {
                self.key.name.wire_len()
                    + 64
                    + soa.as_ref().map(|r| r.rdata.wire_len() + 40).unwrap_or(0)
            }
        }
    }

    /// The behavioural class of this entry, as far as the cache can establish
    /// it.
    ///
    /// The role term is the record's consequence class **as an answer**
    /// ([`Consequence::classify`] with `is_delegation_data = false`). The cache
    /// does not record whether a record was learned as delegation data, so a
    /// glue address is classified here as an ordinary address. That is a
    /// deliberate under-classification, and it is safe for the one thing this
    /// value is used for — ordering refresh work — because ordering is not
    /// gating. The consequence that *does* gate service is computed where the
    /// role is actually known (the answer's provenance, see
    /// [`crate::planner::StaleContext`]), and the two must not be conflated:
    /// using an ordering value as a safety input is exactly the class of
    /// mistake the value/risk split in [`crate::cache::score`] exists to
    /// prevent.
    pub fn behavior_class(&self) -> crate::behavior::BehaviorClass {
        crate::behavior::BehaviorClass::from_model(
            &self.stability,
            self.answer_consequence(),
            self.trust_level(),
            self.cost_ms,
        )
    }

    /// The consequence class of the record in this entry, read as an answer.
    ///
    /// See [`CacheEntry::behavior_class`] for why "as an answer" is the honest
    /// reading on this side of the cache and why it is not the classification
    /// that gates anything.
    pub fn answer_consequence(&self) -> Consequence {
        let rr_type = match &self.kind {
            EntryKind::Positive(s) => s.rr_type,
            // A negative answer's staleness is about existence rather than
            // about a value; there is no type to classify, and `Critical` is
            // the honest reading of "this name does not exist" being wrong.
            EntryKind::Negative { .. } => RrType::NS,
        };
        Consequence::classify(rr_type, false)
    }

    /// How well this entry's authenticity was established.
    pub fn trust_level(&self) -> TrustLevel {
        if self.validated {
            TrustLevel::CryptoVerified
        } else {
            TrustLevel::Unverified
        }
    }

    /// The keyed behavioural fingerprint of this entry.
    pub fn fingerprint(
        &self,
        key: &crate::behavior::FingerprintKey,
    ) -> crate::behavior::BehaviorFingerprint {
        crate::behavior::fingerprint_of(key, self.behavior_class(), &self.key.name)
    }
}

/// A per-name NXDOMAIN negative entry (applies to any type below the name).
#[derive(Clone, Debug)]
pub struct NegativeEntry {
    /// Absolute expiry timestamp.
    pub expires: Ts,
    /// The negative response code (always NXDOMAIN here).
    pub rcode: Rcode,
    /// The SOA record, if present.
    pub soa: Option<Record>,
    /// When the entry was inserted.
    pub inserted: Ts,
    /// Number of times served.
    pub served: u64,
}

/// The outcome of a cache lookup.
#[derive(Clone, Debug)]
pub enum LookupOutcome {
    /// A live entry (return the whole entry so the caller can build the
    /// response with the correct TTL and validation flag).
    Fresh(CacheEntry),
    /// An expired-but-servable entry (serve-stale, RFC 8767).
    Stale(CacheEntry),
    /// The exact type is not cached, but a fresh CNAME for the name is.
    Cname {
        /// The CNAME target.
        target: Name,
        /// TTL of the CNAME record in seconds.
        ttl_secs: u32,
        /// Absolute expiry timestamp.
        expires: Ts,
        /// Whether the CNAME was DNSSEC-validated.
        validated: bool,
    },
    /// A live NXDOMAIN for the name.
    NxDomain {
        /// Absolute expiry timestamp.
        expires: Ts,
        /// The SOA record, if present.
        soa: Option<Record>,
    },
    /// Nothing usable.
    Miss,
}

impl LookupOutcome {
    /// Whether the lookup produced a usable result (anything but `Miss`).
    pub fn is_hit(&self) -> bool {
        !matches!(self, LookupOutcome::Miss)
    }
}

/// Cache configuration.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CacheConfig {
    /// Hot tier capacity (entries).
    pub hot_capacity: usize,
    /// Warm tier capacity (entries).
    pub warm_capacity: usize,
    /// Cold tier capacity (entries).
    pub cold_capacity: usize,
    /// NXDOMAIN store capacity (entries, one per name).
    ///
    /// NXDOMAIN has its own bound because it is the cheapest entry to make
    /// an attacker's way: any random name produces one, so without a cap a
    /// stream of distinct nonexistent names would grow memory until the
    /// negative TTLs start expiring.
    pub nx_capacity: usize,
    /// How long an expired entry stays servable (serve-stale, RFC 8767).
    pub stale_window_secs: u32,
    /// Cap on negative TTLs (RFC 2308 §5 recommends ≤ 300 s).
    pub negative_ttl_cap: u32,
    /// Absolute cap on positive TTLs (defends against TTL 2^31-1 abuse).
    pub max_ttl_cap: u32,
    /// Admission score threshold for the hot tier.
    pub hot_admit_score: f64,
    /// Admission score threshold for the warm tier.
    pub warm_admit_score: f64,
    /// Minimum admission score (below this the entry is not cached at all).
    pub min_admit_score: f64,
    /// The admission weights.
    pub weights: score::ScoreWeights,
    /// The refresh model's hazard configuration.
    pub hazard: HazardConfig,
    /// Prefetch: prediction horizon in seconds.
    pub prefetch_horizon_secs: u32,
    /// Prefetch: the `P_LCB(fresh, horizon)` below which a refresh is due.
    pub prefetch_target_freshness: f64,
    /// Prefetch: minimum effective exposure before prediction is used.
    pub prefetch_min_evidence_secs: f64,
    /// How the refresh budget is allocated across due entries.
    pub refresh_scheduling: RefreshScheduling,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            hot_capacity: 2_048,
            warm_capacity: 131_072,
            cold_capacity: 32_768,
            nx_capacity: 65_536,
            // RFC 8767 suggests keeping stale data up to 1-3 days.
            stale_window_secs: 86_400,
            negative_ttl_cap: 300,
            // One week — defends against absurd authoritative TTLs.
            max_ttl_cap: 7 * 86_400,
            hot_admit_score: 0.72,
            warm_admit_score: 0.35,
            min_admit_score: 0.15,
            weights: score::ScoreWeights::default(),
            hazard: HazardConfig::default(),
            prefetch_horizon_secs: 60,
            prefetch_target_freshness: 0.9,
            prefetch_min_evidence_secs: 300.0,
            refresh_scheduling: RefreshScheduling::default(),
        }
    }
}

/// Runtime cache counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Entries in the hot tier.
    pub hot_len: usize,
    /// Entries in the warm tier.
    pub warm_len: usize,
    /// Entries in the cold tier.
    pub cold_len: usize,
    /// Entries in the NXDOMAIN store.
    pub nx_len: usize,
    /// Cache hits.
    pub hits: u64,
    /// Cache misses.
    pub misses: u64,
    /// Stale entries served (RFC 8767).
    pub stale_served: u64,
    /// Entries admitted.
    pub inserts: u64,
    /// Entries evicted.
    pub evictions: u64,
}

/// One capacity-bounded tier of the cache.
///
/// `map` holds the entries; `rank` is a secondary index keyed by
/// `(score rank, key)` so the lowest-scored entry can be found *and removed*
/// in `O(log n)`. The index is what makes eviction affordable: a cache that
/// scans its own contents to choose a victim does `O(n)` work per insert
/// once it is full — `O(n²)` to fill, with no upper bound on the per-insert
/// cost, which is exactly the kind of work an attacker who can force
/// evictions would like the resolver to do.
///
/// Every mutation goes through this type, so `map` and `rank` cannot drift
/// apart: an entry is removed from both together, and a score change is
/// always a remove + insert of the entry carrying the new score.
struct TierMap {
    map: BTreeMap<CacheKey, CacheEntry>,
    rank: BTreeMap<(u64, CacheKey), ()>,
    capacity: usize,
}

impl TierMap {
    fn new(capacity: usize) -> Self {
        Self {
            map: BTreeMap::new(),
            rank: BTreeMap::new(),
            capacity,
        }
    }

    fn capacity(&self) -> usize {
        self.capacity
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the tier holds `key` (test/diagnostic accessor).
    #[cfg(test)]
    fn contains_key(&self, key: &CacheKey) -> bool {
        self.map.contains_key(key)
    }

    fn get_mut(&mut self, key: &CacheKey) -> Option<&mut CacheEntry> {
        self.map.get_mut(key)
    }

    fn values(&self) -> impl Iterator<Item = &CacheEntry> {
        self.map.values()
    }

    /// Insert (or replace) an entry. When the tier is full and the key is
    /// new, the lowest-scored entry is evicted and returned.
    fn insert(&mut self, entry: CacheEntry) -> Option<CacheEntry> {
        let victim = if self.capacity > 0
            && !self.map.contains_key(&entry.key)
            && self.map.len() >= self.capacity
        {
            self.pop_lowest()
        } else {
            None
        };
        let key = entry.key.clone();
        if let Some(old) = self.map.remove(&key) {
            self.rank.remove(&(score::rank_of(old.score), key.clone()));
        }
        self.rank
            .insert((score::rank_of(entry.score), key.clone()), ());
        self.map.insert(key, entry);
        victim
    }

    fn remove(&mut self, key: &CacheKey) -> Option<CacheEntry> {
        let entry = self.map.remove(key)?;
        self.rank
            .remove(&(score::rank_of(entry.score), key.clone()));
        Some(entry)
    }

    /// Remove and return the lowest-scored entry in the tier.
    fn pop_lowest(&mut self) -> Option<CacheEntry> {
        while let Some(((rank, key), _)) = self.rank.pop_first() {
            if let Some(entry) = self.map.remove(&key) {
                debug_assert_eq!(score::rank_of(entry.score), rank);
                return Some(entry);
            }
            // Index entry without a live entry: keep draining. Dropping it
            // here is what keeps `rank` honest rather than leaking.
        }
        None
    }

    /// Keep only the entries the predicate accepts.
    fn retain(&mut self, mut keep: impl FnMut(&CacheKey, &CacheEntry) -> bool) {
        let dead: Vec<CacheKey> = self
            .map
            .iter()
            .filter(|(k, e)| !keep(k, e))
            .map(|(k, _)| k.clone())
            .collect();
        for key in dead {
            self.remove(&key);
        }
    }
}

/// The semantic multi-tier cache.
pub struct SemanticCache {
    config: CacheConfig,
    hot: TierMap,
    warm: TierMap,
    cold: TierMap,
    /// NXDOMAIN store: one entry per name, shared across types.
    nx: BTreeMap<Name, NegativeEntry>,
    stats: CacheStats,
}

/// Sizes only: an entry dump would be megabytes of records and tells a log
/// reader nothing a per-tier count does not.
impl fmt::Debug for SemanticCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SemanticCache(hot={}, warm={}, cold={}, nx={})",
            self.hot.len(),
            self.warm.len(),
            self.cold.len(),
            self.nx.len()
        )
    }
}

impl SemanticCache {
    /// A cache with the given configuration.
    pub fn new(config: CacheConfig) -> Self {
        Self {
            hot: TierMap::new(config.hot_capacity),
            warm: TierMap::new(config.warm_capacity),
            cold: TierMap::new(config.cold_capacity),
            nx: BTreeMap::new(),
            stats: CacheStats::default(),
            config,
        }
    }

    /// The configuration.
    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    /// The current statistics.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hot_len: self.hot.len(),
            warm_len: self.warm.len(),
            cold_len: self.cold.len(),
            nx_len: self.nx.len(),
            ..self.stats
        }
    }

    /// Look up a key.
    ///
    /// # ECS partitions (RFC 7871)
    ///
    /// An entry lives in exactly one partition, and a requester may read a
    /// partition only if it is a *superset* of the requester's network:
    ///
    /// | stored under | readable by |
    /// |--------------|-------------|
    /// | the global partition (no ECS) | any requester |
    /// | an ECS scope of `S` bits | requesters with prefix `P ≥ S` whose address matches the first `S` bits |
    ///
    /// The walk below therefore tries the requester's own partition first,
    /// then progressively broader scopes, and finally the global partition.
    /// The direction matters: an answer computed for a `/24` is reused by a
    /// `/25` client inside it, but a `/25`-specific answer is never handed to
    /// the `/24` — and a client that sent no ECS never sees an ECS partition
    /// at all, because its key carries none.
    ///
    /// Sitting in the requester's walk order is how the stale and tiered
    /// paths stay consistent: a broader scope is a *less* specific claim, so
    /// it is only consulted when the narrower one is absent.
    pub fn lookup(&mut self, key: &CacheKey, now: Ts) -> LookupOutcome {
        if let Some(outcome) = Self::walk_partitions(key, |k| self.lookup_exact(k, now)) {
            return outcome;
        }
        // CNAME redirect for the same name.
        if key.rr_type != RrType::CNAME && key.rr_type != RrType::ANY {
            let cname_key = key.with_type(RrType::CNAME);
            if let Some(outcome) = Self::walk_partitions(&cname_key, |k| self.lookup_cname(k, now))
            {
                return outcome;
            }
        }
        // NXDOMAIN for the name (applies to every type under the name).
        //
        // This store is keyed by name alone, so it *is* the global
        // partition's negative store, and it is reached only at the end of a
        // walk — i.e. after every ECS partition that could answer has been
        // tried. That is what keeps a subnet-scoped NXDOMAIN from being
        // handed to the world; the resolver's insert side refuses to put one
        // there in the first place.
        if let Some(neg) = self.nx.get(&key.name) {
            if now < neg.expires {
                self.stats.hits += 1;
                return LookupOutcome::NxDomain {
                    expires: neg.expires,
                    soa: neg.soa.clone(),
                };
            }
        }
        self.stats.misses += 1;
        LookupOutcome::Miss
    }

    /// Try `f` on the requester's own partition, then on every broader ECS
    /// scope that still contains the requester's network, then on the global
    /// partition. Returns the first `Some`.
    ///
    /// The loop is bounded by the requester's own prefix length (`≤ 32` for
    /// IPv4, `≤ 128` for IPv6), and it exits at the first hit, so a
    /// well-behaved client — one whose answer was cached at exactly the
    /// scope it asked with — pays a single map lookup. The last step is what
    /// makes a scope-0 response (or any response learned without ECS) usable
    /// by everybody, which is the whole point of a scope-0 answer.
    ///
    /// A client that sent **no** ECS carries no partition in its key, so it
    /// never enters the loop and never reads an ECS entry: the asymmetry is
    /// in the key, not in a runtime check that could be forgotten.
    fn walk_partitions<T>(key: &CacheKey, mut f: impl FnMut(&CacheKey) -> Option<T>) -> Option<T> {
        if let Some(hit) = f(key) {
            return Some(hit);
        }
        let ecs = key.ecs.as_ref()?;
        let mut scope = ecs.prefix;
        while scope > 1 {
            scope -= 1;
            let Some(broader) = ecs.with_scope(scope) else {
                break;
            };
            if let Some(hit) = f(&key.with_ecs(Some(broader))) {
                return Some(hit);
            }
        }
        f(&key.with_ecs(None))
    }

    fn lookup_exact(&mut self, key: &CacheKey, now: Ts) -> Option<LookupOutcome> {
        for tier in [Tier::Hot, Tier::Warm, Tier::Cold] {
            let Some(mut entry) = self.tier_map_mut(tier).remove(key) else {
                continue;
            };
            entry.last_served = now;
            entry.served += 1;
            if entry.is_fresh(now) {
                self.stats.hits += 1;
                entry.score = self.score_entry(&entry, now, score::ScoreInputs::default());
                let outcome = LookupOutcome::Fresh(entry.clone());
                self.place(entry);
                return Some(outcome);
            } else if entry.is_stale_servable(now, self.config.stale_window_secs) {
                self.stats.hits += 1;
                self.stats.stale_served += 1;
                let outcome = LookupOutcome::Stale(entry.clone());
                // Park the expired entry in the cold tier, whose whole job
                // is to keep stale-servable data around.
                entry.tier = Tier::Cold;
                self.park(entry);
                return Some(outcome);
            } else {
                // Fully dead: drop it and keep looking.
                self.stats.misses += 1;
            }
        }
        None
    }

    /// The storage behind a tier label.
    fn tier_map(&self, tier: Tier) -> &TierMap {
        match tier {
            Tier::Hot => &self.hot,
            Tier::Warm => &self.warm,
            Tier::Cold => &self.cold,
        }
    }

    fn tier_map_mut(&mut self, tier: Tier) -> &mut TierMap {
        match tier {
            Tier::Hot => &mut self.hot,
            Tier::Warm => &mut self.warm,
            Tier::Cold => &mut self.cold,
        }
    }

    /// The tier a score earns, or `None` when the entry is not worth
    /// caching at all.
    fn tier_for(&self, score: f64) -> Option<Tier> {
        let cfg = &self.config;
        let tier = if score >= cfg.hot_admit_score {
            Tier::Hot
        } else if score >= cfg.warm_admit_score {
            Tier::Warm
        } else if score >= cfg.min_admit_score {
            Tier::Cold
        } else {
            return None;
        };
        // A tier configured with capacity 0 is disabled.
        if self.tier_map(tier).capacity() == 0 {
            let fallback = match tier {
                Tier::Hot => Some(Tier::Warm),
                Tier::Warm => Some(Tier::Cold),
                Tier::Cold => None,
            };
            return fallback.filter(|t| self.tier_map(*t).capacity() > 0);
        }
        Some(tier)
    }

    /// Store an entry in the tier its score earns, evicting (and, for a
    /// full hot/warm tier, demoting) as needed.
    ///
    /// Work per insert is bounded: at most one eviction here plus at most
    /// one in [`SemanticCache::spill`], each `O(log n)`.
    fn place(&mut self, mut entry: CacheEntry) {
        let Some(tier) = self.tier_for(entry.score) else {
            return; // below min_admit_score: not cached at all
        };
        entry.tier = tier;
        if let Some(victim) = self.tier_map_mut(tier).insert(entry) {
            self.spill(victim, tier);
        }
    }

    /// Park an expired entry in the cold tier (serve-stale). The cold tier
    /// is bounded like every other, so this can evict — but it never grows
    /// past its capacity.
    fn park(&mut self, mut entry: CacheEntry) {
        entry.tier = Tier::Cold;
        // An evicted stale entry is simply dropped: stale data is only ever
        // served as a fallback, never migrated upward.
        let _ = self.cold.insert(entry);
    }

    /// One demotion step for an entry evicted from `from`.
    ///
    /// The victim moves one tier down if that tier has room; if it does not,
    /// the lower tier's own lowest-scored entry is dropped. Passing the
    /// victim further down is deliberately not attempted: a recursively
    /// cascading demotion would make the cost of one insert unbounded.
    fn spill(&mut self, victim: CacheEntry, from: Tier) {
        self.stats.evictions += 1;
        let next = match from {
            Tier::Hot => Some(Tier::Warm),
            Tier::Warm => Some(Tier::Cold),
            Tier::Cold => None,
        };
        let Some(next) = next else {
            return; // evicted from cold: dropped
        };
        if self.tier_map(next).capacity() == 0 {
            return;
        }
        let mut v = victim;
        v.tier = next;
        // The lower tier may evict its own lowest to make room; that entry is
        // dropped rather than pushed further down.
        let _dropped = self.tier_map_mut(next).insert(v);
    }

    fn lookup_cname(&mut self, key: &CacheKey, now: Ts) -> Option<LookupOutcome> {
        for tier in [Tier::Hot, Tier::Warm, Tier::Cold] {
            let Some(mut entry) = self.tier_map_mut(tier).remove(key) else {
                continue;
            };
            let target = match &entry.kind {
                EntryKind::Positive(s) => s.cname_target().cloned(),
                _ => None,
            };
            let Some(target) = target else {
                self.place(entry);
                continue;
            };
            if !entry.is_fresh(now) {
                // Expired CNAME: keep it only if still stale-servable.
                if entry.is_stale_servable(now, self.config.stale_window_secs) {
                    entry.tier = Tier::Cold;
                    self.park(entry);
                }
                continue;
            }
            self.stats.hits += 1;
            entry.last_served = now;
            entry.served += 1;
            entry.score = self.score_entry(&entry, now, score::ScoreInputs::default());
            let ttl_secs = entry.ttl_secs();
            let expires = entry.expires;
            let validated = entry.validated;
            let outcome = LookupOutcome::Cname {
                target,
                ttl_secs,
                expires,
                validated,
            };
            self.place(entry);
            return Some(outcome);
        }
        None
    }

    /// Insert a positive RRset under `key`. If the key already exists, the
    /// data is compared and the stability model updated accordingly.
    pub fn insert_positive(
        &mut self,
        key: &CacheKey,
        mut rrset: RrSet,
        now: Ts,
        inputs: score::ScoreInputs,
        validated: bool,
    ) {
        rrset.ttl = rrset.ttl.min(self.config.max_ttl_cap);
        let expires = now.saturating_add(rrset.ttl as Ts * 1_000_000_000);
        let hazard_cfg = self.config.hazard;
        let trust = if validated {
            1.0
        } else {
            UNVERIFIED_OBSERVATION_TRUST
        };

        if let Some(existing) = self.take_entry_any(key) {
            let mut entry = existing;
            let changed = match &entry.kind {
                EntryKind::Positive(old) => !old.same_data(&rrset),
                _ => true,
            };
            entry
                .stability
                .observe_weighted(rrset.ttl, changed, now, trust);
            entry.inserted = now;
            entry.expires = expires;
            // A CD=1 (checking disabled) resolution arrives unvalidated, but
            // it must not erase the validation state of identical data that
            // was validated before.
            entry.validated = validated || (!changed && entry.validated);
            entry.refreshing = false;
            entry.kind = EntryKind::Positive(rrset);
            entry.score = self.score_entry(&entry, now, inputs);
            self.place(entry);
            return;
        }

        let entry_ttl = rrset.ttl;
        let mut entry = CacheEntry {
            key: key.clone(),
            kind: EntryKind::Positive(rrset),
            inserted: now,
            expires,
            served: 0,
            last_served: now,
            stability: StabilityModel::with_config(hazard_cfg, entry_ttl, now),
            validated,
            score: 0.0,
            tier: Tier::Warm,
            refreshing: false,
            cost_ms: inputs.est_cost_ms,
        };
        entry
            .stability
            .observe_weighted(entry_ttl, false, now, trust);
        entry.score = self.score_entry(&entry, now, inputs);
        self.stats.inserts += 1;
        self.place(entry);
    }

    /// Insert a negative (NODATA) answer for `key`.
    pub fn insert_negative(
        &mut self,
        key: &CacheKey,
        rcode: Rcode,
        soa: Option<Record>,
        authoritative_ttl: u32,
        now: Ts,
        inputs: score::ScoreInputs,
    ) {
        let ttl = authoritative_ttl.min(self.config.negative_ttl_cap);
        let expires = now.saturating_add(ttl as Ts * 1_000_000_000);
        let hazard_cfg = self.config.hazard;
        if let Some(existing) = self.take_entry_any(key) {
            let mut entry = existing;
            entry.inserted = now;
            entry.expires = expires;
            entry.stability.observe(ttl, true, now); // replacing data counts as a change
            entry.kind = EntryKind::Negative {
                rcode,
                soa,
                ttl_secs: ttl,
            };
            entry.refreshing = false;
            entry.score = self.score_entry(&entry, now, inputs);
            self.place(entry);
            return;
        }
        let mut entry = CacheEntry {
            key: key.clone(),
            kind: EntryKind::Negative {
                rcode,
                soa,
                ttl_secs: ttl,
            },
            inserted: now,
            expires,
            served: 0,
            last_served: now,
            stability: StabilityModel::with_config(hazard_cfg, ttl, now),
            validated: false,
            score: 0.0,
            tier: Tier::Warm,
            refreshing: false,
            cost_ms: inputs.est_cost_ms,
        };
        entry.score = self.score_entry(&entry, now, inputs);
        self.stats.inserts += 1;
        self.place(entry);
    }

    /// Insert an entry restored from the persistent tier.
    ///
    /// Restoring goes through the same capacity machinery as any other
    /// insert: a snapshot cannot overflow the tiers, and an entry that was
    /// already expired when it was loaded is parked in the cold tier
    /// (serve-stale), where it belongs.
    pub fn restore_entry(&mut self, entry: CacheEntry, now: Ts) {
        if entry.expires <= now {
            self.park(entry);
        } else {
            self.place(entry);
        }
    }

    /// Insert an NXDOMAIN answer for `name`.
    pub fn insert_nxdomain(
        &mut self,
        name: &Name,
        rcode: Rcode,
        soa: Option<Record>,
        authoritative_ttl: u32,
        now: Ts,
    ) {
        let ttl = authoritative_ttl.min(self.config.negative_ttl_cap);
        let expires = now.saturating_add(ttl as Ts * 1_000_000_000);
        match self.nx.get_mut(name) {
            Some(e) => {
                e.expires = e.expires.max(expires);
                e.inserted = now;
                e.soa = soa.or_else(|| e.soa.clone());
            }
            None => {
                if self.nx.len() >= self.config.nx_capacity {
                    // Bounded like every other table: drop entries that are
                    // already expired, then (if the store is genuinely full
                    // of live entries) a stride of them. Never an O(n) scan
                    // per insert.
                    crate::bounded::evict_for_capacity(&mut self.nx, now, EVICT_STRIDE, |e| {
                        e.expires
                    });
                }
                self.nx.insert(
                    name.clone(),
                    NegativeEntry {
                        expires,
                        rcode,
                        soa,
                        inserted: now,
                        served: 0,
                    },
                );
            }
        }
    }

    fn score_entry(&self, entry: &CacheEntry, now: Ts, inputs: score::ScoreInputs) -> f64 {
        score::score(
            &self.config.weights,
            entry.ttl_secs(),
            now,
            entry.last_served,
            &entry.stability,
            &inputs,
            entry.estimated_bytes(),
        )
    }

    /// Re-score an entry with externally provided popularity/cost signals
    /// (called by the resolver as the estimator warms up).
    pub fn rescore(&mut self, key: &CacheKey, inputs: score::ScoreInputs, now: Ts) {
        let Some(mut entry) = self.take_entry_any(key) else {
            return;
        };
        entry.score = score::score(
            &self.config.weights,
            entry.ttl_secs(),
            now,
            entry.last_served,
            &entry.stability,
            &inputs,
            entry.estimated_bytes(),
        );
        self.place(entry);
    }

    /// Remove every entry that is past its stale window (background task).
    ///
    /// The NXDOMAIN store is swept at *expiry*, not at the end of the stale
    /// window: a stale NXDOMAIN is never served (`lookup` requires it to be
    /// fresh), so keeping it longer would only let a stream of random names
    /// grow memory for a day.
    pub fn sweep(&mut self, now: Ts) {
        let stale_window = self.config.stale_window_secs as Ts * 1_000_000_000;
        self.hot
            .retain(|_, e| e.expires.saturating_add(stale_window) >= now);
        self.warm
            .retain(|_, e| e.expires.saturating_add(stale_window) >= now);
        self.cold
            .retain(|_, e| e.expires.saturating_add(stale_window) >= now);
        self.nx.retain(|_, e| e.expires > now);
    }

    /// Record a refresh failure for a key (updates the stability model) and
    /// end the refresh.
    ///
    /// Ending it here is not cosmetic: the `refreshing` flag is what
    /// suppresses duplicate prefetches, so a key left marked after a failed
    /// refresh could never be prefetched again — the entry would sit in the
    /// cache, unreachable by the prefetcher, until it was evicted.
    pub fn record_refresh_failure(&mut self, key: &CacheKey, now: Ts) {
        if let Some(e) = self
            .hot
            .get_mut(key)
            .or_else(|| self.warm.get_mut(key))
            .or_else(|| self.cold.get_mut(key))
        {
            e.stability.record_failure(now);
            e.refreshing = false;
        }
    }

    /// Clear the in-flight mark of a key (a queued refresh that never ran).
    pub fn clear_refreshing(&mut self, key: &CacheKey) {
        if let Some(e) = self
            .hot
            .get_mut(key)
            .or_else(|| self.warm.get_mut(key))
            .or_else(|| self.cold.get_mut(key))
        {
            e.refreshing = false;
        }
    }

    /// Mark a key as refreshing. Returns false if a refresh is already in
    /// flight for this key (deduplicates prefetch).
    pub fn mark_refreshing(&mut self, key: &CacheKey) -> bool {
        if let Some(e) = self
            .hot
            .get_mut(key)
            .or_else(|| self.warm.get_mut(key))
            .or_else(|| self.cold.get_mut(key))
        {
            if e.refreshing {
                return false;
            }
            e.refreshing = true;
            true
        } else {
            false
        }
    }

    /// The observations to spend this tick's refresh budget on, best value
    /// first.
    ///
    /// # Two questions, two answers
    ///
    /// `policy.wants_refresh` answers *whether an entry is due* — a threshold:
    /// its conservative freshness has fallen below the target. This method
    /// answers the question a finite budget actually poses: **where does the
    /// next token buy the most**.
    ///
    /// They are not the same question, and answering the second with the first
    /// costs real value. A threshold can only say "look at this too": it is
    /// blind to how much an observation would *teach* (an entry confirmed a
    /// minute ago carries an observation with almost no exposure and therefore
    /// almost no information), to how much the answer is *worth* (`value_ms`),
    /// and to how much harm the record's class can do. So the due-ness test is
    /// kept as the admissibility filter — an entry that is not due is never a
    /// candidate — and the ordering is the expected reduction in the risk
    /// functional, from [`crate::voi`].
    ///
    /// # What the caller supplies
    ///
    /// `inputs(apex, horizon)` returns the estimator's demand probability for
    /// the zone and the value of a hit in milliseconds. `budget` is the number
    /// of observations the caller can afford (one token each); the selection is
    /// `crate::voi::schedule`, which also applies the per-class reservation.
    ///
    /// Ordering ties by the **keyed behavioural fingerprint** rather than by
    /// the key is not cosmetic. Equal values are the *normal* case at the top of
    /// a tick — entries written at the same instant have identical models — and
    /// ordering them by name makes the order a public function of the query
    /// stream. Every resolver in a fleet would then spend its budget on the same
    /// entries in the same sequence, and an observer who can see a query would
    /// know which entry we look at next, which is the window in which a forged
    /// answer has its best chance of entering the model. See [`crate::behavior`].
    ///
    /// `key` is `None` only for callers with no secret to hold. That reproduces
    /// the correlated order exactly, which is why the resolver never passes
    /// `None`.
    pub fn refresh_schedule<F>(
        &mut self,
        policy: &PrefetchPolicy,
        key: Option<&crate::behavior::FingerprintKey>,
        budget: usize,
        now: Ts,
        inputs: F,
    ) -> Vec<CacheKey>
    where
        F: Fn(&Name, u32) -> RefreshInputs,
    {
        let scheduling = self.config.refresh_scheduling;
        let horizon_secs = policy.horizon_secs as f64;
        let mut candidates: Vec<crate::voi::Candidate<CacheKey>> = Vec::new();
        for map in [&self.hot, &self.warm] {
            for entry in map.values() {
                if !matches!(entry.kind, EntryKind::Positive(_)) {
                    continue;
                }
                if entry.refreshing {
                    continue;
                }
                let apex = entry.key.name.apex();
                let supplied = inputs(&apex, policy.horizon_secs);
                if !policy.wants_refresh(&entry.stability, supplied.query_probability) {
                    continue;
                }
                // The horizon and the tail probability come from the policy and
                // the model rather than from a second copy of the same setting:
                // an admissibility gate and a value that disagreed about the
                // horizon would be pricing a different question than the one
                // they both admitted the entry for.
                let cfg = crate::voi::VoiConfig {
                    horizon_secs,
                    ttl_secs: entry.ttl_secs(),
                    tail_probability: entry.stability.hazard().config().tail_probability(),
                    observation_weight: if entry.validated {
                        1.0
                    } else {
                        UNVERIFIED_OBSERVATION_TRUST
                    },
                    min_value: scheduling.min_value,
                    reservation_per_class: scheduling.reservation_per_class,
                };
                let value = crate::voi::observation_value(
                    &entry.stability,
                    entry.answer_consequence(),
                    entry.trust_level(),
                    supplied.value_ms,
                    now,
                    &cfg,
                );
                let tie_break = match key {
                    Some(k) => entry.fingerprint(k).as_u128(),
                    None => 0,
                };
                candidates.push(crate::voi::Candidate {
                    payload: entry.key.clone(),
                    class: entry.behavior_class(),
                    value,
                    tie_break,
                });
            }
        }
        crate::voi::schedule(
            candidates,
            budget,
            &crate::voi::VoiConfig {
                horizon_secs,
                min_value: scheduling.min_value,
                reservation_per_class: scheduling.reservation_per_class,
                ..crate::voi::VoiConfig::default()
            },
        )
    }

    /// The number of entries across all tiers.
    pub fn len(&self) -> usize {
        self.hot.len() + self.warm.len() + self.cold.len() + self.nx.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over every positive entry (used by the persistent tier and
    /// diagnostics).
    pub fn iter_entries(&self) -> impl Iterator<Item = &CacheEntry> {
        self.hot
            .values()
            .chain(self.warm.values())
            .chain(self.cold.values())
    }

    fn take_entry_any(&mut self, key: &CacheKey) -> Option<CacheEntry> {
        self.hot
            .remove(key)
            .or_else(|| self.warm.remove(key))
            .or_else(|| self.cold.remove(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdata::RData;
    #[cfg(not(feature = "std"))]
    use alloc::format;

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    fn key(name: &str, t: RrType) -> CacheKey {
        CacheKey::plain(Name::from_ascii(name).unwrap(), t, RrClass::IN)
    }

    fn cfg() -> CacheConfig {
        CacheConfig {
            hot_capacity: 4,
            warm_capacity: 8,
            cold_capacity: 4,
            stale_window_secs: 60,
            ..CacheConfig::default()
        }
    }

    #[test]
    fn insert_and_lookup_fresh() {
        let mut cache = SemanticCache::new(cfg());
        let k = key("example.com", RrType::A);
        cache.insert_positive(
            &k,
            RrSet::a("example.com", "192.0.2.1", 300),
            now(),
            score::ScoreInputs::default(),
            false,
        );
        match cache.lookup(&k, now()) {
            LookupOutcome::Fresh(e) => {
                assert_eq!(e.ttl_secs(), 300);
                assert_eq!(e.rrset().unwrap().records.len(), 1);
            }
            other => panic!("expected fresh, got {other:?}"),
        }
    }

    #[test]
    fn expires_and_stale_serving() {
        let mut cache = SemanticCache::new(cfg());
        let k = key("example.com", RrType::A);
        cache.insert_positive(
            &k,
            RrSet::a("example.com", "192.0.2.1", 5),
            now(),
            score::ScoreInputs::default(),
            false,
        );
        assert!(matches!(
            cache.lookup(&k, now() + 4_000_000_000),
            LookupOutcome::Fresh(_)
        ));
        assert!(matches!(
            cache.lookup(&k, now() + 10_000_000_000),
            LookupOutcome::Stale(_)
        ));
        assert!(matches!(
            cache.lookup(&k, now() + 70_000_000_000),
            LookupOutcome::Miss
        ));
    }

    #[test]
    fn cname_redirect_detected() {
        let mut cache = SemanticCache::new(cfg());
        let cname_key = key("www.example.com", RrType::CNAME);
        let mut s = RrSet::new(
            Name::from_ascii("www.example.com").unwrap(),
            RrType::CNAME,
            RrClass::IN,
            300,
        );
        s.add_record(Record {
            name: s.name.clone(),
            rr_type: RrType::CNAME,
            class: RrClass::IN,
            ttl: 300,
            rdata: RData::Cname(Name::from_ascii("cdn.example.net").unwrap()),
        });
        cache.insert_positive(&cname_key, s, now(), score::ScoreInputs::default(), false);
        match cache.lookup(&key("www.example.com", RrType::A), now()) {
            LookupOutcome::Cname { target, .. } => {
                assert_eq!(target.to_ascii(), "cdn.example.net");
            }
            other => panic!("expected cname, got {other:?}"),
        }
    }

    #[test]
    fn negative_and_nxdomain() {
        let mut cache = SemanticCache::new(cfg());
        let k = key("nodata.example.com", RrType::A);
        cache.insert_negative(
            &k,
            Rcode::NOERROR,
            None,
            60,
            now(),
            score::ScoreInputs::default(),
        );
        match cache.lookup(&k, now()) {
            LookupOutcome::Fresh(e) => {
                assert!(matches!(e.kind, EntryKind::Negative { .. }));
            }
            other => panic!("expected negative entry, got {other:?}"),
        }

        cache.insert_nxdomain(
            &Name::from_ascii("missing.example.com").unwrap(),
            Rcode::NXDOMAIN,
            None,
            60,
            now(),
        );
        match cache.lookup(&key("missing.example.com", RrType::AAAA), now()) {
            LookupOutcome::NxDomain { .. } => {}
            other => panic!("expected nxdomain, got {other:?}"),
        }
    }

    /// The cache key an answer for `ip`/`prefix` is filed under when the
    /// server declared `scope`.
    fn partitioned_key(name: &str, ip: &str, prefix: u8, scope: u8) -> CacheKey {
        let ecs = Ecs::ipv4(ip.parse().unwrap(), prefix).unwrap();
        let request = EcsKey::from_ecs(&ecs);
        CacheKey {
            name: Name::from_ascii(name).unwrap(),
            rr_type: RrType::A,
            class: RrClass::IN,
            ecs: answer_partition(request.as_ref(), Some(scope)),
        }
    }

    /// The key a client asking from `ip`/`prefix` looks up with.
    fn requester_key(name: &str, ip: &str, prefix: u8) -> CacheKey {
        let ecs = Ecs::ipv4(ip.parse().unwrap(), prefix).unwrap();
        CacheKey {
            name: Name::from_ascii(name).unwrap(),
            rr_type: RrType::A,
            class: RrClass::IN,
            ecs: EcsKey::from_ecs(&ecs),
        }
    }

    fn address_of(outcome: &LookupOutcome) -> alloc::string::String {
        match outcome {
            LookupOutcome::Fresh(e) => match e.rrset().and_then(|s| s.records.first()) {
                Some(r) => alloc::format!("{:?}", r.rdata),
                None => alloc::string::String::from("<no record>"),
            },
            other => alloc::format!("{other:?}"),
        }
    }

    fn store(cache: &mut SemanticCache, k: &CacheKey, addr: &str) {
        cache.insert_positive(
            k,
            RrSet::a("geo.example.com", addr, 300),
            now(),
            score::ScoreInputs::default(),
            false,
        );
    }

    #[test]
    fn ecs_partitioning() {
        let mut cache = SemanticCache::new(cfg());
        let plain = key("example.com", RrType::A);
        cache.insert_positive(
            &plain,
            RrSet::a("example.com", "192.0.2.1", 300),
            now(),
            score::ScoreInputs::default(),
            false,
        );
        let ecs = Ecs::ipv4("10.0.0.1".parse().unwrap(), 24).unwrap();
        let ecs_key = CacheKey {
            name: Name::from_ascii("example.com").unwrap(),
            rr_type: RrType::A,
            class: RrClass::IN,
            ecs: EcsKey::from_ecs(&ecs),
        };
        cache.insert_positive(
            &ecs_key,
            RrSet::a("example.com", "203.0.113.9", 300),
            now(),
            score::ScoreInputs::default(),
            false,
        );
        match cache.lookup(&ecs_key, now()) {
            LookupOutcome::Fresh(e) => {
                let rr = e.rrset().unwrap().records.first().unwrap();
                assert_eq!(rr.rdata, RData::A("203.0.113.9".parse().unwrap()));
            }
            other => panic!("expected ecs entry, got {other:?}"),
        }
        match cache.lookup(&plain, now()) {
            LookupOutcome::Fresh(e) => {
                let rr = e.rrset().unwrap().records.first().unwrap();
                assert_eq!(rr.rdata, RData::A("192.0.2.1".parse().unwrap()));
            }
            other => panic!("expected plain entry, got {other:?}"),
        }
    }

    /// The regression this whole rule set exists for: an answer computed for
    /// one client subnet must never be readable by a client that sent no ECS.
    ///
    /// The insert side used to ignore the partition entirely and file every
    /// answer under the global key, which meant a resolver that advertised
    /// ECS support was in fact handing subnet-specific answers to everyone.
    #[test]
    fn ecs_answer_is_never_visible_to_a_client_without_ecs() {
        let mut cache = SemanticCache::new(cfg());
        let stored = partitioned_key("geo.example.com", "10.0.0.1", 24, 24);
        assert!(
            stored.is_ecs(),
            "a /24 scope must land in a scoped partition"
        );
        store(&mut cache, &stored, "203.0.113.9");

        match cache.lookup(&key("geo.example.com", RrType::A), now()) {
            LookupOutcome::Miss => {}
            other => panic!("an ECS-scoped answer leaked into the global partition: {other:?}"),
        }
        // The client that asked from the same subnet still hits it.
        assert_ne!(
            address_of(&cache.lookup(&requester_key("geo.example.com", "10.0.0.1", 24), now())),
            "Miss",
        );
    }

    /// A scope a server declares is a *claim about reuse*: everything inside
    /// that network may share the answer, and nothing outside it may.
    #[test]
    fn a_broader_scope_serves_more_specific_clients_only() {
        let mut cache = SemanticCache::new(cfg());
        store(
            &mut cache,
            &partitioned_key("geo.example.com", "10.0.0.0", 24, 24),
            "203.0.113.9",
        );

        // Inside the /24, at any granularity: hit.
        for (ip, prefix) in [("10.0.0.129", 25), ("10.0.0.7", 32), ("10.0.0.0", 24)] {
            let k = requester_key("geo.example.com", ip, prefix);
            assert_ne!(
                address_of(&cache.lookup(&k, now())),
                "Miss",
                "{ip}/{prefix} is inside 10.0.0.0/24 and must reuse the answer"
            );
        }

        // Outside it: a different /24 is a different network, and a /16 client
        // is *broader* than the answer's scope, so it cannot be reused either
        // (we only ever proved the answer for the /24).
        for (ip, prefix) in [("10.0.1.5", 24), ("10.0.0.1", 16)] {
            let k = requester_key("geo.example.com", ip, prefix);
            assert_eq!(
                address_of(&cache.lookup(&k, now())),
                "Miss",
                "{ip}/{prefix} is outside 10.0.0.0/24"
            );
        }
    }

    /// The other direction: a narrow answer is never widened.
    #[test]
    fn a_narrow_scope_is_not_widened_by_the_walk() {
        let mut cache = SemanticCache::new(cfg());
        store(
            &mut cache,
            &partitioned_key("geo.example.com", "10.0.0.0", 25, 25),
            "203.0.113.9",
        );
        let broader = requester_key("geo.example.com", "10.0.0.1", 24);
        assert_eq!(address_of(&cache.lookup(&broader, now())), "Miss");
    }

    /// RFC 7871 §7.2.2: a response with SCOPE 0 — or one with no ECS option at
    /// all — is valid for every client, so it belongs in the global partition
    /// and heals the fragmentation the other partitions create.
    #[test]
    fn scope_zero_is_the_global_partition() {
        let ecs = EcsKey::from_ecs(&Ecs::ipv4("10.0.0.1".parse().unwrap(), 24).unwrap()).unwrap();
        assert!(answer_partition(Some(&ecs), Some(0)).is_none());
        assert!(answer_partition(Some(&ecs), None).is_none());
        assert!(answer_partition(None, Some(24)).is_none());
        assert!(answer_partition(Some(&ecs), Some(24)).is_some());

        let mut cache = SemanticCache::new(cfg());
        // A scope-0 answer for an ECS query is filed globally...
        let stored = partitioned_key("geo.example.com", "10.0.0.1", 24, 0);
        assert!(!stored.is_ecs());
        store(&mut cache, &stored, "203.0.113.9");
        // ...and is therefore readable by both an ECS client and a plain one.
        assert_ne!(
            address_of(&cache.lookup(&requester_key("geo.example.com", "10.0.0.1", 24), now())),
            "Miss",
        );
        assert_ne!(
            address_of(&cache.lookup(&key("geo.example.com", RrType::A), now())),
            "Miss",
        );
    }

    /// A server may not widen an answer beyond the network we asked about.
    #[test]
    fn effective_scope_is_clamped_to_the_source_prefix() {
        let ecs = EcsKey::from_ecs(&Ecs::ipv4("10.0.0.1".parse().unwrap(), 24).unwrap()).unwrap();
        assert_eq!(ecs.effective_scope(32), 24);
        assert_eq!(ecs.effective_scope(16), 16);
        assert_eq!(ecs.effective_scope(0), 0);
    }

    #[test]
    fn with_scope_narrows_the_address_not_just_the_label() {
        let ecs =
            EcsKey::from_ecs(&Ecs::ipv4("10.20.30.40".parse().unwrap(), 32).unwrap()).unwrap();
        let narrow = ecs.with_scope(8).unwrap();
        assert_eq!(narrow.prefix, 8);
        assert_eq!(narrow.addr.first(), Some(&10));
        assert!(
            narrow.addr.iter().skip(1).all(|&b| b == 0),
            "{:?}",
            narrow.addr
        );
        // Narrowing to zero is the global partition, not a `/0` key.
        assert!(ecs.with_scope(0).is_none());
        // Narrowing never *widens*.
        assert_eq!(ecs.with_scope(64).unwrap().prefix, 32);
    }

    #[test]
    fn truncate_to_masks_and_normalises_the_octet_count() {
        // RFC 7871 §6: the address is `ceil(prefix / 8)` octets, so the octet
        // count is part of the partition's identity.
        assert_eq!(truncate_to(&[10, 0, 0, 255], 24), alloc::vec![10, 0, 0]);
        assert_eq!(truncate_to(&[10, 0, 0, 255], 12), alloc::vec![10, 0]);
        assert_eq!(
            truncate_to(&[10, 0, 0, 255], 32),
            alloc::vec![10, 0, 0, 255]
        );
        assert_eq!(truncate_to(&[10, 255, 255, 255], 8), alloc::vec![10]);
        assert_eq!(truncate_to(&[255], 1), alloc::vec![128]);
        assert_eq!(truncate_to(&[1, 2, 3], 0), alloc::vec::Vec::<u8>::new());
        assert_eq!(
            truncate_to(&[1, 2], 64),
            alloc::vec![1, 2, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(truncate_to(&[], 24), alloc::vec![0, 0, 0]);
        // The property that matters for key equality: two addresses in the
        // same prefix produce *byte-identical* keys, whatever octet count
        // they came in with.
        let a = truncate_to(&[10, 0, 0, 0], 24);
        let b = truncate_to(&[10, 0, 0, 128], 24);
        let c = truncate_to(&[10, 0, 0], 24);
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn eviction_respects_capacity() {
        let mut cache = SemanticCache::new(cfg());
        for i in 0..40 {
            let name = format!("host{i}.example.com");
            let k = key(&name, RrType::A);
            cache.insert_positive(
                &k,
                RrSet::a(&name, "192.0.2.1", 300),
                now(),
                score::ScoreInputs {
                    popularity: 0.1,
                    est_cost_ms: 10.0,
                },
                false,
            );
        }
        let total = cache.hot.len() + cache.warm.len() + cache.cold.len();
        assert!(
            total <= cfg().hot_capacity + cfg().warm_capacity + cfg().cold_capacity,
            "cache overflowed: {total}"
        );
    }

    #[test]
    fn due_entries_are_scheduled_and_demand_gates_them() {
        let mut cache = SemanticCache::new(cfg());
        let k = key("hot.example.com", RrType::A);
        let t0 = now() - 5_000_000_000_000;
        for i in 0..6u32 {
            let t = t0 + i as Ts * 1_000_000_000;
            cache.insert_positive(
                &k,
                RrSet::a("hot.example.com", "192.0.2.1", 30),
                t,
                score::ScoreInputs::default(),
                true,
            );
        }
        let policy = PrefetchPolicy {
            horizon_secs: 60,
            target_freshness: 0.999_999,
            min_probability: 0.5,
            min_evidence_secs: 1.0,
        };
        let cands = cache.refresh_schedule(&policy, None, 8, now(), |apex, _| {
            assert_eq!(apex.to_ascii(), "example.com");
            RefreshInputs {
                query_probability: 0.99,
                value_ms: 50.0,
            }
        });
        assert!(cands.iter().any(|c| c.name.to_ascii() == "hot.example.com"));
        // Demand is still a gate on *value*: with no demand, nothing is
        // refreshed even though the freshness criterion is met.
        let no_demand = PrefetchPolicy {
            min_probability: 0.5,
            ..policy
        };
        let cands = cache.refresh_schedule(&no_demand, None, 8, now(), |_, _| RefreshInputs {
            query_probability: 0.0,
            value_ms: 50.0,
        });
        assert!(cands.is_empty());
    }

    #[test]
    fn an_answer_worth_nothing_is_not_worth_observing() {
        // `value_ms` is the `V` of the risk functional. A record whose absence
        // costs no latency is not worth a refresh token however uncertain its
        // model is — the threshold rule could not see that difference, which is
        // the whole reason the ordering is a value.
        let mut cache = SemanticCache::new(cfg());
        let k = key("cheap.example.com", RrType::A);
        let t0 = now() - 5_000_000_000_000;
        for i in 0..4u32 {
            cache.insert_positive(
                &k,
                RrSet::a("cheap.example.com", "192.0.2.1", 30),
                t0 + i as Ts * 1_000_000_000,
                score::ScoreInputs::default(),
                true,
            );
        }
        let policy = PrefetchPolicy {
            horizon_secs: 60,
            target_freshness: 0.999_999,
            min_probability: 0.5,
            min_evidence_secs: 1.0,
        };
        let free = cache.refresh_schedule(&policy, None, 8, now(), |_, _| RefreshInputs {
            query_probability: 0.99,
            value_ms: 0.0,
        });
        assert!(free.is_empty(), "a zero-value answer bought a refresh");
    }

    #[test]
    fn equally_due_entries_are_ordered_by_the_key_not_by_the_name() {
        // The tie-break in `prefetch_candidates` is the fleet's refresh order:
        // every resolver holding these entries spends its per-tick budget from
        // the front. Ordering ties by name makes that order a public function
        // of the query stream — every resolver refreshes the same names in the
        // same sequence — and lets an observer predict which entry we look at
        // next. The keyed fingerprint makes the same order reproducible for us
        // and unguessable for anyone else.
        let mut cache = SemanticCache::new(cfg());
        // Two writes per name, two seconds apart, far enough in the past that
        // every entry is past its 30 s TTL. That gives each one the same
        // amount of evidence (so all of them are equally due) and leaves the
        // tie to be broken by something — which is the point of the test.
        let t0 = now() - 5_000_000_000_000;
        for i in 0..12 {
            let n = alloc::format!("h{i}.example.com");
            for step in 0..2u32 {
                cache.insert_positive(
                    &key(&n, RrType::A),
                    RrSet::a(&n, "192.0.2.1", 30),
                    t0 + step as Ts * 2_000_000_000,
                    score::ScoreInputs::default(),
                    true,
                );
            }
        }
        assert!(
            cache.len() >= 8,
            "only {} entries survived admission; the test needs a tie",
            cache.len()
        );
        let policy = PrefetchPolicy {
            horizon_secs: 60,
            target_freshness: 0.999_999,
            min_probability: 0.5,
            min_evidence_secs: 1.0,
        };
        let k1 = crate::behavior::FingerprintKey::from_words(1, 2);
        let k2 = crate::behavior::FingerprintKey::from_words(3, 4);
        // A `fn` item rather than a closure: a closure bound to a variable gets
        // one concrete lifetime for its reference parameter, and this has to be
        // usable as `Fn(&Name, u32)` for any of them.
        fn demand(_: &Name, _: u32) -> RefreshInputs {
            RefreshInputs {
                query_probability: 0.99,
                value_ms: 50.0,
            }
        }
        let budget = 12;
        let by_key1 = cache.refresh_schedule(&policy, Some(&k1), budget, now(), demand);
        let by_key2 = cache.refresh_schedule(&policy, Some(&k2), budget, now(), demand);
        let by_name = cache.refresh_schedule(&policy, None, budget, now(), demand);
        // All three contain the same entries: the ordering is a permutation,
        // not a filter.
        assert_eq!(by_key1.len(), by_name.len());
        assert_eq!(by_key2.len(), by_name.len());
        assert!(
            by_name.len() >= 6,
            "only {} entries were due; the test needs a tie to exist",
            by_name.len()
        );
        // Name order is not the keyed order, for either key. If it were, the
        // key would be doing nothing.
        assert_ne!(by_key1, by_name);
        assert_ne!(by_key2, by_name);
        // And two different secrets disagree with each other, which is what
        // stops one observer from predicting every deployment at once.
        assert_ne!(by_key1, by_key2);
        // The keyless order is exactly the key order — stable, public, and
        // therefore the correlated case the key exists to avoid.
        let mut sorted = by_name.clone();
        sorted.sort();
        assert_eq!(sorted, by_name);
    }

    #[test]
    fn update_existing_tracks_stability() {
        let mut cache = SemanticCache::new(cfg());
        let k = key("example.com", RrType::A);
        cache.insert_positive(
            &k,
            RrSet::a("example.com", "192.0.2.1", 300),
            now(),
            score::ScoreInputs::default(),
            false,
        );
        cache.insert_positive(
            &k,
            RrSet::a("example.com", "192.0.2.1", 300),
            now() + 1_000_000_000,
            score::ScoreInputs::default(),
            false,
        );
        cache.insert_positive(
            &k,
            RrSet::a("example.com", "192.0.2.2", 300),
            now() + 2_000_000_000,
            score::ScoreInputs::default(),
            false,
        );
        match cache.lookup(&k, now() + 3_000_000_000) {
            LookupOutcome::Fresh(e) => {
                assert_eq!(e.stability.changes(), 1);
                assert_eq!(e.served, 1);
            }
            other => panic!("expected fresh, got {other:?}"),
        }
    }

    /// The NXDOMAIN store has its own capacity: a stream of distinct
    /// nonexistent names must not grow it without bound.
    #[test]
    fn nxdomain_store_is_bounded() {
        let mut cache = SemanticCache::new(CacheConfig {
            nx_capacity: 16,
            ..cfg()
        });
        for i in 0..200 {
            let name = Name::from_ascii(&format!("missing{i}.example.com")).unwrap();
            cache.insert_nxdomain(&name, Rcode::NXDOMAIN, None, 300, now());
        }
        assert!(
            cache.nx.len() <= 16,
            "nxdomain store grew to {}",
            cache.nx.len()
        );
        // And the store still works for a name that is in it.
        let last = Name::from_ascii("missing199.example.com").unwrap();
        assert!(matches!(
            cache.lookup(&CacheKey::plain(last, RrType::A, RrClass::IN), now()),
            LookupOutcome::NxDomain { .. }
        ));
    }

    /// Parking an expired entry for serve-stale must respect the cold tier's
    /// capacity — previously it bypassed it entirely.
    #[test]
    fn stale_parking_respects_cold_capacity() {
        let small = CacheConfig {
            hot_capacity: 0,
            warm_capacity: 0,
            cold_capacity: 4,
            stale_window_secs: 3_600,
            ..CacheConfig::default()
        };
        let mut cache = SemanticCache::new(small);
        // 20 entries with a 1-second TTL, all expired but stale-servable.
        for i in 0..20 {
            let name = format!("h{i}.example.com");
            let k = key(&name, RrType::A);
            cache.insert_positive(
                &k,
                RrSet::a(&name, "192.0.2.1", 1),
                now(),
                score::ScoreInputs::default(),
                false,
            );
        }
        let later = now() + 2_000_000_000;
        for i in 0..20 {
            let name = format!("h{i}.example.com");
            let _ = cache.lookup(&key(&name, RrType::A), later);
        }
        assert!(
            cache.cold.len() <= 4,
            "cold tier grew to {}",
            cache.cold.len()
        );
    }

    /// Eviction is exact, not sampled: with the rank index the lowest-scored
    /// entry of the full tier is the one that goes.
    #[test]
    fn eviction_takes_the_lowest_scored_entry() {
        let one_tier = CacheConfig {
            hot_capacity: 0,
            warm_capacity: 3,
            cold_capacity: 0,
            min_admit_score: 0.0,
            warm_admit_score: 0.0,
            ..CacheConfig::default()
        };
        let mut cache = SemanticCache::new(one_tier);
        // Popularity rises with i, so scores do too.
        for i in 0..3u32 {
            let name = format!("h{i}.example.com");
            cache.insert_positive(
                &key(&name, RrType::A),
                RrSet::a(&name, "192.0.2.1", 300),
                now(),
                score::ScoreInputs {
                    popularity: 0.2 + i as f64 * 0.2,
                    est_cost_ms: 10.0,
                },
                false,
            );
        }
        assert_eq!(cache.warm.len(), 3);
        // A fourth entry with the highest score forces one eviction.
        cache.insert_positive(
            &key("h9.example.com", RrType::A),
            RrSet::a("h9.example.com", "192.0.2.1", 300),
            now(),
            score::ScoreInputs {
                popularity: 1.0,
                est_cost_ms: 10.0,
            },
            false,
        );
        assert!(!cache.warm.contains_key(&key("h0.example.com", RrType::A)));
        assert!(cache.warm.contains_key(&key("h2.example.com", RrType::A)));
        assert!(cache.warm.contains_key(&key("h9.example.com", RrType::A)));
    }

    /// A refresh that fails must end the refresh, or that key could never be
    /// prefetched again.
    #[test]
    fn refresh_failure_clears_the_in_flight_mark() {
        let mut cache = SemanticCache::new(cfg());
        let k = key("pf.example.com", RrType::A);
        cache.insert_positive(
            &k,
            RrSet::a("pf.example.com", "192.0.2.1", 30),
            now(),
            score::ScoreInputs::default(),
            false,
        );
        assert!(cache.mark_refreshing(&k));
        assert!(!cache.mark_refreshing(&k), "double-mark must be refused");
        cache.record_refresh_failure(&k, now());
        assert!(
            cache.mark_refreshing(&k),
            "a failed refresh must free the key"
        );
        cache.clear_refreshing(&k);
        assert!(cache.mark_refreshing(&k));
    }
}
