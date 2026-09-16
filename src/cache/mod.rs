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
use crate::name::Name;
use crate::qtype::{Rcode, RrClass, RrType};
use crate::rdata::Record;
use crate::rrset::RrSet;
use crate::stability::StabilityModel;
use crate::time::Ts;

/// Eviction stride for a table that is full of live entries.
const EVICT_STRIDE: usize = 8;

/// A compact, hashable representation of the ECS network used as part of
/// the cache key (RFC 7871 §7.2: ECS and non-ECS answers must not mix).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct EcsKey {
    /// The address family (1 = IPv4, 2 = IPv6, RFC 7871).
    pub family: u16,
    /// The source prefix length in bits.
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
            addr: ecs.address.clone(),
        })
    }
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
    /// Prefetch: refresh when remaining TTL drops below this.
    pub prefetch_threshold_ttl: u32,
    /// Prefetch: required probability of a query within the horizon.
    pub prefetch_probability: f64,
    /// Prefetch: prediction horizon in seconds.
    pub prefetch_horizon_secs: u32,
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
            prefetch_threshold_ttl: 30,
            prefetch_probability: 0.75,
            prefetch_horizon_secs: 60,
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

    /// Look up a key. Applies ECS partition rules: a non-ECS query only
    /// ever sees non-ECS entries; an ECS query first tries its exact
    /// partition, then falls back to the non-ECS partition (RFC 7871 §7.2.2).
    pub fn lookup(&mut self, key: &CacheKey, now: Ts) -> LookupOutcome {
        if let Some(outcome) = self.lookup_exact(key, now) {
            return outcome;
        }
        if key.is_ecs() {
            let plain = CacheKey::plain(key.name.clone(), key.rr_type, key.class);
            if let Some(outcome) = self.lookup_exact(&plain, now) {
                return outcome;
            }
        }
        // CNAME redirect for the same name.
        if key.rr_type != RrType::CNAME && key.rr_type != RrType::ANY {
            let cname_key = key.with_type(RrType::CNAME);
            if let Some(outcome) = self.lookup_cname(&cname_key, now) {
                return outcome;
            }
        }
        // NXDOMAIN for the name (applies to every type under the name).
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

        if let Some(existing) = self.take_entry_any(key) {
            let mut entry = existing;
            let changed = match &entry.kind {
                EntryKind::Positive(old) => !old.same_data(&rrset),
                _ => true,
            };
            entry.stability.observe(rrset.ttl, changed, now);
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

        let mut entry = CacheEntry {
            key: key.clone(),
            kind: EntryKind::Positive(rrset),
            inserted: now,
            expires,
            served: 0,
            last_served: now,
            stability: StabilityModel::new(now),
            validated,
            score: 0.0,
            tier: Tier::Warm,
            refreshing: false,
        };
        entry.stability.observe(entry.ttl_secs(), false, now);
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
            stability: StabilityModel::new(now),
            validated: false,
            score: 0.0,
            tier: Tier::Warm,
            refreshing: false,
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

    /// Candidate keys for predictive prefetch.
    ///
    /// `probability_of_query(apex, horizon)` is a closure into the query
    /// estimator: `P(a query for this zone within the next `horizon` secs)`.
    pub fn prefetch_candidates<F>(&mut self, now: Ts, probability_of_query: F) -> Vec<CacheKey>
    where
        F: Fn(&Name, u32) -> f64,
    {
        let cfg = self.config;
        let mut out = Vec::new();
        for map in [&self.hot, &self.warm] {
            for entry in map.values() {
                if !matches!(entry.kind, EntryKind::Positive(_)) {
                    continue;
                }
                if entry.refreshing {
                    continue;
                }
                if !entry.stability.is_mature() {
                    continue;
                }
                if entry.remaining_ttl(now) > cfg.prefetch_threshold_ttl {
                    continue;
                }
                let apex = entry.key.name.apex();
                let p = probability_of_query(&apex, cfg.prefetch_horizon_secs);
                if p >= cfg.prefetch_probability {
                    out.push(entry.key.clone());
                }
            }
        }
        out
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
    fn prefetch_candidates_are_low_ttl_and_likely() {
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
                false,
            );
        }
        let now2 = t0 + 6_000_000_000 + 25_000_000_000;
        let cands = cache.prefetch_candidates(now2, |apex, _| {
            assert_eq!(apex.to_ascii(), "example.com");
            0.99
        });
        assert!(cands.iter().any(|c| c.name.to_ascii() == "hot.example.com"));
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
                assert_eq!(e.stability.changes, 1);
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
