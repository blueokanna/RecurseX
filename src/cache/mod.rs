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
//! Admission is score-driven ([`score::compute_full`]); eviction picks the
//! lowest-scored entry by sampling, so the cache is honest about what it
//! keeps. TTLs are authoritative values — the cache never invents TTLs; it
//! only decides *internal* timing (refresh, stale fallback, admission).

#[cfg(feature = "persist")]
pub mod persist;
pub mod score;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::edns::Ecs;
use crate::name::Name;
use crate::prng::SplitMix64;
use crate::qtype::{Rcode, RrClass, RrType};
use crate::rdata::Record;
use crate::rrset::RrSet;
use crate::stability::StabilityModel;
use crate::time::Ts;

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

/// The semantic multi-tier cache.
pub struct SemanticCache {
    config: CacheConfig,
    hot: BTreeMap<CacheKey, CacheEntry>,
    warm: BTreeMap<CacheKey, CacheEntry>,
    cold: BTreeMap<CacheKey, CacheEntry>,
    nx: BTreeMap<Name, NegativeEntry>,
    stats: CacheStats,
    rng: SplitMix64,
}

impl SemanticCache {
    /// A cache with the given configuration.
    pub fn new(config: CacheConfig) -> Self {
        let rng = {
            #[cfg(feature = "std")]
            {
                SplitMix64::seeded()
            }
            #[cfg(not(feature = "std"))]
            {
                SplitMix64::new(0x6a09e667f3bcc909)
            }
        };
        Self {
            config,
            hot: BTreeMap::new(),
            warm: BTreeMap::new(),
            cold: BTreeMap::new(),
            nx: BTreeMap::new(),
            stats: CacheStats::default(),
            rng,
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
            let Some(mut entry) = self.take_entry(key, tier) else {
                continue;
            };
            entry.last_served = now;
            entry.served += 1;
            if entry.is_fresh(now) {
                self.stats.hits += 1;
                entry.score = self.score_entry(&entry, now, score::ScoreInputs::default());
                let outcome = LookupOutcome::Fresh(entry.clone());
                self.reinsert(entry, now);
                return Some(outcome);
            } else if entry.is_stale_servable(now, self.config.stale_window_secs) {
                self.stats.hits += 1;
                self.stats.stale_served += 1;
                let outcome = LookupOutcome::Stale(entry.clone());
                // Park the stale entry in the cold tier so it stays servable.
                entry.tier = Tier::Cold;
                self.cold.insert(key.clone(), entry);
                return Some(outcome);
            } else {
                // Fully dead: drop it and keep looking.
                self.stats.misses += 1;
            }
        }
        None
    }

    fn lookup_cname(&mut self, key: &CacheKey, now: Ts) -> Option<LookupOutcome> {
        for tier in [Tier::Hot, Tier::Warm, Tier::Cold] {
            let Some(mut entry) = self.take_entry(key, tier) else {
                continue;
            };
            let target = match &entry.kind {
                EntryKind::Positive(s) => s.cname_target().cloned(),
                _ => None,
            };
            let Some(target) = target else {
                self.reinsert(entry, now);
                continue;
            };
            if !entry.is_fresh(now) {
                // Expired CNAME: keep it only if still stale-servable.
                if entry.is_stale_servable(now, self.config.stale_window_secs) {
                    entry.tier = Tier::Cold;
                    self.cold.insert(key.clone(), entry);
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
            self.reinsert(entry, now);
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
            entry.validated = validated;
            entry.refreshing = false;
            entry.kind = EntryKind::Positive(rrset);
            entry.score = self.score_entry(&entry, now, inputs);
            self.reinsert(entry, now);
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
        self.admit(entry, now);
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
            self.reinsert(entry, now);
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
        self.admit(entry, now);
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
        score::compute_full(
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
        entry.score = score::compute_full(
            &self.config.weights,
            entry.ttl_secs(),
            now,
            entry.last_served,
            &entry.stability,
            &inputs,
            entry.estimated_bytes(),
        );
        self.reinsert(entry, now);
    }

    /// Admit a brand-new entry to the tier its score earns, evicting as
    /// needed.
    fn admit(&mut self, mut entry: CacheEntry, now: Ts) {
        self.stats.inserts += 1;
        let cfg = self.config;
        if entry.score >= cfg.hot_admit_score {
            entry.tier = Tier::Hot;
            if self.hot.len() >= cfg.hot_capacity {
                if let Some(v) =
                    Self::evict_lowest(&mut self.rng, &mut self.hot, cfg.warm_admit_score)
                {
                    self.demote_or_drop(v, now);
                }
            }
            self.hot.insert(entry.key.clone(), entry);
        } else if entry.score >= cfg.warm_admit_score {
            entry.tier = Tier::Warm;
            if self.warm.len() >= cfg.warm_capacity {
                if let Some(v) =
                    Self::evict_lowest(&mut self.rng, &mut self.warm, cfg.min_admit_score)
                {
                    self.demote_or_drop(v, now);
                }
            }
            self.warm.insert(entry.key.clone(), entry);
        } else if entry.score >= cfg.min_admit_score {
            entry.tier = Tier::Cold;
            if self.cold.len() >= cfg.cold_capacity {
                Self::evict_lowest(&mut self.rng, &mut self.cold, 0.0);
            }
            self.cold.insert(entry.key.clone(), entry);
        }
        // Below min_admit: not cached at all.
    }

    /// Reinsert an entry that was removed for serving/updating, choosing
    /// the best tier its (possibly changed) score earns.
    fn reinsert(&mut self, entry: CacheEntry, now: Ts) {
        let cfg = self.config;
        let mut e = entry;
        let desired = if e.score >= cfg.hot_admit_score {
            Tier::Hot
        } else if e.score >= cfg.warm_admit_score {
            Tier::Warm
        } else if e.score >= cfg.min_admit_score {
            Tier::Cold
        } else {
            return; // no longer worth caching
        };
        e.tier = desired;
        match desired {
            Tier::Hot => {
                if self.hot.len() >= cfg.hot_capacity {
                    if let Some(v) =
                        Self::evict_lowest(&mut self.rng, &mut self.hot, cfg.warm_admit_score)
                    {
                        self.demote_or_drop(v, now);
                    }
                }
                self.hot.insert(e.key.clone(), e);
            }
            Tier::Warm => {
                if self.warm.len() >= cfg.warm_capacity {
                    if let Some(v) =
                        Self::evict_lowest(&mut self.rng, &mut self.warm, cfg.min_admit_score)
                    {
                        self.demote_or_drop(v, now);
                    }
                }
                self.warm.insert(e.key.clone(), e);
            }
            Tier::Cold => {
                if self.cold.len() >= cfg.cold_capacity {
                    Self::evict_lowest(&mut self.rng, &mut self.cold, 0.0);
                }
                self.cold.insert(e.key.clone(), e);
            }
        }
    }

    /// Move an evicted entry to a lower tier, or drop it.
    fn demote_or_drop(&mut self, victim: CacheEntry, now: Ts) {
        self.stats.evictions += 1;
        let cfg = self.config;
        let v = victim;
        if v.score >= cfg.warm_admit_score {
            if self.warm.len() >= cfg.warm_capacity {
                if let Some(x) =
                    Self::evict_lowest(&mut self.rng, &mut self.warm, cfg.min_admit_score)
                {
                    self.demote_or_drop(x, now);
                }
            }
            self.warm.insert(v.key.clone(), v);
        } else if v.score >= cfg.min_admit_score || v.is_stale_servable(now, cfg.stale_window_secs)
        {
            if self.cold.len() >= cfg.cold_capacity {
                Self::evict_lowest(&mut self.rng, &mut self.cold, 0.0);
            }
            self.cold.insert(v.key.clone(), v);
        }
    }

    /// Remove the lowest-scored entry in `tier` (sampled, to bound cost).
    fn evict_lowest(
        rng: &mut SplitMix64,
        tier: &mut BTreeMap<CacheKey, CacheEntry>,
        floor: f64,
    ) -> Option<CacheEntry> {
        let mut keys: Vec<CacheKey> = tier.keys().cloned().collect();
        if keys.is_empty() {
            return None;
        }
        let sample_size = keys.len().min(24);
        let mut best: Option<(f64, CacheKey)> = None;
        for _ in 0..sample_size {
            let idx = rng.below(keys.len() as u64) as usize;
            let key = &keys[idx];
            let s = tier.get(key).map(|e| e.score).unwrap_or(0.0);
            if best.as_ref().map(|(bs, _)| s < *bs).unwrap_or(true) {
                best = Some((s, key.clone()));
            }
        }
        let (score, key) = best.unwrap_or((0.0, keys.remove(0)));
        if score < floor {
            return None; // nothing worth evicting
        }
        tier.remove(&key)
    }

    /// Remove every entry that is past its stale window (background task).
    pub fn sweep(&mut self, now: Ts) {
        let stale_window = self.config.stale_window_secs as Ts * 1_000_000_000;
        self.hot
            .retain(|_, e| e.expires.saturating_add(stale_window) >= now);
        self.warm
            .retain(|_, e| e.expires.saturating_add(stale_window) >= now);
        self.cold
            .retain(|_, e| e.expires.saturating_add(stale_window) >= now);
        self.nx
            .retain(|_, e| e.expires >= now.saturating_sub(stale_window));
    }

    /// Record a refresh failure for a key (updates the stability model).
    pub fn record_refresh_failure(&mut self, key: &CacheKey, now: Ts) {
        if let Some(e) = self
            .hot
            .get_mut(key)
            .or_else(|| self.warm.get_mut(key))
            .or_else(|| self.cold.get_mut(key))
        {
            e.stability.record_failure(now);
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

    fn take_entry(&mut self, key: &CacheKey, tier: Tier) -> Option<CacheEntry> {
        match tier {
            Tier::Hot => self.hot.remove(key),
            Tier::Warm => self.warm.remove(key),
            Tier::Cold => self.cold.remove(key),
        }
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
}
