//! L3 persistent cache tier.
//!
//! A warm recursive resolver's cache is a *prediction asset*: the stability
//! models, admission scores and tier assignments accumulated over hours of
//! live resolution are exactly the state that a cold restart would throw
//! away. This module snapshots the whole [`SemanticCache`] into a single
//! compact binary frame with [`rustbinary`], writes it atomically (temp
//! file + rename), and restores it on startup.
//!
//! Design notes:
//!
//! * Records are stored in their canonical DNS wire form (RFC 1035,
//!   uncompressed names) — the cache already knows how to emit and parse
//!   those, so we reuse one codec instead of teaching the binary codec
//!   about every RDATA variant.
//! * The frame is type-tagged and self-describing (rustbinary/nextjson), so
//!   a future version can evolve fields without a byte-level migration.
//! * Decoding is bounded (`with_limit`) — the file is untrusted input at
//!   the trust boundary.
//! * On restore, expired-but-stale-servable entries are parked in the cold
//!   tier; fully dead entries are dropped; the *remaining* TTL is
//!   recomputed from the absolute expiry, never invented.
//! * Persistence is best-effort: a failed save is logged away (returned as
//!   an `Err`) and never poisons the live cache.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use std::path::Path;

use nextjson::{NsonDeserialize, NsonSerialize};

use crate::cache::{CacheEntry, CacheKey, EcsKey, EntryKind, NegativeEntry, SemanticCache, Tier};
use crate::error::{Error, Result};
use crate::name::Name;
use crate::qtype::{Rcode, RrClass, RrType};
use crate::rdata::Record;
use crate::stability::StabilityModel;
use crate::time::Ts;

/// Magic identifier for RecurseX cache frames ("RXC" + 0x5e).
const MAGIC: u32 = 0x5258435e;
/// Current frame version.
const VERSION: u32 = 1;
/// Default decode limit: 32 MiB of frame (many thousands of entries).
const DEFAULT_FRAME_LIMIT: u64 = 32 * 1024 * 1024;
/// Default per-collection element limit.
const DEFAULT_COLLECTION_LIMIT: u64 = 1_000_000;

/// How the persistent tier is configured by the resolver.
#[derive(Clone, Debug, PartialEq)]
pub struct PersistConfig {
    /// Where the cache frame lives.
    pub path: std::path::PathBuf,
    /// How often the maintenance loop writes a fresh snapshot (ms).
    /// 0 disables periodic saves (only explicit [`save`] calls).
    pub save_interval_ms: u64,
    /// Maximum accepted frame size on load (bytes).
    pub frame_limit: u64,
}

impl PersistConfig {
    /// A persistent tier at `path`, saving every `save_interval_ms`.
    pub fn new(path: impl Into<std::path::PathBuf>, save_interval_ms: u64) -> Self {
        Self {
            path: path.into(),
            save_interval_ms,
            frame_limit: DEFAULT_FRAME_LIMIT,
        }
    }
}

/// A complete on-disk cache snapshot.
#[derive(Debug, NsonSerialize, NsonDeserialize)]
struct Snapshot {
    magic: u32,
    version: u32,
    saved_at_unix: i64,
    entries: Vec<EntryDto>,
    negatives: Vec<NegativeDto>,
}

/// One positive or negative cache entry.
#[derive(Debug, NsonSerialize, NsonDeserialize)]
struct EntryDto {
    /// Canonical (lower-cased) wire name, uncompressed.
    name: Vec<u8>,
    rr_type: u16,
    class: u16,
    ecs: Option<EcsDto>,
    /// 0 = hot, 1 = warm, 2 = cold.
    tier: u8,
    kind: KindDto,
    /// Absolute wall-clock seconds (unix) the entry was inserted.
    inserted_unix: i64,
    /// Absolute wall-clock seconds (unix) the entry expires.
    expires_unix: i64,
    served: u64,
    last_served_unix: i64,
    stability: StabilityDto,
    validated: bool,
    score: f64,
}

/// The payload of an entry.
#[derive(Debug, NsonSerialize, NsonDeserialize)]
enum KindDto {
    Positive {
        /// Each element is one full record in DNS wire form.
        records: Vec<Vec<u8>>,
        rrsigs: Vec<Vec<u8>>,
    },
    Negative {
        rcode: u8,
        /// The SOA record in DNS wire form, if present.
        soa: Option<Vec<u8>>,
        ttl_secs: u32,
    },
}

/// ECS partition (RFC 7871).
#[derive(Debug, NsonSerialize, NsonDeserialize)]
struct EcsDto {
    family: u16,
    prefix: u8,
    addr: Vec<u8>,
}

/// The stability model, reduced to its persistent fields.
#[derive(Debug, NsonSerialize, NsonDeserialize)]
struct StabilityDto {
    samples: u64,
    changes: u64,
    stability: f64,
    change_ratio: f64,
    ttl_ewma: f64,
    ttl_volatility: f64,
    consecutive_failures: u64,
    failures: u64,
    last_refresh_unix: i64,
    last_change_unix: i64,
}

/// One NXDOMAIN negative entry (shared across types under a name).
#[derive(Debug, NsonSerialize, NsonDeserialize)]
struct NegativeDto {
    name: Vec<u8>,
    expires_unix: i64,
    rcode: u8,
    soa: Option<Vec<u8>>,
    inserted_unix: i64,
    served: u64,
}

impl Snapshot {
    fn new(cache: &SemanticCache, now_unix: i64) -> Self {
        let mut entries = Vec::new();
        for (tier, map) in tier_maps(cache) {
            for e in map.values() {
                if let Some(dto) = entry_to_dto(e, tier) {
                    entries.push(dto);
                }
            }
        }
        let negatives = cache
            .nx
            .iter()
            .map(|(name, neg)| NegativeDto {
                name: name.to_wire_bytes(),
                expires_unix: ts_to_unix(neg.expires),
                rcode: neg.rcode.0,
                soa: neg.soa.as_ref().map(record_wire),
                inserted_unix: ts_to_unix(neg.inserted),
                served: neg.served,
            })
            .collect();
        Snapshot {
            magic: MAGIC,
            version: VERSION,
            saved_at_unix: now_unix,
            entries,
            negatives,
        }
    }

    /// Restore into `cache`; returns the number of entries restored.
    fn restore_into(&self, cache: &mut SemanticCache, now: Ts, stale_window_secs: u32) -> usize {
        if self.magic != MAGIC || self.version != VERSION {
            return 0;
        }
        let mut restored = 0usize;
        for dto in &self.entries {
            let Some(entry) = dto_to_entry(dto, now, stale_window_secs) else {
                continue;
            };
            let tier = entry.tier;
            match tier {
                Tier::Hot => cache.hot.insert(entry.key.clone(), entry),
                Tier::Warm => cache.warm.insert(entry.key.clone(), entry),
                Tier::Cold => cache.cold.insert(entry.key.clone(), entry),
            };
            restored += 1;
        }
        for dto in &self.negatives {
            let Ok(name) = Name::from_wire(&dto.name, 0) else {
                continue;
            };
            let (name, _) = name;
            let expires = unix_to_ts(dto.expires_unix);
            let end = expires.saturating_add(stale_window_secs as Ts * 1_000_000_000);
            if now >= end {
                continue;
            }
            let soa = dto.soa.as_deref().and_then(parse_record);
            cache.nx.insert(
                name,
                NegativeEntry {
                    expires,
                    rcode: Rcode(dto.rcode),
                    soa,
                    inserted: unix_to_ts(dto.inserted_unix),
                    served: dto.served,
                },
            );
            restored += 1;
        }
        cache.stats.inserts += restored as u64;
        restored
    }
}

/// Serialize the cache to a bounded binary frame.
pub fn encode(cache: &SemanticCache, now_unix: i64) -> Result<Vec<u8>> {
    let snap = Snapshot::new(cache, now_unix);
    rustbinary::options()
        .with_limit(DEFAULT_FRAME_LIMIT)
        .with_collection_limit(DEFAULT_COLLECTION_LIMIT)
        .serialize(&snap)
        .map_err(|e| Error::internal(format!("cache encode: {e}")))
}

/// Atomically write a snapshot to `path` (temp file + rename).
pub fn save_to(cache: &SemanticCache, path: &Path, now_unix: i64) -> Result<()> {
    let bytes = encode(cache, now_unix)?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)
        .map_err(|e| Error::io(format!("cache persist write {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| Error::io(format!("cache persist rename {}: {e}", path.display())))?;
    Ok(())
}

/// Load a snapshot from `path` into `cache`; returns the number of entries
/// restored (0 when the file is absent or unreadable — a cold start).
pub fn load_from(cache: &mut SemanticCache, path: &Path, now: Ts) -> Result<usize> {
    load_from_limit(cache, path, now, DEFAULT_FRAME_LIMIT)
}

/// Like [`load_from`] with an explicit frame-size bound.
pub fn load_from_limit(
    cache: &mut SemanticCache,
    path: &Path,
    now: Ts,
    frame_limit: u64,
) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }
    let bytes = std::fs::read(path)
        .map_err(|e| Error::io(format!("cache persist read {}: {e}", path.display())))?;
    let snap: Snapshot = rustbinary::options()
        .with_limit(frame_limit)
        .with_collection_limit(DEFAULT_COLLECTION_LIMIT)
        .deserialize(&bytes)
        .map_err(|e| Error::internal(format!("cache decode: {e}")))?;
    let stale = cache.config.stale_window_secs;
    Ok(snap.restore_into(cache, now, stale))
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

fn tier_maps(cache: &SemanticCache) -> Vec<(Tier, &BTreeMap<CacheKey, CacheEntry>)> {
    vec![
        (Tier::Hot, &cache.hot),
        (Tier::Warm, &cache.warm),
        (Tier::Cold, &cache.cold),
    ]
}

fn record_wire(r: &Record) -> Vec<u8> {
    let mut out = Vec::with_capacity(r.name.wire_len() + 40);
    r.to_wire(&mut out, None);
    out
}

fn parse_record(wire: &[u8]) -> Option<Record> {
    let mut pos = 0usize;
    Record::parse(wire, &mut pos).ok()
}

fn ecs_to_dto(ecs: &EcsKey) -> EcsDto {
    EcsDto {
        family: ecs.family,
        prefix: ecs.prefix,
        addr: ecs.addr.clone(),
    }
}

fn ts_to_unix(ts: Ts) -> i64 {
    (ts / 1_000_000_000).clamp(i64::MIN as Ts, i64::MAX as Ts) as i64
}

fn unix_to_ts(unix: i64) -> Ts {
    unix as Ts * 1_000_000_000
}

fn stability_to_dto(s: &StabilityModel) -> StabilityDto {
    StabilityDto {
        samples: s.samples,
        changes: s.changes,
        stability: s.stability,
        change_ratio: s.change_ratio,
        ttl_ewma: s.ttl_ewma,
        ttl_volatility: s.ttl_volatility,
        consecutive_failures: s.consecutive_failures,
        failures: s.failures,
        last_refresh_unix: ts_to_unix(s.last_refresh),
        last_change_unix: ts_to_unix(s.last_change),
    }
}

fn dto_to_stability(d: &StabilityDto) -> StabilityModel {
    StabilityModel {
        samples: d.samples,
        changes: d.changes,
        stability: d.stability,
        change_ratio: d.change_ratio,
        ttl_ewma: d.ttl_ewma,
        ttl_volatility: d.ttl_volatility,
        consecutive_failures: d.consecutive_failures,
        failures: d.failures,
        last_refresh: unix_to_ts(d.last_refresh_unix),
        last_change: unix_to_ts(d.last_change_unix),
    }
}

fn entry_to_dto(e: &CacheEntry, tier: Tier) -> Option<EntryDto> {
    let name = e.key.name.to_wire_bytes();
    let kind = match &e.kind {
        EntryKind::Positive(rrset) => KindDto::Positive {
            records: rrset.records.iter().map(record_wire).collect(),
            rrsigs: rrset.rrsigs.iter().map(record_wire).collect(),
        },
        EntryKind::Negative {
            rcode,
            soa,
            ttl_secs,
        } => KindDto::Negative {
            rcode: rcode.0,
            soa: soa.as_ref().map(record_wire),
            ttl_secs: *ttl_secs,
        },
    };
    Some(EntryDto {
        name,
        rr_type: e.key.rr_type.to_u16(),
        class: e.key.class.to_u16(),
        ecs: e.key.ecs.as_ref().map(ecs_to_dto),
        tier: tier as u8,
        kind,
        inserted_unix: ts_to_unix(e.inserted),
        expires_unix: ts_to_unix(e.expires),
        served: e.served,
        last_served_unix: ts_to_unix(e.last_served),
        stability: stability_to_dto(&e.stability),
        validated: e.validated,
        score: e.score,
    })
}

fn dto_to_entry(d: &EntryDto, now: Ts, stale_window_secs: u32) -> Option<CacheEntry> {
    let (name, _) = Name::from_wire(&d.name, 0).ok()?;
    let expires = unix_to_ts(d.expires_unix);
    // Fully dead: neither fresh nor stale-servable.
    let stale_end = expires.saturating_add(stale_window_secs as Ts * 1_000_000_000);
    if now >= stale_end {
        return None;
    }
    let key = CacheKey {
        name,
        rr_type: RrType(d.rr_type),
        class: RrClass(d.class),
        ecs: d.ecs.as_ref().map(|e| EcsKey {
            family: e.family,
            prefix: e.prefix,
            addr: e.addr.clone(),
        }),
    };
    let kind = match &d.kind {
        KindDto::Positive { records, rrsigs } => {
            if records.is_empty() {
                return None;
            }
            let mut data = Vec::with_capacity(records.len());
            let mut sigs = Vec::with_capacity(rrsigs.len());
            for w in records {
                data.push(parse_record(w)?);
            }
            for w in rrsigs {
                sigs.push(parse_record(w)?);
            }
            let rrset = crate::rrset::RrSet {
                name: key.name.clone(),
                rr_type: key.rr_type,
                class: key.class,
                records: data,
                rrsigs: sigs,
                ttl: d.kind.ttl(),
                validated: d.validated,
            };
            EntryKind::Positive(rrset)
        }
        KindDto::Negative {
            rcode,
            soa,
            ttl_secs,
        } => EntryKind::Negative {
            rcode: Rcode(*rcode),
            soa: soa.as_deref().and_then(parse_record),
            ttl_secs: *ttl_secs,
        },
    };
    let tier = match d.tier {
        0 => Tier::Hot,
        1 => Tier::Warm,
        _ => Tier::Cold,
    };
    // Expired-but-servable entries belong in the cold tier regardless of
    // where they were parked at save time.
    let tier = if now >= expires { Tier::Cold } else { tier };
    Some(CacheEntry {
        key,
        kind,
        inserted: unix_to_ts(d.inserted_unix),
        expires,
        served: d.served,
        last_served: unix_to_ts(d.last_served_unix),
        stability: dto_to_stability(&d.stability),
        validated: d.validated,
        score: d.score,
        tier,
        refreshing: false,
    })
}

impl KindDto {
    /// The effective TTL for a positive entry (min of record TTLs).
    fn ttl(&self) -> u32 {
        match self {
            KindDto::Positive { records, .. } => records
                .iter()
                .filter_map(|w| parse_record(w))
                .map(|r| r.ttl)
                .min()
                .unwrap_or(0),
            KindDto::Negative { ttl_secs, .. } => *ttl_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{CacheConfig, CacheKey};
    use crate::rrset::RrSet;

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    fn cache_with_entries() -> SemanticCache {
        let mut c = SemanticCache::new(CacheConfig::default());
        let k = CacheKey::plain(
            Name::from_ascii("persisted.example").unwrap(),
            RrType::A,
            RrClass::IN,
        );
        c.insert_positive(
            &k,
            RrSet::a("persisted.example", "192.0.2.77", 300),
            now(),
            crate::cache::score::ScoreInputs::default(),
            false,
        );
        c.insert_nxdomain(
            &Name::from_ascii("missing.example").unwrap(),
            Rcode::NXDOMAIN,
            None,
            60,
            now(),
        );
        c
    }

    #[test]
    fn snapshot_roundtrip() {
        let cache = cache_with_entries();
        let bytes = encode(&cache, 1_700_000_000).unwrap();
        assert!(!bytes.is_empty());

        // A fresh cache with a different random seed; restore into it.
        let mut restored = SemanticCache::new(CacheConfig::default());
        let stale = restored.config.stale_window_secs;
        let n = {
            let snap: Snapshot = rustbinary::options().deserialize(&bytes).unwrap();
            snap.restore_into(&mut restored, now(), stale)
        };
        assert_eq!(n, 2);

        let k = CacheKey::plain(
            Name::from_ascii("persisted.example").unwrap(),
            RrType::A,
            RrClass::IN,
        );
        let outcome = restored.lookup(&k, now());
        assert!(outcome.is_hit());
        match outcome {
            crate::cache::LookupOutcome::Fresh(e) => {
                assert!(e.rrset().is_some());
                let set = e.rrset().unwrap();
                assert_eq!(set.records.len(), 1);
                assert_eq!(set.ttl, 300);
                assert!(!e.validated);
                // insert_positive records one stability observation.
                assert_eq!(e.stability.samples, 1);
            }
            _ => panic!("expected fresh positive hit"),
        }

        // NXDOMAIN survives.
        let nx = Name::from_ascii("missing.example").unwrap();
        let out = restored.lookup(&CacheKey::plain(nx, RrType::AAAA, RrClass::IN), now());
        assert!(matches!(out, crate::cache::LookupOutcome::NxDomain { .. }));
    }

    #[test]
    fn stale_entry_restores_into_cold() {
        let mut cache = cache_with_entries();
        // Rewrite the entry so it is expired but within the stale window.
        {
            let k = CacheKey::plain(
                Name::from_ascii("persisted.example").unwrap(),
                RrType::A,
                RrClass::IN,
            );
            let mut e = cache.take_entry_any(&k).unwrap();
            e.expires = now() - 5_000_000_000; // 5 s ago
            e.tier = Tier::Warm;
            cache.warm.insert(k, e);
        }
        let bytes = encode(&cache, 1_700_000_000).unwrap();
        let mut restored = SemanticCache::new(CacheConfig::default());
        let snap: Snapshot = rustbinary::options().deserialize(&bytes).unwrap();
        let n = snap.restore_into(&mut restored, now(), 86_400);
        assert_eq!(n, 2);
        // The expired-but-servable entry must be in cold.
        let k = CacheKey::plain(
            Name::from_ascii("persisted.example").unwrap(),
            RrType::A,
            RrClass::IN,
        );
        assert!(restored.cold.contains_key(&k));
        assert!(!restored.hot.contains_key(&k));
        assert!(!restored.warm.contains_key(&k));
        // And it is stale-servable.
        let out = restored.lookup(&k, now());
        assert!(matches!(out, crate::cache::LookupOutcome::Stale(_)));
    }

    #[test]
    fn dead_entry_is_dropped() {
        let mut cache = cache_with_entries();
        {
            let k = CacheKey::plain(
                Name::from_ascii("persisted.example").unwrap(),
                RrType::A,
                RrClass::IN,
            );
            let mut e = cache.take_entry_any(&k).unwrap();
            // Long dead: 3 days ago, well beyond the 1-day stale window.
            e.expires = now() - 3 * 86_400 * 1_000_000_000;
            cache.warm.insert(k, e);
        }
        let bytes = encode(&cache, 1_700_000_000).unwrap();
        let mut restored = SemanticCache::new(CacheConfig::default());
        let snap: Snapshot = rustbinary::options().deserialize(&bytes).unwrap();
        let n = snap.restore_into(&mut restored, now(), 86_400);
        // Only the NXDOMAIN survives; the dead A entry is dropped.
        assert_eq!(n, 1);
        assert_eq!(
            restored.hot.len() + restored.warm.len() + restored.cold.len(),
            0
        );
    }

    #[test]
    fn ecs_partition_survives() {
        let mut cache = SemanticCache::new(CacheConfig::default());
        let ecs = EcsKey {
            family: 1,
            prefix: 24,
            addr: vec![192, 0, 2, 0],
        };
        let k = CacheKey {
            name: Name::from_ascii("ecs.example").unwrap(),
            rr_type: RrType::A,
            class: RrClass::IN,
            ecs: Some(ecs),
        };
        cache.insert_positive(
            &k,
            RrSet::a("ecs.example", "198.51.100.9", 120),
            now(),
            crate::cache::score::ScoreInputs::default(),
            false,
        );
        let bytes = encode(&cache, 1_700_000_000).unwrap();
        let mut restored = SemanticCache::new(CacheConfig::default());
        let snap: Snapshot = rustbinary::options().deserialize(&bytes).unwrap();
        let n = snap.restore_into(&mut restored, now(), 86_400);
        assert_eq!(n, 1);
        let k2 = CacheKey {
            name: Name::from_ascii("ecs.example").unwrap(),
            rr_type: RrType::A,
            class: RrClass::IN,
            ecs: Some(EcsKey {
                family: 1,
                prefix: 24,
                addr: vec![192, 0, 2, 0],
            }),
        };
        let out = restored.lookup(&k2, now());
        assert!(matches!(out, crate::cache::LookupOutcome::Fresh(_)));
    }

    #[test]
    fn save_and_load_roundtrip_via_disk() {
        let cache = cache_with_entries();
        let dir =
            std::env::temp_dir().join(format!("recursex_persist_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("cache.rxc");
        save_to(&cache, &path, 1_700_000_000).unwrap();
        assert!(path.exists());
        assert!(!path.with_extension("tmp").exists());

        let mut loaded = SemanticCache::new(CacheConfig::default());
        let n = load_from(&mut loaded, &path, now()).unwrap();
        assert_eq!(n, 2);
        let k = CacheKey::plain(
            Name::from_ascii("persisted.example").unwrap(),
            RrType::A,
            RrClass::IN,
        );
        assert!(loaded.lookup(&k, now()).is_hit());

        // Missing file = cold start, not an error.
        let mut empty = SemanticCache::new(CacheConfig::default());
        let n2 = load_from(&mut empty, &dir.join("nope.rxc"), now()).unwrap();
        assert_eq!(n2, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_frame_is_rejected() {
        let cache = cache_with_entries();
        let bytes = encode(&cache, 1_700_000_000).unwrap();
        let mut bad = bytes.clone();
        if !bad.is_empty() {
            let last = bad.len() - 1;
            bad[last] ^= 0xff;
        }
        let res: std::result::Result<Snapshot, _> = rustbinary::options().deserialize(&bad);
        assert!(res.is_err() || !matches!(res, Ok(ref s) if s.magic == MAGIC));
        let _ = bytes;
    }
}
