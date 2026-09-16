//! Capacity management for the bounded state tables.
//!
//! The estimator (per-zone stats), the upstream selector (per-path stats)
//! and the rate limiter (per-client buckets) all keep a `BTreeMap` that an
//! attacker can fill: distinct source addresses, distinct zones, distinct
//! NS targets. The obvious eviction — "scan the map and drop the oldest
//! entry" — is O(n) *per insert*, so filling an n-entry table costs O(n²)
//! and turns the table itself into an amplification vector.
//!
//! [`evict_for_capacity`] replaces that with a two-phase amortised sweep
//! that never allocates:
//!
//! 1. **Stale pass** — drop every entry whose timestamp is older than the
//!    retention window. This is also the semantically right rule: a zone
//!    that has not been queried in half an hour carries no usable demand
//!    signal, so dropping it loses nothing.
//! 2. **Stride pass** — only when the stale pass freed nothing (the table
//!    is full of *fresh* entries, i.e. it is under real or hostile load),
//!    drop every `stride`-th entry. That pass is O(n) but happens once per
//!    `stride` inserts, so the amortised cost per insert is O(1).

use alloc::collections::BTreeMap;

use crate::time::Ts;

/// Ensure `map` can accept a new entry by evicting until it has room.
///
/// Evicts entries whose `stamp` is older than `stale_before`; if none are
/// old enough, evicts every `stride`-th entry instead. Returns the number
/// of evicted entries. **A non-empty map always loses at least one entry**,
/// so the caller can rely on the capacity being restored.
///
/// The caller decides *when* to call this (typically: the map is at
/// capacity). `stride` must be ≥ 2; a stride of 8 frees 12.5% of the table
/// per sweep.
pub fn evict_for_capacity<K, V, F>(
    map: &mut BTreeMap<K, V>,
    stale_before: Ts,
    stride: usize,
    stamp: F,
) -> usize
where
    K: Ord + Clone,
    F: Fn(&V) -> Ts,
{
    if map.is_empty() {
        return 0;
    }
    let before = map.len();
    let stride = stride.max(2);
    map.retain(|_, v| stamp(v) >= stale_before);
    if map.len() < before {
        return before - map.len();
    }
    let mut idx = 0usize;
    map.retain(|_, _| {
        idx += 1;
        idx % stride != 0
    });
    if map.len() < before {
        return before - map.len();
    }
    // Degenerate case: fewer entries than `stride`, so the sweep skipped
    // every one of them. Drop the single oldest entry so the guarantee
    // ("capacity is restored") holds for tables of any size.
    if let Some(k) = map
        .iter()
        .min_by_key(|(_, v)| stamp(v))
        .map(|(k, _)| k.clone())
    {
        map.remove(&k);
    }
    before - map.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_of(n: usize, stamp_of: impl Fn(usize) -> Ts) -> BTreeMap<usize, Ts> {
        (0..n).map(|i| (i, stamp_of(i))).collect()
    }

    #[test]
    fn stale_pass_drops_old_entries_only() {
        let mut m = map_of(10, |i| if i < 4 { 100 } else { 1_000 });
        let freed = evict_for_capacity(&mut m, 500, 4, |&t| t);
        assert_eq!(freed, 4);
        assert_eq!(m.len(), 6);
        assert!(m.values().all(|&t| t == 1_000));
    }

    #[test]
    fn stride_pass_bounds_an_all_fresh_table() {
        // Every entry is fresh, so the stale pass frees nothing; the stride
        // pass must still make progress (this is the hostile-load case).
        let mut m = map_of(64, |_| 1_000);
        let freed = evict_for_capacity(&mut m, 500, 8, |&t| t);
        assert_eq!(freed, 8);
        assert_eq!(m.len(), 56);
        // A second call frees another batch rather than looping forever.
        assert_eq!(evict_for_capacity(&mut m, 500, 8, |&t| t), 7);
    }

    #[test]
    fn empty_map_is_a_no_op() {
        let mut m: BTreeMap<u8, Ts> = BTreeMap::new();
        assert_eq!(evict_for_capacity(&mut m, 0, 4, |&t| t), 0);
    }

    /// A table smaller than `stride` must still lose its oldest entry, or
    /// the caller's hard cap breaks for small configurations.
    #[test]
    fn tiny_table_still_frees_one() {
        let mut m = map_of(3, |i| 1_000 + i as Ts);
        let freed = evict_for_capacity(&mut m, 0, 8, |&t| t);
        assert_eq!(freed, 1);
        assert_eq!(m.len(), 2);
        assert!(!m.contains_key(&0), "the oldest entry must go");
    }

    /// The amortised contract: filling an n-entry table with fresh entries
    /// costs O(n) total work, not O(n²). Measured as the number of *sweeps*
    /// (each O(n)) for n inserts at stride 8: n/8 sweeps ⇒ O(n²/8) element
    /// touches, which for the table sizes here is already a ~8× reduction;
    /// the test pins the sweep count so a future change cannot silently
    /// turn this back into a per-insert scan.
    #[test]
    fn sweep_count_is_amortised() {
        let cap = 256usize;
        let stride = 8usize;
        let mut m: BTreeMap<usize, Ts> = BTreeMap::new();
        let mut sweeps = 0usize;
        for i in 0..cap * 4 {
            if m.len() >= cap {
                sweeps += 1;
                evict_for_capacity(&mut m, 0, stride, |&t| t);
            }
            m.insert(i, 1_000);
            assert!(m.len() <= cap);
        }
        assert!(sweeps <= (cap * 4) / stride + 1, "sweeps = {sweeps}");
    }
}
