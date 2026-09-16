//! Alias dependencies between cached answers.
//!
//! A cache answers one question: *what is stored under this key*. There is a
//! second question it structurally cannot answer — *what else does this data
//! keep servable* — because a `BTreeMap<key, data>` has no notion of one
//! entry being useful only while another is fresh. In DNS that relation is
//! pervasive and real: a resolver serves `www.example.com A` from cache only
//! when **both** the CNAME at `www` and the target's address data are fresh.
//! Refresh the target while the CNAME expires a minute later and the client
//! pays a full resolution anyway — the prefetch did half a job.
//!
//! `AliasGraph` records that relation and both directions of it:
//!
//! * [`AliasGraph::dependents`] — what an entry keeps servable. The resolver
//!   uses it whenever it refreshes an entry (predictive prefetch, or a
//!   serve-stale refresh from the request path) to pull the alias along, so a
//!   chain is refreshed as a unit while both hops are still cheap to fetch.
//! * [`AliasGraph::depends_on`] / [`AliasGraph::closure`] — the forward
//!   direction, for walking a chain from its head.
//!
//! Scope note: an earlier revision of this module was a general resolution
//! graph with zone, nameserver and server-address nodes. Nothing ever
//! queried it — every resolution step paid to record edges no decision read.
//! It was replaced by this structure, which has one relation, one purpose,
//! and one consumer.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::fmt;

use crate::cache::CacheKey;
use crate::time::Ts;

/// Bounds for the alias graph.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AliasConfig {
    /// Maximum number of edges. At the cap, a new edge is not recorded: the
    /// background prune is what makes room again, which keeps [`AliasGraph::link`]
    /// at `O(log n)` in every case instead of evicting on the resolution path.
    pub max_edges: usize,
    /// Keys not touched for this long are pruned.
    pub prune_age_secs: u64,
}

impl Default for AliasConfig {
    fn default() -> Self {
        Self {
            max_edges: 100_000,
            prune_age_secs: 3_600,
        }
    }
}

/// The alias-dependency graph over cached keys.
pub struct AliasGraph {
    config: AliasConfig,
    /// `from` depends on `to`.
    fwd: BTreeMap<CacheKey, BTreeSet<CacheKey>>,
    /// `to` is depended on by `from`.
    rev: BTreeMap<CacheKey, BTreeSet<CacheKey>>,
    /// Last time a key took part in a resolution (drives pruning).
    seen: BTreeMap<CacheKey, Ts>,
    edges: usize,
}

impl AliasGraph {
    /// An empty graph.
    pub fn new(config: AliasConfig) -> Self {
        Self {
            config,
            fwd: BTreeMap::new(),
            rev: BTreeMap::new(),
            seen: BTreeMap::new(),
            edges: 0,
        }
    }

    /// The configuration.
    pub fn config(&self) -> &AliasConfig {
        &self.config
    }

    /// Record that the CNAME entry at `alias` is only servable while the
    /// data at `target` is fresh. Idempotent.
    pub fn link(&mut self, alias: &CacheKey, target: &CacheKey, now: Ts) {
        self.seen.insert(alias.clone(), now);
        self.seen.insert(target.clone(), now);
        if self
            .fwd
            .get(alias)
            .map(|s| s.contains(target))
            .unwrap_or(false)
        {
            return;
        }
        if self.edges >= self.config.max_edges {
            return;
        }
        self.fwd
            .entry(alias.clone())
            .or_default()
            .insert(target.clone());
        self.rev
            .entry(target.clone())
            .or_default()
            .insert(alias.clone());
        self.edges += 1;
    }

    /// The entries kept servable by `key` (its aliases).
    pub fn dependents(&self, key: &CacheKey) -> Vec<CacheKey> {
        self.rev
            .get(key)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// The data `key` needs fresh to be servable (its targets).
    pub fn depends_on(&self, key: &CacheKey) -> Vec<CacheKey> {
        self.fwd
            .get(key)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Every entry reachable from `key` through alias edges, including `key`
    /// itself, bounded to `max` keys.
    pub fn closure(&self, key: &CacheKey, max: usize) -> Vec<CacheKey> {
        let mut seen: BTreeSet<CacheKey> = BTreeSet::new();
        let mut queue: VecDeque<CacheKey> = VecDeque::new();
        seen.insert(key.clone());
        queue.push_back(key.clone());
        while let Some(cur) = queue.pop_front() {
            if seen.len() >= max {
                break;
            }
            for next in self.depends_on(&cur) {
                if seen.insert(next.clone()) {
                    queue.push_back(next);
                }
            }
        }
        seen.into_iter().collect()
    }

    /// Drop keys (and their edges) not seen within `min_age_secs`, or older
    /// than the configured age when `min_age_secs == 0`.
    ///
    /// One pass selects the dead keys and one pass rewrites the maps, so the
    /// cost is `O(keys + edges)` per sweep rather than `O(dead × edges)`.
    pub fn prune(&mut self, now: Ts, min_age_secs: u64) {
        let age = if min_age_secs == 0 {
            self.config.prune_age_secs
        } else {
            min_age_secs
        };
        let cutoff = now.saturating_sub(age as Ts * 1_000_000_000);
        let dead: BTreeSet<CacheKey> = self
            .seen
            .iter()
            .filter(|(_, t)| **t < cutoff)
            .map(|(k, _)| k.clone())
            .collect();
        if dead.is_empty() {
            return;
        }
        for k in &dead {
            self.seen.remove(k);
        }
        for (k, deps) in self.fwd.iter_mut() {
            if !dead.contains(k) {
                deps.retain(|d| !dead.contains(d));
            }
        }
        self.fwd.retain(|k, v| !dead.contains(k) && !v.is_empty());
        for (k, deps) in self.rev.iter_mut() {
            if !dead.contains(k) {
                deps.retain(|d| !dead.contains(d));
            }
        }
        self.rev.retain(|k, v| !dead.contains(k) && !v.is_empty());
        // Recount rather than adjusting incrementally: with keys and edges
        // removed in the same sweep, a running counter is exactly the kind
        // of bookkeeping that drifts and then silently disables the cap.
        self.edges = self.fwd.values().map(|s| s.len()).sum();
    }

    /// The number of recorded edges.
    pub fn edge_count(&self) -> usize {
        self.edges
    }

    /// The number of keys that take part in a dependency.
    pub fn key_count(&self) -> usize {
        self.fwd
            .keys()
            .chain(self.rev.keys())
            .collect::<BTreeSet<_>>()
            .len()
    }
}

impl fmt::Debug for AliasGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AliasGraph(keys={}, edges={})",
            self.key_count(),
            self.edges
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::Name;
    use crate::qtype::{RrClass, RrType};
    #[cfg(not(feature = "std"))]
    use alloc::{format, vec};

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    fn key(name: &str, t: RrType) -> CacheKey {
        CacheKey::plain(Name::from_ascii(name).unwrap(), t, RrClass::IN)
    }

    /// The two-hop chain `www --CNAME--> cdn --CNAME--> edge`, and what each
    /// direction of the relation answers.
    #[test]
    fn alias_chain_is_queryable_both_ways() {
        let mut g = AliasGraph::new(AliasConfig::default());
        let www = key("www.example.com", RrType::CNAME);
        let cdn = key("cdn.example.net", RrType::A);
        let cdn_alias = key("cdn.example.net", RrType::CNAME);
        let edge = key("edge.example.net", RrType::A);
        g.link(&www, &cdn, now());
        g.link(&cdn_alias, &edge, now());

        assert_eq!(g.dependents(&cdn), vec![www.clone()]);
        assert_eq!(g.dependents(&edge), vec![cdn_alias.clone()]);
        assert_eq!(g.depends_on(&www), vec![cdn.clone()]);
        assert_eq!(g.edge_count(), 2);
        assert_eq!(g.key_count(), 4);

        // Walking from the head of the chain reaches the target's data.
        let closure = g.closure(&www, 8);
        assert_eq!(closure.len(), 2);
        assert!(closure.contains(&www));
        assert!(closure.contains(&cdn));
        assert_eq!(g.closure(&www, 1).len(), 1);
    }

    #[test]
    fn link_is_idempotent_and_capped() {
        let mut g = AliasGraph::new(AliasConfig {
            max_edges: 2,
            prune_age_secs: 60,
        });
        let a = key("a.example.com", RrType::A);
        let b = key("b.example.com", RrType::A);
        let c = key("c.example.com", RrType::A);
        let d = key("d.example.com", RrType::A);
        g.link(&a, &b, now());
        g.link(&a, &b, now());
        assert_eq!(g.edge_count(), 1, "a repeated link is not a new edge");
        g.link(&b, &c, now());
        g.link(&c, &d, now());
        assert_eq!(g.edge_count(), 2, "the cap holds");
    }

    /// Pruning must drop the pruned keys' edges in both directions — a
    /// dangling reverse edge would make the resolver refresh keys forever.
    #[test]
    fn prune_drops_edges_in_both_directions() {
        let mut g = AliasGraph::new(AliasConfig {
            max_edges: 100,
            prune_age_secs: 60,
        });
        let old = key("old.example.com", RrType::CNAME);
        let fresh = key("fresh.example.com", RrType::A);
        g.link(&old, &fresh, now() - 3_600_000_000_000);
        g.link(
            &key("fresh.example.com", RrType::CNAME),
            &key("new.example.com", RrType::A),
            now(),
        );

        g.prune(now(), 0);
        assert!(!g.dependents(&fresh).contains(&old));
        assert_eq!(g.edge_count(), 1, "stale edge must be gone");
        assert_eq!(g.key_count(), 2);
    }

    /// A graph that never prunes must not grow past its edge cap.
    #[test]
    fn unbounded_links_are_capped() {
        let mut g = AliasGraph::new(AliasConfig {
            max_edges: 8,
            prune_age_secs: 3_600,
        });
        for i in 0..50 {
            let from = key(&format!("h{i}.example.com"), RrType::CNAME);
            let to = key("target.example.com", RrType::A);
            g.link(&from, &to, now());
        }
        assert_eq!(g.edge_count(), 8);
        assert_eq!(g.dependents(&key("target.example.com", RrType::A)).len(), 8);
    }
}
