//! Answer provenance: what one final answer depends on.
//!
//! # The gap a per-entry model leaves
//!
//! [`crate::hazard`] answers "is *this* RRset still correct?". A resolver
//! never serves one RRset, though: it serves a *final answer*, assembled
//! from several cache entries that were each resolved at a different time
//! and each have their own freshness. For `www.example.com` that can be a
//! CNAME, the target's A RRset, the delegation that made the target
//! resolvable, the address of the nameserver that answered, and the DNSSEC
//! proof that binds them. The answer is correct only if *all* of them are
//! correct, and the resolver's per-entry view cannot say that.
//!
//! # The bound
//!
//! For an answer `A` with dependency set `D(A)`:
//!
//! ```text
//! P(A servable) ≤ min      P_LCB(v fresh)
//!                 v ∈ D(A)
//! ```
//!
//! The minimum is the *only* sound combination without an independence
//! assumption, and the independence assumption is usually false: an
//! authoritative republish can change a CNAME and its target in the same
//! zone at the same instant, so multiplying the probabilities would
//! understate the risk. The product
//! ([`Provenance::independent_bound`]) is therefore offered as a diagnostic
//! and never as the decision input.
//!
//! # Why this changes the refresh decision
//!
//! Sorting the dependencies by freshness gives an immediate and slightly
//! uncomfortable result: **refreshing anything except a bottleneck cannot
//! raise the answer's bound at all.** A resolver that prefetches every
//! expiring member of the chain spends the whole refresh budget and improves
//! the weakest-link bound by exactly zero whenever the same member remains
//! the weakest. [`Provenance::refresh_plan`] consequently returns the
//! dependencies in ascending freshness order — the bottleneck first, then the
//! next one, up to a bound — and [`Provenance::risk_reduction`] reports what
//! each would actually buy, so a caller can stop when the marginal refresh
//! stops mattering.
//!
//! This is also why [`crate::alias`] and this module coexist rather than
//! duplicating: the alias graph answers "what becomes invalid when this entry
//! changes" (a global reverse index, needed for invalidation), and this
//! module answers "what must be true for *this* answer to be serveable"
//! (a per-answer forward set, needed for the decision). Neither can be
//! derived cheaply from the other.
//!
//! # Bounds
//!
//! A dependency set is capped at [`ProvenanceConfig::max_dependencies`]. The
//! obvious implementation — keep the members you might want to refresh and
//! discard the rest — is a safety bug: `bound()` is a *minimum*, so dropping
//! a member can only raise it, and raising it is exactly the optimistic
//! error the bound exists to prevent. The implementation instead retains the
//! **weakest** `cap` dependencies and folds the minimum of everything
//! discarded into a residual floor ([`Provenance::residual`]). The reported
//! bound is then `min(retained ∪ {residual})`, which is *identical* to the
//! bound of the untrimmed set. Trimming costs memory, not soundness.
//!
//! The residual is also why [`Provenance::risk_reduction`] can return `0.0`
//! even for the bottleneck: if the floor comes from a dependency that is no
//! longer retained, no refresh of a retained member can lift the bound past
//! it, and the plan should say so rather than promise an improvement.

use alloc::vec::Vec;
use core::fmt;

use crate::cache::CacheKey;
use crate::name::Name;
use crate::qtype::RrType;
use crate::risk::Consequence;

/// The part a dependency plays in a final answer.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum DependencyRole {
    /// The answer RRset itself.
    Answer,
    /// A CNAME hop.
    Cname,
    /// A DNAME hop.
    Dname,
    /// The delegation (NS RRset) that made a hop resolvable.
    Delegation,
    /// An NS name's address.
    NsAddress,
    /// RRSIG/DS/DNSKEY/NSEC material backing the answer.
    DnssecProof,
}

impl DependencyRole {
    /// The consequence class this role implies.
    ///
    /// A hop is a *hop*: its own content is cheap (`Medium`), but a broken
    /// hop invalidates the whole chain, which is exactly what the
    /// consequence coefficient is meant to price. Delegation and proof
    /// material escalate to `Critical` and `Absolute` because they are not
    /// answer data at all — they are the machinery the answer rests on.
    pub fn consequence(self) -> Consequence {
        match self {
            DependencyRole::Answer => Consequence::Low,
            DependencyRole::Cname | DependencyRole::Dname => Consequence::Medium,
            DependencyRole::Delegation | DependencyRole::NsAddress => Consequence::Critical,
            DependencyRole::DnssecProof => Consequence::Absolute,
        }
    }

    /// Whether an answer containing this role may be served stale at all.
    ///
    /// A security proof that cannot be shown to be current is not a
    /// degraded answer; it is an unverifiable one.
    #[inline]
    pub fn permits_stale(self) -> bool {
        !matches!(self, DependencyRole::DnssecProof)
    }

    /// A short stable name, for logs and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            DependencyRole::Answer => "answer",
            DependencyRole::Cname => "cname",
            DependencyRole::Dname => "dname",
            DependencyRole::Delegation => "delegation",
            DependencyRole::NsAddress => "ns-address",
            DependencyRole::DnssecProof => "dnssec-proof",
        }
    }
}

/// Tuning for a dependency set.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProvenanceConfig {
    /// Maximum dependencies retained per answer.
    pub max_dependencies: usize,
}

impl Default for ProvenanceConfig {
    fn default() -> Self {
        Self {
            max_dependencies: 16,
        }
    }
}

/// One dependency of a final answer.
#[derive(Clone, Debug, PartialEq)]
pub struct Dependency {
    /// What part of the answer this is.
    pub role: DependencyRole,
    /// The cache key it lives at.
    pub key: CacheKey,
    /// How many CNAME/DNAME hops from the query name this sits.
    pub hop: u8,
    /// `P_LCB(fresh)` for this entry, in `[0, 1]`.
    pub freshness_lcb: f64,
}

impl Dependency {
    /// A dependency at the given role, key, hop count and freshness.
    pub fn new(role: DependencyRole, key: CacheKey, hop: u8, freshness_lcb: f64) -> Self {
        Self {
            role,
            key,
            hop,
            freshness_lcb: if freshness_lcb.is_nan() {
                0.0
            } else {
                freshness_lcb.clamp(0.0, 1.0)
            },
        }
    }

    /// Whether this dependency may be served stale.
    #[inline]
    pub fn permits_stale(&self) -> bool {
        self.role.permits_stale()
    }
}

/// The dependency set of one final answer.
#[derive(Clone, Debug)]
pub struct Provenance {
    config: ProvenanceConfig,
    deps: Vec<Dependency>,
    /// The minimum freshness among dependencies that were discarded by the
    /// cap. Keeps the bound identical to the untrimmed one.
    residual: f64,
}

impl Default for Provenance {
    fn default() -> Self {
        Self::new(ProvenanceConfig::default())
    }
}

impl Provenance {
    /// An empty set with the given configuration.
    pub fn new(config: ProvenanceConfig) -> Self {
        Self {
            config,
            deps: Vec::new(),
            residual: 1.0,
        }
    }

    /// Build from a dependency list, applying the cap.
    ///
    /// Trimming keeps the **weakest** `cap` dependencies — the ones whose
    /// refresh could matter — and records the minimum of the discarded ones
    /// as a residual floor, so the reported bound is unchanged. Every
    /// [`DependencyRole::DnssecProof`] is retained regardless, because a
    /// proof that has been discarded is an answer that can no longer be
    /// shown to be stale-eligible at all.
    pub fn from_dependencies(config: ProvenanceConfig, mut deps: Vec<Dependency>) -> Self {
        let cap = config.max_dependencies.max(1);
        let mut residual = 1.0f64;
        if deps.len() > cap {
            // Ascending freshness: the weakest sort first.
            deps.sort_by(|a, b| {
                a.freshness_lcb
                    .partial_cmp(&b.freshness_lcb)
                    .unwrap_or(core::cmp::Ordering::Equal)
                    .then_with(|| a.role.cmp(&b.role))
                    .then_with(|| a.key.cmp(&b.key))
            });
            let proofs: usize = deps
                .iter()
                .filter(|d| d.role == DependencyRole::DnssecProof)
                .count();
            // Room left for non-proof dependencies once the proofs are in.
            let room = cap.saturating_sub(proofs);
            let mut kept: Vec<Dependency> = Vec::with_capacity(cap.max(proofs));
            let mut others_kept = 0usize;
            for d in deps.drain(..) {
                if d.role == DependencyRole::DnssecProof || others_kept < room {
                    if d.role != DependencyRole::DnssecProof {
                        others_kept += 1;
                    }
                    kept.push(d);
                } else {
                    residual = residual.min(d.freshness_lcb);
                }
            }
            deps = kept;
        }
        Self {
            config,
            deps,
            residual,
        }
    }

    /// Add a dependency, honouring the cap by dropping the strongest
    /// non-proof member (dropping the weakest would raise the bound).
    pub fn push(&mut self, dep: Dependency) {
        self.deps.push(dep);
        let cap = self.config.max_dependencies.max(1);
        if self.deps.len() > cap {
            if let Some(idx) = self
                .deps
                .iter()
                .enumerate()
                .filter(|(_, d)| d.role != DependencyRole::DnssecProof)
                .max_by(|(_, a), (_, b)| {
                    a.freshness_lcb
                        .partial_cmp(&b.freshness_lcb)
                        .unwrap_or(core::cmp::Ordering::Equal)
                })
                .map(|(i, _)| i)
            {
                let dropped = self.deps.remove(idx);
                self.residual = self.residual.min(dropped.freshness_lcb);
            }
        }
    }

    /// The dependencies, in insertion order.
    pub fn dependencies(&self) -> &[Dependency] {
        &self.deps
    }

    /// The freshness floor contributed by dependencies discarded by the cap.
    ///
    /// `1.0` when nothing was discarded. A caller that wants to know whether
    /// the bound is attributable to a refreshable entry should compare this
    /// against [`Provenance::bound`].
    pub fn residual(&self) -> f64 {
        self.residual
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.deps.is_empty()
    }

    /// The number of retained dependencies.
    pub fn len(&self) -> usize {
        self.deps.len()
    }

    /// The conservative serviceability bound: the weakest link, including
    /// the residual floor.
    ///
    /// An empty set has no dependencies to be wrong, so it is `1.0`; callers
    /// that treat "no dependencies" as "unknown" must check
    /// [`Provenance::is_empty`] themselves, which is deliberate — silently
    /// mapping empty to `0.0` would make every answer look unsafe during
    /// construction.
    pub fn bound(&self) -> f64 {
        let weakest = self
            .deps
            .iter()
            .map(|d| d.freshness_lcb)
            .fold(f64::INFINITY, f64::min);
        weakest.min(self.residual)
    }

    /// The product of the per-dependency freshness values.
    ///
    /// **Diagnostic only.** The product is the right answer under
    /// independence, and authoritative zones violate independence routinely
    /// (one republish, several records). Reported so the gap between it and
    /// [`Provenance::bound`] can be observed, never used to decide.
    pub fn independent_bound(&self) -> f64 {
        if self.deps.is_empty() {
            return 1.0;
        }
        let mut p = 1.0;
        for d in &self.deps {
            p *= d.freshness_lcb;
        }
        p.clamp(0.0, 1.0)
    }

    /// The weakest retained dependency — the only one whose refresh can
    /// raise [`Provenance::bound`] in this moment.
    pub fn bottleneck(&self) -> Option<&Dependency> {
        self.deps.iter().min_by(|a, b| {
            a.freshness_lcb
                .partial_cmp(&b.freshness_lcb)
                .unwrap_or(core::cmp::Ordering::Equal)
        })
    }

    /// The increase in [`Provenance::bound`] obtainable by refreshing the
    /// retained dependency at `index` and nothing else.
    ///
    /// Refreshing anything but the bottleneck yields `0.0`: the bound is a
    /// minimum, so it moves only when the minimiser moves. Making that
    /// explicit is the point — a refresh scheduler that ignores it spends
    /// its budget without improving the guarantee.
    pub fn risk_reduction_at(&self, index: usize) -> f64 {
        if self.deps.get(index).is_none() {
            return 0.0;
        }
        let others = self
            .deps
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != index)
            .map(|(_, d)| d.freshness_lcb)
            .fold(f64::INFINITY, f64::min)
            .min(self.residual)
            .min(1.0);
        (others - self.bound()).max(0.0)
    }

    /// The same as [`Provenance::risk_reduction_at`], locating the
    /// dependency by value. Returns `0.0` when it is not retained
    /// (including when it was discarded by the cap).
    pub fn risk_reduction(&self, dep: &Dependency) -> f64 {
        match self.deps.iter().position(|d| d == dep) {
            Some(i) => self.risk_reduction_at(i),
            None => 0.0,
        }
    }

    /// The dependencies to refresh, bottleneck first, at most `max` of them.
    ///
    /// Ties are ordered by role then key so the plan is deterministic, which
    /// makes it reproducible in an experiment.
    pub fn refresh_plan(&self, max: usize) -> Vec<CacheKey> {
        let mut ordered: Vec<&Dependency> = self.deps.iter().collect();
        ordered.sort_by(|a, b| {
            a.freshness_lcb
                .partial_cmp(&b.freshness_lcb)
                .unwrap_or(core::cmp::Ordering::Equal)
                .then_with(|| a.role.cmp(&b.role))
                .then_with(|| a.key.cmp(&b.key))
        });
        ordered
            .into_iter()
            .take(max.max(1))
            .map(|d| d.key.clone())
            .collect()
    }

    /// Whether every dependency permits stale service at all.
    pub fn permits_stale(&self) -> bool {
        self.deps.iter().all(|d| d.permits_stale())
    }

    /// The strictest consequence class present in the set.
    pub fn worst_consequence(&self) -> Option<Consequence> {
        self.deps.iter().map(|d| d.role.consequence()).max()
    }

    /// Whether the answer's bound clears `threshold` *and* every dependency
    /// is stale-eligible.
    pub fn can_serve_stale(&self, threshold: f64) -> bool {
        !self.is_empty() && self.permits_stale() && self.bound() >= threshold
    }
}

impl fmt::Display for Provenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "provenance(n={} bound={:.3} independent={:.3} stale_ok={}",
            self.deps.len(),
            self.bound(),
            self.independent_bound(),
            self.permits_stale()
        )?;
        for d in &self.deps {
            write!(
                f,
                " {}@{}={:.3}",
                d.role.as_str(),
                d.key.name.to_ascii(),
                d.freshness_lcb
            )?;
        }
        write!(f, ")")
    }
}

/// Build the dependency set of an answer assembled from a CNAME chain.
///
/// `chain` is the ordered list of `(name, ttl-key)` hops the resolver
/// actually walked; `freshness_of` is a closure into the cache that returns
/// `P_LCB(fresh)` for a key (`0.0` when the entry is not present, which is
/// the conservative reading). The final answer's RRset is appended as the
/// last dependency, and — when present — a proof node is added for the
/// DNSSEC material.
///
/// Returning a [`Provenance`] rather than a score is what lets the decision
/// layer distinguish "the chain is degraded" from "the data is degraded".
pub fn from_alias_chain<F>(
    config: ProvenanceConfig,
    qname: &Name,
    qtype: RrType,
    chain: &[Name],
    proof_freshness: Option<f64>,
    mut freshness_of: F,
) -> Provenance
where
    F: FnMut(&CacheKey) -> f64,
{
    let mut deps: Vec<Dependency> = Vec::with_capacity(chain.len() + 2);
    let class = crate::qtype::RrClass::IN;
    // The chain hops: the first hop's owner is the query name, and each
    // subsequent hop is owned by the previous hop's target.
    for (i, _target) in chain.iter().enumerate() {
        let owner = if i == 0 {
            qname.clone()
        } else {
            chain.get(i - 1).cloned().unwrap_or_else(|| qname.clone())
        };
        let key = CacheKey::plain(owner, RrType::CNAME, class);
        let f = freshness_of(&key);
        deps.push(Dependency::new(
            DependencyRole::Cname,
            key,
            i.min(u8::MAX as usize) as u8,
            f,
        ));
    }
    let answer_owner = chain.last().cloned().unwrap_or_else(|| qname.clone());
    let answer_key = CacheKey::plain(answer_owner, qtype, class);
    let f = freshness_of(&answer_key);
    let hop = chain.len().min(u8::MAX as usize) as u8;
    deps.push(Dependency::new(
        DependencyRole::Answer,
        answer_key.clone(),
        hop,
        f,
    ));
    if let Some(pf) = proof_freshness {
        deps.push(Dependency::new(
            DependencyRole::DnssecProof,
            answer_key,
            hop,
            pf,
        ));
    }
    Provenance::from_dependencies(config, deps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qtype::RrClass;
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    fn key(name: &str, t: RrType) -> CacheKey {
        CacheKey::plain(Name::from_ascii(name).unwrap(), t, RrClass::IN)
    }

    fn dep(role: DependencyRole, name: &str, f: f64) -> Dependency {
        Dependency::new(role, key(name, RrType::A), 0, f)
    }

    #[test]
    fn bound_is_the_minimum_not_the_product() {
        let p = Provenance::from_dependencies(
            ProvenanceConfig::default(),
            vec![
                dep(DependencyRole::Answer, "a.example.com", 0.99),
                dep(DependencyRole::Cname, "b.example.com", 0.50),
            ],
        );
        assert!((p.bound() - 0.50).abs() < 1e-12);
        assert!(p.independent_bound() < p.bound());
    }

    #[test]
    fn only_the_bottleneck_refresh_moves_the_bound() {
        let weak = dep(DependencyRole::Cname, "b.example.com", 0.50);
        let strong = dep(DependencyRole::Answer, "a.example.com", 0.99);
        let p = Provenance::from_dependencies(
            ProvenanceConfig::default(),
            vec![weak.clone(), strong.clone()],
        );
        assert!((p.risk_reduction(&strong) - 0.0).abs() < 1e-12);
        // Refreshing the bottleneck perfectly raises the bound to the next
        // weakest.
        assert!((p.risk_reduction(&weak) - 0.49).abs() < 1e-12);
    }

    #[test]
    fn refresh_plan_is_bottleneck_first_and_deterministic() {
        let p = Provenance::from_dependencies(
            ProvenanceConfig::default(),
            vec![
                dep(DependencyRole::Answer, "a.example.com", 0.99),
                dep(DependencyRole::Cname, "b.example.com", 0.10),
                dep(DependencyRole::Cname, "c.example.com", 0.50),
            ],
        );
        let plan = p.refresh_plan(2);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.first().unwrap().name.to_ascii(), "b.example.com");
        assert_eq!(plan.get(1).unwrap().name.to_ascii(), "c.example.com");
        // Same input, same plan.
        let again = p.refresh_plan(2);
        assert_eq!(plan, again);
    }

    #[test]
    fn dnssec_proof_forbids_stale_service_entirely() {
        let p = Provenance::from_dependencies(
            ProvenanceConfig::default(),
            vec![
                dep(DependencyRole::Answer, "a.example.com", 1.0),
                dep(DependencyRole::DnssecProof, "a.example.com", 1.0),
            ],
        );
        assert!(!p.permits_stale());
        assert!(!p.can_serve_stale(0.0));
        assert_eq!(p.worst_consequence(), Some(Consequence::Absolute));
    }

    #[test]
    fn trimming_keeps_the_bound_conservative() {
        let config = ProvenanceConfig {
            max_dependencies: 3,
        };
        // Five dependencies; the weakest two must survive the trim, and the
        // resulting bound must not be higher than the untrimmed one.
        let all = vec![
            dep(DependencyRole::Answer, "a.example.com", 0.99),
            dep(DependencyRole::Answer, "b.example.com", 0.98),
            dep(DependencyRole::Answer, "c.example.com", 0.97),
            dep(DependencyRole::Answer, "d.example.com", 0.10),
            dep(DependencyRole::Answer, "e.example.com", 0.05),
        ];
        let full_bound = all
            .iter()
            .map(|d| d.freshness_lcb)
            .fold(f64::INFINITY, f64::min);
        let p = Provenance::from_dependencies(config, all);
        assert_eq!(p.len(), 3);
        assert!(p.bound() <= full_bound + 1e-12);
        assert!((p.bound() - full_bound).abs() < 1e-12);
    }

    #[test]
    fn push_drops_the_strongest_not_the_weakest() {
        let mut p = Provenance::new(ProvenanceConfig {
            max_dependencies: 2,
        });
        p.push(dep(DependencyRole::Answer, "weak.example.com", 0.10));
        p.push(dep(DependencyRole::Answer, "strong.example.com", 0.99));
        p.push(dep(DependencyRole::Answer, "mid.example.com", 0.50));
        assert_eq!(p.len(), 2);
        // The strongest was dropped, so the bound did not rise.
        assert!((p.bound() - 0.10).abs() < 1e-12);
    }

    #[test]
    fn empty_set_is_not_serviceable_but_bounds_at_one() {
        let p = Provenance::default();
        assert!(p.is_empty());
        assert_eq!(p.bound(), 1.0);
        assert!(
            !p.can_serve_stale(0.0),
            "an empty set must not read as safe"
        );
    }

    #[test]
    fn alias_chain_builds_the_expected_dependencies() {
        let chain = vec![
            Name::from_ascii("cdn.example.net").unwrap(),
            Name::from_ascii("edge.example.org").unwrap(),
        ];
        let p = from_alias_chain(
            ProvenanceConfig::default(),
            &Name::from_ascii("www.example.com").unwrap(),
            RrType::A,
            &chain,
            Some(1.0),
            |k| {
                // CNAMEs are weaker than the final answer.
                if k.rr_type == RrType::CNAME {
                    0.6
                } else {
                    0.95
                }
            },
        );
        assert_eq!(p.len(), 4); // 2 CNAMEs + answer + proof
        assert!((p.bound() - 0.6).abs() < 1e-12);
        assert!(!p.permits_stale(), "the proof node forbids stale");
        let roles: Vec<DependencyRole> = p.dependencies().iter().map(|d| d.role).collect();
        assert!(roles.contains(&DependencyRole::Cname));
        assert!(roles.contains(&DependencyRole::Answer));
        assert!(roles.contains(&DependencyRole::DnssecProof));
    }

    #[test]
    fn nan_freshness_is_treated_as_unsafe() {
        let d = Dependency::new(
            DependencyRole::Answer,
            key("a.example.com", RrType::A),
            0,
            f64::NAN,
        );
        assert_eq!(d.freshness_lcb, 0.0);
    }
}
