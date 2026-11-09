//! Answer dependencies and bounded safety summaries.
//!
//! `bound()` reports the weakest marginal prediction for diagnostics only.
//! The joint lower bound is `max(0, 1 - sum(1 - p_i))`, without assuming
//! independence. It is conditional on valid marginal lower bounds; the
//! approximate observation model does not itself establish their coverage.
//!
//! Every dependency obeys the configured capacity. Dropped dependencies keep
//! their failure mass, worst consequence and stale prohibition in a fixed-size
//! summary. Refresh plans rank the improvement in the joint lower bound.

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
            freshness_lcb: if !freshness_lcb.is_finite() {
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
    residual_failure_sum: f64,
    residual_worst_consequence: Option<Consequence>,
    residual_forbids_stale: bool,
    has_dependencies: bool,
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
            residual_failure_sum: 0.0,
            residual_worst_consequence: None,
            residual_forbids_stale: false,
            has_dependencies: false,
        }
    }

    /// Build from a dependency list using the same bounded rule as `push`.
    pub fn from_dependencies(config: ProvenanceConfig, deps: Vec<Dependency>) -> Self {
        let mut result = Self::new(config);
        for dep in deps {
            result.push(dep);
        }
        result
    }

    /// Retain at most the configured number of nodes, summarizing every
    /// discarded restriction. Even a zero capacity and proof-only set obey it.
    pub fn push(&mut self, mut dep: Dependency) {
        // Public fields may bypass Dependency::new: validate at ingestion too.
        dep.freshness_lcb = if dep.freshness_lcb.is_finite() {
            dep.freshness_lcb.clamp(0.0, 1.0)
        } else {
            0.0
        };
        self.has_dependencies = true;
        if self.deps.len() < self.config.max_dependencies {
            self.deps.push(dep);
            return;
        }
        if let Some((index, strongest)) = self.deps.iter().enumerate().max_by(|(_, a), (_, b)| {
            a.freshness_lcb
                .total_cmp(&b.freshness_lcb)
                .then_with(|| a.role.cmp(&b.role))
                .then_with(|| a.key.cmp(&b.key))
        }) {
            if dep.freshness_lcb < strongest.freshness_lcb {
                if let Some(retained) = self.deps.get_mut(index) {
                    dep = core::mem::replace(retained, dep);
                }
            }
        }
        self.residual = self.residual.min(dep.freshness_lcb);
        self.residual_failure_sum = (self.residual_failure_sum + 1.0 - dep.freshness_lcb).min(1.0);
        self.residual_worst_consequence = self
            .residual_worst_consequence
            .max(Some(dep.role.consequence()));
        self.residual_forbids_stale |= !dep.permits_stale();
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
        !self.has_dependencies
    }

    /// The number of retained dependencies.
    pub fn len(&self) -> usize {
        self.deps.len()
    }

    /// Diagnostic weakest marginal prediction, including
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

    /// Joint lower bound, conditional on valid marginal bounds. No
    /// independence assumption is made. Trimming cannot raise this value.
    pub fn joint_lower_bound(&self) -> f64 {
        let failure_sum = self
            .deps
            .iter()
            .fold(self.residual_failure_sum, |sum, dep| {
                (sum + (1.0 - dep.freshness_lcb)).min(1.0)
            });
        (1.0 - failure_sum).clamp(0.0, 1.0)
    }

    /// The weakest retained marginal prediction (diagnostic only).
    pub fn bottleneck(&self) -> Option<&Dependency> {
        self.deps
            .iter()
            .min_by(|a, b| a.freshness_lcb.total_cmp(&b.freshness_lcb))
    }

    /// Joint-bound improvement if one retained dependency becomes fresh.
    pub fn risk_reduction_at(&self, index: usize) -> f64 {
        if index >= self.deps.len() {
            return 0.0;
        }
        let remaining = self
            .deps
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != index)
            .fold(self.residual_failure_sum, |sum, (_, d)| {
                (sum + 1.0 - d.freshness_lcb).min(1.0)
            });
        ((1.0 - remaining) - self.joint_lower_bound()).max(0.0)
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

    /// Rank retained dependencies by joint-bound improvement, at most `max`.
    ///
    /// Ties are ordered by role then key so the plan is deterministic, which
    /// makes it reproducible in an experiment.
    pub fn refresh_plan(&self, max: usize) -> Vec<CacheKey> {
        let mut ordered: Vec<_> = self
            .deps
            .iter()
            .enumerate()
            .map(|(index, dep)| (dep, self.risk_reduction_at(index)))
            .collect();
        ordered.sort_by(|(a, gain_a), (b, gain_b)| {
            gain_b
                .total_cmp(gain_a)
                .then_with(|| a.role.cmp(&b.role))
                .then_with(|| a.key.cmp(&b.key))
        });
        ordered
            .into_iter()
            .take(max)
            .map(|(dep, _)| dep.key.clone())
            .collect()
    }

    /// Whether every dependency permits stale service at all.
    pub fn permits_stale(&self) -> bool {
        !self.residual_forbids_stale && self.deps.iter().all(|d| d.permits_stale())
    }

    /// The strictest consequence class present in the set.
    pub fn worst_consequence(&self) -> Option<Consequence> {
        self.deps
            .iter()
            .map(|d| d.role.consequence())
            .max()
            .max(self.residual_worst_consequence)
    }

    /// Whether the answer's bound clears `threshold` *and* every dependency
    /// is stale-eligible.
    pub fn can_serve_stale(&self, threshold: f64) -> bool {
        !self.is_empty() && self.permits_stale() && self.joint_lower_bound() >= threshold
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
    fn regression_joint_gate_does_not_use_minimum() {
        let p = Provenance::from_dependencies(
            ProvenanceConfig::default(),
            vec![
                dep(DependencyRole::Answer, "a.example", 0.99),
                dep(DependencyRole::Cname, "b.example", 0.99),
            ],
        );
        assert!(!p.can_serve_stale(0.99));
    }

    #[test]
    fn regression_proofs_obey_capacity() {
        let mut p = Provenance::new(ProvenanceConfig {
            max_dependencies: 1,
        });
        for i in 0..10 {
            p.push(dep(
                DependencyRole::DnssecProof,
                &alloc::format!("p{i}.example"),
                1.0,
            ));
        }
        assert_eq!(p.len(), 1);
        assert!(!p.permits_stale());
    }

    #[test]
    fn regression_trim_preserves_consequence() {
        let p = Provenance::from_dependencies(
            ProvenanceConfig {
                max_dependencies: 1,
            },
            vec![
                dep(DependencyRole::Answer, "a.example", 0.5),
                dep(DependencyRole::Delegation, "b.example", 1.0),
            ],
        );
        assert_eq!(p.worst_consequence(), Some(Consequence::Critical));
    }

    #[test]
    fn regression_joint_bound_saturates_and_empty_is_one() {
        assert_eq!(Provenance::default().joint_lower_bound(), 1.0);
        let p = Provenance::from_dependencies(
            ProvenanceConfig::default(),
            vec![
                dep(DependencyRole::Answer, "a.example", 0.2),
                dep(DependencyRole::Answer, "b.example", 0.3),
            ],
        );
        assert_eq!(p.joint_lower_bound(), 0.0);
    }

    #[test]
    fn regression_trimming_is_safety_equivalent_including_zero_capacity() {
        let deps = vec![
            dep(DependencyRole::Answer, "a.example", 0.99),
            dep(DependencyRole::Delegation, "b.example", 0.98),
            dep(DependencyRole::DnssecProof, "c.example", 0.97),
        ];
        let full = Provenance::from_dependencies(ProvenanceConfig::default(), deps.clone());
        for cap in 0..=deps.len() {
            let config = ProvenanceConfig {
                max_dependencies: cap,
            };
            let bulk = Provenance::from_dependencies(config, deps.clone());
            let mut pushed = Provenance::new(config);
            for dep in deps.iter().rev() {
                pushed.push(dep.clone());
            }
            for p in [bulk, pushed] {
                assert!(p.len() <= cap);
                assert!(!p.is_empty());
                assert!((p.joint_lower_bound() - full.joint_lower_bound()).abs() < 1e-12);
                assert_eq!(p.bound(), full.bound());
                assert_eq!(p.worst_consequence(), full.worst_consequence());
                assert_eq!(p.permits_stale(), full.permits_stale());
            }
        }
    }

    #[test]
    fn regression_public_dependency_fields_are_validated() {
        for probability in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0] {
            let mut d = dep(DependencyRole::Answer, "a.example", 1.0);
            d.freshness_lcb = probability;
            let p = Provenance::from_dependencies(ProvenanceConfig::default(), vec![d]);
            assert_eq!(p.joint_lower_bound(), 0.0);
        }
    }

    #[test]
    fn regression_joint_risk_refresh_gain_accounts_for_residual() {
        let p = Provenance::from_dependencies(
            ProvenanceConfig {
                max_dependencies: 1,
            },
            vec![
                dep(DependencyRole::Answer, "a.example", 0.8),
                dep(DependencyRole::Answer, "b.example", 0.9),
            ],
        );
        assert!((p.joint_lower_bound() - 0.7).abs() < 1e-12);
        assert!((p.risk_reduction_at(0) - 0.2).abs() < 1e-12);
        assert!(p.refresh_plan(0).is_empty());
    }

    #[test]
    fn regression_planner_uses_joint_probability_and_trimmed_restrictions() {
        let p = Provenance::from_dependencies(
            ProvenanceConfig {
                max_dependencies: 1,
            },
            vec![
                dep(DependencyRole::Answer, "a.example", 0.99),
                dep(DependencyRole::Delegation, "b.example", 0.99),
            ],
        );
        let ctx = crate::planner::StaleContext {
            consequence: Consequence::Low,
            trust: crate::risk::TrustLevel::Unverified,
            freshness_lcb: 1.0,
            staleness_secs: 1.0,
            value_ms: 50.0,
        }
        .with_provenance(&p);
        assert!((ctx.freshness_lcb - 0.98).abs() < 1e-12);
        assert_eq!(ctx.consequence, Consequence::Critical);
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
    fn every_dependency_refresh_can_reduce_joint_risk() {
        let weak = dep(DependencyRole::Cname, "b.example.com", 0.50);
        let strong = dep(DependencyRole::Answer, "a.example.com", 0.99);
        let p = Provenance::from_dependencies(
            ProvenanceConfig::default(),
            vec![weak.clone(), strong.clone()],
        );
        assert!((p.risk_reduction(&strong) - 0.01).abs() < 1e-12);
        assert!((p.risk_reduction(&weak) - 0.50).abs() < 1e-12);
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
