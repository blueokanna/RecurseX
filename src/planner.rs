//! The resolution planner: what to do with a cache outcome.
//!
//! Three answers are possible for a query whose data has expired:
//!
//! * **Resolve** — block the client on a real resolution.
//! * **Serve stale** — answer from the expired copy and refresh out of band.
//! * **Serve fresh** — nothing to decide.
//!
//! The plan chooses between the first two, and the choice is where the whole
//! design either holds together or does not.
//!
//! # What the plan must not do
//!
//! The tempting rule is *"answer stale when the name is popular"* — a cache
//! hit is cheaper than a resolution, so serve one whenever somebody wants
//! it. The rule is wrong, and it is wrong in the direction that hurts:
//! popularity measures the **benefit** of an answer and is silent about its
//! **safety**. Applying it means the busiest zone in the deployment becomes
//! the one most likely to be answered from a copy that a decommissioned NS
//! or a revoked key has invalidated, and the failure is correlated with
//! traffic — precisely the shape of an outage.
//!
//! # What the plan does instead
//!
//! Two questions, answered separately, then combined:
//!
//! * **Is it safe?** The freshness of the *whole answer* — the weakest link
//!   of its provenance DAG ([`crate::provenance`]) — must clear a
//!   consequence-scaled floor, and the resulting ex-ante risk must fit the
//!   aggregate budget ([`crate::risk::RiskLedger`]).
//! * **Is it worth it?** Used only to decide what to *refresh* and what to
//!   *keep*, never whether stale may be served.
//!
//! A "no" from the safety question is final. A "no" from the value question
//! only means a refresh is not worth a slot — the answer may still be served
//! stale if it is safe, because serving a safe stale answer costs nothing
//! while a needless upstream query costs bandwidth.
//!
//! # Prefetch is scheduling, not a threshold
//!
//! The conventional rule is "refresh once the remaining TTL falls below some
//! fraction of the original" (Unbound's classic prefetch uses 10 %). That
//! rule is a proxy: it uses the zone's *claim* about its data as a stand-in
//! for how often the data changes, which is exactly the conflation
//! [`crate::hazard`] exists to remove. The rule here is the model's own
//! scheduling answer — refresh when the conservative probability of still
//! being correct will fall below a target inside the horizon:
//!
//! ```text
//! refresh  ⇔  P_LCB(fresh, horizon) < target  ∧  demand is expected
//! ```
//!
//! which for a well-observed set happens near its natural expiry and for a
//! volatile one happens early and often, without either case naming a
//! percentage.

use crate::cache::{CacheEntry, LookupOutcome};
use crate::hazard::HazardConfig;
use crate::provenance::Provenance;
use crate::risk::{assess, Assessment, Consequence, Refusal, RiskConfig, RiskLedger, TrustLevel};
use crate::stability::StabilityModel;
use crate::time::Ts;

/// What the resolver should do for a query.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Plan {
    /// Answer from a fresh cache entry.
    ServeFresh,
    /// Answer from a stale entry (serve-stale, RFC 8767). When
    /// `refresh_in_background` is set, a refresh is queued so the next query
    /// gets fresh data.
    ServeStale {
        /// Whether to queue a background refresh after serving stale.
        refresh_in_background: bool,
    },
    /// Do a full (or iterative) resolution now.
    Resolve,
}

/// The inputs a stale decision needs that the cache entry cannot supply.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StaleContext {
    /// The consequence class of the record in its role in *this* answer.
    pub consequence: Consequence,
    /// How well the authenticity of the data was established.
    pub trust: TrustLevel,
    /// The conservative freshness of the whole answer's provenance DAG.
    ///
    /// Taken from [`Provenance::bound`] when a provenance set is available
    /// (the correct source), or from the entry's own model when the answer
    /// has a single dependency.
    pub freshness_lcb: f64,
    /// How far past expiry the answer would be served, in seconds.
    pub staleness_secs: f64,
    /// Expected saved latency if the answer is served from memory, in ms.
    pub value_ms: f64,
}

impl StaleContext {
    /// A context for a single-dependency answer, derived from the entry.
    pub fn from_entry(entry: &CacheEntry, now: Ts, value_ms: f64, trust: TrustLevel) -> Self {
        let staleness = now.saturating_sub(entry.expires) as f64 / 1e9;
        let staleness = staleness.max(0.0);
        Self {
            consequence: Consequence::classify(entry.key.rr_type, false),
            trust,
            freshness_lcb: entry.stability.freshness_lcb(staleness),
            staleness_secs: staleness,
            value_ms,
        }
    }

    /// The same context, with the freshness and the consequence replaced by
    /// those of a whole provenance set.
    pub fn with_provenance(mut self, provenance: &Provenance) -> Self {
        self.freshness_lcb = provenance.bound();
        if let Some(worst) = provenance.worst_consequence() {
            self.consequence = self.consequence.max(worst);
        }
        self
    }
}

/// Planner configuration.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PlannerConfig {
    /// The hazard configuration used for entries the cache did not create
    /// with one (diagnostics and tests).
    pub hazard: HazardConfig,
    /// The risk model's configuration.
    pub risk: RiskConfig,
    /// Minimum effective exposure before prediction is used at all.
    ///
    /// Redundant with the credibility bound for safety, and deliberately
    /// kept: "do not act on prediction for a name I met a minute ago" is a
    /// legitimate operational preference, and expressing it as exposure
    /// rather than as a sample count makes it checkable.
    pub min_evidence_secs: f64,
    /// The prediction horizon used for stale and prefetch decisions, in
    /// seconds.
    pub prefetch_horizon_secs: u32,
    /// The demand probability below which a background refresh is not worth
    /// a budget slot. Value only — it never gates stale service.
    pub prefetch_min_probability: f64,
    /// The `P_LCB(fresh, horizon)` below which the model asks to be
    /// refreshed. This is the replacement for the fixed
    /// remaining-TTL-fraction rule.
    pub prefetch_target_freshness: f64,
}

impl Default for PlannerConfig {
    fn default() -> Self {
        Self {
            hazard: HazardConfig::default(),
            risk: RiskConfig::default(),
            min_evidence_secs: 300.0,
            prefetch_horizon_secs: 60,
            prefetch_min_probability: 0.5,
            prefetch_target_freshness: 0.9,
        }
    }
}

/// The value-only inputs of a prefetch decision.
///
/// Separated from [`PlannerConfig`] so the cache can evaluate candidates
/// without holding a planner (and hence without holding the risk policy,
/// which is not its business).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PrefetchPolicy {
    /// The horizon over which freshness is evaluated.
    pub horizon_secs: u32,
    /// The freshness below which a refresh is worthwhile.
    pub target_freshness: f64,
    /// The demand probability below which a refresh is not worth a slot.
    pub min_probability: f64,
    /// Minimum effective exposure before prediction is used at all.
    pub min_evidence_secs: f64,
}

impl PrefetchPolicy {
    /// Evaluate the policy's freshness criterion on one entry model.
    ///
    /// `query_probability` is the estimator's `P(a query within the
    /// horizon)` for the entry's zone.
    pub fn wants_refresh(&self, stability: &StabilityModel, query_probability: f64) -> bool {
        if query_probability.is_nan() || query_probability < self.min_probability {
            return false;
        }
        if !stability.hazard().has_evidence(self.min_evidence_secs) {
            return false;
        }
        stability.freshness_lcb(self.horizon_secs as f64) < self.target_freshness
    }
}

impl PlannerConfig {
    /// The value-only prefetch inputs derived from this configuration.
    pub fn prefetch_policy(&self) -> PrefetchPolicy {
        PrefetchPolicy {
            horizon_secs: self.prefetch_horizon_secs,
            target_freshness: self.prefetch_target_freshness,
            min_probability: self.prefetch_min_probability,
            min_evidence_secs: self.min_evidence_secs,
        }
    }
}

/// The resolution planner.
#[derive(Clone, Debug)]
pub struct ResolutionPlanner {
    config: PlannerConfig,
}

impl ResolutionPlanner {
    /// A planner with the given configuration.
    pub fn new(config: PlannerConfig) -> Self {
        Self { config }
    }

    /// The configuration.
    pub fn config(&self) -> &PlannerConfig {
        &self.config
    }

    /// The risk configuration.
    pub fn risk_config(&self) -> &RiskConfig {
        &self.config.risk
    }

    /// Assess a stale candidate without charging any budget. Pure.
    pub fn assess_stale(&self, ctx: &StaleContext) -> Assessment {
        assess(
            &self.config.risk,
            ctx.value_ms,
            ctx.consequence,
            ctx.trust,
            ctx.freshness_lcb,
            ctx.staleness_secs,
        )
    }

    /// Decide a cache outcome, charging the risk ledger when stale service
    /// is admitted.
    ///
    /// The ledger is a parameter rather than a field because it is shared,
    /// mutable state: putting it inside the planner would make the planner
    /// non-`Clone` and would hide the fact that the decision has a cost.
    pub fn plan(
        &self,
        outcome: &LookupOutcome,
        now: Ts,
        ctx: Option<&StaleContext>,
        ledger: &mut RiskLedger,
    ) -> Plan {
        match outcome {
            LookupOutcome::Fresh(_) => Plan::ServeFresh,
            LookupOutcome::Stale(entry) => {
                let derived;
                let ctx = match ctx {
                    Some(c) => c,
                    None => {
                        derived = StaleContext::from_entry(entry, now, 0.0, TrustLevel::Unverified);
                        &derived
                    }
                };
                // Prediction requires evidence. The credibility bound already
                // enforces this statistically; the gate exists so an operator
                // can see *why* a young entry was not predicted about,
                // instead of watching a probability move.
                if !entry
                    .stability
                    .hazard()
                    .has_evidence(self.config.min_evidence_secs)
                {
                    return Plan::Resolve;
                }
                let a = self.assess_stale(ctx);
                if !a.allowed {
                    return Plan::Resolve;
                }
                if !ledger.try_charge(a.risk, now) {
                    return Plan::Resolve;
                }
                Plan::ServeStale {
                    refresh_in_background: true,
                }
            }
            _ => Plan::Resolve,
        }
    }

    /// Whether a cached entry should be refreshed in the background.
    ///
    /// The criterion is the model's own scheduling answer, gated on expected
    /// demand. This function decides **value**, never safety: a `false` here
    /// does not forbid serving the entry stale.
    pub fn should_prefetch(&self, stability: &StabilityModel, query_probability: f64) -> bool {
        self.config
            .prefetch_policy()
            .wants_refresh(stability, query_probability)
    }

    /// The reason a stale plan would be refused, as a diagnostic helper. Not
    /// part of the decision path.
    pub fn refusal_of(&self, ctx: &StaleContext) -> Option<Refusal> {
        self.assess_stale(ctx).refusal
    }
}

/// The consequence class of a record in the role it plays *for us* rather
/// than for the client.
///
/// A record lifted from a referral's authority or additional section is
/// addressed to the resolver, and its staleness poisons the walk for every
/// later query under that zone — which is why the same A record is
/// `Consequence::Low` as answer data and `Consequence::Critical` as glue.
pub fn delegation_consequence(rr_type: crate::qtype::RrType) -> Consequence {
    Consequence::classify(rr_type, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{CacheKey, EntryKind, Tier};
    use crate::estimator::QueryEstimator;
    use crate::name::Name;
    use crate::qtype::{RrClass, RrType};
    use crate::rrset::RrSet;

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    fn entry(
        rr_type: RrType,
        validated: bool,
        stability: StabilityModel,
        expired_secs: Ts,
    ) -> CacheEntry {
        CacheEntry {
            key: CacheKey::plain(
                Name::from_ascii("www.example.com").unwrap(),
                rr_type,
                RrClass::IN,
            ),
            kind: EntryKind::Positive(RrSet::a("www.example.com", "192.0.2.1", 300)),
            inserted: now() - 400 * 1_000_000_000,
            expires: now() - expired_secs * 1_000_000_000,
            served: 5,
            last_served: now() - 10 * 1_000_000_000,
            stability,
            validated,
            score: 0.5,
            tier: Tier::Cold,
            refreshing: false,
            cost_ms: 50.0,
        }
    }

    fn well_observed(start: Ts) -> StabilityModel {
        let mut m = StabilityModel::new(start);
        for i in 1..=200 {
            m.observe(300, false, start + i * 300 * 1_000_000_000);
        }
        m
    }

    #[test]
    fn fresh_outcome_serves_from_cache() {
        let planner = ResolutionPlanner::new(PlannerConfig::default());
        let mut ledger = RiskLedger::new(planner.config().risk, now());
        let e = entry(
            RrType::A,
            true,
            well_observed(now() - 60_000 * 1_000_000_000),
            -100,
        );
        assert_eq!(
            planner.plan(&LookupOutcome::Fresh(e), now(), None, &mut ledger),
            Plan::ServeFresh
        );
    }

    #[test]
    fn a_young_entry_is_never_predicted_about() {
        let planner = ResolutionPlanner::new(PlannerConfig::default());
        let mut ledger = RiskLedger::new(planner.config().risk, now());
        let e = entry(RrType::A, true, StabilityModel::new(now()), 10);
        let ctx = StaleContext::from_entry(&e, now(), 50.0, TrustLevel::ChainAnchored);
        assert_eq!(
            planner.plan(&LookupOutcome::Stale(e), now(), Some(&ctx), &mut ledger),
            Plan::Resolve
        );
        assert_eq!(ledger.debt(), 0.0);
    }

    #[test]
    fn a_well_observed_low_risk_entry_may_serve_stale() {
        let planner = ResolutionPlanner::new(PlannerConfig::default());
        let mut ledger = RiskLedger::new(planner.config().risk, now());
        let ctx = StaleContext {
            consequence: Consequence::Low,
            trust: TrustLevel::ChainAnchored,
            freshness_lcb: 0.999,
            staleness_secs: 20.0,
            value_ms: 60.0,
        };
        let e = entry(
            RrType::A,
            true,
            well_observed(now() - 60_000 * 1_000_000_000),
            20,
        );
        let plan = planner.plan(&LookupOutcome::Stale(e), now(), Some(&ctx), &mut ledger);
        assert!(matches!(plan, Plan::ServeStale { .. }), "{plan:?}");
        assert!(ledger.debt() > 0.0);
    }

    /// The delegation case: the same probability that buys stale service for
    /// an A record must not buy it for key material.
    #[test]
    fn key_material_is_never_served_stale() {
        let planner = ResolutionPlanner::new(PlannerConfig::default());
        let mut ledger = RiskLedger::new(planner.config().risk, now());
        let ctx = StaleContext {
            consequence: Consequence::Absolute,
            trust: TrustLevel::ChainAnchored,
            freshness_lcb: 0.9999,
            staleness_secs: 0.0,
            value_ms: 500.0,
        };
        let e = entry(
            RrType::DS,
            true,
            well_observed(now() - 60_000 * 1_000_000_000),
            5,
        );
        assert_eq!(
            planner.plan(&LookupOutcome::Stale(e), now(), Some(&ctx), &mut ledger),
            Plan::Resolve
        );
        assert_eq!(ledger.debt(), 0.0, "a forbidden class must not even charge");
    }

    #[test]
    fn an_exhausted_budget_stops_stale_service() {
        let cfg = PlannerConfig {
            risk: RiskConfig {
                budget_per_sec: 0.0,
                // Each decision costs 100 × 0.01 = 1.0, so a bucket of 1.5
                // admits exactly one and refuses the next. The margin keeps
                // the test about the budget rather than about the last bit
                // of `1.0 - 0.99`.
                budget_capacity: 1.5,
                ..RiskConfig::default()
            },
            ..PlannerConfig::default()
        };
        let planner = ResolutionPlanner::new(cfg);
        let mut ledger = RiskLedger::new(*planner.risk_config(), now());
        let ctx = StaleContext {
            consequence: Consequence::Low,
            trust: TrustLevel::ChainAnchored,
            freshness_lcb: 0.99,
            staleness_secs: 10.0,
            value_ms: 100.0,
        };
        let e = entry(
            RrType::A,
            true,
            well_observed(now() - 60_000 * 1_000_000_000),
            10,
        );
        let first = planner.plan(
            &LookupOutcome::Stale(e.clone()),
            now(),
            Some(&ctx),
            &mut ledger,
        );
        assert!(matches!(first, Plan::ServeStale { .. }), "{first:?}");
        let second = planner.plan(&LookupOutcome::Stale(e), now(), Some(&ctx), &mut ledger);
        assert_eq!(second, Plan::Resolve);
    }

    #[test]
    fn prefetch_follows_the_model_not_a_ttl_fraction() {
        let planner = ResolutionPlanner::new(PlannerConfig::default());
        let mut durable = StabilityModel::new(now() - 200_000 * 1_000_000_000);
        for i in 1..=400 {
            durable.observe(
                300,
                false,
                now() - 200_000 * 1_000_000_000 + i * 300 * 1_000_000_000,
            );
        }
        // Confidence is high at the configured horizon, so no refresh.
        assert!(!planner.should_prefetch(&durable, 1.0));
        // Demand gates value: no demand, no prefetch.
        assert!(!planner.should_prefetch(&durable, 0.0));
        // An unobserved entry is never prefetched.
        let young = StabilityModel::new(now());
        assert!(!planner.should_prefetch(&young, 1.0));
        // A set whose confidence has decayed asks to be refreshed: measured
        // over a horizon long enough that the bound has fallen below target.
        let long_horizon = 30.0 * 86_400.0;
        assert!(
            durable.freshness_lcb(long_horizon) < 0.9,
            "the model must eventually ask for a refresh"
        );
    }

    #[test]
    fn delegation_data_is_classified_critically() {
        assert_eq!(delegation_consequence(RrType::A), Consequence::Critical);
        assert_eq!(delegation_consequence(RrType::DS), Consequence::Absolute);
        assert_eq!(delegation_consequence(RrType::NS), Consequence::Critical);
    }

    #[test]
    fn provenance_weakest_link_overrides_the_entry() {
        use crate::provenance::{Dependency, DependencyRole, Provenance, ProvenanceConfig};
        let mut p = Provenance::new(ProvenanceConfig::default());
        p.push(Dependency::new(
            DependencyRole::Cname,
            CacheKey::plain(
                Name::from_ascii("cdn.example.net").unwrap(),
                RrType::CNAME,
                RrClass::IN,
            ),
            0,
            0.2,
        ));
        let e = entry(
            RrType::A,
            true,
            well_observed(now() - 60_000 * 1_000_000_000),
            10,
        );
        let ctx = StaleContext::from_entry(&e, now(), 50.0, TrustLevel::ChainAnchored)
            .with_provenance(&p);
        assert!(
            (ctx.freshness_lcb - 0.2).abs() < 1e-12,
            "{}",
            ctx.freshness_lcb
        );
    }

    /// The planner never consults the estimator for the safety question.
    /// This test exists so that a future change reintroducing the dependency
    /// has to delete it deliberately.
    #[test]
    fn estimator_population_is_not_required_for_safety() {
        let planner = ResolutionPlanner::new(PlannerConfig::default());
        let est = QueryEstimator::new(64);
        let mut ledger = RiskLedger::new(planner.config().risk, now());
        let e = entry(
            RrType::A,
            true,
            well_observed(now() - 60_000 * 1_000_000_000),
            10,
        );
        let ctx = StaleContext {
            consequence: Consequence::Low,
            trust: TrustLevel::ChainAnchored,
            freshness_lcb: 0.999,
            staleness_secs: 10.0,
            value_ms: 50.0,
        };
        let plan = planner.plan(&LookupOutcome::Stale(e), now(), Some(&ctx), &mut ledger);
        assert!(matches!(plan, Plan::ServeStale { .. }));
        assert_eq!(est.len(), 0);
    }
}
