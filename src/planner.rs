//! The Resolution Planner.
//!
//! Given a cache lookup outcome and the query estimator's prediction, the
//! planner decides *how* to answer: serve the cache, serve stale while
//! refreshing in the background, or resolve synchronously. This is the
//! layer where the estimator's probability feeds the request path.

use crate::cache::LookupOutcome;
use crate::estimator::QueryEstimator;
use crate::time::Ts;

/// What the resolver should do for a query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    /// Answer from a fresh cache entry.
    ServeFresh,
    /// Answer from a stale entry (serve-stale). When
    /// `refresh_in_background` is set, a refresh is queued so the next
    /// query gets fresh data.
    ServeStale {
        /// Whether to queue a background refresh after serving stale.
        refresh_in_background: bool,
    },
    /// Do a full (or iterative) resolution now.
    Resolve,
}

/// Planner thresholds.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PlannerConfig {
    /// Minimum `P(query within the horizon)` to serve stale data and
    /// refresh in the background instead of blocking the request.
    pub stale_serve_min_prob: f64,
    /// Minimum stability score to trust a background refresh.
    pub stale_refresh_stability: f64,
    /// The prediction horizon used for stale/refresh decisions.
    pub prefetch_horizon_secs: u32,
}

impl Default for PlannerConfig {
    fn default() -> Self {
        Self {
            stale_serve_min_prob: 0.5,
            stale_refresh_stability: 0.85,
            prefetch_horizon_secs: 60,
        }
    }
}

/// The resolution planner.
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

    /// Decide the plan for a query given its cache outcome and the
    /// estimator state.
    pub fn plan(&self, outcome: &LookupOutcome, now: Ts, estimator: &QueryEstimator) -> Plan {
        match outcome {
            LookupOutcome::Fresh(_) => Plan::ServeFresh,
            LookupOutcome::Stale(entry) => {
                let apex = entry.key.name.apex();
                let p = estimator.probability(&apex, now, self.config.prefetch_horizon_secs);
                if p >= self.config.stale_serve_min_prob
                    && entry
                        .stability
                        .is_very_stable(self.config.stale_refresh_stability)
                {
                    Plan::ServeStale {
                        refresh_in_background: true,
                    }
                } else {
                    Plan::Resolve
                }
            }
            _ => Plan::Resolve,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{CacheConfig, CacheEntry, CacheKey, EntryKind, LookupOutcome, Tier};
    use crate::name::Name;
    use crate::qtype::{RrClass, RrType};
    use crate::rrset::RrSet;
    use crate::stability::StabilityModel;

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    fn stale_entry(stability: f64) -> LookupOutcome {
        let mut st = StabilityModel::new(now());
        // Force the stability value by direct assignment (tests only).
        st.stability = stability;
        st.samples = 10;
        let entry = CacheEntry {
            key: CacheKey::plain(
                Name::from_ascii("www.example.com").unwrap(),
                RrType::A,
                RrClass::IN,
            ),
            kind: EntryKind::Positive(RrSet::a("www.example.com", "192.0.2.1", 300)),
            inserted: now() - 400_000_000_000,
            expires: now() - 100_000_000_000,
            served: 5,
            last_served: now() - 10_000_000_000,
            stability: st,
            validated: false,
            score: 0.5,
            tier: Tier::Cold,
            refreshing: false,
        };
        LookupOutcome::Stale(entry)
    }

    #[test]
    fn fresh_serves_from_cache() {
        let planner = ResolutionPlanner::new(PlannerConfig::default());
        let mut est = QueryEstimator::new(64);
        let name = Name::from_ascii("www.example.com").unwrap();
        est.observe_query(&name, now());
        let cfg = CacheConfig::default();
        let _ = cfg;
        // Build a fresh outcome.
        let entry = CacheEntry {
            key: CacheKey::plain(name, RrType::A, RrClass::IN),
            kind: EntryKind::Positive(RrSet::a("www.example.com", "192.0.2.1", 300)),
            inserted: now(),
            expires: now() + 300_000_000_000,
            served: 1,
            last_served: now(),
            stability: StabilityModel::new(now()),
            validated: false,
            score: 0.5,
            tier: Tier::Warm,
            refreshing: false,
        };
        let plan = planner.plan(&LookupOutcome::Fresh(entry), now(), &est);
        assert_eq!(plan, Plan::ServeFresh);
    }

    #[test]
    fn stale_served_when_likely_and_stable() {
        let planner = ResolutionPlanner::new(PlannerConfig::default());
        let mut est = QueryEstimator::new(64);
        let name = Name::from_ascii("www.example.com").unwrap();
        for i in 0..20 {
            est.observe_query(&name, now() - (20 - i) as Ts * 1_000_000_000);
        }
        let plan = planner.plan(&stale_entry(0.95), now(), &est);
        assert_eq!(
            plan,
            Plan::ServeStale {
                refresh_in_background: true
            }
        );
    }

    #[test]
    fn stale_resolved_when_unstable() {
        let planner = ResolutionPlanner::new(PlannerConfig::default());
        let mut est = QueryEstimator::new(64);
        let name = Name::from_ascii("www.example.com").unwrap();
        est.observe_query(&name, now());
        let plan = planner.plan(&stale_entry(0.2), now(), &est);
        assert_eq!(plan, Plan::Resolve);
    }
}
