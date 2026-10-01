//! The per-RRset refresh model.
//!
//! # What this used to be, and why it changed
//!
//! This module used to hold an EWMA "stability score" in `0..1`, built from
//! a count of refreshes and a count of changes. It had three defects that no
//! amount of weight tuning fixes, and they are worth naming because they are
//! why the replacement is a different kind of object:
//!
//! 1. **It was not a probability.** Nothing could be said about what `0.93`
//!    meant, so the thresholds compared against it were arbitrary, and they
//!    silently encoded the traffic the weights had been fitted on.
//! 2. **It ignored the sampling cadence.** Ten looks at a name spaced two
//!    seconds apart and ten looks spread over ten hours produced the same
//!    score. They are not the same evidence.
//! 3. **It could not be conservative.** An EWMA starts from a neutral `0.5`
//!    and moves toward what it has seen, so a name observed twice and never
//!    changed looked *more* trustworthy the less it had been watched.
//!
//! The replacement is [`crate::hazard`]: a posterior over the *rate* at
//! which the RRset changes, and a one-sided credibility bound on that rate.
//! Everything in this module exists to hold one of those per cache entry and
//! to answer the questions the cache and the decision layer ask, in the
//! units they need:
//!
//! * "Is the data I hold still correct, conservatively?" →
//!   [`StabilityModel::freshness_lcb`].
//! * "When should I look again?" → [`StabilityModel::next_interval_secs`].
//! * "How durable is this, for ranking?" →
//!   [`StabilityModel::durability_score`], which is explicitly *not* a
//!   decision input.
//!
//! # Nothing here is a "stability"
//!
//! The word survives in the type name only because renaming it would churn
//! every call site for no semantic gain. There is no stability scalar: there
//! is a rate, a bound on the rate, and probabilities derived from them. A
//! count of changes is a *sampling* statistic — [`StabilityModel::changes`]
//! — and is kept for diagnostics, never for decisions.

use crate::hazard::{HazardConfig, HazardModel};
use crate::time::Ts;

/// The authoritative TTL assumed before the first observation, in seconds.
///
/// A new entry has no observed TTL yet; anchoring the prior to a minute is
/// the conservative choice, because a *shorter* prior TTL gives a *higher*
/// prior rate and therefore less willingness to serve stale before there is
/// evidence. The first successful refresh replaces it with the real value.
pub const DEFAULT_PRIOR_TTL_SECS: u32 = 300;

/// The per-RRset refresh model.
#[derive(Clone, Debug)]
pub struct StabilityModel {
    model: HazardModel,
}

impl StabilityModel {
    /// A model with no evidence, using the default hazard configuration.
    pub fn new(now: Ts) -> Self {
        Self {
            model: HazardModel::new(HazardConfig::default(), DEFAULT_PRIOR_TTL_SECS, now),
        }
    }

    /// A model with no evidence and an explicit hazard configuration.
    pub fn with_config(config: HazardConfig, ttl_secs: u32, now: Ts) -> Self {
        Self {
            model: HazardModel::new(config, ttl_secs, now),
        }
    }

    /// The underlying hazard model.
    pub fn hazard(&self) -> &HazardModel {
        &self.model
    }

    /// The underlying hazard model, mutably.
    pub fn hazard_mut(&mut self) -> &mut HazardModel {
        &mut self.model
    }

    /// Rebuild from a hazard model (used by the persistent tier).
    pub fn from_hazard(model: HazardModel) -> Self {
        Self { model }
    }

    /// The model's state, as plain data (used by the persistent tier).
    pub fn state(&self) -> crate::hazard::HazardState {
        self.model.state()
    }

    /// Rebuild from a persisted state.
    pub fn from_state(config: HazardConfig, state: crate::hazard::HazardState) -> Self {
        Self {
            model: HazardModel::from_state(config, state),
        }
    }

    /// Record a successful refresh, using the wall-clock interval since the
    /// previous observation as the exposure.
    ///
    /// The interval is *measured*, not assumed: the model turns on which
    /// exposures produced which outcomes, so a caller that supplies a
    /// nominal interval it did not have is feeding the likelihood a
    /// falsehood.
    pub fn observe(&mut self, ttl_secs: u32, changed: bool, now: Ts) {
        self.observe_weighted(ttl_secs, changed, now, 1.0);
    }

    /// Record a successful refresh whose answer was accepted on the strength
    /// of a non-cryptographic check only, weighting it down accordingly.
    ///
    /// `trust ∈ (0, 1]`; see [`HazardModel::observe`].
    pub fn observe_weighted(&mut self, ttl_secs: u32, changed: bool, now: Ts, trust: f64) {
        let interval = now.saturating_sub(self.model.last_observation()) as f64 / 1e9;
        self.model.observe(interval, changed, ttl_secs, now, trust);
    }

    /// Record a refresh that failed.
    ///
    /// Time passed, so the evidence ages; nothing was learned, so the
    /// posterior does not move. Recording a failure as "unchanged" would be
    /// the single most dangerous thing this module could do — it would let an
    /// unreachable upstream masquerade as a stable zone.
    pub fn record_failure(&mut self, now: Ts) {
        self.model.observe_failure(now);
    }

    /// `P_LCB(fresh, Δ)`: the conservative probability that the data held at
    /// this entry is still correct `delta_secs` from now.
    pub fn freshness_lcb(&self, delta_secs: f64) -> f64 {
        self.model.freshness_lcb(delta_secs)
    }

    /// The Bayesian posterior-predictive freshness, for calibration
    /// reporting only.
    pub fn freshness_predictive(&self, delta_secs: f64) -> f64 {
        self.model.freshness_predictive(delta_secs)
    }

    /// The interval at which the next observation should be scheduled.
    pub fn next_interval_secs(&self) -> f64 {
        self.model.next_interval_secs()
    }

    /// Effective (decayed) exposure in seconds.
    pub fn evidence_secs(&self) -> f64 {
        self.model.evidence_secs()
    }

    /// Lifetime `(observations, changes, failures)`.
    pub fn counts(&self) -> (u64, u64, u64) {
        self.model.counts()
    }

    /// Lifetime observed content changes — a *sampling* statistic.
    ///
    /// Kept for diagnostics and for the persistent snapshot. It is not the
    /// model's state and must not be compared against a threshold: the same
    /// zone observed twice as often yields twice as many changes and is not
    /// thereby twice as volatile.
    pub fn changes(&self) -> u64 {
        self.model.counts().1
    }

    /// Consecutive refresh failures since the last success.
    pub fn consecutive_failures(&self) -> u64 {
        self.model.consecutive_failures()
    }

    /// EWMA of the authoritative TTL, in seconds.
    pub fn ttl_ewma(&self) -> f64 {
        self.model.ttl_ewma()
    }

    /// EWMA of `|T − T̄|`, in seconds.
    pub fn ttl_volatility(&self) -> f64 {
        self.model.ttl_volatility()
    }

    /// Wall time of the last *successful* observation.
    pub fn last_refresh(&self) -> Ts {
        self.model.last_observation()
    }

    /// Wall time of the last observed content change.
    pub fn last_change(&self) -> Ts {
        self.model.last_change()
    }

    /// Whether the entry has been watched for at least two of its own TTLs.
    ///
    /// A policy gate, not a statistical one — the credibility bound already
    /// carries the uncertainty. It exists because "do not act on prediction
    /// for a name I met thirty seconds ago" is a legitimate operational
    /// preference, and stating it as `2 × TTL` of exposure is at least
    /// checkable, unlike `samples >= 3`.
    pub fn is_mature(&self) -> bool {
        let ttl = self.model.ttl_ewma().max(1.0);
        self.model.has_evidence(2.0 * ttl)
    }

    /// The nominal horizon over which [`StabilityModel::durability_score`]
    /// is evaluated, in seconds.
    pub const DURABILITY_HORIZON_SECS: f64 = 60.0;

    /// A `0..1` durability value used only to rank cache entries.
    ///
    /// This is the **posterior-predictive** freshness over the stated
    /// horizon, not the credibility bound. The distinction is the whole
    /// value/risk separation in one line: ranking is *estimation*, where the
    /// best available point estimate is the right input, and a lower bound
    /// would confuse "we have no evidence yet" with "we have evidence that
    /// this is volatile", starving every new entry to the bottom of the
    /// cache. Safety is a *decision*, where the bound is the right input and
    /// is used by [`crate::risk`].
    ///
    /// It exists **only** to order entries for admission and eviction. It is
    /// not a decision input for stale service.
    pub fn durability_score(&self) -> f64 {
        self.freshness_predictive(Self::DURABILITY_HORIZON_SECS)
    }
}

impl Default for StabilityModel {
    fn default() -> Self {
        Self::new(0)
    }
}

impl core::fmt::Display for StabilityModel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (obs, chg, fails) = self.counts();
        write!(
            f,
            "refresh(obs={obs} chg={chg} fail={fails} p60={:.4} evidence={:.0}s ttl={:.0}s d_ttl={:.0}s)",
            self.durability_score(),
            self.evidence_secs(),
            self.ttl_ewma(),
            self.ttl_volatility(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    #[test]
    fn fresh_model_is_conservative() {
        let m = StabilityModel::new(now());
        assert!(!m.is_mature());
        assert_eq!(m.counts(), (0, 0, 0));
        // The two numbers a new entry reports are deliberately different:
        // the credibility *bound* is pessimistic (no evidence, so no
        // guarantee), while the point estimate is not (the TTL is the only
        // thing we know, and it is the best available guess). Ranking uses
        // the estimate; decisions use the bound.
        assert!(m.freshness_lcb(300.0) < 0.1, "{}", m.freshness_lcb(300.0));
        assert!(m.durability_score() > m.freshness_lcb(300.0));
    }

    #[test]
    fn a_well_observed_set_becomes_durable() {
        let mut m = StabilityModel::new(now());
        for i in 1..=200 {
            m.observe(300, false, now() + i * 300 * 1_000_000_000);
        }
        assert!(m.is_mature(), "evidence {}", m.evidence_secs());
        assert!(m.durability_score() > 0.95, "{}", m.durability_score());
        assert_eq!(m.changes(), 0);
    }

    #[test]
    fn the_sampling_cadence_matters() {
        // The same number of observations with different exposures: the set
        // watched for longer must end up more credible. This is precisely
        // the property the previous EWMA did not have.
        let mut frequent = StabilityModel::new(now());
        let mut sparse = StabilityModel::new(now());
        for i in 1..=50 {
            frequent.observe(300, false, now() + i * 10 * 1_000_000_000);
        }
        for i in 1..=50 {
            sparse.observe(300, false, now() + i * 600 * 1_000_000_000);
        }
        assert!(
            sparse.evidence_secs() > frequent.evidence_secs(),
            "{} vs {}",
            sparse.evidence_secs(),
            frequent.evidence_secs()
        );
        assert!(sparse.durability_score() >= frequent.durability_score());
    }

    #[test]
    fn a_change_lowers_durability() {
        let mut m = StabilityModel::new(now());
        for i in 1..=50 {
            m.observe(300, false, now() + i * 300 * 1_000_000_000);
        }
        let before = m.durability_score();
        m.observe(300, true, now() + 51 * 300 * 1_000_000_000);
        assert!(m.durability_score() < before);
        assert_eq!(m.changes(), 1);
    }

    #[test]
    fn failures_do_not_make_a_set_look_durable() {
        let mut m = StabilityModel::new(now());
        let before = m.durability_score();
        for i in 1..=10 {
            m.record_failure(now() + i * 300 * 1_000_000_000);
        }
        assert!(m.durability_score() <= before + 1e-12);
        assert_eq!(m.consecutive_failures(), 10);
    }

    #[test]
    fn low_trust_refreshes_are_discounted() {
        let mut trusted = StabilityModel::new(now());
        let mut untrusted = StabilityModel::new(now());
        for i in 1..=100 {
            let t = now() + i * 300 * 1_000_000_000;
            trusted.observe(300, false, t);
            untrusted.observe_weighted(300, false, t, 0.2);
        }
        assert!(untrusted.durability_score() < trusted.durability_score());
    }

    #[test]
    fn observation_interval_is_measured_from_the_clock() {
        // Two observations three hours apart: the exposure must be 10 800 s,
        // not the number of calls.
        let mut m = StabilityModel::with_config(HazardConfig::default(), 300, now());
        m.observe(300, false, now() + 10_800 * 1_000_000_000);
        assert!(
            (m.evidence_secs() - 10_800.0).abs() < 1e-6,
            "{}",
            m.evidence_secs()
        );
    }

    #[test]
    fn a_long_ttl_zone_needs_looking_at_less_often() {
        let mut short = StabilityModel::new(now());
        let mut long = StabilityModel::new(now());
        for i in 1..=200 {
            let t = now() + i * 300 * 1_000_000_000;
            short.observe(60, false, t);
            long.observe(3600, false, t);
        }
        assert!(long.next_interval_secs() >= short.next_interval_secs());
        assert!(long.next_interval_secs() >= 15.0);
    }

    #[test]
    fn display_is_stable_and_informative() {
        use alloc::format;
        let m = StabilityModel::new(now());
        let s = format!("{m}");
        assert!(s.starts_with("refresh("), "{s}");
        assert!(s.contains("obs=0"), "{s}");
    }
}
