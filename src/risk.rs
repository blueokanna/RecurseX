//! Risk-constrained stale service.
//!
//! # Why "is it popular?" is the wrong gate
//!
//! The obvious heuristic for serve-stale is to ask "will anyone query this
//! again soon?" and, if so, answer from the expired copy and refresh in the
//! background. That question measures the *benefit* of an answer. It says
//! nothing about whether the answer is *safe*, and it is exactly the wrong
//! axis: a name can be enormously popular and its stale answer can be worse
//! than a timeout. Conflating the two produces the classic failure where a
//! high-traffic zone's delegation records get served stale during an
//! upstream outage and traffic is steered at a decommissioned nameserver.
//!
//! # The two quantities, separated
//!
//! **Value** — how much latency a cache hit saves. It decides *what is worth
//! refreshing*, *what is worth keeping*, and the order in which the refresh
//! budget is spent. It is measured in milliseconds and it is comparable
//! across entries.
//!
//! **Risk** — how much harm returning the old answer can do. It decides
//! *whether stale service is permitted at all*. It is measured in
//! millisecond-equivalents of harm and it is comparable across entries too,
//! because the two factors are the same unit.
//!
//! ```text
//! R_i(a) = V_i · (1 − P_LCB_i(fresh, a)) · C_i · κ(trust_i)
//!            │        └── probability the answer is wrong ──┘   │
//!            │                                                  └── trust penalty
//!            └── latency the hit saves, in ms
//! ```
//!
//! * `V_i` — expected saved resolution latency for this entry, in ms.
//! * `P_LCB_i(fresh, a)` — the conservative freshness probability from
//!   [`crate::hazard`], evaluated `a` seconds beyond the expiry we would be
//!   serving from. Using the *lower* credibility bound means the risk is an
//!   *upper* bound on the true expected harm.
//! * `C_i` — a consequence coefficient by role: an A record and a DS record
//!   being wrong are not the same event, and no amount of traffic changes
//!   that.
//! * `κ(trust_i)` — the penalty for answering from data whose authenticity
//!   the resolver could not establish. Unverified data is not "probably
//!   fine"; it is data whose error could have been *manufactured*, so it
//!   needs a much lower staleness probability to be served.
//!
//! Because `R` has the units of the value term, an aggregate constraint
//! `E[Σ R_i] ≤ B_risk` is meaningful: it says "the resolver may spend up to
//! `B_risk` milliseconds of saved latency per second on the *expected* harm
//! of serving stale", which is a quantity an operator can reason about and
//! an auditor can recompute from the ledger.
//!
//! # The budget is charged, not refunded
//!
//! [`RiskLedger`] is a leaky bucket charged with the *ex ante* risk of each
//! decision at the moment the decision is made. The alternative — charge
//! only when a stale answer turns out to have been wrong — is unworkable for
//! a resolver, because a resolver does not learn that it answered wrongly
//! unless it happens to look again before the client acts; charging the
//! conservative bound means the true spend is always below the reported one,
//! and the reported one is auditable from the log alone.
//!
//! # What this module does *not* claim
//!
//! It does not claim to model the loss an operator actually suffers, and it
//! does not claim the coefficients are correct for anyone else's deployment.
//! The coefficients are *policies*: they are declared, ordered, and
//! overridable; what is not negotiable is that they are separate from the
//! value signal and that they are the thing which decides stale service.

use core::fmt;

use crate::qtype::RrType;
use crate::time::Ts;

/// How bad it is for this data to be wrong.
///
/// The ordering is the claim: `Absolute` must never be traded for latency,
/// whatever the budget.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Consequence {
    /// Ordinary, non-safety-critical data (A/AAAA/TXT/PTR).
    Low,
    /// A CNAME in a CDN chain: the alias itself is cheap, but the whole
    /// chain must be coherent for the answer to be usable.
    Medium,
    /// Service discovery and mail routing (MX/SRV/CAA/TLSA).
    High,
    /// NS names, glue addresses and delegations. Wrong here redirects a
    /// whole subtree of traffic, and it is self-sustaining because the bad
    /// delegation is itself cached.
    Critical,
    /// Key material and denial-of-existence proofs (DNSKEY/DS/RRSIG/
    /// NSEC/NSEC3). A stale answer here is a *security* failure, not a
    /// freshness failure: it can resurrect a revoked key or forge a proof
    /// that a name does not exist.
    Absolute,
}

impl Consequence {
    /// Classify an RRset by its type and its role in the answer.
    ///
    /// `is_delegation_data` is `true` for records lifted out of a referral's
    /// authority/additional sections: those are addressed to *us*, not to
    /// the client, and they are the ones whose staleness poisons the walk.
    pub fn classify(rr_type: RrType, is_delegation_data: bool) -> Consequence {
        if is_delegation_data {
            return match rr_type {
                RrType::DS | RrType::DNSKEY | RrType::RRSIG | RrType::NSEC | RrType::NSEC3 => {
                    Consequence::Absolute
                }
                _ => Consequence::Critical,
            };
        }
        match rr_type {
            RrType::DS | RrType::DNSKEY | RrType::RRSIG | RrType::NSEC | RrType::NSEC3 => {
                Consequence::Absolute
            }
            RrType::NS => Consequence::Critical,
            RrType::MX
            | RrType::SRV
            | RrType::TLSA
            | RrType::CAA
            | RrType::SVCB
            | RrType::HTTPS => Consequence::High,
            RrType::CNAME | RrType::DNAME => Consequence::Medium,
            _ => Consequence::Low,
        }
    }

    /// The consequence coefficient `C_i`, relative to ordinary data
    /// (`Low = 1`).
    ///
    /// The gaps are deliberately wide: correctness of the ordering matters
    /// far more than the exact scale, because the scale is absorbed by the
    /// budget on first deployment and the ordering is what the safety
    /// argument rests on.
    pub fn coefficient(self) -> f64 {
        match self {
            Consequence::Low => 1.0,
            Consequence::Medium => 5.0,
            Consequence::High => 25.0,
            Consequence::Critical => 100.0,
            Consequence::Absolute => f64::INFINITY,
        }
    }

    /// Whether stale service is permitted for this class at all.
    #[inline]
    pub fn allows_stale(self) -> bool {
        !matches!(self, Consequence::Absolute)
    }

    /// The longest staleness this class may ever be served at, in seconds,
    /// regardless of what the freshness bound says.
    ///
    /// This is a *policy* ceiling on top of the statistical one, in the same
    /// spirit as RFC 8767 §4's maximum-stale limit; it exists so that a
    /// statistical fluke (or a forged series of "unchanged" observations)
    /// cannot extend stale service past what an operator accepted.
    pub fn stale_horizon_secs(self) -> u32 {
        match self {
            Consequence::Low => 86_400,
            Consequence::Medium => 3_600,
            Consequence::High => 300,
            Consequence::Critical => 30,
            Consequence::Absolute => 0,
        }
    }

    /// A short stable name, for logs and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            Consequence::Low => "low",
            Consequence::Medium => "medium",
            Consequence::High => "high",
            Consequence::Critical => "critical",
            Consequence::Absolute => "absolute",
        }
    }
}

/// How well the authenticity of an answer was established.
///
/// This is the *honest* DNSSEC ladder from [`crate::dnssec`], and it is
/// wired into the risk model because "we could not verify this" must not be
/// the same as "we verified this and it was fine".
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum TrustLevel {
    /// Chain-of-trust validated from a configured anchor, with both the
    /// answer and the authority RRsets authentic (RFC 4035 §3.2.3).
    ChainAnchored,
    /// Signature verified against a key matched by a parent DS, but the DS
    /// RRset's own chain was not walked to an anchor.
    CryptoVerified,
    /// No validation was attempted or none applied (unsigned zone, or
    /// DNSSEC disabled). This is the honest default, not a failure.
    Unverified,
    /// Validation was attempted and could not conclude. Strictly worse than
    /// `Unverified`: the zone *is* signed and we could not check it.
    Indeterminate,
}

impl TrustLevel {
    /// The trust penalty `κ` multiplying the consequence coefficient.
    ///
    /// `ChainAnchored` is the reference (`1.0`). Everything below it costs a
    /// multiple, because the risk being bounded is "the answer is wrong" and
    /// an unauthenticated channel enlarges that set beyond "the zone
    /// republished" to include "somebody injected".
    pub fn penalty(self) -> f64 {
        match self {
            TrustLevel::ChainAnchored => 1.0,
            TrustLevel::CryptoVerified => 2.0,
            TrustLevel::Unverified => 5.0,
            TrustLevel::Indeterminate => 10.0,
        }
    }

    /// Whether an `AD` bit may be set for data at this level. Only a fully
    /// anchored chain qualifies.
    #[inline]
    pub fn permits_authentic_data(self) -> bool {
        matches!(self, TrustLevel::ChainAnchored)
    }

    /// A short stable name, for logs and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            TrustLevel::ChainAnchored => "chain-anchored",
            TrustLevel::CryptoVerified => "crypto-verified",
            TrustLevel::Unverified => "unverified",
            TrustLevel::Indeterminate => "indeterminate",
        }
    }
}

/// Why a stale answer was refused. Exposed so the decision is auditable
/// rather than merely logged as a boolean.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The record class forbids stale service outright (key material,
    /// delegations beyond the policy horizon).
    ClassForbidsStale,
    /// The staleness exceeded the class's policy horizon.
    HorizonExceeded,
    /// The freshness bound was below the class's minimum.
    FreshnessTooLow,
    /// The aggregate risk budget for this window is exhausted.
    RiskBudgetExhausted,
    /// The value of the hit did not justify its risk.
    NotWorthIt,
    /// The aggregate refresh budget is exhausted.
    RefreshBudgetExhausted,
}

impl Refusal {
    /// A short stable name, for logs and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::ClassForbidsStale => "class-forbids-stale",
            Refusal::HorizonExceeded => "horizon-exceeded",
            Refusal::FreshnessTooLow => "freshness-too-low",
            Refusal::RiskBudgetExhausted => "risk-budget-exhausted",
            Refusal::NotWorthIt => "not-worth-it",
            Refusal::RefreshBudgetExhausted => "refresh-budget-exhausted",
        }
    }
}

/// The outcome of a risk assessment.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Assessment {
    /// Expected saved latency, in ms (`V_i`).
    pub value_ms: f64,
    /// The consequence class (`C_i`).
    pub consequence: Consequence,
    /// The conservatively estimated freshness probability at the offered
    /// staleness.
    pub freshness_lcb: f64,
    /// The ex-ante risk `R_i`, in ms-equivalents of harm.
    pub risk: f64,
    /// Whether stale service is permitted.
    pub allowed: bool,
    /// The reason for refusal, when `allowed` is false.
    pub refusal: Option<Refusal>,
}

impl Assessment {
    /// The assessment corresponding to "not worthwhile, do not even
    /// consider": the value is zero and the staleness is zero.
    pub fn none() -> Self {
        Self {
            value_ms: 0.0,
            consequence: Consequence::Low,
            freshness_lcb: 1.0,
            risk: 0.0,
            allowed: false,
            refusal: Some(Refusal::NotWorthIt),
        }
    }
}

/// Tuning for the risk model.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RiskConfig {
    /// Minimum conservatively-estimated freshness required of the
    /// *lowest-risk* class. Every other class starts from this and is
    /// scaled by its coefficient, so one number moves the whole policy
    /// coherently instead of N independent thresholds drifting apart.
    pub base_min_freshness: f64,
    /// Value floor for `V_i`, in ms. An entry with no estimator history must
    /// not look free to serve stale; the floor is the assumed cost of a
    /// resolution.
    pub value_floor_ms: f64,
    /// Risk budget, in ms-equivalents of harm per second.
    pub budget_per_sec: f64,
    /// Bucket capacity, in the same units. Bounds the burst.
    pub budget_capacity: f64,
    /// Refresh budget, in refreshes per second.
    pub refresh_per_sec: f64,
    /// Refresh bucket capacity (burst).
    pub refresh_capacity: f64,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            base_min_freshness: 0.95,
            value_floor_ms: 20.0,
            budget_per_sec: 40.0,
            budget_capacity: 2_400.0,
            refresh_per_sec: 50.0,
            refresh_capacity: 512.0,
        }
    }
}

impl RiskConfig {
    /// The minimum freshness probability required of a class.
    ///
    /// The functional is linear in `(1 − p)`, so a class with coefficient
    /// `C` may tolerate only `1/C` of the staleness *probability* that
    /// ordinary data may. Inverting that gives the probability floor
    /// `p_min(C) = 1 − (1 − base)/C`, which keeps the per-decision admission
    /// test in the same units as the measurement: `Low` clears the base
    /// probability, `Critical` (C = 100) needs to be 100× closer to certain,
    /// and `Absolute` needs certainty itself.
    pub fn min_freshness(&self, consequence: Consequence) -> f64 {
        let c = consequence.coefficient();
        if !c.is_finite() {
            return 1.0;
        }
        let base = self.base_min_freshness.clamp(0.0, 1.0);
        let slack = 1.0 - base;
        (1.0 - slack / c).clamp(0.0, 1.0)
    }
}

/// The ex-ante risk of serving stale.
///
/// `staleness_secs` is how far past the expiry the answer would be served
/// (0 for a fresh hit). Returns `+∞` when the class forbids stale or the
/// freshness bound collapses, so an unbounded risk is never accidentally
/// compared as "small".
pub fn risk_of(
    config: &RiskConfig,
    value_ms: f64,
    consequence: Consequence,
    trust: TrustLevel,
    freshness_lcb: f64,
    staleness_secs: f64,
) -> f64 {
    if !consequence.allows_stale() {
        return f64::INFINITY;
    }
    if staleness_secs > consequence.stale_horizon_secs() as f64 {
        return f64::INFINITY;
    }
    let v = if value_ms.is_finite() {
        value_ms.max(config.value_floor_ms)
    } else {
        config.value_floor_ms
    };
    let p = if freshness_lcb.is_nan() {
        0.0
    } else {
        freshness_lcb.clamp(0.0, 1.0)
    };
    v * (1.0 - p) * consequence.coefficient() * trust.penalty()
}

/// Assess whether a stale answer may be served.
///
/// Pure: the aggregate budgets are *not* consulted here, because that is a
/// stateful, shared decision ([`RiskLedger`]); this function answers the
/// per-entry question "is this worth doing at all, and what does it cost?".
pub fn assess(
    config: &RiskConfig,
    value_ms: f64,
    consequence: Consequence,
    trust: TrustLevel,
    freshness_lcb: f64,
    staleness_secs: f64,
) -> Assessment {
    let risk = risk_of(
        config,
        value_ms,
        consequence,
        trust,
        freshness_lcb,
        staleness_secs,
    );
    let mut refusal = None;
    if !consequence.allows_stale() {
        refusal = Some(Refusal::ClassForbidsStale);
    } else if staleness_secs > consequence.stale_horizon_secs() as f64 {
        refusal = Some(Refusal::HorizonExceeded);
    } else if freshness_lcb < config.min_freshness(consequence) {
        refusal = Some(Refusal::FreshnessTooLow);
    } else if !risk.is_finite() {
        refusal = Some(Refusal::NotWorthIt);
    }
    Assessment {
        value_ms: value_ms.max(config.value_floor_ms),
        consequence,
        freshness_lcb,
        risk: if risk.is_finite() { risk } else { 0.0 },
        allowed: refusal.is_none(),
        refusal,
    }
}

/// A leaky-bucket accounting of the aggregate risk bound
/// `E[Σ R_i] ≤ B_risk`.
///
/// The bucket holds *debt*, in ms-equivalents of harm, and drains at
/// [`RiskConfig::budget_per_sec`]. A decision is admitted iff the debt after
/// charging stays within [`RiskConfig::budget_capacity`]. The invariant that
/// makes it auditable: **the sum of admitted risks over any window can never
/// exceed `capacity + rate × window`**, so the bound holds by construction
/// rather than by measurement.
#[derive(Clone, Debug)]
pub struct RiskLedger {
    config: RiskConfig,
    debt: f64,
    last_update: Ts,
    charged_total: f64,
    admitted: u64,
    refused: u64,
}

impl RiskLedger {
    /// A ledger with an empty bucket.
    pub fn new(config: RiskConfig, now: Ts) -> Self {
        Self {
            config,
            debt: 0.0,
            last_update: now,
            charged_total: 0.0,
            admitted: 0,
            refused: 0,
        }
    }

    /// The current configuration.
    pub fn config(&self) -> &RiskConfig {
        &self.config
    }

    /// Replace the configuration (the bucket keeps its debt).
    pub fn set_config(&mut self, config: RiskConfig) {
        self.config = config;
    }

    /// Drain the bucket up to `now`.
    fn drain(&mut self, now: Ts) {
        let dt = now.saturating_sub(self.last_update) as f64 / 1e9;
        if dt <= 0.0 {
            return;
        }
        self.debt = (self.debt - self.config.budget_per_sec * dt).max(0.0);
        self.last_update = now;
    }

    /// Current debt, in ms-equivalents.
    pub fn debt(&self) -> f64 {
        self.debt
    }

    /// Total risk charged since construction.
    pub fn charged_total(&self) -> f64 {
        self.charged_total
    }

    /// `(admitted, refused)` decision counts.
    pub fn counts(&self) -> (u64, u64) {
        (self.admitted, self.refused)
    }

    /// Try to charge `risk` to the bucket.
    ///
    /// A non-finite risk is refused without touching the bucket, so a class
    /// that forbids stale never even partially charges.
    pub fn try_charge(&mut self, risk: f64, now: Ts) -> bool {
        self.drain(now);
        if !risk.is_finite() || risk < 0.0 {
            self.refused = self.refused.saturating_add(1);
            return false;
        }
        if self.debt + risk > self.config.budget_capacity {
            self.refused = self.refused.saturating_add(1);
            return false;
        }
        self.debt += risk;
        self.charged_total += risk;
        self.admitted = self.admitted.saturating_add(1);
        true
    }
}

/// A token bucket bounding the aggregate refresh rate
/// `Σ ρ_i ≤ B_refresh`.
///
/// Separate from [`RiskLedger`] because the two constraints bind on
/// different resources: risk bounds *what the client may be told*, refresh
/// bounds *what the upstream may be asked*. A deployment with a slow
/// upstream needs a tight refresh budget and a loose risk budget; one
/// serving a hostile client population needs the reverse.
#[derive(Clone, Debug)]
pub struct RefreshBudget {
    per_sec: f64,
    capacity: f64,
    tokens: f64,
    last_update: Ts,
    granted: u64,
    denied: u64,
}

impl RefreshBudget {
    /// A bucket starting full (a cold resolver has budget to spend on
    /// learning).
    pub fn new(per_sec: f64, capacity: f64, now: Ts) -> Self {
        let capacity = capacity.max(0.0);
        Self {
            per_sec: per_sec.max(0.0),
            capacity,
            tokens: capacity,
            last_update: now,
            granted: 0,
            denied: 0,
        }
    }

    /// Build from a risk configuration.
    pub fn from_config(config: &RiskConfig, now: Ts) -> Self {
        Self::new(config.refresh_per_sec, config.refresh_capacity, now)
    }

    /// Refill and return how many of `want` may proceed *now*.
    ///
    /// Partial grants are returned rather than refused wholesale, so a tick
    /// that asks for 64 prefetches with 3 tokens left still performs 3 —
    /// the alternative is a budget that is never used at the rate it
    /// authorises.
    pub fn take(&mut self, want: usize, now: Ts) -> usize {
        let dt = now.saturating_sub(self.last_update) as f64 / 1e9;
        if dt > 0.0 {
            self.tokens = (self.tokens + self.per_sec * dt).min(self.capacity);
            self.last_update = now;
        }
        let allowed = if self.capacity <= 0.0 {
            0
        } else {
            self.tokens.max(0.0).min(want as f64) as usize
        };
        if allowed == 0 && want > 0 {
            self.denied = self.denied.saturating_add(1);
        }
        self.tokens -= allowed as f64;
        self.granted = self.granted.saturating_add(allowed as u64);
        allowed
    }

    /// Tokens currently available.
    pub fn tokens(&self) -> f64 {
        self.tokens
    }

    /// `(granted, denied_ticks)` counts.
    pub fn counts(&self) -> (u64, u64) {
        (self.granted, self.denied)
    }
}

impl fmt::Display for Assessment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.refusal {
            Some(r) if !self.allowed => write!(
                f,
                "risk(V={:.0}ms C={} p_lcb={:.3} R={:.2} → refused: {})",
                self.value_ms,
                self.consequence.as_str(),
                self.freshness_lcb,
                self.risk,
                r.as_str()
            ),
            _ => write!(
                f,
                "risk(V={:.0}ms C={} p_lcb={:.3} R={:.2} → allowed)",
                self.value_ms,
                self.consequence.as_str(),
                self.freshness_lcb,
                self.risk
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    #[test]
    fn key_material_never_serves_stale() {
        for t in [
            RrType::DS,
            RrType::DNSKEY,
            RrType::RRSIG,
            RrType::NSEC,
            RrType::NSEC3,
        ] {
            let c = Consequence::classify(t, false);
            assert_eq!(c, Consequence::Absolute, "{t:?}");
            assert!(!c.allows_stale());
            assert_eq!(c.stale_horizon_secs(), 0);
            let cfg = RiskConfig::default();
            let a = assess(&cfg, 500.0, c, TrustLevel::ChainAnchored, 0.9999, 0.0);
            assert!(!a.allowed);
            assert_eq!(a.refusal, Some(Refusal::ClassForbidsStale));
        }
    }

    #[test]
    fn delegations_are_critical() {
        assert_eq!(
            Consequence::classify(RrType::NS, true),
            Consequence::Critical
        );
        assert_eq!(
            Consequence::classify(RrType::A, true),
            Consequence::Critical
        );
        assert_eq!(
            Consequence::classify(RrType::DS, true),
            Consequence::Absolute
        );
        // The same A record is harmless as ordinary answer data.
        assert_eq!(Consequence::classify(RrType::A, false), Consequence::Low);
    }

    #[test]
    fn unverified_trust_costs_more() {
        let cfg = RiskConfig::default();
        let anchored = risk_of(
            &cfg,
            100.0,
            Consequence::Low,
            TrustLevel::ChainAnchored,
            0.9,
            10.0,
        );
        let indeterminate = risk_of(
            &cfg,
            100.0,
            Consequence::Low,
            TrustLevel::Indeterminate,
            0.9,
            10.0,
        );
        assert!(indeterminate > anchored);
        assert!((indeterminate / anchored - 10.0).abs() < 1e-9);
    }

    #[test]
    fn freshness_floor_escalates_with_consequence() {
        let cfg = RiskConfig::default();
        let low = cfg.min_freshness(Consequence::Low);
        let crit = cfg.min_freshness(Consequence::Critical);
        assert!(crit > low);
        assert!((low - 0.95).abs() < 1e-12);
        assert_eq!(cfg.min_freshness(Consequence::Absolute), 1.0);
    }

    #[test]
    fn horizon_is_enforced_before_statistics() {
        let cfg = RiskConfig::default();
        // A perfectly confident, cheap, low-consequence answer that is
        // nonetheless past the policy horizon must be refused.
        let a = assess(
            &cfg,
            100.0,
            Consequence::High,
            TrustLevel::ChainAnchored,
            1.0,
            400.0,
        );
        assert!(!a.allowed);
        assert_eq!(a.refusal, Some(Refusal::HorizonExceeded));
    }

    #[test]
    fn ledger_bounds_aggregate_risk() {
        let cfg = RiskConfig {
            budget_per_sec: 10.0,
            budget_capacity: 100.0,
            ..RiskConfig::default()
        };
        let mut l = RiskLedger::new(cfg, now());
        let mut admitted = 0;
        for i in 0..1000 {
            if l.try_charge(30.0, now() + i) {
                admitted += 1;
            }
        }
        assert!(
            admitted <= 4,
            "capacity 100 with 30-unit charges admits ≤ 4, got {admitted}"
        );
        assert!(l.debt() <= cfg.budget_capacity + 1e-9);
    }

    #[test]
    fn ledger_drains_at_the_configured_rate() {
        let cfg = RiskConfig {
            budget_per_sec: 10.0,
            budget_capacity: 100.0,
            ..RiskConfig::default()
        };
        let mut l = RiskLedger::new(cfg, now());
        assert!(l.try_charge(100.0, now()));
        assert!(!l.try_charge(1.0, now()));
        // After 5 s the bucket has drained 50 units.
        assert!(l.try_charge(40.0, now() + 5 * 1_000_000_000));
        assert!(!l.try_charge(20.0, now() + 5 * 1_000_000_000));
    }

    #[test]
    fn infinite_risk_never_charges() {
        let cfg = RiskConfig::default();
        let mut l = RiskLedger::new(cfg, now());
        assert!(!l.try_charge(f64::INFINITY, now()));
        assert_eq!(l.debt(), 0.0);
        assert_eq!(l.charged_total(), 0.0);
    }

    #[test]
    fn refresh_budget_grants_partially_and_refills() {
        let mut b = RefreshBudget::new(2.0, 10.0, now());
        assert_eq!(b.take(4, now()), 4);
        assert_eq!(b.take(100, now()), 6);
        assert_eq!(b.take(1, now()), 0);
        // 5 s at 2/s = 10 tokens.
        assert_eq!(b.take(100, now() + 5 * 1_000_000_000), 10);
        let (granted, denied) = b.counts();
        assert_eq!(granted, 20);
        assert_eq!(denied, 1);
    }

    #[test]
    fn zero_capacity_refresh_budget_grants_nothing() {
        let mut b = RefreshBudget::new(0.0, 0.0, now());
        assert_eq!(b.take(10, now() + 10_000_000_000), 0);
    }
}
