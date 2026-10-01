//! The observable-change hazard model.
//!
//! # The problem this module exists to solve
//!
//! A recursive resolver that wants to *predict* — rather than merely obey a
//! TTL — has to answer one question repeatedly:
//!
//! > What is the probability that the RRset I am about to answer from
//! > memory is still correct?
//!
//! The naive answers are all wrong in the same way: they claim to know
//! something nobody measured.
//!
//! * **"The TTL has not expired, so it is correct."** A TTL is what the
//!   *authoritative server* claims, not a measurement of how often the zone
//!   actually publishes a new RRset. Zones routinely publish a 300 s TTL for
//!   data that changes hourly, and a 86 400 s TTL for data that changes
//!   every second behind a CDN.
//! * **"It has been unchanged N times in a row, so it is stable."** `N` is
//!   not a property of the zone; it is a property of *our sampling*. Two
//!   resolvers with different refresh cadences will report different `N` for
//!   the same zone, and neither number is a stability.
//! * **"The EWMA stability is 0.93."** A unitless score with hand-tuned
//!   weights. It cannot be calibrated (nothing to compare against), it
//!   cannot be combined across entries, and it silently encodes the tuning
//!   set it was fitted on.
//!
//! # The model
//!
//! Assume changes to an RRset arrive as a Poisson process with an unknown
//! rate `λ > 0` (changes per second). An observation is a pair — the
//! *exposure* `h` since we last looked, and the *outcome*
//! `Y ∈ {0, 1}` (did the data differ when we looked again?). The likelihood
//! of one observation is
//!
//! ```text
//! Pr(Y = 1 | λ, h) = 1 − e^(−λh)          Pr(Y = 0 | λ, h) = e^(−λh)
//! ```
//!
//! so the likelihood of a whole history is
//!
//! ```text
//! L(λ) = Π_k (1 − e^(−λ h_k))^(Y_k) · (e^(−λ h_k))^(1 − Y_k)
//! ```
//!
//! Note what this does *and does not* assume: it does **not** assume the
//! observation intervals are equal (they never are — they depend on cache
//! pressure, client traffic and the scheduler), and it does **not** treat
//! `Y = 0` as proof that nothing happened. `Y = 0` means "no *observable*
//! difference was found at that sample"; a change that came and went between
//! two samples is invisible, which is precisely why the inference is
//! probabilistic rather than a counter.
//!
//! # Why the posterior is a Gamma and why that is not a coincidence
//!
//! `λ` is a rate, so its conjugate prior is `Gamma(α, β)`. With the
//! `e^(−λh)` factors above, the *exact* conjugate update needs the
//! exponential-integral family — but the small-`λh` regime that a resolver
//! actually operates in (`λh ≪ 1`: the data changes on a scale of hours, we
//! sample on a scale of minutes) has `1 − e^(−λh) ≈ λh`, so the
//! per-observation information about `λ` is, to first order, `h` units of
//! exposure for `Y = 1` and none for `Y = 0`. The Gamma update
//!
//! ```text
//! α ← α + Y            β ← β + h
//! ```
//!
//! is therefore the *first-order-correct* rule, and it is honest about the
//! regime it is valid in. That is documented at [`HazardModel::observe`].
//! The consequence of the approximation is conservative in the direction
//! that matters: an unchanged sample still grows `β` (evidence of
//! durability), but a *changed* sample grows `α`, which moves the rate
//! estimate up hard.
//!
//! # Non-stationarity, and the accidental anti-forgery bound
//!
//! DNS data is not stationary: a zone is republished, a CDN moves, a
//! delegation changes. Evidence from a week ago should not weigh the same as
//! evidence from a minute ago. So the *evidence* — not the prior — is
//! exponentially forgotten with time constant
//! [`HazardConfig::forgetting_secs`]:
//!
//! ```text
//! γ = e^(−h/τ),   a ← γa + w·Y,   b ← γb + w·h
//! ```
//!
//! This has a property that matters for security and that is worth stating
//! plainly: **forgetting puts a ceiling on accumulated evidence.** With a
//! fixed sampling interval `h`, `b → w·h/(1 − γ) ≈ w·τ`, so no amount of
//! refreshes — honest or forged — can drive the model past `τ` seconds of
//! effective exposure, and hence `λ` can never be driven to zero. An
//! attacker who can answer our refreshes (a cache-poisoning position) cannot
//! manufacture unbounded confidence that a name never changes, because the
//! model never accumulates unbounded confidence in anything. The credible
//! interval stays open, and [`HazardModel::freshness_lcb`] therefore stays
//! strictly below 1. This is a *structural* defence, not a check bolted on.
//!
//! # From a posterior to a decision
//!
//! The decision layer must never use the posterior mean. It uses a
//! one-sided upper credibility bound on `λ` at level `1 − δ`
//! ([`HazardModel::hazard_upper_bound`]) and evaluates the survival
//! probability at that worst-case rate:
//!
//! ```text
//! P_LCB(fresh, Δ) = inf        e^(−λΔ) = e^(−λ_hi · Δ)
//!                   λ∈CI_(1−δ)
//! ```
//!
//! In words: *"even taking the most pessimistic change rate still
//! consistent with what we have observed, the probability that this data is
//! still correct `Δ` seconds from now is at least `P_LCB`."* That is a
//! statement a safety argument can be built on; "the stability score is
//! 0.93" is not.
//!
//! The bound is the exact Chernoff bound on a `Gamma(α, β)` law,
//! `Pr(Λ ≥ x) ≤ e^(α − βx)·(βx/α)^α` for `x > α/β`, solved for `x`. It is
//! valid for every `α > 0` (in particular for `α < 1`, i.e. the low-evidence
//! regime), and it returns `+∞` — hence `P_LCB = 0`, hence "never serve
//! stale" — when there is no information at all. Small samples *must* be
//! conservative, and here they are, by construction rather than by a
//! threshold someone picked.
//!
//! # What is deliberately absent
//!
//! No "change count", no "true stability", no per-entry score. The model
//! reports a distribution over a rate, and a probability, and both are
//! falsifiable against observed outcomes — which is what makes
//! [`crate::calibration`] meaningful.

use core::fmt;

use crate::float::{exp, exp_nonpos, is_positive, ln};
use crate::time::Ts;

/// Default non-stationarity time constant (seconds).
///
/// One day: a resolver that forgets slower than this carries evidence from
/// a previous operational regime (different CDN, different delegation) into
/// its current decisions; one that forgets faster never leaves the prior.
pub const DEFAULT_FORGETTING_SECS: f64 = 86_400.0;

/// Default credibility level for the upper bound on `λ`.
pub const DEFAULT_CONFIDENCE: f64 = 0.95;

/// Default prior shape `α₀`.
///
/// `α₀ = 1` reads as "one change before any evidence", which makes the prior
/// mean `1/T` (one change per TTL) and keeps the prior *weak* — a handful of
/// honest observations moves it. `α₀ < 1` (Jeffreys) would be more
/// agnostic, but it also makes the upper bound on `λ` diverge for a set
/// with a long TTL, and a resolver that can never serve stale is a resolver
/// that has not gained anything. `α₀ = 1` is the smallest value that keeps
/// the prior mean finite and interpretable.
pub const DEFAULT_PRIOR_SHAPE: f64 = 1.0;

/// Default minimum observation interval (seconds).
pub const DEFAULT_MIN_INTERVAL_SECS: f64 = 15.0;

/// Default maximum observation interval (seconds).
///
/// Six hours: past this, the observation stops being a measurement of the
/// current regime and starts being an assumption about it.
pub const DEFAULT_MAX_INTERVAL_SECS: f64 = 6.0 * 3600.0;

/// Tuning of a [`HazardModel`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HazardConfig {
    /// Prior shape `α₀ > 0`.
    pub prior_shape: f64,
    /// Credibility level `1 − δ` for the upper bound on `λ`.
    pub confidence: f64,
    /// Non-stationarity time constant `τ` in seconds. Evidence older than
    /// this is exponentially discounted; it is also the hard ceiling on
    /// effective exposure.
    pub forgetting_secs: f64,
    /// Lower clamp for the adaptive observation interval.
    pub min_interval_secs: f64,
    /// Upper clamp for the adaptive observation interval.
    pub max_interval_secs: f64,
    /// Target `P_LCB(fresh, ·)` at which the next observation is scheduled.
    /// A value of `0.9` means "look again while we are still 90 % sure the
    /// data we hold is correct", so a refresh never races the expiry.
    pub target_freshness: f64,
}

impl Default for HazardConfig {
    fn default() -> Self {
        Self {
            prior_shape: DEFAULT_PRIOR_SHAPE,
            confidence: DEFAULT_CONFIDENCE,
            forgetting_secs: DEFAULT_FORGETTING_SECS,
            min_interval_secs: DEFAULT_MIN_INTERVAL_SECS,
            max_interval_secs: DEFAULT_MAX_INTERVAL_SECS,
            target_freshness: 0.9,
        }
    }
}

impl HazardConfig {
    /// `δ = 1 − confidence`, clamped away from 0 and 1 so the Chernoff solve
    /// is always well posed.
    pub fn tail_probability(&self) -> f64 {
        let delta = 1.0 - self.confidence;
        if delta.is_nan() {
            return 0.05;
        }
        delta.clamp(1e-12, 1.0 - 1e-12)
    }

    /// The same config with `confidence` replaced, for per-class policy
    /// overrides (a delegation needs a tighter bound than an A record).
    pub fn with_confidence(self, confidence: f64) -> Self {
        Self {
            confidence: if confidence.is_nan() {
                self.confidence
            } else {
                confidence
            },
            ..self
        }
    }

    /// The configuration with every field forced into a usable range.
    ///
    /// Used on the persistence path, where the input may be a corrupt frame.
    /// The failure mode this prevents is specific and severe: `forgetting
    /// _secs <= 0` would make [`crate::hazard::HazardModel::forgetting
    /// _factor`] return `1.0`, i.e. *no forgetting at all*, which would
    /// remove the ceiling on accumulated evidence that bounds what a
    /// forged series of observations can buy.
    pub fn sanitised(self) -> Self {
        let d = HazardConfig::default();
        let finite = |v: f64, fallback: f64| if v.is_finite() { v } else { fallback };
        let min = finite(self.min_interval_secs, d.min_interval_secs).clamp(0.001, 86_400.0);
        let max = finite(self.max_interval_secs, d.max_interval_secs).max(min);
        Self {
            prior_shape: finite(self.prior_shape, d.prior_shape).clamp(1e-6, 1e6),
            confidence: finite(self.confidence, d.confidence).clamp(1e-9, 1.0 - 1e-9),
            forgetting_secs: finite(self.forgetting_secs, d.forgetting_secs).clamp(1.0, 1e9),
            min_interval_secs: min,
            max_interval_secs: max,
            target_freshness: finite(self.target_freshness, d.target_freshness)
                .clamp(1e-6, 1.0 - 1e-9),
        }
    }
}

/// An upper credibility bound on a `Gamma(α, β)` rate.
///
/// Returns `x` such that `Pr(Λ ≥ x) ≤ δ` under `Λ ~ Gamma(α, β)`, evaluated
/// through the Chernoff bound `x ↦ e^(α − βx)(βx/α)^α`, which is exact at
/// the boundary `x = α/β` (value 1) and strictly decreasing above it.
///
/// * `α ≤ 0` or `β ≤ 0` — no information: returns `+∞`, so the caller's
///   survival probability is exactly `0`.
/// * `δ ≥ 1` — no constraint is imposed by the bound; returns the mean.
///
/// The result is always `≥` the posterior mean `α/β`, which is the property
/// that makes it a *conservative* substitute for the mean.
pub fn gamma_upper_bound(alpha: f64, beta: f64, delta: f64) -> f64 {
    if !is_positive(alpha) || !is_positive(beta) {
        return f64::INFINITY;
    }
    let mean = alpha / beta;
    if !is_positive(delta) {
        return f64::INFINITY;
    }
    if delta >= 1.0 {
        return mean;
    }
    let ln_delta = ln(delta);
    // g(x) = ln(e^(α − βx)·(βx/α)^α / δ), decreasing on (mean, ∞), and
    // g(mean) = ln(1/δ) > 0, so the root brackets [mean, ∞).
    let g = |x: f64| alpha - beta * x + alpha * ln(beta * x / alpha) - ln_delta;

    let mut lo = mean;
    let mut hi = mean * 2.0;
    let mut growth = 0;
    while g(hi) > 0.0 {
        hi *= 2.0;
        growth += 1;
        if growth > 64 || !hi.is_finite() {
            return f64::INFINITY;
        }
    }
    // Bisection. g is monotone, so this converges to the unique root; the
    // loop is fixed-length rather than tolerance-driven so the cost per
    // call is a constant, independent of the inputs.
    let mut i = 0;
    while i < 96 {
        let mid = 0.5 * (lo + hi);
        if mid <= lo || mid >= hi {
            break;
        }
        if g(mid) > 0.0 {
            lo = mid;
        } else {
            hi = mid;
        }
        i += 1;
    }
    hi
}

/// The per-entry observable-change model.
///
/// State is a fixed number of scalars — there is no per-observation history,
/// so the memory cost is independent of how many times the entry has been
/// refreshed, and a hostile traffic pattern cannot grow it.
#[derive(Clone, Debug)]
pub struct HazardModel {
    config: HazardConfig,
    /// Decayed change evidence `a`. The posterior shape is `α₀ + a`.
    alpha_ev: f64,
    /// Decayed exposure evidence `b`, in seconds. The posterior rate scale
    /// is `α₀·T + b`.
    beta_ev: f64,
    /// The authoritative TTL the prior is anchored to (seconds). The prior
    /// *mean* is `1/T` — "one change per TTL" — which is the weakest
    /// assumption a resolver can make about a zone while still using the
    /// zone's own claim as a starting point.
    prior_ttl_secs: f64,
    /// Effective (decayed) exposure in seconds — the honest answer to "how
    /// much have we actually watched this set?".
    evidence_secs: f64,
    /// Total exposure ever recorded, never decayed (diagnostics/audit).
    lifetime_exposure_secs: f64,
    /// Lifetime observations, changes and failures.
    observations: u64,
    changes: u64,
    failures: u64,
    /// Consecutive failures since the last success.
    consecutive_failures: u64,
    /// EWMA of the authoritative TTL (seconds) and its volatility.
    ttl_ewma: f64,
    ttl_volatility: f64,
    /// Wall time of the last *successful* observation.
    last_observation: Ts,
    /// Wall time of the last observed content change.
    last_change: Ts,
}

impl HazardModel {
    /// A model with no evidence, anchored to an authoritative TTL of
    /// `ttl_secs`.
    pub fn new(config: HazardConfig, ttl_secs: u32, now: Ts) -> Self {
        let t = (ttl_secs.max(1)) as f64;
        Self {
            config,
            alpha_ev: 0.0,
            beta_ev: 0.0,
            prior_ttl_secs: t,
            evidence_secs: 0.0,
            lifetime_exposure_secs: 0.0,
            observations: 0,
            changes: 0,
            failures: 0,
            consecutive_failures: 0,
            ttl_ewma: t,
            ttl_volatility: 0.0,
            last_observation: now,
            last_change: now,
        }
    }

    /// The model's configuration.
    pub fn config(&self) -> &HazardConfig {
        &self.config
    }

    /// Replace the configuration (the next observation uses the new
    /// forgetting constant).
    pub fn set_config(&mut self, config: HazardConfig) {
        self.config = config;
    }

    /// The prior shape `α₀`, floored away from zero.
    fn prior_shape(&self) -> f64 {
        self.config.prior_shape.max(1e-9)
    }

    /// The current posterior `(α, β)`.
    pub fn posterior(&self) -> (f64, f64) {
        let a0 = self.prior_shape();
        (a0 + self.alpha_ev, a0 * self.prior_ttl_secs + self.beta_ev)
    }

    /// The posterior mean change rate (changes per second).
    ///
    /// **Not** for decisions — use [`HazardModel::hazard_upper_bound`]. This
    /// is what gets reported and compared against observed outcomes.
    pub fn hazard_mean(&self) -> f64 {
        let (alpha, beta) = self.posterior();
        if beta > 0.0 {
            alpha / beta
        } else {
            f64::INFINITY
        }
    }

    /// The one-sided upper credibility bound on the change rate.
    pub fn hazard_upper_bound(&self) -> f64 {
        let (alpha, beta) = self.posterior();
        gamma_upper_bound(alpha, beta, self.config.tail_probability())
    }

    /// `P_LCB(fresh, Δ)` — the conservative probability that this data is
    /// still correct `delta_secs` from now.
    ///
    /// This is the number every stale-serving decision must be based on.
    pub fn freshness_lcb(&self, delta_secs: f64) -> f64 {
        if delta_secs <= 0.0 {
            return 1.0;
        }
        let lambda = self.hazard_upper_bound();
        if !lambda.is_finite() {
            return 0.0;
        }
        // `exp_nonpos` keeps underflow at exactly 0 instead of a denormal.
        exp_nonpos(-lambda * delta_secs).clamp(0.0, 1.0)
    }

    /// The exact Bayesian posterior-predictive probability of no change over
    /// `delta_secs`, `(β / (β + Δ))^α`.
    ///
    /// Reported alongside [`HazardModel::freshness_lcb`] because the gap
    /// between the two *is* the price of the guarantee: the LCB is what the
    /// decision uses, the predictive mean is what a calibration study
    /// measures against reality.
    pub fn freshness_predictive(&self, delta_secs: f64) -> f64 {
        if delta_secs <= 0.0 {
            return 1.0;
        }
        let (alpha, beta) = self.posterior();
        if !is_positive(beta) {
            return 0.0;
        }
        let ratio = beta / (beta + delta_secs);
        if ratio <= 0.0 {
            return 0.0;
        }
        exp(alpha * ln(ratio)).clamp(0.0, 1.0)
    }

    /// Effective exposure in seconds — how much has actually been watched,
    /// after forgetting.
    pub fn evidence_secs(&self) -> f64 {
        self.evidence_secs
    }

    /// Total exposure ever recorded, before forgetting. The gap between
    /// this and [`HazardModel::evidence_secs`] is the non-stationarity
    /// discount the model is applying, which is what an operator needs to
    /// see to tune `forgetting_secs`.
    pub fn lifetime_exposure_secs(&self) -> f64 {
        self.lifetime_exposure_secs
    }

    /// Whether the model has watched the set for at least `secs` seconds of
    /// effective exposure. A policy gate, not a statistical one: the LCB
    /// already encodes the uncertainty, this exists so an operator can say
    /// "do not use prediction on a set I have only just met".
    pub fn has_evidence(&self, secs: f64) -> bool {
        self.evidence_secs >= secs
    }

    /// Lifetime observations / changes / failures.
    pub fn counts(&self) -> (u64, u64, u64) {
        (self.observations, self.changes, self.failures)
    }

    /// Consecutive refresh failures since the last success.
    pub fn consecutive_failures(&self) -> u64 {
        self.consecutive_failures
    }

    /// EWMA of the authoritative TTL, in seconds.
    pub fn ttl_ewma(&self) -> f64 {
        self.ttl_ewma
    }

    /// EWMA of `|T − T̄|`, in seconds. A volatile TTL means the zone is
    /// under active management, which is a hazard signal the TTL *value*
    /// alone does not carry.
    pub fn ttl_volatility(&self) -> f64 {
        self.ttl_volatility
    }

    /// Wall time of the last observed content change.
    pub fn last_change(&self) -> Ts {
        self.last_change
    }

    /// Wall time of the last successful observation.
    pub fn last_observation(&self) -> Ts {
        self.last_observation
    }

    /// Advance the non-stationarity clock to `now` without recording an
    /// observation.
    ///
    /// Used before a *failed* refresh: time passed, so the evidence is
    /// older, but nothing was learned about the RRset — in particular a
    /// failed refresh must never be recorded as `Y = 0`, because silence is
    /// not evidence of stability.
    pub fn decay_to(&mut self, now: Ts) {
        let elapsed = now.saturating_sub(self.last_observation) as f64 / 1e9;
        if elapsed <= 0.0 {
            return;
        }
        let gamma = self.forgetting_factor(elapsed);
        self.alpha_ev *= gamma;
        self.beta_ev *= gamma;
        self.evidence_secs *= gamma;
        self.last_observation = now;
    }

    /// Record a *failed* refresh: the evidence ages, nothing is learned.
    ///
    /// Returns nothing; the caller records the failure in its own counters
    /// as well (this model's `failures` is a diagnostic).
    pub fn observe_failure(&mut self, now: Ts) {
        self.decay_to(now);
        self.failures = self.failures.saturating_add(1);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    /// Record a successful refresh.
    ///
    /// * `interval_secs` — the exposure since the previous successful
    ///   observation. **This is the caller's measurement**, not a nominal
    ///   scheduler period: an observation that claims an interval it did not
    ///   have is a wrong likelihood, and the whole point of the model is that
    ///   the sampling cadence is irregular.
    /// * `changed` — whether the RRset content differed from the snapshot.
    /// * `ttl_secs` — the authoritative TTL of the *new* data.
    /// * `trust` — observation weight in `(0, 1]`. `1.0` for a refresh whose
    ///   answer was fully authentic; lower for an answer that was accepted on
    ///   the strength of a non-cryptographic check (ID/port/0x20 alone).
    ///   This is where authenticity enters the statistics instead of being
    ///   bolted on as a separate gate.
    ///
    /// # The first-order approximation, stated honestly
    ///
    /// The exact likelihood of an unchanged sample is `e^(−λh)`, whose
    /// information about `λ` is `O(h²)` — second order. The Gamma update used
    /// here adds `h` to `β` for *every* sample, `Y = 0` included. That
    /// over-states the information in an unchanged sample when `λh` is not
    /// small. Two things bound the damage: `β` saturates at `τ` (see the
    /// module documentation), and the bias is in the direction of *more*
    /// confidence, which is why the decision layer uses the upper bound
    /// rather than the mean. A set whose true `λh` is not small is, by
    /// definition, one that changes between samples — i.e. one whose
    /// observations are mostly `Y = 1`, where the approximation is exact.
    pub fn observe(
        &mut self,
        interval_secs: f64,
        changed: bool,
        ttl_secs: u32,
        now: Ts,
        trust: f64,
    ) {
        let h = if interval_secs.is_finite() && interval_secs > 0.0 {
            interval_secs
        } else {
            0.0
        };
        let w = if trust.is_nan() {
            0.0
        } else {
            trust.clamp(0.0, 1.0)
        };
        let gamma = self.forgetting_factor(h);

        // Fold the newly observed TTL into the prior anchor before the
        // posterior is recomputed, so a zone that raises its TTL is believed
        // to have become more durable.
        let t = (ttl_secs.max(1)) as f64;
        if self.observations == 0 {
            self.ttl_ewma = t;
            self.ttl_volatility = 0.0;
            self.prior_ttl_secs = t;
        } else {
            self.ttl_volatility =
                self.ttl_volatility * 0.8 + crate::float::fabs(t - self.ttl_ewma) * 0.2;
            self.ttl_ewma = self.ttl_ewma * 0.8 + t * 0.2;
            self.prior_ttl_secs = self.ttl_ewma.max(1.0);
        }

        let y = if changed { 1.0 } else { 0.0 };
        // Decay the evidence only; the prior is a permanent floor, so the
        // credible interval never collapses to a point.
        self.alpha_ev = self.alpha_ev * gamma + w * y;
        self.beta_ev = self.beta_ev * gamma + w * h;
        self.evidence_secs = self.beta_ev.max(0.0);
        self.lifetime_exposure_secs += w * h;
        self.observations = self.observations.saturating_add(1);
        if changed {
            self.changes = self.changes.saturating_add(1);
            self.last_change = now;
        }
        self.consecutive_failures = 0;
        self.last_observation = now;
    }

    /// The interval at which the next observation should be scheduled.
    ///
    /// Solved from the model itself rather than fixed in advance: sample
    /// again when the conservative probability of still being fresh has
    /// fallen to [`HazardConfig::target_freshness`], i.e.
    /// `h* = −ln(target) / λ_hi`, clamped to `[min, max]`.
    ///
    /// The consequences are exactly what the sampling theory asks for: an
    /// entry about which little is known (`λ_hi` large) is sampled often; an
    /// entry with a long, well-observed life is sampled rarely; and an entry
    /// whose bound cannot be computed (`λ_hi = ∞`) is sampled at the minimum
    /// interval. A short TTL does not by itself buy a short interval, and a
    /// long TTL does not by itself buy a long one — only evidence does.
    pub fn next_interval_secs(&self) -> f64 {
        let cfg = &self.config;
        let min = cfg.min_interval_secs.max(0.001);
        let max = cfg.max_interval_secs.max(min);
        let target = cfg.target_freshness.clamp(1e-6, 1.0 - 1e-9);
        let lambda = self.hazard_upper_bound();
        if !lambda.is_finite() || lambda <= 0.0 {
            return min;
        }
        let h = -ln(target) / lambda;
        if h.is_nan() {
            return min;
        }
        h.clamp(min, max)
    }

    /// The forgetting factor for an interval `h`.
    fn forgetting_factor(&self, h: f64) -> f64 {
        let tau = self.config.forgetting_secs;
        if !is_positive(tau) || !h.is_finite() {
            return 1.0;
        }
        exp(-h / tau)
    }
}

/// A plain snapshot of a [`HazardModel`]'s state, for persistence.
///
/// Every field is a scalar the model already carries; nothing is derived and
/// nothing is recomputed, so a restored model is *bit-identical* to the one
/// that was saved. That matters more than it looks: a persistent tier whose
/// restore path silently re-derives state would make a restart look like a
/// learning event, and the resulting behaviour would not be reproducible.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HazardState {
    /// The authoritative TTL the prior is anchored to, in seconds.
    pub prior_ttl_secs: f64,
    /// Decayed change evidence `a`.
    pub alpha_ev: f64,
    /// Decayed exposure evidence `b`, in seconds.
    pub beta_ev: f64,
    /// Effective exposure, in seconds.
    pub evidence_secs: f64,
    /// Lifetime exposure before forgetting, in seconds.
    pub lifetime_exposure_secs: f64,
    /// Lifetime observations.
    pub observations: u64,
    /// Lifetime observed changes.
    pub changes: u64,
    /// Lifetime refresh failures.
    pub failures: u64,
    /// Consecutive failures since the last success.
    pub consecutive_failures: u64,
    /// EWMA of the authoritative TTL, in seconds.
    pub ttl_ewma: f64,
    /// EWMA of `|T − T̄|`, in seconds.
    pub ttl_volatility: f64,
    /// Wall time of the last successful observation.
    pub last_observation: Ts,
    /// Wall time of the last observed content change.
    pub last_change: Ts,
}

impl HazardModel {
    /// The model's state, as plain data.
    pub fn state(&self) -> HazardState {
        HazardState {
            prior_ttl_secs: self.prior_ttl_secs,
            alpha_ev: self.alpha_ev,
            beta_ev: self.beta_ev,
            evidence_secs: self.evidence_secs,
            lifetime_exposure_secs: self.lifetime_exposure_secs,
            observations: self.observations,
            changes: self.changes,
            failures: self.failures,
            consecutive_failures: self.consecutive_failures,
            ttl_ewma: self.ttl_ewma,
            ttl_volatility: self.ttl_volatility,
            last_observation: self.last_observation,
            last_change: self.last_change,
        }
    }

    /// Rebuild a model from a persisted state.
    ///
    /// Non-finite or negative inputs are replaced by the corresponding
    /// untouched-initial value rather than being trusted: a corrupt frame
    /// must not be able to manufacture confidence, and `α ≤ 0` or `β ≤ 0`
    /// would do exactly that by making the credibility bound infinite.
    pub fn from_state(config: HazardConfig, state: HazardState) -> Self {
        let config = config.sanitised();
        let prior = if state.prior_ttl_secs.is_finite() && state.prior_ttl_secs >= 1.0 {
            state.prior_ttl_secs
        } else {
            DEFAULT_PRIOR_TTL_SECS_FALLBACK
        };
        let alpha_ev = if state.alpha_ev.is_finite() && state.alpha_ev >= 0.0 {
            state.alpha_ev
        } else {
            0.0
        };
        let beta_ev = if state.beta_ev.is_finite() && state.beta_ev >= 0.0 {
            state.beta_ev
        } else {
            0.0
        };
        let evidence = if state.evidence_secs.is_finite() && state.evidence_secs >= 0.0 {
            state.evidence_secs
        } else {
            beta_ev
        };
        Self {
            config,
            alpha_ev,
            beta_ev,
            prior_ttl_secs: prior,
            evidence_secs: evidence,
            lifetime_exposure_secs: if state.lifetime_exposure_secs.is_finite()
                && state.lifetime_exposure_secs >= 0.0
            {
                state.lifetime_exposure_secs
            } else {
                0.0
            },
            observations: state.observations,
            changes: state.changes,
            failures: state.failures,
            consecutive_failures: state.consecutive_failures,
            ttl_ewma: if state.ttl_ewma.is_finite() && state.ttl_ewma >= 1.0 {
                state.ttl_ewma
            } else {
                prior
            },
            ttl_volatility: if state.ttl_volatility.is_finite() && state.ttl_volatility >= 0.0 {
                state.ttl_volatility
            } else {
                0.0
            },
            last_observation: state.last_observation,
            last_change: state.last_change,
        }
    }
}

/// The TTL a restored model falls back to when the frame's value is unusable.
const DEFAULT_PRIOR_TTL_SECS_FALLBACK: f64 = 300.0;

impl fmt::Display for HazardModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (alpha, beta) = self.posterior();
        write!(
            f,
            "hazard(alpha={:.3} beta={:.0}s lambda_ub={:.3e}/s evidence={:.0}s obs={} chg={} fail={} ttl={:.0}s)",
            alpha,
            beta,
            self.hazard_upper_bound(),
            self.evidence_secs,
            self.observations,
            self.changes,
            self.failures,
            self.ttl_ewma
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    fn cfg() -> HazardConfig {
        HazardConfig {
            forgetting_secs: 86_400.0,
            ..HazardConfig::default()
        }
    }

    /// The bound must actually be a bound. Sample the Gamma law by its
    /// exact tail at the returned point: for integer shape, the survival
    /// function is `e^(−βx)·Σ_{k<α} (βx)^k/k!`, which is cheap to evaluate
    /// and independent of the Chernoff derivation.
    fn gamma_survival_integer_shape(alpha: u32, beta: f64, x: f64) -> f64 {
        let bx = beta * x;
        let mut term = 1.0;
        let mut sum = 1.0;
        for k in 1..alpha {
            term *= bx / k as f64;
            sum += term;
        }
        exp(-bx) * sum
    }

    #[test]
    fn chernoff_bound_is_valid() {
        for alpha in 1u32..8 {
            for beta in [1.0, 10.0, 1_000.0] {
                for delta in [0.5, 0.2, 0.05, 0.01, 1e-4] {
                    let x = gamma_upper_bound(alpha as f64, beta, delta);
                    let tail = gamma_survival_integer_shape(alpha, beta, x);
                    assert!(
                        tail <= delta * 1.000_000_1,
                        "α={alpha} β={beta} δ={delta}: tail {tail} > δ at x={x}"
                    );
                    assert!(x >= alpha as f64 / beta, "bound must exceed the mean");
                }
            }
        }
    }

    #[test]
    fn bound_is_tighter_than_mean_only_above_it() {
        // Sanity on the bracket: the root is always strictly above the mean
        // for δ < 1.
        let x = gamma_upper_bound(2.0, 100.0, 0.05);
        assert!(x > 0.02);
        assert!(x < 1.0);
    }

    #[test]
    fn no_information_yields_no_confidence() {
        let m = HazardModel::new(cfg(), 300, now());
        // Prior only: one change per TTL, with a wide credible interval.
        let p = m.freshness_lcb(600.0);
        assert!(p < 0.5, "prior-only LCB should be weak, got {p}");
        assert!(
            m.freshness_predictive(600.0) > p,
            "the LCB must be the conservative side"
        );
    }

    #[test]
    fn evidence_raises_confidence_monotonically() {
        let mut m = HazardModel::new(cfg(), 300, now());
        let mut last = m.freshness_lcb(60.0);
        for i in 1..=200 {
            m.observe(300.0, false, 300, now() + i * 300 * 1_000_000_000, 1.0);
            let p = m.freshness_lcb(60.0);
            assert!(p >= last - 1e-12, "LCB fell at step {i}: {last} → {p}");
            last = p;
        }
        assert!(
            last > 0.99,
            "a set unchanged for a day should be very credible, got {last}"
        );
    }

    #[test]
    fn confidence_saturates_because_forgetting_bounds_exposure() {
        // The anti-forgery property: no amount of "unchanged" observations
        // can push the effective exposure past the forgetting constant.
        let mut m = HazardModel::new(cfg(), 300, now());
        for i in 1..=100_000 {
            m.observe(60.0, false, 300, now() + i * 60 * 1_000_000_000, 1.0);
        }
        assert!(
            m.evidence_secs() <= cfg().forgetting_secs * 1.02,
            "exposure {} escaped the forgetting ceiling",
            m.evidence_secs()
        );
        let p = m.freshness_lcb(3600.0);
        assert!(p < 1.0, "confidence must never be absolute, got {p}");
    }

    #[test]
    fn a_change_resets_confidence_hard() {
        let mut m = HazardModel::new(cfg(), 300, now());
        for i in 1..=100 {
            m.observe(300.0, false, 300, now() + i * 300 * 1_000_000_000, 1.0);
        }
        let before = m.freshness_lcb(60.0);
        m.observe(300.0, true, 300, now() + 101 * 300 * 1_000_000_000, 1.0);
        let after = m.freshness_lcb(60.0);
        assert!(
            after < before,
            "a change must lower confidence: {before} → {after}"
        );
        let (_, _, _) = m.counts();
        assert_eq!(m.counts().1, 1);
    }

    #[test]
    fn low_trust_observations_move_the_model_less() {
        let mut trusted = HazardModel::new(cfg(), 300, now());
        let mut untrusted = HazardModel::new(cfg(), 300, now());
        for i in 1..=100 {
            let t = now() + i * 300 * 1_000_000_000;
            trusted.observe(300.0, false, 300, t, 1.0);
            untrusted.observe(300.0, false, 300, t, 0.25);
        }
        assert!(
            untrusted.freshness_lcb(60.0) < trusted.freshness_lcb(60.0),
            "an unauthenticated channel must not buy the same confidence"
        );
    }

    #[test]
    fn failures_are_not_evidence_of_stability() {
        let mut m = HazardModel::new(cfg(), 300, now());
        let before = m.freshness_lcb(60.0);
        m.observe_failure(now() + 3600 * 1_000_000_000);
        let after = m.freshness_lcb(60.0);
        assert!(after <= before + 1e-12, "silence must not raise confidence");
        assert_eq!(m.consecutive_failures(), 1);
    }

    #[test]
    fn adaptive_interval_shrinks_with_uncertainty() {
        let mut unknown = HazardModel::new(cfg(), 300, now());
        let mut known = HazardModel::new(cfg(), 300, now());
        for i in 1..=200 {
            known.observe(300.0, false, 300, now() + i * 300 * 1_000_000_000, 1.0);
        }
        let h_unknown = unknown.next_interval_secs();
        let h_known = known.next_interval_secs();
        assert!(
            h_known > h_unknown,
            "a well-observed set should be sampled less often: {h_known} vs {h_unknown}"
        );
        // And the interval always means what it says: at that horizon the
        // LCB is at the target.
        let p = known.freshness_lcb(h_known);
        assert!((p - 0.9).abs() < 0.02, "target freshness not honoured: {p}");
        unknown.set_config(cfg());
    }

    #[test]
    fn predictive_matches_beta_for_prior_only() {
        // With α = 1 the posterior predictive is β/(β+Δ) exactly.
        let m = HazardModel::new(cfg(), 300, now());
        let d = 100.0;
        let want = 300.0 / (300.0 + d);
        assert!((m.freshness_predictive(d) - want).abs() < 1e-12);
    }

    #[test]
    fn ttl_volatility_is_tracked() {
        let mut m = HazardModel::new(cfg(), 300, now());
        for (i, ttl) in [300u32, 60, 300, 60, 300, 60].iter().enumerate() {
            m.observe(
                300.0,
                false,
                *ttl,
                now() + (i as Ts) * 300 * 1_000_000_000,
                1.0,
            );
        }
        assert!(
            m.ttl_volatility() > 1.0,
            "volatility {}",
            m.ttl_volatility()
        );
    }
}
