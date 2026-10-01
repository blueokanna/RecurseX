//! Value of information: what one more observation is worth, in risk units.
//!
//! # The gap this fills
//!
//! The refresh path has two halves. [`crate::planner::PrefetchPolicy`] answers
//! *whether an entry is due*: it compares the conservative freshness against a
//! target and admits the entry if it has fallen short. That is a threshold, and
//! a threshold can only say "look at this too". The maintenance loop holds a
//! **finite** budget — [`crate::risk::RefreshBudget`] mints tokens at a fixed
//! rate — so the question that actually decides the outcome is not *whether* but
//! **where the next token buys the most**. Until this module existed the answer
//! was "the entry with the lowest `P_LCB`", which is a heuristic: it is blind to
//! how much an observation would *teach*, to how much the answer is *worth*, and
//! to how much harm its class of data can do.
//!
//! # The objective
//!
//! An observation is worth the **reduction in expected risk** it produces, using
//! the same risk functional the serve-stale decision uses:
//!
//! ```text
//! R = V · (1 − p) · C · κ
//! ```
//!
//! with `V` the value of a hit in milliseconds, `p` the probability the data is
//! still correct, `C` the consequence coefficient of the record's class, and `κ`
//! the trust penalty. The value of observing is
//!
//! ```text
//! VoI = R(do nothing)  −  E[ R(after observing) ]
//! ```
//!
//! where the expectation is over the two outcomes an observation can have, each
//! weighted by the model's own predictive probability.
//!
//! # Why it is computed by *replaying* the update
//!
//! The posterior after an observation is obtained by cloning the hazard model
//! and calling the very same [`crate::hazard::HazardModel::observe`] the real
//! refresh path calls. Not a re-derivation of the conjugate update, not an
//! approximation of the credibility bound: the same function.
//!
//! That choice is the whole reason this module can be trusted. A value function
//! that re-implements the dynamics is a second source of truth, and the failure
//! mode is silent — the ranking would look reasonable while pricing an update
//! the model never performs. Replaying costs one clone and two bounded
//! bisections per candidate, which is nothing next to the network round trip the
//! token is about to buy.
//!
//! # Two distinctions that must not be blurred
//!
//! **Prediction may be used here; it may not be used for safety.** The
//! expectation above weights the outcomes by
//! [`StabilityModel::freshness_predictive`], the posterior-predictive mean. That
//! is correct in this module because a value is an expectation — what we will
//! learn, on average. It would be *incorrect* in [`crate::risk`], where the
//! quantity is the probability of being wrong and a mean is not a guarantee.
//! The same separation already splits [`crate::cache::score`] (ranking) from
//! [`crate::risk`] (deciding), and it holds here for the same reason.
//!
//! **The consequence coefficient `∞` becomes a large finite number.** The
//! `Absolute` class returns an infinite coefficient because it must never be
//! traded against latency. A *value function* that is summed over candidates
//! cannot contain an infinity and remain a total order, so the ranking uses
//! [`ABSOLUTE_WEIGHT`]. This does not soften the prohibition by one bit: that
//! lives in `risk::assess`, which still returns `ClassForbidsStale` and still
//! refuses. Here the number exists only to put such an entry at the top of a
//! list.
//!
//! # What this is not
//!
//! It is a **one-step** lookahead. It prices the next observation, not a policy:
//! solving for the optimal sequence would need a planner over a belief state,
//! and a per-tick scheduler cannot justify one. Where the one-step assumption
//! shows is that after observing, the entry would in reality be observed again
//! inside the same horizon, so `E[R(after)]` is a slight over-estimate and the
//! value a slight under-estimate. The direction is the safe one, and it is
//! stated rather than hidden.

use alloc::vec::Vec;

use crate::behavior::BehaviorClass;
use crate::float::{exp_nonpos, is_positive};
use crate::risk::{Consequence, TrustLevel};
use crate::stability::StabilityModel;
use crate::time::Ts;

/// The weight used in place of an unbounded consequence coefficient.
///
/// The `Absolute` class (`DNSKEY`, `DS`, `RRSIG`, `NSEC`, `NSEC3`) has
/// `coefficient() == ∞`, because a stale answer there is a security failure
/// rather than a freshness one and must never be traded. A ranking cannot hold
/// an infinity: `∞ − ∞` is `NaN`, and a `NaN` sorts unpredictably. This finite
/// stand-in keeps the class at the top of the ranking, and the prohibition
/// itself is enforced — untouched — in [`crate::risk::assess`].
pub const ABSOLUTE_WEIGHT: f64 = 1000.0;

/// The weight a consequence class contributes to the value of an observation.
///
/// Identical to [`Consequence::coefficient`] except that the unbounded case is
/// made finite; see [`ABSOLUTE_WEIGHT`].
pub fn class_weight(consequence: Consequence) -> f64 {
    let c = consequence.coefficient();
    if c.is_finite() {
        c.max(0.0)
    } else {
        ABSOLUTE_WEIGHT
    }
}

/// Tuning of the value computation and of the schedule it drives.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct VoiConfig {
    /// The horizon over which the risk of *not* looking is evaluated, in
    /// seconds.
    ///
    /// This must be the same horizon the admissibility gate uses, or the two
    /// halves of the decision would disagree about what "due" means: the gate
    /// would admit an entry for missing one target while the value function
    /// priced it against another.
    pub horizon_secs: f64,
    /// The authoritative TTL the refresh is expected to return, in seconds.
    ///
    /// It is needed because [`crate::hazard::HazardModel::observe`] folds the
    /// observed TTL into the prior anchor, so the posterior it produces depends
    /// on it. Pricing the simulation with a zero or a guess would price a
    /// *different update* than the one that will actually run — the value would
    /// be computed for a model we do not have.
    pub ttl_secs: u32,
    /// The credibility level's tail probability `δ`, for the bound each
    /// simulated observation is priced against.
    pub tail_probability: f64,
    /// The observation weight assumed for the refresh being contemplated, in
    /// `(0, 1]`. Matches how the entry's own observations are weighted — a
    /// refresh whose answer will be authenticated is worth more than one
    /// accepted on an ID and a port alone, because it buys more evidence.
    pub observation_weight: f64,
    /// Candidates whose value does not exceed this are not scheduled at all.
    ///
    /// Zero is the honest default: a refresh that reduces no risk is not worth
    /// a token, and every positive value is worth having if the budget is
    /// otherwise idle. Raising it is an operator's statement that small
    /// improvements are not worth the upstream load.
    pub min_value: f64,
    /// Slots reserved for each behaviour class that has candidates.
    ///
    /// See [`schedule`]; this is the anti-starvation knob, and it is the one
    /// setting here that can trade total value for a guarantee.
    pub reservation_per_class: usize,
}

impl Default for VoiConfig {
    fn default() -> Self {
        Self {
            horizon_secs: 60.0,
            ttl_secs: 300,
            tail_probability: 0.05,
            observation_weight: 1.0,
            min_value: 0.0,
            reservation_per_class: 1,
        }
    }
}

impl VoiConfig {
    /// The same configuration with every field forced into a usable range.
    ///
    /// The horizon and the tail probability come from configuration files and
    /// from measurements, so a `NaN` in either is a plausible input. Both would
    /// otherwise propagate: `NaN` compares false against everything, so a
    /// `NaN` horizon would make every value `0.0` and silently disable
    /// scheduling altogether, which looks exactly like "nothing is due".
    pub fn sanitised(self) -> Self {
        let d = Self::default();
        let finite = |v: f64, fallback: f64| if v.is_finite() { v } else { fallback };
        Self {
            horizon_secs: finite(self.horizon_secs, d.horizon_secs).clamp(0.0, 86_400.0),
            ttl_secs: self.ttl_secs.max(1),
            tail_probability: finite(self.tail_probability, d.tail_probability)
                .clamp(1e-12, 1.0 - 1e-12),
            observation_weight: finite(self.observation_weight, d.observation_weight)
                .clamp(1e-6, 1.0),
            min_value: finite(self.min_value, d.min_value).max(0.0),
            reservation_per_class: self.reservation_per_class.min(64),
        }
    }
}

/// `P(still correct after t seconds)` under a change rate of `lambda`.
///
/// Deliberately the same expression [`crate::hazard::HazardModel::freshness_lcb`]
/// evaluates, so a value quoted here and a bound quoted there are the same
/// quantity in the same units.
fn survival(lambda: f64, t: f64) -> f64 {
    if !is_positive(lambda) {
        // No bound at all: nothing may be assumed about the data.
        return 0.0;
    }
    if t <= 0.0 {
        return 1.0;
    }
    exp_nonpos(-lambda * t).clamp(0.0, 1.0)
}

/// How long ago the model last observed the set, in seconds.
///
/// Clamped to the model's own maximum observation interval. A cold entry can
/// have an age of days, but an observation the model would never accept at that
/// exposure is not an observation we may price: `β` is bounded by `τ` in
/// steady state (see [`crate::hazard`]), and pricing a measure the model will not
/// take would make cold entries look artificially cheap to refresh.
fn knowledge_age_secs(model: &StabilityModel, now: Ts) -> f64 {
    let hazard = model.hazard();
    let raw = now.saturating_sub(hazard.last_observation()) as f64 / 1e9;
    let cap = hazard.config().max_interval_secs;
    if !raw.is_finite() || raw < 0.0 {
        return 0.0;
    }
    if is_positive(cap) {
        raw.min(cap)
    } else {
        raw
    }
}

/// The expected reduction in risk from observing `model` once, now.
///
/// Returns `0.0` whenever the value cannot be established to be positive —
/// a degenerate value, an unbounded change rate, a class whose coefficient
/// makes the arithmetic meaningless. Zero is the right failure value in every
/// one of those cases: it schedules nothing, which is the conservative action
/// for a *value* function. (A safety function would have to fail the other way;
/// this one is not consulted for safety.)
pub fn observation_value(
    model: &StabilityModel,
    consequence: Consequence,
    trust: TrustLevel,
    value_ms: f64,
    now: Ts,
    config: &VoiConfig,
) -> f64 {
    let cfg = config.sanitised();
    let weight = class_weight(consequence);
    let penalty = trust.penalty();
    if !is_positive(weight) || !penalty.is_finite() || penalty <= 0.0 {
        return 0.0;
    }
    let value = if value_ms.is_finite() {
        value_ms.max(0.0)
    } else {
        0.0
    };
    if value <= 0.0 {
        return 0.0;
    }
    let scale = value * weight * penalty;

    let hazard = model.hazard();
    let lambda = hazard.hazard_upper_bound();
    if !lambda.is_finite() {
        // No credible bound: the data may change at any rate, so an
        // observation cannot be shown to improve anything. The entry is still
        // *served* conservatively — that decision is `risk::assess`, and it
        // does not consult this function.
        return 0.0;
    }
    let age = knowledge_age_secs(model, now);
    let horizon = cfg.horizon_secs.max(0.0);

    // What the guarantee would look like at the end of the horizon having done
    // nothing: our knowledge is `age + horizon` seconds old.
    let r_without = scale * (1.0 - survival(lambda, age + horizon));

    // What it looks like having observed: the exposure the observation will
    // report is exactly `age`, and the two outcomes are weighted by the
    // model's own predictive probability for that exposure.
    let p_unchanged = hazard.freshness_predictive(age).clamp(0.0, 1.0);
    let mut r_with = 0.0;
    for changed in [false, true] {
        let mut after = hazard.clone();
        after.observe(age, changed, cfg.ttl_secs, now, cfg.observation_weight);
        let lambda_after = after.hazard_upper_bound();
        let r = if lambda_after.is_finite() {
            scale * (1.0 - survival(lambda_after, horizon))
        } else {
            r_without
        };
        let p = if changed {
            1.0 - p_unchanged
        } else {
            p_unchanged
        };
        r_with += p * r;
    }

    let delta = r_without - r_with;
    if delta.is_finite() && delta > 0.0 {
        delta
    } else {
        0.0
    }
}

/// One schedulable observation.
#[derive(Clone, Copy, Debug)]
pub struct Candidate<T> {
    /// What the caller wants back — a cache key, an index, anything.
    pub payload: T,
    /// The behavioural class, used as the cohort key for [`schedule`]'s
    /// reservation.
    pub class: BehaviorClass,
    /// The expected risk reduction, in milliseconds. From
    /// [`observation_value`].
    pub value: f64,
    /// The keyed behavioural fingerprint, used to break value ties.
    ///
    /// Two candidates with equal value would otherwise be ordered by whatever
    /// the cache's iteration order happens to be, which is a function of the
    /// query stream and therefore identical on every resolver in a fleet. The
    /// fingerprint makes the order reproducible for us and unguessable for
    /// anyone else; see [`crate::behavior`].
    pub tie_break: u128,
}

/// Which candidates to spend a budget of `budget` observations on.
///
/// # The allocation
///
/// Each observation costs exactly one token — the refresh budget is a token
/// bucket, not a bit-stream of cost-weighted work — so the objective is a plain
/// sum and the allocation that maximises it is the `budget` largest values. The
/// work is in *computing* the values, which is [`observation_value`]; the
/// selection itself is honest about being a sort, and is not dressed up as
/// anything else.
///
/// # The reservation, and what it costs
///
/// A pure value sort starves. A class of entries that is uncertain, valuable and
/// high-consequence can hold every token of every tick, and the cost of that
/// starvation is not merely "those entries are refreshed later": an entry that
/// is never observed has its evidence decay by design (`τ`), so its bound
/// widens, so it fails the freshness floor more often, so it can no longer be
/// served stale when a lookup *does* arrive. Starvation is therefore
/// self-reinforcing, and a scheduler with a budget should not have one.
///
/// So before the global fill, each behaviour class present is given up to
/// `reservation_per_class` slots, taken from that class's best candidates. The
/// guarantee is exactly this and no more: **if the budget is at least
/// `classes · reservation_per_class`, then every class with that many
/// candidates contributes at least `reservation_per_class`** of them. Below that
/// budget some class gets nothing, and the function does not pretend otherwise.
///
/// The reservation can only lower the total value — it spends slots on
/// candidates a global sort would have skipped. That is the trade, it is
/// deliberate, and `reservation_per_class = 0` turns it off for an operator who
/// would rather have the maximum.
///
/// The returned list is ordered by value, descending, with ties broken by
/// [`Candidate::tie_break`] and then by position; a caller that can afford fewer
/// than `budget` observations should take from the front.
pub fn schedule<T>(candidates: Vec<Candidate<T>>, budget: usize, config: &VoiConfig) -> Vec<T> {
    let cfg = config.sanitised();
    if budget == 0 {
        return Vec::new();
    }
    // Non-finite values are dropped rather than sorted. `observation_value`
    // cannot produce one — it is bounded by a finite class weight — so a
    // non-finite value here is a caller defect, and scheduling it would put an
    // arbitrary entry at the head of the queue.
    let items: Vec<Candidate<T>> = candidates
        .into_iter()
        .filter(|c| c.value.is_finite() && c.value > cfg.min_value)
        .collect();
    if items.is_empty() {
        return Vec::new();
    }

    // Total order: value desc, then fingerprint asc, then the caller's order.
    // The last term is what makes the sort a function of its input rather than
    // of the sort implementation's mood; the middle term is what makes it
    // different on every resolver in a fleet.
    let mut order: Vec<usize> = (0..items.len()).collect();
    order.sort_by(|&a, &b| {
        let (Some(ca), Some(cb)) = (items.get(a), items.get(b)) else {
            return a.cmp(&b);
        };
        cb.value
            .partial_cmp(&ca.value)
            .unwrap_or(core::cmp::Ordering::Equal)
            .then_with(|| ca.tie_break.cmp(&cb.tie_break))
            .then_with(|| a.cmp(&b))
    });
    // Rank lookup, so the final sort is O(n log n) rather than a scan per
    // comparison.
    let mut rank = alloc::vec![usize::MAX; items.len()];
    for (r, &idx) in order.iter().enumerate() {
        if let Some(slot) = rank.get_mut(idx) {
            *slot = r;
        }
    }

    let mut chosen: Vec<usize> = Vec::with_capacity(budget.min(items.len()));

    if cfg.reservation_per_class > 0 {
        // First pass: the reservation. The per-class counter is incremented only
        // in this pass, which is what the guarantee is stated over — a running
        // count on the class entry, not a difference of positions, because the
        // classes interleave in value order.
        let mut classes: Vec<(BehaviorClass, usize)> = Vec::new();
        for &idx in &order {
            if chosen.len() >= budget {
                break;
            }
            let Some(candidate) = items.get(idx) else {
                continue;
            };
            let class = candidate.class;
            let slot = match classes.iter().position(|(c, _)| *c == class) {
                Some(p) => p,
                None => {
                    classes.push((class, 0));
                    classes.len() - 1
                }
            };
            let taken = classes.get(slot).map(|(_, n)| *n).unwrap_or(0);
            if taken >= cfg.reservation_per_class {
                continue;
            }
            if let Some(entry) = classes.get_mut(slot) {
                entry.1 += 1;
            }
            chosen.push(idx);
        }
    }

    // Second pass: the global fill. Everything not already chosen, best first.
    if chosen.len() < budget {
        let mut taken = alloc::vec![false; items.len()];
        for &idx in &chosen {
            if let Some(slot) = taken.get_mut(idx) {
                *slot = true;
            }
        }
        for &idx in &order {
            if chosen.len() >= budget {
                break;
            }
            if taken.get(idx).copied().unwrap_or(true) {
                continue;
            }
            if let Some(slot) = taken.get_mut(idx) {
                *slot = true;
            }
            chosen.push(idx);
        }
    }

    chosen.sort_by_key(|&idx| rank.get(idx).copied().unwrap_or(usize::MAX));
    let mut slots: Vec<Option<T>> = items.into_iter().map(|c| Some(c.payload)).collect();
    let mut out: Vec<T> = Vec::with_capacity(chosen.len());
    for idx in chosen {
        if let Some(payload) = slots.get_mut(idx).and_then(Option::take) {
            out.push(payload);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hazard::HazardConfig;

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    fn secs(n: i64) -> Ts {
        (n as Ts) * 1_000_000_000
    }

    /// A model that has been watched for `observations` intervals of `step`
    /// seconds each, none of which changed.
    fn observed(ttl: u32, step_secs: i64, observations: usize) -> StabilityModel {
        let mut m = StabilityModel::with_config(HazardConfig::default(), ttl, now());
        for i in 1..=observations {
            m.observe(ttl, false, now() + secs(step_secs * i as i64));
        }
        m
    }

    fn cfg() -> VoiConfig {
        VoiConfig {
            horizon_secs: 60.0,
            ttl_secs: 300,
            ..VoiConfig::default()
        }
    }

    /// How long ago the last observation is assumed to have been when an entry
    /// is priced.
    ///
    /// Never zero, and that is not a test convenience: a refresh reports the
    /// exposure *since the last observation*, so pricing an entry at the
    /// instant it was last observed is pricing an observation with no exposure
    /// — which carries no information and is therefore correctly worth nothing.
    /// The maintenance loop can only ever see entries with a non-zero age.
    const AGE: i64 = 120;

    fn priced_at(
        model: &StabilityModel,
        age_secs: i64,
        consequence: Consequence,
        trust: TrustLevel,
        value_ms: f64,
    ) -> f64 {
        observation_value(
            model,
            consequence,
            trust,
            value_ms,
            model.hazard().last_observation() + secs(age_secs),
            &cfg(),
        )
    }

    #[test]
    fn an_unobserved_entry_is_worth_observing_and_a_watched_one_is_worth_less() {
        // The property the whole module exists for. A set nobody has watched
        // has a wide bound, so the risk of not looking is real; a set watched
        // for hours has a narrow one, so there is little left to buy.
        let fresh = StabilityModel::with_config(HazardConfig::default(), 300, now());
        let watched = observed(300, 60, 40);
        let v_fresh = priced_at(
            &fresh,
            AGE,
            Consequence::Low,
            TrustLevel::ChainAnchored,
            50.0,
        );
        let v_watched = priced_at(
            &watched,
            AGE,
            Consequence::Low,
            TrustLevel::ChainAnchored,
            50.0,
        );
        assert!(v_fresh > 0.0, "an unwatched entry must be worth observing");
        assert!(
            v_watched < v_fresh,
            "watching must reduce what is left to buy: {v_watched} vs {v_fresh}"
        );
    }

    #[test]
    fn looking_at_something_we_just_looked_at_buys_nothing() {
        // The refresh reports the exposure since the previous observation, so
        // an observation taken zero seconds after the last one carries no
        // evidence and cannot improve the bound. A value function that priced
        // it as positive would let the scheduler spend the whole budget
        // re-observing whatever it had just seen.
        let m = StabilityModel::with_config(HazardConfig::default(), 300, now());
        assert_eq!(
            observation_value(
                &m,
                Consequence::Critical,
                TrustLevel::Unverified,
                500.0,
                now(),
                &cfg()
            ),
            0.0
        );
    }

    #[test]
    fn value_grows_with_how_long_ago_we_last_looked() {
        // Age is the exposure the next observation would report, so a longer
        // gap is both more risk carried and more evidence bought. It is the
        // one input the threshold rule cannot see at all: two entries with the
        // same `P_LCB` are not equally worth a token if one was confirmed a
        // minute ago and the other an hour ago.
        let m = StabilityModel::with_config(HazardConfig::default(), 300, now());
        let mut previous = 0.0;
        for age in [30i64, 120, 600, 3600] {
            let v = priced_at(&m, age, Consequence::High, TrustLevel::Unverified, 50.0);
            assert!(v > previous, "age {age} gave {v}, not more than {previous}");
            previous = v;
        }
    }

    #[test]
    fn value_increases_with_the_consequence_class() {
        let m = StabilityModel::with_config(HazardConfig::default(), 300, now());
        let vals: Vec<f64> = [
            Consequence::Low,
            Consequence::Medium,
            Consequence::High,
            Consequence::Critical,
            Consequence::Absolute,
        ]
        .iter()
        .map(|&c| priced_at(&m, AGE, c, TrustLevel::ChainAnchored, 50.0))
        .collect();
        for w in vals.windows(2) {
            assert!(w[1] > w[0], "value must increase with class: {vals:?}");
        }
    }

    #[test]
    fn value_increases_with_the_trust_penalty() {
        let m = StabilityModel::with_config(HazardConfig::default(), 300, now());
        let vals: Vec<f64> = [
            TrustLevel::ChainAnchored,
            TrustLevel::CryptoVerified,
            TrustLevel::Unverified,
            TrustLevel::Indeterminate,
        ]
        .iter()
        .map(|&t| priced_at(&m, AGE, Consequence::High, t, 50.0))
        .collect();
        for w in vals.windows(2) {
            assert!(
                w[1] > w[0],
                "value must increase with the penalty: {vals:?}"
            );
        }
    }

    #[test]
    fn value_increases_with_what_the_answer_is_worth() {
        let m = StabilityModel::with_config(HazardConfig::default(), 300, now());
        let cheap = priced_at(&m, AGE, Consequence::High, TrustLevel::Unverified, 10.0);
        let dear = priced_at(&m, AGE, Consequence::High, TrustLevel::Unverified, 100.0);
        assert!(
            dear > cheap,
            "a dearer answer is worth more: {dear} vs {cheap}"
        );
    }

    #[test]
    fn the_value_never_exceeds_the_risk_of_not_acting() {
        // An observation can only remove risk; it cannot create value out of
        // nothing. The upper bound is the risk of doing nothing computed with
        // the same scale.
        for (consequence, trust, value_ms) in [
            (Consequence::Low, TrustLevel::ChainAnchored, 50.0),
            (Consequence::Critical, TrustLevel::Unverified, 500.0),
            (Consequence::Absolute, TrustLevel::Indeterminate, 200.0),
        ] {
            let m = StabilityModel::with_config(HazardConfig::default(), 300, now());
            let v = priced_at(&m, AGE, consequence, trust, value_ms);
            let ceiling = value_ms * class_weight(consequence) * trust.penalty();
            assert!(
                v > 0.0 && v <= ceiling,
                "{v} was outside (0, {ceiling}] for {consequence:?}/{trust:?}"
            );
        }
    }

    #[test]
    fn a_zero_change_rate_leaves_nothing_to_buy() {
        // A model watched for far longer than `τ` with no changes has a bound
        // that the evidence ceiling cannot shrink further, so observing again
        // is worth almost nothing. This is the case a threshold rule cannot
        // distinguish from a genuinely volatile entry whose bound merely
        // happens to be low.
        let watched = observed(300, 3600, 200);
        let v = priced_at(
            &watched,
            AGE,
            Consequence::Low,
            TrustLevel::ChainAnchored,
            50.0,
        );
        let unwatched = priced_at(
            &StabilityModel::with_config(HazardConfig::default(), 300, now()),
            AGE,
            Consequence::Low,
            TrustLevel::ChainAnchored,
            50.0,
        );
        assert!(
            v < unwatched / 4.0,
            "a long-clean set is nearly worthless: {v} vs {unwatched}"
        );
    }

    #[test]
    fn value_needs_the_data_to_be_worth_something() {
        let m = StabilityModel::with_config(HazardConfig::default(), 300, now());
        assert_eq!(
            observation_value(
                &m,
                Consequence::High,
                TrustLevel::Unverified,
                0.0,
                now(),
                &cfg()
            ),
            0.0
        );
        assert_eq!(
            observation_value(
                &m,
                Consequence::High,
                TrustLevel::Unverified,
                -5.0,
                now(),
                &cfg()
            ),
            0.0
        );
        assert_eq!(
            observation_value(
                &m,
                Consequence::High,
                TrustLevel::Unverified,
                f64::NAN,
                now(),
                &cfg()
            ),
            0.0
        );
    }

    #[test]
    fn degenerate_timing_never_produces_a_non_value() {
        // Every one of these can come out of an arithmetic path fed a bad
        // sample. None may panic and none may return NaN or a negative.
        let m = StabilityModel::with_config(HazardConfig::default(), 300, now());
        for now_v in [
            now(),
            now() - secs(10_000),
            now() + secs(10_000_000),
            Ts::MIN,
            Ts::MAX,
        ] {
            for horizon in [0.0, -1.0, 60.0, f64::NAN, f64::INFINITY] {
                let c = VoiConfig {
                    horizon_secs: horizon,
                    ..VoiConfig::default()
                };
                let v = observation_value(
                    &m,
                    Consequence::High,
                    TrustLevel::Unverified,
                    50.0,
                    now_v,
                    &c,
                );
                assert!(
                    v.is_finite() && v >= 0.0,
                    "value {v} for horizon {horizon} at {now_v}"
                );
            }
        }
    }

    #[test]
    fn the_absolute_class_is_not_rejected_by_the_value_function() {
        // `∞ − ∞` is `NaN`. The class whose coefficient is unbounded must still
        // receive a finite, comparable value — the prohibition on serving it
        // stale lives in `risk::assess`, and is not this function's business.
        let m = StabilityModel::with_config(HazardConfig::default(), 300, now());
        let v = priced_at(&m, AGE, Consequence::Absolute, TrustLevel::Unverified, 50.0);
        assert!(v.is_finite() && v > 0.0);
        assert_eq!(class_weight(Consequence::Absolute), ABSOLUTE_WEIGHT);
        assert!(class_weight(Consequence::Absolute) > class_weight(Consequence::Critical));
    }

    // ---------------------------------------------------------------- schedule

    fn class_of(consequence: Consequence) -> BehaviorClass {
        BehaviorClass {
            role: crate::behavior::role_code(consequence),
            change: 64,
            ttl: 72,
            volatility: 0,
            trust: 1,
            cost: 68,
        }
    }

    fn cand(id: usize, class: BehaviorClass, value: f64) -> Candidate<usize> {
        Candidate {
            payload: id,
            class,
            value,
            tie_break: id as u128,
        }
    }

    #[test]
    fn the_budget_is_never_exceeded_and_the_best_values_come_first() {
        let c = VoiConfig {
            reservation_per_class: 0,
            ..VoiConfig::default()
        };
        let cands = alloc::vec![
            cand(0, class_of(Consequence::Low), 1.0),
            cand(1, class_of(Consequence::Low), 9.0),
            cand(2, class_of(Consequence::Low), 5.0),
            cand(3, class_of(Consequence::Low), 7.0),
            cand(4, class_of(Consequence::Low), 3.0),
        ];
        let got = schedule(cands, 3, &c);
        assert_eq!(
            got,
            alloc::vec![1, 3, 2],
            "the top three by value, in order"
        );
    }

    #[test]
    fn a_candidate_at_or_below_the_threshold_is_never_scheduled() {
        let c = VoiConfig {
            min_value: 4.0,
            reservation_per_class: 0,
            ..VoiConfig::default()
        };
        let cands = alloc::vec![
            cand(0, class_of(Consequence::Low), 4.0),
            cand(1, class_of(Consequence::Low), 4.0001),
            cand(2, class_of(Consequence::Low), 100.0),
        ];
        assert_eq!(schedule(cands, 10, &c), alloc::vec![2, 1]);
    }

    #[test]
    fn the_reservation_gives_every_class_a_slot_before_the_global_fill() {
        // Class A holds the four best values; class B's best is fifth. Without
        // the reservation, a budget of four would starve B completely — and a
        // starved entry decays, widens its bound, and loses its ability to be
        // served stale at all, which is why this is not merely a fairness
        // preference.
        let a = class_of(Consequence::Low);
        let b = class_of(Consequence::Critical);
        let cands = alloc::vec![
            cand(0, a, 10.0),
            cand(1, a, 9.0),
            cand(2, a, 8.0),
            cand(3, a, 7.0),
            cand(4, b, 1.0),
            cand(5, b, 0.5),
        ];
        let with = schedule(cands.clone(), 4, &VoiConfig::default());
        assert!(with.contains(&4), "class B must be represented: {with:?}");
        // The guarantee is per class and bounded by the budget: with the
        // reservation on, exactly one slot per class is reserved.
        let b_count = with.iter().filter(|&&i| i == 4 || i == 5).count();
        assert_eq!(b_count, 1);
        // And with the reservation off, the same budget starves B.
        let without = schedule(
            cands,
            4,
            &VoiConfig {
                reservation_per_class: 0,
                ..VoiConfig::default()
            },
        );
        assert_eq!(without, alloc::vec![0, 1, 2, 3]);
    }

    #[test]
    fn every_class_present_is_reserved_when_the_budget_allows() {
        let classes: Vec<BehaviorClass> = [
            Consequence::Low,
            Consequence::Medium,
            Consequence::High,
            Consequence::Critical,
        ]
        .iter()
        .map(|&c| class_of(c))
        .collect();
        let mut cands = Vec::new();
        let mut id = 0usize;
        for (ci, class) in classes.iter().enumerate() {
            for k in 0..3 {
                // Class 3 holds the three best values overall.
                let value = 100.0 - (ci as f64) * 10.0 - (k as f64);
                cands.push(cand(id, *class, value));
                id += 1;
            }
        }
        let got = schedule(cands, 8, &VoiConfig::default());
        for (ci, class) in classes.iter().enumerate() {
            let base = ci * 3;
            let present = got
                .iter()
                .filter(|&&i| (base..base + 3).contains(&i))
                .count();
            assert!(
                present >= 1,
                "class {ci} ({class:?}) got {present} slots: {got:?}"
            );
        }
        assert_eq!(got.len(), 8);
    }

    #[test]
    fn value_ties_are_broken_by_the_fingerprint_and_not_by_input_order() {
        // Equal values are the normal case at the top of a tick: entries that
        // were all written at the same instant have identical models. Ordering
        // them by input position is ordering them by the query stream, which is
        // the same order on every resolver in a fleet and therefore predictable
        // to an observer — exactly what the fingerprint exists to prevent.
        let class = class_of(Consequence::Low);
        let mut a: Vec<Candidate<usize>> = (0..8)
            .map(|i| Candidate {
                payload: i,
                class,
                value: 5.0,
                tie_break: (7 - i) as u128,
            })
            .collect();
        let mut b = a.clone();
        // Reverse the input order. The output must not change.
        b.reverse();
        let got_a = schedule(core::mem::take(&mut a), 8, &VoiConfig::default());
        let got_b = schedule(b, 8, &VoiConfig::default());
        assert_eq!(got_a, got_b, "the order must be a function of the values");
        assert_eq!(got_a, alloc::vec![7, 6, 5, 4, 3, 2, 1, 0]);
    }

    #[test]
    fn a_fleet_with_different_secrets_orders_ties_differently() {
        let class = class_of(Consequence::Low);
        let mk = |salt: u128| -> Vec<Candidate<usize>> {
            (0..32)
                .map(|i| Candidate {
                    payload: i,
                    class,
                    value: 5.0,
                    tie_break: (i as u128) ^ salt,
                })
                .collect()
        };
        let a = schedule(mk(0), 32, &VoiConfig::default());
        let b = schedule(mk(0x5555_5555), 32, &VoiConfig::default());
        assert_ne!(a, b, "a different secret must not reproduce the same order");
        let mut sorted_a = a.clone();
        let mut sorted_b = b.clone();
        sorted_a.sort_unstable();
        sorted_b.sort_unstable();
        assert_eq!(sorted_a, sorted_b, "only the order may differ");
    }

    #[test]
    fn an_empty_or_useless_candidate_set_schedules_nothing() {
        assert!(schedule::<usize>(Vec::new(), 4, &VoiConfig::default()).is_empty());
        assert!(schedule(
            alloc::vec![cand(0, class_of(Consequence::Low), 1.0)],
            0,
            &VoiConfig::default()
        )
        .is_empty());
        // Non-finite values are dropped rather than sorted unpredictably.
        let nan = Candidate {
            payload: 0usize,
            class: class_of(Consequence::Low),
            value: f64::NAN,
            tie_break: 0,
        };
        let inf = Candidate {
            payload: 1usize,
            class: class_of(Consequence::Low),
            value: f64::INFINITY,
            tie_break: 1,
        };
        assert!(schedule(alloc::vec![nan, inf], 4, &VoiConfig::default()).is_empty());
    }

    #[test]
    fn a_budget_larger_than_the_candidate_set_returns_everything_once() {
        let cands = alloc::vec![
            cand(0, class_of(Consequence::Low), 3.0),
            cand(1, class_of(Consequence::Critical), 1.0),
            cand(2, class_of(Consequence::High), 2.0),
        ];
        let mut got = schedule(cands, 100, &VoiConfig::default());
        got.sort_unstable();
        assert_eq!(got, alloc::vec![0, 1, 2]);
    }

    #[test]
    fn a_degenerate_config_still_produces_a_valid_schedule() {
        let c = VoiConfig {
            horizon_secs: f64::NAN,
            ttl_secs: 0,
            tail_probability: -1.0,
            observation_weight: f64::INFINITY,
            min_value: f64::NAN,
            reservation_per_class: usize::MAX,
        };
        let cands = alloc::vec![
            cand(0, class_of(Consequence::Low), 1.0),
            cand(1, class_of(Consequence::High), 2.0),
        ];
        let got = schedule(cands, 2, &c);
        assert_eq!(got, alloc::vec![1, 0]);
    }
}
