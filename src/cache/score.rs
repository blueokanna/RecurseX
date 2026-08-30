//! Cache admission scoring.
//!
//! A cache that admits everything is a cache that thrashes. RecurseX scores
//! every candidate entry and admits it to the tier its score earns:
//!
//! ```text
//! CacheScore =
//!     α × popularity        — estimated query rate for the zone
//!   + β × temporal locality  — how recently (and how often) it was served
//!   + γ × stability          — the observed stability model score
//!   + δ × TTL                — longer-lived entries amortize better
//!   + ε × resolution cost    — expensive-to-resolve data is worth keeping
//!   − ζ × memory cost        — large entries cost more to keep hot
//! ```
//!
//! All terms are normalized to `0..1` so the weights are comparable. The
//! score is recomputed on every serve and drives both admission and
//! eviction (a victim is the lowest-scored entry in a tier).

use crate::stability::StabilityModel;
use crate::time::Ts;

/// Reference value for the popularity signal (estimator output is already 0..1).
pub const POPULARITY_REF: f64 = 1.0;
/// Reference recency window in seconds (5 minutes counts as "fully local").
pub const LOCALITY_WINDOW_SECS: f64 = 300.0;
/// Reference TTL in seconds (an hour of TTL is "full value").
pub const TTL_REF_SECS: f64 = 3600.0;
/// Reference resolution cost in milliseconds (500 ms is "full cost").
pub const COST_REF_MS: f64 = 500.0;
/// Reference entry size in bytes (4 KiB is "full cost").
pub const MEM_REF_BYTES: f64 = 4096.0;

/// The linear weights of the admission score.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScoreWeights {
    /// α — popularity weight.
    pub popularity: f64,
    /// β — temporal locality weight.
    pub locality: f64,
    /// γ — stability weight.
    pub stability: f64,
    /// δ — TTL weight.
    pub ttl: f64,
    /// ε — resolution-cost weight.
    pub cost: f64,
    /// ζ — memory-cost weight (subtracted).
    pub memory: f64,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            popularity: 0.30,
            locality: 0.18,
            stability: 0.20,
            ttl: 0.16,
            cost: 0.11,
            memory: 0.05,
        }
    }
}

/// The external signals the admission policy needs from the estimator /
/// upstream model. The cache stays decoupled from those modules.
#[derive(Clone, Copy, Debug)]
pub struct ScoreInputs {
    /// Normalized popularity `0..1` (estimated query rate for the zone).
    pub popularity: f64,
    /// Estimated resolution cost for this entry in milliseconds.
    pub est_cost_ms: f64,
}

impl Default for ScoreInputs {
    fn default() -> Self {
        Self {
            popularity: 0.5,
            est_cost_ms: 50.0,
        }
    }
}

/// Compute the admission score of an entry.
///
/// * `weights` — the linear weights.
/// * `ttl_secs` — the entry's TTL in seconds.
/// * `now` — current wall time.
/// * `last_served` — when the entry was last served.
/// * `stability` — the stability model.
/// * `inputs` — external signals.
pub fn compute(
    weights: &ScoreWeights,
    ttl_secs: u32,
    now: Ts,
    last_served: Ts,
    stability: &StabilityModel,
    inputs: &ScoreInputs,
) -> f64 {
    let age_secs = now.saturating_sub(last_served) as f64 / 1_000_000_000.0;
    let locality = (1.0 - (age_secs / LOCALITY_WINDOW_SECS).min(1.0)).max(0.0);

    let pop = inputs.popularity.clamp(0.0, 1.0);
    let stab = stability.score().clamp(0.0, 1.0);
    let ttl = (ttl_secs as f64 / TTL_REF_SECS).clamp(0.0, 1.0);
    let cost = (inputs.est_cost_ms / COST_REF_MS).clamp(0.0, 1.0);
    // Memory term grows with the RRset size.
    let mem = (0.0f64).min(1.0); // populated by the caller via entry size below

    let raw = weights.popularity * pop
        + weights.locality * locality
        + weights.stability * stab
        + weights.ttl * ttl
        + weights.cost * cost
        - weights.memory * mem;

    raw.clamp(0.0, 1.0)
}

/// The memory term for an entry of `bytes` size.
pub fn memory_term(bytes: usize) -> f64 {
    (bytes as f64 / MEM_REF_BYTES).clamp(0.0, 1.0)
}

/// A full score including the memory term (call this in the cache).
pub fn compute_full(
    weights: &ScoreWeights,
    ttl_secs: u32,
    now: Ts,
    last_served: Ts,
    stability: &StabilityModel,
    inputs: &ScoreInputs,
    entry_bytes: usize,
) -> f64 {
    let mut s = compute(weights, ttl_secs, now, last_served, stability, inputs);
    s -= weights.memory * memory_term(entry_bytes);
    s.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    #[test]
    fn hot_entry_scores_higher() {
        let weights = ScoreWeights::default();
        let stable = StabilityModel::new(now());
        // Popular, just served, long TTL.
        let hot = compute_full(
            &weights,
            3600,
            now(),
            now() - 1_000_000_000,
            &stable,
            &ScoreInputs {
                popularity: 1.0,
                est_cost_ms: 400.0,
            },
            512,
        );
        // Unpopular, never served, short TTL.
        let cold = compute_full(
            &weights,
            30,
            now(),
            now() - 3_600_000_000_000,
            &stable,
            &ScoreInputs {
                popularity: 0.01,
                est_cost_ms: 5.0,
            },
            8192,
        );
        assert!(hot > cold);
    }

    #[test]
    fn score_is_bounded() {
        let weights = ScoreWeights::default();
        let s = compute_full(
            &weights,
            u32::MAX,
            now(),
            now(),
            &StabilityModel::new(now()),
            &ScoreInputs::default(),
            0,
        );
        assert!((0.0..=1.0).contains(&s));
    }

    #[test]
    fn memory_term_grows() {
        assert!(memory_term(0) < memory_term(4096));
        assert!(memory_term(8192) <= 1.0);
    }
}
