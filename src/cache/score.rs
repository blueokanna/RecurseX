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

/// The memory term for an entry of `bytes` size.
pub fn memory_term(bytes: usize) -> f64 {
    (bytes as f64 / MEM_REF_BYTES).clamp(0.0, 1.0)
}

/// The admission score of one entry: the weighted sum of all six terms
/// (the memory term is subtracted), clamped to `0..1`.
///
/// This is the only scoring entry point — admission, re-scoring on a serve,
/// and eviction ranking all call it with the same arguments, so an entry's
/// tier and its position in the eviction order can never disagree.
pub fn score(
    weights: &ScoreWeights,
    ttl_secs: u32,
    now: Ts,
    last_served: Ts,
    stability: &StabilityModel,
    inputs: &ScoreInputs,
    entry_bytes: usize,
) -> f64 {
    let age_secs = now.saturating_sub(last_served) as f64 / 1_000_000_000.0;
    let locality = (1.0 - (age_secs / LOCALITY_WINDOW_SECS).min(1.0)).max(0.0);

    let pop = inputs.popularity.clamp(0.0, 1.0);
    let stab = stability.score().clamp(0.0, 1.0);
    let ttl = (ttl_secs as f64 / TTL_REF_SECS).clamp(0.0, 1.0);
    let cost = (inputs.est_cost_ms / COST_REF_MS).clamp(0.0, 1.0);

    let raw = weights.popularity * pop
        + weights.locality * locality
        + weights.stability * stab
        + weights.ttl * ttl
        + weights.cost * cost
        - weights.memory * memory_term(entry_bytes);
    raw.clamp(0.0, 1.0)
}

/// A monotone `f64 → u64` map used to key ordered (rank) indices on a score.
///
/// `0.0` maps to `0`, `1.0` maps to `u32::MAX`; two scores that differ by
/// less than 2⁻³² land on the same rank and are then ordered by their key,
/// which is all the eviction index needs (it must pick *a* lowest-scored
/// entry, and must never disagree with `f64` comparison on the ordering of
/// two scores that differ materially).
pub fn rank_of(score: f64) -> u64 {
    (score.clamp(0.0, 1.0) * u32::MAX as f64) as u64
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
        let hot = score(
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
        let cold = score(
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
        let s = score(
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

    /// The memory term must actually reduce the score: a 16 KiB entry is
    /// more expensive to keep than a 64-byte one, everything else equal.
    #[test]
    fn memory_term_lowers_the_score() {
        let weights = ScoreWeights::default();
        let inputs = ScoreInputs {
            popularity: 0.8,
            est_cost_ms: 120.0,
        };
        let stability = StabilityModel::new(now());
        let small = score(&weights, 300, now(), now(), &stability, &inputs, 64);
        let large = score(&weights, 300, now(), now(), &stability, &inputs, 65_536);
        assert!(large < small, "large = {large}, small = {small}");
        let expected = weights.memory * memory_term(65_536);
        assert!(expected > 0.0);
    }

    #[test]
    fn memory_term_grows() {
        assert!(memory_term(0) < memory_term(4096));
        assert!(memory_term(8192) <= 1.0);
    }

    /// Ranks are monotone in the score and bounded — the eviction index
    /// relies on both.
    #[test]
    fn rank_is_monotone() {
        assert_eq!(rank_of(0.0), 0);
        assert_eq!(rank_of(1.0), u32::MAX as u64);
        assert_eq!(rank_of(-1.0), 0);
        assert_eq!(rank_of(2.0), u32::MAX as u64);
        assert!(rank_of(0.2) < rank_of(0.8));
    }
}
