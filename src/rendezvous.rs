//! Deterministic weighted rendezvous selection.
//!
//! Given a set of interchangeable candidates and a subject — a query name, a
//! client, a job — this picks one, *without any shared state*, such that:
//!
//! 1. everybody who holds the same candidate list and the same key makes the
//!    same choice for the same subject (so no coordination is needed);
//! 2. the fraction of subjects that land on a candidate is exactly its weight
//!    divided by the total (so weights are honoured);
//! 3. removing one candidate moves *only* the subjects that had chosen it and
//!    leaves every other choice untouched (so a change is minimally
//!    disruptive); and
//! 4. an observer who does not hold the key cannot compute the choice.
//!
//! # Why the exponential race, and not a modulo
//!
//! The obvious construction — `hash(subject) % candidates.len()` — satisfies
//! (1) and even (2) for equal weights, and fails (3) completely: changing the
//! modulus reshuffles *every* subject, so a fleet rebalances everything to
//! accommodate one change. It also has no way to express weights, and a
//! weighted variant built on a running cumulative sum has the same
//! reshuffle-on-change defect.
//!
//! This module uses highest-random-weight instead. For each candidate `i` it
//! draws `U_i` uniform on `(0, 1]` from the keyed hash and scores
//!
//! ```text
//! s_i = −ln(U_i) / w_i
//! ```
//!
//! and selects the candidate with the smallest score. `−ln(U_i)` is
//! exponential with rate 1, so `−ln(U_i)/w_i` is exponential with rate `w_i`,
//! and the minimum of independent exponentials is attained by `i` with
//! probability `w_i / Σ w_j` — property (2) exactly, not approximately. The
//! `U_i` for the other candidates do not depend on which candidates are
//! present, so removing one leaves every other score unchanged; the new
//! minimum is the old minimum unless the removed candidate held it — property
//! (3) exactly.
//!
//! No `exp` is needed, only `ln`, because the comparison is on the score rather
//! than on the weight itself.
//!
//! # Related work, stated plainly
//!
//! Rendezvous (highest-random-weight) hashing is Thaler and Ravishankar's
//! 1998 construction, and weighted variants are standard in the
//! consistent-hashing literature. This module is not a new selection algorithm
//! and does not claim to be. What is specific to this crate is where it is
//! pointed: candidate weights derived from *measured* path behaviour rather
//! than from configuration, applied to a band of statistically
//! indistinguishable servers, with the key drawn from the deployment's secret
//! entropy so that the choice is not predictable from the wire. See
//! [`crate::upstream::UpstreamSelector::rank_with_affinity`].

use alloc::vec::Vec;
use core::fmt;

use crate::float;
use crate::prng::siphash24_128;

/// Domain-separation tag, so a rendezvous score can never coincide with a
/// behavioural fingerprint even if the same key were used for both.
const DOMAIN_TAG: &[u8; 12] = b"recursex:rdv";

/// `2^64` as an `f64`, the denominator that turns a 64-bit hash into a fraction.
const TWO64: f64 = 18446744073709551616.0;

/// A score meaning "this candidate is not eligible".
const INELIGIBLE: f64 = f64::INFINITY;

/// The secret behind every selection.
///
/// Same discipline as [`crate::behavior::FingerprintKey`]: no accessor returns
/// the words, `Debug` redacts, and the only constructors are an explicit one
/// for tests and [`RendezvousKey::random`] for a deployment.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RendezvousKey {
    k0: u64,
    k1: u64,
}

impl RendezvousKey {
    /// A key from two 64-bit words.
    pub const fn from_words(k0: u64, k1: u64) -> Self {
        Self { k0, k1 }
    }

    /// A fresh key from OS entropy.
    ///
    /// The unpredictability of the selection is a property of this key. An
    /// attacker who can compute the choice can aim a spoofing attempt at the
    /// one server we are about to use, so the key is not a nicety.
    #[cfg(feature = "std")]
    pub fn random() -> Self {
        let mut rng = crate::entropy::secure_random();
        use crate::prng::RandomSource;
        let k0 = rng.next_u64();
        let k1 = rng.next_u64();
        Self::from_words(k0, k1)
    }
    /// The uniform draw in `(0, 1]` for `candidate` under `subject`.
    ///
    /// The `+1` keeps the result away from 0, where `ln` would diverge; the
    /// `min(1.0)` covers the rounding of an `f64` conversion that can push the
    /// value a hair above 1 and make `−ln` a hair below 0.
    fn uniform(&self, subject: &[u8], candidate: u64) -> f64 {
        let mut buf: Vec<u8> = Vec::with_capacity(DOMAIN_TAG.len() + subject.len() + 8);
        buf.extend_from_slice(DOMAIN_TAG);
        buf.extend_from_slice(subject);
        buf.extend_from_slice(&candidate.to_le_bytes());
        let h = siphash24_128(self.k0, self.k1, &buf);
        let lo = u64::from_le_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]]);
        ((lo as f64 + 1.0) / TWO64).min(1.0)
    }

    /// The score for `candidate`: lower wins.
    ///
    /// `weight <= 0`, `NaN` and infinities all mean "do not use this
    /// candidate", which is the only reading of a zero weight that cannot
    /// silently send traffic somewhere the caller excluded.
    pub fn score(&self, subject: &[u8], candidate: u64, weight: f64) -> f64 {
        if !float::is_positive(weight) {
            return INELIGIBLE;
        }
        let u = self.uniform(subject, candidate);
        -float::ln(u) / weight
    }

    /// The winning candidate, or `None` when nothing is eligible.
    pub fn select(&self, subject: &[u8], candidates: &[u64]) -> Option<u64> {
        self.select_weighted(subject, candidates.iter().map(|&c| (c, 1.0)))
    }

    /// The winning candidate among weighted candidates.
    pub fn select_weighted<I>(&self, subject: &[u8], candidates: I) -> Option<u64>
    where
        I: IntoIterator<Item = (u64, f64)>,
    {
        let mut best: Option<(f64, u64)> = None;
        for (id, w) in candidates {
            let s = self.score(subject, id, w);
            // `>=` on the id, not on the score: two candidates can score
            // equally only through floating-point rounding, and breaking that
            // by id keeps the selection a function of its inputs rather than of
            // the order the caller happened to enumerate them in.
            let take = match best {
                None => true,
                Some((bs, bid)) => s < bs || (s == bs && id < bid),
            };
            if take {
                best = Some((s, id));
            }
        }
        match best {
            // An all-ineligible set has no winner; returning the first id would
            // be a lie the caller cannot detect.
            Some((s, id)) if s.is_finite() => Some(id),
            _ => None,
        }
    }

    /// All candidates, best first, as indices into `items`.
    ///
    /// Ties are broken by candidate id, so the order is total and reproducible.
    pub fn rank(&self, subject: &[u8], items: &[(u64, f64)]) -> Vec<usize> {
        let mut scored: Vec<(f64, u64, usize)> = Vec::with_capacity(items.len());
        for (idx, &(id, w)) in items.iter().enumerate() {
            scored.push((self.score(subject, id, w), id, idx));
        }
        scored.sort_by(|a, b| {
            a.0.partial_cmp(&b.0)
                .unwrap_or(core::cmp::Ordering::Equal)
                .then_with(|| a.1.cmp(&b.1))
        });
        scored.into_iter().map(|(_, _, i)| i).collect()
    }
}

impl fmt::Debug for RendezvousKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RendezvousKey(<redacted>)")
    }
}

/// The cost-based affinity policy: how much worse than the best a candidate may
/// be and still enter the lottery.
///
/// Two tolerances rather than one, because either alone is wrong. A purely
/// relative band collapses when the cheapest candidate is very fast — 10 % of
/// 1 ms is 100 µs, less than the resolution of the measurements, so the band
/// would contain one candidate and the lottery would never run. A purely
/// absolute band cannot tell "these two servers are 3 ms apart and
/// indistinguishable" from "these two servers are 3 ms apart and one is twice
/// the price", because at 500 ms the relative gap is negligible and at 3 ms it
/// is total. The pair — `max(pct · min, absolute)` — is the smaller of the two
/// mistakes.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct CostBand {
    /// Tolerance as a percentage of the cheapest candidate's cost.
    pub percent: f64,
    /// Absolute tolerance in milliseconds.
    pub absolute_ms: f64,
}

impl Default for CostBand {
    fn default() -> Self {
        Self {
            percent: 10.0,
            absolute_ms: 2.0,
        }
    }
}

impl CostBand {
    /// The highest cost still inside the band, given the cheapest.
    pub fn limit(&self, min_cost: f64) -> f64 {
        if !min_cost.is_finite() || min_cost < 0.0 {
            return f64::INFINITY;
        }
        let relative = if self.percent.is_finite() && self.percent > 0.0 {
            min_cost * self.percent / 100.0
        } else {
            0.0
        };
        let absolute = if self.absolute_ms.is_finite() && self.absolute_ms > 0.0 {
            self.absolute_ms
        } else {
            0.0
        };
        min_cost + relative.max(absolute)
    }

    /// Whether the band admits more than one of the given costs.
    ///
    /// Exposed so a caller can count how often the lottery actually ran rather
    /// than assume it did; a band that never admits a second candidate is a
    /// policy that silently does nothing.
    pub fn admits_more_than_one(&self, costs: &[f64]) -> bool {
        let Some(&min) = costs
            .iter()
            .filter(|c| c.is_finite())
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(core::cmp::Ordering::Equal))
        else {
            return false;
        };
        let limit = self.limit(min);
        costs
            .iter()
            .filter(|c| c.is_finite() && **c <= limit)
            .count()
            > 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: RendezvousKey =
        RendezvousKey::from_words(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210);

    fn subject(i: usize) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"host");
        v.extend_from_slice(&(i as u64).to_le_bytes());
        v
    }

    #[test]
    fn the_selection_is_a_pure_function_of_the_key_and_subject() {
        let c = [1u64, 2, 3, 4, 5];
        for i in 0..64 {
            let s = subject(i);
            assert_eq!(KEY.select(&s, &c), KEY.select(&s, &c));
        }
        // And a second call site holding a copy of the key agrees, which is the
        // "no shared state" property: there is nothing to synchronise.
        let key2 = RendezvousKey::from_words(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210);
        for i in 0..64 {
            let s = subject(i);
            assert_eq!(KEY.select(&s, &c), key2.select(&s, &c));
        }
    }

    #[test]
    fn every_candidate_gets_roughly_its_share() {
        // Property (2), measured. 1:2:3 over 60 000 subjects; the tolerance is
        // wide enough to be a real test of the construction and narrow enough
        // that a modulo-based or unweighted scheme fails it outright.
        let weights = [(10u64, 1.0), (20, 2.0), (30, 3.0)];
        let mut counts = [0u64; 3];
        const N: usize = 60_000;
        for i in 0..N {
            let s = subject(i);
            let winner = KEY.select_weighted(&s, weights.iter().copied()).unwrap();
            for (idx, &(id, _)) in weights.iter().enumerate() {
                if id == winner {
                    counts[idx] += 1;
                }
            }
        }
        let total: u64 = counts.iter().sum();
        assert_eq!(total, N as u64);
        for (idx, expected) in [1.0f64 / 6.0, 2.0 / 6.0, 3.0 / 6.0].iter().enumerate() {
            let share = counts[idx] as f64 / total as f64;
            assert!(
                (share - expected).abs() < 0.02,
                "candidate {idx} took {share:.4}, expected about {expected:.4}"
            );
        }
    }

    #[test]
    fn equal_weights_are_balanced() {
        let c = [1u64, 2, 3, 4];
        let mut counts = [0u64; 4];
        const N: usize = 40_000;
        for i in 0..N {
            let s = subject(i);
            let w = KEY.select(&s, &c).unwrap();
            for (idx, &id) in c.iter().enumerate() {
                if id == w {
                    counts[idx] += 1;
                }
            }
        }
        for (idx, &count) in counts.iter().enumerate() {
            let share = count as f64 / N as f64;
            assert!(
                (share - 0.25).abs() < 0.02,
                "candidate {idx} took {share:.4}, expected about 0.25"
            );
        }
    }

    #[test]
    fn removing_a_candidate_moves_exactly_the_keys_it_owned() {
        // Property (3), asserted *exactly* rather than statistically. This is
        // the whole reason for highest-random-weight over a modulo: a change to
        // the candidate set must not be a fleet-wide reshuffle.
        let full = [1u64, 2, 3, 4, 5];
        let reduced = [1u64, 3, 4, 5]; // candidate 2 withdrawn
        const N: usize = 20_000;
        let mut owned_by_removed = 0u64;
        let mut moved = 0u64;
        for i in 0..N {
            let s = subject(i);
            let a = KEY.select(&s, &full).unwrap();
            let b = KEY.select(&s, &reduced).unwrap();
            if a == 2 {
                owned_by_removed += 1;
            }
            if a != b {
                moved += 1;
            }
            // Every key that moved had to have been on the removed candidate.
            if a != b {
                assert_eq!(a, 2, "key {i} moved off {a}, which is still present");
            }
        }
        assert_eq!(moved, owned_by_removed);
        // And the withdrawn candidate owned a real share, so the test is not
        // passing because nothing was ever removed.
        assert!(owned_by_removed > N as u64 / 10);
    }

    #[test]
    fn adding_a_candidate_moves_only_the_keys_it_takes() {
        let before = [1u64, 3, 4, 5];
        let after = [1u64, 2, 3, 4, 5]; // candidate 2 joins
        const N: usize = 20_000;
        let mut moved = 0u64;
        for i in 0..N {
            let s = subject(i);
            if KEY.select(&s, &before) != KEY.select(&s, &after) {
                moved += 1;
            }
        }
        let share = moved as f64 / N as f64;
        // Joining a five-way set should take about a fifth.
        assert!(
            (0.15..0.25).contains(&share),
            "joining took {share:.4} of the keys, expected about 0.2"
        );
    }

    #[test]
    fn the_subject_decides_within_a_fixed_candidate_set() {
        let c = [1u64, 2, 3, 4, 5];
        let mut seen = [false; 6];
        for i in 0..512 {
            let s = subject(i);
            seen[KEY.select(&s, &c).unwrap() as usize] = true;
        }
        assert!(
            seen.iter().skip(1).all(|&x| x),
            "one subject pattern must not pin every query to one server"
        );
    }

    #[test]
    fn the_key_is_what_makes_the_choice_unpredictable() {
        let c = [1u64, 2, 3, 4, 5];
        let other = RendezvousKey::from_words(9, 9);
        let mut differences = 0;
        for i in 0..512 {
            let s = subject(i);
            if KEY.select(&s, &c) != other.select(&s, &c) {
                differences += 1;
            }
        }
        assert!(
            differences > 200,
            "a different secret changed only {differences} of 512 choices"
        );
    }

    #[test]
    fn a_zero_or_degenerate_weight_is_never_selected() {
        let s = subject(7);
        let items = [(1u64, 0.0), (2, -1.0), (3, f64::NAN), (4, 9.0)];
        for _ in 0..3 {
            assert_eq!(KEY.select_weighted(&s, items.iter().copied()), Some(4));
        }
        assert_eq!(KEY.select_weighted(&s, [(1u64, 0.0)]), None);
        assert_eq!(KEY.select(&s, &[]), None);
    }

    #[test]
    fn an_infinite_weight_is_rejected_rather_than_treated_as_certainty() {
        // `1/0` in a caller's arithmetic must not become "always pick this".
        // Treating it as ineligible fails closed and leaves the other
        // candidates to compete.
        let s = subject(11);
        let winner = KEY.select_weighted(&s, [(1u64, f64::INFINITY), (2, 1.0)]);
        assert_eq!(winner, Some(2));
    }

    #[test]
    fn a_single_candidate_is_always_selected() {
        for i in 0..64 {
            let s = subject(i);
            assert_eq!(KEY.select(&s, &[42]), Some(42));
        }
    }

    #[test]
    fn ranking_is_a_total_order_over_the_candidates() {
        let items = [(1u64, 1.0), (2, 1.0), (3, 1.0), (4, 1.0)];
        let order = KEY.rank(&subject(3), &items);
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, alloc::vec![0, 1, 2, 3], "ranking lost a candidate");
        assert_eq!(order.len(), items.len());
        // The head of the ranking is the selection.
        let head = items.get(order[0]).map(|&(id, _)| id);
        assert_eq!(head, KEY.select(&subject(3), &[1, 2, 3, 4]));
    }

    #[test]
    fn the_band_admits_a_gap_larger_than_either_tolerance_alone() {
        // 1 ms apart at a 20 ms minimum: the relative term (2 ms) covers it,
        // and the absolute floor is not what decided.
        let band = CostBand::default();
        assert!(band.admits_more_than_one(&[20.0, 21.0]));
        // 0.4 ms apart at a 2 ms minimum: the relative term is 0.2 ms, so only
        // the absolute floor admits it. This is the case a purely relative
        // band gets wrong, and it is the common one — a set of anycast servers
        // within one region differ by fractions of a millisecond.
        assert!(band.admits_more_than_one(&[2.0, 2.4]));
        // 40 ms apart at a 20 ms minimum: outside both.
        assert!(!band.admits_more_than_one(&[20.0, 60.0]));
        // 3.5x apart at a 2 ms minimum: the absolute floor must not be read as
        // "anything goes when the base is small".
        assert!(!band.admits_more_than_one(&[2.0, 7.0]));
    }

    #[test]
    fn a_degenerate_band_never_excludes_everything() {
        let band = CostBand {
            percent: f64::NAN,
            absolute_ms: -1.0,
        };
        // Both tolerances are unusable, so the band is the single cheapest
        // candidate — a defensible reading, and crucially not one that
        // produces an empty set or a NaN limit.
        let limit = band.limit(10.0);
        assert_eq!(limit, 10.0);
        assert!(!band.admits_more_than_one(&[10.0, 11.0]));
        assert!(band.limit(f64::NAN).is_infinite());
        assert!(!band.admits_more_than_one(&[]));
    }

    #[test]
    fn the_debug_form_never_prints_the_key() {
        let s = alloc::format!("{:?}", RendezvousKey::from_words(0xaaaa, 0xbbbb));
        assert_eq!(s, "RendezvousKey(<redacted>)");
    }
}
