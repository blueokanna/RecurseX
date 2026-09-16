//! The Query State Estimator — the "PARR" brain.
//!
//! DNS queries are not independent events. They arrive with time-of-day
//! structure, short-term recency bursts, and long-run popularity. This
//! module keeps a compact per-zone model of those signals and answers the
//! two questions the resolution planner actually needs:
//!
//! * `P(a query for this zone within the next `Δt` seconds)`
//! * the zone's normalized popularity (for cache admission)
//! * the zone's observed upstream cost (for admission and transport choice)
//!
//! The model is deliberately bounded: state is aggregated per apex (the
//! right-most two labels), and the number of tracked zones is capped, so
//! hostile or enormous query streams cannot grow memory without bound.

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use core::fmt;

use crate::name::Name;
use crate::time::Ts;

/// `e^x` for `x ≤ 0`, computed without `libm`.
///
/// `core` has no transcendental functions (they live in `std`/`libm`), and
/// the allowed dependency set does not include `libm`, so the estimator
/// carries its own `exp`. The argument here is always `-λ·Δt ≤ 0`, so we
/// use the standard decomposition `e^x = 2^(x·log₂e)` with a Taylor
/// expansion of `2^f` on `f ∈ [-0.5, 0.5]` and an exponent-field shift for
/// the `2^n` part — no allocations, no unsafe, ~1e-11 relative error.
/// Round half away from zero (IEEE-754 `round`), via bit arithmetic —
/// `core` does not provide `f64::round` (it needs `libm`).
fn round_f64(y: f64) -> f64 {
    let bits = y.to_bits();
    // Biased exponent, then unbiased.
    let biased = ((bits >> 52) & 0x7ff) as i32;
    let exp = biased - 1023;
    if exp >= 52 {
        // Integral (or infinite/NaN); nothing to round.
        return y;
    }
    let sign = bits >> 63;
    if exp < 0 {
        // |y| < 1: round to ±1 when |y| ≥ 0.5, else ±0.
        let abs = bits & 0x7fff_ffff_ffff_ffff;
        if abs >= 0x3fe0_0000_0000_0000 {
            if sign == 1 {
                -1.0
            } else {
                1.0
            }
        } else if sign == 1 {
            -0.0
        } else {
            0.0
        }
    } else {
        // 0 ≤ exp < 52: the low (52 − exp) bits are the fraction.
        let frac_bits = 52 - exp as u32;
        let frac_mask = (1u64 << frac_bits) - 1;
        let frac = bits & frac_mask;
        let half = 1u64 << (frac_bits - 1);
        if frac >= half {
            // Round the magnitude up (away from zero); carries into the
            // exponent naturally (e.g. 1.5 → 2.0).
            let up = (bits & !frac_mask) + (1u64 << frac_bits);
            f64::from_bits(up)
        } else {
            f64::from_bits(bits & !frac_mask)
        }
    }
}

fn exp_nonpos(x: f64) -> f64 {
    debug_assert!(x <= 0.0);
    if x <= -745.0 {
        return 0.0;
    }
    let y = x * core::f64::consts::LOG2_E;
    let n = round_f64(y);
    let t = (y - n) * core::f64::consts::LN_2; // |t| ≤ 0.35
                                               // exp(t) = Σ t^i / i! (10 terms ⇒ rel. err < 1e-11 on |t| ≤ 0.35).
    let mut p = 1.0;
    let mut term = 1.0;
    let mut i = 1.0;
    while i <= 9.0 {
        term *= t / i;
        p += term;
        i += 1.0;
    }
    // Multiply by 2^n by nudging the exponent field (works for p ∈ [0.5,2)).
    let bits = (p.to_bits() as i64).wrapping_add((n as i64) << 52);
    f64::from_bits(bits as u64)
}

/// Number of time-of-day buckets (96 × 15 min = one day).
pub const TOD_BUCKETS: usize = 96;
/// Seconds per time-of-day bucket.
pub const BUCKET_SECS: u32 = 900;
/// Nanoseconds per day.
const NS_PER_DAY: Ts = 86_400 * 1_000_000_000;
/// Short-term recency window (seconds).
pub const RECENT_WINDOW_SECS: Ts = 300 * 1_000_000_000;
/// Ring size of recent query timestamps.
pub const RECENT_MAX: usize = 64;
/// Reference query rate (queries/sec) that maps to popularity 1.0.
pub const POPULARITY_REF_RATE: f64 = 10.0;
/// Default number of tracked zones.
pub const DEFAULT_MAX_DOMAINS: usize = 100_000;
/// Zones idle for longer than this are dropped first when the table is
/// full. Half an hour is deliberate: every horizon the planner and the
/// prefetcher evaluate is a minute at most, so a demand history older than
/// that cannot change a decision and costs memory for nothing. Zones are
/// also forgotten across a table sweep.
pub const ZONE_RETENTION_SECS: Ts = 30 * 60;
/// Eviction stride used when the table is full of *fresh* zones (hostile
/// distinct-zone load). See [`crate::bounded::evict_for_capacity`].
pub const EVICT_STRIDE: usize = 8;

/// Per-zone query statistics.
#[derive(Clone, Debug)]
pub struct DomainStats {
    /// Total queries observed.
    pub queries: u64,
    /// First observation.
    pub first_seen: Ts,
    /// Last query time.
    pub last_seen: Ts,
    /// EWMA query rate (queries/sec).
    pub ewma_rate: f64,
    /// Recent query timestamps (for window-rate estimation).
    pub recent: VecDeque<Ts>,
    /// Per-time-of-day-bucket query counts (demand profile).
    pub tod: [u32; TOD_BUCKETS],
    /// Total failures observed.
    pub failures: u64,
    /// EWMA failure rate `0..1`.
    pub failure_rate: f64,
    /// EWMA upstream round-trip cost (ms).
    pub upstream_ewma_ms: f64,
    /// Number of upstream observations.
    pub upstream_samples: u64,
}

impl DomainStats {
    fn new(now: Ts) -> Self {
        let mut tod = [0u32; TOD_BUCKETS];
        tod[tod_bucket(now)] = 1;
        let mut recent = VecDeque::with_capacity(RECENT_MAX);
        recent.push_back(now);
        Self {
            queries: 1,
            first_seen: now,
            last_seen: now,
            ewma_rate: 0.0,
            recent,
            tod,
            failures: 0,
            failure_rate: 0.0,
            upstream_ewma_ms: 0.0,
            upstream_samples: 0,
        }
    }

    /// Record a query.
    pub fn record_query(&mut self, now: Ts) {
        // The gap to the previous query *is* the instantaneous rate the
        // EWMA is built from, so read `last_seen` before advancing it.
        let gap_ns = now.saturating_sub(self.last_seen);
        self.queries += 1;
        self.last_seen = now;
        self.tod[tod_bucket(now)] = self.tod[tod_bucket(now)].saturating_add(1);
        self.recent.push_back(now);
        while self.recent.len() > RECENT_MAX {
            self.recent.pop_front();
        }
        // EWMA of the instantaneous rate: exponential-decayed inter-arrival
        // estimate. α = 0.1 gives a ~10-event time constant.
        let inst_rate = if gap_ns == 0 {
            0.0
        } else {
            1_000_000_000.0 / gap_ns as f64
        };
        let alpha = 0.1;
        self.ewma_rate = self.ewma_rate * (1.0 - alpha) + inst_rate * alpha;
    }

    /// Record an upstream failure for this zone.
    pub fn record_failure(&mut self) {
        self.failures += 1;
        // EWMA failure rate toward 1.
        self.failure_rate = self.failure_rate * 0.9 + 1.0 * 0.1;
    }

    /// Record a successful upstream exchange and its RTT.
    pub fn record_upstream(&mut self, rtt_ms: f64) {
        self.upstream_samples += 1;
        if self.upstream_samples == 1 {
            self.upstream_ewma_ms = rtt_ms;
        } else {
            self.upstream_ewma_ms = self.upstream_ewma_ms * 0.9 + rtt_ms * 0.1;
        }
    }

    /// The query rate over the recent window (queries/sec).
    pub fn window_rate(&self, now: Ts) -> f64 {
        let cutoff = now.saturating_sub(RECENT_WINDOW_SECS);
        let count = self.recent.iter().filter(|&&t| t >= cutoff).count() as f64;
        count / (RECENT_WINDOW_SECS as f64 / 1_000_000_000.0)
    }

    /// The expected number of queries in the next `horizon_secs`, from the
    /// time-of-day demand profile (Poisson rate assumption).
    pub fn expected_tod_queries(&self, now: Ts, horizon_secs: u32) -> f64 {
        let days = ((now.saturating_sub(self.first_seen)) / NS_PER_DAY).max(1) as f64;
        let mut expected = 0.0;
        let mut pos = now;
        let end = now.saturating_add(horizon_secs as Ts * 1_000_000_000);
        let mut guard = 0u32;
        while pos < end && guard < 512 {
            let bucket = tod_bucket(pos);
            let bucket_start =
                (pos / (BUCKET_SECS as Ts * 1_000_000_000)) * (BUCKET_SECS as Ts * 1_000_000_000);
            let bucket_end = bucket_start + BUCKET_SECS as Ts * 1_000_000_000;
            let seg_end = end.min(bucket_end);
            let frac = (seg_end - pos) as f64 / (BUCKET_SECS as Ts * 1_000_000_000) as f64;
            expected += self.tod[bucket] as f64 * frac;
            pos = seg_end;
            guard += 1;
        }
        expected / days
    }

    /// `P(a query for this zone within the next `horizon_secs`)`.
    ///
    /// Combines the time-of-day profile with a short-term recency boost:
    /// if the zone was queried moments ago, the short-term rate dominates.
    pub fn query_probability(&self, now: Ts, horizon_secs: u32) -> f64 {
        let p_tod = 1.0 - exp_nonpos(-self.expected_tod_queries(now, horizon_secs));
        // Recency boost: within the recent window the EWMA rate applies.
        let recent = now.saturating_sub(self.last_seen) < RECENT_WINDOW_SECS;
        let p_recency = if recent {
            1.0 - exp_nonpos(-self.ewma_rate * horizon_secs as f64)
        } else {
            0.0
        };
        p_tod.max(p_recency).clamp(0.0, 1.0)
    }

    /// Normalized popularity `0..1` (for cache admission).
    pub fn popularity(&self, now: Ts) -> f64 {
        let rate = self.ewma_rate.max(self.window_rate(now));
        (rate / POPULARITY_REF_RATE).clamp(0.0, 1.0)
    }

    /// The observed upstream cost estimate in ms (for admission).
    pub fn est_cost_ms(&self) -> f64 {
        if self.upstream_samples == 0 {
            50.0
        } else {
            self.upstream_ewma_ms
        }
    }
}

fn tod_bucket(now: Ts) -> usize {
    let secs_of_day = ((now / 1_000_000_000) % 86_400) as u32;
    ((secs_of_day / BUCKET_SECS) as usize).min(TOD_BUCKETS - 1)
}

/// The bounded per-zone query estimator.
pub struct QueryEstimator {
    domains: BTreeMap<Name, DomainStats>,
    max_domains: usize,
}

impl Default for QueryEstimator {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_DOMAINS)
    }
}

impl QueryEstimator {
    /// A new estimator tracking up to `max_domains` zones.
    pub fn new(max_domains: usize) -> Self {
        Self {
            domains: BTreeMap::new(),
            max_domains: max_domains.max(1),
        }
    }

    /// Observe a query for a name (aggregated at the apex).
    ///
    /// A new zone arriving while the table is at capacity triggers an
    /// amortised sweep ([`crate::bounded::evict_for_capacity`]) instead of
    /// an O(n) scan per query.
    pub fn observe_query(&mut self, name: &Name, now: Ts) {
        let apex = name.apex();
        if let Some(s) = self.domains.get_mut(&apex) {
            s.record_query(now);
        } else {
            if self.domains.len() >= self.max_domains {
                let stale_before = now.saturating_sub(ZONE_RETENTION_SECS * 1_000_000_000);
                crate::bounded::evict_for_capacity(
                    &mut self.domains,
                    stale_before,
                    EVICT_STRIDE,
                    |s| s.last_seen,
                );
            }
            self.domains.insert(apex, DomainStats::new(now));
        }
    }

    /// Observe an upstream failure for the zone.
    pub fn observe_failure(&mut self, name: &Name) {
        let apex = name.apex();
        if let Some(s) = self.domains.get_mut(&apex) {
            s.record_failure();
        }
    }

    /// Observe an upstream exchange and its RTT for the zone.
    pub fn observe_upstream(&mut self, name: &Name, rtt_ms: f64) {
        let apex = name.apex();
        if let Some(s) = self.domains.get_mut(&apex) {
            s.record_upstream(rtt_ms);
        }
    }

    /// Per-zone statistics, if tracked.
    pub fn stats(&self, name: &Name) -> Option<&DomainStats> {
        self.domains.get(&name.apex())
    }

    /// `P(a query for this zone within the next `horizon_secs`)`, given the
    /// current wall time.
    pub fn probability(&self, name: &Name, now: Ts, horizon_secs: u32) -> f64 {
        match self.domains.get(&name.apex()) {
            Some(s) => s.query_probability(now, horizon_secs),
            None => 0.0,
        }
    }

    /// Normalized popularity `0..1`, given the current wall time.
    pub fn popularity(&self, name: &Name, now: Ts) -> f64 {
        match self.domains.get(&name.apex()) {
            Some(s) => s.popularity(now),
            None => 0.0,
        }
    }

    /// The observed upstream cost in ms for the zone.
    pub fn est_cost_ms(&self, name: &Name) -> f64 {
        match self.domains.get(&name.apex()) {
            Some(s) => s.est_cost_ms(),
            None => 50.0,
        }
    }

    /// Build admission inputs for a cache insert.
    pub fn score_inputs(&self, name: &Name, now: Ts) -> crate::cache::score::ScoreInputs {
        crate::cache::score::ScoreInputs {
            popularity: self.popularity(name, now),
            est_cost_ms: self.est_cost_ms(name),
        }
    }

    /// The number of tracked zones.
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    /// Whether the estimator is empty.
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Iterate over tracked zones.
    pub fn iter(&self) -> impl Iterator<Item = (&Name, &DomainStats)> {
        self.domains.iter()
    }
}

impl fmt::Debug for QueryEstimator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QueryEstimator(zones={})", self.domains.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::format;

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    #[test]
    fn probability_grows_with_demand() {
        let mut est = QueryEstimator::new(100);
        let name = Name::from_ascii("www.example.com").unwrap();
        // One query now.
        est.observe_query(&name, now());
        let p1 = est.probability(&name, now(), 60);
        // A burst of queries over a minute → much higher short-term P.
        for i in 1..60 {
            est.observe_query(&name, now() + i as Ts * 1_000_000_000);
        }
        let p2 = est.probability(&name, now() + 60 as Ts * 1_000_000_000, 60);
        assert!(p2 > p1, "{p2} should exceed {p1}");
    }

    #[test]
    fn popularity_reflects_rate() {
        let mut est = QueryEstimator::new(100);
        let name = Name::from_ascii("example.com").unwrap();
        for i in 0..50 {
            est.observe_query(&name, now() + i as Ts * 50_000_000); // 20 qps
        }
        let pop = est.popularity(&name, now() + 50 as Ts * 50_000_000);
        assert!(pop > 0.0);
        // Aggregation by apex: a subdomain maps to the same stats.
        let sub = Name::from_ascii("a.b.example.com").unwrap();
        assert_eq!(sub.apex(), name.apex());
    }

    #[test]
    fn bounded_memory() {
        let mut est = QueryEstimator::new(10);
        for i in 0..50 {
            est.observe_query(
                &Name::from_ascii(&format!("zone{i}.com")).unwrap(),
                now() + i as Ts,
            );
        }
        assert!(est.len() <= 10);
    }

    #[test]
    fn tod_profile_gives_daily_shape() {
        let mut est = QueryEstimator::new(100);
        let name = Name::from_ascii("example.com").unwrap();
        // Simulate 3 days of queries at a fixed time of day.
        let day = 86_400 as Ts * 1_000_000_000;
        let anchor = now();
        for d in 0..3i64 {
            for _ in 0..10 {
                est.observe_query(
                    &name,
                    anchor + d as Ts * day + 12 * 3_600 as Ts * 1_000_000_000,
                );
            }
        }
        // Probability in the next hour around that time should be material.
        let t = anchor + 12 * 3_600 as Ts * 1_000_000_000;
        let p = est.stats(&name).unwrap().query_probability(t, 3600);
        assert!(p > 0.3, "p={p}");
    }

    #[test]
    fn exp_matches_reference() {
        // Reference values computed independently (Python math.exp).
        let cases: &[(f64, f64)] = &[
            (0.0, 1.0),
            (-0.0, 1.0),
            (-0.5, 0.6065306597126334),
            (-1.0, 0.36787944117144233),
            (-2.0, 0.1353352832366127),
            (-5.0, 0.006737946999085467),
            (-10.0, 4.539_992_976_248_485_4e-5),
            (-20.0, 2.061_153_622_438_558e-9),
            (-50.0, 1.9287498479639178e-22),
            (-100.0, 3.720075976020836e-44),
            (-200.0, 1.3838965267367376e-87),
            (-700.0, 9.85967654375977e-305),
        ];
        for (x, want) in cases {
            let got = exp_nonpos(*x);
            let rel = (got - want).abs() / want.abs().max(f64::MIN_POSITIVE);
            assert!(
                rel < 1e-9,
                "exp_nonpos({x}) = {got:e}, want {want:e}, rel {rel:e}"
            );
        }
        // Underflow to zero.
        assert_eq!(exp_nonpos(-800.0), 0.0);
        // The probability path stays in [0, 1].
        for x in [0.0, -1e-9, -0.1, -3.0, -40.0, -745.0] {
            let p = 1.0 - exp_nonpos(x);
            assert!((0.0..=1.0).contains(&p), "p={p} for x={x}");
        }
    }

    #[test]
    fn round_matches_reference() {
        // Rust's `round` is half-away-from-zero; these are the exact
        // half-away-from-zero results.
        let cases: &[(f64, f64)] = &[
            (0.0, 0.0),
            (0.49, 0.0),
            (0.5, 1.0),
            (0.51, 1.0),
            (1.5, 2.0),
            (2.5, 3.0),
            (-0.49, -0.0),
            (-0.5, -1.0),
            (-1.5, -2.0),
            (123.456, 123.0),
            (-123.456, -123.0),
            (1e10, 1e10),
            (1e20, 1e20),
        ];
        for (x, want) in cases {
            let got = round_f64(*x);
            assert!(
                (got - want).abs() <= f64::EPSILON.max(got.abs() * 1e-15),
                "round({x}) = {got}, want {want}"
            );
        }
    }
}
