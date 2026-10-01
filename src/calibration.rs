//! Measurement: probability calibration and latency quantiles.
//!
//! # Why this module is not optional
//!
//! A threshold is only meaningful if the number it is compared against means
//! what it says. "Serve stale when `P(fresh) ≥ 0.95`" is a safety claim only
//! if, among all the decisions the resolver made when it *believed* 0.95,
//! about 95 % of them were in fact still correct. If the model's 0.95 is
//! really 0.7, the threshold is decoration.
//!
//! Two proper scoring rules make that checkable, and both are strictly
//! proper — they are minimised by the true probability, so they cannot be
//! gamed by a model that merely becomes more confident:
//!
//! * **Brier score** `mean((p − y)²)` — squared error, in `[0, 1]`.
//! * **Log loss** `mean(−[y·ln p + (1−y)·ln(1−p)])` — unbounded above, and
//!   it punishes confident errors far harder, which is the failure mode a
//!   stale-serving decision actually cares about.
//!
//! Alongside the scalars sits the **reliability table**: the predictions
//! binned by predicted value, with the observed frequency of each bin. A
//! well-calibrated model is the diagonal. A single aggregate number can hide
//! a model that is right on average and wrong everywhere it matters; the
//! table cannot, and the expected calibration error
//! ([`Calibration::expected_calibration_error`]) is its collapsed form.
//!
//! # What is *not* claimed
//!
//! These are estimators over a sample, and a sample of stale-serving
//! decisions is not i.i.d. — it is a sequence of decisions made by the very
//! policy being evaluated, on data whose distribution moves. The right use
//! of this module is pre-deployment calibration on a trace and continuous
//! production monitoring with the caveats stated in the report, not a
//! p-value. It reports; it does not conclude.

use core::fmt;

use crate::float::ln;

/// Number of reliability bins.
pub const RELIABILITY_BINS: usize = 10;

/// One row of the reliability table.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ReliabilityBin {
    /// Number of predictions in this bin.
    pub n: u64,
    /// Sum of the predicted probabilities.
    pub predicted_sum: f64,
    /// Number of outcomes that happened.
    pub observed: u64,
}

impl ReliabilityBin {
    /// Mean predicted probability in the bin, or `None` when empty.
    pub fn mean_predicted(&self) -> Option<f64> {
        if self.n == 0 {
            None
        } else {
            Some(self.predicted_sum / self.n as f64)
        }
    }

    /// Observed frequency in the bin, or `None` when empty.
    pub fn observed_frequency(&self) -> Option<f64> {
        if self.n == 0 {
            None
        } else {
            Some(self.observed as f64 / self.n as f64)
        }
    }

    /// The signed calibration gap (observed − predicted) for the bin.
    pub fn gap(&self) -> Option<f64> {
        match (self.mean_predicted(), self.observed_frequency()) {
            (Some(p), Some(o)) => Some(o - p),
            _ => None,
        }
    }
}

/// A streaming calibration monitor for one prediction source.
#[derive(Clone, Debug)]
pub struct Calibration {
    bins: [ReliabilityBin; RELIABILITY_BINS],
    n: u64,
    brier_sum: f64,
    logloss_sum: f64,
    /// Predictions clamped away from 0/1 purely for the log-loss term
    /// (identical values, different reasons — see [`Calibration::observe`]).
    clamped: u64,
}

impl Default for Calibration {
    fn default() -> Self {
        Self::new()
    }
}

impl Calibration {
    /// An empty monitor.
    pub fn new() -> Self {
        Self {
            bins: core::array::from_fn(|_| ReliabilityBin::default()),
            n: 0,
            brier_sum: 0.0,
            logloss_sum: 0.0,
            clamped: 0,
        }
    }

    /// Record one prediction and its outcome.
    ///
    /// `predicted` is the probability the model assigned to "the data was
    /// still correct"; `happened` is what was observed. A `NaN` prediction
    /// is recorded as `0.0` rather than skipped — a model that produces
    /// `NaN` must not be able to keep its score clean by having the sample
    /// discarded. Values outside `[0, 1]` are clamped.
    pub fn observe(&mut self, predicted: f64, happened: bool) {
        let p = if predicted.is_nan() {
            0.0
        } else {
            predicted.clamp(0.0, 1.0)
        };
        let y = if happened { 1.0 } else { 0.0 };
        let d = p - y;
        self.brier_sum += d * d;

        // Log loss needs `p ∈ (0, 1)`; a predicted 0 or 1 with the opposite
        // outcome is an infinite loss, which would poison every downstream
        // average. Clamping to a finite floor keeps the score informative;
        // the event is counted in `clamped` so the operator can see that the
        // clamp was reached, which is itself a defect report.
        let eps = 1e-12;
        let (pc, was_clamped) = if p <= eps {
            (eps, true)
        } else if p >= 1.0 - eps {
            (1.0 - eps, true)
        } else {
            (p, false)
        };
        if was_clamped {
            self.clamped = self.clamped.saturating_add(1);
        }
        self.logloss_sum += -((y * ln(pc)) + ((1.0 - y) * ln(1.0 - pc)));

        self.n = self.n.saturating_add(1);
        let idx = bin_index(p);
        if let Some(b) = self.bins.get_mut(idx) {
            b.n = b.n.saturating_add(1);
            b.predicted_sum += p;
            if happened {
                b.observed = b.observed.saturating_add(1);
            }
        }
    }

    /// The number of recorded predictions.
    pub fn samples(&self) -> u64 {
        self.n
    }

    /// Number of predictions that required clamping for the log-loss term.
    pub fn clamped(&self) -> u64 {
        self.clamped
    }

    /// The Brier score, or `None` with no samples. Lower is better;
    /// `0.25` is what a constant 0.5 predictor scores.
    pub fn brier(&self) -> Option<f64> {
        if self.n == 0 {
            None
        } else {
            Some(self.brier_sum / self.n as f64)
        }
    }

    /// The mean log loss, or `None` with no samples. Lower is better;
    /// `ln 2 ≈ 0.693` is what a constant 0.5 predictor scores.
    pub fn log_loss(&self) -> Option<f64> {
        if self.n == 0 {
            None
        } else {
            Some(self.logloss_sum / self.n as f64)
        }
    }

    /// The reliability table.
    pub fn bins(&self) -> &[ReliabilityBin] {
        &self.bins
    }

    /// Expected calibration error: the sample-weighted mean absolute gap
    /// between predicted and observed frequency across bins.
    ///
    /// A collapsed scalar, offered because it is the conventional summary;
    /// the table is the thing to read before believing it.
    pub fn expected_calibration_error(&self) -> Option<f64> {
        if self.n == 0 {
            return None;
        }
        let mut sum = 0.0;
        for b in &self.bins {
            if let Some(gap) = b.gap() {
                sum += crate::float::fabs(gap) * b.n as f64;
            }
        }
        Some(sum / self.n as f64)
    }

    /// Signed over/under-confidence: `mean(observed − predicted)`.
    ///
    /// Negative means the model is *over*-confident, which is the direction
    /// that makes a freshness threshold unsafe.
    pub fn bias(&self) -> Option<f64> {
        if self.n == 0 {
            return None;
        }
        let observed = self.bins.iter().map(|b| b.observed).sum::<u64>() as f64;
        let predicted = self.bins.iter().map(|b| b.predicted_sum).sum::<f64>();
        Some((observed - predicted) / self.n as f64)
    }
}

/// The bin a prediction falls in. `p = 1.0` lands in the last bin.
fn bin_index(p: f64) -> usize {
    let scaled = (p.clamp(0.0, 1.0) * RELIABILITY_BINS as f64) as usize;
    scaled.min(RELIABILITY_BINS - 1)
}

impl fmt::Display for Calibration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "calibration(n={} brier={:?} logloss={:?} ece={:?} bias={:?} clamped={})",
            self.n,
            self.brier(),
            self.log_loss(),
            self.expected_calibration_error(),
            self.bias(),
            self.clamped
        )
    }
}

/// Number of latency buckets (powers of two in microseconds, plus overflow).
pub const LATENCY_BUCKETS: usize = 24;

/// A fixed-size latency quantile digest.
///
/// Buckets are powers of two microseconds, so a reported quantile is the
/// *upper edge* of a bucket — a conservative interval, not a point
/// estimate, and that is stated rather than hidden. The alternative (an
/// exact sample list) is unbounded memory driven by the query stream, which
/// is exactly the kind of thing an attacker gets to choose.
#[derive(Clone, Debug)]
pub struct LatencyDigest {
    counts: [u64; LATENCY_BUCKETS],
    total: u64,
    sum_us: u64,
    min_us: u64,
    max_us: u64,
}

impl Default for LatencyDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl LatencyDigest {
    /// An empty digest.
    pub fn new() -> Self {
        Self {
            counts: [0; LATENCY_BUCKETS],
            total: 0,
            sum_us: 0,
            min_us: u64::MAX,
            max_us: 0,
        }
    }

    /// Record one observation, in microseconds.
    pub fn record(&mut self, micros: u64) {
        let idx = latency_bucket(micros);
        if let Some(c) = self.counts.get_mut(idx) {
            *c = c.saturating_add(1);
        }
        self.total = self.total.saturating_add(1);
        self.sum_us = self.sum_us.saturating_add(micros);
        self.min_us = self.min_us.min(micros);
        self.max_us = self.max_us.max(micros);
    }

    /// The number of observations.
    pub fn samples(&self) -> u64 {
        self.total
    }

    /// The arithmetic mean in microseconds, or `None` when empty.
    pub fn mean_us(&self) -> Option<f64> {
        if self.total == 0 {
            None
        } else {
            Some(self.sum_us as f64 / self.total as f64)
        }
    }

    /// The minimum observed value in microseconds, or `None` when empty.
    pub fn min_us(&self) -> Option<u64> {
        if self.total == 0 {
            None
        } else {
            Some(self.min_us)
        }
    }

    /// The maximum observed value in microseconds, or `None` when empty.
    pub fn max_us(&self) -> Option<u64> {
        if self.total == 0 {
            None
        } else {
            Some(self.max_us)
        }
    }

    /// The `q`-quantile (0..1) as the upper edge of its bucket, in
    /// microseconds.
    pub fn quantile_us(&self, q: f64) -> Option<u64> {
        if self.total == 0 {
            return None;
        }
        let target = crate::float::ceil(q.clamp(0.0, 1.0) * self.total as f64) as u64;
        let target = target.max(1);
        let mut seen = 0u64;
        for (i, &c) in self.counts.iter().enumerate() {
            seen = seen.saturating_add(c);
            if seen >= target {
                return Some(bucket_upper_us(i));
            }
        }
        Some(self.max_us)
    }
}

fn latency_bucket(micros: u64) -> usize {
    if micros == 0 {
        return 0;
    }
    // 64 − leading_zeros gives the position of the highest set bit, i.e.
    // floor(log2) + 1; `micros = 1` therefore lands in bucket 0.
    let bits = 64 - micros.leading_zeros() as usize;
    (bits - 1).min(LATENCY_BUCKETS - 1)
}

fn bucket_upper_us(idx: usize) -> u64 {
    if idx >= LATENCY_BUCKETS - 1 {
        // The final bucket is the overflow bucket.
        return u64::MAX;
    }
    1u64.checked_shl(idx as u32 + 1).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perfect_predictions_score_zero() {
        let mut c = Calibration::new();
        for _ in 0..100 {
            c.observe(1.0, true);
        }
        assert!(c.brier().unwrap() < 1e-12);
        assert!(c.log_loss().unwrap() < 1e-9);
        assert_eq!(c.clamped(), 100);
        assert!(c.bias().unwrap().abs() < 1e-9);
    }

    #[test]
    fn constant_half_scores_the_reference_values() {
        let mut c = Calibration::new();
        for i in 0..1000 {
            c.observe(0.5, i % 2 == 0);
        }
        // Brier of a constant 0.5 predictor is exactly 0.25.
        assert!((c.brier().unwrap() - 0.25).abs() < 1e-12);
        // Log loss is ln 2.
        assert!((c.log_loss().unwrap() - core::f64::consts::LN_2).abs() < 1e-9);
    }

    #[test]
    fn overconfident_model_is_penalised_more_by_log_loss() {
        let mut honest = Calibration::new();
        let mut hubris = Calibration::new();
        for i in 0..1000 {
            let y = i % 5 == 0; // true rate 0.2
            honest.observe(0.2, y);
            hubris.observe(0.95, y);
        }
        assert!(hubris.log_loss().unwrap() > honest.log_loss().unwrap() * 3.0);
        assert!(hubris.brier().unwrap() > honest.brier().unwrap());
        assert!(hubris.bias().unwrap() < -0.5, "must read as over-confident");
    }

    #[test]
    fn reliability_table_separates_bins() {
        let mut c = Calibration::new();
        // Ten predictions at 0.1 of which one happens, and ten at 0.9 of
        // which nine do: the model is exactly calibrated, in two bins.
        for i in 0..10 {
            c.observe(0.1, i == 0);
            c.observe(0.9, i != 9);
        }
        let low = c.bins().get(1).unwrap();
        let high = c.bins().get(9).unwrap();
        assert_eq!(low.n, 10);
        assert_eq!(high.n, 10);
        assert!(low.gap().unwrap().abs() < 1e-9);
        assert!(high.gap().unwrap().abs() < 1e-9);
        assert!(c.expected_calibration_error().unwrap().abs() < 1e-9);
        assert!(c.bias().unwrap().abs() < 1e-9);
    }

    #[test]
    fn nan_prediction_is_not_a_free_pass() {
        let mut c = Calibration::new();
        c.observe(f64::NAN, true);
        assert_eq!(c.samples(), 1);
        assert!((c.brier().unwrap() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn empty_monitor_reports_nothing() {
        let c = Calibration::new();
        assert!(c.brier().is_none());
        assert!(c.log_loss().is_none());
        assert!(c.expected_calibration_error().is_none());
        assert!(c.bias().is_none());
    }

    #[test]
    fn latency_quantiles_are_conservative() {
        let mut d = LatencyDigest::new();
        for i in 1..=1000u64 {
            d.record(i);
        }
        let p50 = d.quantile_us(0.5).unwrap();
        let p99 = d.quantile_us(0.99).unwrap();
        // Values 1..=1000: the median is 500, its bucket upper edge is 512.
        assert!((500..=512).contains(&p50), "p50 = {p50}");
        assert!((990..=1024).contains(&p99), "p99 = {p99}");
        assert!(d.mean_us().unwrap() > 499.0 && d.mean_us().unwrap() < 501.0);
        assert_eq!(d.min_us(), Some(1));
        assert_eq!(d.max_us(), Some(1000));
    }

    #[test]
    fn latency_digest_is_bounded_and_never_panics() {
        let mut d = LatencyDigest::new();
        d.record(0);
        d.record(u64::MAX);
        assert_eq!(d.samples(), 2);
        let q = d.quantile_us(1.0).unwrap();
        assert_eq!(q, u64::MAX);
        assert!(d.quantile_us(0.0).is_some());
    }
}
