//! Per-RRset stability model.
//!
//! The core observation behind RecurseX is that *TTL ≠ data stability*: a
//! TTL is what an authoritative server claims, not a measurement of how
//! often it actually changes. This module tracks the observable history of
//! each RRset and reduces it to a single `0..1` stability score plus the
//! statistics that drive prefetch timing and stale fallback.
//!
//! The model never changes the TTL we report to clients — it only tunes
//! internal policy (prefetch timing, serve-stale willingness, admission
//! score).

use core::fmt;

use crate::time::Ts;

/// The stability model of one cached RRset.
#[derive(Clone, Debug)]
pub struct StabilityModel {
    /// Number of refreshes observed.
    pub samples: u64,
    /// Number of refreshes where the content changed.
    pub changes: u64,
    /// EWMA stability in `0..1` (1 = never changed).
    pub stability: f64,
    /// Long-run change ratio `changes / samples` (0..1).
    pub change_ratio: f64,
    /// EWMA of the authoritative TTL in seconds.
    pub ttl_ewma: f64,
    /// EWMA of `|ttl - ttl_ewma|` (TTL volatility, in seconds).
    pub ttl_volatility: f64,
    /// Consecutive refresh failures (timeouts/SERVFAIL) since the last
    /// successful refresh.
    pub consecutive_failures: u64,
    /// Total refresh failures.
    pub failures: u64,
    /// Wall time of the last observation.
    pub last_refresh: Ts,
    /// Wall time of the last observed content change.
    pub last_change: Ts,
}

impl StabilityModel {
    /// A fresh model with no history.
    pub fn new(now: Ts) -> Self {
        Self {
            samples: 0,
            changes: 0,
            stability: 0.5, // neutral prior
            change_ratio: 0.0,
            ttl_ewma: 0.0,
            ttl_volatility: 0.0,
            consecutive_failures: 0,
            failures: 0,
            last_refresh: now,
            last_change: now,
        }
    }

    /// Record a successful refresh of the RRset.
    ///
    /// * `ttl_secs` — the authoritative TTL observed.
    /// * `changed` — whether the data differed from what was cached.
    pub fn observe(&mut self, ttl_secs: u32, changed: bool, now: Ts) {
        self.samples += 1;
        if changed {
            self.changes += 1;
            self.last_change = now;
        }
        self.consecutive_failures = 0;

        // Stability EWMA: unchanged refreshes pull toward 1, changes pull
        // sharply down. A single change is a big signal.
        let target = if changed { 0.0 } else { 1.0 };
        let alpha = if changed { 0.4 } else { 0.2 };
        self.stability = self.stability * (1.0 - alpha) + target * alpha;

        // Long-run change ratio (equal-weight; resets the EWMA influence).
        self.change_ratio = self.changes as f64 / self.samples as f64;

        // TTL statistics (EWMA, α = 0.2).
        let t = ttl_secs as f64;
        if self.samples == 1 {
            self.ttl_ewma = t;
            self.ttl_volatility = 0.0;
        } else {
            self.ttl_volatility = self.ttl_volatility * 0.8 + (t - self.ttl_ewma).abs() * 0.2;
            self.ttl_ewma = self.ttl_ewma * 0.8 + t * 0.2;
        }
        self.last_refresh = now;
    }

    /// Record a refresh failure (timeout, SERVFAIL, transport error).
    pub fn record_failure(&mut self, now: Ts) {
        self.failures += 1;
        self.consecutive_failures += 1;
        self.last_refresh = now;
    }

    /// The stability score in `0..1`.
    #[inline]
    pub fn score(&self) -> f64 {
        self.stability
    }

    /// Whether the model has enough history to be meaningful.
    #[inline]
    pub fn is_mature(&self) -> bool {
        self.samples >= 3
    }

    /// Whether the set is "very stable": enough samples and a high score.
    /// Very stable sets are refreshed in the background rather than in the
    /// request path, and are allowed to serve stale while refreshing.
    pub fn is_very_stable(&self, threshold: f64) -> bool {
        self.is_mature() && self.stability >= threshold
    }

    /// A prediction-friendly "likely to change soon" score in `0..1`.
    /// Combines EWMA instability, long-run change ratio, and TTL volatility
    /// (a set whose TTL fluctuates is under active management).
    pub fn change_likelihood(&self) -> f64 {
        if self.samples == 0 {
            return 0.5;
        }
        let instab = 1.0 - self.stability;
        let ttl_term = (self.ttl_volatility / (self.ttl_ewma.max(1.0))).min(1.0) * 0.3;
        (instab * 0.5 + self.change_ratio * 0.4 + ttl_term).clamp(0.0, 1.0)
    }
}

impl Default for StabilityModel {
    fn default() -> Self {
        Self::new(0)
    }
}

impl fmt::Display for StabilityModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "samples={} changes={} stability={:.3} chg_ratio={:.3} ttl_ewma={:.0}s ttl_vol={:.0}s fails={}",
            self.samples,
            self.changes,
            self.stability,
            self.change_ratio,
            self.ttl_ewma,
            self.ttl_volatility,
            self.failures
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
    fn stable_set_scores_high() {
        let mut m = StabilityModel::new(now());
        for i in 0..12 {
            m.observe(300, false, now() + i * 1_000_000_000);
        }
        assert!(m.score() > 0.9);
        assert!(m.is_very_stable(0.9));
        assert!(m.change_likelihood() < 0.3);
    }

    #[test]
    fn one_change_drops_score() {
        let mut m = StabilityModel::new(now());
        for i in 0..10 {
            m.observe(300, false, now() + i * 1_000_000_000);
        }
        m.observe(300, true, now() + 10_000_000_000);
        assert!(m.score() < 0.8);
        assert_eq!(m.changes, 1);
        assert!((m.change_ratio - 1.0 / 11.0).abs() < 1e-9);
    }

    #[test]
    fn failures_track() {
        let mut m = StabilityModel::new(now());
        m.record_failure(now());
        m.record_failure(now() + 1);
        assert_eq!(m.consecutive_failures, 2);
        m.observe(300, false, now() + 2);
        assert_eq!(m.consecutive_failures, 0);
    }

    #[test]
    fn ttl_volatility_tracks_changes() {
        let mut m = StabilityModel::new(now());
        for (i, ttl) in [300u32, 300, 3600, 300, 3600].iter().enumerate() {
            m.observe(*ttl, false, now() + i as i128 * 1_000_000_000);
        }
        assert!(m.ttl_volatility > 0.0);
        // The set with volatile TTLs is more likely to change.
        assert!(m.change_likelihood() > 0.1);
    }

    #[test]
    fn fresh_model_is_neutral() {
        let m = StabilityModel::new(now());
        assert_eq!(m.score(), 0.5);
        assert!(!m.is_very_stable(0.9));
    }
}
