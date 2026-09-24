//! Resolver statistics (atomic counters, `std`).

use core::sync::atomic::{AtomicU64, Ordering};

/// Live counters.
#[derive(Debug, Default)]
pub struct Stats {
    /// Queries received.
    pub queries: AtomicU64,
    /// Cache hits.
    pub cache_hits: AtomicU64,
    /// Cache misses.
    pub cache_misses: AtomicU64,
    /// Stale answers served (RFC 8767).
    pub served_stale: AtomicU64,
    /// Background prefetches performed.
    pub prefetches: AtomicU64,
    /// Alias refreshes queued by change propagation (entries whose data is
    /// derived from a changed entry).
    pub propagated: AtomicU64,
    /// Alias edges currently recorded (gauge, updated by the maintenance
    /// task).
    pub alias_edges: AtomicU64,
    /// Queries sent upstream.
    pub upstream_queries: AtomicU64,
    /// Upstream timeouts.
    pub upstream_timeouts: AtomicU64,
    /// SERVFAIL responses.
    pub servfails: AtomicU64,
    /// NXDOMAIN responses.
    pub nxdomain: AtomicU64,
    /// NODATA (empty NOERROR) responses.
    pub nodata: AtomicU64,
    /// Queries rate-limited.
    pub rate_limited: AtomicU64,
    /// Queries blocked by policy.
    pub policy_blocked: AtomicU64,
    /// Queries served by coalescing.
    pub coalesced: AtomicU64,
    /// Internal errors.
    pub errors: AtomicU64,
    /// Answers served from a `hosts` pin.
    pub hosts_answered: AtomicU64,
    /// Names that reached `local_answer` but were **not** synthesized because
    /// `fake-ip-filter` excludes them. A name showing up here is being
    /// resolved for real by design.
    pub fake_ip_filtered: AtomicU64,
    /// `A` answers synthesized from the fake-IP pool.
    pub fake_ip_answered: AtomicU64,
    /// Reverse (`PTR`) answers synthesized from the fake-IP pool.
    pub fake_ip_ptr: AtomicU64,
    /// Live fake-IP mappings (gauge, updated by the maintenance task).
    pub fake_ip_entries: AtomicU64,
    /// Fake-IP mappings dropped to stay inside the cap (gauge). Non-zero here
    /// means the pool is recycling, which is the signal to raise
    /// `fake-ip-max-entries`.
    pub fake_ip_evicted: AtomicU64,
    /// Queries whose group was chosen by `nameserver-policy` (rather than
    /// falling to the default group). A config that expects routing and shows
    /// zero here has a suffix that does not match.
    pub policy_routed: AtomicU64,
    /// Queries re-sent to the `fallback` group because the default group's
    /// answer looked poisoned.
    pub fallback_triggered: AtomicU64,
    /// Sum of resolve times in microseconds (for the average).
    pub resolve_time_us_sum: AtomicU64,
    /// Number of resolves sampled for the average.
    pub resolve_count: AtomicU64,
}

/// A point-in-time snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// Queries received.
    pub queries: u64,
    /// Cache hits.
    pub cache_hits: u64,
    /// Cache misses.
    pub cache_misses: u64,
    /// Stale answers served (RFC 8767).
    pub served_stale: u64,
    /// Background prefetches performed.
    pub prefetches: u64,
    /// Alias refreshes queued by change propagation.
    pub propagated: u64,
    /// Alias edges recorded.
    pub alias_edges: u64,
    /// Queries sent upstream.
    pub upstream_queries: u64,
    /// Upstream timeouts.
    pub upstream_timeouts: u64,
    /// SERVFAIL responses.
    pub servfails: u64,
    /// NXDOMAIN responses.
    pub nxdomain: u64,
    /// NODATA (empty NOERROR) responses.
    pub nodata: u64,
    /// Queries rate-limited.
    pub rate_limited: u64,
    /// Queries blocked by policy.
    pub policy_blocked: u64,
    /// Queries served by coalescing.
    pub coalesced: u64,
    /// Internal errors.
    pub errors: u64,
    /// Answers served from a `hosts` pin.
    pub hosts_answered: u64,
    /// Names excluded from fake-IP by `fake-ip-filter`.
    pub fake_ip_filtered: u64,
    /// `A` answers synthesized from the fake-IP pool.
    pub fake_ip_answered: u64,
    /// Reverse (`PTR`) answers synthesized from the fake-IP pool.
    pub fake_ip_ptr: u64,
    /// Live fake-IP mappings.
    pub fake_ip_entries: u64,
    /// Fake-IP mappings dropped to stay inside the cap.
    pub fake_ip_evicted: u64,
    /// Queries whose group was chosen by `nameserver-policy`.
    pub policy_routed: u64,
    /// Queries re-sent to the `fallback` group by the poison gate.
    pub fallback_triggered: u64,
    /// Average resolve time in microseconds (0 when no samples).
    pub avg_resolve_us: u64,
}

impl Stats {
    /// A snapshot of the counters.
    pub fn snapshot(&self) -> StatsSnapshot {
        let resolve_count = self.resolve_count.load(Ordering::Relaxed);
        let total = self.resolve_time_us_sum.load(Ordering::Relaxed);
        StatsSnapshot {
            queries: self.queries.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            served_stale: self.served_stale.load(Ordering::Relaxed),
            prefetches: self.prefetches.load(Ordering::Relaxed),
            propagated: self.propagated.load(Ordering::Relaxed),
            alias_edges: self.alias_edges.load(Ordering::Relaxed),
            upstream_queries: self.upstream_queries.load(Ordering::Relaxed),
            upstream_timeouts: self.upstream_timeouts.load(Ordering::Relaxed),
            servfails: self.servfails.load(Ordering::Relaxed),
            nxdomain: self.nxdomain.load(Ordering::Relaxed),
            nodata: self.nodata.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            policy_blocked: self.policy_blocked.load(Ordering::Relaxed),
            coalesced: self.coalesced.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            hosts_answered: self.hosts_answered.load(Ordering::Relaxed),
            fake_ip_filtered: self.fake_ip_filtered.load(Ordering::Relaxed),
            fake_ip_answered: self.fake_ip_answered.load(Ordering::Relaxed),
            fake_ip_ptr: self.fake_ip_ptr.load(Ordering::Relaxed),
            fake_ip_entries: self.fake_ip_entries.load(Ordering::Relaxed),
            fake_ip_evicted: self.fake_ip_evicted.load(Ordering::Relaxed),
            policy_routed: self.policy_routed.load(Ordering::Relaxed),
            fallback_triggered: self.fallback_triggered.load(Ordering::Relaxed),
            avg_resolve_us: total.checked_div(resolve_count).unwrap_or(0),
        }
    }
}
