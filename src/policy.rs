//! Security / policy layer.
//!
//! This module owns the rules that sit between the client and the cache:
//! rate limiting (token buckets keyed by client), name-based filtering
//! (blocklists), and request validation. Anti-cache-poisoning checks
//! (0x20, bailiwick, source/ID validation) live in the resolution engine,
//! where the wire state they need is available.
//!
//! # What per-client rate limiting can and cannot do
//!
//! UDP source addresses are spoofable, so a token bucket keyed by source
//! address is best-effort by construction: an attacker who forges sources
//! gets a fresh bucket per packet. What the limiter *guarantees* is that
//! the bucket table stays bounded and cheap to fill — capacity is enforced
//! by an amortised sweep, never by a scan per packet — so a spoofing flood
//! costs the resolver a bounded amount of memory and CPU rather than
//! unbounded work per packet. Worth noting: the eviction order deliberately
//! favours *idle* buckets over busy ones. Dropping an idle bucket is free
//! (it would have refilled to capacity anyway), whereas dropping the
//! busiest bucket would hand the most aggressive client a fresh burst.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::message::Message;
use crate::name::Name;
use crate::qtype::{Opcode, RrType};
use crate::time::Ts;

/// Buckets idle for longer than this are dropped first when the table is
/// full. A bucket this quiet has refilled to capacity, so evicting it is
/// indistinguishable from keeping it.
pub const BUCKET_RETENTION_SECS: Ts = 60;
/// Eviction stride for a table full of freshly-active buckets.
pub const EVICT_STRIDE: usize = 8;

/// A token bucket (used for both client and upstream rate limiting).
///
/// Tokens accumulate at `refill_per_sec` up to `capacity`; `take` consumes
/// and reports whether the burst was allowed. Time-based refill uses the
/// injected wall clock, so buckets are exact under a manual clock in tests.
#[derive(Clone, Debug)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last_refill: Ts,
}

impl TokenBucket {
    /// A bucket with the given capacity and refill rate.
    pub fn new(capacity: f64, refill_per_sec: f64, now: Ts) -> Self {
        Self {
            capacity: capacity.max(1.0),
            tokens: capacity.max(1.0),
            refill_per_sec: refill_per_sec.max(0.0),
            last_refill: now,
        }
    }

    fn refill(&mut self, now: Ts) {
        if now > self.last_refill {
            let dt = (now - self.last_refill) as f64 / 1_000_000_000.0;
            self.tokens = (self.tokens + dt * self.refill_per_sec).min(self.capacity);
            self.last_refill = now;
        }
    }

    /// Try to consume `n` tokens. Returns true if allowed.
    pub fn take(&mut self, n: f64, now: Ts) -> bool {
        self.refill(now);
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }

    /// The current token level.
    pub fn level(&self, now: Ts) -> f64 {
        let mut b = self.clone();
        b.refill(now);
        b.tokens
    }
}

/// A bounded map of token buckets keyed by a hash of the caller identity
/// (client IP or upstream endpoint).
pub struct RateLimiter {
    buckets: BTreeMap<u64, TokenBucket>,
    capacity: f64,
    refill_per_sec: f64,
    max_buckets: usize,
}

impl core::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "RateLimiter(clients={}/{}, burst={}, refill={}/s)",
            self.buckets.len(),
            self.max_buckets,
            self.capacity,
            self.refill_per_sec
        )
    }
}

impl RateLimiter {
    /// A limiter with `capacity` burst and `refill_per_sec` steady state,
    /// tracking at most `max_buckets` distinct callers.
    pub fn new(capacity: f64, refill_per_sec: f64, max_buckets: usize) -> Self {
        Self {
            buckets: BTreeMap::new(),
            capacity: capacity.max(1.0),
            refill_per_sec: refill_per_sec.max(0.0),
            max_buckets: max_buckets.max(1),
        }
    }

    /// Whether a request from `key` is allowed (consuming one token).
    ///
    /// When the bucket table is full a new caller triggers an amortised
    /// sweep ([`crate::bounded::evict_for_capacity`]) instead of an O(n)
    /// scan per packet: buckets idle longer than
    /// [`BUCKET_RETENTION_SECS`] go first — dropping an idle bucket is
    /// semantically free, because a bucket that quiet has refilled to
    /// capacity anyway, so a reappearing client sees exactly the same
    /// state. See the module docs for why the eviction order is not
    /// "the most throttled client".
    pub fn allow(&mut self, key: u64, now: Ts) -> bool {
        if !self.buckets.contains_key(&key) {
            if self.buckets.len() >= self.max_buckets {
                let stale_before = now.saturating_sub(BUCKET_RETENTION_SECS * 1_000_000_000);
                crate::bounded::evict_for_capacity(
                    &mut self.buckets,
                    stale_before,
                    EVICT_STRIDE,
                    |b| b.last_refill,
                );
            }
            self.buckets.insert(
                key,
                TokenBucket::new(self.capacity, self.refill_per_sec, now),
            );
        }
        self.buckets
            .get_mut(&key)
            .map(|b| b.take(1.0, now))
            .unwrap_or(false)
    }

    /// The number of tracked buckets.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// Whether the limiter is empty.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Hash a client IP (IPv4 or IPv6) into a bucket key.
    pub fn hash_ip(ip: &core::net::IpAddr) -> u64 {
        use crate::prng::fnv1a64;
        match ip {
            core::net::IpAddr::V4(v) => fnv1a64(&v.octets()),
            core::net::IpAddr::V6(v) => fnv1a64(&v.octets()),
        }
    }
}

/// A filter rule: everything under `suffix` is blocked (RPZ-style
/// `*.example.com`), or exactly the name when `exact` is set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRule {
    /// The blocked suffix (all names at or below it when `exact` is false).
    pub suffix: Name,
    /// If true, only `suffix` itself is blocked (not its subtree).
    pub exact: bool,
}

impl BlockRule {
    /// Block every name under (and including) `suffix`.
    pub fn subtree(suffix: Name) -> Self {
        Self {
            suffix,
            exact: false,
        }
    }

    /// Block exactly `name`.
    pub fn exact(name: Name) -> Self {
        Self {
            suffix: name,
            exact: true,
        }
    }
}

/// Policy configuration.
#[derive(Clone, Debug)]
pub struct PolicyConfig {
    /// Names that are blocked.
    pub block: Vec<BlockRule>,
    /// Maximum labels in a query name (anti-malware amplification).
    pub max_qname_labels: usize,
    /// Maximum question count per message (must be 1 for QUERY).
    pub enforce_single_question: bool,
    /// Refuse queries with opcode != QUERY.
    pub enforce_query_opcode: bool,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            block: Vec::new(),
            max_qname_labels: 127,
            enforce_single_question: true,
            enforce_query_opcode: true,
        }
    }
}

/// The policy engine: filtering + request validation.
#[derive(Debug)]
pub struct PolicyEngine {
    config: PolicyConfig,
}

impl PolicyEngine {
    /// A policy engine from the given configuration.
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    /// The configuration.
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    /// Whether a query name is blocked by policy.
    pub fn is_blocked(&self, name: &Name) -> bool {
        self.config.block.iter().any(|r| {
            if r.exact {
                &r.suffix == name
            } else {
                name.is_subdomain_of(&r.suffix)
            }
        })
    }

    /// Whether a client (by IP) is allowed, consuming a token.
    pub fn client_allowed(
        &self,
        limiter: &mut RateLimiter,
        ip: &core::net::IpAddr,
        now: Ts,
    ) -> bool {
        limiter.allow(RateLimiter::hash_ip(ip), now)
    }

    /// Validate an incoming client query message. Returns an error the
    /// server should map to a FORMERR / REFUSED response.
    pub fn validate_query(&self, msg: &Message) -> Result<()> {
        if self.config.enforce_query_opcode && msg.flags.opcode != Opcode::QUERY {
            return Err(Error::new(
                crate::error::ErrorKind::Policy,
                "only QUERY opcode is supported",
            ));
        }
        if self.config.enforce_single_question && msg.questions.len() != 1 {
            return Err(Error::new(
                crate::error::ErrorKind::Policy,
                "exactly one question required",
            ));
        }
        if let Some(q) = msg.question() {
            if q.qname.label_count() > self.config.max_qname_labels {
                return Err(Error::new(
                    crate::error::ErrorKind::Policy,
                    "query name has too many labels",
                ));
            }
            if q.qtype == RrType::AXFR || q.qtype == RrType::IXFR {
                return Err(Error::new(
                    crate::error::ErrorKind::Policy,
                    "zone transfers are not served",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    #[test]
    fn bucket_refills() {
        let mut b = TokenBucket::new(10.0, 5.0, now());
        for _ in 0..10 {
            assert!(b.take(1.0, now()));
        }
        // Exhausted.
        assert!(!b.take(1.0, now()));
        // After 1 second, 5 tokens back.
        assert!(b.take(1.0, now() + 1_000_000_000));
        assert!(b.take(1.0, now() + 1_000_000_000));
        assert!(!b.take(5.0, now() + 1_000_000_000));
    }

    #[test]
    fn limiter_isolates_clients() {
        let mut lim = RateLimiter::new(2.0, 1.0, 16);
        let a = RateLimiter::hash_ip(&"10.0.0.1".parse().unwrap());
        let b = RateLimiter::hash_ip(&"10.0.0.2".parse().unwrap());
        assert!(lim.allow(a, now()));
        assert!(lim.allow(a, now()));
        assert!(!lim.allow(a, now()));
        assert!(lim.allow(b, now())); // different client unaffected
    }

    #[test]
    fn blocklist() {
        let cfg = PolicyConfig {
            block: vec![BlockRule::subtree(
                Name::from_ascii("ads.example.com").unwrap(),
            )],
            ..Default::default()
        };
        let eng = PolicyEngine::new(cfg);
        assert!(eng.is_blocked(&Name::from_ascii("tracker.ads.example.com").unwrap()));
        assert!(eng.is_blocked(&Name::from_ascii("ads.example.com").unwrap()));
        assert!(!eng.is_blocked(&Name::from_ascii("example.com").unwrap()));
    }

    #[test]
    fn query_validation() {
        let eng = PolicyEngine::new(PolicyConfig::default());
        let m = Message::query(1, Name::from_ascii("example.com").unwrap(), RrType::A, true);
        assert!(eng.validate_query(&m).is_ok());

        let mut bad = Message::query(1, Name::from_ascii("example.com").unwrap(), RrType::A, true);
        bad.flags.opcode = Opcode::UPDATE;
        assert!(eng.validate_query(&bad).is_err());

        let zt = Message::query(
            1,
            Name::from_ascii("example.com").unwrap(),
            RrType::AXFR,
            true,
        );
        assert!(eng.validate_query(&zt).is_err());
    }
}
