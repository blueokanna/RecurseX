//! Adaptive upstream selection.
//!
//! Picking an authoritative server by raw RTT is wrong: a server that is
//! fast 92% of the time can be *more expensive in expectation* than a
//! slightly slower server that never fails, once retransmissions and
//! SERVFAIL penalties are counted. Every candidate path here carries a
//! small statistical model — EWMA RTT, RTT variance, loss, SERVFAIL rate —
//! and selection minimizes the *expected resolution cost*:
//!
//! ```text
//! cost = rtt_ewma + conn_setup + loss_penalty + failure_penalty
//! loss_penalty   = RTO · p_loss / (1 − p_loss)
//! failure_penalty= RTO · p_servfail · 1.5
//! ```

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec::Vec;
use core::fmt;
use core::net::IpAddr;

use crate::time::Ts;

/// The transport used to reach an upstream.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Proto {
    /// Plain DNS over UDP (RFC 1035).
    Udp,
    /// Plain DNS over TCP (RFC 1035 / 7766).
    Tcp,
    /// DNS over TLS, a.k.a. DoT (RFC 7858).
    Tls,
    /// DNS over HTTPS (RFC 8484).
    DoH,
    /// DNS over HTTP/3 (RFC 8484 over QUIC).
    DoH3,
    /// DNS over QUIC (RFC 9250).
    DoQ,
}

impl Proto {
    /// Whether this transport encrypts DNS traffic.
    pub fn is_encrypted(self) -> bool {
        matches!(self, Proto::Tls | Proto::DoH | Proto::DoH3 | Proto::DoQ)
    }

    /// The default connection-setup cost as a multiple of one RTT.
    /// UDP needs none; DoQ/TCP pay one round trip; TLS/DoH pay two.
    pub fn setup_rtts(self) -> f64 {
        match self {
            Proto::Udp => 0.0,
            Proto::DoQ | Proto::Tcp | Proto::DoH3 => 1.0,
            Proto::Tls | Proto::DoH => 2.0,
        }
    }

    /// A short mnemonic.
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Udp => "udp",
            Proto::Tcp => "tcp",
            Proto::Tls => "dot",
            Proto::DoH => "doh",
            Proto::DoH3 => "doh3",
            Proto::DoQ => "doq",
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A concrete upstream endpoint.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct Endpoint {
    /// The server address.
    pub ip: IpAddr,
    /// The server port.
    pub port: u16,
    /// The transport to use.
    pub proto: Proto,
}

impl Endpoint {
    /// A UDP endpoint on port 53.
    pub fn udp(ip: IpAddr) -> Self {
        Self {
            ip,
            port: 53,
            proto: Proto::Udp,
        }
    }

    /// Any endpoint.
    pub fn new(ip: IpAddr, port: u16, proto: Proto) -> Self {
        Self { ip, port, proto }
    }

    /// The host:port presentation.
    pub fn addr_str(&self) -> alloc::string::String {
        format!("{}:{}", self.ip, self.port)
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{} ({})", self.ip, self.port, self.proto)
    }
}

/// The statistical path model for one upstream.
#[derive(Clone, Debug)]
pub struct PathModel {
    /// The endpoint this model describes.
    pub endpoint: Endpoint,
    /// Successful exchanges.
    pub successes: u64,
    /// Failed exchanges (timeouts / transport errors).
    pub failures: u64,
    /// Timeouts specifically.
    pub timeouts: u64,
    /// SERVFAIL responses.
    pub servfails: u64,
    /// EWMA RTT in ms.
    pub rtt_ewma_ms: f64,
    /// EWMA RTT variance in ms (mean absolute deviation).
    pub rtt_var_ms: f64,
    /// EWMA loss probability `0..1`.
    pub loss_rate: f64,
    /// When the path was last used.
    pub last_seen: Ts,
    /// Estimated connection setup cost in ms (transport-dependent).
    pub conn_cost_ms: f64,
}

impl PathModel {
    /// A fresh model for an endpoint.
    pub fn new(endpoint: Endpoint, rtt_ms: f64) -> Self {
        Self {
            endpoint,
            successes: 0,
            failures: 0,
            timeouts: 0,
            servfails: 0,
            rtt_ewma_ms: rtt_ms,
            rtt_var_ms: 0.0,
            loss_rate: 0.0,
            last_seen: 0,
            conn_cost_ms: endpoint.proto.setup_rtts() * rtt_ms,
        }
    }

    /// Record a successful exchange.
    pub fn record_success(&mut self, rtt_ms: f64, now: Ts) {
        self.successes += 1;
        self.last_seen = now;
        // EWMA of RTT (α = 0.2).
        self.rtt_var_ms =
            self.rtt_var_ms * 0.8 + crate::float::fabs(rtt_ms - self.rtt_ewma_ms) * 0.2;
        self.rtt_ewma_ms = self.rtt_ewma_ms * 0.8 + rtt_ms * 0.2;
        // Decay loss slowly on success.
        self.loss_rate *= 0.95;
        self.conn_cost_ms = self.endpoint.proto.setup_rtts() * self.rtt_ewma_ms;
    }

    /// Record a timeout.
    pub fn record_timeout(&mut self, now: Ts) {
        self.failures += 1;
        self.timeouts += 1;
        self.last_seen = now;
        self.loss_rate = (self.loss_rate * 0.8 + 0.2).min(1.0);
    }

    /// Record a SERVFAIL (the server answered, but badly).
    pub fn record_servfail(&mut self, now: Ts) {
        self.servfails += 1;
        self.last_seen = now;
        // A SERVFAIL is not a transport loss but it is a failed resolution.
        self.failures += 1;
    }

    /// The empirical probability of a successful exchange.
    pub fn success_probability(&self) -> f64 {
        let n = self.successes + self.failures;
        if n == 0 {
            0.9 // optimistic prior
        } else {
            (self.successes as f64 + 1.0) / (n as f64 + 2.0)
        }
    }

    /// The SERVFAIL rate `0..1`.
    pub fn servfail_rate(&self) -> f64 {
        let n = self.successes + self.servfails;
        if n == 0 {
            0.0
        } else {
            (self.servfails as f64) / (n as f64)
        }
    }

    /// The estimated RTO (retransmission timeout) in ms: RTT + 4·variance
    /// plus a floor that absorbs scheduler jitter.
    pub fn rto_ms(&self) -> f64 {
        (self.rtt_ewma_ms + 4.0 * self.rtt_var_ms).max(25.0)
    }

    /// The expected cost in ms of one resolution attempt over this path,
    /// accounting for retransmissions and failures.
    pub fn expected_cost_ms(&self, retransmit_budget: u32) -> f64 {
        let rto = self.rto_ms();
        let p = self.loss_rate.clamp(0.0, 0.95);
        // Geometric series of expected retransmission time.
        let retrans_penalty = if p >= 1.0 {
            rto * retransmit_budget as f64
        } else {
            (p / (1.0 - p)) * rto
        };
        let fail = self.servfail_rate().min(0.9);
        let failure_penalty = fail * rto * 1.5;
        self.rtt_ewma_ms + self.conn_cost_ms + retrans_penalty + failure_penalty
    }

    /// Whether this path has been seen before.
    pub fn is_known(&self) -> bool {
        self.successes + self.failures > 0
    }
}

/// The per-authority path model store + selector.
pub struct UpstreamSelector {
    paths: BTreeMap<Endpoint, PathModel>,
    /// Cap on tracked paths (defends against NS-flood attacks).
    max_paths: usize,
}

impl Default for UpstreamSelector {
    fn default() -> Self {
        Self::new(4096)
    }
}

impl UpstreamSelector {
    /// A selector tracking up to `max_paths`.
    pub fn new(max_paths: usize) -> Self {
        Self {
            paths: BTreeMap::new(),
            max_paths: max_paths.max(1),
        }
    }

    /// Record a successful exchange.
    pub fn record_success(&mut self, ep: Endpoint, rtt_ms: f64, now: Ts) {
        let path = self.path_mut(ep, rtt_ms);
        path.record_success(rtt_ms, now);
    }

    /// Record a timeout.
    pub fn record_timeout(&mut self, ep: Endpoint, now: Ts) {
        if let Some(p) = self.paths.get_mut(&ep) {
            p.record_timeout(now);
        }
    }

    /// Record a SERVFAIL.
    pub fn record_servfail(&mut self, ep: Endpoint, now: Ts) {
        if let Some(p) = self.paths.get_mut(&ep) {
            p.record_servfail(now);
        }
    }

    /// The model for an endpoint, if tracked.
    pub fn path(&self, ep: &Endpoint) -> Option<&PathModel> {
        self.paths.get(ep)
    }

    /// The number of tracked paths.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Whether the selector is empty.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    /// The best candidate by expected resolution cost.
    pub fn best(
        &self,
        candidates: &[Endpoint],
        now: Ts,
        retransmit_budget: u32,
    ) -> Option<Endpoint> {
        self.sort_by_cost(candidates, now, retransmit_budget)
            .first()
            .map(|(ep, _)| *ep)
    }

    /// Candidates sorted by expected cost, cheapest first. Unknown paths
    /// use a neutral prior so they are not starved.
    pub fn sort_by_cost(
        &self,
        candidates: &[Endpoint],
        now: Ts,
        retransmit_budget: u32,
    ) -> Vec<(Endpoint, f64)> {
        let mut ranked: Vec<(Endpoint, f64)> = candidates
            .iter()
            .map(|&ep| {
                let cost = match self.paths.get(&ep) {
                    Some(p) => p.expected_cost_ms(retransmit_budget),
                    None => {
                        // Neutral prior: assume one RTT of 100 ms and no
                        // history. Prefer unknown paths slightly so they
                        // get probed.
                        let prior = 100.0 + ep.proto.setup_rtts() * 100.0;
                        let _ = now;
                        prior
                    }
                };
                (ep, cost)
            })
            .collect();
        ranked.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(core::cmp::Ordering::Equal));
        ranked
    }

    fn path_mut(&mut self, ep: Endpoint, rtt_ms: f64) -> &mut PathModel {
        if !self.paths.contains_key(&ep) {
            if self.paths.len() >= self.max_paths {
                // Evict the least-recently-seen path.
                if let Some(k) = self
                    .paths
                    .iter()
                    .min_by_key(|(_, p)| p.last_seen)
                    .map(|(k, _)| *k)
                {
                    self.paths.remove(&k);
                }
            }
            self.paths.insert(ep, PathModel::new(ep, rtt_ms));
        }
        self.paths.get_mut(&ep).expect("just inserted")
    }
}

impl fmt::Debug for UpstreamSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UpstreamSelector(paths={})", self.paths.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    fn ep(ip: &str, proto: Proto) -> Endpoint {
        Endpoint::new(ip.parse().unwrap(), 53, proto)
    }

    #[test]
    fn cost_model_prefers_reliable() {
        // ns1: fast but lossy. ns2: slower but reliable.
        let mut sel = UpstreamSelector::new(64);
        let ns1 = ep("192.0.2.1", Proto::Udp);
        let ns2 = ep("192.0.2.2", Proto::Udp);
        for _ in 0..20 {
            sel.record_success(ns1, 7.0, now());
        }
        for _ in 0..20 {
            sel.record_success(ns2, 20.0, now());
        }
        // Make ns1 lossy: 3 timeouts out of ~23 attempts.
        for _ in 0..3 {
            sel.record_timeout(ns1, now());
        }
        let best = sel.best(&[ns1, ns2], now(), 3).unwrap();
        // The reliable server wins even though it is slower.
        assert_eq!(best, ns2, "expected ns2 to win on expected cost");
    }

    #[test]
    fn servfail_penalizes() {
        let mut sel = UpstreamSelector::new(64);
        let a = ep("192.0.2.1", Proto::Udp);
        let b = ep("192.0.2.2", Proto::Udp);
        for _ in 0..10 {
            sel.record_success(a, 10.0, now());
            sel.record_success(b, 10.0, now());
        }
        for _ in 0..8 {
            sel.record_servfail(b, now());
        }
        let best = sel.best(&[a, b], now(), 3).unwrap();
        assert_eq!(best, a);
    }

    #[test]
    fn unknown_candidates_are_ranked() {
        let sel = UpstreamSelector::new(64);
        let a = ep("192.0.2.1", Proto::Udp);
        let b = ep("192.0.2.2", Proto::Tls);
        let ranked = sel.sort_by_cost(&[a, b], now(), 2);
        // UDP's setup cost is lower than TLS's, so UDP ranks first.
        assert_eq!(ranked[0].0, a);
    }

    #[test]
    fn rto_has_floor() {
        let m = PathModel::new(ep("192.0.2.1", Proto::Udp), 1.0);
        assert!(m.rto_ms() >= 25.0);
    }

    #[test]
    fn bounded_paths() {
        let mut sel = UpstreamSelector::new(10);
        for i in 0..50 {
            sel.record_success(
                ep(&format!("192.0.2.{i}"), Proto::Udp),
                10.0,
                now() + i as Ts,
            );
        }
        assert!(sel.len() <= 10);
    }
}
