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

/// The RTT assumed for a path with no measurements. It is the optimistic
/// end of the range published for public DNS servers, so an unmeasured
/// server ranks ahead of a measured one and gets probed — and because a
/// failed probe now creates a model (see [`UpstreamSelector::record_timeout`]),
/// a bad server is demoted after exactly one try.
pub const ASSUMED_RTT_MS: f64 = 40.0;

/// Paths idle for longer than this are dropped first when the path table
/// is full. An hour of silence means the server is no longer on any live
/// delegation path we observed.
pub const PATH_RETENTION_SECS: Ts = 3600;
/// Eviction stride for a path table full of freshly-measured entries.
pub const EVICT_STRIDE: usize = 8;

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

    /// A stable 64-bit identifier for this endpoint, for use as a rendezvous
    /// candidate id.
    ///
    /// The id must be derived from the endpoint's *content* rather than from
    /// its position in a list. A positional id would look fine until a server
    /// was withdrawn, at which point every later id would shift and the whole
    /// fleet would reshuffle — the exact defect
    /// [`crate::rendezvous`] exists to avoid.
    ///
    /// The mixing is SipHash-2-4 under fixed, public constants: what is needed
    /// here is avalanche (two addresses differing in one octet must produce
    /// unrelated ids, or the lottery would systematically favour whichever half
    /// of the address space sorts low), and SipHash is designed for that. The
    /// *secrecy* in a rendezvous selection comes from the key, not from this
    /// id, so a public function is the right tool.
    pub fn affinity_id(&self) -> u64 {
        const K0: u64 = 0x9e37_79b9_7f4a_7c15;
        const K1: u64 = 0xbf58_476d_1ce4_e5b9;
        let mut buf: [u8; 19] = [0u8; 19];
        let mut n = 0usize;
        if let Some(b) = buf.get_mut(n) {
            *b = self.proto as u8;
            n += 1;
        }
        for b in self.port.to_be_bytes() {
            if let Some(slot) = buf.get_mut(n) {
                *slot = b;
                n += 1;
            }
        }
        match self.ip {
            core::net::IpAddr::V4(v4) => {
                for b in v4.octets() {
                    if let Some(slot) = buf.get_mut(n) {
                        *slot = b;
                        n += 1;
                    }
                }
            }
            core::net::IpAddr::V6(v6) => {
                for b in v6.octets() {
                    if let Some(slot) = buf.get_mut(n) {
                        *slot = b;
                        n += 1;
                    }
                }
            }
        }
        crate::prng::siphash24(K0, K1, buf.get(..n).unwrap_or(&[]))
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
        let path = self.path_mut(ep, rtt_ms, now);
        path.record_success(rtt_ms, now);
    }

    /// Record a timeout.
    ///
    /// A timeout on a path we have never measured is *the* first thing we
    /// learn about it, so it must create the model: dropping the
    /// observation would leave a black-holed server ranked by the
    /// optimistic prior forever, and the resolver would keep dialling it
    /// first on every query.
    pub fn record_timeout(&mut self, ep: Endpoint, now: Ts) {
        let path = self.path_mut(ep, ASSUMED_RTT_MS, now);
        path.record_timeout(now);
    }

    /// Record a SERVFAIL.
    pub fn record_servfail(&mut self, ep: Endpoint, now: Ts) {
        let path = self.path_mut(ep, ASSUMED_RTT_MS, now);
        path.record_servfail(now);
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

    /// Candidates sorted by expected cost, cheapest first.
    ///
    /// A candidate with no history is ranked by a prior *below* what a
    /// measured path costs: the assumption is one clean RTT
    /// ([`ASSUMED_RTT_MS`]) with no loss and no SERVFAIL, i.e. the best case
    /// this protocol can do. An unmeasured server is therefore probed once
    /// and then ranked by what it actually did.
    pub fn sort_by_cost(
        &self,
        candidates: &[Endpoint],
        now: Ts,
        retransmit_budget: u32,
    ) -> Vec<(Endpoint, f64)> {
        let _ = now;
        let mut ranked: Vec<(Endpoint, f64)> = candidates
            .iter()
            .map(|&ep| {
                let cost = match self.paths.get(&ep) {
                    Some(p) => p.expected_cost_ms(retransmit_budget),
                    None => ASSUMED_RTT_MS + ep.proto.setup_rtts() * ASSUMED_RTT_MS,
                };
                (ep, cost)
            })
            .collect();
        ranked.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(core::cmp::Ordering::Equal));
        ranked
    }

    /// Candidates ranked by expected cost, with a band of near-equal ones
    /// permuted by a keyed rendezvous lottery.
    ///
    /// [`Self::sort_by_cost`] breaks ties by the order the caller happened to
    /// enumerate the candidates in. That is not neutral: every resolver in a
    /// fleet holding the same delegation gets the same candidates, computes the
    /// same costs, and therefore converges on the **same** server — and stays
    /// there, because the measurement it takes confirms the choice. A single
    /// authoritative's server set is served by every resolver in the fleet as
    /// if it were one machine, which is the opposite of what a redundant set is
    /// for.
    ///
    /// The fix is not "randomise the order". A purely random choice would
    /// discard the cost model, and it would also make a name's server
    /// non-reproducible, so a retry would land somewhere else and the
    /// measurement attached to the first attempt would be attributed to the
    /// wrong path. What this does instead:
    ///
    /// * candidates whose cost is **outside** the band keep their exact cost
    ///   order — a server that is genuinely more expensive is not made
    ///   reachable by lottery;
    /// * candidates **inside** the band are, by construction, indistinguishable
    ///   at the resolution of the measurements, so the lottery is applied
    ///   among equals with equal weight;
    /// * the lottery is a pure function of `(key, subject)`, so the same name
    ///   picks the same server on every resolver in the fleet and on every
    ///   retry, while two different names spread across the band.
    ///
    /// The key comes from the deployment's secret entropy, so an observer who
    /// can see the query cannot compute which server we will contact. That is
    /// the security half: an attacker who could compute it would know exactly
    /// which path to pre-position a spoofing attempt against.
    ///
    /// A candidate-id collision inside the band would silently collapse two
    /// servers into one lottery slot, so it is detected and the ranking falls
    /// back to plain cost order rather than quietly narrowing the set.
    pub fn rank_with_affinity(
        &self,
        candidates: &[Endpoint],
        now: Ts,
        retransmit_budget: u32,
        band: crate::rendezvous::CostBand,
        affinity: &crate::rendezvous::RendezvousKey,
        subject: &[u8],
    ) -> Vec<(Endpoint, f64)> {
        let ranked = self.sort_by_cost(candidates, now, retransmit_budget);
        if ranked.len() < 2 {
            return ranked;
        }
        let min_cost = match ranked.first() {
            Some(&(_, c)) => c,
            None => return ranked,
        };
        let limit = band.limit(min_cost);
        let in_band = ranked.iter().take_while(|(_, c)| *c <= limit).count();
        if in_band < 2 {
            return ranked;
        }
        let head = match ranked.get(..in_band) {
            Some(h) => h,
            None => return ranked,
        };
        let items: Vec<(u64, f64)> = head
            .iter()
            .map(|(ep, cost)| {
                // The weight *is* the measurement. A band makes servers
                // comparable; it does not make them identical, and throwing the
                // cost away inside the band — which is what an equal weight
                // does — discards the only reason there is a cost model at all.
                //
                // `w = cost_min / cost` is the inverse of measured cost, so a
                // server that is 10 % dearer is picked 10 % less often. It is
                // bounded above by 1 by construction (nothing in the band is
                // cheaper than the minimum), so no candidate can be made
                // arbitrarily dominant by a fluke measurement, and the floor
                // keeps a pathological cost from suppressing a candidate
                // entirely — a server that is *in* the band has been declared
                // usable, and a weight of zero would contradict that.
                let w = if *cost > 0.0 && min_cost > 0.0 {
                    (min_cost / cost).clamp(1e-3, 1.0)
                } else {
                    1.0
                };
                (ep.affinity_id(), w)
            })
            .collect();
        {
            let mut ids: Vec<u64> = items.iter().map(|&(id, _)| id).collect();
            ids.sort_unstable();
            ids.dedup();
            if ids.len() != items.len() {
                return ranked;
            }
        }
        let order = affinity.rank(subject, &items);
        let mut out: Vec<(Endpoint, f64)> = Vec::with_capacity(ranked.len());
        for idx in order {
            if let Some(&pair) = head.get(idx) {
                out.push(pair);
            }
        }
        out.extend(ranked.into_iter().skip(in_band));
        out
    }

    /// Whether [`Self::rank_with_affinity`] would actually permute anything for
    /// this candidate set.
    ///
    /// Exposed so a deployment can *measure* whether the lottery is doing work.
    /// A band that admits only one candidate is a policy that silently does
    /// nothing, and "nothing happened" is indistinguishable from "the feature
    /// is off" unless something counts it. This is the predicate the resolver
    /// reports as `affinity_lotteries`.
    pub fn affinity_applies(
        &self,
        candidates: &[Endpoint],
        now: Ts,
        retransmit_budget: u32,
        band: crate::rendezvous::CostBand,
    ) -> bool {
        let ranked = self.sort_by_cost(candidates, now, retransmit_budget);
        if ranked.len() < 2 {
            return false;
        }
        let min_cost = match ranked.first() {
            Some(&(_, c)) => c,
            None => return false,
        };
        let limit = band.limit(min_cost);
        let in_band = ranked.iter().take_while(|(_, c)| *c <= limit).count();
        if in_band < 2 {
            return false;
        }
        let mut ids: Vec<u64> = ranked
            .iter()
            .take(in_band)
            .map(|(ep, _)| ep.affinity_id())
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids.len() == in_band
    }

    fn path_mut(&mut self, ep: Endpoint, rtt_ms: f64, now: Ts) -> &mut PathModel {
        if !self.paths.contains_key(&ep) {
            if self.paths.len() >= self.max_paths {
                let stale_before = now.saturating_sub(PATH_RETENTION_SECS * 1_000_000_000);
                crate::bounded::evict_for_capacity(
                    &mut self.paths,
                    stale_before,
                    EVICT_STRIDE,
                    |p| p.last_seen,
                );
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

    /// Four servers measured 20.0 / 20.5 / 21.0 / 60.0 ms. The first three are
    /// inside a 10 % / 2 ms band; the fourth is not.
    fn cluster() -> (UpstreamSelector, [Endpoint; 4]) {
        let mut sel = UpstreamSelector::new(64);
        let eps = [
            ep("192.0.2.11", Proto::Udp),
            ep("192.0.2.12", Proto::Udp),
            ep("192.0.2.13", Proto::Udp),
            ep("192.0.2.99", Proto::Udp),
        ];
        for _ in 0..40 {
            sel.record_success(eps[0], 20.0, now());
            sel.record_success(eps[1], 20.5, now());
            sel.record_success(eps[2], 21.0, now());
            sel.record_success(eps[3], 60.0, now());
        }
        (sel, eps)
    }

    fn subject(i: usize) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"name");
        v.extend_from_slice(&(i as u64).to_le_bytes());
        v
    }

    #[test]
    fn affinity_never_promotes_a_server_that_is_measurably_worse() {
        let (sel, eps) = cluster();
        let key = crate::rendezvous::RendezvousKey::from_words(1, 2);
        let band = crate::rendezvous::CostBand::default();
        for i in 0..512 {
            let ranked = sel.rank_with_affinity(&eps, now(), 2, band, &key, &subject(i));
            assert_eq!(ranked.len(), eps.len());
            assert_eq!(
                ranked.last().map(|(e, _)| *e),
                Some(eps[3]),
                "the out-of-band server must stay last for every subject"
            );
        }
    }

    #[test]
    fn affinity_spreads_a_fleet_over_indistinguishable_servers() {
        // The defect being fixed: without affinity the head of the ranking is
        // the same endpoint for every subject, because the tie is broken by the
        // input order. With it, all three in-band servers take a real share.
        let (sel, eps) = cluster();
        let key = crate::rendezvous::RendezvousKey::from_words(
            0x1122_3344_5566_7788,
            0x99aa_bbcc_ddee_ff00,
        );
        let band = crate::rendezvous::CostBand::default();
        let mut head_counts = [0usize; 4];
        const N: usize = 4096;
        for i in 0..N {
            let ranked = sel.rank_with_affinity(&eps, now(), 2, band, &key, &subject(i));
            let head = ranked.first().map(|(e, _)| *e).unwrap();
            for (slot, e) in head_counts.iter_mut().zip(eps.iter()) {
                if *e == head {
                    *slot += 1;
                }
            }
        }
        assert_eq!(head_counts[3], 0, "an out-of-band server took the head");
        for (idx, &count) in head_counts.iter().take(3).enumerate() {
            let share = count as f64 / N as f64;
            assert!(
                (0.2..0.47).contains(&share),
                "in-band server {idx} took {share:.3} of the head slots"
            );
        }
        // And the plain cost ranking is the control: one server takes all of it.
        let plain = sel.sort_by_cost(&eps, now(), 2);
        assert_eq!(plain.first().map(|(e, _)| *e), Some(eps[0]));
    }

    #[test]
    fn the_lottery_weights_the_band_by_measured_cost_rather_than_uniformly() {
        // A band declares servers *comparable*; it does not declare them
        // identical. An equal-weight lottery would give each a quarter and
        // throw away the cost model inside the band, so this asserts the thing
        // that distinguishes the two: the order of the shares must follow the
        // order of the measured costs.
        //
        // The band is widened on purpose. At the shipping tolerance the weights
        // differ by a couple of percent, which is correct but needs millions of
        // draws to separate from noise; widening it makes the mechanism
        // observable without changing it.
        let mut sel = UpstreamSelector::new(64);
        let eps = [
            ep("192.0.2.21", Proto::Udp),
            ep("192.0.2.22", Proto::Udp),
            ep("192.0.2.23", Proto::Udp),
            ep("192.0.2.24", Proto::Udp),
        ];
        for _ in 0..200 {
            sel.record_success(eps[0], 20.0, now());
            sel.record_success(eps[1], 22.0, now());
            sel.record_success(eps[2], 25.0, now());
            sel.record_success(eps[3], 28.0, now());
        }
        let key = crate::rendezvous::RendezvousKey::from_words(
            0x0f1e_2d3c_4b5a_6978,
            0x8877_6655_4433_2211,
        );
        let band = crate::rendezvous::CostBand {
            percent: 50.0,
            absolute_ms: 0.0,
        };
        let mut head_counts = [0usize; 4];
        const N: usize = 60_000;
        for i in 0..N {
            let ranked = sel.rank_with_affinity(&eps, now(), 2, band, &key, &subject(i));
            let head = ranked.first().map(|(e, _)| *e).unwrap();
            for (slot, e) in head_counts.iter_mut().zip(eps.iter()) {
                if *e == head {
                    *slot += 1;
                }
            }
        }
        let shares: Vec<f64> = head_counts.iter().map(|&c| c as f64 / N as f64).collect();
        // Strictly decreasing: the cheapest server takes the most, the dearest
        // the least, in the same order as the measured cost.
        for w in shares.windows(2) {
            assert!(
                w[0] > w[1],
                "shares must follow measured cost, got {shares:?}"
            );
        }
        // And the spread is real rather than a rounding artefact.
        assert!(
            shares.first().copied().unwrap_or(0.0) - shares.last().copied().unwrap_or(0.0) > 0.05,
            "the weighting barely moved anything: {shares:?}"
        );
        // An equal-weight lottery would put every share near 0.25; this one
        // must not.
        assert!(
            shares.iter().any(|s| (s - 0.25).abs() > 0.02),
            "the shares look uniform, so the weights did nothing: {shares:?}"
        );
    }

    #[test]
    fn affinity_is_reproducible_for_a_name_and_varies_between_names() {
        let (sel, eps) = cluster();
        let key = crate::rendezvous::RendezvousKey::from_words(7, 11);
        let band = crate::rendezvous::CostBand::default();
        // Reproducible: the same subject, twice, on two selector instances.
        let (sel2, eps2) = cluster();
        for i in 0..64 {
            let a = sel.rank_with_affinity(&eps, now(), 2, band, &key, &subject(i));
            let b = sel2.rank_with_affinity(&eps2, now(), 2, band, &key, &subject(i));
            assert_eq!(a, b, "the ranking must not depend on any local state");
        }
        // And a different secret gives a different assignment, which is the
        // property an off-path attacker would need to break.
        let other = crate::rendezvous::RendezvousKey::from_words(13, 17);
        let mut differences = 0;
        for i in 0..256 {
            let a = sel.rank_with_affinity(&eps, now(), 2, band, &key, &subject(i));
            let b = sel.rank_with_affinity(&eps, now(), 2, band, &other, &subject(i));
            if a != b {
                differences += 1;
            }
        }
        assert!(
            differences > 100,
            "only {differences} of 256 subjects differed"
        );
    }

    #[test]
    fn affinity_preserves_the_candidate_set_exactly() {
        let (sel, eps) = cluster();
        let key = crate::rendezvous::RendezvousKey::from_words(3, 5);
        let band = crate::rendezvous::CostBand::default();
        let mut seen = Vec::new();
        let ranked = sel.rank_with_affinity(&eps, now(), 2, band, &key, &subject(1));
        for (e, _) in &ranked {
            seen.push(*e);
        }
        seen.sort();
        let mut want = eps.to_vec();
        want.sort();
        assert_eq!(seen, want, "the lottery must reorder, never add or drop");
    }

    #[test]
    fn affinity_is_inert_when_the_costs_are_not_close() {
        let mut sel = UpstreamSelector::new(64);
        let a = ep("192.0.2.1", Proto::Udp);
        let b = ep("192.0.2.2", Proto::Udp);
        for _ in 0..40 {
            sel.record_success(a, 5.0, now());
            sel.record_success(b, 200.0, now());
        }
        let key = crate::rendezvous::RendezvousKey::from_words(1, 1);
        let band = crate::rendezvous::CostBand::default();
        for i in 0..64 {
            let ranked = sel.rank_with_affinity(&[a, b], now(), 2, band, &key, &subject(i));
            assert_eq!(ranked.first().map(|(e, _)| *e), Some(a));
        }
    }

    #[test]
    fn affinity_handles_a_single_candidate_and_none() {
        let (sel, eps) = cluster();
        let key = crate::rendezvous::RendezvousKey::from_words(1, 1);
        let band = crate::rendezvous::CostBand::default();
        let one = sel.rank_with_affinity(&eps[..1], now(), 2, band, &key, &subject(0));
        assert_eq!(one.len(), 1);
        assert_eq!(one.first().map(|(e, _)| *e), Some(eps[0]));
        assert!(sel
            .rank_with_affinity(&[], now(), 2, band, &key, &subject(0))
            .is_empty());
    }

    #[test]
    fn endpoint_ids_differ_for_endpoints_that_differ_in_one_octet() {
        // Poor avalanche here would bias the lottery towards one half of the
        // address space, which is the failure mode that looks like it works.
        let mut ids = alloc::collections::BTreeSet::new();
        for last in 1u8..=32 {
            let e = ep(&alloc::format!("192.0.2.{last}"), Proto::Udp);
            assert!(ids.insert(e.affinity_id()), "id collision at .{last}");
        }
        // Protocol and port are part of the identity: the same address reached
        // over a different transport is a different path with different
        // measured behaviour, and must be a different lottery candidate.
        assert!(ids.insert(ep("192.0.2.1", Proto::Tcp).affinity_id()));
        assert!(
            ids.insert(Endpoint::new("192.0.2.1".parse().unwrap(), 5353, Proto::Udp).affinity_id())
        );
        // High and low bits must both vary, or a hash-space ordering would be
        // an address ordering.
        let lows: alloc::collections::BTreeSet<u8> = (1u8..=16)
            .map(|l| (ep(&alloc::format!("192.0.2.{l}"), Proto::Udp).affinity_id() & 0xff) as u8)
            .collect();
        assert!(lows.len() > 8, "low byte barely varies: {lows:?}");
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
