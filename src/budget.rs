//! The per-resolution resource envelope.
//!
//! # Why a depth limit is not a work limit
//!
//! A recursive resolver's cost is set by the *shape* of the zone data it is
//! willing to chase, and that data is chosen by whoever authored the zone.
//! The natural defence — "do not follow more than `k` levels of delegation"
//! — bounds one dimension and leaves the expensive one open. The NXNSAttack
//! (Shafir, Cohen, Hadas & Herzberg, USENIX Security 2020) exploits exactly
//! that gap: a referral may carry an unbounded number of NS records whose
//! addresses are *not* glued, and each one obliges the resolver to perform
//! its own NS-address resolution. A single client query then fans out into
//! hundreds of sub-resolutions, each of which can fan out again; the paper
//! reports amplification factors well above 1 000× and a resolver-side
//! multiplier that grows with the number of NS names an attacker is willing
//! to publish.
//!
//! The correct response is not a bigger `max_depth` or a smaller timeout —
//! those treat the symptom and tax every honest resolution. It is to make
//! the *total* work of one resolution a bounded, countable resource, and to
//! refuse to start any step that would exceed it.
//!
//! # The envelope
//!
//! [`FetchBudget`] tracks six counters for exactly one client query (plus
//! every sub-resolution that query causes):
//!
//! | counter | what it bounds |
//! |---------|----------------|
//! | delegation depth | how far down the tree we will walk |
//! | NS names per referral | the fan-out of one referral |
//! | glue addresses per referral | how many addresses one referral may name |
//! | NS-address lookups | how many *extra* resolutions referrals may trigger |
//! | sub-queries | total upstream messages |
//! | bytes | total wire bytes in and out |
//!
//! The wall-clock limit is not here: it needs a monotonic clock, which the
//! `no_std` core does not have. The resolver pairs this budget with its own
//! deadline, and both must hold.
//!
//! # Referral admission
//!
//! [`FetchBudget::admit_referral`] is the NXNS gate. It is intentionally
//! *not* a heuristic threshold: it enforces the RFC 9471 requirement that a
//! delegation be usable, by demanding that a referral which needs
//! address resolution carry glue for a meaningful fraction of its
//! nameservers. A referral that names 300 servers and glues none of them is
//! not a delegation the resolver can use; treating it as one is what turns
//! an attacker's zone into our bandwidth bill.

use core::fmt;

/// The limits of one resolution.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FetchLimits {
    /// Maximum delegation steps from the root.
    pub max_delegation_depth: u32,
    /// Maximum NS names accepted from a single referral.
    pub max_ns_names: u32,
    /// Maximum glue addresses accepted from a single referral.
    pub max_glue_addresses: u32,
    /// Maximum NS-address resolutions a single query may trigger. This is
    /// the counter the NXNS amplification actually consumes.
    pub max_ns_address_lookups: u32,
    /// Maximum upstream messages a single query may cause (all kinds).
    pub max_subqueries: u32,
    /// Maximum total wire bytes (sent + received) a single query may cause.
    pub max_bytes: u64,
    /// Minimum fraction of a referral's NS names that must be covered by
    /// glue before a referral is accepted. `0.0` disables the check.
    pub min_glue_fraction: f64,
    /// A referral with at most this many NS names is always usable, glue or
    /// not: a two-server delegation with no glue is normal operation, not an
    /// attack, and rejecting it would break real zones.
    pub small_referral_ns: u32,
}

impl Default for FetchLimits {
    fn default() -> Self {
        Self {
            max_delegation_depth: 32,
            max_ns_names: 13,
            max_glue_addresses: 64,
            max_ns_address_lookups: 32,
            max_subqueries: 96,
            max_bytes: 1 << 20,
            min_glue_fraction: 0.5,
            small_referral_ns: 2,
        }
    }
}

impl FetchLimits {
    /// The limits of a `no_std`-only build with no networking: everything
    /// bounded at zero, so any attempt to spend is refused. Used as the
    /// "budget not configured" sentinel.
    pub fn none() -> Self {
        Self {
            max_delegation_depth: 0,
            max_ns_names: 0,
            max_glue_addresses: 0,
            max_ns_address_lookups: 0,
            max_subqueries: 0,
            max_bytes: 0,
            min_glue_fraction: 1.0,
            small_referral_ns: 0,
        }
    }
}

/// A counter that ran out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Exhausted {
    /// Delegation depth.
    Depth,
    /// NS names in one referral.
    NsNames,
    /// Glue addresses in one referral.
    GlueAddresses,
    /// NS-address resolutions for the whole query.
    NsAddressLookups,
    /// Upstream messages for the whole query.
    Subqueries,
    /// Wire bytes for the whole query.
    Bytes,
}

impl Exhausted {
    /// A short stable name, for logs and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            Exhausted::Depth => "depth",
            Exhausted::NsNames => "ns-names",
            Exhausted::GlueAddresses => "glue-addresses",
            Exhausted::NsAddressLookups => "ns-address-lookups",
            Exhausted::Subqueries => "subqueries",
            Exhausted::Bytes => "bytes",
        }
    }
}

impl fmt::Display for Exhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "resolution budget exhausted: {}", self.as_str())
    }
}

/// Why a referral was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReferralRejected {
    /// The referral named more NS records than the limit allows.
    TooManyNs,
    /// The referral needs address resolution for more NS names than it can
    /// glue, which is the NXNS shape.
    InsufficientGlue,
}

impl ReferralRejected {
    /// A short stable name, for logs and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            ReferralRejected::TooManyNs => "too-many-ns",
            ReferralRejected::InsufficientGlue => "insufficient-glue",
        }
    }
}

/// The admission decision for one referral.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReferralAdmission {
    /// Proceed, spending at most the returned number of NS-address lookups.
    Accept {
        /// NS names that will be used from this referral.
        ns_names: u32,
        /// Glue addresses that will be used from this referral.
        glue_addresses: u32,
        /// NS-address resolutions this referral may trigger.
        address_lookups: u32,
    },
    /// Refuse the referral; it is not a usable delegation.
    Reject(ReferralRejected),
}

/// The work accounting of one resolution.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Work {
    /// Delegation steps taken.
    pub delegations: u32,
    /// Referrals seen (accepted or not).
    pub referrals: u32,
    /// Referrals refused by the NXNS gate.
    pub referrals_refused: u32,
    /// NS names consumed.
    pub ns_names: u32,
    /// Glue addresses consumed.
    pub glue_addresses: u32,
    /// NS-address resolutions performed.
    pub ns_address_lookups: u32,
    /// Upstream messages sent.
    pub subqueries: u32,
    /// Wire bytes sent and received.
    pub bytes: u64,
}

impl Work {
    /// The NS-resolution amplification factor: how many address lookups each
    /// referral bought. A well-behaved internet sits near 1; an NXNS-style
    /// adversary pushes it toward `max_ns_names`.
    pub fn ns_amplification(&self) -> f64 {
        if self.referrals == 0 {
            0.0
        } else {
            self.ns_address_lookups as f64 / self.referrals as f64
        }
    }
}

/// A bounded, countable work envelope for one resolution.
#[derive(Clone, Debug)]
pub struct FetchBudget {
    limits: FetchLimits,
    work: Work,
}

impl FetchBudget {
    /// A fresh budget with the given limits.
    pub fn new(limits: FetchLimits) -> Self {
        Self {
            limits,
            work: Work::default(),
        }
    }

    /// The limits.
    pub fn limits(&self) -> &FetchLimits {
        &self.limits
    }

    /// What has been spent so far.
    pub fn spent(&self) -> &Work {
        &self.work
    }

    /// Whether any work at all is permitted. A budget built from
    /// [`FetchLimits::none`] refuses everything.
    pub fn is_enabled(&self) -> bool {
        self.limits.max_subqueries > 0
    }

    /// Charge one delegation step.
    pub fn spend_delegation(&mut self) -> Result<u32, Exhausted> {
        if self.work.delegations >= self.limits.max_delegation_depth {
            return Err(Exhausted::Depth);
        }
        self.work.delegations += 1;
        Ok(self.work.delegations)
    }

    /// Charge one upstream message.
    pub fn spend_subquery(&mut self) -> Result<(), Exhausted> {
        if self.work.subqueries >= self.limits.max_subqueries {
            return Err(Exhausted::Subqueries);
        }
        self.work.subqueries += 1;
        Ok(())
    }

    /// Charge one NS-address resolution. This is the counter an NXNS
    /// adversary consumes, so it is bounded separately from
    /// [`FetchBudget::spend_subquery`] as well as by it.
    pub fn spend_ns_address_lookup(&mut self, n: u32) -> Result<(), Exhausted> {
        if self.work.ns_address_lookups.saturating_add(n) > self.limits.max_ns_address_lookups {
            return Err(Exhausted::NsAddressLookups);
        }
        self.work.ns_address_lookups += n;
        Ok(())
    }

    /// Charge wire bytes. `n` counts both directions, because the cheaper
    /// direction for the attacker is the one we must pay to receive.
    pub fn spend_bytes(&mut self, n: u64) -> Result<(), Exhausted> {
        if self.work.bytes.saturating_add(n) > self.limits.max_bytes {
            return Err(Exhausted::Bytes);
        }
        self.work.bytes += n;
        Ok(())
    }

    /// The NXNS gate: decide whether a referral is usable, and at what cost.
    ///
    /// `ns_count` is the number of NS records in the referral; `glue_count`
    /// is how many distinct addresses for those names arrived in the
    /// additional section; `ns_with_glue` is how many of the NS *names* have
    /// at least one address already, which is what makes a name free.
    pub fn admit_referral(
        &mut self,
        ns_count: u32,
        glue_count: u32,
        ns_with_glue: u32,
    ) -> ReferralAdmission {
        self.work.referrals += 1;
        let lim = &self.limits;

        if ns_count > lim.max_ns_names {
            self.work.referrals_refused += 1;
            return ReferralAdmission::Reject(ReferralRejected::TooManyNs);
        }

        // Names that must be resolved for this referral to be usable.
        let unresolved = ns_count.saturating_sub(ns_with_glue.min(ns_count));
        // A delegation with few servers is normal without glue; a large one
        // without glue is the NXNS shape, because the absence of glue is
        // what forces the resolver to do the extra work.
        if ns_count > lim.small_referral_ns && lim.min_glue_fraction > 0.0 {
            let covered = ns_count - unresolved;
            let fraction = covered as f64 / ns_count as f64;
            if fraction + 1e-9 < lim.min_glue_fraction {
                self.work.referrals_refused += 1;
                return ReferralAdmission::Reject(ReferralRejected::InsufficientGlue);
            }
        }

        let glue = glue_count.min(lim.max_glue_addresses);
        let address_lookups = unresolved.min(lim.max_ns_address_lookups);
        self.work.ns_names += ns_count;
        self.work.glue_addresses += glue;
        ReferralAdmission::Accept {
            ns_names: ns_count,
            glue_addresses: glue,
            address_lookups,
        }
    }
}

impl fmt::Display for Work {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "work(depth={} referrals={} refused={} ns={} glue={} ns_lookups={} subq={} bytes={})",
            self.delegations,
            self.referrals,
            self.referrals_refused,
            self.ns_names,
            self.glue_addresses,
            self.ns_address_lookups,
            self.subqueries,
            self.bytes
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_is_bounded() {
        let mut b = FetchBudget::new(FetchLimits {
            max_delegation_depth: 3,
            ..FetchLimits::default()
        });
        for i in 1..=3 {
            assert_eq!(b.spend_delegation(), Ok(i));
        }
        assert_eq!(b.spend_delegation(), Err(Exhausted::Depth));
        assert_eq!(b.spent().delegations, 3);
    }

    #[test]
    fn subqueries_and_bytes_are_bounded() {
        let mut b = FetchBudget::new(FetchLimits {
            max_subqueries: 2,
            max_bytes: 100,
            ..FetchLimits::default()
        });
        assert!(b.spend_subquery().is_ok());
        assert!(b.spend_subquery().is_ok());
        assert_eq!(b.spend_subquery(), Err(Exhausted::Subqueries));
        assert!(b.spend_bytes(60).is_ok());
        assert!(b.spend_bytes(40).is_ok());
        assert_eq!(b.spend_bytes(1), Err(Exhausted::Bytes));
        // Saturating arithmetic: a huge request must not overflow into a
        // passing budget.
        let mut b = FetchBudget::new(FetchLimits::default());
        assert_eq!(b.spend_bytes(u64::MAX), Err(Exhausted::Bytes));
    }

    #[test]
    fn ns_address_lookups_are_bounded_separately() {
        let mut b = FetchBudget::new(FetchLimits {
            max_ns_address_lookups: 5,
            ..FetchLimits::default()
        });
        assert!(b.spend_ns_address_lookup(3).is_ok());
        assert!(b.spend_ns_address_lookup(2).is_ok());
        assert_eq!(
            b.spend_ns_address_lookup(1),
            Err(Exhausted::NsAddressLookups)
        );
        assert_eq!(b.spent().ns_address_lookups, 5);
    }

    /// The NXNS shape: many NS names, no glue. It must be refused, and it
    /// must be refused *before* any address lookup is charged.
    #[test]
    fn nxns_shaped_referral_is_refused() {
        let mut b = FetchBudget::new(FetchLimits::default());
        match b.admit_referral(12, 0, 0) {
            ReferralAdmission::Reject(r) => assert_eq!(r, ReferralRejected::InsufficientGlue),
            other => panic!("expected refusal, got {other:?}"),
        }
        assert_eq!(b.spent().referrals_refused, 1);
        assert_eq!(b.spent().ns_address_lookups, 0);
    }

    #[test]
    fn oversized_referral_is_refused() {
        let mut b = FetchBudget::new(FetchLimits::default());
        match b.admit_referral(500, 500, 500) {
            ReferralAdmission::Reject(r) => assert_eq!(r, ReferralRejected::TooManyNs),
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn honest_referral_is_accepted() {
        let mut b = FetchBudget::new(FetchLimits::default());
        // 3 servers, all glued: normal.
        let a = b.admit_referral(3, 3, 3);
        assert!(matches!(
            a,
            ReferralAdmission::Accept {
                address_lookups: 0,
                ..
            }
        ));
        // 4 servers with half glued: usable, 2 lookups.
        let a = b.admit_referral(4, 3, 2);
        match a {
            ReferralAdmission::Accept {
                address_lookups, ..
            } => assert_eq!(address_lookups, 2),
            other => panic!("expected accept, got {other:?}"),
        }
        assert_eq!(b.spent().referrals, 2);
        assert_eq!(b.spent().referrals_refused, 0);
    }

    /// A two-server delegation with no glue is ordinary DNS; rejecting it
    /// would break real zones. The `small_referral_ns` escape hatch exists
    /// precisely for this.
    #[test]
    fn small_glueless_delegation_is_still_usable() {
        let mut b = FetchBudget::new(FetchLimits::default());
        let a = b.admit_referral(2, 0, 0);
        match a {
            ReferralAdmission::Accept {
                address_lookups, ..
            } => assert_eq!(address_lookups, 2),
            other => panic!("expected accept, got {other:?}"),
        }
    }

    #[test]
    fn amplification_is_measurable() {
        let mut b = FetchBudget::new(FetchLimits::default());
        // Three small delegations that legitimately carry no glue: each
        // costs its own NS count in address lookups.
        for _ in 0..3 {
            match b.admit_referral(2, 0, 0) {
                ReferralAdmission::Accept {
                    address_lookups: 2, ..
                } => {
                    // The referral *grants* the lookups; the caller charges
                    // them when it actually performs them, which is what
                    // makes the counter reflect real work rather than
                    // intent.
                    assert!(b.spend_ns_address_lookup(2).is_ok());
                }
                other => panic!("expected accept, got {other:?}"),
            }
        }
        assert!((b.spent().ns_amplification() - 2.0).abs() < 1e-12);
        // The NXNS shape adds no amplification at all, because it is
        // refused before any lookup is charged — that is the whole point of
        // gating on the referral rather than on the result.
        let before = b.spent().ns_address_lookups;
        assert!(matches!(
            b.admit_referral(8, 0, 0),
            ReferralAdmission::Reject(ReferralRejected::InsufficientGlue)
        ));
        assert_eq!(b.spent().ns_address_lookups, before);
    }

    #[test]
    fn disabled_budget_refuses_everything() {
        let mut b = FetchBudget::new(FetchLimits::none());
        assert!(!b.is_enabled());
        assert_eq!(b.spend_delegation(), Err(Exhausted::Depth));
        assert_eq!(b.spend_subquery(), Err(Exhausted::Subqueries));
    }
}
