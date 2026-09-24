//! Fake-IP allocation (Clash `enhanced-mode: fake-ip`).
//!
//! In fake-IP mode the resolver hands the client a synthetic address from a
//! reserved block instead of the real one. The proxy then sees a connection
//! to that address, reverses the mapping back to the domain name, and routes
//! on the *name* — which is the whole point: a routing rule can only match on
//! a domain if the domain survives the trip through the client's socket API,
//! and a socket API only carries an address.
//!
//! # The mapping is the contract
//!
//! Two properties matter more than allocation speed, because breaking either
//! one breaks live connections:
//!
//! * **Stability.** The same name gets the same address for as long as the
//!   mapping lives. Re-allocating on every query would give one domain a
//!   different address per lookup, and a client that resolved twice — or
//!   followed a redirect and re-resolved — would open two connections that
//!   the proxy sees as two different domains.
//! * **Reversibility.** Every address handed out maps back to exactly one
//!   name. A recycled address that still has live connections is the failure
//!   mode here, so recycling only happens past the entry TTL, and every
//!   recycle is counted so it can be observed rather than guessed at.
//!
//! # The pool recycles, and says how much
//!
//! `maxEntries` bounds memory, and at that bound the pool reclaims the
//! least-recently-used mappings: recency is the only signal available for
//! "probably no longer in use", and the pool keeps answering.
//!
//! The tempting alternative — refuse once full, and let the caller resolve
//! the name for real — is worse *for this deployment*. A real answer means
//! the client dials the true address directly, escaping the proxy and the
//! routing rules with it: the domain silently stops being proxied. A
//! renumbered mapping costs one connection's routing; a leaked connection
//! costs the rule. So the pool recycles, counts every recycle
//! ([`FakeIpPool::evicted`]), and leaves the tuning to `maxEntries` — which
//! should sit comfortably above the working set so recycling stays rare.
//!
//! Stale entries are always chosen first: an entry past its TTL has no live
//! connection by definition, so dropping it is free, while dropping a fresh
//! one is a real (if bounded) risk. Only when *every* entry is fresh does a
//! recency-ordered batch go.
//!
//! # Bounds and bookkeeping
//!
//! Live entries are capped at `min(addresses in range, maxEntries)`. At the
//! cap the pool reclaims through [`crate::bounded::evict_for_capacity`],
//! whose contract — a non-empty map always loses at least one entry — is
//! what lets allocation assume room afterwards. Both maps are rebuilt from
//! the address-keyed one after a sweep rather than patched in place: a
//! running index over two maps is bookkeeping that drifts, and a drifted
//! index means a name mapped to an address nobody owns.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

use crate::bounded::evict_for_capacity;
use crate::cidr::Ipv4Cidr;
use crate::error::{Error, Result};
use crate::name::Name;
use crate::pattern::{parse_all, DomainPattern};
use crate::time::Ts;

/// The reserved block fake-IP uses when none is configured: RFC 2544
/// benchmarking space, which is not routable and which no real answer should
/// ever legitimately contain — so a stray real address from this range is
/// itself a signal that something is wrong.
pub const DEFAULT_FAKE_IP_RANGE: &str = "198.18.0.0/16";

/// The default TTL carried by a synthesized fake-IP answer, in seconds.
///
/// One second, matching the Clash family. A fake-IP answer is not data to be
/// cached — it is a pointer into the pool — and a long TTL lets a client keep
/// using an address whose mapping the pool has since recycled. Short answers
/// also keep the mapping warm, so recycling stays the exception.
pub const DEFAULT_FAKE_IP_ANSWER_TTL: u32 = 1;

/// The default entry lifetime, in seconds.
pub const DEFAULT_FAKE_IP_TTL_SECS: u64 = 3600;

/// Names excluded from fake-IP when `fake-ip-filter` is **absent**.
///
/// Shipping a default list is not a convenience, it is a correctness fix.
/// Fake-IP is not transparent: every name it covers is answered with an
/// address that only means "ask the proxy". For a name the *operating
/// system* uses to decide whether it has a network at all, that answer is a
/// lie the OS believes — Windows reports "no internet", the clock never
/// syncs, and WebRTC never finds a path. mihomo ships a comparable list for
/// exactly these reasons.
///
/// An explicit `"fake-ip-filter": []` disables the list, which is a
/// decision; omitting the key takes these defaults, which is a different
/// statement. Conflating the two would leave a deployment with none of this
/// protection while its config read as if it had some.
///
/// Grouped by what breaks when the entry is missing:
///
/// * **Local names** that must resolve on the local network.
/// * **Captive-portal / connectivity probes** — the OS concludes there is no
///   internet and marks the network as such until the user intervenes.
/// * **NTP and time** hosts — a fake address means the clock never syncs,
///   which then breaks TLS.
/// * **STUN and console NAT checks** — voice, video and games fail to find a
///   path, usually blaming the network.
/// * **Windows NCSI probes**, which also drive "is this a metered
///   connection" decisions.
pub const DEFAULT_FAKE_IP_FILTER: [&str; 24] = [
    // Local and special-use names.
    "*.lan",
    "*.local",
    "*.localhost",
    "*.localdomain",
    "localhost",
    "*.home.arpa",
    "*.invalid",
    "*.test",
    // Captive-portal and connectivity probes.
    "+.msftconnecttest.com",
    "+.msftncsi.com",
    "+.connectivitycheck.gstatic.com",
    "+.connectivitycheck.android.com",
    "+.captive.apple.com",
    // NTP and time. The wildcard forms are the ones mihomo ships; they are
    // why this module supports embedded wildcards at all.
    "time.*.com",
    "time.*.gov",
    "time.*.edu.cn",
    "time.*.apple.com",
    "time.windows.com",
    "time.nist.gov",
    "*.pool.ntp.org",
    // STUN, for voice, video and WebRTC.
    "stun.*.*",
    "*.stun.*.*",
    // Console connectivity and NAT-type checks.
    "*.srv.nintendo.net",
    "*.stun.playstation.net",
];

/// The default cap on live mappings. A `/16` holds 65 535 usable addresses;
/// capping below that keeps a hostile client from pinning the whole block by
/// querying random names.
pub const DEFAULT_FAKE_IP_MAX_ENTRIES: usize = 16_384;

/// Eviction stride for a pool full of fresh entries.
const EVICT_STRIDE: usize = 8;

/// A ceiling on the configured TTL, so a typo cannot make entries immortal
/// (or overflow the nanosecond arithmetic).
const MAX_TTL_SECS: u64 = 7 * 24 * 3600;

/// What to do with a name that asked for an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Allocation {
    /// Hand the client this synthetic address.
    Address(Ipv4Addr),
    /// The name is excluded by `fake-ip-filter`. Resolve it normally.
    Filtered,
}

/// A live fake-IP mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    name: Name,
    created: Ts,
    last_access: Ts,
}

/// Validated fake-IP configuration.
///
/// Separated from [`FakeIpPool`] so configuration can be checked (and
/// reported on) at load time while the mutable pool lives behind the
/// resolver's lock. Parsing is fallible; building from a parsed value is not,
/// because everything that could fail has already been ruled out.
#[derive(Debug, Clone)]
pub struct FakeIpSettings {
    /// The address range.
    pub range: Ipv4Cidr,
    /// Names excluded from fake-IP.
    pub filter: Vec<DomainPattern>,
    /// Entry lifetime in seconds.
    pub ttl_secs: u64,
    /// Cap on live mappings.
    pub max_entries: usize,
    /// TTL carried by a synthesized answer. Distinct from `ttl_secs`: one
    /// bounds how long a *mapping* may live, the other how long a *client*
    /// may reuse the address it was handed.
    pub answer_ttl: u32,
}

impl FakeIpSettings {
    /// Parse and validate configuration.
    ///
    /// `filter` distinguishes *absent* from *empty*, because the two mean
    /// different things and conflating them silently removes the protection
    /// [`DEFAULT_FAKE_IP_FILTER`] exists to provide:
    ///
    /// * `None` — no `fake-ip-filter` was configured, so the built-in list
    ///   applies.
    /// * `Some(list)` — the operator supplied the list; it is used as given,
    ///   even when empty, because an explicit empty list is a decision.
    pub fn parse(
        range: &str,
        filter: Option<&[String]>,
        ttl_secs: u64,
        max_entries: usize,
    ) -> Result<Self> {
        let range = Ipv4Cidr::parse(range)
            .ok_or_else(|| Error::config(alloc::format!("invalid fake-ip range {range:?}")))?;
        if range.len() < 2 {
            return Err(Error::config(alloc::format!(
                "fake-ip range {range} has no usable addresses"
            )));
        }
        if max_entries == 0 {
            return Err(Error::config(
                "fake-ip maxEntries must be at least 1 (0 would disable fake-ip silently)",
            ));
        }
        if ttl_secs == 0 {
            return Err(Error::config(
                "fake-ip ttl must be at least 1 second (0 would expire every mapping \
                 immediately, so no client could ever use one)",
            ));
        }
        Ok(Self {
            range,
            filter: match filter {
                None => parse_all(
                    &DEFAULT_FAKE_IP_FILTER
                        .iter()
                        .map(|s| alloc::string::String::from(*s))
                        .collect::<Vec<_>>(),
                )?,
                Some(list) => parse_all(list)?,
            },
            ttl_secs,
            max_entries,
            answer_ttl: DEFAULT_FAKE_IP_ANSWER_TTL,
        })
    }

    /// Set the TTL carried by synthesized answers.
    pub fn with_answer_ttl(mut self, ttl: u32) -> Self {
        self.answer_ttl = ttl.max(1);
        self
    }

    /// The TTL carried by a synthesized answer.
    pub fn answer_ttl(&self) -> u32 {
        self.answer_ttl
    }

    /// Build the pool this configuration describes.
    pub fn build(&self) -> FakeIpPool {
        FakeIpPool::new(
            self.range,
            self.filter.clone(),
            self.ttl_secs,
            self.max_entries,
        )
    }

    /// The pool's settings with defaults applied, including the built-in
    /// filter.
    pub fn with_defaults() -> Result<Self> {
        Self::parse(
            DEFAULT_FAKE_IP_RANGE,
            None,
            DEFAULT_FAKE_IP_TTL_SECS,
            DEFAULT_FAKE_IP_MAX_ENTRIES,
        )
    }
}

/// The fake-IP pool.
#[derive(Debug)]
pub struct FakeIpPool {
    range: Ipv4Cidr,
    filter: Vec<DomainPattern>,
    ttl_nanos: Ts,
    max_entries: usize,
    /// Next candidate address (host order). Always inside `range`.
    next: u32,
    /// The authoritative map: address to mapping.
    by_ip: BTreeMap<u32, Entry>,
    /// The reverse index: name to address. Rebuilt from `by_ip` after every
    /// sweep, never patched in place.
    by_name: BTreeMap<Name, u32>,
    /// Names turned away by the filter.
    filtered_hits: u64,
    /// Mappings dropped to stay inside the cap.
    evicted: u64,
}

impl FakeIpPool {
    /// Build a pool from raw configuration strings.
    pub fn from_config(
        range: &str,
        filter: Option<&[String]>,
        ttl_secs: u64,
        max_entries: usize,
    ) -> Result<Self> {
        Ok(FakeIpSettings::parse(range, filter, ttl_secs, max_entries)?.build())
    }

    /// Build a pool from already-parsed parts.
    pub fn new(
        range: Ipv4Cidr,
        filter: Vec<DomainPattern>,
        ttl_secs: u64,
        max_entries: usize,
    ) -> Self {
        let first = u32::from(range.network()).wrapping_add(1);
        Self {
            range,
            filter,
            ttl_nanos: ttl_nanos(ttl_secs),
            max_entries: max_entries.max(1),
            next: first,
            by_ip: BTreeMap::new(),
            by_name: BTreeMap::new(),
            filtered_hits: 0,
            evicted: 0,
        }
    }

    /// The pool's address range.
    pub fn range(&self) -> Ipv4Cidr {
        self.range
    }

    /// The number of usable addresses in the range (the network address is
    /// reserved so a mapping is never `x.x.x.0`, which some client stacks
    /// treat as a network identifier rather than a host).
    pub fn address_capacity(&self) -> usize {
        (self.range.len() - 1) as usize
    }

    /// The cap on live mappings.
    pub fn max_entries(&self) -> usize {
        self.max_entries.min(self.address_capacity())
    }

    /// The number of live mappings.
    pub fn len(&self) -> usize {
        self.by_ip.len()
    }

    /// Whether the pool holds no mappings.
    pub fn is_empty(&self) -> bool {
        self.by_ip.is_empty()
    }

    /// The number of names excluded by the filter.
    pub fn filtered_hits(&self) -> u64 {
        self.filtered_hits
    }

    /// The number of mappings dropped to respect the entry cap.
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Whether `ip` is inside the pool's range. Pure range test: it does not
    /// consult the mapping table and does not touch recency. Use this to ask
    /// "did this address come from fake-IP", and [`lookup`](Self::lookup) to
    /// ask "which name owns it".
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        self.range.contains(ip)
    }

    /// Whether `name` is excluded from fake-IP by the filter.
    pub fn is_filtered(&self, name: &Name) -> bool {
        self.filter.iter().any(|p| p.matches(name))
    }

    /// Assign (or re-fetch) the fake address for `name`, refreshing its
    /// recency.
    pub fn allocate(&mut self, name: &Name, now: Ts) -> Result<Allocation> {
        if self.is_filtered(name) {
            self.filtered_hits += 1;
            return Ok(Allocation::Filtered);
        }
        if let Some(&ip) = self.by_name.get(name) {
            if let Some(e) = self.by_ip.get_mut(&ip) {
                e.last_access = now;
            }
            return Ok(Allocation::Address(Ipv4Addr::from(ip)));
        }

        if self.by_ip.len() >= self.max_entries() {
            self.reclaim(now);
        }

        let candidate = self
            .take_address()
            .ok_or_else(|| Error::internal("fake-ip pool reported room but had no free address"))?;
        self.by_ip.insert(
            candidate,
            Entry {
                name: name.clone(),
                created: now,
                last_access: now,
            },
        );
        self.by_name.insert(name.clone(), candidate);
        Ok(Allocation::Address(Ipv4Addr::from(candidate)))
    }

    /// The name that owns `ip`, refreshing its recency.
    pub fn lookup(&mut self, ip: Ipv4Addr, now: Ts) -> Option<Name> {
        let key = u32::from(ip);
        let e = self.by_ip.get_mut(&key)?;
        e.last_access = now;
        Some(e.name.clone())
    }

    /// The name that owns `ip`, without touching recency. For read-only
    /// callers such as a status endpoint.
    pub fn peek(&self, ip: Ipv4Addr) -> Option<&Name> {
        self.by_ip.get(&u32::from(ip)).map(|e| &e.name)
    }

    /// Record a mapping loaded from a snapshot, so restarting does not
    /// renumber the domains a client is still holding addresses for.
    ///
    /// Returns `false` when the address is outside the range or already
    /// owned by another name — a snapshot that disagrees with the configured
    /// range is not something to guess about.
    pub fn restore(&mut self, name: &Name, ip: Ipv4Addr, now: Ts) -> bool {
        if !self.range.contains(ip) {
            return false;
        }
        let key = u32::from(ip);
        if let Some(existing) = self.by_ip.get(&key) {
            if &existing.name != name {
                return false;
            }
        }
        if let Some(&mapped) = self.by_name.get(name) {
            if mapped != key {
                return false;
            }
        }
        self.by_name.insert(name.clone(), key);
        self.by_ip.insert(
            key,
            Entry {
                name: name.clone(),
                created: now,
                last_access: now,
            },
        );
        true
    }

    /// Iterate live mappings, for snapshotting.
    pub fn iter(&self) -> impl Iterator<Item = (&Name, Ipv4Addr)> {
        self.by_ip
            .iter()
            .map(|(ip, e)| (&e.name, Ipv4Addr::from(*ip)))
    }

    /// Drop mappings untouched for longer than the TTL. Returns how many.
    pub fn cleanup_expired(&mut self, now: Ts) -> usize {
        let cutoff = now.saturating_sub(self.ttl_nanos);
        let before = self.by_ip.len();
        self.by_ip.retain(|_, e| e.last_access >= cutoff);
        if self.by_ip.len() != before {
            self.rebuild_name_index();
        }
        before - self.by_ip.len()
    }

    /// Forget a single mapping, e.g. when a domain is removed from a rule set.
    pub fn release(&mut self, name: &Name) -> Option<Ipv4Addr> {
        let ip = self.by_name.remove(name)?;
        self.by_ip.remove(&ip);
        Some(Ipv4Addr::from(ip))
    }

    /// Forget everything.
    pub fn clear(&mut self) {
        self.by_ip.clear();
        self.by_name.clear();
    }

    /// Reclaim space at the cap: stale entries first, then an amortised
    /// stride batch if every entry is still fresh.
    fn reclaim(&mut self, now: Ts) {
        let cutoff = now.saturating_sub(self.ttl_nanos);
        let freed = evict_for_capacity(&mut self.by_ip, cutoff, EVICT_STRIDE, |e| e.last_access);
        if freed > 0 {
            self.evicted += freed as u64;
            self.rebuild_name_index();
        }
    }

    /// Rebuild the name index from the authoritative address index. Rebuilding
    /// rather than removing the evicted keys one by one is deliberate: with
    /// two maps and a sweep that reports only a *count*, an incremental update
    /// is the classic place for the two to disagree.
    fn rebuild_name_index(&mut self) {
        self.by_name.clear();
        for (ip, e) in &self.by_ip {
            self.by_name.insert(e.name.clone(), *ip);
        }
    }

    /// The next free address, scanning at most `len + 1` candidates.
    ///
    /// The bound is a pigeonhole argument, not a heuristic: among `n + 1`
    /// *distinct* candidates at most `n` can be occupied when the pool holds
    /// `n` mappings, so a free one is always found — or the range itself is
    /// exhausted, which the cap already prevents.
    fn take_address(&mut self) -> Option<u32> {
        let limit = self.by_ip.len() + 1;
        for _ in 0..limit {
            let c = self.advance();
            if !self.by_ip.contains_key(&c) {
                return Some(c);
            }
        }
        None
    }

    /// Advance the cursor to the next in-range candidate.
    fn advance(&mut self) -> u32 {
        let first = u32::from(self.range.network()).wrapping_add(1);
        let last = u32::from(self.range.broadcast());
        if self.next < first || self.next > last {
            self.next = first;
        }
        let cur = self.next;
        self.next = if cur >= last { first } else { cur + 1 };
        cur
    }
}

/// Convert a TTL in seconds to nanoseconds, clamped to a sane ceiling.
fn ttl_nanos(secs: u64) -> Ts {
    let secs = secs.min(MAX_TTL_SECS);
    (secs as Ts).saturating_mul(1_000_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    fn now() -> Ts {
        1_700_000_000_000_000_000
    }

    fn name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn pool(range: &str, filter: &[&str], max_entries: usize) -> FakeIpPool {
        let f: Vec<String> = filter.iter().map(|s| (*s).to_string()).collect();
        FakeIpPool::from_config(range, Some(&f), 3600, max_entries).unwrap()
    }

    fn addr(a: Allocation) -> Ipv4Addr {
        match a {
            Allocation::Address(ip) => ip,
            Allocation::Filtered => panic!("expected an address, got Filtered"),
        }
    }

    #[test]
    fn first_allocation_is_the_second_address_in_the_range() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        let ip = addr(p.allocate(&name("a.com"), now()).unwrap());
        assert_eq!(ip, "198.18.0.1".parse::<Ipv4Addr>().unwrap());
        assert!(p.contains(ip));
        assert_eq!(p.len(), 1);
    }

    /// The same name must not get a second address, or a client that
    /// re-resolves opens two connections the proxy reads as two domains.
    #[test]
    fn allocation_is_stable_for_a_name() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        let a = addr(p.allocate(&name("a.com"), now()).unwrap());
        let b = addr(p.allocate(&name("a.com"), now() + 1_000).unwrap());
        assert_eq!(a, b);
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn distinct_names_get_distinct_addresses() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        let a = addr(p.allocate(&name("a.com"), now()).unwrap());
        let b = addr(p.allocate(&name("b.com"), now()).unwrap());
        assert_ne!(a, b);
        assert_eq!(p.len(), 2);
    }

    /// The reverse direction is what makes fake-IP usable at all.
    #[test]
    fn reverse_lookup_recovers_the_name() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        let ip = addr(p.allocate(&name("a.com"), now()).unwrap());
        assert_eq!(p.lookup(ip, now()).unwrap(), name("a.com"));
        assert_eq!(p.peek(ip), Some(&name("a.com")));
        assert!(p.lookup("198.18.0.200".parse().unwrap(), now()).is_none());
        assert!(!p.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn filtered_names_are_not_allocated() {
        let mut p = pool("198.18.0.0/24", &["*.lan", "localhost"], 100);
        assert_eq!(
            p.allocate(&name("printer.lan"), now()).unwrap(),
            Allocation::Filtered
        );
        assert_eq!(
            p.allocate(&name("lan"), now()).unwrap(),
            Allocation::Filtered
        );
        assert_eq!(
            p.allocate(&name("localhost"), now()).unwrap(),
            Allocation::Filtered
        );
        assert_eq!(p.len(), 0, "a filtered name must not consume an address");
        assert_eq!(p.filtered_hits(), 3);
        // A name that merely ends with the same characters is not filtered.
        assert!(matches!(
            p.allocate(&name("notlan"), now()).unwrap(),
            Allocation::Address(_)
        ));
    }

    /// Past the TTL a mapping is reclaimable; before it, it is not.
    #[test]
    fn cleanup_respects_the_ttl() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        let ip = addr(p.allocate(&name("a.com"), now()).unwrap());
        // Half the TTL later: still live.
        assert_eq!(p.cleanup_expired(now() + 1_800_000_000_000), 0);
        assert_eq!(p.len(), 1);
        // Past the TTL: reclaimed, and the reverse map goes with it.
        assert_eq!(p.cleanup_expired(now() + 3_601_000_000_000), 1);
        assert_eq!(p.len(), 0);
        assert!(p.lookup(ip, now()).is_none());
    }

    /// A reclaimed address must be fully detached from its old name: the
    /// failure mode is a name and an address disagreeing about each other.
    #[test]
    fn reclaim_detaches_both_directions() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        let ip = addr(p.allocate(&name("a.com"), now()).unwrap());
        assert_eq!(p.lookup(ip, now()).unwrap(), name("a.com"));

        assert_eq!(p.cleanup_expired(now() + 3_601_000_000_000), 1);
        // Neither direction remembers the expired mapping.
        assert!(p.lookup(ip, now()).is_none());
        assert!(p.peek(ip).is_none());

        let ip2 = addr(
            p.allocate(&name("b.com"), now() + 3_602_000_000_000)
                .unwrap(),
        );
        assert_eq!(p.lookup(ip2, now()).unwrap(), name("b.com"));
        assert_eq!(p.len(), 1);
    }

    /// The cursor scans forward, so a freed address is not reused while free
    /// addresses remain ahead of it — that is deliberate, since a just-freed
    /// address is the one most likely to still have a live connection behind
    /// it. On a small range the cursor wraps, and freed addresses come back
    /// into circulation instead of the pool stalling.
    #[test]
    fn freed_addresses_return_after_wrap_around() {
        let mut p = pool("198.18.0.0/30", &[], 100);
        let first: Vec<Ipv4Addr> = (0..3)
            .map(|i| {
                addr(
                    p.allocate(&name(&alloc::format!("a{i}.com")), now())
                        .unwrap(),
                )
            })
            .collect();
        assert_eq!(first.len(), 3);

        let later = now() + 3_601_000_000_000;
        assert_eq!(p.cleanup_expired(later), 3);

        // Only three addresses exist, so a second round must reuse them.
        for i in 0..3 {
            let ip = addr(
                p.allocate(&name(&alloc::format!("b{i}.com")), later)
                    .unwrap(),
            );
            assert!(
                first.contains(&ip),
                "{ip} is not one of the range's three addresses"
            );
        }
        assert_eq!(p.len(), 3);
    }

    /// At the cap with everything fresh, the pool reclaims and keeps
    /// answering rather than refusing. Refusing would resolve the name for
    /// real, which escapes the proxy and its routing rules.
    #[test]
    fn full_pool_of_fresh_entries_recycles_and_keeps_answering() {
        let mut p = pool("198.18.0.0/24", &[], 4);
        for i in 0..4 {
            p.allocate(&name(&alloc::format!("host{i}.com")), now())
                .unwrap();
        }
        assert_eq!(p.len(), 4);
        let ip = addr(p.allocate(&name("overflow.com"), now()).unwrap());
        assert_eq!(p.lookup(ip, now()).unwrap(), name("overflow.com"));
        assert!(p.evicted() >= 1, "the recycle must be counted, not hidden");
        assert!(p.len() <= 4, "the cap still holds");
    }

    /// At the cap with stale entries, allocation reclaims and proceeds.
    #[test]
    fn full_pool_with_stale_entries_reclaims() {
        let mut p = pool("198.18.0.0/24", &[], 4);
        for i in 0..4 {
            p.allocate(&name(&alloc::format!("host{i}.com")), now())
                .unwrap();
        }
        let later = now() + 3_601_000_000_000;
        let ip = addr(p.allocate(&name("fresh.com"), later).unwrap());
        assert!(p.contains(ip));
        assert_eq!(p.lookup(ip, later).unwrap(), name("fresh.com"));
        assert!(p.evicted() >= 1, "the reclaim should be counted");
        assert!(p.len() <= 4);
    }

    /// The cap also respects the address space: `/30` has three usable
    /// addresses, so a `maxEntries` of 100 must not promise a hundred.
    #[test]
    fn cap_is_bounded_by_the_range() {
        let p = pool("198.18.0.0/30", &[], 100);
        assert_eq!(p.address_capacity(), 3);
        assert_eq!(p.max_entries(), 3);
    }

    /// The network address is never handed out.
    #[test]
    fn network_address_is_never_allocated() {
        let mut p = pool("198.18.0.0/30", &[], 100);
        for i in 0..3 {
            let ip = addr(
                p.allocate(&name(&alloc::format!("h{i}.com")), now())
                    .unwrap(),
            );
            assert_ne!(ip, "198.18.0.0".parse::<Ipv4Addr>().unwrap());
        }
    }

    /// A snapshot round-trips, and a snapshot that disagrees with the range
    /// or with another name is refused rather than guessed at.
    #[test]
    fn restore_round_trips_and_refuses_conflicts() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        let ip = addr(p.allocate(&name("a.com"), now()).unwrap());
        let snapshot: Vec<(Name, Ipv4Addr)> = p.iter().map(|(n, i)| (n.clone(), i)).collect();
        assert_eq!(snapshot, vec![(name("a.com"), ip)]);

        let mut q = pool("198.18.0.0/24", &[], 100);
        assert!(q.restore(&name("a.com"), ip, now()));
        assert_eq!(q.lookup(ip, now()).unwrap(), name("a.com"));
        // Out of range.
        assert!(!q.restore(&name("b.com"), "10.0.0.1".parse().unwrap(), now()));
        // The address already belongs to another name.
        assert!(!q.restore(&name("b.com"), ip, now()));
        // The name already owns a different address.
        assert!(!q.restore(&name("a.com"), "198.18.0.9".parse().unwrap(), now()));
    }

    #[test]
    fn release_forgets_one_mapping() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        let ip = addr(p.allocate(&name("a.com"), now()).unwrap());
        p.allocate(&name("b.com"), now()).unwrap();
        assert_eq!(p.release(&name("a.com")), Some(ip));
        assert!(p.lookup(ip, now()).is_none());
        assert_eq!(p.len(), 1);
        assert_eq!(p.release(&name("a.com")), None);
    }

    #[test]
    fn clear_empties_the_pool() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        p.allocate(&name("a.com"), now()).unwrap();
        p.clear();
        assert!(p.is_empty());
        assert!(p.peek("198.18.0.1".parse().unwrap()).is_none());
    }

    /// Bad configuration is refused at construction, with the field named.
    #[test]
    fn bad_config_is_refused() {
        let e = FakeIpPool::from_config("not-a-cidr", None, 3600, 10).unwrap_err();
        assert!(e.msg.contains("fake-ip range"), "{}", e.msg);

        let e = FakeIpPool::from_config("198.18.0.0/32", None, 3600, 10);
        // A /32 holds one address and the network address is reserved.
        assert!(
            e.is_err(),
            "a range with no usable addresses must be refused"
        );

        let bad = ["*.".to_string()];
        let e = FakeIpPool::from_config("198.18.0.0/24", Some(&bad), 3600, 10).unwrap_err();
        assert!(e.msg.contains("empty suffix"), "{}", e.msg);

        let e = FakeIpPool::from_config("198.18.0.0/24", None, 3600, 0).unwrap_err();
        assert!(e.msg.contains("maxEntries"), "{}", e.msg);
    }

    /// Omitting `fake-ip-filter` takes the built-in list; supplying an empty
    /// list is an explicit "no exclusions". Conflating the two would leave a
    /// deployment with none of the protection the defaults exist to give.
    #[test]
    fn absent_filter_takes_defaults_while_empty_means_none() {
        let builtin = FakeIpSettings::with_defaults().unwrap();
        assert_eq!(builtin.filter.len(), DEFAULT_FAKE_IP_FILTER.len());

        let none = FakeIpSettings::parse("198.18.0.0/16", Some(&[]), 3600, 128).unwrap();
        assert!(none.filter.is_empty());

        // Every default entry must parse: a default that cannot be parsed
        // would stop fake-IP mode from starting at all.
        for s in DEFAULT_FAKE_IP_FILTER {
            assert!(
                crate::pattern::DomainPattern::parse(s).is_ok(),
                "built-in default {s:?} does not parse"
            );
        }
    }

    /// The default filter covers the names whose faking breaks something
    /// visible: the OS connectivity probe, NTP, STUN, and local names.
    #[test]
    fn default_filter_covers_the_breakage_cases() {
        let mut p = FakeIpSettings::with_defaults().unwrap().build();
        let filtered = [
            "printer.lan",
            "foo.local",
            "localhost",
            "www.msftconnecttest.com",
            "msftncsi.com",
            "connectivitycheck.gstatic.com",
            "captive.apple.com",
            "time.apple.com",
            "time.windows.com",
            "time.nist.gov",
            "pool.ntp.org",
            "a.b.pool.ntp.org",
            "stun.example.com",
            "stun.a.b",
            "a.stun.b.c",
            "srv.nintendo.net",
            "stun.playstation.net",
        ];
        for n in filtered {
            assert_eq!(
                p.allocate(&name(n), now()).unwrap(),
                Allocation::Filtered,
                "{n} should be excluded from fake-IP by default"
            );
        }
        // An ordinary name is still synthesized.
        assert!(matches!(
            p.allocate(&name("www.example.com"), now()).unwrap(),
            Allocation::Address(_)
        ));
    }

    /// A handful of names must not be able to fill a large pool's scan.
    #[test]
    fn allocation_stays_cheap_under_churn() {
        let mut p = pool("198.18.0.0/16", &[], 64);
        // Force repeated sweeps: fresh entries, cap 64, so each new name
        // past the cap triggers a reclaim.
        for i in 0..512 {
            let _ = p.allocate(&name(&alloc::format!("h{i}.com")), now());
        }
        assert!(p.len() <= 64);
    }

    /// A mapping is one name to one address in both directions: the two
    /// indexes must never disagree, however many sweeps happen.
    #[test]
    fn both_indexes_stay_consistent_across_evictions() {
        let mut p = pool("198.18.0.0/24", &[], 32);
        for i in 0..400 {
            let _ = p.allocate(&name(&alloc::format!("h{i}.com")), now());
        }
        for (name, ip) in p.iter() {
            assert_eq!(
                p.peek(ip),
                Some(name),
                "reverse index disagrees for {name} -> {ip}"
            );
        }
        assert_eq!(p.len(), p.iter().count());
    }
}
