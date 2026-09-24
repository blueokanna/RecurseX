//! Fake-IP allocation (Clash `enhanced-mode: fake-ip`).
//!
//! In fake-IP mode the resolver hands the client a synthetic address from a
//! reserved block instead of the real one. The proxy then sees a connection
//! to that address, reverses the mapping back to the domain name, and routes
//! on the *name* — which is the whole point: a routing rule can only match on
//! a domain if the domain survives the trip through the client's socket API,
//! and a socket API only carries an address.
//!
//! # Two families, and why they are not symmetric
//!
//! A v4 range (`fake-ip-range`) is required; a v6 range (`fake-ip-range6`)
//! is optional, and its presence is what makes `AAAA` synthesized instead of
//! answered NODATA.
//!
//! The asymmetry is the point. A dual-stack client that receives a synthetic
//! `AAAA` will happily connect over IPv6 to an address that only means "ask
//! the proxy" — which is correct when a v6 pool exists to back it, and a
//! silent bypass when one does not. So the v6 pool is opt-in: an operator
//! who wants IPv6 traffic proxied says so once and both families are
//! synthesized; an operator who does not keeps the NODATA answer and the
//! client falls back to the v4 address. Either way the resolver never hands
//! out a v6 address it cannot reverse.
//!
//! A name may hold one mapping per family. The two spaces allocate
//! independently, so the address a client got for `A` says nothing about the
//! one it gets for `AAAA`.
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
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::bounded::evict_for_capacity;
use crate::cidr::{Ipv4Cidr, Ipv6Cidr};
use crate::error::{Error, Result};
use crate::name::Name;
use crate::pattern::{parse_all, DomainPattern};
use crate::time::Ts;

/// The reserved block fake-IP uses when none is configured: RFC 2544
/// benchmarking space, which is not routable and which no real answer should
/// ever legitimately contain — so a stray real address from this range is
/// itself a signal that something is wrong.
pub const DEFAULT_FAKE_IP_RANGE: &str = "198.18.0.0/16";

/// The v6 block the Clash family uses for fake-IP (`fake-ip-range6`).
///
/// Not enabled by default: synthesizing `AAAA` is what lets a dual-stack
/// client connect over IPv6, so it is a deployment decision rather than a
/// default. Provided as a constant because it is the value an operator
/// porting a working mihomo configuration will reach for.
///
/// It sits inside `fc00::/7` (unique local), so a leaked address from this
/// block cannot route anywhere real — the same property `198.18.0.0/16`
/// gives the v4 side.
pub const DEFAULT_FAKE_IP_RANGE6: &str = "fdfe:dcba:9876::/48";

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
    Address(IpAddr),
    /// The name is excluded by `fake-ip-filter`. Resolve it normally.
    Filtered,
}

/// Which address family a synthesized answer belongs to.
///
/// Fake-IP is deliberately *not* symmetric across the two families. A v4
/// range is required and a v6 range is optional, because an `AAAA` answer is
/// exactly what lets a dual-stack client dial the host directly and escape
/// the proxy — so synthesizing one is a decision the operator makes
/// explicitly (by configuring `fake-ip-range6`) rather than a default they
/// inherit. With no v6 range the answer for `AAAA` is NODATA, which pushes
/// the client onto the synthesized v4 address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Family {
    /// IPv4, the family `A` queries ask for.
    V4,
    /// IPv6, the family `AAAA` queries ask for.
    V6,
}

impl Family {
    /// The width of an address in this family, in bits.
    pub fn bits(self) -> u32 {
        match self {
            Family::V4 => 32,
            Family::V6 => 128,
        }
    }

    /// The address for `key`, which must be within the family's width.
    pub fn addr(self, key: u128) -> IpAddr {
        match self {
            Family::V4 => IpAddr::V4(Ipv4Addr::from(key as u32)),
            Family::V6 => IpAddr::V6(Ipv6Addr::from(key)),
        }
    }

    /// The key for `ip`, or `None` when it belongs to the other family.
    pub fn key(self, ip: IpAddr) -> Option<u128> {
        match (self, ip) {
            (Family::V4, IpAddr::V4(v)) => Some(u128::from(u32::from(v))),
            (Family::V6, IpAddr::V6(v)) => Some(u128::from(v)),
            _ => None,
        }
    }
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
    /// The IPv4 range. Required.
    pub range: Ipv4Cidr,
    /// The IPv6 range. `None` means `AAAA` is answered NODATA, which is the
    /// pre-existing behaviour and the safe default: a synthesized `AAAA`
    /// without a pool behind it would be an address nothing can reverse.
    pub range6: Option<Ipv6Cidr>,
    /// Names excluded from fake-IP.
    pub filter: Vec<DomainPattern>,
    /// Entry lifetime in seconds.
    pub ttl_secs: u64,
    /// Cap on live mappings, **per family**.
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
        range6: Option<&str>,
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
        let range6 = match range6 {
            None => None,
            Some(s) => {
                let c = Ipv6Cidr::parse(s)
                    .ok_or_else(|| Error::config(alloc::format!("invalid fake-ip range6 {s:?}")))?;
                if c.network() == c.broadcast() {
                    return Err(Error::config(alloc::format!(
                        "fake-ip range6 {c} has no usable addresses"
                    )));
                }
                Some(c)
            }
        };
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
            range6,
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

    /// Whether answers of `family` are synthesized. When this is false the
    /// caller must answer NODATA rather than resolve the name for real —
    /// see the module documentation.
    pub fn synthesizes(&self, family: Family) -> bool {
        match family {
            Family::V4 => true,
            Family::V6 => self.range6.is_some(),
        }
    }

    /// Build the pool this configuration describes.
    pub fn build(&self) -> FakeIpPool {
        FakeIpPool::new(
            self.range,
            self.range6,
            self.filter.clone(),
            self.ttl_secs,
            self.max_entries,
        )
    }

    /// The pool's settings with defaults applied, including the built-in
    /// filter. IPv6 synthesis stays off: it is a deployment decision.
    pub fn with_defaults() -> Result<Self> {
        Self::parse(
            DEFAULT_FAKE_IP_RANGE,
            None,
            None,
            DEFAULT_FAKE_IP_TTL_SECS,
            DEFAULT_FAKE_IP_MAX_ENTRIES,
        )
    }
}

/// One address family's allocation space.
///
/// The family-independent half of the pool: everything here works on integer
/// keys, and [`Family`] is what turns a key back into an address. Sharing one
/// implementation is deliberate — a v6 space that recycled differently from
/// the v4 one would be two behaviours to reason about and only one of them
/// tested.
#[derive(Debug)]
struct Space {
    family: Family,
    /// The lowest allocatable key. The network address is reserved, so a
    /// mapping is never `x.x.x.0`, which some client stacks read as a network
    /// identifier rather than a host.
    first: u128,
    /// The highest allocatable key.
    last: u128,
    /// The next candidate key.
    next: u128,
    /// How long a mapping may sit untouched.
    ttl_nanos: Ts,
    /// The authoritative map: address key to mapping.
    by_key: BTreeMap<u128, Entry>,
    /// The reverse index: name to address key. Rebuilt from `by_key` after
    /// every sweep, never patched in place.
    by_name: BTreeMap<Name, u128>,
    /// The cap on live mappings.
    max_entries: usize,
    /// Mappings dropped to stay inside the cap.
    evicted: u64,
}

impl Space {
    /// A space over the keys `first..=last`.
    fn new(family: Family, first: u128, last: u128, max_entries: usize, ttl_nanos: Ts) -> Self {
        Self {
            family,
            first,
            last,
            next: first,
            ttl_nanos,
            by_key: BTreeMap::new(),
            by_name: BTreeMap::new(),
            max_entries: max_entries.max(1),
            evicted: 0,
        }
    }

    /// A v4 space over `range`.
    fn v4(range: Ipv4Cidr, max_entries: usize, ttl_nanos: Ts) -> Self {
        Self::new(
            Family::V4,
            u128::from(u32::from(range.network())) + 1,
            u128::from(u32::from(range.broadcast())),
            max_entries,
            ttl_nanos,
        )
    }

    /// A v6 space over `range`.
    fn v6(range: Ipv6Cidr, max_entries: usize, ttl_nanos: Ts) -> Self {
        Self::new(
            Family::V6,
            u128::from(range.network()) + 1,
            u128::from(range.broadcast()),
            max_entries,
            ttl_nanos,
        )
    }

    /// The number of usable keys in the space.
    ///
    /// A v6 block holds more addresses than a `usize` can count, so this
    /// saturates. That is not a loss: the value only clamps `max_entries`, and
    /// a saturated capacity clamps nothing.
    fn capacity(&self) -> usize {
        let n = self.last.saturating_sub(self.first) + 1;
        usize::try_from(n).unwrap_or(usize::MAX)
    }

    /// The effective cap on live mappings: the configured cap, or the space
    /// itself if it is smaller.
    fn cap(&self) -> usize {
        self.max_entries.min(self.capacity())
    }

    /// The number of live mappings.
    fn len(&self) -> usize {
        self.by_key.len()
    }

    /// Whether `key` is inside the space, including the reserved network
    /// address at the bottom.
    fn covers(&self, key: u128) -> bool {
        key >= self.first.saturating_sub(1) && key <= self.last
    }

    fn allocate(&mut self, name: &Name, now: Ts) -> Result<IpAddr> {
        if let Some(&key) = self.by_name.get(name) {
            if let Some(e) = self.by_key.get_mut(&key) {
                e.last_access = now;
            }
            return Ok(self.family.addr(key));
        }
        if self.by_key.len() >= self.cap() {
            self.reclaim(now);
        }
        let key = self
            .take_key()
            .ok_or_else(|| Error::internal("fake-ip space reported room but had no free key"))?;
        self.by_key.insert(
            key,
            Entry {
                name: name.clone(),
                created: now,
                last_access: now,
            },
        );
        self.by_name.insert(name.clone(), key);
        Ok(self.family.addr(key))
    }

    /// The name that owns `key`, refreshing its recency.
    fn lookup(&mut self, key: u128, now: Ts) -> Option<Name> {
        let e = self.by_key.get_mut(&key)?;
        e.last_access = now;
        Some(e.name.clone())
    }

    /// The name that owns `key`, without touching recency.
    fn peek(&self, key: u128) -> Option<&Name> {
        self.by_key.get(&key).map(|e| &e.name)
    }

    /// Record a mapping loaded from a snapshot.
    ///
    /// Returns `false` when the key is outside the space or already owned by
    /// another name — a snapshot that disagrees with the configured range is
    /// not something to guess about.
    fn restore(&mut self, name: &Name, key: u128, now: Ts) -> bool {
        if !self.covers(key) || key < self.first {
            return false;
        }
        if let Some(existing) = self.by_key.get(&key) {
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
        self.by_key.insert(
            key,
            Entry {
                name: name.clone(),
                created: now,
                last_access: now,
            },
        );
        true
    }

    /// Drop mappings untouched for longer than the TTL. Returns how many.
    fn cleanup_expired(&mut self, now: Ts) -> usize {
        let cutoff = now.saturating_sub(self.ttl_nanos);
        let before = self.by_key.len();
        self.by_key.retain(|_, e| e.last_access >= cutoff);
        if self.by_key.len() != before {
            self.rebuild_name_index();
        }
        before - self.by_key.len()
    }

    /// Forget one mapping.
    fn release(&mut self, name: &Name) -> Option<u128> {
        let key = self.by_name.remove(name)?;
        self.by_key.remove(&key);
        Some(key)
    }

    /// Forget everything.
    fn clear(&mut self) {
        self.by_key.clear();
        self.by_name.clear();
    }

    /// Reclaim space at the cap: stale entries first, then an amortised
    /// stride batch if every entry is still fresh.
    fn reclaim(&mut self, now: Ts) {
        let cutoff = now.saturating_sub(self.ttl_nanos);
        let freed = evict_for_capacity(&mut self.by_key, cutoff, EVICT_STRIDE, |e| e.last_access);
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
        for (key, e) in &self.by_key {
            self.by_name.insert(e.name.clone(), *key);
        }
    }

    /// The next free key, scanning at most `len + 1` candidates.
    ///
    /// The bound is a pigeonhole argument, not a heuristic: among `n + 1`
    /// *distinct* candidates at most `n` can be occupied when the space holds
    /// `n` mappings, so a free one is always found — or the space itself is
    /// exhausted, which the cap already prevents.
    fn take_key(&mut self) -> Option<u128> {
        let limit = self.by_key.len() + 1;
        for _ in 0..limit {
            let c = self.advance();
            if !self.by_key.contains_key(&c) {
                return Some(c);
            }
        }
        None
    }

    /// Advance the cursor to the next in-range candidate.
    fn advance(&mut self) -> u128 {
        if self.next < self.first || self.next > self.last {
            self.next = self.first;
        }
        let cur = self.next;
        self.next = if cur >= self.last {
            self.first
        } else {
            cur + 1
        };
        cur
    }
}

/// The fake-IP pool: one allocation space per configured family.
///
/// The filter, the TTL and the recency policy are shared across families; the
/// address spaces are not, because a name may hold one mapping per family and
/// the address a client got for `A` says nothing about the one it gets for
/// `AAAA`.
#[derive(Debug)]
pub struct FakeIpPool {
    /// The v4 range.
    v4_net: Ipv4Cidr,
    /// The v6 range, when v6 synthesis is configured.
    v6_net: Option<Ipv6Cidr>,
    /// The v4 space. Always present: `fake-ip-range` is required.
    v4: Space,
    /// The v6 space, present only when `fake-ip-range6` is configured.
    v6: Option<Space>,
    /// Names excluded from fake-IP.
    filter: Vec<DomainPattern>,
    /// Names turned away by the filter.
    filtered_hits: u64,
}

impl FakeIpPool {
    /// Build a pool from raw configuration strings.
    pub fn from_config(
        range: &str,
        range6: Option<&str>,
        filter: Option<&[String]>,
        ttl_secs: u64,
        max_entries: usize,
    ) -> Result<Self> {
        Ok(FakeIpSettings::parse(range, range6, filter, ttl_secs, max_entries)?.build())
    }

    /// Build a pool from already-parsed parts.
    pub fn new(
        range: Ipv4Cidr,
        range6: Option<Ipv6Cidr>,
        filter: Vec<DomainPattern>,
        ttl_secs: u64,
        max_entries: usize,
    ) -> Self {
        let ttl = ttl_nanos(ttl_secs);
        Self {
            v4_net: range,
            v6_net: range6,
            v4: Space::v4(range, max_entries, ttl),
            v6: range6.map(|r| Space::v6(r, max_entries, ttl)),
            filter,
            filtered_hits: 0,
        }
    }

    /// The v4 range.
    pub fn range_v4(&self) -> Ipv4Cidr {
        self.v4_net
    }

    /// The v6 range, when v6 synthesis is configured.
    pub fn range_v6(&self) -> Option<Ipv6Cidr> {
        self.v6_net
    }

    /// Whether answers of `family` are synthesized at all.
    pub fn synthesizes(&self, family: Family) -> bool {
        self.space(family).is_some()
    }

    /// The number of usable addresses in `family`'s range.
    pub fn capacity(&self, family: Family) -> usize {
        self.space(family).map(|s| s.capacity()).unwrap_or(0)
    }

    /// The effective cap on live mappings in `family`.
    pub fn max_entries(&self, family: Family) -> usize {
        self.space(family).map(|s| s.cap()).unwrap_or(0)
    }

    /// The number of live mappings across both families.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.as_ref().map(|s| s.len()).unwrap_or(0)
    }

    /// The number of live mappings in one family.
    pub fn len_for(&self, family: Family) -> usize {
        self.space(family).map(|s| s.len()).unwrap_or(0)
    }

    /// Whether the pool holds no mappings.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The number of names excluded by the filter.
    pub fn filtered_hits(&self) -> u64 {
        self.filtered_hits
    }

    /// The number of mappings dropped to respect the entry cap, across both
    /// families.
    pub fn evicted(&self) -> u64 {
        self.v4.evicted + self.v6.as_ref().map(|s| s.evicted).unwrap_or(0)
    }

    /// Whether `ip` is inside either configured range and therefore *could*
    /// have come from this pool. Pure range test: it does not consult the
    /// mapping table and does not touch recency.
    ///
    /// Note that this is a test of the address, not of the mapping — use
    /// [`lookup`](Self::lookup) to ask which name owns it.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (Family::V4.key(ip), Family::V6.key(ip)) {
            (Some(k), _) => self.v4.covers(k),
            (_, Some(k)) => self.v6.as_ref().is_some_and(|s| s.covers(k)),
            _ => false,
        }
    }

    /// Whether `name` is excluded from fake-IP by the filter.
    pub fn is_filtered(&self, name: &Name) -> bool {
        self.filter.iter().any(|p| p.matches(name))
    }

    /// The space for a family, if it is configured.
    fn space(&self, family: Family) -> Option<&Space> {
        match family {
            Family::V4 => Some(&self.v4),
            Family::V6 => self.v6.as_ref(),
        }
    }

    /// The mutable space for a family, if it is configured.
    fn space_mut(&mut self, family: Family) -> Option<&mut Space> {
        match family {
            Family::V4 => Some(&mut self.v4),
            Family::V6 => self.v6.as_mut(),
        }
    }
}

/// The pool's per-query API.
///
/// Everything here delegates to the space for the family being asked about,
/// so allocation, reverse lookup and recycling have one implementation rather
/// than one per family.
impl FakeIpPool {
    /// Assign (or re-fetch) the fake address for `name` in `family`,
    /// refreshing its recency.
    ///
    /// The filter is consulted once, here, rather than per space: a name
    /// excluded from fake-IP is excluded from both families.
    ///
    /// Returns [`Allocation::Filtered`] for an excluded name. For a family
    /// with no configured space the caller should not have asked at all, so
    /// that is an internal error rather than a confident wrong-family answer.
    pub fn allocate(&mut self, name: &Name, family: Family, now: Ts) -> Result<Allocation> {
        if self.is_filtered(name) {
            self.filtered_hits += 1;
            return Ok(Allocation::Filtered);
        }
        match self.space_mut(family) {
            Some(space) => Ok(Allocation::Address(space.allocate(name, now)?)),
            None => Err(Error::internal(alloc::format!(
                "no fake-ip space is configured for {family:?}"
            ))),
        }
    }

    /// The name that owns `ip`, refreshing its recency. `None` when the
    /// address is outside both ranges or was never handed out.
    pub fn lookup(&mut self, ip: IpAddr, now: Ts) -> Option<Name> {
        match (Family::V4.key(ip), Family::V6.key(ip)) {
            (Some(k), _) => self.v4.lookup(k, now),
            (_, Some(k)) => self.v6.as_mut()?.lookup(k, now),
            _ => None,
        }
    }

    /// The name that owns `ip`, without touching recency. For read-only
    /// callers such as a status endpoint.
    pub fn peek(&self, ip: IpAddr) -> Option<&Name> {
        match (Family::V4.key(ip), Family::V6.key(ip)) {
            (Some(k), _) => self.v4.peek(k),
            (_, Some(k)) => self.v6.as_ref()?.peek(k),
            _ => None,
        }
    }

    /// Record a mapping loaded from a snapshot, so restarting does not
    /// renumber the domains a client is still holding addresses for.
    ///
    /// Returns `false` when the address is outside the configured ranges or
    /// already belongs to another name — a snapshot that disagrees with the
    /// configuration is not something to guess about.
    pub fn restore(&mut self, name: &Name, ip: IpAddr, now: Ts) -> bool {
        match (Family::V4.key(ip), Family::V6.key(ip)) {
            (Some(k), _) => self.v4.restore(name, k, now),
            (_, Some(k)) => match self.v6.as_mut() {
                Some(space) => space.restore(name, k, now),
                None => false,
            },
            _ => false,
        }
    }

    /// Iterate live mappings across both families, for snapshotting.
    pub fn iter(&self) -> impl Iterator<Item = (&Name, IpAddr)> {
        let four = self
            .v4
            .by_key
            .iter()
            .map(|(k, e)| (&e.name, Family::V4.addr(*k)));
        let six = self
            .v6
            .iter()
            .flat_map(|s| s.by_key.iter().map(|(k, e)| (&e.name, Family::V6.addr(*k))));
        four.chain(six)
    }

    /// Drop mappings untouched for longer than the TTL, across both families.
    /// Returns how many were dropped.
    pub fn cleanup_expired(&mut self, now: Ts) -> usize {
        let mut dropped = self.v4.cleanup_expired(now);
        if let Some(space) = self.v6.as_mut() {
            dropped += space.cleanup_expired(now);
        }
        dropped
    }

    /// Forget `name`'s mapping in one family, e.g. when a domain is removed
    /// from a rule set.
    pub fn release(&mut self, name: &Name, family: Family) -> Option<IpAddr> {
        let key = self.space_mut(family)?.release(name)?;
        Some(family.addr(key))
    }

    /// Forget everything.
    pub fn clear(&mut self) {
        self.v4.clear();
        if let Some(space) = self.v6.as_mut() {
            space.clear();
        }
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

    /// A v4-only pool: what a configuration without `fake-ip-range6`
    /// produces, and what the pre-existing suite exercises.
    fn pool(range: &str, filter: &[&str], max_entries: usize) -> FakeIpPool {
        let f: Vec<String> = filter.iter().map(|s| (*s).to_string()).collect();
        FakeIpPool::from_config(range, None, Some(&f), 3600, max_entries).unwrap()
    }

    /// A dual-stack pool with no filter, for the v6 tests.
    fn dual(range: &str, range6: &str, max_entries: usize) -> FakeIpPool {
        FakeIpPool::from_config(range, Some(range6), Some(&[]), 3600, max_entries).unwrap()
    }

    /// Allocate in the v4 space and return the address.
    fn alloc(p: &mut FakeIpPool, host: &str, now: Ts) -> Ipv4Addr {
        match p.allocate(&name(host), Family::V4, now).unwrap() {
            Allocation::Address(IpAddr::V4(v4)) => v4,
            other => panic!("expected a v4 address for {host}, got {other:?}"),
        }
    }

    /// Allocate in the v6 space and return the address.
    fn alloc6(p: &mut FakeIpPool, host: &str, now: Ts) -> Ipv6Addr {
        match p.allocate(&name(host), Family::V6, now).unwrap() {
            Allocation::Address(IpAddr::V6(v6)) => v6,
            other => panic!("expected a v6 address for {host}, got {other:?}"),
        }
    }

    /// Allocate and hand back the raw outcome, for the filtered/error cases.
    fn alloc_raw(p: &mut FakeIpPool, host: &str, family: Family, now: Ts) -> Allocation {
        p.allocate(&name(host), family, now).unwrap()
    }

    #[test]
    fn first_allocation_is_the_second_address_in_the_range() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        let ip = alloc(&mut p, "a.com", now());
        assert_eq!(ip, "198.18.0.1".parse::<Ipv4Addr>().unwrap());
        assert!(p.contains(ip.into()));
        assert_eq!(p.len(), 1);
    }

    /// The same name must not get a second address, or a client that
    /// re-resolves opens two connections the proxy reads as two domains.
    #[test]
    fn allocation_is_stable_for_a_name() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        let a = alloc(&mut p, "a.com", now());
        let b = alloc(&mut p, "a.com", now() + 1_000);
        assert_eq!(a, b);
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn distinct_names_get_distinct_addresses() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        let a = alloc(&mut p, "a.com", now());
        let b = alloc(&mut p, "b.com", now());
        assert_ne!(a, b);
        assert_eq!(p.len(), 2);
    }

    /// The reverse direction is what makes fake-IP usable at all.
    #[test]
    fn reverse_lookup_recovers_the_name() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        let ip: IpAddr = alloc(&mut p, "a.com", now()).into();
        assert_eq!(p.lookup(ip, now()).unwrap(), name("a.com"));
        assert_eq!(p.peek(ip), Some(&name("a.com")));
        assert!(p.lookup("198.18.0.200".parse().unwrap(), now()).is_none());
        assert!(!p.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn filtered_names_are_not_allocated() {
        let mut p = pool("198.18.0.0/24", &["*.lan", "localhost"], 100);
        for host in ["printer.lan", "lan", "localhost"] {
            assert_eq!(
                alloc_raw(&mut p, host, Family::V4, now()),
                Allocation::Filtered,
                "{host} should be filtered"
            );
        }
        assert_eq!(p.len(), 0, "a filtered name must not consume an address");
        assert_eq!(p.filtered_hits(), 3);
        // A name that merely ends with the same characters is not filtered.
        assert!(matches!(
            alloc_raw(&mut p, "notlan", Family::V4, now()),
            Allocation::Address(_)
        ));
    }

    /// Past the TTL a mapping is reclaimable; before it, it is not.
    #[test]
    fn cleanup_respects_the_ttl() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        let ip: IpAddr = alloc(&mut p, "a.com", now()).into();
        assert_eq!(p.cleanup_expired(now() + 1_800_000_000_000), 0);
        assert_eq!(p.len(), 1);
        assert_eq!(p.cleanup_expired(now() + 3_601_000_000_000), 1);
        assert_eq!(p.len(), 0);
        assert!(p.lookup(ip, now()).is_none());
    }

    /// A reclaimed address must be fully detached from its old name: the
    /// failure mode is a name and an address disagreeing about each other.
    #[test]
    fn reclaim_detaches_both_directions() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        let ip: IpAddr = alloc(&mut p, "a.com", now()).into();
        assert_eq!(p.lookup(ip, now()).unwrap(), name("a.com"));

        assert_eq!(p.cleanup_expired(now() + 3_601_000_000_000), 1);
        // Neither direction remembers the expired mapping.
        assert!(p.lookup(ip, now()).is_none());
        assert!(p.peek(ip).is_none());

        let ip2: IpAddr = alloc(&mut p, "b.com", now() + 3_602_000_000_000).into();
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
            .map(|i| alloc(&mut p, &alloc::format!("a{i}.com"), now()))
            .collect();
        assert_eq!(first.len(), 3);

        let later = now() + 3_601_000_000_000;
        assert_eq!(p.cleanup_expired(later), 3);

        // Only three addresses exist, so a second round must reuse them.
        for i in 0..3 {
            let ip = alloc(&mut p, &alloc::format!("b{i}.com"), later);
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
            alloc(&mut p, &alloc::format!("host{i}.com"), now());
        }
        assert_eq!(p.len(), 4);
        let ip: IpAddr = alloc(&mut p, "overflow.com", now()).into();
        assert_eq!(p.lookup(ip, now()).unwrap(), name("overflow.com"));
        assert!(p.evicted() >= 1, "the recycle must be counted, not hidden");
        assert!(p.len() <= 4, "the cap still holds");
    }

    /// At the cap with stale entries, allocation reclaims and proceeds.
    #[test]
    fn full_pool_with_stale_entries_reclaims() {
        let mut p = pool("198.18.0.0/24", &[], 4);
        for i in 0..4 {
            alloc(&mut p, &alloc::format!("host{i}.com"), now());
        }
        let later = now() + 3_601_000_000_000;
        let ip: IpAddr = alloc(&mut p, "fresh.com", later).into();
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
        assert_eq!(p.capacity(Family::V4), 3);
        assert_eq!(p.max_entries(Family::V4), 3);
    }

    /// The network address is never handed out.
    #[test]
    fn network_address_is_never_allocated() {
        let mut p = pool("198.18.0.0/30", &[], 100);
        for i in 0..3 {
            let ip = alloc(&mut p, &alloc::format!("h{i}.com"), now());
            assert_ne!(ip, "198.18.0.0".parse::<Ipv4Addr>().unwrap());
        }
    }

    /// A snapshot round-trips, and a snapshot that disagrees with the range
    /// or with another name is refused rather than guessed at.
    #[test]
    fn restore_round_trips_and_refuses_conflicts() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        let ip: IpAddr = alloc(&mut p, "a.com", now()).into();
        let snapshot: Vec<(Name, IpAddr)> = p.iter().map(|(n, i)| (n.clone(), i)).collect();
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
        let ip: IpAddr = alloc(&mut p, "a.com", now()).into();
        alloc(&mut p, "b.com", now());
        assert_eq!(p.release(&name("a.com"), Family::V4), Some(ip));
        assert!(p.lookup(ip, now()).is_none());
        assert_eq!(p.len(), 1);
        assert_eq!(p.release(&name("a.com"), Family::V4), None);
    }

    #[test]
    fn clear_empties_the_pool() {
        let mut p = pool("198.18.0.0/24", &[], 100);
        alloc(&mut p, "a.com", now());
        p.clear();
        assert!(p.is_empty());
        assert!(p.peek("198.18.0.1".parse().unwrap()).is_none());
    }

    // ---- the v6 space --------------------------------------------------

    /// A pool without `fake-ip-range6` has no v6 space, and asking for one is
    /// an error rather than a wrong-family answer. This is the property that
    /// keeps `AAAA` NODATA in the default configuration.
    #[test]
    fn v6_space_is_opt_in() {
        let mut p = pool("198.18.0.0/24", &[], 64);
        assert!(p.synthesizes(Family::V4));
        assert!(!p.synthesizes(Family::V6));
        assert_eq!(p.range_v6(), None);
        assert_eq!(p.capacity(Family::V6), 0);
        assert_eq!(p.max_entries(Family::V6), 0);
        assert!(p.allocate(&name("a.com"), Family::V6, now()).is_err());
    }

    /// With `fake-ip-range6` configured, v6 allocations come from that range
    /// and the v4 space is left alone.
    #[test]
    fn v6_allocates_from_its_own_range() {
        let mut p = dual("198.18.0.0/24", "fdfe:dcba:9876::/48", 64);
        assert!(p.synthesizes(Family::V6));
        assert_eq!(p.range_v6().unwrap().to_string(), "fdfe:dcba:9876::/48");

        let ip = alloc6(&mut p, "a.com", now());
        assert_eq!(ip, "fdfe:dcba:9876::1".parse::<Ipv6Addr>().unwrap());
        assert!(p.contains(ip.into()));
        assert_eq!(p.len_for(Family::V6), 1);
        assert_eq!(p.len_for(Family::V4), 0, "v4 must not be touched");
    }

    /// The reverse map is per family: a v6 address resolves in the v6 space,
    /// and an address outside it resolves to nothing rather than searching
    /// the wrong pool.
    #[test]
    fn v6_reverse_lookup_stays_in_its_family() {
        let mut p = dual("198.18.0.0/24", "fdfe:dcba:9876::/48", 64);
        let ip6 = alloc6(&mut p, "a.com", now());
        assert_eq!(p.lookup(ip6.into(), now()).unwrap(), name("a.com"));
        assert_eq!(p.peek(ip6.into()), Some(&name("a.com")));

        // In the v6 range but never handed out.
        let unknown = "fdfe:dcba:9876::ffff".parse::<Ipv6Addr>().unwrap();
        assert!(p.lookup(unknown.into(), now()).is_none());
        // A v4 address must not be matched by the v6 space, and vice versa.
        assert!(!p.contains("fdfe:dcba:9877::1".parse().unwrap()));
        assert!(!p.contains("198.19.0.1".parse().unwrap()));
    }

    /// A name may hold one mapping per family. This is the whole point of two
    /// spaces: the address a client got for `A` says nothing about the one it
    /// gets for `AAAA`, and both must reverse to the same name.
    #[test]
    fn one_mapping_per_family_coexists() {
        let mut p = dual("198.18.0.0/24", "fdfe:dcba:9876::/48", 64);
        let ip4 = alloc(&mut p, "a.com", now());
        let ip6 = alloc6(&mut p, "a.com", now());

        assert_eq!(p.lookup(ip4.into(), now()).unwrap(), name("a.com"));
        assert_eq!(p.lookup(ip6.into(), now()).unwrap(), name("a.com"));
        assert_eq!(p.len(), 2);
        assert_eq!(p.len_for(Family::V4), 1);
        assert_eq!(p.len_for(Family::V6), 1);

        // Each family is released independently.
        assert_eq!(p.release(&name("a.com"), Family::V4), Some(ip4.into()));
        assert_eq!(p.lookup(ip6.into(), now()).unwrap(), name("a.com"));
        assert_eq!(p.len(), 1);
    }

    /// The entry cap is per family, so a v6 flood cannot evict v4 mappings
    /// (or the reverse).
    #[test]
    fn each_family_has_its_own_cap() {
        let mut p = dual("198.18.0.0/24", "fdfe:dcba:9876::/48", 2);
        assert_eq!(p.max_entries(Family::V4), 2);
        assert_eq!(p.max_entries(Family::V6), 2);

        for i in 0..2 {
            alloc(&mut p, &alloc::format!("v4-{i}.com"), now());
            alloc6(&mut p, &alloc::format!("v6-{i}.com"), now());
        }
        assert_eq!(p.len_for(Family::V4), 2);
        assert_eq!(p.len_for(Family::V6), 2);
        assert_eq!(p.len(), 4);

        // Pushing past the v4 cap recycles a v4 mapping and leaves v6 alone.
        alloc(&mut p, "extra.com", now());
        assert_eq!(p.len_for(Family::V4), 2);
        assert_eq!(p.len_for(Family::V6), 2);
        assert!(p.evicted() >= 1);
    }

    /// v6 hygiene: a range with no usable address is refused, and the cap is
    /// clamped by a small range just as it is for v4.
    #[test]
    fn v6_range_validation() {
        let e = FakeIpPool::from_config("198.18.0.0/24", Some("fdfe::/128"), Some(&[]), 3600, 8)
            .unwrap_err();
        assert!(e.msg.contains("range6"), "{}", e.msg);

        let e = FakeIpPool::from_config("198.18.0.0/24", Some("not-a-cidr"), Some(&[]), 3600, 8)
            .unwrap_err();
        assert!(e.msg.contains("range6"), "{}", e.msg);

        // A /127 leaves one usable address, so the cap follows it.
        let mut p = dual("198.18.0.0/24", "fdfe::/127", 100);
        assert_eq!(p.capacity(Family::V6), 1);
        assert_eq!(p.max_entries(Family::V6), 1);
        assert_eq!(
            alloc6(&mut p, "a.com", now()),
            "fdfe::1".parse::<Ipv6Addr>().unwrap()
        );
        // The next name must recycle rather than hand out the network
        // address or an address outside the block.
        let second = alloc6(&mut p, "b.com", now());
        assert_eq!(second, "fdfe::1".parse::<Ipv6Addr>().unwrap());
    }

    /// Both spaces share the filter: a name excluded from fake-IP is excluded
    /// from both families, not just the one that happens to be configured.
    #[test]
    fn the_filter_covers_both_families() {
        let f = ["*.lan".to_string()];
        let mut p = FakeIpPool::from_config(
            "198.18.0.0/24",
            Some("fdfe:dcba:9876::/48"),
            Some(&f),
            3600,
            64,
        )
        .unwrap();
        for family in [Family::V4, Family::V6] {
            assert_eq!(
                p.allocate(&name("printer.lan"), family, now()).unwrap(),
                Allocation::Filtered
            );
        }
        assert_eq!(p.len(), 0);
        assert_eq!(p.filtered_hits(), 2);
    }

    /// The maintenance sweep covers both spaces, so a quiet v6 mapping is
    /// reclaimed on schedule rather than only under v6 pressure.
    #[test]
    fn cleanup_covers_both_spaces() {
        let mut p = dual("198.18.0.0/24", "fdfe:dcba:9876::/48", 64);
        alloc(&mut p, "a.com", now());
        alloc6(&mut p, "b.com", now());
        assert_eq!(p.cleanup_expired(now() + 1_800_000_000_000), 0);
        assert_eq!(p.cleanup_expired(now() + 3_601_000_000_000), 2);
        assert!(p.is_empty());
    }

    /// Bad configuration is refused at construction, with the field named.
    #[test]
    fn bad_config_is_refused() {
        let e = FakeIpPool::from_config("not-a-cidr", None, None, 3600, 10).unwrap_err();
        assert!(e.msg.contains("fake-ip range"), "{}", e.msg);

        let e = FakeIpPool::from_config("198.18.0.0/32", None, None, 3600, 10);
        // A /32 holds one address and the network address is reserved.
        assert!(
            e.is_err(),
            "a range with no usable addresses must be refused"
        );

        let bad = ["*.".to_string()];
        let e = FakeIpPool::from_config("198.18.0.0/24", None, Some(&bad), 3600, 10).unwrap_err();
        assert!(e.msg.contains("empty suffix"), "{}", e.msg);

        let e = FakeIpPool::from_config("198.18.0.0/24", None, None, 3600, 0).unwrap_err();
        assert!(e.msg.contains("maxEntries"), "{}", e.msg);

        // A zero TTL would expire every mapping before a client could use it.
        let e = FakeIpPool::from_config("198.18.0.0/24", None, None, 0, 10).unwrap_err();
        assert!(e.msg.contains("ttl"), "{}", e.msg);
    }

    /// Omitting `fake-ip-filter` takes the built-in list; supplying an empty
    /// list is an explicit "no exclusions". Conflating the two would leave a
    /// deployment with none of the protection the defaults exist to give.
    #[test]
    fn absent_filter_takes_defaults_while_empty_means_none() {
        let builtin = FakeIpSettings::with_defaults().unwrap();
        assert_eq!(builtin.filter.len(), DEFAULT_FAKE_IP_FILTER.len());
        // IPv6 synthesis stays off in the defaults: it is a deployment
        // decision, not something to inherit.
        assert!(!builtin.synthesizes(Family::V6));

        let none = FakeIpSettings::parse("198.18.0.0/16", None, Some(&[]), 3600, 128).unwrap();
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
                alloc_raw(&mut p, n, Family::V4, now()),
                Allocation::Filtered,
                "{n} should be excluded from fake-IP by default"
            );
        }
        // An ordinary name is still synthesized.
        assert!(matches!(
            alloc_raw(&mut p, "www.example.com", Family::V4, now()),
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
            let _ = p.allocate(&name(&alloc::format!("h{i}.com")), Family::V4, now());
        }
        assert!(p.len() <= 64);
    }

    /// A mapping is one name to one address in both directions: the two
    /// indexes must never disagree, however many sweeps happen. Checked once
    /// per family, because each family has its own pair of index maps.
    #[test]
    fn both_indexes_stay_consistent_across_evictions() {
        for family in [Family::V4, Family::V6] {
            let mut p = dual("198.18.0.0/24", "fdfe:dcba:9876::/48", 32);
            for i in 0..400 {
                let _ = p.allocate(&name(&alloc::format!("h{i}.com")), family, now());
            }
            for (name, ip) in p.iter() {
                assert_eq!(
                    p.peek(ip),
                    Some(name),
                    "reverse index disagrees for {name} -> {ip} in {family:?}"
                );
            }
            assert_eq!(p.len(), p.iter().count());
        }
    }
}
