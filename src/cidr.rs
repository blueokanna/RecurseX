//! CIDR parsing and containment, without a dependency.
//!
//! The policy layer needs exactly two things from a CIDR block: *is this
//! address inside it* (fallback filtering, bogus-answer detection) and
//! *what is the allocatable host range* (fake-IP). Both are masking and
//! comparison, so a CIDR crate would be a dependency for fifty lines of
//! integer arithmetic — and this crate's `no_std` core could not use it
//! without inheriting that crate's own feature surface.
//!
//! # Host bits are masked, not rejected
//!
//! `192.168.1.5/24` is accepted and treated as `192.168.1.0/24`. The prefix
//! defines the network; the bits below it are not part of the block. Every
//! other resolver accepts this spelling, so rejecting it would fail
//! configurations that are not wrong.
//!
//! # Family is part of the match
//!
//! An [`IpCidr`] matches only addresses of its own family. In particular a
//! v4 block does **not** match a v4-mapped IPv6 address: treating
//! `::ffff:198.18.0.1` as inside `198.18.0.0/16` would be a guess about
//! intent, and a security-relevant one once fake-IP is involved.

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The IPv4 prefix bit mask, with `prefix == 0` handled separately because
/// shifting a `u32` by 32 is undefined.
const fn mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    }
}

/// The IPv6 prefix bit mask, with `prefix == 0` handled separately because
/// shifting a `u128` by 128 is undefined.
const fn mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else if prefix >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// Split `a.b.c.d/n` into its address and prefix, or a bare address with a
/// full-length prefix.
fn split_prefix(s: &str, full: u8) -> Option<(&str, u8)> {
    match s.split_once('/') {
        Some((addr, p)) => {
            let p: u8 = p.trim().parse().ok()?;
            if p > full {
                return None;
            }
            Some((addr.trim(), p))
        }
        None => Some((s.trim(), full)),
    }
}

/// An IPv4 CIDR block.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Cidr {
    /// The network address (host bits cleared).
    base: u32,
    /// The prefix length in bits, `0..=32`.
    prefix: u8,
}

impl Ipv4Cidr {
    /// A block covering `addr` with the given prefix length, or `None` when
    /// `prefix > 32`.
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Option<Self> {
        if prefix > 32 {
            return None;
        }
        Some(Self {
            base: u32::from(addr) & mask_v4(prefix),
            prefix,
        })
    }

    /// Parse `a.b.c.d/n`, or a bare `a.b.c.d` (which becomes a `/32`).
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, prefix) = split_prefix(s, 32)?;
        let addr: Ipv4Addr = addr.parse().ok()?;
        Self::new(addr, prefix)
    }

    /// Whether `ip` is inside this block.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & mask_v4(self.prefix) == self.base
    }

    /// The prefix length in bits.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// The network address (the first address in the block).
    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.base)
    }

    /// The broadcast address (the last address in the block).
    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.base | !mask_v4(self.prefix))
    }

    /// The number of addresses in the block, `2^(32 - prefix)`.
    pub fn len(&self) -> u64 {
        1u64 << (32 - self.prefix)
    }

    /// Whether the block cannot contain any address. Always false: a CIDR
    /// always contains at least one address, but the accessor keeps the
    /// `len`/`is_empty` pair honest for lints and callers.
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl fmt::Debug for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

/// An IPv6 CIDR block.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Cidr {
    /// The network address (host bits cleared).
    base: u128,
    /// The prefix length in bits, `0..=128`.
    prefix: u8,
}

impl Ipv6Cidr {
    /// A block covering `addr` with the given prefix length, or `None` when
    /// `prefix > 128`.
    pub fn new(addr: Ipv6Addr, prefix: u8) -> Option<Self> {
        if prefix > 128 {
            return None;
        }
        Some(Self {
            base: u128::from(addr) & mask_v6(prefix),
            prefix,
        })
    }

    /// Parse `addr/n`, or a bare address (which becomes a `/128`).
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, prefix) = split_prefix(s, 128)?;
        let addr: Ipv6Addr = addr.parse().ok()?;
        Self::new(addr, prefix)
    }

    /// Whether `ip` is inside this block.
    pub fn contains(&self, ip: Ipv6Addr) -> bool {
        u128::from(ip) & mask_v6(self.prefix) == self.base
    }

    /// The prefix length in bits.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// The network address (the first address in the block).
    pub fn network(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.base)
    }

    /// The last address in the block.
    pub fn broadcast(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.base | !mask_v6(self.prefix))
    }
}

impl fmt::Debug for Ipv6Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

impl fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

/// A CIDR block of either family.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum IpCidr {
    /// An IPv4 block.
    V4(Ipv4Cidr),
    /// An IPv6 block.
    V6(Ipv6Cidr),
}

impl IpCidr {
    /// Parse a CIDR of either family.
    pub fn parse(s: &str) -> Option<Self> {
        let addr = s.split('/').next()?.trim();
        match addr.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => Ipv4Cidr::parse(s).map(IpCidr::V4),
            Ok(IpAddr::V6(_)) => Ipv6Cidr::parse(s).map(IpCidr::V6),
            Err(_) => None,
        }
    }

    /// Whether `ip` is inside this block. The families must match: a v4
    /// block never contains a v6 address, and vice versa.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (IpCidr::V4(c), IpAddr::V4(a)) => c.contains(a),
            (IpCidr::V6(c), IpAddr::V6(a)) => c.contains(a),
            _ => false,
        }
    }

    /// The prefix length in bits (of this block's family).
    pub fn prefix(&self) -> u8 {
        match self {
            IpCidr::V4(c) => c.prefix(),
            IpCidr::V6(c) => c.prefix(),
        }
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpCidr::V4(c) => write!(f, "{c}"),
            IpCidr::V6(c) => write!(f, "{c}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_contains_respects_prefix() {
        let c = Ipv4Cidr::parse("198.18.0.0/16").unwrap();
        assert!(c.contains("198.18.0.1".parse().unwrap()));
        assert!(c.contains("198.18.255.254".parse().unwrap()));
        assert!(!c.contains("198.19.0.1".parse().unwrap()));
        assert!(!c.contains("198.17.255.255".parse().unwrap()));
        assert_eq!(c.prefix(), 16);
        assert_eq!(c.network(), "198.18.0.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(c.broadcast(), "198.18.255.255".parse::<Ipv4Addr>().unwrap());
        assert_eq!(c.len(), 65_536);
    }

    /// Host bits below the prefix are masked off, not rejected.
    #[test]
    fn v4_host_bits_are_masked() {
        let a = Ipv4Cidr::parse("192.168.1.5/24").unwrap();
        let b = Ipv4Cidr::parse("192.168.1.0/24").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.network(), "192.168.1.0".parse::<Ipv4Addr>().unwrap());
    }

    /// `/0` must match everything and must not panic on the shift.
    #[test]
    fn v4_zero_prefix_matches_all() {
        let c = Ipv4Cidr::parse("0.0.0.0/0").unwrap();
        assert!(c.contains("0.0.0.0".parse().unwrap()));
        assert!(c.contains("255.255.255.255".parse().unwrap()));
        assert_eq!(c.len(), 1u64 << 32);
    }

    /// `/32` is a single-address block.
    #[test]
    fn v4_full_prefix_is_single_host() {
        let c = Ipv4Cidr::parse("1.2.3.4").unwrap();
        assert_eq!(c.prefix(), 32);
        assert!(c.contains("1.2.3.4".parse().unwrap()));
        assert!(!c.contains("1.2.3.5".parse().unwrap()));
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn v4_rejects_bad_input() {
        assert!(Ipv4Cidr::parse("198.18.0.0/33").is_none());
        assert!(Ipv4Cidr::parse("198.18.0.0/").is_none());
        assert!(Ipv4Cidr::parse("not-an-ip/16").is_none());
        assert!(Ipv4Cidr::parse("2001:db8::/32").is_none());
        assert!(Ipv4Cidr::parse("").is_none());
    }

    #[test]
    fn v6_contains_respects_prefix() {
        let c = Ipv6Cidr::parse("2001:db8::/32").unwrap();
        assert!(c.contains("2001:db8::1".parse().unwrap()));
        assert!(c.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(!c.contains("2001:db9::1".parse().unwrap()));
        assert_eq!(c.prefix(), 32);
        assert_eq!(c.network(), "2001:db8::".parse::<Ipv6Addr>().unwrap());
    }

    /// `/0` and `/128` are the v6 boundary cases.
    #[test]
    fn v6_boundary_prefixes() {
        let all = Ipv6Cidr::parse("::/0").unwrap();
        assert!(all.contains("ffff::1".parse().unwrap()));
        let one = Ipv6Cidr::parse("2001:db8::1/128").unwrap();
        assert!(one.contains("2001:db8::1".parse().unwrap()));
        assert!(!one.contains("2001:db8::2".parse().unwrap()));
    }

    /// A block only matches its own address family. The v4-mapped case is
    /// the one that matters: `::ffff:198.18.0.1` is not "inside"
    /// `198.18.0.0/16`, and pretending it is would let a v6 answer escape a
    /// v4 bogus-address filter.
    #[test]
    fn family_never_crosses() {
        let v4 = IpCidr::parse("198.18.0.0/16").unwrap();
        assert!(v4.contains("198.18.0.1".parse().unwrap()));
        assert!(!v4.contains("::ffff:198.18.0.1".parse().unwrap()));

        let v6 = IpCidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6.contains("198.18.0.1".parse().unwrap()));
    }

    #[test]
    fn ip_cidr_parses_both_families() {
        assert!(matches!(IpCidr::parse("10.0.0.0/8"), Some(IpCidr::V4(_))));
        assert!(matches!(IpCidr::parse("fe80::/10"), Some(IpCidr::V6(_))));
        assert!(IpCidr::parse("fe80::/129").is_none());
        assert!(IpCidr::parse("garbage").is_none());
    }

    #[test]
    fn display_round_trips_network_form() {
        let c = Ipv4Cidr::parse("192.168.1.5/24").unwrap();
        assert_eq!(c.to_string(), "192.168.1.0/24");
        assert_eq!(format!("{c:?}"), "192.168.1.0/24");
    }
}
