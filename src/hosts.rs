//! Static answers: the `hosts` table.
//!
//! `hosts` pins a name to addresses before any network work happens. It is
//! the one answer source that is *always* right by construction — the
//! operator said so — so it sits in front of the cache, not behind it, and
//! nothing it answers is ever cached: config reloads and local overrides
//! must take effect on the next query, not after a TTL.
//!
//! # What the table owns, and what it does not
//!
//! A pin is authoritative for **`A` and `AAAA` only**:
//!
//! * `example.com` pinned to `10.0.0.1` answers `A` with `10.0.0.1`.
//! * The same pin answers `AAAA` with **NODATA**, not with the real address
//!   and not by going upstream. This is the point of the pin: a client that
//!   follows a leaked `AAAA` record would dial a host the operator explicitly
//!   pointed somewhere else.
//! * `MX`, `TXT`, `SRV` and everything else are **not** touched. A user who
//!   pins `example.com` for local development still wants its mail to work,
//!   and a `hosts` entry is a statement about addresses, not an assertion
//!   that the name has no other records.
//!
//! # Wildcards
//!
//! Keys accept the Clash wildcard spellings through
//! [`DomainPattern`]: `*.example.com`,
//! `+.example.com` and `.example.com` all pin `example.com` **and** every
//! name below it. The most specific pattern wins, so a `+.*` entry can be
//! overridden by an exact entry on one host.
//!
//! `*` on its own is rejected. A catch-all `hosts` entry answers every name
//! from a static table, which is indistinguishable from "DNS is broken", and
//! it is never what someone meant to write.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;

use crate::error::{Error, Result};
use crate::name::Name;
use crate::pattern::DomainPattern;
use crate::qtype::{RrClass, RrType};
use crate::rdata::{RData, Record};

/// The TTL reported for a `hosts` answer when none is configured.
///
/// Short on purpose. The data is static, but the *configuration* is not: a
/// reload should be visible quickly, and a client that caches a pin for an
/// hour makes a typo hard to undo.
pub const DEFAULT_HOSTS_TTL: u32 = 60;

/// A static name-to-address table.
#[derive(Debug, Clone)]
pub struct HostsTable {
    ttl: u32,
    /// Exact-name pins.
    exact: BTreeMap<Name, Vec<IpAddr>>,
    /// Pattern pins, ordered most-specific first (longest match wins).
    wildcard: Vec<(DomainPattern, Vec<IpAddr>)>,
}

/// An empty table with the default TTL. Deriving this would set the TTL to
/// zero, which is a different thing from "unconfigured".
impl Default for HostsTable {
    fn default() -> Self {
        Self::new(DEFAULT_HOSTS_TTL)
    }
}

impl HostsTable {
    /// An empty table whose answers carry `ttl` seconds.
    pub fn new(ttl: u32) -> Self {
        Self {
            ttl,
            exact: BTreeMap::new(),
            wildcard: Vec::new(),
        }
    }

    /// The TTL carried by answers from this table.
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// The number of configured patterns (not the number of addresses).
    pub fn len(&self) -> usize {
        self.exact.len() + self.wildcard.len()
    }

    /// Whether the table has no entries.
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty()
    }

    /// Add a pin. `pattern` accepts the Clash wildcard spellings; values are
    /// added to any already pinned for the same key.
    pub fn insert(&mut self, pattern: &str, addrs: &[IpAddr]) -> Result<()> {
        let parsed = DomainPattern::parse(pattern)?;
        if matches!(parsed, DomainPattern::Any) {
            return Err(Error::config(
                "a \"*\" entry in `hosts` would answer every name from the static table; \
                 list the domains you meant instead",
            ));
        }
        if let DomainPattern::Exact(name) = parsed {
            let slot = self.exact.entry(name).or_default();
            for a in addrs {
                if !slot.contains(a) {
                    slot.push(*a);
                }
            }
            return Ok(());
        }
        // Every other pattern is matched in order of specificity. Keeping
        // them in one list (rather than separate lists per pattern kind) is
        // what lets a `Subtree` entry and an embedded-wildcard entry compete
        // on label count instead of on which list they happen to be in.
        if let Some((_, slot)) = self.wildcard.iter_mut().find(|(p, _)| *p == parsed) {
            for a in addrs {
                if !slot.contains(a) {
                    slot.push(*a);
                }
            }
        } else {
            let mut slot: Vec<IpAddr> = Vec::with_capacity(addrs.len());
            for a in addrs {
                if !slot.contains(a) {
                    slot.push(*a);
                }
            }
            self.wildcard.push((parsed, slot));
        }
        // Most specific first, so the first match is the answer.
        self.wildcard
            .sort_by(|a, b| b.0.label_count().cmp(&a.0.label_count()));
        Ok(())
    }

    /// Add a pin from configuration, parsing each value as an IP address.
    ///
    /// A value that is not an IP address is an error, not a skipped entry.
    /// Clash's `hosts` is an address map; a domain value would silently
    /// become a pin that answers nothing, which is worse than refusing to
    /// start.
    pub fn insert_from_config(&mut self, pattern: &str, values: &[String]) -> Result<()> {
        if values.is_empty() {
            return Err(Error::config(alloc::format!(
                "hosts entry {pattern:?} has no addresses"
            )));
        }
        let mut addrs = Vec::with_capacity(values.len());
        for v in values {
            let ip: IpAddr = v.trim().parse().map_err(|_| {
                Error::config(alloc::format!(
                    "hosts entry {pattern:?}: {:?} is not an IP address",
                    v.trim()
                ))
            })?;
            addrs.push(ip);
        }
        self.insert(pattern, &addrs)
    }

    /// The addresses pinned for `name`: an exact match first, else the
    /// most-specific pattern that matches.
    pub fn lookup(&self, name: &Name) -> Option<&[IpAddr]> {
        if let Some(v) = self.exact.get(name) {
            return Some(v.as_slice());
        }
        for (pattern, addrs) in &self.wildcard {
            if pattern.matches(name) {
                return Some(addrs.as_slice());
            }
        }
        None
    }

    /// Whether the table owns `name`.
    pub fn contains(&self, name: &Name) -> bool {
        self.lookup(name).is_some()
    }

    /// The records to answer `name`/`rr_type` with.
    ///
    /// * `None` — the table does not own this name, or does not manage this
    ///   record type; the caller resolves normally.
    /// * `Some([])` — the table owns the name and it has no address of the
    ///   queried family: answer NODATA. Do not fall through to the network.
    /// * `Some(records)` — answer with these records.
    pub fn answer(&self, name: &Name, rr_type: RrType) -> Option<Vec<Record>> {
        if !matches!(rr_type, RrType::A | RrType::AAAA) {
            return None;
        }
        let addrs = self.lookup(name)?;
        let mut out = Vec::new();
        for ip in addrs {
            let rdata = match (rr_type, ip) {
                (RrType::A, IpAddr::V4(v4)) => RData::A(*v4),
                (RrType::AAAA, IpAddr::V6(v6)) => RData::Aaaa(*v6),
                _ => continue,
            };
            out.push(Record {
                name: name.clone(),
                rr_type,
                class: RrClass::IN,
                ttl: self.ttl,
                rdata,
            });
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn table(pairs: &[(&str, &[&str])]) -> HostsTable {
        let mut t = HostsTable::new(DEFAULT_HOSTS_TTL);
        for (k, vs) in pairs {
            let vals: Vec<String> = vs.iter().map(|s| (*s).to_string()).collect();
            t.insert_from_config(k, &vals).unwrap();
        }
        t
    }

    fn a_addrs(recs: &[Record]) -> Vec<alloc::string::String> {
        recs.iter()
            .filter_map(|r| match &r.rdata {
                RData::A(v) => Some(v.to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn exact_pin_answers_the_matching_family() {
        let t = table(&[("example.com", &["10.0.0.1", "2001:db8::1"])]);
        let v4 = t.answer(&n("example.com"), RrType::A).unwrap();
        assert_eq!(a_addrs(&v4), vec!["10.0.0.1"]);
        assert_eq!(v4[0].ttl, DEFAULT_HOSTS_TTL);

        let v6 = t.answer(&n("example.com"), RrType::AAAA).unwrap();
        assert_eq!(v6.len(), 1);
        assert!(matches!(v6[0].rdata, RData::Aaaa(_)));
    }

    /// A v4-only pin makes `AAAA` NODATA. Returning the real address, or
    /// falling through to the network, would defeat the pin.
    #[test]
    fn missing_family_is_nodata_not_a_leak() {
        let t = table(&[("example.com", &["10.0.0.1"])]);
        let v6 = t.answer(&n("example.com"), RrType::AAAA).unwrap();
        assert!(v6.is_empty(), "AAAA must be an empty answer, not a miss");
    }

    /// The pin is about addresses only; other record types still resolve.
    #[test]
    fn other_record_types_pass_through() {
        let t = table(&[("example.com", &["10.0.0.1"])]);
        assert!(t.answer(&n("example.com"), RrType::MX).is_none());
        assert!(t.answer(&n("example.com"), RrType::TXT).is_none());
        assert!(t.answer(&n("example.com"), RrType::AAAA).is_some());
    }

    #[test]
    fn unpinned_name_is_not_owned() {
        let t = table(&[("example.com", &["10.0.0.1"])]);
        assert!(t.answer(&n("other.com"), RrType::A).is_none());
        assert!(!t.contains(&n("other.com")));
    }

    /// Wildcards cover the apex and every child, and nothing that merely
    /// ends with the same characters.
    #[test]
    fn wildcard_covers_apex_and_children_only() {
        let t = table(&[("*.example.com", &["10.0.0.9"])]);
        for name in ["example.com", "a.example.com", "a.b.example.com"] {
            let recs = t.answer(&n(name), RrType::A).expect("owned");
            assert_eq!(a_addrs(&recs), vec!["10.0.0.9"], "{name}");
        }
        assert!(t.answer(&n("notexample.com"), RrType::A).is_none());
        assert!(t.answer(&n("example.com.evil.test"), RrType::A).is_none());
    }

    /// The most specific pattern wins, and an exact entry beats a wildcard.
    #[test]
    fn most_specific_pattern_wins() {
        let t = table(&[
            ("+.example.com", &["10.0.0.1"]),
            ("+.deep.example.com", &["10.0.0.2"]),
            ("special.deep.example.com", &["10.0.0.3"]),
        ]);
        let get = |name: &str| a_addrs(&t.answer(&n(name), RrType::A).unwrap());
        assert_eq!(get("a.example.com"), vec!["10.0.0.1"]);
        assert_eq!(get("a.deep.example.com"), vec!["10.0.0.2"]);
        assert_eq!(get("deep.example.com"), vec!["10.0.0.2"]);
        // Exact beats the broader wildcard.
        assert_eq!(get("special.deep.example.com"), vec!["10.0.0.3"]);
        // A sibling of the exact entry still uses the wildcard.
        assert_eq!(get("other.deep.example.com"), vec!["10.0.0.2"]);
    }

    /// Every wildcard spelling means the same thing here too.
    #[test]
    fn wildcard_spellings_agree() {
        let plus = table(&[("+.example.com", &["10.0.0.1"])]);
        let star = table(&[("*.example.com", &["10.0.0.1"])]);
        let dot = table(&[(".example.com", &["10.0.0.1"])]);
        for name in ["example.com", "a.example.com"] {
            assert_eq!(plus.lookup(&n(name)), star.lookup(&n(name)));
            assert_eq!(plus.lookup(&n(name)), dot.lookup(&n(name)));
        }
    }

    /// A non-IP value is refused with the offending entry named, because a
    /// silently-inert pin is the failure mode worth preventing.
    #[test]
    fn non_ip_value_is_rejected() {
        let mut t = HostsTable::new(60);
        let err = t
            .insert_from_config("example.com", &["not-an-ip".to_string()])
            .unwrap_err();
        assert!(err.msg.contains("example.com"), "{}", err.msg);
        assert!(err.msg.contains("not-an-ip"), "{}", err.msg);
        assert!(t.is_empty(), "a rejected entry must not be inserted");
    }

    #[test]
    fn empty_value_list_is_rejected() {
        let mut t = HostsTable::new(60);
        let err = t.insert_from_config("example.com", &[]).unwrap_err();
        assert!(err.msg.contains("no addresses"), "{}", err.msg);
    }

    /// A catch-all would answer every name from a static table.
    #[test]
    fn catch_all_is_rejected() {
        let mut t = HostsTable::new(60);
        let err = t.insert("*", &["10.0.0.1".parse().unwrap()]).unwrap_err();
        assert!(err.msg.contains("hosts"), "{}", err.msg);
        assert!(t.is_empty());
    }

    /// Repeating a key unions the addresses rather than replacing them.
    #[test]
    fn repeated_key_unions_and_dedupes() {
        let mut t = HostsTable::new(60);
        t.insert("example.com", &["10.0.0.1".parse().unwrap()])
            .unwrap();
        t.insert("example.com", &["10.0.0.1".parse().unwrap()])
            .unwrap();
        t.insert("example.com", &["10.0.0.2".parse().unwrap()])
            .unwrap();
        let recs = t.answer(&n("example.com"), RrType::A).unwrap();
        assert_eq!(a_addrs(&recs), vec!["10.0.0.1", "10.0.0.2"]);
        assert_eq!(t.len(), 1);
    }

    /// Default table is empty and owns nothing.
    #[test]
    fn default_is_empty() {
        let t = HostsTable::default();
        assert!(t.is_empty());
        assert!(t.answer(&n("example.com"), RrType::A).is_none());
    }

    /// A trailing-dot / uppercase key in config is the same pin as the
    /// wire form a client actually sends.
    #[test]
    fn keys_are_normalized() {
        let t = table(&[("Example.COM.", &["10.0.0.1"])]);
        assert_eq!(
            a_addrs(&t.answer(&n("example.com"), RrType::A).unwrap()),
            vec!["10.0.0.1"]
        );
    }

    /// An embedded-wildcard key works here too: `hosts` uses the same matcher
    /// as every other pattern surface, so the syntax cannot drift apart.
    #[test]
    fn embedded_wildcard_keys_are_supported() {
        let t = table(&[("time.*.com", &["10.0.0.7"])]);
        assert_eq!(
            a_addrs(&t.answer(&n("time.apple.com"), RrType::A).unwrap()),
            vec!["10.0.0.7"]
        );
        // Wrong label count or wrong tail is not owned, so it resolves
        // normally rather than silently answering.
        assert!(t.answer(&n("time.a.b.com"), RrType::A).is_none());
        assert!(t.answer(&n("time.apple.org"), RrType::A).is_none());
    }

    /// Patterns of different kinds compete on label count, not on the order
    /// they appear in the configuration.
    #[test]
    fn pattern_kinds_compete_on_specificity() {
        let t = table(&[
            ("+.example.com", &["10.0.0.1"]),
            ("time.*.com", &["10.0.0.2"]),
        ]);
        // Only the embedded pattern matches this one.
        assert_eq!(
            a_addrs(&t.answer(&n("time.apple.com"), RrType::A).unwrap()),
            vec!["10.0.0.2"]
        );
        // Only the subtree matches this one.
        assert_eq!(
            a_addrs(&t.answer(&n("time.apple.example.com"), RrType::A).unwrap()),
            vec!["10.0.0.1"]
        );
    }
}
