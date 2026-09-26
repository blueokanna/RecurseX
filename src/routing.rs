//! Upstream routing: which servers serve a name, and whether to trust them.
//!
//! Two Clash surfaces, one decision. `nameserver-policy` picks *who* answers
//! a name; `fallback-filter` decides whether the answer that came back is
//! worth believing and, when it is not, sends the name to the fallback
//! servers instead. Splitting them across two modules would put the "which
//! upstream" answer and the "was it any good" question in different places,
//! and the second only makes sense next to the first.
//!
//! # What the primary path is for
//!
//! `nameserver-policy` exists because a resolver serving a proxy is asked two
//! kinds of question. Public names should go to a public resolver; the
//! proxy's *own* node domains frequently have no public record at all, or a
//! decoy one, and must go to a private resolver. The failure is quiet and
//! total — every connection to those nodes dies immediately — so the policy
//! is consulted before the default servers, never after.
//!
//! Most specific wins: `+.node.example` beats `+.example`. Ties between an
//! exact and a wildcard pattern cannot occur on the same name (an exact
//! pattern matches only itself, a wildcard matches it and below), but the
//! ordering is fixed anyway so the outcome never depends on config order.
//!
//! # What the fallback filter is for
//!
//! Pollution works by answering with an address the real server never gave:
//! a reserved block, a `0.0.0.0` sinkhole, or a foreign address for a name
//! that should resolve domestically. The filter catches the first two
//! directly — the address is one no public `A` record may legitimately
//! carry — and the third through the operator's own `ipcidr` list.
//!
//! ## `geoip` is refused, not ignored
//!
//! Clash's `fallback-filter.geoip` needs a country-to-CIDR database. This
//! crate does not embed one and will not pretend to: a `geoip: true` setting
//! is a **configuration error** naming the two supported replacements
//! (`ipcidr`, `domain`). Silently accepting it would leave an anti-pollution
//! deployment with no anti-pollution at all while its config read as if it
//! had one — the exact failure mode this module exists to avoid.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;

use crate::cidr::IpCidr;
use crate::error::{Error, Result};
use crate::name::Name;
use crate::pattern::{parse_all, DomainPattern};

/// Address blocks that no public `A`/`AAAA` answer may legitimately carry.
///
/// Deliberately *only* those. Private ranges (`10/8`, `192.168/16`) are
/// **not** here: a split-horizon or home-network upstream answers with them
/// all the time, and flagging those as pollution would break working
/// setups. These are the ranges that mean "something is wrong with the
/// answer" rather than "this name is internal" — and they match Clash's
/// defaults, so a ported config keeps its meaning.
pub const DEFAULT_BOGUS_CIDRS: [&str; 6] = [
    "0.0.0.0/8",   // "this network"; a sinkhole's favourite answer
    "127.0.0.0/8", // loopback
    "240.0.0.0/4", // reserved, includes the 255.255.255.255 broadcast
    "::/128",      // unspecified, IPv6
    "::1/128",     // loopback, IPv6
    "100::/64",    // discard-only prefix (RFC 6666)
];

/// Identifies one configured upstream group.
///
/// A plain index into the group table the caller builds. Keeping the module
/// free of the transport types is what lets it stay in the `no_std` core and
/// lets the resolver decide how a group becomes real sockets.
pub type GroupId = usize;

/// The result of consulting [`NameserverPolicy`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Route {
    /// A policy rule matched; use this group.
    Group(GroupId),
    /// No rule matched; use the default group.
    Default,
}

/// Suffix-based upstream selection (`nameserver-policy`).
#[derive(Debug, Clone, Default)]
pub struct NameserverPolicy {
    /// Rules ordered most-specific-first.
    rules: Vec<(DomainPattern, GroupId)>,
}

impl NameserverPolicy {
    /// Build a policy from `(pattern, group)` pairs.
    ///
    /// A pattern that cannot be parsed is an error, and so is a rule whose
    /// pattern is `*`: it would silently shadow every other rule, which is
    /// never what a `nameserver-policy` entry is for.
    pub fn new(rules: &[(String, GroupId)]) -> Result<Self> {
        let mut parsed: Vec<(DomainPattern, GroupId)> = Vec::with_capacity(rules.len());
        for (pattern, group) in rules {
            let p = DomainPattern::parse(pattern).map_err(|e| {
                Error::config(alloc::format!(
                    "nameserver-policy entry {pattern:?}: {}",
                    e.msg
                ))
            })?;
            if matches!(p, DomainPattern::Any) {
                return Err(Error::config(
                    "nameserver-policy entry \"*\" would shadow every other rule; \
                     set the default `nameservers` instead",
                ));
            }
            parsed.push((p, *group));
        }
        parsed.sort_by_key(|entry| core::cmp::Reverse(specificity(&entry.0)));
        Ok(Self { rules: parsed })
    }

    /// The group responsible for `name`.
    pub fn route(&self, name: &Name) -> Route {
        for (pattern, group) in &self.rules {
            if pattern.matches(name) {
                return Route::Group(*group);
            }
        }
        Route::Default
    }

    /// The number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether no rules are configured.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The rules, most specific first.
    pub fn rules(&self) -> &[(DomainPattern, GroupId)] {
        &self.rules
    }
}

/// Specificity key for rule ordering: more labels first, and an exact
/// pattern ahead of a wildcard anchored at the same suffix.
fn specificity(p: &DomainPattern) -> (usize, u8) {
    (
        p.label_count(),
        // Only `Exact` can claim the exact-name slot; every other form is a
        // wildcard of some kind, including the embedded-wildcard form.
        u8::from(p.is_exact()),
    )
}

/// Answer-quality gate (`fallback-filter`).
#[derive(Debug, Clone)]
pub struct FallbackFilter {
    /// Names that skip the primary group entirely.
    domain: Vec<DomainPattern>,
    /// Blocks that mark an answer as poisoned.
    ipcidr: Vec<IpCidr>,
}

impl Default for FallbackFilter {
    fn default() -> Self {
        Self {
            domain: Vec::new(),
            ipcidr: DEFAULT_BOGUS_CIDRS
                .iter()
                .filter_map(|s| IpCidr::parse(s))
                .collect(),
        }
    }
}

impl FallbackFilter {
    /// Build a filter from configuration.
    ///
    /// `ipcidr` distinguishes *absent* from *empty*, because the two mean
    /// different things and conflating them is a silent loss of protection:
    ///
    /// * `None` — the operator configured no `ipcidr` (only, say, `domain`),
    ///   so [`DEFAULT_BOGUS_CIDRS`] applies. A filter that detects nothing
    ///   because the config mentioned a different field is worse than no
    ///   filter at all, since the config still reads as if it protects.
    /// * `Some(list)` — the operator supplied the list; it is used as given,
    ///   even when empty, because an explicit empty list is a decision.
    ///
    /// `geoip` is accepted as a field so a ported Clash config parses, and
    /// rejected when `true` so it cannot be mistaken for working.
    pub fn new(domain: &[String], ipcidr: Option<&[String]>, geoip: bool) -> Result<Self> {
        if geoip {
            return Err(Error::config(
                "fallback-filter.geoip requires a country-to-CIDR database, which this \
                 build does not embed; set `geoip` to false and use `ipcidr` (the ranges \
                 that count as pollution) and `domain` (names that always use the \
                 fallback servers) instead",
            ));
        }
        let domain = parse_all(domain)?;
        let blocks = match ipcidr {
            None => DEFAULT_BOGUS_CIDRS
                .iter()
                .filter_map(|s| IpCidr::parse(s))
                .collect(),
            Some(list) => {
                let mut blocks = Vec::with_capacity(list.len());
                for (i, s) in list.iter().enumerate() {
                    let c = IpCidr::parse(s).ok_or_else(|| {
                        Error::config(alloc::format!(
                            "fallback-filter.ipcidr #{i}: {s:?} is not a CIDR"
                        ))
                    })?;
                    blocks.push(c);
                }
                blocks
            }
        };
        Ok(Self {
            domain,
            ipcidr: blocks,
        })
    }

    /// Whether `name` must use the fallback group outright, without trying
    /// the primary group first.
    pub fn forces_fallback(&self, name: &Name) -> bool {
        self.domain.iter().any(|p| p.matches(name))
    }

    /// Whether an answer containing these addresses looks poisoned.
    ///
    /// Returns the first offending address so a caller can log *what* was
    /// rejected. Any single bad address is enough: a polluted response
    /// typically mixes the real record with fabricated ones, and trusting
    /// the response because one address looked fine is exactly the mistake
    /// the filter is here to prevent.
    pub fn looks_poisoned(&self, addrs: &[IpAddr]) -> Option<IpAddr> {
        addrs
            .iter()
            .find(|a| self.ipcidr.iter().any(|b| b.contains(**a)))
            .copied()
    }

    /// The configured pollution blocks.
    pub fn ipcidr(&self) -> &[IpCidr] {
        &self.ipcidr
    }

    /// The names that always use the fallback group.
    pub fn domain(&self) -> &[DomainPattern] {
        &self.domain
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::string::ToString;
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn policy(rules: &[(&str, GroupId)]) -> NameserverPolicy {
        let owned: Vec<(String, GroupId)> =
            rules.iter().map(|(s, g)| ((*s).to_string(), *g)).collect();
        NameserverPolicy::new(&owned).unwrap()
    }

    #[test]
    fn policy_picks_the_most_specific_rule() {
        let p = policy(&[
            ("+.example.com", 1),
            ("+.node.example.com", 2),
            ("special.node.example.com", 3),
        ]);
        assert_eq!(p.route(&n("a.example.com")), Route::Group(1));
        assert_eq!(p.route(&n("a.node.example.com")), Route::Group(2));
        assert_eq!(p.route(&n("node.example.com")), Route::Group(2));
        assert_eq!(p.route(&n("special.node.example.com")), Route::Group(3));
        assert_eq!(p.route(&n("other.com")), Route::Default);
    }

    /// Config key order must not change behaviour.
    #[test]
    fn rule_order_in_config_does_not_matter() {
        let a = policy(&[("+.node.example.com", 2), ("+.example.com", 1)]);
        let b = policy(&[("+.example.com", 1), ("+.node.example.com", 2)]);
        for name in ["a.example.com", "a.node.example.com", "unrelated.test"] {
            assert_eq!(a.route(&n(name)), b.route(&n(name)), "{name}");
        }
    }

    /// The proxy's own node domains are the motivating case: they must reach
    /// the private resolver, and a sibling name must not.
    #[test]
    fn node_domains_are_routed_and_neighbours_are_not() {
        let p = policy(&[("+.v51124-6.qpon", 1), ("+.qpon", 2)]);
        assert_eq!(p.route(&n("n1.v51124-6.qpon")), Route::Group(1));
        assert_eq!(p.route(&n("other.qpon")), Route::Group(2));
        assert_eq!(p.route(&n("notqpon")), Route::Default);
    }

    #[test]
    fn catch_all_policy_is_refused() {
        let rules = vec![("*".to_string(), 1)];
        let err = NameserverPolicy::new(&rules).unwrap_err();
        assert!(err.msg.contains("shadow"), "{}", err.msg);
    }

    #[test]
    fn bad_policy_pattern_is_refused_with_its_key() {
        let rules = vec![("+.".to_string(), 1)];
        let err = NameserverPolicy::new(&rules).unwrap_err();
        assert!(err.msg.contains("nameserver-policy"), "{}", err.msg);
    }

    #[test]
    fn empty_policy_always_routes_default() {
        let p = NameserverPolicy::default();
        assert!(p.is_empty());
        assert_eq!(p.route(&n("example.com")), Route::Default);
    }

    /// The default filter catches exactly the ranges no public answer may
    /// carry — and does not catch private space, which is legitimate.
    #[test]
    fn default_filter_catches_sinkholes_but_not_private_space() {
        let f = FallbackFilter::default();
        let bad = [
            "0.0.0.0",
            "127.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
        ];
        for s in bad {
            let ip: IpAddr = s.parse().unwrap();
            assert_eq!(
                f.looks_poisoned(&[ip]),
                Some(ip),
                "{s} should be flagged as pollution"
            );
        }
        let fine = ["1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"];
        for s in fine {
            assert!(
                f.looks_poisoned(&[s.parse().unwrap()]).is_none(),
                "{s} is a legitimate answer"
            );
        }
    }

    /// Private ranges must NOT be flagged by default: home and split-horizon
    /// upstreams answer with them legitimately.
    #[test]
    fn private_space_is_not_pollution_by_default() {
        let f = FallbackFilter::default();
        for s in ["10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1"] {
            assert!(f.looks_poisoned(&[s.parse().unwrap()]).is_none(), "{s}");
        }
    }

    /// One bad address among good ones poisons the whole answer.
    #[test]
    fn any_bad_address_marks_the_answer() {
        let f = FallbackFilter::default();
        let mixed: Vec<IpAddr> = vec!["1.1.1.1".parse().unwrap(), "0.0.0.0".parse().unwrap()];
        assert_eq!(f.looks_poisoned(&mixed), Some("0.0.0.0".parse().unwrap()));
        assert!(f.looks_poisoned(&[]).is_none());
    }

    #[test]
    fn custom_ipcidr_replaces_the_defaults() {
        let list = vec!["198.18.0.0/15".to_string()];
        let f = FallbackFilter::new(&[], Some(&list), false).unwrap();
        assert_eq!(
            f.looks_poisoned(&["198.18.0.1".parse().unwrap()]),
            Some("198.18.0.1".parse().unwrap())
        );
        // An explicit list replaces the built-ins rather than merging with
        // them: 0.0.0.0 is no longer flagged once the operator supplied
        // their own list.
        assert!(f.looks_poisoned(&["0.0.0.0".parse().unwrap()]).is_none());
    }

    /// Omitting `ipcidr` keeps the built-in protection; supplying an empty
    /// list is an explicit decision to have none. Conflating the two would
    /// leave a config that mentions `domain` looking protected while
    /// detecting nothing.
    #[test]
    fn absent_ipcidr_keeps_defaults_while_empty_means_empty() {
        let absent = FallbackFilter::new(&["+.google.com".to_string()], None, false).unwrap();
        assert_eq!(absent.ipcidr().len(), DEFAULT_BOGUS_CIDRS.len());
        assert!(absent
            .looks_poisoned(&["0.0.0.0".parse().unwrap()])
            .is_some());

        let empty = FallbackFilter::new(&["+.google.com".to_string()], Some(&[]), false).unwrap();
        assert!(empty.ipcidr().is_empty());
        assert!(empty
            .looks_poisoned(&["0.0.0.0".parse().unwrap()])
            .is_none());
        // ... and the domain rule still works either way.
        assert!(empty.forces_fallback(&n("www.google.com")));
    }

    /// A `domain` entry forces the fallback group for that name and below.
    #[test]
    fn domain_entries_force_the_fallback_group() {
        let f = FallbackFilter::new(&["+.google.com".to_string()], None, false).unwrap();
        assert!(f.forces_fallback(&n("google.com")));
        assert!(f.forces_fallback(&n("www.google.com")));
        assert!(!f.forces_fallback(&n("notgoogle.com")));
        assert!(!f.forces_fallback(&n("google.com.evil.test")));
    }

    /// `geoip: true` is refused with the replacements named, because
    /// accepting it would leave an anti-pollution deployment with none.
    #[test]
    fn geoip_is_refused_with_a_usable_alternative() {
        let err = FallbackFilter::new(&[], None, true).unwrap_err();
        assert!(err.msg.contains("geoip"), "{}", err.msg);
        assert!(err.msg.contains("ipcidr"), "{}", err.msg);
        assert!(err.msg.contains("domain"), "{}", err.msg);
        // ... and false is fine.
        assert!(FallbackFilter::new(&[], None, false).is_ok());
    }

    #[test]
    fn bad_ipcidr_is_refused_with_its_position() {
        let list = vec!["not-a-cidr".to_string()];
        let err = FallbackFilter::new(&[], Some(&list), false).unwrap_err();
        assert!(err.msg.contains("#0"), "{}", err.msg);
        let list = vec!["10.0.0.0/8".to_string(), "junk".to_string()];
        let err = FallbackFilter::new(&[], Some(&list), false).unwrap_err();
        assert!(err.msg.contains("#1"), "{}", err.msg);
    }
}
