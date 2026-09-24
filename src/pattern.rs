//! Clash-style domain patterns, in one place.
//!
//! Four different configuration surfaces ask the same question — *does this
//! name match this pattern* — in Clash syntax:
//!
//! | Surface               | Example entry            |
//! |-----------------------|--------------------------|
//! | `hosts`               | `"*.example.com"`        |
//! | `fake-ip-filter`      | `"+.lan"`                |
//! | `fallback-filter`     | `"*.google.com"`         |
//! | `nameserver-policy`   | `"+.v51124-6.qpon"`      |
//!
//! Writing that matcher once per surface is how the surfaces drift apart, and
//! drift in a *filter* is not a cosmetic bug: a `fake-ip-filter` entry that
//! silently means something other than what its neighbours mean leaks a real
//! address where the operator asked for a fake one. So this module owns the
//! syntax, and every surface parses through [`DomainPattern::parse`].
//!
//! # Syntax
//!
//! | Form | Meaning |
//! |------|---------|
//! | `example.com` | exactly that name |
//! | `*.example.com`, `+.example.com`, `.example.com` | `example.com` and every name below it |
//! | `*` | every name |
//! | `time.*.com`, `stun.*.*` | label-wise: each `*` is exactly one label |
//! | `*.stun.*.*` | a leading `*` is zero or more labels, the rest one each |
//!
//! All of `*.example.com`, `+.example.com` and `.example.com` mean **the same
//! thing**: `example.com` and every name below it. A bare `example.com` is
//! exact — only that name.
//!
//! Folding the three wildcard spellings together is deliberate. Clash-family
//! clients accept all three for "this domain and its subdomains", and a
//! configuration ported between them must not change meaning. The one visible
//! consequence: `*.example.com` matches `example.com` itself. That is the
//! useful reading (an operator writing `*.example.com` in a filter means the
//! site, not just its children), and it is the reading mihomo documents for
//! `+.`.
//!
//! # Embedded wildcards
//!
//! A `*` may also appear in a non-leading position, which is what mihomo's
//! own default `fake-ip-filter` does (`time.*.com`, `*.stun.*.*`). Those
//! patterns are matched label by label, and a `*` label matches exactly one
//! label. Supporting the form is not a flourish: `time.*.com` parsed as a
//! literal name would compile into a pattern that matches nothing, and a
//! filter that silently matches nothing looks exactly like a filter that is
//! not configured. Rejecting it would be honest but would make a ported
//! config fail on a pattern mihomo ships by default.
//!
//! A leading `*` always means "zero or more labels" and makes the pattern a
//! **suffix** match, so `*.stun.*.*` matches both `stun.a.b` and
//! `x.stun.a.b`. A pattern with no leading `*` must match the whole name
//! label for label, so `time.*.com` matches `time.apple.com` and not
//! `x.time.apple.com` — a time-server entry names a three-label host, not a
//! namespace.
//!
//! # Matching is label-bounded
//!
//! `example.com` never matches `notexample.com` or `example.com.evil.test`.
//! The comparison is a whole-label suffix test on the wire encoding, so
//! `example.com` only matches a name whose last two labels are exactly
//! `example` and `com`.
//!
//! # No allocation per match
//!
//! Comparison runs directly on the two wire forms
//! ([`Name::is_subdomain_of`](crate::name::Name::is_subdomain_of)), which is
//! a `memcmp` on the tail. Names parsed from the wire and names parsed from
//! config are both canonical lowercase (see
//! [`Name::from_ascii`](crate::name::Name::from_ascii) and
//! [`Name::from_wire`](crate::name::Name::from_wire)), so a byte comparison
//! is the correct case-insensitive comparison and needs no normalization
//! step on the query path.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::error::{Error, Result};
use crate::name::Name;

/// A Clash-style domain pattern.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DomainPattern {
    /// Matches every name (`*`).
    Any,
    /// Matches exactly one name (`example.com`).
    Exact(Name),
    /// Matches a name and everything below it
    /// (`*.example.com`, `+.example.com`, `.example.com`).
    Subtree(Name),
    /// Matches label by label with embedded wildcards (`time.*.com`,
    /// `*.stun.*.*`).
    Wildcard(WildcardPattern),
}

/// A pattern with a `*` in a non-leading position.
///
/// A `*` label matches exactly one label. When the pattern begins with a `*`,
/// that leading `*` matches zero or more labels and the rest of the pattern is
/// matched against the **tail** of the name; otherwise the name must have the
/// same number of labels as the pattern.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WildcardPattern {
    /// The pattern's labels; `None` is a `*`.
    labels: Vec<Option<Vec<u8>>>,
    /// Whether the pattern began with `*`, making it a suffix match.
    leading_wildcard: bool,
}

impl WildcardPattern {
    /// The number of labels in the pattern. A leading wildcard counts as one,
    /// which is what makes it comparable with the label count of a
    /// [`DomainPattern::Subtree`] suffix in the rule ordering.
    pub fn label_count(&self) -> usize {
        self.labels.len() + usize::from(self.leading_wildcard)
    }

    /// Whether `name` matches.
    pub fn matches(&self, name: &Name) -> bool {
        let labels = name.labels();
        let (candidate, pattern) = if self.leading_wildcard {
            // The leading `*` absorbs whatever comes before the tail. Zero
            // labels is allowed, so `*.a.b` matches `a.b` — the same reading
            // `Subtree` gives `*.a.b`.
            match labels.len().checked_sub(self.labels.len()) {
                Some(skip) => (
                    labels.get(skip..).unwrap_or_default(),
                    self.labels.as_slice(),
                ),
                None => return false,
            }
        } else {
            if labels.len() != self.labels.len() {
                return false;
            }
            (&labels[..], &self.labels[..])
        };
        candidate
            .iter()
            .zip(pattern.iter())
            .all(|(label, pat)| match pat {
                None => true,
                Some(lit) => &lit[..] == *label,
            })
    }
}

impl fmt::Display for WildcardPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.leading_wildcard {
            f.write_str("*.")?;
        }
        for (i, label) in self.labels.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            match label {
                None => f.write_str("*")?,
                Some(lit) => f.write_str(&alloc::string::String::from_utf8_lossy(lit))?,
            }
        }
        Ok(())
    }
}

impl DomainPattern {
    /// Parse one pattern. Rejects anything that would silently mean
    /// "nothing" — an empty string, a lone `*.`, an empty suffix, an empty
    /// label.
    pub fn parse(s: &str) -> Result<Self> {
        let raw = s.trim();
        if raw.is_empty() {
            return Err(Error::config("empty domain pattern"));
        }
        if raw == "*" {
            return Ok(DomainPattern::Any);
        }
        if raw.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err(Error::config(alloc::format!(
                "domain pattern {raw:?} contains whitespace"
            )));
        }
        // Escapes in a pattern would have to be honoured through the label
        // split, and no Clash-family config uses them. Accepting them and
        // mishandling them is the failure mode this module exists to avoid.
        if raw.contains('\\') {
            return Err(Error::config(alloc::format!(
                "domain pattern {raw:?}: escapes are not supported in patterns"
            )));
        }

        // A leading marker means "this name and below".
        let (suffix, leading) = if let Some(r) = raw.strip_prefix("*.") {
            (r, true)
        } else if let Some(r) = raw.strip_prefix("+.") {
            (r, true)
        } else if let Some(r) = raw.strip_prefix('.') {
            (r, true)
        } else {
            (raw, false)
        };
        let suffix = suffix.trim_end_matches('.');
        if suffix.is_empty() {
            return Err(Error::config(alloc::format!(
                "domain pattern {raw:?} has an empty suffix"
            )));
        }

        let parts: Vec<&str> = suffix.split('.').collect();
        if parts.iter().any(|p| p.is_empty()) {
            return Err(Error::config(alloc::format!(
                "domain pattern {raw:?} has an empty label"
            )));
        }
        if !parts.iter().any(|p| *p == "*") {
            let name = Name::from_ascii(suffix)
                .map_err(|e| Error::config(alloc::format!("bad domain pattern {raw:?}: {e}")))?;
            if name.is_root() {
                return Err(Error::config(alloc::format!(
                    "domain pattern {raw:?} resolves to the root; use \"*\" for a match-all"
                )));
            }
            return Ok(if leading {
                DomainPattern::Subtree(name)
            } else {
                DomainPattern::Exact(name)
            });
        }

        // At least one `*` label. Validate every literal label through the
        // name parser so a pattern and a query name are judged by the same
        // rules (case folding, the 63-octet label limit, character escapes).
        let mut labels: Vec<Option<Vec<u8>>> = Vec::with_capacity(parts.len());
        for part in &parts {
            if *part == "*" {
                labels.push(None);
                continue;
            }
            let one = Name::from_ascii(part)
                .map_err(|e| Error::config(alloc::format!("bad domain pattern {raw:?}: {e}")))?;
            let bytes = one
                .labels()
                .first()
                .map(|l| l.to_vec())
                .ok_or_else(|| Error::config(alloc::format!("bad domain pattern {raw:?}")))?;
            labels.push(Some(bytes));
        }
        Ok(DomainPattern::Wildcard(WildcardPattern {
            labels,
            leading_wildcard: leading,
        }))
    }

    /// Whether `name` matches this pattern.
    pub fn matches(&self, name: &Name) -> bool {
        match self {
            DomainPattern::Any => true,
            DomainPattern::Exact(n) => name == n,
            DomainPattern::Subtree(n) => name.is_subdomain_of(n),
            DomainPattern::Wildcard(w) => w.matches(name),
        }
    }

    /// The suffix this pattern is anchored on, or `None` when it is not
    /// anchored to a single name ([`Any`] and [`Wildcard`]).
    ///
    /// [`Any`]: DomainPattern::Any
    /// [`Wildcard`]: DomainPattern::Wildcard
    pub fn suffix(&self) -> Option<&Name> {
        match self {
            DomainPattern::Any | DomainPattern::Wildcard(_) => None,
            DomainPattern::Exact(n) | DomainPattern::Subtree(n) => Some(n),
        }
    }

    /// Whether this pattern is a wildcard pattern.
    pub fn is_wildcard(&self) -> bool {
        matches!(self, DomainPattern::Subtree(_) | DomainPattern::Wildcard(_))
    }

    /// The number of labels this pattern is anchored on. Used to order rules
    /// most-specific-first; `0` for [`Any`].
    ///
    /// [`Any`]: DomainPattern::Any
    pub fn label_count(&self) -> usize {
        match self {
            DomainPattern::Any => 0,
            DomainPattern::Exact(n) | DomainPattern::Subtree(n) => n.label_count(),
            DomainPattern::Wildcard(w) => w.label_count(),
        }
    }

    /// Whether this pattern names exactly one name.
    pub fn is_exact(&self) -> bool {
        matches!(self, DomainPattern::Exact(_))
    }
}

impl fmt::Display for DomainPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainPattern::Any => f.write_str("*"),
            DomainPattern::Exact(n) => write!(f, "{}", n.to_ascii()),
            DomainPattern::Subtree(n) => write!(f, "*.{}", n.to_ascii()),
            DomainPattern::Wildcard(w) => write!(f, "{w}"),
        }
    }
}

/// Parse a list of patterns, reporting the first bad entry by position.
pub fn parse_all(items: &[String]) -> Result<alloc::vec::Vec<DomainPattern>> {
    let mut out = alloc::vec::Vec::with_capacity(items.len());
    for (i, s) in items.iter().enumerate() {
        out.push(
            DomainPattern::parse(s)
                .map_err(|e| Error::config(alloc::format!("pattern #{i} ({s:?}): {}", e.msg)))?,
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    /// The three wildcard spellings are one rule: self and subdomains.
    #[test]
    fn wildcard_spellings_are_equivalent() {
        for spelling in ["*.example.com", "+.example.com", ".example.com"] {
            let p = DomainPattern::parse(spelling).unwrap();
            assert!(p.is_wildcard(), "{spelling} should be a subtree pattern");
            assert!(p.matches(&n("example.com")), "{spelling} matches the apex");
            assert!(p.matches(&n("a.example.com")), "{spelling} matches a child");
            assert!(
                p.matches(&n("a.b.example.com")),
                "{spelling} matches a deep child"
            );
            assert_eq!(p.suffix(), Some(&n("example.com")));
        }
    }

    /// Label boundaries matter: a suffix match must not become a substring
    /// match. This is the classic way a domain filter gets bypassed.
    #[test]
    fn subtree_respects_label_boundaries() {
        let p = DomainPattern::parse("*.example.com").unwrap();
        assert!(!p.matches(&n("notexample.com")), "no bare-substring match");
        assert!(!p.matches(&n("aexample.com")), "no prefix-glued match");
        assert!(
            !p.matches(&n("example.com.evil.test")),
            "the pattern must not match when it is the middle of the name"
        );
        assert!(!p.matches(&n("com")), "no shorter suffix");
        assert!(!p.matches(&n("example.org")), "different TLD");
    }

    /// A bare name is exact, not a subtree: `example.com` in `hosts` must not
    /// pin every subdomain.
    #[test]
    fn bare_name_is_exact() {
        let p = DomainPattern::parse("example.com").unwrap();
        assert!(!p.is_wildcard());
        assert!(p.matches(&n("example.com")));
        assert!(!p.matches(&n("a.example.com")));
        assert!(!p.matches(&n("example.com.evil.test")));
    }

    #[test]
    fn match_all_covers_everything_including_root() {
        let p = DomainPattern::parse("*").unwrap();
        for name in ["example.com", "a.b.c.example.org", "."] {
            assert!(p.matches(&n(name)), "{name} should match *");
        }
        assert!(p.suffix().is_none());
    }

    /// Trailing dots and spacing must not change the meaning.
    #[test]
    fn normalization_is_forgiving() {
        let a = DomainPattern::parse("  +.Example.COM.  ").unwrap();
        let b = DomainPattern::parse("example.com").unwrap();
        assert_eq!(a.suffix(), b.suffix());
        assert!(a.matches(&n("WWW.EXAMPLE.COM")));
    }

    /// Anything that would match nothing is rejected loudly, never accepted
    /// as a silent no-op.
    #[test]
    fn empty_patterns_are_rejected() {
        for bad in ["", "   ", "*.", "+.", ".", "*..", "  *."] {
            assert!(
                DomainPattern::parse(bad).is_err(),
                "{bad:?} must be rejected, not silently ignored"
            );
        }
    }

    /// The root, however spelled, is a mistake worth reporting: it is either
    /// a typo or the user means `*`.
    #[test]
    fn root_is_rejected_with_a_hint() {
        let err = DomainPattern::parse(".").unwrap_err();
        assert!(err.msg.contains("root") || err.msg.contains("empty"));
    }

    #[test]
    fn bad_names_are_rejected() {
        assert!(DomainPattern::parse("*.exa mple.com").is_err());
        assert!(DomainPattern::parse("+.a..b").is_err());
    }

    #[test]
    fn parse_all_reports_the_offending_index() {
        let items = vec!["*.a.com".into(), "bad..name".into()];
        let err = parse_all(&items).unwrap_err();
        assert!(
            err.msg.contains("#1"),
            "should name the bad entry: {}",
            err.msg
        );
    }

    #[test]
    fn display_round_trips() {
        assert_eq!(DomainPattern::parse("*").unwrap().to_string(), "*");
        assert_eq!(
            DomainPattern::parse("+.example.com").unwrap().to_string(),
            "*.example.com"
        );
        assert_eq!(
            DomainPattern::parse("example.com").unwrap().to_string(),
            "example.com"
        );
        // The embedded forms print back in the spelling that produced them.
        for s in ["time.*.com", "stun.*.*", "*.stun.*.*", "a.*.b.*.c"] {
            assert_eq!(DomainPattern::parse(s).unwrap().to_string(), s);
        }
    }

    // ---- embedded wildcards -------------------------------------------

    /// A `*` in a non-leading position matches exactly one label, and the
    /// pattern must account for the whole name. This is the form mihomo's
    /// default `fake-ip-filter` uses.
    #[test]
    fn embedded_wildcard_matches_one_label() {
        let p = DomainPattern::parse("time.*.com").unwrap();
        assert!(p.is_wildcard());
        assert!(p.matches(&n("time.apple.com")));
        assert!(p.matches(&n("time.windows.com")));
        // Exactly one label, and the whole name.
        assert!(!p.matches(&n("time.a.b.com")), "one label, not several");
        assert!(
            !p.matches(&n("x.time.apple.com")),
            "no implicit suffix match"
        );
        assert!(!p.matches(&n("time.com")), "the label is required");
        assert!(!p.matches(&n("ntp.apple.com")), "the literal label matters");
        assert!(!p.matches(&n("time.apple.org")), "the tail matters");
        // No single suffix to report, so callers cannot treat it as anchored.
        assert_eq!(p.suffix(), None);
        assert_eq!(p.label_count(), 3);
    }

    /// A pattern of label wildcards with no literals still needs the right
    /// label count.
    #[test]
    fn all_wildcard_labels_still_count_labels() {
        let p = DomainPattern::parse("stun.*.*").unwrap();
        assert!(p.matches(&n("stun.example.com")));
        assert!(p.matches(&n("stun.a.b")));
        assert!(!p.matches(&n("stun.a")), "too few labels");
        assert!(!p.matches(&n("a.stun.b.c")), "too many, and no leading `*`");
    }

    /// A leading `*` means zero or more labels, so the pattern matches a
    /// suffix — the same reading `*.example.com` gives `example.com`.
    #[test]
    fn leading_wildcard_makes_embedded_patterns_suffix_matches() {
        let p = DomainPattern::parse("*.stun.*.*").unwrap();
        assert!(p.matches(&n("stun.b.c")), "the leading `*` may cover zero");
        assert!(p.matches(&n("a.stun.b.c")));
        assert!(p.matches(&n("a.b.stun.c.d")));
        assert!(!p.matches(&n("stun.b")), "the tail needs its labels");
        assert!(!p.matches(&n("a.stun.b.c.d")), "the tail is fixed length");
        assert_eq!(p.label_count(), 4);
    }

    /// An embedded pattern is not more specific than a literal name of the
    /// same length, and both are compared on label count.
    #[test]
    fn embedded_wildcard_specificity_is_its_label_count() {
        assert!(!DomainPattern::parse("time.*.com").unwrap().is_exact());
        assert_eq!(DomainPattern::parse("time.*.com").unwrap().label_count(), 3);
        assert_eq!(DomainPattern::parse("a.b.c").unwrap().label_count(), 3);
        assert_eq!(DomainPattern::parse("a.b.c").unwrap().label_count(), 3);
        assert!(DomainPattern::parse("a.b.c").unwrap().is_exact());
    }

    /// Patterns that would silently mean nothing are still refused, and the
    /// message says why.
    #[test]
    fn malformed_embedded_patterns_are_refused() {
        assert!(DomainPattern::parse("time..com").is_err(), "empty label");
        assert!(
            DomainPattern::parse("*.time.*..com").is_err(),
            "empty label"
        );
        let e = DomainPattern::parse("a\\.b.com").unwrap_err();
        assert!(e.msg.contains("escapes"), "{}", e.msg);
    }
}
