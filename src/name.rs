//! DNS domain names.
//!
//! A [`Name`] is stored in its canonical wire form (lower-cased label
//! sequence, never compressed), which makes it directly usable as a cache
//! key and comparable with ordinary byte ordering. Parsing handles RFC 1035
//! compression pointers; serialization is uncompressed (compression is the
//! message writer's job).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::error::{Error, Result};
use crate::prng::SplitMix64;

/// Maximum wire size of a domain name (RFC 1035 §2.3.4).
pub const MAX_NAME_LEN: usize = 255;
/// Maximum number of labels in a name (implicit in the 255-byte limit).
pub const MAX_LABELS: usize = 127;

/// A DNS domain name in canonical wire form.
///
/// The internal representation is `[len][label]... [len][label] 0x00`,
/// with every ASCII letter lower-cased. Compression pointers are never
/// stored. This layout is `Ord`-comparable and directly usable as a map
/// key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(Box<[u8]>);

impl Name {
    /// The root name `.`.
    #[inline]
    pub fn root() -> Self {
        Name(Box::new([0]))
    }

    /// Whether this is the root name.
    #[inline]
    pub fn is_root(&self) -> bool {
        self.0.len() == 1 && self.0[0] == 0
    }

    /// The canonical wire bytes (uncompressed).
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The length of the uncompressed wire form.
    #[inline]
    pub fn wire_len(&self) -> usize {
        self.0.len()
    }

    /// The number of labels (the root counts as zero labels).
    pub fn label_count(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < self.0.len() {
            let l = self.0[i] as usize;
            if l == 0 {
                break;
            }
            n += 1;
            i += 1 + l;
        }
        n
    }

    /// The left-most label of this name, as an ASCII string slice without
    /// the trailing dot (e.g. `www` for `www.example.com.`). Returns
    /// `None` for the root.
    pub fn first_label(&self) -> Option<&[u8]> {
        if self.is_root() {
            return None;
        }
        let l = self.0[0] as usize;
        Some(&self.0[1..1 + l])
    }

    /// The right-most label (the TLD, e.g. `com`).
    pub fn last_label(&self) -> Option<&[u8]> {
        if self.is_root() {
            return None;
        }
        // Walk to the last non-root label.
        let mut i = 0;
        let mut last_start = 0;
        while i < self.0.len() {
            let l = self.0[i] as usize;
            if l == 0 {
                break;
            }
            last_start = i;
            i += 1 + l;
        }
        let l = self.0[last_start] as usize;
        Some(&self.0[last_start + 1..last_start + 1 + l])
    }

    /// The parent name: drop the left-most label. `com.`'s parent is the
    /// root; the root has no parent.
    pub fn parent(&self) -> Option<Name> {
        let bytes = &self.0;
        if bytes.len() == 1 {
            return None;
        }
        let first = bytes[0] as usize;
        Some(Name(bytes[1 + first..].to_vec().into_boxed_slice()))
    }

    /// The apex of this name: the right-most two labels (`example.com`) or
    /// the whole name when it has two or fewer labels. This is the natural
    /// aggregation key for the query estimator.
    pub fn apex(&self) -> Name {
        let total = self.label_count();
        if total <= 2 {
            return self.clone();
        }
        // Skip all but the last two labels.
        let skip = total - 2;
        let mut i = 0;
        for _ in 0..skip {
            let l = self.0[i] as usize;
            i += 1 + l;
        }
        Name(self.0[i..].to_vec().into_boxed_slice())
    }

    /// Whether `self` is a subdomain of (or equal to) `other`.
    pub fn is_subdomain_of(&self, other: &Name) -> bool {
        let a: &[u8] = &self.0;
        let b: &[u8] = &other.0;
        if a.len() < b.len() {
            return false;
        }
        a[a.len() - b.len()..] == *b
    }

    /// Whether `self` is a strict subdomain of `other`.
    pub fn is_strict_subdomain_of(&self, other: &Name) -> bool {
        self != other && self.is_subdomain_of(other)
    }

    /// The longest name that is both a subdomain of `self` and of `other`
    /// (i.e. the common suffix, label-aligned). Returns the root when there
    /// is no common non-root suffix.
    pub fn common_suffix(&self, other: &Name) -> Name {
        // Compare label by label from the right.
        let a_labels = self.labels();
        let b_labels = other.labels();
        let mut suffix: Vec<u8> = Vec::new();
        let mut i = a_labels.len();
        let mut j = b_labels.len();
        while i > 0 && j > 0 {
            if a_labels[i - 1] != b_labels[j - 1] {
                break;
            }
            let label = &a_labels[i - 1];
            let mut prefix = Vec::with_capacity(1 + label.len());
            prefix.push(label.len() as u8);
            prefix.extend_from_slice(label);
            prefix.extend_from_slice(&suffix);
            suffix = prefix;
            i -= 1;
            j -= 1;
        }
        suffix.push(0);
        Name(suffix.into_boxed_slice())
    }

    /// The individual labels (without length prefixes), left to right.
    pub fn labels(&self) -> Vec<&[u8]> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.0.len() {
            let l = self.0[i] as usize;
            if l == 0 {
                break;
            }
            out.push(&self.0[i + 1..i + 1 + l]);
            i += 1 + l;
        }
        out
    }

    /// Parse a (possibly compressed) name from `buf` starting at `pos`.
    ///
    /// Returns the canonical name and the position just past the encoded
    /// name (past the pointer if the name was compressed at the top level).
    /// Bounds all jumps to defeat pointer loops.
    pub fn from_wire(buf: &[u8], pos: usize) -> Result<(Name, usize)> {
        if pos >= buf.len() {
            return Err(Error::wire("truncated name (position out of bounds)"));
        }
        let mut label_bytes: Vec<u8> = Vec::with_capacity(32);
        let mut lens: Vec<u8> = Vec::with_capacity(8);
        let mut p = pos;
        let mut end = pos;
        let mut jumped = false;
        let mut hops = 0usize;
        let mut total = 1usize; // the terminal root octet
        loop {
            if p >= buf.len() {
                return Err(Error::wire("truncated name"));
            }
            let len = buf[p] as usize;
            match len & 0xc0 {
                0x00 => {
                    if len == 0 {
                        p += 1;
                        if !jumped {
                            end = p;
                        }
                        break;
                    }
                    if len > 63 {
                        return Err(Error::wire("label longer than 63 octets"));
                    }
                    if p + 1 + len > buf.len() {
                        return Err(Error::wire("truncated label"));
                    }
                    total += 1 + len;
                    if total > MAX_NAME_LEN {
                        return Err(Error::wire("name exceeds 255 octets"));
                    }
                    if lens.len() >= MAX_LABELS {
                        return Err(Error::wire("too many labels"));
                    }
                    lens.push(len as u8);
                    let start = label_bytes.len();
                    label_bytes.extend_from_slice(&buf[p + 1..p + 1 + len]);
                    for b in &mut label_bytes[start..] {
                        b.make_ascii_lowercase();
                    }
                    p += 1 + len;
                }
                0xc0 => {
                    if p + 1 >= buf.len() {
                        return Err(Error::wire("truncated compression pointer"));
                    }
                    let off = ((len & 0x3f) << 8) | buf[p + 1] as usize;
                    if off >= buf.len() {
                        return Err(Error::wire("compression pointer out of range"));
                    }
                    if !jumped {
                        end = p + 2;
                        jumped = true;
                    }
                    p = off;
                    hops += 1;
                    if hops > 40 {
                        return Err(Error::wire("compression pointer loop"));
                    }
                }
                _ => {
                    return Err(Error::wire(
                        "unsupported label type (EDNS label types are not accepted)",
                    ))
                }
            }
        }
        if lens.len() >= MAX_LABELS {
            return Err(Error::wire("too many labels"));
        }
        let mut out = Vec::with_capacity(total);
        let mut off = 0;
        for &l in &lens {
            out.push(l);
            out.extend_from_slice(&label_bytes[off..off + l as usize]);
            off += l as usize;
        }
        out.push(0);
        Ok((Name(out.into_boxed_slice()), end))
    }

    /// Write the uncompressed canonical wire form to `out`.
    pub fn write_wire(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    /// The uncompressed canonical wire form as a fresh buffer.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Parse from presentation format, e.g. `www.example.com` or
    /// `www\.example.com` or `com.` (trailing dot accepted). Escapes
    /// follow RFC 4343 (`\.`, `\\`, `\DDD`).
    pub fn from_ascii(s: &str) -> Result<Name> {
        let bytes = s.as_bytes();
        let mut labels: Vec<u8> = Vec::with_capacity(s.len() + 1);
        let mut current: Vec<u8> = Vec::with_capacity(16);
        let mut label_count = 0usize;
        let mut i = 0;
        let mut total = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' => {
                    i += 1;
                    if i >= bytes.len() {
                        return Err(Error::wire("trailing backslash in name"));
                    }
                    if bytes[i].is_ascii_digit() {
                        if i + 2 >= bytes.len()
                            || !bytes[i + 1].is_ascii_digit()
                            || !bytes[i + 2].is_ascii_digit()
                        {
                            return Err(Error::wire("bad \\DDD escape in name"));
                        }
                        let v = (bytes[i] - b'0') as usize * 100
                            + (bytes[i + 1] - b'0') as usize * 10
                            + (bytes[i + 2] - b'0') as usize;
                        if v > 255 {
                            return Err(Error::wire("bad \\DDD escape in name"));
                        }
                        current.push(v as u8);
                        i += 3;
                    } else {
                        current.push(bytes[i]);
                        i += 1;
                    }
                }
                b'.' => {
                    if current.is_empty() {
                        // A leading dot or an empty label (e.g. "a..b") is
                        // rejected; a trailing dot is fine (it terminates
                        // the last label, root follows).
                        if i == bytes.len() - 1 {
                            break;
                        }
                        return Err(Error::wire("empty label in name"));
                    }
                    if current.len() > 63 {
                        return Err(Error::wire("label longer than 63 octets"));
                    }
                    total += 1 + current.len();
                    if total > MAX_NAME_LEN {
                        return Err(Error::wire("name exceeds 255 octets"));
                    }
                    if label_count >= MAX_LABELS {
                        return Err(Error::wire("too many labels"));
                    }
                    label_count += 1;
                    labels.push(current.len() as u8);
                    labels.extend_from_slice(&current);
                    current.clear();
                    i += 1;
                }
                b => {
                    current.push(b);
                    i += 1;
                }
            }
        }
        if !current.is_empty() {
            if current.len() > 63 {
                return Err(Error::wire("label longer than 63 octets"));
            }
            total += 1 + current.len();
            if total > MAX_NAME_LEN {
                return Err(Error::wire("name exceeds 255 octets"));
            }
            if label_count >= MAX_LABELS {
                return Err(Error::wire("too many labels"));
            }
            labels.push(current.len() as u8);
            labels.extend_from_slice(&current);
        }
        for b in &mut labels {
            b.make_ascii_lowercase();
        }
        labels.push(0);
        Ok(Name(labels.into_boxed_slice()))
    }

    /// Presentation format (RFC 4343 escaping). The root renders as `.`.
    pub fn to_ascii(&self) -> String {
        let bytes = &self.0;
        let mut s = String::with_capacity(bytes.len() + 4);
        let mut i = 0;
        while i < bytes.len() {
            let l = bytes[i] as usize;
            if l == 0 {
                break;
            }
            if !s.is_empty() {
                s.push('.');
            }
            for &b in &bytes[i + 1..i + 1 + l] {
                match b {
                    b'.' => s.push_str("\\."),
                    b'\\' => s.push_str("\\\\"),
                    b' ' => s.push_str("\\032"),
                    b'"' => s.push_str("\\042"),
                    b'@' => s.push_str("\\064"),
                    b'(' => s.push_str("\\040"),
                    b')' => s.push_str("\\041"),
                    b';' => s.push_str("\\059"),
                    _ if !(0x21..=0x7e).contains(&b) => {
                        s.push('\\');
                        s.push_str(&format!("{:03}", b));
                    }
                    _ => s.push(b as char),
                }
            }
            i += 1 + l;
        }
        if s.is_empty() {
            s.push('.');
        }
        s
    }

    /// A 0x20 randomized variant: the same labels with randomly chosen
    /// letter case (RFC 6840 §5.6 anti-spoofing). Only applied to names
    /// where at least one letter exists.
    pub fn randomized_case(&self, rng: &mut SplitMix64) -> Name {
        let bytes = &self.0;
        let mut out = Vec::with_capacity(bytes.len());
        for &b in bytes {
            if b.is_ascii_alphabetic() {
                let upper = (rng.next_u64() & 1) == 0;
                out.push(if upper { b.to_ascii_uppercase() } else { b });
            } else {
                out.push(b);
            }
        }
        Name(out.into_boxed_slice())
    }

    /// The canonical (all lower-case) form of this name.
    pub fn canonical(&self) -> Name {
        let mut out = self.0.to_vec();
        for b in &mut out {
            b.make_ascii_lowercase();
        }
        Name(out.into_boxed_slice())
    }

    /// Whether the name is eligible for 0x20 case randomization (it has at
    /// least one ASCII letter and is not the root).
    pub fn is_0x20_eligible(&self) -> bool {
        self.0.iter().any(|b| b.is_ascii_alphabetic())
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_ascii())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({})", self.to_ascii())
    }
}

impl Default for Name {
    fn default() -> Self {
        Name::root()
    }
}

/// RFC 1035 name compression table for one message.
///
/// Tracks the message offset at which each (non-root) name suffix has been
/// written, and emits compression pointers when a suffix is already
/// present. Pointers always reference earlier bytes, so this is safe to
/// feed a streaming writer.
#[derive(Debug, Default)]
pub struct NameCompressor {
    offsets: BTreeMap<Name, usize>,
}

impl NameCompressor {
    /// An empty compressor.
    pub fn new() -> Self {
        Self {
            offsets: BTreeMap::new(),
        }
    }

    /// Write `name` to `out`, compressing any suffix already emitted.
    pub fn write(&mut self, name: &Name, out: &mut Vec<u8>) {
        // Enumerate suffixes (full name → single label), each with its
        // relative offset inside the name. The bare root is excluded from
        // compression targets.
        let mut suffixes: Vec<(Name, usize)> = Vec::with_capacity(8);
        let mut cur = name.clone();
        let total = name.wire_len();
        loop {
            if cur.is_root() {
                break;
            }
            suffixes.push((cur.clone(), total - cur.wire_len()));
            match cur.parent() {
                Some(p) => cur = p,
                None => break,
            }
        }
        // Find the longest suffix already in the table.
        let mut hit: Option<usize> = None;
        for (i, (s, _)) in suffixes.iter().enumerate() {
            if self.offsets.contains_key(s) {
                hit = Some(i);
                break;
            }
        }
        let base = out.len();
        match hit {
            None => {
                name.write_wire(out);
                for (s, rel) in &suffixes {
                    self.offsets.entry(s.clone()).or_insert(base + rel);
                }
            }
            Some(i) => {
                // Write the prefix not covered by the found suffix, then a
                // pointer to it. The suffix start offset is exactly the
                // number of prefix bytes to emit.
                let prefix_len = suffixes[i].1;
                out.extend_from_slice(&name.as_bytes()[..prefix_len]);
                let off = self.offsets[&suffixes[i].0];
                out.push(0xc0 | ((off >> 8) as u8));
                out.push((off & 0xff) as u8);
                for (s, rel) in suffixes.iter().take(i) {
                    self.offsets.entry(s.clone()).or_insert(base + rel);
                }
            }
        }
    }
}

impl From<&str> for Name {
    /// Panic-free parse of a presentation-format name; use the `TryFrom`
    /// / `from_ascii` API for fallible parsing. This panics on malformed
    /// input and is provided for convenience in tests and configs.
    fn from(s: &str) -> Self {
        Name::from_ascii(s).expect("valid domain name")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ascii() {
        for n in [
            "",
            ".",
            "com",
            "example.com",
            "www.example.com",
            "a.b.c.d.e.f.g",
        ] {
            let name = Name::from_ascii(n).unwrap();
            let s = name.to_ascii();
            assert_eq!(Name::from_ascii(&s).unwrap(), name, "roundtrip {n:?}");
        }
    }

    #[test]
    fn case_insensitive() {
        let a = Name::from_ascii("WWW.Example.COM").unwrap();
        let b = Name::from_ascii("www.example.com").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn compression_parse() {
        // A message with a name, then a pointer to it.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ]);
        // pointer to offset 0
        buf.extend_from_slice(&[0xc0, 0x00]);
        let (name, next) = Name::from_wire(&buf, 0).unwrap();
        assert_eq!(name, Name::from_ascii("www.example.com").unwrap());
        assert_eq!(next, 17);
        let (name2, next2) = Name::from_wire(&buf, 17).unwrap();
        assert_eq!(name2, name);
        assert_eq!(next2, 19);
    }

    #[test]
    fn pointer_loop_detected() {
        // pointer to itself
        let buf = [0xc0, 0x00];
        assert!(Name::from_wire(&buf, 0).is_err());
    }

    #[test]
    fn parent_and_apex() {
        let n = Name::from_ascii("www.example.com").unwrap();
        assert_eq!(
            n.parent().unwrap(),
            Name::from_ascii("example.com").unwrap()
        );
        assert_eq!(n.apex(), Name::from_ascii("example.com").unwrap());
        assert_eq!(
            Name::from_ascii("com").unwrap().parent().unwrap(),
            Name::root()
        );
        assert_eq!(Name::root().parent(), None);
    }

    #[test]
    fn subdomain() {
        let www = Name::from_ascii("www.example.com").unwrap();
        let example = Name::from_ascii("example.com").unwrap();
        let com = Name::from_ascii("com").unwrap();
        assert!(www.is_subdomain_of(&example));
        assert!(www.is_subdomain_of(&com));
        assert!(www.is_subdomain_of(&www));
        assert!(!example.is_subdomain_of(&www));
        assert!(www.is_strict_subdomain_of(&example));
    }

    #[test]
    fn common_suffix_works() {
        let a = Name::from_ascii("a.example.com").unwrap();
        let b = Name::from_ascii("b.example.com").unwrap();
        assert_eq!(
            a.common_suffix(&b),
            Name::from_ascii("example.com").unwrap()
        );
        let c = Name::from_ascii("x.org").unwrap();
        assert_eq!(a.common_suffix(&c), Name::root());
    }

    #[test]
    fn escapes() {
        let n = Name::from_ascii(r"a\.b.example.com").unwrap();
        assert_eq!(n.label_count(), 3);
        assert_eq!(n.first_label().unwrap(), b"a.b");
        assert_eq!(n.to_ascii(), r"a\.b.example.com");
    }

    #[test]
    fn randomized_case_changes_case_only() {
        let n = Name::from_ascii("www.example.com").unwrap();
        let mut rng = SplitMix64::new(1);
        let r = n.randomized_case(&mut rng);
        assert_eq!(r.canonical(), n);
        // The two forms must differ in at least one case position (the
        // seed 1 produces a mix).
        let a = n.as_bytes();
        let b = r.as_bytes();
        assert_eq!(a.len(), b.len());
        let changed = a.iter().zip(b.iter()).any(|(x, y)| x != y);
        assert!(changed);
        // And the wire layout (labels/lengths) is identical.
        for (x, y) in a.iter().zip(b.iter()) {
            if !x.is_ascii_alphabetic() {
                assert_eq!(x, y);
            }
        }
    }

    #[test]
    fn rejects_oversized() {
        let long = "a".repeat(64);
        assert!(Name::from_ascii(&format!("{long}.com")).is_err());
        let mut name = String::new();
        for _ in 0..130 {
            name.push_str("ab.");
        }
        name.push_str("com");
        assert!(Name::from_ascii(&name).is_err());
    }

    #[test]
    fn label_order_is_correct() {
        let n = Name::from_ascii("www.example.com").unwrap();
        let labels = n.labels();
        assert_eq!(labels, vec![&b"www"[..], &b"example"[..], &b"com"[..]]);
        assert_eq!(n.first_label(), Some(&b"www"[..]));
        assert_eq!(n.last_label(), Some(&b"com"[..]));
    }

    #[test]
    fn wire_roundtrip() {
        let n = Name::from_ascii("a.b.example.com").unwrap();
        let mut out = Vec::new();
        n.write_wire(&mut out);
        let (m, next) = Name::from_wire(&out, 0).unwrap();
        assert_eq!(m, n);
        assert_eq!(next, out.len());
        // Uncompressed wire form is exactly [1,a,1,b,7,example,3,com,0].
        let mut expect = Vec::new();
        expect.extend_from_slice(&[1, b'a', 1, b'b', 7]);
        expect.extend_from_slice(b"example");
        expect.extend_from_slice(&[3]);
        expect.extend_from_slice(b"com");
        expect.push(0);
        assert_eq!(out, expect);
    }
}
