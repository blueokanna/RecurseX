//! RRset model: the unit of caching.
//!
//! The cache is semantic, not message-shaped: it stores resource-record
//! sets keyed by `(owner, type, class, ECS)`. This is what lets one cached
//! CNAME RRset serve every query that aliases through it, and what lets
//! negative answers be shared across questions.

use alloc::format;
use alloc::vec::Vec;

use crate::error::Result;
use crate::name::Name;
use crate::prng::fnv1a_combine;
use crate::qtype::{RrClass, RrType};
use crate::rdata::{RData, Record};
use crate::time::Ts;

/// A resource-record set: all records of one type at one owner name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RrSet {
    /// The owner name.
    pub name: Name,
    /// The record type.
    pub rr_type: RrType,
    /// The record class.
    pub class: RrClass,
    /// The data records (excludes RRSIG).
    pub records: Vec<Record>,
    /// The RRSIG records covering this set (DNSSEC), if any.
    pub rrsigs: Vec<Record>,
    /// The effective TTL (minimum of the record TTLs, capped).
    pub ttl: u32,
    /// Whether this set was DNSSEC-validated.
    pub validated: bool,
}

impl RrSet {
    /// A new, empty set with the given TTL.
    pub fn new(name: Name, rr_type: RrType, class: RrClass, ttl: u32) -> Self {
        Self {
            name,
            rr_type,
            class,
            records: Vec::new(),
            rrsigs: Vec::new(),
            ttl,
            validated: false,
        }
    }

    /// Add a data record and refresh the effective TTL to the minimum.
    pub fn add_record(&mut self, rec: Record) {
        self.ttl = self.ttl.min(rec.ttl);
        self.records.push(rec);
    }

    /// Add an RRSIG record.
    pub fn add_rrsig(&mut self, rec: Record) {
        self.rrsigs.push(rec);
    }

    /// The number of data records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The canonical content fingerprint (order-independent-ish: FNV over
    /// the sorted wire form of each record, with the TTL field zeroed so a
    /// TTL-only change does not count as a content change). Used for
    /// change detection in the stability model. Not cryptographic.
    pub fn fingerprint(&self) -> u64 {
        let mut items: Vec<Vec<u8>> = Vec::with_capacity(self.records.len());
        for r in &self.records {
            items.push(record_wire_without_ttl(r));
        }
        items.sort();
        let mut acc: u64 = 0xcbf29ce484222325;
        for item in &items {
            acc = fnv1a_combine(acc, item);
        }
        acc
    }

    /// Whether two sets have identical data records (used by the stability
    /// model to detect authoritative changes). TTL differences are not
    /// content changes.
    ///
    /// RRSIGs are deliberately outside the comparison: a signature rotation is
    /// not a data change, and letting it count as one would reset the stability
    /// score of a zone that is behaving correctly. The consequence is that
    /// adding or removing a signature is not visible here — that is the DNSSEC
    /// layer's business, not the change detector's, and the comparison is not
    /// used to decide whether an answer is trustworthy.
    pub fn same_data(&self, other: &RrSet) -> bool {
        if self.records.len() != other.records.len() {
            return false;
        }
        self.fingerprint() == other.fingerprint()
    }

    /// The absolute expiry of the set given `now` (saturating).
    pub fn expires_at(&self, now: Ts) -> Ts {
        now.saturating_add(self.ttl as Ts * 1_000_000_000)
    }

    /// A clone of just the data records.
    pub fn records_cloned(&self) -> Vec<Record> {
        self.records.clone()
    }

    /// An iterator over the CNAME target, if this is a CNAME set.
    ///
    /// A set built through [`RrSet::from_records`] holds at most one CNAME
    /// (RFC 2181 §10.1), so "the" target is well defined. The unchecked
    /// builders ([`RrSet::new`] plus [`RrSet::add_record`]) do not enforce
    /// that, so this reports the first record rather than assuming there is
    /// exactly one.
    pub fn cname_target(&self) -> Option<&Name> {
        self.records.iter().find_map(|r| match &r.rdata {
            RData::Cname(n) => Some(n),
            _ => None,
        })
    }

    /// An iterator over the DNAME target, if this is a DNAME set.
    pub fn dname_target(&self) -> Option<&Name> {
        self.records.iter().find_map(|r| match &r.rdata {
            RData::Dname(n) => Some(n),
            _ => None,
        })
    }

    /// The NS names, if this is an NS set.
    pub fn ns_names(&self) -> Vec<&Name> {
        self.records
            .iter()
            .filter_map(|r| match &r.rdata {
                RData::Ns(n) => Some(n),
                _ => None,
            })
            .collect()
    }

    /// Parse a set from a list of records already filtered to a single
    /// (name, type, class). `max_ttl_cap` clamps absurd TTLs.
    ///
    /// Refuses a CNAME or DNAME set with more than one record. RFC 2181 §10.1
    /// gives those types a cardinality of exactly one, and the reason is not
    /// pedantry: with two targets the answer is genuinely ambiguous, and every
    /// consumer picks a different one — which resolver you ask changes the
    /// address you get. Refusing the set keeps that ambiguity out of the cache
    /// and out of the alias graph, where it would otherwise persist and be
    /// served long after the offending response is forgotten. Callers that
    /// cannot act on the refusal skip the set, which is the intended outcome:
    /// the wire answer still reaches the client unchanged, it just is not
    /// remembered.
    pub fn from_records(records: Vec<Record>, max_ttl_cap: u32) -> Result<RrSet> {
        let first = records
            .first()
            .ok_or_else(|| crate::error::Error::internal("empty RRset construction"))?;
        let name = first.name.clone();
        let rr_type = first.rr_type;
        let class = first.class;
        let mut ttl = u32::MAX;
        let mut data = Vec::with_capacity(records.len());
        let mut rrsigs = Vec::new();
        for rec in records {
            ttl = ttl.min(rec.ttl);
            if rec.rr_type == RrType::RRSIG {
                rrsigs.push(rec);
            } else {
                data.push(rec);
            }
        }
        if ttl == u32::MAX {
            ttl = 0;
        }
        // RFC 2181 §10.1: CNAME and DNAME have a cardinality of exactly one.
        if matches!(rr_type, RrType::CNAME | RrType::DNAME) && data.len() > 1 {
            return Err(crate::error::Error::wire(format!(
                "{rr_type} RRset has {} records; RFC 2181 §10.1 allows exactly one",
                data.len()
            )));
        }
        ttl = ttl.min(max_ttl_cap);
        Ok(Self {
            name,
            rr_type,
            class,
            records: data,
            rrsigs,
            ttl,
            validated: false,
        })
    }

    /// The estimated in-memory footprint in bytes (approximate, used by the
    /// admission policy's memory term).
    pub fn estimated_bytes(&self) -> usize {
        let mut n = self.name.wire_len() + 24;
        for r in &self.records {
            n += r.name.wire_len() + 40 + r.rdata.wire_len();
        }
        for r in &self.rrsigs {
            n += r.name.wire_len() + 40 + r.rdata.wire_len();
        }
        n
    }
}

/// Serialize a record with the TTL field zeroed (content fingerprints must
/// not treat TTL changes as data changes).
fn record_wire_without_ttl(r: &Record) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    r.name.write_wire(&mut v);
    v.extend_from_slice(&r.rr_type.to_u16().to_be_bytes());
    v.extend_from_slice(&r.class.to_u16().to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 0]); // TTL zeroed
    let mut rd = Vec::new();
    r.rdata.to_wire(&mut rd, None);
    v.extend_from_slice(&(rd.len() as u16).to_be_bytes());
    v.extend_from_slice(&rd);
    v
}

/// Convenience constructors for tests.
#[cfg(test)]
impl RrSet {
    /// One A record, for the tests that only care about the RRset shape.
    pub(crate) fn a(name: &str, ip: &str, ttl: u32) -> RrSet {
        let mut s = RrSet::new(Name::from_ascii(name).unwrap(), RrType::A, RrClass::IN, ttl);
        s.add_record(Record {
            name: s.name.clone(),
            rr_type: RrType::A,
            class: RrClass::IN,
            ttl,
            rdata: RData::A(ip.parse().unwrap()),
        });
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_changes_with_content() {
        let a = RrSet::a("example.com", "192.0.2.1", 300);
        let b = RrSet::a("example.com", "192.0.2.2", 300);
        assert_ne!(a.fingerprint(), b.fingerprint());
        let c = RrSet::a("example.com", "192.0.2.1", 300);
        assert_eq!(a.fingerprint(), c.fingerprint());
    }

    #[test]
    fn same_data_ignores_ttl() {
        let a = RrSet::a("example.com", "192.0.2.1", 300);
        let mut b = RrSet::a("example.com", "192.0.2.1", 600);
        b.ttl = 300;
        // A TTL-only change is not a content change: `fingerprint` hashes
        // `record_wire_without_ttl`, so the TTL bytes never reach the hash.
        assert_eq!(b.fingerprint(), a.fingerprint());
    }

    /// RFC 2181 §10.1 gives CNAME and DNAME a cardinality of exactly one, and
    /// the reason is not pedantry: with two targets every consumer picks a
    /// different one, so "which address does this name have" would depend on
    /// which resolver you asked. The set must be refused rather than truncated
    /// to its first record, or that ambiguity gets cached and served long after
    /// the offending response is forgotten.
    #[test]
    fn a_multi_record_cname_is_refused() {
        let owner = Name::from_ascii("www.example.com").unwrap();
        let cname = |target: &str| Record {
            name: owner.clone(),
            rr_type: RrType::CNAME,
            class: RrClass::IN,
            ttl: 300,
            rdata: RData::Cname(Name::from_ascii(target).unwrap()),
        };
        let one = RrSet::from_records(vec![cname("a.example.net")], 86_400).unwrap();
        assert_eq!(
            one.cname_target().map(Name::to_ascii).as_deref(),
            Some("a.example.net")
        );
        assert_eq!(one.records.len(), 1);

        let two = RrSet::from_records(
            vec![cname("a.example.net"), cname("b.example.net")],
            86_400,
        );
        assert!(two.is_err(), "a two-record CNAME set must be refused");

        let dname = |target: &str| Record {
            name: owner.clone(),
            rr_type: RrType::DNAME,
            class: RrClass::IN,
            ttl: 300,
            rdata: RData::Dname(Name::from_ascii(target).unwrap()),
        };
        assert!(RrSet::from_records(
            vec![dname("a.example.net"), dname("b.example.net")],
            86_400
        )
        .is_err());

        // The rule is specific to those two types: an NS set with two servers
        // is the normal case, not an error.
        let apex = Name::from_ascii("example.com").unwrap();
        let ns = |target: &str| Record {
            name: apex.clone(),
            rr_type: RrType::NS,
            class: RrClass::IN,
            ttl: 300,
            rdata: RData::Ns(Name::from_ascii(target).unwrap()),
        };
        let set = RrSet::from_records(
            vec![ns("ns1.example.net"), ns("ns2.example.net")],
            86_400,
        )
        .unwrap();
        assert_eq!(set.ns_names().len(), 2);
    }

    #[test]
    fn ttl_is_min() {
        let mut s = RrSet::new(
            Name::from_ascii("example.com").unwrap(),
            RrType::A,
            RrClass::IN,
            300,
        );
        s.add_record(Record {
            name: s.name.clone(),
            rr_type: RrType::A,
            class: RrClass::IN,
            ttl: 600,
            rdata: RData::A("192.0.2.1".parse().unwrap()),
        });
        assert_eq!(s.ttl, 300);
    }

    #[test]
    fn cname_target_detected() {
        let mut s = RrSet::new(
            Name::from_ascii("www.example.com").unwrap(),
            RrType::CNAME,
            RrClass::IN,
            300,
        );
        s.add_record(Record {
            name: s.name.clone(),
            rr_type: RrType::CNAME,
            class: RrClass::IN,
            ttl: 300,
            rdata: RData::Cname(Name::from_ascii("cdn.example.net").unwrap()),
        });
        assert_eq!(
            s.cname_target().map(|n| n.to_ascii()),
            Some("cdn.example.net".into())
        );
    }
}
