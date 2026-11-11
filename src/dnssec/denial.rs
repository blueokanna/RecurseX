//! Authenticated denial predicates. Callers must authenticate every supplied
//! RRset with the zone's authenticated keys before using these predicates.

use super::Verdict;
use crate::qtype::Rcode;
use crate::{Name, RData, Record, RrType};
use core::cmp::Ordering;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Denial {
    pub delegation: bool,
    pub opt_out: bool,
}

fn order(a: &Name, b: &Name) -> Ordering {
    a.labels().iter().rev().cmp(b.labels().iter().rev())
}

fn wildcard(name: &Name) -> Name {
    let mut bytes = vec![1, b'*'];
    name.write_wire(&mut bytes);
    Name::from_wire(&bytes, 0).expect("valid wildcard name").0
}

fn next_closer(name: &Name, encloser: &Name) -> Option<Name> {
    if !name.is_strict_subdomain_of(encloser) {
        return None;
    }
    let mut next = name.clone();
    while next.label_count() > encloser.label_count() + 1 {
        next = next.parent()?;
    }
    Some(next)
}

fn no_type(types: &[RrType], qtype: RrType) -> bool {
    if qtype == RrType::ANY {
        return types.is_empty();
    }
    !types.contains(&qtype) && !types.contains(&RrType::CNAME)
}

fn delegation(types: &[RrType]) -> bool {
    types.contains(&RrType::NS) && !types.contains(&RrType::SOA)
}

fn nsec_covers(record: &Record, name: &Name, zone: &Name) -> bool {
    let RData::Nsec { next, types } = &record.rdata else {
        return false;
    };
    if !record.name.is_subdomain_of(zone)
        || !next.is_subdomain_of(zone)
        || (name.is_strict_subdomain_of(&record.name)
            && (delegation(types) || types.contains(&RrType::DNAME)))
    {
        return false;
    }
    match order(&record.name, next) {
        Ordering::Less => order(&record.name, name).is_lt() && order(name, next).is_lt(),
        // Only the final NSEC may wrap, and it must end at the zone apex.
        Ordering::Greater => next == zone && order(&record.name, name).is_lt(),
        Ordering::Equal => &record.name == zone && name != zone,
    }
}

fn nsec_exists(name: &Name, records: &[Record], zone: &Name) -> bool {
    name == zone
        || records.iter().any(|r| match &r.rdata {
            RData::Nsec { next, .. } => r.name.is_subdomain_of(name) || next.is_subdomain_of(name),
            _ => false,
        })
}

fn check_nsec(records: &[Record], zone: &Name) -> Result<(), Verdict> {
    for record in records {
        if let RData::Nsec { next, .. } = &record.rdata {
            if !record.name.is_subdomain_of(zone)
                || !next.is_subdomain_of(zone)
                || (order(&record.name, next).is_ge() && next != zone)
            {
                return Err(Verdict::Bogus);
            }
        }
    }
    Ok(())
}

fn nsec_denial(
    name: &Name,
    qtype: RrType,
    code: Rcode,
    zone: &Name,
    records: &[Record],
) -> Result<Denial, Verdict> {
    if let Some(types) = records.iter().find_map(|r| match &r.rdata {
        RData::Nsec { types, .. } if r.name == *name => Some(types),
        _ => None,
    }) {
        if code != Rcode::NOERROR
            || !no_type(types, qtype)
            || (delegation(types) && qtype != RrType::DS)
        {
            return Err(Verdict::Bogus);
        }
        return Ok(Denial {
            delegation: qtype == RrType::DS && delegation(types),
            opt_out: false,
        });
    }
    if !records.iter().any(|r| nsec_covers(r, name, zone)) {
        return Err(Verdict::Bogus);
    }
    // An empty nonterminal exists even though it owns no NSEC itself.
    if nsec_exists(name, records, zone) {
        return if code == Rcode::NOERROR {
            Ok(Denial::default())
        } else {
            Err(Verdict::Bogus)
        };
    }
    let mut ce = name.parent().ok_or(Verdict::Bogus)?;
    while !nsec_exists(&ce, records, zone) {
        ce = ce.parent().ok_or(Verdict::Bogus)?;
    }
    if !ce.is_subdomain_of(zone) {
        return Err(Verdict::Bogus);
    }
    let wc = wildcard(&ce);
    if code == Rcode::NXDOMAIN && records.iter().any(|r| nsec_covers(r, &wc, zone)) {
        return Ok(Denial::default());
    }
    if code == Rcode::NOERROR
        && records.iter().any(|r| match &r.rdata {
            RData::Nsec { types, .. } => {
                r.name == wc && no_type(types, qtype) && !delegation(types)
            }
            _ => false,
        })
    {
        return Ok(Denial::default());
    }
    Err(Verdict::Bogus)
}

struct Nsec3<'a> {
    owner: Vec<u8>,
    next: &'a [u8],
    types: &'a [RrType],
    opt_out: bool,
}

fn unbase32(label: &[u8]) -> Option<Vec<u8>> {
    if label.len() != 32 {
        return None;
    }
    let mut out = Vec::with_capacity(20);
    let mut bits = 0u32;
    let mut count = 0;
    for b in label {
        let value = match b.to_ascii_lowercase() {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'v' => b.to_ascii_lowercase() - b'a' + 10,
            _ => return None,
        };
        bits = (bits << 5) | u32::from(value);
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    Some(out)
}

struct Hashed<'a> {
    records: Vec<Nsec3<'a>>,
    salt: &'a [u8],
    iterations: u16,
    work: usize,
}

impl<'a> Hashed<'a> {
    fn new(records: &'a [Record], zone: &Name) -> Result<Self, Verdict> {
        let mut out = Self {
            records: Vec::new(),
            salt: &[],
            iterations: 0,
            work: 0,
        };
        for r in records {
            let RData::Nsec3 {
                hash_alg,
                flags,
                iterations,
                salt,
                next_hashed,
                types,
            } = &r.rdata
            else {
                continue;
            };
            if *hash_alg != 1
                || flags & !1 != 0
                || *iterations > 150
                || next_hashed.len() != 20
                || r.name.parent().as_ref() != Some(zone)
            {
                return Err(Verdict::Bogus);
            }
            if !out.records.is_empty() && (*iterations != out.iterations || salt != out.salt) {
                return Err(Verdict::Bogus);
            }
            out.salt = salt;
            out.iterations = *iterations;
            out.records.push(Nsec3 {
                owner: unbase32(r.name.first_label().ok_or(Verdict::Bogus)?)
                    .ok_or(Verdict::Bogus)?,
                next: next_hashed,
                types,
                opt_out: flags & 1 != 0,
            });
        }
        if out.records.is_empty() {
            return Err(Verdict::Bogus);
        }
        Ok(out)
    }

    fn hash(&mut self, name: &Name) -> Result<Vec<u8>, Verdict> {
        self.work += usize::from(self.iterations) + 1;
        if self.work > 10_000 {
            return Err(Verdict::Bogus);
        }
        let mut input = name.as_bytes().to_vec();
        for _ in 0..=self.iterations {
            input.extend_from_slice(self.salt);
            input = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input)
                .as_ref()
                .to_vec();
        }
        Ok(input)
    }

    fn exact(&self, hash: &[u8]) -> Option<&Nsec3<'a>> {
        self.records.iter().find(|r| r.owner == hash)
    }

    fn cover(&self, hash: &[u8]) -> Option<&Nsec3<'a>> {
        self.records.iter().find(|r| {
            let owner = r.owner.as_slice();
            match owner.cmp(r.next) {
                Ordering::Less => owner < hash && hash < r.next,
                Ordering::Greater => owner < hash || hash < r.next,
                Ordering::Equal => owner != hash,
            }
        })
    }

    fn closest(&mut self, name: &Name, zone: &Name) -> Result<(Name, bool), Verdict> {
        if !name.is_strict_subdomain_of(zone) {
            return Err(Verdict::Bogus);
        }
        let mut ce = name.parent().ok_or(Verdict::Bogus)?;
        loop {
            let hash = self.hash(&ce)?;
            if let Some(record) = self.exact(&hash) {
                if delegation(record.types) || record.types.contains(&RrType::DNAME) {
                    return Err(Verdict::Bogus);
                }
                let next = next_closer(name, &ce).ok_or(Verdict::Bogus)?;
                let next_hash = self.hash(&next)?;
                return Ok((ce, self.cover(&next_hash).ok_or(Verdict::Bogus)?.opt_out));
            }
            if ce == *zone {
                return Err(Verdict::Bogus);
            }
            ce = ce
                .parent()
                .filter(|p| p.is_subdomain_of(zone))
                .ok_or(Verdict::Bogus)?;
        }
    }
}

pub(super) fn negative(
    name: &Name,
    qtype: RrType,
    code: Rcode,
    zone: &Name,
    records: &[Record],
) -> Result<Denial, Verdict> {
    if !name.is_subdomain_of(zone) || !matches!(code, Rcode::NOERROR | Rcode::NXDOMAIN) {
        return Err(Verdict::Bogus);
    }
    let nsec = records.iter().any(|r| r.rr_type == RrType::NSEC);
    let nsec3 = records.iter().any(|r| r.rr_type == RrType::NSEC3);
    if nsec == nsec3 {
        return Err(Verdict::Bogus);
    }
    if nsec {
        check_nsec(records, zone)?;
        return nsec_denial(name, qtype, code, zone, records);
    }
    let mut hashed = Hashed::new(records, zone)?;
    let hash = hashed.hash(name)?;
    if let Some(record) = hashed.exact(&hash) {
        if code != Rcode::NOERROR
            || !no_type(record.types, qtype)
            || (delegation(record.types) && qtype != RrType::DS)
        {
            return Err(Verdict::Bogus);
        }
        return Ok(Denial {
            delegation: qtype == RrType::DS && delegation(record.types),
            opt_out: false,
        });
    }
    let (ce, opt_out) = hashed.closest(name, zone)?;
    if qtype == RrType::DS && code == Rcode::NOERROR && opt_out {
        return Ok(Denial {
            delegation: true,
            opt_out: true,
        });
    }
    let wc_hash = hashed.hash(&wildcard(&ce))?;
    if code == Rcode::NXDOMAIN {
        let cover = hashed.cover(&wc_hash).ok_or(Verdict::Bogus)?;
        return Ok(Denial {
            delegation: false,
            opt_out: opt_out || cover.opt_out,
        });
    }
    let record = hashed.exact(&wc_hash).ok_or(Verdict::Bogus)?;
    if !no_type(record.types, qtype) || delegation(record.types) {
        return Err(Verdict::Bogus);
    }
    Ok(Denial {
        delegation: false,
        opt_out,
    })
}

pub(super) fn expanded(
    name: &Name,
    labels: u8,
    zone: &Name,
    records: &[Record],
) -> Result<bool, Verdict> {
    let mut ce = name.clone();
    while ce.label_count() > usize::from(labels) {
        ce = ce.parent().ok_or(Verdict::Bogus)?;
    }
    if !ce.is_subdomain_of(zone) {
        return Err(Verdict::Bogus);
    }
    let next = next_closer(name, &ce).ok_or(Verdict::Bogus)?;
    let nsec = records.iter().any(|r| r.rr_type == RrType::NSEC);
    let nsec3 = records.iter().any(|r| r.rr_type == RrType::NSEC3);
    if nsec == nsec3 {
        return Err(Verdict::Bogus);
    }
    if nsec {
        check_nsec(records, zone)?;
        return if records.iter().any(|r| nsec_covers(r, &next, zone)) {
            Ok(false)
        } else {
            Err(Verdict::Bogus)
        };
    }
    let mut hashed = Hashed::new(records, zone)?;
    let hash = hashed.hash(&next)?;
    Ok(hashed.cover(&hash).ok_or(Verdict::Bogus)?.opt_out)
}
