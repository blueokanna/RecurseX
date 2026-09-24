//! Resolution engine helpers (pure, no I/O).
//!
//! This module owns the parts of iterative resolution that are pure
//! functions of a response: outgoing query construction (with 0x20 and
//! EDNS), response classification (answer / CNAME / DNAME / negative /
//! referral), bailiwick checks, and DNAME synthesis. The I/O loop that
//! drives them lives in the resolver.

use alloc::vec::Vec;

use crate::edns::{Ecs, Edns};
use crate::message::{HeaderFlags, Message, Question};
use crate::name::Name;
use crate::prng::SplitMix64;
use crate::qtype::{Rcode, RrClass, RrType};
use crate::rdata::{RData, Record};

/// The 13 IANA root server addresses (IPv4), used as the initial
/// delegation set when no configured roots exist.
pub const ROOT_SERVER_V4: [&str; 13] = [
    "198.41.0.4",     // a.root-servers.net
    "170.247.170.2",  // b
    "192.33.4.12",    // c
    "199.7.91.13",    // d
    "192.203.230.10", // e
    "192.5.5.241",    // f
    "192.112.36.4",   // g
    "198.97.190.53",  // h
    "192.36.148.17",  // i
    "192.58.128.30",  // j
    "193.0.14.129",   // k
    "199.7.83.42",    // l
    "202.12.27.33",   // m
];

/// The 13 IANA root server addresses (IPv6).
pub const ROOT_SERVER_V6: [&str; 13] = [
    "2001:503:ba3e::2:30", // a
    "2801:1b8:10::b",      // b
    "2001:500:2::c",       // c
    "2001:500:2d::d",      // d
    "2001:500:a8::e",      // e
    "2001:500:2f::f",      // f
    "2001:500:12::d0d",    // g
    "2001:500:1::53",      // h
    "2001:7fe::53",        // i
    "2001:503:c27::2:30",  // j
    "2001:7fd::1",         // k
    "2001:500:9f::42",     // l
    "2001:dc3::35",        // m
];

/// Default root UDP endpoints.
pub fn root_endpoints() -> Vec<crate::upstream::Endpoint> {
    use crate::upstream::{Endpoint, Proto};
    let mut v = Vec::with_capacity(26);
    for s in ROOT_SERVER_V4 {
        if let Ok(ip) = s.parse() {
            v.push(Endpoint::new(ip, 53, Proto::Udp));
        }
    }
    for s in ROOT_SERVER_V6 {
        if let Ok(ip) = s.parse() {
            v.push(Endpoint::new(ip, 53, Proto::Udp));
        }
    }
    v
}

/// What to put in the outgoing query's EDNS record.
#[derive(Clone, Debug, Default)]
pub struct EdnsSpec {
    /// UDP payload size to advertise.
    pub udp_size: u16,
    /// Set the DNSSEC OK bit.
    pub dnssec_ok: bool,
    /// An ECS option to attach, if any.
    pub ecs: Option<Ecs>,
    /// A client cookie to attach, if any.
    pub client_cookie: Option<[u8; 8]>,
}

impl EdnsSpec {
    /// Build the EDNS record for an outgoing query.
    pub fn to_edns(&self) -> Edns {
        let mut e = Edns::new(self.udp_size.max(512));
        e.dnssec_ok = self.dnssec_ok;
        if let Some(ecs) = &self.ecs {
            e.options.push(crate::edns::EdnsOption::Ecs(ecs.clone()));
        }
        if let Some(c) = self.client_cookie {
            e.options.push(crate::edns::EdnsOption::Cookie {
                client: c,
                server: Vec::new(),
            });
        }
        e
    }
}

/// A fully-built outgoing query.
#[derive(Debug)]
pub struct OutQuery {
    /// The wire bytes to send.
    pub bytes: Vec<u8>,
    /// The exact QNAME case used on the wire (for 0x20 matching).
    pub qname: Name,
    /// The query ID.
    pub id: u16,
}

/// Build an outgoing query.
///
/// With `use_0x20`, the QNAME letters are randomly cased (RFC 6840 §5.6);
/// the exact case is returned so the response's question can be compared.
pub fn build_query(
    id: u16,
    qname: &Name,
    qtype: RrType,
    rd: bool,
    edns: Option<&EdnsSpec>,
    use_0x20: bool,
    rng: &mut SplitMix64,
) -> OutQuery {
    let wire_name = if use_0x20 && qname.is_0x20_eligible() {
        qname.randomized_case(rng)
    } else {
        qname.clone()
    };
    let mut m = Message::new(id);
    m.flags = HeaderFlags {
        rd,
        ..HeaderFlags::default()
    };
    m.questions.push(Question {
        qname: wire_name.clone(),
        qtype,
        qclass: RrClass::IN,
    });
    if let Some(spec) = edns {
        m.edns = Some(spec.to_edns());
    }
    let bytes = m.to_bytes().unwrap_or_default();
    OutQuery {
        bytes,
        qname: wire_name,
        id,
    }
}

/// How a response should drive the resolution loop.
#[derive(Clone, Debug)]
pub enum ResponseKind {
    /// The answer section contains the requested data.
    Answer {
        /// The data records (owner == qname, type == qtype).
        records: Vec<Record>,
        /// RRSIGs carried alongside.
        rrsigs: Vec<Record>,
    },
    /// A CNAME for the query name.
    Cname {
        /// The CNAME record.
        record: Record,
        /// RRSIGs carried alongside.
        rrsigs: Vec<Record>,
    },
    /// A DNAME that applies to the query name.
    Dname {
        /// The DNAME record.
        record: Record,
    },
    /// A negative answer (NXDOMAIN or NODATA) with an optional SOA.
    Negative {
        /// The negative response code.
        rcode: Rcode,
        /// The SOA from the authority section, if present.
        soa: Option<Record>,
    },
    /// A referral to a child zone.
    Referral {
        /// The zone being referred to.
        zone: Name,
        /// The NS records of the child zone.
        ns: Vec<Record>,
        /// Glue address records, if any.
        glue: Vec<Record>,
    },
    /// Nothing usable.
    Empty,
}

/// Classify a validated response. `qname` is the canonical (lowercase)
/// name currently being resolved; `zone` is the zone the current servers
/// are authoritative for.
pub fn classify_response(msg: &Message, qname: &Name, qtype: RrType, zone: &Name) -> ResponseKind {
    let rcode = msg.rcode();
    if rcode == 3 {
        return ResponseKind::Negative {
            rcode: Rcode::NXDOMAIN,
            soa: msg.authority_soa().cloned(),
        };
    }

    let mut rrsigs: Vec<Record> = Vec::new();
    let mut answer_data: Vec<Record> = Vec::new();
    let mut cname: Option<Record> = None;
    let mut dname: Option<Record> = None;

    for rec in &msg.answers {
        if rec.rr_type == RrType::RRSIG {
            rrsigs.push(rec.clone());
            continue;
        }
        if rec.name == *qname {
            if rec.rr_type == qtype {
                answer_data.push(rec.clone());
            } else if rec.rr_type == RrType::CNAME && cname.is_none() {
                cname = Some(rec.clone());
            }
        }
        if rec.rr_type == RrType::DNAME
            && qname.is_strict_subdomain_of(&rec.name)
            && dname.is_none()
        {
            dname = Some(rec.clone());
        }
    }

    if !answer_data.is_empty() {
        return ResponseKind::Answer {
            records: answer_data,
            rrsigs,
        };
    }
    if let Some(c) = cname {
        return ResponseKind::Cname { record: c, rrsigs };
    }
    if let Some(d) = dname {
        return ResponseKind::Dname { record: d };
    }

    // No direct answer: check the authority section.
    let soa = msg.authority_soa();
    if soa.is_some() {
        return ResponseKind::Negative {
            rcode: Rcode::NOERROR,
            soa: soa.cloned(),
        };
    }
    // A referral is an NS RRset for a zone strictly below the current one.
    // The NS owner may equal the query name when the query is for the zone
    // apex itself (the delegating server's referral for `example.com A`).
    let mut referral: Option<(Name, Vec<Record>, Vec<Record>)> = None;
    for rec in &msg.authorities {
        if rec.rr_type == RrType::NS && rec.name.is_strict_subdomain_of(zone) {
            let zone = rec.name.clone();
            let ns: Vec<Record> = msg
                .authorities
                .iter()
                .filter(|r| r.rr_type == RrType::NS && r.name == zone)
                .cloned()
                .collect();
            // Glue: A/AAAA in the additional section.
            let glue: Vec<Record> = msg
                .additionals
                .iter()
                .filter(|r| matches!(r.rr_type, RrType::A | RrType::AAAA))
                .cloned()
                .collect();
            referral = Some((zone, ns, glue));
            break;
        }
    }
    if let Some((zone, ns, glue)) = referral {
        return ResponseKind::Referral { zone, ns, glue };
    }

    ResponseKind::Empty
}

/// Whether a record owner is inside `zone` (bailiwick). Only in-bailiwick
/// data may be cached from a response.
pub fn in_bailiwick(owner: &Name, zone: &Name) -> bool {
    owner.is_subdomain_of(zone)
}

/// Synthesize the CNAME target implied by a DNAME (RFC 6672 §3): replace
/// the DNAME owner suffix of `qname` with the DNAME target.
pub fn synthesize_dname_cname(
    qname: &Name,
    dname_owner: &Name,
    dname_target: &Name,
) -> Option<Name> {
    if !qname.is_strict_subdomain_of(dname_owner) {
        return None;
    }
    let q_labels = qname.labels();
    let owner_labels = dname_owner.label_count();
    let keep = q_labels.len().saturating_sub(owner_labels);
    let mut out: Vec<u8> = Vec::with_capacity(64);
    for l in q_labels.iter().take(keep) {
        out.push(l.len() as u8);
        out.extend_from_slice(l);
    }
    for l in dname_target.labels() {
        out.push(l.len() as u8);
        out.extend_from_slice(l);
    }
    out.push(0);
    Name::from_wire(&out, 0).ok().map(|(n, _)| n)
}

/// A CNAME record for `name → target`.
pub fn make_cname_record(name: &Name, target: &Name, ttl: u32) -> Record {
    Record {
        name: name.clone(),
        rr_type: RrType::CNAME,
        class: RrClass::IN,
        ttl,
        rdata: RData::Cname(target.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_builds_with_edns() {
        let mut rng = SplitMix64::new(1);
        let name = Name::from_ascii("www.example.com").unwrap();
        let q = build_query(
            7,
            &name,
            RrType::A,
            true,
            Some(&EdnsSpec {
                udp_size: 1232,
                dnssec_ok: true,
                ..Default::default()
            }),
            true,
            &mut rng,
        );
        let m = Message::parse(&q.bytes).unwrap();
        assert_eq!(m.id, 7);
        assert_eq!(m.question().unwrap().qtype, RrType::A);
        assert!(m.edns.is_some());
        assert!(m.edns.as_ref().unwrap().dnssec_ok);
        // 0x20: the wire name may differ in case from the canonical form.
        assert_eq!(q.qname.canonical(), name);
    }

    #[test]
    fn classify_answer() {
        let mut m = Message::new(1);
        m.flags.qr = true;
        m.answers.push(Record {
            name: Name::from_ascii("example.com").unwrap(),
            rr_type: RrType::A,
            class: RrClass::IN,
            ttl: 300,
            rdata: RData::A("93.184.216.34".parse().unwrap()),
        });
        let qname = Name::from_ascii("example.com").unwrap();
        let kind = classify_response(&m, &qname, RrType::A, &Name::root());
        match kind {
            ResponseKind::Answer { records, .. } => assert_eq!(records.len(), 1),
            other => panic!("expected answer, got {other:?}"),
        }
    }

    #[test]
    fn classify_cname() {
        let mut m = Message::new(1);
        m.flags.qr = true;
        m.answers.push(Record {
            name: Name::from_ascii("www.example.com").unwrap(),
            rr_type: RrType::CNAME,
            class: RrClass::IN,
            ttl: 300,
            rdata: RData::Cname(Name::from_ascii("cdn.example.net").unwrap()),
        });
        let qname = Name::from_ascii("www.example.com").unwrap();
        match classify_response(&m, &qname, RrType::A, &Name::root()) {
            ResponseKind::Cname { record, .. } => {
                assert_eq!(record.name.to_ascii(), "www.example.com");
            }
            other => panic!("expected cname, got {other:?}"),
        }
    }

    #[test]
    fn classify_referral() {
        let mut m = Message::new(1);
        m.flags.qr = true;
        // Authority: NS for example.com (below root).
        m.authorities.push(Record {
            name: Name::from_ascii("example.com").unwrap(),
            rr_type: RrType::NS,
            class: RrClass::IN,
            ttl: 172800,
            rdata: RData::Ns(Name::from_ascii("ns1.example.com").unwrap()),
        });
        // Glue.
        m.additionals.push(Record {
            name: Name::from_ascii("ns1.example.com").unwrap(),
            rr_type: RrType::A,
            class: RrClass::IN,
            ttl: 172800,
            rdata: RData::A("192.0.2.53".parse().unwrap()),
        });
        let qname = Name::from_ascii("www.example.com").unwrap();
        match classify_response(&m, &qname, RrType::A, &Name::root()) {
            ResponseKind::Referral { zone, ns, glue } => {
                assert_eq!(zone.to_ascii(), "example.com");
                assert_eq!(ns.len(), 1);
                assert_eq!(glue.len(), 1);
            }
            other => panic!("expected referral, got {other:?}"),
        }
    }

    #[test]
    fn classify_negative() {
        let mut m = Message::new(1);
        m.flags.qr = true;
        m.authorities.push(Record {
            name: Name::from_ascii("example.com").unwrap(),
            rr_type: RrType::SOA,
            class: RrClass::IN,
            ttl: 60,
            rdata: RData::Soa {
                mname: Name::from_ascii("ns1.example.com").unwrap(),
                rname: Name::from_ascii("hostmaster.example.com").unwrap(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 86400,
                minimum: 300,
            },
        });
        let qname = Name::from_ascii("none.example.com").unwrap();
        match classify_response(
            &m,
            &qname,
            RrType::A,
            &Name::from_ascii("example.com").unwrap(),
        ) {
            ResponseKind::Negative { rcode, .. } => assert_eq!(rcode, Rcode::NOERROR),
            other => panic!("expected negative, got {other:?}"),
        }
    }

    #[test]
    fn dname_synthesis() {
        let qname = Name::from_ascii("www.example.com").unwrap();
        let owner = Name::from_ascii("example.com").unwrap();
        let target = Name::from_ascii("example.net").unwrap();
        let synthesized = synthesize_dname_cname(&qname, &owner, &target).unwrap();
        assert_eq!(synthesized.to_ascii(), "www.example.net");
    }

    #[test]
    fn bailiwick() {
        let zone = Name::from_ascii("example.com").unwrap();
        assert!(in_bailiwick(
            &Name::from_ascii("www.example.com").unwrap(),
            &zone
        ));
        assert!(!in_bailiwick(
            &Name::from_ascii("www.evil.net").unwrap(),
            &zone
        ));
    }
}
