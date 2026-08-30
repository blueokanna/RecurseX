//! DNS message model: header, questions, records, and EDNS(0), with full
//! wire parsing and serialization (including RFC 1035 name compression).

use alloc::vec::Vec;

use crate::edns::Edns;
use crate::error::{Error, Result};
use crate::name::{Name, NameCompressor};
use crate::qtype::{Opcode, Rcode, RrClass, RrType};
use crate::rdata::Record;

/// Upper bound on any section count in a single message (anti-amplification
/// / parse-depth bound).
pub const MAX_SECTION_RECORDS: usize = 512;
/// Upper bound on the number of questions in a message.
pub const MAX_QUESTIONS: usize = 16;

/// The 16-bit flags word of a DNS header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderFlags {
    pub qr: bool,
    pub opcode: Opcode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
    pub rcode: Rcode,
}

impl Default for HeaderFlags {
    fn default() -> Self {
        Self {
            qr: false,
            opcode: Opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            ad: false,
            cd: false,
            rcode: Rcode::NOERROR,
        }
    }
}

impl HeaderFlags {
    pub fn to_u16(self) -> u16 {
        let mut v = 0u16;
        if self.qr {
            v |= 0x8000;
        }
        v |= ((self.opcode.to_u8() as u16) & 0x0f) << 11;
        if self.aa {
            v |= 0x0400;
        }
        if self.tc {
            v |= 0x0200;
        }
        if self.rd {
            v |= 0x0100;
        }
        if self.ra {
            v |= 0x0080;
        }
        if self.ad {
            v |= 0x0020;
        }
        if self.cd {
            v |= 0x0010;
        }
        v |= (self.rcode.to_u8() & 0x0f) as u16;
        v
    }

    pub fn from_u16(v: u16) -> Self {
        Self {
            qr: v & 0x8000 != 0,
            opcode: Opcode(((v >> 11) & 0x0f) as u8),
            aa: v & 0x0400 != 0,
            tc: v & 0x0200 != 0,
            rd: v & 0x0100 != 0,
            ra: v & 0x0080 != 0,
            ad: v & 0x0020 != 0,
            cd: v & 0x0010 != 0,
            rcode: Rcode((v & 0x0f) as u8),
        }
    }
}

/// A question section entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub qname: Name,
    pub qtype: RrType,
    pub qclass: RrClass,
}

/// A parsed or to-be-serialized DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    pub flags: HeaderFlags,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    /// Non-OPT additional records.
    pub additionals: Vec<Record>,
    /// The EDNS(0) OPT pseudo-record, if present.
    pub edns: Option<Edns>,
}

impl Default for Message {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Message {
    /// A new, empty message with the given ID.
    pub fn new(id: u16) -> Self {
        Self {
            id,
            flags: HeaderFlags::default(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        }
    }

    /// A query message for `(qname, qtype)` with RD set.
    pub fn query(id: u16, qname: Name, qtype: RrType, rd: bool) -> Self {
        let mut m = Self::new(id);
        m.flags.rd = rd;
        m.questions.push(Question {
            qname,
            qtype,
            qclass: RrClass::IN,
        });
        m
    }

    /// The first question, if any.
    pub fn question(&self) -> Option<&Question> {
        self.questions.first()
    }

    /// The effective response code, including the EDNS extended bits.
    pub fn rcode(&self) -> u16 {
        match &self.edns {
            Some(e) => e.extended_rcode(self.flags.rcode.to_u8()),
            None => self.flags.rcode.to_u8() as u16,
        }
    }

    /// Whether this is a response.
    pub fn is_response(&self) -> bool {
        self.flags.qr
    }

    /// Whether the TC bit is set (message truncated).
    pub fn is_truncated(&self) -> bool {
        self.flags.tc
    }

    /// Parse a message from wire bytes.
    pub fn parse(buf: &[u8]) -> Result<Message> {
        if buf.len() < 12 {
            return Err(Error::wire("message shorter than header"));
        }
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = HeaderFlags::from_u16(u16::from_be_bytes([buf[2], buf[3]]));
        let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
        let ns = u16::from_be_bytes([buf[8], buf[9]]) as usize;
        let ar = u16::from_be_bytes([buf[10], buf[11]]) as usize;
        if qd > MAX_QUESTIONS
            || an > MAX_SECTION_RECORDS
            || ns > MAX_SECTION_RECORDS
            || ar > MAX_SECTION_RECORDS
        {
            return Err(Error::wire("section count exceeds limits"));
        }

        let mut pos = 12usize;
        let mut questions = Vec::with_capacity(qd);
        for _ in 0..qd {
            let (qname, p) = Name::from_wire(buf, pos)?;
            if p + 4 > buf.len() {
                return Err(Error::wire("question truncated"));
            }
            let qtype = RrType(u16::from_be_bytes([buf[p], buf[p + 1]]));
            let qclass = RrClass(u16::from_be_bytes([buf[p + 2], buf[p + 3]]));
            pos = p + 4;
            questions.push(Question {
                qname,
                qtype,
                qclass,
            });
        }

        let mut answers = Vec::with_capacity(an);
        for _ in 0..an {
            answers.push(Record::parse(buf, &mut pos)?);
        }
        let mut authorities = Vec::with_capacity(ns);
        for _ in 0..ns {
            authorities.push(Record::parse(buf, &mut pos)?);
        }

        let mut additionals = Vec::with_capacity(ar);
        let mut edns = None;
        for _ in 0..ar {
            let rec = Record::parse(buf, &mut pos)?;
            if rec.rr_type == RrType::OPT {
                if edns.is_some() {
                    return Err(Error::wire("multiple OPT records"));
                }
                let options_data = match &rec.rdata {
                    crate::rdata::RData::Unknown(d) => d.clone(),
                    _ => Vec::new(),
                };
                edns = Some(Edns::parse(rec.class.to_u16(), rec.ttl, &options_data)?);
            } else {
                additionals.push(rec);
            }
        }

        Ok(Message {
            id,
            flags,
            questions,
            answers,
            authorities,
            additionals,
            edns,
        })
    }

    /// Serialize this message to wire bytes with name compression.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(512);
        let mut comp = NameCompressor::new();

        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_u16().to_be_bytes());
        // Placeholder for the four section counts (patched below).
        let count_pos = out.len();
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);

        for q in &self.questions {
            comp.write(&q.qname, &mut out);
            out.extend_from_slice(&q.qtype.to_u16().to_be_bytes());
            out.extend_from_slice(&q.qclass.to_u16().to_be_bytes());
        }
        for r in &self.answers {
            r.to_wire(&mut out, Some(&mut comp));
        }
        for r in &self.authorities {
            r.to_wire(&mut out, Some(&mut comp));
        }
        for r in &self.additionals {
            r.to_wire(&mut out, Some(&mut comp));
        }
        if let Some(edns) = &self.edns {
            // Write the OPT pseudo-record: owner = root, type = OPT,
            // class = UDP payload size, TTL = ext rcode/version/flags.
            comp.write(&Name::root(), &mut out);
            out.extend_from_slice(&RrType::OPT.to_u16().to_be_bytes());
            out.extend_from_slice(&edns.udp_payload_size.to_be_bytes());
            out.extend_from_slice(&edns.ttl_field().to_be_bytes());
            let opt_data = edns.options_wire();
            out.extend_from_slice(&(opt_data.len() as u16).to_be_bytes());
            out.extend_from_slice(&opt_data);
        }

        // Patch the section counts.
        let extra = self.additionals.len() + usize::from(self.edns.is_some());
        out[count_pos..count_pos + 8].copy_from_slice(&[
            (self.questions.len() as u16).to_be_bytes()[0],
            (self.questions.len() as u16).to_be_bytes()[1],
            (self.answers.len() as u16).to_be_bytes()[0],
            (self.answers.len() as u16).to_be_bytes()[1],
            (self.authorities.len() as u16).to_be_bytes()[0],
            (self.authorities.len() as u16).to_be_bytes()[1],
            (extra as u16).to_be_bytes()[0],
            (extra as u16).to_be_bytes()[1],
        ]);
        Ok(out)
    }

    /// The serialized wire length (with compression), or [`usize::MAX`]
    /// when serialization fails. Used for UDP truncation decisions.
    pub fn wire_len(&self) -> usize {
        self.to_bytes().map(|b| b.len()).unwrap_or(usize::MAX)
    }

    /// Truncate this (response) message so its wire form fits in `limit`
    /// bytes, per RFC 6891 §6.2.5 and RFC 1035 §4.2.1.
    ///
    /// Sets the TC bit and drops records — additional, then authority, then
    /// answer — from the end until the message fits. The question and the
    /// EDNS OPT record are preserved (the OPT record is small; the limit is
    /// a floor of 512 so a minimal message always fits). Used by the UDP
    /// server to avoid sending oversized, fragmenting datagrams.
    pub fn truncate_for_udp(&mut self, limit: usize) {
        let limit = limit.max(512);
        if self.wire_len() <= limit {
            return;
        }
        self.flags.tc = true;
        while self.wire_len() > limit {
            if !self.additionals.is_empty() {
                self.additionals.pop();
            } else if !self.authorities.is_empty() {
                self.authorities.pop();
            } else if !self.answers.is_empty() {
                self.answers.pop();
            } else {
                // Nothing left to drop; the header+question+EDNS still
                // overflows the (≥512) limit, which cannot happen for a
                // bounded message — stop to avoid an infinite loop.
                break;
            }
        }
    }

    /// Build a response with the same ID and question, the given flags, and
    /// the standard SERVFAIL rcode.
    pub fn error_response(&self, rcode: Rcode) -> Message {
        let mut m = Message::new(self.id);
        m.flags.qr = true;
        m.flags.rd = self.flags.rd;
        m.flags.ra = true;
        m.flags.rcode = rcode;
        m.questions.clone_from(&self.questions);
        // Preserve a minimal EDNS echo.
        if let Some(e) = &self.edns {
            m.edns = Some(Edns {
                udp_payload_size: e.udp_payload_size,
                ..Edns::new(e.udp_payload_size)
            });
        }
        m
    }

    /// Whether the message's first question matches `(name, qtype)`.
    pub fn matches_question(&self, name: &Name, qtype: RrType) -> bool {
        match self.question() {
            Some(q) => &q.qname == name && q.qtype == qtype,
            None => false,
        }
    }

    /// All records in the answer section of a given type.
    pub fn answers_of_type(&self, t: RrType) -> alloc::vec::Vec<&Record> {
        self.answers.iter().filter(|r| r.rr_type == t).collect()
    }

    /// The SOA record in the authority section (for negative caching).
    pub fn authority_soa(&self) -> Option<&Record> {
        self.authorities.iter().find(|r| r.rr_type == RrType::SOA)
    }
}

/// Build a DNS query payload (a `Message::to_bytes` convenience).
pub fn encode_query(id: u16, qname: &Name, qtype: RrType, edns: Option<&Edns>) -> Result<Vec<u8>> {
    let mut m = Message::query(id, qname.clone(), qtype, true);
    if let Some(e) = edns {
        m.edns = Some(e.clone());
    }
    m.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edns::EdnsOption;
    use crate::rdata::RData;

    fn sample_query() -> Vec<u8> {
        // A simple query for www.example.com A with RD.
        let mut v = Vec::new();
        v.extend_from_slice(&[0x12, 0x34]); // id
        v.extend_from_slice(&[0x01, 0x00]); // RD
        v.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // 1 question
        v.extend_from_slice(&[
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ]);
        v.extend_from_slice(&[0, 1, 0, 1]); // A IN
        v
    }

    #[test]
    fn parse_query() {
        let m = Message::parse(&sample_query()).unwrap();
        assert_eq!(m.id, 0x1234);
        assert!(m.flags.rd);
        assert!(!m.flags.qr);
        assert_eq!(m.questions.len(), 1);
        let q = &m.questions[0];
        assert_eq!(q.qname, Name::from_ascii("www.example.com").unwrap());
        assert_eq!(q.qtype, RrType::A);
        assert_eq!(q.qclass, RrClass::IN);
    }

    #[test]
    fn roundtrip_query() {
        let m = Message::parse(&sample_query()).unwrap();
        let bytes = m.to_bytes().unwrap();
        let m2 = Message::parse(&bytes).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn roundtrip_response_with_compression() {
        let mut m = Message::new(1);
        m.flags.qr = true;
        m.flags.ra = true;
        m.questions.push(Question {
            qname: Name::from_ascii("www.example.com").unwrap(),
            qtype: RrType::A,
            qclass: RrClass::IN,
        });
        // Two records whose owner names share the "example.com" suffix, so
        // the second owner name and the CNAME target compress.
        m.answers.push(Record {
            name: Name::from_ascii("www.example.com").unwrap(),
            rr_type: RrType::CNAME,
            class: RrClass::IN,
            ttl: 300,
            rdata: RData::Cname(Name::from_ascii("cdn.example.com").unwrap()),
        });
        m.answers.push(Record {
            name: Name::from_ascii("cdn.example.com").unwrap(),
            rr_type: RrType::A,
            class: RrClass::IN,
            ttl: 300,
            rdata: RData::A("93.184.216.34".parse().unwrap()),
        });
        m.edns = Some(Edns {
            udp_payload_size: 1232,
            ext_rcode: 0,
            version: 0,
            dnssec_ok: true,
            options: vec![EdnsOption::Nsid(vec![1, 2, 3])],
        });
        let bytes = m.to_bytes().unwrap();
        let m2 = Message::parse(&bytes).unwrap();
        assert_eq!(m, m2);
        // Verify compression actually happened: the second owner name is a
        // 2-byte pointer (0xc0 0x0c) referencing the first name.
        assert!(bytes.windows(2).any(|w| w == [0xc0, 0x0c]));
        assert!(bytes.len() < 100, "compressed size should be small");
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(Message::parse(&[0; 5]).is_err());
        assert!(Message::parse(&[0; 12]).is_ok()); // empty message is legal
                                                   // section count overflow
        let mut buf = [0u8; 12];
        buf[4] = 0xff;
        buf[5] = 0xff;
        assert!(Message::parse(&buf).is_err());
    }

    #[test]
    fn error_response() {
        let q = Message::parse(&sample_query()).unwrap();
        let e = q.error_response(Rcode::SERVFAIL);
        assert!(e.flags.qr);
        assert_eq!(e.flags.rcode, Rcode::SERVFAIL);
        assert_eq!(e.questions, q.questions);
        assert_eq!(e.id, q.id);
    }

    #[test]
    fn truncate_oversized_response_sets_tc_and_fits() {
        // A response with many distinct records so it far exceeds 512 bytes.
        let mut m = Message::new(7);
        m.flags.qr = true;
        m.questions.push(Question {
            qname: Name::from_ascii("big.example.com").unwrap(),
            qtype: RrType::TXT,
            qclass: RrClass::IN,
        });
        for i in 0..40u8 {
            let txt: Vec<u8> = (0..200).map(|_| i).collect();
            m.answers.push(Record {
                name: Name::from_ascii("big.example.com").unwrap(),
                rr_type: RrType::TXT,
                class: RrClass::IN,
                ttl: 300,
                rdata: RData::Txt(vec![txt]),
            });
        }
        let full = m.wire_len();
        assert!(full > 512);
        assert!(!m.is_truncated());

        m.truncate_for_udp(512);
        assert!(m.is_truncated());
        let bytes = m.to_bytes().unwrap();
        assert!(bytes.len() <= 512, "truncated size {}", bytes.len());
        // The question survives truncation.
        assert_eq!(m.questions.len(), 1);

        // A small response is left untouched.
        let mut small = Message::new(8);
        small.flags.qr = true;
        small.answers.push(Record {
            name: Name::from_ascii("a.example.com").unwrap(),
            rr_type: RrType::A,
            class: RrClass::IN,
            ttl: 300,
            rdata: RData::A("192.0.2.1".parse().unwrap()),
        });
        let before = small.wire_len();
        small.truncate_for_udp(512);
        assert!(!small.is_truncated());
        assert_eq!(small.wire_len(), before);
    }
}
