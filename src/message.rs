//! DNS message model: header, questions, records, and EDNS(0), with full
//! wire parsing and serialization (including RFC 1035 name compression).

use alloc::vec::Vec;

use crate::edns::Edns;
use crate::error::{Error, Result};
use crate::name::{Name, NameCompressor};
use crate::qtype::{Opcode, Rcode, RrClass, RrType};
use crate::rdata::Record;
use crate::wire::WireBytes;

/// Upper bound on any section count in a single message.
///
/// A record needs at least 11 octets on the wire (1 for the root owner
/// name, 10 for type/class/TTL/RDLENGTH), so a 64 KiB DNS-over-TCP message
/// cannot carry more than ~5950 of them. Bounding at 4096 keeps parsing
/// linear in the message size while never rejecting a response that could
/// legitimately exist — a larger cap would not make any legal message
/// parseable, a smaller one (512) rejects real answers such as a name with
/// a few hundred A records.
pub const MAX_SECTION_RECORDS: usize = 4096;
/// Upper bound on the number of questions in a message.
pub const MAX_QUESTIONS: usize = 16;

/// The 16-bit flags word of a DNS header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderFlags {
    /// Query/response flag (0 = query, 1 = response).
    pub qr: bool,
    /// The opcode.
    pub opcode: Opcode,
    /// Authoritative answer flag.
    pub aa: bool,
    /// Truncation flag.
    pub tc: bool,
    /// Recursion desired flag.
    pub rd: bool,
    /// Recursion available flag.
    pub ra: bool,
    /// Authentic data flag (DNSSEC).
    pub ad: bool,
    /// Checking disabled flag (DNSSEC).
    pub cd: bool,
    /// The response code.
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
    /// Encode the flags into the 16-bit wire word.
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

    /// Decode the flags from the 16-bit wire word.
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
    /// The query name.
    pub qname: Name,
    /// The query type.
    pub qtype: RrType,
    /// The query class.
    pub qclass: RrClass,
}

/// A parsed or to-be-serialized DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The 16-bit message ID.
    pub id: u16,
    /// The header flags.
    pub flags: HeaderFlags,
    /// The question section.
    pub questions: Vec<Question>,
    /// The answer section.
    pub answers: Vec<Record>,
    /// The authority section.
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
        let id = buf.u16_at(0)?;
        let flags = HeaderFlags::from_u16(buf.u16_at(2)?);
        let qd = usize::from(buf.u16_at(4)?);
        let an = usize::from(buf.u16_at(6)?);
        let ns = usize::from(buf.u16_at(8)?);
        let ar = usize::from(buf.u16_at(10)?);
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
            // The two reads below carry the truncation check: `u16_at(p + 2)`
            // fails unless all four bytes are there.
            let qtype = RrType(
                buf.u16_at(p)
                    .map_err(|_| Error::wire("question truncated"))?,
            );
            let qclass = RrClass(
                buf.u16_at(p + 2)
                    .map_err(|_| Error::wire("question truncated"))?,
            );
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
            r.to_wire(&mut out, Some(&mut comp))?;
        }
        for r in &self.authorities {
            r.to_wire(&mut out, Some(&mut comp))?;
        }
        for r in &self.additionals {
            r.to_wire(&mut out, Some(&mut comp))?;
        }
        if let Some(edns) = &self.edns {
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
        let counts = [
            self.questions.len() as u16,
            self.answers.len() as u16,
            self.authorities.len() as u16,
            extra as u16,
        ];
        let mut header_tail = [0u8; 8];
        for (dst, n) in header_tail.chunks_exact_mut(2).zip(counts) {
            dst.copy_from_slice(&n.to_be_bytes());
        }
        // `count_pos` was recorded where the header was written, so the range
        // is in bounds by construction — the check is what keeps that a fact
        // rather than an assumption.
        let dst = out
            .get_mut(count_pos..)
            .and_then(|tail| tail.get_mut(..header_tail.len()))
            .ok_or_else(|| Error::internal("header count offset out of range"))?;
        dst.copy_from_slice(&header_tail);
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
    /// EDNS OPT record are preserved (the OPT record is small, and the
    /// limit is floored at 512, so a minimal message always fits).
    ///
    /// The fit is computed in a single serialization pass: because name
    /// compression never rewrites bytes it has already emitted, the encoded
    /// prefix of a message is byte-identical to the prefix of its encoding,
    /// so the accepted record counts can be derived without re-serializing
    /// the message once per dropped record.
    pub fn truncate_for_udp(&mut self, limit: usize) {
        let limit = limit.max(512);
        if self.wire_len() <= limit {
            return;
        }
        self.flags.tc = true;
        let (answers, authorities, additionals) = self.fit_sections(limit);
        self.answers.truncate(answers);
        self.authorities.truncate(authorities);
        self.additionals.truncate(additionals);
    }

    /// How many records of each section fit in `limit` bytes (see
    /// [`Message::truncate_for_udp`]). The OPT record's own footprint is
    /// reserved so it survives truncation.
    fn fit_sections(&self, limit: usize) -> (usize, usize, usize) {
        let opt_len = self
            .edns
            .as_ref()
            .map(|e| 1 + 10 + e.options_wire().len())
            .unwrap_or(0);
        let budget = limit.saturating_sub(opt_len);

        let mut out: Vec<u8> = Vec::with_capacity(512);
        let mut comp = NameCompressor::new();
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags.to_u16().to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        for q in &self.questions {
            comp.write(&q.qname, &mut out);
            out.extend_from_slice(&q.qtype.to_u16().to_be_bytes());
            out.extend_from_slice(&q.qclass.to_u16().to_be_bytes());
        }

        let mut counts = (0usize, 0usize, 0usize);
        let sections: [(usize, &[Record]); 3] = [
            (0, &self.answers),
            (1, &self.authorities),
            (2, &self.additionals),
        ];
        'sections: for (idx, recs) in sections {
            for r in recs {
                let before = out.len();
                if r.to_wire(&mut out, Some(&mut comp)).is_err() {
                    out.truncate(before);
                    break 'sections;
                }
                if out.len() > budget {
                    out.truncate(before);
                    break 'sections;
                }
                match idx {
                    0 => counts.0 += 1,
                    1 => counts.1 += 1,
                    _ => counts.2 += 1,
                }
            }
        }
        counts
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
    #[cfg(not(feature = "std"))]
    use alloc::vec;

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
