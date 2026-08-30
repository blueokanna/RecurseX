//! Resource-record RDATA: parsing, serialization, and the in-memory model.
//!
//! RDATA parsing needs the enclosing message buffer because name-bearing
//! RDATA may use RFC 1035 compression pointers into the message. The parse
//! functions therefore take the full buffer plus a cursor bounded by the
//! RDATA length.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};
use crate::name::{Name, NameCompressor};
use crate::qtype::{DnssecAlgorithm, DsDigestType, RrClass, RrType};

/// The payload of a resource record.
#[derive(Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(Name),
    Dname(Name),
    Ns(Name),
    Ptr(Name),
    Mx {
        preference: u16,
        exchange: Name,
    },
    Soa {
        mname: Name,
        rname: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Txt(Vec<Vec<u8>>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: Name,
    },
    Naptr {
        order: u16,
        preference: u16,
        flags: Vec<u8>,
        services: Vec<u8>,
        regexp: Vec<u8>,
        replacement: Name,
    },
    Ds {
        key_tag: u16,
        algorithm: DnssecAlgorithm,
        digest_type: DsDigestType,
        digest: Vec<u8>,
    },
    Dnskey {
        flags: u16,
        protocol: u8,
        algorithm: DnssecAlgorithm,
        public_key: Vec<u8>,
    },
    Rrsig {
        type_covered: RrType,
        algorithm: DnssecAlgorithm,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer: Name,
        signature: Vec<u8>,
    },
    Nsec {
        next: Name,
        types: Vec<RrType>,
    },
    Nsec3 {
        hash_alg: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
        next_hashed: Vec<u8>,
        types: Vec<RrType>,
    },
    Nsec3Param {
        hash_alg: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
    },
    Caa {
        flags: u8,
        tag: Vec<u8>,
        value: Vec<u8>,
    },
    Tlsa {
        usage: u8,
        selector: u8,
        matching_type: u8,
        data: Vec<u8>,
    },
    Svcb {
        priority: u16,
        target: Name,
        params: Vec<(u16, Vec<u8>)>,
    },
    /// Any other type: the raw RDATA bytes.
    Unknown(Vec<u8>),
}

impl RData {
    /// Parse one RDATA from `buf` starting at `*pos`, with the RDATA
    /// bounded by `end` (exclusive). Name compression is resolved against
    /// the whole message `buf`. On success `*pos` is advanced past the
    /// consumed bytes.
    pub fn parse(buf: &[u8], pos: &mut usize, end: usize, rr_type: RrType) -> Result<RData> {
        if end > buf.len() {
            return Err(Error::wire("RDATA length exceeds message"));
        }
        if *pos > end {
            return Err(Error::wire("RDATA cursor past end"));
        }
        let rdlen = end - *pos;
        let need = |n: usize| -> Result<()> {
            if rdlen < n {
                return Err(Error::wire("RDATA truncated"));
            }
            Ok(())
        };
        let u16_at = |p: usize| -> Result<u16> {
            if p + 2 > end {
                return Err(Error::wire("RDATA truncated"));
            }
            Ok(u16::from_be_bytes([buf[p], buf[p + 1]]))
        };
        let u32_at = |p: usize| -> Result<u32> {
            if p + 4 > end {
                return Err(Error::wire("RDATA truncated"));
            }
            Ok(u32::from_be_bytes([
                buf[p],
                buf[p + 1],
                buf[p + 2],
                buf[p + 3],
            ]))
        };
        let read_name = |p: &mut usize| -> Result<Name> {
            let (n, next) = Name::from_wire(buf, *p)?;
            if next > end {
                return Err(Error::wire("name in RDATA overruns RDATA length"));
            }
            *p = next;
            Ok(n)
        };
        // A name whose total wire length is exactly `rdlen` (uncompressed)
        // is the most common case; validate that nothing trails.
        let name_exact = |p: &mut usize| -> Result<Name> {
            let n = read_name(p)?;
            if *p != end {
                return Err(Error::wire("trailing bytes after name in RDATA"));
            }
            Ok(n)
        };

        let r = match rr_type {
            RrType::A => {
                need(4)?;
                let ip = Ipv4Addr::new(buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]);
                *pos += 4;
                RData::A(ip)
            }
            RrType::AAAA => {
                need(16)?;
                let mut oct = [0u8; 16];
                oct.copy_from_slice(&buf[*pos..*pos + 16]);
                *pos += 16;
                RData::Aaaa(Ipv6Addr::from(oct))
            }
            RrType::CNAME => RData::Cname(name_exact(pos)?),
            RrType::DNAME => RData::Dname(name_exact(pos)?),
            RrType::NS => RData::Ns(name_exact(pos)?),
            RrType::PTR => RData::Ptr(name_exact(pos)?),
            RrType::MX => {
                need(2)?;
                let pref = u16_at(*pos)?;
                *pos += 2;
                let exchange = name_exact(pos)?;
                RData::Mx {
                    preference: pref,
                    exchange,
                }
            }
            RrType::SOA => {
                need(20)?; // two names (minimum 2 bytes each) + 20 fixed
                let mname = read_name(pos)?;
                let rname = read_name(pos)?;
                let fixed = |p: usize| -> Result<(u32, u32, u32, u32)> {
                    Ok((u32_at(p)?, u32_at(p + 4)?, u32_at(p + 8)?, u32_at(p + 12)?))
                };
                if *pos + 20 > end {
                    return Err(Error::wire("SOA RDATA truncated"));
                }
                let (serial, refresh, retry, expire) = fixed(*pos)?;
                let minimum = u32_at(*pos + 16)?;
                *pos += 20;
                RData::Soa {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }
            }
            RrType::TXT => {
                let mut strings = Vec::new();
                while *pos < end {
                    let l = buf[*pos] as usize;
                    *pos += 1;
                    if *pos + l > end {
                        return Err(Error::wire("TXT string truncated"));
                    }
                    strings.push(buf[*pos..*pos + l].to_vec());
                    *pos += l;
                }
                RData::Txt(strings)
            }
            RrType::SRV => {
                need(6)?;
                let priority = u16_at(*pos)?;
                let weight = u16_at(*pos + 2)?;
                let port = u16_at(*pos + 4)?;
                *pos += 6;
                let target = name_exact(pos)?;
                RData::Srv {
                    priority,
                    weight,
                    port,
                    target,
                }
            }
            RrType::NAPTR => {
                need(4)?;
                let order = u16_at(*pos)?;
                let preference = u16_at(*pos + 2)?;
                *pos += 4;
                let flags = read_char_string(buf, pos, end)?;
                let services = read_char_string(buf, pos, end)?;
                let regexp = read_char_string(buf, pos, end)?;
                let replacement = name_exact(pos)?;
                RData::Naptr {
                    order,
                    preference,
                    flags,
                    services,
                    regexp,
                    replacement,
                }
            }
            RrType::DS | RrType::CDS => {
                need(4)?;
                let key_tag = u16_at(*pos)?;
                let algorithm = DnssecAlgorithm(buf[*pos + 2]);
                let digest_type = DsDigestType(buf[*pos + 3]);
                *pos += 4;
                if *pos > end {
                    return Err(Error::wire("DS digest truncated"));
                }
                let digest = buf[*pos..end].to_vec();
                *pos = end;
                RData::Ds {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                }
            }
            RrType::DNSKEY | RrType::CDNSKEY => {
                need(4)?;
                let flags = u16_at(*pos)?;
                let protocol = buf[*pos + 2];
                let algorithm = DnssecAlgorithm(buf[*pos + 3]);
                *pos += 4;
                if *pos > end {
                    return Err(Error::wire("DNSKEY public key truncated"));
                }
                let public_key = buf[*pos..end].to_vec();
                *pos = end;
                RData::Dnskey {
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                }
            }
            RrType::RRSIG | RrType::SIG => {
                need(18)?;
                let type_covered = RrType(u16_at(*pos)?);
                let algorithm = DnssecAlgorithm(buf[*pos + 2]);
                let labels = buf[*pos + 3];
                let original_ttl = u32_at(*pos + 4)?;
                let expiration = u32_at(*pos + 8)?;
                let inception = u32_at(*pos + 12)?;
                let key_tag = u16_at(*pos + 16)?;
                *pos += 18;
                let signer = read_name(pos)?;
                if *pos > end {
                    return Err(Error::wire("RRSIG signature truncated"));
                }
                let signature = buf[*pos..end].to_vec();
                *pos = end;
                RData::Rrsig {
                    type_covered,
                    algorithm,
                    labels,
                    original_ttl,
                    expiration,
                    inception,
                    key_tag,
                    signer,
                    signature,
                }
            }
            RrType::NSEC => {
                let next = read_name(pos)?;
                let types = parse_type_bitmap(buf, pos, end)?;
                RData::Nsec { next, types }
            }
            RrType::NSEC3 => {
                need(5)?;
                let hash_alg = buf[*pos];
                let flags = buf[*pos + 1];
                let iterations = u16_at(*pos + 2)?;
                let salt_len = buf[*pos + 4] as usize;
                *pos += 5;
                if *pos + salt_len > end {
                    return Err(Error::wire("NSEC3 salt truncated"));
                }
                let salt = buf[*pos..*pos + salt_len].to_vec();
                *pos += salt_len;
                if *pos >= end {
                    return Err(Error::wire("NSEC3 next-hashed length missing"));
                }
                let next_len = buf[*pos] as usize;
                *pos += 1;
                if *pos + next_len > end {
                    return Err(Error::wire("NSEC3 next-hashed truncated"));
                }
                let next_hashed = buf[*pos..*pos + next_len].to_vec();
                *pos += next_len;
                let types = parse_type_bitmap(buf, pos, end)?;
                RData::Nsec3 {
                    hash_alg,
                    flags,
                    iterations,
                    salt,
                    next_hashed,
                    types,
                }
            }
            RrType::NSEC3PARAM => {
                need(5)?;
                let hash_alg = buf[*pos];
                let flags = buf[*pos + 1];
                let iterations = u16_at(*pos + 2)?;
                let salt_len = buf[*pos + 4] as usize;
                *pos += 5;
                if *pos + salt_len > end {
                    return Err(Error::wire("NSEC3PARAM salt truncated"));
                }
                let salt = buf[*pos..*pos + salt_len].to_vec();
                *pos += salt_len;
                RData::Nsec3Param {
                    hash_alg,
                    flags,
                    iterations,
                    salt,
                }
            }
            RrType::CAA => {
                need(2)?;
                let flags = buf[*pos];
                let tag_len = buf[*pos + 1] as usize;
                *pos += 2;
                if *pos + tag_len > end {
                    return Err(Error::wire("CAA tag truncated"));
                }
                let tag = buf[*pos..*pos + tag_len].to_vec();
                *pos += tag_len;
                let value = buf[*pos..end].to_vec();
                *pos = end;
                RData::Caa { flags, tag, value }
            }
            RrType::TLSA | RrType::SMIMEA => {
                need(3)?;
                let usage = buf[*pos];
                let selector = buf[*pos + 1];
                let matching_type = buf[*pos + 2];
                *pos += 3;
                let data = buf[*pos..end].to_vec();
                *pos = end;
                RData::Tlsa {
                    usage,
                    selector,
                    matching_type,
                    data,
                }
            }
            RrType::SVCB | RrType::HTTPS => {
                need(2)?;
                let priority = u16_at(*pos)?;
                *pos += 2;
                let target = read_name(pos)?;
                let mut params = Vec::new();
                while *pos < end {
                    if *pos + 4 > end {
                        return Err(Error::wire("SVCB param header truncated"));
                    }
                    let key = u16_at(*pos)?;
                    let len = u16_at(*pos + 2)? as usize;
                    *pos += 4;
                    if *pos + len > end {
                        return Err(Error::wire("SVCB param value truncated"));
                    }
                    params.push((key, buf[*pos..*pos + len].to_vec()));
                    *pos += len;
                }
                RData::Svcb {
                    priority,
                    target,
                    params,
                }
            }
            _ => {
                let data = buf[*pos..end].to_vec();
                *pos = end;
                RData::Unknown(data)
            }
        };
        Ok(r)
    }

    /// Serialize this RDATA into `out`, optionally using name compression
    /// for the types that RFC 1035 / RFC 6672 permit.
    pub fn to_wire(&self, out: &mut Vec<u8>, mut comp: Option<&mut NameCompressor>) {
        let mut name = |out: &mut Vec<u8>, n: &Name, allow: bool| {
            if allow {
                if let Some(c) = comp.as_deref_mut() {
                    c.write(n, out);
                    return;
                }
            }
            n.write_wire(out);
        };
        match self {
            RData::A(ip) => out.extend_from_slice(&ip.octets()),
            RData::Aaaa(ip) => out.extend_from_slice(&ip.octets()),
            RData::Cname(n) => name(out, n, true),
            RData::Dname(n) => name(out, n, true),
            RData::Ns(n) => name(out, n, true),
            RData::Ptr(n) => name(out, n, true),
            RData::Mx {
                preference,
                exchange,
            } => {
                out.extend_from_slice(&preference.to_be_bytes());
                name(out, exchange, true);
            }
            RData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                name(out, mname, true);
                name(out, rname, true);
                out.extend_from_slice(&serial.to_be_bytes());
                out.extend_from_slice(&refresh.to_be_bytes());
                out.extend_from_slice(&retry.to_be_bytes());
                out.extend_from_slice(&expire.to_be_bytes());
                out.extend_from_slice(&minimum.to_be_bytes());
            }
            RData::Txt(strings) => {
                for s in strings {
                    out.push(s.len().min(255) as u8);
                    out.extend_from_slice(&s[..s.len().min(255)]);
                }
            }
            RData::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                out.extend_from_slice(&priority.to_be_bytes());
                out.extend_from_slice(&weight.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
                // RFC 2782: the target name MUST NOT be compressed.
                target.write_wire(out);
            }
            RData::Naptr {
                order,
                preference,
                flags,
                services,
                regexp,
                replacement,
            } => {
                out.extend_from_slice(&order.to_be_bytes());
                out.extend_from_slice(&preference.to_be_bytes());
                write_char_string(out, flags);
                write_char_string(out, services);
                write_char_string(out, regexp);
                // RFC 3403 §4.1: the replacement name MUST NOT be compressed.
                replacement.write_wire(out);
            }
            RData::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                out.extend_from_slice(&key_tag.to_be_bytes());
                out.push(algorithm.to_u8());
                out.push(digest_type.to_u8());
                out.extend_from_slice(digest);
            }
            RData::Dnskey {
                flags,
                protocol,
                algorithm,
                public_key,
            } => {
                out.extend_from_slice(&flags.to_be_bytes());
                out.push(*protocol);
                out.push(algorithm.to_u8());
                out.extend_from_slice(public_key);
            }
            RData::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer,
                signature,
            } => {
                out.extend_from_slice(&type_covered.to_u16().to_be_bytes());
                out.push(algorithm.to_u8());
                out.push(*labels);
                out.extend_from_slice(&original_ttl.to_be_bytes());
                out.extend_from_slice(&expiration.to_be_bytes());
                out.extend_from_slice(&inception.to_be_bytes());
                out.extend_from_slice(&key_tag.to_be_bytes());
                signer.write_wire(out);
                out.extend_from_slice(signature);
            }
            RData::Nsec { next, types } => {
                next.write_wire(out);
                write_type_bitmap(out, types);
            }
            RData::Nsec3 {
                hash_alg,
                flags,
                iterations,
                salt,
                next_hashed,
                types,
            } => {
                out.push(*hash_alg);
                out.push(*flags);
                out.extend_from_slice(&iterations.to_be_bytes());
                out.push(salt.len().min(255) as u8);
                out.extend_from_slice(&salt[..salt.len().min(255)]);
                out.push(next_hashed.len().min(255) as u8);
                out.extend_from_slice(&next_hashed[..next_hashed.len().min(255)]);
                write_type_bitmap(out, types);
            }
            RData::Nsec3Param {
                hash_alg,
                flags,
                iterations,
                salt,
            } => {
                out.push(*hash_alg);
                out.push(*flags);
                out.extend_from_slice(&iterations.to_be_bytes());
                out.push(salt.len().min(255) as u8);
                out.extend_from_slice(&salt[..salt.len().min(255)]);
            }
            RData::Caa { flags, tag, value } => {
                out.push(*flags);
                out.push(tag.len().min(255) as u8);
                out.extend_from_slice(&tag[..tag.len().min(255)]);
                out.extend_from_slice(value);
            }
            RData::Tlsa {
                usage,
                selector,
                matching_type,
                data,
            } => {
                out.push(*usage);
                out.push(*selector);
                out.push(*matching_type);
                out.extend_from_slice(data);
            }
            RData::Svcb {
                priority,
                target,
                params,
            } => {
                out.extend_from_slice(&priority.to_be_bytes());
                target.write_wire(out);
                for (key, value) in params {
                    out.extend_from_slice(&key.to_be_bytes());
                    out.extend_from_slice(&(value.len().min(0xffff) as u16).to_be_bytes());
                    out.extend_from_slice(&value[..value.len().min(0xffff)]);
                }
            }
            RData::Unknown(data) => out.extend_from_slice(data),
        }
    }

    /// The wire length of this RDATA (no compression applied — used for
    /// sizing and for RDATA that must not be compressed).
    pub fn wire_len(&self) -> usize {
        let mut v = Vec::new();
        self.to_wire(&mut v, None);
        v.len()
    }

    /// The rrtype this RData corresponds to (for `Unknown`).
    pub fn type_hint(&self) -> Option<RrType> {
        match self {
            RData::A(_) => Some(RrType::A),
            RData::Aaaa(_) => Some(RrType::AAAA),
            RData::Cname(_) => Some(RrType::CNAME),
            RData::Dname(_) => Some(RrType::DNAME),
            RData::Ns(_) => Some(RrType::NS),
            RData::Ptr(_) => Some(RrType::PTR),
            RData::Mx { .. } => Some(RrType::MX),
            RData::Soa { .. } => Some(RrType::SOA),
            RData::Txt(_) => Some(RrType::TXT),
            RData::Srv { .. } => Some(RrType::SRV),
            RData::Naptr { .. } => Some(RrType::NAPTR),
            RData::Ds { .. } => Some(RrType::DS),
            RData::Dnskey { .. } => Some(RrType::DNSKEY),
            RData::Rrsig { .. } => Some(RrType::RRSIG),
            RData::Nsec { .. } => Some(RrType::NSEC),
            RData::Nsec3 { .. } => Some(RrType::NSEC3),
            RData::Nsec3Param { .. } => Some(RrType::NSEC3PARAM),
            RData::Caa { .. } => Some(RrType::CAA),
            RData::Tlsa { .. } => Some(RrType::TLSA),
            RData::Svcb { .. } => Some(RrType::SVCB),
            RData::Unknown(_) => None,
        }
    }
}

fn read_char_string(buf: &[u8], pos: &mut usize, end: usize) -> Result<Vec<u8>> {
    if *pos >= end {
        return Err(Error::wire("character-string truncated"));
    }
    let l = buf[*pos] as usize;
    *pos += 1;
    if *pos + l > end {
        return Err(Error::wire("character-string truncated"));
    }
    let s = buf[*pos..*pos + l].to_vec();
    *pos += l;
    Ok(s)
}

fn write_char_string(out: &mut Vec<u8>, s: &[u8]) {
    out.push(s.len().min(255) as u8);
    out.extend_from_slice(&s[..s.len().min(255)]);
}

/// Parse an NSEC/NSEC3 type-bitmap (RFC 4034 §4.1.2).
fn parse_type_bitmap(buf: &[u8], pos: &mut usize, end: usize) -> Result<Vec<RrType>> {
    let mut types = Vec::new();
    while *pos < end {
        if *pos + 2 > end {
            return Err(Error::wire("type bitmap window truncated"));
        }
        let window = buf[*pos];
        let len = buf[*pos + 1] as usize;
        *pos += 2;
        if len == 0 || len > 32 || *pos + len > end {
            return Err(Error::wire("type bitmap window length invalid"));
        }
        for (i, &byte) in buf[*pos..*pos + len].iter().enumerate() {
            for bit in 0..8 {
                if byte & (0x80 >> bit) != 0 {
                    let t = (window as u16) * 256 + (i as u16) * 8 + bit as u16;
                    types.push(RrType(t));
                }
            }
        }
        *pos += len;
    }
    Ok(types)
}

/// Serialize a type-bitmap (RFC 4034 §4.1.2).
fn write_type_bitmap(out: &mut Vec<u8>, types: &[RrType]) {
    if types.is_empty() {
        return;
    }
    let mut sorted: Vec<u16> = types.iter().map(|t| t.to_u16()).collect();
    sorted.sort_unstable();
    sorted.dedup();
    let mut windows: Vec<(u8, [u8; 32], usize)> = Vec::new();
    for &t in &sorted {
        let window = (t >> 8) as u8;
        let idx = ((t & 0xff) / 8) as usize;
        let bit = ((t & 0xff) % 8) as usize;
        match windows.iter_mut().find(|(w, _, _)| *w == window) {
            Some((_, bytes, used)) => {
                bytes[idx] |= 0x80 >> bit;
                *used = (*used).max(idx + 1);
            }
            None => {
                let mut bytes = [0u8; 32];
                bytes[idx] |= 0x80 >> bit;
                windows.push((window, bytes, idx + 1));
            }
        }
    }
    for (window, bytes, used) in windows {
        out.push(window);
        out.push(used as u8);
        out.extend_from_slice(&bytes[..used]);
    }
}

/// A parsed resource record.
#[derive(Clone, PartialEq, Eq)]
pub struct Record {
    /// Owner name.
    pub name: Name,
    /// Record type.
    pub rr_type: RrType,
    /// Class.
    pub class: RrClass,
    /// TTL in seconds.
    pub ttl: u32,
    /// The record data.
    pub rdata: RData,
}

impl Record {
    /// Parse one record from `buf` at `*pos`; advances `*pos` past the
    /// record. The record's own RDATA length governs parsing.
    pub fn parse(buf: &[u8], pos: &mut usize) -> Result<Record> {
        let (name, mut p) = Name::from_wire(buf, *pos)?;
        if p + 10 > buf.len() {
            return Err(Error::wire("record header truncated"));
        }
        let rr_type = RrType(u16::from_be_bytes([buf[p], buf[p + 1]]));
        let class = RrClass(u16::from_be_bytes([buf[p + 2], buf[p + 3]]));
        let ttl = u32::from_be_bytes([buf[p + 4], buf[p + 5], buf[p + 6], buf[p + 7]]);
        let rdlen = u16::from_be_bytes([buf[p + 8], buf[p + 9]]) as usize;
        p += 10;
        let end = p + rdlen;
        if end > buf.len() {
            return Err(Error::wire("record RDATA overruns message"));
        }
        let rdata = if rr_type == RrType::OPT {
            // OPT records are pseudo-records handled by the message layer;
            // keep the raw options.
            RData::Unknown(buf[p..end].to_vec())
        } else {
            RData::parse(buf, &mut p, end, rr_type)?
        };
        *pos = end;
        Ok(Record {
            name,
            rr_type,
            class,
            ttl,
            rdata,
        })
    }

    /// Serialize this record into `out` with optional name compression.
    pub fn to_wire(&self, out: &mut Vec<u8>, mut comp: Option<&mut NameCompressor>) {
        match comp.as_deref_mut() {
            Some(c) => c.write(&self.name, out),
            None => self.name.write_wire(out),
        }
        out.extend_from_slice(&self.rr_type.to_u16().to_be_bytes());
        out.extend_from_slice(&self.class.to_u16().to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        let rdlen_pos = out.len();
        out.extend_from_slice(&[0, 0]);
        self.rdata.to_wire(out, comp);
        let rdlen = out.len() - rdlen_pos - 2;
        debug_assert!(rdlen <= u16::MAX as usize);
        out[rdlen_pos..rdlen_pos + 2].copy_from_slice(&(rdlen as u16).to_be_bytes());
    }
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {:?} {:?} ttl={} {:?}",
            self.name, self.rr_type, self.class, self.ttl, self.rdata
        )
    }
}

impl fmt::Debug for RData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RData::A(ip) => write!(f, "A {ip}"),
            RData::Aaaa(ip) => write!(f, "AAAA {ip}"),
            RData::Cname(n) => write!(f, "CNAME {n}"),
            RData::Dname(n) => write!(f, "DNAME {n}"),
            RData::Ns(n) => write!(f, "NS {n}"),
            RData::Ptr(n) => write!(f, "PTR {n}"),
            RData::Mx { preference, exchange } => write!(f, "MX {preference} {exchange}"),
            RData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => write!(
                f,
                "SOA {mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
            ),
            RData::Txt(s) => {
                write!(f, "TXT")?;
                for part in s {
                    let _ = write!(f, " \"{}\"", String::from_utf8_lossy(part));
                }
                Ok(())
            }
            RData::Srv {
                priority,
                weight,
                port,
                target,
            } => write!(f, "SRV {priority} {weight} {port} {target}"),
            RData::Naptr {
                order,
                preference,
                flags,
                services,
                regexp,
                replacement,
            } => write!(
                f,
                "NAPTR {order} {preference} {:?} {:?} {:?} {replacement}",
                String::from_utf8_lossy(flags),
                String::from_utf8_lossy(services),
                String::from_utf8_lossy(regexp)
            ),
            RData::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => write!(
                f,
                "DS {key_tag} {} {} {}",
                algorithm.as_str(),
                digest_type.to_u8(),
                hex(digest)
            ),
            RData::Dnskey {
                flags,
                protocol,
                algorithm,
                public_key,
            } => write!(
                f,
                "DNSKEY flags={flags} proto={protocol} alg={} key={}",
                algorithm.as_str(),
                hex(public_key)
            ),
            RData::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer,
                ..
            } => write!(
                f,
                "RRSIG {:?} {} labels={} orig_ttl={original_ttl} exp={expiration} inc={inception} key_tag={key_tag} signer={signer}",
                type_covered, algorithm.as_str(), labels
            ),
            RData::Nsec { next, types } => {
                write!(f, "NSEC {next}")?;
                for t in types {
                    write!(f, " {:?}", t)?;
                }
                Ok(())
            }
            RData::Nsec3 {
                hash_alg,
                flags,
                iterations,
                salt,
                next_hashed,
                types,
            } => {
                write!(
                    f,
                    "NSEC3 alg={hash_alg} flags={flags} iters={iterations} salt={} next={}",
                    hex(salt),
                    hex(next_hashed)
                )?;
                for t in types {
                    write!(f, " {:?}", t)?;
                }
                Ok(())
            }
            RData::Nsec3Param {
                hash_alg,
                flags,
                iterations,
                salt,
            } => write!(
                f,
                "NSEC3PARAM alg={hash_alg} flags={flags} iters={iterations} salt={}",
                hex(salt)
            ),
            RData::Caa { flags, tag, value } => write!(
                f,
                "CAA {flags} {:?} {:?}",
                String::from_utf8_lossy(tag),
                String::from_utf8_lossy(value)
            ),
            RData::Tlsa {
                usage,
                selector,
                matching_type,
                data,
            } => write!(
                f,
                "TLSA {usage} {selector} {matching_type} {}",
                hex(data)
            ),
            RData::Svcb {
                priority,
                target,
                params,
            } => {
                write!(f, "SVCB {priority} {target}")?;
                for (k, v) in params {
                    write!(f, " k{k}={}", hex(v))?;
                }
                Ok(())
            }
            RData::Unknown(data) => write!(f, "RAW {}", hex(data)),
        }
    }
}

/// Render bytes as lowercase hex.
pub fn hex(bytes: &[u8]) -> alloc::string::String {
    use alloc::string::String;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_rdata(bytes: &[u8], rr_type: RrType) -> RData {
        let mut pos = 0;
        let end = bytes.len();
        RData::parse(bytes, &mut pos, end, rr_type).unwrap()
    }

    #[test]
    fn a_and_aaaa() {
        let a = parse_rdata(&[192, 0, 2, 1], RrType::A);
        assert_eq!(a, RData::A(Ipv4Addr::new(192, 0, 2, 1)));
        let mut v = Vec::new();
        a.to_wire(&mut v, None);
        assert_eq!(v, [192, 0, 2, 1]);

        let mut ip6 = [0u8; 16];
        ip6[0] = 0x20;
        ip6[1] = 0x01;
        let aaaa = parse_rdata(&ip6, RrType::AAAA);
        assert_eq!(aaaa, RData::Aaaa(Ipv6Addr::from(ip6)));
    }

    #[test]
    fn mx_roundtrip() {
        // 0x000a, name "example.com"
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0, 10]);
        bytes.extend_from_slice(&[7]);
        bytes.extend_from_slice(b"example");
        bytes.extend_from_slice(&[3]);
        bytes.extend_from_slice(b"com");
        bytes.push(0);
        let mx = parse_rdata(&bytes, RrType::MX);
        assert_eq!(
            mx,
            RData::Mx {
                preference: 10,
                exchange: Name::from_ascii("example.com").unwrap()
            }
        );
        let mut v = Vec::new();
        mx.to_wire(&mut v, None);
        assert_eq!(v, bytes);
    }

    #[test]
    fn txt_roundtrip() {
        let txt = RData::Txt(vec![b"hello".to_vec(), b"world".to_vec()]);
        let mut v = Vec::new();
        txt.to_wire(&mut v, None);
        assert_eq!(
            v,
            [5, b'h', b'e', b'l', b'l', b'o', 5, b'w', b'o', b'r', b'l', b'd']
        );
        let parsed = parse_rdata(&v, RrType::TXT);
        assert_eq!(parsed, txt);
    }

    #[test]
    fn soa_roundtrip() {
        let soa = RData::Soa {
            mname: Name::from_ascii("ns1.example.com").unwrap(),
            rname: Name::from_ascii("hostmaster.example.com").unwrap(),
            serial: 2024010101,
            refresh: 7200,
            retry: 900,
            expire: 1209600,
            minimum: 300,
        };
        let mut v = Vec::new();
        soa.to_wire(&mut v, None);
        let parsed = parse_rdata(&v, RrType::SOA);
        assert_eq!(parsed, soa);
    }

    #[test]
    fn dnskey_ds_rrsig_roundtrip() {
        let dnskey = RData::Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: DnssecAlgorithm::RSASHA256,
            public_key: vec![1, 2, 3, 4],
        };
        let mut v = Vec::new();
        dnskey.to_wire(&mut v, None);
        assert_eq!(parse_rdata(&v, RrType::DNSKEY), dnskey);

        let ds = RData::Ds {
            key_tag: 12345,
            algorithm: DnssecAlgorithm::RSASHA256,
            digest_type: DsDigestType::SHA256,
            digest: vec![0xab; 32],
        };
        let mut v = Vec::new();
        ds.to_wire(&mut v, None);
        assert_eq!(parse_rdata(&v, RrType::DS), ds);

        let rrsig = RData::Rrsig {
            type_covered: RrType::A,
            algorithm: DnssecAlgorithm::RSASHA256,
            labels: 3,
            original_ttl: 300,
            expiration: 1_700_000_000,
            inception: 1_690_000_000,
            key_tag: 12345,
            signer: Name::from_ascii("example.com").unwrap(),
            signature: vec![9, 8, 7],
        };
        let mut v = Vec::new();
        rrsig.to_wire(&mut v, None);
        assert_eq!(parse_rdata(&v, RrType::RRSIG), rrsig);
    }

    #[test]
    fn nsec_bitmap_roundtrip() {
        let nsec = RData::Nsec {
            next: Name::from_ascii("zzz.example.com").unwrap(),
            types: vec![
                RrType::A,
                RrType::NS,
                RrType::SOA,
                RrType::RRSIG,
                RrType::NSEC,
                RrType::MX,
                RrType::AAAA,
            ],
        };
        let mut v = Vec::new();
        nsec.to_wire(&mut v, None);
        let parsed = parse_rdata(&v, RrType::NSEC);
        // The bitmap serializes types in ascending numeric order.
        let (next, mut types) = match nsec {
            RData::Nsec { next, types } => (next, types),
            _ => unreachable!(),
        };
        types.sort_by_key(|t| t.to_u16());
        assert_eq!(parsed, RData::Nsec { next, types });
    }

    #[test]
    fn nsec3_roundtrip() {
        let nsec3 = RData::Nsec3 {
            hash_alg: 1,
            flags: 0,
            iterations: 5,
            salt: vec![0x01, 0x02],
            next_hashed: vec![0xaa; 20],
            types: vec![RrType::A, RrType::NS],
        };
        let mut v = Vec::new();
        nsec3.to_wire(&mut v, None);
        let parsed = parse_rdata(&v, RrType::NSEC3);
        assert_eq!(parsed, nsec3);
    }

    #[test]
    fn truncated_is_rejected() {
        assert!(RData::parse(&[192, 0, 2], &mut 0, 3, RrType::A).is_err());
    }

    #[test]
    fn caa_roundtrip() {
        let caa = RData::Caa {
            flags: 0,
            tag: b"issue".to_vec(),
            value: b"letsencrypt.org".to_vec(),
        };
        let mut v = Vec::new();
        caa.to_wire(&mut v, None);
        assert_eq!(parse_rdata(&v, RrType::CAA), caa);
    }

    #[test]
    fn svcb_roundtrip() {
        let svcb = RData::Svcb {
            priority: 1,
            target: Name::from_ascii("dns.example.net").unwrap(),
            params: vec![(1, vec![0x04, 0x00, 0x02, 0x01]), (3, vec![b'a', b'b'])],
        };
        let mut v = Vec::new();
        svcb.to_wire(&mut v, None);
        assert_eq!(parse_rdata(&v, RrType::HTTPS), svcb);
    }
}
