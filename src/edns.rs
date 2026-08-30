//! EDNS(0) (RFC 6891) and its options: ECS (RFC 7871), Cookies (RFC 7873),
//! Padding (RFC 7830), TCP Keepalive (RFC 7828), Key Tag (RFC 8145).

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};

/// EDNS option codes (RFC 6891 §6.1.2 and successors).
pub mod opt {
    /// LLQ (RFC 2136, experimental).
    pub const LLQ: u16 = 1;
    /// Update Lease (RFC 2136, experimental).
    pub const UL: u16 = 2;
    /// Name Server Identifier (RFC 5001).
    pub const NSID: u16 = 3;
    /// DNSSEC Algorithm Understood (RFC 6975).
    pub const DAU: u16 = 5;
    /// DS Hash Understood (RFC 6975).
    pub const DHU: u16 = 6;
    /// NSEC3 Hash Understood (RFC 6975).
    pub const N3U: u16 = 7;
    /// Client Subnet (RFC 7871).
    pub const ECS: u16 = 8;
    /// Expire (RFC 7314).
    pub const EXPIRE: u16 = 9;
    /// DNS Cookie (RFC 7873).
    pub const COOKIE: u16 = 10;
    /// TCP Keepalive (RFC 7828).
    pub const KEEPALIVE: u16 = 11;
    /// Padding (RFC 7830).
    pub const PADDING: u16 = 12;
    /// CHAIN (RFC 7901).
    pub const CHAIN: u16 = 13;
    /// Key Tag (RFC 8145).
    pub const KEY_TAG: u16 = 14;
    /// Extended DNS Errors (RFC 8914).
    pub const EDE: u16 = 15;
    /// Client Tag (RFC 8914).
    pub const CLIENT_TAG: u16 = 16;
    /// Server Tag (RFC 8914).
    pub const SERVER_TAG: u16 = 17;
    /// Zone Version (RFC 9108).
    pub const ZONEVERSION: u16 = 18;
}

/// A single EDNS option.
#[derive(Clone, PartialEq, Eq)]
pub enum EdnsOption {
    /// Client Subnet (RFC 7871).
    Ecs(Ecs),
    /// DNS Cookie (RFC 7873): the 8-byte client cookie and, optionally,
    /// the server cookie.
    Cookie {
        /// The 8-byte client cookie.
        client: [u8; 8],
        /// The server cookie, if the server returned one.
        server: Vec<u8>,
    },
    /// TCP Keepalive (RFC 7828). `None` requests the server's idle timeout.
    TcpKeepalive(Option<u16>),
    /// Padding (RFC 7830) — the length in octets the sender asks to pad to.
    Padding(u16),
    /// Key Tag (RFC 8145) — used for RFC 5011 trust-anchor signaling.
    KeyTag(Vec<u16>),
    /// NSID (RFC 5001).
    Nsid(Vec<u8>),
    /// Extended DNS Errors (RFC 8914).
    Ede {
        /// The EDE info-code (RFC 8914 §6).
        info_code: u16,
        /// Extra text carried with the error.
        extra: Vec<u8>,
    },
    /// Any other option, kept raw.
    Unknown {
        /// The option code on the wire.
        code: u16,
        /// The raw option data.
        data: Vec<u8>,
    },
}

impl EdnsOption {
    /// The option code on the wire.
    pub fn code(&self) -> u16 {
        match self {
            EdnsOption::Ecs(_) => opt::ECS,
            EdnsOption::Cookie { .. } => opt::COOKIE,
            EdnsOption::TcpKeepalive(_) => opt::KEEPALIVE,
            EdnsOption::Padding(_) => opt::PADDING,
            EdnsOption::KeyTag(_) => opt::KEY_TAG,
            EdnsOption::Nsid(_) => opt::NSID,
            EdnsOption::Ede { .. } => opt::EDE,
            EdnsOption::Unknown { code, .. } => *code,
        }
    }
}

impl fmt::Debug for EdnsOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EdnsOption::Ecs(e) => write!(f, "ECS {e:?}"),
            EdnsOption::Cookie { client, server } => {
                write!(f, "COOKIE client={:02x?} server={:02x?}", client, server)
            }
            EdnsOption::TcpKeepalive(t) => write!(f, "KEEPALIVE {t:?}"),
            EdnsOption::Padding(n) => write!(f, "PADDING {n}"),
            EdnsOption::KeyTag(tags) => write!(f, "KEY-TAG {tags:?}"),
            EdnsOption::Nsid(v) => write!(f, "NSID {:02x?}", v),
            EdnsOption::Ede { info_code, extra } => {
                write!(f, "EDE {info_code} {:02x?}", extra)
            }
            EdnsOption::Unknown { code, data } => write!(f, "OPT{code} {:02x?}", data),
        }
    }
}

/// EDNS Client Subnet (RFC 7871).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Ecs {
    /// Address family: 1 = IPv4, 2 = IPv6.
    pub family: u16,
    /// Source prefix length (network bits).
    pub source_prefix: u8,
    /// Scope prefix length (from the server; 0 in queries).
    pub scope_prefix: u8,
    /// The (masked) address bytes: `ceil(source_prefix / 8)` octets.
    pub address: Vec<u8>,
}

impl fmt::Debug for Ecs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}/{} (scope {})",
            match self.family {
                1 => "IPv4",
                2 => "IPv6",
                _ => "?",
            },
            self.address_string(),
            self.source_prefix,
            self.scope_prefix
        )
    }
}

impl Ecs {
    /// Build an IPv4 ECS with a given prefix length (0..=32).
    pub fn ipv4(ip: Ipv4Addr, prefix: u8) -> Result<Ecs> {
        if prefix > 32 {
            return Err(Error::wire("ECS IPv4 prefix > 32"));
        }
        let octets = ip.octets();
        let addr = mask(&octets, prefix);
        Ok(Ecs {
            family: 1,
            source_prefix: prefix,
            scope_prefix: 0,
            address: addr,
        })
    }

    /// Build an IPv6 ECS with a given prefix length (0..=128).
    pub fn ipv6(ip: Ipv6Addr, prefix: u8) -> Result<Ecs> {
        if prefix > 128 {
            return Err(Error::wire("ECS IPv6 prefix > 128"));
        }
        let octets = ip.octets();
        let addr = mask(&octets, prefix);
        Ok(Ecs {
            family: 2,
            source_prefix: prefix,
            scope_prefix: 0,
            address: addr,
        })
    }

    /// The address bytes, zero-padded to the family's full length.
    pub fn full_address(&self) -> Vec<u8> {
        let full = match self.family {
            1 => 4,
            2 => 16,
            _ => 0,
        };
        if full == 0 {
            return self.address.clone();
        }
        let mut v = vec![0u8; full];
        let n = (self.address.len()).min(full);
        v[..n].copy_from_slice(&self.address[..n]);
        v
    }

    /// Render the masked address as a presentation string.
    pub fn address_string(&self) -> alloc::string::String {
        use alloc::string::ToString;
        let fa = self.full_address();
        match self.family {
            1 if fa.len() >= 4 => Ipv4Addr::new(fa[0], fa[1], fa[2], fa[3]).to_string(),
            2 if fa.len() >= 16 => {
                let mut oct = [0u8; 16];
                oct.copy_from_slice(&fa[..16]);
                Ipv6Addr::from(oct).to_string()
            }
            _ => {
                let mut s = alloc::string::String::new();
                for b in &self.address {
                    use alloc::fmt::Write as _;
                    let _ = write!(s, "{:02x}", b);
                }
                s
            }
        }
    }

    /// Whether this ECS is the "no ECS" convention (family 0).
    pub fn is_none(&self) -> bool {
        self.family == 0 || self.source_prefix == 0
    }

    /// Parse from wire option data.
    pub fn parse(data: &[u8]) -> Result<Ecs> {
        if data.len() < 4 {
            return Err(Error::wire("ECS option too short"));
        }
        let family = u16::from_be_bytes([data[0], data[1]]);
        let source_prefix = data[2];
        let scope_prefix = data[3];
        let max_prefix = match family {
            1 => 32,
            2 => 128,
            _ => return Err(Error::wire("ECS unknown family")),
        };
        if source_prefix > max_prefix || scope_prefix > max_prefix {
            return Err(Error::wire("ECS prefix out of range"));
        }
        let addr_len = (usize::from(source_prefix)).div_ceil(8);
        if data.len() != 4 + addr_len {
            return Err(Error::wire("ECS address length mismatch"));
        }
        // The trailing bits beyond the prefix must be zero (canonical).
        let addr = &data[4..];
        if let Some(&last) = addr.last() {
            let valid_bits = source_prefix % 8;
            if valid_bits != 0 {
                let mask_byte = 0xffu8 << (8 - valid_bits);
                if last & !mask_byte != 0 {
                    return Err(Error::wire("ECS non-canonical address"));
                }
            }
        }
        Ok(Ecs {
            family,
            source_prefix,
            scope_prefix,
            address: addr.to_vec(),
        })
    }

    /// Serialize to wire option data.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.address.len());
        v.extend_from_slice(&self.family.to_be_bytes());
        v.push(self.source_prefix);
        v.push(self.scope_prefix);
        v.extend_from_slice(&self.address);
        v
    }
}

/// Mask `addr` to `prefix` bits and return `ceil(prefix/8)` bytes.
fn mask(addr: &[u8], prefix: u8) -> Vec<u8> {
    let n = (usize::from(prefix)).div_ceil(8);
    let mut out = vec![0u8; n];
    out.copy_from_slice(&addr[..n]);
    if prefix % 8 != 0 && n > 0 {
        let valid = prefix % 8;
        let mask_byte = 0xffu8 << (8 - valid);
        out[n - 1] &= mask_byte;
    }
    out
}

/// The EDNS(0) pseudo-record carried in the additional section.
#[derive(Clone, PartialEq, Eq)]
pub struct Edns {
    /// The UDP payload size the sender can receive (≥ 512; 1232 is the
    /// recommended modern default).
    pub udp_payload_size: u16,
    /// The high 8 bits of the extended RCODE (RFC 6891 §6.1.3).
    pub ext_rcode: u8,
    /// EDNS version (must be 0 for this implementation).
    pub version: u8,
    /// The DNSSEC OK (DO) bit.
    pub dnssec_ok: bool,
    /// The EDNS options.
    pub options: Vec<EdnsOption>,
}

impl fmt::Debug for Edns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EDNS udp={} ver={} do={} {:?}",
            self.udp_payload_size, self.version, self.dnssec_ok, self.options
        )
    }
}

impl Edns {
    /// A minimal EDNS header with the given UDP payload size.
    pub fn new(udp_payload_size: u16) -> Self {
        Self {
            udp_payload_size,
            ext_rcode: 0,
            version: 0,
            dnssec_ok: false,
            options: Vec::new(),
        }
    }

    /// The full 12-bit response code (extended rcode in the high nibble).
    pub fn extended_rcode(&self, base: u8) -> u16 {
        ((self.ext_rcode as u16) << 4) | (base & 0x0f) as u16
    }

    /// Parse the EDNS fields from a raw OPT record.
    ///
    /// * `class` — the 2-byte field (UDP payload size).
    /// * `ttl` — the 4-byte TTL field (ext rcode | version | flags).
    /// * `rdata` — the option payload.
    pub fn parse(class: u16, ttl: u32, rdata: &[u8]) -> Result<Edns> {
        let ext_rcode = ((ttl >> 24) & 0xff) as u8;
        let version = ((ttl >> 16) & 0xff) as u8;
        let dnssec_ok = (ttl & 0x8000) != 0;
        let options = parse_options(rdata)?;
        Ok(Edns {
            udp_payload_size: class,
            ext_rcode,
            version,
            dnssec_ok,
            options,
        })
    }

    /// The wire TTL field value.
    pub fn ttl_field(&self) -> u32 {
        let mut ttl = ((self.ext_rcode as u32) << 24) | ((self.version as u32) << 16);
        if self.dnssec_ok {
            ttl |= 0x8000;
        }
        ttl
    }

    /// The wire option payload.
    pub fn options_wire(&self) -> Vec<u8> {
        let mut v = Vec::new();
        for opt in &self.options {
            let mut data = Vec::new();
            match opt {
                EdnsOption::Ecs(e) => data = e.to_wire(),
                EdnsOption::Cookie { client, server } => {
                    data.extend_from_slice(client);
                    data.extend_from_slice(server);
                }
                EdnsOption::TcpKeepalive(Some(t)) => data.extend_from_slice(&t.to_be_bytes()),
                EdnsOption::TcpKeepalive(None) => {}
                EdnsOption::Padding(_) => {}
                EdnsOption::KeyTag(tags) => {
                    for t in tags {
                        data.extend_from_slice(&t.to_be_bytes());
                    }
                }
                EdnsOption::Nsid(v) => data.extend_from_slice(v),
                EdnsOption::Ede { info_code, extra } => {
                    data.extend_from_slice(&info_code.to_be_bytes());
                    data.extend_from_slice(extra);
                }
                EdnsOption::Unknown { data: d, .. } => data.extend_from_slice(d),
            }
            v.extend_from_slice(&opt.code().to_be_bytes());
            v.extend_from_slice(&(data.len() as u16).to_be_bytes());
            v.extend_from_slice(&data);
        }
        v
    }

    /// Convenience accessor: the ECS option, if any.
    pub fn ecs(&self) -> Option<&Ecs> {
        self.options.iter().find_map(|o| match o {
            EdnsOption::Ecs(e) => Some(e),
            _ => None,
        })
    }

    /// Convenience accessor: the client cookie, if present.
    pub fn client_cookie(&self) -> Option<[u8; 8]> {
        self.options.iter().find_map(|o| match o {
            EdnsOption::Cookie { client, .. } => Some(*client),
            _ => None,
        })
    }
}

/// Parse the option list from an OPT RDATA payload.
pub fn parse_options(rdata: &[u8]) -> Result<Vec<EdnsOption>> {
    let mut options = Vec::new();
    let mut pos = 0;
    while pos < rdata.len() {
        if pos + 4 > rdata.len() {
            return Err(Error::wire("EDNS option header truncated"));
        }
        let code = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        pos += 4;
        if pos + len > rdata.len() {
            return Err(Error::wire("EDNS option data truncated"));
        }
        let data = &rdata[pos..pos + len];
        let option = match code {
            opt::ECS => EdnsOption::Ecs(Ecs::parse(data)?),
            opt::COOKIE => {
                if data.len() < 8 {
                    return Err(Error::wire("cookie option too short"));
                }
                let mut client = [0u8; 8];
                client.copy_from_slice(&data[..8]);
                EdnsOption::Cookie {
                    client,
                    server: data[8..].to_vec(),
                }
            }
            opt::KEEPALIVE => {
                if data.is_empty() {
                    EdnsOption::TcpKeepalive(None)
                } else if data.len() == 2 {
                    EdnsOption::TcpKeepalive(Some(u16::from_be_bytes([data[0], data[1]])))
                } else {
                    return Err(Error::wire("keepalive option malformed"));
                }
            }
            opt::PADDING => EdnsOption::Padding(data.len() as u16),
            opt::KEY_TAG => {
                if data.len() % 2 != 0 {
                    return Err(Error::wire("key-tag option malformed"));
                }
                let tags = data
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                EdnsOption::KeyTag(tags)
            }
            opt::NSID => EdnsOption::Nsid(data.to_vec()),
            opt::EDE => {
                if data.len() < 2 {
                    return Err(Error::wire("EDE option too short"));
                }
                EdnsOption::Ede {
                    info_code: u16::from_be_bytes([data[0], data[1]]),
                    extra: data[2..].to_vec(),
                }
            }
            _ => EdnsOption::Unknown {
                code,
                data: data.to_vec(),
            },
        };
        options.push(option);
        pos += len;
    }
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecs_ipv4_roundtrip() {
        let ecs = Ecs::ipv4(Ipv4Addr::new(192, 0, 2, 7), 24).unwrap();
        let wire = ecs.to_wire();
        assert_eq!(wire, [0, 1, 24, 0, 192, 0, 2]);
        let parsed = Ecs::parse(&wire).unwrap();
        assert_eq!(parsed, ecs);
        assert_eq!(parsed.full_address(), vec![192, 0, 2, 0]);
    }

    #[test]
    fn ecs_ipv6_roundtrip() {
        let ip = Ipv6Addr::from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let ecs = Ecs::ipv6(ip, 56).unwrap();
        let wire = ecs.to_wire();
        let parsed = Ecs::parse(&wire).unwrap();
        assert_eq!(parsed, ecs);
    }

    #[test]
    fn ecs_rejects_noncanonical() {
        // prefix 24 means the 4th byte must be zero.
        let wire = [0, 1, 24, 0, 192, 0, 2, 1];
        assert!(Ecs::parse(&wire).is_err());
    }

    #[test]
    fn edns_options_roundtrip() {
        let edns = Edns {
            udp_payload_size: 1232,
            ext_rcode: 0,
            version: 0,
            dnssec_ok: true,
            options: vec![
                EdnsOption::Ecs(Ecs::ipv4(Ipv4Addr::new(10, 0, 0, 1), 16).unwrap()),
                EdnsOption::Cookie {
                    client: [1, 2, 3, 4, 5, 6, 7, 8],
                    server: vec![9, 10],
                },
                EdnsOption::KeyTag(vec![1, 2, 3]),
                EdnsOption::TcpKeepalive(Some(30)),
            ],
        };
        let wire = edns.options_wire();
        let parsed = parse_options(&wire).unwrap();
        assert_eq!(parsed, edns.options);
        assert_eq!(edns.ttl_field() & 0x8000, 0x8000);
        let re = Edns::parse(1232, edns.ttl_field(), &wire).unwrap();
        assert_eq!(re, edns);
    }

    #[test]
    fn edns_rejects_truncation() {
        assert!(parse_options(&[0, 8, 0, 5, 1]).is_err());
    }
}
