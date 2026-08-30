//! DNS wire constants: record types, classes, opcodes, response codes.

use core::fmt;

/// A DNS resource-record type (RFC 1035 and friends).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RrType(pub u16);

impl RrType {
    pub const A: RrType = RrType(1);
    pub const NS: RrType = RrType(2);
    pub const MD: RrType = RrType(3);
    pub const MF: RrType = RrType(4);
    pub const CNAME: RrType = RrType(5);
    pub const SOA: RrType = RrType(6);
    pub const MB: RrType = RrType(7);
    pub const MG: RrType = RrType(8);
    pub const MR: RrType = RrType(9);
    pub const NULL: RrType = RrType(10);
    pub const WKS: RrType = RrType(11);
    pub const PTR: RrType = RrType(12);
    pub const HINFO: RrType = RrType(13);
    pub const MINFO: RrType = RrType(14);
    pub const MX: RrType = RrType(15);
    pub const TXT: RrType = RrType(16);
    pub const RP: RrType = RrType(17);
    pub const AFSDB: RrType = RrType(18);
    pub const SIG: RrType = RrType(24);
    pub const KEY: RrType = RrType(25);
    pub const AAAA: RrType = RrType(28);
    pub const LOC: RrType = RrType(29);
    pub const SRV: RrType = RrType(33);
    pub const NAPTR: RrType = RrType(35);
    pub const KX: RrType = RrType(36);
    pub const CERT: RrType = RrType(37);
    pub const DNAME: RrType = RrType(39);
    pub const OPT: RrType = RrType(41);
    pub const APL: RrType = RrType(42);
    pub const DS: RrType = RrType(43);
    pub const SSHFP: RrType = RrType(44);
    pub const IPSECKEY: RrType = RrType(45);
    pub const RRSIG: RrType = RrType(46);
    pub const NSEC: RrType = RrType(47);
    pub const DNSKEY: RrType = RrType(48);
    pub const DHCID: RrType = RrType(49);
    pub const NSEC3: RrType = RrType(50);
    pub const NSEC3PARAM: RrType = RrType(51);
    pub const TLSA: RrType = RrType(52);
    pub const SMIMEA: RrType = RrType(53);
    pub const HIP: RrType = RrType(55);
    pub const CDS: RrType = RrType(59);
    pub const CDNSKEY: RrType = RrType(60);
    pub const OPENPGPKEY: RrType = RrType(61);
    pub const CSYNC: RrType = RrType(62);
    pub const ZONEMD: RrType = RrType(63);
    pub const SVCB: RrType = RrType(64);
    pub const HTTPS: RrType = RrType(65);
    pub const SPF: RrType = RrType(99);
    pub const TKEY: RrType = RrType(249);
    pub const TSIG: RrType = RrType(250);
    pub const IXFR: RrType = RrType(251);
    pub const AXFR: RrType = RrType(252);
    pub const ANY: RrType = RrType(255);
    pub const URI: RrType = RrType(256);
    pub const CAA: RrType = RrType(257);
    pub const TA: RrType = RrType(32768);
    pub const DLV: RrType = RrType(32769);

    /// The raw wire value.
    #[inline]
    pub fn to_u16(self) -> u16 {
        self.0
    }

    /// Whether this type is a known, registry-assigned type.
    pub fn is_known(self) -> bool {
        matches!(self.0, 1..=65 | 99..=109 | 249..=260 | 32768..=32769)
    }

    /// Whether the type can ever appear in a positive answer set (i.e. it
    /// is not a meta/pseudo type).
    pub fn is_rrset_type(self) -> bool {
        !matches!(
            self.0,
            41 /* OPT */ | 250 /* TSIG */ | 249 /* TKEY */ | 251 /* IXFR */ | 252 /* AXFR */ | 255 /* ANY */
        )
    }

    /// Whether records of this type hold a domain name in RDATA that RFC
    /// 1035 / 6672 permit to use name compression on the wire.
    pub fn permits_compression(self) -> bool {
        matches!(self.0, 2 | 5 | 6 | 12 | 15 | 39) // NS CNAME SOA PTR MX DNAME
    }

    /// Human-readable name; falls back to `TYPE###`.
    pub fn as_str(self) -> &'static str {
        match self.0 {
            1 => "A",
            2 => "NS",
            3 => "MD",
            4 => "MF",
            5 => "CNAME",
            6 => "SOA",
            7 => "MB",
            8 => "MG",
            9 => "MR",
            10 => "NULL",
            11 => "WKS",
            12 => "PTR",
            13 => "HINFO",
            14 => "MINFO",
            15 => "MX",
            16 => "TXT",
            17 => "RP",
            18 => "AFSDB",
            24 => "SIG",
            25 => "KEY",
            28 => "AAAA",
            29 => "LOC",
            33 => "SRV",
            35 => "NAPTR",
            36 => "KX",
            37 => "CERT",
            39 => "DNAME",
            41 => "OPT",
            42 => "APL",
            43 => "DS",
            44 => "SSHFP",
            45 => "IPSECKEY",
            46 => "RRSIG",
            47 => "NSEC",
            48 => "DNSKEY",
            49 => "DHCID",
            50 => "NSEC3",
            51 => "NSEC3PARAM",
            52 => "TLSA",
            53 => "SMIMEA",
            55 => "HIP",
            59 => "CDS",
            60 => "CDNSKEY",
            61 => "OPENPGPKEY",
            62 => "CSYNC",
            63 => "ZONEMD",
            64 => "SVCB",
            65 => "HTTPS",
            99 => "SPF",
            249 => "TKEY",
            250 => "TSIG",
            251 => "IXFR",
            252 => "AXFR",
            255 => "ANY",
            256 => "URI",
            257 => "CAA",
            32768 => "TA",
            32769 => "DLV",
            _ => "TYPE",
        }
    }
}

impl From<u16> for RrType {
    #[inline]
    fn from(v: u16) -> Self {
        RrType(v)
    }
}

impl fmt::Display for RrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 <= 32769 && !self.is_known() && self.as_str() == "TYPE" {
            write!(f, "TYPE{}", self.0)
        } else {
            write!(f, "{}", self.as_str())
        }
    }
}

/// A DNS class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RrClass(pub u16);

impl RrClass {
    pub const IN: RrClass = RrClass(1);
    pub const CS: RrClass = RrClass(2);
    pub const CH: RrClass = RrClass(3);
    pub const HS: RrClass = RrClass(4);
    pub const NONE: RrClass = RrClass(254);
    pub const ANY: RrClass = RrClass(255);

    #[inline]
    pub fn to_u16(self) -> u16 {
        self.0
    }
}

impl From<u16> for RrClass {
    #[inline]
    fn from(v: u16) -> Self {
        RrClass(v)
    }
}

impl fmt::Display for RrClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "IN"),
            2 => write!(f, "CS"),
            3 => write!(f, "CH"),
            4 => write!(f, "HS"),
            254 => write!(f, "NONE"),
            255 => write!(f, "ANY"),
            _ => write!(f, "CLASS{}", self.0),
        }
    }
}

/// A DNS opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Opcode(pub u8);

impl Opcode {
    pub const QUERY: Opcode = Opcode(0);
    pub const IQUERY: Opcode = Opcode(1);
    pub const STATUS: Opcode = Opcode(2);
    pub const NOTIFY: Opcode = Opcode(4);
    pub const UPDATE: Opcode = Opcode(5);

    #[inline]
    pub fn to_u8(self) -> u8 {
        self.0
    }
}

impl From<u8> for Opcode {
    #[inline]
    fn from(v: u8) -> Self {
        Opcode(v & 0x0f)
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => write!(f, "QUERY"),
            1 => write!(f, "IQUERY"),
            2 => write!(f, "STATUS"),
            4 => write!(f, "NOTIFY"),
            5 => write!(f, "UPDATE"),
            _ => write!(f, "OPCODE{}", self.0),
        }
    }
}

/// A DNS response code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rcode(pub u8);

impl Rcode {
    pub const NOERROR: Rcode = Rcode(0);
    pub const FORMERR: Rcode = Rcode(1);
    pub const SERVFAIL: Rcode = Rcode(2);
    pub const NXDOMAIN: Rcode = Rcode(3);
    pub const NOTIMP: Rcode = Rcode(4);
    pub const REFUSED: Rcode = Rcode(5);
    pub const YXDOMAIN: Rcode = Rcode(6);
    pub const YXRRSET: Rcode = Rcode(7);
    pub const NXRRSET: Rcode = Rcode(8);
    pub const NOTAUTH: Rcode = Rcode(9);
    pub const NOTZONE: Rcode = Rcode(10);
    /// Extended error from EDNS(0) BADVERS.
    pub const BADVERS: Rcode = Rcode(16);

    #[inline]
    pub fn to_u8(self) -> u8 {
        self.0
    }

    /// Whether this code marks a name that does not exist.
    #[inline]
    pub fn is_nxdomain(self) -> bool {
        self.0 == 3
    }

    /// Whether this code marks a non-existent data (NODATA) style answer.
    #[inline]
    pub fn is_noerror(self) -> bool {
        self.0 == 0
    }

    /// Whether this is a server-side failure code.
    #[inline]
    pub fn is_failure(self) -> bool {
        matches!(self.0, 1 | 2 | 4 | 5 | 9 | 10)
    }
}

impl From<u8> for Rcode {
    #[inline]
    fn from(v: u8) -> Self {
        Rcode(v)
    }
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => write!(f, "NOERROR"),
            1 => write!(f, "FORMERR"),
            2 => write!(f, "SERVFAIL"),
            3 => write!(f, "NXDOMAIN"),
            4 => write!(f, "NOTIMP"),
            5 => write!(f, "REFUSED"),
            6 => write!(f, "YXDOMAIN"),
            7 => write!(f, "YXRRSET"),
            8 => write!(f, "NXRRSET"),
            9 => write!(f, "NOTAUTH"),
            10 => write!(f, "NOTZONE"),
            _ => write!(f, "RCODE{}", self.0),
        }
    }
}

/// DNSSEC algorithm numbers (RFC 4034 §A.1 and friends).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DnssecAlgorithm(pub u8);

impl DnssecAlgorithm {
    pub const RSAMD5: DnssecAlgorithm = DnssecAlgorithm(1);
    pub const DH: DnssecAlgorithm = DnssecAlgorithm(2);
    pub const DSA: DnssecAlgorithm = DnssecAlgorithm(3);
    pub const ECC: DnssecAlgorithm = DnssecAlgorithm(4);
    pub const RSASHA1: DnssecAlgorithm = DnssecAlgorithm(5);
    pub const DSANSEC3SHA1: DnssecAlgorithm = DnssecAlgorithm(6);
    pub const RSASHA1NSEC3SHA1: DnssecAlgorithm = DnssecAlgorithm(7);
    pub const RSASHA256: DnssecAlgorithm = DnssecAlgorithm(8);
    pub const RSASHA512: DnssecAlgorithm = DnssecAlgorithm(10);
    pub const ECCGOST: DnssecAlgorithm = DnssecAlgorithm(12);
    pub const ECDSAP256SHA256: DnssecAlgorithm = DnssecAlgorithm(13);
    pub const ECDSAP384SHA384: DnssecAlgorithm = DnssecAlgorithm(14);
    pub const ED25519: DnssecAlgorithm = DnssecAlgorithm(15);
    pub const ED448: DnssecAlgorithm = DnssecAlgorithm(16);
    pub const INDIRECT: DnssecAlgorithm = DnssecAlgorithm(252);
    pub const PRIVATEDNS: DnssecAlgorithm = DnssecAlgorithm(253);
    pub const PRIVATEOID: DnssecAlgorithm = DnssecAlgorithm(254);

    #[inline]
    pub fn to_u8(self) -> u8 {
        self.0
    }

    /// Whether this implementation can verify signatures for this
    /// algorithm. RSASHA256 (8) is implemented; the SHA-1 and RSA-MD5
    /// family is deliberately rejected as deprecated; ECDSA / EdDSA are
    /// recognized but not yet verified by this build.
    pub fn supported(self) -> bool {
        matches!(self.0, 8)
    }

    pub fn as_str(self) -> &'static str {
        match self.0 {
            1 => "RSAMD5",
            2 => "DH",
            3 => "DSA",
            4 => "ECC",
            5 => "RSASHA1",
            6 => "DSA-NSEC3-SHA1",
            7 => "RSASHA1-NSEC3-SHA1",
            8 => "RSASHA256",
            10 => "RSASHA512",
            12 => "ECC-GOST",
            13 => "ECDSA-P256-SHA256",
            14 => "ECDSA-P384-SHA384",
            15 => "ED25519",
            16 => "ED448",
            252 => "INDIRECT",
            253 => "PRIVATE-DNS",
            254 => "PRIVATE-OID",
            _ => "UNKNOWN",
        }
    }
}

/// DNSSEC digest types for DS records (RFC 4034 §5.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DsDigestType(pub u8);

impl DsDigestType {
    pub const SHA1: DsDigestType = DsDigestType(1);
    pub const SHA256: DsDigestType = DsDigestType(2);
    pub const SHA384: DsDigestType = DsDigestType(4);
    pub const GOST: DsDigestType = DsDigestType(3);

    #[inline]
    pub fn to_u8(self) -> u8 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_display() {
        assert_eq!(RrType::A.as_str(), "A");
        assert_eq!(RrType(1234).to_string(), "TYPE1234");
        assert_eq!(RrType::AAAA.to_string(), "AAAA");
    }

    #[test]
    fn class_roundtrip() {
        assert_eq!(RrClass::IN.to_u16(), 1);
        assert_eq!(RrClass::from(1), RrClass::IN);
    }
}
