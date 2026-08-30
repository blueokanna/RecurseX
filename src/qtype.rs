//! DNS wire constants: record types, classes, opcodes, response codes.

use core::fmt;

/// A DNS resource-record type (RFC 1035 and friends).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RrType(pub u16);

impl RrType {
    /// IPv4 host address (RFC 1035).
    pub const A: RrType = RrType(1);
    /// Authoritative name server (RFC 1035).
    pub const NS: RrType = RrType(2);
    /// Mail destination (obsolete, RFC 1035).
    pub const MD: RrType = RrType(3);
    /// Mail forwarder (obsolete, RFC 1035).
    pub const MF: RrType = RrType(4);
    /// Canonical name (RFC 1035).
    pub const CNAME: RrType = RrType(5);
    /// Start of a zone of authority (RFC 1035).
    pub const SOA: RrType = RrType(6);
    /// Mailbox domain name (experimental, RFC 1035).
    pub const MB: RrType = RrType(7);
    /// Mail group member (experimental, RFC 1035).
    pub const MG: RrType = RrType(8);
    /// Mail rename domain name (experimental, RFC 1035).
    pub const MR: RrType = RrType(9);
    /// Null RR (RFC 1035).
    pub const NULL: RrType = RrType(10);
    /// Well-known service description (RFC 1035).
    pub const WKS: RrType = RrType(11);
    /// Domain name pointer (RFC 1035).
    pub const PTR: RrType = RrType(12);
    /// Host information (RFC 1035).
    pub const HINFO: RrType = RrType(13);
    /// Mailbox or mail list information (RFC 1035).
    pub const MINFO: RrType = RrType(14);
    /// Mail exchange (RFC 1035).
    pub const MX: RrType = RrType(15);
    /// Text strings (RFC 1035).
    pub const TXT: RrType = RrType(16);
    /// Responsible person (RFC 1183).
    pub const RP: RrType = RrType(17);
    /// AFS database location (RFC 1183).
    pub const AFSDB: RrType = RrType(18);
    /// Security signature (obsolete, RFC 2535).
    pub const SIG: RrType = RrType(24);
    /// Public key (obsolete, RFC 2535).
    pub const KEY: RrType = RrType(25);
    /// IPv6 host address (RFC 3596).
    pub const AAAA: RrType = RrType(28);
    /// Location information (RFC 1876).
    pub const LOC: RrType = RrType(29);
    /// Service locator (RFC 2782).
    pub const SRV: RrType = RrType(33);
    /// Naming authority pointer (RFC 3403).
    pub const NAPTR: RrType = RrType(35);
    /// Key exchanger (RFC 2230).
    pub const KX: RrType = RrType(36);
    /// Certificate store (RFC 4398).
    pub const CERT: RrType = RrType(37);
    /// Non-terminal DNAME redirection (RFC 6672).
    pub const DNAME: RrType = RrType(39);
    /// EDNS(0) pseudo-record (RFC 6891).
    pub const OPT: RrType = RrType(41);
    /// Address prefix list (RFC 3123).
    pub const APL: RrType = RrType(42);
    /// Delegation signer (RFC 4034).
    pub const DS: RrType = RrType(43);
    /// SSH public key fingerprint (RFC 4255).
    pub const SSHFP: RrType = RrType(44);
    /// IPsec keying material (RFC 4025).
    pub const IPSECKEY: RrType = RrType(45);
    /// DNSSEC signature (RFC 4034).
    pub const RRSIG: RrType = RrType(46);
    /// Next secure record (RFC 4034).
    pub const NSEC: RrType = RrType(47);
    /// DNSSEC public key (RFC 4034).
    pub const DNSKEY: RrType = RrType(48);
    /// DHCP identifier (RFC 4701).
    pub const DHCID: RrType = RrType(49);
    /// Hashed next secure record (RFC 5155).
    pub const NSEC3: RrType = RrType(50);
    /// NSEC3 parameters (RFC 5155).
    pub const NSEC3PARAM: RrType = RrType(51);
    /// TLSA certificate association (RFC 6698).
    pub const TLSA: RrType = RrType(52);
    /// S/MIME certificate association (RFC 8162).
    pub const SMIMEA: RrType = RrType(53);
    /// Host identity protocol (RFC 8005).
    pub const HIP: RrType = RrType(55);
    /// Child DS (RFC 7344).
    pub const CDS: RrType = RrType(59);
    /// Child DNSKEY (RFC 7344).
    pub const CDNSKEY: RrType = RrType(60);
    /// OpenPGP public key (RFC 7929).
    pub const OPENPGPKEY: RrType = RrType(61);
    /// Child-to-parent synchronization (RFC 7477).
    pub const CSYNC: RrType = RrType(62);
    /// Zone message digest (RFC 8976).
    pub const ZONEMD: RrType = RrType(63);
    /// Service binding and parameters (RFC 9460).
    pub const SVCB: RrType = RrType(64);
    /// HTTPS service binding (RFC 9460).
    pub const HTTPS: RrType = RrType(65);
    /// Sender policy framework (RFC 7208).
    pub const SPF: RrType = RrType(99);
    /// Transaction key (RFC 2930).
    pub const TKEY: RrType = RrType(249);
    /// Transaction signature (RFC 8945).
    pub const TSIG: RrType = RrType(250);
    /// Incremental zone transfer (RFC 1995).
    pub const IXFR: RrType = RrType(251);
    /// Authoritative zone transfer (RFC 5936).
    pub const AXFR: RrType = RrType(252);
    /// All cached records (meta type, RFC 8482).
    pub const ANY: RrType = RrType(255);
    /// Uniform resource identifier (RFC 7553).
    pub const URI: RrType = RrType(256);
    /// Certification authority authorization (RFC 8659).
    pub const CAA: RrType = RrType(257);
    /// DNSSEC trust anchor (RFC 4034, private use).
    pub const TA: RrType = RrType(32768);
    /// DNSSEC lookaside validation (RFC 4431).
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
    /// Internet class (RFC 1035).
    pub const IN: RrClass = RrClass(1);
    /// CSNET class (obsolete, RFC 1035).
    pub const CS: RrClass = RrClass(2);
    /// CHAOS class (RFC 1035).
    pub const CH: RrClass = RrClass(3);
    /// Hesiod class (RFC 1035).
    pub const HS: RrClass = RrClass(4);
    /// None class (RFC 2136).
    pub const NONE: RrClass = RrClass(254);
    /// Any class (RFC 1035).
    pub const ANY: RrClass = RrClass(255);

    /// The raw wire value.
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
    /// Standard query (RFC 1035).
    pub const QUERY: Opcode = Opcode(0);
    /// Inverse query (obsolete, RFC 3425).
    pub const IQUERY: Opcode = Opcode(1);
    /// Server status request (RFC 1035).
    pub const STATUS: Opcode = Opcode(2);
    /// Zone change notification (RFC 1996).
    pub const NOTIFY: Opcode = Opcode(4);
    /// Dynamic update (RFC 2136).
    pub const UPDATE: Opcode = Opcode(5);

    /// The raw wire value.
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
    /// No error (RFC 1035).
    pub const NOERROR: Rcode = Rcode(0);
    /// Format error: the server could not parse the query (RFC 1035).
    pub const FORMERR: Rcode = Rcode(1);
    /// Server failure (RFC 1035).
    pub const SERVFAIL: Rcode = Rcode(2);
    /// Name does not exist (RFC 1035).
    pub const NXDOMAIN: Rcode = Rcode(3);
    /// Not implemented (RFC 1035).
    pub const NOTIMP: Rcode = Rcode(4);
    /// Query refused (RFC 1035).
    pub const REFUSED: Rcode = Rcode(5);
    /// Name exists but is outside the zone (RFC 2136).
    pub const YXDOMAIN: Rcode = Rcode(6);
    /// RRset exists but is outside the zone (RFC 2136).
    pub const YXRRSET: Rcode = Rcode(7);
    /// RRset that should exist does not (RFC 2136).
    pub const NXRRSET: Rcode = Rcode(8);
    /// Server is not authoritative for the zone (RFC 2136).
    pub const NOTAUTH: Rcode = Rcode(9);
    /// Name is not in the zone (RFC 2136).
    pub const NOTZONE: Rcode = Rcode(10);
    /// Extended error from EDNS(0) BADVERS.
    pub const BADVERS: Rcode = Rcode(16);

    /// The raw wire value.
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
    /// RSA/MD5 (deprecated, RFC 2536).
    pub const RSAMD5: DnssecAlgorithm = DnssecAlgorithm(1);
    /// Diffie-Hellman (RFC 2539).
    pub const DH: DnssecAlgorithm = DnssecAlgorithm(2);
    /// DSA (RFC 2536).
    pub const DSA: DnssecAlgorithm = DnssecAlgorithm(3);
    /// Elliptic curve (obsolete, RFC 2536).
    pub const ECC: DnssecAlgorithm = DnssecAlgorithm(4);
    /// RSA/SHA-1 (RFC 3110).
    pub const RSASHA1: DnssecAlgorithm = DnssecAlgorithm(5);
    /// DSA-NSEC3-SHA1 (RFC 5155).
    pub const DSANSEC3SHA1: DnssecAlgorithm = DnssecAlgorithm(6);
    /// RSA/SHA-1 with NSEC3 (RFC 5155).
    pub const RSASHA1NSEC3SHA1: DnssecAlgorithm = DnssecAlgorithm(7);
    /// RSA/SHA-256 (RFC 5702).
    pub const RSASHA256: DnssecAlgorithm = DnssecAlgorithm(8);
    /// RSA/SHA-512 (RFC 5702).
    pub const RSASHA512: DnssecAlgorithm = DnssecAlgorithm(10);
    /// GOST R 34.10-2001 (RFC 5933).
    pub const ECCGOST: DnssecAlgorithm = DnssecAlgorithm(12);
    /// ECDSA P-256 with SHA-256 (RFC 6605).
    pub const ECDSAP256SHA256: DnssecAlgorithm = DnssecAlgorithm(13);
    /// ECDSA P-384 with SHA-384 (RFC 6605).
    pub const ECDSAP384SHA384: DnssecAlgorithm = DnssecAlgorithm(14);
    /// Ed25519 (RFC 8080).
    pub const ED25519: DnssecAlgorithm = DnssecAlgorithm(15);
    /// Ed448 (RFC 8080).
    pub const ED448: DnssecAlgorithm = DnssecAlgorithm(16);
    /// Indirect keys (RFC 4034).
    pub const INDIRECT: DnssecAlgorithm = DnssecAlgorithm(252);
    /// Private algorithm, domain name (RFC 4034).
    pub const PRIVATEDNS: DnssecAlgorithm = DnssecAlgorithm(253);
    /// Private algorithm, OID (RFC 4034).
    pub const PRIVATEOID: DnssecAlgorithm = DnssecAlgorithm(254);

    /// The raw wire value.
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

    /// Human-readable algorithm name; falls back to `UNKNOWN`.
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
    /// SHA-1 digest (RFC 4034).
    pub const SHA1: DsDigestType = DsDigestType(1);
    /// SHA-256 digest (RFC 4509).
    pub const SHA256: DsDigestType = DsDigestType(2);
    /// GOST R 34.11-94 digest (RFC 5933).
    pub const GOST: DsDigestType = DsDigestType(3);
    /// SHA-384 digest (RFC 6605).
    pub const SHA384: DsDigestType = DsDigestType(4);

    /// The raw wire value.
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
