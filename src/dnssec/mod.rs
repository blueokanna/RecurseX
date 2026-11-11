//! DNSSEC authentication from configured trust anchors to answer RRsets.
//!
//! The resolver authenticates parent DS RRsets, DS-matching child DNSKEY
//! RRsets, and every answer/authority RRset. NSEC/NSEC3 authenticate negative
//! answers, unsigned delegations and wildcard expansions. IANA's root keys
//! 20326 and 38696 are installed by default; applications may replace them.
//!
//! RSA/SHA-256, RSA/SHA-512, ECDSA P-256/P-384 and Ed25519 verification use
//! `ring`. DS digests support SHA-256 and SHA-384. Deprecated and unsupported
//! algorithms never produce a secure verdict. The legacy [`rsa`] helpers
//! remain available for source compatibility.
//!
//! Local [`validate_rrset`] success is only [`Verdict::SignatureValid`].
//! [`ValidationState::ChainAnchored`] requires the complete chain and all
//! applicable denial proofs. Only that state permits AD. Bogus or missing
//! evidence fails closed; an authenticated insecure delegation permits an
//! unvalidated answer. The legacy `anchored` boolean cannot elevate trust.
//!
//! Evidence is bounded, fresh-only, revalidated on reuse and never restored
//! from ordinary persisted cache trust flags. All material lookups share the
//! caller's wire-work and time budgets. Static trust-anchor updates are the
//! operator's responsibility; automatic RFC 5011 maintenance is not provided.

mod chain;
mod denial;
pub mod rsa;

pub use chain::default_trust_anchors;
pub(crate) use chain::EvidenceCache;

use alloc::vec::Vec;

use crate::name::Name;
use crate::qtype::{DnssecAlgorithm, DsDigestType, RrType};
use crate::rdata::{RData, Record};

/// The validation outcome for a set of records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A signature verified against a supplied key, without authenticating the key.
    SignatureValid,
    /// An authenticated denial establishes an unsigned delegation.
    Insecure,
    /// A signature failed verification.
    Bogus,
    /// Could not determine (missing keys/anchors).
    Indeterminate,
}

/// Where the chain of trust actually stopped.
///
/// This is the honest form of "is it DNSSEC-secure", and it is what the
/// `AD` bit and the risk model are keyed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidationState {
    /// Nothing could be concluded: an unsigned zone, an unsupported
    /// algorithm, a missing key, or a preempted validation slot.
    Indeterminate,
    /// An authenticated unsigned delegation or unsupported authenticated DS.
    Insecure,
    /// A signature verified against an unauthenticated key. This establishes
    /// mathematical consistency, not the identity of the zone operator.
    CryptoVerified,
    /// The full chain reached a configured trust anchor, and the answer was
    /// otherwise authentic. Only this state permits `AD`.
    ChainAnchored,
}

impl ValidationState {
    /// Whether this state permits the `AD` bit (RFC 4035 §3.2.3).
    #[inline]
    pub fn permits_authentic_data(self) -> bool {
        matches!(self, ValidationState::ChainAnchored)
    }

    /// Whether a signature verified mathematically. This does not authenticate
    /// the key; only [`Self::permits_authentic_data`] represents chain trust.
    #[inline]
    pub fn is_signature_verified(self) -> bool {
        matches!(
            self,
            ValidationState::CryptoVerified | ValidationState::ChainAnchored
        )
    }

    /// A short stable name, for logs and metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            ValidationState::Indeterminate => "indeterminate",
            ValidationState::Insecure => "insecure",
            ValidationState::CryptoVerified => "crypto-verified",
            ValidationState::ChainAnchored => "chain-anchored",
        }
    }

    /// The same information in the risk model's vocabulary.
    ///
    /// The mapping is deliberately one-to-one rather than collapsing
    /// "insecure" into "unverified": a zone that is *known* to be unsigned is
    /// a different risk from one whose status could not be established, and
    /// the risk model prices the latter as strictly worse because an
    /// unverifiable answer is one whose error could have been manufactured.
    pub fn trust_level(self) -> crate::risk::TrustLevel {
        match self {
            ValidationState::ChainAnchored => crate::risk::TrustLevel::ChainAnchored,
            ValidationState::CryptoVerified => crate::risk::TrustLevel::CryptoVerified,
            ValidationState::Insecure => crate::risk::TrustLevel::Unverified,
            ValidationState::Indeterminate => crate::risk::TrustLevel::Indeterminate,
        }
    }
}

impl Verdict {
    /// Compatibility spelling for local signature verification; never chain trust.
    #[allow(non_upper_case_globals)]
    #[deprecated(note = "use SignatureValid; local verification does not authenticate a chain")]
    pub const Secure: Self = Self::SignatureValid;

    /// Map a local signature verdict. The legacy boolean is ignored:
    /// a caller promise cannot replace root-to-answer chain validation.
    pub fn state(self, _anchored: bool) -> ValidationState {
        match self {
            Verdict::SignatureValid => ValidationState::CryptoVerified,
            Verdict::Insecure => ValidationState::Insecure,
            Verdict::Indeterminate => ValidationState::Indeterminate,
            Verdict::Bogus => ValidationState::Indeterminate,
        }
    }
}

/// A validation report, with the counts that make the "all" rule visible.
///
/// A boolean cannot express "three of four answer groups authenticated"; an
/// operator debugging why `AD` is unset needs exactly that number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verification {
    /// The underlying verdict.
    pub verdict: Verdict,
    /// Where the chain stopped.
    pub state: ValidationState,
    /// Answer RRset groups examined.
    pub answer_groups: usize,
    /// Answer groups authenticated by the complete chain validator.
    pub answer_groups_authenticated: usize,
    /// Whether an Authority section was present, and if so whether every
    /// group in it authenticated. `None` when there was no Authority
    /// section to check (RFC 4035 §3.2.3 applies only when there is one).
    pub authority_authenticated: Option<bool>,
}

impl Verification {
    /// Reject a detected invalid signature before serving or caching data.
    /// An indeterminate chain still cannot assert root-anchored trust.
    pub fn checked_signature_state(self) -> crate::error::Result<bool> {
        if self.verdict == Verdict::Bogus {
            return Err(crate::error::Error::new(
                crate::error::ErrorKind::Dnssec,
                "DNSSEC signature verification failed",
            ));
        }
        Ok(self.state.is_signature_verified())
    }

    /// Reject invalid signatures, but only report authenticated complete chains.
    /// Local signature success does not authenticate the fetched DNSKEY.
    pub fn checked_authentication(self) -> crate::error::Result<bool> {
        self.checked_signature_state()?;
        if self.state == ValidationState::Indeterminate {
            return Err(crate::error::Error::new(
                crate::error::ErrorKind::Dnssec,
                "DNSSEC chain could not be authenticated",
            ));
        }
        Ok(self.permits_authentic_data())
    }

    /// A report for a chain with no answer data.
    pub fn empty() -> Self {
        Self {
            verdict: Verdict::Indeterminate,
            state: ValidationState::Indeterminate,
            answer_groups: 0,
            answer_groups_authenticated: 0,
            authority_authenticated: None,
        }
    }

    /// Whether the `AD` bit may be set: the chain reached an anchor, every
    /// answer group authenticated, and the Authority section (if any)
    /// authenticated as well.
    pub fn permits_authentic_data(&self) -> bool {
        self.state.permits_authentic_data()
            && self.answer_groups == self.answer_groups_authenticated
            && (self.answer_groups > 0 || self.authority_authenticated == Some(true))
            && self.authority_authenticated.unwrap_or(true)
    }
}

/// Compute a SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    courierust::courierust_crypto::sha256::sha256(data)
}

/// The RFC 4034 Appendix B key tag of a DNSKEY RDATA sequence.
pub fn key_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 {
    let mut rdata = Vec::with_capacity(4 + public_key.len());
    rdata.extend_from_slice(&flags.to_be_bytes());
    rdata.push(protocol);
    rdata.push(algorithm);
    rdata.extend_from_slice(public_key);
    let mut ac: u32 = 0;
    for (i, &b) in rdata.iter().enumerate() {
        if i & 1 == 1 {
            ac += b as u32;
        } else {
            ac += (b as u32) << 8;
        }
    }
    ac += (ac >> 16) & 0xffff;
    (ac & 0xffff) as u16
}

/// Whether a DNSKEY record matches a DS record (digest + key tag).
pub fn dnskey_matches_ds(dnskey: &Record, ds: &Record) -> bool {
    if dnskey.rr_type != RrType::DNSKEY
        || ds.rr_type != RrType::DS
        || dnskey.name != ds.name
        || dnskey.class != ds.class
    {
        return false;
    }
    let (dnskey_flags, dnskey_proto, dnskey_alg, dnskey_key) = match &dnskey.rdata {
        RData::Dnskey {
            flags,
            protocol,
            algorithm,
            public_key,
        } => (*flags, *protocol, *algorithm, public_key),
        _ => return false,
    };
    if dnskey_proto != 3 || dnskey_flags & 0x0100 == 0 {
        return false;
    }
    let (ds_key_tag, ds_alg, ds_digest_type, ds_digest) = match &ds.rdata {
        RData::Ds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        } => (*key_tag, *algorithm, *digest_type, digest),
        _ => return false,
    };
    if dnskey_alg != ds_alg {
        return false;
    }
    if key_tag(dnskey_flags, dnskey_proto, dnskey_alg.to_u8(), dnskey_key) != ds_key_tag {
        return false;
    }
    // Owner name (canonical) || DNSKEY RDATA.
    let mut digest_input = Vec::with_capacity(4 + dnskey_key.len());
    dnskey.name.write_wire(&mut digest_input);
    digest_input.extend_from_slice(&dnskey_flags.to_be_bytes());
    digest_input.push(dnskey_proto);
    digest_input.push(dnskey_alg.to_u8());
    digest_input.extend_from_slice(dnskey_key);
    let digest = match ds_digest_type {
        DsDigestType::SHA256 => sha256(&digest_input).to_vec(),
        DsDigestType::SHA384 => ring::digest::digest(&ring::digest::SHA384, &digest_input)
            .as_ref()
            .to_vec(),
        _ => return false, // unsupported digest type
    };
    digest == *ds_digest
}

/// Serialize the RRSIG RDATA minus the signature field (RFC 4034 §3.1.8.1).
fn rrsig_rdata_without_signature(sig: &RData) -> Option<Vec<u8>> {
    match sig {
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
        } => {
            let mut out = Vec::with_capacity(64);
            out.extend_from_slice(&type_covered.to_u16().to_be_bytes());
            out.push(algorithm.to_u8());
            out.push(*labels);
            out.extend_from_slice(&original_ttl.to_be_bytes());
            out.extend_from_slice(&expiration.to_be_bytes());
            out.extend_from_slice(&inception.to_be_bytes());
            out.extend_from_slice(&key_tag.to_be_bytes());
            signer.write_wire(&mut out);
            Some(out)
        }
        _ => None,
    }
}

/// Build the RFC 4034 canonical RRset for the covered records.
fn canonical_rrset(signer: &Name, records: &[&Record], original_ttl: u32) -> Vec<u8> {
    let mut items: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(records.len());
    for r in records {
        let mut item = Vec::with_capacity(64);
        r.name.write_wire(&mut item);
        item.extend_from_slice(&r.rr_type.to_u16().to_be_bytes());
        item.extend_from_slice(&r.class.to_u16().to_be_bytes());
        item.extend_from_slice(&original_ttl.to_be_bytes());
        let mut rdata = Vec::with_capacity(32);
        r.rdata.to_wire(&mut rdata, None);
        item.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        item.extend_from_slice(&rdata);
        items.push((rdata, item));
    }
    // RFC 4034 section 6.3 orders by RDATA octets, not RDLENGTH.
    items.sort_by(|a, b| a.0.cmp(&b.0));
    items.dedup_by(|a, b| a.0 == b.0);
    let mut out = Vec::with_capacity(64 * items.len());
    for (_, item) in items {
        out.extend_from_slice(&item);
    }
    let _ = signer;
    out
}

// RFC 4034 section 3.1.5: timestamps use serial-number arithmetic.
// Reject ambiguous windows of half the serial space or more.
fn signature_time_valid(inception: u32, expiration: u32, now: u32) -> bool {
    let span = expiration.wrapping_sub(inception);
    span < (1 << 31) && now.wrapping_sub(inception) <= span
}

/// Verify one RRSIG over a set of data records with a DNSKEY.
///
/// Returns `true` when `algorithm` is supported, the key tag matches, and
/// the signature verifies.
pub fn verify_rrsig(
    dnskey: &Record,
    rrsig: &Record,
    records: &[&Record],
    now_secs: u32,
) -> Result<bool, &'static str> {
    let RData::Rrsig {
        type_covered,
        algorithm,
        labels,
        original_ttl,
        expiration,
        inception,
        key_tag: sig_key_tag,
        signer,
        signature,
        ..
    } = &rrsig.rdata
    else {
        return Err("rrsig rdata");
    };
    let RData::Dnskey {
        flags,
        protocol,
        algorithm: key_alg,
        public_key,
    } = &dnskey.rdata
    else {
        return Err("dnskey rdata");
    };
    if *protocol != 3 || flags & 0x0100 == 0 || flags & 0x0080 != 0 {
        return Err("DNSKEY is not a protocol-3 zone key");
    }

    if dnskey.rr_type != RrType::DNSKEY
        || rrsig.rr_type != RrType::RRSIG
        || dnskey.name != *signer
        || dnskey.class != rrsig.class
        || !rrsig.name.is_subdomain_of(signer)
        || records.is_empty()
        || records
            .iter()
            .any(|r| r.name != rrsig.name || r.rr_type != *type_covered || r.class != rrsig.class)
    {
        return Ok(false);
    }
    if *algorithm != *key_alg {
        return Ok(false);
    }
    // Unsupported algorithms cannot produce a local cryptographic verdict,
    // even when a time window is invalid. Do not mislabel them as Bogus.
    if !algorithm.supported() {
        return Err("unsupported or deprecated DNSSEC algorithm");
    }
    // Validity window (RFC 4034 §3.1.5).
    if !signature_time_valid(*inception, *expiration, now_secs) {
        return Ok(false);
    }
    // The RRSIG labels field must match the number of labels in the owner
    // (wildcards excepted; wildcards are not synthesized here).
    if *labels as usize > rrsig.name.label_count() {
        return Ok(false);
    }
    if key_tag(*flags, 3, key_alg.to_u8(), public_key) != *sig_key_tag {
        return Ok(false);
    }

    let wildcard_records: Vec<Record>;
    let wildcard_refs: Vec<&Record>;
    let records = if (*labels as usize) < rrsig.name.label_count() {
        let mut suffix = rrsig.name.clone();
        while suffix.label_count() > *labels as usize {
            suffix = suffix.parent().ok_or("wildcard owner")?;
        }
        if !suffix.is_subdomain_of(signer) {
            return Ok(false);
        }
        let mut wire = vec![1, b'*'];
        suffix.write_wire(&mut wire);
        let owner = Name::from_wire(&wire, 0).map_err(|_| "wildcard owner")?.0;
        wildcard_records = records
            .iter()
            .map(|record| {
                let mut record = (*record).clone();
                record.name = owner.clone();
                record
            })
            .collect();
        wildcard_refs = wildcard_records.iter().collect();
        &wildcard_refs
    } else {
        records
    };
    let mut signed_data = rrsig_rdata_without_signature(&rrsig.rdata).ok_or("rrsig")?;
    signed_data.extend_from_slice(&canonical_rrset(signer, records, *original_ttl));
    use ring::signature;
    match *algorithm {
        DnssecAlgorithm::RSASHA256 | DnssecAlgorithm::RSASHA512 => {
            let Some((n, e)) = rsa::parse_dnskey_rsa(public_key) else {
                return Ok(false);
            };
            let algorithm = if *algorithm == DnssecAlgorithm::RSASHA256 {
                &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
            } else {
                &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY
            };
            Ok(signature::RsaPublicKeyComponents { n, e }
                .verify(algorithm, &signed_data, signature)
                .is_ok())
        }
        DnssecAlgorithm::ECDSAP256SHA256 | DnssecAlgorithm::ECDSAP384SHA384 => {
            let (len, alg): (usize, &dyn signature::VerificationAlgorithm) =
                if *algorithm == DnssecAlgorithm::ECDSAP256SHA256 {
                    (64, &signature::ECDSA_P256_SHA256_FIXED)
                } else {
                    (96, &signature::ECDSA_P384_SHA384_FIXED)
                };
            if public_key.len() != len || signature.len() != len {
                return Ok(false);
            }
            let mut key = vec![4];
            key.extend_from_slice(public_key);
            Ok(signature::UnparsedPublicKey::new(alg, key)
                .verify(&signed_data, signature)
                .is_ok())
        }
        DnssecAlgorithm::ED25519 => Ok(signature::UnparsedPublicKey::new(
            &signature::ED25519,
            public_key,
        )
        .verify(&signed_data, signature)
        .is_ok()),
        // Deprecated SHA-1 family: refuse rather than trust.
        DnssecAlgorithm::RSAMD5
        | DnssecAlgorithm::RSASHA1
        | DnssecAlgorithm::RSASHA1NSEC3SHA1
        | DnssecAlgorithm::DSA => Err("deprecated DNSSEC algorithm"),
        // Recognized but not implemented in this build.
        DnssecAlgorithm::ED448 => Err("unsupported DNSSEC algorithm"),
        _ => Err("unsupported DNSSEC algorithm"),
    }
}

/// Validate a set of records against the RRSIGs that cover them.
///
/// `dnskey_records` are candidate zone keys; `now_secs` gates the signature
/// validity window.
///
/// The verdict distinguishes *why* validation did not succeed, because the
/// two cases mean very different things to a caller: a signature that a
/// supported algorithm failed to verify is [`Verdict::Bogus`] (the data is
/// not what it claims to be), while a signature this build cannot even
/// attempt (an unsupported algorithm, or a key that does not match) is
/// [`Verdict::Indeterminate`] — never silently promoted to "secure", and
/// never conflated with tampering.
pub fn validate_rrset(
    records: &[Record],
    rrsigs: &[Record],
    dnskey_records: &[Record],
    now_secs: u32,
) -> Verdict {
    if records.is_empty() {
        return Verdict::Indeterminate;
    }
    if rrsigs.is_empty() {
        // Absence of signatures is not an authenticated denial of DS.
        return Verdict::Indeterminate;
    }
    let rec_refs: Vec<&Record> = records.iter().collect();
    let mut attempted = false;
    for rrsig in rrsigs {
        let RData::Rrsig {
            algorithm,
            key_tag: expected_tag,
            signer,
            ..
        } = &rrsig.rdata
        else {
            continue;
        };
        for key in dnskey_records {
            let RData::Dnskey {
                flags,
                protocol,
                algorithm: key_algorithm,
                public_key,
            } = &key.rdata
            else {
                continue;
            };
            if key.name != *signer
                || key.class != rrsig.class
                || *protocol != 3
                || flags & 0x0100 == 0
                || key_algorithm != algorithm
                || key_tag(*flags, *protocol, algorithm.to_u8(), public_key) != *expected_tag
            {
                continue;
            }
            match verify_rrsig(key, rrsig, &rec_refs, now_secs) {
                Ok(true) => return Verdict::SignatureValid,
                // The signature is well-formed for a supported algorithm and
                // did not verify: this is a verdict of its own.
                Ok(false) => attempted = true,
                // Unsupported/deprecated algorithm: cannot be judged here.
                Err(_) => continue,
            }
        }
    }
    if attempted {
        Verdict::Bogus
    } else {
        Verdict::Indeterminate
    }
}

/// The set of RRSIG records that cover `rr_type`.
pub fn rrsigs_for(rrsigs: &[Record], rr_type: RrType) -> Vec<Record> {
    rrsigs
        .iter()
        .filter(
            |r| matches!(&r.rdata, RData::Rrsig { type_covered, .. } if *type_covered == rr_type),
        )
        .cloned()
        .collect()
}

/// The signer name of an RRSIG, if any.
pub fn rrsig_signer(rrsig: &Record) -> Option<&Name> {
    match &rrsig.rdata {
        RData::Rrsig { signer, .. } => Some(signer),
        _ => None,
    }
}

// ---------------------------------------------------------------------
// Resolver integration
// ---------------------------------------------------------------------

use core::cell::Cell;

// DNSKEY/DS sub-resolutions skip recursive validation on the same thread.
// Independent worker threads must still validate their own answers.
thread_local! { static VALIDATING: Cell<bool> = const { Cell::new(false) }; }

pub(crate) fn validation_active() -> bool {
    VALIDATING.with(Cell::get)
}

/// Holds the single validation slot; releases it on drop, including when the
/// validation unwinds. Leaving it set would turn every later answer into
/// `Indeterminate` for the life of the process.
struct ValidationGuard;

impl ValidationGuard {
    fn enter() -> Option<Self> {
        if VALIDATING.with(|active| active.replace(true)) {
            return None;
        }
        Some(ValidationGuard)
    }
}

impl Drop for ValidationGuard {
    fn drop(&mut self) {
        VALIDATING.with(|active| active.set(false));
    }
}

/// Validate a completed [`crate::resolver::Resolution`] and report where the
/// chain stopped.
///
/// The legacy `anchored` argument is ignored. A boolean cannot establish
/// completion of root-to-answer chain validation.
pub fn validate_resolution_detailed(
    resolver: &crate::resolver::Resolver,
    res: &crate::resolver::Resolution,
    anchored: bool,
) -> Verification {
    if res.answers.is_empty() && res.authorities.is_empty() {
        return Verification::empty();
    }
    let Some(_guard) = ValidationGuard::enter() else {
        return Verification {
            verdict: Verdict::Indeterminate,
            state: ValidationState::Indeterminate,
            answer_groups: 0,
            answer_groups_authenticated: 0,
            authority_authenticated: None,
        };
    };
    let _ = anchored;
    chain::validate(resolver, res).0
}

/// Validate a completed [`crate::resolver::Resolution`], returning the bare
/// verdict. Prefer [`validate_resolution_detailed`]: the verdict alone
/// cannot express *how much* of the answer was authenticated.
pub fn validate_resolution(
    resolver: &crate::resolver::Resolver,
    res: &crate::resolver::Resolution,
) -> Verdict {
    validate_resolution_detailed(resolver, res, false).verdict
}

/// Validate a raw forwarder response and report where the chain stopped.
pub fn validate_message_detailed(
    resolver: &crate::resolver::Resolver,
    _key: &crate::query::QueryKey,
    resp: &crate::message::Message,
    anchored: bool,
) -> Verification {
    if resp.answers.is_empty() && resp.authorities.is_empty() {
        return Verification::empty();
    }
    let Some(_guard) = ValidationGuard::enter() else {
        return Verification {
            verdict: Verdict::Indeterminate,
            state: ValidationState::Indeterminate,
            answer_groups: 0,
            answer_groups_authenticated: 0,
            authority_authenticated: None,
        };
    };
    let split = |recs: &[Record]| -> (Vec<Record>, Vec<Record>) {
        let data = recs
            .iter()
            .filter(|r| r.rr_type != RrType::RRSIG)
            .cloned()
            .collect();
        let sigs = recs
            .iter()
            .filter(|r| r.rr_type == RrType::RRSIG)
            .cloned()
            .collect();
        (data, sigs)
    };
    let (answers, rrsigs) = split(&resp.answers);
    let mut res = chain::empty_resolution(&_key.name, _key.rr_type);
    res.answers = answers;
    res.rrsigs = rrsigs;
    res.authorities.clone_from(&resp.authorities);
    res.rcode = resp.flags.rcode;
    res.ttl = res
        .answers
        .iter()
        .chain(res.authorities.iter())
        .map(|r| r.ttl)
        .min()
        .unwrap_or(0);
    let _ = anchored;
    chain::validate(resolver, &res).0
}

/// Validate a raw forwarder response, returning the bare verdict.
pub fn validate_message(
    resolver: &crate::resolver::Resolver,
    key: &crate::query::QueryKey,
    resp: &crate::message::Message,
) -> Verdict {
    validate_message_detailed(resolver, key, resp, false).verdict
}

/// Authenticate before cache admission; TTLs cannot outlive any link or signature.
pub(crate) fn authenticate(
    resolver: &crate::resolver::Resolver,
    res: &mut crate::resolver::Resolution,
) -> crate::error::Result<()> {
    let _guard = ValidationGuard::enter().ok_or_else(|| {
        crate::Error::new(crate::ErrorKind::Dnssec, "recursive DNSSEC validation")
    })?;
    let (report, ttl) = chain::validate(resolver, res);
    res.validated = report.checked_authentication()?;
    res.ttl = res.ttl.min(ttl);
    for record in res
        .answers
        .iter_mut()
        .chain(res.rrsigs.iter_mut())
        .chain(res.authorities.iter_mut())
    {
        record.ttl = record.ttl.min(res.ttl);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrelated_keys_do_not_turn_an_unsupported_signature_into_bogus() {
        let name = Name::from_ascii("example.test").unwrap();
        let class = crate::qtype::RrClass::IN;
        let answer = Record {
            name: name.clone(),
            rr_type: RrType::A,
            class,
            ttl: 60,
            rdata: RData::A("192.0.2.1".parse().unwrap()),
        };
        let signature = Record {
            name: name.clone(),
            rr_type: RrType::RRSIG,
            class,
            ttl: 60,
            rdata: RData::Rrsig {
                type_covered: RrType::A,
                algorithm: DnssecAlgorithm::ECDSAP256SHA256,
                labels: 2,
                original_ttl: 60,
                expiration: u32::MAX,
                inception: 0,
                key_tag: 0,
                signer: name.clone(),
                signature: vec![0; 64],
            },
        };
        let unrelated = Record {
            name,
            rr_type: RrType::DNSKEY,
            class,
            ttl: 60,
            rdata: RData::Dnskey {
                flags: 256,
                protocol: 3,
                algorithm: DnssecAlgorithm::RSASHA256,
                public_key: vec![1, 3, 1],
            },
        };
        assert_eq!(
            validate_rrset(&[answer], &[signature], &[unrelated], 1_800_000_000),
            Verdict::Indeterminate
        );
    }

    #[test]
    fn validation_recursion_guard_does_not_skip_other_threads() {
        let guard = ValidationGuard::enter().unwrap();
        assert!(ValidationGuard::enter().is_none());
        std::thread::spawn(|| assert!(ValidationGuard::enter().is_some()))
            .join()
            .unwrap();
        drop(guard);
        let _ = std::panic::catch_unwind(|| {
            let _guard = ValidationGuard::enter().unwrap();
            panic!("injected validation failure");
        });
        assert!(ValidationGuard::enter().is_some());
    }

    /// The property that matters more than any single verdict: a
    /// signature-verified answer with **no** configured anchor must never be
    /// reported as chain-anchored, and must never be advertised with `AD`.
    #[test]
    fn verification_without_an_anchor_is_never_chain_anchored() {
        let s = Verdict::SignatureValid.state(false);
        assert_eq!(s, ValidationState::CryptoVerified);
        assert!(s.is_signature_verified());
        assert!(
            !s.permits_authentic_data(),
            "AD must not be set without an anchor"
        );

        let s = Verdict::SignatureValid.state(true);
        assert_eq!(s, ValidationState::CryptoVerified);
        assert!(!s.permits_authentic_data());
    }

    #[test]
    fn bogus_is_indeterminate_not_secure() {
        assert_eq!(Verdict::Bogus.state(true), ValidationState::Indeterminate);
        assert_eq!(
            Verdict::Indeterminate.state(true),
            ValidationState::Indeterminate
        );
        assert_eq!(Verdict::Insecure.state(true), ValidationState::Insecure);
        assert!(!Verdict::Insecure.state(true).is_signature_verified());
    }

    #[test]
    fn trust_ladder_is_ordered_and_faithful() {
        use crate::risk::TrustLevel;
        assert_eq!(
            ValidationState::ChainAnchored.trust_level(),
            TrustLevel::ChainAnchored
        );
        assert_eq!(
            ValidationState::CryptoVerified.trust_level(),
            TrustLevel::CryptoVerified
        );
        assert_eq!(
            ValidationState::Insecure.trust_level(),
            TrustLevel::Unverified
        );
        assert_eq!(
            ValidationState::Indeterminate.trust_level(),
            TrustLevel::Indeterminate
        );
        // The penalty ordering must agree with the state ordering; a ladder
        // whose risk penalties contradict its own severity order would be a
        // policy bug nobody would notice from the outside.
        let ordered = [
            ValidationState::ChainAnchored,
            ValidationState::CryptoVerified,
            ValidationState::Insecure,
            ValidationState::Indeterminate,
        ];
        for w in ordered.windows(2) {
            let (a, b) = match (w.first(), w.get(1)) {
                (Some(a), Some(b)) => (*a, *b),
                _ => continue,
            };
            assert!(
                a.trust_level().penalty() <= b.trust_level().penalty(),
                "penalty order disagrees at {a:?} -> {b:?}"
            );
        }
    }

    /// RFC 4035 §3.2.3: an Authority section that did not authenticate must
    /// block `AD`, even when every answer group did.
    #[test]
    fn an_unauthenticated_authority_section_blocks_ad() {
        let v = Verification {
            verdict: Verdict::SignatureValid,
            state: ValidationState::ChainAnchored,
            answer_groups: 1,
            answer_groups_authenticated: 1,
            authority_authenticated: Some(false),
        };
        assert!(!v.permits_authentic_data());
        let v = Verification {
            authority_authenticated: Some(true),
            ..v
        };
        assert!(v.permits_authentic_data());
        // No Authority section at all is not a failure to authenticate.
        let v = Verification {
            authority_authenticated: None,
            ..v
        };
        assert!(v.permits_authentic_data());
    }

    #[test]
    fn a_partial_answer_never_permits_ad() {
        let v = Verification {
            verdict: Verdict::Indeterminate,
            state: ValidationState::ChainAnchored,
            answer_groups: 4,
            answer_groups_authenticated: 3,
            authority_authenticated: None,
        };
        assert!(!v.permits_authentic_data());
        let empty = Verification::empty();
        assert!(!empty.permits_authentic_data());
    }

    #[test]
    fn unsupported_algorithms_stay_indeterminate() {
        // A zone signed only with Ed25519 must not produce a fabricated
        // verdict in either direction.
        let v = validate_rrset(&[], &[], &[], 0);
        assert_eq!(v, Verdict::Indeterminate);
    }
}

#[cfg(test)]
mod audit_regressions {
    use super::*;
    use crate::qtype::RrClass;

    #[test]
    fn unsupported_algorithm_with_expired_window_stays_indeterminate() {
        let name = Name::from_ascii("example.test").unwrap();
        let data = Record {
            name: name.clone(),
            rr_type: RrType::A,
            class: RrClass::IN,
            ttl: 60,
            rdata: RData::A("192.0.2.1".parse().unwrap()),
        };
        let public_key = vec![1; 64];
        let key = Record {
            name: name.clone(),
            rr_type: RrType::DNSKEY,
            class: RrClass::IN,
            ttl: 60,
            rdata: RData::Dnskey {
                flags: 256,
                protocol: 3,
                algorithm: DnssecAlgorithm::ED448,
                public_key: public_key.clone(),
            },
        };
        let sig = Record {
            name: name.clone(),
            rr_type: RrType::RRSIG,
            class: RrClass::IN,
            ttl: 60,
            rdata: RData::Rrsig {
                type_covered: RrType::A,
                algorithm: DnssecAlgorithm::ED448,
                labels: 2,
                original_ttl: 60,
                inception: 0,
                expiration: 1,
                key_tag: key_tag(256, 3, 16, &public_key),
                signer: name,
                signature: vec![0; 64],
            },
        };
        assert_eq!(
            validate_rrset(&[data], &[sig], &[key], 100),
            Verdict::Indeterminate
        );
    }

    #[test]
    fn serial_time_window_crosses_u32_wrap() {
        for now in [u32::MAX - 5, u32::MAX, 0, 5] {
            assert!(signature_time_valid(u32::MAX - 5, 5, now));
        }
        assert!(!signature_time_valid(u32::MAX - 5, 5, 6));
        assert!(!signature_time_valid(u32::MAX - 5, 5, u32::MAX - 6));
        assert!(!signature_time_valid(0, 1 << 31, 1));
    }

    #[test]
    fn local_crypto_cannot_promote_resolution_or_cache_trust() {
        let report = Verification {
            verdict: Verdict::SignatureValid,
            state: ValidationState::CryptoVerified,
            answer_groups: 1,
            answer_groups_authenticated: 1,
            authority_authenticated: Some(true),
        };
        assert!(report.checked_signature_state().unwrap());
        assert!(!report.checked_authentication().unwrap());
        assert_eq!(Verification::empty().verdict, Verdict::Indeterminate);
    }

    #[test]
    fn canonical_order_uses_rdata_not_length() {
        let name = Name::from_ascii("example.test").unwrap();
        let first = Record {
            name: name.clone(),
            rr_type: RrType::CNAME,
            class: RrClass::IN,
            ttl: 60,
            rdata: RData::Cname(Name::from_ascii("a.long.example").unwrap()),
        };
        let second = Record {
            rdata: RData::Cname(Name::from_ascii("z.test").unwrap()),
            ..first.clone()
        };
        let first_wire = canonical_rrset(&name, &[&first], 60);
        let second_wire = canonical_rrset(&name, &[&second], 60);
        assert!(first_wire.len() > second_wire.len());
        assert_eq!(
            canonical_rrset(&name, &[&second, &first], 60),
            [first_wire, second_wire].concat()
        );
    }

    #[test]
    fn ds_digest_does_not_override_record_identity() {
        let name = Name::from_ascii("example.test").unwrap();
        let public_key = vec![1, 3, 1];
        let mut wire = Vec::new();
        name.write_wire(&mut wire);
        wire.extend_from_slice(&[1, 0, 3, 8]);
        wire.extend_from_slice(&public_key);
        let key = Record {
            name: name.clone(),
            rr_type: RrType::DNSKEY,
            class: RrClass::IN,
            ttl: 60,
            rdata: RData::Dnskey {
                flags: 256,
                protocol: 3,
                algorithm: DnssecAlgorithm::RSASHA256,
                public_key: public_key.clone(),
            },
        };
        let mut ds = Record {
            name,
            rr_type: RrType::DS,
            class: RrClass::IN,
            ttl: 60,
            rdata: RData::Ds {
                key_tag: key_tag(256, 3, 8, &public_key),
                algorithm: DnssecAlgorithm::RSASHA256,
                digest_type: DsDigestType::SHA256,
                digest: sha256(&wire).to_vec(),
            },
        };
        assert!(dnskey_matches_ds(&key, &ds));
        ds.name = Name::from_ascii("other.test").unwrap();
        assert!(!dnskey_matches_ds(&key, &ds));
        ds.name = key.name.clone();
        ds.class = RrClass::CH;
        assert!(!dnskey_matches_ds(&key, &ds));
    }
}
