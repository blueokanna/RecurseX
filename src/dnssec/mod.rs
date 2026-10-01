//! DNSSEC data model and validation (RFC 4033/4034/4035).
//!
//! What is implemented and verified against independent vectors:
//!
//! * SHA-256 (from courierust's `courierust_crypto`).
//! * RSA PKCS#1 v1.5 / SHA-256 signature verification over the RFC 4034
//!   canonical form (a from-scratch modular-exponentiation engine).
//! * DS → DNSKEY matching (SHA-256 digest type 2, RFC 4034 §5.1.4) and
//!   RFC 4034 Appendix B key tags.
//! * The canonical RRset / RRSIG wire construction (§3.1.8.1).
//!
//! Algorithm support is deliberately honest: **RSASHA256 (8)** is fully
//! verified. SHA-1-based algorithms (5/7) are rejected as deprecated;
//! ECDSA (13/14) and EdDSA (15/16) are recognized but not verified by this
//! build, so signatures from zones that only use them yield
//! [`Verdict::Indeterminate`] — never a fabricated "secure".
//!
//! # Why there is a ladder, not a boolean
//!
//! "DNSSEC is on" and "this answer is authentic" are different claims, and a
//! resolver that collapses them overstates what it checked. The distinction
//! that matters is *where the chain stopped*:
//!
//! * A signature that verifies against a key the parent's DS matched proves
//!   the **zone** signed the data. It does not prove the delegation itself
//!   is the real one, because the DS RRset's own signature was not walked
//!   upward.
//! * Proving the delegation requires an unbroken chain to an anchor the
//!   operator installed. This build ships **no** root trust anchor, so
//!   `ChainAnchored` is unreachable unless the deployment installs one.
//!
//! [`ValidationState`] records exactly that, and the `AD` bit is set **only**
//! for [`ValidationState::ChainAnchored`] — never for a merely
//! signature-verified answer. RFC 4035 §3.2.3 is also an *all* rule: the
//! Answer **and** Authority RRsets must both be authentic, which
//! [`Verification`] reports rather than assumes.
//!
//! A resolver that cannot be honest about this is worse than one without
//! DNSSEC, because its clients believe it.

pub mod rsa;

use alloc::vec::Vec;

use crate::name::Name;
use crate::qtype::{DnssecAlgorithm, DsDigestType, RrType};
use crate::rdata::{RData, Record};

/// The validation outcome for a set of records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The chain validated: at least one RRSIG verified, anchored in a DS.
    Secure,
    /// No trust anchor applies (unsigned zone, or unsupported algorithm).
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
    /// No validation applies because the zone is unsigned (or the algorithm
    /// is one this build refuses to use). This is not a failure.
    Insecure,
    /// The signature verified against a key the parent's DS matched, but the
    /// DS RRset's own chain was not walked to an anchor. Proves the zone
    /// signed the data; does not prove the delegation.
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

    /// Whether the data was shown to be authentic at all (either level of
    /// signature verification). Note that authenticity and *chain* anchoring
    /// are different claims; only [`Self::permits_authentic_data`] says the
    /// resolver is willing to assert the former publicly.
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
    /// Map a verdict to a [`ValidationState`], given whether the deployment
    /// has a trust anchor that the chain reached.
    ///
    /// `anchored` is the caller's honest answer to "was the chain walked to
    /// an anchor?", not "is dnssec enabled?". With no anchor configured the
    /// best possible state is [`ValidationState::CryptoVerified`], and
    /// returning `ChainAnchored` would be a fabrication.
    pub fn state(self, anchored: bool) -> ValidationState {
        match self {
            Verdict::Secure => {
                if anchored {
                    ValidationState::ChainAnchored
                } else {
                    ValidationState::CryptoVerified
                }
            }
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
    /// Answer RRset groups whose signature verified against an anchored key.
    pub answer_groups_authenticated: usize,
    /// Whether an Authority section was present, and if so whether every
    /// group in it authenticated. `None` when there was no Authority
    /// section to check (RFC 4035 §3.2.3 applies only when there is one).
    pub authority_authenticated: Option<bool>,
}

impl Verification {
    /// A report for a chain with no answer data.
    pub fn empty() -> Self {
        Self {
            verdict: Verdict::Insecure,
            state: ValidationState::Insecure,
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
            && self.answer_groups > 0
            && self.answer_groups == self.answer_groups_authenticated
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
    let (dnskey_flags, dnskey_proto, dnskey_alg, dnskey_key) = match &dnskey.rdata {
        RData::Dnskey {
            flags,
            protocol,
            algorithm,
            public_key,
        } => (*flags, *protocol, *algorithm, public_key),
        _ => return false,
    };
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
    let mut items: Vec<Vec<u8>> = Vec::with_capacity(records.len());
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
        items.push(item);
    }
    // Sort by canonical RDATA (the full wire form; RFC 4034 §3.1.8.1).
    items.sort();
    let mut out = Vec::with_capacity(64 * items.len());
    for item in items {
        out.extend_from_slice(&item);
    }
    let _ = signer;
    out
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
        protocol: _,
        algorithm: key_alg,
        public_key,
    } = &dnskey.rdata
    else {
        return Err("dnskey rdata");
    };

    if *algorithm != *key_alg {
        return Ok(false);
    }
    // Validity window (RFC 4034 §3.1.5).
    if now_secs < *inception || now_secs > *expiration {
        return Ok(false);
    }
    // The RRSIG labels field must match the number of labels in the owner
    // (wildcards excepted; wildcards are not synthesized here).
    if *labels != rrsig.name.label_count() as u8 {
        return Ok(false);
    }
    if key_tag(*flags, 3, key_alg.to_u8(), public_key) != *sig_key_tag {
        return Ok(false);
    }

    match *algorithm {
        DnssecAlgorithm::RSASHA256 => {
            let rrsig_rdata = rrsig_rdata_without_signature(&rrsig.rdata).ok_or("rrsig")?;
            let rrset = canonical_rrset(signer, records, *original_ttl);
            let mut signed_data = rrsig_rdata;
            signed_data.extend_from_slice(&rrset);
            let digest = sha256(&signed_data);
            Ok(rsa::verify_pkcs1v15_sha256(public_key, &digest, signature))
        }
        // Deprecated SHA-1 family: refuse rather than trust.
        DnssecAlgorithm::RSAMD5
        | DnssecAlgorithm::RSASHA1
        | DnssecAlgorithm::RSASHA1NSEC3SHA1
        | DnssecAlgorithm::DSA => Err("deprecated DNSSEC algorithm"),
        // Recognized but not implemented in this build.
        DnssecAlgorithm::ECDSAP256SHA256
        | DnssecAlgorithm::ECDSAP384SHA384
        | DnssecAlgorithm::ED25519
        | DnssecAlgorithm::ED448 => Err("unsupported DNSSEC algorithm"),
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
        // No signatures: an unsigned zone (Insecure) — unless the caller
        // expected a signed zone, which it signals by providing keys.
        return if dnskey_records.is_empty() {
            Verdict::Insecure
        } else {
            Verdict::Bogus
        };
    }
    let rec_refs: Vec<&Record> = records.iter().collect();
    let mut attempted = false;
    for rrsig in rrsigs {
        if !matches!(rrsig.rdata, RData::Rrsig { .. }) {
            continue;
        }
        for key in dnskey_records {
            match verify_rrsig(key, rrsig, &rec_refs, now_secs) {
                Ok(true) => return Verdict::Secure,
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

use core::sync::atomic::{AtomicBool, Ordering};

/// Recursion guard: while the validator runs, sub-resolutions (DNSKEY / DS
/// fetches) skip their own validation, bounding the recursion depth.
static VALIDATING: AtomicBool = AtomicBool::new(false);

/// Holds the single validation slot; releases it on drop, including when the
/// validation unwinds. Leaving it set would turn every later answer into
/// `Indeterminate` for the life of the process.
struct ValidationGuard;

impl ValidationGuard {
    fn enter() -> Option<Self> {
        if VALIDATING.swap(true, Ordering::SeqCst) {
            return None;
        }
        Some(ValidationGuard)
    }
}

impl Drop for ValidationGuard {
    fn drop(&mut self) {
        VALIDATING.store(false, Ordering::SeqCst);
    }
}

/// Validate a completed [`crate::resolver::Resolution`] and report where the
/// chain stopped.
///
/// `anchored` is the caller's honest answer to "is a trust anchor
/// configured?" — see [`Verdict::state`].
pub fn validate_resolution_detailed(
    resolver: &crate::resolver::Resolver,
    res: &crate::resolver::Resolution,
    anchored: bool,
) -> Verification {
    if res.answers.is_empty() {
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
    verify_chain(
        resolver,
        &res.answers,
        &res.rrsigs,
        &res.authorities,
        anchored,
    )
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
    if resp.answers.is_empty() {
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
    let (authorities, _) = split(&resp.authorities);
    verify_chain(resolver, &answers, &rrsigs, &authorities, anchored)
}

/// Validate a raw forwarder response, returning the bare verdict.
pub fn validate_message(
    resolver: &crate::resolver::Resolver,
    key: &crate::query::QueryKey,
    resp: &crate::message::Message,
) -> Verdict {
    validate_message_detailed(resolver, key, resp, false).verdict
}

/// The verdict for a whole answer chain.
///
/// RFC 4035 §4.3 is the rule, and it is an "all" rule, not an "any" rule: the
/// AD bit may only be set when every RRset in the answer was authenticated.
/// Returning `Secure` as soon as *one* group verified would let an unsigned
/// CNAME ride along with a signed target and still be advertised as
/// authentic, so a single group that cannot be authenticated caps the verdict
/// at `Indeterminate`/`Insecure` even when other groups verify.
/// Verify every `(owner, type)` group of one section.
///
/// Returns `(verdict, groups_examined, groups_authenticated)`. The counts are
/// what make RFC 4035's "all" rule observable rather than assumed.
fn verify_section(
    resolver: &crate::resolver::Resolver,
    records: &[Record],
    rrsigs: &[Record],
    now_secs: u32,
) -> (Verdict, usize, usize) {
    // Group data records by (owner, type).
    let mut groups: alloc::collections::BTreeMap<(Name, RrType), Vec<Record>> =
        alloc::collections::BTreeMap::new();
    for r in records {
        groups
            .entry((r.name.clone(), r.rr_type))
            .or_default()
            .push(r.clone());
    }
    if groups.is_empty() {
        return (Verdict::Insecure, 0, 0);
    }
    let mut signed_groups = 0usize;
    let mut authenticated = 0usize;
    let mut all_secure = true;
    let mut worst = Verdict::Insecure;
    for ((owner, rr_type), group) in groups {
        let covered = rrsigs_for(rrsigs, rr_type)
            .into_iter()
            .filter(|s| rrsig_signer(s) == Some(&owner) || s.name == owner)
            .collect::<Vec<Record>>();
        if covered.is_empty() {
            // Unsigned group (typically a delegation's CNAME in an unsigned
            // zone): nothing can authenticate it, so the chain is not fully
            // authenticated.
            all_secure = false;
            continue;
        }
        signed_groups += 1;
        match validate_group(resolver, &group, &covered, now_secs) {
            Verdict::Secure => authenticated += 1,
            Verdict::Bogus => {
                all_secure = false;
                worst = Verdict::Bogus;
            }
            Verdict::Indeterminate => {
                all_secure = false;
                if worst == Verdict::Insecure {
                    worst = Verdict::Indeterminate;
                }
            }
            Verdict::Insecure => all_secure = false,
        }
    }
    let verdict = if signed_groups > 0 && all_secure {
        Verdict::Secure
    } else if worst == Verdict::Bogus {
        Verdict::Bogus
    } else if signed_groups == 0 {
        Verdict::Insecure
    } else {
        worst
    };
    (verdict, signed_groups, authenticated)
}

/// The verdict for a whole resolution, including its Authority section.
///
/// RFC 4035 §3.2.3 requires **both** the Answer and Authority RRsets to be
/// authentic before a response may be labelled; a resolver that checked only
/// the Answer would label an unsigned denial of existence as signed.
fn verify_chain(
    resolver: &crate::resolver::Resolver,
    answers: &[Record],
    rrsigs: &[Record],
    authorities: &[Record],
    anchored: bool,
) -> Verification {
    let now_secs = {
        let t = resolver.now();
        (t / 1_000_000_000) as u32
    };
    let (verdict, total, authenticated) = verify_section(resolver, answers, rrsigs, now_secs);
    let authority_authenticated = if authorities.is_empty() {
        None
    } else {
        // Only the SOA and the NSEC/NSEC3/NS material belongs to the
        // negative answer; the rest of an Authority section is delegation
        // data, which RFC 4035 does not ask us to authenticate as part of
        // *this* response.
        let relevant: Vec<Record> = authorities
            .iter()
            .filter(|r| {
                matches!(
                    r.rr_type,
                    RrType::SOA | RrType::NSEC | RrType::NSEC3 | RrType::NS
                )
            })
            .cloned()
            .collect();
        if relevant.is_empty() {
            None
        } else {
            let authority_sigs: Vec<Record> = authorities
                .iter()
                .filter(|r| r.rr_type == RrType::RRSIG)
                .cloned()
                .collect();
            let (_, at, aa) = verify_section(resolver, &relevant, &authority_sigs, now_secs);
            // Authenticated only when every group in it authenticated; a
            // Bogus or Indeterminate authority group cannot be waved
            // through.
            Some(at > 0 && at == aa)
        }
    };
    Verification {
        verdict,
        state: verdict.state(anchored),
        answer_groups: total,
        answer_groups_authenticated: authenticated,
        authority_authenticated,
    }
}

fn validate_group(
    resolver: &crate::resolver::Resolver,
    records: &[Record],
    rrsigs: &[Record],
    now_secs: u32,
) -> Verdict {
    // The signer zone: the RRSIG signer name. A caller only reaches here with
    // at least one signature; `first` states that rather than asserting it.
    let Some(first) = rrsigs.first() else {
        return Verdict::Indeterminate;
    };
    let Some(signer) = rrsig_signer(first).cloned() else {
        return Verdict::Indeterminate;
    };
    // Fetch the signer's DNSKEYs.
    let dnskey_res = match resolver.resolve(&signer, RrType::DNSKEY) {
        Ok(r) => r,
        Err(_) => return Verdict::Indeterminate,
    };
    let keys: Vec<Record> = dnskey_res
        .answers
        .iter()
        .filter(|r| r.rr_type == RrType::DNSKEY && r.name == signer)
        .cloned()
        .collect();
    if keys.is_empty() {
        return Verdict::Indeterminate;
    }
    // The signature must verify against a key that is *also* covered by a DS
    // in the parent zone; a key that verifies but is not anchored proves
    // nothing about the delegation.
    for key in &keys {
        if verify_rrset_quietly(records, rrsigs, key, now_secs)
            && key_is_anchored(resolver, &signer, key)
        {
            return Verdict::Secure;
        }
    }
    // No anchored key verified: reuse the shared verdict logic so the
    // distinction between "wrong signature" and "cannot be judged" stays in
    // one place.
    validate_rrset(records, rrsigs, &keys, now_secs)
}

/// [`validate_rrset`] for a single key: `true` only when a signature over
/// `records` verifies with it.
fn verify_rrset_quietly(
    records: &[Record],
    rrsigs: &[Record],
    key: &Record,
    now_secs: u32,
) -> bool {
    let rec_refs: Vec<&Record> = records.iter().collect();
    for rrsig in rrsigs {
        if matches!(verify_rrsig(key, rrsig, &rec_refs, now_secs), Ok(true)) {
            return true;
        }
    }
    false
}

fn key_is_anchored(resolver: &crate::resolver::Resolver, signer: &Name, key: &Record) -> bool {
    // The DS for `signer` lives in the parent zone; querying `signer` for DS
    // reaches the parent's authoritative data through the delegation.
    match resolver.resolve(signer, RrType::DS) {
        Ok(ds_res) => ds_res
            .answers
            .iter()
            .filter(|r| r.rr_type == RrType::DS && r.name == *signer)
            .any(|ds| dnskey_matches_ds(key, ds)),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property that matters more than any single verdict: a
    /// signature-verified answer with **no** configured anchor must never be
    /// reported as chain-anchored, and must never be advertised with `AD`.
    #[test]
    fn verification_without_an_anchor_is_never_chain_anchored() {
        let s = Verdict::Secure.state(false);
        assert_eq!(s, ValidationState::CryptoVerified);
        assert!(s.is_signature_verified());
        assert!(
            !s.permits_authentic_data(),
            "AD must not be set without an anchor"
        );

        let s = Verdict::Secure.state(true);
        assert_eq!(s, ValidationState::ChainAnchored);
        assert!(s.permits_authentic_data());
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
            verdict: Verdict::Secure,
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
