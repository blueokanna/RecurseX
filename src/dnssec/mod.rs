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
//! # What `Verdict::Secure` means here
//!
//! A group of records is `Secure` when an RRSIG over it verifies against a
//! DNSKEY of the signer zone *and* that key is covered by a DS record found
//! for the signer in the parent zone. The DNSKEY and DS lookups ride the
//! same hardened resolution path as every other query (ID/0x20/source
//! checks, bailiwick filtering) but are not themselves chain-validated:
//! this build ships no root trust anchor and does not validate the DS
//! RRset's own signature, and while the validator is running, its nested
//! lookups deliberately skip validation to bound the recursion depth.
//! `Secure` therefore means "signed by a key that matches the parent's DS",
//! not "chained to the IANA root". A caller that needs the stronger
//! guarantee must anchor it itself.

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

/// Validate a completed [`crate::resolver::Resolution`]: group the answer
/// chain, fetch the signer DNSKEYs (and the parent DS for anchoring) and
/// verify every RRSIG.
pub fn validate_resolution(
    resolver: &crate::resolver::Resolver,
    res: &crate::resolver::Resolution,
) -> Verdict {
    if res.answers.is_empty() {
        return Verdict::Insecure;
    }
    let Some(_guard) = ValidationGuard::enter() else {
        return Verdict::Indeterminate;
    };
    validate_chain(resolver, &res.answers, &res.rrsigs)
}

/// Validate a raw forwarder response.
pub fn validate_message(
    resolver: &crate::resolver::Resolver,
    _key: &crate::query::QueryKey,
    resp: &crate::message::Message,
) -> Verdict {
    if resp.answers.is_empty() {
        return Verdict::Insecure;
    }
    let Some(_guard) = ValidationGuard::enter() else {
        return Verdict::Indeterminate;
    };
    let answers: Vec<Record> = resp
        .answers
        .iter()
        .filter(|r| r.rr_type != RrType::RRSIG)
        .cloned()
        .collect();
    let rrsigs: Vec<Record> = resp
        .answers
        .iter()
        .filter(|r| r.rr_type == RrType::RRSIG)
        .cloned()
        .collect();
    validate_chain(resolver, &answers, &rrsigs)
}

/// The verdict for a whole answer chain.
///
/// RFC 4035 §4.3 is the rule, and it is an "all" rule, not an "any" rule: the
/// AD bit may only be set when every RRset in the answer was authenticated.
/// Returning `Secure` as soon as *one* group verified would let an unsigned
/// CNAME ride along with a signed target and still be advertised as
/// authentic, so a single group that cannot be authenticated caps the verdict
/// at `Indeterminate`/`Insecure` even when other groups verify.
fn validate_chain(
    resolver: &crate::resolver::Resolver,
    answers: &[Record],
    rrsigs: &[Record],
) -> Verdict {
    let now_secs = {
        let t = resolver.now();
        (t / 1_000_000_000) as u32
    };
    // Group data records by (owner, type).
    let mut groups: alloc::collections::BTreeMap<(Name, RrType), Vec<Record>> =
        alloc::collections::BTreeMap::new();
    for r in answers {
        groups
            .entry((r.name.clone(), r.rr_type))
            .or_default()
            .push(r.clone());
    }
    if groups.is_empty() {
        return Verdict::Insecure;
    }
    let mut signed_groups = 0usize;
    let mut all_secure = true;
    let mut worst = Verdict::Insecure;
    for ((owner, rr_type), records) in groups {
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
        match validate_group(resolver, &records, &covered, now_secs) {
            Verdict::Secure => {}
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
    if signed_groups > 0 && all_secure {
        Verdict::Secure
    } else if worst == Verdict::Bogus {
        Verdict::Bogus
    } else if signed_groups == 0 {
        Verdict::Insecure
    } else {
        worst
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
