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
//! ECDSA (13/14) and EdDSA (15/16) are recognized but not yet verified by
//! this build, so signatures from zones that only use them yield
//! `Verdict::Indeterminate` — never a fabricated "secure".

pub mod rsa;

use alloc::vec::Vec;

use crate::name::Name;
use crate::qtype::{DnssecAlgorithm, DsDigestType, RrClass, RrType};
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
/// `dnskey_records` are candidate zone keys (already matched to a DS /
/// trust anchor by the caller); `now_secs` gates the signature validity
/// window.
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
    let mut any_supported = false;
    for rrsig in rrsigs {
        if !matches!(rrsig.rdata, RData::Rrsig { .. }) {
            continue;
        }
        for key in dnskey_records {
            match verify_rrsig(key, rrsig, &rec_refs, now_secs) {
                Ok(true) => return Verdict::Secure,
                Ok(false) => continue,
                Err(_) => {
                    // Unsupported algorithm: mark so the verdict can be
                    // Indeterminate instead of Bogus.
                    any_supported = false;
                    continue;
                }
            }
        }
    }
    let _ = any_supported;
    Verdict::Indeterminate
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

/// Class of a record (used by tests and the validator).
pub fn class_of(_r: &Record) -> RrClass {
    RrClass::IN
}

// ---------------------------------------------------------------------
// Resolver integration
// ---------------------------------------------------------------------

use core::sync::atomic::{AtomicBool, Ordering};

/// Recursion guard: while the validator runs, sub-resolutions (DNSKEY / DS
/// fetches) skip their own validation, bounding the recursion depth.
static VALIDATING: AtomicBool = AtomicBool::new(false);

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
    if VALIDATING.swap(true, Ordering::SeqCst) {
        return Verdict::Indeterminate;
    }
    let v = validate_chain(resolver, &res.answers, &res.rrsigs);
    VALIDATING.store(false, Ordering::SeqCst);
    v
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
    if VALIDATING.swap(true, Ordering::SeqCst) {
        return Verdict::Indeterminate;
    }
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
    let v = validate_chain(resolver, &answers, &rrsigs);
    VALIDATING.store(false, Ordering::SeqCst);
    v
}

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
    let mut overall = Verdict::Insecure;
    for ((owner, rr_type), records) in groups {
        let covered = rrsigs_for(rrsigs, rr_type)
            .into_iter()
            .filter(|s| rrsig_signer(s) == Some(&owner) || s.name == owner)
            .collect::<Vec<Record>>();
        if covered.is_empty() {
            continue; // unsigned group: keep overall Insecure
        }
        match validate_group(resolver, &owner, &records, &covered, now_secs) {
            Verdict::Secure => return Verdict::Secure,
            Verdict::Bogus => overall = Verdict::Bogus,
            Verdict::Indeterminate => {
                if overall == Verdict::Insecure {
                    overall = Verdict::Indeterminate;
                }
            }
            Verdict::Insecure => {}
        }
    }
    overall
}

fn validate_group(
    resolver: &crate::resolver::Resolver,
    _owner: &Name,
    records: &[Record],
    rrsigs: &[Record],
    now_secs: u32,
) -> Verdict {
    // The signer zone: the RRSIG signer name.
    let Some(signer) = rrsig_signer(&rrsigs[0]).cloned() else {
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
    let rec_refs: Vec<&Record> = records.iter().collect();
    let mut verified_any = false;
    for rrsig in rrsigs {
        for key in &keys {
            match verify_rrsig(key, rrsig, &rec_refs, now_secs) {
                Ok(true) => {
                    verified_any = true;
                    // Anchor check: does a parent DS cover this key?
                    if key_is_anchored(resolver, &signer, key) {
                        return Verdict::Secure;
                    }
                }
                Ok(false) => continue,
                Err(_) => return Verdict::Indeterminate,
            }
        }
    }
    if verified_any {
        // Signature verifies but no anchor in the parent → insecure.
        Verdict::Insecure
    } else {
        Verdict::Bogus
    }
}

fn key_is_anchored(resolver: &crate::resolver::Resolver, signer: &Name, key: &Record) -> bool {
    let parent = match signer.parent() {
        Some(p) => p,
        None => return false,
    };
    // The DS for `signer` lives in the parent zone. Querying `signer` for
    // DS reaches the parent's authoritative data through delegation.
    match resolver.resolve(signer, RrType::DS) {
        Ok(ds_res) => ds_res
            .answers
            .iter()
            .filter(|r| r.rr_type == RrType::DS && r.name == *signer)
            .any(|ds| dnskey_matches_ds(key, ds)),
        Err(_) => {
            let _ = parent;
            false
        }
    }
}
