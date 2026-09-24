//! RSA PKCS#1 v1.5 / SHA-256 signature verification.
//!
//! A from-scratch modular-exponentiation engine (little-endian `u32`
//! limbs, square-and-multiply with modular reduction by long division).
//! Not constant-time — this is a public-key *verification* path with no
//! secret inputs — but correctness-critical, so it is verified against
//! independently generated vectors in the tests.
//!
//! # Contract
//!
//! `verify_pkcs1v15_sha256` is **total** over attacker-controlled input.
//! Every byte it reads arrives from the wire: the DNSKEY is public data an
//! on-path attacker can replay, and the signature is theirs to choose. A
//! malformed key or signature is therefore answered with `false` — never a
//! panic, and never an error the caller has to catch. An arithmetic helper
//! that can panic on a degenerate operand is a remote denial of service, not
//! a style problem, which is why the limb helpers treat zero as the value
//! `[0]` rather than as an empty slice.

use alloc::vec::Vec;

/// The ASN.1 DigestInfo prefix for SHA-256 (RFC 8017 §9.2 note).
pub const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Parse an RFC 3110 RSA DNSKEY public key: `[exp_len][exponent][modulus]`.
/// Returns `(modulus_be, exponent_be)`.
///
/// The exponent length is one octet, or — when that octet is zero — the two
/// octets that follow it (RFC 3110 §2), which is how an exponent longer than
/// 255 bytes is expressed. The three-octet form moves the exponent to offset
/// 3; reading it as a fixed-width exponent misplaces both fields, so any key
/// encoded that way would be parsed as garbage and never verify.
///
/// Returns `None` rather than a partial value whenever the encoding does not
/// hold together, so the caller's only failure mode is a rejected signature.
pub fn parse_dnskey_rsa(public_key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (exp_len, exp_off) = match public_key.first() {
        None => return None,
        Some(&0) => {
            let hi = *public_key.get(1)?;
            let lo = *public_key.get(2)?;
            (u16::from_be_bytes([hi, lo]) as usize, 3usize)
        }
        Some(&n) => (n as usize, 1usize),
    };
    // A zero-length exponent is not a key.
    if exp_len == 0 {
        return None;
    }
    // At least one byte must remain for the modulus, so that the slices below
    // are in bounds by construction.
    let exp_end = exp_off.checked_add(exp_len)?;
    if exp_end + 1 > public_key.len() {
        return None;
    }
    let exponent = public_key.get(exp_off..exp_end)?.to_vec();
    let modulus = public_key.get(exp_end..)?.to_vec();
    if modulus.len() < 3 {
        return None;
    }
    Some((modulus, exponent))
}

// ---------------------------------------------------------------------
// Big integers: little-endian u32 limbs.
// ---------------------------------------------------------------------

fn to_limbs_be(bytes: &[u8]) -> Vec<u32> {
    // Big-endian bytes → little-endian limbs. `rchunks(4)` groups from the
    // right, so the most significant group — which may be one to three bytes —
    // comes last, which is exactly limb order.
    let mut limbs: Vec<u32> = bytes
        .rchunks(4)
        .map(|group| {
            let mut v: u32 = 0;
            for &b in group {
                v = (v << 8) | u32::from(b);
            }
            v
        })
        .collect();
    trim(&mut limbs);
    if limbs.is_empty() {
        // Canonical zero. A limb vector always holds at least one limb, so
        // "is this number zero?" is never answered by "is this empty?" — an
        // ambiguity that once turned a zero dividend into an out-of-bounds
        // read in `mod_rem`.
        limbs.push(0);
    }
    limbs
}

fn to_be_bytes(limbs: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(limbs.len() * 4);
    for &l in limbs.iter().rev() {
        out.extend_from_slice(&l.to_be_bytes());
    }
    // Trim leading zero bytes, keeping one so that zero encodes as a single
    // `0x00` rather than as an empty string.
    let first_nonzero = out.iter().position(|&b| b != 0);
    match first_nonzero {
        Some(start) => out.into_iter().skip(start).collect(),
        None => vec![0],
    }
}

fn trim(limbs: &mut Vec<u32>) {
    while limbs.len() > 1 && *limbs.last().unwrap() == 0 {
        limbs.pop();
    }
}

fn cmp_limbs(a: &[u32], b: &[u32]) -> core::cmp::Ordering {
    let la = trim_len(a);
    let lb = trim_len(b);
    if la != lb {
        return la.cmp(&lb);
    }
    // Equal limb counts: compare from the most significant down. Both sides
    // are truncated to the same length, so `zip` pairs them exactly and stops
    // when they run out.
    for (x, y) in a.iter().take(la).rev().zip(b.iter().take(lb).rev()) {
        match x.cmp(y) {
            core::cmp::Ordering::Equal => continue,
            o => return o,
        }
    }
    core::cmp::Ordering::Equal
}

fn trim_len(a: &[u32]) -> usize {
    let mut n = a.len();
    // `get(n - 1)` is the element the loop is looking at, without an index
    // expression; it is in range for every `n` this loop reaches.
    while n > 1 && a.get(n - 1).copied() == Some(0) {
        n -= 1;
    }
    n
}

/// The bit at `index` of a little-endian limb array, or `false` past its end.
fn bit_at(limbs: &[u32], index: usize) -> bool {
    limbs
        .get(index / 32)
        .is_some_and(|limb| (limb >> (index % 32)) & 1 == 1)
}

/// Schoolbook multiplication (u64 intermediates).
fn mul_limbs(a: &[u32], b: &[u32]) -> Vec<u32> {
    let la = trim_len(a);
    let lb = trim_len(b);
    let mut out = vec![0u32; la + lb];
    for (i, &av) in a.iter().take(la).enumerate() {
        let mut carry: u64 = 0;
        // Each limb of `b` lands at offset `i` onwards, which `skip(i)`
        // expresses without computing `i + j`. `zip` bounds it to `lb` limbs.
        for (slot, &bv) in out.iter_mut().skip(i).zip(b.iter().take(lb)) {
            let cur = u64::from(*slot) + u64::from(av) * u64::from(bv) + carry;
            *slot = cur as u32;
            carry = cur >> 32;
        }
        // Propagate the final carry through the limbs above. The product fits
        // in `la + lb` limbs, so this runs out of carry before it runs out of
        // vector, and the loop cannot walk off the end.
        for slot in out.iter_mut().skip(i + lb) {
            if carry == 0 {
                break;
            }
            let cur = u64::from(*slot) + carry;
            *slot = cur as u32;
            carry = cur >> 32;
        }
    }
    trim(&mut out);
    out
}

/// Shift a limb vector left by `bits` (0..32).
fn shl_limbs(a: &[u32], bits: u32) -> Vec<u32> {
    if bits == 0 {
        return a.to_vec();
    }
    let word = (bits / 32) as usize;
    let bit = bits % 32;
    let mut out = vec![0u32; a.len() + word + 1];
    if bit == 0 {
        for (slot, &v) in out.iter_mut().skip(word).zip(a.iter()) {
            *slot = v;
        }
    } else {
        // Each limb feeds two output limbs: its low part at its own offset and
        // its high part one limb above. The two halves occupy disjoint bits,
        // so doing every low part and then every high part with `|=` gives the
        // same vector as interleaving them.
        for (slot, &v) in out.iter_mut().skip(word).zip(a.iter()) {
            *slot |= v << bit;
        }
        for (slot, &v) in out.iter_mut().skip(word + 1).zip(a.iter()) {
            *slot |= v >> (32 - bit);
        }
    }
    trim(&mut out);
    out
}

/// Subtract `b` from `a` in place (a >= b). Returns the borrow (0 or 1).
fn sub_limbs_in_place(a: &mut Vec<u32>, b: &[u32]) -> u32 {
    let mut borrow: u64 = 0;
    // `b` is padded with zeros past its end rather than indexed, and `zip`
    // stops at `a`'s length, which is what the old `for i in 0..a.len()` did.
    let padded = b.iter().copied().chain(core::iter::repeat(0u32));
    for (slot, bv) in a.iter_mut().zip(padded) {
        let (res, underflow) = u64::from(*slot).overflowing_sub(u64::from(bv) + borrow);
        *slot = res as u32;
        borrow = u64::from(underflow);
    }
    trim(a);
    borrow as u32
}

/// Reduce `a` modulo `m` via bitwise long division.
///
/// A degenerate operand yields the canonical zero instead of walking a buffer
/// that is not there: an empty dividend has no most-significant bit to start
/// from, and an empty or all-zero modulus has no meaningful remainder, so both
/// fail closed at the caller's comparison rather than panicking here.
fn mod_rem(a: &[u32], m: &[u32]) -> Vec<u32> {
    let a_len = trim_len(a);
    let m_len = trim_len(m);
    // `take(m_len)` is the significand of `m`; `take(a_len)` below is the
    // dividend's. Neither is an index expression, so neither can panic.
    if a_len == 0 || m_len == 0 || m.iter().take(m_len).all(|&w| w == 0) {
        return vec![0];
    }
    // `a_len` never exceeds `a`'s length, so this is the dividend's
    // significand; `get` is what makes that a checked fact.
    let r: &[u32] = a.get(..a_len).unwrap_or(a);
    // Start at the dividend's most significant *set* bit. `trim_len` only
    // removes whole zero limbs, so the leading zero bits of the top limb are
    // still there; skipping them is safe because a leading zero bit only ever
    // shifts zero into the accumulator.
    let lead = r.last().map_or(32, |w| w.leading_zeros()) as usize;
    let mut acc: Vec<u32> = vec![0];
    for bit in (0..a_len * 32 - lead).rev() {
        acc = shl_limbs(&acc, 1);
        if bit_at(r, bit) {
            if let Some(low) = acc.first_mut() {
                *low |= 1;
            }
        }
        if cmp_limbs(&acc, m) != core::cmp::Ordering::Less {
            sub_limbs_in_place(&mut acc, m);
        }
    }
    trim(&mut acc);
    acc
}

/// Modular exponentiation: `base^exp mod m`, `exp` as big-endian bytes.
fn mod_pow(base_be: &[u8], exp_be: &[u8], m_be: &[u8]) -> Vec<u8> {
    let m = to_limbs_be(m_be);
    let base = mod_rem(&to_limbs_be(base_be), &m);
    let mut result: Vec<u32> = vec![1];
    for &b in exp_be {
        for bit in (0..8).rev() {
            // result = result^2 mod m
            result = mod_rem(&mul_limbs(&result, &result), &m);
            if (b >> bit) & 1 == 1 {
                result = mod_rem(&mul_limbs(&result, &base), &m);
            }
        }
    }
    to_be_bytes(&result)
}

/// Verify a PKCS#1 v1.5 / SHA-256 signature with an RFC 3110 DNSKEY.
pub fn verify_pkcs1v15_sha256(
    dnskey_public_key: &[u8],
    digest: &[u8; 32],
    signature: &[u8],
) -> bool {
    let Some((modulus, exponent)) = parse_dnskey_rsa(dnskey_public_key) else {
        return false;
    };
    // The DER-style leading 0x00 (sign bit) is not part of the modulus
    // value; the EM is padded to the true modulus byte length.
    let trimmed = trim_leading_zeros(&modulus);
    let em_be = mod_pow(signature, &exponent, &trimmed);
    verify_em(&em_be, trimmed.len(), digest)
}

fn trim_leading_zeros(bytes: &[u8]) -> Vec<u8> {
    // Keeping one byte for an all-zero input means the length this returns is
    // always a usable modulus length.
    match bytes.iter().position(|&b| b != 0) {
        Some(start) => bytes.get(start..).unwrap_or_default().to_vec(),
        None => vec![0],
    }
}

/// Check the PKCS#1 v1.5 encoded message (EM) against the expected
/// DigestInfo || digest, zero-padded to the modulus length.
fn verify_em(em_be: &[u8], modulus_len: usize, digest: &[u8; 32]) -> bool {
    // Left-pad to the modulus size.
    if em_be.len() > modulus_len {
        return false;
    }
    let mut em = vec![0u8; modulus_len - em_be.len()];
    em.extend_from_slice(em_be);
    // EM = 0x00 0x01 0xFF..0xFF 0x00 || DigestInfo || digest.
    if em.len() < 11 || em.first() != Some(&0x00) || em.get(1) != Some(&0x01) {
        return false;
    }
    let mut i = 2;
    // `get` past the end is `None`, which is not `Some(&0xff)`, so the walk
    // stops at the end of the message without a separate length test.
    while em.get(i) == Some(&0xff) {
        i += 1;
    }
    // RFC 8017 §9.2 requires at least 8 padding octets. Accepting a shorter
    // run is the structural laxity behind Bleichenbacher's PKCS#1 v1.5
    // signature forgery against low-exponent keys: no key large enough to be
    // usable with SHA-256 can produce a shorter run, so this only ever
    // rejects a malformed encoding.
    if i < 2 + 8 || em.get(i) != Some(&0x00) {
        return false;
    }
    let Some(body) = em.get(i + 1..) else {
        return false;
    };
    if body.len() != DIGEST_INFO_SHA256.len() + 32 {
        return false;
    }
    // The length test just above means both halves exist.
    let (Some(di), Some(dg)) = (
        body.get(..DIGEST_INFO_SHA256.len()),
        body.get(DIGEST_INFO_SHA256.len()..),
    ) else {
        return false;
    };
    di == DIGEST_INFO_SHA256 && dg == digest
}

/// Constant-time equality (defense in depth; the verify path has no
/// secrets, but comparisons against attacker-controlled bytes should not
/// leak through early exit).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn limb_roundtrip() {
        let v = vec![1u8, 2, 3, 4, 5];
        let limbs = to_limbs_be(&v);
        assert_eq!(to_be_bytes(&limbs), v);
        // Big value with high bit set.
        let big = hex("ffeeddccbbaa99887766554433221100");
        assert_eq!(to_be_bytes(&to_limbs_be(&big)), big);
    }

    #[test]
    fn mul_and_mod() {
        let a = to_limbs_be(&[0xff, 0xff, 0xff, 0xff]);
        let b = to_limbs_be(&[0xff, 0xff, 0xff, 0xff]);
        let p = mul_limbs(&a, &b);
        assert_eq!(to_be_bytes(&p), hex("fffffffe00000001"));
        // 17^3 mod 1000 = 913? 17^3 = 4913, 4913 mod 1000 = 913.
        let r = mod_pow(&[17], &[3], &hex("03e8"));
        assert_eq!(r, hex("0391"));
    }

    /// A 1024-bit RSA key + PKCS#1 v1.5 SHA-256 signature generated with an
    /// independent implementation (openssl) over the digest of the message
    /// "RecurseX DNSSEC vector".
    #[test]
    fn rsa_pkcs1v15_sha256_vector() {
        let n = hex(
            "00d784d86b862ed84f89f29a1d6849c0b9d8180e40abf515b96e06e741352310ade6bccecc483e66eb00b96db1de095b572e47570c37279f6370fbff653accf7885976a7f1494c387e78725a022ccf24a040aebd023692a1b2afe1f19ec121b484c5c44b080e92be8affa2f00264d1f72e115acb3ee42ddaa8f359a9015b586acb",
        );
        let e = hex("010001");
        let digest = [
            0xb7, 0x7c, 0xa8, 0xc4, 0xbe, 0x1d, 0xeb, 0xd0, 0x32, 0x9d, 0x82, 0xc6, 0x8d, 0xe0,
            0xb1, 0x7a, 0x64, 0x0f, 0xd9, 0x9b, 0xdc, 0xe5, 0xb5, 0x2b, 0x93, 0xe7, 0x75, 0x6f,
            0x01, 0x2a, 0xd6, 0x2e,
        ];
        let signature = hex(
            "690957d2ed6a588065ab683cf924fbe61c1793ccdad79977c22f9fe9ce2992b06e7b51ebf73c84941d0ed7caa3068235173671c3d9c330cd021ed41bf1a0d9353c2db4bef20448f2e1e703259f190f0a485377ac8608c071d3707541178e807aeebbd9e749325d91afd83cceefea08ffdd501047e813ee03eb795d43286531e9",
        );
        // Build an RFC 3110 DNSKEY public key: exponent length (1 byte) +
        // exponent + modulus.
        let mut dnskey = vec![e.len() as u8];
        dnskey.extend_from_slice(&e);
        dnskey.extend_from_slice(&n);
        assert!(verify_pkcs1v15_sha256(&dnskey, &digest, &signature));
        // A tampered digest must fail.
        let mut bad = digest;
        bad[0] ^= 0x80;
        assert!(!verify_pkcs1v15_sha256(&dnskey, &bad, &signature));
        // A tampered signature must fail.
        let mut sig_bad = signature.clone();
        sig_bad[0] ^= 0x01;
        assert!(!verify_pkcs1v15_sha256(&dnskey, &digest, &sig_bad));
    }

    #[test]
    fn dnskey_rsa_parse() {
        // Exponent length 3, exponent 0x010001, then modulus.
        let mut pk = vec![3, 1, 0, 1];
        pk.extend_from_slice(&[0xab; 128]);
        let (m, e) = parse_dnskey_rsa(&pk).unwrap();
        assert_eq!(e, vec![1, 0, 1]);
        assert_eq!(m.len(), 128);

        // The three-octet form (RFC 3110 §2): a leading zero octet means the
        // exponent length is the *next two* octets and the exponent starts at
        // offset 3. The same key must come out as from the single-octet form.
        let mut pk2 = vec![0, 0, 3, 1, 0, 1];
        pk2.extend_from_slice(&[0xab; 128]);
        let (m2, e2) = parse_dnskey_rsa(&pk2).unwrap();
        assert_eq!(e2, vec![1, 0, 1]);
        assert_eq!(m2, m);

        // An exponent of 256 bytes, which only the three-octet form can
        // describe: a single length octet cannot hold it.
        let long_exp: Vec<u8> = (1..=255u8).chain(core::iter::once(1)).collect();
        assert_eq!(long_exp.len(), 256);
        let mut pk3 = vec![0, 0x01, 0x00];
        pk3.extend_from_slice(&long_exp);
        pk3.extend_from_slice(&[0xab; 128]);
        let (m3, e3) = parse_dnskey_rsa(&pk3).unwrap();
        assert_eq!(e3, long_exp);
        assert_eq!(m3.len(), 128);

        // Structures that do not hold together are refused, not guessed at.
        assert!(parse_dnskey_rsa(&[]).is_none());
        assert!(parse_dnskey_rsa(&[0]).is_none(), "truncated length field");
        assert!(parse_dnskey_rsa(&[0, 0]).is_none(), "truncated length field");
        assert!(
            parse_dnskey_rsa(&[0, 0, 0, 1, 0, 1, 0xab, 0xab, 0xab]).is_none(),
            "a zero exponent length is not a key"
        );
        assert!(
            parse_dnskey_rsa(&[0, 1, 0x00]).is_none(),
            "an exponent with no modulus is not a key"
        );
        assert!(
            parse_dnskey_rsa(&[2, 1, 0, 0xab, 0xab]).is_none(),
            "a modulus shorter than three octets is not a key"
        );
    }

    /// The arithmetic helpers are reachable with degenerate operands, and a
    /// panic in a verifier is a remote denial of service.
    #[test]
    fn degenerate_operands_are_answers_not_panics() {
        assert_eq!(mod_rem(&[], &[1]), vec![0], "zero dividend");
        assert_eq!(mod_rem(&[0], &[1]), vec![0], "zero dividend, leading limb");
        assert_eq!(mod_rem(&[0, 0], &[1]), vec![0], "zero dividend, two limbs");
        assert_eq!(mod_rem(&[5], &[]), vec![0], "absent modulus");
        assert_eq!(mod_rem(&[5], &[0]), vec![0], "zero modulus");
        assert_eq!(mod_rem(&[5], &[0, 0]), vec![0], "zero modulus, two limbs");
        assert_eq!(to_be_bytes(&[]), vec![0], "zero encodes to one byte");
        assert_eq!(to_be_bytes(&[0, 0]), vec![0]);
        assert_eq!(to_limbs_be(&[]), vec![0]);
        assert_eq!(trim_leading_zeros(&[]), vec![0]);
        assert_eq!(trim_leading_zeros(&[0, 0, 0]), vec![0]);
        // And the whole verifier, which is where an attacker actually stands.
        assert!(!verify_pkcs1v15_sha256(&[3, 1, 0, 1, 0xff, 0xff, 0xff], &[0u8; 32], &[]));
    }
}
