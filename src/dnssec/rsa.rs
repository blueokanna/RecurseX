//! RSA PKCS#1 v1.5 / SHA-256 signature verification.
//!
//! A from-scratch modular-exponentiation engine (little-endian `u32`
//! limbs, square-and-multiply with modular reduction by long division).
//! Not constant-time — this is a public-key *verification* path with no
//! secret inputs — but correctness-critical, so it is verified against
//! independently generated vectors in the tests.

use alloc::vec::Vec;

/// The ASN.1 DigestInfo prefix for SHA-256 (RFC 8017 §9.2 note).
pub const DIGEST_INFO_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Parse an RFC 3110 RSA DNSKEY public key: `[exp_len][exponent][modulus]`.
/// Returns `(modulus_be, exponent_be)`.
pub fn parse_dnskey_rsa(public_key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if public_key.is_empty() {
        return None;
    }
    let exp_len = public_key[0] as usize;
    // Exponent length 0 means a 4-byte exponent (RFC 3110 §3).
    let (exp_len, exp_off) = if exp_len == 0 {
        (4usize, 1usize)
    } else {
        (exp_len, 1usize)
    };
    if public_key.len() < exp_off + exp_len + 1 {
        return None;
    }
    let exponent = public_key[exp_off..exp_off + exp_len].to_vec();
    let modulus = public_key[exp_off + exp_len..].to_vec();
    if modulus.len() < 3 {
        return None;
    }
    Some((modulus, exponent))
}

// ---------------------------------------------------------------------
// Big integers: little-endian u32 limbs.
// ---------------------------------------------------------------------

fn to_limbs_be(bytes: &[u8]) -> Vec<u32> {
    // Big-endian bytes → little-endian limbs.
    let mut limbs = Vec::with_capacity(bytes.len() / 4 + 1);
    let mut i = bytes.len();
    while i > 0 {
        let start = i.saturating_sub(4);
        let mut v: u32 = 0;
        for &b in &bytes[start..i] {
            v = (v << 8) | b as u32;
        }
        limbs.push(v);
        i = start;
    }
    trim(&mut limbs);
    limbs
}

fn to_be_bytes(limbs: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(limbs.len() * 4);
    for &l in limbs.iter().rev() {
        out.extend_from_slice(&l.to_be_bytes());
    }
    // Trim leading zero bytes (keep at least one).
    let start = out.iter().position(|&b| b != 0).unwrap_or(out.len() - 1);
    out[start..].to_vec()
}

fn trim(limbs: &mut Vec<u32>) {
    while limbs.len() > 1 && *limbs.last().unwrap() == 0 {
        limbs.pop();
    }
}

fn cmp_limbs(a: &[u32], b: &[u32]) -> core::cmp::Ordering {
    let la = trim_len(a);
    let lb = trim_len(b);
    la.cmp(&lb).then_with(|| {
        for i in (0..la).rev() {
            match a[i].cmp(&b[i]) {
                core::cmp::Ordering::Equal => continue,
                o => return o,
            }
        }
        core::cmp::Ordering::Equal
    })
}

fn trim_len(a: &[u32]) -> usize {
    let mut n = a.len();
    while n > 1 && a[n - 1] == 0 {
        n -= 1;
    }
    n
}

/// Schoolbook multiplication (u64 intermediates).
fn mul_limbs(a: &[u32], b: &[u32]) -> Vec<u32> {
    let la = trim_len(a);
    let lb = trim_len(b);
    let mut out = vec![0u32; la + lb];
    for (i, &av) in a[..la].iter().enumerate() {
        let mut carry: u64 = 0;
        for (j, &bv) in b[..lb].iter().enumerate() {
            let cur = out[i + j] as u64 + (av as u64) * (bv as u64) + carry;
            out[i + j] = cur as u32;
            carry = cur >> 32;
        }
        let mut k = i + lb;
        while carry > 0 {
            let cur = out[k] as u64 + carry;
            out[k] = cur as u32;
            carry = cur >> 32;
            k += 1;
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
        for (i, &v) in a.iter().enumerate() {
            out[i + word] = v;
        }
    } else {
        for (i, &v) in a.iter().enumerate() {
            out[i + word] |= v << bit;
            out[i + word + 1] = v >> (32 - bit);
        }
    }
    trim(&mut out);
    out
}

/// Subtract `b` from `a` in place (a >= b). Returns the borrow (0 or 1).
fn sub_limbs_in_place(a: &mut Vec<u32>, b: &[u32]) -> u32 {
    let mut borrow: u64 = 0;
    for i in 0..a.len() {
        let bv = if i < b.len() { b[i] as u64 } else { 0 };
        let av = a[i] as u64;
        let (res, b1) = av.overflowing_sub(bv + borrow);
        a[i] = res as u32;
        borrow = if b1 { 1 } else { 0 };
    }
    trim(a);
    borrow as u32
}

/// Reduce `a` modulo `m` via bitwise long division.
fn mod_rem(a: &[u32], m: &[u32]) -> Vec<u32> {
    let m_len = trim_len(m);
    if m_len == 0 {
        return Vec::new();
    }
    let r = a.to_vec();
    // Work from the top bit of the dividend down to 0.
    let r_bits = trim_len(&r) * 32;
    let top = if r_bits == 0 { 0 } else { r_bits - 1 };
    let mut acc: Vec<u32> = vec![0];
    for bit in (0..=top).rev() {
        // acc = (acc << 1) | bit_of(r, bit)
        acc = shl_limbs(&acc, 1);
        let word = bit / 32;
        let b = (r[word] >> (bit % 32)) & 1;
        if b == 1 {
            acc[0] |= 1;
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
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    bytes[start..].to_vec()
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
    if em.len() < 11 || em[0] != 0x00 || em[1] != 0x01 {
        return false;
    }
    let mut i = 2;
    while i < em.len() && em[i] == 0xff {
        i += 1;
    }
    if i < 3 || i >= em.len() || em[i] != 0x00 {
        return false;
    }
    let body = &em[i + 1..];
    if body.len() != DIGEST_INFO_SHA256.len() + 32 {
        return false;
    }
    let (di, dg) = body.split_at(DIGEST_INFO_SHA256.len());
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
        // exponent length 3, exponent 0x010001, then modulus.
        let mut pk = vec![3, 1, 0, 1];
        pk.extend_from_slice(&[0xab; 128]);
        let (m, e) = parse_dnskey_rsa(&pk).unwrap();
        assert_eq!(e, vec![1, 0, 1]);
        assert_eq!(m.len(), 128);
        // Zero-length exponent → 4-byte exponent.
        let mut pk2 = vec![0, 0, 1, 0, 1];
        pk2.extend_from_slice(&[0xab; 128]);
        let (_, e2) = parse_dnskey_rsa(&pk2).unwrap();
        assert_eq!(e2, vec![0, 1, 0, 1]);
        assert!(parse_dnskey_rsa(&[]).is_none());
    }
}
