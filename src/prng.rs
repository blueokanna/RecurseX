//! Small self-contained pseudo-random and hashing primitives.
//!
//! The resolver needs three cheap primitives and the allowed crate set does
//! not include a generic RNG/hash crate, so they live here:
//!
//! * [`SplitMix64`] — a deterministic 64-bit PRNG used for 0x20 QNAME
//!   case randomization, EDNS query IDs, and cache-eviction sampling. It is
//!   seeded from wall time plus process entropy; it is *not* a
//!   cryptographically secure generator and must not be used for secrets.
//! * [`fnv1a64`] — FNV-1a for cheap content fingerprints (cache-change
//!   detection). Not cryptographic.
//! * [`siphash24`] — a from-scratch SipHash-2-4 (the reference MAC used by
//!   RFC 7873 DNS Cookies). This one *is* keyed and is the only primitive
//!   used for cookie generation; it is verified against the published
//!   reference vectors.

use core::num::Wrapping;

/// SplitMix64: a fast, well-distributed deterministic generator.
///
/// This is the classic `splitmix64` from Vigna's "An experimental
/// exploration of Marsaglia's xorshift generators, scrambled". Deterministic
/// and seedable, which is what 0x20 and eviction sampling need.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Create a generator from an arbitrary seed.
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Seed from the current time and a per-process jitter value.
    #[cfg(feature = "std")]
    pub fn seeded() -> Self {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        // Fold the stack address of a local in as process entropy. This is
        // weak on purpose: 0x20/cookies are not the only anti-spoofing
        // mechanism and this generator is never used for keys.
        let jitter = (&t as *const _ as usize) as u64;
        Self::new(t ^ jitter.rotate_left(17) ^ 0x9e3779b97f4a7c15)
    }

    /// The next 64-bit value.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    /// The next 32-bit value.
    #[inline]
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// A value in `0..n` (rejection sampling, unbiased).
    #[inline]
    pub fn below(&mut self, n: u64) -> u64 {
        debug_assert!(n > 0);
        // Largest multiple of `n` that fits in u64; values below it are
        // uniform mod n. Rejection sampling removes the modulo bias.
        let limit = (u64::MAX / n) * n;
        loop {
            let v = self.next_u64();
            if v < limit {
                return v % n;
            }
        }
    }

    /// Fill `out` with random bytes.
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// FNV-1a 64-bit hash (for cheap content fingerprints only — not a MAC).
#[inline]
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// A stable fingerprint of an `&[u8]` slice that can be combined with
/// [`fnv1a_combine`].
#[inline]
pub fn fnv1a_combine(acc: u64, bytes: &[u8]) -> u64 {
    let mut h = acc;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

// ---------------------------------------------------------------------------
// SipHash-2-4 (RFC 7873 DNS Cookies use SipHash-2-4 with a 128-bit key).
//
// Implemented from the specification (Aumasson & Bernstein, "SipHash: a
// fast short-input PRF"). Verified against the reference vectors below.
// ---------------------------------------------------------------------------

#[inline]
fn rotl(x: u64, b: u32) -> u64 {
    x.rotate_left(b)
}

#[inline]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = rotl(*v1, 13);
    *v1 ^= *v0;
    *v0 = rotl(*v0, 32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = rotl(*v3, 16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = rotl(*v3, 21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = rotl(*v1, 17);
    *v1 ^= *v2;
    *v2 = rotl(*v2, 32);
}

/// SipHash-2-4 of `input` under the 128-bit key `(k0, k1)`.
pub fn siphash24(k0: u64, k1: u64, input: &[u8]) -> u64 {
    let mut v0 = Wrapping(k0) ^ Wrapping(0x736f6d6570736575);
    let mut v1 = Wrapping(k1) ^ Wrapping(0x646f72616e646f6d);
    let mut v2 = Wrapping(k0) ^ Wrapping(0x6c7967656e657261);
    let mut v3 = Wrapping(k1) ^ Wrapping(0x7465646279746573);

    let mut i = 0usize;
    let n = input.len() / 8;
    for _ in 0..n {
        let m = u64::from_le_bytes(input[i..i + 8].try_into().unwrap());
        v3 ^= Wrapping(m);
        sip_round(&mut v0.0, &mut v1.0, &mut v2.0, &mut v3.0);
        sip_round(&mut v0.0, &mut v1.0, &mut v2.0, &mut v3.0);
        v0 ^= Wrapping(m);
        i += 8;
    }

    let mut last = (input.len() as u64) << 56;
    let rem = &input[i..];
    for (j, &b) in rem.iter().enumerate() {
        last |= (b as u64) << (8 * j);
    }

    v3 ^= Wrapping(last);
    sip_round(&mut v0.0, &mut v1.0, &mut v2.0, &mut v3.0);
    sip_round(&mut v0.0, &mut v1.0, &mut v2.0, &mut v3.0);
    v0 ^= Wrapping(last);
    v2 ^= Wrapping(0xff);
    for _ in 0..4 {
        sip_round(&mut v0.0, &mut v1.0, &mut v2.0, &mut v3.0);
    }
    (v0 ^ v1 ^ v2 ^ v3).0
}

/// A 128-bit SipHash-2-4 output (two independent 64-bit halves with
/// different finalization constants, standard practice for DNS cookies).
pub fn siphash24_128(k0: u64, k1: u64, input: &[u8]) -> [u8; 16] {
    let a = siphash24(k0, k1, input);
    let b = siphash24(k0 ^ 0x736f6d6570736575, k1 ^ 0x646f72616e646f6d, input);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&a.to_le_bytes());
    out[8..].copy_from_slice(&b.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference vectors from the SipHash reference implementation
    /// (`vectors.h` in veorq/SipHash), key bytes 00..0f, input bytes 00..i.
    #[test]
    fn siphash24_reference_vectors() {
        let k0 = 0x0706050403020100u64;
        let k1 = 0x0f0e0d0c0b0a0908u64;
        let expected: [u64; 8] = [
            0x726fdb47dd0e0e31, // len 0
            0x74f839c593dc67fd, // len 1
            0x0d6c8009d9a94f5a, // len 2
            0x85676696d7fb7e2d, // len 3
            0xcf2794e0277187b7, // len 4
            0x18765564cd99a68d, // len 5
            0xcbc9466e58fee3ce, // len 6
            0xab0200f58b01d137, // len 7
        ];
        for (i, &want) in expected.iter().enumerate() {
            let input: Vec<u8> = (0..i as u8).collect();
            let got = siphash24(k0, k1, &input);
            assert_eq!(got, want, "vector {i}");
        }
        // Also verify the well-known "0123456789" vector.
        assert_eq!(siphash24(k0, k1, b"0123456789"), 0x266fb4ed0635fd04);
    }

    #[test]
    fn splitmix64_is_deterministic() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        assert!(a.next_u64() != SplitMix64::new(43).next_u64());
    }

    #[test]
    fn below_is_bounded() {
        let mut rng = SplitMix64::new(7);
        for _ in 0..10_000 {
            let v = rng.below(5);
            assert!(v < 5);
        }
    }

    #[test]
    fn fnv1a_is_stable() {
        assert_eq!(fnv1a64(b"www.example.com"), fnv1a64(b"www.example.com"));
        assert_ne!(fnv1a64(b"www.example.com"), fnv1a64(b"www.example.org"));
    }
}
