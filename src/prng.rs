//! Small self-contained pseudo-random, cryptographic and hashing
//! primitives.
//!
//! The resolver needs several cheap primitives and the allowed crate set
//! does not include a generic RNG/hash crate, so they live here. The
//! distinction between them is a security boundary, not a convenience:
//!
//! * [`SplitMix64`] — a fast deterministic 64-bit generator. **Not**
//!   cryptographically secure, and it is *not* used for anything an
//!   attacker can win by predicting: cache-capacity sampling and test
//!   fixtures only.
//! * [`Csprng`] — ChaCha20 (RFC 8439) in counter mode, used for every
//!   security-critical draw: DNS query IDs and 0x20 QNAME case
//!   randomization (RFC 5452 §9.2 explicitly requires these to be
//!   unpredictable, and requires the unpredictability to resist an attacker
//!   who has observed a long prefix of the stream — which is exactly what a
//!   counter-mode cipher with a periodically rekeyed secret provides and a
//!   seeded arithmetic generator does not).
//! * [`fnv1a64`] — FNV-1a for cheap content fingerprints (cache-change
//!   detection). Not cryptographic.
//! * [`siphash24`] — a from-scratch SipHash-2-4 (the reference MAC used by
//!   RFC 7873 DNS Cookies). This one *is* keyed and is the only primitive
//!   used for cookie generation; it is verified against the published
//!   reference vectors.

use core::fmt;
use core::num::Wrapping;

/// A source of unpredictable-or-arbitrary bytes.
///
/// Implemented by [`SplitMix64`] (for sampling) and [`Csprng`] (for
/// anything security-relevant). Making the callers generic over this trait
/// keeps the *choice* of generator at the call site visible: a function that
/// takes `&mut dyn RandomSource` can be fed either, and the review of "which
/// one did we hand it" happens where the argument is passed.
pub trait RandomSource {
    /// The next 64-bit value.
    fn next_u64(&mut self) -> u64;
    /// Fill `out` with bytes.
    fn fill_bytes(&mut self, out: &mut [u8]);

    /// The next 32-bit value.
    #[inline]
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// A value in `0..n` by rejection sampling. `n <= 1` yields 0 rather
    /// than dividing by zero: callers derive `n` from a collection length,
    /// and an empty collection must not panic a server.
    #[inline]
    fn below(&mut self, n: u64) -> u64 {
        if n <= 1 {
            return 0;
        }
        let limit = (u64::MAX / n) * n;
        loop {
            let v = self.next_u64();
            if v < limit {
                return v % n;
            }
        }
    }
}

/// SplitMix64: a fast, well-distributed deterministic generator.
///
/// This is the classic `splitmix64` from Vigna's "An experimental
/// exploration of Marsaglia's xorshift generators, scrambled". Deterministic
/// and seedable, which is what eviction sampling and test fixtures need — and
/// all it may be used for. It is *not* a CSPRNG: the state is 64 bits and
/// the output is invertible, so an observer who sees one output recovers the
/// state and predicts every later one.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Create a generator from an arbitrary seed.
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Seed from OS entropy (`crate::entropy`). Only for non-security uses
    /// (sampling, jitter, fixtures); security-critical draws must use
    /// [`crate::entropy::secure_random`], which returns a [`Csprng`].
    #[cfg(feature = "std")]
    pub fn seeded() -> Self {
        Self::new(crate::entropy::seed_u64())
    }

    /// Replace the internal state.
    pub fn reseed(&mut self, seed: u64) {
        self.state = seed;
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
        <Self as RandomSource>::below(self, n)
    }

    /// Fill `out` with bytes.
    pub fn fill_bytes(&mut self, out: &mut [u8]) {
        <Self as RandomSource>::fill_bytes(self, out)
    }
}

impl RandomSource for SplitMix64 {
    #[inline]
    fn next_u64(&mut self) -> u64 {
        SplitMix64::next_u64(self)
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = SplitMix64::next_u64(self).to_le_bytes();
            chunk.copy_from_slice(crate::wire::capped(&v, chunk.len()));
        }
    }
}

// ---------------------------------------------------------------------------
// ChaCha20 (RFC 8439) as a counter-mode CSPRNG.
//
// The block function is verified against the RFC's own test vector, so the
// security argument rests on a published construction rather than on
// properties of a bespoke generator.
// ---------------------------------------------------------------------------

/// The ChaCha20 quarter round on four words of a state array.
#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    let (mut sa, mut sb, mut sc, mut sd) = (word(s, a), word(s, b), word(s, c), word(s, d));
    sa = sa.wrapping_add(sb);
    sd = (sd ^ sa).rotate_left(16);
    sc = sc.wrapping_add(sd);
    sb = (sb ^ sc).rotate_left(12);
    sa = sa.wrapping_add(sb);
    sd = (sd ^ sa).rotate_left(8);
    sc = sc.wrapping_add(sd);
    sb = (sb ^ sc).rotate_left(7);
    set_word(s, a, sa);
    set_word(s, b, sb);
    set_word(s, c, sc);
    set_word(s, d, sd);
}

#[inline]
fn word(s: &[u32; 16], i: usize) -> u32 {
    s.get(i).copied().unwrap_or(0)
}

#[inline]
fn set_word(s: &mut [u32; 16], i: usize, v: u32) {
    if let Some(x) = s.get_mut(i) {
        *x = v;
    }
}

/// The 20-round ChaCha20 block function (RFC 8439 §2.3.2).
///
/// `counter` is the 32-bit block counter and `nonce` the 96-bit nonce; both
/// together must be unique per `(key, message)`. The caller
/// ([`Csprng`]) owns that discipline.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u32; 16] {
    let mut state = [0u32; 16];
    // Constants: "expand 32-byte k".
    set_word(&mut state, 0, 0x6170_7865);
    set_word(&mut state, 1, 0x3320_646e);
    set_word(&mut state, 2, 0x7962_2d32);
    set_word(&mut state, 3, 0x6b20_6574);
    for (i, chunk) in key.chunks_exact(4).enumerate() {
        let mut b = [0u8; 4];
        b.copy_from_slice(chunk);
        set_word(&mut state, 4 + i, u32::from_le_bytes(b));
    }
    set_word(&mut state, 12, counter);
    for (i, chunk) in nonce.chunks_exact(4).enumerate() {
        let mut b = [0u8; 4];
        b.copy_from_slice(chunk);
        set_word(&mut state, 13 + i, u32::from_le_bytes(b));
    }

    let working = state;
    // 10 double rounds = 20 rounds.
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    for i in 0..16 {
        let sum = word(&state, i).wrapping_add(word(&working, i));
        set_word(&mut state, i, sum);
    }
    state
}

/// A ChaCha20 counter-mode CSPRNG.
///
/// # Why a cipher and not a bigger arithmetic generator
///
/// RFC 5452 §9.2 requires that the query ID be unpredictable to an attacker
/// who has already observed a large number of the resolver's queries. A
/// generator with a 64-bit state fails that requirement: observing one
/// output reveals the state. A keyed stream cannot fail it, because the
/// observation reveals a *block of keystream* and says nothing about the
/// key — the attacker's next block is as unknown as the first.
///
/// # Rekeying
///
/// A ChaCha20 key/nonce pair must not produce more than `2^38` bytes (RFC
/// 8439 §2.8, the counter-width limit) and best practice is far below that.
/// [`Csprng::rekey`] installs fresh key material; [`Csprng::needs_rekey`]
/// says when. The owner is responsible for calling it — this type has no
/// access to OS entropy, which keeps the module `no_std` and the dependency
/// direction honest (entropy depends on prng, never the reverse).
#[derive(Clone)]
pub struct Csprng {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
    block: [u8; 64],
    pos: usize,
    bytes_since_rekey: u64,
    rekey_after_bytes: u64,
}

impl fmt::Debug for Csprng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material, even in a Debug line that reaches a log.
        write!(
            f,
            "Csprng(blocks={} buffered={} bytes_since_rekey={})",
            self.counter, self.pos, self.bytes_since_rekey
        )
    }
}

/// Default rekey threshold: one mebibyte of keystream per key.
///
/// At roughly 40 bytes of ID-and-case material per upstream query this is
/// about 26 000 queries between rekeys — well inside any deployment's
/// tolerance for a `getrandom` call, and four orders of magnitude below the
/// cipher's own limit.
pub const DEFAULT_REKEY_BYTES: u64 = 1 << 20;

impl Csprng {
    /// A generator over 32 bytes of key material and a 96-bit nonce.
    pub fn new(key: [u8; 32], nonce: [u8; 12]) -> Self {
        Self {
            key,
            nonce,
            counter: 0,
            block: [0u8; 64],
            pos: 64,
            bytes_since_rekey: 0,
            rekey_after_bytes: DEFAULT_REKEY_BYTES,
        }
    }

    /// Install fresh key material and reset the counter.
    ///
    /// The caller must supply the entropy; see the type documentation.
    pub fn rekey(&mut self, key: [u8; 32], nonce: [u8; 12]) {
        self.key = key;
        self.nonce = nonce;
        self.counter = 0;
        self.pos = 64;
        self.bytes_since_rekey = 0;
    }

    /// Whether the keystream produced so far has reached the rekey
    /// threshold.
    pub fn needs_rekey(&self) -> bool {
        self.bytes_since_rekey >= self.rekey_after_bytes
    }

    /// Lower the rekey threshold (for tests and for deployments that want
    /// a tighter bound).
    pub fn set_rekey_threshold(&mut self, bytes: u64) {
        self.rekey_after_bytes = bytes.max(64);
    }

    /// Bytes produced since the last rekey.
    pub fn bytes_since_rekey(&self) -> u64 {
        self.bytes_since_rekey
    }

    /// Refill the internal block buffer.
    fn refill(&mut self) {
        let words = chacha20_block(&self.key, self.counter, &self.nonce);
        for (i, w) in words.iter().enumerate() {
            let bytes = w.to_le_bytes();
            let base = i * 4;
            for (j, b) in bytes.iter().enumerate() {
                if let Some(slot) = self.block.get_mut(base + j) {
                    *slot = *b;
                }
            }
        }
        // Counter overflow would repeat keystream; the rekey threshold is
        // set far below it, but a defensive wrap keeps the type total.
        self.counter = self.counter.wrapping_add(1);
        self.pos = 0;
    }
}

impl RandomSource for Csprng {
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        <Self as RandomSource>::fill_bytes(self, &mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut written = 0usize;
        while written < out.len() {
            if self.pos >= self.block.len() {
                self.refill();
            }
            let available = self.block.len().saturating_sub(self.pos);
            let want = out.len() - written;
            let n = available.min(want);
            if n == 0 {
                break;
            }
            let src = self.block.get(self.pos..self.pos + n).unwrap_or(&[]);
            let dst = out.get_mut(written..written + n).unwrap_or(&mut []);
            dst.copy_from_slice(src);
            self.pos += n;
            written += n;
            self.bytes_since_rekey = self.bytes_since_rekey.saturating_add(n as u64);
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

    // `chunks_exact(8)` hands out eight-byte blocks and keeps the tail, so
    // neither the block loop nor the tail loop needs an offset into `input`.
    let mut chunks = input.chunks_exact(8);
    for block in chunks.by_ref() {
        let mut m = 0u64;
        for (i, &b) in block.iter().enumerate() {
            m |= u64::from(b) << (8 * i);
        }
        v3 ^= Wrapping(m);
        sip_round(&mut v0.0, &mut v1.0, &mut v2.0, &mut v3.0);
        sip_round(&mut v0.0, &mut v1.0, &mut v2.0, &mut v3.0);
        v0 ^= Wrapping(m);
    }

    let mut last = (input.len() as u64) << 56;
    for (j, &b) in chunks.remainder().iter().enumerate() {
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
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;

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

    /// RFC 8439 §2.3.2 test vector for the ChaCha20 block function. Passing
    /// this is what licenses the security claim: the construction is the
    /// published one, not something bespoke.
    #[test]
    fn chacha20_block_matches_rfc8439_vector() {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let want: [u32; 16] = [
            0xe4e7_f110,
            0x1559_3bd1,
            0x1fdd_0f50,
            0xc471_20a3,
            0xc7f4_d1c7,
            0x0368_c033,
            0x9aaa_2204,
            0x4e6c_d4c3,
            0x4664_82d2,
            0x09aa_9f07,
            0x05d7_c214,
            0xa202_8bd9,
            0xd19c_12b5,
            0xb94e_16de,
            0xe883_d0cb,
            0x4e3c_50a2,
        ];
        assert_eq!(chacha20_block(&key, 1, &nonce), want);
    }

    #[test]
    fn csprng_stream_is_deterministic_per_key() {
        let mut a = Csprng::new([7u8; 32], [3u8; 12]);
        let mut b = Csprng::new([7u8; 32], [3u8; 12]);
        let mut x = [0u8; 200];
        let mut y = [0u8; 200];
        a.fill_bytes(&mut x);
        b.fill_bytes(&mut y);
        assert_eq!(x, y);
        // A different key gives a different stream.
        let mut c = Csprng::new([8u8; 32], [3u8; 12]);
        let mut z = [0u8; 200];
        c.fill_bytes(&mut z);
        assert_ne!(x, z);
    }

    #[test]
    fn csprng_fills_arbitrary_lengths_and_streams_across_blocks() {
        let mut rng = Csprng::new([1u8; 32], [2u8; 12]);
        // 1000 bytes spans 16 blocks; every byte must be written and the
        // sequence must not restart at a block boundary.
        let mut buf = [0u8; 1000];
        rng.fill_bytes(&mut buf);
        let first_64: [u8; 64] = buf[..64].try_into().unwrap();
        let second_64: [u8; 64] = buf[64..128].try_into().unwrap();
        assert_ne!(first_64, second_64);
        assert!(buf.iter().any(|&b| b != 0));
        assert_eq!(rng.bytes_since_rekey(), 1000);
        // 0 and 1 byte cases must not misbehave.
        rng.fill_bytes(&mut []);
        let mut one = [0u8; 1];
        rng.fill_bytes(&mut one);
        assert_eq!(rng.bytes_since_rekey(), 1001);
    }

    #[test]
    fn csprng_reports_when_a_rekey_is_due() {
        let mut rng = Csprng::new([9u8; 32], [9u8; 12]);
        rng.set_rekey_threshold(128);
        assert!(!rng.needs_rekey());
        let mut buf = [0u8; 128];
        rng.fill_bytes(&mut buf);
        assert!(rng.needs_rekey());
        rng.rekey([10u8; 32], [10u8; 12]);
        assert!(!rng.needs_rekey());
        assert_eq!(rng.bytes_since_rekey(), 0);
    }

    #[test]
    fn csprng_below_is_bounded() {
        let mut rng = Csprng::new([4u8; 32], [5u8; 12]);
        for _ in 0..1000 {
            assert!(<Csprng as RandomSource>::below(&mut rng, 7) < 7);
        }
        assert_eq!(<Csprng as RandomSource>::below(&mut rng, 0), 0);
        assert_eq!(<Csprng as RandomSource>::below(&mut rng, 1), 0);
    }

    #[test]
    fn debug_never_prints_key_material() {
        let rng = Csprng::new([0xABu8; 32], [0xCDu8; 12]);
        let s = alloc::format!("{rng:?}");
        assert!(!s.contains("171"), "{s}");
        assert!(s.contains("Csprng"), "{s}");
    }
}
