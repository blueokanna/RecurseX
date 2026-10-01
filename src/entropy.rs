//! OS entropy access for anti-spoofing seeding (std only).
//!
//! The resolver's anti-spoofing defence (RFC 5452) has two halves, and this
//! module supplies the first: unpredictable *key material*. The second half
//! — a generator that stays unpredictable after an attacker has observed a
//! long prefix of its output — is [`crate::prng::Csprng`], a ChaCha20
//! counter-mode stream. Seeding a non-cryptographic generator from OS
//! entropy does not make it a CSPRNG; using a cipher in counter mode does.
//!
//! Two sources of key material, in order of preference:
//!
//! 1. **courierust's CSPRNG** — `courierust_tls::crypto::rng::fill_random`
//!    uses the OS cryptographic RNG (`RtlGenRandom` on Windows,
//!    `/dev/urandom` on Unix). Available whenever any feature that pulls
//!    in courierust is enabled (`dot`, `doh`, `doh3`, `doq`, `dnssec`).
//! 2. **`std::hash::RandomState`** — pure-std fallback. `RandomState`
//!    seeds its SipHash keys from OS randomness once per thread, so hashing
//!    a counter through a fresh instance yields per-process bytes that an
//!    off-path attacker cannot predict. This is weaker than a kernel RNG
//!    and the module says so, but it is enough to give the cipher a secret
//!    key; the cipher, not the seed, is what provides the RFC 5452
//!    property after the first block.

use crate::prng::Csprng;

/// Fill `buf` with OS-derived entropy. Returns `false` only when every
/// source failed (process entropy via `RandomState` is the final fallback
/// and effectively never fails on a normal OS).
pub fn fill(buf: &mut [u8]) -> bool {
    // Preferred: courierust's OS CSPRNG when it is linked in.
    #[cfg(any(
        feature = "dot",
        feature = "doh",
        feature = "doh3",
        feature = "doq",
        feature = "dnssec"
    ))]
    {
        if courierust::courierust_tls::crypto::rng::fill_random(buf) {
            return true;
        }
    }
    // Fallback: RandomState-derived bytes (per-process entropy, pure std).
    // RandomState's SipHash keys come from OS randomness once per thread;
    // a per-call atomic counter is mixed in so consecutive draws differ
    // even though the key material is per-thread.
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0x243f_6a88_85a3_08d3);
    let rs = RandomState::new();
    for c in buf.chunks_mut(8) {
        let mut h = rs.build_hasher();
        h.write_u64(COUNTER.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed));
        let v = h.finish().to_le_bytes();
        let n = c.len().min(8);
        if let Some(dst) = c.get_mut(..n) {
            dst.copy_from_slice(crate::wire::capped(&v, n));
        }
    }
    true
}

/// A 64-bit OS-derived seed, for the *non-security* generator
/// ([`crate::prng::SplitMix64`]). Security-critical draws must use
/// [`secure_random`].
pub fn seed_u64() -> u64 {
    let mut b = [0u8; 16];
    if fill(&mut b) {
        let (lo, hi) = b.split_at(8);
        let lo = u64::from_le_bytes(lo.try_into().unwrap_or([0u8; 8]));
        let hi = u64::from_le_bytes(hi.try_into().unwrap_or([0u8; 8]));
        lo ^ hi
    } else {
        // Last resort: time plus a fresh RandomState-derived value.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mut b = [0u8; 8];
        let _ = fill(&mut b);
        t ^ u64::from_le_bytes(b)
    }
}

/// A ChaCha20 CSPRNG seeded from OS key material.
///
/// This is the generator the query-ID and 0x20 code paths must use. It is
/// *not* `SplitMix64` with a good seed: the cipher's output does not reveal
/// its key, so an attacker who observes any number of query IDs still cannot
/// compute the next one, which is the exact property RFC 5452 §9.2 asks for
/// and the exact property a 64-bit arithmetic generator lacks.
pub fn secure_random() -> Csprng {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    if !fill(&mut key) {
        // `RandomState` is the last fallback inside `fill` and effectively
        // never fails; if it somehow did, mix the wall clock so the key is
        // at least not a constant.
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        for (i, slot) in key.iter_mut().enumerate() {
            *slot = (t.rotate_left((i as u32) % 64) & 0xff) as u8;
        }
    }
    let _ = fill(&mut nonce);
    Csprng::new(key, nonce)
}

/// Rekey `rng` from OS entropy if it has produced its threshold of
/// keystream.
///
/// Returns whether a rekey happened, so a caller can count it. Called from
/// the hot path of the query-ID generator: a resolver that draws a few dozen
/// bytes per query crosses a one-mebibyte threshold a few times a minute, and
/// a `getrandom` call at that rate is not measurable.
pub fn rekey_if_due(rng: &mut Csprng) -> bool {
    if !rng.needs_rekey() {
        return false;
    }
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    let _ = fill(&mut key);
    let _ = fill(&mut nonce);
    rng.rekey(key, nonce);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_is_entropy_like() {
        // Two draws must differ (astronomically unlikely to collide).
        let a = seed_u64();
        let b = seed_u64();
        assert_ne!(a, b);
    }

    #[test]
    fn fill_fills_all_bytes() {
        let mut b = [0u8; 32];
        assert!(fill(&mut b));
        assert!(b.iter().any(|&x| x != 0));
    }
}
