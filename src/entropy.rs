//! OS entropy access for anti-spoofing seeding (std only).
//!
//! The resolver randomizes query IDs and 0x20 QNAME case to defend against
//! cache poisoning (RFC 5452). That defence is only as strong as the
//! generator's seed: a predictable seed lets an off-path attacker predict
//! the next ID/case. This module supplies cryptographically strong OS
//! entropy, with an honest fallback chain:
//!
//! 1. **courierust's CSPRNG** — `courierust_tls::crypto::rng::fill_random`
//!    uses the OS cryptographic RNG (`RtlGenRandom` on Windows,
//!    `/dev/urandom` on Unix). Available whenever any feature that pulls
//!    in courierust is enabled (`dot`, `doh`, `doh3`, `doq`, `dnssec`).
//! 2. **`std::hash::RandomState`** — pure-std fallback. `RandomState`
//!    seeds its SipHash keys from OS randomness once per thread, so hashing
//!    a fixed value through a fresh instance yields unpredictable,
//!    per-process bytes. This is process entropy, not a per-call CSPRNG;
//!    it is used only when courierust is not compiled in.
//!
//! `SplitMix64::seeded()` consumes [`seed_u64`] so every resolver instance
//! starts from OS entropy, and the resolver reseeds its query-ID generator
//! periodically from the same source to stop state-recovery attacks.

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
        c[..n].copy_from_slice(&v[..n]);
    }
    true
}

/// A 64-bit OS-derived seed (for `SplitMix64`).
pub fn seed_u64() -> u64 {
    let mut b = [0u8; 16];
    if fill(&mut b) {
        u64::from_le_bytes(b[..8].try_into().unwrap())
            ^ u64::from_le_bytes(b[8..].try_into().unwrap())
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
