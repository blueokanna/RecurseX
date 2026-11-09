//! OS entropy access for anti-spoofing seeding (std only).
//!
//! The resolver's anti-spoofing defence (RFC 5452) has two halves, and this
//! module supplies the first: unpredictable *key material*. The second half
//! — a generator that stays unpredictable after an attacker has observed a
//! long prefix of its output — is [`crate::prng::Csprng`], a ChaCha20
//! counter-mode stream. Seeding a non-cryptographic generator from OS
//! entropy does not make it a CSPRNG; using a cipher in counter mode does.
//!
//! Every networking build uses courierust's operating-system RNG. Entropy
//! failure aborts construction; hash output and wall-clock values are never
//! substituted for secret key material. A failed rekey preserves the current
//! secret and retries at the next opportunity.

use crate::prng::Csprng;

/// Fill `buf` from the operating-system cryptographic RNG.
pub fn fill(buf: &mut [u8]) -> bool {
    courierust::courierust_tls::crypto::rng::fill_random(buf)
}

/// A 64-bit OS-derived seed, for the *non-security* generator
/// ([`crate::prng::SplitMix64`]). Security-critical draws must use
/// [`secure_random`].
pub fn seed_u64() -> u64 {
    let mut bytes = [0u8; 8];
    assert!(fill(&mut bytes), "operating-system entropy unavailable");
    u64::from_le_bytes(bytes)
}

/// A ChaCha20 CSPRNG seeded from OS key material.
///
/// This is the generator the query-ID and 0x20 code paths must use. It is
/// *not* `SplitMix64` with a good seed: the cipher's output does not reveal
/// its key, so an attacker who observes any number of query IDs still cannot
/// compute the next one, which is the exact property RFC 5452 §9.2 asks for
/// and the exact property a 64-bit arithmetic generator lacks.
pub fn secure_random() -> Csprng {
    try_secure_random().expect("operating-system entropy unavailable")
}

/// Construct a generator, reporting OS entropy failure to a fallible caller.
pub fn try_secure_random() -> crate::error::Result<Csprng> {
    random_with(fill)
}

fn random_with(mut source: impl FnMut(&mut [u8]) -> bool) -> crate::error::Result<Csprng> {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    if !source(&mut key) || !source(&mut nonce) {
        return Err(crate::error::Error::internal(
            "operating-system entropy unavailable",
        ));
    }
    Ok(Csprng::new(key, nonce))
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
    if !fill(&mut key) || !fill(&mut nonce) {
        return false;
    }
    rng.rekey(key, nonce);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_failure_never_constructs_a_predictable_generator() {
        assert!(random_with(|_| false).is_err());
        let mut calls = 0;
        assert!(random_with(|bytes| {
            calls += 1;
            bytes.fill(42);
            calls == 1
        })
        .is_err());
        assert_eq!(calls, 2, "nonce entropy is required as well as key entropy");
    }

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
