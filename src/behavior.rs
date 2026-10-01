//! Keyed behavioural identity.
//!
//! A DNS answer has two identities. One is *where it lives*: a name, a type, a
//! class, an ECS partition — the tuple the cache is keyed on. The other is
//! *how it behaves*: how fast the data moves, how far the authoritative TTL
//! wanders, how expensive the record is to re-resolve, and how well its
//! authenticity was established.
//!
//! Decisions that need the second identity reconstruct it from the entry every
//! time, and where two entries tie, the tie is broken by the first identity —
//! which is to say, by the name. Breaking a tie by name is not neutral, because
//! names are chosen by whoever wants the answer and are visible on the wire.
//!
//! * **Fleet correlation.** Every resolver holding the same two entries breaks
//!   the same tie the same way. A fleet sharing a configuration therefore
//!   converges on identical schedules, and the refresh load it puts on an
//!   authoritative arrives as one thundering herd rather than as a spread.
//! * **Off-path prediction.** If the tie-break is a public function of the
//!   name, an observer who can see the query knows which entry we will look at
//!   next. That is a targeting primitive: the window between an entry's last
//!   observation and its next refresh is precisely the window in which a forged
//!   answer has its best chance of being the one that ends up in the model.
//!
//! This module derives a **keyed, coarse** behavioural identity and offers it
//! wherever a tie has to be broken. *Coarse*, because the identity has to be
//! stable: it orders work, so an identity that moved every time the model did
//! would reshuffle the order on nearly every observation and the decorrelation
//! it buys would be noise. *Keyed*, because the order must be reproducible for
//! us and unguessable for everyone else. The key is a 128-bit secret drawn from
//! the OS at startup and never exported — there is deliberately no accessor that
//! returns it, because the only failure mode of such an accessor is that
//! someone logs it.
//!
//! # What this is not
//!
//! It is not an address, and it cannot route a packet. A hash computed at the
//! sender cannot select a destination, because the destination's behaviour is
//! not known at the sender; and forwarding by hash distance still requires a
//! structure that maps every region of the hash space to a next hop, which is a
//! routing table under a different name. What *is* available to a resolver — and
//! what this module provides — is binding an internal decision to measured
//! behaviour without letting the name, and therefore an attacker, choose it.

use core::fmt;

use alloc::vec::Vec;

use crate::float;
use crate::name::Name;
use crate::prng::siphash24_128;
use crate::risk::{Consequence, TrustLevel};
use crate::stability::StabilityModel;

/// Domain-separation tag.
///
/// The keyed hash here and the ones wrapped in [`crate::prng`] are the same
/// primitive; the tag is what keeps a fingerprint from ever colliding with a
/// value computed for another purpose, even if two call sites were to be handed
/// the same key by accident.
const DOMAIN_TAG: &[u8; 16] = b"recursex:behav:1";

/// The `floor(log2 v) + 64` offset. Buckets are one doubling wide, and the
/// offset puts ordinary DNS magnitudes (roughly `1e-6` to `1e6`) in the middle
/// of the byte rather than at its bottom.
const LOG2_OFFSET: f64 = 64.0;

/// Quantise a positive magnitude to one bucket per doubling.
///
/// The identity has to survive the model moving. An exact value does not: the
/// hazard bound and the TTL EWMA both drift continuously, so a fingerprint over
/// their exact bits would change on nearly every observation and the order it
/// produced would be noise. Quantising at one bit per octave means the class
/// changes only when the behaviour has moved by a *factor of two* — which is a
/// change of regime, not a change of reading.
///
/// Non-positive, non-finite and zero inputs map to bucket 0 rather than
/// panicking: this is called from the refresh path with values derived from
/// measurements, and a resolver must not fault on a measurement.
pub fn log2_bucket(value: f64) -> u8 {
    if !float::is_positive(value) {
        return 0;
    }
    let l = float::log2(value);
    // `floor` without a `floor`: `ceil` is exact, and the two agree except on
    // integers, where `ceil` is already the answer. `crate::float` has no
    // `floor` because nothing else needed one; deriving it here keeps the
    // dependency surface unchanged.
    let c = float::ceil(l);
    let f = if c == l { c } else { c - 1.0 };
    let b = f + LOG2_OFFSET;
    if b <= 0.0 {
        0
    } else if b >= 255.0 {
        255
    } else {
        b as u8
    }
}

/// A coarse, stable description of how a record behaves.
///
/// Every field is a quantised bucket, so two records with the same class are
/// interchangeable for the purposes of ordering: they will change at the same
/// rate, cost the same to re-resolve, and deserve the same trust.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BehaviorClass {
    /// Consequence class of the record in the role it plays in this answer,
    /// as the stable code from [`role_code`].
    pub role: u8,
    /// Quantised one-sided bound on the change rate (changes per second).
    pub change: u8,
    /// Quantised authoritative TTL, in seconds.
    pub ttl: u8,
    /// Quantised TTL volatility.
    pub volatility: u8,
    /// How well the authenticity of the data was established, as the stable
    /// code from [`trust_code`].
    ///
    /// A code rather than a quantised penalty: the penalties are `1, 2, 5, 10`,
    /// and bracketing them by doubling would put the two weakest levels in one
    /// bucket and the two strongest in another — merging exactly the distinction
    /// the ladder exists to draw.
    pub trust: u8,
    /// Quantised expected resolution cost, in milliseconds.
    pub cost: u8,
}

impl BehaviorClass {
    /// Derive a class from a model, the role the data plays, how well its
    /// authenticity was established, and what re-resolving it costs.
    ///
    /// The change-rate term is the *upper bound* rather than the mean. The
    /// bound is what the refresh decision is made on, so an ordering derived
    /// from the mean would be an ordering of a quantity the system does not
    /// otherwise use — two records could share a mean while differing by orders
    /// of magnitude in how fast they *could* be moving, and those two belong in
    /// different classes.
    pub fn from_model(
        model: &StabilityModel,
        role: Consequence,
        trust: TrustLevel,
        cost_ms: f64,
    ) -> Self {
        Self {
            role: role_code(role),
            change: log2_bucket(model.hazard().hazard_upper_bound()),
            ttl: log2_bucket(model.ttl_ewma()),
            volatility: log2_bucket(model.ttl_volatility()),
            trust: trust_code(trust),
            cost: log2_bucket(cost_ms),
        }
    }

    /// The canonical byte form folded into a fingerprint.
    ///
    /// Fixed width and fully populated, so two classes cannot collide by
    /// producing the same bytes in different shapes. The trailing byte is
    /// reserved and written as zero — bumping it is how a future revision
    /// invalidates every fingerprint derived under the old definition.
    pub fn canonical_bytes(self) -> [u8; 8] {
        [
            self.role,
            self.change,
            self.ttl,
            self.volatility,
            self.trust,
            self.cost,
            0,
            0,
        ]
    }
}

/// The secret behind every fingerprint.
///
/// There is no constructor from a string, no accessor that returns the key, and
/// no `Display`. The only ways to obtain one are [`FingerprintKey::random`]
/// (the deployment path) and [`FingerprintKey::from_words`] (tests and
/// reconstruction from an out-of-band secret store). `Debug` redacts, because
/// the value's only realistic path to an attacker in a well-built program is a
/// log line.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FingerprintKey {
    k0: u64,
    k1: u64,
}

impl FingerprintKey {
    /// A key from two 64-bit words.
    pub const fn from_words(k0: u64, k1: u64) -> Self {
        Self { k0, k1 }
    }

    /// A fresh key from OS entropy.
    ///
    /// This is the constructor every deployment should reach: the entire
    /// security property — that an off-path observer cannot predict the
    /// ordering — is a property of this key being unknown to them.
    #[cfg(feature = "std")]
    pub fn random() -> Self {
        let mut rng = crate::entropy::secure_random();
        use crate::prng::RandomSource;
        let k0 = rng.next_u64();
        let k1 = rng.next_u64();
        Self::from_words(k0, k1)
    }

    /// Compute a 128-bit keyed tag over `message`.
    pub fn tag(&self, message: &[u8]) -> u128 {
        u128::from_le_bytes(siphash24_128(self.k0, self.k1, message))
    }
}

impl fmt::Debug for FingerprintKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FingerprintKey(<redacted>)")
    }
}

/// The keyed behavioural identity of one entry.
///
/// `Debug` prints the value, not the key. The fingerprint is not itself secret
/// — it is a coarse class combined with a public name — but it is *unpredictable
/// without the key*, and that is the whole difference between a schedule an
/// attacker can aim at and one they cannot.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BehaviorFingerprint(u128);

impl BehaviorFingerprint {
    /// The raw value, for ordering.
    ///
    /// This is the whole interface. The value is used as a tie-break in an
    /// ordering, so it is compared and nothing else; there is deliberately no
    /// method that turns it into a *time*, because a fingerprint-derived offset
    /// that could move a refresh deadline is a scheduling convenience that
    /// costs a correctness property, and the crate does not have one.
    pub const fn as_u128(self) -> u128 {
        self.0
    }
}

impl fmt::Debug for BehaviorFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BehaviorFingerprint({:032x})", self.0)
    }
}

/// The ordered form of one class, ready to be tagged.
///
/// The name is appended in wire form rather than as text: the wire form is
/// canonical — lower-case, with a single trailing root label — by the time a
/// [`Name`] exists, so two spellings of the same name cannot produce two
/// fingerprints, and appending it needs no normalisation or escaping.
fn tagged_message(class: BehaviorClass, name: &Name) -> Vec<u8> {
    let bytes = class.canonical_bytes();
    let mut msg = Vec::with_capacity(DOMAIN_TAG.len() + bytes.len() + name.wire_len());
    msg.extend_from_slice(DOMAIN_TAG);
    msg.extend_from_slice(&bytes);
    msg.extend_from_slice(name.as_bytes());
    msg
}

/// The keyed behavioural fingerprint of `name` in `class`.
///
/// Two entries with the same fingerprint behave the same way and are the same
/// name; the fingerprint is therefore stable for as long as the class is, and
/// changes only when the behaviour has moved by a factor of two in some
/// dimension (see [`log2_bucket`]).
pub fn fingerprint_of(
    key: &FingerprintKey,
    class: BehaviorClass,
    name: &Name,
) -> BehaviorFingerprint {
    BehaviorFingerprint(key.tag(&tagged_message(class, name)))
}

/// A stable code for a consequence class.
///
/// Deliberately a `match` and not `as u8`: a fingerprint is a *persisted*
/// quantity (a diagnostic label), so it must not change because somebody
/// reordered an enum. Assigning the code here makes that a compile-time-visible
/// decision rather than an accident of declaration order.
pub const fn role_code(role: Consequence) -> u8 {
    match role {
        Consequence::Low => 0,
        Consequence::Medium => 1,
        Consequence::High => 2,
        Consequence::Critical => 3,
        Consequence::Absolute => 4,
    }
}

/// A stable code for a trust level, for the same reason as
/// [`role_code`].
pub const fn trust_code(trust: TrustLevel) -> u8 {
    match trust {
        TrustLevel::ChainAnchored => 0,
        TrustLevel::CryptoVerified => 1,
        TrustLevel::Unverified => 2,
        TrustLevel::Indeterminate => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::{Consequence, TrustLevel};

    #[cfg(not(feature = "std"))]
    use alloc::format;

    fn name(s: &str) -> Name {
        Name::from_ascii(s).expect("valid name")
    }

    fn class(role: Consequence, ttl: f64, cost: f64) -> BehaviorClass {
        BehaviorClass {
            role: role_code(role),
            change: log2_bucket(1.0 / 300.0),
            ttl: log2_bucket(ttl),
            volatility: log2_bucket(0.0),
            trust: trust_code(TrustLevel::Unverified),
            cost: log2_bucket(cost),
        }
    }

    #[test]
    fn quantiser_is_one_bucket_per_doubling() {
        assert_eq!(log2_bucket(1.0), 64);
        assert_eq!(log2_bucket(2.0), 65);
        assert_eq!(log2_bucket(4.0), 66);
        assert_eq!(log2_bucket(0.5), 63);
        assert_eq!(log2_bucket(0.25), 62);
        // An order of magnitude is a hair over three doublings.
        assert_eq!(log2_bucket(1000.0) - log2_bucket(1.0), 9);
    }

    #[test]
    fn quantiser_never_faults_on_a_measurement() {
        // Every one of these can fall out of an arithmetic path that has been
        // fed a degenerate sample. None may panic, and none may wrap.
        for v in [
            0.0,
            -0.0,
            -1.0,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            1e-300,
            1e300,
        ] {
            // The quantiser must be total: every `f64`, including the
            // degenerate ones, lands in a byte. A panic here would be a
            // remote fault, because these values come from measurements.
            let b = log2_bucket(v);
            assert!((0..=255u8).contains(&b), "bucket out of range for {v}: {b}");
        }
        assert_eq!(log2_bucket(0.0), 0);
        assert_eq!(log2_bucket(-1.0), 0);
        assert_eq!(log2_bucket(f64::NAN), 0);
        assert_eq!(log2_bucket(f64::INFINITY), 0);
        assert_eq!(log2_bucket(1e-300), 0);
        assert_eq!(log2_bucket(1e300), 255);
    }

    #[test]
    fn a_fingerprint_is_stable_for_a_fixed_class_and_name() {
        let key = FingerprintKey::from_words(0x1111_2222_3333_4444, 0x5555_6666_7777_8888);
        let c = class(Consequence::Low, 300.0, 12.0);
        let n = name("www.example.com");
        let a = fingerprint_of(&key, c, &n);
        let b = fingerprint_of(&key, c, &n);
        assert_eq!(a, b);
        assert_eq!(a.as_u128(), b.as_u128());
    }

    #[test]
    fn the_key_is_what_makes_the_fingerprint_unpredictable() {
        let c = class(Consequence::Low, 300.0, 12.0);
        let n = name("www.example.com");
        let k1 = FingerprintKey::from_words(1, 2);
        let k2 = FingerprintKey::from_words(3, 4);
        // Same class, same name, different secrets: the fingerprints must
        // differ, or the key would be doing nothing.
        assert_ne!(
            fingerprint_of(&k1, c, &n).as_u128(),
            fingerprint_of(&k2, c, &n).as_u128()
        );
    }

    #[test]
    fn a_class_separates_names_that_share_a_behaviour() {
        let key = FingerprintKey::from_words(0xdead_beef_dead_beef, 0xfeed_face_feed_face);
        let c = class(Consequence::Low, 300.0, 12.0);
        let a = fingerprint_of(&key, c, &name("a.example.com"));
        let b = fingerprint_of(&key, c, &name("b.example.com"));
        assert_ne!(
            a, b,
            "distinct names in one class must not share a fingerprint"
        );
    }

    #[test]
    fn a_class_separates_names_that_share_a_spelling_across_roles() {
        let key = FingerprintKey::from_words(7, 9);
        let n = name("example.com");
        // The same name is a different *behaviour* as an answer and as
        // delegation data: it moves for different reasons and its staleness has
        // a different consequence. They must not be ordered together.
        let a = fingerprint_of(&key, class(Consequence::Low, 300.0, 12.0), &n);
        let b = fingerprint_of(&key, class(Consequence::Critical, 300.0, 12.0), &n);
        assert_ne!(a, b);
    }

    #[test]
    fn a_coarse_class_is_robust_to_noise_in_the_model() {
        // Two readings of the same record that differ by 20% — far more than
        // measurement noise, far less than a regime change — must land in the
        // same class. If they did not, the fingerprint would churn and the
        // decorrelation it buys would be lost.
        let c1 = class(Consequence::Low, 300.0, 12.0);
        let c2 = class(Consequence::Low, 300.0 * 1.2, 12.0 * 1.2);
        assert_eq!(c1, c2);
        // A factor of two is a regime change and must move it.
        let c3 = class(Consequence::Low, 600.0, 12.0);
        assert_ne!(c1, c3);
    }

    #[test]
    fn fingerprints_spread_a_fleet_rather_than_piling_up() {
        // The property the fingerprint exists for, measured directly: across
        // many names in one class, the fingerprints must cover the ordering
        // space. Ordering by name does not do this — it is a *different* order,
        // not a spread one, and it is the same different order on every
        // resolver in a fleet.
        let key = FingerprintKey::from_words(0x0f0f_0f0f_0f0f_0f0f, 0xf0f0_f0f0_f0f0_f0f0);
        let c = class(Consequence::Low, 300.0, 12.0);
        const BINS: usize = 16;
        const N: usize = 4096;
        let mut bins = [0usize; BINS];
        for i in 0..N {
            let n = name(&format!("host{i}.example.com"));
            let fp = fingerprint_of(&key, c, &n).as_u128();
            let idx = ((fp >> 100) as usize) % BINS;
            if let Some(b) = bins.get_mut(idx) {
                *b += 1;
            }
        }
        let expected = N / BINS;
        for (i, &count) in bins.iter().enumerate() {
            assert!(
                count > expected / 2 && count < expected * 2,
                "bin {i} holds {count}, expected about {expected}"
            );
        }
    }

    #[test]
    fn the_debug_form_never_prints_the_key() {
        let key = FingerprintKey::from_words(0xaaaa_aaaa_aaaa_aaaa, 0xbbbb_bbbb_bbbb_bbbb);
        let s = format!("{key:?}");
        assert_eq!(s, "FingerprintKey(<redacted>)");
        assert!(!s.contains("aaaa"), "key material leaked into Debug");
    }
}
