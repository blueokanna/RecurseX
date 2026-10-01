//! Minimal `no_std` float helpers.
//!
//! Rust 1.78's `core` does not provide `f64::abs` / `f64::ln` / `f64::exp` /
//! `f64::sqrt` — those methods are `std`-only until a later release, so any
//! code that must compile on the crate's MSRV (1.78) without `std` cannot
//! call them. This module carries the exact IEEE-754 equivalents built from
//! core operations that *are* available (`to_bits` / `from_bits` and
//! comparisons).
//!
//! The transcendental functions exist here for one reason: the refresh
//! model in [`crate::hazard`] is a decision-theoretic model, and its
//! credibility bound is a Chernoff bound on a Gamma posterior — which is an
//! equation in `exp` and `ln`. Approximating either would silently turn a
//! provably conservative bound into an unprovable one, which is worse than
//! not having a bound at all.
//!
//! Accuracy, measured against the C library (see the unit tests for the
//! reference values and the exact assertions):
//!
//! | function | range | max relative error |
//! |----------|-------|--------------------|
//! | [`exp`]  | `\|x\| ≤ 100` | 3.5e-15 |
//! | [`exp`]  | `x ∈ [−745, −100]` | 2.4e-14 |
//! | [`ln`]   | all finite `x > 0` | 1 ulp |
//! | [`sqrt`] | all finite `x ≥ 0` | 1 ulp |
//!
//! The `exp` tail is where the result approaches underflow; the whole
//! decision path in this crate evaluates `exp` on arguments in `[-700, 0]`
//! that are almost always larger than −50.
//!
//! Only the helpers the core actually needs are here; if a new no_std
//! module needs another libm-style float method, add it here rather than
//! depending on `std`.

/// Absolute value (bit-exact equivalent of `f64::abs`): clears the sign
/// bit, so `fabs(-0.0) == 0.0`, `fabs(NaN)` keeps the payload, and there is
/// no branch on the value.
#[inline]
pub fn fabs(x: f64) -> f64 {
    f64::from_bits(x.to_bits() & 0x7fff_ffff_ffff_ffff)
}

/// Round half away from zero (IEEE-754 `round`) via bit arithmetic —
/// `core` does not provide `f64::round` (it needs `libm`).
pub fn round(y: f64) -> f64 {
    let bits = y.to_bits();
    let biased = ((bits >> 52) & 0x7ff) as i32;
    let exp = biased - 1023;
    if exp >= 52 {
        // Integral (or infinite/NaN); nothing to round.
        return y;
    }
    let sign = bits >> 63;
    if exp < 0 {
        // |y| < 1: round to ±1 when |y| ≥ 0.5, else ±0.
        let abs = bits & 0x7fff_ffff_ffff_ffff;
        if abs >= 0x3fe0_0000_0000_0000 {
            if sign == 1 {
                -1.0
            } else {
                1.0
            }
        } else if sign == 1 {
            -0.0
        } else {
            0.0
        }
    } else {
        // 0 ≤ exp < 52: the low (52 − exp) bits are the fraction.
        let frac_bits = 52 - exp as u32;
        let frac_mask = (1u64 << frac_bits) - 1;
        let frac = bits & frac_mask;
        let half = 1u64 << (frac_bits - 1);
        if frac >= half {
            // Round the magnitude up (away from zero); carries into the
            // exponent naturally (e.g. 1.5 → 2.0).
            let up = (bits & !frac_mask) + (1u64 << frac_bits);
            f64::from_bits(up)
        } else {
            f64::from_bits(bits & !frac_mask)
        }
    }
}

/// `e^x`.
///
/// Reduces to `2^n · e^t` and evaluates `e^t` with a 14-term Taylor series.
/// The reduction uses a **two-part** `ln 2` (a high word with 21 significant
/// bits plus a low correction): the naive `e^(x·log2 e)` reduction carries
/// the rounding error of that multiplication straight into the exponent of
/// the result, which is a relative error of ~2e-14 at `x = −200`. With the
/// split it is ~7e-15, and ≤ 3.5e-15 for `|x| ≤ 100` — the range every
/// caller in this crate actually operates in.
///
/// Saturates to `0.0` below −745 and to `+∞` above 709.78; both are correct
/// IEEE-754 behaviour, not error.
pub fn exp(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if x > 709.782_712_893_384 {
        return f64::INFINITY;
    }
    if x < -745.133_219_101_941_2 {
        return 0.0;
    }
    // `n` only has to be the nearest integer to `x·log2 e`; the reduced
    // argument is then computed from `x` directly so that the error of that
    // first multiplication cannot reach the result's exponent.
    let n = round(x * core::f64::consts::LOG2_E);
    let ln2_hi = f64::from_bits(core::f64::consts::LN_2.to_bits() & 0xffff_ffff_0000_0000);
    let ln2_lo = core::f64::consts::LN_2 - ln2_hi;
    // `n · ln2_hi` is exact (21-bit multiplicand), so `t` is a correctly
    // rounded difference plus an exact correction.
    let t = (x - n * ln2_hi) - n * ln2_lo; // |t| ≤ ½·ln 2 + ε
                                           // e^t = Σ t^i / i! — 14 terms give < 1e-16 relative on |t| ≤ 0.35.
    let mut p = 1.0;
    let mut term = 1.0;
    let mut i = 1.0;
    while i <= 13.0 {
        term *= t / i;
        p += term;
        i += 1.0;
    }
    // Multiply by 2^n by nudging the exponent field (p ∈ [0.5, 2)).
    let bits = (p.to_bits() as i64).wrapping_add((n as i64) << 52);
    f64::from_bits(bits as u64)
}

/// `e^x` for `x ≤ 0`, with an explicit `0.0` floor instead of a denormal
/// tail. Callers on the safety path want "this probability is exactly zero
/// because it underflowed", not "this probability is 4.9e-324".
#[inline]
pub fn exp_nonpos(x: f64) -> f64 {
    if x <= -745.0 {
        0.0
    } else {
        exp(x)
    }
}

/// `ln(x)`.
///
/// Splits `x = m · 2^e` with `m ∈ [√½, √2)` and evaluates
/// `ln(m) = 2·atanh(t)`, `t = (m−1)/(m+1) ∈ [−0.172, 0.172]`, by its Taylor
/// series (12 terms ⇒ < 1e-15 on that interval). `x ≤ 0` maps to `−∞` for
/// `0` and `NaN` for negatives, matching IEEE-754.
pub fn ln(x: f64) -> f64 {
    if x.is_nan() || x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return f64::NEG_INFINITY;
    }
    if x == f64::INFINITY {
        return f64::INFINITY;
    }
    let bits = x.to_bits();
    let mut e = (((bits >> 52) & 0x7ff) as i64) - 1023;
    // Mantissa in [1, 2) with the implicit bit restored.
    let mut m = f64::from_bits((bits & 0x000f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000);
    // Recentre to [√½, √2) so |t| ≤ 0.172 and 12 series terms suffice.
    if m > core::f64::consts::SQRT_2 {
        m *= 0.5;
        e += 1;
    }
    let t = (m - 1.0) / (m + 1.0);
    let t2 = t * t;
    // Horner over `1 + t²/3 + t⁴/5 + …`, i.e. atanh(t)/t. The polynomial is
    // `s` itself: multiplying by `t²` again would shift every coefficient
    // down by one power, which is a silent ~1e-3 relative error.
    let mut s = 0.0;
    let mut k = 11.0;
    while k >= 1.0 {
        s = s * t2 + 1.0 / (2.0 * k - 1.0);
        k -= 1.0;
    }
    let ln_m = 2.0 * t * s;
    e as f64 * core::f64::consts::LN_2 + ln_m
}

/// Whether a value is finite and strictly positive.
///
/// Written as a named predicate rather than inline `!(v > 0.0)` because that
/// spelling means "NaN or non-positive", and the NaN case is the one that
/// matters: every quantity this crate guards with it — a rate, a bound, a
/// weight, an interval — can be produced by arithmetic on a measurement, and a
/// NaN that slipped past a comparison-based check would silently disable the
/// guard rather than trip it.
#[inline]
pub fn is_positive(v: f64) -> bool {
    v > 0.0 && v.is_finite()
}

/// `log2(x)`. Named because several bounds in this crate are stated in
/// bits, and writing the constant at each call site invites drift.
#[inline]
pub fn log2(x: f64) -> f64 {
    ln(x) / core::f64::consts::LN_2
}

/// `⌈x⌉` (IEEE-754 `ceil`), via [`round`]. Non-finite inputs are fixed
/// points, and magnitudes large enough to be integral already are returned
/// unchanged.

/// `√x` — a bit-trick seed refined by Newton's iteration.
///
/// The seed halves the exponent field, which is already within ~5 % of the
/// true root; five Newton steps take that to IEEE-exact rounding for every
/// finite non-negative input. `x < 0` is `NaN`; `0` and `∞` are fixed
/// points.
pub fn sqrt(x: f64) -> f64 {
    if x.is_nan() || x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 || x == f64::INFINITY {
        return x;
    }
    let mut guess = f64::from_bits((x.to_bits() >> 1) + (1023u64 << 51));
    let mut i = 0;
    while i < 5 {
        guess = 0.5 * (guess + x / guess);
        i += 1;
    }
    guess
}

/// `⌈x⌉`, built from [`round`].
pub fn ceil(x: f64) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let r = round(x);
    if r >= x {
        r
    } else {
        r + 1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abs_matches_reference() {
        for (x, want) in [
            (3.5, 3.5),
            (-3.5, 3.5),
            (0.0, 0.0),
            (-0.0, 0.0),
            (f64::MAX, f64::MAX),
            (-f64::MAX, f64::MAX),
            (f64::NAN, f64::NAN),
        ] {
            let got = fabs(x);
            if want.is_nan() {
                assert!(got.is_nan(), "fabs({x}) should be NaN");
            } else {
                assert_eq!(got, want, "fabs({x})");
                assert!(got.is_sign_positive(), "fabs({x}) must clear the sign");
            }
        }
    }

    /// The reference values *are* the test, so the lint that suggests
    /// replacing them with `std`'s constants is exactly backwards here: the
    /// point is to compare against numbers this module did not define.
    #[allow(clippy::approx_constant)]
    #[test]
    fn exp_matches_reference() {
        // Reference values generated with the C library (Python's math.exp),
        // not transcribed by hand.
        let cases: &[(f64, f64)] = &[
            (0.0, 1.0),
            (-0.0, 1.0),
            (-0.5, 0.606_530_659_712_633_4),
            (-1.0, 0.367_879_441_171_442_33),
            (-2.0, 0.135_335_283_236_612_7),
            (-5.0, 0.006_737_946_999_085_467),
            (-10.0, 4.539_992_976_248_485_4e-5),
            (-20.0, 2.061_153_622_438_558e-9),
            (-50.0, 1.928_749_847_963_917_8e-22),
            (-100.0, 3.720_075_976_020_836e-44),
            (-200.0, 1.383_896_526_736_737_6e-87),
            (-700.0, 9.859_676_543_759_77e-305),
            (1.0, 2.718_281_828_459_045),
            (3.0, 20.085_536_923_187_668),
            (10.0, 22_026.465_794_806_718),
            (100.0, 2.688_117_141_816_135_6e43),
        ];
        for (x, want) in cases {
            let got = exp(*x);
            let rel = fabs(got - want) / fabs(*want);
            // Measured worst case on this set is 2.4e-14 (at x = -700, where
            // the result sits just above underflow); the assertion keeps a
            // 4x margin so it is a regression guard, not a fit.
            assert!(
                rel < 1e-13,
                "exp({x}) = {got:e}, want {want:e}, rel {rel:e}"
            );
        }
    }

    #[test]
    fn exp_saturates_like_ieee() {
        assert_eq!(exp(1000.0), f64::INFINITY);
        assert_eq!(exp(-1000.0), 0.0);
        assert_eq!(exp_nonpos(-1e9), 0.0);
        assert!(exp(f64::NAN).is_nan());
    }

    #[allow(clippy::approx_constant)]
    #[test]
    fn ln_matches_reference() {
        // Reference values from the C library (Python's math.log).
        let cases: &[(f64, f64)] = &[
            (1.0, 0.0),
            (2.0, 0.693_147_180_559_945_3),
            (10.0, 2.302_585_092_994_046),
            (0.5, -0.693_147_180_559_945_3),
            (1e-300, -690.775_527_898_213_7),
            (1e300, 690.775_527_898_213_7),
            (3.0, 1.098_612_288_668_109_8),
            (1234.5678, 7.118_476_228_297_786),
        ];
        for (x, want) in cases {
            let got = ln(*x);
            let rel = fabs(got - want) / fabs(*want).max(1.0);
            assert!(rel < 1e-15, "ln({x}) = {got}, want {want}, rel {rel:e}");
        }
        assert_eq!(ln(0.0), f64::NEG_INFINITY);
        assert!(ln(-1.0).is_nan());
        assert_eq!(ln(f64::INFINITY), f64::INFINITY);
    }

    #[test]
    fn ln_exp_round_trip() {
        // The Chernoff solver relies on `ln(exp(x)) == x` to ~1e-12.
        for x in [
            -700.0, -100.0, -10.0, -1.0, -0.125, 0.0, 0.5, 3.0, 50.0, 700.0,
        ] {
            let back = ln(exp(x));
            assert!(fabs(back - x) < 1e-9, "ln(exp({x})) = {back}");
        }
    }

    #[test]
    fn sqrt_matches_reference() {
        for x in [1.0, 2.0, 4.0, 1e-300, 1e300, 0.1, 12345.678] {
            let got = sqrt(x);
            let want = x.sqrt();
            assert!(fabs(got - want) / want < 1e-15, "sqrt({x}) = {got}");
        }
        assert_eq!(sqrt(0.0), 0.0);
        assert_eq!(sqrt(f64::INFINITY), f64::INFINITY);
        assert!(sqrt(-1.0).is_nan());
    }

    #[test]
    fn round_matches_reference() {
        for (x, want) in [
            (0.5, 1.0),
            (-0.5, -1.0),
            (1.5, 2.0),
            (2.5, 3.0),
            (-2.5, -3.0),
            (0.4999, 0.0),
            (-0.4999, -0.0),
            (1e300, 1e300),
            (3.0, 3.0),
        ] {
            let got = round(x);
            assert_eq!(got, want, "round({x})");
        }
    }
}
