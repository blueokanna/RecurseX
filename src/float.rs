//! Minimal `no_std` float helpers.
//!
//! Rust 1.78's `core` does not provide `f64::abs` / `f64::signum` /
//! `f64::mul_add` — those methods are `std`-only until a later release, so
//! any code that must compile on the crate's MSRV (1.78) without `std`
//! cannot call them. This module carries the exact IEEE-754 equivalents
//! built from core operations that *are* available (`to_bits` / `from_bits`
//! and comparisons).
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
}
