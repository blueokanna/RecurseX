//! Bounds-checked byte reads for wire parsing.
//!
//! Every parser in this crate reads bytes that arrived from the network, so
//! every read is a decision: *is there a byte here?* `slice[i]` and
//! `&slice[a..b]` answer that question by panicking, and a panic reached from
//! a packet is a remote denial of service — one malformed message takes down
//! whichever thread parsed it. Parsers here therefore ask the question through
//! this module, where the answer is an `Err`.
//!
//! The trait exists so that a decoder can write `buf.u16_at(pos)` instead of
//! `u16::from_be_bytes([buf[pos], buf[pos + 1]])`. That is not cosmetic: with
//! no indexing expression in the source, the compiler cannot emit a bounds
//! check that panics, so the property is enforced by construction rather than
//! by remembering to call a guard first. The arithmetic is `checked_add`, so
//! even a length field of `usize::MAX` is an error rather than an overflow.
//!
//! Reads are *not* clamped to a record boundary — a caller that has one passes
//! its own `end` and uses [`WireBytes::slice_at`] with `end - pos`, because a
//! hostname inside a record may legitimately point past that record via
//! compression (RFC 1035 §4.1.4) while its own bytes may not.

use crate::error::{Error, Result};

/// The error every out-of-range read returns. A separate constructor keeps the
/// message uniform, so a fuzz failure reads the same wherever it was found.
fn out_of_range() -> Error {
    Error::wire("read past the end of the message")
}

/// Bounds-checked reads over a raw message.
///
/// Implemented for `[u8]`, so a decoder calls these directly on the slice it
/// was handed.
pub trait WireBytes {
    /// The byte at `at`.
    fn byte_at(&self, at: usize) -> Result<u8>;

    /// The big-endian `u16` at `at`.
    fn u16_at(&self, at: usize) -> Result<u16>;

    /// The big-endian `u32` at `at`.
    fn u32_at(&self, at: usize) -> Result<u32>;

    /// The big-endian 24-bit integer at `at`, widened to `u32`.
    ///
    /// Three octets is not an arbitrary width: it is the TLS length prefix
    /// (RFC 8446 §4 gives a 3-octet length to every handshake message, to the
    /// Certificate list, and to each CertificateEntry). It gets its own reader
    /// rather than a masked [`WireBytes::u32_at`] because the two differ by
    /// exactly one octet, and a masked read of a 3-octet length is one edit
    /// away from consuming the byte that follows it.
    fn u24_at(&self, at: usize) -> Result<u32>;

    /// The big-endian 48-bit integer at `at`, widened to `u64`. This is the
    /// width of a DNSSEC timing field and of a TLSA/SVCB parameter length.
    fn u48_at(&self, at: usize) -> Result<u64>;

    /// Exactly `N` bytes at `at`, as an array. The array type is what keeps
    /// this free of indexing: a slice of unknown length cannot be coerced into
    /// `[u8; N]` without a checked conversion.
    fn array_at<const N: usize>(&self, at: usize) -> Result<[u8; N]>;

    /// Exactly `len` bytes at `at`.
    fn slice_at(&self, at: usize, len: usize) -> Result<&[u8]>;

    /// Everything from `at` to the end of the message. An empty result is
    /// legitimate here — a zero-length tail is the right answer for, say, an
    /// eight-byte cookie with no server half — so this errors only when `at`
    /// is past the end of the message.
    fn rest_at(&self, at: usize) -> Result<&[u8]>;
}

impl WireBytes for [u8] {
    fn byte_at(&self, at: usize) -> Result<u8> {
        self.get(at).copied().ok_or_else(out_of_range)
    }

    fn u16_at(&self, at: usize) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array_at::<2>(at)?))
    }

    fn u32_at(&self, at: usize) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array_at::<4>(at)?))
    }

    fn u24_at(&self, at: usize) -> Result<u32> {
        let b = self.array_at::<3>(at)?;
        Ok((u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]))
    }

    fn u48_at(&self, at: usize) -> Result<u64> {
        let b = self.array_at::<6>(at)?;
        let mut v = 0u64;
        for byte in b {
            v = (v << 8) | u64::from(byte);
        }
        Ok(v)
    }

    fn array_at<const N: usize>(&self, at: usize) -> Result<[u8; N]> {
        let bytes = self.slice_at(at, N)?;
        <[u8; N]>::try_from(bytes)
            .map_err(|_| Error::internal("wire read returned the wrong length"))
    }

    fn slice_at(&self, at: usize, len: usize) -> Result<&[u8]> {
        // `at + len` can overflow on a hostile length field; that is an error,
        // not a wrapping bound.
        let end = at.checked_add(len).ok_or_else(out_of_range)?;
        self.get(at..end).ok_or_else(out_of_range)
    }

    fn rest_at(&self, at: usize) -> Result<&[u8]> {
        // `get(at..)` is `None` exactly when `at` is past the end; `at == len`
        // is the empty tail.
        self.get(at..).ok_or_else(out_of_range)
    }
}

/// At most `limit` leading bytes of `bytes`.
///
/// The encoders cap a length prefix at the width of the field that carries it
/// — 255 octets for a character-string, 65535 for a service parameter — which
/// is a `min` on the length. Expressing it here keeps that out of a slice
/// expression, where an off-by-one would be a panic rather than a short write.
pub fn capped(bytes: &[u8], limit: usize) -> &[u8] {
    // `get` is `None` exactly when `limit` exceeds the length, in which case the
    // whole slice is the answer anyway.
    bytes.get(..limit).unwrap_or(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_within_bounds_succeed() {
        let buf = [0x12u8, 0x34, 0x56, 0x78, 0x9a, 0xbc];
        assert_eq!(buf.byte_at(0).unwrap(), 0x12);
        assert_eq!(buf.u16_at(0).unwrap(), 0x1234);
        assert_eq!(buf.u32_at(0).unwrap(), 0x1234_5678);
        assert_eq!(buf.u48_at(0).unwrap(), 0x1234_5678_9abc);
        assert_eq!(buf.array_at::<3>(2).unwrap(), [0x56, 0x78, 0x9a]);
        assert_eq!(buf.slice_at(4, 2).unwrap(), &[0x9a, 0xbc]);
        assert_eq!(buf.rest_at(4).unwrap(), &[0x9a, 0xbc]);
        // An empty read of zero bytes is in range, and so is an empty tail.
        assert!(buf.slice_at(6, 0).unwrap().is_empty());
        assert!(buf.rest_at(6).unwrap().is_empty());
    }

    /// The contract: an out-of-range read is an error, never a panic, whatever
    /// the operands are.
    #[test]
    fn reads_past_the_end_are_errors() {
        let buf = [1u8, 2, 3];
        assert!(buf.byte_at(3).is_err(), "one past the last byte");
        assert!(buf.u16_at(2).is_err(), "a u16 that straddles the end");
        assert!(buf.u32_at(0).is_err(), "a u32 in a 3-byte buffer");
        assert!(buf.u48_at(0).is_err(), "a u48 in a 3-byte buffer");
        assert!(buf.array_at::<4>(0).is_err());
        assert!(buf.slice_at(1, 3).is_err());
        assert!(buf.rest_at(4).is_err(), "one past the last byte");

        // Degenerate operands: an empty buffer, and arithmetic that would
        // overflow if it were not checked.
        let empty: &[u8] = &[];
        assert!(empty.byte_at(0).is_err());
        assert!(empty.u16_at(0).is_err());
        assert!(empty.rest_at(0).unwrap().is_empty());
        assert!(empty.rest_at(1).is_err());
        assert!(buf.slice_at(0, usize::MAX).is_err(), "len overflow");
        assert!(buf.slice_at(usize::MAX, 1).is_err(), "offset overflow");
        assert!(buf.slice_at(usize::MAX, usize::MAX).is_err());
    }

    #[test]
    fn a_three_octet_length_does_not_read_a_fourth_byte() {
        // The trap this reader exists for. `u24_at(0)` must be 256, and the
        // `0x02` sitting right behind the length must stay out of it — which is
        // precisely what reading a `u32` and masking would get wrong.
        let buf = [0x00u8, 0x01, 0x00, 0x02];
        assert_eq!(buf.u24_at(0).unwrap(), 256);
        assert_eq!(buf.u24_at(1).unwrap(), 0x0001_0002);
        assert_eq!([0xffu8, 0xff, 0xff].u24_at(0).unwrap(), 0x00ff_ffff);
        assert_eq!([0u8, 0, 0].u24_at(0).unwrap(), 0);

        // Three octets means three: two is short, and one past the end is short.
        assert!(buf.u24_at(2).is_err());
        assert!([0x00u8, 0x01].u24_at(0).is_err());
    }

    #[test]
    fn capping_takes_the_shorter_of_the_two() {
        let buf = [1u8, 2, 3];
        assert_eq!(capped(&buf, 2), &[1, 2]);
        assert_eq!(capped(&buf, 3), &[1, 2, 3]);
        assert_eq!(capped(&buf, 0), &[] as &[u8]);
        assert_eq!(capped(&buf, usize::MAX), &[1, 2, 3]);
        assert_eq!(capped(&[], 8), &[] as &[u8]);
    }
}
