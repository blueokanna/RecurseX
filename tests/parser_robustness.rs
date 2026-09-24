//! Parser robustness for the decoders that consume *untrusted* bytes.
//!
//! `wire_robustness.rs` covers `Message::parse`. This file covers the rest of
//! the attack surface — the parsers that a hostile authoritative server, an
//! on-path attacker, or a corrupted file can drive:
//!
//! * every `RData` variant, called directly rather than hoping a random
//!   message reaches it;
//! * the EDNS option walker;
//! * the RSA verifier, which is the one place a *cryptographic* function is
//!   handed attacker-controlled input and must answer `false` rather than
//!   anything louder;
//! * the hand-written QUIC/TLS framing.
//!
//! The contract these tests hold the code to is the same one for all of them:
//!
//! 1. **Never panic.** A panic reached from a network packet is a remote
//!    denial of service, and in a resolver it takes down a worker thread.
//! 2. **Never read past the region it was given.** A decoder is handed a
//!    slice and a length; the length is a limit, not a hint.
//! 3. **A verifier says `false`.** Verification of malformed input is a
//!    rejected signature, never an error the caller has to catch.
//!
//! The generators are deterministic, so a failure is reproducible from the
//! seed in the assertion message.

use recurse_x::dnssec::rsa::{parse_dnskey_rsa, verify_pkcs1v15_sha256};
use recurse_x::edns::{parse_options, Ecs, Edns};
use recurse_x::qtype::RrType;
use recurse_x::rdata::RData;

/// SplitMix64, so the test has no dependency the library does not already
/// have, and so every case is reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() & 0xff) as u8).collect()
    }
}

/// Every record type the decoder claims to handle. A type missing from the
/// code path that parses it is a type that has never been fed garbage.
const TYPES: [RrType; 40] = [
    RrType::A,
    RrType::NS,
    RrType::MD,
    RrType::MF,
    RrType::CNAME,
    RrType::SOA,
    RrType::MB,
    RrType::MG,
    RrType::MR,
    RrType::NULL,
    RrType::WKS,
    RrType::PTR,
    RrType::HINFO,
    RrType::MINFO,
    RrType::MX,
    RrType::TXT,
    RrType::RP,
    RrType::AFSDB,
    RrType::SIG,
    RrType::KEY,
    RrType::AAAA,
    RrType::LOC,
    RrType::SRV,
    RrType::NAPTR,
    RrType::KX,
    RrType::CERT,
    RrType::DNAME,
    RrType::APL,
    RrType::DS,
    RrType::SSHFP,
    RrType::IPSECKEY,
    RrType::RRSIG,
    RrType::NSEC,
    RrType::DNSKEY,
    RrType::NSEC3,
    RrType::NSEC3PARAM,
    RrType::TLSA,
    RrType::HIP,
    RrType::SVCB,
    RrType::HTTPS,
];

/// Every rdata decoder must reject or consume garbage without panicking, and
/// a successful parse must never advance past the length it was given.
///
/// Random bytes exercise the *rejection* path, which is the one a hostile
/// server drives. Acceptance is not asserted here: these decoders require the
/// rdata to be consumed exactly, so arbitrary bytes are almost always refused
/// and an "it accepted something" assertion would only measure luck. The
/// acceptance path is pinned down deterministically by
/// `well_formed_rdata_round_trips` below.
#[test]
fn every_rdata_decoder_survives_garbage() {
    let mut rng = Rng(0x0bad_c0de_dead_beef);
    for rr_type in TYPES {
        for case in 0..300 {
            let len = match case % 3 {
                0 => rng.below(4),
                1 => rng.below(64),
                _ => rng.below(600),
            };
            let buf = rng.bytes(len);
            let mut pos = 0usize;
            if let Ok(rd) = RData::parse(&buf, &mut pos, buf.len(), rr_type) {
                assert!(
                    pos <= buf.len(),
                    "{rr_type}: parse advanced past the buffer ({pos} > {})",
                    buf.len()
                );
                // What came out must survive a trip through the encoder and
                // come back the same. An empty encoding is legitimate for a
                // zero-length rdata (`NULL`, an empty `TXT`, an unhandled
                // type), so the assertion is not "it encoded something" —
                // it is "nothing was silently dropped", which is the bug an
                // asymmetric codec produces.
                let mut out = Vec::new();
                rd.to_wire(&mut out, None);
                let mut back_pos = 0usize;
                match RData::parse(&out, &mut back_pos, out.len(), rr_type) {
                    Ok(again) => assert_eq!(
                        again, rd,
                        "{rr_type}: re-parsing the encoding changed the value \
                         (encoded to {} bytes)",
                        out.len()
                    ),
                    Err(e) => panic!(
                        "{rr_type}: a value this decoder produced ({rd:?}) does not \
                         parse back out of its own {}-byte encoding: {e}",
                        out.len()
                    ),
                }
            }
        }
    }
}

/// Encode a domain name as a sequence of length-prefixed labels plus root.
fn name(labels: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for label in labels {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// The other half of the contract: a *well-formed* record must come back out
/// byte-identical. A decoder that mangles valid data is as broken as one that
/// panics on invalid data, and unlike the garbage sweep this test is
/// deterministic — every case either passes or names the type that failed.
#[test]
fn well_formed_rdata_round_trips() {
    // MX: preference, then the exchange name.
    let mut mx = 10u16.to_be_bytes().to_vec();
    mx.extend_from_slice(&name(&["mail", "example"]));

    // SOA: two names then five 32-bit fields.
    let mut soa = name(&["ns1", "example"]);
    soa.extend_from_slice(&name(&["hostmaster", "example"]));
    for v in [1u32, 3600, 600, 604_800, 60] {
        soa.extend_from_slice(&v.to_be_bytes());
    }

    // SRV: priority, weight, port, then the target name (never compressed).
    let mut srv = Vec::new();
    for v in [1u16, 2, 8080] {
        srv.extend_from_slice(&v.to_be_bytes());
    }
    srv.extend_from_slice(&name(&["target", "example"]));

    // DS: key tag, algorithm, digest type, digest.
    let mut ds = vec![0x12, 0x34, 0x08, 0x02];
    ds.extend_from_slice(&[0xa5u8; 32]);

    // RRSIG: 18 fixed bytes, then the signer name, then the signature.
    let mut rrsig = vec![0x00, 0x01, 0x08, 0x02];
    for v in [3600u32, 1_700_000_000, 1_699_000_000] {
        rrsig.extend_from_slice(&v.to_be_bytes());
    }
    rrsig.extend_from_slice(&0x1234u16.to_be_bytes());
    rrsig.extend_from_slice(&name(&["example"]));
    rrsig.extend_from_slice(&[0x5au8; 64]);

    let cases: Vec<(RrType, Vec<u8>)> = vec![
        (RrType::A, vec![192, 0, 2, 1]),
        (
            RrType::AAAA,
            vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ),
        (RrType::NS, name(&["ns1", "example"])),
        (RrType::CNAME, name(&["target", "example"])),
        (RrType::DNAME, name(&["example"])),
        (RrType::PTR, name(&["1", "0", "2", "192", "in-addr", "arpa"])),
        (RrType::MX, mx),
        // TXT: length-prefixed character-strings.
        (RrType::TXT, b"\x05hello\x05world".to_vec()),
        (RrType::SOA, soa),
        (RrType::SRV, srv),
        (RrType::DS, ds),
        (RrType::RRSIG, rrsig),
    ];

    for (rr_type, bytes) in &cases {
        let mut pos = 0usize;
        let rd = RData::parse(bytes, &mut pos, bytes.len(), *rr_type).unwrap_or_else(|e| {
            panic!("{rr_type}: a well-formed rdata was rejected: {e}")
        });
        assert_eq!(
            pos,
            bytes.len(),
            "{rr_type}: the rdata was not consumed exactly"
        );
        let mut out = Vec::new();
        // No compressor: an uncompressed name re-encodes to its input bytes,
        // so a mismatch here is a genuine asymmetry rather than a choice of
        // compression.
        rd.to_wire(&mut out, None);
        assert_eq!(out, *bytes, "{rr_type}: re-encoding changed the rdata");
    }
}

/// The `end` argument is a limit. A caller that passes one beyond the buffer
/// — a length field read from an untrusted header, say — must not turn into
/// an out-of-bounds read; the decoder has to clamp.
#[test]
fn a_hostile_end_never_reads_past_the_buffer() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    for rr_type in TYPES {
        for _ in 0..200 {
            let len = rng.below(24);
            let buf = rng.bytes(len);
            // `end` deliberately points past the slice, as a bogus RDLENGTH
            // would.
            let bogus_end = buf.len() + 1 + rng.below(64);
            let mut pos = 0usize;
            let _ = RData::parse(&buf, &mut pos, bogus_end, rr_type);
        }
    }
}

/// An EDNS option list is a sequence of `(code, len, body)` triples, and a
/// `len` that disagrees with the body is the classic way to walk off the end.
#[test]
fn edns_option_walking_survives_garbage() {
    let mut rng = Rng(0xfeed_face_cafe_babe);

    // Random bodies.
    for case in 0..4_000 {
        let len = match case % 3 {
            0 => rng.below(4),
            1 => rng.below(40),
            _ => rng.below(400),
        };
        let buf = rng.bytes(len);
        // All three entry points into the same walker: the option list, the
        // whole OPT record, and the ECS option body on its own.
        let _ = parse_options(&buf);
        let _ = Edns::parse(1232, 0, &buf);
        let _ = Ecs::parse(&buf);
    }

    // A body length far larger than the remaining bytes, which is the shape a
    // linear walker gets wrong.
    for claimed in [0x0001u16, 0xfffe, 0xffff] {
        let mut buf = vec![0x00, 0x08]; // option code 8 (ECS)
        buf.extend_from_slice(&claimed.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x01, 0x18]); // far too short
        assert!(
            parse_options(&buf).is_err(),
            "a body length of {claimed} with 3 bytes present must be rejected"
        );
    }

    // A padding option whose length disagrees with its body.
    let mut buf = vec![0x00, 0x0cu8];
    buf.extend_from_slice(&0x0004u16.to_be_bytes());
    buf.extend_from_slice(&[0, 0]); // two bytes, not four
    assert!(parse_options(&buf).is_err(), "short padding must be rejected");
}

/// A verifier is handed bytes chosen by whoever signed — or did not sign —
/// the answer. Invalid input is `false`, never a panic and never an error the
/// caller has to catch.
#[test]
fn rsa_verification_rejects_malformed_input() {
    let digest = [0x5au8; 32];

    // The shapes that reach the arithmetic: no signature, a one-byte
    // signature, and a signature that is all zeros.
    for sig in [vec![], vec![0u8], vec![0u8; 1], vec![0u8; 64], vec![0xff; 64]] {
        // A well-formed RSA DNSKEY so the parse succeeds and the signature
        // is what is actually under test.
        let key = well_formed_rsa_dnskey();
        assert!(
            !verify_pkcs1v15_sha256(&key, &digest, &sig),
            "a signature of {} bytes must not verify",
            sig.len()
        );
    }

    // Keys that must be refused before any arithmetic runs.
    for key in [
        vec![],
        vec![0u8],
        vec![0u8; 4],
        vec![0xffu8; 4],
        // Exponent length says 255 but nothing follows.
        vec![0, 0, 3, 8, 0xff],
        // The RFC 3110 three-octet form claiming a huge exponent.
        vec![0, 0, 3, 8, 0x00, 0xff, 0xff],
        // A zero modulus: the arithmetical degenerate case.
        vec![0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
    ] {
        let _ = parse_dnskey_rsa(&key);
        assert!(
            !verify_pkcs1v15_sha256(&key, &digest, &[0u8; 64]),
            "a malformed DNSKEY must not verify"
        );
    }

    // And the fully random case, which is what an attacker actually sends.
    //
    // The sizes stay small on purpose. Every degenerate shape a panic could
    // hide in is short — an empty dividend, a missing length octet, a zero
    // modulus — while the modular exponentiation costs O(bits^2) per case, so
    // an unbounded key would make this loop dominate the suite's runtime
    // without reaching any input the short ones miss.
    let mut rng = Rng(0xabcd_ef01_2345_6789);
    for _ in 0..2_000 {
        let key_len = rng.below(48);
        let sig_len = rng.below(48);
        let key = rng.bytes(key_len);
        let sig = rng.bytes(sig_len);
        let _ = parse_dnskey_rsa(&key);
        let _ = verify_pkcs1v15_sha256(&key, &digest, &sig);
    }

    // One realistic-sized key, so the arithmetic is exercised with an
    // exponent that actually has bits set rather than only with stubs.
    let key = well_formed_rsa_dnskey();
    let mut sig = vec![0u8; 128];
    sig[127] = 1;
    assert!(!verify_pkcs1v15_sha256(&key, &digest, &sig));
    assert!(!verify_pkcs1v15_sha256(&key, &digest, &[0xffu8; 128]));
}

/// A minimal RSA DNSKEY that parses cleanly: exponent 65537, a 128-byte
/// modulus, in the RFC 3110 single-octet-length form.
fn well_formed_rsa_dnskey() -> Vec<u8> {
    let mut key = vec![0x03, 0x01, 0x00, 0x01]; // exponent length 3, 65537
    key.extend_from_slice(&[0x01, 0x00, 0x01]);
    // A modulus that is odd and full length, so the arithmetic is exercised
    // rather than short-circuited.
    key.extend_from_slice(&[0xff; 127]);
    key.push(0xfd);
    key
}

/// The QUIC response framing is read straight off a UDP socket.
#[test]
fn quic_deframing_survives_garbage() {
    use recurse_x::transports::doq::deframe_response;
    let mut rng = Rng(0x9999_1111_2222_3333);
    for case in 0..4_000 {
        let len = match case % 4 {
            0 => rng.below(3),
            1 => rng.below(16),
            2 => rng.below(200),
            _ => rng.below(2_000),
        };
        let buf = rng.bytes(len);
        let _ = deframe_response(&buf);
    }

    // The declared length is the field a framer gets wrong.
    for claimed in [0x0000u16, 0x0001, 0xfffe, 0xffff] {
        let mut buf = claimed.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        let _ = deframe_response(&buf);
    }
}

/// The TLS handshake parsers run on bytes from the QUIC peer's first flight.
#[test]
fn tls_handshake_parsing_survives_garbage() {
    use recurse_x::transports::doq::tls::{decode_server_transport_params, parse_certificate_list};
    let mut rng = Rng(0x7777_8888_9999_aaaa);
    for case in 0..4_000 {
        let len = match case % 3 {
            0 => rng.below(6),
            1 => rng.below(200),
            _ => rng.below(2_000),
        };
        let buf = rng.bytes(len);
        let _ = decode_server_transport_params(&buf);
        let _ = parse_certificate_list(&buf);
    }
}
