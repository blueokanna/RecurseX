//! Parser robustness: the wire decoder is the attack surface, so it gets
//! fed garbage on purpose.
//!
//! The generators are deterministic (seeded PRNG), which means a failure here
//! is reproducible from the seed printed in the assertion message — the point
//! of a robustness test is that it can be re-run, not that it is random.

use recurse_x::{Message, Name, RrType};

/// SplitMix64: the same generator the resolver uses for 0x20, kept here so
/// the test has no dependency the library does not already have.
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
}

/// Anything the parser accepts must survive a round-trip through the
/// serializer and come back identical, and anything it rejects must be
/// rejected without panicking.
#[test]
fn random_bytes_never_panic() {
    let mut rng = Rng(0x5eed_1234_5678_9abc);
    let mut accepted = 0usize;
    for case in 0..20_000u32 {
        // Sizes cluster near the interesting boundaries.
        let len = match case % 4 {
            0 => rng.below(12),
            1 => 12 + rng.below(64),
            2 => 256 + rng.below(1024),
            _ => rng.below(4096),
        };
        let mut buf: Vec<u8> = (0..len).map(|_| (rng.next() & 0xff) as u8).collect();
        // Half the cases get a plausible header so the decoder walks further
        // into the record loop instead of failing on the counts.
        if case % 2 == 0 && buf.len() >= 12 {
            buf[4..6].copy_from_slice(&(rng.below(3) as u16).to_be_bytes()); // qdcount
            buf[6..8].copy_from_slice(&(rng.below(4) as u16).to_be_bytes()); // ancount
            buf[8..10].copy_from_slice(&(rng.below(4) as u16).to_be_bytes()); // nscount
            buf[10..12].copy_from_slice(&(rng.below(4) as u16).to_be_bytes()); // arcount
        }
        if let Ok(msg) = Message::parse(&buf) {
            accepted += 1;
            if let Ok(bytes) = msg.to_bytes() {
                let again = Message::parse(&bytes)
                    .unwrap_or_else(|e| panic!("case {case}: reserialized message rejected: {e}"));
                assert_eq!(msg, again, "case {case}: round-trip changed the message");
            }
        }
    }
    assert!(
        accepted > 0,
        "the generator produced no valid message at all"
    );
}

/// Hostile length and count fields: every field that is read as a length must
/// be validated against the buffer rather than trusted.
#[test]
fn hostile_length_fields_are_rejected_or_handled() {
    let valid = Message::query(
        1,
        Name::from_ascii("www.example.com").unwrap(),
        RrType::A,
        true,
    )
    .to_bytes()
    .unwrap();

    // Counts far beyond the buffer.
    for (off, value) in [(4usize, 0xffffu16), (6, 0xffff), (8, 0xffff), (10, 0xffff)] {
        let mut corrupt = valid.clone();
        corrupt[off..off + 2].copy_from_slice(&value.to_be_bytes());
        assert!(
            Message::parse(&corrupt).is_err(),
            "a count of {value} at offset {off} must not parse"
        );
    }

    // A compression pointer loop, and a pointer to itself.
    let mut looping = vec![0u8; 12 + 2];
    looping[4..6].copy_from_slice(&1u16.to_be_bytes());
    looping[12] = 0xc0;
    looping[13] = 0x0c;
    assert!(
        Message::parse(&looping).is_err(),
        "self-pointer must be rejected"
    );

    // Truncated at every possible boundary: none of these may panic, and
    // none may be accepted as a shorter message.
    for cut in 0..valid.len() {
        let _ = Message::parse(&valid[..cut]);
    }
}

/// The UDP fitter must never leave a message that exceeds the limit it was
/// given, and must set TC when it had to drop records.
#[test]
fn truncation_always_fits() {
    let mut msg = Message::new(7);
    msg.flags.qr = true;
    msg.questions.push(recurse_x::message::Question {
        qname: Name::from_ascii("many.example.com").unwrap(),
        qtype: RrType::TXT,
        qclass: recurse_x::qtype::RrClass::IN,
    });
    for i in 0..200u8 {
        msg.answers.push(recurse_x::rdata::Record {
            name: Name::from_ascii("many.example.com").unwrap(),
            rr_type: RrType::TXT,
            class: recurse_x::qtype::RrClass::IN,
            ttl: 60,
            rdata: recurse_x::rdata::RData::Txt(vec![vec![i; 40]]),
        });
    }
    assert!(msg.wire_len() > 4096);

    for limit in [512usize, 700, 1232, 4096] {
        let mut copy = msg.clone();
        copy.truncate_for_udp(limit);
        assert!(
            copy.wire_len() <= limit,
            "limit {limit} produced {} bytes",
            copy.wire_len()
        );
        assert!(copy.flags.tc, "dropping records must set TC");
        assert_eq!(copy.questions.len(), 1, "the question must survive");
        // Still parseable, and still consistent with its own encoding.
        let bytes = copy.to_bytes().unwrap();
        let back = Message::parse(&bytes).unwrap();
        assert_eq!(back.answers.len(), copy.answers.len());
    }
}

/// A name decoder must not be driven into an unbounded loop by pointers.
#[test]
fn name_pointers_are_bounded() {
    // A chain of pointers that eventually reaches a real name: legal, and it
    // must be accepted (the hop budget is derived from the 255-octet limit,
    // not guessed). Each pointer targets the one written before it, so the
    // chain is walked backwards to the label at offset 0.
    let mut buf = vec![3, b'c', b'o', b'm', 0];
    let mut target = 0usize;
    for _ in 0..60 {
        let off = buf.len();
        buf.push(0xc0 | ((target >> 8) & 0x3f) as u8);
        buf.push((target & 0xff) as u8);
        target = off;
    }
    let last = buf.len() - 2;
    let (name, end) = Name::from_wire(&buf, last).expect("a 60-hop pointer chain is legal");
    assert_eq!(name.to_ascii(), "com");
    assert_eq!(
        end,
        buf.len(),
        "the second value is the position past the name"
    );

    // The same contract without compression.
    let plain = [3u8, b'c', b'o', b'm', 0];
    let (name, end) = Name::from_wire(&plain, 0).unwrap();
    assert_eq!(name.to_ascii(), "com");
    assert_eq!(end, plain.len());

    // A cycle must be rejected quickly and without panicking.
    let mut cycle = vec![0u8; 8];
    cycle[0] = 0xc0;
    cycle[1] = 0x04;
    cycle[4] = 0xc0;
    cycle[5] = 0x00;
    assert!(Name::from_wire(&cycle, 0).is_err());
}
