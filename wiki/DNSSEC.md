# DNSSEC

The `dnssec` feature validates answer chains: RRSIG signatures over canonical
RRsets, DS digest chains from the trust anchor down, and `Secure` /
`Insecure` / `Bogus` verdicts. Validation is deliberate and self-contained —
the allowed dependency set has no general crypto crate, so the RSA
verification is implemented from scratch.

## What is validated

- **RRSIG (RFC 4034 §3.1.5)** — the canonical RRset (owner name lower-cased,
  sorted RRs, original TTL), SHA-256 digest, verified against the signer's
  DNSKEY.
- **DS (RFC 4034 §5.1)** — the DS digest is SHA-256 over the canonical owner
  name + DNSKEY RDATA, and must match a DS record in the parent zone.
- **Chain walk** — from the zone's DNSKEYs up through the DS chain to the
  trust anchor, with a recursion guard.

Verdicts: `Secure` (validated), `Insecure` (a confirmed lack of a secure
chain), `Bogus` (signature or chain failed), `Indeterminate` (could not
establish).

## The RSA implementation

`dnssec/rsa.rs` implements RSA PKCS#1 v1.5 verification with a from-scratch
u32-limb big integer (modular exponentiation via square-and-multiply,
bitwise long-division reduction), plus RFC 3110 DNSKEY RSA parsing. The
exponent length is one octet, or — when that octet is zero — the two octets
that follow it (RFC 3110 §2), which is how an exponent longer than 255 octets
is expressed; the exponent then starts at offset 3, not at offset 1. The test
suite includes an **authentic 1024-bit RSA/SHA-256 vector generated with
openssl** — not a fabricated constant — plus tamper checks on both the digest
and the signature.

The verifier is a **total function over attacker-controlled input**: both the
DNSKEY (public data an on-path attacker can replay) and the signature (theirs
to choose) arrive from the wire, so a malformed key or signature is answered
with `false` — never a panic. `tests/parser_robustness.rs` holds it to that,
including the degenerate shapes an arithmetic helper gets wrong: an empty
signature, a zero modulus, an exponent declared longer than the key.

## Honest scope

- RSA PKCS#1 v1.5 with SHA-256 is implemented. ECDSA and SHA-1 signatures
  are recognized but not yet validated, so a chain that relies on them is
  reported as `Indeterminate` rather than falsely `Secure`.
- The encoded message is checked strictly: the full DigestInfo prefix, the
  exact digest, and at least the 8 padding octets RFC 8017 §9.2 requires, so
  a low-exponent forgery cannot pass through a short padding run.
- The `do` bit is honored when requesting DNSSEC; the resolver stores the
  RRSIGs alongside the RRset so validated data stays validated across cache
  hits, and the `validated` flag survives persistence.

## Aggressive caching

The cache stores negative answers with their SOA-derived TTLs (RFC 2308),
which is the substrate for aggressive NSEC/NSEC3 caching; the NSEC bitmap
parse/serialize is in the wire codec.
