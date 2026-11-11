# DNSSEC authentication

Enable validation with `{"engine":{"dnssec":true}}`. Rust **1.78** remains the
minimum supported version. The optional ring 0.17.14 dependency supplies
cryptographic verification; all network requests use RecurseX's existing path.

## Root-to-answer chain

The built-in IANA root DS anchors are 20326 (KSK-2017) and 38696 (KSK-2024,
activated on 11 October 2026). The validator authenticates the root DNSKEY RRset
with an anchor-matching key, verifies each parent DS RRset, matches the child's
key to that DS, authenticates the complete child DNSKEY RRset, and verifies the
answer with its authenticated zone keys. Multiple DS/DNSKEY records and KSK/ZSK
separation are supported, including overlapping key rollovers.

| Result | Behavior |
| --- | --- |
| `ChainAnchored` | Required answer, authority and denial proofs authenticate; `Resolution.validated=true`. |
| `Insecure` | Authenticated unsigned delegation, NSEC3 opt-out, or authenticated DS with only unsupported algorithms/digests; return data with AD clear. |
| `Indeterminate` | Missing anchors/material or exhausted validation resources; validation-enabled resolution fails with `ErrorKind::Dnssec`. |
| `Bogus` verdict | Invalid/expired signatures, missing signatures in a secure zone, broken DS/DNSKEY links or invalid denial; reject before answer-cache admission. |

`SignatureValid`/`CryptoVerified` still describe local verification against
supplied keys, not zone identity. Neither the deprecated `Verdict::Secure` alias
nor the legacy `dnssec_anchored` flag can elevate trust.

## Coverage

- RSA/SHA-256 (8), RSA/SHA-512 (10), ECDSA P-256/SHA-256 (13),
  ECDSA P-384/SHA-384 (14), Ed25519 (15); SHA-256 (2) and SHA-384 (4) DS digests.
- Owner/class, DNSKEY protocol and zone-key/revocation flags, algorithm and key
  tags; canonical RRset sorting/deduplication and 32-bit serial signature times.
- NSEC/NSEC3 NXDOMAIN, NODATA, closest-encloser, wildcard and unsigned-delegation
  proofs, including NSEC3 opt-out. An SOA alone cannot authenticate denial.
- CNAME chains and DNAME-authenticated synthesized CNAMEs. An insecure link
  prevents AD on the combined answer.
- AD requires complete authentication, CD clear, and a client AD or DO request.
  CD permits unchecked data but never AD. Upstream AD is not trusted.
  Ordinary non-DO responses omit DNSSEC denial records and signatures.

## Evidence and limits

DNSKEY/DS fetches share the client's routing, privacy, wire-work budget and
deadline. They bypass client in-flight coalescing to avoid self-waits. NS address
lookups needed to reach evidence are routing hints: they do not recursively
validate or populate the client answer cache during validation.

A private 256-entry cache retains complete, fresh response/proof evidence.
Material is admitted after authentication. Reuse rechecks signatures and the
chain; ordinary/persisted `validated` flags are not proof. Negative and wildcard
answers retain their authority proofs. Response TTLs cannot outlive authenticated
chain material or signatures. Expired evidence is discarded.

Each validation permits at most 128 material lookups, 128 eligible signature/key
checks, 8 candidate signatures per RRset, 64 DNSKEYs per set and 64 denial records
per proof. NSEC3 permits at most 150 iterations and 10,000 hash rounds per proof.
The shared query budget can stop work sooner. Exceeding a limit fails closed.

## Trust-anchor configuration

Omitting `dnssecTrustAnchors` uses the built-in set. An explicit array **replaces**
it; an empty array cannot establish trust. Example using KSK-2024:

```json
{
  "engine": {
    "dnssec": true,
    "dnssecTrustAnchors": [{
      "name": ".",
      "keyTag": 38696,
      "algorithm": 8,
      "digestType": 2,
      "digest": "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16"
    }]
  }
}
```

Library callers can supply DS or DNSKEY `Record`s through
`EngineConfig::dnssec_trust_anchors`, including private-zone anchors. Configuring
validation without the `dnssec` feature is rejected.

Anchors are static operator configuration. **Automatic RFC 5011 maintenance is
not implemented**: future rollovers require trusted software/configuration
updates. Ed448 and deprecated algorithms are not verified. Resource limits
deliberately reject unusually expensive chains. This implementation has not had
an independent security audit; hermetic tests do not establish interoperability
with every authoritative server.

## Tests

`tests/dnssec_chain.rs` covers signed root/TLD/child zones, KSK/ZSK separation,
rollover, SHA-384 DS, all five algorithms, proof/cache reuse, negative and
wildcard proofs, aliases, CD/AD, tampering, expiration and work limits.
`tests/dnssec_fail_closed.rs` covers invalid signatures in caches and forwarded
answers. CI runs Rust 1.78/stable on Linux/Windows and a `dnssec`-only build.
These tests do not depend on public DNS.

References: [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034),
[RFC 4035](https://www.rfc-editor.org/rfc/rfc4035),
[RFC 5155](https://www.rfc-editor.org/rfc/rfc5155),
[RFC 6840](https://www.rfc-editor.org/rfc/rfc6840),
[RFC 9718](https://www.rfc-editor.org/rfc/rfc9718),
[IANA root anchors](https://www.iana.org/dnssec/files).
