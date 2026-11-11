# DNSSEC: signature checks and the trust boundary

Version: **0.2.6**.

RecurseX currently implements RSA/SHA-256 signature verification (algorithm 8),
SHA-256 DS matching and canonical RRset construction. It does **not** implement a
complete validating recursive resolver: there is no installed root trust anchor,
authenticated parent-DS walk, NSEC/NSEC3 denial validation or wildcard denial proof.
ECDSA 13/14 and EdDSA 15/16 are recognized but unsupported.

| Result | Meaning in this release |
|---|---|
| `SignatureValid` | The signature is mathematically consistent with a fetched/supplied key. The key is not authenticated. |
| `Indeterminate` | Missing evidence, unsupported algorithm, unsigned data without authenticated denial, or unsupported wildcard proof. |
| `Bogus` | A supported, applicable signature failed local checks. This is not proof that the zone was securely delegated. |
| `Insecure` | Reserved for an authenticated unsigned delegation; the current validator does not produce it. |

`Verdict::Secure` remains a deprecated compatibility constant for `SignatureValid`.
Code should use the explicit name. `ValidationState::CryptoVerified` describes only
local cryptography; `ChainAnchored` requires a complete chain and is never emitted
by the current validator. The legacy `anchored` boolean cannot promote a result.

`Verification::checked_signature_state()` reports local signature success.
The resolver uses `checked_authentication()` for `Resolution.validated` and cache
trust. Consequently local success leaves `validated=false`, and emitted responses
never assert AD. Historical `answer_groups_authenticated` and
`authority_authenticated` fields count local signature checks, not trusted chains.
Every owner/type/class group is counted, including unsigned groups.

Verification binds DNSKEY owner and class to the signer, checks protocol 3 and the
zone-key flag, and binds every covered record to the RRSIG owner, type and class.
The signer must enclose the owner. DS matching checks owner, class, record types,
key tag and digest; matching an unauthenticated DS is still not anchoring.
The resolver no longer fetches DS solely to give local verification a stronger name.

Canonical RRsets sort by RDATA octets, not by the preceding RDLENGTH.
Signature time windows use 32-bit serial arithmetic, including wraparound; ambiguous
windows of half the serial space or more are rejected. Wildcard expansion is
indeterminate, rather than incorrectly reporting a valid wildcard signature as bogus.

DNSKEY subqueries suppress nested validation on the same thread to bound recursion.
The guard is thread-local, so an unrelated worker does not skip checks. Invalid
signatures fail before cache admission and are rechecked on reuse. Unsupported or
missing evidence remains indeterminate and is not silently relabeled secure.

For applications requiring authenticated answers, this release's local verifier
does not satisfy that requirement. A validating upstream can supply answers, but
RecurseX does not convert an upstream AD bit into a locally validated chain.

References: [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034),
[RFC 4035](https://www.rfc-editor.org/rfc/rfc4035).
