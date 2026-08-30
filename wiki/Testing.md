# Testing & verification

## Commands

```sh
# full suite, all features
cargo test --features std,dot,doh,doh3,doq,dnssec,persist --lib

# the no_std core still builds
cargo build --no-default-features

# strict lint (warnings are errors)
cargo clippy --features std,dot,doh,doh3,doq,dnssec,persist --all-targets -- -D warnings
```

## What the 130 tests cover

- **Wire codec** (`message`, `rdata`, `name`, `qtype`, `edns`) — parse /
  serialize round-trips, name compression, truncation, error responses,
  NSEC bitmaps, EDNS options.
- **Cache** — insert/lookup across tiers, CNAME chains, serve-stale,
  NXDOMAIN store, ECS partitioning, eviction, prefetch candidacy, sweep.
- **Stability & admission** — the EWMA math, fingerprint TTL-independence,
  score thresholds.
- **Estimator / planner / graph / upstream** — probability growth, TOD
  profile shape, bounded memory, graph pruning, cost ranking. The estimator
  also verifies its self-contained `exp` and rounding against reference
  values.
- **Policy** — rate limiting, filtering, token buckets.
- **Engine & resolver** — response classification (answer / NXDOMAIN /
  NODATA / referral / empty), QNAME minimization steps, negative TTL rules,
  server binds UDP and TCP and answers.
- **Config** — JSON round-trip, minimal document, forwarder default ports.
- **Encrypted transports** — DoT/DoH/DoH3/DoQ protocol behavior (framing,
  error codes, QUIC packet/crypto/ACK and TLS handshake unit tests; the DoQ
  QUIC-TLS client is also verified against a local courierust HTTP/3 server
  with Retry + full handshake + 1-RTT).
- **DNSSEC** — an authentic openssl-generated 1024-bit RSA/SHA-256 vector
  verifies; tampering with the digest or the signature fails; DNSKEY parsing
  edge cases (zero-length → 4-byte exponent).
- **Persistence** — round-trip, stale parking into cold, dead-entry drop,
  ECS survival, tamper rejection, atomic write.

## Live verification

`examples/quick_check.rs` resolves `example.com`, `www.example.com`,
`google.com`, `ietf.org` and `nonexistent.invalid` through the full iterative
pipeline twice (the second pass must hit cache), then prints stats:

```sh
cargo run --no-default-features --features std --example quick_check
```

A healthy run resolves all four real names and returns NXDOMAIN for the
invalid one; `ietf.org` exercises the out-of-zone NS path (afilias-nst.info),
which is also the case that catches QNAME-minimization regressions — a
NODATA for a minimized prefix must deepen the query, not terminate it.

## Why the numbers are trustworthy

- No fabricated test vectors: the RSA vector was generated with openssl and
  cross-checked with an independent Python implementation.
- Live names are resolved against the actual DNS tree, not a mock.
- The `no_std` build is part of CI-style verification, so the core cannot
  silently grow a `std` dependency.
