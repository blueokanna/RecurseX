# Testing & verification

## Commands

```sh
# full suite: unit, integration and doctests
cargo test --all-features

# the algorithmic core, including its own tests, is no_std
cargo test --no-default-features --lib

# strict lint (warnings are errors)
cargo clippy --all-targets --all-features -- -D warnings
```

## What the tests cover

The suite is 159 unit tests, 7 integration tests in `tests/`, and 4 doctests,
and it is **hermetic**: every test that needs an upstream gets a local stub
server, so `cargo test` never depends on the public Internet (or on its
latency). A test that talked to real root servers would be a flaky test that
reports on the network rather than on the resolver.

- **Wire codec** (`message`, `rdata`, `name`, `qtype`, `edns`) — parse /
  serialize round-trips, name compression, truncation, error responses,
  NSEC bitmaps, EDNS options.
- **Cache** — insert/lookup across tiers, CNAME chains, serve-stale,
  NXDOMAIN store and its capacity, ECS partitioning, exact-lowest eviction,
  prefetch candidacy, sweep.
- **Stability & admission** — the EWMA math, fingerprint TTL-independence,
  score thresholds, the memory term (which must actually move the score).
- **Estimator / planner / alias graph / upstream** — probability growth, TOD
  profile shape, bounded memory, alias edges in both directions and pruning,
  cost ranking, timeouts creating a path model. The estimator also verifies
  its self-contained `exp` and rounding against reference values.
- **Policy** — rate limiting, filtering, token buckets.
- **Engine & resolver** — response classification (answer / NXDOMAIN /
  NODATA / referral / empty), QNAME minimization steps, negative TTL rules,
  coalescing (including an owner that vanishes without publishing), the
  CNAME-to-alias-edge wiring, AD/CD response flags, and the server's UDP and
  TCP paths against a stub upstream.
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
- **Server lifecycle** — every loop stops on request: the UDP receivers, the
  handler pool, the TCP accept loop, the per-connection reader and the
  maintenance thread are all started and stopped inside a test with a
  watchdog, and a connection that goes idle (or drips one byte at a time) is
  closed instead of holding a thread forever.

## Integration tests (`tests/`)

These use the crate the way an embedder does — public API only, no access to
internals:

- `end_to_end.rs` builds a resolver from a JSON document, binds a UDP and a
  TCP listener on port 0, queries both over the wire, asserts the second
  query is served from cache without a new upstream query, restarts a
  "process" from its `persist` snapshot (and asserts the restart needs no
  network), drives a configured forwarder, and stops everything through
  `Server::shutdown`/`Resolver::shutdown` with a join watchdog.
- `wire_robustness.rs` is the decoder's adversary: 20,000 deterministic
  pseudo-random buffers (seeded SplitMix64, so a failure reproduces), half of
  them with plausible header counts; hostile count fields; a compression
  pointer cycle; every truncation boundary of a valid message. It asserts the
  parser never panics, that anything it accepts re-encodes to something it
  accepts again, and that `truncate_for_udp` never exceeds the limit it was
  given while keeping the question and setting TC.

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
- The `no_std` core is built *and tested* in CI, so it cannot silently grow a
  `std` dependency.
- CI runs on the MSRV (1.78) and on stable, for Linux and Windows, with
  `RUSTFLAGS=-D warnings`; the release profile (fat LTO, one codegen unit) is
  tested too, because that is the profile that ships.
