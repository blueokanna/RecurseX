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

The suite is 291 unit tests, 22 integration tests in `tests/`, and 4 doctests.

It is hermetic in the sense that matters: **no test asserts on a reply from the
public Internet**, so the result depends on the resolver and not on the network's
health or latency. Every test that needs an upstream gets a local stub, and the
iterative walk is driven against a stub root server over loopback. Three tests do
open a socket, and it is worth being exact about them: two send to `192.0.2.1`
(TEST-NET-1, unroutable by definition) and assert only that the exchange *fails*
inside its timeout, and one drives a stub upstream over loopback. A test that
talked to real root servers would report on the network rather than on the
resolver — and on a machine whose upstream intercepts UDP/53 it would report on
the interception.

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
  with Retry + full handshake + 1-RTT). The hand-written codecs carry their own
  adversarial cases: every DER length form and its truncations, an RSA public
  key with and without its sign octet, a Certificate list whose entry lengths
  are bounded by the *list* rather than by the message it arrived in, a
  ServerHello that offers the wrong group or the wrong key length, and a stream
  reassembly offset that tries to ask for a terabyte.
- **Timeouts** — `tests/iterative_path.rs` ends a dead walk at the engine's
  `query_budget_ms`, and asserts that a walk whose budget is already spent stops
  without touching the network. The DoQ transport's test puts a clock on the
  same contract: a 200 ms budget has to fail inside a second, because the
  transport used to floor the caller at ten seconds and nothing short of a clock
  could see it.
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

- `iterative_path.rs` is the iterative walk under a microscope: a stub root and
  a stub `test` zone are walked through delegation, an NXDOMAIN with its SOA, a
  refusal, a completely empty NOERROR, and a black hole that never answers. It
  asserts the properties that are invisible from the outside — that a referral
  chain is walked to the answer, that QNAME minimization changes the queries but
  not the answer, that the walk never asks about a name unrelated to the
  question, that a refusal is retried rather than returned, that an NXDOMAIN is
  cached and not re-asked, and that a dead walk ends at `query_budget_ms`. Two of
  its eight tests found real bugs the first time they ran: the empty-response
  skip discarded a legal SOA-less NXDOMAIN as "no server answered", and a UDP
  read timeout was reported as an I/O error because Windows spells it `TimedOut`
  where Unix says `WouldBlock`.
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
- `parser_robustness.rs` covers the parsers `wire_robustness.rs` cannot reach
  through `Message::parse`: every one of the 40 rdata decoders called
  directly on garbage, an `end` pointing deliberately past the end of the
  buffer, the EDNS option walker, the RSA verifier, QUIC response deframing,
  and the TLS handshake parsers. Random bytes only exercise the *rejection*
  path — these decoders require the rdata to be consumed exactly, so
  arbitrary input is almost always refused — which is why the accepted path
  is pinned down separately by a hand-written corpus of well-formed rdata for
  12 types that must re-encode byte-for-byte.

## Reading bytes that came off the network

Every wire parser reads through `crate::wire::WireBytes`, an extension trait on
`[u8]` whose reads are checked and — this is the point — contain no indexing
expression. `slice[i]` and `&slice[a..b]` answer "is there a byte here?" by
panicking, and a panic reached from a packet is a remote denial of service. With
`buf.byte_at(i)?` / `buf.u16_at(i)?` / `buf.slice_at(i, n)?` / `array_at::<N>(i)`,
the compiler cannot emit a bounds check that panics, only one that returns
`None`. The arithmetic inside is `checked_add`, so a length field of `usize::MAX`
is an error rather than a wrap. `wire::capped(bytes, limit)` is the encoding-side
counterpart, replacing `&x[..x.len().min(N)]` for length prefixes.

The crate is linted with `clippy::indexing_slicing` over the library, and that is
enforced rather than aspired to: `lib.rs` carries
`#![cfg_attr(not(test), warn(clippy::indexing_slicing))]`, so
`cargo clippy --all-targets -- -D warnings` fails on a new index expression in
shipped code. It is deliberately *not* applied to the crate's own test modules
(`cfg(not(test))`) or to the `tests/` and `examples/` targets, which are separate
crates: indexing a fixture is the clearest way to say what its bytes are, and a
wrong index there is a failing test rather than a remote fault.

The two hand-written codecs in `transports/doq/` were the last 120 sites and are
now at zero. Two things are worth recording about that conversion:

- The trap is real and it is quiet. A TLS handshake length is three octets, and
  the first attempt at this rewrite read one as a `u32` and masked it — which is
  exactly one byte away from consuming the first byte of the body it describes.
  The existing reassembly tests caught it. The fix is `WireBytes::u24_at`, which
  exists so that "three octets" cannot be spelled as "four octets, minus one".
- Some of those sites were not panics-in-waiting but live bugs. `on_stream` grew
  its reassembly buffer to the offset carried by a `STREAM` frame *before*
  checking the buffer cap, so a peer could name a terabyte and the process would
  ask the allocator for it — a one-packet remote OOM. It now bounds the length
  through `reassembly_end` (checked arithmetic, cap compared first), which has a
test of its own.

The DNS wire parsers, which have `wire_robustness.rs` and `parser_robustness.rs`
behind them, converted first and cleanly.

## Panics and lock poisoning

Every mutex in the crate is `crate::sync::Mutex`, not `std::sync::Mutex`.
The difference is one policy decision made in one place: `lock()` recovers
from poisoning instead of returning a `LockResult`, so it cannot fail.

`std::sync::Mutex` poisons itself when a thread panics while holding it, and
every later `lock().unwrap()` then panics too — a single bug on a single
thread becomes a permanent refusal to answer *any* query, because the poison
never clears. The data behind these locks is a cache, a popularity model, a
rate limiter, and connection pools: each is revalidated on use or safely
discardable, none holds an invariant whose violation could produce a wrong
answer rather than a failed lookup, and the crate denies `unsafe_code`, so a
torn value cannot become undefined behaviour. `src/sync.rs` has a test that
poisons a lock with a deliberate panic and then asserts the lock still hands
back the value it held.

## Live verification

`examples/quick_check.rs` resolves `example.com`, `www.example.com`,
`google.com`, `ietf.org` and `nonexistent.invalid` through the full iterative
pipeline twice (the second pass must hit cache), then prints stats:

```sh
cargo run --no-default-features --features std --example quick_check
```

On a network that answers truthfully, a healthy run resolves all four real
names and returns NXDOMAIN for the invalid one; `ietf.org` exercises the
out-of-zone NS path (afilias-nst.info), which is also the case that catches
QNAME-minimization regressions — a NODATA for a minimized prefix must deepen the
query, not terminate it. On a network that does *not* answer truthfully it proves
only that nothing crashed, which is still worth knowing and is not the same claim
(see below).

## Why the numbers are trustworthy

- No fabricated test vectors: the RSA vector was generated with openssl and
  cross-checked with an independent Python implementation.
- Live names are resolved against the actual DNS tree, not a mock.
- A live run is evidence that the wiring works, not a verdict on correctness.
  The machine this was developed on has an upstream that hijacks UDP/53: two
  thirds of queries to a well-known root address time out, and
  `nonexistent.invalid` comes back empty in 8 ms, which is the interception
  answering rather than the DNS tree. Correctness is therefore settled by the
  hermetic stub tests, and a live run is re-read as "did anything crash".
- The `no_std` core is built *and tested* in CI, so it cannot silently grow a
  `std` dependency.
- CI runs on the MSRV (1.78) and on stable, for Linux and Windows, with
  `RUSTFLAGS=-D warnings`; the release profile (fat LTO, one codegen unit) is
  tested too, because that is the profile that ships.
