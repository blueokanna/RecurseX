# RecurseX

A predictive adaptive recursive DNS resolver written in Rust. It walks the
delegation tree the way BIND/Unbound do, but the caching layer is not a
`HashMap<query, answer>`. Every entry carries a stability model, an admission
score, and a tier, and the resolver predicts *which* data is worth keeping,
*when* it is going to be asked for, and *which* upstream to ask — without ever
inventing a TTL.

```
Client Layer ──▶ Query Processing ──▶ Multi-tier Semantic Cache ──▶ Resolution Engine ──▶ Upstream Transport
  UDP / TCP         normalize         hot / warm / cold / NXDOMAIN    root→TLD→auth      UDP / TCP / DoT
  (DoT/DoH/DoH3/    dedup / ECS       stability + score admission     CNAME/DNAME/NS      DoH / DoH3 / DoQ
   DoQ acceptor)    QNAME min.        serve-stale / prefetch          DNSSEC validate
                                                                              │
                                                                              ▼
                                                                      Security / Policy
                                                                      rate limit · filtering
                                                                      anti-spoofing · DNSSEC
```

## Why this exists

TTL is what an authoritative server *claims*. It is not a measurement of how
often the data actually changes. A `3600` on a record that rotates every five
minutes and a `3600` on a record that has not moved in six months are
completely different animals, and a cache that treats them the same is wasting
memory and requests. RecurseX measures the observable history of every RRset
and lets that history drive the internal policy — prefetch timing, serve-stale
willingness, admission, eviction — while the TTL you serve to clients stays
exactly what the authority said.

The core prediction loop (the "PARR" brain, see `wiki/PARR.md`):

```
Query State Estimator ──▶ Resolution Planner ──▶ Cache / Prefetch / Parallel ──▶ Adaptive Resolver
  popularity                serve vs stale          stability-aware tier          picks servers by
  temporal locality         vs prefetch vs resolve  background refresh            expected cost
  TTL behavior
```

## Feature set

- **Full recursive resolution** — root → TLD → authoritative, with
  CNAME/DNAME chasing, NS referrals, glue, and bailiwick filtering.
- **QNAME minimization (RFC 9156)** — the resolver never reveals more of the
  qname than it has to; empty answers to minimized prefixes deepen the query
  instead of terminating it.
- **EDNS(0)** with ECS (RFC 7871), cookies, keepalive, NSID, padding.
- **0x20 randomization** and transaction-ID checking as anti-spoofing
  (cache-poisoning defense).
- **Multi-tier semantic cache** — hot / warm / cold + NXDOMAIN store.
  Score-driven admission (`CacheScore`), serve-stale (RFC 8767), predictive
  prefetch, CNAME-chain walking.
- **Query State Estimator** — per-zone time-of-day profile, short-term EWMA
  rate, popularity, upstream cost. Bounded memory.
- **Resolution Graph** — tracks `depends_on` / `delegates_to` / `cname_to` /
  `served_by` / `reachable_via` across queries so prefetch can fan out across
  a whole dependency set.
- **Adaptive upstream selection** — per-authority EWMA RTT, loss and SERVFAIL
  models; selection minimizes *expected resolution cost*, not raw latency.
- **Encrypted transports** — DoT (RFC 7858), DoH (RFC 8484), DoH3, and the
  DoQ protocol layer (RFC 9250) via the `dot` / `doh` / `doh3` / `doq`
  features, built on courierust.
- **Forwarding** — UDP/TCP/DoT/DoH/DoH3/DoQ forwarders, forward-first with
  iterative fallback.
- **DNSSEC** (`dnssec` feature) — RRSIG validation (RSA PKCS#1 v1.5 +
  SHA-256), DS digest chains, `Secure` / `Insecure` / `Bogus` verdicts.
- **L3 persistent cache** (`persist` feature) — rustbinary-serialized
  snapshot (stability models, scores and tiers survive a restart), atomic
  writes, bounded decode.
- **Policy** — token-bucket rate limiting per client, name filtering,
  validation gate.
- **no_std core** — the wire codec, cache, estimator, graph and upstream
  model compile without `std`; the networked resolver is `std`-gated.

## Quick start

```rust
use recurse_x::{Name, RrType, Resolver, ResolverConfig};

let resolver = Resolver::new(ResolverConfig::default());

let name = Name::from_ascii("ietf.org").unwrap();
match resolver.resolve(&name, RrType::A) {
    Ok(res) => {
        // res.answers, res.ttl, res.validated, res.from_cache ...
        for r in &res.answers {
            println!("{} {:?}", r.name, r.rdata);
        }
    }
    Err(e) => eprintln!("resolution failed: {e}"),
}
```

Run the bundled live check (needs network):

```sh
cargo run --no-default-features --features std --example quick_check
```

It resolves a handful of names through the full iterative pipeline twice — the
second pass should come from cache. Verified against the live tree on a normal
connection (example.com ~127 ms, google.com ~3.2 s first hit, ietf.org ~0.7 s,
`nonexistent.invalid` → NXDOMAIN in ~23 ms).

### Examples

The `examples/` directory has several self-contained, runnable programs:

| Example | What it shows |
| ------- | ------------- |
| `quick_check` | live end-to-end iterative resolution + cache hits |
| `multi_type_resolve` | resolving A / AAAA / MX / TXT / NS / SOA for a name |
| `server_demo` | a local UDP+TCP DNS server, JSON config, self-test |
| `custom_config` | building a strict resolver entirely in code |
| `forward_resolver` | forwarding through DoT / plain UDP (RFC 8484-style) |
| `persist_cache` | L3 snapshot: warm cache survives a restart |

```sh
cargo run --example multi_type_resolve
cargo run --example custom_config
cargo run --example persist_cache
cargo run --example forward_resolver
cargo run --example server_demo   # blocks; query it with dig -p 5353
```

### Client-facing server

```rust
use recurse_x::{Resolver, ResolverConfig, Server};

let resolver = Resolver::new(ResolverConfig::default());
let server = Server::new(resolver);
let addr = server.bind_udp("127.0.0.1:5353".parse().unwrap())?;
server.bind_tcp("127.0.0.1:5353".parse().unwrap())?;
// dig @127.0.0.1 -p 5353 example.com A
```

### JSON configuration

The whole resolver is configurable from one JSON document (nextjson):

```json
{
  "listen": [{ "addr": "0.0.0.0:53", "proto": "udp" }],
  "cache": { "hotCapacity": 2048, "warmCapacity": 131072 },
  "engine": {
    "qnameMinimization": true,
    "use0x20": true,
    "dnssec": true,
    "forwarders": [
      { "proto": "dot", "ip": "1.1.1.1", "port": 853, "host": "cloudflare-dns.com" }
    ]
  },
  "persist": { "path": "/var/lib/recursex/cache.rxc", "saveIntervalMs": 60000 }
}
```

```rust
let cfg = recurse_x::config::Config::from_json_str(json)?;
let rc = cfg.into_resolver_config()?;
let resolver = Resolver::new(rc);
```

### Background maintenance

```rust
let resolver = Resolver::new(ResolverConfig::default());
let _thread = resolver.spawn_maintenance(); // sweep + graph prune + predictive prefetch
```

The maintenance loop sweeps dead entries, prunes the resolution graph, and
runs predictive prefetch over the estimator's candidates. With `persist`
enabled it also writes the cache snapshot on the configured interval.

## Design decisions worth knowing

- **TTL is authoritative.** The estimator and planner never alter the TTL you
  serve. They only tune *internal* timing (when to refresh, whether to serve
  stale, what to admit). If an authority says `300`, clients get `300`.
- **Admission is score-driven.** `CacheScore = α·popularity + β·locality +
  γ·stability + δ·ttl + ε·cost − ζ·memory`, with α=0.30, β=0.18, γ=0.20,
  δ=0.16, ε=0.11, ζ=0.05 by default. Entries below `min_admit_score` are not
  cached at all; the hot tier takes the highest-scored ones.
- **Stability is measured, not assumed.** Each RRset tracks sample count,
  change ratio, EWMA stability, TTL EWMA and volatility, and consecutive
  failures. Very stable sets are refreshed in the background; volatile ones
  are never trusted stale.
- **Eviction is honest.** The lowest-scored entry is evicted by sampling
  (bounded work per eviction), not by a fixed recency policy.
- **Spoofing defense is layered.** Response matching checks ID + question
  echo, 0x20 randomization is on by default, and glue/bailiwick rules decide
  what may be cached from a response.
- **Bounded everywhere.** The estimator caps tracked zones, the graph caps
  nodes, the cache caps tiers, the coalescer caps in-flight queries, the
  policy engine caps client buckets. Hostile query streams cannot grow memory
  without bound.

## Honest limitations

- **DNSSEC scope**: RRSIG validation implements RSA PKCS#1 v1.5 with SHA-256
  (from-scratch limb arithmetic, no external crypto dependency). ECDSA and
  SHA-1 signatures are not validated yet.
- **DoQ transport**: a from-scratch RFC 9000/9001/9002 QUIC v1 client plus
  RFC 9250 framing, session semantics and error codes. The QUIC transport
  and the QUIC-TLS 1.3 handshake are implemented directly on courierust's
  public wire codecs (packet/frame codecs, X25519, HKDF, RSA-PSS/
  PKCS#1/ECDSA/Ed25519 verification), so the default transport talks to real
  RFC 9250 servers. A custom QUIC stack can still be substituted through the
  [`DoqProvider`](https://docs.rs/recurse-x/latest/recurse_x/transports/doq/trait.DoqProvider.html) trait.
- **Time**: `tzcraft` has no IANA timezone database, so the estimator's
  time-of-day profile is wall-clock UTC.
- **No DNS-over-HTTPS server side**: the client-facing server accepts plain
  UDP/TCP. DoT/DoH/DoH3/DoQ are upstream transports.
- **`cargo build` needs a network on first run** (courierust et al. are
  fetched from crates.io).

## Feature flags

| Feature   | Default | What it adds                                    |
|-----------|---------|-------------------------------------------------|
| `std`     | yes     | networked resolver, server, config              |
| `dot`     | yes     | DoT upstream transport (courierust TLS)         |
| `doh`     | yes     | DoH upstream transport (courierust HTTP client) |
| `doh3`    | yes     | DoH3 upstream (implies `doh`)                   |
| `doq`     | yes    | DoQ (RFC 9250) upstream transport, from-scratch QUIC client |
| `dnssec`  | yes     | DNSSEC validation                               |
| `persist` | yes     | rustbinary-backed L3 persistent cache           |

The algorithmic core (`--no-default-features`) is `no_std` + `alloc`.

## MSRV and CI

- **MSRV: Rust 1.78** (`rust-version = "1.78"`, pinned by `rust-toolchain.toml`).
  The no_std core deliberately avoids libm-style float methods that only
  landed in `core` after 1.78 (see `src/float.rs`).
- **CI** (`.github/workflows/ci.yml`) runs on the MSRV toolchain and on
  stable: `cargo fmt --check`, `cargo clippy -D warnings` (all features and
  the no_std lib), `cargo build` for every feature combination, and
  `cargo test --all-features`.

## Testing

```sh
# full suite, all features (MSRV toolchain)
cargo +1.78.0 test --all-features

# no_std core build + lint
cargo +1.78.0 build --no-default-features
cargo +1.78.0 clippy --no-default-features --lib -- -D warnings

# strict lint (all features)
cargo +1.78.0 clippy --all-targets --all-features -- -D warnings
```

The suite is 130 tests: wire codec, cache/stability/admission, estimator,
planner, graph, upstream model, policy, engine classification, resolver
orchestration, server, config JSON round-trip, encrypted transports, DNSSEC
(including an authentic openssl-generated 1024-bit RSA vector), the persistent
cache (round-trip, stale-parking, dead-entry drop, tamper rejection), the
self-contained float helpers, OS-entropy seeding, and UDP truncation.

## Security hardening

- **OS-entropy PRNG seeding**: query IDs and 0x20 QNAME case are drawn from a
  SplitMix64 generator seeded from the OS CSPRNG (courierust's
  `fill_random`; pure-std `RandomState` fallback), and the generator is
  periodically reseeded so an observer who recovered part of the stream
  cannot predict far ahead (`src/entropy.rs`).
- **UDP truncation**: the server never sends a datagram larger than the
  client's advertised EDNS payload size — it sets TC and drops records per
  RFC 6891 §6.2.5, which also prevents reflection amplification
  (`Message::truncate_for_udp`).
- **Bounded wire parsing**: section-count limits, a 255-octet name cap, and
  a 40-hop compression-pointer loop guard reject malformed packets before
  any allocation of note.
- **Per-client rate limiting** with a bounded bucket table, bailiwick
  discipline on cache admission, and response matching on ID + question
  echo.

## License

Apache-2.0.
