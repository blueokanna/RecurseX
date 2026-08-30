# Architecture

RecurseX is a pipeline, not a blob. Each layer owns one job and talks to the
next through narrow interfaces, so the algorithmic core is `no_std` and the
networked parts are isolated behind the `std` feature.

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. Client Layer            server.rs        UDP/TCP listeners,          │
│                                              per-query response builder │
├────────────────────────────────────────────────────────────────────────┤
│ 2. Query Processing        query.rs         normalize, dedup,           │
│                            policy.rs        coalesce, 0x20, rate-limit  │
├────────────────────────────────────────────────────────────────────────┤
│ 3. Multi-tier Cache        cache/           hot/warm/cold + NXDOMAIN,   │
│                            stability.rs     stability model, score      │
│                            cache/score.rs   admission, serve-stale,     │
│                            cache/persist.rs prefetch, L3 persistence    │
├────────────────────────────────────────────────────────────────────────┤
│ 4. Resolution Engine       resolver.rs      root→TLD→authoritative,     │
│                            engine.rs        CNAME/DNAME, referrals,     │
│                            dnssec/          DNSSEC validation           │
├────────────────────────────────────────────────────────────────────────┤
│ 5. Upstream Transport      transport.rs     DnsTransport trait,         │
│                            transports/      UDP/TCP/DoT/DoH/DoH3/DoQ    │
│                            forward.rs       forwarder set               │
├────────────────────────────────────────────────────────────────────────┤
│ 6. Security / Policy       policy.rs        rate limits, filtering,     │
│                            query.rs         anti-spoofing checks,       │
│                            dnssec/          DNSSEC verdicts             │
└────────────────────────────────────────────────────────────────────────┘
```

## Data flow for one recursive query

1. **Client layer** receives a wire message (UDP datagram or TCP stream).
   It is parsed by the wire codec in `message.rs` / `rdata.rs` / `name.rs`.
2. **Query processing** normalizes the qname (lowercase, trailing dot),
   deduplicates concurrent identical queries (a coalescer with a condvar
   wait), applies the client rate limit, and builds a `QueryKey` (name, type,
   class, ECS partition, DNSSEC flags).
3. **Cache** is consulted first. A fresh hit returns immediately with the
   remaining TTL. An expired-but-within-window entry may be served stale
   (RFC 8767) while a refresh is kicked off. A miss proceeds to the engine.
4. **Resolution engine** walks the tree. It queries the root hints, follows
   referrals one zone at a time, applies QNAME minimization (RFC 9156),
   chases CNAME/DNAME, filters out-of-bailiwick data, and (with `dnssec`)
   validates the answer chain.
5. **Upstream transport** delivers the wire query over the selected
   protocol. UDP truncation falls back to TCP. Encrypted transports are
   feature-gated.
6. **Security/policy** is interleaved: rate limits at the front door,
   response-matching at the engine (ID + question echo), bailiwick rules at
   cache time, DNSSEC verdicts at the end.

Every layer that touches time does so through the `Clock` trait (`time.rs`),
so the whole pipeline can be driven by a manual clock in tests and
simulations.

## Where the no_std boundary is

`--no-default-features` builds the wire codec, cache, estimator, graph,
upstream model, policy and planner without `std` (only `alloc`). Sockets,
threads, the resolver, the server, JSON config and the encrypted transports
are `std`-gated. The no_std core is what makes the prediction machinery
portable to embedded targets that only want the model, not the network.

## Error model

One `Error` type (`error.rs`) with a `kind` — wire, protocol, internal,
transport, io, config. The resolver maps failures to DNS responses
(SERVFAIL) at the client boundary; internal errors never leak wire details.
