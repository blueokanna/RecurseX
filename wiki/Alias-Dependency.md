# Alias dependency

A resolver serves `www.example.com A` from cache only while **both** the CNAME
at `www` and the target's address data are fresh. That is a dependency between
two cache entries, and a cache cannot represent it: `BTreeMap<key, data>` has
no notion of one entry being useful only while another is fresh.

`src/alias.rs` records that one relation and nothing else.

## The relation

```
(www.example.com, CNAME) ──alias──▶ (cdn.example.net, A)
```

The resolver records an edge whenever it follows a CNAME — whether the hop came
from the network or from cache — so a chain seen once through the wire keeps
the same dependency when it is later served from cache.

Both directions are stored:

- `dependents(key)` — the aliases that `key` keeps servable;
- `depends_on(key)` / `closure(key, max)` — the data an alias needs fresh.

## What it buys

**Chain-coherent refresh.** The maintenance loop's predictive prefetcher calls
`Resolver::refresh_with_dependents`. Refreshing a target also queues the
aliases that point at it, so the whole chain is fresh together. Refreshing only
the target leaves the next client query to walk the chain and pay for a
resolution anyway — half a prefetch is worthless.

The same call is used by serve-stale hits in the request path, so a stale chain
member coming back brings its aliases with it.

## Bounding

`max_edges` caps the graph; at the cap a new edge is simply not recorded (the
prune makes room again), which keeps `link` at `O(log n)` instead of putting an
eviction scan on the resolution path. The maintenance thread calls
`prune(now, max_age)` on every tick and samples the edge count into the
statistics as `alias_edges`.

## History

An earlier revision of this module was a general resolution graph with zone,
nameserver and server-address nodes and five edge kinds. Every resolution step
paid to write those edges and no decision ever read them. It was deleted in
favour of the structure above: one relation, one purpose, one consumer.
