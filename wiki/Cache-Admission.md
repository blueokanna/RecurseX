# Cache admission & stability math

The cache is *semantic*: keys are `(name, type, class, ECS partition)`, not
raw wire messages, so a CNAME chain and an NXDOMAIN for the same name live in
different structures. Entries are partitioned into hot / warm / cold tiers
plus a per-name NXDOMAIN store.

## The stability model

TTL ≠ data stability. Every RRset carries a `StabilityModel`:

- `samples` / `changes` — how many refreshes, and how many changed the data;
- `stability` — an EWMA in `[0,1]`, pulled toward `1` by unchanged refreshes
  (α = 0.2) and sharply toward `0` by a change (α = 0.4);
- `change_ratio` — the long-run `changes / samples`;
- `ttl_ewma` / `ttl_volatility` — EWMA of the authoritative TTL and of its
  deviation;
- `consecutive_failures` / `failures` — refresh failures since the last
  success.

Content identity is a fingerprint over the sorted wire form of the RRset with
the TTL field zeroed, so a TTL-only change does not count as a content
change. `is_very_stable` requires enough samples and a high score; those sets
are refreshed in the background and trusted for serve-stale.

## CacheScore admission

Every entry gets a score on insert and on lookup:

```
CacheScore = α·popularity + β·locality + γ·stability + δ·ttl + ε·cost − ζ·memory
```

with the default weights α=0.30, β=0.18, γ=0.20, δ=0.16, ε=0.11, ζ=0.05.
Each term is normalized to `[0,1]`:

- `popularity` — the estimator's normalized query rate for the zone;
- `locality` — recency of the last serve, decaying over a window;
- `stability` — the stability model score;
- `ttl` — TTL relative to a reference;
- `cost` — estimated resolution cost relative to a reference (expensive-to-
  resolve data is worth more);
- `memory` — estimated footprint relative to a reference (subtracted).

Admission thresholds: below `min_admit_score` the entry is not cached at all;
`hot_admit_score` promotes to the hot tier, `warm_admit_score` to warm. The
tiers have hard capacities.

## Eviction

Eviction is exact and cheap. Each tier keeps a secondary index keyed by
`(quantized score, key)`, so "the lowest-scored entry" is found and removed in
`O(log n)` — no scan of the tier, and no sampling either. The obvious
implementation (walk the tier, take the minimum) is `O(n)` per insert once the
cache is full, which makes filling a cache `O(n²)` and puts an attacker-chosen
amount of work on the insert path.

Evicting from hot or warm demotes the victim one tier instead of dropping it,
so a valuable entry gets a second chance. That demotion is deliberately *not*
recursive: a cascading demotion would make the cost of a single insert
unbounded.

An entry below `min_admit_score` is not cached at all, so what the cache keeps
is what the score says is worth keeping.

## Serve-stale and prefetch

An expired entry stays servable for `stale_window_secs` (default one day,
per RFC 8767's guidance) with a short client-facing TTL
(`stale_serve_ttl`, default 30 s), while a background refresh is queued. The
planner decides whether stale data is worth serving given the predicted
query probability. Near-expiry entries with a high predicted probability are
prefetched by the maintenance loop (bounded per tick).

## NXDOMAIN store

NXDOMAIN is stored per name (not per type), because it applies to every type
below the name. NODATA (NOERROR, empty) is stored per `(name, type)` key.
Negative TTLs follow RFC 2308: `min(SOA TTL, SOA MINIMUM)`, capped at
`negative_ttl_cap` (default 300 s).

## ECS

ECS and non-ECS answers never mix (RFC 7871 §7.2): a non-ECS query only sees
non-ECS entries; an ECS query tries its exact partition first, then falls
back to the non-ECS partition.
