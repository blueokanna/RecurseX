# PARR — the prediction core

"Predictive Adaptive Recursive Resolver" is the name for the whole feedback
loop: the resolver *measures* the query stream and the upstream behavior, and
*tunes* its own cache and transport policy from those measurements. The loop
has four stages.

```
┌─────────────────┐     ┌──────────────────┐     ┌────────────────────────────┐
│ Query State     │────▶│ Resolution        │────▶│ Cache / Prefetch /         │
│ Estimator       │     │ Planner          │     │ Parallel / Adaptive        │
│ (estimator.rs)  │     │ (planner.rs)     │     │ Resolver (resolver.rs)     │
└─────────────────┘     └──────────────────┘     └────────────────────────────┘
        ▲                                                     │
        └────────────── observe outcomes ─────────────────────┘
```

## Stage 1 — Query State Estimator

DNS queries are not independent events. They arrive with time-of-day
structure (the office hits `mail.example.com` at 9am, the batch job at
midnight), short-term recency bursts, and long-run popularity. Per zone apex
the estimator keeps:

- a **time-of-day profile**: 96 buckets of 15 minutes each, counting queries;
- a **short-term EWMA rate** with a ring of recent timestamps;
- **popularity** (normalized rate);
- **observed upstream cost** (EWMA of resolution RTT).

It answers the two questions the planner needs:

- `P(a query for this zone within the next Δt seconds)` — from the TOD
  profile plus a recency boost;
- the zone's normalized popularity, for cache admission.

Memory is bounded: `max_domains` caps how many zones are tracked, and
eviction is by staleness. The estimator is `no_std`-clean. The exponential
decay uses a self-contained `exp` (no `libm`, which is not in the allowed
dependency set) — see the module doc for the accuracy budget (~1e-11 relative
error).

## Stage 2 — Resolution Planner

Given the cache outcome of a query and the estimator's prediction, the
planner picks one of four plans:

| Plan                  | When                                                     |
|-----------------------|----------------------------------------------------------|
| `ServeFresh`          | entry is live                                            |
| `ServeStaleAndRefresh`| expired, within the stale window, query likely (p ≥ threshold) |
| `Prefetch`            | entry is live but near expiry and likely to be asked     |
| `Resolve`             | miss, or stale data with a low predicted probability     |

The planner is deliberately simple and stateless — all the state lives in the
estimator and the cache. Default thresholds: `stale_serve_min_prob = 0.5`,
`stale_refresh_stability = 0.85`, `prefetch_horizon_secs = 60`.

## Stage 3 — Stability-aware cache

The cache is described in [Cache-Admission](Cache-Admission.md). The key
point for PARR: **the cache never serves a predicted TTL**. It uses the
stability model to decide *when* to refresh in the background (very stable
sets), *whether* to serve stale while refreshing, and *what* to admit or
evict. The estimator's probability drives prefetch fan-out: the maintenance
loop walks entries near expiry and refreshes those whose predicted query
probability clears the bar, bounded per tick.

## Stage 4 — Adaptive resolver

Upstream selection is adaptive per authority ([Upstream-Selection](Upstream-Selection.md)),
and the alias dependency graph ([Alias-Dependency](Alias-Dependency.md)) makes a
single refresh decision cover a whole CNAME chain instead of one hop of it.
Both feed their observations back into the estimator and the upstream model,
closing the loop.

## The one rule that keeps it honest

Every prediction tunes *internal timing and admission* — never the bytes we
send to a client. If an authoritative server says TTL 300 and the data has
been stable for a month, we may refresh it in the background before it
expires, and we may serve it stale for a short window, but the TTL field in
our answer is still what the authority said. This is what makes PARR a policy
layer on top of correct DNS, rather than a cache that lies.
