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

The planner answers one question per cache outcome. Note which question it
*stops* asking: popularity decides what is **worth** refreshing, never what is
**safe** to return. Those are two different ledgers, and conflating them was the
mistake the risk-constrained model exists to fix.

| Outcome | Plan | Decided by |
|---------|------|-----------|
| entry is live | `ServeFresh` | the entry's own TTL |
| entry is expired, inside the stale window | `ServeStale { refresh_in_background }` | the risk model |
| miss, or stale refused | `Resolve` | — |

For a stale entry the planner computes a risk

$$R = V \cdot (1 - P_{\text{LCB}}) \cdot C \cdot \kappa$$

and refuses — `Resolve` instead — unless *all four* hold: the consequence class
permits stale data at all, the staleness is inside that class's horizon, the
answer's conservative freshness clears `1 - (1 - \text{base}) / C`, and the
over-serving ledger has room. `V` is the expected saved latency, so an answer
worth 20 ms that is 99 % likely correct is not worth defending a bad one at
1000× the price. See [Refresh-Theory](Refresh-Theory.md) for the derivation.

`Prefetch` is not a plan. It is a separate policy consulted by the maintenance
loop: an entry is a prefetch candidate when its model has at least
`min_evidence_secs` (300 s) of actual exposure, the query is likely enough
(`p >= 0.5` over the next 60 s), and the current time is close enough to expiry
that a refresh now would buy the target freshness (0.9). The horizontal
probability is the estimator's; the vertical "would it have changed" is the
hazard model's. Defaults: `min_evidence_secs = 300`, `prefetch_horizon_secs =
60`, `prefetch_min_probability = 0.5`, `prefetch_target_freshness = 0.9`.

That test admits a candidate. **Which admitted candidate gets the next token is
a separate question**, and it is answered by [value of
information](Value-of-Information.md): each due entry is priced by the expected
reduction in the risk functional that one more observation would produce, and
the budget goes to the largest values.

The planner is stateless — every number it consumes lives in the hazard model,
the estimator, or the cache. The only mutable state it touches is the risk
ledger, which is passed in explicitly so a caller can inspect or reset it.

## Stage 3 — The change-rate model and the cache

See [Cache-Admission](Cache-Admission.md) and
[Refresh-Theory](Refresh-Theory.md). The key point for PARR: **the cache never
serves a predicted TTL.** The authority's number goes out unchanged; the model
only decides *internal* timing and admission.

What the model adds over an EWMA score is a *measurable* quantity. A TTL is a
claim; the number of times an RRset actually changed over a measured exposure is
a measurement. The estimator's popularity says how often the name is *asked*;
the hazard model says how often the data *moves*. The two are orthogonal, and
the maintenance loop needs both: popularity without a change rate prefetches
immortal records forever, and a change rate without popularity spends the
refresh budget on names nobody asks for.

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
