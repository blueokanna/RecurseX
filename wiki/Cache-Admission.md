# Cache admission and the change-rate model

The cache is *semantic*: keys are `(name, type, class, ECS partition)`, not
raw wire messages, so a CNAME chain and an NXDOMAIN for the same name live in
different structures. Entries are partitioned into hot / warm / cold tiers
plus a per-name NXDOMAIN store.

## The change-rate model

TTL ≠ data stability. A TTL is a *claim* about the maximum age of an answer;
the number of times the RRset actually changed over a measured exposure is a
*measurement* of a different thing. Every RRset carries a
[`HazardModel`](Refresh-Theory.md) that keeps the measurement:

- a `Gamma(α, β)` posterior over the change rate λ, where α counts changes
  (including a prior shape of 1) and β counts observed seconds;
- `alpha_ev` / `beta_ev` — the *evidence* half of that state, tracked
  separately from the prior, so `has_evidence(secs)` can ask "have we
  actually watched this long?" rather than "does the number look high?";
- a hard ceiling: β never exceeds `w · τ`, where `w` is the prior rate and τ is
  the forgetting constant (24 h). That ceiling is simultaneously the
  non-stationarity mechanism and an anti-forgery bound — see
  [the derivation](Refresh-Theory.md#non-stationarity-and-the-anti-forgery-bound-that-falls-out-of-it);
- `ttl_ewma` / `ttl_volatility` — EWMA of the authoritative TTL and of its
  deviation, which is how a name's TTL is *learned* rather than trusted;
- `consecutive_failures` — refreshes that failed since the last success.

`hazard_upper_bound()` returns the one-sided Chernoff bound `λ_hi` at
confidence `1 − δ = 0.95`; `freshness_lcb(δ)` turns it into the probability
that the data we hold is still correct. The refresh interval is then chosen so
the data is looked at *before* the bound drops below `target_freshness = 0.9`,
which is why a refresh never races the expiry.

Content identity is a fingerprint over the sorted wire form of the RRset with
the TTL field zeroed, so a TTL-only change does not count as a content change —
and neither does an RRSIG rotation. That is deliberate: signature churn is not
data churn, and treating it as such would drive every signed zone's change rate
to the rollover constant.

`durability_score()` is the posterior *predictive* probability over a 60 s
horizon. It is used for **ranking** (what is worth keeping, what is worth
prefetching), never as the safety gate — a decision uses the conservative
bound, because a mean is not a guarantee.

## CacheScore admission

Every entry gets a score on insert and on lookup:

```
CacheScore = α·popularity + β·locality + γ·durability + δ·ttl + ε·cost − ζ·memory
```

with the default weights α=0.30, β=0.18, γ=0.20, δ=0.16, ε=0.11, ζ=0.05.
Each term is normalized to `[0,1]`:

- `popularity` — the estimator's normalized query rate for the zone;
- `locality` — recency of the last serve, decaying over a window;
- `durability` — the hazard model's 60 s posterior predictive probability;
- `ttl` — TTL relative to a reference;
- `cost` — estimated resolution cost relative to a reference (expensive-to-
  resolve data is worth more);
- `memory` — estimated footprint relative to a reference (subtracted).

**This score is a value ranking, not a safety gate.** Nothing is served or
refused because of it. An entry that scores badly is evicted first; an entry
that scores well is prefetched first. Whether a *stale* answer may go out is
decided by the risk model and nothing else.

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

An expired entry stays *eligible* to be served for `stale_window_secs` (default
one day, per RFC 8767's guidance) with a short client-facing TTL
(`stale_serve_ttl`, default 30 s), while a background refresh is queued.
Eligibility is not permission: the planner decides whether stale data may
actually go out, from the risk bound of the answer's provenance and the
consequence class of the record in its role. A delegation record is not an
address record and does not get the same staleness horizon. See
[Refresh-Theory](Refresh-Theory.md#4-value-and-risk-are-different-questions).

## NXDOMAIN store

NXDOMAIN is stored per name (not per type), because it applies to every type
below the name. NODATA (NOERROR, empty) is stored per `(name, type)` key.
Negative TTLs follow RFC 2308: `min(SOA TTL, SOA MINIMUM)`, capped at
`negative_ttl_cap` (default 300 s).

## ECS

ECS and non-ECS answers never mix (RFC 7871 §7.2). The lookup walks *upward*
from the requester's own partition to broader and broader scopes, and finally to
the global partition:

```
P, P-1, …, 1, global
```

where `P` is the requester's prefix length. First hit wins. A broader answer may
serve a more specific client — it was computed for a superset of the query's
network — but a narrower one may not, so the walk only ever goes one way.

Three things make that walk well-defined:

- **The address is truncated, not merely labelled.** `truncate_to(addr, bits)`
  masks the address *and* normalises the octet count to `ceil(bits / 8)`, so
  `10.0.0.0/24` and `10.0.0.0/25` cannot collide as two strings that differ only
  in length.
- **The response decides the partition.** A reply's declared `SCOPE
  PREFIX-LENGTH` (RFC 7871 §6) is folded in with the requester's own prefix:
  `effective = min(declared, prefix)`. A server that declares a wider scope than
  we asked about does not get to widen our key, and a server that declares `/0` —
  or answers a scoped query with no ECS at all, which §7.2.2 tells us to read as
  global — lands the entry in the global partition.
- **Negatives are partitioned too.** A scoped NXDOMAIN or NODATA is filed under
  the scoped key. Only a global partition writes the shared negative store, so a
  `/24`-scoped "does not exist" cannot answer for the whole Internet.

Referral NS and glue records are deliberately *not* partitioned: they are
delegation data about the zone, not an answer about the querier's subnet.

**This implementation never sends ECS.** It handles the scope of answers it
receives. Generating our own ECS would require a client-subnet agreement with
each upstream plus its own privacy analysis, and neither is in scope here.
