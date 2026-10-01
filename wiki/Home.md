# RecurseX wiki

A predictive adaptive recursive DNS resolver. The short story is in the
[README](../README.md); this wiki goes one level deeper into how the pieces
actually work and why they are shaped the way they are.

## Contents

- [Architecture](Architecture.md) — the six layers and the data flow.
- [**Risk-constrained refresh**](Refresh-Theory.md) — the hazard model, the
  credibility bound, the risk budget and dependency-consistent refresh. This
  is the design document for the part of the resolver that is not "a careful
  implementation of known techniques".
- [**Value of information**](Value-of-Information.md) — what one more
  observation is worth, and which entries a finite refresh budget should be
  spent on. The allocation half of the same theory.
- [PARR — the prediction core](PARR.md) — Query State Estimator, Resolution
  Planner, the change-rate model, adaptive resolver.
- [Cache admission and the change-rate model](Cache-Admission.md) — what
  `CacheScore` is made of, why it is a value function rather than a safety
gate, and how ECS partitions the key space.
- [Alias dependency](Alias-Dependency.md) — why a cache needs a second
  structure to keep a CNAME chain servable as a unit.
- [Upstream selection cost model](Upstream-Selection.md) — why raw RTT is the
  wrong signal, and what we rank on instead.
- [DNS policy layer](DNS-Policy.md) — Clash-compatible `hosts`, fake-IP,
  `nameserver-policy` and `fallback-filter`, and why an unknown key is now an
  error.
- [DNSSEC](DNSSEC.md) — what is validated, how, and the honest scope.
- [Persistence](Persistence.md) — the L3 tier: format, atomicity, restore
  rules.
- [Deployment & hardening](Deployment.md) — running it in front of real
  clients, rate limiting, spoofing defenses.
- [Testing & verification](Testing.md) — what the suite covers and how to
  reproduce the live checks.
- [**Beyond the lookup**](Beyond-The-Lookup.md) — what of the
  "serverless / behavioural-hash / holographic" proposal is impossible and why,
  and what part of it is real and is now in the crate: keyed behavioural
  identity and weighted rendezvous selection.
- [**The paper**](../paper/RecurseX-risk-constrained-refresh.md) — the same
  argument written for reviewers: model, theorems, evaluation protocol,
  limitations, and what it refrains from claiming.

Chinese versions of the core pages are available as `*-zh.md` next to these
files.

## Ground rules (read this first)

1. **TTL is never invented.** Every prediction the resolver makes only tunes
   *internal* policy. The TTL a client sees is exactly what the authority
   returned (minus elapsed time for cached data).
2. **Nothing unbounded.** Every model in this crate has a hard cap. A hostile
   query stream can make the resolver busy, but it cannot make it grow
   without bound.
3. **No faked transports.** Every transport ships a real, usable
   implementation. If a layer were only a stub, the crate would say so
   instead of pretending.
