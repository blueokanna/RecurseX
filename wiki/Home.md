# RecurseX wiki

A predictive adaptive recursive DNS resolver. The short story is in the
[README](../README.md); this wiki goes one level deeper into how the pieces
actually work and why they are shaped the way they are.

## Contents

- [Architecture](Architecture.md) — the six layers and the data flow.
- [PARR — the prediction core](PARR.md) — Query State Estimator, Resolution
  Planner, stability-aware cache, adaptive resolver.
- [Cache admission & stability math](Cache-Admission.md) — what `CacheScore`
  is made of and why stability is measured, not assumed.
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
