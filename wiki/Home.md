# RecurseX wiki

> Version: **0.2.6**. The current contracts are the conditional union bound, disabled-by-default stale service, explicit DNSSEC limitations and loopback-only listener access unless additional CIDRs are configured.


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

## Operating boundaries

Normal cache answers age the authoritative TTL; explicitly enabled stale service
uses the configured positive response TTL. Defaults bound resource use, but an
explicit unlimited connection setting and volumetric attacks still require operator
controls. Transport implementation is not proof of universal interoperability;
DoQ remains experimental.
