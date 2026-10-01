# Beyond the lookup

A proposal was put to this project: replace destination-addressed routing with a
**behavioural hash**, replace deterministic resolution with **probabilistic
superposition**, make the **name itself the route**, and replace caching with
**holographic geometric synchronisation**. Four radical breaks with DNS, each
presented as "non-associative" — a break with the axioms rather than an
extension of them.

This page says, for each one, what is impossible and why, and what part of it is
real and is now in the crate. It is written that way on purpose. A design
document that lists four inventions and omits the two that violate a theorem is
not ambitious, it is wrong, and the wrongness is expensive: the parts that
cannot work are exactly the parts a reader would rely on.

The two mechanisms that came out of this are real, tested, and documented on
their own terms: [`src/behavior.rs`](../../src/behavior.rs) and
[`src/rendezvous.rs`](../../src/rendezvous.rs).

---

## 1. Behavioural-hash routing

**The claim.** A packet leaving the NIC is not addressed to a destination IP but
to a *behavioural hash* of the destination; routers forward by mathematical
distance in the hash space instead of consulting a routing table or DNS.

**Why it cannot be done as stated.** Two independent obstructions, either one
fatal.

*The sender cannot compute it.* A behaviour is a property of a destination,
measured over time. The sender has not reached the destination — that is what
routing is for. Any hash the sender can compute is a hash of something the
sender already knows: a name, a policy, a hint. That is a name, and names are
what we already have.

*Distance in a hash space is not a next hop.* Even granting the hash, "forward
in the direction of decreasing distance" is not a forwarding rule: a router
needs, for each region of the space, an interface. That mapping is a routing
table. Computing it lazily from the hash means every router must know the global
distribution, which is a routing table with extra steps and worse convergence
properties. Geometric routing works on *embedded* graphs — a planar graph with
faces, as in greedy face routing — where the embedding comes from physical
position. A hash space has no embedding; it is a uniform random space by
construction, and greedy forwarding on a random graph has no delivery guarantee.

**What is real, and is now built.** The *use* of behaviour in a local decision,
with the name kept out of it. `src/behavior.rs` derives a **keyed, coarse
behavioural fingerprint** from the measurements the resolver already makes — the
one-sided change-rate bound, the TTL and its volatility, the trust level, the
resolution cost — quantised at one bucket per doubling so it does not churn, and
tagged under a 128-bit secret drawn from the OS.

Two properties follow, and both are defects being repaired rather than features
being added:

* **A fleet stops self-synchronising.** Two entries that are equally due for a
  refresh used to be ordered by name. Every resolver in a fleet holding the same
  entries therefore refreshed the same names in the same sequence, so the
  authoritative saw one thundering herd instead of a spread. The fingerprint
  decorrelates the order without changing the *criterion*: the ordering is still
  ascending `P_LCB(fresh, horizon)`, and only the ties move.
* **An off-path observer cannot predict us.** With the order a public function
  of the query, an observer who can see a query knows which entry we look at
  next. The interval between an entry's last observation and its next refresh is
  exactly the interval in which a forged answer has the best chance of being the
  one that ends up in the model — so knowing the schedule is a targeting
  primitive. The key removes it, and `Debug` redacts the key, and there is no
  accessor that returns it, because an accessor's only realistic outcome is a
  log line.

**What it is not.** It is not an address. It cannot route a packet. It is not
visible on the wire and is not meant to be.

---

## 2. Probabilistic resolution

**The claim.** Stop returning an exact address. Return a probability
distribution, or an "energy orbital". Until a connection is established, the
packet exists in a superposition of possible destination nodes; DNS becomes a
funnel that reduces network entropy, so there is no fixed authoritative IP for a
DDoS to aim at.

**Why it cannot be done as stated.** A packet is a byte sequence. At every hop it
has exactly one next hop, and "observation" is not a physical act that collapses
a state — it is just arrival. There is no mechanism by which a router holds a
packet in superposition, and if there were, the packet would still have to leave
by one interface. A distribution is not something a network can carry; it is
something an *endpoint* can sample from, and that is a different claim.

The DDoS half is worse than unsupported, it is inverted. Removing the fixed
address does not remove the target, it moves it: the authoritative server still
exists, still has an address, and is still the only thing that can sign the zone.
A resolver that returns a "probability cloud" still sends its queries to that
server. What actually absorbs a volumetric attack is *distribution* — anycast,
a large footprint of independent resolvers, and a cache that answers without
asking anyone.

**What is real, and is now built.** The legitimate mechanism behind "the answer
is not a single fixed target": **weighted rendezvous selection**, in
`src/rendezvous.rs`. A delegation's servers are candidates; the ones whose
measured expected cost is inside a tolerance band are, by construction,
indistinguishable at the resolution of the measurements; among *those* the
server is chosen by a pure function of a secret and the question:

```text
score_i = −ln(U_i) / w_i ,    U_i uniform on (0, 1] from the keyed hash
select argmin score_i
```

Three properties, each proved rather than asserted:

| Property | Statement | Why it holds |
|---|---|---|
| Reproducible | every resolver with the same key and candidates makes the same choice for the same question | the score is a pure function of `(key, question, candidate)` |
| Weighted | candidate `i` wins with probability `w_i / Σ w_j` | `−ln(U)` is exponential with rate 1, so `−ln(U)/w` has rate `w`; the minimum of independent exponentials wins with probability proportional to its rate |
| Minimal disruption | withdrawing one candidate changes **only** the questions it was winning | the other scores do not depend on which candidates are present |

The third is asserted *exactly* in the test suite — the number of questions that
move when a candidate is withdrawn is compared for equality with the number that
candidate was winning, not within a tolerance. A modulo-based construction fails
it completely, which is why it is not used.

The differences from a "probability cloud" are worth stating plainly. The
**answer is unchanged**: all records are returned, the RRset is a set
(RFC 2181 §5.1), and *this selection happens between us and the authoritative,
not between the client and us*. A client sees the zone's answer. The
distribution is over our own next hop, which is the only place a resolver can
legitimately act.

The security half is the key. An attacker who can compute which authoritative we
will contact for a given name can aim a spoofing attempt at exactly that path.
The key comes from OS entropy at startup and never leaves the process.

**What is not claimed.** This does not mitigate a volumetric attack on an
authoritative. It removes *fleet convergence* — the case where a whole resolver
fleet behaves as one machine against a redundant server set, which is a real and
common defect, and which is what `affinity_lotteries` counts. Claiming more
would be false.

---

## 3. Name-native routing

**The claim.** Names and addresses are separated by DNS; remove the separation.
A random network node has no IP; the name *is* the route, and routers forward on
the intent inside the name plus live congestion, collapsing the resolution and
transport layers into one.

**Prior art, stated plainly.** This is information-centric networking, and it is
about twenty years old. The IRTF published the research challenges in
**RFC 7927** (2016) and the architectural considerations in **RFC 8569** (2019);
NDN, CCNx and PURSUIT are long-running programmes with production-adjacent
deployments. "Name-based routing as a replacement for the DNS layer" is not a
novel proposition, and a patent claim to it would be read against that body of
work on the first office action. Presenting it here as an unclaimed break with
the axioms would be a factual error about the field.

**What is real and already in this crate.** The parts of the idea that are
standards-track and genuinely usable:

* **The cache is keyed on names, not addresses.** `CacheKey` is
  `(name, type, class, ECS partition)`. A CNAME chain and an NXDOMAIN for the
  same name live in different structures under the same key space.
* **A name can carry its own steering parameters**, inside DNS, today:
  **SVCB / HTTPS** (RFC 9460) expresses `ipv4hint`, `ipv6hint`, ALPN, port
  overrides and `mandatory` parameters — the closest thing to "the name contains
  the route" that a client can act on without a new internet.
* **Intent is already a first-class layer** in this crate: `policy.rs` and
  `routing.rs` implement `nameserver-policy`, `fallback-filter`, `hosts` and
  fake-IP, which is policy routing by name.

No new mechanism is claimed for this item. The honest contribution is that the
resolver implements the standards-track version of it.

---

## 4. Holographic synchronisation

**The claim.** Abandon cache and primary-replica replication. Map the global
state of the name space into one high-dimensional geometric model; a change is a
perturbation of curvature that every node perceives "simultaneously, within the
light-speed limit". TTL disappears because consistency is immediate and
absolute, so CAP's cache-layer trade-off is eliminated.

**Why it cannot be done as stated.** Three separate impossibilities.

*"Simultaneously" and "within the light-speed limit" cannot both hold.*
Simultaneity is frame-dependent, and a perturbation propagating at `c` arrives
at a distant node at a strictly later time. That interval is a propagation
delay. A propagation delay on data whose truth changes is exactly what a TTL
bounds. Renaming it does not remove it; a system with a bounded staleness is a
cached system, whatever the mechanism.

*CAP is a theorem, not an implementation limit.* Given a partition, a request
must either be answered with possibly-stale data or refused. Those are the only
options, and choosing is what "AP" and "CP" name. No representation removes the
choice. **FLP** adds that deterministic consensus cannot be both safe and
live under asynchrony. These are proofs; a curvature field does not falsify
them.

*Removing the cache re-creates the problem the proposal claims to solve.* A
cache is what lets a resolver answer without asking anyone. Delete it and every
query reaches the authoritative — which is the definition of the amplification a
volumetric attack wants. The proposal's DDoS claim and its no-cache claim point
in opposite directions.

**What is real and already in this crate.** Making staleness *provable* instead
of assumed, which is the only part of the idea with content:

* **A credibility bound, not a guess.** `HazardModel` produces a one-sided
  Chernoff bound on the change rate, so "this is still correct with probability
  `p`" is a statement with a derivation behind it. An operator can set the
  probability they accept; the system can say whether it is met.
* **Forgetting as an anti-forgery ceiling.** The same `τ` that models
  non-stationarity caps accumulated evidence at `wτ`, so no series of forged
  "unchanged" observations can drive the change rate to zero. A system that
  claimed perfect consistency would have no such ceiling, and no way to notice
  that it was being fed.
* **A dependency-consistent answer.** A stale answer is only as fresh as the
  weakest member of its provenance set, and refusing at the *bottleneck* is what
  makes a refresh worth spending.

These reach the same goal by the available route: the staleness that cannot be
removed is bounded, measured, and reported, instead of being denied.

---

## What actually changed

| Module | What it is | Where it acts |
|---|---|---|
| `behavior.rs` | keyed, coarse behavioural identity of an entry | the refresh order's tie-break, so a fleet decorrelates and an observer cannot predict the schedule |
| `rendezvous.rs` | weighted highest-random-weight selection with a cost tolerance band | which authoritative a question goes to, so a redundant server set is used as one |
| `voi.rs` | the expected reduction in risk one more observation buys | which entries a finite refresh budget is spent on, instead of a threshold that can only say "look at this too" |

All three are `no_std`, all three use only the primitives already in the crate
(SipHash-2-4 for the keyed tag, the crate's own `ln` for the score), all three
are covered by property tests rather than smoke tests, and none adds a
dependency.

`engine.affinityBandPct` (default 10) and `engine.affinityBandMs` (default 2)
tune the band; setting **both** to `0` collapses it to the cheapest candidate and
disables the lottery. `stats.affinityLotteries` reports how often it actually
ran — a zero rate on a multi-server delegation means the band admitted only one
candidate, which is a policy reading and not a fault.

`engine.decorrelateRefresh` (default `true`) is the other half of the same idea:
turning it off restores name order for a deployment that cannot hold a secret,
and `stats.refreshUndecorrelated` counts the maintenance rounds that ran that
way. Both switches exist so that their statistic means something — a counter that
no configuration can move is unreachable code with extra steps.

## See also

* [Risk-constrained refresh](Refresh-Theory.md) — the hazard model and the risk
  functional the fingerprint is derived from.
* [Cache admission and the change-rate model](Cache-Admission.md) — where the
  behavioural identity is computed and why `CacheScore` is not a safety gate.
* [Upstream selection cost model](Upstream-Selection.md) — the cost model the
  affinity band is layered on top of.
* [The paper](../../paper/RecurseX-risk-constrained-refresh.md) — the same
  argument in reviewable form.
