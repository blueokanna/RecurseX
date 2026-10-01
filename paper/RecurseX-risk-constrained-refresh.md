# Risk-Constrained, Dependency-Consistent Cache Refresh for Recursive DNS Resolvers

**Authors.** *RecurseX contributors (blueokanna, HyphenTeam).*

**Target venue.** IEEE/ACM *Transactions on Networking*; suitable also for
*Computer Networks* or IEEE *ICNP*.

---

## Abstract

Recursive resolvers must decide, for every expired cache entry, whether to
resolve again or to answer from the copy they already hold. The decision has
been governed by two heuristics: serve stale when demand is expected, and
refresh when the remaining TTL falls below a fraction of the original. Both
conflate two quantities — the *benefit* of an answer and its *safety* — and
neither is falsifiable. We reformulate the problem as a partially observable,
risk-constrained refresh scheduling problem and present a mechanism with four
parts. (i) A **hazard model** infers a Gamma posterior over the RRset change
rate from irregular, censored observation intervals, and every decision uses a
one-sided **credibility bound** on that rate rather than a point estimate; the
non-stationarity forgetting factor that makes the estimator track regime
change also imposes a hard ceiling on accumulated evidence, which bounds how
much confidence an attacker in a cache-poisoning position can manufacture.
(ii) A **risk functional** separates the value of a hit (expected saved
latency) from the ex-ante harm of serving it, with declared consequence
coefficients by record role and a trust penalty from an explicit DNSSEC
verification ladder; stale service is admitted only while an aggregate **risk
budget** covers it. (iii) An answer's safety bound is the **weakest link of
its dependency set**, from which we prove that only a bottleneck refresh can
raise it, and derive the refresh schedule accordingly. (iv) A **per-resolution
work envelope** bounds delegation depth, NS fan-out, NS-address lookups,
sub-queries and wire bytes, closing the amplification channel exploited by
NXNSAttack. We give the model, the bounds and their proofs; state the
methodology by which the mechanism is to be falsified (proper scoring rules
and a reliability table ship with the implementation); and report an
adversarial-work bound that holds by construction. No empirical results are
claimed: the paper specifies the protocol, and the harness that produces the
numbers is part of the released artifact.

**Index Terms.** DNS, recursive resolution, caching, serve-stale, refresh
scheduling, Bayesian inference, credible intervals, calibration, risk
budgets, availability.

---

## I. Introduction

A recursive DNS resolver is a cache with an obligation. When a cached RRset
expires it may either resolve again — paying a walk over the delegation tree,
with its latency, its failure probability and its bandwidth — or answer from
the expired copy. The latter is standardised practice (serve-stale,
RFC 8767 [7]) and is a measurable availability win during upstream
degradation.

The decision is usually taken by heuristics with two properties in common.
First, they answer the wrong question: the dominant heuristic is *"is this
name likely to be queried soon?"*, which is a statement about the **benefit**
of answering and is silent about whether the answer is still **true**.
Second, they are unfalsifiable: a threshold on a hand-tuned unitless score
cannot be checked against outcomes, so an operator cannot tell a
well-calibrated model from a badly tuned one.

The consequence is a specific and unpleasant failure mode. Applying
popularity as the gate makes the busiest zone in a deployment the most likely
to be answered from a copy that a decommissioned nameserver or a revoked key
has invalidated — that is, the error correlates with traffic, which is the
shape of an outage rather than of a slow query.

### A. What this paper does *not* claim

We state this before the contributions, because the literature is easily
mis-summarised. Serve-stale is not ours [7]. Prefetching near expiry is not
ours, and neither is the observation that a resolver's sampling behaviour
influences what it can infer; Unbound's long-standing rule ("refresh when the
remaining TTL is below 10 % of the original") is a prefetch policy, and TTL
proportionality is a *proxy* for change rate. Measuring RRset change
behaviour is not ours either. Bounded caches and bounded
coalescing are standard engineering practice. We do not claim "the first
predictive caching resolver".

What we claim is a **specific formulation and mechanism**: that the refresh
problem is a risk-constrained scheduling problem under partial observability
and dependence, that its decision variable must be a *credibility bound* and
not a point estimate, that the safety bound of an answer is a minimum over a
dependency set (which changes the scheduler), and that the whole thing can be
made falsifiable at the cost of shipping a calibration surface. We also give
a structural, rather than procedural, argument against a forgery attack on the
estimator.

### B. Contributions

1. **An observable-change hazard model** over irregular, right-censored
   observations (§IV). The estimator is a Gamma posterior whose sufficient
   statistics cost a constant amount of state per entry, whose sampling
   cadence is measured rather than assumed, and whose evidence is
   exponentially forgotten. We show that forgetting is simultaneously the
   non-stationarity mechanism and the ceiling on forged evidence
   (Lemma 2), and we give the exact Chernoff bound on the posterior that the
   decision layer consumes (Theorem 1).
2. **A risk functional and budget for stale service** (§V), which separates
   value from safety, prices consequences by record role, penalises
   unauthenticated answers through an explicit verification ladder, and
   admits a stale answer only while an aggregate budget covers its
   ex-ante risk. The budget is a leaky bucket whose invariant bounds the
   admitted risk over any window *by construction* (Theorem 2).
3. **Dependency-consistent refresh** (§VI). An answer's conservative safety
   bound is the minimum of its dependencies' bounds (Theorem 3); we prove
   that only a bottleneck refresh can raise it (Theorem 4) and give a
   trimming construction that preserves the bound exactly (Lemma 5). This
   yields a scheduler whose budget is spent where it changes the guarantee.
4. **A per-resolution work envelope** (§VII) that bounds counted work rather
   than depth, together with a referral-admission gate for the NXNSAttack
   shape; the amplification factor becomes a bounded quantity rather than a
   property of the attacker's zone.
5. **Falsifiability as a shipped feature** (§IX): Brier score, log loss and a
   reliability table are part of the implementation, with the caveats the
   sampling structure requires. We describe the protocol by which the
   mechanism is to be rejected.

---

## II. Background and Related Work

### A. Negative caching and serve-stale

RFC 2308 [2] established that negative answers are cached with a TTL derived
from the SOA MINTTL. RFC 8767 [7] standardised serving stale data after
expiry when resolution fails, and made three requirements that constrain any
policy built on it: the TTL reported with a stale answer should be short
(30 s is suggested, and must not be zero), use of stale data should be
observable, and an operator must be able to bound how stale an answer may be.
Our design keeps all three: the reported TTL of a stale answer is a configured
`stale_serve_ttl` (default 30 s) *and* is clamped to be at least 1 s; staleness
is bounded twice, once statistically by `P_LCB` and once by a per-class policy
horizon (§V-C); and stale service is counted, along with the reason it was
refused.

### B. Caching behaviour and TTLs

Jung *et al.* [16] measured that DNS cache behaviour is dominated by a small
set of names and that TTL values are frequently inconsistent with observed
change behaviour. That gap is the premise of this work: a TTL is a *claim* by
the authority, and the quantity a refresh policy needs is the rate at which
the data actually changes. Where earlier work used the gap to *describe*
caching, we use it to *schedule* refresh, and we are explicit that the TTL
remains the only value ever served to a client (TTL is never rewritten; the
cached expiry is authoritative-value-minus-age).

### C. Prefetch and refresh scheduling

Unbound's controller prefetches entries whose remaining TTL is below a
fraction of the original. The rule is cheap and stateless, and it fails in
both directions: a 300 s TTL on an hourly-rotating record is prefetched far
too rarely, and an 86 400 s TTL on a per-second rotating record is
prefetched far too late. Our scheduler replaces the fraction with the model's
own validity horizon (§IV-D). Conceptually the resulting object is an
age-based scheduling policy for a partially observable, non-stationary
system, in which the observation cost is the upstream query and the state is
a posterior over the change rate.

### D. Spoofing resistance and amplification

RFC 5452 [4] requires query IDs and (recommended) QNAME case to be
unpredictable to an off-path attacker, and notes that unpredictability must
survive observation of a prefix of the generator's output. A 64-bit
arithmetic generator does not satisfy this once one output is observed; a
keyed stream does. We use ChaCha20 [6] in counter mode with periodically
rekeyed material (§VIII-B), and we keep a non-cryptographic generator only
for capacity sampling.

Shafir *et al.* [10] showed that a referral may carry unbounded many NS
records whose addresses are not glued, obliging the resolver to perform an
independent address resolution per name, with amplification factors above
10³. A depth limit does not bound this: each level is cheap to enter. Our
answer (§VII) is a counted work envelope plus a referral admission gate that
refuses a delegation the resolver could not use.

### E. Calibration

Brier [11] and Gneiting & Raftery [12] establish that proper scoring rules
are the appropriate way to evaluate probabilistic forecasts and that they
cannot be improved by becoming more confident. We ship Brier score, log loss
and a reliability table (§IX); the reliability table, not the aggregate, is
the object of interest, since an aggregate can hide a model that is right on
average and wrong where it matters.

---

## III. System Model and Problem Formulation

### A. Notation

Let $\mathcal{K}$ be the set of cached keys $(q, t, c, s)$ of query name,
type, class and ECS scope. For $k \in \mathcal{K}$ let $T_k$ be the
authoritative TTL observed for it, $e_k$ its insertion instant, and
$d_k(t) = \max(0, t - (e_k + T_k))$ the staleness of the data at time $t$;
$d_k = 0$ means fresh and is served unconditionally, exactly as RFC 1035 [1]
and RFC 8767 [7] require.

For each $k$ the resolver may observe the outcome of a refresh at times
$t_1 < t_2 < \cdots$; the $j$-th observation has exposure
$h_j = t_j - t_{j-1}$ and outcome
$Y_j \in \{0, 1\}$ indicating whether the RRset content differed from the
snapshot. Content equality is decided on the canonical RRset form with TTLs
excluded, since a TTL-only change is not a data change.

An answer $A$ is assembled from a dependency set $D(A)$ of cached entries
(§VI-A). We write $p_v(\Delta)$ for the conservative probability that
dependency $v$ is still correct $\Delta$ seconds from now.

### B. The decision problem

At an expired lookup for $k$ at time $t$ the resolver chooses
$\pi \in \{\textsc{resolve}, \textsc{stale}\}$. The objectives are:

$$
\max_{\pi}\;
\mathbb{E}\bigl[\textsc{LatencySaved} + \textsc{AvailabilityGain}\bigr]
\tag{1}
$$

subject to

$$
\mathbb{E}\Bigl[\sum_{i} R_i(a_i)\Bigr] \le B_{\text{risk}},
\qquad
\sum_i \rho_i \le B_{\text{refresh}}
\tag{2}
$$

where $R_i$ is the ex-ante harm of a stale answer (§V), $a_i$ its staleness,
$\rho_i$ the refresh rate of entry $i$, and $B_\bullet$ operator-chosen
budgets. The two constraints bind on different resources — the first on what
the client may be told, the second on what the upstream may be asked — and a
design that merges them cannot express a deployment with a slow upstream or a
hostile client population.

Two features make (1)–(2) non-trivial. The state is **partially observable**:
$Y = 0$ means no *visible* difference was found, and a change that came and
went between two samples is invisible. The constraints are **dependent**:
the events "this CNAME is current" and "its target is current" are not
independent, because one authoritative republish changes both.

---

## IV. The Observable-Change Hazard Model

### A. Likelihood

Assume changes to an RRset are a Poisson process of unknown rate
$\lambda > 0$. Then

$$
\Pr(Y_j = 1 \mid \lambda, h_j) = 1 - e^{-\lambda h_j},
\qquad
\Pr(Y_j = 0 \mid \lambda, h_j) = e^{-\lambda h_j}
\tag{3}
$$

and

$$
\mathcal{L}(\lambda) = \prod_j
\bigl(1 - e^{-\lambda h_j}\bigr)^{Y_j}
\bigl(e^{-\lambda h_j}\bigr)^{1 - Y_j}.
\tag{4}
$$

Two modelling commitments are visible in (3)–(4) and both are load-bearing.
The likelihood conditions on $h_j$ **per observation**: the sampling cadence
is an input, not an assumption, so two resolvers with different cadences draw
different inferences from the same zone rather than producing the same
unitless score. And $Y_j = 0$ contributes a factor
$e^{-\lambda h_j} < 1$ rather than certifying stability: the model never
represents "nothing happened", only "nothing was seen".

### B. Posterior and the forgetting update

The conjugate prior for a rate is
$\lambda \sim \Gamma(\alpha_0, \beta_0)$. In the operating regime
$\lambda h \ll 1$ inherited from the resolver's own cadence we have
$1 - e^{-\lambda h} = \lambda h + O(\lambda^2 h^2)$, so to first order the
information about $\lambda$ in an observation is $h$ units of exposure for
$Y = 1$ and *none* for $Y = 0$. The corresponding update,

$$
\alpha \leftarrow \alpha + Y, \qquad \beta \leftarrow \beta + h,
\tag{5}
$$

is first-order-correct in that regime and *exact* in the opposite one: a set
whose observations are predominantly $Y = 1$ is one whose $\lambda h$ is not
small, and there (3) is dominated by the $1 - e^{-\lambda h}$ factor that (5)
represents exactly. We state the approximation rather than hiding it; the
bias is toward *more* confidence, which is why the decision layer consumes the
upper bound of §C rather than the posterior mean.

The prior is anchored to the authority's own claim: $\alpha_0 = 1$ and
$\beta_0 = \alpha_0 T$, i.e. prior mean $1/T$ — "one change per TTL". This
uses the TTL in the only role it is entitled to (a claim), keeps the prior
weak enough that a handful of observations dominates it, and — because
$\alpha_0 > 0$ is a permanent floor — keeps the credible interval open for
every entry.

Because DNS data is not stationary, the *evidence* is forgotten with time
constant $\tau$:

$$
\gamma = e^{-h/\tau}, \qquad
a \leftarrow \gamma a + w Y, \qquad
b \leftarrow \gamma b + w h,
\tag{6}
$$

with $\alpha = \alpha_0 + a$, $\beta = \alpha_0 T' + b$ (where $T'$ is the
TTL EWMA, so a zone that raises its TTL is believed to have become more
durable) and observation weight $w \in (0, 1]$.

**Lemma 1 (bounded state).** *For any observation sequence, $a$ and $b$ are
$O(1)$: with fixed cadence $h$, $b \to wh/(1-\gamma)$ and
$a \to w/(1-\gamma)$. The estimator therefore costs a constant number of
scalars per entry, independent of how often the entry is refreshed.*

*Proof.* Both are geometric series with ratio $\gamma \in (0,1)$; the sums
converge to the stated limits. $\square$

**Lemma 2 (evidence ceiling — the anti-forgery property).** *For any
sequence of observations with weights $w_j \le 1$, the effective exposure
satisfies $b < \tau$ in the limit, and consequently
$\lambda_{\mathrm{hi}} \ge \alpha_0/(\alpha_0 T' + \tau) > 0$ and
$P^{\mathrm{LCB}}(\text{fresh}, \Delta) < 1$ for every finite $\Delta$.*

*Proof.* With cadence $h$, (6) gives
$b_j = wh \sum_{i<j}\gamma^{\,i} < wh/(1-\gamma) \to w\tau$ as $h \to 0$;
for finite $h$ the same bound holds because
$h/(1-e^{-h/\tau}) \le \tau$. Hence $b$ is bounded above by $\tau$
independently of the number of observations, and $\beta \le \alpha_0 T' + \tau$
while $\alpha \ge \alpha_0$. The Chernoff bound of §C is therefore finite at
every $x$, and $P^{\mathrm{LCB}} = e^{-\lambda_{\mathrm{hi}}\Delta} < 1$.
$\square$

Lemma 2 is the answer to a question the heuristic models cannot answer at
all: *what happens if the observations are forged?* An adversary positioned to
answer the resolver's refreshes can drive the observations toward $Y = 0$,
but the point estimate is not what the decision uses, and the ceiling is
structural. The weight $w$ — set from the verification ladder of §V-C — scales
the ceiling as well as the rate, so an unauthenticated channel cannot reach
the same confidence no matter how long it is observed.

### C. The credibility bound

The decision layer requires a one-sided upper bound on $\lambda$ at level
$1-\delta$, and evaluates survival at that worst case:

$$
P^{\mathrm{LCB}}(\text{fresh}, \Delta)
= \inf_{\lambda \in \mathrm{CI}_{1-\delta}} e^{-\lambda \Delta}
= e^{-\lambda_{\mathrm{hi}}\Delta}.
\tag{7}
$$

**Theorem 1 (validity and conservatism of $\lambda_{\mathrm{hi}}$).** *Let
$\Lambda \sim \Gamma(\alpha, \beta)$ with $\alpha, \beta > 0$ and
$0 < \delta < 1$. Define $g(x) = \alpha - \beta x + \alpha \ln(\beta x /
\alpha) - \ln \delta$ on $x > \alpha/\beta$. Then $g$ is continuous and
strictly decreasing with $\lim_{x \downarrow \alpha/\beta} g(x) =
\ln(1/\delta) > 0$ and $\lim_{x\to\infty} g(x) = -\infty$; its unique root
$\lambda_{\mathrm{hi}}$ satisfies $\Pr(\Lambda \ge
\lambda_{\mathrm{hi}}) \le \delta$ and $\lambda_{\mathrm{hi}} \ge
\mathbb{E}[\Lambda] = \alpha/\beta$.*

*Proof.* For $t \in (0, \beta)$ the moment generating function is
$M(t) = (1 - t/\beta)^{-\alpha}$. Chernoff's inequality gives
$\Pr(\Lambda \ge x) \le \inf_{t} e^{-tx} M(t)$. Substituting $u = t/\beta$,
the bound is $f(u) = e^{-u\beta x}(1-u)^{-\alpha}$; $f'(u) = 0$ gives
$1 - u = \alpha/(\beta x)$, which requires $x > \alpha/\beta$, and
back-substitution yields
$f^\* = e^{\alpha - \beta x}(\beta x/\alpha)^\alpha$. Then
$g(x) = \ln f^\* - \ln \delta$ and $g'(x) = -\beta + \alpha/x < 0$ exactly
on the stated domain, with $g(\alpha/\beta) = \ln(1/\delta)$. The bound is
therefore $\le \delta$ at the root; and since the bound at
$x = \alpha/\beta$ equals 1 and is decreasing, the root exceeds
$\alpha/\beta$. $\square$

Theorem 1 holds for every $\alpha > 0$, which matters: the regime
$\alpha < 1$ is precisely the low-evidence regime where a normal
approximation is invalid, and there the bound is *wide by construction* rather
than narrow by accident. As $\alpha, \beta \to 0$ the root diverges, so no
information means $P^{\mathrm{LCB}} = 0$ and no stale authorisation — the
requirement that small samples be conservative is discharged by the
mathematics rather than by a threshold. The root is found by bisection on
$g$, a fixed 96 iterations, so the per-decision cost is constant.

For reporting and for calibration we also evaluate the exact
posterior-predictive

$$
P^{\mathrm{pred}}(\text{fresh}, \Delta)
= \Bigl(\frac{\beta}{\beta + \Delta}\Bigr)^{\alpha},
\tag{8}
$$

which is never used to decide anything. The gap between (7) and (8) is the
price of the guarantee.

### D. Adaptive observation scheduling

The next observation is scheduled from the model:

$$
h^\* = \operatorname{clamp}\Bigl(-\frac{\ln p^\*}
{\lambda_{\mathrm{hi}}},\; h_{\min},\; h_{\max}\Bigr),
\tag{9}
$$

i.e. sample again while the conservative probability of still being correct
is at least $p^\*$. A well-observed set is sampled near its natural expiry; a
volatile one early and often. Note that a short TTL buys a short interval only
through the prior $\beta_0 = \alpha_0 T$, and that after evidence accumulates
the prior's influence vanishes — the cadence is governed by evidence, not by
the authority's claim.

---

## V. Risk-Constrained Stale Service

### A. Value

For entry $k$ let $V_k$ be the expected latency a cache hit saves, taken from
the per-zone upstream cost model and floored at $\underline{V}$ so that an
entry with no history does not appear free. $V$ governs *what is worth
refreshing*, *what is worth keeping*, and the *order* in which the refresh
budget is spent. It is provably not an input to the stale decision: in the
implementation the stale path never reads the estimator, and a test exists
solely to force a future change that reintroduces the dependency to delete
that test deliberately.

### B. The risk functional

$$
R_k(a) = V_k \cdot \bigl(1 - P^{\mathrm{LCB}}_k(\text{fresh}, a)\bigr)
\cdot C_k \cdot \kappa(\theta_k)
\tag{10}
$$

with $a$ the staleness at which the answer would be served, $C_k$ a
consequence coefficient, and $\kappa$ a trust penalty. $R$ inherits the units
of $V$ (milliseconds of saved latency), which is what makes (2) meaningful:
$B_{\text{risk}}$ is "how much saved latency the resolver may spend per second
on expected harm".

### C. Consequence coefficients and the verification ladder

$C_k$ is chosen from the role the record plays, not only its type. Table I
gives the shipped default. The same A record is `Low` as answer data and
`Critical` as glue, because stale glue poisons the walk for every later query
beneath that zone, and a stale delegation is self-reinforcing because the bad
delegation is itself cached.

**TABLE I. Consequence classes**

| Class | Records | $C$ | Stale horizon |
|---|---|---|---|
| Low | A, AAAA, TXT, PTR, … | 1 | 24 h |
| Medium | CNAME, DNAME | 5 | 1 h |
| High | MX, SRV, TLSA, CAA, SVCB, HTTPS | 25 | 5 min |
| Critical | NS, glue, delegation data | 100 | 30 s |
| Absolute | DNSKEY, DS, RRSIG, NSEC, NSEC3 | $\infty$ | none |

`Absolute` is not a large number: it is infinity, and the corresponding
entries are excluded from stale service unconditionally. A stale proof of
existence is not a freshness failure but a *security* failure — it can
resurrect a revoked key.

$\kappa$ comes from an explicit verification ladder with four states —
`ChainAnchored`, `CryptoVerified`, `Unverified`, `Indeterminate` — with
$\kappa \in \{1, 2, 5, 10\}$. The ladder is deliberately finer than a boolean
because "we could not verify this" must not be the same as "we verified this
and it was fine", and because a zone known to be unsigned is a different risk
from one whose status is unknown. The `AD` bit is set **only** for
`ChainAnchored`, i.e. only when the chain reached an operator-installed
anchor and the Answer *and* Authority RRsets are both authentic
(RFC 4035 §3.2.3 [3]); a merely signature-verified answer is used internally
but never advertised, since RFC 4035 does not permit it and it would overstate
what was checked.

### D. The aggregate budget

**Theorem 2 (budget invariant).** *Let the ledger hold debt $D$, drain at
rate $r$, and have capacity $B$. Admit a decision of risk $R$ iff
$D + R \le B$ after draining, then set $D \leftarrow D + R$. Then for every
window $[t_0, t_1]$ the sum of admitted risks satisfies*

$$
\sum_{i:\, t_i \in [t_0, t_1]} R_i \;\le\; B + r\,(t_1 - t_0).
\tag{11}
$$

*Proof.* Let $D_0$ be the debt at $t_0$. Draining is a non-increasing
function and admission requires $D \le B$ after the charge, so
$D(t) \le B$ for all $t$; and $D$ is exactly the admitted risk in the window
minus the drained amount, which is at most $r(t_1-t_0)$ over the window.
Hence the admitted sum is at most $D(t_1) + r(t_1-t_0) \le B + r(t_1-t_0)$.
$\square$

Two implementation details matter for the guarantee to be real rather than
nominal. The ledger is charged with the *conservative* bound (10) at decision
time, so the true harm is below the reported spend and the reported spend is
auditable from the log alone. And the refresh budget is charged at the single
point where a refresh is actually spawned, so every caller — maintenance
prefetch, serve-stale refresh, dependency propagation — funnels through it and
$\sum \rho_i \le B_{\text{refresh}}$ holds by construction rather than on
average. Denial counts are exported for both, because "the policy is the
constraint" and "the network is the constraint" have opposite remedies.

---

## VI. Dependency-Consistent Refresh

### A. The dependency set

A resolver does not serve one RRset. For `www.example.com` the answer may
comprise a CNAME, the target's A RRset, the delegation that made the target
resolvable, the address of the nameserver that answered, and the DNSSEC proof
binding them. Let

$$
D(A) = \{\textsc{Answer}, \textsc{Cname}, \textsc{Dname},
\textsc{Delegation}, \textsc{NsAddress}, \textsc{DnssecProof}\}
\tag{12}
$$

be the set of dependencies of a final answer $A$, each carrying its own
freshness bound $p_v$.

**Theorem 3 (weakest-link bound).** *Without an assumption of independence,
the probability that $A$ is serviceable satisfies
$P(A) \le \min_{v \in D(A)} p_v$.*

*Proof.* $A$ is serviceable implies every $v \in D(A)$ is fresh, so
$\{A\} \subseteq \bigcap_v \{v\}$ and
$P(A) \le P(\bigcap_v \{v\}) \le \min_v P(v)$ by monotonicity of probability.
$\square$

Theorem 3 needs no independence, and the independence assumption is usually
false: one authoritative republish changes a CNAME and its target in the same
instant. The product $\prod_v p_v$ is available in the implementation as
`independent_bound()`, as a diagnostic only, and the gap between the two is
reported rather than hidden.

### B. Bottleneck dominance

**Theorem 4 (only the bottleneck moves the bound).** *Let
$\beta = \min_v p_v$ and let $v^\*$ attain it. Refreshing
$v \ne v^\*$ to freshness 1 leaves the bound at $\beta$; refreshing
$v^\*$ to freshness 1 raises it to $\min_{v \ne v^\*} p_v$.*

*Proof.* The bound is a minimum over the set; replacing any non-minimiser by 1
leaves the minimum unchanged, since $v^\*$ is still present. Replacing the
minimiser by 1 makes the minimum the second-smallest value. $\square$

Theorem 4 is what changes the scheduler. A predictor that refreshes each
expiring member of a chain independently — including the CNAME-reverse
trigger of the alias graph — spends its whole budget and improves the
weakest-link bound by exactly zero whenever the same member remains weakest.
The implementation therefore returns a plan ordered by ascending $p_v$ and
exposes `risk_reduction` per member, so a caller stops when the marginal
refresh stops mattering.

### C. Trimming without weakening

**Lemma 5 (bound-preserving trim).** *Retain the $\kappa$ smallest $p_v$ and
let $r = \min\{p_v : v \text{ discarded}\}$. Then
$\min(\{p_v\}_{\text{retained}} \cup \{r\}) = \min_v p_v$.*

*Proof.* The discarded set is non-empty when trimming occurs, so $r$ is
defined and equals the minimum over the discarded members; the union of the
retained members with the discarded minimum therefore has the same minimum as
the whole set. $\square$

Lemma 5 exists because the obvious implementation is unsafe. `bound()` is a
minimum, so *discarding* a member can only raise it, and a raised safety bound
is an optimistic error — the one class of error a safety bound must not make.
Keeping the weakest members and carrying the discarded minimum as a residual
floor makes trimming cost memory rather than soundness.

### D. Relation to the alias reverse index

The implementation keeps two structures rather than deriving one from the
other. An **alias graph** is a global reverse index: given an entry that
changed, which cached answers become invalid (needed for invalidation). A
**provenance set** is a per-answer forward set: given an answer, what must be
true for it to be serviceable (needed for the decision). Neither is cheaply
derivable from the other, and conflating them yields the CNAME-reverse trigger
whose zero-gain behaviour Theorem 4 predicts.

---

## VII. Bounded Work per Resolution

### A. Why depth is not enough

A depth limit bounds one dimension and leaves the expensive one open. The
NXNSAttack [10] exploits exactly that: a referral may name many NS records
with no glue, and each obliges an independent address resolution. Each level
is cheap to *enter* and expensive to *finish*, so the cost is in the fan-out,
not the depth. The correct countermeasure is a budget on counted work.

### B. The envelope

For every client query and every sub-resolution it spawns we bound:
delegation depth $D$; NS names per referral $N$; glue addresses per referral
$G$; NS-address lookups per resolution $L$; upstream messages per resolution
$Q$; and wire bytes per resolution $Y$. The shipped defaults are
$D{=}32, N{=}13, G{=}64, L{=}32, Q{=}96, Y{=}2^{20}$. Compliance is by
*charging*: each counter is incremented at the site where the work happens,
and exhaustion returns a typed error naming the counter, so a budget failure
is distinguishable from a network failure in the logs.

### C. Referral admission

A referral with $n$ NS names of which $g$ are glued leaves $n - g$ names to
resolve. The gate accepts a referral only if $n \le N$ and, when
$n > n_{\text{small}}$, the glued fraction is at least $\phi$; otherwise it is
refused outright and the resolution fails rather than chasing. The
$n_{\text{small}}$ escape hatch exists because a two-server delegation with
no glue is ordinary DNS and rejecting it would break real zones.

**Proposition 6 (amplification is bounded).** *With the envelope of §VII-B,
the number of upstream messages generated by one client query is at most
$Q$, and the NS-address lookups at most $L$, independently of the content of
any zone the attacker controls.*

*Proof.* Every upstream message passes through the sub-query charge and every
address lookup through the address-lookup charge; both are monotone counters
compared against fixed limits. $\square$

Proposition 6 is deliberately weak — it is a construction rather than an
asymptotic bound — and that is the point: the mechanism does not need the
attacker's zone to be well-behaved, only for our own counters to be
authoritative.

---

## VIII. Implementation

### A. Structure

The crate is `no_std` at its core and `std` at the networking layer. The
refresh model, the risk model, the work envelope, the calibration surface and
the provenance set are all allocation-free or bounded-allocating and carry no
dependency on a clock: all time enters as an explicit timestamp, which is what
makes every temporal property testable deterministically. The wire codec
performs no unchecked indexing; the crate denies `unsafe_code` and warns on
`clippy::indexing_slicing` outside tests, because a panic while parsing
network input is a remote denial of service.

### B. Randomness

Query IDs and 0x20 QNAME case [4] are drawn from a ChaCha20 [6]
counter-mode stream whose key is rekeyed from OS entropy after a bounded
volume of keystream. The generator is verified against the RFC 8439 test
vector, so the security argument rests on a published construction. A
non-cryptographic generator is retained only for cache-capacity sampling and
test fixtures. The distinction is enforced by type and by an explicit
`RandomSource` trait, so which generator a call site receives is visible
where the argument is passed.

### C. Floating point

`core` provides neither `exp` nor `ln` on the MSRV, and both are needed by
Theorem 1's solve. Approximating either would silently convert a provably
conservative bound into an unprovable one, so both are implemented
from scratch with a two-part `ln 2` reduction for `exp`. Accuracy is asserted
against C-library reference values that are generated by the test harness
rather than transcribed; the measured worst case is $3.5\times10^{-15}$
relative for $|x| \le 100$ and $2.4\times10^{-14}$ at $x = -700$, where the
result sits just above underflow.

### D. ECS partitions

An ECS answer is filed under the **scope** the answering server declared, not
under the prefix the requester asked with, and a requester may read a
partition only if its own network is contained in it:

| stored under | readable by |
|---|---|
| the global partition (no ECS) | any requester |
| an ECS scope of $S$ bits | requesters with prefix $P \ge S$ whose address matches the first $S$ bits |

Two claims are load-bearing and both are enforced in the key rather than in a
runtime check. A requester that sent no ECS carries no partition at all, so it
*structurally* cannot read a scoped entry — the failure mode of storing an ECS
answer globally is not a policy error to be remembered but a state the key
type cannot express. And the effective scope is
$\min(\text{SCOPE}, \text{SOURCE PREFIX-LENGTH})$ per §7.3.1, because an
answer was only ever computed for the network that was asked about; letting a
server widen it would claim validity the resolver has no evidence for.

One consequence is worth stating because it is a *repair* rather than a
restriction: a response whose scope is 0, or a response that arrived with no
ECS option at all to a query that carried one (§7.2.2), is valid for every
client and is therefore filed in the global partition. Subnet-scoped caching
fragments the cache; a scope-0 answer heals the fragment.

### E. Verification states

DNSSEC validation reports `ChainAnchored`, `CryptoVerified`,
`NegativeProofVerified`/`Insecure`, or `Indeterminate`, together with the
number of answer groups examined and authenticated and whether the Authority
section authenticated. This build ships no root trust anchor, so
`ChainAnchored` is unreachable unless an operator installs one — and the
implementation refuses to claim it otherwise. Algorithm support is explicit:
RSASHA256 is verified; SHA-1-based algorithms are refused as deprecated;
ECDSA and EdDSA are recognised but unverified, and yield `Indeterminate`
rather than a fabricated verdict in either direction.

---

## IX. Evaluation Protocol

This section specifies how the mechanism is to be **rejected**. We report no
empirical results, because none have been measured; a paper that invents them
is worse than one that states the protocol.

### A. Calibration

For every prediction $p$ the resolver acts on, record $(p, y)$ where $y = 1$
if the answer turned out to still be correct. Report Brier score
$\frac{1}{n}\sum (p_i - y_i)^2$, log loss
$-\frac{1}{n}\sum [y_i \ln p_i + (1-y_i)\ln(1-p_i)]$, and the reliability
table with bin means against observed frequencies, plus the expected
calibration error and the signed bias. Both scoring rules are strictly proper
[11], [12], so a model cannot improve its score by becoming more confident.
The failure to test for is *over*-confidence (negative bias), because that is
the direction which makes a freshness threshold unsafe.

Three caveats belong in the report. The sample is not i.i.d. — it is a
sequence of decisions taken by the policy being evaluated, on data whose
distribution moves. Predictions and outcomes for the same entry are
correlated. And the LCB is deliberately not the predictive mean, so the
reliability table for $P^{\mathrm{LCB}}$ should sit *above* the diagonal;
the quantity to calibrate against reality is (8).

### B. Model misspecification

Fit the posterior under the Poisson model and compare against a
non-parametric alternative (empirical hazard by exposure bucket) on a held-out
trace. Report the log-loss difference. The protocol should be able to exhibit
the regime where (5) breaks down — high change rate, long sampling interval —
and to show that the failure is toward over-confidence rather than
over-conservatism, as §IV-B predicts.

### C. Risk-constrained behaviour

Sweeping $B_{\text{risk}}$ should produce a monotone trade-off in the
measured (admitted-risk, upstream-query) plane, and per-class curves should
be ordered by $C$. The claim to falsify is the one Theorem 4 predicts: a
scheduler that ignores the bottleneck should show *no* improvement in the
weakest-link bound as its refresh budget increases, while a bottleneck-first
scheduler should show improvement until the bound is limited by the residual
floor of Lemma 5.

### D. Adversarial work

Against a synthetic zone that publishes $n$ unglued NS records with
$n$ chosen by the experiment, measure sub-queries, bytes and NS-address
lookups per client query. Proposition 6 predicts a hard cap independent of
$n$. Additionally measure the per-resolution amplification factor
$L / \text{referrals}$ and report its distribution, which is the quantity
[10] uses.

### E. Analytic predictions reported here

The following are derived from (7) at $\delta = 0.05$, $\tau = 1$ day,
$T = 300$ s, and are not measurements (Table II). They are stated so that the
experiments above have something to falsify.

**TABLE II. Derived confidence, prior and observed**

| Evidence | $\lambda_{\mathrm{hi}}$ (s⁻¹) | $P^{\mathrm{LCB}}$ over 60 s |
|---|---|---|
| none (prior only) | $1.9\times10^{-2}$ | 0.32 |
| 1 h watched, unchanged | $1.3\times10^{-3}$ | 0.93 |
| 1 day watched, unchanged | $6.6\times10^{-5}$ | 0.996 |

The third row is the interesting one: a day of perfect stability is worth
about 0.996 over a minute and never 1. By Lemma 2 no sequence of observations
can produce 1.

---

## X. Limitations and Threats to Validity

**The Poisson assumption.** Changes are assumed memoryless. Real zones have
diurnal and event-driven structure, and a change that has just happened may
make another more likely (a coordinated republish) or less (a completed
migration). The model is asserted, not validated; §IX-B is how it would be
rejected.

**The first-order update.** Equation (5) is not the exact conjugate update
for (4). The bias is toward confidence, bounded by the forgetting ceiling, and
its regime of validity is stated — but a deployment with a very long sampling
interval relative to the change rate is outside it.

**Coefficient selection.** The values in Table I and the trust penalties are
declared operating points, not estimates. The ordering is the load-bearing
part; the scale is absorbed by $B_{\text{risk}}$ on first deployment. We do
not claim the numbers transfer.

**Dependence.** Theorem 3's bound is sound but may be loose, since
dependencies are negatively correlated in some measurements (a single
republish changes several records at once, which makes the bound conservative)
and positively correlated in others. Tightening it without an independence
assumption is open.

**ECS partitioning.** RFC 7871 [5] scope selection is implemented as a
longest-prefix walk over the *scope* the answering server declared, and an
answer is filed under the matching partition rather than under the prefix the
client asked with (§VIII-D). What is *not* implemented is the second half of
the ECS design: the resolver forwards the client's own source prefix rather
than choosing one, so it inherits whatever privacy and fragmentation
properties the client's prefix carries. Choosing a canonical per-deployment
prefix, as §7.1.2 permits, is a configuration feature we have not built.

**Non-DNS cost terms.** Equation (10) prices CPU and memory only through the
value term. A deployment under memory pressure may need an explicit resource
constraint of the form (2); the mechanism admits one but the shipped
configuration does not implement it.

---

## XI. Conclusion

We recast the recursive resolver's refresh decision as a risk-constrained
scheduling problem under partial observability and dependence, and gave a
mechanism with three properties the heuristic it replaces cannot have. Its
uncertainty is a distribution rather than a score, so its decision variable is
a credible bound and small samples are conservative by construction rather
than by threshold. Its safety bound is a minimum over a dependency set, which
we proved changes the scheduler: only a bottleneck refresh can raise the
guarantee, so a budget spent anywhere else is spent for nothing. Its
aggregate risk is bounded by construction and auditable from the log. And it
is falsifiable on purpose: proper scoring rules and a reliability table ship
with the implementation, so the claim "this probability means what it says"
is a thing the system can be shown to fail at.

The most useful direction of future work is the one the limitations suggest:
replacing the Poisson assumption with a model that can be fitted and rejected
on real traces, and tightening Theorem 3 with a dependence model rather than
an independence assumption.

---

## References

[1] P. Mockapetris, "Domain names — implementation and specification,"
RFC 1035, Nov. 1987.

[2] M. Andrews, "Negative caching of DNS queries," RFC 2308, Mar. 1998.

[3] R. Arends, R. Austein, M. Larson, D. Massey, and S. Rose, "DNS security
introduction and requirements," RFC 4033; "Resource records for the DNS
security extensions," RFC 4034; "Protocol modifications for the DNS security
extensions," RFC 4035, Mar. 2005.

[4] A. Hubert and R. van Mook, "Measures for making DNS more resilient against
forged answers," RFC 5452, Jan. 2009.

[5] C. Contavalli, W. van der Gaast, D. Lawrence, and W. Kumari, "Client
subnet in DNS queries," RFC 7871, May 2016.

[6] Y. Nir and A. Langley, "ChaCha20 and Poly1305 for IETF protocols,"
RFC 8439, Jun. 2018.

[7] M. Koster, M. Hoffman, and P. Hoffman, "Serving stale data in the domain
name system," RFC 8767, Mar. 2020.

[8] S. Bortzmeyer, R. Dolmans, and P. Hoffman, "DNS query name minimisation to
improve privacy," RFC 9156, Nov. 2021.

[9] K. Shafir, Y. Cohen, D. Hadas, and A. Herzberg, "NXNSAttack: recursive
DNS inefficiencies and vulnerabilities," in *Proc. 29th USENIX Security
Symp.*, 2020, pp. 631–648.

[10] J. Jung, E. Sit, H. Balakrishnan, and R. Morris, "DNS performance and the
effectiveness of caching," *IEEE/ACM Trans. Netw.*, vol. 10, no. 5,
pp. 589–603, Oct. 2002.

[11] G. W. Brier, "Verification of forecasts expressed in terms of
probability," *Monthly Weather Review*, vol. 78, no. 1, pp. 1–3, Jan. 1950.

[12] T. Gneiting and A. E. Raftery, "Strictly proper scoring rules,
prediction, and estimation," *J. Amer. Statist. Assoc.*, vol. 102, no. 477,
pp. 359–378, 2007.

[13] J.-P. Aumasson and D. J. Bernstein, "SipHash: a fast short-input PRF," in
*Progress in Cryptology — INDOCRYPT 2012*, LNCS 7668, pp. 489–508.

[14] S. Vigna, "Further scramblings of Marsaglia's xorshift generators,"
*J. Computational and Applied Mathematics*, vol. 315, pp. 175–181, 2017.

[15] A. Gelman, J. B. Carlin, H. S. Stern, D. B. Dunson, A. Vehtari, and
D. B. Rubin, *Bayesian Data Analysis*, 3rd ed. Boca Raton, FL, USA: CRC
Press, 2013.

[16] NLnet Labs, "Unbound: prefetch and serve-expired configuration,"
Unbound documentation, §`prefetch` and §`serve-expired`.
