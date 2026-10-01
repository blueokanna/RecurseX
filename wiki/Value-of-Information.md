# Value of information — where the refresh budget goes

The refresh path has two halves, and until this module existed only one of them
was built.

[`PrefetchPolicy`](Refresh-Theory.md) answers *whether an entry is due*: it
compares the conservative freshness against a target and admits the entry when
it has fallen short. That is a **threshold**, and a threshold can only say "look
at this too".

The maintenance loop holds a **finite** budget — `RefreshBudget` mints tokens at
a fixed rate — so the question that decides the outcome is not *whether* but
**where the next token buys the most**. The answer used to be "the entry with
the lowest `P_LCB`", and that is a heuristic: measured against the risk
functional the rest of the system is built on, it is blind to three things at
once.

| What a threshold cannot see | Why it matters |
|---|---|
| how much an observation would **teach** | a refresh reports the exposure *since the last observation*. Confirming something we confirmed a minute ago carries almost no evidence; confirming something we confirmed an hour ago carries a great deal. Both have the same `P_LCB` at the moment the scheduler runs. |
| how much the answer is **worth** | `V`, the saved latency. A record nobody waits for is not worth a token however uncertain its model is. |
| how much harm the record's **class** can do | `C·κ`. A stale TXT is a nuisance; a stale delegation redirects a subtree. |

## The objective

An observation is worth the reduction in expected risk it produces, using the
same functional the serve-stale decision uses:

```text
R = V · (1 − p) · C · κ
VoI = R(do nothing)  −  E[ R(after observing) ]
```

Both sides are evaluated at the horizon. With `age` = seconds since the model
last observed the set, and `Δ_h` the horizon:

```text
R(do nothing)      = V · C · κ · (1 − e^(−λ_hi · (age + Δ_h)))
E[R(after)]        = p₀ · R(unchanged) + (1 − p₀) · R(changed)
R(unchanged)       = V · C · κ · (1 − e^(−λ'_hi · Δ_h))
R(changed)         = V · C · κ · (1 − e^(−λ''_hi · Δ_h))
p₀                 = P(no change over `age`) = (β / (β + age))^α
```

`λ_hi` is the credibility bound of [`hazard`](../src/hazard.rs); `λ'_hi` and
`λ''_hi` are the bounds **after** the update the model would apply for each
outcome. `age` is the exposure the refresh will report — which is why an
observation of something just observed is worth exactly zero, and why that is a
property rather than an artefact: it is asserted by
`looking_at_something_we_just_looked_at_buys_nothing`.

### A worked value

Evaluated from the formulas above, with a fresh model (`α = 1`, `β = 300`,
`δ = 0.05`), `V = 50 ms`, `C = 1`, `κ = 1`, `Δ_h = 60 s`, `age = 120 s`:

| Quantity | Value |
|---|---|
| `λ_hi` | 0.01915 s⁻¹ |
| `R(do nothing)` | 48.41 ms |
| `p₀` | 0.7143 |
| `R(unchanged)` | 27.99 ms |
| `R(changed)` | 33.33 ms |
| `E[R(after)]` | 29.52 ms |
| **VoI** | **18.89 ms** |

These are a *formula evaluation*, reproducible from the code with those inputs.
They are not a network measurement, and nothing in this repository claims they
are.

## Why it is computed by replaying the update

The posterior after an observation is obtained by cloning the hazard model and
calling **the same `HazardModel::observe` the real refresh path calls**. Not a
re-derivation of the conjugate update, not an approximation of the credibility
bound.

That choice is the reason the number can be trusted. A value function that
re-implements the dynamics is a second source of truth, and its failure mode is
silent: the ranking would look entirely reasonable while pricing an update the
model never performs. Replaying costs one clone and two bounded bisections per
candidate — nothing next to the network round trip the token is about to buy.

## Two distinctions that must not be blurred

**Prediction may be used here; it may not be used for safety.** `p₀` is the
posterior-*predictive* mean. That is correct in this module, because a value is
an expectation — what we will learn, on average. It would be incorrect in
`risk`, where the quantity is the probability of being wrong and a mean is not a
guarantee. The same split already separates `CacheScore` (ranking) from `risk`
(deciding), and it holds here for the same reason.

**`C = ∞` becomes a large finite number.** The `Absolute` class (`DNSKEY`, `DS`,
`RRSIG`, `NSEC`, `NSEC3`) returns an infinite coefficient because it must never
be traded against latency. A ranking cannot contain an infinity: `∞ − ∞` is
`NaN`, and a `NaN` sorts unpredictably. So the ranking uses `ABSOLUTE_WEIGHT =
1000`. This softens the prohibition by nothing — that lives in `risk::assess`,
which still refuses with `ClassForbidsStale` — the number exists only to put
such an entry at the top of a list.

## The allocation, and its honest size

Each observation costs exactly one token, so the objective is a plain sum and
the allocation that maximises it is the `budget` largest values. The work is in
*computing* the values; the selection itself is a sort, and is not dressed up as
anything more.

## The reservation, and what it costs

A pure value sort starves. A class of entries that is uncertain, valuable and
high-consequence can hold every token of every tick — and the cost of that
starvation is not merely "those entries are refreshed later". An entry that is
never observed has its evidence decay by design (`τ`), so its bound widens, so
it fails the freshness floor more often, so it can no longer be **served stale**
when a lookup does arrive. Starvation is self-reinforcing: the entries the
scheduler skips are the ones that most need the guarantee the scheduler is
supposed to protect.

So before the global fill, each **behaviour class** present is given up to
`reservation_per_class` slots from its own best candidates. The guarantee is
exactly this and no more:

> If the budget is at least `classes · reservation_per_class`, then every class
> with that many candidates contributes at least `reservation_per_class` of
> them.

Below that budget some class gets nothing, and the function does not pretend
otherwise.

The reservation can only **lower** the total value — it spends slots on
candidates a global sort would have skipped. That is the trade, it is
deliberate, and `reservation_per_class = 0` turns it off for an operator who
would rather have the maximum. Both behaviours are pinned by
`the_reservation_gives_every_class_a_slot_before_the_global_fill`, which asserts
the starvation and the remedy side by side.

## What the behavioural fingerprint does here

The fingerprint is the **tie-break**, and equal values are the *normal* case at
the top of a tick: entries written at the same instant have identical models,
identical classes and identical values. Ordering those by name orders them by
the query stream — the same order on every resolver in a fleet, and predictable
to an observer, which is the window in which a forged answer has the best chance
of entering the model. The fingerprint makes the order reproducible for us and
unguessable for anyone else.

It is also the cohort key for the reservation, because a cohort has to be a
stable property of the entry and the class is.

## What this is not

**A one-step lookahead.** It prices the next observation, not a policy. The
optimal *sequence* would need a planner over a belief state, and a per-tick
scheduler cannot justify one. Where the assumption shows: after observing, the
entry would in reality be observed again inside the same horizon, so
`E[R(after)]` is a slight over-estimate and the value a slight under-estimate.
The direction is the safe one, and it is stated rather than hidden.

**A claim of measurement.** Every number above is derived. The module has
property tests — monotone in class, in penalty, in value, in age; bounded by the
risk of not acting; zero when there is nothing to learn — and no performance
figures.

## See also

* [Risk-constrained refresh](Refresh-Theory.md) — the hazard model and the risk
  functional this module prices against.
* [Cache admission and the change-rate model](Cache-Admission.md) — where the
  candidates come from.
* [The paper](../paper/RecurseX-risk-constrained-refresh.md) — the same
  argument in reviewable form.
