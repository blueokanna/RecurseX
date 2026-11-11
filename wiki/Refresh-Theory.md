# Refresh model and dependency bounds

Version: **0.2.6**. This page replaces the earlier weakest-link and conjugate-posterior arguments.

## What is observed

The resolver compares canonical RRset content at successful refreshes. TTL and
RRSIG rotation are excluded from content equality. Equality is an exact comparison
of sorted canonical records, not a decision based only on a non-cryptographic hash.
An interval supplies its duration `h` and a binary endpoint difference `Y`.
It does not supply the number of changes. In particular, A → B → A is invisible.

For a non-reverting Poisson change process, the interval likelihood would be

```
L(lambda) = product((1-exp(-lambda*h_i))^Y_i * exp(-lambda*h_i*(1-Y_i)))
```

A Gamma prior is not conjugate to this likelihood when any `Y_i=1`. The implemented
update `alpha += w*Y; beta += w*h` is a working approximation inspired by count data.
It is not an exact posterior for the observations. An unchanged observation does
carry information under the idealized likelihood; the earlier claim that it carries
none was incorrect. Neither the direction nor the size of the approximation error
is established for arbitrary DNS update processes.

Forgetting discounts evidence toward the TTL-based prior. Trust weights and finite
evidence ceilings limit influence; they do not detect fabricated observations or
prove that the selected prior is realistic. TTL is a cache lifetime, not a measured
event rate. All positive Gamma shapes have finite means for a positive rate parameter;
the default shape of 1 is an engineering choice, not a mathematical minimum.

## What the Gamma calculation proves

For the chosen law `Lambda ~ Gamma(alpha,beta)`, and `x >= alpha/beta`,

```
Pr(Lambda >= x) <= exp(alpha-beta*x) * (beta*x/alpha)^alpha
```

The implementation solves this Chernoff expression for a requested tail probability
and evaluates `p_i = exp(-lambda_hi*age)`. This is a model-conditional calculation.
It does not prove frequentist coverage for the real DNS process, nor authenticate
data or the server supplying it. A calibrated mean is not a proof of tail coverage.

## Combining dependencies

If each `p_i` is a valid marginal lower bound for event `E_i`, the union bound gives

```
Pr(all E_i) >= max(0, 1 - sum(1-p_i))
```

No independence assumption is needed. The premise matters: combining predictions
does not establish the marginal coverage that the model itself has not proved.
`min(p_i)` is not a general lower bound for an intersection. Two 0.99 marginals
with disjoint failures have joint probability 0.98. Multiplication needs independence.

`Provenance::joint_lower_bound()` implements the union expression. `bound()` retains
the minimum as a diagnostic only; `independent_bound()` is a diagnostic product of
the retained members, not an authorization decision or a summary of omitted members.
Non-finite member values are treated as zero. Invalid decision thresholds are rejected.

The dependency capacity is a memory bound. Omitted dependencies retain their failure
mass, worst consequence and stale prohibition in a fixed-size residual summary.
Even a zero-capacity provenance set cannot discard a DNSSEC-proof prohibition.
Residual mass is conservative; once identities are discarded, deduplication and
per-member refresh accounting cannot be recovered from it.

## Refresh benefit

For `L=max(0,1-S)` and `S=sum(1-p_i)`, hypothetically refreshing member `j` to 1 yields

```
gain_j = max(0, 1 - (S - (1-p_j))) - L
```

A non-minimal member can improve this bound. If total failure mass exceeds 1,
several members may need refresh before the bound becomes positive. A zero immediate
gain therefore does not mean that a member is irrelevant. `refresh_plan` orders
available candidates by their gain and uses deterministic tie breakers. This is not
a proof that the plan globally optimizes a finite multi-step refresh budget.

Value-of-information scheduling simulates both outcomes through the same `observe`
routine used by real refreshes. It ranks model-based expected benefit and reserves
capacity across consequence classes; it does not turn predictions into security facts.

## Stale policy

`PlannerConfig::stale_policy` defaults to `Disabled`. `OnRefreshFailure` requires an
upstream failure for the current request before considering age, evidence, consequence,
provenance and aggregate risk-budget gates. `ImmediateExperimental` explicitly enables
immediate model-based stale service. JSON spells these `disabled`,
`on-refresh-failure` and `immediate-experimental` under the top-level `stalePolicy` key.

The risk functional `V*(1-p)*C*kappa` is an engineering policy score. Budgeting it
does not establish a real-world error-rate guarantee. DNSSEC proof dependencies forbid
stale service; invalid signatures are rejected before cache admission and on cache reuse.
Stale responses use the configured positive response TTL (default 30 seconds), and
never assert AD. See [RFC 8767](https://www.rfc-editor.org/rfc/rfc8767).

## Evaluation that remains necessary

`content_calibration()` scores predictions made before successful replacements
against subsequent endpoint equality. Failed refreshes are not counted as unchanged.
Refresh selection biases this sample. Coverage evaluation needs independently sampled
traces, timestamped authoritative ground truth, reversion and bursty processes,
failure censoring and out-of-sample intervals. No such public-network coverage result
is asserted by 0.2.6. Formula tests and hermetic regressions test implementation
consistency, not authenticity, universal availability or continuous correctness.
