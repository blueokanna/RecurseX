# RecurseX refresh model: corrected engineering note

Version: **0.2.6**.

The previous manuscript's weakest-link lower bound and bottleneck-only refresh
theorems were incorrect and are withdrawn. Its Gamma update also did not define
the exact posterior of the stated binary-observation likelihood. Keeping those
proofs as the design's justification would misrepresent the implementation.

The corrected derivation, assumptions, bounded residual summary, refresh-gain
formula and evaluation requirements are maintained in
[Refresh model and dependency bounds](../wiki/Refresh-Theory.md), with a
[Chinese version](../wiki/Refresh-Theory-zh.md).

The valid probability statement is conditional: if each marginal bound is valid,
`P(intersection E_i) >= max(0,1-sum(1-p_i))`. It is not `min(p_i)`.
Real-data coverage of the approximate marginals remains unestablished. The default
stale policy is disabled, and local signature checks are not chain authentication.

This document is an engineering correction, not a claim of peer review,
novelty, measured coverage or proven public-network availability.
