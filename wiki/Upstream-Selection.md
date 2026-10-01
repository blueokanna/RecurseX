# Upstream selection cost model

Picking an authoritative server by raw RTT is wrong. A server that is fast
92% of the time can be *more expensive in expectation* than a slightly
slower server that never fails, once retransmissions and SERVFAIL penalties
are counted.

## The per-authority path model

Each `(authority, endpoint)` pair carries a small statistical model:

- EWMA RTT and RTT variance;
- loss count and SERVFAIL count;
- a bounded number of tracked paths (`bounded_paths`).

## Expected resolution cost

Selection ranks candidates by

```
cost = rtt_ewma + conn_setup + loss_penalty + failure_penalty
loss_penalty    = RTO · p_loss / (1 − p_loss)
failure_penalty = RTO · p_servfail · 1.5
```

where `p_loss` and `p_servfail` are smoothed failure probabilities and `RTO`
is the retransmit budget. Unknown paths get a neutral prior (one 100 ms RTT
plus transport setup), and are *slightly preferred* so they get probed —
otherwise a new, possibly better server would never be learned.

## Feedback

Every exchange records `record_success` / `record_timeout` / `record_servfail`
into the model. A server that starts failing accumulates penalty; a server
that recovers decays back. The resolver only queries servers that clear the
attempt budget per exchange, bounded by `max_servers_tried` and
`max_total_attempts` so a pathological zone cannot burn the whole request
timeout.

## Transport setup

Setup cost differs by protocol (`Udp`, `Tcp`, `Tls`/DoT, `DoH`, `DoH3`,
`DoQ`). TCP and TLS pay a handshake; UDP pays nothing — which is one reason
the engine prefers UDP and only falls back to TCP on truncation.

## Exchange-level failure policy

The cost model above ranks *paths*. It cannot help when an exchange settles on
one forwarder and that forwarder answers with a failure: the exchange would be
over before any other candidate is tried. `Forwarders::exchange_with` therefore
treats a failure *reply* as a non-answer:

- `REFUSED`, `SERVFAIL` and any other non-`NOERROR` code mark that forwarder as
  failed for this exchange — recorded through `record_servfail` — and the next
  candidate is tried. One broken upstream no longer vetoes the healthy ones,
  which is what a nameserver list with a single dead member used to cost: every
  lookup failed even though six of the seven servers answered.
- `NXDOMAIN` is *not* a failure. The name does not exist, and saying so is the
  answer, so it ends the exchange immediately and no further upstream is
  queried — that is what makes negative answers cheap.
- When every forwarder fails, the caller gets the last failure (a refusal
  surfaces as `ErrorKind::Refused`, anything else as `ErrorKind::Servfail`)
  together with the endpoint that produced it. Never a bare empty answer, so
  the layer above can report *why* a name could not be resolved instead of
  guessing.
