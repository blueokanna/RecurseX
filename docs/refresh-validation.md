# Risk and refresh validation

Base: `f7a387c0813a2b15ec6532864dcd9187d5a19794`. Local HEAD matched the
requested base and the working tree was initially clean. Validation date:
2026-11-09. No real request trace was available; production performance
acceptance remains open.

## Correctness and safety

The original implementation failed three newly added tests: two 0.99
dependencies admitted a 0.99 stale threshold; ten proof nodes exceeded a
capacity of one; dropping a delegation reduced Critical consequence to Low.
All three now pass. Eight provenance regressions cover these cases plus
saturation, zero capacity, insertion-order/trimming equivalence, malformed
public probabilities, residual-aware refresh gain and planner integration.

`bound()` remains a weakest-marginal diagnostic. Decisions use the union-bound
joint lower bound. The change proves correct combination conditional on valid
marginals; it does not validate the approximate per-record Gamma model.

Stale is disabled by default. Failure fallback requires an actual failed
attempt for the current request; immediate prediction requires explicit
experimental configuration. Regression tests cover no early stale return,
failure fallback, positive TTL, AD suppression and zero-worker configurations.
The legacy `dnssec_anchored` flag cannot create root-anchored trust.

Loopback TLS tests include a successful trusted handshake and wrong hostname,
untrusted certificate and expired certificate rejection. All rejection cases
verify that no DNS application payload reaches the test server. The fixture
certificate/private key are generated public test material, never deployment
credentials. JSON encrypted-upstream configuration requires a PEM trust file;
library construction fails closed until roots are supplied. An existing direct
`EngineConfig::forwarders` routing omission was also corrected: it must use
the configured forwarding group instead of falling into iterative resolution.

## Scheduler and work limits

The ordered due index is implemented as a BTreeSet alongside each tier's
key map, an updateable O(log n) index rather than a heap with obsolete nodes.
Insert, replacement, tier movement, eviction, restore and expiry update it
together with the cache. Tests assert one node per entry through 500 mutations,
bounded batch progress and non-reused generations after eviction/reinsertion.
Generation, expiry and refresh ownership are rechecked at admission; workers
check the generation again before execution.

The fixed pool uses a bounded channel and an active-key set. Queued plus
running tasks cannot exceed `max_concurrent_refreshes`; zero disables them.
Tests cover duplicate submissions across replacement, disconnected queue,
task unwind, shutdown and stale snapshots. Background work joins the existing
query coalescer, with a deadline when waiting for an owner. Restored snapshots
receive new runtime generations; scheduling state is not persisted.

All resolver exchange dispatch goes through the scoped work limiter, including
forwarder retries and nested DNSSEC queries. An on-wire loopback test verifies
that the second forwarder attempt is stopped before sending when the global
exchange limit is one. The limiter separately enforces global exchanges,
reserved DNS bytes, per-IP concurrency/rate, and per-task exchanges/bytes and
deadline. Existing referral/depth/subquery limits remain in place.

Byte limits cover DNS payloads. Before sending, a maximum-size DNS response is
reserved; successful completion refunds unused bytes, while failure retains
the reservation. This can reject small queries conservatively when less than
65,535 response bytes remain. It does not budget transport framing, handshake
packets, unsolicited traffic or bytes consumed inside a failed partial read.
External capture is required for total network-cost acceptance. Existing
transport timeouts remain subject to their protocol/library semantics; the
limiter prevents new sends after the task deadline and cannot preempt a thread
already inside a blocking transport call.

Calibration records the Gamma model's predictive unchanged probability before
updating the model, then the observed content equality. Failed attempts are
not unchanged observations. Stale service is counted only after admission;
the next differing observation increments `stale_later_changed`. This counts
changed stale-served content versions, not the number of clients affected.
Eviction without another observation cannot establish a retrospective outcome.

## Offline measurements

Command: `cargo run --release --example refresh_bench -- 10000 20`.
Windows x64, Rust 1.78, release profile; one scheduler thread and one concurrent
cache-reader thread. Fixed 10,000 entries and 20 rounds, 100 lookups per round.
No network traffic, CPU pinning or RSS sampling. These are a lock-contention
microbenchmark, not DNS client latency or production throughput results.

| Scheduler | Entries checked | Total lock hold | Scoring time | Lookup p50 / p95 / p99 | Index nodes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original scorer, full scan | 200,000 | 2,120,778 µs | 2,120,779 µs | 1 / 1 / 24 µs | 10,000 |
| Prediction off | 0 | 0 µs | 0 µs | 0 / 1 / 1 µs | 10,000 |
| Incremental, 256 checks/tick | 5,120 | 3,094 µs | 72,971 µs | 1 / 2 / 36 µs | 10,000 |

This run demonstrates bounded scan work and shorter lock holds. **Lookup p99
did not improve.** Timing depends on OS scheduling, and fewer candidates per
round can defer useful refreshes. No production latency or upstream-cost
improvement is established. The old scorer is reproduced in
`examples/support/legacy_refresh.rs`; the comparison still uses the new cache
and engine and is not an execution of the entire original release.

## Real trace entry point

Trace rows are `offset_ms name rr_type`, whitespace-separated, with optional
`#` comments. Offsets must be ordered. The runner is a sequential client;
`max_lateness_us` exposes inability to keep up. It is not an open-loop QPS test.

```text
0 www.example.com A
10 www.example.com AAAA
50 mail.example.com MX
```

```powershell
cargo run --release --example request_replay -- config.json trace.tsv legacy
cargo run --release --example request_replay -- config.json trace.tsv off
cargo run --release --example request_replay -- config.json trace.tsv incremental
```

Use the same trace, capacity, CPU allocation and controlled upstream for every
run; repeat in varied order. `legacy` reproduces the old scorer on the new
engine, `off` disables predictive maintenance, and `incremental` runs the new
scheduler. For a release-to-release comparison also run the original commit
under the same external load generator. Do not reuse production persistence
files for benchmark configurations.

CSV includes client p50/p95/p99, errors, schedule lateness, exchange attempts
and known DNS bytes per client query, background work/denials, index length,
peak reserved tasks, rejected duplicates, cumulative queue time, scheduler
cache-lock wait/hold time, stale answers and subsequently changed versions.
Lock metrics cover the new scheduler's snapshot phase, not every cache lock
or the legacy scorer; zero legacy counters do not mean zero contention.
Use external CPU/RSS sampling and packet capture, and record queue-time and
lock-time distributions in a load harness for full acceptance. At exit,
`background_remaining` must be zero for a complete work tally.

A loopback smoke replay exercised all three modes with ten requests and a
two-second TTL. Each mode completed with zero errors; its 2 exchange attempts
and 182 DNS bytes matched the UDP stub's independent counters. That validates
the replay plumbing, not useful predictive behavior on a real workload.

## Checks

The dependency upgrade on 2026-11-09 uses the official crates.io releases:
[courierust 1.1.1](https://crates.io/crates/courierust/1.1.1),
[nextjson 0.1.5](https://crates.io/crates/nextjson/0.1.5),
[tzcraft 0.1.2](https://crates.io/crates/tzcraft/0.1.2), and
[rustbinary 0.1.10](https://crates.io/crates/rustbinary/0.1.10).
The registry API confirmed these as the latest stable versions at the time
of the upgrade. There is no vendored source or path override. RustBinary
uses only its `std` feature; schema derives come from nextjson.

The upgrade adds fail-closed DNSSEC handling to fresh/cache/stale paths,
thread-local validation recursion guards, a shared foreground/nested fetch
envelope, and active-owner retention when the coalescing table is full.
UDP truncation in forwarding now retries TCP against the same upstream.
UDP wrong-source floods and TCP/DoT framing use a monotonic deadline.

Snapshot reads are capped before decoding, with explicit codec token/work
limits. Restore validates record identity, ECS partitions and capacity, and
clears validation flags. Saves use exclusive temporary files, file sync,
atomic replacement, bounded Windows rename retries and Unix directory sync.
The concurrent-save test reproduced Windows access-denied races before the
bounded commit logic was added.

HTTP/2 and HTTP/3 loopback tests independently verify connection reuse,
media type, redirect rejection, and certificate failure before DNS payload.
With this published dependency, pinned DoH requires an IP certificate
identity; separate hostname/IP routing is rejected instead of using system
DNS. The pooled HTTP client is refreshed when its validation second changes,
which prevents a permanently frozen certificate clock but reduces connection
retention. HTTP phase timeouts still follow the dependency's blocking I/O
semantics; there is no claim of preempting an in-progress library call.

Observed test results:

| Build | Unit | Integration | Documentation |
| --- | ---: | ---: | ---: |
| Rust 1.78, all features | 481 | 40 | 4 |
| Installed stable, all features | 481 | 40 | 4 |
| Rust 1.78, no default features | 335 | 8 | 3 |
| Rust 1.78, std only | 414 | 19 | 4 |

The Windows MSRV CI failures were reproduced with the test process restricted
to two logical CPUs and eight test threads. The original DoT fixture's
two-second deadline expired during all five concurrent handshakes: the two
success cases failed, while three certificate-rejection cases falsely passed
because they reduced every error to `false`. The earlier HTTP fixture fix
did not cover this separate test binary.

DoT and HTTP fixtures now share a functional-test budget and serialization
helper. DoT assertions retain both peers' errors, require the specific
certificate rejection reason and count every received application byte.
Successful cases exchange complete DNS messages with the response length
prefix and payload split across TLS records. Listener acceptance is bounded,
and teardown joins the server before releasing the test gate. CI repeats
both encrypted-DNS test binaries; a failed round terminates the step.

Formatting and strict Clippy are also checked.
The existing empty documentation line in `src/float.rs` was fixed instead of
waiving the stable Clippy warning. Exact final counts are reported in the
task delivery; no historical 441/32/4 count is treated as current evidence.

Open acceptance items: real trace replay, fixed-resource CPU/RSS and network
cost comparison, client tail-latency improvement, calibration coverage, and
complete root-to-answer DNSSEC validation. No new statistical model or
transport connection pool is introduced by this patch.
