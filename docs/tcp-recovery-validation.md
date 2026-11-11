# TCP recovery and bounded server I/O

## Reported failure

[GitHub Actions job 130455275846](https://github.com/blueokanna/RecurseX/actions/runs/43000537493/job/130455275846)
tested commit `1aae3a839f0ede1b980c25fb9d9b8c5d41535e2f` on Windows Server 2025
with Rust 1.99.1. The sole failed job was `test (stable, windows-latest)`:
`udp_blackhole_can_resolve_over_tcp_inside_the_original_deadline` failed while
reading the TCP length prefix, with Winsock error 10054.

The local authority used a nonblocking listener but performed blocking-style
`read_exact` and `write_all` on accepted sockets. On Windows, accepted sockets
inherit the listener's properties. A read before the query arrives can therefore
return `WouldBlock`; the fixture discarded that error and closed the connection.
Setting read/write timeouts does not reset nonblocking mode.
See [Microsoft's accept documentation](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-accept).

Thirty ordinary baseline runs passed locally. A regression that waits until
accept, then delays and fragments the query, failed before the fix with a closed
connection. This establishes why repeating only the original test missed the race.

## Changes

- Explicitly put accepted fixture sockets into blocking mode before frame I/O.
- Keep a silent authority's TCP connections open; model immediate close separately.
- Propagate unexpected accept/read/write failures from workers and join every
  worker before reporting an error. Do not panic a second time during unwinding.
- Assert that UDP timeout recovery actually used both UDP and TCP exactly once.
- Exercise delayed queries and fragmented length prefixes and bodies.
- Repeat the recovery suite ten times in every Linux/Windows, MSRV/stable CI leg.

The related server review also found that response `write_all` had only a
per-system-call timeout. Short writes could restart that timeout, and a blocked
write could postpone noticing shutdown. `src/server/stream_io.rs` now owns
partial progress, polling, cancellation and absolute read/write deadlines.
`src/server.rs` retains connection admission, DNS framing and resolver dispatch.
No public API, Rust 1.78 requirement, upstream retry budget or dependency changed.

Server I/O regressions cover fragmented reads across polling timeouts, EOF in a
frame, short/interrupted writes, slow progress exhausting an absolute deadline,
shutdown between writes, zero progress and non-retryable errors. The write-policy
tests inject short writes rather than assume an OS-specific socket buffer size.

## Verification scope

Both Rust 1.78 and stable passed thirty consecutive recovery-suite runs locally
on Windows after the fixture fix. Final all-feature runs each passed 622 tests
with zero failures and one intentionally ignored test. The std-only run passed
474 tests with one ignored; the no_std library run passed 339 tests. Formatting,
Clippy (all features, std-only and no_std), rustdoc, release compilation and
offline package verification also passed. Local command logs are under
`target/ci-verification/recovery-*.log`.

This is a targeted review of the failing fixture and related TCP I/O/resource
bounds, not a complete security audit or a claim that the repository has no
vulnerabilities. The dependency advisory scanner (`cargo audit`) is not installed
in this environment. A remote run of the changed commit is still required to
establish the updated Linux/Windows matrix result; rerunning the old commit does
not test these changes.
