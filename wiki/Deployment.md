# Deployment and failure boundaries

Version: **0.2.6**.

## Listener and lifecycle

`Server::new` accepts loopback clients only, even when bound to `0.0.0.0` or `::`.
LAN service must configure `ServerConfig::allowed_clients` with explicit `IpCidr`
networks. IPv4-mapped IPv6 peers are normalized at this access check. UDP rejects
unapproved clients before queuing; TCP rejects them before allocating a handler.
This ACL is programmatic; `Config` JSON does not currently expose `allowed_clients`.

Bind UDP and TCP to the same port. In particular, when requesting port zero, use the
address returned by `bind_udp` for `bind_tcp`. If either bind fails, shut down and
join the partially started server. Client-side encrypted listeners are not provided.

Run `spawn_maintenance()` explicitly for prefetch, sweeps and scheduled persistence.
For shutdown, signal the server and resolver, then join the server and maintenance
handles. Socket and queue loops poll shutdown at 100 ms intervals; a resolution
already in progress can take its remaining upstream deadline. Shutdown is not an
instantaneous cancellation of blocking dependency I/O.

## Resource limits

Defaults: 2 UDP receivers, 8 UDP handlers, 1024 queued datagrams, 1024 concurrent TCP
connections and a 30-second TCP idle timeout. The configured UDP receive-buffer size
is honored and clamped to 512..65535 bytes. Mobile embedders should set smaller queue
and thread limits. A TCP limit of zero explicitly disables that cap; do not use it
on an untrusted network. In-message reads have a deadline, so a slow byte stream
cannot keep a connection alive indefinitely by continually resetting an idle timer.

Per-source token buckets are best effort: forged source addresses can evade them.
EDNS negotiation limits response size, not the response/request amplification ratio.
Keep recursive service behind source validation, firewall policy and appropriate
network rate limits. Allowing `0.0.0.0/0` or `::/0` explicitly opens recursion to the
world; the in-process limits do not make this safe against volumetric attacks.

## Upstream behavior

Pure recursion needs reachable authoritative UDP/TCP port 53. If a network drops,
redirects or restricts it, transport recovery cannot make that path universally work.
Configure acceptable forwarding alternatives deliberately; a privacy-constrained
route never silently escapes to an unconfigured public resolver.

Authority attempts reserve time for alternatives. UDP timeout or truncation can retry
TCP within the same deadline; truncated TCP is not accepted. A failed loopback
forwarder with alternatives is avoided for five seconds; network-generation changes
clear this cooldown. Valid negative answers do not penalize endpoint availability.

DoT/DoH/DoH3/DoQ require configured trust roots and verified identity. JSON uses
`forwarderCaFile`; library callers use `EngineConfig::forwarder_roots` or
`set_forwarder_roots(roots, true)`. DoT/DoQ can separate connection IP and TLS name.
Current Courierust HTTP APIs cannot do that for DoH/DoH3: `host` must match `ip` as an
IP literal, with matching certificate IP identity. Unsupported combinations fail
configuration instead of silently dialing a different address. Redirects are refused.
DoQ remains experimental: public interoperability, congestion control and migration
are not established deployment guarantees.

Security randomness uses OS-seeded ChaCha20 and rekeys after 1 MiB of output.
SplitMix64 is for non-security sampling and deterministic tests. Upstream source,
transaction ID and question identity checks remain necessary alongside randomness.
See [DNSSEC](DNSSEC.md) for why local signature success cannot assert AD.

## Observations and diagnosis

Collection is off until `observation::configure(capacity)`; capacity is capped at 512.
Snapshots report completed resolver calls, not packet counts. Nested calls can appear
separately; each event retains at most eight 256-byte answer summaries. Contention
drops observations rather than blocking resolution. `configure(0)` disables and
clears the ring. History is not persisted and clearing it does not clear the cache.

Test UDP and TCP separately, then a cold recursive answer, a cache hit, an authoritative
negative and a configured fallback. Distinguish DNS response codes, transport errors,
certificate failures and work-budget exhaustion. A bound listener proves only that
the socket opened, not that authoritative resolution is reachable.
