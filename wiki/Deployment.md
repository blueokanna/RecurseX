# Deployment & hardening

## Running it

The client-facing `Server` binds UDP and TCP (plain DNS). The JSON config
(`config::Config`) covers listen addresses, cache sizes, engine behavior,
policy, forwarders and persistence. A minimal systemd-style deployment:

```json
{
  "listen": [{ "addr": "0.0.0.0:53", "proto": "udp" }],
  "listen": [{ "addr": "0.0.0.0:53", "proto": "tcp" }],
  "cache": { "hotCapacity": 2048, "warmCapacity": 131072 },
  "engine": {
    "qnameMinimization": true,
    "use0x20": true,
    "dnssec": true
  },
  "persist": { "path": "/var/lib/recursex/cache.rxc", "saveIntervalMs": 60000 }
}
```

Note the example above shows two listen entries; in practice a single entry
with `"proto": "udp"` plus `Server::bind_tcp` on the same port covers both.

Run the maintenance loop (`spawn_maintenance`) so sweeps, graph pruning and
predictive prefetch actually happen, and so the persistent tier is written on
schedule.

## Stopping it

Both the server and the resolver have a shutdown path, and a deployment
should use it: dropping the process without it leaves the `persist` snapshot
up to one `saveIntervalMs` old, and leaves connection state to the OS.

```rust
// SIGTERM handler, or the end of main:
server.shutdown();      // every loop stops within 100 ms
resolver.shutdown();
server.join();          // returns once the threads have exited
```

Shutdown is a flag, not a signal: the UDP receivers wake on their socket
timeout, the handler pool on its queue timeout, the TCP accept loop is
released by a self-connect (so it does not wait for a real client) and each
connection reader on its own socket timeout. The maintenance loop stops
sleeping in at most 100 ms slices and writes a final snapshot on the way out,
so the next start restores from a fresh file even if the last scheduled save
had not fired yet.

Two client-facing bounds protect the thread budget:

- **TCP idle timeout** (`tcp_idle_timeout_ms`, default 30 s): a connection
  that sends nothing between messages is closed (RFC 7766 section 6.2.3
  recommends exactly this instead of holding an idle client forever).
- **Message deadline**: a client that dribbles a message one byte at a time
  cannot hold a reader past the idle timeout either, because the in-message
  deadline is capped at the smaller of 10 s and the idle timeout.

## Security model

- **Rate limiting**: a token-bucket limiter per client IP (`client_qps` /
  `client_burst`), with a bounded bucket table so a spoofed-source flood
  cannot grow memory.
- **Anti-spoofing**: every upstream response is checked against the query —
  transaction ID *and* question echo. 0x20 randomization (`use0x20`) adds
  per-query entropy in the qname, making blind cache poisoning substantially
  harder.
- **Bailiwick discipline**: only in-zone data may be cached from a response.
  Out-of-zone glue is used transiently, never cached as authoritative.
- **DNSSEC**: with `dnssec` enabled, answers are validated and marked;
  `Bogus` data is not presented as secure.
- **Filtering**: policy `block` rules drop queries under the listed names.

## Operational notes

- The UDP transport validates the source address of every response; on
  Windows, "connection reset" on a connected UDP socket is treated as a
  transient event (it is how the OS surfaces ICMP errors), not a fatal
  connection state.
- Timeouts: per-server attempt budgets and a global attempt budget bound the
  worst case for a pathological zone; `timeout_ms` bounds each exchange.
- The resolver never blocks on upstream in the request path for cache hits;
  misses and stale-refresh go through the coalescer, so duplicate concurrent
  queries share one upstream exchange.

## Limits to know before you trust it

- DoT/DoH/DoH3/DoQ are **upstream** transports; the client-facing server is
  plain UDP/TCP. Terminate TLS in front of it if you need encrypted client
  transport.
- DoQ ships a from-scratch RFC 9250 client (QUIC v1 + QUIC-TLS 1.3) as the
  default transport, so encrypted upstream forwarding works out of the box;
  a custom QUIC stack can still be plugged in through the `DoqProvider` trait.
- DNSSEC is RSA/SHA-256; ECDSA chains resolve as `Indeterminate`.
