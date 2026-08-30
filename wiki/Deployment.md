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
- DoQ's QUIC connection comes from a provider trait; the default provider
  reports DoQ as unavailable (see the README limitations).
- DNSSEC is RSA/SHA-256; ECDSA chains resolve as `Indeterminate`.
