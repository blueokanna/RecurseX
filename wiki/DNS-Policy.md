# DNS policy layer (Clash compatible)

The `dns` section brings the surfaces a Clash / mihomo user already knows into
RecurseX:

```json
{
  "dns": {
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.0/16",
    "fake-ip-filter": ["*.lan", "*.local", "localhost"],

    "hosts": {
      "internal.example": "10.0.0.53",
      "dual.example": ["10.0.0.1", "2001:db8::1"]
    },

    "nameservers": ["tls://1.1.1.1#one.one.one.one"],
    "fallback": ["tls://8.8.8.8#dns.google"],

    "nameserver-policy": {
      "+.v51124-6.qpon": ["tcp://127.0.0.1:8080#node.internal"]
    },

    "fallback-filter": {
      "ipcidr": ["240.0.0.0/4", "0.0.0.0/8", "127.0.0.0/8"],
      "domain": ["+.google.com"]
    }
  }
}
```

## Every key accepts three spellings

| Clash | underscore | this crate's JSON |
|---|---|---|
| `enhanced-mode` | `enhanced_mode` | `enhancedMode` |
| `fake-ip-range` | `fake_ip_range` | `fakeIpRange` |
| `nameserver-policy` | `nameserver_policy` | `nameserverPolicy` |
| `fallback-filter` | `fallback_filter` | `fallbackFilter` |

A key copied out of an existing proxy config is **not** dropped. That is
deliberate: a key that parses, is stored, and then does nothing is far more
dangerous than one that fails — the configuration reads as if it works.

## Unknown keys are errors

Every struct in the `dns` section (and in `engine`, `cache`, `policy`,
`listen`) declares `deny_unknown_fields`. One mistyped letter produces an error
that **names the key**:

```
{"dns": {"nameserver-policyy": {...}}}
→ Config: unknown field `nameserver-policyy`
```

That rule is the reason this layer exists. The surface previously ignored
unknown keys by default, which made "I wrote it but it did nothing"
indistinguishable from "it works".

## Wildcard syntax

All four surfaces (`hosts`, `fake-ip-filter`, `fallback-filter.domain`, and the
keys of `nameserver-policy`) use **one** matcher, so the syntax cannot drift
apart between them:

| Form | Meaning |
|---|---|
| `example.com` | exactly that name |
| `*.example.com`, `+.example.com`, `.example.com` | that name and every name below it |
| `*` | every name |
| `time.*.com`, `stun.*.*` | label-wise; each `*` is exactly one label |
| `*.stun.*.*` | a leading `*` is zero or more labels, the rest one each |

Embedded wildcards are not a flourish: mihomo's own default `fake-ip-filter`
contains `time.*.com` and `*.stun.*.*`. Without support those entries parse
into literal names that match nothing — and a filter that silently matches
nothing looks exactly like a filter that is not configured.

With no leading `*` the pattern must match the **whole name**, label for
label (`time.*.com` matches `time.apple.com`, not `x.time.apple.com`); with a
leading `*` it matches a **suffix**.

## `hosts`: static answers

Consulted **before** the cache, and **never cached** — a reload has to take
effect on the next query, not after a TTL.

* A value is one address or a list of them.
* Keys accept `*.example.com`, `+.example.com` and `.example.com`: all mean
  "this domain and its subdomains". The most specific pattern wins, so an exact
  entry overrides a wildcard one.
* The table is **authoritative for `A`/`AAAA`**: a name pinned to a v4 address
  answers `AAAA` with **NODATA**, not with the real IPv6 address and not by
  going upstream. Pinning a name should pin it.
* `MX`/`TXT`/`SRV` and the rest are **untouched**: `hosts` is a statement about
  addresses, not an assertion that the name has no other records.
* A value that is not an IP address is an error naming the entry — a silently
  inert pin is nearly invisible to debug.
* A bare `*` is rejected: answering every name from a static table is
  indistinguishable from "DNS is broken".

## `enhanced-mode` / fake-IP

* `normal` and `redir-host` are both off; `fake-ip`, `fakeip` and `fake_ip`
  turn it on.
* With the mode on, `A` queries return a synthetic address from
  `fake-ip-range`; `AAAA` returns **NODATA**. A real IPv6 address would let the
  client dial the host directly and escape the proxy and its routing rules, so
  it has to be an empty answer.
* A name in `fake-ip-filter` is not synthesized and resolves for real — which
  is what local domains like `*.lan` need.
* **Omitting `fake-ip-filter` takes a built-in list**: local names, the
  Windows/macOS/Android connectivity probes, NTP/time hosts, STUN, and console
  NAT-type checks. This is correctness, not convenience: with those names
  faked, **the operating system concludes there is no internet**, the clock
  never syncs (which then breaks TLS), and WebRTC and games never find a path.
  An explicit `"fake-ip-filter": []` means "no exclusions", which is a
  different statement — the two must not be conflated.

### IPv6: `fake-ip-range6`

By default only IPv4 is synthesized and `AAAA` is answered NODATA. Configure
`fake-ip-range6` and `AAAA` is synthesized from that block instead (see
`DEFAULT_FAKE_IP_RANGE6`, i.e. `fdfe:dcba:9876::/48`):

```json
{ "enhanced-mode": "fake-ip", "fake-ip-range6": "fdfe:dcba:9876::/48" }
```

Why the switch has to be explicit:

* A dual-stack client that receives a synthetic `AAAA` will connect over IPv6
  to it. With a v6 pool behind it that is correct; without one, that address
  is one **nothing can reverse** — a silent bypass rather than a mapping.
* Conversely, with no v6 range the NODATA answer pushes the client back onto
  the v4 address it was already given.

The two families are **independent**: one name may hold a v4 and a v6 mapping
at once without either affecting the other, each family has its own
`maxEntries`, its own allocation cursor and its own recycle count, and
pressure in one family cannot evict the other's mappings. Reverse resolution
works for both: `in-addr.arpa` and `ip6.arpa` (32 nibble labels, least
significant first, with non-canonical labels refused rather than read as an
address).
* A name keeps the same address until the mapping expires, and the address maps
  back to the name. Reversibility is what makes the mode usable at all.
* When the pool is full it **recycles the least-recently-used mapping** and
  keeps answering rather than refusing. For a proxy, refusing means the client
  gets the real address and leaks past the routing rules; a renumbered mapping
  costs one connection. The recycle count is readable at
  `shared.fake_ip.evicted()`.
* `fake-ip-ttl` is the **mapping** lifetime (default 3600s);
  `fake-ip-answer-ttl` is the **answer** TTL (default 1s). They are different
  things: one bounds the pool, the other bounds how long a client may keep
  using the address it was handed.

## Upstreams and routing

* `nameservers` is the default group, `fallback` is the fallback group.
* `nameserver-policy` selects a group by suffix, **longest suffix first**, and
  an exact pattern ahead of a wildcard at the same suffix. Config key order
  does not affect the result: two configs that differ only in key order behave
  identically.
* Setting both `dns.nameservers` and `engine.forwarders` is refused. They are
  one setting in two spellings, and one of them would be ignored.
* Upstream strings use an IP literal, with the TLS identity after `#`:

  | Spelling | Transport |
  |---|---|
  | `8.8.8.8`, `8.8.8.8:5353`, `8.8.8.8@5353` | UDP |
  | `udp://`, `tcp://` | UDP / TCP |
  | `tls://1.1.1.1#one.one.one.one` | DoT |
  | `https://1.1.1.1/dns-query#cloudflare-dns.com` | DoH |
  | `h3://1.1.1.1/dns-query#cloudflare-dns.com` | DoH3 |
  | `quic://1.1.1.1#dns.example` | DoQ |
  | `tls://[2001:db8::1]:8853#dns.example` | IPv6, bracketed |

  The port may follow `:` or `@`. Unbound writes
  `1.1.1.1@853#cloudflare-dns.com`, so a forwarder line copied from an Unbound
  configuration keeps working.

  **Current limitation**: the address must be an IP literal; `tls://dns.google`
  is not accepted. A hostname upstream would have to be resolved before the
  resolver exists, and using the system resolver for it would make the resolver
  silently depend on whatever `/etc/resolv.conf` says — the one dependency it
  must not have, since it is the thing you install *because* resolution is
  broken. Unbound solves the same problem the same way (an address plus an
  explicit TLS name), so this is a convention rather than a gap.

## `fallback-filter`: is the answer trustworthy

* `ipcidr`: an answer containing any of these blocks is treated as poisoned and
  the query goes to the `fallback` group instead. **Any** matching address is
  enough — a polluted response typically mixes the real record with fabricated
  ones.
* **Omitting** `ipcidr` keeps the built-in list (`0.0.0.0/8`, `127.0.0.0/8`,
  `240.0.0.0/4`, `::/128`, `::1/128`, `100::/64`). An **explicit empty list**
  means "flag nothing". The two are different, and a config that only sets
  `domain` is still protected by the built-in list.
* RFC1918 private ranges are deliberately **not** in the default: home and
  split-horizon upstreams return private addresses legitimately, and flagging
  those as pollution would break working setups.
* `domain`: these names go straight to the `fallback` group, never touching the
  default servers.
* `geoip` / `geoipCode` need a country-to-CIDR database, which this build does
  not embed, so setting `geoip: true` is a **configuration error** naming the
  replacements (`ipcidr` + `domain`). Accepting it silently would leave an
  "anti-pollution config" with no anti-pollution at all while reading as if it
  had some.

## Observability

Every decision this layer makes has a counter (`stats_snapshot()`), because
all of them are quiet-failure shaped:

| Counter | What it tells you |
|---|---|
| `hosts_answered` | pins that fired |
| `fake_ip_answered` / `fake_ip_ptr` | synthesized forward / reverse answers |
| `fake_ip_filtered` | names excluded from the pool and resolved for real |
| `fake_ip_entries` / `fake_ip_evicted` | pool size (gauge) / recycles |
| `policy_routed` | `nameserver-policy` rules that matched — **zero means your suffixes do not** |
| `fallback_triggered` | poison-gate trips |

A rising `fake_ip_evicted` is the explicit signal to raise
`fake-ip-max-entries`.

## With no `dns` section

Nothing changes. An empty `dns` section produces a default-valued policy: no
pins, no synthesis, no routing, and a poison gate with nowhere to send a query.
That property is what makes the whole feature safe to adopt incrementally.

## See also

- [Architecture](Architecture.md) — where this layer sits in the pipeline.
- [Deployment](Deployment.md) — running it for real clients.
- [Testing](Testing.md) — how these behaviours are pinned down.
