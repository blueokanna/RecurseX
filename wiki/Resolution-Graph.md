# Resolution graph

A recursive resolution is not a linear walk. `www.example.com` depends on the
`example.com` zone, which is delegated from `.com`, which is served by a set
of servers — and the CNAME may jump to a completely different tree. The
resolution graph makes that structure explicit and bounded.

## Nodes and edges

```
www.example.com ──cname_to──▶ cdn.example.net ──depends_on──▶ example.net zone
       │                                                          │
       └──depends_on──▶ example.com zone ──served_by──▶ ns1/ns2.example.com
                              │                                   │
                              └──delegates_to──▶ .com ──served_by──▶ a.gtld-servers.net
```

- `NodeId::Domain(Name)` / `NodeId::Ns(Name)` / `NodeId::Server(ip, port)`;
- edges: `DependsOn` (a name needs a zone), `DelegatesTo` (zone → child
  zone), `ServedBy` (zone → NS), `CnameTo` (name → target), `ReachableVia`
  (server → domain it answered).

## What it buys

1. **Prefetch fan-out.** When a prefetch decision is made for a zone, the
   graph shows which names depend on it. Instead of refreshing one key, the
   maintenance loop can refresh the whole dependency set.
2. **Sub-resolution sharing.** The NS names and addresses of a zone are one
   graph neighborhood; many queries under that zone reuse it.
3. **Diagnostics.** The graph is a live map of what the resolver actually
   talked to — which servers answered which zones.

## Bounding

`max_nodes` caps the graph. `prune(now, max_age)` removes nodes not touched
within the age bound, so long-lived resolvers do not accumulate dead
structure. The maintenance thread calls this on every tick.
