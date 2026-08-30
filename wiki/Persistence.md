# Persistence (L3 tier)

A warm resolver's cache is a *prediction asset*: the stability models,
admission scores and tier assignments accumulated over hours of live
resolution are exactly the state a cold restart throws away. The `persist`
feature snapshots the whole semantic cache into one binary frame with
`rustbinary` (the only required use of that crate), writes it atomically, and
restores it on startup.

## Format

One type-tagged, self-describing frame (`cache/persist.rs`):

- magic + version;
- saved-at wall clock;
- entries — key (canonical wire name, type, class, ECS partition), tier,
  kind, timestamps, serve counts, the **full stability model**, validation
  flag and admission score;
- negatives — the per-name NXDOMAIN store.

RRset payloads are stored in their canonical **DNS wire form** (RFC 1035,
uncompressed names). The cache already knows how to emit and parse those, so
one codec serves both the network and the disk — no need to teach the binary
codec every RDATA variant.

## Write path

- `save_to` serializes with a bounded config, writes a `.tmp` file, then
  `rename`s it over the target — an interrupted write can never leave a
  half-written frame where the loader expects one.
- The maintenance loop writes on the configured `save_interval_ms`
  (default 60 s in the JSON config); `Resolver::persist_cache()` saves on
  demand.

## Restore rules

- Missing or unreadable file = cold start, not a startup failure.
- Decoding is bounded (`frame_limit`), because the file is untrusted input at
  a trust boundary.
- Fully dead entries (beyond the stale window) are dropped.
- Expired-but-stale-servable entries are parked in the **cold** tier, so
  serve-stale keeps working after a restart.
- The **remaining** TTL is recomputed from the absolute expiry — never
  invented.

## Tests

The suite covers: encode/decode round-trip, stale entries restoring into the
cold tier, dead entries dropped, ECS partitions surviving, and tamper
rejection.
