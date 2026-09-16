# Architecture

RecurseX is a pipeline, not a blob. Each layer owns one job and talks to the
next through narrow interfaces, so the algorithmic core is `no_std` and the
networked parts are isolated behind the `std` feature.

| # | 架构层 | 主要文件 / 模块 | 核心职责 |
|---:|---|---|---|
| **1** | **Client Layer**<br>客户端层 | `server.rs` | UDP/TCP 监听器<br>每次查询的响应构建器 |
| **2** | **Query Processing**<br>查询处理 | `query.rs`<br>`policy.rs` | 规范化（Normalize）<br>请求去重（Dedup）<br>请求合并（Coalesce）<br>0x20 编码<br>速率限制（Rate Limit） |
| **3** | **Multi-tier Cache**<br>多级缓存 | `cache/`<br>`stability.rs`<br>`cache/score.rs`<br>`cache/persist.rs` | Hot / Warm / Cold + NXDOMAIN<br>缓存稳定性模型<br>评分准入（Score Admission）<br>过期缓存服务（Serve-stale）<br>预取（Prefetch）<br>L3 持久化 |
| **4** | **Resolution Engine**<br>解析引擎 | `resolver.rs`<br>`engine.rs`<br>`dnssec/` | Root → TLD → Authoritative<br>CNAME / DNAME<br>Referral 处理<br>DNSSEC 验证 |
| **5** | **Upstream Transport**<br>上游传输 | `transport.rs`<br>`transports/`<br>`forward.rs` | `DnsTransport` Trait<br>UDP / TCP / DoT / DoH / DoH3 / DoQ<br>Forwarder 集合 |
| **6** | **Security / Policy**<br>安全与策略 | `policy.rs`<br>`query.rs`<br>`dnssec/` | 速率限制<br>内容过滤<br>防欺骗检查（Anti-spoofing）<br>DNSSEC 判定（Verdicts） |

## Data flow for one recursive query

1. **Client layer** receives a wire message (UDP datagram or TCP stream).
   It is parsed by the wire codec in `message.rs` / `rdata.rs` / `name.rs`.
2. **Query processing** normalizes the qname (lowercase, trailing dot),
   deduplicates concurrent identical queries (a coalescer with a condvar
   wait), applies the client rate limit, and builds a `QueryKey` (name, type,
   class, ECS partition, DNSSEC flags).
3. **Cache** is consulted first. A fresh hit returns immediately with the
   remaining TTL. An expired-but-within-window entry may be served stale
   (RFC 8767) while a refresh is kicked off. A miss proceeds to the engine.
4. **Resolution engine** walks the tree. It queries the root hints, follows
   referrals one zone at a time, applies QNAME minimization (RFC 9156),
   chases CNAME/DNAME, filters out-of-bailiwick data, and (with `dnssec`)
   validates the answer chain.
5. **Upstream transport** delivers the wire query over the selected
   protocol. UDP truncation falls back to TCP. Encrypted transports are
   feature-gated.
6. **Security/policy** is interleaved: rate limits at the front door,
   response-matching at the engine (ID + question echo), bailiwick rules at
   cache time, DNSSEC verdicts at the end.

Every layer that touches time does so through the `Clock` trait (`time.rs`),
so the whole pipeline can be driven by a manual clock in tests and
simulations.

## Where the no_std boundary is

`--no-default-features` builds the wire codec, cache, estimator, graph,
upstream model, policy and planner without `std` (only `alloc`). Sockets,
threads, the resolver, the server, JSON config and the encrypted transports
are `std`-gated. The no_std core is what makes the prediction machinery
portable to embedded targets that only want the model, not the network.

## Error model

One `Error` type (`error.rs`) with a `kind` — wire, protocol, internal,
transport, io, config. The resolver maps failures to DNS responses
(SERVFAIL) at the client boundary; internal errors never leak wire details.
