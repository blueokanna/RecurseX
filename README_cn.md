# RecurseX

用 Rust 写的一个「预测式自适应」递归 DNS 解析器。它会像 BIND/Unbound 那样沿委派树逐级解析，
但缓存层绝不是一张 `HashMap<query, answer>`。每条缓存条目都带着稳定性模型、准入分数和层级，
解析器会去预测**哪些数据值得留**、**什么时候会被问到**、**该问哪个上游**——但永远不会发明一个 TTL。

```
Client Layer ──▶ Query Processing ──▶ Multi-tier Semantic Cache ──▶ Resolution Engine ──▶ Upstream Transport
  UDP / TCP         normalize         hot / warm / cold / NXDOMAIN    root→TLD→auth      UDP / TCP / DoT
  (DoT/DoH/DoH3/    dedup / ECS       stability + score admission     CNAME/DNAME/NS      DoH / DoH3 / DoQ
   DoQ acceptor)    QNAME min.        serve-stale / prefetch          DNSSEC validate
                                                                              │
                                                                              ▼
                                                                      Security / Policy
                                                                      rate limit · filtering
                                                                      anti-spoofing · DNSSEC
```

## 为什么做这个

TTL 只是权威服务器**声称**的值，不是数据真实变化频率的度量。`3600` 秒的 TTL，配一个每五分钟
就轮换的记录，和配一个半年没动过的记录，是完全不同的两种东西。把这两者一视同仁的缓存，既浪费
内存也浪费请求。RecurseX 会测量每条 RRset 的可观测历史，让历史去驱动内部策略——预取时机、
serve-stale 意愿、准入、淘汰——而你返回给客户端的 TTL，仍然和权威说的一模一样。

核心预测回路（"PARR" 大脑，详见 `wiki/PARR.md`）：

```
Query State Estimator ──▶ Resolution Planner ──▶ Cache / Prefetch / Parallel ──▶ Adaptive Resolver
  popularity                serve vs stale          stability-aware tier          picks servers by
  temporal locality         vs prefetch vs resolve  background refresh            expected cost
  TTL behavior
```

## 功能清单

- **完整递归解析** —— root → TLD → 权威，支持 CNAME/DNAME 追踪、NS 委派、glue 和 bailiwick 过滤。
- **QNAME 最小化（RFC 9156）** —— 解析器不会泄露超出必要的 qname；对最小化前缀的空应答会继续
  加深查询，而不是直接终止。
- **EDNS(0)**：ECS（RFC 7871）、cookie、keepalive、NSID、padding。
- **0x20 随机化** + 事务 ID 校验，作为防缓存投毒的对抗手段。
- **多层语义缓存** —— hot / warm / cold + NXDOMAIN 存储。分数驱动准入（`CacheScore`）、
  serve-stale（RFC 8767）、预测式预取、CNAME 链追踪。
- **查询状态估计器** —— 每个域的时段（time-of-day）画像、短期 EWMA 速率、流行度、上游成本。
  内存有界。
- **解析图（Resolution Graph）** —— 跨查询追踪 `depends_on` / `delegates_to` / `cname_to` /
  `served_by` / `reachable_via`，让预取能沿整条依赖集发散。
- **自适应上游选择** —— 每个权威维护 EWMA RTT、丢包率和 SERVFAIL 率；按**期望解析成本**选路，
  而不是裸延迟。
- **加密传输** —— DoT（RFC 7858）、DoH（RFC 8484）、DoH3、DoQ 协议层（RFC 9250），
  由 `dot` / `doh` / `doh3` / `doq` feature 控制，基于 courierust。
- **转发（Forwarding）** —— UDP/TCP/DoT/DoH/DoH3/DoQ 转发器，先转发、失败再回退迭代。
- **DNSSEC**（`dnssec` feature）—— RRSIG 校验（RSA PKCS#1 v1.5 + SHA-256）、DS 摘要链、
  `Secure` / `Insecure` / `Bogus` 判定。
- **L3 持久化缓存**（`persist` feature）—— 用 rustbinary 序列化快照（稳定性模型、分数、层级
  在重启后不丢），原子写入，解码有界。
- **策略** —— 按客户端令牌桶限速、名称过滤、校验门禁。
- **no_std 核心** —— 线格式编解码、缓存、估计器、图、上游模型都可以不带 `std` 编译；
  联网解析器由 `std` 控制。

## 快速开始

```rust
use recurse_x::{Name, RrType, Resolver, ResolverConfig};

let resolver = Resolver::new(ResolverConfig::default());

let name = Name::from_ascii("ietf.org").unwrap();
match resolver.resolve(&name, RrType::A) {
    Ok(res) => {
        // res.answers, res.ttl, res.validated, res.from_cache ...
        for r in &res.answers {
            println!("{} {:?}", r.name, r.rdata);
        }
    }
    Err(e) => eprintln!("resolution failed: {e}"),
}
```

跑自带的在线检查（需要网络）：

```sh
cargo run --no-default-features --features std --example quick_check
```

它会走完整迭代管线解析几个名字两遍——第二遍应该命中缓存。已在真实 DNS 树上验证过
（example.com 约 127ms、google.com 首次约 3.2s、ietf.org 约 0.7s、`nonexistent.invalid`
约 23ms 返回 NXDOMAIN）。

### 客户端服务器

```rust
use recurse_x::{Resolver, ResolverConfig, Server};

let resolver = Resolver::new(ResolverConfig::default());
let server = Server::new(resolver);
let addr = server.bind_udp("127.0.0.1:5353".parse().unwrap())?;
server.bind_tcp("127.0.0.1:5353".parse().unwrap())?;
// dig @127.0.0.1 -p 5353 example.com A
```

### JSON 配置

整个解析器可以用一份 JSON 文档配置（nextjson）：

```json
{
  "listen": [{ "addr": "0.0.0.0:53", "proto": "udp" }],
  "cache": { "hotCapacity": 2048, "warmCapacity": 131072 },
  "engine": {
    "qnameMinimization": true,
    "use0x20": true,
    "dnssec": true,
    "forwarders": [
      { "proto": "dot", "ip": "1.1.1.1", "port": 853, "host": "cloudflare-dns.com" }
    ]
  },
  "persist": { "path": "/var/lib/recursex/cache.rxc", "saveIntervalMs": 60000 }
}
```

```rust
let cfg = recurse_x::config::Config::from_json_str(json)?;
let rc = cfg.into_resolver_config()?;
let resolver = Resolver::new(rc);
```

### 后台维护

```rust
let resolver = Resolver::new(ResolverConfig::default());
let _thread = resolver.spawn_maintenance(); // sweep + 图剪枝 + 预测式预取
```

维护循环会清扫死条目、剪掉解析图里的旧节点、按估计器候选做预测式预取。开了 `persist` 时，
还会按配置间隔写缓存快照。

## 值得知道的设计决策

- **TTL 是权威的。** 估计器和规划器永远不会改动你下发的 TTL，只调**内部**时机（何时刷新、
  是否给 stale、准入什么）。权威说 `300`，客户端拿到的就是 `300`。
- **准入看分数。** `CacheScore = α·popularity + β·locality + γ·stability + δ·ttl +
  ε·cost − ζ·memory`，默认 α=0.30、β=0.18、γ=0.20、δ=0.16、ε=0.11、ζ=0.05。低于
  `min_admit_score` 的条目根本不进缓存；hot 层只留给分数最高的一批。
- **稳定性是测出来的，不是猜的。** 每条 RRset 记录样本数、变更率、EWMA 稳定性、TTL EWMA 与
  波动、连续失败次数。非常稳定的集合走后台刷新；波动大的从不信任 stale。
- **淘汰是诚实的。** 每次淘汰按采样挑分数最低的条目（单次淘汰工作量有界），不是固定 LRU。
- **防欺骗是分层的。** 应答匹配校验 ID + 问题回显，默认开 0x20 随机化，glue/bailiwick 规则
  决定响应里哪些数据可以入缓存。
- **处处有界。** 估计器限制追踪域数、图限制节点数、缓存限制各层容量、合并器限制在途查询数、
  策略引擎限制客户端桶数。恶意查询流无法无界撑大内存。

## 诚实的局限

- **DNSSEC 范围**：RRSIG 校验实现了 RSA PKCS#1 v1.5 + SHA-256（从零手写的 limb 大数运算，
  不依赖外部密码库）。ECDSA 与 SHA-1 签名尚未支持。
- **DoQ 传输**：RFC 9250 的帧、会话语义和错误码都实现了，但 QUIC 连接本身走一个
  [`DoqProvider`](https://docs.rs/recurse-x/latest/recurse_x/transports/doq/trait.DoqProvider.html) trait——courierust 的 QUIC 传输藏在它的 HTTP/3 运行时后面，没有暴露裸连接，
  所以默认 provider 会如实报告 DoQ 不可用，而不是假装能用。接上 provider 即可用。
- **时间**：`tzcraft` 没有 IANA 时区库，所以估计器的时段画像用的是墙钟 UTC。
- **没有 DoH 服务端**：面向客户端的服务器只收普通 UDP/TCP。DoT/DoH/DoH3/DoQ 是上游传输。
- **首次 `cargo build` 需要网络**（要从 crates.io 拉 courierust 等依赖）。

## Feature 开关

| Feature   | 默认 | 作用                                        |
|-----------|------|---------------------------------------------|
| `std`     | 开   | 联网解析器、服务器、配置                     |
| `dot`     | 开   | DoT 上游传输（courierust TLS）              |
| `doh`     | 开   | DoH 上游传输（courierust HTTP 客户端）      |
| `doh3`    | 开   | DoH3 上游（隐含 `doh`）                     |
| `doq`     | 关   | DoQ（RFC 9250）协议层                       |
| `dnssec`  | 开   | DNSSEC 校验                                 |
| `persist` | 开   | rustbinary 支撑的 L3 持久化缓存             |

算法核心（`--no-default-features`）是 `no_std` + `alloc`。

## 测试

```sh
# 全 feature 全量测试
cargo test --features std,dot,doh,doh3,doq,dnssec,persist --lib

# no_std 核心构建
cargo build --no-default-features

# 严格 lint
cargo clippy --features std,dot,doh,doh3,doq,dnssec,persist --all-targets -- -D warnings
```

共 124 个测试：线格式编解码、缓存/稳定性/准入、估计器、规划器、图、上游模型、策略、引擎分类、
解析器编排、服务器、JSON 配置回环、加密传输、DNSSEC（含一个用 openssl 真实生成的 1024 位 RSA
测试向量），以及持久化缓存（回环、stale 归位、死条目丢弃、篡改拒绝）。

## License

Apache-2.0。
