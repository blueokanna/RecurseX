# 架构

RecurseX 是流水线，不是一坨。每层只干一件事，通过窄接口往下传，所以算法核心是 `no_std`，
联网部分隔离在 `std` feature 后面。

| # | 架构层 | 主要文件 / 模块 | 核心职责 |
|---:|---|---|---|
| **1** | **客户端层** | `server.rs` | UDP/TCP 监听<br>按查询构造应答 |
| **2** | **查询处理** | `query.rs`<br>`policy.rs` | Normalize（规范化）<br>请求去重（Dedup）<br>请求合并（Coalesce）<br>0x20 编码<br>速率限制（Rate Limit） |
| **3** | **多层缓存** | `cache/`<br>`stability.rs`<br>`cache/score.rs`<br>`cache/persist.rs` | Hot / Warm / Cold + NXDOMAIN<br>缓存稳定性模型<br>分数准入（Score Admission）<br>过期缓存服务（Serve-stale）<br>预取（Prefetch）<br>L3 持久化 |
| **4** | **解析引擎** | `resolver.rs`<br>`engine.rs`<br>`dnssec/` | Root → TLD → 权威服务器<br>CNAME / DNAME<br>委派（Referrals）<br>DNSSEC 校验 |
| **5** | **上游传输** | `transport.rs`<br>`transports/`<br>`forward.rs` | `DnsTransport` Trait<br>UDP / TCP / DoT / DoH / DoH3 / DoQ<br>转发器（Forwarder） |
| **6** | **安全 / 策略** | `policy.rs`<br>`query.rs`<br>`dnssec/` | 限速（Rate Limit）<br>过滤（Filtering）<br>防欺骗校验（Anti-spoofing）<br>DNSSEC 判定（Verdict） |

## 一次递归查询的数据流

1. **客户端层**收到线格式报文（UDP 数据报或 TCP 流），由 `message.rs` / `rdata.rs` /
   `name.rs` 的编解码器解析。
2. **查询处理**规范化 qname（小写、去尾点）、合并并发相同查询（条件变量等待的合并器）、
   按客户端限速，构造 `QueryKey`（name、type、class、ECS 分区、DNSSEC 标志）。
3. **缓存**先行。新鲜命中立刻带剩余 TTL 返回；过期但在窗口内的条目可以 serve-stale
   （RFC 8767）同时触发后台刷新；未命中进入引擎。
4. **解析引擎**沿树走。从根提示开始，一级级跟委派，做 QNAME 最小化（RFC 9156）、
   追 CNAME/DNAME、过滤 bailiwick 外数据，（开了 `dnssec` 时）校验应答链。
5. **上游传输**按所选协议发线格式查询。UDP 截断回退 TCP；加密传输按 feature 隔离。
6. **安全/策略**穿插其中：入口限速、引擎层应答匹配（ID + 问题回显）、缓存时 bailiwick
   规则、最后 DNSSEC 判定。

所有碰时间的层都走 `Clock` trait（`time.rs`），所以整条流水线在测试/仿真里可以用手动时钟驱动。

## no_std 边界在哪

`--no-default-features` 只构建线格式编解码、缓存、估计器、图、上游模型、策略和规划器
（仅 `alloc`）。socket、线程、解析器、服务器、JSON 配置、加密传输都是 `std` 门控。
no_std 核心让预测机制可以移植到只要「模型」不要「网络」的嵌入式目标。

## 错误模型

一个 `Error` 类型（`error.rs`），带 `kind`——wire、protocol、internal、transport、io、
config。解析器在客户端边界把失败映射成 DNS 应答（SERVFAIL），内部错误不泄露线格式细节。
