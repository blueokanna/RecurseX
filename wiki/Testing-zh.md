# 测试与验证

## 命令

```sh
# 全量：单测 + 集成测试 + 文档测试
cargo test --all-features

# 算法核心（含它自己的测试）是 no_std
cargo test --no-default-features --lib

# 严格 lint（警告即错误）
cargo clippy --all-targets --all-features -- -D warnings
```

## 测试覆盖了什么

套件共 159 个单测、`tests/` 下 7 个集成测试、4 个文档测试，而且是**自洽的**：任何需要上游的
测试都拿到一个本地桩服务器，所以 `cargo test` 不依赖公网（也不依赖公网延迟）。一个去问真实根
服务器的测试是脆弱的测试 —— 它报告的是网络状况，不是解析器状况。

- **线格式编解码**（`message`、`rdata`、`name`、`qtype`、`edns`）—— 解析/序列化回环、
  名字压缩、截断、错误应答、NSEC 位图、EDNS 选项。
- **缓存** —— 跨层插入/查找、CNAME 链、serve-stale、NXDOMAIN 存储及其容量、ECS 分区、
  精确淘汰最低分、预取候选、清扫。
- **稳定性与准入** —— EWMA 数学、指纹与 TTL 无关、分数阈值、内存项（它必须真的影响分数）。
- **估计器 / 规划器 / 别名图 / 上游** —— 概率增长、时段画像形状、内存有界、别名边双向查询与
  剪枝、成本排序、超时也会建立路径模型。估计器还拿参考值验证自带的 `exp` 和取整。
- **策略** —— 限速、过滤、令牌桶。
- **引擎与解析器** —— 应答分类（answer / NXDOMAIN / NODATA / referral / empty）、QNAME
  最小化步骤、负 TTL 规则、请求合并（含 owner 消失却不发布的场景）、CNAME 到别名边的接线、
  AD/CD 应答标志，以及服务器面对桩上游的 UDP 与 TCP 路径。
- **配置** —— JSON 回环、最小文档、转发器默认端口。
- **加密传输** —— DoT/DoH/DoH3/DoQ 协议行为（帧、错误码、QUIC 包/加密/ACK 与 TLS
  握手的单测；DoQ 的 QUIC-TLS 客户端还用本地 courierust HTTP/3 服务器做了含
  Retry + 完整握手 + 1-RTT 的互操作验证）。
- **DNSSEC** —— 一个 openssl 真实生成的 1024 位 RSA/SHA-256 向量能验过；改摘要或改签名都
  失败；DNSKEY 解析边界（零长度 → 4 字节指数）。
- **持久化** —— 回环、stale 归位 cold、死条目丢弃、ECS 存活、篡改拒绝、原子写。
- **服务端生命周期** —— 每个循环都能被叫停：UDP 接收循环、处理线程池、TCP accept 循环、
  每连接的读取循环、维护线程，都在测试里带看门狗启动并停止；空闲连接（或每次只滴一个字节的
  连接）会被关上，而不是永久占住一个线程。

## 集成测试（`tests/`）

这些测试按嵌入者的方式使用 crate —— 只用公开 API，不碰内部：

- `end_to_end.rs` 从 JSON 文档搭出解析器，在 0 端口绑 UDP 与 TCP 监听，直接在网上查询两者，
  断言第二次查询由缓存回答且不产生新的上游查询；从 `persist` 快照"重启进程"（并断言重启
  不需要网络）；跑一遍配置好的转发器；最后用 `Server::shutdown`/`Resolver::shutdown` 带看门狗
  停掉全部东西。
- `wire_robustness.rs` 是解码器的对手：20000 个确定性伪随机缓冲区（SplitMix64 定种，失败可
  复现），其中一半带上了看似合理的 header 计数；恶意计数字段；压缩指针成环；一个合法报文的
  每一个截断边界。它断言解析器绝不 panic、凡是被接受的输入重新编码后仍能被接受，且
  `truncate_for_udp` 绝不超出给定上限、同时保住问题段并置 TC。

## 在线验证

`examples/quick_check.rs` 走完整迭代管线把 `example.com`、`www.example.com`、`google.com`、
`ietf.org`、`nonexistent.invalid` 各解析两遍（第二遍必须命中缓存），然后打印统计：

```sh
cargo run --no-default-features --features std --example quick_check
```

健康的一次运行应解析出全部四个真实名字、对非法名返回 NXDOMAIN；`ietf.org` 走的是区外 NS 路径
（afilias-nst.info），也是能抓住 QNAME 最小化回归的用例——对最小化前缀的 NODATA 必须加深查询，
而不是直接终止。

## 为什么这些数字可信

- 没有造出来的测试向量：RSA 向量用 openssl 生成，并用独立 Python 实现交叉验证。
- 在线名字是对着真实 DNS 树解析的，不是 mock。
- `no_std` 核心在 CI 里不仅构建，还跑它自己的测试，所以核心不会偷偷长出 `std` 依赖。
- CI 在 MSRV（1.78）与 stable、Linux 与 Windows 上都跑，并带 `RUSTFLAGS=-D warnings`；发行用的
  release profile（fat LTO、单个 codegen unit）也一并测试，因为那才是真正发出去的东西。
