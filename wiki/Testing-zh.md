# 测试与验证

## 命令

```sh
# 全 feature 全量测试
cargo test --features std,dot,doh,doh3,doq,dnssec,persist --lib

# no_std 核心仍能构建
cargo build --no-default-features

# 严格 lint（警告即错误）
cargo clippy --features std,dot,doh,doh3,doq,dnssec,persist --all-targets -- -D warnings
```

## 130 个测试覆盖了什么

- **线格式编解码**（`message`、`rdata`、`name`、`qtype`、`edns`）—— 解析/序列化回环、
  名字压缩、截断、错误应答、NSEC 位图、EDNS 选项。
- **缓存** —— 跨层插入/查找、CNAME 链、serve-stale、NXDOMAIN 存储、ECS 分区、淘汰、
  预取候选、清扫。
- **稳定性与准入** —— EWMA 数学、指纹与 TTL 无关、分数阈值。
- **估计器 / 规划器 / 图 / 上游** —— 概率增长、时段画像形状、内存有界、图剪枝、成本排序。
  估计器还拿参考值验证自带的 `exp` 和取整。
- **策略** —— 限速、过滤、令牌桶。
- **引擎与解析器** —— 应答分类（answer / NXDOMAIN / NODATA / referral / empty）、QNAME
  最小化步骤、负 TTL 规则、服务器绑 UDP 和 TCP 并应答。
- **配置** —— JSON 回环、最小文档、转发器默认端口。
- **加密传输** —— DoT/DoH/DoH3/DoQ 协议行为（帧、错误码、QUIC 包/加密/ACK 与 TLS
  握手的单测；DoQ 的 QUIC-TLS 客户端还用本地 courierust HTTP/3 服务器做了含
  Retry + 完整握手 + 1-RTT 的互操作验证）。
- **DNSSEC** —— 一个 openssl 真实生成的 1024 位 RSA/SHA-256 向量能验过；改摘要或改签名都
  失败；DNSKEY 解析边界（零长度 → 4 字节指数）。
- **持久化** —— 回环、stale 归位 cold、死条目丢弃、ECS 存活、篡改拒绝、原子写。

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
- `no_std` 构建纳入验证流程，核心不会偷偷长出 `std` 依赖。
