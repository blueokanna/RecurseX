# DNSSEC

`dnssec` feature 校验应答链：对规范化 RRset 的 RRSIG 签名、从信任锚往下走的 DS 摘要链，
以及 `Secure` / `Insecure` / `Bogus` 判定。校验刻意自包含——允许的依赖集里没有通用密码库，
所以 RSA 校验是手写的。

## 校验什么

- **RRSIG（RFC 4034 §3.1.5）** —— 规范化 RRset（owner 名小写、RR 排序、原始 TTL）、SHA-256
  摘要，用签名者 DNSKEY 验证。
- **DS（RFC 4034 §5.1）** —— DS 摘要是对「规范化 owner 名 + DNSKEY RDATA」做 SHA-256，
  必须与父区的 DS 记录匹配。
- **链走查** —— 从该区 DNSKEY 沿 DS 链上溯到信任锚，带递归保护。

判定：`Secure`（校验通过）、`Insecure`（确认无安全链）、`Bogus`（签名或链失败）、
`Indeterminate`（无法确认）。

## RSA 实现

`dnssec/rsa.rs` 用从零写的 u32-limb 大整数（平方-乘模幂、逐位长除取模）实现 RSA PKCS#1 v1.5
验签，加 RFC 3110 DNSKEY RSA 解析。指数长度是一个字节；**该字节为 0 时，长度是紧随其后的
两个字节**（RFC 3110 §2）——超过 255 字节的指数只能用这种三字节形式表达，此时指数从
偏移 3 开始而不是偏移 1。测试套件里有一个用
**openssl 真实生成的 1024 位 RSA/SHA-256 向量**——不是造出来的常量——外加对摘要和签名的篡改
检查。

验签是**对攻击者输入的全定义函数**：DNSKEY（中间人可重放的公开数据）和签名（由攻击者自选）
都来自网络，所以畸形的 key 或签名一律返回 `false`，**绝不 panic**。
`tests/parser_robustness.rs` 用空签名、零模数、声明长度超过 key 的指数等退化形状把这套契约锁住。

## 诚实的边界

- 实现了 RSA PKCS#1 v1.5 + SHA-256。ECDSA 与 SHA-1 签名能识别但尚未校验，所以依赖它们的链
  报告为 `Indeterminate`，绝不会误报 `Secure`。
- 编码消息的检查是严格的：完整的 DigestInfo 前缀、精确的摘要，以及 RFC 8017 §9.2 要求的至少
  8 个 0xFF 填充字节——小指数伪造无法从一个过短的填充段里钻过去。
- 请求 DNSSEC 时尊重 `do` 位；解析器把 RRSIG 和 RRset 一起存，校验过的数据在缓存命中时保持
  校验状态，`validated` 标志能跨持久化保留。

## 激进缓存

缓存按 RFC 2308 用 SOA 推导的 TTL 存负应答，这是激进 NSEC/NSEC3 缓存的基座；NSEC 位图的
解析/序列化在编解码器里。
