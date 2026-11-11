# DNSSEC 根信任链认证

通过 `{"engine":{"dnssec":true}}` 开启验证，最低 Rust 版本保持 **1.78**。
ring 0.17.14 提供密码学验签，DNS 请求继续使用 RecurseX 自己的路由、传输和预算。

## 认证流程

默认根锚包含 IANA 的 20326（KSK-2017）和 38696（KSK-2024，2026 年 10 月启用）。
先用根锚匹配的密钥认证根 DNSKEY RRset，再逐级认证父区 DS、匹配子区 DNSKEY、
认证完整子区密钥集合，最后验证答案及所需否定证明。支持轮换期多个 DS/DNSKEY 和 KSK/ZSK 分离。

| 判定 | 行为 |
| --- | --- |
| `ChainAnchored` | 答案、权威记录和所需证明全部认证，`Resolution.validated=true`。 |
| `Insecure` | 已认证的未签名委派、NSEC3 opt-out，或仅包含不支持算法/摘要的已认证 DS；返回答案但不置 AD。 |
| `Indeterminate` | 缺少锚或证明、资源耗尽等；开启验证时返回 `ErrorKind::Dnssec`。 |
| `Bogus` | 签名无效/过期、安全区缺签名、断链或否定证明不成立；拒绝答案准入。 |

`SignatureValid`、`CryptoVerified` 只表示局部密码学验证。
旧 `dnssec_anchored` 布尔值和已弃用的 `Verdict::Secure` 别名不能提升信任。

## 已实现范围

- 验签算法：RSA/SHA-256（8）、RSA/SHA-512（10）、ECDSA P-256（13）、P-384（14）、Ed25519（15）。
- DS 摘要：SHA-256（2）、SHA-384（4）；检查名称、class、协议、zone-key/revoke 标志、算法和 key tag。
- RRset 规范化、排序去重、通配符名称重建、32 位签名时间回绕。
- NSEC/NSEC3 的 NXDOMAIN、NODATA、closest-encloser、通配符、无 DS 证明和 opt-out。
- CNAME 链及已认证 DNAME 推导的 CNAME；不安全链路会阻止整个答案设置 AD。
- 仅完整认证成功、CD 关闭且客户端请求 AD/DO 时设置 AD。不信任上游自行给出的 AD。
  CD 请求可获取未验证数据但不能获得 AD；普通非 DO 应答不附带 DNSSEC 否定证明和签名。

## 缓存与资源边界

完整响应和证明使用私有的 256 项有界缓存，仅保存未过期证据，材料认证后才准入。
重用时重新检查签名和链路；普通缓存或快照里的 `validated` 标志不能替代证明。
否定和通配符答案保留完整权威证明，响应 TTL 不超过认证链和签名有效期。

DNSKEY/DS 子查询共享原请求的网络额度、隐私策略和截止时间，并绕开客户端请求合并，
防止查询等待自身。为获取证明而查询的 NS 地址只是路由提示，不递归启动验签，
也不作为已认证答案写入客户端缓存。

每次验证最多 128 次材料查询、128 次候选密钥验签、每组 8 个候选签名、
每组 64 个 DNSKEY、每份证明 64 条否定记录。NSEC3 上限为 150 次迭代和每份证明
10,000 轮哈希；查询总预算可以更早终止。超过限制拒绝验证，不降级为安全答案。

## 信任锚配置

省略 `dnssecTrustAnchors` 使用默认根锚；显式数组替换整个集合，空数组无法建立信任。

```json
{
  "engine": {
    "dnssec": true,
    "dnssecTrustAnchors": [{
      "name": ".",
      "keyTag": 38696,
      "algorithm": 8,
      "digestType": 2,
      "digest": "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16"
    }]
  }
}
```

库调用者可通过 `EngineConfig::dnssec_trust_anchors` 提供 DS 或 DNSKEY `Record`，
包括私有区信任锚。未编译 `dnssec` 特性时，启用验证的配置会明确报错。

根锚属于静态配置，**未实现 RFC 5011 自动信任锚维护**；未来轮换需要通过可信软件或配置
更新完成。Ed448 和已弃用算法不产生安全判定，资源限制会拒绝超出上限的查询。
当前实现尚未经过独立安全审计，本地签名测试不等于所有公网权威服务器的互操作认证。

## 测试

`tests/dnssec_chain.rs` 覆盖签名根/TLD/子区、KSK/ZSK、轮换、五种算法、缓存、
否定证明、通配符、别名、AD/CD、篡改、过期及预算。
`tests/dnssec_fail_closed.rs` 覆盖缓存和转发中的无效签名拒绝。
CI 在 Rust 1.78/stable、Linux/Windows 矩阵内运行，并单独验证 `dnssec` 特性构建。
所有这些测试都不依赖公网 DNS。

标准和英文细节见 [DNSSEC](DNSSEC.md)，根锚信息见
[IANA](https://www.iana.org/dnssec/files)。
