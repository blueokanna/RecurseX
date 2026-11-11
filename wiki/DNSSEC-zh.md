# DNSSEC：局部验签与信任边界

版本：**0.2.6**。

当前实现 RSA/SHA-256 验签（算法 8）、SHA-256 DS 匹配及 RRset 规范化。
这还不是完整的 DNSSEC 验证解析器：没有安装根信任锚，没有完成父区 DS 的认证链，
没有 NSEC/NSEC3 否定证明和通配符展开证明。ECDSA 13/14、EdDSA 15/16 只识别，尚不验证。

| 结果 | 本版本语义 |
|---|---|
| `SignatureValid` | 签名与取回或传入的密钥在数学上相符，但密钥身份未经认证。 |
| `Indeterminate` | 缺证据、算法不支持、没有可信否定证明的未签名数据，或未支持的通配符证明。 |
| `Bogus` | 受支持且适用的签名未通过局部校验；不代表已经证明该区属于安全委派。 |
| `Insecure` | 为已认证的未签名委派保留；当前验证器不会产生此结果。 |

`Verdict::Secure` 保留为已弃用的兼容常量，等价于 `SignatureValid`，新代码应使用明确名称。
`CryptoVerified` 仅表示局部验签；`ChainAnchored` 要求完整信任链，当前验证器不产生它。
旧的 `anchored` 布尔参数不能提升验证等级。

`checked_signature_state()` 返回局部验签结果。解析器用 `checked_authentication()`
决定 `Resolution.validated` 与缓存信任，因此局部成功仍然 `validated=false`，响应不置 AD。
历史字段 `answer_groups_authenticated`、`authority_authenticated` 统计的是局部验签，
不是可信链。所有 owner/type/class 分组都计入，包括没有签名的分组。

验签入口检查 DNSKEY 的 owner、class、protocol=3、zone-key 标记；每个数据记录必须与
RRSIG 的 owner、type、class 一致，signer 必须覆盖 owner。DS 匹配检查所属名称、类别、
记录类型、key tag 和摘要；匹配未经认证的 DS 仍然不建立信任锚。
解析器不再为了给局部验签更强的名称而额外查询 DS。

规范化排序按 RDATA 字节进行，不把 RDLENGTH 当排序依据。签名时间使用 32 位序列号运算，
支持回绕，拒绝跨度达到半个序列空间的歧义窗口。通配符展开缺少否定证明时返回无法判定，
不会把有效通配符错误归为签名损坏。

DNSKEY 子查询在当前线程跳过嵌套验证以限制递归；线程局部保护不会使其他工作线程漏检。
无效签名在缓存准入前拒绝，缓存重用时重新检查；不支持和证据不足均保留无法判定状态。

若应用要求经过信任链认证的答案，当前局部验证器不能满足该要求。
可以配置验证型上游，但 RecurseX 不把上游的 AD 位当作本地完成的信任链。

规范：[RFC 4034](https://www.rfc-editor.org/rfc/rfc4034)、
[RFC 4035](https://www.rfc-editor.org/rfc/rfc4035)。
