# RecurseX

[English](README.md) · [接口文档](https://docs.rs/recurse-x) · [验收记录](docs/refresh-validation.md)

RecurseX 是 Rust 实现的递归 DNS 解析器，包含委派走查、语义缓存、请求合并和受预算约束的后台刷新。
正常应答遵守权威 TTL。变化模型用于刷新排序；过期服务默认关闭。

## 解析与缓存

- 支持 UDP/TCP 客户端请求、QNAME 最小化、CNAME/DNAME 追踪、bailiwick 过滤和 ECS 分区。
- 上游支持 UDP、TCP、DoT、DoH、DoH3 和 DoQ。UDP 转发收到 TC 后向同一上游重试 TCP。
- Hot、Warm、Cold 三层缓存与独立 NXDOMAIN 存储均有容量限制。
- 相同查询合并到同一个在途解析。容量耗尽时拒绝新键，保留现有所有者与等待者。
- 提供 hosts、Fake-IP、域名路由、回退过滤和可选的磁盘快照。

配置了转发器后，上游失败会返回错误，不会悄悄切换为根递归。回退过滤已经判为可疑的主应答，
也不会在备用上游失败后被重新放行。

## 刷新与风险边界

每个缓存条目最多有一个到期索引节点。维护循环默认每轮检查至多 256 项，只在短锁内复制键、版本、
过期时间和模型标量；估计器查询与 VoI 评分在缓存锁外执行。提交任务时重新检查版本、存活状态和刷新所有权。
固定工作池限制排队与运行中的任务总数；拒绝、失败和异常退出都会释放资源。

刷新优先级使用“预计服务收益 + 预计风险下降”除以预计实际成本。这是分配资源的启发式，不是全局最优算法。
调度次数预算、后台 exchange/字节预算、每上游并发与速率限制，以及单次解析预算共同约束工作。
嵌套 DNSKEY/DS 查询共享调用者的发送额度和截止时间。字节记账覆盖 DNS 负载，不包括 TLS、HTTP、IP 开销或失败的部分读取。

`Provenance::bound()` 保留最弱依赖的诊断语义；完整答案使用：

```text
P(所有依赖同时新鲜) >= max(0, 1 - sum(1 - p_i))
```

两个 0.99 的依赖只能给出 0.98 的联合下界。所有节点，包括 proof，都受容量限制；裁剪保留失败概率之和、
最严格后果等级与禁止 stale 的属性。容量为零时这些限制也不会丢失。

这条组合公式以有效的边际下界为前提。当前 Gamma 更新把二元区间观测近似为事件计数，
并非该似然的精确共轭后验；Gamma 分布上的 Chernoff 界不能证明真实 DNS 数据的覆盖率。
两次内容相同，也无法排除中间发生过 A→B→A。

`stalePolicy` 有三种取值：

| 策略 | 行为 |
| --- | --- |
| `disabled` | 默认值，拒绝过期服务 |
| `on-refresh-failure` | 先尝试本次上游刷新，失败后评估过期副本 |
| `immediate-experimental` | 显式启用立即返回过期数据的实验策略 |

放行仍需满足后果等级、证据与风险预算检查。过期应答使用正 TTL，默认 30 秒。
在线校准记录模型更新前的预测与刷新后的内容比较；失败不能记成“未变化”，校准也不能代替真实性验证。

## 加密上游与 DNSSEC

加密上游默认验证证书。JSON 配置通过 `forwarderCaFile` 装载 PEM 信任根；库调用者可使用
`EngineConfig::forwarder_roots` 或 `Resolver::set_forwarder_roots(roots, true)`。空信任根拒绝连接。

DoT/DoQ 可以分别指定连接 IP 和 TLS 主机名。courierust 1.1.1 的 HTTP 客户端无法分别指定这两个值，
因此 DoH/DoH3 的 `host` 必须是与 `ip` 相同的 IP 字面值，并由证书中的 IP 身份认证。
无法保证指定 IP 的配置在加载时明确拒绝；HTTP 重定向也不会跟随。请求和响应使用 `application/dns-message`。

传输的 `now = 0` 使用实时证书时钟。DoH/DoH3 在校验秒值变化时重建现有客户端，避免长期沿用启动时间；
同一校验周期内继续复用 courierust 的连接池。这会缩短连接保留时间，不能作为性能提升来宣传。
HTTP 阶段超时仍受依赖的阻塞 I/O 语义约束，代码不能抢占已经进入依赖内部的调用。

DNSSEC 检测到无效签名时会拒绝答案，缓存命中与 stale 回退也会检查。验证递归保护限于当前线程，
一个工作线程的验签不会跳过其他线程的检查。快照恢复会清除保存的验证标记。

**完整的根信任锚到答案的验证链尚未实现，AD 位保持关闭。** 当前验证器支持 RSASHA256；
ECDSA/EdDSA 尚未实现验证，NSEC/NSEC3 否定证明也未完成。`dnssec_anchored` 布尔值不能提升信任状态。

## 构建与配置

MSRV 为 Rust 1.78。当前使用 crates.io 正式版本：courierust 1.1.1、nextjson 0.1.5、tzcraft 0.1.2、rustbinary 0.1.10。
不包含本地依赖副本。`std` 构建统一使用系统密码学随机源；获取随机源失败时不会使用哈希值或时间生成密钥。

```powershell
cargo build --release --all-features --locked
cargo test --all-features --locked
cargo test --no-default-features --locked
cargo clippy --all-features --all-targets --locked -- -D warnings
```

默认特性包括 `std`、`dot`、`doh`、`doh3`、`doq`、`dnssec`、`persist`。
关闭默认特性可构建 `no_std + alloc` 算法核心；联网与服务端需要 `std`。

下面的路径需替换为部署环境内实际存在的 PEM 文件和可写目录：

```json
{
  "listen": [{ "addr": "127.0.0.1:5353", "proto": "udp" }],
  "forwarderCaFile": "/etc/ssl/certs/ca-certificates.crt",
  "stalePolicy": "disabled",
  "engine": {
    "forwarders": [
      { "proto": "dot", "ip": "1.1.1.1", "port": 853, "host": "cloudflare-dns.com" }
    ]
  },
  "persist": { "path": "/var/lib/recursex/cache.rxc", "saveIntervalMs": 60000 }
}
```

快照读取在解码前限制文件大小，并限制解码 token、集合、深度和工作量。恢复检查记录所属键、ECS 分区与容量。
保存使用独占创建的临时文件、文件同步和原子替换；Windows 对短暂占用执行有界重试，Unix 同步父目录。
缓存文件及其所在目录应由部署账户控制。

## 验证范围

测试覆盖本地 UDP/TCP 解析、DNSSEC 拒绝路径、TLS 身份失败、HTTP/2 与 HTTP/3 连接复用、
慢速响应、资源回收和并发快照保存。详细命令、计数与限制见[验收记录](docs/refresh-validation.md)。
这些测试不等同于公网互操作性、长期稳定性或吞吐量证明。

已有离线微基准证明刷新检查量有界、持锁时间缩短，但缓存查询 p99 没有改善。
真实请求回放、固定资源下的 CPU/RSS 与网络成本对比仍待完成。设计历史和推导可继续参考 paper 与 wiki；
当前行为与验证结论以实现、测试和验收记录为准。

许可证见 [LICENSE](LICENSE)。
