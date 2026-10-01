# 部署与加固

## 跑起来

面向客户端的 `Server` 绑定 UDP 和 TCP（普通 DNS）。JSON 配置（`config::Config`）覆盖监听地址、
缓存大小、引擎行为、策略、转发器和持久化。最小部署示例：

```json
{
  "listen": [{ "addr": "0.0.0.0:53", "proto": "udp" }],
  "cache": { "hotCapacity": 2048, "warmCapacity": 131072 },
  "engine": {
    "qnameMinimization": true,
    "use0x20": true,
    "dnssec": true
  },
  "persist": { "path": "/var/lib/recursex/cache.rxc", "saveIntervalMs": 60000 }
}
```

实际部署时 UDP 和 TCP 都绑同一端口：一个 listen 条目 + 对同端口再调 `Server::bind_tcp`。

要跑 `spawn_maintenance()`，清扫、图剪枝、预测式预取才会发生，持久层才会按计划落盘。

## 停下来

服务器和解析器都有停止路径，部署时应该用它：不走这个路径地丢进程，`persist` 快照会停留在最多
一个 `saveIntervalMs` 之前，连接状态则交给 OS 收尾。

```rust
// SIGTERM 处理，或者 main 的结尾：
server.shutdown();      // 所有循环在 100 ms 内停下
resolver.shutdown();
server.join();          // 线程退出后返回
```

停止是一个标志、不是一个信号：UDP 接收循环靠套接字超时醒、处理池靠队列超时醒、TCP accept 靠
自连接释放（所以不用等真实客户端）、每个连接读取循环靠自己套接字超时醒。维护循环把长睡眠切成
不超过 100 ms 的片段，并在退出前写下最后一份快照 —— 于是下次启动总能从新文件恢复，即使上一次
计划落盘还没触发。

面向客户端还有两条保护线程预算的边界：

- **TCP 空闲超时**（`tcp_idle_timeout_ms`，默认 30 秒）：两条报文之间什么都不发的连接会被关掉
  （RFC 7766 第 6.2.3 节推荐的正是在这个位置这么做，而不是永久占着一个空闲客户端）。
- **报文截止时间**：每次只滴一个字节的客户端也不能靠慢滴拖住读取循环，因为报文内的截止时间取
  `min(10 秒, 空闲超时)`。

## 安全模型

- **限速**：按客户端 IP 的令牌桶（`client_qps` / `client_burst`），桶表有界——伪造源地址的
  洪泛撑不大内存。
- **防欺骗**：每个上游应答都对查询做校验——事务 ID **和**问题回显；而 ID 与 0x20 大小写来自一个
  **ChaCha20 计数器模式 CSPRNG**，不是一个快但非密码学的混合器。RFC 5452 §9.2 明说此处 ID 的
  可猜性就是安全参数：可预测的生成器会让 65536 个 ID 和端口空间变成装饰。生成器每产出 1 MiB
  密钥流（`DEFAULT_REKEY_BYTES`）就重新上键——按**量**而非按**次数**封顶，因为按次数只间接封顶，
  而且对 0x20 密集的流量封得还不一样。非密码学混合（SplitMix64）仍用在猜测对攻击者毫无收益的
  地方——淘汰采样与测试夹具——并在文档里写明这一点。
- **Bailiwick 纪律**：应答里只有区内数据可以入缓存。区外 glue 只临时用，绝不作为权威缓存。
- **DNSSEC**：开了 `dnssec` 后应答会被放到一条四态阶梯上——`Indeterminate`（没有可用信任锚或
  签名）、`Insecure`（已验证为未签名）、`CryptoVerified`（签名验过，但 DS 链未锚定）、
  `ChainAnchored`（链已到达配置的信任锚）。只有最后一个状态才置 `AD`，因为只有它是在对**委派链**
  做声明，而不是仅仅对这条报文里的字节做声明。
- **过滤**：策略 `block` 规则丢弃所列名下的查询。

## 运维要点

- UDP 传输校验每个应答的源地址；Windows 上「已连接」UDP socket 报 connection reset 按瞬态
  处理（那是 OS 暴露 ICMP 错误的方式），不是致命的连接状态。
- 超时：每服务器尝试预算 + 全局尝试预算，兜住病理区的最坏情况；`timeout_ms` 限制每次交换。
- 缓存命中不阻塞上游；未命中和 stale 刷新走合并器，并发的重复查询共享同一次上游交换。

## 信任它之前要知道的边界

- DoT/DoH/DoH3/DoQ 是**上游**传输；面向客户端的服务器是普通 UDP/TCP。要加密客户端传输，
  请在前面挂 TLS 终结。
- DoQ 自带从零实现的 RFC 9250 客户端（QUIC v1 + QUIC-TLS 1.3）作为默认传输，
  开箱即可加密上游转发；仍可通过 `DoqProvider` trait 插入自定义 QUIC 栈。
- DNSSEC 是 RSA/SHA-256；ECDSA 链解析为 `Indeterminate`。
