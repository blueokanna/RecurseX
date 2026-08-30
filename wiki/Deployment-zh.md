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

## 安全模型

- **限速**：按客户端 IP 的令牌桶（`client_qps` / `client_burst`），桶表有界——伪造源地址的
  洪泛撑不大内存。
- **防欺骗**：每个上游应答都对查询做校验——事务 ID **和**问题回显。0x20 随机化（`use0x20`）
  在 qname 里加每查询熵，让盲目缓存投毒明显更难。
- **Bailiwick 纪律**：应答里只有区内数据可以入缓存。区外 glue 只临时用，绝不作为权威缓存。
- **DNSSEC**：开了 `dnssec` 后应答会被校验并标记；`Bogus` 数据不会被当作安全数据给出。
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
