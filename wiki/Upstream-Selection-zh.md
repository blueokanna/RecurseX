# 上游选择成本模型

按裸 RTT 挑权威服务器是错的。一台 92% 时间都很快的服务器，把重传和 SERVFAIL 罚分算进去后，
**期望上**可能比一台稍慢但从不失败的服务器更贵。

## 每权威路径模型

每个 `(权威, 端点)` 对都带一个小统计模型：

- EWMA RTT 与 RTT 方差；
- 丢包计数与 SERVFAIL 计数；
- 跟踪路径数有上限（`bounded_paths`）。

## 期望解析成本

选路按

```
cost = rtt_ewma + conn_setup + loss_penalty + failure_penalty
loss_penalty    = RTO · p_loss / (1 − p_loss)
failure_penalty = RTO · p_servfail · 1.5
```

`p_loss` / `p_servfail` 是平滑过的失败概率，`RTO` 是重传预算。未知路径给一个中性先验
（100ms 一跳加传输建立），并**略微优先**，好让它们被探测——否则一台新的、可能更好的服务器
永远学不到。

## 反馈

每次交换都回填 `record_success` / `record_timeout` / `record_servfail`。开始失败的服务器积累
罚分，恢复的按 EWMA 衰减回去。解析器只在交换预算内查询达标的服务器，`max_servers_tried` 和
`max_total_attempts` 兜底，病理区烧不穿整个请求超时。

## 传输建立

不同协议建立成本不同（`Udp`、`Tcp`、`Tls`/DoT、`DoH`、`DoH3`、`DoQ`）。TCP 和 TLS 要付握手，
UDP 不付——这也是引擎偏好 UDP、只在截断时回退 TCP 的原因之一。
