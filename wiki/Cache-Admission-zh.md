# 缓存准入与稳定性数学

缓存是**语义化**的：键是 `(name, type, class, ECS 分区)`，不是原始报文，所以同名下的 CNAME 链和
NXDOMAIN 住在不同结构里。条目分 hot / warm / cold 三层，外加按名的 NXDOMAIN 存储。

## 稳定性模型

TTL ≠ 数据稳定性。每条 RRset 都带一个 `StabilityModel`：

- `samples` / `changes` —— 刷新过几次、其中几次数据变了；
- `stability` —— `[0,1]` 的 EWMA：未变的刷新把分数拉向 1（α=0.2），一次变更狠狠拉向 0（α=0.4）；
- `change_ratio` —— 长期 `changes / samples`；
- `ttl_ewma` / `ttl_volatility` —— 权威 TTL 的 EWMA 和它的偏离；
- `consecutive_failures` / `failures` —— 距上次成功以来的刷新失败。

内容身份是对 RRset 排序后的线格式做指纹（TTL 字段清零），所以只改 TTL 不算内容变化。
`is_very_stable` 要求样本够多且分数高；这类集合走后台刷新，并可以信任 serve-stale。

## CacheScore 准入

每条条目在插入和命中的时候都打分：

```
CacheScore = α·popularity + β·locality + γ·stability + δ·ttl + ε·cost − ζ·memory
```

默认权重 α=0.30、β=0.18、γ=0.20、δ=0.16、ε=0.11、ζ=0.05。每项都归一化到 `[0,1]`：

- `popularity` —— 该域估计器算出的归一化查询速率；
- `locality` —— 上次被服务的近期程度，按窗口衰减；
- `stability` —— 稳定性模型分数；
- `ttl` —— 相对参考的 TTL；
- `cost` —— 相对参考的解析成本（越难解析越值得留）；
- `memory` —— 相对参考的内存占用（做减法）。

准入阈值：低于 `min_admit_score` 根本不进缓存；`hot_admit_score` 提升到 hot，`warm_admit_score`
提升到 warm。各层容量是硬上限。

## 淘汰

淘汰在每层采样一个有界子集（不全表扫描），丢掉分数最低的——所以缓存对自己留着什么很诚实：
冷门低分条目比热门高分条目更便宜地被淘汰。

## Serve-stale 与预取

过期条目在 `stale_window_secs`（默认一天，按 RFC 8767 的建议）内仍可服务，客户端 TTL 用
短的 `stale_serve_ttl`（默认 30 秒），同时排一个后台刷新。规划器根据预测查询概率决定 stale
值不值得给。快过期的条目若预测概率高，由维护循环预取（每 tick 有上限）。

## NXDOMAIN 存储

NXDOMAIN 按名存（不按 type），因为它对该名下的所有类型都成立。NODATA（NOERROR 空应答）按
`(name, type)` 键存。负 TTL 按 RFC 2308：`min(SOA TTL, SOA MINIMUM)`，上限 `negative_ttl_cap`
（默认 300 秒）。

## ECS

ECS 与非 ECS 应答绝不混用（RFC 7871 §7.2）：非 ECS 查询只看非 ECS 条目；ECS 查询先试自己的精确
分区，再回退到非 ECS 分区。
