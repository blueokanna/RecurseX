# RecurseX wiki（中文）

一个预测式自适应递归 DNS 解析器。概览见 [README_CN](../README_CN.md)；这里讲各模块到底怎么
工作、为什么长成这样。

## 目录

- [架构](Architecture-zh.md) —— 六层结构与数据流。
- [**风险约束刷新**](Refresh-Theory-zh.md) —— 风险模型、可信界、风险预算与依赖一致刷新。
  本项目里**不属于**「把成熟手段认真实现一遍」的那部分，设计文档在这里。
- [**信息价值**](Value-of-Information-zh.md) —— 一次额外观测值多少，以及有限的刷新预算该花在哪些
  条目上。同一套理论的另一半：分配。
- [PARR 预测核心](PARR-zh.md) —— 查询状态估计器、解析规划器、变化率模型、自适应解析器。
- [缓存准入与变化率模型](Cache-Admission-zh.md) —— `CacheScore` 由什么构成、为什么它是价值函数而非安全门，
  以及 ECS 如何划分键空间。
- [别名依赖](Alias-Dependency-zh.md) —— 为什么缓存之外还需要一个结构，才能把 CNAME 链当作整体保持可服务。
- [上游选择成本模型](Upstream-Selection-zh.md) —— 为什么裸 RTT 是错的信号。
- [DNS 策略层](DNS-Policy-zh.md) —— Clash 兼容的 `hosts` / fake-IP /
  `nameserver-policy` / `fallback-filter`，以及为什么未知键会报错。
- [DNSSEC](DNSSEC-zh.md) —— 校验什么、怎么校验、诚实的边界。
- [持久化](Persistence-zh.md) —— L3 层：格式、原子写、恢复规则。
- [部署与加固](Deployment-zh.md) —— 面向真实客户端的运行方式、限速、防欺骗。
- [测试与验证](Testing-zh.md) —— 测试覆盖了什么、怎么复现在线检查。
- [**越过查表**](Beyond-The-Lookup-zh.md) —— 「无服务器 / 行为哈希 / 全息」提案里哪部分做不到、
  为什么，以及哪部分是真的、已经进了 crate：带密钥的行为身份与带权会合选择。
- [**论文**](../paper/RecurseX-risk-constrained-refresh.md) —— 同一套论证的评审版本：模型、定理、
  评测协议、局限，以及明确不声称的部分。

## 先立三条规矩

1. **永远不发明 TTL。** 所有预测只调**内部**策略。客户端看到的 TTL 就是权威返回的值
   （缓存数据再扣掉已流逝的时间）。
2. **不允许无界。** 这个 crate 里每个模型都有硬上限。恶意查询流可以让它忙，但不能让它无界长大。
3. **不假装传输可用。** 每个传输都带真实可用的实现。如果哪一层只是个桩，就直说，
   而不是假装能用。
