# RecurseX wiki（中文）

一个预测式自适应递归 DNS 解析器。概览见 [README_cn](../README_cn.md)；这里讲各模块到底怎么
工作、为什么长成这样。

## 目录

- [架构](Architecture-zh.md) —— 六层结构与数据流。
- [PARR 预测核心](PARR-zh.md) —— 查询状态估计器、解析规划器、稳定性感知缓存、自适应解析器。
- [缓存准入与稳定性数学](Cache-Admission-zh.md) —— `CacheScore` 由什么构成，为什么稳定性要「测」不能「猜」。
- [解析图](Resolution-Graph-zh.md) —— 预取发散背后的依赖模型。
- [上游选择成本模型](Upstream-Selection-zh.md) —— 为什么裸 RTT 是错的信号。
- [DNSSEC](DNSSEC-zh.md) —— 校验什么、怎么校验、诚实的边界。
- [持久化](Persistence-zh.md) —— L3 层：格式、原子写、恢复规则。
- [部署与加固](Deployment-zh.md) —— 面向真实客户端的运行方式、限速、防欺骗。
- [测试与验证](Testing-zh.md) —— 测试覆盖了什么、怎么复现在线检查。

## 先立三条规矩

1. **永远不发明 TTL。** 所有预测只调**内部**策略。客户端看到的 TTL 就是权威返回的值
   （缓存数据再扣掉已流逝的时间）。
2. **不允许无界。** 这个 crate 里每个模型都有硬上限。恶意查询流可以让它忙，但不能让它无界长大。
3. **不假装传输可用。** 哪个协议层还没完全可用（比如 DoQ provider），就说实话。
