# 测试与验证

## 命令

```sh
# 全量：单测 + 集成测试 + 文档测试
cargo test --all-features

# 算法核心（含它自己的测试）是 no_std
cargo test --no-default-features --lib

# 严格 lint（警告即错误）
cargo clippy --all-targets --all-features -- -D warnings
```

## 测试覆盖了什么

套件共 291 个单测、`tests/` 下 22 个集成测试、4 个文档测试。

它是**在关键意义上自洽的**：没有任何测试断言公网的应答，所以结果取决于解析器，而不取决于
网络状况或延迟。任何需要上游的测试都拿到本地桩服务器，迭代查询则对着环回上的桩根服务器跑。
有三个测试确实开了套接字，这点值得说准：两个发往 `192.0.2.1`（TEST-NET-1，按定义不可路由），
只断言交换在超时内**失败**；一个在环回上驱动桩上游。去问真实根服务器的测试报告的是网络状况，
而在上游劫持 UDP/53 的机器上，它报告的其实是那次劫持。

- **线格式编解码**（`message`、`rdata`、`name`、`qtype`、`edns`）—— 解析/序列化回环、
  名字压缩、截断、错误应答、NSEC 位图、EDNS 选项。
- **缓存** —— 跨层插入/查找、CNAME 链、serve-stale、NXDOMAIN 存储及其容量、ECS 分区、
  精确淘汰最低分、预取候选、清扫。
- **稳定性与准入** —— EWMA 数学、指纹与 TTL 无关、分数阈值、内存项（它必须真的影响分数）。
- **估计器 / 规划器 / 别名图 / 上游** —— 概率增长、时段画像形状、内存有界、别名边双向查询与
  剪枝、成本排序、超时也会建立路径模型。估计器还拿参考值验证自带的 `exp` 和取整。
- **策略** —— 限速、过滤、令牌桶。
- **引擎与解析器** —— 应答分类（answer / NXDOMAIN / NODATA / referral / empty）、QNAME
  最小化步骤、负 TTL 规则、请求合并（含 owner 消失却不发布的场景）、CNAME 到别名边的接线、
  AD/CD 应答标志，以及服务器面对桩上游的 UDP 与 TCP 路径。
- **配置** —— JSON 回环、最小文档、转发器默认端口。
- **加密传输** —— DoT/DoH/DoH3/DoQ 协议行为（帧、错误码、QUIC 包/加密/ACK 与 TLS
  握手的单测；DoQ 的 QUIC-TLS 客户端还用本地 courierust HTTP/3 服务器做了含
  Retry + 完整握手 + 1-RTT 的互操作验证）。手写的两个编解码器还各自带上了对抗性用例：
  DER 的两种长度形式及其各类截断、带与不带符号字节的 RSA 公钥、一个条目长度受**列表**而非
  报文约束的 Certificate 列表、一个给错群组或错密钥长度的 ServerHello，以及一个试图申请
  一 TB 的流重组偏移。
- **超时** —— `tests/iterative_path.rs` 让一次死掉的迭代在引擎的 `query_budget_ms` 处收尾，
  并断言预算已耗尽时不碰网络就停。DoQ 传输的测试给同一份契约装了秒表：200ms 的预算必须在
  一秒内失败——这个传输过去会把调用方的时间下限抬到十秒，除了秒表没有任何断言能看见它。
- **DNSSEC** —— 一个 openssl 真实生成的 1024 位 RSA/SHA-256 向量能验过；改摘要或改签名都
  失败；DNSKEY 解析边界（零长度 → 4 字节指数）。
- **持久化** —— 回环、stale 归位 cold、死条目丢弃、ECS 存活、篡改拒绝、原子写。
- **服务端生命周期** —— 每个循环都能被叫停：UDP 接收循环、处理线程池、TCP accept 循环、
  每连接的读取循环、维护线程，都在测试里带看门狗启动并停止；空闲连接（或每次只滴一个字节的
  连接）会被关上，而不是永久占住一个线程。

## 集成测试（`tests/`）

这些测试按嵌入者的方式使用 crate —— 只用公开 API，不碰内部：

- `iterative_path.rs` 把迭代查询放到解剖台上：一个桩根和一个桩 `test` 区，走完委派链、
  带 SOA 的 NXDOMAIN、一次 REFUSED、一个彻底空的 NOERROR，以及一个从不回答的黑洞。它断言
  的都是从外面看不见的性质 —— 委派链会被走到答案、QNAME 最小化只改变查询而不改变答案、整轮
  迭代绝不会去问与问题无关的名字、REFUSED 会被重试而不是直接返回、NXDOMAIN 会被缓存而不再
  追问、死掉的迭代停在 `query_budget_ms`。八个测试里有**两个在第一次运行时就抓出了真 bug**：
  空应答跳过的条件把一个合法的“无 SOA 的 NXDOMAIN”当成“没有服务器回答”丢掉了；而 UDP 读超时
  被报成了 I/O 错误，因为 Windows 管这叫 `TimedOut` 而 Unix 叫它 `WouldBlock`。
- `end_to_end.rs` 从 JSON 文档搭出解析器，在 0 端口绑 UDP 与 TCP 监听，直接在网上查询两者，
  断言第二次查询由缓存回答且不产生新的上游查询；从 `persist` 快照"重启进程"（并断言重启
  不需要网络）；跑一遍配置好的转发器；最后用 `Server::shutdown`/`Resolver::shutdown` 带看门狗
  停掉全部东西。
- `wire_robustness.rs` 是解码器的对手：20000 个确定性伪随机缓冲区（SplitMix64 定种，失败可
  复现），其中一半带上了看似合理的 header 计数；恶意计数字段；压缩指针成环；一个合法报文的
  每一个截断边界。它断言解析器绝不 panic、凡是被接受的输入重新编码后仍能被接受，且
  `truncate_for_udp` 绝不超出给定上限、同时保住问题段并置 TC。
- `parser_robustness.rs` 覆盖 `wire_robustness.rs` 走不到的那些解析器：**40 种 rdata 解码器
  逐个**直接喂垃圾、故意指向缓冲区之外的 `end`、EDNS option 遍历器、RSA 验签、QUIC 应答分帧、
  TLS 握手解析器。随机字节只能压到**拒绝路径**——这些解码器要求 rdata 被精确消费完，所以随便
  的输入几乎必被拒——正因如此，接受路径由另一组**手写合法 rdata（12 种类型）的字节级往返**
  单独钉住。

## 读取来自网络的字节

每个线格式解析器都通过 `crate::wire::WireBytes` 读取——一个加在 `[u8]` 上的扩展 trait，
它的读取是受检的，而且关键的一点是：**里面没有任何索引表达式**。`slice[i]` 和
`&slice[a..b]` 是用 panic 来回答"这里有没有字节"的，而由报文触发的 panic 就是远程拒绝服务。
换成 `buf.byte_at(i)?` / `buf.u16_at(i)?` / `buf.slice_at(i, n)?` / `array_at::<N>(i)` 之后，
编译器不可能生成会 panic 的边界检查，只能生成返回 `None` 的。内部算术用 `checked_add`，
所以长度为 `usize::MAX` 的字段是错误而不是回绕。编码侧的对应物是
`wire::capped(bytes, limit)`，用来取代 `&x[..x.len().min(N)]` 这种长度前缀封顶。

crate 在库上启用了 `clippy::indexing_slicing`，而且是**强制**而非志向：`lib.rs` 里挂着
`#![cfg_attr(not(test), warn(clippy::indexing_slicing))]`，所以
`cargo clippy --all-targets -- -D warnings` 会在发出代码里新增一个索引表达式时直接报错。
它**故意不**覆盖 crate 自己的测试模块（`cfg(not(test))`）与 `tests/`、`examples/` 目标，
那些是独立的 crate：对夹具做下标是说明“这些字节是什么”最清楚的写法，而那里索引写错是一个
失败的测试，不是远程故障。

`transports/doq/` 里手写的两个编解码器是最后 120 处，现在已归零。这次收尾有两点值得记下来：

- 那个坑是真的，而且很安静。TLS 握手长度是三个字节，而这次改写的**第一版**把它当 `u32`
  读再掩码——正好差一个字节就会吃掉它所描述的那个 body 的首字节。抓到它的是已有的重组测试。
  最终的修法是 `WireBytes::u24_at`：它存在的意义，就是让“三个字节”没法被写成“四个字节减一”。
- 其中一些点不只是“潜在的 panic”，而是活着的 bug。`on_stream` 会**先**把重组缓冲区扩到
  `STREAM` 帧自带的 offset，**然后**才检查缓冲区上限——也就是说对端可以报一个 TB，进程就会
  真的去问分配器要。一个包就能远程打爆内存。现在它通过 `reassembly_end` 约束长度（先算受检
  算术，再比上限），而那个函数有自己的测试。

有 `wire_robustness.rs` 与 `parser_robustness.rs` 兜底的 DNS 线格式解析器，是最先改完也最干净
的一批。

## panic 与锁中毒

crate 里每个互斥锁都是 `crate::sync::Mutex`，不是 `std::sync::Mutex`。差别就是**在一处做出的
一个策略决定**：`lock()` 从中毒中恢复，不返回 `LockResult`，因此不可能失败。

`std::sync::Mutex` 在某线程持锁 panic 后会给自己下毒，之后每一次 `lock().unwrap()` 也会 panic
——单个线程上的一个 bug 就变成**永久拒绝回答任何查询**，因为毒永远不会解。这些锁后面是缓存、
流行度模型、限流器和连接池：每一个都是使用时重校或可安全丢弃，没有一个持有"被破坏就会给出
错误答案而不是查询失败"的不变式；而且 crate 禁用了 `unsafe_code`，撕裂的值不可能变成 UB。
`src/sync.rs` 有一个测试故意用 panic 给锁下毒，然后断言这把锁仍然交出它持有的值。

## 在线验证

`examples/quick_check.rs` 走完整迭代管线把 `example.com`、`www.example.com`、`google.com`、
`ietf.org`、`nonexistent.invalid` 各解析两遍（第二遍必须命中缓存），然后打印统计：

```sh
cargo run --no-default-features --features std --example quick_check
```

在诚实回答的网络上，一次健康的运行会解析出全部四个真实名字、对非法名返回 NXDOMAIN；
`ietf.org` 走的是区外 NS 路径（afilias-nst.info），也是能抓住 QNAME 最小化回归的用例——
对最小化前缀的 NODATA 必须加深查询，而不是直接终止。在不诚实回答的网络上，它只能证明“没有
东西崩”，这也值得知道，但和前者不是一回事（见下）。

## 为什么这些数字可信

- 没有造出来的测试向量：RSA 向量用 openssl 生成，并用独立 Python 实现交叉验证。
- 在线名字是对着真实 DNS 树解析的，不是 mock。
- **在线运行只能证明“接线是对的”，不能当正确性的判决。** 开发这台机器的上游劫持了
  UDP/53：问一个知名根地址，三分之二的查询直接超时，而 `nonexistent.invalid` 会在 8ms 内
  返回空——那是劫持在回答，不是 DNS 树在回答。所以正确性由自洽的桩测试裁定，在线运行只读成
  “有没有东西崩了”。
- `no_std` 核心在 CI 里不仅构建，还跑它自己的测试，所以核心不会偷偷长出 `std` 依赖。
- CI 在 MSRV（1.78）与 stable、Linux 与 Windows 上都跑，并带 `RUSTFLAGS=-D warnings`；发行用的
  release profile（fat LTO、单个 codegen unit）也一并测试，因为那才是真正发出去的东西。
