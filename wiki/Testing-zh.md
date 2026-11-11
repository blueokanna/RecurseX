# 测试与验证

版本：**0.2.6**.


## 命令

下面就是 CI 的各个作业，按顺序。它不是一份菜单：每一行之所以存在，是因为另一个特性前沿有
自己的代码路径，尤以三条 clippy 腿为甚——那是三个不同的程序。`.github/workflows/ci.yml` 设置了
`RUSTFLAGS=-D warnings`，本地也要设：本地看着无害的告警，在 CI 里就是构建失败。

```sh
# fmt：版式由 rustfmt 定，不由作者定
cargo fmt --all -- --check

# clippy：全特性、no_std 核心、以及不带传输的 std
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --no-default-features --lib -- -D warnings
cargo clippy --no-default-features --features std --all-targets -- -D warnings

# doc：rustdoc 零告警，且文档测试也是测试
cargo doc --all-features --no-deps
cargo test --doc --all-features
cargo test --doc --no-default-features

# test：真正发出去的东西，MSRV 与 stable 都跑
cargo test --all-features
cargo test
cargo test --release --all-features

# features：每个前沿都要构建，两个核心还要**跑**自己的测试
cargo build --no-default-features
cargo test --no-default-features --lib
cargo build --no-default-features --features std
cargo test --no-default-features --features std --lib
for f in dot doh doh3 doq dnssec persist; do
  cargo build --no-default-features --features "$f"
done

# release：发行用的 profile，以及声明了自己依赖的 examples
cargo build --release --all-features
cargo build --release --examples --all-features
cargo build --examples --no-default-features --features std
cargo package --allow-dirty
```

其中两条腿值得点名记住，因为它们才是会咬人的：

- `cargo test --no-default-features --lib` 是**唯一**在无 `std` 情况下编译核心自带测试模块的
  地方。`#![no_std]` 让测试模块只剩 `core` 预导入，于是 `String`、`Vec`、`to_string`、
  `format!`、`vec!` 都得写全名——而漏掉的测试模块在**其它每一条腿**上都编得过。修法就是这个
  仓库里写的那个：在旁边加 `#[cfg(not(feature = "std"))] use alloc::string::ToString;`。
- `cargo clippy --no-default-features --features std --all-targets` 是**唯一**在不带可选特性的
  情况下编译 `tests/` 的地方，所以一个 import 了特性门控模块（`recurse_x::dnssec::rsa`、
  `recurse_x::transports::doq`）的测试，只在这里解析失败。要门控的是**那个测试**而不是整个
  文件：线格式解码器属于核心，它们在 CI 构建的每种配置里都必须保持覆盖。

## 测试覆盖了什么

0.2.6 新增 `answer_boundaries.rs` 与 DNSSEC、监听访问测试，覆盖记录归属、class、
委派祖先关系、别名否定回答、签名时间回绕、RDATA 排序和默认客户端范围。
恢复测试覆盖 UDP 黑洞、TCP 重试与截断、回环避让；观测测试比对真实解析结果与缓存命中。

测试使用本地固定服务，不依赖公网 DNS 成功。计数取决于 feature，命令和结果应一并记录，
见 [本轮审计记录](../docs/audit-0.2.6.md)。本地测试不等于公网互操作、真实概率覆盖率或设备实测。

- **线格式编解码**（`message`、`rdata`、`name`、`qtype`、`edns`）—— 解析/序列化回环、
  名字压缩、截断、错误应答、NSEC 位图、EDNS 选项。
- **缓存** —— 跨层插入/查找、CNAME 链、serve-stale、NXDOMAIN 存储及其容量、ECS 分区、
  精确淘汰最低分、预取候选、清扫。
- **危险模型与准入** —— 近似更新、限制累计模型影响的证据上限、指纹与 TTL 无关、
  分数阈值、内存项（它必须真的影响分数）。
- **估计器 / 规划器 / 别名图 / 上游** —— 概率增长、时段画像形状、内存有界、别名边双向查询与
  剪枝、成本排序、超时也会建立路径模型。估计器还拿参考值验证自带的 `exp` 和取整。
- **带密钥身份与亲和** —— 量化器每翻倍一档，且对包括 NaN 在内的**每一个** `f64` 都是全函数；
  指纹对固定的类别与名字稳定，而在**密钥改变时**必须改变；同一类别下的两个不同名字得到不同
  指纹；指纹在排序空间上铺开而不是挤进一个桶；密钥的 `Debug` 只打印 `<redacted>`。亲和抽签
  一侧：选择是密钥与主体的纯函数；带内每台服务器拿到的头部席位占比在容差内均匀，而带外服务器
  一次都拿不到；最小扰动性质按**等式**断言——撤掉一个候选后改变的主体数，与该候选原本赢下的
  主体数**相等**。
- **信息价值** —— 对后果等级、信任惩罚、`V`、以及自上次观测以来多久单调；被「不行动的风险」封顶；
  无物可学时恰为零；对后果系数为无穷的类别仍给出有限值。调度器针对它所防止的饥饿做了测试：保留额度
  与被无保留额度便会饥饿的那次价值排序并排断言，而且「某类别是否被代表」是按类别逐个检查而非总体
  检查。
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
  追问、死掉的迭代停在 `query_budget_ms`。这些测试里有**两个在第一次运行时就抓出了真 bug**：
  空应答跳过的条件把一个合法的“无 SOA 的 NXDOMAIN”当成“没有服务器回答”丢掉了；而 UDP 读超时
  被报成了 I/O 错误，因为 Windows 管这叫 `TimedOut` 而 Unix 叫它 `WouldBlock`。另外两个覆盖
  随刷新模型一起加进来的机制：一份列了十二台服务器却一条 glue 都没有的转介，必须在**任何地址
  查询之前**被拒（断言的是**查询次数**而不是错误码，因为一个只限深度的解析器会用十二次解析去
  应答它）；以及服务器声明对整个 `/24` 有效的答案，必须被该网段内的 `/25` 客户端以**零次**新的
  上游查询复用，而另一个 `/24`、以及压根没发 ECS 的客户端必须自己去问。
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
一个策略决定**：`lock()` 从中毒中恢复，不返回 `LockResult`，因此不可能失败。唯一的那把读写锁
——每次查询都要读的手动时钟——同样是 `crate::sync::RwLock`，理由一致。

`std::sync::Mutex` 在某线程持锁 panic 后会给自己下毒，之后每一次 `lock().unwrap()` 也会 panic
——单个线程上的一个 bug 就变成**永久拒绝回答任何查询**，因为毒永远不会解。这些锁后面是缓存、
流行度模型、限流器和连接池：每一个都是使用时重校或可安全丢弃，没有一个持有"被破坏就会给出
错误答案而不是查询失败"的不变式；而且 crate 禁用了 `unsafe_code`，撕裂的值不可能变成 UB。
`src/sync.rs` 有一个测试故意用 panic 给锁下毒，然后断言这把锁仍然交出它持有的值；`src/time.rs`
对时钟做了同一个测试。

读写锁比互斥锁多一件必须处理的事：它的 `Display` 可能**从 panic 消息里被调到**，因此不能阻塞。
在那里直接 `read()` 会去等一个由正在 panic 的线程持有的写锁，而同线程重入读在 `std` 的文档里
明说可能 panic——于是变成"在报告 abort 的过程中 abort"。所以时钟走 `try_read()`，拿不到锁时
打印 `ManualClock(<locked>)` 而不是等下去；`src/time.rs` 有测试在持有写锁的情况下断言这一点。

## 独立客户端与公网验证

Windows 可显式运行 `cargo test --all-features --test system_client_interop -- --ignored --nocapture`。
它临时绑定回环 53 端口，用系统 nslookup 分别查询 UDP/TCP 的固定 hosts 记录，结束后关闭服务。
端口被占用时应失败，不停止已有服务；不修改系统 DNS。使用固定记录验证的是协议互操作，不是公网解析。

`cargo run --no-default-features --features std --example quick_check` 则访问真实权威网络。
超时、空答案或错误码必须原样报告，不能仅凭这些现象断言上游劫持。
当前网络的纯递归失败记录不构成普遍可用性证据，DNSSEC 信任链也不能由连通测试代替。
本地回归、独立客户端和公网实验分别覆盖不同边界，任何一项都不证明系统没有所有漏洞。
