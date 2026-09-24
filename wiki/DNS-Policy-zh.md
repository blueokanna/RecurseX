# DNS 策略层（Clash 兼容）

`dns` 段把 Clash / mihomo 用户已经熟悉的那套东西搬进 RecurseX：

```json
{
  "dns": {
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.0/16",
    "fake-ip-filter": ["*.lan", "*.local", "localhost"],

    "hosts": {
      "internal.example": "10.0.0.53",
      "dual.example": ["10.0.0.1", "2001:db8::1"]
    },

    "nameservers": ["tls://1.1.1.1#one.one.one.one"],
    "fallback": ["tls://8.8.8.8#dns.google"],

    "nameserver-policy": {
      "+.v51124-6.qpon": ["tcp://127.0.0.1:8080#node.internal"]
    },

    "fallback-filter": {
      "ipcidr": ["240.0.0.0/4", "0.0.0.0/8", "127.0.0.0/8"],
      "domain": ["+.google.com"]
    }
  }
}
```

## 键名：三种拼法都认

每个多词键都接受三种写法：

| Clash | 下划线 | 本 crate 的 JSON |
|---|---|---|
| `enhanced-mode` | `enhanced_mode` | `enhancedMode` |
| `fake-ip-range` | `fake_ip_range` | `fakeIpRange` |
| `nameserver-policy` | `nameserver_policy` | `nameserverPolicy` |
| `fallback-filter` | `fallback_filter` | `fallbackFilter` |

从别的代理配置里复制过来的键**不会**被丢掉。这是刻意的：一个键被解析、被保存、然后
什么也不做，比一个报了错的键危险得多——配置读起来像是生效了。

## 未知键会报错

`dns` 段内所有结构体（以及 `engine`、`cache`、`policy`、`listen`）都开启了
`deny_unknown_fields`。写错一个字母会得到一个**点名那个键**的错误：

```
{"dns": {"nameserver-policyy": {...}}}
→ Config: unknown field `nameserver-policyy`
```

这条规则是这一层存在的理由。在此之前的配置面默认静默忽略未知键，所以
「写了但没生效」和「写对了但没生效」看起来一模一样。

## 通配符语法

四类配置（`hosts`、`fake-ip-filter`、`fallback-filter.domain`、
`nameserver-policy` 的键）用的是**同一个**匹配器，所以语法不可能在各处漂移：

| 写法 | 含义 |
|---|---|
| `example.com` | 只有这一个名字 |
| `*.example.com`、`+.example.com`、`.example.com` | 该域名及其所有子域（含自身） |
| `*` | 所有名字 |
| `time.*.com`、`stun.*.*` | 逐标签匹配，每个 `*` 恰好一个标签 |
| `*.stun.*.*` | 开头的 `*` 是零个或多个标签，其余各一个 |

中间通配符不是装饰：mihomo 自带的 `fake-ip-filter` 默认表里就有 `time.*.com`
和 `*.stun.*.*`。如果不支持，它们会被解析成一个永远匹配不到的字面名字——
而一个静默匹配不到任何东西的过滤器，看起来和「没配过滤器」完全一样。

没有前导 `*` 时，模式必须**整名逐标签**匹配（`time.*.com` 匹配 `time.apple.com`，
不匹配 `x.time.apple.com`）；有前导 `*` 时按**后缀**匹配。

## `hosts`：静态应答

在缓存**之前**命中，且**永不进缓存**——配置改动必须在下一个查询就生效，而不是等 TTL。

* 值可以是单个地址或地址列表。
* 键接受 `*.example.com` / `+.example.com` / `.example.com`：都是「该域名及其子域」。
  最具体的模式优先，所以精确条目能压过通配条目。
* **对 `A`/`AAAA` 是权威的**：只钉了 v4 的名字，`AAAA` 会得到 **NODATA**，而不是真实的
  IPv6 地址、也不会去上游问。钉住一个名字就该钉住它。
* `MX`/`TXT`/`SRV` 等**不受影响**：`hosts` 说的是地址，不是「这个域名没有别的记录」。
* 值不是 IP 会直接报错并点名该条目——一个静默失效的钉子在排查时几乎不可见。
* 单独的 `*` 会被拒绝：把所有名字都交给静态表，和「DNS 坏了」无法区分。

## `enhanced-mode` / fake-IP

* `normal` 与 `redir-host` 都是关闭状态；`fake-ip`、`fakeip`、`fake_ip` 打开。
* 模式打开后，`A` 查询返回 `fake-ip-range` 里的合成地址；`AAAA` 返回 **NODATA**。
  真实的 IPv6 地址会让客户端直接连过去、绕开代理和路由规则，所以必须是空答案。
* `fake-ip-filter` 里的名字不合成，正常解析（`*.lan` 等本地域名需要这个）。
* **缺省会启用内置过滤表**（`fake-ip-filter` 键不存在时）：覆盖本地域名、
  Windows/macOS/Android 的连通性探测、NTP/授时、STUN，以及主机 NAT 类型检测。
  这不是便利性，是正确性：这些名字被合成后，**操作系统会得出"无网络"**、
  时钟永远不同步（进而让 TLS 失败）、WebRTC 与游戏找不到通路。
  显式写 `"fake-ip-filter": []` 表示"什么都不过滤"，这是另一个决定——
  两者含义不同，不能混同。
* 同一个名字拿到同一个地址，直到映射过期——地址可逆查回域名，这是这个模式能用的前提。
* 池满时**回收最久未使用的映射**并继续作答，而不是拒绝。对代理来说，拒绝意味着客户端
  拿到真实地址、流量绕开路由规则；重新编号只影响一条连接。回收次数在
  `shared.fake_ip.evicted()` 里可读。
* `fake-ip-ttl` 是**映射**寿命（默认 3600s）；`fake-ip-answer-ttl` 是**应答 TTL**（默认 1s）。
  两者不同：前者限制池里的条目，后者限制客户端能拿这个地址用多久。

## 上游与路由

* `nameservers` 是默认组，`fallback` 是回退组。
* `nameserver-policy` 按后缀选组，**最长后缀优先**，同长度时精确条目优先。
  规则顺序不影响结果——两份只有键序不同的配置行为完全一致。
* **不能**同时设置 `dns.nameservers` 和 `engine.forwarders`：它们是同一个设置的两种拼法，
  同时出现会报错，而不是让其中一个被静默忽略。
* 上游字符串写成 IP 字面量，`#` 后面是 TLS 身份：

  | 写法 | 传输 |
  |---|---|
  | `8.8.8.8`、`8.8.8.8:5353`、`8.8.8.8@5353` | UDP |
  | `udp://`、`tcp://` | UDP / TCP |
  | `tls://1.1.1.1#one.one.one.one` | DoT |
  | `https://1.1.1.1/dns-query#cloudflare-dns.com` | DoH |
  | `h3://1.1.1.1/dns-query#cloudflare-dns.com` | DoH3 |
  | `quic://1.1.1.1#dns.example` | DoQ |
  | `tls://[2001:db8::1]:8853#dns.example` | IPv6 要方括号 |

  端口前可以是 `:` 也可以是 `@`。Unbound 写 `1.1.1.1@853#cloudflare-dns.com`，
  所以从 Unbound 配置里拄来的一行可以直接用。

  **当前限制**：地址必须是 IP 字面量，不能写 `tls://dns.google`。域名上游需要先用
  迭代引擎做一次引导解析，本段还没做；用系统解析器去猜会让解析器隐式依赖
  `/etc/resolv.conf`——而解析器恰恰是那个「装它就是因为原来的解析坏了」的家伙。
  Unbound 用同样办法解决同一个问题（地址 + 显式 TLS 名），所以这是业界惯例。

## `fallback-filter`：应答可信度

* `ipcidr`：答案里出现这些段就视为被污染，改走 `fallback` 组。**任一**地址命中即判定
  污染——污染应答通常是真记录混着假记录。
* **缺省**保留内置列表（`0.0.0.0/8`、`127.0.0.0/8`、`240.0.0.0/4`、`::/128`、`::1/128`、
  `100::/64`）。**显式空列表**表示「一个都不标记」。两者含义不同，不能混同：
  只配了 `domain` 的配置仍然受内置列表保护。
* 默认**不**包含 RFC1918 私网段：家庭网络和 split-horizon 上游合法地返回私网地址，
  把它们当污染会打坏正常配置。
* `domain`：这些名字直接走 `fallback` 组，完全不经默认组。
* `geoip` / `geoipCode` 需要国家级 CIDR 数据库，本 build 不内嵌，因此**设为 `true` 会报错**
  并指明替代写法（`ipcidr` + `domain`）。静默接受会让一个「反污染配置」实际上毫无反污染，
  而配置读起来像是有。

## 可观测性

策略层的每个决定都有计数器（`stats_snapshot()`），因为它们都是「静默失败」的温床：

| 计数器 | 看什么 |
|---|---|
| `hosts_answered` | 钉子生效次数 |
| `fake_ip_answered` / `fake_ip_ptr` | 合成地址的正向 / 反向应答 |
| `fake_ip_filtered` | 被过滤器排除、改为真实解析的次数 |
| `fake_ip_entries` / `fake_ip_evicted` | 池规模（仪表）/ 回收次数 |
| `policy_routed` | `nameserver-policy` 真的命中的次数——**为 0 就说明后缀没匹配上** |
| `fallback_triggered` | 污染门控触发次数 |

`fake_ip_evicted` 持续增长是「把 `fake-ip-max-entries` 调大」的明确信号。

## 没有 `dns` 段时

什么都不变。空的 `dns` 段产生一个默认策略：没有钉子、没有合成、没有路由，
污染门控因为回退组为空而不起作用。这条性质让整个特性可以安全地增量引入。

## 相关

- [架构](Architecture-zh.md) —— 这一层在整个流水线里的位置。
- [部署与加固](Deployment-zh.md) —— 面向真实客户端的运行方式。
- [测试与验证](Testing-zh.md) —— 这些行为怎么被测住。
