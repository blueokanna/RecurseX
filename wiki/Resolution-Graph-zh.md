# 解析图

递归解析不是线性走查。`www.example.com` 依赖 `example.com` 区，它从 `.com` 委派下来，
由一组服务器服务——而 CNAME 可能跳到完全另一棵树。解析图把这种结构显式化、且有界。

## 节点与边

```
www.example.com ──cname_to──▶ cdn.example.net ──depends_on──▶ example.net zone
       │                                                          │
       └──depends_on──▶ example.com zone ──served_by──▶ ns1/ns2.example.com
                              │                                   │
                              └──delegates_to──▶ .com ──served_by──▶ a.gtld-servers.net
```

- `NodeId::Domain(Name)` / `NodeId::Ns(Name)` / `NodeId::Server(ip, port)`；
- 边：`DependsOn`（名字需要某区）、`DelegatesTo`（区 → 子区）、`ServedBy`（区 → NS）、
  `CnameTo`（名字 → 目标）、`ReachableVia`（服务器 → 它应答过的域）。

## 换来什么

1. **预取发散。** 对一个区做出预取决定时，图能告诉你哪些名字依赖它。维护循环不必只刷新一个
   键，可以刷新整条依赖集。
2. **子解析共享。** 一个区的 NS 名字和地址是图里的同一片邻域，该区下的很多查询都能复用。
3. **可诊断。** 图是解析器实际跟谁说话的实时地图——哪个服务器应答了哪个区。

## 有界

`max_nodes` 限制图的大小。`prune(now, max_age)` 移除超过年龄未触碰的节点，长跑解析器不会
积累死结构。维护线程每 tick 调一次。
