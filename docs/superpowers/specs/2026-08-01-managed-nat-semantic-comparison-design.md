# 受管 NAT 规则语义比较修复设计

## 背景与根因

`lsec` 写入 `/etc/ufw/before.rules` 后，UFW/iptables 会以自身的规范格式重新输出规则。例如，脚本生成的 SNAT 规则可能先写 `-o` 再写 `-d`，而 `iptables-save` 会先输出 `-d` 再输出 `-o`，同时补充 `/32` 和 `-m tcp`。两条规则语义相同，但当前整行字符串比较将其误判为不一致，导致创建事务在首次 reload 后回滚。

## 目标

- 对脚本严格受管的 DNAT、SNAT 规则进行字段化语义比较。
- 接受参数顺序、IPv4 主机地址 `/32`、`-m tcp/udp` 和 comment 引号等合法输出差异。
- 继续识别接口、协议、来源、端口、目标地址、动作和 marker 的真实变化。
- 保持同一 iptables 链内规则顺序敏感，避免掩盖匹配优先级变化。
- 不扩大脚本所有权范围，不解析或修改非受管 NAT 规则。

## 设计

新增一个严格的受管 NAT 规则规范化器。它只接收符合当前或旧版受管 marker 格式的 PREROUTING/DNAT 与 POSTROUTING/MASQUERADE 规则，并将每条规则输出为固定字段序列：

```text
chain | protocol | source | input-interface | output-interface | destination |
destination-port | comment | jump | translated-destination
```

缺省来源使用 `any`，缺省接口或目标字段使用明确的占位值。IPv4 地址末尾的 `/32` 在字段值层面移除。`-m tcp`、`-m udp` 和 `-m comment` 只作为合法匹配模块接受，不参与语义值比较。

解析器采用白名单：发现重复字段、缺少必需字段、链与动作不匹配、未知选项、非法 marker，或者 DNAT/SNAT 结构不完整时返回失败，而不是忽略异常内容。

`verify_nat_file_effective` 仍分别比较 PREROUTING 和 POSTROUTING。每条规则先规范化，但不排序规则列表，因此只忽略单条规则内部的参数排列差异，不忽略链内规则顺序变化。

用于精确执行 `iptables -D` 的规则文本保持现状，继续尽量保留 `iptables-save` 原始参数；语义规范化器只用于验证，不用于生成删除命令。

## 错误处理

规范化任意一侧失败即视为 NAT 不一致：

- 事务开始前返回“需要修复”，不产生事务日志。
- 应用阶段验证失败时按现有事务机制完整回滚。
- 回滚后的快照验证仍失败时保持保护锁，禁止继续变更。

## 测试

新增回归用例证明：

- 真实风格的 TCP/UDP POSTROUTING 参数重排仍判定一致。
- `/32`、`-m tcp/udp`、comment 引号不影响语义一致性。
- DNAT 参数的合法重排同样判定一致。
- 端口、接口、目标地址或动作变化判定不一致。
- 未知参数、重复字段或不完整规则判定解析失败。
- 同一链内两条受管规则顺序反转仍判定不一致。
- 完整事务测试与脚本语法检查继续通过。

## 发布

修复版本提升到 `4.0.2`，推送至 `main` 后服务器通过 `lsec upgrade` 获取。
