# 转发语义验证与事务诊断完整修复设计

## 背景

`lsec` 4.0.2 已将受管 NAT 验证改为字段语义比较，但 UFW 路由仍按 `ufw show added` 的完整字符串比较。UFW 会重建等价命令，可能省略 `from any` 并调整协议位置，因此合法路由会在最终验证阶段被误判。与此同时，当前验证函数大多只返回 `1`，事务进入 `rolled_back` 后又会清空 `last_error`，造成失败层级、期望值、实际值和瞬时现场全部丢失。

本设计将 UFW、NAT、IPv4 forwarding、状态登记和事务诊断统一为一套结构化验证模型，不再逐项增加特例。

## 目标与边界

- 对 UFW 持久化路由进行严格字段语义比较，允许等价的命令重建差异。
- 同时验证 UFW 持久化配置、运行时 marker 和 active 状态。
- 为每个验证出口提供稳定错误代码、中文摘要、期望值和实际值。
- 原始失败在成功回滚后仍永久保留；回滚失败另行记录，不覆盖原始原因。
- 在回滚前保存瞬时 NAT、UFW、IPv4 和状态现场。
- 创建、删除、覆盖、迁移、恢复备份与 UFW 初始化事务使用一致的错误模型。
- 保持旧事务日志可恢复，不迁移现有转发状态 schema。
- 不耦合 Xboard、证书、Hysteria2 或 VLESS。

## UFW 路由语义模型

新增严格的 UFW route 解析器，将 `ufw show added` 中带有合法受管 marker 的规则转换为：

```text
action | input-interface | output-interface | protocol | source |
destination | destination-port | comment
```

解析规则如下：

- 只接收 `ufw route allow`。
- `in on`、`out on`、`proto`、`from`、`to`、`port` 和 `comment` 可按 UFW 输出顺序出现。
- 未输出 `from` 时规范化为 `source=any`。
- comment 的单引号与双引号差异被规范化。
- 入站接口、出站接口、协议、目标、目标端口和 comment 为必需字段。
- 未知子句、重复字段、缺失参数、非法 marker 或结构不完整均解析失败。
- marker 必须恰好出现一次；前缀相似规则不能计为匹配。

验证一条状态规则时，同时要求：

1. `ufw status` 为 active。
2. `ufw show added` 中恰好一条持久化 route 与状态字段语义一致。
3. `ufw status numbered` 中恰好一条运行时规则携带完全相同的 marker。

## 统一验证顺序

所有转发提交和恢复验证统一执行：

1. UFW active。
2. IPv4 runtime forwarding。
3. IPv4 persistent forwarding。
4. 状态 marker 唯一。
5. 持久化 DNAT/SNAT 语义。
6. live DNAT/SNAT 语义。
7. UFW 持久化 route 语义。
8. UFW runtime marker 唯一。

删除验证使用对应的缺失断言，但沿用相同错误上下文。迁移、覆盖和恢复备份必须逐 marker 报告，TCP 成功而 UDP 失败时应明确指向 UDP。

## 结构化错误上下文

验证层使用统一上下文，至少包含：

```text
failure_stage
failure_code
failure_protocol
failure_marker
failure_summary
failure_expected
failure_actual
failure_at
```

稳定错误代码包括：

```text
UFW_INACTIVE
IPV4_RUNTIME_DISABLED
IPV4_PERSISTENT_DISABLED
STATE_MARKER_MISSING
STATE_MARKER_DUPLICATE
NAT_PERSISTED_DNAT_MISMATCH
NAT_PERSISTED_SNAT_MISMATCH
NAT_LIVE_DNAT_MISMATCH
NAT_LIVE_SNAT_MISMATCH
UFW_ROUTE_PARSE_FAILED
UFW_ROUTE_MISSING
UFW_ROUTE_DUPLICATE
UFW_ROUTE_SEMANTIC_MISMATCH
UFW_RUNTIME_MARKER_MISSING
UFW_RUNTIME_MARKER_DUPLICATE
```

实现不得依赖子 shell 中修改全局变量。命令输出先由调用者捕获，再由当前 shell 设置失败上下文。所有写入 TSV 的值必须移除制表符、回车和换行，防止破坏日志结构。

## 事务日志

新增独立 `TRANSACTION_SCHEMA_VERSION=3`。转发状态 `STATE_SCHEMA_VERSION` 保持 2。

新事务日志增加：

```text
failure_stage
failure_code
failure_protocol
failure_marker
failure_summary
failure_expected
failure_actual
failure_at
rollback_status
rollback_error
evidence_error
```

规则：

- `set_transaction_phase` 只更新阶段、时间和当前阶段错误，不删除 `failure_*`。
- 首次根因通过专用函数一次性写入，后续回滚不得覆盖。
- 回滚成功写入 `rollback_status=verified`。
- 回滚失败写入 `rollback_status=failed` 和 `rollback_error`，并进入保护锁。
- schema 2 日志缺少新增字段时按空值读取，仍可自动恢复。
- `rolled_back` 日志必须同时保留原始失败和回滚结果。

## 回滚前现场证据

确认应用或验证失败后、执行任何删除或快照恢复前，尽力创建：

```text
/etc/ufw/relay-manager/backups/<batch>/failure/
├── verification.tsv
├── iptables-save-nat.txt
├── ufw-show-added.txt
├── ufw-status-numbered.txt
├── ipv4-forwarding.txt
├── before.rules.failed
└── forwarding.tsv.failed
```

目录权限为 `700`，文件权限为 `600`。证据采集失败不能阻止回滚，而应写入 `evidence_error`。诊断导出包含上述内容。证据中不包含 Xboard、证书或应用密钥。

## 用户输出

事务失败并成功回滚后输出：

```text
[错误] 转发创建失败，事务已验证回滚
[错误] 批次：<batch>
[错误] 阶段：<failure_stage 中文名称>
[错误] 代码：<failure_code>
[错误] 协议：<protocol>
[错误] 标记：<marker>
[错误] 原因：<failure_summary>
[错误] 期望：<failure_expected>
[错误] 实际：<failure_actual>
[信息] 回滚状态：已恢复并验证
[信息] 现场证据：<failure-directory>
```

不适用的字段不显示。回滚失败时明确输出原始失败与回滚失败两个区块，并显示保护锁路径。前置检查发生在事务创建前时仍输出结构化原因，但不伪造事务日志。

## 测试要求

- UFW 省略 `from any`、调整 `proto` 位置时语义一致。
- UFW 接口、协议、来源、目标、端口或 marker 变化分别失败。
- UFW 持久化规则缺失、重复、解析失败可区分。
- UFW runtime marker 缺失、重复可区分。
- IPv4 runtime 与 persistent 失败可区分。
- NAT 持久化与 live、DNAT 与 SNAT 失败可区分。
- TCP、UDP、TCP+UDP 成功；部分协议失败时报告准确协议和 marker。
- 原始失败在成功回滚后保留。
- 回滚失败同时保留根因和回滚错误。
- 回滚前证据包含失败时刻的 live 规则，权限正确。
- 证据采集失败不影响回滚且被记录。
- schema 2 未完成事务继续自动恢复。
- 创建、删除、覆盖、迁移、备份恢复及 UFW 初始化具有结构化错误。
- 完整 shell 语法与现有事务测试继续通过。

## 发布

版本提升到 `4.1.0`。完成测试与独立复审后直接推送 `main`，服务器使用 `lsec upgrade` 获取。
