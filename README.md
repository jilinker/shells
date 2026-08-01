# Linux Security Manager

`linux_security.sh` 是面向 Debian 和 Ubuntu 的交互式安全管理脚本，包含 UFW SSH 和 Fail2Ban 管理

## 远程执行

首次运行会安装到 `/usr/local/bin/lsec` 并立即打开菜单

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh)
```

没有 curl 时使用 wget

```bash
bash <(wget -qO- https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh)
```

脚本只允许 root 运行，非 root 会退出并提示使用 sudo

安装后直接运行

```bash
lsec
lsec upgrade
lsec uninstall
```

`upgrade` 始终拉取 `main` 最新版，`uninstall` 只删除程序并保留全部安全配置

远程执行会信任当时 `main` 分支中的内容，执行前可先在 GitHub 查看脚本

## 本地执行

```bash
sudo ./linux_security.sh
```

运行自检

```bash
bash tests/run_all.sh
```

## 转发事务安全

完整端口转发使用原子事务管理 NAT、UFW 路由规则、状态登记和脚本拥有的 IPv4 forwarding 变更。一次确认的 TCP+UDP 批次要么全部通过本机验证，要么恢复事务前快照；无法验证回滚时会进入保护锁，禁止继续修改，但保留状态检查、诊断导出和恢复操作。

执行前会显示规则标记、涉及文件、回滚范围和验证边界，并提供执行、仅运行前置检查、取消三个选项。缺少组件时可选择自动安装或取消；同参数旧规则只能在用户明确选中全部精确标记后覆盖。

中转机和落地机的配置示例、旧状态迁移、IPv4 恢复、备份保留及故障处理见 [转发事务与恢复指南](docs/forwarding-transaction-recovery.md)。

## 只读系统安全检查

主菜单选择 `4` 可一次性检查 SSH 加固与监听端口 root 公钥 UFW Fail2Ban 及 Docker 防火墙风险

检查仅显示通过 警告和未知结果 不安装软件 不修改配置 不重启服务
