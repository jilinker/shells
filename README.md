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
./tests/linux_security_self_test.sh
```
