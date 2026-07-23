# Linux Security Manager

`linux_security.sh` 是面向 Debian 和 Ubuntu 的交互式安全管理脚本，包含 UFW SSH 和 Fail2Ban 管理

## 远程执行

以下命令始终执行 GitHub `main` 分支的最新版本，不会把脚本保存到磁盘

```bash
bash -c 'u=https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh; if command -v curl >/dev/null 2>&1; then s=$(curl -fsSL "$u") || exit 1; elif command -v wget >/dev/null 2>&1; then s=$(wget -qO- "$u") || exit 1; else echo "需要 curl 或 wget" >&2; exit 1; fi; bash <(printf "%s\n" "$s")'
```

脚本只允许 root 运行，非 root 会退出并提示使用 sudo

```bash
sudo bash -c 'u=https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh; if command -v curl >/dev/null 2>&1; then s=$(curl -fsSL "$u") || exit 1; elif command -v wget >/dev/null 2>&1; then s=$(wget -qO- "$u") || exit 1; else echo "需要 curl 或 wget" >&2; exit 1; fi; bash <(printf "%s\n" "$s")'
```

远程执行会信任当时 `main` 分支中的内容，执行前可先在 GitHub 查看脚本

## 本地执行

```bash
sudo ./linux_security.sh
```

运行自检

```bash
./tests/linux_security_self_test.sh
```
