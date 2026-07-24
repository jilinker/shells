# System Security Check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Replace the system security check placeholder with a one-shot read-only report for SSH UFW Fail2Ban and Docker risk

**Architecture:** Keep the feature inside `linux_security.sh` and reuse existing status helpers. Each check records one of three outcomes in shared counters, while the runner executes every check and prints a final summary without mutating the system

**Tech Stack:** Bash systemd OpenSSH UFW Fail2Ban iproute2

---

## File structure

- Modify `linux_security.sh` to add result accounting, six read-only checks, the report runner, and menu dispatch
- Modify `tests/linux_security_self_test.sh` to cover classification, SSH policy evaluation, continued execution, summary counts, and the no-mutation boundary
- Modify `README.md` to document the one-shot read-only report

### Task 1: Result accounting and SSH policy evaluation

**Files:**
- Modify: `tests/linux_security_self_test.sh`
- Modify: `linux_security.sh`

- [x] **Step 1: Add failing result and policy assertions**

Append these assertions before the existing final success message:

```bash
SECURITY_PASS_COUNT=0
SECURITY_WARNING_COUNT=0
SECURITY_UNKNOWN_COUNT=0
result_output="$TEST_TMP/security-result"
record_security_check pass "通过项" > "$result_output"
record_security_check warning "警告项" >> "$result_output"
record_security_check unknown "未知项" >> "$result_output"
assert_contains "$(cat "$result_output")" '[通过] 通过项'
assert_contains "$(cat "$result_output")" '[警告] 警告项'
assert_contains "$(cat "$result_output")" '[未知] 未知项'
assert_eq 1 "$SECURITY_PASS_COUNT"
assert_eq 1 "$SECURITY_WARNING_COUNT"
assert_eq 1 "$SECURITY_UNKNOWN_COUNT"

hardened_config=$'permitrootlogin prohibit-password\npubkeyauthentication yes\npasswordauthentication no\nkbdinteractiveauthentication no\nmaxauthtries 3\nlogingracetime 30'
ssh_effective_config_hardened "$hardened_config"
assert_fails ssh_effective_config_hardened "${hardened_config/passwordauthentication no/passwordauthentication yes}"
assert_fails ssh_effective_config_hardened "${hardened_config/maxauthtries 3/maxauthtries 4}"
```

- [x] **Step 2: Run the self-check and verify red**

Run: `./tests/linux_security_self_test.sh`

Expected: nonzero exit because `record_security_check` is undefined

- [x] **Step 3: Add counters and result rendering**

Add near the existing color and output helpers:

```bash
SECURITY_PASS_COUNT=0
SECURITY_WARNING_COUNT=0
SECURITY_UNKNOWN_COUNT=0

# 记录安全检查结果
record_security_check() {
    local status=$1
    local message=$2
    case "$status" in
        pass)
            ((SECURITY_PASS_COUNT+=1))
            printf "%b[通过]%b %s\n" "$GREEN" "$NC" "$message"
            ;;
        warning)
            ((SECURITY_WARNING_COUNT+=1))
            printf "%b[警告]%b %s\n" "$YELLOW" "$NC" "$message"
            ;;
        unknown)
            ((SECURITY_UNKNOWN_COUNT+=1))
            printf "%b[未知]%b %s\n" "$BLUE" "$NC" "$message"
            ;;
        *) return 1 ;;
    esac
}
```

- [x] **Step 4: Add effective SSH policy evaluation**

Add beside `show_ssh_status`:

```bash
# 检查 SSH 生效加固配置
ssh_effective_config_hardened() {
    local config=$1
    local max_tries grace_time
    grep -qx 'permitrootlogin prohibit-password' <<< "$config" || return 1
    grep -qx 'pubkeyauthentication yes' <<< "$config" || return 1
    grep -qx 'passwordauthentication no' <<< "$config" || return 1
    grep -qx 'kbdinteractiveauthentication no' <<< "$config" || return 1
    max_tries=$(awk '$1 == "maxauthtries" {print $2; exit}' <<< "$config")
    grace_time=$(awk '$1 == "logingracetime" {print $2; exit}' <<< "$config")
    [[ "$max_tries" =~ ^[0-9]+$ && "$grace_time" =~ ^[0-9]+$ ]] || return 1
    (( max_tries <= 3 && grace_time <= 30 ))
}
```

- [x] **Step 5: Run the self-check and commit**

Run: `./tests/linux_security_self_test.sh && bash -n linux_security.sh tests/linux_security_self_test.sh`

Expected: `linux security self test passed` and exit zero

```bash
git add linux_security.sh tests/linux_security_self_test.sh
git commit -m "feat: add security check result model"
```

### Task 2: Six read-only checks and report runner

**Files:**
- Modify: `tests/linux_security_self_test.sh`
- Modify: `linux_security.sh`

- [x] **Step 1: Add a failing complete-report check**

Append a deterministic environment at the end of the self-check before its success message:

```bash
sshd() {
    [[ ${1:-} == -T ]] || return 1
    printf '%s\n' "$hardened_config"
}
ssh_service_name() { echo ssh.service; }
ssh-keygen() { return 0; }
has_valid_authorized_key() { return 0; }
all_current_ssh_ports() { echo 2222; }
port_is_listening() { [[ $1 == 2222 ]]; }
ss() { return 0; }
is_ufw_active() { return 0; }
systemd_unit_loaded() { return 0; }
ufw() { return 0; }
fail2ban-client() { return 0; }
systemctl() {
    if [[ "$*" == *docker* ]]; then
        return 1
    fi
    return 0
}

mutation_called=0
install_apt_packages() { mutation_called=1; return 1; }
write_managed_content() { mutation_called=1; return 1; }
reload_ssh_runtime() { mutation_called=1; return 1; }
apply_fail2ban_config() { mutation_called=1; return 1; }
setup_and_enable_ufw() { mutation_called=1; return 1; }

security_report="$TEST_TMP/security-report"
run_security_check > "$security_report"
assert_contains "$(cat "$security_report")" '通过 6  警告 0  未知 0'
assert_eq 0 "$mutation_called"
```

- [x] **Step 2: Run the self-check and verify red**

Run: `./tests/linux_security_self_test.sh`

Expected: nonzero exit because `run_security_check` is undefined

- [x] **Step 3: Implement the SSH key and port checks**

Add before `main_menu`:

```bash
# 检查 SSH 服务与配置
security_check_ssh() {
    local service config
    command -v sshd >/dev/null 2>&1 || { record_security_check unknown "SSH 未安装"; return 0; }
    service=$(ssh_service_name 2>/dev/null) || { record_security_check unknown "未找到 SSH systemd 服务"; return 0; }
    systemctl is-active --quiet "$service" 2>/dev/null || { record_security_check warning "SSH 服务未运行"; return 0; }
    config=$(sshd -T 2>/dev/null) || { record_security_check warning "SSH 生效配置无法读取"; return 0; }
    if ssh_effective_config_hardened "$config"; then
        record_security_check pass "SSH 服务运行且生效配置已加固"
    else
        record_security_check warning "SSH 生效配置未达到加固目标"
    fi
}

# 检查 root 公钥
security_check_root_key() {
    command -v ssh-keygen >/dev/null 2>&1 || { record_security_check unknown "无法校验 root SSH 公钥"; return 0; }
    if has_valid_authorized_key; then
        record_security_check pass "root authorized_keys 包含有效公钥"
    else
        record_security_check warning "root authorized_keys 没有有效公钥"
    fi
}

# 检查 SSH 监听端口
security_check_ssh_ports() {
    local ports port
    command -v ss >/dev/null 2>&1 || { record_security_check unknown "缺少 ss 无法检查 SSH 监听端口"; return 0; }
    ports=$(all_current_ssh_ports 2>/dev/null || true)
    [[ -n "$ports" ]] || { record_security_check unknown "无法确定 SSH 监听端口"; return 0; }
    while IFS= read -r port; do
        port_is_listening "$port" || { record_security_check warning "SSH 端口 ${port} 未监听"; return 0; }
    done <<< "$ports"
    record_security_check pass "SSH 端口 $(paste -sd, <<< "$ports") 正在监听"
}
```

- [x] **Step 4: Implement UFW Fail2Ban and Docker checks**

```bash
# 检查 UFW 状态
security_check_ufw() {
    command -v ufw >/dev/null 2>&1 || { record_security_check unknown "UFW 未安装"; return 0; }
    if is_ufw_active; then
        record_security_check pass "UFW 已启用"
    else
        record_security_check warning "UFW 未启用"
    fi
}

# 检查 Fail2Ban 状态
security_check_fail2ban() {
    command -v fail2ban-client >/dev/null 2>&1 || { record_security_check unknown "Fail2Ban 未安装"; return 0; }
    systemd_unit_loaded fail2ban.service || { record_security_check unknown "未找到 Fail2Ban systemd 服务"; return 0; }
    systemctl is-active --quiet fail2ban.service 2>/dev/null || { record_security_check warning "Fail2Ban 服务未运行"; return 0; }
    if fail2ban-client status sshd >/dev/null 2>&1; then
        record_security_check pass "Fail2Ban 服务运行且 sshd jail 可用"
    else
        record_security_check warning "Fail2Ban sshd jail 不可用"
    fi
}

# 检查 Docker 防火墙风险
security_check_docker() {
    if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker.service 2>/dev/null; then
        record_security_check warning "Docker 正在运行 发布端口可能绕过普通 UFW 入站规则"
    else
        record_security_check pass "未检测到运行中的 Docker 防火墙绕过风险"
    fi
}
```

- [x] **Step 5: Implement the report runner**

```bash
# 运行系统安全检查
run_security_check() {
    SECURITY_PASS_COUNT=0
    SECURITY_WARNING_COUNT=0
    SECURITY_UNKNOWN_COUNT=0
    echo "========================================"
    echo "系统安全检查"
    echo "========================================"
    security_check_ssh || record_security_check unknown "SSH 检查执行失败"
    security_check_root_key || record_security_check unknown "root 公钥检查执行失败"
    security_check_ssh_ports || record_security_check unknown "SSH 端口检查执行失败"
    security_check_ufw || record_security_check unknown "UFW 检查执行失败"
    security_check_fail2ban || record_security_check unknown "Fail2Ban 检查执行失败"
    security_check_docker || record_security_check unknown "Docker 检查执行失败"
    echo "----------------------------------------"
    printf '汇总 通过 %d  警告 %d  未知 %d\n' "$SECURITY_PASS_COUNT" "$SECURITY_WARNING_COUNT" "$SECURITY_UNKNOWN_COUNT"
}
```

- [x] **Step 6: Run checks and commit**

Run: `./tests/linux_security_self_test.sh && bash -n linux_security.sh tests/linux_security_self_test.sh`

Expected: `linux security self test passed` and exit zero

```bash
git add linux_security.sh tests/linux_security_self_test.sh
git commit -m "feat: add read-only system security check"
```

### Task 3: Menu documentation and final verification

**Files:**
- Modify: `linux_security.sh`
- Modify: `README.md`
- Test: `tests/linux_security_self_test.sh`

- [x] **Step 1: Add failing menu and documentation assertions**

```bash
assert_not_contains "$(declare -f main_menu)" 'module_not_implemented'
assert_contains "$(declare -f main_menu)" 'run_security_check'
grep -Fq '只读系统安全检查' "$ROOT_DIR/README.md"
```

- [x] **Step 2: Run the self-check and verify red**

Run: `./tests/linux_security_self_test.sh`

Expected: nonzero exit because the menu still calls `module_not_implemented`

- [x] **Step 3: Connect the menu and update the version**

Change the version to `3.2.0`, remove `module_not_implemented`, and replace menu item 4 with:

```bash
echo "4) 系统安全检查"
```

Dispatch it with:

```bash
4) clear || true; run_security_check; pause ;;
```

- [x] **Step 4: Document the report**

Add to `README.md`:

```markdown
## 系统安全检查

主菜单选择 `4` 可一次性检查 SSH 加固与监听端口 root 公钥 UFW Fail2Ban 及 Docker 防火墙风险

检查仅显示通过 警告和未知结果 不安装软件 不修改配置 不重启服务
```

- [x] **Step 5: Run final verification**

Run: `./tests/linux_security_self_test.sh`

Expected: `linux security self test passed`

Run: `bash -n linux_security.sh tests/linux_security_self_test.sh`

Expected: exit zero

Run: `git diff --check`

Expected: exit zero

- [x] **Step 6: Commit and push**

```bash
git add README.md linux_security.sh tests/linux_security_self_test.sh docs/superpowers/plans/2026-07-24-system-security-check.md
git commit -m "feat: implement system security check"
git push origin main
```
