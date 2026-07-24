# UFW Menu Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Cache UFW status output inside the UFW module so submenu navigation does not repeatedly launch synchronous UFW commands

**Architecture:** Add one process-local snapshot with explicit refresh ensure and invalidation helpers. Read-only menu rendering uses the snapshot while all mutation helpers keep using live UFW commands and invalidate the snapshot after every attempted action

**Tech Stack:** Bash UFW existing self-test script

---

## File structure

- Modify `linux_security.sh` for snapshot state helpers cached rendering and invalidation points
- Modify `tests/linux_security_self_test.sh` for command-count refresh failure and invalidation checks

### Task 1: Snapshot lifecycle

**Files:**
- Modify: `tests/linux_security_self_test.sh`
- Modify: `linux_security.sh`

- [x] **Step 1: Add a failing snapshot lifecycle test**

Add before the existing security-check command mocks:

```bash
UFW_CALL_LOG="$TEST_TMP/ufw-call-log"
UFW_FAKE_FAIL=no
ufw() {
    printf '%s\n' "$*" >> "$UFW_CALL_LOG"
    [[ "$UFW_FAKE_FAIL" == no ]] || return 1
    case "$*" in
        'status numbered') printf '%s\n' 'Status: active' '[ 1] 22/tcp ALLOW IN Anywhere' ;;
        'status verbose') printf '%s\n' 'Status: active' 'Default: deny (incoming), allow (outgoing), deny (routed)' ;;
        'show added') printf '%s\n' 'Added user rules (see ufw status)' 'ufw allow 22/tcp' ;;
        *) return 1 ;;
    esac
}

invalidate_ufw_snapshot
ensure_ufw_snapshot
assert_eq 3 "$(wc -l < "$UFW_CALL_LOG" | tr -d ' ')"
ensure_ufw_snapshot
assert_eq 3 "$(wc -l < "$UFW_CALL_LOG" | tr -d ' ')"
ufw_snapshot_active
assert_contains "$UFW_STATUS_NUMBERED_CACHE" '[ 1] 22/tcp ALLOW IN Anywhere'

invalidate_ufw_snapshot
ensure_ufw_snapshot
assert_eq 6 "$(wc -l < "$UFW_CALL_LOG" | tr -d ' ')"

invalidate_ufw_snapshot
UFW_FAKE_FAIL=yes
assert_fails ensure_ufw_snapshot
assert_eq 0 "$UFW_SNAPSHOT_READY"
UFW_FAKE_FAIL=no
: > "$UFW_CALL_LOG"
ensure_ufw_snapshot
assert_eq 3 "$(wc -l < "$UFW_CALL_LOG" | tr -d ' ')"
```

- [x] **Step 2: Run the self-check and verify red**

Run: `./tests/linux_security_self_test.sh`

Expected: nonzero exit because `invalidate_ufw_snapshot` is undefined

- [x] **Step 3: Add snapshot state and lifecycle helpers**

Add beside the existing UFW state globals and `is_ufw_active`:

```bash
UFW_SNAPSHOT_READY=0
UFW_STATUS_NUMBERED_CACHE=
UFW_STATUS_VERBOSE_CACHE=
UFW_SHOW_ADDED_CACHE=

# 清除 UFW 状态快照
invalidate_ufw_snapshot() {
    UFW_SNAPSHOT_READY=0
    UFW_STATUS_NUMBERED_CACHE=
    UFW_STATUS_VERBOSE_CACHE=
    UFW_SHOW_ADDED_CACHE=
}

# 刷新 UFW 状态快照
refresh_ufw_snapshot() {
    local numbered verbose added
    if ! numbered=$(ufw status numbered 2>&1) \
        || ! verbose=$(ufw status verbose 2>&1) \
        || ! added=$(ufw show added 2>&1); then
        invalidate_ufw_snapshot
        error "UFW 状态读取失败"
        return 1
    fi
    UFW_STATUS_NUMBERED_CACHE=$numbered
    UFW_STATUS_VERBOSE_CACHE=$verbose
    UFW_SHOW_ADDED_CACHE=$added
    UFW_SNAPSHOT_READY=1
}

# 确保 UFW 状态快照可用
ensure_ufw_snapshot() {
    (( UFW_SNAPSHOT_READY == 1 )) || refresh_ufw_snapshot
}

# 检查快照中的 UFW 状态
ufw_snapshot_active() {
    ensure_ufw_snapshot || return 1
    grep -q '^Status: active$' <<< "$UFW_STATUS_NUMBERED_CACHE"
}
```

Keep `is_ufw_active` unchanged because mutation paths require live state.

- [x] **Step 4: Run checks and commit**

Run: `./tests/linux_security_self_test.sh && bash -n linux_security.sh tests/linux_security_self_test.sh`

Expected: `linux security self test passed` and exit zero

```bash
git add linux_security.sh tests/linux_security_self_test.sh
git commit -m "feat: add UFW status snapshot"
```

### Task 2: Cached rendering and invalidation

**Files:**
- Modify: `tests/linux_security_self_test.sh`
- Modify: `linux_security.sh`

- [x] **Step 1: Add failing cached rendering assertions**

After the successful snapshot assertions add:

```bash
rendered_rules="$TEST_TMP/ufw-rendered-rules"
show_direction_rules in "入站" > "$rendered_rules"
show_direction_rules in "入站" >> "$rendered_rules"
assert_contains "$(cat "$rendered_rules")" '22/tcp ALLOW IN Anywhere'
assert_eq 3 "$(wc -l < "$UFW_CALL_LOG" | tr -d ' ')"

invalidate_ufw_snapshot
ensure_ufw_snapshot
assert_eq 6 "$(wc -l < "$UFW_CALL_LOG" | tr -d ' ')"
```

The call count remains unchanged across both render calls and increases by three only after invalidation.

- [x] **Step 2: Run the self-check and verify red**

Run: `./tests/linux_security_self_test.sh`

Expected: nonzero exit because `show_direction_rules` still invokes live UFW commands

- [x] **Step 3: Change read-only helpers to consume cached text**

Replace the three read-only rendering helpers with:

```bash
show_saved_rules_when_inactive() {
    local direction=$1
    local line found=0
    ensure_ufw_snapshot || return 1

    while IFS= read -r line; do
        [[ "$line" == ufw\ * ]] || continue
        case "$direction" in
            in)
                [[ "$line" == "ufw route "* ]] && continue
                [[ " $line " == *" out "* ]] && continue
                ;;
            out)
                [[ " $line " == *" out "* ]] || continue
                ;;
            fwd)
                [[ "$line" == "ufw route "* ]] || continue
                ;;
        esac
        printf '  %s\n' "$line"
        found=1
    done <<< "$UFW_SHOW_ADDED_CACHE"

    (( found == 1 )) || echo "  暂无相关已保存规则"
}

show_direction_rules() {
    local direction=$1
    local title=$2
    local line found=0

    echo "--- ${title}现有配置 ---"
    ensure_ufw_snapshot || return 1
    if ! ufw_snapshot_active; then
        warn "UFW 当前未启用，下面显示的是已保存配置；启用后才能按编号删除"
        show_saved_rules_when_inactive "$direction"
        echo
        return 0
    fi

    while IFS= read -r line; do
        [[ "$line" =~ ^\[ ]] || continue
        if rule_line_matches_direction "$direction" "$line"; then
            printf '%s\n' "$line"
            found=1
        fi
    done <<< "$UFW_STATUS_NUMBERED_CACHE"

    (( found == 1 )) || echo "  暂无相关规则"
    echo
}

show_forward_overview() {
    local line found=0
    echo "--- 本脚本管理的完整端口转发 ---"
    list_forward_rules
    echo "--- UFW 路由放行规则 ---"
    ensure_ufw_snapshot || return 1
    if ufw_snapshot_active; then
        while IFS= read -r line; do
            [[ "$line" =~ ^\[ ]] || continue
            if rule_line_matches_direction fwd "$line"; then
                printf '%s\n' "$line"
                found=1
            fi
        done <<< "$UFW_STATUS_NUMBERED_CACHE"
        (( found == 1 )) || echo "  暂无 UFW 路由规则"
    else
        warn "UFW 当前未启用，显示已保存的 route 配置"
        show_saved_rules_when_inactive fwd
    fi
    echo
}
```

Keep deletion number validation on a live `ufw status numbered` result because it protects a mutation from stale rule numbers.

- [x] **Step 4: Change menu displays to consume the snapshot**

Replace inbound and outbound option 3 with:

```bash
3) ensure_ufw_snapshot && printf '%s\n' "$UFW_STATUS_NUMBERED_CACHE"; pause ;;
```

At the top of each `control_menu` loop render the cached verbose text:

```bash
ensure_ufw_snapshot && printf '%s\n' "$UFW_STATUS_VERBOSE_CACHE"
echo
```

Replace control option 1 with:

```bash
1)
    ensure_ufw_snapshot || true
    printf '%s\n' "$UFW_STATUS_NUMBERED_CACHE"
    echo
    printf '%s\n' "$UFW_SHOW_ADDED_CACHE"
    pause
    ;;
```

At the start of each UFW main loop derive the label from the snapshot:

```bash
if ! ensure_ufw_snapshot; then
    status_text="状态获取失败"
elif ufw_snapshot_active; then
    status_text="已启用"
else
    status_text="未启用"
fi
```

- [x] **Step 5: Invalidate after every mutation attempt**

Use these mutation cases in `inbound_menu`:

```bash
1) add_inbound_rule_interactive || true; invalidate_ufw_snapshot; pause ;;
2) delete_direction_rules_interactive "入站" in || true; invalidate_ufw_snapshot; pause ;;
```

Use these mutation cases in `outbound_menu`:

```bash
1) add_outbound_rule_interactive || true; invalidate_ufw_snapshot; pause ;;
2) delete_direction_rules_interactive "出站" out || true; invalidate_ufw_snapshot; pause ;;
```

Use these mutation cases in `forward_menu`:

```bash
1) add_forward_rule_interactive || true; invalidate_ufw_snapshot; pause ;;
2) delete_forward_rule_interactive || true; invalidate_ufw_snapshot; pause ;;
3)
    warn "该操作只删除 ufw route 规则，不会清理手工配置的 DNAT/SNAT"
    delete_direction_rules_interactive "转发" fwd || true
    invalidate_ufw_snapshot
    pause
    ;;
```

Use these control cases for initialization and reload:

```bash
2) setup_and_enable_ufw || true; invalidate_ufw_snapshot; pause ;;
3) reload_ufw || true; invalidate_ufw_snapshot; pause ;;
```

Use these control cases for disable and logging:

```bash
4)
    warn "禁用 UFW 会停止防火墙保护，但不会删除规则。"
    if confirm "确认禁用 UFW？" N; then
        ufw disable
    fi
    invalidate_ufw_snapshot
    pause
    ;;
5)
    echo "日志级别：1) off  2) low  3) medium  4) high  5) full"
    read -r -p "请选择 [默认 2]: " level
    level=${level:-2}
    case "$level" in
        1) ufw logging off ;;
        2) ufw logging low ;;
        3) ufw logging medium ;;
        4) ufw logging high ;;
        5) ufw logging full ;;
        *) warn "无效选项" ;;
    esac
    invalidate_ufw_snapshot
    pause
    ;;
```

At UFW module entry call this immediately after `init_state`, and call it again after the just-installed setup path:

```bash
invalidate_ufw_snapshot
```

- [x] **Step 6: Run checks and commit**

Run: `./tests/linux_security_self_test.sh && bash -n linux_security.sh tests/linux_security_self_test.sh && git diff --check`

Expected: `linux security self test passed` and exit zero

```bash
git add linux_security.sh tests/linux_security_self_test.sh
git commit -m "perf: cache UFW menu status"
```

### Task 3: Version and final verification

**Files:**
- Modify: `linux_security.sh`
- Modify: `tests/linux_security_self_test.sh`
- Modify: `docs/superpowers/plans/2026-07-24-ufw-menu-cache.md`

- [x] **Step 1: Add a failing version assertion**

Change the version assertion to:

```bash
grep -Fq 'VERSION="3.3.0"' "$ROOT_DIR/linux_security.sh"
```

- [x] **Step 2: Run the self-check and verify red**

Run: `./tests/linux_security_self_test.sh`

Expected: nonzero exit because the script is still version 3.2.1

- [x] **Step 3: Update the version**

```bash
VERSION="3.3.0"
```

- [x] **Step 4: Run final verification**

Run: `./tests/linux_security_self_test.sh`

Expected: `linux security self test passed`

Run: `bash -n linux_security.sh tests/linux_security_self_test.sh`

Expected: exit zero

Run: `git diff --check`

Expected: exit zero

- [x] **Step 5: Commit and push**

```bash
git add linux_security.sh tests/linux_security_self_test.sh docs/superpowers/plans/2026-07-24-ufw-menu-cache.md
git commit -m "perf: optimize UFW submenu navigation"
git push origin main
```
