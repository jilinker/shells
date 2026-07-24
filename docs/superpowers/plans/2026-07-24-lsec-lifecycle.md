# lsec Installation Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Install the remotely executed security manager as `lsec` with explicit upgrade and safe program only uninstall commands

**Architecture:** Keep lifecycle behavior inside `linux_security.sh` and install that same validated file at `/usr/local/bin/lsec`. Detect only process substitution sources for automatic installation while local script execution continues unchanged

**Tech Stack:** Bash curl wget install mktemp GitHub Raw

---

## File structure

- Modify `linux_security.sh` for install validation download upgrade uninstall and argument dispatch
- Modify `tests/linux_security_self_test.sh` for temporary directory lifecycle checks
- Modify `README.md` for short first run commands and persistent command usage

### Task 1: Candidate validation and installation

**Files:**
- Modify: `tests/linux_security_self_test.sh`
- Modify: `linux_security.sh`

- [x] **Step 1: Add failing lifecycle assertions**

Use a temporary install target so tests never touch `/usr/local`

```bash
INSTALL_PATH="$TEST_TMP/lsec"
assert_eq yes "$(is_streamed_source /dev/fd/63 && echo yes)"
assert_fails is_streamed_source ./linux_security.sh
validate_lsec_candidate "$ROOT_DIR/linux_security.sh"
install_lsec_candidate "$ROOT_DIR/linux_security.sh"
assert_eq 755 "$(stat -f '%Lp' "$INSTALL_PATH" 2>/dev/null || stat -c '%a' "$INSTALL_PATH")"
cmp -s "$ROOT_DIR/linux_security.sh" "$INSTALL_PATH"
```

- [x] **Step 2: Run the self check and verify it fails**

Run: `./tests/linux_security_self_test.sh`

Expected: nonzero exit because `is_streamed_source` is undefined

- [x] **Step 3: Add lifecycle constants and pure source detection**

```bash
VERSION="3.1.0"
INSTALL_PATH=${INSTALL_PATH:-/usr/local/bin/lsec}
REMOTE_URL=${REMOTE_URL:-https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh}
PROGRAM_MARKER='PROGRAM_NAME="Linux 服务器安全防护管理器"'

is_streamed_source() {
    case "$1" in
        /dev/fd/*|/proc/self/fd/*) return 0 ;;
        *) return 1 ;;
    esac
}
```

- [x] **Step 4: Implement validation and atomic installation**

```bash
validate_lsec_candidate() {
    local file=$1
    [[ -s "$file" ]] || return 1
    grep -Fq "$PROGRAM_MARKER" "$file" || return 1
    bash -n "$file"
}

install_lsec_candidate() {
    local source=$1
    local install_dir tmp
    validate_lsec_candidate "$source" || return 1
    install_dir=$(dirname "$INSTALL_PATH")
    install -d -m 755 "$install_dir" || return 1
    tmp=$(mktemp "${install_dir}/.lsec.XXXXXX") || return 1
    if ! install -m 755 "$source" "$tmp" || ! mv -f "$tmp" "$INSTALL_PATH"; then
        rm -f "$tmp"
        return 1
    fi
}
```

- [x] **Step 5: Run checks**

Run: `./tests/linux_security_self_test.sh && bash -n linux_security.sh tests/linux_security_self_test.sh`

Expected: exit zero

### Task 2: Upgrade uninstall and command dispatch

**Files:**
- Modify: `tests/linux_security_self_test.sh`
- Modify: `linux_security.sh`

- [x] **Step 1: Add failing download and uninstall checks**

Create a fake curl command under the test temporary directory that copies `linux_security.sh` to curl's `-o` target then prepend that directory to `PATH`

```bash
FAKE_BIN="$TEST_TMP/bin"
mkdir -p "$FAKE_BIN"
cat > "$FAKE_BIN/curl" <<'EOF'
#!/usr/bin/env bash
while (( $# > 0 )); do
    case "$1" in
        -o) target=$2; shift 2 ;;
        *) shift ;;
    esac
done
cp "$FAKE_CURL_SOURCE" "$target"
EOF
chmod +x "$FAKE_BIN/curl"
export FAKE_CURL_SOURCE="$ROOT_DIR/linux_security.sh"
PATH="$FAKE_BIN:$PATH"
REMOTE_URL=https://example.invalid/linux_security.sh
download_lsec_candidate "$TEST_TMP/downloaded"
validate_lsec_candidate "$TEST_TMP/downloaded"
remove_installed_lsec
assert_fails test -e "$INSTALL_PATH"
test -e "$ROOT_DIR/linux_security.sh"
```

- [x] **Step 2: Run the self check and verify it fails**

Run: `./tests/linux_security_self_test.sh`

Expected: nonzero exit because `download_lsec_candidate` is undefined

- [x] **Step 3: Implement downloader selection**

```bash
download_lsec_candidate() {
    local target=$1
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$REMOTE_URL" -o "$target"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$target" "$REMOTE_URL"
    else
        error "需要 curl 或 wget 才能升级"
        return 1
    fi
}
```

- [x] **Step 4: Implement upgrade and uninstall cores**

Upgrade downloads to `mktemp` validates then calls `install_lsec_candidate` and always removes the temporary file

Uninstall requires the existing `confirm` helper with default `N` then removes only `INSTALL_PATH`

```bash
remove_installed_lsec() {
    rm -f "$INSTALL_PATH"
}
```

- [x] **Step 5: Implement dispatch and streamed installation**

Before the menu dispatch recognized arguments

```bash
case "${1:-}" in
    upgrade) upgrade_lsec; return ;;
    uninstall) uninstall_lsec; return ;;
    "") ;;
    *) show_lsec_usage; return 2 ;;
esac
```

When `BASH_SOURCE[0]` is streamed validate and install it then execute `INSTALL_PATH` so stdin stays attached to the terminal

- [x] **Step 6: Run checks**

Run: `./tests/linux_security_self_test.sh && bash -n linux_security.sh tests/linux_security_self_test.sh`

Expected: exit zero

### Task 3: Documentation and final verification

**Files:**
- Modify: `README.md`
- Modify: `linux_security.sh`
- Modify: `docs/superpowers/plans/2026-07-24-lsec-lifecycle.md`

- [x] **Step 1: Replace the long remote command**

Document the primary curl command and separate wget fallback

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh)
bash <(wget -qO- https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh)
```

Document `lsec` `lsec upgrade` and `lsec uninstall`

- [x] **Step 2: Run complete local verification**

Run: `./tests/linux_security_self_test.sh`

Expected: `linux security self test passed`

Run: `bash -n linux_security.sh tests/linux_security_self_test.sh`

Expected: exit zero

Run: `git diff --check`

Expected: exit zero

- [x] **Step 3: Review and commit**

```bash
git add README.md linux_security.sh tests/linux_security_self_test.sh docs/superpowers/plans/2026-07-24-lsec-lifecycle.md
git commit -m "feat: add lsec lifecycle commands"
```
