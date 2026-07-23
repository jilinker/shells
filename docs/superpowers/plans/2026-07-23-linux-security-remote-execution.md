# Linux Security Remote Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a documented one line command that runs the latest `linux_security.sh` from GitHub without writing it to disk

**Architecture:** Keep the security manager standalone and add no launcher file. Document one Bash command that chooses curl or wget checks the fetch result retains the script in memory and preserves terminal input for the interactive menu

**Tech Stack:** Bash curl wget GitHub Raw

---

### Task 1: Document and verify remote execution

**Files:**
- Create: `README.md`
- Modify: `linux_security.sh`
- Modify: `tests/linux_security_self_test.sh`

- [ ] **Step 1: Add failing documentation assertions**

```bash
remote_url='https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh'
grep -Fq "$remote_url" "$ROOT_DIR/README.md"
grep -Fq 'command -v curl' "$ROOT_DIR/README.md"
grep -Fq 'command -v wget' "$ROOT_DIR/README.md"
grep -Fq "$remote_url" "$ROOT_DIR/linux_security.sh"
```

- [ ] **Step 2: Run the self check and verify it fails**

Run: `./tests/linux_security_self_test.sh`

Expected: nonzero exit because `README.md` does not exist

- [ ] **Step 3: Add the README and script header command**

Use this exact non persistent command in both locations

```bash
bash -c 'u=https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh; if command -v curl >/dev/null 2>&1; then s=$(curl -fsSL "$u") || exit 1; elif command -v wget >/dev/null 2>&1; then s=$(wget -qO- "$u") || exit 1; else echo "需要 curl 或 wget" >&2; exit 1; fi; bash <(printf "%s\n" "$s")'
```

Document that the command always executes the mutable `main` branch and must be run again with sudo after the script rejects a non root user

- [ ] **Step 4: Run local verification**

Run: `./tests/linux_security_self_test.sh && bash -n linux_security.sh tests/linux_security_self_test.sh`

Expected: exit zero

- [ ] **Step 5: Commit and push**

```bash
git add README.md linux_security.sh tests/linux_security_self_test.sh docs/superpowers
git commit -m "feat: add remote Linux security execution"
git push origin main
```

- [ ] **Step 6: Verify GitHub Raw**

Fetch the raw URL and verify the response contains `VERSION="3.0.0"` and exits through the root guard when executed as a non root user

