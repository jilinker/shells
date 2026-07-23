# Linux Security Manager SSH and Fail2Ban Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add safe root only SSH key hardening two phase port migration and isolated Fail2Ban management to the existing interactive Linux security manager

**Architecture:** Create one standalone script by inheriting the complete existing UFW implementation then add SSH and Fail2Ban modules using the same validation confirmation logging and menu patterns. Add one shell self check that sources the new script and exercises pure functions while all host mutations remain behind explicit interactive actions with backups validation and rollback

**Tech Stack:** Bash systemd OpenSSH UFW Fail2Ban apt-get

---

## File structure

- Create `linux_security.sh` with the complete inherited UFW implementation plus root enforcement SSH management Fail2Ban management and menu wiring
- Leave `linux_security_manager.sh` unchanged and do not source or execute it from the new script
- Create `tests/linux_security_self_test.sh` for pure validation rendering and state checks

### Task 1: Root enforcement and reusable safe file helpers

**Files:**
- Create: `linux_security.sh`
- Create: `tests/linux_security_self_test.sh`

- [ ] **Step 1: Write the failing root and helper self checks**

Create an executable test that sources the manager and checks the pure helpers without touching `/etc`

```bash
#!/usr/bin/env bash
set -Eeuo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/linux_security.sh"

validate_port 22
! validate_port 0
! validate_port 65536
validate_ssh_public_key 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBogusButStructurallyValidPayload root@test'
! validate_ssh_public_key 'not-a-key'
[[ "$(render_ssh_hardening)" == *'PasswordAuthentication no'* ]]
[[ "$(render_fail2ban_config no 2222)" == *'[sshd]'* ]]
[[ "$(render_fail2ban_config yes 2222)" == *'[recidive]'* ]]
```

- [ ] **Step 2: Run the self check and verify it fails**

Run: `bash tests/linux_security_self_test.sh`

Expected: nonzero exit because `validate_ssh_public_key` is not defined

- [ ] **Step 3: Add constants root enforcement and shared helpers**

Add root only paths and package helpers near the existing constants

```bash
SSH_CONFIG_DIR=/etc/ssh/sshd_config.d
SSH_MAIN_CONFIG=/etc/ssh/sshd_config
SSH_PORT_CONFIG="$SSH_CONFIG_DIR/99-security-manager-port.conf"
SSH_SECURITY_CONFIG="$SSH_CONFIG_DIR/99-security-manager-security.conf"
SSH_STATE_DIR=/etc/ssh/security-manager
SSH_PORT_STATE="$SSH_STATE_DIR/port-migration.tsv"
SSH_SOCKET_DROPIN_DIR=/etc/systemd/system/ssh.socket.d
SSH_SOCKET_DROPIN="$SSH_SOCKET_DROPIN_DIR/99-security-manager.conf"
AUTHORIZED_KEYS=/root/.ssh/authorized_keys
FAIL2BAN_CONFIG=/etc/fail2ban/jail.d/99-security-manager.local
```

Change `main` to reject non root execution before showing menus

```bash
main() {
    require_root || exit 1
    main_menu
}
```

Add narrowly scoped helpers

```bash
backup_file() {
    local file=$1
    [[ -e "$file" ]] || return 0
    local backup="${file}.bak.$(date +%Y%m%d%H%M%S)"
    cp -a "$file" "$backup"
    printf '%s\n' "$backup"
}

ensure_apt_package() {
    local command_name=$1 package_name=$2
    command -v "$command_name" >/dev/null 2>&1 && return 0
    confirm "是否安装 ${package_name}？" N || return 1
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y "$package_name"
}
```

- [ ] **Step 4: Run syntax validation**

Run: `bash -n linux_security.sh tests/linux_security_self_test.sh`

Expected: exit zero

- [ ] **Step 5: Commit the foundation**

```bash
git add linux_security.sh tests/linux_security_self_test.sh
git commit -m "feat: add security manager foundation"
```

### Task 2: Root public key management and SSH hardening

**Files:**
- Modify: `linux_security.sh`
- Test: `tests/linux_security_self_test.sh`

- [ ] **Step 1: Add failing public key and hardening checks**

Extend the self check with duplicate detection and exact rendering assertions

```bash
valid_key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBogusButStructurallyValidPayload root@test'
validate_ssh_public_key "$valid_key"
! validate_ssh_public_key 'ssh-rsa missing-body'
expected_hardening=$'PermitRootLogin prohibit-password\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nMaxAuthTries 3\nLoginGraceTime 30'
[[ "$(render_ssh_hardening)" == "$expected_hardening" ]]
```

- [ ] **Step 2: Run the self check and verify the new assertion fails**

Run: `bash tests/linux_security_self_test.sh`

Expected: nonzero exit until rendering is implemented

- [ ] **Step 3: Implement public key validation and append**

Accept one OpenSSH public key line at a time validate the key type and base64 body then append only when absent

```bash
validate_ssh_public_key() {
    local key=${1:-} type body extra
    read -r type body extra <<< "$key"
    [[ "$type" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))$ ]]
    [[ "$body" =~ ^[A-Za-z0-9+/]+={0,2}$ ]]
}

append_root_public_key() {
    local key
    read -r -p "请粘贴客户端 SSH 公钥: " key
    validate_ssh_public_key "$key" || { error "SSH 公钥格式无效"; return 1; }
    install -d -m 700 /root/.ssh
    touch "$AUTHORIZED_KEYS"
    chmod 600 "$AUTHORIZED_KEYS"
    grep -qxF "$key" "$AUTHORIZED_KEYS" || printf '%s\n' "$key" >> "$AUTHORIZED_KEYS"
}
```

- [ ] **Step 4: Implement managed hardening with validation rollback**

Render only the approved settings and write them atomically after confirming that a valid authorized key exists

```bash
render_ssh_hardening() {
    printf '%s\n' \
        'PermitRootLogin prohibit-password' \
        'PubkeyAuthentication yes' \
        'PasswordAuthentication no' \
        'KbdInteractiveAuthentication no' \
        'MaxAuthTries 3' \
        'LoginGraceTime 30'
}
```

The action backs up the managed file writes a temporary file installs it with mode `600` runs `sshd -t` and restores the backup or removes the new file on failure before reloading the detected SSH unit

- [ ] **Step 5: Run the self check and syntax check**

Run: `bash tests/linux_security_self_test.sh && bash -n linux_security.sh`

Expected: exit zero

- [ ] **Step 6: Commit key management and hardening**

```bash
git add linux_security.sh tests/linux_security_self_test.sh
git commit -m "feat: manage root SSH keys and hardening"
```

### Task 3: Two phase SSH port migration

**Files:**
- Modify: `linux_security.sh`
- Test: `tests/linux_security_self_test.sh`

- [ ] **Step 1: Add failing configuration rendering checks**

```bash
[[ "$(render_ssh_ports 22 2222)" == $'Port 22\nPort 2222' ]]
[[ "$(render_ssh_ports 2222)" == 'Port 2222' ]]
[[ "$(render_ssh_socket_ports 22 2222)" == *'ListenStream=2222'* ]]
```

- [ ] **Step 2: Run the self check and verify it fails**

Run: `bash tests/linux_security_self_test.sh`

Expected: nonzero exit because the renderers are not defined

- [ ] **Step 3: Implement effective port and service detection**

Reuse `detect_ssh_ports` and add helpers that return all effective ports the `ssh` or `sshd` service name and whether `ssh.socket` is enabled or active

```bash
ssh_service_name() {
    systemctl list-unit-files ssh.service >/dev/null 2>&1 && printf ssh || printf sshd
}

ssh_socket_managed() {
    systemctl is-enabled --quiet ssh.socket 2>/dev/null || systemctl is-active --quiet ssh.socket 2>/dev/null
}
```

- [ ] **Step 4: Implement pure port and socket renderers**

```bash
render_ssh_ports() {
    local port
    for port in "$@"; do printf 'Port %s\n' "$port"; done
}

render_ssh_socket_ports() {
    local port
    printf '[Socket]\nListenStream=\n'
    for port in "$@"; do printf 'ListenStream=%s\n' "$port"; done
}
```

- [ ] **Step 5: Implement migration start**

Validate a distinct unused target port create root only state write both ports to the managed SSH file add a tagged UFW rule when UFW exists and write a socket drop-in only when socket activation is detected

Validate with `sshd -t` then run `systemctl daemon-reload` and reload or restart the detected service or socket

On any failure restore all backups remove newly created managed files reload the previous configuration and keep no state record

- [ ] **Step 6: Implement migration finish**

Read the exact old and new ports from state require explicit confirmation rewrite managed SSH and socket files with only the new port and comment only active `Port OLD` lines outside the managed file

Use a temporary file and this match shape so commented lines and unrelated ports remain unchanged

```bash
awk -v port="$old_port" '
    $0 ~ "^[[:space:]]*Port[[:space:]]+" port "([[:space:]]|$)" { print "# security-manager migrated " $0; next }
    { print }
' "$file"
```

After validation and reload remove UFW rules only by the script comment and clear state

- [ ] **Step 7: Run all local checks**

Run: `bash tests/linux_security_self_test.sh && bash -n linux_security.sh`

Expected: exit zero

- [ ] **Step 8: Commit port migration**

```bash
git add linux_security.sh tests/linux_security_self_test.sh
git commit -m "feat: add safe SSH port migration"
```

### Task 4: Fail2Ban isolated jail management

**Files:**
- Modify: `linux_security.sh`
- Test: `tests/linux_security_self_test.sh`

- [ ] **Step 1: Add failing Fail2Ban rendering checks**

```bash
sshd_only=$(render_fail2ban_config no 2222)
[[ "$sshd_only" == *'port = 2222'* ]]
[[ "$sshd_only" != *'[recidive]'* ]]
with_recidive=$(render_fail2ban_config yes 2222)
[[ "$with_recidive" == *'findtime = 7d'* ]]
[[ "$with_recidive" == *'bantime = 30d'* ]]
```

- [ ] **Step 2: Run the self check and verify it fails**

Run: `bash tests/linux_security_self_test.sh`

Expected: nonzero exit until exact rendering is implemented

- [ ] **Step 3: Implement isolated configuration rendering**

Render the approved defaults and enabled `sshd` jail using all effective SSH ports joined by commas

Append the approved `recidive` block only when the function receives `yes`

Do not set a custom ban action and do not add the current client address to `ignoreip`

- [ ] **Step 4: Implement install validate and service controls**

Install `fail2ban` and `python3-systemd` only after confirmation write only `/etc/fail2ban/jail.d/99-security-manager.local` back up an existing managed file and require `fail2ban-client -t` before restart

Provide status start stop restart and enable operations with explicit confirmation for stop

- [ ] **Step 5: Run all local checks**

Run: `bash tests/linux_security_self_test.sh && bash -n linux_security.sh`

Expected: exit zero

- [ ] **Step 6: Commit Fail2Ban management**

```bash
git add linux_security.sh tests/linux_security_self_test.sh
git commit -m "feat: add Fail2Ban management"
```

### Task 5: Menu integration and final verification

**Files:**
- Modify: `linux_security.sh`
- Test: `tests/linux_security_self_test.sh`

- [ ] **Step 1: Add SSH and Fail2Ban menus**

Replace the two placeholder menu actions with `ssh_management_menu` and `fail2ban_management_menu`

Keep system security inspection on `module_not_implemented`

Each module performs Debian package and executable checks only after entry

- [ ] **Step 2: Update program metadata**

Change the header description to list UFW SSH and Fail2Ban and bump the version to `3.0.0`

- [ ] **Step 3: Run required checks**

Run: `bash -n linux_security.sh tests/linux_security_self_test.sh`

Expected: exit zero

Run: `bash tests/linux_security_self_test.sh`

Expected: exit zero with a final success line

Run: `shellcheck linux_security.sh tests/linux_security_self_test.sh` when ShellCheck is installed

Expected: exit zero or documented warnings that cannot be reproduced on the current host

- [ ] **Step 4: Inspect the final diff**

Run: `git diff --check && git status --short && git diff --stat HEAD~4..HEAD`

Expected: no whitespace errors and `linux_security_manager.sh` remains unchanged

- [ ] **Step 5: Commit menu integration**

```bash
git add linux_security.sh tests/linux_security_self_test.sh docs/superpowers/plans/2026-07-23-linux-security-manager.md docs/superpowers/specs/2026-07-23-linux-security-manager-design.md
git commit -m "feat: complete Linux security management menus"
```
