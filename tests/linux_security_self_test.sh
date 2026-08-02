#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_TMP=$(mktemp -d)
trap 'rm -rf -- "$TEST_TMP"' EXIT

# shellcheck source=../linux_security.sh
LSEC_SOURCE_ONLY=1 source "$ROOT_DIR/linux_security.sh"

remote_url='https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh'
grep -Fq "$remote_url" "$ROOT_DIR/README.md"
grep -Fq "bash <(curl -fsSL $remote_url)" "$ROOT_DIR/README.md"
grep -Fq "bash <(wget -qO- $remote_url)" "$ROOT_DIR/README.md"
grep -Fq "$remote_url" "$ROOT_DIR/linux_security.sh"
grep -Fq 'VERSION="4.1.0"' "$ROOT_DIR/linux_security.sh"

# 断言命令失败
assert_fails() {
    if "$@"; then
        printf 'expected command to fail: %s\n' "$*" >&2
        exit 1
    fi
}

# 断言值相等
assert_eq() {
    local expected=$1
    local actual=$2
    if [[ "$actual" != "$expected" ]]; then
        printf 'expected <%s> but got <%s>\n' "$expected" "$actual" >&2
        exit 1
    fi
}

# 断言值不相等
assert_ne() {
    local left=$1
    local right=$2
    if [[ "$left" == "$right" ]]; then
        printf 'expected values to differ: <%s>\n' "$left" >&2
        exit 1
    fi
}

# 断言包含文本
assert_contains() {
    local text=$1
    local expected=$2
    if [[ "$text" != *"$expected"* ]]; then
        printf 'expected text to contain <%s>\n' "$expected" >&2
        exit 1
    fi
}

# 断言不包含文本
assert_not_contains() {
    local text=$1
    local unexpected=$2
    if [[ "$text" == *"$unexpected"* ]]; then
        printf 'expected text not to contain <%s>\n' "$unexpected" >&2
        exit 1
    fi
}

# 计算文件哈希
hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

configured_remote_url=$(env REMOTE_URL=https://example.invalid/linux_security.sh bash -c 'source "$1"; printf "%s\n" "$REMOTE_URL"' _ "$ROOT_DIR/linux_security.sh")
assert_eq "$remote_url" "$configured_remote_url"

INSTALL_PATH="$TEST_TMP/lsec"
is_streamed_source /dev/fd/63
is_streamed_source /proc/self/fd/10
assert_fails is_streamed_source ./linux_security.sh
validate_lsec_candidate "$ROOT_DIR/linux_security.sh"
install_lsec_candidate "$ROOT_DIR/linux_security.sh"
installed_mode=$(stat -f '%Lp' "$INSTALL_PATH" 2>/dev/null || stat -c '%a' "$INSTALL_PATH")
assert_eq 755 "$installed_mode"
cmp -s "$ROOT_DIR/linux_security.sh" "$INSTALL_PATH"

# 模拟 curl 下载
curl() {
    local target=
    while (( $# > 0 )); do
        case "$1" in
            -o) target=$2; shift 2 ;;
            *) shift ;;
        esac
    done
    cp "$FAKE_CURL_SOURCE" "$target"
}

FAKE_CURL_SOURCE="$ROOT_DIR/linux_security.sh"
download_lsec_candidate "$TEST_TMP/downloaded"
validate_lsec_candidate "$TEST_TMP/downloaded"

exec 9< "$ROOT_DIR/linux_security.sh"
cat <&9 >/dev/null
install_lsec_candidate /dev/fd/9
exec 9<&-
cmp -s "$ROOT_DIR/linux_security.sh" "$INSTALL_PATH"

printf 'invalid\n' > "$TEST_TMP/invalid"
FAKE_CURL_SOURCE="$TEST_TMP/invalid"
installed_before=$(hash_file "$INSTALL_PATH")
assert_fails upgrade_lsec >/dev/null 2>&1
installed_after=$(hash_file "$INSTALL_PATH")
assert_eq "$installed_before" "$installed_after"

upgrade_candidate="$TEST_TMP/upgrade-candidate"
cp "$ROOT_DIR/linux_security.sh" "$upgrade_candidate"
printf '\n# upgraded candidate\n' >> "$upgrade_candidate"
FAKE_CURL_SOURCE="$upgrade_candidate"
upgrade_lsec >/dev/null
cmp -s "$upgrade_candidate" "$INSTALL_PATH"

FAKE_BIN="$TEST_TMP/fake-bin"
mkdir -p "$FAKE_BIN"
printf '%s\n' '#!/bin/bash' '/bin/cp "$FAKE_CURL_SOURCE" "$2"' > "$FAKE_BIN/wget"
chmod +x "$FAKE_BIN/wget"
unset -f curl
original_path=$PATH
PATH=$FAKE_BIN
FAKE_CURL_SOURCE="$ROOT_DIR/linux_security.sh" download_lsec_candidate "$TEST_TMP/downloaded-by-wget"
PATH=$original_path
validate_lsec_candidate "$TEST_TMP/downloaded-by-wget"

preserved_config="$TEST_TMP/preserved-config"
touch "$preserved_config"
remove_installed_lsec
assert_fails test -e "$INSTALL_PATH"
test -e "$preserved_config"
test -e "$ROOT_DIR/linux_security.sh"

install_lsec_candidate "$ROOT_DIR/linux_security.sh"
set +e
printf 'n\n' | uninstall_lsec >/dev/null
uninstall_cancel_result=$?
set -e
assert_eq 10 "$uninstall_cancel_result"
test -e "$INSTALL_PATH"
printf 'y\n' | uninstall_lsec >/dev/null
assert_fails test -e "$INSTALL_PATH"
usage=$(show_lsec_usage)
assert_contains "$usage" 'lsec upgrade'
assert_contains "$usage" 'lsec uninstall'

validate_port 22
assert_fails validate_port 0
assert_fails validate_port 65536
validate_address_token_or_any 192.168.1.1
validate_address_token_or_any 192.168.1.0/24
validate_address_token_or_any 2001:db8::1
validate_address_token_or_any 2001:db8::/64
assert_fails validate_address_token_or_any 999.999.999.999
assert_fails validate_address_token_or_any 192.168.1.1/99
assert_fails validate_address_token_or_any 2001:::1

backup_source="$TEST_TMP/backup-source"
printf 'first\n' > "$backup_source"
backup_one=$(backup_file "$backup_source")
printf 'second\n' > "$backup_source"
backup_two=$(backup_file "$backup_source")
assert_ne "$backup_one" "$backup_two"
assert_eq 'first' "$(cat "$backup_one")"
assert_eq 'second' "$(cat "$backup_two")"

ssh-keygen -q -t ed25519 -N '' -f "$TEST_TMP/id_ed25519"
valid_key=$(cat "$TEST_TMP/id_ed25519.pub")
validate_ssh_public_key "$valid_key"
assert_fails validate_ssh_public_key 'not-a-key'
assert_fails validate_ssh_public_key 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBogusButStructurallyValidPayload root@test'

ROOT_SSH_DIR="$TEST_TMP/root-ssh"
AUTHORIZED_KEYS="$ROOT_SSH_DIR/authorized_keys"
install_root_public_key "$valid_key"
install_root_public_key "$valid_key"
has_valid_authorized_key
assert_eq 1 "$(grep -cFx "$valid_key" "$AUTHORIZED_KEYS")"

expected_hardening=$'PermitRootLogin prohibit-password\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nMaxAuthTries 3\nLoginGraceTime 30'
assert_eq "$expected_hardening" "$(render_ssh_hardening)"

assert_eq $'Port 22\nPort 2222' "$(render_ssh_ports 22 2222)"
assert_eq 'Port 2222' "$(render_ssh_ports 2222)"
assert_eq $'[Socket]\nListenStream=\nListenStream=22\nListenStream=2222' "$(render_ssh_socket_ports 22 2222)"
socket_status=$'22 (Stream)\n[::]:2222 (Stream)\n0.0.0.0:2200 (Stream)'
assert_eq $'22\n2200\n2222' "$(printf '%s\n' "$socket_status" | parse_ssh_socket_ports)"
ports_include_all $'22\n2222' 22 2222
assert_fails ports_include_all $'22\n2222' 22 2200

port_config=$'Port 22\nport 22\n  Port 2222 # keep\n# Port 22\nPort 2200'
expected_port_config=$'# security-manager migrated Port 22\n# security-manager migrated port 22\n  Port 2222 # keep\n# Port 22\nPort 2200'
assert_eq "$expected_port_config" "$(printf '%s\n' "$port_config" | comment_ssh_port 22)"

sshd_only=$(render_fail2ban_config no 2222)
assert_contains "$sshd_only" '[sshd]'
assert_contains "$sshd_only" 'port = 2222'
assert_not_contains "$sshd_only" '[recidive]'

with_recidive=$(render_fail2ban_config yes 2222)
assert_contains "$with_recidive" '[recidive]'
assert_contains "$with_recidive" 'findtime = 7d'
assert_contains "$with_recidive" 'bantime = 30d'

# 模拟 UFW 清理结果
delete_ssh_migration_ufw_rule() {
    [[ "$2" != "fail" ]]
}

cleanup_ssh_migration_ufw_rules 22 old 2222 new
assert_fails cleanup_ssh_migration_ufw_rules 22 old 2222 fail

# 完成迁移已切换 SSH 运行时后，如果 UFW 清理失败，必须恢复原端口集合并返回准确结果。
original_confirm=$(declare -f confirm)
original_collect_ssh_config_files=$(declare -f collect_ssh_config_files)
original_sshd=$(declare -f sshd 2>/dev/null || true)
original_reload_ssh_runtime=$(declare -f reload_ssh_runtime)
original_delete_ssh_migration_ufw_rule=$(declare -f delete_ssh_migration_ufw_rule)
original_preflight_ssh_migration_ufw_cleanup=$(declare -f preflight_ssh_migration_ufw_cleanup)
original_ssh_config_dir=$SSH_CONFIG_DIR
original_ssh_main_config=$SSH_MAIN_CONFIG
original_ssh_port_config=$SSH_PORT_CONFIG
original_ssh_state_dir=$SSH_STATE_DIR
original_ssh_port_state=$SSH_PORT_STATE
original_ssh_socket_dropin=$SSH_SOCKET_DROPIN

SSH_CONFIG_DIR="$TEST_TMP/ssh-finish/config.d"
SSH_MAIN_CONFIG="$TEST_TMP/ssh-finish/sshd_config"
SSH_PORT_CONFIG="$SSH_CONFIG_DIR/99-security-manager-port.conf"
SSH_STATE_DIR="$TEST_TMP/ssh-finish/state"
SSH_PORT_STATE="$SSH_STATE_DIR/port-migration.tsv"
SSH_SOCKET_DROPIN="$TEST_TMP/ssh-finish/ssh.socket.conf"
install -d -m 755 "$SSH_CONFIG_DIR" "$SSH_STATE_DIR"
printf 'Include /etc/ssh/sshd_config.d/*.conf\n' > "$SSH_MAIN_CONFIG"
printf 'Port 22\nPort 2222\n' > "$SSH_PORT_CONFIG"
printf '22\t2222\tno\tsecurity-manager-ssh-old-22\tsecurity-manager-ssh-new-2222\n' > "$SSH_PORT_STATE"
SSH_FINISH_RELOAD_LOG="$TEST_TMP/ssh-finish/reload.log"
: > "$SSH_FINISH_RELOAD_LOG"
confirm() { return 0; }
collect_ssh_config_files() { return 0; }
sshd() { [[ ${1:-} == -t ]]; }
reload_ssh_runtime() { printf '%s\n' "$*" >> "$SSH_FINISH_RELOAD_LOG"; }
preflight_ssh_migration_ufw_cleanup() { return 0; }
delete_ssh_migration_ufw_rule() { return 1; }

SSH_FINISH_OUTPUT="$TEST_TMP/ssh-finish/output.log"
set +e
finish_ssh_port_migration > "$SSH_FINISH_OUTPUT" 2>&1
ssh_finish_result=$?
set -e
assert_eq "$RESULT_APPLY_FAILED_ROLLED_BACK" "$ssh_finish_result"
assert_contains "$(cat "$SSH_FINISH_OUTPUT")" 'UFW 迁移规则清理失败，SSH 与 UFW 已验证回滚'
assert_eq $'Port 22\nPort 2222' "$(cat "$SSH_PORT_CONFIG")"
test -s "$SSH_PORT_STATE"
assert_contains "$(cat "$SSH_FINISH_RELOAD_LOG")" 'no 2222'
assert_contains "$(cat "$SSH_FINISH_RELOAD_LOG")" 'no 22 2222'

# 兼容现场的部分完成状态：SSH 已仅保留新端口、旧 UFW 规则已不存在、状态文件仍在。
printf 'Port 2222\n' > "$SSH_PORT_CONFIG"
: > "$SSH_FINISH_RELOAD_LOG"
preflight_ssh_migration_ufw_cleanup() { return 0; }
delete_ssh_migration_ufw_rule() { return 0; }
set +e
finish_ssh_port_migration > "$SSH_FINISH_OUTPUT" 2>&1
ssh_finish_result=$?
set -e
assert_eq "$RESULT_OK" "$ssh_finish_result"
assert_eq 'Port 2222' "$(cat "$SSH_PORT_CONFIG")"
assert_fails test -e "$SSH_PORT_STATE"
assert_contains "$(cat "$SSH_FINISH_OUTPUT")" 'SSH 已迁移到端口 2222'
assert_contains "$(cat "$SSH_FINISH_RELOAD_LOG")" 'no 2222'

eval "$original_confirm"
eval "$original_collect_ssh_config_files"
if [[ -n "$original_sshd" ]]; then eval "$original_sshd"; else unset -f sshd; fi
eval "$original_reload_ssh_runtime"
eval "$original_delete_ssh_migration_ufw_rule"
eval "$original_preflight_ssh_migration_ufw_cleanup"
SSH_CONFIG_DIR=$original_ssh_config_dir
SSH_MAIN_CONFIG=$original_ssh_main_config
SSH_PORT_CONFIG=$original_ssh_port_config
SSH_STATE_DIR=$original_ssh_state_dir
SSH_PORT_STATE=$original_ssh_port_state
SSH_SOCKET_DROPIN=$original_ssh_socket_dropin

RED=
GREEN=
YELLOW=
BLUE=
NC=
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

hardened_config=$'port 2222\npermitrootlogin prohibit-password\npubkeyauthentication yes\npasswordauthentication no\nkbdinteractiveauthentication no\nmaxauthtries 3\nlogingracetime 30'
ssh_effective_config_hardened "$hardened_config"
ssh_effective_config_hardened "${hardened_config/prohibit-password/without-password}"
assert_fails ssh_effective_config_hardened "${hardened_config/passwordauthentication no/passwordauthentication yes}"
assert_fails ssh_effective_config_hardened "${hardened_config/maxauthtries 3/maxauthtries 4}"

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
assert_fails ensure_ufw_snapshot >/dev/null 2>&1
assert_eq 0 "$UFW_SNAPSHOT_READY"
UFW_FAKE_FAIL=no
: > "$UFW_CALL_LOG"
ensure_ufw_snapshot
assert_eq 3 "$(wc -l < "$UFW_CALL_LOG" | tr -d ' ')"

rendered_rules="$TEST_TMP/ufw-rendered-rules"
show_direction_rules in "入站" > "$rendered_rules"
show_direction_rules in "入站" >> "$rendered_rules"
assert_contains "$(cat "$rendered_rules")" '22/tcp ALLOW IN Anywhere'
assert_eq 3 "$(wc -l < "$UFW_CALL_LOG" | tr -d ' ')"

invalidate_ufw_snapshot
ensure_ufw_snapshot
assert_eq 6 "$(wc -l < "$UFW_CALL_LOG" | tr -d ' ')"

sshd() {
    [[ ${1:-} == -T ]] || return 1
    printf '%s\n' "$hardened_config"
}
ssh_service_name() { echo ssh.service; }
has_valid_authorized_key() { return 0; }
all_current_ssh_ports() { echo 22; }
port_is_listening() { [[ $1 == 2222 ]]; }
ss() { return 0; }
is_ufw_active() { return 0; }
systemd_unit_loaded() { return 0; }
ufw() { return 0; }
fail2ban-client() { return 0; }
systemctl() {
    if [[ "$*" == *docker* || "$*" == *ssh.socket* ]]; then
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
assert_contains "$(cat "$security_report")" 'SSH 端口 2222 正在监听'
assert_contains "$(cat "$security_report")" '通过 6  警告 0  未知 0'
assert_eq 0 "$mutation_called"

original_security_check_ssh=$(declare -f security_check_ssh)
security_check_ssh() { return 1; }
run_security_check > "$security_report"
assert_contains "$(cat "$security_report")" '[未知] SSH 检查执行失败'
assert_contains "$(cat "$security_report")" '通过 5  警告 0  未知 1'
eval "$original_security_check_ssh"

sshd() {
    [[ ${1:-} == -T ]] || return 1
    printf '%s\n' "${hardened_config/passwordauthentication no/passwordauthentication yes}"
}
has_valid_authorized_key() { return 1; }
all_current_ssh_ports() { return 0; }
is_ufw_active() { return 1; }
fail2ban-client() { return 1; }
docker() { return 0; }
systemctl() { return 0; }
run_security_check > "$security_report"
assert_contains "$(cat "$security_report")" '通过 0  警告 5  未知 1'

assert_not_contains "$(declare -f main_menu)" 'module_not_implemented'
assert_contains "$(declare -f main_menu)" 'run_security_check'
grep -Fq '只读系统安全检查' "$ROOT_DIR/README.md"
assert_not_contains "$(declare -f inbound_menu)" 'ufw status numbered'
assert_not_contains "$(declare -f outbound_menu)" 'ufw status numbered'
assert_not_contains "$(declare -f control_menu)" 'ufw status verbose'
assert_contains "$(declare -f inbound_menu)" 'invalidate_ufw_snapshot'
assert_contains "$(declare -f outbound_menu)" 'invalidate_ufw_snapshot'
assert_contains "$(declare -f forward_menu)" 'invalidate_ufw_snapshot'
assert_contains "$(declare -f control_menu)" 'invalidate_ufw_snapshot'
assert_contains "$(declare -f ufw_management_menu)" 'ensure_ufw_snapshot'

printf 'linux security self test passed\n'
