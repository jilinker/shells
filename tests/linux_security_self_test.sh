#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_TMP=$(mktemp -d)
trap 'rm -rf -- "$TEST_TMP"' EXIT

# shellcheck source=../linux_security.sh
source "$ROOT_DIR/linux_security.sh"

remote_url='https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh'
grep -Fq "$remote_url" "$ROOT_DIR/README.md"
grep -Fq "bash <(curl -fsSL $remote_url)" "$ROOT_DIR/README.md"
grep -Fq "bash <(wget -qO- $remote_url)" "$ROOT_DIR/README.md"
grep -Fq "$remote_url" "$ROOT_DIR/linux_security.sh"

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
printf 'n\n' | uninstall_lsec >/dev/null
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
    [[ "$1" != "fail" ]]
}

cleanup_ssh_migration_ufw_rules old new
assert_fails cleanup_ssh_migration_ufw_rules old fail

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

hardened_config=$'permitrootlogin prohibit-password\npubkeyauthentication yes\npasswordauthentication no\nkbdinteractiveauthentication no\nmaxauthtries 3\nlogingracetime 30'
ssh_effective_config_hardened "$hardened_config"
assert_fails ssh_effective_config_hardened "${hardened_config/passwordauthentication no/passwordauthentication yes}"
assert_fails ssh_effective_config_hardened "${hardened_config/maxauthtries 3/maxauthtries 4}"

printf 'linux security self test passed\n'
