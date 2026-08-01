#!/usr/bin/env bash
# Linux 服务器安全防护交互式管理器
# 包含 UFW SSH 和 Fail2Ban 管理模块
# 远程执行 bash <(curl -fsSL https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh)

set -Eeuo pipefail
export LC_ALL=C

PROGRAM_NAME="Linux 服务器安全防护管理器"
VERSION="4.0.2"
INSTALL_PATH=/usr/local/bin/lsec
unset REMOTE_URL
readonly REMOTE_URL=https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh
PROGRAM_MARKER='PROGRAM_NAME="Linux 服务器安全防护管理器"'
STATE_DIR="${LSEC_STATE_DIR:-/etc/ufw/relay-manager}"
STATE_FILE=
STATE_VERSION_FILE=
OPERATION_LOCK=
PROTECTED_LOCK=
TRANSACTION_DIR=
BACKUP_DIR=
IP_FORWARDING_STATE=
BEFORE_RULES="${LSEC_BEFORE_RULES:-/etc/ufw/before.rules}"
UFW_SYSCTL_FILE="${LSEC_UFW_SYSCTL_FILE:-/etc/ufw/sysctl.conf}"
NAT_BEGIN="# BEGIN UFW-RELAY-MANAGER RULES"
NAT_END="# END UFW-RELAY-MANAGER RULES"
UFW_JUST_INSTALLED=0
UFW_SNAPSHOT_READY=0
UFW_STATUS_NUMBERED_CACHE=
UFW_STATUS_VERBOSE_CACHE=
UFW_SHOW_ADDED_CACHE=
SSH_CONFIG_DIR="/etc/ssh/sshd_config.d"
SSH_MAIN_CONFIG="/etc/ssh/sshd_config"
SSH_PORT_CONFIG="${SSH_CONFIG_DIR}/99-security-manager-port.conf"
SSH_SECURITY_CONFIG="${SSH_CONFIG_DIR}/99-security-manager-security.conf"
SSH_STATE_DIR="/etc/ssh/security-manager"
SSH_PORT_STATE="${SSH_STATE_DIR}/port-migration.tsv"
SSH_SOCKET_DROPIN_DIR="/etc/systemd/system/ssh.socket.d"
SSH_SOCKET_DROPIN="${SSH_SOCKET_DROPIN_DIR}/99-security-manager.conf"
ROOT_SSH_DIR="/root/.ssh"
AUTHORIZED_KEYS="${ROOT_SSH_DIR}/authorized_keys"
FAIL2BAN_CONFIG="/etc/fail2ban/jail.d/99-security-manager.local"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
SECURITY_PASS_COUNT=0
SECURITY_WARNING_COUNT=0
SECURITY_UNKNOWN_COUNT=0

readonly RESULT_OK=0
readonly RESULT_CANCELLED=10
readonly RESULT_PRECHECK_FAILED=20
readonly RESULT_APPLY_FAILED_ROLLED_BACK=30
readonly RESULT_ROLLBACK_FAILED=40
readonly RESULT_VERIFY_FAILED_ROLLED_BACK=50
readonly RESULT_PROTECTED_LOCKOUT=60
readonly RESULT_REPAIR_REQUIRED=70
readonly MUTATION_LOCK_FD=9
readonly STATE_SCHEMA_VERSION=2
MUTATION_LOCK_HELD=0
MISSING_DEPENDENCIES=()
readonly FORWARD_DEPENDENCIES='flock ufw iptables iptables-save iptables-restore sysctl'
readonly UFW_RISK_CONFIRMATION='我确认SSH端口已放行并承担断连风险'

configure_state_paths() {
    STATE_FILE="${STATE_DIR}/forwarding.tsv"
    STATE_VERSION_FILE="${STATE_DIR}/state.version"
    OPERATION_LOCK="${STATE_DIR}/operation.lock"
    PROTECTED_LOCK="${STATE_DIR}/protected.lock"
    TRANSACTION_DIR="${STATE_DIR}/transactions"
    BACKUP_DIR="${STATE_DIR}/backups"
    IP_FORWARDING_STATE="${STATE_DIR}/ip-forwarding.tsv"
}

configure_state_paths

info()  { printf "%b[信息]%b %s\n" "$BLUE" "$NC" "$*"; }
ok()    { printf "%b[成功]%b %s\n" "$GREEN" "$NC" "$*"; }
warn()  { printf "%b[警告]%b %s\n" "$YELLOW" "$NC" "$*"; }
error() { printf "%b[错误]%b %s\n" "$RED" "$NC" "$*" >&2; }
die()   { error "$*"; exit 1; }

# 将内部结果转换为准确且稳定的用户提示。
result_message() {
    case ${1:-} in
        0)  printf '%s' '操作成功且已完成本机验证' ;;
        10) printf '%s' '操作已取消，未执行任何变更' ;;
        20) printf '%s' '前置检查失败，未执行任何变更' ;;
        30) printf '%s' '应用失败，已验证回滚' ;;
        40) printf '%s' '回滚失败，已进入保护锁定' ;;
        50) printf '%s' '应用后验证失败，已验证回滚' ;;
        60) printf '%s' '当前处于保护锁定，仅允许诊断与恢复' ;;
        70) printf '%s' '发现旧状态或漂移，必须先修复' ;;
        *)  printf '%s' '未知结果' ;;
    esac
}

normalize_result_code() {
    case ${1:-1} in
        0|10|20|30|40|50|60|70) return "${1:-1}" ;;
        *) return "$RESULT_PRECHECK_FAILED" ;;
    esac
}

run_mutation_action() {
    local operation=$1 function=$2 result
    shift 2
    if begin_mutation "$operation"; then :; else
        result=$?
        error "$(result_message "$result")"
        return "$result"
    fi
    if require_mutation_allowed; then :; else
        result=$?
        end_mutation
        error "$(result_message "$result")"
        return "$result"
    fi
    if "$function" "$@"; then result=$RESULT_OK; else
        result=$?
        normalize_result_code "$result" || result=$?
    fi
    end_mutation
    case "$result" in
        0) ok "$(result_message "$result")" ;;
        10) warn "$(result_message "$result")" ;;
        *) error "$(result_message "$result")" ;;
    esac
    return "$result"
}

# 获取所有系统变更共用的非阻塞排他锁。
begin_mutation() {
    local operation=${1:-未命名操作}

    bootstrap_flock_dependency || return $?
    if (( MUTATION_LOCK_HELD == 1 )); then
        error "当前进程已经持有全局变更锁"
        return "$RESULT_PRECHECK_FAILED"
    fi
    if ! install -d -m 700 "$STATE_DIR"; then
        error "无法创建状态目录：${STATE_DIR}"
        return "$RESULT_PRECHECK_FAILED"
    fi
    if ! exec 9>"$OPERATION_LOCK"; then
        error "无法打开全局变更锁：${OPERATION_LOCK}"
        return "$RESULT_PRECHECK_FAILED"
    fi
    if ! flock -n "$MUTATION_LOCK_FD"; then
        exec 9>&-
        warn "已有其他 lsec 变更正在执行"
        [[ -s "$OPERATION_LOCK" ]] && sed -n '1,3p' "$OPERATION_LOCK" >&2
        return "$RESULT_PRECHECK_FAILED"
    fi

    MUTATION_LOCK_HELD=1
    if ! printf 'pid\t%s\nstarted_at\t%s\noperation\t%s\n' \
        "$$" "$(date -u +%FT%TZ)" "$operation" > "$OPERATION_LOCK"; then
        end_mutation
        return "$RESULT_PRECHECK_FAILED"
    fi
}

# flock 是取得全局锁本身所需的唯一引导依赖；安装完成后仍从完整锁流程继续。
bootstrap_flock_dependency() {
    local bootstrap_lock="${STATE_DIR}/.flock-bootstrap"
    dependency_available flock && return "$RESULT_OK"
    [[ ! -s "$PROTECTED_LOCK" ]] || return "$RESULT_PROTECTED_LOCKOUT"
    install -d -m 700 "$STATE_DIR" || return "$RESULT_PRECHECK_FAILED"
    if ! mkdir "$bootstrap_lock" 2>/dev/null; then
        local stale_pid
        stale_pid=$(cat "$bootstrap_lock/owner-pid" 2>/dev/null || true)
        if [[ "$stale_pid" =~ ^[0-9]+$ ]] && ! kill -0 "$stale_pid" 2>/dev/null; then
            warn "检测到已退出进程 ${stale_pid} 遗留的 flock 引导锁"
            if confirm "是否清理该 stale 引导锁并继续？" N; then
                rm -f -- "$bootstrap_lock/owner-pid" \
                    && rmdir "$bootstrap_lock" \
                    && mkdir "$bootstrap_lock" || return "$RESULT_PRECHECK_FAILED"
            else
                return "$RESULT_CANCELLED"
            fi
        else
            error "另一个 flock 引导安装正在执行"
            return "$RESULT_PRECHECK_FAILED"
        fi
    fi
    printf '%s\n' "$$" > "$bootstrap_lock/owner-pid" || {
        rmdir "$bootstrap_lock" 2>/dev/null || true
        return "$RESULT_PRECHECK_FAILED"
    }
    MISSING_DEPENDENCIES=(flock)
    warn "缺少全局事务锁组件 flock，尚未执行任何受管变更"
    if ! confirm "是否自动安装 flock（util-linux）后继续？" N; then
        MISSING_DEPENDENCIES=()
        cleanup_bootstrap_lock_if_owned
        return "$RESULT_CANCELLED"
    fi
    if ! install_missing_dependencies || ! dependency_available flock; then
        MISSING_DEPENDENCIES=()
        cleanup_bootstrap_lock_if_owned
        error "flock 安装失败，无法安全继续"
        return "$RESULT_PRECHECK_FAILED"
    fi
    MISSING_DEPENDENCIES=()
    cleanup_bootstrap_lock_if_owned
    return "$RESULT_OK"
}

cleanup_bootstrap_lock_if_owned() {
    local bootstrap_lock="${STATE_DIR}/.flock-bootstrap"
    [[ -f "$bootstrap_lock/owner-pid" ]] || return 0
    [[ $(cat "$bootstrap_lock/owner-pid" 2>/dev/null) == "$$" ]] || return 0
    rm -f -- "$bootstrap_lock/owner-pid" || return 1
    rmdir "$bootstrap_lock" 2>/dev/null || true
}

end_mutation() {
    (( MUTATION_LOCK_HELD == 1 )) || return 0
    : > "$OPERATION_LOCK" || true
    flock -u "$MUTATION_LOCK_FD" || true
    exec 9>&-
    MUTATION_LOCK_HELD=0
}

end_mutation_if_held() {
    end_mutation
    cleanup_bootstrap_lock_if_owned || true
}

mutation_signal_exit() {
    local signal=$1
    end_mutation_if_held
    trap - "$signal"
    kill -s "$signal" "$$"
}

install_mutation_cleanup_trap() {
    trap 'end_mutation_if_held' EXIT
    trap 'mutation_signal_exit INT' INT
    trap 'mutation_signal_exit TERM' TERM
    trap 'mutation_signal_exit HUP' HUP
}

require_mutation_allowed() {
    if [[ -s "$PROTECTED_LOCK" ]]; then
        error "检测到保护锁定：${PROTECTED_LOCK}"
        return "$RESULT_PROTECTED_LOCKOUT"
    fi
    return "$RESULT_OK"
}

require_recovery_allowed() {
    case ${1:-} in
        restore|repair|reconcile) return "$RESULT_OK" ;;
        *) require_mutation_allowed ;;
    esac
}

require_current_state_schema() {
    [[ -s "$STATE_FILE" ]] || return "$RESULT_OK"
    if [[ -f "$STATE_VERSION_FILE" && $(cat "$STATE_VERSION_FILE" 2>/dev/null) == "$STATE_SCHEMA_VERSION" ]]; then
        return "$RESULT_OK"
    fi
    return "$RESULT_REPAIR_REQUIRED"
}

audit_legacy_forwarding_state() {
    local marker proto source in_if public_port out_if landing_ip landing_port masquerade batch extra status
    [[ -f "$STATE_FILE" ]] || return 0
    while IFS=$'\t' read -r marker proto source in_if public_port out_if landing_ip landing_port masquerade batch extra; do
        [[ -n "$marker" ]] || continue
        status=malformed
        if [[ -z "$extra" ]] && validate_port "$public_port" && validate_port "$landing_port" \
            && validate_interface_name "$in_if" && validate_interface_name "$out_if" \
            && validate_ipv4 "$landing_ip" && [[ "$proto" == tcp || "$proto" == udp ]] \
            && [[ "$masquerade" == yes || "$masquerade" == no ]]; then
            if validate_managed_marker "$marker" && [[ -n "$batch" ]]; then
                status=current
            elif [[ -z "$batch" ]]; then
                status=legacy-drift
                if [[ "$marker" =~ ^[A-Za-z0-9._-]+$ ]]; then
                    if verify_legacy_nat_definition "$marker" "$proto" "$source" "$in_if" \
                        "$public_port" "$out_if" "$landing_ip" "$landing_port" "$masquerade" \
                        && verify_ufw_route_definition "ufw-relay:${marker}" "$proto" "$source" \
                            "$in_if" "$out_if" "$landing_ip" "$landing_port"; then
                        status=legacy-exact
                    fi
                fi
            fi
        fi
        printf '%s\t%s\n' "$marker" "$status"
    done < "$STATE_FILE"
}

verify_legacy_nat_definition() {
    local id=$1 proto=$2 source=$3 in_if=$4 public_port=$5 out_if=$6 landing_ip=$7 landing_port=$8 masquerade=$9
    local source_match expected_dnat expected_snat actual_dnat actual_snat
    source_match=
    [[ "$source" != any ]] && source_match="-s ${source} "
    expected_dnat="-A PREROUTING -i ${in_if} -p ${proto} ${source_match}--dport ${public_port} -m comment --comment ufw-relay:${id}:dnat -j DNAT --to-destination ${landing_ip}:${landing_port}"
    expected_snat="-A POSTROUTING -o ${out_if} -p ${proto} -d ${landing_ip} --dport ${landing_port} -m comment --comment ufw-relay:${id}:snat -j MASQUERADE"
    expected_dnat=$(printf '%s\n' "$expected_dnat" | normalize_iptables_rule)
    expected_snat=$(printf '%s\n' "$expected_snat" | normalize_iptables_rule)
    actual_dnat=$(awk -v tag="--comment ufw-relay:${id}:dnat" 'index($0, tag) {print}' "$BEFORE_RULES" | normalize_iptables_rule) || return 1
    actual_snat=$(awk -v tag="--comment ufw-relay:${id}:snat" 'index($0, tag) {print}' "$BEFORE_RULES" | normalize_iptables_rule) || return 1
    [[ "$actual_dnat" == "$expected_dnat" ]] || return 1
    if [[ "$masquerade" == yes ]]; then
        [[ "$actual_snat" == "$expected_snat" ]]
    else
        [[ -z "$actual_snat" ]]
    fi
}

render_legacy_migration_mapping() {
    local batch_id=$1 index=0
    local old_id proto source in_if public_port out_if landing_ip landing_port masquerade extra
    while IFS=$'\t' read -r old_id proto source in_if public_port out_if landing_ip landing_port masquerade extra; do
        [[ -n "$old_id" ]] || continue
        ((index += 1))
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$old_id" "$(managed_marker "$batch_id" "legacy-${index}")" "$proto" "$source" \
            "$in_if" "$public_port" "$out_if" "$landing_ip" "$landing_port" "$masquerade"
    done < "$STATE_FILE"
}

stage_legacy_migration_nat() {
    local staged=$1 mapping=$2 old_id new_marker rest temp
    cp -a "$BEFORE_RULES" "$staged" || return 1
    while IFS=$'\t' read -r old_id new_marker rest; do
        [[ -n "$old_id" && -n "$new_marker" ]] || continue
        temp=$(mktemp "${staged}.tmp.XXXXXX") || return 1
        if ! awk -v old="ufw-relay:${old_id}:" -v new="${new_marker}:" '
            function replace_literal(text, old, new, position) {
                while ((position = index(text, old)) > 0) {
                    text = substr(text, 1, position - 1) new substr(text, position + length(old))
                }
                return text
            }
            {print replace_literal($0, old, new)}
        ' "$staged" > "$temp" || ! mv -f -- "$temp" "$staged"; then
            rm -f -- "$temp"
            return 1
        fi
    done < "$mapping"
}

render_migrated_forwarding_state() {
    local mapping=$1 old_id marker proto source in_if public_port out_if landing_ip landing_port masquerade
    local marker_tail migration_batch
    while IFS=$'\t' read -r old_id marker proto source in_if public_port out_if landing_ip landing_port masquerade; do
        marker_tail=${marker#lsec:}
        migration_batch=${marker_tail%%:*}
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$marker" "$proto" "$source" "$in_if" "$public_port" "$out_if" \
            "$landing_ip" "$landing_port" "$masquerade" "$migration_batch"
    done < "$mapping"
}

restore_legacy_ufw_rules() {
    local mapping=$1 old_id marker proto source in_if public_port out_if landing_ip landing_port masquerade
    while IFS=$'\t' read -r old_id marker proto source in_if public_port out_if landing_ip landing_port masquerade; do
        if ufw_marker_present "ufw-relay:${old_id}"; then
            verify_ufw_route_definition "ufw-relay:${old_id}" "$proto" "$source" \
                "$in_if" "$out_if" "$landing_ip" "$landing_port" || return 1
        else
            add_forward_ufw_route "$proto" "$source" "$in_if" "$out_if" \
                "$landing_ip" "$landing_port" "ufw-relay:${old_id}" || return 1
        fi
    done < "$mapping"
    verify_legacy_ufw_mapping "$mapping"
}

verify_legacy_ufw_mapping() {
    local mapping=$1 old_id marker proto source in_if public_port out_if landing_ip landing_port masquerade
    while IFS=$'\t' read -r old_id marker proto source in_if public_port out_if landing_ip landing_port masquerade; do
        verify_ufw_route_definition "ufw-relay:${old_id}" "$proto" "$source" \
            "$in_if" "$out_if" "$landing_ip" "$landing_port" || return 1
    done < "$mapping"
}

rollback_legacy_migration() {
    local batch_id=$1 mapping="${BACKUP_DIR}/${batch_id}/legacy-mapping.tsv" result=0
    remove_transaction_ufw_rules "$batch_id" || result=1
    restore_transaction_snapshot "$batch_id" || result=1
    restore_legacy_ufw_rules "$mapping" || result=1
    sync_live_nat_marker_files_to_file "$BEFORE_RULES" \
        "${BACKUP_DIR}/${batch_id}/nat-sync-markers.txt" || result=1
    verify_snapshot_restored "$batch_id" || result=1
    verify_legacy_ufw_mapping "$mapping" || result=1
    if (( result == 0 )); then
        set_transaction_phase "$batch_id" rolled_back
        return 0
    fi
    protect_failed_transaction "$batch_id" rollback_failed '无法验证旧状态迁移回滚'
    return 1
}

migrate_legacy_forwarding_state() {
    local batch_id=$1 audit mapping staged
    local old_id marker proto source in_if public_port out_if landing_ip landing_port masquerade
    local expected_count processed_count=0
    audit=$(audit_legacy_forwarding_state)
    [[ -n "$audit" ]] || return "$RESULT_PRECHECK_FAILED"
    if awk -F '\t' '$2 != "legacy-exact" {bad=1} END {exit bad ? 0 : 1}' <<< "$audit"; then
        return "$RESULT_REPAIR_REQUIRED"
    fi
    verify_nat_file_effective "$BEFORE_RULES" || return "$RESULT_REPAIR_REQUIRED"
    mapping=$(mktemp) || return "$RESULT_PRECHECK_FAILED"
    staged=$(mktemp) || { rm -f -- "$mapping"; return "$RESULT_PRECHECK_FAILED"; }
    render_legacy_migration_mapping "$batch_id" > "$mapping" || {
        rm -f -- "$mapping" "$staged"
        return "$RESULT_PRECHECK_FAILED"
    }
    if ! stage_legacy_migration_nat "$staged" "$mapping" || ! validate_staged_nat "$staged"; then
        rm -f -- "$mapping" "$staged"
        return "$RESULT_PRECHECK_FAILED"
    fi
    begin_transaction "$batch_id" migrate_legacy legacy || {
        rm -f -- "$mapping" "$staged"
        return "$RESULT_PRECHECK_FAILED"
    }
    install -m 600 "$mapping" "${BACKUP_DIR}/${batch_id}/legacy-mapping.tsv" || {
        rm -f -- "$mapping" "$staged"
        rollback_legacy_migration "$batch_id" || return "$RESULT_ROLLBACK_FAILED"
        return "$RESULT_APPLY_FAILED_ROLLED_BACK"
    }
    if ! render_legacy_nat_sync_markers "$mapping" > "${BACKUP_DIR}/${batch_id}/nat-sync-markers.txt" \
        || ! chmod 600 "${BACKUP_DIR}/${batch_id}/nat-sync-markers.txt"; then
        if rollback_legacy_migration "$batch_id"; then
            rm -f -- "$mapping" "$staged"
            return "$RESULT_APPLY_FAILED_ROLLED_BACK"
        fi
        rm -f -- "$mapping" "$staged"
        return "$RESULT_ROLLBACK_FAILED"
    fi
    expected_count=$(awk 'NF {count++} END {print count + 0}' "$mapping")
    if set_transaction_phase "$batch_id" applying_nat && apply_staged_nat_file "$staged" \
        && set_transaction_phase "$batch_id" applying_ufw; then
        while IFS=$'\t' read -r old_id marker proto source in_if public_port out_if landing_ip landing_port masquerade; do
            if record_intended_ufw_marker "$batch_id" "$marker" \
                && verify_ufw_route_definition "ufw-relay:${old_id}" "$proto" "$source" \
                    "$in_if" "$out_if" "$landing_ip" "$landing_port" \
                && delete_ufw_rules_by_comment "ufw-relay:${old_id}" \
                && add_forward_ufw_route "$proto" "$source" "$in_if" "$out_if" "$landing_ip" "$landing_port" "$marker" \
                && record_added_ufw_marker "$batch_id" "$marker"; then
                ((processed_count += 1))
            else
                break
            fi
        done < "$mapping"
        if (( processed_count == expected_count )) \
            && set_transaction_phase "$batch_id" committing_state \
            && atomic_write "$STATE_FILE" render_migrated_forwarding_state "$mapping" \
            && atomic_write "$STATE_VERSION_FILE" write_state_schema_version \
            && sync_live_nat_marker_files_to_file "$BEFORE_RULES" \
                "${BACKUP_DIR}/${batch_id}/nat-sync-markers.txt" \
            && set_transaction_phase "$batch_id" verifying \
            && verify_migrated_mapping "$mapping"; then
            set_transaction_phase "$batch_id" verified \
                && finish_transaction "$batch_id" committed \
                && { rm -f -- "$mapping" "$staged"; return "$RESULT_OK"; }
        fi
    fi
    rm -f -- "$mapping" "$staged"
    if rollback_legacy_migration "$batch_id"; then
        return "$RESULT_APPLY_FAILED_ROLLED_BACK"
    fi
    return "$RESULT_ROLLBACK_FAILED"
}

render_legacy_nat_sync_markers() {
    local mapping=$1 old_id marker rest
    while IFS=$'\t' read -r old_id marker rest; do
        [[ -n "$old_id" && -n "$marker" ]] || continue
        printf 'ufw-relay:%s\n%s\n' "$old_id" "$marker" || return 1
    done < "$mapping"
}

verify_migrated_mapping() {
    local mapping=$1 old_id marker proto source in_if public_port out_if landing_ip landing_port masquerade
    is_ufw_active || return 1
    verify_ipv4_forwarding_effective || return 1
    while IFS=$'\t' read -r old_id marker proto source in_if public_port out_if landing_ip landing_port masquerade; do
        verify_managed_rule_identity "$marker" || return 1
    done < "$mapping"
}

scan_incomplete_transactions() {
    local journal phase batch_id
    [[ -d "$TRANSACTION_DIR" ]] || return 0
    for journal in "$TRANSACTION_DIR"/*.txn; do
        [[ -f "$journal" ]] || continue
        phase=$(transaction_value "$journal" phase)
        case "$phase" in
            committed|rolled_back) continue ;;
        esac
        batch_id=$(transaction_value "$journal" batch_id)
        [[ "$batch_id" =~ ^[A-Za-z0-9._-]+$ ]] && printf '%s\n' "$batch_id"
    done
}

recover_transaction() {
    local batch_id=$1 operation snapshot
    local journal="${TRANSACTION_DIR}/${batch_id}.txn"
    [[ "$batch_id" =~ ^[A-Za-z0-9._-]+$ && -f "$journal" ]] || return "$RESULT_PRECHECK_FAILED"
    operation=$(transaction_value "$journal" operation)
    snapshot="${BACKUP_DIR}/${batch_id}"
    if [[ ! -d "$snapshot" || ! -f "$snapshot/before.rules" || ! -f "$snapshot/forwarding.tsv" ]]; then
        protect_failed_transaction "$batch_id" recovery_failed '事务快照缺失，无法自动恢复'
        return "$RESULT_ROLLBACK_FAILED"
    fi
    case "$operation" in
        create) rollback_created_forwarding "$batch_id" ;;
        delete) rollback_deleted_forwarding "$batch_id" ;;
        overwrite) rollback_replaced_forwarding "$batch_id" ;;
        enable_ufw) rollback_ufw_bootstrap "$batch_id" ;;
        migrate_legacy) rollback_legacy_migration "$batch_id" ;;
        restore) rollback_replaced_forwarding "$batch_id" ;;
        *)
            protect_failed_transaction "$batch_id" recovery_failed "未知事务类型：${operation}"
            return "$RESULT_ROLLBACK_FAILED"
            ;;
    esac
    if [[ $? -eq 0 ]]; then
        return "$RESULT_OK"
    fi
    return "$RESULT_ROLLBACK_FAILED"
}

startup_transaction_recovery() {
    local pending batch_id result=$RESULT_OK
    pending=$(scan_incomplete_transactions)
    [[ -n "$pending" ]] || return "$RESULT_OK"
    warn "检测到未完成事务，开始按日志自动恢复"
    if begin_mutation "启动事务恢复"; then :; else return $?; fi
    while IFS= read -r batch_id; do
        [[ -n "$batch_id" ]] || continue
        if recover_transaction "$batch_id"; then
            info "事务 ${batch_id} 已恢复并验证"
        else
            result=$?
            error "事务 ${batch_id} 自动恢复失败，已进入保护锁定"
            break
        fi
    done <<< "$pending"
    end_mutation
    return "$result"
}

# 使用目标文件所在目录中的临时文件，并以 rename 原子替换。
atomic_write() {
    local destination=$1 writer=$2 temp
    shift 2

    temp=$(mktemp "${destination}.tmp.XXXXXX") || return 1
    if ! chmod 600 "$temp"; then
        rm -f -- "$temp"
        return 1
    fi
    if "$writer" "$@" > "$temp"; then
        if mv -f -- "$temp" "$destination"; then
            return 0
        fi
    fi
    rm -f -- "$temp"
    return 1
}

new_batch_id() {
    printf '%s-%s-%s' "$(date -u +%Y%m%dT%H%M%SZ)" "$$" "$RANDOM"
}

write_transaction_record() {
    local batch_id=$1 operation=$2 phase=$3 snapshot=$4 rule_ids=$5 last_error=${6:-}
    printf 'schema\t%s\n' "$STATE_SCHEMA_VERSION"
    printf 'batch_id\t%s\n' "$batch_id"
    printf 'operation\t%s\n' "$operation"
    printf 'phase\t%s\n' "$phase"
    printf 'created_at\t%s\n' "$(date -u +%FT%TZ)"
    printf 'updated_at\t%s\n' "$(date -u +%FT%TZ)"
    printf 'snapshot\t%s\n' "$snapshot"
    printf 'rule_ids\t%s\n' "$rule_ids"
    printf 'last_error\t%s\n' "$last_error"
}

snapshot_metadata() {
    local batch_id=$1 operation=$2
    printf 'schema\t%s\n' "$STATE_SCHEMA_VERSION"
    printf 'batch_id\t%s\n' "$batch_id"
    printf 'operation\t%s\n' "$operation"
    printf 'created_at\t%s\n' "$(date -u +%FT%TZ)"
    printf 'created_epoch\t%s\n' "$(date +%s)"
    printf 'status\tactive\n'
}

snapshot_copy_or_empty() {
    local source=$1 destination=$2
    if [[ -f "$source" ]]; then
        install -m 600 "$source" "$destination"
    else
        install -m 600 /dev/null "$destination"
    fi
}

snapshot_current_state() {
    local batch_id=$1 operation=$2
    local snapshot="${BACKUP_DIR}/${batch_id}"
    local runtime_value=unknown

    install -d -m 700 "$TRANSACTION_DIR" "$BACKUP_DIR" "$snapshot" || return 1
    snapshot_copy_or_empty "$BEFORE_RULES" "$snapshot/before.rules" || return 1
    snapshot_copy_or_empty "$STATE_FILE" "$snapshot/forwarding.tsv" || return 1
    snapshot_copy_or_empty "$IP_FORWARDING_STATE" "$snapshot/ip-forwarding.tsv" || return 1
    if [[ -f "$STATE_VERSION_FILE" ]]; then
        install -m 600 "$STATE_VERSION_FILE" "$snapshot/state.version" || return 1
    else
        install -m 600 /dev/null "$snapshot/state.version.absent" || return 1
    fi
    if [[ -f "$UFW_SYSCTL_FILE" ]]; then
        install -m 600 "$UFW_SYSCTL_FILE" "$snapshot/ufw-sysctl.conf" || return 1
    else
        install -m 600 /dev/null "$snapshot/ufw-sysctl.conf.absent" || return 1
    fi
    runtime_value=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || printf 'unknown')
    printf '%s\n' "$runtime_value" > "$snapshot/runtime-ip-forward" || return 1
    chmod 600 "$snapshot/runtime-ip-forward" || return 1
    atomic_write "$snapshot/metadata.tsv" snapshot_metadata "$batch_id" "$operation"
}

begin_transaction() {
    local batch_id=$1 operation=$2 rule_ids=${3:-}
    local snapshot="${BACKUP_DIR}/${batch_id}"

    snapshot_current_state "$batch_id" "$operation" || return 1
    atomic_write "${TRANSACTION_DIR}/${batch_id}.txn" write_transaction_record \
        "$batch_id" "$operation" prepared "$snapshot" "$rule_ids" ''
}

transaction_value() {
    local journal=$1 key=$2
    awk -F '\t' -v key="$key" '$1 == key {sub(/^[^\t]*\t/, ""); print; exit}' "$journal"
}

render_transaction_phase() {
    local journal=$1 phase=$2 last_error=${3:-}
    awk -F '\t' -v OFS='\t' -v phase="$phase" -v now="$(date -u +%FT%TZ)" \
        -v last_error="$last_error" '
        $1 == "phase" {print "phase", phase; next}
        $1 == "updated_at" {print "updated_at", now; next}
        $1 == "last_error" {print "last_error", last_error; next}
        {print}
    ' "$journal"
}

set_transaction_phase() {
    local batch_id=$1 phase=$2 last_error=${3:-}
    local journal="${TRANSACTION_DIR}/${batch_id}.txn"
    [[ -f "$journal" ]] || return 1
    atomic_write "$journal" render_transaction_phase "$journal" "$phase" "$last_error" || return 1
    case "$phase" in
        committed) set_snapshot_status "$batch_id" success ;;
        rolled_back) set_snapshot_status "$batch_id" failed ;;
        protected) set_snapshot_status "$batch_id" inconsistent ;;
        *) return 0 ;;
    esac
}

finish_transaction() {
    local batch_id=$1 terminal_phase=$2
    local journal="${TRANSACTION_DIR}/${batch_id}.txn" current
    [[ -f "$journal" ]] || return 1
    current=$(transaction_value "$journal" phase)
    if [[ "$terminal_phase" == committed && "$current" != verified ]]; then
        return 1
    fi
    set_transaction_phase "$batch_id" "$terminal_phase"
}

metadata_value() {
    transaction_value "$1" "$2"
}

render_snapshot_status() {
    local metadata=$1 status=$2
    awk -F '\t' -v OFS='\t' -v status="$status" '
        $1 == "status" {print "status", status; found=1; next}
        {print}
        END {if (!found) print "status", status}
    ' "$metadata"
}

set_snapshot_status() {
    local batch_id=$1 status=$2
    local metadata="${BACKUP_DIR}/${batch_id}/metadata.tsv"
    [[ -f "$metadata" ]] || return 1
    atomic_write "$metadata" render_snapshot_status "$metadata" "$status"
}

classify_snapshot() {
    local batch_id=$1 status protected_batch
    local metadata="${BACKUP_DIR}/${batch_id}/metadata.tsv"
    [[ -f "$metadata" ]] || { printf 'unverified\n'; return 0; }
    if [[ -s "$PROTECTED_LOCK" ]]; then
        protected_batch=$(transaction_value "$PROTECTED_LOCK" batch_id)
        [[ "$protected_batch" == "$batch_id" ]] && { printf 'protected\n'; return 0; }
    fi
    status=$(metadata_value "$metadata" status)
    case "$status" in
        success|failed|active|inconsistent) printf '%s\n' "$status" ;;
        *) printf 'unverified\n' ;;
    esac
}

list_snapshots() {
    local snapshot batch_id status epoch operation metadata
    [[ -d "$BACKUP_DIR" ]] || return 0
    for snapshot in "$BACKUP_DIR"/*; do
        [[ -d "$snapshot" && ! -L "$snapshot" ]] || continue
        batch_id=${snapshot##*/}
        [[ "$batch_id" =~ ^[A-Za-z0-9._-]+$ ]] || continue
        metadata="$snapshot/metadata.tsv"
        status=$(classify_snapshot "$batch_id")
        epoch=$(metadata_value "$metadata" created_epoch 2>/dev/null || true)
        operation=$(metadata_value "$metadata" operation 2>/dev/null || true)
        printf '%s\t%s\t%s\t%s\n' "$batch_id" "$status" "${epoch:-0}" "${operation:-unknown}"
    done | sort
}

eligible_success_snapshots_for_cleanup() {
    local now_epoch=${1:-$(date +%s)} batch_id
    while IFS= read -r batch_id; do
        snapshot_is_referenced "$batch_id" || printf '%s\n' "$batch_id"
    done < <(list_snapshots \
        | awk -F '\t' '$2 == "success" {print $3 "\t" $1}' \
        | sort -t $'\t' -k1,1nr \
        | awk -F '\t' -v now="$now_epoch" 'NR > 20 && now - $1 > 2592000 {print $2}')
}

snapshot_is_referenced() {
    local batch_id=$1 owner_snapshot journal snapshot phase protected_batch
    if [[ -s "$IP_FORWARDING_STATE" ]]; then
        owner_snapshot=$(transaction_value "$IP_FORWARDING_STATE" owner_snapshot 2>/dev/null || true)
        [[ ${owner_snapshot##*/} == "$batch_id" ]] && return 0
    fi
    if [[ -s "$STATE_FILE" ]] \
        && awk -F '\t' -v batch_id="$batch_id" '$10 == batch_id {found=1} END {exit found ? 0 : 1}' "$STATE_FILE"; then
        return 0
    fi
    for journal in "$TRANSACTION_DIR"/*.txn; do
        [[ -f "$journal" ]] || continue
        phase=$(transaction_value "$journal" phase 2>/dev/null || true)
        case "$phase" in committed|rolled_back) continue ;; esac
        snapshot=$(transaction_value "$journal" snapshot 2>/dev/null || true)
        [[ ${snapshot##*/} == "$batch_id" ]] && return 0
    done
    if [[ -s "$PROTECTED_LOCK" ]]; then
        protected_batch=$(transaction_value "$PROTECTED_LOCK" batch_id 2>/dev/null || true)
        [[ "$protected_batch" == "$batch_id" ]] && return 0
    fi
    return 1
}

cleanup_selected_snapshots() {
    local now_epoch=$1 batch_id eligible
    shift
    local -a selected=("$@")
    require_mutation_allowed || return $?
    (( ${#selected[@]} > 0 )) || return "$RESULT_CANCELLED"
    eligible=$(eligible_success_snapshots_for_cleanup "$now_epoch")
    for batch_id in "${selected[@]}"; do
        [[ "$batch_id" =~ ^[A-Za-z0-9._-]+$ ]] || return "$RESULT_PRECHECK_FAILED"
        grep -qxF -- "$batch_id" <<< "$eligible" || return "$RESULT_PRECHECK_FAILED"
        [[ -d "${BACKUP_DIR}/${batch_id}" && ! -L "${BACKUP_DIR}/${batch_id}" ]] \
            || return "$RESULT_PRECHECK_FAILED"
    done
    for batch_id in "${selected[@]}"; do
        rm -rf -- "${BACKUP_DIR:?}/${batch_id}" || return "$RESULT_PRECHECK_FAILED"
    done
    return "$RESULT_OK"
}

restore_snapshot_transaction() {
    local target_batch=$1 restore_batch marker proto source in_if public_port out_if landing_ip landing_port masquerade original_batch
    local target="${BACKUP_DIR}/${target_batch}" target_state current_row result=0
    local delete_intent
    [[ "$target_batch" =~ ^[A-Za-z0-9._-]+$ && -d "$target" && ! -L "$target" ]] \
        || return "$RESULT_PRECHECK_FAILED"
    [[ $(classify_snapshot "$target_batch") == success ]] || return "$RESULT_PRECHECK_FAILED"
    [[ -f "$target/before.rules" && -f "$target/forwarding.tsv" && -f "$target/ip-forwarding.tsv" ]] \
        || return "$RESULT_PRECHECK_FAILED"
    target_state="$target/forwarding.tsv"
    if [[ -s "$target_state" ]]; then
        [[ -f "$target/state.version" && $(cat "$target/state.version") == "$STATE_SCHEMA_VERSION" ]] \
            || return "$RESULT_REPAIR_REQUIRED"
    fi

    restore_batch="restore-$(new_batch_id)"
    begin_transaction "$restore_batch" restore "$target_batch" || return "$RESULT_PRECHECK_FAILED"
    delete_intent="${BACKUP_DIR}/${restore_batch}/ufw-delete-intended.tsv"
    if ! install -m 600 /dev/null "$delete_intent"; then
        rollback_replaced_forwarding "$restore_batch" \
            && return "$RESULT_APPLY_FAILED_ROLLED_BACK"
        return "$RESULT_ROLLBACK_FAILED"
    fi
    set_transaction_phase "$restore_batch" applying_ufw || result=1

    if (( result == 0 )) && [[ -f "$STATE_FILE" ]]; then
        while IFS=$'\t' read -r marker proto source in_if public_port out_if landing_ip landing_port masquerade original_batch; do
            [[ -n "$marker" ]] || continue
            if ! awk -F '\t' -v marker="$marker" '$1 == marker {found=1} END {exit found ? 0 : 1}' "$target_state"; then
                verify_managed_rule_identity "$marker" || { result=1; break; }
                current_row=$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                    "$marker" "$proto" "$source" "$in_if" "$public_port" "$out_if" \
                    "$landing_ip" "$landing_port" "$masquerade" "$original_batch")
                printf '%s\n' "$current_row" >> "$delete_intent" || { result=1; break; }
                delete_ufw_rules_by_comment "$marker" || { result=1; break; }
            fi
        done < "$STATE_FILE"
    fi

    if (( result == 0 )); then
        while IFS=$'\t' read -r marker proto source in_if public_port out_if landing_ip landing_port masquerade original_batch; do
            [[ -n "$marker" ]] || continue
            if ufw_marker_present "$marker"; then
                verify_ufw_route_definition "$marker" "$proto" "$source" "$in_if" "$out_if" \
                    "$landing_ip" "$landing_port" || { result=1; break; }
            else
                record_intended_ufw_marker "$restore_batch" "$marker" \
                    && add_forward_ufw_route "$proto" "$source" "$in_if" "$out_if" "$landing_ip" "$landing_port" "$marker" \
                    && record_added_ufw_marker "$restore_batch" "$marker" \
                    || { result=1; break; }
            fi
        done < "$target_state"
    fi

    if (( result == 0 )) && restore_transaction_snapshot "$target_batch" \
        && reconcile_all_live_managed_nat_to_file "$BEFORE_RULES" \
        && verify_snapshot_restored "$target_batch" && is_ufw_active; then
        while IFS=$'\t' read -r marker proto source in_if public_port out_if landing_ip landing_port masquerade original_batch; do
            [[ -n "$marker" ]] || continue
            verify_nat_marker_effective "$marker" \
                && verify_ufw_route_definition "$marker" "$proto" "$source" "$in_if" "$out_if" \
                    "$landing_ip" "$landing_port" \
                || { result=1; break; }
        done < "$target_state"
        if [[ -s "$target_state" ]]; then
            verify_ipv4_forwarding_effective || result=1
        fi
    else
        result=1
    fi
    if (( result == 0 )); then
        set_transaction_phase "$restore_batch" verified \
            && finish_transaction "$restore_batch" committed \
            && return "$RESULT_OK"
    fi
    if rollback_replaced_forwarding "$restore_batch"; then
        return "$RESULT_APPLY_FAILED_ROLLED_BACK"
    fi
    return "$RESULT_ROLLBACK_FAILED"
}

render_transaction_diagnostics() {
    printf 'lsec transaction diagnostics\n'
    printf 'generated_at\t%s\n' "$(date -u +%FT%TZ)"
    printf 'version\t%s\n' "$VERSION"
    printf '\n[snapshots]\n'
    list_snapshots
    printf '\n[incomplete_transactions]\n'
    scan_incomplete_transactions
    printf '\n[protected_lock]\n'
    [[ -f "$PROTECTED_LOCK" ]] && cat "$PROTECTED_LOCK"
    printf '\n[state_audit]\n'
    audit_legacy_forwarding_state
    printf '\n[ufw_status]\n'
    ufw status verbose 2>&1 || true
}

export_transaction_diagnostics() {
    local target=$1
    install -d -m 700 "$(dirname "$target")" || return 1
    atomic_write "$target" render_transaction_diagnostics
}

dependency_available() {
    command -v "$1" >/dev/null 2>&1
}

collect_missing_dependencies() {
    local dependency
    MISSING_DEPENDENCIES=()
    for dependency in $FORWARD_DEPENDENCIES; do
        dependency_available "$dependency" || MISSING_DEPENDENCIES+=("$dependency")
    done
    (( ${#MISSING_DEPENDENCIES[@]} == 0 ))
}

print_missing_dependencies() {
    warn "缺少转发事务所需组件：${MISSING_DEPENDENCIES[*]}"
}

missing_dependency_packages() {
    local dependency package packages=' '
    for dependency in "${MISSING_DEPENDENCIES[@]}"; do
        case "$dependency" in
            flock) package=util-linux ;;
            ufw) package=ufw ;;
            iptables|iptables-save|iptables-restore) package=iptables ;;
            sysctl) package=procps ;;
            *) return 1 ;;
        esac
        if [[ "$packages" != *" $package "* ]]; then
            packages+="$package "
            printf '%s\n' "$package"
        fi
    done
}

install_missing_dependencies() {
    local -a packages=()
    check_debian_family || {
        error "请手动安装以下命令后重试：${MISSING_DEPENDENCIES[*]}"
        return 1
    }
    mapfile -t packages < <(missing_dependency_packages) || return 1
    (( ${#packages[@]} > 0 )) || return 0
    apt-get update || return 1
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
}

run_dependency_preflight() {
    while true; do
        if collect_missing_dependencies; then
            return "$RESULT_OK"
        fi
        print_missing_dependencies
        if ! confirm "是否自动安装缺失组件？" N; then
            return "$RESULT_CANCELLED"
        fi
        if ! install_missing_dependencies; then
            error "组件安装失败，已停止操作"
            return "$RESULT_PRECHECK_FAILED"
        fi
        info "组件处理完成，正在从头重新执行前置检查"
    done
}

render_execution_preview() {
    local operation=$1 marker=$2 description=$3 nat_file=$4 state_file=$5 ipv4_change=$6
    cat <<EOF
========================================
执行预览
========================================
操作：${operation}
规则：${description}
受管标记：${marker}
NAT 配置：${nat_file}
状态文件：${state_file}
IPv4 转发：${ipv4_change}
回滚范围：NAT、UFW 路由规则、状态文件、由本事务拥有的 IPv4 转发变更
验证边界：仅验证本机配置，不证明应用协议端到端可达
EOF
}

select_execution_mode() {
    local choice
    {
        echo "1) 执行变更"
        echo "2) 仅运行前置检查"
        echo "3) 取消"
    } >&2
    read -r -p "请选择 [默认 3]: " choice
    case ${choice:-3} in
        1) printf 'execute\n' ;;
        2) printf 'preflight\n' ;;
        3) printf 'cancel\n' ;;
        *) printf 'cancel\n' ;;
    esac
}

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

# 检查流式脚本路径
is_streamed_source() {
    case ${1:-} in
        /dev/fd/*|/proc/self/fd/*) return 0 ;;
        *) return 1 ;;
    esac
}

# 校验 lsec 候选脚本
validate_lsec_candidate() {
    local file=$1
    [[ -s "$file" ]] || return 1
    grep -Fq "$PROGRAM_MARKER" "$file" || return 1
    bash -n "$file"
}

# 原子安装 lsec 脚本
install_lsec_candidate() {
    local source=$1
    local candidate=$source
    local install_dir tmp staged=

    if is_streamed_source "$source"; then
        staged=$(mktemp) || return 1
        if ! download_lsec_candidate "$staged"; then
            rm -f "$staged"
            return 1
        fi
        candidate=$staged
    fi

    if ! validate_lsec_candidate "$candidate"; then
        [[ -n "$staged" ]] && rm -f "$staged"
        return 1
    fi
    install_dir=$(dirname "$INSTALL_PATH")
    if ! install -d -m 755 "$install_dir"; then
        [[ -n "$staged" ]] && rm -f "$staged"
        return 1
    fi
    tmp=$(mktemp "${install_dir}/.lsec.XXXXXX") || {
        [[ -n "$staged" ]] && rm -f "$staged"
        return 1
    }
    if ! install -m 755 "$candidate" "$tmp" || ! mv -f "$tmp" "$INSTALL_PATH"; then
        rm -f "$tmp"
        [[ -n "$staged" ]] && rm -f "$staged"
        return 1
    fi
    if [[ -n "$staged" ]]; then
        rm -f "$staged"
    fi
    return 0
}

# 下载 lsec 候选脚本
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

# 升级 lsec 脚本
upgrade_lsec() {
    local tmp version
    tmp=$(mktemp) || return 1
    if ! download_lsec_candidate "$tmp" \
        || ! validate_lsec_candidate "$tmp" \
        || ! install_lsec_candidate "$tmp"; then
        rm -f "$tmp"
        error "lsec 升级失败 已保留当前版本"
        return 1
    fi
    version=$(awk -F '"' '$1 == "VERSION=" {print $2; exit}' "$tmp")
    rm -f "$tmp"
    ok "lsec 已升级到 ${version:-latest}"
}

# 删除 lsec 安装文件
remove_installed_lsec() {
    rm -f "$INSTALL_PATH"
}

# 卸载 lsec 脚本
uninstall_lsec() {
    if [[ ! -e "$INSTALL_PATH" ]]; then
        info "lsec 当前未安装"
        return 0
    fi
    warn "只会删除 ${INSTALL_PATH}"
    warn "UFW SSH Fail2Ban 配置和状态都会保留"
    confirm "确认卸载 lsec？" N || return "$RESULT_CANCELLED"
    if ! remove_installed_lsec; then
        error "lsec 卸载失败"
        return 1
    fi
    ok "lsec 已卸载 系统安全配置保持不变"
}

# 显示 lsec 用法
show_lsec_usage() {
    cat <<'EOF'
用法
  lsec             打开安全管理菜单
  lsec upgrade     升级到 main 最新版
  lsec uninstall   卸载程序并保留系统配置
EOF
}

pause() {
    read -r -p "按回车键继续..." _
}

confirm() {
    local prompt=${1:-"确认继续？"}
    local default=${2:-Y}
    local answer

    if [[ "$default" == "Y" ]]; then
        read -r -p "${prompt} [Y/n]: " answer
        answer=${answer:-Y}
    else
        read -r -p "${prompt} [y/N]: " answer
        answer=${answer:-N}
    fi

    [[ "$answer" =~ ^[Yy]$ ]]
}

require_root() {
    if [[ ${EUID} -eq 0 ]]; then
        return 0
    fi

    error "此脚本需要 root 权限，请使用 sudo 重新运行，例如：sudo bash $0"
    return 1
}

# 备份现有文件
backup_file() {
    local file=$1
    local backup
    [[ -e "$file" ]] || return 0
    backup=$(mktemp "${file}.bak.$(date +%Y%m%d%H%M%S).XXXXXX")
    if ! cp -a "$file" "$backup"; then
        rm -f "$backup"
        return 1
    fi
    printf '%s\n' "$backup"
}

# 恢复备份文件
restore_file() {
    local file=$1
    local backup=${2:-}
    if [[ -n "$backup" && -e "$backup" ]]; then
        cp -a "$backup" "$file"
    else
        rm -f "$file"
    fi
}

# 校验 SSH 公钥格式
validate_ssh_public_key() {
    local key=${1:-}
    local type body comment
    read -r type body comment <<< "$key"

    case "$type" in
        ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) ;;
        *) return 1 ;;
    esac

    [[ "$body" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || return 1
    printf '%s\n' "$key" | ssh-keygen -l -f - >/dev/null 2>&1
}

# 安装 root SSH 公钥
install_root_public_key() {
    local key=$1
    validate_ssh_public_key "$key" || return 1
    install -d -m 700 "$ROOT_SSH_DIR" || return 1
    touch "$AUTHORIZED_KEYS" || return 1
    chmod 600 "$AUTHORIZED_KEYS" || return 1
    grep -qxF "$key" "$AUTHORIZED_KEYS" || printf '%s\n' "$key" >> "$AUTHORIZED_KEYS"
}

# 检查有效 SSH 公钥
has_valid_authorized_key() {
    local key
    [[ -s "$AUTHORIZED_KEYS" ]] || return 1
    while IFS= read -r key; do
        validate_ssh_public_key "$key" && return 0
    done < "$AUTHORIZED_KEYS"
    return 1
}

# 交互添加 root SSH 公钥
add_root_public_key_interactive() {
    local key
    read -r -p "请粘贴客户端 SSH 公钥: " key
    if ! validate_ssh_public_key "$key"; then
        error "SSH 公钥格式无效"
        return 1
    fi
    if [[ -f "$AUTHORIZED_KEYS" ]] && grep -qxF "$key" "$AUTHORIZED_KEYS"; then
        info "该公钥已存在"
        return 0
    fi
    if ! install_root_public_key "$key"; then
        error "SSH 公钥写入失败"
        return 1
    fi
    ok "公钥已添加到 ${AUTHORIZED_KEYS}"
}

# 渲染 SSH 加固配置
render_ssh_hardening() {
    printf '%s\n' \
        'PermitRootLogin prohibit-password' \
        'PubkeyAuthentication yes' \
        'PasswordAuthentication no' \
        'KbdInteractiveAuthentication no' \
        'MaxAuthTries 3' \
        'LoginGraceTime 30'
}

# 渲染 SSH 端口配置
render_ssh_ports() {
    local port
    for port in "$@"; do
        printf 'Port %s\n' "$port"
    done
}

# 渲染 SSH Socket 端口配置
render_ssh_socket_ports() {
    local port
    printf '[Socket]\nListenStream=\n'
    for port in "$@"; do
        printf 'ListenStream=%s\n' "$port"
    done
}

# 解析 SSH Socket 监听端口
parse_ssh_socket_ports() {
    awk '$NF == "(Stream)" {port=$(NF-1); sub(/^.*:/, "", port); if (port ~ /^[0-9]+$/) print port}' | sort -n -u
}

# 检查端口集合
ports_include_all() {
    local actual=$1
    shift
    local port
    for port in "$@"; do
        grep -qxF "$port" <<< "$actual" || return 1
    done
}

# 注释指定 SSH 端口
comment_ssh_port() {
    local port=$1
    awk -v port="$port" '
        tolower($0) ~ "^[[:space:]]*port[[:space:]]+" port "([[:space:]#]|$)" {
            print "# security-manager migrated " $0
            next
        }
        { print }
    '
}

# 渲染 Fail2Ban 配置
render_fail2ban_config() {
    local enable_recidive=$1
    local ssh_ports=$2

    cat <<EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
findtime = 10m
maxretry = 5
bantime = 24h
bantime.increment = true
bantime.factor = 2

[sshd]
enabled = true
port = ${ssh_ports}
backend = systemd
mode = normal
EOF

    if [[ "$enable_recidive" == "yes" ]]; then
        cat <<'EOF'

[recidive]
enabled = true
backend = auto
logpath = /var/log/fail2ban.log
findtime = 7d
bantime = 30d
maxretry = 3
EOF
    fi
}

# 安装缺失软件包
install_apt_packages() {
    local description=$1
    shift
    local package
    local -a missing=()

    for package in "$@"; do
        dpkg -s "$package" >/dev/null 2>&1 || missing+=("$package")
    done
    (( ${#missing[@]} == 0 )) && return 0

    warn "缺少 ${description}：${missing[*]}"
    confirm "是否现在安装？" N || return 1
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
}

# 写入受管配置文件
write_managed_content() {
    local target=$1
    local mode=$2
    local content=$3
    local tmp
    tmp=$(mktemp) || return 1
    if ! printf '%s\n' "$content" > "$tmp" \
        || ! install -d -m 755 "$(dirname "$target")" \
        || ! install -m "$mode" "$tmp" "$target"; then
        rm -f "$tmp"
        return 1
    fi
    rm -f "$tmp"
}

# 确保 SSH 包含配置目录
ensure_ssh_include() {
    local backup tmp mode
    grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSH_MAIN_CONFIG" && return 0

    backup=$(backup_file "$SSH_MAIN_CONFIG") || return 1
    tmp=$(mktemp) || return 1
    mode=$(stat -c '%a' "$SSH_MAIN_CONFIG") || { rm -f "$tmp"; return 1; }
    if ! {
        echo 'Include /etc/ssh/sshd_config.d/*.conf'
        cat "$SSH_MAIN_CONFIG"
    } > "$tmp" || ! install -m "$mode" "$tmp" "$SSH_MAIN_CONFIG"; then
        rm -f "$tmp"
        cp -a "$backup" "$SSH_MAIN_CONFIG" >/dev/null 2>&1 || true
        return 1
    fi
    rm -f "$tmp"
    printf '%s\n' "$backup"
}

# 检查 systemd 单元
systemd_unit_loaded() {
    local unit=$1
    [[ "$(systemctl show -p LoadState --value "$unit" 2>/dev/null || true)" == "loaded" ]]
}

# 获取 SSH 服务名称
ssh_service_name() {
    if systemd_unit_loaded ssh.service; then
        echo ssh.service
    elif systemd_unit_loaded sshd.service; then
        echo sshd.service
    else
        return 1
    fi
}

# 检查 SSH Socket 管理状态
ssh_socket_managed() {
    systemd_unit_loaded ssh.socket || return 1
    systemctl is-enabled --quiet ssh.socket 2>/dev/null || systemctl is-active --quiet ssh.socket 2>/dev/null
}

# 重载 SSH 运行环境
reload_ssh_runtime() {
    local socket_changed=${1:-no}
    shift || true
    local service
    local actual_ports
    service=$(ssh_service_name) || { error "未找到 SSH systemd 服务"; return 1; }

    if [[ "$socket_changed" == "yes" ]]; then
        systemctl daemon-reload
        systemctl restart ssh.socket
        actual_ports=$(systemctl show ssh.socket -p Listen --value 2>/dev/null | parse_ssh_socket_ports)
        ports_include_all "$actual_ports" "$@" || { error "ssh.socket 未监听预期端口"; return 1; }
    fi
    systemctl try-reload-or-restart "$service"
}

# 检查 SSH 管理环境
check_ssh_environment() {
    check_debian_family || return 1
    install_apt_packages "OpenSSH 服务" openssh-server || return 1
    command -v sshd >/dev/null 2>&1 || { error "未找到 sshd 命令"; return 1; }
    command -v systemctl >/dev/null 2>&1 || { error "未找到 systemctl 命令"; return 1; }
    [[ -f "$SSH_MAIN_CONFIG" ]] || { error "未找到 ${SSH_MAIN_CONFIG}"; return 1; }
}

# 应用 SSH 密钥登录加固
apply_ssh_hardening() {
    local include_backup security_backup

    if ! has_valid_authorized_key; then
        error "${AUTHORIZED_KEYS} 中没有有效公钥"
        warn "请先添加公钥并验证新的密钥登录会话"
        return 1
    fi

    warn "此操作会禁用所有 SSH 密码与键盘交互登录"
    confirm "确认已验证 root 密钥登录并继续？" N || return 0

    if ! include_backup=$(ensure_ssh_include); then
        error "SSH Include 配置失败"
        return 1
    fi
    if ! security_backup=$(backup_file "$SSH_SECURITY_CONFIG"); then
        [[ -n "$include_backup" ]] && restore_file "$SSH_MAIN_CONFIG" "$include_backup"
        error "SSH 加固配置备份失败"
        return 1
    fi
    if ! write_managed_content "$SSH_SECURITY_CONFIG" 600 "$(render_ssh_hardening)"; then
        restore_file "$SSH_SECURITY_CONFIG" "$security_backup"
        [[ -n "$include_backup" ]] && restore_file "$SSH_MAIN_CONFIG" "$include_backup"
        error "SSH 加固配置写入失败并已回滚"
        return 1
    fi

    if ! sshd -t || ! reload_ssh_runtime no; then
        restore_file "$SSH_SECURITY_CONFIG" "$security_backup"
        [[ -n "$include_backup" ]] && restore_file "$SSH_MAIN_CONFIG" "$include_backup"
        sshd -t >/dev/null 2>&1 && reload_ssh_runtime no >/dev/null 2>&1 || true
        error "SSH 加固失败并已回滚"
        return 1
    fi

    ok "SSH 已切换为 root 密钥登录"
}

# 显示 SSH 状态
show_ssh_status() {
    local service
    service=$(ssh_service_name 2>/dev/null || true)
    echo "--- SSH 生效配置 ---"
    sshd -T 2>/dev/null | awk '$1 ~ /^(port|permitrootlogin|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|maxauthtries|logingracetime)$/ {print}'
    echo
    if [[ -n "$service" ]]; then
        systemctl --no-pager --full status "$service" 2>/dev/null | sed -n '1,8p' || true
    fi
    if ssh_socket_managed; then
        echo
        info "检测到 ssh.socket 正在管理监听端口"
        systemctl show ssh.socket -p Listen --value 2>/dev/null || true
    fi
}

# 检查 SSH 生效加固配置
ssh_effective_config_hardened() {
    local config=$1
    local max_tries grace_time
    grep -Eq '^permitrootlogin (prohibit-password|without-password)$' <<< "$config" || return 1
    grep -qx 'pubkeyauthentication yes' <<< "$config" || return 1
    grep -qx 'passwordauthentication no' <<< "$config" || return 1
    grep -qx 'kbdinteractiveauthentication no' <<< "$config" || return 1
    max_tries=$(awk '$1 == "maxauthtries" {print $2; exit}' <<< "$config")
    grace_time=$(awk '$1 == "logingracetime" {print $2; exit}' <<< "$config")
    [[ "$max_tries" =~ ^[0-9]+$ && "$grace_time" =~ ^[0-9]+$ ]] || return 1
    (( max_tries <= 3 && grace_time <= 30 ))
}

# 检测 SSH Socket 监听端口
detect_ssh_socket_ports() {
    ssh_socket_managed || return 0
    systemctl show ssh.socket -p Listen --value 2>/dev/null | parse_ssh_socket_ports
}

# 列出当前 SSH 端口
all_current_ssh_ports() {
    {
        detect_ssh_ports no
        detect_ssh_socket_ports
    } | sort -n -u
}

# 获取当前 SSH 端口
current_ssh_port() {
    local -a parts=()
    if [[ -n ${SSH_CONNECTION:-} ]]; then
        read -r -a parts <<< "$SSH_CONNECTION"
        if (( ${#parts[@]} >= 4 )) && validate_port "${parts[3]}"; then
            echo "${parts[3]}"
            return 0
        fi
    fi
    all_current_ssh_ports | head -n 1
}

# 检查端口占用状态
port_is_listening() {
    local port=$1
    command -v ss >/dev/null 2>&1 || return 1
    ss -H -lnt 2>/dev/null | awk -v port="$port" '$4 ~ ":" port "$" {found=1} END {exit found ? 0 : 1}'
}

# 添加 SSH 迁移防火墙规则
add_ssh_migration_ufw_rule() {
    local port=$1
    local comment=$2
    command -v ufw >/dev/null 2>&1 && is_ufw_active || return 0
    ufw status 2>/dev/null | grep -Fq "$comment" || add_inbound_allow_rule "$port" tcp "$comment"
}

# 删除 SSH 迁移防火墙规则
delete_ssh_migration_ufw_rule() {
    local comment=$1
    command -v ufw >/dev/null 2>&1 && is_ufw_active || return 0
    delete_ufw_rules_by_comment "$comment"
}

# 清理 SSH 迁移防火墙规则
cleanup_ssh_migration_ufw_rules() {
    local old_comment=$1
    local new_comment=$2
    local failed=0
    delete_ssh_migration_ufw_rule "$old_comment" || failed=1
    delete_ssh_migration_ufw_rule "$new_comment" || failed=1
    return "$failed"
}

# 保存 SSH 端口迁移状态
save_ssh_port_state() {
    local old_port=$1
    local new_port=$2
    local socket_managed=$3
    local old_comment=$4
    local new_comment=$5
    install -d -m 700 "$SSH_STATE_DIR" || return 1
    printf '%s\t%s\t%s\t%s\t%s\n' "$old_port" "$new_port" "$socket_managed" "$old_comment" "$new_comment" > "$SSH_PORT_STATE" || return 1
    chmod 600 "$SSH_PORT_STATE"
}

# 回滚 SSH 端口迁移启动
rollback_ssh_port_start() {
    local include_backup=$1
    local port_backup=$2
    local socket_backup=$3
    local socket_managed=$4
    local old_comment=$5
    local new_comment=$6
    local old_port=$7
    local failed=0

    restore_file "$SSH_PORT_CONFIG" "$port_backup"
    [[ -n "$include_backup" ]] && restore_file "$SSH_MAIN_CONFIG" "$include_backup"
    if [[ "$socket_managed" == "yes" ]]; then
        restore_file "$SSH_SOCKET_DROPIN" "$socket_backup"
    fi
    cleanup_ssh_migration_ufw_rules "$old_comment" "$new_comment" || failed=1
    sshd -t >/dev/null 2>&1 && reload_ssh_runtime "$socket_managed" "$old_port" >/dev/null 2>&1 || failed=1
    (( failed == 0 )) || warn "SSH 配置已回滚但部分运行状态或 UFW 规则需要手工检查"
    return "$failed"
}

# 开始 SSH 端口迁移
start_ssh_port_migration() {
    local old_port new_port socket_managed=no
    local include_backup port_backup socket_backup old_comment new_comment

    if [[ -s "$SSH_PORT_STATE" ]]; then
        error "已有待完成的 SSH 端口迁移"
        warn "请先验证新端口并完成迁移"
        return 1
    fi

    old_port=$(current_ssh_port)
    validate_port "$old_port" || { error "无法确定当前 SSH 端口"; return 1; }
    read -r -p "请输入新的 SSH 端口 [当前 ${old_port}]: " new_port
    new_port=${new_port:-$old_port}
    validate_port "$new_port" || { error "SSH 端口无效"; return 1; }
    if [[ "$new_port" == "$old_port" ]]; then
        info "新旧端口相同 无需迁移"
        return 0
    fi
    if all_current_ssh_ports | grep -qx "$new_port" || port_is_listening "$new_port"; then
        error "端口 ${new_port} 已被监听"
        return 1
    fi

    warn "第一阶段会同时保留 ${old_port} 和 ${new_port}"
    confirm "确认开始端口迁移？" N || return 0

    if ! include_backup=$(ensure_ssh_include); then
        error "SSH Include 配置失败"
        return 1
    fi
    if ! port_backup=$(backup_file "$SSH_PORT_CONFIG"); then
        [[ -n "$include_backup" ]] && restore_file "$SSH_MAIN_CONFIG" "$include_backup"
        error "SSH 端口配置备份失败"
        return 1
    fi
    if ssh_socket_managed; then
        socket_managed=yes
        if ! socket_backup=$(backup_file "$SSH_SOCKET_DROPIN"); then
            [[ -n "$include_backup" ]] && restore_file "$SSH_MAIN_CONFIG" "$include_backup"
            error "ssh.socket 配置备份失败"
            return 1
        fi
    fi
    old_comment="security-manager-ssh-old-${old_port}"
    new_comment="security-manager-ssh-new-${new_port}"

    if ! add_ssh_migration_ufw_rule "$old_port" "$old_comment" \
        || ! add_ssh_migration_ufw_rule "$new_port" "$new_comment" \
        || ! write_managed_content "$SSH_PORT_CONFIG" 600 "$(render_ssh_ports "$old_port" "$new_port")"; then
        rollback_ssh_port_start "$include_backup" "$port_backup" "${socket_backup:-}" "$socket_managed" "$old_comment" "$new_comment" "$old_port" || true
        error "SSH 端口迁移准备失败并已回滚"
        return 1
    fi

    if [[ "$socket_managed" == "yes" ]] \
        && ! write_managed_content "$SSH_SOCKET_DROPIN" 644 "$(render_ssh_socket_ports "$old_port" "$new_port")"; then
        rollback_ssh_port_start "$include_backup" "$port_backup" "${socket_backup:-}" "$socket_managed" "$old_comment" "$new_comment" "$old_port" || true
        error "ssh.socket 配置失败并已回滚"
        return 1
    fi

    if ! sshd -t || ! reload_ssh_runtime "$socket_managed" "$old_port" "$new_port"; then
        rollback_ssh_port_start "$include_backup" "$port_backup" "${socket_backup:-}" "$socket_managed" "$old_comment" "$new_comment" "$old_port" || true
        error "SSH 端口迁移启动失败并已回滚"
        return 1
    fi

    if ! save_ssh_port_state "$old_port" "$new_port" "$socket_managed" "$old_comment" "$new_comment"; then
        rollback_ssh_port_start "$include_backup" "$port_backup" "${socket_backup:-}" "$socket_managed" "$old_comment" "$new_comment" "$old_port" || true
        error "SSH 端口迁移状态保存失败并已回滚"
        return 1
    fi
    ok "新端口 ${new_port} 已启用 旧端口 ${old_port} 仍保留"
    warn "请从新终端验证端口 ${new_port} 登录成功后再完成迁移"
}

# 收集 SSH 配置文件
collect_ssh_config_files() {
    printf '%s\n' "$SSH_MAIN_CONFIG"
    if [[ -d "$SSH_CONFIG_DIR" ]]; then
        find "$SSH_CONFIG_DIR" -maxdepth 1 -type f -name '*.conf' ! -path "$SSH_PORT_CONFIG" -print
    fi
}

# 完成 SSH 端口迁移
finish_ssh_port_migration() {
    local old_port new_port socket_managed old_comment new_comment
    local port_backup socket_backup file backup tmp mode index
    local operation_failed=0
    local -a changed_files=()
    local -a changed_backups=()

    [[ -s "$SSH_PORT_STATE" ]] || { info "当前没有待完成的端口迁移"; return 0; }
    IFS=$'\t' read -r old_port new_port socket_managed old_comment new_comment < "$SSH_PORT_STATE"
    validate_port "$old_port" && validate_port "$new_port" || { error "端口迁移状态无效"; return 1; }

    warn "仅在新端口 ${new_port} 已通过独立 SSH 会话验证后继续"
    confirm "确认关闭旧 SSH 端口 ${old_port}？" N || return 0

    if ! port_backup=$(backup_file "$SSH_PORT_CONFIG"); then
        error "SSH 端口配置备份失败"
        return 1
    fi
    if [[ "$socket_managed" == "yes" ]]; then
        if ! socket_backup=$(backup_file "$SSH_SOCKET_DROPIN"); then
            error "ssh.socket 配置备份失败"
            return 1
        fi
    fi

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        if grep -Eiq "^[[:space:]]*Port[[:space:]]+${old_port}([[:space:]#]|$)" "$file"; then
            if ! backup=$(backup_file "$file") || ! tmp=$(mktemp); then
                operation_failed=1
                break
            fi
            if ! comment_ssh_port "$old_port" < "$file" > "$tmp" \
                || ! mode=$(stat -c '%a' "$file") \
                || ! install -m "$mode" "$tmp" "$file"; then
                rm -f "$tmp"
                restore_file "$file" "$backup"
                operation_failed=1
                break
            fi
            rm -f "$tmp"
            changed_files+=("$file")
            changed_backups+=("$backup")
        fi
    done < <(collect_ssh_config_files)

    if (( operation_failed == 0 )) \
        && ! write_managed_content "$SSH_PORT_CONFIG" 600 "$(render_ssh_ports "$new_port")"; then
        operation_failed=1
    fi
    if (( operation_failed == 0 )) && [[ "$socket_managed" == "yes" ]] \
        && ! write_managed_content "$SSH_SOCKET_DROPIN" 644 "$(render_ssh_socket_ports "$new_port")"; then
        operation_failed=1
    fi

    if (( operation_failed == 1 )); then
        restore_file "$SSH_PORT_CONFIG" "$port_backup"
        [[ "$socket_managed" == "yes" ]] && restore_file "$SSH_SOCKET_DROPIN" "${socket_backup:-}"
        for (( index=0; index<${#changed_files[@]}; index++ )); do
            restore_file "${changed_files[$index]}" "${changed_backups[$index]}"
        done
        error "SSH 端口配置写入失败并已回滚"
        return 1
    fi

    if ! sshd -t || ! reload_ssh_runtime "$socket_managed" "$new_port"; then
        restore_file "$SSH_PORT_CONFIG" "$port_backup"
        [[ "$socket_managed" == "yes" ]] && restore_file "$SSH_SOCKET_DROPIN" "${socket_backup:-}"
        for (( index=0; index<${#changed_files[@]}; index++ )); do
            restore_file "${changed_files[$index]}" "${changed_backups[$index]}"
        done
        sshd -t >/dev/null 2>&1 && reload_ssh_runtime "$socket_managed" "$old_port" "$new_port" >/dev/null 2>&1 || true
        error "关闭旧 SSH 端口失败并已回滚"
        return 1
    fi

    if ! delete_ssh_migration_ufw_rule "$old_comment"; then
        error "旧端口已关闭但 UFW 迁移规则清理失败"
        warn "请修复 UFW 后重新执行完成迁移"
        return 1
    fi
    if ! rm -f "$SSH_PORT_STATE"; then
        error "SSH 迁移已生效但状态文件清理失败"
        return 1
    fi
    ok "SSH 已迁移到端口 ${new_port}"
}

# 检查 Fail2Ban 管理环境
check_fail2ban_environment() {
    check_debian_family || return 1
    install_apt_packages "Fail2Ban 服务" fail2ban python3-systemd || return 1
    command -v fail2ban-client >/dev/null 2>&1 || { error "未找到 fail2ban-client 命令"; return 1; }
    command -v systemctl >/dev/null 2>&1 || { error "未找到 systemctl 命令"; return 1; }
}

# 检查 recidive 管理状态
managed_recidive_enabled() {
    [[ -f "$FAIL2BAN_CONFIG" ]] && grep -q '^\[recidive\]$' "$FAIL2BAN_CONFIG"
}

# 写入 Fail2Ban 管理配置
apply_fail2ban_config() {
    local enable_recidive=$1
    local ports backup
    ports=$(all_current_ssh_ports | paste -sd, -)
    if [[ -z "$ports" ]]; then
        error "无法确定 SSH 监听端口"
        return 1
    fi
    if ! backup=$(backup_file "$FAIL2BAN_CONFIG"); then
        error "Fail2Ban 配置备份失败"
        return 1
    fi
    if ! write_managed_content "$FAIL2BAN_CONFIG" 644 "$(render_fail2ban_config "$enable_recidive" "$ports")"; then
        restore_file "$FAIL2BAN_CONFIG" "$backup"
        error "Fail2Ban 配置写入失败并已回滚"
        return 1
    fi
    if ! fail2ban-client -t; then
        restore_file "$FAIL2BAN_CONFIG" "$backup"
        fail2ban-client -t >/dev/null 2>&1 || true
        error "Fail2Ban 配置校验失败并已回滚"
        return 1
    fi
    if ! systemctl restart fail2ban; then
        restore_file "$FAIL2BAN_CONFIG" "$backup"
        fail2ban-client -t >/dev/null 2>&1 && systemctl restart fail2ban >/dev/null 2>&1 || true
        error "Fail2Ban 重启失败并已回滚"
        return 1
    fi
    if ! systemctl enable fail2ban >/dev/null 2>&1; then
        error "Fail2Ban 配置已生效但设置开机启动失败"
        return 1
    fi
    ok "Fail2Ban 配置已生效"
}

# 配置 Fail2Ban SSH 防护
configure_fail2ban_sshd() {
    local recidive=no
    managed_recidive_enabled && recidive=yes
    confirm "确认配置并启用 sshd jail？" Y || return 0
    apply_fail2ban_config "$recidive"
}

# 设置 recidive 防护
set_fail2ban_recidive() {
    local enable=$1
    if [[ "$enable" == "yes" ]]; then
        warn "recidive 会长期封禁反复触发规则的来源"
        confirm "确认启用 recidive jail？" N || return 0
    else
        confirm "确认禁用 recidive jail？" N || return 0
    fi
    apply_fail2ban_config "$enable"
}

# 显示 Fail2Ban 状态
show_fail2ban_status() {
    systemctl --no-pager --full status fail2ban 2>/dev/null | sed -n '1,8p' || true
    echo
    fail2ban-client status 2>/dev/null || true
    fail2ban-client status sshd 2>/dev/null || true
    if managed_recidive_enabled; then
        fail2ban-client status recidive 2>/dev/null || true
    fi
}

# 控制 Fail2Ban 服务
control_fail2ban_service() {
    local action=$1
    if [[ "$action" == "stop" ]]; then
        warn "停止 Fail2Ban 会暂停自动封禁"
        confirm "确认停止 Fail2Ban？" N || return 0
    fi
    systemctl "$action" fail2ban
    ok "Fail2Ban 已执行 ${action}"
}

# SSH 安全管理菜单
ssh_management_menu() {
    local choice

    clear || true
    echo "正在检查 SSH 管理环境..."
    if ! run_mutation_action "准备 SSH 管理环境" check_ssh_environment; then
        pause
        return 0
    fi

    while true; do
        clear || true
        echo "========================================"
        echo "SSH 安全管理"
        echo "========================================"
        echo "1) 查看 SSH 状态"
        echo "2) 添加 root SSH 公钥"
        echo "3) 开始 SSH 端口迁移"
        echo "4) 完成 SSH 端口迁移"
        echo "5) 禁用密码并启用密钥登录"
        echo "6) 校验并重载 SSH"
        echo "0) 返回主菜单"
        read -r -p "请选择: " choice

        case "$choice" in
            1) show_ssh_status; pause ;;
            2) if run_mutation_action "添加 root SSH 公钥" add_root_public_key_interactive; then :; else :; fi; pause ;;
            3) if run_mutation_action "开始 SSH 端口迁移" start_ssh_port_migration; then :; else :; fi; pause ;;
            4) if run_mutation_action "完成 SSH 端口迁移" finish_ssh_port_migration; then :; else :; fi; pause ;;
            5) if run_mutation_action "应用 SSH 加固" apply_ssh_hardening; then :; else :; fi; pause ;;
            6)
                if sshd -t && reload_ssh_runtime no; then
                    ok "SSH 配置校验通过并已重载"
                else
                    error "SSH 配置校验或重载失败"
                fi
                pause
                ;;
            0) return 0 ;;
            *) warn "无效选项"; pause ;;
        esac
    done
}

# Fail2Ban 管理菜单
fail2ban_management_menu() {
    local choice

    clear || true
    echo "正在检查 Fail2Ban 管理环境..."
    if ! run_mutation_action "准备 Fail2Ban 管理环境" check_fail2ban_environment; then
        pause
        return 0
    fi

    while true; do
        clear || true
        echo "========================================"
        echo "Fail2Ban 管理"
        echo "========================================"
        echo "1) 查看状态"
        echo "2) 配置并启用 sshd jail"
        echo "3) 启用 recidive jail"
        echo "4) 禁用 recidive jail"
        echo "5) 启动服务"
        echo "6) 停止服务"
        echo "7) 重启服务"
        echo "8) 设置开机启动"
        echo "0) 返回主菜单"
        read -r -p "请选择: " choice

        case "$choice" in
            1) show_fail2ban_status; pause ;;
            2) if run_mutation_action "配置 Fail2Ban sshd" configure_fail2ban_sshd; then :; else :; fi; pause ;;
            3) if run_mutation_action "启用 Fail2Ban recidive" set_fail2ban_recidive yes; then :; else :; fi; pause ;;
            4) if run_mutation_action "禁用 Fail2Ban recidive" set_fail2ban_recidive no; then :; else :; fi; pause ;;
            5) if run_mutation_action "启动 Fail2Ban" control_fail2ban_service start; then :; else :; fi; pause ;;
            6) if run_mutation_action "停止 Fail2Ban" control_fail2ban_service stop; then :; else :; fi; pause ;;
            7) if run_mutation_action "重启 Fail2Ban" control_fail2ban_service restart; then :; else :; fi; pause ;;
            8) if run_mutation_action "启用 Fail2Ban 开机启动" control_fail2ban_service enable; then :; else :; fi; pause ;;
            0) return 0 ;;
            *) warn "无效选项"; pause ;;
        esac
    done
}

check_debian_family() {
    if [[ ! -r /etc/os-release ]]; then
        error "无法读取 /etc/os-release，不能确认系统类型"
        return 1
    fi

    # shellcheck disable=SC1091
    . /etc/os-release
    local id=${ID:-}
    local like=${ID_LIKE:-}

    if [[ "$id" != "debian" && "$id" != "ubuntu" && " $like " != *" debian "* ]]; then
        error "当前系统不是 Debian 系发行版：ID=${id:-unknown} ID_LIKE=${like:-unknown}"
        return 1
    fi

    if ! command -v apt-get >/dev/null 2>&1; then
        error "当前系统未提供 apt-get，脚本无法自动安装安全组件"
        return 1
    fi

    info "系统校验通过：${PRETTY_NAME:-$id}"
}

is_ufw_active() {
    ufw status 2>/dev/null | grep -q '^Status: active$'
}

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

install_ufw_if_needed() {
    UFW_JUST_INSTALLED=0

    if command -v ufw >/dev/null 2>&1; then
        return 0
    fi

    warn "当前系统未安装 UFW"
    if ! confirm "是否现在安装 UFW？" Y; then
        warn "已取消安装，返回上一级菜单"
        return 1
    fi

    if ! apt-get update; then
        error "apt-get update 执行失败"
        return 1
    fi

    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y ufw; then
        error "UFW 安装失败"
        return 1
    fi

    if ! command -v ufw >/dev/null 2>&1; then
        error "安装完成后仍未找到 ufw 命令"
        return 1
    fi

    UFW_JUST_INSTALLED=1
    ok "UFW 安装完成"
}

init_state() {
    if ! install -d -m 700 "$STATE_DIR"; then
        error "无法创建状态目录：${STATE_DIR}"
        return 1
    fi
    if ! touch "$STATE_FILE" || ! chmod 600 "$STATE_FILE"; then
        error "无法初始化状态文件：${STATE_FILE}"
        return 1
    fi
    if [[ ! -f "$BEFORE_RULES" ]]; then
        error "未找到 ${BEFORE_RULES}，请检查 UFW 安装状态"
        return 1
    fi
}

validate_port() {
    local port=${1:-}
    [[ "$port" =~ ^[0-9]+$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 ))
}

validate_port_spec() {
    local spec=${1:-}
    local item start end count=0
    local -a items=()

    [[ "$spec" =~ ^([0-9]+|[0-9]+:[0-9]+)(,([0-9]+|[0-9]+:[0-9]+))*$ ]] || return 1

    IFS=',' read -r -a items <<< "$spec"
    for item in "${items[@]}"; do
        if [[ "$item" == *:* ]]; then
            start=${item%%:*}
            end=${item##*:}
            validate_port "$start" || return 1
            validate_port "$end" || return 1
            (( 10#$start <= 10#$end )) || return 1
            (( count += 2 ))
        else
            validate_port "$item" || return 1
            (( count += 1 ))
        fi
    done

    # UFW 最多支持 15 个端口元素，端口范围按两个元素计算
    (( count <= 15 ))
}

# 只接受可安全作为单个 ip/ufw 参数传递的 Linux 网卡名。
validate_interface_name() {
    local iface=${1:-}
    [[ "$iface" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$ ]]
}

managed_marker() {
    local batch_id=${1:-} rule_id=${2:-}
    printf 'lsec:%s:%s' "$batch_id" "$rule_id"
}

validate_managed_marker() {
    local marker=${1:-}
    [[ "$marker" =~ ^lsec:[A-Za-z0-9._-]+:[A-Za-z0-9._-]+$ ]]
}

state_marker_count() {
    local marker=$1
    [[ -f "$STATE_FILE" ]] || { printf '0\n'; return 0; }
    awk -F '\t' -v marker="$marker" '$1 == marker {count++} END {print count + 0}' "$STATE_FILE"
}

state_has_unique_marker() {
    local marker=$1
    validate_managed_marker "$marker" || return 1
    [[ $(state_marker_count "$marker") == 1 ]]
}

validate_ipv4() {
    local ip=${1:-}
    local a b c d extra
    IFS=. read -r a b c d extra <<< "$ip"
    [[ -z ${extra:-} && -n ${a:-} && -n ${b:-} && -n ${c:-} && -n ${d:-} ]] || return 1
    [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$c" =~ ^[0-9]+$ && "$d" =~ ^[0-9]+$ ]] || return 1
    (( 10#$a <= 255 && 10#$b <= 255 && 10#$c <= 255 && 10#$d <= 255 ))
}

validate_ipv4_cidr_or_any() {
    local value=${1:-}
    local ip prefix
    [[ "$value" == "any" ]] && return 0

    if [[ "$value" == */* ]]; then
        ip=${value%/*}
        prefix=${value#*/}
        validate_ipv4 "$ip" || return 1
        [[ "$prefix" =~ ^[0-9]+$ ]] && (( 10#$prefix >= 0 && 10#$prefix <= 32 ))
    else
        validate_ipv4 "$value"
    fi
}

# 校验 IPv6 地址
validate_ipv6() {
    local ip=${1:-}
    local left right group
    local -a groups=()
    local count=0

    [[ "$ip" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
    [[ "$ip" != *:::* ]] || return 1

    if [[ "$ip" == *::* ]]; then
        left=${ip%%::*}
        right=${ip#*::}
        [[ "$right" != *::* ]] || return 1
        for group in "$left" "$right"; do
            [[ -n "$group" ]] || continue
            IFS=: read -r -a groups <<< "$group"
            for group in "${groups[@]}"; do
                [[ "$group" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
                (( count += 1 ))
            done
        done
        (( count < 8 ))
        return
    fi

    [[ "$ip" != :* && "$ip" != *: ]] || return 1
    IFS=: read -r -a groups <<< "$ip"
    (( ${#groups[@]} == 8 )) || return 1
    for group in "${groups[@]}"; do
        [[ "$group" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
    done
}

# 校验 UFW 地址参数
validate_address_token_or_any() {
    local value=${1:-}
    local address prefix=
    [[ "$value" == "any" ]] && return 0

    if [[ "$value" == */* ]]; then
        address=${value%/*}
        prefix=${value#*/}
        [[ "$address" != */* && "$prefix" != */* && "$prefix" =~ ^[0-9]+$ ]] || return 1
    else
        address=$value
    fi

    if [[ "$address" == *:* ]]; then
        validate_ipv6 "$address" || return 1
        [[ -z "$prefix" ]] || (( 10#$prefix <= 128 ))
    else
        validate_ipv4 "$address" || return 1
        [[ -z "$prefix" ]] || (( 10#$prefix <= 32 ))
    fi
}

validate_interface() {
    local iface=${1:-}
    validate_interface_name "$iface" && ip link show dev "$iface" >/dev/null 2>&1
}

default_interface() {
    ip -4 route show default 2>/dev/null | awk 'NR==1 {print $5}'
}

route_interface_to() {
    local ip=$1
    ip -4 route get "$ip" 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}'
}

detect_ssh_ports() {
    local -a ports=()
    local port addr
    local allow_default=${1:-yes}

    if [[ -n ${SSH_CONNECTION:-} ]]; then
        read -r -a ssh_parts <<< "$SSH_CONNECTION"
        if (( ${#ssh_parts[@]} >= 4 )) && validate_port "${ssh_parts[3]}"; then
            ports+=("${ssh_parts[3]}")
        fi
    fi

    if command -v sshd >/dev/null 2>&1; then
        while read -r port; do
            validate_port "$port" && ports+=("$port")
        done < <(sshd -T 2>/dev/null | awk '$1=="port" {print $2}')
    fi

    if command -v ss >/dev/null 2>&1; then
        while read -r addr; do
            port=${addr##*:}
            port=${port//]/}
            validate_port "$port" && ports+=("$port")
        done < <(ss -H -lntp 2>/dev/null | awk '/sshd/ {print $4}')
    fi

    if (( ${#ports[@]} == 0 )) && [[ "$allow_default" == "yes" ]]; then
        ports=(22)
    fi

    (( ${#ports[@]} > 0 )) && printf '%s\n' "${ports[@]}" | sort -n -u
}

add_inbound_allow_rule() {
    local port=$1
    local proto=$2
    local comment=${3:-"managed-by-ufw-manager"}
    ufw allow in proto "$proto" from any to any port "$port" comment "$comment"
}

select_common_inbound_ports() {
    local -a ssh_ports=()
    local selected choice custom_port proto_choice
    mapfile -t ssh_ports < <(detect_ssh_ports)

    echo
    echo "启用 UFW 前，请选择需要保留的入站端口（可多选，逗号分隔）："
    echo "  1) 当前 SSH 端口：$(IFS=,; echo "${ssh_ports[*]}")/tcp（默认，强烈建议）"
    echo "  2) HTTP：80/tcp"
    echo "  3) HTTPS：443/tcp"
    echo "  4) HTTP/3 / QUIC：443/udp"
    echo "  5) DNS：53/tcp + 53/udp"
    echo "  6) 自定义端口"
    read -r -p "请选择 [默认 1]: " selected
    selected=${selected:-1}
    selected=${selected// /}

    IFS=',' read -r -a choices <<< "$selected"
    for choice in "${choices[@]}"; do
        case "$choice" in
            1)
                for custom_port in "${ssh_ports[@]}"; do
                    add_inbound_allow_rule "$custom_port" tcp "SSH-${custom_port}"
                done
                ;;
            2) add_inbound_allow_rule 80 tcp "HTTP" ;;
            3) add_inbound_allow_rule 443 tcp "HTTPS" ;;
            4) add_inbound_allow_rule 443 udp "HTTP3-QUIC" ;;
            5)
                add_inbound_allow_rule 53 tcp "DNS-TCP"
                add_inbound_allow_rule 53 udp "DNS-UDP"
                ;;
            6)
                while true; do
                    read -r -p "请输入自定义端口（1-65535，直接回车结束）: " custom_port
                    [[ -z "$custom_port" ]] && break
                    if ! validate_port "$custom_port"; then
                        warn "端口格式无效"
                        continue
                    fi
                    echo "协议：1) TCP  2) UDP  3) TCP+UDP"
                    read -r -p "请选择 [默认 1]: " proto_choice
                    proto_choice=${proto_choice:-1}
                    case "$proto_choice" in
                        1) add_inbound_allow_rule "$custom_port" tcp "CUSTOM-${custom_port}-TCP" ;;
                        2) add_inbound_allow_rule "$custom_port" udp "CUSTOM-${custom_port}-UDP" ;;
                        3)
                            add_inbound_allow_rule "$custom_port" tcp "CUSTOM-${custom_port}-TCP"
                            add_inbound_allow_rule "$custom_port" udp "CUSTOM-${custom_port}-UDP"
                            ;;
                        *) warn "协议选择无效，已跳过端口 ${custom_port}" ;;
                    esac
                done
                ;;
            *) warn "忽略无效选项：$choice" ;;
        esac
    done

    # 当前会话通过 SSH 接入时，无论菜单是否选择，都确保当前 SSH 服务端口已放行。
    if [[ -n ${SSH_CONNECTION:-} ]]; then
        read -r -a ssh_parts <<< "$SSH_CONNECTION"
        if (( ${#ssh_parts[@]} >= 4 )) && validate_port "${ssh_parts[3]}"; then
            info "检测到当前 SSH 会话使用端口 ${ssh_parts[3]}，将确保该端口已放行"
            add_inbound_allow_rule "${ssh_parts[3]}" tcp "CURRENT-SSH-${ssh_parts[3]}"
        fi
    fi
}

resolve_ssh_ports_for_ufw() {
    local port_spec phrase port
    local -a ports=() parsed=()
    while IFS= read -r port; do
        validate_port "$port" && ports+=("$port")
    done < <(detect_ssh_ports no)
    if (( ${#ports[@]} > 0 )); then
        printf '%s\n' "${ports[@]}" | sort -n -u
        return 0
    fi

    warn "无法从 SSH 会话、sshd 生效配置或监听套接字可靠确定 SSH 端口" >&2
    read -r -p "请输入必须放行的 SSH 端口，多个用逗号分隔: " port_spec
    [[ "$port_spec" =~ ^[0-9]+(,[0-9]+)*$ ]] || return "$RESULT_PRECHECK_FAILED"
    IFS=',' read -r -a parsed <<< "$port_spec"
    for port in "${parsed[@]}"; do
        validate_port "$port" || return "$RESULT_PRECHECK_FAILED"
    done
    warn "高风险确认短语：${UFW_RISK_CONFIRMATION}" >&2
    read -r -p "请完整输入确认短语，或直接回车取消: " phrase
    [[ "$phrase" == "$UFW_RISK_CONFIRMATION" ]] || return "$RESULT_CANCELLED"
    printf '%s\n' "${parsed[@]}" | sort -n -u
}

snapshot_ufw_bootstrap() {
    local batch_id=$1
    local snapshot="${BACKUP_DIR}/${batch_id}"
    ufw status verbose > "$snapshot/ufw-status-before.txt" || return 1
    ufw show added > "$snapshot/ufw-added-before.txt" || return 1
    chmod 600 "$snapshot/ufw-status-before.txt" "$snapshot/ufw-added-before.txt"
}

restore_ufw_default_policies() {
    local batch_id=$1 line incoming outgoing routed
    line=$(grep '^Default:' "${BACKUP_DIR}/${batch_id}/ufw-status-before.txt" | head -1) || return 1
    incoming=$(sed -n 's/^Default: \([^ ]*\) (incoming).*/\1/p' <<< "$line")
    outgoing=$(sed -n 's/^Default: [^,]*, \([^ ]*\) (outgoing).*/\1/p' <<< "$line")
    routed=$(sed -n 's/^Default: [^,]*, [^,]*, \([^ ]*\) (routed).*/\1/p' <<< "$line")
    [[ -n "$incoming" && -n "$outgoing" && -n "$routed" ]] || return 1
    ufw default "$incoming" incoming || return 1
    ufw default "$outgoing" outgoing || return 1
    ufw default "$routed" routed
}

verify_ufw_bootstrap_markers() {
    local batch_id=$1 port marker added
    shift
    added=$(ufw show added 2>/dev/null) || return 1
    for port in "$@"; do
        marker=$(managed_marker "$batch_id" "ssh-${port}")
        grep -Fq -- "$marker" <<< "$added" || return 1
    done
}

rollback_ufw_bootstrap() {
    local batch_id=$1 result=0
    if is_ufw_active; then
        ufw disable || result=1
    fi
    remove_transaction_ufw_rules "$batch_id" || result=1
    restore_ufw_default_policies "$batch_id" || result=1
    is_ufw_active && result=1
    verify_transaction_ufw_rules_absent "$batch_id" || result=1
    if (( result == 0 )); then
        set_transaction_phase "$batch_id" rolled_back
        return 0
    fi
    protect_failed_transaction "$batch_id" rollback_failed '无法验证 UFW 初始化回滚'
    return 1
}

enable_ufw_transaction() {
    local batch_id=$1 port marker failure_result=$RESULT_APPLY_FAILED_ROLLED_BACK
    shift
    local -a ssh_ports=("$@")
    (( ${#ssh_ports[@]} > 0 )) || return "$RESULT_PRECHECK_FAILED"
    begin_transaction "$batch_id" enable_ufw "$(IFS=,; echo "${ssh_ports[*]}")" \
        || return "$RESULT_PRECHECK_FAILED"
    snapshot_ufw_bootstrap "$batch_id" || {
        set_transaction_phase "$batch_id" rolled_back 'UFW 初始化快照不完整，未执行变更' || true
        set_snapshot_status "$batch_id" failed || true
        return "$RESULT_PRECHECK_FAILED"
    }
    if set_transaction_phase "$batch_id" applying_ufw \
        && ufw default deny incoming \
        && ufw default allow outgoing \
        && ufw default deny routed; then
        for port in "${ssh_ports[@]}"; do
            marker=$(managed_marker "$batch_id" "ssh-${port}")
            if record_intended_ufw_marker "$batch_id" "$marker" \
                && add_inbound_allow_rule "$port" tcp "$marker" \
                && record_added_ufw_marker "$batch_id" "$marker"; then
                :
            else
                break
            fi
        done
        if verify_ufw_bootstrap_markers "$batch_id" "${ssh_ports[@]}" \
            && confirm_ufw_activation_after_ssh_check "${ssh_ports[@]}" \
            && ufw --force enable \
            && ufw logging low \
            && is_ufw_active \
            && verify_ufw_bootstrap_markers "$batch_id" "${ssh_ports[@]}"; then
            set_transaction_phase "$batch_id" verified \
                && finish_transaction "$batch_id" committed \
                && return "$RESULT_OK"
        fi
    fi
    if rollback_ufw_bootstrap "$batch_id"; then
        return "$failure_result"
    fi
    return "$RESULT_ROLLBACK_FAILED"
}

confirm_ufw_activation_after_ssh_check() {
    local ports=("$@")
    warn "SSH 放行规则已写入并验证，下一步将启用 UFW；当前 SSH 端口：${ports[*]}"
    ufw show added || return 1
    ufw status verbose || return 1
    confirm "确认现在启用 UFW？" N
}

setup_and_enable_ufw_locked() {
    local batch_id mode result port ssh_output
    local -a ssh_ports=()

    if is_ufw_active; then
        info "UFW 当前已启用"
        return "$RESULT_OK"
    fi
    if ssh_output=$(resolve_ssh_ports_for_ufw); then
        result=$RESULT_OK
    else
        return $?
    fi
    while IFS= read -r port; do
        [[ -n "$port" ]] && ssh_ports+=("$port")
    done <<< "$ssh_output"
    (( ${#ssh_ports[@]} > 0 )) || return "$RESULT_PRECHECK_FAILED"
    batch_id=$(new_batch_id)
    render_execution_preview enable_ufw "lsec:${batch_id}:ssh-{${ssh_ports[*]}}" \
        "先放行并验证 SSH TCP 端口 ${ssh_ports[*]}，再设置默认策略并启用 UFW" \
        "$BEFORE_RULES" "$STATE_FILE" '不修改 IPv4 forwarding'
    mode=$(select_execution_mode)
    case "$mode" in
        preflight)
            info "SSH 端口识别和 UFW 前置检查通过，未执行任何变更"
            return "$RESULT_OK"
            ;;
        cancel) return "$RESULT_CANCELLED" ;;
    esac
    if enable_ufw_transaction "$batch_id" "${ssh_ports[@]}"; then
        ok "UFW 已启用，SSH 放行规则与本机状态均已验证"
        return "$RESULT_OK"
    fi
    return $?
}

setup_and_enable_ufw() {
    local result
    if is_ufw_active; then
        info "UFW 当前已启用"
        return "$RESULT_OK"
    fi
    if begin_mutation "安全初始化并启用 UFW"; then :; else
        result=$?
        error "$(result_message "$result")"
        return "$result"
    fi
    if require_mutation_allowed; then :; else
        result=$?
        end_mutation
        error "$(result_message "$result")"
        return "$result"
    fi
    if run_dependency_preflight; then :; else
        result=$?
        end_mutation
        warn "$(result_message "$result")"
        return "$result"
    fi
    if setup_and_enable_ufw_locked; then result=$RESULT_OK; else result=$?; fi
    end_mutation
    case "$result" in
        0) ;;
        10) warn "$(result_message "$result")" ;;
        *) error "$(result_message "$result")" ;;
    esac
    return "$result"
}

ensure_ipv4_forwarding() {
    local file="$UFW_SYSCTL_FILE"
    local tmp
    tmp=$(mktemp) || return 1

    if [[ -f "$file" ]] && grep -Eq '^[[:space:]]*net[./]ipv4[./]ip_forward[[:space:]]*=' "$file"; then
        if ! awk '
            $0 ~ "^[[:space:]]*net[./]ipv4[./]ip_forward[[:space:]]*=" {
                if (!done) print "net/ipv4/ip_forward=1"
                done=1
                next
            }
            { print }
        ' "$file" > "$tmp"; then
            rm -f -- "$tmp"
            return 1
        fi
    else
        if [[ -f "$file" ]] && ! cat "$file" > "$tmp"; then
            rm -f -- "$tmp"
            return 1
        fi
        if ! printf '\n# Enabled by UFW relay manager\nnet/ipv4/ip_forward=1\n' >> "$tmp"; then
            rm -f -- "$tmp"
            return 1
        fi
    fi

    if ! install -d -m 755 "$(dirname "$file")" || ! install -m 644 "$tmp" "$file"; then
        rm -f -- "$tmp"
        return 1
    fi
    rm -f -- "$tmp"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
}

backup_before_rules() {
    local backup_dir="${STATE_DIR}/backups"
    local backup
    install -d -m 700 "$backup_dir"
    backup=$(mktemp "${backup_dir}/before.rules.$(date +%Y%m%d%H%M%S).bak.XXXXXX")
    if ! cp -a "$BEFORE_RULES" "$backup"; then
        rm -f "$backup"
        return 1
    fi
    printf '%s\n' "$backup"
}

ensure_nat_managed_section() {
    local tmp tmp2 nat_block need_pre=0 need_post=0 nat_table_count
    tmp=$(mktemp)
    tmp2=$(mktemp)

    if validate_nat_managed_section "$BEFORE_RULES"; then
        rm -f "$tmp" "$tmp2"
        return 0
    fi
    if nat_managed_markers_present "$BEFORE_RULES"; then
        rm -f "$tmp" "$tmp2"
        error "NAT 受管区标记重复、错序或不在唯一的 *nat 表内"
        protect_nat_structure_drift || true
        return 1
    fi
    nat_table_count=$(awk '/^\*nat[[:space:]]*$/ {count++} END {print count + 0}' "$BEFORE_RULES")
    if (( nat_table_count > 1 )); then
        rm -f "$tmp" "$tmp2"
        error "检测到多个 *nat 表，拒绝自动插入受管区"
        return 1
    fi

    if grep -Eq '^\*nat[[:space:]]*$' "$BEFORE_RULES"; then
        nat_block=$(awk '
            /^\*nat[[:space:]]*$/ {inside=1}
            inside {print}
            inside && /^COMMIT[[:space:]]*$/ {exit}
        ' "$BEFORE_RULES")

        grep -Eq '^:PREROUTING[[:space:]]' <<< "$nat_block" || need_pre=1
        grep -Eq '^:POSTROUTING[[:space:]]' <<< "$nat_block" || need_post=1

        awk -v need_pre="$need_pre" -v need_post="$need_post" '
            !done && /^\*nat[[:space:]]*$/ {
                print
                if (need_pre == 1) print ":PREROUTING ACCEPT [0:0]"
                if (need_post == 1) print ":POSTROUTING ACCEPT [0:0]"
                done=1
                next
            }
            {print}
        ' "$BEFORE_RULES" > "$tmp"

        awk -v begin="$NAT_BEGIN" -v end="$NAT_END" '
            /^\*nat[[:space:]]*$/ && !inserted {inside=1}
            inside && /^COMMIT[[:space:]]*$/ && !inserted {
                print begin
                print end
                inserted=1
                inside=0
            }
            {print}
        ' "$tmp" > "$tmp2"
    else
        {
            echo "# UFW relay manager NAT table"
            echo "*nat"
            echo ":PREROUTING ACCEPT [0:0]"
            echo ":POSTROUTING ACCEPT [0:0]"
            echo "$NAT_BEGIN"
            echo "$NAT_END"
            echo "COMMIT"
            echo
            cat "$BEFORE_RULES"
        } > "$tmp2"
    fi

    install -m 640 "$tmp2" "$BEFORE_RULES"
    rm -f "$tmp" "$tmp2"
}

protect_nat_structure_drift() {
    install -d -m 700 "$STATE_DIR" || return 1
    atomic_write "$PROTECTED_LOCK" write_protected_record nat-structure repair_required \
        'NAT 受管区标记重复、错序或位置无效'
}

# 有标记时，必须恰好存在一对有序标记，且位于唯一的 *nat/COMMIT 区间内。
validate_nat_managed_section() {
    local file=$1
    awk -v begin="$NAT_BEGIN" -v end="$NAT_END" '
        /^\*nat[[:space:]]*$/ {nat_tables++; in_nat=1; nat_closed=0; next}
        in_nat && /^COMMIT[[:space:]]*$/ {in_nat=0; next}
        $0 == begin {
            begins++
            if (!in_nat || ends > 0) invalid=1
            begin_seen=1
            next
        }
        $0 == end {
            ends++
            if (!in_nat || !begin_seen || ends > begins) invalid=1
            next
        }
        END {
            exit !(nat_tables == 1 && begins == 1 && ends == 1 && !invalid)
        }
    ' "$file"
}

nat_managed_markers_present() {
    local file=$1
    grep -Fq -e "$NAT_BEGIN" -e "$NAT_END" "$file"
}

# 在临时副本中生成整个转发批次，不修改正在使用的 before.rules。
stage_forward_nat() {
    local staged=$1 batch_id=$2 source=$3 in_if=$4 public_port=$5
    local out_if=$6 landing_ip=$7 landing_port=$8 masquerade=$9
    shift 9
    local proto marker source_match dnat_line snat_line
    local original_before_rules=$BEFORE_RULES result=0

    validate_address_token_or_any "$source" || return 1
    validate_interface_name "$in_if" || return 1
    validate_interface_name "$out_if" || return 1
    validate_port "$public_port" || return 1
    validate_ipv4 "$landing_ip" || return 1
    validate_port "$landing_port" || return 1
    [[ "$masquerade" == yes || "$masquerade" == no ]] || return 1
    (( $# > 0 )) || return 1

    cp -a "$BEFORE_RULES" "$staged" || return 1
    BEFORE_RULES=$staged
    if ! ensure_nat_managed_section; then
        result=1
    fi

    source_match=
    [[ "$source" != any ]] && source_match="-s ${source}"
    if (( result == 0 )); then
        for proto in "$@"; do
            if [[ "$proto" != tcp && "$proto" != udp ]]; then
                result=1
                break
            fi
            marker=$(managed_marker "$batch_id" "$proto")
            validate_managed_marker "$marker" || { result=1; break; }
            dnat_line="-A PREROUTING -i ${in_if} -p ${proto} ${source_match} --dport ${public_port} -m comment --comment ${marker}:dnat -j DNAT --to-destination ${landing_ip}:${landing_port}"
            insert_nat_rule_line "$dnat_line" || { result=1; break; }
            if [[ "$masquerade" == yes ]]; then
                snat_line="-A POSTROUTING -o ${out_if} -p ${proto} -d ${landing_ip} --dport ${landing_port} -m comment --comment ${marker}:snat -j MASQUERADE"
                insert_nat_rule_line "$snat_line" || { result=1; break; }
            fi
        done
    fi
    BEFORE_RULES=$original_before_rules
    return "$result"
}

validate_staged_nat() {
    local staged=$1
    [[ -s "$staged" ]] || return 1
    iptables-restore --test < "$staged"
}

apply_staged_nat_file() {
    local staged=$1
    install -m 640 "$staged" "$BEFORE_RULES"
}

add_forward_ufw_route() {
    local proto=$1 source=$2 in_if=$3 out_if=$4 landing_ip=$5 landing_port=$6 marker=$7
    ufw route allow in on "$in_if" out on "$out_if" proto "$proto" \
        from "$source" to "$landing_ip" port "$landing_port" comment "$marker"
}

render_state_with_forward_batch() {
    local current_state=$1 batch_id=$2 source=$3 in_if=$4 public_port=$5
    local out_if=$6 landing_ip=$7 landing_port=$8 masquerade=$9
    shift 9
    local proto marker

    [[ -f "$current_state" ]] || return 1
    cat "$current_state" || return 1
    for proto in "$@"; do
        marker=$(managed_marker "$batch_id" "$proto")
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$marker" "$proto" "$source" "$in_if" "$public_port" "$out_if" \
            "$landing_ip" "$landing_port" "$masquerade" "$batch_id" || return 1
    done
}

write_state_schema_version() {
    printf '%s\n' "$STATE_SCHEMA_VERSION"
}

commit_forward_state() {
    local batch_id=$1 source=$2 in_if=$3 public_port=$4 out_if=$5
    local landing_ip=$6 landing_port=$7 masquerade=$8
    shift 8
    atomic_write "$STATE_FILE" render_state_with_forward_batch "$STATE_FILE" \
        "$batch_id" "$source" "$in_if" "$public_port" "$out_if" \
        "$landing_ip" "$landing_port" "$masquerade" "$@" || return 1
    atomic_write "$STATE_VERSION_FILE" write_state_schema_version
}

record_added_ufw_marker() {
    local batch_id=$1 marker=$2
    printf '%s\n' "$marker" >> "${BACKUP_DIR}/${batch_id}/ufw-added.txt"
}

record_intended_ufw_marker() {
    local batch_id=$1 marker=$2
    printf '%s\n' "$marker" >> "${BACKUP_DIR}/${batch_id}/ufw-intended.txt"
}

apply_ipv4_forwarding_for_transaction() {
    local batch_id=$1 runtime persistent owned_runtime=no owned_persistent=no
    runtime=$(sysctl -n net.ipv4.ip_forward 2>/dev/null) || return 1
    persistent=$(persistent_ipv4_forwarding_value)
    if [[ "$runtime" == 1 && "$persistent" == 1 ]]; then
        return 0
    fi
    [[ "$runtime" == 1 ]] || owned_runtime=yes
    [[ "$persistent" == 1 ]] || owned_persistent=yes
    atomic_write "$IP_FORWARDING_STATE" write_ipv4_ownership_record \
        "$batch_id" "$runtime" "$persistent" "$owned_runtime" "$owned_persistent" || return 1
    ensure_ipv4_forwarding || return 1
    [[ $(sysctl -n net.ipv4.ip_forward 2>/dev/null) == 1 ]] \
        && [[ $(persistent_ipv4_forwarding_value) == 1 ]]
}

persistent_ipv4_forwarding_value() {
    [[ -f "$UFW_SYSCTL_FILE" ]] || { printf 'absent\n'; return 0; }
    awk -F '=' '
        $0 ~ "^[[:space:]]*net[./]ipv4[./]ip_forward[[:space:]]*=" {
            value=$2
            gsub(/[[:space:]]/, "", value)
        }
        END {print (value == "" ? "unset" : value)}
    ' "$UFW_SYSCTL_FILE"
}

write_ipv4_ownership_record() {
    local batch_id=$1 original_runtime=$2 original_persistent=$3
    local owned_runtime=$4 owned_persistent=$5
    printf 'owner_batch\t%s\n' "$batch_id"
    printf 'owner_snapshot\t%s\n' "${BACKUP_DIR}/${batch_id}"
    printf 'original_runtime\t%s\n' "$original_runtime"
    printf 'original_persistent\t%s\n' "$original_persistent"
    printf 'owned_runtime\t%s\n' "$owned_runtime"
    printf 'owned_persistent\t%s\n' "$owned_persistent"
}

detect_other_forwarding_use() {
    local marker line skip
    local -a ignored_markers=("$@")

    if [[ -s "$STATE_FILE" ]]; then
        while IFS=$'\t' read -r marker line; do
            [[ -n "$marker" ]] || continue
            skip=0
            if (( ${#ignored_markers[@]} > 0 )); then
                for line in "${ignored_markers[@]}"; do
                    [[ "$marker" == "$line" ]] && { skip=1; break; }
                done
            fi
            (( skip == 1 )) || return 0
        done < "$STATE_FILE"
    fi

    if [[ -f "$BEFORE_RULES" ]]; then
        while IFS= read -r line; do
            [[ "$line" == *'-j DNAT'* || "$line" == *'-j SNAT'* || "$line" == *'-j MASQUERADE'* ]] || continue
            skip=0
            if (( ${#ignored_markers[@]} > 0 )); then
                for marker in "${ignored_markers[@]}"; do
                    [[ "$line" == *"--comment ${marker}:"* ]] && { skip=1; break; }
                done
            fi
            (( skip == 1 )) || return 0
        done < "$BEFORE_RULES"
    fi
    return 1
}

write_empty_file() {
    :
}

restore_owned_ipv4_forwarding() {
    local owner_batch owned_runtime owned_persistent snapshot runtime_value
    [[ -s "$IP_FORWARDING_STATE" ]] || return 1
    owner_batch=$(awk -F '\t' '$1 == "owner_batch" {print $2; exit}' "$IP_FORWARDING_STATE")
    owned_runtime=$(awk -F '\t' '$1 == "owned_runtime" {print $2; exit}' "$IP_FORWARDING_STATE")
    owned_persistent=$(awk -F '\t' '$1 == "owned_persistent" {print $2; exit}' "$IP_FORWARDING_STATE")
    [[ "$owner_batch" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
    snapshot="${BACKUP_DIR}/${owner_batch}"
    [[ -d "$snapshot" ]] || return 1

    if [[ "$owned_persistent" == yes ]]; then
        if [[ -f "$snapshot/ufw-sysctl.conf.absent" ]]; then
            rm -f -- "$UFW_SYSCTL_FILE" || return 1
        else
            install -m 644 "$snapshot/ufw-sysctl.conf" "$UFW_SYSCTL_FILE" || return 1
        fi
    fi
    if [[ "$owned_runtime" == yes ]]; then
        runtime_value=$(cat "$snapshot/runtime-ip-forward") || return 1
        [[ "$runtime_value" == 0 || "$runtime_value" == 1 ]] || return 1
        sysctl -w "net.ipv4.ip_forward=${runtime_value}" >/dev/null || return 1
    fi

    if [[ "$owned_persistent" == yes ]]; then
        if [[ -f "$snapshot/ufw-sysctl.conf.absent" ]]; then
            [[ ! -e "$UFW_SYSCTL_FILE" ]] || return 1
        else
            cmp -s "$snapshot/ufw-sysctl.conf" "$UFW_SYSCTL_FILE" || return 1
        fi
    fi
    if [[ "$owned_runtime" == yes ]]; then
        [[ $(sysctl -n net.ipv4.ip_forward 2>/dev/null) == "$runtime_value" ]] || return 1
    fi
    atomic_write "$IP_FORWARDING_STATE" write_empty_file
}

verify_forwarding_batch() {
    local batch_id=$1
    shift
    local proto marker
    is_ufw_active || return 1
    verify_ipv4_forwarding_effective || return 1
    for proto in "$@"; do
        marker=$(managed_marker "$batch_id" "$proto")
        state_has_unique_marker "$marker" || return 1
        verify_nat_marker_effective "$marker" || return 1
        verify_ufw_marker_effective "$marker" || return 1
    done
}

normalize_iptables_rule() {
    sed -E 's/--comment "([^"]+)"/--comment \1/g; s/ -m (tcp|udp)( |$)/ /g; s/(-[sd] [0-9.]+)\/32([[:space:]]|$)/\1\2/g; s/[[:space:]]+/ /g; s/^ //; s/ $//'
}

normalize_iptables_rule_for_delete() {
    sed -E 's/--comment "([^"]+)"/--comment \1/g; s/[[:space:]]+/ /g; s/^ //; s/ $//'
}

verify_nat_marker_effective() {
    local marker=$1 row proto source in_if public_port out_if landing_ip landing_port masquerade batch
    local expected_dnat expected_snat persisted_dnat persisted_snat live_nat live_dnat live_snat
    row=$(awk -F '\t' -v marker="$marker" '$1 == marker {print}' "$STATE_FILE") || return 1
    [[ $(printf '%s\n' "$row" | awk 'NF {count++} END {print count + 0}') == 1 ]] || return 1
    IFS=$'\t' read -r marker proto source in_if public_port out_if landing_ip landing_port masquerade batch <<< "$row"
    expected_dnat=$(render_expected_dnat_rule "$marker" "$proto" "$source" "$in_if" \
        "$public_port" "$landing_ip" "$landing_port" | canonicalize_managed_nat_rules) || return 1
    expected_snat=$(render_expected_snat_rule "$marker" "$proto" "$out_if" \
        "$landing_ip" "$landing_port" | canonicalize_managed_nat_rules) || return 1
    persisted_dnat=$(normalize_iptables_rule_for_delete < "$BEFORE_RULES" \
        | managed_nat_rules_for_marker_and_chain "$marker" PREROUTING \
        | canonicalize_managed_nat_rules) || return 1
    [[ "$persisted_dnat" == "$expected_dnat" ]] || return 1
    persisted_snat=$(normalize_iptables_rule_for_delete < "$BEFORE_RULES" \
        | managed_nat_rules_for_marker_and_chain "$marker" POSTROUTING \
        | canonicalize_managed_nat_rules) || return 1
    if [[ "$masquerade" == yes ]]; then
        [[ "$persisted_snat" == "$expected_snat" ]] || return 1
    else
        [[ -z "$persisted_snat" ]] || return 1
    fi
    live_nat=$(iptables-save -t nat 2>/dev/null | normalize_iptables_rule_for_delete) || return 1
    live_dnat=$(managed_nat_rules_for_marker_and_chain "$marker" PREROUTING <<< "$live_nat" \
        | canonicalize_managed_nat_rules) || return 1
    [[ "$live_dnat" == "$expected_dnat" ]] || return 1
    live_snat=$(managed_nat_rules_for_marker_and_chain "$marker" POSTROUTING <<< "$live_nat" \
        | canonicalize_managed_nat_rules) || return 1
    if [[ "$masquerade" == yes ]]; then
        [[ "$live_snat" == "$expected_snat" ]] || return 1
    else
        [[ -z "$live_snat" ]] || return 1
    fi
}

render_expected_dnat_rule() {
    local marker=$1 proto=$2 source=$3 in_if=$4 public_port=$5 landing_ip=$6 landing_port=$7
    local source_match=
    [[ "$source" != any ]] && source_match="-s ${source} "
    printf '%s\n' "-A PREROUTING -i ${in_if} -p ${proto} ${source_match}--dport ${public_port} -m comment --comment ${marker}:dnat -j DNAT --to-destination ${landing_ip}:${landing_port}"
}

render_expected_snat_rule() {
    local marker=$1 proto=$2 out_if=$3 landing_ip=$4 landing_port=$5
    printf '%s\n' "-A POSTROUTING -o ${out_if} -p ${proto} -d ${landing_ip} --dport ${landing_port} -m comment --comment ${marker}:snat -j MASQUERADE"
}

ufw_numbered_lines_for_marker() {
    local marker=$1
    ufw status numbered 2>/dev/null | awk -v marker="$marker" '$NF == marker {print}'
}

verify_ufw_marker_effective() {
    local marker=$1 row proto source in_if public_port out_if landing_ip landing_port masquerade batch line
    row=$(awk -F '\t' -v marker="$marker" '$1 == marker {print}' "$STATE_FILE") || return 1
    [[ $(printf '%s\n' "$row" | awk 'NF {count++} END {print count + 0}') == 1 ]] || return 1
    IFS=$'\t' read -r marker proto source in_if public_port out_if landing_ip landing_port masquerade batch <<< "$row"
    verify_ufw_route_definition "$marker" "$proto" "$source" "$in_if" "$out_if" \
        "$landing_ip" "$landing_port"
}

verify_ufw_route_definition() {
    local marker=$1 proto=$2 source=$3 in_if=$4 out_if=$5 landing_ip=$6 landing_port=$7
    local expected added
    expected="ufw route allow in on ${in_if} out on ${out_if} proto ${proto} from ${source} to ${landing_ip} port ${landing_port} comment ${marker}"
    added=$(ufw show added 2>/dev/null | normalize_ufw_added_rule) || return 1
    [[ $(awk -v expected="$expected" '$0 == expected {count++} END {print count + 0}' <<< "$added") == 1 ]]
}

normalize_ufw_added_rule() {
    sed -E "s/comment ['\"]([^'\"]+)['\"]/comment \\1/g; s/[[:space:]]+/ /g; s/^ //; s/ $//"
}

verify_managed_rule_identity() {
    local marker=$1
    state_has_unique_marker "$marker" || return 1
    verify_nat_marker_effective "$marker" || return 1
    verify_ufw_marker_effective "$marker"
}

verify_ipv4_forwarding_effective() {
    [[ $(sysctl -n net.ipv4.ip_forward 2>/dev/null) == 1 ]] \
        && [[ $(persistent_ipv4_forwarding_value) == 1 ]]
}

restore_transaction_snapshot() {
    local batch_id=$1
    local snapshot="${BACKUP_DIR}/${batch_id}"
    local runtime_value
    install -m 640 "$snapshot/before.rules" "$BEFORE_RULES" || return 1
    install -m 600 "$snapshot/forwarding.tsv" "$STATE_FILE" || return 1
    install -m 600 "$snapshot/ip-forwarding.tsv" "$IP_FORWARDING_STATE" || return 1
    if [[ -f "$snapshot/state.version.absent" ]]; then
        rm -f -- "$STATE_VERSION_FILE" || return 1
    else
        install -m 600 "$snapshot/state.version" "$STATE_VERSION_FILE" || return 1
    fi
    if [[ -f "$snapshot/ufw-sysctl.conf.absent" ]]; then
        rm -f -- "$UFW_SYSCTL_FILE" || return 1
    else
        install -m 644 "$snapshot/ufw-sysctl.conf" "$UFW_SYSCTL_FILE" || return 1
    fi
    runtime_value=$(cat "$snapshot/runtime-ip-forward") || return 1
    if [[ "$runtime_value" == 0 || "$runtime_value" == 1 ]]; then
        sysctl -w "net.ipv4.ip_forward=${runtime_value}" >/dev/null || return 1
    fi
    return 0
}

verify_snapshot_restored() {
    local batch_id=$1
    local snapshot="${BACKUP_DIR}/${batch_id}"
    local runtime_value
    cmp -s "$snapshot/before.rules" "$BEFORE_RULES" || return 1
    cmp -s "$snapshot/forwarding.tsv" "$STATE_FILE" || return 1
    cmp -s "$snapshot/ip-forwarding.tsv" "$IP_FORWARDING_STATE" || return 1
    if [[ -f "$snapshot/state.version.absent" ]]; then
        [[ ! -e "$STATE_VERSION_FILE" ]]
    else
        cmp -s "$snapshot/state.version" "$STATE_VERSION_FILE" || return 1
    fi
    if [[ -f "$snapshot/ufw-sysctl.conf.absent" ]]; then
        [[ ! -e "$UFW_SYSCTL_FILE" ]] || return 1
    else
        cmp -s "$snapshot/ufw-sysctl.conf" "$UFW_SYSCTL_FILE" || return 1
    fi
    runtime_value=$(cat "$snapshot/runtime-ip-forward") || return 1
    if [[ "$runtime_value" == 0 || "$runtime_value" == 1 ]]; then
        [[ $(sysctl -n net.ipv4.ip_forward 2>/dev/null) == "$runtime_value" ]] || return 1
    fi
    verify_nat_file_effective "$snapshot/before.rules"
}

verify_nat_file_effective() {
    local expected_file=$1 chain expected live live_dump
    live_dump=$(iptables-save -t nat 2>/dev/null | normalize_iptables_rule_for_delete) || return 1
    for chain in PREROUTING POSTROUTING; do
        expected=$(normalize_iptables_rule_for_delete < "$expected_file" \
            | managed_nat_rules_for_chain "$chain" \
            | canonicalize_managed_nat_rules) || return 1
        live=$(managed_nat_rules_for_chain "$chain" <<< "$live_dump" \
            | canonicalize_managed_nat_rules) || return 1
        [[ "$expected" == "$live" ]] || return 1
    done
}

managed_nat_rules_for_chain() {
    local chain=$1
    awk -v chain="$chain" '
        $1 == "-A" && $2 == chain {
            for (i = 1; i < NF; i++) {
                if ($i == "--comment" && ($(i + 1) ~ /^lsec:[A-Za-z0-9._-]+:[A-Za-z0-9._-]+:(dnat|snat)$/ \
                    || $(i + 1) ~ /^ufw-relay:[A-Za-z0-9._-]+:(dnat|snat)$/)) {
                    print
                    break
                }
            }
        }
    '
}

managed_nat_rules_for_marker_and_chain() {
    local marker=$1 chain=$2
    validate_nat_ownership_marker "$marker" || return 1
    managed_nat_rules_for_chain "$chain" | awk \
        -v dnat="${marker}:dnat" -v snat="${marker}:snat" '
            {
                for (i = 1; i < NF; i++) {
                    if ($i == "--comment" && ($(i + 1) == dnat || $(i + 1) == snat)) {
                        print
                        break
                    }
                }
            }
        '
}

canonicalize_managed_nat_rules() {
    normalize_iptables_rule_for_delete | awk '
        function fail() {
            invalid=1
        }
        function set_value(name, value) {
            if (seen[name]++) {
                fail()
                return
            }
            field[name]=value
        }
        function host_address(value) {
            sub(/\/32$/, "", value)
            return value
        }
        {
            for (name in seen) delete seen[name]
            for (name in field) delete field[name]
            for (name in module) delete module[name]
            invalid=0
            if ($1 != "-A" || ($2 != "PREROUTING" && $2 != "POSTROUTING")) fail()
            for (i=3; i<=NF && !invalid; i++) {
                token=$i
                if (token == "-p") set_value("proto", $(++i))
                else if (token == "-s") set_value("source", $(++i))
                else if (token == "-d") set_value("destination", $(++i))
                else if (token == "-i") set_value("input", $(++i))
                else if (token == "-o") set_value("output", $(++i))
                else if (token == "--dport") set_value("dport", $(++i))
                else if (token == "--comment") set_value("comment", $(++i))
                else if (token == "-j") set_value("jump", $(++i))
                else if (token == "--to-destination") set_value("translated", $(++i))
                else if (token == "-m") {
                    value=$(++i)
                    if (value !~ /^(tcp|udp|comment)$/ || module[value]++) fail()
                } else fail()
                if (i > NF || $(i) == "") fail()
            }
            source=("source" in field) ? host_address(field["source"]) : "any"
            destination=("destination" in field) ? host_address(field["destination"]) : "-"
            input=("input" in field) ? field["input"] : "-"
            output=("output" in field) ? field["output"] : "-"
            translated=("translated" in field) ? field["translated"] : "-"
            if (field["proto"] !~ /^(tcp|udp)$/ || field["dport"] !~ /^[0-9]+$/) fail()
            if (field["comment"] !~ /^(lsec:[A-Za-z0-9._-]+:[A-Za-z0-9._-]+|ufw-relay:[A-Za-z0-9._-]+):(dnat|snat)$/) fail()
            if ($2 == "PREROUTING" && (input == "-" || output != "-" || destination != "-" \
                || field["jump"] != "DNAT" || translated == "-" || field["comment"] !~ /:dnat$/)) fail()
            if ($2 == "POSTROUTING" && (input != "-" || output == "-" || destination == "-" \
                || source != "any" || field["jump"] != "MASQUERADE" || translated != "-" \
                || field["comment"] !~ /:snat$/)) fail()
            if (invalid) exit 1
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", \
                $2, field["proto"], source, input, output, destination, field["dport"], \
                field["comment"], field["jump"], translated
        }
    '
}

validate_nat_ownership_marker() {
    local marker=$1
    [[ "$marker" =~ ^lsec:[A-Za-z0-9._-]+:[A-Za-z0-9._-]+$ \
        || "$marker" =~ ^ufw-relay:[A-Za-z0-9._-]+$ ]]
}

list_live_nat_rules_for_marker() {
    local marker=$1 live_dump chain
    validate_nat_ownership_marker "$marker" || return 1
    live_dump=$(iptables-save -t nat 2>/dev/null | normalize_iptables_rule_for_delete) || return 1
    for chain in PREROUTING POSTROUTING; do
        managed_nat_rules_for_chain "$chain" <<< "$live_dump" \
            | awk -v dnat="${marker}:dnat" -v snat="${marker}:snat" '
                {for (i = 1; i < NF; i++) if ($i == "--comment" && ($(i + 1) == dnat || $(i + 1) == snat)) {print; break}}
            '
    done
}

list_live_managed_nat_rules() {
    local live_dump
    live_dump=$(iptables-save -t nat 2>/dev/null | normalize_iptables_rule_for_delete) || return 1
    managed_nat_rules_for_chain PREROUTING <<< "$live_dump"
    managed_nat_rules_for_chain POSTROUTING <<< "$live_dump"
}

delete_live_nat_rule_line() {
    local line=$1
    local -a arguments=()
    read -r -a arguments <<< "$line"
    (( ${#arguments[@]} >= 3 )) || return 1
    [[ "${arguments[0]}" == -A ]] || return 1
    [[ "${arguments[1]}" == PREROUTING || "${arguments[1]}" == POSTROUTING ]] || return 1
    arguments[0]=-D
    iptables -t nat "${arguments[@]}"
}

clear_live_managed_nat_rules() {
    local line rules_file remaining result=0
    rules_file=$(mktemp) || return 1
    list_live_managed_nat_rules > "$rules_file" || { rm -f -- "$rules_file"; return 1; }
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        delete_live_nat_rule_line "$line" || { result=1; break; }
    done < "$rules_file"
    rm -f -- "$rules_file"
    (( result == 0 )) || return 1
    remaining=$(list_live_managed_nat_rules) || return 1
    [[ -z "$remaining" ]]
}

clear_live_nat_rules_for_marker() {
    local marker=$1 line rules_file remaining result=0
    validate_nat_ownership_marker "$marker" || return 1
    rules_file=$(mktemp) || return 1
    list_live_nat_rules_for_marker "$marker" > "$rules_file" \
        || { rm -f -- "$rules_file"; return 1; }
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        delete_live_nat_rule_line "$line" || { result=1; break; }
    done < "$rules_file"
    rm -f -- "$rules_file"
    (( result == 0 )) || return 1
    remaining=$(list_live_nat_rules_for_marker "$marker") || return 1
    [[ -z "$remaining" ]]
}

list_managed_nat_markers_in_file() {
    local file=$1 chain
    for chain in PREROUTING POSTROUTING; do
        normalize_iptables_rule < "$file" | managed_nat_rules_for_chain "$chain"
    done | awk '
        {for (i = 1; i < NF; i++) if ($i == "--comment") {
            marker=$(i + 1)
            sub(/:(dnat|snat)$/, "", marker)
            print marker
            break
        }}
    ' | sort -u
}

sync_live_nat_marker_files_to_file() {
    local target_file=$1 marker_file line marker target_markers
    shift
    target_markers=$(mktemp) || return 1
    list_managed_nat_markers_in_file "$target_file" > "$target_markers" \
        || { rm -f -- "$target_markers"; return 1; }
    while IFS= read -r marker; do
        [[ -n "$marker" ]] || continue
        clear_live_nat_rules_for_marker "$marker" \
            || { rm -f -- "$target_markers"; return 1; }
    done < "$target_markers"
    rm -f -- "$target_markers"
    for marker_file in "$@"; do
        [[ -f "$marker_file" ]] || continue
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            marker=${line%%$'\t'*}
            clear_live_nat_rules_for_marker "$marker" || return 1
        done < "$marker_file"
    done
    reload_ufw || return 1
    verify_nat_file_effective "$target_file"
}

reconcile_all_live_managed_nat_to_file() {
    local target_file=$1
    clear_live_managed_nat_rules || return 1
    reload_ufw || return 1
    verify_nat_file_effective "$target_file"
}

remove_transaction_ufw_rules() {
    local batch_id=$1 marker result=0 count
    local added_file="${BACKUP_DIR}/${batch_id}/ufw-intended.txt"
    [[ -f "$added_file" ]] || return 0
    while IFS= read -r marker; do
        [[ -n "$marker" ]] || continue
        count=$(ufw_numbered_lines_for_marker "$marker" | awk 'NF {count++} END {print count + 0}') || { result=1; continue; }
        if (( count == 1 )); then
            delete_ufw_rules_by_comment "$marker" || result=1
        elif (( count > 1 )); then
            result=1
        fi
    done < "$added_file"
    return "$result"
}

verify_transaction_ufw_rules_absent() {
    local batch_id=$1 marker
    local added_file="${BACKUP_DIR}/${batch_id}/ufw-intended.txt"
    [[ -f "$added_file" ]] || return 0
    while IFS= read -r marker; do
        [[ -n "$marker" ]] || continue
        [[ -z $(ufw_numbered_lines_for_marker "$marker") ]] || return 1
    done < "$added_file"
    return 0
}

write_protected_record() {
    local batch_id=$1 phase=$2 reason=$3
    printf 'batch_id\t%s\nphase\t%s\nreason\t%s\ncreated_at\t%s\n' \
        "$batch_id" "$phase" "$reason" "$(date -u +%FT%TZ)"
}

protect_failed_transaction() {
    local batch_id=$1 phase=$2 reason=$3
    atomic_write "$PROTECTED_LOCK" write_protected_record "$batch_id" "$phase" "$reason" || return 1
    set_transaction_phase "$batch_id" protected "$reason" || true
}

rollback_created_forwarding() {
    local batch_id=$1
    local result=0
    remove_transaction_ufw_rules "$batch_id" || result=1
    restore_transaction_snapshot "$batch_id" || result=1
    sync_live_nat_marker_files_to_file "$BEFORE_RULES" \
        "${BACKUP_DIR}/${batch_id}/ufw-intended.txt" || result=1
    verify_snapshot_restored "$batch_id" || result=1
    verify_transaction_ufw_rules_absent "$batch_id" || result=1
    if (( result == 0 )); then
        set_transaction_phase "$batch_id" rolled_back
        return 0
    fi
    protect_failed_transaction "$batch_id" rollback_failed '无法验证事务快照恢复'
    return 1
}

create_forwarding_transaction() {
    local batch_id=$1 staged=$2 source=$3 in_if=$4 public_port=$5
    local out_if=$6 landing_ip=$7 landing_port=$8 masquerade=$9
    shift 9
    local -a protocols=("$@")
    local proto marker failure_result=$RESULT_APPLY_FAILED_ROLLED_BACK

    require_current_state_schema || return $?
    is_ufw_active || return "$RESULT_PRECHECK_FAILED"
    verify_nat_file_effective "$BEFORE_RULES" || return "$RESULT_REPAIR_REQUIRED"
    validate_staged_nat "$staged" || return "$RESULT_PRECHECK_FAILED"
    begin_transaction "$batch_id" create "$(IFS=,; echo "${protocols[*]}")" || return "$RESULT_PRECHECK_FAILED"
    if ! apply_ipv4_forwarding_for_transaction "$batch_id"; then
        set_transaction_phase "$batch_id" applying_ipv4 'IPv4 转发启用失败' || true
    elif set_transaction_phase "$batch_id" applying_nat \
        && apply_staged_nat_file "$staged" \
        && set_transaction_phase "$batch_id" applying_ufw; then
        for proto in "${protocols[@]}"; do
            marker=$(managed_marker "$batch_id" "$proto")
            if ! record_intended_ufw_marker "$batch_id" "$marker" \
                || ! add_forward_ufw_route "$proto" "$source" "$in_if" "$out_if" \
                "$landing_ip" "$landing_port" "$marker" \
                || ! record_added_ufw_marker "$batch_id" "$marker"; then
                set_transaction_phase "$batch_id" applying_ufw "UFW ${proto} 路由规则添加失败" || true
                break
            fi
        done
        if (( ${#protocols[@]} == $(wc -l < "${BACKUP_DIR}/${batch_id}/ufw-added.txt" 2>/dev/null || echo 0) )) \
            && set_transaction_phase "$batch_id" committing_state \
            && commit_forward_state "$batch_id" "$source" "$in_if" "$public_port" "$out_if" \
                "$landing_ip" "$landing_port" "$masquerade" "${protocols[@]}" \
            && sync_live_nat_marker_files_to_file "$BEFORE_RULES" \
                "${BACKUP_DIR}/${batch_id}/ufw-intended.txt" \
            && set_transaction_phase "$batch_id" verifying; then
            if verify_forwarding_batch "$batch_id" "${protocols[@]}"; then
                set_transaction_phase "$batch_id" verified \
                    && finish_transaction "$batch_id" committed \
                    && return "$RESULT_OK"
            else
                failure_result=$RESULT_VERIFY_FAILED_ROLLED_BACK
                set_transaction_phase "$batch_id" verifying '应用后本机验证失败' || true
            fi
        fi
    fi

    if rollback_created_forwarding "$batch_id"; then
        return "$failure_result"
    fi
    return "$RESULT_ROLLBACK_FAILED"
}

stage_forward_nat_removal() {
    local staged=$1 marker temp
    shift
    (( $# > 0 )) || return 1
    cp -a "$BEFORE_RULES" "$staged" || return 1
    for marker in "$@"; do
        validate_managed_marker "$marker" || return 1
        temp=$(mktemp "${staged}.tmp.XXXXXX") || return 1
        if ! awk -v marker="$marker" '
            index($0, "--comment " marker ":dnat") == 0 &&
            index($0, "--comment " marker ":snat") == 0 {print}
        ' "$staged" > "$temp" || ! mv -f -- "$temp" "$staged"; then
            rm -f -- "$temp"
            return 1
        fi
    done
}

render_state_without_markers() {
    local current_state=$1
    shift
    awk -F '\t' -v OFS='\t' '
        BEGIN {
            for (arg_index = 2; arg_index < ARGC; arg_index++) {
                removed[ARGV[arg_index]] = 1
                delete ARGV[arg_index]
            }
        }
        !($1 in removed) {print}
    ' "$current_state" "$@"
}

commit_forward_state_removal() {
    atomic_write "$STATE_FILE" render_state_without_markers "$STATE_FILE" "$@" || return 1
    atomic_write "$STATE_VERSION_FILE" write_state_schema_version
}

record_delete_intent() {
    local batch_id=$1 marker row
    local target="${BACKUP_DIR}/${batch_id}/ufw-delete-intended.tsv"
    shift
    : > "$target" || return 1
    for marker in "$@"; do
        row=$(awk -F '\t' -v marker="$marker" '$1 == marker {print; exit}' "$STATE_FILE")
        [[ -n "$row" ]] || return 1
        printf '%s\n' "$row" >> "$target" || return 1
    done
    chmod 600 "$target"
}

ufw_marker_present() {
    local marker=$1
    [[ $(ufw_numbered_lines_for_marker "$marker" | awk 'NF {count++} END {print count + 0}') == 1 ]]
}

restore_deleted_ufw_rules() {
    local batch_id=$1
    local marker proto source in_if public_port out_if landing_ip landing_port masquerade original_batch
    local intended="${BACKUP_DIR}/${batch_id}/ufw-delete-intended.tsv"
    [[ -f "$intended" ]] || return 0
    while IFS=$'\t' read -r marker proto source in_if public_port out_if landing_ip landing_port masquerade original_batch; do
        [[ -n "$marker" ]] || continue
        if ! ufw_marker_present "$marker"; then
            add_forward_ufw_route "$proto" "$source" "$in_if" "$out_if" \
                "$landing_ip" "$landing_port" "$marker" || return 1
        fi
    done < "$intended"
}

verify_deleted_ufw_rules_restored() {
    local batch_id=$1 marker proto source in_if public_port out_if landing_ip landing_port masquerade original_batch
    local intended="${BACKUP_DIR}/${batch_id}/ufw-delete-intended.tsv"
    [[ -f "$intended" ]] || return 0
    while IFS=$'\t' read -r marker proto source in_if public_port out_if landing_ip landing_port masquerade original_batch; do
        [[ -n "$marker" ]] || continue
        verify_ufw_route_definition "$marker" "$proto" "$source" "$in_if" "$out_if" \
            "$landing_ip" "$landing_port" || return 1
    done < "$intended"
}

verify_forwarding_markers_absent() {
    local marker live_nat
    live_nat=$(iptables-save -t nat 2>/dev/null | normalize_iptables_rule) || return 1
    for marker in "$@"; do
        grep -Fq -- "--comment ${marker}:" "$BEFORE_RULES" && return 1
        [[ $(state_marker_count "$marker") == 0 ]] || return 1
        grep -Fq -- "--comment ${marker}:" <<< "$live_nat" && return 1
        [[ -z $(ufw_numbered_lines_for_marker "$marker") ]] || return 1
    done
    return 0
}

rollback_deleted_forwarding() {
    local batch_id=$1 result=0
    restore_transaction_snapshot "$batch_id" || result=1
    restore_deleted_ufw_rules "$batch_id" || result=1
    sync_live_nat_marker_files_to_file "$BEFORE_RULES" \
        "${BACKUP_DIR}/${batch_id}/ufw-delete-intended.tsv" || result=1
    verify_snapshot_restored "$batch_id" || result=1
    verify_deleted_ufw_rules_restored "$batch_id" || result=1
    if (( result == 0 )); then
        set_transaction_phase "$batch_id" rolled_back
        return 0
    fi
    protect_failed_transaction "$batch_id" rollback_failed '无法验证删除事务恢复'
    return 1
}

delete_forwarding_transaction() {
    local batch_id=$1 staged=$2
    shift 2
    local restore_ipv4=no
    if [[ ${1:-} == --restore-ipv4=* ]]; then
        restore_ipv4=${1#*=}
        shift
    fi
    local -a markers=("$@")
    local marker failure_result=$RESULT_APPLY_FAILED_ROLLED_BACK deleted=0

    require_current_state_schema || return $?
    is_ufw_active || return "$RESULT_PRECHECK_FAILED"
    verify_nat_file_effective "$BEFORE_RULES" || return "$RESULT_REPAIR_REQUIRED"
    (( ${#markers[@]} > 0 )) || return "$RESULT_PRECHECK_FAILED"
    validate_staged_nat "$staged" || return "$RESULT_PRECHECK_FAILED"
    for marker in "${markers[@]}"; do
        validate_managed_marker "$marker" || return "$RESULT_PRECHECK_FAILED"
        verify_managed_rule_identity "$marker" || return "$RESULT_REPAIR_REQUIRED"
    done
    begin_transaction "$batch_id" delete "$(IFS=,; echo "${markers[*]}")" || return "$RESULT_PRECHECK_FAILED"
    record_delete_intent "$batch_id" "${markers[@]}" || {
        rollback_deleted_forwarding "$batch_id" || return "$RESULT_ROLLBACK_FAILED"
        return "$RESULT_APPLY_FAILED_ROLLED_BACK"
    }
    if set_transaction_phase "$batch_id" applying_nat && apply_staged_nat_file "$staged" \
        && set_transaction_phase "$batch_id" applying_ufw; then
        for marker in "${markers[@]}"; do
            if verify_ufw_marker_effective "$marker" \
                && delete_ufw_rules_by_comment "$marker" && ! ufw_marker_present "$marker"; then
                ((deleted += 1))
            else
                set_transaction_phase "$batch_id" applying_ufw "UFW 规则删除失败：${marker}" || true
                break
            fi
        done
        if (( deleted == ${#markers[@]} )) \
            && set_transaction_phase "$batch_id" committing_state \
            && commit_forward_state_removal "${markers[@]}" \
            && { [[ "$restore_ipv4" == no ]] || restore_owned_ipv4_forwarding; } \
            && sync_live_nat_marker_files_to_file "$BEFORE_RULES" \
                "${BACKUP_DIR}/${batch_id}/ufw-delete-intended.tsv" \
            && set_transaction_phase "$batch_id" verifying; then
            if verify_forwarding_markers_absent "${markers[@]}"; then
                set_transaction_phase "$batch_id" verified \
                    && finish_transaction "$batch_id" committed \
                    && return "$RESULT_OK"
            else
                failure_result=$RESULT_VERIFY_FAILED_ROLLED_BACK
                set_transaction_phase "$batch_id" verifying '删除后本机验证失败' || true
            fi
        fi
    fi
    if rollback_deleted_forwarding "$batch_id"; then
        return "$failure_result"
    fi
    return "$RESULT_ROLLBACK_FAILED"
}

find_parameter_collisions() {
    local proto=$1 source=$2 in_if=$3 public_port=$4 out_if=$5
    local landing_ip=$6 landing_port=$7 masquerade=$8
    [[ -f "$STATE_FILE" ]] || return 0
    awk -F '\t' -v proto="$proto" -v source="$source" -v in_if="$in_if" \
        -v public_port="$public_port" -v out_if="$out_if" -v landing_ip="$landing_ip" \
        -v landing_port="$landing_port" -v masquerade="$masquerade" '
        $2 == proto && $3 == source && $4 == in_if && $5 == public_port &&
        $6 == out_if && $7 == landing_ip && $8 == landing_port && $9 == masquerade {print $1}
    ' "$STATE_FILE"
}

select_collision_rules() {
    local choice selection selected_marker
    local -a candidates=("$@") indexes=() selected=()
    (( ${#candidates[@]} > 0 )) || return "$RESULT_PRECHECK_FAILED"
    echo "1) 取消（默认）" >&2
    echo "2) 明确选择旧规则并覆盖" >&2
    read -r -p "请选择: " choice
    [[ "${choice:-1}" == 2 ]] || return "$RESULT_CANCELLED"
    read -r -p "请输入要覆盖的旧规则序号，多个用逗号分隔: " selection
    [[ -n "$selection" ]] || return "$RESULT_CANCELLED"
    selection=${selection// /}
    IFS=',' read -r -a indexes <<< "$selection"
    for selection in "${indexes[@]}"; do
        [[ "$selection" =~ ^[0-9]+$ ]] \
            && (( 10#$selection >= 1 && 10#$selection <= ${#candidates[@]} )) \
            || return "$RESULT_PRECHECK_FAILED"
        selected_marker=${candidates[$((10#$selection - 1))]}
        if (( ${#selected[@]} == 0 )) || [[ " ${selected[*]} " != *" ${selected_marker} "* ]]; then
            selected+=("$selected_marker")
        fi
    done
    (( ${#selected[@]} == ${#candidates[@]} )) || return "$RESULT_PRECHECK_FAILED"
    (IFS=,; printf '%s\n' "${selected[*]}")
}

stage_forward_nat_replacement() {
    local staged=$1 batch_id=$2 source=$3 in_if=$4 public_port=$5
    local out_if=$6 landing_ip=$7 landing_port=$8 masquerade=$9 old_csv=${10}
    shift 10
    local original_before_rules=$BEFORE_RULES removal_stage="${staged}.removal"
    local -a old_markers=()
    IFS=',' read -r -a old_markers <<< "$old_csv"
    (( ${#old_markers[@]} > 0 && $# > 0 )) || return 1
    stage_forward_nat_removal "$removal_stage" "${old_markers[@]}" || return 1
    BEFORE_RULES=$removal_stage
    if stage_forward_nat "$staged" "$batch_id" "$source" "$in_if" "$public_port" \
        "$out_if" "$landing_ip" "$landing_port" "$masquerade" "$@"; then
        BEFORE_RULES=$original_before_rules
        rm -f -- "$removal_stage"
        return 0
    fi
    BEFORE_RULES=$original_before_rules
    rm -f -- "$removal_stage"
    return 1
}

render_state_replacement() {
    local current_state=$1 batch_id=$2 old_csv=$3 source=$4 in_if=$5 public_port=$6
    local out_if=$7 landing_ip=$8 landing_port=$9 masquerade=${10}
    shift 10
    local proto marker
    local -a old_markers=()
    IFS=',' read -r -a old_markers <<< "$old_csv"
    render_state_without_markers "$current_state" "${old_markers[@]}" || return 1
    for proto in "$@"; do
        marker=$(managed_marker "$batch_id" "$proto")
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$marker" "$proto" "$source" "$in_if" "$public_port" "$out_if" \
            "$landing_ip" "$landing_port" "$masquerade" "$batch_id" || return 1
    done
}

commit_forward_state_replacement() {
    local batch_id=$1 old_csv=$2 source=$3 in_if=$4 public_port=$5 out_if=$6
    local landing_ip=$7 landing_port=$8 masquerade=$9
    shift 9
    atomic_write "$STATE_FILE" render_state_replacement "$STATE_FILE" "$batch_id" "$old_csv" \
        "$source" "$in_if" "$public_port" "$out_if" "$landing_ip" "$landing_port" \
        "$masquerade" "$@" || return 1
    atomic_write "$STATE_VERSION_FILE" write_state_schema_version
}

rollback_replaced_forwarding() {
    local batch_id=$1 result=0 operation
    remove_transaction_ufw_rules "$batch_id" || result=1
    restore_transaction_snapshot "$batch_id" || result=1
    restore_deleted_ufw_rules "$batch_id" || result=1
    operation=$(transaction_value "${TRANSACTION_DIR}/${batch_id}.txn" operation 2>/dev/null || true)
    if [[ "$operation" == restore ]]; then
        reconcile_all_live_managed_nat_to_file "$BEFORE_RULES" || result=1
    else
        sync_live_nat_marker_files_to_file "$BEFORE_RULES" \
            "${BACKUP_DIR}/${batch_id}/ufw-intended.txt" \
            "${BACKUP_DIR}/${batch_id}/ufw-delete-intended.tsv" || result=1
    fi
    verify_snapshot_restored "$batch_id" || result=1
    verify_transaction_ufw_rules_absent "$batch_id" || result=1
    verify_deleted_ufw_rules_restored "$batch_id" || result=1
    if (( result == 0 )); then
        set_transaction_phase "$batch_id" rolled_back
        return 0
    fi
    protect_failed_transaction "$batch_id" rollback_failed '无法验证覆盖事务恢复'
    return 1
}

replace_forwarding_transaction() {
    local batch_id=$1 staged=$2 old_csv=$3 source=$4 in_if=$5 public_port=$6
    local out_if=$7 landing_ip=$8 landing_port=$9 masquerade=${10}
    shift 10
    local -a protocols=("$@") old_markers=()
    local marker proto deleted=0 added=0 failure_result=$RESULT_APPLY_FAILED_ROLLED_BACK

    require_current_state_schema || return $?
    is_ufw_active || return "$RESULT_PRECHECK_FAILED"
    verify_nat_file_effective "$BEFORE_RULES" || return "$RESULT_REPAIR_REQUIRED"
    IFS=',' read -r -a old_markers <<< "$old_csv"
    (( ${#old_markers[@]} > 0 && ${#protocols[@]} > 0 )) || return "$RESULT_PRECHECK_FAILED"
    validate_staged_nat "$staged" || return "$RESULT_PRECHECK_FAILED"
    for marker in "${old_markers[@]}"; do
        validate_managed_marker "$marker" && verify_managed_rule_identity "$marker" \
            || return "$RESULT_REPAIR_REQUIRED"
    done
    begin_transaction "$batch_id" overwrite "$old_csv" || return "$RESULT_PRECHECK_FAILED"
    record_delete_intent "$batch_id" "${old_markers[@]}" || {
        rollback_replaced_forwarding "$batch_id" || return "$RESULT_ROLLBACK_FAILED"
        return "$RESULT_APPLY_FAILED_ROLLED_BACK"
    }
    if set_transaction_phase "$batch_id" applying_nat && apply_staged_nat_file "$staged" \
        && set_transaction_phase "$batch_id" applying_ufw; then
        for marker in "${old_markers[@]}"; do
            if verify_ufw_marker_effective "$marker" \
                && delete_ufw_rules_by_comment "$marker" && ! ufw_marker_present "$marker"; then
                ((deleted += 1))
            else
                break
            fi
        done
        if (( deleted == ${#old_markers[@]} )); then
            for proto in "${protocols[@]}"; do
                marker=$(managed_marker "$batch_id" "$proto")
                if record_intended_ufw_marker "$batch_id" "$marker" \
                    && add_forward_ufw_route "$proto" "$source" "$in_if" "$out_if" \
                        "$landing_ip" "$landing_port" "$marker" \
                    && record_added_ufw_marker "$batch_id" "$marker"; then
                    ((added += 1))
                else
                    break
                fi
            done
        fi
        if (( added == ${#protocols[@]} )) \
            && set_transaction_phase "$batch_id" committing_state \
            && commit_forward_state_replacement "$batch_id" "$old_csv" "$source" "$in_if" \
                "$public_port" "$out_if" "$landing_ip" "$landing_port" "$masquerade" "${protocols[@]}" \
            && sync_live_nat_marker_files_to_file "$BEFORE_RULES" \
                "${BACKUP_DIR}/${batch_id}/ufw-intended.txt" \
                "${BACKUP_DIR}/${batch_id}/ufw-delete-intended.tsv" \
            && set_transaction_phase "$batch_id" verifying; then
            if verify_forwarding_markers_absent "${old_markers[@]}" \
                && verify_forwarding_batch "$batch_id" "${protocols[@]}"; then
                set_transaction_phase "$batch_id" verified \
                    && finish_transaction "$batch_id" committed \
                    && return "$RESULT_OK"
            else
                failure_result=$RESULT_VERIFY_FAILED_ROLLED_BACK
                set_transaction_phase "$batch_id" verifying '覆盖后本机验证失败' || true
            fi
        fi
    fi
    if rollback_replaced_forwarding "$batch_id"; then
        return "$failure_result"
    fi
    return "$RESULT_ROLLBACK_FAILED"
}

insert_nat_rule_line() {
    local line=$1
    local tmp
    tmp=$(mktemp)

    awk -v marker="$NAT_END" -v newline="$line" '
        $0 == marker {print newline}
        {print}
    ' "$BEFORE_RULES" > "$tmp"

    install -m 640 "$tmp" "$BEFORE_RULES"
    rm -f "$tmp"
}

remove_nat_rules_by_id() {
    local id=$1
    local tmp
    tmp=$(mktemp)

    awk -v tag="ufw-relay:${id}:" 'index($0, tag) == 0 {print}' "$BEFORE_RULES" > "$tmp"
    install -m 640 "$tmp" "$BEFORE_RULES"
    rm -f "$tmp"
}

reload_ufw() {
    if is_ufw_active; then
        ufw reload
    else
        warn "UFW 当前未启用，规则已保存但尚未加载"
    fi
}

find_forward_duplicate() {
    local proto=$1 source=$2 in_if=$3 public_port=$4 out_if=$5 landing_ip=$6 landing_port=$7 masquerade=$8
    awk -F '\t' \
        -v proto="$proto" -v source="$source" -v in_if="$in_if" \
        -v public_port="$public_port" -v out_if="$out_if" \
        -v landing_ip="$landing_ip" -v landing_port="$landing_port" \
        -v masquerade="$masquerade" '
        $2==proto && $3==source && $4==in_if && $5==public_port &&
        $6==out_if && $7==landing_ip && $8==landing_port && $9==masquerade {found=1}
        END {exit found ? 0 : 1}
    ' "$STATE_FILE"
}

add_forward_protocol() {
    local proto=$1 source=$2 in_if=$3 public_port=$4 out_if=$5 landing_ip=$6 landing_port=$7 masquerade=$8
    local id source_match dnat_line snat_line backup route_added=0

    if find_forward_duplicate "$proto" "$source" "$in_if" "$public_port" "$out_if" "$landing_ip" "$landing_port" "$masquerade"; then
        warn "已存在相同的 ${proto^^} 转发规则，已跳过"
        return 0
    fi

    id="$(date +%Y%m%d%H%M%S)-${RANDOM}${RANDOM}"
    backup=$(backup_before_rules)
    ensure_nat_managed_section

    source_match=""
    [[ "$source" != "any" ]] && source_match="-s ${source}"

    dnat_line="-A PREROUTING -i ${in_if} -p ${proto} ${source_match} --dport ${public_port} -m comment --comment ufw-relay:${id}:dnat -j DNAT --to-destination ${landing_ip}:${landing_port}"
    insert_nat_rule_line "$dnat_line"

    if [[ "$masquerade" == "yes" ]]; then
        snat_line="-A POSTROUTING -o ${out_if} -p ${proto} -d ${landing_ip} --dport ${landing_port} -m comment --comment ufw-relay:${id}:snat -j MASQUERADE"
        insert_nat_rule_line "$snat_line"
    fi

    if ufw route allow in on "$in_if" out on "$out_if" proto "$proto" from "$source" to "$landing_ip" port "$landing_port" comment "ufw-relay:${id}"; then
        route_added=1
    else
        cp -a "$backup" "$BEFORE_RULES"
        error "UFW 路由放行规则添加失败，已回滚 NAT 配置"
        return 1
    fi

    if ! reload_ufw; then
        cp -a "$backup" "$BEFORE_RULES"
        if (( route_added == 1 )); then
            delete_forward_ufw_route "$proto" "$source" "$in_if" "$out_if" "$landing_ip" "$landing_port" "ufw-relay:${id}" || true
        fi
        ufw reload || true
        error "UFW 重新加载失败，已尝试回滚"
        return 1
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$id" "$proto" "$source" "$in_if" "$public_port" "$out_if" "$landing_ip" "$landing_port" "$masquerade" \
        >> "$STATE_FILE"

    ok "已添加 ${proto^^}：${in_if}:${public_port} → ${landing_ip}:${landing_port}"
}

list_forward_rules() {
    if [[ ! -s "$STATE_FILE" ]]; then
        info "当前没有由本脚本管理的转发规则"
        return 0
    fi

    printf '\n%-4s %-24s %-5s %-18s %-10s %-18s %-10s %-6s\n' \
        "序号" "ID" "协议" "来源" "入口" "目标" "出口" "SNAT"
    printf '%s\n' "---------------------------------------------------------------------------------------------------------------"

    awk -F '\t' '
        {
            printf "%-4d %-24s %-5s %-18s %-10s %-18s %-10s %-6s\n",
                NR, $1, toupper($2), $3, $4 ":" $5, $7 ":" $8, $6, $9
        }
    ' "$STATE_FILE"
    echo
}

delete_ufw_rules_by_comment() {
    local comment=$1
    local -a numbers=()
    local number

    while IFS= read -r number; do
        [[ -n "$number" ]] && numbers+=("$number")
    done < <(
        ufw_numbered_lines_for_marker "$comment" \
            | sed -n 's/^\[[[:space:]]*\([0-9][0-9]*\)\].*/\1/p' \
            | sort -rn
    )

    (( ${#numbers[@]} == 1 )) || return 1
    ufw --force delete "${numbers[0]}"
}


delete_forward_ufw_route() {
    local proto=$1 source=$2 in_if=$3 out_if=$4 landing_ip=$5 landing_port=$6 comment=${7:-}

    if ufw --force route delete allow \
        in on "$in_if" out on "$out_if" \
        proto "$proto" from "$source" to "$landing_ip" port "$landing_port"; then
        return 0
    fi

    # 某些旧版 UFW 对按完整规则删除的行为不一致，使用备注编号作为后备方案。
    if [[ -n "$comment" ]]; then
        delete_ufw_rules_by_comment "$comment"
        return 0
    fi

    return 1
}

delete_forward_by_id() {
    local id=$1
    local backup state_backup
    local row_id proto source in_if public_port out_if landing_ip landing_port masquerade

    grep -q "^${id}"$'\t' "$STATE_FILE" || {
        warn "未找到转发规则 ID：$id"
        return 0
    }

    IFS=$'\t' read -r row_id proto source in_if public_port out_if landing_ip landing_port masquerade \
        < <(awk -F '\t' -v id="$id" '$1 == id {print; exit}' "$STATE_FILE")

    backup=$(backup_before_rules)
    state_backup=$(mktemp)
    cp -a "$STATE_FILE" "$state_backup"

    remove_nat_rules_by_id "$id"
    delete_forward_ufw_route "$proto" "$source" "$in_if" "$out_if" "$landing_ip" "$landing_port" "ufw-relay:${id}" || true

    awk -F '\t' -v id="$id" '$1 != id {print}' OFS='\t' "$STATE_FILE" > "${STATE_FILE}.tmp"
    install -m 600 "${STATE_FILE}.tmp" "$STATE_FILE"
    rm -f "${STATE_FILE}.tmp"

    if ! reload_ufw; then
        cp -a "$backup" "$BEFORE_RULES"
        cp -a "$state_backup" "$STATE_FILE"
        ufw reload || true
        rm -f "$state_backup"
        error "删除后 UFW 加载失败，NAT 和登记文件已回滚；UFW 路由规则可能需要手工检查"
        return 1
    fi

    rm -f "$state_backup"
    ok "已删除转发规则：$id"
}

add_forward_rule_interactive_locked() {
    local default_in in_if public_port landing_ip landing_port default_out out_if source proto_choice masquerade
    local batch_id staged mode description result proto collision old_csv=
    local transaction_kind=create
    local -a protocols=() collision_markers=()

    default_in=$(default_interface)
    read -r -p "请输入中转机入站网卡 [默认 ${default_in:-无}]: " in_if
    in_if=${in_if:-$default_in}
    validate_interface "$in_if" || { error "网卡不存在：$in_if"; return 1; }

    read -r -p "请输入中转机对外端口（1-65535）: " public_port
    validate_port "$public_port" || { error "中转端口无效"; return 1; }

    read -r -p "请输入落地机 IPv4 地址: " landing_ip
    validate_ipv4 "$landing_ip" || { error "落地机 IPv4 地址无效"; return 1; }

    read -r -p "请输入落地机监听端口（1-65535）: " landing_port
    validate_port "$landing_port" || { error "落地端口无效"; return 1; }

    default_out=$(route_interface_to "$landing_ip")
    read -r -p "请输入访问落地机的出站网卡 [默认 ${default_out:-$default_in}]: " out_if
    out_if=${out_if:-${default_out:-$default_in}}
    validate_interface "$out_if" || { error "网卡不存在：$out_if"; return 1; }

    read -r -p "允许的客户端来源 IPv4/CIDR [默认 any]: " source
    source=${source:-any}
    validate_ipv4_cidr_or_any "$source" || { error "来源地址无效，仅支持 IPv4、IPv4/CIDR 或 any"; return 1; }

    echo "协议：1) TCP  2) UDP  3) TCP+UDP"
    read -r -p "请选择 [默认 2]: " proto_choice
    proto_choice=${proto_choice:-2}
    case "$proto_choice" in
        1) protocols=(tcp) ;;
        2) protocols=(udp) ;;
        3) protocols=(tcp udp) ;;
        *) error "协议选择无效"; return 1 ;;
    esac

    if confirm "是否启用 MASQUERADE，确保落地机响应经中转机返回？" Y; then
        masquerade=yes
    else
        masquerade=no
        warn "未启用 MASQUERADE 时，必须保证落地机的回程路由经过中转机"
    fi

    for proto in "${protocols[@]}"; do
        while IFS= read -r collision; do
            [[ -n "$collision" ]] || continue
            validate_managed_marker "$collision" || {
                error "检测到同参数旧格式规则，必须先审计/迁移：${collision}"
                return "$RESULT_REPAIR_REQUIRED"
            }
            if [[ " ${collision_markers[*]} " != *" ${collision} "* ]]; then
                collision_markers+=("$collision")
            fi
        done < <(find_parameter_collisions "$proto" "$source" "$in_if" "$public_port" \
            "$out_if" "$landing_ip" "$landing_port" "$masquerade")
    done

    if (( ${#collision_markers[@]} > 0 )); then
        warn "检测到同参数受管规则："
        for (( result=0; result<${#collision_markers[@]}; result++ )); do
            printf '  %d) %s\n' "$((result + 1))" "${collision_markers[$result]}"
        done
        if old_csv=$(select_collision_rules "${collision_markers[@]}"); then
            transaction_kind=overwrite
        else
            result=$?
            (( result == RESULT_PRECHECK_FAILED )) && error "必须明确选中全部同参数旧规则，否则会产生重复行为"
            return "$result"
        fi
    fi

    batch_id=$(new_batch_id)
    staged=$(mktemp) || return "$RESULT_PRECHECK_FAILED"
    result=0
    if [[ "$transaction_kind" == overwrite ]]; then
        stage_forward_nat_replacement "$staged" "$batch_id" "$source" "$in_if" "$public_port" \
            "$out_if" "$landing_ip" "$landing_port" "$masquerade" "$old_csv" "${protocols[@]}" || result=1
    else
        stage_forward_nat "$staged" "$batch_id" "$source" "$in_if" "$public_port" \
            "$out_if" "$landing_ip" "$landing_port" "$masquerade" "${protocols[@]}" || result=1
    fi
    if (( ${result:-0} != 0 )) || ! validate_staged_nat "$staged"; then
        rm -f -- "$staged"
        error "NAT 暂存配置校验失败，未执行任何变更"
        return "$RESULT_PRECHECK_FAILED"
    fi

    description="${protocols[*]} ${in_if}:${public_port} -> ${landing_ip}:${landing_port} via ${out_if}, source=${source}, masquerade=${masquerade}"
    [[ "$transaction_kind" == overwrite ]] && description+="; 删除并重建=${old_csv}"
    render_execution_preview "$transaction_kind" "lsec:${batch_id}:{${protocols[*]}}" "$description" \
        "$BEFORE_RULES" "$STATE_FILE" '仅在确认执行后按需启用'
    mode=$(select_execution_mode)
    case "$mode" in
        preflight)
            rm -f -- "$staged"
            info "前置检查与 NAT 语法校验通过，未执行任何变更"
            return "$RESULT_OK"
            ;;
        cancel)
            rm -f -- "$staged"
            return "$RESULT_CANCELLED"
            ;;
    esac

    if ! init_state; then
        rm -f -- "$staged"
        return "$RESULT_PRECHECK_FAILED"
    fi
    if [[ "$transaction_kind" == overwrite ]]; then
        if replace_forwarding_transaction "$batch_id" "$staged" "$old_csv" "$source" "$in_if" "$public_port" \
            "$out_if" "$landing_ip" "$landing_port" "$masquerade" "${protocols[@]}"; then
            result=$RESULT_OK
        else
            result=$?
        fi
    else
        if create_forwarding_transaction "$batch_id" "$staged" "$source" "$in_if" "$public_port" \
            "$out_if" "$landing_ip" "$landing_port" "$masquerade" "${protocols[@]}"; then
            result=$RESULT_OK
        else
            result=$?
        fi
    fi
    rm -f -- "$staged"
    return "$result"
}

add_forward_rule_interactive() {
    local result

    if begin_mutation "创建完整端口转发"; then
        :
    else
        result=$?
        error "$(result_message "$result")"
        return "$result"
    fi
    if require_mutation_allowed; then
        :
    else
        result=$?
        end_mutation
        error "$(result_message "$result")"
        return "$result"
    fi
    if run_dependency_preflight; then
        :
    else
        result=$?
        end_mutation
        warn "$(result_message "$result")"
        return "$result"
    fi
    if add_forward_rule_interactive_locked; then
        result=$RESULT_OK
    else
        result=$?
    fi
    end_mutation
    case "$result" in
        0) ok "$(result_message "$result")" ;;
        10) warn "$(result_message "$result")" ;;
        *) error "$(result_message "$result")" ;;
    esac
    return "$result"
}

delete_forward_rule_interactive_locked() {
    local selection marker staged batch_id mode result restore_ipv4=no total_rules
    local -a indexes=()
    local -a markers=()

    list_forward_rules
    [[ -s "$STATE_FILE" ]] || return 0
    if [[ ! -f "$STATE_VERSION_FILE" || $(cat "$STATE_VERSION_FILE") != "$STATE_SCHEMA_VERSION" ]]; then
        error "转发状态尚未迁移，必须先运行审计/迁移"
        return "$RESULT_REPAIR_REQUIRED"
    fi

    read -r -p "请输入要删除的序号，多个用逗号分隔 [直接回车取消]: " selection
    [[ -n "$selection" ]] || return "$RESULT_CANCELLED"
    selection=${selection// /}
    IFS=',' read -r -a indexes <<< "$selection"

    for selection in "${indexes[@]}"; do
        [[ "$selection" =~ ^[0-9]+$ ]] || { error "无效序号：$selection"; return "$RESULT_PRECHECK_FAILED"; }
        marker=$(awk -F '\t' -v n="$selection" 'NR==n {print $1}' "$STATE_FILE")
        [[ -n "$marker" ]] || { error "序号不存在：$selection"; return "$RESULT_PRECHECK_FAILED"; }
        validate_managed_marker "$marker" || { error "规则不是当前版本受管格式：$marker"; return "$RESULT_REPAIR_REQUIRED"; }
        state_has_unique_marker "$marker" || { error "规则标记不唯一：$marker"; return "$RESULT_REPAIR_REQUIRED"; }
        markers+=("$marker")
    done

    (( ${#markers[@]} > 0 )) || return "$RESULT_CANCELLED"
    total_rules=$(awk 'NF {count++} END {print count + 0}' "$STATE_FILE")
    if (( ${#markers[@]} == total_rules )) && grep -Eq '^owned_(runtime|persistent)[[:space:]]+yes$' "$IP_FORWARDING_STATE" 2>/dev/null; then
        if detect_other_forwarding_use "${markers[@]}"; then
            warn "检测到其他转发用途，不允许自动恢复 IPv4 forwarding"
        elif confirm "这是最后一批受管转发，是否恢复本脚本启用前的 IPv4 forwarding？" N; then
            restore_ipv4=yes
        else
            info "将保留当前 IPv4 forwarding 设置"
        fi
    fi
    batch_id=$(new_batch_id)
    staged=$(mktemp) || return "$RESULT_PRECHECK_FAILED"
    if ! stage_forward_nat_removal "$staged" "${markers[@]}" || ! validate_staged_nat "$staged"; then
        rm -f -- "$staged"
        error "删除后的 NAT 暂存配置校验失败"
        return "$RESULT_PRECHECK_FAILED"
    fi
    render_execution_preview delete "$(IFS=,; echo "${markers[*]}")" \
        "删除 ${#markers[@]} 条精确受管规则" "$BEFORE_RULES" "$STATE_FILE" "restore=${restore_ipv4}"
    mode=$(select_execution_mode)
    case "$mode" in
        preflight)
            rm -f -- "$staged"
            info "删除前置检查与 NAT 语法校验通过，未执行任何变更"
            return "$RESULT_OK"
            ;;
        cancel)
            rm -f -- "$staged"
            return "$RESULT_CANCELLED"
            ;;
    esac

    if delete_forwarding_transaction "$batch_id" "$staged" "--restore-ipv4=${restore_ipv4}" "${markers[@]}"; then
        result=$RESULT_OK
    else
        result=$?
    fi
    rm -f -- "$staged"
    return "$result"
}

delete_forward_rule_interactive() {
    local result

    if begin_mutation "删除完整端口转发"; then :; else
        result=$?
        error "$(result_message "$result")"
        return "$result"
    fi
    if require_mutation_allowed; then :; else
        result=$?
        end_mutation
        error "$(result_message "$result")"
        return "$result"
    fi
    if run_dependency_preflight; then :; else
        result=$?
        end_mutation
        warn "$(result_message "$result")"
        return "$result"
    fi
    if delete_forward_rule_interactive_locked; then result=$RESULT_OK; else result=$?; fi
    end_mutation
    case "$result" in
        0) ok "$(result_message "$result")" ;;
        10) warn "$(result_message "$result")" ;;
        *) error "$(result_message "$result")" ;;
    esac
    return "$result"
}

legacy_state_management_interactive() {
    local audit choice batch_id result
    audit=$(audit_legacy_forwarding_state)
    if [[ -z "$audit" ]]; then
        info "没有需要迁移的旧转发状态"
        return "$RESULT_OK"
    fi
    echo "旧状态审计结果："
    printf '%s\n' "$audit"
    echo "1) 迁移全部 legacy-exact 规则"
    echo "2) 显示人工处理说明"
    echo "0) 取消"
    read -r -p "请选择 [默认 0]: " choice
    case ${choice:-0} in
        1)
            if grep -qv $'\tlegacy-exact$' <<< "$audit"; then
                error "包含 malformed 或 legacy-drift 项，不能自动迁移；请先人工核对 NAT、UFW 与登记文件"
                return "$RESULT_REPAIR_REQUIRED"
            fi
            ;;
        2)
            info "请比对 ${STATE_FILE}、${BEFORE_RULES} 和 ufw status numbered"
            info "只有三层唯一对应的规则可自动迁移；不确定时保留原规则并导出诊断"
            return "$RESULT_OK"
            ;;
        *) return "$RESULT_CANCELLED" ;;
    esac
    if begin_mutation "迁移旧转发状态"; then :; else return $?; fi
    if require_mutation_allowed; then :; else
        result=$?
        end_mutation
        return "$result"
    fi
    batch_id=$(new_batch_id)
    if migrate_legacy_forwarding_state "$batch_id"; then result=$RESULT_OK; else result=$?; fi
    end_mutation
    case "$result" in
        0) ok "旧转发状态已迁移并完成本机验证" ;;
        *) error "$(result_message "$result")" ;;
    esac
    return "$result"
}

verify_consistent_state() {
    local audit marker rest
    require_current_state_schema || return 1
    audit=$(audit_legacy_forwarding_state)
    [[ -z "$audit" ]] && return 0
    grep -qv $'\tcurrent$' <<< "$audit" && return 1
    is_ufw_active || return 1
    [[ ! -s "$STATE_FILE" ]] || verify_ipv4_forwarding_effective || return 1
    while IFS=$'\t' read -r marker rest; do
        [[ -n "$marker" ]] || continue
        verify_managed_rule_identity "$marker" || return 1
    done < "$STATE_FILE"
}

attempt_protected_repair() {
    local batch_id phase
    [[ -s "$PROTECTED_LOCK" ]] || return "$RESULT_OK"
    batch_id=$(transaction_value "$PROTECTED_LOCK" batch_id)
    phase=$(transaction_value "$PROTECTED_LOCK" phase)
    if [[ "$phase" == repair_required ]]; then
        validate_reconciled_nat_structure || return "$RESULT_PROTECTED_LOCKOUT"
    else
        recover_transaction "$batch_id" || return "$RESULT_ROLLBACK_FAILED"
    fi
    verify_consistent_state || return "$RESULT_PROTECTED_LOCKOUT"
    rm -f -- "$PROTECTED_LOCK" || return "$RESULT_PROTECTED_LOCKOUT"
}

validate_reconciled_nat_structure() {
    if nat_managed_markers_present "$BEFORE_RULES"; then
        validate_nat_managed_section "$BEFORE_RULES"
    else
        ! grep -Eq -- '--comment (lsec:|ufw-relay:)' "$BEFORE_RULES"
    fi
}

transaction_maintenance_menu() {
    local choice batch_id selection export_path result
    local -a selected=()
    while true; do
        echo "1) 列出备份"
        echo "2) 恢复选定备份（作为新事务）"
        echo "3) 清理选定的合规成功备份"
        echo "4) 导出诊断"
        echo "5) 尝试修复保护锁"
        echo "0) 返回"
        read -r -p "请选择: " choice
        case "$choice" in
            1) list_snapshots ;;
            2)
                list_snapshots
                read -r -p "请输入要恢复的备份 ID [回车取消]: " batch_id
                [[ -n "$batch_id" ]] || continue
                confirm "确认以新事务恢复 ${batch_id}？" N || continue
                if begin_mutation "恢复备份 ${batch_id}"; then :; else continue; fi
                if require_recovery_allowed restore && restore_snapshot_transaction "$batch_id"; then
                    ok "备份已恢复并验证"
                else
                    result=$?
                    error "$(result_message "$result")"
                fi
                end_mutation
                ;;
            3)
                eligible_success_snapshots_for_cleanup
                read -r -p "请输入要清理的备份 ID，多个用逗号分隔 [回车取消]: " selection
                [[ -n "$selection" ]] || continue
                selection=${selection// /}
                IFS=',' read -r -a selected <<< "$selection"
                confirm "确认永久清理明确选中的 ${#selected[@]} 个备份？" N || continue
                if begin_mutation "清理事务备份"; then :; else continue; fi
                if cleanup_selected_snapshots "$(date +%s)" "${selected[@]}"; then
                    ok "选定备份已清理"
                else
                    error "备份不符合清理策略，未执行清理"
                fi
                end_mutation
                ;;
            4)
                export_path="/root/lsec-diagnostics-$(date +%Y%m%d%H%M%S).txt"
                export_transaction_diagnostics "$export_path" && ok "诊断已导出：${export_path}"
                ;;
            5)
                if begin_mutation "修复保护锁"; then :; else continue; fi
                if attempt_protected_repair; then ok "一致性已验证，保护锁已清除"; else error "修复未通过，保护锁保持"; fi
                end_mutation
                ;;
            0) return 0 ;;
            *) warn "无效选项" ;;
        esac
    done
}

select_action() {
    local direction=$1
    local choice
    echo "动作：1) allow  2) deny  3) reject  4) limit（仅 TCP）" >&2
    read -r -p "请选择 [默认 1]: " choice
    choice=${choice:-1}
    case "$choice" in
        1) echo allow ;;
        2) echo deny ;;
        3) echo reject ;;
        4)
            if [[ "$direction" == "out" ]]; then
                warn "出站规则不建议使用 limit，将改为 deny/allow/reject 之一"
                return 1
            fi
            echo limit
            ;;
        *) return 1 ;;
    esac
}

select_protocols() {
    local choice
    echo "协议：1) TCP  2) UDP  3) TCP+UDP" >&2
    read -r -p "请选择 [默认 1]: " choice
    choice=${choice:-1}
    case "$choice" in
        1) echo tcp ;;
        2) echo udp ;;
        3) printf 'tcp\nudp\n' ;;
        *) return 1 ;;
    esac
}

add_inbound_rule_interactive() {
    local action port_spec source iface comment proto
    local -a protocols=()
    local -a cmd=()

    action=$(select_action in) || { error "动作选择无效"; return 1; }
    mapfile -t protocols < <(select_protocols)
    (( ${#protocols[@]} > 0 )) || { error "协议选择无效"; return 1; }

    if [[ "$action" == "limit" && " ${protocols[*]} " != " tcp " ]]; then
        error "limit 仅支持 TCP，请重新添加"
        return 1
    fi

    read -r -p "请输入本机端口，可用逗号或冒号范围，例如 80,443,8000:8010: " port_spec
    validate_port_spec "$port_spec" || { error "端口格式无效，或端口元素超过 15 个"; return 1; }

    read -r -p "允许/限制的来源地址 [默认 any]: " source
    source=${source:-any}
    validate_address_token_or_any "$source" || { error "来源地址格式无效"; return 1; }

    read -r -p "限定入站网卡 [默认所有网卡]: " iface
    if [[ -n "$iface" ]] && ! validate_interface "$iface"; then
        error "网卡不存在：$iface"
        return 1
    fi

    read -r -p "规则备注 [默认 managed-inbound]: " comment
    comment=${comment:-managed-inbound}

    echo
    echo "将添加入站规则：${action} ${protocols[*]} from ${source} to port ${port_spec}${iface:+ on $iface}"
    confirm "确认添加？" Y || return 0

    for proto in "${protocols[@]}"; do
        cmd=(ufw "$action" in)
        [[ -n "$iface" ]] && cmd+=(on "$iface")
        cmd+=(proto "$proto" from "$source" to any port "$port_spec" comment "$comment")
        "${cmd[@]}"
    done
    ok "入站规则添加完成"
}

add_outbound_rule_interactive() {
    local action port_spec destination iface comment proto action_choice
    local -a protocols=()
    local -a cmd=()

    echo "动作：1) allow  2) deny  3) reject"
    read -r -p "请选择 [默认 1]: " action_choice
    action_choice=${action_choice:-1}
    case "$action_choice" in
        1) action=allow ;;
        2) action=deny ;;
        3) action=reject ;;
        *) error "动作选择无效"; return 1 ;;
    esac

    mapfile -t protocols < <(select_protocols)
    (( ${#protocols[@]} > 0 )) || { error "协议选择无效"; return 1; }

    read -r -p "请输入远端端口，可用逗号或冒号范围，例如 53,80,443: " port_spec
    validate_port_spec "$port_spec" || { error "端口格式无效，或端口元素超过 15 个"; return 1; }

    read -r -p "目标地址 [默认 any]: " destination
    destination=${destination:-any}
    validate_address_token_or_any "$destination" || { error "目标地址格式无效"; return 1; }

    read -r -p "限定出站网卡 [默认所有网卡]: " iface
    if [[ -n "$iface" ]] && ! validate_interface "$iface"; then
        error "网卡不存在：$iface"
        return 1
    fi

    read -r -p "规则备注 [默认 managed-outbound]: " comment
    comment=${comment:-managed-outbound}

    echo
    echo "将添加出站规则：${action} ${protocols[*]} to ${destination}:${port_spec}${iface:+ on $iface}"
    confirm "确认添加？" Y || return 0

    for proto in "${protocols[@]}"; do
        cmd=(ufw "$action" out)
        [[ -n "$iface" ]] && cmd+=(on "$iface")
        cmd+=(proto "$proto" from any to "$destination" port "$port_spec" comment "$comment")
        "${cmd[@]}"
    done
    ok "出站规则添加完成"
}

rule_line_matches_direction() {
    local direction=$1
    local line=$2

    case "$direction" in
        in)  grep -Eq '(ALLOW|DENY|REJECT|LIMIT)[[:space:]]+IN([[:space:]]|$)' <<< "$line" ;;
        out) grep -Eq '(ALLOW|DENY|REJECT|LIMIT)[[:space:]]+OUT([[:space:]]|$)' <<< "$line" ;;
        fwd) grep -Eq '(ALLOW|DENY|REJECT|LIMIT)[[:space:]]+FWD([[:space:]]|$)' <<< "$line" ;;
        *) return 1 ;;
    esac
}

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

    if (( found == 0 )); then
        echo "  暂无相关已保存规则"
    fi
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

    if (( found == 0 )); then
        echo "  暂无相关规则"
    fi
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

delete_direction_rules_interactive() {
    local category=$1
    local direction=$2
    local selection number line
    local -a requested=()
    local -a verified=()

    if ! is_ufw_active; then
        warn "UFW 当前未启用，无法获得稳定的规则编号"
        warn "请先进入“UFW 状态与控制”启用 UFW，再执行按编号删除"
        return 0
    fi

    show_direction_rules "$direction" "$category"
    read -r -p "请输入要删除的 UFW 规则编号，多个用逗号分隔 [直接回车取消]: " selection
    [[ -n "$selection" ]] || return 0

    selection=${selection// /}
    IFS=',' read -r -a requested <<< "$selection"

    for number in "${requested[@]}"; do
        if [[ ! "$number" =~ ^[0-9]+$ ]]; then
            warn "忽略无效编号：$number"
            continue
        fi

        line=$(ufw status numbered 2>/dev/null | grep -E "^\\[[[:space:]]*${number}[[:space:]]*\\]" | head -n 1 || true)
        if [[ -z "$line" ]]; then
            warn "规则编号不存在：$number"
            continue
        fi

        if ! rule_line_matches_direction "$direction" "$line"; then
            warn "编号 ${number} 不属于${category}规则，已跳过"
            continue
        fi

        verified+=("$number")
    done

    (( ${#verified[@]} > 0 )) || {
        warn "没有可删除的${category}规则"
        return 0
    }

    mapfile -t verified < <(printf '%s\n' "${verified[@]}" | sort -rn -u)
    confirm "确认删除编号：$(IFS=,; echo "${verified[*]}")？" N || return 0

    for number in "${verified[@]}"; do
        ufw --force delete "$number"
    done

    ok "${category}规则删除完成"
}

forward_menu() {
    local choice
    while true; do
        clear || true
        echo "========================================"
        echo "UFW 管理 > 转发管理"
        echo "========================================"
        show_forward_overview
        echo "1) 新增完整端口转发"
        echo "2) 删除本脚本管理的完整端口转发"
        echo "3) 删除独立 UFW 路由规则（不处理 NAT）"
        echo "4) 查看 UFW 原始规则"
        echo "5) 审计/迁移旧转发状态"
        echo "6) 事务备份、恢复与诊断"
        echo "0) 返回上一级"
        read -r -p "请选择: " choice
        case "$choice" in
            1) if add_forward_rule_interactive; then :; else :; fi; invalidate_ufw_snapshot; pause ;;
            2) if delete_forward_rule_interactive; then :; else :; fi; invalidate_ufw_snapshot; pause ;;
            3)
                warn "该操作只删除 ufw route 规则，不会清理手工配置的 DNAT/SNAT"
                if run_mutation_action "删除独立 UFW 路由规则" delete_direction_rules_interactive "转发" fwd; then :; else :; fi
                invalidate_ufw_snapshot
                pause
                ;;
            4) ufw show raw || true; pause ;;
            5) if legacy_state_management_interactive; then :; else :; fi; invalidate_ufw_snapshot; pause ;;
            6) transaction_maintenance_menu; invalidate_ufw_snapshot ;;
            0) return 0 ;;
            *) warn "无效选项"; pause ;;
        esac
    done
}

inbound_menu() {
    local choice
    while true; do
        clear || true
        echo "========================================"
        echo "UFW 管理 > 入站管理"
        echo "========================================"
        show_direction_rules in "入站"
        echo "1) 新增入站规则"
        echo "2) 删除入站规则"
        echo "3) 查看全部 UFW 规则"
        echo "0) 返回上一级"
        read -r -p "请选择: " choice
        case "$choice" in
            1) if run_mutation_action "添加 UFW 入站规则" add_inbound_rule_interactive; then :; else :; fi; invalidate_ufw_snapshot; pause ;;
            2) if run_mutation_action "删除 UFW 入站规则" delete_direction_rules_interactive "入站" in; then :; else :; fi; invalidate_ufw_snapshot; pause ;;
            3) ensure_ufw_snapshot && printf '%s\n' "$UFW_STATUS_NUMBERED_CACHE"; pause ;;
            0) return 0 ;;
            *) warn "无效选项"; pause ;;
        esac
    done
}

outbound_menu() {
    local choice
    while true; do
        clear || true
        echo "========================================"
        echo "UFW 管理 > 出站管理"
        echo "========================================"
        show_direction_rules out "出站"
        echo "1) 新增出站规则"
        echo "2) 删除出站规则"
        echo "3) 查看全部 UFW 规则"
        echo "0) 返回上一级"
        read -r -p "请选择: " choice
        case "$choice" in
            1) if run_mutation_action "添加 UFW 出站规则" add_outbound_rule_interactive; then :; else :; fi; invalidate_ufw_snapshot; pause ;;
            2) if run_mutation_action "删除 UFW 出站规则" delete_direction_rules_interactive "出站" out; then :; else :; fi; invalidate_ufw_snapshot; pause ;;
            3) ensure_ufw_snapshot && printf '%s\n' "$UFW_STATUS_NUMBERED_CACHE"; pause ;;
            0) return 0 ;;
            *) warn "无效选项"; pause ;;
        esac
    done
}

control_menu() {
    local choice
    while true; do
        clear || true
        echo "========================================"
        echo "UFW 管理 > 状态与控制"
        echo "========================================"
        if ensure_ufw_snapshot; then
            printf '%s\n' "$UFW_STATUS_VERBOSE_CACHE"
        fi
        echo
        echo "1) 查看详细规则"
        echo "2) 安全初始化并启用 UFW"
        echo "3) 重新加载 UFW"
        echo "4) 禁用 UFW"
        echo "5) 设置日志级别"
        echo "0) 返回上一级"
        read -r -p "请选择: " choice
        case "$choice" in
            1)
                if ensure_ufw_snapshot; then
                    printf '%s\n' "$UFW_STATUS_NUMBERED_CACHE"
                    echo
                    printf '%s\n' "$UFW_SHOW_ADDED_CACHE"
                fi
                pause
                ;;
            2) if setup_and_enable_ufw; then :; else :; fi; invalidate_ufw_snapshot; pause ;;
            3) if run_mutation_action "重新加载 UFW" reload_ufw; then :; else :; fi; invalidate_ufw_snapshot; pause ;;
            4) if run_mutation_action "禁用 UFW" disable_ufw_interactive; then :; else :; fi; invalidate_ufw_snapshot; pause ;;
            5) if run_mutation_action "设置 UFW 日志级别" set_ufw_logging_interactive; then :; else :; fi; invalidate_ufw_snapshot; pause ;;
            0) return 0 ;;
            *) warn "无效选项"; pause ;;
        esac
    done
}

disable_ufw_interactive() {
    warn "禁用 UFW 会停止防火墙保护，但不会删除规则。"
    confirm "确认禁用 UFW？" N || return "$RESULT_CANCELLED"
    ufw disable
}

set_ufw_logging_interactive() {
    local level
    echo "日志级别：1) off  2) low  3) medium  4) high  5) full"
    read -r -p "请选择 [默认 2]: " level
    case ${level:-2} in
        1) ufw logging off ;;
        2) ufw logging low ;;
        3) ufw logging medium ;;
        4) ufw logging high ;;
        5) ufw logging full ;;
        *) return "$RESULT_PRECHECK_FAILED" ;;
    esac
}

show_docker_warning() {
    if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker 2>/dev/null; then
        warn "检测到 Docker 正在运行。Docker 发布端口可能使用自己的防火墙链，不能仅依赖普通 UFW 入站规则。"
    fi
}

prepare_ufw_management_environment() {
    check_debian_family || return 1
    install_ufw_if_needed || return 1
    init_state
}

ufw_management_menu() {
    local choice status_text

    clear || true
    if ! require_root; then
        pause
        return 0
    fi

    echo "正在检查 UFW 运行环境..."
    if ! run_mutation_action "准备 UFW 管理环境" prepare_ufw_management_environment; then
        pause
        return 0
    fi
    invalidate_ufw_snapshot
    show_docker_warning

    if (( UFW_JUST_INSTALLED == 1 )); then
        echo
        info "UFW 刚刚安装完成，需要先确认 SSH、HTTP、HTTPS 等必要入站端口"
        if setup_and_enable_ufw; then :; else :; fi
        invalidate_ufw_snapshot
    fi

    while true; do
        clear || true
        if ! ensure_ufw_snapshot; then
            status_text="状态获取失败"
        elif ufw_snapshot_active; then
            status_text="已启用"
        else
            status_text="未启用"
        fi

        echo "========================================"
        echo "UFW 管理"
        echo "当前状态：${status_text}"
        echo "========================================"
        echo "1) 入站管理"
        echo "2) 出站管理"
        echo "3) 转发管理"
        echo "4) UFW 状态与控制"
        echo "0) 返回主菜单"
        read -r -p "请选择: " choice

        case "$choice" in
            1) inbound_menu ;;
            2) outbound_menu ;;
            3) forward_menu ;;
            4) control_menu ;;
            0) return 0 ;;
            *) warn "无效选项"; pause ;;
        esac
    done
}

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
    if ssh_socket_managed; then
        ports=$(detect_ssh_socket_ports 2>/dev/null || true)
    else
        command -v sshd >/dev/null 2>&1 || { record_security_check unknown "无法确定 SSH 配置端口"; return 0; }
        ports=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | sort -n -u)
    fi
    [[ -n "$ports" ]] || { record_security_check unknown "无法确定 SSH 监听端口"; return 0; }
    while IFS= read -r port; do
        port_is_listening "$port" || { record_security_check warning "SSH 端口 ${port} 未监听"; return 0; }
    done <<< "$ports"
    record_security_check pass "SSH 端口 $(paste -sd, - <<< "$ports") 正在监听"
}

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

main_menu() {
    local choice
    while true; do
        clear || true
        echo "========================================"
        echo "${PROGRAM_NAME} v${VERSION}"
        echo "========================================"
        echo "1) UFW 防火墙管理"
        echo "2) SSH 安全管理"
        echo "3) Fail2Ban 管理"
        echo "4) 系统安全检查"
        echo "0) 退出"
        echo
        echo "说明：启动时只检查 root 权限。"
        echo "      进入对应模块后，才检查环境并询问安装缺失组件。"
        read -r -p "请选择: " choice

        case "$choice" in
            1) ufw_management_menu ;;
            2) ssh_management_menu ;;
            3) fail2ban_management_menu ;;
            4) clear || true; run_security_check; pause ;;
            0) echo "已退出。"; return 0 ;;
            *) warn "无效选项"; pause ;;
        esac
    done
}

main() {
    install_mutation_cleanup_trap
    require_root || exit 1

    if is_streamed_source "${BASH_SOURCE[0]}"; then
        info "正在安装 lsec 到 ${INSTALL_PATH}"
        begin_mutation "安装 lsec" || die "无法获取全局变更锁"
        if ! install_lsec_candidate "${BASH_SOURCE[0]}"; then
            end_mutation
            die "lsec 安装失败"
        fi
        end_mutation
        ok "lsec 安装完成"
        exec "$INSTALL_PATH" "$@"
    fi

    case ${1:-} in
        "")
            if startup_transaction_recovery; then :; else
                warn "存在未修复的一致性问题，变更功能将保持锁定；只读检查仍可使用"
            fi
            main_menu
            ;;
        upgrade) run_mutation_action "升级 lsec" upgrade_lsec ;;
        uninstall) run_mutation_action "卸载 lsec" uninstall_lsec ;;
        help|-h|--help) show_lsec_usage ;;
        *) show_lsec_usage; return 2 ;;
    esac
}

if [[ "${LSEC_SOURCE_ONLY:-0}" != "1" && "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
