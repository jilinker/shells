#!/usr/bin/env bash
# Linux 服务器安全防护交互式管理器
# 包含 UFW SSH 和 Fail2Ban 管理模块
# 远程执行 bash <(curl -fsSL https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh)

set -Eeuo pipefail
export LC_ALL=C

PROGRAM_NAME="Linux 服务器安全防护管理器"
VERSION="3.1.1"
INSTALL_PATH=/usr/local/bin/lsec
unset REMOTE_URL
readonly REMOTE_URL=https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh
PROGRAM_MARKER='PROGRAM_NAME="Linux 服务器安全防护管理器"'
STATE_DIR="/etc/ufw/relay-manager"
STATE_FILE="${STATE_DIR}/forwarding.tsv"
BEFORE_RULES="/etc/ufw/before.rules"
NAT_BEGIN="# BEGIN UFW-RELAY-MANAGER RULES"
NAT_END="# END UFW-RELAY-MANAGER RULES"
UFW_JUST_INSTALLED=0
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

info()  { printf "%b[信息]%b %s\n" "$BLUE" "$NC" "$*"; }
ok()    { printf "%b[成功]%b %s\n" "$GREEN" "$NC" "$*"; }
warn()  { printf "%b[警告]%b %s\n" "$YELLOW" "$NC" "$*"; }
error() { printf "%b[错误]%b %s\n" "$RED" "$NC" "$*" >&2; }
die()   { error "$*"; exit 1; }

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
    confirm "确认卸载 lsec？" N || return 0
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
    grep -qx 'permitrootlogin prohibit-password' <<< "$config" || return 1
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
    if ! check_ssh_environment; then
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
            2) add_root_public_key_interactive || true; pause ;;
            3) start_ssh_port_migration || true; pause ;;
            4) finish_ssh_port_migration || true; pause ;;
            5) apply_ssh_hardening || true; pause ;;
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
    if ! check_fail2ban_environment; then
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
            2) configure_fail2ban_sshd || true; pause ;;
            3) set_fail2ban_recidive yes || true; pause ;;
            4) set_fail2ban_recidive no || true; pause ;;
            5) control_fail2ban_service start || true; pause ;;
            6) control_fail2ban_service stop || true; pause ;;
            7) control_fail2ban_service restart || true; pause ;;
            8) control_fail2ban_service enable || true; pause ;;
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
    install -d -m 700 "$STATE_DIR"
    touch "$STATE_FILE"
    chmod 600 "$STATE_FILE"
    [[ -f "$BEFORE_RULES" ]] || die "未找到 ${BEFORE_RULES}，请检查 UFW 安装状态"
}

validate_port() {
    local port=${1:-}
    [[ "$port" =~ ^[0-9]+$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 ))
}

validate_port_spec() {
    local spec=${1:-}
    local item start end count=0
    [[ "$spec" =~ ^[0-9,:]+$ ]] || return 1

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
    [[ -n "$iface" ]] && ip link show dev "$iface" >/dev/null 2>&1
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

setup_and_enable_ufw() {
    if is_ufw_active; then
        info "UFW 当前已启用"
        return 0
    fi

    warn "UFW 当前未启用。启用防火墙可能影响远程连接。"
    if ! confirm "是否配置必要端口并启用 UFW？" Y; then
        warn "已保留 UFW 未启用状态；规则可编辑，但不会生效"
        return 0
    fi

    # 安全默认策略：入站拒绝、出站允许、路由转发默认拒绝。
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny routed

    select_common_inbound_ports

    echo
    ufw status numbered || true
    echo
    if ! confirm "以上端口确认无误，是否正式启用 UFW？" Y; then
        warn "已取消启用 UFW，已添加的规则会保留"
        return 0
    fi

    ufw --force enable
    ufw logging low
    ok "UFW 已启用，并设置为开机启动"
}

ensure_ipv4_forwarding() {
    local file="/etc/ufw/sysctl.conf"
    local tmp
    tmp=$(mktemp)

    if grep -Eq '^[[:space:]]*net[./]ipv4[./]ip_forward[[:space:]]*=' "$file"; then
        awk '
            /^[[:space:]]*net[./]ipv4[./]ip_forward[[:space:]]*=/ {
                if (!done) print "net/ipv4/ip_forward=1"
                done=1
                next
            }
            { print }
        ' "$file" > "$tmp"
    else
        cat "$file" > "$tmp"
        printf '\n# Enabled by UFW relay manager\nnet/ipv4/ip_forward=1\n' >> "$tmp"
    fi

    install -m 644 "$tmp" "$file"
    rm -f "$tmp"
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
    local tmp tmp2 nat_block need_pre=0 need_post=0
    tmp=$(mktemp)
    tmp2=$(mktemp)

    if grep -Fq "$NAT_BEGIN" "$BEFORE_RULES" && grep -Fq "$NAT_END" "$BEFORE_RULES"; then
        rm -f "$tmp" "$tmp2"
        return 0
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

    mapfile -t numbers < <(
        ufw status numbered 2>/dev/null \
            | grep -F "$comment" \
            | sed -n 's/^\[[[:space:]]*\([0-9][0-9]*\)\].*/\1/p' \
            | sort -rn
    )

    for number in "${numbers[@]}"; do
        ufw --force delete "$number"
    done
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

add_forward_rule_interactive() {
    local default_in in_if public_port landing_ip landing_port default_out out_if source proto_choice masquerade
    local -a protocols=()

    ensure_ipv4_forwarding

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

    echo
    echo "即将添加："
    echo "  来源：${source}"
    echo "  入口：${in_if}:${public_port}"
    echo "  协议：${protocols[*]}"
    echo "  目标：${landing_ip}:${landing_port}"
    echo "  出口：${out_if}"
    echo "  SNAT：${masquerade}"
    echo
    confirm "确认添加该转发规则？" Y || { warn "已取消"; return 0; }

    local proto
    for proto in "${protocols[@]}"; do
        add_forward_protocol "$proto" "$source" "$in_if" "$public_port" "$out_if" "$landing_ip" "$landing_port" "$masquerade" || warn "${proto^^} 转发添加失败"
    done
}

delete_forward_rule_interactive() {
    local selection id
    local -a indexes=()
    local -a ids=()

    list_forward_rules
    [[ -s "$STATE_FILE" ]] || return 0

    read -r -p "请输入要删除的序号，多个用逗号分隔 [直接回车取消]: " selection
    [[ -n "$selection" ]] || { warn "已取消"; return 0; }
    selection=${selection// /}
    IFS=',' read -r -a indexes <<< "$selection"

    for selection in "${indexes[@]}"; do
        [[ "$selection" =~ ^[0-9]+$ ]] || { warn "忽略无效序号：$selection"; continue; }
        id=$(awk -F '\t' -v n="$selection" 'NR==n {print $1}' "$STATE_FILE")
        [[ -n "$id" ]] && ids+=("$id") || warn "序号不存在：$selection"
    done

    (( ${#ids[@]} > 0 )) || return 0
    confirm "确认删除选中的 ${#ids[@]} 条转发规则？" N || { warn "已取消"; return 0; }

    for id in "${ids[@]}"; do
        delete_forward_by_id "$id" || warn "转发规则删除失败：$id"
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
    done < <(ufw show added 2>/dev/null || true)

    if (( found == 0 )); then
        echo "  暂无相关已保存规则"
    fi
}

show_direction_rules() {
    local direction=$1
    local title=$2
    local line found=0

    echo "--- ${title}现有配置 ---"

    if ! is_ufw_active; then
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
    done < <(ufw status numbered 2>/dev/null || true)

    if (( found == 0 )); then
        echo "  暂无相关规则"
    fi
    echo
}

show_forward_overview() {
    echo "--- 本脚本管理的完整端口转发 ---"
    list_forward_rules
    echo "--- UFW 路由放行规则 ---"
    if is_ufw_active; then
        local line found=0
        while IFS= read -r line; do
            [[ "$line" =~ ^\[ ]] || continue
            if rule_line_matches_direction fwd "$line"; then
                printf '%s\n' "$line"
                found=1
            fi
        done < <(ufw status numbered 2>/dev/null || true)
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
        echo "0) 返回上一级"
        read -r -p "请选择: " choice
        case "$choice" in
            1) add_forward_rule_interactive || true; pause ;;
            2) delete_forward_rule_interactive || true; pause ;;
            3)
                warn "该操作只删除 ufw route 规则，不会清理手工配置的 DNAT/SNAT"
                delete_direction_rules_interactive "转发" fwd || true
                pause
                ;;
            4) ufw show raw || true; pause ;;
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
            1) add_inbound_rule_interactive || true; pause ;;
            2) delete_direction_rules_interactive "入站" in || true; pause ;;
            3) ufw status numbered || true; pause ;;
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
            1) add_outbound_rule_interactive || true; pause ;;
            2) delete_direction_rules_interactive "出站" out || true; pause ;;
            3) ufw status numbered || true; pause ;;
            0) return 0 ;;
            *) warn "无效选项"; pause ;;
        esac
    done
}

control_menu() {
    local choice level
    while true; do
        clear || true
        echo "========================================"
        echo "UFW 管理 > 状态与控制"
        echo "========================================"
        ufw status verbose || true
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
                ufw status numbered || true
                echo
                ufw show added || true
                pause
                ;;
            2) setup_and_enable_ufw || true; pause ;;
            3) reload_ufw || true; pause ;;
            4)
                warn "禁用 UFW 会停止防火墙保护，但不会删除规则。"
                if confirm "确认禁用 UFW？" N; then
                    ufw disable
                fi
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
                pause
                ;;
            0) return 0 ;;
            *) warn "无效选项"; pause ;;
        esac
    done
}

show_docker_warning() {
    if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker 2>/dev/null; then
        warn "检测到 Docker 正在运行。Docker 发布端口可能使用自己的防火墙链，不能仅依赖普通 UFW 入站规则。"
    fi
}

ufw_management_menu() {
    local choice status_text

    clear || true
    if ! require_root; then
        pause
        return 0
    fi

    echo "正在检查 UFW 运行环境..."
    if ! check_debian_family; then
        pause
        return 0
    fi

    if ! install_ufw_if_needed; then
        pause
        return 0
    fi

    init_state
    show_docker_warning

    if (( UFW_JUST_INSTALLED == 1 )); then
        echo
        info "UFW 刚刚安装完成，需要先确认 SSH、HTTP、HTTPS 等必要入站端口"
        setup_and_enable_ufw || true
    fi

    while true; do
        clear || true
        if is_ufw_active; then
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
    ports=$(all_current_ssh_ports 2>/dev/null || true)
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

module_not_implemented() {
    local module_name=$1
    warn "${module_name}模块尚未实现，已返回主菜单"
    pause
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
        echo "4) 系统安全检查（待扩展）"
        echo "0) 退出"
        echo
        echo "说明：启动时只检查 root 权限。"
        echo "      进入对应模块后，才检查环境并询问安装缺失组件。"
        read -r -p "请选择: " choice

        case "$choice" in
            1) ufw_management_menu ;;
            2) ssh_management_menu ;;
            3) fail2ban_management_menu ;;
            4) module_not_implemented "系统安全检查" ;;
            0) echo "已退出。"; return 0 ;;
            *) warn "无效选项"; pause ;;
        esac
    done
}

main() {
    require_root || exit 1

    if is_streamed_source "${BASH_SOURCE[0]}"; then
        info "正在安装 lsec 到 ${INSTALL_PATH}"
        install_lsec_candidate "${BASH_SOURCE[0]}" || die "lsec 安装失败"
        ok "lsec 安装完成"
        exec "$INSTALL_PATH" "$@"
    fi

    case ${1:-} in
        "") main_menu ;;
        upgrade) upgrade_lsec ;;
        uninstall) uninstall_lsec ;;
        help|-h|--help) show_lsec_usage ;;
        *) show_lsec_usage; return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
