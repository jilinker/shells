#!/usr/bin/env bash

set -Eeuo pipefail

source "$(dirname "$0")/testlib.sh"
source_manager

assert_eq "$RESULT_OK" 0
assert_eq "$RESULT_CANCELLED" 10
assert_eq "$RESULT_PRECHECK_FAILED" 20
assert_eq "$RESULT_APPLY_FAILED_ROLLED_BACK" 30
assert_eq "$RESULT_ROLLBACK_FAILED" 40
assert_eq "$RESULT_VERIFY_FAILED_ROLLED_BACK" 50
assert_eq "$RESULT_PROTECTED_LOCKOUT" 60
assert_eq "$RESULT_REPAIR_REQUIRED" 70
assert_eq "$(result_message "$RESULT_CANCELLED")" "操作已取消，未执行任何变更"

TEST_TMP="$(mktemp -d)"
trap 'rm -rf -- "$TEST_TMP"' EXIT

STATE_DIR="$TEST_TMP/state"
configure_state_paths

FLOCK_TEST_RESULT=0
flock() {
    [[ "$FLOCK_TEST_RESULT" == 0 ]]
}

begin_mutation "创建转发"
assert_file_contains "$OPERATION_LOCK" $'pid\t'
assert_file_contains "$OPERATION_LOCK" $'started_at\t'
assert_file_contains "$OPERATION_LOCK" $'operation\t创建转发'
end_mutation

FLOCK_TEST_RESULT=1
assert_status "$RESULT_PRECHECK_FAILED" begin_mutation "并发变更" >/dev/null 2>&1
FLOCK_TEST_RESULT=0

mkdir -p "$STATE_DIR"
printf 'batch\ttest\n' > "$PROTECTED_LOCK"
assert_status "$RESULT_PROTECTED_LOCKOUT" require_mutation_allowed >/dev/null 2>&1
rm -f "$PROTECTED_LOCK"
assert_status "$RESULT_OK" require_mutation_allowed

assert_contains "$(declare -f main)" "install_mutation_cleanup_trap"

write_complete_fixture() {
    printf 'complete\n'
}

write_partial_then_fail() {
    printf 'partial\n'
    return 1
}

atomic_target="$TEST_TMP/atomic-state"
printf 'original\n' > "$atomic_target"
assert_status 1 atomic_write "$atomic_target" write_partial_then_fail
assert_eq "$(cat "$atomic_target")" "original"
atomic_write "$atomic_target" write_complete_fixture
assert_eq "$(cat "$atomic_target")" "complete"
assert_eq "$(file_mode "$atomic_target")" 600

BEFORE_RULES="$TEST_TMP/before.rules"
IP_FORWARDING_STATE="$STATE_DIR/ip-forwarding.tsv"
mkdir -p "$STATE_DIR"
printf '*filter\nCOMMIT\n' > "$BEFORE_RULES"
printf 'existing-state\n' > "$STATE_FILE"
printf 'owned\tno\n' > "$IP_FORWARDING_STATE"

batch_id="$(new_batch_id)"
begin_transaction "$batch_id" create 'rule-a,rule-b'
snapshot_dir="$BACKUP_DIR/$batch_id"
journal_file="$TRANSACTION_DIR/$batch_id.txn"
for snapshot_file in before.rules forwarding.tsv metadata.tsv ip-forwarding.tsv; do
    [[ -f "$snapshot_dir/$snapshot_file" ]] || fail "missing snapshot: $snapshot_file"
done
assert_eq "$(file_mode "$journal_file")" 600
assert_file_contains "$journal_file" $'phase\tprepared'

for phase in applying_nat applying_ufw committing_state verifying; do
    set_transaction_phase "$batch_id" "$phase"
    assert_file_contains "$journal_file" $'phase\t'"$phase"
done
assert_status 1 finish_transaction "$batch_id" committed
set_transaction_phase "$batch_id" verified
finish_transaction "$batch_id" committed
assert_file_contains "$journal_file" $'phase\tcommitted'

for valid_spec in 80 80,443 10000:10100 53,80:90,443; do
    assert_status 0 validate_port_spec "$valid_spec"
done
for invalid_spec in '80,' ',80' '80,,81' '80::90' '80:90,' 0 65536 '90:80' '80 81' '80;id'; do
    assert_status 1 validate_port_spec "$invalid_spec"
done

for valid_interface in eth0 ens3.100 wg-test0; do
    assert_status 0 validate_interface_name "$valid_interface"
done
for invalid_interface in '' '-eth0' 'eth0/1' 'eth0;id' 'interface-name-too-long'; do
    assert_status 1 validate_interface_name "$invalid_interface"
done

marker="$(managed_marker batch-1 rule_2)"
assert_eq "$marker" 'lsec:batch-1:rule_2'
assert_status 0 validate_managed_marker "$marker"
assert_status 1 validate_managed_marker 'ufw-relay:old-id'
assert_status 1 validate_managed_marker 'lsec:batch:rule;id'

printf '%s\n' \
    $'lsec:batch-1:rule-a\ttcp\tany' \
    $'lsec:batch-1:rule-a\tudp\tany' \
    $'lsec:batch-1:rule-b\ttcp\tany' > "$STATE_FILE"
assert_eq "$(state_marker_count 'lsec:batch-1:rule-a')" 2
assert_status 1 state_has_unique_marker 'lsec:batch-1:rule-a'
assert_status 0 state_has_unique_marker 'lsec:batch-1:rule-b'

original_dependency_available="$(declare -f dependency_available 2>/dev/null || true)"
AVAILABLE_DEPENDENCIES='flock ufw sysctl'
dependency_available() {
    [[ " $AVAILABLE_DEPENDENCIES " == *" $1 "* ]]
}
assert_status 1 collect_missing_dependencies
assert_eq "${MISSING_DEPENDENCIES[*]}" 'iptables iptables-restore'
AVAILABLE_DEPENDENCIES='flock ufw iptables iptables-restore sysctl'
assert_status 0 collect_missing_dependencies

original_confirm="$(declare -f confirm)"
confirm() { return 1; }
AVAILABLE_DEPENDENCIES='flock'
assert_status "$RESULT_CANCELLED" run_dependency_preflight >/dev/null 2>&1

install_attempts=0
confirm() { return 0; }
install_missing_dependencies() {
    ((install_attempts += 1))
    AVAILABLE_DEPENDENCIES='flock ufw iptables iptables-restore sysctl'
}
run_dependency_preflight >/dev/null
assert_eq "$install_attempts" 1
eval "$original_confirm"
if [[ -n "$original_dependency_available" ]]; then
    eval "$original_dependency_available"
else
    unset -f dependency_available
fi
unset -f install_missing_dependencies

preview_output="$(render_execution_preview \
    create 'lsec:batch-2:rule-a' 'TCP+UDP 52350 -> 10.0.0.2:52350' \
    "$BEFORE_RULES" "$STATE_FILE" 'enable-if-needed')"
assert_contains "$preview_output" '执行预览'
assert_contains "$preview_output" 'lsec:batch-2:rule-a'
assert_contains "$preview_output" '回滚范围'
assert_contains "$preview_output" '仅验证本机配置，不证明应用协议端到端可达'
assert_eq "$(printf '1\n' | select_execution_mode 2>/dev/null)" execute
assert_eq "$(printf '2\n' | select_execution_mode 2>/dev/null)" preflight
assert_eq "$(printf '3\n' | select_execution_mode 2>/dev/null)" cancel

nat_fixture="$TEST_TMP/nat-fixture.rules"
cat > "$nat_fixture" <<'EOF'
*filter
:ufw-before-input - [0:0]
COMMIT
EOF
BEFORE_RULES="$nat_fixture"
staged_nat="$TEST_TMP/staged-before.rules"
nat_before_hash="$(shasum -a 256 "$BEFORE_RULES" | awk '{print $1}')"
stage_forward_nat "$staged_nat" batch-create any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp
assert_eq "$(shasum -a 256 "$BEFORE_RULES" | awk '{print $1}')" "$nat_before_hash"
assert_file_contains "$staged_nat" 'lsec:batch-create:tcp:dnat'
assert_file_contains "$staged_nat" 'lsec:batch-create:tcp:snat'
assert_file_contains "$staged_nat" 'lsec:batch-create:udp:dnat'
assert_file_contains "$staged_nat" 'lsec:batch-create:udp:snat'

IPTABLES_RESTORE_FAIL=0
IPTABLES_RESTORE_LOG="$TEST_TMP/iptables-restore.log"
iptables-restore() {
    printf '%s\n' "$*" >> "$IPTABLES_RESTORE_LOG"
    cat >/dev/null
    [[ "$IPTABLES_RESTORE_FAIL" == 0 ]]
}
validate_staged_nat "$staged_nat"
assert_file_contains "$IPTABLES_RESTORE_LOG" '--test'
IPTABLES_RESTORE_FAIL=1
assert_status 1 validate_staged_nat "$staged_nat"
IPTABLES_RESTORE_FAIL=0

STATE_DIR="$TEST_TMP/create-state"
configure_state_paths
BEFORE_RULES="$TEST_TMP/create-before.rules"
printf '*filter\n:ufw-before-input - [0:0]\nCOMMIT\n' > "$BEFORE_RULES"
mkdir -p "$STATE_DIR"
: > "$STATE_FILE"
printf 'runtime_original\t0\nowned\tno\n' > "$IP_FORWARDING_STATE"
create_staged="$TEST_TMP/create-staged.rules"
stage_forward_nat "$create_staged" batch-success any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp

UFW_ADDED_MARKERS=()
UFW_ADD_COUNT=0
UFW_FAIL_ADD_AT=0
UFW_DELETE_COUNT=0
UFW_FAIL_DELETE_AT=0
ufw() {
    local previous= argument number index
    case "$*" in
        'status') printf 'Status: active\n'; return 0 ;;
        'reload') return 0 ;;
        'status numbered')
            local marker index=1
            if (( ${#UFW_ADDED_MARKERS[@]} > 0 )); then
                for marker in "${UFW_ADDED_MARKERS[@]}"; do
                    printf '[ %d] route ALLOW %s\n' "$index" "$marker"
                    ((index += 1))
                done
            fi
            return 0
            ;;
    esac
    if [[ "$1" == --force && "$2" == delete ]]; then
        ((UFW_DELETE_COUNT += 1))
        if (( UFW_FAIL_DELETE_AT > 0 && UFW_DELETE_COUNT == UFW_FAIL_DELETE_AT )); then
            return 1
        fi
        number=$3
        index=$((number - 1))
        if (( ${#UFW_ADDED_MARKERS[@]} == 1 )); then
            UFW_ADDED_MARKERS=()
        else
            unset 'UFW_ADDED_MARKERS[index]'
            UFW_ADDED_MARKERS=("${UFW_ADDED_MARKERS[@]}")
        fi
        return 0
    fi
    for argument in "$@"; do
        if [[ "$previous" == comment ]]; then
            ((UFW_ADD_COUNT += 1))
            if (( UFW_FAIL_ADD_AT > 0 && UFW_ADD_COUNT == UFW_FAIL_ADD_AT )); then
                return 1
            fi
            UFW_ADDED_MARKERS+=("$argument")
            return 0
        fi
        previous=$argument
    done
    return 0
}

original_ipv4_apply="$(declare -f apply_ipv4_forwarding_for_transaction 2>/dev/null || true)"
apply_ipv4_forwarding_for_transaction() { return 0; }
create_forwarding_transaction batch-success "$create_staged" any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp
assert_file_contains "$BEFORE_RULES" 'lsec:batch-success:tcp:dnat'
assert_file_contains "$STATE_FILE" $'lsec:batch-success:tcp\ttcp'
assert_file_contains "$STATE_FILE" $'lsec:batch-success:udp\tudp'
assert_file_contains "$TRANSACTION_DIR/batch-success.txn" $'phase\tcommitted'
if [[ -n "$original_ipv4_apply" ]]; then
    eval "$original_ipv4_apply"
else
    unset -f apply_ipv4_forwarding_for_transaction
fi

STATE_DIR="$TEST_TMP/create-failure-state"
configure_state_paths
BEFORE_RULES="$TEST_TMP/create-failure-before.rules"
printf '*filter\n:ufw-before-input - [0:0]\nCOMMIT\n' > "$BEFORE_RULES"
mkdir -p "$STATE_DIR"
: > "$STATE_FILE"
printf 'runtime_original\t0\nowned\tno\n' > "$IP_FORWARDING_STATE"
failure_staged="$TEST_TMP/create-failure-staged.rules"
stage_forward_nat "$failure_staged" batch-ufw-fail any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp
failure_before_hash="$(shasum -a 256 "$BEFORE_RULES" | awk '{print $1}')"
UFW_ADDED_MARKERS=()
UFW_ADD_COUNT=0
UFW_FAIL_ADD_AT=2
apply_ipv4_forwarding_for_transaction() { return 0; }
assert_status "$RESULT_APPLY_FAILED_ROLLED_BACK" create_forwarding_transaction \
    batch-ufw-fail "$failure_staged" any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp
assert_eq "$(shasum -a 256 "$BEFORE_RULES" | awk '{print $1}')" "$failure_before_hash"
assert_eq "$(wc -c < "$STATE_FILE" | tr -d ' ')" 0
assert_eq "${#UFW_ADDED_MARKERS[@]}" 0
[[ ! -e "$PROTECTED_LOCK" ]] || fail 'verified rollback must not create protected lock'
eval "$original_ipv4_apply"
UFW_FAIL_ADD_AT=0

STATE_DIR="$TEST_TMP/create-validation-state"
configure_state_paths
BEFORE_RULES="$TEST_TMP/create-validation-before.rules"
printf '*filter\n:ufw-before-input - [0:0]\nCOMMIT\n' > "$BEFORE_RULES"
mkdir -p "$STATE_DIR"
: > "$STATE_FILE"
: > "$IP_FORWARDING_STATE"
validation_staged="$TEST_TMP/create-validation-staged.rules"
stage_forward_nat "$validation_staged" batch-validation any eth0 52350 eth1 10.0.0.2 52350 yes tcp
validation_before_hash="$(shasum -a 256 "$BEFORE_RULES" | awk '{print $1}')"
IPTABLES_RESTORE_FAIL=1
apply_ipv4_forwarding_for_transaction() { return 0; }
assert_status "$RESULT_PRECHECK_FAILED" create_forwarding_transaction \
    batch-validation "$validation_staged" any eth0 52350 eth1 10.0.0.2 52350 yes tcp
assert_eq "$(shasum -a 256 "$BEFORE_RULES" | awk '{print $1}')" "$validation_before_hash"
[[ ! -e "$TRANSACTION_DIR/batch-validation.txn" ]] || fail 'invalid staging created a journal'
IPTABLES_RESTORE_FAIL=0
eval "$original_ipv4_apply"

STATE_DIR="$TEST_TMP/create-record-state"
configure_state_paths
BEFORE_RULES="$TEST_TMP/create-record-before.rules"
printf '*filter\n:ufw-before-input - [0:0]\nCOMMIT\n' > "$BEFORE_RULES"
mkdir -p "$STATE_DIR"
: > "$STATE_FILE"
: > "$IP_FORWARDING_STATE"
record_staged="$TEST_TMP/create-record-staged.rules"
stage_forward_nat "$record_staged" batch-record-fail any eth0 52350 eth1 10.0.0.2 52350 yes tcp
UFW_ADDED_MARKERS=()
UFW_ADD_COUNT=0
apply_ipv4_forwarding_for_transaction() { return 0; }
original_record_added="$(declare -f record_added_ufw_marker)"
record_added_ufw_marker() { return 1; }
assert_status "$RESULT_APPLY_FAILED_ROLLED_BACK" create_forwarding_transaction \
    batch-record-fail "$record_staged" any eth0 52350 eth1 10.0.0.2 52350 yes tcp >/dev/null 2>&1
assert_eq "${#UFW_ADDED_MARKERS[@]}" 0
eval "$original_record_added"
eval "$original_ipv4_apply"

prepare_create_failure_case() {
    local batch=$1
    STATE_DIR="$TEST_TMP/${batch}-state"
    configure_state_paths
    BEFORE_RULES="$TEST_TMP/${batch}-before.rules"
    printf '*filter\n:ufw-before-input - [0:0]\nCOMMIT\n' > "$BEFORE_RULES"
    mkdir -p "$STATE_DIR"
    : > "$STATE_FILE"
    : > "$IP_FORWARDING_STATE"
    FAILURE_STAGED="$TEST_TMP/${batch}-staged.rules"
    stage_forward_nat "$FAILURE_STAGED" "$batch" any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp
    FAILURE_BEFORE_HASH="$(shasum -a 256 "$BEFORE_RULES" | awk '{print $1}')"
    UFW_ADDED_MARKERS=()
    UFW_ADD_COUNT=0
    UFW_FAIL_ADD_AT=0
}

original_apply_staged="$(declare -f apply_staged_nat_file)"
prepare_create_failure_case batch-nat-fail
apply_ipv4_forwarding_for_transaction() { return 0; }
apply_staged_nat_file() { return 1; }
assert_status "$RESULT_APPLY_FAILED_ROLLED_BACK" create_forwarding_transaction \
    batch-nat-fail "$FAILURE_STAGED" any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp >/dev/null 2>&1
assert_eq "$(shasum -a 256 "$BEFORE_RULES" | awk '{print $1}')" "$FAILURE_BEFORE_HASH"
eval "$original_apply_staged"
eval "$original_ipv4_apply"

original_commit_state="$(declare -f commit_forward_state)"
prepare_create_failure_case batch-state-fail
apply_ipv4_forwarding_for_transaction() { return 0; }
commit_forward_state() { return 1; }
assert_status "$RESULT_APPLY_FAILED_ROLLED_BACK" create_forwarding_transaction \
    batch-state-fail "$FAILURE_STAGED" any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp >/dev/null 2>&1
assert_eq "${#UFW_ADDED_MARKERS[@]}" 0
eval "$original_commit_state"
eval "$original_ipv4_apply"

original_verify_batch="$(declare -f verify_forwarding_batch)"
prepare_create_failure_case batch-verify-fail
apply_ipv4_forwarding_for_transaction() { return 0; }
verify_forwarding_batch() { return 1; }
assert_status "$RESULT_VERIFY_FAILED_ROLLED_BACK" create_forwarding_transaction \
    batch-verify-fail "$FAILURE_STAGED" any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp >/dev/null 2>&1
assert_eq "${#UFW_ADDED_MARKERS[@]}" 0
[[ ! -e "$STATE_VERSION_FILE" ]] || fail 'rollback left a state.version that did not exist before'
eval "$original_verify_batch"
eval "$original_ipv4_apply"

original_restore_snapshot="$(declare -f restore_transaction_snapshot)"
prepare_create_failure_case batch-rollback-fail
apply_ipv4_forwarding_for_transaction() { return 0; }
apply_staged_nat_file() { return 1; }
restore_transaction_snapshot() { return 1; }
assert_status "$RESULT_ROLLBACK_FAILED" create_forwarding_transaction \
    batch-rollback-fail "$FAILURE_STAGED" any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp >/dev/null 2>&1
assert_file_contains "$PROTECTED_LOCK" $'batch_id\tbatch-rollback-fail'
assert_status "$RESULT_PROTECTED_LOCKOUT" require_mutation_allowed >/dev/null 2>&1
eval "$original_apply_staged"
eval "$original_restore_snapshot"
eval "$original_ipv4_apply"

forward_create_definition="$(declare -f add_forward_rule_interactive_locked; declare -f add_forward_rule_interactive)"
assert_not_contains "$forward_create_definition" 'ensure_ipv4_forwarding'
assert_not_contains "$forward_create_definition" 'add_forward_protocol'
assert_contains "$forward_create_definition" 'stage_forward_nat'
assert_contains "$forward_create_definition" 'render_execution_preview'
assert_contains "$forward_create_definition" 'select_execution_mode'
assert_contains "$forward_create_definition" 'create_forwarding_transaction'
assert_contains "$forward_create_definition" 'find_parameter_collisions'
assert_contains "$forward_create_definition" 'replace_forwarding_transaction'

original_begin_mutation="$(declare -f begin_mutation)"
begin_mutation() { return "$RESULT_PRECHECK_FAILED"; }
assert_status "$RESULT_PRECHECK_FAILED" add_forward_rule_interactive >/dev/null 2>&1
eval "$original_begin_mutation"

bad_state_parent="$TEST_TMP/not-a-directory"
printf 'file\n' > "$bad_state_parent"
STATE_DIR="$bad_state_parent/state"
configure_state_paths
BEFORE_RULES="$TEST_TMP/existing-before.rules"
printf '*filter\nCOMMIT\n' > "$BEFORE_RULES"
assert_status 1 init_state >/dev/null 2>&1

STATE_DIR="$TEST_TMP/delete-success-state"
configure_state_paths
BEFORE_RULES="$TEST_TMP/delete-success-before.rules"
delete_base="$TEST_TMP/delete-base.rules"
printf '*filter\n:ufw-before-input - [0:0]\nCOMMIT\n' > "$delete_base"
BEFORE_RULES="$delete_base"
stage_forward_nat "$TEST_TMP/delete-live.rules" old-batch any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp
BEFORE_RULES="$TEST_TMP/delete-success-before.rules"
cp "$TEST_TMP/delete-live.rules" "$BEFORE_RULES"
mkdir -p "$STATE_DIR"
render_state_with_forward_batch /dev/null old-batch any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp > "$STATE_FILE"
printf '%s\n' "$STATE_SCHEMA_VERSION" > "$STATE_VERSION_FILE"
: > "$IP_FORWARDING_STATE"
UFW_ADDED_MARKERS=('lsec:old-batch:tcp' 'lsec:old-batch:udp')
UFW_DELETE_COUNT=0
delete_staged="$TEST_TMP/delete-staged.rules"
delete_live_hash="$(shasum -a 256 "$BEFORE_RULES" | awk '{print $1}')"
stage_forward_nat_removal "$delete_staged" 'lsec:old-batch:tcp' 'lsec:old-batch:udp'
assert_eq "$(shasum -a 256 "$BEFORE_RULES" | awk '{print $1}')" "$delete_live_hash"
delete_forwarding_transaction delete-batch "$delete_staged" 'lsec:old-batch:tcp' 'lsec:old-batch:udp'
assert_not_contains "$(cat "$BEFORE_RULES")" 'lsec:old-batch:'
assert_eq "$(wc -c < "$STATE_FILE" | tr -d ' ')" 0
assert_eq "${#UFW_ADDED_MARKERS[@]}" 0
assert_file_contains "$TRANSACTION_DIR/delete-batch.txn" $'phase\tcommitted'

STATE_DIR="$TEST_TMP/delete-failure-state"
configure_state_paths
delete_failure_base="$TEST_TMP/delete-failure-base.rules"
printf '*filter\n:ufw-before-input - [0:0]\nCOMMIT\n' > "$delete_failure_base"
BEFORE_RULES="$delete_failure_base"
stage_forward_nat "$TEST_TMP/delete-failure-live.rules" old-failure any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp
BEFORE_RULES="$TEST_TMP/delete-failure-before.rules"
cp "$TEST_TMP/delete-failure-live.rules" "$BEFORE_RULES"
mkdir -p "$STATE_DIR"
render_state_with_forward_batch /dev/null old-failure any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp > "$STATE_FILE"
printf '%s\n' "$STATE_SCHEMA_VERSION" > "$STATE_VERSION_FILE"
: > "$IP_FORWARDING_STATE"
UFW_ADDED_MARKERS=('lsec:old-failure:tcp' 'lsec:old-failure:udp')
UFW_DELETE_COUNT=0
UFW_FAIL_DELETE_AT=2
delete_failure_staged="$TEST_TMP/delete-failure-staged.rules"
stage_forward_nat_removal "$delete_failure_staged" 'lsec:old-failure:tcp' 'lsec:old-failure:udp'
delete_failure_hash="$(shasum -a 256 "$BEFORE_RULES" | awk '{print $1}')"
assert_status "$RESULT_APPLY_FAILED_ROLLED_BACK" delete_forwarding_transaction \
    delete-failure-batch "$delete_failure_staged" 'lsec:old-failure:tcp' 'lsec:old-failure:udp' >/dev/null 2>&1
assert_eq "$(shasum -a 256 "$BEFORE_RULES" | awk '{print $1}')" "$delete_failure_hash"
assert_eq "$(state_marker_count 'lsec:old-failure:tcp')" 1
assert_eq "$(state_marker_count 'lsec:old-failure:udp')" 1
assert_eq "${#UFW_ADDED_MARKERS[@]}" 2
[[ ! -e "$PROTECTED_LOCK" ]] || fail 'verified delete rollback created protected lock'
UFW_FAIL_DELETE_AT=0

forward_delete_definition="$(declare -f delete_forward_rule_interactive_locked; declare -f delete_forward_rule_interactive)"
assert_not_contains "$forward_delete_definition" 'delete_forward_by_id'
assert_contains "$forward_delete_definition" 'stage_forward_nat_removal'
assert_contains "$forward_delete_definition" 'delete_forwarding_transaction'
assert_contains "$forward_delete_definition" 'select_execution_mode'

STATE_DIR="$TEST_TMP/replace-success-state"
configure_state_paths
replace_base="$TEST_TMP/replace-base.rules"
printf '*filter\n:ufw-before-input - [0:0]\nCOMMIT\n' > "$replace_base"
BEFORE_RULES="$replace_base"
stage_forward_nat "$TEST_TMP/replace-live.rules" replace-old any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp
BEFORE_RULES="$TEST_TMP/replace-success-before.rules"
cp "$TEST_TMP/replace-live.rules" "$BEFORE_RULES"
mkdir -p "$STATE_DIR"
render_state_with_forward_batch /dev/null replace-old any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp > "$STATE_FILE"
printf '%s\n' "$STATE_SCHEMA_VERSION" > "$STATE_VERSION_FILE"
: > "$IP_FORWARDING_STATE"
assert_eq "$(find_parameter_collisions tcp any eth0 52350 eth1 10.0.0.2 52350 yes)" 'lsec:replace-old:tcp'
replace_staged="$TEST_TMP/replace-staged.rules"
stage_forward_nat_replacement "$replace_staged" replace-new any eth0 52350 eth1 10.0.0.2 52350 yes \
    'lsec:replace-old:tcp,lsec:replace-old:udp' tcp udp
assert_not_contains "$(cat "$replace_staged")" 'lsec:replace-old:'
assert_contains "$(cat "$replace_staged")" 'lsec:replace-new:tcp:dnat'
UFW_ADDED_MARKERS=('lsec:replace-old:tcp' 'lsec:replace-old:udp')
UFW_ADD_COUNT=0
UFW_DELETE_COUNT=0
replace_forwarding_transaction replace-new "$replace_staged" \
    'lsec:replace-old:tcp,lsec:replace-old:udp' any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp
assert_eq "$(state_marker_count 'lsec:replace-old:tcp')" 0
assert_eq "$(state_marker_count 'lsec:replace-new:tcp')" 1
assert_eq "${#UFW_ADDED_MARKERS[@]}" 2
assert_contains "${UFW_ADDED_MARKERS[*]}" 'lsec:replace-new:tcp'
assert_contains "${UFW_ADDED_MARKERS[*]}" 'lsec:replace-new:udp'

assert_status "$RESULT_CANCELLED" select_collision_rules \
    'lsec:replace-old:tcp' 'lsec:replace-old:udp' <<< $'1\n' >/dev/null 2>&1
assert_status "$RESULT_PRECHECK_FAILED" select_collision_rules \
    'lsec:replace-old:tcp' 'lsec:replace-old:udp' <<< $'2\n1\n' >/dev/null 2>&1
assert_eq "$(select_collision_rules 'lsec:replace-old:tcp' 'lsec:replace-old:udp' \
    <<< $'2\n1,2\n' 2>/dev/null)" 'lsec:replace-old:tcp,lsec:replace-old:udp'

STATE_DIR="$TEST_TMP/replace-failure-state"
configure_state_paths
replace_failure_base="$TEST_TMP/replace-failure-base.rules"
printf '*filter\n:ufw-before-input - [0:0]\nCOMMIT\n' > "$replace_failure_base"
BEFORE_RULES="$replace_failure_base"
stage_forward_nat "$TEST_TMP/replace-failure-live.rules" replace-restore any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp
BEFORE_RULES="$TEST_TMP/replace-failure-before.rules"
cp "$TEST_TMP/replace-failure-live.rules" "$BEFORE_RULES"
mkdir -p "$STATE_DIR"
render_state_with_forward_batch /dev/null replace-restore any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp > "$STATE_FILE"
printf '%s\n' "$STATE_SCHEMA_VERSION" > "$STATE_VERSION_FILE"
: > "$IP_FORWARDING_STATE"
replace_failure_staged="$TEST_TMP/replace-failure-staged.rules"
stage_forward_nat_replacement "$replace_failure_staged" replace-fails any eth0 52350 eth1 10.0.0.2 52350 yes \
    'lsec:replace-restore:tcp,lsec:replace-restore:udp' tcp udp
UFW_ADDED_MARKERS=('lsec:replace-restore:tcp' 'lsec:replace-restore:udp')
UFW_ADD_COUNT=0
UFW_DELETE_COUNT=0
UFW_FAIL_ADD_AT=1
assert_status "$RESULT_APPLY_FAILED_ROLLED_BACK" replace_forwarding_transaction replace-fails \
    "$replace_failure_staged" 'lsec:replace-restore:tcp,lsec:replace-restore:udp' \
    any eth0 52350 eth1 10.0.0.2 52350 yes tcp udp >/dev/null 2>&1
assert_eq "$(state_marker_count 'lsec:replace-restore:tcp')" 1
assert_eq "$(state_marker_count 'lsec:replace-fails:tcp')" 0
assert_eq "${#UFW_ADDED_MARKERS[@]}" 2
assert_contains "${UFW_ADDED_MARKERS[*]}" 'lsec:replace-restore:tcp'
assert_contains "${UFW_ADDED_MARKERS[*]}" 'lsec:replace-restore:udp'
UFW_FAIL_ADD_AT=0

assert_contains "$(declare -f ensure_ipv4_forwarding)" 'UFW_SYSCTL_FILE'

STATE_DIR="$TEST_TMP/ipv4-state"
configure_state_paths
mkdir -p "$STATE_DIR"
BEFORE_RULES="$TEST_TMP/ipv4-before.rules"
printf '*filter\nCOMMIT\n' > "$BEFORE_RULES"
: > "$STATE_FILE"
UFW_SYSCTL_FILE="$TEST_TMP/ufw-sysctl.conf"
printf 'net/ipv4/ip_forward=0\n' > "$UFW_SYSCTL_FILE"
SYSCTL_RUNTIME=0
sysctl() {
    case "$1" in
        -n) printf '%s\n' "$SYSCTL_RUNTIME" ;;
        -w) SYSCTL_RUNTIME=${2#*=}; printf 'net.ipv4.ip_forward = %s\n' "$SYSCTL_RUNTIME" ;;
        *) return 1 ;;
    esac
}
begin_transaction ipv4-batch create tcp
apply_ipv4_forwarding_for_transaction ipv4-batch
assert_eq "$SYSCTL_RUNTIME" 1
assert_file_contains "$UFW_SYSCTL_FILE" 'net/ipv4/ip_forward=1'
assert_file_contains "$IP_FORWARDING_STATE" $'original_runtime\t0'
assert_file_contains "$IP_FORWARDING_STATE" $'owned_runtime\tyes'
assert_file_contains "$IP_FORWARDING_STATE" $'owned_persistent\tyes'
restore_transaction_snapshot ipv4-batch
assert_eq "$SYSCTL_RUNTIME" 0
assert_file_contains "$UFW_SYSCTL_FILE" 'net/ipv4/ip_forward=0'

apply_ipv4_forwarding_for_transaction ipv4-batch
assert_status 1 detect_other_forwarding_use
printf '%s\n' $'lsec:other:tcp\ttcp\tany\teth0\t80\teth1\t10.0.0.3\t80\tyes\tother' > "$STATE_FILE"
assert_status 0 detect_other_forwarding_use
: > "$STATE_FILE"
printf '%s\n' '*nat' ':PREROUTING ACCEPT [0:0]' '-A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 10.0.0.3:80' 'COMMIT' > "$BEFORE_RULES"
assert_status 0 detect_other_forwarding_use
printf '*filter\nCOMMIT\n' > "$BEFORE_RULES"
restore_owned_ipv4_forwarding
assert_eq "$SYSCTL_RUNTIME" 0
assert_file_contains "$UFW_SYSCTL_FILE" 'net/ipv4/ip_forward=0'
assert_eq "$(wc -c < "$IP_FORWARDING_STATE" | tr -d ' ')" 0

SYSCTL_RUNTIME=1
printf 'net/ipv4/ip_forward=1\n' > "$UFW_SYSCTL_FILE"
: > "$IP_FORWARDING_STATE"
apply_ipv4_forwarding_for_transaction no-ownership
assert_eq "$(wc -c < "$IP_FORWARDING_STATE" | tr -d ' ')" 0
assert_contains "$(declare -f delete_forward_rule_interactive_locked)" 'detect_other_forwarding_use'
assert_contains "$(declare -f delete_forwarding_transaction)" 'restore_owned_ipv4_forwarding'
unset -f sysctl

original_detect_ssh_ports="$(declare -f detect_ssh_ports)"
detect_ssh_ports() { return 0; }
assert_status "$RESULT_CANCELLED" resolve_ssh_ports_for_ufw <<< $'2222\n错误短语\n' >/dev/null 2>&1
assert_eq "$(resolve_ssh_ports_for_ufw <<< $'2222\n我确认SSH端口已放行并承担断连风险\n' 2>/dev/null)" 2222
detect_ssh_ports() { printf '2200\n2222\n'; }
assert_eq "$(resolve_ssh_ports_for_ufw 2>/dev/null)" $'2200\n2222'
eval "$original_detect_ssh_ports"

BOOT_UFW_ACTIVE=no
BOOT_UFW_FAIL=
BOOT_UFW_MARKERS=()
BOOT_UFW_LOG="$TEST_TMP/ufw-bootstrap.log"
ufw() {
    local previous= argument number index
    printf '%s\n' "$*" >> "$BOOT_UFW_LOG"
    [[ "$BOOT_UFW_FAIL" != "$1 ${2:-}" && "$BOOT_UFW_FAIL" != "$1" ]] || return 1
    case "$*" in
        status) printf 'Status: %s\n' "$([[ "$BOOT_UFW_ACTIVE" == yes ]] && echo active || echo inactive)" ;;
        'status verbose')
            printf 'Status: %s\n' "$([[ "$BOOT_UFW_ACTIVE" == yes ]] && echo active || echo inactive)"
            printf 'Default: deny (incoming), allow (outgoing), deny (routed)\n'
            ;;
        'show added')
            if (( ${#BOOT_UFW_MARKERS[@]} > 0 )); then printf '%s\n' "${BOOT_UFW_MARKERS[@]}"; fi
            ;;
        'status numbered')
            if (( ${#BOOT_UFW_MARKERS[@]} > 0 )); then
                for (( index=0; index<${#BOOT_UFW_MARKERS[@]}; index++ )); do
                    printf '[ %d] ALLOW IN %s\n' "$((index + 1))" "${BOOT_UFW_MARKERS[$index]}"
                done
            fi
            ;;
        '--force enable') BOOT_UFW_ACTIVE=yes ;;
        disable) BOOT_UFW_ACTIVE=no ;;
        '--force delete '*)
            number=$3
            index=$((number - 1))
            if (( ${#BOOT_UFW_MARKERS[@]} == 1 )); then BOOT_UFW_MARKERS=(); else
                unset 'BOOT_UFW_MARKERS[index]'
                BOOT_UFW_MARKERS=("${BOOT_UFW_MARKERS[@]}")
            fi
            ;;
        *)
            for argument in "$@"; do
                if [[ "$previous" == comment ]]; then BOOT_UFW_MARKERS+=("$argument"); break; fi
                previous=$argument
            done
            ;;
    esac
}

STATE_DIR="$TEST_TMP/ufw-bootstrap-state"
configure_state_paths
mkdir -p "$STATE_DIR"
: > "$BOOT_UFW_LOG"
enable_ufw_transaction ufw-success 2200 2222
assert_eq "$BOOT_UFW_ACTIVE" yes
allow_line=$(grep -n 'allow in proto tcp.*port 2200' "$BOOT_UFW_LOG" | head -1 | cut -d: -f1)
enable_line=$(grep -n '^--force enable$' "$BOOT_UFW_LOG" | head -1 | cut -d: -f1)
(( allow_line < enable_line )) || fail 'UFW enabled before SSH allow rule'

STATE_DIR="$TEST_TMP/ufw-bootstrap-failure-state"
configure_state_paths
mkdir -p "$STATE_DIR"
BOOT_UFW_ACTIVE=no
BOOT_UFW_MARKERS=()
BOOT_UFW_FAIL='--force enable'
assert_status "$RESULT_APPLY_FAILED_ROLLED_BACK" enable_ufw_transaction ufw-failure 2222 >/dev/null 2>&1
assert_eq "$BOOT_UFW_ACTIVE" no
assert_eq "${#BOOT_UFW_MARKERS[@]}" 0
[[ ! -e "$PROTECTED_LOCK" ]] || fail 'verified UFW rollback created protected lock'
BOOT_UFW_FAIL=

ufw_setup_definition="$(declare -f setup_and_enable_ufw_locked; declare -f setup_and_enable_ufw)"
assert_contains "$ufw_setup_definition" 'resolve_ssh_ports_for_ufw'
assert_contains "$ufw_setup_definition" 'enable_ufw_transaction'
assert_not_contains "$ufw_setup_definition" 'select_common_inbound_ports'
assert_not_contains "$(declare -f control_menu)" 'setup_and_enable_ufw || true'
detect_ssh_ports() { return 0; }
assert_status "$RESULT_CANCELLED" setup_and_enable_ufw_locked <<< $'2222\n错误短语\n' >/dev/null 2>&1
eval "$original_detect_ssh_ports"

STATE_DIR="$TEST_TMP/recovery-state"
configure_state_paths
mkdir -p "$STATE_DIR"
BEFORE_RULES="$TEST_TMP/recovery-before.rules"
printf 'original\n' > "$BEFORE_RULES"
: > "$STATE_FILE"
UFW_SYSCTL_FILE="$TEST_TMP/recovery-sysctl.conf"
printf 'net/ipv4/ip_forward=1\n' > "$UFW_SYSCTL_FILE"
begin_transaction recovery-batch create tcp
printf 'mutated\n' > "$BEFORE_RULES"
set_transaction_phase recovery-batch applying_nat
assert_eq "$(scan_incomplete_transactions)" recovery-batch
recover_transaction recovery-batch >/dev/null
assert_eq "$(cat "$BEFORE_RULES")" original
assert_file_contains "$TRANSACTION_DIR/recovery-batch.txn" $'phase\trolled_back'

printf '%s\n' $'batch_id\tbroken-batch' $'operation\tcreate' $'phase\tapplying_nat' \
    $'snapshot\t/not/present' > "$TRANSACTION_DIR/broken-batch.txn"
assert_status "$RESULT_ROLLBACK_FAILED" recover_transaction broken-batch >/dev/null 2>&1
assert_file_contains "$PROTECTED_LOCK" $'batch_id\tbroken-batch'
rm -f "$PROTECTED_LOCK" "$TRANSACTION_DIR/broken-batch.txn"

printf 'legacy-id\ttcp\tany\teth0\t80\teth1\t10.0.0.2\t80\tyes\n' > "$STATE_FILE"
rm -f "$STATE_VERSION_FILE"
assert_status "$RESULT_REPAIR_REQUIRED" require_current_state_schema
printf '%s\n' '*nat' ':PREROUTING ACCEPT [0:0]' \
    '-A PREROUTING -p tcp --dport 80 -m comment --comment ufw-relay:legacy-id:dnat -j DNAT --to-destination 10.0.0.2:80' \
    '-A POSTROUTING -p tcp -d 10.0.0.2 --dport 80 -m comment --comment ufw-relay:legacy-id:snat -j MASQUERADE' \
    'COMMIT' > "$BEFORE_RULES"
BOOT_UFW_MARKERS=('ufw-relay:legacy-id')
assert_contains "$(audit_legacy_forwarding_state)" $'legacy-id\tlegacy-exact'
printf '*filter\nCOMMIT\n' > "$BEFORE_RULES"
assert_contains "$(audit_legacy_forwarding_state)" $'legacy-id\tlegacy-drift'
: > "$STATE_FILE"
assert_status 0 require_current_state_schema
assert_contains "$(declare -f main)" 'startup_transaction_recovery'

printf 'legacy-migrate\ttcp\tany\teth0\t80\teth1\t10.0.0.2\t80\tyes\n' > "$STATE_FILE"
rm -f "$STATE_VERSION_FILE"
printf '%s\n' '*nat' ':PREROUTING ACCEPT [0:0]' \
    '-A PREROUTING -p tcp --dport 80 -m comment --comment ufw-relay:legacy-migrate:dnat -j DNAT --to-destination 10.0.0.2:80' \
    '-A POSTROUTING -p tcp -d 10.0.0.2 --dport 80 -m comment --comment ufw-relay:legacy-migrate:snat -j MASQUERADE' \
    'COMMIT' > "$BEFORE_RULES"
BOOT_UFW_MARKERS=('ufw-relay:legacy-migrate')
BOOT_UFW_ACTIVE=yes
migrate_legacy_forwarding_state migration-batch
assert_eq "$(state_marker_count 'lsec:migration-batch:legacy-1')" 1
assert_file_contains "$BEFORE_RULES" 'lsec:migration-batch:legacy-1:dnat'
assert_contains "${BOOT_UFW_MARKERS[*]}" 'lsec:migration-batch:legacy-1'
assert_file_contains "$STATE_VERSION_FILE" "$STATE_SCHEMA_VERSION"
assert_file_contains "$TRANSACTION_DIR/migration-batch.txn" $'phase\tcommitted'
assert_contains "$(declare -f forward_menu)" 'legacy_state_management_interactive'

STATE_DIR="$TEST_TMP/backup-policy-state"
configure_state_paths
mkdir -p "$BACKUP_DIR" "$TRANSACTION_DIR"
for backup_index in $(seq -w 1 22); do
    backup_id="backup-${backup_index}"
    mkdir -p "$BACKUP_DIR/$backup_id"
    printf 'batch_id\t%s\nstatus\tsuccess\ncreated_epoch\t%s\noperation\tcreate\n' \
        "$backup_id" "$((10#$backup_index))" > "$BACKUP_DIR/$backup_id/metadata.tsv"
    printf 'batch_id\t%s\nphase\tcommitted\n' "$backup_id" > "$TRANSACTION_DIR/$backup_id.txn"
done
mkdir -p "$BACKUP_DIR/backup-failed"
printf 'batch_id\tbackup-failed\nstatus\tfailed\ncreated_epoch\t1\noperation\tcreate\n' \
    > "$BACKUP_DIR/backup-failed/metadata.tsv"
printf 'batch_id\tbackup-failed\nphase\trolled_back\n' > "$TRANSACTION_DIR/backup-failed.txn"
eligible_backups="$(eligible_success_snapshots_for_cleanup 4000000)"
assert_contains "$eligible_backups" 'backup-01'
assert_contains "$eligible_backups" 'backup-02'
assert_not_contains "$eligible_backups" 'backup-03'
assert_not_contains "$eligible_backups" 'backup-failed'
assert_contains "$(list_snapshots)" $'backup-failed\tfailed'

diagnostic_export="$TEST_TMP/lsec-diagnostics.txt"
export_transaction_diagnostics "$diagnostic_export"
assert_eq "$(file_mode "$diagnostic_export")" 600
assert_file_contains "$diagnostic_export" 'lsec transaction diagnostics'

cleanup_selected_snapshots 4000000 backup-01
[[ ! -e "$BACKUP_DIR/backup-01" ]] || fail 'eligible selected backup was not removed'
assert_status "$RESULT_PRECHECK_FAILED" cleanup_selected_snapshots 4000000 backup-03 >/dev/null 2>&1
[[ -d "$BACKUP_DIR/backup-03" ]] || fail 'protected newest-20 backup was removed'
assert_status "$RESULT_PRECHECK_FAILED" cleanup_selected_snapshots 4000000 '../escape' >/dev/null 2>&1

STATE_DIR="$TEST_TMP/restore-state"
configure_state_paths
mkdir -p "$STATE_DIR"
BEFORE_RULES="$TEST_TMP/restore-before.rules"
UFW_SYSCTL_FILE="$TEST_TMP/restore-sysctl.conf"
printf 'restore-point\n' > "$BEFORE_RULES"
printf 'net/ipv4/ip_forward=1\n' > "$UFW_SYSCTL_FILE"
: > "$STATE_FILE"
begin_transaction restore-source create none
set_transaction_phase restore-source verified
finish_transaction restore-source committed
printf 'current-mutated\n' > "$BEFORE_RULES"
restore_snapshot_transaction restore-source
assert_eq "$(cat "$BEFORE_RULES")" restore-point
restore_journal=$(grep -l $'operation\trestore' "$TRANSACTION_DIR"/*.txn | head -1)
assert_file_contains "$restore_journal" $'phase\tcommitted'
assert_contains "$(declare -f forward_menu)" 'transaction_maintenance_menu'

printf 'linux security transaction test passed\n'
