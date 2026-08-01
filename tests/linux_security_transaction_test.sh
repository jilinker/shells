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

printf 'linux security transaction test passed\n'
