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

printf 'linux security transaction test passed\n'
