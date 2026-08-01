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

printf 'linux security transaction test passed\n'
