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

printf 'linux security transaction test passed\n'
