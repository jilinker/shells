#!/usr/bin/env bash

set -Eeuo pipefail

TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
    printf 'not ok - %s\n' "$*" >&2
    exit 1
}

assert_eq() {
    local actual=$1 expected=$2
    [[ "$actual" == "$expected" ]] || fail "expected [$expected], got [$actual]"
}

assert_file_contains() {
    local file=$1 expected=$2
    grep -Fq -- "$expected" "$file" || fail "$file lacks: $expected"
}

source_manager() {
    LSEC_SOURCE_ONLY=1 source "$TEST_ROOT/linux_security.sh"
}
