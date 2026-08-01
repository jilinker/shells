#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bash "$ROOT_DIR/tests/linux_security_self_test.sh"
bash "$ROOT_DIR/tests/linux_security_transaction_test.sh"
