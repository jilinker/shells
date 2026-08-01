# Linux Security Manager Transaction Safety Implementation Plan

> **Execution requirement:** Use `superpowers:executing-plans` for inline execution, or `superpowers:subagent-driven-development` when the user selects delegated execution. Implement one task at a time and run each stated verification before committing.

**Goal:** Make every mutation in `linux_security.sh` serialized, transactional, recoverable, and honestly reported, while keeping the script a generic standalone Linux security manager.

**Architecture:** Add a result-code and transaction layer inside the existing single-file runtime. Forwarding changes stage exact-ID NAT, UFW route, state, and IPv4-forwarding updates under a global lock; journals and snapshots drive verified rollback or recovery. Existing interactive menus call this layer but remain independent of Xboard, Hysteria2, and VLESS.

**Implementation language:** Bash 4+, UFW, iptables/iptables-restore, flock, sysctl; shell test harness with command shims.

**Design source:** `docs/superpowers/specs/2026-08-01-linux-security-transaction-safety-design.md`

---

## Task 1: Establish the test harness and explicit outcomes

**Files:**

- Create: `tests/testlib.sh`
- Create: `tests/linux_security_transaction_test.sh`
- Create: `tests/run_all.sh`
- Modify: `tests/linux_security_self_test.sh`
- Modify: `linux_security.sh`

### Step 1: Write failing tests for stable result codes

Create a test helper that sources the script without opening the menu and supplies assertions:

```bash
#!/usr/bin/env bash
set -Eeuo pipefail

TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() { printf 'not ok - %s\n' "$*" >&2; exit 1; }
assert_eq() { [[ "$1" == "$2" ]] || fail "expected [$2], got [$1]"; }
assert_file_contains() { grep -Fq -- "$2" "$1" || fail "$1 lacks: $2"; }

source_manager() {
    LSEC_SOURCE_ONLY=1 source "$TEST_ROOT/linux_security.sh"
}
```

In `tests/linux_security_transaction_test.sh`, assert the public constants and messages:

```bash
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
```

Add `tests/run_all.sh`:

```bash
#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bash "$ROOT_DIR/tests/linux_security_self_test.sh"
bash "$ROOT_DIR/tests/linux_security_transaction_test.sh"
```

Run: `bash tests/linux_security_transaction_test.sh`

Expected: FAIL because the constants and source-only entry point do not exist.

### Step 2: Add the result model and source-only guard

Near the top of `linux_security.sh`, define readonly constants:

```bash
readonly RESULT_OK=0
readonly RESULT_CANCELLED=10
readonly RESULT_PRECHECK_FAILED=20
readonly RESULT_APPLY_FAILED_ROLLED_BACK=30
readonly RESULT_ROLLBACK_FAILED=40
readonly RESULT_VERIFY_FAILED_ROLLED_BACK=50
readonly RESULT_PROTECTED_LOCKOUT=60
readonly RESULT_REPAIR_REQUIRED=70

result_message() {
    case "$1" in
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
```

Wrap the existing main entry call:

```bash
if [[ "${LSEC_SOURCE_ONLY:-0}" != "1" ]]; then
    main "$@"
fi
```

Update the legacy self-test to source with `LSEC_SOURCE_ONLY=1`.

Run: `bash tests/run_all.sh`

Expected: PASS.

### Step 3: Commit

```bash
git add linux_security.sh tests/testlib.sh tests/linux_security_transaction_test.sh tests/linux_security_self_test.sh tests/run_all.sh
git commit -m "test: establish security manager result contract"
```

## Task 2: Add the global mutation and protected-lock guards

**Files:**

- Modify: `linux_security.sh`
- Modify: `tests/linux_security_transaction_test.sh`

### Step 1: Write failing lock tests

Use a temporary state directory and a second shell holding `flock`. Test:

- `begin_mutation "创建转发"` succeeds when unlocked;
- a concurrent begin returns `RESULT_PRECHECK_FAILED` and does not kill the owner;
- the lock metadata contains PID, start time, and operation;
- `require_mutation_allowed` returns `RESULT_PROTECTED_LOCKOUT` when `protected.lock` exists;
- readonly `show_forwarding_status` remains callable while protected.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: FAIL because the coordinator functions do not exist.

### Step 2: Implement lock acquisition and release

Define overridable paths for testing and a single descriptor:

```bash
STATE_DIR="${LSEC_STATE_DIR:-/etc/ufw/relay-manager}"
OPERATION_LOCK="$STATE_DIR/operation.lock"
PROTECTED_LOCK="$STATE_DIR/protected.lock"
MUTATION_LOCK_FD=9

begin_mutation() {
    local operation=$1
    mkdir -p -m 0700 "$STATE_DIR" || return "$RESULT_PRECHECK_FAILED"
    eval "exec ${MUTATION_LOCK_FD}>\"$OPERATION_LOCK\"" || return "$RESULT_PRECHECK_FAILED"
    flock -n "$MUTATION_LOCK_FD" || return "$RESULT_PRECHECK_FAILED"
    printf 'pid\t%s\nstarted_at\t%s\noperation\t%s\n' \
        "$$" "$(date -u +%FT%TZ)" "$operation" >"$OPERATION_LOCK"
}

end_mutation() {
    : >"$OPERATION_LOCK"
    flock -u "$MUTATION_LOCK_FD"
}

require_mutation_allowed() {
    [[ ! -s "$PROTECTED_LOCK" ]] || return "$RESULT_PROTECTED_LOCKOUT"
}
```

Install `trap 'end_mutation_if_held' EXIT INT TERM HUP` without replacing existing cleanup behavior. All mutation menu entries must eventually call the coordinator; readonly entries must not acquire the lock.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: PASS.

### Step 3: Commit

```bash
git add linux_security.sh tests/linux_security_transaction_test.sh
git commit -m "feat: serialize security manager mutations"
```

## Task 3: Add atomic storage, snapshots, and journals

**Files:**

- Modify: `linux_security.sh`
- Modify: `tests/linux_security_transaction_test.sh`

### Step 1: Write failing persistence tests

Test `atomic_write`, `begin_transaction`, and `set_transaction_phase` using temporary files. Verify:

- the destination is never partially written when the writer fails;
- permissions are `0600` for journals and state;
- snapshots contain `before.rules`, `forwarding.tsv`, `metadata.tsv`, and `ip-forwarding.tsv`;
- phases advance through `prepared`, `applying_nat`, `applying_ufw`, `committing_state`, and `verifying`;
- a journal is never marked `committed` before live verification.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: FAIL.

### Step 2: Implement durable file primitives

Use same-directory temporary files and rename:

```bash
atomic_write() {
    local destination=$1 writer=$2 temp
    temp="$(mktemp "${destination}.tmp.XXXXXX")" || return 1
    chmod 0600 "$temp" || { rm -f -- "$temp"; return 1; }
    if "$writer" >"$temp"; then
        mv -f -- "$temp" "$destination"
    else
        rm -f -- "$temp"
        return 1
    fi
}
```

Add `new_batch_id`, `snapshot_current_state`, `begin_transaction`, `set_transaction_phase`, and `finish_transaction`. Journal fields are tab-separated and include schema, batch ID, operation, phase, timestamps, snapshot path, intended rule IDs, and last error. Write `state.version` separately from row data.

Never remove a transaction or failed snapshot. A committed transaction may be retained for cleanup policy processing.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: PASS.

### Step 3: Commit

```bash
git add linux_security.sh tests/linux_security_transaction_test.sh
git commit -m "feat: add durable transaction journals"
```

## Task 4: Make input and managed-rule identity strict

**Files:**

- Modify: `linux_security.sh`
- Modify: `tests/linux_security_self_test.sh`
- Modify: `tests/linux_security_transaction_test.sh`

### Step 1: Add strict validation cases

Extend tests so these are rejected: `80,`, `,80`, `80,,81`, `80::90`, `80:90,`, `0`, `65536`, reversed ranges, whitespace, shell metacharacters, invalid IPv4/IPv6 addresses, invalid interfaces, and duplicate exact rule IDs. Valid examples include `80`, `80,443`, and `10000:10100`.

Test that an exact managed marker has this form and is identical in NAT, UFW comment, and state:

```text
lsec:<batch-id>:<rule-id>
```

Run: `bash tests/run_all.sh`

Expected: FAIL for trailing separators and identity helpers.

### Step 2: Replace permissive parsing

Parse a comma-separated port specification one token at a time, reject empty tokens, and normalize each token before any mutation. Add:

```bash
managed_marker() { printf 'lsec:%s:%s' "$1" "$2"; }
validate_managed_marker() {
    [[ "$1" =~ ^lsec:[A-Za-z0-9._-]+:[A-Za-z0-9._-]+$ ]]
}
```

Make the rendered NAT block use exact begin/end markers, and make UFW route rules carry the same marker in their comment. State rows include the full marker as the primary identifier; deletes accept only an exact selected identifier.

Run: `bash tests/run_all.sh`

Expected: PASS.

### Step 3: Commit

```bash
git add linux_security.sh tests/linux_security_self_test.sh tests/linux_security_transaction_test.sh
git commit -m "fix: enforce strict forwarding identities and inputs"
```

## Task 5: Add dependency repair and a no-mutation preview

**Files:**

- Modify: `linux_security.sh`
- Modify: `tests/linux_security_transaction_test.sh`

### Step 1: Write failing preflight tests

Shim `command`, package managers, and privileged commands. Verify:

- missing `flock`, `ufw`, `iptables`, `iptables-restore`, or `sysctl` produces an explicit list;
- the user can choose install or cancel;
- cancellation returns `RESULT_CANCELLED` with no mutations;
- accepted installation runs under the global lock, then restarts the entire preflight;
- unsupported distributions return `RESULT_PRECHECK_FAILED` with manual package guidance;
- preflight-only mode prints proposed NAT, UFW, state, and IPv4-forwarding changes without writing them.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: FAIL.

### Step 2: Implement repairable preflight

Add `collect_missing_dependencies`, `offer_dependency_install`, and `run_mutation_preflight`. The caller loops only after a successful install:

```bash
while ! collect_missing_dependencies; do
    print_missing_dependencies
    confirm_dependency_install || return "$RESULT_CANCELLED"
    install_missing_dependencies || return "$RESULT_PRECHECK_FAILED"
done
```

Add `render_execution_preview` with sections for requested rules, exact markers, files, commands, rollback scope, and success limitations. The final prompt offers:

1. execute;
2. run preflight only;
3. cancel.

Preflight-only completes all validation and staging validation but performs no system mutation.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: PASS.

### Step 3: Commit

```bash
git add linux_security.sh tests/linux_security_transaction_test.sh
git commit -m "feat: add repairable preflight and execution preview"
```

## Task 6: Implement atomic forwarding creation

**Files:**

- Modify: `linux_security.sh`
- Modify: `tests/linux_security_transaction_test.sh`

### Step 1: Build failure-injection tests

Create shims recording invocations for `iptables-restore`, `ufw`, and `sysctl`. For a confirmed TCP+UDP request, inject failure at each boundary:

- NAT staging validation;
- live NAT apply;
- first or second UFW route add;
- atomic state commit;
- live verification.

After every injected failure assert either:

- NAT, UFW, state, and IPv4 forwarding exactly equal the snapshot; or
- `protected.lock` exists and subsequent mutations return `RESULT_PROTECTED_LOCKOUT`.

Also assert cancellation and preflight failure leave all four layers untouched.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: FAIL because creation is not coordinated.

### Step 2: Add staged NAT validation

Render the complete proposed `before.rules` to the snapshot directory. Validate syntax before the confirmation with:

```bash
validate_staged_nat() {
    local staged=$1
    iptables-restore --test <"$staged"
}
```

If the installed implementation does not support `--test`, detect that in preflight and clearly offer installation/upgrade guidance; do not fall back to applying unvalidated content.

### Step 3: Implement the create state machine

Add `create_forwarding_batch` with this exact order:

1. acquire global lock and reject protected state;
2. run dependency, migration, ambiguity, and input preflight;
3. create the full preview and obtain the final user choice;
4. create journal and snapshot;
5. enable IPv4 forwarding if needed and record ownership;
6. apply the full staged NAT file;
7. add every UFW route rule, recording each successful exact marker;
8. atomically write the complete new `forwarding.tsv`;
9. verify all effective layers;
10. mark committed and report `RESULT_OK`.

The operation must not call `ensure_ipv4_forwarding` before step 3.

### Step 4: Implement verified rollback

`rollback_transaction` restores the saved NAT file, removes only UFW rules recorded by the journal, restores state, and restores IPv4 settings only when owned by this transaction. Then `verify_snapshot_restored` rereads every layer.

Return `RESULT_APPLY_FAILED_ROLLED_BACK` or `RESULT_VERIFY_FAILED_ROLLED_BACK` only after verified restoration. Otherwise write `protected.lock` atomically and return `RESULT_ROLLBACK_FAILED`.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: PASS for all failure injection points.

### Step 5: Commit

```bash
git add linux_security.sh tests/linux_security_transaction_test.sh
git commit -m "feat: make forwarding creation transactional"
```

## Task 7: Make deletion and explicit overwrite transactional

**Files:**

- Modify: `linux_security.sh`
- Modify: `tests/linux_security_transaction_test.sh`

### Step 1: Write delete and collision tests

Test that deleting a selected managed rule is atomic across NAT, UFW route, state, and IPv4 lifecycle. Inject failures at each layer and require verified restoration or protected lockout.

For same-parameter collisions, test these paths:

- cancel preserves every existing rule;
- selecting overwrite without selecting exact old rules is rejected;
- the preview lists every exact selected old rule and the replacement marker;
- confirmed overwrite deletes only the selected old rules and recreates the same requested behavior as one transaction;
- any failure restores both old rules and state.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: FAIL.

### Step 2: Implement exact managed deletion

Replace positional/substring deletion with selection by exact marker. `delete_forwarding_batch` uses the same coordinator and snapshot/verify/rollback flow as creation. Remove all existing `|| true` handling from UFW route deletion; every failure is a transaction failure.

### Step 3: Implement explicit adoption by replacement

Add `find_parameter_collisions` and `select_collision_rules`. Unknown or unmanaged rules are never silently adopted. When the user explicitly selects old same-parameter rules and confirms overwrite, record their full definitions in the journal, delete them, and create a new exact managed rule inside one batch.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: PASS.

### Step 4: Commit

```bash
git add linux_security.sh tests/linux_security_transaction_test.sh
git commit -m "feat: transact forwarding deletion and overwrite"
```

## Task 8: Track IPv4-forwarding ownership and protect UFW enablement

**Files:**

- Modify: `linux_security.sh`
- Modify: `tests/linux_security_transaction_test.sh`

### Step 1: Write IPv4 lifecycle tests

Verify:

- creating the first forward records whether this script changed runtime or persistent forwarding;
- creating later forwards does not claim ownership of pre-existing settings;
- deleting a non-final rule never disables forwarding;
- deleting the final rule offers restoration only when the script owns the change;
- restoration defaults to “no” and is blocked if other forwarding use is detected.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: FAIL.

### Step 2: Implement ownership records and conservative restore

Store original runtime value, persistent file/value, ownership flag, and transaction ID in `ip-forwarding.tsv`. Add `detect_other_forwarding_use` to inspect active managed state and non-managed NAT forwarding before offering restoration. Restoration participates in the delete transaction and is verified.

### Step 3: Write safe-UFW-enable tests

Simulate SSH discovery from `SSH_CONNECTION`, `sshd -T`, listening sockets, and service configuration. Verify:

- reliable detection adds and verifies SSH allow rules before `ufw enable`;
- ambiguous detection blocks automatic enablement;
- ambiguous users may cancel or type the displayed high-risk confirmation phrase exactly;
- any allow/default/enable/reload/verification failure returns a non-success result and restores the snapshot when possible.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: FAIL against the current `setup_and_enable_ufw` path.

### Step 4: Replace unsafe enablement flow

Make UFW bootstrap a global transaction. Never call it through `|| true`. Detect SSH endpoints, preview defaults and rules, add and verify access first, enable UFW, reload, then verify status and expected rules. When detection is ambiguous, require the literal phrase shown to the user and include the candidate ports in the prompt.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: PASS.

### Step 5: Commit

```bash
git add linux_security.sh tests/linux_security_transaction_test.sh
git commit -m "fix: protect forwarding lifecycle and UFW enablement"
```

## Task 9: Recover interrupted work and migrate legacy state

**Files:**

- Modify: `linux_security.sh`
- Modify: `tests/linux_security_transaction_test.sh`

### Step 1: Write startup recovery tests

Create journals stopped at every nonterminal phase. Verify startup:

- detects the incomplete operation before showing mutation menus;
- automatically rolls back when the journal and snapshots are complete;
- verifies recovery before clearing protected state;
- enters protected lockout when recovery cannot be verified;
- still permits status, diagnostics, journal inspection, backup listing, and restore preview.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: FAIL.

### Step 2: Implement deterministic recovery

Add `scan_incomplete_transactions` and `recover_transaction`. Recovery is driven only by the recorded phase and artifacts, never by guessing user intent. Write recovery attempts and results back to the journal atomically. Clear `protected.lock` only after `verify_consistent_state` succeeds.

### Step 3: Write legacy audit and migration tests

Fixture legacy state rows and NAT/UFW combinations for:

- exact unambiguous matches;
- malformed rows;
- missing NAT or UFW layers;
- duplicate/same-parameter rules;
- unmanaged rules.

Assert no mutation operation proceeds until audit finishes. Unambiguous records can be previewed and migrated; ambiguous records require explicit selection or remain unmanaged.

### Step 4: Implement schema migration

When `state.version` is absent or old, run a readonly audit first. Present migration, manual reconciliation, export diagnostics, and cancel options. A migration itself is a journaled global transaction with snapshot and rollback. Never rewrite an ambiguous row automatically.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: PASS.

### Step 5: Commit

```bash
git add linux_security.sh tests/linux_security_transaction_test.sh
git commit -m "feat: recover transactions and migrate legacy state"
```

## Task 10: Add backup retention, restore, cleanup, and diagnostics

**Files:**

- Modify: `linux_security.sh`
- Modify: `tests/linux_security_transaction_test.sh`

### Step 1: Write backup policy tests

Create dated fixtures and assert:

- successful snapshots are retained for 30 days and at least the newest 20 are kept;
- active, failed, inconsistent, protected-lock-associated, and unverified snapshots are never automatically removed;
- listing is readonly and labels status, date, batch, operation, and protection association;
- cleanup requires explicit item selection and confirmation;
- restore always previews files and affected layers and runs as a new transaction;
- diagnostic export redacts no operational facts needed for recovery but uses mode `0600`.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: FAIL.

### Step 2: Implement retention classification

Add `classify_snapshot`, `list_snapshots`, and `eligible_success_snapshots_for_cleanup`. Automatic cleanup computes eligibility from both age and newest-20 protection; it never takes an arbitrary directory supplied by the user.

### Step 3: Implement explicit maintenance actions

Add menu actions for:

- list and inspect backups;
- preview and restore a chosen verified snapshot;
- explicitly clean selected eligible successful snapshots;
- export diagnostics;
- attempt protected-state repair and re-verification.

Restore, cleanup, and repair acquire the global lock. Use validated batch IDs and resolved paths beneath the configured backup root; reject traversal and symlink escapes.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: PASS.

### Step 4: Commit

```bash
git add linux_security.sh tests/linux_security_transaction_test.sh
git commit -m "feat: add safe backup and recovery maintenance"
```

## Task 11: Integrate result-aware menus and remove false-success paths

**Files:**

- Modify: `linux_security.sh`
- Modify: `tests/linux_security_self_test.sh`
- Modify: `tests/linux_security_transaction_test.sh`

### Step 1: Add static and interactive regression tests

Test that:

- mutation functions are never invoked through `|| true`;
- menu handlers capture the result and print `result_message`;
- success text appears only for `RESULT_OK`;
- cancellation is visually distinct from failure;
- a protected result immediately returns to readonly choices;
- application protocols are not claimed reachable after local verification;
- no Xboard, Hysteria2, VLESS, certificate, or acme.sh behavior is added.

Run: `bash tests/run_all.sh`

Expected: FAIL until all legacy handlers are converted.

### Step 2: Convert every mutation entry point

Introduce one wrapper:

```bash
run_mutation_action() {
    local operation=$1 function=$2 result
    shift 2
    begin_mutation "$operation" || { result=$?; print_result "$result"; return "$result"; }
    require_mutation_allowed || { result=$?; end_mutation; print_result "$result"; return "$result"; }
    "$function" "$@"
    result=$?
    end_mutation
    print_result "$result"
    return "$result"
}
```

Audit SSH, Fail2Ban, UFW, forwarding, lifecycle, package installation, migration, restore, and cleanup handlers. Replace ignored mutation failures with explicit checks and preserve readonly behavior during protected lockout. Ensure helper commands inside conditionals do not accidentally alter `errexit` semantics; transaction correctness must rely on returned results and verification.

Run: `bash tests/run_all.sh`

Expected: PASS.

### Step 3: Run shell analysis

Run:

```bash
bash -n linux_security.sh
bash -n tests/testlib.sh
bash -n tests/linux_security_self_test.sh
bash -n tests/linux_security_transaction_test.sh
bash -n tests/run_all.sh
shellcheck linux_security.sh tests/*.sh
```

Expected: all commands exit 0. If ShellCheck is unavailable, install it through the dependency prompt for the development environment or document that single verification gap before proceeding.

### Step 4: Commit

```bash
git add linux_security.sh tests/testlib.sh tests/linux_security_self_test.sh tests/linux_security_transaction_test.sh tests/run_all.sh
git commit -m "refactor: report security mutations accurately"
```

## Task 12: Document operations and perform final verification

**Files:**

- Modify: `README.md`
- Modify: `docs/README.md`
- Create: `docs/forwarding-transaction-recovery.md`
- Modify: `tests/linux_security_transaction_test.sh`

### Step 1: Add a documentation contract test

Assert the documentation contains:

- the relay/landing TCP and UDP model;
- a HY2/VLESS example clearly labeled as a generic port example only;
- landing-host source restriction guidance;
- atomic batch, rollback, and protected-lock semantics;
- dependency install/cancel, collision cancel/overwrite, and preflight-only choices;
- IPv4 restoration safeguards;
- backup list/restore/cleanup and legacy migration instructions;
- the boundary that local checks do not prove end-to-end application reachability.

Run: `bash tests/linux_security_transaction_test.sh`

Expected: FAIL before documentation changes.

### Step 2: Write operator documentation

Update the README entry points and add `docs/forwarding-transaction-recovery.md` with exact menu flows, state paths, result meanings, recovery choices, and worked examples. Explain that a relay DNAT+MASQUERADE setup causes the landing server to see the relay IP, so landing UFW rules can restrict UDP 52350 and TCP 52351 to that relay. Keep all protocol names outside runtime logic.

Run: `bash tests/run_all.sh`

Expected: PASS.

### Step 3: Run clean final verification

Run from the repository root:

```bash
bash -n linux_security.sh
bash tests/run_all.sh
shellcheck linux_security.sh tests/*.sh
git diff --check
git status --short
```

Expected: syntax, tests, ShellCheck, and whitespace checks pass; status lists only intended documentation/code/test changes before the final commit.

### Step 4: Request code review and resolve findings

Use `superpowers:requesting-code-review` against the design and this plan. Review transaction ordering, rollback verification, protected lockout, shell failure semantics, exact ownership, path safety, and test coverage. Apply accepted findings and rerun Step 3.

### Step 5: Commit

```bash
git add README.md docs/README.md docs/forwarding-transaction-recovery.md tests/linux_security_transaction_test.sh
git commit -m "docs: explain transactional forwarding recovery"
```

## Completion criteria

Implementation is complete only when:

- every mutation is serialized by the global lock;
- confirmed batch creation, deletion, and overwrite are all-or-nothing;
- rollback is verified or protected lockout prevents further mutations;
- startup recovery and legacy migration are tested;
- dependency repair always reruns preflight;
- IPv4 forwarding and UFW enablement cannot silently lock out or misreport success;
- backups obey the 30-day/newest-20 rule and protected artifacts are preserved;
- all automated checks in Task 12 pass;
- documentation makes the local-verification boundary explicit.
