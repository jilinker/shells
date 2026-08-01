# Forwarding Verification Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace fragile UFW route string comparison with strict semantic verification and preserve actionable failure evidence across successful or failed transaction rollback.

**Architecture:** Introduce a current-shell verification failure context, persist its first root cause in transaction schema 3, and keep rollback outcome separate. Reuse strict field canonicalizers for NAT and UFW while capturing transient system state before rollback; all transaction types report through one diagnostic renderer.

**Tech Stack:** Bash 4+, POSIX AWK/sed, UFW, iptables-save, sysctl, existing atomic TSV journal and shell test harness.

---

### Task 1: Transaction schema 3 and failure context

**Files:**
- Modify: `linux_security.sh` near constants and transaction journal helpers
- Modify: `tests/linux_security_transaction_test.sh`

- [ ] **Step 1: Add failing tests for structured failure state**

Add tests that call the planned helpers before they exist:

```bash
clear_verification_failure
set_verification_failure verify_ufw_persistent UFW_ROUTE_MISSING tcp \
    lsec:failure:tcp 'UFW 持久化路由缺失' \
    'in=eth0 out=eth1 proto=tcp source=any dst=10.0.0.2 port=52350' 'count=0'
assert_eq "$VERIFY_FAILURE_CODE" UFW_ROUTE_MISSING
assert_eq "$VERIFY_FAILURE_PROTOCOL" tcp

begin_transaction failure-journal create tcp
record_transaction_failure failure-journal
set_transaction_phase failure-journal rolled_back
assert_file_contains "$TRANSACTION_DIR/failure-journal.txn" $'schema\t3'
assert_file_contains "$TRANSACTION_DIR/failure-journal.txn" $'failure_code\tUFW_ROUTE_MISSING'
assert_file_contains "$TRANSACTION_DIR/failure-journal.txn" $'rollback_status\t'
set_transaction_rollback_result failure-journal verified ''
assert_file_contains "$TRANSACTION_DIR/failure-journal.txn" $'rollback_status\tverified'
assert_file_contains "$TRANSACTION_DIR/failure-journal.txn" $'failure_code\tUFW_ROUTE_MISSING'
```

Also write a value containing tabs/newlines and assert the journal remains one TSV row per key. Create a schema 2 fixture without new fields and assert `transaction_value` plus `recover_transaction` can still read it.

- [ ] **Step 2: Run the focused test and verify RED**

```bash
bash tests/linux_security_transaction_test.sh
```

Expected: failure because `clear_verification_failure` is undefined.

- [ ] **Step 3: Implement current-shell failure context**

Add globals initialized to empty:

```bash
VERIFY_FAILURE_STAGE=
VERIFY_FAILURE_CODE=
VERIFY_FAILURE_PROTOCOL=
VERIFY_FAILURE_MARKER=
VERIFY_FAILURE_SUMMARY=
VERIFY_FAILURE_EXPECTED=
VERIFY_FAILURE_ACTUAL=
VERIFY_FAILURE_AT=
```

Implement:

```bash
sanitize_tsv_value() {
    tr '\t\r\n' '   ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//'
}

clear_verification_failure() {
    VERIFY_FAILURE_STAGE=
    VERIFY_FAILURE_CODE=
    VERIFY_FAILURE_PROTOCOL=
    VERIFY_FAILURE_MARKER=
    VERIFY_FAILURE_SUMMARY=
    VERIFY_FAILURE_EXPECTED=
    VERIFY_FAILURE_ACTUAL=
    VERIFY_FAILURE_AT=
}

set_verification_failure() {
    VERIFY_FAILURE_STAGE=$(printf '%s' "$1" | sanitize_tsv_value)
    VERIFY_FAILURE_CODE=$(printf '%s' "$2" | sanitize_tsv_value)
    VERIFY_FAILURE_PROTOCOL=$(printf '%s' "$3" | sanitize_tsv_value)
    VERIFY_FAILURE_MARKER=$(printf '%s' "$4" | sanitize_tsv_value)
    VERIFY_FAILURE_SUMMARY=$(printf '%s' "$5" | sanitize_tsv_value)
    VERIFY_FAILURE_EXPECTED=$(printf '%s' "$6" | sanitize_tsv_value)
    VERIFY_FAILURE_ACTUAL=$(printf '%s' "$7" | sanitize_tsv_value)
    VERIFY_FAILURE_AT=$(date -u +%FT%TZ)
}
verification_failure_present() { [[ -n "$VERIFY_FAILURE_CODE" ]]; }
```

`set_verification_failure` must sanitize every external value and set UTC `failure_at`; it must run in the current shell, not behind a pipeline or command substitution.

- [ ] **Step 4: Upgrade only transaction journal schema**

Add:

```bash
readonly TRANSACTION_SCHEMA_VERSION=3
```

Keep `STATE_SCHEMA_VERSION=2`. `write_transaction_record` must emit all `failure_*`, `rollback_status`, `rollback_error`, and `evidence_error` keys with empty values. Add atomic renderers:

```bash
record_transaction_failure <batch>
set_transaction_rollback_result <batch> <verified|failed> <detail>
set_transaction_evidence_error <batch> <detail>
```

`record_transaction_failure` records only the first non-empty root cause. `set_transaction_phase` must preserve every structured field.

- [ ] **Step 5: Run tests and commit**

```bash
bash tests/linux_security_transaction_test.sh
git diff --check
git add linux_security.sh tests/linux_security_transaction_test.sh
git commit -m "feat: persist structured transaction failures"
```

Expected: transaction tests pass and schema 2 recovery remains green.

### Task 2: Strict UFW route semantic verification

**Files:**
- Modify: `linux_security.sh` near `normalize_ufw_added_rule` and UFW verification helpers
- Modify: `tests/linux_security_transaction_test.sh`

- [ ] **Step 1: Replace the fake UFW output with real canonical forms and confirm RED**

Change the test fake for `ufw show added` to reconstruct routes as UFW does:

```bash
printf "ufw route allow in on eth0 out on eth1 to 10.0.0.2 port 52350 proto %s comment '%s'\n" \
    "$proto" "$marker"
```

Add a fixture where `proto` appears before `to` and `from any` is explicit; both forms must normalize to the same fields. Run the transaction test and expect the current whole-string verifier to fail.

- [ ] **Step 2: Add strict parser tests**

Define expected API:

```bash
canonicalize_ufw_route_rules <<< \
  "ufw route allow in on eth0 out on eth1 to 10.0.0.2 port 52350 proto tcp comment 'lsec:batch:tcp'"
```

Expected canonical output:

```text
allow\teth0\teth1\ttcp\tany\t10.0.0.2\t52350\tlsec:batch:tcp
```

Add rejection tests for unknown clauses, duplicate `in`, missing `out`, missing `to`, missing `port`, invalid protocol, invalid marker, non-route action, and missing clause arguments.

- [ ] **Step 3: Implement the UFW canonicalizer**

Implement a portable AWK scanner that accepts only:

```text
ufw route allow
in on <interface>
out on <interface>
proto <tcp|udp>
from <IPv4/CIDR|any>
to <IPv4>
port <1-65535>
comment <legal marker>
```

Clause order may vary. Missing `from` becomes `any`. Duplicate or unknown clauses return nonzero. Quote normalization happens before AWK.

- [ ] **Step 4: Verify persistent and runtime UFW state with detailed codes**

Implement exact marker selection and semantic comparison in `verify_ufw_route_definition`:

```text
UFW_ROUTE_PARSE_FAILED
UFW_ROUTE_MISSING
UFW_ROUTE_DUPLICATE
UFW_ROUTE_SEMANTIC_MISMATCH
```

After the persistent match, count exact marker occurrences from `ufw status numbered` and report:

```text
UFW_RUNTIME_MARKER_MISSING
UFW_RUNTIME_MARKER_DUPLICATE
```

Expected/actual strings use canonical fields, not raw full command lines.

- [ ] **Step 5: Run tests and commit**

```bash
bash tests/linux_security_transaction_test.sh
git diff --check
git add linux_security.sh tests/linux_security_transaction_test.sh
git commit -m "fix: verify UFW routes semantically"
```

Expected: omitted `from any` and reordered `proto` pass; every real field drift reports its specific code.

### Task 3: Detailed NAT, IPv4, state and batch verification

**Files:**
- Modify: `linux_security.sh` verification helpers
- Modify: `tests/linux_security_transaction_test.sh`

- [ ] **Step 1: Add failing assertions for every verification layer**

Extend fixtures to cause one failure at a time and assert code, protocol, marker, expected, and actual:

```text
UFW_INACTIVE
IPV4_RUNTIME_DISABLED
IPV4_PERSISTENT_DISABLED
STATE_MARKER_MISSING
STATE_MARKER_DUPLICATE
NAT_RULE_PARSE_FAILED
NAT_PERSISTED_DNAT_MISMATCH
NAT_PERSISTED_SNAT_MISMATCH
NAT_LIVE_DNAT_MISMATCH
NAT_LIVE_SNAT_MISMATCH
```

For a TCP+UDP batch, keep TCP valid and corrupt UDP; assert `VERIFY_FAILURE_PROTOCOL=udp` and the exact UDP marker.

- [ ] **Step 2: Split IPv4 checks**

Replace the combined boolean-only check with explicit current-shell checks:

```bash
verify_ipv4_forwarding_effective() {
    local runtime persistent
    runtime=$(sysctl -n net.ipv4.ip_forward 2>/dev/null) || runtime=unknown
    [[ "$runtime" == 1 ]] || {
        set_verification_failure verify_ipv4_runtime IPV4_RUNTIME_DISABLED '' '' \
            '运行时 IPv4 forwarding 未启用' '1' "$runtime"
        return 1
    }
    persistent=$(persistent_ipv4_forwarding_value 2>/dev/null || printf unknown)
    [[ "$persistent" == 1 ]] || {
        set_verification_failure verify_ipv4_persistent IPV4_PERSISTENT_DISABLED '' '' \
            '持久化 IPv4 forwarding 未启用' '1' "$persistent"
        return 1
    }
}
```

- [ ] **Step 3: Add exact state and NAT failure reporting**

Use marker counts rather than a single boolean. Every comparison in `verify_nat_marker_effective` and `verify_nat_file_effective` must set the correct code before returning. Parser failures are distinct from semantic mismatch. Expected and actual are sanitized canonical fields.

- [ ] **Step 4: Make batch verification preserve the first failure**

`verify_forwarding_batch` clears context once at entry, verifies protocols in requested order, and returns immediately on the first detailed failure. It must not replace a child error with generic `应用后本机验证失败`.

- [ ] **Step 5: Run tests and commit**

```bash
bash tests/linux_security_transaction_test.sh
git diff --check
git add linux_security.sh tests/linux_security_transaction_test.sh
git commit -m "feat: report detailed forwarding verification failures"
```

### Task 4: Evidence capture and rollback result preservation

**Files:**
- Modify: `linux_security.sh` transaction and rollback helpers
- Modify: `tests/linux_security_transaction_test.sh`

- [ ] **Step 1: Add failing evidence tests**

Create a failed live fixture, call the planned capture helper, then mutate live files to simulate rollback. Assert the captured copies retain the pre-rollback marker and modes:

```bash
capture_transaction_failure_evidence evidence-batch
assert_file_contains "$BACKUP_DIR/evidence-batch/failure/iptables-save-nat.txt" 'lsec:evidence:tcp:dnat'
assert_eq "$(file_mode "$BACKUP_DIR/evidence-batch/failure")" 700
assert_eq "$(file_mode "$BACKUP_DIR/evidence-batch/failure/verification.tsv")" 600
```

Force one evidence command to fail and assert rollback still succeeds while `evidence_error` is non-empty.

- [ ] **Step 2: Implement best-effort evidence capture**

Create the failure directory and capture, before rollback mutation:

```text
verification.tsv
iptables-save-nat.txt
ufw-show-added.txt
ufw-status-numbered.txt
ipv4-forwarding.txt
before.rules.failed
forwarding.tsv.failed
```

Each capture uses a temporary file plus atomic rename where practical. Accumulate capture errors, record them in the journal, and always return control to the rollback path.

- [ ] **Step 3: Introduce a single pre-rollback hook**

Implement:

```bash
prepare_failed_transaction_rollback <batch>
```

It records the first structured failure and captures evidence exactly once. Call it before rollback for create, delete, overwrite, migrate, restore, and UFW bootstrap failures. Startup recovery may capture a separate `RECOVERY_OF_INCOMPLETE_TRANSACTION` context only when no original failure exists.

- [ ] **Step 4: Separate rollback status from root cause**

Every rollback function writes `rollback_status=verified` only after all restore checks pass. Before entering a protection lock, write `rollback_status=failed` with the concrete failed restore checks. Neither path may change `failure_*`.

- [ ] **Step 5: Add all-operation integration tests and commit**

Exercise create, delete, overwrite, legacy migration, explicit backup restore, and UFW bootstrap. Assert root cause, evidence, rollback result, journal terminal phase, and protected-lock behavior.

```bash
bash tests/linux_security_transaction_test.sh
git diff --check
git add linux_security.sh tests/linux_security_transaction_test.sh
git commit -m "feat: preserve failure evidence across rollback"
```

### Task 5: User diagnostics, export and 4.1.0 release

**Files:**
- Modify: `linux_security.sh` result reporting and diagnostic export
- Modify: `tests/linux_security_self_test.sh`
- Modify: `tests/linux_security_transaction_test.sh`
- Modify: `docs/forwarding-transaction-recovery.md`
- Modify: `README.md` only if the diagnostic command description needs clarification

- [ ] **Step 1: Add failing output tests**

Capture diagnostic rendering for a rolled-back transaction and assert it contains batch, localized stage, code, protocol, marker, summary, expected, actual, rollback status, and failure directory. Add a rollback-failed fixture that prints both original and rollback failures plus the protected-lock path. Empty optional values must not print blank labels.

- [ ] **Step 2: Implement journal-backed diagnostic rendering**

Implement:

```bash
render_transaction_failure_details <batch>
show_transaction_failure_details <batch>
failure_stage_label <stage>
```

The renderer reads the journal after rollback rather than relying on globals. All interactive mutation handlers retain their batch ID and print details when the result is 30, 40, or 50. Preflight failures without a journal render the current failure context.

- [ ] **Step 3: Include failure evidence in diagnostic export**

Extend `render_transaction_diagnostics` to include structured journal failure fields and the selected batch failure files with clear section labels. Missing optional evidence is reported, not treated as export failure.

- [ ] **Step 4: Bump version with RED/GREEN discipline**

Change the self-test expectation to `VERSION="4.1.0"`, run it and confirm RED, then update production version and documentation. Document semantic UFW/NAT verification, persistent root cause, rollback status, evidence directory, and schema 2 recovery compatibility.

- [ ] **Step 5: Run complete verification and independent review**

```bash
bash -n linux_security.sh tests/*.sh
bash tests/run_all.sh
git diff --check
LSEC_SOURCE_ONLY=1 bash -c 'source ./linux_security.sh; test "$VERSION" = 4.1.0'
```

Request spec-compliance and code-quality review over the entire range. Resolve every Critical or Important finding and rerun the complete commands.

- [ ] **Step 6: Commit and push**

```bash
git add linux_security.sh tests/linux_security_self_test.sh tests/linux_security_transaction_test.sh docs/forwarding-transaction-recovery.md README.md
git commit -m "feat: add structured forwarding failure diagnostics"
git push origin main
```

Expected: `main` matches `origin/main`; `.idea/` remains untracked and untouched. The server can run `lsec upgrade` and retry the TCP+UDP forwarding transaction.
