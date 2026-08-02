# SSH Port Migration UFW Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make SSH migration completion idempotently remove its old logical UFW rule and accurately roll back/report failures.

**Architecture:** Add SSH-specific UFW inspection/deletion helpers that distinguish persistent logical rules from IPv4/IPv6 runtime display rows. Keep the existing SSH file backups, but centralize finish rollback and return stable transaction result codes.

**Tech Stack:** Bash, UFW CLI, existing shell test harness.

---

### Task 1: Add failing UFW cleanup regression tests

**Files:**
- Modify: `tests/linux_security_transaction_test.sh`
- Test: `tests/linux_security_transaction_test.sh`

- [ ] Add fixtures where one persistent SSH rule produces two numbered IPv4/IPv6 rows.
- [ ] Assert deleting the old logical rule succeeds and leaves a different-comment rule untouched.
- [ ] Assert an already absent old marker succeeds.
- [ ] Run `bash tests/linux_security_transaction_test.sh` and verify failure against the current exact-one numbered-line implementation.

### Task 2: Implement idempotent SSH logical-rule cleanup

**Files:**
- Modify: `linux_security.sh:1952-1975`
- Test: `tests/linux_security_transaction_test.sh`

- [ ] Change the SSH deletion helper to accept port and marker.
- [ ] Read the persistent marker count; return success for zero and reject ambiguous duplicate logical definitions.
- [ ] Delete with `ufw --force delete allow in proto tcp from any to any port "$port" comment "$marker"`.
- [ ] Verify both persistent and numbered exact-marker views contain no residual rule.
- [ ] Run the focused transaction test and verify it passes.

### Task 3: Add failing finish rollback/result tests

**Files:**
- Modify: `tests/linux_security_self_test.sh`
- Test: `tests/linux_security_self_test.sh`

- [ ] Build a temporary migration state and SSH port configuration fixture.
- [ ] Force UFW cleanup failure after the new-only SSH runtime has been applied.
- [ ] Assert the old/new SSH configuration is restored, migration state remains, and result is `RESULT_APPLY_FAILED_ROLLED_BACK`.
- [ ] Run `bash tests/linux_security_self_test.sh` and verify the test fails because current code returns generic status 1 without rollback.

### Task 4: Implement verified finish rollback and precise results

**Files:**
- Modify: `linux_security.sh:2097-2184`
- Test: `tests/linux_security_self_test.sh`

- [ ] Add a finish rollback helper that restores every changed SSH file and reloads the old/new listener set.
- [ ] Return `RESULT_PRECHECK_FAILED` only before mutation.
- [ ] Return `RESULT_APPLY_FAILED_ROLLED_BACK` after a verified rollback and `RESULT_ROLLBACK_FAILED` when restoration cannot be verified.
- [ ] Keep migration state until all SSH and UFW steps succeed.
- [ ] Run the focused self-test and verify it passes.

### Task 5: Full verification

**Files:**
- Verify: `linux_security.sh`
- Verify: `tests/linux_security_self_test.sh`
- Verify: `tests/linux_security_transaction_test.sh`

- [ ] Run `bash -n linux_security.sh tests/linux_security_self_test.sh tests/linux_security_transaction_test.sh`.
- [ ] Run `bash tests/run_all.sh` and require both suites to pass.
- [ ] Inspect `git diff --check` and the scoped diff.
- [ ] Do not commit or push unless the user explicitly requests it.
