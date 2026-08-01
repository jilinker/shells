# Managed NAT Semantic Comparison Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent valid UFW/iptables parameter reordering from causing forwarding transactions to roll back while continuing to reject real rule drift.

**Architecture:** Add a strict AWK-backed canonicalizer for the small DNAT/MASQUERADE grammar owned by `lsec`. `verify_nat_file_effective` will compare canonical fields per chain while preserving the original rule order within each chain; deletion continues to use the near-original `iptables-save` text.

**Tech Stack:** Bash 4+, AWK, sed, iptables-save fixtures, existing shell test harness.

---

### Task 1: Reproduce real iptables-save reordering

**Files:**
- Modify: `tests/linux_security_transaction_test.sh`

- [ ] **Step 1: Add a failing regression test**

After the existing `verify_nat_file_effective` formatting tests, temporarily redefine `iptables-save` so both DNAT and SNAT options are reordered in the form observed on Linux:

```bash
iptables-save() {
    normalize_iptables_rule_for_delete < "$LIVE_NAT_FILE" | sed -E \
        -e 's/^-A PREROUTING -i ([^ ]+) -p (tcp|udp) --dport ([^ ]+) -m comment --comment ([^ ]+) -j DNAT --to-destination ([^ ]+)$/-A PREROUTING -p \2 -m \2 -i \1 -m comment --comment "\4" --dport \3 -j DNAT --to-destination \5/' \
        -e 's/^-A POSTROUTING -o ([^ ]+) -p (tcp|udp) -d ([^ ]+) --dport ([^ ]+) -m comment --comment ([^ ]+) -j MASQUERADE$/-A POSTROUTING -d \3\/32 -o \1 -p \2 -m \2 --dport \4 -m comment --comment "\5" -j MASQUERADE/'
}
assert_status 0 verify_nat_file_effective "$BEFORE_RULES"
iptables-save() { awk '/^-A (PREROUTING|POSTROUTING) / {print}' "$LIVE_NAT_FILE"; }
```

- [ ] **Step 2: Run the transaction test and confirm RED**

Run:

```bash
bash tests/linux_security_transaction_test.sh
```

Expected: FAIL at the new assertion because the current whole-line comparison returns status 1 instead of 0.

- [ ] **Step 3: Commit the regression test**

```bash
git add tests/linux_security_transaction_test.sh
git commit -m "test: reproduce iptables NAT option reordering"
```

### Task 2: Canonicalize strictly owned NAT rule fields

**Files:**
- Modify: `linux_security.sh` near `managed_nat_rules_for_chain`
- Test: `tests/linux_security_transaction_test.sh`

- [ ] **Step 1: Add the strict canonicalizer**

Add `canonicalize_managed_nat_rules` after `managed_nat_rules_for_chain`. Its AWK scanner must:

```bash
canonicalize_managed_nat_rules() {
    normalize_iptables_rule_for_delete | awk '
        function fail() { invalid=1 }
        function set_value(name, value) {
            if (seen[name]++) { fail(); return }
            field[name]=value
        }
        function host_address(value) {
            sub(/\/32$/, "", value)
            return value
        }
        {
            for (name in seen) delete seen[name]
            for (name in field) delete field[name]
            for (name in module) delete module[name]
            invalid=0
            if ($1 != "-A" || ($2 != "PREROUTING" && $2 != "POSTROUTING")) fail()
            for (i=3; i<=NF && !invalid; i++) {
                token=$i
                if (token == "-p") set_value("proto", $(++i))
                else if (token == "-s") set_value("source", $(++i))
                else if (token == "-d") set_value("destination", $(++i))
                else if (token == "-i") set_value("input", $(++i))
                else if (token == "-o") set_value("output", $(++i))
                else if (token == "--dport") set_value("dport", $(++i))
                else if (token == "--comment") set_value("comment", $(++i))
                else if (token == "-j") set_value("jump", $(++i))
                else if (token == "--to-destination") set_value("translated", $(++i))
                else if (token == "-m") {
                    value=$(++i)
                    if (value !~ /^(tcp|udp|comment)$/ || module[value]++) fail()
                } else fail()
                if (i > NF || $(i) == "") fail()
            }
            source=("source" in field) ? host_address(field["source"]) : "any"
            destination=("destination" in field) ? host_address(field["destination"]) : "-"
            input=("input" in field) ? field["input"] : "-"
            output=("output" in field) ? field["output"] : "-"
            translated=("translated" in field) ? field["translated"] : "-"
            if (field["proto"] !~ /^(tcp|udp)$/ || field["dport"] !~ /^[0-9]+$/) fail()
            if (field["comment"] !~ /^(lsec:[A-Za-z0-9._-]+:[A-Za-z0-9._-]+|ufw-relay:[A-Za-z0-9._-]+):(dnat|snat)$/) fail()
            if ($2 == "PREROUTING" && (input == "-" || output != "-" || destination != "-" || field["jump"] != "DNAT" || translated == "-" || field["comment"] !~ /:dnat$/)) fail()
            if ($2 == "POSTROUTING" && (input != "-" || output == "-" || destination == "-" || source != "any" || field["jump"] != "MASQUERADE" || translated != "-" || field["comment"] !~ /:snat$/)) fail()
            if (invalid) exit 1
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", $2, field["proto"], source, input, output, destination, field["dport"], field["comment"], field["jump"], translated
        }
    '
}
```

The implementation may format the AWK for readability, but must retain the exact whitelist and failure semantics.

- [ ] **Step 2: Integrate canonical fields into live/file verification**

Update `verify_nat_file_effective` so each side uses deletion-only text normalization, strict marker filtering, and canonicalization:

```bash
expected=$(normalize_iptables_rule_for_delete < "$expected_file" \
    | managed_nat_rules_for_chain "$chain" \
    | canonicalize_managed_nat_rules) || return 1
live=$(managed_nat_rules_for_chain "$chain" <<< "$live_dump" \
    | canonicalize_managed_nat_rules) || return 1
```

Capture `live_dump` with `normalize_iptables_rule_for_delete`. Do not sort either result.

- [ ] **Step 3: Run the regression test and confirm GREEN**

Run:

```bash
bash tests/linux_security_transaction_test.sh
```

Expected: `linux security transaction test passed`.

- [ ] **Step 4: Commit the implementation**

```bash
git add linux_security.sh
git commit -m "fix: compare managed NAT rules semantically"
```

### Task 3: Prove strict mismatch handling

**Files:**
- Modify: `tests/linux_security_transaction_test.sh`

- [ ] **Step 1: Add parser rejection and drift tests**

Add assertions using one valid managed rule fixture and mutations of it:

```bash
valid_snat='-A POSTROUTING -d 10.0.0.2/32 -o eth1 -p tcp -m tcp --dport 52350 -m comment --comment "lsec:strict:tcp:snat" -j MASQUERADE'
assert_status 0 canonicalize_managed_nat_rules <<< "$valid_snat"
assert_status 1 canonicalize_managed_nat_rules <<< "${valid_snat/--dport 52350/--dport 52350 --sport 40000}"
assert_status 1 canonicalize_managed_nat_rules <<< "${valid_snat/-o eth1/-o eth1 -o eth2}"
assert_status 1 canonicalize_managed_nat_rules <<< "${valid_snat/-j MASQUERADE/-j ACCEPT}"
```

Also redefine `iptables-save` once per semantic drift so `verify_nat_file_effective` rejects a changed output interface, port, translated destination, or jump action. Retain the existing same-chain reversal assertion.

- [ ] **Step 2: Run the focused tests**

Run:

```bash
bash tests/linux_security_transaction_test.sh
```

Expected: `linux security transaction test passed`.

- [ ] **Step 3: Commit strictness tests**

```bash
git add tests/linux_security_transaction_test.sh
git commit -m "test: enforce strict managed NAT semantics"
```

### Task 4: Release and full verification

**Files:**
- Modify: `linux_security.sh:10`
- Modify: `tests/linux_security_self_test.sh:17`
- Modify: `docs/forwarding-transaction-recovery.md`

- [ ] **Step 1: Bump the expected release test to 4.0.2 and confirm RED**

Change the self-test expectation to:

```bash
grep -Fq 'VERSION="4.0.2"' "$ROOT_DIR/linux_security.sh"
```

Run `bash tests/linux_security_self_test.sh` and expect failure while production still reports `4.0.1`.

- [ ] **Step 2: Bump production version and document semantic verification**

Set:

```bash
VERSION="4.0.2"
```

Document that managed NAT verification tolerates backend formatting and option-order differences but rejects semantic field drift and same-chain reordering.

- [ ] **Step 3: Run all verification commands**

```bash
bash -n linux_security.sh tests/*.sh
bash tests/run_all.sh
git diff --check
LSEC_SOURCE_ONLY=1 bash -c 'source ./linux_security.sh; test "$VERSION" = 4.0.2'
```

Expected: both test suites pass, syntax and whitespace checks produce no output, and the version assertion exits 0.

- [ ] **Step 4: Request code review, then commit and push**

After review reports no unresolved findings:

```bash
git add linux_security.sh tests/linux_security_self_test.sh tests/linux_security_transaction_test.sh docs/forwarding-transaction-recovery.md
git commit -m "fix: tolerate iptables NAT option reordering"
git push origin main
```

Expected: `main` advances on `origin`; `.idea/` remains untracked and untouched.
