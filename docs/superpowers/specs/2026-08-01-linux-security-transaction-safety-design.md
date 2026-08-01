# Linux Security Manager Transaction Safety Design

## Goal

Make every system-changing operation in `linux_security.sh` explicit, recoverable, and verifiable, with particular emphasis on UFW enablement and complete TCP/UDP port forwarding.

The manager must report success only when the intended Linux configuration is active and its persistent state is consistent. If rollback cannot be verified, all mutation features enter a protected locked state until the inconsistency is repaired.

## Scope

This design covers:

- global serialization of UFW, SSH, Fail2Ban, lifecycle, and dependency-install mutations;
- transactional creation and deletion of complete port-forwarding rules;
- atomic TCP+UDP batch behavior;
- safe IPv4 forwarding lifecycle management;
- safe initial UFW enablement with SSH lockout prevention;
- strict validation of ports, addresses, interfaces, NAT markers, and managed rule identifiers;
- versioned state, transaction journals, snapshots, recovery, backup retention, and cleanup;
- migration of existing forwarding state and managed rules;
- failure-injection tests for mutations and rollback.

## Non-goals

- Do not add Xboard, Hysteria2, VLESS, or other application-specific concepts.
- Do not modify a remote panel or install an application protocol server.
- Do not claim that an upper-layer protocol is reachable based only on local firewall state.
- Do not provide atomic transactions across multiple Linux hosts.
- Do not automatically adopt, overwrite, or delete rules whose ownership cannot be proven.
- Do not split the installed implementation into multiple runtime scripts; `linux_security.sh` remains the standalone program installed as `lsec`.

## Design principles

1. `set -Eeuo pipefail` is a final safety net, not the transaction engine. Every external mutation command is checked explicitly.
2. A user cancellation is not an error and must produce no mutation.
3. One user confirmation creates one batch. Every rule in that batch succeeds or the entire batch is rolled back.
4. A forwarding rule is consistent only when NAT, UFW route, and committed state all agree.
5. A command return code alone is not proof. The manager rereads effective system state after apply and rollback.
6. Managed ownership is established only by an exact unique identifier present in every managed layer.
7. Unknown user rules are preserved unless the user selects an exact rule and performs a high-risk confirmation.
8. Read-only inspection remains available during a protected lockout.

## Architecture

The existing single script gains a small internal transaction layer used by all mutation modules.

### Mutation coordinator

The coordinator is responsible for:

- acquiring and releasing the global mutation lock;
- checking dependency and migration readiness;
- checking whether a protected lockout is active;
- creating a batch identifier and snapshots;
- atomically advancing the transaction phase;
- dispatching apply, verification, rollback, and recovery;
- translating internal outcomes into accurate user messages.

### Port-forwarding transaction adapter

The forwarding adapter owns:

- rendering managed DNAT and optional MASQUERADE rules;
- validating the staged `before.rules` file;
- creating and removing exact UFW route rules;
- managing IPv4 forwarding when required;
- verifying the live NAT, UFW route, kernel forwarding, and committed state;
- restoring all changed layers on failure.

### Recovery and migration manager

The recovery manager owns:

- detecting incomplete journals and state drift;
- automatically recovering operations when a reliable journal and snapshots exist;
- presenting manual reconciliation options when intent cannot be proven;
- migrating legacy `forwarding.tsv` and existing managed rules;
- maintaining the protected lockout marker.

### Backup manager

The backup manager lists, describes, restores, exports, and safely cleans snapshots according to retention and association rules.

## Persistent layout

The state directory remains `/etc/ufw/relay-manager` and becomes:

```text
/etc/ufw/relay-manager/
├── forwarding.tsv
├── state.version
├── operation.lock
├── protected.lock
├── transactions/
│   └── <batch-id>.txn
└── backups/
    └── <batch-id>/
        ├── metadata.tsv
        ├── before.rules
        ├── forwarding.tsv
        ├── ufw-added.txt
        └── ip-forwarding.tsv
```

`forwarding.tsv` contains only committed and verified rules. Pending mutations live only in the transaction journal.

`state.version` records the schema version separately so existing row-oriented parsing cannot mistake a header for a rule.

`protected.lock` records the batch, failed phase, reason, and recovery status when consistency cannot be verified.

All state and journal updates use a same-directory temporary file, restrictive mode, and atomic rename. Existing ownership and intended modes are preserved.

## Global mutation lock

All UFW, SSH, Fail2Ban, lifecycle, dependency-install, migration, restore, and cleanup mutations acquire one global exclusive `flock` lock.

Read-only status, security checks, diagnostics, and backup listing do not require the exclusive lock.

When the lock is busy, the manager displays the owner PID, start time, and operation description when available. It never kills the owner automatically. A stale lock may be cleared only after confirming that the recorded PID no longer exists.

If `flock` is unavailable, the manager offers to install `util-linux`, verifies the command after installation, reruns the complete preflight, and restarts the requested workflow from the beginning.

## Result model

Mutation functions return explicit categories:

```text
0   success
10  user cancelled with no mutation
20  input or preflight validation failed
30  dependency unavailable or installation failed
40  apply failed and rollback was verified
50  apply failed and rollback was not verified
60  pre-existing state inconsistency detected
70  global mutation lock unavailable
```

The menu reports the corresponding outcome without using `mutation || true`. Recoverable failures return to the menu. Outcomes 50 and 60 activate or preserve protected lockout and stop mutation workflows.

## Dependencies

Complete forwarding requires a usable read-only NAT syntax validator, normally `iptables-restore --test`, plus commands already needed by UFW and route inspection.

When a required component is missing, the manager shows:

- the missing command;
- the Debian or Ubuntu package to install;
- the exact command that will run;
- options to install, inspect, or cancel.

Installation is a separate locked mutation. After installation, the manager verifies capabilities and restarts the original workflow from preflight. It never resumes from a partially completed phase.

If safe syntax validation remains unavailable, complete forwarding creation and modification are disabled. Read-only inspection and only those deletion operations that can be safely verified remain available.

## Strict input validation

Port-list inputs accept comma-separated tokens only when each token exactly matches one of:

```text
^[0-9]+$
^[0-9]+:[0-9]+$
```

Every bound is validated as decimal 1 through 65535, ranges must be ascending, and the UFW element limit is enforced. Empty tokens, trailing commas, repeated colons, and extra delimiters are rejected.

Complete forwarding continues to accept one public port and one landing port per protocol rule.

Interfaces must exist. IPv4 and CIDR sources must pass strict validation. Generated rule text is derived only from validated tokens.

Managed NAT markers must appear exactly once, in the correct order, inside one NAT table. A partial, reversed, or duplicate marker set activates protected lockout rather than creating another managed section.

Insertion must prove that exactly one end marker was found. Removal must prove that exact managed identifiers were removed and unrelated lines remained unchanged.

## Execution preview and preflight-only mode

Before every high-risk mutation, the manager displays:

- the exact intended state change;
- every rule and protocol in the batch;
- IPv4 forwarding impact;
- dependency and validation results;
- snapshot paths;
- the rollback plan.

The user may execute, run the complete preflight without mutation, or cancel. No high-risk menu selection mutates the host before this confirmation.

## Forwarding create transaction

One confirmation produces one batch. Selecting TCP+UDP creates two protocol rules under one batch identifier and must be atomic.

The workflow is:

1. Acquire the global lock.
2. Reject protected lockout or incomplete legacy migration.
3. Validate dependencies, input, markers, current state, and duplicates.
4. Display the execution plan and obtain confirmation.
5. Snapshot `before.rules`, `forwarding.tsv`, UFW added rules, and IPv4 forwarding state.
6. Write an atomic `PREPARED` journal containing all intended rules and hashes.
7. Enable IPv4 forwarding only if required, after confirmation, and record whether the manager changed it.
8. Render every batch NAT rule into a staged file.
9. Run read-only syntax validation on the staged file.
10. Add every exact UFW route rule and record progress in the journal.
11. Atomically install the staged NAT file and reload UFW.
12. Verify live DNAT, optional MASQUERADE, UFW route, and kernel forwarding for every rule.
13. Atomically add all batch rows to `forwarding.tsv`.
14. Verify all three managed layers again.
15. Mark the transaction `VERIFIED` and report local configuration success.

If any step fails, rollback runs in reverse order for every rule created by the batch. A verified rollback returns result 40. An unverifiable rollback returns result 50 and creates `protected.lock`.

Existing verified rules are not included in a new batch rollback.

## Forwarding delete transaction

Deletion requires an exact managed ID in committed state, NAT, and UFW route.

Before mutation, the manager verifies expected cardinality:

- exactly one committed state row;
- exactly one DNAT rule;
- zero or one MASQUERADE rule according to the state row;
- exactly one UFW route rule.

It then snapshots all layers, writes a `DELETING` journal, removes the exact UFW route and NAT rules, validates and reloads UFW, confirms absence, and atomically removes the committed state row.

The manager never ignores route deletion failure and never discards the only state record before effective absence is proven.

## Ambiguous and unmanaged matching rules

Parameter equality does not establish ownership.

When a same-parameter UFW route lacks the managed ID, the manager offers:

1. cancel, recommended;
2. inspect the full candidate rule;
3. overwrite the explicitly selected candidate as a managed rule.

Overwrite means:

1. snapshot all affected layers;
2. require the user to enter the selected UFW number and target parameters again;
3. delete only that selected rule;
4. recreate the same behavior with a new exact managed ID;
5. verify effective behavior and commit state atomically;
6. restore the original rule if any step fails.

For deletion ambiguity, the manager offers cancel, inspect, or force-delete an explicitly selected numbered rule. Force deletion requires both the managed rule ID and UFW number as typed confirmation.

Substring comment matching is prohibited.

## IPv4 forwarding lifecycle

The manager does not enable IPv4 forwarding when the user merely enters the add workflow.

After final confirmation, it records the previous runtime value and persistent UFW sysctl content, then enables forwarding as part of the batch. A failed batch restores both when the manager changed them.

When deleting the final managed forwarding rule:

- if forwarding was already enabled before manager ownership, keep it enabled;
- if the manager originally enabled it, offer to restore the original state, defaulting to keep enabled;
- when other forwarding uses are detected, warn and prohibit automatic disablement.

## Safe initial UFW enablement

The manager discovers required SSH management ports from:

1. the current `SSH_CONNECTION` server port;
2. effective `sshd -T` ports;
3. actual SSH listeners.

It merges and validates all reliable results. It no longer silently assumes port 22 when detection fails.

If no reliable port is found, UFW enablement is blocked and the manager offers manual entry, re-detection, detailed diagnostics, or cancellation. Manual entry requires the user to retype the selected port in a high-risk confirmation.

The enable transaction snapshots the previous UFW state, adds and verifies all required rules, applies default policies, displays the final rules, asks for final confirmation, enables UFW, and verifies both active status and management-port coverage.

Any prerequisite failure prevents enablement. If UFW was initially inactive and enablement fails, the manager restores policies and batch rules. If UFW was already active, rollback removes only batch changes and never disables the firewall as a recovery shortcut.

## Recovery and protected lockout

When a reliable incomplete journal exists, recovery may automatically roll back to the saved snapshot or finish the recorded operation when all original preconditions remain valid.

When no reliable journal exists, the manager does not select a source of truth automatically. It displays the NAT, UFW, and state differences and offers:

- rebuild system rules from selected committed records;
- remove exact marked remnants;
- inspect and explicitly overwrite a selected same-parameter rule;
- restore a selected snapshot;
- export diagnostics;
- cancel without mutation.

Every repair is itself a locked transaction with new snapshots and a journal. Protected lockout is cleared only after a full consistency verification.

## Legacy migration

When `state.version` is absent but old forwarding state or markers exist, mutation features remain disabled until migration completes.

Migration acquires the global lock, performs a read-only scan, creates complete snapshots, and classifies each item as:

- safely importable and uniquely consistent;
- missing NAT;
- missing UFW route;
- orphaned NAT;
- orphaned UFW route;
- duplicate ID or duplicate parameters;
- unrecognized or invalid.

The user may import all safely identified rules, review individually, repair deterministic issues, inspect without mutation, or postpone. Safe imports preserve existing IDs and parameters. Unknown rules are neither adopted nor deleted automatically.

The new schema version is written only after migration and complete verification succeed.

## Backups, cleanup, and restore

The backup menu provides:

1. list all backups;
2. inspect a batch and its associations;
3. restore a selected batch;
4. clean expired successful backups;
5. clean explicitly selected eligible backups;
6. export a diagnostic bundle.

Successful transaction backups are retained for 30 days and at least the latest 20 successful batches are kept. Backups associated with failed or inconsistent transactions and initial snapshots for active rules are not cleaned automatically.

Cleanup displays age, size, associations, and recoverability before confirmation. A backup that is still required for recovery cannot be deleted through normal cleanup. High-risk forced cleanup must first remove or resolve the association and require typed confirmation.

Restore is a new locked transaction with its own snapshots, journal, syntax validation, reload, and consistency verification.

Diagnostic exports exclude SSH private keys, authorized key contents, panel tokens, credentials, and other secrets.

## Success semantics

The manager distinguishes:

```text
Configured: persistent state and effective rule layers agree.
Locally verified: live NAT, UFW route, and kernel forwarding are active.
End-to-end unverified: no upper-layer client test has been observed.
```

Optional TCP target probes may report target reachability but do not prove the forwarded client path. Generic UDP probes are not treated as proof of application reachability.

The user may record an external validation timestamp and note, but that record does not replace current local verification.

## Testing strategy

Tests remain host-safe by redirecting paths into temporary directories and replacing external commands with deterministic fakes.

The suite must cover:

- strict accepted and rejected port specifications, including trailing delimiters and repeated colons;
- partial, reversed, duplicate, absent, and valid NAT markers;
- exact ID matching without substring collisions;
- dependency absence, declined install, failed install, and successful re-preflight;
- global lock contention and stale-lock handling;
- cancellation before mutation;
- failure injection at every create phase;
- TCP+UDP rollback when either protocol fails;
- state write failure after live rule application;
- verified rollback and unverified rollback lockout;
- interrupted transaction recovery;
- exact deletion, ambiguous deletion, and overwrite-as-managed flows;
- IPv4 forwarding restore and final-rule removal choices;
- SSH-port detection failure and manual high-risk confirmation;
- initial UFW enablement rollback;
- legacy migration classifications and blocked mutation before migration;
- backup retention, protected associations, cleanup, and transactional restore;
- correct result-category messages;
- read-only inspection remaining available during protected lockout.

Every regression follows red-green TDD. Final verification runs the complete self-test, `bash -n`, ShellCheck when available, and `git diff --check`.

## Documentation impact

The README will document:

- transactional and batch behavior;
- protected lockout and recovery menus;
- the distinction between local verification and end-to-end reachability;
- the global mutation lock;
- dependency installation prompts;
- backup retention and cleanup;
- legacy migration expectations.

The legacy `linux_security_manager.sh` remains unused and unchanged unless a separate cleanup task is approved.
