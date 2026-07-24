# System Security Check Design

## Goal

Implement the existing system security check menu item as a one-shot read-only report for the security components managed by `linux_security.sh`.

## Scope

The report checks six areas:

1. SSH service and effective hardening configuration
2. Valid root SSH public key
3. Effective SSH ports and their listening state
4. UFW installation and active state
5. Fail2Ban service and `sshd` jail state
6. Docker firewall bypass risk

System updates, password scanning, account auditing, external port scanning, and third-party scanners are excluded to avoid new dependencies and misleading results.

## Behavior

Selecting menu item 4 runs all checks immediately. Each check prints exactly one result category:

- `通过` when the expected protection is active
- `警告` when a known unsafe or incomplete state is detected
- `未知` when the required component or command is unavailable

The report continues after individual failures and ends with counts for passed, warning, and unknown results. It then waits for Enter and returns to the main menu.

The check must not install packages, update package indexes, write files, alter firewall rules, change SSH or Fail2Ban configuration, or start, stop, enable, restart, or reload services.

## Checks

### SSH service and configuration

Return `未知` when `sshd` or the SSH systemd unit cannot be found. Return `警告` when the unit is inactive, `sshd -T` fails, or any effective value differs from the managed target:

- `PermitRootLogin prohibit-password`
- `PubkeyAuthentication yes`
- `PasswordAuthentication no`
- `KbdInteractiveAuthentication no`
- `MaxAuthTries` no greater than 3
- `LoginGraceTime` no greater than 30 seconds

Return `通过` only when the service is active and all values satisfy the target.

### Root public key

Reuse `has_valid_authorized_key`. Return `通过` when at least one entry in `/root/.ssh/authorized_keys` is accepted by `ssh-keygen`; otherwise return `警告`. Return `未知` when `ssh-keygen` is unavailable.

### SSH listening ports

Reuse `all_current_ssh_ports` and `port_is_listening`. Return `未知` when ports cannot be determined or `ss` is unavailable. Return `警告` when any detected SSH port is not listening. Otherwise return `通过` and include the port list.

### UFW

Return `未知` when `ufw` is unavailable, `警告` when UFW is inactive, and `通过` when UFW is active.

### Fail2Ban

Return `未知` when `fail2ban-client` or the Fail2Ban systemd unit is unavailable. Return `警告` when the service is inactive or `fail2ban-client status sshd` fails. Otherwise return `通过`.

### Docker risk

Return `警告` when Docker is installed and its service is active because published container ports may bypass ordinary UFW input rules. Otherwise return `通过` without requiring Docker to be installed.

## Implementation

Add small read-only check functions and one report runner inside `linux_security.sh`. Reuse existing helpers for systemd units, SSH keys, SSH ports, UFW, and Fail2Ban. Replace the menu placeholder with the report runner and remove `module_not_implemented` when it has no callers.

Do not add dependencies, configuration files, caches, report files, command-line options, or remediation actions.

## Error Handling

Every external command runs inside an explicit conditional or tolerant pipeline so `set -e` cannot terminate the report. Missing commands map to `未知`; confirmed insecure states map to `警告`. Diagnostic details remain concise and must not expose key contents or other credentials.

## Testing

Extend `tests/linux_security_self_test.sh` with command and function replacements that simulate protected, warning, and unavailable states. Verify result classification, summary counts, continued execution after a failed check, and that the report does not invoke installation or mutation helpers.
