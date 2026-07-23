# Linux Security Manager SSH and Fail2Ban Design

## Scope

Create a standalone `linux_security.sh` with SSH security management Fail2Ban management and the complete existing UFW implementation

The new script does not source call or modify `linux_security_manager.sh`

System security inspection remains unimplemented

## Runtime requirements

- Require root when the script starts and exit with a clear message otherwise
- Support Debian and Ubuntu systems using `apt-get` and systemd
- Check and install missing packages only after the user enters the relevant module and confirms installation
- Keep all management in the standalone script and add only a minimal runnable self check

## SSH management

The SSH menu provides these operations

- Show effective SSH configuration and service status
- Append a client public key to `/root/.ssh/authorized_keys`
- Start a two phase SSH port migration
- Finish a verified port migration and close the old port
- Apply key only login hardening
- Validate and reload SSH

### Public key handling

The script accepts a client public key from standard input and validates its supported OpenSSH key type and encoded key body before writing it

It creates `/root/.ssh` with mode `700` and `authorized_keys` with mode `600`

It appends keys exactly once and supports adding more keys later

The script never generates displays or stores a private key

### Port migration

The default proposed port is the current effective SSH port

Starting a migration performs these steps

1. Validate the target port and reject conflicts
2. Back up every file that will change
3. Add a managed SSH configuration containing both the old and new ports
4. If UFW is installed add a tagged allow rule for the new TCP port before changing SSH
5. If `ssh.socket` controls the listener create a managed systemd drop-in that listens on both ports
6. Validate with `sshd -t`
7. Reload the relevant SSH service or socket
8. Record the pending old and new ports in root only state

The script tells the user to open a separate SSH session on the new port before finishing the migration

Finishing a migration requires explicit confirmation and performs these steps

1. Back up every file that will change
2. Keep only the new port in the managed SSH configuration
3. Comment active `Port` lines for the old port in the main configuration and other drop-ins
4. If `ssh.socket` is active update its managed drop-in to keep only the new port
5. Validate with `sshd -t`
6. Reload SSH
7. Remove only UFW rules tagged by this script for the old port
8. Clear the pending migration state

Any validation or reload failure restores changed files from the backups and attempts to restore the previous running configuration

### Login hardening

Hardening is a separate menu action after the user confirms a new key based session works

The action refuses to continue unless `/root/.ssh/authorized_keys` contains at least one valid key

It writes a managed drop-in with these values

```text
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
MaxAuthTries 3
LoginGraceTime 30
```

The script validates with `sshd -t` and rolls back on failure before reloading SSH

## Fail2Ban management

The Fail2Ban menu provides these operations

- Install `fail2ban` and `python3-systemd` after confirmation
- Show service and jail status
- Configure and enable the `sshd` jail
- Separately enable or disable the `recidive` jail
- Validate configuration and restart Fail2Ban
- Start stop restart and enable the service

The script owns only `/etc/fail2ban/jail.d/99-security-manager.local` and never overwrites `jail.local` or other jail files

The managed defaults are

```text
ignoreip = 127.0.0.1/8 ::1
findtime = 10m
maxretry = 5
bantime = 24h
bantime.increment = true
bantime.factor = 2
```

The `sshd` jail is enabled by default and uses the effective SSH ports with the systemd backend

The `recidive` jail is disabled until explicitly enabled and then uses the existing Fail2Ban log with a seven day find window a thirty day ban and three retries

The current SSH client address is not automatically trusted

Configuration is checked with `fail2ban-client -t` before the service is restarted

## Existing UFW integration

The new script inherits the complete current UFW module for firewall management

SSH port migration reuses its existing validation and rule helpers where possible and tags any rules it creates so cleanup cannot delete unrelated user rules

The reference script's separate UFW setup flow is not copied

## Error handling and verification

- Dangerous actions require explicit confirmation with a safe default
- Configuration writes use temporary files and restrictive permissions where applicable
- Existing configuration is backed up before modification
- SSH configuration must pass `sshd -t`
- Fail2Ban configuration must pass `fail2ban-client -t`
- A small shell self check covers pure validation state and configuration rendering logic without changing the host system
- `bash -n` and ShellCheck are run when available

## Remote execution

The repository documents one command that always fetches `linux_security.sh` from the `main` branch through `raw.githubusercontent.com`

The command uses `curl` when available and falls back to `wget` otherwise

It validates the downloader exit status stores the script only in memory and executes it through Bash process substitution so interactive input remains attached to the terminal

The command does not elevate privileges and the downloaded script keeps the existing root check

The command is documented in `README.md` and as one usage line near the top of `linux_security.sh`
