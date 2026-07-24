# lsec Installation Lifecycle Design

## Goal

Allow one remote execution to install the Linux security manager as `lsec` so later use does not require the long GitHub command

## Architecture

The existing `linux_security.sh` remains the only executable implementation

No systemd service or timer is added because the manager is interactive and requires a terminal

Remote process substitution execution installs the current validated script to `/usr/local/bin/lsec` and immediately opens the existing menu

Normal local execution of `linux_security.sh` continues to open the menu without installing itself

## First installation

The documented primary command is

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh)
```

The documented fallback command is

```bash
bash <(wget -qO- https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh)
```

The script keeps the existing root requirement

When the script source path is a process substitution descriptor such as `/dev/fd/*` or `/proc/self/fd/*` it performs these steps

1. Validate its own Bash syntax and program marker
2. Install itself atomically with mode `755` at `/usr/local/bin/lsec`
3. Execute the installed `lsec` with the original terminal input and arguments

An already installed executable is replaced only after validation succeeds

## Command interface

Running `lsec` with no arguments opens the existing interactive security menu

Running `lsec upgrade` downloads the latest `main` branch version using curl when available and wget otherwise

Running `lsec uninstall` removes only the installed executable after explicit confirmation

Unknown arguments print concise usage and exit nonzero

## Upgrade

Upgrade performs these steps

1. Require root
2. Create a temporary file
3. Download the latest script from GitHub Raw
4. Require a nonempty file containing the expected program marker
5. Validate it with `bash -n`
6. Install it atomically over `/usr/local/bin/lsec` with mode `755`
7. Remove the temporary file and report the installed version

Any download or validation failure leaves the installed executable unchanged

There is no automatic or scheduled upgrade

## Uninstall

Uninstall requires explicit confirmation with a safe default

It removes only `/usr/local/bin/lsec`

It does not remove or alter UFW rules SSH configuration Fail2Ban configuration backups or manager state

## Configuration

The production install path defaults to `/usr/local/bin/lsec`

The GitHub Raw URL defaults to `https://raw.githubusercontent.com/jilinker/shells/main/linux_security.sh`

Tests may override both values through environment variables so lifecycle behavior can be verified under a temporary directory without root filesystem changes

## Error handling and tests

- Installation and upgrade validate before replacement
- Temporary files are cleaned on success and failure
- Missing curl and wget produce a clear error
- Uninstall never performs configuration cleanup
- The self check covers install target content mode upgrade validation argument dispatch and uninstall target scope
- Existing syntax root gate UFW SSH and Fail2Ban checks continue to pass

