# security-measures

`New_secure_linux.sh` applies baseline security hardening to Debian and Ubuntu servers. It is safe to re-run, backs up every file it changes, and can undo its own config changes.

## Quick start

Preview first. This shows a diff of every file it would change and modifies nothing:

```bash
sudo ./New_secure_linux.sh --dry-run
```

Then apply:

```bash
sudo ./New_secure_linux.sh --email you@example.com
```

**Keep your current SSH session open** until you have tested a new login in a second terminal.

## What it does

| Area | Change |
|------|--------|
| Updates | `apt-get upgrade`, then enables unattended security updates |
| SSH | Drop-in `/etc/ssh/sshd_config.d/00-hardening.conf`: key-only login (when a key exists), no root login, fewer auth attempts, idle timeout, forwarding off |
| Firewall | UFW: deny incoming, allow outgoing, rate-limited SSH |
| Fail2Ban | Bans brute-force SSH sources, with longer bans for repeat offenders (reads journald) |
| Kernel | `/etc/sysctl.d/99-hardening.conf`: network and memory hardening |
| Passwords | `libpam-pwquality`: at least 12 characters and 3 character classes for new passwords |
| Auditing | `auditd` rules that record changes to users, sudoers and SSH config (`ausearch -k identity`) |
| Reports | logwatch daily email (with `--email`), daily rkhunter scan |

## Options

| Flag | Meaning |
|------|---------|
| `-n`, `--dry-run` | Show what would change; modify nothing |
| `-e`, `--email ADDR` | Email logwatch and rkhunter reports to ADDR. Needs a working MTA (postfix, msmtp-mta) |
| `-p`, `--ssh-port N` | Move sshd to port N. The old port stays open in UFW until you remove it |
| `--allow-forwarding` | Keep SSH TCP/agent forwarding on. **Needed for VS Code Remote-SSH and `ssh -L` tunnels** |
| `--skip-ssh` | Leave SSH config alone |
| `--skip-rkhunter` | Don't install rkhunter |
| `--rollback DIR` | Undo the config changes of a previous run |

## Lockout protection

- Password login is turned off only when **root or a sudo user who can still log in** has an SSH key. Without one, the script keeps password login on and tells you to run `ssh-copy-id`.
- Root login is fully disabled only when a sudo user has a key. If only root has a key, root keeps key-only login.
- `sshd -t` validates the new config before reload. If validation fails, this run's SSH changes are reverted.
- When you change the SSH port, the new port is opened in UFW **before** sshd moves to it, and the old port stays open. After a new login on the new port works, remove the old rule with `sudo ufw delete limit <old-port>/tcp`.

## Undoing a run

Every run that changes files prints a backup directory, for example:

```bash
sudo ./New_secure_linux.sh --rollback /var/backups/hardening-20261112-140501
```

This restores the files that run changed, deletes the files it created, and reloads the affected services. It does **not** remove installed packages, UFW rules or applied upgrades. Kernel settings stay in effect until the next reboot.

## Things to know

- **Docker:** ports published with `docker run -p` bypass UFW.
- **UFW rate limit:** UFW blocks an IP after 6 SSH connections in 30 seconds, which can hit scripted `scp` or Ansible loops. Use SSH connection multiplexing (`ControlMaster`) to avoid it.
- **logwatch** reads `/var/log` files. On journald-only systems (Debian 12+), install `rsyslog` for complete reports.
- **Not automated on purpose:** 2FA (`libpam-google-authenticator`) needs each user to enrol on their phone, and changing the root password needs a person. Do both by hand.
- **Log file:** `/var/log/secure_linux.log`

## Repo layout

- `New_secure_linux.sh`: the current script
- `New_secure_linux.sh.bak`: the version before this rewrite
- `archive/`: the first two versions, kept for reference. **Do not run them.** They edit `/etc/sudoers` unsafely and can lock you out.
