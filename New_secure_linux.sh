#!/usr/bin/env bash
#
# secure_linux.sh - baseline hardening for Debian/Ubuntu servers
#
# Usage: sudo ./secure_linux.sh [options]
#   -n, --dry-run           Show what would change (with diffs); modify nothing
#   -e, --email ADDR        Email daily logwatch and rkhunter reports to ADDR
#                           (needs a working MTA such as postfix or msmtp)
#   -p, --ssh-port N        Move sshd to port N and open it in UFW
#                           (default: keep the current port, auto-detected)
#       --allow-forwarding  Keep SSH TCP/agent forwarding enabled
#                           (needed for VS Code Remote-SSH, ssh -L/-R tunnels)
#       --skip-ssh          Do not touch SSH configuration
#       --skip-rkhunter     Do not install Rootkit Hunter
#       --rollback DIR      Undo the config changes of a previous run, using
#                           the backup directory it printed at the end
#   -h, --help              Show this help
#
# Safe to re-run: every step is idempotent and changed files are backed up.

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_NAME="${0##*/}"
readonly LOG_FILE="/var/log/secure_linux.log"
readonly LOCK_FILE="/run/secure_linux.lock"
readonly BACKUP_DIR="/var/backups/hardening-$(date +%Y%m%d-%H%M%S)"
readonly -a APT_OPTS=(
  -o DPkg::Lock::Timeout=300            # wait for unattended-upgrades on fresh VMs
  -o Dpkg::Options::=--force-confdef    # keep local config edits, never prompt
  -o Dpkg::Options::=--force-confold
)
export DEBIAN_FRONTEND=noninteractive

DRY_RUN=false
EMAIL=""
SSH_PORT=""
SSH_PORT_FROM_FLAG=false
CURRENT_SSH_PORT=22
ALLOW_FORWARDING=false
SKIP_SSH=false
SKIP_RKHUNTER=false
ROLLBACK_DIR=""

# ---------- helpers ----------------------------------------------------------

# IFS is newline/tab, so "$*" would join words with newlines; use spaces here.
log()  { local IFS=' '; printf '[%s] [+] %s\n' "$(date +%T)" "$*"; }
warn() { local IFS=' '; printf '[%s] [!] %s\n' "$(date +%T)" "$*" >&2; }
die()  { local IFS=' '; printf '[%s] [x] %s\n' "$(date +%T)" "$*" >&2; exit 1; }

# Print the comment header at the top of this file (no hard-coded line numbers).
usage() { awk 'NR < 3 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; }

# Run a command, or just print it in dry-run mode.
run() {
  if $DRY_RUN; then local IFS=' '; log "[dry-run] $*"; else "$@"; fi
}

# Like run, but hides the command's stdout (stderr still shows). The redirect
# lives here so the [dry-run] line itself is never swallowed.
run_quiet() {
  if $DRY_RUN; then local IFS=' '; log "[dry-run] $*"; else "$@" >/dev/null; fi
}

in_manifest() {
  [[ -f $BACKUP_DIR/MANIFEST ]] &&
    awk -F'\t' -v p="$1" '$2 == p { f = 1 } END { exit !f }' "$BACKUP_DIR/MANIFEST"
}

# Record a file in this run's manifest before its first change, so --rollback
# can restore it (backup) or delete it (created) later.
record_change() {
  local path=$1
  in_manifest "$path" && return 0
  install -d -m 0700 "$BACKUP_DIR/files"
  if [[ -f $path ]]; then
    cp -a --parents "$path" "$BACKUP_DIR/files/"
    printf 'backup\t%s\n' "$path" >>"$BACKUP_DIR/MANIFEST"
  else
    printf 'created\t%s\n' "$path" >>"$BACKUP_DIR/MANIFEST"
  fi
}

# Write stdin to a file, backing up any existing one and keeping its mode.
# Returns 0 if the file changed (or would, in dry-run), 1 if unchanged.
write_file() {
  local path=$1 tmp mode
  tmp=$(mktemp)
  cat >"$tmp"
  if [[ -f $path ]] && cmp -s "$tmp" "$path"; then
    rm -f "$tmp"; log "Unchanged: $path"; return 1
  fi
  if $DRY_RUN; then
    log "[dry-run] would write $path:"
    if [[ -f $path ]]; then
      diff -u "$path" "$tmp" | tail -n +3 | sed 's/^/    /' || true
    else
      sed 's/^/    + /' "$tmp"
    fi
    rm -f "$tmp"; return 0
  fi
  mode=$(stat -c %a "$path" 2>/dev/null || echo 644)
  record_change "$path"
  install -m "$mode" "$tmp" "$path"; rm -f "$tmp"
  log "Wrote $path"
}

# Undo one manifest entry from backup directory $1.
undo_entry() {
  local dir=$1 action=$2 path=$3
  case $action in
    backup)  run cp -a "$dir/files$path" "$path"; $DRY_RUN || log "Restored $path" ;;
    created) run rm -f "$path";                   $DRY_RUN || log "Removed $path" ;;
    *)       warn "Unknown manifest entry: $action $path" ;;
  esac
}

# Undo a file changed during THIS run (files untouched this run are left alone).
restore_file() {
  local action=""
  [[ -f $BACKUP_DIR/MANIFEST ]] &&
    action=$(awk -F'\t' -v p="$1" '$2 == p { print $1; exit }' "$BACKUP_DIR/MANIFEST")
  if [[ -n $action ]]; then undo_entry "$BACKUP_DIR" "$action" "$1"; fi
}

# Print stdin with KEY="VALUE" set: replaces the first (possibly commented-out)
# KEY= line, or appends one if the key is missing.
set_kv() {
  awk -v k="$1" -v v="$2" '
    !done && $0 ~ "^#?[[:space:]]*" k "=" { print k "=\"" v "\""; done = 1; next }
    { print }
    END { if (!done) print k "=\"" v "\"" }'
}

pkg_install() {
  run apt-get "${APT_OPTS[@]}" install -y --no-install-recommends "$@"
}

# Reload sshd. With socket activation (Ubuntu 22.10+) the listening port lives
# in ssh.socket, which systemd regenerates from sshd_config on daemon-reload.
reload_ssh() {
  local port_changed=${1:-false} svc=ssh
  systemctl cat ssh.service >/dev/null 2>&1 || svc=sshd
  if $port_changed && systemctl is-active --quiet ssh.socket; then
    run systemctl daemon-reload
    run systemctl restart ssh.socket
  fi
  run systemctl try-reload-or-restart "$svc"
}

on_error() {
  if $DRY_RUN; then
    warn "Failed at line $1 (exit $2) during dry-run; nothing was changed."
  else
    warn "Failed at line $1 (exit $2). See $LOG_FILE."
    if [[ -f $BACKUP_DIR/MANIFEST ]]; then
      warn "Undo this run's config changes with: sudo $SCRIPT_NAME --rollback $BACKUP_DIR"
    fi
  fi
}
trap 'on_error $LINENO $?' ERR

# ---------- preflight --------------------------------------------------------

parse_args() {
  while (($#)); do
    case $1 in
      -n|--dry-run)       DRY_RUN=true ;;
      -e|--email)         EMAIL=${2:?--email needs an address}; shift ;;
      -p|--ssh-port)      SSH_PORT=${2:?--ssh-port needs a number}; SSH_PORT_FROM_FLAG=true; shift ;;
      --allow-forwarding) ALLOW_FORWARDING=true ;;
      --skip-ssh)         SKIP_SSH=true ;;
      --skip-rkhunter)    SKIP_RKHUNTER=true ;;
      --rollback)         ROLLBACK_DIR=${2:?--rollback needs a backup directory}; shift ;;
      -h|--help)          usage; exit 0 ;;
      *)                  usage; die "Unknown option: $1" ;;
    esac
    shift
  done

  # Strict pattern: the address is written into config files, so no quotes,
  # backslashes or spaces may get through.
  local email_re='^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
  if [[ -n $EMAIL && ! $EMAIL =~ $email_re ]]; then
    die "Invalid email address: $EMAIL"
  fi
  if $SSH_PORT_FROM_FLAG; then
    [[ $SSH_PORT =~ ^[0-9]+$ ]] && ((10#$SSH_PORT >= 1 && 10#$SSH_PORT <= 65535)) \
      || die "Invalid SSH port: $SSH_PORT (must be 1-65535)"
    SSH_PORT=$((10#$SSH_PORT))
    # The firewall would open the new port while sshd stays on the old one.
    if $SKIP_SSH; then die "--ssh-port cannot be combined with --skip-ssh"; fi
  fi
}

preflight() {
  [[ $EUID -eq 0 ]] || die "Run as root (try: sudo $SCRIPT_NAME)"
  command -v apt-get >/dev/null || die "This script supports Debian/Ubuntu (apt) only"

  exec 9>"$LOCK_FILE"
  flock -n 9 || die "Another copy of $SCRIPT_NAME is already running"

  if ! $DRY_RUN; then
    mkdir -p "$(dirname "$LOG_FILE")"; touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
    exec > >(tee -a "$LOG_FILE") 2>&1
  fi
  log "Starting $SCRIPT_NAME (dry-run: $DRY_RUN)"
}

# ---------- steps ------------------------------------------------------------

update_system() {
  log "Updating packages"
  run apt-get "${APT_OPTS[@]}" update -qq
  run apt-get "${APT_OPTS[@]}" -y upgrade
}

# One apt transaction instead of one per step: dpkg locks and runs triggers once.
install_packages() {
  local pkgs=(unattended-upgrades ufw fail2ban python3-systemd auditd libpam-pwquality)
  $SKIP_SSH       || pkgs+=(openssh-server)
  $SKIP_RKHUNTER  || pkgs+=(rkhunter)
  [[ -n $EMAIL ]] && pkgs+=(logwatch)
  log "Installing: ${pkgs[*]}"
  pkg_install "${pkgs[@]}"
}

enable_auto_updates() {
  log "Enabling unattended security updates"
  write_file /etc/apt/apt.conf.d/20auto-upgrades <<'EOF' || true
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
}

detect_ssh_port() {
  if command -v sshd >/dev/null; then
    # sshd -T refuses to run without its privilege-separation dir, which is
    # missing on socket-activated systems until the first connection.
    mkdir -p /run/sshd
    local ports
    ports=$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }') || true
    if [[ -n $ports ]]; then
      CURRENT_SSH_PORT=$(head -n1 <<<"$ports")
      if (($(wc -l <<<"$ports") > 1)); then
        warn "sshd listens on several ports ($(tr '\n' ' ' <<<"$ports")); only $CURRENT_SSH_PORT is opened in UFW."
      fi
    fi
  fi
  if ! $SSH_PORT_FROM_FLAG; then SSH_PORT=$CURRENT_SSH_PORT; fi
}

setup_firewall() {
  log "Configuring UFW (SSH on port $SSH_PORT)"
  run ufw default deny incoming
  run ufw default allow outgoing
  # 'limit' = allow + block an IP after 6 connections in 30 seconds
  run ufw limit "${SSH_PORT}/tcp" comment 'SSH (rate limited)'
  if [[ $CURRENT_SSH_PORT != "$SSH_PORT" ]]; then
    # Keep the old port open until a login on the new one has been tested.
    run ufw limit "${CURRENT_SSH_PORT}/tcp" comment 'SSH old port - remove after testing'
    warn "Keeping old SSH port $CURRENT_SSH_PORT open so this session cannot be cut off."
    warn "Once a NEW login on port $SSH_PORT works, run: sudo ufw delete limit $CURRENT_SSH_PORT/tcp"
  fi
  run ufw --force enable
  if command -v docker >/dev/null; then
    warn "Docker detected: ports published with 'docker run -p' bypass UFW (Docker writes its own iptables rules)."
  fi
}

# Members of the admin groups (sudo on Debian/Ubuntu, admin on old Ubuntu).
sudo_members() {
  { getent group sudo admin 2>/dev/null || true; } | cut -d: -f4 | tr ',' '\n' \
    | grep -vx -e '' -e root | sort -u || true
}

# True if user $1 has at least one non-comment line in an authorized_keys file.
user_has_key() {
  local home f
  home=$(getent passwd "$1" | cut -d: -f6) || return 1
  [[ -n $home ]] || return 1
  for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
    [[ -f $f ]] && grep -qE '^[[:space:]]*[^#[:space:]]' "$f" && return 0
  done
  return 1
}

harden_ssh() {
  if $SKIP_SSH; then log "Skipping SSH hardening (--skip-ssh)"; return 0; fi
  if ! command -v sshd >/dev/null; then
    $DRY_RUN || die "sshd not found even after installing openssh-server"
    log "[dry-run] openssh-server is not installed yet; skipping SSH checks"
    return 0
  fi
  log "Hardening SSH"

  # Only turn off passwords if someone who may STILL log in has a key.
  # (Checking 'any user has a key' is not enough: if only root has one and
  # root login is disabled, nobody can get in.)
  local password_auth root_login="" u key_user=""
  for u in $(sudo_members); do
    if user_has_key "$u"; then key_user=$u; break; fi
  done
  if [[ -n $key_user ]]; then
    password_auth=no; root_login=no
    log "Sudo user '$key_user' has an SSH key: disabling password and root login"
  elif user_has_key root; then
    password_auth=no; root_login=prohibit-password
    warn "Only root has an SSH key - keeping key-only root login (prohibit-password)."
    warn "Add a key for a sudo user (ssh-copy-id user@host) and re-run to disable root login."
  else
    password_auth=yes
    warn "No SSH key found for root or any sudo user - KEEPING password auth to avoid lockout."
    warn "From your own machine run: ssh-copy-id user@this-host   then re-run this script."
    if [[ -n $(sudo_members) ]]; then
      root_login=no
    else
      warn "No sudo user exists either - leaving PermitRootLogin as it is."
    fi
  fi

  local forwarding=no
  if $ALLOW_FORWARDING; then forwarding=yes; fi

  local cfg=/etc/ssh/sshd_config dropin=/etc/ssh/sshd_config.d/00-hardening.conf
  local changed=false port_changed=false dropin_port=""

  # Only write Port when asked to, or to keep a port set by a previous run.
  # (Port is cumulative in sshd, so writing it unasked could add a 2nd port.)
  if $SSH_PORT_FROM_FLAG; then
    dropin_port=$SSH_PORT
  elif [[ -f $dropin ]]; then
    dropin_port=$(awk '$1 == "Port" { print $2; exit }' "$dropin")
  fi
  if [[ $CURRENT_SSH_PORT != "$SSH_PORT" ]]; then port_changed=true; fi

  # OpenSSH uses the FIRST value it sees and reads sshd_config.d in lexical
  # order, so 00- wins over distro/cloud-init files like 50-cloud-init.conf.
  # That only works if sshd_config includes the directory near the top.
  if ! grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "$cfg"; then
    warn "$cfg has no Include for sshd_config.d - adding one at the top."
    if { printf '%s\n\n' 'Include /etc/ssh/sshd_config.d/*.conf'; cat "$cfg"; } | write_file "$cfg"; then
      changed=true
    fi
  fi
  run mkdir -p /etc/ssh/sshd_config.d

  if {
    echo "# Managed by $SCRIPT_NAME - re-run the script instead of editing"
    [[ -n $dropin_port ]] && echo "Port $dropin_port"
    echo "PasswordAuthentication $password_auth"
    echo "KbdInteractiveAuthentication $password_auth"
    [[ -n $root_login ]] && echo "PermitRootLogin $root_login"
    cat <<EOF
PermitEmptyPasswords no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
MaxStartups 10:30:60
X11Forwarding no
AllowAgentForwarding $forwarding
AllowTcpForwarding $forwarding
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
  } | write_file "$dropin"; then
    changed=true
  fi

  if ! $ALLOW_FORWARDING; then
    log "TCP/agent forwarding disabled; use --allow-forwarding if you need VS Code Remote-SSH or tunnels."
  fi
  if $DRY_RUN; then return 0; fi

  # Private host keys 600, directories traversable.
  chmod 755 /etc/ssh /etc/ssh/sshd_config.d
  chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null || true
  chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null || true

  if ! $changed; then log "SSH config unchanged; no reload needed"; return 0; fi

  # Never reload with a config sshd rejects.
  mkdir -p /run/sshd
  if ! sshd -t; then
    restore_file "$dropin"; restore_file "$cfg"
    die "sshd config test failed; reverted this run's SSH changes."
  fi

  reload_ssh "$port_changed"
  log "SSH reloaded (port: $SSH_PORT, password auth: $password_auth, root login: ${root_login:-unchanged})"
  log "Keep your current session open and test a NEW login before disconnecting."
}

setup_fail2ban() {
  log "Configuring Fail2Ban"
  local ports=$SSH_PORT changed=false
  if [[ $CURRENT_SSH_PORT != "$SSH_PORT" ]]; then ports+=",$CURRENT_SSH_PORT"; fi
  local jail=/etc/fail2ban/jail.d/10-hardening.local

  # jail.d drop-in survives package upgrades; copying jail.conf does not.
  # backend = systemd: Debian 12 / Ubuntu 24.04 log only to journald, so
  # there is no /var/log/auth.log and the default file backend fails.
  run mkdir -p /etc/fail2ban/jail.d
  if write_file "$jail" <<EOF; then
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
bantime.increment = true

[sshd]
enabled = true
port    = $ports
backend = systemd
EOF
    changed=true
  fi

  run systemctl enable --now fail2ban
  if $changed && ! run systemctl restart fail2ban; then
    restore_file "$jail"
    systemctl restart fail2ban || true
    warn "Fail2Ban would not start with the new jail; reverted it. Check: journalctl -u fail2ban"
  fi
}

apply_sysctl() {
  log "Applying kernel/network hardening (sysctl)"
  write_file /etc/sysctl.d/99-hardening.conf <<'EOF' || true
# Managed by secure_linux.sh
net.ipv4.tcp_syncookies = 1
# 2 = loose reverse-path filtering; 1 (strict) breaks Docker, VPNs and
# multi-homed hosts while giving little extra protection.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 1
net.core.bpf_jit_harden = 2
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF
  # Some keys don't exist in containers or on older kernels; don't abort.
  if ! run_quiet sysctl --system; then
    warn "Some sysctl settings could not be applied (normal in containers); see errors above."
  fi
}

setup_password_policy() {
  log "Setting password quality rules (applies to future password changes)"
  run mkdir -p /etc/security/pwquality.conf.d
  write_file /etc/security/pwquality.conf.d/10-hardening.conf <<'EOF' || true
# Managed by secure_linux.sh
minlen = 12
minclass = 3
maxrepeat = 3
dictcheck = 1
EOF
}

setup_auditd() {
  log "Configuring auditd"
  local changed=false
  run mkdir -p /etc/audit/rules.d
  if write_file /etc/audit/rules.d/50-hardening.rules <<'EOF'; then
# Managed by secure_linux.sh - search with: ausearch -k <key>
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
EOF
    changed=true
  fi
  if ! run systemctl enable --now auditd; then
    warn "auditd could not start (normal inside containers)"; return 0
  fi
  if $changed && ! run_quiet augenrules --load; then
    warn "Could not load audit rules (rules may be locked until reboot)"
  fi
}

setup_logwatch() {
  if [[ -z $EMAIL ]]; then log "No --email given; skipping logwatch"; return 0; fi
  log "Configuring logwatch daily report to $EMAIL"
  if ! command -v sendmail >/dev/null; then
    warn "No MTA (sendmail) found - install postfix or msmtp-mta or reports won't be delivered."
  fi
  if [[ ! -e /var/log/auth.log ]]; then
    warn "No /var/log/auth.log (journald-only system): install rsyslog for complete logwatch reports."
  fi
  # Debian's logwatch package already runs daily via /etc/cron.daily,
  # so we only set options (no duplicate crontab entries on re-run).
  run mkdir -p /etc/logwatch/conf
  write_file /etc/logwatch/conf/logwatch.conf <<EOF || true
Output = mail
Format = html
MailTo = $EMAIL
Detail = Med
Range = yesterday
EOF
}

setup_rkhunter() {
  if $SKIP_RKHUNTER; then log "Skipping rkhunter (--skip-rkhunter)"; return 0; fi
  log "Configuring Rootkit Hunter"
  local def=/etc/default/rkhunter content
  if [[ -f $def ]]; then
    # Daily scan; APT_AUTOGEN refreshes the baseline after apt upgrades so
    # updated binaries don't show up as false positives.
    content=$(set_kv CRON_DAILY_RUN true <"$def" | set_kv APT_AUTOGEN true)
    if [[ -n $EMAIL ]]; then content=$(set_kv REPORT_EMAIL "$EMAIL" <<<"$content"); fi
    printf '%s\n' "$content" | write_file "$def" || true
  elif $DRY_RUN; then
    log "[dry-run] would enable daily scans in $def once rkhunter is installed"
  fi
  if ! run_quiet rkhunter --propupd 2>/dev/null; then
    warn "rkhunter baseline (--propupd) failed"
  fi
}

summary() {
  if $DRY_RUN; then
    log "Dry run finished; nothing was changed."
  else
    log "Done. Log: $LOG_FILE"
    if [[ -f $BACKUP_DIR/MANIFEST ]]; then
      log "Changed files backed up in $BACKUP_DIR"
      log "Undo with: sudo $SCRIPT_NAME --rollback $BACKUP_DIR"
    else
      log "No config files needed changing."
    fi
    ufw status verbose | sed 's/^/    /'
  fi
  if [[ -f /var/run/reboot-required ]]; then
    warn "A reboot is required to finish applying updates."
  fi
}

# ---------- rollback ---------------------------------------------------------

rollback() {
  local dir=${1%/} action path
  [[ -f $dir/MANIFEST ]] || die "No MANIFEST in $dir - is it a backup directory from this script?"
  log "Rolling back config changes recorded in $dir"
  while IFS=$'\t' read -r action path; do
    undo_entry "$dir" "$action" "$path"
  done < <(tac "$dir/MANIFEST")

  log "Reloading affected services"
  if ! run_quiet sysctl --system; then warn "Some sysctl settings could not be applied"; fi
  if command -v sshd >/dev/null; then
    mkdir -p /run/sshd
    if $DRY_RUN || sshd -t; then
      reload_ssh true
    else
      warn "Restored SSH config fails 'sshd -t' - NOT reloading sshd. Fix it before closing this session."
    fi
  fi
  if systemctl is-active --quiet fail2ban; then
    run systemctl restart fail2ban || warn "Fail2Ban restart failed"
  fi
  if command -v augenrules >/dev/null; then
    run_quiet augenrules --load || warn "Could not reload audit rules"
  fi
  warn "Not undone: installed packages, UFW rules and applied upgrades."
  warn "Kernel settings removed from sysctl.d stay in effect until the next reboot."
  log "Rollback finished. Test a NEW SSH login before disconnecting."
}

# ---------- main -------------------------------------------------------------

main() {
  parse_args "$@"
  preflight
  if [[ -n $ROLLBACK_DIR ]]; then rollback "$ROLLBACK_DIR"; return 0; fi
  update_system
  install_packages
  enable_auto_updates
  detect_ssh_port
  setup_firewall        # before sshd changes, so a new port is already open
  harden_ssh
  setup_fail2ban
  apply_sysctl
  setup_password_policy
  setup_auditd
  setup_logwatch
  setup_rkhunter
  summary
}

main "$@"
