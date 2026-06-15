#!/usr/bin/env bash
# tests/fixtures/audit_fixture.sh
# Sourced via BASH_ENV before vps-audit.sh runs.
# Provides deterministic mock functions for all system-dependent commands
# and sets AUDIT_* paths to controlled fixture files.

AUDIT_FIXTURE_DIR="${AUDIT_FIXTURE_DIR:-$(mktemp -d)}"
export AUDIT_FIXTURE_DIR

# ── Create fixture files ─────────────────────────────────────────────

mkdir -p "$AUDIT_FIXTURE_DIR/etc/ssh"
mkdir -p "$AUDIT_FIXTURE_DIR/var/log"

cat > "$AUDIT_FIXTURE_DIR/etc/ssh/sshd_config" <<'SSHD'
Port 2222
PermitRootLogin no
PasswordAuthentication no
SSHD

cat > "$AUDIT_FIXTURE_DIR/etc/sudoers" <<'SUDO'
Defaults logfile=/var/log/sudo.log
SUDO

cat > "$AUDIT_FIXTURE_DIR/etc/security/pwquality.conf" <<'PWQ'
minlen = 12
PWQ

cat > "$AUDIT_FIXTURE_DIR/etc/os-release" <<'OSR'
PRETTY_NAME="Fixture Test OS 1.0"
OSR

cat > "$AUDIT_FIXTURE_DIR/var/log/auth.log" <<'AUTH'
Jan  1 00:00:01 host sshd[1]: Failed password for root from 1.2.3.4 port 22
Jan  1 00:00:02 host sshd[2]: Failed password for admin from 1.2.3.5 port 22
Jan  1 00:00:03 host sshd[3]: Accepted password for user from 1.2.3.6 port 22
AUTH

# AUDIT_REBOOT_REQ intentionally does NOT exist → System Restart = PASS

# ── Point script's file-path variables at fixture files ──────────────

export AUDIT_SSHD_CONFIG="$AUDIT_FIXTURE_DIR/etc/ssh/sshd_config"
export AUDIT_SUDOERS="$AUDIT_FIXTURE_DIR/etc/sudoers"
export AUDIT_PWQUALITY="$AUDIT_FIXTURE_DIR/etc/security/pwquality.conf"
export AUDIT_REBOOT_REQ="$AUDIT_FIXTURE_DIR/var/run/reboot-required"
export AUDIT_AUTH_LOG="$AUDIT_FIXTURE_DIR/var/log/auth.log"

# ── Mock system commands ─────────────────────────────────────────────

curl() {
    case "$*" in
        *api.ipify.org*) echo "203.0.113.42" ;;
        *) command curl "$@" 2>/dev/null || echo "" ;;
    esac
}

uptime() {
    case "$*" in
        -p) echo "up 3 days, 4 hours, 5 minutes" ;;
        -s) echo "2025-06-12 10:00:00" ;;
        *)  echo " 10:05:00 up 3 days,  4:05,  1 user,  load average: 0.15, 0.10, 0.05" ;;
    esac
}

lscpu() {
    echo "Model name:       Fixture CPU @ 2.40GHz"
    echo "CPU(s):           4"
}

nproc() {
    echo "4"
}

free() {
    if [ "${1:-}" = "-h" ]; then
        echo "              total        used        free      shared  buff/cache   available"
        echo "Mem:           16Gi       4.0Gi       8.0Gi       200Mi       4.0Gi        11Gi"
        echo "Swap:         2.0Gi          0B       2.0Gi"
    else
        # Raw kB output (for MEM_USAGE calculation: $3/$2 * 100 = 25%)
        echo "              total        used        free      shared  buff/cache   available"
        echo "Mem:       16777216     4194304     8388608      204800     4194304    11534336"
        echo "Swap:       2097152           0     2097152"
    fi
}

df() {
    case "$*" in
        *-h*)
            echo "Filesystem      Size  Used Avail Use% Mounted on"
            echo "/dev/sda1        50G   15G   33G  30% /"
            ;;
        *)
            echo "Filesystem     1K-blocks     Used Available Use% Mounted on"
            echo "/dev/sda1       52428800 15728640 34603008  30% /"
            ;;
    esac
}

top() {
    case "$*" in
        *-b*)
            echo "Tasks: 100 total,   1 running,  99 sleeping"
            echo "%Cpu(s):  12.0 us,  3.0 sy,  0.0 ni, 83.0 id,  1.5 wa,  0.0 hi,  0.5 si,  0.0 st"
            ;;
        *)
            echo "%Cpu(s):  12.0 us,  3.0 sy,  0.0 ni, 83.0 id"
            ;;
    esac
}

hostname() {
    echo "fixture-host"
}

sysctl() {
    case "$*" in
        *ip_unprivileged_port_start*) echo "1024" ;;
        *) echo "0" ;;
    esac
}

systemctl() {
    case "$*" in
        *is-active*fail2ban*)  return 1 ;;
        *is-active*crowdsec*)  return 1 ;;
        *is-active*docker*)    return 1 ;;
        *list-units*)
            echo "  ssh.service               loaded active running OpenSSH server"
            echo "  cron.service              loaded active running Regular cron jobs"
            ;;
        *) return 1 ;;
    esac
}

dpkg() {
    case "$*" in
        *-l*)
            echo "ii  unattended-upgrades  2.0  all  automatic installation of security upgrades"
            echo "ii  fail2ban             0.11 all  ban hosts that cause multiple auth errors"
            ;;
    esac
    return 0
}

apt-get() {
    case "$*" in
        *-s*upgrade*)
            echo "3 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."
            ;;
    esac
    return 0
}

netstat() {
    return 1  # force script to use ss
}

ss() {
    case "$*" in
        *-tuln*)
            echo "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port"
            echo "tcp   LISTEN 0      128    0.0.0.0:2222         0.0.0.0:*"
            echo "tcp   LISTEN 0      128    0.0.0.0:443          0.0.0.0:*"
            echo "tcp   LISTEN 0      128    0.0.0.0:80           0.0.0.0:*"
            ;;
    esac
}

find() {
    case "$*" in
        */*\ -type*\ -perm*)
            # SUID file search → return nothing (clean system)
            # Do NOT echo "" — it produces a trailing newline that wc -l counts as 1
            ;;
        *)
            command find "$@" 2>/dev/null || true
            ;;
    esac
}

# Firewall tools: deterministic PASS via iptables mock
ufw() { return 1; }
firewall-cmd() { return 1; }
iptables() {
    case "$*" in
        *-L*) echo "Chain INPUT (policy ACCEPT)" ;;
    esac
    return 0
}
nft() { return 1; }
docker() { return 1; }

# Mock wc to handle edge case where empty pipe input might give wrong counts
wc() {
    local input
    input=$(cat)
    if [ -z "$input" ]; then
        echo "0"
        return 0
    fi
    echo "$input" | command wc "$@"
}

# Selective grep mock: intercepts known fixture/config file paths,
# falls through to real grep for everything else (piped input, etc.)
grep() {
    local args=("$@")
    local last_arg="${args[${#args[@]}-1]}"

    case "$last_arg" in
        "$AUDIT_SSHD_CONFIG"|/etc/ssh/sshd_config)
            command grep "${args[@]}" 2>/dev/null || return 1
            ;;
        "$AUDIT_SUDOERS"|/etc/sudoers)
            command grep "${args[@]}" 2>/dev/null || return 1
            ;;
        "$AUDIT_PWQUALITY"|/etc/security/pwquality.conf)
            command grep "${args[@]}" 2>/dev/null || return 1
            ;;
        "$AUDIT_AUTH_LOG")
            command grep "${args[@]}" 2>/dev/null || return 1
            ;;
        /etc/os-release)
            # Always use fixture data for os-release (determinism)
            if [ -f "$AUDIT_FIXTURE_DIR/etc/os-release" ]; then
                local tmp_args=("${args[@]}")
                tmp_args[${#tmp_args[@]}-1]="$AUDIT_FIXTURE_DIR/etc/os-release"
                command grep "${tmp_args[@]}" 2>/dev/null || return 1
            else
                command grep "${args[@]}" 2>/dev/null || return 1
            fi
            ;;
        /etc/debian_version)
            return 1  # not debian, force fallback path
            ;;
        *)
            # Piped / stdin / anything else → real grep
            command grep "${args[@]}"
            ;;
    esac
}

export -f curl uptime lscpu nproc free df top hostname sysctl
export -f systemctl dpkg apt-get netstat ss find grep wc
export -f ufw firewall-cmd iptables nft docker
