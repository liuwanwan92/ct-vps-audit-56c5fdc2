#!/usr/bin/env bash
#
# VPS Security Audit Tool
# https://github.com/vernu/vps-audit
#
# Runs security and performance checks on a VPS, outputs results to the
# terminal (color-coded) and a plain-text report file. An optional trace
# file records every check for post-run diagnostics.
#
# Usage:
#   bash vps-audit.sh              # Normal audit
#   bash vps-audit.sh --diagnose   # Audit + self-consistency verification
#

# ============================================================
# Colors
# ============================================================
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
GRAY='\033[0;90m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ============================================================
# Run ID & File Paths
# ============================================================
RUN_ID=$(head -c 4 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n' || echo "fallback")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Allow output directory override (useful for testing)
OUTPUT_DIR="${AUDIT_OUTPUT_DIR:-.}"
REPORT_FILE="${OUTPUT_DIR}/vps-audit-report-${TIMESTAMP}.txt"
TRACE_FILE="${OUTPUT_DIR}/vps-audit-report-${TIMESTAMP}.trace.log"

# Allow system file paths to be overridden (useful for testing)
OS_RELEASE="${VPS_AUDIT_OS_RELEASE:-/etc/os-release}"
SSHD_CONFIG="${VPS_AUDIT_SSHD_CONFIG:-/etc/ssh/sshd_config}"
SUDOERS="${VPS_AUDIT_SUDOERS:-/etc/sudoers}"
PWQUALITY="${VPS_AUDIT_PWQUALITY:-/etc/security/pwquality.conf}"
REBOOT_FLAG="${VPS_AUDIT_REBOOT_FLAG:-/var/run/reboot-required}"
AUTH_LOG="${VPS_AUDIT_AUTH_LOG:-/var/log/auth.log}"

# ============================================================
# Counters
# ============================================================
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0
SEQ_NUM=0

# ============================================================
# Core Output Functions
# ============================================================

# Strip ANSI escape codes from a string
strip_ansi() {
    sed 's/\x1b\[[0-9;]*m//g' <<< "$1"
}

print_header() {
    local header="$1"
    echo -e "\n${BLUE}${BOLD}$header${NC}"
    echo -e "\n$header" >> "$REPORT_FILE"
    echo "================================" >> "$REPORT_FILE"
    echo "[HEADER] $header" >> "$TRACE_FILE"
}

print_info() {
    local label="$1"
    local value="$2"
    echo -e "${BOLD}$label:${NC} $value"
    echo "$label: $value" >> "$REPORT_FILE"
    echo "[INFO] $label=$value" >> "$TRACE_FILE"
}

check_security() {
    local test_name="$1"
    local status="$2"
    local message="$3"

    SEQ_NUM=$((SEQ_NUM + 1))
    local seq_id
    seq_id=$(printf "%03d" "$SEQ_NUM")

    case $status in
        "PASS")
            echo -e "${GREEN}[PASS]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[PASS] $test_name - $message" >> "$REPORT_FILE"
            PASS_COUNT=$((PASS_COUNT + 1))
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[WARN] $test_name - $message" >> "$REPORT_FILE"
            WARN_COUNT=$((WARN_COUNT + 1))
            ;;
        "FAIL")
            echo -e "${RED}[FAIL]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[FAIL] $test_name - $message" >> "$REPORT_FILE"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            ;;
    esac
    echo "" >> "$REPORT_FILE"

    # Write to trace log with sequence number for ordering verification
    # Use | as field separator so multi-word check names parse correctly
    echo "[SEQ:$seq_id] name=$test_name|status=$status|msg=$message" >> "$TRACE_FILE"
}

# Log a raw command and its output to the trace file only.
# This captures the "ground truth" for post-run diagnosis.
trace_raw() {
    local check_name="$1"
    local cmd="$2"
    local output
    output=$(eval "$cmd" 2>&1 || true)
    echo "[RAW] check=$check_name cmd=$cmd output=\"$output\"" >> "$TRACE_FILE"
}

# ============================================================
# Main Audit Logic
# ============================================================
main() {
    local DIAGNOSE_MODE=0
    if [ "${1:-}" = "--diagnose" ]; then
        DIAGNOSE_MODE=1
    fi

    # --- Initialize output files ---
    echo "VPS Security Audit Tool" > "$REPORT_FILE"
    echo "https://github.com/vernu/vps-audit" >> "$REPORT_FILE"
    echo "Run ID: $RUN_ID" >> "$REPORT_FILE"
    echo "Starting audit at $(date)" >> "$REPORT_FILE"
    echo "================================" >> "$REPORT_FILE"

    echo "[RUN] id=$RUN_ID timestamp=$(date)" > "$TRACE_FILE"

    echo -e "${BLUE}${BOLD}VPS Security Audit Tool${NC}"
    echo -e "${GRAY}https://github.com/vernu/vps-audit${NC}"
    echo -e "${GRAY}Run ID: $RUN_ID${NC}"
    echo -e "${GRAY}Starting audit at $(date)${NC}\n"

    # ============================================================
    # System Information
    # ============================================================
    print_header "System Information"

    # Capture all system info ONCE — no re-fetching later
    OS_INFO=$(grep PRETTY_NAME "$OS_RELEASE" 2>/dev/null | cut -d'"' -f2 || echo "Unknown")
    KERNEL_VERSION=$(uname -r)
    CURRENT_HOSTNAME=$(hostname)
    UPTIME=$(uptime -p)
    UPTIME_SINCE=$(uptime -s)
    CPU_INFO=$(lscpu 2>/dev/null | grep "Model name" | cut -d':' -f2 | xargs || echo "Unknown")
    CPU_CORES=$(nproc)
    TOTAL_MEM=$(free -h | awk '/^Mem:/ {print $2}')
    TOTAL_DISK=$(df -h / | awk 'NR==2 {print $2}')
    PUBLIC_IP=$(curl -s --connect-timeout 5 https://api.ipify.org || echo "Unknown")
    LOAD_AVERAGE=$(uptime | awk -F'load average:' '{print $2}' | xargs)

    # Trace raw system info for diagnostics
    trace_raw "System Info" "uptime -p"
    trace_raw "System Info" "free -h"
    trace_raw "System Info" "df -h /"

    print_info "Hostname" "$CURRENT_HOSTNAME"
    print_info "Operating System" "$OS_INFO"
    print_info "Kernel Version" "$KERNEL_VERSION"
    print_info "Uptime" "$UPTIME (since $UPTIME_SINCE)"
    print_info "CPU Model" "$CPU_INFO"
    print_info "CPU Cores" "$CPU_CORES"
    print_info "Total Memory" "$TOTAL_MEM"
    print_info "Total Disk Space" "$TOTAL_DISK"
    print_info "Public IP" "$PUBLIC_IP"
    print_info "Load Average" "$LOAD_AVERAGE"

    # Write sysinfo to trace
    for key in Hostname "Operating System" "Kernel Version" Uptime "CPU Model" "CPU Cores" "Total Memory" "Total Disk Space" "Public IP" "Load Average"; do
        echo "[SYSINFO] key=$key" >> "$TRACE_FILE"
    done

    echo "" >> "$REPORT_FILE"

    # ============================================================
    # Security Audit Section
    # ============================================================
    print_header "Security Audit Results"

    # --- Uptime (use already-captured values, no re-fetch) ---
    print_header "System Uptime Information"
    print_info "Current uptime" "$UPTIME"
    print_info "System up since" "$UPTIME_SINCE"

    # --- System Restart ---
    if [ -f "$REBOOT_FLAG" ]; then
        check_security "System Restart" "WARN" "System requires a restart to apply updates"
    else
        check_security "System Restart" "PASS" "No restart required"
    fi

    # --- SSH Config Overrides ---
    SSH_CONFIG_OVERRIDES=$(grep "^Include" "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}')

    # --- SSH Root Login ---
    if [ -n "$SSH_CONFIG_OVERRIDES" ] && [ -d "$(dirname "$SSH_CONFIG_OVERRIDES")" ]; then
        SSH_ROOT=$(grep "^PermitRootLogin" $SSH_CONFIG_OVERRIDES "$SSHD_CONFIG" 2>/dev/null | head -1 | awk '{print $2}')
    else
        SSH_ROOT=$(grep "^PermitRootLogin" "$SSHD_CONFIG" 2>/dev/null | head -1 | awk '{print $2}')
    fi
    if [ -z "$SSH_ROOT" ]; then
        SSH_ROOT="prohibit-password"
    fi
    if [ "$SSH_ROOT" = "no" ]; then
        check_security "SSH Root Login" "PASS" "Root login is properly disabled in SSH configuration"
    else
        check_security "SSH Root Login" "FAIL" "Root login is currently allowed - this is a security risk. Disable it in $SSHD_CONFIG"
    fi

    # --- SSH Password Authentication ---
    if [ -n "$SSH_CONFIG_OVERRIDES" ] && [ -d "$(dirname "$SSH_CONFIG_OVERRIDES")" ]; then
        SSH_PASSWORD=$(grep "^PasswordAuthentication" $SSH_CONFIG_OVERRIDES "$SSHD_CONFIG" 2>/dev/null | head -1 | awk '{print $2}')
    else
        SSH_PASSWORD=$(grep "^PasswordAuthentication" "$SSHD_CONFIG" 2>/dev/null | head -1 | awk '{print $2}')
    fi
    if [ -z "$SSH_PASSWORD" ]; then
        SSH_PASSWORD="yes"
    fi
    if [ "$SSH_PASSWORD" = "no" ]; then
        check_security "SSH Password Auth" "PASS" "Password authentication is disabled, key-based auth only"
    else
        check_security "SSH Password Auth" "FAIL" "Password authentication is enabled - consider using key-based authentication only"
    fi

    # --- SSH Port ---
    UNPRIVILEGED_PORT_START=$(sysctl -n net.ipv4.ip_unprivileged_port_start 2>/dev/null || echo 1024)
    SSH_PORT=""
    if [ -n "$SSH_CONFIG_OVERRIDES" ] && [ -d "$(dirname "$SSH_CONFIG_OVERRIDES")" ]; then
        SSH_PORT=$(grep "^Port" $SSH_CONFIG_OVERRIDES "$SSHD_CONFIG" 2>/dev/null | head -1 | awk '{print $2}')
    else
        SSH_PORT=$(grep "^Port" "$SSHD_CONFIG" 2>/dev/null | head -1 | awk '{print $2}')
    fi
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT="22"
    fi

    if [ "$SSH_PORT" = "22" ]; then
        check_security "SSH Port" "WARN" "Using default port 22 - consider changing to a non-standard port for security by obscurity"
    elif [ "$SSH_PORT" -ge "$UNPRIVILEGED_PORT_START" ] 2>/dev/null; then
        check_security "SSH Port" "FAIL" "Using unprivileged port $SSH_PORT - use a port below $UNPRIVILEGED_PORT_START for better security"
    else
        check_security "SSH Port" "PASS" "Using non-default port $SSH_PORT which helps prevent automated attacks"
    fi

    # --- Firewall Status ---
    check_firewall_status() {
        if command -v ufw >/dev/null 2>&1; then
            if ufw status 2>/dev/null | grep -qw "active"; then
                check_security "Firewall Status (UFW)" "PASS" "UFW firewall is active and protecting your system"
            else
                check_security "Firewall Status (UFW)" "FAIL" "UFW firewall is not active - your system is exposed to network attacks"
            fi
        elif command -v firewall-cmd >/dev/null 2>&1; then
            if firewall-cmd --state 2>/dev/null | grep -q "running"; then
                check_security "Firewall Status (firewalld)" "PASS" "Firewalld is active and protecting your system"
            else
                check_security "Firewall Status (firewalld)" "FAIL" "Firewalld is not active - your system is exposed to network attacks"
            fi
        elif command -v iptables >/dev/null 2>&1; then
            if iptables -L -n 2>/dev/null | grep -q "Chain INPUT"; then
                check_security "Firewall Status (iptables)" "PASS" "iptables rules are active and protecting your system"
            else
                check_security "Firewall Status (iptables)" "FAIL" "No active iptables rules found - your system may be exposed"
            fi
        elif command -v nft >/dev/null 2>&1; then
            if nft list ruleset 2>/dev/null | grep -q "table"; then
                check_security "Firewall Status (nftables)" "PASS" "nftables rules are active and protecting your system"
            else
                check_security "Firewall Status (nftables)" "FAIL" "No active nftables rules found - your system may be exposed"
            fi
        else
            check_security "Firewall Status" "FAIL" "No recognized firewall tool is installed on this system"
        fi
    }
    check_firewall_status

    # --- Unattended Upgrades ---
    if dpkg -l 2>/dev/null | grep -q "unattended-upgrades"; then
        check_security "Unattended Upgrades" "PASS" "Automatic security updates are configured"
    else
        check_security "Unattended Upgrades" "FAIL" "Automatic security updates are not configured - system may miss critical updates"
    fi

    # --- Intrusion Prevention Systems (Fail2ban / CrowdSec) ---
    # Consolidated: only ONE check_security call is emitted for this check.
    IPS_INSTALLED=0
    IPS_ACTIVE=0
    IPS_MESSAGE=""

    if dpkg -l 2>/dev/null | grep -q "fail2ban"; then
        IPS_INSTALLED=1
        systemctl is-active fail2ban >/dev/null 2>&1 && IPS_ACTIVE=1
    fi

    if command -v docker >/dev/null 2>&1; then
        if systemctl is-active --quiet docker 2>/dev/null; then
            if docker ps -a 2>/dev/null | awk '{print $2}' | grep -q "fail2ban"; then
                IPS_INSTALLED=1
                docker ps 2>/dev/null | grep -q "fail2ban" && IPS_ACTIVE=1
            fi
        else
            IPS_MESSAGE="Docker installed but not running - cannot check containers"
        fi
    fi

    if dpkg -l 2>/dev/null | grep -q "crowdsec"; then
        IPS_INSTALLED=1
        systemctl is-active crowdsec >/dev/null 2>&1 && IPS_ACTIVE=1
    fi

    if command -v docker >/dev/null 2>&1; then
        if systemctl is-active --quiet docker 2>/dev/null; then
            if docker ps -a 2>/dev/null | awk '{print $2}' | grep -q "crowdsec"; then
                IPS_INSTALLED=1
                docker ps 2>/dev/null | grep -q "crowdsec" && IPS_ACTIVE=1
            fi
        else
            if [ -z "$IPS_MESSAGE" ]; then
                IPS_MESSAGE="Docker installed but not running - cannot check containers"
            fi
        fi
    fi

    # Single consolidated result for Intrusion Prevention
    if [ "$IPS_INSTALLED" -eq 1 ] && [ "$IPS_ACTIVE" -eq 1 ]; then
        check_security "Intrusion Prevention" "PASS" "Fail2ban or CrowdSec is installed and running"
    elif [ "$IPS_INSTALLED" -eq 1 ]; then
        check_security "Intrusion Prevention" "WARN" "Fail2ban or CrowdSec is installed but not running"
    else
        local fail_msg="No intrusion prevention system (Fail2ban or CrowdSec) is installed"
        if [ -n "$IPS_MESSAGE" ]; then
            fail_msg="$fail_msg ($IPS_MESSAGE)"
        fi
        check_security "Intrusion Prevention" "FAIL" "$fail_msg"
    fi

    # --- Failed Login Attempts ---
    FAILED_LOGINS=0
    if [ -f "$AUTH_LOG" ]; then
        FAILED_LOGINS=$(grep -c "Failed password" "$AUTH_LOG" 2>/dev/null || echo 0)
    elif [ -f "/etc/debian_version" ]; then
        DEB_VERSION=$(cut -d'.' -f1 /etc/debian_version 2>/dev/null || echo 0)
        if [ "$DEB_VERSION" -gt 10 ] 2>/dev/null; then
            # FIXED: pipe journalctl output to grep (was: grep treating command as filename)
            FAILED_LOGINS=$(journalctl -u ssh --since "24 hours ago" 2>/dev/null | grep -c "Failed password" || echo 0)
        fi
    else
        check_security "Auth Log" "WARN" "Log file $AUTH_LOG not found or inaccessible"
    fi

    # Ensure FAILED_LOGINS is numeric
    FAILED_LOGINS=$(echo "$FAILED_LOGINS" | tr -d '[:space:]')
    FAILED_LOGINS=$((10#$FAILED_LOGINS))

    trace_raw "Failed Logins" "echo $FAILED_LOGINS"

    if [ "$FAILED_LOGINS" -lt 10 ]; then
        check_security "Failed Logins" "PASS" "Only $FAILED_LOGINS failed login attempts detected - this is within normal range"
    elif [ "$FAILED_LOGINS" -lt 50 ]; then
        check_security "Failed Logins" "WARN" "$FAILED_LOGINS failed login attempts detected - might indicate breach attempts"
    else
        check_security "Failed Logins" "FAIL" "$FAILED_LOGINS failed login attempts detected - possible brute force attack in progress"
    fi

    # --- System Updates ---
    UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -P '^\d+ upgraded' | cut -d" " -f1 || true)
    if [ -z "$UPDATES" ]; then
        UPDATES=0
    fi
    if [ "$UPDATES" -eq 0 ]; then
        check_security "System Updates" "PASS" "All system packages are up to date"
    else
        check_security "System Updates" "FAIL" "$UPDATES security updates available - system is vulnerable to known exploits"
    fi

    # --- Running Services ---
    SERVICES=$(systemctl list-units --type=service --state=running 2>/dev/null | grep -c "loaded active running" || echo 0)
    if [ "$SERVICES" -lt 20 ]; then
        check_security "Running Services" "PASS" "Running minimal services ($SERVICES) - good for security"
    elif [ "$SERVICES" -lt 40 ]; then
        check_security "Running Services" "WARN" "$SERVICES services running - consider reducing attack surface"
    else
        check_security "Running Services" "FAIL" "Too many services running ($SERVICES) - increases attack surface"
    fi

    # --- Port Security ---
    LISTENING_PORTS=""
    if command -v netstat >/dev/null 2>&1; then
        LISTENING_PORTS=$(netstat -tuln 2>/dev/null | grep LISTEN | awk '{print $4}')
    elif command -v ss >/dev/null 2>&1; then
        LISTENING_PORTS=$(ss -tuln 2>/dev/null | grep LISTEN | awk '{print $5}')
    fi

    trace_raw "Port Security" "ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null"

    if [ -n "$LISTENING_PORTS" ]; then
        PUBLIC_PORTS=$(echo "$LISTENING_PORTS" | awk -F':' '{print $NF}' | sort -n | uniq | tr '\n' ',' | sed 's/,$//')
        PORT_COUNT=$(echo "$PUBLIC_PORTS" | tr ',' '\n' | wc -w)
        INTERNET_PORTS=$PORT_COUNT

        if [ "$PORT_COUNT" -lt 10 ] && [ "$INTERNET_PORTS" -lt 3 ]; then
            check_security "Port Security" "PASS" "Good configuration (Total: $PORT_COUNT, Public: $INTERNET_PORTS accessible ports): $PUBLIC_PORTS"
        elif [ "$PORT_COUNT" -lt 20 ] && [ "$INTERNET_PORTS" -lt 5 ]; then
            check_security "Port Security" "WARN" "Review recommended (Total: $PORT_COUNT, Public: $INTERNET_PORTS accessible ports): $PUBLIC_PORTS"
        else
            check_security "Port Security" "FAIL" "High exposure (Total: $PORT_COUNT, Public: $INTERNET_PORTS accessible ports): $PUBLIC_PORTS"
        fi
    else
        # FIXED: consistent name "Port Security" (was "Port Scanning")
        check_security "Port Security" "WARN" "Neither 'netstat' nor 'ss' is available - cannot scan listening ports"
    fi

    # --- Disk Usage ---
    DISK_TOTAL=$(df -h / | awk 'NR==2 {print $2}')
    DISK_USED=$(df -h / | awk 'NR==2 {print $3}')
    DISK_AVAIL=$(df -h / | awk 'NR==2 {print $4}')
    DISK_USAGE=$(df -h / | awk 'NR==2 {print int($5)}')
    trace_raw "Disk Usage" "df -h /"

    if [ "$DISK_USAGE" -lt 50 ]; then
        check_security "Disk Usage" "PASS" "Healthy disk space available (${DISK_USAGE}% used - Used: ${DISK_USED} of ${DISK_TOTAL}, Available: ${DISK_AVAIL})"
    elif [ "$DISK_USAGE" -lt 80 ]; then
        check_security "Disk Usage" "WARN" "Disk space usage is moderate (${DISK_USAGE}% used - Used: ${DISK_USED} of ${DISK_TOTAL}, Available: ${DISK_AVAIL})"
    else
        check_security "Disk Usage" "FAIL" "Critical disk space usage (${DISK_USAGE}% used - Used: ${DISK_USED} of ${DISK_TOTAL}, Available: ${DISK_AVAIL})"
    fi

    # --- Memory Usage ---
    MEM_TOTAL=$(free -h | awk '/^Mem:/ {print $2}')
    MEM_USED=$(free -h | awk '/^Mem:/ {print $3}')
    MEM_AVAIL=$(free -h | awk '/^Mem:/ {print $7}')
    MEM_USAGE=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2 * 100}')
    trace_raw "Memory Usage" "free"

    if [ "$MEM_USAGE" -lt 50 ]; then
        check_security "Memory Usage" "PASS" "Healthy memory usage (${MEM_USAGE}% used - Used: ${MEM_USED} of ${MEM_TOTAL}, Available: ${MEM_AVAIL})"
    elif [ "$MEM_USAGE" -lt 80 ]; then
        check_security "Memory Usage" "WARN" "Moderate memory usage (${MEM_USAGE}% used - Used: ${MEM_USED} of ${MEM_TOTAL}, Available: ${MEM_AVAIL})"
    else
        check_security "Memory Usage" "FAIL" "Critical memory usage (${MEM_USAGE}% used - Used: ${MEM_USED} of ${MEM_TOTAL}, Available: ${MEM_AVAIL})"
    fi

    # --- CPU Usage ---
    CPU_CORES=$(nproc)
    CPU_USAGE=$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{print int($2)}' || echo 0)
    CPU_IDLE=$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{print int($8)}' || echo 0)
    CPU_LOAD=$(uptime | awk -F'load average:' '{ print $2 }' | awk -F',' '{ print $1 }' | tr -d ' ')
    trace_raw "CPU Usage" "top -bn1"

    if [ "$CPU_USAGE" -lt 50 ]; then
        check_security "CPU Usage" "PASS" "Healthy CPU usage (${CPU_USAGE}% used - Active: ${CPU_USAGE}%, Idle: ${CPU_IDLE}%, Load: ${CPU_LOAD}, Cores: ${CPU_CORES})"
    elif [ "$CPU_USAGE" -lt 80 ]; then
        check_security "CPU Usage" "WARN" "Moderate CPU usage (${CPU_USAGE}% used - Active: ${CPU_USAGE}%, Idle: ${CPU_IDLE}%, Load: ${CPU_LOAD}, Cores: ${CPU_CORES})"
    else
        check_security "CPU Usage" "FAIL" "Critical CPU usage (${CPU_USAGE}% used - Active: ${CPU_USAGE}%, Idle: ${CPU_IDLE}%, Load: ${CPU_LOAD}, Cores: ${CPU_CORES})"
    fi

    # --- Sudo Logging ---
    if grep -q "^Defaults.*logfile" "$SUDOERS" 2>/dev/null; then
        check_security "Sudo Logging" "PASS" "Sudo commands are being logged for audit purposes"
    else
        check_security "Sudo Logging" "FAIL" "Sudo commands are not being logged - reduces audit capability"
    fi

    # --- Password Policy ---
    if [ -f "$PWQUALITY" ]; then
        if grep -q "minlen.*12" "$PWQUALITY" 2>/dev/null; then
            check_security "Password Policy" "PASS" "Strong password policy is enforced"
        else
            check_security "Password Policy" "FAIL" "Weak password policy - passwords may be too simple"
        fi
    else
        check_security "Password Policy" "FAIL" "No password policy configured - system accepts weak passwords"
    fi

    # --- SUID Files ---
    COMMON_SUID_PATHS='^/usr/bin/|^/bin/|^/sbin/|^/usr/sbin/|^/usr/lib|^/usr/libexec'
    KNOWN_SUID_BINS='ping$|sudo$|mount$|umount$|su$|passwd$|chsh$|newgrp$|gpasswd$|chfn$'

    SUID_FILES=$(find / -type f -perm -4000 2>/dev/null | \
        grep -v -E "$COMMON_SUID_PATHS" | \
        grep -v -E "$KNOWN_SUID_BINS" | \
        wc -l)

    trace_raw "SUID Files" "find / -type f -perm -4000 2>/dev/null | wc -l"

    if [ "$SUID_FILES" -eq 0 ]; then
        check_security "SUID Files" "PASS" "No suspicious SUID files found - good security practice"
    else
        check_security "SUID Files" "WARN" "Found $SUID_FILES SUID files outside standard locations - verify if legitimate"
    fi

    # ============================================================
    # Result Summary (written to BOTH terminal and report)
    # ============================================================
    local total=$((PASS_COUNT + WARN_COUNT + FAIL_COUNT))

    echo "================================" >> "$REPORT_FILE"
    echo "Audit Summary: $total checks ($PASS_COUNT PASS, $WARN_COUNT WARN, $FAIL_COUNT FAIL)" >> "$REPORT_FILE"
    echo "================================" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "End of VPS Audit Report (Run ID: $RUN_ID)" >> "$REPORT_FILE"
    echo "Please review all failed checks and implement the recommended fixes." >> "$REPORT_FILE"

    echo ""
    echo -e "${BOLD}Audit Summary:${NC} $total checks (${GREEN}$PASS_COUNT PASS${NC}, ${YELLOW}$WARN_COUNT WARN${NC}, ${RED}$FAIL_COUNT FAIL${NC})"

    echo ""
    echo -e "VPS audit complete. Full report saved to ${BOLD}$REPORT_FILE${NC}"
    echo -e "Trace log saved to ${BOLD}$TRACE_FILE${NC}"
    echo -e "Review $REPORT_FILE for detailed recommendations."

    # Write summary to trace
    echo "[SUMMARY] total=$total pass=$PASS_COUNT warn=$WARN_COUNT fail=$FAIL_COUNT" >> "$TRACE_FILE"

    # ============================================================
    # Diagnose Mode: self-consistency verification
    # ============================================================
    if [ "$DIAGNOSE_MODE" -eq 1 ]; then
        echo ""
        echo -e "${BLUE}${BOLD}--- Diagnostics (Run ID: $RUN_ID) ---${NC}"
        run_diagnostics
    fi
}

# ============================================================
# Diagnostics: verify trace/report/terminal consistency
# ============================================================
run_diagnostics() {
    local issues=0

    # 1. Verify check counts match between trace and report
    local trace_count report_count
    trace_count=$(grep -c '^\[SEQ:' "$TRACE_FILE" 2>/dev/null || echo 0)
    report_count=$(grep -cE '^\[(PASS|WARN|FAIL)\]' "$REPORT_FILE" 2>/dev/null || echo 0)

    if [ "$trace_count" -ne "$report_count" ]; then
        echo -e "  ${RED}[DIAG FAIL]${NC} Check count mismatch: trace=$trace_count, report=$report_count"
        issues=$((issues + 1))
    else
        echo -e "  ${GREEN}[DIAG OK]${NC} Check counts match: $trace_count"
    fi

    # 2. Verify no duplicate check names in trace
    local dupes
    dupes=$(grep '^\[SEQ:' "$TRACE_FILE" 2>/dev/null | sed 's/\[SEQ:[0-9]*\] name=\([^|]*\).*/\1/' | sort | uniq -d)
    if [ -n "$dupes" ]; then
        echo -e "  ${RED}[DIAG FAIL]${NC} Duplicate check names in trace: $dupes"
        issues=$((issues + 1))
    else
        echo -e "  ${GREEN}[DIAG OK]${NC} No duplicate check names"
    fi

    # 3. Verify sequence numbers are consecutive (no gaps)
    local seq_nums expected prev=0 gap_found=0
    seq_nums=$(grep '^\[SEQ:' "$TRACE_FILE" 2>/dev/null | sed 's/\[SEQ:\([0-9]*\)\].*/\1/' | sed 's/^0*//')
    for num in $seq_nums; do
        expected=$((prev + 1))
        if [ "$num" -ne "$expected" ] 2>/dev/null; then
            gap_found=1
            break
        fi
        prev=$num
    done
    if [ "$gap_found" -eq 1 ]; then
        echo -e "  ${RED}[DIAG FAIL]${NC} Non-consecutive sequence numbers (gap at $expected, got $num)"
        issues=$((issues + 1))
    else
        echo -e "  ${GREEN}[DIAG OK]${NC} Sequence numbers are consecutive"
    fi

    # 4. Verify check names match between trace and report (in order)
    local trace_names report_names
    trace_names=$(grep '^\[SEQ:' "$TRACE_FILE" 2>/dev/null | sed 's/\[SEQ:[0-9]*\] name=\([^|]*\).*/\1/')
    report_names=$(grep -E '^\[(PASS|WARN|FAIL)\]' "$REPORT_FILE" 2>/dev/null | sed 's/^\[[A-Z]*\] //' | sed 's/ - .*//')
    if [ "$trace_names" != "$report_names" ]; then
        echo -e "  ${RED}[DIAG FAIL]${NC} Check name order mismatch between trace and report"
        issues=$((issues + 1))
    else
        echo -e "  ${GREEN}[DIAG OK]${NC} Check names match in order"
    fi

    # 5. Verify statuses match
    local trace_statuses report_statuses
    trace_statuses=$(grep '^\[SEQ:' "$TRACE_FILE" 2>/dev/null | sed 's/.*|status=\([^|]*\).*/\1/')
    report_statuses=$(grep -E '^\[(PASS|WARN|FAIL)\]' "$REPORT_FILE" 2>/dev/null | sed 's/^\[\([A-Z]*\)\].*/\1/')
    if [ "$trace_statuses" != "$report_statuses" ]; then
        echo -e "  ${RED}[DIAG FAIL]${NC} Status mismatch between trace and report"
        issues=$((issues + 1))
    else
        echo -e "  ${GREEN}[DIAG OK]${NC} Check statuses match"
    fi

    # 6. Check for raw commands that returned empty output
    local empty_raw
    empty_raw=$(grep '^\[RAW\]' "$TRACE_FILE" 2>/dev/null | grep 'output=""' | wc -l)
    if [ "$empty_raw" -gt 0 ]; then
        echo -e "  ${YELLOW}[DIAG WARN]${NC} $empty_raw raw command(s) returned empty output (possible missing tools or permissions)"
    else
        echo -e "  ${GREEN}[DIAG OK]${NC} All traced commands produced output"
    fi

    # Summary
    echo ""
    if [ "$issues" -eq 0 ]; then
        echo -e "  ${GREEN}${BOLD}Diagnostics complete: No inconsistencies found.${NC}"
    else
        echo -e "  ${RED}${BOLD}Diagnostics complete: $issues inconsistency(ies) found.${NC}"
        echo -e "  Trace file: $TRACE_FILE"
        echo -e "  Report file: $REPORT_FILE"
    fi
}

# ============================================================
# Entry Point
# ============================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
