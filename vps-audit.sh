#!/usr/bin/env bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
GRAY='\033[0;90m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Result-consistency core
#
# Every verdict flows through ONE sink (record_result) so the terminal output
# and the saved report are derived from the SAME string and can never diverge.
# Each check is a PURE decide_* function that emits exactly one
# "STATUS<TAB>MESSAGE"; run_check captures it and routes it through the sink.
# This structurally prevents the terminal-vs-report mismatch and the
# multi-emit (same check reported more than once) problems.
# ---------------------------------------------------------------------------

RESULTS=()          # ordered in-memory log: one "STATUS<TAB>NAME<TAB>MESSAGE" per verdict
CHECK_INDEX=0       # execution order counter (used by diagnostic mode)
DIAG_EVIDENCE=""    # raw evidence for the current check (shown in diagnostic mode)

# record_result <name> <status> <message>
# The ONLY place a verdict line is formatted/emitted. Terminal and report both
# derive from the same $name/$status/$message, so stripping ANSI from the
# terminal line yields a byte-identical string to the report line.
record_result() {
    local name="$1" status="$2" message="$3"
    local line="[$status] $name - $message"
    RESULTS+=("$status"$'\t'"$name"$'\t'"$message")

    local color
    case "$status" in
        PASS) color="$GREEN" ;;
        WARN) color="$YELLOW" ;;
        FAIL) color="$RED" ;;
        SKIP) color="$BLUE" ;;
        *)    color="$NC" ;;
    esac

    echo -e "${color}[$status]${NC} $name ${GRAY}- $message${NC}"
    echo "$line" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

# run_check <name> <decider_fn> [args...]
# Calls a pure decider, captures its single STATUS<TAB>MESSAGE, and routes it
# through record_result. In diagnostic mode it also prints an aligned trace
# (execution order + check name + raw evidence) to BOTH terminal and report so
# all three views come from the same single run.
run_check() {
    local name="$1"; shift
    local decider="$1"; shift
    local out status message
    out="$("$decider" "$@")"
    status="${out%%$'\t'*}"
    message="${out#*$'\t'}"
    if [ -z "$out" ] || [ "$status" = "$out" ]; then   # decider contract violation: no TAB
        status="SKIP"
        message="internal: check '$name' produced no verdict"
    fi

    if [ "${VPS_AUDIT_DIAG:-0}" = "1" ]; then
        CHECK_INDEX=$((CHECK_INDEX + 1))
        echo -e "${GRAY}--- [#$CHECK_INDEX] $name${NC}"
        [ -n "$DIAG_EVIDENCE" ] && echo -e "${GRAY}    evidence: $DIAG_EVIDENCE${NC}"
        {
            echo "--- [#$CHECK_INDEX] $name"
            [ -n "$DIAG_EVIDENCE" ] && echo "    evidence: $DIAG_EVIDENCE"
        } >> "$REPORT_FILE"
    fi

    record_result "$name" "$status" "$message"
    DIAG_EVIDENCE=""
}

print_header() {
    local header="$1"
    echo -e "\n${BLUE}${BOLD}$header${NC}"
    echo -e "\n$header" >> "$REPORT_FILE"
    echo "================================" >> "$REPORT_FILE"
}

print_info() {
    local label="$1"
    local value="$2"
    echo -e "${BOLD}$label:${NC} $value"
    echo "$label: $value" >> "$REPORT_FILE"
}

# Summary computed from the single RESULTS[] log, so the tally shown on the
# terminal and written to the report are guaranteed to match the run.
print_summary() {
    local pass=0 warn=0 fail=0 skip=0 entry status
    for entry in "${RESULTS[@]}"; do
        status="${entry%%$'\t'*}"
        case "$status" in
            PASS) pass=$((pass + 1)) ;;
            WARN) warn=$((warn + 1)) ;;
            FAIL) fail=$((fail + 1)) ;;
            SKIP) skip=$((skip + 1)) ;;
        esac
    done

    echo -e "\n${BOLD}Audit Summary${NC}"
    echo -e "${GREEN}PASS: $pass${NC}  ${YELLOW}WARN: $warn${NC}  ${RED}FAIL: $fail${NC}  ${BLUE}SKIP: $skip${NC}"

    {
        echo ""
        echo "Audit Summary"
        echo "================================"
        echo "PASS: $pass  WARN: $warn  FAIL: $fail  SKIP: $skip"
    } >> "$REPORT_FILE"
}

# ---------------------------------------------------------------------------
# Pure deciders: each takes already-gathered inputs and emits exactly one
# "STATUS<TAB>MESSAGE". Verdict logic and thresholds are unchanged from the
# original; [SKIP] is only ever an additive leading branch guarded by an
# explicit "could not evaluate" precondition.
# ---------------------------------------------------------------------------

# <reboot_required: 1|0>
decide_system_restart() {
    if [ "$1" = "1" ]; then
        printf 'WARN\t%s\n' "System requires a restart to apply updates"
    else
        printf 'PASS\t%s\n' "No restart required"
    fi
}

# <PermitRootLogin value>
decide_ssh_root() {
    if [ "$1" = "no" ]; then
        printf 'PASS\t%s\n' "Root login is properly disabled in SSH configuration"
    else
        printf 'FAIL\t%s\n' "Root login is currently allowed - this is a security risk. Disable it in /etc/ssh/sshd_config"
    fi
}

# <PasswordAuthentication value>
decide_ssh_password() {
    if [ "$1" = "no" ]; then
        printf 'PASS\t%s\n' "Password authentication is disabled, key-based auth only"
    else
        printf 'FAIL\t%s\n' "Password authentication is enabled - consider using key-based authentication only"
    fi
}

# <ssh_port> <unprivileged_port_start>
decide_ssh_port() {
    local port="$1" unpriv="$2"
    if [ "$port" = "22" ]; then
        printf 'WARN\t%s\n' "Using default port 22 - consider changing to a non-standard port for security by obscurity"
    elif [ "$port" -ge "$unpriv" ]; then
        printf 'FAIL\t%s\n' "Using unprivileged port $port -  use a port below $unpriv for better security"
    else
        printf 'PASS\t%s\n' "Using non-default port $port which helps prevent automated attacks"
    fi
}

# <tool: ufw|firewalld|iptables|nftables|none> <active: yes|no>
decide_firewall() {
    local tool="$1" active="$2"
    case "$tool" in
        ufw)
            if [ "$active" = "yes" ]; then
                printf 'PASS\t%s\n' "UFW firewall is active and protecting your system"
            else
                printf 'FAIL\t%s\n' "UFW firewall is not active - your system is exposed to network attacks"
            fi
            ;;
        firewalld)
            if [ "$active" = "yes" ]; then
                printf 'PASS\t%s\n' "Firewalld is active and protecting your system"
            else
                printf 'FAIL\t%s\n' "Firewalld is not active - your system is exposed to network attacks"
            fi
            ;;
        iptables)
            if [ "$active" = "yes" ]; then
                printf 'PASS\t%s\n' "iptables rules are active and protecting your system"
            else
                printf 'FAIL\t%s\n' "No active iptables rules found - your system may be exposed"
            fi
            ;;
        nftables)
            if [ "$active" = "yes" ]; then
                printf 'PASS\t%s\n' "nftables rules are active and protecting your system"
            else
                printf 'FAIL\t%s\n' "No active nftables rules found - your system may be exposed"
            fi
            ;;
        *)
            printf 'FAIL\t%s\n' "No recognized firewall tool is installed on this system"
            ;;
    esac
}

# <installed: 1|0>
decide_unattended_upgrades() {
    if [ "$1" = "1" ]; then
        printf 'PASS\t%s\n' "Automatic security updates are configured"
    else
        printf 'FAIL\t%s\n' "Automatic security updates are not configured - system may miss critical updates"
    fi
}

# <installed: 1|0> <active: 1|0> <native: 1|0> <docker_present: 1|0> <docker_running: 1|0>
decide_intrusion_prevention() {
    local installed="$1" active="$2" native="$3" docker_present="$4" docker_running="$5"
    # Genuinely unevaluable: no native IPS package, and a stopped Docker means we
    # cannot inspect for a containerized Fail2ban/CrowdSec.
    if [ "$native" -eq 0 ] && [ "$docker_present" -eq 1 ] && [ "$docker_running" -eq 0 ]; then
        printf 'SKIP\t%s\n' "Docker is installed but not running - cannot verify a containerized Fail2ban/CrowdSec, and no native IPS package was found"
        return
    fi
    case "$installed$active" in
        "11") printf 'PASS\t%s\n' "Fail2ban or CrowdSec is installed and running" ;;
        "10") printf 'WARN\t%s\n' "Fail2ban or CrowdSec is installed but not running" ;;
        *)    printf 'FAIL\t%s\n' "No intrusion prevention system (Fail2ban or CrowdSec) is installed" ;;
    esac
}

# <evaluable: 1|0> <count>
decide_failed_logins() {
    local evaluable="$1" count="$2"
    if [ "$evaluable" -ne 1 ]; then
        printf 'SKIP\t%s\n' "Could not read auth log (/var/log/auth.log) or query journalctl - failed login count is unevaluable"
        return
    fi
    if [ "$count" -lt 10 ]; then
        printf 'PASS\t%s\n' "Only $count failed login attempts detected - this is within normal range"
    elif [ "$count" -lt 50 ]; then
        printf 'WARN\t%s\n' "$count failed login attempts detected - might indicate breach attempts"
    else
        printf 'FAIL\t%s\n' "$count failed login attempts detected - possible brute force attack in progress"
    fi
}

# <updates_count>
decide_system_updates() {
    if [ "$1" -eq 0 ]; then
        printf 'PASS\t%s\n' "All system packages are up to date"
    else
        printf 'FAIL\t%s\n' "$1 security updates available - system is vulnerable to known exploits"
    fi
}

# <running_services_count>
decide_running_services() {
    local services="$1"
    if [ "$services" -lt 20 ]; then
        printf 'PASS\t%s\n' "Running minimal services ($services) - good for security"
    elif [ "$services" -lt 40 ]; then
        printf 'WARN\t%s\n' "$services services running - consider reducing attack surface"
    else
        printf 'FAIL\t%s\n' "Too many services running ($services) - increases attack surface"
    fi
}

# <evaluable: 1|0> <port_count> <internet_ports> <public_ports>
decide_port_security() {
    local evaluable="$1" port_count="$2" internet_ports="$3" public_ports="$4"
    if [ "$evaluable" -ne 1 ]; then
        printf 'SKIP\t%s\n' "Neither 'netstat' nor 'ss' is available - listening ports are unevaluable"
        return
    fi
    if [ "$port_count" -lt 10 ] && [ "$internet_ports" -lt 3 ]; then
        printf 'PASS\t%s\n' "Good configuration (Total: $port_count, Public: $internet_ports accessible ports): $public_ports"
    elif [ "$port_count" -lt 20 ] && [ "$internet_ports" -lt 5 ]; then
        printf 'WARN\t%s\n' "Review recommended (Total: $port_count, Public: $internet_ports accessible ports): $public_ports"
    else
        printf 'FAIL\t%s\n' "High exposure (Total: $port_count, Public: $internet_ports accessible ports): $public_ports"
    fi
}

# <usage_pct> <used> <total> <avail>
decide_disk_usage() {
    local usage="$1" used="$2" total="$3" avail="$4"
    if [ "$usage" -lt 50 ]; then
        printf 'PASS\t%s\n' "Healthy disk space available (${usage}% used - Used: ${used} of ${total}, Available: ${avail})"
    elif [ "$usage" -lt 80 ]; then
        printf 'WARN\t%s\n' "Disk space usage is moderate (${usage}% used - Used: ${used} of ${total}, Available: ${avail})"
    else
        printf 'FAIL\t%s\n' "Critical disk space usage (${usage}% used - Used: ${used} of ${total}, Available: ${avail})"
    fi
}

# <usage_pct> <used> <total> <avail>
decide_memory_usage() {
    local usage="$1" used="$2" total="$3" avail="$4"
    if [ "$usage" -lt 50 ]; then
        printf 'PASS\t%s\n' "Healthy memory usage (${usage}% used - Used: ${used} of ${total}, Available: ${avail})"
    elif [ "$usage" -lt 80 ]; then
        printf 'WARN\t%s\n' "Moderate memory usage (${usage}% used - Used: ${used} of ${total}, Available: ${avail})"
    else
        printf 'FAIL\t%s\n' "Critical memory usage (${usage}% used - Used: ${used} of ${total}, Available: ${avail})"
    fi
}

# <usage_pct> <idle_pct> <load> <cores>
decide_cpu_usage() {
    local usage="$1" idle="$2" load="$3" cores="$4"
    if [ "$usage" -lt 50 ]; then
        printf 'PASS\t%s\n' "Healthy CPU usage (${usage}% used - Active: ${usage}%, Idle: ${idle}%, Load: ${load}, Cores: ${cores})"
    elif [ "$usage" -lt 80 ]; then
        printf 'WARN\t%s\n' "Moderate CPU usage (${usage}% used - Active: ${usage}%, Idle: ${idle}%, Load: ${load}, Cores: ${cores})"
    else
        printf 'FAIL\t%s\n' "Critical CPU usage (${usage}% used - Active: ${usage}%, Idle: ${idle}%, Load: ${load}, Cores: ${cores})"
    fi
}

# <has_logfile: 1|0>
decide_sudo_logging() {
    if [ "$1" = "1" ]; then
        printf 'PASS\t%s\n' "Sudo commands are being logged for audit purposes"
    else
        printf 'FAIL\t%s\n' "Sudo commands are not being logged - reduces audit capability"
    fi
}

# <state: strong|weak|none>
decide_password_policy() {
    case "$1" in
        strong) printf 'PASS\t%s\n' "Strong password policy is enforced" ;;
        weak)   printf 'FAIL\t%s\n' "Weak password policy - passwords may be too simple" ;;
        *)      printf 'FAIL\t%s\n' "No password policy configured - system accepts weak passwords" ;;
    esac
}

# <suid_count>
decide_suid_files() {
    if [ "$1" -eq 0 ]; then
        printf 'PASS\t%s\n' "No suspicious SUID files found - good security practice"
    else
        printf 'WARN\t%s\n' "Found $1 SUID files outside standard locations - verify if legitimate"
    fi
}

# ---------------------------------------------------------------------------
# main: gather data and run every check through the single sink.
# ---------------------------------------------------------------------------
main() {
    # Get current timestamp for the report filename (overridable via REPORT_FILE)
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    REPORT_FILE="${REPORT_FILE:-vps-audit-report-${TIMESTAMP}.txt}"

    # Start the audit
    echo -e "${BLUE}${BOLD}VPS Security Audit Tool${NC}"
    echo -e "${GRAY}https://github.com/vernu/vps-audit${NC}"
    echo -e "${GRAY}Starting audit at $(date)${NC}\n"

    echo "VPS Security Audit Tool" > "$REPORT_FILE"
    echo "https://github.com/vernu/vps-audit" >> "$REPORT_FILE"
    echo "Starting audit at $(date)" >> "$REPORT_FILE"
    echo "================================" >> "$REPORT_FILE"

    # System Information Section
    print_header "System Information"

    # Get system information
    OS_INFO=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
    KERNEL_VERSION=$(uname -r)
    HOSTNAME=$HOSTNAME
    UPTIME=$(uptime -p)
    UPTIME_SINCE=$(uptime -s)
    CPU_INFO=$(lscpu | grep "Model name" | cut -d':' -f2 | xargs)
    CPU_CORES=$(nproc)
    TOTAL_MEM=$(free -h | awk '/^Mem:/ {print $2}')
    TOTAL_DISK=$(df -h / | awk 'NR==2 {print $2}')
    if command -v curl >/dev/null 2>&1; then
        PUBLIC_IP=$(curl -s https://api.ipify.org)
        [ -z "$PUBLIC_IP" ] && PUBLIC_IP="unavailable (no response)"
    else
        PUBLIC_IP="unavailable (curl not found)"
    fi
    LOAD_AVERAGE=$(uptime | awk -F'load average:' '{print $2}' | xargs)

    # Print system information
    print_info "Hostname" "$HOSTNAME"
    print_info "Operating System" "$OS_INFO"
    print_info "Kernel Version" "$KERNEL_VERSION"
    print_info "Uptime" "$UPTIME (since $UPTIME_SINCE)"
    print_info "CPU Model" "$CPU_INFO"
    print_info "CPU Cores" "$CPU_CORES"
    print_info "Total Memory" "$TOTAL_MEM"
    print_info "Total Disk Space" "$TOTAL_DISK"
    print_info "Public IP" "$PUBLIC_IP"
    print_info "Load Average" "$LOAD_AVERAGE"

    echo "" >> "$REPORT_FILE"

    # Security Audit Section
    print_header "Security Audit Results"

    # Uptime information (informational, written to report; summary on terminal)
    UPTIME=$(uptime -p)
    UPTIME_SINCE=$(uptime -s)
    echo -e "\nSystem Uptime Information:" >> "$REPORT_FILE"
    echo "Current uptime: $UPTIME" >> "$REPORT_FILE"
    echo "System up since: $UPTIME_SINCE" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo -e "System Uptime: $UPTIME (since $UPTIME_SINCE)"

    # Check if system requires restart
    if [ -f /var/run/reboot-required ]; then REBOOT_REQUIRED=1; else REBOOT_REQUIRED=0; fi
    DIAG_EVIDENCE="/var/run/reboot-required present=$REBOOT_REQUIRED"
    run_check "System Restart" decide_system_restart "$REBOOT_REQUIRED"

    # Check SSH config overrides
    SSH_CONFIG_OVERRIDES=$(grep "^Include" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')

    # Check SSH root login (handle both main config and overrides if they exist)
    if [ -n "$SSH_CONFIG_OVERRIDES" ] && [ -d "$(dirname "$SSH_CONFIG_OVERRIDES")" ]; then
        SSH_ROOT=$(grep "^PermitRootLogin" $SSH_CONFIG_OVERRIDES /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
    else
        SSH_ROOT=$(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
    fi
    if [ -z "$SSH_ROOT" ]; then
        SSH_ROOT="prohibit-password"
    fi
    DIAG_EVIDENCE="PermitRootLogin=$SSH_ROOT overrides=${SSH_CONFIG_OVERRIDES:-none}"
    run_check "SSH Root Login" decide_ssh_root "$SSH_ROOT"

    # Check SSH password authentication (handle both main config and overrides if they exist)
    if [ -n "$SSH_CONFIG_OVERRIDES" ] && [ -d "$(dirname "$SSH_CONFIG_OVERRIDES")" ]; then
        SSH_PASSWORD=$(grep "^PasswordAuthentication" $SSH_CONFIG_OVERRIDES /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
    else
        SSH_PASSWORD=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
    fi
    if [ -z "$SSH_PASSWORD" ]; then
        SSH_PASSWORD="yes"
    fi
    DIAG_EVIDENCE="PasswordAuthentication=$SSH_PASSWORD"
    run_check "SSH Password Auth" decide_ssh_password "$SSH_PASSWORD"

    # Check for default/unsecure SSH ports
    UNPRIVILEGED_PORT_START=$(sysctl -n net.ipv4.ip_unprivileged_port_start)
    SSH_PORT=""
    if [ -n "$SSH_CONFIG_OVERRIDES" ] && [ -d "$(dirname "$SSH_CONFIG_OVERRIDES")" ]; then
        SSH_PORT=$(grep "^Port" $SSH_CONFIG_OVERRIDES /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
    else
        SSH_PORT=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}')
    fi
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT="22"
    fi
    DIAG_EVIDENCE="Port=$SSH_PORT unprivileged_start=$UNPRIVILEGED_PORT_START"
    run_check "SSH Port" decide_ssh_port "$SSH_PORT" "$UNPRIVILEGED_PORT_START"

    # Firewall status
    FW_TOOL="none"
    FW_ACTIVE=""
    if command -v ufw >/dev/null 2>&1; then
        FW_TOOL="ufw"
        if ufw status | grep -qw "active"; then FW_ACTIVE="yes"; else FW_ACTIVE="no"; fi
    elif command -v firewall-cmd >/dev/null 2>&1; then
        FW_TOOL="firewalld"
        if firewall-cmd --state 2>/dev/null | grep -q "running"; then FW_ACTIVE="yes"; else FW_ACTIVE="no"; fi
    elif command -v iptables >/dev/null 2>&1; then
        FW_TOOL="iptables"
        if iptables -L -n | grep -q "Chain INPUT"; then FW_ACTIVE="yes"; else FW_ACTIVE="no"; fi
    elif command -v nft >/dev/null 2>&1; then
        FW_TOOL="nftables"
        if nft list ruleset | grep -q "table"; then FW_ACTIVE="yes"; else FW_ACTIVE="no"; fi
    fi
    case "$FW_TOOL" in
        ufw)       FW_NAME="Firewall Status (UFW)" ;;
        firewalld) FW_NAME="Firewall Status (firewalld)" ;;
        iptables)  FW_NAME="Firewall Status (iptables)" ;;
        nftables)  FW_NAME="Firewall Status (nftables)" ;;
        *)         FW_NAME="Firewall Status" ;;
    esac
    DIAG_EVIDENCE="tool=$FW_TOOL active=${FW_ACTIVE:-n/a}"
    run_check "$FW_NAME" decide_firewall "$FW_TOOL" "$FW_ACTIVE"

    # Check for unattended upgrades
    if dpkg -l | grep -q "unattended-upgrades"; then UU_INSTALLED=1; else UU_INSTALLED=0; fi
    DIAG_EVIDENCE="unattended-upgrades installed=$UU_INSTALLED"
    run_check "Unattended Upgrades" decide_unattended_upgrades "$UU_INSTALLED"

    # Check Intrusion Prevention Systems (Fail2ban or CrowdSec)
    IPS_INSTALLED=0
    IPS_ACTIVE=0
    IPS_NATIVE=0
    DOCKER_PRESENT=0
    DOCKER_RUNNING=0

    if dpkg -l | grep -q "fail2ban"; then
        IPS_NATIVE=1
        IPS_INSTALLED=1
        systemctl is-active fail2ban >/dev/null 2>&1 && IPS_ACTIVE=1
    fi
    if dpkg -l | grep -q "crowdsec"; then
        IPS_NATIVE=1
        IPS_INSTALLED=1
        systemctl is-active crowdsec >/dev/null 2>&1 && IPS_ACTIVE=1
    fi

    if command -v docker >/dev/null 2>&1; then
        DOCKER_PRESENT=1
        if systemctl is-active --quiet docker; then
            DOCKER_RUNNING=1
            if docker ps -a | awk '{print $2}' | grep -E "fail2ban|crowdsec" >/dev/null 2>&1; then
                IPS_INSTALLED=1
                docker ps | grep -E "fail2ban|crowdsec" >/dev/null 2>&1 && IPS_ACTIVE=1
            fi
        fi
    fi
    DIAG_EVIDENCE="installed=$IPS_INSTALLED active=$IPS_ACTIVE native=$IPS_NATIVE docker_present=$DOCKER_PRESENT docker_running=$DOCKER_RUNNING"
    run_check "Intrusion Prevention" decide_intrusion_prevention \
        "$IPS_INSTALLED" "$IPS_ACTIVE" "$IPS_NATIVE" "$DOCKER_PRESENT" "$DOCKER_RUNNING"

    # Check failed login attempts
    LOG_FILE="/var/log/auth.log"
    FAILED_LOGINS=0
    FL_EVALUABLE=1
    FL_SOURCE=""
    if [ -r "$LOG_FILE" ]; then
        FAILED_LOGINS=$(grep -c "Failed password" "$LOG_FILE" 2>/dev/null || echo 0)
        FL_SOURCE="$LOG_FILE"
    elif command -v journalctl >/dev/null 2>&1; then
        FAILED_LOGINS=$(journalctl -u ssh --since "24 hours ago" 2>/dev/null | grep -c "Failed password" || echo 0)
        FL_SOURCE="journalctl"
    else
        FL_EVALUABLE=0
    fi
    if [ "$FL_EVALUABLE" -eq 1 ]; then
        # Ensure FAILED_LOGINS is numeric and strip whitespace
        FAILED_LOGINS=$(echo "$FAILED_LOGINS" | tr -d '[:space:]')
        FAILED_LOGINS=$((10#${FAILED_LOGINS:-0}))
    fi
    DIAG_EVIDENCE="source=${FL_SOURCE:-none} evaluable=$FL_EVALUABLE count=$FAILED_LOGINS"
    run_check "Failed Logins" decide_failed_logins "$FL_EVALUABLE" "$FAILED_LOGINS"

    # Check system updates
    UPDATES=$(apt-get -s upgrade 2>/dev/null | grep -P '^\d+ upgraded' | cut -d" " -f1)
    if [ -z "$UPDATES" ]; then
        UPDATES=0
    fi
    DIAG_EVIDENCE="pending_updates=$UPDATES"
    run_check "System Updates" decide_system_updates "$UPDATES"

    # Check running services
    SERVICES=$(systemctl list-units --type=service --state=running | grep -c "loaded active running")
    DIAG_EVIDENCE="running_services=$SERVICES"
    run_check "Running Services" decide_running_services "$SERVICES"

    # Check ports using netstat or ss
    PORTS_EVALUABLE=1
    LISTENING_PORTS=""
    PORTS_TOOL="none"
    if command -v netstat >/dev/null 2>&1; then
        PORTS_TOOL="netstat"
        LISTENING_PORTS=$(netstat -tuln | grep LISTEN | awk '{print $4}')
    elif command -v ss >/dev/null 2>&1; then
        PORTS_TOOL="ss"
        LISTENING_PORTS=$(ss -tuln | grep LISTEN | awk '{print $5}')
    else
        PORTS_EVALUABLE=0
    fi

    PUBLIC_PORTS=""
    PORT_COUNT=0
    INTERNET_PORTS=0
    if [ "$PORTS_EVALUABLE" -eq 1 ] && [ -n "$LISTENING_PORTS" ]; then
        PUBLIC_PORTS=$(echo "$LISTENING_PORTS" | awk -F':' '{print $NF}' | sort -n | uniq | tr '\n' ',' | sed 's/,$//')
        PORT_COUNT=$(echo "$PUBLIC_PORTS" | tr ',' '\n' | wc -w)
        INTERNET_PORTS=$(echo "$PUBLIC_PORTS" | tr ',' '\n' | wc -w)
    fi
    DIAG_EVIDENCE="tool=$PORTS_TOOL evaluable=$PORTS_EVALUABLE total=$PORT_COUNT public=$INTERNET_PORTS ports=${PUBLIC_PORTS:-none}"
    run_check "Port Security" decide_port_security "$PORTS_EVALUABLE" "$PORT_COUNT" "$INTERNET_PORTS" "$PUBLIC_PORTS"

    # Check disk space usage
    DISK_TOTAL=$(df -h / | awk 'NR==2 {print $2}')
    DISK_USED=$(df -h / | awk 'NR==2 {print $3}')
    DISK_AVAIL=$(df -h / | awk 'NR==2 {print $4}')
    DISK_USAGE=$(df -h / | awk 'NR==2 {print int($5)}')
    DIAG_EVIDENCE="usage=${DISK_USAGE}% used=$DISK_USED total=$DISK_TOTAL avail=$DISK_AVAIL"
    run_check "Disk Usage" decide_disk_usage "$DISK_USAGE" "$DISK_USED" "$DISK_TOTAL" "$DISK_AVAIL"

    # Check memory usage
    MEM_TOTAL=$(free -h | awk '/^Mem:/ {print $2}')
    MEM_USED=$(free -h | awk '/^Mem:/ {print $3}')
    MEM_AVAIL=$(free -h | awk '/^Mem:/ {print $7}')
    MEM_USAGE=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2 * 100}')
    DIAG_EVIDENCE="usage=${MEM_USAGE}% used=$MEM_USED total=$MEM_TOTAL avail=$MEM_AVAIL"
    run_check "Memory Usage" decide_memory_usage "$MEM_USAGE" "$MEM_USED" "$MEM_TOTAL" "$MEM_AVAIL"

    # Check CPU usage
    CPU_CORES=$(nproc)
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print int($2)}')
    CPU_IDLE=$(top -bn1 | grep "Cpu(s)" | awk '{print int($8)}')
    CPU_LOAD=$(uptime | awk -F'load average:' '{ print $2 }' | awk -F',' '{ print $1 }' | tr -d ' ')
    DIAG_EVIDENCE="usage=${CPU_USAGE}% idle=${CPU_IDLE}% load=$CPU_LOAD cores=$CPU_CORES"
    run_check "CPU Usage" decide_cpu_usage "$CPU_USAGE" "$CPU_IDLE" "$CPU_LOAD" "$CPU_CORES"

    # Check sudo configuration
    if grep -q "^Defaults.*logfile" /etc/sudoers; then SUDO_LOG=1; else SUDO_LOG=0; fi
    DIAG_EVIDENCE="sudoers_logfile=$SUDO_LOG"
    run_check "Sudo Logging" decide_sudo_logging "$SUDO_LOG"

    # Check password policy
    if [ -f "/etc/security/pwquality.conf" ]; then
        if grep -q "minlen.*12" /etc/security/pwquality.conf; then
            PW_POLICY="strong"
        else
            PW_POLICY="weak"
        fi
    else
        PW_POLICY="none"
    fi
    DIAG_EVIDENCE="pwquality=$PW_POLICY"
    run_check "Password Policy" decide_password_policy "$PW_POLICY"

    # Check for suspicious SUID files
    COMMON_SUID_PATHS='^/usr/bin/|^/bin/|^/sbin/|^/usr/sbin/|^/usr/lib|^/usr/libexec'
    KNOWN_SUID_BINS='ping$|sudo$|mount$|umount$|su$|passwd$|chsh$|newgrp$|gpasswd$|chfn$'

    SUID_FILES=$(find / -type f -perm -4000 2>/dev/null | \
        grep -v -E "$COMMON_SUID_PATHS" | \
        grep -v -E "$KNOWN_SUID_BINS" | \
        wc -l)
    DIAG_EVIDENCE="suspicious_suid_count=$SUID_FILES"
    run_check "SUID Files" decide_suid_files "$SUID_FILES"

    # Add system information summary to report
    echo "================================" >> "$REPORT_FILE"
    echo "System Information Summary:" >> "$REPORT_FILE"
    echo "Hostname: $(hostname)" >> "$REPORT_FILE"
    echo "Kernel: $(uname -r)" >> "$REPORT_FILE"
    echo "OS: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)" >> "$REPORT_FILE"
    echo "CPU Cores: $(nproc)" >> "$REPORT_FILE"
    echo "Total Memory: $(free -h | awk '/^Mem:/ {print $2}')" >> "$REPORT_FILE"
    echo "Total Disk Space: $(df -h / | awk 'NR==2 {print $2}')" >> "$REPORT_FILE"
    echo "================================" >> "$REPORT_FILE"

    # Aligned summary of all verdicts from this run
    print_summary

    echo -e "\nVPS audit complete. Full report saved to $REPORT_FILE"
    echo -e "Review $REPORT_FILE for detailed recommendations."

    # Add summary to report
    echo "================================" >> "$REPORT_FILE"
    echo "End of VPS Audit Report" >> "$REPORT_FILE"
    echo "Please review all failed checks and implement the recommended fixes." >> "$REPORT_FILE"
}

# Run the audit only when executed directly; sourcing (e.g. from tests) exposes
# the functions without running an audit or creating a report.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
