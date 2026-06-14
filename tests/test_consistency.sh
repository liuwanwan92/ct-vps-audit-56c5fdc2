#!/usr/bin/env bash
#
# test_consistency.sh - Regression tests for vps-audit.sh
#
# Ensures terminal output, report file, and trace file are always consistent.
# Uses mock commands to simulate a VPS environment.
#
# Usage: ./tests/test_consistency.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_SCRIPT="$SCRIPT_DIR/../vps-audit.sh"

# ============================================================
# Test Framework
# ============================================================

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
FAIL_DETAILS=""
TEST_TMPDIR=""

pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo "  [PASS] $1"
}

fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    FAIL_DETAILS="${FAIL_DETAILS}\n  [FAIL] $1: $2"
    echo "  [FAIL] $1: $2"
}

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        pass "$desc"
    else
        fail "$desc" "expected '$expected', got '$actual'"
    fi
}

assert_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -qF "$needle"; then
        pass "$desc"
    else
        fail "$desc" "output does not contain '$needle'"
    fi
}

assert_not_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if ! echo "$haystack" | grep -qF "$needle"; then
        pass "$desc"
    else
        fail "$desc" "output should NOT contain '$needle'"
    fi
}

assert_ge() {
    local desc="$1" actual="$2" min="$3"
    if [ "$actual" -ge "$min" ]; then
        pass "$desc"
    else
        fail "$desc" "expected >= $min, got $actual"
    fi
}

assert_file_exists() {
    local desc="$1" filepath="$2"
    if [ -f "$filepath" ]; then
        pass "$desc"
    else
        fail "$desc" "file not found: $filepath"
    fi
}

# ============================================================
# Mock Environment Setup
# ============================================================

setup() {
    TEST_TMPDIR=$(mktemp -d)
    local mock_bin="$TEST_TMPDIR/bin"
    local mock_etc="$TEST_TMPDIR/etc"
    local mock_var="$TEST_TMPDIR/var"
    mkdir -p "$mock_bin" "$mock_etc/ssh" "$mock_etc/security" "$mock_var/run" "$mock_var/log"

    # --- Mock system files ---
    cat > "$mock_etc/os-release" <<'EOF'
PRETTY_NAME="Mock Linux 24.04 LTS"
NAME="Mock Linux"
VERSION_ID="24.04"
EOF

    cat > "$mock_etc/ssh/sshd_config" <<'EOF'
Port 2222
PermitRootLogin no
PasswordAuthentication no
EOF

    cat > "$mock_etc/sudoers" <<'EOF'
Defaults logfile=/var/log/sudo.log
EOF

    cat > "$mock_etc/security/pwquality.conf" <<'EOF'
minlen = 14
dcredit = -1
EOF

    # --- Mock commands ---

    cat > "$mock_bin/uptime" <<'MOCK'
#!/usr/bin/env bash
case "${1:-}" in
    -p) echo "up 2 hours, 30 minutes" ;;
    -s) echo "2026-06-15 10:00:00" ;;
    *)  echo " 12:30:00 up 2:30, 1 user, load average: 0.50, 0.45, 0.40" ;;
esac
MOCK

    cat > "$mock_bin/nproc" <<'MOCK'
#!/usr/bin/env bash
echo "4"
MOCK

    cat > "$mock_bin/lscpu" <<'MOCK'
#!/usr/bin/env bash
echo "Architecture: x86_64"
echo "Model name: Mock CPU @ 2.5GHz"
MOCK

    cat > "$mock_bin/free" <<'MOCK'
#!/usr/bin/env bash
if [ "${1:-}" = "-h" ]; then
    echo "               total        used        free      shared  buff/cache   available"
    echo "Mem:           8.0Gi       2.0Gi       4.0Gi       100Mi       2.0Gi       5.5Gi"
    echo "Swap:          2.0Gi          0B       2.0Gi"
else
    echo "               total        used        free      shared  buff/cache   available"
    echo "Mem:         8000000     2000000     4000000      100000     2000000     5500000"
    echo "Swap:        2000000           0     2000000"
fi
MOCK

    cat > "$mock_bin/df" <<'MOCK'
#!/usr/bin/env bash
echo "Filesystem      Size  Used Avail Use% Mounted on"
echo "/dev/sda1       100G   25G   75G  25% /"
MOCK

    cat > "$mock_bin/curl" <<'MOCK'
#!/usr/bin/env bash
echo "1.2.3.4"
MOCK

    cat > "$mock_bin/uname" <<'MOCK'
#!/usr/bin/env bash
case "${1:-}" in
    -r) echo "6.1.0-mock" ;;
    *)  echo "Linux" ;;
esac
MOCK

    cat > "$mock_bin/hostname" <<'MOCK'
#!/usr/bin/env bash
echo "mock-vps"
MOCK

    cat > "$mock_bin/systemctl" <<'MOCK'
#!/usr/bin/env bash
case "${1:-}" in
    is-active)
        case "${2:-}" in
            fail2ban|crowdsec) exit 1 ;;
            docker) exit 1 ;;
            *) exit 1 ;;
        esac
        ;;
    list-units)
        echo "  ssh.service loaded active running OpenSSH"
        echo "  cron.service loaded active running Cron"
        ;;
esac
MOCK

    cat > "$mock_bin/dpkg" <<'MOCK'
#!/usr/bin/env bash
echo ""
MOCK

    cat > "$mock_bin/apt-get" <<'MOCK'
#!/usr/bin/env bash
echo "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded."
MOCK

    cat > "$mock_bin/top" <<'MOCK'
#!/usr/bin/env bash
echo "%Cpu(s): 15.0 us,  5.0 sy,  0.0 ni, 78.0 id,  1.0 wa,  0.0 hi,  1.0 si,  0.0 st"
MOCK

    cat > "$mock_bin/find" <<'MOCK'
#!/usr/bin/env bash
echo ""
MOCK

    cat > "$mock_bin/ss" <<'MOCK'
#!/usr/bin/env bash
echo "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port"
echo "tcp   LISTEN 0      128    0.0.0.0:2222         0.0.0.0:*"
MOCK

    cat > "$mock_bin/sysctl" <<'MOCK'
#!/usr/bin/env bash
echo "1024"
MOCK

    # NOTE: We do NOT mock grep — the real grep works fine with mock files.
    # Mocking grep would cause infinite recursion since command -v grep finds the mock.

    chmod +x "$mock_bin"/*

    # Export env vars for the audit script
    export VPS_AUDIT_OS_RELEASE="$mock_etc/os-release"
    export VPS_AUDIT_SSHD_CONFIG="$mock_etc/ssh/sshd_config"
    export VPS_AUDIT_SUDOERS="$mock_etc/sudoers"
    export VPS_AUDIT_PWQUALITY="$mock_etc/security/pwquality.conf"
    export VPS_AUDIT_REBOOT_FLAG="$mock_var/run/reboot-required"
    export VPS_AUDIT_AUTH_LOG="$mock_var/log/auth.log"

    # Prepend mock bin to PATH
    export PATH="$mock_bin:$PATH"

    # Use a temp directory for output files
    export AUDIT_OUTPUT_DIR="$TEST_TMPDIR/output"
    mkdir -p "$AUDIT_OUTPUT_DIR"
}

teardown() {
    if [ -n "$TEST_TMPDIR" ] && [ -d "$TEST_TMPDIR" ]; then
        rm -rf "$TEST_TMPDIR"
    fi
}

# Run the audit script and capture outputs.
# Sets: TERMINAL_OUTPUT, REPORT_FILE_PATH, TRACE_FILE_PATH
run_audit() {
    local extra_args="${1:-}"
    local output_file="$TEST_TMPDIR/terminal_output.txt"

    # Run from the script's directory so relative paths work.
    # Use timeout to prevent hanging on unexpected prompts or network calls.
    (cd "$SCRIPT_DIR/.." && timeout 30 bash vps-audit.sh $extra_args) > "$output_file" 2>&1 || true

    TERMINAL_OUTPUT=$(cat "$output_file")

    # Find report and trace files
    REPORT_FILE_PATH=$(ls "$AUDIT_OUTPUT_DIR"/vps-audit-report-*.txt 2>/dev/null | head -1)
    TRACE_FILE_PATH=$(ls "$AUDIT_OUTPUT_DIR"/vps-audit-report-*.trace.log 2>/dev/null | head -1)

    # Fallback: check current directory
    if [ -z "$REPORT_FILE_PATH" ]; then
        REPORT_FILE_PATH=$(ls "$SCRIPT_DIR"/../vps-audit-report-*.txt 2>/dev/null | head -1)
    fi
    if [ -z "$TRACE_FILE_PATH" ]; then
        TRACE_FILE_PATH=$(ls "$SCRIPT_DIR"/../vps-audit-report-*.trace.log 2>/dev/null | head -1)
    fi

    REPORT_CONTENT=""
    TRACE_CONTENT=""
    if [ -n "$REPORT_FILE_PATH" ] && [ -f "$REPORT_FILE_PATH" ]; then
        REPORT_CONTENT=$(cat "$REPORT_FILE_PATH")
    fi
    if [ -n "$TRACE_FILE_PATH" ] && [ -f "$TRACE_FILE_PATH" ]; then
        TRACE_CONTENT=$(cat "$TRACE_FILE_PATH")
    fi
}

# ============================================================
# Test Cases
# ============================================================

test_check_count_consistency() {
    echo "TEST: terminal/report/trace check counts must match"
    setup
    run_audit

    # Count checks in trace (authoritative)
    local trace_count=0
    if [ -n "$TRACE_CONTENT" ]; then
        trace_count=$(echo "$TRACE_CONTENT" | grep -c '^\[SEQ:' || true)
    fi

    # Count checks in report
    local report_count=0
    if [ -n "$REPORT_CONTENT" ]; then
        report_count=$(echo "$REPORT_CONTENT" | grep -cE '^\[(PASS|WARN|FAIL)\]' || true)
    fi

    # Count checks in terminal output
    local terminal_count=0
    if [ -n "$TERMINAL_OUTPUT" ]; then
        terminal_count=$(echo "$TERMINAL_OUTPUT" | grep -cE '\[(PASS|WARN|FAIL)\]' || true)
    fi

    assert_ge "trace has checks" "$trace_count" 1
    assert_eq "report count == trace count" "$trace_count" "$report_count"
    assert_eq "terminal count == trace count" "$trace_count" "$terminal_count"

    teardown
}

test_check_order_consistency() {
    echo "TEST: check order must be identical in trace and report"
    setup
    run_audit

    if [ -z "$TRACE_CONTENT" ] || [ -z "$REPORT_CONTENT" ]; then
        fail "check_order_consistency" "trace or report is empty"
        teardown
        return
    fi

    # Extract check names from trace (in order) — trace uses | as field separator
    local trace_names
    trace_names=$(echo "$TRACE_CONTENT" | grep '^\[SEQ:' | sed 's/\[SEQ:[0-9]*\] name=\([^|]*\).*/\1/')

    # Extract check names from report (in order) — strip status prefix, then strip " - message"
    local report_names
    report_names=$(echo "$REPORT_CONTENT" | grep -E '^\[(PASS|WARN|FAIL)\]' | sed 's/^\[[A-Z]*\] //' | sed 's/ - .*//')

    assert_eq "check names order matches" "$trace_names" "$report_names"

    teardown
}

test_check_status_consistency() {
    echo "TEST: each check's status must match across trace and report"
    setup
    run_audit

    if [ -z "$TRACE_CONTENT" ] || [ -z "$REPORT_CONTENT" ]; then
        fail "check_status_consistency" "trace or report is empty"
        teardown
        return
    fi

    local trace_statuses report_statuses
    trace_statuses=$(echo "$TRACE_CONTENT" | grep '^\[SEQ:' | sed 's/.*|status=\([^|]*\).*/\1/')
    report_statuses=$(echo "$REPORT_CONTENT" | grep -E '^\[(PASS|WARN|FAIL)\]' | sed 's/^\[\([A-Z]*\)\].*/\1/')

    assert_eq "statuses match across outputs" "$trace_statuses" "$report_statuses"

    teardown
}

test_no_duplicate_checks() {
    echo "TEST: no check name should appear more than once"
    setup
    run_audit

    if [ -z "$TRACE_CONTENT" ]; then
        fail "no_duplicate_checks" "trace is empty"
        teardown
        return
    fi

    local check_names dupes
    check_names=$(echo "$TRACE_CONTENT" | grep '^\[SEQ:' | sed 's/\[SEQ:[0-9]*\] name=\([^|]*\).*/\1/')
    dupes=$(echo "$check_names" | sort | uniq -d)

    if [ -z "$dupes" ]; then
        pass "no duplicate check names"
    else
        fail "no_duplicate_checks" "duplicates found: $dupes"
    fi

    teardown
}

test_no_duplicate_system_info() {
    echo "TEST: system information section appears exactly once in report"
    setup
    run_audit

    if [ -z "$REPORT_CONTENT" ]; then
        fail "no_duplicate_system_info" "report is empty"
        teardown
        return
    fi

    local count
    count=$(echo "$REPORT_CONTENT" | grep -c "System Information Summary" || true)
    assert_eq "no System Information Summary block" "0" "$count"

    count=$(echo "$REPORT_CONTENT" | grep -c "System Information$" || true)
    assert_eq "System Information header appears once" "1" "$count"

    teardown
}

test_no_duplicate_uptime() {
    echo "TEST: uptime is measured only once"
    setup
    run_audit

    if [ -z "$TRACE_CONTENT" ]; then
        fail "no_duplicate_uptime" "trace is empty"
        teardown
        return
    fi

    local raw_uptime_count
    raw_uptime_count=$(echo "$TRACE_CONTENT" | grep -c '^\[RAW\].*cmd=uptime -p' || true)
    assert_eq "uptime -p called exactly once" "1" "$raw_uptime_count"

    teardown
}

test_journalctl_pipe() {
    echo "TEST: journalctl must be piped to grep, not used as filename"
    setup

    # Static analysis: check the source code
    local source_content
    source_content=$(cat "$AUDIT_SCRIPT")

    # Should NOT contain the broken pattern: grep ... "journalctl
    local broken_pattern
    broken_pattern=$(echo "$source_content" | grep -c 'grep.*"journalctl' || true)
    assert_eq "no broken journalctl-as-filename pattern" "0" "$broken_pattern"

    # Should contain the fixed pattern: journalctl ... | grep
    local fixed_pattern
    fixed_pattern=$(echo "$source_content" | grep -c 'journalctl.*|.*grep' || true)
    assert_ge "journalctl piped to grep exists" "$fixed_pattern" 1

    teardown
}

test_result_summary_present() {
    echo "TEST: result summary with counts must appear in terminal and report"
    setup
    run_audit

    assert_contains "terminal has Audit Summary" "$TERMINAL_OUTPUT" "Audit Summary"

    if [ -n "$REPORT_CONTENT" ]; then
        assert_contains "report has Audit Summary" "$REPORT_CONTENT" "Audit Summary"
    else
        fail "report has Audit Summary" "report is empty"
    fi

    teardown
}

test_missing_commands_no_crash() {
    echo "TEST: missing ss/netstat should not crash the script"
    setup

    # Remove ss and netstat mocks
    rm -f "$TEST_TMPDIR/bin/ss" "$TEST_TMPDIR/bin/netstat"

    run_audit

    # Script should still complete (exit code 0 or at least produce output)
    assert_contains "script completes despite missing commands" "$TERMINAL_OUTPUT" "audit complete"

    # Port Security check should report the failure
    if [ -n "$REPORT_CONTENT" ]; then
        assert_contains "port check reports missing tool" "$REPORT_CONTENT" "Port Security"
    fi

    teardown
}

test_trace_file_created() {
    echo "TEST: trace file is created with valid structure"
    setup
    run_audit

    if [ -z "$TRACE_FILE_PATH" ]; then
        fail "trace_file_created" "trace file not found"
        teardown
        return
    fi

    assert_file_exists "trace file exists" "$TRACE_FILE_PATH"

    assert_contains "trace has RUN entry" "$TRACE_CONTENT" "[RUN]"
    assert_contains "trace has SUMMARY entry" "$TRACE_CONTENT" "[SUMMARY]"
    assert_contains "trace has SEQ entries" "$TRACE_CONTENT" "[SEQ:"

    teardown
}

test_diagnose_mode() {
    echo "TEST: --diagnose mode runs and reports consistency"
    setup
    run_audit "--diagnose"

    assert_contains "diagnose shows Diagnostics" "$TERMINAL_OUTPUT" "Diagnostics"
    assert_contains "diagnose reports no issues" "$TERMINAL_OUTPUT" "No inconsistencies found"

    teardown
}

test_run_id_in_outputs() {
    echo "TEST: RUN_ID appears in terminal, report, and trace"
    setup
    run_audit

    if [ -z "$TRACE_CONTENT" ]; then
        fail "run_id_in_outputs" "trace is empty"
        teardown
        return
    fi

    # Extract RUN_ID from trace
    local run_id
    run_id=$(echo "$TRACE_CONTENT" | grep '^\[RUN\]' | head -1 | sed 's/.*id=\([^ ]*\).*/\1/')

    if [ -z "$run_id" ]; then
        fail "run_id_in_outputs" "could not extract RUN_ID from trace"
        teardown
        return
    fi

    assert_contains "RUN_ID in terminal" "$TERMINAL_OUTPUT" "$run_id"

    if [ -n "$REPORT_CONTENT" ]; then
        assert_contains "RUN_ID in report" "$REPORT_CONTENT" "$run_id"
    else
        fail "RUN_ID in report" "report is empty"
    fi

    teardown
}

# ============================================================
# Test Runner
# ============================================================

echo "============================================"
echo " VPS Audit - Consistency Regression Tests"
echo "============================================"
echo ""

# Discover and run all test functions
for test_func in $(declare -F | awk '{print $3}' | grep '^test_' | sort); do
    TESTS_RUN=$((TESTS_RUN + 1))
    $test_func
    echo ""
done

echo "============================================"
echo " Results: $TESTS_RUN tests, $TESTS_PASSED passed, $TESTS_FAILED failed"
echo "============================================"

if [ "$TESTS_FAILED" -gt 0 ]; then
    echo ""
    echo " Failed tests:"
    echo -e "$FAIL_DETAILS"
    echo ""
    exit 1
fi

echo ""
echo " All tests passed!"
exit 0
