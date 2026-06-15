#!/usr/bin/env bash
# tests/test_consistency.sh
#
# Regression tests for vps-audit.sh — verifies that "real-time output" (stdout)
# and "final report" (file) are structurally consistent: same checks, same order,
# same statuses, no duplicates, no drift.
#
# Usage:
#   ./tests/run_tests.sh                    # run all tests
#   ./tests/run_tests.sh --verbose          # show passing test details
#   ./tests/run_tests.sh tee_passthrough    # run tests matching pattern
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
AUDIT_SCRIPT="$PROJECT_DIR/vps-audit.sh"
FIXTURE_SCRIPT="$SCRIPT_DIR/fixtures/audit_fixture.sh"

# ── Test framework ────────────────────────────────────────────────────

PASS_COUNT=0
FAIL_COUNT=0
CURRENT_TEST=""
VERBOSE=0
FILTER=""
FAILURES=()

for arg in "$@"; do
    case "$arg" in
        --verbose|-v) VERBOSE=1 ;;
        *) FILTER="$arg" ;;
    esac
done

run_test() {
    local name="$1"
    CURRENT_TEST="$name"
    if [ -n "$FILTER" ] && [[ ! "$name" == *"$FILTER"* ]]; then
        return 0
    fi
    echo -n "  [$(( PASS_COUNT + FAIL_COUNT + 1 ))] $name ... "
}

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "PASS"
    if [ "$VERBOSE" -eq 1 ] && [ -n "${1:-}" ]; then
        echo "       $1"
    fi
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "FAIL"
    FAILURES+=("$CURRENT_TEST")
    local indent="       "
    while IFS= read -r line; do
        echo "${indent}$line"
    done <<< "$1"
}

diag() {
    echo "  DIAG [$CURRENT_TEST]"
    local indent="    "
    while IFS= read -r line; do
        echo "${indent}${line}"
    done <<< "$1"
}

# ── Helpers ───────────────────────────────────────────────────────────

strip_ansi() {
    sed 's/\x1b\[[0-9;]*m//g'
}

# Extract "[STATUS] TestName - Message" lines (the canonical check-result format)
extract_checks() {
    grep -E '^\[(PASS|WARN|FAIL)\] ' || true
}

# Extract just the test name from check lines (handles multi-word names like "SSH Root Login")
extract_check_names() {
    extract_checks | sed 's/^\[[A-Z]*\] \(.*\) - .*/\1/'
}

# Extract status + full test name pairs
extract_status_name() {
    extract_checks | sed 's/^\[\([A-Z]*\)\] \(.*\) - .*/\1 \2/'
}

# Find the newest report file in a directory
find_report() {
    local dir="$1"
    find "$dir" -name 'vps-audit-report-*.txt' -type f 2>/dev/null | sort -r | head -1
}

# Run the audit script with fixture environment.
# Args: [--piped|--tee <file>|--non-interactive|--redirected]
# Captures stdout to $STDOUT_FILE, report path to $REPORT_PATH, stderr to $STDERR_FILE.
run_audit() {
    local mode="${1:-normal}"
    local tee_file="${2:-}"
    local work_dir
    work_dir=$(mktemp -d)

    local env_vars=(
        "AUDIT_FIXTURE_DIR=$FIXTURE_DIR"
        "AUDIT_SSHD_CONFIG=$FIXTURE_DIR/etc/ssh/sshd_config"
        "AUDIT_SUDOERS=$FIXTURE_DIR/etc/sudoers"
        "AUDIT_PWQUALITY=$FIXTURE_DIR/etc/security/pwquality.conf"
        "AUDIT_REBOOT_REQ=$FIXTURE_DIR/var/run/reboot-required"
        "AUDIT_AUTH_LOG=$FIXTURE_DIR/var/log/auth.log"
        "BASH_ENV=$FIXTURE_SCRIPT"
    )

    case "$mode" in
        normal)
            env "${env_vars[@]}" bash "$AUDIT_SCRIPT" > "$work_dir/stdout.txt" 2>"$work_dir/stderr.txt"
            ;;
        piped)
            # Simulate piping: stdout is not a terminal
            env "${env_vars[@]}" bash "$AUDIT_SCRIPT" 2>"$work_dir/stderr.txt" \
                | cat > "$work_dir/stdout.txt"
            ;;
        tee)
            env "${env_vars[@]}" bash "$AUDIT_SCRIPT" 2>"$work_dir/stderr.txt" \
                | tee "$tee_file" > "$work_dir/stdout.txt"
            ;;
        non-interactive)
            env "${env_vars[@]}" bash "$AUDIT_SCRIPT" < /dev/null \
                > "$work_dir/stdout.txt" 2>"$work_dir/stderr.txt"
            ;;
        redirected)
            env "${env_vars[@]}" bash "$AUDIT_SCRIPT" \
                > "$work_dir/stdout.txt" 2>"$work_dir/stderr.txt" < /dev/null
            ;;
    esac

    STDOUT_FILE="$work_dir/stdout.txt"
    STDERR_FILE="$work_dir/stderr.txt"
    REPORT_PATH=$(find_report "$PROJECT_DIR")
    WORK_DIR="$work_dir"
}

# ── Fixture setup ─────────────────────────────────────────────────────

FIXTURE_DIR=$(mktemp -d)
export FIXTURE_DIR

# Create fixture files (same as audit_fixture.sh, but needed here for test-level checks)
mkdir -p "$FIXTURE_DIR/etc/ssh" "$FIXTURE_DIR/var/log" "$FIXTURE_DIR/etc/security"
cat > "$FIXTURE_DIR/etc/ssh/sshd_config" <<'SSHD'
Port 2222
PermitRootLogin no
PasswordAuthentication no
SSHD
cat > "$FIXTURE_DIR/etc/sudoers" <<'SUDO'
Defaults logfile=/var/log/sudo.log
SUDO
cat > "$FIXTURE_DIR/etc/security/pwquality.conf" <<'PWQ'
minlen = 12
PWQ
cat > "$FIXTURE_DIR/etc/os-release" <<'OSR'
PRETTY_NAME="Fixture Test OS 1.0"
OSR
cat > "$FIXTURE_DIR/var/log/auth.log" <<'AUTH'
Jan  1 00:00:01 host sshd[1]: Failed password for root from 1.2.3.4 port 22
Jan  1 00:00:02 host sshd[2]: Failed password for admin from 1.2.3.5 port 22
Jan  1 00:00:03 host sshd[3]: Accepted password for user from 1.2.3.6 port 22
AUTH

# Clean up any stale report files from prior runs
rm -f "$PROJECT_DIR"/vps-audit-report-*.txt

echo ""
echo "========================================"
echo " vps-audit Consistency Regression Tests"
echo "========================================"
echo ""

# ══════════════════════════════════════════════════════════════════════
#  T01 — stdout and report contain the same number of check results
# ══════════════════════════════════════════════════════════════════════
run_test "stdout_report_check_count_matches"
run_audit "normal"

STDOUT_CHECKS=$(strip_ansi < "$STDOUT_FILE" | extract_checks | wc -l | tr -d ' ')
REPORT_CHECKS=$(extract_checks < "$REPORT_PATH" | wc -l | tr -d ' ')

if [ "$STDOUT_CHECKS" -eq "$REPORT_CHECKS" ] && [ "$STDOUT_CHECKS" -gt 0 ]; then
    pass "both have $STDOUT_CHECKS check results"
else
    fail "stdout=$STDOUT_CHECKS checks, report=$REPORT_CHECKS checks"
    diag "stdout checks:
$(strip_ansi < "$STDOUT_FILE" | extract_checks)
report checks:
$(extract_checks < "$REPORT_PATH")"
fi

# ══════════════════════════════════════════════════════════════════════
#  T02 — every stdout check line appears verbatim (sans ANSI) in report
# ══════════════════════════════════════════════════════════════════════
run_test "every_stdout_check_in_report"
run_audit "normal"

STDOUT_LINES=$(strip_ansi < "$STDOUT_FILE" | extract_checks)
REPORT_LINES=$(extract_checks < "$REPORT_PATH")
ALL_MATCH=true
MISMATCH_DIAG=""
LINE_NUM=0

while IFS= read -r line; do
    LINE_NUM=$((LINE_NUM + 1))
    [ -z "$line" ] && continue
    if ! echo "$REPORT_LINES" | grep -qxF "$line"; then
        ALL_MATCH=false
        MISMATCH_DIAG+="line $LINE_NUM in stdout not found in report:
  stdout: '$line'
"
    fi
done <<< "$STDOUT_LINES"

if $ALL_MATCH; then
    pass "all $LINE_NUM stdout checks found in report"
else
    fail "$MISMATCH_DIAG"
    diag "full report content:
$REPORT_LINES"
fi

# ══════════════════════════════════════════════════════════════════════
#  T03 — check results appear in the same order in stdout and report
# ══════════════════════════════════════════════════════════════════════
run_test "check_order_identical"
run_audit "normal"

STDOUT_NAMES=$(strip_ansi < "$STDOUT_FILE" | extract_check_names)
REPORT_NAMES=$(extract_check_names < "$REPORT_PATH")

if [ "$STDOUT_NAMES" = "$REPORT_NAMES" ]; then
    pass "order matches"
else
    fail "check ordering differs between stdout and report"
    diag "stdout order:
$STDOUT_NAMES
report order:
$REPORT_NAMES
diff:
$(diff <(echo "$STDOUT_NAMES") <(echo "$REPORT_NAMES") || true)"
fi

# ══════════════════════════════════════════════════════════════════════
#  T04 — no duplicate check names in report
# ══════════════════════════════════════════════════════════════════════
run_test "no_duplicate_checks_in_report"
run_audit "normal"

REPORT_NAMES=$(extract_check_names < "$REPORT_PATH")
DUPES=$(echo "$REPORT_NAMES" | sort | uniq -d)

if [ -z "$DUPES" ]; then
    pass "no duplicates in report"
else
    fail "duplicate check(s) in report file:
$DUPES"
    diag "all report check names (in order):
$REPORT_NAMES"
fi

# ══════════════════════════════════════════════════════════════════════
#  T05 — no duplicate check names in stdout
# ══════════════════════════════════════════════════════════════════════
run_test "no_duplicate_checks_in_stdout"
run_audit "normal"

STDOUT_NAMES=$(strip_ansi < "$STDOUT_FILE" | extract_check_names)
DUPES=$(echo "$STDOUT_NAMES" | sort | uniq -d)

if [ -z "$DUPES" ]; then
    pass "no duplicates in stdout"
else
    fail "duplicate check(s) in stdout:
$DUPES"
    diag "all stdout check names (in order):
$STDOUT_NAMES"
fi

# ══════════════════════════════════════════════════════════════════════
#  T06 — status tags (PASS/WARN/FAIL) match per check between streams
# ══════════════════════════════════════════════════════════════════════
run_test "status_tags_match"
run_audit "normal"

STDOUT_SN=$(strip_ansi < "$STDOUT_FILE" | extract_status_name)
REPORT_SN=$(extract_status_name < "$REPORT_PATH")

if [ "$STDOUT_SN" = "$REPORT_SN" ]; then
    pass "all statuses match"
else
    fail "status mismatch for one or more checks"
    diag "stdout (STATUS NAME):
$STDOUT_SN
report (STATUS NAME):
$REPORT_SN
diff:
$(diff <(echo "$STDOUT_SN") <(echo "$REPORT_SN") || true)"
fi

# ══════════════════════════════════════════════════════════════════════
#  T07 — tee passthrough: captured stdout is byte-identical
# ══════════════════════════════════════════════════════════════════════
run_test "tee_passthrough_consistency"

# Clean stale reports before each run
rm -f "$PROJECT_DIR"/vps-audit-report-*.txt
run_audit "normal"
# Strip timestamps and report filenames for stable comparison
NORMAL_STDOUT=$(strip_ansi < "$STDOUT_FILE" | sed 's/[0-9]\{8\}_[0-9]\{6\}/TS/g; s/Starting audit at .*/Starting audit at TS/')
rm -f "$PROJECT_DIR"/vps-audit-report-*.txt

TEE_OUT=$(mktemp)
run_audit "tee" "$TEE_OUT"
TEE_STDOUT=$(strip_ansi < "$TEE_OUT" | sed 's/[0-9]\{8\}_[0-9]\{6\}/TS/g; s/Starting audit at .*/Starting audit at TS/')

if [ "$NORMAL_STDOUT" = "$TEE_STDOUT" ]; then
    pass "tee stdout == direct stdout (timestamps normalized)"
else
    fail "tee mode produces different stdout than direct execution"
    diag "diff (direct vs tee):
$(diff <(echo "$NORMAL_STDOUT") <(echo "$TEE_STDOUT") || true)"
fi
rm -f "$TEE_OUT"

# ══════════════════════════════════════════════════════════════════════
#  T08 — tee mode produces the same report file content
# ══════════════════════════════════════════════════════════════════════
run_test "tee_report_file_unchanged"

rm -f "$PROJECT_DIR"/vps-audit-report-*.txt
run_audit "normal"
NORMAL_REPORT=$(cat "$REPORT_PATH")

rm -f "$PROJECT_DIR"/vps-audit-report-*.txt
TEE_OUT=$(mktemp)
run_audit "tee" "$TEE_OUT"
TEE_REPORT=$(cat "$REPORT_PATH")

# Strip timestamps for comparison (first 3 lines contain date)
NORMAL_REPORT_NT=$(echo "$NORMAL_REPORT" | sed 's/[0-9]\{8\}_[0-9]\{6\}/TIMESTAMP/g; s/Starting audit at .*/Starting audit at TIMESTAMP/')
TEE_REPORT_NT=$(echo "$TEE_REPORT" | sed 's/[0-9]\{8\}_[0-9]\{6\}/TIMESTAMP/g; s/Starting audit at .*/Starting audit at TIMESTAMP/')

if [ "$NORMAL_REPORT_NT" = "$TEE_REPORT_NT" ]; then
    pass "report file identical in tee and direct modes"
else
    fail "report file differs between tee and direct modes"
    diag "diff:
$(diff <(echo "$NORMAL_REPORT_NT") <(echo "$TEE_REPORT_NT") || true)"
fi
rm -f "$TEE_OUT"

# ══════════════════════════════════════════════════════════════════════
#  T09 — piped (non-terminal) stdout text matches report content
# ══════════════════════════════════════════════════════════════════════
run_test "piped_stdout_text_matches_report"
rm -f "$PROJECT_DIR"/vps-audit-report-*.txt
run_audit "piped"

PIPED_CHECKS=$(strip_ansi < "$STDOUT_FILE" | extract_checks)
REPORT_CHECKS=$(extract_checks < "$REPORT_PATH")

if [ "$PIPED_CHECKS" = "$REPORT_CHECKS" ]; then
    pass "piped stdout checks == report checks"
else
    fail "piped stdout differs from report"
    diag "piped stdout:
$PIPED_CHECKS
report:
$REPORT_CHECKS
diff:
$(diff <(echo "$PIPED_CHECKS") <(echo "$REPORT_CHECKS") || true)"
fi

# ══════════════════════════════════════════════════════════════════════
#  T10 — non-interactive execution (stdin closed) produces all checks
# ══════════════════════════════════════════════════════════════════════
run_test "non_interactive_execution"
rm -f "$PROJECT_DIR"/vps-audit-report-*.txt
run_audit "non-interactive"

NI_CHECKS=$(strip_ansi < "$STDOUT_FILE" | extract_checks | wc -l | tr -d ' ')
REPORT_NI=$(extract_checks < "$REPORT_PATH" | wc -l | tr -d ' ')

if [ "$NI_CHECKS" -gt 0 ] && [ "$NI_CHECKS" -eq "$REPORT_NI" ]; then
    pass "non-interactive: $NI_CHECKS checks in both streams"
else
    fail "non-interactive mode: stdout=$NI_CHECKS, report=$REPORT_NI"
    diag "stderr:
$(cat "$STDERR_FILE")"
fi

# ══════════════════════════════════════════════════════════════════════
#  T11 — uptime is not duplicated in the report file
#        (catches the L60 print_info + L99-102 direct echo double-write)
# ══════════════════════════════════════════════════════════════════════
run_test "no_duplicate_uptime_in_report"
rm -f "$PROJECT_DIR"/vps-audit-report-*.txt
run_audit "normal"

UPTIME_LINES=$(grep -ci 'uptime' "$REPORT_PATH" || echo 0)

if [ "$UPTIME_LINES" -le 1 ]; then
    pass "uptime appears at most once ($UPTIME_LINES occurrence)"
else
    fail "uptime appears $UPTIME_LINES times in report — likely double-write"
    diag "matching lines:
$(grep -i 'uptime' "$REPORT_PATH" | sed 's/^/  /')"
fi

# ══════════════════════════════════════════════════════════════════════
#  T12 — System Information Summary block does not duplicate data
#        (catches the L407-415 summary re-fetching already-reported values)
# ══════════════════════════════════════════════════════════════════════
run_test "no_duplicate_sysinfo_in_report"
rm -f "$PROJECT_DIR"/vps-audit-report-*.txt
run_audit "normal"

# Count lines matching "Hostname:" — appears once in print_info,
# should NOT appear again in the "System Information Summary" block
HOSTNAME_COUNT=$(grep -c '^Hostname:' "$REPORT_PATH" || echo 0)
KERNEL_COUNT=$(grep -c '^Kernel' "$REPORT_PATH" || echo 0)

DUPES_FOUND=""
[ "$HOSTNAME_COUNT" -gt 1 ] && DUPES_FOUND+="Hostname: appears $HOSTNAME_COUNT times
"
[ "$KERNEL_COUNT" -gt 1 ] && DUPES_FOUND+="Kernel: appears $KERNEL_COUNT times
"

if [ -z "$DUPES_FOUND" ]; then
    pass "no duplicated system info fields"
else
    fail "system info fields duplicated in report:
$DUPES_FOUND"
    diag "full report:
$(cat "$REPORT_PATH" | sed 's/^/  /')"
fi

# ══════════════════════════════════════════════════════════════════════
#  T13 — PORT_COUNT and INTERNET_PORTS are independently computed
#        (catches the L314-315 bug where both use identical expressions)
# ══════════════════════════════════════════════════════════════════════
run_test "port_count_vs_internet_ports"
rm -f "$PROJECT_DIR"/vps-audit-report-*.txt
run_audit "normal"

PORT_LINE=$(grep 'Total:' "$REPORT_PATH" || echo "")
if [ -n "$PORT_LINE" ]; then
    TOTAL_VAL=$(echo "$PORT_LINE" | sed 's/.*Total: \([0-9]*\).*/\1/')
    PUBLIC_VAL=$(echo "$PORT_LINE" | sed 's/.*Public: \([0-9]*\).*/\1/')

    if [ "$TOTAL_VAL" = "$PUBLIC_VAL" ]; then
        fail "PORT_COUNT ($TOTAL_VAL) == INTERNET_PORTS ($PUBLIC_VAL) — computed identically (L314-315 bug)"
        diag "line: $PORT_LINE
These should be independently computed metrics."
    else
        pass "PORT_COUNT=$TOTAL_VAL != INTERNET_PORTS=$PUBLIC_VAL"
    fi
else
    pass "no Port Security line with Total/Public found (port check took different path)"
fi

# ══════════════════════════════════════════════════════════════════════
#  T14 — multiple runs produce identical check results (determinism)
# ══════════════════════════════════════════════════════════════════════
run_test "multi_run_determinism"

REPORTS_TEXT=()
for i in 1 2 3; do
    rm -f "$PROJECT_DIR"/vps-audit-report-*.txt
    run_audit "normal"
    # Extract only the check-result lines (skip timestamps and system info)
    CHECKS=$(extract_checks < "$REPORT_PATH" | sort)
    REPORTS_TEXT+=("$CHECKS")
    sleep 1  # ensure different timestamp
done

if [ "${REPORTS_TEXT[0]}" = "${REPORTS_TEXT[1]}" ] && \
   [ "${REPORTS_TEXT[1]}" = "${REPORTS_TEXT[2]}" ]; then
    pass "3 runs produced identical check results"
else
    fail "check results differ across runs"
    diag "run 1:
${REPORTS_TEXT[0]}
run 2:
${REPORTS_TEXT[1]}
run 3:
${REPORTS_TEXT[2]}"
fi

# ══════════════════════════════════════════════════════════════════════
#  T15 — all three status types (PASS/WARN/FAIL) are exercised
# ══════════════════════════════════════════════════════════════════════
run_test "all_three_statuses_covered"
rm -f "$PROJECT_DIR"/vps-audit-report-*.txt
run_audit "normal"

REPORT_CHECKS=$(extract_checks < "$REPORT_PATH")
STDOUT_CHECKS=$(strip_ansi < "$STDOUT_FILE" | extract_checks)

HAS_PASS_R=$(echo "$REPORT_CHECKS" | grep -c '^\[PASS\]' || echo 0)
HAS_WARN_R=$(echo "$REPORT_CHECKS" | grep -c '^\[WARN\]' || echo 0)
HAS_FAIL_R=$(echo "$REPORT_CHECKS" | grep -c '^\[FAIL\]' || echo 0)

HAS_PASS_S=$(echo "$STDOUT_CHECKS" | grep -c '^\[PASS\]' || echo 0)
HAS_WARN_S=$(echo "$STDOUT_CHECKS" | grep -c '^\[WARN\]' || echo 0)
HAS_FAIL_S=$(echo "$STDOUT_CHECKS" | grep -c '^\[FAIL\]' || echo 0)

MISSING=""
[ "$HAS_PASS_R" -eq 0 ] && MISSING+="report missing PASS; "
[ "$HAS_WARN_R" -eq 0 ] && MISSING+="report missing WARN; "
[ "$HAS_FAIL_R" -eq 0 ] && MISSING+="report missing FAIL; "
[ "$HAS_PASS_S" -eq 0 ] && MISSING+="stdout missing PASS; "
[ "$HAS_WARN_S" -eq 0 ] && MISSING+="stdout missing WARN; "
[ "$HAS_FAIL_S" -eq 0 ] && MISSING+="stdout missing FAIL; "

if [ -z "$MISSING" ]; then
    pass "PASS=$HAS_PASS_R WARN=$HAS_WARN_R FAIL=$HAS_FAIL_R in both streams"
else
    fail "$MISSING"
    diag "report statuses:
$(echo "$REPORT_CHECKS" | sed 's/^/  /')"
fi

# ── Summary ───────────────────────────────────────────────────────────

echo ""
echo "========================================"
TOTAL=$((PASS_COUNT + FAIL_COUNT))
echo " Results: $PASS_COUNT/$TOTAL passed, $FAIL_COUNT failed"
echo "========================================"

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo ""
    echo " Failed tests:"
    for t in "${FAILURES[@]}"; do
        echo "   - $t"
    done
    echo ""
    exit 1
fi

echo ""
exit 0
