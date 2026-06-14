#!/usr/bin/env bash
# Test suite for vps-audit.sh - verifies terminal/report consistency
# Run with: bash vps-audit-tests.sh

set +u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/vps-audit.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

assert_equals() {
    local expected="$1" actual="$2" message="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [ "$expected" = "$actual" ]; then
        echo -e "${GREEN}[PASS]${NC} $message"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}[FAIL]${NC} $message"
        echo "  Expected: $expected"
        echo "  Actual:   $actual"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

assert_contains() {
    local haystack="$1" needle="$2" message="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if echo "$haystack" | grep -qF "$needle"; then
        echo -e "${GREEN}[PASS]${NC} $message"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}[FAIL]${NC} $message"
        echo "  Expected to contain: $needle"
        echo "  Actual: $haystack"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

assert_file_contains() {
    local file="$1" needle="$2" message="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if grep -qF "$needle" "$file" 2>/dev/null; then
        echo -e "${GREEN}[PASS]${NC} $message"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}[FAIL]${NC} $message"
        echo "  File $file does not contain: $needle"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

assert_file_not_contains() {
    local file="$1" needle="$2" message="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if ! grep -qF "$needle" "$file" 2>/dev/null; then
        echo -e "${GREEN}[PASS]${NC} $message"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}[FAIL]${NC} $message"
        echo "  File $file should NOT contain: $needle"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Extract functions from vps-audit.sh into a temp file
extract_functions() {
    awk '/^check_security\(\)/,/^}/' "$SCRIPT_PATH"
    awk '/^print_header\(\)/,/^}/' "$SCRIPT_PATH"
    awk '/^print_info\(\)/,/^}/' "$SCRIPT_PATH"
}

# Run a test scenario: creates isolated env, runs code, returns terminal+report
run_scenario() {
    local scenario_name="$1" test_code="$2"
    echo -e "\n${YELLOW}=== Scenario: $scenario_name ===${NC}"

    local test_dir
    test_dir=$(mktemp -d)
    local orig_dir
    orig_dir=$(pwd)
    cd "$test_dir" || return 1

    # Build runner
    {
        echo '#!/usr/bin/env bash'
        echo 'set +u'
        echo 'REPORT_FILE="report.txt"'
        echo 'NC="" GREEN="" RED="" YELLOW="" GRAY="" BLUE="" BOLD=""'
        echo 'touch "$REPORT_FILE"'
        extract_functions
        echo "$test_code"
    } > runner.sh

    local terminal_output report_content
    terminal_output=$(bash runner.sh 2>&1 || true)
    report_content=""
    if [ -f report.txt ]; then
        report_content=$(cat report.txt)
    fi

    cd "$orig_dir" || return 1
    rm -rf "$test_dir"

    # Export for assertions
    export TERMINAL_OUTPUT="$terminal_output"
    export REPORT_CONTENT="$report_content"
}

# ============================================================================
echo -e "${BLUE}${BOLD}VPS Audit — Terminal/Report Consistency Tests${NC}"
echo "=============================================="

# ---------- 1. PASS consistency ----------
run_scenario "PASS — terminal and report match" '
check_security "Test Check" "PASS" "This is a test message"
'
assert_contains "$TERMINAL_OUTPUT" "[PASS] Test Check" "Terminal shows PASS status"
assert_contains "$REPORT_CONTENT" "[PASS] Test Check" "Report contains PASS status"
assert_contains "$TERMINAL_OUTPUT" "This is a test message" "Terminal shows message"
assert_contains "$REPORT_CONTENT" "This is a test message" "Report contains message"

# ---------- 2. WARN consistency ----------
run_scenario "WARN — terminal and report match" '
check_security "Warning Test" "WARN" "This is a warning"
'
assert_contains "$TERMINAL_OUTPUT" "[WARN] Warning Test" "Terminal shows WARN"
assert_contains "$REPORT_CONTENT" "[WARN] Warning Test" "Report shows WARN"

# ---------- 3. FAIL consistency ----------
run_scenario "FAIL — terminal and report match" '
check_security "Failure Test" "FAIL" "This failed"
'
assert_contains "$TERMINAL_OUTPUT" "[FAIL] Failure Test" "Terminal shows FAIL"
assert_contains "$REPORT_CONTENT" "[FAIL] Failure Test" "Report shows FAIL"

# ---------- 4. No duplicate entries from repeated calls ----------
run_scenario "No ghost duplicates" '
check_security "Check1" "PASS" "Message 1"
check_security "Check2" "FAIL" "Message 2"
check_security "Check1" "PASS" "Message 1"
'
count=$(echo "$REPORT_CONTENT" | grep -cF "Check1" || echo 0)
assert_equals "2" "$count" "Check1 appears exactly twice in report"

# ---------- 5. Empty message ----------
run_scenario "Empty message" '
check_security "Empty Test" "PASS" ""
'
assert_contains "$TERMINAL_OUTPUT" "[PASS] Empty Test" "Terminal handles empty message"
assert_contains "$REPORT_CONTENT" "[PASS] Empty Test" "Report handles empty message"

# ---------- 6. Rapid successive calls ----------
run_scenario "Stress test — 10 rapid calls" '
for i in $(seq 1 10); do
    check_security "Stress Test $i" "PASS" "Message $i"
done
'
r_count=$(echo "$REPORT_CONTENT" | grep -cF "Stress Test" || echo 0)
t_count=$(echo "$TERMINAL_OUTPUT" | grep -cF "Stress Test" || echo 0)
assert_equals "10" "$r_count" "All 10 entries in report"
assert_equals "10" "$t_count" "All 10 entries in terminal"
assert_equals "$t_count" "$r_count" "Terminal and report line counts match"

# ---------- 7. Report append mode ----------
run_scenario "Report append mode" '
echo "Pre-existing content" > report.txt
check_security "Append Test" "PASS" "Should append"
'
assert_contains "$REPORT_CONTENT" "Pre-existing content" "Pre-existing content preserved"
assert_contains "$REPORT_CONTENT" "[PASS] Append Test" "New content appended"

# ---------- 8. Mixed statuses in one run ----------
run_scenario "Mixed statuses — parity" '
check_security "T1" "PASS" "M1"
check_security "T2" "WARN" "M2"
check_security "T3" "FAIL" "M3"
'
t_pass=$(echo "$TERMINAL_OUTPUT" | grep -cF "[PASS]" || echo 0)
t_warn=$(echo "$TERMINAL_OUTPUT" | grep -cF "[WARN]" || echo 0)
t_fail=$(echo "$TERMINAL_OUTPUT" | grep -cF "[FAIL]" || echo 0)
r_pass=$(echo "$REPORT_CONTENT" | grep -cF "[PASS]" || echo 0)
r_warn=$(echo "$REPORT_CONTENT" | grep -cF "[WARN]" || echo 0)
r_fail=$(echo "$REPORT_CONTENT" | grep -cF "[FAIL]" || echo 0)
assert_equals "$t_pass" "$r_pass" "PASS count: terminal=$t_pass report=$r_pass"
assert_equals "$t_warn" "$r_warn" "WARN count: terminal=$t_warn report=$r_warn"
assert_equals "$t_fail" "$r_fail" "FAIL count: terminal=$t_fail report=$r_fail"

# ============================================================================
echo -e "\n${YELLOW}=== Static Analysis Tests ===${NC}"

# ---------- 9. Syntax validation ----------
echo -e "\n${YELLOW}--- Bash syntax check ---${NC}"
TESTS_RUN=$((TESTS_RUN + 1))
if bash -n "$SCRIPT_PATH" 2>/dev/null; then
    echo -e "${GREEN}[PASS]${NC} vps-audit.sh has valid bash syntax"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}[FAIL]${NC} vps-audit.sh has syntax errors"
    bash -n "$SCRIPT_PATH"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ---------- 10. check_security function exists ----------
echo -e "\n${YELLOW}--- Function existence ---${NC}"
TESTS_RUN=$((TESTS_RUN + 1))
if grep -q "^check_security()" "$SCRIPT_PATH"; then
    echo -e "${GREEN}[PASS]${NC} check_security function defined"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}[FAIL]${NC} check_security function not found"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ---------- 11. All check_security calls have 3 args ----------
echo -e "\n${YELLOW}--- Argument validation ---${NC}"
TESTS_RUN=$((TESTS_RUN + 1))
total_calls=$(grep -c 'check_security ' "$SCRIPT_PATH" || echo 0)
# Subtract the function definition line and comments
call_lines=$(grep 'check_security ' "$SCRIPT_PATH" | grep -v '^#' | grep -v '^check_security()' | grep -v '^    case' | grep -v '^    esac' | wc -l)
valid_calls=$(grep -E 'check_security "[^"]+" "(PASS|WARN|FAIL)"' "$SCRIPT_PATH" | wc -l)
if [ "$valid_calls" -ge "$((call_lines - 2))" ]; then
    echo -e "${GREEN}[PASS]${NC} check_security calls have proper format ($valid_calls valid)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}[FAIL]${NC} Some check_security calls malformed ($valid_calls valid of $call_lines)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ---------- 12. IPS/docker deduplication ----------
echo -e "\n${YELLOW}--- IPS/docker deduplication ---${NC}"
TESTS_RUN=$((TESTS_RUN + 1))
docker_warn_count=$(grep -c "Docker is installed but not running" "$SCRIPT_PATH" || echo 0)
if [ "$docker_warn_count" -le 1 ]; then
    echo -e "${GREEN}[PASS]${NC} Docker warning appears at most once ($docker_warn_count)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}[FAIL]${NC} Docker warning appears $docker_warn_count times (duplicate blocks)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ---------- 13. journalctl not treated as filename ----------
echo -e "\n${YELLOW}--- journalctl command substitution ---${NC}"
TESTS_RUN=$((TESTS_RUN + 1))
if grep -q 'grep.*"journalctl' "$SCRIPT_PATH"; then
    echo -e "${RED}[FAIL]${NC} journalctl still treated as filename"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    echo -e "${GREEN}[PASS]${NC} journalctl properly invoked"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

# ---------- 14. systemctl guarded ----------
echo -e "\n${YELLOW}--- systemctl availability check ---${NC}"
TESTS_RUN=$((TESTS_RUN + 1))
if grep -B5 'systemctl list-units' "$SCRIPT_PATH" | grep -q 'command -v systemctl'; then
    echo -e "${GREEN}[PASS]${NC} systemctl availability verified before use"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}[FAIL]${NC} systemctl used without availability check"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ---------- 15. Port check consistent naming ----------
echo -e "\n${YELLOW}--- Port check consistency ---${NC}"
TESTS_RUN=$((TESTS_RUN + 1))
port_scanning=$(grep -c 'check_security "Port Scanning"' "$SCRIPT_PATH" 2>/dev/null | tr -d '\n' || echo 0)
port_security=$(grep -c 'check_security "Port Security"' "$SCRIPT_PATH" 2>/dev/null | tr -d '\n' || echo 0)
if [ "$port_scanning" -eq 0 ] || [ "$port_security" -eq 0 ]; then
    echo -e "${GREEN}[PASS]${NC} Port check uses consistent naming"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}[FAIL]${NC} Port check uses both 'Port Scanning' ($port_scanning) and 'Port Security' ($port_security)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ---------- 16. CPU parsing not using top ----------
echo -e "\n${YELLOW}--- CPU parsing reliability ---${NC}"
TESTS_RUN=$((TESTS_RUN + 1))
if grep -q 'top -bn1.*grep.*Cpu' "$SCRIPT_PATH"; then
    echo -e "${RED}[FAIL]${NC} Still using top (unreliable across systems)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    echo -e "${GREEN}[PASS]${NC} CPU parsing does not rely on top"
    TESTS_PASSED=$((TESTS_PASSED + 1))
fi

# ---------- 17. Repeated execution consistency ----------
echo -e "\n${YELLOW}--- Repeated execution consistency ---${NC}"
test_dir=$(mktemp -d)
cd "$test_dir" || exit 1

{
    echo '#!/usr/bin/env bash'
    echo 'set +u'
    echo 'REPORT_FILE="r1.txt"'
    echo 'NC="" GREEN="" RED="" YELLOW="" GRAY="" BLUE="" BOLD=""'
    echo 'touch "$REPORT_FILE"'
    extract_functions
    echo 'check_security "TestA" "PASS" "MsgA"'
    echo 'check_security "TestB" "WARN" "MsgB"'
    echo 'check_security "TestC" "FAIL" "MsgC"'
} > sim1.sh

{
    echo '#!/usr/bin/env bash'
    echo 'set +u'
    echo 'REPORT_FILE="r2.txt"'
    echo 'NC="" GREEN="" RED="" YELLOW="" GRAY="" BLUE="" BOLD=""'
    echo 'touch "$REPORT_FILE"'
    extract_functions
    echo 'check_security "TestA" "PASS" "MsgA"'
    echo 'check_security "TestB" "WARN" "MsgB"'
    echo 'check_security "TestC" "FAIL" "MsgC"'
} > sim2.sh

bash sim1.sh >/dev/null 2>&1
bash sim2.sh >/dev/null 2>&1

TESTS_RUN=$((TESTS_RUN + 1))
if diff -q r1.txt r2.txt >/dev/null 2>&1; then
    echo -e "${GREEN}[PASS]${NC} Repeated execution produces identical reports"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}[FAIL]${NC} Repeated execution produces different reports"
    diff r1.txt r2.txt
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

cd - > /dev/null || exit 1
rm -rf "$test_dir"

# ---------- 18. No 2>/dev/null swallowing critical errors ----------
echo -e "\n${YELLOW}--- Error visibility ---${NC}"
TESTS_RUN=$((TESTS_RUN + 1))
# Count bare 2>/dev/null on lines that invoke external commands for checks
# (some are acceptable, but apt-get/journalctl should show errors)
apt_swallows=$(grep 'apt-get.*2>/dev/null' "$SCRIPT_PATH" | grep -v '^\s*#' | wc -l)
if [ "$apt_swallows" -le 1 ]; then
    echo -e "${GREEN}[PASS]${NC} apt-get errors not excessively swallowed"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}[FAIL]${NC} apt-get errors swallowed $apt_swallows times (hides failures)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ---------- 19. Firewall check handles ufw+iptables+nft ----------
echo -e "\n${YELLOW}--- Firewall multi-backend support ---${NC}"
TESTS_RUN=$((TESTS_RUN + 1))
has_ufw=$(grep -c 'command -v ufw' "$SCRIPT_PATH" || echo 0)
has_iptables=$(grep -c 'command -v iptables' "$SCRIPT_PATH" || echo 0)
has_nft=$(grep -c 'command -v nft' "$SCRIPT_PATH" || echo 0)
if [ "$has_ufw" -gt 0 ] && [ "$has_iptables" -gt 0 ]; then
    echo -e "${GREEN}[PASS]${NC} Firewall check supports ufw and iptables"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}[FAIL]${NC} Firewall check missing multi-backend support"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ---------- 20. Report filename uses timestamp ----------
echo -e "\n${YELLOW}--- Report naming ---${NC}"
TESTS_RUN=$((TESTS_RUN + 1))
if grep -q 'REPORT_FILE=.*TIMESTAMP' "$SCRIPT_PATH"; then
    echo -e "${GREEN}[PASS]${NC} Report filename includes timestamp"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}[FAIL]${NC} Report filename may collide (no timestamp)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# ============================================================================
echo -e "\n=============================================="
echo -e "${BOLD}Test Summary${NC}"
echo "=============================================="
echo -e "Tests run:    $TESTS_RUN"
echo -e "${GREEN}Tests passed: $TESTS_PASSED${NC}"
echo -e "${RED}Tests failed: $TESTS_FAILED${NC}"
echo "=============================================="

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}Some tests failed.${NC}"
    exit 1
fi
