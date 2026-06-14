#!/usr/bin/env bash
# Integration tests: the core regression lock.
# Runs the FULL auditor under controlled scenarios and asserts that the verdict
# lines shown on the terminal are identical (content + order) to those written
# to the report, that no check is reported more than once, and that missing
# preconditions surface as SKIP (not a silent PASS/FAIL).
# Requires: lib.sh sourced.

# assert_parity <stdout_file> <report_file> <label>
assert_parity() {
    local t r
    t="$(verdict_lines < "$1")"
    r="$(verdict_lines < "$2")"
    assert_eq "$t" "$r" "$3: terminal verdicts == report verdicts"
}

# check_names <report_file> -> one check name per line
check_names() {
    local ln name
    while IFS= read -r ln; do
        ln="${ln#*] }"        # strip "[STATUS] "
        name="${ln%% - *}"    # keep text up to the first " - "
        printf '%s\n' "$name"
    done < <(verdict_lines < "$1")
}

# assert_no_dup_checks <report_file> <label>
assert_no_dup_checks() {
    TESTS_RUN=$((TESTS_RUN + 1))
    local dups
    dups="$(check_names "$1" | sort | uniq -d)"
    if [ -z "$dups" ]; then
        pass "$2: no duplicate check names"
    else
        fail "$2: no duplicate check names" "duplicated: $(echo "$dups" | tr '\n' ',')"
    fi
}

# assert_check_count <report_file> <name> <expected_count> <label>
assert_check_count() {
    TESTS_RUN=$((TESTS_RUN + 1))
    local n
    n="$(check_names "$1" | grep -cxF "$2")"
    if [ "$n" -eq "$3" ]; then
        pass "$4 (count=$n)"
    else
        fail "$4" "expected $3 occurrence(s) of '$2', got $n"
    fi
}

_new_scenario() {
    SCN="$(mktemp -d)"
    FAKEBIN="$SCN/fakebin"
    OUT="$SCN/stdout.txt"
    REPORT="$SCN/report.txt"
    make_fakebin "$FAKEBIN"
    unset FAKE_ABSENT FAKE_DPKG FAKE_UPDATES FAKE_IPS_ACTIVE FAKE_DOCKER_RUNNING \
          FAKE_SERVICES_COUNT FAKE_DISK_PCT FAKE_MEM_USED FAKE_CPU_USED \
          FAKE_SUID FAKE_UNPRIV_START FAKE_CORES FAKE_HOST VPS_AUDIT_DIAG 2>/dev/null
}
_end_scenario() { rm -rf "$SCN"; }

run_integration_tests() {
    echo "== integration: terminal/report parity =="

    # --- Scenario 1: degraded host (missing tools / unreadable logs) ----------
    _new_scenario
    export FAKE_ABSENT="curl ss netstat docker journalctl ufw firewall-cmd iptables nft"
    run_audit "$OUT" "$REPORT"
    assert_parity "$OUT" "$REPORT" "degraded"
    assert_no_dup_checks "$REPORT" "degraded"
    assert_contains "$(cat "$REPORT")" "[SKIP] Failed Logins - " "degraded: failed logins -> SKIP (not silent PASS)"
    assert_contains "$(cat "$REPORT")" "[SKIP] Port Security - "  "degraded: port security -> SKIP"
    assert_contains "$(cat "$REPORT")" "[FAIL] Firewall Status - " "degraded: no firewall tool -> FAIL"
    _end_scenario

    # --- Scenario 2: healthy host (ufw active, ss present, ips active) ---------
    _new_scenario
    export FAKE_ABSENT="netstat docker firewall-cmd iptables nft"
    export FAKE_DPKG="unattended-upgrades fail2ban"
    export FAKE_IPS_ACTIVE=1
    write_shim "$FAKEBIN/ufw" <<'EOF'
echo "Status: active"
EOF
    write_shim "$FAKEBIN/curl" <<'EOF'
echo "203.0.113.7"
EOF
    write_shim "$FAKEBIN/journalctl" <<'EOF'
exit 0
EOF
    write_shim "$FAKEBIN/ss" <<'EOF'
echo "Netid State  Recv-Q Send-Q Local           Peer"
echo "tcp   LISTEN 0      128    0.0.0.0:22      0.0.0.0:*"
echo "tcp   LISTEN 0      128    0.0.0.0:80      0.0.0.0:*"
EOF
    run_audit "$OUT" "$REPORT"
    assert_parity "$OUT" "$REPORT" "healthy"
    assert_no_dup_checks "$REPORT" "healthy"
    assert_contains "$(cat "$REPORT")" "[PASS] Firewall Status (UFW) - " "healthy: ufw active -> PASS"
    assert_contains "$(cat "$REPORT")" "[PASS] Failed Logins - "          "healthy: 0 failed logins -> PASS"
    assert_contains "$(cat "$REPORT")" "[PASS] Port Security - "          "healthy: few ports -> PASS"
    assert_contains "$(cat "$REPORT")" "[PASS] Unattended Upgrades - "    "healthy: unattended upgrades -> PASS"
    assert_contains "$(cat "$REPORT")" "[PASS] Intrusion Prevention - "   "healthy: fail2ban active -> PASS"
    _end_scenario

    # --- Scenario 3: docker installed but down, no native IPS -----------------
    # This is the historic multi-emit case: the old code emitted Intrusion
    # Prevention 2-3 times. It must now emit exactly once (as SKIP).
    _new_scenario
    export FAKE_ABSENT="curl ss netstat journalctl ufw firewall-cmd iptables nft"
    export FAKE_DOCKER_RUNNING=0
    write_shim "$FAKEBIN/docker" <<'EOF'
exit 0
EOF
    run_audit "$OUT" "$REPORT"
    assert_parity "$OUT" "$REPORT" "docker-down"
    assert_no_dup_checks "$REPORT" "docker-down"
    assert_check_count "$REPORT" "Intrusion Prevention" 1 "docker-down: IPS reported exactly once"
    assert_contains "$(cat "$REPORT")" "[SKIP] Intrusion Prevention - " "docker-down: IPS -> SKIP"
    _end_scenario

    # --- Scenario 4: diagnostic mode still keeps terminal/report in sync ------
    _new_scenario
    export FAKE_ABSENT="curl ss netstat docker journalctl ufw firewall-cmd iptables nft"
    export VPS_AUDIT_DIAG=1
    run_audit "$OUT" "$REPORT"
    assert_parity "$OUT" "$REPORT" "diagnostic"
    assert_no_dup_checks "$REPORT" "diagnostic"
    assert_contains "$(cat "$REPORT")" "--- [#1] System Restart" "diagnostic: trace present in report"
    assert_contains "$(cat "$OUT")"    "evidence:"               "diagnostic: evidence present on terminal"
    _end_scenario
}
