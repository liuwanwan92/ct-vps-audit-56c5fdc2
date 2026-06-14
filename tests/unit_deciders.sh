#!/usr/bin/env bash
# Unit tests for the pure decide_* helpers.
# Requires: lib.sh sourced, and vps-audit.sh sourced (guard prevents the audit
# from running, so the decide_* functions are available directly).

run_unit_tests() {
    echo "== unit: deciders =="

    # System restart
    assert_status WARN "$(decide_system_restart 1)" "system_restart: reboot required -> WARN"
    assert_status PASS "$(decide_system_restart 0)" "system_restart: no reboot -> PASS"

    # SSH root login
    assert_status PASS "$(decide_ssh_root no)"               "ssh_root: no -> PASS"
    assert_status FAIL "$(decide_ssh_root yes)"              "ssh_root: yes -> FAIL"
    assert_status FAIL "$(decide_ssh_root prohibit-password)" "ssh_root: prohibit-password -> FAIL"

    # SSH password auth
    assert_status PASS "$(decide_ssh_password no)"  "ssh_password: no -> PASS"
    assert_status FAIL "$(decide_ssh_password yes)" "ssh_password: yes -> FAIL"

    # SSH port (unprivileged start = 1024)
    assert_status WARN "$(decide_ssh_port 22 1024)"   "ssh_port: 22 -> WARN"
    assert_status PASS "$(decide_ssh_port 1022 1024)" "ssh_port: 1022 (<unpriv) -> PASS"
    assert_status FAIL "$(decide_ssh_port 1024 1024)" "ssh_port: 1024 (>=unpriv) -> FAIL"
    assert_status FAIL "$(decide_ssh_port 2222 1024)" "ssh_port: 2222 (>=unpriv) -> FAIL"
    assert_eq "FAIL"$'\t'"Using unprivileged port 2222 -  use a port below 1024 for better security" \
        "$(decide_ssh_port 2222 1024)" "ssh_port: unprivileged message verbatim (double space)"

    # Firewall
    assert_status PASS "$(decide_firewall ufw yes)"        "firewall: ufw active -> PASS"
    assert_status FAIL "$(decide_firewall ufw no)"         "firewall: ufw inactive -> FAIL"
    assert_status PASS "$(decide_firewall firewalld yes)"  "firewall: firewalld running -> PASS"
    assert_status FAIL "$(decide_firewall iptables no)"    "firewall: iptables none -> FAIL"
    assert_status PASS "$(decide_firewall nftables yes)"   "firewall: nftables active -> PASS"
    assert_status FAIL "$(decide_firewall none '')"        "firewall: no tool -> FAIL (not SKIP)"

    # Unattended upgrades
    assert_status PASS "$(decide_unattended_upgrades 1)" "unattended: installed -> PASS"
    assert_status FAIL "$(decide_unattended_upgrades 0)" "unattended: missing -> FAIL"

    # Intrusion prevention (installed active native docker_present docker_running)
    assert_status PASS "$(decide_intrusion_prevention 1 1 1 0 0)" "ips: native installed+active -> PASS"
    assert_status WARN "$(decide_intrusion_prevention 1 0 1 0 0)" "ips: installed not active -> WARN"
    assert_status FAIL "$(decide_intrusion_prevention 0 0 0 0 0)" "ips: nothing, no docker -> FAIL"
    assert_status SKIP "$(decide_intrusion_prevention 0 0 0 1 0)" "ips: no native + docker down -> SKIP"
    assert_status FAIL "$(decide_intrusion_prevention 0 0 0 1 1)" "ips: docker up, no IPS container -> FAIL"
    assert_status PASS "$(decide_intrusion_prevention 1 1 0 1 1)" "ips: container installed+active -> PASS"

    # Failed logins (evaluable count) - threshold boundaries
    assert_status SKIP "$(decide_failed_logins 0 0)"  "failed_logins: unevaluable -> SKIP"
    assert_status PASS "$(decide_failed_logins 1 0)"  "failed_logins: 0 -> PASS"
    assert_status PASS "$(decide_failed_logins 1 9)"  "failed_logins: 9 -> PASS (boundary)"
    assert_status WARN "$(decide_failed_logins 1 10)" "failed_logins: 10 -> WARN (boundary)"
    assert_status WARN "$(decide_failed_logins 1 49)" "failed_logins: 49 -> WARN (boundary)"
    assert_status FAIL "$(decide_failed_logins 1 50)" "failed_logins: 50 -> FAIL (boundary)"
    assert_eq "PASS"$'\t'"Only 5 failed login attempts detected - this is within normal range" \
        "$(decide_failed_logins 1 5)" "failed_logins: PASS message verbatim"

    # System updates
    assert_status PASS "$(decide_system_updates 0)" "updates: 0 -> PASS"
    assert_status FAIL "$(decide_system_updates 1)" "updates: 1 -> FAIL (boundary)"
    assert_status FAIL "$(decide_system_updates 7)" "updates: 7 -> FAIL"

    # Running services - boundaries
    assert_status PASS "$(decide_running_services 19)" "services: 19 -> PASS (boundary)"
    assert_status WARN "$(decide_running_services 20)" "services: 20 -> WARN (boundary)"
    assert_status WARN "$(decide_running_services 39)" "services: 39 -> WARN (boundary)"
    assert_status FAIL "$(decide_running_services 40)" "services: 40 -> FAIL (boundary)"

    # Port security
    assert_status SKIP "$(decide_port_security 0 0 0 '')"          "ports: unevaluable -> SKIP"
    assert_status PASS "$(decide_port_security 1 9 2 '22,80')"     "ports: 9/2 -> PASS (boundary)"
    assert_status WARN "$(decide_port_security 1 10 2 'x')"        "ports: 10/2 -> WARN (boundary)"
    assert_status WARN "$(decide_port_security 1 19 4 'x')"        "ports: 19/4 -> WARN (boundary)"
    assert_status FAIL "$(decide_port_security 1 20 4 'x')"        "ports: 20/4 -> FAIL (boundary)"
    assert_status FAIL "$(decide_port_security 1 5 5 'x')"         "ports: 5/5 public -> FAIL (boundary)"

    # Disk usage - boundaries
    assert_status PASS "$(decide_disk_usage 49 5G 50G 45G)" "disk: 49% -> PASS (boundary)"
    assert_status WARN "$(decide_disk_usage 50 25G 50G 25G)" "disk: 50% -> WARN (boundary)"
    assert_status WARN "$(decide_disk_usage 79 40G 50G 10G)" "disk: 79% -> WARN (boundary)"
    assert_status FAIL "$(decide_disk_usage 80 40G 50G 10G)" "disk: 80% -> FAIL (boundary)"

    # Memory usage - boundaries
    assert_status PASS "$(decide_memory_usage 49 1G 2G 1G)" "mem: 49% -> PASS (boundary)"
    assert_status WARN "$(decide_memory_usage 50 1G 2G 1G)" "mem: 50% -> WARN (boundary)"
    assert_status WARN "$(decide_memory_usage 79 1G 2G 1G)" "mem: 79% -> WARN (boundary)"
    assert_status FAIL "$(decide_memory_usage 80 2G 2G 0)"  "mem: 80% -> FAIL (boundary)"

    # CPU usage - boundaries
    assert_status PASS "$(decide_cpu_usage 49 51 0.5 2)" "cpu: 49% -> PASS (boundary)"
    assert_status WARN "$(decide_cpu_usage 50 50 0.5 2)" "cpu: 50% -> WARN (boundary)"
    assert_status WARN "$(decide_cpu_usage 79 21 0.5 2)" "cpu: 79% -> WARN (boundary)"
    assert_status FAIL "$(decide_cpu_usage 80 20 0.5 2)" "cpu: 80% -> FAIL (boundary)"

    # Sudo logging
    assert_status PASS "$(decide_sudo_logging 1)" "sudo_logging: on -> PASS"
    assert_status FAIL "$(decide_sudo_logging 0)" "sudo_logging: off -> FAIL"

    # Password policy
    assert_status PASS "$(decide_password_policy strong)" "pwpolicy: strong -> PASS"
    assert_status FAIL "$(decide_password_policy weak)"   "pwpolicy: weak -> FAIL"
    assert_status FAIL "$(decide_password_policy none)"   "pwpolicy: none -> FAIL"

    # SUID files
    assert_status PASS "$(decide_suid_files 0)" "suid: 0 -> PASS"
    assert_status WARN "$(decide_suid_files 3)" "suid: 3 -> WARN"
}
