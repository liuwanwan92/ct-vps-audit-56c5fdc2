#!/usr/bin/env bash
# Shared helpers for the vps-audit test suite.
#
# Portability note: the classic "restrict PATH to a fakebin" technique does not
# work on MSYS/Git-bash because bash resolves its own DLLs via PATH. So instead
# we keep the real PATH intact, PREPEND a shim directory to control command
# OUTPUT, and fake command ABSENCE with an exported `command` wrapper driven by
# the FAKE_ABSENT denylist. This works identically on Linux and Git-bash.

TESTS_RUN=0
TESTS_FAILED=0

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$LIB_DIR/.." && pwd)"
AUDIT_SCRIPT="$REPO_ROOT/vps-audit.sh"

pass() { printf '  ok   - %s\n' "$1"; }
fail() {
    printf '  FAIL - %s\n' "$1"
    [ -n "${2:-}" ] && printf '         %s\n' "$2"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

# assert_eq <expected> <actual> <label>
assert_eq() {
    TESTS_RUN=$((TESTS_RUN + 1))
    if [ "$1" = "$2" ]; then
        pass "$3"
    else
        fail "$3" "expected: [$1] actual: [$2]"
    fi
}

# assert_contains <haystack> <needle> <label>
assert_contains() {
    TESTS_RUN=$((TESTS_RUN + 1))
    case "$1" in
        *"$2"*) pass "$3" ;;
        *)      fail "$3" "[$2] not found in output" ;;
    esac
}

# assert_status <expected_status> <decider_output> <label>
# Verifies the decider emitted EXACTLY ONE STATUS<TAB>MESSAGE line with the
# expected status (single-emit contract).
assert_status() {
    local expected="$1" out="$2" label="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    local nl status
    nl="$(printf '%s' "$out" | grep -c '')"          # number of lines in output
    status="${out%%$'\t'*}"
    if [ "$out" = "$status" ]; then
        fail "$label" "output has no TAB separator: [$out]"
    elif [ "$nl" -ne 1 ]; then
        fail "$label" "expected exactly 1 line, got $nl: [$out]"
    elif [ "$status" != "$expected" ]; then
        fail "$label" "expected status $expected, got $status: [$out]"
    else
        pass "$label"
    fi
}

# Remove ANSI color escapes so terminal output can be compared to the report.
strip_ansi() { sed -E "s/$(printf '\033')\[[0-9;]*m//g"; }

# Extract only verdict lines ("[PASS|WARN|FAIL|SKIP] ...") after stripping color.
verdict_lines() { strip_ansi | grep -E '^\[(PASS|WARN|FAIL|SKIP)\] ' || true; }

# write_shim <path>   (body read from stdin)
write_shim() {
    local path="$1"
    {
        echo '#!/usr/bin/env bash'
        cat
    } > "$path"
    chmod +x "$path"
}

# make_fakebin <dir>
# Populate <dir> with deterministic shims for the system-probing commands the
# auditor runs, so verdicts are reproducible and fast (no host scan, no network).
# Behaviour is tunable via FAKE_* environment variables read at run time.
make_fakebin() {
    local d="$1"
    mkdir -p "$d"

    write_shim "$d/uname"    <<'EOF'
echo "6.1.0-test"
EOF
    write_shim "$d/nproc"    <<'EOF'
echo "${FAKE_CORES:-2}"
EOF
    write_shim "$d/hostname" <<'EOF'
echo "${FAKE_HOST:-testhost}"
EOF
    write_shim "$d/uptime"   <<'EOF'
case "$1" in
    -p) echo "up 1 day" ;;
    -s) echo "2026-01-01 00:00:00" ;;
    *)  echo " 00:00:00 up 1 day,  1 user,  load average: 0.10, 0.20, 0.30" ;;
esac
EOF
    write_shim "$d/lscpu"    <<'EOF'
echo "Model name:  Test CPU @ 1.0GHz"
EOF
    write_shim "$d/df"       <<'EOF'
echo "Filesystem Size Used Avail Use% Mounted"
echo "/dev/sda1 50G 5G 45G ${FAKE_DISK_PCT:-10}% /"
EOF
    write_shim "$d/free"     <<'EOF'
echo "              total        used        free      shared  buff/cache   available"
echo "Mem: 2048 ${FAKE_MEM_USED:-205} 1600 0 243 1700"
EOF
    write_shim "$d/top"      <<'EOF'
echo "top - 00:00:00 up 1 day"
echo "%Cpu(s):  ${FAKE_CPU_USED:-10}.0 us,  0.0 sy,  0.0 ni, 85.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st"
EOF
    write_shim "$d/sysctl"   <<'EOF'
echo "${FAKE_UNPRIV_START:-1024}"
EOF
    write_shim "$d/dpkg"     <<'EOF'
for p in ${FAKE_DPKG:-}; do echo "ii  $p  1.0  all  pkg"; done
EOF
    write_shim "$d/apt-get"  <<'EOF'
echo "${FAKE_UPDATES:-0} upgraded, 0 newly installed, 0 to remove and 0 not upgraded."
EOF
    write_shim "$d/find"     <<'EOF'
[ -n "${FAKE_SUID:-}" ] && for f in $FAKE_SUID; do echo "$f"; done
exit 0
EOF
    write_shim "$d/systemctl" <<'EOF'
args="$*"
case "$args" in
    *"is-active --quiet docker"*)
        [ "${FAKE_DOCKER_RUNNING:-0}" = "1" ] && exit 0 || exit 3 ;;
    *"is-active fail2ban"*|*"is-active crowdsec"*)
        [ "${FAKE_IPS_ACTIVE:-0}" = "1" ] && exit 0 || exit 3 ;;
    *"list-units"*)
        n="${FAKE_SERVICES_COUNT:-1}"
        i=0; while [ "$i" -lt "$n" ]; do echo "svc$i.service loaded active running desc"; i=$((i+1)); done ;;
    *) exit 0 ;;
esac
EOF
}

# run_audit <stdout_file> <report_file>
# Runs the auditor with the fakebin prepended and the `command` absence wrapper
# installed (only inside the subshell, so the caller's shell is untouched).
# Scenario controls: FAKEBIN, FAKE_ABSENT, and any FAKE_* tunables in the env.
run_audit() {
    local out_file="$1" report_file="$2"
    (
        command() {
            if [ "$1" = "-v" ]; then
                case " ${FAKE_ABSENT:-} " in *" $2 "*) return 1 ;; esac
                builtin command -v "$2"; return $?
            fi
            builtin command "$@"
        }
        export -f command
        export PATH="${FAKEBIN}:$PATH"
        export REPORT_FILE="$report_file"
        bash "$AUDIT_SCRIPT" > "$out_file" 2>/dev/null
    )
}
