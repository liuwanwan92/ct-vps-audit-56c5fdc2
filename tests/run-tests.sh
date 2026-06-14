#!/usr/bin/env bash
# Entry point for the vps-audit test suite.
# Sources the guarded auditor (so decide_* are available for unit tests without
# running an audit) plus the unit and integration suites, runs them, and exits
# non-zero if any assertion fails.

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=tests/lib.sh
source "$DIR/lib.sh"

if [ ! -f "$AUDIT_SCRIPT" ]; then
    echo "ERROR: cannot find auditor at $AUDIT_SCRIPT" >&2
    exit 2
fi

# Sourcing is safe: the auditor's bottom guard only runs main() when executed
# directly, so this just loads the functions.
# shellcheck source=vps-audit.sh
source "$AUDIT_SCRIPT"

# shellcheck source=tests/unit_deciders.sh
source "$DIR/unit_deciders.sh"
# shellcheck source=tests/integration_parity.sh
source "$DIR/integration_parity.sh"

run_unit_tests
echo
run_integration_tests

echo
echo "================================"
echo "Tests run: $TESTS_RUN   Failed: $TESTS_FAILED"
if [ "$TESTS_FAILED" -ne 0 ]; then
    echo "RESULT: FAIL"
    exit 1
fi
echo "RESULT: PASS"
