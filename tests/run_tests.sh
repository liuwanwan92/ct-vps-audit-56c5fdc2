#!/usr/bin/env bash
# tests/run_tests.sh — entry point for vps-audit regression tests
#
# Usage:
#   ./tests/run_tests.sh                     # run all tests
#   ./tests/run_tests.sh --verbose           # verbose output
#   ./tests/run_tests.sh tee_passthrough     # run tests matching pattern
#   ./tests/run_tests.sh -v port_count       # verbose + filter
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "Running vps-audit consistency regression tests..."
echo ""

exec bash "$SCRIPT_DIR/test_consistency.sh" "$@"
