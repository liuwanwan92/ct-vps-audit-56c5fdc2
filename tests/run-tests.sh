#!/usr/bin/env bash
#
# run-tests.sh - regression harness for vps-audit.sh.
#
# It protects ONE invariant: the audit findings shown on the live terminal must
# be the same result that lands in the report file -- same content, same order,
# no spurious duplicates -- whether the script is run directly, piped through
# tee, or executed non-interactively.
#
# Phases:
#   1. Detector self-tests   -- prove the comparator catches divergence,
#                               duplication, reordering and value-desync
#                               (fixtures in tests/fixtures/*). NOT happy-path only.
#   2. Static source check   -- the start banner computes $(date) twice, a
#                               latent (intermittent) live/report divergence.
#   3. Integration, 3 modes  -- run the UNMODIFIED vps-audit.sh under a mocked
#                               environment (direct / tee / non-interactive),
#                               assert live==report per mode and that findings
#                               are identical across all three modes.
#
# vps-audit.sh is never modified; only its environment is controlled.
#
# Two real defects in the current script are pinned as a documented baseline
# (the "Intrusion Prevention" triple-emission and the banner double-$(date)).
# They are reported loudly but do not fail the suite, so the harness stays a
# usable drift detector. Set STRICT_KNOWN=1 to make them hard failures too.

set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$DIR/.." && pwd)"
SCRIPT="$REPO/vps-audit.sh"
FIX="$DIR/fixtures"
STRICT_KNOWN="${STRICT_KNOWN:-0}"

# shellcheck source=tests/lib/findings.sh
source "$DIR/lib/findings.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0; known=0
ok()    { echo "  [OK]    $*"; pass=$((pass+1)); }
bad()   { echo "  [FAIL]  $*"; fail=$((fail+1)); }
note()  { echo "  [KNOWN] $*"; known=$((known+1)); }
indent(){ sed 's/^/          /'; }

# ---------------------------------------------------------------------------
# Phase 1 -- detector self-tests
# ---------------------------------------------------------------------------
echo "== Phase 1: detector self-tests (fixtures) =="

declare -A EXPA=( [good]=0 [divergence]=1 [duplicate]=0 [reorder]=1 [desync]=1 )
declare -A EXPB=( [good]=0 [divergence]=0 [duplicate]=1 [reorder]=0 [desync]=0 )
declare -A KEYW=( [divergence]="MISSING IN REPORT" [duplicate]="DUPLICATE" \
                  [reorder]="ORDER DRIFT" [desync]="VALUE DESYNC" )

for f in good divergence duplicate reorder desync; do
    lf="$WORK/$f.lf"; rf="$WORK/$f.rf"
    fa_extract_findings "$FIX/$f/live.txt"   > "$lf"
    fa_extract_findings "$FIX/$f/report.txt" > "$rf"

    aout="$(fa_cmp_streams "$lf" "$rf")"; rcA=$?
    bout="$(fa_check_integrity "$rf")"; rcB=$?

    expa="${EXPA[$f]}"; expb="${EXPB[$f]}"; key="${KEYW[$f]:-}"
    combined="$aout"$'\n'"$bout"

    if [ "$rcA" -eq "$expa" ] && [ "$rcB" -eq "$expb" ] \
       && { [ -z "$key" ] || grep -qF "$key" <<< "$combined"; }; then
        if [ -z "$key" ]; then
            ok "fixture '$f' -> clean (Layer A & B agree), as expected"
        else
            ok "fixture '$f' -> detected as $key, as expected"
        fi
    else
        bad "fixture '$f' misclassified (got rcA=$rcA rcB=$rcB, wanted A=$expa B=$expb${key:+, class '$key'})"
        [ -n "$aout" ] && echo "$aout" | indent
        [ -n "$bout" ] && echo "$bout" | indent
    fi
done

# ---------------------------------------------------------------------------
# Phase 2 -- static source check (intermittent banner divergence)
# ---------------------------------------------------------------------------
echo
echo "== Phase 2: static check on vps-audit.sh =="

if banner_out="$(fa_check_banner_single_source "$SCRIPT")"; then
    ok "start banner timestamp is single-sourced (live and report cannot disagree)"
else
    note "start banner timestamp is computed twice (intermittent live/report drift):"
    echo "$banner_out" | indent
    [ "$STRICT_KNOWN" = "1" ] && bad "STRICT_KNOWN=1: failing on banner double-\$(date)"
fi

# ---------------------------------------------------------------------------
# Phase 3 -- integration: run the real script under the mock, three ways
# ---------------------------------------------------------------------------
echo
echo "== Phase 3: integration (direct / tee / non-interactive) =="

run_direct()         { ( source "$DIR/lib/mockenv.sh"; cd "$1" && bash "$SCRIPT" >live.txt 2>err.txt ); }
run_tee()            { ( source "$DIR/lib/mockenv.sh"; cd "$1" && bash "$SCRIPT" 2>err.txt | tee live.txt >/dev/null ); }
run_noninteractive() { ( source "$DIR/lib/mockenv.sh"; cd "$1" && bash "$SCRIPT" </dev/null >live.txt 2>err.txt ); }

analyze_mode() {
    local mode="$1"
    local d="$WORK/$mode"
    local report; report="$(ls "$d"/vps-audit-report-*.txt 2>/dev/null | head -1)"
    if [ -z "$report" ]; then bad "$mode: vps-audit.sh produced no report file"; return; fi

    fa_extract_findings "$d/live.txt" > "$d/live.findings"
    fa_extract_findings "$report"     > "$d/report.findings"

    if [ ! -s "$d/report.findings" ]; then
        bad "$mode: report contains no findings (run failed?)"; return
    fi

    # Layer A -- the protected cross-stream invariant.
    local aout; aout="$(fa_cmp_streams "$d/live.findings" "$d/report.findings")"
    if [ $? -eq 0 ]; then
        ok "$mode: live output and report agree on all findings"
    else
        bad "$mode: live output and report DIVERGE (regression!):"
        echo "$aout" | indent
    fi

    # Layer B -- duplicate checks. The IPS triple is the pinned baseline; any
    # OTHER duplicate is a new regression.
    local dupnames; dupnames="$(fa_names < "$d/report.findings" | sort | uniq -d)"
    if [ -z "$dupnames" ]; then
        note "$mode: no duplicate checks found -- the pinned 'Intrusion Prevention' triple appears RESOLVED; update the baseline"
    elif [ "$dupnames" = "Intrusion Prevention" ]; then
        note "$mode: known duplicate present (check \"Intrusion Prevention\" emitted 3x)"
        [ "$STRICT_KNOWN" = "1" ] && bad "$mode: STRICT_KNOWN=1: failing on known duplicate"
    else
        bad "$mode: NEW duplicate check(s) detected:"
        fa_check_integrity "$d/report.findings" | indent
    fi
}

mkdir -p "$WORK/direct" "$WORK/tee" "$WORK/noninteractive"
run_direct          "$WORK/direct"
run_tee             "$WORK/tee"
run_noninteractive  "$WORK/noninteractive"
analyze_mode direct
analyze_mode tee
analyze_mode noninteractive

# Mode-invariance: the findings must not depend on how the script was launched.
echo
echo "== Mode invariance =="
invariant_ok=1
for stream in report live; do
    base="$WORK/direct/$stream.findings"
    for m in tee noninteractive; do
        other="$WORK/$m/$stream.findings"
        if [ -f "$base" ] && [ -f "$other" ] && diff -q "$base" "$other" >/dev/null 2>&1; then
            :
        else
            invariant_ok=0
            bad "$stream findings differ: direct vs $m"
            [ -f "$base" ] && [ -f "$other" ] && diff "$base" "$other" | indent
        fi
    done
done
[ "$invariant_ok" -eq 1 ] && ok "findings identical across direct / tee / non-interactive (live and report)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "== Summary =="
echo "  passed:        $pass"
echo "  failed:        $fail"
echo "  known/pinned:  $known   (documented baseline defects in vps-audit.sh)"
if [ "$known" -gt 0 ] && [ "$STRICT_KNOWN" != "1" ]; then
    echo "  (set STRICT_KNOWN=1 to treat the pinned defects as failures)"
fi

if [ "$fail" -eq 0 ]; then
    echo "  RESULT: PASS"
    exit 0
else
    echo "  RESULT: FAIL"
    exit 1
fi
