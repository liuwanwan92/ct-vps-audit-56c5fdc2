#!/usr/bin/env bash
#
# findings.sh - canonicalize and compare the audit "findings" stream that
# vps-audit.sh emits to BOTH the live terminal and the report file.
#
# The invariant under protection: the audit findings shown live (after ANSI
# stripping) must equal the findings written to the report -- same content,
# same order, same multiplicity -- and each check must be emitted exactly once.
#
# This library is pure text processing. It never runs vps-audit.sh and has no
# environment dependencies beyond coreutils (sed, grep, sort, uniq, comm, diff,
# awk). Source it and call the fa_* functions. Diagnostics go to stdout;
# functions return 0 on agreement, 1 on a detected deviation.

# A canonical "finding" is a line of the form:  [PASS|WARN|FAIL] <test> - <msg>
FA_FINDING_RE='^\[(PASS|WARN|FAIL)\] '

# Remove ANSI SGR / clear escape sequences (the live stream is colorized; the
# report is not). Filter: stdin -> stdout.
fa_strip_ansi() {
    sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g'
}

# Extract the ordered findings stream from a captured file (live or report).
# Strips ANSI first so a live capture and a report capture become comparable.
fa_extract_findings() {
    local file="$1"
    fa_strip_ansi < "$file" | grep -E "$FA_FINDING_RE" || true
}

# Map a findings stream (stdin) to just the test names (stdin -> stdout).
# Name is everything between the "[STATUS] " prefix and the first " - ".
# Messages may themselves contain " - ", so we split on the FIRST occurrence.
fa_names() {
    sed -E 's/^\[(PASS|WARN|FAIL)\] //; s/ - .*$//'
}

# Pretty-print one finding's text for a given test name from a findings file.
_fa_msg_for() {
    local name="$1" file="$2"
    grep -E "^\[(PASS|WARN|FAIL)\] ${name//\//\\/} - " "$file" | head -1
}

# Layer A -- cross-stream comparison.
# Args: <live_findings_file> <report_findings_file>
# Detects: divergence (missing/extra), value desync (same check, different
# message on each stream), and order drift (same multiset, different order).
fa_cmp_streams() {
    local live="$1" report="$2"
    local only_live only_report rc=0

    only_live=$(comm -23 <(sort "$live") <(sort "$report"))
    only_report=$(comm -13 <(sort "$live") <(sort "$report"))

    if [ -n "$only_live" ] || [ -n "$only_report" ]; then
        rc=1
        local live_names report_names desync_names
        live_names=$(printf '%s\n' "$only_live"   | grep -E "$FA_FINDING_RE" | fa_names | sort -u)
        report_names=$(printf '%s\n' "$only_report" | grep -E "$FA_FINDING_RE" | fa_names | sort -u)
        # A check present on both sides but with different text = value desync.
        desync_names=$(comm -12 <(printf '%s\n' "$live_names") <(printf '%s\n' "$report_names") | grep -E '.')

        local n
        if [ -n "$desync_names" ]; then
            while IFS= read -r n; do
                [ -z "$n" ] && continue
                echo "  [VALUE DESYNC] check \"$n\" differs between live and report:"
                echo "      live  : $(_fa_msg_for "$n" "$live")"
                echo "      report: $(_fa_msg_for "$n" "$report")"
            done <<< "$desync_names"
        fi
        # Lines whose check is NOT a desync are genuinely missing/extra.
        local line lname
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            lname=$(printf '%s\n' "$line" | fa_names)
            grep -qxF "$lname" <<< "$desync_names" && continue
            echo "  [MISSING IN REPORT] shown live, absent from report: $line"
        done <<< "$only_live"
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            lname=$(printf '%s\n' "$line" | fa_names)
            grep -qxF "$lname" <<< "$desync_names" && continue
            echo "  [EXTRA IN REPORT] in report, never shown live: $line"
        done <<< "$only_report"
    elif ! diff -q "$live" "$report" >/dev/null 2>&1; then
        rc=1
        echo "  [ORDER DRIFT] identical findings, different order (live# vs report#):"
        diff <(cat -n "$live") <(cat -n "$report") | sed 's/^/      /'
    fi
    return $rc
}

# Layer B -- within-stream integrity.
# Arg: <findings_file>. A check emitted more than once (even consistently to
# both streams) is a defect: e.g. one test reported as both WARN and FAIL.
fa_check_integrity() {
    local file="$1" dup_names
    dup_names=$(fa_names < "$file" | sort | uniq -d)
    if [ -z "$dup_names" ]; then
        return 0
    fi
    local n c
    while IFS= read -r n; do
        [ -z "$n" ] && continue
        c=$(grep -cE "^\[(PASS|WARN|FAIL)\] ${n//\//\\/} - " "$file")
        echo "  [DUPLICATE] check \"$n\" emitted $c times:"
        grep -E "^\[(PASS|WARN|FAIL)\] ${n//\//\\/} - " "$file" | sed 's/^/      /'
    done <<< "$dup_names"
    return 1
}

# Static check -- the start banner computes $(date) once for the live echo and
# again for the report echo. Same second -> same string, so this divergence is
# intermittent and cannot be caught reliably at runtime. Catch the CLASS here.
# Arg: <path to vps-audit.sh>
fa_check_banner_single_source() {
    local script="$1" hits n
    hits=$(grep -n 'Starting audit at \$(date)' "$script")
    n=$(printf '%s\n' "$hits" | grep -c '.')
    if [ "${n:-0}" -ge 2 ]; then
        echo "  [LATENT DIVERGENCE] banner timestamp is computed independently per stream:"
        printf '%s\n' "$hits" | sed 's/^/      /'
        echo "      -> capture once (NOW=\$(date)) and reuse; otherwise live and report can disagree."
        return 1
    fi
    return 0
}
