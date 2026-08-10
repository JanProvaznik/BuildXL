#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Runs one workload three ways - unobserved, under the interposition ingress, and under the
# Endpoint Security ingress - and reports wall clock and what each ingress saw.
#
# This exists because the question "is ES worth an entitlement" is not answerable from either
# backend alone. Section 16 of Documentation/Wiki/MacOsSandbox.md is produced by this script; the
# headline it found is that interposition reports *zero* accesses to the build tool itself and to
# the shared libraries the toolchain loads, because dyld maps those before any user code in the
# process runs. That is a class of false cache hit, and it is only visible by diffing the two.
#
# Three things the measurement protocol has to do, each learned by getting it wrong first:
#
#   - Interleave the arms. Load on this machine is mostly decay from the sample before it, and a
#     blocked design once produced "the sandbox is 3x faster" purely from Defender contamination.
#   - Gate on load average. Ungated, the same measurement has produced 27 s, 73 s and twice over
#     1,000 s for work that takes 10 s on a quiet machine.
#   - Invoke the *real* toolchain, not /usr/bin/cc. /usr/bin/make and /usr/bin/clang are the same
#     file with 78 hard links - libxcselect shims that dispatch on their own filename. Interposition
#     has to shadow-copy platform binaries under a mangled name to stop dyld stripping
#     DYLD_INSERT_LIBRARIES, and the mangled name is what the shim then fails to resolve. Measuring
#     through the shim measures the shim.
#
# Prerequisites are the same as es-run.sh: broker and es-makefam built, broker signed with the
# Endpoint Security entitlement, SIP and AMFI relaxed or a real entitlement from Apple.
#
# Usage:
#   es-compare.sh --workdir DIR --build 'CMD' [--clean 'CMD'] [--reps N] [--max-load N]
#
# Example - the 61-file clang build used in section 16:
#   TOOLS=/Library/Developer/CommandLineTools/usr/bin
#   es-compare.sh --workdir /tmp/esbench \
#                 --build "$TOOLS/make -j8" --clean "$TOOLS/make clean"

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BROKER="${BXL_ES_BROKER:-$HERE/../bxl-es-broker}"
MAKEFAM="${BXL_ES_MAKEFAM:-$HERE/../es-makefam}"
RUNSH="$HERE/es-run.sh"

WORKDIR=""
BUILD=""
CLEAN=""
REPS=5
MAXLOAD=4.0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --workdir)  WORKDIR="$2"; shift 2 ;;
        --build)    BUILD="$2";   shift 2 ;;
        --clean)    CLEAN="$2";   shift 2 ;;
        --reps)     REPS="$2";    shift 2 ;;
        --max-load) MAXLOAD="$2"; shift 2 ;;
        *) echo "es-compare.sh: unexpected argument '$1'" >&2; exit 2 ;;
    esac
done

if [[ -z "$WORKDIR" || -z "$BUILD" ]]; then
    echo "usage: es-compare.sh --workdir DIR --build 'CMD' [--clean 'CMD'] [--reps N] [--max-load N]" >&2
    exit 2
fi

# Waits for the machine to go quiet. Returns non-zero rather than measuring through a storm.
WaitForQuietMachine() {
    for _ in $(seq 1 120); do
        local load
        load=$(uptime | sed 's/.*load averages*: //' | awk '{print $1}' | tr -d ,)
        if [[ "$(python3 -c "print(1 if float('$load') < float('$MAXLOAD') else 0)")" == "1" ]]; then
            return 0
        fi
        sleep 5
    done
    return 1
}

Field() { echo "$1" | grep -E "^[[:space:]]*$2[[:space:]]" | awk '{print $2}' | head -1; }

Now() { python3 -c 'import time; print(time.time())'; }

printf '%-4s %-11s %9s %5s %10s %10s %7s %8s %6s\n' \
    REP ARM SECONDS RC EVENTS REPORTS PROCS TAINT GAPS

RESULTS=$(mktemp "${TMPDIR:-/tmp}/es-compare.XXXXXX")

for rep in $(seq 1 "$REPS"); do
    for arm in none interpose es; do
        WaitForQuietMachine || { echo "es-compare.sh: machine never went quiet" >&2; exit 1; }
        [[ -n "$CLEAN" ]] && (cd "$WORKDIR" && eval "$CLEAN" >/dev/null 2>&1)

        start=$(Now)
        if [[ "$arm" == none ]]; then
            (cd "$WORKDIR" && eval "$BUILD" >/dev/null 2>&1); rc=$?
            out=""
        else
            out=$(cd "$WORKDIR" && BXL_ES_BROKER="$BROKER" BXL_ES_MAKEFAM="$MAKEFAM" \
                  bash "$RUNSH" --backend "$arm" -- \
                  /bin/sh -c "cd '$WORKDIR' && $BUILD >/dev/null 2>&1" 2>&1); rc=$?
        fi
        seconds=$(python3 -c "print(f'{$(Now)-$start:.2f}')")

        printf '%-4s %-11s %9s %5s %10s %10s %7s %8s %6s\n' \
            "$rep" "$arm" "$seconds" "$rc" \
            "$(Field "$out" eventsProcessed)" "$(Field "$out" reportsWritten)" \
            "$(Field "$out" processCount)" "$(Field "$out" taintReason)" \
            "$(Field "$out" sequenceGaps)"
        echo "$arm $seconds" >> "$RESULTS"
    done
done

echo
python3 - "$RESULTS" <<'PY'
import statistics, sys, collections

samples = collections.defaultdict(list)
for line in open(sys.argv[1]):
    arm, seconds = line.split()
    samples[arm].append(float(seconds))

if "none" not in samples:
    sys.exit(0)

baseline = statistics.median(samples["none"])
print(f"{'arm':<11}{'median':>9}{'min':>8}{'max':>8}{'vs none':>10}")
for arm in ("none", "interpose", "es"):
    if arm not in samples:
        continue
    values = samples[arm]
    median = statistics.median(values)
    print(f"{arm:<11}{median:>8.2f}s{min(values):>8.2f}{max(values):>8.2f}{median/baseline:>9.2f}x")
PY

rm -f "$RESULTS"
