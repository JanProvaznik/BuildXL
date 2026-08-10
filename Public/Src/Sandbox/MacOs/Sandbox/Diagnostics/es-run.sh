#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Runs a workload under bxl-es-broker on a chosen backend and reports what the sandbox saw.
#
# This exists because the interesting failures are only visible against the real kernel. The
# replay corpus emits contiguous sequence numbers, invents self-consistent process identities, and
# contains neither broker self-traffic nor foreign processes - so three real defects passed 100,000
# replayed scenarios without a mark and were found in the first minute of a live run.
#
# Prerequisites:
#   - bxl-es-broker and es-makefam built (see Documentation/Wiki/MacOsSandbox.md section 4.5)
#   - the broker signed with the Endpoint Security entitlement:
#       codesign --force --sign - --entitlements <ent.plist> <broker>
#   - SIP and AMFI relaxed, or a real provisioned entitlement from Apple
#
# Usage:
#   es-run.sh [--backend es|interpose|auto] [--broker PATH] [--makefam PATH] -- <command> [args...]

set -uo pipefail

BACKEND="es"
BROKER="${BXL_ES_BROKER:-./bxl-es-broker}"
MAKEFAM="${BXL_ES_MAKEFAM:-./es-makefam}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --backend) BACKEND="$2"; shift 2 ;;
        --broker)  BROKER="$2";  shift 2 ;;
        --makefam) MAKEFAM="$2"; shift 2 ;;
        --) shift; break ;;
        *) break ;;
    esac
done

if [[ $# -eq 0 ]]; then
    echo "usage: es-run.sh [--backend es|interpose|auto] [--broker PATH] [--makefam PATH] -- <command> [args...]" >&2
    exit 2
fi

for tool in "$BROKER" "$MAKEFAM"; do
    if [[ ! -x "$tool" ]]; then
        echo "es-run.sh: '$tool' is not executable - build it first" >&2
        exit 2
    fi
done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/es-run.XXXXXX")
FIFO="$WORK/report.fifo"
FAM="$WORK/manifest.fam"
REPORT="$WORK/report.txt"
EVIDENCE="$WORK/evidence.json"

mkfifo "$FIFO"

# /tmp and /private/tmp are both named because macOS resolves one to the other, and a scope that
# names only the symlink will not match a path the kernel reports through the real directory.
"$MAKEFAM" "$FAM" "$FIFO" /tmp /private/tmp "$WORK" || { echo "es-run.sh: manifest build failed" >&2; exit 2; }

# The report FIFO must have a reader before the broker opens it for writing, or the broker blocks.
cat "$FIFO" > "$REPORT" &
READER=$!

__BUILDXL_MACOS_SANDBOX_BACKEND="$BACKEND" \
    __BUILDXL_FAM_PATH="$FAM" \
    __BUILDXL_MACOS_EVIDENCE_PATH="$EVIDENCE" \
    "$BROKER" "$@" > "$WORK/tool.out" 2> "$WORK/tool.err"
RC=$?

wait $READER 2>/dev/null

echo "backend=$BACKEND broker_rc=$RC report_lines=$(wc -l < "$REPORT" | tr -d ' ')"

if [[ -s "$WORK/tool.err" ]]; then
    echo "--- broker stderr ---"
    head -10 "$WORK/tool.err"
fi

# The report is a binary-ish protocol, so it is parsed rather than piped through text tools: sort
# and uniq fail on it with "Illegal byte sequence".
if [[ -s "$EVIDENCE" ]]; then
    echo "--- evidence ---"
    python3 - "$EVIDENCE" <<'PY'
import json, sys
with open(sys.argv[1]) as handle:
    summary = json.load(handle)
keys = ["backend", "taintReason", "cacheable", "eventsProcessed", "reportsWritten",
        "sequenceGaps", "unmappedLineageEvents", "foreignProcessEvents",
        "processCount", "lifecycleClosed"]
for key in keys:
    if key in summary:
        print(f"  {key:<22} {summary[key]}")
extra = sorted(set(summary) - set(keys))
for key in extra:
    print(f"  {key:<22} {summary[key]}")
PY
fi

echo "--- report op histogram ---"
python3 - "$REPORT" <<'PY'
import collections, sys
counts = collections.Counter()
with open(sys.argv[1], errors="replace") as handle:
    for line in handle:
        head = line.split(",", 1)[0].strip()
        if head:
            counts[head] += 1
for op, count in counts.most_common(12):
    print(f"  {count:6d}  {op}")
PY

echo "WORKDIR=$WORK"
exit $RC
