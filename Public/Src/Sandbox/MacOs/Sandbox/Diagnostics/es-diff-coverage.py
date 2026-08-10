#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Diffs the paths two sandbox ingresses reported for the same build.

This is the analysis that produced section 16.2 of Documentation/Wiki/MacOsSandbox.md. Run one
workload under each backend, keep both report files, and compare what they saw.

It found two things worth having a tool for.

The first is a class of false cache hit. Interposition reports *zero* accesses to the build tool
itself and to the shared libraries the toolchain loads, because dyld maps those before any user code
in the process runs; Endpoint Security reports about twenty each. Those are build inputs - upgrading
the linker's support libraries can change link output - so under interposition the toolchain is
absent from the fingerprint and the upgrade invalidates nothing.

The second is a defect in the ES ingress, found only because three paths appeared to be seen by
interposition alone. Reporting them as ES blind spots would have been wrong: all three were the same
file under a different spelling, and ES was emitting paths with '..' still in them. Hence
--explain, which shows the spellings side by side rather than only the set difference.

Comparing raw strings produces mostly noise, so three normalisations are applied by default, each
for a stated reason:

  - clang picks a random temporary name per invocation, so two runs never agree on them
  - macOS spells the same file two ways, /tmp against /private/tmp and MacOSX.sdk against
    MacOSX27.0.sdk, and the two backends differ in which they report (see section 16.4)
  - es-run.sh works in a fresh mktemp directory each run

Pass --raw to suppress all of them, which is how the remaining backend disagreement is measured.

Usage:
  es-diff-coverage.py REPORT_A REPORT_B [--label-a NAME] [--label-b NAME] [--raw] [--explain TEXT]
"""

import argparse
import collections
import re
import sys

TEMP_NAME = re.compile(r"-[0-9a-f]{6,}\.")
WORK_DIR = re.compile(r"/es-run\.[A-Za-z0-9]+/")


def Canonicalize(path, raw):
    """Removes differences that are known not to be coverage differences."""
    if raw:
        return path

    path = TEMP_NAME.sub("-H.", path)
    path = WORK_DIR.sub("/es-run.WORK/", path)
    path = path.replace("/private/tmp/", "/tmp/").replace("/private/var/", "/var/")
    return re.sub(r"/SDKs/MacOSX[0-9.]*\.sdk/", "/SDKs/MacOSX.sdk/", path)


def ReadReport(filename, raw):
    """Returns {path: {operation, ...}} from a sandbox report file.

    exec records are skipped: their trailing field is the argument vector, not a path, and it would
    otherwise be counted as a path containing spaces.
    """
    paths = collections.defaultdict(set)
    with open(filename, errors="replace") as handle:
        for line in handle:
            fields = line.rstrip("\n").split("|")
            if len(fields) < 3:
                continue

            operation = fields[1].strip()
            path = fields[-1].strip()
            if operation == "exec" or not path.startswith("/") or " " in path:
                continue

            paths[Canonicalize(path, raw)].add(operation)

    return paths


def Classify(path):
    if "CommandLineTools" in path or "/Xcode" in path or "/usr/lib/" in path:
        return "toolchain"
    if path.startswith(("/System", "/Library", "/AppleInternal", "/var", "/dev", "/usr")):
        return "system"
    return "workload"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report_a")
    parser.add_argument("report_b")
    parser.add_argument("--label-a", default="A")
    parser.add_argument("--label-b", default="B")
    parser.add_argument("--raw", action="store_true", help="compare literal strings, no normalisation")
    parser.add_argument("--explain", metavar="TEXT",
                        help="show every path containing TEXT in both reports, with operations")
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()

    a = ReadReport(args.report_a, args.raw)
    b = ReadReport(args.report_b, args.raw)

    if args.explain:
        for label, report in ((args.label_a, a), (args.label_b, b)):
            print(f"=== {label} ===")
            matches = sorted(p for p in report if args.explain in p)
            for path in matches or ["(none)"]:
                print(f"    {sorted(report.get(path, [])) if matches else ''} {path}")
        return 0

    only_a = set(a) - set(b)
    only_b = set(b) - set(a)

    print(f"{args.label_a}: {len(a)} paths    {args.label_b}: {len(b)} paths"
          f"    {'(raw)' if args.raw else '(normalised)'}")
    print(f"only {args.label_a}: {len(only_a)}    only {args.label_b}: {len(only_b)}")

    for label, only, report in ((args.label_a, only_a, a), (args.label_b, only_b, b)):
        if not only:
            continue

        buckets = collections.Counter(Classify(p) for p in only)
        print(f"\n--- seen only by {label} ({len(only)}) : "
              + ", ".join(f"{n} {k}" for k, n in buckets.most_common()))

        # Toolchain first: a build input the other backend cannot see is the finding that matters,
        # and it is a needle in a haystack of system paths if listed in path order.
        ordered = sorted(only, key=lambda p: (Classify(p) != "toolchain", p))
        for path in ordered[: args.limit]:
            print(f"    {sorted(report[path])} {path}")
        if len(ordered) > args.limit:
            print(f"    ... {len(ordered) - args.limit} more")

    return 0


if __name__ == "__main__":
    sys.exit(main())
