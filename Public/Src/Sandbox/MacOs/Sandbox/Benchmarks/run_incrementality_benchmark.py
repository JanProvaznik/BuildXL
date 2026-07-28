#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Pre-registered incrementality benchmark for the macOS Endpoint Security sandbox.

The point of this harness is not to produce a fast number. It is to produce a number that
survives an adversarial reading. Three properties are what make it credible:

  1. The scenarios, their expected outcomes, and the repeat count are declared as data below,
     before any measurement runs. They are hashed into the result file, so a result cannot be
     matched to a quietly edited scenario list after the fact.

  2. Every scenario declares whether it is expected to HIT or MISS. A cache that always hits is
     broken, not fast. If a negative control -- a real code change -- hits, the entire run is
     marked INVALID and no speedup is reported at all.

  3. Each scenario runs n times and the median is reported with the full spread. A single fast
     run proves nothing.

Usage:

    python3 run_incrementality_benchmark.py --repo <path> --bxl <path/to/bxl> [options]

Run it once per configuration you want to compare, with a distinct --label, then combine:

    python3 run_incrementality_benchmark.py --combine out/*.json --markdown report.md
"""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone

# --------------------------------------------------------------------------------------------
# PRE-REGISTERED PROTOCOL
#
# Changing anything below changes PROTOCOL_VERSION and therefore the protocol hash recorded in
# every result file. Results produced under different protocol hashes must not be compared.
# --------------------------------------------------------------------------------------------

PROTOCOL_VERSION = 2

DEFAULT_REPEATS = 5

# expect:
#   "miss"      -- this scenario must execute pips; if it does not, the cache is unsound
#   "hit"       -- this scenario must be served from cache; if it is not, incrementality failed
#   "partial"   -- some hits and some misses; both counts are recorded but neither is asserted
#   "baseline"  -- the cold build; establishes the denominator, asserts nothing
SCENARIOS = [
    {
        "id": "cold",
        "title": "Cold build, empty cache",
        "expect": "baseline",
        "mutation": None,
        "reset_cache": True,
        "rationale": "Establishes the denominator and measures the cost of populating the cache.",
    },
    {
        "id": "noop",
        "title": "No-op rebuild, nothing changed",
        "expect": "hit",
        "mutation": None,
        "reset_cache": False,
        "rationale": "The headline number. Today this is a full rebuild because nothing is observed.",
    },
    {
        "id": "comment",
        "title": "Comment-only change in a leaf source file",
        "expect": "partial",
        "mutation": "comment",
        "reset_cache": False,
        "rationale": (
            "The edited pip must miss because its input content changed. Everything downstream "
            "should hit. Note that MSBuild already handles this case well via reference "
            "assemblies -- measured at 1 of 40 projects rebuilt -- so this scenario is a parity "
            "check, not a win to claim."
        ),
    },
    {
        "id": "timestamp-churn",
        "title": "Identical content, new timestamps (branch switch / fresh clone / CI agent)",
        "expect": "hit",
        "mutation": "touch",
        "reset_cache": False,
        "rationale": (
            "The decisive scenario. Measured on plain MSBuild this rebuilds 40 of 40 projects and "
            "every one emits byte-identical output -- about 80% of a cold build, entirely wasted. "
            "MSBuild compares timestamps and cannot do better. A content-addressed engine must "
            "hit here, and if it does not, the fingerprint is picking up something it should not."
        ),
    },
    {
        "id": "leaf-change",
        "title": "Observable change in a leaf source file",
        "expect": "partial",
        "mutation": "observable",
        "reset_cache": False,
        "rationale": "Only the edited pip and its downstream cone may run. Anything more is over-building.",
    },
    {
        "id": "negative-control",
        "title": "NEGATIVE CONTROL: observable change must NOT be fully cached",
        "expect": "miss",
        "mutation": "observable",
        "reset_cache": False,
        "depends_on_clean_state": False,
        "rationale": (
            "Deliberately fails the run if it hits. A cache that returns a hit after a real code "
            "change is silently producing wrong outputs, which is far worse than being slow."
        ),
    },
    {
        "id": "revert",
        "title": "Revert the change, rebuild",
        "expect": "hit",
        "mutation": "revert",
        "reset_cache": False,
        "rationale": (
            "Content-addressed caching must recognise the reverted state, which a timestamp-based "
            "system cannot. This is also the 'switch branch and switch back' case."
        ),
    },
]


def protocol_hash():
    """Hash of the pre-registered protocol. Recorded in every result file."""
    blob = json.dumps(
        {"version": PROTOCOL_VERSION, "scenarios": SCENARIOS, "repeats": DEFAULT_REPEATS},
        sort_keys=True,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------------------------
# Environment provenance
# --------------------------------------------------------------------------------------------


def _run_capture(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        return ""


def describe_environment():
    env = {
        "os": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "hostname": platform.node(),
        "cpu_count": os.cpu_count(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    if sys.platform == "darwin":
        env["product_version"] = _run_capture(["sw_vers", "-productVersion"])
        env["build_version"] = _run_capture(["sw_vers", "-buildVersion"])
        env["cpu_brand"] = _run_capture(["sysctl", "-n", "machdep.cpu.brand_string"])
        env["mem_bytes"] = _run_capture(["sysctl", "-n", "hw.memsize"])
        # SIP state materially changes what the sandbox can do, so it is provenance, not trivia.
        env["sip"] = _run_capture(["csrutil", "status"])
    elif sys.platform.startswith("linux"):
        try:
            with open("/proc/cpuinfo") as handle:
                for line in handle:
                    if line.startswith("model name"):
                        env["cpu_brand"] = line.split(":", 1)[1].strip()
                        break
        except OSError:
            pass
        try:
            with open("/proc/meminfo") as handle:
                env["mem_bytes"] = handle.readline().split()[1] + " kB"
        except OSError:
            pass
    return env


# --------------------------------------------------------------------------------------------
# BuildXL invocation and stats extraction
# --------------------------------------------------------------------------------------------

# These keys are emitted by Scheduler.cs into BuildXL.stats and are read back by
# Execution.Analyzer's PerfSummaryAnalyzer, so they are a stable public surface rather than
# something this script invented.
STAT_KEYS = [
    "ProcessPipCacheHits",
    "ProcessPipCacheMisses",
    "TotalProcessPips",
    "PipsFailed",
    "ProcessPipsSkippedDueToFailedDependencies",
    "ProcessPipsIncrementalSchedulingPruned",
]


def parse_stats(stats_path):
    """BuildXL.stats is a flat key=value file."""
    values = {}
    try:
        with open(stats_path, "r", errors="replace") as handle:
            for line in handle:
                if "=" not in line:
                    continue
                key, _, raw = line.partition("=")
                key = key.strip()
                raw = raw.strip()
                if key in STAT_KEYS:
                    try:
                        values[key] = int(raw)
                    except ValueError:
                        values[key] = raw
    except OSError as exc:
        values["_error"] = str(exc)
    return values


def find_latest_log_dir(repo):
    logs = os.path.join(repo, "Out", "Logs")
    if not os.path.isdir(logs):
        return None
    entries = [os.path.join(logs, name) for name in os.listdir(logs)]
    entries = [path for path in entries if os.path.isdir(path)]
    if not entries:
        return None
    return max(entries, key=os.path.getmtime)


def run_build(bxl, repo, extra_args, log_prefix):
    """Run one build. Wall time is measured externally with a monotonic clock."""
    cmd = [bxl] + extra_args
    started = time.monotonic()
    completed = subprocess.run(
        cmd, cwd=repo, capture_output=True, text=True, errors="replace"
    )
    elapsed = time.monotonic() - started

    log_dir = find_latest_log_dir(repo)
    stats = {}
    err_text = ""
    if log_dir:
        stats = parse_stats(os.path.join(log_dir, "BuildXL.stats"))
        err_path = os.path.join(log_dir, "BuildXL.err")
        if os.path.exists(err_path):
            with open(err_path, "r", errors="replace") as handle:
                err_text = handle.read()[:8000]

    return {
        "wall_seconds": round(elapsed, 3),
        "exit_code": completed.returncode,
        "stats": stats,
        "log_dir": log_dir,
        "stderr_tail": completed.stderr[-4000:] if completed.stderr else "",
        "stdout_tail": completed.stdout[-4000:] if completed.stdout else "",
        "build_err": err_text,
        "command": " ".join(cmd),
        "log_prefix": log_prefix,
    }


# --------------------------------------------------------------------------------------------
# Source mutations
# --------------------------------------------------------------------------------------------

COMMENT_MARKER = "// bxl-benchmark comment mutation"


def apply_mutation(kind, target_file, counter, repo=None):
    """Mutate the target file. Returns a description of what was done.

    'comment' adds a line comment: the file content changes, so the compile pip must miss, but the
    compiler output is typically byte-identical.

    'observable' changes a string literal, which must propagate.

    'touch' rewrites modification times without changing any content. This is what `git checkout`,
    a fresh clone and a clean CI workspace all do, and it is the case where timestamp-based
    incrementality is forced to redo everything while a content-addressed cache skips all of it.
    """
    if kind is None:
        return {"kind": "none"}

    if kind == "touch":
        stamp = time.time() + 1
        touched = 0
        skipped_dirs = {"bin", "obj", "Out", ".git", "node_modules"}
        for dirpath, dirnames, filenames in os.walk(repo or os.path.dirname(target_file)):
            dirnames[:] = [d for d in dirnames if d not in skipped_dirs]
            for name in filenames:
                try:
                    os.utime(os.path.join(dirpath, name), (stamp, stamp))
                    touched += 1
                except OSError:
                    pass
        return {"kind": "touch", "files_touched": touched}

    with open(target_file, "r", errors="replace") as handle:
        original = handle.read()

    if kind == "revert":
        cleaned = "\n".join(
            line for line in original.splitlines() if COMMENT_MARKER not in line
        )
        cleaned = re.sub(r"BXL_BENCH_[0-9]+", "BXL_BENCH_0", cleaned)
        with open(target_file, "w") as handle:
            handle.write(cleaned + ("\n" if original.endswith("\n") else ""))
        return {"kind": "revert", "file": target_file}

    if kind == "comment":
        mutated = original.rstrip("\n") + f"\n{COMMENT_MARKER} {counter}\n"
        with open(target_file, "w") as handle:
            handle.write(mutated)
        return {"kind": "comment", "file": target_file, "counter": counter}

    if kind == "observable":
        if "BXL_BENCH_" in original:
            mutated = re.sub(r"BXL_BENCH_[0-9]+", f"BXL_BENCH_{counter}", original)
        else:
            mutated = original.rstrip("\n") + f"\n{COMMENT_MARKER} marker BXL_BENCH_{counter}\n"
        with open(target_file, "w") as handle:
            handle.write(mutated)
        return {"kind": "observable", "file": target_file, "counter": counter}

    raise ValueError(f"unknown mutation kind: {kind}")


# --------------------------------------------------------------------------------------------
# Scenario evaluation
# --------------------------------------------------------------------------------------------


def evaluate_expectation(scenario, stats):
    """Check the measured outcome against the pre-registered expectation.

    Returns (verdict, detail). verdict is one of "ok", "violated", "unknown".
    """
    expect = scenario["expect"]
    if expect == "baseline":
        return "ok", "baseline, nothing asserted"

    hits = stats.get("ProcessPipCacheHits")
    misses = stats.get("ProcessPipCacheMisses")
    if hits is None or misses is None:
        return "unknown", "cache statistics not found in BuildXL.stats"

    if expect == "hit":
        if misses == 0:
            return "ok", f"{hits} hits, 0 misses"
        return "violated", f"expected no misses, observed {misses}"

    if expect == "miss":
        if misses > 0:
            return "ok", f"{misses} misses as required"
        return (
            "violated",
            "a real source change produced zero cache misses; the cache is returning stale outputs",
        )

    if expect == "partial":
        return "ok", f"{hits} hits, {misses} misses"

    return "unknown", f"unrecognised expectation {expect!r}"


def summarize(values):
    if not values:
        return None
    ordered = sorted(values)
    return {
        "n": len(values),
        "median": round(statistics.median(ordered), 3),
        "min": round(ordered[0], 3),
        "max": round(ordered[-1], 3),
        "mean": round(statistics.fmean(ordered), 3),
        "stdev": round(statistics.stdev(ordered), 3) if len(ordered) > 1 else 0.0,
    }


def run_campaign(args):
    result = {
        "label": args.label,
        "protocol_version": PROTOCOL_VERSION,
        "protocol_hash": protocol_hash(),
        "repeats": args.repeats,
        "repo": os.path.abspath(args.repo),
        "bxl": args.bxl,
        "filter": args.filter,
        "sandbox_kind": args.sandbox_kind,
        "environment": describe_environment(),
        "scenarios": [],
        "valid": True,
        "invalid_reasons": [],
    }

    build_args = list(args.bxl_arg)
    if args.filter:
        build_args.append(f"/f:{args.filter}")

    counter = 0
    for scenario in SCENARIOS:
        entry = {
            "id": scenario["id"],
            "title": scenario["title"],
            "expect": scenario["expect"],
            "rationale": scenario["rationale"],
            "runs": [],
        }
        print(f"\n=== {scenario['id']}: {scenario['title']} ===", flush=True)

        for repeat in range(args.repeats):
            counter += 1

            if scenario.get("reset_cache") and not args.keep_cache:
                cache_dir = os.path.join(args.repo, "Out", "Cache")
                if os.path.isdir(cache_dir):
                    shutil.rmtree(cache_dir, ignore_errors=True)

            mutation = apply_mutation(scenario["mutation"], args.target_file, counter, args.repo)

            run = run_build(
                args.bxl, args.repo, build_args, f"{scenario['id']}-{repeat}"
            )
            run["mutation"] = mutation
            run["repeat"] = repeat

            verdict, detail = evaluate_expectation(scenario, run["stats"])
            run["verdict"] = verdict
            run["verdict_detail"] = detail

            if run["exit_code"] != 0:
                result["valid"] = False
                result["invalid_reasons"].append(
                    f"{scenario['id']} repeat {repeat}: build failed with exit code {run['exit_code']}"
                )
            if verdict == "violated":
                result["valid"] = False
                result["invalid_reasons"].append(
                    f"{scenario['id']} repeat {repeat}: {detail}"
                )

            print(
                f"  run {repeat}: {run['wall_seconds']:.2f}s  exit={run['exit_code']}  "
                f"hits={run['stats'].get('ProcessPipCacheHits')} "
                f"misses={run['stats'].get('ProcessPipCacheMisses')}  [{verdict}] {detail}",
                flush=True,
            )
            entry["runs"].append(run)

        entry["wall_seconds"] = summarize([r["wall_seconds"] for r in entry["runs"]])
        entry["hits"] = summarize(
            [
                float(r["stats"]["ProcessPipCacheHits"])
                for r in entry["runs"]
                if isinstance(r["stats"].get("ProcessPipCacheHits"), int)
            ]
        )
        entry["misses"] = summarize(
            [
                float(r["stats"]["ProcessPipCacheMisses"])
                for r in entry["runs"]
                if isinstance(r["stats"].get("ProcessPipCacheMisses"), int)
            ]
        )
        result["scenarios"].append(entry)

    # Restore the tree so a benchmark run leaves no residue.
    apply_mutation("revert", args.target_file, 0, args.repo)

    baseline = next(
        (s for s in result["scenarios"] if s["id"] == "cold" and s["wall_seconds"]), None
    )
    if baseline and result["valid"]:
        cold_median = baseline["wall_seconds"]["median"]
        for entry in result["scenarios"]:
            if entry["id"] != "cold" and entry["wall_seconds"] and entry["wall_seconds"]["median"] > 0:
                entry["speedup_vs_cold"] = round(
                    cold_median / entry["wall_seconds"]["median"], 2
                )
    elif not result["valid"]:
        # Withholding the speedup when a control failed is the point: a number produced by an
        # invalid run is worse than no number, because it will be quoted without the caveat.
        for entry in result["scenarios"]:
            entry["speedup_vs_cold"] = None

    return result


# --------------------------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------------------------


def render_markdown(results):
    lines = []
    lines.append("# Incrementality benchmark")
    lines.append("")
    hashes = {r["protocol_hash"] for r in results}
    if len(hashes) > 1:
        lines.append(
            "> **These results are not comparable.** They were produced under different "
            f"protocol hashes: {', '.join(sorted(hashes))}."
        )
        lines.append("")
    else:
        lines.append(f"Protocol hash `{hashes.pop()}` (version {results[0]['protocol_version']}).")
        lines.append("")

    for result in results:
        env = result["environment"]
        lines.append(f"## {result['label']}")
        lines.append("")
        if not result["valid"]:
            lines.append("> **RUN INVALID — no speedup is reported.**")
            lines.append(">")
            for reason in result["invalid_reasons"][:20]:
                lines.append(f"> - {reason}")
            lines.append("")
        lines.append(
            f"- Host: {env.get('os')} {env.get('product_version') or env.get('release')} "
            f"({env.get('machine')}), {env.get('cpu_count')} logical CPUs"
        )
        if env.get("cpu_brand"):
            lines.append(f"- CPU: {env['cpu_brand']}")
        if env.get("sip"):
            lines.append(f"- SIP: {env['sip']}")
        lines.append(f"- Sandbox: `{result['sandbox_kind']}`")
        lines.append(f"- Repeats per scenario: {result['repeats']}")
        lines.append(f"- Recorded: {env.get('timestamp_utc')}")
        lines.append("")
        lines.append("| Scenario | Expect | Median wall | Spread (min–max) | Hits | Misses | Speedup vs cold | Verdict |")
        lines.append("|---|---|---:|---:|---:|---:|---:|---|")
        for entry in result["scenarios"]:
            wall = entry.get("wall_seconds")
            hits = entry.get("hits")
            misses = entry.get("misses")
            verdicts = {run["verdict"] for run in entry["runs"]}
            verdict = "violated" if "violated" in verdicts else ("unknown" if "unknown" in verdicts else "ok")
            speedup = entry.get("speedup_vs_cold")
            lines.append(
                "| {id} | {expect} | {median} | {spread} | {hits} | {misses} | {speedup} | {verdict} |".format(
                    id=entry["id"],
                    expect=entry["expect"],
                    median=f"{wall['median']:.2f}s" if wall else "n/a",
                    spread=f"{wall['min']:.2f}–{wall['max']:.2f}s" if wall else "n/a",
                    hits=f"{hits['median']:.0f}" if hits else "n/a",
                    misses=f"{misses['median']:.0f}" if misses else "n/a",
                    speedup=f"{speedup}×" if speedup else "—",
                    verdict=verdict,
                )
            )
        lines.append("")
        lines.append("Scenario rationale:")
        lines.append("")
        for entry in result["scenarios"]:
            lines.append(f"- **{entry['id']}** — {entry['rationale']}")
        lines.append("")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", help="Repository to build")
    parser.add_argument("--bxl", help="Path to the bxl launcher (bxl.sh / bxl.cmd)")
    parser.add_argument("--target-file", help="Source file the mutations are applied to")
    parser.add_argument("--filter", default=None, help="BuildXL /f: filter expression")
    parser.add_argument("--label", default="unlabelled", help="Name for this configuration")
    parser.add_argument("--sandbox-kind", default="unspecified", help="Sandbox kind in use, recorded as provenance")
    parser.add_argument("--repeats", type=int, default=DEFAULT_REPEATS)
    parser.add_argument("--bxl-arg", action="append", default=[], help="Extra argument passed to bxl (repeatable)")
    parser.add_argument("--keep-cache", action="store_true", help="Do not delete Out/Cache for the cold scenario")
    parser.add_argument("--out", default=None, help="Write the JSON result here")
    parser.add_argument("--combine", nargs="+", default=None, help="Combine existing JSON results instead of running")
    parser.add_argument("--markdown", default=None, help="Write a markdown report here")
    parser.add_argument("--print-protocol", action="store_true", help="Print the pre-registered protocol and exit")
    args = parser.parse_args()

    if args.print_protocol:
        print(json.dumps({"version": PROTOCOL_VERSION, "hash": protocol_hash(), "repeats": DEFAULT_REPEATS, "scenarios": SCENARIOS}, indent=2))
        return 0

    if args.combine:
        results = []
        for path in args.combine:
            with open(path) as handle:
                results.append(json.load(handle))
        report = render_markdown(results)
        if args.markdown:
            with open(args.markdown, "w") as handle:
                handle.write(report)
            print(f"wrote {args.markdown}")
        else:
            print(report)
        return 0

    missing = [name for name in ("repo", "bxl", "target_file") if not getattr(args, name)]
    if missing:
        parser.error("--" + ", --".join(name.replace("_", "-") for name in missing) + " required unless --combine or --print-protocol is used")

    if args.repeats < 5:
        print(
            f"warning: {args.repeats} repeats is below the pre-registered minimum of 5; "
            "the result is not comparable to a compliant run",
            file=sys.stderr,
        )

    result = run_campaign(args)

    out = args.out or f"benchmark-{args.label}-{int(time.time())}.json"
    with open(out, "w") as handle:
        json.dump(result, handle, indent=2)
    print(f"\nwrote {out}")

    if args.markdown:
        with open(args.markdown, "w") as handle:
            handle.write(render_markdown([result]))
        print(f"wrote {args.markdown}")

    if not result["valid"]:
        print("\nRUN INVALID:", file=sys.stderr)
        for reason in result["invalid_reasons"]:
            print(f"  - {reason}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
