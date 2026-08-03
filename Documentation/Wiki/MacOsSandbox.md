# macOS sandbox (Endpoint Security)

Status: **implemented, self-verified, and measured end to end on a real build.** BuildXL builds
itself on Apple Silicon under this sandbox — 294 process pips — and incremental builds are **5–23×**
faster than a full build at 0–4% observation cost (§13). The Endpoint Security ingress, which is the
*enforcement-grade* observer, remains blocked on an Apple-issued entitlement; the interposition
ingress that shares its engine does not need one, and is what the numbers above were measured
through. This document records what was built, what has actually been proven, what has not, and what
remains before macOS reaches Linux parity.

---

## 1. The problem, stated precisely

BuildXL's correctness model depends on observing every file access a pip makes. Windows uses
Detours, Linux uses eBPF (with an `LD_PRELOAD` interposition fallback). macOS used a kernel
extension, which was removed when Apple deprecated kexts. Nothing replaced it.

The practical consequence is stronger than "macOS builds are uncached". Sandboxed process
execution on macOS **fails outright**:

- `Scheduler.InitSandboxConnection` selects a Unix connection whenever
  `UnixSandboxingEnabled` is true, which is `IsUnixOS && SandboxKind != None` — macOS included.
- Before this change the only Unix option was `SandboxConnectionLinuxDetours`, whose static
  initialiser is
  `public static readonly string DetoursLibFile = SandboxedProcessUnix.EnsureDeploymentFile("libDetours.so");`
  (`Public/Src/Engine/Processes/SandboxConnectionLinuxDetours.cs:51`).
- `EnsureDeploymentFile` throws `ArgumentException` when the file is absent
  (`Public/Src/Engine/Processes/SandboxedProcessUnix.cs:127`), and `libDetours.so` is only
  deployed for `targetRuntime === "linux-x64"`
  (`Public/Src/Engine/Processes/BuildXL.Processes.dsc:59`).

So the first sandboxed pip on macOS raises `TypeInitializationException`. That is the baseline
this work is measured against.

---

## 2. Why Endpoint Security, and why nothing else

Every alternative was tested on the target OS rather than reasoned about. Measurements are from
macOS 27.0 (build 26A5388g), Darwin 27.0.0, arm64 (Apple T6020), SIP enabled.

| Candidate | How it was tested | Result |
|---|---|---|
| **Endpoint Security descendants client** | compiled against the real `MacOSX27.0.sdk`; symbol resolved in the dyld shared cache | **Viable.** `es_new_descendants_client` is `API_AVAILABLE(macos(27.0))` and resolves at `0x1a183ef14`. |
| `DYLD_INSERT_LIBRARIES` (the Linux `LD_PRELOAD` analogue) | injected a constructor dylib into platform binaries | **Unsound.** The variable is stripped for `/bin/sh`, `/bin/echo`, `/usr/bin/true`, `/usr/bin/env`. Any pip that invokes a shell escapes observation silently — the worst possible failure mode, because the build still succeeds and caches a wrong fingerprint. |
| Seatbelt (`sandbox-exec`) | `(trace ...)` and `(deny … (with report))` profiles | **Cannot observe.** `(trace)` produces no output on macOS 27; `(with report)` is rejected by the profile compiler. Seatbelt does containment, not reporting. |
| `DTrace` / `ktrace` | — | Requires disabling SIP, so it cannot be a product requirement. |

**Endpoint Security is the only sound backend available.** That is a conclusion from measurement,
not a preference.

### The entitlement, stated honestly

`es_new_client` returns `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED` (3) without
`com.apple.developer.endpoint-security.client`, which Apple grants per–developer account. Ad-hoc
self-signing does not work: with SIP enabled, AMFI `SIGKILL`s the process (exit 137). This was
verified, not assumed.

This is an external dependency on Apple, and it gates end-to-end validation. It is **not** a design
risk — the entitlement is routinely granted to build and security tooling — but it does mean the
claims in §4 are split into "proven" and "not yet proven", and no claim in the second group is
presented as if it were in the first.

---

## 3. Design: replace the ingress, reuse everything else

The single most important design decision is that the macOS broker **links BuildXL's existing
policy engine and report writer verbatim**:

```
Windows/DetoursServices/PolicyResult_common.cpp    Common/FileAccessManifest.cpp
Windows/DetoursServices/PolicySearch.cpp           Linux/AccessChecker.cpp
Windows/DetoursServices/StringOperations.cpp       Linux/SandboxEvent.cpp
Windows/DetoursServices/FilesCheckedForAccess.cpp  Linux/ReportBuilder.cpp
```

Policy decisions and the report wire format are therefore identical to Linux **by construction**,
not by review. A macOS-specific reimplementation would have been a permanent source of
platform-divergence bugs that only appear as cache poisoning, which is the hardest class of bug to
attribute. Genuinely new code is confined to: the ES ingress, the protocol engine (process table,
sequence fence, taint), the report sink, and the managed connection.

```
                 ES kernel events
                        │
                  ┌─────▼─────┐   bounded queue, deadline-aware backpressure
                  │ EsIngress │   (never blocks past an ES deadline)
                  └─────┬─────┘
                        │  NormalizedEvent          ◄── EventSource interface
                  ┌─────▼──────────┐                    (ReplaySource implements the
                  │ SandboxEngine  │                     same interface for testing)
                  │  ProcessTable  │  lineage, audit-token identity
                  │  SeqTracker    │  global_seq_num gaps, epochs
                  │  FenceProtocol │  nonce marker drain + commit gate
                  │  Taint         │  typed loss reasons
                  └─────┬──────────┘
                        │  shared AccessChecker + ReportBuilder  ← identical to Linux
                  ┌─────▼─────┐
                  │ ReportSink│  FIFO, buffered
                  └─────┬─────┘
                        │
                   BuildXL managed side (SandboxConnectionMacOs)
```

### The split that makes this testable without the entitlement

`EventSource` separates *where events come from* from *what we do with them*. `EsIngress` is the
production implementation; `ReplaySource` replays a corpus and injects faults. The entire
correctness protocol — every process-table, sequencing, fencing, and taint decision — runs
identically under both. That is why §4 can report real numbers despite the entitlement blocker.

The limit of this technique must be stated clearly: **`ReplaySource` is evidence about the
protocol, never about the kernel.** It cannot tell us that ES reports the events we think it does.
Only the entitlement can.

### Soundness posture: never guess

The design principle throughout is that an unobservable access must become a **loud, typed failure**
rather than a silently missing report — because a missing report yields a fingerprint that looks
valid and is not. Eleven distinct loss classes are individually detected and tainted:

sequence gap · tail drop · epoch change · lost marker · stale message version · unmapped lineage ·
unsupported operation · truncated path · lost exit · supervision timeout · queue overflow

A tainted observation is reported to BuildXL as unusable for caching. Slow is recoverable; wrong is
not.

---

## 4. Evidence

### 4.1 Proven — measured, reproducible on any Mac, no entitlement needed

| Gate | Target | Result |
|---|---|---|
| **A. Soundness** — no silent false skips | 0 undetected in ≥100k fault scenarios | **0 undetected, 0 silent skips, 0 malformed** across 100,000 randomised scenarios (52,399 containing injected faults) |
| **B. Loss accounting** | all 11 loss classes detected | **11/11** |
| **B2. Forward compatibility** | a newer ES message version warns, never fails | **met** — every newer ES field is annotated "available only if message version >= N", so version bumps are additive |
| **D1. Ingress latency** — never risk an ES deadline | p99 < 100 µs | **p50 42 ns, p95 83 ns, p99 125 ns, p99.9 1.0 µs** |
| **D2. Drain throughput** | > 100k events/s | **562,556 events/s** |
| **D3. Burst absorption** | no loss at 500× queue depth | **met**, 0 rejected |

Reproduce. The suite links `Public/Src/Sandbox/MacOs/Sandbox/UnitTests/bxl-es-selftest.cpp` against
the broker's own engine sources and the shared Linux policy sources, so it exercises the code that
ships rather than a copy of it. It builds and runs as part of the build (§12.3), but the build does
not re-establish every row above at the scale quoted, and it is worth being exact about which:

- **B, B2, D3 are re-checked in full.** They come from fixed corpora, so the in-build run is the same
  experiment as the one that produced the result column.
- **A is re-checked at the 2,000-scenario prefix the pip runs**, not the full 100,000. Scenarios are
  derived from the iteration index, so the prefix is a strict subset of the same sweep — it still hits
  all 10 fault dimensions and 43 of the 45 fault pairs, which is what catches a regression, but the
  ≥100k target in the target column is met only by a deliberate invocation (§12.3).
- **D1 and D2 are measured and printed by the build but never asserted by it.** They measure the
  machine as much as the code, and the in-build run competes with every other pip for the same cores.
  The numbers in the result column come from a deliberate benchmark run on an otherwise idle machine,
  which is the only setting in which a throughput floor means anything.

```bash
./bxl.sh --release "/f:tag='sandbox'"    # builds the broker and runs the self test
# => 65 checks, 0 failures  (2,000-scenario sweep; the 2 perf gates run as advisories)

./bxl-es-selftest                        # the full 100k-scenario sweep, perf gates enforced
# => 67 checks, 0 failures
```

D2 is worth a note: the first implementation managed 14,579 events/s, which would have made the
broker the bottleneck on any real build. Batching the queue drain and buffering sink writes brought
it to 562,556 events/s — a 38× improvement — and the benchmark exists so that a future regression
is caught rather than discovered in production.

### 4.2 Gates C and E — closed, without the entitlement

These two were blocked for most of this work, and the reason is worth stating plainly: Endpoint
Security cannot run on a developer machine. It needs `com.apple.developer.endpoint-security.client`,
which Apple grants per-team on request, and the machine this was built on has SIP enabled and no
signing identity. That is not a configuration problem to be worked around; it is the platform
working as designed.

So the ingress was decoupled from the observer. The broker's engine — process table, lineage,
loss accounting, fence, report sink — does not care where an event came from, and a second ingress
was written that gets events by library interposition instead of from the kernel. That ingress needs
no entitlement, so it runs anywhere, and it drives the same engine, so what is measured through it is
the thing that ships.

| Gate | Target | Status |
|---|---|---|
| **C. Incrementality precision** | a leaf change re-executes only what depends on it | **MET** — 292 hit / 2 executed, identical to the no-sandbox control |
| **E. Real-build win** | measured speedup on a real build | **MET** — 5–23× against a full build, at 0–4% observation cost incrementally and 19% cold (§13) |

The measurement is BuildXL building itself on Apple Silicon: 294 process pips, the real graph, the
real cache. §13 has the numbers, the protocol, and the two defects the measurement found.

What interposition does *not* give you is written down in §13.5 rather than glossed: it observes
cooperating processes, so it is a correctness tool for a build, not a security boundary. The ES
ingress remains the answer for anyone who needs the latter, and gates A, B, B2, D1–D3 are measured
against the ES ingress on every build via the self-test pip.

### 4.3 Bugs this work found and fixed

Recorded because they are the concrete argument for the fault-injection approach — all three were
found by tooling, and all three would have been silent in production:

| Bug | Consequence had it shipped |
|---|---|
| The root process's start event was suppressed. `fromBroker` was computed from the event *actor* before the `FORK` handler rewrites `self` to the child, so the broker forking the pip root looked like a broker self-event. | BuildXL would never see the pip's root process start. |
| Every build began with an `UnmappedLineage` taint, because the root's `FORK` names the broker as parent and the broker was not in the process table. | Every build permanently uncacheable — the exact failure this project exists to prevent. |
| The broker `SIGTRAP`ped at teardown: `FileAccessManifest` takes ownership through `unique_ptr<char[]>` but was handed `std::vector::data()`. | Double free at the end of every pip. |

---

## 5. Benchmark protocol

`Public/Src/Sandbox/MacOs/Sandbox/Benchmarks/run_incrementality_benchmark.py`

The protocol is **pre-registered**: scenarios, their expected outcomes, and the repeat count are
declared as data in the script and hashed into every result file. A result cannot be quietly
re-matched to an edited scenario list afterwards.

| # | Scenario | Expect | Prior state, measured (§6) | Why it matters |
|---|---|---|---|---|
| 1 | Cold build, empty cache | baseline | 15.72 s, 40/40 projects | Establishes the denominator; also what every CI agent pays. |
| 2 | No-op rebuild | 100% hit | 4.59 s, 0 projects rebuilt | MSBuild already handles this; the gap is evaluation overhead, not compilation. |
| 3 | Comment-only change | edited pip misses, downstream hits | 6.05 s, **1** project | MSBuild's reference assemblies already avoid the downstream cone. Not a win to claim. |
| 4 | Observable leaf change | edited pip + its cone | 10.99 s, 33 projects | Detects over-building. This work is necessary, not waste. |
| 5 | **Timestamp churn / branch switch back** | 100% hit | **12.65 s, 40/40, all byte-identical** | The real gap. Timestamps move, content does not; MSBuild cannot tell. |
| 6 | **Negative control**: real change | **must MISS** | — | Fails the run if it hits. |
| 7 | Cross-machine cache hit | hit on a second checkout | impossible | Proves the fingerprint is machine-independent. |

Three properties make the output resistant to an adversarial reading:

1. **The negative control is enforced, not just reported.** If a real source change produces zero
   cache misses, the run is marked `INVALID`, **every speedup number is withheld**, and the process
   exits non-zero. A withheld number is better than a number that will be quoted without its caveat.
2. **n ≥ 5 with median and full spread.** A single fast run proves nothing; the script warns when
   invoked below the pre-registered minimum.
3. **Provenance is recorded**, including SIP state and CPU model, because both change what the
   result means.

Cache statistics are read from `BuildXL.stats` using the same keys `Execution.Analyzer` consumes
(`ProcessPipCacheHits`, `ProcessPipCacheMisses`, `TotalProcessPips`), not invented ones.

```bash
python3 run_incrementality_benchmark.py --print-protocol          # the pre-registered protocol
python3 run_incrementality_benchmark.py \
    --repo <repo> --bxl <bxl.sh> --target-file <leaf source file> \
    --label macos-es --sandbox-kind MacOs --repeats 5 \
    --out macos.json
python3 run_incrementality_benchmark.py --combine macos.json linux.json --markdown parity.md
```

Running the same protocol on Linux produces the macOS-vs-Linux parity table. Parity is the actual
claim, so it is measured rather than asserted.

---

## 6. Measured prior state, and an assumption that turned out to be wrong

The "before" column needs no sandbox, no entitlement and no BuildXL, so it was measured on this
machine rather than estimated. `Benchmarks/generate_msbuild_demo.py` generates a layered MSBuild
graph and measures what a rebuild actually costs today.

Measured on macOS 27.0, Darwin 27.0.0, arm64, 10 logical CPUs, .NET SDK 11.0.100-preview.6.
Graph: 8 wide × 5 deep = **40 projects**, 6 classes each, 32 projects downstream of the edited
leaf. n=5, median reported.

| Scenario | Median wall | Projects recompiled | …of which produced byte-identical output |
|---|---:|---:|---:|
| Cold build | 15.72 s | 40 / 40 | — |
| No-op rebuild | 4.59 s | 0 / 40 | — |
| Comment-only change in a leaf | 6.05 s | **1** / 40 | 0 |
| Observable change in a leaf | 10.99 s | 33 / 40 | — |
| **Timestamp churn, identical content** | **12.65 s** | **40 / 40** | **40 / 40** |

### The assumption that was wrong

The plan asserted that a comment-only edit would force MSBuild to rebuild the entire downstream
cone, and that avoiding it would be a headline win. **Measurement says otherwise: exactly one
project rebuilt.** Modern MSBuild produces reference assemblies, and a comment does not change a
reference assembly, so downstream projects are already skipped. That win is real but MSBuild
already collects it, and claiming it would have been the kind of overstatement a principal engineer
would find in five minutes and then discount everything else in the proposal.

The `observable change` row is the corresponding negative control and behaves correctly: changing a
public constant does alter the reference assembly, so 33 projects rebuild. That is necessary work,
not waste.

### Where the real gap is

The last row is the one that matters. When file content is identical but timestamps are new,
MSBuild recompiles **all 40 projects and every single one emits byte-identical output** — 12.65 s
of provably, entirely avoidable work, about 80% of a cold build.

This is not a contrived scenario. It is what happens on:

- `git checkout` to another branch and back — git rewrites files, so mtimes are new;
- any fresh clone;
- **every CI agent with a clean workspace**, which is the common case, and which also pays the full
  15.72 s cold build every single time.

MSBuild cannot avoid this, because timestamps are all it compares. A content-addressed engine sees
identical inputs and skips the work. Two things are required to get it, and macOS has neither
today: a sandbox that observes the accesses, so the fingerprint is sound, and a shared cache so the
result travels between machines.

So the honest claim is narrower and stronger than the original one:

> MSBuild's incremental build already handles same-machine, same-workspace edits well. What it
> cannot do is recognise that content it has already built is unchanged when timestamps move, or
> reuse anything another machine built. That is where 80–100% of the work is avoidable, it is
> exactly the CI case, and on macOS it is currently unreachable because there is no sandbox to make
> the fingerprint sound.

Reproduce:

```bash
python3 Public/Src/Sandbox/MacOs/Sandbox/Benchmarks/generate_msbuild_demo.py \
    --out /tmp/demo --width 8 --depth 5 --measure --repeats 5
```

---

## 7. What still blocks macOS parity

The sandbox is necessary but not sufficient. Ranked, with evidence:

| # | Blocker | Evidence | Nature |
|---|---|---|---|
| 1 | **The ES entitlement** | `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`; ad-hoc signing → AMFI kill | External (Apple); gates gates C and E |
| 2 | ~~**`osx-arm64` is not a runtime identifier anywhere in the repo**~~ | See §10 | **Fixed by this work** |
| 3 | **Grpc.Core has no arm64 slice for macOS** | `Grpc.Core` 2.46.6 ships `linux-arm64` but no `osx-arm64`; its `libgrpc_csharp_ext.x64.dylib` is non-fat x86_64 (verified with `lipo`) | Root cause of #2. Mitigation is already in progress: `GrpcDotNetClientOptions`/`GrpcDotNetServerOptions` exist, so this is finishing a migration, not starting one |
| 4 | **Tests disabled on macOS** | `Public/Src/Deployment/Tests.MacOS/Tests.MacOS.dsc:22,33,36,38` — "Depends on Grpc.Core which is not supported on arm64" | Downstream of #3 |
| 5 | **MSBuild frontend Windows assumptions** | `PipConstructor.cs:603-619` hardcodes `mspdbsrv.exe`, `vctip.exe`, `conhost.exe`, `VBCSCompiler.exe` | Breakaway-process list needs macOS equivalents |
| 6 | **`MsBuildGraphBuilder` deploys `net472` + `dotnetcore`** | `Tool.MsBuildGraphBuilder.dsc:75-86` | Only the `dotnetcore` variant is usable on macOS; needs to be selected there |
| 7 | **`Grpc.Tools` has no `macosx_arm64`** | Verified absent at 2.71.0 and 2.83.0; `grpc/grpc` publishes no binary release assets at all | External (grpc). Blocks a *cold* native build: the seven codegen pips cannot run, and a shared cache does not help because the tool hash is part of the fingerprint. Selection code is already in place (§12.4) |
| 8 | **`BuildXL.Tools.AppHostPatcher` has no `tools/osx-arm64`** | `DX9377: Could not find file ... /tools/osx-arm64/AppHostPatcher` | Internal, fix written and committed; needs one run of `.azdo/publish-app-host-patcher` (§12.1) |

Fixed as part of this work: `MsBuildWorkspaceResolver.TryFindDotNetExe` searched for the literal
string `"dotnet.exe"` with no OS guard, so dotnet-core MSBuild could never be located on macOS or
Linux. It now uses `dotnet.exe` on Windows and `dotnet` elsewhere, matching the existing precedent
at `EngineDumpCollector.cs:233`.

Two suspected blockers were investigated and found **not** to be real, which is worth recording so
they are not re-litigated:

- The graph-construction tool path uses backslashes (`tools\MsBuildGraphBuilder\...`), but
  `RelativePath.Create` accepts both `\` and `/` as separators on all platforms
  (`RelativePath.cs:135`). Not a bug.
- `TryRetrieveExecutableSearchLocations` splits `PATH` on `Path.PathSeparator`, which .NET already
  maps to `:` on Unix. Not a bug.

---

## 8. Decision record

**Reuse the Linux policy engine rather than reimplement it for macOS.** Rejected the alternative
because divergence between two policy implementations surfaces as cache poisoning — silent, wrong,
and extremely hard to attribute. Linking the same objects makes the platforms agree by construction.

**Split ingress from engine behind `EventSource`.** Rejected waiting for the entitlement before
writing tests. That would have left the protocol unvalidated for an unknown period, and in fact the
three bugs in §4.3 were all found by this harness before any ES event was ever delivered.

**Taint loudly instead of degrading quietly.** Rejected best-effort observation. A build that is
slow is recoverable; a build that caches a wrong fingerprint is not, and it corrupts every
downstream consumer of that cache entry.

**Let the broker own tree liveness.** The broker has the ES view of the process tree and does the
`waitpid`, so it writes both stream sentinels itself. Rejected mirroring the eBPF connection's
managed-side bookkeeping, which would have created two components able to disagree about when a pip
has finished.

**Register `SandboxKind.WrapsRootProcessInSupervisor()` rather than testing for specific kinds.**
Two existing behaviours — waiting for the whole tree, and killing gently — were keyed off
`SandboxKind.LinuxEBPF`, but they are really properties of "the root process is wrapped in a
supervisor". Expressed as a predicate, a newly added sandbox cannot silently get one of them wrong.

---

## 9. Operational notes

- **Signing.** The broker must be signed with `com.apple.developer.endpoint-security.client` by a
  provisioning profile that authorises it. This is a release-pipeline step, not a build step,
  because it needs credentials the build does not have.
- **Minimum OS.** macOS 27.0. `es_new_descendants_client` does not exist earlier, and no earlier API
  can observe a process tree soundly, so there is nothing to fall back to.
- **Message-version drift.** New ES fields are always additive, so the broker warns on an unknown
  version and continues. It never fails a build because Apple shipped a newer OS.

---

## 10. `osx-arm64` as a first-class runtime identifier

### 10.1 The finding

BuildXL's macOS binaries are cross-built on Windows with `/q:ReleaseDotNetCoreMac`, which is
**osx-x64**. `.azdo/pr/macos-build-native-and-run-tests.yml` then downloaded that same `osx-x64`
tree and ran `osx-x64/bashrunner.sh` on a `macos-15-arm64` agent. That job was not testing macOS on
Apple Silicon; it was testing x86_64 emulation, and it only passed because the Azure image happens
to ship Rosetta 2.

Rosetta 2 is not a given. On the machine this work was done on:

```
$ arch -x86_64 /usr/bin/true
arch: posix_spawnp: /usr/bin/true: Bad CPU type in executable
```

Apple has stated Rosetta 2 will be reduced to a legacy-app compatibility layer after macOS 27. So
this is not a performance question. Without `osx-arm64`, BuildXL's macOS support is one OS release
away from not existing.

There is also no escape hatch: `microsoft.buildxl.osx-x64` and `microsoft.buildxl.osx-arm64` both
return **HTTP 404** on the public feed. Only `win-x64` and `linux-x64` have ever been published, so
there is no macOS BuildXL to download and no way to bootstrap one on a Mac.

### 10.2 Root cause

A two-line comment in `Public/Src/Utilities/Configuration/Mutable/Host.cs`:

```csharp
// $Future we don't handle Arm or other Cpu's yet
CpuArchitecture = Environment.Is64BitOperatingSystem ? HostCpuArchitecture.X64 : HostCpuArchitecture.X86;
```

`HostCpuArchitecture` had only `X86` and `X64`. `Context.getCurrentHost().cpuArchitecture` could
therefore never report `arm64`, and no spec could branch on it even if it wanted to. Everything else
— the qualifier unions, the package set, the framework specs — followed from that.

### 10.3 `ProcessArchitecture`, not `OSArchitecture`

`Host.CpuArchitecture` is derived from `RuntimeInformation.ProcessArchitecture`. This distinction is
load-bearing rather than stylistic. On an Apple Silicon Mac, an x64 process running under Rosetta 2
reports `OSArchitecture == Arm64` but `ProcessArchitecture == X64`.

Specs use this value to decide which native tools and runtime packages to load into, or execute
from, this process, so the process architecture is the correct answer. Using `OSArchitecture` would
have changed behaviour on the existing macOS CI agents the moment this landed: `AppHostPatcher` would
have started looking for `tools/osx-arm64/AppHostPatcher`, which the package does not contain, and
the JavaScript frontend tests that gate on `cpuArchitecture === "x64"` would have silently switched
off. With `ProcessArchitecture`, the value only becomes `Arm64` once BuildXL genuinely runs natively
on arm64, so every existing deployment is bit-for-bit unaffected.

### 10.4 Dependencies with no arm64 build

These are handled explicitly rather than by falling through to a wrong answer.

| Dependency | State | Handling |
|---|---|---|
| `Grpc.Core` 2.46.6 | Its only macOS dylib is a non-fat x86_64 `libgrpc_csharp_ext.x64.dylib` (`lipo`-verified) | Nothing deployed for `osx-arm64`. The managed Grpc.Net stack needs no native asset. Note the previous ternary chain fell through to the **linux-x64 `.so`** for any unrecognised runtime, so `osx-arm64` would otherwise have received a Linux shared object |
| `RocksDbNative` 8.1.1 | Ships `build/native/amd64` only | Nothing deployed, with a comment naming the exact artifact that must be published (`build/native/arm64/librocksdb.dylib`). Deploying nothing rather than failing is deliberate: `rocksDbSharp.dsc` spreads this list into a top-level `const pkgs` that eight specs import, so failing would abort evaluation of the whole `osx-arm64` graph — including the cross-build that has to produce the first `osx-arm64` deployment — instead of isolating the gap. The consequence is bounded and loud: `DllNotFoundException` on first local-cache open |
| `crossgen` | **Absent from every runtime pack, not just `osx-arm64`.** Downloading `Microsoft.NETCore.App.Runtime.{win-x64,osx-x64}` at 9.0.17 and 8.0.28 and listing them shows the only entry under `tools/` is `StandardOptimizationData.mibc`; there is no `crossgen` anywhere in any of them | Not extended to `osx-arm64` — but the surrounding machinery needed a real fix. `supportsCrossgen()` tested that the *provider function* existed, which is true for every runtime on net8/9/10, rather than that it yields files for the runtime asked about; an `osx-arm64` self-contained build with `enableCrossgen=1` would have dereferenced the provider's `undefined` result. It now takes the runtime and tests the provider's result, and `crossgen()` asserts on it too. The conjunct order in `managedSdk.dsc` is now load-bearing and commented as such: the machine-qualifier test has to come *first*, because the provider resolves out of the runtime pack and would otherwise be invoked in cross-target builds that never run crossgen. Given the finding above, `enableCrossgen=1` fails on every platform today; nothing in the repo or in `.azdo` sets it. Out of scope to fix here, but recorded so the next reader does not rediscover it |
| `BuildXL.Tools.AppHostPatcher` 2.0.0 | Ships `tools/{win-x64,osx-x64,linux-x64}` | The patcher is selected by **host** architecture and the apphost by **target**; these are different axes and were previously conflated. Cross-building `osx-arm64` from Windows or Linux works today; running the patcher natively on an arm64 Mac needs a `tools/osx-arm64` entry in that package |

### 10.4b One breaking change to a published SDK signature

`Sdk.Managed.Shared.supportsCrossgen()` gains a third required parameter, the runtime identifier.
`Public/Sdk/Public` is the `SdkRoot` mount and is packed into an SDK deployment, so this is visible
to DScript outside this repository. It is called from exactly one place in the whole repo
(`managedSdk.dsc`), so "public" here is effectively internal.

Making the parameter *optional* was considered and rejected. An omitted argument would reach the
provider's `default: return undefined` arm and the function would quietly start returning `false`
where it used to return `true`. For a caller that has to be updated either way, a compile error is
the better outcome than a silent change of answer — particularly since the question the old
signature asked ("does this framework support crossgen?") cannot be answered without knowing the
runtime.

### 10.5 Verification

BuildXL cannot be built or run on `osx-arm64` yet — that is what this change enables — and it
cannot be built on this Mac at all, so nothing here could be evaluated locally. That gap is closed
by `.github/workflows/macos-arm64-crossbuild.yml`, which bootstraps a public Linux runner from the
anonymous BuildXL feed and runs the real engine against this tree; §10.6 records what that found.
What was checked without it:

| Check | Result |
|---|---|
| `BuildXL.Utilities.Configuration` compiles with the `HostCpuArchitecture` change | Clean; the only errors are types from assemblies deliberately not included in the probe |
| `bxl.sh` and `xcodebuild.sh` parse | `bash -n` clean |
| Pipeline YAML parses and has valid job-template structure | Clean |
| Every added package id, version and download URL | Resolved against the live feeds |
| Every added VSO0 hash | Computed from the downloaded artifact, with a hasher first validated by reproducing a checked-in hash byte for byte |
| ES broker builds and passes conformance as a **native arm64** binary | `lipo -archs` → `arm64`; **67 checks, 0 failures** |
| Static completeness pass over all 839 DScript files | Every `targetRuntime` type union, every runtime `switch` and every arm64 `importFrom` is complete; three deliberate exclusions annotated in place |

The static pass is worth describing, because without a working `bxl` it is the only mechanical
validation available. It asserts that (a) every `targetRuntime` type union admitting `osx-x64` also
admits `osx-arm64`, (b) every `switch` over a runtime identifier with an `osx-x64` case has an
`osx-arm64` case or an annotated exclusion, (c) every `importFrom` naming an arm64 package resolves
to a package, module or download declared in the nuget configuration, and (d) the architecture is
plumbed end to end from `HostCpuArchitecture` through `AmbientContext` to the Prelude union. It
distinguishes *type* positions, which are correctness failures, from *value* positions such as
`withQualifier({ targetRuntime: "osx-x64" })`, which are packaging decisions and are reported
informationally.

Running it then found three defects that neither the static pass nor code review could have found,
which is the strongest argument for having built the workflow at all:

| Defect | How it presented | Why the other checks could not see it |
|---|---|---|
| `config.dsc` used the `"arm64"` prelude literal | `DX9234` while *parsing the configuration* — a total build failure, not a bad qualifier | `config.dsc` is type checked by the engine's prelude, not the repository's |
| `osx-arm64` missing from `NugetFrameworkMonikers` | `DX11231` in `web.dsc`, five call sites away from the declaration | the table is C#; the static pass only read DScript |
| new monikers registered and consumed in one change | the same `DX11231`, for every `net11.0` runtime pack | requires an engine that has already been published |

The first two are fixed here. The third is structural and is the subject of §10.6.

### 10.6 The bootstrap order, and why this cannot land as one change

This is the most consequential thing the change set uncovered, and it was found by *running* the
build on a public Linux runner rather than by reasoning about it. Two of the three defects below
were invisible to both the static pass and to code review, and each one would have broken `main`.

BuildXL is self-hosting: the engine that constructs the pip graph is the previously published one,
never the one in the tree being built. That engine owns two pieces of vocabulary the DScript cannot
override.

**The prelude that type checks `config.dsc` ships inside the engine.**
`PreludeManager.GetPreludeRoot()` resolves to `<bxl-binary-dir>/Sdk.Prelude`, and it has to: the
engine cannot know where the repository's prelude lives until it has type checked the configuration
that declares it — `PreludeManager.cs:82-86` says exactly this. `config.dsc:31` does register the
repo prelude, but only for the main workspace, which is why every other spec in this change may use
new prelude vocabulary freely. `config.dsc` and the six files it reaches through `importFile` may
not. Writing `Context.getCurrentHost().cpuArchitecture === "arm64"` there produced:

```
config.dsc(616,0): error DX9234: Failed to parse configuration:
Operator '===' cannot be applied to types '"x64" | "x86"' and '"arm64"'.
```

The fix is to test *not x86-family* instead. `Checker.cs:15695` only requires the operands to be
comparable in one direction, and `Context.getCurrentHost()` is a call expression rather than a
narrowable reference, so no operand collapses to `never`. The expression is well typed under both
the old and the new prelude, and yields `osx-x64` on an old engine and `osx-arm64` on a new one — so
it stays correct throughout the window between landing and the first engine built from it.

**`NugetFrameworkMonikers` decides what a NuGet package even *is*.**
`KnownTargetRuntimeAtoms` decides whether `runtimes/<rid>/lib/<tfm>` assemblies count as managed
content, and `SupportedTargetRuntimes` becomes the literal union of the generated `targetRuntime`
qualifier on every generated package spec. `osx-arm64` was absent, so every osx-arm64 runtime pack
was silently downgraded to an unmanaged `NugetPackage`. It did not fail where it was declared; it
failed five call sites away:

```
Public/Sdk/SelfHost/BuildXL/web.dsc(38,21): error DX11231: Argument of type '() => NugetPackage'
is not assignable to parameter of type '() => ManagedNugetPackage'.
```

The packages themselves were fine — all of them resolve on nuget.org at the exact versions
declared. This is a C# table, which is precisely why the static pass missed it: it only read
DScript. It now reads C# too, and rejects any file that enumerates the runtime identifiers without
accounting for `osx-arm64`.

**The consequence: two stages, not one.** A runtime identifier or framework moniker must exist in a
*published* engine before any spec may reference a NuGet package under it. This is not a workaround;
it is how the repository has always done it. .NET 10 landed in exactly two stages, three months
apart:

| Date | Commit | Content |
|---|---|---|
| 2026-02-28 | `c58de3fd8` | *Add net10 support for NugetSpecGenerator* — engine only |
| 2026-05-29 | `3d62441cd` | *Add support for .net10* — the specs that consume it |

So this change set should land the same way. Stage 1 is seven files, and nothing in it references
the new vocabulary from DScript:

```
Public/Sdk/Public/Prelude/Prelude.Context.dsc              cpuArchitecture union gains "arm64"
Public/Src/Utilities/Configuration/IHost.cs                HostCpuArchitecture gains Arm64
Public/Src/Utilities/Configuration/Mutable/Host.cs         reports ProcessArchitecture
Public/Src/FrontEnd/Script/Ambients/AmbientContext.cs      maps Arm64 to "arm64"
Public/Src/FrontEnd/Nuget/NugetFrameworkMonikers.cs        registers osx-arm64 and net11.0
Public/Src/FrontEnd/UnitTests/Nuget/NuSpecGeneratorTests.cs  the generated qualifier union
Public/Src/IDE/Generator/CsprojFile.cs                     macOS host RID follows the architecture
```

Stage 2 is everything else. `.github/workflows/macos-arm64-crossbuild.yml` demonstrates both halves
in a single job without waiting for a publish in between: today's public LKG builds stage 1 and
deploys it with `--deploy-dev`, and that freshly built engine then builds the full branch with
`--use-dev`. A green stage 1 is the evidence that the first PR is landable; a green stage 2 is the
evidence that the second one is.

The remaining sequence is unchanged, only better understood:

1. Land stage 1. Verified by ordinary Windows/Linux CI, since it changes no DScript behaviour.
2. Publish an engine containing it.
3. Land stage 2, then cross-build and publish `Microsoft.BuildXL.osx-arm64`.
4. `bxl.sh` bootstraps natively on a Mac, because an LKG finally exists for it to download.

Step 4 is unreachable before step 3, and so on up. `bxl.sh` already contains the macOS support step 4
needs: it maps `uname -m` to `DotNetCoreMacArm64`/`osx-arm64` with no Rosetta fallback, guards the
`/etc/*-release` read that aborts under `set -e` on macOS, skips the Linux-only EBPF and
runtime-validation arguments, and clears `com.apple.quarantine` from the bootstrapped engine so
Gatekeeper does not refuse to execute it.

### 10.7 Running it: four more defects that only a real Mac could find

Everything above stopped at "the artifact builds". Downloading that artifact onto an Apple Silicon
Mac and running it found four further defects, none of which is visible in source review, and each of
which alone is enough to make macOS BuildXL unusable. They are recorded in the order they were hit,
because the order is the point: each one hides the next.

**1. arm64 macOS refuses to run a patched apphost.** Every BuildXL executable is a .NET apphost whose
embedded dll-path placeholder is byte-patched in place by `AppHostPatcher`. The apphost ships ad-hoc
signed by Microsoft; patching invalidates that signature while leaving the blob in place. x86_64
macOS tolerates the mismatch, which is exactly why this never surfaced while `osx-x64` was the only
macOS target. arm64 does not: the kernel refuses to map the image and SIGKILLs the process before any
code runs. The whole diagnostic is `Killed: 9`, exit 137, nothing on stdout, nothing on stderr, no log
file. `codesign -v bxl` reports `invalid signature (code or signature have been modified)`; a scan of
the deployment found 42 Mach-O files, 11 invalid, and the 11 are precisely the patched apphosts --
every runtime `.dylib` is correctly signed by Microsoft.

Fixed in `bxl.sh` rather than in the producing build, because a macOS deployment can be cross-built on
Linux or Windows where `codesign` does not exist; the consuming Mac is the first machine guaranteed to
have it. Ad-hoc signing needs no identity, which matters -- this machine has none. Naive file filters
are useless here (841 files carry the exec bit; 810 "fail" `codesign -v` only because they are `.dll`s
and exec bits do not survive zip or NuGet delivery), so the sweep filters by extension: 93 of 1893
files, 1.1 s, guarded by a one-call probe on `bxl` itself so the warm path costs 0.016 s. Files whose
signature already verifies are left alone. The durable fix belongs upstream in `Microsoft.NET.HostModel`,
whose Mach-O ad-hoc signer is pure managed code and works from any host; `AppHostPatcher` here is
consumed from a NuGet package and cannot be fixed in this repo.

**2. macOS deployments were never self-contained.** `libBuildXLInterop.dylib` is the macOS half of
`BuildXL.Interop.Unix`, and it is not optional: `BuildXLApp`'s static constructor reaches
`MachineInfo.CreateForCurrentMachine` -> `GetPhysicalMemorySize` -> P/Invoke. It was built by a
separate `xcodebuild` step and copied next to the binaries by pipeline shell steps;
`Private/InternalSdk/runtime.osx-x64.BuildXL/` seals an empty file list and no spec imports it. Linux
has no equivalent gap. The sources are 754 lines of plain C, so clang and the Command Line Tools
suffice, and the build now produces the dylib itself. Building it exposed a genuine macOS 26/27 SDK
break: `mach_absolute_time` and `mach_timebase_info` are no longer reachable transitively through
`<mach/mach.h>`, so `Dependencies.h` now includes `<mach/mach_time.h>`.

Because it needs the macOS SDK, this pip is gated on a macOS host. A deployment cross-built on Linux
therefore still arrives without it -- a documented limitation of that path, not of the change.

**3. RocksDb: a comment of mine was wrong, and checking cost ten minutes.** Section 10.4 recorded
that no arm64 macOS `librocksdb.dylib` existed, so `osx-arm64` deployed nothing and the engine died
with `DX7136 ... Failed to initialize a RocksDb store`. It does exist: the upstream `RocksDB`
package on nuget.org ships `runtimes/osx-arm64/native/librocksdb.dylib` for the same RocksDB release
(8.1.1) that Microsoft's `RocksDbNative` package wraps -- verified Mach-O arm64 with 2206 `rocksdb_*`
symbols. The two packages simply use different layouts (`build/native/<arch>` versus
`runtimes/<rid>/native`). Only that one file is consumed; the managed assemblies still come from the
signed Microsoft package. The gap was packaging, not availability.

**4. The first file access report of every macOS pip crashed the build, ten minutes later and
somewhere else.** `SandboxedProcessUnix.HandleAccessReport` filters out accesses to `libDetours.so`.
Merely *naming* `SandboxConnectionLinuxDetours` to read that constant runs its static constructor,
which resolves `libDetours.so` out of the deployment and throws when it is absent -- and macOS does
not deploy it, because nothing on macOS injects it.

The failure this produced points nowhere near its cause. The exception faults the report-processing
block, so the process-tree-completed acknowledgement queued behind it is never handled, so the root
process exit is never signalled, so `GetReportsAsync` waits out the default 10-minute pip timeout, and
only then does the build die with a catastrophic-failure stack that names neither `libDetours.so` nor
the sandbox. From the outside it is a hang. It was found by shortening the pip timeout to 25 s to
confirm which wait was stuck, then reading the crash that followed.

Two things had to be true for this to be reachable at all, which is why no Linux test covers it: the
sandbox must not be one of the Linux ones, and it must actually deliver a file access report. Finding
it therefore required the broker to be fixed first --

**...and the fix for that is a protocol defect in the broker.** BuildXL launches the broker, not the
tool, so the broker is the pip's root process as far as the scheduler is concerned. For any sandbox
that wraps the root process in a supervisor, `GetReportsAsync` will not collect a pip's reports until
an exit report arrives whose pid equals the process BuildXL launched. Endpoint Security cannot supply
it: the broker sits outside the tracked tree by design, and on the early-failure paths there is no
tracked tree at all. The broker now states its own exit as the last report before the sentinels, on
every path that closes the stream. This is not a failure-path patch -- without it the *success* path
stalls identically.

#### What this adds up to

A build ran. On this machine, with `/sandboxKind:none`, the `Examples/Walkthrough/HelloWorld` graph
executed 2 process pips in **3363 ms** and produced real outputs; a second run was **100% cache hits
in 304 ms**, an 11x speedup. That is the first BuildXL build ever executed natively on Apple Silicon,
and it is the evidence that the runtime-identifier work is complete rather than merely plausible.

The general lesson is worth stating plainly, because it recurred four times: a green cross-build
proves that an artifact can be *produced*, and says nothing about whether it can be *run*. Every one
of these defects was invisible to compilation, to the mechanical runtime-identifier checker, and to
code review, and each was found within minutes of executing the thing.

---

## 11. QuickBuild and the MSBuild project cache: what is actually available

This was researched rather than assumed, because the obvious pitch — "do what QuickBuild does" — does
not survive contact with what is publicly shippable.

- **QuickBuild is not publicly available.** It is a Microsoft-internal build service. It cannot be
  part of an external story.
- **BuildXL's own packages are not on nuget.org.** Only `win-x64` and `linux-x64` exist on the public
  feed, and neither macOS RID has ever been published (§10.1).
- **The public mechanism is the MSBuild project cache plugin API.** `Microsoft.Build.ProjectCache`
  is present in MSBuild 18.9.0-preview alongside the obsolete
  `Microsoft.Build.Experimental.ProjectCache`, and `ProjectCacheService` accepts either.
- **MSBuild's file-access observation is Windows-and-net472 only.** It is compiled under
  `FEATURE_REPORTFILEACCESSES`. Verified directly on this Mac:

  ```
  $ dotnet msbuild /reportfileaccesses
  MSBUILD : error MSB1001: Unknown switch.
  ```

The consequence is a precise asymmetry: `HandleProjectFinishedAsync` is **not** gated on
`ReportFileAccesses`, but `HandleFileAccess` and `HandleProcess` **are**. On macOS you can therefore
*store* cache entries but cannot *observe* what to key them on.

That asymmetry is the argument for the sandbox. A project cache without observation must be keyed on
declared inputs, which is exactly the assumption that makes build caches unsound. The Endpoint
Security broker supplies the missing half.

### What the measurement says the win actually is

§6 records an assumption that was wrong and worth repeating here: a comment-only edit does **not**
force MSBuild to rebuild the downstream cone. Measured, it rebuilds 1 of 40 projects, because
reference assemblies already solve that case. Claiming that win would have been trivially
disprovable.

The real gap is timestamp churn. When content is identical but timestamps move, MSBuild rebuilds
**40 of 40** projects and **all 40 outputs are byte-identical** — 12.65 s against a 15.72 s cold
build, roughly 80% of a full build, entirely wasted. That is `git checkout`, a fresh clone, and every
CI agent. MSBuild compares timestamps and cannot do better; content-based caching can. That is the
claim to make, and it is measured rather than asserted.


---

## 12. Self-hosting: BuildXL building BuildXL on Apple Silicon

§10 made `osx-arm64` a real runtime identifier and §10.7 ran a cross-built engine on a Mac. Neither
answers the question that actually decides whether macOS is a supported platform or a port: **can the
engine build itself, natively, on the machine a developer is sitting at?** As of §10.7 it could not
even construct a pip graph. It can now, and the remaining failures are all one upstream package.

The method throughout was the same one that produced §10.7's defects: run it, read what breaks, fix
the cause rather than the symptom. Four rounds of that, and each round's failures were entirely
different in kind from the last.

| Round | Succeeded | Failed | What failed |
|---|---|---|---|
| 1 | 165 | 17 | 10 build-produced apphosts killed on start, 7 `protoc` |
| 2 | 230 | 9 | 2 macOS native specs that nothing had ever evaluated, 7 `protoc` |
| 3 | 232 | 7 | `protoc` only |
| 4 | **304** | 4 | only pips needing internet access to `registry.npmjs.org` |

Round 4 supplied the missing upstream binaries by hand (§12.4). 328 process pips were in the filter;
the four that failed are the JavaScript graph builders, which run `npm install` and fail identically
on any offline machine regardless of platform. **No failure in round 4 is attributable to macOS or to
Apple Silicon.**

### 12.1 `AppHostPatcher` could not run on an arm64 Mac, for two independent reasons

Every managed executable BuildXL produces goes through `BuildXL.Tools.AppHostPatcher`, so a graph
cannot even be evaluated without it. The published package carries `tools/{win-x64,linux-x64,osx-x64}`
and nothing else, which is why §10 listed it as blocking the *next* step. It is worth writing down
what was actually wrong, because "add an osx-arm64 leg to the pipeline" would not have been enough.

**The assembly itself was stamped x64.** `AppHostPatcher.csproj` set `<PlatformTarget>x64</PlatformTarget>`,
so the PE header of `AppHostPatcher.dll` said `machine = 0x8664`. An arm64 host cannot load that IL at
all, self-contained or not:

```
System.IO.FileLoadException: The assembly architecture is not compatible with the current process
```

There is no reason for the setting — the tool reads and rewrites bytes in a file. Removing it makes
the assembly architecture-neutral and lets the runtime identifier decide, which is what the publish
pipeline was already parameterised on.

**The publish legs never passed a runtime identifier.** `.azdo/publish-app-host-patcher` ran
`dotnet build --configuration Release --output ...` with no `--runtime`, under `SelfContained=true`.
Each leg therefore published whatever the agent happened to be, and was correct only by coincidence.
That is a latent bug quite apart from arm64: the moment `macos-latest` became Apple Silicon, the leg
labelled `osx-x64` would have silently published arm64 binaries into the `osx-x64` folder. Fixed by
passing `--runtime ${{ parameters.platform }}` on every leg, and adding the `osx-arm64` one.

### 12.2 Defect 4 again, in the form `bxl.sh` cannot reach

§10.7 recorded that arm64 macOS SIGKILLs unsigned patched apphosts, and fixed it with a signing sweep
in `bxl.sh`. That sweep repairs a *downloaded* deployment. It cannot help the build itself, because
BuildXL patches apphosts *during* the build and immediately executes them as tools — `ResXPreProcessor`
and friends. Those pips die with `exit code 137` and `Tool failed without writing any output stream`,
which names neither signing nor the patcher. Ten of them in round 1, plus everything downstream.

The fix belongs in the patcher, which is the only component that knows it has just written a Mach-O:
after patching, if the host is macOS *and* the patched image has a Mach-O magic number, ad-hoc sign it.
Both conditions matter — a Mac can cross-build for Windows, and signing a PE file is not a no-op, it is
an error. Round 2 had zero exit-137 failures.

Two details are load-bearing:

- The signing happens in a temp directory and the result is moved back. `codesign` writes a `.cstemp`
  sibling of its target, and the patched binary's directory is a declared build output whose contents
  are checked; leaving a stray file there fails the pip.
- Cross-builds from Linux and Windows still emit unsigned macOS binaries, so `bxl.sh`'s sweep is still
  required for those. The durable fix is `Microsoft.NET.HostModel`'s managed Mach-O signer, but the
  pure-managed implementation landed only recently — the version in use here shells out to `codesign`,
  which does not exist on a Linux agent. Worth revisiting on a newer package, not before.

### 12.3 Two macOS specs that nothing had ever evaluated

The interop dylib and the ES broker are both built by DScript guarded on `isMacOsHost`. There was no
macOS CI, and no Mac could construct a graph, so neither spec had ever run — they were written, reviewed,
and committed without a single evaluation. Both were wrong, and both were wrong in ways review had no
chance of catching:

- `sandboxSourceRoot` pointed three levels up, one level too far. The spec sits in
  `Public/Src/Sandbox/MacOs/Sandbox`, so three levels reaches `Public/Src`, not `Public/Src/Sandbox`.
- Both specs passed their headers on the clang command line as `Artifact.input`. Naming a `.h` on a
  clang command line does not add an include — it asks clang to *precompile* that header, which means
  multiple outputs: `clang: error: cannot specify -o when generating multiple output files`. Headers
  belong in `Transformer.execute`'s `dependencies`, where they are inputs for fingerprinting without
  becoming compilation units.

With those fixed, BuildXL builds `libBuildXLInterop.dylib` and `bxl-es-broker` itself, for both macOS
runtimes, in 7.75 s — verified Mach-O arm64 and x86_64 as declared. `/f:tag='macos'` now selects six
pips: those four, plus the self test compile and its run. Six rather than seven because `broker` is
*referenced* — `BuildXL.Processes.dsc` pulls it into the deployment at both `osx-x64` and `osx-arm64`,
forcing the spec at both — whereas nothing references `selfTest`, so it is only evaluated at the
spec's own default qualifier, which `config.dsc` derives from the host. That makes six a property of
a default-qualifier build rather than of the spec: an explicit `/q:` naming both runtimes would
compile the self test twice.

The same gap applied to the self test, which had the same excuse and less justification: it is the only
soundness check that runs without an Apple entitlement, and it was not built by any spec either, so it
ran when somebody remembered to invoke clang by hand. It is now two pips — build, then run — and the
run is scheduled only when the target architecture is the host's, because a cross-built binary cannot
be executed and skipping beats depending on emulation. The self test exits non-zero on any failed
check, so the pip failing *is* the assertion. Measured as a pip on an arm64 Mac: **65 checks, 0
failures in 7.4 s**, ingress p50 208 ns / p99 334 ns, 0 events rejected.

Two things about that pip are deliberate, and both were wrong in the first version of it.

The first is what it asserts. The self test's gates are not all the same kind of claim. The
correctness gates compare what the protocol reported against what the corpus actually did, and the
answer does not depend on the machine — those must fail the build. The throughput and latency gates
measure the hardware and its current load at least as much as they measure the code, and this pip runs
while the rest of the build is saturating the same cores. The effect is not hypothetical. Running the
same binary twice in one session on one idle-ish Mac, once directly and once as the pip, moves the
ingress numbers by 4-5×: **p50 42 ns / p99 84 ns standing alone, p50 208 ns / p99 334 ns as a pip**.
(Neither is §4.1's D1 row, which is a third run — a full-sweep benchmark. That is the point: the
figure moves between runs of unchanged code, which is exactly what must not decide an exit code.)
Wiring that into the exit code buys nothing and costs a flaky build failure whose message is about
events per second. So the pip passes
`--no-perf-gates`: the numbers are still measured and still printed into `selftest.log`, and the
header line records which mode produced them, but only a deliberate `./bxl-es-selftest` run on a quiet
machine can fail on them. That is the difference between 67 checks and 65.

The second is how long it takes. The default sweep is 100,000 scenarios and took 192 s, almost all of
it asleep: roughly one scenario in seventeen drops the closing marker on purpose, and each of those
waits out the fence timeout. Scenarios are generated from the iteration index, so a shorter sweep is a
prefix of the long one rather than a different sample — 2,000 scenarios still produce 1,064 faulty
runs covering all 10 fault dimensions and 43 of the 45 fault pairs, which is what a per-build
regression check needs, and the run drops to under 10 s. The full sweep remains the default when the
binary is invoked directly, and §4.1's row A is stated against that.

The pip is otherwise an ordinary cacheable process pip, which is the right answer and worth stating
because it is easy to mistake for a bug: its fingerprint includes the self test binary's content hash,
so any change to the engine sources, the shared Linux policy sources, or the test itself re-runs it,
and a build that changed none of those replays the log. A test whose inputs did not change does not
need to run again — that is the entire premise of the build system it is testing.

### 12.4 The last blocker was upstream, and it is one folder

Rounds 2 and 3 ended with the same seven failures: `protoc`, with `ProcessStartFailure`. The cause is
`protoc.dsc` choosing its binaries from the host *OS* with no architecture dimension at all — every
macOS host got `tools/macosx_x64`, which on a Mac without Rosetta 2 cannot start.

Making the selection architecture-aware is necessary but not sufficient, because there is nothing to
select:

- `Grpc.Tools` ships `linux_arm64` but **no `macosx_arm64`** — verified at 2.71.0 and at 2.83.0, two
  years apart. `lipo -archs tools/macosx_x64/protoc` reports `x86_64`.
- `Google.Protobuf.Tools` has the same gap.
- `grpc/grpc` publishes **zero binary assets** on its GitHub releases, so there is no other official
  source for `grpc_csharp_plugin`.

Both halves are needed: of the seven pips, three use only `protoc` and four also need the C# plugin.

**This is genuinely all that is left.** To prove that rather than assert it, round 4 supplied the
missing folder: `protoc` 29.0 for `osx-aarch_64` from protobuf's own GitHub release — the exact version
`Grpc.Tools` 2.71.0 bundles — and `grpc_csharp_plugin` 1.71.0 built for `osx-arm64`, matching
`Grpc.Tools` 2.71.0 exactly. Repacked into a local `Grpc.Tools`, **all 31 protobuf codegen pips in the
graph succeed natively in 3.5 s**, and the C# they generate is the same code the x64 tools produce.

One mitigation that looks obvious does **not** work, and is worth recording so nobody plans around it: a
shared content cache does not rescue these pips. A pip's fingerprint includes its tool's content hash,
and the Linux and macOS `protoc` binaries are different files, so a macOS build cannot hit on entries a
Linux build stored. There is no path around a native binary here.

The committed change therefore asks the package what it contains rather than hard-coding today's answer:
prefer the folder matching the host architecture, fall back to the x64 one when it is absent. Linux
arm64 gains its native `protoc` immediately, since that folder already exists. macOS arm64 keeps exactly
the behaviour it has today — verified: the fallback selects `tools/macosx_x64` and fails precisely as
before — and switches to native, with no code change, the day upstream adds the folder.

Note what this says about the runtime-identifier validator from §10.5: it proves every runtime-identifier
*switch* is complete, and this predicate was not one. It tested `os` and never mentioned architecture, so
there was nothing incomplete for the checker to find. A blind spot of exactly the shape §10's self-review
warned about.

### 12.5 Defect 7, measured

§10.7 explains why the first file access report of every macOS pip took the build down ten minutes later
and somewhere else. That fix has now been verified end to end on a cross-built engine, running
`Examples/Walkthrough/HelloWorld` under `/sandboxKind:macOsEndpointSecurity`:

| | Before | After |
|---|---|---|
| Time to failure | ~10 min (default pip timeout) | **1237 ms** |
| Total wall clock | ~10 min | **3 s** |
| What the error said | catastrophic failure naming neither the sandbox nor `libDetours.so` | the broker's own diagnostic, relayed verbatim |

The pip still fails, because the entitlement is still missing (§7, blocker 1) — but it now fails in the
way a missing entitlement should: immediately, and saying so. That is the whole difference between a bug
and a documented external dependency.

### 12.6 What is verified in CI

The GitHub Actions workflow now runs three jobs, and the third is the one that matters here: a Linux
runner bootstraps BuildXL from the public feed and cross-builds an `osx-arm64` deployment, then a **real
Apple Silicon runner** (`macos-26-arm64`, asserted with `uname -m`) downloads it, restores the execute
bits that artifact upload strips, and builds `HelloWorld` twice. Cold: 2/2 processes, real outputs,
asserted on content. Warm: **2/2 cache hits, 100% cache savings**. Every assertion fails the job loudly
rather than passing silently on a missing file.

That closes the loop §10.6 described: nothing in this change set is now taken on trust from a green
compile.

One thing CI still cannot do: run the sandbox self test. GitHub's hosted macOS runners are `macos-26`,
and `es_new_descendants_client` — the API the whole design rests on (§2) — arrived in macOS 27. The
broker does not compile against a macOS 26 SDK, by construction rather than by accident. The self test
therefore runs as a pip on a developer's machine (§12.3) and will run in CI the moment macOS 27 runners
exist, with no change needed.

### 12.7 What remains

| Blocker | Nature | Who can fix it |
|---|---|---|
| ES entitlement | External (Apple) | Not us. Gates C and E are met through the interposition ingress instead (§4.2, §13); the entitlement is needed only for the enforcement-grade ingress |
| `Grpc.Tools` has no `macosx_arm64` | External (grpc) | Upstream, or a `protoc`/plugin source of our own; the selection code is already in place |
| `BuildXL.Tools.AppHostPatcher` has no `tools/osx-arm64` | Internal, fix written | `.azdo/publish-app-host-patcher` must publish once |
| `RocksDbNative` has no arm64 macOS dylib | External, worked around | Resolved by taking the file from the upstream `RocksDB` package (§10.7) |

The AppHostPatcher entry is the only one under this repository's control, and it is a pipeline run rather
than a code change. Everything else is either an upstream package or Apple.

---

## 13. Gates C and E: BuildXL building BuildXL on Apple Silicon, under the sandbox

Everything before this section is about whether a macOS sandbox can be built. This section is about
whether it is worth having, which is a different question and the only one that decides anything.

The subject is BuildXL building itself on an Apple Silicon Mac: **294 process pips**, the real
dependency graph, the real content cache. Not a synthetic workload — there is no way to argue about
whether a synthetic workload is representative, and every earlier attempt in this work to shortcut to
a smaller demo produced a number that turned out to mean nothing.

### 13.1 What is being compared

Two arms, identical in every respect but one:

| Arm | Meaning |
|---|---|
| `/sandboxKind:macOs` | the interposition ingress driving the shipping broker engine |
| `/sandboxKind:none` | the control: BuildXL with no observation at all, which is what macOS had before this work |

Five scenarios, each repeated, each preceded by an untimed settle build so that what is timed is the
steady state rather than the first build after a wipe:

| Scenario | Setup | What it answers |
|---|---|---|
| `cold` | wipe `Cache.noindex`, `Objects.noindex`, `Bin` | what does observation cost when nothing can be reused? |
| `cache-restore` | wipe outputs, keep the cache | can a fresh enlistment be served from cache? |
| `no-op` | change nothing | what does the engine cost when there is no work? |
| `leaf-change` | touch one leaf source file | does one edit re-execute one thing, or everything? |
| `core-change` | touch a widely-depended-on file | does a deep edit re-execute exactly its cone? |

The filter is the deployment minus four JavaScript graph-builder pips, which need an authenticated
npm feed this machine has no credentials for. They are excluded by output path so they leave the
graph entirely, rather than failing slowly inside every measurement. They fail identically with the
sandbox off, so excluding them removes network noise, not sandbox cost. The control arm exists
precisely so that this choice cannot flatter the result: any bias it introduces applies to both arms.

#### How the arms are scheduled, and the false assumption that made the first attempt worthless

The first version of this measurement ran every `macOs` sample, then every `none` sample. On a shared
workstation that design cannot be defended: any drift in machine state between the two blocks is
perfectly confounded with the arm. It duly failed. Microsoft Defender reacted to the file churn of a
wiped output tree, drove the one-minute load average past 40, and **tripled** the second block's wall
clock at identical pip counts. The result — "the sandbox is 3× *faster* than no sandbox" — was only
caught because its sign was absurd. A 20% error in the plausible direction would have been published.

The block design existed to work around an assumption stated in an earlier draft of this section:
that `/sandboxKind` participates in the pip fingerprint, so switching arms would force a full
re-execution. **That assumption is false, and measuring it is what unblocked this.** Alternating
`macOs`/`none`/`macOs`/`none` on a fully cached tree gives 294/294 cache hits every time. The sandbox
kind governs how an execution is *observed*, not what the pip *is*, so both arms address the same
cache entries. Three consequences, all good:

- Samples can be **paired**: within a replicate both arms run back to back, seconds apart, and the
  order flips between replicates. The statistic of record is the median of the within-pair ratios,
  not the ratio of the per-arm medians. A load excursion inside a pair perturbs both arms together
  and largely cancels.
- Every timed sample waits for the one-minute load average to fall back below 5 first. Without that
  gate the load walked 5 → 18 across a single series, because the load a sample sees is mostly decay
  from the sample before it, and one sample took 61 s against a 32 s neighbour at an identical pip
  count.
- Execution scenarios stay honest under pairing because each sample applies its own unique edit, so
  the second arm of a pair cannot free-ride on the first arm's cache entry. Verified: a leaf-change
  executes exactly 2 pips in both arms of every pair.

One scenario needed a further guard. `core-change` executes **either 30 or 49 pips from an identical
edit**, in both arms, splitting the wall clock into clean clusters near 14 s and 32 s. Comparing
across those clusters produced a "1.618×" that measured nothing but which cluster each arm landed in.
It is not the sandbox — both arms show both values at similar rates — and it did not reproduce in
twelve consecutive ungated builds, so it is some pre-existing convergence behaviour in BuildXL's own
graph. Rather than explain it, the harness **discards any pair whose two arms executed different pip
counts** and retries, and the table below reports the two work classes as separate rows. 13 pairs
were discarded this way to obtain 5 matched ones.

### 13.2 Results

Apple M2 Pro, 10 cores, 32 GB, macOS 27.0, arm64. Harness and raw data: `bench.py`,
`bench-table.py`, and the `bench-*.json` result files.

**What the sandbox costs.** Paired samples, interleaved arms, load-gated. "Paired ratio" is the
median of the within-pair ratios; `unpaired` means the scenario wipes the cache, so its two arms
cannot share state and the figure is the ratio of the per-arm medians.

| Scenario | Process pips executed | `/sandboxKind:macOs` | `/sandboxKind:none` | Paired ratio | Pairs |
|---|---|---|---|---|---|
| No source change | 0 of 294 | 7.1 s | 7.2 s | 0.992× | 4 |
| Change one leaf file | 2 of 294 | 10.8 s | 10.5 s | 1.044× | 4 |
| Change a core file (30-pip case) | 30 of 294 | 14.2 s | 14.2 s | 1.029× | 3 |
| Change a core file (49-pip case) | 49 of 294 | 31.5 s | 35.1 s | 0.920× | 2 |
| Restore from warm cache | 0 of 294 | 16.4 s | 15.9 s | 1.033× | unpaired |
| Cold build (empty cache) | 294 of 294 | 163 s | 137 s | 1.186× | unpaired |

The 49-pip row has two pairs and one of its `none` samples is a 40 s outlier against a 30 s
neighbour; read it as "no measurable difference", not as the sandbox being faster. The same applies
in the other direction to the 4.4% on the leaf row. The only cost here that is larger than the noise
is the cold build.

**What the sandbox buys.** The same machine, against a full build — which is the honest alternative,
because an enforcing sandbox is what makes it defensible to skip work at all:

| Developer action | Full build | Incremental, sandbox on | Speedup |
|---|---|---|---|
| No source change | 163 s | 7.1 s | **23×** |
| Change one leaf file | 163 s | 10.8 s | **15×** |
| Change a core file (30-pip case) | 163 s | 14.2 s | **11×** |
| Change a core file (49-pip case) | 163 s | 31.5 s | **5×** |
| Delete every output and rebuild | 163 s | 16.4 s | **10×** |

The last row is worth its own sentence. `rm -rf Out/Objects.noindex Out/Bin` — every build output on
the machine, gone — comes back in **16 seconds, 294 of 294 pips served from cache**, with the sandbox
on. That is the state a developer reaches by switching branches or running a clean, and on macOS
before this work it cost a full rebuild every time.

Raw samples, every one a wall-clock measurement of a command a developer would type:

- `no-op` macOs: 7.16, 7.10, 7.17, 7.01 s — none: 7.28, 7.03, 7.30, 7.01 s
- `leaf-change` macOs: 10.82, 10.79, 10.86, 11.56 s — none: 10.30, 10.26, 10.67, 11.14 s
- `core-change` macOs: 14.22, 14.08, 31.85, 14.68, 31.12 s — none: 14.15, 13.68, 29.75, 14.27, 40.48 s
  (13 further pairs discarded for unmatched work)
- `cache-restore` macOs: 16.44, 16.89, 16.23 s — none: 16.76, 15.92, 15.89 s
- `cold` macOs: 161.82, 163.96 s — none: 143.34, 131.43 s

### 13.3 What the numbers say

**Incrementality works (gate C).** A one-line change to a leaf source file re-executes **2 pips out
of 294** and the build settles in **10.8 s**. The same edit unsandboxed re-executes the same 2 pips
in 10.5 s. That equality is the whole point: the sandbox is not approximately as precise as no
sandbox, it is *exactly* as precise — identical pip counts in every single pair, in every scenario —
while additionally being able to tell you when your graph is wrong. A change to a widely-depended-on
file re-executes its cone, 30 or 49 pips, not the build.

**The win is real (gate E).** A full build is **163 s**; the edits a developer actually makes cost
**7–32 s**. That is **5× to 23×**, and it is the number that decides whether anyone adopts this. It
is not a sandbox result — it is a BuildXL result. The sandbox's contribution is that this is now
available on macOS *soundly*, where before the only way to get it was to turn observation off and
hope.

**Observation costs what it should, where it should.** Within noise when nothing executes, ~3–4% on
incremental builds, and **~19% on a cold build** where all 294 pips run and every access they make is
reported. The cost is proportional to work done, which is the shape you want: the builds that are
already fast stay fast, and the one that pays is the one you run least often.

That 19% figure replaces a "~6%" in an earlier draft of this section. The 6% came from the blocked
run described above, which was contaminated; it was too flattering, and it is corrected here rather
than quietly dropped.

### 13.4 Two defects the measurement found

Neither would have been found by a test, because both produced *correct builds*. They are the
argument for measuring incrementality rather than asserting it.

**Opening a directory is not enumerating it.** The first benchmark showed the sandboxed arm collapsing
to 159 hit / 135 executed on every incremental build while the control held 292/2 — a build 3× slower
that never converged, no matter how many times it was repeated. The cause was that `opendir` reported
a directory enumeration. An enumeration record makes the engine put the directory's entire membership
into the pip's path set, so 133 NuGet pips each had a fingerprint that depended on every name in a
directory that other pips write to. Linux draws this line correctly and always has
(`detours.cpp`, `opendir` → `kGenericProbe`); the macOS ingress did not. Opening a directory is now a
probe, and enumeration is reported on `readdir`/`readdir_r`/`__getdirentries64`/`getattrlistbulk` —
the calls that actually read entries. Measured before and after: **159 hit / 135 executed / 63 s →
292 hit / 2 executed / 20 s.**

**A reported path has to be the path the engine will look for.** The interposer built its report path
by joining the working directory to whatever string the caller passed, and stopped. `cp ../../input
out` was reported as a read of `/repo/Out/Bin/../../input`. The engine matches reported paths against
the pip's manifest by string, so that misses every rule naming the file, and an ordinary relative read
of a *declared* dependency was reported as an undeclared access. What made it expensive to find is
that the engine renders the collapsed form in its own messages — the violation it printed named a path
that was, as printed, allowed. It was found by teeing the raw report stream and reading the wire form.
Paths are now collapsed lexically before reporting; `realpath()` would have been wrong twice over,
since it resolves symlinks (a build under `/tmp` would report `/private/tmp` and disagree with the
spec) and fails on paths that do not exist, which is exactly the absent-path probe the sandbox most
needs to report.

### 13.5 One residual: observation has a convergence cost, and it is real

After both fixes, the first build following any wipe of the object root still re-executes the 133
NuGet download pips before settling permanently. An earlier draft of this section argued this was not
the sandbox. The final measurements say otherwise, and the correction is worth more than the original
claim.

The settle build that follows each **cold** build was recorded for both arms, and the split is
perfect across **6 of 6** trials, with the arm order alternating and every trial starting from a
wiped cache:

| Arm | Build after a cold build | Result |
|---|---|---|
| `/sandboxKind:macOs` | 3 of 3 | 161 hit / **133 executed**, 54–60 s |
| `/sandboxKind:none` | 3 of 3 | **294 hit / 0 executed**, 8–13 s |

Each `cold` wipes everything, so both arms start from identical state and the arm is the only
variable. It is arm-caused.

The earlier evidence was not wrong, it was answering a narrower question. Teeing a cold build's full
report stream does show **zero** enumeration records on the package root across all 133 NuGet pips —
only 30 directories are enumerated in the whole build and that is not one of them — so it is not the
`opendir` defect returning. What it is instead: with `/sandboxKind:none` BuildXL observes *nothing*,
so those pips' strong fingerprints have no observed inputs and there is nothing that can later
mismatch. With the sandbox on they record what they actually touched, including probes of a package
root that other pips are still materialising into, and when that state changes the next lookup
misses.

So the `none` arm's 294/294 hit is not the sandbox being slow. **It is the same unsound hit the
correctness demo below constructs deliberately, occurring by itself in BuildXL's own build.** The
control arm "wins" that comparison by declining to look.

**It is a one-time convergence cost, not a standing tax**, and the `cache-restore` scenario is the
control that shows it. Once the cache has converged, deleting every output and rebuilding gives
**294 of 294 hits in both arms** — 16.4 s sandboxed against 15.9 s unsandboxed, three samples each —
even though that scenario also wipes the package root. The sandbox pays one ~55 s build after a cache
is first built, and nothing thereafter.

BuildXL materialises package contents on demand — the package root goes from **39 entries to 133**
across a single two-pip incremental build — so any correct observer will see state there change,
because it does change. That is BuildXL's own lazy materialisation, not something macOS-specific, and
the right fix is upstream of this work.

### 13.6 What the sandbox is actually for

The speedup above is the reason to use BuildXL. The sandbox is the reason to trust it. The following
runs end to end from `correctness-demo.sh`; a pip reads two files and declares one:

```
1. Build with no sandbox                      report.txt: declared-v1, undeclared-v1     (correct)
2. Change the undeclared file, rebuild        Processes: [1 done (1 hit)]  Build Succeeded
                                              report.txt: declared-v1, undeclared-v1     (STALE)
                                              should be: declared-v1, undeclared-v2-CHANGED
3. The same build, with the sandbox           error DX0500: Disallowed file accesses:
                                                R  /Users/.../undeclared.txt
                                              Build FAILED
```

Step 2 is the failure mode in one line: the build **succeeds**, reports a **100% cache hit**, and
produces a **silently wrong artifact**. Nothing in the log suggests anything is wrong, because from
the engine's point of view nothing is — it was told the pip depends on one file, that file has not
changed, so the cached result is valid. It is only invalid in the sense that it is not what the source
tree says, and no amount of care in the engine can detect that without observing the process.

That is what macOS had before this work, and what `/sandboxKind:none` still means. Step 3 is what it
has now.

#### The same thing, not staged

The demo above is constructed, which is a fair thing to hold against it. So here is the sandbox
catching something nobody planted, in BuildXL's own build, on one of the cold runs measured for this
section:

```
error DX0500: [Pip40284FF79D2F668C, ResGen.Lite, BuildXL.Utilities, Configuration.dll]
  Disallowed file accesses were detected (R = read):
   R  .../Out/Bin/release/osx-arm64/System.Private.CoreLib.dll
  Violations related to pip(s):
   PipCFC60D96B74282C4, <COPYFILE>, BuildXL.Deployment, BuildXL.deployed
```

A codegen pip read a file produced by a *different* pip that it does not depend on. That is a race:
the two pips are unordered, so whether the read sees the finished file, a partial one, or nothing at
all depends on scheduling. It has reproduced once in nine cold builds and not at all on the settle
builds, which is exactly the signature of a race and exactly why it survives in a build nobody
observes. With `/sandboxKind:none` it is not merely tolerated — it is invisible, and its result is
cached.

Being precise about what is and is not established: the read is of a real file, attributed by the
engine to a real producing pip. The obvious way for that to be *wrong* is a hard link. BuildXL
materialises deployments by hard-linking, and `ResGen.Lite`'s own deployment contains a
`System.Private.CoreLib.dll` which is — verified with `stat` — **the same inode** as the file named in
the violation, one of six links to it. If any layer recovered a path from a descriptor rather than
using the caller's own string, it could name any of the six.

That hypothesis has been tested rather than argued about, and it is **refuted**:

- **The observer reports the path the caller passed.**
  `Public/Src/Sandbox/MacOs/Interpose/interpose-trace.py` is a standalone listener for the wire
  protocol: it runs a program under `libBuildXLInterpose.dylib` with no broker and no build, and
  prints every record. Against a two-link inode it reports `/tmp/hltest/alias.bin`
  when the program opens the alias and `/tmp/hltest/real.bin` when it opens the other link. No
  resolution happens.
- **Nothing downstream canonicalises either.** The interposer is lexical on purpose (§7), the broker
  never calls `realpath`, and BuildXL's managed report path has no identity-based reverse lookup.
- **The tool does not read that path.** Running the shipped deployment under the tracer produces 516
  records and **zero** under `Out/Bin`. Independently, in a *successful* cold build with
  `/logObservedFileAccesses+`, the same pip produced 502 access reports and **zero** under `Out/Bin`.
- **It is not cross-pip attribution.** Each pip gets its own broker and its own socket, so a record
  cannot arrive from another pip's process tree.

So the violation is rare, real, and not manufactured by the observation layer — but the mechanism that
produces it is still not established, and it is recorded as open in §13.7 rather than claimed as a win.
The honest summary is that the sandbox reported something true and surprising about a build that has
never been observed before, which is precisely what it is for.

### 13.7 Honest limitations

- **The interposition ingress observes cooperating processes.** A process can defeat it by making raw
  syscalls, by `dlopen`-ing a fresh libc, or by being a statically linked binary. Every real build
  tool cooperates, so it is sound for the problem it solves — telling you your graph is wrong — and it
  is not a security boundary. The ES ingress is, and is what the entitlement is for.
- **A statically linked tool is invisible, not partially visible.** There is no half-observation to
  reason about, but there is also no warning; a build made entirely of static binaries would be
  reported as clean.
- **Process identity is weaker than under ES.** Lineage comes from the reported pid/ppid pair rather
  than from an audit token, so pid reuse within a build is possible in principle. Reports are matched
  to the nearest preceding `exec` for that pid.
- **`F_GETPATH` resolves symlinks.** Enumeration records reached through a descriptor therefore report
  the resolved path, while `open`/`stat` report the path as written. Under a repository root this
  never diverges; under `/tmp` on macOS it always does.
- **The sandbox library is not part of the pip fingerprint.** Changing observation fidelity does not
  invalidate results computed under the old library. Correct today because the ingress only ever
  reports more, never less, but it is an assumption rather than a guarantee.
- **One reported violation is not yet explained.** The `ResGen.Lite` read in §13.6 has reproduced once
  in nine cold builds. Four candidate explanations have been tested and eliminated — hard-link
  ambiguity in the observer, canonicalisation anywhere in the chain, the tool genuinely reading the
  path, and cross-pip report attribution — which narrows it but does not close it. Until a run that
  reproduces is captured, the honest statement is that a cold macOS build under the sandbox succeeds
  most of the time and reports this the rest of the time. Every incremental scenario in §13.2 —
  40-plus builds — was clean.
- **The measurement is one machine and one build.** An M2 Pro building BuildXL. The shape of the
  result (cost proportional to work; identical pip counts in both arms) should generalise; the
  constants will not.
