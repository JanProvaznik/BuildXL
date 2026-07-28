# macOS sandbox (Endpoint Security)

Status: **implemented and self-verified; blocked on an Apple-issued entitlement for end-to-end
validation.** This document records what was built, what has actually been proven, what has not,
and what remains before macOS reaches Linux parity.

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

Reproduce (the suite is built from
`Public/Src/Sandbox/MacOs/Sandbox/UnitTests/bxl-es-selftest.cpp` together with the broker sources
and the shared Linux policy sources):

```bash
./bxl-es-selftest      # conformance + fault injection + benchmarks
# => 67 checks, 0 failures
```

D2 is worth a note: the first implementation managed 14,579 events/s, which would have made the
broker the bottleneck on any real build. Batching the queue drain and buffering sink writes brought
it to 562,556 events/s — a 38× improvement — and the benchmark exists so that a future regression
is caught rather than discovered in production.

### 4.2 Not proven — requires the entitlement

| Gate | What it needs |
|---|---|
| **C. Incrementality precision** — real cache hits on a real build | a signed broker |
| **E. Real-build win** — measured speedup vs. today | a signed broker |

The harness for both is written and tested (§5). Nothing is blocked on further design work.

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
    --label macos-es --sandbox-kind MacOsEndpointSecurity --repeats 5 \
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
| `RocksDbNative` 8.1.1 | Ships `build/native/amd64` only | Fails with a message naming the exact artifact that must be published (`build/native/arm64/librocksdb.dylib`), rather than a generic missing-file error |
| `crossgen` | Not known to exist in `Microsoft.NETCore.App.Runtime.osx-arm64` | Deliberately unhandled. It is an optional optimisation and an unhandled runtime already falls through to "no crossgen available". A case pointing at a file that may not exist would turn an optimisation into a build break |
| `BuildXL.Tools.AppHostPatcher` 2.0.0 | Ships `tools/{win-x64,osx-x64,linux-x64}` | The patcher is selected by **host** architecture and the apphost by **target**; these are different axes and were previously conflated. Cross-building `osx-arm64` from Windows or Linux works today; running the patcher natively on an arm64 Mac needs a `tools/osx-arm64` entry in that package |

### 10.5 Verification

BuildXL cannot be built or run on `osx-arm64` yet — that is what this change enables — so the
DScript here cannot be evaluated locally and CI is the verification step. This is the same caveat
that applies to the sandbox specs and the .NET 11 change set. What *was* checked:

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

### 10.6 The bootstrap order

There is a chicken-and-egg problem worth stating plainly, because it determines the landing sequence:

1. Land the RID support (this change). Verified by Windows/Linux CI.
2. CI cross-builds an `osx-arm64` deployment and publishes `Microsoft.BuildXL.osx-arm64`.
3. `bxl.sh` can then bootstrap natively on a Mac, because an LKG exists for it to download.

Step 3 is unreachable before step 2, and step 2 is unreachable before step 1. `bxl.sh` already
contains the macOS support needed for step 3; it maps `uname -m` to `DotNetCoreMacArm64`/`osx-arm64`
with no Rosetta fallback, guards the `/etc/*-release` read that aborts under `set -e` on macOS, skips
the Linux-only EBPF and runtime-validation arguments, and clears `com.apple.quarantine` from the
bootstrapped engine so Gatekeeper does not refuse to execute it.

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
