# macOS sandbox (Endpoint Security)

Status: **implemented, self-verified, and measured end to end on a real build.** BuildXL builds
itself on Apple Silicon under this sandbox — 294 process pips — and incremental builds are **5–23×**
faster than a full build at 0–4% observation cost (§13). Churning the timestamps of all 6,284 source
files without changing a byte re-executes **zero** of the 294 pips, where MSBuild rebuilds 40 of 40
projects for the same event (§13.7). The Endpoint Security ingress, which is the
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

There are two ways to carry that capability, and conflating them is what made an earlier draft of
this section unreadable:

| | Entitlement from Apple | SIP + AMFI relaxed locally |
|---|---|---|
| What it is for | shipping to other people's Macs | answering questions on a development machine |
| Cost | a developer account and an Apple approval | one machine deliberately made less secure |
| Sufficient to run ES? | yes | **yes** |

**The second route was taken, and the sandbox has now been run.** SIP was disabled and
`amfi_get_out_of_my_way=0x1` set, which lets an ad-hoc signature carry
`com.apple.developer.endpoint-security.client`. Everything in §4.4 is a live kernel measurement:
14,714 real `es_message_t`s, four defects found that 100,000 replayed scenarios could not, and the
client budget quantified.

So the remaining dependency on Apple is narrower than it looks. It is **not** needed to know whether
the design works - that is answered. It is needed to *distribute* BuildXL with the ES backend
enabled, because no user is going to disable SIP. Which is a shipping prerequisite, not a research
risk, and the entitlement is routinely granted to build and security tooling.

The build measurements in §13 and §14 remain the dyld-interpose backend, which needs no entitlement
and no SIP change and is what a developer gets today.

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
| **E. Real-build win** | measured speedup on a real build | **MET** — 5–23× against a full build, at 0–4% observation cost incrementally and 19% cold; 0 of 294 pips re-executed on pure timestamp churn (§13) |

The measurement is BuildXL building itself on Apple Silicon: 294 process pips, the real graph, the
real cache. §13 has the numbers, the protocol, and the two defects the measurement found.

What interposition does *not* give you is written down in §13.5 rather than glossed: it observes
cooperating processes, so it is a correctness tool for a build, not a security boundary. The ES
ingress remains the answer for anyone who needs the latter.

Gates A, B, B2 and D1–D3 are measured against the engine that the ES ingress feeds, driven by
`ReplaySource`, not against `EsIngress` itself. Per §3 that is evidence about the protocol and never
about the kernel — a distinction §4.4 then proved was not pedantic, since the kernel went on to
expose four defects the replay sweep could not see.

Every **build** measurement in §13 and §14 used the dyld-interpose backend, and the execution logs
record `Context: macOS sandbox (dyld-interpose backend)` for all 81 tainted pips. The live ES numbers
are confined to §4.4 and are workload measurements rather than build measurements; the two are not
mixed anywhere in this document.

### 4.3 Bugs this work found and fixed

Recorded because they are the concrete argument for the fault-injection approach — all three were
found by tooling, and all three would have been silent in production:

| Bug | Consequence had it shipped |
|---|---|
| The root process's start event was suppressed. `fromBroker` was computed from the event *actor* before the `FORK` handler rewrites `self` to the child, so the broker forking the pip root looked like a broker self-event. | BuildXL would never see the pip's root process start. |
| Every build began with an `UnmappedLineage` taint, because the root's `FORK` names the broker as parent and the broker was not in the process table. | Every build permanently uncacheable — the exact failure this project exists to prevent. |
| The broker `SIGTRAP`ped at teardown: `FileAccessManifest` takes ownership through `unique_ptr<char[]>` but was handed `std::vector::data()`. | Double free at the end of every pip. |

### 4.4 The ES ingress, run live against the real kernel

This section used to be a list of things the missing entitlement left unproven. Every row in it is
now closed. SIP and AMFI were relaxed on a development machine so an ad-hoc signature could carry
`com.apple.developer.endpoint-security.client`, which is the same capability Apple grants by
entitlement and is enough to answer every question that had been open. What it does not substitute
for is *shipping*: a distributed BuildXL still needs the real entitlement. It substitutes for
guessing about behaviour, which is what §4.4 previously had to do.

| Was unproven | Now |
|---|---|
| `EsIngress::Normalize` maps a real `es_message_t` for every subscribed type | 14,714 real kernel messages across 46 processes, 0 unmapped |
| The subscription set is accepted by `es_subscribe` as written | accepted, all 96 NOTIFY types, probes included |
| ES throughput and latency under a real build | callback p50 **42 ns**, p95 209 ns, p99 2.4 us, max 68 us |
| `FAIL_OPEN` degrades to a sequence gap rather than a dead client | no deadline kills a NOTIFY client at all - 500 ms/event, 0 gaps (§4.4.3) |
| One descendants client per pip stays inside the OS client budget | **192 clients**, ~19x this machine's core count (§4.4.2) |

#### 4.4.1 Four defects that only the kernel could find

The replay corpus had swept 100,000 randomised scenarios with fault injection and found nothing,
because a corpus written from the documentation models the documentation. Each of these was invisible
to it, and each is now fault-injected so it stays fixed.

| # | Defect | What it would have cost |
|---|---|---|
| 1 | Suppressed self-events counted against the sequence, so the broker's own traffic looked like kernel drops | every pip tainted as lossy |
| 2 | A process was keyed by its pre-`exec` identity; macOS renumbers `pidversion` across `exec` | every compiler invocation unattributable |
| 3 | `bootstrap_look_up` is submitted *by launchd*, so `message->process` is launchd, not the caller | events attributed to a foreign process |
| 4 | Delegation was judged per *operation*, not per *event* | **every real compile uncacheable** |

Defect 4 was the showstopper, and it is worth stating why it survived so long: verification had been
done with `/bin/sh -c 'ls; cat; true'`, which contacts no service. The first real `cc -o t t.c`
produced `taintReason: DelegationEscape, cacheable: false`. Compiling one C file generates nine
delegation events and **all nine** are platform binaries reaching `com.apple.*` - `logd`,
`notification_center`, `opendirectoryd.membership`, `analyticsd`. Tainting on those is tainting on
the operating system existing.

The fix judges each event on its own terms: `bootstrap_look_up` is name resolution and never an
escape; `xpc_connect` escapes only outside `com.apple.*` in `ES_XPC_DOMAIN_TYPE_SYSTEM`;
`uipc_connect` carries a real path so it goes through the manifest like any other access. The
grounding argument is a consistency one - **the Linux sandbox does not intercept `connect()` at
all**, and neither does Detours. Tainting on platform-service contact would have made macOS stricter
than both supported platforms at the price of never caching anything. The policy is still stricter
than Linux.

Each fix was fault-injected by breaking it deliberately and confirming the sweep notices:

| Fix removed | Result |
|---|---|
| sequence suppression accounting | 74 checks, **4 failures** |
| `exec` re-keying | 80 checks, **16 failures** |
| process-origin probe | 80 checks, **3 failures** |
| delegation classification | 86 checks, **16 failures** |
| *none - the shipped code* | 86 checks, **0 failures** |

The lesson generalises past this work: three of the four were fixed by **making the corpus resemble
the kernel** rather than by writing a targeted test. Modelling `exec` renumbering in the generator
turned the entire 100,000-scenario sweep into a test of the real behaviour, which is worth far more
than one assertion that would have passed for the wrong reason.

#### 4.4.2 The client budget, which is where the 2020 implementation broke

The design gives each pip its own broker holding one descendants client, so the number of clients the
OS will grant is a hard ceiling on build concurrency. This was the single largest unquantified risk
in the whole design, and it is the same resource wall that forced the 2020 sandbox to shard six
system-wide clients across event buckets and still switch probe events off on a 2-core CI VM (§16).

| Measurement | Value |
|---|---|
| Ceiling, one process | 192, then `ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS` |
| Ceiling, separate processes | **192** - identical, so it is one global pool |
| Create + subscribe | 155 us mean, 568 us max |
| Delete | 59 us mean, 175 us max |

192 is roughly 19x this machine's core count, and exceeds the core count of every Mac Apple sells.
At 214 us per lifecycle a 294-pip build spends **63 ms** in total on clients, against a 163 s build.
The honest caveat is that the pool is global, so a corporate endpoint-security product draws from the
same 192 - but those take a handful, not a hundred.

#### 4.4.3 A slow handler does not lose events

`ES_DEADLINE_MISS_MODE_FAIL_OPEN` is set because the default kills the client. It turns out the
protection is insurance against something that does not happen on this path: with all-NOTIFY
subscriptions and no AUTH ones, a handler taking **500 ms per event** - three orders of magnitude
past the measured p99 of 2.4 us - left the client alive with zero gaps. Under 12-way parallel load at
2 ms/event, 1,087 events and zero gaps. Paired against a fast handler on identical work, both arms
saw exactly **655 events**, which is the measurement that makes this an argument rather than an
absence of evidence: a kernel dropping under pressure would have delivered fewer to the slow arm.

The residual risk is queue overflow rather than deadlines, and that is already covered - a dropped
message leaves a `global_seq_num` gap, the broker counts gaps, and the sweep fault-injects both
scattered drops and a truncated tail and requires the pip to taint.

#### 4.4.4 What a live run actually looks like

12 compiles and a link, which is a real workload rather than a shell that touches nothing:

| | |
|---|---|
| processes tracked | 46 |
| kernel messages | 14,714 |
| access reports | 13,404 |
| sequence gaps / unmapped / foreign / drops | **0 / 0 / 0 / 0** |
| delegations | 60, all benign; **0 escapes** |
| `taintReason` | `None` |
| `cacheable` | **True** |

Reproduce with `Diagnostics/es-run.sh`, which is the committed form of the ad-hoc harness that found
all of this.

### 4.5 How to actually get the entitlement, and how to check it worked

`Public/Src/Sandbox/MacOs/Sandbox/Diagnostics/es-check.sh` answers "can this machine run it, and if
not, exactly which precondition is missing". It reports the OS, the SDK, SIP, the AMFI boot argument,
keychain identities and installed provisioning profiles, then builds `es-probe.c`, signs it with the
best identity available, and runs a real four-stage check: client created, `FAIL_OPEN` accepted,
subscription accepted, and a file access by a `/bin/sh` child actually observed. The last stage
matters because `/bin/sh` is a platform binary, so it is precisely what dyld interposition cannot
see — a pass there is the thing this whole document is missing.

```bash
Public/Src/Sandbox/MacOs/Sandbox/Diagnostics/es-check.sh              # diagnose, build, sign, run
Public/Src/Sandbox/MacOs/Sandbox/Diagnostics/es-check.sh --diagnose   # report only
```

Exit codes: 0 usable, 1 a precondition is missing, 2 could not build. On the machine this work was
done on it exits 137 — built, ad-hoc signed, `SIGKILL`ed by AMFI — which is the blocker reproduced
in one command.

**Route A, the entitlement (what CI and production need).** Requires an Apple Developer Program
membership; for a company that means an Organization account. Request
`com.apple.developer.endpoint-security.client` through Apple's system extension request form at
`https://developer.apple.com/contact/request/system-extension/`, describing the use — a build system
observing file accesses of its own child processes in order to decide what is safe to cache. Apple
grants this routinely to build and security tooling. On approval, add the entitlement to the App ID,
regenerate and install the provisioning profile, and sign the broker with a Developer ID Application
certificate. `es-check.sh` then reports "properly entitled" and the probe passes.

**Route B, relax AMFI locally (fastest real measurement, not for CI).** On Apple silicon the order
matters, because `boot-args` is itself protected by SIP — setting it before SIP is off silently
fails:

1. Shut down. Press and **hold** the power button until *Loading startup options* appears, then
   **Options → Continue**. With FileVault on, pick an admin user and enter the password to unlock
   the volume.
2. **Utilities → Startup Security Utility**, select the system disk, **Security Policy… → Reduced
   Security**, authenticate.
3. **Utilities → Terminal**, run `csrutil disable`, confirm, authenticate. On Apple silicon this
   moves the policy to Permissive Security.
4. Restart and log in normally.
5. `sudo nvram boot-args=amfi_get_out_of_my_way=0x1` — this is the step that needs SIP already off.
6. Restart again.
7. Verify with `csrutil status` (disabled), `nvram boot-args` (set), then run `es-check.sh`.

An ad-hoc signature carrying the entitlement is accepted from that point on.

To revert: `sudo nvram -d boot-args`, then in Recovery `csrutil enable` and set the Security Policy
back to **Full Security**. FileVault is unaffected throughout. A macOS update may reset the policy on
its own, so re-check after one. This lowers the security of the machine, so it has to be a machine you
are willing to compromise — and it has to be running macOS 27, which rules out the obvious
workaround. A VM is **not** a shortcut here: `VZMacOSRestoreImage.fetchLatestSupported` returns
macOS 26.6.1, the newest publicly fetchable image, and 26.x contains no `es_new_descendants_client`
at all (0 occurrences in the 26.5 SDK header, 3 in the 27.0 one). Building a macOS 27 guest needs a
beta IPSW from an Apple seed account — `com_apple_macOSIPSWSeed` returns 403 without one — so the VM
route needs the same Apple relationship as Route A. Until then the only machine that can run this
code is a macOS 27 host with AMFI relaxed.

Route B closes the §4.4 rows about `Normalize`, subscription acceptance, throughput and `FAIL_OPEN`,
because the kernel behaviour is the same whether the caller is entitled or merely tolerated. It does
not close the CI row.

**What does not substitute: `/usr/bin/eslogger`.** macOS ships an Apple-signed Endpoint Security
client that already carries `com.apple.developer.endpoint-security.client`, and with Full Disk
Access it streams real kernel events as JSON today. It is genuinely useful for one thing — checking
that the event model matches reality, including the `seq_num`/`global_seq_num` accounting that drop
detection depends on, and the fact that platform binaries such as `/bin/sh` are visible where dyld
interposition is blind. But it calls `es_new_client`, so it *is* the 2020 architecture: system-wide
delivery narrowed in userspace, requiring root and TCC. Measuring it would say nothing about
descendant scoping, deadline control, or the client budget, which are the entire reason this design
targets macOS 27. Quoting its numbers as evidence for this design would be the same category error
this section exists to prevent.

The gate ordering makes the difference concrete. Run unentitled and non-root:

| call | unentitled | entitled |
|---|---|---|
| `es_new_client` (system-wide) | `5 ERR_NOT_PRIVILEGED` | **`not privileged`** |
| `es_new_descendants_client` | `3 ERR_NOT_ENTITLED` | **`success`** |

Both columns are measured as an ordinary user, and together they are the clearest answer to what
this design actually takes from macOS 27.

The unentitled column shows the descendants client never reaching the root check. The entitled
column, taken later with the capability in hand, completes it: **the descendants client runs as an
unprivileged user, and the system-wide client still does not.** Apple's "does NOT require root
privilege, does NOT require TCC approval" holds, and it holds only for the scoped client.

That is the dependency, stated concretely. Without `es_new_descendants_client` an ES-based sandbox
must open a *system-wide* client, which means **every build runs as root** — unacceptable for a
developer machine and for CI alike — and means the sandbox observes every process on the machine,
including other users' and unrelated applications'. A build tool has no business holding that. The
descendants client is scoped to the caller's own process subtree, which is exactly what a build
needs and is also why there is nothing left to escalate: the privilege requirement disappears
because the capability did.

Reproduce with `bxl-es-broker --probe-es`, which probes both clients and prints both results.

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
| 1 | **The ES entitlement, for distribution *and* for any end-to-end measurement** | `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED` without it. With SIP+AMFI relaxed locally the ES backend runs and is fully measured (§4.4, §16). But relaxing AMFI stops **every** .NET process from starting, so the sandbox and the engine cannot run on one machine without the real entitlement (§16.7) | External (Apple). Does **not** gate C or E — those are met through the interposition ingress, which needs no entitlement (§4.2, §13) |
| 2 | ~~**`osx-arm64` is not a runtime identifier anywhere in the repo**~~ | See §10 | **Fixed by this work** |
| 3 | **Grpc.Core has no arm64 slice for macOS** | `Grpc.Core` 2.46.6 ships `linux-arm64` but no `osx-arm64`; its `libgrpc_csharp_ext.x64.dylib` is non-fat x86_64 (verified with `lipo`) | Root cause of #2. Mitigation is already in progress: `GrpcDotNetClientOptions`/`GrpcDotNetServerOptions` exist, so this is finishing a migration, not starting one |
| 4 | **Tests disabled on macOS** | `Public/Src/Deployment/Tests.MacOS/Tests.MacOS.dsc:22,33,36,38` — "Depends on Grpc.Core which is not supported on arm64" | Downstream of #3 |
| 5 | **MSBuild frontend Windows assumptions** | `PipConstructor.cs:603-619` hardcodes `mspdbsrv.exe`, `vctip.exe`, `conhost.exe`, `VBCSCompiler.exe` | Breakaway-process list needs macOS equivalents |
| 6 | **`MsBuildGraphBuilder` deploys `net472` + `dotnetcore`** | `Tool.MsBuildGraphBuilder.dsc:75-86` | Only the `dotnetcore` variant is usable on macOS; needs to be selected there |
| 7 | **`Grpc.Tools` has no `macosx_arm64`** | Verified absent at 2.71.0 and 2.83.0; `grpc/grpc` publishes no binary release assets at all | External (grpc). Blocks a *cold* native build: the seven codegen pips cannot run, and a shared cache does not help because the tool hash is part of the fingerprint. Selection code is already in place (§12.4) |
| 8 | **`BuildXL.Tools.AppHostPatcher` has no `tools/osx-arm64`** | `DX9377: Could not find file ... /tools/osx-arm64/AppHostPatcher` | Internal, fix written and committed; needs one run of `.azdo/publish-app-host-patcher` (§12.1) |

| 9 | **Interposition does not observe the toolchain it runs** | Measured against ES on an identical build: `make`, `libtapi.dylib`, `libcodedirectory.dylib` and `libswiftDemangle.dylib` get **0** records under interposition and 20–21 under ES. dyld maps them before any user code runs, so no hook can see them | Internal, and a **correctness** blocker rather than a performance one: the toolchain is absent from the fingerprint, so upgrading it does not invalidate the cache (§16.2) |

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

Half of that comparison was still an assertion when this section was written: it measured what
MSBuild wastes without measuring what replaces it. §13.7 closes it on the same machine — the same
event against BuildXL's own 294-pip build under the sandbox re-executes **0** pips.


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
| ES entitlement | External (Apple) | Not us, and narrower than it looks. Gates C and E are met through the interposition ingress (§4.2, §13). The ES ingress itself is now proven live under relaxed SIP (§4.4); the entitlement buys the right to ship it to machines with SIP on |
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
all depends on scheduling. It has reproduced once in fourteen cold builds and not at all on the settle
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
produces it is still not established, and it is recorded as open in §13.8 rather than claimed as a win.
The honest summary is that the sandbox reported something true and surprising about a build that has
never been observed before, which is precisely what it is for.

### 13.7 The scenario that actually happens: `git checkout`

Every number in §13.2 is an *edit* scenario, which is the case a developer notices. The case that
costs the most in aggregate is the one nobody notices, and §11 already measured it on the MSBuild
side: when file contents are identical but timestamps have moved, MSBuild rebuilds **40 of 40**
projects and produces **40 of 40 byte-identical outputs** — 12.65 s against a 15.72 s cold build,
about 80% of a full build, entirely wasted. That is `git checkout`, `git clean`, a fresh clone, and
every CI agent that starts from an empty workspace.

§11 measured the waste but never measured the alternative on the same machine, which left the
interesting half of the comparison as an assertion. Here it is, on the same 294-pip build of BuildXL
itself, under the sandbox:

```bash
find Public Private Shared -type f \( -name '*.cs' -o -name '*.dsc' -o -name '*.c' \
    -o -name '*.cpp' -o -name '*.h' -o -name '*.resx' \) -exec touch {} +   # 6,284 files
./bxl.sh --use-dev --release /q:ReleaseDotNetCoreMacArm64 <filter> /sandboxKind:macOs
```

| | pips executed | wall clock |
|---|---|---|
| Cold build | 294 / 294 | 163 s |
| No change at all | 0 / 294 | 7 s |
| **6,284 source timestamps churned, contents identical** | **0 / 294** | **10–11 s** |

Zero. Not "few" — the build is 294 cache hits out of 294. And BuildXL did not simply fail to notice
the touch; its own counters show it doing exactly the work the design says it should. Against a
no-op build on the same tree:

| `BuildXL.stats` counter | no-op | after churn |
|---|---|---|
| `LocalDiskContentStore.HashFileContentSizeBytes` | 249,257 | **36,700,570** |
| `FileContentTable.NumHit` | 6,408 | 2,131 |

The content table is keyed on file identity including the timestamp, so churning it costs a *rehash*
— 35 MB of it, 147× a no-op — and the rehash then proves the content is unchanged, so nothing
executes. That is the whole mechanism, and it is the 3–4 s difference between 7 s and 10–11 s.
Against the 163 s cold build that is **16×**; against MSBuild's response to the same event it is the
difference between rebuilding almost everything for nothing and rebuilding nothing.

The sandbox is not a tax on this. Three replicates, arms interleaved and load-gated exactly as in
§13.1: `macOs` 10 s and 11 s, `none` 12 s and 10 s. Indistinguishable, which is what §13.3 predicts —
there is no execution to observe.

Two caveats, because this is the strongest number in the document:

- **The first build after switching arms is not this.** One replicate recorded 73 s and 160/294 hits,
  and that is the §13.5 convergence cost, not the churn. It appears once and then does not recur.
- **6,284 files is a worse case than `git checkout`.** Touching every source file at once provokes an
  indexing storm from Spotlight and Defender that has nothing to do with BuildXL — the same
  measurement, ungated, produced 1588 s, 27 s, 13 s and 1070 s on four consecutive runs that all
  reported 294 cache hits out of 294. Every number above was taken after the machine returned to
  `loadavg < 4`. This is the same contamination §13.1 was rewritten to defend against, and it is
  worth recording that it reappeared the moment a new scenario was added.

### 13.8 Honest limitations

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
  in fourteen cold builds. Four candidate explanations have been tested and eliminated — hard-link
  ambiguity in the observer, canonicalisation anywhere in the chain, the tool genuinely reading the
  path, and cross-pip report attribution — which narrows it but does not close it. Until a run that
  reproduces is captured, the honest statement is that a cold macOS build under the sandbox succeeds
  most of the time and reports this the rest of the time. Every incremental scenario in §13.2 —
  40-plus builds — was clean.
- **The measurement is one machine and one build.** An M2 Pro building BuildXL. The shape of the
  result (cost proportional to work; identical pip counts in both arms) should generalise; the
  constants will not.

## 14. Generalisation: a real MSBuild graph, not BuildXL's own

Everything in §13 measures BuildXL building BuildXL. That is a real build, but it is a DScript build,
and DScript is BuildXL's own language. The obvious objection is that the result says more about the
codebase than about the platform. §14 answers it by running the **MsBuild resolver** on macOS — a
frontend that consumes ordinary `.csproj` files, the format the rest of the world actually uses.

Getting there required fixing five defects. None of them was in the sandbox.

### 14.1 The MsBuild resolver had three independent Windows gates

Each failed with a symptom that pointed somewhere else.

| Gate | Symptom | Actual cause |
|---|---|---|
| `#if PLATFORM_WIN` around the `using`, the ETW registration and the `AddFrontEnd` call in `FrontEndControllerFactory` | `DX11200: Resolver kind 'MsBuild' is not registered` | Reads like a missing assembly. The assembly was in the deployment; it was never registered |
| `GenerateFileAccessManifest` passing `GetFolderPath(Windows\|InternetCache\|History)` to `AbsolutePath.Create` | `ContractException: Invalid path ''`, engine dead in `PopulateGraph` | Off Windows those three return `""`, and `AbsolutePath.Create` **asserts** on the empty string. `WindowsOsDefaults.GetSpecialFolder` guards this with `TryCreate`; this was a hand-rolled copy that did not |
| `MsBuildRuntime` has no default, and `ShouldRunDotNetCoreMSBuild()` required it to be explicitly `"DotNetCore"` | `cannot launch .../MsBuildGraphBuilder/net472/ProjectGraphBuilder.exe: No such file or directory` | The resolver selected the net472 graph construction tool, which is deliberately not deployed off Windows. The dotnetcore one was present all along |

The deployment gate in `BuildXL.FrontEnd.Factory.dsc` had been removed in an earlier round, which is
why the first symptom was so confusing: the binary was there and the resolver still did not exist.

**Method note.** Three gates in series, each one hiding the next, is the normal shape of a
"platform support" change. The first fix produced a *different* error, which felt like progress and
was — but a plan that had budgeted one fix would have been wrong three times over.

### 14.2 Graph construction did not hang, it was hashing the operating system

After the gates, `bxl` sat at 167% CPU for ten minutes with no output after "Done constructing build
graph". `sample` was useless — JIT frames come back as `???`. `dotnet-stack report -p <pid>` gave the
answer immediately:

```
MsBuildWorkspaceResolver.ComputeBuildGraphAsync
  -> TrackFilesAndEnvironment
    -> FrontEndUtilities.TrackToolFileAccesses
      -> FrontEndEngineImplementation.RecordFrontEndFile
        -> InputTracker.RegisterFileAccess
          -> GetAndRecordContentHashAsync(...).GetAwaiter().GetResult()
```

Two independent problems, both fixed:

- **The manifest untracked nothing.** Because the hand-rolled special-folder list had been the only
  untracked scope, `/usr`, `/bin`, `/private`, `/var`, `/etc`, `/dev`, `/lib` and `/System` were all
  tracked. Every access the graph-construction sandbox reported was then opened and hashed. Switching
  to `BuildXL.Pips.Graph.OsDefaults` — the same source `GenerateToolFileAccessManifest` already uses
  for the JavaScript and Ninja resolvers — fixed it by construction.
- **`TrackToolFileAccesses` hashed each path once per distinct access record.**
  `SandboxedProcessReports.FileAccesses` is a `HashSet<ReportedFileAccess>`, deduplicated on the whole
  record — operation, flags, error code — not on the path. Measured with the tracer shipped at
  `Public/Src/Sandbox/MacOs/Interpose/interpose-trace.py`, a hello-world restore produced **7,063
  access records over 839 distinct paths: 8.4x amplification**. `TrackDirectory`, `FileExists` and
  `RecordFrontEndFile` are all idempotent, so collapsing to one entry per path with the union of the
  flags is free.

Result: no output in ten minutes → **7 seconds**.

### 14.3 `/tmp` was untracked as a path but not as a scope

MSBuild pips then failed with `DX0500` on
`/tmp/.dotnet/lockfiles/global/<hash>.{client,server}` and the matching `shm` entries.

`UnixDefaults` listed `/tmp` in `UntrackedFiles` but not in `UntrackedDirectories`. `/etc` is
deliberately in **both** lists, with the comment "could be a folder or a directory symlink, hence
should be untracked as both a path and a scope". `/tmp` had simply been missed. Two independent
reasons it matters:

- On macOS `/tmp` is a symlink to `/private/tmp`. Untracking `/private` only covers accesses reported
  through the *resolved* path, and a sandbox ingress reports the lexical path the process used.
- Regardless of the symlink, the .NET runtime puts its cross-process named-mutex state under
  `/tmp/.dotnet/{lockfiles,shm}/global` **regardless of `TMPDIR`**, because that namespace is global
  by definition. Every `dotnet` child process in a build writes there.

The interesting part is the second-order effect. A pip with a disallowed access is not just failed —
it is **never stored in the cache**. The visible symptom was not "the build fails"; it was "the build
never gets a cache hit", with `MissForDescriptorsDueToStrongFingerprints` and an `Old` strong
fingerprint that never changed across runs. Cache-miss analysis (`/cacheMiss+`) named the paths;
the DFA that explained *why* they never converged was three lines further down the same log.

### 14.4 The failure that only appears once something actually compiles

With the above fixed, a 24-project graph reported **Build Succeeded, 24 pips, 22 s**. That result was
worthless. MSBuild had found every project up to date from a previous `dotnet build` and compiled
nothing. Once the outputs were scrubbed, all 24 pips failed:

```
MSBUILD : error MSB4017: The build stopped unexpectedly because of an unexpected logger failure.
  ---> System.InvalidOperationException: Failed at reporting augmented file accesses for the
       following files: [ ... 160 reference assemblies ... ]
```

This is the **shared compilation** design. `VBCSCompiler`, the Roslyn compiler server, is allowed to
break away from the sandbox; `VBCSCompilerLogger` compensates by reporting the compiler's inputs and
outputs on its behalf. That reporting needs an *augmented manifest* channel — and only Detours has
one. `AugmentedManifestReporter` writes to the handle published in
`BUILDXL_AUGMENTED_MANIFEST_HANDLE`, and **nothing sets that variable off Windows**. The Linux sandbox
implements breakaway but no augmented reporting either, so this is a Unix-wide gap, not a macOS one.

Off Windows, shared compilation now defaults to off. That is also the more conservative choice: the
compiler runs as an ordinary child process and the sandbox observes it directly instead of trusting a
logger's reconstruction of what it did.

**Method note.** "Build Succeeded" is not evidence that a build built anything. The 22 s result had a
plausible wall clock, the expected pip count and a green verdict, and was pure measurement of MSBuild
deciding to do nothing. The check that caught it was mechanical: edit a string literal, then search the
produced DLL for its UTF-16LE bytes. (`strings -e l` does *not* find these; it was tried first and
silently returned nothing, which would have produced a second wrong conclusion.)

### 14.5 The benchmark, and what it says

60 projects in 6 layers, each depending on 3 projects in the layer below, 40 source files each —
**2,460 source files**. Wide rather than linear, because a linear chain gives BuildXL no parallelism
and is not what real repositories look like. Both arms build the same tree from the same sources;
BuildXL runs `/sandboxKind:macOs`. Load-gated at `loadavg < 4`, interleaved, 3 reps, medians.
Same machine as §13: M2 Pro, 10 cores, macOS 27.0, arm64.

| Scenario | BuildXL + macOS sandbox | `dotnet build` | ratio |
|---|---|---|---|
| Cold | 66 s | 19 s | 0.29x |
| No change | 8.8 s (58/58 hit) | 3.0 s | 0.34x |
| **6,000 timestamps churned, contents identical** | **7.2 s (58/58 hit)** | **33.0 s** | **4.6x** |
| Revert to an already-built state | 6.5 s (58/58 hit) | 11.3 s | 1.7x |
| Public API change in a layer-0 project | 56.6 s (13/58 hit) | 24.9 s | 0.44x |
| Method-body change in a layer-0 project | 52.6 s (13/58 hit) | 4.4 s | 0.08x |

Reported as measured, including the rows where BuildXL loses badly. Three things explain them.

**1. Almost the entire cold-build gap is the compiler server, not the sandbox.** The decisive control
is to take the compiler server away from MSBuild too:

| Cold build of the same 60-project graph | wall clock |
|---|---|
| `dotnet build`, compiler server on (default) | **10.2 s** |
| `dotnet build`, `-p:UseSharedCompilation=false` | **60.0 s** |
| BuildXL, macOS sandbox (compiler server unavailable, §14.4) | **66 s** |

66 s against a 60.0 s like-for-like baseline is **1.10x** — the same order as the 1.19x cold-build
overhead measured independently in §13. The 3.4x that the naive comparison shows is 6x of missing
compiler server and 1.1x of sandbox. This single number is the most useful result in §14: it converts
"BuildXL is slow on macOS" into "one specific feature is missing, here is what it costs".

**2. Project-granular caching is strictly coarser than reference-assembly incrementality.** A
method-body change does not alter `L0P0`'s public surface, so MSBuild's ref-assembly check skips all
45 downstream projects and rebuilds exactly one. BuildXL's pips consume the real DLL, whose content
did change, so all 45 re-execute. This is a genuine design trade, not a macOS defect, and it is the
price of the property that makes the cache shareable at all.

**3. The wins are exactly where MSBuild's incrementality collapses.** Timestamp churn is `git
checkout`, `git clean`, a fresh clone, and every CI agent that starts from an empty workspace: MSBuild
rebuilds all 60 projects to produce byte-identical outputs, BuildXL executes nothing. "Revert to an
already-built state" is undoing a change or moving back to `main`.

### 14.6 The gap that stops this being a CI story on macOS today

The obvious next scenario — build in one workspace, then get cache hits in a *different* workspace,
which is what a CI agent or a second developer is — **does not work on macOS or Linux**. Measured, not
assumed: a pristine copy of the same sources pointed at the same `/cacheDirectory` got **0 of 58 hits**.

Fingerprints embed absolute paths. Windows solves this with `/RunInSubst`, which maps the repository
root to a drive letter; its own help text says "Only effective on Windows, in other platforms the
option is ignored". Two workarounds were tried and both failed:

- **`/substSource` + `/substTarget`** only rewrite log messages. The help text says so; the
  fingerprints are untouched.
- **A symlink at a canonical path** fails because the *tools* canonicalise, not BuildXL. Invoking
  `bxl /c:$HOME/bxlwork/config.dsc` did root the pip graph at `$HOME/bxlwork` — and then every pip
  failed `DX0500` writing to `/Users/janpro/wide-bxl/...`, because MSBuild resolved the symlink and
  wrote through the real path while BuildXL had declared outputs under the link. (Invoking it via
  `cd` does not even get that far: `getcwd()` returns the physical path.)

So the honest scope of §14's result is *one machine, across time* — which is the developer
inner-loop case, and is real — but not yet *across machines*, which is the CI and dev-cache case.

**§15 supersedes this section.** The conclusion drawn above — that closing the gap needs source-root
tokenisation in the fingerprint — is wrong, and the third workaround that was never tried is the one
that works. Both are corrected there.

### 14.7 What this adds to §13, and what it does not

Adds:

- The sandbox is not the bottleneck for a non-DScript build either: **1.10x** on a cold 60-project
  MSBuild graph, measured against a like-for-like baseline, consistent with §13's 1.19x.
- The timestamp-churn result reproduces on a completely different frontend and codebase:
  **4.6x** here, 16x in §13. Different constant, same shape, and it is the scenario §11 had measured
  MSBuild losing 40 of 40 projects to.
- Five real defects fixed, all of them platform gates or Windows-only assumptions, none in the
  sandbox.

Does not add:

- Any claim that BuildXL is faster than `dotnet build` for a developer editing one file in a warm
  tree on one machine. On this graph it is not, and §14.5 explains exactly why.
- Any cross-machine result. §14.6 is a blocker, not an omission.

### 14.8 Ranked follow-ups

| # | Item | Why it is ranked here |
|---|---|---|
| 1 | **Augmented manifest ingress for the Unix sandboxes** | Worth 6x on cold MSBuild builds (§14.5). Needs a transport for `AugmentedManifestReporter` off Windows plus breakaway for a `dotnet`-hosted `VBCSCompiler`, which cannot be matched by process name |
| 2 | ~~Source-root tokenisation in fingerprints~~ | **Withdrawn.** §15 shows this is the wrong fix — BuildXL deliberately rejects tokenising non-system mounts, and cross-machine caching works today without it |
| 3 | Reference-assembly awareness for MSBuild pips | Would close the method-body-change row (§14.5). Large change; the trade is deliberate today |
| 4 | The `ResGen.Lite` `DX0500` in §13.6 | Still one occurrence in fourteen cold builds, still unexplained |

## 15. Caching across machines, and fetching the results

§14.6 concluded that cross-workspace caching does not work on Unix and that closing it needs
source-root tokenisation in the fingerprint. The first half was a correct measurement of a wrong
configuration. The second half was simply wrong. Both are corrected here.

### 15.1 BuildXL does not tokenise the source root, and that is deliberate

The tokenisation machinery exists. `MountPathExpander` can rewrite a path to `%MountName%/...`, and
`MountsTable` decides which mounts get that treatment. It restricts the set on purpose:

> We don't tokenize all mounts because that can lead to incorrect fingerprinting. E.g. let's say a
> tool writes a path P in an output file, P is a descendant of a tokenized mount root M and the
> corresponding pip gets cached. If the pip is looked up on a machine where M is a different root M',
> then we can get a cache hit, whereas it should have been a miss because the tool would have
> produced an output file with a written path P'.
> — `Public/Src/Engine/Dll/MountsTable.cs`

Only *system* mounts, and mounts beneath them, are tokenised. `PipFingerprinter` records that the
behaviour was narrowed further still: it "used to check `process.ProducedPathIndependentOutput` …
That was when the `MountPathExpander` tokenized paths based on what mount they were under. It now
only has this behavior for the user profile directory."

So tokenising the source root is not a missing feature. It is a rejected one, and the rejection is
sound: any tool that bakes an absolute path into an output — every PDB, every `.deps.json`, every
generated source file — would make the cache silently wrong.

**Which means `/RunInSubst` on Windows is not tokenisation either.** It maps the repository root to a
drive letter so that the root is *the same literal path on every machine*. Path identity, not path
abstraction. That sidesteps the unsoundness completely: if the path really is identical everywhere,
then a path embedded in an output is correct everywhere too.

The question for macOS is therefore not "how do we tokenise" but "what plays the role of `subst`".

### 15.2 A mount point is the Unix `subst`

§14.6 tried a symlink and it failed, because tools canonicalise. A **mount point does not
canonicalise** — it is a real directory in the VFS, and `realpath` returns it unchanged:

```
$ cd /Volumes/BXLSRC/probe && pwd -P
/Volumes/BXLSRC/probe
>>> os.path.realpath('.')
'/Volumes/BXLSRC/probe'
```

On macOS an APFS volume or a sparse disk image mounts at `/Volumes/<volname>` with no root privileges,
no `/etc/synthetic.conf` edit and no kernel extension. Two machines that name the volume identically
have the source at an identical absolute path. That is the whole mechanism.

The A/B, on the 60-project / 2,460-file graph of §14, against one shared `/cacheDirectory`:

| Workspace | Source root | Cache hits | Wall |
|---|---|---|---|
| Volume 1 — populates the cache | `/Volumes/BXLSRC/work` | 0 / 58 (cold) | 82 s |
| **Volume 2 — a different APFS volume at the same path** | `/Volumes/BXLSRC/work` | **58 / 58** | **16 s** |
| **Volume 3 — a third volume at the same path** | `/Volumes/BXLSRC/work` | **58 / 58** | **16 s** |
| Control — an ordinary directory | `/Users/janpro/xmctl` | 0 / 58 | 85 s |

Same machine, same binary, same sources, same cache. The only variable is the absolute path of the
source root, and it decides everything. The control is the important row: it is §14.6's original
measurement, reproduced, so the two results are consistent rather than contradictory.

The volumes are genuinely distinct storage — different sparse images, different devices, different
inode numbers, and no BuildXL state carried across. What they share is a path.

### 15.3 Fetching the results: an empty local cache and a shared remote

Path portability alone would only prove that fingerprints match. "Fetch the results" needs the
content to arrive from somewhere else. BuildXL's `VerticalAggregator` provides the topology: a local
L1 and a shared L2, configured through `/cacheConfigFilePath`.

```json
{
  "Assembly": "BuildXL.Cache.VerticalAggregator",
  "Type": "BuildXL.Cache.VerticalAggregator.VerticalCacheAggregatorFactory",
  "RemoteIsReadOnly": false,
  "WriteThroughCasData": true,
  "LocalCache":  { "Assembly": "BuildXL.Cache.MemoizationStoreAdapter",
                   "Type": "BuildXL.Cache.MemoizationStoreAdapter.MemoizationStoreCacheFactory",
                   "CacheId": "L1Local", "MaxCacheSizeInMB": 10240,
                   "CacheLogPath": "[BuildXLSelectedLogPath]",
                   "CacheRootPath": "[BuildXLSelectedRootPath]" },
  "RemoteCache": { "Assembly": "BuildXL.Cache.BasicFilesystem",
                   "Type": "BuildXL.Cache.BasicFilesystem.BasicFilesystemCacheFactory",
                   "CacheId": "L2Shared", "StrictMetadataCasCoupling": true,
                   "CacheRootPath": "/Users/janpro/xmL2" }
}
```

Machine A populates: 74 s, 0 hits, and the L2 ends up holding 60 fingerprint entries and 876
content blobs, 102 MB.

Machine B is a brand-new volume at the same mount point, with **no build outputs and no local cache
directory at all** — `~/xmL1b` did not exist when the build started:

```
PRE-BUILD  dlls=0   L1=ABSENT
Processes: [58 done (58 hit), 0 executing, 0 waiting]      24 s
POST-BUILD dlls materialized=1006
```

1,006 assemblies appeared on a volume that had none, from a cache the workspace had never written to.
The local L1's memoization database reports zero hits *and* zero misses, so the descriptors came from
L2. Repeated on the same volume with three separate empty L1 directories: 58/58 every time, 7–14 s.

That is the CI shape — an agent with an empty workspace and an empty local cache, pulling a whole
build out of a shared store.

### 15.4 The defect that made it intermittent, and why it was not the sandbox

The first runs were not clean: across fourteen fresh-workspace builds, three missed completely. An
intermittent 20% cold-miss rate would make the whole idea unusable, so it was worth chasing.

BuildXL named the miss type — `MissForDescriptorsDueToWeakFingerprints`, meaning the *statically*
declared inputs differed. Three measurements narrowed it:

1. **The inputs were byte-identical.** A manifest of all 2,823 non-output files, captured per cycle,
   differed in **0** files between a cycle that hit and a cycle that missed. `dotnet restore` was
   separately verified deterministic at a fixed path (240 restore artifacts, 0 differing).
2. **The shared cache accumulated exactly three fingerprint generations.** Its weak-fingerprint entry
   count went 60 → 120 → 180 for the same 58 pips, then stopped: six further fresh-volume builds
   added nothing and all hit. So the variation had low cardinality and saturated.
3. **The outputs were not deterministic.** Content blobs grew 876 → 1,458, which cannot happen in a
   content-addressed store unless executions produce different bytes. Forcing two full executions
   with different fingerprint salts and diffing every produced file: **49 of 2,806 differed, and all
   49 were `*.csproj.AssemblyReference.cache`** — MSBuild's `ResolveAssemblyReference` state file.

That closes the loop. The RAR state file is written into each project's intermediate directory, its
serialised content is not stable across runs, and it is a pip output; its instability propagates into
the weak fingerprints of dependent pips, forking the cache on every execution.

Under BuildXL the file is also pointless. It exists to give MSBuild its own incrementality, which
BuildXL replaces — each project is an isolated pip with its own cache entry. So `PipConstructor` now
suppresses it alongside the other MSBuild behaviours BuildXL already turns off:

```csharp
// Public/Src/FrontEnd/MsBuild/PipConstructor.cs
"/nodeReuse:false",
"/p:DisableRarCache=true"
```

Measured after the change, with no workaround in the demo tree:

| | before | after |
|---|---|---|
| Output files differing between two identical full executions | 49 of 2,806 | **0 of 2,757** |
| Weak-fingerprint generations in the shared cache for 58 pips | 3 | **1** |
| Fresh volume, empty L1, shared L2 | intermittent | 58/58, 6–10 s |

The obvious objection is that the RAR state file exists for a reason and removing it should cost
something. Measured, paired and interleaved, forcing all 58 pips to execute in both arms by swapping
the resolver assembly between runs:

| rep | suppressed (new default) | enabled (old behaviour) |
|---|---|---|
| 1 | 77 s | 91 s |
| 2 | 74 s | 70 s |
| 3 | 64 s | 65 s |
| **median** | **74 s** | **70 s** |

The spread *within* each arm (64–77 s and 65–91 s) is larger than the difference *between* them, so at
this sample size there is no resolvable cost. That is the expected result rather than a lucky one:
BuildXL runs each project as a one-shot isolated pip, so a state file written to accelerate the *next*
invocation in the same workspace has almost nothing to accelerate.

**None of this is macOS-specific.** The RAR state file behaves the same way on Windows and Linux; it
was invisible there only because nobody had pointed two workspaces at one cache and counted. It is
the kind of defect that a cross-machine cache exposes and a single-machine cache hides.

### 15.5 What this does not prove

- **The L2 is a shared directory, not a network service.** The topology, the miss/fetch path and the
  materialisation are real, but the transport is a filesystem. `AzureBlobStorageCacheFactory`,
  `BlobCacheFactory` and `EphemeralCacheFactory` all ship in the `osx-arm64` deployment and were not
  exercised — see below for why.
- **One machine.** The volume swap makes the storage, the inodes, the file identities and the local
  cache genuinely fresh, but the OS install, the user profile and the SDK are shared. Encouragingly
  `ExtraFingerprintSalts` contains no machine name, user name or host identifier — the only
  host-dependent salt is the Linux distribution id, and macOS contributes nothing — and the user
  profile is one of the two things still tokenised, so `~/.nuget` differing per user is handled by
  design. Neither was tested with a second account.
- **A second developer's SDK is assumed identical.** Nothing here establishes what happens when the
  .NET SDK patch version differs; the SDK's own files are declared inputs, so it should miss
  correctly rather than be wrong, but that is reasoning, not a measurement.

**Why the blob path could not be tested here, and a finding that matters more than the test.** The
repo vendors an Azurite emulator as `BuildXL.Azurite.Executables`, and it ships `win-x64`,
`linux-x64` and `osx-x64` binaries only — `AzuriteStorageProcess` hard-codes `tools/osx-x64/blob`. On
Apple Silicon that has always meant Rosetta. **This machine, on macOS 27.0 (26A5388g), has no Rosetta
2 at all**: `/Library/Apple/usr/libexec/oah` contains only `RosettaLinux`, and a freshly compiled,
trivial `x86_64` binary fails with `Bad CPU type in executable`. Building an arm64 Azurite instead was
not possible either — `registry.npmjs.org` is unreachable from this network, which is also why the
four npm graph-builder pips in §12 fail.

That is worth more than the test it blocked. §10 justified making `osx-arm64` a first-class runtime
identifier partly by observing that the old macOS pipeline downloaded `osx-x64` binaries and passed
only because the agent image shipped Rosetta — it was testing emulation. On macOS 27 that pipeline
would not run at all. The `osx-arm64` work is not an optimisation; it is the difference between
working and not working, and the same is now true of the Azurite test fixture.

### 15.6 Where this leaves the cross-machine question

The blocker identified in §14.6 was real, but it was a configuration problem with a wrong diagnosis,
not an architectural gap. Cross-workspace caching on macOS needs no new BuildXL feature: it needs the
source root at a stable absolute path, which a mount point provides, plus one defect fixed in the
MSBuild resolver.

What has to be true for a team to actually get this, in order of remaining risk:

| | Requirement | Status |
|---|---|---|
| 1 | Source root at an identical absolute path on every machine | **Solved on macOS** by a named volume mount. Needs a convention, not code. Linux has `mount --bind`; the same reasoning applies |
| 2 | Deterministic pip outputs | **One defect found and fixed.** There is no guarantee others do not exist; the method that found this one — forced double execution and a full output diff — is cheap and should be run per frontend |
| 3 | A shared cache the build can reach | Topology proven with a shared L2. A real network backend is untested on macOS |
| 4 | Content actually fetched, not just fingerprints matched | **Proven**: 1,006 assemblies materialised into an empty workspace from an empty local cache |

Items 1, 2 and 4 are the ones that were in doubt, and they are the ones now measured. Item 3 is the
one a funded increment would have to close, and nothing found here suggests it is hard — it is
managed code that already ships in the `osx-arm64` deployment.

## 16. Endpoint Security measured against interposition, on the same build

§4.4 established that the ES ingress runs against the real kernel and is clean. It did not answer
the question that decides whether ES is worth an entitlement at all: **what does it buy over the
interposition sandbox that already works and needs no entitlement?**

Both ingresses were run over an identical workload — 61 C files compiled and linked with clang at
`-j8` — interleaved, load-gated below 4, five repetitions. Reproduce with
`Diagnostics/es-compare.sh`, which runs all three arms, and `Diagnostics/es-diff-coverage.py`, which
diffs what each ingress reported:

```
TOOLS=/Library/Developer/CommandLineTools/usr/bin
Diagnostics/es-compare.sh --workdir <dir> --build "$TOOLS/make -j8" --clean "$TOOLS/make clean"
Diagnostics/es-diff-coverage.py report-interpose.txt report-es.txt --label-a interpose --label-b es
``` The two ingresses share everything above
the ingress boundary, so a difference between them is a difference in what the kernel tells them.

### 16.1 Cost

| arm | median | min | max | vs unobserved | events | reports | processes |
|---|---|---|---|---|---|---|---|
| unobserved | 0.61 s | 0.60 | 0.62 | 1.00× | — | — | — |
| interposition | 0.79 s | 0.79 | 0.80 | 1.30× | 13,660 | 13,721 | 128 |
| Endpoint Security | 0.95 s | 0.94 | 0.98 | 1.56× | 64,011 | 56,978 | 134 |

Five repetitions produced a spread of 0.02 s, so the ordering is not in doubt. Both arms reported
`taintReason: None` and zero sequence gaps in every run.

**This is a deliberately hostile workload for ES.** 61 compilations in 0.61 s is about 105,000
kernel events per second of real work; a build whose pips do more work each is far less event-dense.
Read 1.56× as an upper bound at maximum density, not as what a normal build pays — §13 measured the
interposition sandbox at 1.19× on a cold 294-pip build and 0–4% incrementally, and ES's *marginal*
cost per event is lower, not higher:

| | added wall | events | per event |
|---|---|---|---|
| interposition | +0.18 s | 13,660 | 13.2 µs |
| Endpoint Security | +0.34 s | 64,011 | **5.3 µs** |

ES costs more in total because it sees 4.7× more, not because each observation is dearer. Which
raises the only question that matters about the extra 50,351 events: are they noise?

### 16.2 Coverage — and a class of false cache hit

Comparing the reported paths of the two arms, after normalising clang's per-invocation random temp
names and the two spellings macOS gives the same file (`/tmp` vs `/private/tmp`, `MacOSX.sdk` vs
`MacOSX27.0.sdk`):

| | |
|---|---|
| paths seen only by Endpoint Security | **180** |
| paths seen only by interposition | **0** |

ES observes a strict superset. Three paths initially appeared to be interposition-only, which would
have been a serious hole; all three were false, and chasing them found a real defect — see §16.3.

The interesting part is *which* paths ES sees alone. Excluding `exec` argument vectors:

| ES-only path | records under interposition | records under ES |
|---|---|---|
| `/Library/Developer/CommandLineTools/usr/bin/make` | **0** | 21 |
| `/Library/Developer/CommandLineTools/usr/lib/libtapi.dylib` | **0** | 20 |
| `/Library/Developer/CommandLineTools/usr/lib/libcodedirectory.dylib` | **0** | 20 |
| `/Library/Developer/CommandLineTools/usr/lib/libswiftDemangle.dylib` | **0** | 20 |

These are not noise. They are **the build tool itself and three shared libraries the toolchain
loads** — with `open`, `mmap`, `stat` and `close`. They are build inputs by any definition: if
`libtapi.dylib` is upgraded, link output can change.

Interposition reports zero accesses to all four, and this is structural rather than an oversight.
`DYLD_INSERT_LIBRARIES` hooks 62 libc symbols in the traced process, but dyld maps the main
executable and its dependent libraries *before* any user code in that process runs, so those
accesses happen where there is nothing yet to observe them. Neither `dlopen` nor `mmap` appears in
`bxl-interpose.c` at all; hooking `dlopen` would recover later loads, but nothing hookable can
recover the ones that happen before the interposer exists.

**The consequence is a false cache hit.** Under interposition the toolchain is not in the
fingerprint, so upgrading the linker's support libraries does not invalidate anything and the build
returns stale outputs. Under ES it does. This — not throughput, and not the enforcement boundary —
is the concrete argument for the entitlement.

The caveat is that it is a *class* demonstrated on one workload, not a full audit. 180 paths were
compared on one build; a different toolchain may leak differently.

### 16.3 A defect found by disbelieving the comparison

Three paths appeared to be seen only by interposition. Rather than report a hole in ES, each was
checked, and all three turned out to be the same file under a different spelling:

```
interpose  62x open    /Library/Developer/CommandLineTools/usr/local/lib/clang/workarounds.jsonl
es         62x lookup  /Library/Developer/CommandLineTools/usr/bin/../local/lib/clang/workarounds.jsonl
```

ES reports the path the caller supplied, not a resolved one, and the ingress concatenated it
verbatim — so `..` survived into the report. That is not cosmetic. `AccessChecker` resolves policy
by walking the manifest's path tree, so a path carrying `..` matches no node: an access inside a
declared cone is judged as if it were outside one, which is a spurious violation or a silently
unreported access depending on which policy it should have hit. It also splits one file across two
fingerprint entries, so the two backends cannot agree on a cache key for the same build.

Fixed by cleaning lexically — `.`, `..`, duplicate separators and a trailing separator — once at the
end of `Normalize`, rather than at each of the 44 sites that assign a path, so a newly modelled
event cannot forget it. Lexical rather than `realpath` on purpose: `realpath` would be a syscall on
each of 64,011 events *and* would resolve symlinks, moving the disagreement with the interposer
instead of removing it, since the interposer is deliberately lexical. Lexical `..` removal is
unsound when a component is a symlink; that is the trade-off every other BuildXL sandbox already
makes.

Seventeen cases are in the self test, including both spellings measured live, `..` at and past the
root, and names that only look like dot segments (`/...`, `/a/..b/c`, `/a/b../c`). The self test is
now 103 checks. Verified live afterwards: ES emits the cleaned spelling, counts unchanged, and
interposition-only paths went **3 → 0**.

### 16.4 What was left of the two backends' disagreement

Two spelling differences remain, and they are properties of the kernel rather than defects:

| | interposition | Endpoint Security |
|---|---|---|
| `/tmp` (a firmlink) | `/tmp/...` — reports what the caller passed | `/private/tmp/...` — reports the resolved vnode |
| `MacOSX.sdk` (a symlink) | `MacOSX.sdk/...` | `MacOSX27.0.sdk/...` |

**The two backends are therefore not interchangeable for caching**: a fingerprint produced under one
will not match the other. Within a single backend this is consistent and harmless, and `es-run.sh`
already names both `/tmp` and `/private/tmp` as manifest scopes for exactly this reason. Making them
interchangeable is unfinished work, and the honest position is that it is unproven either way which
spelling BuildXL should prefer.

### 16.5 Two operational findings from the same run

**The Xcode shim defeats the shadow-tool mechanism.** The first attempt to run `make` under
interposition failed with

```
xcode-select: Failed to locate 'make-4ae58c797353c675-118640-1784265256.000000000'
```

`/usr/bin/make` and `/usr/bin/clang` are *the same 118,640-byte file* with 78 hard links: they are
`libxcselect` shims that dispatch on their own filename. Interposition must shadow-copy platform
binaries under a mangled name to stop dyld stripping `DYLD_INSERT_LIBRARIES`, and the mangled name
is exactly what the shim then fails to resolve. ES has no equivalent problem — it needs no copy.
The benchmark above therefore invokes the real toolchain under
`/Library/Developer/CommandLineTools/usr/bin`, so that it measures the sandboxes rather than the
shim. Anything driving `/usr/bin/cc` under interposition on a developer Mac will hit this.

**Backends must announce themselves.** The backend name previously reached the log only through
`WriteTaint`, which fires when a pip taints — so a clean build never recorded which sandbox produced
it, while `auto` silently falls back from ES to interposition. That is precisely how a number gets
attributed to the wrong sandbox. The broker now announces its backend at startup unconditionally.

### 16.6 Where ES's fixed per-pip cost went

An ES-observed pip running a trivial tool cost **520 ms**; the same pip under interposition cost
6 ms. Phase timers put all of it in the two fences — baseline established at 251 ms, stream closed at
513 ms, everything else about 1 ms — and none of it in the tool.

ES client warm-up was the obvious suspect and is not the cause: `Diagnostics/es-warmup.c` measures
`es_new_client` plus subscribe at 218 µs, with the first event arriving 917 µs later. The difference
between that probe and the broker is that the probe emitted markers in a loop and the broker emitted
one:

| emission pattern | first-event latency |
|---|---|
| one `stat` on a missing path | 251,000 µs |
| one `open` + `create` | 251,000 µs |
| re-emit until observed | **535 µs**, after a median of 15 emissions |

**Endpoint Security does not flush a nearly-idle NOTIFY queue; it sits on a ~250 ms timer.** A fence
that emits once and waits pays that timer in full, twice per pip, on the critical path. On §13's
294-pip build that is roughly 15 s of a 163 s build spent waiting for a queue holding one entry.

Fixed by chasing the marker instead of waiting for it: wait in short slices and re-emit on each
timeout, against the same overall deadline. Sound because the marker is a `stat` on a path that does
not exist — extra emissions have no side effect — and `TryConsumeMarker` already discards
marker-shaped events arriving outside a window. The replay backend needed care, since its emitter
pumps the whole corpus synchronously and a second emission would invent events; waiting first and
re-emitting only on timeout is safe there by construction, because replay observes its own marker
inside the emitter and the first slice always succeeds.

Measured after, on the same tool: **520 ms → 34 ms**, fence latency 11.6 ms, `taintReason: None`.
Self test unaffected.

Re-emission is new hot-path behaviour, so it was checked for storming under contention: ten brokers
started at once, on a ten-core machine, produced fence latencies of 11.1–11.9 ms and
`markerAttempts` of **23 in every one of the ten** — identical to a single broker running alone. The
loop converges rather than amplifying, and the extra markers it emits are ~23 events against the
64,011 a small build already produces.

### 16.7 Disabling AMFI to test ES breaks .NET, and a one-flag patch unblocks it

Relaxing SIP and AMFI is what makes an ad-hoc signature carry the ES entitlement, and §4.5 presents
it as the way to answer these questions without Apple. It has a consequence that section did not
anticipate: **with AMFI disabled, no .NET process starts on the machine at all.** Every .NET binary,
`dotnet --version` included, fails with `Failed to create CoreCLR, HRESULT: 0x8007000C`.

The mechanism is a segment flag. `libcoreclr.dylib` carries `SG_READ_ONLY` on its `__DATA_CONST`
segment; dyld honours that by mapping the segment read-only, and CoreCLR writes to it while
initialising. With AMFI active the write is permitted, and with AMFI disabled it faults. `0x8007000C`
is `E_OUTOFMEMORY`, which sends you looking for a resource limit that is not the problem.

Clearing that one flag and re-signing ad-hoc makes the runtime start. The
[`relax-dataconst.py`](../../Public/Src/Sandbox/MacOs/Sandbox/Diagnostics/relax-dataconst.py)
diagnostic sweeps a set of roots and does this to every CoreCLR it finds.

Ruled out first, each by direct probe: Server GC, `TMPDIR`, `ulimit -n`, OS build drift, `MAP_JIT`,
the full `pthread_jit_write_protect_np` write/execute cycle, and Mach exception ports. Also ruled
out afterwards, by holding everything else fixed: the signing authority and the hardened-runtime
flag are both irrelevant — an ad-hoc signature re-applied with `--options runtime` still fails while
`SG_READ_ONLY` is set, and Microsoft's own Developer ID signature fails too. Only the flag matters,
and that holds across .NET 9.0.18 and 11.0-preview.6, for shared frameworks and self-contained
deployments alike.

> An earlier revision of this section concluded the opposite — that the patch was unnecessary,
> because an unpatched-looking runtime appeared to start. That test was confounded: a self-contained
> deployment loads the `libcoreclr.dylib` sitting beside it and ignores `--fx-version`, so the
> experiment had been exercising a still-patched copy. The lesson generalises to anything measured
> here: on macOS, verify *which* runtime image was loaded, not which one was named.

**The earlier conclusion that you can have the ES sandbox or BuildXL but not both was wrong.** With
the flag cleared, both run on the same machine, and every end-to-end result in this document — a
real BuildXL build on the ES backend, including the C++ build in §17 — was produced that way.

What remains true is narrower and still worth stating: this is a *workaround for a workaround*. It
compensates for a local security configuration that only exists because the machine has no ES
entitlement. On a machine with the entitlement, AMFI stays enabled and none of this applies. The
entitlement is still required for distribution, and still the one thing here that cannot be
substituted for locally — but it no longer gates measurement.

---

## 17. End to end: real BuildXL builds on the Endpoint Security backend

Everything before this section measures the broker, or measures the sandbox against a corpus. This
section is the thing those were standing in for: BuildXL building real targets, with the ES backend
attached to every pip. It became possible once §16.7's `SG_READ_ONLY` finding let the engine and the
sandbox run on the same machine.

The results below were produced in one sitting. They are reported in the order they happened,
including the two occasions where the first answer was wrong, because the corrections are the part
worth trusting.

### 17.1 What running real builds found that synthetic tests could not

Three defects. Each was invisible to the self test, and each is invisible to the interposition
backend, because all three come from Endpoint Security reporting *less* than an interposed library
call does.

**Every file a process read was reported as a file it wrote.** `NOTIFY_CLOSE` arrives for every
descriptor a process closes, and the translator treated the close itself as the write signal. A
compiler that opened a header therefore claimed to have produced it. `es_event_close_t` carries a
`modified` flag; only a modifying close is a write. **151 `DX0500` to 0.**

**Apple's own preferences agent was classified as a sandbox escape.** An XPC connect was an escape
unless the name began with `com.apple.` *and* the domain was `ES_XPC_DOMAIN_TYPE_SYSTEM`. The
reasoning was sound — any process can register a name in the user and session domains — but
`es_xpc_connect_t` carries no identity for the responder, so a name test was all that event could
do. The kernel does supply that identity, on the `BOOTSTRAP_LOOK_UP` for the same name, as
`is_platform_binary`; the broker already received it and already used it, just not for XPC. Measured
on a `dotnet` run: every XPC connect was preceded by a bootstrap lookup for the same name, and
`com.apple.cfprefsd.agent` — which every process reading a preference contacts, and .NET does at
startup — is kernel-attested while living in the *user* domain. **148 pips failing to 0.**

The attestation is applied at finalize rather than on arrival, because the bootstrap lookup is
submitted by launchd: ES describes launchd as the actor and does not order the two events against
each other, so judging the connect on arrival would make the verdict depend on delivery order. The
self test pins both orders.

**Directory probes were reported as reads of regular files.** `NOTIFY_LOOKUP` is the one event that
names a path without saying what is there — `es_event_lookup_t` carries a stat for the *parent* and
nothing for the target. The defaults said "exists, not a directory", so every directory a tool
resolved became a file read. That is not cosmetic: BuildXL allows directory probes unconditionally,
because it has no way to declare a probe-dependency on a directory and "tools tend to emit many such
innocuous probes" (`PolicyResult_common.cpp`). It surfaced as disallowed accesses on `/`, `/Users`
and the repository root, because `realpath()` resolves one component at a time. **DFA lists
collapsed from full ancestor chains to a single real file.**

Two decisions inside that fix are load-bearing:

* **`LOOKUP` is kept, not dropped** — which was the tempting fix, since it is redundant for paths
  that exist. Measured: a `stat` of an *absent* path emits `NOTIFY_LOOKUP` and **nothing else**, no
  `STAT`, no `ACCESS`. Dropping it would silently discard exactly the absent-path probes that cache
  correctness depends on — the 2019 failure, reintroduced deliberately.
* **Resolution is injected, not called directly.** The first implementation called `lstat` in the
  engine, which made a replayed corpus depend on the filesystem of the machine replaying it. It
  showed up as an unrelated-looking fence failure that was nearly dismissed as flaky. It is now
  `EngineOptions::lookupPathType`, matching the existing `processOrigin` seam, with
  `NormalizedEvent::sourceTypeKnown` so only the ES ingress — which genuinely cannot know — pays.

### 17.2 The C++ build

C++ is the workload that ended the 2019 attempt, so it is the one that matters. BuildXL's own macOS
sandbox sources build through BuildXL with real `clang++` pips and real header search, which gives a
C++ target with no new dependencies.

The first run failed one pip with **`LocalQueueOverflow`** — the broker's queue, not the kernel's,
but the same volume pressure one layer up. The cause was the directory-probe fix itself: resolving a
lookup costs a syscall on the drain thread, which is also what the ingress backs up against.

The fix came from noticing that ES already provides the answer for free. A lookup *names the
directory it resolved in*, and that parent is a directory by construction, so it never needs asking
about. Recording it turns an ancestor walk into one filesystem call per directory per pip rather
than one per component per walk — and a compiler re-resolving the same `-I` directories for every
header in every translation unit pays nothing after the first. Overflow gone.

| | Result |
|---|---|
| C++ build under ES | **Build Succeeded**, including the sandbox's own self test running as a sandboxed pip |
| No-op rebuild | **5 of 6 processes cache hit**, **zero sandbox taints**; the sixth is declared uncacheable by the spec |
| Self test | 111 → **118 checks, 0 failures** |

### 17.3 The cache-correctness proof

Succeeding and caching are not enough — a sandbox that silently misses probes also succeeds and
caches, right up until it serves a stale result. The 2019 blocker was specifically that absent-path
probes are cache inputs and were being lost.

The include search order puts `Sandbox/` before `Linux/`, so a header resolved in `Linux/` was
probed-and-absent in `Sandbox/` first. Placing a decoy header at that absent path:

* **The cache correctly invalidated.** Pips re-executed and the decoy was picked up (its `#error`
  fired). A sandbox that had not observed the absent probe would have reported a cache hit and built
  stale output.
* **Removing it restored the full cache hit**, 5 of 6, so the invalidation was precise rather than a
  blanket miss.

This is the direct test of the requirement the 2019 attempt could not meet, and it passes.

### 17.4 A product gap this surfaced

`PipGraph.UnixDefaults` untracked `/System/Library` but nothing else under `/System`. **Cryptexes
postdate that list** — Apple now ships parts of the OS, including the dyld shared cache, in cryptexes
so they can be replaced without a full OS update, and every process reads from them before it runs a
single instruction of the tool. Every pip on a current macOS reported undeclared reads of
`/System/Cryptexes/OS`, `/System/Cryptexes/Rosetta`, and the shared cache under Preboot.

Both `/System/Cryptexes` and `/System/Volumes/Preboot/Cryptexes` are now untracked, for the same
reason `/usr/lib` is: which OS libraries a process loads is not deterministic across runs, so sealing
them would make identical builds look different. `/System` is deliberately *not* untracked wholesale
— `/System/Volumes/Data` is a firmlink to the data volume, and that would untrack every user file
reached through it.

This is a real gap in BuildXL's macOS support, independent of which sandbox backend is used.

### 17.5 What this does and does not establish

Established:

* The ES backend runs real BuildXL builds, including C++, and caches them correctly.
* Absent-path probes — the 2019 blocker — are observed, and demonstrably drive invalidation.
* Loss is detectable. `global_seq_num` (message version ≥ 4) did not exist on macOS 10.15, so the
  2019 prototype could not tell it was dropping events. The broker now requires it and refuses to
  trust an older stream, which turns a correctness failure into a performance failure: a lossy run
  is uncacheable, never wrong.

Not established:

* Everything was measured on one machine, with SIP and AMFI relaxed. Nothing observed suggests those
  settings affect ES event delivery, but nothing rules it out either.
* The BuildXL C++ target here is a handful of translation units. §17.6 measures event volume far
  past it, but on synthetic parallelism rather than a real large codebase's dependency graph.

### 17.6 Kernel drop rate, measured

This is the question the 2019 attempt failed on and that this document could not answer until now:
under a real C++ workload, does Endpoint Security drop events?

It does — with the settings this design started with. Measured on parallel `clang++` compiles, since
C++ header search is what produces path-resolution events in bulk:

| queue capacity | concurrent compiles | events observed | kernel drops |
|---|---|---|---|
| 16384 | 8 | 51,796 | 16 |
| 16384 | 16 | 69,708 | 93,523 |
| 16384 | 32 | 98,788 | 248,264 |
| 262144 | 16 | **103,407** | **0** |
| 262144 | 32 | **206,725** | **0** |
| 262144 | 64 | **412,758** | **0** |
| 262144 | 128 | 636,738 | 429,827 |

**Read the event column, not just the drop column.** At 16 concurrent compiles the deeper queue
observes 103,407 events where the shallow one observed 69,708. The shallow queue was not coping and
reporting less — it was losing a third of the stream and would have reported a *cleaner* build than
actually happened. That is the 2019 failure mode precisely, and the only reason it is visible at all
is `global_seq_num`, which macOS 10.15 did not have.

Two different failures, needing two different fixes. 2000 µs of backpressure was too small to absorb
a scheduling hiccup — at 8 compiles the delivery thread gave up 16 times — and raising it to
20000 µs eliminated those completely. But at 16 compiles the same change made things *worse*, because
no amount of waiting rescues a queue that is genuinely too small. Only the deeper queue fixed the
higher concurrencies.

The cost is near zero, because the queue grows on demand rather than being preallocated: a single
`clang++` compile still peaks at **34 queue slots and 7 MB resident**. And 64 concurrent processes
inside *one pip's* tree is already an order of magnitude past what a scheduler produces on this
machine's 6 performance cores — BuildXL parallelises across pips, each with its own broker, not
within one.

Where it still breaks — 128-way — it breaks *safely*: `KernelSequenceGap+LocalQueueOverflow`, the pip
is tainted and uncacheable. Slower, never wrong. That distinction is the whole reason this design is
viable where the 2019 one was not.

These numbers were produced with `Diagnostics/bxl-es-fam.cpp`, which writes a manifest so the broker
can be run directly on any command. Without it, the broker's own statistics are reachable only
through a full BuildXL build — which is why they had gone unmeasured for so long.

### 17.7 The test suite, and the one failure that is left

BuildXL's own test suite — `bxl /f:tag='test'`, 909 test pips — was run under the ES backend:

| | |
|---|---|
| Succeeded | **238** |
| **Disallowed file accesses (DX0500)** | **0**, across all 909 pips |
| Failed — environment | 6 (4 `npm install`, unreachable `registry.npmjs.org`; 2 NuGet packages with no published `osx-arm64` build) |
| Failed — sandbox | 4, all `LocalQueueOverflow` |
| Skipped | 661, blocked behind the above |

Zero DFAs is the number that matters most here: across 909 pips of every shape the repository
contains, the sandbox's file-access reporting produced no false violations at all.

**The 4 sandbox failures are transient, and the fix is retry.** They are different pips on every
run, which rules out a workload that is inherently too heavy. Three hypotheses were tested and two
were wrong:

* *Queue too small* — no. A 262144-entry queue peaks at **38** on the same NuGet extraction workload
  run alone, and 50 concurrent brokers compiling in parallel produced 1,151,743 events with zero
  drops. The queue is nearly empty when this fires.
* *Backpressure cap too short* — partly. Raising it from 20 ms to 1 s took overflows from 5 to 1 on a
  smaller build. The cap had been justified by the Endpoint Security deadline, but the SDK says that
  deadline governs **auth** events, and this client subscribes to 96 NOTIFY and zero AUTH — so it was
  guarding a hazard that cannot occur here.
* *Drain thread starved of CPU* — no. Raising its QoS to `USER_INITIATED` changed nothing (4 before,
  4 after). The remaining pressure is downstream of the queue, where the drain thread writes into the
  report FIFO that BuildXL reads.

Which is exactly why **Linux already has a retry for this**: `SandboxedProcessPipExecutor` turns a
`MessageProcessingFailure` exit code into a retriable `SandboxInternalErrorFailure`. That branch
tested `IsLinuxOS`, so on macOS the identical failure — produced by the identical code path — was
permanent, and the log said the pip "may be retried" while it never was. That gate is now fixed.

### 17.8 The osx-arm64 build blocker, and what it was hiding

"BuildXL cannot be built on osx-arm64" turns out to reduce to a single missing file.
`BuildXL.Tools.AppHostPatcher` publishes `tools/win-x64`, `tools/linux-x64` and `tools/osx-x64` —
and no `tools/osx-arm64`. The patcher runs on the *host*, so on Apple silicon the osx-x64 build is
unusable without Rosetta, and `AppHostPatcher.dsc` resolves `tools/osx-arm64/AppHostPatcher`
directly. Every managed pip depends on it, so the managed build stops before it starts.

Nothing had to be invented: the tool's source is already in the repository, at
`Public/Sdk/Public/Managed/Tools/AppHostPatcher`.
[`Diagnostics/apphostpatcher-local-feed.sh`](../../Public/Src/Sandbox/MacOs/Sandbox/Diagnostics/apphostpatcher-local-feed.sh)
rebuilds it, packs it under the id and version `config.dsc` already asks for, and writes a package a
local NuGet v3 feed can serve. **The AppHostPatcher pips, which previously could not run at all, now
execute and succeed during a real build.**

Two details cost real time and are worth recording. The package must also carry empty placeholders
for the other three platforms, because BuildXL's generated package spec enumerates every file the
published package contains and fails the download pip if any is missing. And the payload has to be
passed through `relax-dataconst.py` *before* packing — it is a self-contained .NET app and inherits
the same `__DATA_CONST` problem as every other CoreCLR here, and BuildXL re-extracts the package, so
a patch applied afterwards is discarded.

With that unblocked, the managed build runs far enough to expose the real capacity limit, which had
been hidden behind it. On a near-cold cache — where almost every pip executes at once, the worst
case this machine can produce — tainted pips went **19 → 10** after the report-sink fix in §17.7.
Those builds have 0–5% cache hits precisely because each change invalidates fingerprints; a normal
incremental build runs at 40–90% hits with far less concurrency, which is why the C++ build and
warm rebuilds pass cleanly.

### 17.9 The retry, observed end to end

The retry fix was the last claim in this document resting on inspection rather than execution. It no
longer is.

Deploying it needed a build of `BuildXL.ProcessPipExecutor.dll`, which the managed build could not
produce here. Compiling that one assembly directly against the deployed assemblies works, with two
details that must match or the runtime refuses to load it: BuildXL's strong-name key
(`Public/Sdk/SelfHost/BuildXL/BuildXL.DevKey.snk`), and assembly version `1.0.0.0` — a default
`0.0.0.0` produces a `FileNotFoundException` naming the assembly that is plainly present on disk.

With it deployed, on the same `--minimal` build that previously failed pips outright:

| | Before | After |
|---|---|---|
| Sandbox internal errors raised (`DX10110`) | 8 | 6 |
| Pips **failed** with `MessageProcessingFailure` | 8 | **0** |
| Pips that recovered | 0 | **6 of 6** |

And on the full test suite, 909 pips:

| | |
|---|---|
| Sandbox internal errors raised | 5 |
| Pips failed with `MessageProcessingFailure` | **0** |
| **Disallowed file accesses** | **0** |
| Remaining failures | 4 `protoc`, 4 `node` — neither a sandbox failure |

Every pip that hit a transient sandbox condition retried and succeeded. Before the fix each one was
a permanent failure that also skipped everything downstream.

### 17.10 What still fails, and why none of it is the sandbox

Two failures remain on this machine, and both are toolchain or network, not BuildXL:

**`protoc` — grpc ships no arm64 macOS tooling.** `Grpc.Tools` carries `linux_arm64` but no
`macosx_arm64`, so on Apple silicon `protoc` and `grpc_csharp_plugin` fall back to the x86_64 build
and need Rosetta 2, which is not installed here. This is a genuine macOS-vs-Linux parity gap that
has nothing to do with the sandbox: Linux arm64 gets native tooling, macOS arm64 does not.
`protoc` itself can be replaced with the universal binary from protobuf's own releases, which runs
natively — but `grpc_csharp_plugin` has no equivalent, and grpc publishes no standalone build of it.
The broker now reports this in terms that name the cause and the fix rather than "Bad CPU type in
executable".

**`node` — `registry.npmjs.org` is unreachable from this machine.** Environmental.

So the honest summary: **there are no known sandbox failures left**. Under load the sandbox still
raises transient internal errors, and those are now absorbed by the retry path that Linux has always
had — visibly, on real builds, with the pips going on to succeed.
