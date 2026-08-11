# BuildXL Cross Platform

* BuildXL is fully supported for Windows.
* Linux: see [Readme.md](../../README.md) for supported distros.
* macOS is not currently supported.

## Linux Support

### Prerequisites
On Linux, BuildXL uses an eBPF-based sandbox for file access monitoring. This requires the following native shared libraries to be installed on the system:

<!-- CODESYNC: Public/Src/Engine/Processes/SandboxConnectionLinuxEBPF.cs (s_requiredNativeLibraries) -->
<!-- CODESYNC: Public/Src/Sandbox/Linux/ebpf/BuildXL.Sandbox.Linux.eBPF.dsc (libraries list in link step) -->

| Library | Ubuntu/Debian | Mariner/Azure Linux |
|---------|---------------|---------------------|
| `libelf` | `libelf1` | `elfutils-libelf` |
| `zlib` | `zlib1g` | `zlib` |
| `libnuma` | `libnuma1` | `numactl-libs` |

```bash
# Ubuntu/Debian
sudo apt install libelf1 zlib1g libnuma1

# Mariner/Azure Linux
sudo dnf install elfutils-libelf zlib numactl-libs
```

BuildXL will check for these libraries at startup and report a clear error message if any are missing.

### Limitations

The following features are not supported on the PTrace sandbox.
- Blocking disallowed file accesses

## macOS Support History
In the past there was a push to bring BuildXL to macOS to provide cached and distributed builds to the a number of Microsoft teams. BuildXL moved to .netcore and scrubbed the codebase to add Unix support. The core bxl executable can be cross compiled on Windows to run on macOS. The major component that needed to be rewritten for macOS is the file access monitoring layer. This is what allows BuildXL to provide reliable caching.

There are a number of options for monitoring process trees and the files they access on unix platforms, and slightly fewer on macOS. Thorough analysis and prototyping was performed and all existing frameworks had issues that prevented their use. The last resort was writing a custom Kernel Extension (KEXT). This was able to satisfy the requirements for high performance and lossless file access tracking for child process trees. It enabled moving forward with macOS support but it came with the risk of of using a technology that might not be supported long term.

In 2020, it was announced that KEXT support would be deprecated from new versions of macOS. Apple provided a replacement for the core functionality in [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity). A prototype Endpoint Security based monitoring sandbox for BuildXL has been implemented, but at the time it proved to drop too many events to be practical for our main use case. That use case was primarily C++ and various scripts where including probes to non-existing files was important for the correctness of caching. Those probes were the highest volume of events which caused the Endpoint Security to be lossy. Between this and competing priorities on the build graph translation work, the decision was made to cease the effort.

Porting BuildXL to macOS helped jump start the team's other cross platform investments, namely Linux. The process execution and monitoring layer is common now across many Microsoft build products, including the Windows and Linux monitoring layer.

## macOS: Current Status

An Endpoint Security based sandbox has been rebuilt against the macOS 26/27 APIs and now runs real BuildXL builds, including C++ builds. See [MacOsSandbox.md](MacOsSandbox.md) for the design, the measurements, and the open questions.

The 2019 attempt failed on a specific point, and it is worth being precise about what has and has not changed.

**What made it unfixable then.** Probes of non-existent files are inputs to the cache key, they are the highest-volume events a build produces, and Endpoint Security dropped them. Critically, the prototype could not *tell* it was dropping them: it targeted macOS 10.15, where `es_message_t` had no sequence numbers at all. Loss was therefore silent, and silent loss corrupts the cache rather than slowing the build.

**What has changed.**

* `global_seq_num` (message version 4 and later) makes loss detectable. The broker requires it and refuses to trust an older stream, so a dropped event now taints the pip and makes it uncacheable. This converts a correctness failure into a performance failure - the build gets slower, never wrong.
* `es_new_descendants_client` (macOS 27) delivers only the pip's own process subtree. The 2019 prototype had to subscribe system-wide and filter, paying for every process on the machine.
* Absent-path probes are observable and are observed. A `stat` of a path that does not exist emits `NOTIFY_LOOKUP` and nothing else, so that event carries the whole signal and cannot be dropped from the design.

**What has been demonstrated.** Building the sandbox's own C++ sources through BuildXL under Endpoint Security succeeds; a no-op rebuild is a full cache hit with no sandbox taints; and creating a file at a path the compiler had probed and found absent correctly invalidates the cache, while removing it restores the hit. That last check is the direct test of the requirement the 2019 attempt could not meet.

**What has not been established.** Kernel drop rate has not yet been measured on a large build, and the workloads exercised so far are small. Whether the event volume of a large C++ codebase is tractable is the open question; it is now a measurable one rather than a blocking one, because loss can no longer pass silently.

The macOS sandbox is not supported. It is a working prototype with evidence behind it.