// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace BuildXL.Utilities.Core
{
    /// <summary>
    /// Different kinds of sandboxes
    /// </summary>
    public enum SandboxKind : byte
    {
        /// <summary>
        /// No sandboxing
        /// </summary>
        None,

        /// <summary>
        /// Default sandboxing for the current platform.
        /// </summary>
        Default,

        /// <summary>
        /// Windows-specific: using Detours
        /// </summary>
        WinDetours,

        /// <summary>
        /// Linux-specific: using LD_PRELOAD interposing
        /// </summary>
        LinuxDetours,

        /// <summary>
        /// Linux-specific: using EBPF for tracing syscalls
        /// </summary>
        LinuxEBPF,

        /// <summary>
        /// macOS-specific: observing file accesses through a supervising broker process.
        /// </summary>
        /// <remarks>
        /// Deliberately not named after a mechanism, unlike the Linux kinds. The broker picks its
        /// observation backend when it starts: an Endpoint Security descendants client where the
        /// restricted entitlement is available, and dyld interposition otherwise. Both are driven by
        /// the same protocol engine and produce the same reports, and the backend that ran is recorded
        /// in the evidence file. Naming the enum after one of them would make the setting a lie on
        /// every machine that had to use the other.
        /// </remarks>
        MacOs,
    }

    /// <nodoc />
    public static class SandboxKindExtensions
    {
        /// <summary>
        /// Whether the sandbox wraps the pip's root process in a helper process that stays alive until
        /// the entire process tree, including orphans, has exited.
        /// </summary>
        /// <remarks>
        /// This changes how BuildXL waits for and terminates a pip: the OS process tree ending no
        /// longer coincides with the process executor returning, and the helper needs a chance to
        /// finish writing its report stream before it is killed. Expressing it as a property of the
        /// sandbox kind rather than as scattered equality checks is what keeps a newly added sandbox
        /// from silently getting the wrong behaviour at one of the decision points.
        /// </remarks>
        public static bool WrapsRootProcessInSupervisor(this SandboxKind kind) =>
            kind == SandboxKind.LinuxEBPF || kind == SandboxKind.MacOs;
    }
}
