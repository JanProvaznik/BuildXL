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
        /// macOS-specific: using an Endpoint Security descendants client to observe file accesses
        /// </summary>
        MacOsEndpointSecurity,
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
            kind == SandboxKind.LinuxEBPF || kind == SandboxKind.MacOsEndpointSecurity;
    }
}
