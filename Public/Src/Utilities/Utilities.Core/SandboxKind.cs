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
}
