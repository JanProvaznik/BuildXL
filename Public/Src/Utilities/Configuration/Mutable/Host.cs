// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics.ContractsLight;
using System.Runtime.InteropServices;

namespace BuildXL.Utilities.Configuration.Mutable
{
    /// <nodoc />
    public sealed class Host : IHost
    {
        /// <summary>
        /// Gets the current host information
        /// </summary>
        public static IHost Current { get; } = new Host();

        /// <nodoc />
        public Host()
        {
            CurrentOS = BuildXL.Interop.Dispatch.CurrentOS();
            CpuArchitecture = GetCpuArchitecture();
        }

        /// <nodoc />
        public Host(IHost template, PathRemapper pathRemapper)
        {
            Contract.Assume(template != null);
            Contract.Assume(pathRemapper != null);

            CurrentOS = template.CurrentOS;
            CpuArchitecture = template.CpuArchitecture;
        }

        /// <inheritdoc />
        public BuildXL.Interop.OperatingSystem CurrentOS { get; set;  }

        /// <inheritdoc />
        public HostCpuArchitecture CpuArchitecture { get; set; }

        /// <summary>
        /// Reports the architecture of the running engine.
        /// </summary>
        /// <remarks>
        /// This deliberately uses <see cref="RuntimeInformation.ProcessArchitecture"/> rather than
        /// <see cref="RuntimeInformation.OSArchitecture"/>. On an Apple Silicon Mac, an x64 process
        /// running under Rosetta 2 sees <c>OSArchitecture == Arm64</c> but
        /// <c>ProcessArchitecture == X64</c>. Specs use this value to choose which native tools and
        /// runtime packages to load into, or execute from, this process, so the process architecture
        /// is the correct answer: an x64 engine must keep selecting x64 assets even when the machine
        /// underneath it is arm64. It also means this value only becomes Arm64 once BuildXL genuinely
        /// runs natively on arm64, so existing x64 deployments are unaffected.
        /// </remarks>
        private static HostCpuArchitecture GetCpuArchitecture()
        {
            switch (RuntimeInformation.ProcessArchitecture)
            {
                case Architecture.Arm64:
                    return HostCpuArchitecture.Arm64;
                case Architecture.X86:
                    return HostCpuArchitecture.X86;
                case Architecture.X64:
                    return HostCpuArchitecture.X64;
                default:
                    // Deliberately not a failure: an unrecognized architecture should not stop a
                    // build, and the pre-existing behavior of reporting the OS bitness is a
                    // reasonable answer for any other 64-bit architecture.
                    return Environment.Is64BitOperatingSystem ? HostCpuArchitecture.X64 : HostCpuArchitecture.X86;
            }
        }
    }
}
