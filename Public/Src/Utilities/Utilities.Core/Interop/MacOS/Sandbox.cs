// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member

namespace BuildXL.Interop.Unix
{
    /// <summary>
    /// The Sandbox class offers interop calls for sandbox based tasks into the macOS sandbox interop library
    /// </summary>
    public static class Sandbox
    {
        /// <summary>
        /// Normalizes a path and returns its manifest hash.
        /// </summary>
        /// <remarks>
        /// macOS used to route this into the native sandbox library, which was removed along with the
        /// kernel extension; the export no longer exists, so calling it now throws at runtime. The
        /// managed implementation is byte-identical to what the native side computes on every Unix
        /// platform, so both macOS and Linux use it directly.
        /// CODESYNC: NormalizePathChar in Public/Src/Sandbox/Windows/DetoursServices/StringOperations.h
        /// </remarks>
        public static int NormalizePathAndReturnHash(byte[] pPath, byte[] normalizedPath)
        {
            return Impl_Linux.NormalizePathAndReturnHash(pPath, normalizedPath);
        }

        /// <summary>
        /// Callback the SandboxConnection uses to report any unrecoverable failure back to
        /// the scheduler (which, in response, should then terminate the build).
        /// </summary>
        /// <param name="status">Error code indicating what failure happened</param>
        /// <param name="description">Arbitrary description</param>
        public delegate void ManagedFailureCallback(int status, string description);
    }
}

#pragma warning restore CS1591