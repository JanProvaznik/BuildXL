// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_INTERPOSE_PROTOCOL_H
#define BUILDXL_SANDBOX_MACOS_INTERPOSE_PROTOCOL_H

#include <stdint.h>

/**
 * Wire format between the injected observer (libBuildXLInterpose.dylib) and the broker's
 * InterposeIngress.
 *
 * Deliberately its own enum rather than a shared NormOp: the injected library is loaded into every
 * process a build starts, so it must not depend on the broker's C++ headers, and the ingress must
 * perform an explicit, testable mapping rather than reinterpreting integers it did not define.
 * CODESYNC: Public/Src/Sandbox/MacOs/Sandbox/InterposeIngress.cpp (OpToNormOp).
 *
 * Framing is length-prefixed rather than newline-delimited because paths on macOS may legitimately
 * contain newlines. This is not hypothetical: MSBuild resolves properties such as
 * AssemblySearchPaths into multi-line strings and then stat()s the result, so a newline-delimited
 * report stream corrupts on an ordinary `dotnet build`.
 */

#define BXL_INTERPOSE_SOCKET_ENV_VAR "__BUILDXL_INTERPOSE_SOCKET"
#define BXL_INTERPOSE_LIBRARY_ENV_VAR "__BUILDXL_INTERPOSE_LIBRARY"

#ifdef __cplusplus
namespace buildxl {
namespace macos {
namespace interpose {
#endif

enum
{
    /** 'BXLI'. Guards against a stray connection to the socket. */
    kInterposeMagic = 0x42584C49,

    kInterposeVersion = 1,

    /** Longer paths are sent truncated with kFlagSourceTruncated set, which taints the pip. */
    kInterposeMaxPath = 4096,
};

/** Record kinds. */
enum InterposeRecordKind
{
    /** First record on a connection: the process announcing itself. */
    kRecordHello = 1,

    /** A file system or process operation. */
    kRecordEvent = 2,

    /**
     * The observer could not be installed into a process the observed tree started, so everything
     * that process does is unobserved. The pip must not be cached on the strength of this run.
     */
    kRecordUnobservableChild = 3,
};

/**
 * Operations the injected library reports.
 *
 * The set is the file system surface .NET, MSBuild and Roslyn actually use on macOS, derived from
 * the imports of libSystem.Native.dylib rather than from a general list of POSIX calls. That
 * derivation matters: .NET binds the non-cancellable aliases (open$NOCANCEL and friends), so a
 * library that interposes only `open` observes almost nothing.
 */
enum InterposeOp
{
    kOpUnknown = 0,

    kOpOpenRead = 1,
    kOpOpenWrite = 2,
    kOpCreate = 3,
    kOpStat = 4,
    kOpAccess = 5,
    kOpReadDir = 6,
    kOpReadLink = 7,
    kOpMkDir = 8,
    kOpRmDir = 9,
    kOpUnlink = 10,
    kOpRename = 11,
    kOpLink = 12,
    kOpSymlink = 13,
    kOpChMod = 14,
    kOpChOwn = 15,
    kOpTruncate = 16,
    kOpUTimes = 17,
    kOpCloneFile = 18,
    kOpCopyFile = 19,
    kOpExec = 20,
    kOpSpawn = 21,
    kOpChDir = 22,
    kOpExit = 23,
    kOpSetFlags = 24,

    kOpMax
};

enum InterposeFlags
{
    kFlagSucceeded = 1 << 0,
    kFlagSourceIsDirectory = 1 << 1,
    kFlagDestinationIsDirectory = 1 << 2,
    kFlagSourceExists = 1 << 3,
    kFlagDestinationExists = 1 << 4,
    kFlagSourceTruncated = 1 << 5,
    kFlagDestinationTruncated = 1 << 6
};

#pragma pack(push, 1)

/**
 * Fixed-size prologue. `totalLength` covers this header plus both path payloads, so a reader can
 * always advance even across a record whose kind or op it does not recognise.
 */
struct InterposeRecordHeader
{
    uint32_t magic;
    uint32_t totalLength;

    uint16_t kind;
    uint16_t op;
    uint16_t flags;
    uint16_t version;

    int32_t pid;
    int32_t parentPid;

    /**
     * Process start time in seconds since the epoch, for `pid` and `parentPid`.
     *
     * A bare pid is not a process identity: macOS recycles pids, and a build can outlive the whole
     * pid space. Endpoint Security supplies a pidversion for this; libproc does not, so the start
     * time serves as the disambiguator. Zero means the lookup failed, which the ingress treats as
     * "unknown" rather than as a match.
     */
    int32_t pidStartSeconds;
    int32_t parentPidStartSeconds;

    int32_t error;
    uint32_t reserved;

    /** Per-process monotonically increasing. A gap means the process's records were truncated. */
    uint64_t sequence;

    uint64_t machTime;

    uint32_t sourceLength;
    uint32_t destinationLength;
};

#pragma pack(pop)

#ifdef __cplusplus
} // namespace interpose
} // namespace macos
} // namespace buildxl
#endif

#endif // BUILDXL_SANDBOX_MACOS_INTERPOSE_PROTOCOL_H
