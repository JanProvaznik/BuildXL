// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_NORMALIZED_EVENT_H
#define BUILDXL_SANDBOX_MACOS_NORMALIZED_EVENT_H

#include <cstdint>
#include <string>

namespace buildxl {
namespace macos {

/**
 * Backend-agnostic operation classes.
 *
 * This is deliberately *not* the Endpoint Security event enum: it is the boundary between the ES
 * ingress and the protocol engine, so that the engine (process attribution, sequence accounting,
 * fence, taint, translation) can be exercised without an entitled ES client.
 *
 * Every ES event type the broker subscribes to maps onto exactly one of these; anything that maps to
 * kUnsupported taints the pip.
 */
enum class NormOp : uint16_t
{
    kUnknown = 0,

    // Process lifecycle
    kFork,
    kExec,
    kExit,

    // Path resolution / reads
    kLookup,
    kOpen,
    kClose,
    kReaddir,
    kReadlink,
    kStat,
    kAccess,
    kGetAttrList,
    kGetExtAttr,
    kListExtAttr,
    kMmap,
    kFsGetPath,
    kSearchFs,
    kChdir,
    kDup,
    kFcntl,

    // Writes / mutations
    kCreate,
    kWrite,
    kTruncate,
    kUnlink,
    kRename,
    kLink,
    kClone,
    kCopyFile,
    kExchangeData,
    kSetAttrList,
    kSetExtAttr,
    kDeleteExtAttr,
    kSetFlags,
    kSetMode,
    kSetOwner,
    kSetAcl,
    kUtimes,

    // Domain-escape / unsupported delegation. These always taint.
    kUipcConnect,
    kXpcConnect,
    kBootstrapLookUp,
    kRemoteThreadCreate,
    kGetTask,
    kTrace,
    kProcSuspendResume,
    kChroot,
    kMount,
    kUnmount,
    kRemount,
    kSetUid,

    /** Subscribed-to but unmodellable. Always taints. */
    kUnsupported,

    kMax
};

/** Stable machine readable name; used for the report's "system call" field and the evidence JSONL. */
const char *NormOpName(NormOp op);

/**
 * Stable process identity.
 *
 * A bare pid is not sufficient: macOS recycles pids, and a pip's tree can outlive individual pids.
 * The (pid, pidversion) pair from the message's audit token is unique for the lifetime of the boot.
 */
struct ProcessIdentity
{
    int32_t pid = 0;
    int32_t pidversion = 0;

    bool IsValid() const { return pid > 0; }

    bool operator==(const ProcessIdentity &other) const
    {
        return pid == other.pid && pidversion == other.pidversion;
    }

    bool operator!=(const ProcessIdentity &other) const { return !(*this == other); }
};

struct ProcessIdentityHash
{
    size_t operator()(const ProcessIdentity &id) const
    {
        return (static_cast<size_t>(static_cast<uint32_t>(id.pid)) << 32)
             ^ static_cast<size_t>(static_cast<uint32_t>(id.pidversion));
    }
};

/**
 * One event, already copied out of any kernel-owned memory.
 *
 * The ES callback must not retain the es_message_t, so the ingress performs a bounded copy into this
 * structure and returns immediately.
 */
struct NormalizedEvent
{
    /** Per-client monotonically increasing sequence. Gaps mean the kernel dropped messages. */
    uint64_t globalSequence = 0;

    /** Per-client, per-event-type sequence. Used as an independent cross-check on gap detection. */
    uint64_t typeSequence = 0;

    /** ES message version. Unknown versions taint. */
    uint32_t messageVersion = 0;

    /**
     * True when `globalSequence` was assigned by the kernel and is therefore evidence about loss.
     *
     * Endpoint Security stamps every message with a per-client `global_seq_num`, so a gap in it is a
     * statement that the kernel dropped something. The interposition backend has no such authority:
     * its sequences are assigned per process in user space, so a "gap" across processes is normal
     * interleaving and means nothing. Setting this false makes SequenceTracker abstain rather than
     * manufacture a taint, and moves the loss claim to where it can actually be made -- the ingress,
     * which sees each process's framing and reports through EventSource::BackendReportedLosses().
     */
    bool sequenceIsKernelAssigned = true;

    /** Mach absolute time the event was generated. */
    uint64_t machTime = 0;

    /** Identity of the ES client connection this event belongs to. Changes on reconnect. */
    uint64_t clientEpoch = 0;

    NormOp op = NormOp::kUnknown;

    /** True for AUTH events (which must be responded to), false for NOTIFY. */
    bool isAuth = false;

    /** For NOTIFY events, whether the underlying operation succeeded. */
    bool succeeded = true;

    /** errno for failed operations, 0 when unknown or successful. */
    int32_t error = 0;

    ProcessIdentity self;
    ProcessIdentity parent;

    bool sourceIsDirectory = false;
    bool destinationIsDirectory = false;
    bool sourceExists = true;
    bool destinationExists = true;

    /** Set when ES reported the path itself as truncated. Always taints. */
    bool sourcePathTruncated = false;
    bool destinationPathTruncated = false;

    std::string sourcePath;
    std::string destinationPath;

    /** Populated for kExec only. */
    std::string commandLine;

    /** True when the broker itself instigated this event (fence markers, self-reads). */
    bool fromBroker = false;

    /** True when the event's target could only be identified by descriptor, not by path. */
    bool descriptorOnly = false;
};

/** True for operations whose observation is required for dependency correctness. */
bool IsRelevantForDependencies(NormOp op);

/** True for operations that always mark the pip non-cacheable. */
bool IsAlwaysTainting(NormOp op);

} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_NORMALIZED_EVENT_H
