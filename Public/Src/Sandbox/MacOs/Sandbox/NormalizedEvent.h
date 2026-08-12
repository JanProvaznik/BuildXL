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

    /**
     * How many kernel messages the ingress deliberately withheld between the previously forwarded
     * event and this one.
     *
     * The broker is itself a descendant of nothing and an ancestor of everything it observes, so a
     * descendants client reports the broker's own syscalls - including the writes it makes to the
     * report FIFO, which would otherwise feed back without bound. Those messages are suppressed, but
     * the kernel has already spent their sequence numbers. Without this field the next forwarded
     * event looks like it arrived after a gap, and SequenceTracker reports a kernel drop that never
     * happened. On a real build the broker writes constantly, so every pip would taint and nothing
     * would ever be cacheable.
     *
     * `Global` counts all withheld messages; `Type` counts only those that shared this event's
     * NormOp, because the per-event-type cross-check needs the same correction.
     */
    uint64_t suppressedBeforeGlobal = 0;
    uint64_t suppressedBeforeType = 0;

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

    /**
     * errno for failed operations, 0 when unknown or successful.
     *
     * BuildXL reads this to decide whether the target existed: ReportedFileAccess.IsNonexistent is
     * `Error == ERROR_FILE_NOT_FOUND || Error == ERROR_PATH_NOT_FOUND`, and that answer feeds ACL
     * decisions. Anything other than a real errno here is therefore not a cosmetic inaccuracy.
     */
    int32_t error = 0;

    /**
     * Open flags, for the events that carry them. Not an errno.
     *
     * These used to be stuffed into `error`, where BuildXL read them as one: an open for writing
     * (O_WRONLY, 1) was reported as errno 1, EPERM.
     */
    uint32_t openFlags = 0;

    ProcessIdentity self;
    ProcessIdentity parent;

    /**
     * For an exec, the identity the process had before it. Invalid on every other event.
     *
     * macOS renumbers a process when it execs: its pidversion changes, so the (pid, pidversion) pair
     * recorded when the process was forked stops matching the pair on every message it sends
     * afterwards. `self` is the identity going forward, which is what the rest of the system should
     * use; this is the one that finds the entry the FORK event created, so it can be re-keyed rather
     * than orphaned.
     */
    ProcessIdentity identityBeforeExec;

    bool sourceIsDirectory = false;
    bool destinationIsDirectory = false;
    bool sourceExists = true;
    bool destinationExists = true;

    /**
     * For a lookup, the directory the name was resolved in.
     *
     * Endpoint Security does not say what a lookup found, but it does say where it looked, and that
     * parent is a directory by construction. Recording it turns the expensive case - walking an
     * ancestor chain one component at a time - into something the engine already knows the answer
     * to, without asking the filesystem.
     */
    std::string lookupParentPath;

    /**
     * Whether sourceExists/sourceIsDirectory were established by whoever produced this event.
     *
     * Endpoint Security's LOOKUP carries no stat for what it found, so for that one event the fields
     * above are defaults rather than observations and the engine has to resolve them. Every other
     * producer - the interpose ingress, a replayed corpus - already knows, and must say so, or the
     * engine would overwrite a known answer with one read from the live filesystem.
     */
    bool sourceTypeKnown = true;

    /**
     * For a close, whether the file was actually written through the descriptor being closed.
     *
     * This deserves its own field rather than riding on one of the ones above, because it is the
     * only write signal a close carries and getting it wrong is not a subtle failure: a close is
     * emitted for every file a process opens, so treating them all as writes reports every file a
     * compiler merely read as a file it produced. Defaults to false so that a backend which does
     * not set it cannot silently manufacture writes.
     */
    bool contentModified = false;

    /** Set when ES reported the path itself as truncated. Always taints. */
    bool sourcePathTruncated = false;
    bool destinationPathTruncated = false;

    std::string sourcePath;
    std::string destinationPath;

    /** Populated for kExec only. */
    std::string commandLine;

    /**
     * For a delegation event, what the process was trying to reach: an XPC or bootstrap service
     * name, or the path of a UNIX-domain socket. Empty on every other event.
     *
     * Recorded because the decision about whether a delegation is an escape cannot be made from the
     * operation alone. Every process on macOS contacts system services simply to run - a compile of
     * one C file produces nine delegation events, all of them to com.apple.logd,
     * com.apple.system.notification_center, com.apple.system.opendirectoryd.membership and
     * com.apple.analyticsd. Treating those as escapes makes every macOS pip uncacheable, which is
     * the same as having no sandbox at all.
     */
    std::string delegationTarget;

    /**
     * True when the delegation target is a service the operating system owns.
     *
     * The soundness worry behind delegation is that a pip asks a service outside the descendant
     * domain to touch the filesystem on its behalf, so the observation set is incomplete. That worry
     * is real for a service the build itself runs - a compiler server is the canonical example - and
     * it is why BuildXL has an explicit switch for shared compilation. It is not real for the
     * platform's own daemons, whose filesystem effects are confined to system locations no build
     * declares and do not vary with build content.
     *
     * Note the production Linux sandbox does not intercept connect() at all and Detours does not
     * model IPC either, so treating platform-service contact as an escape would make macOS strictly
     * stricter than both supported platforms, at the cost of never caching anything.
     */
    bool delegationTargetIsPlatform = false;

    /** True when the broker itself instigated this event (fence markers, self-reads). */
    bool fromBroker = false;

    /** True when the event's target could only be identified by descriptor, not by path. */
    bool descriptorOnly = false;
};

/** True for operations whose observation is required for dependency correctness. */
bool IsRelevantForDependencies(NormOp op);

/** True for operations that always mark the pip non-cacheable. */
bool IsAlwaysTainting(NormOp op);

/** True for the three operations that hand work to something outside the descendant domain. */
bool IsDelegation(NormOp op);

/** Whether an operation can change what is at a path, and so invalidate a remembered path type. */
bool IsMutation(NormOp op);

/**
 * Decides whether a delegation event actually puts the pip's observation set at risk.
 *
 * Judged per event rather than per operation, because the operation alone does not carry enough
 * information: contacting com.apple.logd and contacting a build's own compiler server are the same
 * operation with entirely different consequences.
 */
bool IsDelegationEscape(const NormalizedEvent &event);

/**
 * Removes `.` and `..` segments, duplicate separators and a trailing separator from an absolute
 * path, in place. Relative paths and paths already clean are left untouched.
 *
 * Endpoint Security reports the path a caller supplied rather than a cleaned one, so a LOOKUP can
 * arrive as `/Library/Developer/CommandLineTools/usr/bin/../local/lib/clang/workarounds.jsonl`.
 * Measured on a 61-file clang build, that exact path arrives 62 times, while the interposition
 * ingress reports the same 62 accesses as `/Library/Developer/CommandLineTools/usr/local/...`.
 *
 * Two spellings of one file is not cosmetic. The access checker resolves policy by walking the
 * manifest's path tree, so a path carrying `..` matches no node: an access inside a declared cone
 * is judged as if it were outside one. It also splits a single file across two fingerprint entries,
 * so the two backends cannot agree on a cache key for the same build.
 *
 * The cleanup is purely lexical, which is deliberate. realpath() would be a syscall on every one of
 * the ~64,000 events a small build produces, and it would additionally resolve symlinks - moving
 * the disagreement with the interposer rather than removing it, since the interposer stays lexical
 * on purpose. Lexical `..` removal is unsound when a component is a symlink, which is the same
 * trade-off every other BuildXL sandbox already makes, and it matches what the tool itself believes
 * about the path it passed.
 */
void CleanPath(std::string &path);

} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_NORMALIZED_EVENT_H
