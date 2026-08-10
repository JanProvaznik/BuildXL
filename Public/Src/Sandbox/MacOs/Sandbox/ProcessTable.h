// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_PROCESS_TABLE_H
#define BUILDXL_SANDBOX_MACOS_PROCESS_TABLE_H

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "NormalizedEvent.h"
#include "Taint.h"

namespace buildxl {
namespace macos {

/** What the process table knows about one process in the pip's tree. */
struct TrackedProcess
{
    ProcessIdentity identity;
    ProcessIdentity parent;
    std::string executablePath;
    std::string commandLine;

    /** Global sequence at which the process entered the tree. */
    uint64_t startSequence = 0;

    /** Global sequence at which EXIT was observed; 0 while alive. */
    uint64_t exitSequence = 0;

    bool alive = true;

    /** True when the process matched a breakaway rule and its accesses are intentionally not tracked. */
    bool brokeAway = false;

    /**
     * True for an entry that was inserted to anchor lineage rather than because a process was
     * observed. The broker itself is the only such entry: it is the parent of the pip's root process,
     * so lineage validation needs to find it, but it is not part of the pip and must not count
     * towards liveness or towards "did we observe anything at all".
     */
    bool synthetic = false;
};

/**
 * Tracks the pip's process tree by audit-token identity.
 *
 * Why not pid alone: macOS reuses pids aggressively, and a pip can outlive several generations of
 * short-lived children. Two different processes with the same pid are distinguished by pidversion,
 * so (pid, pidversion) is used as the key everywhere. A bare pid is only ever used when writing the
 * report line, because that is what the managed side's report format carries.
 *
 * Lifecycle closure: the table is "closed" when every process that was ever added has been observed
 * exiting. The fence protocol requires closure before it will even attempt to place a marker; a
 * table that never closes produces TaintReason::kLifecycleNotClosed rather than a silent completion.
 *
 * Not thread safe; owned by the single drain thread.
 */
class ProcessTable
{
public:
    /** Registers the pip's root process, observed via the broker's own fork/exec of the runner. */
    void AddRoot(const ProcessIdentity &identity, const std::string &executablePath, uint64_t sequence);

    /**
     * Anchors lineage at an identity that is not part of the pip.
     *
     * The broker forks the pip's root process, so the root's FORK event names the broker as its
     * parent. Without an anchor that fork has no mapped parent and every build would start with a
     * kUnmappedLineage taint. The anchor is recorded as already-exited and flagged synthetic so it
     * affects neither liveness nor closure.
     */
    void AddSyntheticAncestor(const ProcessIdentity &identity, const std::string &executablePath);

    /**
     * Handles a FORK event.
     *
     * @return kUnmappedLineage when the parent is not part of the tracked tree, kNone otherwise.
     */
    TaintReason HandleFork(const NormalizedEvent &event);

    /** Handles an EXEC event, recording the new image and command line. */
    TaintReason HandleExec(const NormalizedEvent &event, bool isBreakaway);

    /** Handles an EXIT event. */
    TaintReason HandleExit(const NormalizedEvent &event);

    bool IsTracked(const ProcessIdentity &identity) const;

    bool IsBreakaway(const ProcessIdentity &identity) const;

    /** Number of processes currently believed to be alive. */
    size_t LiveCount() const { return m_liveCount; }

    /** Number of processes ever seen. */
    size_t TotalCount() const { return m_processes.size(); }

    /**
     * True when at least one real process was observed and every one of them has been observed
     * exiting.
     *
     * The "at least one" half matters: if the root's FORK is lost, nothing real is ever recorded, and
     * a table that is merely not-live would look closed. Synthetic anchors are excluded from both
     * halves so that adding one can never turn an unclosed tree into a closed one.
     */
    bool IsClosed() const { return m_liveCount == 0 && m_observedCount > 0; }

    const TrackedProcess *TryGet(const ProcessIdentity &identity) const;

    /** All processes still believed alive; used when reporting an unclosed tree. */
    std::vector<ProcessIdentity> LiveProcesses() const;

    /** Identities that produced events without ever being introduced by fork/exec. */
    const std::unordered_set<ProcessIdentity, ProcessIdentityHash> &UnmappedIdentities() const
    {
        return m_unmapped;
    }

private:
    TrackedProcess *TryGetMutable(const ProcessIdentity &identity);

    /**
     * Maps an identity to the one the process currently answers to, following renames recorded at
     * exec. Returns the identity unchanged when there is nothing to follow.
     */
    ProcessIdentity Resolve(const ProcessIdentity &identity) const;

    std::unordered_map<ProcessIdentity, TrackedProcess, ProcessIdentityHash> m_processes;

    /**
     * Pre-exec identity to post-exec identity, for every process that has execed.
     *
     * Bounded by the number of execs in one pip, which is the number of processes it runs, so this
     * does not grow without limit. It exists because the kernel is free to deliver a message that
     * was in flight when the exec happened, and such a message still carries the old identity.
     */
    std::unordered_map<ProcessIdentity, ProcessIdentity, ProcessIdentityHash> m_execPredecessors;

    mutable std::unordered_set<ProcessIdentity, ProcessIdentityHash> m_unmapped;
    size_t m_liveCount = 0;
    size_t m_observedCount = 0;
};

} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_PROCESS_TABLE_H
