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
     * Handles a FORK event.
     *
     * @return kUnmappedLineage when the parent is not part of the tracked tree, kNone otherwise.
     */
    TaintReason HandleFork(const NormalizedEvent &event);

    /** Handles an EXEC event, recording the new image and command line. */
    TaintReason HandleExec(const NormalizedEvent &event, bool isBreakaway);

    /** Handles an EXIT event. */
    TaintReason HandleExit(const NormalizedEvent &event);

    /**
     * Confirms that an event belongs to the tracked tree.
     *
     * An event from an untracked identity means either that the broker missed the FORK/EXEC that
     * introduced it (a real loss) or that the descendants domain contains something the broker did
     * not model. Both are unsound, so both taint.
     */
    TaintReason ValidateLineage(const NormalizedEvent &event) const;

    bool IsTracked(const ProcessIdentity &identity) const;

    bool IsBreakaway(const ProcessIdentity &identity) const;

    /** Number of processes currently believed to be alive. */
    size_t LiveCount() const { return m_liveCount; }

    /** Number of processes ever seen. */
    size_t TotalCount() const { return m_processes.size(); }

    /** True when every known process has been observed exiting. */
    bool IsClosed() const { return m_liveCount == 0 && !m_processes.empty(); }

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

    std::unordered_map<ProcessIdentity, TrackedProcess, ProcessIdentityHash> m_processes;
    mutable std::unordered_set<ProcessIdentity, ProcessIdentityHash> m_unmapped;
    size_t m_liveCount = 0;
};

} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_PROCESS_TABLE_H
