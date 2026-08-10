// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ProcessTable.h"

namespace buildxl {
namespace macos {

void ProcessTable::AddRoot(const ProcessIdentity &identity, const std::string &executablePath, uint64_t sequence)
{
    TrackedProcess root;
    root.identity = identity;
    root.parent = ProcessIdentity{};
    root.executablePath = executablePath;
    root.startSequence = sequence;
    root.alive = true;

    auto inserted = m_processes.emplace(identity, root);
    if (inserted.second)
    {
        m_liveCount++;
        m_observedCount++;
    }

    m_unmapped.erase(identity);
}

void ProcessTable::AddSyntheticAncestor(const ProcessIdentity &identity, const std::string &executablePath)
{
    TrackedProcess anchor;
    anchor.identity = identity;
    anchor.parent = ProcessIdentity{};
    anchor.executablePath = executablePath;
    anchor.startSequence = 0;
    anchor.alive = false;
    anchor.synthetic = true;

    m_processes.emplace(identity, anchor);
}

TaintReason ProcessTable::HandleFork(const NormalizedEvent &event)
{
    // On a fork event, 'self' is the child and 'parent' is the process that called fork.
    if (!event.parent.IsValid() || TryGet(event.parent) == nullptr)
    {
        m_unmapped.insert(event.self);
        return TaintReason::kUnmappedLineage;
    }

    const TrackedProcess *parent = TryGet(event.parent);

    TrackedProcess child;
    child.identity = event.self;
    child.parent = event.parent;
    child.executablePath = parent != nullptr ? parent->executablePath : std::string();
    child.commandLine = parent != nullptr ? parent->commandLine : std::string();
    child.startSequence = event.globalSequence;
    child.alive = true;
    // Breakaway is inherited: a child of a broken-away process is equally untracked.
    child.brokeAway = parent != nullptr && parent->brokeAway;

    auto inserted = m_processes.emplace(event.self, child);
    if (inserted.second)
    {
        m_liveCount++;
        m_observedCount++;
    }

    m_unmapped.erase(event.self);
    return TaintReason::kNone;
}

TaintReason ProcessTable::HandleExec(const NormalizedEvent &event, bool isBreakaway)
{
    // A process is renumbered when it execs, so the entry to update is filed under the identity it
    // had before. Re-keying it here is what keeps the tree connected; without it, every process
    // that execs - which is every process a build runs - would look untracked from its exec onward.
    if (event.identityBeforeExec.IsValid() && event.identityBeforeExec != event.self)
    {
        auto previous = m_processes.find(event.identityBeforeExec);
        if (previous != m_processes.end())
        {
            TrackedProcess renamed = previous->second;
            renamed.identity = event.self;
            m_processes.erase(previous);

            // The pre-exec identity is retained so that a later message still carrying it - the
            // ordering between an exec and a straggling message from the same process is the
            // kernel's to choose, not ours - resolves to the same process rather than looking like
            // a lost fork.
            m_execPredecessors[event.identityBeforeExec] = event.self;

            auto inserted = m_processes.emplace(event.self, renamed);
            if (!inserted.second)
            {
                // The identity is already taken. Rather than merge two processes into one entry,
                // which would silently lose one of them, this is reported.
                m_unmapped.insert(event.self);
                return TaintReason::kUnmappedLineage;
            }
        }
    }

    TrackedProcess *process = TryGetMutable(event.self);
    if (process == nullptr)
    {
        // An exec by a process the broker never saw being created. This is exactly the shape a
        // dropped FORK takes, so it must not be silently absorbed by creating the entry here.
        m_unmapped.insert(event.self);
        return TaintReason::kUnmappedLineage;
    }

    process->executablePath = event.sourcePath;
    process->commandLine = event.commandLine;
    if (isBreakaway)
    {
        process->brokeAway = true;
    }

    return TaintReason::kNone;
}

TaintReason ProcessTable::HandleExit(const NormalizedEvent &event)
{
    TrackedProcess *process = TryGetMutable(event.self);
    if (process == nullptr)
    {
        m_unmapped.insert(event.self);
        return TaintReason::kUnmappedLineage;
    }

    if (process->alive)
    {
        process->alive = false;
        process->exitSequence = event.globalSequence;
        m_liveCount--;
    }

    return TaintReason::kNone;
}

bool ProcessTable::IsTracked(const ProcessIdentity &identity) const
{
    return TryGet(identity) != nullptr;
}

bool ProcessTable::IsBreakaway(const ProcessIdentity &identity) const
{
    const TrackedProcess *process = TryGet(identity);
    return process != nullptr && process->brokeAway;
}

const TrackedProcess *ProcessTable::TryGet(const ProcessIdentity &identity) const
{
    auto found = m_processes.find(Resolve(identity));
    return found == m_processes.end() ? nullptr : &found->second;
}

TrackedProcess *ProcessTable::TryGetMutable(const ProcessIdentity &identity)
{
    auto found = m_processes.find(Resolve(identity));
    return found == m_processes.end() ? nullptr : &found->second;
}

ProcessIdentity ProcessTable::Resolve(const ProcessIdentity &identity) const
{
    if (m_processes.find(identity) != m_processes.end())
    {
        return identity;
    }

    // Follows the renames recorded at exec. Bounded so that a corrupt chain cannot spin: a process
    // that execs more than this many times in one pip is not a case worth serving, and the fallback
    // is to report it as untracked, which is the safe answer.
    ProcessIdentity current = identity;
    for (int hops = 0; hops < 32; hops++)
    {
        auto renamed = m_execPredecessors.find(current);
        if (renamed == m_execPredecessors.end())
        {
            return identity;
        }

        current = renamed->second;
        if (m_processes.find(current) != m_processes.end())
        {
            return current;
        }
    }

    return identity;
}

std::vector<ProcessIdentity> ProcessTable::LiveProcesses() const
{
    std::vector<ProcessIdentity> live;
    for (const auto &entry : m_processes)
    {
        if (entry.second.alive && !entry.second.synthetic)
        {
            live.push_back(entry.first);
        }
    }

    return live;
}

} // namespace macos
} // namespace buildxl
