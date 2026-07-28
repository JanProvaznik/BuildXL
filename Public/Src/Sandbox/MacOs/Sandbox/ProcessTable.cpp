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
    }

    m_unmapped.erase(identity);
}

TaintReason ProcessTable::HandleFork(const NormalizedEvent &event)
{
    // On a fork event, 'self' is the child and 'parent' is the process that called fork.
    if (!event.parent.IsValid() || m_processes.find(event.parent) == m_processes.end())
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
    }

    m_unmapped.erase(event.self);
    return TaintReason::kNone;
}

TaintReason ProcessTable::HandleExec(const NormalizedEvent &event, bool isBreakaway)
{
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

TaintReason ProcessTable::ValidateLineage(const NormalizedEvent &event) const
{
    if (m_processes.find(event.self) != m_processes.end())
    {
        return TaintReason::kNone;
    }

    m_unmapped.insert(event.self);
    return TaintReason::kUnmappedLineage;
}

bool ProcessTable::IsTracked(const ProcessIdentity &identity) const
{
    return m_processes.find(identity) != m_processes.end();
}

bool ProcessTable::IsBreakaway(const ProcessIdentity &identity) const
{
    const TrackedProcess *process = TryGet(identity);
    return process != nullptr && process->brokeAway;
}

const TrackedProcess *ProcessTable::TryGet(const ProcessIdentity &identity) const
{
    auto found = m_processes.find(identity);
    return found == m_processes.end() ? nullptr : &found->second;
}

TrackedProcess *ProcessTable::TryGetMutable(const ProcessIdentity &identity)
{
    auto found = m_processes.find(identity);
    return found == m_processes.end() ? nullptr : &found->second;
}

std::vector<ProcessIdentity> ProcessTable::LiveProcesses() const
{
    std::vector<ProcessIdentity> live;
    for (const auto &entry : m_processes)
    {
        if (entry.second.alive)
        {
            live.push_back(entry.first);
        }
    }

    return live;
}

} // namespace macos
} // namespace buildxl
