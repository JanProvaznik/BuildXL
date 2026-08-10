// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "SequenceTracker.h"

namespace buildxl {
namespace macos {

TaintReason SequenceTracker::Observe(const NormalizedEvent &event)
{
    TaintReason taint = TaintReason::kNone;

    if (!event.sequenceIsKernelAssigned)
    {
        // Nothing here applies. The message version is an Endpoint Security concept, and the sequence
        // is per process rather than per client, so consecutive events from different processes are
        // expected to "go backwards". Asserting on either would produce a taint on every single build
        // that says nothing about whether anything was lost. Loss for this backend is detected where
        // the per-process framing is visible and surfaced through BackendReportedLosses().
        m_userSpaceSequencedCount++;
        m_observedCount++;
        return taint;
    }

    if (event.messageVersion < kMinimumSupportedMessageVersion)
    {
        // Without global_seq_num there is no way to know whether the kernel dropped anything, so the
        // whole stream has to be treated as lossy.
        taint |= TaintReason::kUnknownMessageVersion;
    }
    else if (event.messageVersion > kMaximumKnownMessageVersion)
    {
        // Newer versions only add fields, so the message is still readable. Count it so that the
        // evidence makes it obvious the broker is running against an OS it has not been validated on.
        m_newerVersionCount++;
    }

    if (!m_epochInitialized)
    {
        m_currentEpoch = event.clientEpoch;
        m_epochInitialized = true;
    }
    else if (event.clientEpoch != m_currentEpoch)
    {
        // A new connection restarts sequence numbering, so nothing can be concluded about whether
        // events were lost across the boundary.
        taint |= TaintReason::kClientEpochChanged;
        ResetForNewEpoch(event.clientEpoch);
    }

    if (m_observedCount > 0 && event.messageVersion >= kMinimumSupportedMessageVersion)
    {
        // Messages the ingress withheld still consumed sequence numbers, so the first sequence this
        // event could legitimately carry is one past them. Anything beyond that is a real drop.
        const uint64_t expected = m_lastGlobalSequence + 1 + event.suppressedBeforeGlobal;

        if (event.globalSequence > expected)
        {
            m_estimatedDrops += event.globalSequence - expected;
            m_gapCount++;
            taint |= TaintReason::kKernelSequenceGap;
        }
        else if (event.globalSequence <= m_lastGlobalSequence)
        {
            // Out-of-order or repeated delivery. The fence protocol relies on the serial handler
            // queue delivering messages in global sequence order, so this invalidates the fence.
            m_gapCount++;
            taint |= TaintReason::kKernelSequenceGap;
        }

        m_suppressedAccountedFor += event.suppressedBeforeGlobal;
    }

    // Independent per-event-type cross-check.
    const uint16_t typeKey = static_cast<uint16_t>(event.op);
    auto lastForType = m_lastTypeSequence.find(typeKey);
    if (lastForType != m_lastTypeSequence.end())
    {
        const uint64_t expectedForType = lastForType->second + 1 + event.suppressedBeforeType;
        if (event.typeSequence > expectedForType)
        {
            m_estimatedDrops += event.typeSequence - expectedForType;
            m_gapCount++;
            taint |= TaintReason::kKernelSequenceGap;
        }
    }

    m_lastTypeSequence[typeKey] = event.typeSequence;
    m_lastGlobalSequence = event.globalSequence;
    m_observedCount++;

    return taint;
}

void SequenceTracker::ResetForNewEpoch(uint64_t newEpoch)
{
    m_currentEpoch = newEpoch;
    m_epochInitialized = true;
    m_lastGlobalSequence = 0;
    m_lastTypeSequence.clear();
    m_observedCount = 0;
}

} // namespace macos
} // namespace buildxl
