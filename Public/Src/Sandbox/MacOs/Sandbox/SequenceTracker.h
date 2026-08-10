// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_SEQUENCE_TRACKER_H
#define BUILDXL_SANDBOX_MACOS_SEQUENCE_TRACKER_H

#include <cstdint>
#include <unordered_map>

#include "NormalizedEvent.h"
#include "Taint.h"

namespace buildxl {
namespace macos {

/**
 * Tracks Endpoint Security sequence numbers and turns any discontinuity into a taint.
 *
 * Two independent signals are used:
 *  - global_seq_num: per-client, increments by exactly 1 per delivered message.
 *  - seq_num:        per-client per-event-type, increments by exactly 1 per delivered message of
 *                    that type.
 *
 * Both are checked. The per-type counter catches the case where a whole run of consecutive messages
 * of one type is dropped in a way that a naive reader of only the global counter could rationalize.
 * The message version is also validated: global_seq_num only exists from version 4 onwards, so an
 * older message version means gap detection is not possible at all and must taint.
 *
 * This class is not thread safe; it is owned by the single drain thread.
 */
class SequenceTracker
{
public:
    /** Minimum ES message version that carries global_seq_num. */
    static constexpr uint32_t kMinimumSupportedMessageVersion = 4;

    /**
     * Maximum ES message version the broker knows how to read. Newer messages are still processed
     * (ES guarantees older fields keep their meaning) but the broker records that it saw one.
     */
    static constexpr uint32_t kMaximumKnownMessageVersion = 11;

    /**
     * Observes one event.
     *
     * @param event the event, already copied out of kernel memory
     * @return the taint incurred by this observation, or kNone
     */
    TaintReason Observe(const NormalizedEvent &event);

    /** Total number of messages the kernel reported as dropped, derived from sequence deltas. */
    uint64_t EstimatedDroppedMessages() const { return m_estimatedDrops; }

    /** How many distinct discontinuities were seen. */
    uint64_t GapCount() const { return m_gapCount; }

    /** Number of messages accepted. */
    uint64_t ObservedCount() const { return m_observedCount; }

    /** Highest global sequence number processed so far. */
    uint64_t HighestGlobalSequence() const { return m_lastGlobalSequence; }

    /** Whether any event has been observed yet. */
    bool HasObservedAny() const { return m_observedCount > 0; }

    /** The client epoch of the most recent event. */
    uint64_t CurrentEpoch() const { return m_currentEpoch; }

    /** Number of messages seen with a version newer than kMaximumKnownMessageVersion. */
    uint64_t NewerVersionCount() const { return m_newerVersionCount; }

    /**
     * Events whose sequence was assigned in user space rather than by the kernel, and for which this
     * tracker therefore made no loss claim at all. Non-zero means loss detection for those events
     * lives in the ingress, not here.
     */
    uint64_t UserSpaceSequencedCount() const { return m_userSpaceSequencedCount; }

    /**
     * Messages the ingress withheld that were accounted for rather than counted as drops.
     *
     * Reported in the evidence so that "no gaps" can be distinguished from "gaps explained away":
     * if this number is implausible relative to ObservedCount(), the suppression rule is wrong.
     */
    uint64_t SuppressedAccountedFor() const { return m_suppressedAccountedFor; }

    /**
     * Resets the per-epoch state. The caller is responsible for having already tainted the pip;
     * this only makes subsequent gap detection meaningful again.
     */
    void ResetForNewEpoch(uint64_t newEpoch);

private:
    uint64_t m_lastGlobalSequence = 0;
    std::unordered_map<uint16_t, uint64_t> m_lastTypeSequence;
    uint64_t m_estimatedDrops = 0;
    uint64_t m_gapCount = 0;
    uint64_t m_observedCount = 0;
    uint64_t m_currentEpoch = 0;
    uint64_t m_newerVersionCount = 0;
    uint64_t m_userSpaceSequencedCount = 0;
    uint64_t m_suppressedAccountedFor = 0;
    bool m_epochInitialized = false;
};

} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_SEQUENCE_TRACKER_H
