// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_REPLAY_SOURCE_H
#define BUILDXL_SANDBOX_MACOS_REPLAY_SOURCE_H

#include <cstdint>
#include <string>
#include <vector>

#include "EventSource.h"

namespace buildxl {
namespace macos {

/**
 * Faults the replay source can inject.
 *
 * Each one models a real way the Endpoint Security stream can betray us. They exist so the claim
 * "the broker never silently loses an access" can be *tested* rather than asserted.
 */
struct FaultScript
{
    /** Drop this many events outright, leaving global_seq_num gaps. Indices are chosen by seed. */
    uint32_t dropCount = 0;

    /** Drop a contiguous run at the very end of the stream, after the closing marker was emitted. */
    bool dropTail = false;

    /** Deliver events beyond the queue capacity in a burst, forcing enqueue rejection. */
    bool floodQueue = false;

    /** Restart global_seq_num partway through, as a recreated client would. */
    bool changeEpoch = false;

    /** Suppress the marker event so the fence never closes. */
    bool loseMarker = false;

    /** Report a message version newer than the broker knows. Benign: ES versioning is additive. */
    bool unknownVersion = false;

    /** Report a message version too old to carry global_seq_num, which makes loss undetectable. */
    bool staleVersion = false;

    /** Emit an event attributed to a process outside the tracked lineage. */
    bool unmappedLineage = false;

    /** Emit an operation the translator cannot model. */
    bool unsupportedOperation = false;

    /**
     * Emit a delegation to a service the operating system does not own - the shape of a pip talking
     * to its own daemon, which must taint.
     */
    bool escapingDelegation = false;

    /** Truncate a path so it cannot be matched against the manifest. */
    bool truncatePath = false;

    /** Never deliver the exit event for one live process. */
    bool loseExit = false;

    /** Seed for choosing which events the numeric faults hit. */
    uint64_t seed = 0;

    bool Any() const
    {
        // escapingDelegation is listed; the benign delegations are not faults at all and are
        // emitted by every corpus, because every real macOS process makes them.
        return dropCount > 0 || dropTail || floodQueue || changeEpoch || loseMarker || staleVersion
            || unmappedLineage || unsupportedOperation || truncatePath || loseExit || escapingDelegation;
    }
};

/**
 * Replays a fixed event list, optionally corrupting it on the way through.
 *
 * The corpus is delivered on a dedicated thread so the engine sees the same producer/consumer
 * split it sees with a real ES dispatch queue - the queue-overflow path is unreachable otherwise.
 */
class ReplaySource : public EventSource
{
public:
    ReplaySource(std::vector<NormalizedEvent> corpus, FaultScript faults, ProcessIdentity brokerIdentity);
    ~ReplaySource() override;

    bool Start(EventHandler handler, std::string &errorMessage) override;
    void Stop() override;
    bool EmitMarker(const std::string &noncePath) override;

    /**
     * Hands the corpus to the engine. Represents the observed process tree doing its work, so it
     * belongs between the baseline fence and the closing fence, exactly where a real pip runs.
     */
    void DeliverCorpus();
    ProcessIdentity BrokerIdentity() const override { return m_brokerIdentity; }
    const char *BackendName() const override { return "replay"; }

    /** Events the script deliberately withheld. Ground truth for "did the broker notice?". */
    const std::vector<NormalizedEvent> &SuppressedEvents() const { return m_suppressed; }

    /** Events actually handed to the engine. */
    uint64_t DeliveredCount() const { return m_delivered; }

    /** Serializes a corpus so a failing selftest run can be replayed byte-for-byte. */
    static bool WriteCorpus(const std::string &path, const std::vector<NormalizedEvent> &corpus);
    static bool ReadCorpus(const std::string &path, std::vector<NormalizedEvent> &corpus, std::string &errorMessage);

private:

    std::vector<NormalizedEvent> m_corpus;
    std::vector<NormalizedEvent> m_suppressed;
    const FaultScript m_faults;
    const ProcessIdentity m_brokerIdentity;

    EventHandler m_handler;
    uint64_t m_delivered = 0;
    uint64_t m_nextSequence = 1;
    uint64_t m_epoch = 1;
    bool m_started = false;
    bool m_baselineEmitted = false;
    bool m_corpusDelivered = false;
};

/** Parameters for the synthetic build trace the conformance harness runs against. */
struct CorpusShape
{
    uint32_t processCount = 24;
    uint32_t maxDepth = 4;
    uint32_t accessesPerProcess = 40;
    uint32_t distinctPaths = 200;
    uint64_t seed = 1;

    /** Root of the synthetic source tree; must be inside the manifest. */
    std::string sourceRoot = "/tmp/bxl-selftest/src";

    /** Root of the synthetic output tree. */
    std::string outputRoot = "/tmp/bxl-selftest/out";
};

/**
 * One expected observation, used to check that nothing was silently skipped.
 * Reported in the same terms the broker reports, so comparison needs no interpretation.
 */
struct ExpectedAccess
{
    int32_t pid = 0;
    NormOp op = NormOp::kUnknown;
    std::string path;

    bool operator<(const ExpectedAccess &other) const
    {
        if (pid != other.pid) { return pid < other.pid; }
        if (op != other.op) { return op < other.op; }
        return path < other.path;
    }
};

/**
 * Builds a causally consistent process tree and access stream.
 *
 * "Causally consistent" is the important part: forks precede any event from the child, execs precede
 * the child's file accesses, and exits come last. A corpus that violated causality would let the
 * broker pass by accident.
 */
std::vector<NormalizedEvent> GenerateCorpus(
    const CorpusShape &shape,
    ProcessIdentity root,
    std::vector<ExpectedAccess> &expectedAccesses);

} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_REPLAY_SOURCE_H
