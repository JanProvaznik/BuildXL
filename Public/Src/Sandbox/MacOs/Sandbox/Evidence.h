// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_EVIDENCE_H
#define BUILDXL_SANDBOX_MACOS_EVIDENCE_H

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include "NormalizedEvent.h"
#include "Taint.h"

namespace buildxl {
namespace macos {

/**
 * One observation record.
 *
 * The schema is deliberately backend-neutral and self-describing so that a run recorded under the
 * replay backend and a run recorded under Endpoint Security can be diffed directly. Comparing them
 * is the only way to tell an ingress bug from a protocol bug.
 */
struct EvidenceRecord
{
    uint64_t eventSequence = 0;
    ProcessIdentity processIdentity;
    ProcessIdentity parentIdentity;
    const char *operationClass = "";
    const char *sourceEventType = "";
    std::string lexicalPath;
    std::string resolvedFileIdentity;
    const char *requestedAccess = "";
    const char *resultClass = "";
    uint64_t timestampNanos = 0;
    TaintReason taint = TaintReason::kNone;
};

/** Summary of a whole run, emitted once as the final record. */
struct EvidenceSummary
{
    uint64_t eventsAccepted = 0;
    uint64_t eventsProcessed = 0;
    uint64_t eventsRejected = 0;
    uint64_t reportsWritten = 0;
    uint64_t sequenceGaps = 0;
    uint64_t estimatedKernelDrops = 0;
    uint64_t unmappedLineageEvents = 0;
    uint64_t foreignProcessEvents = 0;
    uint64_t queueHighWaterMark = 0;
    uint64_t queueCapacity = 0;
    uint64_t callbackNanosMax = 0;
    uint64_t callbackNanosP50 = 0;
    uint64_t callbackNanosP95 = 0;
    uint64_t callbackNanosP99 = 0;
    uint64_t callbackNanosP999 = 0;
    uint64_t fenceLatencyNanos = 0;
    uint64_t wallClockNanos = 0;
    uint64_t peakResidentBytes = 0;
    uint32_t markerAttempts = 0;
    uint32_t processCount = 0;
    bool fenceClosed = false;
    bool supervisionQuiesced = false;
    bool lifecycleClosed = false;

    /**
     * Losses the observation backend detected in its own transport, which the sequence tracker cannot
     * see. Zero for Endpoint Security, where the kernel sequence is the only loss signal.
     */
    uint64_t backendReportedLosses = 0;

    /** Events delivered before the engine was published. Expected to be zero; recorded so it is checkable. */
    uint64_t eventsDroppedBeforeEngineStart = 0;
    TaintReason taint = TaintReason::kNone;
    int32_t childExitCode = 0;
};

/**
 * Append-only JSONL writer.
 *
 * Writing is best-effort by design: evidence is diagnostic, and a full disk must never be able to
 * change a build's correctness verdict. Failures are counted and surfaced, not escalated.
 */
class EvidenceWriter
{
public:
    EvidenceWriter() = default;

    EvidenceWriter(const EvidenceWriter &) = delete;
    EvidenceWriter &operator=(const EvidenceWriter &) = delete;

    /** Opens the sink. An empty path disables evidence entirely and always succeeds. */
    bool Open(const std::string &path, std::string runId, std::string pipId, std::string backend);

    bool IsEnabled() const { return m_stream.is_open(); }

    void WriteObservation(const EvidenceRecord &record);
    void WriteSummary(const EvidenceSummary &summary);
    void WriteNote(const char *category, const std::string &message);

    void Close();

    uint64_t RecordsWritten() const { return m_recordsWritten; }

private:
    void WriteCommonPrefix(const char *recordType);

    std::ofstream m_stream;
    std::string m_runId;
    std::string m_pipId;
    std::string m_backend;
    uint64_t m_recordsWritten = 0;
};

/** Peak resident set size of the current process, or 0 when unavailable. */
uint64_t PeakResidentBytes();

/** Nanosecond percentile over an unsorted sample vector; the vector is sorted in place. */
uint64_t Percentile(std::vector<uint64_t> &samples, double fraction);

/** A run identifier that is unique per process and sorts chronologically. */
std::string NewRunId();

} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_EVIDENCE_H
