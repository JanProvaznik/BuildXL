// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <mach/mach.h>
#include <sys/resource.h>
#include <unistd.h>
#include <vector>

#include "Evidence.h"

namespace buildxl {
namespace macos {

namespace {

std::string Escape(const std::string &value)
{
    std::string result;
    result.reserve(value.size() + 8);
    for (char c : value)
    {
        switch (c)
        {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20)
                {
                    char buffer[8];
                    snprintf(buffer, sizeof(buffer), "\\u%04x", c);
                    result += buffer;
                }
                else
                {
                    result += c;
                }
                break;
        }
    }

    return result;
}

} // namespace

bool EvidenceWriter::Open(const std::string &path, std::string runId, std::string pipId, std::string backend)
{
    m_runId = std::move(runId);
    m_pipId = std::move(pipId);
    m_backend = std::move(backend);

    if (path.empty())
    {
        return true;
    }

    m_stream.open(path, std::ios::out | std::ios::app);
    return m_stream.is_open();
}

void EvidenceWriter::WriteCommonPrefix(const char *recordType)
{
    m_stream << "{\"recordType\":\"" << recordType << "\""
             << ",\"runId\":\"" << Escape(m_runId) << "\""
             << ",\"pipId\":\"" << Escape(m_pipId) << "\""
             << ",\"backend\":\"" << Escape(m_backend) << "\"";
}

void EvidenceWriter::WriteObservation(const EvidenceRecord &record)
{
    if (!m_stream.is_open())
    {
        return;
    }

    WriteCommonPrefix("observation");
    m_stream << ",\"eventSequence\":" << record.eventSequence
             << ",\"processIdentity\":{\"pid\":" << record.processIdentity.pid
             << ",\"pidversion\":" << record.processIdentity.pidversion << "}"
             << ",\"parentIdentity\":{\"pid\":" << record.parentIdentity.pid
             << ",\"pidversion\":" << record.parentIdentity.pidversion << "}"
             << ",\"operationClass\":\"" << record.operationClass << "\""
             << ",\"sourceEventType\":\"" << record.sourceEventType << "\""
             << ",\"lexicalPath\":\"" << Escape(record.lexicalPath) << "\""
             << ",\"resolvedFileIdentity\":\"" << Escape(record.resolvedFileIdentity) << "\""
             << ",\"requestedAccess\":\"" << record.requestedAccess << "\""
             << ",\"resultClass\":\"" << record.resultClass << "\""
             << ",\"timestamp\":" << record.timestampNanos
             << ",\"taintReason\":\"" << Escape(TaintSetToString(record.taint)) << "\""
             << "}\n";

    m_recordsWritten++;
}

void EvidenceWriter::WriteSummary(const EvidenceSummary &summary)
{
    if (!m_stream.is_open())
    {
        return;
    }

    WriteCommonPrefix("summary");
    m_stream << ",\"eventsAccepted\":" << summary.eventsAccepted
             << ",\"eventsProcessed\":" << summary.eventsProcessed
             << ",\"eventsRejected\":" << summary.eventsRejected
             << ",\"reportsWritten\":" << summary.reportsWritten
             << ",\"sequenceGaps\":" << summary.sequenceGaps
             << ",\"estimatedKernelDrops\":" << summary.estimatedKernelDrops
             << ",\"unmappedLineageEvents\":" << summary.unmappedLineageEvents
             << ",\"foreignProcessEvents\":" << summary.foreignProcessEvents
             << ",\"benignDelegations\":" << summary.benignDelegations
             << ",\"delegationEscapes\":" << summary.delegationEscapes
             << ",\"queueHighWaterMark\":" << summary.queueHighWaterMark
             << ",\"queueCapacity\":" << summary.queueCapacity
             << ",\"callbackNanosMax\":" << summary.callbackNanosMax
             << ",\"callbackNanosP50\":" << summary.callbackNanosP50
             << ",\"callbackNanosP95\":" << summary.callbackNanosP95
             << ",\"callbackNanosP99\":" << summary.callbackNanosP99
             << ",\"callbackNanosP999\":" << summary.callbackNanosP999
             << ",\"fenceLatencyNanos\":" << summary.fenceLatencyNanos
             << ",\"wallClockNanos\":" << summary.wallClockNanos
             << ",\"peakResidentBytes\":" << summary.peakResidentBytes
             << ",\"markerAttempts\":" << summary.markerAttempts
             << ",\"processCount\":" << summary.processCount
             << ",\"fenceClosed\":" << (summary.fenceClosed ? "true" : "false")
             << ",\"supervisionQuiesced\":" << (summary.supervisionQuiesced ? "true" : "false")
             << ",\"lifecycleClosed\":" << (summary.lifecycleClosed ? "true" : "false")
             << ",\"backendReportedLosses\":" << summary.backendReportedLosses
             << ",\"eventsDroppedBeforeEngineStart\":" << summary.eventsDroppedBeforeEngineStart
             << ",\"childExitCode\":" << summary.childExitCode
             << ",\"taintReason\":\"" << Escape(TaintSetToString(summary.taint)) << "\""
             << ",\"cacheable\":" << (summary.taint == TaintReason::kNone ? "true" : "false")
             << "}\n";

    m_stream.flush();
    m_recordsWritten++;
}

void EvidenceWriter::WriteNote(const char *category, const std::string &message)
{
    if (!m_stream.is_open())
    {
        return;
    }

    WriteCommonPrefix("note");
    m_stream << ",\"category\":\"" << category << "\""
             << ",\"message\":\"" << Escape(message) << "\""
             << "}\n";

    m_recordsWritten++;
}

void EvidenceWriter::Close()
{
    if (m_stream.is_open())
    {
        m_stream.flush();
        m_stream.close();
    }
}

uint64_t PeakResidentBytes()
{
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0)
    {
        return 0;
    }

    // Darwin reports ru_maxrss in bytes, unlike Linux which reports kilobytes.
    return static_cast<uint64_t>(usage.ru_maxrss);
}

uint64_t Percentile(std::vector<uint64_t> &samples, double fraction)
{
    if (samples.empty())
    {
        return 0;
    }

    std::sort(samples.begin(), samples.end());
    size_t index = static_cast<size_t>(fraction * static_cast<double>(samples.size() - 1) + 0.5);
    if (index >= samples.size())
    {
        index = samples.size() - 1;
    }

    return samples[index];
}

std::string NewRunId()
{
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(now).count();

    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%lld-%d", static_cast<long long>(micros), static_cast<int>(getpid()));
    return std::string(buffer);
}

} // namespace macos
} // namespace buildxl
