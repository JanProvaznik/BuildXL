// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_REPORT_SINK_H
#define BUILDXL_SANDBOX_MACOS_REPORT_SINK_H

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "Operations.h"
#include "SandboxEvent.h"
#include "Taint.h"

namespace buildxl {
namespace macos {

/**
 * Writes access reports to the per-pip FIFO in the exact format the managed side already parses.
 *
 * The wire format is deliberately identical to the Linux sandbox's:
 *
 *   <uint32 length><ReportType>|<syscall>|<FileOperation>|<pid>|<ppid>|<error>
 *       |<requestedAccess>|<fileAccessStatus>|<explicitReport>|<isDirectory>|<isTruncated>|<path>[|<cmdline>]\n
 *
 * CODESYNC: Public/Src/Sandbox/Linux/ReportBuilder.cpp
 * CODESYNC: Public/Src/Engine/Processes/SandboxConnectionMacOs.cs
 *
 * Matching the format byte for byte is what makes macOS reach parity with Linux by construction:
 * every downstream consumer (FileAccessManifest interpretation, observed input processing, cache
 * fingerprinting) is shared, not reimplemented.
 */
class ReportSink
{
public:
    /**
     * Sentinel written in place of a length prefix to tell the managed reader that no active
     * processes remain but late start-process reports may still arrive.
     * CODESYNC: Public/Src/Engine/Processes/SandboxConnectionMacOs.cs (NoActiveProcessesSentinel)
     */
    static constexpr int32_t kNoActiveProcessesSentinel = -21;

    /**
     * Sentinel written in place of a length prefix to tell the managed reader that the report stream
     * is complete.
     * CODESYNC: Public/Src/Engine/Processes/SandboxConnectionMacOs.cs (EndOfReportsSentinel)
     */
    static constexpr int32_t kEndOfReportsSentinel = -22;

    /** Maximum size of a single report, including the length prefix. */
    static constexpr unsigned int kMaxReportLength = 64 * 1024;

    ReportSink() = default;
    ~ReportSink();

    ReportSink(const ReportSink &) = delete;
    ReportSink &operator=(const ReportSink &) = delete;

    /** Opens the FIFO for writing. Returns false and sets errorMessage on failure. */
    bool Open(const std::string &fifoPath, std::string &errorMessage);

    /** Takes ownership of an already-open descriptor. Used by tests to write into a pipe. */
    bool AttachFd(int fd);

    /**
     * Writes the source (and, when present, destination) access reports for a sandbox event.
     * Returns the taint incurred: kPathTruncated when a path had to be shortened,
     * kReportSinkFailure when the write itself failed.
     */
    TaintReason WriteSandboxEvent(buildxl::linux::SandboxEvent &event);

    /**
     * Writes a debug/infrastructure message.
     *
     * A message with kError severity is the mechanism by which the broker refuses to let a pip
     * produce a cacheable result; see SandboxedProcessUnix.HandleAccessReport.
     */
    bool WriteDebugMessage(buildxl::linux::DebugEventSeverity severity, int32_t pid, const std::string &message);

    /** Writes a taint as an error-severity debug message, so the pip cannot be cached. */
    bool WriteTaint(TaintReason taint, int32_t pid, const std::string &context);

    /** Writes one of the stream sentinels. */
    bool WriteSentinel(int32_t sentinel);

    /**
     * Pushes buffered reports to the FIFO. The drain thread calls this once per batch: a report is
     * only useful to managed code once it is readable, but paying a syscall per access halves
     * throughput for no benefit.
     */
    bool Flush();

    void Close();

    uint64_t ReportsWritten() const { return m_reportsWritten; }
    uint64_t TruncatedPaths() const { return m_truncatedPaths; }
    uint64_t WriteFailures() const { return m_writeFailures; }

    /** Largest amount of report bytes held before an implicit flush. */
    static constexpr size_t kFlushThreshold = 1 << 16;

private:
    bool WriteRaw(const char *buffer, size_t length);
    bool FlushLocked();
    static bool IsPathTruncated(const char *buffer, unsigned int reportLength);
    TaintReason WriteOneReport(buildxl::linux::SandboxEvent &event, const buildxl::linux::AccessReport &report);

    std::mutex m_mutex;
    std::vector<char> m_scratch;
    std::vector<char> m_pending;

    /**
     * Set once the sink is closing, which makes FlushLocked block until everything is written.
     *
     * During the run a short write is kept buffered rather than waited on, because the drain thread
     * that calls this is also the only consumer of the event queue. At close there is no queue left
     * to protect and a dropped report is a missing cache-key input, so the trade reverses.
     */
    bool m_drainingToClose = false;
    int m_fd = -1;
    uint64_t m_reportsWritten = 0;
    uint64_t m_truncatedPaths = 0;
    uint64_t m_writeFailures = 0;
};

} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_REPORT_SINK_H
