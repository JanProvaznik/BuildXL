// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_TEST_REPORT_READER_H
#define BUILDXL_SANDBOX_MACOS_TEST_REPORT_READER_H

#include <cstdint>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace buildxl {
namespace macos {
namespace testing {

/** One decoded report from the FIFO. */
struct ParsedReport
{
    int reportType = 0;
    std::string systemCall;
    int fileOperation = 0;
    int pid = 0;
    int parentPid = 0;
    int error = 0;
    unsigned int requestedAccess = 0;
    int fileAccessStatus = 0;
    bool explicitReport = false;
    bool isDirectory = false;
    bool isPathTruncated = false;
    std::string path;
    std::string commandLine;

    // Debug messages reuse the same envelope with a different body.
    int severity = 0;
    std::string message;
};

/**
 * Reads and decodes the report stream on a background thread.
 *
 * Decoding here is written against the wire format rather than against the writer, so a change to
 * either side that breaks the contract shows up as a test failure instead of silently agreeing.
 */
class ReportReader
{
public:
    /** Takes ownership of the read end. */
    explicit ReportReader(int fd);
    ~ReportReader();

    void Start();

    /** Waits for the writer to close and the stream to drain. */
    void Join();

    const std::vector<ParsedReport> &Reports() const { return m_reports; }

    /** (pid, path) pairs seen in file-access reports. */
    const std::set<std::pair<int, std::string>> &ReportedAccesses() const { return m_reportedAccesses; }

    bool SawErrorDebugMessage() const { return m_sawErrorDebugMessage; }

    bool SawWarningDebugMessage() const { return m_sawWarningDebugMessage; }
    bool SawNoActiveProcessesSentinel() const { return m_sawNoActiveProcesses; }
    bool SawEndOfReportsSentinel() const { return m_sawEndOfReports; }
    bool SawMalformedReport() const { return m_sawMalformed; }
    uint64_t BytesRead() const { return m_bytesRead; }

private:
    void ReadLoop();
    bool ReadExactly(void *buffer, size_t length);
    void Decode(const std::string &body);

    int m_fd;
    std::thread m_thread;
    std::vector<ParsedReport> m_reports;
    std::set<std::pair<int, std::string>> m_reportedAccesses;
    bool m_sawErrorDebugMessage = false;
    bool m_sawWarningDebugMessage = false;
    bool m_sawNoActiveProcesses = false;
    bool m_sawEndOfReports = false;
    bool m_sawMalformed = false;
    uint64_t m_bytesRead = 0;
};

} // namespace testing
} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_TEST_REPORT_READER_H
