// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "ReportReader.h"
#include "ReportSink.h"
#include "ReportType.h"

namespace buildxl {
namespace macos {
namespace testing {

namespace {

std::vector<std::string> Split(const std::string &value, char separator, size_t maxFields)
{
    std::vector<std::string> fields;
    std::string current;
    for (char c : value)
    {
        if (c == separator && fields.size() + 1 < maxFields)
        {
            fields.push_back(current);
            current.clear();
        }
        else
        {
            current += c;
        }
    }

    fields.push_back(current);
    return fields;
}

} // namespace

ReportReader::ReportReader(int fd) : m_fd(fd) {}

ReportReader::~ReportReader()
{
    Join();
    if (m_fd >= 0)
    {
        close(m_fd);
        m_fd = -1;
    }
}

void ReportReader::Start()
{
    m_thread = std::thread([this] { ReadLoop(); });
}

void ReportReader::Join()
{
    if (m_thread.joinable())
    {
        m_thread.join();
    }
}

bool ReportReader::ReadExactly(void *buffer, size_t length)
{
    size_t total = 0;
    char *cursor = static_cast<char *>(buffer);
    while (total < length)
    {
        const ssize_t result = read(m_fd, cursor + total, length - total);
        if (result == 0)
        {
            return false;
        }

        if (result < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            return false;
        }

        total += static_cast<size_t>(result);
        m_bytesRead += static_cast<uint64_t>(result);
    }

    return true;
}

void ReportReader::ReadLoop()
{
    while (true)
    {
        int32_t prefix = 0;
        if (!ReadExactly(&prefix, sizeof(prefix)))
        {
            return;
        }

        // Sentinels occupy the length slot, which is why they must be checked before the value is
        // interpreted as a size.
        if (prefix == ReportSink::kNoActiveProcessesSentinel)
        {
            m_sawNoActiveProcesses = true;
            continue;
        }

        if (prefix == ReportSink::kEndOfReportsSentinel)
        {
            m_sawEndOfReports = true;
            continue;
        }

        if (prefix <= 0 || prefix > static_cast<int32_t>(ReportSink::kMaxReportLength))
        {
            m_sawMalformed = true;
            return;
        }

        std::string body(static_cast<size_t>(prefix), '\0');
        if (!ReadExactly(&body[0], static_cast<size_t>(prefix)))
        {
            m_sawMalformed = true;
            return;
        }

        Decode(body);
    }
}

void ReportReader::Decode(const std::string &body)
{
    if (body.empty() || body.back() != '\n')
    {
        m_sawMalformed = true;
        return;
    }

    const std::string trimmed = body.substr(0, body.size() - 1);
    const size_t firstSeparator = trimmed.find('|');
    if (firstSeparator == std::string::npos)
    {
        m_sawMalformed = true;
        return;
    }

    ParsedReport report;
    report.reportType = std::atoi(trimmed.substr(0, firstSeparator).c_str());

    if (report.reportType == static_cast<int>(buildxl::common::ReportType::kDebugMessage))
    {
        const std::vector<std::string> fields = Split(trimmed, '|', 4);
        if (fields.size() != 4)
        {
            m_sawMalformed = true;
            return;
        }

        report.pid = std::atoi(fields[1].c_str());
        report.severity = std::atoi(fields[2].c_str());
        report.message = fields[3];

        if (report.severity == static_cast<int>(buildxl::linux::DebugEventSeverity::kWarning))
        {
            m_sawWarningDebugMessage = true;
        }

        if (report.severity == static_cast<int>(buildxl::linux::DebugEventSeverity::kError))
        {
            m_sawErrorDebugMessage = true;
        }

        m_reports.push_back(std::move(report));
        return;
    }

    if (report.reportType != static_cast<int>(buildxl::common::ReportType::kFileAccess))
    {
        m_sawMalformed = true;
        return;
    }

    // Exec reports carry a trailing command line; everything else stops at the path. Splitting with
    // a cap of 13 keeps any '|' inside a command line attached to the command line field.
    const std::vector<std::string> fields = Split(trimmed, '|', 13);
    if (fields.size() < 12)
    {
        m_sawMalformed = true;
        return;
    }

    report.systemCall = fields[1];
    report.fileOperation = std::atoi(fields[2].c_str());
    report.pid = std::atoi(fields[3].c_str());
    report.parentPid = std::atoi(fields[4].c_str());
    report.error = std::atoi(fields[5].c_str());
    report.requestedAccess = static_cast<unsigned int>(std::strtoul(fields[6].c_str(), nullptr, 10));
    report.fileAccessStatus = std::atoi(fields[7].c_str());
    report.explicitReport = fields[8] == "1";
    report.isDirectory = fields[9] == "1";
    report.isPathTruncated = fields[10] == "1";
    report.path = fields[11];
    if (fields.size() > 12)
    {
        report.commandLine = fields[12];
    }

    if (!report.path.empty())
    {
        m_reportedAccesses.insert({report.pid, report.path});
    }

    m_reports.push_back(std::move(report));
}

} // namespace testing
} // namespace macos
} // namespace buildxl
