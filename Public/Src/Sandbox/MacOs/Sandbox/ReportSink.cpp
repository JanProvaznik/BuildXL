// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <stdlib.h>
#include <string>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <vector>

#include "ReportBuilder.h"
#include "ReportSink.h"
#include "ReportType.h"

namespace buildxl {
namespace macos {

namespace {

/**
 * Diagnostic tee. When __BUILDXL_MACOS_REPORT_TEE names a file, every report this broker writes to
 * the managed reader is also appended there in its wire form. The managed side only ever surfaces
 * the *conclusions* it drew from a report, so when a build disagrees with a standalone repro this is
 * the only way to see what was actually sent. Off unless the variable is set.
 *
 * Deliberately env-var only. An earlier revision also honoured a well-known marker file, because the
 * engine does not forward its own environment to the broker and a marker was the only way to arm
 * this for a whole build. That is a backdoor: any process on the machine could turn it on, and the
 * write it then performs is undeclared, so it fails the very pip it is meant to diagnose. To capture
 * a whole build, put the variable in the pip's declared environment, or drive the broker directly.
 */
void TeeReport(const char *buffer, unsigned int length)
{
    static int s_teeFd = [] {
        const char *path = getenv("__BUILDXL_MACOS_REPORT_TEE");
        return path != nullptr ? open(path, O_WRONLY | O_CREAT | O_APPEND, 0644) : -1;
    }();

    if (s_teeFd < 0 || length <= sizeof(uint32_t))
    {
        return;
    }

    // Skip the length prefix; append a newline so the file is greppable.
    std::string line(buffer + sizeof(uint32_t), length - sizeof(uint32_t));
    line.push_back('\n');
    (void)write(s_teeFd, line.data(), line.size());
}

} // anonymous namespace

ReportSink::~ReportSink()
{
    Close();
}

bool ReportSink::Open(const std::string &fifoPath, std::string &errorMessage)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // Blocking open: the managed side creates the FIFO and opens the read end before launching the
    // broker, so this returns as soon as the reader is present.
    int fd = open(fifoPath.c_str(), O_WRONLY);
    if (fd < 0)
    {
        errorMessage = "Failed to open report FIFO '" + fifoPath + "': " + strerror(errno);
        return false;
    }

    m_fd = fd;
    return true;
}

void ReportSink::Close()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // Everything buffered has to reach the reader before the descriptor goes away, so the deliberate
    // non-blocking behaviour of FlushLocked is switched off here. This is the one place where
    // blocking is correct: the observed process has finished, so there is no event queue left to
    // stall, and a report dropped at this point is a missing dependency in the pip's cache key.
    m_drainingToClose = true;

    if (m_fd >= 0)
    {
        const int flags = fcntl(m_fd, F_GETFL, 0);
        if (flags >= 0)
        {
            (void)fcntl(m_fd, F_SETFL, flags & ~O_NONBLOCK);
        }
    }

    FlushLocked();
    if (m_fd >= 0)
    {
        close(m_fd);
        m_fd = -1;
    }
}

bool ReportSink::AttachFd(int fd)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_fd >= 0 || fd < 0)
    {
        return false;
    }

    // Non-blocking, so a reader that falls behind cannot stall the drain thread. See FlushLocked.
    // A failure here is not fatal: the descriptor simply stays blocking, which is the old behaviour.
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
    {
        (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    m_fd = fd;
    return true;
}

bool ReportSink::IsPathTruncated(const char *buffer, unsigned int reportLength)
{
    // Field 11 (zero-based index 10) of every report is the truncation flag. Reading it back is the
    // only way to know what ReportBuilder decided: it shortens the path internally and nothing else
    // in the return value distinguishes that from a report that happened to be long.
    const size_t prefixLength = sizeof(unsigned int);
    if (reportLength <= prefixLength)
    {
        return false;
    }

    const char *body = buffer + prefixLength;
    const size_t bodyLength = reportLength - prefixLength;

    size_t separators = 0;
    for (size_t i = 0; i < bodyLength; i++)
    {
        if (body[i] != '|')
        {
            continue;
        }

        separators++;
        if (separators == 10)
        {
            return i + 1 < bodyLength && body[i + 1] == '1';
        }
    }

    return false;
}

bool ReportSink::WriteRaw(const char *buffer, size_t length)
{
    if (m_fd < 0)
    {
        return false;
    }

    m_pending.insert(m_pending.end(), buffer, buffer + length);
    if (m_pending.size() < kFlushThreshold)
    {
        return true;
    }

    return FlushLocked();
}

bool ReportSink::Flush()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return FlushLocked();
}

bool ReportSink::FlushLocked()
{
    if (m_fd < 0 || m_pending.empty())
    {
        return m_fd >= 0;
    }

    const char *buffer = m_pending.data();
    const size_t length = m_pending.size();

    size_t written = 0;
    while (written < length)
    {
        ssize_t result = write(m_fd, buffer + written, length - written);
        if (result < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            if ((errno == EAGAIN || errno == EWOULDBLOCK) && !m_drainingToClose)
            {
                // The reader is behind. Keeping the rest buffered and returning is the whole point:
                // this runs on the drain thread, which is also the only consumer of the event queue,
                // so blocking here stalls that queue until the delivery thread gives up and taints
                // the pip. The reports are not lost - they stay in m_pending and go out on the next
                // flush, or at close, where the descriptor is put back into blocking mode so nothing
                // is dropped.
                m_pending.erase(m_pending.begin(), m_pending.begin() + static_cast<ptrdiff_t>(written));
                return true;
            }

            m_writeFailures++;
            m_pending.clear();
            return false;
        }

        written += static_cast<size_t>(result);
    }

    m_pending.clear();
    return true;
}

TaintReason ReportSink::WriteOneReport(buildxl::linux::SandboxEvent &event, const buildxl::linux::AccessReport &report)
{
    // Reused across reports. Allocating the maximum report size per access showed up as the single
    // largest cost in the throughput benchmark; the caller already holds m_mutex, so a member buffer
    // is safe here.
    if (m_scratch.size() != kMaxReportLength)
    {
        m_scratch.resize(kMaxReportLength);
    }

    std::vector<char> &buffer = m_scratch;
    unsigned int reportLength = 0;

    // ReportBuilder writes the length prefix and shortens the path if the report does not fit.
    if (!buildxl::linux::ReportBuilder::SandboxEventReportString(
            event, report, buffer.data(), kMaxReportLength, reportLength))
    {
        m_writeFailures++;
        return TaintReason::kReportSinkFailure;
    }

    TeeReport(buffer.data(), reportLength);

    if (!WriteRaw(buffer.data(), reportLength))
    {
        return TaintReason::kReportSinkFailure;
    }

    m_reportsWritten++;

    if (IsPathTruncated(buffer.data(), reportLength))
    {
        m_truncatedPaths++;
        return TaintReason::kPathTruncated;
    }

    return TaintReason::kNone;
}

TaintReason ReportSink::WriteSandboxEvent(buildxl::linux::SandboxEvent &event)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    TaintReason taint = TaintReason::kNone;

    const buildxl::linux::AccessReport source = event.GetSourceAccessReport();
    if (source.file_operation != buildxl::linux::FileOperation::kMax)
    {
        taint |= WriteOneReport(event, source);
    }

    const buildxl::linux::AccessReport destination = event.GetDestinationAccessReport();
    if (!destination.path.empty() && destination.file_operation != buildxl::linux::FileOperation::kMax)
    {
        taint |= WriteOneReport(event, destination);
    }

    event.Seal();
    return taint;
}

bool ReportSink::WriteDebugMessage(buildxl::linux::DebugEventSeverity severity, int32_t pid, const std::string &message)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_scratch.size() != kMaxReportLength)
    {
        m_scratch.resize(kMaxReportLength);
    }

    std::vector<char> &buffer = m_scratch;
    int totalLength = buildxl::linux::ReportBuilder::DebugReportReportString(
        severity, static_cast<pid_t>(pid), message.c_str(), buffer.data(), kMaxReportLength);

    if (totalLength <= 0)
    {
        m_writeFailures++;
        return false;
    }

    return WriteRaw(buffer.data(), static_cast<size_t>(totalLength));
}

bool ReportSink::WriteTaint(TaintReason taint, int32_t pid, const std::string &context)
{
    if (!IsTainted(taint))
    {
        return true;
    }

    const std::string message =
        "[macOS sandbox] The observed file access stream for this pip is incomplete or ambiguous "
        "(" + TaintSetToString(taint) + "). The pip cannot be cached from this execution. Context: " + context;

    return WriteDebugMessage(buildxl::linux::DebugEventSeverity::kError, pid, message);
}

bool ReportSink::WriteSentinel(int32_t sentinel)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    // Sentinels are what unblocks the managed reader, so they are never left sitting in the buffer.
    return WriteRaw(reinterpret_cast<const char *>(&sentinel), sizeof(sentinel)) && FlushLocked();
}

} // namespace macos
} // namespace buildxl
