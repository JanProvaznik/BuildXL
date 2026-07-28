// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//
// bxl-es-broker: the macOS side of BuildXL's Unix sandbox contract.
//
// BuildXL launches this instead of the pip's own executable:
//
//     bxl-es-broker <tool> [args...]
//
// with __BUILDXL_FAM_PATH pointing at the serialized file access manifest. The broker establishes an
// Endpoint Security descendants client *before* launching the tool, so there is no window in which
// the tool can run unobserved, then reports every access over the same FIFO wire format the Linux
// sandbox uses.
//
// One broker per pip. That costs an Endpoint Security client per concurrent pip, which is the reason
// EsIngress backs off and retries rather than failing, but it buys three things that a shared daemon
// cannot: attribution is exact (the descendants client sees this pip's tree and nothing else), a
// taint is scoped to the pip that caused it, and the process-scoped state in the shared policy code
// means what it means on Linux.
//

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstdarg>
#include <cstring>
#include <memory>
#include <random>
#include <thread>
#include <string>
#include <vector>

#include "EsIngress.h"
#include "Evidence.h"
#include "FileAccessManifest.h"
#include "ReportSink.h"
#include "SandboxEngine.h"

extern char **environ;

using namespace buildxl::macos;

namespace {

constexpr const char *kFamPathEnvVar = "__BUILDXL_FAM_PATH";
constexpr const char *kEvidenceEnvVar = "__BUILDXL_MACOS_EVIDENCE_PATH";
constexpr const char *kSupervisionTimeoutEnvVar = "__BUILDXL_MACOS_SUPERVISION_TIMEOUT_SECONDS";

/** Exit code used when the broker itself fails, distinct from any plausible tool exit code. */
constexpr int kBrokerFailureExitCode = 253;

void Fail(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    fprintf(stderr, "[bxl-es-broker] ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

std::vector<char> ReadWholeFile(const std::string &path, std::string &errorMessage)
{
    std::vector<char> contents;

    FILE *file = fopen(path.c_str(), "rb");
    if (file == nullptr)
    {
        errorMessage = "cannot open '" + path + "': " + strerror(errno);
        return contents;
    }

    char buffer[65536];
    size_t read = 0;
    while ((read = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        contents.insert(contents.end(), buffer, buffer + read);
    }

    fclose(file);
    return contents;
}

std::string MakeNoncePath()
{
    std::random_device device;
    std::mt19937_64 generator(device());

    char buffer[128];
    snprintf(
        buffer,
        sizeof(buffer),
        "/tmp/.bxl-es-fence-%d-%016llx",
        static_cast<int>(getpid()),
        static_cast<unsigned long long>(generator()));

    return std::string(buffer);
}

/**
 * Waits for the observed tree to finish.
 *
 * The root process exiting is not the same thing as the tree finishing: a tool can leave a
 * grandchild running. The broker waits for the root, then reaps anything else still attributed to
 * this process group, then reports whether it reached a genuinely quiescent state. That answer feeds
 * the closure evaluation - a tree that never quiesced cannot be proven complete, so it taints.
 */
bool WaitForTree(pid_t rootPid, std::chrono::seconds timeout, int &exitCode)
{
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    exitCode = kBrokerFailureExitCode;

    int status = 0;
    while (true)
    {
        const pid_t result = waitpid(rootPid, &status, 0);
        if (result == rootPid)
        {
            exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : (128 + WTERMSIG(status));
            break;
        }

        if (result < 0 && errno == EINTR)
        {
            continue;
        }

        if (result < 0)
        {
            return false;
        }
    }

    // Reap any remaining descendants that share the process group. Anything still alive after the
    // timeout means the tree did not quiesce and the stream cannot be proven complete.
    while (std::chrono::steady_clock::now() < deadline)
    {
        const pid_t result = waitpid(-rootPid, &status, WNOHANG);
        if (result > 0)
        {
            continue;
        }

        if (result < 0 && errno == ECHILD)
        {
            return true;
        }

        if (result < 0 && errno == EINTR)
        {
            continue;
        }

        // Nothing reapable right now, but children still exist. Give them a moment.
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    return false;
}

} // namespace

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        Fail("usage: bxl-es-broker <tool> [args...]");
        return kBrokerFailureExitCode;
    }

    const char *famPathRaw = getenv(kFamPathEnvVar);
    if (famPathRaw == nullptr || *famPathRaw == '\0')
    {
        Fail("%s is not set; the broker cannot run without a file access manifest", kFamPathEnvVar);
        return kBrokerFailureExitCode;
    }

    std::string errorMessage;
    std::vector<char> famBytes = ReadWholeFile(famPathRaw, errorMessage);
    if (famBytes.empty())
    {
        Fail("cannot read the file access manifest: %s", errorMessage.c_str());
        return kBrokerFailureExitCode;
    }

    buildxl::common::FileAccessManifest manifest(famBytes.data(), famBytes.size());

    int reportPathLength = 0;
    const char *reportPath = manifest.GetReportsPath(&reportPathLength);
    if (reportPath == nullptr || reportPathLength <= 0)
    {
        Fail("the file access manifest at '%s' does not name a report path", famPathRaw);
        return kBrokerFailureExitCode;
    }

    ReportSink sink;
    if (!sink.Open(std::string(reportPath), errorMessage))
    {
        Fail("cannot open the report FIFO: %s", errorMessage.c_str());
        return kBrokerFailureExitCode;
    }

    EsIngress ingress;
    const std::string noncePath = MakeNoncePath();

    SandboxEngine engine(
        &manifest,
        &sink,
        ingress.BrokerIdentity(),
        noncePath,
        [&ingress](const std::string &nonce) { return ingress.EmitMarker(nonce); },
        EngineOptions());

    engine.Start();

    // Subscribing before the tool exists is what makes the observation gap-free: a descendants client
    // created now sees every process forked from here on, so there is no interval during which the
    // tool could touch a file unobserved.
    if (!ingress.Start([&engine](NormalizedEvent &&event) { engine.OnEvent(std::move(event)); }, errorMessage))
    {
        Fail("%s", errorMessage.c_str());
        sink.WriteDebugMessage(
            buildxl::linux::DebugEventSeverity::kError,
            static_cast<int32_t>(getpid()),
            std::string("macOS sandbox could not start: ") + errorMessage);
        sink.WriteSentinel(ReportSink::kNoActiveProcessesSentinel);
        sink.WriteSentinel(ReportSink::kEndOfReportsSentinel);
        sink.Close();
        return kBrokerFailureExitCode;
    }

    // The baseline fence proves the client is live and delivering before anything is launched. If the
    // subscription silently did nothing, this is where it is caught - not after the pip has run.
    if (!engine.EstablishBaseline())
    {
        Fail("the Endpoint Security stream did not deliver the baseline marker");
    }

    // Own process group, so the whole tree can be waited on and signalled as a unit.
    posix_spawnattr_t attributes;
    posix_spawnattr_init(&attributes);
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP);
    posix_spawnattr_setpgroup(&attributes, 0);

    pid_t childPid = -1;
    const int spawnResult = posix_spawnp(&childPid, argv[1], nullptr, &attributes, &argv[1], environ);
    posix_spawnattr_destroy(&attributes);

    if (spawnResult != 0)
    {
        Fail("cannot launch '%s': %s", argv[1], strerror(spawnResult));
        engine.Shutdown();
        ingress.Stop();
        sink.WriteDebugMessage(
            buildxl::linux::DebugEventSeverity::kError,
            static_cast<int32_t>(getpid()),
            std::string("macOS sandbox could not launch the tool: ") + strerror(spawnResult));
        sink.WriteSentinel(ReportSink::kNoActiveProcessesSentinel);
        sink.WriteSentinel(ReportSink::kEndOfReportsSentinel);
        sink.Close();
        return kBrokerFailureExitCode;
    }

    engine.RegisterRoot(ProcessIdentity{childPid, 0}, argv[1]);

    std::chrono::seconds supervisionTimeout(600);
    if (const char *raw = getenv(kSupervisionTimeoutEnvVar))
    {
        const long parsed = strtol(raw, nullptr, 10);
        if (parsed > 0)
        {
            supervisionTimeout = std::chrono::seconds(parsed);
        }
    }

    int toolExitCode = kBrokerFailureExitCode;
    const bool quiesced = WaitForTree(childPid, supervisionTimeout, toolExitCode);

    // waitpid returning is a statement about processes, not about the event stream: messages the
    // kernel generated before the exit may still be in flight. The closing fence is what turns "the
    // tool finished" into "everything the tool did has been seen".
    engine.CloseStream();
    engine.Shutdown();
    ingress.Stop();

    const TaintReason taint = engine.Evaluate(quiesced);
    const EngineStatistics stats = engine.Statistics();

    if (IsTainted(taint))
    {
        // An error-severity debug message is how the Unix sandbox tells BuildXL that this pip's
        // observations are incomplete. BuildXL then refuses to cache the pip and re-runs it, which is
        // the whole reason it is safe to be conservative everywhere else in this broker.
        sink.WriteTaint(taint, childPid, "macOS Endpoint Security sandbox");
    }

    sink.WriteSentinel(ReportSink::kNoActiveProcessesSentinel);
    sink.WriteSentinel(ReportSink::kEndOfReportsSentinel);
    sink.Close();

    const char *evidencePath = getenv(kEvidenceEnvVar);
    if (evidencePath != nullptr && *evidencePath != '\0')
    {
        EvidenceWriter evidence;
        if (evidence.Open(evidencePath, NewRunId(), std::to_string(manifest.GetPipId()), ingress.BackendName()))
        {
            EvidenceSummary summary;
            summary.eventsAccepted = stats.eventsAccepted;
            summary.eventsProcessed = stats.eventsProcessed;
            summary.eventsRejected = stats.eventsRejected;
            summary.reportsWritten = stats.reportsWritten;
            summary.sequenceGaps = stats.sequenceGaps;
            summary.estimatedKernelDrops = stats.estimatedKernelDrops;
            summary.unmappedLineageEvents = stats.unmappedLineageEvents;
            summary.queueHighWaterMark = stats.queueHighWaterMark;
            summary.queueCapacity = EngineOptions().queueCapacity;
            summary.callbackNanosMax = stats.callbackNanosMax;
            summary.fenceLatencyNanos = stats.fenceLatencyNanos;
            summary.peakResidentBytes = PeakResidentBytes();
            summary.supervisionQuiesced = quiesced;
            summary.taint = taint;
            summary.childExitCode = toolExitCode;
            evidence.WriteSummary(summary);
            evidence.Close();
        }
    }

    ::unlink(noncePath.c_str());

    return toolExitCode;
}
