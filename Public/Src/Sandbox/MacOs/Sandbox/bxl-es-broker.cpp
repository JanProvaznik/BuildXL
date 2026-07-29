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
#include <algorithm>
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

#include "AccessChecker.h"
#include "EsIngress.h"
#include "Evidence.h"
#include "FileAccessManifest.h"
#include "InterposeIngress.h"
#include "ReportSink.h"
#include "SandboxEngine.h"
#include "../Interpose/InterposeProtocol.h"

#include <libgen.h>
#include <libproc.h>
#include <limits.h>
#include <memory>
#include <sys/stat.h>

extern char **environ;

using namespace buildxl::macos;

namespace {

constexpr const char *kFamPathEnvVar = "__BUILDXL_FAM_PATH";
constexpr const char *kEvidenceEnvVar = "__BUILDXL_MACOS_EVIDENCE_PATH";
constexpr const char *kSupervisionTimeoutEnvVar = "__BUILDXL_MACOS_SUPERVISION_TIMEOUT_SECONDS";

/**
 * Which observation backend to use: "es", "interpose", or "auto" (the default).
 *
 * CODESYNC: Public/Src/Engine/Processes/SandboxConnectionMacOs.cs
 */
constexpr const char *kBackendEnvVar = "__BUILDXL_MACOS_SANDBOX_BACKEND";

/** Exit code used when the broker itself fails, distinct from any plausible tool exit code. */
constexpr int kBrokerFailureExitCode = 253;

/**
 * Reports the broker's own exit, then closes the report stream.
 *
 * BuildXL launches the broker, not the tool, so from the scheduler's point of view the broker *is*
 * the pip's root process (SandboxConnectionMacOs.OverrideProcessStartInfo). For a sandbox that wraps
 * the root process in a supervisor, SandboxedProcessUnix.GetReportsAsync will not collect a pip's
 * reports until an exit report arrives whose pid equals the process BuildXL launched; nothing else
 * completes that wait short of the pip timeout, so omitting it turns every pip into a stall that
 * ends in a spurious timeout rather than in whatever actually happened.
 *
 * Endpoint Security cannot supply that report. The broker is deliberately outside the tracked tree
 * (see the note where the tool is spawned), and on the early-failure paths there is no tracked tree
 * at all. So the broker states its own exit, as the last report before the sentinels, on every path
 * that closes the stream. Writing it while the broker is still alive is correct: the report answers
 * "is this pip's process tree finished", and BuildXL waits for the real OS exit separately.
 *
 * CODESYNC: Public/Src/Engine/Processes/SandboxedProcessUnix.cs (HandleAccessReport, GetReportsAsync)
 */
void CloseReportStream(ReportSink &sink, const buildxl::common::FileAccessManifest *manifest, const char *brokerPath)
{
    buildxl::linux::SandboxEvent exitEvent = buildxl::linux::SandboxEvent::ExitSandboxEvent(
        "exit",
        brokerPath,
        getpid(),
        getppid());

    if (exitEvent.IsValid())
    {
        exitEvent.SetRequiredPathResolution(buildxl::linux::RequiredPathResolution::kDoNotResolve);
        buildxl::linux::AccessChecker::CheckAccessAndGetReport(manifest, exitEvent, /* basedOnPolicy */ false);
        sink.WriteSandboxEvent(exitEvent);
    }

    sink.WriteSentinel(ReportSink::kNoActiveProcessesSentinel);
    sink.WriteSentinel(ReportSink::kEndOfReportsSentinel);
    sink.Close();
}

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
/**
 * Set from a signal handler when BuildXL asks the broker to stop.
 *
 * BuildXL cancels or times out a pip by sending SIGTERM to the process it launched, which is this
 * broker. Dying on the spot would leave the report FIFO without its end-of-reports sentinel, and the
 * managed reader would have to treat a truncated stream as the end of the pip. Catching the signal
 * instead lets the broker run its normal shutdown -- close the stream, taint, write the sentinels --
 * so what BuildXL receives is complete and explicitly marked as a partial observation.
 */
volatile sig_atomic_t g_terminationRequested = 0;

void OnTerminationSignal(int)
{
    g_terminationRequested = 1;
}

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
            if (g_terminationRequested)
            {
                // Pass the signal on to the whole tree rather than just the root: the point of the
                // process group is that orphans are reachable, and leaving them running would hold
                // the ES client open after this pip is done.
                kill(-rootPid, SIGTERM);
                exitCode = 128 + SIGTERM;
                return false;
            }

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
        if (g_terminationRequested)
        {
            kill(-rootPid, SIGTERM);
            return false;
        }

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

// CODESYNC: Public/Src/Sandbox/Windows/DetoursServices/DataTypes.h (ManifestDebugFlag_t)
// A release-mode manifest starts with the 32-bit word 0xDB600000.
bool LooksLikeReleaseManifest(const std::vector<char> &bytes)
{
    constexpr uint32_t kReleaseManifestDebugFlag = 0xDB600000;

    if (bytes.size() < sizeof(uint32_t))
    {
        return false;
    }

    uint32_t flag = 0;
    memcpy(&flag, bytes.data(), sizeof(flag));
    return flag == kReleaseManifestDebugFlag;
}

/**
 * Locates libBuildXLInterpose.dylib.
 *
 * The deployment puts it beside the broker, so the broker's own path is the answer in every case
 * BuildXL produces. The environment variable exists for the unit tests, which run the broker out of
 * a build tree rather than a deployment.
 */
std::string FindInterposeLibrary(const char *brokerPath)
{
    if (const char *configured = getenv(BXL_INTERPOSE_LIBRARY_ENV_VAR))
    {
        if (*configured != '\0')
        {
            return configured;
        }
    }

    char resolved[PATH_MAX];
    memset(resolved, 0, sizeof(resolved));
    if (proc_pidpath(getpid(), resolved, sizeof(resolved)) <= 0)
    {
        if (brokerPath == nullptr)
        {
            return std::string();
        }

        strncpy(resolved, brokerPath, sizeof(resolved) - 1);
    }

    std::string directory(resolved);
    const size_t lastSlash = directory.find_last_of('/');
    if (lastSlash == std::string::npos)
    {
        return std::string();
    }

    return directory.substr(0, lastSlash) + "/libBuildXLInterpose.dylib";
}

/**
 * Chooses the observation backend.
 *
 * "auto" prefers Endpoint Security and falls back to interposition when it cannot be started, which
 * on a machine without the restricted entitlement is every time. The fallback is deliberately not
 * silent: the backend name is recorded in the evidence file and in the taint accounting, because
 * "which backend observed this build" is the first question anyone reading the numbers should ask.
 */
std::unique_ptr<EventSource> CreateEventSource(
    const char *brokerPath,
    EventSource::EventHandler handler,
    std::string &backendChoice,
    std::string &errorMessage)
{
    const char *requested = getenv(kBackendEnvVar);
    const std::string mode = requested != nullptr && *requested != '\0' ? requested : "auto";

    if (mode != "interpose")
    {
        auto endpointSecurity = std::unique_ptr<EsIngress>(new EsIngress());
        std::string esError;
        if (endpointSecurity->Start(handler, esError))
        {
            backendChoice = "es";
            return endpointSecurity;
        }

        if (mode == "es")
        {
            errorMessage = esError;
            return nullptr;
        }

        errorMessage = esError;
    }

    auto interpose = std::unique_ptr<InterposeIngress>(new InterposeIngress());
    const std::string socketPath = interpose->SocketPath();
    const std::string libraryPath = FindInterposeLibrary(brokerPath);

    if (libraryPath.empty())
    {
        errorMessage = "cannot locate libBuildXLInterpose.dylib next to the broker";
        return nullptr;
    }

    struct stat libraryInfo;
    if (stat(libraryPath.c_str(), &libraryInfo) != 0)
    {
        errorMessage = "the interpose library is not deployed at '" + libraryPath + "'";
        return nullptr;
    }

    std::string interposeError;
    if (!interpose->Start(handler, interposeError))
    {
        errorMessage = interposeError;
        return nullptr;
    }

    // Set on the broker's own environment because posix_spawnp passes `environ` straight through, so
    // this is what the tool and every descendant inherit. dyld strips DYLD_INSERT_LIBRARIES when it
    // execs a SIP protected binary, which is why the injected library reports that case rather than
    // relying on the variable still being present further down the tree.
    setenv(BXL_INTERPOSE_SOCKET_ENV_VAR, socketPath.c_str(), 1);
    setenv(BXL_INTERPOSE_LIBRARY_ENV_VAR, libraryPath.c_str(), 1);
    setenv("DYLD_INSERT_LIBRARIES", libraryPath.c_str(), 1);

    backendChoice = "interpose";
    errorMessage.clear();
    return interpose;
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

    // The shared parser asserts (and in a build with NDEBUG, silently walks off the end) when handed
    // a blob that is not a manifest. A truncated or half-written manifest file is a realistic failure,
    // so check the leading debug-flag word here and turn it into an actionable message rather than an
    // abort trap with no context.
    if (!LooksLikeReleaseManifest(famBytes))
    {
        Fail("the file at '%s' is not a valid release-mode file access manifest (%zu bytes)",
             famPathRaw,
             famBytes.size());
        return kBrokerFailureExitCode;
    }

    // FileAccessManifest takes ownership of the payload and frees it with delete[], so it must be
    // handed a buffer allocated with new[] -- not the storage of a std::vector, which would then be
    // freed twice. CODESYNC: Public/Src/Sandbox/Linux/bxl_observer.cpp does the same thing.
    char *famPayload = new char[famBytes.size()];
    memcpy(famPayload, famBytes.data(), famBytes.size());
    buildxl::common::FileAccessManifest manifest(famPayload, famBytes.size());

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

    const auto brokerStartedAt = std::chrono::steady_clock::now();

    // The source is started before the engine exists, so events are routed through a pointer that is
    // published only once the engine is running. The window is provably empty rather than merely
    // small: no process is under observation until the tool is spawned, which happens far below.
    // It is counted anyway, because "provably empty" is a claim that should fail loudly if wrong.
    std::atomic<SandboxEngine *> enginePointer{nullptr};
    std::atomic<uint64_t> eventsBeforeEngineExisted{0};
    auto handler = [&enginePointer, &eventsBeforeEngineExisted](NormalizedEvent &&event) {
        SandboxEngine *const engine = enginePointer.load(std::memory_order_acquire);
        if (engine == nullptr)
        {
            eventsBeforeEngineExisted.fetch_add(1, std::memory_order_relaxed);
            return;
        }

        engine->OnEvent(std::move(event));
    };

    std::string backendChoice;
    std::string backendError;
    std::unique_ptr<EventSource> ingress = CreateEventSource(argv[0], handler, backendChoice, backendError);
    if (ingress == nullptr)
    {
        Fail("no macOS sandbox backend could be started: %s", backendError.c_str());
        sink.WriteDebugMessage(
            buildxl::linux::DebugEventSeverity::kError,
            static_cast<int32_t>(getpid()),
            std::string("macOS sandbox could not start: ") + backendError);
        CloseReportStream(sink, &manifest, argv[0]);
        return kBrokerFailureExitCode;
    }

    const std::string noncePath = MakeNoncePath();

    SandboxEngine engine(
        &manifest,
        &sink,
        ingress->BrokerIdentity(),
        noncePath,
        [&ingress](const std::string &nonce) { return ingress->EmitMarker(nonce); },
        EngineOptions());

    engine.Start();
    enginePointer.store(&engine, std::memory_order_release);

    // The baseline fence proves the client is live and delivering before anything is launched. If the
    // subscription silently did nothing, this is where it is caught - not after the pip has run.
    if (!engine.EstablishBaseline())
    {
        // Failing here and continuing anyway would be the worst outcome available: the tool would run
        // with a stream that was never proven to deliver, its accesses might never be reported, and
        // BuildXL would cache the result as though it had been observed. The fence exists precisely to
        // stop that, so its failure has to stop the launch.
        Fail("the %s sandbox stream did not deliver the baseline marker", ingress->BackendName());
        engine.Shutdown();
        ingress->Stop();
        sink.WriteDebugMessage(
            buildxl::linux::DebugEventSeverity::kError,
            static_cast<int32_t>(getpid()),
            std::string("macOS sandbox could not confirm the ") + ingress->BackendName()
                + " stream was delivering; refusing to launch the tool unobserved");
        CloseReportStream(sink, &manifest, argv[0]);
        return kBrokerFailureExitCode;
    }

    // Installed before the tool exists, so a cancellation that arrives during startup is still
    // handled by the shutdown path rather than by the default disposition. SA_RESTART is deliberately
    // not set: the waits below need to see EINTR to notice the request.
    struct sigaction terminationAction = {};
    terminationAction.sa_handler = OnTerminationSignal;
    sigemptyset(&terminationAction.sa_mask);
    terminationAction.sa_flags = 0;
    sigaction(SIGTERM, &terminationAction, nullptr);
    sigaction(SIGINT, &terminationAction, nullptr);

    // Own process group, so the whole tree can be waited on and signalled as a unit.
    // Said before the spawn rather than inferred from the taint afterwards. A SIP protected tool
    // produces a correct but unhelpful LifecycleNotClosed: the pip is not cached, which is right, but
    // nothing tells the operator that the cause is the executable they chose and that it is fixable.
    const char *toolToExecute = argv[1];
    std::string shadowTool;

    if (backendChoice == "interpose")
    {
        std::string reason;
        if (!InterposeIngress::IsInjectable(argv[1], reason))
        {
            std::string shadowError;
            if (InterposeIngress::MakeInjectable(argv[1], shadowTool, shadowError))
            {
                // argv is untouched, so the tool still sees its own path in argv[0].
                toolToExecute = shadowTool.c_str();
                sink.WriteDebugMessage(
                    buildxl::linux::DebugEventSeverity::kInfo,
                    static_cast<int32_t>(getpid()),
                    "macOS sandbox is running an ad-hoc signed copy of '" + std::string(argv[1])
                        + "' so that it can be observed: System Integrity Protection would otherwise "
                          "strip the observation library from it and from everything it starts");
            }
            else
            {
                sink.WriteDebugMessage(
                    buildxl::linux::DebugEventSeverity::kWarning,
                    static_cast<int32_t>(getpid()),
                    "macOS sandbox cannot observe this pip: " + reason + ". A copy that could be "
                    "observed was not usable either: " + shadowError);
            }
        }
    }

    posix_spawnattr_t attributes;
    posix_spawnattr_init(&attributes);
    posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP);
    posix_spawnattr_setpgroup(&attributes, 0);

    pid_t childPid = -1;
    const int spawnResult = posix_spawnp(&childPid, toolToExecute, nullptr, &attributes, &argv[1], environ);
    posix_spawnattr_destroy(&attributes);

    if (spawnResult != 0)
    {
        Fail("cannot launch '%s': %s", argv[1], strerror(spawnResult));
        engine.Shutdown();
        ingress->Stop();
        sink.WriteDebugMessage(
            buildxl::linux::DebugEventSeverity::kError,
            static_cast<int32_t>(getpid()),
            std::string("macOS sandbox could not launch the tool: ") + strerror(spawnResult));
        CloseReportStream(sink, &manifest, argv[0]);
        return kBrokerFailureExitCode;
    }

    // Deliberately no explicit root registration here: the root process enters the process table
    // through its own FORK event, carrying the audit-token identity ES will use for every subsequent
    // event. Registering it from the pid that posix_spawnp returned would create a second entry that
    // never matches (pidversion would be unknown), and would mask a genuinely lost FORK. The broker's
    // own identity is anchored in the engine instead, so the root's fork has a mapped parent.
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
    ingress->Stop();

    TaintReason taint = engine.Evaluate(quiesced);

    // The tracker abstains for backends whose sequences it does not own, so a backend that can detect
    // its own losses has to be asked. Until now this interface existed and nothing called it, which
    // meant an interposition drop would have been silently survivable -- the exact failure the whole
    // taint mechanism is for.
    const uint64_t backendLosses = ingress->BackendReportedLosses();
    if (backendLosses > 0)
    {
        taint = taint | TaintReason::kKernelSequenceGap;
    }

    // Events delivered before the engine was published are dropped by the routing handler. The window
    // is meant to be empty; if it ever is not, the pip must not be cached on the strength of it.
    const uint64_t droppedBeforeEngine = eventsBeforeEngineExisted.load(std::memory_order_relaxed);
    if (droppedBeforeEngine > 0)
    {
        taint = taint | TaintReason::kKernelSequenceGap;
    }

    if (g_terminationRequested)
    {
        // The stream is complete and well formed, but it is a prefix of what the pip would have done.
        // Saying so explicitly is what stops it from being mistaken for a full observation.
        taint = taint | TaintReason::kBrokerTerminated;
    }
    const EngineStatistics stats = engine.Statistics();

    if (IsTainted(taint))
    {
        // An error-severity debug message is how the Unix sandbox tells BuildXL that this pip's
        // observations are incomplete. BuildXL then refuses to cache the pip and re-runs it, which is
        // the whole reason it is safe to be conservative everywhere else in this broker.
        sink.WriteTaint(taint, childPid, std::string("macOS sandbox (") + ingress->BackendName() + " backend)");
    }

    CloseReportStream(sink, &manifest, argv[0]);

    const char *evidencePath = getenv(kEvidenceEnvVar);
    if (evidencePath != nullptr && *evidencePath != '\0')
    {
        EvidenceWriter evidence;
        if (evidence.Open(evidencePath, NewRunId(), std::to_string(manifest.GetPipId()), ingress->BackendName()))
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

            // These were declared by the evidence schema and never filled in, so every evidence file
            // ever written claimed the fence had not closed and that the run saw zero processes. A
            // field that is always false is worse than an absent one: it reads as a measurement.
            summary.markerAttempts = stats.markerAttempts;
            summary.processCount = static_cast<uint32_t>(engine.Processes().TotalCount());
            summary.fenceClosed = engine.Fence().CurrentState() == FenceProtocol::State::kClosed;
            summary.lifecycleClosed = engine.Processes().IsClosed();
            summary.wallClockNanos = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - brokerStartedAt).count());
            summary.backendReportedLosses = backendLosses;
            summary.eventsDroppedBeforeEngineStart = droppedBeforeEngine;

            std::vector<uint64_t> samples = stats.callbackNanosSamples;
            if (!samples.empty())
            {
                std::sort(samples.begin(), samples.end());
                const auto percentile = [&samples](double fraction) {
                    size_t index = static_cast<size_t>(fraction * static_cast<double>(samples.size()));
                    if (index >= samples.size()) { index = samples.size() - 1; }
                    return samples[index];
                };

                summary.callbackNanosP50 = percentile(0.50);
                summary.callbackNanosP95 = percentile(0.95);
                summary.callbackNanosP99 = percentile(0.99);
                summary.callbackNanosP999 = percentile(0.999);
            }
            evidence.WriteSummary(summary);
            evidence.Close();
        }
    }

    ::unlink(noncePath.c_str());

    return toolExitCode;
}
