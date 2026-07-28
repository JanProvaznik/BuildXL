// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Protocol conformance harness for the macOS Endpoint Security sandbox broker.
//
// This binary exists because the Endpoint Security client entitlement is not obtainable on a
// developer machine with SIP enabled, and "we could not test it" is not an acceptable answer for
// code that decides whether a build result may be cached. The broker is therefore split so that
// every decision that affects cache correctness lives behind an EventSource, and this harness
// drives that seam with a deterministic corpus plus scripted faults.
//
// What it proves:
//   Gate A (soundness):       under any fault, every access in the corpus is either reported or the
//                             pip is tainted. Zero silent false skips.
//   Gate B (loss accounting):  every injected loss is detected. No fault produces a clean verdict.
//
// What it does not prove: that macOS actually behaves the way the replay source models it. That
// claim needs the entitlement, and the same harness runs against EsEventSource once it is available.

#include <atomic>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>
#include <vector>

#include "Evidence.h"
#include "ManifestBuilder.h"
#include "ReplaySource.h"
#include "ReportReader.h"
#include "ReportSink.h"
#include "SandboxEngine.h"

using namespace buildxl::macos;
using namespace buildxl::macos::testing;

namespace {

const char *kSourceRoot = "/tmp/bxl-selftest/src";
const char *kOutputRoot = "/tmp/bxl-selftest/out";

struct ScenarioOptions
{
    CorpusShape shape;
    FaultScript faults;
    EngineOptions engine;
    bool supervisionQuiesced = true;
    bool registerRoot = true;

    /**
     * Models what actually happens in production: the broker forks the pip's root process, so the
     * root enters the process table through a FORK event whose parent is the broker, not through an
     * out-of-band registration.
     */
    bool rootEntersViaBrokerFork = false;
};

struct ScenarioResult
{
    TaintReason taint = TaintReason::kNone;
    size_t expectedCount = 0;
    size_t missingCount = 0;
    size_t reportedCount = 0;
    bool sawErrorDebugMessage = false;
    bool sawWarningDebugMessage = false;
    bool sawNoActiveProcesses = false;
    bool sawEndOfReports = false;
    bool malformed = false;
    uint64_t wallNanos = 0;
    EngineStatistics stats;
    std::vector<ExpectedAccess> missingExamples;
};

uint64_t NowNanos()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

std::unique_ptr<buildxl::common::FileAccessManifest> BuildTestManifest()
{
    return ManifestBuilder()
        .WithReportPath("/tmp/bxl-selftest/reports.fifo")
        .WithPipId(0x1234)
        .WithScope(kSourceRoot, ReportAllPolicy())
        .WithScope(kOutputRoot, ReportAllPolicy())
        .BuildManifest();
}

ScenarioResult RunScenario(const ScenarioOptions &options, buildxl::common::FileAccessManifest *manifest)
{
    ScenarioResult result;
    const uint64_t start = NowNanos();

    int fds[2] = {-1, -1};
    if (pipe(fds) != 0)
    {
        result.malformed = true;
        return result;
    }

    ReportReader reader(fds[0]);
    reader.Start();

    ReportSink sink;
    sink.AttachFd(fds[1]);

    const ProcessIdentity brokerIdentity{static_cast<int32_t>(getpid()), 7};
    const ProcessIdentity rootIdentity{100000, 1};

    std::vector<ExpectedAccess> expected;
    CorpusShape shape = options.shape;
    shape.sourceRoot = kSourceRoot;
    shape.outputRoot = kOutputRoot;
    std::vector<NormalizedEvent> corpus = GenerateCorpus(shape, rootIdentity, expected);

    if (options.rootEntersViaBrokerFork)
    {
        NormalizedEvent rootFork;
        rootFork.op = NormOp::kFork;
        rootFork.self = rootIdentity;
        rootFork.parent = brokerIdentity;
        rootFork.sourcePath = std::string(kSourceRoot) + "/tool0";
        rootFork.messageVersion = 8;
        rootFork.succeeded = true;
        corpus.insert(corpus.begin(), rootFork);

        NormalizedEvent rootExit;
        rootExit.op = NormOp::kExit;
        rootExit.self = rootIdentity;
        rootExit.parent = brokerIdentity;
        rootExit.sourcePath = std::string(kSourceRoot) + "/tool0";
        rootExit.messageVersion = 8;
        rootExit.succeeded = true;
        corpus.push_back(rootExit);
    }

    ReplaySource source(std::move(corpus), options.faults, brokerIdentity);

    SandboxEngine engine(
        manifest,
        &sink,
        brokerIdentity,
        "/tmp/bxl-selftest",
        [&source](const std::string &noncePath) { return source.EmitMarker(noncePath); },
        options.engine);

    engine.Start();

    std::string errorMessage;
    source.Start([&engine](NormalizedEvent &&event) { engine.OnEvent(std::move(event)); }, errorMessage);

    if (options.registerRoot)
    {
        engine.RegisterRoot(rootIdentity, std::string(kSourceRoot) + "/tool0");
    }

    engine.EstablishBaseline();

    // The corpus stands in for the observed process tree doing its work, so it is delivered between
    // the two fences, exactly where a real pip runs. Keeping it out of CloseStream() is what makes
    // the measured closing-fence latency meaningful.
    source.DeliverCorpus();

    engine.CloseStream();
    engine.Shutdown();

    result.taint = engine.Evaluate(options.supervisionQuiesced);
    result.stats = engine.Statistics();

    sink.WriteTaint(result.taint, rootIdentity.pid, "selftest");
    sink.WriteSentinel(ReportSink::kNoActiveProcessesSentinel);
    sink.WriteSentinel(ReportSink::kEndOfReportsSentinel);
    sink.Close();

    reader.Join();

    const auto &reported = reader.ReportedAccesses();
    result.expectedCount = expected.size();
    result.reportedCount = reported.size();

    for (const ExpectedAccess &access : expected)
    {
        if (reported.find({access.pid, access.path}) == reported.end())
        {
            result.missingCount++;
            if (result.missingExamples.size() < 5)
            {
                result.missingExamples.push_back(access);
            }
        }
    }

    result.sawErrorDebugMessage = reader.SawErrorDebugMessage();
    result.sawWarningDebugMessage = reader.SawWarningDebugMessage();
    result.sawNoActiveProcesses = reader.SawNoActiveProcessesSentinel();
    result.sawEndOfReports = reader.SawEndOfReportsSentinel();
    result.malformed = reader.SawMalformedReport();
    result.wallNanos = NowNanos() - start;

    return result;
}

// ---------------------------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------------------------

int g_failures = 0;
int g_checks = 0;

// Correctness gates always decide the exit code: they compare what the protocol reported against what
// the corpus did, and the answer does not depend on the machine. Throughput and latency gates are a
// different kind of claim - they measure the hardware and its current load as much as they measure the
// code - so they only decide the exit code when the caller asked for a benchmark. Inside a build the
// same numbers are still measured and printed, but a machine that is busy running the rest of the
// build must not turn a timing dip into a build failure.
bool g_perfGates = true;

void Check(bool condition, const std::string &description)
{
    g_checks++;
    if (!condition)
    {
        g_failures++;
        fprintf(stderr, "FAIL: %s\n", description.c_str());
    }
}

void CheckPerf(bool condition, const std::string &description)
{
    if (g_perfGates)
    {
        Check(condition, description);
        return;
    }

    printf("  advisory          %s: %s\n", condition ? "met" : "NOT MET", description.c_str());
}

void ReportScenario(const char *name, const ScenarioResult &result)
{
    printf("  %-34s taint=%-28s expected=%-6zu missing=%-5zu reports=%-6" PRIu64 " gaps=%" PRIu64 "\n",
           name,
           TaintSetToString(result.taint).c_str(),
           result.expectedCount,
           result.missingCount,
           result.stats.reportsWritten,
           result.stats.sequenceGaps);
}

} // namespace

// ---------------------------------------------------------------------------------------------
// Test bodies
// ---------------------------------------------------------------------------------------------

/**
 * Regression test for the production process-tree shape.
 *
 * In a real build nothing registers the root out of band: the broker forks it, so the root arrives
 * as a FORK event whose parent is the broker. Two things previously went wrong with that shape and
 * both were invisible to every other test here, because every other test hands the root to the
 * engine directly:
 *
 *  1. The ingress decided "is this the broker's own event" from the process that *acted*, and FORK
 *     rewrites the subject to the child -- so the root's own start event was suppressed as if the
 *     broker had produced it, and BuildXL would never see the pip start.
 *  2. The broker was not in the process table at all, so the root's fork had no mapped parent and
 *     every build began with a kUnmappedLineage taint.
 *
 * The engine anchors the broker's identity for exactly this reason. The anchor must not, however,
 * make an empty tree look complete, which is the third assertion below.
 */
static void TestRootForkedByBrokerIsTrackedWithoutTaint(buildxl::common::FileAccessManifest *manifest)
{
    printf("[root forked by broker]\n");

    ScenarioOptions options;
    options.shape.processCount = 8;
    options.shape.accessesPerProcess = 12;
    options.shape.seed = 991;
    options.registerRoot = false;
    options.rootEntersViaBrokerFork = true;

    const ScenarioResult result = RunScenario(options, manifest);
    ReportScenario("root forked by broker", result);

    Check(!HasTaint(result.taint, TaintReason::kUnmappedLineage),
          "a root process forked by the broker must have mapped lineage");
    Check(!HasTaint(result.taint, TaintReason::kLifecycleNotClosed),
          "a tree whose root arrived by fork and exited must close");
    Check(result.missingCount == 0, "no access may be lost when the root arrives by fork");
    Check(!result.sawErrorDebugMessage, "the production process-tree shape must not raise an infrastructure error");

    // The anchor is synthetic, so on its own it must not be able to satisfy closure. Without a real
    // observed process the tree is not closed, and that must still be reported.
    ScenarioOptions empty;
    empty.shape.processCount = 0;
    empty.shape.accessesPerProcess = 0;
    empty.shape.seed = 992;
    empty.registerRoot = false;

    const ScenarioResult emptyResult = RunScenario(empty, manifest);
    ReportScenario("nothing observed", emptyResult);

    Check(HasTaint(emptyResult.taint, TaintReason::kLifecycleNotClosed),
          "the broker anchor alone must not make an unobserved tree look closed");
}

static void TestCleanRunReportsEverything(buildxl::common::FileAccessManifest *manifest)
{
    printf("[clean run]\n");

    ScenarioOptions options;
    options.shape.processCount = 24;
    options.shape.accessesPerProcess = 40;
    options.shape.seed = 12345;

    const ScenarioResult result = RunScenario(options, manifest);
    ReportScenario("no faults", result);

    Check(result.taint == TaintReason::kNone, "a clean stream must produce no taint");
    Check(result.missingCount == 0, "a clean stream must report every observed access");
    Check(!result.malformed, "the report stream must be well formed");
    Check(result.expectedCount > 500, "the corpus must be substantial enough to be meaningful");
    Check(result.stats.reportsWritten >= result.expectedCount, "every expected access must produce at least one report");
    Check(!result.sawErrorDebugMessage, "a clean run must not emit an infrastructure error");
    Check(result.sawEndOfReports, "the end-of-reports sentinel must reach the reader");
    Check(result.sawNoActiveProcesses, "the no-active-processes sentinel must reach the reader");
    Check(result.stats.markerEvents == 2, "exactly two fence markers must be consumed");
}

static void TestEachFaultIsDetected(buildxl::common::FileAccessManifest *manifest)
{
    printf("[single faults]\n");

    struct Case
    {
        const char *name;
        FaultScript faults;
        bool supervisionQuiesced = true;
    };

    std::vector<Case> cases;

    {
        FaultScript f; f.dropCount = 1; f.seed = 1;
        cases.push_back({"single dropped event", f});
    }
    {
        FaultScript f; f.dropCount = 37; f.seed = 2;
        cases.push_back({"many dropped events", f});
    }
    {
        FaultScript f; f.dropTail = true; f.seed = 3;
        cases.push_back({"dropped tail", f});
    }
    {
        FaultScript f; f.changeEpoch = true; f.seed = 4;
        cases.push_back({"client epoch change", f});
    }
    {
        FaultScript f; f.loseMarker = true; f.seed = 5;
        cases.push_back({"lost closing marker", f});
    }
    {
        FaultScript f; f.staleVersion = true; f.seed = 6;
        cases.push_back({"message too old for global_seq_num", f});
    }
    {
        FaultScript f; f.unmappedLineage = true; f.seed = 7;
        cases.push_back({"event from untracked process", f});
    }
    {
        FaultScript f; f.unsupportedOperation = true; f.seed = 8;
        cases.push_back({"unmodellable operation", f});
    }
    {
        FaultScript f; f.truncatePath = true; f.seed = 9;
        cases.push_back({"truncated path", f});
    }
    {
        FaultScript f; f.loseExit = true; f.seed = 10;
        cases.push_back({"missing process exit", f});
    }
    {
        FaultScript f; f.seed = 11;
        cases.push_back({"supervision timeout", f, /* quiesced */ false});
    }

    for (const Case &testCase : cases)
    {
        ScenarioOptions options;
        options.shape.processCount = 12;
        options.shape.accessesPerProcess = 24;
        options.shape.seed = 900 + testCase.faults.seed;
        options.faults = testCase.faults;
        options.supervisionQuiesced = testCase.supervisionQuiesced;
        options.engine.fenceTimeout = std::chrono::milliseconds(50);
        options.engine.maxFenceAttempts = 1;

        const ScenarioResult result = RunScenario(options, manifest);
        ReportScenario(testCase.name, result);

        Check(IsTainted(result.taint), std::string("fault must be detected: ") + testCase.name);
        Check(result.sawErrorDebugMessage, std::string("fault must reach managed code as an error: ") + testCase.name);
        Check(!result.malformed, std::string("report stream must stay well formed: ") + testCase.name);
    }
}

/**
 * Endpoint Security grows es_message_t additively; the fields this broker reads never change shape.
 * Tainting on a version bump would break every build on the next macOS update, which is exactly the
 * kind of unusability this port exists to avoid. The contract is therefore: surface it, keep going.
 */
static void TestNewerMessageVersionWarnsButDoesNotFail(buildxl::common::FileAccessManifest *manifest)
{
    printf("[forward compatibility]\n");

    ScenarioOptions options;
    options.shape.processCount = 12;
    options.shape.accessesPerProcess = 24;
    options.shape.seed = 777;
    options.faults.unknownVersion = true;
    options.faults.seed = 6;

    const ScenarioResult result = RunScenario(options, manifest);
    ReportScenario("message newer than validated", result);

    Check(!IsTainted(result.taint), "a newer ES message version must not fail the pip");
    Check(!result.sawErrorDebugMessage, "a newer ES message version must not raise an infrastructure error");
    Check(result.sawWarningDebugMessage, "a newer ES message version must be surfaced as a warning");
    Check(result.missingCount == 0, "a newer ES message version must not lose accesses");
}

static void TestQueueOverflowIsDetected(buildxl::common::FileAccessManifest *manifest)
{
    printf("[queue overflow]\n");

    ScenarioOptions options;
    options.shape.processCount = 40;
    options.shape.accessesPerProcess = 200;
    options.shape.seed = 4242;

    // A queue this small cannot possibly hold the burst, and backpressure is switched off so the
    // drop path is the one under test. The point is not that overflow is likely in production - it
    // is that when it does happen the pip must fail rather than report a partial stream.
    options.engine.queueCapacity = 4;
    options.engine.maxEnqueueBackpressure = std::chrono::microseconds::zero();
    options.faults.floodQueue = true;

    const ScenarioResult result = RunScenario(options, manifest);
    ReportScenario("tiny queue under burst", result);

    Check(result.stats.eventsRejected > 0, "the burst must actually overflow the queue");
    Check(HasTaint(result.taint, TaintReason::kLocalQueueOverflow), "queue overflow must taint the pip");
    Check(result.sawErrorDebugMessage, "queue overflow must reach managed code as an error");
}

/**
 * The same burst that overflows a backpressure-free queue must complete without loss once the
 * delivery thread is allowed to wait. Soundness never depended on this - overflow always taints -
 * but a sandbox that fails pips whenever the machine is busy is not usable, and usability is the
 * whole point of this port.
 */
static void TestBackpressureAvoidsLoss(buildxl::common::FileAccessManifest *manifest)
{
    printf("[backpressure]\n");

    ScenarioOptions options;
    options.shape.processCount = 40;
    options.shape.accessesPerProcess = 200;
    options.shape.seed = 4242;
    options.engine.queueCapacity = 4;
    options.engine.maxEnqueueBackpressure = std::chrono::milliseconds(250);
    options.faults.floodQueue = true;

    const ScenarioResult result = RunScenario(options, manifest);
    ReportScenario("tiny queue, backpressure enabled", result);

    Check(result.stats.eventsRejected == 0, "backpressure must absorb the burst instead of dropping");
    Check(result.stats.backpressureWaits > 0, "the burst must actually exercise backpressure");
    Check(result.taint == TaintReason::kNone, "an absorbed burst must not fail the pip");
    Check(result.missingCount == 0, "an absorbed burst must not lose accesses");
}

static void TestNoSilentSkipUnderRandomFaults(buildxl::common::FileAccessManifest *manifest, uint64_t iterations)
{
    printf("[randomized sweep: %" PRIu64 " scenarios]\n", iterations);

    uint64_t undetected = 0;
    uint64_t silentSkips = 0;
    uint64_t faultyRuns = 0;
    uint64_t cleanRuns = 0;
    uint64_t malformed = 0;

    for (uint64_t i = 0; i < iterations; i++)
    {
        const uint64_t seed = i * 6364136223846793005ull + 1442695040888963407ull;

        ScenarioOptions options;
        options.shape.processCount = 3 + static_cast<uint32_t>(seed % 5);
        options.shape.accessesPerProcess = 4 + static_cast<uint32_t>((seed >> 8) % 8);
        options.shape.distinctPaths = 16;
        options.shape.seed = seed;
        options.engine.fenceTimeout = std::chrono::milliseconds(25);
        options.engine.maxFenceAttempts = 1;
        options.engine.maxLatencySamples = 0;

        FaultScript faults;
        faults.seed = seed >> 16;
        faults.dropCount = ((seed >> 3) % 4 == 0) ? 1 + static_cast<uint32_t>((seed >> 20) % 3) : 0;
        faults.dropTail = ((seed >> 5) % 11) == 0;
        faults.changeEpoch = ((seed >> 7) % 13) == 0;
        faults.loseMarker = ((seed >> 9) % 17) == 0;
        faults.staleVersion = ((seed >> 11) % 19) == 0;
        faults.unmappedLineage = ((seed >> 13) % 23) == 0;
        faults.unsupportedOperation = ((seed >> 15) % 29) == 0;
        faults.truncatePath = ((seed >> 17) % 31) == 0;
        faults.loseExit = ((seed >> 19) % 37) == 0;
        options.faults = faults;
        options.supervisionQuiesced = ((seed >> 21) % 41) != 0;

        const ScenarioResult result = RunScenario(options, manifest);

        const bool anyFault = faults.Any() || !options.supervisionQuiesced;
        if (anyFault)
        {
            faultyRuns++;
            if (!IsTainted(result.taint))
            {
                undetected++;
                if (undetected <= 3)
                {
                    fprintf(stderr,
                            "FAIL: undetected fault at iteration %" PRIu64
                            " (drop=%u tail=%d epoch=%d marker=%d version=%d lineage=%d op=%d trunc=%d exit=%d quiesced=%d)\n",
                            i, faults.dropCount, faults.dropTail, faults.changeEpoch, faults.loseMarker,
                            faults.staleVersion, faults.unmappedLineage, faults.unsupportedOperation,
                            faults.truncatePath, faults.loseExit, options.supervisionQuiesced);
                }
            }
        }
        else
        {
            cleanRuns++;
        }

        // The soundness invariant: a missing access is only acceptable if the pip was tainted.
        if (result.missingCount > 0 && !IsTainted(result.taint))
        {
            silentSkips++;
            if (silentSkips <= 3)
            {
                fprintf(stderr, "FAIL: silent skip at iteration %" PRIu64 " (%zu missing, no taint)\n",
                        i, result.missingCount);
                for (const ExpectedAccess &access : result.missingExamples)
                {
                    fprintf(stderr, "      pid=%d op=%s path=%s\n", access.pid, NormOpName(access.op), access.path.c_str());
                }
            }
        }

        if (result.malformed)
        {
            malformed++;
        }
    }

    printf("  faulty=%" PRIu64 " clean=%" PRIu64 " undetected=%" PRIu64 " silentSkips=%" PRIu64 " malformed=%" PRIu64 "\n",
           faultyRuns, cleanRuns, undetected, silentSkips, malformed);

    Check(faultyRuns > iterations / 4, "the sweep must actually exercise faults");
    Check(cleanRuns > 0, "the sweep must include clean runs so it can fail on false positives");
    Check(undetected == 0, "every injected fault must be detected");
    Check(silentSkips == 0, "no run may skip an access without tainting the pip");
    Check(malformed == 0, "no run may corrupt the report stream");
}

static void RunBenchmark(buildxl::common::FileAccessManifest *manifest)
{
    printf("[benchmark]\n");

    ScenarioOptions options;
    options.shape.processCount = 64;
    options.shape.accessesPerProcess = 4000;
    options.shape.distinctPaths = 2000;
    options.shape.seed = 777;

    // The replay source produces events as fast as a tight loop can, which no real syscall stream can
    // match. A generous backpressure budget turns "producer outruns consumer" into a wait instead of
    // a drop, so the number measured below is the drain path's sustained rate rather than an artifact
    // of the synthetic producer's speed.
    options.engine.maxEnqueueBackpressure = std::chrono::milliseconds(1000);

    const ScenarioResult result = RunScenario(options, manifest);

    std::vector<uint64_t> samples = result.stats.callbackNanosSamples;
    const uint64_t p50 = Percentile(samples, 0.50);
    const uint64_t p95 = Percentile(samples, 0.95);
    const uint64_t p99 = Percentile(samples, 0.99);
    const uint64_t p999 = Percentile(samples, 0.999);

    const double seconds = static_cast<double>(result.wallNanos) / 1e9;
    const double eventsPerSecond = seconds > 0 ? static_cast<double>(result.stats.eventsAccepted) / seconds : 0;

    printf("  events            %" PRIu64 "\n", result.stats.eventsAccepted);
    printf("  reports           %" PRIu64 "\n", result.stats.reportsWritten);
    printf("  wall              %.3f s\n", seconds);
    printf("  throughput        %.0f events/s\n", eventsPerSecond);
    printf("  ingress p50/p95   %" PRIu64 " / %" PRIu64 " ns\n", p50, p95);
    printf("  ingress p99/p99.9 %" PRIu64 " / %" PRIu64 " ns\n", p99, p999);
    printf("  ingress max       %" PRIu64 " ns\n", result.stats.callbackNanosMax);
    printf("  queue high water  %zu / %zu\n", result.stats.queueHighWaterMark, options.engine.queueCapacity);
    printf("  events rejected   %" PRIu64 "\n", result.stats.eventsRejected);
    printf("  backpressure      %" PRIu64 " waits, %.3f s total\n",
        result.stats.backpressureWaits,
        static_cast<double>(result.stats.backpressureNanos) / 1e9);
    printf("  fence latency     %" PRIu64 " ns\n", result.stats.fenceLatencyNanos);
    printf("  peak RSS          %" PRIu64 " bytes\n", PeakResidentBytes());

    Check(result.taint == TaintReason::kNone, "the benchmark corpus must run clean");
    Check(result.missingCount == 0, "the benchmark must not skip accesses");

    // The ingress budget matters because an Endpoint Security AUTH handler that misses its deadline
    // gets its client killed. The bounded-work callback must stay far below any plausible deadline.
    CheckPerf(p99 < 100000, "ingress p99 must stay under 100us");

    // A build that keeps every core busy is nowhere near this rate per pip; the floor exists to catch
    // regressions in the decision path, which is the only part that scales with access count.
    CheckPerf(eventsPerSecond > 100000, "sustained drain throughput must stay above 100k events/s");
}

int main(int argc, char **argv)
{
    uint64_t sweepIterations = 100000;
    std::string evidencePath;

    for (int i = 1; i < argc; i++)
    {
        if (std::strcmp(argv[i], "--sweep") == 0 && i + 1 < argc)
        {
            sweepIterations = std::strtoull(argv[++i], nullptr, 10);
        }
        else if (std::strcmp(argv[i], "--evidence") == 0 && i + 1 < argc)
        {
            evidencePath = argv[++i];
        }
        else if (std::strcmp(argv[i], "--no-perf-gates") == 0)
        {
            g_perfGates = false;
        }
        else if (std::strcmp(argv[i], "--help") == 0)
        {
            printf("usage: bxl-es-selftest [--sweep N] [--evidence PATH] [--no-perf-gates]\n");
            return 0;
        }
    }

    std::unique_ptr<buildxl::common::FileAccessManifest> manifest = BuildTestManifest();

    printf("BuildXL macOS sandbox protocol conformance\n");
    printf("==========================================\n");
    printf("sweep %" PRIu64 " scenarios, perf gates %s\n",
        sweepIterations,
        g_perfGates ? "enforced" : "advisory (measured and printed, not asserted)");

    const uint64_t start = NowNanos();

    TestCleanRunReportsEverything(manifest.get());
    TestRootForkedByBrokerIsTrackedWithoutTaint(manifest.get());
    TestEachFaultIsDetected(manifest.get());
    TestNewerMessageVersionWarnsButDoesNotFail(manifest.get());
    TestQueueOverflowIsDetected(manifest.get());
    TestBackpressureAvoidsLoss(manifest.get());
    TestNoSilentSkipUnderRandomFaults(manifest.get(), sweepIterations);
    RunBenchmark(manifest.get());

    const uint64_t elapsed = NowNanos() - start;

    printf("\n%d checks, %d failures, %.1f s\n", g_checks, g_failures, static_cast<double>(elapsed) / 1e9);

    if (!evidencePath.empty())
    {
        EvidenceWriter evidence;
        evidence.Open(evidencePath, NewRunId(), "selftest", "replay");
        EvidenceSummary summary;
        summary.wallClockNanos = elapsed;
        summary.peakResidentBytes = PeakResidentBytes();
        summary.taint = g_failures == 0 ? TaintReason::kNone : TaintReason::kIngressFailure;
        evidence.WriteNote("conformance", g_failures == 0 ? "all gates passed" : "gate failures present");
        evidence.WriteSummary(summary);
        evidence.Close();
    }

    return g_failures == 0 ? 0 : 1;
}
