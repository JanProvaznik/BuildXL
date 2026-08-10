// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_SANDBOX_ENGINE_H
#define BUILDXL_SANDBOX_MACOS_SANDBOX_ENGINE_H

#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "BoundedQueue.h"
#include "EventSource.h"
#include "EventTranslator.h"
#include "FenceProtocol.h"
#include "FileAccessManifest.h"
#include "NormalizedEvent.h"
#include "ProcessTable.h"
#include "ReportSink.h"
#include "SequenceTracker.h"
#include "Taint.h"

namespace buildxl {
namespace macos {

/** Everything the engine measures, for the gate dashboard in issue #1. */
struct EngineStatistics
{
    uint64_t eventsAccepted = 0;
    uint64_t eventsProcessed = 0;
    uint64_t eventsRejected = 0;
    uint64_t reportsWritten = 0;
    uint64_t markerEvents = 0;
    uint64_t brokerEventsIgnored = 0;
    uint64_t sequenceGaps = 0;
    uint64_t estimatedKernelDrops = 0;
    uint64_t unmappedLineageEvents = 0;

    /**
     * Events discarded because their acting process was established to be outside the pip's tree.
     *
     * Not a fault. Endpoint Security delivers some events to a descendants client whose actor is
     * not a descendant, and counting them separately is what keeps that from being mistaken for a
     * soundness problem - and makes it visible if the number ever stops being small.
     */
    uint64_t foreignProcessEvents = 0;

    /**
     * Delegation events judged not to put the observation set at risk, and those judged to.
     *
     * Both are recorded because the decision is a policy judgement rather than a fact, and a policy
     * that silently absorbs everything is indistinguishable from one that works. If the benign count
     * is large and the escape count is zero on every build, that is the expected shape; if escapes
     * start appearing, the target names are what makes them diagnosable.
     */
    uint64_t benignDelegations = 0;
    uint64_t delegationEscapes = 0;

    /**
     * XPC connects whose verdict could not be reached at the time the event arrived.
     *
     * An XPC connect names a service but carries no identity for whoever answers, so the event on
     * its own cannot distinguish a platform service from a build tool's private daemon. The kernel
     * does supply that identity, but on the bootstrap look-up for the same name. Those two events
     * are emitted by different processes - the look-up is submitted by launchd - so Endpoint
     * Security does not order them against each other, and judging the connect on arrival makes the
     * verdict depend on delivery order. They are collected instead and resolved in Evaluate.
     */
    uint64_t deferredDelegations = 0;

    size_t queueHighWaterMark = 0;

    /** Enqueues that had to wait for the drain thread, and the total time spent waiting. */
    uint64_t backpressureWaits = 0;
    uint64_t backpressureNanos = 0;

    uint64_t callbackNanosTotal = 0;
    uint64_t callbackNanosMax = 0;
    std::vector<uint64_t> callbackNanosSamples;

    uint64_t fenceLatencyNanos = 0;
    uint32_t markerAttempts = 0;
};

/** Configuration for one pip's broker instance. */
/**
 * What a path names, as far as the broker can tell.
 *
 * kAbsent is a real answer and a load-bearing one: BuildXL treats a probe of a path that does not
 * exist as an input to the pip's cache key, because the pip's behaviour would change if it appeared.
 */
enum class LookupPathType
{
    kAbsent,
    kFile,
    kDirectory,
};

/**
 * Where a process sits relative to the pip's process tree.
 *
 * kUnknown is a real answer, not a placeholder: a process that has already exited cannot have its
 * ancestry walked, and the engine treats that as unsound rather than assuming either way.
 */
enum class ProcessOrigin
{
    kUnknown,
    kInsideTree,
    kOutsideTree,
};

/**
 * Walks a process's live ancestry to decide whether it descends from `root`.
 *
 * Only consulted for processes the broker has no record of, which on a healthy build is a handful
 * of events for the whole pip, so the cost of asking the kernel does not appear in the hot path.
 */
ProcessOrigin ProbeProcessOrigin(const ProcessIdentity &identity, const ProcessIdentity &root);

struct EngineOptions
{
    /**
     * Maximum events buffered between the delivery thread and the drain thread.
     *
     * Sized for scheduling jitter, not for absorbing a whole build: with backpressure enabled the
     * delivery thread waits rather than drops, so a deeper queue buys nothing but resident memory -
     * and BuildXL runs one broker per concurrently executing pip.
     */
    size_t queueCapacity = 1 << 14;

    /**
     * Longest a delivery thread may wait for queue space before giving up and tainting.
     *
     * Dropping an event costs the whole pip, so it is worth waiting; missing an Endpoint Security
     * deadline costs the whole client, so the wait must stay small. Callers that know the real
     * remaining deadline pass it to OnEvent and this acts only as the upper bound.
     */
    std::chrono::microseconds maxEnqueueBackpressure{2000};

    /** How long to wait for a fence marker before giving up and tainting. */
    std::chrono::milliseconds fenceTimeout{5000};

    /**
     * How long to wait for a marker to be observed before emitting another one.
     *
     * Endpoint Security does not flush a nearly-idle NOTIFY queue immediately; measured on macOS
     * 27, a lone marker takes ~251 ms to come back, while re-emitting until observed takes ~535 us
     * after about 15 emissions. Both fences are on every pip's critical path, so emitting once and
     * waiting costs ~500 ms per pip for nothing. Re-emission is sound because the marker is a stat
     * on a path that does not exist: it has no side effect, and the protocol already swallows
     * marker-shaped events that arrive outside a marker window.
     *
     * Backends that deliver their marker synchronously - the replay source pumps its whole corpus
     * inside the emitter - satisfy the first wait and never re-emit.
     */
    std::chrono::milliseconds fenceReemitInterval{1};

    /** How many times to retry an unobserved fence marker. */
    uint32_t maxFenceAttempts = 3;

    /** Keep at most this many callback-duration samples for percentile reporting. */
    size_t maxLatencySamples = 1 << 20;

    /**
     * Decides whether a process the broker has no record of belongs to the pip's tree.
     *
     * Injected so the engine stays testable without live processes. When left empty the engine
     * installs the live implementation, which walks the process's ancestry and stops at the broker.
     */
    std::function<ProcessOrigin(const ProcessIdentity &)> processOrigin;

    /**
     * Decides what is actually at a path a LOOKUP names.
     *
     * Endpoint Security reports the path a lookup resolved but nothing about what it found, and the
     * difference decides whether BuildXL sees an innocuous directory probe or an undeclared file
     * read. Injected for the same reason as processOrigin: consulting the real filesystem would make
     * replayed corpora depend on the machine they run on, so tests supply the world the corpus
     * describes. Left empty, the engine installs the live implementation, which stats the path.
     */
    std::function<LookupPathType(const std::string &)> lookupPathType;
};


/**
 * The protocol engine.
 *
 * Owns everything that decides whether the pip's observation set is complete. Deliberately has no
 * dependency on Endpoint Security types: events arrive already normalized, so the engine is exactly
 * as testable as a pure function.
 *
 * Threading: OnEvent() runs on the source's delivery thread and does bounded work only. All decision
 * making happens on the single drain thread inside Drain().
 */
class SandboxEngine
{
public:
    SandboxEngine(
        buildxl::common::FileAccessManifest *manifest,
        ReportSink *sink,
        ProcessIdentity brokerIdentity,
        std::string nonceDirectory,
        FenceProtocol::MarkerEmitter markerEmitter,
        EngineOptions options);

    ~SandboxEngine();

    SandboxEngine(const SandboxEngine &) = delete;
    SandboxEngine &operator=(const SandboxEngine &) = delete;

    /**
     * Accepts one event from the source. Never blocks, never allocates unboundedly, never writes to
     * the filesystem: a rejected event is counted and turned into a taint by the drain thread.
     */
    void OnEvent(NormalizedEvent &&event, std::chrono::nanoseconds deadlineBudget = std::chrono::nanoseconds::max());

    /** Starts the drain thread. */
    void Start();

    /** Registers the pip's root process once it has been launched. */
    void RegisterRoot(const ProcessIdentity &identity, const std::string &executablePath);

    /** Emits the baseline marker and waits for it to be observed. */
    bool EstablishBaseline();

    /**
     * Waits for a fence marker, re-emitting it until it is observed or the fence deadline passes.
     * See EngineOptions::fenceReemitInterval for why a single marker is not enough.
     */
    bool AwaitMarker(FenceProtocol::State desired);

    /**
     * Emits the closing marker and waits for it to be observed, retrying up to maxFenceAttempts.
     * Returns false when no attempt was observed within the timeout.
     */
    bool CloseStream();

    /**
     * Stops the drain thread after processing everything already queued.
     * Must be called after CloseStream().
     */
    void Shutdown();

    /**
     * Final verdict. Any non-kNone result means the pip must not produce a cacheable entry.
     *
     * @param supervisionQuiesced whether independent (non-ES) supervision saw the tree exit
     */
    TaintReason Evaluate(bool supervisionQuiesced) const;

    /** Taint accumulated so far, regardless of closure. */
    TaintReason AccumulatedTaint() const { return m_taint; }

    const EngineStatistics &Statistics() const { return m_stats; }

    const ProcessTable &Processes() const { return m_processes; }

    const FenceProtocol &Fence() const { return m_fence; }

    /** Number of processes the engine currently believes are alive. */
    size_t LiveProcessCount() const { return m_processes.LiveCount(); }

    /**
     * Service names this pip connected to over XPC that the kernel never attested as platform.
     *
     * Empty is the expected shape. A name here is the diagnosable form of a delegation escape: it
     * says which service the pip talked to, which is the only thing that makes the taint
     * actionable. Reported sorted so two runs of the same pip produce the same evidence.
     */
    std::vector<std::string> UnattestedDelegationTargets() const;

private:
    void DrainLoop();
    void ProcessEvent(const NormalizedEvent &event);

    /** Fills in what is actually at a LOOKUP's path, which Endpoint Security does not report. */
    void ResolveLookupTarget(NormalizedEvent &event);
    bool IsBreakawayExec(const NormalizedEvent &event) const;
    void AddTaint(TaintReason reason);

    buildxl::common::FileAccessManifest *m_manifest;
    ReportSink *m_sink;
    const EngineOptions m_options;

    EventTranslator m_translator;
    SequenceTracker m_sequence;
    ProcessTable m_processes;
    std::function<ProcessOrigin(const ProcessIdentity &)> m_processOrigin;
    std::function<LookupPathType(const std::string &)> m_lookupPathType;
    FenceProtocol m_fence;
    BoundedQueue<NormalizedEvent> m_queue;

    // Both are written only on the drain thread, which is the only thread that runs ProcessEvent,
    // and read again once the drain thread has been joined. See UnattestedDelegationTargets.
    std::unordered_set<std::string> m_attestedPlatformServices;
    std::unordered_set<std::string> m_deferredDelegationTargets;

    /**
     * Paths established to be existing directories, so the ancestor chain is stat'ed once.
     *
     * Bounded because a pip that walks a large tree would otherwise make the broker's memory a
     * function of the build rather than of the sandbox. Exceeding the bound costs a syscall per
     * lookup, not correctness.
     */
    static constexpr size_t kMaxKnownDirectories = 1 << 16;
    std::unordered_set<std::string> m_knownDirectories;

    std::thread m_drainThread;
    std::atomic<bool> m_draining{false};
    std::atomic<bool> m_queueOverflowed{false};

    // Written by the drain thread, read by the main thread after Shutdown() or under the relaxed
    // guarantee that a stale read only ever delays a taint, never hides one (the final Evaluate()
    // always runs after the drain thread has been joined).
    std::atomic<uint32_t> m_taintBits{0};
    TaintReason m_taint = TaintReason::kNone;

    EngineStatistics m_stats;
    std::chrono::steady_clock::time_point m_closureRequestedAt;
};

} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_SANDBOX_ENGINE_H
