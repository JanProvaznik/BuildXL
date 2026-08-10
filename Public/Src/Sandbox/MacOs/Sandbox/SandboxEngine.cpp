// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>

#include "SandboxEngine.h"

#include <libproc.h>
#include <unistd.h>

namespace buildxl {
namespace macos {

using buildxl::linux::DebugEventSeverity;
using buildxl::linux::SandboxEvent;

namespace {

uint64_t NowNanos()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

} // namespace

SandboxEngine::SandboxEngine(
    buildxl::common::FileAccessManifest *manifest,
    ReportSink *sink,
    ProcessIdentity brokerIdentity,
    std::string nonceDirectory,
    FenceProtocol::MarkerEmitter markerEmitter,
    EngineOptions options)
    : m_manifest(manifest),
      m_sink(sink),
      m_options(options),
      m_translator(manifest),
      m_fence(std::move(nonceDirectory), brokerIdentity, std::move(markerEmitter)),
      m_queue(options.queueCapacity)
{
    m_stats.callbackNanosSamples.reserve(std::min<size_t>(m_options.maxLatencySamples, 1 << 14));

    // The broker forks the pip's root process, so the root's FORK event names the broker as its
    // parent. Anchoring it here -- before any event can be observed -- is what keeps that first fork
    // from being reported as unmapped lineage. The anchor is synthetic, so it cannot make an
    // unclosed tree look closed.
    if (brokerIdentity.IsValid())
    {
        m_processes.AddSyntheticAncestor(brokerIdentity, "bxl-es-broker");
    }

    m_processOrigin = m_options.processOrigin;
    if (!m_processOrigin)
    {
        m_processOrigin = [brokerIdentity](const ProcessIdentity &identity) {
            return ProbeProcessOrigin(identity, brokerIdentity);
        };
    }
}

ProcessOrigin ProbeProcessOrigin(const ProcessIdentity &identity, const ProcessIdentity &root)
{
    if (!identity.IsValid() || !root.IsValid())
    {
        return ProcessOrigin::kUnknown;
    }

    pid_t current = static_cast<pid_t>(identity.pid);

    // Bounded so that a cycle introduced by pid reuse during the walk cannot spin. Real ancestries
    // are a handful of levels deep; anything past this is not a tree the broker can reason about.
    for (int hops = 0; hops < 64; hops++)
    {
        if (current == static_cast<pid_t>(root.pid))
        {
            return ProcessOrigin::kInsideTree;
        }

        if (current <= 1)
        {
            // launchd, or a process reparented to it. Either way it is outside the pip.
            return ProcessOrigin::kOutsideTree;
        }

        struct proc_bsdinfo info;
        const int read = proc_pidinfo(current, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
        if (read != static_cast<int>(sizeof(info)))
        {
            // The process is gone, so its ancestry cannot be established. Reported as unknown rather
            // than assumed, because assuming "outside" here would silently discard the accesses of a
            // short-lived process that really was ours.
            return ProcessOrigin::kUnknown;
        }

        current = static_cast<pid_t>(info.pbi_ppid);
    }

    return ProcessOrigin::kUnknown;
}

SandboxEngine::~SandboxEngine()
{
    Shutdown();
}

void SandboxEngine::AddTaint(TaintReason reason)
{
    if (reason == TaintReason::kNone)
    {
        return;
    }

    m_taint |= reason;
    m_taintBits.fetch_or(static_cast<uint32_t>(reason), std::memory_order_relaxed);
}

void SandboxEngine::OnEvent(NormalizedEvent &&event, std::chrono::nanoseconds deadlineBudget)
{
    const uint64_t start = NowNanos();

    // Never wait longer than the caller's remaining deadline, and never longer than the configured
    // cap. Both bounds matter: the first keeps the Endpoint Security client alive, the second keeps
    // a wedged report reader from stalling the observed process indefinitely.
    std::chrono::nanoseconds budget =
        std::chrono::duration_cast<std::chrono::nanoseconds>(m_options.maxEnqueueBackpressure);
    if (deadlineBudget < budget)
    {
        budget = deadlineBudget < std::chrono::nanoseconds::zero() ? std::chrono::nanoseconds::zero() : deadlineBudget;
    }

    if (!m_queue.TryEnqueueFor(std::move(event), budget))
    {
        // The only honest response to a full queue. Silently discarding here is precisely the
        // failure mode that produces an unsound cache entry, so the overflow is latched and the pip
        // is tainted even if every other check passes.
        m_queueOverflowed.store(true, std::memory_order_relaxed);
    }

    const uint64_t elapsed = NowNanos() - start;
    m_stats.callbackNanosTotal += elapsed;
    if (elapsed > m_stats.callbackNanosMax)
    {
        m_stats.callbackNanosMax = elapsed;
    }

    if (m_stats.callbackNanosSamples.size() < m_options.maxLatencySamples)
    {
        m_stats.callbackNanosSamples.push_back(elapsed);
    }
}

void SandboxEngine::Start()
{
    if (m_draining.exchange(true))
    {
        return;
    }

    m_drainThread = std::thread([this] { DrainLoop(); });
}

void SandboxEngine::RegisterRoot(const ProcessIdentity &identity, const std::string &executablePath)
{
    m_processes.AddRoot(identity, executablePath, m_sequence.HighestGlobalSequence());
}

bool SandboxEngine::IsBreakawayExec(const NormalizedEvent &event) const
{
    if (m_manifest == nullptr)
    {
        return false;
    }

    std::string arguments = event.commandLine;
    return m_manifest->ShouldBreakaway(event.sourcePath.c_str(), arguments);
}

void SandboxEngine::DrainLoop()
{
    while (true)
    {
        std::deque<NormalizedEvent> batch;
        if (!m_queue.WaitAndDrain(batch))
        {
            break;
        }

        for (NormalizedEvent &event : batch)
        {
            ProcessEvent(event);
        }

        // Reports are buffered by the sink; flushing once per batch keeps the FIFO write count
        // proportional to bursts rather than to individual accesses.
        m_sink->Flush();
    }
}

void SandboxEngine::ProcessEvent(const NormalizedEvent &event)
{
    m_stats.eventsAccepted++;

    // Sequence accounting comes first and unconditionally: a gap must be recorded even for events
    // the engine goes on to ignore, because the gap is evidence about the *stream*, not the event.
    AddTaint(m_sequence.Observe(event));
    m_stats.sequenceGaps = m_sequence.GapCount();
    m_stats.estimatedKernelDrops = m_sequence.EstimatedDroppedMessages();

    if (m_fence.TryConsumeMarker(event))
    {
        m_stats.markerEvents++;
        return;
    }

    if (event.fromBroker)
    {
        // The broker's own filesystem activity is not a pip dependency. Attribution is by audit
        // token, not by path, so this cannot be spoofed by a child that happens to touch the same
        // files.
        m_stats.brokerEventsIgnored++;
        return;
    }

    switch (event.op)
    {
        case NormOp::kFork:
            AddTaint(m_processes.HandleFork(event));
            break;
        case NormOp::kExec:
            AddTaint(m_processes.HandleExec(event, IsBreakawayExec(event)));
            break;
        case NormOp::kExit:
            AddTaint(m_processes.HandleExit(event));
            break;
        default:
            break;
    }

    if (!m_processes.IsTracked(event.self))
    {
        // An event from a process the broker has no record of. There are two very different reasons
        // that happens, and they call for opposite responses.
        //
        // Endpoint Security does deliver events to a descendants client whose acting process is not
        // a descendant: measured on macOS 27, a bootstrap lookup arrives with launchd as its actor,
        // because launchd performs the lookup itself rather than the process that asked for it.
        // Attributing that to the pip was wrong twice over - it reported launchd's activity as a pip
        // dependency, and it raised a delegation-escape taint for something the pip never did.
        //
        // The other reason is a process that really is in the tree whose FORK was never seen, which
        // is a genuine soundness failure. Guessing between them is not good enough, so the origin is
        // established directly, and anything that cannot be established counts as unsound.
        const ProcessOrigin origin = m_processOrigin(event.self);
        if (origin == ProcessOrigin::kOutsideTree)
        {
            m_stats.foreignProcessEvents++;
            m_stats.eventsProcessed++;
            return;
        }

        m_stats.unmappedLineageEvents++;
        AddTaint(TaintReason::kUnmappedLineage);
        m_stats.eventsProcessed++;
        return;
    }

    if (m_processes.IsBreakaway(event.self) && event.op != NormOp::kExit)
    {
        // A process that legitimately broke away is outside the observation domain by design.
        // Its accesses are not reported, and its absence is not a soundness problem.
        m_stats.eventsProcessed++;
        return;
    }

    std::vector<SandboxEvent> translated;
    AddTaint(m_translator.Translate(event, translated));

    for (SandboxEvent &sandboxEvent : translated)
    {
        AddTaint(m_sink->WriteSandboxEvent(sandboxEvent));
    }

    m_stats.reportsWritten = m_sink->ReportsWritten();
    m_stats.eventsProcessed++;
}

bool SandboxEngine::EstablishBaseline()
{
    if (!m_fence.BeginBaseline())
    {
        AddTaint(TaintReason::kFenceTimeout);
        m_stats.markerAttempts = m_fence.MarkerAttempts();
        return false;
    }

    if (!m_fence.WaitFor(FenceProtocol::State::kReady, m_options.fenceTimeout))
    {
        m_fence.MarkTimedOut();
        AddTaint(TaintReason::kFenceTimeout);
        m_stats.markerAttempts = m_fence.MarkerAttempts();
        return false;
    }

    m_stats.markerAttempts = m_fence.MarkerAttempts();
    return true;
}

bool SandboxEngine::CloseStream()
{
    m_closureRequestedAt = std::chrono::steady_clock::now();

    for (uint32_t attempt = 0; attempt < m_options.maxFenceAttempts; attempt++)
    {
        if (!m_fence.BeginClosure())
        {
            continue;
        }

        if (m_fence.WaitFor(FenceProtocol::State::kClosed, m_options.fenceTimeout))
        {
            m_stats.fenceLatencyNanos = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - m_closureRequestedAt)
                    .count());
            m_stats.markerAttempts = m_fence.MarkerAttempts();
            return true;
        }
    }

    m_fence.MarkTimedOut();
    AddTaint(TaintReason::kFenceTimeout);
    m_stats.markerAttempts = m_fence.MarkerAttempts();
    m_stats.fenceLatencyNanos = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - m_closureRequestedAt)
            .count());
    return false;
}

void SandboxEngine::Shutdown()
{
    if (!m_draining.exchange(false))
    {
        return;
    }

    m_queue.Close();
    if (m_drainThread.joinable())
    {
        m_drainThread.join();
    }

    m_stats.queueHighWaterMark = m_queue.HighWaterMark();
    m_stats.eventsRejected = m_queue.EnqueueFailures();
    m_stats.backpressureWaits = m_queue.BackpressureWaits();
    m_stats.backpressureNanos = m_queue.BackpressureNanos();

    // Endpoint Security message versioning is additive: a newer OS grows es_message_t but never
    // changes the fields this broker reads. Failing the build on every OS update would be far worse
    // for usability than surfacing it, so this is a warning and deliberately does not taint.
    if (m_sequence.NewerVersionCount() > 0)
    {
        m_sink->WriteDebugMessage(
            buildxl::linux::DebugEventSeverity::kWarning,
            static_cast<int32_t>(getpid()),
            "macOS sandbox observed " + std::to_string(m_sequence.NewerVersionCount())
                + " Endpoint Security messages newer than the validated version "
                + std::to_string(SequenceTracker::kMaximumKnownMessageVersion)
                + "; fields read by the broker are ABI-stable so the stream is still trusted.");
    }
}

TaintReason SandboxEngine::Evaluate(bool supervisionQuiesced) const
{
    TaintReason result = m_taint;

    // Queue overflow is checked here rather than at enqueue time so that a rejection racing with
    // shutdown still counts.
    const bool overflowed = m_queueOverflowed.load(std::memory_order_relaxed) || m_queue.EnqueueFailures() > 0;

    result |= m_fence.EvaluateClosure(
        TaintReason::kNone,
        overflowed,
        m_processes.IsClosed(),
        supervisionQuiesced);

    if (overflowed)
    {
        result |= TaintReason::kLocalQueueOverflow;
    }

    return result;
}

} // namespace macos
} // namespace buildxl
