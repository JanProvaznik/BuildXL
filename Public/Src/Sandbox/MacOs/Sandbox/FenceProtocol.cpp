// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <unistd.h>

#include "FenceProtocol.h"

namespace buildxl {
namespace macos {

FenceProtocol::FenceProtocol(std::string nonceDirectory, ProcessIdentity brokerIdentity, MarkerEmitter emitter)
    : m_nonceDirectory(std::move(nonceDirectory))
    , m_brokerIdentity(brokerIdentity)
    , m_emitter(std::move(emitter))
{
    // The nonce must be unguessable by the pip's processes so that a descendant cannot forge a fence
    // by touching the same path. pid + pidversion is unique for the boot, and the caller is expected
    // to place the nonce directory somewhere only the broker can enumerate.
    m_noncePath = m_nonceDirectory
        + "/bxl-es-fence-"
        + std::to_string(m_brokerIdentity.pid)
        + "-"
        + std::to_string(m_brokerIdentity.pidversion)
        + ".nonce";
}

bool FenceProtocol::EmitMarker()
{
    // Deliberately called with m_mutex released. The emitter touches the filesystem, and for the
    // replay backend it also pumps the whole corpus; holding the lock across that would stall the
    // consumer thread and manufacture a queue overflow that never happened in the real system.
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_markerAttempts++;
    }

    const bool emitted = m_emitter(m_noncePath);
    if (!emitted)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_state = State::kFailed;
        m_changed.notify_all();
    }

    return emitted;
}

bool FenceProtocol::BeginBaseline()
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_state != State::kIdle)
        {
            return false;
        }

        m_state = State::kAwaitingBaseline;
    }

    return EmitMarker();
}

bool FenceProtocol::BeginClosure()
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Retrying an unobserved closure marker is allowed; starting a closure before the baseline
        // was observed is not, because the baseline is what proves self-observation works at all.
        if (m_state != State::kReady && m_state != State::kAwaitingClosure)
        {
            return false;
        }

        m_state = State::kAwaitingClosure;
    }

    return EmitMarker();
}

bool FenceProtocol::WaitFor(State desired, std::chrono::milliseconds timeout) const
{
    std::unique_lock<std::mutex> lock(m_mutex);
    m_changed.wait_for(lock, timeout, [this, desired] {
        return m_state == desired || m_state == State::kFailed;
    });

    return m_state == desired;
}

FenceProtocol::State FenceProtocol::CurrentState() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_state;
}

uint64_t FenceProtocol::BaselineSequence() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_baselineSequence;
}

uint64_t FenceProtocol::ClosureSequence() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_closureSequence;
}

bool FenceProtocol::ReemitMarker()
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_state != State::kAwaitingBaseline && m_state != State::kAwaitingClosure)
        {
            // The window closed while the caller was waiting, so there is nothing to chase.
            return true;
        }
    }

    return EmitMarker();
}

uint32_t FenceProtocol::MarkerAttempts() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_markerAttempts;
}

bool FenceProtocol::IsMarkerEvent(const NormalizedEvent &event) const
{
    // Both conditions are required. The audit token alone is not enough because the broker touches
    // other paths; the path alone is not enough because a descendant could stat the nonce.
    return event.self == m_brokerIdentity && event.sourcePath == m_noncePath;
}

bool FenceProtocol::TryConsumeMarker(const NormalizedEvent &event)
{
    if (!IsMarkerEvent(event))
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    switch (m_state)
    {
        case State::kAwaitingBaseline:
            m_baselineSequence = event.globalSequence;
            m_state = State::kReady;
            m_changed.notify_all();
            return true;

        case State::kAwaitingClosure:
            m_closureSequence = event.globalSequence;
            m_state = State::kClosed;
            m_changed.notify_all();
            return true;

        default:
            // A marker-shaped event outside a marker window. It is still the broker's own event on
            // the broker's own nonce path, so it carries no pip dependency information and must not
            // be reported, but it also must not advance the protocol.
            return true;
    }
}

TaintReason FenceProtocol::EvaluateClosure(
    TaintReason sequenceTaint,
    bool queueOverflowed,
    bool processTreeClosed,
    bool supervisionQuiesced) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    TaintReason taint = sequenceTaint;

    if (m_state != State::kClosed)
    {
        taint |= TaintReason::kFenceTimeout;
    }

    if (queueOverflowed)
    {
        taint |= TaintReason::kLocalQueueOverflow;
    }

    if (!processTreeClosed)
    {
        taint |= TaintReason::kLifecycleNotClosed;
    }

    if (!supervisionQuiesced)
    {
        taint |= TaintReason::kSupervisionTimeout;
    }

    // The closing marker must come strictly after the baseline. If it did not, the client was reset
    // underneath us and the ordering argument does not hold.
    if (m_state == State::kClosed && m_closureSequence <= m_baselineSequence)
    {
        taint |= TaintReason::kClientEpochChanged;
    }

    return taint;
}

void FenceProtocol::MarkTimedOut()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_state = State::kFailed;
    m_changed.notify_all();
}

const char *FenceProtocol::StateName(State state)
{
    switch (state)
    {
        case State::kIdle:             return "Idle";
        case State::kAwaitingBaseline: return "AwaitingBaseline";
        case State::kReady:            return "Ready";
        case State::kAwaitingClosure:  return "AwaitingClosure";
        case State::kClosed:           return "Closed";
        case State::kFailed:           return "Failed";
        default:                       return "Unknown";
    }
}

} // namespace macos
} // namespace buildxl
