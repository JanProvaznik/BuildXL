// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_FENCE_PROTOCOL_H
#define BUILDXL_SANDBOX_MACOS_FENCE_PROTOCOL_H

#include <cstdint>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>

#include "NormalizedEvent.h"
#include "Taint.h"

namespace buildxl {
namespace macos {

/**
 * Establishes that a pip's Endpoint Security stream is closed before its result may be cached.
 *
 * ## Why a fence is needed
 *
 * Neither "the root process exited" nor "waitpid returned" proves that every file-access event the
 * pip's tree generated has been *delivered*. ES delivery is asynchronous, so a causally earlier
 * access can still be in flight when the process is already gone. Committing at that point would
 * cache a result computed from an incomplete dependency set.
 *
 * ## The protocol
 *
 * 1. Before launching anything, the broker touches a private nonce path and records the client
 *    sequence of the resulting event. This proves the broker can observe its own events, which is
 *    the property the whole protocol rests on, and it fails loudly at startup if it does not hold.
 * 2. The pip runs. FORK/EXEC/EXIT are tracked by audit token, and the runner's process group is
 *    supervised independently of ES (ES EXIT is never the only liveness source).
 * 3. When supervision reports quiescence *and* the tracked process set is closed, the broker touches
 *    the nonce path again. This event is generated strictly after every event the tree could have
 *    generated, so it has a strictly higher global_seq_num than all of them.
 * 4. A fence is accepted only when the event's audit token is the broker's own *and* the path is the
 *    exact nonce. Neither check alone is sufficient: a descendant could stat the nonce path, and the
 *    broker touches other paths as part of its own work.
 * 5. Local processing then drains up to the fence's sequence.
 * 6. The result is cacheable only if the sequence is contiguous through the fence, the client epoch
 *    never changed, the local queue never overflowed, and no other taint was raised.
 *
 * Step 3's precondition is what makes the ordering argument sound: once every process has been
 * observed exiting, no operation of the tree can still be running, so no further event of the tree
 * can be *generated*. Any event generated after that point is the fence or later.
 *
 * A fence that never arrives within its timeout produces TaintReason::kFenceTimeout. There is no
 * code path that treats a missing fence as success.
 */
class FenceProtocol
{
public:
    /**
     * Performs the filesystem touch that generates a marker event.
     * Injectable so the conformance harness can drive the protocol deterministically.
     * Returns false when the touch could not be performed.
     */
    using MarkerEmitter = std::function<bool(const std::string &noncePath)>;

    enum class State
    {
        /** Nothing has been attempted yet. */
        kIdle,

        /** The baseline marker was emitted; waiting for it to be observed. */
        kAwaitingBaseline,

        /** The baseline was observed. The pip may run. */
        kReady,

        /** The closing marker was emitted; waiting for it to be observed. */
        kAwaitingClosure,

        /** The closing marker was observed; the stream is closed. */
        kClosed,

        /** A marker was never observed, or the protocol was otherwise violated. */
        kFailed,
    };

    /**
     * @param nonceDirectory a directory the broker owns; the nonce path is created inside it
     * @param brokerIdentity the broker's own audit-token identity
     * @param emitter        performs the filesystem touch
     */
    FenceProtocol(std::string nonceDirectory, ProcessIdentity brokerIdentity, MarkerEmitter emitter);

    /** Emits the baseline marker. */
    bool BeginBaseline();

    /** Emits the closing marker. May be called again to retry. */
    bool BeginClosure();

    /**
     * Offers an event to the protocol.
     *
     * @return true when the event was the marker currently being awaited (and therefore must not be
     *         reported as a pip dependency).
     */
    bool TryConsumeMarker(const NormalizedEvent &event);

    /**
     * Decides whether the pip's stream may be treated as closed.
     *
     * @param sequenceTaint       taint accumulated by the sequence tracker
     * @param queueOverflowed     whether the local bounded queue ever refused an item
     * @param processTreeClosed   whether every tracked process was observed exiting
     * @param supervisionQuiesced whether independent supervision reported the tree gone
     */
    TaintReason EvaluateClosure(
        TaintReason sequenceTaint,
        bool queueOverflowed,
        bool processTreeClosed,
        bool supervisionQuiesced) const;

    /**
     * Blocks until the protocol reaches the desired state, fails, or the timeout expires.
     * Returns true only for the desired state.
     */
    bool WaitFor(State desired, std::chrono::milliseconds timeout) const;

    /** Marks the protocol failed because a marker was never observed. */
    void MarkTimedOut();

    State CurrentState() const;

    const std::string &NoncePath() const { return m_noncePath; }

    /** Client sequence at which the baseline marker was observed. */
    uint64_t BaselineSequence() const;

    /** Client sequence at which the closing marker was observed; 0 if not yet. */
    uint64_t ClosureSequence() const;

    uint32_t MarkerAttempts() const;

    /**
     * Emits another copy of the marker for the window already in progress.
     *
     * Endpoint Security holds a nearly-idle NOTIFY queue for ~251 ms before flushing it, so a fence
     * that emits once and waits pays that latency twice per pip. Re-emitting is safe: the marker is
     * a side-effect-free probe of a path that does not exist, and TryConsumeMarker already discards
     * marker-shaped events that arrive when no window is open. Returns false only if the emitter
     * itself failed, which fails the fence exactly as an initial emission failure does.
     */
    bool ReemitMarker();

    static const char *StateName(State state);

private:
    bool IsMarkerEvent(const NormalizedEvent &event) const;
    bool EmitMarker();

    mutable std::mutex m_mutex;
    mutable std::condition_variable m_changed;

    const std::string m_nonceDirectory;
    const ProcessIdentity m_brokerIdentity;
    const MarkerEmitter m_emitter;

    std::string m_noncePath;
    State m_state = State::kIdle;
    uint64_t m_baselineSequence = 0;
    uint64_t m_closureSequence = 0;
    uint32_t m_markerAttempts = 0;
};

} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_FENCE_PROTOCOL_H
