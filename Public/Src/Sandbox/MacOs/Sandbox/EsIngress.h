// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_ES_INGRESS_H
#define BUILDXL_SANDBOX_MACOS_ES_INGRESS_H

#include <atomic>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "EventSource.h"

// The broker builds on machines whose SDK predates the descendants client; the ES-specific code then
// compiles out and EsIngress::Start() fails with an actionable message instead of the link failing.
#if defined(__has_include)
#if __has_include(<EndpointSecurity/EndpointSecurity.h>)
#define BXL_ES_SDK_AVAILABLE 1
#endif
#endif

#ifndef BXL_ES_SDK_AVAILABLE
#define BXL_ES_SDK_AVAILABLE 0
#endif

#if BXL_ES_SDK_AVAILABLE
#include <EndpointSecurity/EndpointSecurity.h>
#endif

namespace buildxl {
namespace macos {

/** Tuning knobs for the Endpoint Security client. */
struct EsIngressOptions
{
    /**
     * Retries when the system is already at its Endpoint Security client limit.
     *
     * BuildXL runs one broker per concurrently executing pip, so hitting the limit is a routine
     * scheduling collision rather than an error. Failing the pip immediately would make macOS builds
     * flaky in exactly the way this port exists to prevent.
     */
    uint32_t maxClientRetries = 60;

    /** Initial backoff between client-creation retries; doubles up to maxRetryBackoffMillis. */
    uint32_t initialRetryBackoffMillis = 50;
    uint32_t maxRetryBackoffMillis = 1000;

    /**
     * Subscribe to the operations that can only change process state, not file state.
     *
     * These never contribute dependencies but they do reveal that the observed tree reached outside
     * its own lineage (XPC, task ports, ptrace), which the engine turns into a taint. Leaving them
     * off is faster and still sound for file accesses; leaving them on is what makes "no undetected
     * delegation" a claim rather than a hope.
     */
    bool subscribeToDelegationEvents = true;

    /**
     * Subscribe to the read-only metadata operations (stat/access/getattrlist/...).
     *
     * On Linux these are observed, so they are observed here too; they matter because a tool that
     * probes for a file it does not find still has a dependency on that absence.
     */
    bool subscribeToProbeEvents = true;
};

/**
 * The real ingress: one es_new_descendants_client, whose handler block does bounded work and hands
 * every message to the engine.
 *
 * Two properties of the descendants client are what make this design viable at all, and both were
 * verified against the macOS 27.0 SDK headers rather than assumed:
 *
 *  1. It reports the calling process and its descendants only, so a broker per pip sees exactly the
 *     pip's process tree. No filtering by pid, no races attributing events to the wrong pip.
 *  2. "Messages are handled strictly serially and in the order they are delivered." That ordering is
 *     what lets a fence marker prove that every earlier event has already been seen.
 *
 * The handler deliberately does no policy evaluation and no I/O. It validates, extracts, and
 * enqueues. Everything expensive happens on the drain thread, because an Endpoint Security handler
 * that overruns its deadline gets its client killed.
 */
class EsIngress : public EventSource
{
public:
    explicit EsIngress(EsIngressOptions options = EsIngressOptions());
    ~EsIngress() override;

    bool Start(EventHandler handler, std::string &errorMessage) override;
    void Stop() override;
    bool EmitMarker(const std::string &noncePath) override;
    ProcessIdentity BrokerIdentity() const override { return m_broker; }
    const char *BackendName() const override { return "endpoint-security-descendants"; }

    /** True when this build of the broker can talk to Endpoint Security at all. */
    static bool IsCompiledIn() { return BXL_ES_SDK_AVAILABLE != 0; }

#if BXL_ES_SDK_AVAILABLE
    /** Names an es_new_client failure. Exposed so `bxl-es-broker --probe-es` can report it. */
    static const char *DescribeNewClientResult(es_new_client_result_t result);
#endif

    /** Number of self-generated events dropped before reaching the engine. */
    uint64_t SelfEventsSuppressed() const { return m_selfEventsSuppressed.load(std::memory_order_relaxed); }

    /** Events that could not be mapped to a NormOp and were therefore passed through as unknown. */
    uint64_t UnmappedEvents() const { return m_unmappedEvents.load(std::memory_order_relaxed); }

private:
#if BXL_ES_SDK_AVAILABLE
    /** Invoked by the Endpoint Security handler block for every message. */
    void HandleMessage(const es_message_t *message);

    /** Translates one ES message. Returns false when the message must not reach the engine. */
    bool Normalize(const es_message_t *message, NormalizedEvent &out) const;

    std::vector<es_event_type_t> SubscriptionSet() const;

    es_client_t *m_client = nullptr;
#endif

    EsIngressOptions m_options;
    EventHandler m_handler;
    ProcessIdentity m_broker;
    std::string m_noncePath;
    mutable std::atomic<uint64_t> m_selfEventsSuppressed{0};
    mutable std::atomic<uint64_t> m_unmappedEvents{0};

    // Suppressed-message accounting for SequenceTracker. Only ever touched from the Endpoint
    // Security handler block, which runs on a serial queue, so plain members are correct here and
    // atomics would only obscure that.
    uint64_t m_suppressedSinceForward = 0;
    std::unordered_map<uint16_t, uint64_t> m_suppressedSinceForwardByType;

    std::atomic<bool> m_running{false};
};

} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_ES_INGRESS_H
