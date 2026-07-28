// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_EVENT_SOURCE_H
#define BUILDXL_SANDBOX_MACOS_EVENT_SOURCE_H

#include <functional>
#include <string>

#include "NormalizedEvent.h"

namespace buildxl {
namespace macos {

/**
 * Produces normalized events for the protocol engine.
 *
 * This interface is the reason the broker's correctness logic can be tested at all on a machine
 * without the restricted `com.apple.developer.endpoint-security.client` entitlement. Everything that
 * decides whether a pip may be cached - process attribution, sequence accounting, the fence, taint
 * propagation, translation - sits behind this boundary and never touches an es_message_t.
 *
 * Two implementations exist:
 *  - EsEventSource:     one es_new_descendants_client, one serial dispatch queue.
 *  - ReplayEventSource: a deterministic corpus with scripted fault injection.
 *
 * A run driven by ReplayEventSource is explicitly *not* evidence about macOS kernel behaviour. It is
 * evidence about the broker's protocol, which is a different and separately falsifiable claim.
 */
class EventSource
{
public:
    /** Invoked for every event. Must be safe to call from the source's delivery thread. */
    using EventHandler = std::function<void(NormalizedEvent &&)>;

    virtual ~EventSource() = default;

    /** Establishes the connection and begins delivery. */
    virtual bool Start(EventHandler handler, std::string &errorMessage) = 0;

    /** Stops delivery. Safe to call more than once. */
    virtual void Stop() = 0;

    /**
     * Performs the filesystem touch that generates a fence marker.
     * The event this produces must be observable through the same stream as pip events, otherwise
     * the fence proves nothing.
     */
    virtual bool EmitMarker(const std::string &noncePath) = 0;

    /** The broker's own audit-token identity, used to authenticate fence markers. */
    virtual ProcessIdentity BrokerIdentity() const = 0;

    /** A stable name for evidence records. */
    virtual const char *BackendName() const = 0;

    /**
     * Number of messages the backend itself reports as lost, where the backend can know.
     * Returns 0 when the backend has no such signal (in which case sequence accounting is the only
     * loss detector, which is the normal case for Endpoint Security).
     */
    virtual uint64_t BackendReportedLosses() const { return 0; }
};

} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_EVENT_SOURCE_H
