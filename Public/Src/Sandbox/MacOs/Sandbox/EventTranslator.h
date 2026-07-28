// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_EVENT_TRANSLATOR_H
#define BUILDXL_SANDBOX_MACOS_EVENT_TRANSLATOR_H

#include <vector>

#include "FileAccessManifest.h"
#include "NormalizedEvent.h"
#include "SandboxEvent.h"
#include "Taint.h"

namespace buildxl {
namespace macos {

/**
 * Turns normalized Endpoint Security events into BuildXL sandbox events.
 *
 * ## Conservative classification
 *
 * The asymmetry that drives every decision here: an access the sandbox *fails* to report can make
 * BuildXL cache a wrong result, while an access it reports *unnecessarily* only costs precision.
 * So whenever the ES event does not pin down the access class exactly, this maps to the stronger
 * (more-reported) interpretation:
 *
 *  - metadata-only operations (stat/access/getattrlist/fsgetpath/chdir) become probes rather than
 *    being dropped, because BuildXL's absent-file probes are real dependencies;
 *  - LOOKUP is reported as a probe for every resolved component, which is what lets warm-cache
 *    builds see the negative lookups that decide an include-path search;
 *  - extended-attribute reads become reads, not probes;
 *  - clonefile/copyfile/exchangedata expand into separate read and write accesses rather than being
 *    modelled as a single opaque operation;
 *  - CLOSE is only reported when ES says the file was modified, which is the one place macOS gives
 *    a write signal that a pure open-flags analysis would miss.
 *
 * Operations that cannot be modelled at all (see IsAlwaysTainting) never reach this class as
 * reportable accesses; they taint the pip instead.
 */
class EventTranslator
{
public:
    explicit EventTranslator(const buildxl::common::FileAccessManifest *manifest)
        : m_manifest(manifest)
    {
    }

    /**
     * Produces the sandbox events for one normalized event, with access checks already applied.
     *
     * @param event  the normalized event
     * @param output receives zero or more fully checked sandbox events
     * @return taint incurred by translating this event
     */
    TaintReason Translate(const NormalizedEvent &event, std::vector<buildxl::linux::SandboxEvent> &output) const;

    /** True when the operation produces no dependency information and is intentionally not reported. */
    static bool IsIgnored(NormOp op);

private:
    buildxl::linux::SandboxEvent MakeEvent(
        const NormalizedEvent &event,
        buildxl::linux::EventType eventType,
        const std::string &sourcePath,
        const std::string &destinationPath) const;

    void Finalize(const NormalizedEvent &event, buildxl::linux::SandboxEvent &sandboxEvent, std::vector<buildxl::linux::SandboxEvent> &output) const;

    const buildxl::common::FileAccessManifest *m_manifest;
};

} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_EVENT_TRANSLATOR_H
