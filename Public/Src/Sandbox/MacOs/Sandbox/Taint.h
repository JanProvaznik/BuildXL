// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_TAINT_H
#define BUILDXL_SANDBOX_MACOS_TAINT_H

#include <cstdint>
#include <string>

namespace buildxl {
namespace macos {

/**
 * Reasons a pip's observed dependency stream may be incomplete or ambiguous.
 *
 * Soundness rule: any non-zero taint must prevent the pip from producing a cacheable result. The
 * broker enforces this by emitting a ReportType::kDebugMessage report with DebugEventSeverity::kError,
 * which makes SandboxedProcessUnix set its infra-error flag and fail (and retry) the pip.
 * CODESYNC: Public/Src/Engine/Processes/SandboxedProcessUnix.cs (HandleAccessReport)
 */
enum class TaintReason : uint32_t
{
    kNone = 0,

    /** The kernel dropped messages for this client (global_seq_num discontinuity). */
    kKernelSequenceGap = 1u << 0,

    /** The broker's own bounded queue could not accept an event. */
    kLocalQueueOverflow = 1u << 1,

    /** The ES client was recreated or lost; sequence numbers restart. */
    kClientEpochChanged = 1u << 2,

    /** The subscription or muting set changed while the pip was active. */
    kSubscriptionChanged = 1u << 3,

    /** A message arrived with a version the broker does not know how to read. */
    kUnknownMessageVersion = 1u << 4,

    /** A path did not fit in the report and had to be truncated. */
    kPathTruncated = 1u << 5,

    /** An event was attributed to a process that is not in the tracked lineage. */
    kUnmappedLineage = 1u << 6,

    /** The closing fence was never observed within its timeout. */
    kFenceTimeout = 1u << 7,

    /** An operation the broker cannot model conservatively was observed. */
    kUnsupportedOperation = 1u << 8,

    /** A descriptor was used whose originating path could not be established. */
    kDescriptorProvenanceUnknown = 1u << 9,

    /** The event source itself failed (client creation, subscribe, read error). */
    kIngressFailure = 1u << 10,

    /** Independent supervision timed out while processes were still alive. */
    kSupervisionTimeout = 1u << 11,

    /** A process delegated work outside the descendant domain (XPC/launchd/NSWorkspace). */
    kDelegationEscape = 1u << 12,

    /** The root process tree did not close cleanly (orphans survived teardown). */
    kLifecycleNotClosed = 1u << 13,

    /** The report sink could not write a report. */
    kReportSinkFailure = 1u << 14,
};

inline TaintReason operator|(TaintReason a, TaintReason b)
{
    return static_cast<TaintReason>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline TaintReason &operator|=(TaintReason &a, TaintReason b)
{
    a = a | b;
    return a;
}

inline bool HasTaint(TaintReason set, TaintReason reason)
{
    return (static_cast<uint32_t>(set) & static_cast<uint32_t>(reason)) != 0;
}

inline bool IsTainted(TaintReason set)
{
    return set != TaintReason::kNone;
}

/** Stable machine-readable names, used by both the error reports and the evidence JSONL. */
const char *TaintReasonName(TaintReason singleReason);

/** Renders a taint set as a '+'-separated list of stable names, or "None". */
std::string TaintSetToString(TaintReason set);

} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_TAINT_H
