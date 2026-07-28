// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "Taint.h"

namespace buildxl {
namespace macos {

const char *TaintReasonName(TaintReason singleReason)
{
    switch (singleReason)
    {
        case TaintReason::kNone:                        return "None";
        case TaintReason::kKernelSequenceGap:           return "KernelSequenceGap";
        case TaintReason::kLocalQueueOverflow:          return "LocalQueueOverflow";
        case TaintReason::kClientEpochChanged:          return "ClientEpochChanged";
        case TaintReason::kSubscriptionChanged:         return "SubscriptionChanged";
        case TaintReason::kUnknownMessageVersion:       return "UnknownMessageVersion";
        case TaintReason::kPathTruncated:               return "PathTruncated";
        case TaintReason::kUnmappedLineage:             return "UnmappedLineage";
        case TaintReason::kFenceTimeout:                return "FenceTimeout";
        case TaintReason::kUnsupportedOperation:        return "UnsupportedOperation";
        case TaintReason::kDescriptorProvenanceUnknown: return "DescriptorProvenanceUnknown";
        case TaintReason::kIngressFailure:              return "IngressFailure";
        case TaintReason::kSupervisionTimeout:          return "SupervisionTimeout";
        case TaintReason::kDelegationEscape:            return "DelegationEscape";
        case TaintReason::kLifecycleNotClosed:          return "LifecycleNotClosed";
        case TaintReason::kReportSinkFailure:           return "ReportSinkFailure";
        default:                                        return "Unknown";
    }
}

std::string TaintSetToString(TaintReason set)
{
    if (!IsTainted(set))
    {
        return "None";
    }

    std::string result;
    uint32_t bits = static_cast<uint32_t>(set);
    for (uint32_t bit = 0; bit < 32; bit++)
    {
        uint32_t mask = 1u << bit;
        if ((bits & mask) == 0)
        {
            continue;
        }

        if (!result.empty())
        {
            result += "+";
        }

        result += TaintReasonName(static_cast<TaintReason>(mask));
    }

    return result;
}

} // namespace macos
} // namespace buildxl
