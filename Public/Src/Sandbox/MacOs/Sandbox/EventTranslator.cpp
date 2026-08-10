// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <sys/stat.h>

#include "AccessChecker.h"
#include "EventTranslator.h"

namespace buildxl {
namespace macos {

using buildxl::linux::AccessChecker;
using buildxl::linux::EventType;
using buildxl::linux::RequiredPathResolution;
using buildxl::linux::SandboxEvent;
using buildxl::linux::SandboxEventPathType;

bool EventTranslator::IsIgnored(NormOp op)
{
    switch (op)
    {
        // Descriptor bookkeeping only. Dup/fcntl carry no path, and close is handled separately
        // (it is reported only when it signals a modification).
        case NormOp::kDup:
        case NormOp::kFcntl:
        case NormOp::kUnknown:
        case NormOp::kMax:
            return true;
        default:
            return false;
    }
}

SandboxEvent EventTranslator::MakeEvent(
    const NormalizedEvent &event,
    EventType eventType,
    const std::string &sourcePath,
    const std::string &destinationPath) const
{
    SandboxEvent sandboxEvent = SandboxEvent::AbsolutePathSandboxEvent(
        NormOpName(event.op),
        eventType,
        static_cast<pid_t>(event.self.pid),
        static_cast<pid_t>(event.parent.pid),
        static_cast<uint>(event.error),
        sourcePath,
        destinationPath);

    if (!sandboxEvent.IsValid())
    {
        return sandboxEvent;
    }

    // Endpoint Security already hands us fully resolved absolute paths, so re-resolving would both
    // waste syscalls and, worse, produce filesystem accesses from the broker that the client would
    // then observe.
    sandboxEvent.SetRequiredPathResolution(RequiredPathResolution::kDoNotResolve);

    // Mode drives IsDirectory()/PathExists(), which the access checker uses to pick between read,
    // enumerate and probe. A mode of 0 means "does not exist", which is exactly what a failed
    // lookup or a create-of-a-new-file should look like.
    mode_t mode = 0;
    if (event.sourceExists)
    {
        mode = event.sourceIsDirectory ? S_IFDIR : S_IFREG;
    }

    sandboxEvent.SetMode(mode);
    return sandboxEvent;
}

void EventTranslator::Finalize(
    const NormalizedEvent &event,
    SandboxEvent &sandboxEvent,
    std::vector<SandboxEvent> &output) const
{
    if (!sandboxEvent.IsValid())
    {
        return;
    }

    AccessChecker::CheckAccessAndGetReport(m_manifest, sandboxEvent, /* basedOnPolicy */ false);
    output.push_back(sandboxEvent);
}

TaintReason EventTranslator::Translate(const NormalizedEvent &event, std::vector<SandboxEvent> &output) const
{
    TaintReason taint = TaintReason::kNone;

    if (event.sourcePathTruncated || event.destinationPathTruncated)
    {
        // A truncated path cannot be matched against the manifest, so the access it represents
        // cannot be classified. Reporting the prefix would be worse than useless.
        taint |= TaintReason::kPathTruncated;
    }

    if (IsAlwaysTainting(event.op))
    {
        taint |= event.op == NormOp::kUnsupported
            ? TaintReason::kUnsupportedOperation
            : TaintReason::kDelegationEscape;
        return taint;
    }

    if (IsDelegation(event.op))
    {
        if (IsDelegationEscape(event))
        {
            taint |= TaintReason::kDelegationEscape;
            return taint;
        }

        // A benign delegation still reports its target when that target is a path the manifest
        // cares about, which is how a UNIX-domain socket connect gets treated as the file access it
        // is. Anything without a path - a service name - has nothing to report and falls out here.
        if (event.sourcePath.empty() || event.op != NormOp::kUipcConnect)
        {
            return taint;
        }
    }

    if (IsIgnored(event.op))
    {
        return taint;
    }

    if (event.descriptorOnly && event.sourcePath.empty())
    {
        // The operation targeted a descriptor whose originating path could not be recovered.
        taint |= TaintReason::kDescriptorProvenanceUnknown;
        return taint;
    }

    switch (event.op)
    {
        case NormOp::kFork:
        {
            SandboxEvent sandboxEvent = SandboxEvent::CloneSandboxEvent(
                NormOpName(event.op),
                static_cast<pid_t>(event.self.pid),
                static_cast<pid_t>(event.parent.pid),
                event.sourcePath);
            sandboxEvent.SetRequiredPathResolution(RequiredPathResolution::kDoNotResolve);
            Finalize(event, sandboxEvent, output);
            break;
        }

        case NormOp::kExec:
        {
            SandboxEvent sandboxEvent = SandboxEvent::ExecSandboxEvent(
                NormOpName(event.op),
                static_cast<pid_t>(event.self.pid),
                static_cast<pid_t>(event.parent.pid),
                event.sourcePath,
                event.commandLine);
            sandboxEvent.SetRequiredPathResolution(RequiredPathResolution::kDoNotResolve);
            sandboxEvent.SetMode(S_IFREG);
            Finalize(event, sandboxEvent, output);
            break;
        }

        case NormOp::kExit:
        {
            SandboxEvent sandboxEvent = SandboxEvent::ExitSandboxEvent(
                NormOpName(event.op),
                event.sourcePath,
                static_cast<pid_t>(event.self.pid),
                static_cast<pid_t>(event.parent.pid));
            sandboxEvent.SetRequiredPathResolution(RequiredPathResolution::kDoNotResolve);
            Finalize(event, sandboxEvent, output);
            break;
        }

        // Path resolution and metadata inspection. All of these are probes: BuildXL treats the
        // absence of a file as an observable input, so dropping them would allow a build to be
        // reused after a file appeared on a search path.
        case NormOp::kLookup:
        case NormOp::kStat:
        case NormOp::kAccess:
        case NormOp::kGetAttrList:
        case NormOp::kFsGetPath:
        case NormOp::kChdir:
        // Connecting to a UNIX-domain socket requires the socket file to exist, which is an
        // observable dependency on the path: a build that behaves one way when a socket is present
        // and another way when it is absent must not be reused across that difference. It is a
        // probe rather than a read because a socket has no content to hash.
        case NormOp::kUipcConnect:
        {
            SandboxEvent sandboxEvent = MakeEvent(event, EventType::kGenericProbe, event.sourcePath, "");
            Finalize(event, sandboxEvent, output);
            break;
        }

        case NormOp::kOpen:
        case NormOp::kReaddir:
        {
            SandboxEvent sandboxEvent = MakeEvent(event, EventType::kOpen, event.sourcePath, "");
            Finalize(event, sandboxEvent, output);
            break;
        }

        case NormOp::kReadlink:
        {
            SandboxEvent sandboxEvent = MakeEvent(event, EventType::kReadLink, event.sourcePath, "");
            Finalize(event, sandboxEvent, output);
            break;
        }

        // Content reads.
        case NormOp::kGetExtAttr:
        case NormOp::kListExtAttr:
        case NormOp::kMmap:
        case NormOp::kSearchFs:
        {
            SandboxEvent sandboxEvent = MakeEvent(event, EventType::kGenericRead, event.sourcePath, "");
            Finalize(event, sandboxEvent, output);
            break;
        }

        case NormOp::kCreate:
        {
            SandboxEvent sandboxEvent = MakeEvent(event, EventType::kCreate, event.sourcePath, "");
            Finalize(event, sandboxEvent, output);
            break;
        }

        // Content and metadata writes.
        case NormOp::kWrite:
        case NormOp::kTruncate:
        case NormOp::kSetAttrList:
        case NormOp::kSetExtAttr:
        case NormOp::kDeleteExtAttr:
        case NormOp::kSetFlags:
        case NormOp::kSetMode:
        case NormOp::kSetOwner:
        case NormOp::kSetAcl:
        case NormOp::kUtimes:
        {
            SandboxEvent sandboxEvent = MakeEvent(event, EventType::kGenericWrite, event.sourcePath, "");
            Finalize(event, sandboxEvent, output);
            break;
        }

        case NormOp::kClose:
        {
            // ES sets 'modified' on close when the file was written through this descriptor. That is
            // the most reliable write signal macOS gives us, because a descriptor opened for writing
            // is not proof that anything was written.
            if (event.succeeded)
            {
                SandboxEvent sandboxEvent = MakeEvent(event, EventType::kGenericWrite, event.sourcePath, "");
                Finalize(event, sandboxEvent, output);
            }
            break;
        }

        case NormOp::kUnlink:
        {
            SandboxEvent sandboxEvent = MakeEvent(event, EventType::kUnlink, event.sourcePath, "");
            Finalize(event, sandboxEvent, output);
            break;
        }

        case NormOp::kRename:
        {
            SandboxEvent sandboxEvent = MakeEvent(event, EventType::kRename, event.sourcePath, event.destinationPath);
            Finalize(event, sandboxEvent, output);
            break;
        }

        case NormOp::kLink:
        {
            SandboxEvent sandboxEvent = MakeEvent(event, EventType::kLink, event.sourcePath, event.destinationPath);
            Finalize(event, sandboxEvent, output);
            break;
        }

        // clonefile/copyfile copy content into a brand new file. Modelling that as a single opaque
        // operation would hide the fact that the source is a real content dependency, so it is split
        // into an explicit read of the source and a create of the destination.
        case NormOp::kClone:
        case NormOp::kCopyFile:
        {
            SandboxEvent readEvent = MakeEvent(event, EventType::kGenericRead, event.sourcePath, "");
            Finalize(event, readEvent, output);

            if (!event.destinationPath.empty())
            {
                NormalizedEvent destinationView = event;
                destinationView.sourceExists = event.destinationExists;
                destinationView.sourceIsDirectory = event.destinationIsDirectory;

                SandboxEvent writeEvent = MakeEvent(destinationView, EventType::kCreate, event.destinationPath, "");
                Finalize(destinationView, writeEvent, output);
            }
            break;
        }

        // exchangedata swaps the contents of two files, so both are read and both are written.
        case NormOp::kExchangeData:
        {
            SandboxEvent sourceRead = MakeEvent(event, EventType::kGenericRead, event.sourcePath, "");
            Finalize(event, sourceRead, output);

            SandboxEvent sourceWrite = MakeEvent(event, EventType::kGenericWrite, event.sourcePath, "");
            Finalize(event, sourceWrite, output);

            if (!event.destinationPath.empty())
            {
                NormalizedEvent destinationView = event;
                destinationView.sourceExists = event.destinationExists;
                destinationView.sourceIsDirectory = event.destinationIsDirectory;

                SandboxEvent destinationRead = MakeEvent(destinationView, EventType::kGenericRead, event.destinationPath, "");
                Finalize(destinationView, destinationRead, output);

                SandboxEvent destinationWrite = MakeEvent(destinationView, EventType::kGenericWrite, event.destinationPath, "");
                Finalize(destinationView, destinationWrite, output);
            }
            break;
        }

        default:
        {
            // A subscribed event type with no mapping. Failing closed here is what keeps the
            // translator honest as new ES event types appear in future OS releases.
            taint |= TaintReason::kUnsupportedOperation;
            break;
        }
    }

    return taint;
}

} // namespace macos
} // namespace buildxl
