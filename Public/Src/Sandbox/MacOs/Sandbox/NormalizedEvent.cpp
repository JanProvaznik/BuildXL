// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "NormalizedEvent.h"

#include <cstring>
#include <vector>

namespace buildxl {
namespace macos {

const char *NormOpName(NormOp op)
{
    switch (op)
    {
        case NormOp::kFork:               return "fork";
        case NormOp::kExec:               return "exec";
        case NormOp::kExit:               return "exit";
        case NormOp::kLookup:             return "lookup";
        case NormOp::kOpen:               return "open";
        case NormOp::kClose:              return "close";
        case NormOp::kReaddir:            return "readdir";
        case NormOp::kReadlink:           return "readlink";
        case NormOp::kStat:               return "stat";
        case NormOp::kAccess:             return "access";
        case NormOp::kGetAttrList:        return "getattrlist";
        case NormOp::kGetExtAttr:         return "getxattr";
        case NormOp::kListExtAttr:        return "listxattr";
        case NormOp::kMmap:               return "mmap";
        case NormOp::kFsGetPath:          return "fsgetpath";
        case NormOp::kSearchFs:           return "searchfs";
        case NormOp::kChdir:              return "chdir";
        case NormOp::kDup:                return "dup";
        case NormOp::kFcntl:              return "fcntl";
        case NormOp::kCreate:             return "create";
        case NormOp::kWrite:              return "write";
        case NormOp::kTruncate:           return "truncate";
        case NormOp::kUnlink:             return "unlink";
        case NormOp::kRename:             return "rename";
        case NormOp::kLink:               return "link";
        case NormOp::kClone:              return "clonefile";
        case NormOp::kCopyFile:           return "copyfile";
        case NormOp::kExchangeData:       return "exchangedata";
        case NormOp::kSetAttrList:        return "setattrlist";
        case NormOp::kSetExtAttr:         return "setxattr";
        case NormOp::kDeleteExtAttr:      return "removexattr";
        case NormOp::kSetFlags:           return "chflags";
        case NormOp::kSetMode:            return "chmod";
        case NormOp::kSetOwner:           return "chown";
        case NormOp::kSetAcl:             return "setacl";
        case NormOp::kUtimes:             return "utimes";
        case NormOp::kUipcConnect:        return "uipc_connect";
        case NormOp::kXpcConnect:         return "xpc_connect";
        case NormOp::kBootstrapLookUp:    return "bootstrap_look_up";
        case NormOp::kRemoteThreadCreate: return "remote_thread_create";
        case NormOp::kGetTask:            return "get_task";
        case NormOp::kTrace:              return "trace";
        case NormOp::kProcSuspendResume:  return "proc_suspend_resume";
        case NormOp::kChroot:             return "chroot";
        case NormOp::kMount:              return "mount";
        case NormOp::kUnmount:            return "unmount";
        case NormOp::kRemount:            return "remount";
        case NormOp::kSetUid:             return "setuid";
        case NormOp::kUnsupported:        return "unsupported";
        case NormOp::kUnknown:
        case NormOp::kMax:
        default:                          return "unknown";
    }
}

bool IsRelevantForDependencies(NormOp op)
{
    switch (op)
    {
        // Close/dup/fcntl carry no dependency information on their own; they are subscribed to only
        // so that descriptor provenance can be tracked.
        case NormOp::kClose:
        case NormOp::kDup:
        case NormOp::kFcntl:
        case NormOp::kUnknown:
        case NormOp::kMax:
            return false;
        default:
            return true;
    }
}

bool IsAlwaysTainting(NormOp op)
{
    switch (op)
    {
        // Injecting into, or seizing control of, another process is a genuine escape: the target can
        // perform filesystem work attributed to nothing the broker is watching. These are rare in a
        // build - a compile of a C file produces none - so tainting on them costs nothing real.
        case NormOp::kRemoteThreadCreate:
        case NormOp::kGetTask:
        case NormOp::kTrace:
        case NormOp::kProcSuspendResume:
        // chroot/mount/unmount/remount change how lexical paths resolve, which invalidates every
        // path the broker has already reported.
        case NormOp::kChroot:
        case NormOp::kMount:
        case NormOp::kUnmount:
        case NormOp::kRemount:
        // A uid change can move the process out of the observable domain and changes access checks.
        case NormOp::kSetUid:
        case NormOp::kUnsupported:
            return true;
        default:
            return false;
    }
}

bool IsDelegation(NormOp op)
{
    return op == NormOp::kUipcConnect || op == NormOp::kXpcConnect || op == NormOp::kBootstrapLookUp;
}

bool IsMutation(NormOp op)
{
    switch (op)
    {
        case NormOp::kCreate:
        case NormOp::kWrite:
        case NormOp::kTruncate:
        case NormOp::kUnlink:
        case NormOp::kRename:
        case NormOp::kLink:
        case NormOp::kClone:
        case NormOp::kCopyFile:
        case NormOp::kExchangeData:
            return true;
        default:
            return false;
    }
}

bool IsDelegationEscape(const NormalizedEvent &event)
{
    switch (event.op)
    {
        // Resolving a service name to a port delegates nothing; it is the macOS equivalent of a DNS
        // lookup. What matters is what the process then does with the port, and that shows up as an
        // XPC connect, which is judged on its own. Tainting here would taint every process on the
        // system, because looking up com.apple.logd is part of starting up.
        case NormOp::kBootstrapLookUp:
            return false;

        // A channel to a platform service in the system domain is not an escape this sandbox models,
        // for the same reason neither Detours nor the Linux sandbox models it. A channel to anything
        // else may be the pip talking to its own daemon - a compiler server being the case BuildXL
        // already knows about - and that genuinely can do undeclared work on the pip's behalf.
        case NormOp::kXpcConnect:
            return !event.delegationTargetIsPlatform;

        // A UNIX-domain socket connect names a file, so it is judged as a file access against the
        // manifest like any other rather than as a category. The production Linux sandbox does not
        // intercept connect() at all, so this is already stricter than the supported Unix platform.
        case NormOp::kUipcConnect:
            return false;

        default:
            return false;
    }
}

void CleanPath(std::string &path)
{
    // Relative paths cannot be cleaned without a working directory, and ES never reports one.
    if (path.size() < 2 || path[0] != '/')
    {
        return;
    }

    // A trailing separator is checked too: ES reports directory lookups as `.../AppleInternal/`,
    // and the manifest's tree stores that directory without the separator.
    if (path.find("/.") == std::string::npos && path.find("//") == std::string::npos &&
        path.back() != '/')
    {
        return;
    }

    // Offsets of each retained segment's first character, so `..` can pop the previous one.
    std::vector<size_t> segmentStarts;
    size_t write = 1;

    for (size_t read = 1; read <= path.size();)
    {
        size_t end = path.find('/', read);
        if (end == std::string::npos)
        {
            end = path.size();
        }

        const size_t length = end - read;
        if (length == 0)
        {
            // A duplicate separator names the same directory as one separator.
        }
        else if (length == 1 && path[read] == '.')
        {
            // `.` names the directory it sits in.
        }
        else if (length == 2 && path[read] == '.' && path[read + 1] == '.')
        {
            if (!segmentStarts.empty())
            {
                write = segmentStarts.back();
                segmentStarts.pop_back();
            }
            // At the root `..` is the root, so there is nothing to pop and nothing to write.
        }
        else
        {
            segmentStarts.push_back(write);
            if (write != read)
            {
                std::memmove(&path[write], &path[read], length);
            }

            write += length;
            path[write++] = '/';
        }

        read = end + 1;
    }

    // Every retained segment wrote a trailing separator; the last one is only wanted for the root.
    if (write > 1)
    {
        --write;
    }

    path.resize(write);
}

} // namespace macos
} // namespace buildxl
