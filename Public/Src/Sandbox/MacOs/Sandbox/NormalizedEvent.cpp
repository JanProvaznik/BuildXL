// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "NormalizedEvent.h"

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
        // A process handing work to a service outside the descendant domain means the resulting file
        // accesses are not visible to this client, so the observation set is unsound by construction.
        case NormOp::kUipcConnect:
        case NormOp::kXpcConnect:
        case NormOp::kBootstrapLookUp:
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

} // namespace macos
} // namespace buildxl
