// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "EsIngress.h"

#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <thread>

namespace buildxl {
namespace macos {

namespace {

#if BXL_ES_SDK_AVAILABLE

inline std::string TokenToString(const es_string_token_t &token)
{
    return token.data != nullptr && token.length > 0 ? std::string(token.data, token.length) : std::string();
}

inline std::string JoinDirAndName(const es_file_t *dir, const es_string_token_t &name)
{
    std::string result = TokenToString(dir->path);
    if (!result.empty() && result.back() != '/')
    {
        result.push_back('/');
    }

    result.append(TokenToString(name));
    return result;
}

inline bool IsDirectory(const es_file_t *file)
{
    return S_ISDIR(file->stat.st_mode);
}

inline ProcessIdentity IdentityOf(const audit_token_t &token)
{
    ProcessIdentity identity;
    identity.pid = audit_token_to_pid(token);
    identity.pidversion = audit_token_to_pidversion(token);
    return identity;
}

const char *NewClientResultToString(es_new_client_result_t result)
{
    switch (result)
    {
        case ES_NEW_CLIENT_RESULT_SUCCESS: return "success";
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: return "invalid argument";
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL: return "internal error";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: return "not entitled";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: return "not permitted";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: return "not privileged";
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: return "too many clients";
        default: return "unrecognized result";
    }
}

#endif // BXL_ES_SDK_AVAILABLE

} // namespace

EsIngress::EsIngress(EsIngressOptions options)
    : m_options(options)
{
    m_broker.pid = static_cast<int32_t>(getpid());
    m_broker.pidversion = 0;

    // The broker's identity has to be expressed the same way ES expresses it, because it is compared
    // against identities derived from audit tokens -- in particular it is the parent recorded on the
    // root process's FORK event. A pid alone would not match, since ProcessIdentity compares
    // pidversion too. TASK_AUDIT_TOKEN is the supported way to obtain one's own token.
    audit_token_t token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, reinterpret_cast<task_info_t>(&token), &count) == KERN_SUCCESS)
    {
        m_broker.pidversion = audit_token_to_pidversion(token);
    }
}

EsIngress::~EsIngress()
{
    Stop();
}

#if !BXL_ES_SDK_AVAILABLE

bool EsIngress::Start(EventHandler, std::string &errorMessage)
{
    errorMessage =
        "This build of the BuildXL macOS sandbox was compiled without the Endpoint Security SDK, so "
        "it cannot observe file accesses. Rebuild against a macOS 27.0 or newer SDK.";
    return false;
}

void EsIngress::Stop()
{
}

bool EsIngress::EmitMarker(const std::string &)
{
    return false;
}

#else // BXL_ES_SDK_AVAILABLE

std::vector<es_event_type_t> EsIngress::SubscriptionSet() const
{
    // Everything here is NOTIFY. AUTH would let the broker block a disallowed access in the kernel,
    // but it also puts a deadline on the handler, and a missed deadline costs the whole client.
    // BuildXL already fails a pip whose reported accesses violate the manifest, so observation gives
    // the same build result; enforcement is an availability trade that belongs behind a flag, not a
    // default.
    std::vector<es_event_type_t> events = {
        // Lifecycle. Without these there is no process tree and no lineage to attribute events to.
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,

        // Reads and the operations that turn into reads.
        ES_EVENT_TYPE_NOTIFY_OPEN,
        ES_EVENT_TYPE_NOTIFY_CLOSE,
        ES_EVENT_TYPE_NOTIFY_READLINK,
        ES_EVENT_TYPE_NOTIFY_READDIR,
        ES_EVENT_TYPE_NOTIFY_MMAP,

        // Writes and mutations.
        ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_TRUNCATE,
        ES_EVENT_TYPE_NOTIFY_UNLINK,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_LINK,
        ES_EVENT_TYPE_NOTIFY_CLONE,
        ES_EVENT_TYPE_NOTIFY_COPYFILE,
        ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA,
        ES_EVENT_TYPE_NOTIFY_SETATTRLIST,
        ES_EVENT_TYPE_NOTIFY_SETEXTATTR,
        ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR,
        ES_EVENT_TYPE_NOTIFY_SETFLAGS,
        ES_EVENT_TYPE_NOTIFY_SETMODE,
        ES_EVENT_TYPE_NOTIFY_SETOWNER,
        ES_EVENT_TYPE_NOTIFY_SETACL,
        ES_EVENT_TYPE_NOTIFY_UTIMES,
    };

    if (m_options.subscribeToProbeEvents)
    {
        // A tool that looks for a file and does not find it has a real dependency on that absence:
        // if the file later appears, the tool would behave differently, so the cached result is
        // stale. Linux observes these, so macOS observes them too.
        events.insert(events.end(), {
            ES_EVENT_TYPE_NOTIFY_LOOKUP,
            ES_EVENT_TYPE_NOTIFY_STAT,
            ES_EVENT_TYPE_NOTIFY_ACCESS,
            ES_EVENT_TYPE_NOTIFY_GETATTRLIST,
            ES_EVENT_TYPE_NOTIFY_GETEXTATTR,
            ES_EVENT_TYPE_NOTIFY_LISTEXTATTR,
            ES_EVENT_TYPE_NOTIFY_CHDIR,
            ES_EVENT_TYPE_NOTIFY_FSGETPATH,
            ES_EVENT_TYPE_NOTIFY_SEARCHFS,
            ES_EVENT_TYPE_NOTIFY_DUP,
            ES_EVENT_TYPE_NOTIFY_FCNTL,
        });
    }

    if (m_options.subscribeToDelegationEvents)
    {
        // None of these produce a file access. They exist so that a process handing work to something
        // outside its own lineage - an XPC service, a task port, a debugger - is detected instead of
        // silently producing an unobserved write.
        events.insert(events.end(), {
            ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
            ES_EVENT_TYPE_NOTIFY_XPC_CONNECT,
            ES_EVENT_TYPE_NOTIFY_BOOTSTRAP_LOOK_UP,
            ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
            ES_EVENT_TYPE_NOTIFY_GET_TASK,
            ES_EVENT_TYPE_NOTIFY_TRACE,
            ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME,
            ES_EVENT_TYPE_NOTIFY_CHROOT,
            ES_EVENT_TYPE_NOTIFY_MOUNT,
            ES_EVENT_TYPE_NOTIFY_UNMOUNT,
            ES_EVENT_TYPE_NOTIFY_REMOUNT,
            ES_EVENT_TYPE_NOTIFY_SETUID,
        });
    }

    return events;
}

bool EsIngress::Normalize(const es_message_t *message, NormalizedEvent &out) const
{
    out.messageVersion = message->version;
    out.machTime = message->mach_time;
    out.clientEpoch = 1;
    out.isAuth = message->action_type == ES_ACTION_TYPE_AUTH;

    // seq_num arrived in version 2 and global_seq_num in version 4. Reading them from an older
    // message would be reading uninitialized memory, so they stay zero and SequenceTracker taints.
    out.typeSequence = message->version >= 2 ? message->seq_num : 0;
    out.globalSequence = message->version >= 4 ? message->global_seq_num : 0;

    out.self = IdentityOf(message->process->audit_token);
    out.parent = message->version >= 4
        ? IdentityOf(message->process->parent_audit_token)
        : ProcessIdentity{message->process->ppid, 0};

    if (message->action_type == ES_ACTION_TYPE_NOTIFY)
    {
        // ES reports the syscall's own result. A failed access still matters - a failed open of a
        // missing header is exactly the probe that has to be recorded - so the result is carried
        // through rather than used to filter.
        out.succeeded = message->action.notify.result_type != ES_RESULT_TYPE_FLAGS
            ? message->action.notify.result.auth == ES_AUTH_RESULT_ALLOW
            : true;
    }

    const es_events_t &event = message->event;

    switch (message->event_type)
    {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            out.op = NormOp::kExec;
            out.sourcePath = TokenToString(event.exec.target->executable->path);
            out.sourcePathTruncated = event.exec.target->executable->path_truncated;
            // A process is renumbered when it execs: the identity in message->process is the one it
            // had since it was forked, and the identity in exec.target is the one every subsequent
            // message will carry. Both are needed - the first to find the entry created by the FORK
            // event, the second to re-key it - and this is the only message that carries both.
            out.identityBeforeExec = out.self;
            out.self = IdentityOf(event.exec.target->audit_token);
            {
                // Reconstructed rather than read from a single field: BuildXL's breakaway rules match
                // on the whole command line, so the arguments have to be present.
                const uint32_t argc = es_exec_arg_count(&event.exec);
                std::string commandLine;
                for (uint32_t i = 0; i < argc; i++)
                {
                    if (i > 0)
                    {
                        commandLine.push_back(' ');
                    }

                    commandLine.append(TokenToString(es_exec_arg(&event.exec, i)));
                }

                out.commandLine = std::move(commandLine);
            }
            break;

        case ES_EVENT_TYPE_NOTIFY_FORK:
            out.op = NormOp::kFork;
            out.parent = out.self;
            out.self = IdentityOf(event.fork.child->audit_token);
            out.sourcePath = TokenToString(event.fork.child->executable->path);
            break;

        case ES_EVENT_TYPE_NOTIFY_EXIT:
            out.op = NormOp::kExit;
            out.error = event.exit.stat;
            break;

        case ES_EVENT_TYPE_NOTIFY_OPEN:
            out.op = NormOp::kOpen;
            out.sourcePath = TokenToString(event.open.file->path);
            out.sourcePathTruncated = event.open.file->path_truncated;
            out.sourceIsDirectory = IsDirectory(event.open.file);
            // The access mode decides whether this is a read or a write dependency, and O_ACCMODE is
            // the only part of fflag that is meaningful for that decision.
            out.error = event.open.fflag;
            break;

        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            out.op = NormOp::kClose;
            out.sourcePath = TokenToString(event.close.target->path);
            out.sourcePathTruncated = event.close.target->path_truncated;
            out.sourceIsDirectory = IsDirectory(event.close.target);
            // Only a close that actually modified the file is a write. Treating every close as a
            // write would report a write for every file the compiler merely read.
            out.destinationExists = event.close.modified;
            break;

        case ES_EVENT_TYPE_NOTIFY_CREATE:
            out.op = NormOp::kCreate;
            if (event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE)
            {
                out.sourcePath = TokenToString(event.create.destination.existing_file->path);
                out.sourcePathTruncated = event.create.destination.existing_file->path_truncated;
                out.sourceIsDirectory = IsDirectory(event.create.destination.existing_file);
                out.sourceExists = true;
            }
            else
            {
                out.sourcePath = JoinDirAndName(
                    event.create.destination.new_path.dir,
                    event.create.destination.new_path.filename);
                out.sourcePathTruncated = event.create.destination.new_path.dir->path_truncated;
                out.sourceIsDirectory = S_ISDIR(event.create.destination.new_path.mode);
                out.sourceExists = false;
            }
            break;

        case ES_EVENT_TYPE_NOTIFY_WRITE:
            out.op = NormOp::kWrite;
            out.sourcePath = TokenToString(event.write.target->path);
            out.sourcePathTruncated = event.write.target->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            out.op = NormOp::kTruncate;
            out.sourcePath = TokenToString(event.truncate.target->path);
            out.sourcePathTruncated = event.truncate.target->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            out.op = NormOp::kUnlink;
            out.sourcePath = TokenToString(event.unlink.target->path);
            out.sourcePathTruncated = event.unlink.target->path_truncated;
            out.sourceIsDirectory = IsDirectory(event.unlink.target);
            break;

        case ES_EVENT_TYPE_NOTIFY_RENAME:
            out.op = NormOp::kRename;
            out.sourcePath = TokenToString(event.rename.source->path);
            out.sourcePathTruncated = event.rename.source->path_truncated;
            out.sourceIsDirectory = IsDirectory(event.rename.source);
            if (event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE)
            {
                out.destinationPath = TokenToString(event.rename.destination.existing_file->path);
                out.destinationPathTruncated = event.rename.destination.existing_file->path_truncated;
                out.destinationExists = true;
            }
            else
            {
                out.destinationPath = JoinDirAndName(
                    event.rename.destination.new_path.dir,
                    event.rename.destination.new_path.filename);
                out.destinationPathTruncated = event.rename.destination.new_path.dir->path_truncated;
                out.destinationExists = false;
            }
            break;

        case ES_EVENT_TYPE_NOTIFY_LINK:
            out.op = NormOp::kLink;
            out.sourcePath = TokenToString(event.link.source->path);
            out.sourcePathTruncated = event.link.source->path_truncated;
            out.destinationPath = JoinDirAndName(event.link.target_dir, event.link.target_filename);
            out.destinationPathTruncated = event.link.target_dir->path_truncated;
            out.destinationExists = false;
            break;

        case ES_EVENT_TYPE_NOTIFY_CLONE:
            out.op = NormOp::kClone;
            out.sourcePath = TokenToString(event.clone.source->path);
            out.sourcePathTruncated = event.clone.source->path_truncated;
            out.sourceIsDirectory = IsDirectory(event.clone.source);
            out.destinationPath = JoinDirAndName(event.clone.target_dir, event.clone.target_name);
            out.destinationPathTruncated = event.clone.target_dir->path_truncated;
            out.destinationExists = false;
            break;

        case ES_EVENT_TYPE_NOTIFY_COPYFILE:
            out.op = NormOp::kCopyFile;
            out.sourcePath = TokenToString(event.copyfile.source->path);
            out.sourcePathTruncated = event.copyfile.source->path_truncated;
            out.sourceIsDirectory = IsDirectory(event.copyfile.source);
            if (event.copyfile.target_file != nullptr)
            {
                out.destinationPath = TokenToString(event.copyfile.target_file->path);
                out.destinationPathTruncated = event.copyfile.target_file->path_truncated;
                out.destinationExists = true;
            }
            else
            {
                out.destinationPath = JoinDirAndName(event.copyfile.target_dir, event.copyfile.target_name);
                out.destinationPathTruncated = event.copyfile.target_dir->path_truncated;
                out.destinationExists = false;
            }
            break;

        case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
            out.op = NormOp::kExchangeData;
            out.sourcePath = TokenToString(event.exchangedata.file1->path);
            out.sourcePathTruncated = event.exchangedata.file1->path_truncated;
            out.destinationPath = TokenToString(event.exchangedata.file2->path);
            out.destinationPathTruncated = event.exchangedata.file2->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_LOOKUP:
            out.op = NormOp::kLookup;
            out.sourcePath = JoinDirAndName(event.lookup.source_dir, event.lookup.relative_target);
            out.sourcePathTruncated = event.lookup.source_dir->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_READLINK:
            out.op = NormOp::kReadlink;
            out.sourcePath = TokenToString(event.readlink.source->path);
            out.sourcePathTruncated = event.readlink.source->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_READDIR:
            out.op = NormOp::kReaddir;
            out.sourcePath = TokenToString(event.readdir.target->path);
            out.sourcePathTruncated = event.readdir.target->path_truncated;
            out.sourceIsDirectory = true;
            break;

        case ES_EVENT_TYPE_NOTIFY_MMAP:
            out.op = NormOp::kMmap;
            out.sourcePath = TokenToString(event.mmap.source->path);
            out.sourcePathTruncated = event.mmap.source->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_STAT:
            out.op = NormOp::kStat;
            out.sourcePath = TokenToString(event.stat.target->path);
            out.sourcePathTruncated = event.stat.target->path_truncated;
            out.sourceIsDirectory = IsDirectory(event.stat.target);
            break;

        case ES_EVENT_TYPE_NOTIFY_ACCESS:
            out.op = NormOp::kAccess;
            out.sourcePath = TokenToString(event.access.target->path);
            out.sourcePathTruncated = event.access.target->path_truncated;
            out.sourceIsDirectory = IsDirectory(event.access.target);
            break;

        case ES_EVENT_TYPE_NOTIFY_GETATTRLIST:
            out.op = NormOp::kGetAttrList;
            out.sourcePath = TokenToString(event.getattrlist.target->path);
            out.sourcePathTruncated = event.getattrlist.target->path_truncated;
            out.sourceIsDirectory = IsDirectory(event.getattrlist.target);
            break;

        case ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
            out.op = NormOp::kSetAttrList;
            out.sourcePath = TokenToString(event.setattrlist.target->path);
            out.sourcePathTruncated = event.setattrlist.target->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_GETEXTATTR:
            out.op = NormOp::kGetExtAttr;
            out.sourcePath = TokenToString(event.getextattr.target->path);
            out.sourcePathTruncated = event.getextattr.target->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_SETEXTATTR:
            out.op = NormOp::kSetExtAttr;
            out.sourcePath = TokenToString(event.setextattr.target->path);
            out.sourcePathTruncated = event.setextattr.target->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
            out.op = NormOp::kDeleteExtAttr;
            out.sourcePath = TokenToString(event.deleteextattr.target->path);
            out.sourcePathTruncated = event.deleteextattr.target->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_LISTEXTATTR:
            out.op = NormOp::kListExtAttr;
            out.sourcePath = TokenToString(event.listextattr.target->path);
            out.sourcePathTruncated = event.listextattr.target->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_SETFLAGS:
            out.op = NormOp::kSetFlags;
            out.sourcePath = TokenToString(event.setflags.target->path);
            out.sourcePathTruncated = event.setflags.target->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_SETMODE:
            out.op = NormOp::kSetMode;
            out.sourcePath = TokenToString(event.setmode.target->path);
            out.sourcePathTruncated = event.setmode.target->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_SETOWNER:
            out.op = NormOp::kSetOwner;
            out.sourcePath = TokenToString(event.setowner.target->path);
            out.sourcePathTruncated = event.setowner.target->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_SETACL:
            out.op = NormOp::kSetAcl;
            out.sourcePath = TokenToString(event.setacl.target->path);
            out.sourcePathTruncated = event.setacl.target->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_UTIMES:
            out.op = NormOp::kUtimes;
            out.sourcePath = TokenToString(event.utimes.target->path);
            out.sourcePathTruncated = event.utimes.target->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_CHDIR:
            out.op = NormOp::kChdir;
            out.sourcePath = TokenToString(event.chdir.target->path);
            out.sourcePathTruncated = event.chdir.target->path_truncated;
            out.sourceIsDirectory = true;
            break;

        case ES_EVENT_TYPE_NOTIFY_FSGETPATH:
            out.op = NormOp::kFsGetPath;
            out.sourcePath = TokenToString(event.fsgetpath.target->path);
            out.sourcePathTruncated = event.fsgetpath.target->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_SEARCHFS:
            out.op = NormOp::kSearchFs;
            out.sourcePath = TokenToString(event.searchfs.target->path);
            out.sourcePathTruncated = event.searchfs.target->path_truncated;
            out.sourceIsDirectory = true;
            break;

        case ES_EVENT_TYPE_NOTIFY_DUP:
            out.op = NormOp::kDup;
            out.sourcePath = TokenToString(event.dup.target->path);
            out.sourcePathTruncated = event.dup.target->path_truncated;
            break;

        case ES_EVENT_TYPE_NOTIFY_FCNTL:
            out.op = NormOp::kFcntl;
            out.sourcePath = TokenToString(event.fcntl.target->path);
            out.sourcePathTruncated = event.fcntl.target->path_truncated;
            break;

        // Delegation. Judged individually rather than as a category: see IsDelegationEscape.
        case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
            out.op = NormOp::kUipcConnect;
            // A UNIX-domain socket connect names a file, so the path is carried like any other and
            // checked against the manifest rather than being treated as an opaque category.
            if (event.uipc_connect.file != nullptr)
            {
                out.sourcePath = TokenToString(event.uipc_connect.file->path);
                out.sourcePathTruncated = event.uipc_connect.file->path_truncated;
                out.delegationTarget = out.sourcePath;
            }
            break;

        case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
            out.op = NormOp::kXpcConnect;
            out.delegationTarget = TokenToString(event.xpc_connect->service_name);
            // Only the system domain is owned by the operating system; a process can register into
            // the user and session domains, so a name there proves nothing about who answers.
            out.delegationTargetIsPlatform =
                event.xpc_connect->service_domain_type == ES_XPC_DOMAIN_TYPE_SYSTEM &&
                out.delegationTarget.rfind("com.apple.", 0) == 0;
            break;

        case ES_EVENT_TYPE_NOTIFY_BOOTSTRAP_LOOK_UP:
            out.op = NormOp::kBootstrapLookUp;
            out.delegationTarget = TokenToString(event.bootstrap_look_up->service_name);

            // launchd submits this event on the caller's behalf, so the enclosing message describes
            // launchd rather than the process that made the call. The header is explicit about it:
            // "es_message_t.process describes launchd, not the process that called
            // bootstrap_look_up()". Attributing the event to launchd made it look like traffic from
            // a process outside the tree - which is exactly what was observed, pid 1 with ppid 0 -
            // when it in fact belongs to a tracked process.
            out.self = IdentityOf(event.bootstrap_look_up->instigator_token);
            if (event.bootstrap_look_up->instigator != nullptr)
            {
                out.parent = IdentityOf(event.bootstrap_look_up->instigator->parent_audit_token);
            }

            // On the PROCESS arm the service is already running and the kernel supplies its identity;
            // on the JOB arm there is no live process to ask, and launchd would start one. A service
            // launchd is willing to start on demand is part of the system's own configuration, which
            // is the same category of trust.
            out.delegationTargetIsPlatform =
                event.bootstrap_look_up->target_type == ES_BOOTSTRAP_TARGET_TYPE_PROCESS &&
                event.bootstrap_look_up->target.process.target != nullptr
                    ? event.bootstrap_look_up->target.process.target->is_platform_binary
                    : out.delegationTarget.rfind("com.apple.", 0) == 0;
            break;

        case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE: out.op = NormOp::kRemoteThreadCreate; break;
        case ES_EVENT_TYPE_NOTIFY_GET_TASK: out.op = NormOp::kGetTask; break;
        case ES_EVENT_TYPE_NOTIFY_TRACE: out.op = NormOp::kTrace; break;
        case ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME: out.op = NormOp::kProcSuspendResume; break;
        case ES_EVENT_TYPE_NOTIFY_CHROOT: out.op = NormOp::kChroot; break;
        case ES_EVENT_TYPE_NOTIFY_MOUNT: out.op = NormOp::kMount; break;
        case ES_EVENT_TYPE_NOTIFY_UNMOUNT: out.op = NormOp::kUnmount; break;
        case ES_EVENT_TYPE_NOTIFY_REMOUNT: out.op = NormOp::kRemount; break;
        case ES_EVENT_TYPE_NOTIFY_SETUID: out.op = NormOp::kSetUid; break;

        default:
            // Subscribed to but not modelled. Reported as unsupported rather than dropped, because a
            // silently ignored event is exactly the failure this design exists to rule out.
            out.op = NormOp::kUnsupported;
            m_unmappedEvents.fetch_add(1, std::memory_order_relaxed);
            break;
    }

    // Deliberately computed after the switch, on the event's *subject* rather than its actor. FORK
    // rewrites `self` to the child, and the broker forking the pip's root process is precisely the
    // event that must not be suppressed -- suppressing it would leave the process table with no root
    // and BuildXL would never see the pip start. Events the broker performs on its own behalf (its
    // FIFO writes) still have the broker as their subject and are still suppressed.
    out.fromBroker = out.self.pid == m_broker.pid;

    return true;
}

bool EsIngress::Start(EventHandler handler, std::string &errorMessage)
{
    m_handler = std::move(handler);

    __block EsIngress *self = this;
    es_new_client_result_t result = ES_NEW_CLIENT_RESULT_ERR_INTERNAL;
    uint32_t backoffMillis = m_options.initialRetryBackoffMillis;

    for (uint32_t attempt = 0; attempt <= m_options.maxClientRetries; attempt++)
    {
        result = es_new_descendants_client(&m_client, ^(es_client_t *, const es_message_t *message) {
            self->HandleMessage(message);
        });

        if (result != ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS)
        {
            break;
        }

        // Every other BuildXL pip running on this machine also holds a client. Waiting is the
        // correct response; failing here would make build success depend on scheduling luck.
        std::this_thread::sleep_for(std::chrono::milliseconds(backoffMillis));
        backoffMillis = std::min(backoffMillis * 2, m_options.maxRetryBackoffMillis);
    }

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS)
    {
        errorMessage = std::string("es_new_descendants_client failed: ") + NewClientResultToString(result);
        if (result == ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED)
        {
            errorMessage +=
                ". The broker binary must be signed with com.apple.developer.endpoint-security.client "
                "by a provisioning profile that authorizes it. Endpoint Security cannot be used "
                "without it, and there is no sound fallback: DYLD_INSERT_LIBRARIES is stripped for "
                "platform binaries and the seatbelt trace facility produces no output on macOS 27.";
        }

        m_client = nullptr;
        return false;
    }

    // A missed deadline defaults to killing the client, which would destroy the whole stream. Fail
    // open instead: the access proceeds, the kernel records a gap in global_seq_num, the engine sees
    // the gap and taints the pip. The build stays correct and the pip is simply re-run uncached.
    es_set_deadline_miss_mode(m_client, ES_DEADLINE_MISS_MODE_FAIL_OPEN);

    const std::vector<es_event_type_t> events = SubscriptionSet();
    if (es_subscribe(m_client, events.data(), static_cast<uint32_t>(events.size())) != ES_RETURN_SUCCESS)
    {
        errorMessage = "es_subscribe failed";
        es_delete_client(m_client);
        m_client = nullptr;
        return false;
    }

    m_running.store(true, std::memory_order_release);
    return true;
}

void EsIngress::HandleMessage(const es_message_t *message)
{
    if (!m_running.load(std::memory_order_acquire))
    {
        return;
    }

    NormalizedEvent event;
    if (!Normalize(message, event))
    {
        return;
    }

    if (event.fromBroker)
    {
        // The broker writes reports to a FIFO, and a descendants client also reports the calling
        // process. Feeding those writes back in would amplify without bound: one report generates one
        // event, which generates one report. Only the fence marker is allowed through, and it is
        // recognised by its exact nonce path so no observed process can forge one.
        const bool isMarker = !m_noncePath.empty() && event.sourcePath == m_noncePath;
        if (!isMarker)
        {
            m_selfEventsSuppressed.fetch_add(1, std::memory_order_relaxed);

            // The kernel has already spent this message's sequence numbers. Remember that, so the
            // next forwarded event is not mistaken for one that arrived after a drop.
            m_suppressedSinceForward++;
            m_suppressedSinceForwardByType[static_cast<uint16_t>(event.op)]++;
            return;
        }
    }

    event.suppressedBeforeGlobal = m_suppressedSinceForward;
    m_suppressedSinceForward = 0;

    const uint16_t typeKey = static_cast<uint16_t>(event.op);
    auto suppressedForType = m_suppressedSinceForwardByType.find(typeKey);
    if (suppressedForType != m_suppressedSinceForwardByType.end())
    {
        event.suppressedBeforeType = suppressedForType->second;
        suppressedForType->second = 0;
    }

    // Bounded: the enqueue waits at most a fixed budget and then reports failure. Nothing here
    // allocates beyond the event itself and nothing blocks on I/O.
    m_handler(std::move(event));
}

bool EsIngress::EmitMarker(const std::string &noncePath)
{
    m_noncePath = noncePath;

    // Any observable filesystem touch works; a stat on a path that does not exist is the cheapest one
    // that cannot have a side effect on the build. What matters is only that the kernel assigns it a
    // global_seq_num, which orders it after everything already generated.
    struct stat statBuffer;
    (void)::stat(noncePath.c_str(), &statBuffer);
    return true;
}

void EsIngress::Stop()
{
    if (!m_running.exchange(false, std::memory_order_acq_rel))
    {
        return;
    }

    if (m_client != nullptr)
    {
        es_unsubscribe_all(m_client);
        es_delete_client(m_client);
        m_client = nullptr;
    }
}

#endif // BXL_ES_SDK_AVAILABLE

} // namespace macos
} // namespace buildxl
