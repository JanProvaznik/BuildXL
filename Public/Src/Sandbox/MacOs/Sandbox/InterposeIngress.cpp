// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "InterposeIngress.h"

#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>

#include "../Interpose/InterposeProtocol.h"
#include "../Interpose/ShadowTool.h"

namespace buildxl {
namespace macos {

using namespace buildxl::macos::interpose;

namespace {

int32_t ProcessStartSeconds(pid_t pid)
{
    struct proc_bsdinfo info;
    memset(&info, 0, sizeof(info));
    const int written = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    return written == static_cast<int>(sizeof(info)) ? static_cast<int32_t>(info.pbi_start_tvsec) : 0;
}

/**
 * The explicit mapping from wire opcode to engine operation.
 *
 * Written out rather than derived so that adding an opcode to the injected library cannot silently
 * acquire an engine meaning it was never given. Anything unrecognised becomes kUnsupported, which
 * taints: a report the broker cannot interpret is not a report it may ignore.
 * CODESYNC: Public/Src/Sandbox/MacOs/Interpose/InterposeProtocol.h (InterposeOp).
 */
NormOp OpToNormOp(uint16_t op)
{
    switch (op)
    {
        case kOpOpenRead: return NormOp::kOpen;
        case kOpOpenWrite: return NormOp::kWrite;
        case kOpCreate: return NormOp::kCreate;
        case kOpStat: return NormOp::kStat;
        case kOpAccess: return NormOp::kAccess;
        case kOpReadDir: return NormOp::kReaddir;
        case kOpReadLink: return NormOp::kReadlink;
        case kOpMkDir: return NormOp::kCreate;
        case kOpRmDir: return NormOp::kUnlink;
        case kOpUnlink: return NormOp::kUnlink;
        case kOpRename: return NormOp::kRename;
        case kOpLink: return NormOp::kLink;
        case kOpSymlink: return NormOp::kCreate;
        case kOpChMod: return NormOp::kSetMode;
        case kOpChOwn: return NormOp::kSetOwner;
        case kOpTruncate: return NormOp::kTruncate;
        case kOpUTimes: return NormOp::kUtimes;
        case kOpCloneFile: return NormOp::kClone;
        case kOpCopyFile: return NormOp::kCopyFile;
        case kOpExec: return NormOp::kExec;
        case kOpSpawn: return NormOp::kExec;
        case kOpChDir: return NormOp::kChdir;
        case kOpExit: return NormOp::kExit;
        case kOpSetFlags: return NormOp::kSetFlags;
        case kOpUnknown: return NormOp::kUnknown;
        default: return NormOp::kUnsupported;
    }
}

bool ReadFully(int descriptor, void *buffer, size_t length)
{
    char *cursor = static_cast<char *>(buffer);
    size_t remaining = length;
    while (remaining > 0)
    {
        const ssize_t got = read(descriptor, cursor, remaining);
        if (got > 0)
        {
            cursor += got;
            remaining -= static_cast<size_t>(got);
            continue;
        }

        if (got < 0 && errno == EINTR)
        {
            continue;
        }

        return false;
    }

    return true;
}

/**
 * Where the control socket lives.
 *
 * Not in the pip's temp directory, which is the obvious choice and does not work: sockaddr_un.sun_path
 * is 104 bytes on macOS, and BuildXL's object directory paths routinely exceed that on their own. The
 * first real build under this backend failed on exactly that, for every pip.
 *
 * TMPDIR is no better - macOS points it at /var/folders/<2>/<30ish>/T/ - so the socket goes in a
 * per-user directory directly under /tmp, which keeps the whole path around 40 bytes. The socket is a
 * control channel rather than a build artifact, so it has no reason to live with the pip's outputs.
 *
 * /tmp is world writable with the sticky bit, so the directory is created 0700 and its ownership and
 * mode are verified before it is used. Another user cannot pre-create it and read the build's file
 * access stream, and if one has, this fails rather than proceeding.
 */
/**
 * Creates a private directory under /tmp and refuses to use one that is not ours.
 *
 * /tmp is world writable with the sticky bit, so the directory is created 0700 and its ownership and
 * mode are verified before it is used. Another user cannot pre-create it and read the build's file
 * access stream, and if one has, this fails rather than proceeding.
 */
bool EnsurePrivateDirectory(const std::string &directory, std::string &errorMessage)
{
    if (mkdir(directory.c_str(), 0700) != 0 && errno != EEXIST)
    {
        errorMessage = "cannot create '" + directory + "': " + strerror(errno);
        return false;
    }

    struct stat info;
    if (lstat(directory.c_str(), &info) != 0)
    {
        errorMessage = "cannot stat '" + directory + "': " + strerror(errno);
        return false;
    }

    if (!S_ISDIR(info.st_mode) || info.st_uid != getuid() || (info.st_mode & (S_IRWXG | S_IRWXO)) != 0)
    {
        errorMessage = "'" + directory + "' is not a private directory owned by this user";
        return false;
    }

    return true;
}

std::string SandboxDirectory()
{
    return "/tmp/.bxl-sandbox-" + std::to_string(getuid());
}

std::string DefaultSocketPath(std::string &errorMessage)
{
    const std::string directory = SandboxDirectory();

    if (!EnsurePrivateDirectory(directory, errorMessage))
    {
        return std::string();
    }

    // The pid keeps concurrent brokers - BuildXL runs one per executing pip - from colliding, and the
    // monotonic counter keeps a recycled pid from reusing a path a previous broker left behind.
    static std::atomic<uint64_t> instance{0};
    return directory + "/i" + std::to_string(getpid()) + "-"
        + std::to_string(instance.fetch_add(1, std::memory_order_relaxed)) + ".s";
}

} // namespace

InterposeIngress::InterposeIngress(std::string socketPath)
    : m_socketPath(socketPath.empty() ? DefaultSocketPath(m_socketPathError) : std::move(socketPath))
{
    m_broker.pid = static_cast<int32_t>(getpid());
    m_broker.pidversion = ProcessStartSeconds(getpid());
}

InterposeIngress::~InterposeIngress()
{
    Stop();
}

bool InterposeIngress::Start(EventHandler handler, std::string &errorMessage)
{
    m_handler = std::move(handler);

    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (m_socketPath.empty())
    {
        errorMessage = m_socketPathError.empty() ? "no interpose socket path could be chosen" : m_socketPathError;
        return false;
    }

    if (m_socketPath.size() >= sizeof(address.sun_path))
    {
        errorMessage = "the interpose socket path is longer than the " + std::to_string(sizeof(address.sun_path))
            + " bytes sockaddr_un permits: " + m_socketPath;
        return false;
    }

    strncpy(address.sun_path, m_socketPath.c_str(), sizeof(address.sun_path) - 1);
    ::unlink(m_socketPath.c_str());

    m_listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (m_listener < 0)
    {
        errorMessage = std::string("cannot create the interpose socket: ") + strerror(errno);
        return false;
    }

    if (bind(m_listener, reinterpret_cast<const struct sockaddr *>(&address), sizeof(address)) != 0)
    {
        errorMessage = "cannot bind '" + m_socketPath + "': " + strerror(errno);
        close(m_listener);
        m_listener = -1;
        return false;
    }

    m_ownsSocketPath = true;

    // The backlog has to absorb a burst of processes starting at once. MSBuild starting its node
    // pool is exactly that, and a refused connection is an unobserved process.
    if (listen(m_listener, 512) != 0)
    {
        errorMessage = "cannot listen on '" + m_socketPath + "': " + strerror(errno);
        close(m_listener);
        m_listener = -1;
        return false;
    }

    m_running.store(true, std::memory_order_release);
    m_acceptThread = std::thread([this] { AcceptLoop(); });
    return true;
}

void InterposeIngress::AcceptLoop()
{
    while (m_running.load(std::memory_order_acquire))
    {
        const int accepted = accept(m_listener, nullptr, nullptr);
        if (accepted < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            return;
        }

        {
            std::lock_guard<std::mutex> guard(m_connectionMutex);
            m_activeConnections++;
        }

        std::lock_guard<std::mutex> guard(m_readerMutex);
        m_readerThreads.emplace_back([this, accepted] { ReadLoop(accepted); });
    }
}

void InterposeIngress::OnConnectionClosed()
{
    std::lock_guard<std::mutex> guard(m_connectionMutex);
    if (--m_activeConnections <= 0)
    {
        m_connectionIdle.notify_all();
    }
}

void InterposeIngress::ReadLoop(int descriptor)
{
    std::vector<char> payload;

    // Owned by this thread alone: one connection, one strictly increasing sequence, no sharing.
    uint64_t lastSequence = 0;

    for (;;)
    {
        InterposeRecordHeader header;
        if (!ReadFully(descriptor, &header, sizeof(header)))
        {
            break;
        }

        if (header.magic != static_cast<uint32_t>(kInterposeMagic) ||
            header.totalLength < sizeof(header) ||
            header.version != static_cast<uint16_t>(kInterposeVersion))
        {
            // A misframed stream cannot be resynchronised: the reader has no way to find the next
            // record boundary. Dropping the connection loses the rest of that process's events, and
            // the sequence gap that follows is what turns the loss into a taint rather than a
            // silently short observation.
            m_recordGaps.fetch_add(1, std::memory_order_relaxed);
            break;
        }

        const size_t payloadLength = header.totalLength - sizeof(header);
        if (payloadLength > 2 * static_cast<size_t>(kInterposeMaxPath) + 64)
        {
            m_recordGaps.fetch_add(1, std::memory_order_relaxed);
            break;
        }

        payload.resize(payloadLength);
        if (payloadLength > 0 && !ReadFully(descriptor, payload.data(), payloadLength))
        {
            m_recordGaps.fetch_add(1, std::memory_order_relaxed);
            break;
        }

        if (static_cast<size_t>(header.sourceLength) + header.destinationLength > payloadLength)
        {
            m_recordGaps.fetch_add(1, std::memory_order_relaxed);
            break;
        }

        m_recordsRead.fetch_add(1, std::memory_order_relaxed);

        // Sequence numbers are per *connection*, not per pid. One pid legitimately owns several
        // connections over its life: the atfork child handler reconnects because parent and child
        // must not share a stream, and every exec reloads the library from scratch with its counter
        // reset. Keying loss detection by pid therefore reported a gap at each of those transitions
        // -- three on a four-deep tree -- which is a false accusation of data loss, and a taint that
        // fires on every ordinary build is indistinguishable from one that never fires.
        if (lastSequence != 0 && header.sequence != lastSequence + 1)
        {
            m_recordGaps.fetch_add(1, std::memory_order_relaxed);
        }

        lastSequence = header.sequence;

        const std::string source(payload.data(), header.sourceLength);
        const std::string destination(payload.data() + header.sourceLength, header.destinationLength);

        NormalizedEvent event;
        event.globalSequence = m_globalSequence.fetch_add(1, std::memory_order_relaxed) + 1;
        event.typeSequence = event.globalSequence;
        event.messageVersion = header.version;
        event.sequenceIsKernelAssigned = false;
        event.machTime = header.machTime;
        event.clientEpoch = 1;
        event.isAuth = false;
        event.succeeded = (header.flags & kFlagSucceeded) != 0;
        event.error = header.error;
        event.self.pid = header.pid;
        event.self.pidversion = header.pidStartSeconds;
        event.parent.pid = header.parentPid;
        event.parent.pidversion = header.parentPidStartSeconds;
        event.sourceIsDirectory = (header.flags & kFlagSourceIsDirectory) != 0;
        event.destinationIsDirectory = (header.flags & kFlagDestinationIsDirectory) != 0;
        event.sourceExists = (header.flags & kFlagSourceExists) != 0;
        event.destinationExists = (header.flags & kFlagDestinationExists) != 0;
        event.sourcePathTruncated = (header.flags & kFlagSourceTruncated) != 0;
        event.destinationPathTruncated = (header.flags & kFlagDestinationTruncated) != 0;
        event.sourcePath = source;
        event.destinationPath = destination;

        // The checker indexes the manifest by absolute path and asserts on anything else - including
        // the empty string - so a malformed record has to stop here rather than take the broker down
        // with it and lose the whole pip's stream. Only an exit legitimately names nothing. Counted as
        // a gap, which taints: something happened that could not be modelled, so the pip must not be
        // cached from this execution.
        const bool namesAPath = !(header.kind == kRecordEvent && header.op == kOpExit);
        if ((namesAPath && event.sourcePath.empty())
            || (!event.sourcePath.empty() && event.sourcePath[0] != '/')
            || (!event.destinationPath.empty() && event.destinationPath[0] != '/'))
        {
            m_recordGaps.fetch_add(1, std::memory_order_relaxed);
            fprintf(
                stderr,
                "[bxl] macOS sandbox dropped a malformed record: kind=%u op=%u pid=%d src='%s' dst='%s'\n",
                (unsigned)header.kind,
                (unsigned)header.op,
                (int)header.pid,
                event.sourcePath.c_str(),
                event.destinationPath.c_str());
            continue;
        }

        switch (header.kind)
        {
            case kRecordHello:
            {
                m_observedProcesses.fetch_add(1, std::memory_order_relaxed);

                // A process announcing itself is the interpose equivalent of FORK followed by EXEC.
                // Both are emitted, because the table needs the fork to attach the process to its
                // parent and the exec to learn the executable - which is what breakaway matching and
                // every later report's provenance depend on.
                NormalizedEvent fork = event;
                fork.op = NormOp::kFork;
                fork.sourcePath.clear();
                fork.destinationPath.clear();
                m_handler(std::move(fork));

                event.op = NormOp::kExec;
                event.commandLine = source;
                event.globalSequence = m_globalSequence.fetch_add(1, std::memory_order_relaxed) + 1;
                event.typeSequence = event.globalSequence;
                m_handler(std::move(event));
                break;
            }

            case kRecordUnobservableChild:
            {
                m_unobservableChildren.fetch_add(1, std::memory_order_relaxed);

                // dyld will not inject into the binary about to be exec'd, so nothing it or its
                // descendants do will be reported. kUnsupported is the engine's "an operation
                // happened that cannot be modelled", which is exactly the situation, and it taints.
                event.op = NormOp::kUnsupported;
                m_handler(std::move(event));
                break;
            }

            default:
            {
                event.op = OpToNormOp(header.op);
                m_handler(std::move(event));
                break;
            }
        }
    }

    close(descriptor);
    OnConnectionClosed();
}

bool InterposeIngress::WaitForConnectionsToDrain(std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> guard(m_connectionMutex);
    return m_connectionIdle.wait_for(guard, timeout, [this] { return m_activeConnections == 0; });
}

bool InterposeIngress::IsInjectable(const std::string &executablePath, std::string &reason)
{
    reason.clear();

    if (executablePath.empty())
    {
        return true;
    }

    struct stat info;
    if (stat(executablePath.c_str(), &info) != 0)
    {
        // PATH resolution happens in posix_spawnp, so a bare name is not evidence of anything.
        return true;
    }

    if ((info.st_flags & SF_RESTRICTED) != 0)
    {
        reason = "'" + executablePath + "' is protected by System Integrity Protection, so dyld will "
            "not inject the observation library into it and removes DYLD_INSERT_LIBRARIES from its "
            "environment, which means its children cannot be observed either. Point the pip at the "
            "real tool rather than at a /usr/bin stub, or grant the broker the Endpoint Security "
            "entitlement";
        return false;
    }

    if ((info.st_mode & (S_ISUID | S_ISGID)) != 0)
    {
        reason = "'" + executablePath + "' is setuid or setgid, so dyld will not inject the "
            "observation library into it";
        return false;
    }

    return true;
}

bool InterposeIngress::MakeInjectable(const std::string &executablePath, std::string &shadowPath, std::string &error)
{
    shadowPath.clear();
    error.clear();

    char resolved[BXL_SHADOW_PATH_MAX];
    if (!BxlShadowResolve(executablePath.c_str(), resolved, sizeof(resolved)))
    {
        error = "no injectable copy of '" + executablePath + "' could be made";
        return false;
    }

    shadowPath = resolved;
    return true;
}

bool InterposeIngress::EmitMarker(const std::string &noncePath)
{
    if (m_listener < 0)
    {
        return false;
    }

    // The fence is only ever taken at a quiescent point: before the tool is launched, and after the
    // tree has been observed to exit. Waiting for every connection to reach EOF first is what makes
    // the marker an ordering statement and not merely a liveness one - with one stream per process
    // there is no kernel-assigned global order to appeal to, so "every other stream has ended" is
    // the ordering guarantee.
    WaitForConnectionsToDrain(std::chrono::seconds(30));

    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, m_socketPath.c_str(), sizeof(address.sun_path) - 1);

    const int client = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client < 0)
    {
        return false;
    }

    if (connect(client, reinterpret_cast<const struct sockaddr *>(&address), sizeof(address)) != 0)
    {
        close(client);
        return false;
    }

    // Deliberately sent over the same transport the pip's processes use, rather than injected
    // straight into the handler. A marker that skipped the socket would still arrive if the reader
    // were dead, which is the one thing the fence exists to rule out.
    InterposeRecordHeader header;
    memset(&header, 0, sizeof(header));
    header.magic = kInterposeMagic;
    header.totalLength = static_cast<uint32_t>(sizeof(header) + noncePath.size());
    header.kind = kRecordEvent;
    header.op = kOpStat;
    header.flags = kFlagSucceeded;
    header.version = kInterposeVersion;
    header.pid = m_broker.pid;
    header.parentPid = 0;
    header.pidStartSeconds = m_broker.pidversion;
    header.parentPidStartSeconds = 0;
    header.machTime = mach_absolute_time();
    header.sourceLength = static_cast<uint32_t>(noncePath.size());

    // The marker connection is a connection like any other, so its sequence starts at 1 and the
    // reader tracks it per connection. An earlier version shared the reader's per-pid map with the
    // writer, which made the reader expect N+1 while receiving N and report a gap it had caused.
    header.sequence = m_markerSequence.fetch_add(1, std::memory_order_relaxed) + 1;

    bool sent = write(client, &header, sizeof(header)) == static_cast<ssize_t>(sizeof(header));
    if (sent && !noncePath.empty())
    {
        sent = write(client, noncePath.data(), noncePath.size()) == static_cast<ssize_t>(noncePath.size());
    }

    close(client);
    return sent;
}

void InterposeIngress::Stop()
{
    if (!m_running.exchange(false, std::memory_order_acq_rel))
    {
        return;
    }

    if (m_listener >= 0)
    {
        // Shutting the listener down is what unblocks accept(); closing alone can leave the thread
        // parked on a descriptor number that has already been reused.
        shutdown(m_listener, SHUT_RDWR);
        close(m_listener);
        m_listener = -1;
    }

    if (m_acceptThread.joinable())
    {
        m_acceptThread.join();
    }

    std::vector<std::thread> readers;
    {
        std::lock_guard<std::mutex> guard(m_readerMutex);
        readers.swap(m_readerThreads);
    }

    for (std::thread &reader : readers)
    {
        if (reader.joinable())
        {
            reader.join();
        }
    }

    if (m_ownsSocketPath)
    {
        ::unlink(m_socketPath.c_str());
        m_ownsSocketPath = false;
    }
}

} // namespace macos
} // namespace buildxl
