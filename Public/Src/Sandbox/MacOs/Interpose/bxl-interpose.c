// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * libBuildXLInterpose.dylib - the injected file access observer for macOS.
 *
 * WHY THIS EXISTS
 *
 * The Endpoint Security broker observes a pip's process tree from the kernel, which is the strongest
 * observation macOS offers. It also requires com.apple.developer.endpoint-security.client, a
 * restricted entitlement Apple grants per team. Until that entitlement is in hand - and on any
 * machine that will never have it, which includes hosted CI runners - a build either runs with no
 * sandbox at all or does not run.
 *
 * "No sandbox at all" is not a degraded mode, it is an unsound one. With no reported accesses,
 * SandboxedProcessPipExecutor records every shared opaque directory as *empty* and reports success
 * (CODESYNC: Public/Src/Engine/ProcessPipExecutor/SandboxedProcessPipExecutor.cs, the early return
 * in TryGetObservedFileAccesses). The pip is then cached as though its outputs had been observed.
 *
 * This library is the second backend: dyld interposition, the macOS analogue of the Linux
 * LD_PRELOAD sandbox. It needs no entitlement, no kernel extension and no SIP change, so it works
 * on a stock Mac today.
 *
 * WHAT IT CANNOT DO, AND WHY THAT IS SAFE
 *
 * dyld ignores DYLD_INSERT_LIBRARIES for SIP protected and platform binaries, and - measured, not
 * assumed - it also *erases* the variable from their environment, so the loss is inherited by
 * everything they start. `sh -c dotnet` observes nothing at all.
 *
 * Silently observing nothing is exactly the failure this backend exists to prevent, so every exec
 * of a binary that cannot be injected emits kRecordUnobservableChild before the exec happens. The
 * ingress turns that into a taint, BuildXL refuses to cache the pip, and the build stays correct at
 * the cost of a cache miss. The kernel backend has no such blind spot; this one declares it.
 */

#include <dirent.h>
#include <stdatomic.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <copyfile.h>
#include <sys/attr.h>
#include <sys/clonefile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
#include <sys/un.h>
#include <unistd.h>

#include "InterposeProtocol.h"
#include "ShadowTool.h"

// ---------------------------------------------------------------------------------------------
// dyld interposition
// ---------------------------------------------------------------------------------------------

/**
 * dyld rebinds every *other* image's reference to `_orig` so it lands on `_repl`. References made
 * from within this image are deliberately left alone, which is what lets an interposer call the
 * function it replaced without recursing.
 */
#define BXL_INTERPOSE(_repl, _orig)                                                      \
    __attribute__((used)) static struct                                                  \
    {                                                                                    \
        const void *replacement;                                                         \
        const void *replacee;                                                            \
    } _bxl_interpose_##_repl __attribute__((section("__DATA,__interpose"))) = {           \
        (const void *)(uintptr_t)&_repl, (const void *)(uintptr_t)&_orig};

/**
 * The non-cancellable aliases.
 *
 * .NET's libSystem.Native.dylib imports open$NOCANCEL, read$NOCANCEL, pwrite$NOCANCEL and friends
 * rather than the plain names. Interposing only the plain names observes stat() traffic and almost
 * no opens, which looks like a working sandbox right up until a cached pip is missing its inputs.
 */
extern int bxl_real_open_nocancel(const char *, int, ...) __asm("_open$NOCANCEL");

#ifndef SF_RESTRICTED
#define SF_RESTRICTED 0x00080000
#endif

// ---------------------------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------------------------

static int g_socket = -1;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_sequence = 0;
static int32_t g_pid = 0;
static int32_t g_parentPid = 0;
static int32_t g_pidStart = 0;
static int32_t g_parentPidStart = 0;
static char g_socketPath[PATH_MAX];
static char g_libraryPath[PATH_MAX];

/**
 * Set while a thread is inside the reporting path.
 *
 * The report path itself calls stat() and getcwd(). Those are not interposed for calls originating
 * in this image, but a library loaded after this one could interpose them for everybody, and a
 * reentrant report would deadlock on g_lock. The guard makes that a dropped report instead.
 */
static __thread int t_reporting = 0;

static int32_t ProcessStartSeconds(pid_t pid)
{
    struct proc_bsdinfo info;
    memset(&info, 0, sizeof(info));
    const int written = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (written != (int)sizeof(info))
    {
        return 0;
    }

    return (int32_t)info.pbi_start_tvsec;
}

static void CloseConnection(void)
{
    if (g_socket >= 0)
    {
        close(g_socket);
        g_socket = -1;
    }
}

static int WriteFully(int fd, const void *buffer, size_t length)
{
    const char *cursor = (const char *)buffer;
    size_t remaining = length;
    while (remaining > 0)
    {
        const ssize_t written = write(fd, cursor, remaining);
        if (written > 0)
        {
            cursor += written;
            remaining -= (size_t)written;
            continue;
        }

        if (written < 0 && errno == EINTR)
        {
            continue;
        }

        return -1;
    }

    return 0;
}

static void SendRecord(
    uint16_t kind,
    uint16_t op,
    uint16_t flags,
    int32_t error,
    const char *source,
    size_t sourceLength,
    const char *destination,
    size_t destinationLength)
{
    if (g_socket < 0)
    {
        return;
    }

    if (sourceLength > kInterposeMaxPath)
    {
        sourceLength = kInterposeMaxPath;
        flags |= kFlagSourceTruncated;
    }

    if (destinationLength > kInterposeMaxPath)
    {
        destinationLength = kInterposeMaxPath;
        flags |= kFlagDestinationTruncated;
    }

    struct InterposeRecordHeader header;
    memset(&header, 0, sizeof(header));
    header.magic = kInterposeMagic;
    header.totalLength = (uint32_t)(sizeof(header) + sourceLength + destinationLength);
    header.kind = kind;
    header.op = op;
    header.flags = flags;
    header.version = kInterposeVersion;
    header.pid = g_pid;
    header.parentPid = g_parentPid;
    header.pidStartSeconds = g_pidStart;
    header.parentPidStartSeconds = g_parentPidStart;
    header.error = error;
    header.machTime = mach_absolute_time();
    header.sourceLength = (uint32_t)sourceLength;
    header.destinationLength = (uint32_t)destinationLength;

    pthread_mutex_lock(&g_lock);

    header.sequence = ++g_sequence;

    // One record must reach the ingress whole or not at all, so the header and both payloads go out
    // under the same lock. A short write here is unrecoverable: the stream is then misframed and the
    // ingress cannot tell where the next record starts, so the connection is dropped and the missing
    // sequence numbers become the pip's taint.
    if (WriteFully(g_socket, &header, sizeof(header)) != 0 ||
        (sourceLength > 0 && WriteFully(g_socket, source, sourceLength) != 0) ||
        (destinationLength > 0 && WriteFully(g_socket, destination, destinationLength) != 0))
    {
        CloseConnection();
    }

    pthread_mutex_unlock(&g_lock);
}

/**
 * Rewrites a shadow path back to the tool it stands in for.
 *
 * A shadowed process reads and stats its own image - dyld does, and so does anything that asks where
 * it is running from - and reporting the copy would put a private cache directory into the build's
 * observed accesses in place of the tool the pip declared, which is both wrong and a violation.
 *
 * Deliberately uncached. The obvious optimisation is a thread-local memo of the last shadow seen,
 * and it is fatal: a __thread buffer in a DYLD_INSERT_LIBRARIES library is allocated on first touch,
 * and first touch happens inside an interposed libc call, early, on a thread dyld has not finished
 * setting up. The process is SIGKILLed before main. No cache is needed anyway - BxlShadowResolve
 * begins with a prefix compare against the shadow directory, so every path that is not a shadow
 * costs one strncmp, and a process asks where it is running from a handful of times at startup.
 */
static size_t MapShadow(char *buffer, size_t length, size_t bufferSize)
{
    if (length == 0 || length >= bufferSize)
    {
        return length;
    }

    buffer[length] = '\0';

    char origin[BXL_SHADOW_PATH_MAX];
    if (!BxlShadowOrigin(buffer, origin, sizeof(origin)))
    {
        return length;
    }

    const size_t originLength = strlen(origin);
    if (originLength == 0 || originLength >= bufferSize)
    {
        return length;
    }

    memcpy(buffer, origin, originLength);
    return originLength;
}

/** Turns a possibly relative path into an absolute one. Never allocates. */
static size_t AbsolutizeRaw(const char *path, char *buffer, size_t bufferSize)
{
    // The empty string is not a relative path: it names no file and every call taking it fails with
    // ENOENT without reaching the filesystem. Joining it to the working directory would invent an
    // access to the directory that the caller never made.
    if (path == NULL || path[0] == '\0')
    {
        return 0;
    }

    if (path[0] == '/')
    {
        const size_t length = strnlen(path, bufferSize - 1);
        memcpy(buffer, path, length);
        return length;
    }

    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL)
    {
        const size_t length = strnlen(path, bufferSize - 1);
        memcpy(buffer, path, length);
        return length;
    }

    const size_t cwdLength = strnlen(cwd, sizeof(cwd));
    const size_t pathLength = strnlen(path, PATH_MAX);
    if (cwdLength + 1 + pathLength >= bufferSize)
    {
        memcpy(buffer, cwd, cwdLength);
        return cwdLength;
    }

    memcpy(buffer, cwd, cwdLength);
    buffer[cwdLength] = '/';
    memcpy(buffer + cwdLength + 1, path, pathLength);
    return cwdLength + 1 + pathLength;
}

/** Resolves a path that may be relative to a directory descriptor. */
static size_t AbsolutizeAtRaw(int fd, const char *path, char *buffer, size_t bufferSize)
{
    if (path != NULL && path[0] == '/')
    {
        return AbsolutizeRaw(path, buffer, bufferSize);
    }

    if (fd == AT_FDCWD || fd < 0)
    {
        return AbsolutizeRaw(path, buffer, bufferSize);
    }

    char base[PATH_MAX];
    if (fcntl(fd, F_GETPATH, base) == -1)
    {
        return AbsolutizeRaw(path, buffer, bufferSize);
    }

    const size_t baseLength = strnlen(base, sizeof(base));
    const size_t pathLength = path == NULL ? 0 : strnlen(path, PATH_MAX);
    if (pathLength == 0)
    {
        memcpy(buffer, base, baseLength < bufferSize ? baseLength : bufferSize - 1);
        return baseLength < bufferSize ? baseLength : bufferSize - 1;
    }

    if (baseLength + 1 + pathLength >= bufferSize)
    {
        memcpy(buffer, base, baseLength);
        return baseLength;
    }

    memcpy(buffer, base, baseLength);
    buffer[baseLength] = '/';
    memcpy(buffer + baseLength + 1, path, pathLength);
    return baseLength + 1 + pathLength;
}

static size_t Absolutize(const char *path, char *buffer, size_t bufferSize)
{
    return MapShadow(buffer, AbsolutizeRaw(path, buffer, bufferSize), bufferSize);
}

static size_t AbsolutizeAt(int fd, const char *path, char *buffer, size_t bufferSize)
{
    return MapShadow(buffer, AbsolutizeAtRaw(fd, path, buffer, bufferSize), bufferSize);
}

/**
 * What a call that failed proves about the path it names.
 *
 * A failure is not the absence of information, and guessing which errnos are informative turned out to
 * be the wrong shape of question. ENOENT is the only one that proves a path is not there. Every other
 * failure leaves the question open, so the honest answer is to look:
 *
 *   - mkdir answered EEXIST is how every "create if needed" discovers the directory already exists.
 *     Treating that as no information made .NET's Directory.CreateDirectory look like a write to a
 *     file that is not there, on every package the NuGet downloader unpacked twice.
 *   - readlink answered EINVAL means "this is not a symlink", which is how a caller learns it is a
 *     directory. Treating that as no information made every analyzer directory csc resolved look like
 *     a read of an undeclared file.
 *
 * So the rule is that the errno decides only whether to look, and the lookup decides the answer. It
 * cannot recurse: dyld does not apply an image's own interpositions to itself, which is the same
 * reason every wrapper here can call the function it wraps.
 */
static uint16_t FailureFlags(int capturedErrno, int fd, const char *path)
{
    if (capturedErrno == ENOENT || path == NULL)
    {
        return 0;
    }

    struct stat info;
    const int found = (fd == AT_FDCWD || path[0] == '/')
        ? lstat(path, &info)
        : fstatat(fd, path, &info, AT_SYMLINK_NOFOLLOW);

    if (found != 0)
    {
        return 0;
    }

    return (uint16_t)(kFlagSourceExists | (S_ISDIR(info.st_mode) ? kFlagSourceIsDirectory : 0));
}

/**
 * Existence and kind for a call that proves the path is there but not what it is.
 *
 * The policy engine allows any access to a directory outright, because there is no way to declare a
 * dependency on one and tools probe them constantly. So getting the kind wrong on a directory turns an
 * always-allowed probe into a violation. It matters more than it sounds: realpath() on macOS resolves
 * each component with getattrlist, so a single realpath of a deep path produced a violation for every
 * ancestor - /Users, /Users/janpro, and so on up - in protoc and in every .NET tool that canonicalises
 * a path.
 *
 * stat rather than lstat because these calls follow symlinks, so the kind that matters is the kind of
 * what they landed on.
 */
static uint16_t KindFlags(int result, int fd, const char *path)
{
    if (result != 0 || path == NULL)
    {
        return 0;
    }

    struct stat info;
    const int found = (fd == AT_FDCWD || path[0] == '/')
        ? stat(path, &info)
        : fstatat(fd, path, &info, 0);

    if (found != 0)
    {
        return kFlagSourceExists;
    }

    return (uint16_t)(kFlagSourceExists | (S_ISDIR(info.st_mode) ? kFlagSourceIsDirectory : 0));
}

static uint16_t OutcomeFlags(int result, uint16_t onSuccess, int capturedErrno, int fd, const char *path)
{
    return (uint16_t)(result == 0
        ? (kFlagSucceeded | onSuccess)
        : FailureFlags(capturedErrno, fd, path));
}

/**
 * What a call that succeeded proves about the path it names.
 *
 * The access checker picks between read, probe and enumerate using the mode the event carries, and a
 * mode of zero means "does not exist". Reporting every access as nonexistent is not a small
 * imprecision: a directory that was just created looks like a write to a file that is not there, which
 * is a violation rather than the allowed directory creation it actually was. So each interposer states
 * what its own success implies - mkdir made a directory, opendir opened one, chmod found something -
 * and the stat family, which is handed the answer by the kernel, reports the real st_mode instead of
 * guessing.
 */
#define BXL_EXISTS      ((uint16_t)kFlagSourceExists)
#define BXL_EXISTS_DIR  ((uint16_t)(kFlagSourceExists | kFlagSourceIsDirectory))
#define BXL_IS_DIR      ((uint16_t)kFlagSourceIsDirectory)
#define BXL_BOTH_EXIST  ((uint16_t)(kFlagSourceExists | kFlagDestinationExists))

/** Existence and kind taken from a stat that succeeded, rather than inferred. */
static uint16_t StatFlags(int result, const struct stat *info)
{
    if (result != 0 || info == NULL)
    {
        return 0;
    }

    return (uint16_t)(kFlagSourceExists | (S_ISDIR(info->st_mode) ? kFlagSourceIsDirectory : 0));
}

/** Existence and kind of an open file, taken from the descriptor the call returned. */
static uint16_t OpenedFlags(int fd)
{
    if (fd < 0)
    {
        return 0;
    }

    struct stat info;
    // fstat is not interposed, so this cannot recurse, and it needs no path resolution.
    if (fstat(fd, &info) != 0)
    {
        return kFlagSourceExists;
    }

    return (uint16_t)(kFlagSourceExists | (S_ISDIR(info.st_mode) ? kFlagSourceIsDirectory : 0));
}

/*
 * A call whose path argument is NULL or empty names no file. It fails without reaching the
 * filesystem - EFAULT or ENOENT - so there is nothing to report, and reporting it would push an
 * empty path into the access checker, which indexes the manifest by absolute path. Callers below
 * therefore drop the record rather than send a nameless one.
 */
/*
 * An observer has to be invisible, and errno is part of being invisible.
 *
 * Every interposer below runs its report *after* the real call has already set errno, and reporting
 * is not free of syscalls: it resolves the path (which can open and read a shadow's sidecar) and
 * then writes the record to a socket. Each of those overwrites errno, so without this the caller
 * reads the report's errno instead of its own.
 *
 * This is not cosmetic. libuv inspects errno after every I/O return, and a value it did not expect
 * makes it tear down a poll registration while the handle stays referenced; the event loop then
 * blocks forever in kevent() on a kqueue with nothing in it. That is what made npm hang under the
 * sandbox while the same command succeeded outside it: not a policy decision, not a lost event, just
 * a number the observer forgot to put back.
 *
 * The macros are deliberately spelled like the functions they replace so that call sites read the
 * same as they always did; the definitions above are the only place the Core names appear.
 */
#define BXL_PRESERVING_ERRNO(call)                                                                 \
    do                                                                                             \
    {                                                                                              \
        const int bxlSavedErrno = errno;                                                           \
        call;                                                                                      \
        errno = bxlSavedErrno;                                                                     \
    } while (0)

#define ReportOne(...) BXL_PRESERVING_ERRNO(ReportOneCore(__VA_ARGS__))
#define ReportOneAt(...) BXL_PRESERVING_ERRNO(ReportOneAtCore(__VA_ARGS__))
#define ReportTwo(...) BXL_PRESERVING_ERRNO(ReportTwoCore(__VA_ARGS__))
#define ReportTwoAt(...) BXL_PRESERVING_ERRNO(ReportTwoAtCore(__VA_ARGS__))
#define ReportExec(...) BXL_PRESERVING_ERRNO(ReportExecCore(__VA_ARGS__))
#define ReportUnobservable(...) BXL_PRESERVING_ERRNO(ReportUnobservableCore(__VA_ARGS__))
#define ReportIntermediateSymlinks(...) BXL_PRESERVING_ERRNO(ReportIntermediateSymlinksCore(__VA_ARGS__))

static void ReportOneCore(uint16_t op, const char *path, int result, int capturedErrno, uint16_t onSuccess)
{
    if (t_reporting || g_socket < 0)
    {
        return;
    }

    t_reporting = 1;

    char resolved[PATH_MAX + 64];
    const size_t length = Absolutize(path, resolved, sizeof(resolved));
    if (length == 0)
    {
        t_reporting = 0;
        return;
    }

    SendRecord(
        kRecordEvent,
        op,
        OutcomeFlags(result, onSuccess, capturedErrno, AT_FDCWD, path),
        result == 0 ? 0 : capturedErrno,
        resolved,
        length,
        NULL,
        0);

    t_reporting = 0;
}

static void ReportOneAtCore(uint16_t op, int fd, const char *path, int result, int capturedErrno, uint16_t onSuccess)
{
    if (t_reporting || g_socket < 0)
    {
        return;
    }

    t_reporting = 1;

    char resolved[PATH_MAX + 64];
    const size_t length = AbsolutizeAt(fd, path, resolved, sizeof(resolved));
    if (length == 0)
    {
        t_reporting = 0;
        return;
    }

    SendRecord(
        kRecordEvent,
        op,
        OutcomeFlags(result, onSuccess, capturedErrno, fd, path),
        result == 0 ? 0 : capturedErrno,
        resolved,
        length,
        NULL,
        0);

    t_reporting = 0;
}

static void ReportTwoCore(uint16_t op, const char *source, const char *destination, int result, int capturedErrno, uint16_t onSuccess)
{
    if (t_reporting || g_socket < 0)
    {
        return;
    }

    t_reporting = 1;

    char resolvedSource[PATH_MAX + 64];
    char resolvedDestination[PATH_MAX + 64];
    const size_t sourceLength = Absolutize(source, resolvedSource, sizeof(resolvedSource));
    const size_t destinationLength = Absolutize(destination, resolvedDestination, sizeof(resolvedDestination));
    if (sourceLength == 0 || destinationLength == 0)
    {
        t_reporting = 0;
        return;
    }

    SendRecord(
        kRecordEvent,
        op,
        OutcomeFlags(result, onSuccess, capturedErrno, AT_FDCWD, destination),
        result == 0 ? 0 : capturedErrno,
        resolvedSource,
        sourceLength,
        resolvedDestination,
        destinationLength);

    t_reporting = 0;
}

// ---------------------------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------------------------

static void Connect(void)
{
    const char *socketPath = getenv(BXL_INTERPOSE_SOCKET_ENV_VAR);
    if (socketPath == NULL || *socketPath == '\0')
    {
        return;
    }

    strncpy(g_socketPath, socketPath, sizeof(g_socketPath) - 1);

    const char *libraryPath = getenv(BXL_INTERPOSE_LIBRARY_ENV_VAR);
    if (libraryPath != NULL)
    {
        strncpy(g_libraryPath, libraryPath, sizeof(g_libraryPath) - 1);
    }

    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(g_socketPath) >= sizeof(address.sun_path))
    {
        return;
    }

    strncpy(address.sun_path, g_socketPath, sizeof(address.sun_path) - 1);

    const int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return;
    }

    // Not inherited across exec: the new image runs its own constructor and gets its own connection,
    // and a descriptor left open would otherwise be recycled by the child for something else - which
    // is observable as build output appearing in the report stream.
    fcntl(fd, F_SETFD, FD_CLOEXEC);

    if (connect(fd, (const struct sockaddr *)&address, (socklen_t)sizeof(address)) != 0)
    {
        close(fd);
        return;
    }

    g_socket = fd;
    g_sequence = 0;
    g_pid = (int32_t)getpid();
    g_parentPid = (int32_t)getppid();
    g_pidStart = ProcessStartSeconds((pid_t)g_pid);
    g_parentPidStart = ProcessStartSeconds((pid_t)g_parentPid);

    char executable[PATH_MAX];
    memset(executable, 0, sizeof(executable));
    int executableLength = proc_pidpath((int)g_pid, executable, (uint32_t)sizeof(executable));

    // A shadowed process is running a copy, and the build declared the original. Reporting the copy
    // would put a private cache directory into the observed accesses in place of the tool.
    char origin[PATH_MAX];
    if (executableLength > 0 && BxlShadowOrigin(executable, origin, sizeof(origin)))
    {
        strlcpy(executable, origin, sizeof(executable));
        executableLength = (int)strlen(executable);
    }

    SendRecord(
        kRecordHello,
        kOpUnknown,
        kFlagSucceeded,
        0,
        executable,
        executableLength > 0 ? (size_t)executableLength : 0,
        NULL,
        0);
}

/**
 * After fork() the child shares the parent's connection, and two processes writing framed records
 * into one stream produces a stream that decodes as neither. The child therefore drops the inherited
 * descriptor and connects on its own before it can report anything.
 */
static void OnForkInChild(void)
{
    // This runs inside fork() on the child side, so the very next thing the child does is read errno
    // - libuv's spawn path checks it between fork and exec and reports what it finds as a spawn
    // failure. Reconnecting must not look like one.
    const int savedErrno = errno;

    // The parent's descriptor belongs to the parent; closing it here would not disturb the parent's
    // own copy, but leaving it would corrupt the shared stream.
    g_socket = -1;
    pthread_mutex_init(&g_lock, NULL);
    Connect();

    errno = savedErrno;
}

__attribute__((constructor)) static void OnLoad(void)
{
    Connect();
    pthread_atfork(NULL, NULL, OnForkInChild);
}

__attribute__((destructor)) static void OnUnload(void)
{
    if (g_socket >= 0)
    {
        SendRecord(kRecordEvent, kOpExit, kFlagSucceeded, 0, NULL, 0, NULL, 0);
        CloseConnection();
    }
}

// ---------------------------------------------------------------------------------------------
// Process creation
// ---------------------------------------------------------------------------------------------

/**
 * Whether dyld will honour DYLD_INSERT_LIBRARIES for this binary.
 *
 * SIP protected files carry SF_RESTRICTED, and set-user-ID binaries are refused for the same reason.
 * A path that cannot be examined is reported as observable: the exec is about to fail anyway, and
 * inventing a taint for a failed exec would make ordinary PATH probing uncacheable.
 */
static int IsInjectable(const char *path)
{
    if (path == NULL)
    {
        return 1;
    }

    struct stat info;
    if (stat(path, &info) != 0)
    {
        return 1;
    }

    if ((info.st_flags & SF_RESTRICTED) != 0)
    {
        return 0;
    }

    if ((info.st_mode & (S_ISUID | S_ISGID)) != 0)
    {
        return 0;
    }

    return 1;
}

/**
 * The image to actually run in place of `path`.
 *
 * System Integrity Protection makes dyld drop the observation library from a protected binary and
 * erase DYLD_INSERT_LIBRARIES from its environment, so the process and everything below it goes
 * unobserved. On macOS that reaches almost every build: a shell script is a protected /bin/sh running
 * protected /bin/cp, /usr/bin/sed and /usr/bin/rsync. An ad-hoc signed copy is the same machine code
 * without the protection, so it can be observed. See ShadowTool.h for why a plain copy will not run.
 *
 * `path` is still what gets reported - it is what the pip declared and what its fingerprint is built
 * from - and argv is untouched, so the tool sees its own path in argv[0]. Falls back to the original
 * whenever a copy cannot be made, which is the same outcome as not trying.
 */
static const char *Injectable(const char *path, char *scratch, size_t size)
{
    return BxlShadowResolve(path, scratch, size) ? scratch : path;
}

static void ReportExecCore(uint16_t op, const char *path, const char *image)
{
    if (t_reporting || g_socket < 0)
    {
        return;
    }

    t_reporting = 1;

    char resolved[PATH_MAX + 64];
    const size_t length = Absolutize(path, resolved, sizeof(resolved));
    if (length == 0)
    {
        t_reporting = 0;
        return;
    }

    // Reported before the exec, because a successful execve never returns to report anything.
    // An image about to be executed is a regular file that exists; if it did not, the exec would
    // fail and the caller would carry on, having still made the access we are reporting.
    SendRecord(kRecordEvent, op, (uint16_t)(kFlagSucceeded | kFlagSourceExists), 0, resolved, length, NULL, 0);

    // The image, not the path: a shadowed tool is observable even though the tool it stands in for is
    // not, and claiming a loss that did not happen would make the pip uncacheable for no reason.
    if (!IsInjectable(image))
    {
        SendRecord(kRecordUnobservableChild, op, 0, 0, resolved, length, NULL, 0);
    }

    t_reporting = 0;
}

static void ReportTwoAtCore(
    uint16_t op,
    int sourceFd,
    const char *source,
    int destinationFd,
    const char *destination,
    int result,
    int capturedErrno, uint16_t onSuccess)
{
    if (t_reporting || g_socket < 0)
    {
        return;
    }

    t_reporting = 1;

    char resolvedSource[PATH_MAX + 64];
    char resolvedDestination[PATH_MAX + 64];
    const size_t sourceLength = AbsolutizeAt(sourceFd, source, resolvedSource, sizeof(resolvedSource));
    const size_t destinationLength =
        AbsolutizeAt(destinationFd, destination, resolvedDestination, sizeof(resolvedDestination));
    if (sourceLength == 0 || destinationLength == 0)
    {
        t_reporting = 0;
        return;
    }

    SendRecord(
        kRecordEvent,
        op,
        OutcomeFlags(result, onSuccess, capturedErrno, destinationFd, destination),
        result == 0 ? 0 : capturedErrno,
        resolvedSource,
        sourceLength,
        resolvedDestination,
        destinationLength);

    t_reporting = 0;
}

/**
 * Declares that something happened which the broker cannot model, so the pip must not be cached.
 *
 * Used for operations that invalidate the meaning of paths already reported rather than merely
 * adding one more access. Reporting them as ordinary accesses would be worse than not reporting them
 * at all, because the report would look complete.
 */
static void ReportUnobservableCore(const char *path, const char *reason)
{
    (void)reason;

    if (t_reporting || g_socket < 0)
    {
        return;
    }

    t_reporting = 1;

    char resolved[PATH_MAX + 64];
    const size_t length = Absolutize(path, resolved, sizeof(resolved));
    if (length == 0)
    {
        t_reporting = 0;
        return;
    }

    SendRecord(kRecordUnobservableChild, kOpUnknown, 0, 0, resolved, length, NULL, 0);

    t_reporting = 0;
}

// ---------------------------------------------------------------------------------------------
// Interposers
// ---------------------------------------------------------------------------------------------

static uint16_t OpenOp(int flags)
{
    if ((flags & O_CREAT) != 0)
    {
        return kOpCreate;
    }

    if ((flags & (O_WRONLY | O_RDWR | O_TRUNC | O_APPEND)) != 0)
    {
        return kOpOpenWrite;
    }

    return kOpOpenRead;
}

static int bxl_open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0)
    {
        va_list arguments;
        va_start(arguments, flags);
        mode = (mode_t)va_arg(arguments, int);
        va_end(arguments);
    }

    const int result = open(path, flags, mode);
    ReportOne(OpenOp(flags), path, result >= 0 ? 0 : -1, errno, OpenedFlags(result));
    return result;
}

static int bxl_open_nocancel(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0)
    {
        va_list arguments;
        va_start(arguments, flags);
        mode = (mode_t)va_arg(arguments, int);
        va_end(arguments);
    }

    const int result = bxl_real_open_nocancel(path, flags, mode);
    ReportOne(OpenOp(flags), path, result >= 0 ? 0 : -1, errno, OpenedFlags(result));
    return result;
}

static int bxl_openat(int fd, const char *path, int flags, ...)
{
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0)
    {
        va_list arguments;
        va_start(arguments, flags);
        mode = (mode_t)va_arg(arguments, int);
        va_end(arguments);
    }

    const int result = openat(fd, path, flags, mode);
    ReportOneAt(OpenOp(flags), fd, path, result >= 0 ? 0 : -1, errno, OpenedFlags(result));
    return result;
}

static int bxl_creat(const char *path, mode_t mode)
{
    const int result = creat(path, mode);
    ReportOne(kOpCreate, path, result >= 0 ? 0 : -1, errno, OpenedFlags(result));
    return result;
}

static int bxl_stat(const char *path, struct stat *out)
{
    const int result = stat(path, out);
    ReportOne(kOpStat, path, result, errno, StatFlags(result, out));
    return result;
}

static int bxl_lstat(const char *path, struct stat *out)
{
    const int result = lstat(path, out);
    ReportOne(kOpStat, path, result, errno, StatFlags(result, out));
    return result;
}

static int bxl_fstatat(int fd, const char *path, struct stat *out, int flag)
{
    const int result = fstatat(fd, path, out, flag);
    ReportOneAt(kOpStat, fd, path, result, errno, StatFlags(result, out));
    return result;
}

static int bxl_access(const char *path, int mode)
{
    const int result = access(path, mode);
    ReportOne(kOpAccess, path, result, errno, KindFlags(result, AT_FDCWD, path));
    return result;
}

static int bxl_faccessat(int fd, const char *path, int mode, int flag)
{
    const int result = faccessat(fd, path, mode, flag);
    ReportOneAt(kOpAccess, fd, path, result, errno, KindFlags(result, fd, path));
    return result;
}

/**
 * Opening a directory handle is a probe, not an enumeration.
 *
 * This was originally reported as kOpReadDir, and that one opcode cost 133 spurious cache misses on
 * every incremental self-build. An enumeration record makes the engine record the directory's entire
 * membership in the pip's path set, so the pip's strong fingerprint then depends on every name in
 * that directory. Pips that merely open a shared directory -- and every NuGet download pip opens the
 * shared package root -- were therefore invalidated whenever any other pip added a package to it.
 * A leaf-only source edit went from 2 executed pips to 135.
 *
 * The Linux backend already draws the line in the right place: its opendir reports kGenericProbe and
 * only readdir/getdents report an enumeration (Public/Src/Sandbox/Linux/detours.cpp). Matching that
 * is both more precise and more faithful -- opening a handle genuinely does not read any names.
 */
/**
 * Last descriptor reported as enumerated. See BxlNoteEnumerated for why this is a plain atomic
 * rather than thread-local storage.
 */
static _Atomic int g_lastEnumeratedFd = -1;

static DIR *bxl_opendir(const char *path)
{
    DIR *const result = opendir(path);
    ReportOne(kOpStat, path, result != NULL ? 0 : -1, errno, BXL_EXISTS_DIR);
    // A fresh handle must re-report on its first read even if the kernel reused the descriptor
    // number of a handle that was just closed. See BxlNoteEnumerated.
    atomic_store_explicit(&g_lastEnumeratedFd, -1, memory_order_relaxed);
    return result;
}

static DIR *bxl_fdopendir(int fd)
{
    DIR *const result = fdopendir(fd);
    ReportOneAt(kOpStat, fd, "", result != NULL ? 0 : -1, errno, BXL_EXISTS_DIR);
    atomic_store_explicit(&g_lastEnumeratedFd, -1, memory_order_relaxed);
    return result;
}

/**
 * Enumeration is per directory, but readdir is per entry, so a thousand-entry directory would send a
 * thousand identical records. Collapsing consecutive reads of the same descriptor removes that cost
 * without losing information: the records were identical, so dropping the repeats drops nothing.
 *
 * The memo is a single atomic int, deliberately not thread-local -- a __thread variable in a
 * DYLD_INSERT_LIBRARIES library is allocated on first touch, which here would happen inside an
 * interposed libc call on a thread dyld has not finished setting up, and that is fatal.
 *
 * Two threads enumerating different directories will thrash the memo and re-report. That is the safe
 * direction: this may over-report, never under-report.
 */
static void BxlNoteEnumerated(DIR *dirp)
{
    if (dirp == NULL)
    {
        return;
    }

    const int fd = dirfd(dirp);
    if (fd < 0)
    {
        return;
    }

    if (atomic_exchange_explicit(&g_lastEnumeratedFd, fd, memory_order_relaxed) != fd)
    {
        ReportOneAt(kOpReadDir, fd, "", 0, 0, BXL_EXISTS_DIR);
    }
}

static struct dirent *bxl_readdir(DIR *dirp)
{
    struct dirent *const result = readdir(dirp);
    BxlNoteEnumerated(dirp);
    return result;
}

// readdir_r is deprecated, but a program that calls it still enumerates a directory, and an
// observer that declines to watch deprecated entry points is simply an observer with a hole in it.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static int bxl_readdir_r(DIR *dirp, struct dirent *entry, struct dirent **out)
{
    const int result = readdir_r(dirp, entry, out);
    BxlNoteEnumerated(dirp);
    return result;
}
#pragma clang diagnostic pop

static ssize_t bxl_readlink(const char *path, char *buffer, size_t size)
{
    const ssize_t result = readlink(path, buffer, size);
    ReportOne(kOpReadLink, path, result >= 0 ? 0 : -1, errno, BXL_EXISTS);
    return result;
}

/**
 * Reports a readlink for every component of a path that really is a symlink.
 *
 * realpath() reads only the links it actually encounters, so reporting a readlink on the whole input,
 * or on components that are not links, invents dependencies the caller never took. Mirrors
 * report_intermediate_symlinks() in the Linux sandbox.
 * CODESYNC: Public/Src/Sandbox/Linux/detours.cpp (realpath)
 */
static void ReportIntermediateSymlinksCore(const char *path)
{
    if (path == NULL)
    {
        return;
    }

    const size_t total = strnlen(path, PATH_MAX);
    if (total == 0 || total >= PATH_MAX)
    {
        return;
    }

    char prefix[PATH_MAX];

    for (size_t i = 1; i <= total; i++)
    {
        if (i != total && path[i] != '/')
        {
            continue;
        }

        memcpy(prefix, path, i);
        prefix[i] = '\0';

        struct stat info;
        if (lstat(prefix, &info) == 0 && S_ISLNK(info.st_mode))
        {
            ReportOne(kOpReadLink, prefix, 0, 0, BXL_EXISTS);
        }
    }
}

/**
 * realpath() canonicalises a path; it does not read a link the caller already knows about.
 *
 * Reporting it as a readlink of its input was wrong in a way that only a real build could show: the
 * call succeeds on a directory, so it looked like a successful read of an existing non-directory, and
 * every analyzer directory that csc canonicalised became a missing source dependency. What the caller
 * actually learns is whether the path exists, so the input is a probe - and the links that were really
 * traversed are reported individually, exactly as the Linux sandbox does.
 */
static char *bxl_realpath(const char *path, char *resolved)
{
    char *const result = realpath(path, resolved);
    const int capturedErrno = errno;

    ReportOne(
        kOpStat,
        path,
        result != NULL ? 0 : -1,
        capturedErrno,
        result != NULL ? KindFlags(0, AT_FDCWD, path) : 0);

    // Only worth walking when something was actually resolved away.
    if (path != NULL && result != NULL && strcmp(path, result) != 0)
    {
        ReportIntermediateSymlinks(path);
        ReportOne(kOpStat, result, 0, 0, KindFlags(0, AT_FDCWD, result));
    }

    return result;
}

static int bxl_mkdir(const char *path, mode_t mode)
{
    const int result = mkdir(path, mode);
    ReportOne(kOpMkDir, path, result, errno, BXL_EXISTS_DIR);
    return result;
}

static int bxl_mkdirat(int fd, const char *path, mode_t mode)
{
    const int result = mkdirat(fd, path, mode);
    ReportOneAt(kOpMkDir, fd, path, result, errno, BXL_EXISTS_DIR);
    return result;
}

static int bxl_rmdir(const char *path)
{
    const int result = rmdir(path);
    ReportOne(kOpRmDir, path, result, errno, BXL_IS_DIR);
    return result;
}

static int bxl_unlink(const char *path)
{
    const int result = unlink(path);
    ReportOne(kOpUnlink, path, result, errno, 0);
    return result;
}

static int bxl_unlinkat(int fd, const char *path, int flag)
{
    const int result = unlinkat(fd, path, flag);
    ReportOneAt(kOpUnlink, fd, path, result, errno, 0);
    return result;
}

static int bxl_remove(const char *path)
{
    const int result = remove(path);
    ReportOne(kOpUnlink, path, result, errno, 0);
    return result;
}

static int bxl_rename(const char *from, const char *to)
{
    const int result = rename(from, to);
    ReportTwo(kOpRename, from, to, result, errno, BXL_BOTH_EXIST);
    return result;
}

static int bxl_renamex_np(const char *from, const char *to, unsigned int flags)
{
    const int result = renamex_np(from, to, flags);
    ReportTwo(kOpRename, from, to, result, errno, BXL_BOTH_EXIST);
    return result;
}

static int bxl_link(const char *from, const char *to)
{
    const int result = link(from, to);
    ReportTwo(kOpLink, from, to, result, errno, BXL_BOTH_EXIST);
    return result;
}

static int bxl_symlink(const char *target, const char *path)
{
    const int result = symlink(target, path);
    ReportTwo(kOpSymlink, target, path, result, errno, kFlagDestinationExists);
    return result;
}

static int bxl_clonefile(const char *from, const char *to, int flags)
{
    const int result = clonefile(from, to, flags);
    ReportTwo(kOpCloneFile, from, to, result, errno, BXL_BOTH_EXIST);
    return result;
}

static int bxl_chmod(const char *path, mode_t mode)
{
    const int result = chmod(path, mode);
    ReportOne(kOpChMod, path, result, errno, KindFlags(result, AT_FDCWD, path));
    return result;
}

static int bxl_chown(const char *path, uid_t owner, gid_t group)
{
    const int result = chown(path, owner, group);
    ReportOne(kOpChOwn, path, result, errno, KindFlags(result, AT_FDCWD, path));
    return result;
}

static int bxl_truncate(const char *path, off_t length)
{
    const int result = truncate(path, length);
    ReportOne(kOpTruncate, path, result, errno, BXL_EXISTS);
    return result;
}

static int bxl_utimensat(int fd, const char *path, const struct timespec times[2], int flag)
{
    const int result = utimensat(fd, path, times, flag);
    ReportOneAt(kOpUTimes, fd, path, result, errno, KindFlags(result, fd, path));
    return result;
}

static int bxl_chflags(const char *path, unsigned int flags)
{
    const int result = chflags(path, flags);
    ReportOne(kOpSetFlags, path, result, errno, KindFlags(result, AT_FDCWD, path));
    return result;
}

static int bxl_chdir(const char *path)
{
    const int result = chdir(path);
    ReportOne(kOpChDir, path, result, errno, BXL_EXISTS_DIR);
    return result;
}

static int bxl_execve(const char *path, char *const argv[], char *const envp[])
{
    char shadow[BXL_SHADOW_PATH_MAX];
    const char *const image = Injectable(path, shadow, sizeof(shadow));
    ReportExec(kOpExec, path, image);
    return execve(image, argv, envp);
}

static int bxl_posix_spawn(
    pid_t *pid,
    const char *path,
    const posix_spawn_file_actions_t *fileActions,
    const posix_spawnattr_t *attributes,
    char *const argv[],
    char *const envp[])
{
    char shadow[BXL_SHADOW_PATH_MAX];
    const char *const image = Injectable(path, shadow, sizeof(shadow));
    ReportExec(kOpSpawn, path, image);
    return posix_spawn(pid, image, fileActions, attributes, argv, envp);
}

static int bxl_posix_spawnp(
    pid_t *pid,
    const char *file,
    const posix_spawn_file_actions_t *fileActions,
    const posix_spawnattr_t *attributes,
    char *const argv[],
    char *const envp[])
{
    // A bare name is left alone: posix_spawnp resolves it against PATH, and guessing which entry it
    // will pick would be a different tool, not a copy of the same one.
    char shadow[BXL_SHADOW_PATH_MAX];
    const char *const image = Injectable(file, shadow, sizeof(shadow));
    ReportExec(kOpSpawn, file, image);
    return posix_spawnp(pid, image, fileActions, attributes, argv, envp);
}

// ---------------------------------------------------------------------------------------------
// Coverage completion
// ---------------------------------------------------------------------------------------------
//
// Everything below was added after enumerating every path-affecting export of
// libsystem_kernel.dylib and comparing it against what was interposed. Guessing which entry points
// a build actually uses is not a completeness argument; the list of what the kernel offers is.
// validate-interpose-coverage.py runs that comparison as a pip so this cannot drift.
//
// Note that several higher-level libc functions need no interposer of their own: dyld rebinds
// references made from inside libSystem too, so glob(), scandir(), ftw(), execl(), system() and
// popen() reach the interposed opendir/stat/execve. That is measured, not assumed -- see
// InterposeCoverageTests.

static int bxl_getattrlist(const char *path, void *list, void *buffer, size_t size, unsigned int options)
{
    const int result = getattrlist(path, list, buffer, size, options);
    ReportOne(kOpStat, path, result, errno, KindFlags(result, AT_FDCWD, path));
    return result;
}

static int bxl_setattrlist(const char *path, void *list, void *buffer, size_t size, unsigned int options)
{
    const int result = setattrlist(path, list, buffer, size, options);
    ReportOne(kOpSetFlags, path, result, errno, KindFlags(result, AT_FDCWD, path));
    return result;
}

static int bxl_getattrlistat(int fd, const char *path, void *list, void *buffer, size_t size, unsigned long options)
{
    const int result = getattrlistat(fd, path, list, buffer, size, options);
    ReportOneAt(kOpStat, fd, path, result, errno, KindFlags(result, fd, path));
    return result;
}

static int bxl_setattrlistat(int fd, const char *path, void *list, void *buffer, size_t size, uint32_t options)
{
    const int result = setattrlistat(fd, path, list, buffer, size, options);
    ReportOneAt(kOpSetFlags, fd, path, result, errno, KindFlags(result, fd, path));
    return result;
}

static int bxl_renameat(int fromFd, const char *from, int toFd, const char *to)
{
    const int result = renameat(fromFd, from, toFd, to);
    ReportTwoAt(kOpRename, fromFd, from, toFd, to, result, errno, BXL_BOTH_EXIST);
    return result;
}

static int bxl_renameatx_np(int fromFd, const char *from, int toFd, const char *to, unsigned int flags)
{
    const int result = renameatx_np(fromFd, from, toFd, to, flags);
    ReportTwoAt(kOpRename, fromFd, from, toFd, to, result, errno, BXL_BOTH_EXIST);
    return result;
}

static int bxl_linkat(int fromFd, const char *from, int toFd, const char *to, int flag)
{
    const int result = linkat(fromFd, from, toFd, to, flag);
    ReportTwoAt(kOpLink, fromFd, from, toFd, to, result, errno, BXL_BOTH_EXIST);
    return result;
}

static int bxl_symlinkat(const char *target, int fd, const char *path)
{
    const int result = symlinkat(target, fd, path);
    ReportOneAt(kOpSymlink, fd, path, result, errno, BXL_EXISTS);
    return result;
}

static ssize_t bxl_readlinkat(int fd, const char *path, char *buffer, size_t size)
{
    const ssize_t result = readlinkat(fd, path, buffer, size);
    ReportOneAt(kOpReadLink, fd, path, result < 0 ? -1 : 0, errno, BXL_EXISTS);
    return result;
}

static int bxl_fchmodat(int fd, const char *path, mode_t mode, int flag)
{
    const int result = fchmodat(fd, path, mode, flag);
    ReportOneAt(kOpChMod, fd, path, result, errno, KindFlags(result, fd, path));
    return result;
}

static int bxl_fchownat(int fd, const char *path, uid_t owner, gid_t group, int flag)
{
    const int result = fchownat(fd, path, owner, group, flag);
    ReportOneAt(kOpChOwn, fd, path, result, errno, KindFlags(result, fd, path));
    return result;
}

static int bxl_lchown(const char *path, uid_t owner, gid_t group)
{
    const int result = lchown(path, owner, group);
    ReportOne(kOpChOwn, path, result, errno, KindFlags(result, AT_FDCWD, path));
    return result;
}

static int bxl_lchflags(const char *path, unsigned int flags)
{
    const int result = lchflags(path, flags);
    ReportOne(kOpSetFlags, path, result, errno, KindFlags(result, AT_FDCWD, path));
    return result;
}

static int bxl_utimes(const char *path, const struct timeval times[2])
{
    const int result = utimes(path, times);
    ReportOne(kOpUTimes, path, result, errno, KindFlags(result, AT_FDCWD, path));
    return result;
}

static int bxl_lutimes(const char *path, const struct timeval times[2])
{
    const int result = lutimes(path, times);
    ReportOne(kOpUTimes, path, result, errno, KindFlags(result, AT_FDCWD, path));
    return result;
}

static int bxl_copyfile(const char *from, const char *to, copyfile_state_t state, copyfile_flags_t flags)
{
    const int result = copyfile(from, to, state, flags);
    ReportTwo(kOpCopyFile, from, to, result, errno, BXL_BOTH_EXIST);
    return result;
}

static int bxl_clonefileat(int fromFd, const char *from, int toFd, const char *to, unsigned int flags)
{
    const int result = clonefileat(fromFd, from, toFd, to, flags);
    ReportTwoAt(kOpCloneFile, fromFd, from, toFd, to, result, errno, BXL_BOTH_EXIST);
    return result;
}

static int bxl_exchangedata(const char *first, const char *second, unsigned int options)
{
    const int result = exchangedata(first, second, options);
    ReportTwo(kOpRename, first, second, result, errno, BXL_BOTH_EXIST);
    return result;
}

static int bxl_mkfifo(const char *path, mode_t mode)
{
    const int result = mkfifo(path, mode);
    ReportOne(kOpCreate, path, result, errno, BXL_EXISTS);
    return result;
}

static int bxl_mkfifoat(int fd, const char *path, mode_t mode)
{
    const int result = mkfifoat(fd, path, mode);
    ReportOneAt(kOpCreate, fd, path, result, errno, BXL_EXISTS);
    return result;
}

static int bxl_mknod(const char *path, mode_t mode, dev_t dev)
{
    const int result = mknod(path, mode, dev);
    ReportOne(kOpCreate, path, result, errno, BXL_EXISTS);
    return result;
}

/**
 * The modern bulk directory enumeration call. Reported as a directory read against the descriptor's
 * path: BuildXL models enumeration per directory, so the individual entries returned do not need to
 * be reported, but the fact that the directory was enumerated does.
 */
static int bxl_getattrlistbulk(int fd, void *list, void *buffer, size_t size, uint64_t options)
{
    const int result = getattrlistbulk(fd, list, buffer, size, options);
    ReportOneAt(kOpReadDir, fd, "", result < 0 ? -1 : 0, errno, BXL_EXISTS_DIR);
    return result;
}

/**
 * The real bulk enumeration entry point behind readdir.
 *
 * The documented legacy call, getdirentries, cannot be reached at all on this platform: with 64-bit
 * inodes in effect -- which is unconditional on arm64 -- the SDK redirects it to a deliberately
 * undefined symbol, so a program that calls it fails to link. __getdirentries64 is what libsystem
 * actually uses, and it is exported, so a program can import it directly.
 *
 * libsystem's readdir reaches it by a cross-image call, which interposition does see, so a plain
 * readdir loop reports twice: once here and once from bxl_readdir. That is deliberate. Deduplicating
 * would mean memoising a descriptor number across two layers, and a descriptor number is only unique
 * until it is closed and reused, so the memo could suppress a real enumeration of a different
 * directory. A path set is a set, so the cost of the duplicate is a few thousand extra records in a
 * full build and nothing else, and a missed enumeration is a wrong cache hit. getattrlistbulk has
 * the same shape for the same reason.
 *
 * These were previously exempt from coverage on the grounds that a directory descriptor can only be
 * obtained from the interposed open or opendir. That reasoning depended on opendir reporting an
 * enumeration, and it deliberately no longer does.
 */
extern ssize_t __getdirentries64(int fd, void *buffer, size_t bufferSize, off_t *position);

static ssize_t bxl_getdirentries64(int fd, void *buffer, size_t bufferSize, off_t *position)
{
    const ssize_t result = __getdirentries64(fd, buffer, bufferSize, position);
    ReportOneAt(kOpReadDir, fd, "", result < 0 ? -1 : 0, errno, BXL_EXISTS_DIR);
    return result;
}

static int bxl_mknodat(int fd, const char *path, mode_t mode, dev_t dev)
{
    const int result = mknodat(fd, path, mode, dev);
    ReportOneAt(kOpCreate, fd, path, result, errno, BXL_EXISTS);
    return result;
}

static int bxl_statfs(const char *path, struct statfs *out)
{
    const int result = statfs(path, out);
    ReportOne(kOpStat, path, result, errno, KindFlags(result, AT_FDCWD, path));
    return result;
}

static long bxl_pathconf(const char *path, int name)
{
    const long result = pathconf(path, name);
    ReportOne(kOpStat, path, result < 0 ? -1 : 0, errno, KindFlags(result < 0 ? -1 : 0, AT_FDCWD, path));
    return result;
}

/**
 * chroot changes what every subsequent absolute path means, so every path already reported and every
 * path still to come is measured against a root the broker does not know. There is no way to report
 * that correctly, so it is reported as unmodellable and the pip is not cached.
 */
static int bxl_chroot(const char *path)
{
    ReportUnobservable(path, "chroot changes path resolution for the rest of the process");
    return chroot(path);
}

BXL_INTERPOSE(bxl_open, open)
BXL_INTERPOSE(bxl_open_nocancel, bxl_real_open_nocancel)
BXL_INTERPOSE(bxl_openat, openat)
BXL_INTERPOSE(bxl_creat, creat)
BXL_INTERPOSE(bxl_stat, stat)
BXL_INTERPOSE(bxl_lstat, lstat)
BXL_INTERPOSE(bxl_fstatat, fstatat)
BXL_INTERPOSE(bxl_access, access)
BXL_INTERPOSE(bxl_faccessat, faccessat)
BXL_INTERPOSE(bxl_opendir, opendir)
BXL_INTERPOSE(bxl_fdopendir, fdopendir)
BXL_INTERPOSE(bxl_readdir, readdir)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
BXL_INTERPOSE(bxl_readdir_r, readdir_r)
#pragma clang diagnostic pop
BXL_INTERPOSE(bxl_readlink, readlink)
BXL_INTERPOSE(bxl_realpath, realpath)
BXL_INTERPOSE(bxl_mkdir, mkdir)
BXL_INTERPOSE(bxl_mkdirat, mkdirat)
BXL_INTERPOSE(bxl_rmdir, rmdir)
BXL_INTERPOSE(bxl_unlink, unlink)
BXL_INTERPOSE(bxl_unlinkat, unlinkat)
BXL_INTERPOSE(bxl_remove, remove)
BXL_INTERPOSE(bxl_rename, rename)
BXL_INTERPOSE(bxl_renamex_np, renamex_np)
BXL_INTERPOSE(bxl_link, link)
BXL_INTERPOSE(bxl_symlink, symlink)
BXL_INTERPOSE(bxl_clonefile, clonefile)
BXL_INTERPOSE(bxl_chmod, chmod)
BXL_INTERPOSE(bxl_chown, chown)
BXL_INTERPOSE(bxl_truncate, truncate)
BXL_INTERPOSE(bxl_utimensat, utimensat)
BXL_INTERPOSE(bxl_chflags, chflags)
BXL_INTERPOSE(bxl_chdir, chdir)
BXL_INTERPOSE(bxl_execve, execve)
BXL_INTERPOSE(bxl_posix_spawn, posix_spawn)
BXL_INTERPOSE(bxl_posix_spawnp, posix_spawnp)
BXL_INTERPOSE(bxl_getattrlist, getattrlist)
BXL_INTERPOSE(bxl_setattrlist, setattrlist)
BXL_INTERPOSE(bxl_getattrlistat, getattrlistat)
BXL_INTERPOSE(bxl_setattrlistat, setattrlistat)
BXL_INTERPOSE(bxl_renameat, renameat)
BXL_INTERPOSE(bxl_renameatx_np, renameatx_np)
BXL_INTERPOSE(bxl_linkat, linkat)
BXL_INTERPOSE(bxl_symlinkat, symlinkat)
BXL_INTERPOSE(bxl_readlinkat, readlinkat)
BXL_INTERPOSE(bxl_fchmodat, fchmodat)
BXL_INTERPOSE(bxl_fchownat, fchownat)
BXL_INTERPOSE(bxl_lchown, lchown)
BXL_INTERPOSE(bxl_lchflags, lchflags)
BXL_INTERPOSE(bxl_utimes, utimes)
BXL_INTERPOSE(bxl_lutimes, lutimes)
BXL_INTERPOSE(bxl_copyfile, copyfile)
BXL_INTERPOSE(bxl_clonefileat, clonefileat)
BXL_INTERPOSE(bxl_exchangedata, exchangedata)
BXL_INTERPOSE(bxl_mkfifo, mkfifo)
BXL_INTERPOSE(bxl_mkfifoat, mkfifoat)
BXL_INTERPOSE(bxl_mknod, mknod)
BXL_INTERPOSE(bxl_statfs, statfs)
BXL_INTERPOSE(bxl_pathconf, pathconf)
BXL_INTERPOSE(bxl_chroot, chroot)
BXL_INTERPOSE(bxl_getattrlistbulk, getattrlistbulk)
BXL_INTERPOSE(bxl_getdirentries64, __getdirentries64)
BXL_INTERPOSE(bxl_mknodat, mknodat)
