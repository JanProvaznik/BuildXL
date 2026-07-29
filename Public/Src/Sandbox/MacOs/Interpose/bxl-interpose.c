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
#include <sys/attr.h>
#include <sys/clonefile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
#include <sys/un.h>
#include <unistd.h>

#include "InterposeProtocol.h"

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

/** Turns a possibly relative path into an absolute one. Never allocates. */
static size_t Absolutize(const char *path, char *buffer, size_t bufferSize)
{
    if (path == NULL)
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
static size_t AbsolutizeAt(int fd, const char *path, char *buffer, size_t bufferSize)
{
    if (path != NULL && path[0] == '/')
    {
        return Absolutize(path, buffer, bufferSize);
    }

    if (fd == AT_FDCWD || fd < 0)
    {
        return Absolutize(path, buffer, bufferSize);
    }

    char base[PATH_MAX];
    if (fcntl(fd, F_GETPATH, base) == -1)
    {
        return Absolutize(path, buffer, bufferSize);
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

static uint16_t OutcomeFlags(int result)
{
    return (uint16_t)(result == 0 ? kFlagSucceeded : 0);
}

static void ReportOne(uint16_t op, const char *path, int result, int capturedErrno)
{
    if (t_reporting || g_socket < 0)
    {
        return;
    }

    t_reporting = 1;

    char resolved[PATH_MAX + 64];
    const size_t length = Absolutize(path, resolved, sizeof(resolved));
    SendRecord(
        kRecordEvent,
        op,
        OutcomeFlags(result),
        result == 0 ? 0 : capturedErrno,
        resolved,
        length,
        NULL,
        0);

    t_reporting = 0;
}

static void ReportOneAt(uint16_t op, int fd, const char *path, int result, int capturedErrno)
{
    if (t_reporting || g_socket < 0)
    {
        return;
    }

    t_reporting = 1;

    char resolved[PATH_MAX + 64];
    const size_t length = AbsolutizeAt(fd, path, resolved, sizeof(resolved));
    SendRecord(
        kRecordEvent,
        op,
        OutcomeFlags(result),
        result == 0 ? 0 : capturedErrno,
        resolved,
        length,
        NULL,
        0);

    t_reporting = 0;
}

static void ReportTwo(uint16_t op, const char *source, const char *destination, int result, int capturedErrno)
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
    SendRecord(
        kRecordEvent,
        op,
        OutcomeFlags(result),
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
    const int executableLength = proc_pidpath((int)g_pid, executable, (uint32_t)sizeof(executable));
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
    // The parent's descriptor belongs to the parent; closing it here would not disturb the parent's
    // own copy, but leaving it would corrupt the shared stream.
    g_socket = -1;
    pthread_mutex_init(&g_lock, NULL);
    Connect();
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

static void ReportExec(uint16_t op, const char *path)
{
    if (t_reporting || g_socket < 0)
    {
        return;
    }

    t_reporting = 1;

    char resolved[PATH_MAX + 64];
    const size_t length = Absolutize(path, resolved, sizeof(resolved));

    // Reported before the exec, because a successful execve never returns to report anything.
    SendRecord(kRecordEvent, op, kFlagSucceeded, 0, resolved, length, NULL, 0);

    if (!IsInjectable(path))
    {
        SendRecord(kRecordUnobservableChild, op, 0, 0, resolved, length, NULL, 0);
    }

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
    ReportOne(OpenOp(flags), path, result >= 0 ? 0 : -1, errno);
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
    ReportOne(OpenOp(flags), path, result >= 0 ? 0 : -1, errno);
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
    ReportOneAt(OpenOp(flags), fd, path, result >= 0 ? 0 : -1, errno);
    return result;
}

static int bxl_creat(const char *path, mode_t mode)
{
    const int result = creat(path, mode);
    ReportOne(kOpCreate, path, result >= 0 ? 0 : -1, errno);
    return result;
}

static int bxl_stat(const char *path, struct stat *out)
{
    const int result = stat(path, out);
    ReportOne(kOpStat, path, result, errno);
    return result;
}

static int bxl_lstat(const char *path, struct stat *out)
{
    const int result = lstat(path, out);
    ReportOne(kOpStat, path, result, errno);
    return result;
}

static int bxl_fstatat(int fd, const char *path, struct stat *out, int flag)
{
    const int result = fstatat(fd, path, out, flag);
    ReportOneAt(kOpStat, fd, path, result, errno);
    return result;
}

static int bxl_access(const char *path, int mode)
{
    const int result = access(path, mode);
    ReportOne(kOpAccess, path, result, errno);
    return result;
}

static int bxl_faccessat(int fd, const char *path, int mode, int flag)
{
    const int result = faccessat(fd, path, mode, flag);
    ReportOneAt(kOpAccess, fd, path, result, errno);
    return result;
}

static DIR *bxl_opendir(const char *path)
{
    DIR *const result = opendir(path);
    ReportOne(kOpReadDir, path, result != NULL ? 0 : -1, errno);
    return result;
}

static ssize_t bxl_readlink(const char *path, char *buffer, size_t size)
{
    const ssize_t result = readlink(path, buffer, size);
    ReportOne(kOpReadLink, path, result >= 0 ? 0 : -1, errno);
    return result;
}

static char *bxl_realpath(const char *path, char *resolved)
{
    char *const result = realpath(path, resolved);
    ReportOne(kOpReadLink, path, result != NULL ? 0 : -1, errno);
    return result;
}

static int bxl_mkdir(const char *path, mode_t mode)
{
    const int result = mkdir(path, mode);
    ReportOne(kOpMkDir, path, result, errno);
    return result;
}

static int bxl_mkdirat(int fd, const char *path, mode_t mode)
{
    const int result = mkdirat(fd, path, mode);
    ReportOneAt(kOpMkDir, fd, path, result, errno);
    return result;
}

static int bxl_rmdir(const char *path)
{
    const int result = rmdir(path);
    ReportOne(kOpRmDir, path, result, errno);
    return result;
}

static int bxl_unlink(const char *path)
{
    const int result = unlink(path);
    ReportOne(kOpUnlink, path, result, errno);
    return result;
}

static int bxl_unlinkat(int fd, const char *path, int flag)
{
    const int result = unlinkat(fd, path, flag);
    ReportOneAt(kOpUnlink, fd, path, result, errno);
    return result;
}

static int bxl_remove(const char *path)
{
    const int result = remove(path);
    ReportOne(kOpUnlink, path, result, errno);
    return result;
}

static int bxl_rename(const char *from, const char *to)
{
    const int result = rename(from, to);
    ReportTwo(kOpRename, from, to, result, errno);
    return result;
}

static int bxl_renamex_np(const char *from, const char *to, unsigned int flags)
{
    const int result = renamex_np(from, to, flags);
    ReportTwo(kOpRename, from, to, result, errno);
    return result;
}

static int bxl_link(const char *from, const char *to)
{
    const int result = link(from, to);
    ReportTwo(kOpLink, from, to, result, errno);
    return result;
}

static int bxl_symlink(const char *target, const char *path)
{
    const int result = symlink(target, path);
    ReportTwo(kOpSymlink, target, path, result, errno);
    return result;
}

static int bxl_clonefile(const char *from, const char *to, int flags)
{
    const int result = clonefile(from, to, flags);
    ReportTwo(kOpCloneFile, from, to, result, errno);
    return result;
}

static int bxl_chmod(const char *path, mode_t mode)
{
    const int result = chmod(path, mode);
    ReportOne(kOpChMod, path, result, errno);
    return result;
}

static int bxl_chown(const char *path, uid_t owner, gid_t group)
{
    const int result = chown(path, owner, group);
    ReportOne(kOpChOwn, path, result, errno);
    return result;
}

static int bxl_truncate(const char *path, off_t length)
{
    const int result = truncate(path, length);
    ReportOne(kOpTruncate, path, result, errno);
    return result;
}

static int bxl_utimensat(int fd, const char *path, const struct timespec times[2], int flag)
{
    const int result = utimensat(fd, path, times, flag);
    ReportOneAt(kOpUTimes, fd, path, result, errno);
    return result;
}

static int bxl_chflags(const char *path, unsigned int flags)
{
    const int result = chflags(path, flags);
    ReportOne(kOpSetFlags, path, result, errno);
    return result;
}

static int bxl_chdir(const char *path)
{
    const int result = chdir(path);
    ReportOne(kOpChDir, path, result, errno);
    return result;
}

static int bxl_execve(const char *path, char *const argv[], char *const envp[])
{
    ReportExec(kOpExec, path);
    return execve(path, argv, envp);
}

static int bxl_posix_spawn(
    pid_t *pid,
    const char *path,
    const posix_spawn_file_actions_t *fileActions,
    const posix_spawnattr_t *attributes,
    char *const argv[],
    char *const envp[])
{
    ReportExec(kOpSpawn, path);
    return posix_spawn(pid, path, fileActions, attributes, argv, envp);
}

static int bxl_posix_spawnp(
    pid_t *pid,
    const char *file,
    const posix_spawn_file_actions_t *fileActions,
    const posix_spawnattr_t *attributes,
    char *const argv[],
    char *const envp[])
{
    ReportExec(kOpSpawn, file);
    return posix_spawnp(pid, file, fileActions, attributes, argv, envp);
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
