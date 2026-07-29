// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_MACOS_SHADOW_TOOL_H
#define BUILDXL_MACOS_SHADOW_TOOL_H

/**
 * Injectable copies of System Integrity Protection binaries.
 *
 * SIP is the one thing that makes the dyld-interposition backend structurally weaker than the Linux
 * sandbox. dyld refuses to load the observation library into a protected binary *and* erases
 * DYLD_INSERT_LIBRARIES from its environment, so neither the process nor anything it goes on to start
 * is observed. On macOS that is not a corner case: /bin/sh, /bin/bash, /usr/bin/rsync, /bin/cp and
 * /usr/bin/sed are all protected, BuildXL's own SDK copies directories with rsync, and any build with
 * a shell script in it runs almost entirely inside protected binaries.
 *
 * A plain copy does not run. These are arm64e platform binaries, and the kernel kills a non-platform
 * arm64e image outright - the copy is SIGKILLed before it reaches main, with or without injection.
 * Ad-hoc signing it makes it an ordinary user binary, which both runs and accepts injection. The
 * machine code is untouched; only the signature blob differs.
 *
 * Two callers, deliberately sharing one implementation so their names cannot drift apart: the broker
 * applies this to the pip's own tool before it spawns it, and the interposer applies it to every
 * executable a sandboxed process starts. Both must agree on the name, because they populate the same
 * directory and each is a cache hit for the other.
 *
 * Everything here uses libc directly. That is safe inside the interposer for the same reason every
 * wrapper there can call the function it wraps: dyld does not apply an image's own interpositions to
 * itself. So creating a shadow - the copy, the codesign, the rename - is invisible to the report
 * stream, which is what it should be. It is the build's own machinery, not the pip's behaviour.
 */

#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

extern char **environ;

/** Maximum length of a shadow path, including the terminator. */
#define BXL_SHADOW_PATH_MAX 512

/** Whether System Integrity Protection will make dyld refuse to inject into this file. */
static inline int BxlShadowIsRestricted(const struct stat *info)
{
    return (info->st_flags & SF_RESTRICTED) != 0;
}

/**
 * Creates the private directory the shadows live in.
 *
 * /tmp is world writable with the sticky bit, so the directory is created 0700 and its ownership and
 * mode are verified before it is used. Another user cannot pre-create it and substitute a binary the
 * build would then run, and if one has, this fails rather than proceeding.
 */
static inline int BxlShadowEnsureDirectory(const char *directory)
{
    struct stat info;

    if (mkdir(directory, 0700) != 0 && errno != EEXIST)
    {
        return 0;
    }

    if (lstat(directory, &info) != 0)
    {
        return 0;
    }

    return S_ISDIR(info.st_mode)
        && info.st_uid == getuid()
        && (info.st_mode & (S_IRWXG | S_IRWXO)) == 0;
}

/**
 * Names a shadow after which file it is and which version of that file.
 *
 * The hash is over the full path, so /bin/bash and /opt/homebrew/bin/bash cannot collide. The size and
 * modification time make an OS update produce a new name rather than silently reuse a stale copy.
 */
/**
 * Locale-free string building.
 *
 * Nothing here may call snprintf, and the reason is not style. These functions run inside interposed
 * libc calls, and one of the calls a process makes early is setlocale, which opens the locale file
 * while holding the locale lock. The open is interposed, the interposer builds a path, and snprintf
 * consults the locale for the decimal separator - on the same lock, on the same thread. libplatform
 * detects the recursion and aborts the process with SIGKILL:
 *
 *     BUG IN CLIENT OF LIBPLATFORM: Trying to recursively lock an os_unfair_lock
 *
 * Every process that runs a shadowed tool calls setlocale, so this is not an edge case; it killed
 * every shadowed tool until the formatting was made locale-free. Appending returns 0 once the buffer
 * is exhausted, and callers check once at the end rather than after every part.
 */
typedef struct
{
    char *buffer;
    size_t capacity;
    size_t length;
    int overflowed;
} BxlAppender;

static inline void BxlAppendInit(BxlAppender *appender, char *buffer, size_t capacity)
{
    appender->buffer = buffer;
    appender->capacity = capacity;
    appender->length = 0;
    appender->overflowed = capacity == 0;

    if (capacity > 0)
    {
        buffer[0] = '\0';
    }
}

static inline void BxlAppendText(BxlAppender *appender, const char *text)
{
    size_t index = 0;

    if (appender->overflowed || text == NULL)
    {
        return;
    }

    while (text[index] != '\0')
    {
        if (appender->length + 1 >= appender->capacity)
        {
            appender->overflowed = 1;
            return;
        }

        appender->buffer[appender->length++] = text[index++];
    }

    appender->buffer[appender->length] = '\0';
}

static inline void BxlAppendUnsigned(BxlAppender *appender, unsigned long long value, int width, int hex)
{
    char digits[32];
    int count = 0;
    const char *alphabet = "0123456789abcdef";
    const unsigned long long radix = hex ? 16ULL : 10ULL;

    do
    {
        digits[count++] = alphabet[value % radix];
        value /= radix;
    } while (value != 0 && count < (int)sizeof(digits));

    while (count < width && count < (int)sizeof(digits))
    {
        digits[count++] = '0';
    }

    while (count > 0)
    {
        char one[2];
        one[0] = digits[--count];
        one[1] = '\0';
        BxlAppendText(appender, one);
    }
}

static inline int BxlAppendDone(const BxlAppender *appender)
{
    return !appender->overflowed;
}

/** Writes "/tmp/.bxl-sandbox-<uid>" into the buffer. */
static inline int BxlShadowRoot(char *out, size_t outSize)
{
    BxlAppender appender;
    BxlAppendInit(&appender, out, outSize);
    BxlAppendText(&appender, "/tmp/.bxl-sandbox-");
    BxlAppendUnsigned(&appender, (unsigned long long)getuid(), 0, 0);
    return BxlAppendDone(&appender);
}

static inline int BxlShadowPath(const char *path, const struct stat *info, char *out, size_t outSize)
{
    uint64_t hash = 14695981039346656037ULL;
    const char *cursor = path;
    const char *base = path;
    const char *slash = strrchr(path, '/');
    BxlAppender appender;

    while (*cursor != '\0')
    {
        hash = (hash ^ (uint64_t)(unsigned char)*cursor) * 1099511628211ULL;
        cursor++;
    }

    if (slash != NULL)
    {
        base = slash + 1;
    }

    BxlAppendInit(&appender, out, outSize);
    BxlAppendText(&appender, "/tmp/.bxl-sandbox-");
    BxlAppendUnsigned(&appender, (unsigned long long)getuid(), 0, 0);
    BxlAppendText(&appender, "/tools/");
    BxlAppendText(&appender, base);
    BxlAppendText(&appender, "-");
    BxlAppendUnsigned(&appender, (unsigned long long)hash, 16, 1);
    BxlAppendText(&appender, "-");
    BxlAppendUnsigned(&appender, (unsigned long long)info->st_size, 0, 0);
    BxlAppendText(&appender, "-");
    BxlAppendUnsigned(&appender, (unsigned long long)info->st_mtimespec.tv_sec, 0, 0);
    BxlAppendText(&appender, ".");
    BxlAppendUnsigned(&appender, (unsigned long long)info->st_mtimespec.tv_nsec, 9, 0);

    return BxlAppendDone(&appender);
}

/** Copies a file's bytes into a new private executable. */
static inline int BxlShadowCopy(const char *from, const char *to)
{
    char buffer[64 * 1024];
    int source;
    int destination;
    ssize_t got;
    int ok = 1;

    source = open(from, O_RDONLY);
    if (source < 0)
    {
        return 0;
    }

    destination = open(to, O_WRONLY | O_CREAT | O_EXCL, 0700);
    if (destination < 0)
    {
        close(source);
        return 0;
    }

    while ((got = read(source, buffer, sizeof(buffer))) > 0)
    {
        ssize_t written = 0;
        while (written < got)
        {
            const ssize_t step = write(destination, buffer + written, (size_t)(got - written));
            if (step <= 0)
            {
                ok = 0;
                break;
            }

            written += step;
        }

        if (!ok)
        {
            break;
        }
    }

    if (got < 0)
    {
        ok = 0;
    }

    close(source);
    close(destination);

    if (!ok)
    {
        unlink(to);
    }

    return ok;
}

/** Ad-hoc signs a file, with codesign's output discarded. Returns 1 on success. */
static inline int BxlShadowSign(const char *path)
{
    const char *arguments[6];
    posix_spawn_file_actions_t actions;
    pid_t child = -1;
    int status = 0;
    int spawned;

    arguments[0] = "/usr/bin/codesign";
    arguments[1] = "--force";
    arguments[2] = "--sign";
    arguments[3] = "-";
    arguments[4] = path;
    arguments[5] = NULL;

    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);

    spawned = posix_spawn(&child, arguments[0], &actions, NULL, (char *const *)arguments, environ);
    posix_spawn_file_actions_destroy(&actions);

    if (spawned != 0)
    {
        return 0;
    }

    while (waitpid(child, &status, 0) < 0)
    {
        if (errno != EINTR)
        {
            return 0;
        }
    }

    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/**
 * Records which tool a shadow stands in for, beside it.
 *
 * A shadowed process sees its own image as the copy - proc_pidpath and _NSGetExecutablePath both
 * report the file that is actually running - and reporting that path would put a private cache
 * directory into the build's observed accesses in place of the tool the pip declared. A sidecar keeps
 * the answer with the copy, so it survives exec, works for any launcher, and needs no environment
 * plumbing that a caller supplying its own envp could drop.
 */
static inline void BxlShadowWriteOrigin(const char *shadow, const char *original)
{
    char sidecar[BXL_SHADOW_PATH_MAX + 32];
    char staging[BXL_SHADOW_PATH_MAX + 64];
    BxlAppender appender;
    int descriptor;
    size_t length;

    BxlAppendInit(&appender, sidecar, sizeof(sidecar));
    BxlAppendText(&appender, shadow);
    BxlAppendText(&appender, ".origin");
    if (!BxlAppendDone(&appender))
    {
        return;
    }

    BxlAppendInit(&appender, staging, sizeof(staging));
    BxlAppendText(&appender, sidecar);
    BxlAppendText(&appender, ".");
    BxlAppendUnsigned(&appender, (unsigned long long)getpid(), 0, 0);
    if (!BxlAppendDone(&appender))
    {
        return;
    }

    descriptor = open(staging, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (descriptor < 0)
    {
        return;
    }

    length = strlen(original);
    if (write(descriptor, original, length) != (ssize_t)length)
    {
        close(descriptor);
        unlink(staging);
        return;
    }

    close(descriptor);

    if (rename(staging, sidecar) != 0)
    {
        unlink(staging);
    }
}

/**
 * Recovers the tool a shadow stands in for. Returns 1 when `image` is a shadow and its origin is known.
 */
static inline int BxlShadowOrigin(const char *image, char *out, size_t outSize)
{
    char sidecar[BXL_SHADOW_PATH_MAX + 32];
    char prefix[64];
    BxlAppender appender;
    int descriptor;
    ssize_t got;

    if (image == NULL || out == NULL)
    {
        return 0;
    }

    // macOS resolves /tmp through a symlink, so a process asking the kernel for its own image path
    // gets /private/tmp. Both spellings name the same file and both have to be recognised.
    if (strncmp(image, "/private", 8) == 0)
    {
        image += 8;
    }

    BxlAppendInit(&appender, prefix, sizeof(prefix));
    BxlAppendText(&appender, "/tmp/.bxl-sandbox-");
    BxlAppendUnsigned(&appender, (unsigned long long)getuid(), 0, 0);
    BxlAppendText(&appender, "/tools/");
    if (!BxlAppendDone(&appender) || strncmp(image, prefix, appender.length) != 0)
    {
        return 0;
    }

    BxlAppendInit(&appender, sidecar, sizeof(sidecar));
    BxlAppendText(&appender, image);
    BxlAppendText(&appender, ".origin");
    if (!BxlAppendDone(&appender))
    {
        return 0;
    }

    descriptor = open(sidecar, O_RDONLY);
    if (descriptor < 0)
    {
        return 0;
    }

    got = read(descriptor, out, outSize - 1);
    close(descriptor);

    if (got <= 0)
    {
        return 0;
    }

    out[got] = '\0';
    return 1;
}

/**
 * Returns 1 and fills `out` when `path` needs an injectable copy and one is available.
 *
 * Returns 0 when the file is fine as it is, when it cannot be shadowed, or when anything went wrong -
 * every one of which means "run the original", so a caller never has to distinguish them. A setuid
 * binary is deliberately left alone: a copy would not be setuid, so it would not be the tool that was
 * asked for, and the reason dyld refuses it is one a copy would defeat rather than satisfy.
 */
static inline int BxlShadowResolve(const char *path, char *out, size_t outSize)
{
    struct stat info;
    struct stat existing;
    char staging[BXL_SHADOW_PATH_MAX + 32];
    char directory[64];
    BxlAppender appender;

    if (path == NULL || out == NULL || stat(path, &info) != 0)
    {
        return 0;
    }

    if (!BxlShadowIsRestricted(&info) || (info.st_mode & (S_ISUID | S_ISGID)) != 0 || !S_ISREG(info.st_mode))
    {
        return 0;
    }

    if (!BxlShadowPath(path, &info, out, outSize))
    {
        return 0;
    }

    if (stat(out, &existing) == 0)
    {
        return 1;
    }

    if (!BxlShadowRoot(directory, sizeof(directory)) || !BxlShadowEnsureDirectory(directory))
    {
        return 0;
    }

    strlcat(directory, "/tools", sizeof(directory));
    if (!BxlShadowEnsureDirectory(directory))
    {
        return 0;
    }

    // Built under a unique name and renamed into place, so a concurrent process either sees no copy or
    // a complete one. BuildXL runs one broker per executing pip, so this races constantly.
    BxlAppendInit(&appender, staging, sizeof(staging));
    BxlAppendText(&appender, out);
    BxlAppendText(&appender, ".tmp.");
    BxlAppendUnsigned(&appender, (unsigned long long)getpid(), 0, 0);
    if (!BxlAppendDone(&appender))
    {
        return 0;
    }

    unlink(staging);

    if (!BxlShadowCopy(path, staging))
    {
        return 0;
    }

    if (!BxlShadowSign(staging))
    {
        unlink(staging);
        return 0;
    }

    // Losing the race is a success: the winner wrote the same bytes under the same name.
    if (rename(staging, out) != 0 && stat(out, &existing) != 0)
    {
        unlink(staging);
        return 0;
    }

    unlink(staging);

    if (stat(out, &existing) != 0 || BxlShadowIsRestricted(&existing))
    {
        return 0;
    }

    BxlShadowWriteOrigin(out, path);
    return 1;
}

#ifdef __cplusplus
}
#endif

#endif // BUILDXL_MACOS_SHADOW_TOOL_H
