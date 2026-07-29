#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Checks that the interposition sandbox observes every way a process can reach the filesystem.

A sandbox that misses one entry point does not fail loudly: it reports a slightly shorter list of
accesses, BuildXL caches the pip against that list, and the build is wrong on some later machine in
a way nobody can reproduce. Reviewing bxl-interpose.c cannot find that, because the defect is a
function that isn't there.

So the list of what must be covered is not written by hand. It is read out of libsystem_kernel.dylib,
which is the complete set of path-affecting entry points the kernel offers, and compared against the
interpose table. Anything present in the first and absent from the second must appear in EXEMPT with
a reason, or this exits non-zero.

Two things this deliberately does not claim:

  * That an interposed function reports *correctly*. That is what the runtime tests are for.
  * That libSystem is the only way to reach the kernel. A statically linked binary issuing raw
    syscalls bypasses interposition entirely. That is a property of the mechanism, not a gap in the
    table, and it is why exec of a binary that cannot be injected is reported as unobservable.

Usage:
    validate-interpose-coverage.py [--source bxl-interpose.c] [--fault-inject SYMBOL]
"""

import argparse
import os
import re
import subprocess
import sys

# Every path-affecting entry point, matched against libsystem_kernel's export list. Kept as a
# pattern rather than a literal list so a newly added variant of an existing call (another *at form,
# another $NOCANCEL alias) is caught rather than skipped.
PATH_AFFECTING = re.compile(
    r'^(open|openat|open_dprotected_np|openbyid_np|creat|'
    r'stat|stat64|lstat|lstat64|fstatat|fstatat64|statfs|statfs64|getfsstat|'
    r'access|faccessat|'
    r'mkdir|mkdirat|mkfifo|mkfifoat|mknod|mknodat|rmdir|unlink|unlinkat|'
    r'rename|renameat|renameatx_np|renamex_np|'
    r'link|linkat|symlink|symlinkat|readlink|readlinkat|'
    r'chmod|fchmodat|chown|lchown|fchownat|chflags|lchflags|chflagsat|truncate|'
    r'utimes|lutimes|utimensat|futimesat|'
    r'setattrlist|getattrlist|getattrlistat|setattrlistat|getattrlistbulk|'
    r'searchfs|fsgetpath|getdirentries|getdirentriesattr|'
    r'clonefile|clonefileat|fclonefileat|copyfile|exchangedata|undelete|revoke|'
    r'chdir|chroot|acct|mount|unmount|quotactl|pathconf|'
    r'execve|posix_spawn|fork|vfork|__fork)'
    r'(\$NOCANCEL|\$INODE64|\$UNIX2003|\$1050)?$')

# Uncovered on purpose. Each entry is a claim that can be checked and argued with, which is the only
# kind of exemption worth having.
EXEMPT = {
    # Handled by a different mechanism, not by an interposer.
    "fork": "pthread_atfork drops the inherited socket and reconnects in the child; a fork with no "
            "exec is therefore reported by the child itself rather than by the parent's call",
    "vfork": "the child may only exec or _exit, and the exec is reported by the new image's HELLO",
    "__fork": "the libc private entry point behind fork(), covered by the same atfork handler",
    "posix_spawnp": "interposed, listed here only because the export scan sees it under both names",

    # Reached only through an entry point that is interposed. Measured, not assumed:
    # InterposeCoverageTests exercises each of these and asserts the access is reported.
    "getdirentries": "directory contents are only reachable through a descriptor obtained from the "
                     "interposed open/opendir, and BuildXL models enumeration per directory",
    "getdirentriesattr": "same descriptor argument as getdirentries",
    "fclonefileat": "takes a source descriptor, which came from an interposed open",

    # Cannot occur inside a pip without the pip already being uncacheable for another reason.
    "mount": "requires root and changes what every path in the build means; a pip that mounts is "
             "not reproducible regardless of what the sandbox reports",
    "unmount": "see mount",
    "acct": "process accounting is a system-wide privileged operation, not a build action",
    "quotactl": "filesystem quota administration, requires root",
    "revoke": "requires root",
    "undelete": "whitefs-only operation with no filesystem BuildXL runs on",
    "searchfs": "catalogue search returns paths without opening them, and is unavailable on APFS "
                "volumes without the deprecated HFS+ catalogue",
    "fsgetpath": "resolves a file ID that could only have been obtained from an interposed call",
    "getfsstat": "enumerates mounted volumes, not paths within them",

    # Legacy ABI aliases that do not exist on arm64.
    "stat64": "64-bit inode variants exist only in the i386 ABI; arm64 stat is already 64-bit",
    "lstat64": "see stat64",
    "fstatat64": "see stat64",
    "statfs64": "see stat64",
    "open_dprotected_np": "data-protection classes are an iOS concept; the call fails on macOS "
                          "volumes and cannot create a file the build then depends on",
    "openbyid_np": "opens by file ID, which could only have come from an interposed call",
    "chflagsat": "not exported by libsystem_kernel on macOS 27",
    "futimesat": "not exported by libsystem_kernel on macOS 27",
}


def kernel_exports():
    """Path-affecting symbols exported by libsystem_kernel.dylib."""
    library = "/usr/lib/system/libsystem_kernel.dylib"
    if not os.path.exists(library):
        raise SystemExit("cannot find %s" % library)

    architecture = "arm64e" if os.uname().machine == "arm64" else "x86_64"
    result = subprocess.run(
        ["dyld_info", "-arch", architecture, "-exports", library],
        capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit("dyld_info failed: %s" % result.stderr.strip())

    found = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[1].startswith("_"):
            continue
        symbol = parts[1][1:]
        if PATH_AFFECTING.match(symbol):
            found.add(symbol)
    return found


def interposed_symbols(source):
    text = open(source).read()
    symbols = set()
    for match in re.finditer(r'BXL_INTERPOSE\(\s*\w+\s*,\s*([A-Za-z_0-9$]+)\s*\)', text):
        name = match.group(1)
        # The $NOCANCEL aliases are declared through an asm label, so the table names the local
        # declaration rather than the aliased symbol.
        if name.startswith("bxl_real_"):
            name = name[len("bxl_real_"):].replace("_nocancel", "")
        symbols.add(name)
    return symbols


def normalize(symbol):
    for suffix in ("$NOCANCEL", "$INODE64", "$UNIX2003", "$1050"):
        symbol = symbol.replace(suffix, "")
    return symbol


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source",
                        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "bxl-interpose.c"))
    parser.add_argument("--fault-inject", metavar="SYMBOL",
                        help="pretend SYMBOL is not interposed, to prove this check can fail")
    arguments = parser.parse_args()

    exports = {normalize(s) for s in kernel_exports()}
    interposed = {normalize(s) for s in interposed_symbols(arguments.source)}

    if arguments.fault_inject:
        interposed.discard(arguments.fault_inject)
        EXEMPT.pop(arguments.fault_inject, None)

    uncovered = sorted(exports - interposed - set(EXEMPT))
    stale = sorted(set(EXEMPT) & interposed - {"posix_spawnp"})
    unused = sorted(set(EXEMPT) - exports - {"posix_spawnp"})

    print("libsystem_kernel path-affecting exports : %d" % len(exports))
    print("interposed                              : %d" % len(exports & interposed))
    print("exempt with a stated reason             : %d" % len(exports & set(EXEMPT)))
    print("uncovered                               : %d" % len(uncovered))

    failed = False

    if uncovered:
        failed = True
        print("\nThese can reach the filesystem and are neither interposed nor exempt.")
        print("Add an interposer to bxl-interpose.c, or add an entry to EXEMPT saying why not:")
        for symbol in uncovered:
            print("    %s" % symbol)

    if stale:
        failed = True
        print("\nExempt but actually interposed; remove the exemption so it stops excusing a gap:")
        for symbol in stale:
            print("    %s  (%s)" % (symbol, EXEMPT[symbol]))

    if unused:
        print("\nExempt but not exported by this OS. Harmless, but the reason may be out of date:")
        for symbol in unused:
            print("    %s" % symbol)

    print("\n%s" % ("FAILED" if failed else "PASSED"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
