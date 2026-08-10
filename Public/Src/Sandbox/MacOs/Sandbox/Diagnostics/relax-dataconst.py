#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Clears SG_READ_ONLY on __DATA_CONST in every CoreCLR library under the given roots.

WHY THIS EXISTS
---------------
Running an Endpoint Security client requires the restricted entitlement
com.apple.developer.endpoint-security.client. Apple grants that to real teams; a development
machine substitutes for it by disabling SIP *and* booting with amfi_get_out_of_my_way=1, which
makes the kernel honour an ad-hoc signature carrying the entitlement.

Disabling AMFI has a side effect that has nothing to do with BuildXL: CoreCLR can no longer start.
Every .NET process dies at startup with

    Failed to create CoreCLR, HRESULT: 0x8007000C

0x8007000C is E_OUTOFMEMORY, which is misleading. The real cause is that dyld maps __DATA_CONST
read-only when the segment carries SG_READ_ONLY, and CoreCLR writes to that segment while
initialising. With AMFI active the write is permitted; with AMFI disabled it faults and the runtime
reports the failure as an allocation error. Clearing the flag makes dyld leave the segment writable
and the runtime starts normally.

This was verified rather than assumed. Holding everything else fixed and toggling only this flag
decides whether the runtime starts, across .NET 9.0.18 and 11.0-preview.6, and for both
Microsoft-signed shared frameworks and ad-hoc-signed self-contained deployments. Neither the
signing authority nor the hardened-runtime flag (0x10000) changes the outcome: an ad-hoc signature
re-applied with --options runtime still fails while the flag is set.

SCOPE, AND WHY IT IS NOT PART OF THE PRODUCT
--------------------------------------------
This compensates for a *local* security configuration, so it is a diagnostic and not a build step.
On a machine with a real Endpoint Security entitlement, AMFI stays enabled and none of this is
needed. Nothing here is required to run BuildXL on macOS; it is required to run BuildXL on a
machine that had to fake the entitlement.

Every .NET runtime the build can reach has to be treated, not just the one BuildXL targets: the
runtime is resolved per process, so a single untreated copy - a rolled-forward credential provider,
a freshly materialised Download-resolver output - reintroduces the failure in a way that looks
unrelated to .NET. That is exactly why this is a sweep over roots rather than a single file.

USAGE
-----
    relax-dataconst.py --check <root> [<root> ...]     report status, change nothing
    relax-dataconst.py <root> [<root> ...]             patch and re-sign what needs it

Re-signing is required: editing a Mach-O invalidates its code signature, and an invalid signature
cannot be executed on Apple Silicon at all. Ad-hoc is sufficient because AMFI is not enforcing.
"""

import argparse
import os
import struct
import subprocess
import sys

LC_SEGMENT_64 = 0x19
SG_READ_ONLY = 0x10
SEGMENT_FLAGS_OFFSET = 68
MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE

# Only CoreCLR itself writes to __DATA_CONST during startup. Widening this would mean re-signing
# libraries that have no need of it, and every re-signed binary is one more thing that differs from
# what Microsoft shipped.
TARGET_NAMES = ("libcoreclr.dylib",)


def slice_offsets(buf):
    """Byte offsets of each Mach-O slice, so fat binaries are handled as well as thin ones."""
    magic, = struct.unpack_from(">I", buf, 0)
    if magic != FAT_MAGIC:
        return [0]

    count, = struct.unpack_from(">I", buf, 4)
    return [struct.unpack_from(">I", buf, 8 + i * 20 + 8)[0] for i in range(count)]


def visit(buf, base, clear):
    """Returns how many __DATA_CONST segments in this slice carry SG_READ_ONLY."""
    magic, = struct.unpack_from("<I", buf, base)
    if magic != MAGIC_64:
        return 0

    command_count, = struct.unpack_from("<I", buf, base + 16)
    offset = base + 32
    found = 0

    for _ in range(command_count):
        command, size = struct.unpack_from("<II", buf, offset)
        if command == LC_SEGMENT_64:
            name = buf[offset + 8:offset + 24].rstrip(b"\0").decode("ascii", "replace")
            flags, = struct.unpack_from("<I", buf, offset + SEGMENT_FLAGS_OFFSET)
            if name == "__DATA_CONST" and (flags & SG_READ_ONLY):
                found += 1
                if clear:
                    struct.pack_into("<I", buf, offset + SEGMENT_FLAGS_OFFSET, flags & ~SG_READ_ONLY)
        offset += size

    return found


def process(path, check_only):
    with open(path, "rb") as handle:
        buf = bytearray(handle.read())

    pending = sum(visit(buf, base, clear=not check_only) for base in slice_offsets(buf))
    if pending == 0:
        return "ok"

    if check_only:
        return "needs patching"

    with open(path, "wb") as handle:
        handle.write(buf)

    signed = subprocess.run(
        ["codesign", "--force", "--sign", "-", path],
        capture_output=True,
    )
    if signed.returncode != 0:
        return "PATCHED BUT SIGNING FAILED: " + signed.stderr.decode(errors="replace").strip()

    return "patched"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("roots", nargs="+", help="directories to sweep, or single files")
    parser.add_argument("--check", action="store_true", help="report status without modifying")
    args = parser.parse_args()

    targets = []
    for root in args.roots:
        if os.path.isfile(root):
            targets.append(root)
            continue
        for directory, _, files in os.walk(root):
            targets.extend(os.path.join(directory, f) for f in files if f in TARGET_NAMES)

    if not targets:
        print("no CoreCLR libraries found under: " + ", ".join(args.roots), file=sys.stderr)
        return 1

    outstanding = 0
    for path in sorted(targets):
        result = process(path, args.check)
        if result != "ok":
            outstanding += 1
        print(f"  {result:16} {path}")

    print(f"\n{len(targets)} inspected, {outstanding} {'still need patching' if args.check else 'changed'}")

    # A non-zero exit under --check is what makes this usable as a precondition before a build.
    return 1 if (args.check and outstanding) else 0


if __name__ == "__main__":
    sys.exit(main())
