#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Runs a program under the interposition observer and prints every record it emits.

This exists because the interesting questions about the sandbox are usually of the form "what path
did it actually report for X?", and the expensive way to answer them is to run a build until the
condition reproduces and then read a violation message that has already lost the detail you wanted.
This takes the broker, the engine, the pip graph and the scheduler out of the picture: it binds a
unix socket, injects libBuildXLInterpose.dylib into one process, and shows you the wire.

It was written to settle one such question. BuildXL materialises deployments by hard-linking, so a
single inode routinely has several valid paths, and a violation naming one of them is ambiguous if
any layer resolves paths instead of reporting what the caller passed. Against a two-link inode this
prints the alias when the program opens the alias and the other link when it opens the other link,
which answers it in about a second:

    $ echo hi > /tmp/t/real.bin && ln /tmp/t/real.bin /tmp/t/alias.bin
    $ ./interpose-trace.py Out/Bin/release/osx-arm64/libBuildXLInterpose.dylib \
          /tmp/t/probe /tmp/t/alias.bin
    Event  OpenRead  flags=9  /tmp/t/alias.bin

Two things to know before the output confuses you:

  * macOS strips DYLD_INSERT_LIBRARIES from platform binaries, so tracing /bin/cat reports nothing
    at all rather than failing. That is SIP, not a bug here -- the build defeats it with shadow
    tools (see ShadowTool.h). Trace a binary you built, or a re-signed copy.
  * A hardened-runtime binary with library validation will SIGKILL on injection; the child exits
    with -9 and no records arrive.

CODESYNC: InterposeProtocol.h
"""

import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

# magic, totalLength | kind, op, flags, version | pid, parentPid, pidStart, parentPidStart
# | error, reserved | sequence, machTime | sourceLength, destinationLength
HEADER = struct.Struct("<II HHHH iiii iI QQ II")

MAGIC = 0x42584C49

OPS = {
    1: "OpenRead", 2: "OpenWrite", 3: "Create", 4: "Stat", 5: "Access", 6: "ReadDir",
    7: "ReadLink", 8: "MkDir", 9: "RmDir", 10: "Unlink", 11: "Rename", 12: "Link",
    13: "Symlink", 14: "ChMod", 15: "ChOwn", 16: "Truncate", 17: "UTimes",
    18: "CloneFile", 19: "CopyFile", 20: "Exec", 21: "Spawn", 22: "ChDir",
    23: "Exit", 24: "SetFlags",
}

KINDS = {1: "Hello", 2: "Event", 3: "UnobservableChild"}


class Collector:
    """Accepts observer connections and decodes records off them."""

    def __init__(self):
        self.records = []
        self._lock = threading.Lock()

    def serve(self, listener):
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            thread = threading.Thread(target=self._read, args=(connection,), daemon=True)
            thread.start()

    def _read(self, connection):
        buffered = b""
        with connection:
            while True:
                try:
                    chunk = connection.recv(1 << 16)
                except OSError:
                    return
                if not chunk:
                    return
                buffered += chunk
                buffered = self._drain(buffered)

    def _drain(self, buffered):
        while len(buffered) >= HEADER.size:
            fields = HEADER.unpack_from(buffered, 0)
            magic, total = fields[0], fields[1]
            if magic != MAGIC:
                print(f"stray connection: magic {magic:#x}", file=sys.stderr)
                return b""
            if len(buffered) < total:
                break
            kind, op, flags = fields[2], fields[3], fields[4]
            pid = fields[6]
            sourceLength, destinationLength = fields[14], fields[15]
            body = buffered[HEADER.size:total]
            source = body[:sourceLength].decode("utf-8", "replace")
            destination = body[sourceLength:sourceLength + destinationLength].decode("utf-8", "replace")
            with self._lock:
                self.records.append((kind, op, flags, pid, source, destination))
            buffered = buffered[total:]
        return buffered


def main(argv):
    if len(argv) < 3:
        print(f"usage: {os.path.basename(argv[0])} <libBuildXLInterpose.dylib> <program> [args...]",
              file=sys.stderr)
        return 2

    library, command = argv[1], argv[2:]
    if not os.path.exists(library):
        print(f"no such library: {library}", file=sys.stderr)
        return 2

    directory = tempfile.mkdtemp(prefix="bxl-interpose-trace-")
    socketPath = os.path.join(directory, "s")

    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(socketPath)
    listener.listen(64)

    collector = Collector()
    threading.Thread(target=collector.serve, args=(listener,), daemon=True).start()

    environment = dict(os.environ)
    environment["DYLD_INSERT_LIBRARIES"] = library
    environment["__BUILDXL_INTERPOSE_SOCKET"] = socketPath
    environment["__BUILDXL_INTERPOSE_LIBRARY"] = library

    completed = subprocess.run(command, env=environment)

    # The observer writes its closing records as the process exits, which can land after wait()
    # returns. Without this the last few records are lost, which is exactly the detail being
    # looked for often enough to be worth the delay.
    time.sleep(0.5)
    listener.close()
    os.unlink(socketPath)
    os.rmdir(directory)

    print(f"--- child exited {completed.returncode}, {len(collector.records)} records", file=sys.stderr)
    if completed.returncode == -9 and not collector.records:
        print("--- SIGKILL with no records usually means library validation rejected the injection",
              file=sys.stderr)
    if not collector.records:
        print("--- no records at all usually means SIP stripped DYLD_INSERT_LIBRARIES; "
              "platform binaries cannot be traced directly", file=sys.stderr)

    for kind, op, flags, pid, source, destination in collector.records:
        kindName = KINDS.get(kind, str(kind))
        opName = OPS.get(op, str(op)) if kind == 2 else ""
        line = f"{kindName:<18} {opName:<10} flags={flags:<4} pid={pid:<7} {source}"
        if destination:
            line += f"  ->  {destination}"
        print(line)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
