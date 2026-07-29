// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_INTERPOSE_INGRESS_H
#define BUILDXL_SANDBOX_MACOS_INTERPOSE_INGRESS_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "EventSource.h"

namespace buildxl {
namespace macos {

/**
 * The unentitled ingress: file accesses reported by libBuildXLInterpose.dylib, which dyld loads into
 * every process in the pip's tree.
 *
 * This exists because the Endpoint Security backend needs a restricted entitlement that a given
 * machine may simply never have - a hosted CI runner will not - and the alternative to a second
 * backend is running with no sandbox, which BuildXL treats as "no accesses" rather than as "unknown
 * accesses" and therefore caches unsound results.
 *
 * WHAT IT SHARES WITH THE KERNEL BACKEND
 *
 * Everything after the event boundary. Process attribution, sequence accounting, the fence, taint
 * propagation and translation are the same code, exercised the same way, because both backends
 * produce NormalizedEvent. Only the acquisition differs.
 *
 * WHERE IT IS WEAKER, STATED PLAINLY
 *
 * 1. It is cooperative. A process that issues syscalls directly, or that dlopen()s nothing and was
 *    never injected, is unobserved. The kernel backend cannot be evaded this way.
 * 2. dyld refuses to inject into SIP protected and platform binaries, and erases the variable from
 *    their environment so the loss is inherited. The injected library detects the case at exec time
 *    and reports kRecordUnobservableChild, which taints the pip; a tainted pip is re-run rather than
 *    cached, so the build stays correct while the observation does not.
 * 3. Identity is (pid, process start time) rather than (pid, pidversion). libproc exposes no
 *    pidversion. Start time in whole seconds is a weaker disambiguator than the kernel's counter.
 *
 * The transport is a stream socket per process rather than a shared datagram socket, and that choice
 * is load bearing twice over. Datagrams are dropped silently under pressure, and a dropped access is
 * precisely the failure that must not happen. And because each process owns its connection, its EOF
 * is a positive statement that the process produced no further events - which is what makes the
 * closing fence meaningful without a kernel-assigned global sequence.
 */
class InterposeIngress : public EventSource
{
public:
    /** @param socketPath where to listen. Empty means "choose a private path under TMPDIR". */
    explicit InterposeIngress(std::string socketPath = std::string());
    ~InterposeIngress() override;

    bool Start(EventHandler handler, std::string &errorMessage) override;
    void Stop() override;
    bool EmitMarker(const std::string &noncePath) override;
    ProcessIdentity BrokerIdentity() const override { return m_broker; }
    const char *BackendName() const override { return "dyld-interpose"; }

    /** Records lost inside a process, detected as a gap in that process's own sequence. */
    /**
     * Whether dyld will inject into this executable.
     *
     * False for anything SIP protected or setuid, where dyld both refuses to load the library and
     * erases DYLD_INSERT_LIBRARIES from the environment, so the loss is inherited by everything the
     * process goes on to start. Exposed so the broker can say that plainly when the pip's own tool is
     * one of them, rather than leaving an operator to infer it from a lifecycle taint.
     */
    static bool IsInjectable(const std::string &executablePath, std::string &reason);

    /**
     * Materializes an injectable copy of a System Integrity Protection binary, and returns its path.
     *
     * SIP is the one thing that makes this backend structurally weaker than the Linux one: dyld
     * refuses to load the observation library into a protected binary *and* erases
     * DYLD_INSERT_LIBRARIES from its environment, so the pip and everything it starts go unobserved.
     * That is not a corner case on macOS - /bin/bash, /bin/sh and /usr/bin/rsync are all protected,
     * and BuildXL's own SDK copies directories with rsync.
     *
     * A plain copy does not run: these are arm64e platform binaries, and the kernel kills a
     * non-platform arm64e image outright. Ad-hoc signing the copy makes it an ordinary user binary,
     * which both runs and accepts injection. The machine code is untouched; only the signature blob
     * differs, and the copy is keyed on the original's size and modification time so an OS update
     * produces a new one.
     *
     * Deliberately not applied to setuid binaries: a copy would not be setuid, so it would not be the
     * tool the pip asked for.
     */
    static bool MakeInjectable(const std::string &executablePath, std::string &shadowPath, std::string &error);

    uint64_t BackendReportedLosses() const override { return m_recordGaps.load(std::memory_order_relaxed); }

    /** The path the injected library must connect to. */
    const std::string &SocketPath() const { return m_socketPath; }

    /** Execs of binaries dyld refuses to inject into. Each one taints the pip. */
    uint64_t UnobservableChildren() const { return m_unobservableChildren.load(std::memory_order_relaxed); }

    /** Processes that announced themselves. */
    uint64_t ObservedProcesses() const { return m_observedProcesses.load(std::memory_order_relaxed); }

    /** Total records accepted off the wire. */
    uint64_t RecordsRead() const { return m_recordsRead.load(std::memory_order_relaxed); }

    /**
     * Blocks until every connected process has closed its connection.
     * Returns false on timeout, which means at least one process is still able to emit events.
     */
    bool WaitForConnectionsToDrain(std::chrono::milliseconds timeout);

private:
    void AcceptLoop();
    void ReadLoop(int descriptor);
    void OnConnectionClosed();

    /**
     * Why DefaultSocketPath gave up, so Start() can report the real reason rather than a bare bind
     * failure. Declared before m_socketPath on purpose: members are initialized in declaration order
     * and m_socketPath's initializer takes this by reference.
     */
    std::string m_socketPathError;

    std::string m_socketPath;
    bool m_ownsSocketPath = false;

    EventHandler m_handler;
    ProcessIdentity m_broker;

    int m_listener = -1;
    std::thread m_acceptThread;
    std::vector<std::thread> m_readerThreads;
    std::mutex m_readerMutex;

    std::mutex m_connectionMutex;
    std::condition_variable m_connectionIdle;
    int m_activeConnections = 0;

    /** Global ordering is assigned here: no kernel supplies one for this backend. */
    std::atomic<uint64_t> m_globalSequence{0};

    /** The broker's own marker sequence. Separate from the reader's per-pid view by design. */
    std::atomic<uint64_t> m_markerSequence{0};


    std::atomic<uint64_t> m_recordGaps{0};
    std::atomic<uint64_t> m_unobservableChildren{0};
    std::atomic<uint64_t> m_observedProcesses{0};
    std::atomic<uint64_t> m_recordsRead{0};
    std::atomic<bool> m_running{false};
};

} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_INTERPOSE_INGRESS_H
