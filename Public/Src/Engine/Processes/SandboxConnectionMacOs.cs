// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.ContractsLight;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using BuildXL.Interop.Unix;
using BuildXL.Native.IO;
using BuildXL.Utilities.Core;
using BuildXL.Utilities.Instrumentation.Common;
using Microsoft.Win32.SafeHandles;
using static BuildXL.Interop.Unix.Sandbox;

namespace BuildXL.Processes
{
    /// <summary>
    /// Connects BuildXL to the macOS sandbox, which observes file accesses with an Endpoint Security
    /// descendants client.
    /// </summary>
    /// <remarks>
    /// The shape mirrors <see cref="SandboxConnectionLinuxEBPF"/>: one FIFO and one serialized file
    /// access manifest per pip, and the pip's root process is wrapped in a broker that observes the
    /// whole process tree. The reports are byte-for-byte the Linux ones, because the broker links
    /// BuildXL's existing policy engine and report writer
    /// (CODESYNC: Public/Src/Sandbox/Linux/ReportBuilder.cpp), which is why
    /// <see cref="SandboxReportParser"/> is shared rather than reimplemented.
    ///
    /// It is deliberately much simpler than the eBPF connection in one respect: process lifetime is
    /// tracked in the broker, which knows the pip's process tree from Endpoint Security and owns the
    /// decision about when the tree has quiesced. The broker therefore writes both sentinels itself,
    /// so this side needs neither an active-process set, nor a keep-alive write handle, nor the
    /// sentinel round trip that exists on Linux to synchronize those two things. Duplicating that
    /// machinery here would mean two components disagreeing about when a pip is done.
    /// </remarks>
    public sealed class SandboxConnectionMacOs : ISandboxConnection
    {
        /// <summary>
        /// Sentinel written by the broker once the observed process tree has quiesced.
        /// </summary>
        /// <remarks>
        /// CODESYNC: Public/Src/Sandbox/MacOs/Sandbox/ReportSink.h
        /// </remarks>
        private const int NoActiveProcessesSentinel = -21;

        /// <summary>
        /// Sentinel written by the broker after the last report. Reading it is the only way this loop ends.
        /// </summary>
        /// <remarks>
        /// CODESYNC: Public/Src/Sandbox/MacOs/Sandbox/ReportSink.h
        /// </remarks>
        private const int EndOfReportsSentinel = -22;

        /// <summary>
        /// Path to the serialized file access manifest for the pip being launched.
        /// </summary>
        /// <remarks>
        /// CODESYNC: Public/Src/Sandbox/MacOs/Sandbox/bxl-es-broker.cpp
        /// </remarks>
        public const string BuildXLFamPathEnvVarName = "__BUILDXL_FAM_PATH";

        /// <summary>
        /// How long the broker waits for the observed process tree to quiesce after the root process exits.
        /// </summary>
        /// <remarks>
        /// CODESYNC: Public/Src/Sandbox/MacOs/Sandbox/bxl-es-broker.cpp
        /// </remarks>
        public const string BuildXLSupervisionTimeoutEnvVarName = "__BUILDXL_MACOS_SUPERVISION_TIMEOUT_SECONDS";

        /// <summary>
        /// Where the broker appends one JSON record per pip describing what the sandbox observed.
        /// </summary>
        /// <remarks>
        /// Diagnostic, and off unless the same variable is set in the environment BuildXL itself was
        /// started with. It is forwarded rather than read directly by the broker because BuildXL does
        /// not pass its own environment through to pips - a pip's environment is part of its cache key,
        /// so it is constructed rather than inherited. Without forwarding, setting this on a build has
        /// no effect and the file is silently never written.
        ///
        /// The value is a path the broker opens in append mode, one process per pip, so concurrent
        /// pips share it safely. Records carry a per-run id and the pip id.
        ///
        /// This is how event volume and kernel drop rate get measured on a real build, which is the
        /// question the macOS sandbox has to answer. See Documentation/Wiki/MacOsSandbox.md.
        ///
        /// CODESYNC: Public/Src/Sandbox/MacOs/Sandbox/bxl-es-broker.cpp
        /// </remarks>
        public const string BuildXLEvidencePathEnvVarName = "__BUILDXL_MACOS_EVIDENCE_PATH";

        /// <summary>
        /// Colon-separated paths that macOS resolves on a pip's behalf rather than paths a pip touched.
        /// </summary>
        /// <remarks>
        /// macOS resolves an ancestor shell script's path during the exec transition of every descendant,
        /// and Endpoint Security attributes that resolution to the process being exec'd. Since BuildXL is
        /// normally launched from bxl.sh, every pip would otherwise report an undeclared probe of it.
        /// The launcher tells us its own path; we pass it to each broker so it can drop those resolutions.
        /// Only pure path resolutions are dropped - a pip that genuinely opens the file is still reported.
        /// </remarks>
        public const string BuildXLLauncherPathsEnvVarName = "__BUILDXL_MACOS_LAUNCHER_PATHS";

        /// <summary>
        /// The broker that wraps every sandboxed root process.
        /// </summary>
        /// <remarks>
        /// Prefers the bundled form when the deployment carries one. Apple authorizes a restricted
        /// entitlement through a provisioning profile, and a profile has to live inside a bundle, so a
        /// broker that is honoured on a machine with SIP and AMFI enabled is necessarily bundled. A
        /// development build has no profile and ships the bare executable, which is what an
        /// AMFI-relaxed machine accepts. Preferring the bundle rather than choosing by configuration
        /// means the same BuildXL works with either deployment.
        /// </remarks>
        public static readonly string Broker = ResolveBroker();

        private static string ResolveBroker()
        {
            const string BundledBroker = "bxl-es-broker.app/Contents/MacOS/bxl-es-broker";

            string bundled = SandboxedProcessUnix.GetDeploymentFileFullPath(BundledBroker);
            return File.Exists(bundled)
                ? SandboxedProcessUnix.EnsureDeploymentFile(BundledBroker, setExecuteBit: true)
                : SandboxedProcessUnix.EnsureDeploymentFile("bxl-es-broker", setExecuteBit: true);
        }

        private readonly ConcurrentDictionary<long, Info> m_pipProcesses = new();
        private readonly ManagedFailureCallback m_failureCallback;

        /// <inheritdoc />
        public SandboxKind Kind => SandboxKind.MacOs;

        /// <inheritdoc />
        public bool IsInTestMode { get; }

        /// <nodoc />
        public SandboxConnectionMacOs(ManagedFailureCallback failureCallback = null, bool isInTestMode = false)
        {
            m_failureCallback = failureCallback;
            IsInTestMode = isInTestMode;
        }

        /// <summary>
        /// Reads the report FIFO for one pip on a dedicated thread.
        /// </summary>
        private sealed class Info : IDisposable
        {
            private readonly Thread m_workerThread;
            private readonly ManagedFailureCallback m_failureCallback;

            internal SandboxedProcessUnix Process { get; }

            internal string ReportsFifoPath { get; }

            internal string FamPath { get; }

            /// <remarks>
            /// Only used to answer <see cref="ISandboxConnection.NotifyRootProcessExited"/>. The broker,
            /// not this set, decides when the pip is finished.
            /// </remarks>
            private readonly ConcurrentDictionary<int, byte> m_activeProcesses = new();

            internal Info(ManagedFailureCallback failureCallback, SandboxedProcessUnix process, string reportsFifoPath, string famPath)
            {
                m_failureCallback = failureCallback;
                Process = process;
                ReportsFifoPath = reportsFifoPath;
                FamPath = famPath;

                m_workerThread = new Thread(StartReceivingAccessReports)
                {
                    IsBackground = true,
                    Priority = ThreadPriority.Highest
                };
            }

            internal void Start() => m_workerThread.Start();

            internal bool AreOrphansActive => !m_activeProcesses.IsEmpty;

            internal void RemovePid(int pid) => m_activeProcesses.TryRemove(pid, out _);

            private static int Read(SafeFileHandle handle, byte[] buffer, int offset, int length)
            {
                Contract.Requires(buffer.Length >= offset + length);
                int totalRead = 0;
                while (totalRead < length)
                {
                    var numRead = IO.Read(handle, buffer, offset + totalRead, length - totalRead);
                    if (numRead <= 0)
                    {
                        return numRead;
                    }

                    totalRead += numRead;
                }

                return totalRead;
            }

            /// <remarks>
            /// The loop ends on <see cref="EndOfReportsSentinel"/> and on nothing else. Reaching EOF first
            /// means the broker died without finishing its report stream, which is a lost-observation
            /// condition and must be surfaced rather than treated as a clean end: silently accepting a
            /// truncated stream is exactly how an unsound cache entry gets written.
            /// </remarks>
            private void StartReceivingAccessReports()
            {
                LogDebug($"Opening FIFO '{ReportsFifoPath}' for reading");

                // Blocks until the broker opens the write end.
                var readHandle = IO.Open(ReportsFifoPath, IO.OpenFlags.O_RDONLY, 0);
                try
                {
                    if (readHandle.IsInvalid)
                    {
                        LogError($"Opening FIFO {ReportsFifoPath} for reading failed.");
                        return;
                    }

                    byte[] messageLengthBytes = new byte[sizeof(int)];
                    while (true)
                    {
                        var numRead = Read(readHandle, messageLengthBytes, 0, messageLengthBytes.Length);
                        if (numRead == 0)
                        {
                            LogError("Exiting 'receive reports' loop on EOF without observing the end of reports sentinel value. The macOS sandbox broker did not finish writing its report stream, so the observed accesses for this pip are incomplete.");
                            break;
                        }

                        if (numRead < 0)
                        {
                            LogError($"Read from FIFO {ReportsFifoPath} failed with return value {numRead}.");
                            break;
                        }

                        int messageLength = BitConverter.ToInt32(messageLengthBytes, startIndex: 0);

                        if (messageLength == NoActiveProcessesSentinel)
                        {
                            // The broker owns process-tree liveness, so unlike on Linux there is nothing to
                            // cross-check here; the sentinel is kept in the protocol only so the two
                            // platforms produce the same stream.
                            LogDebug($"NoActiveProcessesSentinel received for fifo {ReportsFifoPath}.");
                            continue;
                        }

                        if (messageLength == EndOfReportsSentinel)
                        {
                            LogDebug($"End of reports sentinel arrived on FIFO {ReportsFifoPath}. Exiting 'receive reports' loop.");
                            break;
                        }

                        if (messageLength <= 0)
                        {
                            LogError($"Unexpected message length {messageLength} on FIFO {ReportsFifoPath}.");
                            break;
                        }

                        byte[] messageBytes = new byte[messageLength];
                        numRead = Read(readHandle, messageBytes, 0, messageLength);
                        if (numRead < messageLength)
                        {
                            LogError($"Read from FIFO {ReportsFifoPath} failed: read only {numRead} out of {messageLength} bytes.");
                            break;
                        }

                        try
                        {
                            ProcessBytes(messageBytes, messageLength);
                        }
                        catch (Exception e)
                        {
                            LogError($"Could not post message to the processing block for {ReportsFifoPath}. Exception details: {e}");
                            break;
                        }
                    }

                    LogDebug($"Completed receiving access reports for fifo '{ReportsFifoPath}'");
                }
                finally
                {
                    LogDebug($"Disposing read handle for fifo '{ReportsFifoPath}'");
                    readHandle.Dispose();
                }

                LogDebug("Posting OpProcessTreeCompleted message");
                Process.PostAccessReport(new SandboxReportLinux
                {
                    ReportType = ReportType.FileAccess,
                    FileOperation = ReportedFileOperation.ProcessTreeCompletedAck,
                });
            }

            private void ProcessBytes(byte[] buffer, int length)
            {
                var report = SandboxReportParser.Parse(SandboxReportParser.Decode(buffer, length).AsSpan(), LogError);

                if (report.FileOperation == ReportedFileOperation.Process)
                {
                    m_activeProcesses[(int)report.ProcessId] = 0;
                }
                else if (report.FileOperation == ReportedFileOperation.ProcessExit
                    || report.FileOperation == ReportedFileOperation.ProcessBreakaway)
                {
                    RemovePid((int)report.ProcessId);
                }

                Process.PostAccessReport(report);
            }

            internal void LogError(string message)
            {
                message = $"{message} (errno: {Marshal.GetLastWin32Error()})";
                Process.LogDebug("[ERROR]: " + message);
                m_failureCallback?.Invoke(1, message);
            }

            internal void LogDebug(string message) => Process.LogDebug(message);

            public void Dispose()
            {
                // Unblock the reader before removing the FIFO. A thread sitting in open(O_RDONLY) on
                // a FIFO waits for a writer and nothing else - deleting the path does not release it,
                // and neither does closing a handle it has not obtained yet. Opening the write end
                // for an instant is what wakes it: it then sees an immediate end of stream and the
                // loop exits.
                //
                // Without this, any pip whose process never starts hangs the whole build rather than
                // failing: the scheduler finishes, calls Thread.Join on this reader, and waits
                // forever. That is a launch failure turning into a silent hang, which is far worse
                // than the failure it is hiding.
                //
                // O_NONBLOCK matters on this side too, so that a reader which has already gone does
                // not leave this open() waiting in its place.
                try
                {
                    var wakeHandle = IO.Open(ReportsFifoPath, IO.OpenFlags.O_WRONLY | IO.OpenFlags.O_NONBLOCK, 0);
                    if (!wakeHandle.IsInvalid)
                    {
                        wakeHandle.Dispose();
                    }
                }
                catch (Exception)
                {
                    // The FIFO may already be gone, which is the case where there is nothing to wake.
                }

                Analysis.IgnoreResult(FileUtilities.TryDeleteFile(ReportsFifoPath, retryOnFailure: false));
                Analysis.IgnoreResult(FileUtilities.TryDeleteFile(FamPath, retryOnFailure: false));
            }
        }

        /// <summary>
        /// Returns the paths for the FIFO and FAM based on the unique name for a pip.
        /// </summary>
        public static (string fifo, string fam) GetPaths(string uniqueName)
        {
            string rootDir = Path.GetTempPath();
            string fifoPath = Path.Combine(rootDir, $"bxl_{uniqueName}.fifo");
            // CODESYNC: Public/Src/Sandbox/MacOs/Sandbox/bxl-es-broker.cpp
            string famPath = Path.ChangeExtension(fifoPath, ".fam");
            return (fifo: fifoPath, fam: famPath);
        }

        /// <inheritdoc />
        public IEnumerable<(string, string)> AdditionalEnvVarsToSet(SandboxedProcessInfo info, string uniqueName)
        {
            (_, string famPath) = GetPaths(uniqueName);
            yield return (BuildXLFamPathEnvVarName, famPath);

            if (info.Timeout != null)
            {
                // The broker gives the tree the pip's own timeout to quiesce after the root exits, so a
                // hung orphan is reported as a supervision timeout rather than hanging the build.
                yield return (BuildXLSupervisionTimeoutEnvVarName, ((int)Math.Ceiling(info.Timeout.Value.TotalSeconds)).ToString());
            }

            string launcherPaths = Environment.GetEnvironmentVariable(BuildXLLauncherPathsEnvVarName);
            if (!string.IsNullOrEmpty(launcherPaths))
            {
                yield return (BuildXLLauncherPathsEnvVarName, launcherPaths);
            }

            string evidencePath = Environment.GetEnvironmentVariable(BuildXLEvidencePathEnvVarName);
            if (!string.IsNullOrEmpty(evidencePath))
            {
                // Forwarded only when explicitly set on the build. This does change the pip's
                // environment and therefore its fingerprint, which is the correct trade: a diagnostic
                // that silently altered cache keys would be worse than one that visibly does.
                yield return (BuildXLEvidencePathEnvVarName, evidencePath);
            }
        }

        /// <inheritdoc />
        public bool NotifyPipStarted(LoggingContext loggingContext, FileAccessManifest fam, SandboxedProcessUnix process) => true;

        /// <inheritdoc />
        public void NotifyPipReady(LoggingContext loggingContext, FileAccessManifest fam, SandboxedProcessUnix process, Task reportCompletion)
        {
            Contract.Requires(!process.Started);
            Contract.Requires(process.PipId != 0);

            (string fifoPath, string famPath) = GetPaths(process.UniqueName);

            if (IsInTestMode)
            {
                fam.EnableLinuxSandboxLogging = true;
            }

            using (var wrapper = Pools.MemoryStreamPool.GetInstance())
            {
                var debugFlags = true;
                ArraySegment<byte> manifestBytes = fam.GetPayloadBytes(
                    loggingContext,
                    new FileAccessSetup { DllNameX64 = string.Empty, DllNameX86 = string.Empty, ReportPath = fifoPath },
                    wrapper.Instance,
                    timeoutMins: 10, // don't care
                    debugFlagsMatch: ref debugFlags);

                Contract.Assert(manifestBytes.Offset == 0);
                File.WriteAllBytes(famPath, manifestBytes.ToArray());
            }

            process.LogDebug($"Saved FAM to '{famPath}'");

            Analysis.IgnoreResult(FileUtilities.TryDeleteFile(fifoPath, retryOnFailure: false));
            if (IO.MkFifo(fifoPath, IO.FilePermissions.S_IRWXU) != 0)
            {
                throw new BuildXLException($"Creating FIFO {fifoPath} failed. (errno: {Marshal.GetLastWin32Error()})");
            }

            process.LogDebug($"Created FIFO at '{fifoPath}'");

            var info = new Info(m_failureCallback, process, fifoPath, famPath);
            if (!m_pipProcesses.TryAdd(process.PipId, info))
            {
                throw new BuildXLException($"Process with PipId {process.PipId} already exists");
            }

            info.Start();
        }

        /// <inheritdoc />
        public void NotifyPipProcessTerminated(long pipId, int processId)
        {
            if (m_pipProcesses.TryGetValue(pipId, out var info))
            {
                info.Process.LogDebug($"NotifyPipProcessTerminated. Removing pid {processId}");
                info.RemovePid(processId);
            }
        }

        /// <inheritdoc />
        public bool NotifyRootProcessExited(long pipId, SandboxedProcessUnix process)
        {
            if (m_pipProcesses.TryGetValue(pipId, out var info))
            {
                info.Process.LogDebug($"NotifyRootProcessExited. Removing pid {process.ProcessId}");
                info.RemovePid(process.ProcessId);
                return info.AreOrphansActive;
            }

            return false;
        }

        /// <inheritdoc />
        public bool NotifyPipFinished(long pipId, SandboxedProcessUnix process)
        {
            var success = m_pipProcesses.TryRemove(pipId, out var info);
            Contract.Assert(success, $"Pip with id {pipId} was not found in the sandbox connection");
            info.Dispose();

            return true;
        }

        /// <inheritdoc />
        public bool NotifyUsage(uint cpuUsageBasisPoints, uint availableRamMB) => true;

        /// <summary>
        /// Wraps the pip's root process in the broker, so that Endpoint Security is subscribed before
        /// the process exists and there is no interval in which it could touch a file unobserved.
        /// </summary>
        public void OverrideProcessStartInfo(ProcessStartInfo processStartInfo)
        {
            processStartInfo.Arguments = $"{processStartInfo.FileName} {processStartInfo.Arguments}";
            processStartInfo.FileName = Broker;
        }

        /// <inheritdoc />
        public void Dispose()
        {
        }
    }
}
