// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics.ContractsLight;
using System.Text;

namespace BuildXL.Processes
{
    /// <summary>
    /// Parses the textual access reports that the Linux and macOS sandboxes write to their report FIFO.
    /// </summary>
    /// <remarks>
    /// Both sandboxes serialize reports with the same native code
    /// (CODESYNC: Public/Src/Sandbox/Linux/ReportBuilder.cpp), so they must be deserialized by the same
    /// managed code. Keeping this in one place is what makes the two platforms report-format identical
    /// by construction rather than by convention.
    /// </remarks>
    internal static class SandboxReportParser
    {
        private static readonly Encoding s_encoding = Encoding.UTF8;

        /// <summary>
        /// Decodes the bytes of a single report message.
        /// </summary>
        public static string Decode(byte[] buffer, int length) => s_encoding.GetString(buffer, index: 0, count: length);

        /// <summary>
        /// Parses a single report message (without its length prefix and with the trailing newline optional).
        /// </summary>
        /// <param name="message">The message to parse.</param>
        /// <param name="logError">Invoked with a description of the problem when a field cannot be parsed.</param>
        /// <returns>The parsed report. Fields that could not be parsed are left at their default value.</returns>
        public static SandboxReportLinux Parse(ReadOnlySpan<char> message, Action<string> logError)
        {
            Contract.RequiresNotNull(logError);

            message = message.TrimEnd('\n');

            // Report format should be in sync with native code on the Linux/macOS sandbox.
            // CODESYNC: Public/Src/Sandbox/Linux/ReportBuilder.cpp

            // 1. Report Type.
            var restOfMessage = message;
            var reportType = (ReportType)assertInt("Report Type", nextField(restOfMessage, out restOfMessage));
            var report = new SandboxReportLinux()
            {
                ReportType = reportType
            };

            switch (reportType)
            {
                case ReportType.FileAccess:
                {
                    /*
                     * File Access Report Format: %d|%s|%d|%d|%d|%d|%d|%d|%d|%d|%s\n
                     * 
                     * 1. Report Type
                     * 2. System call name
                     * 3. File Operation
                     * 4. Process ID
                     * 5. Parent Process ID
                     * 6. Error
                     * 7. Requested Access
                     * 8. File Access Status
                     * 9. Report Explicitly
                     * 10. Is Directory
                     * 11. Is path truncated
                     * 12. Path
                    */
                    report.SystemCall = s_encoding.GetString(s_encoding.GetBytes(nextField(restOfMessage, out restOfMessage).ToArray()));
                    report.FileOperation = FileOperationLinux.ToReportedFileOperation((FileOperationLinux.Operations)assertInt("File Operation", nextField(restOfMessage, out restOfMessage)));
                    report.ProcessId = assertInt("Process ID", nextField(restOfMessage, out restOfMessage));
                    report.ParentProcessId = assertInt("Parent Process ID", nextField(restOfMessage, out restOfMessage));
                    report.Error = assertInt("Error", nextField(restOfMessage, out restOfMessage));
                    report.RequestedAccess = (RequestedAccess)assertInt("Requested Access", nextField(restOfMessage, out restOfMessage));
                    report.FileAccessStatus = assertInt("File Access Status", nextField(restOfMessage, out restOfMessage));
                    report.ExplicitlyReport = assertInt("Explicitly Report", nextField(restOfMessage, out restOfMessage));
                    report.IsDirectory = assertInt("Is Directory", nextField(restOfMessage, out restOfMessage)) != 0;
                    report.IsPathTruncated = assertInt("Is Path Truncated", nextField(restOfMessage, out restOfMessage)) != 0;
                    report.Data = s_encoding.GetString(s_encoding.GetBytes(nextField(restOfMessage, out restOfMessage).ToArray()));

                    if (report.FileOperation == ReportedFileOperation.ProcessExec)
                    {
                        // Process exec may contain a command line as well
                        report.CommandLineArguments = s_encoding.GetString(s_encoding.GetBytes(nextField(restOfMessage, out restOfMessage).ToArray()));
                    }

                    break;
                }
                case ReportType.DebugMessage:
                {
                    /*
                     * Debug report format: %d|%d|%d|%s\n
                     * 
                     * 1. Report Type
                     * 2. Process ID
                     * 3. Severity
                     * 4. Message
                    */
                    report.ProcessId = assertInt("Process ID", nextField(restOfMessage, out restOfMessage));
                    report.Severity = (SandboxInfraSeverity)assertInt("Severity", nextField(restOfMessage, out restOfMessage));
                    report.Data = s_encoding.GetString(s_encoding.GetBytes(nextField(restOfMessage, out restOfMessage).ToArray())).Replace('!', '|');

                    break;
                }
                default:
                    break;
            }

            Contract.Assert(restOfMessage.IsEmpty, $"Rest of message: {restOfMessage.ToString()}");  // We should have reached the end of the message

            return report;

            // Reads next field of the serialized message, i.e. split on the first | and return both parts
            static ReadOnlySpan<char> nextField(ReadOnlySpan<char> message, out ReadOnlySpan<char> rest)
            {
                for (int i = 0; i < message.Length; i++)
                {
                    if (message[i] == '|')
                    {
                        rest = i + 1 == message.Length ? ReadOnlySpan<char>.Empty : message.Slice(i + 1); // Defend against | being the last character, although we don't expect this
                        return message.Slice(0, i);
                    }
                }

                rest = ReadOnlySpan<char>.Empty;
                return message;
            }

            uint assertInt(string fieldName, ReadOnlySpan<char> str)
            {
#if NETCOREAPP
                if (uint.TryParse(str, out uint result))
#else // .NET 472 - no ReadOnlySpan<char> overloads. We don't really care about perf for .NET472 here
                if (uint.TryParse(str.ToString(), out uint result))
#endif
                {
                    return result;
                }
                else
                {
                    logError($"Could not parse int from '{str.ToString()}' for field '{fieldName}'");
                    return 0;
                }
            }
        }
    }
}
