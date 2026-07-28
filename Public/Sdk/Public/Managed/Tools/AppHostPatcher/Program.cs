// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Linq;
using System.Globalization;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace AppHostPatcher
{
    /// <summary>
    /// Embeds the a specified app name into the target OS AppHost binary
    /// </summary>
    public class AppHostPatcher
    {
        /// <nodoc />
        public string AppHostSourcePath { get; set; }

        /// <nodoc />
        public string AppHostDestinationDirectoryPath { get; set; }

        /// <nodoc />
        public string AppBinaryName { get; set; }

        // See: https://github.com/dotnet/sdk/blob/4e90cac1d4b8743e39ed6945677020f9d4cbfd81/src/Tasks/Microsoft.NET.Build.Tasks/AppHost.cs#L20
        // Basically the un-patched apphost from the official Nuget package contains this string as a placeholder
        private static readonly string s_placeHolder = "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2";
        private static readonly byte[] s_bytesToSearch = Encoding.UTF8.GetBytes(s_placeHolder);

        // See: https://en.wikipedia.org/wiki/Knuth%E2%80%93Morris%E2%80%93Pratt_algorithm
        private static int[] ComputeKMPFailureFunction(byte[] pattern)
        {
            int[] table = new int[pattern.Length];
            if (pattern.Length >= 1)
            {
                table[0] = -1;
            }
            if (pattern.Length >= 2)
            {
                table[1] = 0;
            }

            int pos = 2;
            int cnd = 0;
            while (pos < pattern.Length)
            {
                if (pattern[pos - 1] == pattern[cnd])
                {
                    table[pos] = cnd + 1;
                    cnd++;
                    pos++;
                }
                else if (cnd > 0)
                {
                    cnd = table[cnd];
                }
                else
                {
                    table[pos] = 0;
                    pos++;
                }
            }

            return table;
        }

        // See: https://en.wikipedia.org/wiki/Knuth%E2%80%93Morris%E2%80%93Pratt_algorithm
        private static int KMPSearch(byte[] pattern, byte[] bytes)
        {
            int m = 0;
            int i = 0;
            int[] table = ComputeKMPFailureFunction(pattern);

            while (m + i < bytes.Length)
            {
                if (pattern[i] == bytes[m + i])
                {
                    if (i == pattern.Length - 1)
                    {
                        return m;
                    }
                    i++;
                }
                else
                {
                    if (table[i] > -1)
                    {
                        m = m + i - table[i];
                        i = table[i];
                    }
                    else
                    {
                        m++;
                        i = 0;
                    }
                }
            }

            return -1;
        }

        private static void SearchAndReplace(byte[] array, byte[] searchPattern, byte[] patternToReplace)
        {
            int offset = KMPSearch(searchPattern, array);
            if (offset < 0)
            {
                throw new Exception();
            }

            patternToReplace.CopyTo(array, offset);

            if (patternToReplace.Length < searchPattern.Length)
            {
                for (int i = patternToReplace.Length; i < searchPattern.Length; i++)
                {
                    array[i + offset] = 0x0;
                }
            }
        }

        /// <nodoc />
        protected int ExecuteCore(string unpatchedAppHostPath, string hostedFilePath)
        {
            var hostExtension = Path.GetExtension(unpatchedAppHostPath);
            var appBaseName = Path.GetFileNameWithoutExtension(hostedFilePath);

            var bytesToWrite = Encoding.UTF8.GetBytes(Path.GetFileName(hostedFilePath));

            var destinationDirectory = Path.GetFullPath("Output");
            var patchedAppHostPath = Path.Combine(destinationDirectory, $"{appBaseName}{hostExtension}");

            if (bytesToWrite.Length > 1024)
            {
                throw new Exception("Destination file name not supported!");
            }

            var array = File.ReadAllBytes(unpatchedAppHostPath);
            SearchAndReplace(array, s_bytesToSearch, bytesToWrite);

            if (!Directory.Exists(destinationDirectory))
            {
                Directory.CreateDirectory(destinationDirectory);
            }

            // Copy unpatchedHostFilePath to patchedAppHostPath so it inherits the same attributes and permissions.
            File.Copy(unpatchedAppHostPath, patchedAppHostPath);

            // Re-write patchedAppHostPath with the proper contents.
            using (FileStream fs = new FileStream(patchedAppHostPath, FileMode.Truncate, FileAccess.ReadWrite, FileShare.Read))
            {
                fs.Write(array, 0, array.Length);
            }

            return AdHocSignIfMachO(patchedAppHostPath, array);
        }

        private static bool IsMachO(byte[] image)
        {
            if (image.Length < 4)
            {
                return false;
            }

            uint magic = (uint)(image[0] | (image[1] << 8) | (image[2] << 16) | (image[3] << 24));

            // MH_MAGIC / MH_CIGAM / MH_MAGIC_64 / MH_CIGAM_64, and the two fat variants.
            return magic == 0xFEEDFACE || magic == 0xCEFAEDFE
                || magic == 0xFEEDFACF || magic == 0xCFFAEDFE
                || magic == 0xCAFEBABE || magic == 0xBEBAFECA
                || magic == 0xCAFEBABF || magic == 0xBFBAFECA;
        }

        /// <summary>
        /// Restores the ad-hoc code signature that patching the apphost in place invalidates.
        /// </summary>
        /// <remarks>
        /// The apphost arrives from Microsoft.NETCore.App.Host.&lt;rid&gt; already ad-hoc signed. Overwriting the
        /// placeholder leaves the signature blob in place but no longer matching the contents. On x86_64 macOS
        /// the kernel tolerates that, which is why it went unnoticed for as long as osx-x64 was the only macOS
        /// target. On arm64 it refuses to map the image and SIGKILLs the process at exec: exit code 137, nothing
        /// on stdout or stderr. Executables that the build produces and then runs as tools -- ResXPreProcessor,
        /// the C# compiler wrappers, every BuildXL tool -- die that way, so signing has to happen here rather
        /// than only on the machine that consumes a finished deployment.
        ///
        /// Only done when running on macOS, because codesign exists nowhere else. A macOS deployment produced by
        /// a Windows or Linux host is signed by bxl.sh on the Mac that runs it.
        ///
        /// The signature is applied in a temporary directory because codesign writes a .cstemp sibling of its
        /// target before renaming it into place, and the directory the patched binary lives in is a declared
        /// build output whose contents are checked.
        /// </remarks>
        private static int AdHocSignIfMachO(string patchedAppHostPath, byte[] image)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || !IsMachO(image))
            {
                return 0;
            }

            string scratchDirectory = Path.Combine(Path.GetTempPath(), "AppHostPatcher-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(scratchDirectory);

            try
            {
                string scratchPath = Path.Combine(scratchDirectory, Path.GetFileName(patchedAppHostPath));
                File.Copy(patchedAppHostPath, scratchPath);

                var startInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "/usr/bin/codesign",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                };

                startInfo.ArgumentList.Add("--force");
                startInfo.ArgumentList.Add("--sign");
                startInfo.ArgumentList.Add("-");
                startInfo.ArgumentList.Add(scratchPath);

                using (var process = System.Diagnostics.Process.Start(startInfo))
                {
                    string standardError = process.StandardError.ReadToEnd();
                    string standardOutput = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (process.ExitCode != 0)
                    {
                        Console.Error.WriteLine(
                            $"Failed to ad-hoc sign '{patchedAppHostPath}'. codesign exited with {process.ExitCode}." + Environment.NewLine +
                            standardOutput + Environment.NewLine + standardError);
                        return process.ExitCode;
                    }
                }

                File.Delete(patchedAppHostPath);
                File.Move(scratchPath, patchedAppHostPath);
                return 0;
            }
            finally
            {
                try
                {
                    Directory.Delete(scratchDirectory, recursive: true);
                }
                catch (IOException)
                {
                    // A leftover scratch directory under TEMP is not worth failing a build over.
                }
            }
        }

        /// <nodoc />
        public static int Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Usage: AppHostPatcher absolute_path_to_unpatched_apphost absolute_path_to_hosted_binary");
                return 1;
            }

            var patcher = new AppHostPatcher();
            return patcher.ExecuteCore(args[0], args[1]);
        }
    }
}
