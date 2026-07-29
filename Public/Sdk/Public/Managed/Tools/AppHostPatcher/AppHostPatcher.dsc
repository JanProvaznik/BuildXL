// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

import {Artifact, Cmd, Transformer} from "Sdk.Transformers";
import {CoreRT} from "Sdk.MacOS";
import * as Managed from "Sdk.Managed";
import * as Shared from "Sdk.Managed.Shared";
import * as Frameworks from "Sdk.Managed.Frameworks";

export declare const qualifier: Managed.TargetFrameworks.MachineQualifier.Current;

const pkgContents = importFrom("BuildXL.Tools.AppHostPatcher").Contents.all;
const currentOs = Context.getCurrentHost().os;
const isMacOS = currentOs === "macOS";
const isLinuxOS = currentOs === "unix";
const isWinOS = currentOs === "win";

// Which native artifacts to carry out of the apphost package depends on the *target* runtime, not
// on the host: cross-building for macOS from Linux still has to pick up .dylib rather than .so.
// This consulted the current host until osx-arm64 made the two differ for the first time.
function contentFilter(file: File, targetRuntime: Managed.RuntimeVersion): boolean {
    switch (targetRuntime) {
        case "win-x64":
            return file.extension === a`.dll` || file.extension === a`.lib` || file.extension === a`.h`;
        case "osx-x64":
        case "osx-arm64":
            return file.extension === a`.dylib` || file.extension === a`.a` || file.extension === a`.h`;
        case "linux-x64":
            return file.extension === a`.so` || file.extension === a`.a` || file.extension === a`.o`;
        default:
            Contract.fail("Unknown target runtime: " + targetRuntime);
    }
}

// The patcher runs on the *host*, so on an Apple Silicon Mac it has to be an arm64 binary: the
// osx-x64 build in the package cannot be executed there without Rosetta 2. Cross-building for
// macOS from Windows or Linux is unaffected, because then the host is win-x64 or linux-x64.
// The package has to carry a tools/osx-arm64 folder for this to resolve. It is produced by
// .azdo/publish-app-host-patcher, whose osx-arm64 leg has to run before the version in config.dsc
// can be moved forward; until then this path fails with a DX9377 naming the missing file.
const patcherExecutable =
    isWinOS   ? pkgContents.getFile(r`tools/win-x64/AppHostPatcher.exe`) :
    isMacOS   ? (Context.getCurrentHost().cpuArchitecture === "arm64"
                    ? pkgContents.getFile(r`tools/osx-arm64/AppHostPatcher`)
                    : pkgContents.getFile(r`tools/osx-x64/AppHostPatcher`)) :
    isLinuxOS ? pkgContents.getFile(r`tools/linux-x64/AppHostPatcher`) :
    undefined;

const patcher: Transformer.ToolDefinition = {
    exe: patcherExecutable,
    dependsOnCurrentHostOSDirectories: true,
    runtimeDirectoryDependencies: [
        pkgContents
    ]
};

@@public
export function patchBinary(args: Arguments) : Result {
    // Bug 2320602: For Windows, this only supports win-x64, but we should also support win-x86 because we create
    //              32-bit program for Detours crossbitness UTs.
    const targetsWindows = args.targetRuntimeVersion === "win-x64";
    // const targetsWindows = args.targetRuntimeVersion === "win-x64" || args.targetRuntimeVersion === "win-x86";

    const contents: StaticDirectory = 
        args.targetRuntimeVersion === "win-x64"
            ? importFrom("Microsoft.NETCore.App.Host.win-x64.8.0").Contents.all
            :
        args.targetRuntimeVersion === "linux-x64"
            ? importFrom("Microsoft.NETCore.App.Host.linux-x64.8.0").Contents.all
            :
        args.targetRuntimeVersion === "osx-x64"
            ? importFrom("Microsoft.NETCore.App.Host.osx-x64.8.0").Contents.all
            :
        args.targetRuntimeVersion === "osx-arm64"
            ? importFrom("Microsoft.NETCore.App.Host.osx-arm64.8.0").Contents.all
            : Contract.fail("Unknown target runtime: " + args.targetRuntimeVersion);

    // Pick the apphost based on the target OS, not the current OS
    const apphostBinary = targetsWindows
        ? contents.getFile(r`/runtimes/${args.targetRuntimeVersion}/native/apphost.exe`)
        : contents.getFile(r`/runtimes/${args.targetRuntimeVersion}/native/apphost`);

    const arguments : Argument[] = [
        Cmd.argument(Artifact.input(apphostBinary)),
        Cmd.argument(Artifact.input(args.binary)),
    ];

    const wd = Context.getNewOutputDirectory("AppHostPatcher");
    const outputFileName = args.binary.nameWithoutExtension + (targetsWindows ? ".exe" : "");
    const outputPath = p`${wd}/Output/${outputFileName}`;

    const result = Transformer.execute({
        tool: patcher,
        arguments: arguments,
        workingDirectory: wd,
        // The patcher ad-hoc signs its output on macOS, and codesign writes a .cstemp sibling of the
        // file it is signing, so the signing has to happen somewhere scratch. Without a declared temp
        // directory a pip's TMPDIR points at RestrictedTemp, where BuildXL denies every access by
        // design.
        tempDirectory: Context.getTempDirectory("AppHostPatcher"),
        outputs: [
            outputPath,
        ],
        environmentVariables: [
            { name: "COMPlus_EnableDiagnostics", value: "0" }, // Disables debug pipe creation
        ]
    });

    return {
        contents: [
            ...contents.getContent().filter(f => contentFilter(f, args.targetRuntimeVersion)),
        ],
        patchOutputFile: result.getOutputFile(outputPath)
    };
}

@@public
export interface Arguments {
    binary: File,
    targetRuntimeVersion: Managed.RuntimeVersion,
}

/**
 * Binary files that AppHostPatcher patched. These files are part of Assembly.runtimeContent
 * @patchOutputFile: This file is the executable file. Also part of 'contents' as a way to identify the patched output file.
 */
@@public
export interface Result {
    contents: File[],
    patchOutputFile: File,
}

