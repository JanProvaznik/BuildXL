// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

import {Artifact, Cmd, Transformer} from "Sdk.Transformers";
import * as Shared from "Sdk.Managed.Shared";
import * as Deployment from "Sdk.Deployment";
import * as MacOS from "Sdk.MacOS";
import {Helpers} from "Sdk.Managed.Frameworks";

export declare const qualifier: {targetFramework: "net9.0"};

const defaultAssemblies: Shared.Assembly[] = createDefaultAssemblies();

const windowsRuntimeFiles = [
    ...importFrom("Microsoft.NETCore.App.Runtime.win-x64.9.0").Contents.all.getContent().filter(f => f.extension === a`.dll`),
    ...importFrom("runtime.win-x64.Microsoft.NETCore.DotNetHostResolver.8.0").Contents.all.getContent().filter(f => f.extension === a`.dll`),
    ...importFrom("runtime.win-x64.Microsoft.NETCore.DotNetHostPolicy.8.0").Contents.all.getContent().filter(f => f.extension === a`.dll`),
];

const osxRuntimeFiles = [
    ...importFrom("Microsoft.NETCore.App.Runtime.osx-x64.9.0").Contents.all.getContent().filter(f => Helpers.macOSRuntimeExtensions(f)),
    ...importFrom("runtime.osx-x64.Microsoft.NETCore.DotNetHostResolver.8.0").Contents.all.getContent().filter(f => Helpers.macOSRuntimeExtensions(f)),
    ...importFrom("runtime.osx-x64.Microsoft.NETCore.DotNetHostPolicy.8.0").Contents.all.getContent().filter(f => Helpers.macOSRuntimeExtensions(f)),
];

const osxArm64RuntimeFiles = [
    ...importFrom("Microsoft.NETCore.App.Runtime.osx-arm64.9.0").Contents.all.getContent().filter(f => Helpers.macOSRuntimeExtensions(f)),
    ...importFrom("runtime.osx-arm64.Microsoft.NETCore.DotNetHostResolver.8.0").Contents.all.getContent().filter(f => Helpers.macOSRuntimeExtensions(f)),
    ...importFrom("runtime.osx-arm64.Microsoft.NETCore.DotNetHostPolicy.8.0").Contents.all.getContent().filter(f => Helpers.macOSRuntimeExtensions(f)),
];

const linuxRuntimeFiles = [
    ...importFrom("Microsoft.NETCore.App.Runtime.linux-x64.9.0").Contents.all.getContent().filter(f => Helpers.linuxRuntimeExtensions(f)),
    ...importFrom("runtime.linux-x64.Microsoft.NETCore.DotNetHostResolver.8.0").Contents.all.getContent().filter(f => Helpers.linuxRuntimeExtensions(f)),
    ...importFrom("runtime.linux-x64.Microsoft.NETCore.DotNetHostPolicy.8.0").Contents.all.getContent().filter(f => Helpers.linuxRuntimeExtensions(f)),
];


@@public
export function runtimeContentProvider(runtimeVersion: Shared.RuntimeVersion): File[] {
    switch (runtimeVersion)
    {
        case "osx-x64":
            return osxRuntimeFiles;
        case "osx-arm64":
            return osxArm64RuntimeFiles;
        case "win-x64":
            return windowsRuntimeFiles;
        case "linux-x64":
            return linuxRuntimeFiles;
        default:
            Contract.fail(`Unsupported runtime encountered: ${runtimeVersion}`);
    }
}

export function crossgenProvider(runtimeVersion: Shared.RuntimeVersion): Shared.CrossgenFiles {
    // The arms below are already dead. No 'tools/crossgen' entry exists in
    // Microsoft.NETCore.App.Runtime.{win-x64,osx-x64} at the pinned versions -- the only entry under
    // 'tools/' is StandardOptimizationData.mibc -- so reaching either one raises
    // FileNotFoundInStaticDirectory. That predates this change and is only reachable with
    // [Sdk.BuildXL]enableCrossgen=1, which nothing in the repo or in .azdo sets.
    switch (runtimeVersion)
    {
        case "osx-x64":
            const osxFiles = importFrom("Microsoft.NETCore.App.Runtime.osx-x64.9.0").Contents.all;
            return { 
                crossgenExe: osxFiles.getFile(r`tools/crossgen`),
                JITPath: osxFiles.getFile(r`runtimes/osx-x64/native/libclrjit.dylib`)
            };
        case "win-x64":
            const winFiles = importFrom("Microsoft.NETCore.App.Runtime.win-x64.9.0").Contents.all;
            return {
                crossgenExe: winFiles.getFile(r`tools/crossgen.exe`),
                JITPath: winFiles.getFile(r`runtimes/win-x64/native/clrjit.dll`)
            };
        default:
            // Crossgen is deliberately not extended to osx-arm64: an extra arm would only add a third
            // way to hit the problem above. Returning undefined is safe -- this provider is a
            // function of the runtime identifier, and Shared.supportsCrossgen() treats an undefined
            // result as 'no crossgen for this runtime'.
            return undefined;
    }
}

@@public
export const framework : Shared.Framework = {
    targetFramework: qualifier.targetFramework,

    supportedRuntimeVersion: "v9.0",
    assemblyInfoTargetFramework: ".NETCoreApp,Version=v9.0",
    assemblyInfoFrameworkDisplayName: ".NET App",

    standardReferences: defaultAssemblies,

    requiresPortablePdb: true,

    runtimeConfigStyle: "runtimeJson",
    runtimeFrameworkName: "Microsoft.NETCore.App",
    runtimeConfigVersion: "9.0.17",

    // Deployment style for .NET Core applications currently defaults to self-contained
    defaultApplicationDeploymentStyle: "selfContained",
    runtimeContentProvider: runtimeContentProvider,
    crossgenProvider: crossgenProvider,

    conditionalCompileDefines: [
        "NET",
        "NETCOREAPP",
        "NETCOREAPP3_1_OR_GREATER",
        "NET5_0_OR_GREATER",
        "NET6_0",
        "NET6_0_OR_GREATER",
        "NET7_0",
        "NET7_0_OR_GREATER",
        "NET8_0",
        "NET8_0_OR_GREATER",
        "NET9_0",
        "NET9_0_OR_GREATER"
    ],
};

function createDefaultAssemblies() : Shared.Assembly[] {
    const pkgContents = importFrom("Microsoft.NETCore.App.Ref90").Contents.all;
    return Helpers.createDefaultAssemblies(pkgContents, "net9.0", /*includeAllAssemblies*/ true);
}
