// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

import * as Deployment from "Sdk.Deployment";

@@public
export interface Framework {
    /**
     * The minimum runtime version supported.
     * See: https://docs.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/startup/supportedruntime-element
     */
    supportedRuntimeVersion: string,

    /** The qualifier targetFramework moniker */
    targetFramework: string;

    /** The targetFramework name to be placed in TargetFrameworkAttribute in AssemblyInfo file */
    assemblyInfoTargetFramework: string;

    /** The frameworkDisplayName name to be placed in TargetFrameworkAttribute in AssemblyInfo file */
    assemblyInfoFrameworkDisplayName: string;

    /** The standard references that should be added to the compile list */
    standardReferences: Reference[];

    /** Whether to generate portablePdb */
    requiresPortablePdb: boolean;

    /** The style of runtime configuration files */
    runtimeConfigStyle: RuntimeConfigStyle;

    /** Optional set of defines to be passed to compilers to indicate the current target framework */
    conditionalCompileDefines: string[];

    /** When the runtimeConfigStyle is runtimeJson, a runtime framework name is required */
    runtimeFrameworkName?: string;

    /** When the runtimeConfigStyle is runtimeJson, a version is required */
    runtimeConfigVersion?: string;

    /** Whether applications should be deployed framework-dependent or self-contained */
    defaultApplicationDeploymentStyle?: ApplicationDeploymentStyle;

    /** When ApplicationDeploymentStyle is selfContained, runtime files have to be provided for the application execution environment */
    runtimeContentProvider?: (version: RuntimeVersion) => File[];

    /** Framework-specific files for crossgen tool. Only available for netcore app frameworks.*/
    crossgenProvider?: (version: RuntimeVersion) => CrossgenFiles;

}

/** Whether the given framework supports crossgen for the given runtime */
@@public 
export function supportsCrossgen(deploymentStyle: ApplicationDeploymentStyle, framework: Framework, runtimeVersion: RuntimeVersion): boolean {
    // crossgen is supported when the application deployment style is self-contained, the underlying
    // framework sets a provider, and that provider actually yields files for this runtime.
    //
    // The last condition is not redundant. A provider is a function of the runtime identifier and
    // returns undefined for runtimes it has no crossgen for -- net8/net9/net10 do exactly that for
    // everything except win-x64 and osx-x64. Testing only that the provider exists would report
    // support for every runtime the framework declares, and crossgen() would then dereference the
    // undefined result while reading JITPath.
    return deploymentStyle === "selfContained"
        && framework.crossgenProvider !== undefined
        && framework.crossgenProvider(runtimeVersion) !== undefined;
}


/** Path to crossgen tool and its corresponding JIT compiler. */
@@public
export interface CrossgenFiles {
    crossgenExe: File;
    JITPath: File;
}

export type RuntimeConfigStyle = "appConfig" | "runtimeJson" | "none";

@@public
export type ApplicationDeploymentStyle = "frameworkDependent" | "selfContained";

@@public
export type RuntimeVersion = "win-x64" | "osx-x64" | "osx-arm64" | "linux-x64";

/**
 * The runtime identifier matching the machine the build is running on.
 *
 * macOS is the only host where the architecture actually has to be consulted: Apple Silicon Macs
 * cannot run osx-x64 binaries unless Rosetta 2 happens to be installed, and Rosetta is neither
 * present by default nor guaranteed to stay available, so picking osx-x64 on an arm64 Mac produces
 * a deployment that will not start.
 */
@@public
export function currentMachineRuntimeVersion() : RuntimeVersion {
    const host = Context.getCurrentHost();
    switch (host.os) {
        case "win":
            return "win-x64";
        case "macOS":
            return host.cpuArchitecture === "arm64" ? "osx-arm64" : "osx-x64";
        default:
            return "linux-x64";
    }
}

/** True for every macOS runtime identifier. */
@@public
export function isMacOsRuntime(runtimeVersion: RuntimeVersion) : boolean {
    return runtimeVersion === "osx-x64" || runtimeVersion === "osx-arm64";
}

@@public
export type DotNetCoreVersion = "net8.0" | "net9.0" | "net10.0" | "net11.0";

@@public
export function isDotNetCore(targetFramework: TargetFrameworks.AllFrameworks) : targetFramework is DotNetCoreVersion {
    return  targetFramework === 'net8.0' || targetFramework === 'net9.0' || targetFramework === 'net10.0' || targetFramework === 'net11.0';
}

namespace TargetFrameworks {
    @@public
    export const DefaultTargetFramework = "net9.0";
    
    @@public
    export type DesktopTargetFrameworks = "net472";

    @@public
    export type CoreClrTargetFrameworks = "net8.0" | "net9.0" | "net10.0" | "net11.0";

    @@public
    export type StandardTargetFrameworks = "netstandard2.0";

    @@public
    export type AllFrameworks = DesktopTargetFrameworks | CoreClrTargetFrameworks | StandardTargetFrameworks;

    @@public
    export interface ConfigurationQualifier extends Qualifier {
        configuration: "debug" | "release"
    }

    @@public
    export interface BaseQualifier extends ConfigurationQualifier, Qualifier {
        targetRuntime: RuntimeVersion;
    }

    @@public
    export interface Desktop extends BaseQualifier, Qualifier {
        targetFramework: DesktopTargetFrameworks;
    }

    @@public
    export interface CoreClr extends BaseQualifier, Qualifier {
        targetFramework: CoreClrTargetFrameworks;
    }

    @@public
    export interface All extends BaseQualifier, Qualifier {
        targetFramework: AllFrameworks;
    }

    /** Current Machine qualifier that respect current configuration */
    namespace MachineQualifier {
        export declare const qualifier: {configuration: "debug" | "release" };

        @@public
        export interface Current extends Qualifier {
            configuration: "debug" | "release";
            targetFramework: "net9.0",
            targetRuntime: "win-x64" | "osx-x64" | "osx-arm64" | "linux-x64",
        }

        @@public
        export interface CurrentWithStandard extends Qualifier {
            configuration: "debug" | "release";
            targetFramework: "net9.0" | "netstandard2.0",
            targetRuntime: "win-x64" | "osx-x64" | "osx-arm64" | "linux-x64",
        }

        @@public
        export const current : Current = {
            configuration: qualifier.configuration,
            targetFramework: "net9.0",
            targetRuntime: currentMachineRuntimeVersion(),
        };
    }
}
