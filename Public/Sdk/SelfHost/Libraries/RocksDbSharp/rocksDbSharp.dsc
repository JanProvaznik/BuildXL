// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

import * as BuildXLSdk from "Sdk.BuildXL";
import * as Managed from "Sdk.Managed";
import {TargetFrameworks} from "Sdk.Managed.Shared";
import * as Deployment from "Sdk.Deployment";

export declare const qualifier: {
    targetFramework: TargetFrameworks.AllFrameworks;
    targetRuntime: "win-x64" | "osx-x64" | "osx-arm64" | "linux-x64";
    configuration: "debug" | "release";
};

const nativePackage = importFrom("RocksDbNative").pkg;
const managedPackage = importFrom("RocksDbSharpSigned").pkg;

// This is meant to be used only when declaring NuGet packages' dependencies. In that particular case, you should be
// calling this function with includeNetStandard: false
@@public
export function getRocksDbPackages(includeNetStandard: boolean): (Managed.ManagedNugetPackage | Managed.Assembly)[] {
    return [
        ...getRocksDbPackagesWithoutNetStandard(),
        ...BuildXLSdk.getSystemMemoryPackages(includeNetStandard),
    ];
}

@@public
export function getRocksDbPackagesWithoutNetStandard(): Managed.ManagedNugetPackage[] {
    return [
        managedPackage.override<Managed.ManagedNugetPackage>({
            // Rename the package so that we declare the proper nuget dependency.
            name: "RocksDbSharp",
        }),
    
        nativePackage.override<Managed.ManagedNugetPackage>({
            // Mimic the custom msbuild targets to copy bits.
            runtimeContent: {
                contents: [ <Deployment.NestedDefinition>{
                    subfolder: r`native`,
                    contents: [ 
                        ...getRocksDbNativeDeployablesForTargetRuntime()
                    ] 
                }]
            }
        }),

        ...BuildXLSdk.getSystemMemoryPackagesWithoutNetStandard(),
    ];
}

@@public
export const pkgs = getRocksDbPackages(true);

function getRocksDbNativeDeployablesForTargetRuntime() : File[] {
    let nativeFilesToDeploy : File[] = [];
    
    switch (qualifier.targetRuntime) {
        case "win-x64":
            nativeFilesToDeploy = nativeFilesToDeploy.push(nativePackage.contents.getFile(r`build/native/amd64/rocksdb.dll`));
            break;
        case "osx-x64":
            nativeFilesToDeploy = nativeFilesToDeploy.push(nativePackage.contents.getFile(r`build/native/amd64/librocksdb.dylib`));
            break;
        case "linux-x64":
            nativeFilesToDeploy = nativeFilesToDeploy.push(nativePackage.contents.getFile(r`build/native/amd64/librocksdb.so`));
            break;
        case "osx-arm64":
            // The RocksDbNative package is built for amd64 only ('build/native/amd64/...'); it carries no
            // arm64 macOS dylib. Failing here with an explicit message is better than a generic
            // 'file not found in package' error, because the fix is external to this repository:
            // RocksDbNative has to publish 'build/native/arm64/librocksdb.dylib' first.
            Contract.fail(
                "RocksDbNative does not ship an osx-arm64 native library. " +
                "Publish a RocksDbNative package containing 'build/native/arm64/librocksdb.dylib' " +
                "and add it here before building the osx-arm64 target runtime.");
            break;
        default:
            Contract.fail(`Unsupported target runtime '${qualifier.targetRuntime}' for RocksDbNative.`);
            break;
    }

    return nativeFilesToDeploy;
}