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
// Only the arm64 macOS native library is consumed from this package; its managed assemblies are never
// referenced, so RocksDbSharp still comes from the signed package below. See config.dsc.
const nativePackageOsxArm64 = importFrom("RocksDbNativeOsxArm64").pkg;
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
            // RocksDbNative is built for amd64 only ('build/native/amd64/...') and carries no arm64 macOS
            // dylib, so the native library is taken from the upstream distribution of the same RocksDB
            // release instead. Without it an osx-arm64 engine gets as far as evaluating the graph and then
            // fails with "Failed to initialize a RocksDb store" from the memoization store, because every
            // component that opens the local cache needs this library.
            //
            // Note the different layout: RocksDbNative uses 'build/native/<arch>' while the upstream
            // package uses the conventional 'runtimes/<rid>/native'. Switch back to RocksDbNative once it
            // publishes an arm64 macOS binary.
            nativeFilesToDeploy = nativeFilesToDeploy.push(nativePackageOsxArm64.contents.getFile(r`runtimes/osx-arm64/native/librocksdb.dylib`));
            break;
        default:
            Contract.fail(`Unsupported target runtime '${qualifier.targetRuntime}' for RocksDbNative.`);
            break;
    }

    return nativeFilesToDeploy;
}