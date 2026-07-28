// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

import * as SdkDeployment from "Sdk.Deployment";

namespace InteropDeployment {
    export declare const qualifier: {configuration: "debug" | "release", targetRuntime: "osx-x64" | "osx-arm64"};

    /**
     * libBuildXLInterop.dylib is loaded by name from the directory holding the managed assemblies, so
     * it is deployed flat next to bxl rather than under a runtimes/<rid>/native subfolder.
     *
     * Empty when cross-building, because Mach-O objects cannot be produced without the macOS SDK. A
     * deployment cross-built from Linux or Windows therefore still needs this library supplied
     * separately; see Documentation/Wiki/MacOsSandbox.md.
     */
    @@public
    export const natives : SdkDeployment.Definition = Context.getCurrentHost().os === "macOS" && {
        contents: [
            InteropLibrary.interopLibrary
        ]
    };
}
