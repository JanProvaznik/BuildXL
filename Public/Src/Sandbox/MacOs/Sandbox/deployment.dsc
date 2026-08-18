// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

import * as SdkDeployment from "Sdk.Deployment";

namespace EndpointSecurityDeployment {
    export declare const qualifier: {configuration: "debug" | "release", targetRuntime: "osx-x64" | "osx-arm64"};

    /**
     * The broker and the library it injects, deployed next to bxl and launched per pip.
     *
     * The broker locates the library as its own sibling, so the two must stay in the same directory.
     * Signing only matters for the Endpoint Security backend: that client has to be signed with
     * com.apple.developer.endpoint-security.client by a provisioning profile that authorizes it, and
     * an unsigned or ad-hoc signed broker is rejected with ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED.
     * Signing is a release-pipeline step rather than a build step because it needs credentials the
     * build does not have -- which is exactly why the interposition backend exists and why it is what
     * runs on an unsigned build.
     */
    @@public
    export const natives : SdkDeployment.Definition = Context.getCurrentHost().os === "macOS" && {
        contents: [
            // The bundled broker when the build was given a provisioning profile, the bare executable
            // otherwise. Both are deployed by the same name at different paths and BuildXL prefers
            // the bundle, so a deployment produced by a pipeline that holds the team certificate is a
            // drop-in replacement for one produced on a development machine.
            ...(EndpointSecuritySandbox.brokerBundle !== undefined
                ? [EndpointSecuritySandbox.brokerBundle]
                : [EndpointSecuritySandbox.broker]),
            EndpointSecuritySandbox.interposeLibrary
        ]
    };
}
