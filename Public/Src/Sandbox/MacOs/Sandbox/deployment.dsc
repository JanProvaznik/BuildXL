// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

import * as SdkDeployment from "Sdk.Deployment";

namespace EndpointSecurityDeployment {
    export declare const qualifier: {configuration: "debug" | "release", targetRuntime: "osx-x64"};

    /**
     * The broker is deployed next to bxl and launched per pip.
     *
     * It has to be code signed with com.apple.developer.endpoint-security.client by a provisioning
     * profile that authorizes it; an unsigned or ad-hoc signed broker is rejected by the kernel with
     * ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED. Signing is a release-pipeline step rather than a build
     * step because it needs credentials the build does not have.
     */
    @@public
    export const natives : SdkDeployment.Definition = Context.getCurrentHost().os === "macOS" && {
        contents: [
            EndpointSecuritySandbox.broker
        ]
    };
}
