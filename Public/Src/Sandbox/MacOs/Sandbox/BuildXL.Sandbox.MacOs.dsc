// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

import {Artifact, Cmd, Transformer} from "Sdk.Transformers";

namespace EndpointSecuritySandbox {
    export declare const qualifier : {
        configuration: "debug" | "release",
        targetRuntime: "osx-x64" | "osx-arm64"
    };

    const isMacOsHost = Context.getCurrentHost().os === "macOS";

    const clangTool : Transformer.ToolDefinition = {
        exe: f`/usr/bin/clang++`,
        prepareTempDirectory: true,
        dependsOnCurrentHostOSDirectories: true,
        untrackedDirectoryScopes: [
            d`/Library/Developer`,
            d`/Applications/Xcode.app`
        ]
    };

    const sandboxRoot = d`.`;
    const sandboxSourceRoot = d`../../..`;

    /**
     * The broker deliberately shares the Linux sandbox's policy engine and report writer rather than
     * reimplementing them. That is what makes macOS policy decisions and report format identical to
     * Linux by construction instead of by review: the same PolicyResult, the same AccessChecker, the
     * same ReportBuilder produce the bytes on both platforms.
     */
    const sharedSources : File[] = [
        f`${sandboxSourceRoot}/Windows/DetoursServices/PolicyResult_common.cpp`,
        f`${sandboxSourceRoot}/Windows/DetoursServices/PolicySearch.cpp`,
        f`${sandboxSourceRoot}/Windows/DetoursServices/StringOperations.cpp`,
        f`${sandboxSourceRoot}/Windows/DetoursServices/FilesCheckedForAccess.cpp`,
        f`${sandboxSourceRoot}/Common/FileAccessManifest.cpp`,
        f`${sandboxSourceRoot}/Linux/AccessChecker.cpp`,
        f`${sandboxSourceRoot}/Linux/SandboxEvent.cpp`,
        f`${sandboxSourceRoot}/Linux/ReportBuilder.cpp`,
    ];

    const brokerSources : File[] = [
        f`Taint.cpp`,
        f`NormalizedEvent.cpp`,
        f`SequenceTracker.cpp`,
        f`ProcessTable.cpp`,
        f`ReportSink.cpp`,
        f`FenceProtocol.cpp`,
        f`EventTranslator.cpp`,
        f`SandboxEngine.cpp`,
        f`ReplaySource.cpp`,
        f`Evidence.cpp`,
        f`EsIngress.cpp`,
        f`bxl-es-broker.cpp`,
    ];

    const headers : File[] = [
        ...globR(sandboxRoot, "*.h"),
        ...globR(d`${sandboxSourceRoot}/Windows/DetoursServices`, "*.h"),
        ...globR(d`${sandboxSourceRoot}/Common`, "*.h"),
        ...globR(d`${sandboxSourceRoot}/Linux`, "*.h"),
    ];

    const includeDirectories : Directory[] = [
        sandboxRoot,
        d`${sandboxSourceRoot}/Linux`,
        d`${sandboxSourceRoot}/Windows/DetoursServices`,
        d`${sandboxSourceRoot}/Common`,
    ];

    /**
     * Endpoint Security is only available from macOS 27, which is where es_new_descendants_client was
     * introduced. Older releases have no API that can observe a process tree soundly, so there is
     * nothing to fall back to and the minimum is a hard one.
     */
    const minimumOsVersion = "27.0";

    @@public
    export const broker : DerivedFile = isMacOsHost ? build() : undefined;

    function build() : DerivedFile {
        const outDir = Context.getNewOutputDirectory("bxl-es-broker");
        const outFile = p`${outDir}/bxl-es-broker`;

        const args : Argument[] = [
            Cmd.option("-o ", Artifact.output(outFile)),
            Cmd.args([...sharedSources, ...brokerSources].map(Artifact.input)),
            Cmd.args(headers.map(Artifact.input)),
            Cmd.argument("-std=c++17"),
            // Endpoint Security's client handler is a block, so blocks must be enabled.
            Cmd.argument("-fblocks"),
            Cmd.argument(`-mmacosx-version-min=${minimumOsVersion}`),
            Cmd.argument("-DMAC_OS_ES_SANDBOX=1"),
            Cmd.argument("-D_DARWIN_C_SOURCE"),
            Cmd.argument(qualifier.configuration === "debug" ? "-O0" : "-O2"),
            Cmd.flag("-g", qualifier.configuration === "debug"),
            Cmd.options("-I", includeDirectories.map(d => Artifact.none(d))),
            Cmd.argument("-lEndpointSecurity"),
            // audit_token_to_pid and friends live in libbsm.
            Cmd.argument("-lbsm"),
        ];

        const result = Transformer.execute({
            tool: clangTool,
            workingDirectory: outDir,
            arguments: args,
            tags: ["compile", "macos", "sandbox"],
        });

        return result.getOutputFile(outFile);
    }
}
