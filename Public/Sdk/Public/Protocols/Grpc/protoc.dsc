// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

import {Artifact, Cmd, Tool, Transformer} from "Sdk.Transformers";
import * as Managed from "Sdk.Managed.Shared";

const pkgContents = importFrom("Grpc.Tools").Contents.all;
const includesFolder = d`${pkgContents.root}/build/native/include`;

const currentHost = Context.getCurrentHost();
const isHostOsOsx : boolean = currentHost.os === "macOS";
const isHostOsWin : boolean = currentHost.os === "win";
const isHostOsLinux : boolean = currentHost.os === "unix";
const isHostArm64 : boolean = currentHost.cpuArchitecture === "arm64";

/**
 * True when Grpc.Tools carries a tool folder with the given name.
 *
 * The package does not ship a folder for every OS/architecture pair, and which pairs are present
 * changes over time. As of 2.71.0 it carries linux_arm64 but no macosx_arm64, and grpc publishes no
 * standalone plugin binaries anywhere else, so on an arm64 Mac there is currently nothing native to
 * run. Asking the package what it holds - rather than hard-coding today's answer - means the arm64
 * folders get picked up automatically, with no change here, as soon as upstream adds them.
 */
function hasToolDir(name: PathAtom) : boolean {
    const dir = d`${pkgContents.root}/tools/${name}`;
    return pkgContents.getContent().filter(file => (<File>file).isWithin(dir)).length > 0;
}

const nativeBinDir =
    isHostOsWin   ? a`windows_x64` :
    isHostOsOsx   ? (isHostArm64 ? a`macosx_arm64` : a`macosx_x64`) :
    isHostOsLinux ? (isHostArm64 ? a`linux_arm64`  : a`linux_x64`)  :
    Contract.fail("Unsupported OS");

/**
 * Where an arm64 host has no native folder to fall back from, the x64 tools are used instead. That
 * is what every macOS build has done to date, and it only works under emulation (Rosetta 2 on
 * macOS); without it protoc fails to start at all.
 */
const emulatedBinDir =
    isHostOsWin   ? a`windows_x64` :
    isHostOsOsx   ? a`macosx_x64` :
    a`linux_x64`;

const binDir = hasToolDir(nativeBinDir) ? nativeBinDir : emulatedBinDir;

@@public
export const tool: Transformer.ToolDefinition = {
    exe: pkgContents.getFile(isHostOsWin
        ? r`tools/windows_x64/protoc.exe`
        : r`tools/${binDir}/protoc`),
    dependsOnCurrentHostOSDirectories: true
};

@@public
export const pluginPath = (() => {
    const pluginPath = pkgContents.getFile(isHostOsWin
        ? r`tools/windows_x64/grpc_csharp_plugin.exe`
        : r`tools/${binDir}/grpc_csharp_plugin`);

    const outDir = Context.getNewOutputDirectory("plugin-exe");
    const outExe = p`${outDir}/${pluginPath.name}`;

    if (isHostOsOsx || isHostOsLinux) {
        const result = Transformer.execute({
            tool: {
                exe: f`/bin/bash`,
                dependsOnCurrentHostOSDirectories: true
            },
            workingDirectory: outDir,
            arguments: [ 
                Cmd.argument("-c"),
                Cmd.rawArgument('"'),
                Cmd.args([ "cp", Artifact.input(pluginPath), Artifact.output(outExe) ]),
                Cmd.rawArgument(" && "),
                Cmd.args([ "chmod", "u+x", Artifact.none(outExe) ]),
                Cmd.rawArgument('"')
            ]
        });
        return result.getOutputFile(outExe);
    }
    else {
        return Transformer.copyFile(pluginPath, outExe);
    }
})();

/**
 * Standard includes for Protobufs.
 */
@@public
export const includes = Transformer.sealPartialDirectory(
    includesFolder, 
    pkgContents.getContent().filter(file => (<File>file).isWithin(includesFolder))
);

/**
 * Generates the protobuf files.
 * For now this is simply hardcoded to generate C# on windows
 * For production this should be extended to support all languages and multiple platforms
 */
@@public
export function generateCSharp(args: ArgumentsCSharp) : Result {

    let resultSources : File[] = [];

    let filesToProcess : {file: File, isRpc: boolean }[] = [];
    
    if (args.proto) {
        for (let file of args.proto) {
            filesToProcess = filesToProcess.push({file: file, isRpc: false});
        }
    }

    if (args.rpc) {
        for (let file of args.rpc) {
            filesToProcess = filesToProcess.push({file: file, isRpc: true});
        }
    }

    for (let fileToProcess of filesToProcess) {
        const outputDirectory = Context.getNewOutputDirectory("protobuf");
        const arguments : Argument[] = [
            Cmd.option("--proto_path ", Artifact.none(fileToProcess.file.parent)),
            Cmd.option("--csharp_out ", Artifact.none(outputDirectory)),
            Cmd.files([fileToProcess.file]),
            ...addIf(fileToProcess.isRpc,
                Cmd.option("--grpc_out ", Artifact.none(outputDirectory)),
                Cmd.option("--plugin=protoc-gen-grpc=", Artifact.input(pluginPath))
            ),
            Cmd.options("--proto_path=", Artifact.inputs(args.includes)),
        ];

        const targetFileName = fileToProcess.file.nameWithoutExtension.toString().replace("_", "");
        const mainCsFile = p`${outputDirectory}/${targetFileName + ".cs"}`;
        const grpcCsFile = p`${outputDirectory}/${targetFileName + "Grpc.cs"}`;

        const result = Transformer.execute({
            tool: args.tool || tool,
            arguments: arguments,
            tags:["protobufgenerator", "codegen"],
            workingDirectory: outputDirectory,
            outputs: [
                mainCsFile,
                ...addIf(fileToProcess.isRpc,
                    grpcCsFile
                ),
            ],
            dependencies: filesToProcess.map(fileToProcess => fileToProcess.file)
        });

        resultSources = resultSources.push(result.getOutputFile(mainCsFile));
        if (fileToProcess.isRpc) {
            resultSources = resultSources.push(result.getOutputFile(grpcCsFile));
        }
    }

    return {
        sources: resultSources,
    };
}

@@public
export interface ArgumentsCSharp extends Transformer.RunnerArguments{
    proto?: File[],
    rpc?: File[],
    includes?: StaticDirectory[],
}

@@public
export interface Result {
    sources: File[],
}
