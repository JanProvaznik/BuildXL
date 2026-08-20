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
 * changes across versions, so the folder is chosen by asking the package what it actually holds
 * rather than by hard-coding one name per platform.
 */
function hasToolDir(name: PathAtom) : boolean {
    const dir = d`${pkgContents.root}/tools/${name}`;
    return pkgContents.getContent().filter(file => (<File>file).isWithin(dir)).length > 0;
}

/**
 * Tool folders to use for this host, best first.
 *
 * macOS is the interesting case, and it is a moving target. Up to and including Grpc.Tools 2.83 the
 * package carried `macosx_x64` only, so an arm64 Mac had nothing native to run and every protobuf
 * codegen pip went through Rosetta 2. grpc/grpc#41222 changed that on 2026-08-10: macOS now ships a
 * single universal binary as `macosx_universal`, and - this is the part that matters here -
 * `macosx_x64` is *replaced* rather than supplemented. grpc's own BUILD-INTEGRATION.md is explicit:
 * "a build that hard-codes a literal tools/macosx_x64/... path must be updated to
 * tools/macosx_universal/...".
 *
 * So a single hard-coded name is wrong in both directions. Naming only `macosx_x64` breaks outright
 * on the first package that ships the change, because the folder simply is not there any more.
 * Naming only `macosx_universal` breaks on every version released so far. Probing an ordered list
 * handles both, and picks up the native tools on arm64 the moment a package carrying them is used.
 *
 * `macosx_arm64` is probed between the two because it is the natural layout for an arm64-only
 * package built from source, which is the way to get native tooling before an upstream release
 * carries it. Upstream has never published that folder and, given the universal binary, never will.
 */
const binDirCandidates : PathAtom[] =
    isHostOsWin   ? [a`windows_x64`] :
    isHostOsOsx   ? (isHostArm64
                        ? [a`macosx_universal`, a`macosx_arm64`, a`macosx_x64`]
                        : [a`macosx_universal`, a`macosx_x64`]) :
    isHostOsLinux ? (isHostArm64
                        ? [a`linux_arm64`, a`linux_x64`]
                        : [a`linux_x64`]) :
    Contract.fail("Unsupported OS");

/**
 * The first candidate the package actually carries.
 *
 * On an arm64 host the later candidates are x64 folders, which only run under emulation - Rosetta 2
 * on macOS. That is what every macOS build did before the universal binary existed; without the
 * emulator protoc fails to start at all.
 */
const binDir = binDirCandidates.filter(candidate => hasToolDir(candidate))[0];

// Failing here names the problem. Letting it through produces a missing-file error against a path
// nobody wrote down, which reads as a corrupt package rather than an unsupported platform.
const binDirOrFail = binDir !== undefined
    ? binDir
    : Contract.fail(`Grpc.Tools carries none of the expected tool folders for this host: ${binDirCandidates.map(c => c.toString()).join(", ")}`);

@@public
export const tool: Transformer.ToolDefinition = {
    exe: pkgContents.getFile(isHostOsWin
        ? r`tools/windows_x64/protoc.exe`
        : r`tools/${binDirOrFail}/protoc`),
    dependsOnCurrentHostOSDirectories: true
};

@@public
export const pluginPath = (() => {
    const pluginPath = pkgContents.getFile(isHostOsWin
        ? r`tools/windows_x64/grpc_csharp_plugin.exe`
        : r`tools/${binDirOrFail}/grpc_csharp_plugin`);

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
