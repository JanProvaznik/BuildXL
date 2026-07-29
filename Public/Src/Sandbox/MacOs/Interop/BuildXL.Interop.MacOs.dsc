// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

import {Artifact, Cmd, Transformer} from "Sdk.Transformers";

namespace InteropLibrary {
    export declare const qualifier : {
        configuration: "debug" | "release",
        targetRuntime: "osx-x64" | "osx-arm64"
    };

    const isMacOsHost = Context.getCurrentHost().os === "macOS";

    const clangTool : Transformer.ToolDefinition = {
        exe: MacOsClang.clang,
        prepareTempDirectory: true,
        dependsOnCurrentHostOSDirectories: true,
        untrackedDirectoryScopes: MacOsClang.toolchainScopes,
        untrackedDirectories: MacOsClang.toolchainProbedDirectories
    };

    const sources : File[] = [
        f`Posix/cpu.c`,
        f`Posix/io.c`,
        f`Posix/memory.c`,
        f`Posix/process.c`,
    ];

    const headers : File[] = globR(d`Posix`, "*.h");

    // See BuildXL.Sandbox.MacOs.dsc: naming the headers covers what the compiler reads, sealing the
    // directory covers the far larger number of paths it probes and does not find.
    const includeDirectorySeals : StaticDirectory[] = isMacOsHost
        ? [Transformer.sealSourceDirectory(d`Posix`, Transformer.SealSourceDirectoryOption.allDirectories)]
        : [];

    /**
     * arm64 macOS did not exist before macOS 11, so a deployment target older than that is not
     * meaningful for it. x86_64 keeps the 10.13 floor the Xcode project has always used.
     */
    const minimumOsVersion = qualifier.targetRuntime === "osx-arm64" ? "11.0" : "10.13";

    /**
     * Built for the architecture named by the target runtime rather than the host's, for the same
     * reason as the sandbox broker: without an explicit -arch, clang emits host-architecture code.
     */
    const targetArchitecture = qualifier.targetRuntime === "osx-arm64" ? "arm64" : "x86_64";

    /**
     * libBuildXLInterop.dylib carries the macOS implementations behind BuildXL.Interop.Unix -- memory
     * and CPU counters, process resource usage, file attribute and timestamp calls, and crash dump
     * setup. It is not optional: BuildXLApp's static constructor reaches MachineInfo.CreateForCurrentMachine,
     * which P/Invokes GetRamUsageInfo, so bxl throws a TypeInitializationException before doing any work
     * at all when the library is missing.
     *
     * It is built here, from source, rather than being consumed from a prebuilt package because until
     * now no part of the DScript build produced or deployed it. It was compiled by a separate xcodebuild
     * invocation in the macOS pipeline and copied next to the binaries by shell steps, which meant a
     * macOS deployment was never self-contained and could not be produced by BuildXL alone. Linux has
     * no equivalent gap: its native components are built by the build.
     *
     * Compiling with clang directly, rather than through Interop.xcodeproj, keeps this buildable with
     * the Command Line Tools alone. A full Xcode install is not needed for four C files.
     */
    @@public
    export const interopLibrary : DerivedFile = isMacOsHost ? build() : undefined;

    function build() : DerivedFile {
        const outDir = Context.getNewOutputDirectory("libBuildXLInterop");
        const outFile = p`${outDir}/libBuildXLInterop.dylib`;

        const args : Argument[] = [
            Cmd.option("-o ", Artifact.output(outFile)),
            Cmd.args(sources.map(Artifact.input)),
            Cmd.argument("-dynamiclib"),
            Cmd.option("-arch ", targetArchitecture),
            Cmd.option("-isysroot ", Artifact.none(MacOsClang.sdkRoot)),
            Cmd.argument(`-mmacosx-version-min=${minimumOsVersion}`),
            // The managed side resolves the library by name from the deployment directory, so the
            // install name has to be @rpath-relative rather than an absolute build path.
            Cmd.option("-install_name ", "@rpath/libBuildXLInterop.dylib"),
            Cmd.argument("-fPIC"),
            Cmd.argument(qualifier.configuration === "debug" ? "-O0" : "-O2"),
            Cmd.flag("-g", qualifier.configuration === "debug"),
        ];

        const result = Transformer.execute({
            tool: clangTool,
            workingDirectory: outDir,
            arguments: args,
            // Headers are dependencies rather than command line inputs: naming a .h on a clang
            // command line asks it to precompile that header, which makes the invocation produce
            // more than one output and fails with "cannot specify -o when generating multiple
            // output files".
            dependencies: [...headers, ...includeDirectorySeals],
            // ld resolves the @rpath install name against its own search list before writing it, and
            // with no -rpath on the command line the remaining candidate is the literal "rpath/<name>"
            // relative to the working directory. The stat is real - it reproduces outside BuildXL - and
            // the sandbox reports it, so it is declared rather than argued away. The working directory
            // itself is probed for the same reason. Both are the pip's own scratch space, which is why
            // untracking them costs nothing: no other pip can observe what is under it.
            unsafe: {
                untrackedPaths: [outDir],
                untrackedScopes: [d`${outDir}/rpath`],
            },
            tags: ["compile", "macos", "interop"],
        });

        return result.getOutputFile(outFile);
    }
}
