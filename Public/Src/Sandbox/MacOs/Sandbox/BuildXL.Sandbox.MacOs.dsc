// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

import {Artifact, Cmd, Transformer} from "Sdk.Transformers";

namespace EndpointSecuritySandbox {
    export declare const qualifier : {
        configuration: "debug" | "release",
        targetRuntime: "osx-x64" | "osx-arm64"
    };

    const isMacOsHost = Context.getCurrentHost().os === "macOS";

    const clangCTool : Transformer.ToolDefinition = {
        exe: MacOsClang.clang,
        prepareTempDirectory: true,
        dependsOnCurrentHostOSDirectories: true,
        untrackedDirectoryScopes: MacOsClang.toolchainScopes,
        untrackedDirectories: MacOsClang.toolchainProbedDirectories
    };

    const clangTool : Transformer.ToolDefinition = {
        exe: MacOsClang.clangxx,
        prepareTempDirectory: true,
        dependsOnCurrentHostOSDirectories: true,
        untrackedDirectoryScopes: MacOsClang.toolchainScopes,
        untrackedDirectories: MacOsClang.toolchainProbedDirectories
    };

    const sandboxRoot = d`.`;
    // This spec lives in Public/Src/Sandbox/MacOs/Sandbox, so two levels up is Public/Src/Sandbox,
    // which is where the Linux, Common and Windows sources it shares actually live.
    const sandboxSourceRoot = d`../..`;

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

    // Everything the broker is made of except its entry point. The self test links the same set
    // against a main of its own, which is what makes it a test of the shipping engine rather than of
    // a copy of it.
    const engineSources : File[] = [
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
        f`InterposeIngress.cpp`,
    ];

    const brokerSources : File[] = [
        ...engineSources,
        f`bxl-es-broker.cpp`,
    ];

    const headers : File[] = [
        ...globR(sandboxRoot, "*.h"),
        ...globR(d`../Interpose`, "*.h"),
        ...globR(d`${sandboxRoot}/UnitTests`, "*.h"),
        ...globR(d`${sandboxSourceRoot}/Windows/DetoursServices`, "*.h"),
        ...globR(d`${sandboxSourceRoot}/Common`, "*.h"),
        ...globR(d`${sandboxSourceRoot}/Linux`, "*.h"),
    ];

    const includeDirectories : Directory[] = [
        sandboxRoot,
        d`../Interpose`,
        d`${sandboxRoot}/UnitTests`,
        d`${sandboxSourceRoot}/Linux`,
        d`${sandboxSourceRoot}/Windows/DetoursServices`,
        d`${sandboxSourceRoot}/Common`,
    ];

    /**
     * The include directories, sealed so the compiler's search is allowed rather than merely tolerated.
     *
     * Naming the headers as file dependencies covers what clang *reads*, but a header search is mostly
     * made of probes for files that are not there: resolving one #include <string> against six -I paths
     * produces five misses, and under a real sandbox every one of those is an undeclared access. Under
     * /sandboxKind:none they were invisible, which is why this spec appeared to be correct for as long
     * as nothing was watching. A sealed source directory is the declaration that covers both the hits
     * and the misses, and it still fingerprints on the files actually accessed rather than on the whole
     * tree, so it costs no precision.
     */
    const includeDirectorySeals : StaticDirectory[] = isMacOsHost
        ? includeDirectories.map(dir => Transformer.sealSourceDirectory(dir, Transformer.SealSourceDirectoryOption.allDirectories))
        : [];

    /**
     * Endpoint Security is only available from macOS 27, which is where es_new_descendants_client was
     * introduced. Older releases have no API that can observe a process tree soundly, so there is
     * nothing to fall back to and the minimum is a hard one.
     */
    const minimumOsVersion = "27.0";

    /**
     * Built for the architecture named by the target runtime rather than the host's. Without an
     * explicit -arch, clang emits host-architecture code, which would silently produce an x86_64
     * broker when cross-building osx-arm64 from an Intel Mac -- a binary that cannot be loaded on
     * the machine it is meant for.
     */
    const targetArchitecture = qualifier.targetRuntime === "osx-arm64" ? "arm64" : "x86_64";

    @@public
    export const broker : DerivedFile = isMacOsHost ? build() : undefined;

    /**
     * The library dyld injects into every process the broker supervises.
     *
     * Built as C rather than C++ on purpose: it runs inside processes that BuildXL does not own, so it
     * must not pull in a C++ runtime that could differ from the one the host process already loaded.
     */
    @@public
    export const interposeLibrary : DerivedFile = isMacOsHost ? buildInterposeLibrary() : undefined;

    /**
     * The self test drives the broker's engine from a recorded event source rather than from Endpoint
     * Security, so it needs no entitlement and no privileges - which is the whole point. It is the only
     * check of the sandbox's soundness that can run on any Mac, and until it was a pip it only ever ran
     * when somebody remembered to compile it by hand.
     */
    @@public
    export const selfTest : DerivedFile = isMacOsHost ? buildSelfTest() : undefined;

    /**
     * Running it is a separate pip so that a failure names the run rather than the compile. Only
     * attempted when the target architecture is the host's: a cross-built binary cannot be executed
     * here, and silently skipping is better than depending on emulation being installed.
     */
    @@public
    export const selfTestResult : DerivedFile =
        isMacOsHost && Context.getCurrentHost().cpuArchitecture === (qualifier.targetRuntime === "osx-arm64" ? "arm64" : "x64")
            ? runSelfTest()
            : undefined;

    function build() : DerivedFile {
        const outDir = Context.getNewOutputDirectory("bxl-es-broker");
        const outFile = p`${outDir}/bxl-es-broker`;

        const args : Argument[] = [
            Cmd.option("-o ", Artifact.output(outFile)),
            Cmd.args([...sharedSources, ...brokerSources].map(Artifact.input)),
            Cmd.option("-arch ", targetArchitecture),
            Cmd.option("-isysroot ", Artifact.none(MacOsClang.sdkRoot)),
            Cmd.argument("-std=c++17"),
            // Endpoint Security's client handler is a block, so blocks must be enabled.
            Cmd.argument("-fblocks"),
            Cmd.argument(`-mmacosx-version-min=${minimumOsVersion}`),
            Cmd.argument("-DMAC_OS_ES_SANDBOX=1"),
            Cmd.argument("-D_DARWIN_C_SOURCE"),
            Cmd.argument(qualifier.configuration === "debug" ? "-O0" : "-O2"),
            Cmd.flag("-g", qualifier.configuration === "debug"),
            // _DEBUG is not a debugging convenience here, it decides a wire format. The managed side
            // writes a "debug" file access manifest when BuildXL itself is built Debug
            // (FileAccessManifest.WriteDebugFlagBlock, under #if DEBUG), and the native side rejects a
            // manifest whose flag does not match its own build (ManifestDebugFlag::CheckValid, under
            // #ifdef _DEBUG). Without this the two disagree for every debug build: the broker exits
            // with "not a valid release-mode file access manifest" before it opens the report FIFO,
            // and BuildXL then waits forever for reports that can never arrive.
            Cmd.flag("-D_DEBUG", qualifier.configuration === "debug"),
            Cmd.options("-I", includeDirectories.map(d => Artifact.none(d))),
            Cmd.argument("-lEndpointSecurity"),
            // audit_token_to_pid and friends live in libbsm.
            Cmd.argument("-lbsm"),
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
            tags: ["compile", "macos", "sandbox"],
        });

        return signBroker(result.getOutputFile(outFile));
    }

    /**
     * Signs the broker with the Endpoint Security client entitlement.
     *
     * Without this the broker builds fine and then fails at run time with
     * ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED, and the sandbox silently falls back to interposition -
     * a working build with quietly weaker observation, which is the worst way for this to go wrong.
     * The entitlement has to be attached at build time because BuildXL deploys the binary it
     * produced; anything applied afterwards is discarded on the next build.
     *
     * Ad-hoc signing does not grant the entitlement - only Apple does, to a named team. It makes the
     * entitlement *present*, which is what a machine with SIP disabled and amfi_get_out_of_my_way=1
     * honours, and what a shipping build re-signs over with the team's real identity.
     */
    function signBroker(unsigned: DerivedFile) : DerivedFile {
        const outDir = Context.getNewOutputDirectory("bxl-es-broker-signed");
        const outFile = p`${outDir}/bxl-es-broker`;
        const entitlements = f`bxl-es-broker.entitlements`;

        const result = Transformer.execute({
            tool: {
                exe: f`/bin/sh`,
                dependsOnCurrentHostOSDirectories: true,
                untrackedDirectoryScopes: MacOsClang.toolchainScopes,
            },
            workingDirectory: outDir,
            arguments: [
                Cmd.argument("-c"),
                Cmd.rawArgument('"'),
                Cmd.argument("cp"),
                Cmd.argument(Artifact.input(unsigned)),
                Cmd.argument(Artifact.output(outFile)),
                Cmd.rawArgument(" && "),
                // codesign rewrites the file in place, so the copy is made first and signed second.
                Cmd.argument("/usr/bin/codesign"),
                Cmd.argument("--force"),
                Cmd.argument("--sign"),
                Cmd.argument("-"),
                Cmd.argument("--entitlements"),
                Cmd.argument(Artifact.input(entitlements)),
                Cmd.argument(Artifact.none(outFile)),
                Cmd.rawArgument('"'),
            ],
            // codesign consults the user's keychain and the system trust settings even for an ad-hoc
            // signature, and writes a resource fork alongside the binary it is signing.
            unsafe: {
                untrackedScopes: [
                    d`/private/var/db`,
                    d`/private/var/folders`,
                    ...(Environment.hasVariable("HOME") ? [d`${Environment.getDirectoryValue("HOME")}/Library`] : []),
                ],
                untrackedPaths: [outDir],
            },
            tags: ["codesign", "macos", "sandbox"],
        });

        return result.getOutputFile(outFile);
    }

    function buildInterposeLibrary() : DerivedFile {
        const outDir = Context.getNewOutputDirectory("bxl-interpose");
        const outFile = p`${outDir}/libBuildXLInterpose.dylib`;

        const args : Argument[] = [
            Cmd.argument("-dynamiclib"),
            Cmd.option("-o ", Artifact.output(outFile)),
            Cmd.argument(Artifact.input(f`../Interpose/bxl-interpose.c`)),
            Cmd.option("-arch ", targetArchitecture),
            // Also built for arm64e, which is not a variant of the same thing but a requirement.
            // Apple's own command line tools -- /bin/sh, /bin/cp, /usr/bin/sed -- ship only x86_64 and
            // arm64e slices, so the ad-hoc signed copies the sandbox runs in their place are arm64e
            // processes, and dyld will not load an arm64-only library into one.
            ...(targetArchitecture === "arm64" ? [Cmd.option("-arch ", "arm64e")] : []),
            Cmd.option("-isysroot ", Artifact.none(MacOsClang.sdkRoot)),
            Cmd.argument("-std=c11"),
            Cmd.argument(`-mmacosx-version-min=${minimumOsVersion}`),
            Cmd.argument("-D_DARWIN_C_SOURCE"),
            // Injected into arbitrary processes, so it must not export anything beyond the interpose
            // table and must not depend on symbols the host process might resolve differently.
            Cmd.argument("-fvisibility=hidden"),
            Cmd.argument(qualifier.configuration === "debug" ? "-O0" : "-O2"),
            Cmd.flag("-g", qualifier.configuration === "debug"),
            Cmd.argument("-Wall"),
            Cmd.argument("-Wextra"),
            Cmd.argument("-Werror"),
            Cmd.option("-install_name ", "@rpath/libBuildXLInterpose.dylib"),
        ];

        const result = Transformer.execute({
            tool: clangCTool,
            workingDirectory: outDir,
            arguments: args,
            dependencies: [
                f`../Interpose/InterposeProtocol.h`,
                f`../Interpose/ShadowTool.h`,
                ...includeDirectorySeals,
            ],
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
            tags: ["compile", "macos", "sandbox"],
        });

        return result.getOutputFile(outFile);
    }

    function buildSelfTest() : DerivedFile {
        const outDir = Context.getNewOutputDirectory("bxl-es-selftest");
        const outFile = p`${outDir}/bxl-es-selftest`;

        const args : Argument[] = [
            Cmd.option("-o ", Artifact.output(outFile)),
            Cmd.args([
                ...sharedSources,
                ...engineSources,
                f`UnitTests/ManifestBuilder.cpp`,
                f`UnitTests/ReportReader.cpp`,
                f`UnitTests/bxl-es-selftest.cpp`,
            ].map(Artifact.input)),
            Cmd.option("-arch ", targetArchitecture),
            Cmd.option("-isysroot ", Artifact.none(MacOsClang.sdkRoot)),
            Cmd.argument("-std=c++17"),
            Cmd.argument("-fblocks"),
            Cmd.argument(`-mmacosx-version-min=${minimumOsVersion}`),
            Cmd.argument("-DMAC_OS_ES_SANDBOX=1"),
            Cmd.argument("-D_DARWIN_C_SOURCE"),
            Cmd.argument(qualifier.configuration === "debug" ? "-O0" : "-O2"),
            Cmd.flag("-g", qualifier.configuration === "debug"),
            Cmd.options("-I", includeDirectories.map(d => Artifact.none(d))),
            Cmd.argument("-lEndpointSecurity"),
            Cmd.argument("-lbsm"),
        ];

        const result = Transformer.execute({
            tool: clangTool,
            workingDirectory: outDir,
            arguments: args,
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
            tags: ["compile", "macos", "sandbox", "test"],
        });

        return result.getOutputFile(outFile);
    }

    function runSelfTest() : DerivedFile {
        const outDir = Context.getNewOutputDirectory("bxl-es-selftest-run");
        const logFile = p`${outDir}/selftest.log`;

        const result = Transformer.execute({
            tool: {
                exe: selfTest,
                prepareTempDirectory: true,
                dependsOnCurrentHostOSDirectories: true,
                // A self test that hangs should be reported as a hang rather than inherit the default
                // budget silently. The sweep below runs in seconds; these leave generous headroom for
                // a loaded machine while still bounding the damage.
                timeoutInMilliseconds: 10 * 60 * 1000,
                warningTimeoutInMilliseconds: 2 * 60 * 1000,
            },
            workingDirectory: outDir,
            arguments: [
                // The default 100k-scenario sweep spends most of its wall clock asleep: roughly one
                // scenario in seventeen drops the closing marker on purpose, and each of those waits
                // out the fence timeout. The scenarios are generated from the iteration index, so a
                // shorter sweep is a prefix of the long one rather than a different sample: it covers
                // every single fault and most pairs, which is what a per-build regression check needs.
                // The full sweep stays the default for a deliberate run.
                Cmd.option("--sweep ", 2000),

                // Correctness decides this pip. The throughput and latency gates measure the machine
                // as well as the code, and this pip runs while the rest of the build is competing for
                // the same cores, so they are measured and printed here but never fail the build.
                Cmd.argument("--no-perf-gates"),
            ],
            consoleOutput: logFile,
            // A non-zero exit fails the pip, which is the assertion: the self test reports the number
            // of failed checks in its exit code.
            tags: ["macos", "sandbox", "test"],
        });

        return result.getOutputFile(logFile);
    }
}
