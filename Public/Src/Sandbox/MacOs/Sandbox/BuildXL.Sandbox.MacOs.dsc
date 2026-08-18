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
    // Deliberately lower than the 27.0 that es_new_descendants_client requires. Building at 27.0
    // binds that symbol strictly, so dyld refuses to load the broker on anything older and the
    // interposition backend - the documented fallback for machines without Endpoint Security - can
    // never be reached. At 26.0 the macOS 27 entry points are weakly imported, resolve to null on an
    // older system, and EsIngress::Start reports a normal failure that selects interposition. The
    // SDK is still the 27 one, so nothing about the Endpoint Security path changes on macOS 27.
    const minimumOsVersion = "26.0";

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
     * A provisioning profile authorizing the Endpoint Security entitlement, if the pipeline has one.
     *
     * Apple authorizes a *restricted* entitlement for third-party code through a provisioning
     * profile, and AMFI looks for that profile inside the bundle - a bare Mach-O has nowhere to put
     * one. So a broker that must be honoured on a machine with SIP and AMFI enabled has to be
     * bundled. When this is unset, the build produces the bare executable it always has, which is
     * what a development machine wants and what an AMFI-relaxed machine accepts.
     */
    const provisioningProfile = Environment.hasVariable("BUILDXL_MACOS_PROVISIONING_PROFILE")
        ? Environment.getStringValue("BUILDXL_MACOS_PROVISIONING_PROFILE")
        : undefined;

    /**
     * The bundle identifier, which must match the application identifier the profile was issued for.
     * A mismatch is rejected by AMFI even though the profile is present and valid.
     */
    const bundleIdentifier = Environment.hasVariable("BUILDXL_MACOS_BUNDLE_ID")
        ? Environment.getStringValue("BUILDXL_MACOS_BUNDLE_ID")
        : "com.microsoft.buildxl.essandbox";

    /**
     * The broker packaged as a bundle around the signed executable, produced only when a
     * provisioning profile is supplied. This is the form that works on a machine that has not been
     * told to stop checking signatures.
     */
    @@public
    export const brokerBundle : StaticDirectory = isMacOsHost && provisioningProfile !== undefined
        ? packageBrokerBundle()
        : undefined;

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
    /**
     * The identity to sign the broker with.
     *
     * Ad-hoc ("-") by default, which is what a development machine wants: it makes the entitlement
     * present so an AMFI-relaxed machine honours it, and it needs no credentials. A pipeline that
     * holds the team's certificate sets BUILDXL_MACOS_SIGNING_IDENTITY to the identity name, and the
     * broker it produces is one that works on a normal machine with SIP and AMFI both on.
     *
     * The identity lands on the command line, so it is part of the pip's fingerprint: changing it
     * re-signs rather than silently reusing a cached ad-hoc signature. That matters, because the two
     * are indistinguishable by file name and differ only in whether the kernel accepts the result.
     */
    const signingIdentity = Environment.hasVariable("BUILDXL_MACOS_SIGNING_IDENTITY")
        ? Environment.getStringValue("BUILDXL_MACOS_SIGNING_IDENTITY")
        : "-";

    /**
     * A keychain to sign from, for pipelines that import the certificate into a dedicated keychain
     * rather than the login one. Unset means codesign uses the default search list.
     */
    const signingKeychain = Environment.hasVariable("BUILDXL_MACOS_SIGNING_KEYCHAIN")
        ? Environment.getStringValue("BUILDXL_MACOS_SIGNING_KEYCHAIN")
        : undefined;

    /**
     * Wraps the signed broker in a bundle carrying the provisioning profile, then signs the bundle.
     *
     * The layout mirrors the only shipping third-party Endpoint Security client available to compare
     * against: the executable at Contents/MacOS, the profile at Contents/embedded.provisionprofile,
     * and the entitlement in the signature of the code itself. The bundle is signed as a unit after
     * the profile is in place, because codesign seals the bundle's contents - signing first and
     * copying the profile in afterwards produces a bundle that fails its own signature check.
     */
    function packageBrokerBundle() : StaticDirectory {
        const outDir = Context.getNewOutputDirectory("bxl-es-broker-bundle");
        const bundle = d`${outDir}/bxl-es-broker.app`;
        const entitlements = f`bxl-es-broker.entitlements`;
        const infoPlistTemplate = f`bxl-es-broker.Info.plist`;

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
                // Paths inside the bundle are relative to the pip's working directory, which is the
                // output directory. Interpolating a Path into a template string does not produce a
                // plain path - it produces DScript's own path literal syntax, backtick and all - so
                // the bundle would be built inside a directory whose name is the literal text of the
                // expression. Only plain strings from the environment are interpolated below.
                Cmd.rawArgument("mkdir -p bxl-es-broker.app/Contents/MacOS"),
                Cmd.rawArgument(" && cp "),
                Cmd.argument(Artifact.input(broker)),
                Cmd.rawArgument(" bxl-es-broker.app/Contents/MacOS/bxl-es-broker"),
                // The identifier has to match the profile's application identifier, so it is
                // substituted rather than baked into the committed template.
                Cmd.rawArgument(" && sed "),
                Cmd.rawArgument(`'s|__BUNDLE_ID__|${bundleIdentifier}|'`),
                Cmd.argument(Artifact.input(infoPlistTemplate)),
                Cmd.rawArgument(" > bxl-es-broker.app/Contents/Info.plist"),
                Cmd.rawArgument(` && cp '${provisioningProfile}' bxl-es-broker.app/Contents/embedded.provisionprofile`),
                // The bundle is signed as a unit, after the profile is in place: codesign seals the
                // bundle's contents, so copying anything in afterwards invalidates the signature.
                Cmd.rawArgument(" && /usr/bin/codesign --force --sign "),
                Cmd.rawArgument(`'${signingIdentity}'`),
                ...(signingKeychain !== undefined ? [Cmd.rawArgument(` --keychain '${signingKeychain}'`)] : []),
                Cmd.rawArgument(" --entitlements "),
                Cmd.argument(Artifact.input(entitlements)),
                Cmd.rawArgument(" bxl-es-broker.app"),
                Cmd.rawArgument('"'),
            ],
            outputs: [
                { kind: "exclusive", directory: bundle },
            ],
            unsafe: {
                untrackedScopes: [
                    d`/private/var/db`,
                    d`/private/var/folders`,
                    ...(Environment.hasVariable("HOME") ? [d`${Environment.getDirectoryValue("HOME")}/Library`] : []),
                    ...(Environment.hasVariable("BUILDXL_MACOS_SIGNING_KEYCHAIN")
                        ? [Directory.fromPath(Environment.getPathValue("BUILDXL_MACOS_SIGNING_KEYCHAIN").parent)]
                        : []),
                    // The profile is supplied by the pipeline and normally lives outside the repo.
                    // Its path is on the command line, so replacing the file at the same path does
                    // not by itself invalidate this pip - a pipeline that rotates a profile should
                    // treat it like any other credential change and not expect an incremental build
                    // to notice.
                    ...(provisioningProfile !== undefined
                        ? [Directory.fromPath(p`${provisioningProfile}`.parent)]
                        : []),
                ],
                untrackedPaths: [outDir],
            },
            tags: ["codesign", "macos", "sandbox"],
        });

        return result.getOutputDirectory(bundle);
    }

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
                // Single-quoted because this whole command runs inside sh -c "...", and every real
                // signing identity contains spaces - "Developer ID Application: Contoso (AB12CD34EF)".
                // Unquoted, the shell splits it and codesign sees only "Developer", failing with
                // "no identity found" while looking like the certificate is missing.
                Cmd.rawArgument(` '${signingIdentity}'`),
                // Emits nothing when the keychain is unset, which is the common case. Quoted for the
                // same reason: a keychain path may contain spaces.
                ...(signingKeychain !== undefined ? [Cmd.rawArgument(` --keychain '${signingKeychain}'`)] : []),
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
                    // A pipeline that keeps the certificate in a dedicated keychain puts it outside
                    // the paths above, and codesign reads and locks it while signing.
                    ...(Environment.hasVariable("BUILDXL_MACOS_SIGNING_KEYCHAIN")
                        ? [Directory.fromPath(Environment.getPathValue("BUILDXL_MACOS_SIGNING_KEYCHAIN").parent)]
                        : []),
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
