// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace MacOsClang {
    /**
     * Resolves the real clang rather than the shim in /usr/bin.
     *
     * /usr/bin/clang is a stub that reads the active developer directory - global machine state set
     * by xcode-select and not an input to any pip - and execs whichever toolchain it finds. Naming it
     * therefore makes a build depend on state BuildXL does not track, so two machines with different
     * xcode-select settings silently compile with different compilers under the same fingerprint.
     *
     * It is also SIP protected, and dyld refuses to inject into a SIP protected binary and erases
     * DYLD_INSERT_LIBRARIES from its environment for good measure. Under the interposition sandbox
     * that makes every clang pip unobservable, which the broker correctly reports as a taint and
     * which correctly makes the pip uncacheable - a correct answer to a question that did not need
     * asking. The toolchain binaries themselves are not SIP protected.
     *
     * Both problems have the same fix: name the compiler, not the stub that finds it.
     */
    function resolve(name: string) : File {
        const commandLineTools = f`/Library/Developer/CommandLineTools/usr/bin/${name}`;
        if (File.exists(commandLineTools)) {
            return commandLineTools;
        }

        const xcode = f`/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/${name}`;
        if (File.exists(xcode)) {
            return xcode;
        }

        // Nothing to fall back to that would not reintroduce the untracked dependency, so say which
        // two places were looked in rather than failing later inside a compile.
        Contract.fail(
            `No clang toolchain found. Looked for '${name}' in /Library/Developer/CommandLineTools/usr/bin ` +
            `and /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin. ` +
            `Install the Command Line Tools with 'xcode-select --install'.`);
        return undefined;
    }

    /**
     * Resolves the macOS SDK the way the compiler cannot resolve it for itself.
     *
     * /usr/bin/clang appears to know where the SDK is, but it does not: the shim asks xcode-select and
     * passes the answer down. Invoke the real compiler with a clean environment and its include search
     * path contains no SDK at all, so <dirent.h> and <mach/mach.h> are simply not found. That is not a
     * sandbox restriction - it reproduces outside BuildXL with `env -i clang -E -x c /dev/null -v`.
     *
     * So the SDK has to be named. Doing so is again the more correct option on its own merits: it
     * removes the second piece of untracked global state, and it means a build cannot silently start
     * compiling against a different SDK because someone ran xcode-select.
     *
     * MacOSX.sdk is a symlink to the newest installed SDK rather than a fixed version. It is used here
     * because pinning a version in the spec would make the repository un-buildable on any machine that
     * happens to have a different one installed, which is a worse failure than tracking the default.
     */
    function resolveSdk() : Directory {
        const commandLineTools = d`/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk`;
        if (Directory.exists(commandLineTools)) {
            return commandLineTools;
        }

        const xcode = d`/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk`;
        if (Directory.exists(xcode)) {
            return xcode;
        }

        Contract.fail(
            `No macOS SDK found. Looked in /Library/Developer/CommandLineTools/SDKs and ` +
            `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs. ` +
            `Install the Command Line Tools with 'xcode-select --install'.`);
        return undefined;
    }

    @@public
    export const sdkRoot : Directory = Context.getCurrentHost().os === "macOS" ? resolveSdk() : undefined;

    /**
     * Scopes clang reads or probes that are not build inputs.
     *
     * The toolchain and the SDK are pinned by the tool definition, so their content is what determines
     * the output and tracking it again by path would only make the fingerprint depend on files that
     * cannot change without the tool changing. /System is the sealed system volume: read only and
     * verified by the OS, so nothing a build does can alter it.
     */
    @@public
    export const toolchainScopes : Directory[] = [
        d`/Library/Developer`,
        d`/Applications/Xcode.app`,
        d`/System`,
        d`/usr/local`
    ];

    /**
     * Directories clang probes for a toolchain and does not find one in.
     *
     * It looks for cross-prefixed tools - arm64-apple-darwin27.0.0-ld, arm64-apple-darwin27.0.0-dsymutil -
     * next to itself, then in /usr/local, /usr and /, before falling back to the linker beside it. Each
     * miss is a real probe and the sandbox reports every one; they are listed as untracked *directories*
     * rather than scopes so that only the probe of the directory itself is untracked and anything read
     * beneath them still is.
     */
    @@public
    export const toolchainProbedDirectories : Directory[] = [
        d`/`,
        d`/usr`,
        d`/usr/local`
    ];

    @@public
    export const clang : File = Context.getCurrentHost().os === "macOS" ? resolve("clang") : undefined;

    @@public
    export const clangxx : File = Context.getCurrentHost().os === "macOS" ? resolve("clang++") : undefined;
}
