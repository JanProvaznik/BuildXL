#!/bin/bash

set -e

MY_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$MY_DIR/Public/Src/App/Bxl/Unix/env.sh"

# Log the final exit code of this script whenever it exits. This helps diagnose cases where the
# surrounding shell/pipeline reports a non-zero exit code (e.g. 139 == 128 + SIGSEGV) that does
# not originate from bxl itself: bxl's own exit code is logged separately in compileWithBxl, so
# comparing the two makes it clear whether the failure came from bxl or from some other process
# (bash itself, a post-build step, etc.). If this message is missing from the logs entirely, the
# shell process was most likely terminated by a signal before it could run this trap.
function logScriptExitCode {
    local scriptExitCode=$?
    print_info "${tputBold}bxl.sh exiting with code: ${scriptExitCode}${tputReset}"
    exit $scriptExitCode
}
trap logScriptExitCode EXIT

# Capture the distribution release number (e.g. 24.04). macOS has no /etc/*-release, and with
# 'set -e' an unguarded 'cat' of a glob that matches nothing would abort the script.
if compgen -G "/etc/*-release" > /dev/null; then
    DISTRIB_RELEASE=$(cat /etc/*-release | sed -n -e 's/^DISTRIB_RELEASE=//p')
else
    DISTRIB_RELEASE=""
fi

declare DEFAULT_CACHE_CONFIG_FILE_NAME=DefaultCacheConfig.json

declare arg_Positional=()
# stores user-specified args that are not used by this script; added to the end of command line
declare arg_UserProvidedBxlArguments=()
declare arg_DeployDev=""
declare arg_UseDev=""
declare arg_Minimal=""
declare arg_Internal=""
declare arg_Vs=""
# default configuration is debug
declare configuration="Debug"
declare credProviderPath=""
declare arg_CacheConfigFile=""
declare arg_Runner=()
declare arg_useAdoBuildRunner=""
declare arg_UsePublicDepsOnlyFeed=""
declare needsFeedAuth=""

declare g_bxlCmdArgs=()
declare g_adoBuildRunnerCmdArgs=()

if [[ "${OSTYPE}" == "linux-gnu" ]]; then
    readonly HostQualifier=Linux
    readonly DeploymentFolder=linux-x64
    readonly HostIsMacOs=""
elif [[ "${OSTYPE}" == darwin* ]]; then
    # Build for the architecture we are actually running on. There is no Rosetta 2 fallback here on
    # purpose: silently producing x86_64 binaries on an Apple Silicon machine is how macOS support
    # ended up depending on an emulation layer that is not present on every Mac.
    hostArch=$(uname -m)
    if [[ "$hostArch" == "arm64" ]]; then
        readonly HostQualifier=DotNetCoreMacArm64
        readonly DeploymentFolder=osx-arm64
    elif [[ "$hostArch" == "x86_64" ]]; then
        readonly HostQualifier=DotNetCoreMac
        readonly DeploymentFolder=osx-x64
    else
        print_error "Unsupported macOS architecture: ${hostArch}"
        exit 1
    fi
    readonly HostIsMacOs="1"
else
    print_error "Operating system not supported: ${OSTYPE}"
    exit 1
fi

function printHelp() {
    echo "${BASH_SOURCE[0]} [--deploy-dev] [--use-dev] [--minimal] [--internal] [--use-public-deps-only-feed] [--release] [--shared-comp] [--vs] [--use-adobuildrunner] [--runner-arg <arg-to-buildrunner>] [--test-method <full-test-method-name>] [--test-class <full-test-class-name>] <other-arguments>"
}

function parseArgs() {
    arg_Positional=()
    arg_UserProvidedBxlArguments=()
    while [[ $# -gt 0 ]]; do
        cmd="$1"
        case $cmd in
        --help | -h)
            printHelp
            shift
            return 1
            ;;
        --deploy-dev)
            arg_DeployDev="1"
            shift
            ;;
        --use-dev)
            arg_UseDev="1"
            shift
            ;;
        --minimal)
            arg_Minimal="1"
            shift
            ;;
        --release)
            configuration="Release"
            shift
            ;;
        --internal)
            arg_Internal="1"
            shift
            ;;
        --use-public-deps-only-feed)
            # External build that consumes the BuildXL.Internal.PublicDepsOnly feed (which upstreams only
            # publicly available packages) instead of public registries. CODESYNC: config.dsc
            arg_UsePublicDepsOnlyFeed="1"
            arg_Positional+=("/p:[Sdk.BuildXL]usePublicDepsOnlyFeed=1")
            shift
            ;;
        --test-class)
            arg_Positional+=("/p:[UnitTest]Filter.testClass=$2")
            shift
            shift
            ;;
        --test-method)
            arg_Positional+=("/p:[UnitTest]Filter.testMethod=$2")
            shift
            shift
            ;;
        --shared-comp)
            arg_Positional+=("/p:[Sdk.BuildXL]useManagedSharedCompilation=1")
            shift
            ;;
        --vs)
            arg_Positional+=(
                "/vs"
                "/vsNew"
                "/vsTargetFramework:net8.0"
                "/vsTargetFramework:net9.0"
                "/vsTargetFramework:netstandard2.0"
                "/vsTargetFramework:netstandard2.1")
            arg_Vs="1"
            shift
            ;;
        --disable-xunitretry)
            arg_DisableXunitRetry="1"
            shift
            ;;
        --cache-config-file)
            arg_CacheConfigFile="$2"
            shift
            shift
            ;;
        --use-adobuildrunner)
            arg_useAdoBuildRunner="1"
            shift
            ;;
        --runner-arg)
            arg_Runner+=("$2")
            shift
            shift
            ;;
        *)
            # "Script" flags (and the settings associated with them) might conflict with BuildXL arguments set by a user.
            # In such a case, user-provided bxl arguments will override any arguments set by this script.
            arg_UserProvidedBxlArguments+=("$1")
            shift
            ;;
        esac
    done
}

function installLkg() {
    local feed="$1"
    local lkgName="$2"
    local lkgVersion="$3"

    # Prepare temporary directory
    # We'll leave these files on disk since they're in the out directory and can be inspected in case restore fails for some reason.
    local outDir="$MY_DIR/Out/BootStrap/cs"
    local nugetConfigFile="$outDir/nuget.config"
    local csprojFile="$outDir/bootstrap.csproj"
    mkdir -p "$outDir"

    # Clean up existing bootstrap files if still on disk
    rm -f "$nugetConfig"
    rm -f "$csprojFile"

    # Write files required for dotnet restore to run
    local nugetConfig="<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>
<configuration>
    <packageSources>
        <clear />
        <add key=\"BuildXL\" value=\"$feed\" />
    </packageSources>
</configuration>"

    local csproj="<Project Sdk=\"Microsoft.NET.Sdk\">
    <PropertyGroup>
        <OutputType>Exe</OutputType>
        <TargetFramework>net9.0</TargetFramework>
        <ImplicitUsings>enable</ImplicitUsings>
    </PropertyGroup>
    <ItemGroup>
        <PackageReference Include=\"$lkgName\" Version=\"$lkgVersion\" />
    </ItemGroup>
</Project>"

    echo "$nugetConfig" > "$nugetConfigFile"
    echo "$csproj" > "$csprojFile"

    # Run dotnet install to download the BuildXL package to the nuget cache
    dotnet restore --interactive --configfile "$nugetConfigFile" "$csprojFile"
}

function getLkg() {
    local LKG_FILE="BuildXLLkgVersionPublic.cmd"

    if [[ -n "$arg_Internal" ]]; then
        local LKG_FILE="BuildXLLkgVersion.cmd"
    fi

    local BUILDXL_LKG_VERSION=$(grep "BUILDXL_LKG_VERSION" "$MY_DIR/Shared/Scripts/$LKG_FILE" | cut -d= -f2 | tr -d '\r')
    local BUILDXL_LKG_NAME=$(grep "BUILDXL_LKG_NAME" "$MY_DIR/Shared/Scripts/$LKG_FILE" | cut -d= -f2 | perl -pe 's/(net472|win-x64)/'${DeploymentFolder}'/g' | tr -d '\r')
    local BUILDXL_LKG_FEED_1=$(grep "BUILDXL_LKG_FEED_1" "$MY_DIR/Shared/Scripts/$LKG_FILE" | cut -d= -f2 | tr -d '\r')

    print_info "Nuget Feed: $BUILDXL_LKG_FEED_1"
    print_info "Getting package: $BUILDXL_LKG_NAME.$BUILDXL_LKG_VERSION"

    local _BUILDXL_BOOTSTRAP_OUT="$MY_DIR/Out/BootStrap"
    mkdir -p "$_BUILDXL_BOOTSTRAP_OUT"
    export BUILDXL_BIN="$_BUILDXL_BOOTSTRAP_OUT/$BUILDXL_LKG_NAME.$BUILDXL_LKG_VERSION"
    # Set the DOTNET_NOLOGO environment variable to prevent the dotnet CLI from printing the first run logo which can interfere with parsing the output
    # Some commands accept this as an argument, but dotnet nuget locals does not
    export DOTNET_NOLOGO=true

    if [[ ! -d "$BUILDXL_BIN" ]]; then
        # Check if a cached version of the LKG is available
        local nugetPackageRoot=$(dotnet nuget locals global-packages -l | cut -d: -f2 | tr -d ' ')
        local cachePath="$nugetPackageRoot/$(echo $BUILDXL_LKG_NAME/$BUILDXL_LKG_VERSION | tr '[:upper:]' '[:lower:]')"
        if [[ ! -d "$cachePath" ]]; then
            installLkg "$BUILDXL_LKG_FEED_1" "$BUILDXL_LKG_NAME" "$BUILDXL_LKG_VERSION"
        fi
        # Copy the LKG to the local bootstrap directory
        cp -R "$cachePath" "$BUILDXL_BIN"
    fi
    print_info "LKG installed in $BUILDXL_BIN"
}

function setMinimal() {
    arg_Positional+=("/q:${configuration}${HostQualifier} /f:output='$MY_DIR/Out/Bin/${outputConfiguration}/${DeploymentFolder}/*'")
}

function setInternal() {
    arg_Positional+=("/p:[Sdk.BuildXL]microsoftInternal=1")
    arg_Positional+=("/remoteTelemetry+")
    arg_Positional+=("/generateCgManifestForNugets:cg/nuget/cgmanifest.json")
    arg_Positional+=("/p:[Sdk.BuildXL]useQTest=true")

    for arg in "$@"
    do
        to_lower=`printf '%s\n' "$arg" | awk '{ print tolower($0) }'`
        if [[ " $to_lower " == *"endpointsecurity"* ]]; then
            return
        fi
    done
}

# Clears and then populates the 'g_bxlArgs' array with arguments to be passed to 'bxl'.
# The arguments are decided based on sensible defaults as well as the current values of the 'arg_*' variables.
function setBxlCmdArgs {
    # Look this up before building the array. Under 'set -e' a failing command substitution inside an
    # assignment aborts the script immediately, so a missing dotnet used to end the run with no
    # diagnostic whatsoever - just the exit code.
    local dotnetLocation="$(which dotnet || true)"
    if [[ -z $dotnetLocation ]]; then
        print_error "Did not find dotnet on your PATH. Install it per https://learn.microsoft.com/dotnet/core/install/ and make sure 'dotnet' is on PATH."
        exit 1
    fi

    g_bxlCmdArgs=(
        # some environment variables
        "/p:DOTNET_EXE=$dotnetLocation"
        # user-specified config files
        "/c:$MY_DIR/config.dsc"
    )

    if [[ "${OSTYPE}" == "linux-gnu" ]]; then
        g_bxlCmdArgs+=(
            /enableEvaluationThrottling
            # setting up core dump creation failed
            /noWarn:460
        )
    fi

    # If we are not using the ado build runner, inject a default cache. Otherwise, we are using
    # the cache config autogen functionality of the runner, so let that kick in
    if [[ -z "$arg_useAdoBuildRunner" ]]; then
        if [[ -z $arg_CacheConfigFile ]]; then
            arg_CacheConfigFile="$BUILDXL_BIN/$DEFAULT_CACHE_CONFIG_FILE_NAME"
        fi

        g_bxlCmdArgs+=(
            "/cacheMiss+"
            "/cacheConfigFilePath:$arg_CacheConfigFile"
        )
    else
        g_adoBuildRunnerCmdArgs+=(
            "${arg_Runner[@]}"
        )
    fi

    # Set kernel version
    MAJOR_KERNEL_VERSION=$(uname -r | cut -d'.' -f1)
    MINOR_KERNEL_VERSION=$(uname -r | cut -d'.' -f2)
    g_bxlCmdArgs+=(
        "/p:MAJOR_KERNEL_VERSION=$MAJOR_KERNEL_VERSION"
        "/p:MINOR_KERNEL_VERSION=$MINOR_KERNEL_VERSION"
    )

    # all other user-specified args
    g_bxlCmdArgs+=(
       "$@"
    )

    # We want tests that spawn their own sandbox to follow the same sandbox configuration as the main bxl process.
    # The ebpf sandbox is enabled by default. So check whether it is explicitly disabled (/EnableLinuxEBPFSandbox- (case-insensitive)).
    # Set the EnableLinuxEBPFSandboxForTests property accordingly on the bxl command line so tests will honor the sandbox mode.
    # TODO: this is temporary until we can retire interpose
    if [[ -z "$HostIsMacOs" ]]; then
        last_match=$(echo "${g_bxlCmdArgs[@]}" | grep -io '/EnableLinuxEBPFSandbox[+-]\{0,1\}' | tail -1)
        if [[ -n "$last_match" && "$last_match" =~ - ]]; then
            # CODESYNC: Public/Sdk/Public/Managed/Testing/XUnit/xunit.dsc
            g_bxlCmdArgs+=("/p:EnableLinuxEBPFSandboxForTests=0")
        else
            g_bxlCmdArgs+=("/p:EnableLinuxEBPFSandboxForTests=1")
        fi
    fi
}

function validateBxlExecutablesOnDisk() {
    local bxlFilesToCheck="bxl bxl.runtimeconfig.json bxl.deps.json"
    for f in $bxlFilesToCheck; do
        if [[ ! -f $BUILDXL_BIN/$f ]]; then
            print_error "Expected to find file '$f' in '$BUILDXL_BIN' but that file is not present"
            exit -1
        fi
    done
}

function setExecutablePermissions() {
    # On some usages of this script, execution bits might be
    # missing from the deployment. This is the case, for example, on ADO
    # builds where the engine is deployed by downloading pipeline artifacts.
    # Make sure that the executables that we need in the build are indeed executable.
    chmod u+rx "$BUILDXL_BIN/bxl"
    chmod u+rx "$BUILDXL_BIN/NugetDownloader"
    chmod u+rx "$BUILDXL_BIN/Downloader"
    chmod u+rx "$BUILDXL_BIN/Extractor"

    if [[ -n "$HostIsMacOs" ]]; then
        # Files that arrive via a downloaded package carry com.apple.quarantine, and Gatekeeper refuses
        # to execute them. This is a no-op when the attribute is absent, so it is safe to always run.
        xattr -d -r com.apple.quarantine "$BUILDXL_BIN" 2>/dev/null || true

        adHocSignMachOExecutables
    fi
}

function adHocSignMachOExecutables() {
    # Every executable in a BuildXL deployment is produced by AppHostPatcher, which writes the name of
    # the managed assembly into a copy of the .NET apphost by patching its bytes in place. The apphost
    # arrives from the Microsoft.NETCore.App.Host.<rid> package already ad-hoc signed, and patching it
    # invalidates that signature while leaving the signature blob itself in place.
    #
    # On x86_64 macOS an invalid signature is tolerated, which is why this never surfaced while osx-x64
    # was the only macOS target. On arm64 macOS it is fatal: the kernel refuses to map any binary whose
    # signature does not verify and SIGKILLs it at exec. There is no diagnostic of any kind -- the shell
    # reports "Killed: 9" (exit code 137) with nothing at all on stdout or stderr.
    #
    # Signing ad-hoc ("--sign -") requires no signing identity and no Apple developer account.
    #
    # This is repaired here, on the machine about to run the engine, rather than in the build that
    # produced the deployment, because a macOS deployment can be cross-built on Linux or Windows where
    # codesign does not exist. This is the first machine guaranteed to have it.
    if ! command -v codesign > /dev/null 2>&1; then
        return 0
    fi

    # Signing is only ever needed once per deployment, so if the main executable already verifies there
    # is nothing to do. This keeps the common case to a single codesign call rather than a sweep.
    if codesign --verify "$BUILDXL_BIN/bxl" > /dev/null 2>&1; then
        return 0
    fi

    print_info "Ad-hoc signing Mach-O executables in '$BUILDXL_BIN'"

    local signedCount=0
    local failedCount=0
    local f
    while IFS= read -r -d '' f; do
        case "$f" in
            # Managed assemblies and data files make up the overwhelming majority of a deployment and
            # are never Mach-O. Skipping them by name keeps this sweep near a second rather than a minute.
            *.dll|*.pdb|*.json|*.js|*.ts|*.map|*.xml|*.txt|*.md|*.config|*.cs|*.dsc|*.h) continue;;
        esac

        # Anything whose signature already verifies is left strictly alone. The native libraries that
        # come straight out of the runtime packs are signed by Microsoft and are not ours to re-sign.
        if codesign --verify "$f" > /dev/null 2>&1; then
            continue
        fi

        if [[ "$(file -b "$f" 2> /dev/null)" != Mach-O* ]]; then
            continue
        fi

        if codesign --force --sign - "$f" > /dev/null 2>&1; then
            signedCount=$((signedCount + 1))
        else
            print_error "Failed to ad-hoc sign '$f'"
            failedCount=$((failedCount + 1))
        fi
    done < <(find "$BUILDXL_BIN" -type f -print0)

    if [[ $failedCount -gt 0 ]]; then
        print_error "Could not ad-hoc sign $failedCount executable(s) in '$BUILDXL_BIN'. On arm64 macOS these are killed on launch."
        exit 1
    fi

    print_info "Ad-hoc signed $signedCount executable(s)"
}

function compileWithBxl() {
    validateBxlExecutablesOnDisk

    local args=(
        /logsToRetain:20
        # Ignore accesses related to a VSCode tunnel
        /unsafe_GlobalUntrackedScopes:$HOME/.vscode-server
        /unsafe_GlobalUntrackedScopes:$HOME/.vscode-server-insiders
    )

    # Pass through feed credentials for builds that authenticate against an internal Azure DevOps feed:
    # internal builds, and external builds consuming the BuildXL.Internal.PublicDepsOnly feed (--use-public-deps-only-feed).
    if [[ -n "$needsFeedAuth" ]]; then
        args+=("/unsafe_GlobalPassthroughEnvVars:NUGET_CREDENTIALPROVIDERS_PATH;VSS_NUGET_EXTERNAL_FEED_ENDPOINTS")
        # Credential provider mutex for non-Windows concurrency control
        args+=("/unsafe_GlobalUntrackedScopes:/tmp/.dotnet/shm")
    fi

    args+=("$@")

    setBxlCmdArgs "${args[@]}"

    setExecutablePermissions

    local bxlProcessName
    local bxlExitCode

    if [[ -n "$arg_useAdoBuildRunner" ]]; then
        local adoBuildRunnerExe="$BUILDXL_BIN/AdoBuildRunner"
        chmod u=rx "$adoBuildRunnerExe" || true
        bxlProcessName="AdoBuildRunner"
        print_info "${tputBold}Running AdoBuildRunner:${tputReset} '$adoBuildRunnerExe' ${g_adoBuildRunnerCmdArgs[@]} -- ${g_bxlCmdArgs[@]}"
        # Temporarily disable 'set -e' around the invocation so we can capture and log the exact
        # exit code (including termination-by-signal codes like 139 == 128 + SIGSEGV) instead of
        # letting the script abort before we get a chance to report it.
        set +e
        "$adoBuildRunnerExe" "${g_adoBuildRunnerCmdArgs[@]}" "--" "${g_bxlCmdArgs[@]}"
        bxlExitCode=$?
        set -e
    else
        bxlProcessName="bxl"
        print_info "${tputBold}Running bxl:${tputReset} '$BUILDXL_BIN/bxl' ${g_bxlCmdArgs[@]}"

        set +e
        "$BUILDXL_BIN/bxl" "${g_bxlCmdArgs[@]}"
        bxlExitCode=$?
        set -e
    fi

    # Explicitly log the exit code of the process we invoked. This makes it possible to determine,
    # when the surrounding shell/pipeline reports a failure (e.g. exit code 139), whether the
    # non-zero code originated from bxl (or the AdoBuildRunner) or from some other process such as
    # bash itself or a post-build step.
    print_info "${tputBold}${bxlProcessName} process exited with code: ${bxlExitCode}${tputReset}"

    if [[ $bxlExitCode == 0 ]]; then
        echo "${tputBold}${tputGreen}BuildXL Succeeded${tputReset}"
    else
        echo "${tputBold}${tputRed}BuildXL Failed${tputReset}"
    fi

    return $bxlExitCode
}

function deployBxl { # (fromDir, toDir)
    local fromDir="$1"
    local toDir="$2"

    mkdir -p "$toDir"
    /usr/bin/rsync -arhq "$fromDir/" "$toDir" --delete
    print_info "Successfully deployed developer build from $fromDir to: $toDir; use it with the '--use-dev' flag now."
}

function installCredProvider() {

    local dotnetLocation="$(which dotnet)"

    if [[ -z $dotnetLocation ]]; then
        print_error "Did not find dotnet. Please ensure dotnet is installed per: https://docs.microsoft.com/en-us/dotnet/core/install/linux and is accessable in your PATH"
        return 1
    fi

    local destinationFolder="$HOME/.nuget"
    local credentialProvider="$destinationFolder/plugins/netcore/CredentialProvider.Microsoft/"
    local credentialProviderExe="$credentialProvider/CredentialProvider.Microsoft.exe"

    export NUGET_CREDENTIALPROVIDERS_PATH="$credentialProvider"
    
    # If not on ADO, do not install the cred provider if it is already installed.
    # On ADO, just make sure we have the right thing, the download time is not significant for a lab build
    if [[ (! -n "$ADOBuild") && -f "$credentialProviderExe" ]];
    then
        print_info "Credential provider already installed under $destinationFolder"
        return;
    fi

    # Download the artifacts credential provider
    mkdir -p "$destinationFolder"
    wget -q -c https://github.com/microsoft/artifacts-credprovider/releases/download/v1.0.0/Microsoft.NuGet.CredentialProvider.tar.gz -O - | tar -xz -C "$destinationFolder"

    # Remove the .exe, since we want to replace it with a script that runs on Linux
    rm "$credentialProviderExe"

    # Create a new .exe with the shape of a script that calls dotnet against the dotnetcore dll
    echo "#!/bin/bash" >  "$credentialProviderExe"
    echo "exec $dotnetLocation $credentialProvider/CredentialProvider.Microsoft.dll \"\$@\"" >> "$credentialProviderExe"

    chmod u+x "$credentialProviderExe"
}

function launchCredProvider() {
    credProviderPath=$(find "$NUGET_CREDENTIALPROVIDERS_PATH" -name "CredentialProvider*.exe" -type f | head -n 1)

    if [[ -z $credProviderPath ]]; then
        print_error "Did not find a credential provider under $NUGET_CREDENTIALPROVIDERS_PATH"
        exit 1
    fi

    # CODESYNC: config.dsc. The URI needs to match the (single) feed used for the internal build
    $credProviderPath -U https://pkgs.dev.azure.com/cloudbuild/_packaging/BuildXL.Selfhost/nuget/v3/index.json -V Information -C -R
}

function setAuthenticationTokenInNpmrc() {
    # This function is responsible for setting the PAT generated for our internal selfhost feed to be used by npm
    # first parse the local npmrc to see if there already exists a valid PAT
    if ! [ -f "$HOME/.npmrc" ]; then
        # npmrc doesn't exist, lets create one one now
        touch "$HOME/.npmrc"
    else
        # delete any existing lines in the npmrc that might contain a stale token
        # existing token may be valid, but we don't need to check that here because the credential provider has already generated/cached one
        # we can just replace the existing one and save the trouble of having to verify whether it is valid by making a web request
        mv "$HOME/.npmrc" "$HOME/.npmrc.bak"
        touch "$HOME/.npmrc"

        while read line; do
            if [[ "$line" == *"//cloudbuild.pkgs.visualstudio.com/_packaging/BuildXL.Selfhost/npm/registry"* ]]; then
                continue
            fi

            echo "$line" >> "$HOME/.npmrc"
        done < "$HOME/.npmrc.bak"

        rm "$HOME/.npmrc.bak"
    fi

    # get a cached token from credential provider (it should already be cached from when we called it earlier for nuget)
    # we use the nuget uri here, but all this does is return a token with vso_packaging which is what we need for npm
    credProviderOutput=$($credProviderPath -U https://pkgs.dev.azure.com/cloudbuild/_packaging/BuildXL.Selfhost/nuget/v3/index.json -C -F Json)

    # output is in the format '{"Username":"VssSessionToken","Password":"token"}'
    token=$(echo $credProviderOutput | sed -E -e 's/.*\{"Username":"[a-zA-Z0-9]*","Password":"([a-zA-Z0-9]*)"\}.*/\1/')
    b64token=$(echo -ne "$token" | base64 -w 0)

    # write new token to file
    echo "" >> "$HOME/.npmrc"
    echo "//cloudbuild.pkgs.visualstudio.com/_packaging/BuildXL.Selfhost/npm/registry/:username=VssSessionToken" >> "$HOME/.npmrc"
    echo "//cloudbuild.pkgs.visualstudio.com/_packaging/BuildXL.Selfhost/npm/registry/:_password=$b64token" >> "$HOME/.npmrc"
    echo "//cloudbuild.pkgs.visualstudio.com/_packaging/BuildXL.Selfhost/npm/registry/:email=not-used@example.com" >> "$HOME/.npmrc"
}

# allow this script to be sourced, in which case we shouldn't execute anything
if [[ "$0" != "${BASH_SOURCE[0]}" ]]; then 
    return 0
fi

# Make sure we are running in our own working directory
pushd "$MY_DIR"

parseArgs "$@"

outputConfiguration=`printf '%s' "$configuration" | awk '{ print tolower($0) }'`

if [[ -n "$arg_Internal" || -n "$arg_UsePublicDepsOnlyFeed" ]]; then
    # Both internal builds and external builds that consume the BuildXL.Internal.PublicDepsOnly feed
    # restore packages from authenticated Azure DevOps feeds, so they need the NuGet credential provider.
    needsFeedAuth="1"
fi

if [[ -n "$needsFeedAuth" && -n "$TF_BUILD" ]]; then
    readonly ADOBuild="1"
fi

if [[ -n "$arg_DeployDev" || -n "$arg_Minimal" ]]; then
    setMinimal
fi

if [[ -n "$arg_Internal" ]]; then
    setInternal $@
fi

# If the nuget credential provider is not configured, download and install the artifacts credential provider.
# This is needed for builds that authenticate against an internal feed: internal builds, and external builds
# that consume the BuildXL.Internal.PublicDepsOnly feed (--use-public-deps-only-feed).
if [[ -n "$needsFeedAuth" ]] && [[ ! -d "${NUGET_CREDENTIALPROVIDERS_PATH:-}" ]]; then
    installCredProvider
fi

# The internal build needs authentication. When not running on ADO use the configured cred provider
# to prompt for credentials as a way to guarantee the auth token will be cached for the subsequent build.
# This may prompt an interactive pop-up/console. ADO pipelines already configure the corresponding env vars 
# so there is no need to do this on that case. Once the token is cached, launching the provider shouldn't need
# any user interaction.
# For npm authentication, we write the PAT to the npmrc file under $HOME/.npmrc.
# On ADO builds, the CLOUDBUILD_BUILDXL_SELFHOST_FEED_PAT_B64 variable is set instead.
# TF_BUILD is an environment variable that is always present on ADO builds. So we use it to detect that case.
if [[ -n "$arg_Internal" &&  ! -n "$TF_BUILD" ]];then
    launchCredProvider
    setAuthenticationTokenInNpmrc
fi

# Make sure we pass the credential provider as an env var to bxl invocation
if [[ -n $NUGET_CREDENTIALPROVIDERS_PATH ]];then
    arg_Positional+=("/p:NUGET_CREDENTIALPROVIDERS_PATH=$NUGET_CREDENTIALPROVIDERS_PATH")
fi

# If this is an internal build running on ADO, the nuget authentication is non-interactive and therefore we need to setup
# VSS_NUGET_EXTERNAL_FEED_ENDPOINTS if not configured, so the Microsoft credential provider can pick that up. The script assumes the corresponding
# secrets to be exposed in the environment
if [[ -n "$arg_Internal" && -n "$ADOBuild" && (! -n $VSS_NUGET_EXTERNAL_FEED_ENDPOINTS)]];then

    if [[ (! -n $PAT1esSharedAssets) ]]; then
        print_error "Environment variable PAT1esSharedAssets is not set."
        exit 1
    fi

    if [[ (! -n $PATCloudBuild) ]]; then
        print_error "Environment variable PATCloudBuild is not set."
        exit 1
    fi

    export VSS_NUGET_EXTERNAL_FEED_ENDPOINTS="{\"endpointCredentials\":[{\"endpoint\":\"https://pkgs.dev.azure.com/1essharedassets/_packaging/BuildXL/nuget/v3/index.json\",\"password\":\"$PAT1esSharedAssets\"},{\"endpoint\":\"https://pkgs.dev.azure.com/cloudbuild/_packaging/BuildXL.Selfhost/nuget/v3/index.json\",\"password\":\"$PATCloudBuild\"},{\"endpoint\":\"https://cloudbuild.pkgs.visualstudio.com/_packaging/BuildXL.Selfhost/npm/registry/yarn/-/yarn-1.22.19.tgz\",\"password\":\"$PATCloudBuild\"}]}" 
    export CLOUDBUILD_BUILDXL_SELFHOST_FEED_PAT_B64=$(echo -ne "$PATCloudBuild" | base64)
fi

# For local builds we want to use the in-build Linux runtime (as opposed to the runtime.linux-x64.BuildXL package)
if [[ -z "$TF_BUILD" && -z "$HostIsMacOs" ]];then
    arg_Positional+=("/p:[Sdk.BuildXL]validateLinuxRuntime=0")
fi

# Indicates that XUnit tests should be retried due to flakiness with certain tests 
if [[ ! -n "$arg_DisableXunitRetry" ]]; then
    # RetryXunitTests will specify a retry exit code of 1 for all xunit pips, and NumXunitRetries will specify the number of times to retry the xunit pip
    arg_Positional+=("/p:RetryXunitTests=1")
    arg_Positional+=("/p:NumXunitRetries=2")
fi

if [[ -n "$arg_UseDev" ]]; then
    if [[ ! -f $MY_DIR/Out/Selfhost/Dev/bxl ]]; then
        print_error "Error: Could not find the dev deployment. Make sure you build with --deploy-dev first."
        exit 1
    fi

    export BUILDXL_BIN=$MY_DIR/Out/Selfhost/Dev
elif [[ -z "$BUILDXL_BIN" ]]; then
    getLkg
fi

compileWithBxl ${arg_Positional[@]} ${arg_UserProvidedBxlArguments[@]}

if [[ -n "$arg_DeployDev" ]]; then
    deployBxl "$MY_DIR/Out/Bin/${outputConfiguration}/${DeploymentFolder}" "$MY_DIR/Out/Selfhost/Dev"
fi

popd
