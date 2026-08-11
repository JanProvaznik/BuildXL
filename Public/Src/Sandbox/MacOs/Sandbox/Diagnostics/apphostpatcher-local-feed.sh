#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#
# Builds the osx-arm64 AppHostPatcher that the published package omits, and serves it from a local
# NuGet feed so BuildXL can build itself on Apple silicon.
#
# WHY THIS EXISTS
# ---------------
# BuildXL.Tools.AppHostPatcher ships tools/win-x64, tools/linux-x64 and tools/osx-x64, but no
# tools/osx-arm64. The patcher runs on the *host*, so on an Apple silicon Mac the osx-x64 build
# cannot be used without Rosetta, and AppHostPatcher.dsc resolves tools/osx-arm64/AppHostPatcher
# directly. Every managed pip depends on it, so its absence stops the build outright - this is what
# "BuildXL cannot be built on osx-arm64" reduces to.
#
# The tool's own source is already in the repository, at
# Public/Sdk/Public/Managed/Tools/AppHostPatcher, so nothing has to be invented: it is rebuilt from
# source, packed into a package with the id and version config.dsc already asks for, and served from
# a feed on localhost. The real fix is for the publishing pipeline's osx-arm64 leg
# (.azdo/publish-app-host-patcher) to run; this makes the platform usable until then.
#
# The generated package also carries empty placeholders for the other three platforms' files.
# BuildXL's generated package spec enumerates every file the published package contains and fails
# the download pip if any is missing. The placeholders are never executed here - AppHostPatcher.dsc
# selects the host's platform - so only the osx-arm64 payload is real.
#
# USAGE
#     Diagnostics/apphostpatcher-local-feed.sh <feed-directory>
#
# Then add the feed to config.dsc's NuGet configuration, for example:
#     { name: "local", location: "http://127.0.0.1:8213/index.json" }
# and serve it with any NuGet v3 static feed server.
#

set -euo pipefail

readonly FEED_DIR="${1:?usage: $0 <feed-directory>}"
readonly PACKAGE_ID="BuildXL.Tools.AppHostPatcher"
readonly PACKAGE_VERSION="2.1.1"

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "$SCRIPT_DIR/../../../../../.." && pwd)"
readonly TOOL_SOURCE="$REPO_ROOT/Public/Sdk/Public/Managed/Tools/AppHostPatcher"

if [[ ! -f "$TOOL_SOURCE/AppHostPatcher.csproj" ]]; then
    echo "error: AppHostPatcher source not found at $TOOL_SOURCE" >&2
    exit 1
fi

readonly STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "==> building AppHostPatcher for osx-arm64"
dotnet publish "$TOOL_SOURCE/AppHostPatcher.csproj" \
    -r osx-arm64 -c Release -o "$STAGE/publish" --nologo --verbosity quiet

mkdir -p "$STAGE/pkg/tools/osx-arm64"
cp -R "$STAGE/publish/." "$STAGE/pkg/tools/osx-arm64/"
chmod +x "$STAGE/pkg/tools/osx-arm64/AppHostPatcher"

# The same __DATA_CONST relaxation every other CoreCLR on an AMFI-disabled machine needs. Harmless
# where AMFI is enabled, since the flag only matters when the kernel is not granting the exemption.
if [[ -x "$SCRIPT_DIR/relax-dataconst.py" ]]; then
    echo "==> relaxing __DATA_CONST (no-op unless this machine has AMFI disabled)"
    python3 "$SCRIPT_DIR/relax-dataconst.py" "$STAGE/pkg/tools/osx-arm64" || true
fi

# Editing the Mach-O invalidates the signature, and an invalid signature cannot be executed at all
# on Apple silicon.
codesign --force --sign - "$STAGE/pkg/tools/osx-arm64/AppHostPatcher" 2>/dev/null || true

echo "==> verifying the tool runs"
# Usage goes to stderr and the tool exits non-zero when given no arguments, so the output is
# captured first rather than piped: under `set -o pipefail` the tool's exit status would otherwise
# fail the pipeline no matter what grep found. Running it with no arguments is the cheapest proof
# that this host can actually execute the binary, which is the entire point of rebuilding it.
patcher_output="$("$STAGE/pkg/tools/osx-arm64/AppHostPatcher" 2>&1 || true)"
if [[ "$patcher_output" != *"Usage:"* ]]; then
    echo "error: the rebuilt AppHostPatcher does not run on this machine" >&2
    echo "$patcher_output" >&2
    exit 1
fi

# Placeholders for the platforms this machine cannot build, so the download pip's expected output
# list is satisfied. Names are mirrored from the osx-arm64 payload, which has the same shape.
echo "==> adding placeholders for the other platforms"
for platform in win-x64 linux-x64 osx-x64; do
    mkdir -p "$STAGE/pkg/tools/$platform"
    (cd "$STAGE/pkg/tools/osx-arm64" && find . -type f) | while read -r relative; do
        target="$STAGE/pkg/tools/$platform/${relative#./}"
        mkdir -p "$(dirname "$target")"
        : > "$target"
    done
done

cat > "$STAGE/pkg/$PACKAGE_ID.nuspec" <<NUSPEC
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>$PACKAGE_ID</id>
    <version>$PACKAGE_VERSION</version>
    <authors>Microsoft</authors>
    <owners>Microsoft</owners>
    <description>AppHostPatcher rebuilt from source to supply the osx-arm64 tool the published package omits.</description>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
  </metadata>
</package>
NUSPEC

mkdir -p "$FEED_DIR"
readonly OUTPUT="$FEED_DIR/$(echo "$PACKAGE_ID" | tr '[:upper:]' '[:lower:]').$PACKAGE_VERSION.nupkg"
rm -f "$OUTPUT"
(cd "$STAGE/pkg" && zip -qr "$OUTPUT" .)

echo "==> wrote $OUTPUT"
echo "    serve $FEED_DIR as a NuGet v3 source and add it to config.dsc"
