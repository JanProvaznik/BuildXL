#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# pack-grpc-arm64-package.sh - wrap native arm64 protoc/grpc_csharp_plugin in a Grpc.Tools package.
#
# build-grpc-arm64-tools.sh produces the two binaries. This turns them into a NuGet package that
# BuildXL can consume, which is the whole remaining step: the SDK already asks the Grpc.Tools
# package which tool folders it carries and prefers `tools/macosx_arm64` when it finds one (see
# Public/Sdk/Public/Protocols/Grpc/protoc.dsc), so a package with that folder removes the Rosetta
# requirement with no code change anywhere.
#
#   ./pack-grpc-arm64-package.sh --tools <dir> --work <build-grpc-arm64-tools work dir> [--version V]
#
# The package deliberately carries only what the SDK reads:
#
#   tools/macosx_arm64/protoc                 the code generator
#   tools/macosx_arm64/grpc_csharp_plugin     the C# service-stub generator
#   build/native/include/google/protobuf/*    the well-known types, used as a --proto_path
#
# It does not carry the other platforms' tools. That is a deliberate limitation and the reason the
# version is distinct: this package is only correct on an arm64 Mac, so it must never be mistaken
# for the real Grpc.Tools. Publish it to a local feed and pin it there, rather than substituting it
# for the upstream package.
#
# Exit codes: 0 packed, 1 a prerequisite is missing.

set -uo pipefail

TOOLS_DIR=""
WORK_DIR="${TMPDIR:-/tmp}/bxl-grpc-arm64"
VERSION=""
OUT_DIR="$PWD"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tools)   TOOLS_DIR="$2"; shift 2 ;;
        --work)    WORK_DIR="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --out)     OUT_DIR="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m    %s\n' "$*"; }
bad()  { printf '  \033[31mno\033[0m    %s\n' "$*"; }

[[ -n "$TOOLS_DIR" ]] || { bad "--tools is required (the output of build-grpc-arm64-tools.sh)"; exit 1; }
for tool in protoc grpc_csharp_plugin; do
    [[ -x "$TOOLS_DIR/$tool" ]] || { bad "missing or not executable: $TOOLS_DIR/$tool"; exit 1; }
    arch="$(file -b "$TOOLS_DIR/$tool" | grep -o 'arm64\|x86_64')"
    [[ "$arch" == "arm64" ]] || { bad "$tool is $arch, not arm64 - packaging it would defeat the point"; exit 1; }
done
ok "protoc and grpc_csharp_plugin are both arm64"

# The well-known types have to come from the same protobuf the tools were built from. Taking them
# from a different protobuf would be a silent version skew: protoc validates imports against these
# files, so a mismatch shows up as a compile error in generated code rather than as a bad package.
WKT_SRC="$(find "$WORK_DIR" -type d -path "*protobuf/src/google/protobuf" 2>/dev/null | head -1)"
[[ -d "$WKT_SRC" ]] || { bad "could not find the protobuf sources under $WORK_DIR; pass --work"; exit 1; }
ok "well-known types from $(echo "$WKT_SRC" | sed "s|$WORK_DIR/||")"

if [[ -z "$VERSION" ]]; then
    # Encode the protoc version so the package cannot be confused with an upstream one, and so the
    # pin in config.nuget.grpc.dsc says out loud what it is.
    VERSION="$("$TOOLS_DIR/protoc" --version | awk '{print $2}')-macosarm64"
fi
ok "version $VERSION"

STAGE="$WORK_DIR/package-stage"
rm -rf "$STAGE"
mkdir -p "$STAGE/tools/macosx_arm64" "$STAGE/build/native/include/google/protobuf/compiler"

cp "$TOOLS_DIR/protoc" "$TOOLS_DIR/grpc_csharp_plugin" "$STAGE/tools/macosx_arm64/"
chmod +x "$STAGE/tools/macosx_arm64/"*

find "$WKT_SRC" -maxdepth 1 -name "*.proto" -exec cp {} "$STAGE/build/native/include/google/protobuf/" \;
[[ -f "$WKT_SRC/compiler/plugin.proto" ]] && cp "$WKT_SRC/compiler/plugin.proto" "$STAGE/build/native/include/google/protobuf/compiler/"
ok "$(find "$STAGE/build/native/include" -name "*.proto" | wc -l | tr -d ' ') well-known .proto files"

cat > "$STAGE/Grpc.Tools.nuspec" <<NUSPEC
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Grpc.Tools</id>
    <version>$VERSION</version>
    <authors>The gRPC Authors</authors>
    <description>gRPC and Protocol Buffer compiler for managed C# projects, built natively for macOS arm64. Locally built because upstream Grpc.Tools ships macosx_x64 only, which forces protobuf codegen through Rosetta 2 on Apple silicon. Carries macosx_arm64 only.</description>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
  </metadata>
</package>
NUSPEC

mkdir -p "$OUT_DIR"
NUPKG="$OUT_DIR/grpc.tools.$(echo "$VERSION" | tr '[:upper:]' '[:lower:]').nupkg"
rm -f "$NUPKG"
( cd "$STAGE" && zip -q -r -X "$NUPKG" . ) || { bad "could not create the package"; exit 1; }

ok "packed $NUPKG ($(du -h "$NUPKG" | awk '{print $1}'))"
echo
bold "Next: publish to a local feed and pin it"
printf '        { id: "Grpc.Tools", version: "%s" },   in config.nuget.grpc.dsc\n' "$VERSION"
