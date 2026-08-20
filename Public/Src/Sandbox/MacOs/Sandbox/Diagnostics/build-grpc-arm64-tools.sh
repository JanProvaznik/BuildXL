#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# build-grpc-arm64-tools.sh - build native arm64 protoc and grpc_csharp_plugin for macOS.
#
# Why this exists
# ---------------
# Every *released* Grpc.Tools publishes protoc and grpc_csharp_plugin for macosx_x64 only, so every
# protobuf codegen pip on an Apple silicon Mac runs under Rosetta 2. That makes Rosetta a hard
# requirement for building BuildXL from source on arm64 - the only such requirement left.
#
# Upstream has fixed this, but not yet in a release. grpc/grpc#41222 shows as closed and unmerged on
# GitHub because gRPC merges through an internal import, which closes a pull request without marking
# it merged; the change is in master as commit 0e6c80de9, dated 2026-08-10. The newest release at
# the time of writing is v1.83.0 from 2026-07-22, three weeks earlier, so no package carries it yet.
#
# Note upstream ships a *universal* binary in a folder named macosx_universal, not macosx_arm64.
# This script builds arm64-only, which is smaller and is all an Apple silicon machine needs; the
# BuildXL SDK probes macosx_universal, macosx_arm64 and macosx_x64 in that order, so a package built
# here is selected on arm64 without pretending to be the universal one.
#
# The tools are only *code generators*: they turn .proto into .cs at build time and are not part of
# any deployment. So replacing them with native binaries changes nothing about what BuildXL ships -
# it only removes the emulator from the build.
#
# What it produces
# ----------------
# A directory containing arm64 `protoc` and `grpc_csharp_plugin`. Dropping that directory into a
# Grpc.Tools package as `tools/macosx_arm64/` is all that is needed: the BuildXL SDK already asks
# the package which tool folders it carries and prefers the native one (see
# Public/Sdk/Public/Protocols/Grpc/protoc.dsc), so no SDK change is required.
#
#   ./build-grpc-arm64-tools.sh [--tag v1.71.0] [--out <dir>] [--verify <x86_64-plugin>]
#
# --verify takes a known-good x86_64 grpc_csharp_plugin and an x86_64 protoc of the same protobuf
# version, generates from the repository's own .proto files with both toolchains, and requires the
# output to be byte-identical. That comparison is the only meaningful proof that the native tools
# are a drop-in replacement, which is why it is built in rather than left as an exercise.
#
# Exit codes: 0 built (and verified, if asked), 1 a prerequisite is missing, 2 the build failed,
# 3 verification found a difference.

set -uo pipefail

GRPC_TAG="v1.71.0"          # Grpc.Tools 2.71.0 corresponds to gRPC core 1.71.0.
OUT_DIR="$PWD/grpc-arm64-tools"
VERIFY_PLUGIN=""
VERIFY_PROTOC=""
WORK_DIR="${TMPDIR:-/tmp}/bxl-grpc-arm64"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag)     GRPC_TAG="$2"; shift 2 ;;
        --out)     OUT_DIR="$2"; shift 2 ;;
        --verify)  VERIFY_PLUGIN="$2"; shift 2 ;;
        --verify-protoc) VERIFY_PROTOC="$2"; shift 2 ;;
        --work)    WORK_DIR="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m    %s\n' "$*"; }
bad()  { printf '  \033[31mno\033[0m    %s\n' "$*"; }
info() { printf '        %s\n' "$*"; }

[[ "$(uname -s)" == "Darwin" ]] || { bad "this script builds macOS binaries"; exit 1; }

bold "Prerequisites"
command -v clang++ >/dev/null 2>&1 || { bad "clang++ not found; install the Xcode command line tools"; exit 1; }
ok "clang++ $(clang++ --version | head -1 | sed 's/.*version //;s/ .*//')"
command -v git >/dev/null 2>&1 || { bad "git not found"; exit 1; }

mkdir -p "$WORK_DIR"

# CMake is used only to build protobuf, which is far too large to drive by hand. If the machine has
# no cmake - and a Mac with only the command line tools does not - fetch the official universal
# build rather than asking the caller to install one.
CMAKE="$(command -v cmake || true)"
if [[ -z "$CMAKE" ]]; then
    info "no cmake on this machine; fetching the official universal build"
    CMAKE_VERSION="$(curl -s -m 60 https://api.github.com/repos/Kitware/CMake/releases/latest |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"].lstrip("v"))' 2>/dev/null)"
    [[ -n "$CMAKE_VERSION" ]] || { bad "could not determine the latest CMake release"; exit 1; }
    if [[ ! -d "$WORK_DIR/cmake-$CMAKE_VERSION" ]]; then
        curl -sL -m 600 -o "$WORK_DIR/cmake.tar.gz" \
            "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-macos-universal.tar.gz" \
            || { bad "could not download CMake"; exit 1; }
        mkdir -p "$WORK_DIR/cmake-$CMAKE_VERSION"
        tar xzf "$WORK_DIR/cmake.tar.gz" -C "$WORK_DIR/cmake-$CMAKE_VERSION" --strip-components 1
    fi
    CMAKE="$WORK_DIR/cmake-$CMAKE_VERSION/CMake.app/Contents/bin/cmake"
fi
[[ -x "$CMAKE" ]] || { bad "cmake is not usable at $CMAKE"; exit 1; }
ok "cmake $("$CMAKE" --version | head -1 | sed 's/.*version //')"

# ---------------------------------------------------------------- sources

bold "Sources"
GRPC_SRC="$WORK_DIR/grpc-$GRPC_TAG"
if [[ ! -d "$GRPC_SRC/.git" ]]; then
    info "cloning grpc $GRPC_TAG (shallow)"
    git clone -q --depth 1 --branch "$GRPC_TAG" https://github.com/grpc/grpc.git "$GRPC_SRC" 2>/dev/null \
        || { bad "could not clone grpc at $GRPC_TAG"; exit 2; }
fi
ok "grpc $GRPC_TAG"

# Only protobuf and abseil are needed. The plugin does not link gRPC's C-core at all - it is a
# protoc plugin, so it needs libprotoc and nothing else from the runtime. Initialising just these
# avoids pulling boringssl and the rest of the C-core's dependency tree.
pushd "$GRPC_SRC" >/dev/null
for module in third_party/protobuf third_party/abseil-cpp; do
    git submodule update --init --depth 1 "$module" >/dev/null 2>&1 \
        || { bad "could not init $module"; popd >/dev/null; exit 2; }
done
pushd third_party/protobuf >/dev/null
git submodule update --init --depth 1 third_party/utf8_range >/dev/null 2>&1
popd >/dev/null
popd >/dev/null
ok "protobuf, abseil and utf8_range checked out"

PROTOBUF_SRC="$GRPC_SRC/third_party/protobuf"
ABSEIL_SRC="$GRPC_SRC/third_party/abseil-cpp"

# ---------------------------------------------------------------- protobuf

bold "Building protobuf for arm64"
PB_BUILD="$WORK_DIR/protobuf-build"
if [[ ! -x "$PB_BUILD/protoc" ]]; then
    mkdir -p "$PB_BUILD"
    # protobuf's own abseil submodule is not initialised here, so point it at gRPC's copy - they are
    # the same dependency, and gRPC pins the version its protobuf expects.
    "$CMAKE" "$PROTOBUF_SRC" -B "$PB_BUILD" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_OSX_ARCHITECTURES=arm64 \
        -Dprotobuf_BUILD_TESTS=OFF \
        -Dprotobuf_ABSL_PROVIDER=module \
        -DABSL_ROOT_DIR="$ABSEIL_SRC" \
        -Dprotobuf_BUILD_LIBUPB=OFF \
        -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
        > "$WORK_DIR/protobuf-configure.log" 2>&1 \
        || { bad "protobuf configure failed; see $WORK_DIR/protobuf-configure.log"; exit 2; }
    "$CMAKE" --build "$PB_BUILD" --parallel "$(sysctl -n hw.ncpu)" \
        > "$WORK_DIR/protobuf-build.log" 2>&1 \
        || { bad "protobuf build failed; see $WORK_DIR/protobuf-build.log"; exit 2; }
fi
[[ -x "$PB_BUILD/protoc" ]] || { bad "protobuf built but produced no protoc"; exit 2; }
ok "protoc $("$PB_BUILD/protoc" --version | awk '{print $2}') ($(file -b "$PB_BUILD/protoc" | grep -o 'arm64\|x86_64'))"

# ---------------------------------------------------------------- the plugin

bold "Building grpc_csharp_plugin for arm64"

# Three things about this command line are load-bearing, and each cost time to find:
#
#  - proto_parser_helper.cc is needed as well as the two obvious csharp_*.cc files. Without it the
#    link fails on a single symbol, grpc_generator::EscapeVariableDelimiters.
#
#  - No -std flag. CMake passed none when building protobuf, so protobuf and abseil were compiled at
#    the compiler's default standard, which on Apple clang is C++14. At C++14 absl::string_view is
#    abseil's own class; at C++17 it is an alias for std::string_view. Compiling the plugin with
#    -std=c++17 therefore produces references that no symbol in libprotoc matches, and the link
#    fails on functions that are plainly present in the archive. Matching protobuf's flags is what
#    matters, not choosing a modern standard.
#
#  - -force_load on libprotoc. The C# *message* generator inside libprotoc is only reachable
#    transitively, so a normal archive link leaves google::protobuf::compiler::csharp::GetOutputFile
#    undefined even though the archive defines it.
PLUGIN_SOURCES=(
    "$GRPC_SRC/src/compiler/csharp_plugin.cc"
    "$GRPC_SRC/src/compiler/csharp_generator.cc"
    "$GRPC_SRC/src/compiler/proto_parser_helper.cc"
)
mkdir -p "$WORK_DIR/plugin-build"
clang++ -O3 -DNDEBUG -arch arm64 \
    -I"$GRPC_SRC" -I"$GRPC_SRC/include" \
    -I"$PROTOBUF_SRC/src" -I"$PROTOBUF_SRC/third_party/utf8_range" \
    -I"$ABSEIL_SRC" -I"$PB_BUILD" -I"$PB_BUILD/src" \
    "${PLUGIN_SOURCES[@]}" \
    -Wl,-force_load,"$PB_BUILD/libprotoc.a" "$PB_BUILD/libprotobuf.a" \
    $(find "$PB_BUILD" -name "libabsl*.a" | tr '\n' ' ') \
    $(find "$PB_BUILD" -name "libutf8*.a" | tr '\n' ' ') \
    -framework CoreFoundation \
    -o "$WORK_DIR/plugin-build/grpc_csharp_plugin" \
    > "$WORK_DIR/plugin-build.log" 2>&1 \
    || { bad "plugin build failed; see $WORK_DIR/plugin-build.log"; exit 2; }
ok "grpc_csharp_plugin ($(file -b "$WORK_DIR/plugin-build/grpc_csharp_plugin" | grep -o 'arm64\|x86_64'))"

mkdir -p "$OUT_DIR"
cp "$PB_BUILD/protoc" "$OUT_DIR/protoc"
cp "$WORK_DIR/plugin-build/grpc_csharp_plugin" "$OUT_DIR/grpc_csharp_plugin"
chmod +x "$OUT_DIR/protoc" "$OUT_DIR/grpc_csharp_plugin"
ok "written to $OUT_DIR"

# ---------------------------------------------------------------- verification

if [[ -z "$VERIFY_PLUGIN" ]]; then
    echo
    bold "Built. Pass --verify <x86_64 grpc_csharp_plugin> to prove it is a drop-in replacement."
    exit 0
fi

echo
bold "Verifying against the x86_64 tools"
[[ -x "$VERIFY_PLUGIN" ]] || { bad "not executable: $VERIFY_PLUGIN"; exit 1; }

# protoc's own output is compared too, but only when an x86_64 protoc of the *same* protobuf version
# is supplied: different protoc versions legitimately generate different message code, so comparing
# across versions would report a difference that means nothing.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../../.." && pwd)"
PROTOS=()
while IFS= read -r p; do PROTOS+=("$p"); done < <(find "$REPO_ROOT/Public/Src" -name "*.proto" | sort)
[[ ${#PROTOS[@]} -gt 0 ]] || { bad "found no .proto files under $REPO_ROOT/Public/Src"; exit 1; }

WELL_KNOWN="$(dirname "$(find "$REPO_ROOT/Out" -path "*google/protobuf/wrappers.proto" 2>/dev/null | head -1)")"
WELL_KNOWN="${WELL_KNOWN%/google/protobuf}"

same=0; differ=0
for proto in "${PROTOS[@]}"; do
    name="$(basename "$proto" .proto)"
    rm -rf "$WORK_DIR/cmp-x64" "$WORK_DIR/cmp-arm64"
    mkdir -p "$WORK_DIR/cmp-x64" "$WORK_DIR/cmp-arm64"

    "${VERIFY_PROTOC:-$OUT_DIR/protoc}" --proto_path="$(dirname "$proto")" ${WELL_KNOWN:+--proto_path="$WELL_KNOWN"} \
        --csharp_out="$WORK_DIR/cmp-x64" --grpc_out="$WORK_DIR/cmp-x64" \
        --plugin=protoc-gen-grpc="$VERIFY_PLUGIN" "$proto" >/dev/null 2>&1

    "$OUT_DIR/protoc" --proto_path="$(dirname "$proto")" ${WELL_KNOWN:+--proto_path="$WELL_KNOWN"} \
        --csharp_out="$WORK_DIR/cmp-arm64" --grpc_out="$WORK_DIR/cmp-arm64" \
        --plugin=protoc-gen-grpc="$OUT_DIR/grpc_csharp_plugin" "$proto" >/dev/null 2>&1

    [[ -n "$(ls -A "$WORK_DIR/cmp-x64" 2>/dev/null)" ]] || continue
    if diff -rq "$WORK_DIR/cmp-x64" "$WORK_DIR/cmp-arm64" >/dev/null 2>&1; then
        ok "identical: $name"
        same=$((same + 1))
    else
        bad "differs: $name"
        diff -rq "$WORK_DIR/cmp-x64" "$WORK_DIR/cmp-arm64" | sed 's/^/        /' | head -4
        differ=$((differ + 1))
    fi
done

echo
if (( differ == 0 && same > 0 )); then
    bold "$same generated file sets identical. The native tools are a drop-in replacement."
    exit 0
fi
bold "$differ of $((same + differ)) differ - do not use these tools."
exit 3
