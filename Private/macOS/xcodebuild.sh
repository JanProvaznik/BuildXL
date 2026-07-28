#!/bin/bash
# Copyright (c) Microsoft. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.

### Builds the macOS native library using xcode

arg_projectPath=""
arg_scheme=""
arg_configuration=""
arg_outputDirectory=""
arg_bundlePath=""
arg_arch=""

parseArgs() {
    while [[ $# -gt 0 ]]; do
        cmd="$1"
        case $cmd in
        --projectPath)
            arg_projectPath="$2"
            shift
            ;;
        --scheme)
            arg_scheme="$2"
            shift
            ;;
        --configuration)
            arg_configuration="$2"
            shift
            ;;
        --outputDirectory)
            arg_outputDirectory="$2"
            shift
            ;;
        --bundlePath)
            arg_bundlePath="$2"
            shift
            ;;
        --arch)
            arg_arch="$2"
            shift
            ;;
        *)
            shift
            ;;
        esac
    done
}

parseArgs $@

if [[ "$arg_projectPath" == "" || "$arg_scheme"  == "" || "$arg_configuration"  == "" || "$arg_outputDirectory"  == "" || "$arg_bundlePath"  == "" ]]; then
    echo "Usage: $0 --projectPath <path> --scheme <scheme> --configuration <configuration> --outputDirectory <path> --bundlePath <path> [--arch <x86_64|arm64>]"
    exit 1
fi

# Without an explicit architecture, xcodebuild builds for whatever the agent happens to be, and in a
# debug configuration ONLY_ACTIVE_ARCH narrows that to the active architecture alone. That silently
# produces an arm64 dylib on an Apple Silicon agent, which an x64 .NET process running under Rosetta 2
# cannot load. Naming the architecture makes the output match the runtime identifier it is deployed into.
declare -a archArgs=()
if [[ -n "$arg_arch" ]]; then
    archArgs=("ARCHS=$arg_arch" "ONLY_ACTIVE_ARCH=NO")
fi

/usr/bin/xcodebuild build -project $arg_projectPath -scheme $arg_scheme -configuration $arg_configuration -derivedDataPath $arg_outputDirectory -xcconfig $arg_bundlePath -UseModernBuildSystem=YES "${archArgs[@]}"