// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Writes a file access manifest to disk so the broker can be driven without BuildXL.
//
// The broker reads its manifest from __BUILDXL_FAM_PATH, and that blob is normally produced by
// managed code. Running the broker against the real kernel therefore needed either a checked-in
// binary fixture or a way to build one. A fixture would rot silently the moment the format changed,
// so this reuses the test ManifestBuilder, which is written against the same headers the parser
// uses: a format change breaks the build instead of producing a manifest nobody can parse.
//
// Build (from the Sandbox directory):
//
//   clang++ -std=c++17 -DMAC_OS_ES_SANDBOX=1 -D_DARWIN_C_SOURCE -o es-makefam \
//     Diagnostics/es-makefam.cpp UnitTests/ManifestBuilder.cpp \
//     ../../Common/FileAccessManifest.cpp \
//     ../../Windows/DetoursServices/StringOperations.cpp \
//     -I. -I UnitTests -I ../../Common -I ../../Windows/DetoursServices
//
// Usage:
//
//   es-makefam <out.fam> <reportFifoPath> [allowedWriteScope...]

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include "ManifestBuilder.h"

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        std::fprintf(stderr, "usage: es-makefam <out.fam> <reportFifoPath> [allowedWriteScope...]\n");
        return 2;
    }

    const std::string outPath = argv[1];
    const std::string reportPath = argv[2];

    buildxl::macos::testing::ManifestBuilder builder;
    builder.WithReportPath(reportPath)
        .WithPipId(1)
        // Report everything and block nothing. The point of a diagnostic run is to see what the
        // kernel delivers, not to enforce a policy, and a blocking policy would change the
        // behaviour of the very processes being observed.
        .WithRootPolicy(buildxl::macos::testing::ReportAllPolicy());

    // Scopes the caller wants writable. Without these, a workload that writes anywhere would report
    // a violation and the run would be about the policy rather than about the event stream.
    for (int i = 3; i < argc; i++)
    {
        builder.WithScope(argv[i], buildxl::macos::testing::ReportAllPolicy());
    }

    const std::vector<char> blob = builder.Build();

    std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        std::fprintf(stderr, "es-makefam: cannot open '%s' for writing\n", outPath.c_str());
        return 1;
    }

    out.write(blob.data(), static_cast<std::streamsize>(blob.size()));
    if (!out)
    {
        std::fprintf(stderr, "es-makefam: write to '%s' failed\n", outPath.c_str());
        return 1;
    }

    std::fprintf(stderr, "es-makefam: wrote %zu bytes to %s (reports -> %s)\n",
                 blob.size(), outPath.c_str(), reportPath.c_str());
    return 0;
}
