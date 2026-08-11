// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * Writes a file access manifest for the broker, so the broker can be run directly on any command.
 *
 * The broker needs a serialized manifest, and normally BuildXL writes one. That makes the broker's
 * own numbers - event volume, kernel drop rate, queue pressure - reachable only through a full
 * build, and on a machine where the managed build cannot self-host they are not reachable at all.
 *
 * The interesting measurement does not need BuildXL. It needs a real tool doing real work under a
 * real Endpoint Security client, which is exactly what
 *
 *     bxl-es-fam /tmp/x.fam /tmp/x.fifo <root>
 *     __BUILDXL_FAM_PATH=/tmp/x.fam __BUILDXL_MACOS_EVIDENCE_PATH=/tmp/e.jsonl \
 *         bxl-es-broker clang++ -c big.cpp
 *
 * produces. The manifest reports everything and denies nothing: the question being asked is how many
 * events the kernel delivers and how many it drops, not whether a policy is correct.
 */

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "ManifestBuilder.h"

using buildxl::macos::testing::ManifestBuilder;

int main(int argc, char **argv)
{
    if (argc < 4)
    {
        std::fprintf(stderr, "usage: bxl-es-fam <fam-path> <report-fifo-path> <scope> [scope...]\n");
        return 2;
    }

    const std::string famPath = argv[1];
    const std::string reportPath = argv[2];

    ManifestBuilder builder;
    builder.WithReportPath(reportPath).WithPipId(0xE51DE47);

    // Report everything, allow everything. A denial would change what the tool does, and the point
    // is to measure the event stream a normal run produces.
    const FileAccessPolicy observeOnly = static_cast<FileAccessPolicy>(
        FileAccessPolicy_AllowAll | FileAccessPolicy_ReportAccess);

    builder.WithRootPolicy(observeOnly);
    for (int i = 3; i < argc; i++)
    {
        builder.WithScope(argv[i], observeOnly);
    }

    const std::vector<char> payload = builder.Build();

    std::FILE *out = std::fopen(famPath.c_str(), "wb");
    if (out == nullptr)
    {
        std::fprintf(stderr, "cannot write '%s': %s\n", famPath.c_str(), std::strerror(errno));
        return 1;
    }

    const size_t written = std::fwrite(payload.data(), 1, payload.size(), out);
    std::fclose(out);

    if (written != payload.size())
    {
        std::fprintf(stderr, "short write to '%s'\n", famPath.c_str());
        return 1;
    }

    std::printf("%zu bytes -> %s\n", payload.size(), famPath.c_str());
    return 0;
}
