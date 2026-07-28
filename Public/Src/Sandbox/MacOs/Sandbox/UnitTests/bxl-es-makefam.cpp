// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Writes a serialized file access manifest to a file, so shell-level integration tests can drive
// bxl-es-broker exactly the way managed BuildXL does. Managed BuildXL is what produces this blob in
// a real build; this tool exists only so the broker can be exercised without a managed build.

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "ManifestBuilder.h"

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        fprintf(stderr, "usage: bxl-es-makefam <out.fam> <reportFifoPath> [allowedWriteScope...]\n");
        return 2;
    }

    const std::string outPath = argv[1];
    const std::string reportPath = argv[2];

    buildxl::macos::testing::ManifestBuilder builder;
    builder.WithReportPath(reportPath)
        .WithPipId(0x1234)
        .WithRootPolicy(static_cast<FileAccessPolicy>(FileAccessPolicy_AllowRead | FileAccessPolicy_ReportAccess));

    for (int i = 3; i < argc; ++i)
    {
        builder.WithScope(argv[i], static_cast<FileAccessPolicy>(FileAccessPolicy_AllowAll | FileAccessPolicy_ReportAccess));
    }

    const std::vector<char> bytes = builder.Build();

    FILE *out = fopen(outPath.c_str(), "wb");
    if (out == nullptr)
    {
        perror("fopen");
        return 1;
    }

    const size_t written = fwrite(bytes.data(), 1, bytes.size(), out);
    fclose(out);

    if (written != bytes.size())
    {
        fprintf(stderr, "short write: %zu of %zu\n", written, bytes.size());
        return 1;
    }

    printf("wrote %zu bytes to %s (reports -> %s)\n", bytes.size(), outPath.c_str(), reportPath.c_str());
    return 0;
}
