// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_TEST_MANIFEST_BUILDER_H
#define BUILDXL_SANDBOX_MACOS_TEST_MANIFEST_BUILDER_H

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "FileAccessManifest.h"

namespace buildxl {
namespace macos {
namespace testing {

/**
 * Builds a serialized file access manifest payload.
 *
 * BuildXL normally produces this blob from managed code, which means native tests either need a
 * checked-in binary fixture or a way to build one. A fixture would rot silently the moment the
 * format changed; this builder is written against the same headers the parser uses, so a format
 * change breaks the build instead.
 *
 * Only the layout Unix actually parses is produced. Windows-only sections are emitted as empty
 * placeholders because that is what the parser expects to skip.
 */
class ManifestBuilder
{
public:
    ManifestBuilder();

    /** Where the sandbox should send its reports. */
    ManifestBuilder &WithReportPath(const std::string &path);

    ManifestBuilder &WithPipId(uint64_t pipId);

    ManifestBuilder &WithFlags(FileAccessManifestFlag flags);

    ManifestBuilder &WithExtraFlags(FileAccessManifestExtraFlag extraFlags);

    /** Policy applied to everything not covered by a more specific scope. */
    ManifestBuilder &WithRootPolicy(FileAccessPolicy policy);

    /** Applies a policy to a directory cone. */
    ManifestBuilder &WithScope(const std::string &path, FileAccessPolicy conePolicy);

    /** Applies a policy to a single path, leaving the surrounding cone untouched. */
    ManifestBuilder &WithPath(const std::string &path, FileAccessPolicy nodePolicy);

    ManifestBuilder &WithBreakaway(const std::string &executable, const std::string &requiredArgs, bool ignoreCase);

    /** Serializes. The returned buffer is owned by the caller. */
    std::vector<char> Build() const;

    /** Convenience: serializes and constructs the parser object in one step. */
    std::unique_ptr<buildxl::common::FileAccessManifest> BuildManifest() const;

private:
    struct Node
    {
        std::string component;
        uint32_t hash = 0;
        bool conePolicySet = false;
        bool nodePolicySet = false;
        FileAccessPolicy conePolicy = static_cast<FileAccessPolicy>(0);
        FileAccessPolicy nodePolicy = static_cast<FileAccessPolicy>(0);
        std::map<std::string, size_t> children;
    };

    struct BreakawayEntry
    {
        std::string executable;
        std::string requiredArgs;
        bool ignoreCase = false;
    };

    size_t EnsureNode(const std::string &path);
    size_t AddChild(size_t parentIndex, const std::string &component);

    /** Two-pass record layout: sizes first, then bytes, because bucket offsets are self-relative. */
    void LayoutRecords(std::vector<size_t> &sizes, std::vector<size_t> &offsets, std::vector<uint32_t> &bucketCounts) const;
    static uint32_t ChooseBucketCount(const std::vector<uint32_t> &childHashes);

    std::vector<Node> m_nodes;
    std::vector<BreakawayEntry> m_breakaways;
    std::string m_reportPath;
    uint64_t m_pipId = 1;
    FileAccessManifestFlag m_flags;
    FileAccessManifestExtraFlag m_extraFlags;
};

/** Policy that reports everything and blocks nothing: the right default for protocol tests. */
FileAccessPolicy ReportAllPolicy();

} // namespace testing
} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_TEST_MANIFEST_BUILDER_H
