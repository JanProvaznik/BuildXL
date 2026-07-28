// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cassert>
#include <cstring>

#include "ManifestBuilder.h"
#include "StringOperations.h"

namespace buildxl {
namespace macos {
namespace testing {

namespace {

void AppendUint32(std::vector<char> &buffer, uint32_t value)
{
    const char *bytes = reinterpret_cast<const char *>(&value);
    buffer.insert(buffer.end(), bytes, bytes + sizeof(value));
}

void AppendUint64(std::vector<char> &buffer, uint64_t value)
{
    const char *bytes = reinterpret_cast<const char *>(&value);
    buffer.insert(buffer.end(), bytes, bytes + sizeof(value));
}

/** Strings in the manifest are UTF-16 even on Unix, where the parser narrows each unit back down. */
void AppendUtf16(std::vector<char> &buffer, const std::string &value)
{
    AppendUint32(buffer, static_cast<uint32_t>(value.size()));
    for (char c : value)
    {
        buffer.push_back(c);
        buffer.push_back('\0');
    }
}

std::vector<std::string> SplitPath(const std::string &path)
{
    std::vector<std::string> components;
    std::string current;
    for (char c : path)
    {
        if (c == '/')
        {
            if (!current.empty())
            {
                components.push_back(current);
                current.clear();
            }
        }
        else
        {
            current += c;
        }
    }

    if (!current.empty())
    {
        components.push_back(current);
    }

    return components;
}

constexpr size_t kFixedRecordFields = 7; // Hash, ConePolicy, NodePolicy, PathId, UsnLo, UsnHi, BucketCount

size_t RecordSize(size_t bucketCount, const std::string &component)
{
    size_t size = (kFixedRecordFields + bucketCount) * sizeof(uint32_t) + component.size() + 1;

    // Records are addressed through uint32 offsets and read as uint32 fields, so each one has to
    // start on a 4-byte boundary.
    return (size + 3) & ~static_cast<size_t>(3);
}

} // namespace

FileAccessPolicy ReportAllPolicy()
{
    return static_cast<FileAccessPolicy>(
        FileAccessPolicy_AllowAll
        | FileAccessPolicy_ReportAccess
        | FileAccessPolicy_ReportDirectoryEnumerationAccess
        | FileAccessPolicy_AllowSymlinkCreation
        | FileAccessPolicy_AllowRealInputTimestamps);
}

ManifestBuilder::ManifestBuilder()
    : m_flags(static_cast<FileAccessManifestFlag>(
          static_cast<uint32_t>(FileAccessManifestFlag::ReportAllFileAccesses)
          | static_cast<uint32_t>(FileAccessManifestFlag::MonitorChildProcesses)
          | static_cast<uint32_t>(FileAccessManifestFlag::ReportProcessArgs))),
      m_extraFlags(FileAccessManifestExtraFlag::NoneExtra)
{
    // Node 0 is the outer root; node 1 is the Unix root sentinel that the parser insists on.
    Node outerRoot;
    outerRoot.component = "";
    outerRoot.hash = 0;
    m_nodes.push_back(outerRoot);

    Node sentinel;
    sentinel.component = "";
    sentinel.hash = HashPath("", 0);
    sentinel.conePolicySet = true;
    sentinel.conePolicy = ReportAllPolicy();
    m_nodes.push_back(sentinel);

    m_nodes[0].children[""] = 1;
}

ManifestBuilder &ManifestBuilder::WithReportPath(const std::string &path)
{
    m_reportPath = path;
    return *this;
}

ManifestBuilder &ManifestBuilder::WithPipId(uint64_t pipId)
{
    m_pipId = pipId;
    return *this;
}

ManifestBuilder &ManifestBuilder::WithFlags(FileAccessManifestFlag flags)
{
    m_flags = flags;
    return *this;
}

ManifestBuilder &ManifestBuilder::WithExtraFlags(FileAccessManifestExtraFlag extraFlags)
{
    m_extraFlags = extraFlags;
    return *this;
}

ManifestBuilder &ManifestBuilder::WithRootPolicy(FileAccessPolicy policy)
{
    m_nodes[1].conePolicySet = true;
    m_nodes[1].conePolicy = policy;
    return *this;
}

size_t ManifestBuilder::AddChild(size_t parentIndex, const std::string &component)
{
    auto existing = m_nodes[parentIndex].children.find(component);
    if (existing != m_nodes[parentIndex].children.end())
    {
        return existing->second;
    }

    Node node;
    node.component = component;
    node.hash = HashPath(component.c_str(), component.size());

    m_nodes.push_back(node);
    const size_t index = m_nodes.size() - 1;
    m_nodes[parentIndex].children[component] = index;
    return index;
}

size_t ManifestBuilder::EnsureNode(const std::string &path)
{
    size_t current = 1;
    for (const std::string &component : SplitPath(path))
    {
        current = AddChild(current, component);
    }

    return current;
}

ManifestBuilder &ManifestBuilder::WithScope(const std::string &path, FileAccessPolicy conePolicy)
{
    const size_t index = EnsureNode(path);
    m_nodes[index].conePolicySet = true;
    m_nodes[index].conePolicy = conePolicy;
    return *this;
}

ManifestBuilder &ManifestBuilder::WithPath(const std::string &path, FileAccessPolicy nodePolicy)
{
    const size_t index = EnsureNode(path);
    m_nodes[index].nodePolicySet = true;
    m_nodes[index].nodePolicy = nodePolicy;
    return *this;
}

ManifestBuilder &ManifestBuilder::WithBreakaway(const std::string &executable, const std::string &requiredArgs, bool ignoreCase)
{
    m_breakaways.push_back(BreakawayEntry{executable, requiredArgs, ignoreCase});
    return *this;
}

uint32_t ManifestBuilder::ChooseBucketCount(const std::vector<uint32_t> &childHashes)
{
    if (childHashes.empty())
    {
        return 0;
    }

    // Grow until every child lands in its own bucket. Collision chains are part of the format, but
    // building them here would add a second, untested encoder for no benefit: a slightly larger
    // table is read by exactly the same lookup code.
    for (uint32_t buckets = static_cast<uint32_t>(childHashes.size()); buckets < 1u << 20; buckets++)
    {
        std::vector<bool> used(buckets, false);
        bool collision = false;
        for (uint32_t hash : childHashes)
        {
            const uint32_t index = hash % buckets;
            if (used[index])
            {
                collision = true;
                break;
            }

            used[index] = true;
        }

        if (!collision)
        {
            return buckets;
        }
    }

    assert(false && "could not find a collision-free bucket count");
    return static_cast<uint32_t>(childHashes.size());
}

void ManifestBuilder::LayoutRecords(
    std::vector<size_t> &sizes,
    std::vector<size_t> &offsets,
    std::vector<uint32_t> &bucketCounts) const
{
    sizes.assign(m_nodes.size(), 0);
    offsets.assign(m_nodes.size(), 0);
    bucketCounts.assign(m_nodes.size(), 0);

    for (size_t i = 0; i < m_nodes.size(); i++)
    {
        std::vector<uint32_t> childHashes;
        for (const auto &entry : m_nodes[i].children)
        {
            childHashes.push_back(m_nodes[entry.second].hash);
        }

        bucketCounts[i] = i == 0 ? 1 : ChooseBucketCount(childHashes);
        sizes[i] = RecordSize(bucketCounts[i], m_nodes[i].component);
    }

    size_t cursor = 0;
    for (size_t i = 0; i < m_nodes.size(); i++)
    {
        offsets[i] = cursor;
        cursor += sizes[i];
    }
}

std::vector<char> ManifestBuilder::Build() const
{
    std::vector<char> payload;

    // 1. Debug flag. Release layout, because that is what this file is compiled as.
    AppendUint32(payload, 0xDB600000);

    // 2. Injection timeout, in minutes. Must be positive.
    AppendUint32(payload, 10);

    // 3. Breakaway child processes.
    AppendUint32(payload, static_cast<uint32_t>(m_breakaways.size()));
    for (const BreakawayEntry &entry : m_breakaways)
    {
        AppendUtf16(payload, entry.executable);
        AppendUtf16(payload, entry.requiredArgs);
        payload.push_back(entry.ignoreCase ? 1 : 0);
    }

    // 4. Path translations.
    AppendUint32(payload, 0);

    // 5. Error dump location. The struct itself is zero-sized off Windows; only the string remains.
    AppendUtf16(payload, "");

    // 6/7. Flags.
    AppendUint32(payload, static_cast<uint32_t>(m_flags));
    AppendUint32(payload, static_cast<uint32_t>(m_extraFlags));

    // 8. Pip id.
    AppendUint64(payload, m_pipId);

    // 9. Report path. Its length is the one field free enough to absorb the padding that keeps the
    // manifest tree 4-byte aligned, so alignment is fixed up here rather than with a filler section
    // the parser does not know about.
    {
        size_t reportBytes = m_reportPath.size() + 1;
        const size_t offsetAfterSize = payload.size() + sizeof(uint32_t);

        // Sections 10 and 11 contribute a fixed, already-aligned number of bytes.
        while (((offsetAfterSize + reportBytes) % 4) != 0)
        {
            reportBytes++;
        }

        AppendUint32(payload, static_cast<uint32_t>(reportBytes));
        payload.insert(payload.end(), m_reportPath.begin(), m_reportPath.end());
        payload.insert(payload.end(), reportBytes - m_reportPath.size(), '\0');
    }

    // 10. Dll block: no injected libraries.
    AppendUint32(payload, 0); // StringBlockSize
    AppendUint32(payload, 0); // StringCount

    // 11. Substitute process shim: disabled.
    AppendUint32(payload, 0); // ShimAllProcesses
    AppendUint32(payload, 0); // zero-length shim path, which stops the parser from reading further

    assert((payload.size() % 4) == 0 && "manifest tree must start 4-byte aligned");

    // 12. Manifest tree.
    std::vector<size_t> sizes;
    std::vector<size_t> offsets;
    std::vector<uint32_t> bucketCounts;
    LayoutRecords(sizes, offsets, bucketCounts);

    const size_t treeBase = payload.size();
    payload.resize(treeBase + offsets.back() + sizes.back(), '\0');

    for (size_t i = 0; i < m_nodes.size(); i++)
    {
        const Node &node = m_nodes[i];
        std::vector<char> record;
        record.reserve(sizes[i]);

        AppendUint32(record, node.hash);
        AppendUint32(record, static_cast<uint32_t>(node.conePolicySet ? node.conePolicy : static_cast<FileAccessPolicy>(0)));
        AppendUint32(record, static_cast<uint32_t>(node.nodePolicySet ? node.nodePolicy : (node.conePolicySet ? node.conePolicy : static_cast<FileAccessPolicy>(0))));
        AppendUint32(record, 0); // PathId
        AppendUint32(record, 0); // ExpectedUsnLo
        AppendUint32(record, 0); // ExpectedUsnHi
        AppendUint32(record, bucketCounts[i]);

        std::vector<uint32_t> buckets(bucketCounts[i], 0);
        for (const auto &entry : node.children)
        {
            const size_t childIndex = entry.second;
            const uint32_t bucket = bucketCounts[i] == 0
                ? 0
                : m_nodes[childIndex].hash % bucketCounts[i];

            // Offsets are relative to the record that owns the bucket array.
            buckets[bucket] = static_cast<uint32_t>(offsets[childIndex] - offsets[i]);
        }

        for (uint32_t bucket : buckets)
        {
            AppendUint32(record, bucket);
        }

        record.insert(record.end(), node.component.begin(), node.component.end());
        record.push_back('\0');
        record.resize(sizes[i], '\0');

        std::memcpy(payload.data() + treeBase + offsets[i], record.data(), record.size());
    }

    return payload;
}

std::unique_ptr<buildxl::common::FileAccessManifest> ManifestBuilder::BuildManifest() const
{
    const std::vector<char> payload = Build();

    // FileAccessManifest takes ownership of the buffer through a unique_ptr, so it must be a
    // separately allocated array rather than the vector's storage.
    char *owned = new char[payload.size()];
    std::memcpy(owned, payload.data(), payload.size());

    return std::make_unique<buildxl::common::FileAccessManifest>(owned, payload.size());
}

} // namespace testing
} // namespace macos
} // namespace buildxl
