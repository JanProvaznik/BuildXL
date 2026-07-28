// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

#include "ReplaySource.h"

namespace buildxl {
namespace macos {

namespace {

/** splitmix64: tiny, deterministic across platforms and compilers, which is all a corpus needs. */
class Random
{
public:
    explicit Random(uint64_t seed) : m_state(seed + 0x9E3779B97F4A7C15ull) {}

    uint64_t Next()
    {
        uint64_t z = (m_state += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }

    uint32_t Below(uint32_t bound) { return bound == 0 ? 0 : static_cast<uint32_t>(Next() % bound); }

    bool Chance(uint32_t percent) { return Below(100) < percent; }

private:
    uint64_t m_state;
};

std::string EscapeJson(const std::string &value)
{
    std::string result;
    result.reserve(value.size() + 8);
    for (char c : value)
    {
        switch (c)
        {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c; break;
        }
    }

    return result;
}

std::string UnescapeJson(const std::string &value)
{
    std::string result;
    result.reserve(value.size());
    for (size_t i = 0; i < value.size(); i++)
    {
        if (value[i] == '\\' && i + 1 < value.size())
        {
            i++;
            switch (value[i])
            {
                case 'n': result += '\n'; break;
                case 'r': result += '\r'; break;
                case 't': result += '\t'; break;
                default: result += value[i]; break;
            }
        }
        else
        {
            result += value[i];
        }
    }

    return result;
}

/** Minimal field reader for the flat one-level records this file writes. */
bool ReadStringField(const std::string &line, const char *name, std::string &value)
{
    const std::string key = std::string("\"") + name + "\":\"";
    const size_t start = line.find(key);
    if (start == std::string::npos)
    {
        return false;
    }

    size_t cursor = start + key.size();
    std::string raw;
    while (cursor < line.size())
    {
        if (line[cursor] == '\\' && cursor + 1 < line.size())
        {
            raw += line[cursor];
            raw += line[cursor + 1];
            cursor += 2;
            continue;
        }

        if (line[cursor] == '"')
        {
            break;
        }

        raw += line[cursor];
        cursor++;
    }

    value = UnescapeJson(raw);
    return true;
}

bool ReadNumberField(const std::string &line, const char *name, long long &value)
{
    const std::string key = std::string("\"") + name + "\":";
    const size_t start = line.find(key);
    if (start == std::string::npos)
    {
        return false;
    }

    value = std::strtoll(line.c_str() + start + key.size(), nullptr, 10);
    return true;
}

} // namespace

// ---------------------------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------------------------

ReplaySource::ReplaySource(std::vector<NormalizedEvent> corpus, FaultScript faults, ProcessIdentity brokerIdentity)
    : m_corpus(std::move(corpus)),
      m_faults(faults),
      m_brokerIdentity(brokerIdentity)
{
}

ReplaySource::~ReplaySource()
{
    Stop();
}

bool ReplaySource::Start(EventHandler handler, std::string &errorMessage)
{
    if (m_started)
    {
        errorMessage = "replay source already started";
        return false;
    }

    m_handler = std::move(handler);
    m_started = true;
    return true;
}

void ReplaySource::Stop()
{
    m_started = false;
}

void ReplaySource::DeliverCorpus()
{
    if (m_corpusDelivered)
    {
        return;
    }

    m_corpusDelivered = true;

    Random random(m_faults.seed);

    // Decide up front which indices the drop faults hit, so the run is reproducible from the seed
    // alone. A drop still consumes its sequence number: that is what makes the loss detectable, and
    // modelling it any other way would be modelling a kernel that does not exist.
    std::vector<bool> dropped(m_corpus.size(), false);
    for (uint32_t i = 0; i < m_faults.dropCount && !m_corpus.empty(); i++)
    {
        dropped[random.Below(static_cast<uint32_t>(m_corpus.size()))] = true;
    }

    if (m_faults.dropTail && m_corpus.size() > 4)
    {
        const size_t tailStart = m_corpus.size() - std::max<size_t>(1, m_corpus.size() / 10);
        for (size_t i = tailStart; i < m_corpus.size(); i++)
        {
            dropped[i] = true;
        }
    }

    size_t exitsSuppressed = 0;
    const size_t epochChangeIndex = m_corpus.empty() ? 0 : m_corpus.size() / 2;
    const size_t injectionIndex = m_corpus.empty() ? 0 : m_corpus.size() / 3;

    for (size_t i = 0; i < m_corpus.size(); i++)
    {
        NormalizedEvent event = m_corpus[i];

        if (m_faults.changeEpoch && i == epochChangeIndex)
        {
            // A recreated client restarts numbering. Everything before the restart is unrelated to
            // everything after it, so the broker must not try to reconcile the two.
            m_epoch++;
            m_nextSequence = 1;
        }

        event.clientEpoch = m_epoch;
        event.globalSequence = m_nextSequence++;

        if (m_faults.loseExit && event.op == NormOp::kExit && exitsSuppressed == 0
            && !(event.self == m_corpus.front().self))
        {
            exitsSuppressed++;
            m_suppressed.push_back(event);
            continue;
        }

        if (dropped[i])
        {
            m_suppressed.push_back(event);
            continue;
        }

        if (m_faults.unknownVersion && i == injectionIndex)
        {
            event.messageVersion = 99;
        }

        if (m_faults.staleVersion && i == injectionIndex)
        {
            event.messageVersion = 1;
        }

        if (m_faults.unmappedLineage && i == injectionIndex)
        {
            event.self.pid = 0x7FFF0000 + static_cast<int32_t>(i);
            event.self.pidversion = 0x7F00;
        }

        if (m_faults.unsupportedOperation && i == injectionIndex)
        {
            event.op = NormOp::kUnsupported;
        }

        if (m_faults.truncatePath && i == injectionIndex)
        {
            event.sourcePathTruncated = true;
        }

        m_delivered++;
        m_handler(std::move(event));
    }
}

bool ReplaySource::EmitMarker(const std::string &noncePath)
{
    if (!m_started || !m_handler)
    {
        return false;
    }

    const bool isBaseline = !m_baselineEmitted;
    m_baselineEmitted = true;

    if (!isBaseline)
    {
        // The closing marker is generated after the observed tree has quiesced, so everything the
        // corpus represents must already have been handed over. Calling this again is a no-op when
        // the harness already delivered it.
        DeliverCorpus();
    }

    if (m_faults.loseMarker && !isBaseline)
    {
        // Consume the sequence number anyway: a marker that the kernel generated but never
        // delivered is exactly a gap at the end of the stream.
        m_nextSequence++;
        return true;
    }

    NormalizedEvent marker;
    marker.op = NormOp::kStat;
    marker.self = m_brokerIdentity;
    marker.parent = m_brokerIdentity;
    marker.sourcePath = noncePath;
    marker.sourceExists = false;
    marker.fromBroker = true;
    marker.messageVersion = 8;
    marker.clientEpoch = m_epoch;
    marker.globalSequence = m_nextSequence++;

    m_handler(std::move(marker));
    return true;
}

// ---------------------------------------------------------------------------------------------
// Corpus serialization
// ---------------------------------------------------------------------------------------------

bool ReplaySource::WriteCorpus(const std::string &path, const std::vector<NormalizedEvent> &corpus)
{
    std::ofstream stream(path, std::ios::out | std::ios::trunc);
    if (!stream)
    {
        return false;
    }

    for (const NormalizedEvent &event : corpus)
    {
        stream << "{\"op\":\"" << NormOpName(event.op) << "\""
               << ",\"pid\":" << event.self.pid
               << ",\"pidversion\":" << event.self.pidversion
               << ",\"ppid\":" << event.parent.pid
               << ",\"ppidversion\":" << event.parent.pidversion
               << ",\"version\":" << event.messageVersion
               << ",\"error\":" << event.error
               << ",\"succeeded\":" << (event.succeeded ? 1 : 0)
               << ",\"srcExists\":" << (event.sourceExists ? 1 : 0)
               << ",\"srcIsDir\":" << (event.sourceIsDirectory ? 1 : 0)
               << ",\"src\":\"" << EscapeJson(event.sourcePath) << "\""
               << ",\"dst\":\"" << EscapeJson(event.destinationPath) << "\""
               << ",\"cmd\":\"" << EscapeJson(event.commandLine) << "\""
               << "}\n";
    }

    return stream.good();
}

bool ReplaySource::ReadCorpus(const std::string &path, std::vector<NormalizedEvent> &corpus, std::string &errorMessage)
{
    std::ifstream stream(path);
    if (!stream)
    {
        errorMessage = "cannot open corpus: " + path;
        return false;
    }

    std::string line;
    while (std::getline(stream, line))
    {
        if (line.empty())
        {
            continue;
        }

        NormalizedEvent event;
        std::string opName;
        if (!ReadStringField(line, "op", opName))
        {
            errorMessage = "corpus record has no op: " + line;
            return false;
        }

        event.op = NormOp::kUnknown;
        for (uint16_t candidate = 0; candidate < static_cast<uint16_t>(NormOp::kMax); candidate++)
        {
            if (opName == NormOpName(static_cast<NormOp>(candidate)))
            {
                event.op = static_cast<NormOp>(candidate);
                break;
            }
        }

        long long number = 0;
        if (ReadNumberField(line, "pid", number)) { event.self.pid = static_cast<int32_t>(number); }
        if (ReadNumberField(line, "pidversion", number)) { event.self.pidversion = static_cast<int32_t>(number); }
        if (ReadNumberField(line, "ppid", number)) { event.parent.pid = static_cast<int32_t>(number); }
        if (ReadNumberField(line, "ppidversion", number)) { event.parent.pidversion = static_cast<int32_t>(number); }
        if (ReadNumberField(line, "version", number)) { event.messageVersion = static_cast<uint32_t>(number); }
        if (ReadNumberField(line, "error", number)) { event.error = static_cast<int32_t>(number); }
        if (ReadNumberField(line, "succeeded", number)) { event.succeeded = number != 0; }
        if (ReadNumberField(line, "srcExists", number)) { event.sourceExists = number != 0; }
        if (ReadNumberField(line, "srcIsDir", number)) { event.sourceIsDirectory = number != 0; }

        ReadStringField(line, "src", event.sourcePath);
        ReadStringField(line, "dst", event.destinationPath);
        ReadStringField(line, "cmd", event.commandLine);

        corpus.push_back(std::move(event));
    }

    return true;
}

// ---------------------------------------------------------------------------------------------
// Corpus generation
// ---------------------------------------------------------------------------------------------

std::vector<NormalizedEvent> GenerateCorpus(
    const CorpusShape &shape,
    ProcessIdentity root,
    std::vector<ExpectedAccess> &expectedAccesses)
{
    Random random(shape.seed);
    std::vector<NormalizedEvent> corpus;
    expectedAccesses.clear();

    std::vector<std::string> sourcePaths;
    std::vector<std::string> outputPaths;
    for (uint32_t i = 0; i < shape.distinctPaths; i++)
    {
        sourcePaths.push_back(shape.sourceRoot + "/dir" + std::to_string(i % 8) + "/file" + std::to_string(i) + ".h");
        outputPaths.push_back(shape.outputRoot + "/obj" + std::to_string(i % 4) + "/unit" + std::to_string(i) + ".o");
    }

    struct Live
    {
        ProcessIdentity identity;
        ProcessIdentity parent;
        uint32_t depth;
    };

    std::vector<Live> live;
    live.push_back({root, ProcessIdentity{}, 0});

    int32_t nextPid = root.pid + 1;
    int32_t nextVersion = root.pidversion + 1;

    auto record = [&](const NormalizedEvent &event) {
        if (IsRelevantForDependencies(event.op) && !event.sourcePath.empty())
        {
            expectedAccesses.push_back(ExpectedAccess{event.self.pid, event.op, event.sourcePath});
        }
    };

    auto emitAccesses = [&](const Live &process) {
        for (uint32_t i = 0; i < shape.accessesPerProcess; i++)
        {
            NormalizedEvent event;
            event.self = process.identity;
            event.parent = process.parent;
            event.messageVersion = 8;

            const uint32_t roll = random.Below(100);
            if (roll < 35)
            {
                event.op = NormOp::kLookup;
                event.sourcePath = sourcePaths[random.Below(shape.distinctPaths)];
                event.sourceExists = random.Chance(70);
            }
            else if (roll < 60)
            {
                event.op = NormOp::kOpen;
                event.sourcePath = sourcePaths[random.Below(shape.distinctPaths)];
            }
            else if (roll < 68)
            {
                event.op = NormOp::kStat;
                event.sourcePath = sourcePaths[random.Below(shape.distinctPaths)];
                event.sourceExists = random.Chance(60);
            }
            else if (roll < 74)
            {
                event.op = NormOp::kReadlink;
                event.sourcePath = sourcePaths[random.Below(shape.distinctPaths)];
            }
            else if (roll < 80)
            {
                event.op = NormOp::kReaddir;
                event.sourcePath = shape.sourceRoot + "/dir" + std::to_string(random.Below(8));
                event.sourceIsDirectory = true;
            }
            else if (roll < 88)
            {
                event.op = NormOp::kCreate;
                event.sourcePath = outputPaths[random.Below(shape.distinctPaths)];
                event.sourceExists = false;
            }
            else if (roll < 93)
            {
                event.op = NormOp::kWrite;
                event.sourcePath = outputPaths[random.Below(shape.distinctPaths)];
            }
            else if (roll < 96)
            {
                event.op = NormOp::kRename;
                event.sourcePath = outputPaths[random.Below(shape.distinctPaths)];
                event.destinationPath = outputPaths[random.Below(shape.distinctPaths)];
            }
            else if (roll < 98)
            {
                event.op = NormOp::kUnlink;
                event.sourcePath = outputPaths[random.Below(shape.distinctPaths)];
            }
            else
            {
                event.op = NormOp::kClone;
                event.sourcePath = sourcePaths[random.Below(shape.distinctPaths)];
                event.destinationPath = outputPaths[random.Below(shape.distinctPaths)];
                event.destinationExists = false;
            }

            record(event);
            corpus.push_back(std::move(event));
        }
    };

    emitAccesses(live[0]);

    for (uint32_t i = 1; i < shape.processCount; i++)
    {
        // Fork from a live process shallow enough to stay inside the depth bound. Always picking the
        // root would produce a flat tree and would never exercise lineage validation.
        std::vector<size_t> candidates;
        for (size_t j = 0; j < live.size(); j++)
        {
            if (live[j].depth + 1 <= shape.maxDepth)
            {
                candidates.push_back(j);
            }
        }

        if (candidates.empty())
        {
            break;
        }

        const Live parent = live[candidates[random.Below(static_cast<uint32_t>(candidates.size()))]];
        const ProcessIdentity child{nextPid++, nextVersion++};

        NormalizedEvent fork;
        fork.op = NormOp::kFork;
        fork.self = child;
        fork.parent = parent.identity;
        fork.messageVersion = 8;
        fork.sourcePath = shape.sourceRoot + "/tool" + std::to_string(i % 5);
        corpus.push_back(fork);

        NormalizedEvent exec;
        exec.op = NormOp::kExec;
        exec.self = child;
        exec.parent = parent.identity;
        exec.messageVersion = 8;
        exec.sourcePath = shape.sourceRoot + "/tool" + std::to_string(i % 5);
        exec.commandLine = "tool" + std::to_string(i % 5) + " --input x --output y";
        record(exec);
        corpus.push_back(exec);

        const Live liveChild{child, parent.identity, parent.depth + 1};
        live.push_back(liveChild);
        emitAccesses(liveChild);
    }

    // Exit deepest-first so a child never outlives its parent in the trace.
    std::stable_sort(live.begin(), live.end(), [](const Live &a, const Live &b) { return a.depth > b.depth; });
    for (const Live &process : live)
    {
        NormalizedEvent exit;
        exit.op = NormOp::kExit;
        exit.self = process.identity;
        exit.parent = process.parent;
        exit.messageVersion = 8;
        corpus.push_back(exit);
    }

    return corpus;
}

} // namespace macos
} // namespace buildxl
