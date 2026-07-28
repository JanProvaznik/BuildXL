#!/usr/bin/env python3
"""Static completeness checker for the osx-arm64 target runtime.

Adding a runtime identifier to BuildXL means touching qualifier unions, runtime switches, package
declarations and framework specs that are spread across hundreds of DScript files. Missing one of
them does not necessarily produce an error: a ternary chain with no arm on the end falls through to
whichever runtime happens to be last, which is how osx-arm64 would have received a linux-x64 shared
object from Grpc.Core. This checker verifies, purely textually, the invariants that such an omission
would violate:

  1. Every `targetRuntime` type union that admits "osx-x64" also admits "osx-arm64".
  2. Every `switch` over a runtime identifier that has an "osx-x64" case also has an "osx-arm64" case
     (or is explicitly annotated as a deliberate exclusion).
  3. Every ternary chain over `qualifier.targetRuntime` that tests "osx-x64" also tests "osx-arm64".
  4. Every package id referenced via importFrom("...osx-arm64...") is actually declared in the
     nuget configuration.
  5. Every module referenced via importFrom("DotNet-Runtime-N.osx-arm64") exists as a module.
  6. Every named qualifier that sets targetRuntime uses a value inside the RuntimeVersion union.
  7. Download resolver ids referenced from DScript exist in config.dsc.
  8. The architecture is plumbed end to end, from HostCpuArchitecture through AmbientContext to the
     Prelude cpuArchitecture union.
  9. No configuration-phase spec uses prelude vocabulary that the shipped engine does not have.
 10. No C# file enumerates the runtime identifiers without including osx-arm64.

A *type* position -- a union of runtime identifiers, or a `declare const qualifier` annotation -- is a
correctness failure when it omits osx-arm64. A *value* position such as
`withQualifier({ targetRuntime: "osx-x64" })` selects one concrete build and is reported
informationally, because adding a second one is a packaging decision rather than a correctness fix.

Usage: python3 Shared/Scripts/validate-runtime-identifiers.py [repo-root]
Exits non-zero if any invariant is violated.
"""

import os
import re
import sys
from collections import defaultdict

# Shared/Scripts/<this file> -> repository root
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
if len(sys.argv) > 1:
    ROOT = os.path.abspath(sys.argv[1])

DELIBERATE = "not extended to osx-arm64"

# Literals this change adds to the prelude. Configuration-phase specs may not use them; see
# check_config_prelude_window.
NEW_PRELUDE_LITERALS = {'"arm64"'}

failures = []
notes = []


def fail(path, line, msg):
    rel = os.path.relpath(path, ROOT)
    failures.append(f"{rel}:{line}: {msg}")


def read(path):
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        return f.read()


def dsc_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "Out", "node_modules", "obj", "bin")]
        for fn in filenames:
            if fn.endswith(".dsc") or fn.endswith(".bm"):
                yield os.path.join(dirpath, fn)


ALL_DSC = sorted(dsc_files())


# ---------------------------------------------------------------- check 1: unions
UNION_RE = re.compile(r'targetRuntime\s*:\s*((?:"[a-z0-9\-]+"\s*\|\s*)+"[a-z0-9\-]+")')
SINGLE_RE = re.compile(r'targetRuntime\s*:\s*"([a-z0-9\-]+)"(?!\s*\|)')

def check_unions():
    """A *type* position lists two or more RIDs, or is a lone RID inside a type annotation
    (`declare const qualifier : {...}`). A *value* position is a single RID inside a
    `withQualifier({...})` or a named qualifier -- those select one concrete build and are reported
    informationally, because adding one is a packaging decision rather than a correctness fix."""
    for path in ALL_DSC:
        text = read(path)
        for m in UNION_RE.finditer(text):
            members = re.findall(r'"([a-z0-9\-]+)"', m.group(1))
            if "osx-x64" in members and "osx-arm64" not in members:
                line = text.count("\n", 0, m.start()) + 1
                fail(path, line, f"targetRuntime type union admits osx-x64 but not osx-arm64: {m.group(1)}")
        for m in SINGLE_RE.finditer(text):
            if m.group(1) != "osx-x64":
                continue
            line = text.count("\n", 0, m.start()) + 1
            # Type annotation with a single admissible RID: still a type position, still a failure.
            if _is_qualifier_type_annotation(text, m.start()):
                fail(path, line, "single-valued targetRuntime type annotation excludes osx-arm64")
            else:
                notes.append(f"{os.path.relpath(path, ROOT)}:{line}: value position selects osx-x64 "
                             f"(no osx-arm64 counterpart; packaging decision)")


def _enclosing_brace(text, pos):
    """Index of the innermost `{` still open at `pos`, or -1."""
    depth = 0
    i = pos - 1
    while i >= 0:
        c = text[i]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth == 0:
                return i
            depth -= 1
        i -= 1
    return -1


def _opens_type_literal(text, brace, depth=0):
    """Whether the `{` at index `brace` opens a *type* literal rather than a value literal.

    Decided by what immediately precedes the brace. The one genuinely ambiguous form is `NAME: {`,
    which is a property type annotation inside an interface but an ordinary property inside an
    object literal -- config.dsc's 30 named qualifiers are exactly that. It is resolved by recursing
    on the enclosing construct rather than by adding another pattern, because the two forms are
    textually identical and only the context distinguishes them.
    """
    if brace < 0 or depth > 8:
        return False
    prefix = text[max(0, brace - 300):brace]
    if re.search(r'\binterface\s+\w+[^{;=]*$', prefix):          # interface X extends Y {
        return True
    if re.search(r'\btype\s+\w+\s*=\s*$', prefix):              # type X = {
        return True
    if re.search(r'\b(?:const|let|var)\s+\w+\s*:\s*$', prefix):  # declare const qualifier : {
        return True
    if re.search(r'\)\s*:\s*$', prefix):                         # ) : {   (return type)
        return True
    m = re.search(r'(\w+)\s*:\s*$', prefix)
    if m:
        if prefix[:m.start()].rstrip().endswith("("):             # f(q: {   (first parameter)
            return True
        return _opens_type_literal(text, _enclosing_brace(text, brace), depth + 1)
    return False


def _is_qualifier_type_annotation(text, pos):
    """True when `pos` sits inside a type literal.

    The enclosing construct is found by brace balance rather than by a bounded regex. Both member
    separators are in use in this repo -- `{ configuration: "debug", targetRuntime: "osx-x64" }` and
    the semicolon-separated form in BuildXL.SBOMUtilities.dsc, RuntimeContracts.dsc and
    rocksDbSharp.dsc -- so any pattern that cannot cross a `;` would classify half the repo's
    qualifier declarations as value positions and never fire on them.

    All type forms count, not just the inline `declare const qualifier : {...}`: Qualifiers.dsc is
    the canonical home of the RID unions and declares them through `interface` and `type`, so
    restricting this to the inline form would leave exactly the file that matters uncovered.

    Known gaps, all of which fail *safe* -- a type position downgraded to a note, never a false
    alarm on a value position -- and none of which has any precedent in the repo:

      * a non-first parameter, `f(a: X, q: { targetRuntime: ... })`
      * an intersection member, `interface X extends Base & { targetRuntime: ... }`
      * a non-first union member, `type T = A | { targetRuntime: ... }`
      * an inline anonymous cast, `<{ targetRuntime: ... }>y`

    The qualifier idiom here is uniformly `declare const qualifier : {...}` or a named `interface`,
    so closing these would add pattern surface for forms nobody writes -- and pattern surface is
    what produced the config.dsc false alarm this function was rewritten to remove.
    """
    return _opens_type_literal(text, _enclosing_brace(text, pos))


# ---------------------------------------------------------------- check 2/3: switches & ternaries
RID_TOKENS = ("osx-x64", "osx-arm64", "linux-x64", "win-x64")

def check_switches():
    for path in ALL_DSC:
        text = read(path)
        lines = text.splitlines()
        # Group consecutive `case "<rid>":` runs plus any switch body containing an osx-x64 case.
        for m in re.finditer(r'switch\s*\(([^)]*)\)\s*\{', text):
            subject = m.group(1)
            if "untime" not in subject and "Runtime" not in subject:
                continue
            # find matching closing brace
            depth = 0
            i = m.end() - 1
            while i < len(text):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            body = text[m.end():i]
            cases = set(re.findall(r'case\s+"([a-z0-9\-]+)"', body))
            if "osx-x64" in cases and "osx-arm64" not in cases:
                line = text.count("\n", 0, m.start()) + 1
                # The window runs from 600 characters before the switch to the closing brace, so an
                # annotation placed on the `default:` arm is found regardless of how long the
                # comment above the switch grows. Prefer that placement: a marker sitting above the
                # switch silently drops out of range when someone expands the prose, which is
                # exactly how this check once started failing on its own annotations.
                if DELIBERATE in text[max(0, m.start() - 600):i]:
                    notes.append(f"{os.path.relpath(path, ROOT)}:{line}: deliberate osx-arm64 exclusion in switch")
                else:
                    fail(path, line, f"switch({subject.strip()}) handles osx-x64 but not osx-arm64")

        # Ternary / boolean chains: any *statement* mentioning osx-x64 alongside targetRuntime.
        for idx, ln in enumerate(lines, start=1):
            if "osx-x64" not in ln:
                continue
            if "case " in ln or "targetRuntime" not in ln:
                continue
            # only care about comparisons, not package ids or paths
            if not re.search(r'targetRuntime\s*(===|!==)\s*"osx-x64"', ln) and \
               not re.search(r'"osx-x64"\s*(===|!==)\s*qualifier\.targetRuntime', ln):
                continue
            window = "\n".join(lines[max(0, idx - 8):idx + 8])
            # A bare mention of the token is not enough: a comment explaining an exclusion contains
            # it too. Require an actual comparison against osx-arm64.
            if re.search(r'(===|!==|case)\s*"osx-arm64"', window) or \
               re.search(r'"osx-arm64"\s*(===|!==)', window) or \
               re.search(r'\[[^\]]*"osx-arm64"[^\]]*\]\s*\.indexOf', window):
                continue
            if DELIBERATE in window:
                notes.append(f"{os.path.relpath(path, ROOT)}:{idx}: deliberate osx-arm64 exclusion")
                continue
            fail(path, idx, "compares targetRuntime to osx-x64 with no osx-arm64 counterpart nearby")


# ---------------------------------------------------------------- check 4: nuget package ids exist
def declared_package_ids():
    ids = set()
    for fn in ("config.dsc", "config.nuget.dotnetcore.dsc", "config.nuget.aspNetCore.dsc",
               "config.nuget.vssdk.dsc"):
        p = os.path.join(ROOT, fn)
        if not os.path.exists(p):
            continue
        text = read(p)
        for m in re.finditer(r'id\s*:\s*"([^"]+)"', text):
            ids.add(m.group(1))
        # `alias` re-exports a package under a different importFrom name
        for m in re.finditer(r'alias\s*:\s*"([^"]+)"', text):
            ids.add(m.group(1))
    return ids


def module_names():
    names = set()
    for path in ALL_DSC:
        if not path.endswith("module.config.bm") and not path.endswith("module.config.dsc"):
            continue
        text = read(path)
        for m in re.finditer(r'name\s*:\s*"([^"]+)"', text):
            names.add(m.group(1))
    return names


def check_imports():
    ids = declared_package_ids()
    mods = module_names()
    cfg = read(os.path.join(ROOT, "config.dsc"))
    downloads = set(re.findall(r'moduleName\s*:\s*"([^"]+)"', cfg))
    known = ids | mods | downloads
    if not ids:
        fail(os.path.join(ROOT, "config.dsc"), 0, "no package ids parsed - checker is broken")
        return
    seen = defaultdict(list)
    for path in ALL_DSC:
        text = read(path)
        for m in re.finditer(r'importFrom\(\s*"([^"]*arm64[^"]*)"\s*\)', text):
            name = m.group(1)
            line = text.count("\n", 0, m.start()) + 1
            seen[name].append((path, line))
    for name, sites in sorted(seen.items()):
        if name in known:
            continue
        for path, line in sites:
            fail(path, line, f'importFrom("{name}") refers to no declared package or module')


# ---------------------------------------------------------------- check 5: download ids
def check_downloads():
    cfg = read(os.path.join(ROOT, "config.dsc"))
    download_ids = set(re.findall(r'moduleName\s*:\s*"([^"]+)"', cfg))
    referenced = set()
    for path in ALL_DSC:
        text = read(path)
        for m in re.finditer(r'importFrom\(\s*"(DotNet-Runtime[^"]*|NodeJs\.[^"]*)"\s*\)', text):
            referenced.add((m.group(1), path, text.count("\n", 0, m.start()) + 1))
    mods = module_names()
    for name, path, line in sorted(referenced):
        if name not in download_ids and name not in mods:
            fail(path, line, f'importFrom("{name}") is not a declared download module')


# ---------------------------------------------------------------- check 6: named qualifiers
def check_named_qualifiers():
    frameworks = read(os.path.join(ROOT, "Public/Sdk/Public/Managed/Shared/frameworks.dsc"))
    m = re.search(r'export\s+type\s+RuntimeVersion\s*=\s*([^;]+);', frameworks)
    if not m:
        fail(os.path.join(ROOT, "Public/Sdk/Public/Managed/Shared/frameworks.dsc"), 0,
             "could not parse RuntimeVersion union")
        return
    allowed = set(re.findall(r'"([a-z0-9\-]+)"', m.group(1)))
    if "osx-arm64" not in allowed:
        fail(os.path.join(ROOT, "Public/Sdk/Public/Managed/Shared/frameworks.dsc"), 0,
             "RuntimeVersion does not include osx-arm64")
    cfg = read(os.path.join(ROOT, "config.dsc"))
    for m in re.finditer(r'targetRuntime\s*:\s*"([a-z0-9\-]+)"', cfg):
        if m.group(1) not in allowed:
            line = cfg.count("\n", 0, m.start()) + 1
            fail(os.path.join(ROOT, "config.dsc"), line,
                 f'qualifier targetRuntime "{m.group(1)}" is not in RuntimeVersion')
    return allowed


# ---------------------------------------------------------------- check 7: runtime framework arms
def check_framework_specs():
    for ver in ("8", "9", "10", "11"):
        p = os.path.join(ROOT, f"Public/Sdk/Public/Managed/Frameworks/net{ver}/net{ver}.0.dsc")
        if not os.path.exists(p):
            notes.append(f"net{ver}.0.dsc not present, skipped")
            continue
        text = read(p)
        if 'case "osx-arm64"' not in text:
            fail(p, 0, "runtimeContentProvider has no osx-arm64 case")
        if "osxArm64RuntimeFiles" not in text:
            fail(p, 0, "no osxArm64RuntimeFiles declaration")


# ---------------------------------------------------------------- check 8: host arch plumbed
def check_host_arch():
    ihost = os.path.join(ROOT, "Public/Src/Utilities/Configuration/IHost.cs")
    if "Arm64" not in read(ihost):
        fail(ihost, 0, "HostCpuArchitecture has no Arm64 member")
    host = os.path.join(ROOT, "Public/Src/Utilities/Configuration/Mutable/Host.cs")
    t = read(host)
    if "RuntimeInformation.ProcessArchitecture" not in t:
        fail(host, 0, "CurrentCpuArchitecture does not consult RuntimeInformation.ProcessArchitecture")
    amb = os.path.join(ROOT, "Public/Src/FrontEnd/Script/Ambients/AmbientContext.cs")
    if "arm64" not in read(amb):
        fail(amb, 0, 'AmbientContext does not map Arm64 to "arm64"')
    prelude = os.path.join(ROOT, "Public/Sdk/Public/Prelude/Prelude.Context.dsc")
    if '"arm64"' not in read(prelude):
        fail(prelude, 0, "Prelude cpuArchitecture union has no arm64")


# ------------------------------------------------- check 9: configuration-phase prelude window
# Configuration specs are type checked against the prelude deployed *inside the running engine*
# (PreludeManager.GetPreludeRoot -> <engine>/Sdk.Prelude), never against this repo's
# Public/Sdk/Public/Prelude. They have to be: the engine cannot know where the repo's prelude lives
# until it has type checked the config that declares it. config.dsc:31 registers the repo prelude,
# but that only takes effect for the main workspace, which is why every other spec may use new
# prelude vocabulary freely.
#
# The consequence is a one-release window: config.dsc is always parsed by the *previous* LKG's
# prelude, so referencing a literal that this change introduces is a configuration parse error
# (DX9234 / TS2365) rather than a bad qualifier -- it fails the whole build, including this change's
# own PR validation. Found the hard way; see MacOsSandbox.md 10.6.
def configuration_specs():
    """config.dsc plus everything transitively reachable from it through importFile."""
    seen, queue = set(), ["config.dsc"]
    while queue:
        rel = queue.pop()
        if rel in seen:
            continue
        path = os.path.join(ROOT, rel)
        if not os.path.isfile(path):
            continue
        seen.add(rel)
        for m in re.finditer(r"importFile\(\s*f`([^`]+)`", read(path)):
            queue.append(m.group(1))
    return sorted(seen)


def check_config_prelude_window():
    specs = configuration_specs()
    if "config.dsc" not in specs:
        fail(os.path.join(ROOT, "config.dsc"), 0, "root configuration spec not found")
        return
    # Both operand orders, and both the strict and loose forms the checker treats alike.
    patterns = [
        r'cpuArchitecture\s*[=!]==?\s*("[^"]*")',
        r'("[^"]*")\s*[=!]==?\s*[A-Za-z0-9_.()]*cpuArchitecture',
    ]
    for rel in specs:
        path = os.path.join(ROOT, rel)
        text = read(path)
        for pattern in patterns:
            for m in re.finditer(pattern, text):
                if m.group(1) in NEW_PRELUDE_LITERALS:
                    fail(path, text[:m.start()].count("\n") + 1,
                         f"configuration-phase spec compares cpuArchitecture against {m.group(1)}, "
                         "which the shipped engine's prelude does not declare. This is parsed by "
                         "<engine>/Sdk.Prelude, not the repo prelude, so it is a configuration parse "
                         'error on every engine built before this change. Test "not x86-family" '
                         "instead.")
    notes.append(f"{len(specs)} configuration-phase spec(s) checked against the shipped prelude")


# ------------------------------------------------------ check 10: runtime identifier tables in C#
# Checks 1-7 only read DScript, which is a real blind spot: the engine also carries hardcoded runtime
# identifier tables, and those decide what the *DScript* is even allowed to say.
# NugetFrameworkMonikers.SupportedTargetRuntimes is the worst offender -- it becomes the literal union
# of the generated `targetRuntime` qualifier on every NuGet package, and its KnownTargetRuntimeAtoms
# decides whether `runtimes/<rid>/lib/<tfm>` assemblies are treated as managed. Omitting a runtime
# there does not produce a missing-case error; it silently downgrades every runtime pack for that
# identifier to an unmanaged NugetPackage, and the failure surfaces far away as DX11231 in web.dsc.
#
# The rule is textual and deliberately broad: any C# file that spells out all three of the existing
# runtime identifiers is enumerating them, so it must account for osx-arm64 too.
def cs_files():
    skip = {"bin", "obj", "Out", ".git", "node_modules"}
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            if name.endswith(".cs"):
                yield os.path.join(dirpath, name)


def check_cs_runtime_tables():
    required = ('"win-x64"', '"osx-x64"', '"linux-x64"')
    scanned = 0
    for path in cs_files():
        text = read(path)
        if not all(token in text for token in required):
            continue
        scanned += 1
        if '"osx-arm64"' in text or DELIBERATE in text:
            continue
        line = text[:text.index(required[1])].count("\n") + 1
        fail(path, line,
             "enumerates every runtime identifier but omits osx-arm64; a runtime missing from an "
             "engine-side table is not a compile error, it silently downgrades that runtime's NuGet "
             "packages to unmanaged (DX11231) or picks the wrong assets")
    if scanned:
        notes.append(f"{scanned} C# runtime identifier table(s) checked")


def main():
    check_unions()
    check_switches()
    check_imports()
    check_downloads()
    check_named_qualifiers()
    check_framework_specs()
    check_host_arch()
    check_config_prelude_window()
    check_cs_runtime_tables()

    for n in notes:
        print(f"note: {n}")
    if failures:
        print(f"\n{len(failures)} problem(s):\n")
        for f in failures:
            print(f"  {f}")
        return 1
    print(f"\nosx-arm64 completeness: OK ({len(ALL_DSC)} DScript files scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
