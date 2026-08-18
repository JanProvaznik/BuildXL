#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# ci-preflight.sh - will this machine run BuildXL's Endpoint Security sandbox for real work?
#
# es-check.sh answers "can Endpoint Security work here", building and signing a probe from source.
# This script answers the operational question instead: is *this* machine, as provisioned right now,
# able to run a real sandboxed build - and if not, exactly which step is missing.
#
# The distinction that matters most, because it is the one people get wrong:
#
#   Disabling SIP is NOT sufficient.
#
# SIP and AMFI are separate subsystems. The Endpoint Security entitlement is a restricted
# entitlement, and AMFI is what validates it against the signing certificate; an ad-hoc signature has
# no certificate, so AMFI rejects it no matter what SIP is set to. Disabling SIP only makes it
# *possible* to set amfi_get_out_of_my_way=0x1 in boot-args, because writing boot-args is itself
# gated by SIP. So the sequence is: disable SIP -> set the AMFI boot-arg -> reboot. Skipping the
# second step leaves the sandbox silently falling back to interposition.
#
# Relaxing AMFI then has a consequence that is easy to miss and fatal in CI: it breaks CoreCLR.
# Every .NET runtime on the machine must have SG_READ_ONLY cleared on __DATA_CONST, or the runtime
# is SIGKILLed at startup with "Failed to create CoreCLR, HRESULT: 0x8007000C". That is not a
# one-time setup step - it must be re-applied every time a .NET SDK or runtime is installed or
# updated, which is why it is checked here rather than assumed.
#
# None of this is needed by a machine whose broker is signed with a certificate that actually
# carries com.apple.developer.endpoint-security.client. With the real entitlement, SIP stays on,
# AMFI stays on, and .NET is untouched. That is the only configuration worth running a CI fleet in,
# and this script says so when it sees one.
#
#   ./ci-preflight.sh                  check the broker in the default dev deployment
#   ./ci-preflight.sh <path-to-broker> check a specific broker binary
#
# Exit codes: 0 ready for real builds, 1 a precondition is missing.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../../../.." && pwd)"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m    %s\n' "$*"; }
warn() { printf '  \033[33mwarn\033[0m  %s\n' "$*"; }
bad()  { printf '  \033[31mno\033[0m    %s\n' "$*"; }

FAILURES=0
fail() { bad "$*"; FAILURES=$((FAILURES + 1)); }

# Prefer the bundled broker, matching what BuildXL itself does: a profile can only live inside a
# bundle, so that is the form a properly entitled deployment takes.
BROKER="${1:-}"
if [[ -z "$BROKER" ]]; then
    if [[ -x "$REPO_ROOT/Out/Selfhost/Dev/bxl-es-broker.app/Contents/MacOS/bxl-es-broker" ]]; then
        BROKER="$REPO_ROOT/Out/Selfhost/Dev/bxl-es-broker.app/Contents/MacOS/bxl-es-broker"
    else
        BROKER="$REPO_ROOT/Out/Selfhost/Dev/bxl-es-broker"
    fi
fi

# codesign reports a bundle's signature from the bundle, not from the executable inside it, so
# signature questions are asked of whichever of the two actually carries the seal.
SIGN_TARGET="$BROKER"
case "$BROKER" in
    */bxl-es-broker.app/Contents/MacOS/bxl-es-broker) SIGN_TARGET="${BROKER%/Contents/MacOS/bxl-es-broker}" ;;
esac

# ------------------------------------------------------------------ operating system

bold "Operating system"
OS_VERSION="$(sw_vers -productVersion)"
OS_MAJOR="${OS_VERSION%%.*}"
if (( OS_MAJOR >= 27 )); then
    ok "macOS $OS_VERSION - es_new_descendants_client is available"
else
    fail "macOS $OS_VERSION - es_new_descendants_client needs macOS 27 or newer"
fi

# ------------------------------------------------------------------ the broker itself

echo
bold "Broker"
if [[ -x "$BROKER" ]]; then
    ok "found $BROKER"
    [[ "$SIGN_TARGET" != "$BROKER" ]] && ok "bundled, so it can carry a provisioning profile"
else
    fail "no broker at $BROKER (build it, or pass its path as an argument)"
fi

ENTITLED_BINARY=0
if [[ -x "$BROKER" ]]; then
    if codesign -dv "$SIGN_TARGET" >/dev/null 2>&1; then
        # An unsigned broker cannot hold an entitlement at all, so it always falls back to
        # interposition - which still builds, just without the guarantees, and without saying so.
        if codesign -d --entitlements - --xml "$SIGN_TARGET" 2>/dev/null | grep -q 'endpoint-security.client'; then
            ok "signed and carries com.apple.developer.endpoint-security.client"
            # An ad-hoc signature carries the entitlement but no certificate to justify it, which is
            # exactly what AMFI refuses. Distinguish the two, because they need opposite machines.
            if codesign -dv "$SIGN_TARGET" 2>&1 | grep -qi 'Signature=adhoc'; then
                warn "signature is ad-hoc, so this broker only works on an AMFI-relaxed machine"
            else
                ENTITLED_BINARY=1
                ok "signed with a real identity - no SIP or AMFI changes should be required"
            fi
        else
            fail "broker carries no Endpoint Security entitlement; it would silently use interposition"
        fi
    else
        fail "broker is unsigned; it would silently use interposition"
    fi
fi

# ------------------------------------------------------------------ platform gates

echo
bold "Platform gates"
SIP_DISABLED=0
csrutil status 2>/dev/null | grep -qi 'disabled' && SIP_DISABLED=1

AMFI_RELAXED=0
BOOT_ARGS="$(nvram boot-args 2>/dev/null | sed 's/^boot-args[[:space:]]*//')"
[[ "$BOOT_ARGS" == *amfi_get_out_of_my_way* ]] && AMFI_RELAXED=1

if (( ENTITLED_BINARY )); then
    ok "broker is properly entitled, so SIP and AMFI can stay enabled"
    (( SIP_DISABLED )) && warn "SIP is disabled but does not need to be - consider re-enabling it"
else
    # This is the block that answers "is disabling SIP enough". It is not.
    if (( SIP_DISABLED )); then
        ok "SIP disabled"
    else
        fail "SIP is enabled, so the AMFI boot-arg below cannot be set"
    fi

    if (( AMFI_RELAXED )); then
        ok "amfi_get_out_of_my_way is set"
    else
        fail "amfi_get_out_of_my_way is NOT set - disabling SIP alone does not grant restricted entitlements"
        printf '        sudo nvram boot-args="amfi_get_out_of_my_way=0x1"   then reboot\n'
    fi
fi

# ------------------------------------------------------------------ the .NET consequence

echo
bold ".NET runtimes"
# This check deliberately does not depend on having successfully read the AMFI state. An earlier
# version skipped it whenever AMFI looked unrelaxed, which meant a failed `nvram` read - something
# that simply returns nothing rather than erroring - turned an unknown into a green tick on the one
# check whose failure mode is a SIGKILL. An unknown must never produce a pass, so the patch state is
# always measured; only a properly entitled broker, which needs no AMFI change at all, excuses it.
DOTNET_HOME="${DOTNET_ROOT:-$HOME/.dotnet}"
if [[ ! -d "$DOTNET_HOME" ]]; then
    warn "no .NET at $DOTNET_HOME; set DOTNET_ROOT to check the runtime this build will use"
elif python3 "$SCRIPT_DIR/relax-dataconst.py" --check "$DOTNET_HOME" >/dev/null 2>&1; then
    ok "every CoreCLR under $DOTNET_HOME has __DATA_CONST relaxed"
elif (( ENTITLED_BINARY )); then
    ok "CoreCLR is unpatched under $DOTNET_HOME, which is correct for an entitled broker"
else
    fail "a CoreCLR under $DOTNET_HOME is unpatched - it will be SIGKILLed with HRESULT 0x8007000C"
    printf '        python3 %s %s\n' "$SCRIPT_DIR/relax-dataconst.py" "$DOTNET_HOME"
    printf '        (re-apply after every .NET SDK or runtime update)\n'
fi

# ------------------------------------------------------------------ toolchain

echo
bold "Toolchain"
if [[ "$(uname -m)" == "arm64" ]]; then
    # grpc publishes linux_arm64 tooling but no macosx_arm64, so protoc and grpc_csharp_plugin are
    # x86_64 and need Rosetta. This is a real build blocker, not a sandbox one.
    if arch -x86_64 /usr/bin/true >/dev/null 2>&1; then
        ok "Rosetta 2 present - the x86_64 grpc tooling can run"
    else
        fail "Rosetta 2 missing - protoc and grpc_csharp_plugin are x86_64 only"
        printf '        softwareupdate --install-rosetta --agree-to-license\n'
    fi
fi

# ------------------------------------------------------------------ ground truth

echo
bold "Live check"
# Everything above is diagnosis. This is the only result that actually decides the question, because
# it asks the kernel rather than inferring from configuration.
if [[ -x "$BROKER" ]]; then
    PROBE="$("$BROKER" --probe-es 2>&1)"
    if grep -q 'descendants client: success' <<<"$PROBE"; then
        ok "es_new_descendants_client succeeded - the sandbox will observe real builds"
    else
        fail "es_new_descendants_client did not succeed:"
        sed 's/^/        /' <<<"$PROBE" | head -6
    fi
else
    fail "no broker to probe"
fi

# ------------------------------------------------------------------ verdict

echo
if (( FAILURES == 0 )); then
    bold "Ready: this machine can run sandboxed BuildXL builds."
    exit 0
fi

bold "Not ready: $FAILURES precondition(s) missing (listed above)."
exit 1
