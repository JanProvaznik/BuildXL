#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Reports whether this machine can run the Endpoint Security sandbox, whether it can run .NET, and
# therefore whether it can run BuildXL under the ES sandbox at all.
#
# The third question is not the conjunction of the first two, which is the point of this script.
# Honouring `com.apple.developer.endpoint-security.client` from an ad-hoc signature requires AMFI to
# be disabled - but AMFI is also what grants code-signing exemptions, and CoreCLR needs one: it
# calls mprotect(PROT_READ|PROT_WRITE) on a page inside libcoreclr.dylib's own image. With AMFI out
# of the way that call returns EACCES and every .NET process fails to start with
# "Failed to create CoreCLR, HRESULT: 0x8007000C".
#
# So a machine relaxed enough to test the sandbox may be too relaxed to run the engine. Run this
# before concluding that either one is broken.
#
# Usage:
#   es-capability.sh [--broker PATH] [--dotnet PATH]

set -uo pipefail

BROKER="${BXL_ES_BROKER:-}"
DOTNET="${DOTNET_HOST:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --broker) BROKER="$2"; shift 2 ;;
        --dotnet) DOTNET="$2"; shift 2 ;;
        *) echo "es-capability.sh: unexpected argument '$1'" >&2; exit 2 ;;
    esac
done

[[ -z "$DOTNET" ]] && DOTNET="$(command -v dotnet || echo "$HOME/.dotnet/dotnet")"

echo "=== machine ==="
echo "  macOS            $(sw_vers -productVersion) ($(sw_vers -buildVersion)) $(uname -m)"
echo "  SIP              $(csrutil status 2>&1 | sed 's/System Integrity Protection status: //')"

BOOTARGS=$(nvram boot-args 2>/dev/null | sed 's/^boot-args[[:space:]]*//')
if [[ -z "$BOOTARGS" ]]; then
    echo "  boot-args        (none) -> AMFI enforcing"
    AMFI_OFF=0
else
    echo "  boot-args        $BOOTARGS"
    [[ "$BOOTARGS" == *amfi_get_out_of_my_way* ]] && AMFI_OFF=1 || AMFI_OFF=0
fi

echo
echo "=== can .NET start? ==="
if [[ -x "$DOTNET" ]]; then
    OUTPUT=$("$DOTNET" --version 2>&1)
    STATUS=$?
    if [[ $STATUS -eq 0 ]]; then
        echo "  YES              $DOTNET reports $OUTPUT"
        DOTNET_OK=1
    else
        echo "  NO               $(echo "$OUTPUT" | head -1)"
        # The signature of the AMFI interaction, as opposed to a broken install.
        if [[ "$OUTPUT" == *0x8007000C* && $AMFI_OFF -eq 1 ]]; then
            echo "                   this is the AMFI interaction: CoreCLR cannot mprotect its own"
            echo "                   image without a code-signing exemption, and AMFI is disabled"
        fi
        DOTNET_OK=0
    fi
else
    echo "  UNKNOWN          no dotnet host at $DOTNET"
    DOTNET_OK=0
fi

echo
echo "=== can an Endpoint Security client start? ==="
if [[ -z "$BROKER" ]]; then
    echo "  UNKNOWN          pass --broker PATH or set BXL_ES_BROKER"
    ES_OK=-1
elif [[ ! -x "$BROKER" ]]; then
    echo "  UNKNOWN          '$BROKER' is not executable"
    ES_OK=-1
else
    if ! codesign -d --entitlements - "$BROKER" 2>&1 | grep -q "endpoint-security.client"; then
        echo "  NO               the broker carries no ES entitlement; sign it first:"
        echo "                     codesign --force --sign - --entitlements <ent.plist> $BROKER"
        ES_OK=0
    else
        # --probe-es tries both clients and exits. Both are shown because the difference is the
        # whole reason this design needs macOS 27: the system-wide client requires root, the
        # descendants client does not, and only the second is usable by a build.
        OUTPUT=$("$BROKER" --probe-es 2>&1)
        echo "$OUTPUT" | grep -E "^(system-wide|descendants) client:" | sed 's/^/  /'

        if [[ "$OUTPUT" == *"es client ok"* ]]; then
            echo "  YES              a descendants client starts, as an unprivileged user"
            ES_OK=1
        elif [[ "$OUTPUT" == *"descendants client: not entitled"* ]]; then
            echo "  NO               the entitlement is present in the signature but not honoured."
            echo "                   Either install a real provisioned entitlement, or relax AMFI"
            echo "                   (which will cost you .NET - see above, and section 16.7)"
            ES_OK=0
        else
            echo "  NO               $(echo "$OUTPUT" | tail -1)"
            ES_OK=0
        fi
    fi
fi

echo
echo "=== verdict ==="
if [[ $ES_OK -eq 1 && $DOTNET_OK -eq 1 ]]; then
    echo "  Both. BuildXL can be run end to end on the ES backend from this machine."
elif [[ $ES_OK -eq 1 && $DOTNET_OK -eq 0 ]]; then
    echo "  ES only. The sandbox can be measured directly, but no BuildXL build will start."
    echo "  To get .NET back, restore AMFI and reboot:  sudo nvram -d boot-args"
    echo "  Doing so is expected to cost the ES client unless a real Apple entitlement is installed."
elif [[ $ES_OK -eq 0 && $DOTNET_OK -eq 1 ]]; then
    echo "  .NET only. BuildXL runs, but only the interposition backend is available."
    echo "  This is the normal state of a developer Mac, and section 13's numbers were taken here."
else
    echo "  Neither. Check the two sections above."
fi
