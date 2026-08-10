#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# es-check.sh - can this machine run the BuildXL Endpoint Security sandbox, and if not, why not?
#
# The broker needs com.apple.developer.endpoint-security.client. That entitlement is granted by
# Apple per developer account, which makes it the one part of this work that cannot be unblocked
# by writing code. This script reports exactly which precondition is missing, signs the probe with
# the best identity it can find, and runs a real end-to-end check.
#
#   ./es-check.sh              diagnose, build, sign, run
#   ./es-check.sh --diagnose   report only, build nothing
#
# Exit codes: 0 Endpoint Security is usable, 1 a precondition is missing, 2 could not build.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${TMPDIR:-/tmp}/bxl-es-check.$$"
DIAGNOSE_ONLY=0
[[ "${1:-}" == "--diagnose" ]] && DIAGNOSE_ONLY=1

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
ok()    { printf '  \033[32mok\033[0m    %s\n' "$*"; }
warn()  { printf '  \033[33mwarn\033[0m  %s\n' "$*"; }
bad()   { printf '  \033[31mno\033[0m    %s\n' "$*"; }

# ---------------------------------------------------------------- machine facts

bold "Machine"
OS_VERSION="$(sw_vers -productVersion)"
OS_MAJOR="${OS_VERSION%%.*}"
printf '  macOS %s (%s), %s\n' "$OS_VERSION" "$(sw_vers -buildVersion)" "$(sysctl -n machdep.cpu.brand_string)"

if (( OS_MAJOR >= 27 )); then
    ok "macOS 27+, es_new_descendants_client and deadline control are available"
else
    bad "macOS $OS_MAJOR: es_new_descendants_client needs 27+. The broker will not build against this SDK."
fi

SDK_PATH="$(xcrun --show-sdk-path 2>/dev/null)"
if [[ -f "$SDK_PATH/usr/include/EndpointSecurity/EndpointSecurity.h" ]]; then
    ok "EndpointSecurity headers present in $(basename "$SDK_PATH")"
else
    ALT="$(ls -d /Library/Developer/CommandLineTools/SDKs/MacOSX*.sdk 2>/dev/null \
        | while read -r d; do [[ -f "$d/usr/include/EndpointSecurity/EndpointSecurity.h" ]] && echo "$d"; done | tail -1)"
    if [[ -n "$ALT" ]]; then
        warn "default SDK has no EndpointSecurity headers; using $ALT"
        SDK_PATH="$ALT"
    else
        bad "no SDK on this machine ships EndpointSecurity headers"
    fi
fi

# ---------------------------------------------------------------- signing posture

echo
bold "Signing"

SIP_ON=1
csrutil status 2>/dev/null | grep -qi 'disabled' && SIP_ON=0
if (( SIP_ON )); then
    warn "SIP enabled - AMFI will SIGKILL an ad-hoc binary carrying a restricted entitlement"
else
    ok "SIP disabled"
fi

AMFI_OFF=0
BOOT_ARGS="$(nvram boot-args 2>/dev/null | sed 's/^boot-args[[:space:]]*//')"
if [[ "$BOOT_ARGS" == *amfi_get_out_of_my_way* ]]; then
    AMFI_OFF=1
    ok "amfi_get_out_of_my_way is set in boot-args"
else
    warn "amfi_get_out_of_my_way is not set (boot-args: ${BOOT_ARGS:-none})"
fi

# A real identity that carries the entitlement beats every workaround.
IDENTITY=""
while IFS= read -r line; do
    [[ "$line" =~ \"(Developer\ ID\ Application:[^\"]*|Apple\ Development:[^\"]*)\" ]] && { IDENTITY="${BASH_REMATCH[1]}"; break; }
done < <(security find-identity -v -p codesigning 2>/dev/null)

if [[ -n "$IDENTITY" ]]; then
    ok "signing identity: $IDENTITY"
else
    warn "no Developer ID or Apple Development identity in the keychain; will sign ad-hoc"
fi

PROFILES_DIR="$HOME/Library/MobileDevice/Provisioning Profiles"
PROFILE_WITH_ES=""
if [[ -d "$PROFILES_DIR" ]]; then
    while IFS= read -r p; do
        if security cms -D -i "$p" 2>/dev/null | grep -q 'endpoint-security.client'; then
            PROFILE_WITH_ES="$p"; break
        fi
    done < <(find "$PROFILES_DIR" -name '*.provisionprofile' -o -name '*.mobileprovision' 2>/dev/null)
fi
if [[ -n "$PROFILE_WITH_ES" ]]; then
    ok "provisioning profile granting the entitlement: $(basename "$PROFILE_WITH_ES")"
else
    warn "no installed provisioning profile grants com.apple.developer.endpoint-security.client"
fi

# ---------------------------------------------------------------- verdict

echo
bold "Verdict"
VIABLE=0
if [[ -n "$IDENTITY" && -n "$PROFILE_WITH_ES" ]]; then
    ok "properly entitled. This is the configuration CI should use."
    VIABLE=1
elif (( SIP_ON == 0 && AMFI_OFF == 1 )); then
    ok "AMFI is out of the way, so an ad-hoc entitled signature should be accepted."
    VIABLE=1
else
    bad "Endpoint Security cannot run yet. Two ways forward:"
    cat <<'EOF'

  A. Get the entitlement from Apple. This is what production and CI need.
       1. An Apple Developer Program membership (Organization, for a company).
       2. Request it at https://developer.apple.com/contact/request/system-extension/
          Ask for com.apple.developer.endpoint-security.client and describe the use:
          a build system observing file accesses of its own child processes to decide
          what to cache. Turnaround is typically days to a few weeks.
       3. When granted, add it to the App ID, regenerate the provisioning profile,
          install it, and re-run this script.

  B. Turn AMFI off locally. Fastest path to a real measurement, unsuitable for CI,
     and it lowers the security of the machine - prefer a throwaway machine or a VM.
       1. Shut down. Hold the power button until "Loading startup options".
       2. Options -> Utilities -> Startup Security Utility -> pick the volume ->
          Security Policy -> Reduced Security.
       3. Utilities -> Terminal:   csrutil disable
       4. Reboot, then:            sudo nvram boot-args=amfi_get_out_of_my_way=0x1
       5. Reboot again and re-run this script.
     To undo: sudo nvram -d boot-args, then csrutil enable from Recovery, then set the
     Security Policy back to Full Security.

  A VM is the sensible middle ground: macOS 27 guests on Apple silicon can have SIP
  and AMFI relaxed without touching the host. Any Virtualization.framework runner works.
EOF
fi

(( DIAGNOSE_ONLY )) && exit $(( VIABLE ? 0 : 1 ))

# ---------------------------------------------------------------- build, sign, run

echo
bold "Probe"
mkdir -p "$WORK_DIR"

if ! clang -isysroot "$SDK_PATH" -O1 -lEndpointSecurity \
        -o "$WORK_DIR/es-probe" "$SCRIPT_DIR/es-probe.c" 2>"$WORK_DIR/build.log"; then
    bad "build failed"
    sed 's/^/    /' "$WORK_DIR/build.log" | head -20
    exit 2
fi
ok "built"

cat > "$WORK_DIR/es.entitlements" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.endpoint-security.client</key>
    <true/>
</dict>
</plist>
EOF

SIGN_AS="${IDENTITY:--}"
if codesign --force --timestamp=none --options runtime \
        --sign "$SIGN_AS" --entitlements "$WORK_DIR/es.entitlements" \
        "$WORK_DIR/es-probe" 2>"$WORK_DIR/sign.log"; then
    ok "signed with ${IDENTITY:-ad-hoc}"
else
    bad "codesign failed"
    sed 's/^/    /' "$WORK_DIR/sign.log" | head -10
    exit 2
fi

echo
"$WORK_DIR/es-probe"
PROBE_STATUS=$?

if (( PROBE_STATUS == 137 )) || (( PROBE_STATUS == 9 )); then
    echo
    bad "SIGKILL. AMFI rejected the entitlement, which is expected with SIP on and no profile."
    bad "See the two options above."
fi

exit $PROBE_STATUS
