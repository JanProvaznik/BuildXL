// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// stdafx-mac-es.h : mac-specific stdafx for the user-space Endpoint Security sandbox (bxl-es-broker).
//
// This is the macOS analogue of stdafx-linux.h. It exists so that the policy engine that is shared
// with the Linux and Windows sandboxes (PolicyResult, PolicySearch, StringOperations,
// FilesCheckedForAccess, FileAccessManifest) compiles unchanged in a macOS user-space process.
//
// Do not confuse this with stdafx-mac-kext.h (kernel space, retired kernel extension) or
// stdafx-mac-interop.h (the libBuildXLInterop shim, which stubs out the ES types).

#pragma once

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <atomic>
#include <cstring>
#include <iostream>
#include <istream>
#include <memory>
#include <string>

#ifndef MAXPATHLEN
#define MAXPATHLEN PATH_MAX
#endif

#define BUILDXL_BUNDLE_IDENTIFIER "com.microsoft.buildxl.sandbox"
#define BUILDXL_CLASS_PREFIX "com_microsoft_buildxl_"

#define __cdecl

// The shared policy code uses os_log macros that only exist in the kext build.
#define os_log_error
#define os_log
