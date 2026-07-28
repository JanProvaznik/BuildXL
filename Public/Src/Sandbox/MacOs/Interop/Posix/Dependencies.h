// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef Dependencies_h
#define Dependencies_h

#include <mach/mach.h>
// mach_absolute_time and mach_timebase_info live here. Older macOS SDKs exposed them transitively
// through <mach/mach.h>; the macOS 26/27 SDKs do not, so process.c fails to compile without it.
#include <mach/mach_time.h>
#include <libproc.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#define GET_RUSAGE_ERROR    103
#define RUNTIME_ERROR       -1

#endif /* Dependencies_h */
