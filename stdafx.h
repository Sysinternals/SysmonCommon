/*
    SysmonCommon

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently

#pragma once
#if defined _WIN64 || defined _WIN32
#include "..\exe\windowsTypes.h"
#define NTDDI_WIN8                          0x06020000
#define NTDDI_VERSION NTDDI_WINBLUE
#include <SDKDDKVer.h>

// for signer.cpp
#pragma comment(lib, "Crypt32.lib")
#pragma warning(disable : 4127)
#pragma warning(disable : 4189)

#define _CRT_RAND_S
#include <Windows.h>
#include <VersionHelpers.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include <userenv.h>
#include <aclapi.h>
#include <accctrl.h>
#include <tchar.h>
#include <softpub.h>
#include <evntprov.h>
#include <Wtsapi32.h>
#include <tlhelp32.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <psapi.h>
#include <Rpcdce.h>
#include <stddef.h>
#include <lm.h>
#include <lmerr.h>
#include <conio.h>
#include "..\exe\windowsTypes.h"
#ifdef __cplusplus
#include <comdef.h>
#include <cctype>
#endif

#elif defined __linux__ // Linux
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <linux/limits.h>
#include <string.h>
#include "linuxTypes.h"
#include "linuxWideChar.h"
#include "linuxHelpers.h"

#define WCSLEN(a) WideStrlen(a)
#define WCSCHR(a,b) WideStrchr(a,b)
#define WCSSTR(a,b) WideStrstr(a,b)
#define WCSSPN(a,b) WideStrspn(a,b)
#define WCSRCHR(a,b) WideStrrchr(a,b)
#define WCSICMP(a,b) WideStrcasecmp(a,b)
#define WCSNICMP(a,b,c) WideStrncasecmp(a,b,c)
#define TOWLOWER(a) WideTolower(a)
#define TOWUPPER(a) WideToupper(a)
#define _strdup(a) strdup(a)

#endif
#ifdef __cplusplus
extern "C" {
#endif
#if defined _WIN64 || defined _WIN32
#include "ioctlcmd.h"
#include "..\sys\crypto.h"
#include "..\exe\pscommon.h"
#include "..\exe\resource.h"
#include "..\exe\sysmonevents.h"
#elif defined __linux__
#include "ioctlcmd.h"
#include "sysmonevents.h"
#endif
#include "service.h"
#ifdef __cplusplus
}
#endif

#if defined _WIN64 || defined _WIN32
#define Tstr2WstrV(tString) PCWSTR tString##_W = tString
#define Wstr2TstrV(wString) PCTSTR wString##_T = wString
#define Tstr2Wstr(tString) tString
#define Wstr2Tstr(wString) wString

#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32	0x00000800
#endif

//
// Disable this warning for release for signer.cpp on common
//
#ifndef _DEBUG
#pragma warning(disable : 4701)
#pragma warning(disable : 4703)
#endif
#endif
