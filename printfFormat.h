/*
    SysmonCommon

    Copyright (c) Microsoft Corporation

    All rights reserved.

    MIT License

    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the ""Software""), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

//====================================================================
//
// PrintfFormat.h
//
// Specifies printf format specifiers (%d, %ld, etc) that differ
// between Linux and Windows to permit the same code to be compiled
// on both without needing extra ifdefs around printf-family
// statements.
//
//====================================================================
#pragma once

#if defined _WIN64 || defined _WIN32

#define PRINTF_LONG_FS          "%ld"
#define PRINTF_ULONG_FS         "%lu"
#define PRINTF_LONGLONG_FS      "%lld"
#define PRINTF_ULONGLONG_FS     "%llu"
#define PRINTF_ULONG64_FS       "%I64u"

#elif defined __linux__

#define PRINTF_LONG_FS          "%d"
#define PRINTF_ULONG_FS         "%u"
#define PRINTF_LONGLONG_FS      "%ld"
#define PRINTF_ULONGLONG_FS     "%lu"
#define PRINTF_ULONG64_FS       "%" PRIu64


#endif


