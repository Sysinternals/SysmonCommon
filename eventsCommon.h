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
// EventsCommon.h
//
// Event processing code and process cache.
//
//====================================================================
#pragma once

#include <list>

//
// Delay until we purge it from the list (in seconds)
//
#define PROCESS_CACHE_FREE_DELAY_SEC	(1*60)

#define PROCESS_CACHE_FREE_DELAY     ((ULONG64)PROCESS_CACHE_FREE_DELAY_SEC * NT_ONE_SECOND)

#if defined __linux__
#include <string>
typedef std::string _bstr_t;

void EnterCriticalSection( CRITICAL_SECTION* p );

void LeaveCriticalSection( CRITICAL_SECTION* p );

#endif

typedef BOOL( WINAPI* tQueryFullProcessImageName )(
  _In_     HANDLE hProcess,
  _In_     DWORD dwFlags,
  _Out_    LPTSTR lpExeName,
  _Inout_  PDWORD lpdwSize
);

BOOLEAN TrimStringToNChars(
    _In_  PTCHAR field,
    _In_  int maxLength,
    _Out_ ULONG *size
    );

typedef struct {
	DWORD			ProcessId;
	LARGE_INTEGER	Timestamp;
	_bstr_t			QueryName;
	_bstr_t			QueryType;
	_bstr_t			QueryStatus;
	_bstr_t			QueryResult;
} DNS_QUERY_DATA, *PDNS_QUERY_DATA;

typedef std::list<DNS_QUERY_DATA *>	DNS_QUERY_DATA_LIST;

typedef struct {
	LIST_ENTRY 						list;
	GUID							uniqueProcessGUID;
	LARGE_INTEGER					removedTime;
	DNS_QUERY_DATA_LIST				*dnsQueryCache;
	// must be last
	SYSMON_PROCESS_CREATE			data;
} PROCESS_CACHE_INFORMATION, *PPROCESS_CACHE_INFORMATION;


PPROCESS_CACHE_INFORMATION ProcessGetCache(
	_In_ DWORD ProcessId,
	_In_ const PLARGE_INTEGER time,
	_In_opt_ PVOID ProcessObject
);

void ProcessRemoveFromCache(
	_In_ DWORD ProcessId,
	_In_ GUID* ProcessGuid,
	_In_opt_ PLARGE_INTEGER EventTime );

void ProcessAddToCache(
	_In_ GUID uniqueProcessGUID,
	_In_ PSYSMON_EVENT_HEADER event );

typedef enum _OBJECT_TYPE
{
    Process = 0x10000000,
	Session = 0x20000000
} OBJECT_TYPE;

GUID GenerateUniqueId(
	_In_ PLARGE_INTEGER timestamp,
	_In_ ULONGLONG ProcessStartKey,
	OBJECT_TYPE type );

bool ProcessCacheEmpty();

PTCHAR DupStringWithoutNullChar(
	_In_ PTCHAR input,
	_In_ ULONG sizeInByte
);

PTCHAR ReplaceAndDup(
	_In_ PTCHAR Input,
	_In_ ULONG SizeInBytes,
	_In_ ULONG Offset,
	_In_ ULONG SubCch,
	_In_ PTCHAR Replacement
);

VOID
EventSetFieldS(
	_In_ PSYSMON_DATA_DESCRIPTOR DataDescriptor,
	_In_ ULONG FieldIndex,
	_In_ const TCHAR* String,
	_In_ BOOLEAN Allocated
);

VOID
EventSetFieldD(
	_In_ PSYSMON_DATA_DESCRIPTOR DataDescriptor,
	_In_ ULONG FieldIndex,
	_In_ NativeTypes Type,
	_In_ PVOID Ptr,
	_In_ ULONG Size,
	_In_ BOOLEAN Allocated
);

PVOID ExtGetPtr(
	_In_ PULONG extensionsSizes,
	_In_ PVOID extensions,
	_In_ ULONG index,
	_Out_ PULONG retSize
);

DWORD
EventProcess(
	_In_ PSYSMON_EVENT_TYPE_FMT EventType,
	_In_ PSYSMON_DATA_DESCRIPTOR EventBuffer,
	_In_ PSYSMON_EVENT_HEADER EventData,
	_In_ PSID UserSid
);



extern CRITICAL_SECTION g_ProcessCacheLock;

//--------------------------------------------------------------------
//
// EventDataDescCreateX
//
// Helper macro for EventDataDescCreate handling differen types
//
//--------------------------------------------------------------------
#define EventDataDescCreateX(_d, _v) \
	EventDataDescCreate( _d, _v, sizeof( *_v ) );

#define EventDataMarkAllocated( _d ) \
	(_d)->Reserved = 1

#define EventDataIsAllocated( _d ) \
	( (_d)->Reserved != 0 )

#define ExtGetPtrX( _v, _i, _s ) \
	ExtGetPtr( (_v)->m_Extensions, (_v) + 1, _i, _s )

//
// Fast code macros
//
#define EventSetFieldX(_d, _f, _t, _x) \
	EventSetFieldD( _d, _f, _t, &(_x), sizeof((_x)), FALSE )

// Used for null terminated strings to calculate size in bytes
#define EventSetFieldTChar(_d, _f, _t, _x) \
	EventSetFieldD( _d, _f, _t, &(_x), (ULONG)_tcslen((_x)) * sizeof(TCHAR), FALSE )

#define EventSetFieldE(_d, _f, _t, _v, _i) \
	EventSetFieldExt( _d, _f, _t, (_v)->m_Extensions, (_v) + 1, _i )
