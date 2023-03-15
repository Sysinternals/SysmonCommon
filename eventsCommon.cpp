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
// EventsCommon.c
//
// Implements event handling depending of windows versions
//
//====================================================================
#include "stdafx.h"
#include "rules.h"
#include "eventsCommon.h"
#include "printfFormat.h"

#if defined _WIN64 || defined _WIN32
#include <Objbase.h>
#include <WinEvt.h>
#include <VersionHelper.h>
#include "dll.h"
#include "events.h"
extern PFN_EVENT_WRITE  PfnEventWrite;
BOOLEAN 				bPreVista = FALSE;

#elif defined __linux__
#include <pthread.h>
#include "linuxHelpers.h"
#include <sys/time.h>
#include <pwd.h>
#include <syslog.h>
extern "C" {
#include "outputxml.h"
}

extern "C" {
VOID syslogHelper( int priority, const char* fmt, char* msg );
}

// define Linux as being 'pre-Vista' as it helps without event output
BOOLEAN 				bPreVista = TRUE;
#endif

//
// Command line can be up to 0x7FFE but event log strings have a limit
// of 31839 characters (https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-reporteventa)
//
#define PATH_MAX_SIZE 31839
#define MAX_EVENT_PACKET_SIZE 62000

REGHANDLE 				g_Event = 0;
HANDLE 					g_hEventSource = NULL;
BOOLEAN 				bInitialized = FALSE;
ULONG					machineId = 0;

//--------------------------------------------------------------------
//
// Ulong64ToString
//
// Write a Ulong64 as a string.
//
//--------------------------------------------------------------------
BOOLEAN Ulong64ToString(
    PTCHAR out,
    DWORD size,
    ULONG64 value
    )
{
    if (out == NULL) {
        return FALSE;
    }
    _stprintf_s( out, size, _T( "" PRINTF_ULONG64_FS ), value );
    return TRUE;
}

//--------------------------------------------------------------------
//
// LogonIdToString
//
// Write a LogonId as a string.
//
//--------------------------------------------------------------------
BOOLEAN LogonIdToString(
    PTCHAR out,
    DWORD size,
    ULONG64 logonId
    )
{
    if (out == NULL) {
        return FALSE;
    }
#if defined _WIN64 || defined _WIN32
    _stprintf_s( out, size, _T("0x%I64x"), logonId );
#elif defined __linux__
    // On Linux, the low part of the LUID is the Linux logon Id
    _stprintf_s( out, size, "%ld", logonId & 0xffff );
#endif
    return TRUE;
}

//--------------------------------------------------------------------
//
// GenerateUniqueId
//
// Get a unique GUID for this event on this machine
// Structure:
//  - machineID (last part of the machine account SID)
//  - Time of the event in seconds
//  - TokenId (unique object ID) | type of the object
//
//--------------------------------------------------------------------
GUID GenerateUniqueId(
	_In_ PLARGE_INTEGER timestamp,
	_In_ ULONGLONG ProcessStartKey,
	OBJECT_TYPE type
    )
{
	GUID result = {0,};
	DWORD seconds = 0;
	PBYTE pResult = (PBYTE)&result;

#if defined _WIN64 || defined _WIN32
	RtlTimeToSecondsSince1970( timestamp, &seconds );
#elif defined __linux__
    // timestamp in 100ns intervals since epoch
    seconds = LargeTimeToSeconds( timestamp );
#endif

	*(DWORD*) pResult = machineId;
	pResult += sizeof(DWORD);
	*(DWORD*) pResult = seconds;
	pResult += sizeof(DWORD);
	*(DWORD64*) pResult = ProcessStartKey;

	return result;
}

//--------------------------------------------------------------------
//
// ProcessCache class implementation
//
// Static class that caches processes for faster lookup. Does not
// require explicit initialisation. Has locking and unlocking
// functions to guard access to it and the objects returned by it.
//
//--------------------------------------------------------------------

//--------------------------------------------------------------------
//
// ProcessCache::ProcessGet
//
// Fetch a process cache entry.
//
//--------------------------------------------------------------------
PPROCESS_CACHE_INFORMATION ProcessCache::ProcessGet(
	_In_ DWORD ProcessId,
	_In_ const PLARGE_INTEGER time,
	_In_opt_ PVOID ProcessObject
)
{
	PPROCESS_CACHE_INFORMATION	ret = NULL;

	LockCache();

	//
	// search for process ID in unordered map
	//
	auto processEntry = _processCache.find( ProcessId );
	if( processEntry != _processCache.end() ) {

		//
		// iterate over list items for this process ID
		//
		for( auto &current : processEntry->second ) {

			// #444 If a process object was provided, check for a match against this in addition to the PID
			if( (ProcessObject == NULL) ||
				(current.data->m_ProcessObject == NULL) ||
				(current.data->m_ProcessObject == ProcessObject) ) {

				if( time != NULL ) {

					//
					// If I didn't select the entry or the time of the event was
					// before the process was removed
					//
					if( ret == NULL ) {

						//
						// Only if time makes sense, else we will select a wrong old entry
						// and the latest will be skipped
						//
						if( (current.removedTime.QuadPart == 0 ||									// If the current entry is still open
							(ULONG64)time->QuadPart < (ULONG64)(current.removedTime.QuadPart + NT_500_MS)) && // Or it has now terminated but terminated after the process creation time
																									// the half second buffer is because we have seen network events appear marginally later than the process terminate event
							(time->QuadPart >= current.data->m_CreateTime.QuadPart) ) {				// #444. We validate the end of the time window but not the start..

							ret = &current;
						}
					} else if( current.removedTime.QuadPart != 0 &&								// The process has terminadumpted
							   (ULONG64)time->QuadPart < (ULONG64)current.removedTime.QuadPart &&  // The process terminated after our process creation time
							   time->QuadPart >= current.data->m_CreateTime.QuadPart &&				// #444 Validate the start of the time window too
							   (ret->removedTime.QuadPart == 0 ||									// we are either superseding a candidate that is still open
								   (ULONG64)ret->removedTime.QuadPart > ( ULONG64 )current.removedTime.QuadPart) ) {  // or we are superseding a process with a wider windows than the current candidate

						ret = &current;
					}

				} else {

					//
					// Select the latest available;
					//
					if( ret == NULL ) {

						ret = &current;
					} else if( (current.removedTime.QuadPart == 0) ||
							   ((ret->removedTime.QuadPart != 0) &&
								   ((ULONG64)ret->removedTime.QuadPart < (ULONG64)current.removedTime.QuadPart)) ) {

						ret = &current;
					}
					break;
				}
			}
		}
	}

	UnlockCache();

	return ret;
}

//--------------------------------------------------------------------
//
// ProcessCache::RemoveEntries
//
// Remove all entries from the cache.
//
//--------------------------------------------------------------------
void ProcessCache::RemoveEntries()
{
	LockCache();

	//
	// for every entry in the cache (removing after each iteration)
	//
	for( auto cacheEntry = _processCache.begin(); cacheEntry != _processCache.end(); cacheEntry = _processCache.erase( cacheEntry ) ) {

		//
		// iterate over list items for this process ID
		//
		for( auto &current : cacheEntry->second ) {
			free( current.data );
		}
	}

	UnlockCache();
}

//--------------------------------------------------------------------
//
// ProcessCache::ProcessRemove
//
// Mark an entry as expired; calls PurgeExpired() to remove entries
// that were marked as expired further back than the grace period.
//
//--------------------------------------------------------------------
void ProcessCache::ProcessRemove(
	_In_ DWORD ProcessId,
	_In_ GUID* ProcessGuid,
	_In_opt_ PLARGE_INTEGER EventTime
)
{
	LARGE_INTEGER				currentTime;

	if( EventTime == NULL ) {

		GetSystemTimeAsLargeInteger( &currentTime );
		EventTime = &currentTime;
	}

	LockCache();

	//
	// search for process ID in unordered map
	//
	auto processEntry = _processCache.find( ProcessId );
	if( processEntry != _processCache.end() ) {

		//
		// iterate over list items for this process ID
		//
		for( auto &current : processEntry->second) {

			//
			// Mark the entry as removed, but keep it around in case
			// we get delayed ETW events that reference it
			//
			current.removedTime.QuadPart = EventTime->QuadPart;
		}
		_expiringProcesses.emplace( EventTime->QuadPart, ProcessId );
	}

	PurgeExpired( EventTime );
	UnlockCache();
}

//--------------------------------------------------------------------
//
// ProcessCache::PurgeExpired
//
// Remove expired entries from the cache that are older than the grace
// period.
//
//--------------------------------------------------------------------
void ProcessCache::PurgeExpired( PLARGE_INTEGER EventTime )
{
	while( !_expiringProcesses.empty() && Expired( _expiringProcesses.top().time, EventTime->QuadPart ) ) {
		CacheEntryToExpire oldest = _expiringProcesses.top();
		_expiringProcesses.pop();
		auto processes = _processCache.find( oldest.pid );
		if( processes != _processCache.end() ) {

			for( auto &process : processes->second ) {

				free( process.data );
			}

			_processCache.erase( oldest.pid );
		}
	}
}

//--------------------------------------------------------------------
//
// ProcessCache::ProcessAdd
//
// Add a process record to the process cache.
//
//--------------------------------------------------------------------
void ProcessCache::ProcessAdd(
	_In_ GUID uniqueProcessGUID,
	_In_ PSYSMON_EVENT_HEADER event
)
{
	PROCESS_CACHE_INFORMATION	cacheEntry;
	PSYSMON_PROCESS_CREATE		data;
	SIZE_T						dataSize;

	data = &event->m_EventBody.m_ProcessCreateEvent;

	dataSize = event->m_EventSize - offsetof( SYSMON_EVENT_HEADER, m_EventBody );
	cacheEntry.data = static_cast<PSYSMON_PROCESS_CREATE>( malloc( dataSize ) );
	if( cacheEntry.data != NULL ) {
		LockCache();

		memcpy( cacheEntry.data, data, dataSize );

		cacheEntry.uniqueProcessGUID = uniqueProcessGUID;
		cacheEntry.removedTime.QuadPart = 0;
		cacheEntry.dnsQueryCache = {};

		ProcessRemove( data->m_ProcessId, &uniqueProcessGUID, NULL );
		auto processEntry = _processCache.find( data->m_ProcessId );
		if( processEntry == _processCache.end() ) {

			_processCache.emplace( data->m_ProcessId, CacheEntries{ cacheEntry } );
		} else {

			processEntry->second.push_front( cacheEntry );
		}

		UnlockCache();
	}
}

//--------------------------------------------------------------------
//
// ProcessCache::Empty
//
// Reports if the process cache is empty or not.
//
//--------------------------------------------------------------------
bool ProcessCache::Empty()
{
	LockCache();
	bool ret = _processCache.empty();
	UnlockCache();
	return ret;
}

#if defined _WIN64 || defined _WIN32
//--------------------------------------------------------------------
//
// ProcessCache::DnsEntryAdd
//
// Adds a DNS entry to a process in the cache.
//
//--------------------------------------------------------------------
bool ProcessCache::DnsEntryAdd( DWORD ProcessId, PDNS_QUERY_DATA DnsEntry )
{
	LockCache();
	auto processInfo = ProcessGet( ProcessId, NULL, NULL );
	if( processInfo != NULL ) {

		for( auto &cachedQuery : processInfo->dnsQueryCache) {
			if( !_tcsicmp( cachedQuery.QueryName, DnsEntry->QueryName ) &&
				!_tcsicmp( cachedQuery.QueryResult, DnsEntry->QueryResult ) &&
				!_tcsicmp( cachedQuery.QueryStatus, DnsEntry->QueryStatus ) ) {

				UnlockCache();
				return false;
			}
		}

		//
		// Add to the cache
		//
		if( processInfo->dnsQueryCache.size() == DNS_CACHE_LIMIT ) {

			processInfo->dnsQueryCache.pop_back();
		}
		// Performing a copy here, just in case.
		processInfo->dnsQueryCache.push_front( *DnsEntry );
	}
	UnlockCache();
	return true;
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern HANDLE g_hDriver;
#ifdef __cplusplus
}
#endif

//
// Default values
//
TCHAR DefaultString[] = _T("-");
GUID DefaultGuid = {0,};

//--------------------------------------------------------------------
//
// EventDataDescCreateS
//
// Helper function for EventDataDescCreate handling with strings
//
//--------------------------------------------------------------------
VOID EventDataDescCreateS(
	_In_ PEVENT_DATA_DESCRIPTOR Data,
	_In_ const TCHAR* String
	)
{
	if( String == NULL ) {
		String = _T("NULL");
	}

     EventDataDescCreate( Data, (PVOID)String, (ULONG)((_tcslen(String) + 1) * sizeof(TCHAR)) );
}

//--------------------------------------------------------------------
//
// GenerateUniquePGUID
//
// Generate a unique GUID for the process
//
//--------------------------------------------------------------------
void GenerateUniquePGUID(
	_In_ GUID* pguid,
	_In_ PSYSMON_EVENT_HEADER event,
	_In_ BOOLEAN Cache
	)
{
	GUID					g;
	PSYSMON_PROCESS_CREATE	data;

	data = &event->m_EventBody.m_ProcessCreateEvent;
	g = GenerateUniqueId( &data->m_CreateTime, data->m_ProcessKey, Process );

	// Update the cache
	if( Cache ) {

		ProcessCache::Instance().ProcessAdd( g, event );
	}

	*pguid = g;
}

//--------------------------------------------------------------------
//
// FetchUniquePGUID
//
// Fetch a unique GUID for the process from the cache
//
//--------------------------------------------------------------------
void FetchUniquePGUID(
	_Out_ GUID* pguid,
	_In_ ULONG ProcessId,
	_In_ BOOLEAN UpdateCache,
	_In_ PLARGE_INTEGER time
	)
{
	PPROCESS_CACHE_INFORMATION	cache;
	UCHAR						buffer[16386];
	BOOL   						result;
	PSYSMON_EVENT_HEADER		event;

	ProcessCache::Instance().LockCache();

	cache = ProcessCache::Instance().ProcessGet( ProcessId, time, NULL );

	if( cache ) {

		*pguid = cache->uniqueProcessGUID;
		ProcessCache::Instance().UnlockCache();
	} else {

		ProcessCache::Instance().UnlockCache();

#if defined _WIN64 || defined _WIN32
        DWORD						bytesReturned = 1;
        UPDATE_CACHE				cacheRequest;
		cacheRequest.ProcessId = ProcessId;
		cacheRequest.UpdateCache = UpdateCache;

	   	result  = DeviceIoControl( g_hDriver, IOCTL_SYSMON_PROCESS_CACHE, &cacheRequest, sizeof(cacheRequest),
								   buffer, sizeof(buffer), &bytesReturned, NULL );
		if( result ) {

			D_ASSERT(bytesReturned > 0);
			event = (PSYSMON_EVENT_HEADER) buffer;
		    GenerateUniquePGUID( pguid, event, UpdateCache );
		} else {

		    DBG_MODE( _tprintf( _T("PROCESS_CACHE_REQUEST failed with %d\n"), GetLastError() ) );
        }

#elif defined __linux__
        result = GetProcess( (PSYSMON_EVENT_HEADER) buffer, sizeof(buffer), ProcessId );

		if( result ) {

			event = (PSYSMON_EVENT_HEADER) buffer;
		    GenerateUniquePGUID( pguid, event, UpdateCache );
		} else {

		    DBG_MODE( _tprintf( _T("PROCESS_CACHE_REQUEST failed\n") ) );
		}
#endif
	}
}

//--------------------------------------------------------------------
//
// GenerateUniqueSGUID
//
// Generate a unique GUID for the session
//
//--------------------------------------------------------------------
void GenerateUniqueSGUID(
	_In_ GUID* sguid,
	_In_ LUID* authenticationId
	)
{
	GUID							g;
	LARGE_INTEGER					timestamp = {0,};
#if defined _WIN64 || defined _WIN32
	NTSTATUS						status;
	PSECURITY_LOGON_SESSION_DATA 	sessionData;

	status = LsaGetLogonSessionData( authenticationId, &sessionData );

	if (NT_SUCCESS(status))
	{
		timestamp = sessionData->LogonTime;
		LsaFreeReturnBuffer( sessionData );
	}
#elif defined __linux__
    timestamp = GetLogonTime( authenticationId );
#endif

	g = GenerateUniqueId( &timestamp, * (PULONGLONG) authenticationId, Session );

	*sguid = g;
}

//--------------------------------------------------------------------
//
// RefreshProcessCache
//
// Refresh the process cache from the current process list
//
//--------------------------------------------------------------------
VOID RefreshProcessCache(
	VOID
	)
{
	PDWORD	processList = NULL;
	GUID 	tmp;
	DWORD 	i;
	// 16384 entries should be large enough for most systems, but still only uses
	// 64KB of RAM.
	DWORD processSize = 16384 * sizeof( DWORD );
	DWORD processUsed = 0;

	for( i = 0; i < 5; i++ ) {

		processList = (PDWORD)malloc( processSize );

		if( processList == NULL ) {

			PrintErrorEx( (PTCHAR)_T( __FUNCTION__ ), 0, (PTCHAR)_T( "Out of memory condition" ) );
			return;
		}

		// Check that EnumProcesses succeeds AND that we have all the processes available
		// If EnumProcesses fails, for simplicity handle it in the same way as if the buffer
		// is too small. The extra memory usage is inconsequential - total memory usage would
		// reach 128KB if it fails 5 times in a row.
		if( EnumProcesses( processList, processSize, &processUsed ) && processUsed < processSize ) {

			break;
		}

		// If 16K entries is too small, we need to jump a reasonable amount to ensure
		// we find a suitable size before the loop expires.
		processSize += 4096 * sizeof( DWORD );

		free( processList );
		processList = NULL;
	}

	if( processList == NULL ) {

		PrintErrorEx( (PTCHAR)_T( __FUNCTION__ ), 0, (PTCHAR)_T( "Failed to udpate the process cache on start" ) );
		return;
	}

	//
	// Fetch each process GUID to update the cache
	//
	for( i = 0; i < (processUsed / sizeof( DWORD )); i++ ) {

		FetchUniquePGUID( &tmp, processList[i], TRUE, NULL );
	}

	free( processList );
}

//--------------------------------------------------------------------
//
// TimestampFormat
//
// Format a timestamp to local time for event reporting
//
//--------------------------------------------------------------------
VOID TimestampFormat(
	_Out_ PTCHAR buffer,
	_In_ SIZE_T bufferCount,
	_In_ PLARGE_INTEGER timestamp
	)
{
#if defined _WIN64 || defined _WIN32
	SYSTEMTIME		timeFields;
	FILETIME		fileTime;

	fileTime.dwLowDateTime = timestamp->LowPart;
	fileTime.dwHighDateTime = (DWORD)timestamp->HighPart;

	if( FileTimeToSystemTime( &fileTime, &timeFields ) ) {

		_stprintf_s( buffer, bufferCount, _T("%04u-%02u-%02u %02u:%02u:%02u.%03u"),
					 timeFields.wYear, timeFields.wMonth, timeFields.wDay,
					 timeFields.wHour, timeFields.wMinute, timeFields.wSecond, timeFields.wMilliseconds );
	} else {

		_stprintf_s( buffer, bufferCount, _T("Incorrect filetime: 0x%I64x"),
					 timestamp->QuadPart );
	}
#elif defined __linux__
    // time in 100ns intervals since epoch
    struct tm timeFields;
    time_t fileTime = 0;

    // timestamp in 100ns intervals since epoch
    fileTime = LargeTimeToSeconds( timestamp );

    if ( gmtime_r(&fileTime, &timeFields) ) {

        snprintf( buffer, bufferCount, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
                timeFields.tm_year + 1900, timeFields.tm_mon + 1, timeFields.tm_mday,
                timeFields.tm_hour, timeFields.tm_min, timeFields.tm_sec,
                LargeTimeMilliseconds( timestamp ));
    } else {

		_stprintf_s( buffer, bufferCount, _T("Incorrect filetime: 0x%" PRIx64),
					 timestamp->QuadPart );
	}
#endif
}

//--------------------------------------------------------------------
//
// ExtGetPtr
//
// Get a pointer to the target extension of the event
//
//--------------------------------------------------------------------
PVOID ExtGetPtr(
	_In_ PULONG extensionsSizes,
	_In_ PVOID extensions,
	_In_ ULONG index,
	_Out_ PULONG retSize
	)
{
	ULONG i, size;
	PBYTE ptr = (PBYTE) extensions;

	size = extensionsSizes[index];

	if( retSize ) {

		*retSize = size;
	}

	if( size == 0 ) {

		return NULL;
	}

	for( i = 0; i < index; i++ ) {

		ptr += extensionsSizes[i];
	}

	return ptr;
}

//--------------------------------------------------------------------
//
// ExtGetEscapeString
//
// Extract a string from an extension
//
//--------------------------------------------------------------------
PTCHAR ExtGetEscapeString(
	_In_ PULONG extensionsSizes,
	_In_ PVOID extensions,
	_In_ ULONG index
	)
{
	ULONG	size, i, escapes = 0;
	PVOID	ptr;
	PTCHAR	str, strPtr;

	ptr = ExtGetPtr( extensionsSizes, extensions, index, &size );

	if( ptr == NULL || size < sizeof( TCHAR ) ) {

		return NULL;
	}

	if( (size % sizeof( TCHAR )) != 0 ) {

		size--;
	}

	// Count % characters
	for (i = 0; i < size / sizeof(TCHAR); i++) {

		if( ((PTCHAR) ptr)[i] == '%' )
			escapes++;
	}
	str = strPtr = (PTCHAR) malloc( size + (escapes * sizeof( TCHAR )) + sizeof( TCHAR ) );

	if( str != NULL ) {

		size /= sizeof( TCHAR );
		for( i = 0; i < size; i++ ) {

			*strPtr = ((PTCHAR) ptr)[i];
			strPtr++;
			if( ((PTCHAR) ptr)[i] == '%' ) {
				*strPtr = '%';
				strPtr++;
			}
		}
		*strPtr = 0;
	}

	return str;
}

//--------------------------------------------------------------------
//
// ExtGetAnsiString
//
// Extract a string from an extension
//
//--------------------------------------------------------------------
PWCHAR ExtGetAnsiString(
	_In_ PULONG extensionsSizes,
	_In_ PVOID extensions,
	_In_ ULONG index,
	_In_ PULONG size
)
{
	ULONG	origSize;
	PVOID	ptr;
	PWCHAR	str;

	ptr = ExtGetPtr( extensionsSizes, extensions, index, &origSize );

	if( ptr == NULL || origSize < sizeof( TCHAR ) ) {

		return NULL;
	}
#if defined _WIN64 || defined _WIN32
	*size = MultiByteToWideChar( CP_ACP, MB_PRECOMPOSED, (LPCSTR) ptr, origSize, NULL, 0 );
#elif defined __linux__
    *size = UTF8toUTF16( NULL, (LPCSTR) ptr, 0 );
#endif
	if( *size == 0 ) {

		return NULL;
	}

	*size = *size * sizeof( WCHAR );
	str = (PWCHAR)malloc( *size );

	if( str != NULL ) {

#if defined _WIN64 || defined _WIN32
		MultiByteToWideChar( CP_ACP, MB_PRECOMPOSED, (LPCSTR)ptr, origSize, str, *size );
#elif defined __linux__
        UTF8toUTF16( str, (LPCSTR)ptr, *size );
#endif
	}
	return str;
}

//--------------------------------------------------------------------
//
// ExtGetString
//
// Extract a string from an extension
//
//--------------------------------------------------------------------
PTCHAR ExtGetString(
	_In_ PULONG extensionsSizes,
	_In_ PVOID extensions,
	_In_ ULONG index
	)
{
	ULONG	size;
	PVOID	ptr;
	PTCHAR	str;

	ptr = ExtGetPtr( extensionsSizes, extensions, index, &size );

	if( ptr == NULL || size < sizeof(TCHAR) ) {

		return NULL;
	}

	if( (size % sizeof(TCHAR)) != 0 ) {

		size--;
	}

	str = (PTCHAR) malloc( size + sizeof(TCHAR) );

	if( str != NULL ) {

		size /= sizeof(TCHAR);
		_tcsncpy( str, (PTCHAR) ptr, size );
		str[size] = 0;
	}

	return str;
}

//--------------------------------------------------------------------
//
// IsNullTerminated
//
// Check if the string is null terminated
//
//--------------------------------------------------------------------
BOOLEAN IsNullTerminated(
	_In_ PVOID ptr,
	_In_ ULONG size
	)
{
	if( size == 0 ) {

		return FALSE;
	}

	PTCHAR str = (PTCHAR)ptr;
	size /= sizeof(TCHAR);
	return ( str[size-1] == 0 );
}

//--------------------------------------------------------------------
//
// DupStringWithoutNullChar
//
// Duplicate a string without null char bound
//
//--------------------------------------------------------------------
PTCHAR DupStringWithoutNullChar(
	_In_ PTCHAR input,
	_In_ ULONG sizeInByte
	)
{
	PTCHAR str;

	if( input == NULL || sizeInByte < sizeof(TCHAR) ) {

		return NULL;
	}

	if( (sizeInByte % sizeof(TCHAR)) != 0 ) {

		sizeInByte--;
	}

	if( IsNullTerminated( input, sizeInByte ) ) {

		return _tcsdup( input );
	}

	str = (PTCHAR) malloc( sizeInByte + sizeof(TCHAR) );

	if( str == NULL ) {

		return NULL;
	}

	ZeroMemory( str, sizeInByte + sizeof(TCHAR) );
	_tcsncpy( str, input, sizeInByte / sizeof(TCHAR) );
	return str;
}

//--------------------------------------------------------------------
//
// ReplaceAndDup
//
// Replace a part of the string and dup it
//
//--------------------------------------------------------------------
PTCHAR ReplaceAndDup(
	_In_ PTCHAR Input,
	_In_ ULONG SizeInBytes,
	_In_ ULONG Offset,
	_In_ ULONG SubCch,
	_In_ PTCHAR Replacement
	)
{
	ULONG	newSize, replaceSize, sizeCch;
	PTCHAR	str, pos;

	if( Input == NULL || SizeInBytes < sizeof(TCHAR) ) {

		return NULL;
	}

	sizeCch = SizeInBytes / sizeof(TCHAR);

	if( sizeCch <= Offset || sizeCch < (Offset + SubCch) ) {

		return NULL;
	}

	replaceSize = (ULONG)_tcslen( Replacement );
	newSize = sizeCch + replaceSize - SubCch;

	//
	// Need a null char?
	//
	if( sizeCch < 2 || Input[sizeCch-1] != 0 ) {

		newSize++;
	}

	newSize *= sizeof(TCHAR);

	str = (PTCHAR) malloc( newSize );

	if( str == NULL ) {

		return NULL;
	}

	ZeroMemory( str, newSize );

	//
	// Compute the final string with the replacement
	//
	pos = str;
	memcpy( pos, Input, Offset * sizeof(TCHAR) );
	pos += Offset;
	D_ASSERT( pos < (str + newSize/sizeof(TCHAR)) );
	memcpy( pos, Replacement, replaceSize * sizeof(TCHAR) );
	pos += replaceSize;
	D_ASSERT( pos < (str + newSize/sizeof(TCHAR)) );
	D_ASSERT( pos + (sizeCch - Offset - SubCch) <= (str + newSize/sizeof(TCHAR)) );
	memcpy( pos, Input + Offset + SubCch, (sizeCch - Offset - SubCch) * sizeof(TCHAR) );
	return str;
}

//--------------------------------------------------------------------
//
// ExtTranslateNtPath
//
// Extract a nt path string from an extension
//
//--------------------------------------------------------------------
PTCHAR ExtTranslateNtPath(
	_In_ PULONG extensionsSizes,
	_In_ PVOID extensions,
	_In_ ULONG index
	)
{
	ULONG			size;
	PTCHAR			ptr;

	ptr = (PTCHAR) ExtGetPtr( extensionsSizes, extensions, index, &size );

	if( ptr == NULL ) {

		return NULL;
	}

#if defined _WIN64 || defined _WIN32
	return TranslateNtPath( ptr, size );
#elif defined __linux__
    return DupStringWithoutNullChar( ptr, size );
#endif
}

//--------------------------------------------------------------------
//
// TrimStringIfNeeded
//
// Handle trimming of image paths if needed
//
//--------------------------------------------------------------------
BOOLEAN TrimStringIfNeeded(
	_In_ PTCHAR path
	)
{
	if( path != NULL && _tcslen( path ) > PATH_MAX_SIZE ) {

		path[PATH_MAX_SIZE-3] =
		path[PATH_MAX_SIZE-2] =
		path[PATH_MAX_SIZE-1] = _T('.');
		path[PATH_MAX_SIZE] = 0;
		return TRUE;
	}

	return FALSE;
}

//--------------------------------------------------------------------
//
// TrimStringByNChars
//
// Trim path by up to n characters
//
//--------------------------------------------------------------------
BOOLEAN TrimStringByNChars(
	_In_ PTCHAR path,
	_In_ int minlength,
	_In_ int maxCharsToTrim
	)
{
	const int ellipsis = sizeof("...") - sizeof('\0');

	// Minimum path we return is minlength plus the "..."
	if (path != NULL && _tcslen(path) > (size_t)(minlength+ellipsis) )
	{
		int pathlen = (int)_tcslen(path);

		int end = maxCharsToTrim > pathlen ? minlength + ellipsis : pathlen - maxCharsToTrim;
        end = (end > minlength + ellipsis) ? end : minlength + ellipsis;

		path[end - 3] =
			path[end - 2] =
			path[end - 1] = _T('.');
		path[end] = 0;

		return TRUE;
	}

	return FALSE;
}

//--------------------------------------------------------------------
//
// TrimStringToNChars
//
// Trim field to N chars if necessary; if N == -1 do nothing.
//
// Returns true if string was trimmed (and updates size), false
// otherwise.
//
//--------------------------------------------------------------------
BOOLEAN TrimStringToNChars(
	_In_  PTCHAR field,
	_In_  int maxLength,
    _Out_ ULONG *size
	)
{
    // Check we actually need to trim
    if (field == NULL || size == NULL || maxLength < 0 || _tcslen(field) <= (size_t)maxLength)
        return FALSE;

    if (maxLength == 0) {
        field[0] = 0x00;
        *size = sizeof(TCHAR);
        return TRUE;
    }

    // If maxLength is unreasonably short, replace field with '-'
    if (maxLength < 3) {
        field[0] = _T('-');
        field[1] = 0x00;
        *size = 2 * sizeof(TCHAR);
        return TRUE;
    }

    // Set ellipses at end of field
    field[maxLength - 3] =
        field[maxLength - 2] =
        field[maxLength - 1] = _T('.');
    field[maxLength] = 0x00;
    *size = (maxLength + 1) * sizeof(TCHAR);

    return TRUE;
}

//--------------------------------------------------------------------
//
// FetchImageName
//
// Find the image name from the PID or replace with <unknown process>
//
//--------------------------------------------------------------------
VOID FetchImageName(
	_In_ DWORD ProcessId,
	_In_ PTCHAR Buffer,
	_In_ SIZE_T Size,
	_In_ PLARGE_INTEGER time
	)
{
#if defined _WIN64 || defined _WIN32
	HANDLE			hSnap, hProcess;
	MODULEENTRY32	moduleEntry;
	DWORD			dwSize;
	static tQueryFullProcessImageName queryFullImage = NULL;
#endif
	PPROCESS_CACHE_INFORMATION	cache;
	PSYSMON_PROCESS_CREATE	processInfo;
	PTCHAR			imagePath;
	BOOLEAN			ret = FALSE;

	// Default
	_sntprintf ( Buffer, Size, _T("<unknown process>") );
	if( ProcessId == 0 ) {

		//
		// PID can be 0 for clibpard operations that don't have an owner
		//
		return;
	}

	//
	// Look at the cache first
	//
	ProcessCache::Instance().LockCache();

	cache = ProcessCache::Instance().ProcessGet( ProcessId, time , NULL );

	if( cache ) {

		processInfo = cache->data;
		imagePath = ExtTranslateNtPath( processInfo->m_Extensions, processInfo + 1,
										PC_ImagePath );

		_tcsncpy_s( Buffer, Size, imagePath,_TRUNCATE );
		ret = TRUE;

		free( imagePath );
	}

	ProcessCache::Instance().UnlockCache();

	//
	// The cache was successfully used
	//
	if( ret ) {

		return;
	}

#if defined _WIN64 || defined _WIN32

	//
	// Try to use QueryFullProcessImageName for Vista+
	//
	if( queryFullImage == NULL && !bPreVista ) {

		queryFullImage = (tQueryFullProcessImageName) GetProcAddress( GetModuleHandle( _T("kernel32.dll") ), "QueryFullProcessImageName" );
	}

	if( queryFullImage ) {

		hProcess = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId );

		if( hProcess != NULL ) {

			dwSize = (DWORD)Size;
			if( queryFullImage( hProcess, 0, Buffer, &dwSize ) ) {

				ret = TRUE;
			}

			CloseHandle( hProcess );
		}

		if( ret ) {

			return;
		}
	}

	hSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, ProcessId );

	if( hSnap == INVALID_HANDLE_VALUE ) {

		return;
	}

	moduleEntry.dwSize = sizeof( moduleEntry );

	if( Module32First( hSnap, &moduleEntry ) ) {

		wcsncpy_s( Buffer, Size, moduleEntry.szExePath, _TRUNCATE);
	}

	CloseHandle( hSnap );

#elif defined __linux__

    //
    // Get the process name for Linux
    //
    if (!GetProcessName( Buffer, Size, ProcessId )) {
        snprintf ( Buffer, Size, "<unknown process>") ;
    }
#endif

}

//--------------------------------------------------------------------
//
// EventSetFieldD
//
//--------------------------------------------------------------------
VOID
EventSetFieldD(
	_In_ PSYSMON_DATA_DESCRIPTOR DataDescriptor,
	_In_ ULONG FieldIndex,
	_In_ NativeTypes Type,
	_In_ PVOID Ptr,
	_In_ ULONG Size,
	_In_ BOOLEAN Allocated
	)
{
	D_ASSERT( FieldIndex < SYSMON_MAX_EVENT_Fields );

	if( Ptr == NULL || Size == 0 ) {

		Ptr = NULL;
		Size = 0;
	}

	if( DataDescriptor[FieldIndex].Ptr != NULL ) {

		if( DataDescriptor[FieldIndex].Allocated ) {

			free( DataDescriptor[FieldIndex].Ptr );
		}
	}

	DataDescriptor[FieldIndex].Type = Type;
	DataDescriptor[FieldIndex].Ptr = Ptr;
	DataDescriptor[FieldIndex].Size = Size;
	DataDescriptor[FieldIndex].Allocated = Allocated;
}

//--------------------------------------------------------------------
//
// EventSetFieldS
//
//--------------------------------------------------------------------
VOID
EventSetFieldS(
	_In_ PSYSMON_DATA_DESCRIPTOR DataDescriptor,
	_In_ ULONG FieldIndex,
	_In_ const TCHAR* String,
	_In_ BOOLEAN Allocated
	)
{
	ULONG stringLength = 0;

	static TCHAR  emptyField[] = _T( "-" );

	if( String == NULL || *String == 0 ) {

		if( String && Allocated ) {

			free( (void *) String );
		}
		String = emptyField;
		Allocated = FALSE;
	}

	stringLength = (ULONG)(_tcslen(String) + 1) * sizeof(TCHAR);

	EventSetFieldD( DataDescriptor,
					FieldIndex,
					N_UnicodeString,
					(PVOID)String,
					stringLength,
					Allocated );
}

//--------------------------------------------------------------------
//
// EventSetFieldExt
//
//--------------------------------------------------------------------
VOID
EventSetFieldExt(
	_In_ PSYSMON_DATA_DESCRIPTOR DataDescriptor,
	_In_ ULONG FieldIndex,
	_In_ NativeTypes Type,
	_In_ PULONG extensionsSizes,
	_In_ PVOID extensions,
	_In_ ULONG index
	)
{
	PVOID	ptr = NULL;
	ULONG	size = 0;
	BOOLEAN allocated = FALSE;

	if( Type == N_UnicodeString || Type == N_EscapeUnicodeString ) {

		if( Type == N_EscapeUnicodeString ) {

			ptr = ExtGetEscapeString( extensionsSizes, extensions, index );
		}
		else {

			ptr = ExtGetString( extensionsSizes, extensions, index );
		}

		if( ptr != NULL ) {

			allocated = TRUE;
			size = (ULONG)(_tcslen((PTCHAR)ptr) + 1) * sizeof(TCHAR);
		} else {

			EventSetFieldS( DataDescriptor, FieldIndex, NULL, FALSE );
			return;
		}
	}
#if defined __linux__
// Only Linux has Linux Command Lines - null-separated arguments
	else if( Type == N_LinuxCommandLine ) {
        PCHAR cmdline = (PCHAR)ExtGetPtr( extensionsSizes, extensions, index, &size );
        PCHAR cmdptr = (PCHAR)malloc(size);
        if (cmdptr != NULL && cmdline != NULL) {
            // copy the cmdline, swapping nulls for spaces
            for (ULONG i=0; i<size - 1; i++) {
                if (cmdline[i] == 0x00) {
                    cmdptr[i] = ' ';
                } else {
                    cmdptr[i] = cmdline[i];
                }
            }
            cmdptr[size - 1] = 0x00;
            ptr = cmdptr;
            allocated = TRUE;
            // set the type
            Type = N_UnicodeString;
        } else {
			EventSetFieldS( DataDescriptor, FieldIndex, NULL, FALSE );
			return;
        }
    }
#endif

	else if( Type == N_AnsiOrUnicodeString ) {
		ptr = ExtGetString( extensionsSizes, extensions, index );
		if( ptr != NULL ) {

			allocated = TRUE;
			size = (ULONG)(_tcslen( (PTCHAR)ptr ) + 1) * sizeof( TCHAR );
// on Linux, don't check for, nor convert to, UTF16
#if defined _WIN64 || defined _WIN32
			for( size_t i = 0; i < _tcslen( (PTCHAR)ptr ); i++ ) {

				if( !iswprint( ((PWCHAR) ptr)[i] ) ) {

					free( ptr );
					ptr = ExtGetAnsiString( extensionsSizes, extensions, index, &size );
					if( ptr == NULL ) {

						allocated = FALSE;
					}
					break;
				}
			}
#endif

			// clean out carriage returns
			for( ULONG i = 0; i < size/sizeof(TCHAR); i++ ) {

				if( ((PTCHAR)ptr)[i] == 0xA || ((PTCHAR)ptr)[i] == 0xD )
					((PTCHAR)ptr)[i] = ' ';
			}

			Type = N_UnicodeString;
		}
		else {

			EventSetFieldS( DataDescriptor, FieldIndex, NULL, FALSE );
			return;
		}

	}
	else if( Type == N_UnicodePath ) {

		ptr = ExtTranslateNtPath( extensionsSizes, extensions, index );

		if( ptr != NULL ) {

			allocated = TRUE;
			size = (ULONG) (_tcslen( (PTCHAR) ptr ) + 1) * sizeof( TCHAR );
		}
		else {

#if defined _WIN64 || defined _WIN32
			D_ASSERT( !"Using a default path" );
#endif
			EventSetFieldS( DataDescriptor, FieldIndex, NULL, FALSE );
			return;
		}
	}
	else if( Type == N_RegistryPath ) {

		ptr = ExtTranslateNtPath( extensionsSizes, extensions, index );

		if( ptr != NULL ) {

			allocated = TRUE;
			size = (ULONG) (_tcslen( (PTCHAR) ptr ) + 1) * sizeof( TCHAR );
		}
		else {

			D_ASSERT( !"Using a default path" );
			EventSetFieldS( DataDescriptor, FieldIndex, NULL, FALSE );
			return;
		}
	} else {

		ptr = ExtGetPtr( extensionsSizes, extensions, index, &size );
	}

	EventSetFieldD( DataDescriptor, FieldIndex, Type, ptr, size, allocated );
}

//--------------------------------------------------------------------
//
// EventFieldDup
//
// Duplicate an event field
//
//--------------------------------------------------------------------
VOID
EventFieldDup(
	_In_ PSYSMON_DATA_DESCRIPTOR DataDescriptor,
	_In_ ULONG FieldIndex
	)
{
	PVOID dup;

	if( DataDescriptor[FieldIndex].Ptr == NULL ) {

		return;
	}

	dup = malloc( DataDescriptor[FieldIndex].Size );

	if( dup == NULL ) {

		return;
	}

	memcpy( dup, DataDescriptor[FieldIndex].Ptr, DataDescriptor[FieldIndex].Size );

	EventSetFieldD( DataDescriptor, FieldIndex, DataDescriptor[FieldIndex].Type,
					dup, DataDescriptor[FieldIndex].Size, TRUE );
}

//--------------------------------------------------------------------
//
// EventResolveField
//
// This function resolves each field to the appropriate type and an
// output event data descriptor.
//
//--------------------------------------------------------------------
DWORD
EventResolveField(
	_In_opt_ PLARGE_INTEGER Time,
	_In_ PSYSMON_EVENT_TYPE_FMT EventType,
    _In_ PSYSMON_DATA_DESCRIPTOR EventBuffer,
	_In_opt_ PSYSMON_EVENT_HEADER EventHeader,
	_In_ ULONG FieldIndex,
	_Out_ PEVENT_DATA_DESCRIPTOR Output,
	_In_ BOOLEAN ForceOutputString
	)
{
	DWORD	error = ERROR_SUCCESS;
	PSYSMON_DATA_DESCRIPTOR currentBuffer;
#if defined _WIN64 || defined _WIN32
	ULONG   fileIndex, dwCallCount;
	ULONG	numTraceItems, allocSize;
	PULONG	hashType = NULL;
	PSYSMON_RESOLVED_TRACE pResolvedTraceItem;
	PTCHAR	strPtr = NULL;
#endif
	ULONG	size;
	PVOID	ptr;
	TCHAR	tmpStringBuffer[256];
	PPROCESS_CACHE_INFORMATION parentInfo;
	GUID	tmpGuid;
	InTypes inType = EventType->EventOutputTypes[FieldIndex];

	currentBuffer = &EventBuffer[FieldIndex];

	//
	// Checked if already processed
	//
	if( Output[FieldIndex].Ptr != 0 ) {

		// Check that previously string output types are replaced with native.
		// Handle event filtering case where string rendering is required but
		// still let Vista+ event render to use native types.
		if( !ForceOutputString && ( currentBuffer->Type == N_ProcessId ||
									currentBuffer->Type == N_Ulong ||
									currentBuffer->Type == N_Ulong64 ||
									currentBuffer->Type == N_LogonId ||
									currentBuffer->Type == N_GUID ) ) {

			if( EventDataIsAllocated( &Output[FieldIndex] ) ) {

				free( ( PVOID )(ULONG_PTR)Output[FieldIndex].Ptr );
			}

			EventDataDescCreate( &Output[FieldIndex], currentBuffer->Ptr, currentBuffer->Size );
		}

		//
		// Check there are no dependencies
		//
		return ERROR_SUCCESS;
	}

	*tmpStringBuffer = 0;

	//
	// Handle known complex fields with multiple dependencies
	//
	if( EventType == &SYSMONEVENT_CREATE_PROCESS_Type &&
		( FieldIndex == F_CP_ParentCommandLine ||
		  FieldIndex == F_CP_ParentImage ||
		  FieldIndex == F_CP_ParentProcessGuid ||
		  FieldIndex == F_CP_ParentUser ) ) {

		//
		// Resolve parent information
		//
		ProcessCache::Instance().LockCache();

		// #444. Check by process object as well as process ID to minimise the effects of PID reuse..
		parentInfo = ProcessCache::Instance().ProcessGet( EventHeader->m_EventBody.m_ProcessCreateEvent.m_ParentProcessId,
									  &EventHeader->m_EventBody.m_ProcessCreateEvent.m_CreateTime,
									  EventHeader->m_EventBody.m_ProcessCreateEvent.m_ParentProcessObject);
		if( parentInfo ) {

			D_ASSERT( Time->QuadPart >= parentInfo->data->m_CreateTime.QuadPart );

			switch( FieldIndex ) {
			case F_CP_ParentCommandLine:
				EventSetFieldE( EventBuffer, F_CP_ParentCommandLine, N_UnicodeString, parentInfo->data, PC_CommandLine );
				break;
			case F_CP_ParentProcessGuid:
				EventSetFieldX( EventBuffer, F_CP_ParentProcessGuid, N_GUID, parentInfo->uniqueProcessGUID );

				// Dup entries to ensure they don't go away if the cache is cleared. Note this is not required for the two string values
				// since EventSetFieldE allocates and copies those strings.
				EventFieldDup( EventBuffer, F_CP_ParentProcessGuid );
				break;
			case F_CP_ParentImage:
				EventSetFieldE( EventBuffer, F_CP_ParentImage, N_UnicodePath, parentInfo->data, PC_ImagePath );
				break;
			case F_CP_ParentUser:
				TranslateSid( (PSID)ExtGetPtrX( parentInfo->data, PC_Sid, nullptr ), tmpStringBuffer, _countof( tmpStringBuffer ) );
				EventSetFieldS( EventBuffer, F_CP_ParentUser, _tcsdup( tmpStringBuffer ), TRUE );
				break;
			}
		}

		ProcessCache::Instance().UnlockCache();

		if( parentInfo == NULL ) {

			EventSetFieldS( EventBuffer, F_CP_ParentImage, NULL, FALSE );
			EventSetFieldS( EventBuffer, F_CP_ParentCommandLine, NULL, FALSE );
			EventSetFieldX( EventBuffer, F_CP_ParentProcessGuid, N_GUID, DefaultGuid );
			EventSetFieldS( EventBuffer, F_CP_ParentUser, NULL, FALSE );
		}
// On Linux, don't implement hashes yet
#if defined _WIN64 || defined _WIN32
	} else if( currentBuffer->Type == N_Hash ) {

		if( !GetHashTypeInformation( EventType, EventHeader, &hashType, &fileIndex ) ) {

			return ERROR_INVALID_PARAMETER;
		}

		if( currentBuffer->Ptr != NULL && currentBuffer->Size != 0 ) {

			if( !SysmonHashToString( TRUE, *hashType, (PBYTE) currentBuffer->Ptr,
									 tmpStringBuffer, _countof(tmpStringBuffer), FALSE ) ) {

				*tmpStringBuffer = 0;
			}
		} else {

			//
			// Get the file path
			//
			error = EventResolveField( Time, EventType, EventBuffer, EventHeader, fileIndex, Output, ForceOutputString );

			if( error == ERROR_SUCCESS ) {

				//
				// Re-compute the hash and overwrite the hashtype
				//
				GetFileHash( *hashType, (PTCHAR)EventBuffer[fileIndex].Ptr,
							 tmpStringBuffer, _countof(tmpStringBuffer), FALSE );
			}
		}

		EventSetFieldS( EventBuffer, FieldIndex, _tcsdup( tmpStringBuffer ), TRUE );
#endif
	} else if( currentBuffer->Ptr == NULL || currentBuffer->Size == 0 ) {

		//
		// These fields depend on the parent process id resolution
		//
		if( EventType == &SYSMONEVENT_CREATE_PROCESS_Type &&
			(FieldIndex == F_CP_ParentProcessGuid || FieldIndex == F_CP_ParentImage || FieldIndex == F_CP_ParentCommandLine) ) {

			error = EventResolveField( Time, EventType, EventBuffer, EventHeader, F_CP_ParentProcessId, Output, ForceOutputString );

			if( error != ERROR_SUCCESS ) {

				goto error;
			}
		} else {

			if( inType == I_UnicodeString ) {

				DBG_MODE( _tprintf(_T("[!] Default string for %s on %s - %p,%d\n"),
								   EventType->FieldNames[FieldIndex], EventType->EventName,
								   currentBuffer->Ptr, currentBuffer->Size ) );
				EventSetFieldS( EventBuffer, FieldIndex, NULL, FALSE );
			} else {

				error = ERROR_INVALID_PARAMETER;
				goto error;
			}
		}
	}

	*tmpStringBuffer = 0;
	ptr = currentBuffer->Ptr;
	size = currentBuffer->Size;

	switch( currentBuffer->Type ) {
	case N_UnicodeString:
	case N_EscapeUnicodeString:
		if( inType != I_UnicodeString ) {

			error = ERROR_INVALID_PARAMETER;
			goto error;
		}
		//
		// Default string or need to dedup with null byte
		//
	    if( !IsNullTerminated( ptr, size ) ) {

			EventSetFieldS( EventBuffer, FieldIndex, DupStringWithoutNullChar( (PTCHAR) ptr, size ), TRUE );
		}
		break;
// no registry on Linux
#if defined _WIN64 || defined _WIN32
	case N_RegistryPath:
		EventSetFieldS( EventBuffer, FieldIndex, TranslateRegistryPath( ptr, size ), TRUE );
		break;

	case N_UnicodePath:
		EventSetFieldS( EventBuffer, FieldIndex, TranslateNtPath( ptr, size ), TRUE );
		break;
#elif defined __linux__
// don't translate path on Linux
	case N_UnicodePath:
		EventSetFieldS( EventBuffer, FieldIndex, DupStringWithoutNullChar( (PTCHAR)ptr, size ), TRUE );
		break;
#endif
	case N_Ulong:
		if( inType == I_UInt16 ) {

			// Correct the size
			if( EventBuffer[FieldIndex].Size == sizeof(ULONG) ) {

				EventBuffer[FieldIndex].Size = sizeof(WORD);
			}
		} else if( (inType != I_UInt32 && inType != I_Boolean && inType != I_HexInt32) || size != sizeof(ULONG) ) {

			error = ERROR_INVALID_PARAMETER;
			goto error;
		}
		break;

	case N_Ulong64:
		if( (inType != I_UInt64 && inType != I_HexInt64) || size != sizeof(ULONG64) ) {

			error = ERROR_INVALID_PARAMETER;
			goto error;
		}
		break;

	case N_Ptr:
		if( (inType != I_UnicodeString) || size != sizeof(PVOID) ) {

			error = ERROR_INVALID_PARAMETER;
			goto error;
		}
		_stprintf_s( tmpStringBuffer, _countof(tmpStringBuffer), _T("0x%p"), *(PVOID*) ptr );
		EventSetFieldS( EventBuffer, FieldIndex, _tcsdup( tmpStringBuffer ), TRUE );
		break;

	case N_LargeTime:
		if( inType != I_UnicodeString || size != sizeof(LARGE_INTEGER) ) {

			error = ERROR_INVALID_PARAMETER;
			goto error;
		}

		TimestampFormat( tmpStringBuffer, _countof(tmpStringBuffer), (LARGE_INTEGER*)ptr );
		EventSetFieldS( EventBuffer, FieldIndex, _tcsdup( tmpStringBuffer ), TRUE );
		break;

	case N_ProcessId:
		if( size != sizeof(ULONG) ) {

			error = ERROR_INVALID_PARAMETER;
			goto error;
		}

		// For DNS users, the ProcessID is used as input for resolving.
		if( ( EventType == &SYSMONEVENT_DNS_QUERY_Type && FieldIndex == F_DQ_User ) ||
			( EventType == &SYSMONEVENT_CLIPBOARD_Type && FieldIndex == F_C_User ) ) {
			ProcessCache::Instance().LockCache();

			parentInfo = ProcessCache::Instance().ProcessGet( *(ULONG*)ptr, nullptr, nullptr );
			if( parentInfo ) {

				TranslateSid( (PSID)ExtGetPtrX( parentInfo->data, PC_Sid, nullptr ), tmpStringBuffer, _countof( tmpStringBuffer ) );
				EventSetFieldS( EventBuffer, FieldIndex, _tcsdup( tmpStringBuffer ), TRUE );
			}

			ProcessCache::Instance().UnlockCache();

			if( parentInfo == NULL ) {

				EventSetFieldS( EventBuffer, FieldIndex, NULL, FALSE );
			}
			break;
		}

		if( inType == I_GUID ) {

			//
			// ProcessId to Process GUID
			//
			ZeroMemory( &tmpGuid, sizeof(tmpGuid) );
			if( EventType == &SYSMONEVENT_CREATE_PROCESS_Type ) {

				GenerateUniquePGUID( &tmpGuid, EventHeader, TRUE );
			} else {

				FetchUniquePGUID( &tmpGuid, *(ULONG*)ptr, TRUE, Time );
			}
			EventSetFieldX( EventBuffer, FieldIndex, N_GUID, tmpGuid );
			EventFieldDup( EventBuffer, FieldIndex );
		} else if( inType == I_UnicodeString ) {

			//
			// ProcessId to unicode string, resolve image name
			//
			FetchImageName( *(ULONG*)ptr, tmpStringBuffer, _countof(tmpStringBuffer), Time );
			EventSetFieldS( EventBuffer, FieldIndex, _tcsdup( tmpStringBuffer ), TRUE );
		} else if( inType != I_UInt32 ) {

			error = ERROR_INVALID_PARAMETER;
			goto error;
		}
		break;

	case N_LogonId:
		if( ( inType != I_HexInt64 && inType != I_GUID && inType != I_UnicodeString ) || size < sizeof(LUID) ) {

			error = ERROR_INVALID_PARAMETER;
			break;
		}

		if( inType == I_GUID ) {

			//
			// LogonId to Logon GUID
			//
			ZeroMemory( &tmpGuid, sizeof(tmpGuid) );
			GenerateUniqueSGUID( &tmpGuid, (LUID*)ptr );
			EventSetFieldX( EventBuffer, FieldIndex, N_GUID, tmpGuid );
			EventFieldDup( EventBuffer, FieldIndex );
        }
		break;

	case N_Sid:
		if( inType != I_UnicodeString && size < sizeof( SID ) ) {

			error = ERROR_INVALID_PARAMETER;
			break;
		}

		if( EventType == &SYSMONEVENT_CREATE_PROCESS_Type && FieldIndex == F_CP_IntegrityLevel ) {
// no integrity level on Linux
#if defined _WIN64 || defined _WIN32
			//
			// Resolve the integrity level if not AppContainer
			//
			if( EventHeader->m_EventBody.m_ProcessCreateEvent.m_IsAppContainer ) {

				strPtr = (PTCHAR)_T("AppContainer");
			} else if( ptr ) {

				strPtr = GetIntegrityLevel( (PSID)ptr );
			} else {

				strPtr = DefaultString;
			}

			EventSetFieldS( EventBuffer, FieldIndex, strPtr, FALSE );
#endif
		} else {

			TranslateSid( (PSID)ptr, tmpStringBuffer, _countof(tmpStringBuffer) );
			EventSetFieldS( EventBuffer, FieldIndex, _tcsdup( tmpStringBuffer ), TRUE );
		}
		break;

	case N_GUID:
		if( inType != I_GUID || size != sizeof(GUID) ) {

			error = ERROR_INVALID_PARAMETER;
			break;
		}
		break;

// no call traces on Linux yet
#if defined _WIN64 || defined _WIN32
	case N_CallTrace:
		if( inType != I_UnicodeString  || (size % sizeof(SYSMON_RESOLVED_TRACE)) != 0 ) {

			error = ERROR_INVALID_PARAMETER;
			break;
		}

		pResolvedTraceItem = (PSYSMON_RESOLVED_TRACE)ptr;
		numTraceItems = size / sizeof(SYSMON_RESOLVED_TRACE);

		if( numTraceItems > SYSMON_MAX_SBT_FRAMES ) {

			numTraceItems = SYSMON_MAX_SBT_FRAMES;
		}

		if( 0 == numTraceItems || NULL == pResolvedTraceItem ) {

			EventSetFieldS( EventBuffer, FieldIndex, NULL, FALSE );
		} else {

			allocSize = (SYSMON_MAX_IMAGE_PATH + 26) * numTraceItems * sizeof(TCHAR);
			strPtr = (PTCHAR) malloc( allocSize );

			if( strPtr == NULL ) {

				error = ERROR_OUTOFMEMORY;
				break;
			}

			ZeroMemory( strPtr, allocSize );

			//
			// Collect call stack output in callStack
			//
			for( dwCallCount = 0;
				 dwCallCount < numTraceItems;
				 dwCallCount++ )
			{
				TCHAR tmpString[_countof(((SYSMON_RESOLVED_TRACE*)0)->m_ModulePath) +sizeof("|+0xffffffff`ffffffff(wow64)") + sizeof('\0')];

				ZeroMemory(tmpString, sizeof(tmpString));

				if( 0 == pResolvedTraceItem->m_ModuleBase &&
					0 == pResolvedTraceItem->m_ModuleSize ) {

					_sntprintf_s(tmpString,
								_countof(tmpString),
								_TRUNCATE,
								_T("%sUNKNOWN(%p)%s"),
								(dwCallCount > 0) ? _T("|") : _T(""),
								(PVOID)pResolvedTraceItem->m_FrameReturnAddress,
								(pResolvedTraceItem->m_IsWow64) ? _T("(wow64)") : _T("") );
				}else {

					_sntprintf_s(tmpString,
								_countof(tmpString),
								_TRUNCATE,
								_T("%s%s+%x%s"),
								(dwCallCount > 0) ? _T("|") : _T(""),
								pResolvedTraceItem->m_ModulePath,
								int(pResolvedTraceItem->m_FrameReturnAddress - pResolvedTraceItem->m_ModuleBase),
								(pResolvedTraceItem->m_IsWow64) ? _T("(wow64)") : _T("") );
				}

				_tcsncat_s( strPtr,
						   allocSize / sizeof(TCHAR),
						   tmpString,
						   _TRUNCATE);

				pResolvedTraceItem++;
			}

			EventSetFieldS( EventBuffer, FieldIndex, strPtr, TRUE );
		}
		break;
#endif

	default:
		error = ERROR_INVALID_PARAMETER;
		break;
	}

	//
	// No integrity level before Vista
	//
	if( bPreVista && EventType == &SYSMONEVENT_CREATE_PROCESS_Type && FieldIndex == F_CP_IntegrityLevel ) {

		EventSetFieldS( EventBuffer, FieldIndex, _T("no level"), FALSE );
		error = ERROR_SUCCESS;
	}

#if defined __linux__
    // no integrity level on Linux
	if( EventType == &SYSMONEVENT_CREATE_PROCESS_Type && FieldIndex == F_CP_IntegrityLevel ) {

		EventSetFieldS( EventBuffer, FieldIndex, _T("no level"), FALSE );
		error = ERROR_SUCCESS;
	}

    // Cannot tell if a deleted file was an executable on Linux
	if( EventType == &SYSMONEVENT_FILE_DELETE_Type && FieldIndex == F_FD_IsExecutable ) {

		EventSetFieldS( EventBuffer, FieldIndex, _T("-"), FALSE );
		error = ERROR_SUCCESS;
	}
#endif

	//
	// By default set the current buffer as the output event data descriptor
	//
	if( error == ERROR_SUCCESS ) {

		//
		// Test the output is expected
		//
		D_ASSERT( currentBuffer->Type == N_UnicodeString ||
				  currentBuffer->Type == N_EscapeUnicodeString ||
				  currentBuffer->Type == N_UnicodePath ||
				  currentBuffer->Type == N_Ulong ||
				  currentBuffer->Type == N_RegistryPath ||
				  currentBuffer->Type == N_Ulong64 ||
				  currentBuffer->Type == N_GUID ||
				  currentBuffer->Type == N_LogonId ||
				  currentBuffer->Type == N_ProcessId );

		if( ForceOutputString && ( currentBuffer->Type != N_UnicodeString && currentBuffer->Type != N_RegistryPath &&
				currentBuffer->Type != N_EscapeUnicodeString && currentBuffer->Type != N_UnicodePath ) ) {

			*tmpStringBuffer = 0;
			ptr = currentBuffer->Ptr;
			size = currentBuffer->Size;

			//
			// Translate fields to strings
			//
			switch( currentBuffer->Type ) {
			case N_ProcessId:
			case N_Ulong:

				if( inType == I_Boolean ) {

					if( *(ULONG*) ptr == 0 ) {

						EventDataDescCreateS( &Output[FieldIndex], _T("false") );
					} else {

						EventDataDescCreateS( &Output[FieldIndex], _T("true") );
					}
				} else {

					if( inType == I_UInt16 ) {

						_stprintf_s( tmpStringBuffer, _countof(tmpStringBuffer), _T("%hu"), *(USHORT*) ptr );
					} else if( inType == I_HexInt32 ) {

						_stprintf_s( tmpStringBuffer, _countof(tmpStringBuffer), _T("0x%x"), *(ULONG*) ptr );
					} else {

						_stprintf_s( tmpStringBuffer, _countof(tmpStringBuffer), _T("%u"), *(ULONG*) ptr );
					}
					EventDataDescCreateS( &Output[FieldIndex], _tcsdup( tmpStringBuffer ) );
					EventDataMarkAllocated( &Output[FieldIndex] );
				}
				break;

			case N_Ulong64:
                Ulong64ToString( tmpStringBuffer, _countof(tmpStringBuffer), *(ULONG64*) ptr );
				EventDataDescCreateS( &Output[FieldIndex], _tcsdup( tmpStringBuffer ) );
				EventDataMarkAllocated( &Output[FieldIndex] );
				break;

			case N_LogonId:
                LogonIdToString( tmpStringBuffer, _countof(tmpStringBuffer), *(ULONG64*) ptr );
				EventDataDescCreateS( &Output[FieldIndex], _tcsdup( tmpStringBuffer ) );
				EventDataMarkAllocated( &Output[FieldIndex] );
				break;

			case N_GUID:
#if defined _WIN64 || defined _WIN32
				StringFromGUID2( *(const GUID *)ptr, (LPOLESTR) tmpStringBuffer, _countof(tmpStringBuffer) );
#elif defined __linux__
				StringFromGUID2( *(const GUID *)ptr, tmpStringBuffer, _countof(tmpStringBuffer) );
#endif
				EventDataDescCreateS( &Output[FieldIndex], _tcsdup( tmpStringBuffer ) );
				EventDataMarkAllocated( &Output[FieldIndex] );
				break;

			default:
			    error = ERROR_INVALID_BLOCK;
				break;
			}
		} else {

			EventDataDescCreate( &Output[FieldIndex], currentBuffer->Ptr, currentBuffer->Size );
		}
	}

error:
	if( error != ERROR_SUCCESS ) {

		PrintErrorEx( (PTCHAR)_T(__FUNCTION__), error, (PTCHAR)_T("Failed to process argument %s on %s"),
					  EventType->FieldNames[FieldIndex], EventType->EventName );
	}
	return error;
}

//--------------------------------------------------------------------
//
// ProcessEventRules
//
// Main rule processing function checking if an event should be included
// or excluded.
//
//--------------------------------------------------------------------
RuleDefaultType
ProcessEventRules(
	_In_opt_ PLARGE_INTEGER EventTime,
	_In_ PSYSMON_EVENT_TYPE_FMT EventType,
	_In_opt_ PSYSMON_DATA_DESCRIPTOR EventBuffer,
	_In_opt_ PSYSMON_EVENT_HEADER EventData,
	_In_ PEVENT_DATA_DESCRIPTOR Output,
	_Out_opt_ PWCHAR* RuleName,
	_Out_opt_ BOOLEAN* Failures
	)
{
	RULE_CONTEXT 	ruleContext;
	RuleDefaultType	ret;

	if( !InitializeRuleContext( &ruleContext ) ) {

		return EventType->Default;
	}

	ret = FilterEventRules( &ruleContext, EventTime, EventType, EventBuffer, EventData, Output, RuleName, NULL );
	ReleaseRuleContext( &ruleContext );
	return ret;
}

//--------------------------------------------------------------------
//
// ProcessEventRulesDry
//
// Main rule processing function without output captured.
//
//--------------------------------------------------------------------
RuleDefaultType
ProcessEventRulesDry(
	_In_opt_ PLARGE_INTEGER EventTime,
	_In_ PSYSMON_EVENT_TYPE_FMT EventType,
	_In_opt_ PSYSMON_DATA_DESCRIPTOR EventBuffer,
	_In_opt_ PSYSMON_EVENT_HEADER EventData,
	_Out_opt_ PWCHAR* RuleName
	)
{
	ULONG index;
	EVENT_DATA_DESCRIPTOR output[SYSMON_MAX_EVENT_Fields] = {0,};
	RuleDefaultType ret;

	ret = ProcessEventRules( EventTime, EventType, EventBuffer, EventData, output, RuleName, NULL );

	// Clean-up allocated memory
	for( index = 0; index < EventType->FieldCount; index++ ) {

		if( EventDataIsAllocated( &output[index] ) ) {

			free( ( PVOID )(ULONG_PTR)output[index].Ptr );
		}
	}

	return ret;
}

//--------------------------------------------------------------------
//
// GetDescriptorSize
//
// Calculates the overall size for an event descriptor
//
//--------------------------------------------------------------------
int GetDescriptorSize(PEVENT_DATA_DESCRIPTOR descriptor, int maxFields)
{
	int rc = 0;

	if (NULL != descriptor)
	{
		for (int index = 0; index < maxFields; index++)
		{
			rc += descriptor[index].Size;
		}
	}

	return rc;
}

//--------------------------------------------------------------------
//
// EventProcess
//
// Process the resolved event to output the event
//
//--------------------------------------------------------------------
DWORD
EventProcess(
	_In_ PSYSMON_EVENT_TYPE_FMT EventType,
    _In_ PSYSMON_DATA_DESCRIPTOR EventBuffer,
	_In_ PSYSMON_EVENT_HEADER EventData,
	_In_ PSID UserSid
	)
{
	ULONG					index;
	RuleDefaultType				ruleDefault;
	DWORD					error = ERROR_SUCCESS;
	InTypes					outputType;
	EVENT_DATA_DESCRIPTOR 	Output[SYSMON_MAX_EVENT_Fields] = {0,};
    LARGE_INTEGER			currentTime;
	PLARGE_INTEGER			eventTime = NULL;
	PWCHAR					ruleName = NULL;
#if defined _WIN64 || defined _WIN32
	PTCHAR					OutStr[SYSMON_MAX_EVENT_Fields] = {0,};
#elif defined __linux__
    size_t                  eventMax = 65536;
    char                    event[eventMax];
#endif

	//
	// Ensure the event has a timestamp
	//
	if( EventType->EventTimeField != NO_FIELD ) {

		eventTime = (PLARGE_INTEGER)(ULONG_PTR)EventBuffer[EventType->EventTimeField].Ptr;

		//
		// No time given?
		//
		if( eventTime == NULL ) {

#if defined _WIN64 || defined _WIN32
            SYSTEMTIME				sysTime;
            FILETIME				fileTime;
			GetSystemTime( &sysTime );

			if( SystemTimeToFileTime( &sysTime, &fileTime ) ) {

				currentTime.LowPart = fileTime.dwLowDateTime;
				currentTime.HighPart = fileTime.dwHighDateTime;

				eventTime = &currentTime;
				EventSetFieldX( EventBuffer, EventType->EventTimeField, N_LargeTime, currentTime );
			}
#elif defined __linux__
            GetSystemTimeAsLargeInteger( &currentTime );
            eventTime = &currentTime;
            EventSetFieldX( EventBuffer, EventType->EventTimeField, N_LargeTime, currentTime );
#endif
		}
	}

	//
	// Rule filtering. Config changes are exempt from filtering.
	//
	if( (EventType != &SYSMONEVENT_SERVICE_STATE_CHANGE_Type && EventType != &SYSMONEVENT_SERVICE_CONFIGURATION_CHANGE_Type ) &&
		EventType != &SYSMONEVENT_ERROR_Type &&
		((EventData == NULL || !EventData->m_PreFiltered)) ) {

		DBG_MODE_VERBOSE(_tprintf(_T("[R] Checking filter for %d\n"), EventType->EventId));

		//
		//  Process the event
		//
		ruleDefault = ProcessEventRules( eventTime,
							EventType, EventBuffer, EventData, Output, &ruleName, NULL );

		//
		// Do we need to exclude this entry
		//
		D_ASSERT( ruleDefault == Rule_include || ruleDefault == Rule_exclude );

		if( ruleDefault == Rule_exclude ) {

			//
			// Certain fields need to be registered no matter what
			//
			if( EventType == &SYSMONEVENT_CREATE_PROCESS_Type ) {

				EventResolveField( eventTime,
								   EventType,
								   EventBuffer,
								   EventData,
								   F_CP_ProcessGuid,
								   Output,
								   TRUE );

				EventResolveField( eventTime,
								   EventType,
								   EventBuffer,
								   EventData,
								   F_CP_LogonGuid,
								   Output,
								   TRUE );

				EventResolveField( eventTime,
								   EventType,
								   EventBuffer,
								   EventData,
								   F_CP_ParentProcessGuid,
								   Output,
								   TRUE );
			}
			DBG_MODE_VERBOSE( _tprintf( _T("[R] Excluded an event '%s' based on rules\n"), EventType->EventName ) );
			error = ERROR_NO_MATCH;
			goto cleanup;
		}

		//
		// Ensure we clean-up output elements if the output is not a string
		//
		if( !bPreVista ) {

			for( index = 0; index < EventType->FieldCount; index++ ) {

				outputType = EventType->EventOutputTypes[index];

				if( outputType == I_UnicodeString ) {

					continue;
				}

				if( EventDataIsAllocated( &Output[index] ) ) {

					free( (PVOID)(ULONG_PTR)Output[index].Ptr );
				}

				ZeroMemory( &Output[index], sizeof(EVENT_DATA_DESCRIPTOR) );
			}
		}

		//
		// RuleName is always field 0, but is not included in sysmon metaevents
		//
#if defined _WIN64 || defined _WIN32
		EventSetFieldS( EventBuffer, 0, ruleName ? ruleName : _T( "" ), FALSE );
#elif defined __linux__
        if (ruleName) {
            size_t ruleNameUTF8Size = UTF16toUTF8( NULL, ruleName, 0 );
            char* ruleNameUTF8 = (char*) malloc(ruleNameUTF8Size);
            UTF16toUTF8( ruleNameUTF8, ruleName, ruleNameUTF8Size );
            EventSetFieldS( EventBuffer, 0, ruleNameUTF8, FALSE );
        } else {
            EventSetFieldS( EventBuffer, 0, "", FALSE );
        }
#endif

	} else {

		DBG_MODE( _tprintf( _T("[R] No global rule or pre-filtered for %d\n"), EventType->EventId ) );
	}

	//
	// Resolve each field to match the intype (if needed)
	//
	for( index = 0; index < EventType->FieldCount; index++ ) {

		EventResolveField( eventTime,
						   EventType,
						   EventBuffer,
						   EventData,
						   index,
						   Output,
						   bPreVista );
	}

#ifdef _DEBUG
	//
	// Check each field was resolved during testing
	//
	for( index = 0; index < EventType->FieldCount; index++ ) {

		D_ASSERT( Output[index].Ptr != 0 );
	}
#endif

    //
    // Trim any fields that the configuration specifies
    //
    for( index = 0; index < EventType->FieldCount; index++ ) {

        TrimStringToNChars((PTCHAR)(ULONG_PTR)Output[index].Ptr, GetVariableFieldSize(EventType->EventId, index),
                &Output[index].Size);
    }

	//
	// If the event is still too long, look at trimming the command line
	//
	if (EventType == &SYSMONEVENT_CREATE_PROCESS_Type)
	{
		// ETW has an upper limit of 64000 characters. If we exceed this EventWrite will fail silently. We used to truncate the command line to 8k
		// but this can be exploited to hide the command line. Thus the best we can do is reduce the command line to the maximum length we can log
		int descriptorSize = GetDescriptorSize(Output, SYSMONEVENT_CREATE_PROCESS_Count);
		if (descriptorSize > MAX_EVENT_PACKET_SIZE)
		{
			// Start by trimming the parent command line. The intuition here is that we can sacrifice the parent command line more readily than that
			// of the child because the parent command line was already logged when that process was created
			if (TrimStringByNChars(((PTCHAR)(ULONG_PTR)Output[F_CP_ParentCommandLine].Ptr),  MAX_PATH, (descriptorSize - MAX_EVENT_PACKET_SIZE) / sizeof(TCHAR)))
			{
				Output[F_CP_ParentCommandLine].Size = (ULONG)((sizeof('\0') + _tcslen((PTCHAR)Output[F_CP_ParentCommandLine].Ptr)) * sizeof(TCHAR));
			}

			// Hopefully that's enough but if not reduce the size of the command line too
			descriptorSize = GetDescriptorSize(Output, SYSMONEVENT_CREATE_PROCESS_Count);
			if (descriptorSize > MAX_EVENT_PACKET_SIZE)
			{
				// Start by trimming the parent command line. The intuition here is that we can sacrifice the parent command line more readily than that
				// of the child because the parent command line was already logged when that process was created
				if (TrimStringByNChars(((PTCHAR)(ULONG_PTR)Output[F_CP_CommandLine].Ptr), MAX_PATH, (descriptorSize - MAX_EVENT_PACKET_SIZE) / sizeof(TCHAR)))
				{
					Output[F_CP_CommandLine].Size = (ULONG)((sizeof('\0') + _tcslen((PTCHAR)Output[F_CP_CommandLine].Ptr)) * sizeof(TCHAR));
				}
			}
		}
	}

	//
	// Raise the event based on the current version of windows
	//
#if defined _WIN64 || defined _WIN32
	if( !bPreVista ) {

		error = PfnEventWrite( g_Event, EventType->EventDescriptor, EventType->FieldCount, Output );

	} else {

		//
		// Transform to string if needed
		//
		for( index = 0; index < EventType->FieldCount; index++ ) {

			OutStr[index] = (PTCHAR)(ULONG_PTR)Output[index].Ptr;
		}

		if( !ReportEvent( g_hEventSource, EVENTLOG_INFORMATION_TYPE,
						  0, EventType->EventLegacyId, UserSid, EventType->FieldCount, 0, (LPCWSTR *) OutStr, NULL ) ) {

			error = GetLastError();

			//
			// Error when the event viewer is offline. It is a limitation before Vista.
			//
			if( error == RPC_S_UNKNOWN_IF || error == ERROR_GEN_FAILURE ) {

				error = ERROR_SUCCESS;
			}
		}
	}
#elif defined __linux__
    //
    // Transform to string for Syslog
    //
    FormatSyslogString( event, eventMax, EventType, Output, EventType->FieldCount );
    syslogHelper(LOG_USER | LOG_INFO, "%s", event);
#endif

	//
	// Output debug information if needed
	//
	DBG_MODE(
		EnterCriticalSection( &g_DebugModePrintCriticalSection );
		_tprintf( _T("Event %s\n"), EventType->EventName );
		for( index = 0; index < EventType->FieldCount; index++ ) {

			if( !bPreVista ) {

				if( EventDataIsAllocated( &Output[index] ) ) {

					free( (PVOID)(ULONG_PTR)Output[index].Ptr );
				}

				ZeroMemory( &Output[index], sizeof(EVENT_DATA_DESCRIPTOR) );
				EventResolveField( eventTime,
								   EventType,
								   EventBuffer,
								   EventData,
								   index,
								   Output,
								   TRUE );
			}

			_tprintf( _T("\t%s: %s\n"), EventType->FieldNames[index], Output[index].Ptr ? (PTCHAR)(ULONG_PTR)Output[index].Ptr : _T("--NULL--") );
		}
		LeaveCriticalSection( &g_DebugModePrintCriticalSection );
	)

cleanup:
	//
	// Clean-up allocated memory
	//
	for( index = 0; index < EventType->FieldCount; index++ ) {

		if( EventBuffer[index].Allocated ) {

			free( EventBuffer[index].Ptr );
		}
		if( EventDataIsAllocated( &Output[index] ) ) {

			free( (PVOID)(ULONG_PTR)Output[index].Ptr );
		}
	}

	//
	// Do not recurse
	//
	if( error != ERROR_SUCCESS && error != ERROR_NO_MATCH && EventType != &SYSMONEVENT_ERROR_Type) {

		PrintErrorEx( (PTCHAR)_T(__FUNCTION__), error, (PTCHAR)_T("Failed to process event %s"), EventType->EventName );
	}

	return error;
}

#if defined _WIN64 || defined _WIN32

//--------------------------------------------------------------------
//
// ReportError
//
// Report an error in sysmon handling
//
//--------------------------------------------------------------------
VOID ReportError(
	IN PTCHAR ID,
	IN PTCHAR ErrorDescription,
	IN PTCHAR Format,
	IN va_list args
	)
{
	TCHAR						Description[1024];
    SYSMON_DATA_DESCRIPTOR	    eventBuffer[SYSMON_MAX_EVENT_Fields] = {(NativeTypes) 0};
	DWORD						error = ERROR_SUCCESS;

	_vstprintf_s( Description, _countof(Description), Format, args );

	if( ErrorDescription != NULL ) {

		_tcsncat_s(Description, _countof(Description), _T(" - Last error: "), _TRUNCATE);
		_tcsncat_s(Description, _countof(Description), ErrorDescription, _TRUNCATE);
	}

	if( !bInitialized ) {

		DBG_MODE( _ftprintf( stderr, _T("Could not report error in %s: %s\n"), ID, Description ) )
	    else {
			_tprintf( _T("%s Error: %s\n"), ID, Description );
		}
		return;
	}

	//
	// Output message string on stderr.
	//
	DBG_MODE( _ftprintf( stderr, _T("%s Error: %s\n"), ID, Description ) );

	EventSetFieldS( eventBuffer, F_E_ID, ID, FALSE );
	EventSetFieldS( eventBuffer, F_E_Description, Description, FALSE );

	error = EventProcess( &SYSMONEVENT_ERROR_Type, eventBuffer, NULL, NULL );

	//
	// Force assert if we failed to register the error
	//
	_ASSERTE( error == ERROR_SUCCESS );
	D_ASSERT_NOREPORT(!"Break on reported error for debug build");
}


#if !defined(SYSMON_SHARED) && !defined(SYSMON_PUBLIC)
// Handle to the trace file holding all dispatched events.
HANDLE g_hTraceTarget = INVALID_HANDLE_VALUE;

// InitTraceEvents opens the file to save event traces for each dispatched event.
DWORD InitTraceEvents(VOID)
{
	TCHAR		Path[MAX_PATH+1];
	TCHAR		TraceEvents[MAX_PATH+1];
	HKEY		hDriverKey;
	DWORD		regType, archiveDirSize, error;

	_stprintf_s( Path, _countof(Path), _T("System\\CurrentControlSet\\Services\\%s\\Parameters"), SysmonDriverName );
	error = RegOpenKeyEx( HKEY_LOCAL_MACHINE, Path, 0, KEY_READ, &hDriverKey );
	if( error == ERROR_SUCCESS ) {

		archiveDirSize = _countof(TraceEvents);
		error = RegQueryValueEx( hDriverKey, _T("TraceEvents"), NULL, &regType, (LPBYTE)TraceEvents, &archiveDirSize );

		if( error == ERROR_SUCCESS ) {

			if( regType != REG_SZ ) {

				error = ERROR_INVALID_DATA;
			}
		}
		RegCloseKey( hDriverKey );
	}

	if ( error != ERROR_SUCCESS ) {
		if( error == ERROR_FILE_NOT_FOUND ) {
			return ERROR_SUCCESS;
		}

		PrintErrorEx( _T(__FUNCTION__), error, _T("Failed to open driver registry key for tracing") );
		return error;
	}

	if( _tcslen( TraceEvents ) == 0 ) {
		return ERROR_SUCCESS;
	}

	HANDLE hFile = CreateFile(TraceEvents, GENERIC_WRITE | FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if( hFile == INVALID_HANDLE_VALUE ) {
		error = GetLastError();
		PrintErrorEx( _T(__FUNCTION__), error, _T("CreateFile for the tracefile failed") );
		return error;
	}

	g_hTraceTarget = hFile;
	return ERROR_SUCCESS;
}

// TraceEvents is called for each event dispatched and save them to a binary trace file.
VOID TraceEvents(_In_ PSYSMON_EVENT_HEADER event)
{
	if( g_hTraceTarget == INVALID_HANDLE_VALUE ) {
		return;
	}

	if( event->m_EventSize < sizeof(*event) ) {
		_tprintf( _T( "Invalid size for event %u\n" ), event->m_EventSize );
		return;
	}

	DWORD written;
	if( !WriteFile( g_hTraceTarget, event, event->m_EventSize, &written, NULL ) ) {
		PrintErrorEx( _T(__FUNCTION__), GetLastError(), _T("WriteFile to trace event output failed") );
		return;
	}

	if( written != event->m_EventSize ) {
		_tprintf( _T("Invalid written data %u vs %u\n"), written, event->m_EventSize );
		return;
	}
}
#else
#define TraceEvents(x)
#endif

#elif defined __linux__
// Linux version of TraceEvents

#if !defined(SYSMON_SHARED) && !defined(SYSMON_PUBLIC)
// Handle to the trace file holding all dispatched events.
FILE* g_hTraceTarget = NULL;

// TraceEvents is called for each event dispatched and save them to a binary trace file.
VOID TraceEvents(_In_ PSYSMON_EVENT_HEADER event)
{
	if( g_hTraceTarget == NULL ) {
		return;
	}

	if( event->m_EventSize < sizeof(*event) ) {
		_tprintf( _T( "Invalid size for event %u\n" ), event->m_EventSize );
		return;
	}

	DWORD written;
    written = fwrite( event, 1, event->m_EventSize, g_hTraceTarget );
    if ( written < event->m_EventSize ) {
		_tprintf( _T("WriteFile to trace event output failed: %s\n"), strerror( errno ) );
		_tprintf( _T("Invalid written data %u vs %u\n"), written, event->m_EventSize );
		return;
	}
}
#else
#define TraceEvents(x)
#endif

#endif

//--------------------------------------------------------------------
//
// DispatchEvent
//
// Dispatch received event
//
//--------------------------------------------------------------------
DWORD DispatchEvent(
	_In_ PVOID event
	)
{
	DWORD							error = ERROR_SUCCESS;
	PSYSMON_EVENT_HEADER			eventHeader;
	PSYSMON_PROCESS_CREATE			procCreate;
	PSYSMON_FILE_TIME				fileTime;
	PSYSMON_PROCESS_TERMINATE 		processTerminate;
	PSYSMON_KERNEL_ERROR			kernelError;
	PSYSMON_FILE_CREATE				fileCreate;
	PTCHAR							companyName, fileVersion, productName, fileDescription, originalFileName;
	PTCHAR							id = NULL, message = NULL;
	GUID							guid;
	SYSMON_DATA_DESCRIPTOR			eventBuffer[SYSMON_MAX_EVENT_Fields] = {(NativeTypes) 0};
	PSYSMON_PROCESS_ACCESS			processAccess;
	PSYSMON_EVENT_TYPE_FMT			eventType;
	PSYSMON_FILE_DELETE				fileDelete;
	PSYSMON_RAWACCESS_READ			rawAccessRead;

#if defined _WIN64 || defined _WIN32
	DWORD							bytesReturned;
	PSYSMON_EVENT_HEADER			duplicate;
	PSYSMON_IMAGE_LOAD				imageLoad;
	PSYSMON_CREATE_REMOTE_THREAD	createRemoteThread;
	PSYSMON_REGISTRY_EVENT			registryEvent;
	PSYSMON_PIPE_EVENT				pipeEvent;
	PSYSMON_PROCESS_TAMPERING		processTamperingEvent;
	PTCHAR							imagePath = NULL;
	TCHAR							tmpStringBuffer[256];
	PHANDLE							token;
	SYSMON_FILE_DELETE_FILTER_RESULT fileDeleteFilterResult;
#endif

	eventHeader = (PSYSMON_EVENT_HEADER) event;

	DBG_MODE_VERBOSE( _tprintf( _T( "Received event %d\n" ), eventHeader->m_EventType ) );

	TraceEvents(eventHeader);

	switch( eventHeader->m_EventType ) {

	case ConfigUpdate:
		//
		// Configuration updates are responded to by
		// the configuration change notification thread to
		// avoid a deadlock with file delete caused by ETW
		// DNS enab/edisable
		//
		break;

	case KernelError:
		kernelError = &eventHeader->m_EventBody.m_KernelErrorEvent;
		id = ExtGetString( kernelError->m_Extensions, kernelError + 1, KE_ID );
		message = ExtGetString( kernelError->m_Extensions, kernelError + 1, KE_Message );

		//
		// Process the kernel error only if we have a message
		//
		if( message != NULL ) {

			if( id == NULL ) {

				id = _tcsdup( _T("Kernel") );
			}

			PrintErrorEx( id, 0, (PTCHAR)_T("%s"), message );
		}

		if( id ) {


			free( id );
		}
		if( message ) {

			free( message );
		}
		break;

	case ProcessCreateCache:
		// Missed this process starting, just update the cache
		GenerateUniquePGUID( &guid, eventHeader, TRUE );
		break;

	case ProcessCreate:
		procCreate = &eventHeader->m_EventBody.m_ProcessCreateEvent;

#if defined _WIN64 || defined _WIN32
		imagePath = ExtTranslateNtPath(procCreate->m_Extensions, procCreate + 1, PC_ImagePath);
		GetImageInformation ( imagePath, &fileVersion, &fileDescription,
						&companyName, &productName, &originalFileName );
		free(imagePath);
		imagePath = NULL;
#elif defined __linux__
        fileVersion = NULL;
        fileDescription = NULL;
        companyName = NULL;
        productName = NULL;
        originalFileName = NULL;
#endif

		EventSetFieldX( eventBuffer, F_CP_UtcTime, N_LargeTime, procCreate->m_CreateTime );
		EventSetFieldX( eventBuffer, F_CP_ProcessGuid, N_ProcessId, procCreate->m_ProcessId );
		EventSetFieldX( eventBuffer, F_CP_ProcessId, N_ProcessId, procCreate->m_ProcessId );
		EventSetFieldE( eventBuffer, F_CP_Image, N_UnicodePath, procCreate, PC_ImagePath );

		EventSetFieldS( eventBuffer, F_CP_FileVersion, fileVersion, TRUE );
		EventSetFieldS( eventBuffer, F_CP_Description, fileDescription, TRUE );
		EventSetFieldS( eventBuffer, F_CP_Company, companyName, TRUE );
		EventSetFieldS( eventBuffer, F_CP_Product, productName, TRUE );
		EventSetFieldS( eventBuffer, F_CP_OriginalFileName, originalFileName, TRUE );

#if defined _WIN64 || defined _WIN32
		EventSetFieldE( eventBuffer, F_CP_CommandLine, N_EscapeUnicodeString, procCreate, PC_CommandLine );
#elif defined __linux__
		EventSetFieldE( eventBuffer, F_CP_CommandLine, N_LinuxCommandLine, procCreate, PC_CommandLine );
#endif
		EventSetFieldE( eventBuffer, F_CP_CurrentDirectory, N_UnicodeString, procCreate, PC_CurrentDirectory );
		EventSetFieldE( eventBuffer, F_CP_User, N_Sid, procCreate, PC_Sid );
		EventSetFieldE( eventBuffer, F_CP_User, N_Sid, procCreate, PC_Sid );
		EventSetFieldX( eventBuffer, F_CP_LogonGuid, N_LogonId, procCreate->m_AuthenticationId );
		EventSetFieldX( eventBuffer, F_CP_LogonId, N_LogonId, procCreate->m_AuthenticationId );
		EventSetFieldX( eventBuffer, F_CP_TerminalSessionId, N_Ulong, procCreate->m_SessionId );
		EventSetFieldE( eventBuffer, F_CP_IntegrityLevel, N_Sid, procCreate, PC_IntegrityLevel );
		EventSetFieldE( eventBuffer, F_CP_Hashes, N_Hash, procCreate, PC_Hash );
		EventSetFieldX( eventBuffer, F_CP_ParentProcessId, N_ProcessId, procCreate->m_ParentProcessId );

		EventProcess( &SYSMONEVENT_CREATE_PROCESS_Type, eventBuffer, eventHeader, (PSID)ExtGetPtrX( procCreate, PC_Sid, NULL ) );
		break;

	case ProcessTerminate:
		processTerminate = &eventHeader->m_EventBody.m_ProcessTerminateEvent;

		EventSetFieldX( eventBuffer, F_PT_UtcTime, N_LargeTime, processTerminate->m_EventTime );
		EventSetFieldX( eventBuffer, F_PT_ProcessGuid, N_ProcessId, processTerminate->m_ProcessId );
		EventSetFieldX( eventBuffer, F_PT_ProcessId, N_ProcessId, processTerminate->m_ProcessId );
		EventSetFieldX( eventBuffer, F_PT_Image, N_ProcessId, processTerminate->m_ProcessId );
		EventSetFieldE( eventBuffer, F_PT_User, N_Sid, processTerminate, PT_Sid );

		EventProcess( &SYSMONEVENT_PROCESS_TERMINATE_Type, eventBuffer, eventHeader, (PSID)ExtGetPtrX( processTerminate, PT_Sid, NULL ) );
		ProcessCache::Instance().ProcessRemove( processTerminate->m_ProcessId, NULL, &processTerminate->m_EventTime );
		break;

	case FileDelete:
	case FileDeleteDetected:

		if( eventHeader->m_EventType == FileDelete ) {

			eventType = &SYSMONEVENT_FILE_DELETE_Type;

		}
		else {

			eventType = &SYSMONEVENT_FILE_DELETE_DETECTED_Type;
		}

		fileDelete = &eventHeader->m_EventBody.m_FileDeleteEvent;

		EventSetFieldX( eventBuffer, F_FD_UtcTime, N_LargeTime, fileDelete->m_DeleteTime );
		EventSetFieldX( eventBuffer, F_FD_ProcessGuid, N_ProcessId, fileDelete->m_ProcessId );
		EventSetFieldX( eventBuffer, F_FD_ProcessId, N_ProcessId, fileDelete->m_ProcessId );
		EventSetFieldE( eventBuffer, F_FD_User, N_Sid, fileDelete, FD_Sid );
		EventSetFieldE( eventBuffer, F_FD_Image, N_UnicodePath, fileDelete, FD_ImagePath );
		EventSetFieldE( eventBuffer, F_FD_TargetFilename, N_UnicodePath, fileDelete, FD_FileName );
		EventSetFieldE( eventBuffer, F_FD_Hashes, N_Hash, fileDelete, FD_Hash );
		EventSetFieldX( eventBuffer, F_FD_IsExecutable, N_Ulong, fileDelete->m_IsExecutable );
		if( eventHeader->m_EventType == FileDelete ) {

			EventSetFieldS( eventBuffer, F_FD_Archived, fileDelete->m_Archived, FALSE );
		}

#if defined _WIN64 || defined _WIN32
		//
		// If the kernel event field is non-NULL, this is actually just a filter check rather than
		// an event
		//
		if( fileDelete->m_TrackerId != (ULONG) -1 ) {

			DBG_MODE_VERBOSE( _tprintf( _T( "FileDelete filter check\n" ) ) );

			PLARGE_INTEGER			eventTime = NULL;
			RuleDefaultType			ruleDefault;
			fileDeleteFilterResult.m_TrackerId = fileDelete->m_TrackerId;
			fileDeleteFilterResult.m_PassedFilter = FileDeleteExclude;

			// Check if the file should be archived
			ruleDefault = ProcessEventRulesDry( eventTime,
												&SYSMONEVENT_FILE_DELETE_Type,
												eventBuffer,
												eventHeader,
												NULL );
			if( ruleDefault == Rule_include ) {

				fileDeleteFilterResult.m_PassedFilter = FileDeleteArchiveInclude;

			} else {

				// Check if the delete should be logged
				ruleDefault = ProcessEventRulesDry( eventTime,
													&SYSMONEVENT_FILE_DELETE_DETECTED_Type,
													eventBuffer,
													eventHeader,
													NULL );
				if( ruleDefault == Rule_include ) {

					fileDeleteFilterResult.m_PassedFilter = FileDeleteLoggedInclude;
				}
			}

			//
			// Signal the kernel
			//
			DBG_MODE_VERBOSE( _tprintf( _T( "FileDelete signaling driver\n" ) ) );
			DeviceIoControl( g_hDriver, IOCTL_SYSMON_FILE_DELETE_FILTER_RESULT,
										&fileDeleteFilterResult, sizeof( fileDeleteFilterResult ),
										NULL, 0, &bytesReturned, NULL );
			EventFieldFree( &SYSMONEVENT_FILE_DELETE_Type, eventBuffer );

		} else {
			EventProcess( eventType, eventBuffer, eventHeader, (PSID)ExtGetPtrX( fileDelete, FD_Sid, NULL ) );
		}
#elif defined __linux__
        EventProcess( eventType, eventBuffer, eventHeader, (PSID)ExtGetPtrX( fileDelete, FD_Sid, NULL ) );
#endif
		break;

	case ProcessAccess:
		processAccess = &eventHeader->m_EventBody.m_ProcessAccessEvent;

		EventSetFieldX( eventBuffer, F_AP_UtcTime, N_LargeTime, processAccess->m_EventSystemTime );
		EventSetFieldX( eventBuffer, F_AP_SourceProcessGUID, N_ProcessId, processAccess->m_ClientProcessID );
		EventSetFieldX( eventBuffer, F_AP_SourceProcessId, N_ProcessId, processAccess->m_ClientProcessID );
		EventSetFieldX( eventBuffer, F_AP_SourceThreadId, N_Ulong, processAccess->m_ClientThreadID );
		EventSetFieldE( eventBuffer, F_AP_SourceImage, N_UnicodePath, processAccess, PA_ClientImage );
		EventSetFieldX( eventBuffer, F_AP_TargetProcessGUID, N_ProcessId, processAccess->m_TargetPid );
		EventSetFieldX( eventBuffer, F_AP_TargetProcessId, N_ProcessId, processAccess->m_TargetPid );
		EventSetFieldE( eventBuffer, F_AP_TargetImage, N_UnicodePath, processAccess, PA_TargetImage );
		EventSetFieldX( eventBuffer, F_AP_GrantedAccess, N_Ulong, processAccess->m_GrantedAccess );
		EventSetFieldE( eventBuffer, F_AP_CallTrace, N_CallTrace, processAccess, PA_CallTrace );
		EventSetFieldE( eventBuffer, F_AP_SourceUser, N_Sid, processAccess, PA_SidSource );
		EventSetFieldE( eventBuffer, F_AP_TargetUser, N_Sid, processAccess, PA_SidTarget );

		EventProcess( &SYSMONEVENT_ACCESS_PROCESS_Type, eventBuffer, eventHeader, NULL );
		break;

	case FileTime:
		fileTime = &eventHeader->m_EventBody.m_FileTimeEvent;

		EventSetFieldX( eventBuffer, F_FT_UtcTime, N_LargeTime, fileTime->m_EventTime );
		EventSetFieldX( eventBuffer, F_FT_ProcessGuid, N_ProcessId, fileTime->m_ProcessId );
		EventSetFieldX( eventBuffer, F_FT_ProcessId, N_ProcessId, fileTime->m_ProcessId );
		EventSetFieldE( eventBuffer, F_FT_Image, N_UnicodePath, fileTime, FT_ImagePath );
		EventSetFieldE( eventBuffer, F_FT_TargetFilename, N_UnicodePath, fileTime, FT_FileName );
		EventSetFieldX( eventBuffer, F_FT_CreationUtcTime, N_LargeTime, fileTime->m_CreateTime );
		EventSetFieldX( eventBuffer, F_FT_PreviousCreationUtcTime, N_LargeTime, fileTime->m_PreviousCreateTime );
		EventSetFieldE( eventBuffer, F_FT_User, N_Sid, fileTime, FT_Sid );

		EventProcess( &SYSMONEVENT_FILE_TIME_Type, eventBuffer, eventHeader, (PSID)ExtGetPtrX( fileTime, FT_Sid, NULL ) );
		break;

	case FileCreate:
		fileCreate = &eventHeader->m_EventBody.m_FileCreateEvent;
		EventSetFieldX( eventBuffer, F_FC_UtcTime, N_LargeTime, fileCreate->m_EventTime );
		EventSetFieldX( eventBuffer, F_FC_ProcessGuid, N_ProcessId, fileCreate->m_ProcessId );
		EventSetFieldX( eventBuffer, F_FC_ProcessId, N_ProcessId, fileCreate->m_ProcessId );
		EventSetFieldE( eventBuffer, F_FC_Image, N_UnicodePath, fileCreate, FC_ImagePath );
		EventSetFieldE( eventBuffer, F_FC_TargetFilename, N_UnicodePath, fileCreate, FC_FileName );
		EventSetFieldX( eventBuffer, F_FC_CreationUtcTime, N_LargeTime, fileCreate->m_CreateTime );
		EventSetFieldE( eventBuffer, F_FC_User, N_Sid, fileCreate, FC_Sid );

		EventProcess( &SYSMONEVENT_FILE_CREATE_Type, eventBuffer, eventHeader, (PSID)ExtGetPtrX( fileCreate, FC_Sid, NULL ) );
		break;

#if defined _WIN64 || defined _WIN32
	case FileCreateStreamHash:
		fileCreate = &eventHeader->m_EventBody.m_FileCreateEvent;
		EventSetFieldX( eventBuffer, F_FCSH_UtcTime, N_LargeTime, fileCreate->m_EventTime );
		EventSetFieldX( eventBuffer, F_FCSH_ProcessGuid, N_ProcessId, fileCreate->m_ProcessId );
		EventSetFieldX( eventBuffer, F_FCSH_ProcessId, N_ProcessId, fileCreate->m_ProcessId );
		EventSetFieldE( eventBuffer, F_FCSH_Image, N_UnicodePath, fileCreate, FC_ImagePath );
		EventSetFieldE( eventBuffer, F_FCSH_TargetFilename, N_UnicodePath, fileCreate, FC_FileName );
		EventSetFieldX( eventBuffer, F_FCSH_CreationUtcTime, N_LargeTime, fileCreate->m_CreateTime );
		EventSetFieldE( eventBuffer, F_FCSH_Contents, N_AnsiOrUnicodeString, fileCreate, FC_Contents );

		if( ALGO_INVALID != fileCreate->m_hashType )
		{
			ZeroMemory( tmpStringBuffer, sizeof( tmpStringBuffer ) );
			SysmonHashToString( TRUE, fileCreate->m_hashType, fileCreate->m_filehash, tmpStringBuffer, sizeof( tmpStringBuffer ) / sizeof( TCHAR ), FALSE );
			EventSetFieldTChar( eventBuffer, F_FCSH_Hash, N_UnicodeString, tmpStringBuffer );
		}
		else
		{
			_tcscpy( tmpStringBuffer, _T( "Unknown" ) );
			EventSetFieldTChar( eventBuffer, F_FCSH_Hash, N_UnicodeString, tmpStringBuffer );
		}

		EventSetFieldE( eventBuffer, F_FCSH_User, N_Sid, fileCreate, FC_Sid );

		EventProcess( &SYSMONEVENT_FILE_CREATE_STREAM_HASH_Type, eventBuffer, eventHeader, (PSID)ExtGetPtrX( fileCreate, FC_Sid, NULL ) );
		break;

	case ImageLoad:
		imageLoad = &eventHeader->m_EventBody.m_ImageLoadEvent;

		if( imageLoad->m_FetchedImageName == NULL ) {

			imageLoad->m_FetchedImageName = ExtTranslateNtPath( imageLoad->m_Extensions, imageLoad + 1, IL_ImagePath );
		}

		//
		// Image path is NULL, attempt to resolve it by using the process
		//
		if( !imageLoad->m_Driver && imageLoad->m_FetchedImageName == NULL ) {

			imageLoad->m_FetchedImageName = FetchImageNameFromBase( imageLoad->m_ProcessId, imageLoad->m_ImageBase );

			if( imageLoad->m_FetchedImageName == NULL ) {

				break;
			}
		}

		//
		// Check if we need async callback to resolve the binary signature
		//
		if( imageLoad->m_Signed == NULL && imageLoad->m_FetchedImageName != NULL ) {

			token = (PHANDLE) ExtGetPtrX( imageLoad, IL_Token, NULL );
			duplicate = (PSYSMON_EVENT_HEADER) malloc( eventHeader->m_EventSize );

			if( duplicate != NULL ) {

				tmpStringBuffer[0] = 0;

				//
				// Compute the hash ahead, so we have it on edge cases (w2k3 r2 user-mode module)
				//
				if( imageLoad->m_HashType ) {

					if( SysmonHashToString( TRUE, imageLoad->m_HashType,
											(PBYTE) ExtGetPtr( imageLoad->m_Extensions, imageLoad + 1, IL_Hash, NULL ),
											tmpStringBuffer, _countof(tmpStringBuffer), TRUE ) ) {

						imageLoad->m_HashBuffer = _tcsdup( tmpStringBuffer );
					}
				} else {

					imageLoad->m_HashType = SysmonCryptoCurrent();
					GetFileHash( imageLoad->m_HashType, imageLoad->m_FetchedImageName,
								 tmpStringBuffer, _countof(tmpStringBuffer), TRUE );

					if( tmpStringBuffer[0] != 0 ) {

						imageLoad->m_HashBuffer = _tcsdup( tmpStringBuffer );
					} else {

						imageLoad->m_HashType = 0;
					}
				}

				memcpy( duplicate, eventHeader, eventHeader->m_EventSize );

				if( MyIsFileSigned( imageLoad->m_FetchedImageName,
									token ? *token : NULL,
									imageLoad->m_HashType,
									imageLoad->m_HashBuffer,
									&imageLoad->m_Signed,
									&imageLoad->m_SignatureStatus,
									&imageLoad->m_Signature,
									SignCallback,
									duplicate ) ) {

					//
					// Means it was correctly queued
					// else it was resolved by the cache
					//
					if( imageLoad->m_Signed == NULL ) {

						// Cleanup for duplicate, imageLoad->m_HashBuffer, etc is in HandleSignatureEntry()
						break;
					}
				}

				free( duplicate );
			}
		}

		if( imageLoad->m_Signed == NULL ) {

			imageLoad->m_Signed = _T("failed" );
		}

		//
		// Get version information
		//
		GetImageInformation( imageLoad->m_FetchedImageName,
						&fileVersion, &fileDescription, &companyName,
						&productName, &originalFileName );

		//
		// Fallback to classic event system
		//
		if( imageLoad->m_Driver ) {

			EventSetFieldX( eventBuffer, F_DL_UtcTime, N_LargeTime, imageLoad->m_EventTime );
			EventSetFieldS( eventBuffer, F_DL_ImageLoaded, imageLoad->m_FetchedImageName, TRUE );

			EventSetFieldS( eventBuffer, F_IL_FileVersion, fileVersion, TRUE );
			EventSetFieldS( eventBuffer, F_IL_Description, fileDescription, TRUE );
			EventSetFieldS( eventBuffer, F_IL_Company, companyName, TRUE );
			EventSetFieldS( eventBuffer, F_IL_Product, productName, TRUE );
			EventSetFieldS( eventBuffer, F_IL_OriginalFileName, originalFileName, TRUE );

		    EventSetFieldE( eventBuffer, F_DL_Hashes, N_Hash, imageLoad, IL_Hash );
			EventSetFieldS( eventBuffer, F_DL_Signed, imageLoad->m_Signed, FALSE );
			EventSetFieldS( eventBuffer, F_DL_SignatureStatus, imageLoad->m_SignatureStatus, TRUE );
			EventSetFieldS( eventBuffer, F_DL_Signature, imageLoad->m_Signature, TRUE );

			EventProcess( &SYSMONEVENT_DRIVER_LOAD_Type, eventBuffer, eventHeader, (PSID)ExtGetPtrX( imageLoad, IL_Sid, NULL ) );
		} else {

			EventSetFieldX( eventBuffer, F_IL_UtcTime, N_LargeTime, imageLoad->m_EventTime );
			EventSetFieldX( eventBuffer, F_IL_ProcessGuid, N_ProcessId, imageLoad->m_ProcessId );
			EventSetFieldX( eventBuffer, F_IL_ProcessId, N_ProcessId, imageLoad->m_ProcessId );
			EventSetFieldE( eventBuffer, F_IL_Image, N_UnicodePath, imageLoad, IL_ProcessImage );
			EventSetFieldS( eventBuffer, F_IL_ImageLoaded, imageLoad->m_FetchedImageName, TRUE );

			EventSetFieldS( eventBuffer, F_IL_FileVersion, fileVersion, TRUE );
			EventSetFieldS( eventBuffer, F_IL_Description, fileDescription, TRUE );
			EventSetFieldS( eventBuffer, F_IL_Company, companyName, TRUE );
			EventSetFieldS( eventBuffer, F_IL_Product, productName, TRUE );

			EventSetFieldS(eventBuffer, F_IL_OriginalFileName, originalFileName, TRUE);

			EventSetFieldE( eventBuffer, F_IL_Hashes, N_Hash, imageLoad, IL_Hash );
			EventSetFieldS( eventBuffer, F_IL_Signed, imageLoad->m_Signed, FALSE );
			EventSetFieldS( eventBuffer, F_IL_SignatureStatus, imageLoad->m_SignatureStatus, TRUE );
			EventSetFieldS( eventBuffer, F_IL_Signature, imageLoad->m_Signature, TRUE );

			EventSetFieldE( eventBuffer, F_IL_User, N_Sid, imageLoad, IL_Sid );

			EventProcess( &SYSMONEVENT_IMAGE_LOAD_Type, eventBuffer, eventHeader, (PSID)ExtGetPtrX( imageLoad, IL_Sid, NULL ) );
		}
		free( imageLoad->m_HashBuffer );
		break;

	case RemoteThread:
		createRemoteThread = &eventHeader->m_EventBody.m_CreateRemoteThreadEvent;

		EventSetFieldX( eventBuffer, F_CRT_UtcTime, N_LargeTime, createRemoteThread->m_EventSystemTime );
		EventSetFieldX( eventBuffer, F_CRT_SourceProcessGuid, N_ProcessId, createRemoteThread->m_SourceProcessId );
		EventSetFieldX( eventBuffer, F_CRT_SourceProcessId, N_ProcessId, createRemoteThread->m_SourceProcessId );
		EventSetFieldX( eventBuffer, F_CRT_SourceImage, N_ProcessId, createRemoteThread->m_SourceProcessId );
		EventSetFieldX( eventBuffer, F_CRT_TargetProcessGuid, N_ProcessId, createRemoteThread->m_TargetProcessId );
		EventSetFieldX( eventBuffer, F_CRT_TargetProcessId, N_ProcessId, createRemoteThread->m_TargetProcessId );
		EventSetFieldX( eventBuffer, F_CRT_TargetImage, N_ProcessId, createRemoteThread->m_TargetProcessId );
		EventSetFieldX( eventBuffer, F_CRT_NewThreadId, N_Ulong, createRemoteThread->m_TargetThreadId );
		EventSetFieldX( eventBuffer, F_CRT_StartAddress, N_Ptr, createRemoteThread->m_StartAddress );
		EventSetFieldS( eventBuffer, F_CRT_StartModule, createRemoteThread->m_StartModule, FALSE );
		EventSetFieldS( eventBuffer, F_CRT_StartFunction, createRemoteThread->m_StartFunction, FALSE );
		EventSetFieldE( eventBuffer, F_CRT_SourceUser, N_Sid, createRemoteThread, CRT_SidSource );
		EventSetFieldE( eventBuffer, F_CRT_TargetUser, N_Sid, createRemoteThread, CRT_SidTarget );

		EventProcess( &SYSMONEVENT_CREATE_REMOTE_THREAD_Type, eventBuffer, eventHeader, NULL );
		break;
#endif

	case RawAccessRead:
		rawAccessRead = &eventHeader->m_EventBody.m_RawAccessRead;

		EventSetFieldX( eventBuffer, F_RR_UtcTime, N_LargeTime, rawAccessRead->m_EventSystemTime );
		EventSetFieldX( eventBuffer, F_RR_ProcessGuid, N_ProcessId, rawAccessRead->m_ProcessId );
		EventSetFieldX( eventBuffer, F_RR_ProcessId, N_ProcessId, rawAccessRead->m_ProcessId );
		EventSetFieldX( eventBuffer, F_RR_Image, N_ProcessId, rawAccessRead->m_ProcessId );
		EventSetFieldS( eventBuffer, F_RR_Device, rawAccessRead->m_Device, FALSE );
		EventSetFieldE( eventBuffer, F_RR_User, N_Sid, rawAccessRead, RR_Sid );

		EventProcess( &SYSMONEVENT_RAWACCESS_READ_Type, eventBuffer, eventHeader, (PSID)ExtGetPtrX( rawAccessRead, RR_Sid, NULL ) );
		break;

#if defined _WIN64 || defined _WIN32
	case RegistryEvent:
		registryEvent = &eventHeader->m_EventBody.m_RegistryEvent;

		EventSetFieldE(eventBuffer, F_RK_EventType, N_UnicodePath, registryEvent, REG_EventType);
		EventSetFieldX(eventBuffer, F_RK_UtcTime, N_LargeTime, registryEvent->m_EventSystemTime);
		EventSetFieldX(eventBuffer, F_RK_ProcessGuid, N_ProcessId, registryEvent->m_ProcessId);
		EventSetFieldX(eventBuffer, F_RK_ProcessId, N_ProcessId, registryEvent->m_ProcessId);
		EventSetFieldE(eventBuffer, F_RK_Image, N_UnicodePath, registryEvent, REG_ImagePath);
		EventSetFieldE( eventBuffer, F_RK_TargetObject, N_RegistryPath, registryEvent, REG_Target );

		// SetValue and Rename events have additional data so use different events with different insertion strings
		switch (registryEvent->m_EventSubtype)
		{
			case RegistryEventSetValue:
				EventSetFieldE( eventBuffer, F_RS_Details, N_EscapeUnicodeString, registryEvent, REG_Data );
				EventSetFieldE( eventBuffer, F_RS_User, N_Sid, registryEvent, REG_Sid );
				EventProcess(&SYSMONEVENT_REG_SETVALUE_Type, eventBuffer, eventHeader, (PSID)ExtGetPtrX(registryEvent, REG_Sid, NULL));
				break;

			case RegistryEventRenameKey:
				EventSetFieldE( eventBuffer, F_RN_NewName, N_RegistryPath, registryEvent, REG_Data );
				EventSetFieldE( eventBuffer, F_RN_User, N_Sid, registryEvent, REG_Sid );
				EventProcess(&SYSMONEVENT_REG_NAME_Type, eventBuffer, eventHeader, (PSID)ExtGetPtrX(registryEvent, REG_Sid, NULL));
				break;

			default:
				EventSetFieldE( eventBuffer, F_RK_User, N_Sid, registryEvent, REG_Sid );
				EventProcess(&SYSMONEVENT_REG_KEY_Type, eventBuffer, eventHeader, (PSID)ExtGetPtrX(registryEvent, REG_Sid, NULL));
		}
		break;

	case PipeEvent:
		pipeEvent = &eventHeader->m_EventBody.m_PipeEvent;

		EventSetFieldE( eventBuffer, F_CN_EventType, N_UnicodePath, pipeEvent, PIPE_EventType );
		EventSetFieldX( eventBuffer, F_CN_UtcTime, N_LargeTime, pipeEvent->m_EventSystemTime );
		EventSetFieldX( eventBuffer, F_CN_ProcessGuid, N_ProcessId, pipeEvent->m_ProcessId );
		EventSetFieldX( eventBuffer, F_CN_ProcessId, N_ProcessId, pipeEvent->m_ProcessId );
		EventSetFieldE( eventBuffer, F_CN_PipeName, N_UnicodePath, pipeEvent, PIPE_Name);
		EventSetFieldE( eventBuffer, F_CN_Image, N_UnicodePath, pipeEvent, PIPE_ImagePath);
		EventSetFieldE( eventBuffer, F_CN_User, N_Sid, pipeEvent, PIPE_Sid);

		// Differentiate each event with different insertion strings
		switch (pipeEvent->m_EventSubtype)
		{
			case PipeEventCreate:
				EventProcess(&SYSMONEVENT_CREATE_NAMEDPIPE_Type, eventBuffer, eventHeader, NULL);
				break;

			case PipeEventConnect:
				EventProcess(&SYSMONEVENT_CONNECT_NAMEDPIPE_Type, eventBuffer, eventHeader, NULL);
				break;
		}
		break;

	case ProcessTamperingEvent:
		processTamperingEvent = &eventHeader->m_EventBody.m_ProcessTamperingEvent;

		EventSetFieldX( eventBuffer, F_PIT_UtcTime, N_LargeTime, processTamperingEvent->m_EventSystemTime );
		EventSetFieldX( eventBuffer, F_PIT_ProcessGuid, N_ProcessId, processTamperingEvent->m_ProcessId );
		EventSetFieldX( eventBuffer, F_PIT_ProcessId, N_ProcessId, processTamperingEvent->m_ProcessId );
		EventSetFieldX( eventBuffer, F_PIT_Image, N_ProcessId, processTamperingEvent->m_ProcessId );
		EventSetFieldS( eventBuffer, F_PIT_Type, processTamperingEvent->m_Type, FALSE );
		EventSetFieldE( eventBuffer, F_PIT_User, N_Sid, processTamperingEvent, PTP_Sid);
		EventProcess( &SYSMONEVENT_PROCESS_IMAGE_TAMPERING_Type, eventBuffer, eventHeader, NULL );
		break;
#endif

	default:
		PrintErrorEx( (PTCHAR)_T(__FUNCTION__), 0, (PTCHAR)_T("Unknown event type to forward %d"), eventHeader->m_EventType );
		error = ERROR_INVALID_DATA;
	}

	if( error != ERROR_SUCCESS ) {

		if( eventHeader->m_EventType != ConfigUpdate ) {

			PrintErrorEx( (PTCHAR)_T(__FUNCTION__), error, (PTCHAR)_T("Failed to process event %d"), eventHeader->m_EventType );
		} else {

			PrintErrorEx( (PTCHAR)_T(__FUNCTION__), error, (PTCHAR)_T("Failed to update configuration") );
		}
	}
	return error;
}

//--------------------------------------------------------------------
//
// NetworkEvent
//
// Report a network event
//
//--------------------------------------------------------------------
DWORD NetworkEvent(
	_In_ PLARGE_INTEGER Time,
	_In_ DWORD OwnerPID,
	_In_ const TCHAR* user,
	_In_ BOOLEAN isTcp,
	_In_ ULONG isInitiated,
	_In_ ULONG srcIpv6,
	_In_ const TCHAR* srcAddrIp,
	_In_ const TCHAR* srcHostname,
	_In_ WORD srcPort,
	_In_ const TCHAR* srcPortname,
	_In_ ULONG dstIpv6,
	_In_ const TCHAR* dstAddrIp,
	_In_ const TCHAR* dstHostname,
	_In_ WORD dstPort,
	_In_ const TCHAR* dstPortname
)
{
	SYSMON_DATA_DESCRIPTOR		eventBuffer[SYSMON_MAX_EVENT_Fields] = {(NativeTypes) 0};

	EventSetFieldX( eventBuffer, F_NC_UtcTime, N_LargeTime, *Time );
	EventSetFieldX( eventBuffer, F_NC_ProcessGuid, N_ProcessId, OwnerPID );
	EventSetFieldX( eventBuffer, F_NC_ProcessId, N_ProcessId, OwnerPID );
	EventSetFieldX( eventBuffer, F_NC_Image, N_ProcessId, OwnerPID );
	EventSetFieldS( eventBuffer, F_NC_User, user, FALSE );
	EventSetFieldS( eventBuffer, F_NC_Protocol, isTcp ? _T("tcp") : _T("udp"), FALSE );
	EventSetFieldX( eventBuffer, F_NC_Initiated, N_Ulong, isInitiated );

	EventSetFieldX( eventBuffer, F_NC_SourceIsIpv6, N_Ulong, srcIpv6 );
	EventSetFieldS( eventBuffer, F_NC_SourceIp, srcAddrIp, FALSE );
	EventSetFieldS( eventBuffer, F_NC_SourceHostname, srcHostname, FALSE );
	EventSetFieldX( eventBuffer, F_NC_SourcePort, N_Ulong, srcPort );
	EventSetFieldS( eventBuffer, F_NC_SourcePortName, srcPortname, FALSE );

	EventSetFieldX( eventBuffer, F_NC_DestinationIsIpv6, N_Ulong, dstIpv6 );
	EventSetFieldS( eventBuffer, F_NC_DestinationIp, dstAddrIp, FALSE );
	EventSetFieldS( eventBuffer, F_NC_DestinationHostname, dstHostname, FALSE );
	EventSetFieldX( eventBuffer, F_NC_DestinationPort, N_Ulong, dstPort );
	EventSetFieldS( eventBuffer, F_NC_DestinationPortName, dstPortname, FALSE );

	return EventProcess( &SYSMONEVENT_NETWORK_CONNECT_Type, eventBuffer, NULL, NULL );
}

//--------------------------------------------------------------------
//
// SendStateEvent
//
// Reports if Sysmon has started or stopped.
//
//--------------------------------------------------------------------
DWORD SendStateEvent(
    _In_ PTCHAR State,
    _In_ PTCHAR FileVersion
    )
{
	SYSMON_DATA_DESCRIPTOR	eventBuffer[SYSMON_MAX_EVENT_Fields] = {(NativeTypes) 0};
	TCHAR		schemaVersion[64];

	_stprintf_s( schemaVersion, _countof(schemaVersion), _T("%.2f"), TO_DOUBLE( ConfigurationVersion ) );

	EventSetFieldS( eventBuffer, F_SSC_State, State, FALSE );
	EventSetFieldS( eventBuffer, F_SSC_Version, FileVersion, FALSE );
	EventSetFieldS( eventBuffer, F_SSC_SchemaVersion, schemaVersion, FALSE );
	return EventProcess( &SYSMONEVENT_SERVICE_STATE_CHANGE_Type, eventBuffer, NULL, NULL );
}


//--------------------------------------------------------------------
//
// SendConfigEvent
//
// Send the actual config change event
//
//--------------------------------------------------------------------
DWORD SendConfigEvent(
	_In_ PTCHAR ConfigPath,
	_In_ PTCHAR ConfigHash
	)
{
	SYSMON_DATA_DESCRIPTOR	eventBuffer[SYSMON_MAX_EVENT_Fields] = { (NativeTypes) 0 };

	EventSetFieldS( eventBuffer, F_SCC_Configuration, ConfigPath, FALSE );
	EventSetFieldS( eventBuffer, F_SCC_ConfigurationFileHash, ConfigHash ? ConfigHash : _T(""), FALSE );
	return EventProcess( &SYSMONEVENT_SERVICE_CONFIGURATION_CHANGE_Type, eventBuffer, NULL, NULL );
}


