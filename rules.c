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
// Rules.c
//
// Rule engine for user-mode and kernel-mode
//
//====================================================================
#include "rules.h"

#if defined _WIN64 || defined _WIN32
#ifndef SYSMON_DRIVER
	#include "windows.h"
#endif
#elif defined __linux__
#include <stdarg.h>
#include <pthread.h>
#include "linuxTypes.h"
#include "linuxHelpers.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined _WIN64 || defined _WIN32

#define ALIGN_DOWN_BY(length, alignment) \
    ((ULONG_PTR)(length) & ~(alignment - 1))

#define ALIGN_UP_BY(length, alignment) \
    (ALIGN_DOWN_BY(((ULONG_PTR)(length) + alignment - 1), alignment))

#elif defined __linux__

#define MAX_FIELD_VALUE_LEN 512

#define ALIGN_DOWN_BY(length, alignment) \
    ((uint64_t)(length) & ~((uint64_t)alignment - 1))

#define ALIGN_UP_BY(length, alignment) \
    (ALIGN_DOWN_BY(((uint64_t)(length) + alignment - 1), (uint64_t)alignment))

#endif

//
// Current rule set
//
PRULE_SET g_blob = NULL;

#define SYSMON_MAX_ULONG 0xffffffffUL 

//
// Critical section to access g_blog
//
#ifdef SYSMON_DRIVER

#define D_ASSERT(_x)
#define DBG_MODE(...)
#define _tprintf(...)

ERESOURCE g_Lock;

#define INIT_CRIT()			ExInitializeResourceLite( &g_Lock )
#define ENTER_CRIT_READ()	{ KeEnterCriticalRegion(); ExAcquireResourceSharedLite( &g_Lock, TRUE ); }
#define LEAVE_CRIT_READ()	{ ExReleaseResourceLite( &g_Lock ); KeLeaveCriticalRegion(); }
#define ENTER_CRIT_WRITE()  { KeEnterCriticalRegion(); ExAcquireResourceExclusiveLite( &g_Lock, TRUE ); }
#define LEAVE_CRIT_WRITE()  { ExReleaseResourceLite( &g_Lock ); KeLeaveCriticalRegion(); }

extern PVOID
SysmonAllocate(
	POOL_TYPE PoolType,
	ULONG Size,
	ULONG Tag
);
#define ALLOC(_x)	SysmonAllocate( PagedPool, (ULONG) _x, 'R' )
#define FREE(_x)	ExFreePool( _x )

// The driver doesn't need to print errors, replacing by a noop.
#define PrintErrorEx(...)

#else

CRITICAL_SECTION g_crit;

#if defined _WIN64 || defined _WIN32

BOOLEAN g_readWrite = FALSE;
SRWLOCK g_rwLock;

#define RW_PROTO(_r, _n, _p) \
typedef _r (WINAPI * t ## _n)## _p ##; \
t ## _n l_ ## _n = NULL

#define PROTO_RESOLVE( _h, _n ) \
l_ ## _n = (t ## _n) GetProcAddress( _h, #_n );

RW_PROTO( VOID, InitializeSRWLock,			( PSRWLOCK SRWLock ) );
RW_PROTO( VOID, AcquireSRWLockExclusive, 	( PSRWLOCK SRWLock ) );
RW_PROTO( VOID, AcquireSRWLockShared, 		( PSRWLOCK SRWLock ) );
RW_PROTO( VOID, ReleaseSRWLockExclusive,	( PSRWLOCK SRWLock ) );
RW_PROTO( VOID, ReleaseSRWLockShared,		( PSRWLOCK SRWLock ) );

//--------------------------------------------------------------------
//
// InitializeLock
//
// Try to use RW lock for better performance, default to critical
// sections
//
//--------------------------------------------------------------------
VOID
InitializeLock(
	VOID
	)
{
	HMODULE hKernel = GetModuleHandle( _T("kernel32.dll") );

	if( hKernel != NULL ) {

		PROTO_RESOLVE( hKernel, InitializeSRWLock );
		PROTO_RESOLVE( hKernel, AcquireSRWLockExclusive );
		PROTO_RESOLVE( hKernel, AcquireSRWLockShared );
		PROTO_RESOLVE( hKernel, ReleaseSRWLockExclusive );
		PROTO_RESOLVE( hKernel, ReleaseSRWLockShared );
	}

	if( l_InitializeSRWLock != NULL &&
		l_AcquireSRWLockExclusive != NULL &&
		l_AcquireSRWLockShared != NULL &&
		l_ReleaseSRWLockExclusive != NULL &&
		l_ReleaseSRWLockShared != NULL ) {

		g_readWrite = TRUE;
		l_InitializeSRWLock( &g_rwLock );
	} else {

		InitializeCriticalSection( &g_crit );
	}
}

#define INIT_CRIT()			InitializeLock()
#define ENTER_CRIT_READ()	{ if( g_readWrite ) { l_AcquireSRWLockShared( &g_rwLock );  } else { EnterCriticalSection( &g_crit ); } }
#define LEAVE_CRIT_READ()	{ if( g_readWrite ) { l_ReleaseSRWLockShared( &g_rwLock );  } else { LeaveCriticalSection( &g_crit ); } }
#define ENTER_CRIT_WRITE()  { if( g_readWrite ) { l_AcquireSRWLockExclusive( &g_rwLock );  } else { EnterCriticalSection( &g_crit ); } }
#define LEAVE_CRIT_WRITE()  { if( g_readWrite ) { l_ReleaseSRWLockExclusive( &g_rwLock );  } else { LeaveCriticalSection( &g_crit ); } }

#elif defined __linux__

VOID
InitializeLock(
    VOID
    )
{
    InitializeCriticalSection( &g_crit );
}

#define INIT_CRIT()         InitializeLock()
#define ENTER_CRIT_READ()   { EnterCriticalSection( &g_crit ); }
#define LEAVE_CRIT_READ()   { LeaveCriticalSection( &g_crit ); }
#define ENTER_CRIT_WRITE()  { EnterCriticalSection( &g_crit ); }
#define LEAVE_CRIT_WRITE()  { LeaveCriticalSection( &g_crit ); }

LONG
InterlockedIncrement(
    LONG volatile *Addend
    )
{
    (*Addend)++;
    return *Addend;
}

LONG
InterlockedDecrement(
    LONG volatile *Addend
    )
{
    (*Addend)--;
    return *Addend;
}

void PrintErrorEx( PTCHAR ID, DWORD ErrorCode, PTCHAR Format, ... )
{
        va_list args;

        va_start( args, Format );

        fprintf(stderr, "Sysmon error. ID:'%s', ERROR:%d\n", ID, ErrorCode);
        vfprintf(stderr, Format, args);
}

#define min(a,b) (((a) < (b)) ? (a) : (b))

#endif

#define ALLOC(_x)	malloc( _x )
#define FREE(_x)	free( _x )

#endif

// WIDECHAR simplifies using a WCHAR character between Windows and Linux.
#if defined _WIN64 || defined _WIN32
#define WIDECHAR(x) L##x
#elif defined __linux__
#define WIDECHAR(x) (WCHAR)x
#endif

//----------------------------------------------------------------------
//
// NextItem
//
// An helper function to iterate a string list using Delim.
//
// Context tracks the next item in the list.
// Delim is the delimiter WCHAR between elements in the list.
// Token is the current item tracked.
// TokenCchSize is the SIZE in character of the current position.
//
// Returns TRUE if an entry is available, false if done.
//
//----------------------------------------------------------------------
BOOLEAN NextItem( _Inout_ PCWSTR *Context, _In_ WCHAR Delim, _Out_ PCWSTR *Token, _Out_ PSIZE_T TokenCchSize ) {
	PCWSTR start, end;

	start = *Context;
	end = start;

	// Indicates the end of the iteration.
	if( start == NULL ) {
		return FALSE;
	}

	// Iterate to the next entry or the end.
	while( *end && *end != Delim ) {
		end++;
	}

	// Fill information.
	*TokenCchSize = end - start;
	*Token = start;

	// If the end was not \0 WCHAR, put context on the next WCHAR.
	// Else set it to NULL to end during the next iteratior.
	if( *end ) {
		*Context = end + 1;
	} else {
		*Context = NULL;
	}

	return TRUE;
}

//----------------------------------------------------------------------
//
// FindSubString
//
// str is the string which is checked.
// sub is the string being looked for in str. It was lowered when loading
// the rule data.
//
//----------------------------------------------------------------------
PCWSTR FindSubString( _In_ PCWSTR str, _In_ PCWSTR sub, _In_ SIZE_T subCchMax )
{
	PCWSTR str1, str2, subMax = NULL;
	PCWSTR pos = str;
	WCHAR c1, c2;

	if( subCchMax != 0 ) {

		subMax = sub + subCchMax;
	}

	while( *pos ) {

		str1 = pos;
		str2 = sub;

		while( TRUE ) {
			c1 = *str1;
			c2 = *str2;

			// Matched the whole sub string.
			if( !c2 ) {
				return pos;
			}

			// Ended iteration on str without a full match.
			if( !c1 ) {
				return NULL;
			}

			if( TOWLOWER( c1 ) != c2 ) {
				break;
			}

			++str1;
			++str2;

			// Matched the whole string at that point.
			if( str2 == subMax ) {
				return pos;
			}
		}

		++pos;
	}

	return NULL;
}

//--------------------------------------------------------------------
//
// IsVersionGreater
//
// Simple version comparison without using floating point for the kernel
//
//--------------------------------------------------------------------
BOOLEAN
IsVersionGreater(
	ULONG Version,
	ULONG Major,
	ULONG Minor
	)
{
	if( V_MAJOR( Version ) < Major ) {

		return FALSE;
	}

	if( V_MAJOR(Version) == Major &&
		V_MINOR(Version) <= Minor ) {

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------
//
// IsVersionGreaterFromContext
//
// Similar to IsVersionGreater but take RULE_CONTEXT as input.
//
//--------------------------------------------------------------------
BOOLEAN
IsVersionGreaterFromContext(
	_In_ PRULE_CONTEXT Context,
	_In_ ULONG Major,
	_In_ ULONG Minor
	)
{
	PRULE_REG ruleBase = (PRULE_REG)Context->Current->Rules;
	return IsVersionGreater( ruleBase->Version, Major, Minor );
}

//--------------------------------------------------------------------
//
// InitializeRules
//
// Initialize the rule engine
//
//--------------------------------------------------------------------
BOOLEAN
InitializeRules(
	VOID
	)
{
	static BOOLEAN wasInitialized = FALSE;

	if( !wasInitialized ) {

		INIT_CRIT();
		wasInitialized = TRUE;
	}
	return TRUE;
}

//--------------------------------------------------------------------
//
// GetBlobReference
//
// Get a refrence to the current ruleset, increase the reference count
//
//--------------------------------------------------------------------
PRULE_SET
GetBlobReference(
	VOID
	)
{
	PRULE_SET	ret = NULL;
	LONG		value;

	ENTER_CRIT_READ();

	if( g_blob != NULL ) {

		ret = g_blob;
		value = InterlockedIncrement( &ret->ReferenceCount );

		//
		// Unlikely to happen
		//
		if( value < 0 ) {

			InterlockedDecrement( &ret->ReferenceCount );
			ret = NULL;
			D_ASSERT( !"Reference count bug in the rule engine" );
		}
	}

	LEAVE_CRIT_READ();
	return ret;
}

//--------------------------------------------------------------------
//
// CleanupQuickAccessTable
//
// Clean-up a fully or half-initialized table.
//
//--------------------------------------------------------------------
VOID
CleanupQuickAccessTable(
	_In_ PRULE_INDEX_TABLE IndexingTable
	)
{
	ULONG	i;

	if( IndexingTable == NULL ) {

		return;
	}

	for( i = 0; i < _countof( IndexingTable->Entries ); i++ ) {

		FREE( IndexingTable->Entries[i].Events );
	}

	FREE( IndexingTable );
}

//--------------------------------------------------------------------
//
// ReleaseBlobReference
//
// Release reference to a rule set, free it if needed
//
//--------------------------------------------------------------------
VOID
ReleaseBlobReference(
	_In_ PRULE_SET RuleSet
	)
{
	BOOLEAN		release = FALSE;
	LONG		decr;

	if (NULL != RuleSet) {

		ENTER_CRIT_READ();

		decr = InterlockedDecrement( &RuleSet->ReferenceCount );
		if( decr == 0 ) {

			release = TRUE;
		}

		LEAVE_CRIT_READ();

		D_ASSERT( decr >= 0 );

		//
		// Free the rule set as needed
		//
		if( release ) {

			CleanupQuickAccessTable( RuleSet->IndexingTable );
#if !defined(SYSMON_PUBLIC)
			CleanupQuickAccessTable( RuleSet->ShadowIndexingTable );
#endif
			FREE( RuleSet->Rules );
			FREE( RuleSet );
		}
	}
}

//--------------------------------------------------------------------
//
// GetIndexFromEventId
//
// Transform the event id to an index on the quick access table.
// Returns -1 if the event id is not meant for the target table.
//
//--------------------------------------------------------------------
LONG
GetIndexFromEventId(
	_In_ ULONG EventId,
	_In_ BOOLEAN Internal
	)
{
	LONG	ret = -1;
	ULONG	highestMatchingId;

	//
	// For rule types like Registry and Pipe, we need to find highest matching rule
	//
	highestMatchingId = EventId;
	while( highestMatchingId+1 < AllEventsCount &&
		AllEvents[highestMatchingId+1]->RuleName != NULL &&
		!_tcsicmp( AllEvents[EventId]->RuleName, AllEvents[highestMatchingId+1]->RuleName ) ) {

		highestMatchingId++;
	}
	EventId = highestMatchingId;

#if !defined(SYSMON_PUBLIC)
	BOOLEAN	isInternal;

	isInternal = ( ( EventId & INTERNAL_EVENT_MASK ) != 0 );

	if( isInternal != Internal ) {

		ret = -1;
	} else {

		ret = (LONG)( EventId & ~INTERNAL_EVENT_MASK );
	}

#else
	//
	// Public version does not need any change
	//
	D_ASSERT( Internal == FALSE );
	Internal;

	ret = (LONG)EventId;
#endif

	if( ret == 255 ) {

		ret = 0;
	}

	D_ASSERT( ret < 255 );

	return ret;
}

//--------------------------------------------------------------------
//
// GetIndexAndTableFromEventId
//
// Transform the event id to an index on the quick access table.
// Returns -1 if the event id is not meant for the target table.
//
// This function also set the target indexing table
//
//--------------------------------------------------------------------
LONG
GetIndexAndTableFromEventId(
	_In_ PRULE_CONTEXT Context,
	_In_ ULONG EventId,
	_Out_ PRULE_INDEX_TABLE* IndexingTable
	)
{
	LONG	curId;

	*IndexingTable = NULL;
	curId = GetIndexFromEventId( EventId, FALSE );

	if( curId >= 0 ) {

		*IndexingTable = Context->Current->IndexingTable;
	}
#if !defined(SYSMON_PUBLIC)
	else {
		curId = GetIndexFromEventId( EventId, TRUE );

		if( curId >= 0 ) {

			*IndexingTable = Context->Current->ShadowIndexingTable;
		}
	}
#endif
	return curId;
}

//--------------------------------------------------------------------
// LowerRuleFilter
//
// All rule filters are case insensitive, lower the rule data by default
// to make matching faster in many conditions.
//
//--------------------------------------------------------------------
VOID LowerRuleFilter(_In_ PRULE_FILTER ruleFilter)
{
	PWCHAR pos;
	ULONG i;

	for( i = 0; i < ruleFilter->DataSize; i += sizeof(WCHAR) ) {
		pos = &((PWCHAR)ruleFilter->Data)[i/sizeof(WCHAR)];
		*pos = TOWLOWER(*pos);
	}
}

//--------------------------------------------------------------------
//
// BackwardFillEventList
//
// Add entries at the back of the event list based on the event count.
// Simplifies the logic on filling the event rule filter list.
//
//--------------------------------------------------------------------
BOOLEAN
BackwardFillEventList(
	_In_ PRULE_CONTEXT Context,
	_In_ PRULE_INDEX_TABLE Table,
	_In_ BOOLEAN Internal,
	_In_ PUSHORT EventCount,
	_In_ RuleDefaultType DefaultFilter
	)
{
	LONG curId;
	USHORT pos;
	PRULE_EVENT ruleEvent;

	for( ruleEvent = NextRuleEvent( Context, NULL );
		 ruleEvent != NULL;
		 ruleEvent = NextRuleEvent( Context, ruleEvent ) ) {

		curId = GetIndexFromEventId( ruleEvent->EventId, Internal );

		if( curId < 0 || ruleEvent->RuleDefault != DefaultFilter ) {

			continue;
		}

		// The counter should never underflow, still check for it.
		if( EventCount[curId] == 0 ) {

			PrintErrorEx( _T("RuleEngine"), ERROR_INVALID_DATA, _T("Invalid data in rules") );
			return FALSE;
		}

		pos = --EventCount[curId];
		Table->Entries[curId].Events[pos] = ruleEvent;
	}

	return TRUE;
}

//--------------------------------------------------------------------
//
// ComputeQuickAccessTables
//
// Compute a quick access table from the blob so rules can be processed
// as fast as possible without going through all entries.
//
//--------------------------------------------------------------------
BOOLEAN
ComputeQuickAccessTables(
	_In_ PRULE_SET RuleSet,
	_In_ BOOLEAN Internal,
	_Out_ PRULE_INDEX_TABLE* IndexingTable,
	_In_ BOOLEAN Transform
	)
{
	RULE_CONTEXT customContext;
	PRULE_EVENT ruleEvent;
	PRULE_FILTER ruleFilter;
	LONG curId;
	ULONG i, allocSize;
	PRULE_INDEX_TABLE table;
	PRULE_EVENT* events;
	RULE_REG ruleReg;
	RULE_REG_EXT ruleRegExt;
	USHORT eventCount[SYSMON_MAX_EVENT_ID + 1] = {0,};

	*IndexingTable = NULL;
	customContext.Current = RuleSet;

	//
	// Check version is correct
	//
	if( !GetRuleRegInformation( &customContext, &ruleReg ) ||
		ruleReg.RuleCount == 0 ) {

		PrintErrorEx( _T("RuleEngine"), ERROR_INVALID_DATA, _T("Invalid configuration") );
		return FALSE;
	}

	if( !IsCompatibleBinaryVersion( ruleReg.Version ) ) {

		if( IsVersionGreater( ruleReg.Version, 1, 0 ) && GetRuleRegExtInformation( &customContext, &ruleRegExt ) ) {

			PrintErrorEx( _T("RuleEngine"), 0, _T("Registry rule version %.2f (binary %.2f) is incompatible with Sysmon rule")
											   _T(" version %.2f (binary %.2f). ")
											   _T("Please rebuild your manifest with Sysmon schema %.2f."),
						  TO_DOUBLE( ruleRegExt.SchemaVersion ),
						  TO_DOUBLE( ruleReg.Version ),
						  TO_DOUBLE( ConfigurationVersion ),
						  TO_DOUBLE( BinaryVersion ),
						  TO_DOUBLE( ConfigurationVersion ) );
		} else {

			PrintErrorEx( _T("RuleEngine"), 0, _T("Registry rule version %.2f is incompatible with Sysmon rule version %.2f. ")
											   _T("Please rebuild your manifest with Sysmon schema %.2f."),
						  TO_DOUBLE( ruleReg.Version ),
						  TO_DOUBLE( BinaryVersion ),
						  TO_DOUBLE( ConfigurationVersion ) );
		}

		return FALSE;
	}

	table = ALLOC( sizeof( *table ) );

	if( table == NULL ) {

		PrintErrorEx( _T("RuleEngine"), ERROR_OUTOFMEMORY, _T("Failed to allocate memory") );
		return FALSE;
	}

	memset( table, 0, sizeof( *table ) );

	// Check rules are valid, count number of events per type and apply transformation if needed.
	for( ruleEvent = NextRuleEvent( &customContext, NULL );
		 ruleEvent != NULL;
		 ruleEvent = NextRuleEvent( &customContext, ruleEvent ) ) {

		curId = GetIndexFromEventId( ruleEvent->EventId, Internal );

		if( curId < 0 ) {

			continue;
		}

		// Check rules default are valid too
		if( curId > SYSMON_MAX_EVENT_ID ) {

			PrintErrorEx( _T("RuleEngine"), ERROR_INVALID_DATA, _T("Invalid event id in rules") );
			goto failed;
		}

		if( ruleEvent->RuleDefault != Rule_include && ruleEvent->RuleDefault != Rule_exclude ) {

			PrintErrorEx( _T("RuleEngine"), ERROR_INVALID_DATA, _T("Invalid data in rules") );
			goto failed;
		}

		// Check if the value will overflow now or on allocation next.
		if( eventCount[curId] >= 0xFFFE ) {

			PrintErrorEx( _T("RuleEngine"), ERROR_INVALID_DATA, _T("Invalid event count in rules") );
			goto failed;
		}

		eventCount[curId]++;

		if( !Transform ) {

			continue;
		}

		for( ruleFilter = NextRuleFilter( &customContext, ruleEvent, NULL );
			 ruleFilter != NULL;
			 ruleFilter = NextRuleFilter( &customContext, ruleEvent, ruleFilter ) ) {

			LowerRuleFilter( ruleFilter );

#if defined _WIN64 || defined _WIN32
			// Add the Filter_Environment tag so expansion is done only if needed.
			if( wcschr( (PWCHAR)ruleFilter->Data, WIDECHAR( '%' ) ) != NULL ) {

				ruleFilter->FilterType |= Filter_Environment;
			}
#endif
		}
	}

	// Allocate the list for each event id.
	for( i = 0; i < _countof( eventCount ); i++ ) {
		// All events needed and a NULL pointer at the end.
		allocSize = ( eventCount[i] + 1 ) * sizeof( PVOID );
		if( allocSize == 0 ) {

			continue;
		}

		events = ALLOC( allocSize );
		if( events == NULL ) {

			PrintErrorEx( _T("RuleEngine"), ERROR_OUTOFMEMORY, _T("Failed to allocate memory") );
			goto failed;
		}

		memset( events, 0, allocSize );
		table->Entries[i].Events = events;
	}

	// Add default exclude to the back first, then include.
	if( !BackwardFillEventList( &customContext, table, Internal, eventCount, Rule_exclude ) ||
		!BackwardFillEventList( &customContext, table, Internal, eventCount, Rule_include ) ) {

		goto failed;
	}

	// All events should have been added, check in debug mode that eventCount is zero.
	for( i = 0; i < _countof( eventCount ); i++ ) {
		D_ASSERT( eventCount[i] == 0 );
	}

	*IndexingTable = table;
	return TRUE;

failed:
	CleanupQuickAccessTable( table );
	return FALSE;
}

//--------------------------------------------------------------------
//
// SetRuleBlob
//
// Set the current rules to apply and compute the quick access tables.
//
// The Transform parameter indicates if the rule data should be
// modified for quick matching. It is expected to be TRUE when rules
// are loaded in the service or driver.
//
//--------------------------------------------------------------------
BOOLEAN
SetRuleBlob(
	_In_ PVOID Rules,
	_In_ ULONG RulesSize,
	_In_ BOOLEAN Transform
	)
{
	PRULE_SET newSet = NULL, oldSet;

	// The Sysmon driver should always do transformation.
#if defined( SYSMON_DRIVER )
	D_ASSERT( Transform == TRUE );
#endif

	if( Rules != NULL && RulesSize != 0 ) {

		newSet = (PRULE_SET) ALLOC( sizeof(*newSet) );

		if( newSet == NULL ) {

			PrintErrorEx( _T("RuleEngine"), ERROR_OUTOFMEMORY, _T("Failed to allocate memory") );
			return FALSE;
		}

		newSet->Version = 1;
	    newSet->Rules = Rules;
		newSet->RulesSize = RulesSize;
		newSet->ReferenceCount = 1;

		if( !ComputeQuickAccessTables( newSet, FALSE, &newSet->IndexingTable, Transform ) ) {

			FREE( newSet );
			return FALSE;
		}

#if !defined(SYSMON_PUBLIC)
		if( !ComputeQuickAccessTables( newSet, TRUE, &newSet->ShadowIndexingTable, Transform ) ) {

			CleanupQuickAccessTable( newSet->IndexingTable );
			FREE( newSet );
			return FALSE;
		}
#endif
    }

	ENTER_CRIT_WRITE();

	oldSet = g_blob;
	g_blob = newSet;

	if( oldSet != NULL && newSet != NULL ) {

		newSet->Version = oldSet->Version + 1;
	}

	LEAVE_CRIT_WRITE();

	//
	// Decrease reference count on the old set
	//
	if( oldSet != NULL ) {

		ReleaseBlobReference( oldSet );
	}
	return TRUE;
}

//--------------------------------------------------------------------
//
// InitializeRuleContext
//
// Initialize the context used to keep state
//
//--------------------------------------------------------------------
BOOLEAN
InitializeRuleContext(
	_Out_ PRULE_CONTEXT Context
	)
{
	PRULE_SET	ruleSet;

	memset( Context, 0, sizeof( *Context ) );

	ruleSet = GetBlobReference();

	if( ruleSet == NULL ) {

		return FALSE;
	}

	Context->Current = ruleSet;
	return TRUE;
}

//--------------------------------------------------------------------
//
// ReleaseRuleContext
//
// Released an initialized context
//
//--------------------------------------------------------------------
VOID
ReleaseRuleContext(
	_In_ PRULE_CONTEXT Context
	)
{
	ReleaseBlobReference( Context->Current );
	Context->Current = NULL;
}

//--------------------------------------------------------------------
//
// GetRuleVersion
//
// Get the current rule version
//
//--------------------------------------------------------------------
ULONG
GetRuleVersion(
	VOID
	)
{
	ULONG			ret = 0;
	RULE_CONTEXT 	ctx;

	if( InitializeRuleContext( &ctx ) ) {

		ret = GET_RULECTX_VERSION( &ctx );
		ReleaseRuleContext( &ctx );
	}

	return ret;
}

//--------------------------------------------------------------------
//
// IsValidPointer
//
// Verify a pointer is within the rule bounds
//
//--------------------------------------------------------------------
BOOLEAN
IsValidPointer(
	_In_ PRULE_CONTEXT Context,
	_In_ PVOID ptr
	)
{
	PUCHAR		start = (PUCHAR)Context->Current->Rules;
	PUCHAR		end = start + Context->Current->RulesSize;

	if( (PUCHAR)ptr < start || (PUCHAR)ptr >= end ) {

		return FALSE;
	}

	return TRUE;
}

//--------------------------------------------------------------------
//
// GetRuleRegExtInformation
//
// Get the extended structure about the rules
//
//--------------------------------------------------------------------
BOOLEAN
GetRuleRegExtInformation(
	_In_ PRULE_CONTEXT Context,
	_Out_ PRULE_REG_EXT RuleReg
	)
{
	PRULE_SET 	ruleSet;
	ULONG		regSize;

	if( Context == NULL ) {

		ruleSet = GetBlobReference();

	} else {

		ruleSet = Context->Current;
	}

	if( ruleSet == NULL ) {

		return FALSE;
	}

	if( ruleSet->RulesSize < sizeof(RULE_REG) ) {

		if( Context == NULL ) {

			ReleaseBlobReference( ruleSet );
	    }
		return FALSE;
	}

	memcpy( RuleReg, ruleSet->Rules, sizeof( RULE_REG ) );

	//
	// Version 1.1 supports extension
	//
	if( IsVersionGreater(RuleReg->header.Version, 1, 0) && ruleSet->RulesSize >= (ULONG)FIELD_OFFSET(RULE_REG_EXT, SchemaVersion) ) {

		// When dumping the configuration RuleReg is zeroed. We copy the header portion above but this does not include
		// RuleRegSize. Thus the following logic always returns 0.
		// regSize = min( sizeof(*RuleReg), RuleReg->RuleRegSize );
		regSize = min( sizeof(*RuleReg), ruleSet->RulesSize);
		if( ruleSet->RulesSize >= regSize ) {

			memcpy( RuleReg, ruleSet->Rules, regSize );
		}
	}

	if( Context == NULL ) {

		ReleaseBlobReference( ruleSet );
	}
	return TRUE;
}

//--------------------------------------------------------------------
//
// GetRuleRegInformation
//
// Get the main structure about the rules
//
//--------------------------------------------------------------------
BOOLEAN
GetRuleRegInformation(
	_In_ PRULE_CONTEXT Context,
	_Out_ PRULE_REG RuleReg
	)
{
	PRULE_SET ruleSet;

	if( Context == NULL ) {

		ruleSet = GetBlobReference();

	} else {

		ruleSet = Context->Current;
	}

	if( ruleSet == NULL ) {

		return FALSE;
	}

	if( ruleSet->RulesSize < sizeof(*RuleReg) ) {

		if( Context == NULL ) {

			ReleaseBlobReference( ruleSet );
	    }
		return FALSE;
	}

	memcpy( RuleReg, ruleSet->Rules, sizeof( *RuleReg ) );

	if( Context == NULL ) {

		ReleaseBlobReference( ruleSet );
	}
	return TRUE;
}

//--------------------------------------------------------------------
//
// GetRuleEventList
//
// Use the quick access table to get the first rule event for an event
// identifier.
//
//--------------------------------------------------------------------
PRULE_EVENT*
GetRuleEventList(
	_In_ PRULE_CONTEXT Context,
	_In_ ULONG EventId
	)
{
	LONG				curId;
	PRULE_INDEX_TABLE	table;

	curId = GetIndexAndTableFromEventId( Context, EventId, &table );

	if( curId < 0 || table == NULL || (ULONG)curId >= _countof( table->Entries ) ) {

		return NULL;
	}

	return table->Entries[curId].Events;
}

//--------------------------------------------------------------------
//
// MatchFilterOnSpecificRule
//
// Check if a filter entry match for a specific value
//
//--------------------------------------------------------------------
MatchStatus
MatchFilterOnSpecificRule(
	_In_ FilterOption FilterType,
	_In_ PWCHAR FilterData,
	_In_ PWCHAR FieldValue,
	_In_ ULONG SessionId
	)
{
	SIZE_T 	c1, c2, tokenCch;
	PWCHAR	m;
	LPWSTR	pRuleData = FilterData;
	LPWSTR	token;
	BOOLEAN notCondition = FALSE;
	const WCHAR CompoundConditionDelimiter = WIDECHAR(';');

#if defined _WIN64 || defined _WIN32
#ifndef SYSMON_DRIVER
	WCHAR expandedRuleData[MAX_PATH] = { 0 };

	// Expand environment variables using a cache only if the filter indicate that it is needed.
	if( ( FilterType & Filter_Environment ) &&
		!ExpandEnvironmentVariable( SessionId, &pRuleData, expandedRuleData, sizeof( expandedRuleData ) / sizeof( WCHAR ) ) ) {
		return NoMatch;
	}
#else
	// The kernel do not expand environment variables.
	if( ( FilterType & Filter_Environment ) ) {

		return Failed;
	}
#endif
#endif

	// Keep only the value from this point.
	FilterType = FilterValue( FilterType );

	switch( FilterType ) {
		//
		// Path
		//
	case Filter_image:
		if( WCSCHR( pRuleData, '\\' ) == NULL ) {

			m = WCSRCHR( FieldValue, '\\' );

			if( m != NULL ) {

				FieldValue = m + 1;
			}
		}

		if( WCSICMP( FieldValue, pRuleData ) == 0 ) {

			return Match;
		}
		return NoMatch;

	case Filter_is:
		if( WCSICMP( FieldValue, pRuleData ) == 0 ) {

			return Match;
		}
		return NoMatch;

	case Filter_is_not:
		if( WCSICMP( FieldValue, pRuleData ) != 0 ) {

			return Match;
		}
		return NoMatch;

	case Filter_contains:
		if( FindSubString( FieldValue, pRuleData, 0 ) ) {

			return Match;
		}
		return NoMatch;

	case Filter_contains_any:
	case Filter_excludes_any:
		{
			MatchStatus rc = (Filter_excludes_any == FilterType) ? Match : NoMatch;

			while( NextItem( (CONST WCHAR**)&pRuleData, CompoundConditionDelimiter, (CONST WCHAR**)&token, &tokenCch ) ) {

				if( FindSubString( FieldValue, token, tokenCch ) ) {

					rc = ( Filter_contains_any == FilterType ) ? Match : NoMatch;
					break;
				}
			}
			return rc;

		}
	case Filter_is_any:
		{
			MatchStatus rc = NoMatch;
			SIZE_T cchFieldValue = WCSLEN( FieldValue );

			while( NextItem( (CONST WCHAR**)&pRuleData, CompoundConditionDelimiter, (CONST WCHAR**)&token, &tokenCch ) ) {

				if( tokenCch == cchFieldValue && !WCSNICMP( FieldValue, token, tokenCch ) ) {

					rc = Match;
					break;
				}
			}
			return rc;
		}

	case Filter_contains_all:
	case Filter_excludes_all:
		{
			MatchStatus rc = ( Filter_contains_all == FilterType ) ? Match : NoMatch;

			while( NextItem( (CONST WCHAR**)&pRuleData, CompoundConditionDelimiter, (CONST WCHAR**)&token, &tokenCch ) ) {

				// For contains all, a single failure means exclude. For excludes all a single failure means include
				if( !FindSubString( FieldValue, token, tokenCch ) ) {

					rc = ( Filter_contains_all == FilterType ) ? NoMatch : Match;
					break;
				}
			}
			return rc;
		}

	case Filter_excludes:
		if( !FindSubString( FieldValue, pRuleData, 0 ) ) {

			return Match;
		}
	    return NoMatch;
		
	case Filter_not_begin_with:
		notCondition = TRUE;
		// fall through
	case Filter_begin_with:
		c1 = WCSLEN(pRuleData);
		if( !WCSNICMP( FieldValue, pRuleData, c1 ) ) {

			return notCondition ? NoMatch : Match;
		}
		return notCondition ? Match : NoMatch;
		
	case Filter_not_end_with:
		notCondition = TRUE;
		// fall through
	case Filter_end_with:
		c1 = WCSLEN( pRuleData );
		c2 = WCSLEN( FieldValue );
		if( c1 <= c2 && WCSICMP( FieldValue + ( c2 - c1 ), pRuleData ) == 0 ) {

			return notCondition ? NoMatch : Match;
		}
		return notCondition ? Match : NoMatch;

	case Filter_less_than:
		if( WCSICMP( FieldValue, pRuleData ) < 0 ) {

			return Match;
		}
		return NoMatch;

	case Filter_more_than:
		if( WCSICMP( FieldValue, pRuleData ) > 0 ) {

			return Match;
		}
		return NoMatch;
    default:
        return Failed;
	}
}

//--------------------------------------------------------------------
//
// IdHasIncludeRules
//
// Returns true if the event ID isn't completely excluded.
//
//--------------------------------------------------------------------
BOOLEAN
IdHasIncludeRules(
	_In_ PRULE_CONTEXT Context,
	_In_ ULONG EventId
	)
{
	ULONG				curId, i;
	PRULE_INDEX_TABLE	table;
	PRULE_EVENT			*events;

	curId = GetIndexAndTableFromEventId( Context, EventId, &table );
	if( table == NULL ) {

		return FALSE;
	}

	events = table->Entries[curId].Events;
	if( events == NULL || events[0] == NULL ) {

		return FALSE;
	}

	for( i = 0; events[i] != NULL; i++ ) {

		if( events[i]->FilterCount == 0 ) {

			return ( events[i]->RuleDefault == Rule_include );
		}
	}

	return TRUE;
}

//--------------------------------------------------------------------
//
// NextRuleEvent
//
// Used to enumerate rules events
//
//--------------------------------------------------------------------
PRULE_EVENT
NextRuleEvent(
	_In_ PRULE_CONTEXT Context,
	_In_opt_ PRULE_EVENT Current
	)
{
	PRULE_REG		ruleBase;
	PRULE_REG_EXT	ruleRegExt;
	PRULE_EVENT		ret;
	SIZE_T 			offset;

	if( Current == NULL ) {

		if( Context->Current->RulesSize < sizeof(RULE_REG) ) {

		    return NULL;
		}

		ruleBase = (PRULE_REG)Context->Current->Rules;

		if( ruleBase->RuleCount == 0 ) {

			return NULL;
		}

		if( IsVersionGreaterFromContext(Context, 1, 0) ) {

			ruleRegExt = (PRULE_REG_EXT)Context->Current->Rules;
			offset = ruleRegExt->FirstEventOffset;	// RuleBuilder now records the offset of the first event.
		} else {

			offset = ALIGN_UP_BY( sizeof(*ruleBase), sizeof(ULONG64) );
		}
	} else {

		if( !IsValidPointer( Context, Current ) ) {

		    return NULL;
		}

		offset = Current->NextOffset;

		if( offset == 0 ) {

		    return NULL;
		}
	}

	ret = (PRULE_EVENT)((PUCHAR)Context->Current->Rules + offset);

	if( !IsValidPointer( Context, ret ) ) {

		return NULL;
	}

	return ret;
}

//--------------------------------------------------------------------
//
// NextRuleFilter
//
// Used to enumerate event rule filter
//
//--------------------------------------------------------------------
PRULE_FILTER
NextRuleFilter(
	_In_ PRULE_CONTEXT Context,
	_In_ PRULE_EVENT Event,
	_In_opt_ PRULE_FILTER Current
	)
{
	PRULE_FILTER	ret;
	SIZE_T			offset;

	if( !IsValidPointer( Context, Event ) ||
		Event->FilterCount == 0 ) {

		return NULL;
	}

	if( Current == NULL ) {

		offset = Event->FirstFilterOffset;

	} else {

		if( !IsValidPointer( Context, Current ) ||
			Current->NextOffset == 0 ) {

			return NULL;
		}

		offset = Current->NextOffset;
	}

	ret = (PRULE_FILTER)((PUCHAR)Context->Current->Rules + offset);

	if( !IsValidPointer( Context, ret ) ) {

		return NULL;
	}

	//
	// Validate the data
	//
	if( (ret->DataSize % sizeof(TCHAR)) != 0 ||
		offset + ret->DataSize <= offset ||
		offset + ret->DataSize >= Context->Current->RulesSize ) {

		return NULL;
	}

	if( ((PTCHAR)ret->Data)[ret->DataSize/sizeof(TCHAR)-1] != 0 ) {

		return NULL;
	}

	return ret;
}

//--------------------------------------------------------------------
//
// FindEventTypeFromId
//
// Search for the event type format for this configuration
//
//--------------------------------------------------------------------
PSYSMON_EVENT_TYPE_FMT
FindEventTypeFromId(
    _In_ ULONG EventId
	)
{
	if( EventId >= EventTypesByIdCount ) {

		return NULL;
	}

	return EventTypesById[EventId];
}

//--------------------------------------------------------------------
//
// GetFieldName
//
// Get the field name for a field index on a rule
//
//--------------------------------------------------------------------
PTCHAR
GetFieldName(
	_In_ PSYSMON_EVENT_TYPE_FMT Rule,
	_In_ ULONG Index
	)
{
	if( Index >= Rule->FieldCount ) {

		return NULL;
	}

	return Rule->FieldNames[Index];
}

//--------------------------------------------------------------------
//
// SetEventDefault
//
// Sets the default behavior for an event type, overriding the 
// preset default. 
//
//--------------------------------------------------------------------
VOID
SetEventDefault(
	_In_ ULONG EventId,
	_In_ RuleDefaultType RuleSetting
	)
{
	SIZE_T index;

	for( index = 0; index < AllEventsCount; index++ ) {

		if( AllEvents[index]->RuleName != NULL &&
			(ULONG)AllEvents[index]->EventId == EventId ) {

			AllEvents[index]->Default = RuleSetting;
			break;
		}
	}
}

//--------------------------------------------------------------------
//
// CombineGroupDone
//
// Helper function to define if a group check is done based on the field
// match and combine type. Result is set to the group final result.
// Return TRUE if the group is done, FALSE if check continues.
//
// Highlights the different of logic between an AND and OR groups.
// AND expect all entries to match, will stop on any NoMatch. OR will
// stop on any Match.
//
// The function also handle OR conditions between same fields. In an AND
// group, if a field fail the group is seen as NoMatch only if no field
// of the same time is ahead. If a field was matched before, a bit mask
// is used to track it so the AND condition and the field is not checked
// again by the caller.
//
//--------------------------------------------------------------------
BOOLEAN CombineGroupDone(
	_In_opt_ PRULE_CONTEXT Context,
	_In_opt_ PRULE_EVENT Event,
	_In_opt_ PRULE_FILTER Filter,
	_In_ RuleCombineType CombineType,
	_In_ BOOLEAN Aggregate,
	_In_ MatchStatus FieldMatch,
	_Out_ MatchStatus *Result
	)
{
	PRULE_FILTER 	ruleFilter;

	switch( FieldMatch ) {
	case Match:
		if( CombineType == RuleCombineOR ) {
			*Result = Match;
			return TRUE;
		}
		break;

	case NoMatch:
		if( CombineType == RuleCombineAND ) {

			// AND Aggregate overwrite the OR condition between same fields.
			if( !Aggregate && Context != NULL && Event != NULL && Filter != NULL ) {

				// The same field is checked later, don't stop the group comparison yet.
				for( ruleFilter = NextRuleFilter( Context, Event, Filter );
					 ruleFilter != NULL;
					 ruleFilter = NextRuleFilter( Context, Event, ruleFilter ) ) {

					if( ruleFilter->FieldId == Filter->FieldId &&
						ruleFilter->AggregationId == Filter->AggregationId ) {
						return FALSE;
					}
				}
			}

			*Result = NoMatch;
			return TRUE;
		}
		break;

	case Failed:
		*Result = Failed;
		return TRUE;

	default:
		*Result = Failed;
		DBG_MODE( _tprintf( _T("[!] Unknown match value %u\n"), FieldMatch ) );
		return TRUE;
	}

	return FALSE;
}

//--------------------------------------------------------------------
//
// MatchFilterGroup
//
// Identify a rule filter group starting in FilterStart and return the
// status of the check against the event. The group can be an aggregate
// or not. The function can handle sub-aggregate groups while keeping
// the implementation as simple as possible.

// FilterEnd is used to show where the group ended for the caller to
// continue. For example when a sub-aggregate group run into another
// group or the end of the list.
//
//--------------------------------------------------------------------
MatchStatus
MatchFilterGroup(
	_In_ PRULE_CONTEXT Context,
	_In_opt_ PLARGE_INTEGER EventTime,
	_In_ PSYSMON_EVENT_TYPE_FMT EventType,
	_In_opt_ PSYSMON_DATA_DESCRIPTOR EventBuffer,
	_In_opt_ PSYSMON_EVENT_HEADER EventData,
	_In_ PRULE_EVENT Event,
	_In_opt_ PRULE_FILTER FilterStart,
	_Out_opt_ PRULE_FILTER *FilterEnd,
	_In_ PEVENT_DATA_DESCRIPTOR Output,
	_Out_opt_ PWCHAR* RuleName
	)
{
	PRULE_FILTER 			ruleFilter, prevFilter;
	PRULE_AGGREGATION 		agg = NULL;
	MatchStatus				fieldMatch, ret;
	ULONG 					error;
	PWCHAR					fieldValue;
	ULONG					fieldIndex;
	ULONG					sessionId = EventData ? EventData->m_SessionId : 0;
	RuleCombineType			combineType = Event->CombineType;
	ULONG64					fieldBitMatch = 0;
	PSYSMON_EVENT_TYPE_FMT 	filterEventType = NULL;

	// If the current event is different type than received, fetch the underlying type.
	// That's true for events with same name: registry, pipe and WMI.
	if( Event->EventId != EventType->EventId ) {

		filterEventType = FindEventTypeFromId( Event->EventId );
	}

	if( FilterStart != NULL ) {

		ruleFilter = FilterStart;
		if( ruleFilter->AggregationId != 0 ) {

			agg = AGGREGATION_FROM_OFFSET( Context, ruleFilter->AggregationOffset );
			combineType = agg->combineType;
		}
	} else {

		ruleFilter = NextRuleFilter( Context, Event, NULL );

		// No rules, means no match by default.
		if( ruleFilter == NULL ) {

			return NoMatch;
		}
	}

	if( FilterEnd != NULL ) {

		*FilterEnd = NULL;
	}

	ret = Undefined;
	while( ruleFilter != NULL ) {

		// An aggregation group within the event field list.
		// Call MatchFilterGroup for the sub-group and treat the result as a normal field entry.
		if( agg == NULL && ruleFilter->AggregationId != 0 ) {
			prevFilter = ruleFilter;
			fieldMatch = MatchFilterGroup( Context,
										   EventTime,
										   EventType,
										   EventBuffer,
										   EventData,
										   Event,
										   ruleFilter,
										   &ruleFilter,
										   Output,
										   RuleName );

			if( ruleFilter == prevFilter ) {

				DBG_MODE( _tprintf( _T("[!] Subgroup matching didn't move rule filter\n") ) );
				return Failed;
			}

			// Context and rule filter are NULL as no similar fields can exist.
			if( CombineGroupDone( NULL, NULL, NULL, combineType, FALSE, fieldMatch, &ret ) ) {

				break;
			}

			continue;
		}

		// While parsing an aggregation group, something different follows.
		// Complete this group check and return.
		if( agg != NULL && agg->aggregationId != ruleFilter->AggregationId ) {

			if( FilterEnd != NULL ) {

				*FilterEnd = ruleFilter;
			}

			// Set to NULL to show the end of the group parsed.
			ruleFilter = NULL;
			break;
		}

		fieldIndex = ruleFilter->FieldId;

		// Can happen for rules with multiple events ids (registry, pipe or WMI).
		if( fieldIndex >= EventType->FieldCount ) {

			fieldMatch = NoMatch;
			goto nextfield;
		}

		// Different events with same names are referencing different fields.
		// Hashes are computed at build time and checked to be unique for fields.
		if( filterEventType != NULL &&
			EventType->FieldHashes[fieldIndex] != filterEventType->FieldHashes[fieldIndex] ) {

			fieldMatch = NoMatch;
			goto nextfield;
		}

		// Check if the field was already checked and matched, skip it.
		// This check ensure that the same field is treated as OR in an AND group.
		// Aggregates are an exception to that rule.
		if( agg == NULL && fieldBitMatch & ( 1ull << fieldIndex ) ) {

			ruleFilter = NextRuleFilter( Context, Event, ruleFilter );
			continue;
		}

		// Field cache (Output) is kept across checks so the field is resolved only once.
		error = EventResolveField( EventTime,
								   EventType,
								   EventBuffer,
								   EventData,
								   fieldIndex,
								   Output,
								   TRUE );
		if( error != ERROR_SUCCESS ) {

			DBG_MODE( _tprintf( _T("[!] Failed to resolved field '%s' with 0x%08x\n"),
								EventType->FieldNames[fieldIndex],
								error ) );
			return Failed;
		}

		// This case is important for the kernel where field resolution is not possible.
		fieldValue = ( PWCHAR )(ULONG_PTR)Output[fieldIndex].Ptr;
		if( fieldValue == NULL ) {

			DBG_MODE( _tprintf( _T("[!] Failed to resolved field '%s' with no error\n"),
								EventType->FieldNames[fieldIndex] ) );
			return Failed;
		}

#if defined __linux__
		// on Linux, convert data to UTF16, on heap
		size_t fieldValueLen = UTF8toUTF16( NULL, (PCHAR)fieldValue, 0 );
        WCHAR *fieldValueUTF16 = (WCHAR *)malloc(fieldValueLen * sizeof(WCHAR));
        if (fieldValueUTF16 == NULL) {
            printf("Out of memory\n");
            return Failed;
        }
		UTF8toUTF16( fieldValueUTF16, (PCHAR)fieldValue, fieldValueLen );
		fieldValue = fieldValueUTF16;
#endif

		fieldMatch = MatchFilterOnSpecificRule( ruleFilter->FilterType,
												(PWCHAR)ruleFilter->Data,
												fieldValue,
												sessionId );
#if defined __linux__
        free(fieldValue);
        fieldValue = NULL;
#endif

		if( fieldMatch == Failed ) {

#if defined _WIN64 || defined _WIN32
			DBG_MODE( _tprintf( _T("[!] Failed to filter field '%s' on rule '%s'\n"),
								EventType->FieldNames[fieldIndex],
								ruleFilter->Name ) );
#endif
			return Failed;
		}

		if( fieldMatch == Match ) {

			if( RuleName != NULL ) {

				// Use the aggregate name (128 characters) only if the binary version is <= 14.1.
				if( !IsVersionGreaterFromContext(Context, 14, 1) && agg != NULL && agg->name[0] ) {

					*RuleName = agg->name;
				} else if (ruleFilter->Name[0]) {

					*RuleName = ruleFilter->Name;
				}
			}

			// Mark the field as matched so we don't check next fields of the same index.
			fieldBitMatch |= (1ull << fieldIndex);
		}

nextfield:
		if( CombineGroupDone( Context, Event, ruleFilter, combineType, (agg != NULL), fieldMatch, &ret ) ) {

			break;
		}

		ruleFilter = NextRuleFilter( Context, Event, ruleFilter );
	}

	// Complete the logic in CombineGroupDone but when the whole group
	// was checked. An AND group will means a Match, an OR means NoMatch.
	if( ret == Undefined && ruleFilter == NULL ) {

		ret = combineType == RuleCombineAND ? Match : NoMatch;
	}

	// Update FilterEnd if possible.
	if( ruleFilter != NULL && FilterEnd != NULL ) {

		// Ensure we are out of the aggregate.
		while( agg != NULL && ruleFilter != NULL && agg->aggregationId == ruleFilter->AggregationId ) {

			ruleFilter = NextRuleFilter( Context, Event, ruleFilter );
		}

		*FilterEnd = ruleFilter;
	}

	return ret;
}

//--------------------------------------------------------------------
//
// FilterEventRules
//
// Define if an event should be included or excluded. Goes over all
// rules applicable and return default if no match was possible.
//
//--------------------------------------------------------------------
RuleDefaultType
FilterEventRules(
	_In_ PRULE_CONTEXT Context,
	_In_opt_ PLARGE_INTEGER EventTime,
	_In_ PSYSMON_EVENT_TYPE_FMT EventType,
	_In_opt_ PSYSMON_DATA_DESCRIPTOR EventBuffer,
	_In_opt_ PSYSMON_EVENT_HEADER EventData,
	_In_ PEVENT_DATA_DESCRIPTOR Output,
	_Out_opt_ PWCHAR* RuleName,
	_Out_opt_ BOOLEAN *Failures
	)
{
	PRULE_EVENT				*events;
	MatchStatus				match;
	ULONG					index;

	if( Failures != NULL ) {

		*Failures = FALSE;
	}

	if( RuleName != NULL ) {

		*RuleName = NULL;
	}

	events = GetRuleEventList( Context, EventType->EventId );
	if( events == NULL || events[0] == NULL ) {

		// Return type default on no rule.
		return EventType->Default;
	}

	// Go over each rule event in the list to see if one matches.
	// The list starts with default include (onmatch=exclude) to ensure they have priority.
	for( index = 0; events[index] != NULL; index++ ) {

		match = MatchFilterGroup( Context,
								  EventTime,
								  EventType,
								  EventBuffer,
								  EventData,
								  events[index],
								  NULL,
								  NULL,
								  Output,
								  RuleName );
		if( match == Match ) {

			// On match, return the opposite of the default.
			return events[index]->RuleDefault == Rule_include ? Rule_exclude : Rule_include;
		}

		if( match == Failed ) {

			if( Failures != NULL ) {

				*Failures = TRUE;
			}
		}
	}

	// On default, RuleName is NULL.
	if( RuleName != NULL ) {

		*RuleName = NULL;
	}

	// If there was only one rule, use its default.
	if( index == 1 ) {

		return events[0]->RuleDefault;
	}

	// If no match and multiple rules, default to exclude.
	return Rule_exclude;
}

#ifdef __cplusplus
}
#endif
