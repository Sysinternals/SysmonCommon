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
// Rules.h
//
// Rule engine for user-mode and kernel-mode
//
//====================================================================
#pragma once

#if defined _WIN64 || defined _WIN32
#include "..\exe\windowsTypes.h"
#endif
#ifndef SYSMON_DRIVER
#include "stdafx.h"
#if defined _WIN64 || defined _WIN32
#include "..\exe\sysmonevents.h"
#else
#include "sysmonevents.h"
#endif
#else
#include "setenv.h"
#include "ntifs.h"
#include "sdkddkver.h"
#if defined _WIN64 || defined _WIN32
#include "..\exe\sysmonevents.h"
#else
#include "sysmonevents.h"
#endif
#include "..\sysmonCommon\ioctlcmd.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

//
// Helper macros for parsing rules blob
//
#define POINTER_FROM_OFFSET(context, offset)\
    (PVOID)((char*)context->Current->Rules + offset)

#define AGGREGATION_FROM_OFFSET(context, offset)\
    (PRULE_AGGREGATION)POINTER_FROM_OFFSET(context, offset)

#define FILTER_FROM_OFFSET(context, offset)\
	(PRULE_FILTER)POINTER_FROM_OFFSET(context, offset)

// List of RULE_EVENT to process in order for filtering.
// The order should aims to reduce processing as much as possible.
// For example, starting with rules to exclude as they take priority.
typedef struct
{
	PRULE_EVENT* Events;
} INDEX_TABLE_ENTRY, *PINDEX_TABLE_ENTRY;

typedef struct _RULE_INDEX_TABLE {
	INDEX_TABLE_ENTRY Entries[SYSMON_MAX_EVENT_ID + 1];
} RULE_INDEX_TABLE, *PRULE_INDEX_TABLE;

#define RULE_INDEX_MAX_ENTRIES 0xFFFF

typedef struct {
	ULONG Version;
	PVOID Rules;
	ULONG RulesSize;
	PRULE_INDEX_TABLE IndexingTable;
#if !defined(SYSMON_PUBLIC)
	// Handle internal events with their special ids
	PRULE_INDEX_TABLE ShadowIndexingTable;
#endif
	volatile LONG ReferenceCount;
} RULE_SET, *PRULE_SET;

#define INTERNAL_EVENT_MASK 0xf000
#define IS_INTERNAL_EVENT(_x) ( (_x & INTERNAL_EVENT_MASK) != 0 )

typedef struct {
	PRULE_SET Current;
} RULE_CONTEXT, *PRULE_CONTEXT;

#define GET_RULECTX_VERSION(_ctx) ((_ctx)->Current->Version)

typedef enum {
	Match,
	NoMatch,
	Failed,
	Undefined,
} MatchStatus;

//
// Functions
//
BOOLEAN
InitializeRules(
	VOID
	);

BOOLEAN
SetRuleBlob(
	_In_ PVOID Rules,
	_In_ ULONG RulesSize,
	_In_ BOOLEAN Transform
	);

BOOLEAN
InitializeRuleContext(
	_Out_ PRULE_CONTEXT Context
	);

VOID
ReleaseRuleContext(
	_In_ PRULE_CONTEXT Context
	);

ULONG
GetRuleVersion(
	VOID
	);

BOOLEAN
GetRuleRegInformation(
	_In_ PRULE_CONTEXT Context,
	_Out_ PRULE_REG RuleReg
	);

BOOLEAN
GetRuleRegExtInformation(
	_In_ PRULE_CONTEXT Context,
	_Out_ PRULE_REG_EXT RuleReg
	);

PRULE_EVENT
NextRuleEvent(
	_In_ PRULE_CONTEXT Context,
	_In_opt_ PRULE_EVENT Current
	);

PRULE_FILTER
NextRuleFilter(
	_In_ PRULE_CONTEXT Context,
	_In_ PRULE_EVENT Event,
	_In_opt_ PRULE_FILTER Current
	);

PSYSMON_EVENT_TYPE_FMT
FindEventTypeFromId(
    _In_ ULONG EventId
	);

PTCHAR
GetFieldName(
	_In_ PSYSMON_EVENT_TYPE_FMT Rule,
	_In_ ULONG Index
	);

PRULE_EVENT*
GetRuleEventList(
	_In_ PRULE_CONTEXT Context,
	_In_ ULONG EventId
	);

MatchStatus
MatchFilterOnSpecificRule(
	_In_ FilterOption FilterType,
	_In_ PWCHAR FilterData,
	_In_ PWCHAR FieldValue,
	_In_ ULONG SessionId
	);

BOOLEAN
IdHasIncludeRules(
	_In_ PRULE_CONTEXT Context,
	_In_ ULONG EventId
	);

VOID
SetEventDefault(
	_In_ ULONG EventId,
	_In_ RuleDefaultType RuleSetting
	);

BOOLEAN
ExpandEnvironmentVariable(
	_In_ ULONG sessionId,
	_Inout_ LPWSTR *variableString,
	_Out_ LPWSTR expandedString,
	_In_ ULONG expandedStringSize
	);

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
	);

#ifndef SYSMON_DRIVER
DWORD
EventResolveField(
	_In_opt_ PLARGE_INTEGER Time,
	_In_ PSYSMON_EVENT_TYPE_FMT EventType,
    _In_ PSYSMON_DATA_DESCRIPTOR EventBuffer,
	_In_opt_ PSYSMON_EVENT_HEADER EventHeader,
	_In_ ULONG FieldIndex,
	_Out_ PEVENT_DATA_DESCRIPTOR Output,
	_In_ BOOLEAN ForceOutputString
	);
#else
// Driver can't resolve fields that were not resolved already.
#define ERROR_SUCCESS 0
#define EventResolveField(...) ERROR_SUCCESS
#endif

#ifdef __cplusplus
}
#endif
