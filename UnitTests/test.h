// Common header and definitions for testing.
#pragma once

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#if !defined _WIN64 && !defined _WIN32
#include "linuxTypes.h"
#endif
#include "utils.h"
#if defined _WIN64 || defined _WIN32
#include "..\..\sysmonCommon\rules.h"
#include "..\..\sysmonCommon\service.h"
#include "..\..\sysmonCommon\xml.h"
#include "..\..\exe\environmentvar.h"
#include "..\..\sysmonCommon\eventsCommon.h"
#else
#include "rules.h"
#include "xml.h"
#include "eventsCommon.h"
#endif

#define mockSessionId 1111
#define mockSecondSessionId 2222

#if defined _WIN64 || defined _WIN32
extern EnvironmentVariableCache *envCache;

// Common mock classes
class MockEnvironmentVariableCache : public EnvironmentVariableCache
{
public:
    MockEnvironmentVariableCache() {
        replaced = nullptr;

        // Default handlers relay to the parent class.
        ON_CALL(*this, AddValueToCache).WillByDefault([this](
            _In_ ULONG sessionId,
            _In_ LPWSTR variableString,
            _In_ LPWSTR expandedString
        ) {
            EnvironmentVariableCache::AddValueToCache(
                sessionId,
                variableString,
                expandedString
            );
        });

        ON_CALL(*this, GetUserToken).WillByDefault([this](
            _In_ ULONG sessionId,
            _Out_ HANDLE* token
        ) {
            return EnvironmentVariableCache::GetUserToken(
                sessionId,
                token);
        });
    }

    // Constructor to temporarily replace a global cache.
    MockEnvironmentVariableCache(EnvironmentVariableCache **current) : MockEnvironmentVariableCache() {
        if( *current != nullptr ) {
            delete *current;
        }
        replaced = current;
        *current = this;
    }

    ~MockEnvironmentVariableCache() {
        // Clean any pointer that was replaced.
        if( replaced != nullptr ) {
            *replaced = new EnvironmentVariableCache();
        }
    }

    MOCK_METHOD(void, AddValueToCache, (
        _In_ ULONG sessionId,
        _In_ LPWSTR variableString,
        _In_ LPWSTR expandedString), (override));

    MOCK_METHOD(BOOL, GetUserToken, (
        _In_ ULONG sessionId,
        _Out_ HANDLE* token), (override));

    // MockGetUserToken can be used to replace GetUserToken to return the hToken for the current process.
    static BOOL MockGetUserToken(
        _In_ ULONG sessionId,
        _Out_ HANDLE* token) {
        return OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token);
    }

private:
    EnvironmentVariableCache **replaced;
};

#endif
// Internal functions that are called by the unittest framework but not defined in Sysmon headers.

// from events.cpp
RuleDefaultType
ProcessEventRulesDry(
    PLARGE_INTEGER EventTime,
    PSYSMON_EVENT_TYPE_FMT EventType,
    PSYSMON_DATA_DESCRIPTOR EventBuffer,
    PSYSMON_EVENT_HEADER EventData,
    PWCHAR *RuleName);

VOID EventSetFieldS(
    _In_ PSYSMON_DATA_DESCRIPTOR DataDescriptor,
    _In_ ULONG FieldIndex,
    _In_ const TCHAR *String,
    _In_ BOOLEAN Allocated);

PVOID ExtGetPtr(
	_In_ PULONG extensionsSizes,
	_In_ PVOID extensions,
	_In_ ULONG index,
	_Out_ PULONG retSize
	);

#define ExtGetPtrX( _v, _i, _s ) \
	ExtGetPtr( (_v)->m_Extensions, (_v) + 1, _i, _s )

