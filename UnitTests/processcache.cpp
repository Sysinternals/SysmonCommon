// UnitTests for process cache testing.
#include "test.h"

#include "structs.h"

PROCESSCACHE_FETCH_TEST fetches[] = {
	{
		"Emtpy cache means no results",
		{},
		{},
		{
			ProcessCacheEntry( 1, 1, 1, nullptr ),
		},
	},
	{
		"One entry simple match",
		{
			ProcessCacheEntry( 1, 1, 1, nullptr ),
		},
		{
			ProcessCacheEntry( 1, 1, 1, nullptr ),
		},
		{},
	},
	{
		"One entry does not match for different process objects",
		{
			ProcessCacheEntry( 1, 1, 1, (PVOID)1 ),
		},
		{},
		{
			ProcessCacheEntry( 1, 1, 1, (PVOID)2 ),
		},
	},
	{
		"No time input provide latest",
		{
			ProcessCacheEntry( 1, 1, 1, nullptr ),
			ProcessCacheEntry( 1, 1, 2, nullptr ),
		},
		{
			ProcessCacheEntry( 1, 1, 0, nullptr ),
        },
		{},
	},
	{
		"Multi entry check",
		{
			ProcessCacheEntry( 1, 1, 1, nullptr ),
			ProcessCacheEntry( 1, 2, 1, nullptr ),
			ProcessCacheEntry( 1, 3, 1, nullptr ),
		},
		{
			ProcessCacheEntry( 1, 1, 1, nullptr ),
			ProcessCacheEntry( 1, 2, 1, nullptr ),
			ProcessCacheEntry( 1, 3, 1, nullptr ),
        },
		{
			ProcessCacheEntry( 1, 4, 1, nullptr ),
		},
	},
};


// Fetch tests adding and getting entries from the process cache.
TEST( ProcessCacheTests, Fetch )
{
	for( auto& fetch : fetches ) {
        SCOPED_TRACE( fetch.Description );

		ProcessCache::Instance().RemoveEntries();
		ASSERT_TRUE( ProcessCache::Instance().Empty() );

		std::map<ULONG64, ULONG64> pkeyTimeMap;

        // Setup the process cache cache.
		for( auto& input : fetch.Input ) {
			input.AddToCache();

            // Key the latest process created per key in a map.
			auto& proc = input.EventHeader->m_EventBody.m_ProcessCreateEvent;
			ULONG64 key = proc.m_ProcessKey;
			ULONG64 time = proc.m_CreateTime.QuadPart;
			auto it = pkeyTimeMap.find( key );
			if( it == pkeyTimeMap.end() ) {
				pkeyTimeMap.insert( std::pair<ULONG64, ULONG64>( key, time ) );
			} else if( ( *it ).second < time ) {
				( *it ).second = time;
			}
		}

        // Check expect entries in the process cache.
		for( auto& exist : fetch.Exists ) {
			PPROCESS_CACHE_INFORMATION cacheEntry = exist.GetFromCache();
			ASSERT_NE( cacheEntry, nullptr );

            // If the time is unset, replace by latest.
			auto& proc = exist.EventHeader->m_EventBody.m_ProcessCreateEvent;
            if (proc.m_CreateTime.QuadPart == 0) {
				proc.m_CreateTime.QuadPart = pkeyTimeMap[proc.m_ProcessKey];
			}

			ASSERT_EQ( 0, memcmp( cacheEntry->data, &proc, sizeof( *cacheEntry->data ) ) );
		}

        // Check non-expected entries.
		for( const auto& miss : fetch.Miss ) {
			ASSERT_EQ( nullptr, miss.GetFromCache() );
		}
	}
}

// Remove checks behaviour while adding and removing entries.
TEST( ProcessCacheTests, Remove )
{
	ProcessCacheEntry first( 1, 1, 1, nullptr );
	ProcessCacheEntry firstAfter( 1, 1, 2, nullptr );
	ULONG64 expired = PROCESS_CACHE_FREE_DELAY + first.EventHeader->m_EventBody.m_ProcessCreateEvent.m_CreateTime.QuadPart + 1;
	ProcessCacheEntry late( 2, 2, expired, nullptr );

	ProcessCache::Instance().RemoveEntries();
	ASSERT_TRUE( ProcessCache::Instance().Empty() );

    // Add to cache, check cache is not empty and entry is here.
	first.AddToCache();
	ASSERT_FALSE( ProcessCache::Instance().Empty() );
	ASSERT_NE( nullptr, first.GetFromCache() );

    // Remove from cache, just mark as removed but stay for delay.
	first.RemoveFromCache();
	ASSERT_FALSE( ProcessCache::Instance().Empty() );
	ASSERT_NE( nullptr, first.GetFromCache() );

    // Remove an entry later, clean the cache.
	late.RemoveFromCache();
	ASSERT_TRUE( ProcessCache::Instance().Empty() );

    // Add two entries, one is automatically marked as removed.
	first.AddToCache();
	ASSERT_NE( nullptr, first.GetFromCache() );
	ASSERT_EQ( 0, first.GetFromCache()->removedTime.QuadPart );
	firstAfter.AddToCache();
	ASSERT_NE( nullptr, first.GetFromCache() );
	ASSERT_NE( 0, first.GetFromCache()->removedTime.QuadPart );
	ASSERT_FALSE( ProcessCache::Instance().Empty() );

    // Removing the late entry does nothing because removedTime is aligned with current time.
	late.RemoveFromCache();
	auto cacheEntry = first.GetFromCache();
	ASSERT_NE( nullptr, cacheEntry );

    // Update late to work and test it removed everything.
	firstAfter.RemoveFromCache();
	auto& lateCreateTime = late.EventHeader->m_EventBody.m_ProcessCreateEvent.m_CreateTime;
	lateCreateTime.QuadPart = cacheEntry->removedTime.QuadPart;
	lateCreateTime.QuadPart += PROCESS_CACHE_FREE_DELAY + 1;
	late.RemoveFromCache();
	ASSERT_TRUE( ProcessCache::Instance().Empty() );
}

// ParentProcess checks parent user information can be resolved from the cache.
TEST( ProcessCacheTests, ParentProcessUser) {
	SYSMON_DATA_DESCRIPTOR eventBuffer[SYSMON_MAX_EVENT_Fields] = {};
	EVENT_DATA_DESCRIPTOR outputBuffer[SYSMON_MAX_EVENT_Fields] = {};
	SYSMON_EVENT_HEADER eventHeader = {};

	// Prepare a parent entry for SYSTEM user.
	ProcessCacheEntry parent( 1, 1, 1, nullptr );
	auto& proc = eventHeader.m_EventBody.m_ProcessCreateEvent;
	auto& parentProc = parent.EventHeader->m_EventBody.m_ProcessCreateEvent;
	proc.m_ParentProcessId = parentProc.m_ProcessId;
	proc.m_CreateTime.QuadPart = parentProc.m_CreateTime.QuadPart + 1;

	PSID parentUserSid = nullptr;
	ASSERT_TRUE( ConvertStringSidToSid( _T("S-1-5-18"), &parentUserSid ) );

	ProcessCache::Instance().RemoveEntries();
	ASSERT_TRUE( ProcessCache::Instance().Empty() );

	PTCHAR* parentUser = reinterpret_cast<PTCHAR*>(&outputBuffer[F_CP_ParentUser].Ptr);

	// Process cache is empty, result is empty.
	ASSERT_EQ( EventResolveField( &proc.m_CreateTime, &SYSMONEVENT_CREATE_PROCESS_Type, eventBuffer, &eventHeader, F_CP_ParentUser, outputBuffer, false ), 0ul );
	ASSERT_STREQ( *parentUser, _T("-") );

	// Process cache set without PC_Sid (user) defined.
	memset( outputBuffer, 0, sizeof( outputBuffer ) );
	parent.AddToCache();
	ASSERT_EQ( EventResolveField( &proc.m_CreateTime, &SYSMONEVENT_CREATE_PROCESS_Type, eventBuffer, &eventHeader, F_CP_ParentUser, outputBuffer, false ), 0ul );
	ASSERT_STREQ( *parentUser, _T("-") );
	parent.RemoveFromCache();

	// Process cache is correctly resolved with a SYSTEM user.
	memset( outputBuffer, 0, sizeof( outputBuffer ) );
	parent.AddExtension( PC_Sid, parentUserSid, GetLengthSid( parentUserSid ) );
	parent.AddToCache();
	ASSERT_EQ( EventResolveField( &proc.m_CreateTime, &SYSMONEVENT_CREATE_PROCESS_Type, eventBuffer, &eventHeader, F_CP_ParentUser, outputBuffer, false ), 0ul );
	ASSERT_STREQ( *parentUser, _T("NT AUTHORITY\\SYSTEM") );
}