#if defined _WIN64 || defined _WIN32
#include <windows.h>
#endif
#include <memory>

#include "gtest/gtest.h"
#include "test.h"

#if defined _WIN64 || defined _WIN32
#include "../../sysmonCommon/service.h"
#include "../../sysmonCommon/ioctlcmd.h"

// Not yet ported to Linux
PSYSMON_EVENT_HEADER ReadEvent(_In_ HANDLE hFile, _Out_ bool& Eof) {
	ULONG bytesRead;
	const ULONG eventHeaderSize = sizeof(SYSMON_EVENT_HEADER);

	Eof = false;

	PVOID event = malloc(sizeof(SYSMON_EVENT_HEADER));
	if( event == nullptr ) {
		_tprintf( _T("Failed to allocate buffer for SYSMON_EVENT_HEADER\n") );
		return nullptr;
	}

	if( !ReadFile(hFile, event, eventHeaderSize, &bytesRead, NULL) ) {
		_tprintf( _T("ReadFile() for trace events failed with %u\n"), GetLastError() );
		return nullptr;
	}

	if( bytesRead < eventHeaderSize ) {
		if( bytesRead != 0 ) {
			_tprintf( _T("Remaining bytes on the event traced buffer: %u\n"), bytesRead );
		} else {
			Eof = TRUE;
		}
		return nullptr;
	}

	ULONG curEventSize = ((PSYSMON_EVENT_HEADER)event)->m_EventSize;
	if( curEventSize == eventHeaderSize ) {
		return static_cast<PSYSMON_EVENT_HEADER>(event);
	}

	if( curEventSize < eventHeaderSize ) {
		_tprintf( _T("m_EventSize is too small for trace events: %u\n"), curEventSize );
		return nullptr;
	}

	PVOID buffer = malloc(curEventSize);
	if( buffer == nullptr ) {
		_tprintf( _T("malloc(%u) failed\n"), curEventSize );
		return nullptr;
	}

	ULONG remain = curEventSize - eventHeaderSize;
	memcpy(buffer, event, eventHeaderSize);

	if( !ReadFile(hFile, (PCHAR)buffer + eventHeaderSize, remain, &bytesRead, NULL) ) {
		_tprintf( _T("ReadFile() for trace events failed with %u\n"), GetLastError());
		return nullptr;
	}

	if( bytesRead < remain ) {
		_tprintf( _T("Partial record found on event traces: %u vs %u\n"), bytesRead, remain );
		return nullptr;
	}

	return static_cast<PSYSMON_EVENT_HEADER>(buffer);
}

// ReplayEvents will load an event trace binary and replay the events in DispacthEvents for performance profiling.
int ReplayEvents(_In_ PCTCH filename)
{
	HANDLE hFile = CreateFile( filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
	if( hFile == INVALID_HANDLE_VALUE ) {
		_tprintf( _T("Failed to open %s: %u"), filename, GetLastError() );
		return 1;
	}

	int ret = 0;
	DWORD pos = 0;
	while( TRUE ) {
		bool eof;
		PSYSMON_EVENT_HEADER event = ReadEvent( hFile, eof );
		if( event == nullptr ) {
			ret = (eof != TRUE);
			free( event );
			break;
		}

		if( event->m_EventType == ImageLoad ) {
			// ImageLoad requeue the event when a signature is identified, ignore those.
			if( event->m_EventBody.m_ImageLoadEvent.m_Signature != NULL ) {
				goto next;
			}

			// The token set doesn't exist in this context so set it to NULL.
			PHANDLE token = (PHANDLE)ExtGetPtrX( &event->m_EventBody.m_ImageLoadEvent, IL_Token, NULL );
			if( token && *token ) {
				*token = NULL;
			}
		}

		DWORD error = DispatchEvent( event );
		if( error != ERROR_SUCCESS ) {
			_tprintf( _T("DispatchEvent failed with error=%u pos=%u type=%u seq=%llu\n"), error, pos, event->m_EventType, event->m_SequenceNumber );
		}

next:
		pos += event->m_EventSize;
		free( event );
	}

	CloseHandle(hFile);
	return ret;
}
#endif

// main is used instead of _tmain to allow link with sysmonsvc to work without conflict.
int main(int argc, PCHAR* argv) {
	::testing::InitGoogleTest(&argc, argv);

#if defined _WIN64 || defined _WIN32
	// Not yet ported to Linux
	tstring traceConfig;
	tstring traceEvents;
	tstring traceCount = _T("1");
	for( int i = 1; i < argc; i++ ) {
		tstring *flag = NULL;
		tstring argument = string2tstring(std::string(argv[i]));

		if( !_tcsicmp(argument.c_str(), _T("--traceevents")) ) {
			flag = &traceEvents;
		} else if( !_tcsicmp(argument.c_str(), _T("--traceconfig")) ) {
			flag = &traceConfig;
		} else if( !_tcsicmp(argument.c_str(), _T("--tracecount")) ) {
			flag = &traceCount;
		}

		if( flag == NULL ) {
			continue;
		}

		if( i+1 >= argc ) {
			_tprintf( _T("%s expects an argument.\n"), argument.c_str() );
			return 1;
		}

		tstring next = string2tstring(std::string(argv[i + 1]));
		if( next[0] == _T('-') || next[0] == _T('/') ) {
			_tprintf( _T("%s expects an argument, followed by option.\n"), argument.c_str() );
		}

		*flag = next;
		i++;
	}

	if( !traceEvents.empty() ) {
		InitSignatureVerification();

		RegisterWindowsEvent();

		if( !traceConfig.empty() ) {
			PVOID Rules;
			ULONG RulesSize;
			if( !ApplyConfigurationFile( traceConfig.c_str(), &Rules, &RulesSize, TRUE ) ) {
				_tprintf( _T("ApplyConfiguration failed to load: %s\n"), traceConfig.c_str() );
				return 1;
			}
		} else {
			if( !InitializeRules() ) {
				_tprintf( _T("InitializeRules() failed\n") );
				return 1;
			}
		}

		int ret = 0;
		unsigned long count = std::stoul( traceCount );
		LARGE_INTEGER start, end;
		QueryPerformanceCounter( &start );
		for( unsigned long idx = 0; idx < count; idx++ ) {
			ret = ReplayEvents( traceEvents.c_str() );
			if( ret != 0 ) {
				_tprintf( _T("ReplayEvents returned %d\n"), ret );
				break;
			}
		}
		QueryPerformanceCounter( &end );
		if( !ret ) {
			_tprintf( _T("ReplayEvents replay done for %lu tracesn in %lld ns\n"), count, end.QuadPart - start.QuadPart );
		}
		return ret;
	} else if( !traceConfig.empty() ) {
		_tprintf( _T("--traceconfig was specified without --traceevents\n") );
		return 1;
	}
#endif

	return RUN_ALL_TESTS();
}
