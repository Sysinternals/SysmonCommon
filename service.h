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
// Service.h
//
// Function headers.
//
//====================================================================

//
// Application name
//
#define SZAPPNAME            "SysmonSvc"

//
// list of service dependencies - "dep1\0dep2\0\0"
//
#define SZDEPENDENCIES       ""

//
// Pipe defines
//
#define BUFSIZE			65536
#define PIPE_TIMEOUT	10000

//
// Dump configuration defines
//
#define CONFIG_FMT 				"%-34s"
#define CONFIG_NAME(_x) 		_T(" - ") _T(_x) _T(":")
#define CONFIG_DEFAULT_PATH		"\\Sysmon\\"
#define OFFICE_SMART_HYPHEN 0x2013

//
// In sysmon.c
//
VOID ServiceStart(DWORD dwArgc, LPTSTR *lpszArgv);
VOID ServiceStop();
DWORD InitializeService( BOOLEAN Debug );


//
// In Service.c
//
BOOL ReportStatusToSCMgr(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
BOOL GetFileHash( ULONG algorithm, TCHAR *FileName, PTCHAR hashString, SIZE_T hashStringLen, BOOLEAN requireStrongHash );
BOOL HashBuffer( BOOL includeAlgoName, ULONG algorithm, const PBYTE Buffer, SIZE_T BufferSize, PTCHAR hashString, SIZE_T hashStringLen, BOOLEAN requireStrongHash );
DWORD GetConfigurationOptions();
DWORD GetHashingAlgorithm();
BYTE  GetConfigFromRegistry( PTCHAR ConfigName );
PTCHAR GetFieldSizesFromRegistry();
DWORD SetupRules();
BOOLEAN QueryRegistry( _In_ HKEY Key, _In_ PTCHAR Value, _In_ DWORD ValueType, _Out_ PBYTE Buffer, _Out_ PULONG BufferSize );


//
// In Usage.c
//
void PrintUsageText( _In_ CONSOLE_SCREEN_BUFFER_INFO* csbi, _In_ PTCHAR Text );
int Usage( _In_ PTCHAR program, _In_ CONSOLE_SCREEN_BUFFER_INFO* csbi );
VOID ConfigUsage( _In_ CONSOLE_SCREEN_BUFFER_INFO* csbi );


//
// In ParseCommandLine.c
//
BOOLEAN ParseCommandLine( _In_ int argc, _In_ TCHAR** argv, _In_ PVOID* Rules, _In_ PULONG RulesSize,
    _In_ PTCHAR *ConfigFile, _In_ PTCHAR ConfigHash, _In_ SIZE_T ConfigHashSize
#if defined __linux__
	, _In_ BOOLEAN Transform
#endif
	);
PTCHAR StringListDup( _In_ PTCHAR List, _In_opt_ PULONG FinalLength);
BOOLEAN LoadVariableFieldSizes(PCTSTR FieldSizeStr);
int GetVariableFieldSize(ULONG EventId, ULONG FieldId);

//
// In printSchema.c
//
void PrintSchema();

//
// In dumpConfiguration.c
//
VOID DumpConfiguration();

//
// In rules.c
//
void PrintErrorEx( PTCHAR ID, DWORD ErrorCode, PTCHAR Format, ... );

//
// In clipboard.c
//
BOOL RegisterClipboardListening();
VOID StartClipboardListening(PTCHAR PipeName);
VOID ClipboardConfigUpdate();
VOID ClipboardQueueSessionChange(DWORD SessionId, BOOLEAN Active);
VOID CleanupClipboardListening(VOID);


//
// In events.c
//
void ProcessCacheInitialize( void );
DWORD RegisterWindowsEvent(VOID);
DWORD UnRegisterWindowsEvent(VOID);
DWORD DispatchEvent(PVOID event);
DWORD ClipboardEvent(DWORD OwnerPID, PTCHAR ImageName, DWORD SessionId, ULONG HashType, PTCHAR Hash, PTCHAR Archived);
DWORD HandleWindowsEventManifest(BOOL Register);
DWORD DeletegateHandleManifest(PTCHAR szPath);
DWORD WmiFilterEvent(PLARGE_INTEGER Time, const TCHAR* operation, const TCHAR* creatorSID, const TCHAR* eventNamespace, const TCHAR* name, const TCHAR* query);

DWORD WmiConsumerEvent(PLARGE_INTEGER Time, const TCHAR* operation, const TCHAR* creatorSID, const TCHAR* eventNamespace, const TCHAR* name, const TCHAR* filename, const TCHAR* text);

DWORD WmiBindingEvent(PLARGE_INTEGER Time, const TCHAR* operation, const TCHAR* creatorSID, const TCHAR *consumer, const TCHAR* filter);

#if !defined(SYSMON_SHARED) && !defined(SYSMON_PUBLIC)
DWORD InitTraceEvents();
#else
#define InitTraceEvents() ERROR_SUCCESS
#endif
DWORD SendStateEvent( _In_ PTCHAR State, _In_ PTCHAR FileVersion );
DWORD SendConfigEvent( _In_ PTCHAR Config, _In_ PTCHAR ConfigHash );

//
// In crypto.c
//
ULONG SysmonCryptoCurrent( VOID );

//
// In wmi.cpp
//
VOID RegisterWmiListening();
VOID CleanupWmiListening();

//
// In network.cpp
//
DWORD NetworkEnableTracing( BOOLEAN Enable );
void TranslateSid( PSID pUserSid, PTCHAR Buffer, SIZE_T Size );

//
// In Dns.cpp
//
DWORD DnsEnableTracing( BOOLEAN Enable );

//
// In environmentvar.cpp
//
void CleanEnvSessionCache(_In_ ULONG sessionId);
void CleanEnvCache();

extern PTCHAR		SysmonDriverName;
extern PTCHAR		SysmonServiceName;
extern BOOLEAN		bRegisterManifest;
extern BOOLEAN 		bPreVista;
extern BOOLEAN		g_DebugMode;
extern BOOLEAN		g_DebugModeVerbose;
extern CRITICAL_SECTION g_DebugModePrintCriticalSection;
#define DBG_MODE(_x) if( g_DebugMode ) { _x; }
#define DBG_MODE_VERBOSE(_x) if( OPT_SET(DebugMode) && g_DebugModeVerbose) { _x; }

#ifndef AMD64
typedef BOOL (__stdcall *PISWOW64PROCESS)(
			HANDLE hProcess,
			PBOOL Wow64Process
			);
#endif

//
// Useful macros
//
#define InitializeListHead(ListHead) (\
    (ListHead)->Flink = (ListHead)->Blink = (ListHead))
#define RemoveEntryList(Entry) {\
	PLIST_ENTRY _EX_Blink;\
	PLIST_ENTRY _EX_Flink;\
	_EX_Flink = (Entry)->Flink;\
	_EX_Blink = (Entry)->Blink;\
	_EX_Blink->Flink = _EX_Flink;\
	_EX_Flink->Blink = _EX_Blink;\
	}
#define InsertHeadList(ListHead,Entry) {\
	PLIST_ENTRY _EX_Flink;\
	PLIST_ENTRY _EX_ListHead;\
	_EX_ListHead = (ListHead);\
	_EX_Flink = _EX_ListHead->Flink;\
	(Entry)->Flink = _EX_Flink;\
	(Entry)->Blink = _EX_ListHead;\
	_EX_Flink->Blink = (Entry);\
	_EX_ListHead->Flink = (Entry);\
	}
#define IsListEmpty(ListHead) \
    ((ListHead)->Flink == (ListHead))

#ifndef _countof
#define _countof(_x) (sizeof(_x)/sizeof(*_x))
#endif

#ifndef DWORD_MAX
#define DWORD_MAX 0xFFFFFFFF
#endif

#ifndef AF_INET6
#define AF_INET6 23
#endif

