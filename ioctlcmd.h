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
// Sysmon
//
//====================================================================

#pragma once

#define MAX_EVENT_SIZE 0x40000

// Define the various device type values.  Note that values used by Microsoft
// Corporation are in the range 0-32767, and 32768-65535 are reserved for use
// by customers.
#define FILE_DEVICE_SYSMON     0x00008340

#define IOCTL_SYSMON_GET_VERSION		(ULONG) CTL_CODE( FILE_DEVICE_SYSMON, 0x00, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_SYSMON_READ_EVENT			(ULONG) CTL_CODE( FILE_DEVICE_SYSMON, 0x01, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_SYSMON_UPDATE_CONFIG		(ULONG) CTL_CODE( FILE_DEVICE_SYSMON, 0x02, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_SYSMON_PROCESS_CACHE		(ULONG) CTL_CODE( FILE_DEVICE_SYSMON, 0x03, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define IOCTL_SYSMON_FILE_DELETE_FILTER_RESULT  (ULONG) CTL_CODE( FILE_DEVICE_SYSMON, 0x04, METHOD_BUFFERED, FILE_ANY_ACCESS )

// Options
#define SYSMON_OPTIONS_NETWORK		0x1
#define SYSMON_OPTIONS_IMAGE		0x2
#define SYSMON_OPTIONS_DNS			0x4
#define SYSMON_OPTIONS_CLIPBOARD	0x8

// Options Internal & shared
#define SYSMON_OPTIONS_FILTER_PE	0x80000000

// max path size of logged image name+path
#define		SYSMON_MAX_IMAGE_PATH	( 260 )
#define		SYSMON_MAX_NAME			( 128 )

// max number of frames we log for a call trace
#ifdef _AMD64_
#define		SYSMON_MAX_SBT_FRAMES	( 24 )
#else
#define		SYSMON_MAX_SBT_FRAMES	( 16 )
#endif

// Maximum number of process access watches that can be configured
#define		PAL_MAX_CONFIG_ITEMS	( 10 )

// Hundreds of nanoseconds
#define NT_ONE_SECOND			10000000
#define NT_500_MS				NT_ONE_SECOND/2

// Embedded string length
#define ARCHIVED_CCH		60
#define PROCESS_TAMPER_TYPE_CCH 40

// Crypto algorithm
// Supported SHA-1, MD5 & SHA-256
typedef enum {
	ALGO_INVALID = 0,
	ALGO_SHA1,
	ALGO_MD5,
	ALGO_SHA256,
	ALGO_IMPHASH,
	ALGO_MAX
} HASHING_ALGORITHM;

#define ALGO_COUNT			( ALGO_MAX - 1 )
#define ALGO_MULTIPLE		0x80000000
#define ALGO_GET_MASK(_x)	( 1 << (_x - 1) )
#define ALGO_MASK			( ALGO_GET_MASK(ALGO_MAX) - 1 )
#define ALGO_STRONG_MASK	( ALGO_GET_MASK(ALGO_SHA1) | ALGO_GET_MASK(ALGO_MD5) | ALGO_GET_MASK(ALGO_SHA256) )
#define ALGO_ALL			( ALGO_MASK | ALGO_MULTIPLE )

// Warnings to disable accross on level 4
#if defined _WIN64 || defined _WIN32
#pragma warning (disable:4324) // warning C4324: 'struct_name' : structure was padded due to __declspec(align())
#endif


typedef struct {
   	ULONG	ProcessId;
	ULONG	UpdateCache;
} UPDATE_CACHE, *PUPDATE_CACHE;


typedef enum {
	ConfigUpdate,
	ProcessCreate,
	FileTime,
	ProcessTerminate,
	ProcessCreateCache,
	ImageLoad,
	KernelError,
	RemoteThread,
	RawAccessRead,
	ProcessAccess,
	FileCreate,
	FileCreateStreamHash,
	RegistryEvent,				// Registry major type. See SYSMON_REGISTRY_EVENT_SUBTYPE for actual registry event type
	PipeEvent,
	ProcessTamperingEvent,
	FileDelete,
	FileDeleteDetected
} SYSMON_EVENT_TYPE, *PSYSMON_EVENT_TYPE;


typedef enum {
	EVENT_TYPE_NETWORK_UNKNOWN,
	EVENT_TYPE_NETWORK_OTHER,
	EVENT_TYPE_NETWORK_SEND,
	EVENT_TYPE_NETWORK_RECV,
	EVENT_TYPE_NETWORK_ACCEPT,
	EVENT_TYPE_NETWORK_CONNECT,
	EVENT_TYPE_NETWORK_DISCONNECT,
	EVENT_TYPE_NETWORK_RECONNECT,
	EVENT_TYPE_NETWORK_RETRANSMIT,
	EVENT_TYPE_NETWORK_TCPCOPY,
} EVENT_TYPE_NETWORK;

typedef enum {
	FD_Sid = 0,
	FD_FileName,
	FD_ImagePath,
	FD_Hash,
	FILE_DELETE_ExtMax,
} FILE_DELETE_Extensions;


typedef struct {
	ULONG				m_ProcessId;
	LARGE_INTEGER		m_DeleteTime;
	ULONG				m_HashType;
	ULONG				m_IsExecutable;
	ULONG				m_Extensions[FILE_DELETE_ExtMax];
	TCHAR				m_Archived[ARCHIVED_CCH];

	// For filter check upcall
	ULONG				m_TrackerId;
} SYSMON_FILE_DELETE, *PSYSMON_FILE_DELETE;

typedef struct {
	LIST_ENTRY			ListEntry;
	ULONG				TrackerId;
	PVOID				SysmonServiceInstance;
	PVOID				KernelEventPointer;
	PVOID				FilterResultPointer;
} SYSMON_FILE_DELETE_TRACKER, *PSYSMON_FILE_DELETE_TRACKER;

typedef enum {
	FileDeleteExclude,
	FileDeleteArchiveInclude,
	FileDeleteLoggedInclude
} FILE_DELETE_RESULT_VALUE;

typedef struct {
	ULONG						m_TrackerId;
	FILE_DELETE_RESULT_VALUE	m_PassedFilter;
} SYSMON_FILE_DELETE_FILTER_RESULT, * PSYSMON_FILE_DELETE_FILTER_RESULT;

typedef enum {
	PC_Sid = 0,
	PC_IntegrityLevel,
	PC_ImagePath,
	PC_CommandLine,
	PC_Hash,
	PC_CurrentDirectory,
	PROCESS_CREATE_ExtMax
} PROCESS_CREATE_Extensions;

typedef struct {
	ULONGLONG			m_ProcessKey;
	ULONG				m_ProcessId;
	ULONG				m_ParentProcessId;
	ULONG				m_SessionId;
#if defined _WIN64 || defined _WIN32
	ULONG				m_Is64bit;
#elif defined __linux__
// Linux should report the auid for sudo, etc
    ULONG               m_AuditUserId;
#endif
	LARGE_INTEGER		m_CreateTime;
	LUID				m_AuthenticationId;
	ULONG				m_IsAppContainer;
	ULONG				m_HashType;
	PVOID				m_ParentProcessObject;	
	PVOID				m_ProcessObject;
	ULONG				m_Extensions[PROCESS_CREATE_ExtMax];
} SYSMON_PROCESS_CREATE, *PSYSMON_PROCESS_CREATE;

typedef enum {
	FT_Sid = 0,
	FT_ImagePath,
	FT_FileName,
	FILE_TIME_ExtMax
} FILE_TIME_Extensions;

typedef struct {
	ULONG				m_ProcessId;
	LARGE_INTEGER		m_EventTime;
	LARGE_INTEGER		m_CreateTime;
	LARGE_INTEGER		m_PreviousCreateTime;
	ULONG				m_Extensions[FILE_TIME_ExtMax];
} SYSMON_FILE_TIME, *PSYSMON_FILE_TIME;

typedef enum {
	FC_Sid = 0,
	FC_ImagePath,
	FC_FileName,
	FC_Contents,
	FILE_CREATE_ExtMax
} FILE_CREATE_Extensions;

typedef struct {
	ULONG				m_ProcessId;
	LARGE_INTEGER		m_EventTime;
	LARGE_INTEGER		m_CreateTime;
	HASHING_ALGORITHM	m_hashType;
	UCHAR				m_filehash[84];
	ULONG				m_Extensions[FILE_CREATE_ExtMax];
} SYSMON_FILE_CREATE, *PSYSMON_FILE_CREATE;

typedef enum {
	PT_Sid = 0,
	PROCESS_TERMINATE_ExtMax
} PROCESS_TERMINATE_Extensions;

typedef struct {
	ULONG				m_ProcessId;
	LARGE_INTEGER		m_EventTime;
	ULONG				m_Extensions[PROCESS_TERMINATE_ExtMax];
} SYSMON_PROCESS_TERMINATE, *PSYSMON_PROCESS_TERMINATE;

typedef enum {
	IL_Sid = 0,
	IL_ImagePath,
	IL_Hash,
	IL_ProcessImage,
	IL_Token,
	IMAGE_LOAD_ExtMax
} IMAGE_LOAD_Extensions;

typedef struct {
	ULONG				m_ProcessId;
	LARGE_INTEGER		m_EventTime;
	BOOLEAN				m_Driver;
	ULONG				m_HashType;
	PWCHAR				m_HashBuffer;
	PWCHAR				m_Signed;
	PWCHAR				m_SignatureStatus;
	PWCHAR				m_Signature;
	PVOID				m_ImageBase;
	PWCHAR				m_FetchedImageName;
	ULONG				m_Extensions[IMAGE_LOAD_ExtMax];
} SYSMON_IMAGE_LOAD, *PSYSMON_IMAGE_LOAD;

typedef enum {
	KE_ID = 0,
	KE_Message,
	KERNEL_ERROR_ExtMax
} KERNEL_ERROR_Extensions;

typedef struct {
	ULONG				m_Extensions[KERNEL_ERROR_ExtMax];
} SYSMON_KERNEL_ERROR, *PSYSMON_KERNEL_ERROR;

typedef struct {
	WCHAR				m_ModulePath[SYSMON_MAX_IMAGE_PATH + 1];
	UINT_PTR			m_ModuleBase;
	ULONG				m_ModuleSize;
	BOOLEAN				m_IsWow64;
	UINT_PTR			m_FrameReturnAddress;
} SYSMON_RESOLVED_TRACE, *PSYSMON_RESOLVED_TRACE;

typedef enum {
	PA_CallTrace = 0,
	PA_ClientImage,
	PA_TargetImage,
	PA_SidSource,
	PA_SidTarget,
	PROCESS_ACCESS_ExtMax
} PROCESS_ACCESS_Extensions;

typedef struct {
	ULONG				m_ClientProcessID;
	ULONG				m_ClientThreadID;
	ULONG				m_TargetPid;
	ULONG				m_GrantedAccess;
	LARGE_INTEGER		m_EventSystemTime;
	ULONG				m_Extensions[PROCESS_ACCESS_ExtMax];
} SYSMON_PROCESS_ACCESS, *PSYSMON_PROCESS_ACCESS;

typedef enum {
	CRT_SidSource = 0,
	CRT_SidTarget,
	CREATE_REMOTE_THREAD_ExtMax
} CREATE_REMOTE_THREAD_Extensions;

typedef struct {
	LARGE_INTEGER		m_EventSystemTime;
	ULONG				m_SourceProcessId;
	ULONG				m_TargetProcessId;
	ULONG				m_TargetThreadId;
	PVOID				m_StartAddress;
	WCHAR				m_StartModule[SYSMON_MAX_IMAGE_PATH + 1];
	WCHAR				m_StartFunction[SYSMON_MAX_NAME];
	ULONG				m_Extensions[CREATE_REMOTE_THREAD_ExtMax];
} SYSMON_CREATE_REMOTE_THREAD, *PSYSMON_CREATE_REMOTE_THREAD;

typedef enum {
	RR_Sid = 0,
	RAWACCESS_READ_ExtMax
} RAWACCESS_READ_Extensions;

typedef struct {
	LARGE_INTEGER		m_EventSystemTime;
	ULONG				m_ProcessId;
	TCHAR				m_Device[SYSMON_MAX_IMAGE_PATH + 1];
	ULONG				m_Extensions[RAWACCESS_READ_ExtMax];
} SYSMON_RAWACCESS_READ, *PSYSMON_RAWACCESS_READ;

typedef enum {
	RegistryEventMin,
	RegistryEventCreateKey,
	RegistryEventDeleteKey,
	RegistryEventRenameKey,
	RegistryEventCreateValue,
	RegistryEventDeleteValue,
	RegistryEventRenameValue,
	RegistryEventSetValue,
	RegistryEventMax
} SYSMON_REGISTRY_EVENT_SUBTYPE, *PSYSMON_REGISTRY_EVENT_SUBTYPE;

#if defined _WIN64 || defined _WIN32
static const LPWSTR RegistryEventStrings[RegistryEventMax] =
{
	L"Unknown Event type",
	L"CreateKey",
	L"DeleteKey",
	L"RenameKey",
	L"CreateValue",
	L"DeleteValue",
	L"RenameValue",
	L"SetValue"
};
#endif

typedef enum {
	REG_Sid = 0,
	REG_EventType,
	REG_ImagePath,
	REG_Target,
	REG_Data,
	REG_ExtMax
} REGISTRY_EVENT_Extensions;

typedef struct {
	SYSMON_REGISTRY_EVENT_SUBTYPE m_EventSubtype;
	LARGE_INTEGER		m_EventSystemTime;
	ULONG				m_ProcessId;
	ULONG				m_Extensions[REG_ExtMax];
} SYSMON_REGISTRY_EVENT, *PSYSMON_REGISTRY_EVENT;


typedef enum {
	PipeEventMin,
	PipeEventCreate,
	PipeEventConnect,
	PipeEventMax
} SYSMON_PIPE_EVENT_SUBTYPE, *PSYSMON_PIPE_EVENT_SUBTYPE;

#if defined _WIN64 || defined _WIN32
static const LPWSTR PipeEventStrings[PipeEventMax] =
{
	L"Unkown Event Type",
	L"CreatePipe",
	L"ConnectPipe"
};
#endif

typedef enum {
	PIPE_EventType = 0,
	PIPE_Name,
	PIPE_ImagePath,
	PIPE_Sid,
	PIPE_ExtMax
} PIPE_EVENT_Extensions;

typedef struct {
	SYSMON_PIPE_EVENT_SUBTYPE m_EventSubtype;
	LARGE_INTEGER		m_EventSystemTime;
	ULONG				m_ProcessId;
	ULONG				m_Extensions[PIPE_ExtMax];
} SYSMON_PIPE_EVENT, *PSYSMON_PIPE_EVENT;

typedef enum {
	PTP_Sid = 0,
	PROCESS_TAMPERING_ExtMax
} PROCESS_TAMPERING_Extensions;

typedef struct {
	SYSMON_PIPE_EVENT_SUBTYPE m_EventSubtype;
	LARGE_INTEGER		m_EventSystemTime;
	ULONG				m_ProcessId;
	WCHAR				m_Type[PROCESS_TAMPER_TYPE_CCH];
	ULONG				m_Extensions[PROCESS_TAMPERING_ExtMax];
} SYSMON_PROCESS_TAMPERING, *PSYSMON_PROCESS_TAMPERING;

#define FIELD_FILTERED(_x) (1 << _x)

typedef struct {
	SYSMON_EVENT_TYPE	m_EventType;
	ULONG				m_EventSize;
	ULONG				m_FieldFiltered;
	BOOLEAN				m_PreFiltered;
	ULONG64				m_SequenceNumber;
	ULONG				m_SessionId;
	union {
		SYSMON_PROCESS_CREATE		m_ProcessCreateEvent;
		SYSMON_FILE_DELETE			m_FileDeleteEvent;
		SYSMON_FILE_TIME			m_FileTimeEvent;
		SYSMON_PROCESS_TERMINATE	m_ProcessTerminateEvent;
		SYSMON_IMAGE_LOAD			m_ImageLoadEvent;
		SYSMON_KERNEL_ERROR			m_KernelErrorEvent;
		SYSMON_PROCESS_ACCESS		m_ProcessAccessEvent;
		SYSMON_CREATE_REMOTE_THREAD	m_CreateRemoteThreadEvent;
		SYSMON_RAWACCESS_READ		m_RawAccessRead;
		SYSMON_FILE_CREATE			m_FileCreateEvent;
		SYSMON_REGISTRY_EVENT		m_RegistryEvent;
		SYSMON_PIPE_EVENT			m_PipeEvent;
		SYSMON_PROCESS_TAMPERING	m_ProcessTamperingEvent;
	} m_EventBody;
} SYSMON_EVENT_HEADER, *PSYSMON_EVENT_HEADER;
