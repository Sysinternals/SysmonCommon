// UnitTests for field resolution testing.
#include "test.h"

#include "structs.h"

const PTCHAR sampleUnicodeString = _T("a sample unicode string\n\r\ttest");

FIELDS_RESOLUTION_TEST entries[] = {
	{
		"Unicode string",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_RuleName,
			FieldInputData( N_UnicodeString, sampleUnicodeString ),
			false,
		},
		FieldOutputData( sampleUnicodeString ),
	},
	{
		"Unicode string, no nullbyte",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_RuleName,
			FieldInputData( N_UnicodeString, sampleUnicodeString, (ULONG)_tcslen( sampleUnicodeString ) * sizeof( TCHAR ) ),
			false,
		},
		FieldOutputData( sampleUnicodeString ),
	},
	{
		"Input unicode string but output type is different leading to an error",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_ProcessId,
			FieldInputData( N_UnicodeString, sampleUnicodeString ),
			false,
		},
		FieldOutputData( ERROR_INVALID_PARAMETER ),
	},
	{
		"Registry unknown path",
		{
			&SYSMONEVENT_REG_KEY_Type,
			F_RK_TargetObject,
			FieldInputData( N_RegistryPath, _T("\\one\\two\\key") ),
			false,
		},
		FieldOutputData( _T("\\one\\two\\key") ),
	},
	{
		"Registry path HKCC",
		{
			&SYSMONEVENT_REG_KEY_Type,
			F_RK_TargetObject,
			FieldInputData( N_RegistryPath, _T("\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\HARDWARE PROFILES\\CURRENT\\one\\two\\key") ),
			false,
		},
		FieldOutputData( _T("HKCC\\one\\two\\key") ),
	},
	{
		"Registry path current control set",
		{
			&SYSMONEVENT_REG_KEY_Type,
			F_RK_TargetObject,
			FieldInputData( N_RegistryPath, _T("\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet\\one\\two\\key") ),
			false,
		},
		FieldOutputData( _T("HKLM\\SYSTEM\\ControlSet\\one\\two\\key") ),
	},
	{
		"Registry path HKLM",
		{
			&SYSMONEVENT_REG_KEY_Type,
			F_RK_TargetObject,
			FieldInputData( N_RegistryPath, _T("\\REGISTRY\\MACHINE\\one\\two\\key") ),
			false,
		},
		FieldOutputData( _T("HKLM\\one\\two\\key") ),
	},
	{
		"Registry path HKU",
		{
			&SYSMONEVENT_REG_KEY_Type,
			F_RK_TargetObject,
			FieldInputData( N_RegistryPath, _T("\\REGISTRY\\USER\\one\\two\\key") ),
			false,
		},
		FieldOutputData( _T("HKU\\one\\two\\key") ),
	},
	{
		"DOS path wrongly though to be NT Path",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_Image,
			FieldInputData( N_UnicodePath, _T("c:\\test\\path.exe") ),
			false,
		},
		FieldOutputData( _T("c:\\test\\path.exe") ),
	},
	{
		"NT DOS path simple",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_Image,
			FieldInputData( N_UnicodePath, _T("\\??\\c:\\test\\path.exe") ),
			false,
		},
		FieldOutputData( _T("c:\\test\\path.exe") ),
	},
	{
		"NT UNC path",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_Image,
			FieldInputData( N_UnicodePath, _T("\\??\\UNC\\myserver\\c$\\test\\path.exe") ),
			false,
		},
		FieldOutputData( _T("\\\\myserver\\c$\\test\\path.exe") ),
	},
	{
		"NT COM path",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_Image,
			FieldInputData( N_UnicodePath, _T("\\??\\COM20") ),
			false,
		},
		FieldOutputData( _T("COM20") ),
	},
	{
		"NT pipe path",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_Image,
			FieldInputData( N_UnicodePath, _T("\\??\\pipe\\something") ),
			false,
		},
		FieldOutputData( _T("pipe\\something") ),
	},
	{
		"NT path using SystemRoot",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_Image,
			FieldInputData( N_UnicodePath, _T("\\SystemRoot\\system32\\notepad.exe") ),
			false,
		},
		FieldOutputData( [=]() -> PTCHAR {
			auto buffer = new TCHAR[MAX_PATH + 1];
			ExpandEnvironmentStrings( _T("%SYSTEMROOT%\\system32\\notepad.exe"), buffer, MAX_PATH );
			return buffer;
		}() ),
	},
	{
		"NT path of device",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_Image,
			FieldInputData( N_UnicodePath, [=]() -> PTCHAR {
				TCHAR driveName[MAX_PATH + 1] = {};
				QueryDosDevice( _T("C:"), driveName, MAX_PATH );

				auto buffer = new TCHAR[MAX_PATH + 1];
				_stprintf_s( buffer, MAX_PATH, _T("%s\\Windows\\System32\\notepad.exe"), driveName );
				return buffer;
			}() ),
			false,
		},
		FieldOutputData( _T("C:\\Windows\\System32\\notepad.exe") ),
	},
	{
		"Ulong to Ulong",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_ProcessId,
			FieldInputData( N_Ulong, ULONG_MAX, sizeof( ULONG ) ),
			false,
		},
		FieldOutputData( ULONG_MAX, sizeof( ULONG ) ),
	},
	{
		"Ulong to Uint16",
		{
			&SYSMONEVENT_NETWORK_CONNECT_Type,
			F_NC_SourcePort,
			FieldInputData( N_Ulong, ULONG_MAX, sizeof( ULONG ) ),
			false,
		},
		FieldOutputData( 0xFFFF, sizeof( USHORT ) ),
	},
	{
		"Ulong with invalid size",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_ProcessId,
			FieldInputData( N_Ulong, ULONG_MAX, sizeof( ULONG64 ) ),
			false,
		},
		FieldOutputData( ERROR_INVALID_PARAMETER ),
	},
	{
		"Ulong64 to Hex64",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_LogonId,
			FieldInputData( N_Ulong64, 0xf001C00280034004, sizeof( ULONG64 ) ),
			false,
		},
		FieldOutputData( 0xf001C00280034004, sizeof( ULONG64 ) ),
	},
	{
		"Ulong64 to Hex64 string",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_LogonId,
			FieldInputData( N_Ulong64, 0xf001C00280034004, sizeof( ULONG64 ) ),
			true,
		},
		FieldOutputData( _T("17294315161049579524") ),
	},
	{
		"Ulong64 to Hex64 string",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_Image,
			FieldInputData( N_Ptr, 0xffffcccc, sizeof( PVOID ) ),
			false,
		},
		FieldOutputData( [=]() -> PTCHAR {
			auto buffer = new TCHAR[40];
			_stprintf_s( buffer, 40, _T("0x%p"), (PVOID)(ULONG_PTR)0xffffcccc );
			return buffer;
		}() ),
	},
	{
		"Zero time output",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_UtcTime,
			FieldInputData( N_LargeTime, 0ull, sizeof( LARGE_INTEGER ) ),
			false,
		},
		FieldOutputData( _T("1601-01-01 00:00:00.000") ),
	},
	{
		"Convert time when this test was written",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_UtcTime,
			FieldInputData( N_LargeTime, 132730191870340000, sizeof( LARGE_INTEGER ) ),
			false,
		},
		FieldOutputData( _T("2021-08-09 21:46:27.034") ),
	},
	{
		"ProcessID to Uint32",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_ProcessId,
			FieldInputData( N_ProcessId, 12345, sizeof( ULONG ) ),
			false,
		},
		FieldOutputData( 12345, sizeof( ULONG ) ),
	},

#if defined _WIN64 || defined _WIN32
	{
		"LocalSystem SID",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_User,
			FieldInputData( [=]() -> PSID {
				PSID output = nullptr;
				ConvertStringSidToSid( _T("S-1-5-18"), &output );
				return output;
			}() ),
			false,
		},
		FieldOutputData( _T("NT AUTHORITY\\SYSTEM") ),
	},
	{
		"LocalService SID",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_User,
			FieldInputData( [=]() -> PSID {
				PSID output = nullptr;
				ConvertStringSidToSid( _T("S-1-5-19"), &output );
				return output;
			}() ),
			false,
		},
		FieldOutputData( _T("NT AUTHORITY\\LOCAL SERVICE") ),
	},
	{
		"Anonymous SID",
		{
			&SYSMONEVENT_CREATE_PROCESS_Type,
			F_CP_User,
			FieldInputData( [=]() -> PSID {
				PSID output = nullptr;
				ConvertStringSidToSid( _T("S-1-5-7"), &output );
				return output;
			}() ),
			false,
		},
		FieldOutputData( _T("NT AUTHORITY\\ANONYMOUS LOGON") ),
	},
#endif
};

std::vector<NativeTypes> NativeStringTypes = {
	N_UnicodeString, N_EscapeUnicodeString, N_RegistryPath, N_UnicodePath, N_Ptr, N_LargeTime, N_Sid };

// Resolve tests expectations on field resolution.
TEST( Fields, Resolve )
{
	for( auto& entry : entries ) {
		SYSMON_DATA_DESCRIPTOR eventBuffer[SYSMON_MAX_EVENT_Fields] = {};
		EVENT_DATA_DESCRIPTOR outputBuffer[SYSMON_MAX_EVENT_Fields] = {};

		SCOPED_TRACE( entry.Description );

		auto& input = entry.Input;
		input.Data.SetSysmonDataDescriptor( eventBuffer + input.FieldIndex );

		DWORD ret = EventResolveField( nullptr, input.Type, eventBuffer, nullptr, input.FieldIndex, outputBuffer, input.StringOutput );
		ASSERT_EQ( ret, entry.Output.Status );

        // If we expected an error, move forward.
		if( entry.Output.Status != 0 ) {
			continue;
		}

		EVENT_DATA_DESCRIPTOR expected = {};
		entry.Output.SetEventDataDescriptor( &expected );

		auto& output = outputBuffer[input.FieldIndex];

        // Do string comparison whenever possible for easier debugging.
		if( input.StringOutput || std::find( begin( NativeStringTypes ), end( NativeStringTypes ), input.Data.Type ) != std::end( NativeStringTypes ) ) {
			EXPECT_EQ( expected.Size, output.Size );
			ASSERT_STREQ( (PTCHAR)expected.Ptr, (PTCHAR)output.Ptr );
		} else {
			ASSERT_EQ( expected.Size, output.Size );
			ASSERT_EQ( 0, memcmp( (PVOID)expected.Ptr, (PVOID)output.Ptr, expected.Size ) );
		}
	}
}
