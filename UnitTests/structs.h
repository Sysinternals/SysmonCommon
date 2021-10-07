// structs to support the tests
#include "test.h"

#if defined _WIN64 || defined _WIN32
#include <shlwapi.h>
#else
#include <glob.h>
#endif
#include <string>
#include <vector>
#include <algorithm>

using ::testing::_;
using ::testing::Expectation;
using ::testing::Invoke;
using ::testing::AnyNumber;

typedef struct {
    // Description is added to the scope trace to help identify the exact input that broke the test.
    PCSTR Description;
    PVOID Rules;
    ULONG RulesSize;
} RULE_BLOB;

typedef struct
{
    TCHAR FileName[MAX_PATH];
    CHAR XMLEncoding[MAX_PATH];
    BOOLEAN Is16Bit;
    BOOLEAN HasBOM;
} ENCODING;

// RuleEntry is an helper class to generate a Sysmon XML rule.
class RuleEntry {
public:
    static const RuleEntry Empty;

    RuleEntry( const std::string& val ) : value( val )
    {}

    // A tag without any attribute.
    template< class ... Args >
    RuleEntry( const std::string& tag, RuleEntry first, Args ... rest )
        : value( tagify( tag, "", "", "" , unroll( first, rest ... ) ) )
    {}

    // A tag without any attribute but a name.
    RuleEntry( const std::string& tag, const std::string& name )
        : value( tagify( tag, name, "", "", "" ) )
    {}

    template< class ... Args >
    RuleEntry( const std::string& tag, const std::string& name, RuleEntry first, Args ... rest )
        : value( tagify( tag, name, "", "", unroll( first, rest ... ) ) )
    {}
    
    // A tag without a name but an attribute.
    RuleEntry( const std::string& tag,
    const std::string& attributeName, const std::string& attributeValue )
        : value( tagify( tag, "", attributeName, attributeValue, "" ) )
    {}

    template< class ... Args >
    RuleEntry( const std::string& tag,
        const std::string& attributeName, const std::string& attributeValue,
        RuleEntry first, Args ... rest )
        : value( tagify( tag, "", attributeName, attributeValue, unroll( first, rest ... ) ) )
    {}

    // Generates a tag with optional attribute and sub rule entry.
    RuleEntry( const std::string& tag, const std::string& name,
        const std::string& attributeName, const std::string& attributeValue )
        : value( tagify( tag, name, attributeName, attributeValue, "" ) )
    {}

    template< class ... Args >
    RuleEntry( const std::string& tag, const std::string& name,
        const std::string& attributeName, const std::string& attributeValue,
        RuleEntry first, Args ... rest )
        : value( tagify( tag, name, attributeName, attributeValue, unroll( first, rest ... ) ) )
    {}

protected:
    std::string value;

private:
    template< typename T, typename ... Args >
    static std::string unroll( T entry, Args ... rest )
    {
        return unroll(entry) + unroll(rest ... );
    }

    static std::string tagify( const std::string& tag, const std::string& name,
        const std::string& attributeName, const std::string& attributeValue,
        const std::string& body )
    {
        std::ostringstream out;

        out << "<" << tag;
        if( !name.empty() ) {

            out << " name=\"" << name << "\"";
        }
        if( !attributeName.empty() ) {

            out << " " << attributeName << "=\"" << attributeValue << "\"";
        }
        out << ">" << body << "</" << tag << ">";

        return out.str();
    }
};

template<>
inline std::string RuleEntry::unroll<RuleEntry>( RuleEntry entry )
{
    return entry.value;
}


// SysmonRule is the entry point to generate a Sysmon XML rule for testing.
class SysmonRule : public RuleEntry {
public:
    SysmonRule(const std::string version, RuleEntry sub)
        : RuleEntry("Sysmon", "", "schemaversion", version, sub, Empty) { }

    SysmonRule(const tstring file) : RuleEntry("invalid-xml, used configuration file") {
        configurationFile = file;
    }

    // Output returns a const PCHAR to the final rule generated.
    const PCHAR Output()
    {
        return const_cast<PCHAR>(value.c_str());
    }

    const tstring ConfigurationFile() {
        return configurationFile;
    }

    bool HasConfigurationFile() {
        return !configurationFile.empty();
    }

  private:
	tstring configurationFile;
};

#if defined _WIN64 && defined _WIN32
// EnvSolver simplifies rule building by expanding a variable and keeping the input and expanded output in multiple forms.
class EnvSolver {
public:
    EnvSolver(LPCSTR strInput) {
        CHAR buffer[MAX_PATH];
        ExpandEnvironmentStringsA(strInput, buffer, _countof(buffer));

        input = strInput;
        expanded = string2tstring(buffer);
        expandedUpper = expanded;
        std::transform(expandedUpper.begin(), expandedUpper.end(), expandedUpper.begin(), ::towupper);
    }

    tstring expanded;
    tstring expandedUpper;
    std::string input;
};
#endif

typedef struct _FIELD_VALUE {
    ULONG Id;
    LPCTSTR Value;
} FIELD_VALUE;

typedef struct _FIELD_VALUES {
    // Description of the field value test.
    PCSTR Description;

    // Input values to call ProcessEventRules.
    PSYSMON_EVENT_TYPE_FMT EventType;
    std::vector<FIELD_VALUE> Fields;

    // Expected state on return.
    RuleDefaultType ExpectedReturn;
    tstring ExpectedRuleName;
} FIELD_VALUES;

typedef struct _RULE_FILTER_TEST {
    // Description of the test.
    PCSTR Description;

    // Information to generate the rule to apply.
    SysmonRule Rule;

    // Input/Output tests for each field.
    std::vector<FIELD_VALUES> Values;
} RULE_FILTER_TEST;

typedef struct _INCLUDE_VALUES {
    // Type of events to check for.
    PSYSMON_EVENT_TYPE_FMT EventType;

    // Expected state on return.
    BOOLEAN ExpectedReturn;
} INCLUDE_VALUES;

typedef struct _RULE_INCLUDE_TEST {
    // Description of the test.
    PCSTR Description;

    // Information to generate the rule to apply.
    SysmonRule Rule;

    // Input/Output tests for each field.
    std::vector<INCLUDE_VALUES> Values;
} RULE_INCLUDE_TEST;

#if defined _WIN64 || defined _WIN32
//
// This test relies on testing::internal::CaptureStdout() which does not appear to
// function on Linux
//
typedef struct _INCORRECT_XML
{
    // Description of the test.
    const PCSTR Description;

    // Rule loaded.
    SysmonRule Rule;

    // Error regex printed on failure.
    std::string ErrorRegex;
} INCORRECT_XML;

#endif

class ProcessCacheEntry {
public:
  ProcessCacheEntry( _In_ ULONG64 ProcessKey,
					 _In_ DWORD Pid,
					 _In_ ULONG64 CreateTime,
					 _In_opt_ PVOID Object )
  {
	  LARGE_INTEGER largeCreateTime;
	  largeCreateTime.QuadPart = CreateTime;

	  ProcessGUID = GenerateUniqueId( &largeCreateTime, ProcessKey, Process );
	  memset( &EventHeaderLocal, 0, sizeof( EventHeaderLocal ) );
	  EventHeaderLocal.m_EventSize = sizeof( EventHeaderLocal );
	  EventHeaderLocal.m_EventType = ProcessCreate;
	  auto& proc = EventHeaderLocal.m_EventBody.m_ProcessCreateEvent;
	  proc.m_CreateTime = largeCreateTime;
	  proc.m_ProcessId = Pid;
	  proc.m_ProcessObject = Object;
	  EventHeader = &EventHeaderLocal;
  }

  ProcessCacheEntry( const ProcessCacheEntry& entry ) {
	  memcpy( &ProcessGUID, &entry.ProcessGUID, sizeof( ProcessGUID ) );
	  memcpy( &EventHeaderLocal, &entry.EventHeaderLocal, sizeof( EventHeaderLocal ) );
	  if( &entry.EventHeaderLocal != entry.EventHeader ) {
		  EventHeader = (PSYSMON_EVENT_HEADER)malloc( entry.EventHeader->m_EventSize );
		  memcpy( EventHeader, entry.EventHeader, entry.EventHeader->m_EventSize );
	  } else {
		  EventHeader = &EventHeaderLocal;
	  }
  }

  ~ProcessCacheEntry() {
	  if( EventHeader != &EventHeaderLocal ) {
		  free( EventHeader );
		  EventHeader = nullptr;
	  }
  }

  void AddExtension( ULONG Id, PVOID buffer, ULONG size )
  {
	  PSYSMON_EVENT_HEADER prev = EventHeader;

	  ULONG eventSize = prev->m_EventSize + size;
	  PSYSMON_EVENT_HEADER newEventHeader = (PSYSMON_EVENT_HEADER)malloc( eventSize );
	  memcpy( newEventHeader, prev, prev->m_EventSize );
	  memcpy( &newEventHeader->m_EventBody.m_ProcessCreateEvent + 1, buffer, size );
	  newEventHeader->m_EventBody.m_ProcessCreateEvent.m_Extensions[Id] = size;
	  newEventHeader->m_EventSize = eventSize;
	  EventHeader = newEventHeader;

	  if( prev != &EventHeaderLocal ) {
		  free( prev );
	  }
  }

  void AddToCache()
  {
	  ProcessAddToCache( ProcessGUID, EventHeader );
  }

  void RemoveFromCache()
  {
	  auto& proc = EventHeader->m_EventBody.m_ProcessCreateEvent;
	  ProcessRemoveFromCache( proc.m_ProcessId, &ProcessGUID, &proc.m_CreateTime );
  }

  PPROCESS_CACHE_INFORMATION GetFromCache() const
  {
	  auto& proc = EventHeader->m_EventBody.m_ProcessCreateEvent;
	  const PLARGE_INTEGER time = proc.m_CreateTime.QuadPart ? const_cast<PLARGE_INTEGER>( &proc.m_CreateTime ) : nullptr;
	  return ProcessGetCache( proc.m_ProcessId, time, proc.m_ProcessObject );
  }

  GUID ProcessGUID;
  PSYSMON_EVENT_HEADER EventHeader;

private:
  SYSMON_EVENT_HEADER EventHeaderLocal;
};

typedef struct _PROCESSCACHE_FETCH_TEST {
    // Description of the test.
    PCSTR Description;

    // Entries to add to the cache.
	std::vector<ProcessCacheEntry> Input;

    // Entries to check in the cache.
	std::vector<ProcessCacheEntry> Exists;

    // Entries not in the cache.
	std::vector<ProcessCacheEntry> Miss;
} PROCESSCACHE_FETCH_TEST;

class FieldData {
public:
  FieldData( NativeTypes inputType, const PTCHAR input )
  {
	  ULONG inputSize = (ULONG)( _tcslen( input ) + 1 ) * sizeof( TCHAR );
	  Initialize( inputType, input, inputSize );
  }

  FieldData( NativeTypes inputType, ULONG64 input, ULONG inputSize )
  {
	  Initialize( inputType, &input, inputSize );
  }

  FieldData()
  {
	  Initialize( N_Invalid, nullptr, 0 );
  }

  void Initialize( NativeTypes inputType, const PVOID input, ULONG inputSize )
  {
	  Type = inputType;
	  Size = inputSize;
	  Data = malloc( inputSize );
	  memcpy( Data, input, inputSize );
  }

  ~FieldData()
  {
	  free( Data );
  }

  NativeTypes Type;
  PVOID Data;
  ULONG Size;
};

class FieldInputData : public FieldData
{
public:
  FieldInputData( NativeTypes inputType, const PTCHAR input )
	  : FieldData( inputType, input ) {}

  FieldInputData( NativeTypes inputType, const PTCHAR input, ULONG inputSize )
	  : FieldData( inputType, input )
  {
	  Size = inputSize;
  }

  FieldInputData( NativeTypes inputType, ULONG64 input, ULONG inputSize )
	  : FieldData( inputType, input, inputSize ) {}

#if defined _WIN64 || defined _WIN32
  FieldInputData( PSID input )
  {
	  Initialize( N_Sid, input, GetLengthSid( input ) );
  }
#endif

  void SetSysmonDataDescriptor( PSYSMON_DATA_DESCRIPTOR desc )
  {
	  memset( desc, 0, sizeof( *desc ) );
	  desc->Type = Type;
	  desc->Allocated = FALSE;
	  desc->Ptr = Data;
	  desc->Size = Size;
  }
};

class FieldOutputData : public FieldData
{
public:
  FieldOutputData( const PTCHAR input )
	  : FieldData( N_Invalid, input ), Status(0) {}

  FieldOutputData( ULONG64 input, ULONG inputSize )
	  : FieldData( N_Invalid, input, inputSize ), Status(0) {}

  FieldOutputData( LONG error ) : Status((DWORD)error) {}

  void SetEventDataDescriptor( PEVENT_DATA_DESCRIPTOR desc )
  {
	  memset( desc, 0, sizeof( *desc ) );
	  desc->Ptr = (ULONGLONG)Data;
	  desc->Size = Size;
  }

  DWORD Status;
};

typedef struct _FIELDS_RESOLUTION_INPUT
{
    // Type of the events, influence output.
    PSYSMON_EVENT_TYPE_FMT Type;

    // Index of the field to resolve.
    ULONG FieldIndex;

    // Input data used for field resolution.
    FieldInputData Data;

    // Force string output
    bool StringOutput;
} FIELDS_RESOLUTION_INPUT;

typedef struct _FIELDS_RESOLUTION_TEST {
    // Description of the test.
    PCSTR Description;

    // Data used as input for field resolution.
    FIELDS_RESOLUTION_INPUT Input;

    // Data set in the output buffer.
    FieldOutputData Output;
} FIELDS_RESOLUTION_TEST;

typedef struct {
    PCTSTR Str;
    BOOL  Result;
} FieldSizesTest;

typedef struct {
    PCTSTR Field;
    ULONG Size;
} TestFieldSize;

