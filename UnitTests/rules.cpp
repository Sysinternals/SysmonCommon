// UnitTests for rule engine and configuration parsing.
#include "test.h"

#if defined _WIN64 || defined _WIN32
#include <shlwapi.h>
#elif defined __linux__
#include <glob.h>
#endif
#include <string>
#include <vector>
#include <algorithm>

#include "structs.h"
#include "../../sysmonCommon/eventsCommon.h"

using ::testing::_;
using ::testing::Expectation;
using ::testing::Invoke;
using ::testing::AnyNumber;

#if defined _WIN64 || defined _WIN32
const TCHAR testPathRelative[] = _T( "..\\testdata\\" );
#elif defined __linux__
const TCHAR testPathRelative[] = _T( "testdata/" );
#endif


void hexdump( UCHAR* x, size_t n );

// The version used to test by default.
const PCSTR testDefaultVersion = "4.50";

BYTE oneByte[] = { 0xAA };
RULE_REG zeroRules = {};
RULE_REG oldRule = {
    0, /*Version*/
    1, /*RuleCount*/
};

// EmptyBlob verifies an empty or undefined rule blob result in empty rule reg and context.
TEST( Rules, EmptyBlob )
{
    InitializeRules();

    // SetRuleBlob should not add any rule of size zero or pointer NULL.
    RULE_BLOB blobs[] = {
        { "NULL and zero", NULL, 0 },
        { "Non-NULL and zero", (PVOID)1, 0 },
        { "NULL and 100", NULL, 100 },
    };

    for( const auto& blob : blobs ) {
        SCOPED_TRACE( blob.Description );

        ASSERT_TRUE( SetRuleBlob( blob.Rules, blob.RulesSize, FALSE ) );

        RULE_REG rulReg;
        EXPECT_FALSE( GetRuleRegInformation( NULL, &rulReg ) );

        RULE_CONTEXT ruleContext;
        EXPECT_FALSE( InitializeRuleContext( &ruleContext ) );
    }
}

// InvalidRules try to set invalid rules resulting in SetRuleBlob failing an no rule to be registered.
TEST( Rules, InvalidRules )
{
    InitializeRules();

    RULE_BLOB blobs[] = {
        { "Small one-byte rule", oneByte, sizeof( oneByte ) },
        { "No rules attached", &zeroRules, sizeof( zeroRules ) },
        { "Old versions rules", &oldRule, sizeof( oldRule ) },
    };

    for( const auto& blob : blobs ) {
        SCOPED_TRACE( blob.Description );

        ASSERT_FALSE( SetRuleBlob( blob.Rules, blob.RulesSize, FALSE ) );

        RULE_REG ruleReg;
        EXPECT_FALSE( GetRuleRegInformation( NULL, &ruleReg ) );

        RULE_CONTEXT ruleContext;
        EXPECT_FALSE( InitializeRuleContext( &ruleContext ) );
    }
}

#if defined __linux__
void GetModuleFileName( PVOID hModule, LPSTR lpFilename, DWORD nSize )
{
    ssize_t num = readlink( "/proc/self/exe", lpFilename, nSize );
    lpFilename[num] = 0;
}

PCHAR PathCombine( LPTSTR pszDest, LPCTSTR pszDir, LPCTSTR pszFile )
{
    strcpy( pszDest, pszDir );
    PTCHAR lastSlash = strrchr( pszDest, '/' );
    if( lastSlash == NULL ) {
        lastSlash = pszDest - 1;
    }
    strcpy( lastSlash + 1, pszFile );
    return pszDest;
}
#endif

// ListXMLConfigurations returns a vector of file path to Sysmon XML configurations.
BOOL ListXMLConfigurations( std::vector<tstring>& files )
{
    TCHAR szFileName[MAX_PATH + 1];
    GetModuleFileName( NULL, szFileName, MAX_PATH + 1 );

    TCHAR testPath[MAX_PATH] = {};
	if( PathCombine( testPath, szFileName, testPathRelative ) == NULL ) {
		_tprintf( _T( "PathCombine(%s, %s) failed." ), szFileName, testPathRelative );
        return FALSE;
	}

	tstring pattern( testPath );
    pattern += _T( "*.xml" );
#if defined _WIN64 || defined _WIN32
    WIN32_FIND_DATA ffd;
    HANDLE hFind = FindFirstFile( pattern.c_str(), &ffd );
    if( INVALID_HANDLE_VALUE == hFind ) {
        _tprintf( _T( "FindFirstFile(%s) failed." ), pattern.c_str() );
        return FALSE;
    }

    do {
        if( ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
            continue;

        tstring fullPath( testPath );
        fullPath += ffd.cFileName;
        files.push_back( fullPath );
    } while( FindNextFile( hFind, &ffd ) != 0 );
#elif defined __linux__
    glob_t ffd;
    if( glob( pattern.c_str(), 0, NULL, &ffd ) != 0 ) {
        _tprintf( _T( "glob(%s) failed." ), pattern.c_str() );
        return FALSE;
    }

    for( unsigned int i = 0; i < ffd.gl_pathc; i++ ) {
        struct stat path_stat;
        stat( ffd.gl_pathv[i], &path_stat );
        if( !S_ISREG( path_stat.st_mode ) ) {
            continue;
        }
        tstring fullPath( ffd.gl_pathv[i] );
        files.push_back( fullPath );
    }
    globfree( &ffd );
#endif

    return TRUE;
}

extern PRULE_SET g_blob;
#define RULE_BINARY_CHANGE "Rule binary blob changed, if expected re-generate the file using instructions in /doc/internal/testing-switches.md"

// LoadConfiguration reads Sysmon XML configuration, checks no error is reported and ruleset match expected output.
TEST( Rules, LoadConfiguration )
{
    std::vector<tstring> xmlFiles;
    ASSERT_TRUE( ListXMLConfigurations( xmlFiles ) );

    for( const auto& file : xmlFiles ) {
        // Scope to the current file to identify a failure more easily.
        SCOPED_TRACE( tstring2string( file ) );

        PVOID Rules = NULL;
        ULONG RulesSize = 0;
        ASSERT_TRUE( ApplyConfigurationFile( const_cast<PTCHAR>(file.c_str()), &Rules, &RulesSize, FALSE ) );
        EXPECT_NE( Rules, nullptr );
        EXPECT_NE( RulesSize, 0u );

        // The rule returned was assigned to the current context.
        RULE_CONTEXT ctx;
        ASSERT_TRUE( InitializeRuleContext( &ctx ) );
        ASSERT_NE( ctx.Current, nullptr );
        EXPECT_EQ( ctx.Current->Rules, Rules );
        EXPECT_EQ( ctx.Current->RulesSize, RulesSize );
        ReleaseRuleContext( &ctx );

        // Compare the dumped test binary representation with the parse XML result.
        std::vector<CHAR> ruleData;
        ASSERT_TRUE( ReadBinaryFile( file + _T( ".bin" ), ruleData ) );
        ASSERT_EQ( RulesSize, ruleData.size() ) << RULE_BINARY_CHANGE;

        // The binary version will change and should not be part of the test.
        ASSERT_GE( RulesSize, sizeof( ULONG ) ) << "The rule size is smaller than the version field";
        EXPECT_EQ( 0, memcmp( (PCHAR)Rules + sizeof( ULONG ), &ruleData[sizeof( ULONG )], RulesSize - sizeof( ULONG ) ) ) << RULE_BINARY_CHANGE;
    }
}

// DetectEncoding reads Sysmon XML configuration, checks no error is reported and encoding reported correctly.
TEST( Rules, DetectEncoding )
{
    ENCODING FileEncodings[] = {
        { _T( "iso8859-nobom-iso8859enc.xml" ),		"ISO-8859-1",	false,	false },
        { _T( "iso8859-utf8bom-iso8859enc.xml" ),	"ISO-8859-1",	false,	true },
        { _T( "utf16-nobom-noenc-ws.xml" ),			"UTF-16LE",		true,	false },
        { _T( "utf16-nobom-noenc.xml" ),			"UTF-16LE",		true,	false },
        { _T( "utf16-nobom-utf16enc.xml" ),			"UTF-16LE",		true,	false },
        { _T( "utf16-utf16bom-noenc-ws.xml" ),		"",				true,	true },
        { _T( "utf16-utf16bom-noenc.xml" ),			"",				true,	true },
        { _T( "utf16-utf16bom-utf16enc.xml" ),		"UTF-16LE",		true,	true },
        { _T( "utf8-nobom-noenc-ws.xml" ),			"",				false,	false },
        { _T( "utf8-nobom-noenc.xml" ),				"",				false,	false },
        { _T( "utf8-nobom-utf8enc.xml" ),			"UTF-8",		false,	false },
        { _T( "utf8-utf8bom-noenc.xml" ),			"",				false,	true },
        { _T( "utf8-utf8bom-utf8enc.xml" ),			"UTF-8",		false,	true }
    };

    ULONG version;
    PCHAR encoding;
    BOOLEAN is16Bit;
    BOOLEAN hasBOM;
    TCHAR szFileName[MAX_PATH + 1];

    GetModuleFileName( NULL, szFileName, MAX_PATH + 1 );
    TCHAR testPath[MAX_PATH] = {};
    ASSERT_TRUE( PathCombine( testPath, szFileName, testPathRelative ) != NULL );

    for( auto& fileEncoding : FileEncodings ) {
        tstring fileName( testPath );
        fileName += fileEncoding.FileName;

        ASSERT_TRUE( FetchConfigurationVersion( (PTCHAR)fileName.c_str(), &version, &encoding, &is16Bit, &hasBOM ) );
        if( encoding != NULL ) {
            EXPECT_EQ( 0, strcmp( fileEncoding.XMLEncoding, encoding ) );
        } else {
            EXPECT_EQ( 0, strcmp( fileEncoding.XMLEncoding, "" ) );
        }
        EXPECT_EQ( fileEncoding.Is16Bit, is16Bit );
        EXPECT_EQ( fileEncoding.HasBOM, hasBOM );
    }
}

#if defined _WIN64 && defined _WIN32
EnvSolver systemrootVar( "%SystemRoot%\\notepad.exe" );
EnvSolver appDataVar( "%AppData%\\file.log" );
#endif

//
// This test relies on events.cpp and this has not yet been ported to Linux
//
RULE_FILTER_TEST ruleMatches[] = {
    {
        "Includes all by default",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "exclude", RuleEntry::Empty ) ) ),
        {
            {
                "No field set is included",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {},
                Rule_include, _T( "" ),
            },
            {
                "One field set is included",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "svchost.exe" ) } },
                Rule_include, _T( "" ),
            },
        },
    },
    {
        "Includes all by default on a default exclude",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "RawAccessRead", "onmatch", "exclude", RuleEntry::Empty ) ) ),
        {
            {
                "No field set is included",
                &SYSMONEVENT_RAWACCESS_READ_Type,
                {},
                Rule_include, _T( "" ),
            },
            {
                "One field set is included",
                &SYSMONEVENT_RAWACCESS_READ_Type,
                { { F_RR_Image, _T( "svchost.exe" ) } },
                Rule_include, _T( "" ),
            },
        },
    },
    {
        "No rules means the default is applicable",
        SysmonRule( testDefaultVersion, RuleEntry::Empty ),
        {
            {
                "Process create is include by default",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {},
                Rule_include, _T( "" ),
            },
            {
                "Raw access read is exclude by default",
                &SYSMONEVENT_RAWACCESS_READ_Type,
                {},
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Exclude all by default",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include", RuleEntry::Empty ) ) ),
        {
            {
                "No field set is excluded",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {},
                Rule_exclude, _T( "" ),
            },
            {
                "One field set is excluded",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "svchost.exe" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Process command-line contains string",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "RuleGroup", "internet-explorer", "groupRelation", "and",
                    RuleEntry( "ProcessCreate", "onmatch", "include",
                        RuleEntry( "CommandLine", "condition", "contains",
                            RuleEntry( "iexplore.exe" ) ) ) ) ) ),
        {
            {
                "Field without any include rule",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_Image, _T( "iexplore.exe" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Field with an incorrect value",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "svchost.exe" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Field is equal",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "iexplore.exe" ) } },
                Rule_include, _T( "internet-explorer" ),
            },
            {
                "Field is part of the path",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "c:\\iexplore.exe\\something" ) } },
                Rule_include, _T( "internet-explorer" ),
            },
        },
    },
    {
        "Process command-line multiple contains string",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "RuleGroup", "internet-explorer second", "groupRelation", "or",
                    RuleEntry( "ProcessCreate", "onmatch", "include",
                        RuleEntry( "CommandLine", "condition", "contains",
                            RuleEntry( "iexplore.exe" ) ),
                        RuleEntry( "CommandLine", "condition", "contains",
                            RuleEntry( "notepad.exe" ) ) ) ) ) ),
        {
            {
                "Field without any include rule",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_Image, _T( "iexplore.exe" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Field with an incorrect value",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "svchost.exe" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Field is equal to first",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "iexplore.exe" ) } },
                Rule_include, _T( "internet-explorer second" ),
            },
            {
                "Field is part of the path for first",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "\\SMB\\iexplore.exe\\something" ) } },
                Rule_include, _T( "internet-explorer second" ),
            },
            {
                "Field is equal to second",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "notepad.exe" ) } },
                Rule_include, _T( "internet-explorer second" ),
            },
            {
                "Field is part of the path for second",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "z:\\notepad.exe\\something" ) } },
                Rule_include, _T( "internet-explorer second" ),
            },

        },
    },
    {
        "Process command-line multiple contains string but exclude",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "RuleGroup", "internet-explorer second", "groupRelation", "or",
                    RuleEntry( "ProcessCreate", "onmatch", "exclude",
                        RuleEntry( "CommandLine", "condition", "contains",
                            RuleEntry( "iexplore.exe" ) ),
                        RuleEntry( "CommandLine", "condition", "contains",
                            RuleEntry( "notepad.exe" ) ) ) ) ) ),
        {
            {
                "Field without any exclude rule",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_Image, _T( "iexplore.exe" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Field with an incorrect value",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "svchost.exe" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Field is equal to first",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "iexplore.exe" ) } },
                Rule_exclude, _T( "internet-explorer second" ),
            },
            {
                "Field is part of the path for first",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "\\SMB\\iexplore.exe\\something" ) } },
                Rule_exclude, _T( "internet-explorer second" ),
            },
            {
                "Field is equal to second",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "notepad.exe" ) } },
                Rule_exclude, _T( "internet-explorer second" ),
            },
            {
                "Field is part of the path for second",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "z:\\notepad.exe\\something" ) } },
                Rule_exclude, _T( "internet-explorer second" ),
            },

        },
    },
    {
        "Check 4.1 configuration default to OR groups",
        SysmonRule( "4.1",
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "Image", "condition", "is",
                        RuleEntry( "iexplore.exe" ) ),
                    RuleEntry( "CommandLine", "condition", "is",
                        RuleEntry( "notepad.exe" ) ) ) ) ),
        {
            {
                "First field equal is a match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_Image, _T( "iexplore.exe" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Second field contains is a match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "notepad.exe" ) } },
                Rule_include, _T( "" ),
            },
        },
    },
    {
        "Check 4.21 configuration default to AND groups",
        SysmonRule( "4.21",
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "Image", "condition", "is",
                        RuleEntry( "iexplore.exe" ) ),
                    RuleEntry( "CommandLine", "condition", "is",
                        RuleEntry( "notepad.exe" ) ) ) ) ),
        {
            {
                "First field equal is not a match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_Image, _T( "iexplore.exe" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Second field contains is not a match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "notepad.exe" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Boths fields leads to a match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "iexplore.exe" ) },
                    { F_CP_CommandLine, _T( "notepad.exe" ) }
                },
                Rule_include, _T( "" ),
            },
        },
    },
    {
        "Check 'is' condition",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "is",
                        RuleEntry( "/Something:Equal" ) ) ) ) ),
        {
            {
                "Exact match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Something:Equal" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Check match is case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/someThing:equaL" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Check no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/something:else" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Check 'is any' condition",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "is any",
                        RuleEntry( "/Something:Equal;OrElse" ) ) ) ) ),
        {
            {
                "Exact match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Something:Equal" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Check match is case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/sOmething:eqUal" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Exact match on second",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "OrElse" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Check match on second is case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "oReLse" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Check no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/something:else" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Check 'is not' condition",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "is not",
                        RuleEntry( "/Something:Equal" ) ) ) ) ),
        {
            {
                "Exact match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Something:Equal" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Check match is case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/soMething:equAl" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Check no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/something:else" ) } },
                Rule_include, _T( "" ),
            },
        },
    },
    {
        "Check 'contains' condition",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "contains",
                        RuleEntry( "/Something:Equal" ) ) ) ) ),
        {
            {
                "Contains match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Flag1 /Something:Equal /Flag2" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Check contains match is case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Flag1 /somEThing:eqUal /Flag2" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Exact match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Something:Equal" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Check exact match is case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/sOMething:equAl" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Check no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/something:else" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Check 'contains any' condition",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "contains any",
                        RuleEntry( "/Something:Equal;OrElse" ) ) ) ) ),
        {
            {
                "Contains match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Flag1 /Something:Equal /Flag2" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Check match is case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Flag1 /sometHInG:eQual /Flag2" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Contains match on second",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Flag3 OrElse /Flag4" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Check match on second is case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Anotherlfag orELse /Something" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Exact match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Something:Equal" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Check exect match is case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/something:equal" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Exact match on second",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "OrElse" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Check exact match on second is case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "orelSE" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Check no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/something:else" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Check 'contains all' condition",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "contains all",
                        RuleEntry( "/Something:Equal;OrElse" ) ) ) ) ),
        {
            {
                "Only firt",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Flag1 /Something:Equal /Flag5" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Only second",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/FlagP OrElse /FlagC" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Only firt exact",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Something:Equal" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Only second exact",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "OrElse" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Match all",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Flag1 /Something:Equal /Flag2 OrElse /Something" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Match all case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Flag1 /something:equal /Flag2 ORelse /Something" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Check zero match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/something:else" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Check 'excludes' condition",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "excludes",
                        RuleEntry( "/Something:Equal" ) ) ) ) ),
        {
            {
                "Excludes match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Flag1 /Something:Equal /Flag2" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Check excludes match is case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Flag1 /someThiNG:equal /Flag2" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Exact match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Something:Equal" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Check exact match is case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/SOmeTHing:eQUal" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Check no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/something:else" ) } },
                Rule_include, _T( "" ),
            },
        },
    },
    {
        "Check 'excludes any' condition",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "excludes any",
                        RuleEntry( "/Something:Equal;OrElse" ) ) ) ) ),
        {
            {
                "Excludes match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Flag1 /Something:Equal /Flag2" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Check match is case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Flag1 /sometHIng:EQual /Flag2" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Excludes match on second",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Flag3 OrElse /Flag4" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Check match on second is case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Anotherlfag oreLSe /Something" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Exact match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Something:Equal" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Check exact match is case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/soMEThing:eqUAl" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Exact match on second",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "OrElse" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Check exact match on second is case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "orelSE" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Check no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/something:else" ) } },
                Rule_include, _T( "" ),
            },
        },
    },
    {
        "Check 'excludes all' condition",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "excludes all",
                        RuleEntry( "/Something:Equal;OrElse" ) ) ) ) ),
        {
            {
                "Only firt",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Flag1 /Something:Equal /Flag5" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Only second",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/FlagP OrElse /FlagC" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Only firt exact",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Something:Equal" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Only second exact",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "OrElse" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Match all",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Flag1 /Something:Equal /Flag2 OrElse /Something" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Match all case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/Flag1 /somethinG:equal /Flag2 orElse /Something" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Check zero match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/something:else" ) } },
                Rule_include, _T( "" ),
            },
        },
    },
    {
        "Check 'begin with' condition",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "begin with",
                        RuleEntry( "TheFirstString" ) ) ) ) ),
        {
            {
                "Equal",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "TheFirstString" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Begin with",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "TheFirstString and something else" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Shorter",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "TheFirstStrin" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Ends with",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "There was something before TheFirstString" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Middle",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "Before TheFirstString After" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Different",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "Another string" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Check 'end with' condition",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "end with",
                        RuleEntry( "TheLastString" ) ) ) ) ),
        {
            {
                "Equal",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "TheLastString" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Begin with",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "TheLastString and something else" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Shorter",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "TheLastStrin" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Ends with",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "There was something before TheLastString" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Middle",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "Before TheLastString After" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Different",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "Another string" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Check 'less than' condition",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "less than",
                        RuleEntry( "TargetString" ) ) ) ) ),
        {
            {
                "Less than",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "TargetStrinf" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Less than, case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "tarGeTstrinF" ) } },
                Rule_include, _T( "" ),
            },
            {
                "More than",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "TargetStrinh" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "More than, case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "tArgeTStringH" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Equal",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "TargetString" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Check 'more than' condition",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "more than",
                        RuleEntry( "TargetString" ) ) ) ) ),
        {
            {
                "Less than",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "TargetStrinf" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Less than, case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "targetstrINF" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "More than",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "TargetStrinh" ) } },
                Rule_include, _T( "" ),
            },
            {
                "More than, case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "tARGetstringH" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Equal",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "TargetString" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Check 'image' load for notepad.exe but except images from System32",
        SysmonRule( "4.5",
            RuleEntry( "EventFiltering",
                RuleEntry( "ImageLoad", "onmatch", "include",
                    RuleEntry( "Image", "condition", "is", RuleEntry( "notepad.exe" ) ),
                    RuleEntry( "Image", "condition", "is", RuleEntry( "conhost.exe" ) )
                ),
                RuleEntry( "ImageLoad", "onmatch", "exclude",
                    RuleEntry( "Rule", "groupRelation", "and",
                        RuleEntry( "Image", "condition", "is", RuleEntry( "notepad.exe" ) ),
                        RuleEntry( "ImageLoaded", "condition", "contains", RuleEntry( "C:\\Windows\\System32" ) )
                    )
                )
            )
        ),
        {
            {
                "Exclude notepad.exe with System32 dll",
                &SYSMONEVENT_IMAGE_LOAD_Type,
                {
                    { F_IL_Image, _T( "notepad.exe" ) },
                    { F_IL_ImageLoaded, _T( "C:\\Windows\\System32\\user32.dll" ) }
                },
                Rule_exclude, _T( "" )
            },
            {
                "Include notepad.exe with some dll",
                &SYSMONEVENT_IMAGE_LOAD_Type,
                {
                    { F_IL_Image, _T( "notepad.exe" ) },
                    { F_IL_ImageLoaded, _T( "C:\\test\\test.dll" ) }
                },
                Rule_include, _T( "" )
            },
            {
                "Include conhost.exe with System32 dll",
                &SYSMONEVENT_IMAGE_LOAD_Type,
                {
                    { F_IL_Image, _T( "conhost.exe" ) },
                    { F_IL_ImageLoaded, _T( "C:\\Windows\\System32\\user32.dll" ) }
                },
                Rule_include, _T( "" )
            },
            {
                "Include conhost.exe with some dll",
                &SYSMONEVENT_IMAGE_LOAD_Type,
                {
                    { F_IL_Image, _T( "conhost.exe" ) },
                    { F_IL_ImageLoaded, _T( "C:\\test\\test.dll" ) }
                },
                Rule_include, _T( "" )
            },
            {
                "Don't include cmd.exe with System32 dll",
                &SYSMONEVENT_IMAGE_LOAD_Type,
                {
                    { F_IL_Image, _T( "cmd.exe" ) },
                    { F_IL_ImageLoaded, _T( "C:\\Windows\\System32\\user32.dll" ) }
                },
                Rule_exclude, _T( "" )
            },
            {
                "Don't include cmd.exe with some dll",
                &SYSMONEVENT_IMAGE_LOAD_Type,
                {
                    { F_IL_Image, _T( "cmd.exe" ) },
                    { F_IL_ImageLoaded, _T( "C:\\test\\test.dll" ) }
                },
                Rule_exclude, _T( "" )
            }
        }
    },
    {
        "Check 'image' load for notepad.exe but except images from System32 with company 'TestCompany'",
        SysmonRule( "4.5",
            RuleEntry( "EventFiltering",
                RuleEntry( "ImageLoad", "onmatch", "include",
                    RuleEntry( "Image", "condition", "is", RuleEntry( "notepad.exe" ) )
                ),
                RuleEntry( "ImageLoad", "onmatch", "exclude",
                    RuleEntry( "Rule", "groupRelation", "and",
                        RuleEntry( "Image", "condition", "is", RuleEntry( "notepad.exe" ) ),
                        RuleEntry( "ImageLoaded", "condition", "contains", RuleEntry( "C:\\Windows\\System32" ) ),
                        RuleEntry( "Company", "condition", "is", RuleEntry( "TestCompany" ) )
                    )
                )
            )
        ),
        {
            {
                "Include notepad.exe with System32 dll and no company",
                &SYSMONEVENT_IMAGE_LOAD_Type,
                {
                    { F_IL_Image, _T( "notepad.exe" ) },
                    { F_IL_ImageLoaded, _T( "C:\\Windows\\System32\\user32.dll" ) }
                },
                Rule_include, _T( "" )
            },
            {
                "Include notepad.exe with System32 dll and company 'Company'",
                &SYSMONEVENT_IMAGE_LOAD_Type,
                {
                    { F_IL_Image, _T( "notepad.exe" ) },
                    { F_IL_ImageLoaded, _T( "C:\\Windows\\System32\\user32.dll" ) },
                    { F_IL_Company, _T( "Company" ) }
                },
                Rule_include, _T( "" )
            },
            {
                "Exclude notepad.exe with System32 dll and company 'TestCompany'",
                &SYSMONEVENT_IMAGE_LOAD_Type,
                {
                    { F_IL_Image, _T( "notepad.exe" ) },
                    { F_IL_ImageLoaded, _T( "C:\\Windows\\System32\\user32.dll" ) },
                    { F_IL_Company, _T( "TestCompany" ) }
                },
                Rule_exclude, _T( "" )
            }
        }
    },
    {
        "Check 'image' load for notepad.exe but only for a.dll and b.dll, not for c.dll",
        SysmonRule( "4.5",
            RuleEntry( "EventFiltering",
                RuleEntry( "RuleGroup", "groupRelation", "or",
                    RuleEntry( "ImageLoad", "onmatch", "include",
                        RuleEntry( "Rule", "groupRelation", "and",
                            RuleEntry( "Image", "condition", "is", RuleEntry( "notepad.exe" ) ),
                            RuleEntry( "ImageLoaded", "condition", "contains", RuleEntry( "a.dll" ) )
                        ),
                        RuleEntry( "Rule", "groupRelation", "and",
                            RuleEntry( "Image", "condition", "is", RuleEntry( "notepad.exe" ) ),
                            RuleEntry( "ImageLoaded", "condition", "contains", RuleEntry( "b.dll" ) )
                        )
                    )
                )
            )
        ),
        {
            {
                "Include notepad.exe with a.dll",
                &SYSMONEVENT_IMAGE_LOAD_Type,
                {
                    { F_IL_Image, _T( "notepad.exe" ) },
                    { F_IL_ImageLoaded, _T( "C:\\test\\a.dll" ) }
                },
                Rule_include, _T( "" )
            },
            {
                "Include notepad.exe with b.dll",
                &SYSMONEVENT_IMAGE_LOAD_Type,
                {
                    { F_IL_Image, _T( "notepad.exe" ) },
                    { F_IL_ImageLoaded, _T( "C:\\test\\b.dll" ) }
                },
                Rule_include, _T( "" )
            },
            {
                "Exclude notepad.exe with c.dll",
                &SYSMONEVENT_IMAGE_LOAD_Type,
                {
                    { F_IL_Image, _T( "notepad.exe" ) },
                    { F_IL_ImageLoaded, _T( "C:\\test\\c.dll" ) }
                },
                Rule_exclude, _T( "" )
            }
        }
    },
    {
        "Check 'image' load with redundant rules",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "RuleGroup", "groupRelation", "or",
                    RuleEntry( "ImageLoad", "onmatch", "include",
                        RuleEntry( "Rule", "groupRelation", "and",
                            RuleEntry( "Image", "condition", "is", RuleEntry( "notepad.exe" ) ),
                            RuleEntry( "ImageLoaded", "condition", "contains", RuleEntry( "a.dll" ) )
                        ),
                        RuleEntry( "ImageLoaded", "condition", "contains", RuleEntry( "a.dll" ) )
                    )
                )
            )
        ),
        {
            {
                "Include conhost.exe",
                &SYSMONEVENT_IMAGE_LOAD_Type,
                {
                    { F_IL_Image, _T( "conhost.exe" ) },
                    { F_IL_ImageLoaded, _T( "C:\\test\\a.dll" ) }
                },
                Rule_include, _T( "" )
            },
            {
                "Also include notepad.exe",
                &SYSMONEVENT_IMAGE_LOAD_Type,
                {
                    { F_IL_Image, _T( "notepad.exe" ) },
                    { F_IL_ImageLoaded, _T( "C:\\test\\a.dll" ) }
                },
                Rule_include, _T( "" )
            },
        }
    },
    {
        "Check 'image' condition",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "image",
                        RuleEntry( "Svchost.Exe" ) ) ) ) ),
        {
            {
                "Equal",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "Svchost.Exe" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Equal case insensitive",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "sVchost.eXe" ) } },
                Rule_include, _T( "" ),
            },
            {
                "normal path",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "c:\\Windows\\System32\\svchost.exe" ) } },
                Rule_include, _T( "" ),
            },
            {
                "SMB path",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "\\ANOTHERMACHINE\\Windows\\System32\\svchost.exe" ) } },
                Rule_include, _T( "" ),
            },
            {
                "NT path",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "\\??\\Drive0\\Windows\\System32\\svchost.exe" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Relative path",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "..\\System32\\svchost.exe" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Different path",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "D:\\Windows\\System32\\lsass.exe" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Different dir path",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "D:\\Windows\\System32\\" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Different dir path with dirname matching",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "c:\\Windows\\System32\\svchost.exe\\" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Not a path",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "Just a sentence" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
#if defined _WIN64 && defined _WIN32
// These rules test environment variables - not implemented on Linux
    {
        "Check 'is' condition for system variable",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "is",
                        RuleEntry( systemrootVar.input ) ) ) ) ),
        {
            {
                "Exact match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, systemrootVar.expanded.c_str() } },
                Rule_include, _T( "" ),
            },
            {
                "Upper match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, systemrootVar.expandedUpper.c_str() } },
                Rule_include, _T( "" ),
            },
            {
                "Check no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/something:else" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Check 'contains' condition for system variable",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "contains",
                        RuleEntry( systemrootVar.input ) ) ) ) ),
        {
            {
                "Exact match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, systemrootVar.expanded.c_str() } },
                Rule_include, _T( "" ),
            },
            {
                "Upper match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, systemrootVar.expandedUpper.c_str() } },
                Rule_include, _T( "" ),
            },
            {
                "Check no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/something:else" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Check 'is' condition for user variable",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "is",
                        RuleEntry( appDataVar.input ) ) ) ) ),
        {
            {
                "Exact match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, appDataVar.expanded.c_str() } },
                Rule_include, _T( "" ),
            },
            {
                "Upper match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, appDataVar.expandedUpper.c_str() } },
                Rule_include, _T( "" ),
            },
            {
                "Check no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/something:else" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Check 'contains' condition for user variable",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "contains",
                        RuleEntry( appDataVar.input ) ) ) ) ),
        {
            {
                "Exact match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, appDataVar.expanded.c_str() } },
                Rule_include, _T( "" ),
            },
            {
                "Upper match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, appDataVar.expandedUpper.c_str() } },
                Rule_include, _T( "" ),
            },
            {
                "Check no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/something:else" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
#endif
    {
        "Check 'is any' on empty string",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "is any",
                        RuleEntry( "" ) ) ) ) ),
        {
            {
                "Check no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/something:else" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Check 'is any' on multiple empty strings",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "is any",
                        RuleEntry( ";;;;;;;" ) ) ) ) ),
        {
            {
                "Check no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/something:else" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Rulegroup AND on same field",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "RuleGroup", "internet-explorer", "groupRelation", "and",
                    RuleEntry( "ProcessCreate", "onmatch", "include",
                        RuleEntry( "CommandLine", "condition", "contains",
                            RuleEntry( "iexplore.exe" ) ),
                        RuleEntry( "CommandLine", "condition", "contains",
                            RuleEntry( "Windows" ) ) ) ) ) ),
        {
            {
                "Field without any include rule",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_Image, _T( "iexplore.exe" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Field with only one value",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "iexplore.exe" ) } },
                Rule_include, _T( "internet-explorer" ),
            },
            {
                "Field with all match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "c:\\windows\\iexplore.exe" ) } },
                Rule_include, _T( "internet-explorer" ),
            },
        },
    },
    {
        "Rulegroup OR on different fields",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "RuleGroup", "procmatch", "groupRelation", "or",
                    RuleEntry( "ProcessCreate", "onmatch", "include",
                        RuleEntry( "Image", "condition", "is",
                            RuleEntry( "iexplore.exe" ) ),
                        RuleEntry( "CommandLine", "condition", "is",
                            RuleEntry( "notepad.exe" ) ) ) ) ) ),
        {
            {
                "Random event, no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_Image, _T( "svchost.exe" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "First field equal is a match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_Image, _T( "iexplore.exe" ) } },
                Rule_include, _T( "procmatch" ),
            },
            {
                "Second field contains is a match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "notepad.exe" ) } },
                Rule_include, _T( "procmatch" ),
            },
            {
                "Boths fields leads to a match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "iexplore.exe" ) },
                    { F_CP_CommandLine, _T( "notepad.exe" ) }
                },
                Rule_include, _T( "procmatch" ),
            },
        },
    },
    {
        "Rule AND between two fields",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "Image", "condition", "is",
                        RuleEntry( "iexplore.exe" ) ),
                    RuleEntry( "Rule", "cmdmatch", "groupRelation", "and",
                        RuleEntry( "CommandLine", "condition", "begin with",
                            RuleEntry( "/testopt" ) ),
                        RuleEntry( "CommandLine", "condition", "contains",
                            RuleEntry( "https://www.microsoft.com" ) ) ) ) ) ),
        {
            {
                "Random event, no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_Image, _T( "svchost.exe" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "First field equal, no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_Image, _T( "iexplore.exe" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Rule partial match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "iexplore.exe" ) },
                    { F_CP_CommandLine, _T( "/testopt" ) }
                },
                Rule_exclude, _T( "" ),
            },
            {
                "Incorrect command line",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "iexplore.exe" ) },
                    { F_CP_CommandLine, _T( "padding /testopt https://www.microsoft.com" ) }
                },
                Rule_exclude, _T( "" ),
            },
            {
                "Full match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "iexplore.exe" ) },
                    { F_CP_CommandLine, _T( "/testopt https://www.microsoft.com" ) }
                },
                Rule_include, _T( "cmdmatch" ),
            },
        },
    },
    {
        "Rule AND between two fields in a OR RuleGroup",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "RuleGroup", "procmatch", "groupRelation", "or",
                    RuleEntry( "ProcessCreate", "onmatch", "include",
                        RuleEntry( "Image", "condition", "is",
                            RuleEntry( "iexplore.exe" ) ),
                        RuleEntry( "Rule", "cmdmatch", "groupRelation", "and",
                            RuleEntry( "CommandLine", "condition", "begin with",
                                RuleEntry( "/testopt" ) ),
                            RuleEntry( "CommandLine", "condition", "contains",
                                RuleEntry( "https://www.microsoft.com" ) ) ) ) ) ) ),
        {
            {
                "Random event, no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_Image, _T( "svchost.exe" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "First field equal, match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_Image, _T( "iexplore.exe" ) } },
                Rule_include, _T( "procmatch" ),
            },
            {
                "Rule partial match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "iexplore.exe" ) },
                    { F_CP_CommandLine, _T( "/testopt" ) }
                },
                Rule_include, _T( "procmatch" )
            },
            {
                "Incorrect command line",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_CommandLine, _T( "padding /testopt https://www.microsoft.com" ) }
                },
                Rule_exclude, _T( "" ),
            },
            {
                "Full commandline match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_CommandLine, _T( "/testopt https://www.microsoft.com" ) }
                },
                Rule_include, _T( "cmdmatch" ),
            },
            {
                "Full match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "iexplore.exe" ) },
                    { F_CP_CommandLine, _T( "/testopt https://www.microsoft.com" ) }
                },
                Rule_include, _T( "procmatch" ),
            },
        },
    },
    {
        "Rule OR between two fields",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "Image", "condition", "is",
                        RuleEntry( "iexplore.exe" ) ),
                    RuleEntry( "Rule", "cmdmatch", "groupRelation", "or",
                        RuleEntry( "CommandLine", "condition", "begin with",
                            RuleEntry( "/testopt" ) ),
                        RuleEntry( "CommandLine", "condition", "contains",
                            RuleEntry( "https://www.microsoft.com" ) ) ) ) ) ),
        {
            {
                "Random event, no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_Image, _T( "svchost.exe" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "First field equal, no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_Image, _T( "iexplore.exe" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Rule match first field",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "iexplore.exe" ) },
                    { F_CP_CommandLine, _T( "/testopt" ) }
                },
                Rule_include, _T( "cmdmatch" ),
            },
            {
                "Rule match second field",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "iexplore.exe" ) },
                    { F_CP_CommandLine, _T( "padding /testopt https://www.microsoft.com" ) }
                },
                Rule_include, _T( "cmdmatch" ),
            },
            {
                "Rule match all fields",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "iexplore.exe" ) },
                    { F_CP_CommandLine, _T( "/testopt https://www.microsoft.com" ) }
                },
                Rule_include, _T( "cmdmatch" ),
            },
        },
    },
    {
        "Rule AND between three fields",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "Rule", "cmdmatch", "groupRelation", "and",
                        RuleEntry( "CommandLine", "condition", "begin with",
                            RuleEntry( "/testopt" ) ),
                        RuleEntry( "CommandLine", "condition", "end with",
                            RuleEntry( "/end" ) ),
                        RuleEntry( "CommandLine", "condition", "contains",
                            RuleEntry( "https://www.microsoft.com" ) ) ) ) ) ),
        {
            {
                "Random event, no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_Image, _T( "svchost.exe" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "First field equal, no match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_Image, _T( "iexplore.exe" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Rule partial match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "iexplore.exe" ) },
                    { F_CP_CommandLine, _T( "/testopt" ) }
                },
                Rule_exclude, _T( "" ),
            },
            {
                "Incorrect command line",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "iexplore.exe" ) },
                    { F_CP_CommandLine, _T( "padding /testopt https://www.microsoft.com" ) }
                },
                Rule_exclude, _T( "" ),
            },
            {
                "Full match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "iexplore.exe" ) },
                    { F_CP_CommandLine, _T( "/testopt https://www.microsoft.com /end" ) }
                },
                Rule_include, _T( "cmdmatch" ),
            },
        },
    },
    {
        "RegistryEvent (multiple sub-events on the id)",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "Rule", "groupRelation", "or",
                        RuleEntry( "Image", "condition", "contains", RuleEntry( "conhost.exe" ) ),
                        RuleEntry( "Image", "condition", "contains", RuleEntry( "notepad.exe" ) ) ) ),
                RuleEntry( "RegistryEvent", "onmatch", "include",
                    RuleEntry( "Details", "condition", "contains",
                        RuleEntry( "SomeValue" ) ) ) ) ),
        {
            {
                "Random event, no match",
                &SYSMONEVENT_REG_SETVALUE_Type,
                {
                    { F_RS_Details, _T( "OtherValue" ) }
                },
                Rule_exclude, _T( "" ),
            },
            {
                "Full match",
                &SYSMONEVENT_REG_SETVALUE_Type,
                {
                    { F_RS_Details, _T( "SomeValue" ) }
                },
                Rule_include, _T( "" ),
            },
            {
                "Full match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "notepad.exe" ) }
                },
                Rule_include, _T( "" ),
            }
        }
    },
    {
        "Expected behaviour of the sysmon modular configuration",
        SysmonRule( _T( "sysmon-modular-config.xml" ) ),
        {
            {
                "Powershell dll loaded",
                &SYSMONEVENT_IMAGE_LOAD_Type,
                {
                    { F_IL_Image, _T( "c:\\file.exe" ) },
                    { F_IL_ImageLoaded, _T( "C:\\Windows\\assembly\\NativeImages_v2.0.50727_64\\System.Management.A#\\3256e997418c6c8793821826317b9b9c\\System.Management.Automation.ni.dll" ) },
                },
                Rule_include, _T( "technique_id=T1059.001,technique_name=PowerShell" ),
            },
        }
    },
    {
        "Check behaviour on exclude/include on default include",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ProcessCreate", "onmatch", "include",
                    RuleEntry( "CommandLine", "condition", "contains", RuleEntry( "/include" ) ) ),
                RuleEntry( "ProcessCreate", "onmatch", "exclude",
                   RuleEntry( "CommandLine", "condition", "contains", RuleEntry( "/exclude" ) ) ) ) ),
        {
            {
                "Include match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/include" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Exclude match",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/exclude" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Match both, exclude take over",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/include /exclude" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Match none, exclude instead of default",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                { { F_CP_CommandLine, _T( "/nothing" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Check behaviour on exclude/include on default exclude",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "FileCreateTime", "onmatch", "include",
                    RuleEntry( "Image", "condition", "contains", RuleEntry( "include" ) ) ),
                RuleEntry( "FileCreateTime", "onmatch", "exclude",
                   RuleEntry( "Image", "condition", "contains", RuleEntry( "exclude" ) ) ) ) ),
        {
            {
                "Include match",
                &SYSMONEVENT_FILE_TIME_Type,
                { { F_FT_Image, _T( "include" ) } },
                Rule_include, _T( "" ),
            },
            {
                "Exclude match",
                &SYSMONEVENT_FILE_TIME_Type,
                { { F_FT_Image, _T( "exclude" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Match both, exclude take over",
                &SYSMONEVENT_FILE_TIME_Type,
                { { F_FT_Image, _T( "include_exclude" ) } },
                Rule_exclude, _T( "" ),
            },
            {
                "Match none, exclude instead of default",
                &SYSMONEVENT_FILE_TIME_Type,
                { { F_FT_Image, _T( "nothing" ) } },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Check long sub-rules on omega configuration",
        SysmonRule( _T( "sysmonconfig-export-omega.xml" ) ),
        {
            {
                "Different hahes",
                &SYSMONEVENT_DRIVER_LOAD_Type,
                {
                    { F_DL_ImageLoaded, _T("c:\\Windows\\System32\\drivers\\raspppoe.sys") },
                    { F_DL_Hashes, _T( "MD5=3DCFC79E16BA9A0DA42D466237F25120,SHA256=2E2630A58C1488ADE720136FE4A3C493A6045F08C3C1EBBB8642C07B0B7C6649,IMPHASH=3E419F563516B0B50BB14CFE54E4F1AC" ) },
                    { F_DL_Signed, _T("failed: failed: Signing queue is full") },
                    { F_DL_Signature, _T("") },
                    { F_DL_SignatureStatus, _T("") },
                },
                Rule_exclude, _T( "" ),
            },
            {
                "Match last hash on the list, check it was not truncated",
                &SYSMONEVENT_DRIVER_LOAD_Type,
                {
                    { F_DL_ImageLoaded, _T("c:\\Windows\\System32\\drivers\\anydriver.sys") },
                    { F_DL_Hashes, _T( "10b30bdee43b3a2ec4aa63375577ade650269d25;d2fd132ab7bbc6bbb87a84f026fa0244" ) },
                    { F_DL_Signed, _T("failed: failed: Signing queue is full") },
                    { F_DL_Signature, _T("") },
                    { F_DL_SignatureStatus, _T("") },
                },
                Rule_include, _T( "MR=T1195,Tec=Supply Chain Compromise,Tac=Initial Access,Alert=Vulnerable Dell Drivers Detected,Risk=10" ),
            },
       },
    },
    {
        "Check rule names of 255 characters can be loaded and match correctly",
        SysmonRule( _T( "longnames.xml" ) ),
        {
            {
                "RuleGroup long name",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "powershell.exe" ) },
                },
                Rule_include, _T( "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" ),
            },
            {
                "Sub-rule long name",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "cmd.exe" ) },
                },
                Rule_include, _T( "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY" ),
            },
            {
                "Field long name",
                &SYSMONEVENT_CREATE_PROCESS_Type,
                {
                    { F_CP_Image, _T( "bash.exe" ) },
                },
                Rule_include, _T( "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ" ),
            },
        },
    },
    {
        "Check generic registry filtering work as expected",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "RegistryEvent", "onmatch", "include",
                    RuleEntry( "TargetObject", "condition", "contains", RuleEntry( "\\test\\" ) ) ) ) ),
        {
            {
                "No match on reg key with different target",
                &SYSMONEVENT_REG_KEY_Type,
                {
                    { F_RK_TargetObject, _T( "HKLM\\nothing" ) },
                },
                Rule_exclude, _T( "" ),
            },
            {
                "Match for reg key",
                &SYSMONEVENT_REG_KEY_Type,
                {
                    { F_RK_TargetObject, _T( "HKLM\\test\\one" ) },
                },
                Rule_include, _T( "" ),
            },
            {
                "Match for reg set value",
                &SYSMONEVENT_REG_SETVALUE_Type,
                {
                    { F_RS_TargetObject, _T( "HKLM\\test\\two" ) },
                },
                Rule_include, _T( "" ),
            },
             {
                "Match for reg name",
                &SYSMONEVENT_REG_NAME_Type,
                {
                    { F_RN_TargetObject, _T( "HKLM\\test\\three" ) },
                },
                Rule_include, _T( "" ),
            },
        },
    },
    {
        "Registry field specific to reg set value",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "RegistryEvent", "onmatch", "include",
                    RuleEntry( "Details", "condition", "contains", RuleEntry( "something" ) ) ) ) ),
        {
            {
                "No match on reg key with different target",
                &SYSMONEVENT_REG_KEY_Type,
                {
                    { F_RK_TargetObject, _T( "HKLM\\nothing" ) },
                },
                Rule_exclude, _T( "" ),
            },
            {
                "No match, no details field for reg key",
                &SYSMONEVENT_REG_KEY_Type,
                {
                    { F_RK_TargetObject, _T( "HKLM\\test\\one" ) },
                },
                Rule_exclude, _T( "" ),
            },
            {
                "Match for reg set value",
                &SYSMONEVENT_REG_SETVALUE_Type,
                {
                    { F_RS_Details, _T( "something is here" ) },
                },
                Rule_include, _T( "" ),
            },
             {
                "No match for field at same index but different name",
                &SYSMONEVENT_REG_NAME_Type,
                {
                    { F_RN_NewName, _T( "it has something" ) },
                },
                Rule_exclude, _T( "" ),
            },
        },
    },
    {
        "Exclude rule ignored when field does not exists for type",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "RegistryEvent", "onmatch", "exclude",
                    RuleEntry( "Details", "condition", "contains", RuleEntry( "something" ) ) ),
                RuleEntry( "RegistryEvent", "onmatch", "include",
                    RuleEntry( "TargetObject", "condition", "contains", RuleEntry( "\\test\\" ) ) ) ) ),
        {
            {
                "No match on reg key with different target",
                &SYSMONEVENT_REG_KEY_Type,
                {
                    { F_RK_TargetObject, _T( "HKLM\\nothing" ) },
                },
                Rule_exclude, _T( "" ),
            },
            {
                "Match on reg key which does not have details field",
                &SYSMONEVENT_REG_KEY_Type,
                {
                    { F_RK_TargetObject, _T( "HKLM\\test\\one" ) },
                },
                Rule_include, _T( "" ),
            },
            {
                "No match when details field is here (set value) even when targetobject is correct",
                &SYSMONEVENT_REG_SETVALUE_Type,
                {
                    { F_RS_TargetObject, _T( "HKLM\\test\\two" ) },
                    { F_RS_Details, _T( "something is here" ) },
                },
                Rule_exclude, _T(""),
            },
            {
                "Match when details does not have the word something",
                &SYSMONEVENT_REG_SETVALUE_Type,
                {
                    { F_RS_TargetObject, _T( "HKLM\\test\\two" ) },
                    { F_RS_Details, _T( "nothing is here" ) },
                },
                Rule_include, _T(""),
            },
            {
                "Match as the NewName field is same index but different name",
                &SYSMONEVENT_REG_NAME_Type,
                {
                    { F_RN_TargetObject, _T( "HKLM\\test\\three" ) },
                    { F_RN_NewName, _T( "something is here, should match" ) },
                },
                Rule_include, _T(""),
            },
        },
    },
    {
        "Or conditions work even if one or more fields are not part of the event type",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "RuleGroup", "", "groupRelation", "or",
                    RuleEntry( "RegistryEvent", "onmatch", "include",
                        RuleEntry( "Details", "condition", "contains", RuleEntry( "something" ) ),
                        RuleEntry( "TargetObject", "condition", "contains", RuleEntry( "\\test\\" ) ) ) ) ) ),
        {
            {
                "TargetObject is a match, Details is skipped",
                &SYSMONEVENT_REG_KEY_Type,
                {
                    { F_RK_TargetObject, _T( "HKLM\\test\\one" ) },
                },
                Rule_include, _T( "" ),
            },
            {
                "Details is a match",
                &SYSMONEVENT_REG_SETVALUE_Type,
                {
                    { F_RS_Details, _T( "something is here" ) },
                },
                Rule_include, _T( "" ),
            },
            {
                "No match for NewName matching only Details",
                &SYSMONEVENT_REG_NAME_Type,
                {
                    { F_RN_NewName, _T( "there is something here" ) },
                },
                Rule_exclude, _T(""),
            },
        },
    },
};

// ProcessEventRules tests XML configurations against ProcessEventRules for matching.
TEST( Rules, ProcessEventRules )
{
    bool tempFileInUse = false;
    SYSMON_EVENT_HEADER header = {};
    header.m_SessionId = mockSessionId;

	TCHAR testPath[MAX_PATH] = {};
	TCHAR szFileName[MAX_PATH + 1];
    GetModuleFileName( NULL, szFileName, MAX_PATH + 1 );
    ASSERT_TRUE( PathCombine( testPath, szFileName, testPathRelative ) != NULL );

#if defined _WIN64 || defined _WIN32
    MockEnvironmentVariableCache mockCache( &envCache );

    // Support two mock session ids.
    EXPECT_CALL( mockCache, GetUserToken( mockSessionId, _ ) )
        .Times( AnyNumber() )
        .WillRepeatedly( Invoke( MockEnvironmentVariableCache::MockGetUserToken ) );
#endif

    for( auto& test : ruleMatches ) {
        PVOID Rules;
        ULONG RulesSize;
        tstring ruleFile;

		SCOPED_TRACE( test.Description );

#if defined _WIN64 || defined _WIN32
        // Clean the cache between sessions because the configuration is updated but
        // it is not passed through the usual events.
        mockCache.CleanCache();
#endif

		// Use an existing test configuration file or write the generated configuration to file.
		if( test.Rule.HasConfigurationFile() ) {

			ruleFile = testPath;
			ruleFile += test.Rule.ConfigurationFile();
            tempFileInUse = false;
		} else {

			ASSERT_EQ( WriteTempStringFile( test.Rule.Output(), ruleFile ), TRUE );
            tempFileInUse = true;
		}
		ASSERT_EQ( ApplyConfigurationFile( const_cast<PTCHAR>(ruleFile.c_str()), &Rules, &RulesSize, TRUE ), TRUE );

        // Test each field value to ensure the generated configuration aligns with expectations.
        for( auto& fieldValues : test.Values ) {
            SCOPED_TRACE( fieldValues.Description );
            PWCHAR ruleName = NULL;
            LARGE_INTEGER eventTime;
            SYSMON_DATA_DESCRIPTOR eventBuffer[SYSMON_MAX_EVENT_Fields] = {{(NativeTypes) 0}};

            // Set all fields in the event buffer, the rest won't be available.
            for( auto& field : fieldValues.Fields ) {
                EventSetFieldS( eventBuffer, field.Id, field.Value, FALSE );
            }
            EXPECT_EQ( ProcessEventRulesDry( &eventTime, fieldValues.EventType, eventBuffer, &header, &ruleName ),
                fieldValues.ExpectedReturn );
#if defined _WIN64 || defined _WIN32
            tstring ruleTString( ruleName ? ruleName : _T( "" ) );
            EXPECT_EQ( ruleTString, fieldValues.ExpectedRuleName );
#elif defined __linux__
            size_t ruleNameSize;
            if( ruleName != NULL ) {
                ruleNameSize = UTF16toUTF8( NULL, ruleName, 0 );
            } else {
                ruleNameSize = 1;
            }
            CHAR ruleNameChar[ruleNameSize];
            if( ruleName != NULL ) {
                UTF16toUTF8( ruleNameChar, ruleName, ruleNameSize );
            } else {
                *ruleNameChar = 0x00;
            }
            EXPECT_EQ( strcmp( ruleNameChar, fieldValues.ExpectedRuleName.c_str() ), 0 );
#endif
        }
        if (tempFileInUse) {
#if defined _WIN64 || defined _WIN32
            DeleteFile(ruleFile.c_str());
#elif defined __linux__
            unlink(ruleFile.c_str());
#endif
        }
    }
}

#if defined _WIN64 || defined _WIN32
// veryLongString is 256 characters (1 more than allowed on rule names).
const CHAR veryLongString[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

//
// This test relies on testing::internal::CaptureStdout() which does not appear to
// function on Linux
//
INCORRECT_XML xmls[] = {
    {
        "A tag in the XML file was unknown",
        SysmonRule( testDefaultVersion,
            RuleEntry( "IncorrectTag", RuleEntry::Empty ) ),
        "Element Sysmon content does not follow the DTD, expecting \\(.*\\)\\*, got \\(IncorrectTag\\)",
    },
    {
        "An unknown attribute was set on a tag",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering", "unknownattr", "nothing", RuleEntry::Empty ) ),
        "No declaration for attribute unknownattr of element EventFiltering",
    },
    {
        "An unknown attribute value was set for onmatch",
        SysmonRule( testDefaultVersion,
                    RuleEntry( "EventFiltering",
                        RuleEntry( "ProcessCreate", "onmatch", "notsure", RuleEntry::Empty ) ) ),
        "Value \"notsure\" for attribute onmatch of ProcessCreate is not among the enumerated set",
    },
    {
        "An unknown attribute value was set for condition",
        SysmonRule( testDefaultVersion,
                    RuleEntry( "EventFiltering",
                        RuleEntry( "ProcessCreate", "onmatch", "include",
                            RuleEntry( "Image", "condition", "something",
                                RuleEntry( "iexplore.exe" ) ) ) ) ),
        "Error: Unknown condition: something\nExpected values are",
    },
    {
        "A very long rulegroup name",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "RuleGroup", veryLongString, "groupRelation", "and",
                    RuleEntry( "ProcessCreate", "onmatch", "include",
                        RuleEntry( "CommandLine", "condition", "contains",
                            RuleEntry( "iexplore.exe" ) ),
                        RuleEntry( "CommandLine", "condition", "contains",
                            RuleEntry( "Windows" ) ) ) ) ) ),
        "Error: Rule name is larger than 255 characters: ",
    },
    {
        "A very long sub-rule name",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ImageLoad", "onmatch", "exclude",
                    RuleEntry( "Rule", veryLongString, "groupRelation", "and",
                        RuleEntry( "Image", "condition", "is", RuleEntry( "notepad.exe" ) ),
                        RuleEntry( "ImageLoaded", "condition", "contains", RuleEntry( "C:\\Windows\\System32" ) ) ) ) ) ),
        "Error: Rule name is larger than 255 characters: ",
    },
    {
        "A very long field name",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "ImageLoad", "onmatch", "exclude",
                        RuleEntry( "Image", veryLongString, "condition", "is", RuleEntry( "notepad.exe" ) ) ) ) ),
        "Error: Rule name is larger than 255 characters: ",
    }
};

// IncorrectXml verifies incorrect Xml files are correctly captured and error printed.
TEST( Rules, IncorrectXml )
{
    for( auto& test : xmls ) {
        PVOID Rules;
        ULONG RulesSize;
        tstring ruleTempFile;
        SCOPED_TRACE( test.Description );

        // Reset the stdout capture between tests.
        testing::internal::CaptureStdout();

        // Write the generated configuration to file and load it.
        ASSERT_EQ( WriteTempStringFile( test.Rule.Output(), ruleTempFile ), TRUE );
        EXPECT_EQ( ApplyConfigurationFile( const_cast<PTCHAR>(ruleTempFile.c_str()), &Rules, &RulesSize, TRUE ), FALSE );

        // The error is part of the stdout content.
        EXPECT_THAT( testing::internal::GetCapturedStdout(), testing::ContainsRegex( test.ErrorRegex ) );
    }
}
#endif

RULE_INCLUDE_TEST includeEntries[] = {
    {
        "With unrelated rules, default to FALSE",
        SysmonRule( testDefaultVersion,
                    RuleEntry( "EventFiltering",
                        RuleEntry( "DriverLoad", "onmatch", "include",
                            RuleEntry( "Signature", "condition", "contains",
                                RuleEntry( "Microsoft" ) ) ) ) ),
        {
            {
                &SYSMONEVENT_CREATE_PROCESS_Type,
                FALSE,
            },
            {
                &SYSMONEVENT_RAWACCESS_READ_Type,
                FALSE,
            },
        }
    },
    {
        "ProcessCreate with one simple include rule",
        SysmonRule( testDefaultVersion,
                    RuleEntry( "EventFiltering",
                        RuleEntry( "ProcessCreate", "onmatch", "include",
                            RuleEntry( "Image", "condition", "contains",
                                RuleEntry( "iexplore.exe" ) ) ) ) ),
        {
            {
                &SYSMONEVENT_CREATE_PROCESS_Type,
                TRUE,
            },
        },
    },
    {
        "Include all rawread access",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "RawAccessRead", "onmatch", "exclude", RuleEntry::Empty ) ) ),
        {
            {
                &SYSMONEVENT_RAWACCESS_READ_Type,
                TRUE,
            },
        },
    },
    {
        "Include only some entries",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "RawAccessRead", "onmatch", "include",
                            RuleEntry( "Image", "condition", "contains", RuleEntry( "System32" ) ) ) ) ),
        {
            {
                &SYSMONEVENT_RAWACCESS_READ_Type,
                TRUE,
            },
        },
    },
    {
        "Include some entries, exclude others",
        SysmonRule( testDefaultVersion,
            RuleEntry( "EventFiltering",
                RuleEntry( "RawAccessRead", "onmatch", "include",
                            RuleEntry( "Image", "condition", "contains", RuleEntry( "System32" ) ) ),
                RuleEntry( "RawAccessRead", "onmatch", "exclude",
                            RuleEntry( "Image", "condition", "contains", RuleEntry( "Config" ) ) ) ) ),
        {
            {
                &SYSMONEVENT_RAWACCESS_READ_Type,
                TRUE,
            },
        },
    },
};

// IdHasIncludeRules tests XML configurations against IdHasIncludeRules to check if features should be enabled.
TEST( Rules, IdHasIncludeRules )
{
	ASSERT_EQ( InitializeRules(), TRUE );

	for( auto& test : includeEntries ) {

        PVOID Rules;
        ULONG RulesSize;
        tstring ruleTempFile;

        SCOPED_TRACE( test.Description );

        // Write the generated configuration to file and load it.
        ASSERT_EQ( WriteTempStringFile( test.Rule.Output(), ruleTempFile ), TRUE );
		ASSERT_EQ( ApplyConfigurationFile( const_cast<PTCHAR>( ruleTempFile.c_str() ), &Rules, &RulesSize, TRUE ), TRUE );

		RULE_CONTEXT ruleContext;
		ASSERT_EQ( InitializeRuleContext( &ruleContext ), TRUE );

		// Test each field value to ensure the generated configuration align with expectations.
        for( auto& inputValues : test.Values ) {

			EXPECT_EQ( IdHasIncludeRules( &ruleContext, inputValues.EventType->EventId ),
					   inputValues.ExpectedReturn );
		}

		ReleaseRuleContext( &ruleContext );
#if defined _WIN64 || defined _WIN32
        DeleteFile(ruleTempFile.c_str());
#elif defined __linux__
        unlink(ruleTempFile.c_str());
#endif
	}
}


FieldSizesTest FieldSizesTests[] = {
    { NULL, TRUE },
    { _T(""), TRUE },
    { _T("Nonfield:5"), FALSE },
    { _T("Image:5,Nonfield:6"), FALSE },
    { _T("Nonfield:5,Image:6"), FALSE },
    { _T("Image:0"), FALSE },
    { _T("Image:-1"), FALSE },
    { _T("Image:-2"), FALSE },
    { _T("Image:0,User:5"), FALSE },
    { _T("Image:5,User:0"), FALSE },
    { _T("Image:-1,User:5"), FALSE },
    { _T("Image:5,User:-1"), FALSE },
    { _T("Image:-2,User:5"), FALSE },
    { _T("Image:5,User:-2"), FALSE },
    { _T("Image:5.User:6"), FALSE },
    { _T("Image:5,User:6"), TRUE },
};

TestFieldSize TestFieldSizes[] = {
    { _T("Image"), 5 },
    { _T("User"), 6 },
};

// Test FieldSizes global option
TEST( FieldSizes, LoadAndRetrieveFieldSizes )
{
    unsigned int i, j, k, m;
    int fieldSize;

    for( i = 0; i < sizeof(FieldSizesTests) / sizeof(*FieldSizesTests); i++ ) {
        ASSERT_EQ( LoadVariableFieldSizes( FieldSizesTests[i].Str ), FieldSizesTests[i].Result );
    }

    // Every event
    for( j = 0; j < SYSMON_MAX_EVENT_ID; j++ ) {
        // Every field
        for( k = 0; k < AllEvents[i]->FieldCount; k++ ) {
            // Get specified field size
            fieldSize = -1;
            for( m = 0; m < sizeof(TestFieldSizes) / sizeof(*TestFieldSizes); m++ ) {
                if( _tcscmp( AllEvents[j]->FieldNames[k], TestFieldSizes[m].Field ) == 0 ) {
                    fieldSize = TestFieldSizes[m].Size;
                }
            }

            ASSERT_EQ( GetVariableFieldSize( j, k ), fieldSize );
        }
    }
}

TEST( FieldSizes, CheckTrim )
{
    TCHAR str[] = _T("ABCDEFGHIJKLMN");
    const ULONG strLen = (const ULONG)_tcslen( str ); // number of characters
    ULONG size = (strLen + 1) * sizeof(TCHAR); // number of bytes inc \0
    const ULONG cSize = size;

    // NULL string
    ASSERT_EQ( TrimStringToNChars( NULL, 5, &size ), FALSE );
    ASSERT_EQ( size, cSize );

    // maxlength < 0
    ASSERT_EQ( TrimStringToNChars( str, -1, &size ), FALSE );
    ASSERT_EQ( size, cSize );

    // _tcslen( str ) < maxlength
    ASSERT_EQ( TrimStringToNChars( str, 200, &size ), FALSE );
    ASSERT_EQ( size, cSize );

    // _tcslen( str ) == maxlength
    ASSERT_EQ( TrimStringToNChars( str, strLen, &size ), FALSE );
    ASSERT_EQ( size, cSize );

    // trim to N
    ASSERT_EQ( TrimStringToNChars( str, 5, &size ), TRUE );
    ASSERT_EQ( _tcscmp( str, _T("AB...") ), 0 );
    ASSERT_EQ( size, (5 + 1) * sizeof(TCHAR) );

    // trim to 2
    ASSERT_EQ( TrimStringToNChars( str, 2, &size ), TRUE );
    ASSERT_EQ( _tcscmp( str, _T("-") ), 0 );
    ASSERT_EQ( size, (1 + 1) * sizeof(TCHAR) );

    // trim to 1
    _tcscpy( str, _T("ABCDE") );
    ASSERT_EQ( TrimStringToNChars( str, 1, &size ), TRUE );
    ASSERT_EQ( _tcscmp( str, _T("-") ), 0 );
    ASSERT_EQ( size, (1 + 1) * sizeof(TCHAR) );

    // trim to 0
    _tcscpy( str, _T("ABCDE") );
    ASSERT_EQ( TrimStringToNChars( str, 0, &size ), TRUE );
    ASSERT_EQ( _tcscmp( str, _T("") ), 0 );
    ASSERT_EQ( size, sizeof(TCHAR) );
}

