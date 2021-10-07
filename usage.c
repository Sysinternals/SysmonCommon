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
// Usage
//
//====================================================================

//--------------------------------------------------------------------
//
// PrintUsageText
//
// Does intelligent line breaking based on current console sizing.
//
//--------------------------------------------------------------------

#include "stdafx.h"
#include "sysmonevents.h"

void
PrintUsageText(
	_In_ CONSOLE_SCREEN_BUFFER_INFO *csbi,
	_In_ PTCHAR Text
	)
{
	short width = csbi->dwSize.X;
	PTCHAR	curLine;
	PTCHAR	curPtr;
	short	curOffset = 0;
	PTCHAR	textCopy;
	TCHAR	tmpChar;
	short	lastSpaceOffset = -1;

	textCopy = _tcsdup(Text);
	curPtr = textCopy;
	curLine = textCopy;

	while( *curPtr != 0 ) {

		if( *curPtr == _T('\n') ) {

			*curPtr = 0;
			_fputts(curLine, stderr);
			_fputtc(_T('\n'), stderr); 
			curPtr++;
			lastSpaceOffset = -1;
			curLine = curPtr;
			curOffset = 0;
		}
		else if( curOffset == width -1 ) {

			if( lastSpaceOffset > 0) {

				curLine[lastSpaceOffset] = 0;
				_fputts(curLine, stderr);
				_fputtc(_T('\n'), stderr);
				curPtr = &curLine[lastSpaceOffset+1];
				lastSpaceOffset = -1;
				curLine = curPtr;
				curOffset = 0;
			}
			else {

				// line just doesn't fit, so let it wrap
				tmpChar = *curPtr;
				*curPtr = 0;
				_fputts(curLine, stderr);
				_fputtc(_T('\n'), stderr);
				*curPtr = tmpChar;
				lastSpaceOffset = -1;
				curLine = curPtr;
				curOffset = 0;
			}
		}
		else if( *curPtr == ' ' ) {

			lastSpaceOffset = curOffset;
			curPtr++;
			curOffset++;
		}
		else {

			curPtr++;
			curOffset++;
		}
	}
	_fputts(curLine, stderr);
}


//--------------------------------------------------------------------
//
// Usage
//
//--------------------------------------------------------------------
int
Usage(
	_In_ PTCHAR program,
	_In_ CONSOLE_SCREEN_BUFFER_INFO *csbi
	)
{
	TCHAR			baseName[MAX_PATH];

	//
	// The classic cmd Window support 80 characters and we assume Sysmon.exe
	// will be 32 characters
	//
#if defined _WIN64 || defined _WIN32
	GetModuleBaseName( GetCurrentProcess(), NULL, baseName, _countof( baseName ) );
#elif defined __linux__
	GetProcessName(baseName, sizeof(baseName), -1);
#endif

	_ftprintf(stderr, _T("Usage:\n"));
	// Padding is 12 before switches. On first lines 35 characters are available (up to 67 column). Others up to 98 column.
	_ftprintf(stderr, _T("Install:                 %s -i [<configfile>]\n"), baseName );
	_ftprintf(stderr, _T("Update configuration:    %s -c [<configfile>]\n"), baseName );
#if defined _WIN64 || defined _WIN32
	_ftprintf(stderr, _T("Install event manifest:  %s -m\n"), baseName );
#endif
	_ftprintf(stderr, _T("Print schema:            %s -s\n"), baseName );
	_ftprintf(stderr, _T("Uninstall:               %s -u [force]\n"), baseName );

	// Padding is 7. Up to 98 column.
#if 0
	_ftprintf(stderr, _T("  -a   Name of directory to archive deleted files (filter archive\n"));
	_ftprintf(stderr, _T("       directory).\n"));
	_ftprintf(stderr, _T("       Configuration entry: ArchiveDirectory.\n"));
#endif
#if defined _WIN64 || defined _WIN32
#if !defined(SYSMON_SHARED) && !defined(SYSMON_PUBLIC)
	_ftprintf(stderr, _T("  -b   Captures clipboard from interactive sessions.\n"));
	_ftprintf(stderr, _T("       Configuration entry: CaptureClipboard.\n"));
#endif
#endif
	_ftprintf(stderr, _T("  -c   Update configuration of an installed Sysmon driver or dump the\n"));
	_ftprintf(stderr, _T("       current configuration if no other argument is provided. Optionally\n"));
	_ftprintf(stderr, _T("       take a configuration file.\n"));
#if 0
	_ftprintf(stderr, _T("  -d   Specify the name of the installed device driver image.\n"));
	_ftprintf(stderr, _T("       Configuration entry: DriverName.\n"));
	_ftprintf(stderr, _T("       The service image and service name will be the same\n"));
	_ftprintf(stderr, _T("       name of the Sysmon.exe executable image.\n"));
	_ftprintf(stderr, _T("  -e   Captures deleted Portable Executable (PE) files.\n"));
	_ftprintf(stderr, _T("       Configuration entry: CopyOnDeletePE.\n"));
	_ftprintf(stderr, _T("  -f   Captures files deleted by any processes with the.\n"));
	_ftprintf(stderr, _T("       specified SID, account or group names in their tokens.\n"));
	_ftprintf(stderr, _T("       Configuration entry: CopyOnDeleteSIDs.\n"));
	_ftprintf(stderr, _T("  -h   Specify the hash algorithms used for image identification (default\n"));
	_ftprintf(stderr, _T("       is SHA1). It supports multiple algorithms at the same time.\n" ));
	_ftprintf(stderr, _T("       Configuration entry: HashAlgorithms.\n"));
#endif
	_ftprintf(stderr, _T("  -i   Install service and driver. Optionally take a configuration file.\n"));
#if 0
	_ftprintf(stderr, _T("  -j   Capture deleted files with the specified extensions. Can be noisy.\n"));
	_ftprintf(stderr, _T("       Configuration entry: CopyOnDeleteExtensions.\n"));
	_ftprintf(stderr, _T("  -k   Log process access attempts for supplied executable names and access\n"));
	_ftprintf(stderr, _T("       mask.\n"));
	_ftprintf(stderr, _T("       Configuration entry: ProcessAccess.\n"));
	_ftprintf(stderr, _T("  -i   Lookup DNS names for network IP addresses.\n" ));
	_ftprintf(stderr, _T("       Configuration entry: DnsLookup.\n"));
	_ftprintf(stderr, _T("  -l   Log loading of modules. Optionally take a list of processes to track.\n"));
#endif
#if defined _WIN64 || defined _WIN32
	_ftprintf(stderr, _T("  -m   Install the event manifest (done on service install as well)).\n"));
#endif
#if 0
	_ftprintf(stderr, _T("  -n   Log network connections. Optionally take a list of processes to track.\n"));
	_ftprintf(stderr, _T("  -p   Captures files deleted by the specified executable file\n"));
	_ftprintf(stderr, _T("       name or path. The '+' and '-' characters can be used to include\n"));
	_ftprintf(stderr, _T("       or exclude specific files, by default a file is included.\n"));
	_ftprintf(stderr, _T("       Configuration entry: CopyOnDeleteProcesses.\n"));
	_ftprintf( stderr, _T("  -r   Check for signature certificate revocation.\n" ));
	_ftprintf( stderr, _T("       Configuration entry: CheckRevocation.\n" ));
#endif
	_ftprintf( stderr, _T("  -s   Print configuration schema definition of the specified version.\n" ));
	_ftprintf( stderr, _T("       Specify 'all' to dump all schema versions (default is latest)).\n" ));
#ifdef _DEBUG
	_ftprintf(stderr, _T("  -t   Run in interactive console mode for debugging.\n"));
#endif
	_ftprintf(stderr, _T("  -u   Uninstall service and driver. Adding force causes uninstall to proceed\n"));
	_ftprintf(stderr, _T("       even when some components are not installed.\n" ));
	_ftprintf(stderr, _T("\n"));

	PrintUsageText(csbi,
		_T("The service logs events immediately and the driver installs as a boot-start ")
		_T("driver to capture activity from early in the boot that the service will ")
		_T("write to the event log when it starts.\n")
		_T("\n")
#if defined _WIN64 || defined _WIN32
		_T("On Vista and higher, events are stored in ")
		_T("\"Applications and Services Logs/Microsoft/Windows/Sysmon/Operational\". ")
		_T("On older systems, events are written to the System event log.\n")
#elif defined __linux__
        _T("On Linux, events are stored in the Syslog, often found at /var/log/syslog.\n")
#endif
		_T("\n")
		_T("Use the '-? config' command for configuration file documentation. ")
		_T("More examples are available on the Sysinternals website.\n")
		_T("\n")
#if defined _WIN64 || defined _WIN32
		_T("Specify -accepteula to automatically accept the EULA on installation, otherwise ")
		_T("you will be interactively prompted to accept it.\n")
#elif defined __linux__
        _T("Specify -accepteula to automatically accept the EULA on installation.\n")
#endif
		_T("\n")
		_T("Neither install nor uninstall requires a reboot.\n")
		_T("\n"));

	return ERROR_INVALID_PARAMETER;
}

//--------------------------------------------------------------------
//
// ConfigUsage
//
//--------------------------------------------------------------------
VOID
ConfigUsage(
	_In_ CONSOLE_SCREEN_BUFFER_INFO *csbi
	)
{
	ULONG	index;
	PTCHAR	fmt;

	_ftprintf(stderr, _T("Configuration usage (current schema is version: %.2f):\n\n"),
			  TO_DOUBLE(ConfigurationVersion));

	// Up to 98 column to respect cmd default size.
	PrintUsageText(csbi,
		_T("Configuration files can be specified after the -i (installation) or ")
		_T("-c (configuration) switches. They make it easier to deploy a preset ")
		_T("configuration and to filter captured events.\n\n")

		_T("A simple configuration xml file looks like this:\n\n"));

		_ftprintf(stderr, _T("<Sysmon schemaversion=\"%.2f\">\n"), TO_DOUBLE(ConfigurationVersion) );
		_ftprintf(stderr, _T("  <!-- Capture all hashes -->\n"));
		_ftprintf(stderr, _T("  <HashAlgorithms>*</HashAlgorithms>\n"));
		_ftprintf(stderr, _T("  <EventFiltering>\n"));
		_ftprintf(stderr, _T("    <!-- Log all drivers except if the signature -->\n"));
		_ftprintf(stderr, _T("    <!-- contains Microsoft or Windows -->\n"));
		_ftprintf(stderr, _T("    <DriverLoad onmatch=\"exclude\">\n"));
		_ftprintf(stderr, _T("      <Signature condition=\"contains\">microsoft</Signature>\n"));
		_ftprintf(stderr, _T("      <Signature condition=\"contains\">windows</Signature>\n"));
		_ftprintf(stderr, _T("    </DriverLoad>\n"));
		_ftprintf(stderr, _T("    <!-- Do not log process termination -->\n"));
		_ftprintf(stderr, _T("    <ProcessTerminate onmatch=\"include\" />\n"));
		_ftprintf(stderr, _T("    <!-- Log network connection if the destination port equal 443 -->\n"));
		_ftprintf(stderr, _T("    <!-- or 80, and process isn't InternetExplorer -->\n"));
		_ftprintf(stderr, _T("    <NetworkConnect onmatch=\"include\">\n"));
		_ftprintf(stderr, _T("      <DestinationPort>443</DestinationPort>\n"));
		_ftprintf(stderr, _T("      <DestinationPort>80</DestinationPort>\n"));
		_ftprintf(stderr, _T("    </NetworkConnect>\n"));
		_ftprintf(stderr, _T("    <NetworkConnect onmatch=\"exclude\">\n"));
		_ftprintf(stderr, _T("      <Image condition=\"end with\">iexplore.exe</Image>\n"));
		_ftprintf(stderr, _T("    </NetworkConnect>\n"));
		_ftprintf(stderr, _T("  </EventFiltering>\n"));
		_ftprintf(stderr, _T("</Sysmon>\n"));
		_ftprintf(stderr, _T("\n"));

	PrintUsageText(csbi, 
		_T("The configuration file contains a schemaversion attribute on the Sysmon tag.")
		_T("This version is independent from the Sysmon binary version and allows the ")
		_T("parsing of older configuration files. The current schema version is shown in the ")
		_T("sample configuration.\n\n")

		_T("Configuration entries are directly under the Sysmon tag and filters are ")
		_T("under the EventFiltering tag. Configuration entries are similar to ")
		_T("command line switches, and have their configuration entry described ")
		_T("in the Sysmon usage output. Parameters are optional based on the tag. ")
		_T("If a command line switch also enables an event, it needs to be configured ")
		_T("though its filter tag.\n\n")

		_T("Configuration entries include the following:\n\n")
		
		_T("  Entry                 Value     Description\n")
		_T("  ArchiveDirectory      String    Name of directories at volume roots into which copy-on-delete\n")
		_T("                                  files are moved. The directory is protected with a System ACL.\n")
		_T("                                  (you can use PsExec from Sysinternals to access the directory\n")
		_T("                                  using 'psexec -sid cmd').\n")
		_T("                                  Default: Sysmon\n")
		_T("  CheckRevocation        Boolean  Controls signature revocation checks.\n")
		_T("                                  Default: True\n")
		_T("  CopyOnDeletePE         Boolean  Preserves deleted executable image files.\n")
		_T("                                  Default: False\n")
		_T("  CopyOnDeleteSIDs       Strings  Comma-separated list of account SIDs for\n")
		_T("                                  which file deletes will be preserved.\n")
		_T("  CopyOnDeleteExtensions Strings  Extensions for files that are preserved on\n")
		_T("                                  delete.\n")
		_T("  CopyOnDeleteProcesses  Strings  Process name(s) for which file deletes will\n")
		_T("                                  be preserved.\n")
		_T("  DnsLookup              Boolean  Controls reverse DNS lookup.\n")
		_T("                                  Default: True\n")
		_T("  DriverName             String   Uses specied name for driver and service images.\n")
		_T("  HashAlgorithms         Strings  Hash algorithm(s) to apply for hashing. Algorithms\n")
		_T("                                  supported include MD5, SHA1, SHA256, IMPHASH and * (all).\n")
		_T("                                  Default: None\n")
        _T("  FieldSizes             Strings  Comma-separated list of FieldName:Size entries\n")
        _T("                                  that specify the maximum sizes for field output.\n")
        _T("                                  (example 'CommandLine:100,Image:20').\n")

		_T("Event filtering allows you to filter generated events. In many cases events can ") 
		_T("be noisy and gathering everything is not possible. For example, you might be ")
		_T("interested about network connections only for a certain process, but not all ")
		_T("of them. You can filter the output on the host reducing the data to collect.\n\n")

		_T("Each event has its own filter tag under EventFiltering:\n\n") );

		fmt = _T("%-6s %-20s %s\n");
		_ftprintf(stderr, fmt, _T("Id"), _T("Tag"), _T("Event"));
		fmt = _T("%-6d %-20s %s\n");

		for( index = 0; index < AllEventsCount; index++ ) {

			if( AllEvents[index]->RuleName == NULL ) {

				continue;
			}

			_ftprintf(stderr, fmt,
					  AllEvents[index]->EventId,
					  AllEvents[index]->RuleName,
					  AllEvents[index]->EventDescription );
		}
		_ftprintf(stderr, _T("\n")) ;


	PrintUsageText(csbi,
		_T("You can also find these tags in the event viewer on the task name.\n\n")

		_T("The onmatch filter is applied if events are matched. It can be changed ")
		_T("with the \"onmatch\" attribute for the filter tag. If the value is 'include', ")
		_T("it means only matched events are included. If it is set to 'exclude', the ") 
		_T("event will be included except if a rule match.\n\n")

		_T("Each tag under the filter tag is a fieldname from the event. Each field ")
		_T("entry is tested against generated events, if one match the rule is applied and ")
		_T("the rest is ignored.\n\n")

		_T("For example this rule will discard any process event where the IntegrityLevel ")
		_T("is medium:\n\n")

		_T("    <ProcessCreate onmatch=\"exclude\">\n")
		_T("        <IntegrityLevel>Medium</IntegrityLevel>\n")
		_T("    </ProcessCreate>\n\n")

		_T("Field entries can use other conditions to match the value. The conditions are")
		_T("as follow (all are case insensitive):\n\n")

		_T("is            Default, values are equals.\n")
		_T("is not        Values are different.\n")
		_T("contains      The field contains this value.\n")
		_T("contains any  The field contains any of the ; delimited values.\n")
		_T("contains all  The field contains all of the ; delimited values.\n")
		_T("excludes      The field does not contain this value.\n")
		_T("excludes any  The field does not contain one or more of the ; delimited values.\n")
		_T("excludes all  The field does not contain any of the ; delimited values.\n")
		_T("begin with    The field begins with this value.\n")
		_T("not begin with The field does not begin with this value.\n")
		_T("end with      The field ends with this value.\n")
		_T("not end with  The field does not end with this value.\n")
		_T("less than     Lexicographical comparison is less than zero.\n")
		_T("more than     Lexicographical comparison is more than zero.\n")
		_T("image         Match an image path (full path or only image name). \n")
		_T("              For example: lsass.exe will match c:\\windows\\system32\\lsass.exe.\n\n")

		_T("You can use a different condition by specifying it as an attribute. This ")
		_T("excludes network activity from processes with iexplore.exe in their path:\n\n")

		_T("  <NetworkConnect onmatch=\"exclude\">\n")
		_T("    <Image condition=\"contains\">iexplore.exe</Image>\n")
		_T("  </NetworkConnect>\n\n")

		_T("You can use both include and exclude rules for the same tag, where exclude rules override include ")
		_T("rules. Within a rule, filter conditions have OR behavior,  In the sample configuration ")
		_T("shown earlier, the networking filter uses both an include and exclude rule to capture ")
		_T("activity to port 80 and 443 by all processes except those that have iexplore.exe ")
		_T("in their name.\n\n") );

	PrintUsageText(csbi,
		_T("It is also possible to override the way that rules are combined by using a rule group ")
		_T("which allows the rule combine type for one or more events to be set explicity to AND or OR.\n\n")
		_T("The following example demonstrates this usage. In the first rule group, a process create ")
		_T("event will generate when timeout.exe is executed only with a command - line argument of ")
		_T("\"100\", but a process terminate event will generate for termination of ping.exe and ")
		_T("timeout.exe.\n\n")

		_T("  <EventFiltering>\n")
		_T("    <RuleGroup name=\"group 1\" groupRelation=\"and\">\n")
		_T("      <ProcessCreate onmatch=\"include\">\n")
		_T("        <Image condition=\"contains\">timeout.exe</Image>\n")
		_T("        <CommandLine condition=\"contains\">100</CommandLine>\n")
		_T("      </ProcessCreate>\n")
		_T("    </RuleGroup>\n")
		_T("    <RuleGroup groupRelation=\"or\">\n")
		_T("      <ProcessTerminate onmatch=\"include\">\n")
		_T("        <Image condition=\"contains\">timeout.exe</Image>\n")
		_T("        <Image condition=\"contains\">ping.exe</Image>\n")
		_T("      </ProcessTerminate>\n")
		_T("    </RuleGroup>\n")
		_T("    <ImageLoad onmatch=\"include\"/>\n")
		_T("  </EventFiltering>\n\n"));

	PrintUsageText(csbi,
		_T("In addition the <Rule> element can be used to extend the groupRelation attribute down to individual rules.\n")
		_T("As with RuleGroup these can also have an optional name attribute and can be combined with classic rules.\n")
		_T("The following example demonstrates this usage\n\n")
		_T("  <EventFiltering>\n")
		_T("    <RuleGroup name=\"group 1\" groupRelation=\"or\">\n")
		_T("      <ProcessCreate onmatch=\"include\">\n")
		_T("        <Image condition=\"contains any\">chrome.exe;firefox.exe;iexplore.exe</Image>\n")
		_T("        <Rule name=\"powershell by cmd\" groupRelation=\"and\">\n")		
		_T("          <Image condition=\"end with\">powershell.exe</Image>\n")
		_T("          <ParentImage condition=\"contains\">cmd.exe</ParentImage>\n")
		_T("        </Rule>\n")			
		_T("        <Rule groupRelation=\"and\">\n")
		_T("          <Image condition=\"end with\">cmd.exe</Image>\n")
		_T("          <ParentImage condition=\"end with\">explorer.exe</ParentImage>\n")
		_T("        </Rule>\n")
		_T("      </ProcessCreate>\n")
		_T("    </RuleGroup>\n")
		_T("  </EventFiltering>\n\n"));

	PrintUsageText( csbi,
		_T("To have Sysmon report which rule match resulted in an event being logged, ")
		_T("add names to rules:\n\n")

		_T("  <NetworkConnect onmatch=\"exclude\">\n")
		_T("    <Image name=\"network iexplore\" condition=\"contains\">iexplore.exe</Image>\n")
		_T("  </NetworkConnect>\n\n") );
}
