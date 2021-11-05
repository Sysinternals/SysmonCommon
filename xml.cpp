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
// Xml.cpp
//
// Handle XML parsing, validation and registry writing for
// configuration files
//
//====================================================================

#include "stdafx.h"
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#if defined _WIN64 || defined _WIN32
#include <atlbase.h>
#endif
#include <string>
#include "sysmonevents.h"
#include "xml.h"
#include "rules.h"

#if defined _WIN64 || defined _WIN32

#define ALIGN_DOWN_BY(length, alignment) \
	((ULONG_PTR)(length) & ~(alignment - 1))

#define ALIGN_UP_BY(length, alignment) \
	(ALIGN_DOWN_BY(((ULONG_PTR)(length) + alignment - 1), alignment))

#elif defined __linux__

#define ALIGN_DOWN_BY(length, alignment) \
	((uint64_t)(length) & ~((uint64_t)alignment - 1))

#define ALIGN_UP_BY(length, alignment) \
	(ALIGN_DOWN_BY(((uint64_t)(length) + alignment - 1), (uint64_t)alignment))

#endif

//--------------------------------------------------------------------
//
// ParseVersionString
//
// Parse the version string to a ULONG
//
//--------------------------------------------------------------------
ULONG
ParseVersionString(
	_In_ PCHAR version
)
{
	double	dblVersion;
	char	tmp[40];
	ULONG	acc, cur, ret;
	PCHAR	pos;

	//
	// Normalize the version number
	//
	dblVersion = std::stod( version );
	snprintf( tmp, _countof( tmp ), "%.2f", dblVersion );

	acc = ret = 0;

	for( pos = tmp; *pos != 0; pos++ ) {

		if( *pos == '.' ) {

			if( ret != 0 ) {

				return (ULONG)-1;
			}

			ret = (acc << 16);
			acc = 0;

			// Starts at 1.0
			if( ret == 0 ) {
				
				break;
			}
		} else {

			if( *pos < '0' || *pos > '9' ) {

				return (ULONG)-1;
			}

			cur = (ULONG)(*pos - '0');

			if( cur == 0 && acc == 0 && ret == 0 ) {

				return (ULONG)-1;
			}

			acc = (acc * 10) + cur;

			if( acc > 0xFFFF ) {

				return (ULONG)-1;
			}
		}
	}

	ret |= acc;

	//
	// No seperation
	//
	if( ret < 0xFFFF ) {

		ret <<= 16;
	}

	if( ret == 0 ) {

		return (ULONG)-1;
	}

	return ret;
}

//
// Class to build the rule blob while ensuring offsets are correctly updated.
//
class RuleBuilder
{
private:
	PVOID blob;
	ULONG blobSize;
	ULONG blobAllocated;
	ULONG blobVersion;
	ULONG schemaVersion;
	const ULONG steps = 0x1000;

	ULONG lastEventOffset;			// Used to chain events
	ULONG lastFilterOffset;			// Used to chain filters
	ULONG prevBlobSize;
	ULONG prevLastEventOffset;
	ULONG prevLastFilterOffset;
	ULONG aggregationOffset;		// Used to track the current aggregation when adding filters..

	//
	// Grow the blob buffer
	//
	HRESULT
	Grow(
		_In_ ULONG Bytes
		)
	{
		ULONG remain = (blobAllocated - blobSize);
		if( Bytes == 0 || Bytes <= remain ) {
			
			return S_OK;
		}

		ULONG toAlloc = Bytes > steps ? Bytes : steps;
		toAlloc += blobAllocated;

		if( toAlloc < blobAllocated ) {

			return E_OUTOFMEMORY;
		}

		PVOID newAlloc = NULL;

		if( blob == NULL ) {

			newAlloc = malloc( toAlloc );
		} else {

			newAlloc = realloc( blob, toAlloc );
		}

		if( newAlloc == NULL ) {

			return E_OUTOFMEMORY;
		}

		if( blob == NULL ) {

			ZeroMemory( newAlloc, toAlloc );
		} else {

			ZeroMemory( (PBYTE)newAlloc + blobSize, toAlloc - blobSize );
		}

		blob = newAlloc;
		blobAllocated = toAlloc;
		return S_OK;
	}

	//
	// Append data to the blob
	//
	HRESULT
	AddData(
		_In_ PVOID Ptr,
		_In_ ULONG Size
		)
	{
		ULONG alignSize = ALIGN_UP_BY( Size, sizeof(ULONG64) );

		if( alignSize < Size ) {

			return E_OUTOFMEMORY;
		}
		
		HRESULT hr = Grow( alignSize );

		if( FAILED( hr ) ) {

			return hr;
		}
		
		memcpy( (PBYTE)blob + blobSize, Ptr, Size );
		blobSize += alignSize;
		return S_OK;
	}
	
public:
	RuleBuilder(
		VOID
		)
	{
		blob = NULL;
		blobSize = 0;
		blobAllocated = 0;
		blobVersion = BinaryVersion;
		schemaVersion = ConfigurationVersion;
		lastEventOffset = 0;
		lastFilterOffset = 0;
		prevBlobSize = 0;
		prevLastEventOffset = UINT_MAX;
		prevLastFilterOffset = UINT_MAX;
		aggregationOffset = 0;
	}

	VOID
	SetVersion(
		_In_ ULONG Version
		)
	{
		schemaVersion = Version;
	}

	~RuleBuilder(
		VOID
		)
	{
		if( blob != NULL ) {
			
			free( blob );
		}
	}

	//
	// Get the blob data and size
	//
	VOID
	Detach(
		_Out_ PVOID* Rules,
		_Out_ PULONG RulesSize
		)
	{
		*Rules = blob;
		*RulesSize = blobSize;

		blob = NULL;
		blobSize = 0;
		blobAllocated = 0;
	}

	//
	// Add a base event entry
	//
	HRESULT
	AddEventEntry(
		_In_ PRULE_EVENT RuleEvent
		)
	{
		HRESULT hr;

		prevBlobSize = blobSize;

		//
		// Update previous entry
		//
		if( lastEventOffset != 0 ) {

			PRULE_EVENT prev = (PRULE_EVENT) ((PBYTE)blob + lastEventOffset);
			prev->NextOffset = blobSize;
		} else {

			//
			// No entry so the blob is not set
			//
			D_ASSERT( blob == NULL );
			RULE_REG_EXT baseRule = {{0}};

			baseRule.header.Version = blobVersion;
			baseRule.RuleRegSize = sizeof(baseRule);
			baseRule.SchemaVersion = schemaVersion;
			baseRule.FirstEventOffset = sizeof(baseRule);
			hr = AddData( &baseRule, sizeof(baseRule) );

			if( FAILED( hr ) ) {

				return hr;
			}

			// Now that we have added the header update the offset of the first event to reflect the current location
			// We do this because AddData rounds up the location for the next write to be ptr aligned
			PRULE_REG_EXT header = (PRULE_REG_EXT)blob;
			header->FirstEventOffset = blobSize;
		}

		prevLastEventOffset = lastEventOffset;
		lastEventOffset = blobSize;

		hr = AddData( RuleEvent, sizeof(*RuleEvent) );

		if( FAILED( hr ) ) {

			return hr;
		}

		//
		// Update the rule count
		//
		PRULE_REG pRule = (PRULE_REG)blob;
		pRule->RuleCount++;
		prevLastFilterOffset = lastFilterOffset;
		lastFilterOffset = 0;
		return S_OK;
	}

	HRESULT UndoEventAdd()
	{
		if( lastEventOffset == 0 || (unsigned long)prevLastEventOffset == ULONG_MAX ) {

			// Can't undo more than the very last event (no undo history).
			return E_OUTOFMEMORY;
		}

		PRULE_REG pRule = (PRULE_REG)blob;
		pRule->RuleCount--;
		lastEventOffset = prevLastEventOffset;
		prevLastEventOffset = UINT_MAX;
		lastFilterOffset = prevLastFilterOffset;
		prevLastFilterOffset = UINT_MAX;
		blobSize = prevBlobSize;
		if( lastEventOffset == 0 ) {
			free( blob );
			blob = NULL;
			blobSize = 0;
			blobAllocated = 0;
		}
		return S_OK;
	}

	//
	// Add a filter entry for this current event
	//
	HRESULT
	AddFilterEntry(
		_In_ PRULE_FILTER RuleFilter
		)
	{
		HRESULT hr;
		
		D_ASSERT( lastEventOffset != 0 );
		PRULE_EVENT currentEvent = (PRULE_EVENT)((PBYTE)blob + lastEventOffset);

		//
		// Update the previous entry
		//
		if( lastFilterOffset != 0 ) {

			PRULE_FILTER prev = (PRULE_FILTER)((PBYTE)blob + lastFilterOffset);
			prev->NextOffset = blobSize;
		}

		lastFilterOffset = blobSize;

		// If this is part of an aggregation, set the backpointer to the aggregation object
		if (RuleFilter->AggregationId) {

			PRULE_AGGREGATION currentAggregation = (PRULE_AGGREGATION)((PBYTE)blob + aggregationOffset);
			D_ASSERT(NULL != currentAggregation && currentAggregation->aggregationId == RuleFilter->AggregationId);
			
			// If this is the first entry in the aggregation, update the root node
			if (0 == currentAggregation->rootRuleOffset) {

				currentAggregation->rootRuleOffset = blobSize;
			}
			++currentAggregation->ruleCount;

			RuleFilter->AggregationOffset = aggregationOffset;
		}

		// Because we can now include aggregation objects we can no longer assume that the start of the rule chain
		// is at a fixed offset from the start so we need to make a note of that too
		if (0 == currentEvent->FirstFilterOffset) {

			currentEvent->FirstFilterOffset = blobSize;
		}

		hr = AddData( RuleFilter, sizeof(*RuleFilter) + RuleFilter->DataSize );

		// It's possible that this caused a realloc and invalidated the event pointer so recalculate before we dereference it again
		currentEvent = (PRULE_EVENT)((PBYTE)blob + lastEventOffset);

		if( FAILED( hr ) ) {

			return hr;
		}

		//
		// Update the rule event count
		//
		
		currentEvent->FilterCount++;

		return S_OK;
	}

	//
	// Add a rule aggregation entry
	//
	HRESULT	AddAggregationEntry(_In_ PRULE_AGGREGATION pAggregation)
	{
		HRESULT hr;

		D_ASSERT(lastEventOffset != 0);

		// If we already have an aggregation object then set the next pointer to the new one
		if (aggregationOffset != 0) {

			PRULE_AGGREGATION prev = (PRULE_AGGREGATION)((PBYTE)blob + aggregationOffset);
			prev->nextOffset = blobSize;
		}
		else {
			// Record the address of the first record in the header
			PRULE_REG_EXT header = (PRULE_REG_EXT)blob;
			D_ASSERT(0 == header->FirstAggregationOffset);
			header->FirstAggregationOffset = blobSize;
		}

		// Record the position of the node we are about to add. The rule filters will use this to record
		// which aggregation they belong to. It is also used for chaining aggregation nodes.
		aggregationOffset = blobSize;

		hr = AddData(pAggregation, sizeof(RULE_AGGREGATION));

		if (FAILED(hr)) {

			return hr;
		}

		return S_OK;
	}
};

//--------------------------------------------------------------------
//
// GetFileContentWithDtd
//
// Fetch the content of the configuration file and add dtd info
//
//--------------------------------------------------------------------
#if defined _WIN64 || defined _WIN32
std::wstring
#elif defined __linux__
std::string
#endif
GetFileContentWithDtd(
	_In_ PCTCH FileName,
	_In_ ULONG version
	)
{
	FILE* 			stream;
#if defined _WIN64 || defined _WIN32
	std::wstring 	ret;
#elif defined __linux__
	std::string 	ret;
#endif
	TCHAR			Buffer[2048];
	PTCHAR			dtdContent, startPos, endPos;
	BOOLEAN			firstRead = TRUE;
#if defined _WIN64 || defined _WIN32
	const TCHAR		xmlTag[] = _T("<?xml");
	const TCHAR		endTag[] = _T("?>");
#elif defined __linux__
	WCHAR			xmlTag[] = {'<', '?', 'x', 'm', 'l', 0};
	WCHAR			endTag[] = {'?', '>', 0};
#endif
	size_t			numRead = 0;

	if (NULL == FileName) {
		return ret;
	}
#if defined _WIN64 || defined _WIN32
	errno_t			err;
	err = _tfopen_s(&stream, FileName, _T("r, ccs=UTF-16LE"));

	if (err != 0) {

		SetLastError(err);
		_tprintf(_T("Error: Failed to open configuration file %s: %s\n"), FileName,
			GetLastErrorText(Buffer, _countof(Buffer)));
		return ret;
	}

#elif defined __linux__
	stream = fopen(FileName, "rb");
	if (stream == NULL) {
		printf("Error: Failed to open configuration file %s\n", FileName);
		return ret;
	}
#endif

	//
	// Add the dtd rule to identify bad configuration
	//
	dtdContent = GetDtdFormat(version);

	if (dtdContent == NULL) {

		fclose( stream );
		return ret;
	}

#if defined _WIN64 || defined _WIN32
	std::wstring dtdAndConfig( dtdContent );
	while( (numRead = fread( Buffer, 1, _countof( Buffer ), stream ) / 2) > 0 ) {
#elif defined __linux__
	unsigned int len = _tcslen( dtdContent );

	//
	// dtdAndConfig contains WCHAR data, so is twice the length of dtdContent,
	// minus the terminating NULL.
	// UTF8toUTF16() writes the NULL, so write it to tmp and then
	// copy up to the NULL into dtdAndConfig
	//
	std::string dtdAndConfig( len * sizeof(WCHAR), 0 );
	std::string tmp( ( len + 1) * sizeof(WCHAR), 0 );
	if ( 0 == UTF8toUTF16( (PWCHAR)&tmp[0], dtdContent, len + 1 ) ) {
		printf("Error: Failed to convert the DTD to UTF-16LE\n");
		fclose( stream );
		return ret;
	}

	memcpy( &dtdAndConfig[0], &tmp[0], len * sizeof( WCHAR ) );

	while( (numRead = fread( Buffer, 1, sizeof( Buffer ), stream )) > 0 ) {
#endif

		//
		// Discard <?xml tag if it was added in the front.
		//
		if (firstRead == TRUE) {

			startPos = Buffer;

			while ( startPos[0] != '<' && numRead > 0 ) { // skip white space and BOM

				startPos++;
				numRead--;
			}

			if ( numRead == 0 ) {
				printf( "Error: Too much white space\n" );
				fclose( stream );
				return ret;
			}

			firstRead = FALSE;

			if (!WCSNICMP( (PWCHAR)startPos, xmlTag, WCSLEN( xmlTag ) - 1 ) ) {

				endPos = (PTCHAR) WCSSTR( (PWCHAR)(startPos + WCSLEN( xmlTag ) - 1), endTag );

				if ( endPos != NULL ) {

#if defined _WIN64 || defined _WIN32
					endPos += WCSLEN( endTag );
#elif defined __linux__
					endPos += ( WCSLEN( endTag ) * sizeof( WCHAR ) );
#endif
					dtdAndConfig.append( endPos, numRead - (endPos - startPos) );
					continue;
				}
			}

			dtdAndConfig.append( startPos, numRead );
			continue;
		}

		dtdAndConfig.append( Buffer, numRead );
	}

	fclose(stream);

	return dtdAndConfig;
}

//--------------------------------------------------------------------
//
// GetFileContentWithDtd8
//
// Fetch the 8-bit content of the configuration file and add dtd info
//
//--------------------------------------------------------------------
std::string
GetFileContentWithDtd8(
	_In_ PCCH FileName,
	_In_ ULONG version
)
{
	FILE*			stream;
	std::string 	ret;
	CHAR			Buffer[2048];
	PTCHAR			dtdContent;
	PCHAR			startPos;
	PCHAR			endPos;
	BOOLEAN			firstRead = TRUE;
	const CHAR		xmlTag[] = "<?xml";
	const CHAR		endTag[] = "?>";
	size_t			numRead = 0;

	if( NULL == FileName ) {
		return ret;
	}
	stream = fopen( FileName, "rb" );

	if( stream == NULL ) {

		printf( "Error: Failed to open configuration file: %s\n", FileName);
		return ret;
	}

	//
	// Add the dtd rule to identify bad configuration
	//
	dtdContent = GetDtdFormat( version );

	if( dtdContent == NULL ) {

		fclose( stream );
		return ret;
	}

#if defined _WIN64 || defined _WIN32
	size_t convertedChars = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, dtdContent, (int)_tcslen( dtdContent ), NULL, 0, NULL, NULL );
	std::string dtdAndConfig( convertedChars, 0 ); 
	convertedChars = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, dtdContent, (int)_tcslen( dtdContent ), &dtdAndConfig[0], (int)convertedChars, NULL, NULL );
#elif defined __linux__
	std::string dtdAndConfig( dtdContent );
#endif

	while( (numRead = fread( Buffer, 1, sizeof( Buffer ), stream ) ) > 0 ) {

		//
		// Discard <?xml tag if it was added in the front.
		//
		if( firstRead == TRUE ) {

			startPos = Buffer;

			while( startPos[0] != '<' && numRead > 0 ) { // skip white space and BOM

				startPos++;
				numRead--;
			}

			if( numRead == 0 ) {

				printf( "Error: Too much white space\n" );
				fclose( stream );
				return ret;
			}

			firstRead = FALSE;

			if( !xmlStrncasecmp( (xmlChar*)startPos, (xmlChar*)xmlTag, (int)strlen( xmlTag ) ) ) {

				endPos = strstr( startPos + strlen( xmlTag ), endTag );
					
				if( endPos != NULL ) {

					endPos += strlen( endTag );
					dtdAndConfig.append( endPos, numRead - (endPos - startPos) );
					continue;
				}
			}

			dtdAndConfig.append( startPos, numRead );
			continue;
		}

		dtdAndConfig.append( Buffer, numRead );
	}

	fclose( stream );

	return dtdAndConfig;
}

//--------------------------------------------------------------------
//
// FetchConfigurationVersion
//
// Get the configuration file version
//
//--------------------------------------------------------------------
BOOLEAN
FetchConfigurationVersion(
	_In_ PCTCH FileName,
	_In_ ULONG* Version,
	_Out_ char** XMLEncoding,
	_Out_ BOOLEAN* Is16Bit,
	_Out_ BOOLEAN* HasBOM
)
{
	xmlDoc*					doc = NULL;
	xmlNode*				sysmonNode = NULL;
	xmlXPathContextPtr		xpathCtx;
	xmlChar					xmlSysmonQuery[] = "/Sysmon[1]";
	xmlXPathObjectPtr		xpathObj;
	xmlChar*				versionString = NULL;
	ULONG					version = 0;

	PCHAR					fileEncoding = NULL;
	UCHAR					sniff[1024];
	FILE*					sniff_f = NULL;
	size_t					sniff_read = 0;
	CHAR					utf16le_str[] = "UTF-16LE";

	*XMLEncoding = NULL;
	*Is16Bit = false;
	*HasBOM = false;
#if defined _WIN64 || defined _WIN32
	char					fileName[MAX_PATH];
	size_t					fileNameConv;

	fileNameConv = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, FileName, -1, fileName, sizeof( fileName ), NULL, NULL );
	if( fileNameConv == 0 ) {

		_tprintf( _T( "Error: Failed to load xml configuration: %s (could not convert to char array)\n" ),
					  FileName );
		return FALSE;
	}
	fileName[MAX_PATH-1] = 0x00;
#elif defined __linux__
	const char* fileName = FileName;
#endif
	sniff_f = fopen( fileName, "rb" );

	if( !sniff_f ) {

		_tprintf( _T( "Error: Failed to open xml configuration: %s "), FileName );
		printf( "(%s)\n", strerror( errno ) );
		return FALSE;
	}

	sniff_read = fread( sniff, sizeof(unsigned char), sizeof( sniff ), sniff_f );
	if( sniff_read < 2 ) {

		_tprintf( _T( "Error: Failed to read xml configuration bytes: %s" ), FileName );
		printf( "(%s)\n", strerror( errno ) );
		fclose( sniff_f );
		return FALSE;
	}

	fclose( sniff_f );

	//
	// Configuration files can be encoded in an ASCII-like format (one byte per character)
	// or in a 16-bit format (two bytes per character).  We need to identify whether the
	// file is 8 bit or 16 bit so that later when we attach it to a DTD, we can encode the
	// DTD in the same way (if the file is 8 bit, the DTD must be 8 bit; if the file is 16
	// bit, the DTD must be 16 bit).
	//
	// If a Byte Order Mark (BOM) is present (first byte of file isn't white space or the
	// '<' character), then we can work out if it specifies a 16 bit encoding (first byte
	// is 0xFF) or an 8 bit encoding (any other byte).
	//
	// If no BOM, then we can work out manually if the file is 8 bit or 16 bit by examining
	// the second byte and checking if it is 0x00.  The only valid first characters are
	// '<' or a whitespace character, all of which will have 0x00 as the second byte if
	// the file is 16 bit encoded (as '<', ' ', tab, line feed, carriage return, etc, are
	// all in the ASCII range 0x0000 to 0x007F).
	//

	if( !std::isspace( sniff[0] ) && sniff[0] != '<' ) {

		*HasBOM = true;
		if( sniff[0] == 0xff ) {

			*Is16Bit = true;
		}
	} else {

		if( sniff[1] == 0x00 ) {
			fileEncoding = utf16le_str;
			*Is16Bit = true;
		} else {

			*Is16Bit = false;
		}
	}
	
	//
	// read file with detected file encoding if there was no BOM
	//

#if defined _WIN64 || defined _WIN32
	doc = xmlReadFile( fileName, fileEncoding, 0 );
#elif defined __linux__
	doc = xmlReadFile( FileName, fileEncoding, 0 );
#endif
	if( !doc ) {

		_tprintf( _T( "Error: Failed to load xml configuration: %s (could not read file)\n" ),
					  FileName );
		return FALSE;
	}

	xpathCtx = xmlXPathNewContext( doc );
	if( !xpathCtx ) {

		_tprintf( _T( "Error: Failed to find Sysmon tag in configuration: %s\n" ), FileName );
		xmlFreeDoc( doc );
		return FALSE;
	}

	xpathObj = xmlXPathEvalExpression( xmlSysmonQuery, xpathCtx );
	if( !xpathObj || !xpathObj->nodesetval || xpathObj->nodesetval->nodeNr < 1 ) {

		_tprintf( _T( "Error: Failed to find Sysmon tag in configuration: %s\n" ), FileName );
		if (xpathObj != NULL) {
			xmlXPathFreeObject( xpathObj );
		}
		xmlXPathFreeContext( xpathCtx );
		xmlFreeDoc( doc );
		return FALSE;
	}

	xmlXPathFreeContext( xpathCtx );

	sysmonNode = xpathObj->nodesetval->nodeTab[0];
	versionString = xmlGetProp( sysmonNode, (xmlChar *)"schemaversion" );

	//
	// If an <?xml> tag is present and specifies an encoding, then store this to use when reading
	// the file with the DTD.
	//
	if( doc->encoding ) {

		*XMLEncoding = _strdup( (PCHAR)doc->encoding );
	} else {

		*XMLEncoding = NULL;
	}
	xmlFreeDoc( doc );
	xmlXPathFreeObject ( xpathObj );

	version = ParseVersionString( (PCHAR)versionString );
	if( version == (ULONG)-1 ) {

		printf( "Error: Invalid schema version number (%s) ", versionString );
		_tprintf( _T(" for configuration: %s\n"), FileName );
		xmlFree ( versionString );
		return FALSE;
	}

	*Version = version;

	xmlFree ( versionString );
	return TRUE;
}

//--------------------------------------------------------------------
//
// GetAdditionalRules
//
// Get additional rules based on configuration.
//
//--------------------------------------------------------------------
BOOLEAN
GetAdditionalRules(
	_Out_ PADD_RULES AddRules,
	_In_ ULONG MaxSize
	)
{
	ULONG   i;

	D_ASSERT( MaxSize > 2 );

	i = 0;
	ZeroMemory( AddRules, MaxSize * sizeof(*AddRules) );

	if( (i + 1) > MaxSize ) {

		return FALSE;
	}
	if( OPT_VALUE(ImageLoad) ) {

		AddRules[i].eventType = &SYSMONEVENT_IMAGE_LOAD_Type;
		AddRules[i].fieldId = F_IL_Image;
		AddRules[i].filterOption = Filter_image;
		AddRules[i].dataMultiSz = StringListDup( (PTCHAR)OPT_VALUE(ImageLoad), NULL );
		D_ASSERT( AddRules[i].dataMultiSz != NULL && AddRules[i].dataMultiSz[0] != 0 );
		i++;
	}
	if( (i + 1) > MaxSize ) {

		return FALSE;
	}
	if( OPT_VALUE(NetworkConnect) ) {

		AddRules[i].eventType = &SYSMONEVENT_NETWORK_CONNECT_Type;
		AddRules[i].fieldId = F_NC_Image;
		AddRules[i].filterOption = Filter_image;
		AddRules[i].dataMultiSz = StringListDup( (PTCHAR)OPT_VALUE(NetworkConnect), NULL );
		D_ASSERT( AddRules[i].dataMultiSz != NULL && AddRules[i].dataMultiSz[0] != 0 );
		i++;
	}
	if( (i + 1) > MaxSize ) {

		return FALSE;
	}
	return TRUE;
}

//--------------------------------------------------------------------
//
// FindConfigurationOption
//
// Identify the configuration option matched with the node name
//
//--------------------------------------------------------------------
PCONFIGURATION_OPTION_TYPE
FindConfigurationOption(
	_In_ PTCHAR ConfigurationNode
	)
{
	SIZE_T index;
	const TCHAR configName[] = _T("Config");
	SIZE_T len;

	len = _tcslen( ConfigurationNode );

	//
	// Handle special configuration options
	//
	if( len > ARRAYSIZE(configName) &&
		!_tcscmp( ConfigurationNode + len - ARRAYSIZE(configName) + 1,
				  configName ) ) {

		len -= ARRAYSIZE(configName) - 1;
	}

	for( index = 0; index < ConfigOptionTypeCount; index++ ) {

		if( ConfigOptionType[index].CommandLineOnly ||
			len != ConfigOptionType[index].FieldNameCch ) {

			continue;
		}

		if( !_tcsncmp( ConfigurationNode, ConfigOptionType[index].FieldName, len ) ) {

			return &ConfigOptionType[index];
		}
	}

	return NULL;
}

//--------------------------------------------------------------------
//
// GetFieldIndex
//
// Get the field index for a field name on a rule
//
//--------------------------------------------------------------------
WORD
GetFieldIndex(
	_In_ PSYSMON_EVENT_TYPE_FMT Rule,
	_In_ PTCHAR FieldName
	)
{
	WORD index;

	for( index = 0; index < Rule->FieldCount; index++ ) {

		if( !_tcscmp( Rule->FieldNames[index], FieldName ) ) {

			return index;
		}
	}
	
	return (WORD)-1;
}

//--------------------------------------------------------------------
//
// libxml2Error
//
// Reporting function for libxml2 validation errors
//
//--------------------------------------------------------------------
void XMLCDECL libxml2Error( void* ctx, const char* format, ... )
{
	va_list args;
	va_start( args, format );
	vprintf( format, args );
	va_end( args );
}

//--------------------------------------------------------------------
//
// ApplyConfigurationFile
//
// Main entry point
//
//--------------------------------------------------------------------
extern "C"
BOOLEAN
ApplyConfigurationFile(
	_In_opt_ PCTCH FileName,
	_In_ PVOID*	Rules,
	_In_ PULONG RulesSize,
	_In_ BOOLEAN Transform
	)
{
	HRESULT							hr;
	ULONG							version = 0;
	PCONFIGURATION_OPTION_TYPE		option;
	PSYSMON_EVENT_TYPE_FMT			rule = NULL;
	ADD_RULES						addRules[10] = {{0}};
	ULONG							aggregationId = 0;
#if defined _WIN64 || defined _WIN32
	char							fileName[MAX_PATH];
#elif defined __linux__
	const char*						fileName = FileName;
#endif
	xmlDoc*							xmlDoc = NULL;
	xmlValidCtxt*					xmlValidCtx = NULL;
	xmlXPathContextPtr				xpathCtx = NULL;
	xmlXPathObjectPtr				xpathObj = NULL;
	xmlNode*						curNode = NULL;
	xmlChar							xmlSysmonQuery[] = "/Sysmon[1]";
	xmlChar							xmlEventFilteringQuery[] = "/Sysmon/EventFiltering//%s";
	SIZE_T							index;
	xmlChar							xmlEventQuery[256];
#if defined _WIN64 || defined _WIN32
	char							ruleNameChar[256];
	size_t							convertedChars = 0;
#endif
	char*							xmlEncoding = NULL;
	BOOLEAN							is16bit = false;
	BOOLEAN							hasBOM = false;

	*Rules = NULL;
	*RulesSize = 0;

#if defined _WIN64 || defined _WIN32
	CoInitializeEx( NULL , COINIT_MULTITHREADED);
#endif
	RuleBuilder ruleBuilder;

	if( FileName != NULL ) {

		if( !FetchConfigurationVersion( FileName, &version, &xmlEncoding, &is16bit, &hasBOM ) ) {

			return FALSE;
		}
#if _DEBUG
		if( hasBOM ) {
			printf( "Detected configuration file has BOM\n" );
		} else {
			printf( "No configuration file BOM detected\n" );
		}

		if( is16bit ) {
			printf( "Detected configuration file format is wide character set\n" );
		} else {
			printf( "Detected configuration file format is single-width character set\n" );
		}
		
		if( xmlEncoding ) {
			printf( "Detected XML encoding: '%s'\n", xmlEncoding );
		}
#endif
		_tprintf( _T( "Loading configuration file with schema version %.2f\n" ), TO_DOUBLE( version ) );

		//
		// If the version is not an exact match, remind the current schema version
		//
		if( version != ConfigurationVersion ) {
		
			_tprintf( _T("Sysmon schema version: %.2f\n"), TO_DOUBLE(ConfigurationVersion) );
		}

		ruleBuilder.SetVersion( version );
	
#if defined _WIN64 || defined _WIN32
		convertedChars = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, FileName, -1, fileName, sizeof(fileName), NULL, NULL );
		if (convertedChars == 0 ) {
			_tprintf( _T( "LIBXML2 Error: Failed to convert xml configuration filename: %s\n" ), FileName );
			return FALSE;
		}
		fileName[sizeof(fileName)-1] = 0x00;
#endif

		if( is16bit ) {

			//
			// Get the data from the configuration file
			//
#if defined _WIN64 || defined _WIN32
			std::wstring data = GetFileContentWithDtd( FileName, version );
			int dataLen = (int)(data.size() * sizeof ( WCHAR ));
#elif defined __linux__
			std::string data = GetFileContentWithDtd( FileName, version );
			int dataLen = data.size();
#endif

			if( dataLen == 0 ) {

				return FALSE;
			}

#if 0
			DBG_MODE_VERBOSE( _tprintf( _T( "[DBG] XML:\n%s\n\n" ), data.c_str() ) )
#endif

			//
			// Load the document with libxml2
			//
			xmlDoc = xmlReadMemory( (char*)data.c_str(), dataLen, fileName, "UTF-16LE", 0 );

		} else {

			//
			// Get the data from the configuration file
			//
			std::string data = GetFileContentWithDtd8( fileName, version );

			if( data.size() == 0 ) {

				return FALSE;
			}

#if 0
			DBG_MODE_VERBOSE( printf( "[DBG] XML:\n%s\n\n", data.c_str() ) )
#endif

			//
			// Load the document with libxml2
			//
			xmlDoc = xmlReadMemory( (char*)data.c_str(), (int)data.size(), fileName, xmlEncoding, 0 );

		}

		if( xmlDoc == NULL ) {
			_tprintf( _T( "LIBXML2 Error: Failed to load xml configuration: %s\n" ), FileName );
			return FALSE;
		}

		//
		// Validate the file based on the dtd
		//
		xmlValidCtx = xmlNewValidCtxt();
		if( !xmlValidCtx ) {
			printf( "LIBXML2 Error: Failed to create libxml2 validation context\n" );
			xmlFreeDoc( xmlDoc );
			return FALSE;
		}

		xmlValidCtx->error = libxml2Error;
		xmlValidCtx->warning = libxml2Error;
		if( !xmlValidateDocument( xmlValidCtx, xmlDoc ) ) {
			_tprintf( _T( "LIBXML2 Error: Failed to validate the xml configuration: %s\n" ), FileName );
			xmlFreeValidCtxt( xmlValidCtx );
			xmlFreeDoc( xmlDoc );
			return FALSE;
		}

		xmlFreeValidCtxt( xmlValidCtx );

		//
		// Handle configuration
		//
		xpathCtx = xmlXPathNewContext( xmlDoc );
		if( !xpathCtx ) {
			_tprintf( _T( "Error: Failed to find Sysmon tag in configuration: %s\n" ), FileName );
			xmlFreeDoc( xmlDoc );
			return FALSE;
		}

		xpathObj = xmlXPathEvalExpression( xmlSysmonQuery, xpathCtx );
		if( !xpathObj || !xpathObj->nodesetval || xpathObj->nodesetval->nodeNr < 1 ) {
			_tprintf( _T( "Error: Failed to find configuration node: %s\n" ), FileName );
			if ( xpathObj != NULL ) {
				xmlXPathFreeObject( xpathObj );
			}
			xmlXPathFreeContext( xpathCtx );
			xmlFreeDoc( xmlDoc );
			return FALSE;
		}

		for( curNode = xpathObj->nodesetval->nodeTab[0]->children; curNode; curNode = curNode->next ) {
			if( curNode->type == XML_ELEMENT_NODE ) {
				if( !strcmp( (char*)curNode->name, "EventFiltering" ) ) {
					continue;
				}

				char* nodeContent;
				nodeContent = (char*)xmlNodeListGetString( xmlDoc, curNode->xmlChildrenNode, 1 );
				if( !nodeContent ) {
					break;
				}

#if defined _WIN64 || defined _WIN32
				CA2T nodeContent_t( nodeContent, CP_UTF8 );
				CA2T nodeName( (const char *)curNode->name, CP_UTF8 );
#elif defined __linux__
				PTCHAR nodeContent_t = nodeContent;
				PTCHAR nodeName = (char *)curNode->name;
#endif

				option = FindConfigurationOption( nodeName );

				if( option == NULL ) {

					hr = E_INVALIDARG;
					xmlFree( nodeContent );
					break;
				}

				if( option->ValueFlag == ConfigNoValue && nodeContent[0] != 0 ) {

					//
					// This element is disabled
					//
					if( !strcmp( nodeContent, "false" ) ||
						!strcmp( nodeContent, "0" ) ||
						!strcmp( nodeContent, "NULL" ) ||
						!strcmp( nodeContent, "disabled" ) ) {

						xmlFree( nodeContent );
						continue;
					}

					if( !strcmp( nodeContent, "true" ) &&
						!strcmp( nodeContent, "1" ) &&
						!strcmp( nodeContent, "enabled" ) ) {

						printf( "Error: Incorrect value '%s' for node", nodeContent );
						_tprintf( _T( " '%s'\n" ), option->FieldName );

						xmlFree( nodeContent );
						break;
					}

				}

				if( option->Option->IsSet ) {

#if defined _WIN64 || defined _WIN32
					if( option->ValueFlag != ConfigNoValue &&
						option->Option->Value != NULL && 
						nodeContent_t != (BSTR)option->Option->Value ) {
#elif defined __linux__
					if( option->ValueFlag != ConfigNoValue &&
						option->Option->Value != NULL && 
						0 == strcmp(nodeContent_t, (PTCHAR)option->Option->Value) ) {
#endif

						_tprintf( _T( "Warning: Command-line switch '%s' was overwritten by configuration node '%s' value\n" ),
							option->Switch, option->FieldName );
					}

					option->Option->Value = NULL;
					option->Option->Size = 0;
				}

				option->Option->IsSet = TRUE;

				if( nodeContent[0] != 0 ) {

					option->Option->Value = _tcsdup( nodeContent_t );

					if( option->Option->Value == NULL ) {

						hr = E_OUTOFMEMORY;

						xmlFree( nodeContent );
						break;
					}

					option->Option->Size = (ULONG)(_tcslen( (PTCHAR)option->Option->Value ) + 1) * sizeof( TCHAR );
					option->Option->ValueAllocated = TRUE;
				}
				xmlFree( nodeContent );

			}
		}

		if ( xpathObj ) {
			xmlXPathFreeObject ( xpathObj );
			xpathObj = NULL;  // This variable is used later in the function so re-initialize it
		}

		if( !GetAdditionalRules( addRules, _countof( addRules ) ) ) {

			_tprintf( _T( "Error: Failed to compute additional rules.\n" ) );
			return FALSE;
		}

		//
		// Handle rules
		//
		// Iterate through all the event types that have rule names, handling each duplicate only once
		// (for events such as RegistryEvent that has multiple event types with the same rule name).
		// Use XPath to search for event nodes using "/Sysmon/EventFiltering//EVENT_TYPE".
		// Check parents to see if they are RuleGroup nodes.
		//
		// Remainder of this function is directly ported from the MSXML version.

		for( index = 0; index < AllEventsCount; index++ ) {

			if( AllEvents[index]->RuleName != NULL ) {

				//
				// Frame all the duplicate rules (we assume they're consecutive in manifest.xml!!
				// between indexFirstOfSeries and (exclusively) indexLastOfSeries.
				//
				// 
				SIZE_T indexFirstOfSeries = index;
				SIZE_T indexLastOfSeries = indexFirstOfSeries + 1;
				while( indexLastOfSeries < AllEventsCount && AllEvents[indexLastOfSeries]->RuleName != NULL &&
					0 == _tcscmp( AllEvents[indexLastOfSeries]->RuleName, AllEvents[index]->RuleName ) ) {

					indexLastOfSeries++;
				}

				rule = AllEvents[index];
				// Force the for loop to jump over the series of duplicates.
				index = indexLastOfSeries - 1;

#if defined _WIN64 || defined _WIN32
				convertedChars = WideCharToMultiByte( CP_UTF8, WC_ERR_INVALID_CHARS, rule->RuleName, -1, ruleNameChar, sizeof( ruleNameChar ), NULL, NULL );
				if (convertedChars == 0 ) {
					_tprintf( _T( "Failed to convert rule name: '%s'\n" ), rule->RuleName );
					continue;
				}
				ruleNameChar[sizeof(ruleNameChar)-1] = 0x00;

				//
				// Find event node
				//
				snprintf( (char*)xmlEventQuery, sizeof( xmlEventQuery ), (char*)xmlEventFilteringQuery, ruleNameChar );
#elif defined __linux__
				snprintf( (char*)xmlEventQuery, sizeof( xmlEventQuery ), (char*)xmlEventFilteringQuery, rule->RuleName );
#endif
				if ( xpathObj ) {
					xmlXPathFreeObject ( xpathObj );
				}
				xpathObj = xmlXPathEvalExpression( xmlEventQuery, xpathCtx );
				if( !xpathObj || !xpathObj->nodesetval || xpathObj->nodesetval->nodeNr < 0 ) {
					printf( "Error: Failed to find event node: %s\n", (char*)xmlEventQuery );
					if ( xpathObj != NULL ) {
						xmlXPathFreeObject( xpathObj );
						xpathObj = NULL;
					}
					continue;
				}

				if( xpathObj->nodesetval->nodeNr == 0 ) {
					xmlXPathFreeObject( xpathObj );
					xpathObj = NULL;
					continue;
				}

				//
				// Iterate over found event nodes
				//
#if defined _WIN64 || defined _WIN32
				std::wstring breakingField;
#elif defined __linux__
				std::string breakingField;
#endif

				bool isValidXml = true;
				for( int nodeIndex = 0; isValidXml && nodeIndex < xpathObj->nodesetval->nodeNr; nodeIndex++ ) {

					bool ruleFromSeriesFound = false;
					for( SIZE_T ruleIndex = indexFirstOfSeries; !ruleFromSeriesFound && ruleIndex < indexLastOfSeries; ruleIndex++ ) {
						// Optimistically assume that this rule is the one that satisfies the criteria in the config.
						ruleFromSeriesFound = true;

						rule = AllEvents[ruleIndex];
						curNode = xpathObj->nodesetval->nodeTab[nodeIndex];

						xmlChar* groupRuleName = NULL;

						RuleCombineType ruleCombineType = TO_DOUBLE( version ) > 4.1
							? RuleCombineAND
							: RuleCombineOR; // Default to OR on 4.1 for backwards compatibility

						// #397. For AND/OR logic we added an optional RuleGroup node. If no rule groups are used we default to OR for backwards compatibility on 4.1 and earlier
						// If a rule group is defined but no groupRelation is specified then we default to AND as per the documentation.

						if( 0 == xmlStrcasecmp( curNode->parent->name, (xmlChar*)"RuleGroup" ) ) {
							xmlChar* combineType = NULL;

							combineType = xmlGetProp( curNode->parent, (xmlChar*)"groupRelation" );
							if( combineType ) {

								if( 0 == xmlStrcasecmp( combineType, (xmlChar*)"or" ) ) {

									ruleCombineType = RuleCombineOR;
								} else {
									// should be validated by the schema
									D_ASSERT( 0 == xmlStrcasecmp( combineType, (xmlChar*)"and" ) );
									ruleCombineType = RuleCombineAND;
								}

								xmlFree( combineType );
							}
							groupRuleName = xmlGetProp( curNode->parent, (xmlChar*)"name" );
						}

						RuleDefaultType ruleDef;

						xmlChar* ruleMatch = NULL;
						xmlChar* ruleDefault = NULL;
						ruleMatch = xmlGetProp( curNode, (xmlChar*)"onmatch" );
						ruleDefault = xmlGetProp( curNode, (xmlChar*)"default" );

						if( !ruleMatch ) {

							//
							// Check default field
							//
							if( !ruleDefault ) {
								_tprintf( _T( "Error: You need to specifiy the onmatch attribute on %s.\n" ), rule->RuleName );
								hr = E_INVALIDARG;
								break;
							} else {

								ruleDef = GetRuleDefault( (const char *)ruleDefault );
							}
						} else {

							//
							// Check there is no default field
							//
							if( ruleDefault ) {

								_tprintf( _T( "Error: Can't specify onmatch and default on %s (pick only one)\n" ), rule->RuleName );
								hr = E_INVALIDARG;
								break;
							}

							ruleDef = GetRuleMatch( (const char *)ruleMatch );

							xmlFree( ruleMatch );
						}

						if( ruleDefault != NULL ) {
							xmlFree( ruleDefault );
						}

						if( ruleDef == Rule_Unknown ) {

							ruleDef = rule->Default;
						}

						PADD_RULES addMatch = NULL;

						//
						// Look at additional rules
						//
						for( ULONG a = 0; addRules[a].eventType != NULL; a++ ) {

							if( addRules[a].eventType == rule ) {

								addMatch = &addRules[a];
								break;
							}
						}

						//
						// A different default means we cannot create a compatible ruleset
						//
						if( addMatch != NULL && ruleDef != addMatch->eventType->Default ) {

							_tprintf( _T( "Error: Incompatible configuration and command-line rule on %s" ),
								rule->RuleName );

							hr = E_INVALIDARG;
							break;
						}

						RULE_EVENT newEvent = { 0, };
						newEvent.EventId = rule->EventId;
						newEvent.RuleDefault = ruleDef;
						newEvent.CombineType = ruleCombineType;
						hr = ruleBuilder.AddEventEntry( &newEvent );
						D_ASSERT( SUCCEEDED( hr ) );

						if( FAILED( hr ) ) {

							break;
						}

						//
						// Add additional rules first
						//
						if( addMatch != NULL ) {

							PTCHAR pos = addMatch->dataMultiSz;

							while( *pos != 0 ) {

								ULONG dataSize = (ULONG)(_tcslen( pos ) + 1) * sizeof( WCHAR );
								ULONG allocSize = sizeof( RULE_FILTER ) + dataSize;
								PRULE_FILTER ruleFilter = (PRULE_FILTER)malloc( allocSize );

								if( ruleFilter == NULL ) {

									hr = E_OUTOFMEMORY;
									D_ASSERT( SUCCEEDED( hr ) );
									break;
								}
								ZeroMemory( ruleFilter, allocSize );
								ruleFilter->FieldId = addMatch->fieldId;
								ruleFilter->FilterType = addMatch->filterOption;
								ruleFilter->DataSize = dataSize;
#if defined _WIN64 || defined _WIN32
								memcpy( ruleFilter->Data, pos, dataSize );
#elif defined __linux__
								UTF8toUTF16( (PWCHAR)ruleFilter->Data, pos, dataSize / sizeof( WCHAR ) );
#endif

								hr = ruleBuilder.AddFilterEntry( ruleFilter );
								free( ruleFilter );

								if( FAILED( hr ) ) {

									D_ASSERT( SUCCEEDED( hr ) );
									break;
								}

								pos += _tcslen( pos ) + 1;
							}

							if( FAILED( hr ) ) {

								break;
							}

							free( addMatch->dataMultiSz );
							addMatch->dataMultiSz = NULL;
						}

						//
						// curNode is the Event level node (ie ProcessCreate). Each child item is either 
						// a rule or a <rule> element.
						// Iterate over all children of event node.
						//
						xmlNode* sub;
						for( sub = curNode->children; isValidXml && ruleFromSeriesFound && sub; sub = sub->next ) {

							if( sub->type == XML_ELEMENT_NODE ) { // only interested in elements, not comments or whitespace

								PRULE_FILTER ruleFilter;
								bool isAggregation = FALSE;
								xmlNode* currentRule = sub;
								xmlChar* curRuleName = groupRuleName;

								if( 0 == xmlStrcasecmp( currentRule->name, (xmlChar*)"rule" ) ) {

									xmlChar* combineType;
									RuleCombineType aggregateCombineType = RuleCombineDefault;

									combineType = xmlGetProp( sub, (xmlChar*)"groupRelation" );

									if( combineType ) {

										if( 0 == xmlStrcasecmp( combineType, (xmlChar*)"or" ) ) {

											aggregateCombineType = RuleCombineOR;
										} else {

											// should be validated by the schema
											D_ASSERT( 0 == xmlStrcasecmp( combineType, (xmlChar*)"and" ) );
											aggregateCombineType = RuleCombineAND;
										}

										xmlFree( combineType );
									}

									RULE_AGGREGATION aggregation;
									ZeroMemory( &aggregation, sizeof( RULE_AGGREGATION ) );
									aggregation.aggregationId = ++aggregationId;
									aggregation.combineType = aggregateCombineType;

									// Rule may contain an optional name attribute
									xmlChar* ruleName;

									ruleName = xmlGetProp( currentRule, (xmlChar*)"name" );
									if( ruleName ) {
										// Replace rulegroup for aggregate name.
										curRuleName = ruleName;
#if defined _WIN64 || defined _WIN32
										MultiByteToWideChar( CP_UTF8, 0, (char*)ruleName, -1,
												aggregation.name, _countof( aggregation.name ) );
										aggregation.name[_countof( aggregation.name )-1] = 0x00;
#elif defined __linux__
										UTF8toUTF16( aggregation.name, (PCHAR)ruleName, _countof( aggregation.name ) );
#endif
									}

									ruleBuilder.AddAggregationEntry( &aggregation );
									isAggregation = true;

								}

								//
								// <rule> loop 
								// Iterate over the rule nodes. These can be either individual rules (in which case we only go through
								// the following loop once) or rule aggregations that are bound via the <rule> tag, in which case
								// we iterate over the children of the rule node.
								//
								xmlNode* subsub = currentRule;
								if( 0 == xmlStrcasecmp( currentRule->name, (xmlChar*)"rule" ) ) {
									subsub = currentRule->children;
								}

								do {
									if( subsub->type == XML_ELEMENT_NODE ) { // only interested in elements
#if defined _WIN64 || defined _WIN32
										CA2T subName( (char*)subsub->name, CP_UTF8 );
#elif defined __linux__
										PTCHAR subName = (PTCHAR)subsub->name;
#endif
										ULONG fieldId = GetFieldIndex( rule, subName );

										if( fieldId == (WORD)-1 ) {

											ruleFromSeriesFound = false;
											ruleBuilder.UndoEventAdd();
											breakingField = subName;
											break;
										}

										xmlChar* ruleNameP = xmlGetProp( subsub, (xmlChar*)"name" );
										xmlChar* ruleName = ruleNameP;

										// If no name was explicit on the field, use the sub-rule or rulegroup name.
										if( ruleName == nullptr ) {

											ruleName = curRuleName;
										}

										if( ruleName != nullptr &&
											strlen( (char*)ruleName ) >  _countof( ruleFilter->Name ) - 1 ) {

											printf( "Error: Rule name is larger than 255 characters: %s\n", (char*)ruleName );
											hr = E_INVALIDARG;
											xmlFree( ruleNameP );
											break;
										}

										xmlChar* attrCondValue;
										attrCondValue = xmlGetProp( subsub, (xmlChar*)"condition" );

										FilterOption foption = GetFilterOption( (const char *)attrCondValue );

										if( foption == Filter_Unknown ) {

											printf( "Error: Unknown condition: %s\n", (char*)attrCondValue );
											_tprintf( _T( "Expected values are " ) SYSMON_FILTER_CONDITIONS );
											hr = E_INVALIDARG;
                                            xmlFree( attrCondValue );
											xmlFree( ruleNameP );
											break;
										}

										if( attrCondValue != NULL ) {
											xmlFree( attrCondValue );
										}

										xmlChar emptyBuffer[] = "";
										xmlChar* subValueChar = xmlNodeListGetString( xmlDoc, subsub->xmlChildrenNode, 1 );
										if( subValueChar == nullptr ) {
											subValueChar = emptyBuffer;
										}
#if defined _WIN64 || defined _WIN32
										CA2T subValue( (char*)subValueChar, CP_UTF8 );
										ULONG dataSize = ((ULONG)_tcslen( subValue ) + 1) * sizeof( TCHAR );
#elif defined __linux__
										ULONG numDataChars = (ULONG)strlen( (PCHAR)subValueChar ) + 1;
										WCHAR subValue[numDataChars];
										UTF8toUTF16( subValue, (PCHAR)subValueChar, numDataChars );
										ULONG dataSize = ((ULONG)WideStrlen( subValue ) + 1) * sizeof( WCHAR );
#endif

										if( subValueChar != emptyBuffer ) {
											xmlFree( subValueChar );
										}

										ULONG allocSize = sizeof( RULE_FILTER ) + dataSize;
										ruleFilter = (PRULE_FILTER)malloc( allocSize );

										if( ruleFilter == NULL ) {

											xmlFree( ruleNameP );
											hr = E_OUTOFMEMORY;
											D_ASSERT( SUCCEEDED( hr ) );
											break;
										}
										ZeroMemory( ruleFilter, allocSize );
										ruleFilter->FieldId = fieldId;
										ruleFilter->FilterType = foption;
										ruleFilter->DataSize = dataSize;
										ruleFilter->AggregationId = isAggregation ? aggregationId : 0;

										if( ruleName ) {
#if defined _WIN64 || defined _WIN32
											CA2T ruleName_t( (char*)ruleName, CP_UTF8 );
											_tcscpy( ruleFilter->Name, ruleName_t );
#elif defined __linux__
											UTF8toUTF16( ruleFilter->Name, (PCHAR)ruleName,
													sizeof( ruleFilter->Name ) / sizeof( *(ruleFilter->Name) ) );
#endif
										}
										if( ruleNameP != NULL ) {
											xmlFree( ruleNameP );
										}

#if defined _WIN64 || defined _WIN32
										memcpy( ruleFilter->Data, (BSTR)subValue, dataSize - sizeof( WCHAR ) );
#elif defined __linux__
										memcpy( ruleFilter->Data, subValue, dataSize - sizeof( WCHAR ) );
#endif

										hr = ruleBuilder.AddFilterEntry( ruleFilter );
										free( ruleFilter );

										if( FAILED( hr ) ) {

											D_ASSERT( SUCCEEDED( hr ) );
											break;
										}
									}

									//
									// If this is a child of a rule node, then iterate to next sibling.
									// Otherwise make this loop a one-shot.
									//
									if( 0 == xmlStrcasecmp( currentRule->name, (xmlChar*)"rule" ) ) {
										subsub = subsub->next;
									} else {
										subsub = NULL;
									}
								} while( subsub );

								if( FAILED( hr ) ) {

									_tprintf( _T( "Error: Failed to convert EventFiltering nodes: %s\n" ), FileName );
									return FALSE;
								}
							}
						}
						if( groupRuleName != NULL ) {
							xmlFree( groupRuleName );
						}
					}
					if( !ruleFromSeriesFound ) {
						// This means that from all possible rules with the same name, none of them has the same properties as this
						// specific xml entry, so the config asks for fields not specified by the schema.
						isValidXml = false;

						hr = E_INVALIDARG;
						_tprintf( _T( "Incorrect field %s\n" ), breakingField.c_str() );
						D_ASSERT( SUCCEEDED( hr ) );

					}
				}
			}
		}

		if ( xpathObj ) {
			xmlXPathFreeObject ( xpathObj );
		}
		xmlXPathFreeContext( xpathCtx );
		xmlFreeDoc( xmlDoc );
	} else {

		if( !GetAdditionalRules( addRules, _countof(addRules) ) ) {

			_tprintf( _T("Error: Failed to compute additional rules.\n") );
			return FALSE;
		}

#if defined _WIN64 || defined _WIN32
		//
		// No additional rules means nothing to do
		//
		if( addRules[0].eventType == NULL ) {

			return TRUE;
		}
#endif
	}

	//
	// Process elements that were not already added
	//
	if( addRules[0].eventType != NULL ) {
		
		hr = ERROR_SUCCESS;
		for( ULONG i = 0; addRules[i].eventType != NULL; i++ ) {

			if( addRules[i].dataMultiSz == NULL || addRules[i].dataMultiSz[0] == 0 ) {

				continue;
			}

			RULE_EVENT newEvent = {0,};
			newEvent.EventId = addRules[i].eventType->EventId;
			newEvent.RuleDefault = addRules[i].eventType->Default;

			hr = ruleBuilder.AddEventEntry( &newEvent );
			D_ASSERT( SUCCEEDED( hr ) );

			if( FAILED( hr ) ) {

				break;
			}

			PTCHAR pos = addRules[i].dataMultiSz;

			while( *pos != 0 ) {

				ULONG dataSize = (ULONG)(_tcslen( pos ) + 1) * sizeof( WCHAR );
				ULONG allocSize = sizeof( RULE_FILTER ) + dataSize;
				PRULE_FILTER ruleFilter = (PRULE_FILTER) malloc( allocSize );

				if( ruleFilter == NULL ) {

					hr = E_OUTOFMEMORY;
					D_ASSERT( SUCCEEDED( hr ) );
					break;
				}
				ZeroMemory( ruleFilter, allocSize );
				ruleFilter->FieldId = addRules[i].fieldId;
				ruleFilter->FilterType = addRules[i].filterOption;
				ruleFilter->DataSize = dataSize;
#if defined _WIN64 || defined _WIN32
				memcpy( ruleFilter->Data, pos, dataSize );
#elif defined __linux__
				UTF8toUTF16( (PWCHAR)(ruleFilter->Data), pos, dataSize / sizeof( WCHAR ) );
#endif

				hr = ruleBuilder.AddFilterEntry( ruleFilter );
				D_ASSERT( SUCCEEDED( hr ) );
				free( ruleFilter );

				if( FAILED( hr ) ) {

					break;
				}

				pos += _tcslen( pos ) + 1;
			}

			free( addRules[i].dataMultiSz );
			addRules[i].dataMultiSz = NULL;

			if( FAILED( hr ) ) {

				break;
			}
		}
		
		if( FAILED( hr ) ) {

			_tprintf( _T("Error: Failed to convert additional command-line rules\n") );
			return FALSE;
		}
	}

	ruleBuilder.Detach( Rules, RulesSize );

	//
	// Be sure we enable or disable options if needed
	//
	if( !InitializeRules() || !SetRuleBlob( *Rules, *RulesSize, Transform ) ) {

		_tprintf( _T("Error: Failed to correctly compute rule binary format\n") );
		return FALSE;
	}

	RULE_CONTEXT ruleContext;
	if( InitializeRuleContext( &ruleContext ) ) {

		PRULE_EVENT		ruleEvent;
#if !defined(SYSMON_SHARED) && !defined(SYSMON_PUBLIC)
		FILE*			dumpF = NULL;
		PTCHAR			outputRules;
		TCHAR			dumpFile[MAX_PATH];
		PTCHAR			prevRuleName = NULL;
		RuleDefaultType		prevRuleType = Rule_Unknown;
		PRULE_FILTER	ruleFilter;
		PTCHAR			fieldName;
		ULONG			currentAggregation = 0;

		//
		// If the OutputConfiguration switch is present, then write the human readable form
		// to the given filename.  Then exit after taking action, and exit on error.
		//
		if( OPT_SET( OutputRules ) ) {
			outputRules = (PTCHAR)OPT_VALUE( OutputRules );
			printf( "Output the human readable rules\n" );
			if( !outputRules || !*outputRules ) {
				printf( "Output Rules file name missing\n" );
				exit( -1 );
			}
			_stprintf_s( dumpFile, MAX_PATH, _T( "%s" ), outputRules );
			_tprintf( _T( "Writing to: '%s'\n" ), dumpFile );
			dumpF = _tfopen( dumpFile, _T( "wb" ) );
			if( !dumpF ) {
				printf( "Cannot create output file\n" );
				exit( -1 );
			}
		}
#endif

		for( ruleEvent = NextRuleEvent( &ruleContext, NULL );
			 ruleEvent != NULL;
			 ruleEvent = NextRuleEvent( &ruleContext, ruleEvent ) ) {

			PSYSMON_EVENT_TYPE_FMT eventTypeFmt = FindEventTypeFromId( ruleEvent->EventId );

			if( eventTypeFmt == NULL ) {

				continue;
			}

			option = FindConfigurationOption( eventTypeFmt->RuleName );

			if( option == NULL || !option->OnRule ) {

				if( option != NULL && option->CommandLineOnly ) {

					_tprintf( _T( "Warning: The event '%s' cannot be automatically enabled.\n" ),
							  eventTypeFmt->RuleName );
				}
			} else {

				//
				// Disabled if no filter and exclude by default
				//
				if( ruleEvent->FilterCount == 0 &&
					ruleEvent->RuleDefault == Rule_exclude ) {

					option->Option->IsSet = FALSE;
				} else {

					option->Option->IsSet = TRUE;
				}
			}
#if !defined(SYSMON_SHARED) && !defined(SYSMON_PUBLIC)
			if( OPT_SET( OutputRules ) ) {

				// Don't repeat overloaded event type names. Note that we can have include and exclude rules for the
				// same event so we need to check both the name and the type
				if( prevRuleName && !_tcscmp( prevRuleName, eventTypeFmt->RuleName ) &&
					prevRuleType == ruleEvent->RuleDefault ) {

					continue;
				}

				prevRuleName = eventTypeFmt->RuleName;
				prevRuleType = ruleEvent->RuleDefault;

				_ftprintf( dumpF, _T( " - " ) _T( CONFIG_FMT ) _T( " onmatch: %s   combine rules using '%s'\n" ),
					eventTypeFmt->RuleName,
					GetRuleMatchName( ruleEvent->RuleDefault ),
					RuleCombineOR == ruleEvent->CombineType ? _T( "Or" ) : RuleCombineAND == ruleEvent->CombineType ? _T( "And" ) : _T( "Unknown" ) );

				for( ruleFilter = NextRuleFilter( &ruleContext, ruleEvent, NULL );
					ruleFilter != NULL;
					ruleFilter = NextRuleFilter( &ruleContext, ruleEvent, ruleFilter ) ) {

					fieldName = GetFieldName( eventTypeFmt, ruleFilter->FieldId );

					if( fieldName == NULL ) {

						continue;
					}

#if defined __linux__

					int ruleFilterDataSize = WideStrlen((PWCHAR)(ruleFilter->Data)) + 1;
					CHAR ruleFilterData[ruleFilterDataSize * 4];
					UTF16toUTF8(ruleFilterData, (PWCHAR)(ruleFilter->Data), ruleFilterDataSize * 4);
#endif
					if( ruleFilter->AggregationId ) {

						if( ruleFilter->AggregationId != currentAggregation ) {

							PRULE_CONTEXT pContext = &ruleContext;
							PRULE_AGGREGATION pAggregation = AGGREGATION_FROM_OFFSET( pContext, ruleFilter->AggregationOffset );

#if defined _WIN64 || defined _WIN32
							if( wcslen( pAggregation->name ) )
								_ftprintf_s( dumpF, _T( "\tCompound Rule %.32s   combine using %s\n" ), pAggregation->name,
									RuleCombineOR == pAggregation->combineType ? _T( "Or" ) : RuleCombineAND == pAggregation->combineType ? _T( "And" ) : _T( "Unknown" ) );
							else
								_ftprintf_s( dumpF, _T( "\tCompound Rule %04d   combine using %s\n" ), ruleFilter->AggregationId,
									RuleCombineOR == pAggregation->combineType ? _T( "Or" ) : RuleCombineAND == pAggregation->combineType ? _T( "And" ) : _T( "Unknown" ) );

#elif defined __linux__
							int aggNameSize = sizeof(pAggregation->name) / sizeof(pAggregation->name[0]);
							CHAR aggName[aggNameSize];
							UTF16toUTF8(aggName, pAggregation->name, aggNameSize);
							if( WideStrlen( pAggregation->name ) )
								_ftprintf_s( dumpF, _T( "\tCompound Rule %.32s   combine using %s\n" ), aggName,
									RuleCombineOR == pAggregation->combineType ? _T( "Or" ) : RuleCombineAND == pAggregation->combineType ? _T( "And" ) : _T( "Unknown" ) );
							else
								_ftprintf_s( dumpF, _T( "\tCompound Rule %04d   combine using %s\n" ), ruleFilter->AggregationId,
									RuleCombineOR == pAggregation->combineType ? _T( "Or" ) : RuleCombineAND == pAggregation->combineType ? _T( "And" ) : _T( "Unknown" ) );
#endif

							currentAggregation = ruleFilter->AggregationId;
						}

#if defined _WIN64 || defined _WIN32
						_ftprintf( dumpF, _T( "\t    %-30s filter: %-12s value: '%s'\n" ), fieldName,
							GetFilterName( ruleFilter->FilterType ), (LPTSTR)ruleFilter->Data );
#elif defined __linux__
						_ftprintf( dumpF, _T( "\t    %-30s filter: %-12s value: '%s'\n" ), fieldName,
							GetFilterName( ruleFilter->FilterType ), ruleFilterData );
#endif
					} else {

#if defined _WIN64 || defined _WIN32
						_ftprintf( dumpF, _T( "\t%-30s filter: %-12s value: '%s'\n" ), fieldName,
							GetFilterName( ruleFilter->FilterType ), (LPTSTR)ruleFilter->Data );
#elif defined __linux__
						_ftprintf( dumpF, _T( "\t%-30s filter: %-12s value: '%s'\n" ), fieldName,
							GetFilterName( ruleFilter->FilterType ), ruleFilterData );
#endif
					}
				}
			}
#endif
		}

		ReleaseRuleContext( &ruleContext );

#if !defined(SYSMON_SHARED) && !defined(SYSMON_PUBLIC)
		if( OPT_SET( OutputRules ) ) {
			fclose( dumpF );
			exit( 0 );
		}
#endif
	}

	if( FileName ) {

		_tprintf( _T("Configuration file validated.\n") );
	}
	
	return TRUE;
}
