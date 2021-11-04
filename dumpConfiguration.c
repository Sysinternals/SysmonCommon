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
// dumpConfiguration.c
//
// Implements the dumpConfiguration function
//
//====================================================================

#if defined __linux__
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "sysmon_defs.h"
#include "installer.h"
#endif
#include "stdafx.h"
#include "rules.h"
#include "xml.h"

//--------------------------------------------------------------------
//
// DumpConfiguration
//
// Display the current configuration
//
//--------------------------------------------------------------------
VOID
DumpConfiguration(
	VOID
	)
{
#if defined _WIN64 || defined _WIN32
	TCHAR			driverKeyPath[MAX_PATH];
	HKEY			hDriverKey;
	DWORD			archiveDirSize;
	TCHAR			ArchiveDirectory[MAX_PATH + 1];
	PTCHAR			configFile;
	PTCHAR			configHash;
	DWORD			regType, options;
	DWORD			hashingAlgorithm = DEFAULT_CRYPTO;
	PTCHAR			hash;
#elif defined __linux__
    int             rulesFd = 0;
#endif
	RULE_CONTEXT    ruleContext;
	PVOID			rules = NULL;
	RULE_REG_EXT    ruleRegExt = { 0 };
	PRULE_EVENT		ruleEvent;
	PRULE_FILTER	ruleFilter;
	BOOLEAN			releaseContext = FALSE;
	DWORD			bufferSize = 0, ruleError;
	PTCHAR			fieldName;
	PSYSMON_EVENT_TYPE_FMT eventTypeFmt;
	PTCHAR			prevRuleName = NULL;
	PTCHAR			fieldSizesStr = NULL;
	RuleDefaultType		prevRuleType = Rule_Unknown;

#if defined __linux__
    ruleError = ERROR_SUCCESS;

	if( ruleError == ERROR_SUCCESS ) {
        {
#endif

#if defined _WIN64 || defined _WIN32
	_stprintf_s( driverKeyPath, _countof(driverKeyPath),
				 _T("System\\CurrentControlSet\\Services\\%s\\Parameters"), SysmonDriverName );
	ruleError = RegOpenKeyEx( HKEY_LOCAL_MACHINE, driverKeyPath, 0, KEY_READ, &hDriverKey );

	if( ruleError == ERROR_SUCCESS ) {

		_tprintf( _T("Current configuration:\n") );
		_tprintf( _T(CONFIG_FMT) _T("%s\n"), CONFIG_NAME("Service name"), SysmonServiceName );
		_tprintf( _T(CONFIG_FMT) _T("%s\n"), CONFIG_NAME("Driver name"), SysmonDriverName );

		bufferSize = 0;
		ruleError = RegQueryValueEx( hDriverKey, _T( "ConfigFile" ), NULL, &regType, NULL, &bufferSize );
		if( ruleError == ERROR_SUCCESS ) {

			configFile = (PTCHAR)malloc( bufferSize );
			ruleError = RegQueryValueEx( hDriverKey, _T( "ConfigFile" ), NULL, &regType, (PBYTE)configFile, &bufferSize );
			if( ERROR_SUCCESS == ruleError ) {

				_tprintf( _T( CONFIG_FMT ) _T( "%s\n" ), CONFIG_NAME( "Config file" ), configFile );
			}
			free( configFile );
		}

		bufferSize = 0;
		ruleError = RegQueryValueEx( hDriverKey, _T( "ConfigHash" ), NULL, &regType, NULL, &bufferSize );
		if( ruleError == ERROR_SUCCESS && bufferSize ) {

			configHash = (PTCHAR)malloc( bufferSize );
			ruleError = RegQueryValueEx( hDriverKey, _T( "ConfigHash" ), NULL, &regType, (PBYTE)configHash, &bufferSize );
			if( ERROR_SUCCESS == ruleError && *configHash ) {

				_tprintf( _T( CONFIG_FMT ) _T( "%s\n" ), CONFIG_NAME( "Config hash" ), configHash );
			}
			free( configHash );
		}

		bufferSize = 0;
		ruleError = RegQueryValueEx( hDriverKey, _T( "FieldSizes" ), NULL, &regType, NULL, &bufferSize );
		if( ruleError == ERROR_SUCCESS && bufferSize ) {

			fieldSizesStr = (PTCHAR)malloc( bufferSize );
			ruleError = RegQueryValueEx( hDriverKey, _T( "FieldSizes" ), NULL, &regType, (PBYTE)fieldSizesStr, &bufferSize );
			if( ERROR_SUCCESS == ruleError && *fieldSizesStr ) {

				_tprintf( _T( CONFIG_FMT ) _T( "%s\n" ), CONFIG_NAME( "Field Sizes" ), fieldSizesStr );
			}
			free( fieldSizesStr );
		}

		options = 0;
		bufferSize = sizeof(options);
		QueryRegistry( hDriverKey, _T("Options"), REG_DWORD, (PBYTE)&options, &bufferSize );

		rules = NULL;
		bufferSize = 0;
		ruleError = RegQueryValueEx(hDriverKey, _T("Rules"), NULL, &regType, NULL, &bufferSize);

		if (ERROR_SUCCESS == ruleError)
		{
			rules = malloc(bufferSize);
			if (rules == NULL)
			{
				ruleError = ERROR_OUTOFMEMORY;
			}
			else
			{
				ruleError = RegQueryValueEx(hDriverKey, _T("Rules"), NULL, &regType, rules, &bufferSize);
			}

#elif defined __linux__
            fieldSizesStr = readFieldSizes();

            if ( fieldSizesStr != NULL ) {

                _tprintf( _T( CONFIG_FMT ) _T( "%s\n" ), CONFIG_NAME( "Field Sizes" ), fieldSizesStr );
                free( fieldSizesStr );
            }

            ruleError = ERROR_SUCCESS;

            struct stat st;
            rules = NULL;

            rulesFd = open(SYSMON_RULES_FILE, O_RDONLY);
            if (rulesFd < 0) {
                ruleError = ERROR_INVALID_DATA;
            } else {
                if (fstat(rulesFd, &st) < 0) {
                    ruleError = ERROR_INVALID_DATA;
                    close(rulesFd);
                } else {
                    bufferSize = st.st_size;
                    rules = mmap(NULL, bufferSize, PROT_READ, MAP_SHARED, rulesFd, 0);
                    if (rules == MAP_FAILED) {
                        ruleError = ERROR_INVALID_DATA;
                        close(rulesFd);
                    }
                }
            }

            if (ruleError == ERROR_INVALID_DATA) {
                printf("No rules installed\n");
                return;
            }
#endif


			//
			// Initialize the rule engine
			//
			if (ERROR_SUCCESS == ruleError)
			{
				if (!InitializeRules() || !SetRuleBlob(rules, bufferSize, FALSE))
				{
					ruleError = ERROR_OUTOFMEMORY;
				}
				else if (!InitializeRuleContext(&ruleContext))
				{
					ruleError = ERROR_INVALID_DATA;
				}
				else
				{
					releaseContext = TRUE;

					if (!GetRuleRegExtInformation(&ruleContext, &ruleRegExt))
					{
						ruleError = ERROR_INVALID_DATA;
					}
					else if (ruleRegExt.header.RuleCount == 0)
					{
						ruleError = ERROR_FILE_NOT_FOUND;
					}
				}
			}
		}
#if defined _WIN64 || defined _WIN32

		_tprintf( _T("\n") );

		bufferSize = sizeof(hashingAlgorithm);
		QueryRegistry( hDriverKey, _T("HashingAlgorithm"), REG_DWORD, (PBYTE)&hashingAlgorithm, &bufferSize );
		hash = SysmonCryptoName( hashingAlgorithm );
		_tprintf( _T(CONFIG_FMT) _T("%s\n"), CONFIG_NAME("HashingAlgorithms"), hash );
		free( hash );

		_tprintf( _T( CONFIG_FMT ) _T( "%s\n" ), CONFIG_NAME( "Network connection" ),
			(options & SYSMON_OPTIONS_NETWORK ? _T( "enabled" ) : _T( "disabled" )) );
		
		_tcscpy( ArchiveDirectory, _T("-"));
		archiveDirSize = _countof( ArchiveDirectory );
		RegQueryValueEx( hDriverKey, _T( "ArchiveDirectory" ), NULL, &regType, (LPBYTE)ArchiveDirectory, &archiveDirSize );

		_tprintf( _T(CONFIG_FMT) _T("%s\n"), CONFIG_NAME("Archive Directory"), ArchiveDirectory);

		_tprintf( _T(CONFIG_FMT) _T("%s\n"), CONFIG_NAME("Image loading"),
				  (options & SYSMON_OPTIONS_IMAGE ? _T("enabled") : _T("disabled")) );

		_tprintf( _T( CONFIG_FMT ) _T( "%s\n" ), CONFIG_NAME( "CRL checking" ),
			(GetConfigFromRegistry(_T("CheckRevocation")) ? _T( "enabled" ) : _T( "disabled" )) );

		_tprintf( _T( CONFIG_FMT ) _T( "%s\n" ), CONFIG_NAME( "DNS lookup" ),
			(GetConfigFromRegistry( _T( "DnsLookup" ) ) ? _T( "enabled" ) : _T( "disabled" )) );
#endif

		//
		// Rules
		//
		_tprintf(_T("\n"));
		if (ERROR_SUCCESS == ruleError)
		{
		    if (TO_DOUBLE(ruleRegExt.header.Version) >= 1.01)
			{
				_tprintf(_T("Rule configuration (version %.2f):\n"),
					TO_DOUBLE(ruleRegExt.SchemaVersion));
			}
			else
			{
				_tprintf(_T("Rule configuration (binary version %.2f):\n"),
					TO_DOUBLE(ruleRegExt.header.Version));
			}			

			ULONG currentAggregation = 0;

			for (ruleEvent = NextRuleEvent(&ruleContext, NULL);
				ruleEvent != NULL;
				ruleEvent = NextRuleEvent(&ruleContext, ruleEvent)) {

				eventTypeFmt = FindEventTypeFromId(ruleEvent->EventId);

				if (eventTypeFmt == NULL) {

					continue;
				}

				// Don't repeat overloaded event type names. Note that we can have include and exclude rules for the
				// same event so we need to check both the name and the type
				if( prevRuleName && !_tcscmp( prevRuleName, eventTypeFmt->RuleName )  &&  
					prevRuleType == ruleEvent->RuleDefault ) {

					continue;
				}

				prevRuleName = eventTypeFmt->RuleName;
				prevRuleType= ruleEvent->RuleDefault;

				_tprintf(_T(" - ") _T(CONFIG_FMT) _T(" onmatch: %s   combine rules using '%s'\n"),
					eventTypeFmt->RuleName,
					GetRuleMatchName(ruleEvent->RuleDefault),
					RuleCombineOR == ruleEvent->CombineType ? _T("Or") : RuleCombineAND == ruleEvent->CombineType ? _T("And") : _T("Unknown"));
		
				for (ruleFilter = NextRuleFilter(&ruleContext, ruleEvent, NULL);
					ruleFilter != NULL;
					ruleFilter = NextRuleFilter(&ruleContext, ruleEvent, ruleFilter)) {

					fieldName = GetFieldName(eventTypeFmt, ruleFilter->FieldId);

					if (fieldName == NULL) {

						continue;
					}

#if defined _WIN64 || defined _WIN32
                    PTCHAR ruleFilterData = (PTCHAR)ruleFilter->Data;
#elif defined __linux__
                    int ruleFilterDataSize = WideStrlen((PWCHAR)(ruleFilter->Data)) + 1;
                    CHAR ruleFilterData[ruleFilterDataSize * 4];
                    UTF16toUTF8(ruleFilterData, (PWCHAR)(ruleFilter->Data), ruleFilterDataSize * 4);
#endif

					if (ruleFilter->AggregationId) {
						
						if (ruleFilter->AggregationId != currentAggregation) {

							PRULE_CONTEXT pContext = &ruleContext;
							PRULE_AGGREGATION pAggregation = AGGREGATION_FROM_OFFSET(pContext, ruleFilter->AggregationOffset);

							if (WCSLEN( pAggregation->name )) {
#if defined _WIN64 || defined _WIN32
                                PTCHAR aggName = pAggregation->name;
#elif defined __linux__
                                int aggNameSize = sizeof(pAggregation->name) / sizeof(pAggregation->name[0]);
                                CHAR aggName[aggNameSize];
                                UTF16toUTF8(aggName, pAggregation->name, aggNameSize);
#endif
                                _tprintf_s(_T("\tCompound Rule %.32s   combine using %s\n"), aggName,
                                    RuleCombineOR == pAggregation->combineType ? _T("Or") : RuleCombineAND == pAggregation->combineType ? _T("And") : _T("Unknown"));
							} else {
								_tprintf_s(_T("\tCompound Rule %04d   combine using %s\n"), ruleFilter->AggregationId,
									RuleCombineOR == pAggregation->combineType ? _T("Or") : RuleCombineAND == pAggregation->combineType ? _T("And") : _T("Unknown"));
                            }

							currentAggregation = ruleFilter->AggregationId;
						}
#if 0
						_tprintf(_T("\t    [0x%04x] %-30s filter: %-12s value: '%s'\n"), ruleFilter->AggregationId, fieldName,
							GetFilterName(ruleFilter->FilterType), ruleFilterData);
#endif
                        _tprintf(_T("\t    %-30s filter: %-12s value: '%s'\n"), fieldName,
                            GetFilterName(ruleFilter->FilterType), ruleFilterData);
					} else {

                        _tprintf(_T("\t%-30s filter: %-12s value: '%s'\n"), fieldName,
                            GetFilterName(ruleFilter->FilterType), ruleFilterData);

					}
				}
			}
		}

		// rule engine cleanup
		if( ruleError != ERROR_SUCCESS && ruleError != ERROR_FILE_NOT_FOUND ) {

			_tprintf( _T("Failed to open rules configuration with last ruleError %d\n"), ruleError );
		} else if( ruleError == ERROR_FILE_NOT_FOUND ) {

			_tprintf( _T("No rules installed\n") );
		}

		if( releaseContext ) {

			ReleaseRuleContext( &ruleContext );
		}

#if defined _WIN64 || defined _WIN32
		if( rules != NULL ) {

			free( rules );
		}
#elif defined __linux__
        munmap(rules, bufferSize);
        close(rulesFd);
#endif

	} else if( ruleError == ERROR_FILE_NOT_FOUND ) {

		_tprintf( _T("Sysmon is not installed on this computer\n") );
	} else {

		_tprintf( _T("Failed to open driver configuration with last ruleError %d\n"), ruleError );
	}
}


